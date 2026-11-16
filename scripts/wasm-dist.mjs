#!/usr/bin/env node
// Package the wasm32 release assets. Run by `make wasm-dist`.
//
//   libsigma-wasm-<v>.tar.gz      libsigma.wasm, the JS loader, the worker,
//                                 typings, abi.json, notices
//   libsigma-wasm-sdk-<v>.tar.gz  wasm32 static libraries and headers for
//                                 linking libsigma into another wasm32 program
//
// Each tarball has a SHA256SUMS inside and a .sha256 beside it. Entries are
// sorted, owned by 0:0, mode 0644 or 0755, and dated SOURCE_DATE_EPOCH, so the
// tar stream depends only on the inputs.
//
// The module is instantiated through the loader it ships with: a loader and
// module that disagree on the ABI or schema cannot be packaged together.

import { createHash } from "node:crypto";
import { mkdirSync, readdirSync, readFileSync, statSync, writeFileSync } from "node:fs";
import { basename, join, relative } from "node:path";
import { parseArgs } from "node:util";
import { gzipSync } from "node:zlib";

import { SigmaModule } from "../src/js/libsigma-wasm.mjs";

const { values: opt } = parseArgs({
  options: {
    out: { type: "string" },
    version: { type: "string" },
    "wasm-dir": { type: "string" },
    deps: { type: "string" },
    headers: { type: "string" },
  },
});
for (const k of ["out", "version", "wasm-dir", "deps", "headers"]) {
  if (!opt[k]) fail(`--${k} is required`);
}
if (!/^\d+\.\d+\.\d+$/.test(opt.version)) fail(`bad --version ${opt.version}`);

const epoch = Number(process.env.SOURCE_DATE_EPOCH ?? "0");
if (!Number.isSafeInteger(epoch) || epoch < 0) fail("bad SOURCE_DATE_EPOCH");

function fail(msg) {
  console.error(`wasm-dist: ${msg}`);
  process.exit(1);
}

const sha256 = (buf) => createHash("sha256").update(buf).digest("hex");

// Files under dir, relative paths, sorted.
function walk(dir) {
  const out = [];
  for (const name of readdirSync(dir).sort()) {
    const p = join(dir, name);
    if (statSync(p).isDirectory()) out.push(...walk(p).map((q) => join(name, q)));
    else out.push(name);
  }
  return out;
}

// ---------------------------------------------------------------- ustar

function octal(n, width) {
  return n.toString(8).padStart(width - 1, "0") + "\0";
}

function header(path, size, mode, type) {
  const h = Buffer.alloc(512);
  let name = path;
  let prefix = "";
  if (Buffer.byteLength(name) > 100) {
    const cut = path.lastIndexOf("/", 155);
    if (cut <= 0 || Buffer.byteLength(path.slice(cut + 1)) > 100) fail(`path too long for ustar: ${path}`);
    prefix = path.slice(0, cut);
    name = path.slice(cut + 1);
  }
  h.write(name, 0, 100, "utf8");
  h.write(octal(mode, 8), 100, "ascii");
  h.write(octal(0, 8), 108, "ascii");
  h.write(octal(0, 8), 116, "ascii");
  h.write(octal(size, 12), 124, "ascii");
  h.write(octal(epoch, 12), 136, "ascii");
  h.write("        ", 148, "ascii");
  h.write(type, 156, "ascii");
  h.write("ustar\0", 257, "ascii");
  h.write("00", 263, "ascii");
  h.write(prefix, 345, 155, "utf8");
  let sum = 0;
  for (const b of h) sum += b;
  h.write(octal(sum, 7) + " ", 148, "ascii");
  return h;
}

// entries: Map<relative path, Buffer>; directories are derived.
function tarGz(root, entries) {
  const dirs = new Set([root]);
  for (const p of entries.keys()) {
    const parts = p.split("/");
    for (let i = 1; i < parts.length; i++) dirs.add(`${root}/${parts.slice(0, i).join("/")}`);
  }
  const all = [
    ...[...dirs].map((d) => [`${d}/`, null]),
    ...[...entries].map(([p, b]) => [`${root}/${p}`, b]),
  ].sort(([a], [b]) => (a < b ? -1 : a > b ? 1 : 0));
  const blocks = [];
  for (const [p, buf] of all) {
    if (buf === null) {
      blocks.push(header(p, 0, 0o755, "5"));
      continue;
    }
    blocks.push(header(p, buf.length, 0o644, "0"), buf);
    const pad = (512 - (buf.length % 512)) % 512;
    if (pad) blocks.push(Buffer.alloc(pad));
  }
  blocks.push(Buffer.alloc(1024));
  const gz = gzipSync(Buffer.concat(blocks), { level: 9 });
  gz[9] = 3; // OS field: Unix, whatever host zlib was built for
  return gz;
}

function withSums(entries) {
  const lines = [...entries.keys()].sort().map((p) => `${sha256(entries.get(p))}  ${p}\n`);
  entries.set("SHA256SUMS", Buffer.from(lines.join("")));
  return entries;
}

function emit(name, root, entries) {
  const gz = tarGz(root, withSums(entries));
  const file = join(opt.out, name);
  writeFileSync(file, gz);
  writeFileSync(`${file}.sha256`, `${sha256(gz)}  ${name}\n`);
  console.log(`${relative(process.cwd(), file)}  ${gz.length} bytes  ${entries.size} files`);
}

// ---------------------------------------------------------------- inputs

const v = opt.version;
const wasmDir = opt["wasm-dir"];
const deps = opt.deps;
const js = "src/js";

// .pins is "name=version/sha256 ...". The sha256 of a host toolchain tarball
// differs per host, so only versions go into abi.json.
const pins = Object.fromEntries(
  readFileSync(join(deps, ".pins"), "utf8")
    .trim()
    .split(/\s+/)
    .map((kv) => {
      const [k, rest] = kv.split("=");
      return [k, rest.split("/")[0]];
    })
    .filter(([k]) => k !== "wasmtime"),
);

const licenses = new Map([["LICENSE", readFileSync("LICENSE")]]);
for (const p of walk(join(deps, "share/licenses"))) {
  licenses.set(`licenses/${p}`, readFileSync(join(deps, "share/licenses", p)));
}

const wasm = readFileSync(join(wasmDir, "libsigma.wasm"));
const mod = await SigmaModule.instantiate(wasm);
const compiled = new WebAssembly.Module(wasm);
const abi = {
  name: "libsigma-wasm",
  version: v,
  abi: mod._x.sigma_wasm_abi_version(),
  schema: mod._x.sigma_wasm_schema_version(),
  format_version: mod.formatVersions[1],
  format_version_min: mod.formatVersions[0],
  module: {
    file: "libsigma.wasm",
    bytes: wasm.length,
    sha256: sha256(wasm),
    exports: WebAssembly.Module.exports(compiled).map(({ name, kind }) => ({ name, kind })),
    imports: WebAssembly.Module.imports(compiled).map(({ module, name, kind }) => ({ module, name, kind })),
  },
  toolchain: { target: "wasm32-wasip1", ...pins },
};

mkdirSync(opt.out, { recursive: true });

const moduleFiles = new Map([
  ["libsigma.wasm", wasm],
  ["abi.json", Buffer.from(JSON.stringify(abi, null, 2) + "\n")],
]);
for (const f of [
  "libsigma-wasm.mjs",
  "libsigma-wasm.d.mts",
  "libsigma-wasm-remote.mjs",
  "libsigma-wasm-remote.d.mts",
  "libsigma-wasm.worker.mjs",
]) {
  moduleFiles.set(f, readFileSync(join(js, f)));
}
for (const [p, b] of licenses) moduleFiles.set(p, b);
emit(`libsigma-wasm-${v}.tar.gz`, `libsigma-wasm-${v}`, moduleFiles);

const sdkFiles = new Map();
for (const lib of ["libsigma.a", "libsigma_events.a"]) sdkFiles.set(`lib/${lib}`, readFileSync(join(wasmDir, lib)));
for (const lib of ["libpcre2-8.a", "libfastjson.a"]) sdkFiles.set(`lib/${lib}`, readFileSync(join(deps, "lib", lib)));
for (const h of opt.headers.split(/\s+/).filter(Boolean)) {
  sdkFiles.set(`include/sigma/${basename(h)}`, readFileSync(h));
}
sdkFiles.set("include/pcre2.h", readFileSync(join(deps, "include/pcre2.h")));
for (const p of walk(join(deps, "include/libfastjson"))) {
  sdkFiles.set(`include/libfastjson/${p}`, readFileSync(join(deps, "include/libfastjson", p)));
}
const toolchain = [
  `libsigma ${v} for wasm32-wasip1`,
  ...Object.entries(pins).map(([k, ver]) => `${k} ${ver}`),
  "",
  "Link with the same wasi-sdk major version, for example:",
  "  clang --target=wasm32-wasip1 -Iinclude -Iinclude/libfastjson -Iinclude/sigma app.c \\",
  "    lib/libsigma_events.a lib/libsigma.a lib/libpcre2-8.a lib/libfastjson.a -lm",
  "",
];
sdkFiles.set("TOOLCHAIN", Buffer.from(toolchain.join("\n")));
for (const [p, b] of licenses) sdkFiles.set(p, b);
emit(`libsigma-wasm-sdk-${v}.tar.gz`, `libsigma-wasm-sdk-${v}`, sdkFiles);
