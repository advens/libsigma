// libsigma-wasm-remote.test.mjs
// node --test for SigmaWorker against libsigma-wasm.worker.mjs in a
// worker_threads Worker. Same inputs as libsigma-wasm.test.mjs.
//
//   LIBSIGMA_WASM   module            (default build/wasm/libsigma.wasm)
//   CORPUS_SIGMAC   corpus artifact   (default build/wasm/corpus.sigmac)
//
// Copyright 2026 Advens. Author: Jeremie Jourdin <jeremie.jourdin@advens.fr>
// Licensed under the Apache License, Version 2.0 (see LICENSE).

import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { test } from "node:test";
import { Worker } from "node:worker_threads";

import { SigmaError } from "./libsigma-wasm.mjs";
import { SigmaWorker } from "./libsigma-wasm-remote.mjs";

const MODULE = process.env.LIBSIGMA_WASM ?? "build/wasm/libsigma.wasm";
const SIGMAC = process.env.CORPUS_SIGMAC ?? "build/wasm/corpus.sigmac";
const CORPUS = "src/events_corpus";

const wasmBytes = readFileSync(MODULE);
const sigmac = readFileSync(SIGMAC);
const corrText = readFileSync(`${CORPUS}/corpus.corr.json`, "utf8");
const eventsText = readFileSync(`${CORPUS}/events.jsonl`, "utf8");
const golden = readFileSync(`${CORPUS}/golden.txt`, "utf8");
const compiled = await WebAssembly.compile(wasmBytes);

const spawn = () => new Worker(new URL("./libsigma-wasm.worker.mjs", import.meta.url));

async function withWorker(source, fn) {
  const w = await SigmaWorker.create(spawn(), source);
  try {
    await fn(w);
  } finally {
    w.terminate();
  }
}

test("transcript through the worker is byte-identical to the native golden", () =>
  withWorker(compiled, async (w) => {
    assert.deepEqual(w.formatVersions, [4, 5]);
    const eng = await w.load(sigmac);
    const ruleIds = (await eng.info()).rules.map((r) => r.rule_id);
    const lines = eventsText.split("\n").filter((l) => l.length > 0);
    const out = [`match ${await eng.matchJson(eventsText)}`];
    for (const [e, line] of lines.entries()) {
      const wanted = JSON.parse(line)._explain ?? [];
      for (const r of ruleIds) {
        if (wanted.includes(r)) out.push(`explain ${e} ${r} ${await eng.explainJson(line, r)}`);
      }
    }
    out.push(`correlate ${await eng.correlateJson(corrText, eventsText)}`);
    assert.equal(out.join("\n") + "\n", golden);
    await eng.close();
  }));

test("module bytes and artifact bytes are copied, not taken", async () => {
  const bytes = Uint8Array.from(wasmBytes);
  const art = Uint8Array.from(sigmac);
  await withWorker(bytes, async (w) => {
    const eng = await w.load(art);
    assert.equal(bytes.byteLength, wasmBytes.byteLength);
    assert.equal(art.byteLength, sigmac.byteLength);
    assert.equal((await eng.match({})).ok, true);
  });
});

test("errors keep their type, code, and message", () =>
  withWorker(compiled, async (w) => {
    await assert.rejects(w.load(new Uint8Array(64)), (e) => e instanceof SigmaError && e.code === -3);
    const eng = await w.load(sigmac);
    await assert.rejects(eng.match(""), (e) => e instanceof SigmaError && e.message === "no events");
    await assert.rejects(eng.explain({}, 4242), /rule_id 4242 is not in the artifact/);
    await assert.rejects(eng.explain({}, -1), TypeError);
    await eng.close();
    await assert.rejects(eng.match("{}"), /engine is closed/);
    await eng.close();
  }));

test("concurrent calls each get their own answer", () =>
  withWorker(compiled, async (w) => {
    const eng = await w.load(sigmac);
    const dns = (name) => ({ event: { category: "dns" }, dns: { question: { name } } });
    const names = Array.from({ length: 64 }, (_, i) => (i % 2 ? `h${i}.onion` : `h${i}.example`));
    const answers = await Promise.all(names.map((n) => eng.match(dns(n))));
    answers.forEach((a, i) => assert.equal(a.totals.hits, i % 2, names[i]));
  }));

test("terminate rejects pending and later calls", async () => {
  const w = await SigmaWorker.create(spawn(), compiled);
  const eng = await w.load(sigmac);
  const pending = eng.match(eventsText.repeat(200));
  w.terminate();
  await assert.rejects(pending, /worker terminated/);
  await assert.rejects(eng.match("{}"), /worker terminated/);
  await assert.rejects(w.load(sigmac), /worker terminated/);
});

test("a module with the wrong exports fails create and stops the worker", async () => {
  const empty = new Uint8Array([0x00, 0x61, 0x73, 0x6d, 0x01, 0x00, 0x00, 0x00]);
  const worker = spawn();
  const exited = new Promise((resolve) => worker.once("exit", resolve));
  await assert.rejects(SigmaWorker.create(worker, empty));
  await exited;
});
