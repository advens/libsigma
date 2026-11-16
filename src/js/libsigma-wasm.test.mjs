// libsigma-wasm.test.mjs
// node --test for the loader and the module boundary. Run from the repository
// root after `make wasm` and the corpus artifact (make wasm-test does both).
//
//   LIBSIGMA_WASM   module            (default build/wasm/libsigma.wasm)
//   CORPUS_SIGMAC   corpus artifact   (default build/wasm/corpus.sigmac)
//
// Copyright 2026 Advens. Author: Jeremie Jourdin <jeremie.jourdin@advens.fr>
// Licensed under the Apache License, Version 2.0 (see LICENSE).

import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { test } from "node:test";

import { SigmaError, SigmaModule } from "./libsigma-wasm.mjs";

const MODULE = process.env.LIBSIGMA_WASM ?? "build/wasm/libsigma.wasm";
const SIGMAC = process.env.CORPUS_SIGMAC ?? "build/wasm/corpus.sigmac";
const CORPUS = "src/events_corpus";

const wasmBytes = readFileSync(MODULE);
const sigmac = readFileSync(SIGMAC);
const corrText = readFileSync(`${CORPUS}/corpus.corr.json`, "utf8");
const eventsText = readFileSync(`${CORPUS}/events.jsonl`, "utf8");
const golden = readFileSync(`${CORPUS}/golden.txt`, "utf8");

const fresh = () => SigmaModule.instantiate(wasmBytes);

test("transcript is byte-identical to the native golden", async () => {
  const m = await fresh();
  const eng = m.load(sigmac);
  const ruleIds = eng.info().rules.map((r) => r.rule_id);
  const lines = eventsText.split("\n").filter((l) => l.length > 0);
  const out = [`match ${eng.matchJson(eventsText)}`];
  lines.forEach((line, e) => {
    const wanted = JSON.parse(line)._explain ?? [];
    for (const r of ruleIds) {
      if (wanted.includes(r)) out.push(`explain ${e} ${r} ${eng.explainJson(line, r)}`);
    }
  });
  out.push(`correlate ${eng.correlateJson(corrText, eventsText)}`);
  assert.equal(out.join("\n") + "\n", golden);
  eng.close();
});

test("versions", async () => {
  const m = await fresh();
  assert.deepEqual(m.formatVersions, [4, 5]);
  const eng = m.load(sigmac);
  const info = eng.info();
  assert.equal(info.schema, 1);
  assert.equal(info.n_rules, 10);
  eng.close();
});

test("objects, arrays, and text give the same answer", async () => {
  const m = await fresh();
  const eng = m.load(sigmac);
  const evs = [{ event: { category: "dns" }, dns: { question: { name: "a.onion" } } }, {}];
  assert.equal(eng.matchJson(evs), eng.matchJson(JSON.stringify(evs)));
  assert.equal(eng.matchJson(evs[0]), eng.matchJson(JSON.stringify(evs[0])));
  assert.deepEqual(eng.match(evs).events.map((e) => e.hits.map((h) => h.rule_id)), [[90], []]);
  eng.close();
});

const proc = (cmd) => ({ event: { category: "process" }, process: { name: "powershell.exe", command_line: cmd }, user: { name: "bob" } });

test("UTF-8 survives the round trip", async () => {
  const m = await fresh();
  const eng = m.load(sigmac);
  const cmd = "powershell -enc Zoë 😀 漢字 bob";
  const x = eng.explain(proc(cmd), 70);
  assert.equal(x.matched, true);
  assert.equal(x.selections[0].preds[0].got, cmd);
  eng.close();
});

test("an embedded NUL ends the value, as in a C host", async () => {
  const m = await fresh();
  const eng = m.load(sigmac);
  const x = eng.explain(proc("powershell -enc A\u0000 bob"), 70);
  assert.equal(x.selections[0].preds[0].got, "powershell -enc A");
  assert.equal(x.matched, false);
  eng.close();
});

test("bad input is a SigmaError, never a crash", async () => {
  const m = await fresh();
  const eng = m.load(sigmac);
  assert.throws(() => eng.match(""), (e) => e instanceof SigmaError && e.message === "no events");
  assert.throws(() => eng.match("[1]"), /event 0: not a JSON object/);
  assert.throws(() => eng.match('{"a":'), /event 0: invalid or incomplete JSON/);
  assert.throws(() => eng.explain({}, 4242), /rule_id 4242 is not in the artifact/);
  assert.throws(() => eng.explain({}, -1), TypeError);
  assert.throws(() => eng.correlate('{"version":2}', "{}"), /correlation artifact rejected/);
  assert.deepEqual(eng.match("{}").totals.hits, 0);
  eng.close();
  assert.throws(() => eng.match("{}"), /engine is closed/);
  eng.close();
});

test("load failures carry the status", async () => {
  const m = await fresh();
  assert.throws(() => m.load(new Uint8Array(64)), (e) => e instanceof SigmaError && e.code === -3);
  assert.throws(() => m.load(new Uint8Array(0)), (e) => e instanceof SigmaError && e.code === -5);
  const corrupt = Uint8Array.from(sigmac);
  corrupt[corrupt.length - 1] ^= 0xff;
  assert.throws(() => m.load(corrupt), (e) => e instanceof SigmaError && e.code === -6);
  const view = new DataView(new Uint8Array([0, 0, ...sigmac]).buffer, 2);
  m.load(view).close();
});

test("sixteen engines, then the slot limit, then reuse", async () => {
  const m = await fresh();
  const engines = Array.from({ length: 16 }, () => m.load(sigmac));
  assert.throws(() => m.load(sigmac), (e) => e.code === -100);
  engines[3].close();
  const again = m.load(sigmac);
  assert.equal(again.match("{}").ok, true);
  for (const e of [...engines, again]) e.close();
});

test("memory growth keeps the views valid", async () => {
  const m = await fresh();
  const eng = m.load(sigmac);
  const one = '{"event":{"category":"dns"},"dns":{"question":{"name":"x.onion"}},"pad":"' + "p".repeat(200) + '"}\n';
  const big = one.repeat(20000);
  const t0 = performance.now();
  const a = eng.match(big);
  const ms = performance.now() - t0;
  assert.equal(a.n_events, 20000);
  assert.equal(a.totals.hits, 20000);
  assert.equal(eng.match("{}").n_events, 1);
  console.log(`# 20000 events (${(big.length / 1e6).toFixed(1)} MB) matched in ${ms.toFixed(0)} ms`);
  eng.close();
});

test("a trap retires the module", async () => {
  const m = await fresh();
  const eng = m.load(sigmac);
  assert.throws(
    () => m._call(() => m._x.sigma_wasm_match(1, 0xfffffff0, 64)),
    (e) => e instanceof SigmaError && e.trapped,
  );
  assert.throws(() => eng.match("{}"), (e) => e instanceof SigmaError && e.trapped);
  assert.throws(() => m.load(sigmac), (e) => e.trapped);
});
