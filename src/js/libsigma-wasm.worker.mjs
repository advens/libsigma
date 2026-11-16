// libsigma-wasm.worker.mjs
// Worker body: owns one SigmaModule and answers requests from SigmaWorker
// (libsigma-wasm-remote.mjs), so matching never runs on the page's thread.
// Runs as a module Web Worker and as a Node worker_threads Worker.
//
// Request:  {id, op, args}
// Response: {id, ok: true, result} or {id, ok: false, error: {name, message, code, trapped}}
//
// Requests are answered in the order they arrive. Answers to info, match,
// explain, and correlate are the module's JSON text, unparsed.
//
// Copyright 2026 Advens. Author: Jeremie Jourdin <jeremie.jourdin@advens.fr>
// Licensed under the Apache License, Version 2.0 (see LICENSE).

import { SigmaError, SigmaModule } from "./libsigma-wasm.mjs";

let mod = null;
const engines = new Map();
let nextEngine = 1;

function module() {
  if (mod === null) throw new SigmaError("worker is not initialized");
  return mod;
}

function engine(id) {
  const e = engines.get(id);
  if (e === undefined) throw new SigmaError("engine is closed");
  return e;
}

const ops = {
  async init({ source }) {
    if (mod !== null) throw new SigmaError("worker is already initialized");
    mod = await SigmaModule.instantiate(typeof source === "string" ? fetch(source) : source);
    return { formatVersions: mod.formatVersions };
  },
  load({ sigmac }) {
    const e = module().load(sigmac);
    const id = nextEngine++;
    engines.set(id, e);
    return id;
  },
  info({ engine: id }) {
    return engine(id).infoJson();
  },
  match({ engine: id, events }) {
    return engine(id).matchJson(events);
  },
  explain({ engine: id, event, ruleId }) {
    return engine(id).explainJson(event, ruleId);
  },
  correlate({ engine: id, corr, events }) {
    return engine(id).correlateJson(corr, events);
  },
  close({ engine: id }) {
    const e = engines.get(id);
    if (e !== undefined) {
      engines.delete(id);
      e.close();
    }
    return null;
  },
};

function errorOf(err) {
  return {
    name: err instanceof TypeError ? "TypeError" : "SigmaError",
    message: err instanceof Error ? err.message : String(err),
    code: err instanceof SigmaError ? err.code : null,
    trapped: err instanceof SigmaError ? err.trapped : false,
  };
}

async function answer(post, msg) {
  const { id, op, args } = msg ?? {};
  try {
    if (!Object.hasOwn(ops, op)) throw new SigmaError(`unknown op ${String(op)}`);
    post({ id, ok: true, result: await ops[op](args ?? {}) });
  } catch (err) {
    post({ id, ok: false, error: errorOf(err) });
  }
}

let queue = Promise.resolve();

// A Web Worker listens before its module finishes evaluating, or the first
// messages are lost. A Node MessagePort holds messages until a listener is
// attached, so it can wait for the import.
if (typeof WorkerGlobalScope !== "undefined" && self instanceof WorkerGlobalScope) {
  const post = (m) => self.postMessage(m);
  self.addEventListener("message", (e) => {
    queue = queue.then(() => answer(post, e.data));
  });
} else {
  // A variable specifier keeps browser bundlers from resolving the Node module.
  const spec = "node:worker_threads";
  const { parentPort } = await import(/* @vite-ignore */ spec);
  if (parentPort === null) throw new Error("libsigma-wasm.worker.mjs must run in a worker");
  const post = (m) => parentPort.postMessage(m);
  parentPort.on("message", (m) => {
    queue = queue.then(() => answer(post, m));
  });
}
