// libsigma-wasm-remote.mjs
// SigmaWorker: the SigmaModule / SigmaEngine calls, made asynchronously
// against libsigma-wasm.worker.mjs running in a worker the host creates.
//
//   const w = await SigmaWorker.create(
//     new Worker(new URL("./libsigma-wasm.worker.mjs", import.meta.url), { type: "module" }),
//     await fetch("libsigma.wasm").then((r) => r.arrayBuffer()));
//   const eng = await w.load(sigmacBytes);
//   const answer = await eng.match(events);
//
// A Node worker_threads Worker works the same way. The worker owns the module:
// terminate() is how a host stops a call that takes too long.
//
// Copyright 2026 Advens. Author: Jeremie Jourdin <jeremie.jourdin@advens.fr>
// Licensed under the Apache License, Version 2.0 (see LICENSE).

import { SigmaError } from "./libsigma-wasm.mjs";

function toError(e) {
  if (e.name === "TypeError") return new TypeError(e.message);
  return new SigmaError(e.message, { code: e.code, trapped: e.trapped });
}

// A private copy, so transferring it leaves the caller's buffer intact.
function copyBytes(src) {
  if (src instanceof ArrayBuffer) return new Uint8Array(src.slice(0));
  if (ArrayBuffer.isView(src)) {
    return new Uint8Array(src.buffer.slice(src.byteOffset, src.byteOffset + src.byteLength));
  }
  throw new TypeError("expected a BufferSource");
}

export class SigmaWorker {
  /**
   * @param {Worker|import("node:worker_threads").Worker} worker running libsigma-wasm.worker.mjs
   * @param {WebAssembly.Module|BufferSource|string} source the module, its bytes, or a URL the worker fetches
   */
  static async create(worker, source) {
    const w = new SigmaWorker(worker);
    let msg = source;
    const transfer = [];
    if (!(source instanceof WebAssembly.Module) && typeof source !== "string") {
      msg = copyBytes(source);
      transfer.push(msg.buffer);
    }
    try {
      const r = await w._request("init", { source: msg }, transfer);
      w.formatVersions = r.formatVersions;
    } catch (err) {
      w.terminate();
      throw err;
    }
    return w;
  }

  constructor(worker) {
    this._w = worker;
    this._next = 1;
    this._pending = new Map();
    this._dead = null;
    /** .sigmac format versions the module loads, inclusive. */
    this.formatVersions = null;
    const onMessage = (m) => this._settle(m);
    const onError = (what) => this._fail(new SigmaError(`worker failed: ${what}`, { trapped: true }));
    if (typeof worker.addEventListener === "function") {
      worker.addEventListener("message", (e) => onMessage(e.data));
      worker.addEventListener("error", (e) => {
        e.preventDefault?.();
        onError(e.message ?? "error");
      });
      worker.addEventListener("messageerror", () => onError("message could not be deserialized"));
    } else {
      worker.on("message", onMessage);
      worker.on("error", (err) => onError(err.message));
      worker.on("exit", (code) => onError(`exited with status ${code}`));
    }
  }

  _settle(m) {
    const p = this._pending.get(m?.id);
    if (p === undefined) return;
    this._pending.delete(m.id);
    if (m.ok) p.resolve(m.result);
    else p.reject(toError(m.error));
  }

  _fail(err) {
    if (this._dead === null) this._dead = err;
    for (const p of this._pending.values()) p.reject(this._dead);
    this._pending.clear();
  }

  _request(op, args, transfer = []) {
    if (this._dead !== null) return Promise.reject(this._dead);
    const id = this._next++;
    return new Promise((resolve, reject) => {
      this._pending.set(id, { resolve, reject });
      try {
        this._w.postMessage({ id, op, args }, transfer);
      } catch (err) {
        this._pending.delete(id);
        reject(err);
      }
    });
  }

  /**
   * Load a .sigmac artifact. The bytes are copied; the caller keeps its buffer.
   * @param {BufferSource} sigmac
   * @returns {Promise<RemoteEngine>}
   */
  async load(sigmac) {
    const bytes = copyBytes(sigmac);
    const id = await this._request("load", { sigmac: bytes }, [bytes.buffer]);
    return new RemoteEngine(this, id);
  }

  /** Stop the worker. Pending and later calls reject with SigmaError. */
  terminate() {
    this._fail(new SigmaError("worker terminated"));
    this._w.terminate();
  }
}

/** A .sigmac loaded in the worker. Call close() when done: the module has 16 slots. */
export class RemoteEngine {
  constructor(worker, id) {
    this._w = worker;
    this._id = id;
  }

  _call(op, args = {}) {
    if (this._id === 0) return Promise.reject(new SigmaError("engine is closed"));
    return this._w._request(op, { engine: this._id, ...args });
  }

  async _answer(text) {
    const a = JSON.parse(await text);
    if (!a.ok) throw new SigmaError(a.error);
    return a;
  }

  // Raw answers (JSON text, byte for byte what the module wrote).

  infoJson() {
    return this._call("info");
  }

  matchJson(events) {
    return this._call("match", { events });
  }

  explainJson(event, ruleId) {
    return this._call("explain", { event, ruleId });
  }

  correlateJson(corr, events) {
    return this._call("correlate", { corr, events });
  }

  // Parsed answers; an {"ok":false} answer rejects with SigmaError.

  info() {
    return this._answer(this.infoJson());
  }

  match(events) {
    return this._answer(this.matchJson(events));
  }

  explain(event, ruleId) {
    return this._answer(this.explainJson(event, ruleId));
  }

  correlate(corr, events) {
    return this._answer(this.correlateJson(corr, events));
  }

  async close() {
    if (this._id === 0) return;
    const id = this._id;
    this._id = 0;
    if (this._w._dead === null) await this._w._request("close", { engine: id });
  }
}
