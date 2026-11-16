// libsigma-wasm.mjs
// Loader for libsigma.wasm: instantiate the module, load .sigmac artifacts,
// and call match, explain, and correlate with plain JavaScript values.
//
// Runs unchanged in a browser, a Web Worker, and Node 18+. No dependency: the
// module needs nine WASI preview1 imports, implemented here. It has no files,
// no environment, and no arguments; stdout and stderr go to the onOutput
// callback when one is given.
//
// Copyright 2026 Advens. Author: Jeremie Jourdin <jeremie.jourdin@advens.fr>
// Licensed under the Apache License, Version 2.0 (see LICENSE).

/** Export set this loader speaks (sigma_wasm_abi_version). */
export const ABI_VERSION = 1;
/** JSON answer schema this loader expects (sigma_wasm_schema_version). */
export const SCHEMA_VERSION = 1;

/** sigma_status_t values returned by a failed load, plus the slot limit. */
export const LOAD_ERRORS = Object.freeze({
  [-1]: "out of memory",
  [-2]: "I/O error",
  [-3]: "not a .sigmac artifact (bad magic)",
  [-4]: "unsupported .sigmac format version",
  [-5]: "truncated or oversized artifact",
  [-6]: "checksum mismatch",
  [-7]: "internal reference out of range",
  [-8]: "regular expression failed to compile",
  [-100]: "all 16 engine slots are in use",
});

export class SigmaError extends Error {
  /**
   * @param {string} message
   * @param {{code?: number, trapped?: boolean}} [detail]
   */
  constructor(message, detail = {}) {
    super(message);
    this.name = "SigmaError";
    this.code = detail.code ?? null;
    this.trapped = detail.trapped ?? false;
  }
}

const WASI_ESUCCESS = 0;
const WASI_EBADF = 8;
const WASI_EINVAL = 28;

class ProcExit extends Error {
  constructor(code) {
    super(`module exited with status ${code}`);
    this.code = code;
  }
}

function wasiImports(getMemory, onOutput) {
  const dec = new TextDecoder();
  const view = () => new DataView(getMemory().buffer);
  return {
    environ_sizes_get(countPtr, sizePtr) {
      const v = view();
      v.setUint32(countPtr, 0, true);
      v.setUint32(sizePtr, 0, true);
      return WASI_ESUCCESS;
    },
    environ_get() {
      return WASI_ESUCCESS;
    },
    clock_time_get(id, _precision, outPtr) {
      let ns;
      if (id === 0) {
        ns = BigInt(Date.now()) * 1000000n;
      } else if (id === 1 && globalThis.performance) {
        ns = BigInt(Math.round(globalThis.performance.now() * 1e6));
      } else if (id === 1) {
        ns = BigInt(Date.now()) * 1000000n;
      } else {
        return WASI_EINVAL;
      }
      view().setBigUint64(outPtr, ns, true);
      return WASI_ESUCCESS;
    },
    fd_write(fd, iovs, iovsLen, nwrittenPtr) {
      if (fd !== 1 && fd !== 2) return WASI_EBADF;
      const v = view();
      const mem = new Uint8Array(getMemory().buffer);
      let total = 0;
      let text = "";
      for (let i = 0; i < iovsLen; i++) {
        const ptr = v.getUint32(iovs + i * 8, true);
        const len = v.getUint32(iovs + i * 8 + 4, true);
        text += dec.decode(mem.subarray(ptr, ptr + len), { stream: true });
        total += len;
      }
      if (onOutput && text) onOutput(fd === 1 ? "stdout" : "stderr", text);
      v.setUint32(nwrittenPtr, total, true);
      return WASI_ESUCCESS;
    },
    fd_close() {
      return WASI_EBADF;
    },
    fd_seek() {
      return WASI_EBADF;
    },
    fd_prestat_get() {
      return WASI_EBADF;
    },
    fd_prestat_dir_name() {
      return WASI_EBADF;
    },
    proc_exit(code) {
      throw new ProcExit(code);
    },
  };
}

async function toModule(source) {
  if (source instanceof WebAssembly.Module) return source;
  if (typeof Response !== "undefined" && source instanceof Response) {
    if (WebAssembly.compileStreaming) return WebAssembly.compileStreaming(source);
    return WebAssembly.compile(await source.arrayBuffer());
  }
  if (source instanceof ArrayBuffer || ArrayBuffer.isView(source)) return WebAssembly.compile(source);
  if (source && typeof source.then === "function") return toModule(await source);
  throw new TypeError("source must be a WebAssembly.Module, a BufferSource, or a Response");
}

/** One instantiated libsigma.wasm. Engines loaded from it share its memory. */
export class SigmaModule {
  /**
   * @param {WebAssembly.Module|BufferSource|Response|Promise<Response>} source
   * @param {{onOutput?: (stream: "stdout"|"stderr", text: string) => void}} [options]
   */
  static async instantiate(source, options = {}) {
    const module = await toModule(source);
    let memory = null;
    const instance = await WebAssembly.instantiate(module, {
      wasi_snapshot_preview1: wasiImports(() => memory, options.onOutput),
    });
    memory = instance.exports.memory;
    return new SigmaModule(instance);
  }

  /** @param {WebAssembly.Instance} instance */
  constructor(instance) {
    this._x = instance.exports;
    this._enc = new TextEncoder();
    this._dec = new TextDecoder();
    this._dead = null;
    this._call(() => this._x._initialize());
    const abi = this._x.sigma_wasm_abi_version();
    if (abi !== ABI_VERSION) {
      throw new SigmaError(`libsigma.wasm speaks ABI ${abi}, this loader speaks ${ABI_VERSION}`);
    }
    const schema = this._x.sigma_wasm_schema_version();
    if (schema !== SCHEMA_VERSION) {
      throw new SigmaError(`libsigma.wasm answers schema ${schema}, this loader expects ${SCHEMA_VERSION}`);
    }
    /** .sigmac versions this module loads, inclusive. */
    this.formatVersions = [this._x.sigma_wasm_format_version_min(), this._x.sigma_wasm_format_version()];
  }

  /**
   * Load a .sigmac artifact. The bytes are copied into the module.
   * @param {BufferSource} sigmac
   * @returns {SigmaEngine}
   */
  load(sigmac) {
    let bytes;
    if (sigmac instanceof Uint8Array) bytes = sigmac;
    else if (ArrayBuffer.isView(sigmac)) bytes = new Uint8Array(sigmac.buffer, sigmac.byteOffset, sigmac.byteLength);
    else if (sigmac instanceof ArrayBuffer) bytes = new Uint8Array(sigmac);
    else throw new TypeError("sigmac must be a BufferSource");
    const [ptr, len] = this._put(bytes);
    let h;
    try {
      h = this._call(() => this._x.sigma_wasm_load(ptr, len));
    } finally {
      this._free(ptr);
    }
    if (h < 1) throw new SigmaError(LOAD_ERRORS[h] ?? `load failed (status ${h})`, { code: h });
    return new SigmaEngine(this, h);
  }

  _check() {
    if (this._dead) throw this._dead;
  }

  // Every entry into the module goes through here. A trap or an exit leaves
  // the module's memory in an unknown state, so the module is unusable after.
  _call(fn) {
    this._check();
    try {
      return fn();
    } catch (err) {
      if (err instanceof ProcExit || err instanceof WebAssembly.RuntimeError) {
        this._dead = new SigmaError(`libsigma.wasm stopped: ${err.message}`, { trapped: true });
        throw this._dead;
      }
      throw err;
    }
  }

  _put(bytes) {
    const ptr = this._call(() => this._x.sigma_wasm_alloc(bytes.length));
    if (ptr === 0) throw new SigmaError("libsigma.wasm is out of memory");
    new Uint8Array(this._x.memory.buffer, ptr, bytes.length).set(bytes);
    return [ptr, bytes.length];
  }

  _putText(value) {
    const text = typeof value === "string" ? value : JSON.stringify(value);
    return this._put(this._enc.encode(text));
  }

  _free(ptr) {
    if (ptr && !this._dead) this._x.sigma_wasm_free(ptr);
  }

  // Read the NUL-terminated answer at ptr, then release it.
  _take(ptr) {
    if (ptr === 0) throw new SigmaError("libsigma.wasm is out of memory");
    const mem = new Uint8Array(this._x.memory.buffer);
    const end = mem.indexOf(0, ptr);
    const text = this._dec.decode(mem.subarray(ptr, end < 0 ? mem.length : end));
    this._free(ptr);
    return text;
  }
}

/** A loaded .sigmac. Call close() when done: the module has 16 slots. */
export class SigmaEngine {
  constructor(mod, handle) {
    this._m = mod;
    this._h = handle;
  }

  _alive() {
    if (this._h === 0) throw new SigmaError("engine is closed");
  }

  _answer(text) {
    const a = JSON.parse(text);
    if (!a.ok) throw new SigmaError(a.error);
    return a;
  }

  // Raw answers (JSON text, byte for byte what the module wrote).

  infoJson() {
    this._alive();
    const m = this._m;
    return m._take(m._call(() => m._x.sigma_wasm_info(this._h)));
  }

  /** @param {string|object|object[]} events JSON text, one object, or an array */
  matchJson(events) {
    this._alive();
    const m = this._m;
    const [p, n] = m._putText(events);
    try {
      return m._take(m._call(() => m._x.sigma_wasm_match(this._h, p, n)));
    } finally {
      m._free(p);
    }
  }

  /** @param {string|object} event @param {number} ruleId */
  explainJson(event, ruleId) {
    this._alive();
    if (!Number.isInteger(ruleId) || ruleId < 0 || ruleId > 0xffffffff) throw new TypeError("ruleId must be a uint32");
    const m = this._m;
    const [p, n] = m._putText(event);
    try {
      return m._take(m._call(() => m._x.sigma_wasm_explain(this._h, p, n, ruleId)));
    } finally {
      m._free(p);
    }
  }

  /** @param {string|object} corr rules.corr.json @param {string|object|object[]} events */
  correlateJson(corr, events) {
    this._alive();
    const m = this._m;
    const [cp, cn] = m._putText(corr);
    let ep = 0;
    try {
      const [p, n] = m._putText(events);
      ep = p;
      return m._take(m._call(() => m._x.sigma_wasm_correlate(this._h, cp, cn, ep, n)));
    } finally {
      m._free(cp);
      m._free(ep);
    }
  }

  // Parsed answers; an {"ok":false} answer throws SigmaError.

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

  close() {
    if (this._h === 0) return;
    const m = this._m;
    if (!m._dead) m._x.sigma_wasm_unload(this._h);
    this._h = 0;
  }
}
