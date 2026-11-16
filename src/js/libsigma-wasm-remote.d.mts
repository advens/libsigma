// Types for libsigma-wasm-remote.mjs. Answers have the shapes of
// libsigma-wasm.d.mts; every call returns a Promise.

import type {
  Bytes,
  CorrelateAnswer,
  Events,
  ExplainAnswer,
  InfoAnswer,
  MatchAnswer,
} from "./libsigma-wasm.mjs";

/** A browser Worker or a Node worker_threads Worker running libsigma-wasm.worker.mjs. */
export type WorkerLike =
  | {
      postMessage(message: unknown, transfer: Transferable[]): void;
      addEventListener(type: string, listener: (event: any) => void): void;
      terminate(): unknown;
    }
  | {
      postMessage(message: unknown, transfer: readonly unknown[]): void;
      on(event: string, listener: (...args: any[]) => void): unknown;
      terminate(): unknown;
    };

export declare class SigmaWorker {
  /**
   * Initialize the worker with the module, its bytes (copied), or a URL the
   * worker fetches. Rejects, and terminates the worker, if the module does not
   * speak this loader's ABI.
   */
  static create(worker: WorkerLike, source: WebAssembly.Module | Bytes | string): Promise<SigmaWorker>;
  /** .sigmac format versions the module loads, inclusive. */
  readonly formatVersions: [number, number];
  /** Load a .sigmac artifact. The bytes are copied; the caller keeps its buffer. */
  load(sigmac: Bytes): Promise<RemoteEngine>;
  /** Stop the worker. Pending and later calls reject with SigmaError. */
  terminate(): void;
}

export declare class RemoteEngine {
  info(): Promise<InfoAnswer>;
  match(events: Events): Promise<MatchAnswer>;
  explain(event: string | Record<string, unknown>, ruleId: number): Promise<ExplainAnswer>;
  correlate(corr: string | Record<string, unknown>, events: Events): Promise<CorrelateAnswer>;
  infoJson(): Promise<string>;
  matchJson(events: Events): Promise<string>;
  explainJson(event: string | Record<string, unknown>, ruleId: number): Promise<string>;
  correlateJson(corr: string | Record<string, unknown>, events: Events): Promise<string>;
  close(): Promise<void>;
}
