// Types for libsigma-wasm.mjs. The answer shapes are the schemas documented in
// sigma_events.h (SCHEMA_VERSION 1).

export declare const ABI_VERSION: 1;
export declare const SCHEMA_VERSION: 1;
export declare const LOAD_ERRORS: Readonly<Record<number, string>>;

export declare class SigmaError extends Error {
  /** sigma_status_t of a failed load, or -100 when every slot is in use. */
  readonly code: number | null;
  /** The module trapped or exited; it cannot be used any more. */
  readonly trapped: boolean;
}

export type Verdict = "alert" | "escalate" | "benign";

export interface RuleHead {
  rule_id: number;
  title: string | null;
  verdict: Verdict;
  severity: number;
  /** Fixed-point score with two decimals, e.g. 0.35. */
  score: number;
  mitre: string | null;
}

export interface InfoAnswer {
  ok: true;
  schema: number;
  format_version: number;
  format_version_min: number;
  n_rules: number;
  /** Regex predicates PCRE2 could not compile; they never match. */
  re_skipped: number;
  rules: RuleHead[];
}

export interface MatchAnswer {
  ok: true;
  n_events: number;
  events: { index: number; hits: RuleHead[] }[];
  totals: { hits: number; alert: number; escalate: number; benign: number };
}

export type PredOp =
  | "eq" | "contains" | "startswith" | "endswith" | "exists"
  | "gt" | "gte" | "lt" | "lte" | "re" | "cidr" | "numeq";

export interface ExplainPred {
  field: string | null;
  /** Predicates with the same group are OR'ed; groups are AND'ed. */
  group: number;
  op: PredOp;
  /** The operand as the rule states it; the referenced field name for fieldref; null for exists. */
  value: string | null;
  case: boolean;
  negate: boolean;
  fieldref: boolean;
  present: boolean;
  got: string | null;
  got_truncated: boolean;
  matched: boolean;
}

export interface ExplainAnswer {
  ok: true;
  rule_id: number;
  title: string | null;
  /** What the matcher reports for the event (category routing applied). */
  matched: boolean;
  /** The rule alone, without routing. True with matched false: routing kept it out. */
  matched_unrouted: boolean;
  /** RPN tokens ("sel:N", "and", "or", "not"), or null for the AND of all selections. */
  condition: string[] | null;
  selections: { index: number; matched: boolean; preds: ExplainPred[] }[];
}

export interface CorrelationFire {
  event: number;
  corr_id: string | null;
  title: string | null;
  observed: number;
  threshold: number;
  group: Record<string, string | null> | null;
}

export interface CorrelateAnswer {
  ok: true;
  n_events: number;
  n_correlations: number;
  fires: CorrelationFire[];
  /** Events with no parseable time; they keep the previous event's time. */
  untimed: number;
  stats: Record<string, number>;
}

export type Events = string | Record<string, unknown> | Record<string, unknown>[];

export declare class SigmaModule {
  static instantiate(
    source: WebAssembly.Module | BufferSource | Response | Promise<Response>,
    options?: { onOutput?: (stream: "stdout" | "stderr", text: string) => void },
  ): Promise<SigmaModule>;
  /** .sigmac format versions this module loads, inclusive. */
  readonly formatVersions: [number, number];
  load(sigmac: BufferSource): SigmaEngine;
}

export declare class SigmaEngine {
  info(): InfoAnswer;
  match(events: Events): MatchAnswer;
  explain(event: string | Record<string, unknown>, ruleId: number): ExplainAnswer;
  correlate(corr: string | Record<string, unknown>, events: Events): CorrelateAnswer;
  infoJson(): string;
  matchJson(events: Events): string;
  explainJson(event: string | Record<string, unknown>, ruleId: number): string;
  correlateJson(corr: string | Record<string, unknown>, events: Events): string;
  close(): void;
}
