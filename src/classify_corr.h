/* classify_corr.h
 * Warm-path Sigma CORRELATION engine: a self-contained C engine designed to run
 * inside a host log pipeline's worker threads.
 *
 * Sigma correlation primitives (the eight spec types plus a beaconing
 * extension). The first four are the common SigmaHQ set; value_sum / value_avg /
 * value_percentile / value_median are the numeric aggregations; beaconing is
 * a libsigma extension (not in the SigmaHQ spec).
 *
 *   event_count     , >=N base-rule matches, grouped, within a timespan
 *   value_count     , >=N DISTINCT values of a field, grouped, within a timespan
 *   temporal        , base rules A,B,C ALL occur (any order), same group, window
 *                     (or a SEP #198 boolean over those bases)
 *   temporal_ordered, A then B then C IN ORDER within the timespan
 *   value_sum       , SUM(numeric field) <op> threshold over the window
 *   value_avg       , AVG(numeric field) <op> threshold (no fire on empty)
 *   value_percentile, P_k(numeric field) <op> threshold (exact from the ring)
 *   value_median    , P_50, same path as percentile
 *   beaconing       , arrivals are PERIODIC (low gap-CV); libsigma extension
 *
 * The single-event selection matcher (sigma_match.h) has already stamped each
 * event with the rules it matched. This engine consumes that per-event rule-id
 * list + the group-by field values + the event timestamp, and FIRES when a
 * correlation condition holds, emitting a fired-correlation activation that a
 * downstream stage consumes.
 *
 * This unit has NO third-party dependency (libc + pthread + libm only). It
 * operates on already-resolved inputs the caller supplies, plus a compiled,
 * read-only rule table (corr_rule_t[]) the caller builds (from a corr_format
 * loader, or in C directly for the standalone self-test). That keeps it
 * self-contained, deterministic, bounded, and reusable.
 *
 * Cross-instance: commutative types can MERGE COUNT/SUM/SEEN/DISTINCT
 * contributions from a peer (corr_on_contribution). The library does not open
 * sockets: the caller carries contributions between instances on whatever
 * transport it already has. Owner selection is corr_owner_index (djb2).
 * temporal_ordered and raw beaconing stay local-only.
 *
 * Threading (engine-concurrent): a corr_engine_t carries MUTABLE
 * sliding-window state but is SAFE for concurrent corr_on_event from multiple
 * caller threads.  Each correlation's group map is guarded by its own lock, so
 * workers evaluating DIFFERENT correlations proceed in parallel; workers on the
 * same correlation serialise on that one lock (never on the line-rate match
 * path, since correlation runs only on the already-matched minority).  The
 * periodic sweep is single-flight.  The boundary counters are relaxed-atomic.
 * The engine POINTER's lifetime across a reload is the caller's responsibility
 * (e.g. swapped under an rwlock on reload): never free an engine while a worker
 * may still be inside it.
 *
 * BOUNDED EVICTION (anti-exhaustion):
 *   1. per-correlation LRU group cap (max_groups, default 50000)
 *   2. lazy time eviction: every event prunes in-group timestamps older than
 *      the window and drops empty groups
 *   3. periodic global sweep (sweep_interval_s) drops fully-expired groups
 *   4. value_count distinct-set cap (max_distinct, default 10000) per group
 *   5. per-group event ring cap (max_events_per_group, default 4096)
 * Worst-case memory ~= n_corr * max_groups * (event_budget | max_distinct):
 * finite and operator-tunable, never a function of adversary-controlled
 * cardinality.
 *
 * Copyright 2026 Advens.
 * Author: Jeremie Jourdin <jeremie.jourdin@advens.fr>
 *
 * This file is part of libsigma.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *       http://www.apache.org/licenses/LICENSE-2.0
 *       -or-
 *       see LICENSE in the source distribution
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#ifndef CLASSIFY_CORR_H
#define CLASSIFY_CORR_H

#include <stdint.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

/* ============================================================================
 * Correlation type + condition op.  * ========================================================================== */
typedef enum {
    CORR_EVENT_COUNT = 0,
    CORR_VALUE_COUNT,
    CORR_TEMPORAL,
    CORR_TEMPORAL_ORDERED,
    CORR_VALUE_SUM, /* Σ(value_field) over the window <op> threshold */
    CORR_VALUE_AVG, /* AVG(value_field) over the window <op> threshold (no fire on empty) */
    CORR_BEACONING, /* base rule's arrivals on the group are PERIODIC (low gap-CV) */
    CORR_VALUE_PERCENTILE, /* P_k(value_field) over the window <op> threshold */
    CORR_VALUE_MEDIAN, /* P_50(value_field); value_percentile==50 implied */
    CORR_TYPE__MAX
} corr_type_t;

typedef enum {
    CORR_OP_GTE = 0, /* default */
    CORR_OP_GT,
    CORR_OP_LTE,
    CORR_OP_LT,
    CORR_OP_EQ
} corr_op_t;

/* SEP #198: a boolean condition over a correlation's base rules, mirroring the
 * single-event matcher's RPN.  SEL(i) is true iff base_rule_ids[i] fired within
 * the window; AND/OR/NOT compose.  Postfix (RPN) so the C loader/evaluator need
 * no parser.  NULL cond => legacy "all base rules fired" semantics. */
typedef enum { CORR_C_SEL = 0, CORR_C_AND, CORR_C_OR, CORR_C_NOT } corr_ctok_kind_t;
typedef struct {
    uint8_t kind; /* corr_ctok_kind_t */
    uint8_t _pad[3];
    uint32_t rid_idx; /* LOCAL index into corr_rule_t.base_rule_ids (kind==SEL) */
} corr_ctok_t;

/* Fidelity tier of a FIRED correlation.  Only the
 * two tiers tier_for_correlation can produce are exposed here; the weight is the
 * an activation weight. */
typedef enum {
    CORR_TIER_WEAK = 0, /* eta = 0.3 */
    CORR_TIER_STRONG = 1 /* eta = 0.6 */
} corr_tier_t;

const char* corr_tier_name(corr_tier_t t); /* "weak" | "strong" */
double corr_tier_weight(corr_tier_t t); /* 0.3 | 0.6 */

/* Fidelity tier for a fired correlation, given its type + Sigma level string.
 *   temporal / temporal_ordered            -> STRONG (always)
 *   event_count / value_count, high/crit   -> STRONG
 *   event_count / value_count, otherwise   -> WEAK
 * NEVER CONFIRMED, NEVER CONTEXT (DEMOTE-NOT-MUTE).  level==NULL => "medium". */
corr_tier_t corr_tier_for(corr_type_t type, const char* level);

/* ----------------------------------------------------------------------------
 * Compiled, read-only correlation rule.  The caller owns all the string/array
 * storage and must keep it alive for the engine's lifetime, the engine stores
 * pointers, never copies.  (corr_format builds these from rules.corr.json; the
 * self-test constructs them in C directly.)
 *
 * group_by:        ECS field NAMES (e.g. "source.ip").  n_group_by==0 collapses
 *                  to a single global group.  The caller resolves these names to
 *                  values per-event and passes the value array to corr_on_event.
 * base_rule_ids:   compiled rule-ids (as stamped by the selection matcher)
 *                  this correlation watches.
 * ordered_rule_ids: temporal_ordered only, the rids in REQUIRED order.  When
 *                  NULL the engine uses base_rule_ids order.
 * value_field:     value_count (DISTINCT values) / value_sum / value_avg /
 *                  value_percentile / value_median (the NUMERIC field) — the
 *                  caller resolves it per-event.  NULL for the other types.
 * cond_count:      threshold N (event_count / value_count / aggregations).
 *                  For temporal* it is n_base_rule_ids (informational).
 * value_percentile: 1..100 for CORR_VALUE_PERCENTILE (ignored otherwise;
 *                  CORR_VALUE_MEDIAN forces 50).
 * -------------------------------------------------------------------------- */
typedef struct {
    const char* id; /* stable correlation id (Sigma name) */
    const char* title; /* human title (may be NULL) */
    corr_type_t type;
    const uint32_t* base_rule_ids;
    size_t n_base_rule_ids;
    const uint32_t* ordered_rule_ids;
    size_t n_ordered_rule_ids; /* may be NULL/0 */
    const char* const* group_by;
    size_t n_group_by;
    /* Optional per-base-rule group-by field names (Sigma correlation
     * aliases). Parallel to base_rule_ids: alias_group_by[i] is
     * n_group_by ECS names to read when the event matched
     * base_rule_ids[i]. NULL / n_alias_group_by==0 => use group_by
     * for every base rule. */
    const char* const* const* alias_group_by;
    size_t n_alias_group_by;
    const char* value_field; /* value_count only, else NULL */
    corr_op_t cond_op;
    int64_t cond_count;
    int32_t timespan_s; /* window length, seconds (must be > 0) */
    const char* level; /* Sigma level string (fidelity-tier input) */
    const char* mitre; /* primary MITRE technique (T-id) or NULL */
    /* SEP #198: optional boolean RPN over base-rule LOCAL indices for temporal /
     * temporal_ordered.  NULL / n_cond==0 keeps the legacy all-fired semantics. */
    const corr_ctok_t* cond;
    size_t n_cond;
    /* beaconing only: max inter-arrival coefficient-of-variation, in PER-MILLE
     * (cv * 1000). Fire iff the window holds >= cond_count events AND the gap CV
     * is <= this tolerance. e.g. 250 = CV <= 0.25 (evenly spaced). 0 for the
     * other types. Keyed per group (source.ip+destination.ip = one channel), so
     * destination-consistency is implicit in the group key. */
    int32_t beacon_cv_permille;
    /* beaconing horizon mode. 0 = RAW: inter-arrival CV over the ev_ts ring
     * (precise sub-window cadence, bounded to the events that fit the ring).
     * > 0 = BUCKETED: a long-horizon activity histogram of this many time
     * buckets over timespan_s (bucket_secs = timespan_s / beacon_n_buckets); the
     * fire adds a presence gate (active buckets must cover >= 70% of the active
     * span) so low-and-slow multi-day beacons are caught without holding raw
     * events. cond_count is then the MIN active buckets. */
    int32_t beacon_n_buckets;
    /* value_percentile only: k in P_k, 1..100. 0 => default 95. Median type
     * ignores this and uses 50. */
    int32_t value_percentile;
} corr_rule_t;

/* Operator-tunable bounds.  Pass {0,0,0,0} to corr_caps_default() for defaults. */
typedef struct {
    uint32_t max_groups; /* per-correlation LRU group cap (50000) */
    uint32_t max_distinct; /* value_count distinct-set cap (10000) */
    uint32_t max_events_per_group; /* event ring cap (4096) */
    double sweep_interval_s; /* global expired-group sweep cadence (30.0) */
    /* When set, the caller feeds EVENT time (not a monotonic processing clock)
     * as the per-event `ts`, and temporal_ordered requires each matched step's
     * event time to be non-decreasing (so out-of-order processing across
     * concurrent sources cannot fabricate an ordered sequence). Default 0
     * (monotonic processing time). */
    int event_time_ordering;
    /* temporal_ordered reorder buffer, seconds of event-time slack. 0 = no
     * buffer (greedy, current behaviour). A late-but-in-slack event is held
     * and replayed in event-time order once a later event raises the high
     * water mark. Events older than (max_event_ts - watermark_s) are counted
     * as watermark_late and still offered to the greedy evaluator (which may
     * reject them under event_time_ordering). */
    double watermark_s;
} corr_caps_t;

corr_caps_t corr_caps_default(void);

/* ----------------------------------------------------------------------------
 * The engine.  Opaque; per-instance, zero global state.
 * -------------------------------------------------------------------------- */
typedef struct corr_engine corr_engine_t;

/* Build an engine over *rules* (the caller keeps the array + its referenced
 * strings/arrays alive for the engine's lifetime).  Malformed rules (bad type,
 * empty base list, non-positive timespan) are SKIPPED, never fatal, mirroring
 * the Python loader.  Returns NULL only on OOM. */
corr_engine_t* corr_engine_new(const corr_rule_t* rules, size_t n, corr_caps_t caps);
void corr_engine_free(corr_engine_t* e);

/* How many rules were actually admitted (valid). */
size_t corr_engine_rule_count(const corr_engine_t* e);
/* Total live groups across all correlations (health probe / test). */
size_t corr_engine_total_groups(const corr_engine_t* e);
/* Live groups for one correlation by id, or 0 if unknown. */
size_t corr_engine_groups_for(const corr_engine_t* e, const char* id);

/* ----------------------------------------------------------------------------
 * Observable boundary counters (every silent cap is observable).  The engine
 * increments these in-band as caps are hit; the caller reads them via
 * corr_engine_stats and publishes them to its own statistics facility.  Kept as
 * plain uint64_t so the engine stays dependency-free.
 * These count SILENT losses only, timestamps aging out of a window (the
 * intended windowing) are NOT counted, only cap-driven eviction/overwrite/drop.
 * -------------------------------------------------------------------------- */
typedef struct {
    uint64_t groups_evicted; /* LRU group eviction (max_groups) */
    uint64_t distinct_evicted; /* value_count distinct eviction (max_distinct) */
    uint64_t events_overwritten; /* event-ring overwrite (max_events_per_group) */
    uint64_t fires_suppressed; /* re-fire suppression within a lit window */
    uint64_t fires_truncated; /* fires beyond the caller's out[] cap */
    uint64_t rules_rejected; /* rules skipped at admit (malformed) */
    uint64_t event_skipped_missing_field; /* a group-by field was absent -> event skipped */
    uint64_t seen_truncated; /* temporal seen-rid table hit CORR_MAX_SEEN_RULES */
    uint64_t hits_truncated; /* per-event base-rid capture hit CORR_MAX_SEEN_RULES */
    uint64_t group_evidence_dropped; /* fired group-key evidence dropped (scratch full) */
    uint64_t oom_dropped; /* an OOM soft-fail dropped an event/group/value */
    uint64_t values_nonnumeric; /* value_sum/avg/percentile: event value_field not numeric, skipped */
    uint64_t cond_over_arity; /* SEP #198 condition rule with >64 base rules, rejected */
    uint64_t watermark_late; /* temporal_ordered event older than the slack window */
    uint64_t hotkey_fallback; /* a group filled its ring in less than half a window */
} corr_stats_t;

/* Snapshot the engine's boundary counters into *out (both must be non-NULL). */
void corr_engine_stats(const corr_engine_t* e, corr_stats_t* out);

/* ----------------------------------------------------------------------------
 * A fired correlation (the activation the caller serialises).  All string
 * pointers reference the corr_rule_t the caller owns (valid for its lifetime);
 * `group` snapshots the firing group-key values into caller-provided storage -
 * see corr_fire_t.group below.
 * -------------------------------------------------------------------------- */
#define CORR_MAX_GROUP_FIELDS 8 /* group-by arity ceiling (matches builder) */

typedef struct {
    const char* rule_id; /* corr->id */
    const char* title; /* corr->title */
    corr_type_t type;
    const char* technique; /* corr->mitre (may be NULL) */
    const char* level; /* corr->level */
    corr_tier_t tier;
    double fidelity_weight; /* corr_tier_weight(tier) */
    /* grouping evidence: group_by[i] = group[i] (arrays of length n_group).
     * group[] points into the caller's per-worker grp_scratch passed to
     * corr_on_event; the values are caller field-value pointers valid until the
     * caller consumes out[].  group is NULL if the evidence was dropped. */
    const char* const* group_by;
    const char** group;
    size_t n_group;
    int64_t observed; /* count crossing the threshold */
    int64_t threshold; /* corr->cond_count */
    const char* value_field; /* value_count only, else NULL */
    const uint32_t* base_rule_ids;
    size_t n_base_rule_ids;
    /* 1 if this group's state ingested a remote COUNT/SUM/SEEN/DISTINCT
     * contribution (see corr_on_contribution). A consumer that needs
     * single-instance provenance can filter these out. */
    int remote;
} corr_fire_t;

/* Feed ONE event.  Inputs (all caller-resolved):
 *   matched_rids / n_rids : the compiled rule-ids the selection matcher stamped
 *                           on this event.  May be empty => no-op.
 *   group_vals            : per-correlation the engine reads the group-by field
 *                           VALUES from here.  Because different correlations may
 *                           use different group-by fields, the caller supplies a
 *                           resolver instead of a flat array, see below.
 *   value_field_val       : resolved value of EACH interested value_count's
 *                           field for this event (the caller resolves per call;
 *                           see the resolver form).
 *
 * To keep the engine field-name-agnostic (it does not know how to resolve ECS
 * paths, that is the caller's job), the caller passes a resolver callback
 * the engine invokes for each field name it needs.  Returns the value pointer
 * (valid for the duration of THIS call) or NULL when the field is absent.
 */
typedef const char* (*corr_field_fn)(void* ctx, const char* name);

/* Evaluate the event against every interested correlation; append fired
 * activations to out[] (up to max_out).  Returns the number fired (may exceed
 * max_out, out is capped, the count is not).  ts is a monotonic event time in
 * seconds (the caller's clock; the engine only does arithmetic on it).
 *
 * grp_scratch / grp_scratch_cap: CALLER-OWNED, per-worker scratch (an array of
 * max_out * CORR_MAX_GROUP_FIELDS `const char*` slots is ample).  The
 * engine records each fired activation's group-value POINTERS there, and
 * corr_fire_t.group points into it; it must stay valid until the caller has
 * consumed out[].  Pass NULL/0 to omit group evidence (counted as
 * group_evidence_dropped).  Because the slots hold pointers to the caller's
 * field values (from field_fn), those must also stay valid until out[] is
 * consumed.  This makes the engine safe for concurrent callers: no fired-group
 * storage is shared between workers. */
int corr_on_event(corr_engine_t* e,
                  const uint32_t* matched_rids,
                  size_t n_rids,
                  corr_field_fn field_fn,
                  void* field_ctx,
                  double ts,
                  corr_fire_t* out,
                  size_t max_out,
                  const char** grp_scratch,
                  size_t grp_scratch_cap);

/* Return 1 to apply this correlation locally, 0 to skip (caller will emit a
 * contribution for a remote owner). NULL apply => always apply. */
typedef int (*corr_apply_fn)(void* ctx, const corr_rule_t* r, const char* const* group_vals, size_t n_group);

int corr_on_event_apply(corr_engine_t* e,
                        const uint32_t* matched_rids,
                        size_t n_rids,
                        corr_field_fn field_fn,
                        void* field_ctx,
                        double ts,
                        corr_fire_t* out,
                        size_t max_out,
                        const char** grp_scratch,
                        size_t grp_scratch_cap,
                        corr_apply_fn apply,
                        void* apply_ctx);

/* djb2 hash of corr_id + TAB + group values, modulo n_peers: which peer owns
 * this group when correlation state is sharded across instances.
 * n_peers==0 returns 0. */
size_t corr_owner_index(const char* corr_id, const char* const* group_vals, size_t n_group, size_t n_peers);

/* Render the routing key the caller's transport should hash to reach the owner:
 * "id\\tval0\\tval1...".
 * Returns bytes written excluding NUL, 0 if buf too small. */
size_t corr_owner_key(char* buf, size_t cap, const char* corr_id, const char* const* group_vals, size_t n_group);

/* Merge kind for this type, or -1 if it must stay local (temporal_ordered,
 * beaconing, percentile/median). */
int corr_contrib_kind_for(corr_type_t t);

const corr_rule_t* corr_engine_rule_at(const corr_engine_t* e, size_t i);

int corr_rule_hits(const corr_rule_t* r, const uint32_t* rids, size_t n_rids);

/* A contribution is a compact, transport-agnostic input to the engine. The
 * local pipeline builds an EVENT contribution from a matched log line
 * (corr_on_event is a wrapper). A remote peer can feed COUNT / SUM / DISTINCT /
 * SEEN partials that MERGE into the same group state instead of replaying
 * events. No sockets live here. */
typedef enum {
    CORR_CONTRIB_EVENT = 0, /* one matched event; uses field_fn for group-by / value */
    CORR_CONTRIB_COUNT, /* merge: add `count` to event_count (and avg n) */
    CORR_CONTRIB_SUM, /* merge: add `numeric` into value_sum / avg / percentile */
    CORR_CONTRIB_DISTINCT, /* merge: observe one distinct `value` (value_count) */
    CORR_CONTRIB_SEEN /* merge: OR `seen_mask` into temporal seen-set */
} corr_contrib_kind_t;

typedef struct {
    corr_contrib_kind_t kind;
    const char* corr_id; /* required for merge kinds; NULL on EVENT (dispatch by rids) */
    const uint32_t* rids; /* EVENT: matched base rids; unused for merge kinds */
    size_t n_rids;
    const char* const* group_vals; /* merge kinds: already-resolved group-by values */
    size_t n_group;
    double ts; /* event time (same clock as corr_on_event) */
    const char* value; /* DISTINCT: the distinct string; EVENT unused */
    double numeric; /* SUM: the addend */
    uint32_t count; /* COUNT: how many to add; SUM: optional n (default 1) */
    uint64_t seen_mask; /* SEEN: bits matching base_rule_ids local indices */
} corr_contrib_t;

/* Apply one contribution. EVENT with corr_id==NULL is equivalent to
 * corr_on_event (field_fn must be set). Merge kinds ignore field_fn and
 * require corr_id + group_vals. Returns the number of fires (may exceed
 * max_out; out is capped). */
int corr_on_contribution(corr_engine_t* e,
                         const corr_contrib_t* c,
                         corr_field_fn field_fn,
                         void* field_ctx,
                         corr_fire_t* out,
                         size_t max_out,
                         const char** grp_scratch,
                         size_t grp_scratch_cap);

#ifdef __cplusplus
}
#endif

#endif /* CLASSIFY_CORR_H */
