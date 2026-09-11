/* sigma_match.h
 * Sigma selection-match core: a stateless, per-event matcher for compiled Sigma
 * rules.  This unit has NO third-party dependency, it operates on an
 * already-parsed event exposed through a single field-lookup callback, plus
 * a compiled, read-only rule database (sigma_db_t).  That keeps it self-contained
 * and reusable: the bundled sigma_cli is one caller, a host log-pipeline module
 * is another.
 *
 * Sigma YAML is compiled to the binary artifact loaded here (see sigma_format.h);
 * YAML is never interpreted at match time.  Stateful Sigma correlation rules
 * (event_count/value_count/temporal[_ordered]) are out of scope for this unit,
 * which answers one question per event: which selection-match rules fire, and
 * with what verdict.
 *
 * Threading: a sigma_db_t is immutable after load and shared read-only across
 * worker threads.  Per-thread mutable scratch lives in sigma_eval_t, create
 * one per thread, reuse across events.
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

#ifndef SIGMA_MATCH_H
#define SIGMA_MATCH_H

#include <stdint.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

/* ============================================================================
 * Predicate operators.  Map 1:1 to Sigma value modifiers.
 * The numeric ops use sigma_pred_t.ival; string ops use value_id.
 * ========================================================================== */
typedef enum {
    SIGMA_OP_EQ = 0, /* exact match (case-insensitive unless SIGMA_PF_CASE) */
    SIGMA_OP_CONTAINS, /* |contains   */
    SIGMA_OP_STARTSWITH, /* |startswith */
    SIGMA_OP_ENDSWITH, /* |endswith   */
    SIGMA_OP_EXISTS, /* |exists: field present and non-empty (value_id ignored) */
    SIGMA_OP_GT, /* |gt   (numeric, ival) */
    SIGMA_OP_GTE, /* |gte  */
    SIGMA_OP_LT, /* |lt   */
    SIGMA_OP_LTE, /* |lte  */
    SIGMA_OP_RE, /* |re   (PCRE2-backed regex; sigma_db_finalize compiles) */
    SIGMA_OP_CIDR, /* |cidr (pre-parsed network operand, sigma_cidr_t) */
    SIGMA_OP_NUMEQ, /* prefilter: integer equality after sg_to_i64 (field: 80) */
    SIGMA_OP__MAX
} sigma_op_t;

/* Predicate flags. */
#define SIGMA_PF_CASE 0x01 /* case-sensitive string compare (default: insensitive) */
#define SIGMA_PF_NEGATE 0x02 /* logical NOT of this single predicate (Sigma field|...|not idiom) */
#define SIGMA_PF_FIELDREF                                                                   \
    0x04 /* Sigma |fieldref: the operand is another FIELD's value, so value_id indexes the  \
          * fields table (not values). Combines with the string ops EQ/CONTAINS/STARTSWITH/ \
          * ENDSWITH and with SIGMA_PF_CASE. */

/* Verdict for a matched rule (benign = advisory suppression hint). */
typedef enum { SIGMA_VERDICT_ALERT = 0, SIGMA_VERDICT_BENIGN = 1, SIGMA_VERDICT_ESCALATE = 2 } sigma_verdict_t;

/* ----------------------------------------------------------------------------
 * Compiled rule model.  Sigma map-selection semantics are encoded as
 * "AND across groups of OR within a group":
 *   selection: { fieldA: [x, y], fieldB: z }
 *   => group 0 = (fieldA==x OR fieldA==y), group 1 = (fieldB==z), AND them.
 * Predicates within a selection are emitted grouped & contiguous by the
 * builder; the matcher relies on that ordering.
 * -------------------------------------------------------------------------- */
typedef struct {
    uint16_t field_id; /* index into sigma_db_t.fields */
    uint16_t group_id; /* OR within equal group_id, AND across distinct groups */
    uint8_t op; /* sigma_op_t */
    uint8_t flags; /* SIGMA_PF_* */
    uint8_t _pad[2];
    uint32_t value_id; /* index into sigma_db_t.values, or SIGMA_NO_VALUE */
    int64_t ival; /* numeric operand (GT/GTE/LT/LTE) */
} sigma_pred_t;

#define SIGMA_NO_VALUE 0xFFFFFFFFu

typedef struct {
    uint32_t pred_start; /* first predicate (index into sigma_db_t.preds) */
    uint32_t pred_count; /* number of predicates in this selection */
} sigma_sel_t;

/* Condition RPN token.  sel_idx is LOCAL to the rule (0 .. rule.sel_count-1). */
typedef enum {
    SIGMA_C_SEL = 0, /* push selection result */
    SIGMA_C_AND,
    SIGMA_C_OR,
    SIGMA_C_NOT
} sigma_ctok_kind_t;

typedef struct {
    uint8_t kind; /* sigma_ctok_kind_t */
    uint8_t _pad[3];
    uint32_t sel_idx; /* used when kind == SIGMA_C_SEL */
} sigma_ctok_t;

typedef struct {
    uint32_t rule_id;
    uint32_t sel_start, sel_count; /* this rule's selections (index into .sels) */
    uint32_t cond_start, cond_count; /* RPN tokens (.cond); count==0 => AND of all selections */
    uint8_t verdict; /* sigma_verdict_t */
    uint8_t severity; /* 0..4 (info..critical) */
    uint16_t score_x100; /* fixed-point score contribution (e.g. 35 = +0.35) */
    uint32_t name_id; /* rule title (index into .values), or SIGMA_NO_VALUE */
    uint32_t mitre_id; /* primary MITRE technique string e.g. "T1059.001"
                          (index into .values), or SIGMA_NO_VALUE.  Resolved to a
                          strpool pointer at match time (sigma_hit_t.mitre). */
} sigma_rule_t;

typedef struct {
    uint32_t off; /* byte offset into strpool */
    uint32_t len; /* length (no NUL required) */
} sigma_str_t;

/* Pre-parsed CIDR operand (SIGMA_OP_CIDR).  The predicate's value_id indexes
 * this table (NOT the string `values` table).  Network is pre-masked at
 * compile/load time so matching is a family check + a masked compare. */
typedef struct {
    uint8_t family; /* 4 (IPv4) or 6 (IPv6) */
    uint8_t prefix; /* 0..32 for v4, 0..128 for v6 */
    uint8_t _pad[2];
    uint8_t net[16]; /* network address, already masked (v4 uses net[0..3]) */
} sigma_cidr_t;

/* Bucket descriptor (.sigmac).  One per bucket key; the key string
 * is the parallel entry in the `bkeys` table (an ECS event.category token such
 * as "web"/"network"/"dns"/"authentication", or the empty string for the
 * always-verify bucket).  [idx_start, idx_start+idx_count) is a contiguous slice
 * of the flat rule-index pool (sigma_db_t.bucket_idx); each entry is an INDEX
 * into sigma_db_t.rules (NOT a rule_id).  A rule that could match an event of
 * this category appears in this bucket; category-agnostic / no-logsource rules
 * appear only in the always-verify bucket (bucket key ""). */
typedef struct {
    uint32_t idx_start; /* first entry into sigma_db_t.bucket_idx */
    uint32_t idx_count; /* number of rule indices in this bucket */
} sigma_bucket_t;

/* Per-needle postings descriptor (.sigmac).  One per prefilter
 * needle (parallel to the `litndl` case-folded needle table); [idx_start,
 * idx_start+idx_count) slices the flat postings pool (sigma_db_t.litpost_ref).
 * Same shape as sigma_bucket_t but a distinct type for clarity. */
typedef struct {
    uint32_t idx_start; /* first entry into sigma_db_t.litpost_ref */
    uint32_t idx_count; /* number of postings entries for this needle */
} sigma_litpost_t;

/* One postings entry: "this needle, occurring in THIS field, satisfies witness
 * clause `clause_idx` of rule `rule_idx`".
 *
 * The compiler derives a rule's necessary-literal CNF: a conjunction of clauses,
 * each a disjunction of (field, literal) pairs, such that
 *
 *     the rule matches an event  ==>  every clause has at least one of its
 *                                     literals present in its named field.
 *
 * The matcher therefore gates a rule in only once EVERY clause has been
 * satisfied, and only counts a literal towards a clause when it was found in the
 * field that clause names.  Both are candidate restrictions, never decisions:
 * the full rule still verifies, and a rule with no sound literal at all is in
 * the always-verify set and is never gated. */
typedef struct {
    uint32_t rule_idx; /* INDEX into sigma_db_t.rules */
    uint16_t field_id; /* field the literal must occur in, or SIGMA_LITREF_ANY_FIELD */
    uint8_t clause_idx; /* which witness clause of the rule this satisfies */
    uint8_t _pad;
} sigma_litref_t;

#define SIGMA_LITREF_ANY_FIELD 0xFFFFu /* unscoped: any field counts */
#define SIGMA_MAX_CLAUSES 32u /* clauses tracked per rule (one uint32 bitmask) */

/* Field witness (.sigmac v5): a necessary numeric/CIDR atom of a CNF clause.
 * Same soundness contract as a string literal posting: if the atom holds, that
 * clause is satisfied. Evaluated by a field lookup + integer/CIDR test, not
 * Teddy. ival is the numeric rhs, or the cidrs-table index when op==CIDR. */
typedef struct {
    uint32_t rule_idx;
    uint16_t field_id;
    uint8_t clause_idx;
    uint8_t op; /* GT/GTE/LT/LTE/CIDR/NUMEQ */
    int64_t ival;
} sigma_fwit_t;

/* The compiled, read-only rule database.  Built in memory (sigma_builder) or
 * loaded from the binary artifact (sigma_db_load_*).  Immutable. */
typedef struct sigma_db {
    sigma_str_t* fields;
    uint32_t n_fields;
    sigma_str_t* values;
    uint32_t n_values;
    sigma_pred_t* preds;
    uint32_t n_preds;
    sigma_sel_t* sels;
    uint32_t n_sels;
    sigma_ctok_t* cond;
    uint32_t n_cond;
    sigma_rule_t* rules;
    uint32_t n_rules;
    sigma_cidr_t* cidrs;
    uint32_t n_cidrs;
    char* strpool;
    uint32_t strpool_len;
    /* Bucket index (.sigmac), optional match-time accelerator.
     * n_buckets==0 => matcher falls back to the full linear
     * scan.  bucket_keys[i] names bucket i (an event.category token; "" =
     * always-verify); buckets[i] slices bucket_idx; bucket_idx entries are
     * INDICES into `rules`.  av_bucket caches the always-verify bucket index
     * (UINT32_MAX if none), resolved at load. */
    sigma_str_t* bucket_keys;
    uint32_t n_buckets;
    sigma_bucket_t* buckets; /* parallel to bucket_keys (n_buckets entries) */
    uint32_t* bucket_idx;
    uint32_t n_bucket_idx;
    uint32_t av_bucket; /* index of the always-verify bucket, or UINT32_MAX */
    uint32_t cat_field_id; /* field_id of "event.category" in `fields`, or
                            * UINT32_MAX if no compiled field uses it */
    /* Literal-prefilter index (.sigmac).  Arch-neutral on disk;
     * the matcher builds the arch-specific Teddy matcher (`teddy`) from these at
     * load (sigma_db_finalize).  n_litndl==0 and n_fwit==0 => no prefilter:
     * the bucket scan evaluates every rule in the bucket.  litndl[i] is a
     * case-folded needle; litpost[i] slices litpost_ref.  Each litpost_ref
     * entry is a (rule, field, clause) posting: the needle, found in that field,
     * satisfies that witness clause of the rule.  fwit entries are numeric/CIDR
     * atoms of the same CNF.  A rule becomes a candidate only once every clause
     * is satisfied.  litav lists rule indices with no sound required atom
     * (NEVER prefiltered out). */
    sigma_str_t* litndl;
    uint32_t n_litndl; /* parallel to litpost */
    sigma_litpost_t* litpost; /* per-needle postings (n_litndl entries) */
    sigma_litref_t* litpost_ref;
    uint32_t n_litpost_ref;
    uint32_t* litav;
    uint32_t n_litav; /* always-verify rule indices */
    uint8_t* rule_clauses; /* [n_rules] witness clauses per rule (0 = always-verify) */
    sigma_fwit_t* fwit; /* numeric/CIDR CNF atoms (v5); NULL if none */
    uint32_t n_fwit;
    void* teddy; /* full-needle Teddy (sigma_finalize), owned; NULL if no litidx */
    void** field_teddy; /* [n_fields] per-field subset Teddies, owned; NULL if unused */
    /* Derived at finalize, owned, not on disk: per-bucket set of field ids any of
     * that bucket's predicates name, so the prefilter scans only the text a rule
     * in scope could require a literal in.  `lit_any_field` disables that
     * narrowing when the artifact carries an unscoped posting, whose literal
     * could be required in a field outside the bucket's set. */
    uint8_t* bucket_fields;
    uint32_t bucket_fields_stride; /* bytes per bucket bitmap */
    uint8_t lit_any_field;
    void* re; /* compiled regex side-table (sigma_finalize), owned; NULL until built */
    void* backing; /* owned file/buffer to free on db_free; NULL if caller-owned */
    uint32_t n_re_skipped; /* RE predicates that failed to compile (PCRE2), disabled, not fatal */
} sigma_db_t;

/* Resolve a field value for the current event.  Return NULL if absent.
 * *out_len receives the value length.  The pointer must stay valid for the
 * duration of one sigma_eval_run() call. */
typedef const char* (*sigma_field_fn)(void* ctx, const char* name, uint32_t name_len, size_t* out_len);

/* Per-thread evaluation scratch (field-resolution memo cache). */
typedef struct sigma_eval sigma_eval_t;

/* A fired rule.  `mitre`/`mitre_len` carry the rule's primary MITRE technique
 * (e.g. "T1059.001"), resolved from the db strpool at match time; mitre==NULL
 * (mitre_len==0) when the rule carries no technique (SIGMA_NO_VALUE).  The
 * pointer is into the db's immutable strpool, valid for the db's lifetime. */
typedef struct {
    uint32_t rule_id;
    uint8_t verdict;
    uint8_t severity;
    uint16_t score_x100;
    const char* mitre;
    uint32_t mitre_len;
} sigma_hit_t;

/* Per-thread prefilter effectiveness counters, accumulated across events.  The
 * ratio rules_verified / rules_in_scope is what says whether the literal index
 * is earning its keep on a given traffic mix; a prefilter that silently stops
 * narrowing must be visible, not inferred.  The caller can publish the
 * snapshot to its own statistics facility. */
typedef struct {
    uint64_t events; /* sigma_eval_run calls */
    uint64_t rules_in_scope; /* rules the bucket scan would have verified */
    uint64_t rules_verified; /* rules actually run through rule_match */
    uint64_t prefilter_runs; /* events where the literal prefilter ran */
    uint64_t needles_confirmed; /* needles present, summed over events */
    uint64_t chain_steps; /* fingerprint-chain entries examined during confirm */
    uint64_t haystack_bytes; /* searchable text scanned, summed over events */
} sigma_eval_stats_t;

/* Snapshot this scratch's counters (no reset; NULL-safe). */
void sigma_eval_get_stats(const sigma_eval_t* e, sigma_eval_stats_t* out);

/* Zero the counters (NULL-safe).  The bench harness uses this so a soundness
 * pass does not pollute the effectiveness ratio. */
void sigma_eval_reset_stats(sigma_eval_t* e);

/* Create/destroy per-thread scratch bound to a db (sized to db->n_fields). */
sigma_eval_t* sigma_eval_create(const sigma_db_t* db);
void sigma_eval_free(sigma_eval_t* e);

/* Evaluate all rules against one event.  Fills up to max_hits into out[]; the
 * field callback is invoked at most once per distinct field per event.
 * Returns the number of rules that fired (may exceed max_hits, out is capped,
 * the count is not). */
int sigma_eval_run(sigma_eval_t* e, sigma_field_fn fn, void* ctx, sigma_hit_t* out, int max_hits);

/* Set the SIMD literal prefilter mode for this eval scratch:
 *   0 = OFF     , keep bucket narrowing but evaluate EVERY rule in the bucket
 *                  (the oracle for the prefilter soundness gate + the pre-prefilter baseline);
 *   1 = ON      , default: prefilter only large buckets (small buckets skip it
 *                  so they see no regression);
 *   2 = FORCE   , prefilter regardless of bucket size (tests / micro-bench).
 * Production leaves it at the default (1). */
void sigma_eval_set_prefilter(sigma_eval_t* e, int enabled);

/* Force the FULL linear scan (every rule), bypassing the bucket index.
 * Identical semantics to sigma_eval_run on an artifact with no bucket index.
 * Exists for the
 * the correctness gate (assert bucketed hit-set == linear hit-set over a
 * corpus) and for benchmarking the pre-bucketing baseline.  Production uses
 * sigma_eval_run. */
int sigma_eval_run_linear(sigma_eval_t* e, sigma_field_fn fn, void* ctx, sigma_hit_t* out, int max_hits);

/* Compile SIGMA_OP_RE patterns into the db's regex side-table.  Idempotent.
 * Called automatically by sigma_db_load_*; call manually for a builder-made db.
 * Returns 0 on success, -1 on a bad pattern, -2 on OOM. */
int sigma_db_finalize(sigma_db_t* db);

/* Free a db built by the builder or loaded from disk. */
void sigma_db_free(sigma_db_t* db);

#ifdef __cplusplus
}
#endif

#endif /* SIGMA_MATCH_H */
