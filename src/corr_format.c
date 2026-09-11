/* corr_format.c
 * json-c loader for rules.corr.json -> corr_rule_t[].  See corr_format.h.
 * This is the ONLY translation unit that depends on json-c; the engine core and
 * its self-test stay libc-only, so the libc-only acceptance gate does not need
 * a JSON library.
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

#include "corr_format.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

#include <json.h> /* json-c */

/* Absolute ceiling on a correlation's base_rule_ids / ordered_rule_ids array.
 * The artifact is management-tier data but still untrusted input to the loader;
 * this bounds the allocation (an unbounded array length would otherwise request
 * an arbitrary malloc) and the per-rule work.  It is far above any real
 * correlation.  Entries beyond the cap are dropped. */
#define CORR_MAX_RULE_IDS 4096u

/* ----------------------------------------------------------------------------
 * Arena: a simple growable pointer-bag so corr_artifact_free frees every
 * malloc'd string / array in one pass, regardless of which rule referenced it.
 * -------------------------------------------------------------------------- */
typedef struct {
    void** ptrs;
    size_t n, cap;
} arena_t;

struct corr_artifact {
    corr_rule_t* rules; /* the rule array (also tracked in arena for free) */
    size_t n_rules;
    arena_t arena;
};

static int arena_track(arena_t* a, void* p) {
    if (p == NULL) return 0;
    if (a->n == a->cap) {
        size_t nc = a->cap ? a->cap * 2 : 16;
        void** np = realloc(a->ptrs, nc * sizeof(void*));
        if (!np) return -1;
        a->ptrs = np;
        a->cap = nc;
    }
    a->ptrs[a->n++] = p;
    return 0;
}

static char* arena_strdup(arena_t* a, const char* s) {
    if (s == NULL) return NULL;
    size_t len = strlen(s);
    char* p = malloc(len + 1);
    if (!p) return NULL;
    memcpy(p, s, len + 1);
    if (arena_track(a, p) != 0) {
        free(p);
        return NULL;
    }
    return p;
}

/* ----------------------------------------------------------------------------
 * JSON helpers.
 * -------------------------------------------------------------------------- */
static const char* jstr(struct json_object* o, const char* key) {
    struct json_object* v = NULL;
    if (o && json_object_object_get_ex(o, key, &v) && json_object_is_type(v, json_type_string))
        return json_object_get_string(v);
    return NULL;
}

static int jint(struct json_object* o, const char* key, int64_t* out) {
    struct json_object* v = NULL;
    if (o && json_object_object_get_ex(o, key, &v) &&
        (json_object_is_type(v, json_type_int) || json_object_is_type(v, json_type_double))) {
        *out = json_object_get_int64(v);
        return 1;
    }
    return 0;
}

static corr_type_t parse_type(const char* t) {
    if (t == NULL) return CORR_TYPE__MAX;
    if (strcmp(t, "event_count") == 0) return CORR_EVENT_COUNT;
    if (strcmp(t, "value_count") == 0) return CORR_VALUE_COUNT;
    if (strcmp(t, "temporal") == 0) return CORR_TEMPORAL;
    if (strcmp(t, "temporal_ordered") == 0) return CORR_TEMPORAL_ORDERED;
    if (strcmp(t, "value_sum") == 0) return CORR_VALUE_SUM;
    if (strcmp(t, "value_avg") == 0) return CORR_VALUE_AVG;
    if (strcmp(t, "beaconing") == 0) return CORR_BEACONING;
    if (strcmp(t, "value_percentile") == 0) return CORR_VALUE_PERCENTILE;
    if (strcmp(t, "value_median") == 0) return CORR_VALUE_MEDIAN;
    return CORR_TYPE__MAX;
}

static corr_op_t parse_op(const char* op) {
    if (op == NULL) return CORR_OP_GTE;
    if (strcmp(op, "gt") == 0) return CORR_OP_GT;
    if (strcmp(op, "lte") == 0) return CORR_OP_LTE;
    if (strcmp(op, "lt") == 0) return CORR_OP_LT;
    if (strcmp(op, "eq") == 0) return CORR_OP_EQ;
    return CORR_OP_GTE;
}

/* Parse a JSON int array into a heap uint32_t[]; tracks it in the arena.
 * Returns the array (NULL on empty/missing) and writes the count. */
static uint32_t* parse_u32_array(
    arena_t* a, struct json_object* o, const char* key, size_t* out_n, corr_load_stats_t* ls) {
    *out_n = 0;
    struct json_object* arr = NULL;
    if (!o || !json_object_object_get_ex(o, key, &arr) || !json_object_is_type(arr, json_type_array)) return NULL;
    size_t orig = json_object_array_length(arr);
    if (orig == 0) return NULL;
    size_t n = orig;
    if (n > CORR_MAX_RULE_IDS) {
        if (ls) ls->baserules_truncated += (uint64_t)(orig - CORR_MAX_RULE_IDS);
        n = CORR_MAX_RULE_IDS;
    }
    uint32_t* out = malloc(n * sizeof(uint32_t));
    if (!out) return NULL;
    size_t w = 0;
    for (size_t i = 0; i < n; i++) {
        struct json_object* el = json_object_array_get_idx(arr, i);
        int64_t v = json_object_get_int64(el);
        /* rids are matched by equality against uint32 sigma rule_ids; a value
         * outside [0, UINT32_MAX] can never equal a real rule_id.  DROP it
         * rather than truncate, a truncated id could falsely alias a real
         * rule and mis-fire the correlation. */
        if (v < 0 || v > (int64_t)UINT32_MAX) {
            if (ls) ls->rids_dropped++;
            continue;
        }
        out[w++] = (uint32_t)v;
    }
    if (w == 0) {
        free(out);
        return NULL;
    }
    if (arena_track(a, out) != 0) {
        free(out);
        return NULL;
    }
    *out_n = w;
    return out;
}

/* Parse a JSON string array into a heap (const char *)[]; each string is
 * arena-strdup'd, and the array itself tracked. Caps arity at CORR_MAX_GROUP_FIELDS. */
static const char** parse_str_array(
    arena_t* a, struct json_object* o, const char* key, size_t* out_n, corr_load_stats_t* ls) {
    *out_n = 0;
    struct json_object* arr = NULL;
    if (!o || !json_object_object_get_ex(o, key, &arr) || !json_object_is_type(arr, json_type_array)) return NULL;
    size_t n = json_object_array_length(arr);
    if (n == 0) return NULL;
    if (n > CORR_MAX_GROUP_FIELDS) {
        if (ls) ls->groupby_truncated += (uint64_t)(n - CORR_MAX_GROUP_FIELDS);
        n = CORR_MAX_GROUP_FIELDS;
    }
    const char** out = malloc(n * sizeof(char*));
    if (!out) return NULL;
    for (size_t i = 0; i < n; i++) {
        struct json_object* el = json_object_array_get_idx(arr, i);
        const char* s = json_object_is_type(el, json_type_string) ? json_object_get_string(el) : "";
        out[i] = arena_strdup(a, s);
        if (out[i] == NULL) {
            free(out);
            return NULL;
        }
    }
    if (arena_track(a, (void*)out) != 0) {
        free(out);
        return NULL;
    }
    *out_n = n;
    return out;
}

/* SEP #198: parse "condition_rpn" (postfix boolean over base-rule LOCAL indices)
 * into a corr_ctok_t[]. Tokens: {"k":"sel","r":<idx>} | {"k":"and"|"or"|"not"}.
 * Every sel.r must be < n_base (and < 64, the seen_mask width). Any malformed
 * token set returns NULL => the caller rejects the whole rule (never aborts the
 * load). Empty array => NULL (legacy all-fired semantics). */
#define CORR_MAX_COND_TOKENS 256
static corr_ctok_t* parse_cond_rpn(arena_t* a, struct json_object* arr, size_t n_base, size_t* out_n) {
    *out_n = 0;
    size_t n = json_object_array_length(arr);
    if (n == 0 || n > CORR_MAX_COND_TOKENS) return NULL;
    corr_ctok_t* out = calloc(n, sizeof(corr_ctok_t));
    if (!out) return NULL;
    for (size_t i = 0; i < n; i++) {
        struct json_object* el = json_object_array_get_idx(arr, i);
        const char* k = (el && json_object_is_type(el, json_type_object)) ? jstr(el, "k") : NULL;
        if (k == NULL) {
            free(out);
            return NULL;
        }
        if (strcmp(k, "sel") == 0) {
            int64_t r = -1;
            if (!jint(el, "r", &r) || r < 0 || (size_t)r >= n_base || r >= 64) {
                free(out);
                return NULL;
            }
            out[i].kind = CORR_C_SEL;
            out[i].rid_idx = (uint32_t)r;
        } else if (strcmp(k, "and") == 0) {
            out[i].kind = CORR_C_AND;
        } else if (strcmp(k, "or") == 0) {
            out[i].kind = CORR_C_OR;
        } else if (strcmp(k, "not") == 0) {
            out[i].kind = CORR_C_NOT;
        } else {
            free(out);
            return NULL;
        }
    }
    if (arena_track(a, out) != 0) {
        free(out);
        return NULL;
    }
    *out_n = n;
    return out;
}

/* ----------------------------------------------------------------------------
 * The parse.
 * -------------------------------------------------------------------------- */
static int parse_one(arena_t* a, struct json_object* c, corr_rule_t* out, corr_load_stats_t* ls) {
    memset(out, 0, sizeof(*out));
    out->type = parse_type(jstr(c, "type"));
    out->id = arena_strdup(a, jstr(c, "id"));
    out->title = arena_strdup(a, jstr(c, "title"));
    out->level = arena_strdup(a, jstr(c, "level"));
    out->mitre = arena_strdup(a, jstr(c, "mitre"));

    size_t n;
    out->base_rule_ids = parse_u32_array(a, c, "base_rule_ids", &n, ls);
    out->n_base_rule_ids = n;
    out->ordered_rule_ids = parse_u32_array(a, c, "ordered_rule_ids", &n, ls);
    out->n_ordered_rule_ids = n;
    out->group_by = parse_str_array(a, c, "group_by", &n, ls);
    out->n_group_by = n;

    /* Optional Sigma correlation aliases: array of string arrays, one row
     * per base_rule_ids entry, each row n_group_by field names. Absent =>
     * NULL (use group_by). Present but wrong shape rejects the rule. */
    {
        struct json_object* ag = NULL;
        if (json_object_object_get_ex(c, "alias_group_by", &ag) && json_object_is_type(ag, json_type_array)) {
            size_t n_rows = json_object_array_length(ag);
            if (n_rows != out->n_base_rule_ids || out->n_group_by == 0) return -1;
            const char*** rows = malloc(n_rows * sizeof(char**));
            if (!rows) return -1;
            for (size_t i = 0; i < n_rows; i++) {
                struct json_object* row = json_object_array_get_idx(ag, i);
                if (!json_object_is_type(row, json_type_array) ||
                    (size_t)json_object_array_length(row) != out->n_group_by) {
                    free(rows);
                    return -1;
                }
                const char** fields = malloc(out->n_group_by * sizeof(char*));
                if (!fields) {
                    free(rows);
                    return -1;
                }
                for (size_t g = 0; g < out->n_group_by; g++) {
                    struct json_object* el = json_object_array_get_idx(row, g);
                    const char* s = json_object_is_type(el, json_type_string) ? json_object_get_string(el) : "";
                    fields[g] = arena_strdup(a, s);
                    if (fields[g] == NULL) {
                        free(fields);
                        free(rows);
                        return -1;
                    }
                }
                if (arena_track(a, (void*)fields) != 0) {
                    free(fields);
                    free(rows);
                    return -1;
                }
                rows[i] = fields;
            }
            if (arena_track(a, (void*)rows) != 0) {
                free(rows);
                return -1;
            }
            out->alias_group_by = (const char* const* const*)rows;
            out->n_alias_group_by = n_rows;
        }
    }

    int64_t ts = 0;
    if (jint(c, "timespan_s", &ts)) {
        /* Clamp rather than truncate int64 -> int32: a huge timespan must not
         * wrap to a small positive value and silently shrink the correlation
         * window.  Non-positive is rejected later by rule_valid. */
        if (ts > INT32_MAX) ts = INT32_MAX;
        out->timespan_s = (int32_t)ts;
    }

    struct json_object* cond = NULL;
    if (json_object_object_get_ex(c, "condition", &cond) && json_object_is_type(cond, json_type_object)) {
        out->cond_op = parse_op(jstr(cond, "op"));
        int64_t cnt = 0;
        if (jint(cond, "count", &cnt)) out->cond_count = cnt;
        out->value_field = arena_strdup(a, jstr(cond, "field"));
        /* beaconing: max inter-arrival CV tolerance, per-mille. Clamp int64->int32
         * defensively (rule_valid rejects non-positive). */
        int64_t cvpm = 0;
        if (jint(cond, "cv_permille", &cvpm)) {
            if (cvpm > INT32_MAX) cvpm = INT32_MAX;
            if (cvpm < INT32_MIN) cvpm = INT32_MIN;
            out->beacon_cv_permille = (int32_t)cvpm;
        }
        /* value_percentile: k in P_k (1..100). Absent => 0 (engine defaults 95). */
        int64_t pct = 0;
        if (jint(cond, "percentile", &pct)) {
            if (pct > INT32_MAX) pct = INT32_MAX;
            if (pct < INT32_MIN) pct = INT32_MIN;
            out->value_percentile = (int32_t)pct;
        }
        /* beaconing horizon: 0/absent = raw ev_ts mode, >0 = bucketed. */
        int64_t nbk = 0;
        if (jint(cond, "n_buckets", &nbk)) {
            if (nbk > INT32_MAX) nbk = INT32_MAX;
            if (nbk < INT32_MIN) nbk = INT32_MIN;
            out->beacon_n_buckets = (int32_t)nbk;
        }
    } else {
        out->cond_op = CORR_OP_GTE;
    }

    /* SEP #198 optional boolean condition (postfix RPN over base-rule indices).
     * Present-but-malformed rejects the rule; absent keeps all-fired semantics. */
    struct json_object* rpn = NULL;
    if (json_object_object_get_ex(c, "condition_rpn", &rpn) && json_object_is_type(rpn, json_type_array)) {
        out->cond = parse_cond_rpn(a, rpn, out->n_base_rule_ids, &out->n_cond);
        if (out->cond == NULL) return -1;
    }

    /* Defensive: id is mandatory; the engine also re-validates and skips. */
    return (out->id != NULL) ? 0 : -1;
}

corr_artifact_t* corr_artifact_parse(const char* json, size_t len, struct corr_artifact_view* out_view) {
    if (out_view) {
        out_view->rules = NULL;
        out_view->n = 0;
        memset(&out_view->load, 0, sizeof(out_view->load));
    }
    if (json == NULL) return NULL;
    (void)len; /* json-c parses a NUL-terminated string */

    struct json_object* root = json_tokener_parse(json);
    if (root == NULL) return NULL;

    /* Frozen artifact: object with version==1 and a correlations array.
     * A bare list or a missing/wrong version is a reject (NULL), not a
     * partial load. sigmac emits {"version":1,"correlations":[...]}. */
    struct json_object* arr = NULL;
    if (json_object_is_type(root, json_type_object)) {
        struct json_object* ver = NULL;
        if (!json_object_object_get_ex(root, "version", &ver) || !json_object_is_type(ver, json_type_int) ||
            json_object_get_int(ver) != 1) {
            json_object_put(root);
            return NULL;
        }
        if (!json_object_object_get_ex(root, "correlations", &arr) || !json_object_is_type(arr, json_type_array)) {
            json_object_put(root);
            return NULL;
        }
    } else {
        json_object_put(root);
        return NULL;
    }

    corr_artifact_t* a = calloc(1, sizeof(*a));
    if (!a) {
        json_object_put(root);
        return NULL;
    }

    corr_load_stats_t ls = {0, 0, 0, 0};
    size_t n = arr ? json_object_array_length(arr) : 0;
    if (n > 0) {
        a->rules = calloc(n, sizeof(corr_rule_t));
        if (!a->rules) {
            free(a);
            json_object_put(root);
            return NULL;
        }
        for (size_t i = 0; i < n; i++) {
            struct json_object* c = json_object_array_get_idx(arr, i);
            if (!json_object_is_type(c, json_type_object)) {
                ls.rules_rejected++;
                continue;
            }
            corr_rule_t r;
            if (parse_one(&a->arena, c, &r, &ls) == 0)
                a->rules[a->n_rules++] = r;
            else
                ls.rules_rejected++;
            /* a failed parse_one is skipped (tolerant loader);
             * any strings it already arena-tracked are freed at artifact free. */
        }
    }

    json_object_put(root); /* we copied every string we need into the arena */

    if (out_view) {
        out_view->rules = a->rules;
        out_view->n = a->n_rules;
        out_view->load = ls;
    }
    return a;
}

corr_artifact_t* corr_artifact_load_file(const char* path, struct corr_artifact_view* out_view) {
    if (out_view) {
        out_view->rules = NULL;
        out_view->n = 0;
        memset(&out_view->load, 0, sizeof(out_view->load));
    }
    FILE* f = fopen(path, "rb");
    if (!f) return NULL;
    if (fseek(f, 0, SEEK_END) != 0) {
        fclose(f);
        return NULL;
    }
    long sz = ftell(f);
    if (sz < 0 || fseek(f, 0, SEEK_SET) != 0) {
        fclose(f);
        return NULL;
    }
    char* buf = malloc((size_t)sz + 1);
    if (!buf) {
        fclose(f);
        return NULL;
    }
    size_t rd = fread(buf, 1, (size_t)sz, f);
    fclose(f);
    buf[rd] = '\0';
    corr_artifact_t* a = corr_artifact_parse(buf, rd, out_view);
    free(buf);
    return a;
}

void corr_artifact_free(corr_artifact_t* a) {
    if (!a) return;
    for (size_t i = 0; i < a->arena.n; i++) free(a->arena.ptrs[i]);
    free(a->arena.ptrs);
    free(a->rules);
    free(a);
}
