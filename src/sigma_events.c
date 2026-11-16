/* sigma_events.c
 * JSON front end for the matcher and the correlator.  See sigma_events.h for
 * the event model and the answer schemas.
 *
 * Explain never re-implements an operator.  It points a one-rule view of the
 * loaded db (same fields, values, predicates, CIDRs, regex table, string pool)
 * at a single predicate or selection and runs sigma_eval_run_linear on it, so
 * every verdict it reports comes from the matcher's own code.
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

#define _POSIX_C_SOURCE 200809L

#include "sigma_events.h"

#include "classify_corr.h"
#include "corr_format.h"
#include "event_time.h"
#include "sigma_format.h"
#include "sigma_match.h"

#include <limits.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include <json.h>

#define EV_NAME_MAX 1024u /* longest field name resolved */
#define EV_SEG_MAX 128u /* a path segment this long or longer is absent */
#define SB_MAX ((size_t)64 << 20) /* largest answer */
#define CORR_FIRES_MAX 64u /* fires reported per event; more are counted */

/* ----------------------------------------------------------------------------
 * Answer builder: a growable buffer with a hard ceiling.
 * -------------------------------------------------------------------------- */
typedef struct {
    char* buf;
    size_t len;
    size_t cap;
    int failed; /* allocation failed or the ceiling was hit */
    int too_large; /* the ceiling was hit */
} sb_t;

static void sb_reserve(sb_t* b, size_t extra) {
    if (b->failed) return;
    if (extra > SB_MAX - b->len) {
        b->failed = 1;
        b->too_large = 1;
        return;
    }
    size_t need = b->len + extra + 1;
    if (need <= b->cap) return;
    size_t nc = b->cap ? b->cap : 256;
    while (nc < need) nc = (nc > SB_MAX / 2) ? SB_MAX + 1 : nc * 2;
    char* nb = realloc(b->buf, nc);
    if (nb == NULL) {
        b->failed = 1;
        return;
    }
    b->buf = nb;
    b->cap = nc;
}

static void sb_put(sb_t* b, const char* s, size_t n) {
    sb_reserve(b, n);
    if (b->failed) return;
    memcpy(b->buf + b->len, s, n);
    b->len += n;
    b->buf[b->len] = '\0';
}

static void sb_lit(sb_t* b, const char* s) {
    sb_put(b, s, strlen(s));
}

/* Short formatted pieces only (numbers with their keys): longer output is a
 * builder failure, never a cut. */
static void sb_fmt(sb_t* b, const char* fmt, ...) {
    char tmp[256];
    va_list ap;
    va_start(ap, fmt);
    int n = vsnprintf(tmp, sizeof(tmp), fmt, ap);
    va_end(ap);
    if (n < 0 || (size_t)n >= sizeof(tmp)) {
        b->failed = 1;
        return;
    }
    sb_put(b, tmp, (size_t)n);
}

/* s[0..n) as a quoted JSON string.  Bytes >= 0x80 pass through unchanged. */
static void sb_jstr(sb_t* b, const char* s, size_t n) {
    static const char hex[] = "0123456789abcdef";
    size_t run = 0;

    sb_put(b, "\"", 1);
    for (size_t i = 0; i < n; i++) {
        unsigned char c = (unsigned char)s[i];
        if (c >= 0x20 && c != '"' && c != '\\') continue;
        sb_put(b, s + run, i - run);
        run = i + 1;
        if (c == '"' || c == '\\') {
            char e[2] = {'\\', (char)c};
            sb_put(b, e, 2);
        } else if (c == '\n') {
            sb_put(b, "\\n", 2);
        } else if (c == '\t') {
            sb_put(b, "\\t", 2);
        } else if (c == '\r') {
            sb_put(b, "\\r", 2);
        } else {
            char e[6] = {'\\', 'u', '0', '0', hex[c >> 4], hex[c & 0x0f]};
            sb_put(b, e, 6);
        }
    }
    sb_put(b, s + run, n - run);
    sb_put(b, "\"", 1);
}

static void sb_cstr(sb_t* b, const char* s) {
    if (s == NULL)
        sb_lit(b, "null");
    else
        sb_jstr(b, s, strlen(s));
}

static void sb_bool(sb_t* b, int v) {
    sb_lit(b, v ? "true" : "false");
}

static char* err_json(const char* msg);

static char* sb_finish(sb_t* b) {
    if (!b->failed) return b->buf;
    free(b->buf);
    b->buf = NULL;
    if (b->too_large) return err_json("result too large");
    return NULL;
}

static char* err_json(const char* msg) {
    sb_t b = {0};
    sb_lit(&b, "{\"ok\":false,\"error\":");
    sb_cstr(&b, msg);
    sb_lit(&b, "}");
    if (b.failed) {
        free(b.buf);
        return NULL;
    }
    return b.buf;
}

/* ----------------------------------------------------------------------------
 * Engine.
 * -------------------------------------------------------------------------- */
typedef struct {
    uint32_t rule_id;
    uint32_t idx;
} rid_ix_t;

struct sigma_events {
    sigma_db_t db;
    sigma_eval_t* eval;
    sigma_hit_t* hits; /* n_rules entries: a rule fires at most once per event */
    int hits_cap;
    rid_ix_t* ix; /* rule_id -> rule index, sorted */
    /* One-rule view for explain.  Shares db's tables, owns nothing. */
    sigma_db_t view;
    sigma_rule_t vrule;
    sigma_sel_t vsel;
    sigma_eval_t* veval;
};

static int rid_cmp(const void* a, const void* b) {
    const rid_ix_t* x = a;
    const rid_ix_t* y = b;
    if (x->rule_id != y->rule_id) return x->rule_id < y->rule_id ? -1 : 1;
    if (x->idx != y->idx) return x->idx < y->idx ? -1 : 1;
    return 0;
}

/* First rule (lowest table index) carrying rule_id, or NULL. */
static const sigma_rule_t* rule_by_id(const sigma_events_t* se, uint32_t rule_id) {
    size_t lo = 0, hi = se->db.n_rules;
    while (lo < hi) {
        size_t mid = lo + (hi - lo) / 2;
        if (se->ix[mid].rule_id < rule_id)
            lo = mid + 1;
        else
            hi = mid;
    }
    if (lo < se->db.n_rules && se->ix[lo].rule_id == rule_id) return &se->db.rules[se->ix[lo].idx];
    return NULL;
}

static int pool_str(
    const sigma_db_t* db, const sigma_str_t* tab, uint32_t n, uint32_t id, const char** s, size_t* len) {
    if (tab == NULL || id == SIGMA_NO_VALUE || id >= n) return 0;
    if (tab[id].off > db->strpool_len || tab[id].len > db->strpool_len - tab[id].off) return 0;
    *s = db->strpool + tab[id].off;
    *len = tab[id].len;
    return 1;
}

static void view_init(sigma_events_t* se) {
    sigma_db_t* v = &se->view;

    *v = se->db;
    v->rules = &se->vrule;
    v->n_rules = 1;
    v->sels = &se->vsel;
    v->n_sels = 1;
    v->cond = NULL;
    v->n_cond = 0;
    v->bucket_keys = NULL;
    v->n_buckets = 0;
    v->buckets = NULL;
    v->bucket_idx = NULL;
    v->n_bucket_idx = 0;
    v->av_bucket = UINT32_MAX;
    v->cat_field_id = UINT32_MAX;
    v->litndl = NULL;
    v->n_litndl = 0;
    v->litpost = NULL;
    v->litpost_ref = NULL;
    v->n_litpost_ref = 0;
    v->litav = NULL;
    v->n_litav = 0;
    v->rule_clauses = NULL;
    v->fwit = NULL;
    v->n_fwit = 0;
    v->teddy = NULL;
    v->field_teddy = NULL;
    v->bucket_fields = NULL;
    v->bucket_fields_stride = 0;
    v->lit_any_field = 0;
    v->backing = NULL;
}

sigma_events_t* sigma_events_load(const uint8_t* buf, size_t len, int* status) {
    int dummy;
    if (status == NULL) status = &dummy;
    if (buf == NULL || len == 0) {
        *status = SIGMA_ERR_SIZE;
        return NULL;
    }
    sigma_events_t* se = calloc(1, sizeof(*se));
    uint8_t* copy = malloc(len);
    if (se == NULL || copy == NULL) {
        free(se);
        free(copy);
        *status = SIGMA_ERR_NOMEM;
        return NULL;
    }
    memcpy(copy, buf, len);
    int rc = sigma_db_load_buffer(copy, len, &se->db);
    if (rc != SIGMA_OK) {
        free(copy);
        free(se);
        *status = rc;
        return NULL;
    }
    /* The db owns copy from here; sigma_db_free releases it. */
    if (se->db.n_rules > (uint32_t)INT_MAX) {
        sigma_db_free(&se->db);
        free(se);
        *status = SIGMA_ERR_RANGE;
        return NULL;
    }
    view_init(se);
    se->hits_cap = se->db.n_rules ? (int)se->db.n_rules : 1;
    se->hits = calloc((size_t)se->hits_cap, sizeof(*se->hits));
    se->ix = calloc(se->db.n_rules ? se->db.n_rules : 1, sizeof(*se->ix));
    se->eval = sigma_eval_create(&se->db);
    se->veval = sigma_eval_create(&se->view);
    if (se->hits == NULL || se->ix == NULL || se->eval == NULL || se->veval == NULL) {
        sigma_events_free(se);
        *status = SIGMA_ERR_NOMEM;
        return NULL;
    }
    for (uint32_t i = 0; i < se->db.n_rules; i++) {
        se->ix[i].rule_id = se->db.rules[i].rule_id;
        se->ix[i].idx = i;
    }
    qsort(se->ix, se->db.n_rules, sizeof(*se->ix), rid_cmp);
    *status = SIGMA_OK;
    return se;
}

void sigma_events_free(sigma_events_t* se) {
    if (se == NULL) return;
    sigma_eval_free(se->veval);
    sigma_eval_free(se->eval);
    free(se->hits);
    free(se->ix);
    sigma_db_free(&se->db);
    free(se);
}

void sigma_events_str_free(char* s) {
    free(s);
}

/* ----------------------------------------------------------------------------
 * Events.
 * -------------------------------------------------------------------------- */
typedef struct {
    struct json_object** roots; /* owned references, released by evs_free */
    size_t n_roots;
    size_t cap_roots;
    struct json_object** ev; /* borrowed, one per event */
    size_t n;
    size_t cap;
} evs_t;

static void evs_free(evs_t* e) {
    for (size_t i = 0; i < e->n_roots; i++) json_object_put(e->roots[i]);
    free(e->roots);
    free(e->ev);
    memset(e, 0, sizeof(*e));
}

static int grow(struct json_object*** arr, size_t* cap, size_t n) {
    if (n < *cap) return 0;
    size_t nc = *cap ? *cap * 2 : 16;
    struct json_object** na = realloc(*arr, nc * sizeof(*na));
    if (na == NULL) return -1;
    *arr = na;
    *cap = nc;
    return 0;
}

/* Take ownership of a parsed root.  On failure the caller still owns o. */
static int evs_own(evs_t* e, struct json_object* o) {
    if (grow(&e->roots, &e->cap_roots, e->n_roots) != 0) return -1;
    e->roots[e->n_roots++] = o;
    return 0;
}

static int evs_push(evs_t* e, struct json_object* o) {
    if (grow(&e->ev, &e->cap, e->n) != 0) return -1;
    e->ev[e->n++] = o;
    return 0;
}

static int is_ws(char c) {
    return c == ' ' || c == '\t' || c == '\n' || c == '\r';
}

/* Parse text[0..len): one JSON array of objects, or a sequence of objects
 * separated by whitespace (JSON Lines, or pretty-printed objects). */
static int parse_events(const char* text, size_t len, evs_t* out, char* msg, size_t msgcap) {
    memset(out, 0, sizeof(*out));
    if (text == NULL) len = 0;
    size_t pos = 0;
    while (pos < len && is_ws(text[pos])) pos++;
    if (pos == len) {
        snprintf(msg, msgcap, "no events");
        return -1;
    }
    if (len - pos > (size_t)INT_MAX) {
        snprintf(msg, msgcap, "events text too large");
        return -1;
    }
    struct json_tokener* tok = json_tokener_new();
    if (tok == NULL) {
        snprintf(msg, msgcap, "out of memory");
        return -1;
    }
    int rc = -1;
    if (text[pos] == '[') {
        struct json_object* root = json_tokener_parse_ex(tok, text + pos, (int)(len - pos));
        if (root == NULL) {
            snprintf(msg, msgcap, "events: invalid JSON array");
            goto done;
        }
        size_t end = pos + (size_t)tok->char_offset;
        if (evs_own(out, root) != 0) {
            json_object_put(root);
            snprintf(msg, msgcap, "out of memory");
            goto done;
        }
        while (end < len && is_ws(text[end])) end++;
        if (end != len) {
            snprintf(msg, msgcap, "events: data after the array");
            goto done;
        }
        if (!json_object_is_type(root, json_type_array)) {
            snprintf(msg, msgcap, "events: not an array");
            goto done;
        }
        size_t n = (size_t)json_object_array_length(root);
        if (n > SIGMA_EVENTS_MAX) {
            snprintf(msg, msgcap, "more than %u events", SIGMA_EVENTS_MAX);
            goto done;
        }
        for (size_t i = 0; i < n; i++) {
            struct json_object* o = json_object_array_get_idx(root, (int)i);
            if (o == NULL || !json_object_is_type(o, json_type_object)) {
                snprintf(msg, msgcap, "event %zu: not a JSON object", i);
                goto done;
            }
            if (evs_push(out, o) != 0) {
                snprintf(msg, msgcap, "out of memory");
                goto done;
            }
        }
    } else {
        while (pos < len) {
            if (out->n >= SIGMA_EVENTS_MAX) {
                snprintf(msg, msgcap, "more than %u events", SIGMA_EVENTS_MAX);
                goto done;
            }
            json_tokener_reset(tok);
            struct json_object* o = json_tokener_parse_ex(tok, text + pos, (int)(len - pos));
            if (o == NULL) {
                snprintf(msg, msgcap, "event %zu: invalid or incomplete JSON", out->n);
                goto done;
            }
            if (evs_own(out, o) != 0) {
                json_object_put(o);
                snprintf(msg, msgcap, "out of memory");
                goto done;
            }
            if (!json_object_is_type(o, json_type_object)) {
                snprintf(msg, msgcap, "event %zu: not a JSON object", out->n);
                goto done;
            }
            if (evs_push(out, o) != 0) {
                snprintf(msg, msgcap, "out of memory");
                goto done;
            }
            pos += (size_t)tok->char_offset;
            while (pos < len && is_ws(text[pos])) pos++;
        }
    }
    rc = 0;
done:
    json_tokener_free(tok);
    if (rc != 0) evs_free(out);
    return rc;
}

static const char* leaf_value(struct json_object* v, size_t* out_len) {
    if (v == NULL || json_object_is_type(v, json_type_null) || json_object_is_type(v, json_type_object) ||
        json_object_is_type(v, json_type_array))
        return NULL;
    const char* s = json_object_get_string(v);
    if (s == NULL) return NULL;
    *out_len = strlen(s);
    return s;
}

/* sigma_field_fn over one parsed event (ctx is its json_object). */
static const char* ev_field(void* ctx, const char* name, uint32_t name_len, size_t* out_len) {
    struct json_object* root = ctx;
    char key[EV_NAME_MAX];
    struct json_object* v = NULL;

    *out_len = 0;
    if (root == NULL || name == NULL || name_len == 0 || name_len >= EV_NAME_MAX) return NULL;
    memcpy(key, name, name_len);
    key[name_len] = '\0';
    if (json_object_object_get_ex(root, key, &v)) return leaf_value(v, out_len);
    if (strchr(key, '.') == NULL) return NULL;

    struct json_object* cur = root;
    const char* seg = key;
    for (;;) {
        const char* dot = strchr(seg, '.');
        size_t klen = dot ? (size_t)(dot - seg) : strlen(seg);
        char part[EV_SEG_MAX];
        if (klen == 0 || klen >= EV_SEG_MAX) return NULL;
        memcpy(part, seg, klen);
        part[klen] = '\0';
        struct json_object* next = NULL;
        if (!json_object_object_get_ex(cur, part, &next)) return NULL;
        if (dot == NULL) return leaf_value(next, out_len);
        if (next == NULL || !json_object_is_type(next, json_type_object)) return NULL;
        cur = next;
        seg = dot + 1;
    }
}

/* corr_field_fn: same resolution, empty values included. */
static const char* ev_corr_field(void* ctx, const char* name) {
    size_t vlen = 0;
    if (name == NULL) return NULL;
    size_t n = strlen(name);
    if (n >= EV_NAME_MAX) return NULL;
    return ev_field(ctx, name, (uint32_t)n, &vlen);
}

static const char* ev_get(struct json_object* ev, const char* name, size_t* vlen) {
    return ev_field(ev, name, (uint32_t)strlen(name), vlen);
}

static int ev_time(struct json_object* ev, time_t now, double* out) {
    static const char* const names[] = {"@timestamp", "time", "timestamp", "event.created"};
    size_t vlen = 0;
    for (size_t i = 0; i < sizeof(names) / sizeof(names[0]); i++) {
        const char* v = ev_get(ev, names[i], &vlen);
        if (v != NULL && vlen > 0 && event_time_parse(v, vlen, now, out)) return 1;
    }
    size_t dlen = 0, tlen = 0;
    const char* d = ev_get(ev, "event.date", &dlen);
    const char* t = ev_get(ev, "event.time", &tlen);
    if (d != NULL && t != NULL && dlen > 0 && tlen > 0 && dlen + tlen + 2 < 64) {
        char buf[64];
        memcpy(buf, d, dlen);
        buf[dlen] = ' ';
        memcpy(buf + dlen + 1, t, tlen);
        buf[dlen + 1 + tlen] = '\0';
        if (event_time_parse(buf, dlen + 1 + tlen, now, out)) return 1;
    }
    return 0;
}

/* ----------------------------------------------------------------------------
 * Answers.
 * -------------------------------------------------------------------------- */
static const char* verdict_name(uint8_t v) {
    switch (v) {
        case SIGMA_VERDICT_BENIGN:
            return "benign";
        case SIGMA_VERDICT_ESCALATE:
            return "escalate";
        default:
            return "alert";
    }
}

static const char* op_name(uint8_t op) {
    switch (op) {
        case SIGMA_OP_EQ:
            return "eq";
        case SIGMA_OP_CONTAINS:
            return "contains";
        case SIGMA_OP_STARTSWITH:
            return "startswith";
        case SIGMA_OP_ENDSWITH:
            return "endswith";
        case SIGMA_OP_EXISTS:
            return "exists";
        case SIGMA_OP_GT:
            return "gt";
        case SIGMA_OP_GTE:
            return "gte";
        case SIGMA_OP_LT:
            return "lt";
        case SIGMA_OP_LTE:
            return "lte";
        case SIGMA_OP_RE:
            return "re";
        case SIGMA_OP_CIDR:
            return "cidr";
        case SIGMA_OP_NUMEQ:
            return "numeq";
        default:
            return "unknown";
    }
}

static void sb_pool(sb_t* b, const sigma_db_t* db, const sigma_str_t* tab, uint32_t n, uint32_t id) {
    const char* s;
    size_t len;
    if (pool_str(db, tab, n, id, &s, &len))
        sb_jstr(b, s, len);
    else
        sb_lit(b, "null");
}

static void sb_score(sb_t* b, uint16_t x100) {
    sb_fmt(b, "%u.%02u", (unsigned)(x100 / 100u), (unsigned)(x100 % 100u));
}

static void sb_rule_head(sb_t* b, const sigma_db_t* db, const sigma_rule_t* r) {
    sb_fmt(b, "{\"rule_id\":%u,\"title\":", (unsigned)r->rule_id);
    sb_pool(b, db, db->values, db->n_values, r->name_id);
    sb_lit(b, ",\"verdict\":");
    sb_cstr(b, verdict_name(r->verdict));
    sb_fmt(b, ",\"severity\":%u,\"score\":", (unsigned)r->severity);
    sb_score(b, r->score_x100);
    sb_lit(b, ",\"mitre\":");
    sb_pool(b, db, db->values, db->n_values, r->mitre_id);
    sb_lit(b, "}");
}

static void sb_hit(sb_t* b, const sigma_events_t* se, const sigma_hit_t* h) {
    sb_fmt(b, "{\"rule_id\":%u,\"title\":", (unsigned)h->rule_id);
    const sigma_rule_t* r = rule_by_id(se, h->rule_id);
    if (r != NULL)
        sb_pool(b, &se->db, se->db.values, se->db.n_values, r->name_id);
    else
        sb_lit(b, "null");
    sb_lit(b, ",\"verdict\":");
    sb_cstr(b, verdict_name(h->verdict));
    sb_fmt(b, ",\"severity\":%u,\"score\":", (unsigned)h->severity);
    sb_score(b, h->score_x100);
    sb_lit(b, ",\"mitre\":");
    if (h->mitre != NULL)
        sb_jstr(b, h->mitre, h->mitre_len);
    else
        sb_lit(b, "null");
    sb_lit(b, "}");
}

char* sigma_events_info_json(const sigma_events_t* se) {
    if (se == NULL) return err_json("no engine");
    sb_t b = {0};
    sb_fmt(&b, "{\"ok\":true,\"schema\":%u,\"format_version\":%u,\"format_version_min\":%u,", SIGMA_EVENTS_SCHEMA,
           SIGMA_FORMAT_VERSION, SIGMA_FORMAT_VERSION_MIN);
    sb_fmt(&b, "\"n_rules\":%u,\"re_skipped\":%u,\"rules\":[", (unsigned)se->db.n_rules, (unsigned)se->db.n_re_skipped);
    for (uint32_t i = 0; i < se->db.n_rules; i++) {
        if (i) sb_lit(&b, ",");
        sb_rule_head(&b, &se->db, &se->db.rules[i]);
    }
    sb_lit(&b, "]}");
    return sb_finish(&b);
}

static int run_match(sigma_events_t* se, struct json_object* ev) {
    int n = sigma_eval_run(se->eval, ev_field, ev, se->hits, se->hits_cap);
    if (n < 0) return 0;
    return n > se->hits_cap ? se->hits_cap : n;
}

char* sigma_events_match_json(sigma_events_t* se, const char* events, size_t len) {
    char msg[128];
    evs_t evs;
    if (se == NULL) return err_json("no engine");
    if (parse_events(events, len, &evs, msg, sizeof(msg)) != 0) return err_json(msg);

    sb_t b = {0};
    uint64_t total = 0, n_alert = 0, n_esc = 0, n_benign = 0;
    sb_fmt(&b, "{\"ok\":true,\"n_events\":%zu,\"events\":[", evs.n);
    for (size_t i = 0; i < evs.n && !b.failed; i++) {
        int n = run_match(se, evs.ev[i]);
        sb_fmt(&b, "%s{\"index\":%zu,\"hits\":[", i ? "," : "", i);
        for (int j = 0; j < n; j++) {
            if (j) sb_lit(&b, ",");
            sb_hit(&b, se, &se->hits[j]);
            if (se->hits[j].verdict == SIGMA_VERDICT_BENIGN)
                n_benign++;
            else if (se->hits[j].verdict == SIGMA_VERDICT_ESCALATE)
                n_esc++;
            else
                n_alert++;
        }
        total += (uint64_t)n;
        sb_lit(&b, "]}");
    }
    sb_fmt(&b, "],\"totals\":{\"hits\":%llu,", (unsigned long long)total);
    sb_fmt(&b, "\"alert\":%llu,\"escalate\":%llu,", (unsigned long long)n_alert, (unsigned long long)n_esc);
    sb_fmt(&b, "\"benign\":%llu}}", (unsigned long long)n_benign);
    evs_free(&evs);
    return sb_finish(&b);
}

/* ----------------------------------------------------------------------------
 * Explain.
 * -------------------------------------------------------------------------- */
static int view_run(sigma_events_t* se, struct json_object* ev) {
    sigma_hit_t h;
    return sigma_eval_run_linear(se->veval, ev_field, ev, &h, 1) > 0;
}

static void view_one_sel(sigma_events_t* se, const sigma_rule_t* r) {
    se->view.sels = &se->vsel;
    se->view.n_sels = 1;
    se->view.cond = NULL;
    se->view.n_cond = 0;
    se->vrule = *r;
    se->vrule.sel_start = 0;
    se->vrule.sel_count = 1;
    se->vrule.cond_start = 0;
    se->vrule.cond_count = 0;
}

static int eval_pred(sigma_events_t* se, struct json_object* ev, const sigma_rule_t* r, uint32_t pred_idx) {
    view_one_sel(se, r);
    se->vsel.pred_start = pred_idx;
    se->vsel.pred_count = 1;
    return view_run(se, ev);
}

static int eval_sel(sigma_events_t* se, struct json_object* ev, const sigma_rule_t* r, const sigma_sel_t* sel) {
    view_one_sel(se, r);
    se->vsel = *sel;
    return view_run(se, ev);
}

static int eval_rule_unrouted(sigma_events_t* se, struct json_object* ev, const sigma_rule_t* r) {
    se->view.sels = se->db.sels;
    se->view.n_sels = se->db.n_sels;
    se->view.cond = se->db.cond;
    se->view.n_cond = se->db.n_cond;
    se->vrule = *r;
    return view_run(se, ev);
}

static void sb_cidr(sb_t* b, const sigma_cidr_t* c) {
    char buf[64];
    int n;
    if (c->family == 4) {
        n = snprintf(buf, sizeof(buf), "%u.%u.%u.%u/%u", c->net[0], c->net[1], c->net[2], c->net[3],
                     (unsigned)c->prefix);
    } else {
        n = snprintf(buf, sizeof(buf), "%x:%x:%x:%x:%x:%x:%x:%x/%u", (c->net[0] << 8) | c->net[1],
                     (c->net[2] << 8) | c->net[3], (c->net[4] << 8) | c->net[5], (c->net[6] << 8) | c->net[7],
                     (c->net[8] << 8) | c->net[9], (c->net[10] << 8) | c->net[11], (c->net[12] << 8) | c->net[13],
                     (c->net[14] << 8) | c->net[15], (unsigned)c->prefix);
    }
    if (n < 0 || (size_t)n >= sizeof(buf)) {
        sb_lit(b, "null");
        return;
    }
    sb_jstr(b, buf, (size_t)n);
}

/* The operand as the rule states it, always a string (or null for exists). */
static void sb_operand(sb_t* b, const sigma_db_t* db, const sigma_pred_t* p) {
    switch (p->op) {
        case SIGMA_OP_EXISTS:
            sb_lit(b, "null");
            return;
        case SIGMA_OP_GT:
        case SIGMA_OP_GTE:
        case SIGMA_OP_LT:
        case SIGMA_OP_LTE:
        case SIGMA_OP_NUMEQ:
            sb_fmt(b, "\"%lld\"", (long long)p->ival);
            return;
        case SIGMA_OP_CIDR:
            if (p->value_id < db->n_cidrs)
                sb_cidr(b, &db->cidrs[p->value_id]);
            else
                sb_lit(b, "null");
            return;
        default:
            if (p->flags & SIGMA_PF_FIELDREF)
                sb_pool(b, db, db->fields, db->n_fields, p->value_id);
            else
                sb_pool(b, db, db->values, db->n_values, p->value_id);
            return;
    }
}

static void sb_pred(sb_t* b, sigma_events_t* se, struct json_object* ev, const sigma_rule_t* r, uint32_t pred_idx) {
    const sigma_db_t* db = &se->db;
    const sigma_pred_t* p = &db->preds[pred_idx];
    const char* fname = NULL;
    size_t flen = 0;

    sb_lit(b, "{\"field\":");
    if (pool_str(db, db->fields, db->n_fields, p->field_id, &fname, &flen))
        sb_jstr(b, fname, flen);
    else
        sb_lit(b, "null");
    sb_fmt(b, ",\"group\":%u,\"op\":", (unsigned)p->group_id);
    sb_cstr(b, op_name(p->op));
    sb_lit(b, ",\"value\":");
    sb_operand(b, db, p);
    sb_lit(b, ",\"case\":");
    sb_bool(b, (p->flags & SIGMA_PF_CASE) != 0);
    sb_lit(b, ",\"negate\":");
    sb_bool(b, (p->flags & SIGMA_PF_NEGATE) != 0);
    sb_lit(b, ",\"fieldref\":");
    sb_bool(b, (p->flags & SIGMA_PF_FIELDREF) != 0);

    size_t vlen = 0;
    const char* got = fname != NULL ? ev_field(ev, fname, (uint32_t)flen, &vlen) : NULL;
    sb_lit(b, ",\"present\":");
    sb_bool(b, got != NULL);
    sb_lit(b, ",\"got\":");
    if (got != NULL)
        sb_jstr(b, got, vlen > SIGMA_EVENTS_ECHO_MAX ? SIGMA_EVENTS_ECHO_MAX : vlen);
    else
        sb_lit(b, "null");
    sb_lit(b, ",\"got_truncated\":");
    sb_bool(b, got != NULL && vlen > SIGMA_EVENTS_ECHO_MAX);
    sb_lit(b, ",\"matched\":");
    sb_bool(b, eval_pred(se, ev, r, pred_idx));
    sb_lit(b, "}");
}

static void sb_condition(sb_t* b, const sigma_db_t* db, const sigma_rule_t* r) {
    if (r->cond_count == 0) {
        sb_lit(b, "null");
        return;
    }
    sb_lit(b, "[");
    for (uint32_t i = 0; i < r->cond_count; i++) {
        const sigma_ctok_t* t = &db->cond[r->cond_start + i];
        if (i) sb_lit(b, ",");
        switch (t->kind) {
            case SIGMA_C_SEL:
                sb_fmt(b, "\"sel:%u\"", (unsigned)t->sel_idx);
                break;
            case SIGMA_C_AND:
                sb_lit(b, "\"and\"");
                break;
            case SIGMA_C_OR:
                sb_lit(b, "\"or\"");
                break;
            case SIGMA_C_NOT:
                sb_lit(b, "\"not\"");
                break;
            default:
                sb_lit(b, "\"?\"");
                break;
        }
    }
    sb_lit(b, "]");
}

char* sigma_events_explain_json(sigma_events_t* se, const char* event, size_t len, uint32_t rule_id) {
    char msg[128];
    evs_t evs;
    if (se == NULL) return err_json("no engine");
    const sigma_rule_t* r = rule_by_id(se, rule_id);
    if (r == NULL) {
        snprintf(msg, sizeof(msg), "rule_id %u is not in the artifact", (unsigned)rule_id);
        return err_json(msg);
    }
    if (parse_events(event, len, &evs, msg, sizeof(msg)) != 0) return err_json(msg);
    if (evs.n == 0) {
        evs_free(&evs);
        return err_json("no events");
    }
    struct json_object* ev = evs.ev[0];

    int routed = 0;
    int n = run_match(se, ev);
    for (int j = 0; j < n; j++)
        if (se->hits[j].rule_id == rule_id) routed = 1;
    int unrouted = eval_rule_unrouted(se, ev, r);

    sb_t b = {0};
    sb_fmt(&b, "{\"ok\":true,\"rule_id\":%u,\"title\":", (unsigned)rule_id);
    sb_pool(&b, &se->db, se->db.values, se->db.n_values, r->name_id);
    sb_lit(&b, ",\"matched\":");
    sb_bool(&b, routed);
    sb_lit(&b, ",\"matched_unrouted\":");
    sb_bool(&b, unrouted);
    sb_lit(&b, ",\"condition\":");
    sb_condition(&b, &se->db, r);
    sb_lit(&b, ",\"selections\":[");
    for (uint32_t s = 0; s < r->sel_count && !b.failed; s++) {
        const sigma_sel_t* sel = &se->db.sels[r->sel_start + s];
        sb_fmt(&b, "%s{\"index\":%u,\"matched\":", s ? "," : "", (unsigned)s);
        sb_bool(&b, eval_sel(se, ev, r, sel));
        sb_lit(&b, ",\"preds\":[");
        for (uint32_t p = 0; p < sel->pred_count; p++) {
            if (p) sb_lit(&b, ",");
            sb_pred(&b, se, ev, r, sel->pred_start + p);
        }
        sb_lit(&b, "]}");
    }
    sb_lit(&b, "]}");
    evs_free(&evs);
    return sb_finish(&b);
}

/* ----------------------------------------------------------------------------
 * Correlate.
 * -------------------------------------------------------------------------- */
static void sb_corr_stats(sb_t* b, const corr_stats_t* s) {
    sb_fmt(b, "{\"groups_evicted\":%llu,", (unsigned long long)s->groups_evicted);
    sb_fmt(b, "\"distinct_evicted\":%llu,", (unsigned long long)s->distinct_evicted);
    sb_fmt(b, "\"events_overwritten\":%llu,", (unsigned long long)s->events_overwritten);
    sb_fmt(b, "\"fires_suppressed\":%llu,", (unsigned long long)s->fires_suppressed);
    sb_fmt(b, "\"fires_truncated\":%llu,", (unsigned long long)s->fires_truncated);
    sb_fmt(b, "\"rules_rejected\":%llu,", (unsigned long long)s->rules_rejected);
    sb_fmt(b, "\"event_skipped_missing_field\":%llu,", (unsigned long long)s->event_skipped_missing_field);
    sb_fmt(b, "\"seen_truncated\":%llu,", (unsigned long long)s->seen_truncated);
    sb_fmt(b, "\"hits_truncated\":%llu,", (unsigned long long)s->hits_truncated);
    sb_fmt(b, "\"group_evidence_dropped\":%llu,", (unsigned long long)s->group_evidence_dropped);
    sb_fmt(b, "\"oom_dropped\":%llu,", (unsigned long long)s->oom_dropped);
    sb_fmt(b, "\"values_nonnumeric\":%llu,", (unsigned long long)s->values_nonnumeric);
    sb_fmt(b, "\"cond_over_arity\":%llu,", (unsigned long long)s->cond_over_arity);
    sb_fmt(b, "\"watermark_late\":%llu,", (unsigned long long)s->watermark_late);
    sb_fmt(b, "\"hotkey_fallback\":%llu}", (unsigned long long)s->hotkey_fallback);
}

static void sb_fire(sb_t* b, size_t event, const corr_fire_t* f) {
    sb_fmt(b, "{\"event\":%zu,\"corr_id\":", event);
    sb_cstr(b, f->rule_id);
    sb_lit(b, ",\"title\":");
    sb_cstr(b, f->title);
    sb_fmt(b, ",\"observed\":%lld,\"threshold\":%lld,\"group\":", (long long)f->observed, (long long)f->threshold);
    if (f->group == NULL || f->group_by == NULL) {
        sb_lit(b, "null}");
        return;
    }
    sb_lit(b, "{");
    for (size_t k = 0; k < f->n_group; k++) {
        if (k) sb_lit(b, ",");
        sb_cstr(b, f->group_by[k] != NULL ? f->group_by[k] : "");
        sb_lit(b, ":");
        sb_cstr(b, f->group[k]);
    }
    sb_lit(b, "}}");
}

char* sigma_events_correlate_json(
    sigma_events_t* se, const char* corr_json, size_t corr_len, const char* events, size_t len) {
    char msg[128];
    if (se == NULL) return err_json("no engine");
    if (corr_json == NULL || corr_len == 0) return err_json("no correlation artifact");

    struct corr_artifact_view view;
    corr_artifact_t* art = corr_artifact_parse(corr_json, corr_len, &view);
    if (art == NULL) return err_json("correlation artifact rejected");

    corr_caps_t caps = corr_caps_default();
    caps.event_time_ordering = 1;
    caps.watermark_s = 2.0;
    corr_engine_t* ce = corr_engine_new(view.rules, view.n, caps);
    uint32_t* rids = malloc((size_t)se->hits_cap * sizeof(*rids));
    corr_fire_t* fires = malloc(CORR_FIRES_MAX * sizeof(*fires));
    const char** scratch = malloc(CORR_FIRES_MAX * CORR_MAX_GROUP_FIELDS * sizeof(*scratch));
    char* out = NULL;
    evs_t evs = {0};
    sb_t b = {0};
    time_t now = time(NULL);
    double ts = 0.0;
    uint64_t untimed = 0;
    int first = 1;
    corr_stats_t st;

    if (ce == NULL || rids == NULL || fires == NULL || scratch == NULL) goto done;
    if (parse_events(events, len, &evs, msg, sizeof(msg)) != 0) {
        out = err_json(msg);
        goto done;
    }
    sb_fmt(&b, "{\"ok\":true,\"n_events\":%zu,\"n_correlations\":%zu,\"fires\":[", evs.n, corr_engine_rule_count(ce));
    for (size_t i = 0; i < evs.n && !b.failed; i++) {
        double t;
        if (ev_time(evs.ev[i], now, &t))
            ts = t;
        else
            untimed++;
        int n = run_match(se, evs.ev[i]);
        if (n <= 0) continue;
        for (int j = 0; j < n; j++) rids[j] = se->hits[j].rule_id;
        int nf = corr_on_event(ce, rids, (size_t)n, ev_corr_field, evs.ev[i], ts, fires, CORR_FIRES_MAX, scratch,
                               CORR_FIRES_MAX * CORR_MAX_GROUP_FIELDS);
        if (nf > (int)CORR_FIRES_MAX) nf = (int)CORR_FIRES_MAX;
        for (int j = 0; j < nf; j++) {
            if (!first) sb_lit(&b, ",");
            first = 0;
            sb_fire(&b, i, &fires[j]);
        }
    }
    corr_engine_stats(ce, &st);
    sb_fmt(&b, "],\"untimed\":%llu,\"stats\":", (unsigned long long)untimed);
    sb_corr_stats(&b, &st);
    sb_lit(&b, "}");
    out = sb_finish(&b);

done:
    evs_free(&evs);
    free(scratch);
    free(fires);
    free(rids);
    corr_engine_free(ce);
    corr_artifact_free(art);
    return out;
}
