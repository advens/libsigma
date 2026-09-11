/* sigma_match.c
 * libsigma matcher core.  See sigma_match.h for the design contract.
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

#include "sigma_match.h"
#include "sigma_simd.h"
#include "sigma_teddy.h"

#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include <sys/socket.h> /* AF_INET / AF_INET6 (not pulled in transitively on FreeBSD) */
#include <netinet/in.h>
#include <arpa/inet.h> /* inet_pton */
#define PCRE2_CODE_UNIT_WIDTH 8
#include <pcre2.h> /* PCRE2 for SIGMA_OP_RE, the SigmaHQ regex dialect
                          * (\d, lookahead, non-greedy, inline (?ims) flags...)
                          * that POSIX ERE cannot compile. */

/* Compiled-regex side-table entry (db->re is an array of these, sized n_preds;
 * only RE predicates are compiled). Built by sigma_db_finalize, freed by
 * sigma_db_free. */
typedef struct {
    pcre2_code* re; /* compiled pattern; shared read-only across workers */
    uint8_t valid;
} sigma_re_t;

/* Bounded RPN evaluation stack depth.  A compiled condition over N selections
 * needs at most N pushes; we cap at a generous fixed size and the builder
 * rejects rules whose condition exceeds it (no unbounded recursion, no VLA). */
#define SIGMA_COND_STACK_MAX 64

struct sigma_eval {
    const sigma_db_t* db;
    const char** vptr; /* resolved value pointer per field_id */
    size_t* vlen; /* resolved value length per field_id   */
    uint8_t* vstate; /* 0 = not yet resolved, 1 = resolved (may be NULL value) */
    pcre2_match_data* md; /* per-worker PCRE2 match scratch, created
                           * lazily, reused across events; keeps
                           * pcre2_match() thread-safe over the shared
                           * read-only compiled patterns. */
    /* SIMD literal prefilter scratch (reused across events).  rule_mask[ri] is
     * the set of witness clauses of rule ri satisfied so far, valid only while
     * rule_gen[ri] == gen; the generation stamp is what avoids clearing both
     * arrays on every event. */
    uint32_t* rule_mask;
    uint32_t* rule_gen;
    uint32_t* eval_done; /* rule_idx already verified this event (union of buckets) */
    uint32_t gen;
    uint16_t cur_field; /* field being scanned, for the postings callback */
    sigma_teddy_scratch_t tscr; /* per-field needle-confirmation stamps */
    sigma_eval_stats_t st; /* prefilter effectiveness counters */
    int prefilter_on; /* 1 = use Teddy prefilter (default) */
};

void sigma_eval_get_stats(const sigma_eval_t* e, sigma_eval_stats_t* out) {
    if (!out) return;
    if (!e) {
        memset(out, 0, sizeof(*out));
        return;
    }
    *out = e->st;
}

void sigma_eval_reset_stats(sigma_eval_t* e) {
    if (e) memset(&e->st, 0, sizeof(e->st));
}

void sigma_eval_set_prefilter(sigma_eval_t* e, int enabled) {
    if (e) e->prefilter_on = (enabled < 0) ? 0 : (enabled > 2 ? 2 : enabled);
}

static void bump_eval_gen(sigma_eval_t* e) {
    if (++e->gen == 0) {
        if (e->rule_gen && e->db && e->db->n_rules)
            memset(e->rule_gen, 0, (size_t)e->db->n_rules * sizeof(*e->rule_gen));
        if (e->eval_done && e->db && e->db->n_rules)
            memset(e->eval_done, 0, (size_t)e->db->n_rules * sizeof(*e->eval_done));
        e->gen = 1;
    }
}

/* ---- ASCII case-insensitive helpers (locale-independent on purpose) ------ */
static inline char sg_lower(char c) {
    return (c >= 'A' && c <= 'Z') ? (char)(c + 32) : c;
}

static bool sg_eq(const char* a, size_t alen, const char* b, size_t blen, bool cs) {
    if (alen != blen) return false;
    if (cs) return memcmp(a, b, alen) == 0;
    for (size_t i = 0; i < alen; i++)
        if (sg_lower(a[i]) != sg_lower(b[i])) return false;
    return true;
}

/* substring search; case-insensitive when !cs.  needle non-empty. */
static bool sg_contains(const char* hay, size_t hlen, const char* ndl, size_t nlen, bool cs) {
    if (nlen == 0) return true;
    if (nlen > hlen) return false;
    const size_t last = hlen - nlen;
    for (size_t i = 0; i <= last; i++) {
        size_t j = 0;
        if (cs) {
            while (j < nlen && hay[i + j] == ndl[j]) j++;
        } else {
            while (j < nlen && sg_lower(hay[i + j]) == sg_lower(ndl[j])) j++;
        }
        if (j == nlen) return true;
    }
    return false;
}

static bool sg_starts(const char* s, size_t slen, const char* p, size_t plen, bool cs) {
    if (plen > slen) return false;
    return sg_eq(s, plen, p, plen, cs);
}

static bool sg_ends(const char* s, size_t slen, const char* p, size_t plen, bool cs) {
    if (plen > slen) return false;
    return sg_eq(s + (slen - plen), plen, p, plen, cs);
}

/* Parse a leading signed integer.  Returns false if no digits.  Tolerates a
 * trailing non-numeric suffix (e.g. "443/tcp" -> 443) so numeric ops are
 * robust against composite fields. */
static bool sg_to_i64(const char* s, size_t len, int64_t* out) {
    size_t i = 0;
    bool neg = false;
    if (i < len && (s[i] == '-' || s[i] == '+')) {
        neg = (s[i] == '-');
        i++;
    }
    if (i >= len || s[i] < '0' || s[i] > '9') return false;
    /* Accumulate the magnitude in uint64_t and saturate.  A numeric field is
     * attacker-controlled (message content); an over-long run of digits must
     * never overflow a signed int64 (undefined behavior) and flip the sign of a
     * |gt / |lt / |gte / |lte verdict.  Clamp to INT64_MAX / INT64_MIN. */
    uint64_t mag = 0;
    bool sat = false;
    for (; i < len && s[i] >= '0' && s[i] <= '9'; i++) {
        if (mag > (UINT64_MAX - 9u) / 10u) {
            sat = true;
            break;
        }
        mag = mag * 10u + (uint64_t)(s[i] - '0');
    }
    if (neg) {
        const uint64_t lim = (uint64_t)INT64_MAX + 1u; /* magnitude of INT64_MIN */
        *out = (sat || mag >= lim) ? INT64_MIN : -(int64_t)mag;
    } else {
        *out = (sat || mag > (uint64_t)INT64_MAX) ? INT64_MAX : (int64_t)mag;
    }
    return true;
}

static const sigma_str_t* db_str(const sigma_str_t* tab, uint32_t n, uint32_t id) {
    return (id < n) ? &tab[id] : NULL;
}

/* Prefix compare against a pre-masked network.  nbytes = 4 (v4) or 16 (v6). */
static bool prefix_match(const uint8_t* addr, const uint8_t* net, uint8_t prefix, unsigned nbytes) {
    unsigned full = prefix / 8u, rem = prefix % 8u;
    if (full > nbytes) return false;
    if (full && memcmp(addr, net, full) != 0) return false;
    if (rem) {
        uint8_t mask = (uint8_t)(0xFFu << (8u - rem));
        if ((addr[full] & mask) != (net[full] & mask)) return false;
    }
    return true;
}

/* Parse an IP field value and test membership in a pre-parsed CIDR. */
static bool ip_in_cidr(const char* val, size_t vlen, const sigma_cidr_t* c) {
    char buf[INET6_ADDRSTRLEN];
    if (vlen == 0 || vlen >= sizeof(buf)) return false;
    memcpy(buf, val, vlen);
    buf[vlen] = '\0';

    if (c->family == 4) {
        struct in_addr a;
        if (inet_pton(AF_INET, buf, &a) != 1) return false;
        uint8_t addr[4];
        memcpy(addr, &a, 4);
        return prefix_match(addr, c->net, c->prefix, 4);
    } else if (c->family == 6) {
        struct in6_addr a;
        if (inet_pton(AF_INET6, buf, &a) != 1) return false;
        return prefix_match((const uint8_t*)&a, c->net, c->prefix, 16);
    }
    return false;
}

/* Resolve (and memoize) a field value for the current event. */
static const char* resolve_field(sigma_eval_t* e, sigma_field_fn fn, void* ctx, uint16_t field_id, size_t* out_len) {
    const sigma_db_t* db = e->db;
    if (field_id >= db->n_fields) {
        *out_len = 0;
        return NULL;
    }
    if (!e->vstate[field_id]) {
        const sigma_str_t* f = &db->fields[field_id];
        size_t vlen = 0;
        const char* v = fn(ctx, db->strpool + f->off, f->len, &vlen);
        e->vptr[field_id] = v;
        e->vlen[field_id] = v ? vlen : 0;
        e->vstate[field_id] = 1;
    }
    *out_len = e->vlen[field_id];
    return e->vptr[field_id];
}

static bool pred_match(sigma_eval_t* e, sigma_field_fn fn, void* ctx, const sigma_pred_t* p, uint32_t pred_idx) {
    size_t vlen = 0;
    const char* val = resolve_field(e, fn, ctx, p->field_id, &vlen);
    bool res = false;

    if (p->op == SIGMA_OP_EXISTS) {
        res = (val != NULL && vlen > 0);
        goto done;
    }
    if (val == NULL) goto done; /* absent field never matches a value predicate */

    const bool cs = (p->flags & SIGMA_PF_CASE) != 0;

    switch (p->op) {
        case SIGMA_OP_GT:
        case SIGMA_OP_GTE:
        case SIGMA_OP_LT:
        case SIGMA_OP_LTE:
        case SIGMA_OP_NUMEQ: {
            int64_t iv;
            if (!sg_to_i64(val, vlen, &iv)) break;
            if (p->op == SIGMA_OP_GT) res = (iv > p->ival);
            if (p->op == SIGMA_OP_GTE) res = (iv >= p->ival);
            if (p->op == SIGMA_OP_LT) res = (iv < p->ival);
            if (p->op == SIGMA_OP_LTE) res = (iv <= p->ival);
            if (p->op == SIGMA_OP_NUMEQ) res = (iv == p->ival);
            break;
        }
        case SIGMA_OP_CIDR:
            if (p->value_id < e->db->n_cidrs) res = ip_in_cidr(val, vlen, &e->db->cidrs[p->value_id]);
            break;
        case SIGMA_OP_RE: {
            const sigma_re_t* arr = (const sigma_re_t*)e->db->re;
            if (!arr || pred_idx >= e->db->n_preds || !arr[pred_idx].valid) break;
            /* Per-worker match_data, created on first RE use and reused. */
            if (!e->md) {
                e->md = pcre2_match_data_create(1, NULL);
                if (!e->md) break;
            }
            /* PCRE2 matches a length-delimited subject, no NUL copy needed. */
            res = (pcre2_match(arr[pred_idx].re, (PCRE2_SPTR)val, vlen, 0, 0, e->md, NULL) >= 0);
            break;
        }
        default: {
            const char* o;
            size_t olen;
            if (p->flags & SIGMA_PF_FIELDREF) {
                /* |fieldref: the operand is the value of ANOTHER field, so value_id
                 * indexes the FIELDS table (not values). Resolve it via the memo;
                 * an absent referenced field never matches. The > 0xFFFF guard
                 * rejects a value_id a u16 field_id could never denote (a corrupt
                 * artifact), keeping the cast in-range. */
                if (p->value_id >= e->db->n_fields || p->value_id > 0xFFFFu) break;
                o = resolve_field(e, fn, ctx, (uint16_t)p->value_id, &olen);
                if (o == NULL) break;
            } else {
                const sigma_str_t* opnd = db_str(e->db->values, e->db->n_values, p->value_id);
                if (!opnd) break;
                o = e->db->strpool + opnd->off;
                olen = opnd->len;
            }
            switch (p->op) {
                case SIGMA_OP_EQ:
                    res = sg_eq(val, vlen, o, olen, cs);
                    break;
                case SIGMA_OP_CONTAINS:
                    /* Case-insensitive contains is the common Sigma case and the one
                     * worth accelerating (unanchored search over long fields like
                     * url/command_line): route it through the SSE4.2/NEON substring.
                     * Case-sensitive stays scalar (rare). */
                    res = cs ? sg_contains(val, vlen, o, olen, true) : (sigma_memmem_ci(val, vlen, o, olen) != NULL);
                    break;
                case SIGMA_OP_STARTSWITH:
                    res = sg_starts(val, vlen, o, olen, cs);
                    break;
                case SIGMA_OP_ENDSWITH:
                    res = sg_ends(val, vlen, o, olen, cs);
                    break;
                /* SIGMA_OP_RE / SIGMA_OP_CIDR are handled in the outer switch. */
                default:
                    res = false;
                    break;
            }
            break;
        }
    }

done:
    if (p->flags & SIGMA_PF_NEGATE) res = !res;
    return res;
}

/* Selection = AND across groups, OR within a group (Sigma map semantics).
 * Predicates are contiguous and grouped by the builder. */
static bool sel_match(sigma_eval_t* e, sigma_field_fn fn, void* ctx, const sigma_sel_t* sel) {
    if (sel->pred_count == 0) return false;
    const sigma_db_t* db = e->db;
    const sigma_pred_t* preds = db->preds + sel->pred_start;
    const uint32_t n = sel->pred_count;

    bool group_or = false;
    uint16_t cur_group = preds[0].group_id;

    for (uint32_t i = 0; i < n; i++) {
        if (preds[i].group_id != cur_group) {
            if (!group_or) /* a completed group failed -> selection fails */
                return false;
            group_or = false;
            cur_group = preds[i].group_id;
        }
        if (!group_or) /* short-circuit: skip rest of an already-true group */
            group_or = pred_match(e, fn, ctx, &preds[i], sel->pred_start + i);
    }
    return group_or; /* AND with the final group */
}

/* RPN cell: a bool, a not-yet-run selection, or a deferred NOT of a selection.
 * AND/OR force the left operand and skip the right when that already decides
 * (sel and not filter: if sel is false the filter is never verified). */
#define RPN_BOOL 0
#define RPN_SEL 1
#define RPN_NOTSEL 2

typedef struct {
    uint8_t kind;
    uint8_t val;
    uint32_t sel_idx;
} rpn_cell_t;

static bool rpn_force(sigma_eval_t* e, sigma_field_fn fn, void* ctx, const sigma_rule_t* r, rpn_cell_t* c) {
    if (c->kind == RPN_BOOL) return c->val != 0;
    if (c->sel_idx >= r->sel_count) {
        c->kind = RPN_BOOL;
        c->val = 0;
        return false;
    }
    bool hit = sel_match(e, fn, ctx, &e->db->sels[r->sel_start + c->sel_idx]);
    if (c->kind == RPN_NOTSEL) hit = !hit;
    c->kind = RPN_BOOL;
    c->val = hit ? 1 : 0;
    return hit;
}

/* Evaluate a rule's condition.  cond_count==0 => AND of all the rule's
 * selections.  Otherwise run the compiled RPN over local selection results. */
static bool rule_match(sigma_eval_t* e, sigma_field_fn fn, void* ctx, const sigma_rule_t* r) {
    const sigma_db_t* db = e->db;

    /* Implicit AND-of-all when there is no explicit condition. */
    if (r->cond_count == 0) {
        for (uint32_t i = 0; i < r->sel_count; i++)
            if (!sel_match(e, fn, ctx, &db->sels[r->sel_start + i])) return false;
        return r->sel_count > 0;
    }

    rpn_cell_t stack[SIGMA_COND_STACK_MAX];
    int sp = 0;
    const sigma_ctok_t* tok = db->cond + r->cond_start;

    for (uint32_t i = 0; i < r->cond_count; i++) {
        switch (tok[i].kind) {
            case SIGMA_C_SEL: {
                if (sp >= SIGMA_COND_STACK_MAX) return false; /* malformed; builder guarantees this never trips */
                uint32_t li = tok[i].sel_idx;
                if (li >= r->sel_count) return false;
                stack[sp].kind = RPN_SEL;
                stack[sp].val = 0;
                stack[sp].sel_idx = li;
                sp++;
                break;
            }
            case SIGMA_C_NOT:
                if (sp < 1) return false;
                if (stack[sp - 1].kind == RPN_SEL)
                    stack[sp - 1].kind = RPN_NOTSEL;
                else if (stack[sp - 1].kind == RPN_NOTSEL)
                    stack[sp - 1].kind = RPN_SEL;
                else
                    stack[sp - 1].val = (uint8_t)!stack[sp - 1].val;
                break;
            case SIGMA_C_AND: {
                if (sp < 2) return false;
                rpn_cell_t b = stack[--sp];
                rpn_cell_t* a = &stack[sp - 1];
                bool av = rpn_force(e, fn, ctx, r, a);
                a->kind = RPN_BOOL;
                a->val = (av && rpn_force(e, fn, ctx, r, &b)) ? 1 : 0;
                break;
            }
            case SIGMA_C_OR: {
                if (sp < 2) return false;
                rpn_cell_t b = stack[--sp];
                rpn_cell_t* a = &stack[sp - 1];
                bool av = rpn_force(e, fn, ctx, r, a);
                a->kind = RPN_BOOL;
                a->val = (av || rpn_force(e, fn, ctx, r, &b)) ? 1 : 0;
                break;
            }
            default:
                return false;
        }
    }
    if (sp != 1) return false;
    return rpn_force(e, fn, ctx, r, &stack[0]);
}

sigma_eval_t* sigma_eval_create(const sigma_db_t* db) {
    if (!db) return NULL;
    sigma_eval_t* e = calloc(1, sizeof(*e));
    if (!e) return NULL;
    e->db = db;
    /* n_fields may be 0 for a trivial db; guard the allocations. */
    uint32_t nf = db->n_fields ? db->n_fields : 1;
    e->vptr = calloc(nf, sizeof(*e->vptr));
    e->vlen = calloc(nf, sizeof(*e->vlen));
    e->vstate = calloc(nf, sizeof(*e->vstate));
    if (!e->vptr || !e->vlen || !e->vstate) {
        sigma_eval_free(e);
        return NULL;
    }
    e->prefilter_on = 1; /* prefilter on by default */
    if (db->n_rules) {
        e->eval_done = calloc(db->n_rules, sizeof(*e->eval_done));
        if (!e->eval_done) {
            sigma_eval_free(e);
            return NULL;
        }
    }
    /* Prefilter candidate bitset, sized to the rule table (only used when the
     * artifact carries a litidx; harmless otherwise). */
    if (db->n_rules && (db->teddy || db->n_fwit)) {
        e->rule_mask = calloc(db->n_rules, sizeof(*e->rule_mask));
        e->rule_gen = calloc(db->n_rules, sizeof(*e->rule_gen));
        if (!e->rule_mask || !e->rule_gen) {
            sigma_eval_free(e);
            return NULL;
        }
        if (db->teddy && sigma_teddy_scratch_init(&e->tscr, db->n_litndl) != 0) {
            sigma_eval_free(e);
            return NULL;
        }
    }
    return e;
}

void sigma_eval_free(sigma_eval_t* e) {
    if (!e) return;
    free(e->vptr);
    free(e->vlen);
    free(e->vstate);
    free(e->rule_mask);
    free(e->rule_gen);
    free(e->eval_done);
    sigma_teddy_scratch_free(&e->tscr);
    if (e->md) pcre2_match_data_free(e->md);
    free(e);
}

/* Derive, per bucket, the set of field ids that bucket's rules name in any
 * predicate, so the prefilter scans only text a rule in scope could require a
 * literal in.  An unscoped posting (SIGMA_LITREF_ANY_FIELD) could be required in
 * a field outside that set, so its presence disables the narrowing for the whole
 * artifact.  Sound either way: the bitmap only ever skips fields no rule in the
 * bucket reads. */
static int build_bucket_fields(sigma_db_t* db) {
    if (!db->n_buckets || !db->n_fields) return 0;
    for (uint32_t i = 0; i < db->n_litpost_ref; i++) {
        if (db->litpost_ref[i].field_id == SIGMA_LITREF_ANY_FIELD) {
            db->lit_any_field = 1;
            return 0;
        }
    }
    const uint32_t stride = (db->n_fields + 7u) / 8u;
    uint8_t* bm = calloc((size_t)db->n_buckets * stride, 1);
    if (!bm) return -1;
    for (uint32_t b = 0; b < db->n_buckets; b++) {
        const sigma_bucket_t* bk = &db->buckets[b];
        uint8_t* row = bm + (size_t)b * stride;
        for (uint32_t i = 0; i < bk->idx_count; i++) {
            uint32_t ri = db->bucket_idx[bk->idx_start + i];
            if (ri >= db->n_rules) continue;
            const sigma_rule_t* r = &db->rules[ri];
            for (uint32_t si = 0; si < r->sel_count; si++) {
                const sigma_sel_t* sel = &db->sels[r->sel_start + si];
                for (uint32_t pi = 0; pi < sel->pred_count; pi++) {
                    uint16_t f = db->preds[sel->pred_start + pi].field_id;
                    if (f < db->n_fields) row[f >> 3] |= (uint8_t)(1u << (f & 7u));
                }
            }
        }
    }
    db->bucket_fields = bm;
    db->bucket_fields_stride = stride;
    return 0;
}

/* One Teddy per field, chained only with needles posted to that field. Textbook
 * field-partitioned multi-pattern matching: scanning process.command_line does
 * not walk Image or event.original needles. Unscoped (ANY_FIELD) postings keep
 * the single full matcher. */
static void free_field_teddy(sigma_db_t* db) {
    if (!db || !db->field_teddy) return;
    for (uint32_t i = 0; i < db->n_fields; i++) {
        if (db->field_teddy[i]) sigma_teddy_free((sigma_teddy_t*)db->field_teddy[i]);
    }
    free(db->field_teddy);
    db->field_teddy = NULL;
}

static int build_field_teddy(sigma_db_t* db) {
    if (!db->n_fields || !db->n_litndl || !db->litpost || !db->litpost_ref) return 0;
    if (db->lit_any_field) return 0;
    void** arr = calloc(db->n_fields, sizeof(*arr));
    uint8_t* seen = malloc(db->n_litndl);
    uint32_t* ids = malloc((size_t)db->n_litndl * sizeof(*ids));
    if (!arr || !seen || !ids) {
        free(arr);
        free(seen);
        free(ids);
        return -1;
    }
    for (uint32_t f = 0; f < db->n_fields; f++) {
        memset(seen, 0, db->n_litndl);
        uint32_t n = 0;
        for (uint32_t i = 0; i < db->n_litndl; i++) {
            const sigma_litpost_t* p = &db->litpost[i];
            for (uint32_t k = 0; k < p->idx_count; k++) {
                if (db->litpost_ref[p->idx_start + k].field_id != f) continue;
                if (seen[i]) break;
                seen[i] = 1;
                ids[n++] = i;
            }
        }
        if (n == 0) continue;
        arr[f] = sigma_teddy_build_subset(db->litndl, db->n_litndl, db->strpool, ids, n);
        if (!arr[f]) {
            for (uint32_t j = 0; j < db->n_fields; j++)
                if (arr[j]) sigma_teddy_free((sigma_teddy_t*)arr[j]);
            free(arr);
            free(seen);
            free(ids);
            return -1;
        }
    }
    free(seen);
    free(ids);
    db->field_teddy = arr;
    return 0;
}

/* Compile every SIGMA_OP_RE predicate's pattern into the db->re side-table.
 * Idempotent.  Must be called after load/build, before eval, when RE rules are
 * present (sigma_db_load_* calls it automatically).  Returns 0 on success,
 * -1 on a bad/uncompilable pattern, -2 on OOM. */
int sigma_db_finalize(sigma_db_t* db) {
    if (!db) return -1;

    /* build the arch-specific Teddy prefilter from the arch-neutral
     * litidx bytes (idempotent, skip if already built).  An artifact with no
     * litidx needles leaves teddy NULL -> the bucket scan runs every rule (sound).
     * `built_teddy` tracks a build done in THIS call so a later failure below
     * frees it (the caller discards a db whose finalize failed and never calls
     * sigma_db_free, so the derived teddy would otherwise leak). */
    bool built_teddy = false;
    if (!db->teddy && db->n_litndl) {
        db->teddy = sigma_teddy_build(db->litndl, db->n_litndl, db->strpool);
        built_teddy = true;
        if (!db->teddy) return -2;
        if (build_bucket_fields(db) != 0) {
            sigma_teddy_free((sigma_teddy_t*)db->teddy);
            db->teddy = NULL;
            return -2;
        }
        if (build_field_teddy(db) != 0) {
            free_field_teddy(db);
            sigma_teddy_free((sigma_teddy_t*)db->teddy);
            db->teddy = NULL;
            return -2;
        }
    }

    if (db->re) return 0; /* regex side-table already finalized */

    uint32_t n_re = 0;
    for (uint32_t i = 0; i < db->n_preds; i++)
        if (db->preds[i].op == SIGMA_OP_RE) n_re++;
    if (n_re == 0) return 0; /* nothing to compile */

    sigma_re_t* arr = calloc(db->n_preds, sizeof(sigma_re_t));
    if (!arr) {
        if (built_teddy && db->teddy) {
            free_field_teddy(db);
            sigma_teddy_free((sigma_teddy_t*)db->teddy);
            db->teddy = NULL;
        }
        return -2;
    }

    for (uint32_t i = 0; i < db->n_preds; i++) {
        const sigma_pred_t* p = &db->preds[i];
        if (p->op != SIGMA_OP_RE) continue;
        if (p->value_id >= db->n_values) goto fail;
        const sigma_str_t* s = &db->values[p->value_id];
        /* PCRE2 compiles from a length-delimited pattern, no NUL copy. */
        uint32_t options = PCRE2_NEVER_BACKSLASH_C; /* \C (single byte) is
                                                     * unsafe on UTF text; forbid */
        if (!(p->flags & SIGMA_PF_CASE)) options |= PCRE2_CASELESS;
        int errcode = 0;
        PCRE2_SIZE erroff = 0;
        pcre2_code* code = pcre2_compile((PCRE2_SPTR)(db->strpool + s->off), s->len, options, &errcode, &erroff, NULL);
        if (code) (void)pcre2_jit_compile(code, PCRE2_JIT_COMPLETE);
        if (!code) {
            /* A pattern PCRE2 still can't compile (malformed, or a construct
             * even PCRE2 rejects) disables just THIS predicate, eval treats an
             * invalid RE as a non-match, rather than sinking the whole
             * artifact.  n_re_skipped is reported to the caller so it's visible. */
            arr[i].valid = 0;
            arr[i].re = NULL;
            db->n_re_skipped++;
            continue;
        }
        arr[i].re = code;
        arr[i].valid = 1;
    }
    db->re = arr;
    return 0;

fail:
    for (uint32_t i = 0; i < db->n_preds; i++)
        if (arr[i].valid && arr[i].re) pcre2_code_free(arr[i].re);
    free(arr);
    if (built_teddy && db->teddy) {
        free_field_teddy(db);
        sigma_teddy_free((sigma_teddy_t*)db->teddy);
        db->teddy = NULL;
    }
    return -1;
}

/* Evaluate one rule (by table index) and, on a match, emit a hit into out[].
 * `fired` is the running match count (incremented here on a match). */
static inline void eval_one_rule(
    sigma_eval_t* e, sigma_field_fn fn, void* ctx, uint32_t rule_idx, sigma_hit_t* out, int max_hits, int* fired) {
    const sigma_db_t* db = e->db;
    if (e->eval_done) {
        if (e->eval_done[rule_idx] == e->gen) return;
        e->eval_done[rule_idx] = e->gen;
    }
    const sigma_rule_t* r = &db->rules[rule_idx];
    if (!rule_match(e, fn, ctx, r)) return;
    if (out && *fired < max_hits) {
        out[*fired].rule_id = r->rule_id;
        out[*fired].verdict = r->verdict;
        out[*fired].severity = r->severity;
        out[*fired].score_x100 = r->score_x100;
        /* Resolve the primary MITRE technique (a .values string ref) to a
         * strpool pointer.  Emit-time lookup only on a MATCH (the rare/slow
         * path); the load-time range check guarantees mitre_id < n_values. */
        out[*fired].mitre = NULL;
        out[*fired].mitre_len = 0;
        if (r->mitre_id != SIGMA_NO_VALUE && r->mitre_id < db->n_values) {
            const sigma_str_t* m = &db->values[r->mitre_id];
            out[*fired].mitre = db->strpool + m->off;
            out[*fired].mitre_len = m->len;
        }
    }
    (*fired)++;
}

/* ----------------------------------------------------------------------------
 * SIMD literal prefilter.
 *
 * A rule carries a necessary-literal CNF (see sigma_litref_t): a conjunction of
 * clauses, each a disjunction of (field, literal) pairs, such that the rule can
 * only match if EVERY clause has one of its literals present IN THE FIELD that
 * clause names.  So the prefilter scans the event field by field rather than
 * assembling one concatenated haystack: knowing which field a literal turned up
 * in is what lets a clause be credited only when the occurrence is where the
 * predicate needs it.  Scanning per field also drops the copy the concatenation
 * used to cost.
 *
 * Per event: stamp the always-verify rules as candidates, credit every numeric
 * or CIDR field-witness that holds, then scan each in-scope field with Teddy
 * and credit confirmed needle postings. A rule is a candidate once its clause
 * mask is complete. SOUND: a rule is gated out only when one of its necessary
 * clauses has no atom present, and a rule with no sound atom is always-verify
 * and never gated.
 * ------------------------------------------------------------------------- */

/* The bitmask of a complete witness set for rule `ri`. */
static inline uint32_t rule_full_mask(const sigma_db_t* db, uint32_t ri) {
    uint32_t n = db->rule_clauses ? db->rule_clauses[ri] : 0u;
    if (n == 0) return 0u;
    return (n >= 32u) ? 0xFFFFFFFFu : ((1u << n) - 1u);
}

static inline bool pf_is_candidate(const sigma_eval_t* e, uint32_t ri) {
    if (e->rule_gen[ri] != e->gen) return false;
    return e->rule_mask[ri] == rule_full_mask(e->db, ri);
}

static inline void pf_touch(sigma_eval_t* e, uint32_t ri) {
    if (e->rule_gen[ri] != e->gen) {
        e->rule_gen[ri] = e->gen;
        e->rule_mask[ri] = 0u;
    }
}

/* Prefilter is only worth its setup when the selected bucket is large enough
 * that the saved verifies outweigh it.  Below this, the bucket scan is already
 * line-rate; skip the prefilter so small buckets (web/dns/auth) see NO
 * regression. */
#define SIGMA_PREFILTER_MIN_BUCKET 256u
#define SIGMA_MAX_ROUTE_BUCKETS 16u

static void mark_postings(void* ctx, uint32_t needle_index);

/* Does bucket `b` name field `f` in any of its predicates?  A NULL bitmap (no
 * bucket index, or an artifact with an unscoped posting) means "scan every
 * field", which is the sound fallback. */
static inline bool bucket_uses_field(const sigma_db_t* db, uint32_t b, uint32_t f) {
    if (!db->bucket_fields || b >= db->n_buckets) return true;
    const uint8_t* bm = db->bucket_fields + (size_t)b * db->bucket_fields_stride;
    return (bm[f >> 3] >> (f & 7u)) & 1u;
}

/* Is field `f` worth scanning for this event?  Every bucket the caller is about
 * to evaluate must be covered, not just the category one: a rule sitting in the
 * always-verify bucket still carries literals, and skipping the fields IT names
 * would gate it out on every event. */
static inline bool scan_field(const sigma_db_t* db, const uint32_t* buckets, uint32_t n_buckets, uint32_t f) {
    if (db->lit_any_field || !db->bucket_fields) return true;
    if (n_buckets == 0) return true;
    for (uint32_t i = 0; i < n_buckets; i++) {
        if (bucket_uses_field(db, buckets[i], f)) return true;
    }
    return false;
}

/* A numeric/CIDR CNF atom holds on this event. Same necessary-condition
 * contract as a Teddy posting: true means that clause may be credited. */
static bool fwit_holds(sigma_eval_t* e, sigma_field_fn fn, void* ctx, const sigma_fwit_t* w) {
    size_t vlen = 0;
    const char* val = resolve_field(e, fn, ctx, w->field_id, &vlen);
    if (!val || vlen == 0) return false;
    if (w->op == SIGMA_OP_CIDR) {
        uint32_t cid = (uint32_t)w->ival;
        if (cid >= e->db->n_cidrs) return false;
        return ip_in_cidr(val, vlen, &e->db->cidrs[cid]);
    }
    int64_t iv;
    if (!sg_to_i64(val, vlen, &iv)) return false;
    switch (w->op) {
        case SIGMA_OP_GT:
            return iv > w->ival;
        case SIGMA_OP_GTE:
            return iv >= w->ival;
        case SIGMA_OP_LT:
            return iv < w->ival;
        case SIGMA_OP_LTE:
            return iv <= w->ival;
        case SIGMA_OP_NUMEQ:
            return iv == w->ival;
        default:
            return false;
    }
}

/* Compute the candidate set for one event.  Returns true when the caller may
 * restrict the bucket scan to candidates, false when it must scan the bucket in
 * full (always sound). */
static bool prefilter_candidates(
    sigma_eval_t* e, sigma_field_fn fn, void* ctx, const uint32_t* buckets, uint32_t n_buckets) {
    const sigma_db_t* db = e->db;
    const sigma_teddy_t* t = (const sigma_teddy_t*)db->teddy;
    if (!e->rule_mask || !e->prefilter_on) return false;
    if (!t && db->n_fwit == 0) return false;

    /* Always-verify rules are candidates unconditionally (never gated). */
    for (uint32_t i = 0; i < db->n_litav; i++) {
        uint32_t ri = db->litav[i];
        e->rule_gen[ri] = e->gen;
        e->rule_mask[ri] = rule_full_mask(db, ri);
    }

    for (uint32_t i = 0; i < db->n_fwit; i++) {
        const sigma_fwit_t* w = &db->fwit[i];
        if (fwit_holds(e, fn, ctx, w)) {
            pf_touch(e, w->rule_idx);
            e->rule_mask[w->rule_idx] |= 1u << w->clause_idx;
        }
    }

    size_t scanned = 0;
    if (t) {
        for (uint32_t f = 0; f < db->n_fields; f++) {
            /* Only a field named by a rule in one of the buckets about to be
             * evaluated can carry a literal one of them requires. */
            if (!scan_field(db, buckets, n_buckets, f)) continue;
            const sigma_teddy_t* tf = t;
            if (!db->lit_any_field && db->field_teddy) {
                tf = (const sigma_teddy_t*)db->field_teddy[f];
                if (!tf) continue; /* no string needle is posted to this field */
            }
            size_t vlen = 0;
            const char* v = resolve_field(e, fn, ctx, (uint16_t)f, &vlen);
            if (!v || vlen < 2) continue; /* a needle is at least 2 bytes */
            e->cur_field = (uint16_t)f;
            teddy_confirm(tf, v, vlen, &e->tscr, mark_postings, e);
            scanned += vlen;
        }
    }
    e->st.chain_steps = e->tscr.chain_steps;
    e->st.haystack_bytes += scanned;
    e->st.prefilter_runs++;
    return true;
}

/* teddy_confirm callback: a needle confirmed in e->cur_field credits, for every
 * posting that names that field, the witness clause it belongs to. */
static void mark_postings(void* ctx, uint32_t needle_index) {
    sigma_eval_t* e = (sigma_eval_t*)ctx;
    const sigma_db_t* db = e->db;
    e->st.needles_confirmed++;
    const sigma_litpost_t* post = &db->litpost[needle_index];
    const sigma_litref_t* refs = db->litpost_ref + post->idx_start;
    for (uint32_t k = 0; k < post->idx_count; k++) {
        const sigma_litref_t* r = &refs[k];
        if (r->field_id != SIGMA_LITREF_ANY_FIELD && r->field_id != e->cur_field) continue;
        pf_touch(e, r->rule_idx);
        e->rule_mask[r->rule_idx] |= 1u << r->clause_idx;
    }
}

/* Run a bucket through the prefilter: evaluate only candidate rules.  Falls back
 * to the full bucket scan when the prefilter could not run. */
static inline void eval_bucket_prefiltered(sigma_eval_t* e,
                                           sigma_field_fn fn,
                                           void* ctx,
                                           uint32_t bucket_idx,
                                           sigma_hit_t* out,
                                           int max_hits,
                                           int* fired,
                                           bool prefiltered) {
    const sigma_db_t* db = e->db;
    const sigma_bucket_t* b = &db->buckets[bucket_idx];
    const uint32_t* idx = db->bucket_idx + b->idx_start;
    e->st.rules_in_scope += b->idx_count;
    for (uint32_t i = 0; i < b->idx_count; i++) {
        uint32_t ri = idx[i];
        if (prefiltered && !pf_is_candidate(e, ri)) continue; /* a necessary clause has no literal present */
        e->st.rules_verified++;
        eval_one_rule(e, fn, ctx, ri, out, max_hits, fired);
    }
}

/* Resolve the bucket index whose key equals the event's category (NUL-free
 * compare against the strpool key).  Returns UINT32_MAX if none matches.
 * Always-verify (empty key) is NOT returned here, it is run unconditionally. */
static uint32_t find_category_bucket(const sigma_db_t* db, const char* cat, size_t cat_len) {
    for (uint32_t i = 0; i < db->n_buckets; i++) {
        const sigma_str_t* k = &db->bucket_keys[i];
        if (k->len == cat_len && cat_len > 0 && memcmp(db->strpool + k->off, cat, cat_len) == 0) return i;
    }
    return UINT32_MAX;
}

/* Full linear scan over every rule.  Resets the memo, then evaluates all rules
 * in table order. */
static int eval_linear(sigma_eval_t* e, sigma_field_fn fn, void* ctx, sigma_hit_t* out, int max_hits) {
    const sigma_db_t* db = e->db;
    if (db->n_fields) memset(e->vstate, 0, db->n_fields * sizeof(*e->vstate));
    bump_eval_gen(e);
    int fired = 0;
    for (uint32_t i = 0; i < db->n_rules; i++) eval_one_rule(e, fn, ctx, i, out, max_hits, &fired);
    return fired;
}

int sigma_eval_run_linear(sigma_eval_t* e, sigma_field_fn fn, void* ctx, sigma_hit_t* out, int max_hits) {
    if (!e || !fn) return 0;
    return eval_linear(e, fn, ctx, out, max_hits);
}

int sigma_eval_run(sigma_eval_t* e, sigma_field_fn fn, void* ctx, sigma_hit_t* out, int max_hits) {
    if (!e || !fn) return 0;
    const sigma_db_t* db = e->db;

    /* Reset the per-event resolve memo (cheap: one memset over n_fields). */
    if (db->n_fields) memset(e->vstate, 0, db->n_fields * sizeof(*e->vstate));
    e->st.events++;
    bump_eval_gen(e);

    int fired = 0;

    /* ---- bucket narrowing -------------------------------------
     * Parsers stamp event.category, techno, and product on every
     * event ($!techno / $!product). The matcher
     * collects every present route token, looks each up in the
     * bucket index, and evaluates the UNION. A rule listed in two
     * matching buckets is verified once (eval_done). Always-verify
     * (empty logsource) is included when present.
     *
     * `technology` is a leftover alias. observer.product,
     * event.provider, event.module, event.dataset, and
     * log.syslog.appname keep older events working.
     *
     * No route field at all -> full linear scan. */
    if (db->n_buckets) {
        static const struct {
            const char* name;
            uint8_t len;
        } route[] = {
            {"event.category", 14},     {"techno", 6},          {"product", 7},       {"technology", 10},
            {"observer.product", 16},   {"event.provider", 14}, {"event.module", 12}, {"event.dataset", 13},
            {"log.syslog.appname", 18},
        };
        uint32_t sel[SIGMA_MAX_ROUTE_BUCKETS];
        uint32_t nsel = 0;
        int had_route = 0;

        for (unsigned i = 0; i < sizeof route / sizeof route[0]; i++) {
            size_t vlen = 0;
            const char* v;
            if (i == 0 && db->cat_field_id != UINT32_MAX)
                v = resolve_field(e, fn, ctx, (uint16_t)db->cat_field_id, &vlen);
            else
                v = fn(ctx, route[i].name, route[i].len, &vlen);
            if (!v || vlen == 0) continue;
            had_route = 1;
            uint32_t b = find_category_bucket(db, v, vlen);
            if (b == UINT32_MAX) continue;
            uint32_t k;
            for (k = 0; k < nsel; k++)
                if (sel[k] == b) break;
            if (k == nsel && nsel < SIGMA_MAX_ROUTE_BUCKETS) sel[nsel++] = b;
        }
        if (db->av_bucket != UINT32_MAX) {
            uint32_t k;
            for (k = 0; k < nsel; k++)
                if (sel[k] == db->av_bucket) break;
            if (k == nsel && nsel < SIGMA_MAX_ROUTE_BUCKETS) sel[nsel++] = db->av_bucket;
        }
        if (had_route) {
            bool big = false;
            for (uint32_t i = 0; i < nsel; i++) {
                if (sel[i] == db->av_bucket) continue;
                if (e->prefilter_on == 2 || db->buckets[sel[i]].idx_count >= SIGMA_PREFILTER_MIN_BUCKET) {
                    big = true;
                    break;
                }
            }
            bool pf = big ? prefilter_candidates(e, fn, ctx, sel, nsel) : false;
            for (uint32_t i = 0; i < nsel; i++) eval_bucket_prefiltered(e, fn, ctx, sel[i], out, max_hits, &fired, pf);
            return fired;
        }
        /* No route field at all: soundness over speed, full scan. */
    }

    e->st.rules_in_scope += db->n_rules;
    e->st.rules_verified += db->n_rules;
    for (uint32_t i = 0; i < db->n_rules; i++) eval_one_rule(e, fn, ctx, i, out, max_hits, &fired);
    return fired;
}

void sigma_db_free(sigma_db_t* db) {
    if (!db) return;
    if (db->re) {
        sigma_re_t* arr = (sigma_re_t*)db->re;
        for (uint32_t i = 0; i < db->n_preds; i++)
            if (arr[i].valid && arr[i].re) pcre2_code_free(arr[i].re);
        free(arr);
        db->re = NULL;
    }
    if (db->teddy) {
        sigma_teddy_free((sigma_teddy_t*)db->teddy);
        db->teddy = NULL;
    }
    free_field_teddy(db);
    free(db->bucket_fields);
    db->bucket_fields = NULL;
    if (db->backing) {
        /* Loaded from a single backing buffer: members point into it. */
        free(db->backing);
    } else {
        /* Builder-owned: each array allocated separately. */
        free(db->fields);
        free(db->values);
        free(db->preds);
        free(db->sels);
        free(db->cond);
        free(db->rules);
        free(db->cidrs);
        free(db->strpool);
        free(db->bucket_keys);
        free(db->buckets);
        free(db->bucket_idx);
        free(db->litndl);
        free(db->litpost);
        free(db->litpost_ref);
        free(db->litav);
        free(db->rule_clauses);
        free(db->fwit);
    }
    memset(db, 0, sizeof(*db));
}
