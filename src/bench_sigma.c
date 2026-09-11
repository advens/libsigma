/* bench_sigma.c
 * Throughput microbench for the Sigma matcher, CONTAINS-heavy ruleset over
 * a long field (the case the SSE4.2/NEON substring path accelerates).  Not a
 * unit test; a throughput sanity gauge.
 *
 * Build: clang -std=c11 -O3 -march=native bench_sigma.c sigma_match.c -o bench_sigma
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

#define _POSIX_C_SOURCE 199309L /* clock_gettime, CLOCK_MONOTONIC (Linux) */

#include "sigma_match.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <stdint.h>

/* ---- compact, bench-local db construction (one "message" field, N contains) ---- */
static char POOL[2048];
static uint32_t POOLN;

static uint32_t pool_put(const char* s) {
    uint32_t off = POOLN, n = (uint32_t)strlen(s);
    memcpy(POOL + off, s, n);
    POOLN += n;
    return off;
}

static const char* NEEDLES[] = {
    "-EncodedCommand", "/etc/passwd", "sqlmap",     "UNION SELECT", "cmd.exe /c",
    "powershell",      "base64 -d",   "/bin/sh -i", "wget http",    "Invoke-Expression",
};
#define NRULES ((int)(sizeof(NEEDLES) / sizeof(NEEDLES[0])))

static sigma_str_t g_fields[1];
static sigma_str_t g_values[NRULES];
static sigma_pred_t g_preds[NRULES];
static sigma_sel_t g_sels[NRULES];
static sigma_rule_t g_rules[NRULES];

static const char* ev_lookup(void* ctx, const char* name, uint32_t name_len, size_t* out_len) {
    (void)name;
    (void)name_len;
    const char* msg = (const char*)ctx;
    *out_len = strlen(msg);
    return msg;
}

static double now_s(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (double)ts.tv_sec + (double)ts.tv_nsec / 1e9;
}

int main(int argc, char** argv) {
    long iters = (argc > 1) ? strtol(argv[1], NULL, 10) : 2000000;

    uint32_t foff = pool_put("message");
    g_fields[0] = (sigma_str_t){foff, 7};

    for (int i = 0; i < NRULES; i++) {
        uint32_t voff = pool_put(NEEDLES[i]);
        g_values[i] = (sigma_str_t){voff, (uint32_t)strlen(NEEDLES[i])};
        g_preds[i] = (sigma_pred_t){
            .field_id = 0, .group_id = 0, .op = SIGMA_OP_CONTAINS, .flags = 0, .value_id = (uint32_t)i, .ival = 0};
        g_sels[i] = (sigma_sel_t){(uint32_t)i, 1};
        g_rules[i] = (sigma_rule_t){.rule_id = (uint32_t)(1000 + i),
                                    .sel_start = (uint32_t)i,
                                    .sel_count = 1,
                                    .cond_start = 0,
                                    .cond_count = 0,
                                    .verdict = SIGMA_VERDICT_ALERT,
                                    .severity = 2,
                                    .score_x100 = 20,
                                    .name_id = SIGMA_NO_VALUE,
                                    .mitre_id = SIGMA_NO_VALUE};
    }

    sigma_db_t db;
    memset(&db, 0, sizeof(db));
    db.fields = g_fields;
    db.n_fields = 1;
    db.values = g_values;
    db.n_values = NRULES;
    db.preds = g_preds;
    db.n_preds = NRULES;
    db.sels = g_sels;
    db.n_sels = NRULES;
    db.rules = g_rules;
    db.n_rules = NRULES;
    db.strpool = POOL;
    db.strpool_len = POOLN;
    db.backing = NULL;

    sigma_eval_t* ev = sigma_eval_create(&db);

    /* A long, mostly-benign access-log-ish line (no needle until the tail of
     * the matching variant), the worst case for substring scanning. */
    const char* benign =
        "2026-06-17T09:50:00Z 203.0.113.7 GET /api/v1/products?cat=42&sort=price "
        "HTTP/1.1 200 5123 \"https://shop.example.com/\" \"Mozilla/5.0 (X11; Linux "
        "x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120 Safari/537.36\"";
    const char* malicious =
        "2026-06-17T09:50:01Z 198.51.100.9 POST /login id=1 UNION SELECT user,pass "
        "FROM accounts -- HTTP/1.1 500 91 \"-\" \"sqlmap/1.7\"";

    sigma_hit_t hits[NRULES];

    /* warmup + correctness sanity */
    int hb = sigma_eval_run(ev, ev_lookup, (void*)benign, hits, NRULES);
    int hm = sigma_eval_run(ev, ev_lookup, (void*)malicious, hits, NRULES);

    volatile long sink = 0;
    double t0 = now_s();
    for (long i = 0; i < iters; i++) {
        const char* msg = (i & 1) ? malicious : benign;
        sink += sigma_eval_run(ev, ev_lookup, (void*)msg, hits, NRULES);
    }
    double dt = now_s() - t0;

    double evps = iters / dt;
    printf("libsigma bench: %ld events x %d contains-rules in %.3f s\n", iters, NRULES, dt);
    printf("  %.2f M events/s  |  %.1f ns/event  |  %.2f ns/(event*rule)\n", evps / 1e6, dt / iters * 1e9,
           dt / iters / NRULES * 1e9);
    printf("  (benign hits=%d malicious hits=%d, sink=%ld)\n", hb, hm, (long)sink);

    sigma_eval_free(ev);
    return 0;
}
