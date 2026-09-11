/* bench_corpus.c
 * Corpus-scale throughput harness for the Sigma matcher: load a compiled
 * `.sigmac` artifact and a TSV event corpus (the same key=value shape
 * sigma_cli reads), then report per-event cost for the three candidate-
 * narrowing stages the matcher can run:
 *
 *   linear   every rule, no bucket index      (pre-bucketing baseline)
 *   bucket   category bucket + always-verify  (prefilter off)
 *   teddy    the same buckets, literal-prefiltered
 *
 * The prefiltered run is gated against the bucket run: the two must produce
 * the SAME hit multiset for every event, or the prefilter dropped a real
 * match and the harness fails.  Soundness first, throughput second.
 *
 * Build: make bench
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

#define _POSIX_C_SOURCE 200809L /* getline, strtok_r, clock_gettime */

#include "sigma_match.h"
#include "sigma_format.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <stdint.h>

#define MAX_KV 64
#define MAX_HITS 256

typedef struct {
    const char* k;
    size_t klen;
    const char* v;
    size_t vlen;
} kv_t;

typedef struct {
    char* buf; /* owned, NUL-punched copy of the TSV line */
    kv_t kv[MAX_KV];
    int n;
} event_t;

typedef struct {
    event_t* ev;
    size_t n, cap;
} corpus_t;

static const char* ev_lookup(void* ctx, const char* name, uint32_t name_len, size_t* out_len) {
    const event_t* e = (const event_t*)ctx;
    for (int i = 0; i < e->n; i++) {
        if (e->kv[i].klen == name_len && memcmp(e->kv[i].k, name, name_len) == 0) {
            *out_len = e->kv[i].vlen;
            return e->kv[i].v;
        }
    }
    *out_len = 0;
    return NULL;
}

static void parse_event(event_t* e) {
    e->n = 0;
    char* save = NULL;
    for (char* tok = strtok_r(e->buf, "\t", &save); tok && e->n < MAX_KV; tok = strtok_r(NULL, "\t", &save)) {
        char* eq = strchr(tok, '=');
        if (!eq) continue;
        *eq = '\0';
        e->kv[e->n].k = tok;
        e->kv[e->n].klen = (size_t)(eq - tok);
        e->kv[e->n].v = eq + 1;
        e->kv[e->n].vlen = strlen(eq + 1);
        e->n++;
    }
}

static int corpus_load(const char* path, corpus_t* c) {
    FILE* f = fopen(path, "r");
    if (!f) return -1;
    char* line = NULL;
    size_t cap = 0;
    ssize_t len;
    while ((len = getline(&line, &cap, f)) != -1) {
        if (len > 0 && line[len - 1] == '\n') line[--len] = '\0';
        if (len == 0) continue;
        if (c->n == c->cap) {
            size_t nc = c->cap ? c->cap * 2 : 1024;
            event_t* p = realloc(c->ev, nc * sizeof(*p));
            if (!p) break;
            c->ev = p;
            c->cap = nc;
        }
        event_t* e = &c->ev[c->n];
        e->buf = strdup(line);
        if (!e->buf) break;
        parse_event(e);
        c->n++;
    }
    free(line);
    fclose(f);
    return 0;
}

static void corpus_free(corpus_t* c) {
    for (size_t i = 0; i < c->n; i++) free(c->ev[i].buf);
    free(c->ev);
}

static double now_s(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (double)ts.tv_sec + (double)ts.tv_nsec * 1e-9;
}

static int cmp_u32(const void* a, const void* b) {
    uint32_t x = *(const uint32_t*)a, y = *(const uint32_t*)b;
    return (x > y) - (x < y);
}

/* One pass over the corpus.  `mode` selects the narrowing stage; when `sink` is
 * non-NULL the per-event hit rule-ids are recorded (sorted) so two passes can be
 * compared.  Returns the total number of fired rules. */
static long run_pass(sigma_eval_t* e, const corpus_t* c, int mode, uint32_t* sink, int* sink_n) {
    long fired_total = 0;
    sigma_hit_t hits[MAX_HITS];
    for (size_t i = 0; i < c->n; i++) {
        int n;
        if (mode == 0) {
            sigma_eval_set_prefilter(e, 0);
            n = sigma_eval_run_linear(e, ev_lookup, (void*)&c->ev[i], hits, MAX_HITS);
        } else {
            sigma_eval_set_prefilter(e, mode == 1 ? 0 : 2);
            n = sigma_eval_run(e, ev_lookup, (void*)&c->ev[i], hits, MAX_HITS);
        }
        if (n > MAX_HITS) n = MAX_HITS;
        if (sink) {
            uint32_t* slot = sink + i * MAX_HITS;
            for (int k = 0; k < n; k++) slot[k] = hits[k].rule_id;
            qsort(slot, (size_t)n, sizeof(*slot), cmp_u32);
            sink_n[i] = n;
        }
        fired_total += n;
    }
    return fired_total;
}

static void report(const char* label, double secs, size_t n_events, long hits, int iters) {
    double per_ev_us = secs * 1e6 / (double)(n_events * (size_t)iters);
    fprintf(stdout, "  %-8s %9.2f us/event %12.0f events/s   hits=%ld\n", label, per_ev_us, 1.0 / (per_ev_us * 1e-6),
            hits);
}

int main(int argc, char** argv) {
    if (argc < 3) {
        fprintf(stderr, "usage: %s <rules.sigmac> <events.tsv> [iters]\n", argv[0]);
        return 2;
    }
    int iters = (argc > 3) ? atoi(argv[3]) : 1;
    if (iters < 1) iters = 1;

    sigma_db_t db;
    int rc = sigma_db_load_file(argv[1], &db);
    if (rc != SIGMA_OK) {
        fprintf(stderr, "load '%s' failed: status %d\n", argv[1], rc);
        return 1;
    }

    corpus_t c = {0};
    if (corpus_load(argv[2], &c) != 0 || c.n == 0) {
        fprintf(stderr, "no events read from '%s'\n", argv[2]);
        sigma_db_free(&db);
        return 1;
    }

    printf("artifact %s: %u rules, %u preds, %u fields, %u buckets, %u needles, %u always-verify\n", argv[1],
           db.n_rules, db.n_preds, db.n_fields, db.n_buckets, db.n_litndl, db.n_litav);
    for (uint32_t i = 0; i < db.n_buckets; i++) {
        const sigma_str_t* k = &db.bucket_keys[i];
        printf("  bucket %-22.*s %6u rules\n", k->len ? (int)k->len : 14,
               k->len ? db.strpool + k->off : "(always-verify)", db.buckets[i].idx_count);
    }
    printf("corpus %s: %zu events, %d iteration(s)\n", argv[2], c.n, iters);

    sigma_eval_t* e = sigma_eval_create(&db);
    if (!e) {
        corpus_free(&c);
        sigma_db_free(&db);
        return 1;
    }

    uint32_t* ref = calloc(c.n * MAX_HITS, sizeof(*ref));
    uint32_t* got = calloc(c.n * MAX_HITS, sizeof(*got));
    int* ref_n = calloc(c.n, sizeof(*ref_n));
    int* got_n = calloc(c.n, sizeof(*got_n));
    if (!ref || !got || !ref_n || !got_n) {
        fprintf(stderr, "out of memory sizing the hit-set oracle\n");
        free(ref);
        free(got);
        free(ref_n);
        free(got_n);
        sigma_eval_free(e);
        corpus_free(&c);
        sigma_db_free(&db);
        return 1;
    }

    /* Soundness gate: the bucket scan is the oracle, the prefiltered scan must
     * reproduce it exactly. */
    run_pass(e, &c, 1, ref, ref_n);
    run_pass(e, &c, 2, got, got_n);
    long diffs = 0;
    for (size_t i = 0; i < c.n; i++) {
        if (ref_n[i] != got_n[i] ||
            memcmp(ref + i * MAX_HITS, got + i * MAX_HITS, (size_t)ref_n[i] * sizeof(*ref)) != 0) {
            if (diffs < 5) {
                fprintf(stderr, "HIT-SET MISMATCH event %zu: bucket=%d prefilter=%d, missing rule_id:", i, ref_n[i],
                        got_n[i]);
                for (int a = 0; a < ref_n[i]; a++) {
                    int found = 0;
                    for (int g = 0; g < got_n[i]; g++)
                        if (got[i * MAX_HITS + g] == ref[i * MAX_HITS + a]) found = 1;
                    if (!found) fprintf(stderr, " %u", ref[i * MAX_HITS + a]);
                }
                fprintf(stderr, "\n");
            }
            diffs++;
        }
    }

    {
        /* Soundness passes pollute the counters (the bucket oracle verifies
         * every in-scope rule).  Re-run the prefilter once on a clean slate so
         * the ratio is the candidate rate, not an average of gated and ungated. */
        sigma_eval_reset_stats(e);
        run_pass(e, &c, 2, NULL, NULL);
        sigma_eval_stats_t st;
        sigma_eval_get_stats(e, &st);
        if (st.rules_in_scope) {
            printf(
                "candidate rate: %.2f%% of in-scope rules verified (%llu/%llu), "
                "prefilter ran on %llu/%llu events, %.0f needles + %.0f haystack bytes per event\n",
                100.0 * (double)st.rules_verified / (double)st.rules_in_scope, (unsigned long long)st.rules_verified,
                (unsigned long long)st.rules_in_scope, (unsigned long long)st.prefilter_runs,
                (unsigned long long)st.events,
                st.prefilter_runs ? (double)st.needles_confirmed / (double)st.prefilter_runs : 0.0,
                st.prefilter_runs ? (double)st.haystack_bytes / (double)st.prefilter_runs : 0.0);
            printf("chain steps: %.0f per prefiltered event\n",
                   st.prefilter_runs ? (double)st.chain_steps / (double)st.prefilter_runs : 0.0);
        }
    }

    printf("\nthroughput:\n");
    for (int mode = 0; mode <= 2; mode++) {
        run_pass(e, &c, mode, NULL, NULL); /* warm */
        double t0 = now_s();
        long hits = 0;
        for (int it = 0; it < iters; it++) hits = run_pass(e, &c, mode, NULL, NULL);
        double secs = now_s() - t0;
        report(mode == 0 ? "linear" : mode == 1 ? "bucket" : "teddy", secs, c.n, hits, iters);
    }

    if (diffs) {
        fprintf(stderr, "\nPREFILTER UNSOUND: %ld/%zu events differ from the bucket-scan oracle\n", diffs, c.n);
    } else {
        printf("\nprefilter hit-set == bucket-scan hit-set on all %zu events\n", c.n);
    }

    free(ref);
    free(got);
    free(ref_n);
    free(got_n);
    sigma_eval_free(e);
    corpus_free(&c);
    sigma_db_free(&db);
    return diffs ? 1 : 0;
}
