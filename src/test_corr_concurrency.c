/* test_corr_concurrency.c
 * Concurrency stress test for the engine-concurrent correlation engine.
 * Many threads feed ONE shared corr_engine_t through corr_on_event with a mix of
 * event_count / value_count / temporal correlations over a churning group-key
 * space (forcing concurrent group create, LRU eviction, distinct eviction, the
 * temporal seen-table, and the periodic sweep).  Each worker uses its OWN fires[]
 * and group scratch, so no fired-group storage is shared.
 *
 * Built under ThreadSanitizer this proves the
 * per-correlation locking, the single-flight sweep, and the relaxed-atomic
 * boundary counters are race-free.  Without a sanitizer it is still a smoke test
 * that concurrent access does not crash and leaves the engine self-consistent.
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

#include "classify_corr.h"

#include <pthread.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#define NTHREADS 8
#define ITERS 30000

/* ---- event + field resolver (caller-owned per-call values) ---- */
typedef struct {
    const char* ip;
    const char* host;
    const char* user;
    const char* bytes;
} ev_t;

static const char* ev_field(void* ctx, const char* name) {
    const ev_t* e = (const ev_t*)ctx;
    if (strcmp(name, "source.ip") == 0) return e->ip;
    if (strcmp(name, "host.name") == 0) return e->host;
    if (strcmp(name, "user.name") == 0) return e->user;
    if (strcmp(name, "destination.bytes") == 0) return e->bytes;
    return NULL;
}

/* ---- rules: caller owns the arrays for the engine's lifetime ---- */
static const char* GB_IP[] = {"source.ip"};
static const char* GB_HOST[] = {"host.name"};
static const uint32_t B_EC[] = {1};
static const uint32_t B_VC[] = {2};
static const uint32_t B_TP[] = {3, 4};
static const uint32_t B_VS[] = {5};

static corr_rule_t RULES[] = {{.id = "ec",
                               .type = CORR_EVENT_COUNT,
                               .base_rule_ids = B_EC,
                               .n_base_rule_ids = 1,
                               .group_by = GB_IP,
                               .n_group_by = 1,
                               .cond_op = CORR_OP_GTE,
                               .cond_count = 5,
                               .timespan_s = 60,
                               .level = "high"},
                              {.id = "vc",
                               .type = CORR_VALUE_COUNT,
                               .base_rule_ids = B_VC,
                               .n_base_rule_ids = 1,
                               .group_by = GB_IP,
                               .n_group_by = 1,
                               .value_field = "user.name",
                               .cond_op = CORR_OP_GTE,
                               .cond_count = 3,
                               .timespan_s = 60,
                               .level = "high"},
                              {.id = "tp",
                               .type = CORR_TEMPORAL,
                               .base_rule_ids = B_TP,
                               .n_base_rule_ids = 2,
                               .group_by = GB_HOST,
                               .n_group_by = 1,
                               .cond_op = CORR_OP_GTE,
                               .cond_count = 2,
                               .timespan_s = 60,
                               .level = "high"},
                              {.id = "vs",
                               .type = CORR_VALUE_SUM,
                               .base_rule_ids = B_VS,
                               .n_base_rule_ids = 1,
                               .group_by = GB_IP,
                               .n_group_by = 1,
                               .value_field = "destination.bytes",
                               .cond_op = CORR_OP_GTE,
                               .cond_count = 4096,
                               .timespan_s = 60,
                               .level = "high"},
                              {.id = "bc",
                               .type = CORR_BEACONING,
                               .base_rule_ids = B_EC, /* rid 1, shared with "ec" */
                               .n_base_rule_ids = 1,
                               .group_by = GB_IP,
                               .n_group_by = 1,
                               .cond_op = CORR_OP_GTE,
                               .cond_count = 6,
                               .beacon_cv_permille = 200,
                               .timespan_s = 60,
                               .level = "high"}};

static corr_engine_t* g_eng;
static long g_fires; /* summed via relaxed atomic */

static void* worker(void* arg) {
    long tid = (long)arg;
    uint32_t s = 0x9e3779b9u ^ (uint32_t)(tid * 2654435761u); /* per-thread deterministic PRNG */
    corr_fire_t fires[16];
    const char* scratch[16 * CORR_MAX_GROUP_FIELDS];
    long local = 0;

    for (int i = 0; i < ITERS; i++) {
        s = s * 1664525u + 1013904223u;
        unsigned r = s >> 8;

        /* Churning key space (>> max_groups) to force concurrent eviction. */
        char ipbuf[24], hostbuf[16], userbuf[16], bytesbuf[16];
        snprintf(ipbuf, sizeof(ipbuf), "10.%u.%u.%u", (r >> 3) & 15, (r >> 7) & 15, r & 63);
        snprintf(hostbuf, sizeof(hostbuf), "h%u", (r >> 2) & 31);
        snprintf(userbuf, sizeof(userbuf), "u%u", (r >> 5) & 15);
        /* mix numeric and non-numeric values so value_sum exercises both the
         * ev_val ring push and the values_nonnumeric skip path under contention. */
        if ((r & 7) == 0)
            snprintf(bytesbuf, sizeof(bytesbuf), "n/a");
        else
            snprintf(bytesbuf, sizeof(bytesbuf), "%u", (r & 1023) + 1);
        ev_t ev = {ipbuf, hostbuf, userbuf, bytesbuf};

        uint32_t rids[2];
        int nr = 0;
        switch (r % 5) {
            case 0:
                rids[nr++] = 1;
                break; /* event_count base */
            case 1:
                rids[nr++] = 2;
                break; /* value_count base */
            case 2:
                rids[nr++] = 3;
                break; /* temporal base A */
            case 3:
                rids[nr++] = 5;
                break; /* value_sum base */
            default:
                rids[nr++] = 3;
                rids[nr++] = 4;
                break; /* temporal A+B */
        }

        /* Monotonic-ish event time; advancing well past sweep_interval so the
         * periodic sweep runs (single-flight) under concurrency. */
        double ts = 1000.0 + (double)i * 0.01 + (double)tid;

        int nf = corr_on_event(g_eng, rids, (size_t)nr, ev_field, &ev, ts, fires, 16, scratch,
                               sizeof(scratch) / sizeof(scratch[0]));
        if (nf > 0) {
            local += nf;
            /* Exercise the returned group pointers AFTER the call (they must
             * reference this worker's scratch + still-valid stack buffers). */
            if (fires[0].group != NULL && fires[0].group[0] != NULL) {
                volatile size_t glen = strlen(fires[0].group[0]);
                (void)glen;
            }
        }
    }
    __atomic_fetch_add(&g_fires, local, __ATOMIC_RELAXED);
    return NULL;
}

int main(void) {
    corr_caps_t caps = corr_caps_default();
    caps.max_groups = 16; /* small vs the key space => heavy concurrent eviction */

    g_eng = corr_engine_new(RULES, sizeof(RULES) / sizeof(RULES[0]), caps);
    if (g_eng == NULL) {
        fprintf(stderr, "corr_engine_new failed\n");
        return 1;
    }

    pthread_t th[NTHREADS];
    for (long t = 0; t < NTHREADS; t++) {
        if (pthread_create(&th[t], NULL, worker, (void*)t) != 0) {
            fprintf(stderr, "pthread_create failed\n");
            return 1;
        }
    }
    for (int t = 0; t < NTHREADS; t++) pthread_join(th[t], NULL);

    /* Single-threaded post-join sanity. */
    corr_stats_t st;
    corr_engine_stats(g_eng, &st);
    size_t groups = corr_engine_total_groups(g_eng);

    int ok = 1;
    if (corr_engine_rule_count(g_eng) != 5) ok = 0; /* ec + vc + tp + vs + bc */
    /* Every correlation's live group count is capped at max_groups. */
    if (groups > (size_t)caps.max_groups * 5) ok = 0;

    printf(
        "concurrency: %d threads x %d iters, fires=%ld, live_groups=%zu, "
        "groups_evicted=%llu, oom_dropped=%llu\n",
        NTHREADS, ITERS, g_fires, groups, (unsigned long long)st.groups_evicted, (unsigned long long)st.oom_dropped);

    corr_engine_free(g_eng);

    if (ok) {
        printf("libsigma correlation concurrency: PASSED\n");
        return 0;
    }
    printf("libsigma correlation concurrency: FAILED\n");
    return 1;
}
