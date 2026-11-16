/* fuzz_events.c
 * libFuzzer target for the JSON front end (sigma_events).  The first input
 * byte picks the call (match, explain one corpus rule, correlate) and the rest
 * is the events text.  Oracle, beyond ASan and UBSan: every answer is NULL (out
 * of memory) or valid JSON.
 *
 * The artifact and the correlations come from the environment:
 *   SIGMA_EVENTS_FUZZ_SIGMAC   a .sigmac (make writes build/corpus.sigmac)
 *   SIGMA_EVENTS_FUZZ_CORR     a rules.corr.json
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

#include <json.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static sigma_events_t* g_se;
static char* g_corr;
static size_t g_corr_len;

static const uint32_t k_rules[] = {10, 20, 30, 40, 50, 60, 70, 80, 90, 100};

static char* slurp(const char* path, size_t* len) {
    FILE* f = path ? fopen(path, "rb") : NULL;
    if (f == NULL) return NULL;
    char* buf = NULL;
    size_t cap = 0, n = 0;
    for (;;) {
        if (n == cap) {
            size_t nc = cap ? cap * 2 : 4096;
            char* nb = realloc(buf, nc + 1);
            if (nb == NULL) {
                free(buf);
                fclose(f);
                return NULL;
            }
            buf = nb;
            cap = nc;
        }
        size_t r = fread(buf + n, 1, cap - n, f);
        n += r;
        if (r == 0) break;
    }
    fclose(f);
    buf[n] = '\0';
    *len = n;
    return buf;
}

int LLVMFuzzerInitialize(int* argc, char*** argv) {
    (void)argc;
    (void)argv;
    size_t slen = 0;
    char* sigmac = slurp(getenv("SIGMA_EVENTS_FUZZ_SIGMAC"), &slen);
    g_corr = slurp(getenv("SIGMA_EVENTS_FUZZ_CORR"), &g_corr_len);
    if (sigmac == NULL || g_corr == NULL) {
        fprintf(stderr, "fuzz_events: set SIGMA_EVENTS_FUZZ_SIGMAC and SIGMA_EVENTS_FUZZ_CORR\n");
        abort();
    }
    int st = 0;
    g_se = sigma_events_load((const uint8_t*)sigmac, slen, &st);
    free(sigmac);
    if (g_se == NULL) {
        fprintf(stderr, "fuzz_events: artifact load failed, status %d\n", st);
        abort();
    }
    return 0;
}

int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
    if (size < 1) return 0;
    const char* text = (const char*)data + 1;
    size_t len = size - 1;
    char* answer;
    switch (data[0] % 3) {
        case 0:
            answer = sigma_events_match_json(g_se, text, len);
            break;
        case 1:
            answer = sigma_events_explain_json(g_se, text, len, k_rules[(data[0] / 3) % 10]);
            break;
        default:
            answer = sigma_events_correlate_json(g_se, g_corr, g_corr_len, text, len);
            break;
    }
    if (answer == NULL) return 0;
    json_object* j = json_tokener_parse(answer);
    if (j == NULL) {
        fprintf(stderr, "fuzz_events: answer is not JSON: %.200s\n", answer);
        abort();
    }
    json_object_put(j);
    sigma_events_str_free(answer);
    return 0;
}
