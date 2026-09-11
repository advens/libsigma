/* fuzz_match.c
 * libFuzzer target for sigma_eval_run. The rule db is a fixed, valid artifact
 * (seed.sigmac). The fuzzer bytes are the field values, including embedded NUL,
 * high bytes, empty, and over-long inputs. Prefilter is forced on so Teddy and
 * PCRE2 both see adversarial haystacks.
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
 * distributed under the License is distributed as an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include "sigma_match.h"
#include "sigma_format.h"

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

typedef struct {
    const char *p;
    size_t n;
} blob_t;

static sigma_db_t g_db;
static sigma_eval_t *g_ev;
static int g_ready;

static const char *blob_field(void *ctx, const char *name, uint32_t name_len, size_t *out_len) {
    blob_t *b = (blob_t *)ctx;

    (void)name;
    (void)name_len;
    if (!b->p || b->n == 0) {
        *out_len = 0;
        return NULL;
    }
    *out_len = b->n;
    return b->p;
}

int LLVMFuzzerInitialize(int *argc, char ***argv) {
    int rc;

    (void)argc;
    (void)argv;
    memset(&g_db, 0, sizeof(g_db));
    rc = sigma_db_load_file("fuzz_corpus/load/seed.sigmac", &g_db);
    if (rc != SIGMA_OK) {
        fprintf(stderr, "fuzz_match: cannot load seed.sigmac (status %d)\n", rc);
        return 0;
    }
    g_ev = sigma_eval_create(&g_db);
    if (!g_ev) {
        sigma_db_free(&g_db);
        fprintf(stderr, "fuzz_match: sigma_eval_create failed\n");
        return 0;
    }
    sigma_eval_set_prefilter(g_ev, 2); /* FORCE: Teddy even on small buckets */
    g_ready = 1;
    return 0;
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    blob_t b;
    sigma_hit_t hits[16];

    if (!g_ready) return 0;
    b.p = size ? (const char *)data : NULL;
    b.n = size;
    (void)sigma_eval_run(g_ev, blob_field, &b, hits, 16);
    return 0;
}
