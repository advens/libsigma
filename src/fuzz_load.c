/* fuzz_load.c
 * libFuzzer target for sigma_db_load_buffer. The loader is a zero-copy parser
 * over a 136-byte header of offset/count pairs; table entries are indices into
 * other tables. Two inputs per call:
 *   1. the fuzzer bytes as a raw buffer (almost all die at magic/CRC);
 *   2. the seed artifact XOR-mutated at interior offsets with the CRC
 *      rewritten, so range validation actually runs.
 *
 * On SIGMA_OK the db owns the copy (sigma_db_free). On error the caller frees.
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

#include "sigma_format.h"
#include "sigma_simd.h"

#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>

static uint8_t *g_seed;
static size_t g_seed_len;

static void try_load(uint8_t *buf, size_t len) {
    sigma_db_t db;
    int rc;

    memset(&db, 0, sizeof(db));
    rc = sigma_db_load_buffer(buf, len, &db);
    if (rc == SIGMA_OK)
        sigma_db_free(&db); /* frees buf */
    else
        free(buf);
}

static void rewrite_crc(uint8_t *buf, size_t len) {
    uint32_t crc;

    if (len < sizeof(uint32_t) + 8) return;
    crc = sigma_crc32c(0, buf, len - sizeof(uint32_t));
    memcpy(buf + len - sizeof(uint32_t), &crc, sizeof(crc));
}

int LLVMFuzzerInitialize(int *argc, char ***argv) {
    FILE *f;
    long sz;
    const char *path = "fuzz_corpus/load/seed.sigmac";

    (void)argc;
    (void)argv;
    f = fopen(path, "rb");
    if (!f) return 0; /* raw path still runs; CRC-mutant path no-ops */
    if (fseek(f, 0, SEEK_END) != 0) {
        fclose(f);
        return 0;
    }
    sz = ftell(f);
    if (sz <= 0) {
        fclose(f);
        return 0;
    }
    rewind(f);
    g_seed = (uint8_t *)malloc((size_t)sz);
    if (!g_seed) {
        fclose(f);
        return 0;
    }
    if (fread(g_seed, 1, (size_t)sz, f) != (size_t)sz) {
        free(g_seed);
        g_seed = NULL;
        fclose(f);
        return 0;
    }
    g_seed_len = (size_t)sz;
    fclose(f);
    return 0;
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    uint8_t *raw;
    uint8_t *mut;
    size_t i;
    size_t span;

    raw = (uint8_t *)malloc(size ? size : 1);
    if (!raw) return 0;
    if (size) memcpy(raw, data, size);
    try_load(raw, size);

    if (g_seed && g_seed_len >= 140 && size > 0) {
        mut = (uint8_t *)malloc(g_seed_len);
        if (!mut) return 0;
        memcpy(mut, g_seed, g_seed_len);
        /* Stay inside the body, leave magic/version and trailing CRC slot. */
        span = g_seed_len - 12;
        for (i = 0; i < size; i++) mut[8 + (i % span)] ^= data[i];
        rewrite_crc(mut, g_seed_len);
        try_load(mut, g_seed_len);
    }
    return 0;
}
