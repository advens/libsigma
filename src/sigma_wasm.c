/* sigma_wasm.c
 * WebAssembly exports over sigma_events.h.  Built only into the wasm32-wasip1
 * reactor module (make wasm); not part of the native library.
 *
 * Calling convention
 *   The host copies its input into module memory with sigma_wasm_alloc, calls
 *   an entry point with (pointer, length) pairs, reads the NUL-terminated JSON
 *   answer at the returned pointer, then releases both with sigma_wasm_free.
 *   A NULL answer means the module ran out of memory.
 *
 *   Engines are addressed by a handle from sigma_wasm_load: 1..16 on success,
 *   negative on failure (a sigma_status_t value, or SIGMA_WASM_ERR_FULL when
 *   all 16 slots are in use).  A handle that is not live answers
 *   {"ok":false,"error":"no engine"}; the module never dereferences a value the
 *   host passed as a pointer to an engine.
 *
 * sigma_wasm_abi_version changes when an export is added, removed, or changes
 * its signature.  The JSON answers carry their own schema version
 * (sigma_wasm_schema_version, SIGMA_EVENTS_SCHEMA).
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

#include "sigma_events.h"
#include "sigma_format.h"

#include <stdint.h>
#include <stdlib.h>

#define SIGMA_WASM_ABI 1u
#define SIGMA_WASM_MAX_ENGINES 16u
#define SIGMA_WASM_ERR_FULL (-100)

#if defined(__wasm__)
    #define WASM_EXPORT(name) __attribute__((export_name(name)))
#else
    #define WASM_EXPORT(name)
#endif

static sigma_events_t* g_engines[SIGMA_WASM_MAX_ENGINES];

static sigma_events_t* engine_at(int32_t h) {
    if (h < 1 || (uint32_t)h > SIGMA_WASM_MAX_ENGINES) return NULL;
    return g_engines[h - 1];
}

WASM_EXPORT("sigma_wasm_abi_version") uint32_t sigma_wasm_abi_version(void) {
    return SIGMA_WASM_ABI;
}

WASM_EXPORT("sigma_wasm_schema_version") uint32_t sigma_wasm_schema_version(void) {
    return SIGMA_EVENTS_SCHEMA;
}

WASM_EXPORT("sigma_wasm_format_version") uint32_t sigma_wasm_format_version(void) {
    return SIGMA_FORMAT_VERSION;
}

WASM_EXPORT("sigma_wasm_format_version_min") uint32_t sigma_wasm_format_version_min(void) {
    return SIGMA_FORMAT_VERSION_MIN;
}

WASM_EXPORT("sigma_wasm_alloc") void* sigma_wasm_alloc(uint32_t n) {
    return malloc(n ? n : 1);
}

WASM_EXPORT("sigma_wasm_free") void sigma_wasm_free(void* p) {
    free(p);
}

WASM_EXPORT("sigma_wasm_load") int32_t sigma_wasm_load(const uint8_t* buf, uint32_t len) {
    uint32_t slot;
    for (slot = 0; slot < SIGMA_WASM_MAX_ENGINES; slot++)
        if (g_engines[slot] == NULL) break;
    if (slot == SIGMA_WASM_MAX_ENGINES) return SIGMA_WASM_ERR_FULL;
    int status = SIGMA_OK;
    sigma_events_t* se = sigma_events_load(buf, len, &status);
    if (se == NULL) return status < 0 ? status : SIGMA_ERR_NOMEM;
    g_engines[slot] = se;
    return (int32_t)(slot + 1);
}

WASM_EXPORT("sigma_wasm_unload") void sigma_wasm_unload(int32_t h) {
    if (h < 1 || (uint32_t)h > SIGMA_WASM_MAX_ENGINES) return;
    sigma_events_free(g_engines[h - 1]);
    g_engines[h - 1] = NULL;
}

WASM_EXPORT("sigma_wasm_info") char* sigma_wasm_info(int32_t h) {
    return sigma_events_info_json(engine_at(h));
}

WASM_EXPORT("sigma_wasm_match") char* sigma_wasm_match(int32_t h, const char* events, uint32_t len) {
    return sigma_events_match_json(engine_at(h), events, len);
}

WASM_EXPORT("sigma_wasm_explain")
char* sigma_wasm_explain(int32_t h, const char* event, uint32_t len, uint32_t rule_id) {
    return sigma_events_explain_json(engine_at(h), event, len, rule_id);
}

WASM_EXPORT("sigma_wasm_correlate")
char* sigma_wasm_correlate(int32_t h, const char* corr_json, uint32_t corr_len, const char* events, uint32_t len) {
    return sigma_events_correlate_json(engine_at(h), corr_json, corr_len, events, len);
}
