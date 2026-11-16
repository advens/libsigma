/* fuzz_corr.c
 * libFuzzer target for corr_artifact_parse. The input is handed over as is:
 * libFuzzer's buffer is exactly size bytes with no NUL after it, so a read
 * past len is an ASan finding. A parsed artifact has every rule walked.
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
#include "corr_format.h"

#include <stdint.h>
#include <string.h>

int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
    struct corr_artifact_view view;
    corr_artifact_t* a = corr_artifact_parse((const char*)data, size, &view);
    if (a == NULL) return 0;
    size_t sink = 0;
    for (size_t i = 0; i < view.n; i++) {
        const corr_rule_t* r = &view.rules[i];
        if (r->id != NULL) sink += strlen(r->id);
        for (size_t k = 0; k < r->n_base_rule_ids; k++) sink += r->base_rule_ids[k];
        for (size_t k = 0; k < r->n_group_by; k++) {
            if (r->group_by[k] != NULL) sink += strlen(r->group_by[k]);
        }
    }
    corr_artifact_free(a);
    return sink == SIZE_MAX;
}
