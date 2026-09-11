/* fuzz_contrib.c
 * libFuzzer target for corr_contrib_from_json. The payload is an untrusted
 * cross-instance contribution received from a peer. json-c parses the bytes;
 * strings returned by the decoder alias the json object and are dropped with it.
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

#include "contrib_wire.h"
#include "classify_corr.h"

#include <json.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    char *copy;
    json_object *j;
    corr_contrib_t c;
    const char *slots[CORR_MAX_GROUP_FIELDS];
    json_tokener *tok;
    enum json_tokener_error err;

    copy = (char *)malloc(size + 1);
    if (!copy) return 0;
    if (size) memcpy(copy, data, size);
    copy[size] = '\0';

    tok = json_tokener_new();
    if (!tok) {
        free(copy);
        return 0;
    }
    j = json_tokener_parse_ex(tok, copy, (int)(size > 0x7fffffff ? 0x7fffffff : size));
    err = json_tokener_get_error(tok);
    json_tokener_free(tok);
    free(copy);

    if (!j || err != json_tokener_success) {
        if (j) json_object_put(j);
        return 0;
    }
    (void)corr_contrib_from_json(j, &c, slots, CORR_MAX_GROUP_FIELDS);
    json_object_put(j);
    return 0;
}
