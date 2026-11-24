/* contrib_wire.c: JSON codec for a cross-instance correlation contribution.
 * See contrib_wire.h. */

#include "contrib_wire.h"

#include <limits.h>
#include <math.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
/* json.h comes from contrib_wire.h */

/* The corr_owner_key string for c as a JSON string, sized to fit (no cap), or
 * NULL on overflow or allocation failure. */
static json_object* owner_key_json(const corr_contrib_t* c) {
    size_t len = strlen(c->corr_id);
    size_t i;
    char* buf;
    json_object* s;
    for (i = 0; i < c->n_group; i++) {
        const char* gv = (c->group_vals && c->group_vals[i]) ? c->group_vals[i] : "";
        size_t gl = strlen(gv);
        if (gl > SIZE_MAX - 2 - len) return NULL;
        len += 1 + gl;
    }
    if (len > (size_t)INT_MAX) return NULL;
    buf = malloc(len + 1);
    if (!buf) return NULL;
    if (corr_owner_key(buf, len + 1, c->corr_id, c->group_vals, c->n_group) != len) {
        free(buf);
        return NULL;
    }
    s = json_object_new_string_len(buf, (int)len);
    free(buf);
    return s;
}

static const char* kind_name(corr_contrib_kind_t k) {
    switch (k) {
        case CORR_CONTRIB_COUNT:
            return "count";
        case CORR_CONTRIB_SUM:
            return "sum";
        case CORR_CONTRIB_DISTINCT:
            return "distinct";
        case CORR_CONTRIB_SEEN:
            return "seen";
        case CORR_CONTRIB_EVENT:
        default:
            return NULL;
    }
}

static int kind_parse(const char* s, corr_contrib_kind_t* out) {
    if (!s) return -1;
    if (!strcmp(s, "count")) {
        *out = CORR_CONTRIB_COUNT;
        return 0;
    }
    if (!strcmp(s, "sum")) {
        *out = CORR_CONTRIB_SUM;
        return 0;
    }
    if (!strcmp(s, "distinct")) {
        *out = CORR_CONTRIB_DISTINCT;
        return 0;
    }
    if (!strcmp(s, "seen")) {
        *out = CORR_CONTRIB_SEEN;
        return 0;
    }
    return -1;
}

json_object* corr_contrib_to_json(const corr_contrib_t* c, const char* origin) {
    const char* kn;
    json_object* j;
    json_object* g;
    json_object* key;
    size_t i;
    if (!c) return NULL;
    kn = kind_name(c->kind);
    if (kn == NULL) return NULL; /* EVENT is not a wire kind */
    if (c->corr_id == NULL || c->corr_id[0] == '\0') return NULL;
    j = json_object_new_object();
    if (!j) return NULL;
    json_object_object_add(j, "v", json_object_new_int(1));
    json_object_object_add(j, "kind", json_object_new_string(kn));
    json_object_object_add(j, "corr_id", json_object_new_string(c->corr_id));
    json_object_object_add(j, "ts", json_object_new_double(c->ts));
    g = json_object_new_array();
    for (i = 0; i < c->n_group; i++) {
        const char* gv = (c->group_vals && c->group_vals[i]) ? c->group_vals[i] : "";
        json_object_array_add(g, json_object_new_string(gv));
    }
    json_object_object_add(j, "group", g);
    /* the routing key a hash transport needs to reach the owner peer */
    key = owner_key_json(c);
    if (!key) {
        json_object_put(j);
        return NULL;
    }
    json_object_object_add(j, "key", key);
    if (c->kind == CORR_CONTRIB_COUNT)
        json_object_object_add(j, "count", json_object_new_int64(c->count ? c->count : 1));
    if (c->kind == CORR_CONTRIB_SUM) {
        json_object_object_add(j, "numeric", json_object_new_double(c->numeric));
        json_object_object_add(j, "count", json_object_new_int64(c->count ? c->count : 1));
    }
    if (c->kind == CORR_CONTRIB_SEEN)
        json_object_object_add(j, "seen_mask", json_object_new_int64((int64_t)c->seen_mask));
    if (c->kind == CORR_CONTRIB_DISTINCT && c->value)
        json_object_object_add(j, "value", json_object_new_string(c->value));
    if (origin && origin[0]) json_object_object_add(j, "origin", json_object_new_string(origin));
    return j;
}

/* Largest count one partial may carry: the default event ring, which is all
 * the engine can hold for a group. An emitter sends 1. */
#define CONTRIB_MAX_COUNT 4096

/* A JSON number that is finite. json-c parses NaN and Infinity. */
static int get_finite(json_object* f, double* out) {
    if (!json_object_is_type(f, json_type_double) && !json_object_is_type(f, json_type_int)) return -1;
    double v = json_object_get_double(f);
    if (!isfinite(v)) return -1;
    *out = v;
    return 0;
}

int corr_contrib_from_json(json_object* j, corr_contrib_t* out, const char** group_slots, size_t group_slots_cap) {
    json_object* f;
    const char* kn;
    size_t n, i;
    if (!j || !out || !json_object_is_type(j, json_type_object)) return -1;
    memset(out, 0, sizeof(*out));
    /* Wire version is mandatory. Missing or != 1 is a reject, never a partial
     * decode: a contribution may cross a version boundary between instances. */
    if (!json_object_object_get_ex(j, "v", &f) || !json_object_is_type(f, json_type_int) || json_object_get_int(f) != 1)
        return -1;
    if (!json_object_object_get_ex(j, "kind", &f) || !json_object_is_type(f, json_type_string)) return -1;
    kn = json_object_get_string(f);
    if (kind_parse(kn, &out->kind) != 0) return -1;
    if (!json_object_object_get_ex(j, "corr_id", &f) || !json_object_is_type(f, json_type_string)) return -1;
    out->corr_id = json_object_get_string(f);
    if (!json_object_object_get_ex(j, "ts", &f) || get_finite(f, &out->ts) != 0) return -1;
    /* A group that is cut short or retyped would merge into another group. */
    if (!json_object_object_get_ex(j, "group", &f) || !json_object_is_type(f, json_type_array)) return -1;
    n = (size_t)json_object_array_length(f);
    if (n > group_slots_cap) return -1;
    for (i = 0; i < n; i++) {
        json_object* e = json_object_array_get_idx(f, (int)i);
        if (!json_object_is_type(e, json_type_string)) return -1;
        group_slots[i] = json_object_get_string(e);
    }
    out->group_vals = group_slots;
    out->n_group = n;
    if (out->kind == CORR_CONTRIB_COUNT || out->kind == CORR_CONTRIB_SUM) {
        if (json_object_object_get_ex(j, "count", &f)) {
            if (!json_object_is_type(f, json_type_int)) return -1;
            int64_t v = json_object_get_int64(f);
            if (v < 1 || v > CONTRIB_MAX_COUNT) return -1;
            out->count = (uint32_t)v;
        }
    }
    switch (out->kind) {
        case CORR_CONTRIB_COUNT:
            break;
        case CORR_CONTRIB_SUM:
            if (!json_object_object_get_ex(j, "numeric", &f) || get_finite(f, &out->numeric) != 0) return -1;
            break;
        case CORR_CONTRIB_SEEN:
            /* The encoder writes the mask as int64, so bit 63 reads negative. */
            if (!json_object_object_get_ex(j, "seen_mask", &f) || !json_object_is_type(f, json_type_int)) return -1;
            out->seen_mask = (uint64_t)json_object_get_int64(f);
            if (out->seen_mask == 0) return -1;
            break;
        case CORR_CONTRIB_DISTINCT:
            if (!json_object_object_get_ex(j, "value", &f) || !json_object_is_type(f, json_type_string)) return -1;
            out->value = json_object_get_string(f);
            break;
        case CORR_CONTRIB_EVENT:
        default:
            return -1;
    }
    return 0;
}
