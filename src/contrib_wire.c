/* contrib_wire.c: JSON codec for a cross-instance correlation contribution.
 * See contrib_wire.h. */

#include "contrib_wire.h"

#include <string.h>
/* json.h comes from contrib_wire.h */

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
    if (json_object_object_get_ex(j, "ts", &f)) out->ts = json_object_get_double(f);
    if (json_object_object_get_ex(j, "group", &f) && json_object_is_type(f, json_type_array)) {
        n = (size_t)json_object_array_length(f);
        if (n > group_slots_cap) n = group_slots_cap;
        for (i = 0; i < n; i++) {
            json_object* e = json_object_array_get_idx(f, (int)i);
            group_slots[i] = e ? json_object_get_string(e) : "";
        }
        out->group_vals = group_slots;
        out->n_group = n;
    }
    if (json_object_object_get_ex(j, "count", &f)) out->count = (uint32_t)json_object_get_int64(f);
    if (json_object_object_get_ex(j, "numeric", &f)) out->numeric = json_object_get_double(f);
    if (json_object_object_get_ex(j, "seen_mask", &f)) out->seen_mask = (uint64_t)json_object_get_int64(f);
    if (json_object_object_get_ex(j, "value", &f) && json_object_is_type(f, json_type_string))
        out->value = json_object_get_string(f);
    return 0;
}
