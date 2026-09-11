/* contrib_wire.h
 * JSON encoding of corr_contrib_t: the on-the-wire form of a cross-instance
 * correlation contribution. json-c (or libfastjson), same coupling as
 * corr_format.c. The engine stays json-free.
 *
 * The caller carries the encoded bytes between instances on whatever transport
 * it already has. This unit does not open sockets.
 *
 * Copyright 2026 Advens.
 */
#ifndef CONTRIB_WIRE_H
#define CONTRIB_WIRE_H

#include "classify_corr.h"
#include <json.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Build a json-c object. Caller owns the ref (json_object_put). origin may be
 * NULL. Returns NULL on OOM or missing corr_id for merge kinds. */
json_object* corr_contrib_to_json(const corr_contrib_t* c, const char* origin);

/* Parse. group strings alias the json object (valid until json_object_put).
 * group_slots holds the pointer array corr_contrib_t.group_vals uses.
 * Returns 0 on success, -1 on malformed. */
int corr_contrib_from_json(json_object* j, corr_contrib_t* out, const char** group_slots, size_t group_slots_cap);

#ifdef __cplusplus
}
#endif

#endif /* CONTRIB_WIRE_H */
