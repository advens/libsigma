/* corr_format.h
 * Loader for the Sigma correlation artifact (`rules.corr.json`) produced by a
 * Sigma compiler and consumed by the caller.  Parses the JSON into the dep-free
 * corr_rule_t[] the engine (classify_corr.c) drives.
 *
 * This unit depends on json-c (or libfastjson); the engine core
 * (classify_corr.{c,h}) and its standalone self-test stay json-free (the test
 * constructs corr_rule_t in C directly), so that acceptance gate builds with
 * nothing but libc.
 *
 * Artifact shape is frozen as {"version":1,"correlations":[{...}]}.
 * Missing or wrong version, or a bare list, is a reject (parse returns NULL).
 * Each correlation object:
 *   id, title, type, base_rule_ids[int], base_rule_names[str], group_by[str],
 *   [alias_group_by[str[]]], timespan_s, condition{op,count,[field]},
 *   [ordered_rule_ids[int]], mitre, level
 *
 * Ownership: corr_artifact_t owns ALL backing storage (the corr_rule_t array +
 * every string + every id array it references).  corr_artifact_free() releases
 * it.  The engine stores pointers into this storage, so the artifact must
 * outlive any engine built from it (the caller keeps both, swapping atomically
 * on reload).
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

#ifndef CORR_FORMAT_H
#define CORR_FORMAT_H

#include "classify_corr.h"

#ifdef __cplusplus
extern "C" {
#endif

/* A parsed artifact: the rule array + the arena that backs its strings/arrays. */
typedef struct corr_artifact corr_artifact_t;

/* Load-time boundary counters (observable; the caller publishes them to its own
 * statistics facility).  Every silent truncation/skip in the loader is counted
 * here. */
typedef struct {
    uint64_t rules_rejected; /* array elements skipped (non-object / missing id) */
    uint64_t groupby_truncated; /* group_by arrays clamped to CORR_MAX_GROUP_FIELDS */
    uint64_t baserules_truncated; /* base/ordered id arrays clamped to CORR_MAX_RULE_IDS */
    uint64_t rids_dropped; /* out-of-range (>UINT32_MAX / <0) rule ids dropped */
} corr_load_stats_t;

struct corr_artifact_view {
    const corr_rule_t* rules;
    size_t n;
    corr_load_stats_t load; /* load-time truncation/skip counters */
};

/* Parse a JSON blob (NUL-terminated). Returns a heap artifact on success (even
 * with zero rules, an empty/malformed correlation list yields n==0, NOT an
 * error: a missing artifact must never crash the pipeline), or NULL on OOM /
 * unparseable JSON.  *out_view receives the rule array (valid until free). */
corr_artifact_t* corr_artifact_parse(const char* json, size_t len, struct corr_artifact_view* out_view);

/* Read + parse the artifact at *path*.  Returns NULL when absent/unreadable
 * (the caller treats that as "no correlations loaded"). */
corr_artifact_t* corr_artifact_load_file(const char* path, struct corr_artifact_view* out_view);

void corr_artifact_free(corr_artifact_t* a);

#ifdef __cplusplus
}
#endif

#endif /* CORR_FORMAT_H */
