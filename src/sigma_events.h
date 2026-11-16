/* sigma_events.h
 * JSON front end for the matcher and the correlator: load a `.sigmac`, take
 * events as JSON text, and answer with JSON text.  It is the layer a host
 * without its own field model calls (the WebAssembly module, a test harness, a
 * CLI).  It does not compile Sigma YAML.
 *
 * Event model
 *   Input is a JSON array of objects, one object, or JSON Lines (one object per
 *   line, blank lines skipped).  A rule field name resolves against an event as:
 *     1. a top-level key equal to the whole name ("process.name": "x"), then
 *     2. the dotted path walked through nested objects
 *        ({"process": {"name": "x"}}).
 *   A leaf that is an object, an array, or null is absent.  Numbers and booleans
 *   match as the JSON library renders them ("8443", "true").  A path segment of
 *   128 bytes or more is absent.  Arrays are never searched element by element.
 *
 *   Correlation clocks each event on the first of @timestamp, time, timestamp,
 *   event.created that event_time_parse() accepts, then on event.date plus
 *   event.time.  An event with no usable time keeps the previous event's time
 *   and is counted in "untimed".  Temporal ordering uses event time with a
 *   2 second reorder window.
 *
 * Output
 *   Every call returns a malloc'd, NUL-terminated JSON object that the caller
 *   frees with sigma_events_str_free().  {"ok":false,"error":"..."} reports bad
 *   input.  NULL means the allocation for the answer itself failed.  The
 *   schemas are documented next to each function.
 *
 * Threading: one engine is not safe for concurrent calls.  Load one engine per
 * thread, or serialise calls.
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

#ifndef SIGMA_EVENTS_H
#define SIGMA_EVENTS_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Version of the JSON schemas below.  A change to a field name, a type, or a
 * meaning bumps it; adding a field does not. */
#define SIGMA_EVENTS_SCHEMA 1u

/* Most events one call accepts.  More is an error, never a silent cut. */
#define SIGMA_EVENTS_MAX 100000u

/* Longest field value an explain answer echoes back ("got").  Matching always
 * sees the whole value; only the echo is cut, and says so. */
#define SIGMA_EVENTS_ECHO_MAX 4096u

typedef struct sigma_events sigma_events_t;

/* Load a `.sigmac` from buf[0..len).  The buffer is copied; the caller keeps
 * it.  Returns NULL on failure with *status set to a sigma_status_t value
 * (SIGMA_ERR_NOMEM when the engine itself could not be allocated). */
sigma_events_t* sigma_events_load(const uint8_t* buf, size_t len, int* status);
void sigma_events_free(sigma_events_t* se);

/* {"ok":true,"schema":1,"format_version":5,"n_rules":N,"re_skipped":R,
 *  "rules":[{"rule_id":1,"title":"...","verdict":"alert","severity":2,
 *            "score":0.20,"mitre":"T1110"|null}, ...]} */
char* sigma_events_info_json(const sigma_events_t* se);

/* Match every event.
 * {"ok":true,"n_events":N,
 *  "events":[{"index":0,"hits":[{"rule_id":1,"title":"...","verdict":"alert",
 *             "severity":2,"score":0.20,"mitre":null}, ...]}, ...],
 *  "totals":{"hits":H,"alert":A,"escalate":E,"benign":B}} */
char* sigma_events_match_json(sigma_events_t* se, const char* events, size_t len);

/* Explain one rule against one event (the first event of the input).
 * Every predicate is evaluated by the matcher itself, one at a time, so the
 * answer cannot disagree with a match.
 * {"ok":true,"rule_id":1,"title":"...",
 *  "matched":true,           routed run: what the matcher reports for the event
 *  "matched_unrouted":true,  the rule alone, without category routing
 *  "condition":["sel:0","sel:1","not","and"] | null (null: AND of selections),
 *  "selections":[{"index":0,"matched":true,
 *     "preds":[{"field":"source.ip","group":0,"op":"cidr","value":"10.0.0.0/8",
 *               "case":false,"negate":false,"fieldref":false,
 *               "present":true,"got":"10.1.2.3","got_truncated":false,
 *               "matched":true}, ...]}, ...]}
 * matched_unrouted true with matched false means routing kept the rule out of
 * scope for this event. */
char* sigma_events_explain_json(sigma_events_t* se, const char* event, size_t len, uint32_t rule_id);

/* Match every event, then feed the hits to the correlations in corr_json (the
 * rules.corr.json artifact), in input order.
 * {"ok":true,"n_events":N,"n_correlations":C,"untimed":U,
 *  "fires":[{"event":2,"corr_id":"brute","title":"...","observed":3,
 *            "threshold":3,"group":{"source.ip":"203.0.113.9"}}, ...],
 *  "stats":{"groups_evicted":0, ...every corr_stats_t counter...}} */
char* sigma_events_correlate_json(
    sigma_events_t* se, const char* corr_json, size_t corr_len, const char* events, size_t len);

void sigma_events_str_free(char* s);

#ifdef __cplusplus
}
#endif

#endif /* SIGMA_EVENTS_H */
