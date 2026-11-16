/* events_golden.c
 * Run the events corpus through sigma_events and print a transcript, one
 * answer per line, that every build of the front end (native, wasm32, the
 * JavaScript loader) must reproduce byte for byte:
 *
 *   match <answer for the whole events file>
 *   explain <event> <rule_id> <answer>     for each "_explain" rule of an event
 *   correlate <answer>
 *
 * Before printing, it checks the answers against the truth written in the
 * corpus: each event's "_expect" (rules a match returns), "_routing_skips"
 * (rules that match only without category routing), and expect.json (the
 * correlation fires).  Explain is checked for every rule on every event, not
 * only the printed pairs.  Any disagreement goes to stderr and the exit
 * status is 1.
 *
 * Usage: events_golden <corpus.sigmac> <corpus.corr.json> <events.jsonl> <expect.json>
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
#define _POSIX_C_SOURCE 200809L

#include "sigma_events.h"

#include <json.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define MAX_EVENTS 256
#define MAX_IDS 32

typedef struct {
    const char* text; /* points into the events buffer */
    size_t len;
    uint32_t expect[MAX_IDS];
    size_t n_expect;
    uint32_t skips[MAX_IDS];
    size_t n_skips;
    uint32_t explain[MAX_IDS];
    size_t n_explain;
} event_t;

static int g_fail;

static void truth_fail(const char* what, size_t e, uint32_t r) {
    fprintf(stderr, "TRUTH FAIL: %s (event %zu, rule %u)\n", what, e, (unsigned)r);
    g_fail = 1;
}

static char* read_file(const char* path, size_t* len) {
    FILE* f = fopen(path, "rb");
    if (f == NULL) return NULL;
    char* buf = NULL;
    size_t cap = 0, n = 0;
    for (;;) {
        if (n == cap) {
            size_t nc = cap ? cap * 2 : 4096;
            char* nb = realloc(buf, nc + 1);
            if (nb == NULL) {
                free(buf);
                fclose(f);
                return NULL;
            }
            buf = nb;
            cap = nc;
        }
        size_t r = fread(buf + n, 1, cap - n, f);
        n += r;
        if (r == 0) break;
    }
    fclose(f);
    buf[n] = '\0';
    *len = n;
    return buf;
}

static json_object* get(json_object* o, const char* key) {
    json_object* v = NULL;
    if (o == NULL || !json_object_object_get_ex(o, key, &v)) return NULL;
    return v;
}

static size_t ids_of(json_object* arr, uint32_t* out) {
    size_t n = 0;
    if (arr == NULL || !json_object_is_type(arr, json_type_array)) return 0;
    for (size_t i = 0; i < (size_t)json_object_array_length(arr) && n < MAX_IDS; i++)
        out[n++] = (uint32_t)json_object_get_int64(json_object_array_get_idx(arr, (int)i));
    return n;
}

static int has(const uint32_t* ids, size_t n, uint32_t id) {
    for (size_t i = 0; i < n; i++)
        if (ids[i] == id) return 1;
    return 0;
}

static size_t split_events(char* buf, size_t len, event_t* ev) {
    size_t n = 0;
    char* p = buf;
    char* end = buf + len;
    while (p < end && n < MAX_EVENTS) {
        char* nl = memchr(p, '\n', (size_t)(end - p));
        size_t ln = nl ? (size_t)(nl - p) : (size_t)(end - p);
        if (ln > 0) {
            json_object* o = json_tokener_parse(p); /* stops at the newline */
            memset(&ev[n], 0, sizeof(ev[n]));
            ev[n].text = p;
            ev[n].len = ln;
            ev[n].n_expect = ids_of(get(o, "_expect"), ev[n].expect);
            ev[n].n_skips = ids_of(get(o, "_routing_skips"), ev[n].skips);
            ev[n].n_explain = ids_of(get(o, "_explain"), ev[n].explain);
            if (o) json_object_put(o);
            n++;
        }
        p += ln + 1;
    }
    return n;
}

/* Print one transcript line; returns the parsed answer (caller puts it). */
static json_object* emit(const char* prefix, char* answer) {
    if (answer == NULL) {
        fprintf(stderr, "%s: no answer (out of memory)\n", prefix);
        exit(1);
    }
    printf("%s %s\n", prefix, answer);
    json_object* j = json_tokener_parse(answer);
    sigma_events_str_free(answer);
    if (j == NULL) {
        fprintf(stderr, "%s: answer is not JSON\n", prefix);
        exit(1);
    }
    return j;
}

static void check_match(json_object* m, const event_t* ev, size_t n) {
    json_object* evs = get(m, "events");
    if (evs == NULL || (size_t)json_object_array_length(evs) != n) {
        truth_fail("match answer has the wrong number of events", 0, 0);
        return;
    }
    for (size_t e = 0; e < n; e++) {
        uint32_t got[MAX_IDS];
        size_t ng = 0;
        json_object* hits = get(json_object_array_get_idx(evs, (int)e), "hits");
        for (size_t k = 0; k < (size_t)json_object_array_length(hits) && ng < MAX_IDS; k++)
            got[ng++] = (uint32_t)json_object_get_int64(get(json_object_array_get_idx(hits, (int)k), "rule_id"));
        for (size_t k = 0; k < ng; k++)
            if (!has(ev[e].expect, ev[e].n_expect, got[k])) truth_fail("match fired a rule not in _expect", e, got[k]);
        for (size_t k = 0; k < ev[e].n_expect; k++)
            if (!has(got, ng, ev[e].expect[k])) truth_fail("match missed a rule in _expect", e, ev[e].expect[k]);
    }
}

static void check_explain(json_object* x, const event_t* ev, size_t e, uint32_t r) {
    int want = has(ev->expect, ev->n_expect, r);
    int want_unrouted = want || has(ev->skips, ev->n_skips, r);
    json_object* ok = get(x, "ok");
    if (ok == NULL || !json_object_get_boolean(ok)) {
        truth_fail("explain answered an error", e, r);
        return;
    }
    if (json_object_get_boolean(get(x, "matched")) != want) truth_fail("explain matched disagrees with _expect", e, r);
    if (json_object_get_boolean(get(x, "matched_unrouted")) != want_unrouted)
        truth_fail("explain matched_unrouted disagrees with _expect + _routing_skips", e, r);
}

static void check_correlate(json_object* c, json_object* expect) {
    json_object* fires = get(c, "fires");
    json_object* want = get(expect, "fires");
    size_t nf = fires ? (size_t)json_object_array_length(fires) : 0;
    size_t nw = want ? (size_t)json_object_array_length(want) : 0;
    if (nf != nw) {
        fprintf(stderr, "TRUTH FAIL: %zu correlation fires, expect.json lists %zu\n", nf, nw);
        g_fail = 1;
    }
    for (size_t i = 0; i < nw && i < nf; i++) {
        json_object* f = json_object_array_get_idx(fires, (int)i);
        json_object* w = json_object_array_get_idx(want, (int)i);
        const char* fid = json_object_get_string(get(f, "corr_id"));
        const char* wid = json_object_get_string(get(w, "corr_id"));
        int same = json_object_get_int64(get(f, "event")) == json_object_get_int64(get(w, "event")) && fid && wid &&
                   strcmp(fid, wid) == 0;
        const char* gf = json_object_get_string(get(w, "group_field"));
        const char* gv = json_object_get_string(get(w, "group_value"));
        const char* fv = gf ? json_object_get_string(get(get(f, "group"), gf)) : NULL;
        if (gv == NULL || fv == NULL || strcmp(fv, gv) != 0) same = 0;
        if (!same) {
            fprintf(stderr, "TRUTH FAIL: fire %zu differs from expect.json\n", i);
            g_fail = 1;
        }
    }
}

int main(int argc, char** argv) {
    if (argc != 5) {
        fprintf(stderr, "usage: %s <corpus.sigmac> <corpus.corr.json> <events.jsonl> <expect.json>\n", argv[0]);
        return 2;
    }
    size_t slen = 0, clen = 0, elen = 0, xlen = 0;
    char* sigmac = read_file(argv[1], &slen);
    char* corr = read_file(argv[2], &clen);
    char* events = read_file(argv[3], &elen);
    char* expect_txt = read_file(argv[4], &xlen);
    if (sigmac == NULL || corr == NULL || events == NULL || expect_txt == NULL) {
        fprintf(stderr, "events_golden: cannot read the corpus\n");
        return 2;
    }
    int st = 0;
    sigma_events_t* se = sigma_events_load((const uint8_t*)sigmac, slen, &st);
    if (se == NULL) {
        fprintf(stderr, "events_golden: load failed, status %d\n", st);
        return 2;
    }
    static event_t ev[MAX_EVENTS];
    char* copy = malloc(elen + 1);
    if (copy == NULL) return 2;
    memcpy(copy, events, elen + 1);
    size_t n = split_events(copy, elen, ev);

    char* info_txt = sigma_events_info_json(se);
    json_object* info = info_txt ? json_tokener_parse(info_txt) : NULL;
    sigma_events_str_free(info_txt);
    uint32_t rules[MAX_IDS];
    size_t n_rules = 0;
    json_object* rl = get(info, "rules");
    for (size_t i = 0; rl && i < (size_t)json_object_array_length(rl) && n_rules < MAX_IDS; i++)
        rules[n_rules++] = (uint32_t)json_object_get_int64(get(json_object_array_get_idx(rl, (int)i), "rule_id"));
    if (info) json_object_put(info);

    json_object* m = emit("match", sigma_events_match_json(se, events, elen));
    check_match(m, ev, n);
    json_object_put(m);

    for (size_t e = 0; e < n; e++) {
        for (size_t k = 0; k < n_rules; k++) {
            uint32_t r = rules[k];
            char* a = sigma_events_explain_json(se, ev[e].text, ev[e].len, r);
            if (has(ev[e].explain, ev[e].n_explain, r)) {
                char prefix[48];
                snprintf(prefix, sizeof(prefix), "explain %zu %u", e, (unsigned)r);
                json_object* x = emit(prefix, a);
                check_explain(x, &ev[e], e, r);
                json_object_put(x);
            } else {
                json_object* x = a ? json_tokener_parse(a) : NULL;
                sigma_events_str_free(a);
                check_explain(x, &ev[e], e, r);
                if (x) json_object_put(x);
            }
        }
    }

    json_object* c = emit("correlate", sigma_events_correlate_json(se, corr, clen, events, elen));
    json_object* expect = json_tokener_parse(expect_txt);
    check_correlate(c, expect);
    json_object_put(c);
    if (expect) json_object_put(expect);

    sigma_events_free(se);
    free(copy);
    free(sigmac);
    free(corr);
    free(events);
    free(expect_txt);
    if (g_fail) fprintf(stderr, "events_golden: the corpus truth does not hold\n");
    return g_fail;
}
