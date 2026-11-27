/* test_events.c
 * sigma_events: event model, input forms, explain, correlate, and the
 * explain/match agreement property.  Runs natively and as wasm32-wasip1.
 *
 * Usage: test_events <conf.sigmac> <arch.sigmac> <arch.corr.json>
 *   conf.sigmac    output of conformance_emit.py (rules 100..800)
 *   arch.*         src/fuzz_corpus/arch fixture (rule 1, correlation "brute")
 */
#define _POSIX_C_SOURCE 200809L

#include "sigma_events.h"
#include "sigma_format.h"

#include <json.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static int g_pass, g_fail;

static void check(int cond, const char* msg) {
    if (cond) {
        g_pass++;
    } else {
        g_fail++;
        printf("  FAIL  %s\n", msg);
    }
}

static uint8_t* read_file(const char* path, size_t* len) {
    FILE* f = fopen(path, "rb");
    if (f == NULL) return NULL;
    uint8_t* buf = NULL;
    size_t cap = 0, n = 0;
    for (;;) {
        if (n == cap) {
            size_t nc = cap ? cap * 2 : 4096;
            uint8_t* nb = realloc(buf, nc + 1);
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

/* Parse and free an answer.  NULL when it is not valid JSON. */
static json_object* answer(char* s) {
    if (s == NULL) return NULL;
    json_object* j = json_tokener_parse(s);
    sigma_events_str_free(s);
    return j;
}

static json_object* get(json_object* o, const char* key) {
    json_object* v = NULL;
    if (o == NULL || !json_object_object_get_ex(o, key, &v)) return NULL;
    return v;
}

/* json-c represents a JSON null as a NULL object behind a present key. */
static int is_null(json_object* o, const char* key) {
    json_object* v = NULL;
    return o != NULL && json_object_object_get_ex(o, key, &v) && v == NULL;
}

static int is_ok(json_object* j) {
    json_object* v = get(j, "ok");
    return v != NULL && json_object_get_boolean(v);
}

static const char* get_str(json_object* o, const char* key) {
    json_object* v = get(o, key);
    return v != NULL && json_object_is_type(v, json_type_string) ? json_object_get_string(v) : NULL;
}

static int64_t get_int(json_object* o, const char* key) {
    json_object* v = get(o, key);
    return v != NULL ? json_object_get_int64(v) : -1;
}

static json_object* at(json_object* arr, size_t i) {
    if (arr == NULL || !json_object_is_type(arr, json_type_array)) return NULL;
    if (i >= (size_t)json_object_array_length(arr)) return NULL;
    return json_object_array_get_idx(arr, (int)i);
}

static size_t alen(json_object* arr) {
    if (arr == NULL || !json_object_is_type(arr, json_type_array)) return 0;
    return (size_t)json_object_array_length(arr);
}

/* Rule ids that fired on event i of a match answer, as a bitmask over the
 * conformance ids (100 -> bit 1, 200 -> bit 2, ... 800 -> bit 8). */
static unsigned fired_mask(json_object* m, size_t i) {
    json_object* hits = get(at(get(m, "events"), i), "hits");
    unsigned mask = 0;
    for (size_t k = 0; k < alen(hits); k++) {
        int64_t id = get_int(at(hits, k), "rule_id");
        if (id >= 100 && id <= 800 && id % 100 == 0) mask |= 1u << (id / 100);
    }
    return mask;
}

static unsigned match_one(sigma_events_t* se, const char* ev) {
    json_object* m = answer(sigma_events_match_json(se, ev, strlen(ev)));
    unsigned mask = is_ok(m) ? fired_mask(m, 0) : 0xFFFFFFFFu;
    if (m) json_object_put(m);
    return mask;
}

static const char* error_of(sigma_events_t* se, const char* ev) {
    static char buf[160];
    json_object* m = answer(sigma_events_match_json(se, ev, strlen(ev)));
    const char* e = get_str(m, "error");
    snprintf(buf, sizeof(buf), "%s", e != NULL && !is_ok(m) ? e : "");
    if (m) json_object_put(m);
    return buf;
}

#define B(id) (1u << ((id) / 100))

static const char* const k_corpus[] = {
    "{\"process.command_line\":\"powershell -enc ZZ\"}",
    "{\"process\":{\"command_line\":\"POWERSHELL -ENC zz\"}}",
    "{\"process.name\":\"C:\\\\tools\\\\MiMiKatz.exe\"}",
    "{\"process\":{\"name\":[\"mimikatz.exe\"]}}",
    "{\"destination.port\":\"8443\"}",
    "{\"destination\":{\"port\":8443}}",
    "{\"destination\":{\"port\":80}}",
    "{\"destination.port\":\"high\"}",
    "{\"source.ip\":\"10.5.6.7\"}",
    "{\"source\":{\"ip\":\"192.168.1.1\"}}",
    "{\"network.info\":\"connect to port 443 now\"}",
    "{\"network.info\":\"connect to port 44 now\"}",
    "{\"user.name\":\"alice\",\"user.target\":\"alice\"}",
    "{\"user\":{\"name\":\"alice\",\"target\":\"ALICE\"}}",
    "{\"user\":{\"name\":\"alice\"}}",
    "{\"user\":{\"name\":null,\"target\":null}}",
    "{\"process.command_line\":\"x -enc y\",\"source.ip\":\"10.0.0.1\",\"destination.port\":2000}",
    "{}",
};

static void test_load(void) {
    int st = 0;
    check(sigma_events_load(NULL, 0, &st) == NULL && st == SIGMA_ERR_SIZE, "load: empty buffer refused");
    static const uint8_t junk[200] = {1, 2, 3};
    st = 0;
    check(sigma_events_load(junk, sizeof(junk), &st) == NULL && st < 0, "load: junk refused with a status");
    json_object* j = answer(sigma_events_match_json(NULL, "{}", 2));
    check(j != NULL && !is_ok(j), "match: NULL engine answers an error");
    if (j) json_object_put(j);
}

static void test_info(sigma_events_t* se) {
    json_object* j = answer(sigma_events_info_json(se));
    check(is_ok(j), "info: ok");
    check(get_int(j, "n_rules") == 6, "info: 6 conformance rules");
    check(get_int(j, "schema") == SIGMA_EVENTS_SCHEMA, "info: schema version");
    check(get_int(j, "format_version") == SIGMA_FORMAT_VERSION, "info: format version");
    check(alen(get(j, "rules")) == 6, "info: rule list");
    if (j) json_object_put(j);
}

static void test_event_model(sigma_events_t* se) {
    check(match_one(se, k_corpus[0]) == B(100), "flat key: contains");
    check(match_one(se, k_corpus[1]) == B(100), "nested path, case-insensitive contains");
    check(match_one(se, k_corpus[2]) == B(200), "endswith, escaped backslashes");
    check(match_one(se, k_corpus[3]) == B(200), "array leaf: one element");
    check(match_one(se, "{\"process\":{\"name\":[\"notepad.exe\",\"mimikatz.exe\"]}}") == B(200),
          "array leaf: any element");
    check(match_one(se, "{\"process\":{\"name\":[{\"x\":\"mimikatz.exe\"},null,[\"mimikatz.exe\"]]}}") == 0,
          "array leaf: objects, nulls and nested arrays are skipped");
    check(match_one(se, "{\"destination\":{\"port\":[80,8443]}}") == B(300), "array leaf: numeric element");
    check(match_one(se, k_corpus[4]) == B(300), "numeric gte on a string");
    check(match_one(se, k_corpus[5]) == B(300), "numeric gte on a JSON number");
    check(match_one(se, k_corpus[6]) == 0, "numeric gte below the bound");
    check(match_one(se, k_corpus[7]) == 0, "numeric gte on a non-number");
    check(match_one(se, k_corpus[8]) == B(600), "cidr inside");
    check(match_one(se, k_corpus[9]) == 0, "cidr outside");
    check(match_one(se, k_corpus[10]) == B(700), "re through PCRE2");
    check(match_one(se, k_corpus[11]) == 0, "re no match");
    check(match_one(se, k_corpus[12]) == B(800), "fieldref equal");
    check(match_one(se, k_corpus[13]) == B(800), "fieldref equal, case-insensitive");
    check(match_one(se, k_corpus[14]) == 0, "fieldref with the other field absent");
    check(match_one(se, k_corpus[15]) == 0, "null leaves are absent");
    check(match_one(se, k_corpus[16]) == (B(100) | B(300) | B(600)), "three rules on one event");
    check(match_one(se, "{\"process\":{\"command_line\":{\"x\":\"-enc\"}}}") == 0, "object leaf is absent");
    check(match_one(se, "{\"process.command_line\":true}") == 0, "boolean renders as true");
    check(match_one(se, "{\"network\":{\"info\":\"port 9999\"},\"network.info\":\"none\"}") == 0,
          "a top-level dotted key wins over the nested path");
}

static void test_input_forms(sigma_events_t* se) {
    const char* jsonl = "{\"source.ip\":\"10.0.0.1\"}\n\n{\"destination.port\":2000}\r\n";
    json_object* m = answer(sigma_events_match_json(se, jsonl, strlen(jsonl)));
    check(is_ok(m) && get_int(m, "n_events") == 2, "JSON Lines: 2 events, blank line skipped");
    check(fired_mask(m, 0) == B(600) && fired_mask(m, 1) == B(300), "JSON Lines: per-event hits");
    if (m) json_object_put(m);

    const char* pretty =
        "{\n  \"source\": {\n    \"ip\": \"10.0.0.1\"\n  }\n}\n{\n  \"user.name\": \"a\",\n"
        "  \"user.target\": \"a\"\n}\n";
    m = answer(sigma_events_match_json(se, pretty, strlen(pretty)));
    check(is_ok(m) && get_int(m, "n_events") == 2, "pretty-printed objects: 2 events");
    check(fired_mask(m, 1) == B(800), "pretty-printed objects: second event");
    if (m) json_object_put(m);

    const char* arr = " [ {\"source.ip\":\"10.0.0.1\"}, {} ] \n";
    m = answer(sigma_events_match_json(se, arr, strlen(arr)));
    check(is_ok(m) && get_int(m, "n_events") == 2, "array of objects");
    json_object* t = get(m, "totals");
    check(get_int(t, "hits") == 1 && get_int(t, "alert") == 1, "totals");
    if (m) json_object_put(m);

    /* Length is honoured: the second object is outside len. */
    const char* two = "{\"source.ip\":\"10.0.0.1\"}{\"source.ip\":\"10.0.0.2\"}";
    m = answer(sigma_events_match_json(se, two, 24));
    check(is_ok(m) && get_int(m, "n_events") == 1, "input length bounds the parse");
    if (m) json_object_put(m);

    check(strcmp(error_of(se, ""), "no events") == 0, "empty input");
    check(strcmp(error_of(se, "  \n "), "no events") == 0, "whitespace input");
    check(strstr(error_of(se, "[1]"), "event 0: not a JSON object") != NULL, "array element not an object");
    check(strstr(error_of(se, "{} 7"), "event 1") != NULL, "sequence element not an object");
    check(strstr(error_of(se, "{\"a\":"), "event 0") != NULL, "incomplete object");
    check(strstr(error_of(se, "[{}] x"), "after the array") != NULL, "data after the array");
    check(strstr(error_of(se, "\"str\""), "event 0") != NULL, "bare string refused");

    size_t big = (size_t)SIGMA_EVENTS_MAX + 1;
    char* many = malloc(big * 3 + 1);
    if (many != NULL) {
        for (size_t i = 0; i < big; i++) memcpy(many + i * 3, "{}\n", 3);
        many[big * 3] = '\0';
        m = answer(sigma_events_match_json(se, many, big * 3));
        check(!is_ok(m) && strstr(get_str(m, "error") ? get_str(m, "error") : "", "more than") != NULL,
              "event cap is an error, not a cut");
        if (m) json_object_put(m);
        free(many);
    }
}

static json_object* explain(sigma_events_t* se, const char* ev, uint32_t rule_id) {
    return answer(sigma_events_explain_json(se, ev, strlen(ev), rule_id));
}

static void test_explain(sigma_events_t* se) {
    json_object* x = explain(se, "{\"source\":{\"ip\":\"10.1.2.3\"}}", 600);
    json_object* p = at(get(at(get(x, "selections"), 0), "preds"), 0);
    check(is_ok(x) && json_object_get_boolean(get(x, "matched")), "explain cidr: matched");
    check(get_str(p, "op") && !strcmp(get_str(p, "op"), "cidr"), "explain cidr: op");
    check(get_str(p, "value") && !strcmp(get_str(p, "value"), "10.0.0.0/8"), "explain cidr: operand");
    check(get_str(p, "got") && !strcmp(get_str(p, "got"), "10.1.2.3"), "explain cidr: got");
    check(get_str(p, "field") && !strcmp(get_str(p, "field"), "source.ip"), "explain cidr: field");
    check(json_object_get_boolean(get(p, "matched")), "explain cidr: predicate matched");
    check(is_null(x, "condition"), "explain: implicit condition is null");
    if (x) json_object_put(x);

    x = explain(se, "{\"network.info\":\"port 12\"}", 700);
    p = at(get(at(get(x, "selections"), 0), "preds"), 0);
    check(is_ok(x) && !json_object_get_boolean(get(x, "matched")), "explain re: not matched");
    check(json_object_get_boolean(get(p, "present")) && !json_object_get_boolean(get(p, "matched")),
          "explain re: present but the pattern fails");
    check(get_str(p, "value") && !strcmp(get_str(p, "value"), "port \\d{3,}"), "explain re: pattern");
    if (x) json_object_put(x);

    x = explain(se, "{\"user.name\":\"bob\",\"user.target\":\"alice\"}", 800);
    p = at(get(at(get(x, "selections"), 0), "preds"), 0);
    check(json_object_get_boolean(get(p, "fieldref")), "explain fieldref: flag");
    check(get_str(p, "value") && !strcmp(get_str(p, "value"), "user.target"), "explain fieldref: operand");
    check(!json_object_get_boolean(get(p, "matched")), "explain fieldref: not equal");
    if (x) json_object_put(x);

    x = explain(se, "{\"destination.port\":4000}", 300);
    p = at(get(at(get(x, "selections"), 0), "preds"), 0);
    check(get_str(p, "value") && !strcmp(get_str(p, "value"), "1024"), "explain gte: operand as a string");
    check(get_str(p, "got") && !strcmp(get_str(p, "got"), "4000"), "explain gte: number rendered");
    if (x) json_object_put(x);

    x = explain(se, "{}", 600);
    p = at(get(at(get(x, "selections"), 0), "preds"), 0);
    check(p != NULL && !json_object_get_boolean(get(p, "present")) && is_null(p, "got"), "explain: absent field");
    if (x) json_object_put(x);

    x = explain(se, "{}", 4242);
    check(!is_ok(x) && get_str(x, "error") && strstr(get_str(x, "error"), "4242"), "explain: unknown rule");
    if (x) json_object_put(x);

    size_t n = SIGMA_EVENTS_ECHO_MAX + 100;
    char* ev = malloc(n + 64);
    if (ev != NULL) {
        int h = snprintf(ev, 64, "{\"process.command_line\":\"");
        memset(ev + h, 'a', n);
        memcpy(ev + h + n, "-enc\"}", 7);
        x = explain(se, ev, 100);
        p = at(get(at(get(x, "selections"), 0), "preds"), 0);
        check(json_object_get_boolean(get(x, "matched")), "explain long value: matched on the whole value");
        check(json_object_get_boolean(get(p, "got_truncated")), "explain long value: echo truncated");
        check(get_str(p, "got") && strlen(get_str(p, "got")) == SIGMA_EVENTS_ECHO_MAX, "explain long value: echo size");
        if (x) json_object_put(x);
        free(ev);
    }
}

/* For every rule and every corpus event, explain.matched equals membership in
 * the match answer, and with no routing in this artifact matched_unrouted
 * agrees too. */
static void test_agreement(sigma_events_t* se) {
    static const uint32_t ids[] = {100, 200, 300, 600, 700, 800};
    int agree = 1;
    for (size_t e = 0; e < sizeof(k_corpus) / sizeof(k_corpus[0]); e++) {
        unsigned mask = match_one(se, k_corpus[e]);
        for (size_t r = 0; r < sizeof(ids) / sizeof(ids[0]); r++) {
            json_object* x = explain(se, k_corpus[e], ids[r]);
            int want = (mask & B(ids[r])) != 0;
            int routed = json_object_get_boolean(get(x, "matched"));
            int unrouted = json_object_get_boolean(get(x, "matched_unrouted"));
            int sel = json_object_get_boolean(get(at(get(x, "selections"), 0), "matched"));
            if (!is_ok(x) || routed != want || unrouted != want || sel != want) {
                printf("  disagree: event %zu rule %u\n", e, (unsigned)ids[r]);
                agree = 0;
            }
            if (x) json_object_put(x);
        }
    }
    check(agree, "explain agrees with match on every rule x event");
}

static void test_correlate(const uint8_t* sigmac, size_t slen, const char* corr, size_t clen) {
    int st = 0;
    sigma_events_t* se = sigma_events_load(sigmac, slen, &st);
    check(se != NULL, "arch fixture loads");
    if (se == NULL) return;

    /* 1723472400 is 2024-08-12T14:20:00Z.  event_time_parse takes a numeric
     * epoch of 9 digits or more, an ISO-8601 string, or the other forms in
     * event_time.h. */
    const char* evs =
        "{\"event.action\":\"authentication_failure\",\"source.ip\":\"203.0.113.9\",\"@timestamp\":1723472400}\n"
        "{\"event\":{\"action\":\"authentication_failure\"},\"source\":{\"ip\":\"203.0.113.9\"},"
        "\"@timestamp\":\"2024-08-12T14:20:01Z\"}\n"
        "{\"event.action\":\"authentication_failure\",\"source.ip\":\"203.0.113.9\",\"time\":\"1723472402\"}\n"
        "{\"dst_port\":\"4444\",\"destination.port\":\"4444\"}\n";
    json_object* c = answer(sigma_events_correlate_json(se, corr, clen, evs, strlen(evs)));
    json_object* f = at(get(c, "fires"), 0);
    check(is_ok(c), "correlate: ok");
    check(alen(get(c, "fires")) == 1, "correlate: one fire");
    check(get_int(f, "event") == 2, "correlate: fires on the third event");
    check(get_str(f, "corr_id") && !strcmp(get_str(f, "corr_id"), "brute"), "correlate: corr id");
    check(get_int(f, "observed") == 3 && get_int(f, "threshold") == 3, "correlate: observed and threshold");
    check(get_str(get(f, "group"), "source.ip") && !strcmp(get_str(get(f, "group"), "source.ip"), "203.0.113.9"),
          "correlate: group value");
    check(get_int(c, "untimed") == 1, "correlate: the event without time is counted");
    check(get(c, "stats") != NULL && get_int(get(c, "stats"), "rules_rejected") == 0, "correlate: stats");
    if (c) json_object_put(c);

    /* 400 s apart: outside the 300 s window. */
    const char* slow =
        "{\"event.action\":\"authentication_failure\",\"source.ip\":\"1.1.1.1\",\"@timestamp\":1723472400}\n"
        "{\"event.action\":\"authentication_failure\",\"source.ip\":\"1.1.1.1\",\"@timestamp\":1723472800}\n"
        "{\"event.action\":\"authentication_failure\",\"source.ip\":\"1.1.1.1\",\"@timestamp\":1723473200}\n";
    c = answer(sigma_events_correlate_json(se, corr, clen, slow, strlen(slow)));
    check(is_ok(c) && alen(get(c, "fires")) == 0, "correlate: event time drives the window");
    if (c) json_object_put(c);

    c = answer(sigma_events_correlate_json(se, "{\"version\":2}", 13, evs, strlen(evs)));
    check(!is_ok(c), "correlate: bad artifact refused");
    if (c) json_object_put(c);

    c = answer(sigma_events_correlate_json(se, corr, clen, "[1]", 3));
    check(!is_ok(c) && get_str(c, "error") != NULL, "correlate: bad events refused");
    if (c) json_object_put(c);

    sigma_events_free(se);
}

int main(int argc, char** argv) {
    if (argc != 4) {
        fprintf(stderr, "usage: %s <conf.sigmac> <arch.sigmac> <arch.corr.json>\n", argv[0]);
        return 2;
    }
    size_t clen = 0, alen_ = 0, jlen = 0;
    uint8_t* conf = read_file(argv[1], &clen);
    uint8_t* arch = read_file(argv[2], &alen_);
    uint8_t* corr = read_file(argv[3], &jlen);
    if (conf == NULL || arch == NULL || corr == NULL) {
        fprintf(stderr, "test_events: cannot read the fixtures\n");
        return 2;
    }
    int st = 0;
    sigma_events_t* se = sigma_events_load(conf, clen, &st);
    check(se != NULL, "conformance artifact loads");
    if (se != NULL) {
        test_load();
        test_info(se);
        test_event_model(se);
        test_input_forms(se);
        test_explain(se);
        test_agreement(se);
        sigma_events_free(se);
    }
    test_correlate(arch, alen_, (const char*)corr, jlen);
    free(conf);
    free(arch);
    free(corr);
    printf("\nsigma_events: %d passed, %d failed\n", g_pass, g_fail);
    return g_fail ? 1 : 0;
}
