/* test_wire.c
 * Contrib JSON "v" and rules.corr.json "version" are mandatory. Wrong or
 * missing version is a reject, never a partial load.
 */
#include "contrib_wire.h"
#include "corr_format.h"

#include <json.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static int g_pass, g_fail;

static corr_artifact_t* parse_str(const char* json, struct corr_artifact_view* view) {
    return corr_artifact_parse(json, strlen(json), view);
}

static void check(int cond, const char* msg) {
    if (cond) {
        g_pass++;
        printf("  PASS  %s\n", msg);
    } else {
        g_fail++;
        printf("  FAIL  %s\n", msg);
    }
}

int main(void) {
    corr_contrib_t c;
    const char* slots[CORR_MAX_GROUP_FIELDS];
    json_object* j;

    j = json_tokener_parse(
        "{\"v\":1,\"kind\":\"count\",\"corr_id\":\"ec\",\"ts\":1,\"group\":[\"10.0.0.1\"],\"count\":5}");
    check(j != NULL && corr_contrib_from_json(j, &c, slots, CORR_MAX_GROUP_FIELDS) == 0, "contrib v=1 accepted");
    if (j) json_object_put(j);

    j = json_tokener_parse("{\"kind\":\"count\",\"corr_id\":\"ec\",\"ts\":1,\"group\":[\"10.0.0.1\"],\"count\":5}");
    check(j != NULL && corr_contrib_from_json(j, &c, slots, CORR_MAX_GROUP_FIELDS) != 0, "contrib missing v rejected");
    if (j) json_object_put(j);

    j = json_tokener_parse(
        "{\"v\":2,\"kind\":\"count\",\"corr_id\":\"ec\",\"ts\":1,\"group\":[\"10.0.0.1\"],\"count\":5}");
    check(j != NULL && corr_contrib_from_json(j, &c, slots, CORR_MAX_GROUP_FIELDS) != 0, "contrib v=2 rejected");
    if (j) json_object_put(j);

    /* "key" is the corr_owner_key a hash transport routes on: the exact bytes
     * corr_owner_index hashes, whole at any length, and ignored on parse. */
    {
        const char* g[] = {"10.0.0.1", "root"};
        corr_contrib_t out;
        json_object* k;
        memset(&out, 0, sizeof out);
        out.kind = CORR_CONTRIB_COUNT;
        out.corr_id = "brute";
        out.group_vals = g;
        out.n_group = 2;
        out.count = 1;
        j = corr_contrib_to_json(&out, "bee");
        check(j != NULL && json_object_object_get_ex(j, "key", &k) &&
                  !strcmp(json_object_get_string(k), "brute\t10.0.0.1\troot"),
              "contrib key is corr_id TAB group values");
        check(j != NULL && corr_contrib_from_json(j, &c, slots, CORR_MAX_GROUP_FIELDS) == 0 &&
                  corr_owner_index(c.corr_id, c.group_vals, c.n_group, 4) == 1,
              "contrib with key parses, owner unchanged");
        if (j) json_object_put(j);
    }
    {
        static char longv[601];
        const char* g[] = {longv};
        corr_contrib_t out;
        json_object* k;
        memset(longv, 'a', 600);
        longv[600] = '\0';
        memset(&out, 0, sizeof out);
        out.kind = CORR_CONTRIB_COUNT;
        out.corr_id = "brute";
        out.group_vals = g;
        out.n_group = 1;
        out.count = 1;
        j = corr_contrib_to_json(&out, NULL);
        check(j != NULL && json_object_object_get_ex(j, "key", &k) && json_object_get_string_len(k) == 606 &&
                  !strncmp(json_object_get_string(k), "brute\taaaa", 10),
              "contrib key is whole past 512 bytes");
        if (j) json_object_put(j);
    }

    {
        struct corr_artifact_view view;
        corr_artifact_t* a = parse_str("{\"version\":1,\"correlations\":[]}", &view);
        check(a != NULL && view.n == 0, "corr json version=1 empty accepted");
        corr_artifact_free(a);
    }
    {
        struct corr_artifact_view view;
        corr_artifact_t* a = parse_str("[]", &view);
        check(a == NULL, "corr json bare array rejected");
        corr_artifact_free(a);
    }
    {
        struct corr_artifact_view view;
        corr_artifact_t* a = parse_str("{\"correlations\":[]}", &view);
        check(a == NULL, "corr json missing version rejected");
        corr_artifact_free(a);
    }
    {
        struct corr_artifact_view view;
        corr_artifact_t* a = parse_str("{\"version\":2,\"correlations\":[]}", &view);
        check(a == NULL, "corr json version=2 rejected");
        corr_artifact_free(a);
    }

    /* corr_artifact_parse reads exactly len bytes and needs no NUL. */
    {
        static const char doc[] =
            "{\"version\":1,\"correlations\":[{\"id\":\"c1\",\"type\":\"event_count\","
            "\"base_rule_ids\":[10],\"group_by\":[\"host.name\"],\"timespan_s\":60,\"threshold\":2}]}";
        size_t n = sizeof(doc) - 1;
        char* buf = malloc(n); /* no room for a NUL: ASan flags any read past n */
        check(buf != NULL, "corr exact-length buffer allocated");
        if (buf != NULL) {
            struct corr_artifact_view view;
            memcpy(buf, doc, n);
            corr_artifact_t* a = corr_artifact_parse(buf, n, &view);
            check(a != NULL && view.n == 1, "corr json parsed from an unterminated buffer");
            corr_artifact_free(a);
            a = corr_artifact_parse(buf, n - 1, &view);
            check(a == NULL, "corr json cut one byte short rejected");
            corr_artifact_free(a);
            free(buf);
        }
    }
    {
        struct corr_artifact_view view;
        const char* ws = "{\"version\":1,\"correlations\":[]}\r\n\t \n";
        corr_artifact_t* a = corr_artifact_parse(ws, strlen(ws), &view);
        check(a != NULL && view.n == 0, "corr json trailing whitespace accepted");
        corr_artifact_free(a);
        const char* junk = "{\"version\":1,\"correlations\":[]}x";
        a = corr_artifact_parse(junk, strlen(junk), &view);
        check(a == NULL, "corr json trailing data rejected");
        corr_artifact_free(a);
        const char nul[] = "{\"version\":1,\"correlations\":[]}\0{}";
        a = corr_artifact_parse(nul, sizeof(nul) - 1, &view);
        check(a == NULL, "corr json embedded NUL then data rejected");
        corr_artifact_free(a);
        const char* body = "{\"version\":1,\"correlations\":[]}";
        a = corr_artifact_parse(body, strlen(body) - 5, &view);
        check(a == NULL, "corr json prefix of a document rejected");
        corr_artifact_free(a);
        check(corr_artifact_parse(body, 0, &view) == NULL && view.n == 0, "corr json len 0 rejected");
        check(corr_artifact_parse(NULL, 10, &view) == NULL, "corr json NULL rejected");
        check(corr_artifact_parse(body, (size_t)INT_MAX + 1, &view) == NULL, "corr json len > INT_MAX rejected");
    }

    printf("\nwire/version: %d passed, %d failed\n", g_pass, g_fail);
    return g_fail ? 1 : 0;
}
