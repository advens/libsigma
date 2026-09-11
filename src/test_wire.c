/* test_wire.c
 * Contrib JSON "v" and rules.corr.json "version" are mandatory. Wrong or
 * missing version is a reject, never a partial load.
 */
#include "contrib_wire.h"
#include "corr_format.h"

#include <json.h>
#include <stdio.h>
#include <string.h>

static int g_pass, g_fail;

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

    {
        struct corr_artifact_view view;
        corr_artifact_t* a = corr_artifact_parse("{\"version\":1,\"correlations\":[]}", 0, &view);
        check(a != NULL && view.n == 0, "corr json version=1 empty accepted");
        corr_artifact_free(a);
    }
    {
        struct corr_artifact_view view;
        corr_artifact_t* a = corr_artifact_parse("[]", 0, &view);
        check(a == NULL, "corr json bare array rejected");
        corr_artifact_free(a);
    }
    {
        struct corr_artifact_view view;
        corr_artifact_t* a = corr_artifact_parse("{\"correlations\":[]}", 0, &view);
        check(a == NULL, "corr json missing version rejected");
        corr_artifact_free(a);
    }
    {
        struct corr_artifact_view view;
        corr_artifact_t* a = corr_artifact_parse("{\"version\":2,\"correlations\":[]}", 0, &view);
        check(a == NULL, "corr json version=2 rejected");
        corr_artifact_free(a);
    }

    printf("\nwire/version: %d passed, %d failed\n", g_pass, g_fail);
    return g_fail ? 1 : 0;
}
