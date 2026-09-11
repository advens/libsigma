/* test_event_time.c — unit tests for event_time_parse. libc only. */

#include "event_time.h"

#include <stdio.h>
#include <string.h>
#include <math.h>

static int g_pass, g_fail;

#define CHECK(cond, msg)                 \
    do {                                 \
        if (cond) {                      \
            g_pass++;                    \
        } else {                         \
            g_fail++;                    \
            printf("  FAIL: %s\n", msg); \
        }                                \
    } while (0)

#define CLOSE(a, b, msg) CHECK(fabs((a) - (b)) < 1e-6, msg)

int main(void) {
    double a = 0, b = 0;
    time_t ref = 1787227200; /* 2026-08-20 12:00:00 UTC, for RFC3164 year */

    CHECK(event_time_parse("1723472400", 10, ref, &a) == 1, "epoch integer");
    CHECK(a == 1723472400.0, "epoch value");
    CHECK(event_time_parse("1723472400.5", 12, ref, &a) == 1, "epoch frac");
    CHECK(a == 1723472400.5, "epoch frac value");

    CHECK(event_time_parse("2026-08-20T12:00:00Z", 20, ref, &a) == 1, "ISO Z");
    CHECK(event_time_parse("2026-08-20T12:00:00+00:00", 25, ref, &b) == 1, "ISO +00:00");
    CLOSE(a, b, "ISO Z == +00:00");
    CHECK(event_time_parse("2026-08-20T12:00:00+0000", 24, ref, &b) == 1, "ISO +0000");
    CLOSE(a, b, "ISO Z == +0000");
    CHECK(event_time_parse("2026-08-20 12:00:00Z", 20, ref, &b) == 1, "ISO space");
    CLOSE(a, b, "ISO T vs space");
    CHECK(event_time_parse("2026-08-20T12:00:00.123456+0000", 30, ref, &b) == 1, "Suricata us");
    CLOSE(b, a + 0.123456, "Suricata fractional");

    CHECK(event_time_parse("2026-08-20T12:00:00+02:00", 25, ref, &b) == 1, "ISO +02:00");
    CLOSE(a - b, 7200.0, "+02:00 is 2h behind 12:00Z");

    CHECK(event_time_parse("20/Aug/2026:12:00:00 +0000", 26, ref, &b) == 1, "nginx CLF");
    CLOSE(a, b, "CLF == ISO Z");
    CHECK(event_time_parse("20/Aug/2026:12:00:00 +0200", 26, ref, &b) == 1, "nginx CLF +0200");
    CLOSE(a - b, 7200.0, "CLF +0200");

    CHECK(event_time_parse("2026/08/20 12:00:00", 19, ref, &b) == 1, "nginx error");
    CLOSE(a, b, "nginx error == ISO Z");

    CHECK(event_time_parse("Aug 20 12:00:00", 15, ref, &b) == 1, "RFC3164");
    CLOSE(a, b, "RFC3164 year inferred");
    CHECK(event_time_parse("  2026-08-20T12:00:00Z  ", 24, ref, &b) == 1, "trim");
    CLOSE(a, b, "trimmed ISO");

    CHECK(event_time_parse("not-a-date", 10, ref, &a) == 0, "reject garbage");
    CHECK(event_time_parse("", 0, ref, &a) == 0, "reject empty");
    CHECK(event_time_parse(NULL, 4, ref, &a) == 0, "reject NULL");

    printf("\nevent_time: %d passed, %d failed\n", g_pass, g_fail);
    if (g_fail == 0) printf("PASSED %d/%d\n", g_pass, g_pass);
    return g_fail ? 1 : 0;
}
