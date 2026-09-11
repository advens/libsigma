/* event_time.h
 * Parse a log timestamp into UTC epoch seconds. Lets the caller clock
 * correlation windows on WHEN the event happened, not when the pipeline
 * processed it.
 *
 * No third-party dependency. Unit-tested in test_event_time.c.
 *
 * Copyright 2026 Advens.
 */
#ifndef EVENT_TIME_H
#define EVENT_TIME_H

#include <stddef.h>
#include <time.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Parse s[0..len) into UTC epoch seconds (fractional OK). ref_wall is used
 * only to infer the year of an RFC3164 stamp (no year on the wire).
 *
 * Accepted forms (leading/trailing whitespace ignored):
 *   numeric epoch          1723472400 / 1723472400.123
 *   ISO-8601 / RFC5424     2026-08-20T12:34:56[.frac][Z|+HH:MM|+HHMM]
 *                          2026-08-20 12:34:56  (space instead of T)
 *   RFC3164                Aug 20 12:34:56[.frac]  (year inferred)
 *   nginx $time_local/CLF  20/Aug/2026:12:34:56 +0200
 *   nginx error_log        2026/08/20 12:34:56
 *
 * Returns 1 and writes *out on success, else 0.
 */
int event_time_parse(const char* s, size_t len, time_t ref_wall, double* out);

/* Y-M-D h:m:s plus minutes east of UTC (e.g. +0200 => 120). Writes UTC epoch. */
int event_time_from_civil(int Y, int Mo, int D, int h, int mi, double se, int off_min, double* out);

#ifdef __cplusplus
}
#endif

#endif /* EVENT_TIME_H */
