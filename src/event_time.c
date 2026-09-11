/* event_time.c — see event_time.h. Hand-rolled, no strptime / locale. */

#include "event_time.h"

#include <ctype.h>
#include <string.h>
#include <stdlib.h>

static int days_from_civil(int y, int m, int d) {
    y -= (m <= 2);
    int era = (y >= 0 ? y : y - 399) / 400;
    unsigned yoe = (unsigned)(y - era * 400);
    unsigned doy = (unsigned)((153 * (m > 2 ? m - 3 : m + 9) + 2) / 5 + d - 1);
    unsigned doe = yoe * 365u + yoe / 4u - yoe / 100u + doy;
    return era * 146097 + (int)doe - 719468;
}

static int month3(const char* s) {
    static const char m[12][3] = {{'j', 'a', 'n'}, {'f', 'e', 'b'}, {'m', 'a', 'r'}, {'a', 'p', 'r'},
                                  {'m', 'a', 'y'}, {'j', 'u', 'n'}, {'j', 'u', 'l'}, {'a', 'u', 'g'},
                                  {'s', 'e', 'p'}, {'o', 'c', 't'}, {'n', 'o', 'v'}, {'d', 'e', 'c'}};
    if (s[0] == '\0' || s[1] == '\0' || s[2] == '\0') return 0;
    for (int i = 0; i < 12; i++)
        if ((s[0] | 0x20) == m[i][0] && (s[1] | 0x20) == m[i][1] && (s[2] | 0x20) == m[i][2]) return i + 1;
    return 0;
}

static int civil_ok(int Y, int Mo, int D, int h, int mi, double se) {
    return Y >= 1970 && Y <= 2100 && Mo >= 1 && Mo <= 12 && D >= 1 && D <= 31 && h >= 0 && h <= 23 && mi >= 0 &&
           mi <= 59 && se >= 0.0 && se < 61.0;
}

static double to_epoch(int Y, int Mo, int D, int h, int mi, double se, int off_min) {
    return (double)days_from_civil(Y, Mo, D) * 86400.0 + h * 3600.0 + mi * 60.0 + se - (double)off_min * 60.0;
}

/* Parse timezone at p: Z / +HH:MM / +HHMM / +HH. Returns 1 and writes minutes
 * east of UTC (so +0200 => +120). */
static int parse_offset(const char* p, int* off_min) {
    *off_min = 0;
    if (p == NULL || *p == '\0' || *p == 'Z' || *p == 'z') return 1;
    int sign = 0;
    if (*p == '+')
        sign = 1;
    else if (*p == '-')
        sign = -1;
    else
        return 0;
    p++;
    if (!isdigit((unsigned char)p[0]) || !isdigit((unsigned char)p[1])) return 0;
    int oh = (p[0] - '0') * 10 + (p[1] - '0');
    int om = 0;
    p += 2;
    if (*p == ':') p++;
    if (isdigit((unsigned char)p[0]) && isdigit((unsigned char)p[1])) om = (p[0] - '0') * 10 + (p[1] - '0');
    if (oh > 14 || om > 59) return 0;
    *off_min = sign * (oh * 60 + om);
    return 1;
}

static int parse_hms(const char* p, int* h, int* mi, double* se, const char** rest) {
    if (!isdigit((unsigned char)p[0]) || !isdigit((unsigned char)p[1]) || p[2] != ':') return 0;
    *h = (p[0] - '0') * 10 + (p[1] - '0');
    p += 3;
    if (!isdigit((unsigned char)p[0]) || !isdigit((unsigned char)p[1])) return 0;
    *mi = (p[0] - '0') * 10 + (p[1] - '0');
    p += 2;
    *se = 0.0;
    if (*p == ':') {
        p++;
        char* end = NULL;
        *se = strtod(p, &end);
        if (end == p) return 0;
        p = end;
    }
    *rest = p;
    return 1;
}

int event_time_from_civil(int Y, int Mo, int D, int h, int mi, double se, int off_min, double* out) {
    if (out == NULL || !civil_ok(Y, Mo, D, h, mi, se)) return 0;
    *out = to_epoch(Y, Mo, D, h, mi, se, off_min);
    return 1;
}

int event_time_parse(const char* s, size_t len, time_t ref_wall, double* out) {
    if (s == NULL || out == NULL || len < 1 || len > 63) return 0;
    char buf[64];
    memcpy(buf, s, len);
    buf[len] = '\0';
    char* b = buf;
    while (*b == ' ' || *b == '\t') b++;
    size_t n = strlen(b);
    while (n > 0 && (b[n - 1] == ' ' || b[n - 1] == '\t')) b[--n] = '\0';
    if (n < 1) return 0;

    /* numeric epoch */
    if (isdigit((unsigned char)b[0]) && n >= 9 && n <= 18 && b[4] != '-' && b[4] != '/' && b[2] != '/') {
        char* end = NULL;
        double v = strtod(b, &end);
        if (end != b && (*end == '\0' || *end == ' ') && v > 100000000.0) {
            *out = v;
            return 1;
        }
    }

    int Y = 0, Mo = 0, D = 0, h = 0, mi = 0, off = 0;
    double se = 0.0;
    const char* rest = NULL;

    /* ISO-8601 / RFC5424: YYYY-MM-DD[T ]HH:MM:SS */
    if (n >= 10 && isdigit((unsigned char)b[0]) && b[4] == '-' && b[7] == '-') {
        Y = (b[0] - '0') * 1000 + (b[1] - '0') * 100 + (b[2] - '0') * 10 + (b[3] - '0');
        Mo = (b[5] - '0') * 10 + (b[6] - '0');
        D = (b[8] - '0') * 10 + (b[9] - '0');
        if (n == 10) {
            if (!civil_ok(Y, Mo, D, 0, 0, 0.0)) return 0;
            *out = to_epoch(Y, Mo, D, 0, 0, 0.0, 0);
            return 1;
        }
        if (b[10] != 'T' && b[10] != 't' && b[10] != ' ') return 0;
        if (!parse_hms(b + 11, &h, &mi, &se, &rest)) return 0;
        if (!civil_ok(Y, Mo, D, h, mi, se)) return 0;
        while (*rest == ' ') rest++;
        if (!parse_offset(rest, &off)) return 0;
        *out = to_epoch(Y, Mo, D, h, mi, se, off);
        return 1;
    }

    /* nginx error_log: YYYY/MM/DD HH:MM:SS */
    if (n >= 19 && isdigit((unsigned char)b[0]) && b[4] == '/' && b[7] == '/') {
        Y = (b[0] - '0') * 1000 + (b[1] - '0') * 100 + (b[2] - '0') * 10 + (b[3] - '0');
        Mo = (b[5] - '0') * 10 + (b[6] - '0');
        D = (b[8] - '0') * 10 + (b[9] - '0');
        const char* p = b + 10;
        while (*p == ' ') p++;
        if (!parse_hms(p, &h, &mi, &se, &rest)) return 0;
        if (!civil_ok(Y, Mo, D, h, mi, se)) return 0;
        while (*rest == ' ') rest++;
        if (*rest && !parse_offset(rest, &off)) return 0;
        *out = to_epoch(Y, Mo, D, h, mi, se, off);
        return 1;
    }

    /* nginx $time_local / CLF: DD/MMM/YYYY:HH:MM:SS[ offset] */
    if (n >= 20 && (b[1] == '/' || b[2] == '/')) {
        const char* p = b;
        D = 0;
        int nd = 0;
        while (isdigit((unsigned char)*p) && nd < 2) {
            D = D * 10 + (*p - '0');
            p++;
            nd++;
        }
        if (*p != '/') return 0;
        p++;
        Mo = month3(p);
        if (Mo == 0) return 0;
        p += 3;
        if (*p != '/') return 0;
        p++;
        if (!isdigit((unsigned char)p[0]) || !isdigit((unsigned char)p[3])) return 0;
        Y = (p[0] - '0') * 1000 + (p[1] - '0') * 100 + (p[2] - '0') * 10 + (p[3] - '0');
        p += 4;
        if (*p != ':') return 0;
        p++;
        if (!parse_hms(p, &h, &mi, &se, &rest)) return 0;
        if (!civil_ok(Y, Mo, D, h, mi, se)) return 0;
        while (*rest == ' ') rest++;
        if (*rest && !parse_offset(rest, &off)) return 0;
        *out = to_epoch(Y, Mo, D, h, mi, se, off);
        return 1;
    }

    /* RFC3164: Mmm [D]D HH:MM:SS */
    if ((b[0] | 0x20) >= 'a' && (b[0] | 0x20) <= 'z') {
        Mo = month3(b);
        if (Mo == 0) return 0;
        const char* p = b + 3;
        while (*p == ' ') p++;
        D = 0;
        int nd = 0;
        while (isdigit((unsigned char)*p) && nd < 2) {
            D = D * 10 + (*p - '0');
            p++;
            nd++;
        }
        while (*p == ' ') p++;
        if (nd == 0 || !parse_hms(p, &h, &mi, &se, &rest)) return 0;
        if (D < 1 || D > 31 || h < 0 || h > 23 || mi < 0 || mi > 59 || se < 0.0 || se >= 61.0) return 0;
        struct tm reftm;
        time_t rw = ref_wall > 0 ? ref_wall : 0;
        gmtime_r(&rw, &reftm);
        Y = reftm.tm_year + 1900;
        int diff = Mo - (reftm.tm_mon + 1);
        if (diff > 6)
            Y -= 1;
        else if (diff < -6)
            Y += 1;
        while (*rest == ' ') rest++;
        if (*rest && !parse_offset(rest, &off)) return 0;
        *out = to_epoch(Y, Mo, D, h, mi, se, off);
        return 1;
    }

    return 0;
}
