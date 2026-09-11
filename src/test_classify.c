/* test_classify.c
 * Standalone unit tests for the libsigma correlation engine (classify_corr.c).
 * No third-party dependency, pure libc, runs anywhere.  This is THE acceptance
 * gate; `make test` runs it as a CI gate.
 *
 * Cases: event_count at-threshold, value_count distinct-only, temporal any
 * order, temporal_ordered in/out-of-order, window expiry, re-fire suppression,
 * the bounded-eviction / anti-exhaustion caps.
 *
 * Expiry is driven by an explicit monotonic `ts` passed into corr_on_event (the
 * same clock the caller supplies), so expiry is deterministic: no sleeps, no
 * flakiness.
 *
 * Build: cc -std=c11 -O2 -Wall -Wextra -I. -o /tmp/tcorr \
 *           test_classify.c classify_corr.c && /tmp/tcorr
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

#include "classify_corr.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <stdbool.h>

static int g_pass = 0, g_fail = 0;
#define CHECK(cond, msg)                 \
    do {                                 \
        if (cond) {                      \
            g_pass++;                    \
        } else {                         \
            g_fail++;                    \
            printf("  FAIL: %s\n", msg); \
        }                                \
    } while (0)

/* ---------------------------------------------------------------------------
 * A tiny event model: a flat (key,value) list + the matched rule-ids.  The
 * field resolver answers group-by / value_count field lookups from it.
 * ------------------------------------------------------------------------- */
typedef struct {
    const char *k, *v;
} kv_t;
typedef struct {
    const kv_t* kv;
    size_t n;
} event_t;

static const char* ev_field(void* ctx, const char* name) {
    const event_t* e = (const event_t*)ctx;
    for (size_t i = 0; i < e->n; i++)
        if (strcmp(e->kv[i].k, name) == 0) return e->kv[i].v;
    return NULL;
}

/* Feed an event built from inline arrays. Returns the fire count; copies the
 * first fire (if any) into *out_first. */
static int feed(corr_engine_t* e,
                const char* ip,
                const char* user,
                const uint32_t* rids,
                size_t n_rids,
                double ts,
                corr_fire_t* out_first) {
    kv_t kv[2];
    size_t n = 0;
    if (ip) {
        kv[n].k = "source.ip";
        kv[n].v = ip;
        n++;
    }
    if (user) {
        kv[n].k = "user.name";
        kv[n].v = user;
        n++;
    }
    event_t ev = {kv, n};
    corr_fire_t fires[8];
    /* Per-worker group scratch; function-static so a returned fire's group
     * pointers stay valid until the next feed() (single-threaded test). */
    static const char* scratch[8 * CORR_MAX_GROUP_FIELDS];
    int nf = corr_on_event(e, rids, n_rids, ev_field, &ev, ts, fires, 8, scratch, sizeof(scratch) / sizeof(scratch[0]));
    if (nf > 0 && out_first) *out_first = fires[0];
    return nf;
}

/* ---------------------------------------------------------------------------
 * Shared fixtures (mirror the Python EVENT_COUNT / VALUE_COUNT / TEMPORAL /
 * TEMPORAL_ORDERED dicts).  The caller owns the backing arrays for the engine's
 * lifetime, so these live as file-scope statics.
 * ------------------------------------------------------------------------- */
static const uint32_t BASE_1[] = {1};
static const uint32_t BASE_123[] = {1, 2, 3};
static const uint32_t BASE_12[] = {1, 2};
static const char* GB_IP_USER[] = {"source.ip", "user.name"};
static const char* GB_IP[] = {"source.ip"};

static corr_rule_t mk_event_count(void) {
    corr_rule_t r;
    memset(&r, 0, sizeof(r));
    r.id = "brute";
    r.title = "Brute force";
    r.type = CORR_EVENT_COUNT;
    r.base_rule_ids = BASE_1;
    r.n_base_rule_ids = 1;
    r.group_by = GB_IP_USER;
    r.n_group_by = 2;
    r.cond_op = CORR_OP_GTE;
    r.cond_count = 10;
    r.timespan_s = 300;
    r.level = "high";
    r.mitre = "T1110.001";
    return r;
}

static corr_rule_t mk_value_count(void) {
    corr_rule_t r;
    memset(&r, 0, sizeof(r));
    r.id = "spray";
    r.title = "Spray";
    r.type = CORR_VALUE_COUNT;
    r.base_rule_ids = BASE_1;
    r.n_base_rule_ids = 1;
    r.group_by = GB_IP;
    r.n_group_by = 1;
    r.value_field = "user.name";
    r.cond_op = CORR_OP_GTE;
    r.cond_count = 5;
    r.timespan_s = 600;
    r.level = "high";
    r.mitre = "T1110.003";
    return r;
}

static corr_rule_t mk_temporal(void) {
    corr_rule_t r;
    memset(&r, 0, sizeof(r));
    r.id = "cluster";
    r.title = "Cluster";
    r.type = CORR_TEMPORAL;
    r.base_rule_ids = BASE_123;
    r.n_base_rule_ids = 3;
    r.group_by = GB_IP;
    r.n_group_by = 1;
    r.cond_op = CORR_OP_GTE;
    r.cond_count = 3;
    r.timespan_s = 600;
    r.level = "high";
    r.mitre = "T1078";
    return r;
}

static corr_rule_t mk_temporal_ordered(void) {
    corr_rule_t r;
    memset(&r, 0, sizeof(r));
    r.id = "chain";
    r.title = "Chain";
    r.type = CORR_TEMPORAL_ORDERED;
    r.base_rule_ids = BASE_12;
    r.n_base_rule_ids = 2;
    r.ordered_rule_ids = BASE_12;
    r.n_ordered_rule_ids = 2;
    r.group_by = GB_IP;
    r.n_group_by = 1;
    r.cond_op = CORR_OP_GTE;
    r.cond_count = 2;
    r.timespan_s = 600;
    r.level = "critical";
    r.mitre = "T1078";
    return r;
}

/* ===========================================================================
 * event_count
 * ========================================================================= */
static void test_event_count(void) {
    corr_rule_t r = mk_event_count();
    corr_engine_t* e = corr_engine_new(&r, 1, corr_caps_default());
    assert(e);

    /* test_fires_at_threshold: first 9 don't fire, the 10th does. */
    corr_fire_t f;
    memset(&f, 0, sizeof(f));
    for (int i = 0; i < 9; i++)
        CHECK(feed(e, "203.0.113.9", "root", BASE_1, 1, 100.0, NULL) == 0,
              "event_count: should not fire before threshold");
    int nf = feed(e, "203.0.113.9", "root", BASE_1, 1, 100.0, &f);
    CHECK(nf == 1, "event_count: fires AT threshold (10th)");
    CHECK(f.rule_id && strcmp(f.rule_id, "brute") == 0, "event_count: rule_id=brute");
    CHECK(f.observed == 10, "event_count: observed==10");
    CHECK(f.technique && strcmp(f.technique, "T1110.001") == 0, "event_count: technique");
    CHECK(f.tier == CORR_TIER_STRONG, "event_count high-level: STRONG");
    CHECK(f.n_group == 2 && f.group && strcmp(f.group[0], "203.0.113.9") == 0 && strcmp(f.group[1], "root") == 0,
          "event_count: group evidence");
    corr_engine_free(e);

    /* test_distinct_groups_counted_separately: 9 root + 9 admin, neither hits 10. */
    e = corr_engine_new(&r, 1, corr_caps_default());
    for (int i = 0; i < 9; i++)
        CHECK(feed(e, "203.0.113.9", "root", BASE_1, 1, 100.0, NULL) == 0, "event_count: root group under threshold");
    for (int i = 0; i < 9; i++)
        CHECK(feed(e, "203.0.113.9", "admin", BASE_1, 1, 100.0, NULL) == 0,
              "event_count: admin group counted separately, under threshold");
    corr_engine_free(e);

    /* test_missing_group_field_ignored: no user.name -> never attributed. */
    e = corr_engine_new(&r, 1, corr_caps_default());
    for (int i = 0; i < 20; i++)
        CHECK(feed(e, "203.0.113.9", NULL, BASE_1, 1, 100.0, NULL) == 0, "event_count: missing group field => ignored");
    corr_engine_free(e);
}

/* ===========================================================================
 * value_count (DISTINCT only)
 * ========================================================================= */
static void test_value_count(void) {
    corr_rule_t r = mk_value_count();
    corr_engine_t* e = corr_engine_new(&r, 1, corr_caps_default());
    assert(e);

    /* test_fires_on_n_distinct: a,b,c,d,e -> fires at the 5th DISTINCT. */
    const char* users[] = {"a", "b", "c", "d", "e"};
    corr_fire_t f;
    memset(&f, 0, sizeof(f));
    int total = 0;
    for (int i = 0; i < 5; i++) {
        int nf = feed(e, "203.0.113.9", users[i], BASE_1, 1, 100.0, &f);
        total += nf;
    }
    CHECK(total == 1, "value_count: fires once at 5 distinct");
    CHECK(f.rule_id && strcmp(f.rule_id, "spray") == 0, "value_count: rule_id=spray");
    CHECK(f.observed == 5, "value_count: observed==5 distinct");
    CHECK(f.value_field && strcmp(f.value_field, "user.name") == 0, "value_count: value_field");
    corr_engine_free(e);

    /* test_repeated_value_does_not_advance: same user x20 -> 1 distinct, never 5. */
    e = corr_engine_new(&r, 1, corr_caps_default());
    int fired = 0;
    for (int i = 0; i < 20; i++) fired += feed(e, "203.0.113.9", "same", BASE_1, 1, 100.0, NULL);
    CHECK(fired == 0, "value_count: repeated value counts DISTINCT only");
    corr_engine_free(e);
}

/* ===========================================================================
 * temporal (any order)
 * ========================================================================= */
static void test_temporal(void) {
    corr_rule_t r = mk_temporal();
    corr_engine_t* e = corr_engine_new(&r, 1, corr_caps_default());
    assert(e);

    /* test_fires_when_all_present_any_order: 3, then 1, then 2 -> fire. */
    const uint32_t r3[] = {3}, r1[] = {1}, r2[] = {2};
    corr_fire_t f;
    memset(&f, 0, sizeof(f));
    CHECK(feed(e, "203.0.113.9", "root", r3, 1, 100.0, NULL) == 0, "temporal: 3 alone no fire");
    CHECK(feed(e, "203.0.113.9", "root", r1, 1, 100.0, NULL) == 0, "temporal: +1 no fire");
    int nf = feed(e, "203.0.113.9", "root", r2, 1, 100.0, &f);
    CHECK(nf == 1, "temporal: fires when all 3 seen (any order)");
    CHECK(f.rule_id && strcmp(f.rule_id, "cluster") == 0, "temporal: rule_id=cluster");
    corr_engine_free(e);

    /* test_does_not_fire_with_subset: 1 then 2, rule 3 missing -> no fire. */
    e = corr_engine_new(&r, 1, corr_caps_default());
    CHECK(feed(e, "203.0.113.9", "root", r1, 1, 100.0, NULL) == 0, "temporal subset: 1");
    CHECK(feed(e, "203.0.113.9", "root", r2, 1, 100.0, NULL) == 0, "temporal: subset (missing rule 3) does NOT fire");
    corr_engine_free(e);
}

/* ===========================================================================
 * temporal_ordered
 * ========================================================================= */
static void test_temporal_ordered(void) {
    corr_rule_t r = mk_temporal_ordered();
    const uint32_t r1[] = {1}, r2[] = {2}, r12[] = {1, 2};

    /* test_fires_in_order: 1 then 2 -> fire. */
    corr_engine_t* e = corr_engine_new(&r, 1, corr_caps_default());
    corr_fire_t f;
    memset(&f, 0, sizeof(f));
    CHECK(feed(e, "203.0.113.9", "root", r1, 1, 100.0, NULL) == 0, "ordered: step 1 no fire");
    int nf = feed(e, "203.0.113.9", "root", r2, 1, 100.0, &f);
    CHECK(nf == 1, "ordered: fires in order (1 then 2)");
    CHECK(f.technique && strcmp(f.technique, "T1078") == 0, "ordered: technique T1078");
    corr_engine_free(e);

    /* test_wrong_order_does_not_fire: 2 first, twice -> never advances. */
    e = corr_engine_new(&r, 1, corr_caps_default());
    CHECK(feed(e, "203.0.113.9", "root", r2, 1, 100.0, NULL) == 0, "ordered: 2-first no fire");
    CHECK(feed(e, "203.0.113.9", "root", r2, 1, 100.0, NULL) == 0, "ordered: out-of-order does NOT fire");
    corr_engine_free(e);

    /* test_single_event_carrying_both_steps_completes: {1,2} on one event. */
    e = corr_engine_new(&r, 1, corr_caps_default());
    nf = feed(e, "203.0.113.9", "root", r12, 2, 100.0, &f);
    CHECK(nf == 1 && strcmp(f.rule_id, "chain") == 0, "ordered: single event carrying both steps completes");
    corr_engine_free(e);
}

/* event-time correlation clock (caps.event_time_ordering): temporal_ordered
 * requires each step's EVENT time to be non-decreasing, so a later-processed but
 * earlier-timestamped event cannot fabricate an ordered chain across concurrent
 * sources. Monotonic mode (default) keeps advancing on arrival order. */
static void test_temporal_ordered_event_time(void) {
    corr_rule_t r = mk_temporal_ordered();
    const uint32_t r1[] = {1}, r2[] = {2};
    corr_caps_t evt = corr_caps_default();
    evt.event_time_ordering = 1;

    /* in-order event time (t1 < t2) -> fires. */
    corr_engine_t* e = corr_engine_new(&r, 1, evt);
    assert(e);
    CHECK(feed(e, "198.51.100.1", NULL, r1, 1, 100.0, NULL) == 0, "ordered evt-time: step 1 no fire");
    CHECK(feed(e, "198.51.100.1", NULL, r2, 1, 200.0, NULL) == 1, "ordered evt-time: in-order (t1<t2) fires");
    corr_engine_free(e);

    /* step 2's event time PRECEDES step 1's -> rejected, no fire. */
    e = corr_engine_new(&r, 1, evt);
    CHECK(feed(e, "198.51.100.2", NULL, r1, 1, 200.0, NULL) == 0, "ordered evt-time: step 1 @200 no fire");
    CHECK(feed(e, "198.51.100.2", NULL, r2, 1, 100.0, NULL) == 0,
          "ordered evt-time: step 2 predates step 1 => rejected");
    corr_engine_free(e);

    /* monotonic mode (default): arrival-order advance ignores the ts backslide. */
    e = corr_engine_new(&r, 1, corr_caps_default());
    CHECK(feed(e, "198.51.100.3", NULL, r1, 1, 200.0, NULL) == 0, "ordered mono: step 1 no fire");
    CHECK(feed(e, "198.51.100.3", NULL, r2, 1, 100.0, NULL) == 1,
          "ordered mono: arrival-order advance regardless of ts");
    corr_engine_free(e);
}

/* ===========================================================================
 * window expiry (lazy time eviction), driven by explicit ts advancement.
 * ========================================================================= */
static void test_window_expiry(void) {
    /* event_count, timespan 1s: 9 events at t=100, then 9 at t=101.05, the old
     * 9 fell out of the 1s window, so the count is 9 not 18; the 10th crosses. */
    corr_rule_t r = mk_event_count();
    r.timespan_s = 1;
    corr_engine_t* e = corr_engine_new(&r, 1, corr_caps_default());
    for (int i = 0; i < 9; i++) feed(e, "203.0.113.9", "root", BASE_1, 1, 100.0, NULL);
    double t2 = 101.05; /* > 1s later: the first 9 expire */
    int fired = 0;
    for (int i = 0; i < 9; i++) fired += feed(e, "203.0.113.9", "root", BASE_1, 1, t2, NULL);
    CHECK(fired == 0, "expiry: old events fell out, 9 fresh under threshold");
    int nf = feed(e, "203.0.113.9", "root", BASE_1, 1, t2, NULL);
    CHECK(nf == 1, "expiry: the 10th fresh crosses");
    corr_engine_free(e);

    /* temporal_ordered, timespan 1s: step 1 anchored at t=100; step 2 at
     * t=101.05, the anchor aged out, the chain restarted, no fire. */
    corr_rule_t ro = mk_temporal_ordered();
    ro.timespan_s = 1;
    e = corr_engine_new(&ro, 1, corr_caps_default());
    const uint32_t r1[] = {1}, r2[] = {2};
    CHECK(feed(e, "203.0.113.9", "root", r1, 1, 100.0, NULL) == 0, "ordered-expiry: step1");
    CHECK(feed(e, "203.0.113.9", "root", r2, 1, 101.05, NULL) == 0, "ordered-expiry: anchor aged out => no fire");
    corr_engine_free(e);

    /* value_count, timespan 1s: 4 distinct at t=100; 4 NEW distinct at t=101.05
     *, old 4 expired, new 4 still under 5, no fire. */
    corr_rule_t rv = mk_value_count();
    rv.timespan_s = 1;
    e = corr_engine_new(&rv, 1, corr_caps_default());
    const char* u1[] = {"a", "b", "c", "d"};
    for (int i = 0; i < 4; i++) feed(e, "203.0.113.9", u1[i], BASE_1, 1, 100.0, NULL);
    const char* u2[] = {"e", "f", "g", "h"};
    fired = 0;
    for (int i = 0; i < 4; i++) fired += feed(e, "203.0.113.9", u2[i], BASE_1, 1, 101.05, NULL);
    CHECK(fired == 0, "value_count-expiry: old distinct expired, 4 new under 5");
    corr_engine_free(e);
}

/* ===========================================================================
 * re-fire suppression (one activation per window)
 * ========================================================================= */
static void test_refire_suppression(void) {
    corr_rule_t r = mk_event_count();
    corr_engine_t* e = corr_engine_new(&r, 1, corr_caps_default());
    /* fire at the 10th. */
    int total = 0;
    for (int i = 0; i < 10; i++) total += feed(e, "203.0.113.9", "root", BASE_1, 1, 100.0, NULL);
    CHECK(total == 1, "refire: fires once at threshold");
    /* 5 more within the same window: stays lit, no re-fire. */
    int extra = 0;
    for (int i = 0; i < 5; i++) extra += feed(e, "203.0.113.9", "root", BASE_1, 1, 100.0, NULL);
    CHECK(extra == 0, "refire: suppressed within the window (one per window)");
    corr_engine_free(e);
}

/* ===========================================================================
 * bounded eviction / anti-exhaustion (security)
 * ========================================================================= */
static void test_bounded_eviction(void) {
    /* test_group_cap_lru_evicts: max_groups=3, spray 100 distinct keys -> <=3. */
    corr_rule_t r = mk_event_count();
    corr_caps_t caps = corr_caps_default();
    caps.max_groups = 3;
    corr_engine_t* e = corr_engine_new(&r, 1, caps);
    for (int i = 0; i < 100; i++) {
        char ip[32], user[16];
        snprintf(ip, sizeof(ip), "10.0.0.%d", i);
        snprintf(user, sizeof(user), "u%d", i);
        feed(e, ip, user, BASE_1, 1, 100.0, NULL);
    }
    CHECK(corr_engine_groups_for(e, "brute") <= 3, "LRU group cap: <=3 groups after spraying 100 keys");
    corr_engine_free(e);

    /* test_distinct_set_capped: value_count max_distinct=8, 1000 distinct users
     * -> the set never exceeds 8 (and the spray still fired well before). */
    corr_rule_t rv = mk_value_count();
    caps = corr_caps_default();
    caps.max_distinct = 8;
    e = corr_engine_new(&rv, 1, caps);
    int fired = 0;
    for (int i = 0; i < 1000; i++) {
        char user[16];
        snprintf(user, sizeof(user), "user%d", i);
        corr_fire_t f;
        memset(&f, 0, sizeof(f));
        int nf = feed(e, "203.0.113.9", user, BASE_1, 1, 100.0, &f);
        if (nf) {
            fired += nf;
            CHECK(f.observed <= 8, "distinct cap: observed<=8");
        }
    }
    CHECK(fired > 0, "distinct cap: spray still fires (>=5 distinct seen)");
    corr_engine_free(e);

    /* test_events_per_group_ring_capped: huge threshold, ring=16, 1000 events
     * -> the ring never exceeds 16 (so it never fires). */
    corr_rule_t re = mk_event_count();
    re.cond_count = 1000000;
    caps = corr_caps_default();
    caps.max_events_per_group = 16;
    e = corr_engine_new(&re, 1, caps);
    int any = 0;
    for (int i = 0; i < 1000; i++) any += feed(e, "203.0.113.9", "root", BASE_1, 1, 100.0, NULL);
    CHECK(any == 0, "event ring cap: bounded ring never reaches the 1e6 threshold");
    corr_engine_free(e);

    /* test_total_groups_bounded_across_correlations: two correlations,
     * max_groups=5 each, 50 distinct keys -> total <= 5*2. */
    corr_rule_t rules2[2];
    rules2[0] = mk_event_count();
    rules2[1] = mk_value_count();
    caps = corr_caps_default();
    caps.max_groups = 5;
    e = corr_engine_new(rules2, 2, caps);
    for (int i = 0; i < 50; i++) {
        char ip[32], user[16];
        snprintf(ip, sizeof(ip), "10.1.0.%d", i);
        snprintf(user, sizeof(user), "u%d", i);
        feed(e, ip, user, BASE_1, 1, 100.0, NULL);
    }
    CHECK(corr_engine_total_groups(e) <= 5 * 2, "total groups bounded across correlations (<=10)");
    corr_engine_free(e);
}

/* ===========================================================================
 * Observable boundary counters must actually INCREMENT (every silent cap is
 * observable).  Each cap from test_bounded_eviction is re-driven here and the
 * matching corr_stats_t field is asserted non-zero, so a counter that is wired
 * but never fired (or wired to the wrong branch) is caught.
 * ========================================================================= */
static void test_boundary_counters(void) {
    corr_stats_t st;

    /* groups.evicted: max_groups=3, spray 100 distinct keys. */
    corr_rule_t r = mk_event_count();
    corr_caps_t caps = corr_caps_default();
    caps.max_groups = 3;
    corr_engine_t* e = corr_engine_new(&r, 1, caps);
    for (int i = 0; i < 100; i++) {
        char ip[32], user[16];
        snprintf(ip, sizeof(ip), "10.0.0.%d", i);
        snprintf(user, sizeof(user), "u%d", i);
        feed(e, ip, user, BASE_1, 1, 100.0, NULL);
    }
    corr_engine_stats(e, &st);
    CHECK(st.groups_evicted > 0, "counter: groups.evicted increments under LRU group cap");
    corr_engine_free(e);

    /* distinct.evicted: value_count max_distinct=8, 1000 distinct users. */
    corr_rule_t rv = mk_value_count();
    caps = corr_caps_default();
    caps.max_distinct = 8;
    e = corr_engine_new(&rv, 1, caps);
    for (int i = 0; i < 1000; i++) {
        char user[16];
        snprintf(user, sizeof(user), "user%d", i);
        feed(e, "203.0.113.9", user, BASE_1, 1, 100.0, NULL);
    }
    corr_engine_stats(e, &st);
    CHECK(st.distinct_evicted > 0, "counter: distinct.evicted increments under distinct-set cap");
    corr_engine_free(e);

    /* events.overwritten: huge threshold, ring=16, 1000 events into one group. */
    corr_rule_t re = mk_event_count();
    re.cond_count = 1000000;
    caps = corr_caps_default();
    caps.max_events_per_group = 16;
    e = corr_engine_new(&re, 1, caps);
    for (int i = 0; i < 1000; i++) feed(e, "203.0.113.9", "root", BASE_1, 1, 100.0, NULL);
    corr_engine_stats(e, &st);
    CHECK(st.events_overwritten > 0, "counter: events.overwritten increments when the ring is full");
    corr_engine_free(e);

    /* fires.suppressed: cross the threshold, then keep feeding within the window.
     * mk_event_count fires at 10 (timespan 300); events 11+ at ts inside the lit
     * window are suppressed. */
    corr_rule_t rs = mk_event_count();
    e = corr_engine_new(&rs, 1, corr_caps_default());
    int fires_seen = 0;
    for (int i = 0; i < 20; i++) fires_seen += feed(e, "198.51.100.7", "victim", BASE_1, 1, 100.0 + i, NULL);
    corr_engine_stats(e, &st);
    CHECK(fires_seen == 1, "counter setup: exactly one fire before suppression");
    CHECK(st.fires_suppressed > 0, "counter: fires.suppressed increments inside the lit window");
    corr_engine_free(e);

    /* rules.rejected: three malformed rules at admit time. */
    corr_rule_t bad[4];
    bad[0] = mk_event_count();
    bad[1] = mk_event_count();
    bad[1].id = NULL;
    bad[2] = mk_event_count();
    bad[2].timespan_s = 0;
    bad[3] = mk_value_count();
    bad[3].value_field = NULL;
    e = corr_engine_new(bad, 4, corr_caps_default());
    corr_engine_stats(e, &st);
    CHECK(st.rules_rejected == 3, "counter: rules.rejected == 3 malformed at admit");
    corr_engine_free(e);

    /* event.skipped_missing_field: group_by needs user.name; feed without it. */
    corr_rule_t rm = mk_event_count(); /* group_by = source.ip + user.name */
    e = corr_engine_new(&rm, 1, corr_caps_default());
    for (int i = 0; i < 5; i++) feed(e, "192.0.2.1", NULL, BASE_1, 1, 100.0, NULL);
    corr_engine_stats(e, &st);
    CHECK(st.event_skipped_missing_field > 0,
          "counter: event.skipped_missing_field increments when a group-by field is absent");
    corr_engine_free(e);
}

/* ===========================================================================
 * tier_for_correlation (mirror TestTierForCorrelation)
 * ========================================================================= */
static void test_tier(void) {
    CHECK(corr_tier_for(CORR_TEMPORAL, "low") == CORR_TIER_STRONG, "tier: temporal is STRONG regardless of level");
    CHECK(corr_tier_for(CORR_TEMPORAL_ORDERED, "informational") == CORR_TIER_STRONG,
          "tier: temporal_ordered is STRONG");
    CHECK(corr_tier_for(CORR_EVENT_COUNT, "high") == CORR_TIER_STRONG, "tier: event_count high => STRONG");
    CHECK(corr_tier_for(CORR_EVENT_COUNT, "critical") == CORR_TIER_STRONG, "tier: event_count critical => STRONG");
    CHECK(corr_tier_for(CORR_EVENT_COUNT, "low") == CORR_TIER_WEAK, "tier: event_count low => WEAK");
    CHECK(corr_tier_for(CORR_VALUE_COUNT, "medium") == CORR_TIER_WEAK, "tier: value_count medium => WEAK");
    CHECK(corr_tier_for(CORR_EVENT_COUNT, NULL) == CORR_TIER_WEAK, "tier: NULL level defaults to medium => WEAK");
    /* NEVER CONTEXT: the only two outcomes are WEAK/STRONG; weights match. */
    CHECK(corr_tier_weight(CORR_TIER_STRONG) == 0.6, "tier weight STRONG=0.6");
    CHECK(corr_tier_weight(CORR_TIER_WEAK) == 0.3, "tier weight WEAK=0.3");
}

/* ===========================================================================
 * loader-skip parity: malformed rules are skipped, never fatal.
 * ========================================================================= */
static void test_load_skips_malformed(void) {
    corr_rule_t rules[4];
    rules[0] = mk_event_count(); /* valid */
    rules[1] = mk_event_count();
    rules[1].id = NULL; /* invalid: no id */
    rules[2] = mk_event_count();
    rules[2].timespan_s = 0; /* invalid: non-positive window */
    rules[3] = mk_value_count();
    rules[3].value_field = NULL; /* invalid: value_count w/o field */
    corr_engine_t* e = corr_engine_new(rules, 4, corr_caps_default());
    assert(e);
    CHECK(corr_engine_rule_count(e) == 1, "loader: 3 malformed skipped, 1 admitted");
    corr_engine_free(e);

    /* empty engine: feed is a no-op. */
    e = corr_engine_new(NULL, 0, corr_caps_default());
    assert(e);
    CHECK(feed(e, "203.0.113.9", "root", BASE_1, 1, 100.0, NULL) == 0, "empty engine: feed is a no-op");
    corr_engine_free(e);
}

/* ===========================================================================
 * no-group (global) correlation: group key () collapses to one group.
 * ========================================================================= */
static void test_no_group(void) {
    corr_rule_t r = mk_event_count();
    r.group_by = NULL;
    r.n_group_by = 0;
    r.cond_count = 3;
    corr_engine_t* e = corr_engine_new(&r, 1, corr_caps_default());
    CHECK(feed(e, "a", "x", BASE_1, 1, 100.0, NULL) == 0, "no-group: 1");
    CHECK(feed(e, "b", "y", BASE_1, 1, 100.0, NULL) == 0, "no-group: 2 (same global group)");
    int nf = feed(e, "c", "z", BASE_1, 1, 100.0, NULL);
    CHECK(nf == 1, "no-group: all events share group () => fires at 3");
    CHECK(corr_engine_total_groups(e) == 1, "no-group: exactly one global group");
    corr_engine_free(e);
}

/* ---- F3: value_sum / value_avg -------------------------------------------- */
static int feed_num(
    corr_engine_t* e, const char* ip, const char* field, const char* numstr, double ts, corr_fire_t* out_first) {
    kv_t kv[2];
    size_t n = 0;
    kv[n].k = "source.ip";
    kv[n].v = ip;
    n++;
    kv[n].k = field;
    kv[n].v = numstr;
    n++;
    event_t ev = {kv, n};
    corr_fire_t fires[8];
    static const char* scratch[8 * CORR_MAX_GROUP_FIELDS];
    int nf = corr_on_event(e, BASE_1, 1, ev_field, &ev, ts, fires, 8, scratch, sizeof(scratch) / sizeof(scratch[0]));
    if (nf > 0 && out_first) *out_first = fires[0];
    return nf;
}

static corr_rule_t mk_value_sum(void) {
    corr_rule_t r;
    memset(&r, 0, sizeof(r));
    r.id = "exfil";
    r.title = "Bulk egress";
    r.type = CORR_VALUE_SUM;
    r.base_rule_ids = BASE_1;
    r.n_base_rule_ids = 1;
    r.group_by = GB_IP;
    r.n_group_by = 1;
    r.value_field = "destination.bytes";
    r.cond_op = CORR_OP_GTE;
    r.cond_count = 1000;
    r.timespan_s = 600;
    r.level = "high";
    r.mitre = "T1048";
    return r;
}

static corr_rule_t mk_value_avg(void) {
    corr_rule_t r;
    memset(&r, 0, sizeof(r));
    r.id = "bigreq";
    r.title = "Large avg request";
    r.type = CORR_VALUE_AVG;
    r.base_rule_ids = BASE_1;
    r.n_base_rule_ids = 1;
    r.group_by = GB_IP;
    r.n_group_by = 1;
    r.value_field = "http.request.bytes";
    r.cond_op = CORR_OP_GTE;
    r.cond_count = 500;
    r.timespan_s = 600;
    r.level = "medium";
    r.mitre = NULL;
    return r;
}

static void test_value_sum(void) {
    corr_rule_t r = mk_value_sum();
    corr_engine_t* e = corr_engine_new(&r, 1, corr_caps_default());
    CHECK(e != NULL, "value_sum: engine");
    corr_fire_t f;
    memset(&f, 0, sizeof(f));
    /* 3 x 300 = 900 (< 1000): no fire. */
    CHECK(feed_num(e, "10.0.0.1", "destination.bytes", "300", 100.0, NULL) == 0, "value_sum: 300 no fire");
    CHECK(feed_num(e, "10.0.0.1", "destination.bytes", "300", 101.0, NULL) == 0, "value_sum: 600 no fire");
    CHECK(feed_num(e, "10.0.0.1", "destination.bytes", "300", 102.0, NULL) == 0, "value_sum: 900 no fire");
    /* non-numeric: skipped (not zero), sum stays 900, still no fire. */
    CHECK(feed_num(e, "10.0.0.1", "destination.bytes", "N/A", 103.0, NULL) == 0, "value_sum: non-numeric skipped");
    /* +300 -> 1200 >= 1000: FIRE.  Trailing junk tolerated ("300/tcp" -> 300). */
    int nf = feed_num(e, "10.0.0.1", "destination.bytes", "300/tcp", 104.0, &f);
    CHECK(nf == 1, "value_sum: fires when sum crosses threshold");
    CHECK(f.observed == 1200, "value_sum: observed==1200 (sum)");
    CHECK(f.rule_id && strcmp(f.rule_id, "exfil") == 0, "value_sum: rule_id=exfil");
    /* a different source.ip is a different group: its own sum starts at 0. */
    CHECK(feed_num(e, "10.0.0.2", "destination.bytes", "300", 105.0, NULL) == 0, "value_sum: per-group isolation");
    corr_stats_t st;
    corr_engine_stats(e, &st);
    CHECK(st.values_nonnumeric == 1, "value_sum: values_nonnumeric counted");
    corr_engine_free(e);
}

static void test_value_avg(void) {
    corr_rule_t r = mk_value_avg();
    corr_engine_t* e = corr_engine_new(&r, 1, corr_caps_default());
    CHECK(e != NULL, "value_avg: engine");
    corr_fire_t f;
    memset(&f, 0, sizeof(f));
    /* avg of {400} = 400 (< 500): no fire (empty window also never fires). */
    CHECK(feed_num(e, "10.0.0.9", "http.request.bytes", "400", 200.0, NULL) == 0, "value_avg: 400 no fire");
    /* avg of {400,600} = 500 (>= 500): FIRE. */
    int nf = feed_num(e, "10.0.0.9", "http.request.bytes", "600", 201.0, &f);
    CHECK(nf == 1, "value_avg: fires when avg crosses threshold");
    CHECK(f.observed == 500, "value_avg: observed==500 (avg)");
    corr_engine_free(e);
}

/* ---- F2: SEP #198 boolean temporal conditions ----------------------------- */
static const uint32_t BASE_ABC[] = {10, 20, 30};
static const uint32_t R10[] = {10}, R20[] = {20}, R30[] = {30};
/* (A AND B) AND (NOT C) in postfix: SEL0 SEL1 AND SEL2 NOT AND. */
static const corr_ctok_t COND_A_B_NOTC[] = {
    {.kind = CORR_C_SEL, .rid_idx = 0},
    {.kind = CORR_C_SEL, .rid_idx = 1},
    {.kind = CORR_C_AND},
    {.kind = CORR_C_SEL, .rid_idx = 2},
    {.kind = CORR_C_NOT},
    {.kind = CORR_C_AND},
};

static corr_rule_t mk_temporal_cond(void) {
    corr_rule_t r;
    memset(&r, 0, sizeof(r));
    r.id = "multi";
    r.title = "A and B and not C";
    r.type = CORR_TEMPORAL;
    r.base_rule_ids = BASE_ABC;
    r.n_base_rule_ids = 3;
    r.group_by = GB_IP;
    r.n_group_by = 1;
    r.cond_count = 3;
    r.timespan_s = 600;
    r.level = "high";
    r.mitre = "T1000";
    r.cond = COND_A_B_NOTC;
    r.n_cond = sizeof(COND_A_B_NOTC) / sizeof(COND_A_B_NOTC[0]);
    return r;
}

static void test_temporal_condition(void) {
    corr_rule_t r = mk_temporal_cond();
    corr_engine_t* e = corr_engine_new(&r, 1, corr_caps_default());
    CHECK(e != NULL, "temporal_cond: engine");
    corr_fire_t f;
    memset(&f, 0, sizeof(f));
    /* group X: A then B, C absent -> (A and B and not C) FIRES. */
    CHECK(feed(e, "X", NULL, R10, 1, 100.0, NULL) == 0, "temporal_cond: A alone no fire");
    int nf = feed(e, "X", NULL, R20, 1, 101.0, &f);
    CHECK(nf == 1, "temporal_cond: A and B (no C) fires");
    CHECK(f.rule_id && strcmp(f.rule_id, "multi") == 0, "temporal_cond: rule_id");
    /* group Y: C first, then A, then B -> `not C` is false, must NOT fire. */
    CHECK(feed(e, "Y", NULL, R30, 1, 200.0, NULL) == 0, "temporal_cond: C alone no fire");
    CHECK(feed(e, "Y", NULL, R10, 1, 201.0, NULL) == 0, "temporal_cond: C then A no fire");
    CHECK(feed(e, "Y", NULL, R20, 1, 202.0, NULL) == 0, "temporal_cond: A and B but C present -> no fire");
    corr_engine_free(e);
}

/* ----------------------------------------------------------------------------
 * beaconing: periodic arrivals of a base rule on a group fire when the
 * inter-arrival coefficient of variation is within tolerance.
 * ------------------------------------------------------------------------- */
static corr_rule_t mk_beaconing(void) {
    corr_rule_t r;
    memset(&r, 0, sizeof(r));
    r.id = "beacon";
    r.title = "Periodic C2 beacon";
    r.type = CORR_BEACONING;
    r.base_rule_ids = BASE_1;
    r.n_base_rule_ids = 1;
    r.group_by = GB_IP;
    r.n_group_by = 1;
    r.cond_op = CORR_OP_GTE;
    r.cond_count = 6; /* >= 6 events in-window */
    r.beacon_cv_permille = 200; /* CV <= 0.20 */
    r.timespan_s = 3600;
    r.level = "high";
    r.mitre = "T1071.001";
    return r;
}

static void test_beaconing(void) {
    /* perfect 60s cadence: builds up, fires exactly when the 6th event lands. */
    {
        corr_rule_t r = mk_beaconing();
        corr_engine_t* e = corr_engine_new(&r, 1, corr_caps_default());
        int fired = 0;
        double ts[] = {100, 160, 220, 280, 340, 400};
        for (int i = 0; i < 6; i++) fired += feed(e, "10.0.0.9", NULL, BASE_1, 1, ts[i], NULL);
        CHECK(fired == 1, "beaconing: perfect cadence fires once at the 6th event");
        corr_engine_free(e);
    }
    /* real beacon with mild jitter (~60s +/- a few): still within tolerance. */
    {
        corr_rule_t r = mk_beaconing();
        corr_engine_t* e = corr_engine_new(&r, 1, corr_caps_default());
        int fired = 0;
        double ts[] = {100, 158, 222, 279, 341, 402};
        for (int i = 0; i < 6; i++) fired += feed(e, "10.0.0.9", NULL, BASE_1, 1, ts[i], NULL);
        CHECK(fired >= 1, "beaconing: jittered-but-regular beacon still fires");
        corr_engine_free(e);
    }
    /* wildly irregular arrivals: high gap-CV, must NEVER fire. */
    {
        corr_rule_t r = mk_beaconing();
        corr_engine_t* e = corr_engine_new(&r, 1, corr_caps_default());
        int fired = 0;
        double ts[] = {100, 130, 400, 410, 900, 1500};
        for (int i = 0; i < 6; i++) fired += feed(e, "10.0.0.9", NULL, BASE_1, 1, ts[i], NULL);
        CHECK(fired == 0, "beaconing: irregular timing does not fire");
        corr_engine_free(e);
    }
    /* regular cadence but below the min-event count: no fire. */
    {
        corr_rule_t r = mk_beaconing();
        corr_engine_t* e = corr_engine_new(&r, 1, corr_caps_default());
        int fired = 0;
        double ts[] = {100, 160, 220, 280, 340};
        for (int i = 0; i < 5; i++) fired += feed(e, "10.0.0.9", NULL, BASE_1, 1, ts[i], NULL);
        CHECK(fired == 0, "beaconing: below min event count does not fire");
        corr_engine_free(e);
    }
    /* a rule with cv_permille=0 or count<3 must be rejected by the loader/engine. */
    {
        corr_rule_t r = mk_beaconing();
        r.beacon_cv_permille = 0;
        corr_engine_t* e = corr_engine_new(&r, 1, corr_caps_default());
        /* invalid rule is skipped -> no group ever fires. */
        int fired = 0;
        double ts[] = {100, 160, 220, 280, 340, 400};
        for (int i = 0; i < 6; i++) fired += feed(e, "10.0.0.9", NULL, BASE_1, 1, ts[i], NULL);
        CHECK(fired == 0, "beaconing: cv_permille=0 rule is rejected");
        corr_engine_free(e);
    }
}

/* bucketed (long-horizon) beaconing: activity-histogram mode with a presence gate. */
static corr_rule_t mk_beaconing_bucketed(void) {
    corr_rule_t r;
    memset(&r, 0, sizeof(r));
    r.id = "beacon-slow";
    r.title = "Low-and-slow beacon";
    r.type = CORR_BEACONING;
    r.base_rule_ids = BASE_1;
    r.n_base_rule_ids = 1;
    r.group_by = GB_IP;
    r.n_group_by = 1;
    r.cond_op = CORR_OP_GTE;
    r.cond_count = 6; /* >= 6 active buckets */
    r.beacon_cv_permille = 200; /* gap-CV <= 0.20 */
    r.beacon_n_buckets = 24; /* 1-day window, hourly buckets (bucket_secs=3600) */
    r.timespan_s = 86400;
    r.level = "high";
    r.mitre = "T1071.001";
    return r;
}

static void test_beaconing_bucketed(void) {
    const double H = 3600.0, base = 1000000.0;
    /* regular hourly beacon: fires when the 6th hourly bucket goes active. */
    {
        corr_rule_t r = mk_beaconing_bucketed();
        corr_engine_t* e = corr_engine_new(&r, 1, corr_caps_default());
        int fired = 0;
        for (int k = 0; k < 6; k++) fired += feed(e, "10.0.0.9", NULL, BASE_1, 1, base + k * H + 5.0, NULL);
        CHECK(fired == 1, "beaconing/bucketed: regular hourly beacon fires");
        corr_engine_free(e);
    }
    /* two events in the SAME hour collapse to one active bucket: still 6 buckets. */
    {
        corr_rule_t r = mk_beaconing_bucketed();
        corr_engine_t* e = corr_engine_new(&r, 1, corr_caps_default());
        int fired = 0;
        for (int k = 0; k < 6; k++) {
            fired += feed(e, "10.0.0.9", NULL, BASE_1, 1, base + k * H + 100.0, NULL);
            fired += feed(e, "10.0.0.9", NULL, BASE_1, 1, base + k * H + 200.0, NULL);
        }
        CHECK(fired == 1, "beaconing/bucketed: two events/bucket = one active bucket");
        corr_engine_free(e);
    }
    /* irregular bucket cadence: high gap-CV / low presence -> no fire. */
    {
        corr_rule_t r = mk_beaconing_bucketed();
        corr_engine_t* e = corr_engine_new(&r, 1, corr_caps_default());
        int fired = 0;
        double hrs[] = {0, 1, 8, 9, 20, 21};
        for (int k = 0; k < 6; k++) fired += feed(e, "10.0.0.9", NULL, BASE_1, 1, base + hrs[k] * H + 5.0, NULL);
        CHECK(fired == 0, "beaconing/bucketed: irregular cadence does not fire");
        corr_engine_free(e);
    }
    /* regular but SPARSE (every 3rd hour): presence 6/16 < 0.7 -> no fire. */
    {
        corr_rule_t r = mk_beaconing_bucketed();
        corr_engine_t* e = corr_engine_new(&r, 1, corr_caps_default());
        int fired = 0;
        for (int k = 0; k < 6; k++) fired += feed(e, "10.0.0.9", NULL, BASE_1, 1, base + (k * 3) * H + 5.0, NULL);
        CHECK(fired == 0, "beaconing/bucketed: regular-but-sparse fails the presence gate");
        corr_engine_free(e);
    }
    /* invalid: bucket_secs < 1 (timespan < n_buckets) -> rule rejected, never fires. */
    {
        corr_rule_t r = mk_beaconing_bucketed();
        r.beacon_n_buckets = 100000; /* > CORR_BEACON_MAX_BUCKETS and > timespan */
        corr_engine_t* e = corr_engine_new(&r, 1, corr_caps_default());
        int fired = 0;
        for (int k = 0; k < 6; k++) fired += feed(e, "10.0.0.9", NULL, BASE_1, 1, base + k * H + 5.0, NULL);
        CHECK(fired == 0, "beaconing/bucketed: out-of-range n_buckets rejected");
        corr_engine_free(e);
    }
}

static corr_rule_t mk_value_percentile(void) {
    corr_rule_t r;
    memset(&r, 0, sizeof(r));
    r.id = "p95";
    r.title = "P95 bytes";
    r.type = CORR_VALUE_PERCENTILE;
    r.base_rule_ids = BASE_1;
    r.n_base_rule_ids = 1;
    r.group_by = GB_IP;
    r.n_group_by = 1;
    r.value_field = "destination.bytes";
    r.cond_op = CORR_OP_GTE;
    r.cond_count = 80;
    r.value_percentile = 80;
    r.timespan_s = 60;
    r.level = "high";
    return r;
}

static void test_value_percentile(void) {
    corr_rule_t r = mk_value_percentile();
    corr_engine_t* e = corr_engine_new(&r, 1, corr_caps_default());
    CHECK(e != NULL, "percentile: engine");
    /* 10,20,30: P80 of 3 = rank ceil(2.4)=3 -> 30, under 80. Then 100: P80 of 4 =
     * rank ceil(3.2)=4 -> 100, fires. */
    CHECK(feed_num(e, "10.0.0.1", "destination.bytes", "10", 10.0, NULL) == 0, "percentile: 10");
    CHECK(feed_num(e, "10.0.0.1", "destination.bytes", "20", 11.0, NULL) == 0, "percentile: 20");
    CHECK(feed_num(e, "10.0.0.1", "destination.bytes", "30", 12.0, NULL) == 0, "percentile: 30");
    corr_fire_t f;
    memset(&f, 0, sizeof(f));
    int nf = feed_num(e, "10.0.0.1", "destination.bytes", "100", 13.0, &f);
    CHECK(nf == 1, "percentile: P80 crosses 80 when 100 is in");
    CHECK(f.observed == 100, "percentile: observed is P80 value 100");
    corr_engine_free(e);
}

static corr_rule_t mk_value_median(void) {
    corr_rule_t r = mk_value_percentile();
    r.id = "median";
    r.title = "median bytes";
    r.type = CORR_VALUE_MEDIAN;
    r.cond_count = 20;
    r.value_percentile = 0; /* ignored: CORR_VALUE_MEDIAN forces P_50 */
    return r;
}

static void test_value_median(void) {
    corr_rule_t r = mk_value_median();
    corr_engine_t* e = corr_engine_new(&r, 1, corr_caps_default());
    CHECK(e != NULL, "median: engine");
    /* nearest-rank P50 of n=2 (10,20): idx=0 -> 10, under 20.
     * n=3 (10,20,30): idx=1 -> 20, GTE 20 fires. */
    CHECK(feed_num(e, "10.0.0.1", "destination.bytes", "10", 10.0, NULL) == 0, "median: 10");
    CHECK(feed_num(e, "10.0.0.1", "destination.bytes", "20", 11.0, NULL) == 0, "median: 20");
    corr_fire_t f;
    memset(&f, 0, sizeof(f));
    int nf = feed_num(e, "10.0.0.1", "destination.bytes", "30", 12.0, &f);
    CHECK(nf == 1, "median: P50 crosses 20 when 30 is in");
    CHECK(f.observed == 20, "median: observed is P50 value 20");
    corr_engine_free(e);
}

static void test_contrib_merge_count(void) {
    corr_rule_t r = mk_event_count();
    r.cond_count = 5;
    corr_engine_t* e = corr_engine_new(&r, 1, corr_caps_default());
    CHECK(e != NULL, "contrib: engine");
    const char* gvals[] = {"203.0.113.9", "root"};
    corr_contrib_t c;
    memset(&c, 0, sizeof(c));
    c.kind = CORR_CONTRIB_COUNT;
    c.corr_id = "brute";
    c.group_vals = gvals;
    c.n_group = 2;
    c.ts = 100.0;
    c.count = 5;
    corr_fire_t fires[4];
    static const char* scratch[8 * CORR_MAX_GROUP_FIELDS];
    int nf = corr_on_contribution(e, &c, ev_field, NULL, fires, 4, scratch, 32);
    CHECK(nf == 1, "contrib COUNT: merge of 5 fires event_count threshold 5");
    CHECK(fires[0].observed == 5, "contrib COUNT: observed==5");
    CHECK(fires[0].remote == 1, "contrib COUNT: remote flag set");
    corr_engine_free(e);
}

static int apply_never(void* ctx, const corr_rule_t* r, const char* const* g, size_t n) {
    (void)ctx;
    (void)r;
    (void)g;
    (void)n;
    return 0;
}

static void test_apply_skip_and_owner(void) {
    corr_rule_t r = mk_event_count();
    r.cond_count = 1;
    corr_engine_t* e = corr_engine_new(&r, 1, corr_caps_default());
    CHECK(e != NULL, "apply: engine");
    kv_t kv[2] = {{"source.ip", "203.0.113.9"}, {"user.name", "root"}};
    event_t ev = {kv, 2};
    static const char* scratch[8 * CORR_MAX_GROUP_FIELDS];
    corr_fire_t fires[4];
    int nf = corr_on_event_apply(e, BASE_1, 1, ev_field, &ev, 100.0, fires, 4, scratch, 32, apply_never, NULL);
    CHECK(nf == 0, "apply: skip means no local fire");
    nf = corr_on_event(e, BASE_1, 1, ev_field, &ev, 100.0, fires, 4, scratch, 32);
    CHECK(nf == 1, "apply: unfiltered still fires");
    CHECK(fires[0].remote == 0, "apply: local fire is not remote");
    corr_engine_free(e);

    const char* g1[] = {"10.0.0.1", "root"};
    CHECK(corr_owner_index("brute", g1, 2, 0) == 0, "owner: n_peers 0 -> 0");
    CHECK(corr_owner_index("brute", g1, 2, 1) == 0, "owner: n_peers 1 -> 0");
    size_t a = corr_owner_index("brute", g1, 2, 7);
    size_t b = corr_owner_index("brute", g1, 2, 7);
    CHECK(a == b && a < 7, "owner: stable and in range");
    const char* g2[] = {"10.0.0.2", "root"};
    /* different group may or may not collide; just check in range */
    CHECK(corr_owner_index("brute", g2, 2, 7) < 7, "owner: other group in range");
    /* Ingest contract (one owner per group): a group has exactly one owner
     * in a static ring. Non-owners drop the contrib. */
    {
        size_t n_own = 0;
        size_t pi;
        for (pi = 0; pi < 4; pi++) {
            if (corr_owner_index("brute", g1, 2, 4) == pi) n_own++;
        }
        CHECK(n_own == 1, "ingest-owner: exactly one peer owns a group");
    }
    CHECK(corr_contrib_kind_for(CORR_EVENT_COUNT) == (int)CORR_CONTRIB_COUNT, "kind: count");
    CHECK(corr_contrib_kind_for(CORR_TEMPORAL_ORDERED) == -1, "kind: ordered local-only");
    CHECK(corr_rule_hits(&r, BASE_1, 1) == 1, "hits: base rid");
}

static void test_watermark_reorder(void) {
    corr_rule_t r = mk_temporal_ordered();
    corr_caps_t caps = corr_caps_default();
    caps.event_time_ordering = 1;
    caps.watermark_s = 2.0;
    corr_engine_t* e = corr_engine_new(&r, 1, caps);
    CHECK(e != NULL, "watermark: engine");
    /* B (rid 2) at event-time 101 arrives first; A (rid 1) at 100 arrives later.
     * Without watermark, greedy event-time mode rejects A as fabrication.
     * With 2s slack, both sit until high-water 101, cutoff 99, both flush in
     * order 100 then 101 once a later event at 103 raises the mark... actually
     * after inserting A, max is 101, cutoff 99, both 100 and 101 <= 99? No.
     * After A (now=100), max stays 101, cutoff=99, 100>99 so A stays, B stays.
     * Need an event at >= 103 to flush. Use a third hit of rid 1 at 103. */
    CHECK(feed(e, "10.0.0.1", NULL, BASE_12 + 1, 1, 101.0, NULL) == 0, "watermark: B first, buffered, no fire");
    CHECK(feed(e, "10.0.0.1", NULL, BASE_12, 1, 100.0, NULL) == 0, "watermark: A late, buffered, no fire yet");
    corr_fire_t f;
    memset(&f, 0, sizeof(f));
    /* a later event raises high water so cutoff passes 101 */
    int nf = feed(e, "10.0.0.1", NULL, BASE_12, 1, 104.0, &f);
    CHECK(nf == 1, "watermark: A then B replayed in event-time order fires");
    corr_engine_free(e);
}

static void test_group_by_aliases(void) {
    /* Two base rules, same group slot, different field names. Events that
     * only carry the aliased field must still land in one group. */
    static const uint32_t BASE[] = {1, 2};
    static const char* GB[] = {"user.name"};
    static const char* ALIAS1[] = {"user.target.name"};
    static const char* ALIAS2[] = {"user.name"};
    static const char* const* ALIASES[] = {ALIAS1, ALIAS2};

    corr_rule_t r;
    memset(&r, 0, sizeof(r));
    r.id = "alias";
    r.type = CORR_EVENT_COUNT;
    r.base_rule_ids = BASE;
    r.n_base_rule_ids = 2;
    r.group_by = GB;
    r.n_group_by = 1;
    r.alias_group_by = ALIASES;
    r.n_alias_group_by = 2;
    r.cond_op = CORR_OP_GTE;
    r.cond_count = 2;
    r.timespan_s = 300;
    r.level = "high";

    corr_engine_t* e = corr_engine_new(&r, 1, corr_caps_default());
    kv_t kv1[] = {{"user.target.name", "alice"}};
    event_t ev1 = {kv1, 1};
    uint32_t rid1[] = {1};
    static const char* scratch[8];
    CHECK(corr_on_event(e, rid1, 1, ev_field, &ev1, 100.0, NULL, 0, scratch, 8) == 0,
          "alias: first base-rule event does not fire");

    kv_t kv2[] = {{"user.name", "alice"}};
    event_t ev2 = {kv2, 1};
    uint32_t rid2[] = {2};
    corr_fire_t f;
    memset(&f, 0, sizeof(f));
    int nf = corr_on_event(e, rid2, 1, ev_field, &ev2, 101.0, &f, 1, scratch, 8);
    CHECK(nf == 1, "alias: second base-rule event joins the same group and fires");
    corr_engine_free(e);

    /* Without aliases the first event has no user.name and is skipped. */
    corr_rule_t r2;
    memset(&r2, 0, sizeof(r2));
    r2.id = "noalias";
    r2.type = CORR_EVENT_COUNT;
    r2.base_rule_ids = BASE;
    r2.n_base_rule_ids = 2;
    r2.group_by = GB;
    r2.n_group_by = 1;
    r2.cond_op = CORR_OP_GTE;
    r2.cond_count = 2;
    r2.timespan_s = 300;
    e = corr_engine_new(&r2, 1, corr_caps_default());
    CHECK(corr_on_event(e, rid1, 1, ev_field, &ev1, 100.0, NULL, 0, scratch, 8) == 0,
          "no-alias: missing canonical field skips");
    corr_stats_t st;
    corr_engine_stats(e, &st);
    CHECK(st.event_skipped_missing_field > 0, "no-alias: skipped_missing_field increments");
    corr_engine_free(e);
}

int main(void) {
    test_event_count();
    test_value_count();
    test_value_sum();
    test_value_avg();
    test_value_percentile();
    test_value_median();
    test_contrib_merge_count();
    test_apply_skip_and_owner();
    test_watermark_reorder();
    test_temporal_condition();
    test_temporal();
    test_temporal_ordered();
    test_temporal_ordered_event_time();
    test_window_expiry();
    test_refire_suppression();
    test_bounded_eviction();
    test_boundary_counters();
    test_tier();
    test_load_skips_malformed();
    test_no_group();
    test_beaconing();
    test_beaconing_bucketed();
    test_group_by_aliases();

    printf("\nlibsigma correlation engine: %d passed, %d failed\n", g_pass, g_fail);
    if (g_fail == 0) printf("PASSED %d/%d\n", g_pass, g_pass);
    return g_fail ? 1 : 0;
}
