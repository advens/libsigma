/* classify_corr.c
 * Implementation of the warm-path Sigma correlation engine, a dep-free
 * implementation.  See classify_corr.h for the contract.
 *
 * Design notes (design notes):
 *   - Per correlation: a bounded LRU map of group-key tuple -> group state.
 *     The LRU is an intrusive doubly-linked list threaded through the hash
 *     buckets (O(1) touch / evict), matching an
 *     popitem(last=False).
 *   - event_count: a per-group ring of monotonic timestamps; prune < window_start
 *     on every touch; fire when |events| satisfies the condition.
 *   - value_count: a per-group LRU map of distinct value -> latest ts; expire
 *     entries < window_start; cap the set at max_distinct (evict oldest); fire
 *     when |distinct| satisfies the condition.
 *   - temporal: per-base-rid latest in-window ts; fire when ALL base rids are
 *     present (any order).
 *   - temporal_ordered: a running progress index + the anchor ts of step 0;
 *     reset when the anchor ages out; advance greedily through consecutive
 *     expected steps an event satisfies; fire (and reset progress) at the end.
 *   - re-fire suppression: stay "lit" for one full window after a fire.
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

#include <pthread.h>
#include <stdlib.h>
#include <string.h>
#include <math.h> /* isfinite for value_sum/avg numeric parse */

/* Concurrency: the engine is safe for concurrent corr_on_event from
 * multiple caller threads.  Each correlation's group map is guarded by its own
 * corr_state_t.lock (workers on different correlations run in parallel); the
 * periodic sweep runs single-flight under sweep_lock.  The shared boundary
 * counters are not covered by any single per-state lock, so every tally is a
 * relaxed atomic add and every snapshot a relaxed atomic load.  corr_stats_t
 * stays a plain struct: the atomicity is in the access, not the type, so its
 * ABI is unchanged. */
#define CS_INC(sp, field) __atomic_fetch_add(&(sp)->field, 1u, __ATOMIC_RELAXED)

/* _REFIRE_SUPPRESS_FRACTION = 1.0 (one full window after a fire). */
#define CORR_REFIRE_FRACTION 1.0

#define CORR_DEFAULT_MAX_GROUPS 50000u
#define CORR_DEFAULT_MAX_DISTINCT 10000u
#define CORR_DEFAULT_MAX_EVENTS_PER_GROUP 4096u
#define CORR_DEFAULT_SWEEP_INTERVAL_S 30.0
/* beaconing bucketed-mode ceiling: bounds the per-group histogram (nb * 8 bytes)
 * and the per-event window scan (nb iterations). 1024 covers 7 days at ~10-min
 * buckets; the warm detector uses 168 (7 days hourly). */
#define CORR_BEACON_MAX_BUCKETS 1024
#define CORR_WM_CAP 32 /* temporal_ordered pending events under watermark slack */

/* ============================================================================
 * tier_for_correlation + tier helpers
 * ========================================================================== */
const char* corr_tier_name(corr_tier_t t) {
    return (t == CORR_TIER_STRONG) ? "strong" : "weak";
}

double corr_tier_weight(corr_tier_t t) {
    /* activation weights. */
    return (t == CORR_TIER_STRONG) ? 0.6 : 0.3;
}

static int str_ieq(const char* a, const char* b) {
    /* ASCII case-insensitive equality (level strings are ASCII tokens). */
    while (*a && *b) {
        unsigned char ca = (unsigned char)*a, cb = (unsigned char)*b;
        if (ca >= 'A' && ca <= 'Z') ca = (unsigned char)(ca - 'A' + 'a');
        if (cb >= 'A' && cb <= 'Z') cb = (unsigned char)(cb - 'A' + 'a');
        if (ca != cb) return 0;
        a++;
        b++;
    }
    return *a == '\0' && *b == '\0';
}

corr_tier_t corr_tier_for(corr_type_t type, const char* level) {
    if (type == CORR_TEMPORAL || type == CORR_TEMPORAL_ORDERED || type == CORR_BEACONING)
        return CORR_TIER_STRONG; /* a periodic pattern is a strong temporal signal */
    /* event_count / value_count: STRONG iff level high|critical, else WEAK. */
    const char* lvl = (level && *level) ? level : "medium";
    if (str_ieq(lvl, "high") || str_ieq(lvl, "critical")) return CORR_TIER_STRONG;
    return CORR_TIER_WEAK;
}

corr_caps_t corr_caps_default(void) {
    corr_caps_t c;
    c.max_groups = CORR_DEFAULT_MAX_GROUPS;
    c.max_distinct = CORR_DEFAULT_MAX_DISTINCT;
    c.max_events_per_group = CORR_DEFAULT_MAX_EVENTS_PER_GROUP;
    c.sweep_interval_s = CORR_DEFAULT_SWEEP_INTERVAL_S;
    c.event_time_ordering = 0;
    c.watermark_s = 0.0;
    return c;
}

/* ============================================================================
 * FNV-1a hash over a length-tagged byte run (group keys, distinct values).
 * ========================================================================== */
static uint64_t fnv1a(const void* data, size_t len) {
    const unsigned char* p = (const unsigned char*)data;
    uint64_t h = 1469598103934665603ULL;
    for (size_t i = 0; i < len; i++) {
        h ^= p[i];
        h *= 1099511628211ULL;
    }
    return h;
}

/* Hash a group-key tuple: each value's bytes + a separator (NUL byte) so that
 * ("ab","c") and ("a","bc") differ. NULL components are impossible here (a
 * missing group-by field makes the whole event skip the correlation). */
static uint64_t hash_group_key(const char* const* vals, size_t n) {
    uint64_t h = 1469598103934665603ULL;
    for (size_t i = 0; i < n; i++) {
        const char* v = vals[i];
        size_t len = strlen(v);
        for (size_t j = 0; j < len; j++) {
            h ^= (unsigned char)v[j];
            h *= 1099511628211ULL;
        }
        h ^= 0x00; /* component separator */
        h *= 1099511628211ULL;
    }
    return h;
}

static int group_key_eq(const char* const* a, const char* const* b, size_t n) {
    for (size_t i = 0; i < n; i++)
        if (strcmp(a[i], b[i]) != 0) return 0;
    return 1;
}

/* ============================================================================
 * Distinct-value LRU set (value_count).  Open-chained hash + intrusive LRU.
 * ========================================================================== */
typedef struct dval {
    char* val; /* owned copy */
    double ts; /* latest monotonic ts seen */
    uint64_t h;
    struct dval* hnext; /* hash chain */
    struct dval *lru_prev, *lru_next; /* LRU list (head = oldest, tail = newest) */
} dval_t;

typedef struct {
    dval_t** buckets;
    uint32_t n_buckets;
    uint32_t count;
    dval_t *lru_head, *lru_tail; /* head = LRU (oldest), tail = MRU */
} dset_t;

/* ============================================================================
 * Per-group sliding-window state (one group-key tuple of one correlation).
 * ========================================================================== */
#define CORR_MAX_SEEN_RULES 64 /* temporal: distinct base rids tracked / group */

typedef struct group group_t;

/* beaconing bucketed mode: one activity bucket. slot = bucket_index % n_buckets;
 * the slot holds `epoch` (that bucket index) and how many events landed in it.
 * A window of n_buckets consecutive epochs maps 1:1 onto the slots, so the most
 * recent n_buckets buckets never alias — a stale slot (epoch != the queried one)
 * simply reads as inactive. */
typedef struct {
    uint32_t epoch; /* bucket index = floor(ts / bucket_secs); 0 == never written */
    uint32_t count; /* events in this bucket (>= 1 once written) */
} beacon_bucket_t;

struct group {
    char** key; /* owned copies of the group-by VALUES (n_group_by) */
    size_t n_key;

    /* event_count: ring buffer of monotonic timestamps. */
    double* ev_ts; /* capacity = max_events_per_group */
    uint32_t ev_cap;
    uint32_t ev_head; /* index of oldest */
    uint32_t ev_len;

    /* beaconing (bucketed / long-horizon mode, rule.beacon_n_buckets > 0): a
     * compact activity histogram over the window, lazily allocated on the first
     * bucketed-beacon event so only those groups pay. */
    beacon_bucket_t* bbuckets;
    uint32_t bb_cap; /* == rule.beacon_n_buckets when allocated */

    /* value_sum / value_avg: numeric value_field per event, PARALLEL to ev_ts
     * (same head/len/cap indexing, so ev_prune / overwrite move it in lockstep).
     * Lazily allocated on the first sum/avg push, so only those groups pay. */
    double* ev_val;

    /* value_count distinct set. */
    dset_t distinct;

    /* temporal: per base rid latest in-window ts (parallel arrays). */
    uint32_t seen_rid[CORR_MAX_SEEN_RULES];
    double seen_ts[CORR_MAX_SEEN_RULES];
    uint32_t n_seen;

    /* temporal_ordered. */
    uint32_t ordered_progress;
    double ordered_anchor_ts;
    double ordered_last_ts; /* event time of the last advanced step (event-time mode) */

    double last_update;
    double fired_until; /* re-fire suppression deadline */

    /* Merge accumulators from CORR_CONTRIB_{COUNT,SUM,SEEN}. Additive with the
     * local ring / seen-set so a remote partial does not have to replay events. */
    double merge_sum;
    uint32_t merge_n;
    uint64_t merge_seen;
    uint8_t merge_remote; /* set when a remote COUNT/SUM/SEEN/DISTINCT merged */

    /* temporal_ordered watermark buffer (event-time slack). */
    struct {
        double ts;
        uint32_t rid;
    } wm[CORR_WM_CAP];
    uint32_t wm_n;
    double wm_max_ts;

    uint64_t h;
    group_t* hnext; /* hash chain */
    group_t *lru_prev, *lru_next; /* LRU list (head = LRU oldest) */
};

/* ============================================================================
 * Per-correlation bounded group map.
 * ========================================================================== */
typedef struct {
    const corr_rule_t* rule;
    group_t** buckets;
    uint32_t n_buckets;
    uint32_t count;
    group_t *lru_head, *lru_tail; /* head = LRU (least recently used) */
    pthread_mutex_t lock; /* guards this correlation's group map (concurrent workers) */
} corr_state_t;

/* Index entry: base rid -> list of correlation indices that watch it. */
typedef struct rid_watch {
    uint32_t rid;
    uint32_t* corr_idx; /* indices into engine->states */
    uint32_t n;
    uint32_t cap;
    struct rid_watch* next; /* hash chain */
} rid_watch_t;

struct corr_engine {
    corr_state_t* states;
    size_t n_states;

    corr_caps_t caps;
    double last_sweep;
    int sweep_seen; /* last_sweep initialised on first event */
    pthread_mutex_t sweep_lock; /* single-flight periodic sweep; guards last_sweep/sweep_seen */

    /* rid -> watching correlations index (hash table).  Read-only after
     * corr_engine_new, so it needs no lock on the hot path. */
    rid_watch_t** rid_buckets;
    uint32_t n_rid_buckets;

    /* Observable boundary counters (relaxed-atomic; see CS_INC). */
    corr_stats_t stats;

    /* Scratch for value_percentile / median (qsort copy of the live ring). */
    double* pct_scratch;
    uint32_t pct_scratch_cap;
};

/* ---- small helpers ----------------------------------------------------- */

static uint32_t next_pow2(uint32_t v) {
    if (v < 8) return 8;
    v--;
    v |= v >> 1;
    v |= v >> 2;
    v |= v >> 4;
    v |= v >> 8;
    v |= v >> 16;
    v++;
    return v;
}

/* ============================================================================
 * dset (distinct value LRU) operations.
 * ========================================================================== */
static int dset_init(dset_t* d) {
    d->n_buckets = 16;
    d->count = 0;
    d->lru_head = d->lru_tail = NULL;
    d->buckets = calloc(d->n_buckets, sizeof(*d->buckets));
    return d->buckets ? 0 : -1;
}

static void dset_unlink_lru(dset_t* d, dval_t* e) {
    if (e->lru_prev)
        e->lru_prev->lru_next = e->lru_next;
    else
        d->lru_head = e->lru_next;
    if (e->lru_next)
        e->lru_next->lru_prev = e->lru_prev;
    else
        d->lru_tail = e->lru_prev;
    e->lru_prev = e->lru_next = NULL;
}

static void dset_push_mru(dset_t* d, dval_t* e) {
    e->lru_prev = d->lru_tail;
    e->lru_next = NULL;
    if (d->lru_tail)
        d->lru_tail->lru_next = e;
    else
        d->lru_head = e;
    d->lru_tail = e;
}

static void dset_remove(dset_t* d, dval_t* e) {
    uint32_t b = (uint32_t)(e->h & (d->n_buckets - 1));
    dval_t** pp = &d->buckets[b];
    while (*pp && *pp != e) pp = &(*pp)->hnext;
    if (*pp) *pp = e->hnext;
    dset_unlink_lru(d, e);
    d->count--;
    free(e->val);
    free(e);
}

static dval_t* dset_find(dset_t* d, const char* val, size_t len, uint64_t h) {
    uint32_t b = (uint32_t)(h & (d->n_buckets - 1));
    for (dval_t* e = d->buckets[b]; e; e = e->hnext)
        if (e->h == h && strlen(e->val) == len && memcmp(e->val, val, len) == 0) return e;
    return NULL;
}

static int dset_grow(dset_t* d) {
    uint32_t nn = d->n_buckets << 1;
    dval_t** nb = calloc(nn, sizeof(*nb));
    if (!nb) return -1;
    for (uint32_t i = 0; i < d->n_buckets; i++) {
        dval_t* e = d->buckets[i];
        while (e) {
            dval_t* nx = e->hnext;
            uint32_t b = (uint32_t)(e->h & (nn - 1));
            e->hnext = nb[b];
            nb[b] = e;
            e = nx;
        }
    }
    free(d->buckets);
    d->buckets = nb;
    d->n_buckets = nn;
    return 0;
}

/* Expire distinct values older than window_start, observe `val`, enforce the
 * max_distinct cap (evict oldest), return the resulting distinct count. */
static uint32_t dset_observe(
    dset_t* d, const char* val, double ts, double window_start, uint32_t max_distinct, corr_stats_t* stats) {
    /* Expire stale entries.  Recency (LRU) order is NOT timestamp order (a
     * repeated value refreshes ts and moves to MRU), so scan the whole list and
     * drop every entry whose ts is out of window ("drop k where
     * ts < window_start").  Bounded by max_distinct. */
    dval_t* e = d->lru_head;
    while (e) {
        dval_t* nx = e->lru_next;
        if (e->ts < window_start) dset_remove(d, e);
        e = nx;
    }

    size_t len = strlen(val);
    uint64_t h = fnv1a(val, len);
    dval_t* hit = dset_find(d, val, len, h);
    if (hit) {
        hit->ts = ts;
        dset_unlink_lru(d, hit);
        dset_push_mru(d, hit);
        return d->count;
    }
    if (d->count >= max_distinct) {
        /* Cap hit: evict the oldest distinct value, admit the new one. */
        if (d->lru_head) {
            dset_remove(d, d->lru_head);
            if (stats) CS_INC(stats, distinct_evicted);
        }
    }
    if (d->count + 1 > (d->n_buckets * 3) / 4) (void)dset_grow(d); /* soft-fail: stays correct, just more collisions */

    dval_t* ne = calloc(1, sizeof(*ne));
    if (!ne) {
        if (stats) CS_INC(stats, oom_dropped);
        return d->count; /* OOM: count stays, threshold may have fired */
    }
    ne->val = malloc(len + 1);
    if (!ne->val) {
        free(ne);
        if (stats) CS_INC(stats, oom_dropped);
        return d->count;
    }
    memcpy(ne->val, val, len);
    ne->val[len] = '\0';
    ne->ts = ts;
    ne->h = h;
    uint32_t b = (uint32_t)(h & (d->n_buckets - 1));
    ne->hnext = d->buckets[b];
    d->buckets[b] = ne;
    dset_push_mru(d, ne);
    d->count++;
    return d->count;
}

static void dset_free(dset_t* d) {
    if (d->buckets) {
        for (uint32_t i = 0; i < d->n_buckets; i++) {
            dval_t* e = d->buckets[i];
            while (e) {
                dval_t* nx = e->hnext;
                free(e->val);
                free(e);
                e = nx;
            }
        }
        free(d->buckets);
    }
    d->buckets = NULL;
    d->n_buckets = d->count = 0;
    d->lru_head = d->lru_tail = NULL;
}

/* ============================================================================
 * group lifecycle.
 * ========================================================================== */
static void group_free(group_t* g) {
    if (!g) return;
    if (g->key) {
        for (size_t i = 0; i < g->n_key; i++) free(g->key[i]);
        free(g->key);
    }
    free(g->ev_ts);
    free(g->ev_val); /* NULL unless this was a value_sum/avg group */
    free(g->bbuckets); /* NULL unless this was a bucketed-beaconing group */
    dset_free(&g->distinct);
    free(g);
}

static group_t* group_new(const char* const* vals, size_t n, uint64_t h, uint32_t ev_cap) {
    group_t* g = calloc(1, sizeof(*g));
    if (!g) return NULL;
    g->h = h;
    g->n_key = n;
    if (n > 0) {
        g->key = calloc(n, sizeof(char*));
        if (!g->key) {
            group_free(g);
            return NULL;
        }
        for (size_t i = 0; i < n; i++) {
            size_t len = strlen(vals[i]);
            g->key[i] = malloc(len + 1);
            if (!g->key[i]) {
                group_free(g);
                return NULL;
            }
            memcpy(g->key[i], vals[i], len + 1);
        }
    }
    g->ev_cap = ev_cap ? ev_cap : 1;
    g->ev_ts = malloc(sizeof(double) * g->ev_cap);
    if (!g->ev_ts) {
        group_free(g);
        return NULL;
    }
    if (dset_init(&g->distinct) != 0) {
        group_free(g);
        return NULL;
    }
    return g;
}

/* ============================================================================
 * corr_state (per-correlation bounded LRU group map).
 * ========================================================================== */
static void cstate_unlink_lru(corr_state_t* st, group_t* g) {
    if (g->lru_prev)
        g->lru_prev->lru_next = g->lru_next;
    else
        st->lru_head = g->lru_next;
    if (g->lru_next)
        g->lru_next->lru_prev = g->lru_prev;
    else
        st->lru_tail = g->lru_prev;
    g->lru_prev = g->lru_next = NULL;
}

static void cstate_push_mru(corr_state_t* st, group_t* g) {
    g->lru_prev = st->lru_tail;
    g->lru_next = NULL;
    if (st->lru_tail)
        st->lru_tail->lru_next = g;
    else
        st->lru_head = g;
    st->lru_tail = g;
}

static void cstate_remove(corr_state_t* st, group_t* g) {
    uint32_t b = (uint32_t)(g->h & (st->n_buckets - 1));
    group_t** pp = &st->buckets[b];
    while (*pp && *pp != g) pp = &(*pp)->hnext;
    if (*pp) *pp = g->hnext;
    cstate_unlink_lru(st, g);
    st->count--;
    group_free(g);
}

static int cstate_grow(corr_state_t* st) {
    uint32_t nn = st->n_buckets << 1;
    group_t** nb = calloc(nn, sizeof(*nb));
    if (!nb) return -1;
    for (uint32_t i = 0; i < st->n_buckets; i++) {
        group_t* g = st->buckets[i];
        while (g) {
            group_t* nx = g->hnext;
            uint32_t b = (uint32_t)(g->h & (nn - 1));
            g->hnext = nb[b];
            nb[b] = g;
            g = nx;
        }
    }
    free(st->buckets);
    st->buckets = nb;
    st->n_buckets = nn;
    return 0;
}

/* Get-or-create the group for `vals`, evicting the LRU one at capacity.  Marks
 * the returned group most-recently-used (mirrors OrderedDict.move_to_end). */
static group_t* cstate_get_or_create(
    corr_state_t* st, const corr_caps_t* caps, const char* const* vals, size_t n, corr_stats_t* stats) {
    uint64_t h = hash_group_key(vals, n);
    uint32_t b = (uint32_t)(h & (st->n_buckets - 1));
    for (group_t* g = st->buckets[b]; g; g = g->hnext) {
        if (g->h == h && g->n_key == n && group_key_eq((const char* const*)g->key, vals, n)) {
            cstate_unlink_lru(st, g);
            cstate_push_mru(st, g);
            return g;
        }
    }
    /* Admit a new group, evicting the LRU one at capacity (anti-exhaustion). */
    if (st->count >= caps->max_groups && st->lru_head) {
        cstate_remove(st, st->lru_head);
        if (stats) CS_INC(stats, groups_evicted);
    }

    if (st->count + 1 > (st->n_buckets * 3) / 4) {
        (void)cstate_grow(st);
        b = (uint32_t)(h & (st->n_buckets - 1));
    }
    group_t* g = group_new(vals, n, h, caps->max_events_per_group);
    if (!g) return NULL;
    g->hnext = st->buckets[b];
    st->buckets[b] = g;
    cstate_push_mru(st, g);
    st->count++;
    return g;
}

/* Drop groups whose last_update < horizon (the periodic sweep). */
static void cstate_drop_expired(corr_state_t* st, double horizon) {
    /* Walk the LRU list; a group's last_update is event time, not recency, so
     * scan all (bounded by max_groups). Snapshot-free deletion is safe because
     * cstate_remove only touches the node + its neighbours. */
    group_t* g = st->lru_head;
    while (g) {
        group_t* nx = g->lru_next;
        if (g->last_update < horizon) cstate_remove(st, g);
        g = nx;
    }
}

static void cstate_free(corr_state_t* st) {
    if (st->buckets) {
        for (uint32_t i = 0; i < st->n_buckets; i++) {
            group_t* g = st->buckets[i];
            while (g) {
                group_t* nx = g->hnext;
                group_free(g);
                g = nx;
            }
        }
        free(st->buckets);
    }
    st->buckets = NULL;
    st->n_buckets = st->count = 0;
    st->lru_head = st->lru_tail = NULL;
    pthread_mutex_destroy(&st->lock);
}

/* ============================================================================
 * rid index.
 * ========================================================================== */
static void rid_index_add(corr_engine_t* e, uint32_t rid, uint32_t corr_idx) {
    uint32_t b = (uint32_t)(rid & (e->n_rid_buckets - 1));
    rid_watch_t* w = e->rid_buckets[b];
    while (w && w->rid != rid) w = w->next;
    if (!w) {
        w = calloc(1, sizeof(*w));
        if (!w) {
            CS_INC(&e->stats, oom_dropped);
            return; /* soft-fail: this correlation just won't be indexed */
        }
        w->rid = rid;
        w->cap = 4;
        w->corr_idx = malloc(sizeof(uint32_t) * w->cap);
        if (!w->corr_idx) {
            free(w);
            CS_INC(&e->stats, oom_dropped);
            return;
        }
        w->next = e->rid_buckets[b];
        e->rid_buckets[b] = w;
    }
    /* dedup: a correlation listing the same rid twice indexes once. */
    for (uint32_t i = 0; i < w->n; i++)
        if (w->corr_idx[i] == corr_idx) return;
    if (w->n == w->cap) {
        uint32_t nc = w->cap * 2;
        uint32_t* np = realloc(w->corr_idx, sizeof(uint32_t) * nc);
        if (!np) {
            CS_INC(&e->stats, oom_dropped);
            return;
        }
        w->corr_idx = np;
        w->cap = nc;
    }
    w->corr_idx[w->n++] = corr_idx;
}

static const rid_watch_t* rid_index_find(const corr_engine_t* e, uint32_t rid) {
    uint32_t b = (uint32_t)(rid & (e->n_rid_buckets - 1));
    for (const rid_watch_t* w = e->rid_buckets[b]; w; w = w->next)
        if (w->rid == rid) return w;
    return NULL;
}

/* Sigma correlation aliases: the same group-by slot can be a different
 * field on events matched by different base rules. */
static const char* const* corr_group_fields(const corr_rule_t* r, uint32_t rid) {
    if (r->alias_group_by != NULL && r->n_alias_group_by == r->n_base_rule_ids && r->base_rule_ids != NULL) {
        for (size_t i = 0; i < r->n_base_rule_ids; i++) {
            if (r->base_rule_ids[i] == rid && r->alias_group_by[i] != NULL) return r->alias_group_by[i];
        }
    }
    return r->group_by;
}

/* ============================================================================
 * rule validation (skip rules match the corr_format loader).
 * ========================================================================== */
static int rule_valid(const corr_rule_t* r) {
    if (r->id == NULL || r->id[0] == '\0') return 0;
    if (r->type < 0 || r->type >= CORR_TYPE__MAX) return 0;
    if (r->base_rule_ids == NULL || r->n_base_rule_ids == 0) return 0;
    if (r->timespan_s <= 0) return 0;
    if (r->n_group_by > CORR_MAX_GROUP_FIELDS) return 0;
    if (r->n_alias_group_by != 0 && r->n_alias_group_by != r->n_base_rule_ids) return 0;
    /* value_count / value_sum / value_avg / percentile / median need a field. */
    if ((r->type == CORR_VALUE_COUNT || r->type == CORR_VALUE_SUM || r->type == CORR_VALUE_AVG ||
         r->type == CORR_VALUE_PERCENTILE || r->type == CORR_VALUE_MEDIAN) &&
        (r->value_field == NULL || r->value_field[0] == '\0'))
        return 0;
    if (r->type == CORR_VALUE_PERCENTILE && (r->value_percentile < 0 || r->value_percentile > 100)) return 0;
    /* beaconing needs a positive CV tolerance and >= 3 events (>= 2 gaps) to have
     * a coefficient of variation at all. */
    if (r->type == CORR_BEACONING) {
        if (r->beacon_cv_permille <= 0 || r->cond_count < 3) return 0;
        /* bucketed mode: a sane bucket count and bucket_secs >= 1s (timespan
         * must cover at least one second per bucket, else buckets collapse). */
        if (r->beacon_n_buckets < 0) return 0;
        if (r->beacon_n_buckets > 0 && (r->beacon_n_buckets < 2 || r->beacon_n_buckets > CORR_BEACON_MAX_BUCKETS ||
                                        r->timespan_s < r->beacon_n_buckets))
            return 0;
    }
    return 1;
}

/* ============================================================================
 * engine lifecycle.
 * ========================================================================== */
corr_engine_t* corr_engine_new(const corr_rule_t* rules, size_t n, corr_caps_t caps) {
    corr_engine_t* e = calloc(1, sizeof(*e));
    if (!e) return NULL;
    if (caps.max_groups == 0) caps.max_groups = CORR_DEFAULT_MAX_GROUPS;
    if (caps.max_distinct == 0) caps.max_distinct = CORR_DEFAULT_MAX_DISTINCT;
    if (caps.max_events_per_group == 0) caps.max_events_per_group = CORR_DEFAULT_MAX_EVENTS_PER_GROUP;
    if (caps.sweep_interval_s <= 0.0) caps.sweep_interval_s = CORR_DEFAULT_SWEEP_INTERVAL_S;
    e->caps = caps;

    e->states = (n > 0) ? calloc(n, sizeof(corr_state_t)) : NULL;
    if (n > 0 && !e->states) {
        free(e);
        return NULL;
    }

    size_t admitted = 0;
    for (size_t i = 0; i < n; i++) {
        /* SEP #198: a condition's SEL indexes base_rule_ids, and seen_mask is 64
         * bits; a condition rule with >64 bases can reference an unreachable
         * base, so reject it (observably) rather than silently mis-evaluate. */
        if (rules[i].n_cond > 0 && rules[i].n_base_rule_ids > CORR_MAX_SEEN_RULES) {
            CS_INC(&e->stats, cond_over_arity);
            CS_INC(&e->stats, rules_rejected);
            continue;
        }
        if (!rule_valid(&rules[i])) {
            CS_INC(&e->stats, rules_rejected);
            continue;
        }
        corr_state_t* st = &e->states[admitted];
        st->rule = &rules[i];
        st->n_buckets = 16;
        st->count = 0;
        st->lru_head = st->lru_tail = NULL;
        st->buckets = calloc(st->n_buckets, sizeof(group_t*));
        if (!st->buckets) {
            /* roll back: free what we built */
            for (size_t k = 0; k < admitted; k++) cstate_free(&e->states[k]);
            free(e->states);
            free(e);
            return NULL;
        }
        pthread_mutex_init(&st->lock, NULL);
        admitted++;
    }
    e->n_states = admitted;

    /* rid -> correlation index. */
    e->n_rid_buckets = next_pow2((uint32_t)(admitted * 4 + 8));
    e->rid_buckets = calloc(e->n_rid_buckets, sizeof(rid_watch_t*));
    if (!e->rid_buckets) {
        for (size_t k = 0; k < admitted; k++) cstate_free(&e->states[k]);
        free(e->states);
        free(e);
        return NULL;
    }
    for (size_t i = 0; i < admitted; i++) {
        const corr_rule_t* r = e->states[i].rule;
        for (size_t j = 0; j < r->n_base_rule_ids; j++) rid_index_add(e, r->base_rule_ids[j], (uint32_t)i);
    }

    pthread_mutex_init(&e->sweep_lock, NULL);
    e->sweep_seen = 0;
    e->pct_scratch_cap = caps.max_events_per_group;
    e->pct_scratch = malloc(sizeof(double) * e->pct_scratch_cap);
    if (!e->pct_scratch) {
        for (size_t k = 0; k < admitted; k++) cstate_free(&e->states[k]);
        free(e->states);
        if (e->rid_buckets) {
            for (uint32_t i = 0; i < e->n_rid_buckets; i++) {
                rid_watch_t* w = e->rid_buckets[i];
                while (w) {
                    rid_watch_t* nx = w->next;
                    free(w->corr_idx);
                    free(w);
                    w = nx;
                }
            }
            free(e->rid_buckets);
        }
        pthread_mutex_destroy(&e->sweep_lock);
        free(e);
        return NULL;
    }
    return e;
}

void corr_engine_free(corr_engine_t* e) {
    if (!e) return;
    for (size_t i = 0; i < e->n_states; i++) cstate_free(&e->states[i]);
    free(e->states);
    if (e->rid_buckets) {
        for (uint32_t i = 0; i < e->n_rid_buckets; i++) {
            rid_watch_t* w = e->rid_buckets[i];
            while (w) {
                rid_watch_t* nx = w->next;
                free(w->corr_idx);
                free(w);
                w = nx;
            }
        }
        free(e->rid_buckets);
    }
    pthread_mutex_destroy(&e->sweep_lock);
    free(e->pct_scratch);
    free(e);
}

size_t corr_engine_rule_count(const corr_engine_t* e) {
    return e ? e->n_states : 0;
}

size_t corr_engine_total_groups(const corr_engine_t* e) {
    size_t tot = 0;
    if (e)
        for (size_t i = 0; i < e->n_states; i++) tot += e->states[i].count;
    return tot;
}

size_t corr_engine_groups_for(const corr_engine_t* e, const char* id) {
    if (!e || !id) return 0;
    for (size_t i = 0; i < e->n_states; i++)
        if (e->states[i].rule->id && strcmp(e->states[i].rule->id, id) == 0) return e->states[i].count;
    return 0;
}

void corr_engine_stats(const corr_engine_t* e, corr_stats_t* out) {
    if (!out) return;
    if (!e) {
        memset(out, 0, sizeof(*out));
        return;
    }
    /* Relaxed atomic loads: the counters are written by concurrent workers via
     * CS_INC, so a plain struct copy would be a data race. */
#define CS_LD(field) out->field = __atomic_load_n(&e->stats.field, __ATOMIC_RELAXED)
    CS_LD(groups_evicted);
    CS_LD(distinct_evicted);
    CS_LD(events_overwritten);
    CS_LD(fires_suppressed);
    CS_LD(fires_truncated);
    CS_LD(rules_rejected);
    CS_LD(event_skipped_missing_field);
    CS_LD(seen_truncated);
    CS_LD(hits_truncated);
    CS_LD(group_evidence_dropped);
    CS_LD(oom_dropped);
    CS_LD(values_nonnumeric);
    CS_LD(cond_over_arity);
    CS_LD(watermark_late);
    CS_LD(hotkey_fallback);
#undef CS_LD
}

/* ============================================================================
 * per-type window logic.
 * ========================================================================== */
static int cmp_threshold(int64_t observed, corr_op_t op, int64_t n) {
    switch (op) {
        case CORR_OP_GTE:
            return observed >= n;
        case CORR_OP_GT:
            return observed > n;
        case CORR_OP_LTE:
            return observed <= n;
        case CORR_OP_LT:
            return observed < n;
        case CORR_OP_EQ:
            return observed == n;
    }
    return observed >= n;
}

static void ev_prune(group_t* g, double window_start) {
    while (g->ev_len > 0 && g->ev_ts[g->ev_head] < window_start) {
        g->ev_head = (g->ev_head + 1) % g->ev_cap;
        g->ev_len--;
    }
}

static int eval_event_count(const corr_rule_t* r, group_t* g, double now, double window_start, corr_stats_t* stats) {
    /* Append now; bound the ring (drop oldest); then prune out-of-window. */
    if (g->ev_len == g->ev_cap) {
        double oldest = g->ev_ts[g->ev_head];
        g->ev_ts[g->ev_head] = now; /* overwrite oldest */
        g->ev_head = (g->ev_head + 1) % g->ev_cap;
        if (stats) {
            CS_INC(stats, events_overwritten);
            /* Ring filled in less than half the window: this group-key is hot. */
            if (oldest > window_start + (now - window_start) * 0.5) CS_INC(stats, hotkey_fallback);
        }
    } else {
        uint32_t tail = (g->ev_head + g->ev_len) % g->ev_cap;
        g->ev_ts[tail] = now;
        g->ev_len++;
    }
    ev_prune(g, window_start);
    return cmp_threshold((int64_t)g->ev_len + (int64_t)g->merge_n, r->cond_op, r->cond_count);
}

static int eval_value_count(const corr_rule_t* r,
                            group_t* g,
                            const char* value_val,
                            uint32_t max_distinct,
                            double now,
                            double window_start,
                            corr_stats_t* stats) {
    if (value_val == NULL) return 0;
    uint32_t cnt = dset_observe(&g->distinct, value_val, now, window_start, max_distinct, stats);
    return cmp_threshold((int64_t)cnt, r->cond_op, r->cond_count);
}

/* Tolerant numeric parse for value_sum/avg: a leading (optionally signed)
 * decimal with optional fraction/exponent; trailing junk is ignored
 * ("1500/tcp" -> 1500.0). Returns 0 on no leading number or a non-finite
 * result (the event's value is then skipped, NEVER coerced to zero). value_val
 * is NUL-terminated (the corr field_fn contract), so strtod stays in bounds. */
static int sg_to_f64(const char* s, size_t len, double* out) {
    (void)len;
    if (s == NULL || s[0] == '\0') return 0;
    char* end = NULL;
    double v = strtod(s, &end);
    if (end == s || !isfinite(v)) return 0;
    *out = v;
    return 1;
}

static int cond_satisfied_f(corr_op_t op, double val, double thr) {
    switch (op) {
        case CORR_OP_GTE:
            return val >= thr;
        case CORR_OP_GT:
            return val > thr;
        case CORR_OP_LTE:
            return val <= thr;
        case CORR_OP_LT:
            return val < thr;
        case CORR_OP_EQ:
            return val == thr;
    }
    return val >= thr;
}

/* Push (now, val) into the parallel ts/value rings (lazy-allocating ev_val on
 * first use, so only value_sum/avg groups pay), bounded by max_events_per_group,
 * then prune out-of-window. Mirrors eval_event_count's ring discipline so the
 * two arrays index in lockstep. Returns 0 on OOM allocating ev_val. */
static int ev_push_val(group_t* g, double now, double val, double window_start, corr_stats_t* stats) {
    if (g->ev_val == NULL) {
        g->ev_val = malloc(sizeof(double) * g->ev_cap);
        if (g->ev_val == NULL) {
            if (stats) CS_INC(stats, oom_dropped);
            return 0;
        }
    }
    if (g->ev_len == g->ev_cap) {
        double oldest = g->ev_ts[g->ev_head];
        g->ev_ts[g->ev_head] = now; /* overwrite oldest */
        g->ev_val[g->ev_head] = val;
        g->ev_head = (g->ev_head + 1) % g->ev_cap;
        if (stats) {
            CS_INC(stats, events_overwritten);
            if (oldest > window_start + (now - window_start) * 0.5) CS_INC(stats, hotkey_fallback);
        }
    } else {
        uint32_t tail = (g->ev_head + g->ev_len) % g->ev_cap;
        g->ev_ts[tail] = now;
        g->ev_val[tail] = val;
        g->ev_len++;
    }
    ev_prune(g, window_start);
    return 1;
}

/* value_sum (is_avg=0) / value_avg (is_avg=1): aggregate the numeric value_field
 * over the live window. A non-numeric value is counted (values_nonnumeric) and
 * skipped from the aggregate, never coerced to 0. Recomputes over the live ring
 * per event (ring bounded by max_events_per_group; correlation is off the
 * line-rate path, so no incremental-subtract float drift). *out_agg gets the
 * aggregate for the fire record; value_avg never fires on an empty window. */
static int eval_value_sum_avg(const corr_rule_t* r,
                              group_t* g,
                              const char* value_val,
                              int is_avg,
                              double now,
                              double window_start,
                              corr_stats_t* stats,
                              double* out_agg) {
    double v;
    if (value_val != NULL && sg_to_f64(value_val, strlen(value_val), &v)) {
        ev_push_val(g, now, v, window_start, stats);
    } else {
        if (stats) CS_INC(stats, values_nonnumeric);
        ev_prune(g, window_start); /* age the window even when this value is skipped */
    }
    double sum = g->merge_sum;
    if (g->ev_val != NULL) {
        for (uint32_t i = 0; i < g->ev_len; i++) sum += g->ev_val[(g->ev_head + i) % g->ev_cap];
    }
    if (is_avg) {
        uint32_t n = g->ev_len + g->merge_n;
        if (n == 0) {
            *out_agg = 0.0;
            return 0; /* no fire on empty average */
        }
        *out_agg = sum / (double)n;
    } else {
        *out_agg = sum;
    }
    return cond_satisfied_f(r->cond_op, *out_agg, (double)r->cond_count);
}

static int cmp_dbl_asc(const void* a, const void* b) {
    double da = *(const double*)a, db = *(const double*)b;
    return (da > db) - (da < db);
}

/* Exact P_k from the live ring (nearest-rank). merge_sum/n are ignored: a
 * remote percentile merge needs a t-digest, which is a later transport path.
 * Empty window never fires. */
static int eval_value_percentile(const corr_rule_t* r,
                                 group_t* g,
                                 const char* value_val,
                                 double now,
                                 double window_start,
                                 corr_stats_t* stats,
                                 double* scratch,
                                 uint32_t scratch_cap,
                                 double* out_agg) {
    double v;
    if (value_val != NULL && sg_to_f64(value_val, strlen(value_val), &v)) {
        ev_push_val(g, now, v, window_start, stats);
    } else {
        if (stats) CS_INC(stats, values_nonnumeric);
        ev_prune(g, window_start);
    }
    if (g->ev_len == 0 || g->ev_val == NULL || scratch == NULL || scratch_cap < g->ev_len) {
        *out_agg = 0.0;
        return 0;
    }
    int p = (r->type == CORR_VALUE_MEDIAN) ? 50 : (int)r->value_percentile;
    if (p <= 0) p = 95;
    if (p > 100) p = 100;
    uint32_t n = g->ev_len;
    for (uint32_t i = 0; i < n; i++) scratch[i] = g->ev_val[(g->ev_head + i) % g->ev_cap];
    qsort(scratch, n, sizeof(double), cmp_dbl_asc);
    /* nearest-rank: idx = ceil(p/100 * n) - 1 */
    uint32_t idx = (uint32_t)(((uint64_t)p * n + 99u) / 100u);
    if (idx == 0) idx = 1;
    idx -= 1;
    if (idx >= n) idx = n - 1;
    *out_agg = scratch[idx];
    return cond_satisfied_f(r->cond_op, *out_agg, (double)r->cond_count);
}

/* warm-path presence gate (0.7): a bucketed beacon must be active in >= 70% of
 * the buckets spanning its first-to-last activity. */
#define BEACON_PRESENCE_MIN_PERMILLE 700

/* beaconing RAW mode (beacon_n_buckets == 0): is the base rule's activity on this
 * group PERIODIC?  Push the event timestamp into the ev_ts ring (event_count
 * discipline), then measure the regularity of the inter-arrival gaps over the
 * live window as their coefficient of variation, cv = stddev(gaps) / mean(gaps).
 * A low CV = evenly spaced = beacon.  Compared sqrt-free (cv <= tol  <=>  var <=
 * (tol*mean)^2, all terms >= 0), so the engine stays libm-free.  Fires iff the
 * window holds >= cond_count events AND cv <= tolerance.  Precise sub-window
 * cadence, but bounded to the events that fit the ring. */
static int eval_beaconing_raw(const corr_rule_t* r, group_t* g, double now, double window_start, corr_stats_t* stats) {
    /* append now; bound the ring (drop oldest); prune out-of-window */
    if (g->ev_len == g->ev_cap) {
        g->ev_ts[g->ev_head] = now; /* overwrite oldest */
        g->ev_head = (g->ev_head + 1) % g->ev_cap;
        if (stats) CS_INC(stats, events_overwritten);
    } else {
        uint32_t tail = (g->ev_head + g->ev_len) % g->ev_cap;
        g->ev_ts[tail] = now;
        g->ev_len++;
    }
    ev_prune(g, window_start);

    /* need cond_count events in-window, and >= 3 (>= 2 gaps) for a CV at all */
    if ((int64_t)g->ev_len < r->cond_count || g->ev_len < 3) return 0;

    /* mean of consecutive inter-arrival gaps, ring walked in arrival order */
    double prev = g->ev_ts[g->ev_head];
    double sum = 0.0;
    uint32_t ng = 0;
    for (uint32_t i = 1; i < g->ev_len; i++) {
        double t = g->ev_ts[(g->ev_head + i) % g->ev_cap];
        sum += t - prev;
        prev = t;
        ng++;
    }
    if (ng == 0) return 0;
    double mean = sum / (double)ng;
    if (mean <= 0.0) return 0; /* coincident timestamps -> no cadence */

    /* population variance of the gaps (divisor N, matching the warm detector) */
    prev = g->ev_ts[g->ev_head];
    double var = 0.0;
    for (uint32_t i = 1; i < g->ev_len; i++) {
        double t = g->ev_ts[(g->ev_head + i) % g->ev_cap];
        double d = (t - prev) - mean;
        var += d * d;
        prev = t;
    }
    var /= (double)ng;

    /* cv <= tol  <=>  var <= (tol*mean)^2  (sqrt-free, libm-free) */
    double tol = (double)r->beacon_cv_permille / 1000.0;
    double bound = tol * mean;
    bound *= bound;
    return var <= bound;
}

/* beaconing BUCKETED mode (beacon_n_buckets > 0): a long-horizon activity
 * histogram of beacon_n_buckets time buckets over timespan_s (bucket_secs =
 * timespan_s / n_buckets).  Each event bumps its bucket; the ring self-expires
 * (a window of n_buckets consecutive epochs maps 1:1 onto the slots, so a stale
 * slot reads as inactive).  Over the window it computes, on the ACTIVE buckets:
 *   presence = active / (last_active - first_active + 1)   (warm f_presence)
 *   gap-CV   = CV of gaps between consecutive active bucket epochs  (warm f_gap)
 * Fires iff active >= cond_count AND presence >= 0.7 AND gap-CV <= tolerance.
 * This catches low-and-slow multi-day beacons (e.g. one callback/hour for days)
 * without holding raw events; destination-consistency is implicit in the key. */
static int eval_beaconing_bucketed(const corr_rule_t* r, group_t* g, double now, corr_stats_t* stats) {
    uint32_t nb = (uint32_t)r->beacon_n_buckets;
    if (g->bbuckets == NULL) {
        g->bbuckets = calloc(nb, sizeof(beacon_bucket_t)); /* zeroed => all empty */
        if (g->bbuckets == NULL) {
            if (stats) CS_INC(stats, oom_dropped);
            return 0;
        }
        g->bb_cap = nb;
    }
    double bucket_secs = (double)r->timespan_s / (double)nb;
    if (bucket_secs <= 0.0 || now < 0.0) return 0; /* rule_valid guards; defensive */
    uint32_t now_e = (uint32_t)(now / bucket_secs);

    /* bump this event's bucket (reclaim the slot if it held an older epoch) */
    uint32_t slot = now_e % nb;
    if (g->bbuckets[slot].epoch != now_e) {
        g->bbuckets[slot].epoch = now_e;
        g->bbuckets[slot].count = 0;
    }
    if (g->bbuckets[slot].count < UINT32_MAX) g->bbuckets[slot].count++;

    uint32_t win_start = (now_e >= nb - 1) ? (now_e - (nb - 1)) : 0;

    /* pass 1: active count, presence span, gap mean (over active-bucket epochs) */
    uint32_t active = 0, first_e = 0, last_e = 0, prev_e = 0, ngap = 0;
    int have_prev = 0;
    double gap_sum = 0.0;
    for (uint32_t e = win_start;; e++) {
        const beacon_bucket_t* b = &g->bbuckets[e % nb];
        if (b->epoch == e && b->count > 0) {
            if (active == 0) first_e = e;
            last_e = e;
            active++;
            if (have_prev) {
                gap_sum += (double)(e - prev_e);
                ngap++;
            }
            prev_e = e;
            have_prev = 1;
        }
        if (e == now_e) break;
    }
    if ((int64_t)active < r->cond_count || active < 3) return 0;

    /* presence >= 0.7  <=>  active*1000 >= 700 * span   (integer, no float) */
    uint32_t span = last_e - first_e + 1;
    if ((uint64_t)active * 1000ull < (uint64_t)BEACON_PRESENCE_MIN_PERMILLE * (uint64_t)span) return 0;

    if (ngap == 0) return 0;
    double gap_mean = gap_sum / (double)ngap;
    if (gap_mean <= 0.0) return 0;

    /* pass 2: population variance of the active-bucket gaps */
    have_prev = 0;
    double var = 0.0;
    for (uint32_t e = win_start;; e++) {
        const beacon_bucket_t* b = &g->bbuckets[e % nb];
        if (b->epoch == e && b->count > 0) {
            if (have_prev) {
                double d = (double)(e - prev_e) - gap_mean;
                var += d * d;
            }
            prev_e = e;
            have_prev = 1;
        }
        if (e == now_e) break;
    }
    var /= (double)ngap;

    double tol = (double)r->beacon_cv_permille / 1000.0;
    double bound = tol * gap_mean;
    bound *= bound;
    return var <= bound;
}

/* beaconing dispatcher: RAW (ring, sub-window cadence) vs BUCKETED (histogram,
 * long-horizon low-and-slow), selected by beacon_n_buckets. */
static int eval_beaconing(const corr_rule_t* r, group_t* g, double now, double window_start, corr_stats_t* stats) {
    if (r->beacon_n_buckets > 0) return eval_beaconing_bucketed(r, g, now, stats);
    return eval_beaconing_raw(r, g, now, window_start, stats);
}

/* Record the base rids that fired on THIS event into the group's per-rid
 * latest-ts table, then expire out-of-window entries (compact in place).
 * Shared by temporal and temporal_ordered-with-condition. */
static void temporal_record_seen(
    group_t* g, const uint32_t* hit_rids, size_t n_hit, double now, double window_start, corr_stats_t* stats) {
    for (size_t i = 0; i < n_hit; i++) {
        uint32_t rid = hit_rids[i];
        uint32_t k;
        for (k = 0; k < g->n_seen; k++)
            if (g->seen_rid[k] == rid) {
                g->seen_ts[k] = now;
                break;
            }
        if (k == g->n_seen) {
            if (g->n_seen < CORR_MAX_SEEN_RULES) {
                g->seen_rid[g->n_seen] = rid;
                g->seen_ts[g->n_seen] = now;
                g->n_seen++;
            } else if (stats) {
                /* Table full: a new base rid can't be recorded, so this
                 * correlation may never reach "all base rids present". */
                CS_INC(stats, seen_truncated);
            }
        }
    }
    /* Expire stale observations (compact in place). */
    uint32_t w = 0;
    for (uint32_t k = 0; k < g->n_seen; k++) {
        if (g->seen_ts[k] >= window_start) {
            g->seen_rid[w] = g->seen_rid[k];
            g->seen_ts[w] = g->seen_ts[k];
            w++;
        }
    }
    g->n_seen = w;
}

/* SEP #198 boolean evaluator: a stack machine over the RPN, mirroring the
 * single-event matcher's eval. SEL(i) = bit i of seen_mask (base_rule_ids[i]
 * fired in-window). Malformed RPN (loader-validated, but defensive) yields 0. */
#define CORR_COND_STACK_MAX 64
static int corr_cond_eval(const corr_ctok_t* c, size_t n, uint64_t seen_mask) {
    int stack[CORR_COND_STACK_MAX];
    int sp = 0;
    for (size_t i = 0; i < n; i++) {
        switch (c[i].kind) {
            case CORR_C_SEL:
                if (sp >= CORR_COND_STACK_MAX || c[i].rid_idx >= 64) return 0;
                stack[sp++] = (int)((seen_mask >> c[i].rid_idx) & 1u);
                break;
            case CORR_C_NOT:
                if (sp < 1) return 0;
                stack[sp - 1] = !stack[sp - 1];
                break;
            case CORR_C_AND:
                if (sp < 2) return 0;
                stack[sp - 2] = stack[sp - 2] && stack[sp - 1];
                sp--;
                break;
            case CORR_C_OR:
                if (sp < 2) return 0;
                stack[sp - 2] = stack[sp - 2] || stack[sp - 1];
                sp--;
                break;
            default:
                return 0;
        }
    }
    return (sp == 1) ? stack[0] : 0;
}

/* bit i set iff base_rule_ids[i] is currently in the group's (expired) seen set.
 * O(n_base * n_seen), both bounded by CORR_MAX_SEEN_RULES (64). */
static uint64_t corr_seen_mask(const corr_rule_t* r, const group_t* g) {
    uint64_t mask = g->merge_seen;
    size_t nb = r->n_base_rule_ids < 64 ? r->n_base_rule_ids : 64;
    for (size_t i = 0; i < nb; i++) {
        uint32_t want = r->base_rule_ids[i];
        for (uint32_t k = 0; k < g->n_seen; k++)
            if (g->seen_rid[k] == want) {
                mask |= (1ull << i);
                break;
            }
    }
    return mask;
}

/* temporal: record + expire; then fire per the SEP #198 boolean condition when
 * present (SEL(i)=base_rule_ids[i] seen in-window; the non-monotonic `not` is
 * re-evaluated every event, and the caller's fired_until suppresses re-fires),
 * else the legacy "ALL base rids present" semantics. */
static int eval_temporal(const corr_rule_t* r,
                         group_t* g,
                         const uint32_t* hit_rids,
                         size_t n_hit,
                         double now,
                         double window_start,
                         corr_stats_t* stats) {
    temporal_record_seen(g, hit_rids, n_hit, now, window_start, stats);
    if (r->n_cond > 0) return corr_cond_eval(r->cond, r->n_cond, corr_seen_mask(r, g));
    /* legacy: ALL base rids present. */
    uint64_t mask = corr_seen_mask(r, g);
    size_t nb = r->n_base_rule_ids < 64 ? r->n_base_rule_ids : 64;
    for (size_t i = 0; i < nb; i++) {
        if ((mask & (1ull << i)) == 0) return 0;
    }
    return 1;
}

/* temporal_ordered: greedy advance through consecutive expected steps that this
 * event satisfies; reset progress if the anchor aged out; fire + reset at end.
 * event_time: when set, `now` is the log's event time (not a monotonic
 * processing clock), so each advanced step's time must be non-decreasing - an
 * event processed later but timestamped earlier cannot fabricate an ordered
 * chain across concurrent sources. */
static int eval_temporal_ordered(const corr_rule_t* r,
                                 group_t* g,
                                 const uint32_t* hit_rids,
                                 size_t n_hit,
                                 double now,
                                 double window_start,
                                 int event_time) {
    const uint32_t* order = (r->ordered_rule_ids && r->n_ordered_rule_ids) ? r->ordered_rule_ids : r->base_rule_ids;
    size_t n = (r->ordered_rule_ids && r->n_ordered_rule_ids) ? r->n_ordered_rule_ids : r->n_base_rule_ids;
    if (n == 0) return 0;
    if (g->ordered_progress > 0 && g->ordered_anchor_ts < window_start) {
        g->ordered_progress = 0;
        g->ordered_anchor_ts = 0.0;
        g->ordered_last_ts = 0.0;
    }
    int advanced = 1;
    while (advanced && g->ordered_progress < n) {
        advanced = 0;
        uint32_t expected = order[g->ordered_progress];
        int in_hit = 0;
        for (size_t i = 0; i < n_hit; i++)
            if (hit_rids[i] == expected) {
                in_hit = 1;
                break;
            }
        if (in_hit) {
            if (g->ordered_progress == 0) {
                g->ordered_anchor_ts = now;
                g->ordered_last_ts = now;
                g->ordered_progress++;
                advanced = 1;
            } else if (!event_time || now >= g->ordered_last_ts) {
                g->ordered_last_ts = now;
                g->ordered_progress++;
                advanced = 1;
            }
            /* else (event_time && now < ordered_last_ts): this step's event time
             * predates the previous step, so it is not a valid next step. */
        }
    }
    if (g->ordered_progress >= n) {
        g->ordered_progress = 0; /* ready to detect the next sequence */
        g->ordered_anchor_ts = 0.0;
        g->ordered_last_ts = 0.0;
        return 1;
    }
    return 0;
}

static void wm_insert(group_t* g, double ts, uint32_t rid, corr_stats_t* stats) {
    if (g->wm_n >= CORR_WM_CAP) {
        /* drop the oldest pending item to admit the new one */
        uint32_t min_i = 0;
        for (uint32_t i = 1; i < g->wm_n; i++)
            if (g->wm[i].ts < g->wm[min_i].ts) min_i = i;
        g->wm[min_i] = g->wm[g->wm_n - 1];
        g->wm_n--;
        if (stats) CS_INC(stats, watermark_late);
    }
    uint32_t i = g->wm_n;
    while (i > 0 && g->wm[i - 1].ts > ts) {
        g->wm[i] = g->wm[i - 1];
        i--;
    }
    g->wm[i].ts = ts;
    g->wm[i].rid = rid;
    g->wm_n++;
    if (ts > g->wm_max_ts) g->wm_max_ts = ts;
}

/* Buffer out-of-order temporal_ordered hits and replay in event-time order
 * once the high-water mark (max event ts) minus slack has passed them. */
static int eval_temporal_ordered_wm(const corr_rule_t* r,
                                    group_t* g,
                                    const uint32_t* hit_rids,
                                    size_t n_hit,
                                    double now,
                                    double window_start,
                                    double watermark_s,
                                    corr_stats_t* stats) {
    if (g->wm_max_ts > 0.0 && now + watermark_s < g->wm_max_ts) {
        /* this event is older than the slack behind the high water mark */
        if (stats) CS_INC(stats, watermark_late);
        return eval_temporal_ordered(r, g, hit_rids, n_hit, now, window_start, 1);
    }
    for (size_t i = 0; i < n_hit; i++) wm_insert(g, now, hit_rids[i], stats);
    if (now > g->wm_max_ts) g->wm_max_ts = now;
    double cutoff = g->wm_max_ts - watermark_s;
    int fired = 0;
    uint32_t w = 0;
    for (uint32_t i = 0; i < g->wm_n; i++) {
        if (g->wm[i].ts <= cutoff) {
            uint32_t one = g->wm[i].rid;
            if (eval_temporal_ordered(r, g, &one, 1, g->wm[i].ts, window_start, 1)) fired = 1;
        } else {
            g->wm[w++] = g->wm[i];
        }
    }
    g->wm_n = w;
    return fired;
}

/* ============================================================================
 * the hot evaluation.
 * ========================================================================== */
static void sweep_if_due(corr_engine_t* e, double now) {
    /* Single-flight: only one worker sweeps at a time; the rest skip via trylock
     * (they called with no state lock held, so no deadlock).  last_sweep and
     * sweep_seen are read/written only under sweep_lock.  Each state is locked
     * while its expired groups are dropped, so a concurrent corr_on_event on a
     * different state runs unimpeded. */
    if (pthread_mutex_trylock(&e->sweep_lock) != 0) return;
    if (!e->sweep_seen) {
        e->last_sweep = now;
        e->sweep_seen = 1;
        pthread_mutex_unlock(&e->sweep_lock);
        return;
    }
    if (now - e->last_sweep < e->caps.sweep_interval_s) {
        pthread_mutex_unlock(&e->sweep_lock);
        return;
    }
    e->last_sweep = now;
    for (size_t i = 0; i < e->n_states; i++) {
        int32_t ts = e->states[i].rule->timespan_s;
        if (ts > 0) {
            pthread_mutex_lock(&e->states[i].lock);
            cstate_drop_expired(&e->states[i], now - (double)ts);
            pthread_mutex_unlock(&e->states[i].lock);
        }
    }
    pthread_mutex_unlock(&e->sweep_lock);
}

int corr_on_event(corr_engine_t* e,
                  const uint32_t* matched_rids,
                  size_t n_rids,
                  corr_field_fn field_fn,
                  void* field_ctx,
                  double ts,
                  corr_fire_t* out,
                  size_t max_out,
                  const char** grp_scratch,
                  size_t grp_scratch_cap) {
    return corr_on_event_apply(e, matched_rids, n_rids, field_fn, field_ctx, ts, out, max_out, grp_scratch,
                               grp_scratch_cap, NULL, NULL);
}

int corr_on_event_apply(corr_engine_t* e,
                        const uint32_t* matched_rids,
                        size_t n_rids,
                        corr_field_fn field_fn,
                        void* field_ctx,
                        double ts,
                        corr_fire_t* out,
                        size_t max_out,
                        const char** grp_scratch,
                        size_t grp_scratch_cap,
                        corr_apply_fn apply,
                        void* apply_ctx) {
    if (!e || e->n_states == 0 || n_rids == 0) return 0;

    sweep_if_due(e, ts);

    /* Which correlations care about any rid on this event? Mark them via a
     * per-call interested flag stored on the state (cleared after use). We use
     * a small dynamic visited set to avoid O(n_states) scans. */
    int fired_count = 0;
    size_t scratch_used = 0;

    /* Collect interested correlation indices (dedup via the rid index entries;
     * a correlation may be hit by several rids, guard against double-eval). */
    /* Use a transient bitmap on the stack-free path: walk rid watches, and for
     * each candidate correlation evaluate once. We dedup with the state's
     * `count`-independent visited marker reusing ordered_anchor_ts? No, use a
     * local visited array sized to n_states. */
    /* Small n_states in practice; allocate a visited byte array. */
    unsigned char* visited = calloc(e->n_states, 1);
    if (!visited) {
        CS_INC(&e->stats, oom_dropped);
        return 0; /* OOM: skip this event rather than risk double-fire */
    }

    for (size_t ri = 0; ri < n_rids; ri++) {
        const rid_watch_t* w = rid_index_find(e, matched_rids[ri]);
        if (!w) continue;
        for (uint32_t wi = 0; wi < w->n; wi++) {
            uint32_t ci = w->corr_idx[wi];
            if (visited[ci]) continue;
            visited[ci] = 1;

            corr_state_t* st = &e->states[ci];
            const corr_rule_t* r = st->rule;
            double timespan = (double)r->timespan_s;
            double window_start = ts - timespan;

            /* Resolve group-by values; a missing field skips THIS correlation.
             * Aliases pick the field names for the rid that selected this
             * correlation on this event. */
            const char* const* gfields = corr_group_fields(r, matched_rids[ri]);
            const char* gvals[CORR_MAX_GROUP_FIELDS];
            int missing = 0;
            for (size_t g = 0; g < r->n_group_by; g++) {
                const char* fname = (gfields != NULL) ? gfields[g] : NULL;
                const char* v = (field_fn && fname) ? field_fn(field_ctx, fname) : NULL;
                if (v == NULL) {
                    missing = 1;
                    break;
                }
                gvals[g] = v;
            }
            if (missing) {
                CS_INC(&e->stats, event_skipped_missing_field);
                continue;
            }
            if (apply != NULL && !apply(apply_ctx, r, (const char* const*)gvals, r->n_group_by)) continue;

            /* Everything that reads or mutates THIS correlation's group map runs
             * under its per-state lock: cstate_get_or_create, the per-type
             * evaluation, the re-fire deadline, and the observed-count read.  A
             * concurrent worker on a DIFFERENT correlation holds a different lock
             * and runs in parallel; two workers on the same correlation serialise
             * here (correctly) but never on the line-rate match path. */
            pthread_mutex_lock(&st->lock);
            group_t* gs = cstate_get_or_create(st, &e->caps, (const char* const*)gvals, r->n_group_by, &e->stats);
            if (!gs) {
                pthread_mutex_unlock(&st->lock);
                CS_INC(&e->stats, oom_dropped);
                continue; /* OOM admitting the group */
            }
            gs->last_update = ts;

            /* Base rids of THIS correlation that fired on THIS event. */
            uint32_t hit_buf[CORR_MAX_SEEN_RULES];
            size_t n_hit = 0;
            for (size_t bi = 0; bi < r->n_base_rule_ids; bi++) {
                uint32_t want = r->base_rule_ids[bi];
                for (size_t k = 0; k < n_rids; k++)
                    if (matched_rids[k] == want) {
                        if (n_hit < CORR_MAX_SEEN_RULES)
                            hit_buf[n_hit++] = want;
                        else
                            CS_INC(&e->stats, hits_truncated);
                        break;
                    }
            }
            if (n_hit == 0) {
                pthread_mutex_unlock(&st->lock);
                continue; /* none of this correlation's bases on this event */
            }

            int fired_now = 0;
            double vagg = 0.0; /* value_sum/avg aggregate, for the fire record */
            switch (r->type) {
                case CORR_EVENT_COUNT:
                    fired_now = eval_event_count(r, gs, ts, window_start, &e->stats);
                    break;
                case CORR_VALUE_COUNT: {
                    const char* vv = field_fn ? field_fn(field_ctx, r->value_field) : NULL;
                    fired_now = eval_value_count(r, gs, vv, e->caps.max_distinct, ts, window_start, &e->stats);
                    break;
                }
                case CORR_VALUE_SUM:
                case CORR_VALUE_AVG: {
                    const char* vv = field_fn ? field_fn(field_ctx, r->value_field) : NULL;
                    fired_now =
                        eval_value_sum_avg(r, gs, vv, r->type == CORR_VALUE_AVG, ts, window_start, &e->stats, &vagg);
                    break;
                }
                case CORR_VALUE_PERCENTILE:
                case CORR_VALUE_MEDIAN: {
                    const char* vv = field_fn ? field_fn(field_ctx, r->value_field) : NULL;
                    fired_now = eval_value_percentile(r, gs, vv, ts, window_start, &e->stats, e->pct_scratch,
                                                      e->pct_scratch_cap, &vagg);
                    break;
                }
                case CORR_TEMPORAL:
                    fired_now = eval_temporal(r, gs, hit_buf, n_hit, ts, window_start, &e->stats);
                    break;
                case CORR_TEMPORAL_ORDERED:
                    /* With a SEP #198 condition, also track the seen set so the
                     * boolean (incl. `not` absence terms, which are NOT part of
                     * the order) can gate the ordered-sequence fire. */
                    if (r->n_cond > 0) temporal_record_seen(gs, hit_buf, n_hit, ts, window_start, &e->stats);
                    if (e->caps.watermark_s > 0.0 && e->caps.event_time_ordering) {
                        fired_now = eval_temporal_ordered_wm(r, gs, hit_buf, n_hit, ts, window_start,
                                                             e->caps.watermark_s, &e->stats);
                    } else {
                        fired_now =
                            eval_temporal_ordered(r, gs, hit_buf, n_hit, ts, window_start, e->caps.event_time_ordering);
                    }
                    if (fired_now && r->n_cond > 0)
                        fired_now = corr_cond_eval(r->cond, r->n_cond, corr_seen_mask(r, gs));
                    break;
                case CORR_BEACONING:
                    fired_now = eval_beaconing(r, gs, ts, window_start, &e->stats);
                    break;
                default:
                    break;
            }

            if (!fired_now) {
                pthread_mutex_unlock(&st->lock);
                continue;
            }

            /* Re-fire suppression: stay lit for one window after firing. */
            if (ts < gs->fired_until) {
                pthread_mutex_unlock(&st->lock);
                CS_INC(&e->stats, fires_suppressed);
                continue;
            }
            gs->fired_until = ts + timespan * CORR_REFIRE_FRACTION;

            /* Read the observed count while still holding the lock: once released,
             * another worker may evict this group. */
            int64_t observed_val;
            const char* observed_vfield = NULL;
            int fire_remote = gs->merge_remote ? 1 : 0;
            if (r->type == CORR_VALUE_COUNT) {
                observed_val = (int64_t)gs->distinct.count;
                observed_vfield = r->value_field;
            } else if (r->type == CORR_VALUE_SUM || r->type == CORR_VALUE_AVG || r->type == CORR_VALUE_PERCENTILE ||
                       r->type == CORR_VALUE_MEDIAN) {
                observed_val = (int64_t)vagg; /* aggregate, truncated for the int64 observed field */
                observed_vfield = r->value_field;
            } else if (r->type == CORR_EVENT_COUNT) {
                observed_val = (int64_t)gs->ev_len + (int64_t)gs->merge_n;
            } else if (r->type == CORR_BEACONING) {
                observed_val = (int64_t)gs->ev_len; /* beaconing: events in the periodic window */
            } else {
                observed_val = (int64_t)r->n_base_rule_ids;
            }
            pthread_mutex_unlock(&st->lock);

            /* Build the activation.  out[] and grp_scratch are caller-owned,
             * per-worker storage, so no engine lock is held here. */
            if ((size_t)fired_count < max_out) {
                corr_fire_t* f = &out[fired_count];
                corr_tier_t tier = corr_tier_for(r->type, r->level);
                f->rule_id = r->id;
                f->title = r->title;
                f->type = r->type;
                f->technique = r->mitre;
                f->level = r->level ? r->level : "medium";
                f->tier = tier;
                f->fidelity_weight = corr_tier_weight(tier);
                f->group_by = r->group_by;
                f->n_group = r->n_group_by;
                f->threshold = r->cond_count;
                f->base_rule_ids = r->base_rule_ids;
                f->n_base_rule_ids = r->n_base_rule_ids;
                /* Snapshot the group VALUE pointers into the caller's per-worker
                 * scratch; the strings themselves are caller field values valid
                 * for the whole doAction (the field_fn contract). */
                if (r->n_group_by > 0 && grp_scratch != NULL && scratch_used + r->n_group_by <= grp_scratch_cap) {
                    const char** slot = &grp_scratch[scratch_used];
                    for (size_t g = 0; g < r->n_group_by; g++) slot[g] = gvals[g];
                    f->group = slot;
                    scratch_used += r->n_group_by;
                } else {
                    if (r->n_group_by > 0) CS_INC(&e->stats, group_evidence_dropped);
                    f->group = NULL;
                }
                f->observed = observed_val;
                f->value_field = observed_vfield;
                f->remote = fire_remote;
            } else {
                /* Fired, but the caller's out[] is full: the count still
                 * reflects it, the activation payload is dropped. */
                CS_INC(&e->stats, fires_truncated);
            }
            fired_count++;
        }
    }

    free(visited);
    return fired_count;
}

static corr_state_t* corr_state_by_id(corr_engine_t* e, const char* id) {
    if (!e || !id) return NULL;
    for (size_t i = 0; i < e->n_states; i++)
        if (e->states[i].rule->id && strcmp(e->states[i].rule->id, id) == 0) return &e->states[i];
    return NULL;
}

int corr_on_contribution(corr_engine_t* e,
                         const corr_contrib_t* c,
                         corr_field_fn field_fn,
                         void* field_ctx,
                         corr_fire_t* out,
                         size_t max_out,
                         const char** grp_scratch,
                         size_t grp_scratch_cap) {
    if (!e || !c) return 0;
    if (c->kind == CORR_CONTRIB_EVENT)
        return corr_on_event(e, c->rids, c->n_rids, field_fn, field_ctx, c->ts, out, max_out, grp_scratch,
                             grp_scratch_cap);
    if (c->corr_id == NULL || c->corr_id[0] == '\0') return 0;

    sweep_if_due(e, c->ts);
    corr_state_t* st = corr_state_by_id(e, c->corr_id);
    if (!st) return 0;
    const corr_rule_t* r = st->rule;
    if (c->n_group != r->n_group_by) {
        CS_INC(&e->stats, event_skipped_missing_field);
        return 0;
    }
    const char* gvals[CORR_MAX_GROUP_FIELDS];
    for (size_t g = 0; g < r->n_group_by; g++) {
        if (c->group_vals == NULL || c->group_vals[g] == NULL) {
            CS_INC(&e->stats, event_skipped_missing_field);
            return 0;
        }
        gvals[g] = c->group_vals[g];
    }

    double timespan = (double)r->timespan_s;
    double window_start = c->ts - timespan;
    pthread_mutex_lock(&st->lock);
    group_t* gs = cstate_get_or_create(st, &e->caps, (const char* const*)gvals, r->n_group_by, &e->stats);
    if (!gs) {
        pthread_mutex_unlock(&st->lock);
        CS_INC(&e->stats, oom_dropped);
        return 0;
    }
    gs->last_update = c->ts;
    gs->merge_remote = 1;

    int fired_now = 0;
    double vagg = 0.0;
    switch (c->kind) {
        case CORR_CONTRIB_COUNT: {
            uint32_t add = c->count ? c->count : 1u;
            gs->merge_n += add;
            ev_prune(gs, window_start);
            if (r->type == CORR_EVENT_COUNT)
                fired_now = cmp_threshold((int64_t)gs->ev_len + (int64_t)gs->merge_n, r->cond_op, r->cond_count);
            break;
        }
        case CORR_CONTRIB_SUM: {
            gs->merge_sum += c->numeric;
            gs->merge_n += c->count ? c->count : 1u;
            ev_prune(gs, window_start);
            if (r->type == CORR_VALUE_SUM || r->type == CORR_VALUE_AVG) {
                double sum = gs->merge_sum;
                if (gs->ev_val != NULL) {
                    for (uint32_t i = 0; i < gs->ev_len; i++) sum += gs->ev_val[(gs->ev_head + i) % gs->ev_cap];
                }
                uint32_t n = gs->ev_len + gs->merge_n;
                if (r->type == CORR_VALUE_AVG) {
                    if (n == 0) break;
                    vagg = sum / (double)n;
                } else {
                    vagg = sum;
                }
                fired_now = cond_satisfied_f(r->cond_op, vagg, (double)r->cond_count);
            }
            break;
        }
        case CORR_CONTRIB_DISTINCT:
            if (r->type == CORR_VALUE_COUNT && c->value != NULL)
                fired_now = eval_value_count(r, gs, c->value, e->caps.max_distinct, c->ts, window_start, &e->stats);
            break;
        case CORR_CONTRIB_SEEN:
            gs->merge_seen |= c->seen_mask;
            if (r->type == CORR_TEMPORAL) fired_now = eval_temporal(r, gs, NULL, 0, c->ts, window_start, &e->stats);
            break;
        default:
            break;
    }

    if (!fired_now) {
        pthread_mutex_unlock(&st->lock);
        return 0;
    }
    if (c->ts < gs->fired_until) {
        pthread_mutex_unlock(&st->lock);
        CS_INC(&e->stats, fires_suppressed);
        return 0;
    }
    gs->fired_until = c->ts + timespan * CORR_REFIRE_FRACTION;
    int64_t observed_val;
    const char* observed_vfield = NULL;
    if (r->type == CORR_VALUE_COUNT) {
        observed_val = (int64_t)gs->distinct.count;
        observed_vfield = r->value_field;
    } else if (r->type == CORR_VALUE_SUM || r->type == CORR_VALUE_AVG) {
        observed_val = (int64_t)vagg;
        observed_vfield = r->value_field;
    } else if (r->type == CORR_EVENT_COUNT) {
        observed_val = (int64_t)gs->ev_len + (int64_t)gs->merge_n;
    } else {
        observed_val = (int64_t)r->n_base_rule_ids;
    }
    pthread_mutex_unlock(&st->lock);

    if (max_out == 0 || out == NULL) {
        CS_INC(&e->stats, fires_truncated);
        return 1;
    }
    corr_fire_t* f = &out[0];
    corr_tier_t tier = corr_tier_for(r->type, r->level);
    f->rule_id = r->id;
    f->title = r->title;
    f->type = r->type;
    f->technique = r->mitre;
    f->level = r->level ? r->level : "medium";
    f->tier = tier;
    f->fidelity_weight = corr_tier_weight(tier);
    f->group_by = r->group_by;
    f->n_group = r->n_group_by;
    f->threshold = r->cond_count;
    f->base_rule_ids = r->base_rule_ids;
    f->n_base_rule_ids = r->n_base_rule_ids;
    f->observed = observed_val;
    f->value_field = observed_vfield;
    f->remote = 1;
    if (r->n_group_by > 0 && grp_scratch != NULL && r->n_group_by <= grp_scratch_cap) {
        for (size_t g = 0; g < r->n_group_by; g++) grp_scratch[g] = gvals[g];
        f->group = grp_scratch;
    } else {
        if (r->n_group_by > 0) CS_INC(&e->stats, group_evidence_dropped);
        f->group = NULL;
    }
    return 1;
}

int corr_contrib_kind_for(corr_type_t t) {
    switch (t) {
        case CORR_EVENT_COUNT:
            return (int)CORR_CONTRIB_COUNT;
        case CORR_VALUE_SUM:
        case CORR_VALUE_AVG:
            return (int)CORR_CONTRIB_SUM;
        case CORR_VALUE_COUNT:
            return (int)CORR_CONTRIB_DISTINCT;
        case CORR_TEMPORAL:
            return (int)CORR_CONTRIB_SEEN;
        default:
            return -1;
    }
}

const corr_rule_t* corr_engine_rule_at(const corr_engine_t* e, size_t i) {
    if (!e || i >= e->n_states) return NULL;
    return e->states[i].rule;
}

int corr_rule_hits(const corr_rule_t* r, const uint32_t* rids, size_t n_rids) {
    if (!r || !rids || n_rids == 0) return 0;
    for (size_t b = 0; b < r->n_base_rule_ids; b++) {
        for (size_t k = 0; k < n_rids; k++)
            if (rids[k] == r->base_rule_ids[b]) return 1;
    }
    return 0;
}

static unsigned corr_djb2(const char* s) {
    unsigned h = 5381;
    if (s != NULL) {
        while (*s) h = ((h << 5) + h) + (unsigned char)*s++;
    }
    return h;
}

size_t corr_owner_key(char* buf, size_t cap, const char* corr_id, const char* const* group_vals, size_t n_group) {
    if (!buf || cap == 0) return 0;
    size_t n = 0;
    const char* id = corr_id ? corr_id : "";
    size_t idl = strlen(id);
    if (idl + 1 > cap) return 0;
    memcpy(buf, id, idl);
    n = idl;
    for (size_t i = 0; i < n_group; i++) {
        const char* v = (group_vals && group_vals[i]) ? group_vals[i] : "";
        size_t vl = strlen(v);
        if (n + 1 + vl + 1 > cap) return 0;
        buf[n++] = '\t';
        memcpy(buf + n, v, vl);
        n += vl;
    }
    buf[n] = '\0';
    return n;
}

size_t corr_owner_index(const char* corr_id, const char* const* group_vals, size_t n_group, size_t n_peers) {
    char key[512];
    if (n_peers == 0) return 0;
    if (corr_owner_key(key, sizeof(key), corr_id, group_vals, n_group) == 0) return 0;
    return (size_t)(corr_djb2(key) % (unsigned)n_peers);
}
