/* sigma_teddy.h
 * Teddy-style SIMD literal multi-pattern PREFILTER for the Sigma matcher.
 *
 * Purpose: within a selected category bucket (process/AD/IDS can be ~1460
 * rules), narrow the rules we run the full verify (rule_match) on to only those
 * whose REQUIRED literal is actually present in the event's searchable text.  A
 * Teddy hit is a CANDIDATE, never a decision: rule_match still verifies.  The
 * prefilter is SOUND by construction, a rule with no sound required literal is
 * in the always-verify set and is never gated here.
 *
 * Algorithm (Teddy "fat" / first-bytes fingerprint, over a nibble-LUT SIMD
 * shuffle):
 *
 *   - Each needle is keyed by the case-folded fingerprint of its FIRST THREE
 *     bytes.  A 1-byte filter is far too weak (a real PowerShell command line
 *     lights up ~90% of all needle first-bytes) and a 2-byte one is still badly
 *     skewed: over a 5.5k-needle SigmaHQ artifact the common bigrams put ~13
 *     needles on the chain of an average text position.  Three bytes is what the
 *     compiler's 3-byte minimum needle length allows, and it drops that to well
 *     under one.  Needles too short for a 3-byte key (only reachable from the
 *     differential fuzzer) live in a parallel 2-byte table probed alongside.
 *   - The work is driven by TEXT POSITIONS, not by the needle list: for each
 *     adjacent byte pair in the event text we fold it, hash it, and walk only the
 *     (tiny) chain of needles sharing that 2-byte fingerprint.  O(text) lookups,
 *     each touching a short chain - instead of O(needles) substring searches.
 *   - A fingerprint hit at position p means "a needle may START here", so the
 *     confirm is an ANCHORED compare of the needle against buf+p, O(needle), not
 *     a search of the whole text.  Every occurrence is examined at its own start
 *     position, so anchoring confirms exactly the same needle set a full-text
 *     search would, without re-scanning the text once per fingerprint hit.
 *   - A confirmed needle is stamped in the caller's per-thread scratch and never
 *     re-tested (nor re-marked) for the rest of the event: a needle that occurs
 *     fifty times costs one confirm, not fifty confirms and fifty postings walks.
 *   - The SIMD nibble-LUT (vqtbl1q_u8 / pshufb) provides a coarse first-byte
 *     pre-test that lets the position loop SKIP whole 16-byte runs whose bytes
 *     are never a needle first-byte (the common benign case).  Built at load from
 *     the arch-neutral litidx bytes; the scalar fallback is always correct.
 *   - A confirmed needle marks all its postings rules as candidates.  Confirm
 *     removes fingerprint collisions; SOUND (only ADDS candidates).
 *
 * Case folding: fingerprints + memmem are case-insensitive (Sigma default),
 * mirroring sigma_simd.h.  Single-byte needles cannot have a 2-byte fingerprint -
 * the compiler enforces a >=3-byte minimum, so every needle has >=2 bytes here.
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

#ifndef SIGMA_TEDDY_H
#define SIGMA_TEDDY_H

#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>

#include "sigma_match.h"
#include "sigma_simd.h" /* sigma_memmem_ci, sigma__lc, arch defines */

#if defined(__x86_64__) || defined(_M_X64)
    #include <tmmintrin.h> /* SSSE3 _mm_shuffle_epi8 (pshufb) */
#endif

#define TEDDY_HASH_BITS 14u /* 16384 buckets */
#define TEDDY_HASH_SIZE (1u << TEDDY_HASH_BITS)
#define TEDDY_HASH_MASK (TEDDY_HASH_SIZE - 1u)

static inline char sigma__lc_(char c) {
    return (c >= 'A' && c <= 'Z') ? (char)(c + 32) : c;
}

/* Fold two bytes to a case-insensitive 16-bit fingerprint, then hash to the
 * table index.  A cheap multiplicative mix keeps the 16384 buckets well spread. */
static inline uint32_t teddy_fp16(uint8_t a, uint8_t b) {
    return (uint32_t)((uint8_t)sigma__lc_((char)a)) | ((uint32_t)((uint8_t)sigma__lc_((char)b)) << 8);
}
static inline uint32_t teddy_fp24(uint8_t a, uint8_t b, uint8_t c) {
    return teddy_fp16(a, b) | ((uint32_t)((uint8_t)sigma__lc_((char)c)) << 16);
}
static inline uint32_t teddy_hash(uint32_t fp) {
    uint32_t h = fp * 2654435761u; /* Knuth multiplicative */
    return (h >> (32u - TEDDY_HASH_BITS)) & TEDDY_HASH_MASK;
}

typedef struct {
    uint8_t lo_lut[16]; /* nibble LUT over needle FIRST bytes (coarse skip) */
    uint8_t hi_lut[16];
    uint32_t n_needles;
    uint32_t* fp_head; /* [TEDDY_HASH_SIZE] 3-byte-key chain heads (UINT32_MAX = empty) */
    uint32_t* fp_next; /* [n_needles] */
    uint32_t* fp2_head; /* [TEDDY_HASH_SIZE] 2-byte-key chains, len<3 needles only */
    uint32_t* fp2_next; /* [n_needles] */
    uint16_t* fp_c2; /* [n_needles] folded 3rd byte, TEDDY_NO_C2 when len < 3:
                      * rejects hash-bucket collisions before the full compare. */
    uint32_t n_short; /* needles in the 2-byte table (0 on a compiler artifact) */
    const sigma_str_t* litndl; /* borrowed (db strpool refs) */
    const char* strpool; /* borrowed */
} sigma_teddy_t;

#define TEDDY_NO_C2 0xFFFFu

/* Per-thread confirm scratch: `gen` is bumped once per event, `ndl_gen[k]` holds
 * the generation needle k was last confirmed in.  This is what makes a repeated
 * needle cost one confirm per event instead of one per occurrence; it lives in
 * the caller because the teddy matcher itself is immutable and shared across
 * workers. */
typedef struct {
    uint32_t* ndl_gen; /* [n_needles] */
    uint32_t n_needles;
    uint32_t gen;
    uint64_t chain_steps; /* chain entries examined, for the effectiveness counters */
} sigma_teddy_scratch_t;

static inline int sigma_teddy_scratch_init(sigma_teddy_scratch_t* s, uint32_t n_needles) {
    s->ndl_gen = n_needles ? (uint32_t*)calloc(n_needles, sizeof(uint32_t)) : NULL;
    if (n_needles && !s->ndl_gen) return -1;
    s->n_needles = n_needles;
    s->gen = 0;
    s->chain_steps = 0;
    return 0;
}

static inline void sigma_teddy_scratch_free(sigma_teddy_scratch_t* s) {
    if (!s) return;
    free(s->ndl_gen);
    s->ndl_gen = NULL;
    s->n_needles = 0;
}

/* Start a new event.  Generation 0 is the "never confirmed" value, so a wrap
 * clears the stamps instead of confirming a stale needle. */
static inline void sigma_teddy_scratch_next(sigma_teddy_scratch_t* s) {
    if (++s->gen == 0) {
        if (s->ndl_gen) memset(s->ndl_gen, 0, (size_t)s->n_needles * sizeof(uint32_t));
        s->gen = 1;
    }
}

static inline void teddy_mark_byte(sigma_teddy_t* t, uint8_t c) {
    t->lo_lut[c & 0x0Fu] = 1;
    t->hi_lut[c >> 4] = 1;
}

static inline sigma_teddy_t* sigma_teddy_build(const sigma_str_t* litndl, uint32_t n_litndl, const char* strpool) {
    if (!litndl || n_litndl == 0 || !strpool) return NULL;
    sigma_teddy_t* t = (sigma_teddy_t*)calloc(1, sizeof(*t));
    if (!t) return NULL;
    t->fp_head = (uint32_t*)malloc((size_t)TEDDY_HASH_SIZE * sizeof(uint32_t));
    t->fp_next = (uint32_t*)malloc((size_t)n_litndl * sizeof(uint32_t));
    t->fp2_head = (uint32_t*)malloc((size_t)TEDDY_HASH_SIZE * sizeof(uint32_t));
    t->fp2_next = (uint32_t*)malloc((size_t)n_litndl * sizeof(uint32_t));
    t->fp_c2 = (uint16_t*)malloc((size_t)n_litndl * sizeof(uint16_t));
    if (!t->fp_head || !t->fp_next || !t->fp2_head || !t->fp2_next || !t->fp_c2) {
        free(t->fp_head);
        free(t->fp_next);
        free(t->fp2_head);
        free(t->fp2_next);
        free(t->fp_c2);
        free(t);
        return NULL;
    }
    t->n_needles = n_litndl;
    t->litndl = litndl;
    t->strpool = strpool;
    for (uint32_t i = 0; i < TEDDY_HASH_SIZE; i++) t->fp_head[i] = UINT32_MAX;
    for (uint32_t i = 0; i < TEDDY_HASH_SIZE; i++) t->fp2_head[i] = UINT32_MAX;

    for (uint32_t i = 0; i < n_litndl; i++) {
        const char* p = strpool + litndl[i].off; /* len>=2 guaranteed (min-len>=3) */
        t->fp_next[i] = UINT32_MAX;
        t->fp2_next[i] = UINT32_MAX;
        if (litndl[i].len >= 3) {
            uint32_t h = teddy_hash(teddy_fp24((uint8_t)p[0], (uint8_t)p[1], (uint8_t)p[2]));
            t->fp_next[i] = t->fp_head[h];
            t->fp_head[h] = i;
            t->fp_c2[i] = (uint16_t)(uint8_t)sigma__lc_(p[2]);
        } else {
            uint32_t h = teddy_hash(teddy_fp16((uint8_t)p[0], (uint8_t)p[1]));
            t->fp2_next[i] = t->fp2_head[h];
            t->fp2_head[h] = i;
            t->fp_c2[i] = TEDDY_NO_C2;
            t->n_short++;
        }
        /* coarse first-byte LUT: both cases */
        char cl = sigma__lc_(p[0]);
        char cu = (cl >= 'a' && cl <= 'z') ? (char)(cl - 32) : cl;
        teddy_mark_byte(t, (uint8_t)cl);
        teddy_mark_byte(t, (uint8_t)cu);
    }
    return t;
}

/* Same matcher, but only `ids[0..n_ids)` (global needle indices) are chained.
 * Needle index in confirm callbacks stays the global litndl index, so postings
 * lookup is unchanged.  Empty subset -> NULL. */
static inline sigma_teddy_t* sigma_teddy_build_subset(
    const sigma_str_t* litndl, uint32_t n_litndl, const char* strpool, const uint32_t* ids, uint32_t n_ids) {
    if (!litndl || n_litndl == 0 || !strpool || !ids || n_ids == 0) return NULL;
    sigma_teddy_t* t = (sigma_teddy_t*)calloc(1, sizeof(*t));
    if (!t) return NULL;
    t->fp_head = (uint32_t*)malloc((size_t)TEDDY_HASH_SIZE * sizeof(uint32_t));
    t->fp_next = (uint32_t*)malloc((size_t)n_litndl * sizeof(uint32_t));
    t->fp2_head = (uint32_t*)malloc((size_t)TEDDY_HASH_SIZE * sizeof(uint32_t));
    t->fp2_next = (uint32_t*)malloc((size_t)n_litndl * sizeof(uint32_t));
    t->fp_c2 = (uint16_t*)malloc((size_t)n_litndl * sizeof(uint16_t));
    if (!t->fp_head || !t->fp_next || !t->fp2_head || !t->fp2_next || !t->fp_c2) {
        free(t->fp_head);
        free(t->fp_next);
        free(t->fp2_head);
        free(t->fp2_next);
        free(t->fp_c2);
        free(t);
        return NULL;
    }
    t->n_needles = n_litndl;
    t->litndl = litndl;
    t->strpool = strpool;
    for (uint32_t i = 0; i < TEDDY_HASH_SIZE; i++) t->fp_head[i] = UINT32_MAX;
    for (uint32_t i = 0; i < TEDDY_HASH_SIZE; i++) t->fp2_head[i] = UINT32_MAX;
    for (uint32_t i = 0; i < n_litndl; i++) {
        t->fp_next[i] = UINT32_MAX;
        t->fp2_next[i] = UINT32_MAX;
        t->fp_c2[i] = TEDDY_NO_C2;
    }
    for (uint32_t n = 0; n < n_ids; n++) {
        uint32_t i = ids[n];
        if (i >= n_litndl) continue;
        const char* p = strpool + litndl[i].off;
        if (litndl[i].len >= 3) {
            uint32_t h = teddy_hash(teddy_fp24((uint8_t)p[0], (uint8_t)p[1], (uint8_t)p[2]));
            t->fp_next[i] = t->fp_head[h];
            t->fp_head[h] = i;
            t->fp_c2[i] = (uint16_t)(uint8_t)sigma__lc_(p[2]);
        } else {
            uint32_t h = teddy_hash(teddy_fp16((uint8_t)p[0], (uint8_t)p[1]));
            t->fp2_next[i] = t->fp2_head[h];
            t->fp2_head[h] = i;
            t->fp_c2[i] = TEDDY_NO_C2;
            t->n_short++;
        }
        char cl = sigma__lc_(p[0]);
        char cu = (cl >= 'a' && cl <= 'z') ? (char)(cl - 32) : cl;
        teddy_mark_byte(t, (uint8_t)cl);
        teddy_mark_byte(t, (uint8_t)cu);
    }
    return t;
}

static inline void sigma_teddy_free(sigma_teddy_t* t) {
    if (!t) return;
    free(t->fp_head);
    free(t->fp_next);
    free(t->fp2_head);
    free(t->fp2_next);
    free(t->fp_c2);
    free(t);
}

/* SIMD coarse pre-test: does this 16-byte chunk contain ANY interesting (needle
 * first-) byte?  0 => skip the whole chunk in the position loop. */
#if defined(SIGMA_HAVE_NEON)
static inline int teddy_chunk_interesting(uint8x16_t lo_lut, uint8x16_t hi_lut, uint8x16_t lo_mask, const char* p) {
    uint8x16_t chunk = vld1q_u8((const uint8_t*)p);
    uint8x16_t lo = vqtbl1q_u8(lo_lut, vandq_u8(chunk, lo_mask));
    uint8x16_t hi = vqtbl1q_u8(hi_lut, vshrq_n_u8(chunk, 4));
    return vmaxvq_u8(vandq_u8(lo, hi)) != 0;
}
#elif defined(SIGMA_HAVE_SSE42)
    /* The intrinsics below are SSSE3 (_mm_shuffle_epi8); enable the feature per
     * function so the TU compiles under a baseline x86-64 target.  GCC needs this
     * too (not just clang), without it gcc-13 errors "inlining failed ...
     * target specific option mismatch" on the Linux build, which (unlike the
     * FreeBSD CPUTYPE=x86-64-v2 build) does not enable SSSE3/SSE4.2 globally. */
    #if defined(__GNUC__)
__attribute__((target("ssse3,sse4.2")))
    #endif
static inline int
teddy_chunk_interesting(__m128i lo_lut, __m128i hi_lut, __m128i lo_mask, const char* p) {
    __m128i chunk = _mm_loadu_si128((const __m128i*)(const void*)p);
    __m128i lo = _mm_shuffle_epi8(lo_lut, _mm_and_si128(chunk, lo_mask));
    __m128i hin = _mm_and_si128(_mm_srli_epi16(chunk, 4), lo_mask);
    __m128i hi = _mm_shuffle_epi8(hi_lut, hin);
    return _mm_movemask_epi8(_mm_cmpeq_epi8(_mm_and_si128(lo, hi), _mm_setzero_si128())) != 0xFFFF;
}
#endif

/* Mark e->cand for every rule whose required needle is confirmed present in buf.
 * `mark` is invoked with (ctx, needle_index) ONCE for each CONFIRMED needle. */
typedef void (*teddy_mark_fn)(void* ctx, uint32_t needle_index);

/* Anchored case-insensitive compare: does needle `n` (nlen bytes) start at `p`?
 * The chain walk reaches this only for needles sharing a hash bucket, so bytes
 * 0..1 still have to be compared (a bucket is not a fingerprint). */
static inline int teddy_eq_ci(const char* p, const char* n, uint32_t nlen) {
    for (uint32_t i = 0; i < nlen; i++)
        if (sigma__lc_(p[i]) != sigma__lc_(n[i])) return 0;
    return 1;
}

/* Walk one chain and confirm, at `pos`, every not-yet-confirmed needle on it. */
static inline void teddy_walk(const sigma_teddy_t* t,
                              const char* buf,
                              size_t avail,
                              size_t pos,
                              uint32_t head,
                              const uint32_t* next,
                              sigma_teddy_scratch_t* scr,
                              teddy_mark_fn mark,
                              void* ctx) {
    for (uint32_t k = head; k != UINT32_MAX; k = next[k]) {
        scr->chain_steps++;
        if (scr->ndl_gen[k] == scr->gen) continue; /* already confirmed for this event */
        const sigma_str_t* n = &t->litndl[k];
        if (avail < n->len) continue;
        const uint16_t c2 = t->fp_c2[k];
        if (c2 != TEDDY_NO_C2 && (uint16_t)(uint8_t)sigma__lc_(buf[pos + 2]) != c2) continue;
        if (!teddy_eq_ci(buf + pos, t->strpool + n->off, n->len)) continue;
        scr->ndl_gen[k] = scr->gen;
        mark(ctx, k);
    }
}

/* Probe both fingerprint tables at `pos`.  A needle can only start here if its
 * whole key fits, so the 3-byte table is skipped in the last two bytes of the
 * text; the 2-byte table stays empty unless a caller built needles shorter than
 * the compiler's 3-byte minimum. */
static inline void teddy_probe_at(const sigma_teddy_t* t,
                                  const char* buf,
                                  size_t len,
                                  size_t pos,
                                  sigma_teddy_scratch_t* scr,
                                  teddy_mark_fn mark,
                                  void* ctx) {
    const size_t avail = len - pos;
    if (avail >= 3) {
        uint32_t h = teddy_hash(teddy_fp24((uint8_t)buf[pos], (uint8_t)buf[pos + 1], (uint8_t)buf[pos + 2]));
        teddy_walk(t, buf, avail, pos, t->fp_head[h], t->fp_next, scr, mark, ctx);
    }
    if (t->n_short) {
        uint32_t h2 = teddy_hash(teddy_fp16((uint8_t)buf[pos], (uint8_t)buf[pos + 1]));
        teddy_walk(t, buf, avail, pos, t->fp2_head[h2], t->fp2_next, scr, mark, ctx);
    }
}

/* Same target-feature requirement as teddy_chunk_interesting: this function
 * uses SSE2/SSSE3 intrinsics directly on the x86 path, so it must carry the
 * feature attribute on GCC/clang when SIMD is the SSE variant (never on NEON -
 * the attr is x86-only).  Emitted out-of-line into a baseline caller; the
 * SIMD body keeps the intrinsics. */
#if defined(SIGMA_HAVE_SSE42) && defined(__GNUC__)
__attribute__((target("ssse3,sse4.2")))
#endif
static inline void
teddy_confirm(
    const sigma_teddy_t* t, const char* buf, size_t len, sigma_teddy_scratch_t* scr, teddy_mark_fn mark, void* ctx) {
    if (len < 2 || !scr->ndl_gen) return;
    sigma_teddy_scratch_next(scr);
    const size_t last_pair = len - 1; /* last position with a [p,p+1] pair */
    size_t i = 0;

#if defined(SIGMA_HAVE_NEON) || defined(SIGMA_HAVE_SSE42)
    #if defined(SIGMA_HAVE_NEON)
    const uint8x16_t lo_lut = vld1q_u8(t->lo_lut);
    const uint8x16_t hi_lut = vld1q_u8(t->hi_lut);
    const uint8x16_t lo_mask = vdupq_n_u8(0x0F);
    #else
    const __m128i lo_lut = _mm_loadu_si128((const __m128i*)(const void*)t->lo_lut);
    const __m128i hi_lut = _mm_loadu_si128((const __m128i*)(const void*)t->hi_lut);
    const __m128i lo_mask = _mm_set1_epi8(0x0F);
    #endif
    /* Sweep 16-byte chunks; skip a chunk only when NONE of its 16 bytes is a
     * needle first-byte (so no [p,p+1] starting in it can begin a needle).  The
     * pair starting at the chunk's last byte spans into the next chunk, so we
     * still examine positions [i .. i+15] inclusive when the chunk survives. */
    for (; i + 16 <= len;) {
        if (!teddy_chunk_interesting(lo_lut, hi_lut, lo_mask, buf + i)) {
            i += 16;
            continue;
        }
        size_t end = i + 16; /* examine pairs whose first byte is in [i,end) */
        for (size_t p = i; p < end && p < last_pair; p++) teddy_probe_at(t, buf, len, p, scr, mark, ctx);
        i = end;
    }
#endif
    /* Scalar tail (and the whole text on a non-SIMD build). */
    for (; i < last_pair; i++) teddy_probe_at(t, buf, len, i, scr, mark, ctx);
}

#endif /* SIGMA_TEDDY_H */
