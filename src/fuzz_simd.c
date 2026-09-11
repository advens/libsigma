/* fuzz_simd.c
 * Differential fuzz harness proving the libsigma SIMD primitives are
 * bit-identical to their scalar reference on the host arch (NEON on aarch64,
 * SSE4.2 on x86-64).  This is the SIMD parity soundness gate: SIMD paths have shipped
 * SIMD/bounds bugs (the _mm_cmpistri class) precisely because the vector path
 * was never differentially checked against a scalar oracle.  Two properties:
 *
 *   1. sigma_memmem_ci(hay, ndl)  ==  sigma__memmem_ci_scalar(hay, ndl)
 *      for the FIRST (leftmost) match offset, over an adversarial corpus
 *      (empty needle, needle > hay, needle == hay, embedded NUL, high non-ASCII
 *      bytes, mixed case, all-same-byte runs).
 *   2. teddy_confirm(needles, hay)  confirms EXACTLY the needles that are
 *      actually substring-present (per the scalar oracle): sound (no true
 *      needle gated out) AND exact (the 2-byte fingerprint + memmem confirm
 *      leaves no false positive).
 *
 * Deterministic (fixed-seed xorshift), so a failure reproduces from the printed
 * seed and it is CI-stable.  No unit-test framework: exits non-zero on the first
 * mismatch with the reproducing inputs.
 *
 * Build: cc -std=c11 -O2 -Wall -Wextra fuzz_simd.c -o fuzz_simd
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

#include "sigma_match.h" /* sigma_str_t */
#include "sigma_simd.h" /* sigma_memmem_ci, sigma__memmem_ci_scalar */
#include "sigma_teddy.h" /* sigma_teddy_build, teddy_confirm */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <stdbool.h>

#if defined(SIGMA_HAVE_NEON)
    #define ARCH "aarch64 NEON"
#elif defined(SIGMA_HAVE_SSE42)
    #define ARCH "x86-64 SSE4.2/SSSE3"
#else
    #define ARCH "scalar-only (no SIMD to differentially check)"
#endif

/* Deterministic xorshift64 PRNG (no Math.random / time dependence). */
static uint64_t g_rng = 0x9E3779B97F4A7C15ULL;
static uint64_t xrand(void) {
    uint64_t x = g_rng;
    x ^= x << 13;
    x ^= x >> 7;
    x ^= x << 17;
    g_rng = x;
    return x;
}
static uint32_t xrange(uint32_t n) {
    return n ? (uint32_t)(xrand() % n) : 0;
}

/* Fill buf[0..len) with bytes from a small alphabet plus, occasionally, an
 * adversarial byte (NUL, or a high non-ASCII byte).  A small alphabet forces
 * real matches often; the adversarial bytes exercise the exact class that broke
 * _mm_cmpistri (embedded NUL, bytes >= 0x80). */
static void fill_bytes(unsigned char* buf, size_t len) {
    static const char alpha[] = "abcAB C\\/.-1";
    for (size_t i = 0; i < len; i++) {
        uint32_t roll = xrange(100);
        if (roll < 4)
            buf[i] = 0x00; /* embedded NUL */
        else if (roll < 8)
            buf[i] = (unsigned char)(0x80 + xrange(0x80)); /* high, non-ASCII */
        else
            buf[i] = (unsigned char)alpha[xrange(sizeof(alpha) - 1)];
    }
}

static int g_fail = 0;

/* --- property 1: memmem_ci SIMD == scalar (leftmost match) ---------------- */
static void fuzz_memmem(long iters) {
    unsigned char hay[80], ndl[16];
    for (long it = 0; it < iters; it++) {
        size_t hlen = xrange(65); /* 0..64 */
        size_t nlen = xrange(12); /* 0..11 (incl. empty + > hay) */
        fill_bytes(hay, hlen);
        fill_bytes(ndl, nlen);
        /* Bias: sometimes copy a real substring of hay into the needle so
         * matches are common, not just rare random hits. */
        if (nlen && hlen >= nlen && (xrange(2) == 0)) {
            size_t at = xrange((uint32_t)(hlen - nlen + 1));
            memcpy(ndl, hay + at, nlen);
            /* perturb the case of one needle byte to exercise ci-folding */
            if (xrange(2) == 0) ndl[xrange((uint32_t)nlen)] ^= 0x20;
        }
        const char* rs = sigma__memmem_ci_scalar((const char*)hay, hlen, (const char*)ndl, nlen);
        const char* rv = sigma_memmem_ci((const char*)hay, hlen, (const char*)ndl, nlen);
        if (rs != rv) {
            g_fail++;
            fprintf(stderr,
                    "[FAIL] memmem_ci divergence @iter %ld: scalar=%ld simd=%ld "
                    "(hlen=%zu nlen=%zu)\n",
                    it, rs ? (long)(rs - (const char*)hay) : -1, rv ? (long)(rv - (const char*)hay) : -1, hlen, nlen);
            if (g_fail > 8) return;
        }
    }
}

/* teddy_confirm collects confirmed needle indices into this bitset. */
static void mark_cb(void* ctx, uint32_t needle_index) {
    ((unsigned char*)ctx)[needle_index] = 1;
}

/* --- property 2: teddy confirms EXACTLY the present needles --------------- */
static void fuzz_teddy(long iters) {
    for (long it = 0; it < iters; it++) {
        uint32_t nn = 1 + xrange(24); /* 1..24 needles */
        char pool[24 * 10];
        sigma_str_t ndl[24];
        uint32_t off = 0;
        for (uint32_t i = 0; i < nn; i++) {
            uint32_t nlen = 2 + xrange(6); /* 2..7 (teddy needs a 2-byte fp) */
            fill_bytes((unsigned char*)pool + off, nlen);
            /* a NUL inside a needle would truncate the scalar oracle's view via
             * length anyway; both sides use explicit lengths, so keep it. */
            ndl[i].off = off;
            ndl[i].len = nlen;
            off += nlen;
        }
        sigma_teddy_t* t = sigma_teddy_build(ndl, nn, pool);
        if (!t) continue;

        unsigned char hay[96];
        size_t hlen = xrange(97);
        fill_bytes(hay, hlen);
        /* Bias: often plant one needle into the haystack. */
        if (hlen >= 8 && xrange(2) == 0) {
            uint32_t pick = xrange(nn);
            if (ndl[pick].len <= hlen) {
                size_t at = xrange((uint32_t)(hlen - ndl[pick].len + 1));
                memcpy(hay + at, pool + ndl[pick].off, ndl[pick].len);
            }
        }

        unsigned char confirmed[24] = {0};
        sigma_teddy_scratch_t scr;
        if (sigma_teddy_scratch_init(&scr, nn) != 0) {
            sigma_teddy_free(t);
            break;
        }
        teddy_confirm(t, (const char*)hay, hlen, &scr, mark_cb, confirmed);
        sigma_teddy_scratch_free(&scr);

        for (uint32_t i = 0; i < nn; i++) {
            bool present = sigma__memmem_ci_scalar((const char*)hay, hlen, pool + ndl[i].off, ndl[i].len) != NULL;
            if ((bool)confirmed[i] != present) {
                g_fail++;
                fprintf(stderr,
                        "[FAIL] teddy needle %u @iter %ld: confirmed=%d oracle_present=%d "
                        "(hlen=%zu nlen=%u)\n",
                        i, it, confirmed[i], present, hlen, ndl[i].len);
            }
        }
        sigma_teddy_free(t);
        if (g_fail > 8) return;
    }
}

int main(int argc, char** argv) {
    long mem_iters = 2000000, teddy_iters = 200000;
    if (argc > 1) g_rng = strtoull(argv[1], NULL, 0) | 1ULL; /* optional seed */
    printf("libsigma SIMD differential fuzz on %s (seed=0x%llx)\n", ARCH, (unsigned long long)g_rng);

    fuzz_memmem(mem_iters);
    fuzz_teddy(teddy_iters);

    if (g_fail == 0)
        printf("PASSED: memmem_ci (%ld iters) + teddy (%ld iters) SIMD == scalar\n", mem_iters, teddy_iters);
    else
        printf("FAILED: %d SIMD/scalar divergence(s)\n", g_fail);
    return g_fail ? 1 : 0;
}
