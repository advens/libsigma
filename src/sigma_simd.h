/* sigma_simd.h
 * Hardware-accelerated primitives for the Sigma matcher, with a portable scalar fallback.
 * Self-contained (no external dependencies):
 *   - sigma_crc32c()   : CRC32C (Castagnoli), SSE4.2 / ARMv8 CRC / scalar.
 *   - sigma_memmem_ci(): case-insensitive substring, SSE2/SSE4.2 / NEON / scalar.
 *
 * The x86-64 path is wrapped in `#pragma GCC target("sse4.2")` (the standard
 * gcc pattern) so the intrinsics compile even when the global
 * -march does not enable SSE4.2; on aarch64 NEON + ARMv8 CRC are baseline.
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

#ifndef SIGMA_SIMD_H
#define SIGMA_SIMD_H

#include <stdint.h>
#include <stddef.h>

#if defined(__x86_64__) || defined(_M_X64)
    #define SIGMA_HAVE_SSE42 1
#elif defined(__aarch64__) || defined(_M_ARM64)
    #define SIGMA_HAVE_NEON 1
#endif
#ifdef SIGMA_FORCE_SCALAR
    #undef SIGMA_HAVE_SSE42
    #undef SIGMA_HAVE_NEON
#endif

/* ---------------------------------------------------------------------------
 * Shared scalar helpers (used directly and as the SIMD tail/fallback).
 * ------------------------------------------------------------------------- */
static inline char sigma__lc(char c) {
    return (c >= 'A' && c <= 'Z') ? (char)(c + 32) : c;
}

static inline const char* sigma__memmem_ci_scalar(const char* hay, size_t hlen, const char* ndl, size_t nlen) {
    if (nlen == 0) return hay;
    if (nlen > hlen) return NULL;
    const size_t last = hlen - nlen;
    const char n0 = sigma__lc(ndl[0]);
    for (size_t i = 0; i <= last; i++) {
        if (sigma__lc(hay[i]) != n0) continue;
        size_t j = 1;
        while (j < nlen && sigma__lc(hay[i + j]) == sigma__lc(ndl[j])) j++;
        if (j == nlen) return hay + i;
    }
    return NULL;
}

/* Software CRC32C (Castagnoli, reflected 0x82F63B78), used as the fallback
 * wherever the hardware CRC instructions are unavailable (e.g. an ARMv8.0 core
 * without the optional CRC extension). Always correct, never crashes. */
static inline uint32_t sigma__crc32c_sw(uint32_t crc, const void* data, size_t len) {
    const uint8_t* p = (const uint8_t*)data;
    crc = ~crc;
    while (len--) {
        crc ^= *p++;
        for (int k = 0; k < 8; k++) crc = (crc >> 1) ^ (0x82F63B78u & (uint32_t)(-(int32_t)(crc & 1)));
    }
    return ~crc;
}

/* ===========================================================================
 * x86-64, SSE4.2 (CRC32C) + SSE2 first-byte scan
 * ========================================================================= */
#if defined(SIGMA_HAVE_SSE42)
    /* gcc needs the target set before <nmmintrin.h> so the intrinsics are declared;
     * clang ignores `#pragma GCC target` (and would warn), so it uses a per-function
     * target attribute instead. Either path also works when -march already enables
     * SSE4.2 (as the amd64 port build does with x86-64-v2). */
    #if defined(__GNUC__) && !defined(__clang__)
        #pragma GCC push_options
        #pragma GCC target("sse4.2")
    #endif
    #include <nmmintrin.h>
    #if defined(__clang__)
        #define SIGMA_TARGET_SSE42 __attribute__((target("sse4.2")))
    #else
        #define SIGMA_TARGET_SSE42
    #endif

SIGMA_TARGET_SSE42
static inline uint32_t sigma_crc32c(uint32_t crc, const void* data, size_t len) {
    const uint8_t* p = (const uint8_t*)data;
    crc = ~crc;
    while (len >= 8) {
        uint64_t v;
        __builtin_memcpy(&v, p, 8);
        crc = (uint32_t)_mm_crc32_u64(crc, v);
        p += 8;
        len -= 8;
    }
    if (len >= 4) {
        uint32_t v;
        __builtin_memcpy(&v, p, 4);
        crc = _mm_crc32_u32(crc, v);
        p += 4;
        len -= 4;
    }
    while (len--) crc = _mm_crc32_u8(crc, *p++);
    return ~crc;
}

SIGMA_TARGET_SSE42
static inline const char* sigma_memmem_ci(const char* hay, size_t hlen, const char* ndl, size_t nlen) {
    if (nlen == 0) return hay;
    if (nlen > hlen) return NULL;
    const char n0l = sigma__lc(ndl[0]);
    const char n0u = (n0l >= 'a' && n0l <= 'z') ? (char)(n0l - 32) : n0l;
    const __m128i vlo = _mm_set1_epi8(n0l);
    const __m128i vup = _mm_set1_epi8(n0u);
    const size_t last = hlen - nlen;
    size_t i = 0;
    for (; i + 16 <= hlen; i += 16) {
        /* unaligned load, cast via void* to silence -Wcast-align */
        __m128i blk = _mm_loadu_si128((const __m128i*)(const void*)(hay + i));
        __m128i m = _mm_or_si128(_mm_cmpeq_epi8(blk, vlo), _mm_cmpeq_epi8(blk, vup));
        int mask = _mm_movemask_epi8(m);
        while (mask) {
            int b = __builtin_ctz(mask);
            size_t pos = i + (size_t)b;
            if (pos > last) return NULL;
            size_t j = 1;
            while (j < nlen && sigma__lc(hay[pos + j]) == sigma__lc(ndl[j])) j++;
            if (j == nlen) return hay + pos;
            mask &= mask - 1;
        }
    }
    if (i <= last) return sigma__memmem_ci_scalar(hay + i, hlen - i, ndl, nlen);
    return NULL;
}

    #if defined(__GNUC__) && !defined(__clang__)
        #pragma GCC pop_options
    #endif
    #undef SIGMA_TARGET_SSE42

/* ===========================================================================
 * aarch64, ARMv8 CRC32C + NEON first-byte scan
 * ========================================================================= */
#elif defined(SIGMA_HAVE_NEON)
    #include <arm_neon.h> /* Advanced SIMD is mandatory on aarch64 */

    /* CRC32 is OPTIONAL in ARMv8.0, only use the hardware instructions when the
     * compiler advertises the feature (else the always_inline __crc32c* intrinsics
     * fail to compile, and forcing the target would SIGILL on a CRC-less core). */
    #if defined(__ARM_FEATURE_CRC32)
        #include <arm_acle.h>
static inline uint32_t sigma_crc32c(uint32_t crc, const void* data, size_t len) {
    const uint8_t* p = (const uint8_t*)data;
    crc = ~crc;
    while (len >= 8) {
        uint64_t v;
        __builtin_memcpy(&v, p, 8);
        crc = __crc32cd(crc, v);
        p += 8;
        len -= 8;
    }
    if (len >= 4) {
        uint32_t v;
        __builtin_memcpy(&v, p, 4);
        crc = __crc32cw(crc, v);
        p += 4;
        len -= 4;
    }
    while (len--) crc = __crc32cb(crc, *p++);
    return ~crc;
}
    #else
static inline uint32_t sigma_crc32c(uint32_t crc, const void* data, size_t len) {
    return sigma__crc32c_sw(crc, data, len);
}
    #endif

static inline const char* sigma_memmem_ci(const char* hay, size_t hlen, const char* ndl, size_t nlen) {
    if (nlen == 0) return hay;
    if (nlen > hlen) return NULL;
    const char n0l = sigma__lc(ndl[0]);
    const char n0u = (n0l >= 'a' && n0l <= 'z') ? (char)(n0l - 32) : n0l;
    const uint8x16_t vlo = vdupq_n_u8((uint8_t)n0l);
    const uint8x16_t vup = vdupq_n_u8((uint8_t)n0u);
    const size_t last = hlen - nlen;
    size_t i = 0;
    for (; i + 16 <= hlen; i += 16) {
        uint8x16_t blk = vld1q_u8((const uint8_t*)(hay + i));
        uint8x16_t m = vorrq_u8(vceqq_u8(blk, vlo), vceqq_u8(blk, vup));
        if (vmaxvq_u8(m) == 0) continue;
        for (int b = 0; b < 16; b++) {
            size_t pos = i + (size_t)b;
            if (pos > last) return NULL;
            if (sigma__lc(hay[pos]) != n0l) continue;
            size_t j = 1;
            while (j < nlen && sigma__lc(hay[pos + j]) == sigma__lc(ndl[j])) j++;
            if (j == nlen) return hay + pos;
        }
    }
    if (i <= last) return sigma__memmem_ci_scalar(hay + i, hlen - i, ndl, nlen);
    return NULL;
}

/* ===========================================================================
 * Portable scalar fallback
 * ========================================================================= */
#else

static inline uint32_t sigma_crc32c(uint32_t crc, const void* data, size_t len) {
    return sigma__crc32c_sw(crc, data, len);
}

static inline const char* sigma_memmem_ci(const char* hay, size_t hlen, const char* ndl, size_t nlen) {
    return sigma__memmem_ci_scalar(hay, hlen, ndl, nlen);
}

#endif

#endif /* SIGMA_SIMD_H */
