/* sigma_format.h
 * On-disk binary layout for a compiled Sigma rule artifact (`.sigmac`), plus
 * the serializer / zero-copy loader.  This is the artifact the Sigma compiler
 * emits and the matcher loads (and can hot-reload).  Sigma YAML is compiled to
 * this binary form; YAML is never parsed at match time.
 *
 * Layout (all section offsets 8-byte aligned; little-endian; producer and
 * consumer are same-arch amd64/aarch64, both LE):
 *
 *   [sigma_hdr_t]                      fixed header, 8-aligned
 *   [fields : sigma_str_t   x n_fields]   interned field-name refs (-> strpool;
 *                                         each NAME is NUL-TERMINATED in the
 *                                         strpool, strpool[off+len]=='\0')
 *   [values : sigma_str_t   x n_values]   interned literal-operand refs
 *   [preds  : sigma_pred_t  x n_preds ]
 *   [sels   : sigma_sel_t   x n_sels  ]
 *   [cond   : sigma_ctok_t  x n_cond  ]
 *   [rules  : sigma_rule_t  x n_rules ]
 *   [cidrs  : sigma_cidr_t  x n_cidrs ]
 *   [bkeys  : sigma_str_t   x n_bkeys ]   bucket keys (ECS event.category)
 *   [bkts   : sigma_bucket_t x n_bkeys]   per-key [rule_idx slice] descriptors
 *   [bidx   : uint32_t      x n_bidx  ]   flat rule-INDEX pool the slices point into
 *   [litndl : sigma_str_t   x n_litndl]   case-folded prefilter needles
 *   [litpost: sigma_litpost_t x n_litndl] per-needle [rule_idx slice] postings
 *   [litpref: sigma_litref_t x n_litpost_ref] flat postings pool
 *   [litav  : uint32_t      x n_litav ]   always-verify rule indices
 *   [rclause: uint8_t       x n_rules ]   witness clauses per rule
 *   [fwit   : sigma_fwit_t  x n_fwit  ]   numeric/CIDR CNF atoms (v5; 0 on v4)
 *   [strpool: char          x strpool_len]
 *   [crc32c : uint32_t]                CRC32C over [0 .. total_size-4)
 *
 * The bucket index is an OPTIONAL match-time accelerator
 * (n_buckets==0 => the matcher falls back to the full linear scan).  See
 * sigma_match.c for how the matcher narrows candidates to the event's category
 * bucket + the always-verify bucket.
 *
 * FIELD-NAME contract (memcpy-free lookup): every entry of the
 * `fields` table names a string in the strpool that is NUL-TERMINATED, the
 * byte at strpool[fields[i].off + fields[i].len] is '\0' (the length still
 * EXCLUDES the terminator).  This lets the matcher pass `strpool + off`
 * straight to the caller's C-string field lookup with no bounce buffer.  The
 * loader VALIDATES this and rejects a non-terminated
 * artifact (SIGMA_ERR_RANGE).  VALUES / titles / mitre / bucket-key strings are
 * length-only and need NOT be terminated.
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

#ifndef SIGMA_FORMAT_H
#define SIGMA_FORMAT_H

#include <stdint.h>
#include <stddef.h>
#include "sigma_match.h"

#ifdef __cplusplus
extern "C" {
#endif

#define SIGMA_MAGIC 0x53474D41u /* "SGMA" (LE) */
/* The artifact carries the logsource/category bucket index (bkeys/buckets/
 * bucket_idx) AND the SIMD literal-prefilter index (litidx): case-folded needles
 * -> per-needle rule-id postings + an always-verify rule-index set, from which
 * the matcher builds a Teddy multi-pattern matcher at load time to thin a large
 * (process/AD/IDS) bucket WITHIN the bucket scan.  Field NAME strpool entries
 * are NUL-terminated (the loader validates this).  Version 5 is FROZEN:
 * later layout changes bump SIGMA_FORMAT_VERSION and keep a loader compat
 * path.  The loader still accepts version 4 (no field-witness section). */
#define SIGMA_FORMAT_VERSION 5u
#define SIGMA_FORMAT_VERSION_MIN 4u
#define SIGMA_HDR_V4_SIZE 136u

typedef struct {
    uint32_t magic; /* SIGMA_MAGIC */
    uint32_t version; /* SIGMA_FORMAT_VERSION_MIN .. SIGMA_FORMAT_VERSION */
    uint64_t total_size; /* file length, includes trailing CRC32C */
    uint32_t n_fields, off_fields;
    uint32_t n_values, off_values;
    uint32_t n_preds, off_preds;
    uint32_t n_sels, off_sels;
    uint32_t n_cond, off_cond;
    uint32_t n_rules, off_rules;
    uint32_t strpool_len, off_strpool;
    uint32_t n_cidrs, off_cidrs;
    uint32_t flags; /* reserved (0) */
    /* --- logsource/category bucket index -----------------------
     * `n_buckets` counts BOTH the bkeys (sigma_str_t) and the parallel buckets
     * (sigma_bucket_t) arrays; off_buckets points at the descriptor array. */
    uint32_t n_buckets, off_bkeys;
    uint32_t off_buckets;
    uint32_t n_bucket_idx, off_bucket_idx;
    /* --- SIMD literal-prefilter index (litidx) -----------------
     * `n_litndl` counts BOTH the litndl (sigma_str_t, case-folded needles) and
     * the parallel litpost (sigma_litpost_t) arrays; off_litpost_ref points at
     * the flat postings pool (n_litpost_ref sigma_litref_t entries); litav is
     * the always-verify rule-index list (n_litav entries); off_rule_clauses
     * points at the per-rule witness-clause counts (n_rules bytes). */
    uint32_t n_litndl, off_litndl;
    uint32_t off_litpost;
    uint32_t n_litpost_ref, off_litpost_ref;
    uint32_t n_litav, off_litav;
    uint32_t off_rule_clauses; /* uint8_t x n_rules, 0 when absent */
    /* v5: numeric/CIDR field witnesses (0 / 0 on a v4 file). */
    uint32_t n_fwit, off_fwit;
} sigma_hdr_t;

/* Lock the on-disk struct sizes so a layout change is a compile error. */
_Static_assert(sizeof(sigma_hdr_t) == 144, "sigma_hdr_t layout drift");
_Static_assert(sizeof(sigma_str_t) == 8, "sigma_str_t layout drift");
_Static_assert(sizeof(sigma_pred_t) == 24, "sigma_pred_t layout drift");
_Static_assert(sizeof(sigma_sel_t) == 8, "sigma_sel_t layout drift");
_Static_assert(sizeof(sigma_ctok_t) == 8, "sigma_ctok_t layout drift");
_Static_assert(sizeof(sigma_rule_t) == 32, "sigma_rule_t layout drift");
_Static_assert(sizeof(sigma_cidr_t) == 20, "sigma_cidr_t layout drift");
_Static_assert(sizeof(sigma_bucket_t) == 8, "sigma_bucket_t layout drift");
_Static_assert(sizeof(sigma_litpost_t) == 8, "sigma_litpost_t layout drift");
_Static_assert(sizeof(sigma_litref_t) == 8, "sigma_litref_t layout drift");
_Static_assert(sizeof(sigma_fwit_t) == 16, "sigma_fwit_t layout drift");

typedef enum {
    SIGMA_OK = 0,
    SIGMA_ERR_NOMEM = -1,
    SIGMA_ERR_IO = -2,
    SIGMA_ERR_MAGIC = -3,
    SIGMA_ERR_VERSION = -4,
    SIGMA_ERR_SIZE = -5,
    SIGMA_ERR_CRC = -6,
    SIGMA_ERR_RANGE = -7, /* an internal reference is out of bounds */
    SIGMA_ERR_REGEX = -8, /* a SIGMA_OP_RE pattern failed to compile */
} sigma_status_t;

/* Serialize a db to a freshly malloc'd buffer (*out_buf, *out_len).
 * Caller owns *out_buf (free()).  Returns SIGMA_OK or a negative status. */
int sigma_db_serialize(const sigma_db_t* db, uint8_t** out_buf, size_t* out_len);

/* Load + validate (magic/version/size/CRC32C/internal ranges) a db from a
 * buffer.  On SIGMA_OK the db takes ownership of buf (freed by sigma_db_free,
 * zero-copy: db members point INTO buf).  On error the caller still owns buf. */
int sigma_db_load_buffer(uint8_t* buf, size_t len, sigma_db_t* out);

/* Read a .sigmac file and load it.  On error nothing is left allocated. */
int sigma_db_load_file(const char* path, sigma_db_t* out);

#ifdef __cplusplus
}
#endif

#endif /* SIGMA_FORMAT_H */
