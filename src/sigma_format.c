/* sigma_format.c
 * Serializer + zero-copy validating loader for the .sigmac artifact.
 * See sigma_format.h for the layout.
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

#include "sigma_format.h"
#include "sigma_simd.h"

#include <stdlib.h>
#include <string.h>
#include <stdio.h>

static inline size_t align8(size_t x) {
    return (x + 7u) & ~(size_t)7u;
}

int sigma_db_serialize(const sigma_db_t* db, uint8_t** out_buf, size_t* out_len) {
    if (!db || !out_buf || !out_len) return SIGMA_ERR_IO;

    const size_t off_fields = align8(sizeof(sigma_hdr_t));
    const size_t off_values = align8(off_fields + (size_t)db->n_fields * sizeof(sigma_str_t));
    const size_t off_preds = align8(off_values + (size_t)db->n_values * sizeof(sigma_str_t));
    const size_t off_sels = align8(off_preds + (size_t)db->n_preds * sizeof(sigma_pred_t));
    const size_t off_cond = align8(off_sels + (size_t)db->n_sels * sizeof(sigma_sel_t));
    const size_t off_rules = align8(off_cond + (size_t)db->n_cond * sizeof(sigma_ctok_t));
    const size_t off_cidrs = align8(off_rules + (size_t)db->n_rules * sizeof(sigma_rule_t));
    /* Bucket index sections, emitted only when present. */
    const size_t off_bkeys = align8(off_cidrs + (size_t)db->n_cidrs * sizeof(sigma_cidr_t));
    const size_t off_buckets = align8(off_bkeys + (size_t)db->n_buckets * sizeof(sigma_str_t));
    const size_t off_bidx = align8(off_buckets + (size_t)db->n_buckets * sizeof(sigma_bucket_t));
    /* Literal-prefilter (litidx) sections, emitted only when present. */
    const size_t off_litndl = align8(off_bidx + (size_t)db->n_bucket_idx * sizeof(uint32_t));
    const size_t off_litpost = align8(off_litndl + (size_t)db->n_litndl * sizeof(sigma_str_t));
    const size_t off_litpost_ref = align8(off_litpost + (size_t)db->n_litndl * sizeof(sigma_litpost_t));
    const size_t off_litav = align8(off_litpost_ref + (size_t)db->n_litpost_ref * sizeof(sigma_litref_t));
    const size_t off_rule_clauses = align8(off_litav + (size_t)db->n_litav * sizeof(uint32_t));
    const size_t off_fwit = align8(off_rule_clauses + (db->rule_clauses ? (size_t)db->n_rules : 0u));
    const size_t off_strpool = align8(off_fwit + (size_t)db->n_fwit * sizeof(sigma_fwit_t));
    const size_t body_end = off_strpool + db->strpool_len;
    const size_t total = body_end + sizeof(uint32_t); /* trailing CRC */

    uint8_t* buf = calloc(1, total);
    if (!buf) return SIGMA_ERR_NOMEM;

    sigma_hdr_t h;
    memset(&h, 0, sizeof(h));
    h.magic = SIGMA_MAGIC;
    h.version = SIGMA_FORMAT_VERSION;
    h.total_size = total;
    h.n_fields = db->n_fields;
    h.off_fields = (uint32_t)off_fields;
    h.n_values = db->n_values;
    h.off_values = (uint32_t)off_values;
    h.n_preds = db->n_preds;
    h.off_preds = (uint32_t)off_preds;
    h.n_sels = db->n_sels;
    h.off_sels = (uint32_t)off_sels;
    h.n_cond = db->n_cond;
    h.off_cond = (uint32_t)off_cond;
    h.n_rules = db->n_rules;
    h.off_rules = (uint32_t)off_rules;
    h.n_cidrs = db->n_cidrs;
    h.off_cidrs = (uint32_t)off_cidrs;
    h.strpool_len = db->strpool_len;
    h.off_strpool = (uint32_t)off_strpool;
    h.n_buckets = db->n_buckets;
    h.off_bkeys = db->n_buckets ? (uint32_t)off_bkeys : 0u;
    h.off_buckets = db->n_buckets ? (uint32_t)off_buckets : 0u;
    h.n_bucket_idx = db->n_bucket_idx;
    h.off_bucket_idx = db->n_bucket_idx ? (uint32_t)off_bidx : 0u;
    h.n_litndl = db->n_litndl;
    h.off_litndl = db->n_litndl ? (uint32_t)off_litndl : 0u;
    h.off_litpost = db->n_litndl ? (uint32_t)off_litpost : 0u;
    h.n_litpost_ref = db->n_litpost_ref;
    h.off_litpost_ref = db->n_litpost_ref ? (uint32_t)off_litpost_ref : 0u;
    h.n_litav = db->n_litav;
    h.off_litav = db->n_litav ? (uint32_t)off_litav : 0u;
    h.off_rule_clauses = (db->rule_clauses && db->n_rules) ? (uint32_t)off_rule_clauses : 0u;
    h.n_fwit = db->n_fwit;
    h.off_fwit = db->n_fwit ? (uint32_t)off_fwit : 0u;
    memcpy(buf, &h, sizeof(h));

    if (db->n_fields) memcpy(buf + off_fields, db->fields, (size_t)db->n_fields * sizeof(sigma_str_t));
    if (db->n_values) memcpy(buf + off_values, db->values, (size_t)db->n_values * sizeof(sigma_str_t));
    if (db->n_preds) memcpy(buf + off_preds, db->preds, (size_t)db->n_preds * sizeof(sigma_pred_t));
    if (db->n_sels) memcpy(buf + off_sels, db->sels, (size_t)db->n_sels * sizeof(sigma_sel_t));
    if (db->n_cond) memcpy(buf + off_cond, db->cond, (size_t)db->n_cond * sizeof(sigma_ctok_t));
    if (db->n_rules) memcpy(buf + off_rules, db->rules, (size_t)db->n_rules * sizeof(sigma_rule_t));
    if (db->n_cidrs) memcpy(buf + off_cidrs, db->cidrs, (size_t)db->n_cidrs * sizeof(sigma_cidr_t));
    if (db->n_buckets) {
        memcpy(buf + off_bkeys, db->bucket_keys, (size_t)db->n_buckets * sizeof(sigma_str_t));
        memcpy(buf + off_buckets, db->buckets, (size_t)db->n_buckets * sizeof(sigma_bucket_t));
    }
    if (db->n_bucket_idx) memcpy(buf + off_bidx, db->bucket_idx, (size_t)db->n_bucket_idx * sizeof(uint32_t));
    if (db->n_litndl) {
        memcpy(buf + off_litndl, db->litndl, (size_t)db->n_litndl * sizeof(sigma_str_t));
        memcpy(buf + off_litpost, db->litpost, (size_t)db->n_litndl * sizeof(sigma_litpost_t));
    }
    if (db->n_litpost_ref)
        memcpy(buf + off_litpost_ref, db->litpost_ref, (size_t)db->n_litpost_ref * sizeof(sigma_litref_t));
    if (db->n_litav) memcpy(buf + off_litav, db->litav, (size_t)db->n_litav * sizeof(uint32_t));
    if (db->rule_clauses && db->n_rules) memcpy(buf + off_rule_clauses, db->rule_clauses, (size_t)db->n_rules);
    if (db->n_fwit) memcpy(buf + off_fwit, db->fwit, (size_t)db->n_fwit * sizeof(sigma_fwit_t));
    if (db->strpool_len) memcpy(buf + off_strpool, db->strpool, db->strpool_len);

    uint32_t crc = sigma_crc32c(0, buf, total - sizeof(uint32_t));
    memcpy(buf + total - sizeof(uint32_t), &crc, sizeof(crc));

    *out_buf = buf;
    *out_len = total;
    return SIGMA_OK;
}

/* Bounds helper: section [off, off + n*esz) must lie within len and be 8-aligned. */
static int sect_ok(size_t off, uint32_t n, size_t esz, size_t len) {
    if (off & 7u) return 0;
    if (off > len) return 0;
    size_t bytes = (size_t)n * esz;
    return bytes <= len - off;
}

int sigma_db_load_buffer(uint8_t* buf, size_t len, sigma_db_t* out) {
    /* Minimum to safely read magic+version (the first 8 bytes). */
    if (!buf || !out || len < 8u + sizeof(uint32_t)) return SIGMA_ERR_SIZE;

    uint32_t magic, version;
    memcpy(&magic, buf, 4);
    memcpy(&version, buf + 4, 4);
    if (magic != SIGMA_MAGIC) return SIGMA_ERR_MAGIC;
    /* v4 (136-byte header, no field witnesses) still loads. v5 adds fwit.
     * Anything else is refused rather than mis-read. */
    if (version < SIGMA_FORMAT_VERSION_MIN || version > SIGMA_FORMAT_VERSION) return SIGMA_ERR_VERSION;
    const size_t hdr_sz = (version == 4u) ? (size_t)SIGMA_HDR_V4_SIZE : sizeof(sigma_hdr_t);
    if (len < hdr_sz + sizeof(uint32_t)) return SIGMA_ERR_SIZE;

    sigma_hdr_t h;
    memset(&h, 0, sizeof(h));
    memcpy(&h, buf, hdr_sz);
    if (h.total_size != len) return SIGMA_ERR_SIZE;

    if (!sect_ok(h.off_fields, h.n_fields, sizeof(sigma_str_t), len) ||
        !sect_ok(h.off_values, h.n_values, sizeof(sigma_str_t), len) ||
        !sect_ok(h.off_preds, h.n_preds, sizeof(sigma_pred_t), len) ||
        !sect_ok(h.off_sels, h.n_sels, sizeof(sigma_sel_t), len) ||
        !sect_ok(h.off_cond, h.n_cond, sizeof(sigma_ctok_t), len) ||
        !sect_ok(h.off_rules, h.n_rules, sizeof(sigma_rule_t), len) ||
        !sect_ok(h.off_cidrs, h.n_cidrs, sizeof(sigma_cidr_t), len))
        return SIGMA_ERR_RANGE;
    /* Bucket index sections (bkeys + buckets are parallel, both n_buckets). */
    if (!sect_ok(h.off_bkeys, h.n_buckets, sizeof(sigma_str_t), len) ||
        !sect_ok(h.off_buckets, h.n_buckets, sizeof(sigma_bucket_t), len) ||
        !sect_ok(h.off_bucket_idx, h.n_bucket_idx, sizeof(uint32_t), len))
        return SIGMA_ERR_RANGE;
    /* Literal-prefilter (litidx) sections (litndl + litpost are parallel,
     * both n_litndl). */
    if (!sect_ok(h.off_litndl, h.n_litndl, sizeof(sigma_str_t), len) ||
        !sect_ok(h.off_litpost, h.n_litndl, sizeof(sigma_litpost_t), len) ||
        !sect_ok(h.off_litpost_ref, h.n_litpost_ref, sizeof(sigma_litref_t), len) ||
        !sect_ok(h.off_litav, h.n_litav, sizeof(uint32_t), len) ||
        !sect_ok(h.off_rule_clauses, h.off_rule_clauses ? h.n_rules : 0u, sizeof(uint8_t), len) ||
        !sect_ok(h.off_fwit, h.n_fwit, sizeof(sigma_fwit_t), len))
        return SIGMA_ERR_RANGE;
    if ((size_t)h.off_strpool > len || (size_t)h.strpool_len > len - h.off_strpool) return SIGMA_ERR_RANGE;

    uint32_t want;
    memcpy(&want, buf + len - sizeof(uint32_t), sizeof(want));
    if (sigma_crc32c(0, buf, len - sizeof(uint32_t)) != want) return SIGMA_ERR_CRC;

    /* Point the db into the buffer (zero-copy). */
    sigma_db_t d;
    memset(&d, 0, sizeof(d));
    /* Section offsets are validated 8-aligned (sect_ok) and buf is malloc'd
     * (max-aligned), so these are safe; cast via void* to silence -Wcast-align. */
    d.fields = (sigma_str_t*)(void*)(buf + h.off_fields);
    d.n_fields = h.n_fields;
    d.values = (sigma_str_t*)(void*)(buf + h.off_values);
    d.n_values = h.n_values;
    d.preds = (sigma_pred_t*)(void*)(buf + h.off_preds);
    d.n_preds = h.n_preds;
    d.sels = (sigma_sel_t*)(void*)(buf + h.off_sels);
    d.n_sels = h.n_sels;
    d.cond = (sigma_ctok_t*)(void*)(buf + h.off_cond);
    d.n_cond = h.n_cond;
    d.rules = (sigma_rule_t*)(void*)(buf + h.off_rules);
    d.n_rules = h.n_rules;
    d.cidrs = (sigma_cidr_t*)(void*)(buf + h.off_cidrs);
    d.n_cidrs = h.n_cidrs;
    d.strpool = (char*)(buf + h.off_strpool);
    d.strpool_len = h.strpool_len;
    d.bucket_keys = h.n_buckets ? (sigma_str_t*)(void*)(buf + h.off_bkeys) : NULL;
    d.buckets = h.n_buckets ? (sigma_bucket_t*)(void*)(buf + h.off_buckets) : NULL;
    d.n_buckets = h.n_buckets;
    d.bucket_idx = h.n_bucket_idx ? (uint32_t*)(void*)(buf + h.off_bucket_idx) : NULL;
    d.n_bucket_idx = h.n_bucket_idx;
    d.litndl = h.n_litndl ? (sigma_str_t*)(void*)(buf + h.off_litndl) : NULL;
    d.litpost = h.n_litndl ? (sigma_litpost_t*)(void*)(buf + h.off_litpost) : NULL;
    d.n_litndl = h.n_litndl;
    d.litpost_ref = h.n_litpost_ref ? (sigma_litref_t*)(void*)(buf + h.off_litpost_ref) : NULL;
    d.n_litpost_ref = h.n_litpost_ref;
    d.litav = h.n_litav ? (uint32_t*)(void*)(buf + h.off_litav) : NULL;
    d.n_litav = h.n_litav;
    d.rule_clauses = h.off_rule_clauses ? (uint8_t*)(buf + h.off_rule_clauses) : NULL;
    d.fwit = h.n_fwit ? (sigma_fwit_t*)(void*)(buf + h.off_fwit) : NULL;
    d.n_fwit = h.n_fwit;
    d.teddy = NULL;
    d.av_bucket = UINT32_MAX;
    d.cat_field_id = UINT32_MAX;
    d.re = NULL;
    d.backing = buf;

    /* Validate internal references so a corrupt/tampered artifact can't drive
     * the matcher out of bounds (a corrupt or untrusted artifact is rejected). */
    /* Field NAMES are NUL-terminated: the byte at
     * strpool[off + len] MUST be '\0', and must itself lie inside the pool.
     * This is what lets the matcher hand `strpool + off` directly to the
     * zero-copy C-string field lookup with NO bounce buffer / memcpy.  Reject
     * a non-terminated (corrupt/tampered) artifact. */
    for (uint32_t i = 0; i < d.n_fields; i++) {
        size_t end = (size_t)d.fields[i].off + d.fields[i].len;
        if (end + 1 > d.strpool_len) /* name + its terminator must fit */
            return SIGMA_ERR_RANGE;
        if (d.strpool[end] != '\0') /* terminator must actually be there */
            return SIGMA_ERR_RANGE;
    }
    for (uint32_t i = 0; i < d.n_values; i++)
        if ((size_t)d.values[i].off + d.values[i].len > d.strpool_len) return SIGMA_ERR_RANGE;
    for (uint32_t i = 0; i < d.n_preds; i++) {
        if (d.preds[i].field_id >= d.n_fields) return SIGMA_ERR_RANGE;
        if (d.preds[i].flags & SIGMA_PF_FIELDREF) {
            /* |fieldref: value_id indexes the FIELDS table (the referenced field),
             * not values/cidrs. It is dereferenced as a field at match time. */
            if (d.preds[i].value_id >= d.n_fields) return SIGMA_ERR_RANGE;
        } else if (d.preds[i].op == SIGMA_OP_CIDR) {
            if (d.preds[i].value_id >= d.n_cidrs) /* CIDR preds index the cidr table */
                return SIGMA_ERR_RANGE;
        } else if (d.preds[i].value_id != SIGMA_NO_VALUE && d.preds[i].value_id >= d.n_values) {
            return SIGMA_ERR_RANGE;
        }
    }
    for (uint32_t i = 0; i < d.n_sels; i++)
        if ((size_t)d.sels[i].pred_start + d.sels[i].pred_count > d.n_preds) return SIGMA_ERR_RANGE;
    for (uint32_t i = 0; i < d.n_rules; i++) {
        const sigma_rule_t* r = &d.rules[i];
        if ((size_t)r->sel_start + r->sel_count > d.n_sels || (size_t)r->cond_start + r->cond_count > d.n_cond)
            return SIGMA_ERR_RANGE;
        /* name_id / mitre_id are .values string refs resolved (dereferenced) at
         * match time, a corrupt/tampered index must not drive an OOB read. */
        if (r->name_id != SIGMA_NO_VALUE && r->name_id >= d.n_values) return SIGMA_ERR_RANGE;
        if (r->mitre_id != SIGMA_NO_VALUE && r->mitre_id >= d.n_values) return SIGMA_ERR_RANGE;
    }
    for (uint32_t i = 0; i < d.n_cond; i++)
        if (d.cond[i].kind > SIGMA_C_NOT) return SIGMA_ERR_RANGE;

    /* Bucket index: validate every bucket key's strpool ref, every
     * bucket slice against the rule-index pool, and every pool entry against the
     * rules table, a corrupt index must NEVER let the matcher prune unsoundly
     * or read OOB.  Resolve the always-verify bucket (key "") en passant. */
    for (uint32_t i = 0; i < d.n_buckets; i++) {
        const sigma_str_t* k = &d.bucket_keys[i];
        if ((size_t)k->off + k->len > d.strpool_len) return SIGMA_ERR_RANGE;
        if ((size_t)d.buckets[i].idx_start + d.buckets[i].idx_count > d.n_bucket_idx) return SIGMA_ERR_RANGE;
        if (k->len == 0) {
            if (d.av_bucket != UINT32_MAX) return SIGMA_ERR_RANGE; /* at most one always-verify bucket */
            d.av_bucket = i;
        }
    }
    for (uint32_t i = 0; i < d.n_bucket_idx; i++)
        if (d.bucket_idx[i] >= d.n_rules) return SIGMA_ERR_RANGE;

    /* Literal-prefilter index: validate every needle's strpool ref, every
     * postings slice against the postings pool, and every pool / always-verify
     * entry against the rules table.  A corrupt litidx must NEVER let the
     * prefilter prune a rule that could match (unsound) or read OOB. */
    for (uint32_t i = 0; i < d.n_litndl; i++) {
        const sigma_str_t* n = &d.litndl[i];
        if ((size_t)n->off + n->len > d.strpool_len) return SIGMA_ERR_RANGE;
        if (n->len == 0) /* an empty needle would match every line */
            return SIGMA_ERR_RANGE;
        if ((size_t)d.litpost[i].idx_start + d.litpost[i].idx_count > d.n_litpost_ref) return SIGMA_ERR_RANGE;
    }
    /* A posting names a rule, the field its literal must occur in, and which of
     * that rule's witness clauses it satisfies.  A clause index at or past the
     * rule's clause count could never be completed, which would gate the rule out
     * on every event: reject it rather than silently lose a detection. */
    for (uint32_t i = 0; i < d.n_litpost_ref; i++) {
        const sigma_litref_t* r = &d.litpost_ref[i];
        if (r->rule_idx >= d.n_rules) return SIGMA_ERR_RANGE;
        if (r->field_id != SIGMA_LITREF_ANY_FIELD && r->field_id >= d.n_fields) return SIGMA_ERR_RANGE;
        if (r->clause_idx >= SIGMA_MAX_CLAUSES) return SIGMA_ERR_RANGE;
        if (!d.rule_clauses || r->clause_idx >= d.rule_clauses[r->rule_idx]) return SIGMA_ERR_RANGE;
    }
    for (uint32_t i = 0; i < d.n_litav; i++) {
        if (d.litav[i] >= d.n_rules) return SIGMA_ERR_RANGE;
        /* Always-verify means "no sound literal": a clause count here would make
         * the two gates disagree about the same rule. */
        if (d.rule_clauses && d.rule_clauses[d.litav[i]] != 0) return SIGMA_ERR_RANGE;
    }
    if (d.rule_clauses)
        for (uint32_t i = 0; i < d.n_rules; i++)
            if (d.rule_clauses[i] > SIGMA_MAX_CLAUSES) return SIGMA_ERR_RANGE;
    for (uint32_t i = 0; i < d.n_fwit; i++) {
        const sigma_fwit_t* w = &d.fwit[i];
        if (w->rule_idx >= d.n_rules) return SIGMA_ERR_RANGE;
        if (w->field_id == SIGMA_LITREF_ANY_FIELD || w->field_id >= d.n_fields) return SIGMA_ERR_RANGE;
        if (w->clause_idx >= SIGMA_MAX_CLAUSES) return SIGMA_ERR_RANGE;
        if (!d.rule_clauses || w->clause_idx >= d.rule_clauses[w->rule_idx]) return SIGMA_ERR_RANGE;
        if (w->op == SIGMA_OP_CIDR) {
            if ((uint64_t)w->ival >= (uint64_t)d.n_cidrs) return SIGMA_ERR_RANGE;
        } else if (w->op != SIGMA_OP_GT && w->op != SIGMA_OP_GTE && w->op != SIGMA_OP_LT && w->op != SIGMA_OP_LTE &&
                   w->op != SIGMA_OP_NUMEQ) {
            return SIGMA_ERR_RANGE;
        }
    }

    /* Cache the field_id of "event.category" so the matcher resolves it once via
     * the per-thread memo (it is the bucket selector). */
    if (d.n_buckets) {
        static const char CATF[] = "event.category";
        const size_t catf_len = sizeof(CATF) - 1;
        for (uint32_t i = 0; i < d.n_fields; i++) {
            if (d.fields[i].len == catf_len && memcmp(d.strpool + d.fields[i].off, CATF, catf_len) == 0) {
                d.cat_field_id = i;
                break;
            }
        }
    }

    /* Compile any |re patterns now (zero-copy db otherwise; this is the one
     * derived allocation, freed by sigma_db_free). */
    if (sigma_db_finalize(&d) != 0) return SIGMA_ERR_REGEX;

    *out = d;
    return SIGMA_OK;
}

int sigma_db_load_file(const char* path, sigma_db_t* out) {
    if (!path || !out) return SIGMA_ERR_IO;
    FILE* f = fopen(path, "rb");
    if (!f) return SIGMA_ERR_IO;
    if (fseek(f, 0, SEEK_END) != 0) {
        fclose(f);
        return SIGMA_ERR_IO;
    }
    long sz = ftell(f);
    if (sz <= 0) {
        fclose(f);
        return SIGMA_ERR_SIZE;
    }
    rewind(f);

    uint8_t* buf = malloc((size_t)sz);
    if (!buf) {
        fclose(f);
        return SIGMA_ERR_NOMEM;
    }
    if (fread(buf, 1, (size_t)sz, f) != (size_t)sz) {
        free(buf);
        fclose(f);
        return SIGMA_ERR_IO;
    }
    fclose(f);

    int rc = sigma_db_load_buffer(buf, (size_t)sz, out);
    if (rc != SIGMA_OK) free(buf); /* load_buffer only takes ownership on success */
    return rc;
}
