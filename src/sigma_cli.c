/* sigma_cli.c
 * Standalone CLI for the Sigma matcher: load a compiled `.sigmac` artifact,
 * read events from stdin (one event per line, TAB-separated `key=value`
 * pairs), print the rules that fire.  Useful to verify artifacts end-to-end:
 * that a compiler's output is accepted by the loader and matches as expected.
 *
 * Build: clang -std=c11 -O2 sigma_cli.c sigma_match.c sigma_format.c -o sigma_cli
 * Usage: ./sigma_cli rules.sigmac < events.tsv
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

#define _POSIX_C_SOURCE 200809L  /* getline, strtok_r, strdup */

#include "sigma_match.h"
#include "sigma_format.h"
#include "classify_corr.h"
#include "corr_format.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define MAX_KV 64

typedef struct { const char *k; size_t klen; const char *v; size_t vlen; } kv_t;
typedef struct { kv_t kv[MAX_KV]; int n; } event_t;

static const char *ev_lookup(void *ctx, const char *name, uint32_t name_len, size_t *out_len)
{
    const event_t *e = (const event_t *)ctx;
    for (int i = 0; i < e->n; i++) {
        if (e->kv[i].klen == name_len && memcmp(e->kv[i].k, name, name_len) == 0) {
            *out_len = e->kv[i].vlen;
            return e->kv[i].v;
        }
    }
    *out_len = 0;
    return NULL;
}

/* Parse one TAB-separated line of key=value pairs (mutates `line`). */
static void parse_event(char *line, event_t *e)
{
    e->n = 0;
    char *save = NULL;
    for (char *tok = strtok_r(line, "\t", &save); tok && e->n < MAX_KV;
         tok = strtok_r(NULL, "\t", &save)) {
        char *eq = strchr(tok, '=');
        if (!eq)
            continue;
        *eq = '\0';
        e->kv[e->n].k = tok;          e->kv[e->n].klen = (size_t)(eq - tok);
        e->kv[e->n].v = eq + 1;       e->kv[e->n].vlen = strlen(eq + 1);
        e->n++;
    }
}

static const char *verdict_name(uint8_t v)
{
    switch (v) {
    case SIGMA_VERDICT_BENIGN:   return "benign";
    case SIGMA_VERDICT_ESCALATE: return "escalate";
    default:                     return "alert";
    }
}

static const char *corr_lookup(void *ctx, const char *name)
{
    size_t nlen, vlen;
    const char *v;
    if (!name) return NULL;
    nlen = strlen(name);
    v = ev_lookup(ctx, name, (uint32_t)nlen, &vlen);
    if (!v || vlen == 0) return NULL;
    return v;
}

static double event_ts(const event_t *e, long ln)
{
    size_t vlen;
    const char *v = ev_lookup((void *)e, "_ts", 3, &vlen);
    if (v && vlen) {
        char buf[64];
        size_t n = vlen < sizeof(buf) - 1 ? vlen : sizeof(buf) - 1;
        memcpy(buf, v, n);
        buf[n] = '\0';
        return strtod(buf, NULL);
    }
    return (double)ln;
}

int main(int argc, char **argv)
{
    corr_artifact_t *corr_art = NULL;
    corr_engine_t *corr = NULL;
    struct corr_artifact_view view;
    static const char *scratch[64 * CORR_MAX_GROUP_FIELDS];

    if (argc < 2) {
        fprintf(stderr, "usage: %s <rules.sigmac> [rules.corr.json]  < events.tsv\n",
                argv[0]);
        return 2;
    }

    sigma_db_t db;
    int rc = sigma_db_load_file(argv[1], &db);
    if (rc != SIGMA_OK) {
        fprintf(stderr, "load '%s' failed: status %d\n", argv[1], rc);
        return 1;
    }
    fprintf(stderr, "loaded %s: %u rules, %u preds, %u fields, %u cidrs\n",
            argv[1], db.n_rules, db.n_preds, db.n_fields, db.n_cidrs);

    if (argc >= 3) {
        corr_art = corr_artifact_load_file(argv[2], &view);
        if (!corr_art) {
            fprintf(stderr, "load '%s' failed (missing/wrong version or JSON)\n",
                    argv[2]);
            sigma_db_free(&db);
            return 1;
        }
        corr = corr_engine_new(view.rules, view.n, corr_caps_default());
        if (!corr) {
            corr_artifact_free(corr_art);
            sigma_db_free(&db);
            return 1;
        }
        fprintf(stderr, "loaded %s: %zu correlation(s)\n", argv[2], view.n);
    }

    sigma_eval_t *ev = sigma_eval_create(&db);
    if (!ev) {
        if (corr) corr_engine_free(corr);
        corr_artifact_free(corr_art);
        sigma_db_free(&db);
        return 1;
    }

    char *line = NULL;
    size_t cap = 0;
    ssize_t len;
    long ln = 0;
    while ((len = getline(&line, &cap, stdin)) != -1) {
        uint32_t rids[64];
        int i, n;
        event_t e;
        char *dup;
        if (len > 0 && line[len - 1] == '\n')
            line[--len] = '\0';
        if (len == 0)
            continue;
        ln++;
        dup = strdup(line);
        if (!dup) break;
        parse_event(dup, &e);

        sigma_hit_t hits[64];
        n = sigma_eval_run(ev, ev_lookup, &e, hits, 64);
        if (n == 0) {
            printf("event %ld: no match\n", ln);
        } else {
            for (i = 0; i < n && i < 64; i++)
                printf("event %ld: rule=%u verdict=%s sev=%u score=%.2f mitre=%.*s\n",
                       ln, hits[i].rule_id, verdict_name(hits[i].verdict),
                       hits[i].severity, hits[i].score_x100 / 100.0,
                       hits[i].mitre ? (int)hits[i].mitre_len : 1,
                       hits[i].mitre ? hits[i].mitre : "-");
        }
        if (corr && n > 0) {
            corr_fire_t fires[16];
            int nf;
            for (i = 0; i < n && i < 64; i++)
                rids[i] = hits[i].rule_id;
            nf = corr_on_event(corr, rids, (size_t)n, corr_lookup, &e,
                               event_ts(&e, ln), fires, 16, scratch, 64 * CORR_MAX_GROUP_FIELDS);
            for (i = 0; i < nf && i < 16; i++)
                printf("event %ld: corr=%s observed=%lld\n",
                       ln, fires[i].rule_id ? fires[i].rule_id : "-",
                       (long long)fires[i].observed);
        }
        free(dup);
    }

    free(line);
    sigma_eval_free(ev);
    if (corr) corr_engine_free(corr);
    corr_artifact_free(corr_art);
    sigma_db_free(&db);
    return 0;
}
