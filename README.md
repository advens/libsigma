# libsigma

C11 engine for compiled [Sigma](https://sigmahq.io/) rules. It `mmap()`s a
`.sigmac` bytecode file, evaluates events through a field-lookup callback, and
runs an in-process correlator. Sigma YAML is never parsed at match time.

- Selection matching with SIMD-accelerated case-insensitive `contains` and a
  Teddy literal prefilter (SSE4.2 and NEON, bit-identical scalar fallback),
  PCRE2 for `|re`.
- Stateful correlation (`event_count`, `value_count`, `temporal[_ordered]`, the
  numeric aggregations, a periodic-beaconing extension) with bounded memory on
  every axis.
- No YAML parser, no sockets, no threads of its own. The library is a set of
  pure functions over an immutable rule database and a per-thread scratch
  object.

## Related projects

| Project | Home | Language | Role |
|---------|------|----------|------|
| **pySigma** | [SigmaHQ/pySigma](https://github.com/SigmaHQ/pySigma) | Python | Official SigmaHQ compiler. YAML to SIEM backends. |
| **sigma_engine** | [SigmaHQ/sigma_engine](https://github.com/SigmaHQ/sigma_engine) | Rust | Official SigmaHQ matcher. Parses YAML and matches events. |
| **rsigma** | [timescale/rsigma](https://github.com/timescale/rsigma) | Rust | Timescale toolkit: parser, linter, JSON eval, daemon, LSP, MCP. |
| **libsigma** | this repository | C11 | Compiled `.sigmac` matcher + correlator. No YAML at match time. |

## In, not in

**In:**

- load `.sigmac` v5 (CRC32C; v4 still loads; field-scoped conjunctive literal
  postings plus numeric/CIDR field witnesses; logsource buckets on
  `event.category` then product/service keys)
- selection matching (`sigma_match` / `sigma_format`)
- SIMD case-insensitive `contains` (SSE4.2 and NEON, scalar fallback)
- PCRE2 `|re`
- in-process correlator (`event_count`, `value_count`, `temporal`,
  `temporal_ordered`, `value_sum`, `value_avg`, `value_percentile`,
  `value_median`, plus a periodic-beaconing extension)
- a JSON codec for merging counts / sums / seen-sets / distinct-sets across
  engine instances (no sockets in the library: the caller carries the bytes)
- event-time parsing, `sigma_cli`, unit tests, libFuzzer targets, a
  standard-library reference `.sigmac` emitter

**Not in:**

- Sigma YAML parsing / pySigma
- any host-integration glue (field callback wiring, statistics plumbing,
  config reload)
- sockets, cluster membership, signing

## Example

```c
#include <sigma/sigma_format.h>
#include <sigma/sigma_match.h>
#include <stdio.h>
#include <string.h>

/* Resolve an ECS field name to its value for one event. */
static const char *field(void *ctx, const char *name, uint32_t name_len, size_t *out_len)
{
    /* ctx is your parsed event; look name up and return the value pointer. */
    (void)ctx;
    if (name_len == strlen("process.name") && !memcmp(name, "process.name", name_len)) {
        static const char v[] = "mimikatz.exe";
        *out_len = sizeof(v) - 1;
        return v;
    }
    *out_len = 0;
    return NULL;
}

int main(void)
{
    sigma_db_t db;
    if (sigma_db_load_file("rules.sigmac", &db) != SIGMA_OK)
        return 1;

    sigma_eval_t *ev = sigma_eval_create(&db);   /* one per worker thread */

    sigma_hit_t hits[64];
    int n = sigma_eval_run(ev, field, /*ctx=*/NULL, hits, 64);
    for (int i = 0; i < n && i < 64; i++)
        printf("rule %u verdict=%u score=%.2f mitre=%.*s\n",
               hits[i].rule_id, hits[i].verdict, hits[i].score_x100 / 100.0,
               hits[i].mitre ? (int)hits[i].mitre_len : 1,
               hits[i].mitre ? hits[i].mitre : "-");

    sigma_eval_free(ev);
    sigma_db_free(&db);
    return 0;
}
```

```
cc example.c $(pkg-config --cflags --libs sigma) -o example
```

The correlator (`sigma/classify_corr.h`) takes the rule-ids a matched event
fired and the group-by field values, and returns fired correlations. See
`src/sigma_cli.c` for a matcher + correlator driver.

## Build

```
make                 # shared + static library + sigma_cli
make test            # matcher, SIMD, correlation, event-time, wire
make san             # ASan + UBSan
make tsan            # correlation engine under ThreadSanitizer
make PREFIX=/usr/local install
```

`pkg-config --cflags --libs sigma` after install.

### Dependencies

PCRE2, and either json-c or libfastjson.

| Platform | Packages |
|----------|----------|
| Debian / Ubuntu | `libpcre2-dev libjson-c-dev pkg-config` |
| Fedora / RHEL | `pcre2-devel json-c-devel pkgconf-pkg-config` |
| FreeBSD | `pcre2 json-c pkgconf gmake`, plus a C compiler (base has none by default: `pkg install gcc14`, or an `llvmNN` package for clang, then build with `gmake CC=gcc14` / `CC=clang`; base `make` cannot parse this Makefile) |
| macOS (Homebrew) | `pcre2 json-c pkg-config` |

Dual-arch: amd64 builds with SSE4.2, aarch64 with NEON, and both agree
bit-for-bit with the scalar fallback (`make SCALAR=1`).

## Versioning

The shared-library SONAME is `libsigma.so.<MAJOR>` and tracks the C ABI. The
release tag is the full `MAJOR.MINOR.PATCH`.

Three surfaces are frozen and versioned independently of the release number:

| Surface | Identifier | Notes |
|---------|-----------|-------|
| C ABI | SONAME `libsigma.so.3` | exported headers, `pkg-config` |
| `.sigmac` format | `SIGMA_FORMAT_VERSION` = 5 | loader accepts 5 and 4; a v3 file is rejected |
| contrib JSON | `"v"` = 1 | cross-instance contribution wire form |

A commit that touches one of these declares it (`Contract:` line, see
`docs/COMMIT.md`) and needs a human merge owner.

Recompile your rules to pick up new `.sigmac` features (for example the v5
field witnesses); an old artifact keeps working.

## The `.sigmac` format

`src/docs/SIGMAC_FORMAT.md` is the normative specification: section layout,
struct byte layouts, enumerations, CRC, and loader validation rules. A
YAML-to-`.sigmac` compiler is a separate program; a standard-library Python
reference emitter is bundled under `src/reference/sigmac/` and
`make conformance` proves it byte-for-byte against the C loader.
`src/docs/TUTORIAL.md` walks two real Sigma rules through hand-lowering,
`.sigmac` emission, and a `sigma_cli` match, command by command.

## Embedding in another source tree

`src/*.c` and `src/*.h` build with no generated headers and no external
configure step, so they can be vendored directly next to a host module's
sources. Link PCRE2 and a JSON library; the correlator core
(`classify_corr.c`) needs neither.

## Contributing

`docs/COMMIT.md` is the commit contract and `docs/BRANCHES.md` the branch
contract; every commit and every squash-merged PR must pass
`scripts/check-commit-msg.sh`, which CI enforces. See `CONTRIBUTING.md` and
`CODE_OF_CONDUCT.md`.

## Security

See `SECURITY.md`. Report privately; do not open a public issue for a
match-path or loader bug before a fix ships.

## License

Apache License 2.0. See `LICENSE` and `NOTICE`.
