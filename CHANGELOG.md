# Changelog

All notable changes to libsigma are recorded here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/). Versions track the
C ABI: the shared-library SONAME is `libsigma.so.<MAJOR>`.

The frozen surfaces are the C ABI, the `.sigmac` format version
(`SIGMA_FORMAT_VERSION`), and the contrib JSON `"v"`. A change to any of them
is called out explicitly.

## [Unreleased]

### Security

- The `.sigmac` loader now rejects a CIDR with an unknown family or a prefix
  past 32 (v4) or 128 (v6), a predicate op past `SIGMA_OP__MAX`, a prefilter
  needle shorter than 2 bytes, and more than 0xFFFF fields. A v6 prefix of
  129 used to load and read past the address at match time.
- Percentile and median correlations shared one sort buffer across the
  engine, while each correlation only holds its own lock. Two workers on two
  such correlations wrote the same buffer and could fire on the other's
  values. Each percentile or median correlation now owns its buffer.

## [4.1.1] - 2026-11-16

PATCH: a bounds fix. The C ABI, the SONAME (`libsigma.so.4`), the `.sigmac`
format, and the contrib wire are unchanged.

### Security

- `corr_artifact_parse(json, len, view)` ignored `len` and read up to a NUL,
  so a buffer without a terminator was read past its end. It now parses
  exactly `len` bytes and needs no NUL. A document followed by anything but
  whitespace, `len` 0, and `len` above `INT_MAX` are rejected. The callers
  in this tree (`corr_artifact_load_file`, `sigma_events`) always passed a
  terminated buffer. A caller that passed `len` 0 with a terminated string
  must now pass its length. New libFuzzer target `fuzz_corr`.

## [4.1.0] - 2026-11-16

MINOR: new functionality beside the C library. The C ABI, the SONAME
(`libsigma.so.4`), the `.sigmac` format (5, loads 4), and the contrib wire
are unchanged; the native library is built from the same sources as 4.0.2.

### Added

- A JSON front end, `src/sigma_events.{c,h}`: match JSON or JSON Lines
  events against a loaded `.sigmac`, explain one rule against one event
  predicate by predicate, and run `rules.corr.json` correlations over a
  sequence of events. Answers are JSON (schema 1, documented in the
  header). It is not part of `libsigma.so` or the installed headers.
- `libsigma.wasm`, a WASI reactor that exports the front end (ABI 1),
  with a dependency-free JS loader for browsers, Web Workers, and Node
  18+, a worker and its client so matching runs off the page's thread,
  and TypeScript typings.
- A wasm32-wasip1 build from the git tree: `make wasm`, `make wasm-test`
  (the engine tests and the conformance check under wasmtime, the JS
  tests under Node), and `make wasm-san` (UBSan in trap mode).
  `scripts/wasm-deps.sh` fetches wasi-sdk 34, wasmtime, PCRE2, and
  libfastjson, each checked against a pinned sha256.
- Release assets `libsigma-wasm-<v>.tar.gz` (the module, loader, worker,
  typings, `abi.json`) and `libsigma-wasm-sdk-<v>.tar.gz` (wasm32 static
  libraries and headers), built by `make wasm-dist`, with the license
  notices of the code linked into them.
- An events corpus with expected hits written by hand and a golden
  transcript that the native build, the wasm32 build, and the JS loader
  each reproduce byte for byte (`make test-events`), plus
  `make test-events-san` and the `fuzz_events` libFuzzer target.

### CI

- `wasm` on x86_64 and arm64, `wasm-same-bytes` (both hosts build the
  same module), and `codestyle` (clang-format 18 with rsyslog's
  `.clang-format` over `src/`, `sigma_cli.c` excepted).

## [4.0.2] - 2026-11-10

### Fixed

- `teddy_probe_at`'s parameter list is aligned the way rsyslog's
  clang-format expects. Whitespace only.

## [4.0.1] - 2026-11-10

### Fixed

- The engine builds without warnings under rsyslog's flags
  (`-Wswitch-enum`, `-Wswitch-default`, `-Winline`). Switches on
  `corr_type_t` and `corr_contrib_kind_t` name every value, and
  `teddy_probe_at` is no longer declared inline. No result changes.

## [4.0.0] - 2026-10-21

MAJOR for the contrib wire change below: the SONAME is now
`libsigma.so.4`. The C ABI itself is unchanged; consumers relink.

### Changed

- Contrib wire: `corr_owner_index` now hashes the owner key with djb2
  followed by the murmur3 fmix32 finalizer, over the whole key. This is
  the hash rsyslog omfwd `pool.policy="hash"` applies, so the transport
  delivers each contribution to the peer that accepts it. Plain djb2
  modulo a power of two reduced to a byte sum of the key (anagram groups
  shared an owner, one byte picked it), and keys over 511 bytes all went
  to peer 0. Every peer of a ring must run the same version: a peer on
  the old hash refuses contributions the new one routes to it. `"v"`
  stays 1.
- `corr_contrib_to_json` adds `"key"`, the `corr_owner_key` string, so a
  transport can route without rebuilding it from `corr_id` and `group`.
  Parsers ignore it.

### Fixed

- GitHub squash-merge appends ` (#<n>)` to the commit subject. The
  commit-msg checker counted that suffix toward the 72-character cap,
  so a PR whose title passed CI failed on `main` after merge. The
  suffix is now stripped before first-line checks.

## [3.0.1] - 2026-09-14

### Security

- A `|re` predicate matched an attacker-controlled event field value
  against a pattern compiled from the `.sigmac` artifact using PCRE2's
  own compiled-in default match/depth limit (no application-set match
  context), which is not a value libsigma chooses or can rely on being
  consistent across the platforms it ships for. An adversarial (pattern,
  field value) pairing had no application-owned ceiling on the eval hot
  path (CWE-1333). `sigma_match.c` now sets an explicit, deterministic
  PCRE2 match/depth limit, shared read-only across threads; hitting the
  limit degrades to the same safe non-match outcome PCRE2 already
  returns for `PCRE2_ERROR_NOMATCH`, so this bounds worst-case time only
  and never changes match correctness.

### Fixed

- `sigma.pc`'s `Cflags` pointed `-I` at `${includedir}/sigma` instead of
  `${includedir}`; a fresh `make install` broke the README's own
  documented build line (`cc example.c $(pkg-config --cflags --libs
  sigma)`) with a missing-header error. (`Contract: abi`)
- `make libfuzz` / `make libfuzz-ci` built `fuzz_contrib` against the
  generic `JSON_CFLAGS`/`JSON_LIBS`, which prefer libfastjson over
  json-c, even though `fuzz_contrib.c` calls json-c-only symbols; on any
  host with both libraries installed, the target silently skipped
  `fuzz_contrib` instead of building and running it. Now uses the
  json-c-specific `FUZZ_JSON_CFLAGS`/`FUZZ_JSON_LIBS` that already
  existed for exactly this reason.
- `.github/workflows/ci.yml`'s `commit-msg` job used `github.sha` for
  `HEAD`; on a `pull_request` run that is GitHub's synthetic test-merge
  commit, not the PR's real head, so the job failed on every PR
  regardless of its actual commits.

### Added

- `src/docs/TUTORIAL.md`: a worked walkthrough from two Sigma rules
  through hand-lowering, `.sigmac` emission with the bundled reference
  emitter, and a `sigma_cli` match, command by command.
- `docs/RELEASING.md`: the release process, from version bump through
  what the tag push automates.
- CI and license badges on the README.

## [3.0.0] - 2026-09-10

First tagged release.

### Library

- Compiled `.sigmac` selection matcher: `sigma_match` / `sigma_format`, mmap
  loader with a fail-closed validator (magic, version, size, CRC32C, range,
  NUL-terminated field names).
- `.sigmac` format version 5: field-scoped conjunctive literal postings,
  numeric and CIDR field witnesses, logsource buckets. Version 4 still loads.
- SIMD case-insensitive `contains` and a Teddy literal multi-pattern prefilter
  (SSE4.2 and NEON, bit-identical scalar fallback).
- PCRE2-backed `|re`.
- In-process correlator (`classify_corr`): `event_count`, `value_count`,
  `temporal`, `temporal_ordered`, `value_sum`, `value_avg`,
  `value_percentile`, `value_median`, plus a periodic-beaconing extension.
  Bounded eviction on every axis (group LRU, distinct-set cap, event ring,
  time sweep); every silent cap has an observable counter.
- Cross-instance contribution codec (`contrib_wire`): merge COUNT / SUM /
  SEEN / DISTINCT partials between engine instances. No sockets in the
  library.
- Event-time parser (`event_time`) for clocking correlation windows on when
  the event happened.
- `sigma_cli` standalone matcher; `bench_corpus` / `bench_sigma` throughput
  harnesses.

### Tooling

- Reference `.sigmac` emitter under `src/reference/sigmac/` (standard library
  only); `make conformance` proves byte parity against the C loader.
- libFuzzer targets for the loader, the match path, the SIMD primitives, and
  the contribution codec; ASan/UBSan and TSan gates.
- Normative on-disk format specification, `src/docs/SIGMAC_FORMAT.md`.

[Unreleased]: https://github.com/advens/libsigma/compare/4.1.1...HEAD
[4.1.1]: https://github.com/advens/libsigma/releases/tag/4.1.1
[4.1.0]: https://github.com/advens/libsigma/releases/tag/4.1.0
[4.0.2]: https://github.com/advens/libsigma/releases/tag/4.0.2
[4.0.1]: https://github.com/advens/libsigma/releases/tag/4.0.1
[4.0.0]: https://github.com/advens/libsigma/releases/tag/4.0.0
[3.0.1]: https://github.com/advens/libsigma/releases/tag/3.0.1
[3.0.0]: https://github.com/advens/libsigma/releases/tag/3.0.0
