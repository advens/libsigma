# Changelog

All notable changes to libsigma are recorded here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/). Versions track the
C ABI: the shared-library SONAME is `libsigma.so.<MAJOR>`.

The frozen surfaces are the C ABI, the `.sigmac` format version
(`SIGMA_FORMAT_VERSION`), and the contrib JSON `"v"`. A change to any of them
is called out explicitly.

## [Unreleased]

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

[Unreleased]: https://github.com/advens/libsigma/compare/3.0.0...HEAD
[3.0.0]: https://github.com/advens/libsigma/releases/tag/3.0.0
