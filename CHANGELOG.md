# Changelog

All notable changes to libsigma are recorded here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/). Versions track the
C ABI: the shared-library SONAME is `libsigma.so.<MAJOR>`.

The frozen surfaces are the C ABI, the `.sigmac` format version
(`SIGMA_FORMAT_VERSION`), and the contrib JSON `"v"`. A change to any of them
is called out explicitly.

## [Unreleased]

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
