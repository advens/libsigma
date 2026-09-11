# libsigma fuzz targets

A crash on any of these is a security finding: keep the reproducer, and do not
patch the engine in the same change that adds the regression seed.

All targets are driven from the top-level `Makefile`.

## What runs

| Target | Input | Covers | Does not cover |
|---|---|---|---|
| `fuzz_simd` | generated buffers | SIMD `contains` / Teddy vs scalar, bit-identical | loader, JSON, PCRE2 |
| `fuzz_load` | raw bytes + CRC-rewritten mutants of `seed.sigmac` | `sigma_db_load_buffer`: magic, version, size, CRC, range checks, NUL field names, finalize | match-time eval; a mutant that fails CRC never reaches the range checks (the CRC-rewrite path exists so that class is not empty) |
| `fuzz_contrib` | JSON text | `json-c` then `corr_contrib_from_json` (an untrusted cross-instance contribution) | engine merge; sockets |
| `fuzz_match` | field-value bytes against a fixed db | `sigma_eval_run` with the prefilter forced: Teddy, PCRE2, cidr, numeric, fieldref, empty/NUL/high/long values | compiling a fuzzer-authored rule db (that is `fuzz_load`) |
| `fuzz_diff.py` | canned + seeded Sigma YAML / ECS events | C vs a reference Python evaluator, hit sets (id, verdict, sev, score) for eq/contains/start/end/exists/cmp/re/cidr/or/and/not/cased/fieldref | correlation, loader crashes, SIMD |

`fuzz_match` maps every field lookup to the same blob; it does not model
per-field structure. `fuzz_contrib` does not call the engine merge path.

## How to run

Apple Command Line Tools `clang` has no libFuzzer; Homebrew `llvm` does. The
`Makefile` picks `/opt/homebrew/opt/llvm/bin/clang` when present, else any
`clang` on `PATH`, else `$(CC)`.

```
make test                       # matcher + SIMD + correlation + event-time + wire
make san                        # ASan + UBSan over the SIMD oracle and the engine
make tsan                       # correlation engine under ThreadSanitizer
make libfuzz FUZZ_RUNS=100000   # load / match / contrib libFuzzer campaign
make libfuzz-ci                 # bounded (45s per target) libFuzzer smoke
```

`make libfuzz` and `make conformance` build their `.sigmac` inputs with the
bundled reference emitter (`src/reference/sigmac/`, standard library only), so
they need no external compiler.

`make diffuzz` is the only target that needs a full external Sigma compiler and
evaluator: set `SIGMAC_SRC` to the directory that contains that `sigmac`
package. Without it the target fails closed.

```
make diffuzz         SIGMAC_SRC=/path/to/compiler   # C vs reference hit sets
make diffuzz-c-arch                                 # native SIMD vs scalar, no Python
```

Corpora live under `src/fuzz_corpus/`. Regression seeds for a fixed bug go next
to the harness that found it.

## OSS-Fuzz

`src/oss-fuzz/` is a draft integration (`Dockerfile`, `build.sh`,
`project.yaml`). It is not submitted. OSS-Fuzz onboarding needs a public source
repository and a maintainer contact on file; submit once this repository is
public.
