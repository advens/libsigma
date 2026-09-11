# AGENTS.md

C engine for compiled Sigma rules. YAML is not parsed here, and neither is
any host-integration glue: this tree is the library, its CLI, its tests, and
the `.sigmac` format spec.

Read `docs/COMMIT.md` and `docs/BRANCHES.md` before any
commit-shaped or branch-shaped output. You do not commit, push,
or tag. The human does, using those contracts. Work branches are
`<type>/<scope>-<slug>`. Never push `main`.

## Build and test

```
make
make test
make san
make tsan
```

Requires PCRE2 and libfastjson or json-c. Dual-arch: SSE4.2 and NEON,
scalar fallback bit-identical. A change proven only on one arch is
incomplete.

## In

`src/sigma_match.*`, `src/sigma_format.*`, `src/sigma_simd.h`,
`src/sigma_teddy.h`, `src/classify_corr.*`, `src/corr_format.*`,
`src/contrib_wire.*`, `src/event_time.*`, `src/sigma_cli.c`, tests,
fuzzers, `Makefile`.

## Not in

YAML parsing, sockets, cluster membership, signing, and any
host-integration glue (field wiring, statistics plumbing, config reload).

## Must

- One write set. If the task needs a file outside it, stop.
- 4 spaces, K&R braces, snake_case, no VLA, bounded string APIs,
  check every allocation.
- Paste the command and its output. Do not claim tests passed without
  that paste.
- Format version and SONAME are frozen. Bumping them is a human
  decision (`Contract: abi|format|wire`).

## Never

- `git commit`, `git push`, `git tag`, `git rebase`, merge, force-push
- Rewrite `docs/COMMIT.md`, `.githooks/`, `scripts/check-commit-msg.sh`,
  `.github/workflows/`, or `CODEOWNERS` unless that is the write set
- Assistant attribution in comments, commits, or docs
- Em-dashes in anything that ships
- Put an LLM on the match path
