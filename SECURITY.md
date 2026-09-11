# Security Policy

## Reporting a vulnerability

Report privately, either way:

- GitHub: **Security > Report a vulnerability** (private advisory) on this
  repository, or
- email **jeremie.jourdin@advens.fr**.

Do not open a public issue or PR for a match-path, loader, or contribution-codec
bug before a fix is released.

Please include the affected commit or tag, the architecture and OS, and a
reproducer (a hostile `.sigmac`, an input corpus, or a crashing command line).

## What to expect

- Acknowledgement within 3 business days.
- An initial assessment and a target fix window within 10 business days.
- Coordinated disclosure: we agree a publication date with you, normally within
  90 days of the report, and credit you in the advisory unless you prefer
  otherwise.

## Supported versions

Only the latest tagged release and `main` receive security fixes; older
tags do not get backports.

## Hardening invariants

- The `.sigmac` loader fails closed on bad magic, version, size, CRC32C, or any
  out-of-range offset or index. A crash, over-read, or over-write on hostile
  input is a security bug.
- The correlation engine is bounded on every axis (group count, distinct-set
  size, per-group event ring, time). Unbounded growth driven by
  adversary-controlled cardinality is a security bug.
- The contribution JSON decoder treats every input as untrusted and is covered
  by a libFuzzer target.
