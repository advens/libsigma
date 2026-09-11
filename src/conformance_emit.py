#!/usr/bin/env python3
# conformance_emit.py
# Cross-language byte-compatibility conformance: build a .sigmac with the
# reference emitter (src/reference/sigmac/format.py) and hand it to the C
# loader/matcher (sigma_cli). This proves the two on-disk layouts agree by
# EXECUTION, not just by matching-but-separate specs. The emitter is standard
# library only.
#
# Usage:  python3 conformance_emit.py <out.sigmac>
#         SIGMAC_SRC=/path/to/dir/containing/sigmac   (optional override)
#
# Copyright 2026 Advens. Author: Jeremie Jourdin <jeremie.jourdin@advens.fr>
# Licensed under the Apache License, Version 2.0 (see LICENSE).

import os
import sys
import ipaddress

_here = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.environ.get("SIGMAC_SRC") or os.path.join(_here, "reference"))

from sigmac.format import SigmaDbBuilder, Op, Verdict, PF_FIELDREF  # noqa: E402


def build() -> bytes:
    b = SigmaDbBuilder()

    # rule 100: process.command_line |contains "-enc"
    v = b.value("-enc")
    ps = b.begin_sel()
    b.pred("process.command_line", int(Op.CONTAINS), value_id=v)
    s = b.end_sel(ps)
    b.rule(100, s, 1, verdict=int(Verdict.ALERT), severity=3, score_x100=35)

    # rule 200: process.name == "MiMiKatz" (plain EQ, case-insensitive at runtime)
    v = b.value("mimikatz.exe")
    ps = b.begin_sel()
    b.pred("process.name", int(Op.ENDSWITH), value_id=v)
    s = b.end_sel(ps)
    b.rule(200, s, 1, verdict=int(Verdict.ESCALATE), severity=4, score_x100=50)

    # rule 300: destination.port |gte 1024 (numeric)
    ps = b.begin_sel()
    b.pred("destination.port", int(Op.GTE), ival=1024)
    s = b.end_sel(ps)
    b.rule(300, s, 1, severity=1, score_x100=10)

    # rule 600: source.ip |cidr 10.0.0.0/8
    net = ipaddress.ip_network("10.0.0.0/8")
    cid = b.cidr(4, net.prefixlen, net.network_address.packed)
    ps = b.begin_sel()
    b.pred("source.ip", int(Op.CIDR), value_id=cid)
    s = b.end_sel(ps)
    b.rule(600, s, 1, severity=2, score_x100=20)

    # rule 700: command_line |re (PCRE dialect \d, exercises the C PCRE2 path)
    v = b.value(r"port \d{3,}")
    ps = b.begin_sel()
    b.pred("network.info", int(Op.RE), value_id=v)
    s = b.end_sel(ps)
    b.rule(700, s, 1, severity=3, score_x100=30)

    # rule 800: user.name |fieldref user.target (field-to-field equality). The
    # operand indexes the FIELDS table (PF_FIELDREF), not a literal value.
    ref = b.field("user.target")
    ps = b.begin_sel()
    b.pred("user.name", int(Op.EQ), value_id=ref, flags=PF_FIELDREF)
    s = b.end_sel(ps)
    b.rule(800, s, 1, severity=2, score_x100=20)

    return b.serialize()


def main() -> int:
    if len(sys.argv) != 2:
        print("usage: conformance_emit.py <out.sigmac>", file=sys.stderr)
        return 2
    data = build()
    with open(sys.argv[1], "wb") as f:
        f.write(data)
    print(f"wrote {len(data)} bytes to {sys.argv[1]}", file=sys.stderr)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
