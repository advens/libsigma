#!/usr/bin/env python3
# Write a small .sigmac used as the libFuzzer seed for fuzz_load / fuzz_match.
# Standard library only. Same rules as conformance_emit.py plus a litidx +
# category bucket so the Teddy prefilter is exercised in the artifact.

from __future__ import annotations

import os
import sys
import ipaddress

# The bundled reference emitter (src/reference/sigmac/). SIGMAC_SRC, when set,
# overrides it with an external sigmac package.
_here = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.environ.get("SIGMAC_SRC") or os.path.join(_here, "..", "reference"))

from sigmac.format import SigmaDbBuilder, Op, Verdict, PF_FIELDREF, ANY_FIELD  # noqa: E402


def build() -> bytes:
    b = SigmaDbBuilder()

    v = b.value("-enc")
    ps = b.begin_sel()
    b.pred("process.command_line", int(Op.CONTAINS), value_id=v)
    s = b.end_sel(ps)
    b.rule(100, s, 1, verdict=int(Verdict.ALERT), severity=3, score_x100=35)

    v = b.value("mimikatz.exe")
    ps = b.begin_sel()
    b.pred("process.name", int(Op.ENDSWITH), value_id=v)
    s = b.end_sel(ps)
    b.rule(200, s, 1, verdict=int(Verdict.ESCALATE), severity=4, score_x100=50)

    ps = b.begin_sel()
    b.pred("destination.port", int(Op.GTE), ival=1024)
    s = b.end_sel(ps)
    b.rule(300, s, 1, severity=1, score_x100=10)

    net = ipaddress.ip_network("10.0.0.0/8")
    cid = b.cidr(4, net.prefixlen, net.network_address.packed)
    ps = b.begin_sel()
    b.pred("source.ip", int(Op.CIDR), value_id=cid)
    s = b.end_sel(ps)
    b.rule(600, s, 1, severity=2, score_x100=20)

    v = b.value(r"port \d{3,}")
    ps = b.begin_sel()
    b.pred("network.info", int(Op.RE), value_id=v)
    s = b.end_sel(ps)
    b.rule(700, s, 1, severity=3, score_x100=30)

    ref = b.field("user.target")
    ps = b.begin_sel()
    b.pred("user.name", int(Op.EQ), value_id=ref, flags=PF_FIELDREF)
    s = b.end_sel(ps)
    b.rule(800, s, 1, severity=2, score_x100=20)

    # Bucket + litidx so load/match fuzzers hit Teddy and category narrowing.
    # rules: 0=100 1=200 2=300 3=600 4=700 5=800 (indices into b.rules).
    b.set_buckets({"process": [0, 1], "network": [2, 3], "": [4, 5]})
    b.set_litidx(
        {
            "-enc": [(0, ANY_FIELD, 0)],
            "mimikatz.exe": [(1, ANY_FIELD, 0)],
            "port ": [(4, ANY_FIELD, 0)],
        },
        always_verify=[2, 3, 5],          # numeric / cidr / fieldref: no literal
        rule_clauses=[1, 1, 0, 0, 1, 0],
    )
    return b.serialize()


def main() -> int:
    if len(sys.argv) != 2:
        print("usage: gen_seed.py <out.sigmac>", file=sys.stderr)
        return 2
    pathlib_write = sys.argv[1]
    data = build()
    with open(pathlib_write, "wb") as f:
        f.write(data)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
