#!/usr/bin/env python3
# gen_corpus.py
# Build the events-corpus artifact: a small .sigmac that covers every operator,
# both predicate flags, an explicit RPN condition, and a bucket index, so the
# JSON front end is checked through category routing, product routing, and the
# always-verify bucket. Standard library only (bundled reference emitter).
#
# Usage:  python3 gen_corpus.py <out.sigmac>
#
# Copyright 2026 Advens. Author: Jeremie Jourdin <jeremie.jourdin@advens.fr>
# Licensed under the Apache License, Version 2.0 (see LICENSE).

import ipaddress
import os
import sys

_here = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.environ.get("SIGMAC_SRC") or os.path.join(_here, "..", "reference"))

from sigmac.format import (  # noqa: E402
    PF_CASE,
    PF_FIELDREF,
    PF_NEGATE,
    CTok,
    Op,
    SigmaDbBuilder,
    Verdict,
)


def cidr(b: SigmaDbBuilder, text: str) -> int:
    net = ipaddress.ip_network(text)
    return b.cidr(net.version, net.prefixlen, net.network_address.packed)


def build() -> bytes:
    b = SigmaDbBuilder()
    buckets: dict[str, list[int]] = {}

    def add(rule_idx: int, *keys: str) -> None:
        for k in keys:
            buckets.setdefault(k, []).append(rule_idx)

    # 10: encoded PowerShell, not started from explorer.exe.
    #   sel0 = name endswith powershell.exe AND (cmdline contains -enc OR -encodedcommand)
    #   sel1 = parent name == explorer.exe
    #   condition: sel0 and not sel1
    s0 = b.begin_sel()
    b.pred("process.name", Op.ENDSWITH, value_id=b.value("powershell.exe"), group=0)
    b.pred("process.command_line", Op.CONTAINS, value_id=b.value("-enc "), group=1)
    b.pred("process.command_line", Op.CONTAINS, value_id=b.value("-encodedcommand"), group=1)
    sel = b.end_sel(s0)
    s1 = b.begin_sel()
    b.pred("process.parent.name", Op.EQ, value_id=b.value("explorer.exe"))
    b.end_sel(s1)
    r = b.rule(10, sel, 2,
               cond=[(CTok.SEL, 0), (CTok.SEL, 1), (CTok.NOT, 0), (CTok.AND, 0)],
               verdict=Verdict.ALERT, severity=3, score_x100=40,
               name_id=b.value("Encoded PowerShell"), mitre_id=b.value("T1059.001"))
    add(r, "process")

    # 20: failed login from outside 10.0.0.0/8 (negated CIDR).
    s0 = b.begin_sel()
    b.pred("event.action", Op.EQ, value_id=b.value("authentication_failure"), group=0)
    b.pred("source.ip", Op.CIDR, value_id=cidr(b, "10.0.0.0/8"), group=1, flags=PF_NEGATE)
    sel = b.end_sel(s0)
    r = b.rule(20, sel, 1, severity=2, score_x100=20,
               name_id=b.value("External failed login"), mitre_id=b.value("T1110"))
    add(r, "authentication")

    # 30: case-sensitive equality.
    s0 = b.begin_sel()
    b.pred("user.name", Op.EQ, value_id=b.value("Administrator"), flags=PF_CASE)
    sel = b.end_sel(s0)
    r = b.rule(30, sel, 1, severity=2, score_x100=15, name_id=b.value("Administrator exact"))
    add(r, "authentication")

    # 40: low port to a documentation network, IPv6 or IPv4.
    #   condition: sel0 and (sel1 or sel2)
    s0 = b.begin_sel()
    b.pred("destination.port", Op.LT, ival=1024)
    sel = b.end_sel(s0)
    s1 = b.begin_sel()
    b.pred("destination.ip", Op.CIDR, value_id=cidr(b, "2001:db8::/32"))
    b.end_sel(s1)
    s2 = b.begin_sel()
    b.pred("destination.ip", Op.CIDR, value_id=cidr(b, "192.0.2.0/24"))
    b.end_sel(s2)
    r = b.rule(40, sel, 3,
               cond=[(CTok.SEL, 0), (CTok.SEL, 1), (CTok.SEL, 2), (CTok.OR, 0), (CTok.AND, 0)],
               severity=1, score_x100=10, name_id=b.value("Low port to documentation net"))
    add(r, "network")

    # 50: benign verdict, exists.
    s0 = b.begin_sel()
    b.pred("http.request.referrer", Op.EXISTS)
    sel = b.end_sel(s0)
    r = b.rule(50, sel, 1, verdict=Verdict.BENIGN, severity=0, score_x100=0,
               name_id=b.value("Has a referrer"))
    add(r, "web")

    # 60: escalate, startswith AND regex (caseless).
    s0 = b.begin_sel()
    b.pred("url.domain", Op.STARTSWITH, value_id=b.value("intranet."), group=0)
    b.pred("url.path", Op.RE, value_id=b.value(r"^/admin/[0-9]+$"), group=1)
    sel = b.end_sel(s0)
    r = b.rule(60, sel, 1, verdict=Verdict.ESCALATE, severity=4, score_x100=60,
               name_id=b.value("Intranet admin path"), mitre_id=b.value("T1190"))
    add(r, "web")

    # 70: fieldref with contains: the command line names the user.
    s0 = b.begin_sel()
    b.pred("process.command_line", Op.CONTAINS, value_id=b.field("user.name"), flags=PF_FIELDREF)
    sel = b.end_sel(s0)
    r = b.rule(70, sel, 1, severity=1, score_x100=5, name_id=b.value("Command line names the user"))
    add(r, "process")

    # 80: always-verify (no logsource): large .lnk file.
    s0 = b.begin_sel()
    b.pred("file.name", Op.ENDSWITH, value_id=b.value(".lnk"), group=0)
    b.pred("file.size", Op.GTE, ival=1000000, group=1)
    sel = b.end_sel(s0)
    r = b.rule(80, sel, 1, severity=2, score_x100=25, name_id=b.value("Large shortcut file"))
    add(r, "")

    # 90: dns only. An event routed to another category never evaluates it.
    s0 = b.begin_sel()
    b.pred("dns.question.name", Op.ENDSWITH, value_id=b.value(".onion"))
    sel = b.end_sel(s0)
    r = b.rule(90, sel, 1, severity=3, score_x100=30, name_id=b.value("Onion lookup"))
    add(r, "dns")

    # 100: product routing (bucket "sshd", reached through the product field).
    s0 = b.begin_sel()
    b.pred("event.action", Op.EQ, value_id=b.value("invalid_user"))
    sel = b.end_sel(s0)
    r = b.rule(100, sel, 1, severity=2, score_x100=20, name_id=b.value("SSH invalid user"))
    add(r, "sshd")

    b.set_buckets(buckets)
    return b.serialize()


def main() -> int:
    if len(sys.argv) != 2:
        print("usage: gen_corpus.py <out.sigmac>", file=sys.stderr)
        return 2
    data = build()
    with open(sys.argv[1], "wb") as f:
        f.write(data)
    print(f"wrote {len(data)} bytes to {sys.argv[1]}", file=sys.stderr)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
