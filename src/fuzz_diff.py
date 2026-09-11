#!/usr/bin/env python3
"""Differential harness: the C matcher vs an external reference Sigma evaluator.

Generates Sigma YAML + events from a seed, compiles the rules, evaluates each
event with the reference evaluator and in C (sigma_cli on the .sigmac). Hit
sets must agree (fired rule id, verdict, severity, score). Deterministic: a
failure reprints the seed.

    SIGMAC_SRC=/path/to/compiler python3 fuzz_diff.py --seed 1
    make diffuzz SIGMAC_SRC=/path/to/compiler

This target needs a full external Sigma compiler and evaluator exposing a
`sigmac` package (`sigmac.compiler.compile_rules`, `sigmac.sigma_eval.
build_matcher`). The bundled reference emitter only serializes; it does not
compile YAML. Any unexpected divergence is a finding; known semantic gaps are
tabulated, not silently patched. This program does not pick a winner.
"""

from __future__ import annotations

import argparse
import os
import random
import re
import subprocess
import sys
import tempfile
import uuid
from collections import Counter

_HERE = os.path.dirname(os.path.abspath(__file__))
_sigmac = os.environ.get("SIGMAC_SRC")
if not _sigmac:
    sys.exit("SIGMAC_SRC is unset: directory that contains the sigmac package")
sys.path.insert(0, _sigmac)

from sigmac.compiler import compile_rules  # noqa: E402
from sigmac.sigma_eval import build_matcher  # noqa: E402

_CLI = os.environ.get(
    "SIGMA_CLI",
    os.path.join(os.path.dirname(_HERE), "build", "sigma_cli"),
)
_HIT = re.compile(
    r"event (\d+): rule=(\d+) verdict=(\w+) sev=(\d+) score=([0-9.]+)"
)
_MISS = re.compile(r"event (\d+): no match")
_CORR_HIT = re.compile(r"event (\d+): corr=(\S+) observed=(-?\d+)")
_LEVEL_SEV = {
    "informational": 0, "low": 1, "medium": 2, "high": 3, "critical": 4,
}
_LEVEL_SCORE = {0: 0.05, 1: 0.10, 2: 0.20, 3: 0.35, 4: 0.50}

# (tag, event_index) -> reason. Documented sigma_eval vs C gaps, not harness
# bugs. Empty while Python backtest matches C on the catalogue; add a row
# when a new op diverges instead of picking a silent winner.
_KNOWN_GAPS: dict[tuple[str, int], str] = {}


def _uid() -> str:
    return str(uuid.uuid4())


def _yaml(title: str, logsource: str, detection: str, level: str = "medium") -> str:
    return (
        f"title: {title}\n"
        f"id: {_uid()}\n"
        f"level: {level}\n"
        f"logsource: {logsource}\n"
        f"detection:\n{detection}"
    )


def _fw(body: str) -> str:
    return _yaml("t", "{category: firewall}", body)


def _proc(body: str) -> str:
    return _yaml("t", "{category: process_creation}", body)


def catalogue(rng: random.Random) -> list[dict]:
    """Explicit cases so every required op/flag is actually generated."""
    cases: list[dict] = []

    def add(tag: str, yaml: str, events: list[tuple[dict, bool | None]]) -> None:
        cases.append({"tag": tag, "yaml": yaml, "events": events})

    add("eq", _fw("    sel:\n        dst_port: 4444\n    condition: sel\n"), [
        ({"destination.port": "4444"}, True),
        ({"destination.port": "80"}, False),
        ({}, False),
    ])
    add("contains", _proc(
        "    sel:\n        CommandLine|contains: '-enc'\n    condition: sel\n"), [
        ({"process.command_line": "powershell -enc ZZ"}, True),
        ({"process.command_line": "POWERSHELL -ENC zz"}, True),
        ({"process.command_line": "nothing"}, False),
        ({}, False),
    ])
    add("startswith", _proc(
        "    sel:\n        Image|startswith: 'C:\\Windows'\n    condition: sel\n"), [
        ({"process.executable": r"C:\Windows\System32\cmd.exe"}, True),
        ({"process.executable": r"D:\Windows\cmd.exe"}, False),
    ])
    add("endswith", _proc(
        "    sel:\n        Image|endswith: '\\cmd.exe'\n    condition: sel\n"), [
        ({"process.executable": r"C:\Windows\System32\cmd.exe"}, True),
        ({"process.executable": r"C:\Windows\System32\powershell.exe"}, False),
    ])
    add("exists", _fw(
        "    sel:\n        src_ip|exists: true\n    condition: sel\n"), [
        ({"source.ip": "10.0.0.1"}, True),
        ({"source.ip": ""}, False),
        ({}, False),
    ])
    add("gt", _fw("    sel:\n        dst_port|gt: 1024\n    condition: sel\n"), [
        ({"destination.port": "2048"}, True),
        ({"destination.port": "80"}, False),
        ({"destination.port": "2048/tcp"}, True),
    ])
    add("gte", _fw("    sel:\n        dst_port|gte: 1024\n    condition: sel\n"), [
        ({"destination.port": "1024"}, True),
        ({"destination.port": "1023"}, False),
    ])
    add("lt", _fw("    sel:\n        dst_port|lt: 1024\n    condition: sel\n"), [
        ({"destination.port": "80"}, True),
        ({"destination.port": "2048"}, False),
    ])
    add("lte", _fw("    sel:\n        dst_port|lte: 1024\n    condition: sel\n"), [
        ({"destination.port": "1024"}, True),
        ({"destination.port": "1025"}, False),
    ])
    add("re", _proc(
        "    sel:\n        CommandLine|re: 'port \\d{3,}'\n    condition: sel\n"), [
        ({"process.command_line": "connect to port 443 now"}, True),
        ({"process.command_line": "port 12"}, False),
    ])
    add("cidr4", _fw(
        "    sel:\n        src_ip|cidr: '10.0.0.0/8'\n    condition: sel\n"), [
        ({"source.ip": "10.1.2.3"}, True),
        ({"source.ip": "11.0.0.1"}, False),
    ])
    add("cidr6", _fw(
        "    sel:\n        src_ip|cidr: '2001:db8::/32'\n    condition: sel\n"), [
        ({"source.ip": "2001:db8::1"}, True),
        ({"source.ip": "2001:db9::1"}, False),
    ])
    add("or_list", _fw(
        "    sel:\n        dst_port:\n            - 4444\n            - 5555\n"
        "    condition: sel\n"), [
        ({"destination.port": "4444"}, True),
        ({"destination.port": "5555"}, True),
        ({"destination.port": "80"}, False),
    ])
    add("and_fields", _proc(
        "    sel:\n        Image|endswith: '\\cmd.exe'\n"
        "        CommandLine|contains: '/c'\n    condition: sel\n"), [
        ({"process.executable": r"C:\cmd.exe", "process.command_line": "cmd /c dir"}, True),
        ({"process.executable": r"C:\cmd.exe", "process.command_line": "cmd"}, False),
    ])
    add("not", _proc(
        "    sel:\n        CommandLine|contains: 'powershell'\n"
        "    filter:\n        User|startswith: 'NT AUTHORITY'\n"
        "    condition: sel and not filter\n"), [
        ({"process.command_line": "powershell -enc", "user.name": "alice"}, True),
        ({"process.command_line": "powershell -enc", "user.name": "NT AUTHORITY\\SYSTEM"}, False),
    ])
    add("or_cond", _fw(
        "    a:\n        dst_port: 4444\n    b:\n        src_ip|cidr: '10.0.0.0/8'\n"
        "    condition: a or b\n"), [
        ({"destination.port": "4444", "source.ip": "1.2.3.4"}, True),
        ({"destination.port": "80", "source.ip": "10.9.8.7"}, True),
        ({"destination.port": "80", "source.ip": "1.2.3.4"}, False),
    ])
    add("cased", _proc(
        "    sel:\n        Image|cased|endswith: '\\MiMiKatz.exe'\n    condition: sel\n"), [
        ({"process.executable": r"C:\tools\MiMiKatz.exe"}, True),
        ({"process.executable": r"C:\tools\mimikatz.exe"}, False),
    ])
    add("fieldref", _fw(
        "    sel:\n        src_ip|fieldref: dst_ip\n    condition: sel\n"), [
        ({"source.ip": "10.0.0.1", "destination.ip": "10.0.0.1"}, True),
        ({"source.ip": "10.0.0.1", "destination.ip": "10.0.0.2"}, False),
    ])
    add("re_i", _proc(
        "    sel:\n        CommandLine|re|i: 'Invoke-'\n    condition: sel\n"), [
        ({"process.command_line": "invoke-expression"}, True),
        ({"process.command_line": "INVOKE-expression"}, True),
    ])
    add("windash", _proc(
        "    sel:\n        CommandLine|windash|contains: '-enc'\n    condition: sel\n"), [
        ({"process.command_line": "powershell -enc ZZ"}, True),
        ({"process.command_line": "powershell /enc ZZ"}, True),
    ])
    for i in range(8):
        needle = rng.choice(["foo", "bar", "xyz", "ENC"])
        hit = f"pre {needle} post"
        add(f"rand_contains_{i}", _proc(
            f"    sel:\n        CommandLine|contains: '{needle}'\n    condition: sel\n"), [
            ({"process.command_line": hit}, True),
            ({"process.command_line": "zzz"}, False),
        ])
    return cases


def _event_tsv(ev: dict) -> str:
    return "\t".join(f"{k}={v}" for k, v in ev.items())


def _run_c(artifact: bytes, events: list[dict], tmp: str,
           corr_json: str | None = None) -> tuple[list[set[tuple]], list[set[tuple]]]:
    """Per event: matcher hits (rule_id, verdict, sev, score) and corr fires (id, observed)."""
    art = os.path.join(tmp, "r.sigmac")
    evf = os.path.join(tmp, "e.tsv")
    with open(art, "wb") as f:
        f.write(artifact)
    with open(evf, "w", encoding="utf-8") as f:
        for ev in events:
            f.write(_event_tsv(ev) + "\n")
    cmd = [_CLI, art]
    if corr_json:
        cj = os.path.join(tmp, "r.corr.json")
        with open(cj, "w", encoding="utf-8") as f:
            f.write(corr_json)
        cmd.append(cj)
    with open(evf, "rb") as stdin_f:
        proc = subprocess.run(
            cmd, stdin=stdin_f, capture_output=True, text=True, check=False,
        )
    if proc.returncode != 0:
        raise subprocess.CalledProcessError(
            proc.returncode, cmd, proc.stdout, proc.stderr,
        )
    out = proc.stdout
    rows: dict[int, set[tuple]] = {i + 1: set() for i in range(len(events))}
    corrs: dict[int, set[tuple]] = {i + 1: set() for i in range(len(events))}
    for line in out.splitlines():
        m = _HIT.search(line)
        if m:
            idx = int(m.group(1))
            rows[idx].add((int(m.group(2)), m.group(3), int(m.group(4)), m.group(5)))
            continue
        m = _CORR_HIT.search(line)
        if m:
            idx = int(m.group(1))
            corrs[idx].add((m.group(2), int(m.group(3))))
            continue
        m = _MISS.search(line)
        if m:
            rows[int(m.group(1))] = set()
    return (
        [rows[i + 1] for i in range(len(events))],
        [corrs[i + 1] for i in range(len(events))],
    )


def _run_py(yaml: str, events: list[dict], sidecar: dict) -> list[set[tuple]]:
    matcher, _title = build_matcher(yaml)
    meta = sidecar.get(1) or sidecar.get("1") or {}
    level = (meta.get("level") or "medium").lower()
    sev = _LEVEL_SEV.get(level, 2)
    score = f"{_LEVEL_SCORE[sev]:.2f}"
    verd = (meta.get("verdict") or "alert").lower()
    out: list[set[tuple]] = []
    for ev in events:
        if matcher(ev):
            out.append({(1, verd, sev, score)})
        else:
            out.append(set())
    return out


def _compare_case(case: dict, tmp: str) -> dict:
    yaml = case["yaml"]
    events = [e for e, _expect in case["events"]]
    res = compile_rules(yaml, drop_unmapped=False)
    if res.errors or not res.sidecar:
        return {"tag": case["tag"], "compile_error": res.errors, "gaps": [], "findings": [
            {"event": None, "why": f"compile failed: {res.errors}"}
        ], "dump": []}
    py = _run_py(yaml, events, res.sidecar)
    try:
        c, _c_corr = _run_c(res.artifact, events, tmp)
    except subprocess.CalledProcessError as e:
        return {"tag": case["tag"], "compile_error": None, "gaps": [], "findings": [
            {"event": None, "why": f"sigma_cli failed: {e.stderr or e}"}
        ], "dump": []}
    gaps: list[dict] = []
    findings: list[dict] = []
    for i, (_ev, expect) in enumerate(case["events"]):
        py_hit, c_hit = bool(py[i]), bool(c[i])
        gap = _KNOWN_GAPS.get((case["tag"], i))
        if py[i] != c[i]:
            rec = {"event": i, "why": f"py={py[i]} c={c[i]}", "yaml": yaml}
            if gap:
                rec["gap"] = gap
                gaps.append(rec)
            else:
                findings.append(rec)
            continue
        if expect is not None and py_hit != expect:
            findings.append({
                "event": i,
                "why": f"event {i}: expect={expect} py={py_hit} c={c_hit} (agreed)",
                "yaml": yaml,
            })
    dump = []
    for i, hits in enumerate(c):
        for h in sorted(hits):
            dump.append(f"M\t{case['tag']}\t{i}\t{h[0]}\t{h[1]}\t{h[2]}\t{h[3]}")
    return {"tag": case["tag"], "compile_error": None, "gaps": gaps, "findings": findings,
            "dump": dump}


_CORR_BASE = """title: ssh fail
id: 11111111-1111-1111-1111-111111111111
name: ssh_failed_login
logsource: {category: authentication}
detection:
  sel:
    event.action: authentication_failure
  condition: sel
---
title: ssh ok
id: 22222222-2222-2222-2222-222222222222
name: ssh_login_ok
logsource: {category: authentication}
detection:
  sel:
    event.action: authentication_success
  condition: sel
"""


def _corr_compile_checks() -> list[str]:
    findings: list[str] = []
    xor = _CORR_BASE + """---
title: xor not in subset
name: ssh_xor
correlation:
  type: temporal
  rules: [ssh_failed_login, ssh_login_ok]
  group-by: [source.ip]
  timespan: 10m
  condition: ssh_failed_login xor ssh_login_ok
"""
    res = compile_rules(xor)
    compiled_ids = [c.id for c in (res.correlations or [])]
    if "ssh_xor" in compiled_ids:
        findings.append("sep198 xor compiled; must drop at sigmac")
    ok = _CORR_BASE + """---
title: A and not B
name: ssh_and_not
correlation:
  type: temporal
  rules: [ssh_failed_login, ssh_login_ok]
  group-by: [source.ip]
  timespan: 10m
  condition: ssh_failed_login and not ssh_login_ok
"""
    res2 = compile_rules(ok)
    hit = [c for c in (res2.correlations or []) if c.id == "ssh_and_not"]
    if not hit or not hit[0].condition_rpn:
        findings.append("sep198 and/not did not compile to condition_rpn")
    return findings


def _corr_fire_cases() -> list[dict]:
    """C correlation fires (sigma_cli + rules.corr.json). Not the Python
    backtest: that path is a sliding-window count, not classify_corr.c.
    Cross-arch identity is native dump vs scalar dump vs amd64 SSE4.2 dump.
    """
    fail = {"event.action": "authentication_failure", "source.ip": "203.0.113.9"}
    yaml = _CORR_BASE + """---
title: three fails
name: brute
correlation:
  type: event_count
  rules: [ssh_failed_login]
  group-by: [source.ip]
  timespan: 5m
  condition:
    gte: 3
"""
    events = [
        {**fail, "_ts": "100"},
        {**fail, "_ts": "101"},
        {**fail, "_ts": "102"},
        {**fail, "source.ip": "198.51.100.1", "_ts": "103"},
    ]
    return [{"tag": "corr_event_count", "yaml": yaml, "events": events,
             "expect": {2: {("brute", 3)}}}]


def _run_corr_case(case: dict, tmp: str) -> dict:
    res = compile_rules(case["yaml"], drop_unmapped=False)
    findings: list[dict] = []
    dump: list[str] = []
    if res.errors or not res.sidecar:
        return {"tag": case["tag"], "findings": [
            {"why": f"compile failed: {res.errors}"}
        ], "dump": []}
    try:
        _hits, corrs = _run_c(
            res.artifact, case["events"], tmp,
            corr_json=res.correlation_artifact,
        )
    except subprocess.CalledProcessError as e:
        return {"tag": case["tag"], "findings": [
            {"why": f"sigma_cli corr failed: {e.stderr or e}"}
        ], "dump": []}
    expect = case.get("expect") or {}
    for i, got in enumerate(corrs):
        want = expect.get(i, set())
        if got != want:
            findings.append({
                "event": i,
                "why": f"corr fires got={got} want={want}",
            })
        for cid, obs in sorted(got):
            dump.append(f"C\t{case['tag']}\t{i}\t{cid}\t{obs}")
    return {"tag": case["tag"], "findings": findings, "dump": dump}


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--seed", type=int, default=1)
    ap.add_argument("--strict", action="store_true",
                    help="treat known gaps as findings (exit 1)")
    ap.add_argument("--dump", metavar="PATH",
                    help="write canonical matcher+corr hitset for arch compare")
    args = ap.parse_args()
    rng = random.Random(args.seed)
    if not os.path.isfile(_CLI):
        print(f"fuzz_diff: missing {_CLI}; run `make cli`", file=sys.stderr)
        return 2
    cases = catalogue(rng)
    covered = Counter(c["tag"].split("_")[0] for c in cases)
    all_gaps: list[dict] = []
    all_findings: list[dict] = []
    dump_lines: list[str] = [f"# fuzz_diff seed={args.seed}"]
    with tempfile.TemporaryDirectory() as tmp:
        for case in cases:
            r = _compare_case(case, tmp)
            all_gaps.extend({"tag": r["tag"], **g} for g in r["gaps"])
            all_findings.extend({"tag": r["tag"], **f} for f in r["findings"])
            dump_lines.extend(r.get("dump") or [])
        for ccase in _corr_fire_cases():
            cr = _run_corr_case(ccase, tmp)
            all_findings.extend({"tag": cr["tag"], **f} for f in cr["findings"])
            dump_lines.extend(cr.get("dump") or [])
    print(f"fuzz_diff seed={args.seed} cases={len(cases)}")
    print("coverage (generated tags):")
    for tag, n in sorted(covered.items()):
        print(f"  {n:3d}  {tag}")
    print(f"gaps (known): {len(all_gaps)}")
    for g in all_gaps:
        print(f"  [{g['tag']}] event {g['event']}: {g.get('gap', g['why'])}")
    findings = list(all_findings)
    if args.strict:
        findings.extend(
            {**g, "why": f"strict: {g.get('gap', g['why'])}"} for g in all_gaps
        )
    corr_findings = _corr_compile_checks()
    print(f"corr compile checks: {len(corr_findings)} finding(s)")
    findings.extend({"tag": "corr", "why": w} for w in corr_findings)
    if args.dump:
        with open(args.dump, "w", encoding="utf-8") as fh:
            fh.write("\n".join(dump_lines) + "\n")
        print(f"wrote dump {args.dump} ({len(dump_lines)} lines)")
    if not findings:
        print("PASS: no unexpected C/Python divergence")
        print("PASS: correlation compiler SEP subset (xor drop / and-not RPN)")
        print("PASS: correlation C fires (event_count)")
        return 0
    print(f"FINDINGS: {len(findings)} unexpected divergence(s)")
    for f in findings[:20]:
        print(f"  [{f['tag']}] {f['why']}")
        yaml = f.get("yaml") or ""
        if yaml:
            print("    yaml:")
            for line in yaml.splitlines()[:16]:
                print(f"      {line}")
    if len(findings) > 20:
        print(f"  ... {len(findings) - 20} more")
    print(f"reproduce: python3 fuzz_diff.py --seed {args.seed}")
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
