# From a Sigma rule to a match: a worked walkthrough

libsigma does not parse Sigma YAML (see `README.md`, "In, not in"). This
walks through the other side of that boundary: taking a real Sigma
detection rule, lowering it by hand to `.sigmac` with the bundled reference
emitter, and matching real events against it with `sigma_cli`. Every command
and every line of output below was run against this tree; there is no
hand-edited output in this file.

A production compiler (pySigma, `sigma_engine`, or your own) automates the
lowering step. This walkthrough does it by hand so the mapping from Sigma
semantics to `.sigmac` structures is explicit. `src/docs/SIGMAC_FORMAT.md` is
the normative reference for every struct and offset used here.

## The rules

Two ordinary Sigma process-creation rules.

```yaml
title: Mimikatz Credential Dumping via Command Line
logsource:
  category: process_creation
  product: windows
detection:
  selection_img:
    Image|endswith: '\mimikatz.exe'
  selection_cli:
    CommandLine|contains:
      - 'sekurlsa'
      - 'logonpasswords'
  condition: selection_img and selection_cli
level: critical
```

```yaml
title: Suspicious Encoded PowerShell Command
logsource:
  category: process_creation
  product: windows
detection:
  selection:
    Image|endswith: '\powershell.exe'
    CommandLine|contains: '-enc'
  filter_legit:
    ParentImage|endswith: '\TrustedTaskHost.exe'
  condition: selection and not filter_legit
level: high
```

The first rule is "AND of all selections", the shape `cond_count == 0`
exists for. The second needs explicit condition RPN (`and not`) and a
two-field AND inside one selection, which is what `group_id` is for.

## Lowering by hand

```python
import sys
sys.path.insert(0, "src/reference")
from sigmac.format import SigmaDbBuilder, Op, Verdict, CTok

b = SigmaDbBuilder()

# --- rule 100: selection_img and selection_cli (implicit AND, cond=None) ---
v_mimi = b.value(r"\mimikatz.exe")
s = b.begin_sel()
b.pred("Image", int(Op.ENDSWITH), value_id=v_mimi, group=0)
sel_img = b.end_sel(s)

v_sekurlsa = b.value("sekurlsa")
v_logonpw = b.value("logonpasswords")
s = b.begin_sel()
b.pred("CommandLine", int(Op.CONTAINS), value_id=v_sekurlsa, group=0)
b.pred("CommandLine", int(Op.CONTAINS), value_id=v_logonpw, group=0)  # OR: same group_id
sel_cli = b.end_sel(s)

b.rule(100, sel_img, 2, verdict=int(Verdict.ALERT), severity=4, score_x100=50,
       name_id=b.value("Mimikatz Credential Dumping via Command Line"),
       mitre_id=b.value("T1003.001"))

# --- rule 200: selection and not filter_legit (explicit RPN) ---
v_ps = b.value(r"\powershell.exe")
v_enc = b.value("-enc")
s = b.begin_sel()
b.pred("Image", int(Op.ENDSWITH), value_id=v_ps, group=0)
b.pred("CommandLine", int(Op.CONTAINS), value_id=v_enc, group=1)  # AND: distinct group_id
sel_main = b.end_sel(s)

v_trusted = b.value(r"\TrustedTaskHost.exe")
s = b.begin_sel()
b.pred("ParentImage", int(Op.ENDSWITH), value_id=v_trusted, group=0)
sel_filter = b.end_sel(s)

cond = [(int(CTok.SEL), 0), (int(CTok.SEL), 1), (int(CTok.NOT), 0), (int(CTok.AND), 0)]
b.rule(200, sel_main, 2, cond=cond, verdict=int(Verdict.ALERT), severity=3, score_x100=35,
       name_id=b.value("Suspicious Encoded PowerShell Command"),
       mitre_id=b.value("T1059.001"))

open("rules.sigmac", "wb").write(b.serialize())
print("wrote rules.sigmac: 2 rules (100, 200)")
```

Three things to notice:

- `Image|endswith` and a plain string become one `sigma_pred_t` with
  `op=ENDSWITH`. A YAML list under one key (`CommandLine|contains: [a, b]`)
  becomes several predicates sharing one `group_id`, since a list is OR.
  Two different keys in one selection (`Image` and `CommandLine` in
  `selection`) get distinct `group_id`s, since distinct keys are AND.
- `condition: selection_img and selection_cli` is exactly "AND of every
  selection in the rule", the case `cond_count == 0` shortcuts. The moment a
  condition says `not` or picks a subset, it needs explicit RPN
  (`SIGMA_C_SEL`/`AND`/`OR`/`NOT` over local selection indices).
- `name_id` and `mitre_id` are optional string-pool references. `sigma_cli`
  and the `sigma_hit_t` struct surface `mitre`; a caller wanting the rule
  title back resolves `name_id` against the same string pool itself.

Save the block above as `lower.py` and run it from the repository root, so
`src/reference` resolves:

```
$ python3 lower.py
wrote rules.sigmac: 2 rules (100, 200)
```

The output is a 727-byte `.sigmac` file, CRC-stamped, ready to load.

## Matching real events

Build `sigma_cli` (`make cli`, or `make` for the full library) and feed it
TAB-separated `key=value` events, one per line. The rules above name the
fields directly (`Image`, `CommandLine`, `ParentImage`), so the TSV uses the
same names; a host integration instead answers these lookups from its own
parsed event, ECS or otherwise (see the `sigma_field_fn` callback in
`README.md`).

```
$ printf 'Image=C:\\tools\\mimikatz.exe\tCommandLine=sekurlsa::logonpasswords\n' > events.tsv
$ printf 'Image=C:\\tools\\mimikatz.exe\tCommandLine=privilege::debug\n' >> events.tsv
$ printf 'Image=C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe\tCommandLine=powershell.exe -enc SQBFAFgA\tParentImage=C:\\Windows\\explorer.exe\n' >> events.tsv
$ printf 'Image=C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe\tCommandLine=powershell.exe -enc SQBFAFgA\tParentImage=C:\\Program Files\\TrustedTaskHost.exe\n' >> events.tsv

$ ./build/sigma_cli rules.sigmac < events.tsv
loaded rules.sigmac: 2 rules, 6 preds, 3 fields, 0 cidrs
event 1: rule=100 verdict=alert sev=4 score=0.50 mitre=T1003.001
event 2: no match
event 3: rule=200 verdict=alert sev=3 score=0.35 mitre=T1059.001
event 4: no match
```

Event 1 fires rule 100: the image ends with `mimikatz.exe` and the command
line contains `sekurlsa`. Event 2 does not: same image, but neither
`sekurlsa` nor `logonpasswords` is in the command line, so `selection_cli`
never matches. Event 3 fires rule 200: encoded PowerShell launched from
`explorer.exe`. Event 4 is the same command line launched from
`TrustedTaskHost.exe`; `filter_legit` matches, `not filter_legit` is false,
the rule does not fire, exactly the false-positive suppression the YAML
asked for.

## Where a real compiler adds work

This walkthrough skips everything a production YAML-to-`.sigmac` compiler
does for you:

- Sigma value modifiers this hand lowering did not need: `|re`, `|cidr`,
  `|base64`, `|windash`, wildcards (`*foo*` beyond a plain prefix/suffix),
  `|fieldref`.
- Deduplicating field and value strings across hundreds of rules (the
  builder's `field()`/`value()` already dedup within one build; a real
  compiler does the same across an entire ruleset).
- Deriving the necessary-literal CNF for the SIMD prefilter
  (`set_litidx`) and the logsource bucket index (`set_buckets`); both are
  optional accelerators (see `SIGMAC_FORMAT.md` steps 5-6), and a compiler
  that skips them still produces a correct, just slower, artifact.
- Mapping your event schema's field names (ECS, raw Sigma field names, or
  your own) to what the rules were authored against.

`src/reference/sigmac/format.py` and `src/conformance_emit.py` are the
existing code most useful to start from for any of the above.
