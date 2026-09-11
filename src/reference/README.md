# Reference `.sigmac` emitter

`sigmac/format.py` is a standard-library Python serializer for the `.sigmac`
artifact. It is the companion to the normative spec in
`../docs/SIGMAC_FORMAT.md`: where the spec describes the byte layout in prose,
this code produces those bytes.

It does **not** parse Sigma YAML. `SigmaDbBuilder` takes already-lowered
predicates, selections, conditions, rules, CIDRs, buckets, and literal-prefilter
postings, and emits a CRC-stamped `.sigmac`. A full YAML-to-`.sigmac` compiler
is a separate program.

## Use

```python
import sys
sys.path.insert(0, "src/reference")
from sigmac.format import SigmaDbBuilder, Op, Verdict

b = SigmaDbBuilder()
vid = b.value("mimikatz.exe")
ps = b.begin_sel()
b.pred("process.name", int(Op.ENDSWITH), value_id=vid)
sel = b.end_sel(ps)
b.rule(200, sel, 1, verdict=int(Verdict.ALERT), severity=4, score_x100=50)
open("rules.sigmac", "wb").write(b.serialize())
```

`../conformance_emit.py` and `../fuzz_corpus/gen_seed.py` use it. `make
conformance` builds an artifact with this emitter and matches it with the C
`sigma_cli`, proving the Python and C layouts agree by execution.

## Keeping it in sync

The authoritative layout is `../sigma_format.h` (locked by `_Static_assert`) and
`../docs/SIGMAC_FORMAT.md`. When a `.sigmac` format change lands in the C code,
update the struct packs here in the same change; `make conformance` fails loudly
on any drift.
