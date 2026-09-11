# The `.sigmac` artifact format, and how to build a compiler

libsigma never parses Sigma YAML. It loads a compiled binary artifact,
`.sigmac`, and matches events against it. A YAML-to-`.sigmac` compiler is a
separate program; the format is fully specified here so that anyone can build
one in any language.

A standard-library Python emitter is bundled under `src/reference/sigmac/`
(`SigmaDbBuilder`). It serializes the sections below and computes the CRC; it
does not itself parse YAML. `src/conformance_emit.py` uses it to prove the
Python and C on-disk layouts agree by execution.

This is a normative specification. The authoritative source is
`sigma_format.h` / `sigma_match.h`; this document restates their contract and
adds a worked build walkthrough.

## Conventions

- **Endianness:** little-endian throughout. Producer and consumer are the same
  architecture family (amd64 / aarch64), both little-endian.
- **Alignment:** every section starts at an 8-byte aligned file offset. Pad the
  gap between sections with zero bytes.
- **Sizes are fixed** and locked by `_Static_assert` in `sigma_format.h`; a
  compiler MUST emit exactly these byte layouts or the loader rejects the file.

## File layout

```
[ sigma_hdr_t ]                     fixed header (144 bytes; v4 was 136)
[ fields   : sigma_str_t   x n_fields ]   interned field-name refs
[ values   : sigma_str_t   x n_values ]   interned literal-operand refs
[ preds    : sigma_pred_t  x n_preds  ]
[ sels     : sigma_sel_t   x n_sels   ]
[ cond     : sigma_ctok_t  x n_cond   ]
[ rules    : sigma_rule_t  x n_rules  ]
[ cidrs    : sigma_cidr_t  x n_cidrs  ]
[ bkeys    : sigma_str_t   x n_buckets ]  bucket keys (event.category or product/service)
[ buckets  : sigma_bucket_t x n_buckets ] per-key rule-index slices
[ bidx     : uint32        x n_bucket_idx ] flat rule-INDEX pool
[ litndl   : sigma_str_t   x n_litndl ]   case-folded prefilter needles
[ litpost  : sigma_litpost_t x n_litndl ] per-needle postings slices
[ litpref  : sigma_litref_t x n_litpost_ref ] (rule, field, clause) postings
[ litav    : uint32        x n_litav  ]   always-verify rule indices
[ rclause  : uint8         x n_rules  ]   witness clauses per rule
[ fwit     : sigma_fwit_t  x n_fwit   ]   numeric/CIDR CNF atoms (v5; empty on v4)
[ strpool  : char          x strpool_len ]
[ crc32c   : uint32 ]                     CRC32C over [0 .. total_size-4)
```

Sections whose count is 0 occupy no bytes; their offset field is 0.

## Header (`sigma_hdr_t`)

Field order, all little-endian. The header is 144 bytes. A v4 file is 136
bytes and loads with `n_fwit = 0`.

| Offset | Field | Type | Notes |
|---|---|---|---|
| 0  | `magic` | u32 | `0x53474D41` ("SGMA", LE) |
| 4  | `version` | u32 | `5` (FROZEN). `4` still loads (compat). Anything else is REJECTED (`SIGMA_ERR_VERSION`). Tamper/truncate is `SIGMA_ERR_CRC` / `SIGMA_ERR_SIZE` / `SIGMA_ERR_RANGE`; the `fuzz_load` target proves a partial load cannot succeed. |
| 8  | `total_size` | u64 | whole file length, includes the trailing CRC |
| 16 | `n_fields`, `off_fields` | u32,u32 | |
| 24 | `n_values`, `off_values` | u32,u32 | |
| 32 | `n_preds`, `off_preds` | u32,u32 | |
| 40 | `n_sels`, `off_sels` | u32,u32 | |
| 48 | `n_cond`, `off_cond` | u32,u32 | |
| 56 | `n_rules`, `off_rules` | u32,u32 | |
| 64 | `strpool_len`, `off_strpool` | u32,u32 | |
| 72 | `n_cidrs`, `off_cidrs` | u32,u32 | |
| 80 | `flags` | u32 | reserved, 0 |
| 84 | `n_buckets`, `off_bkeys` | u32,u32 | bucket index |
| 92 | `off_buckets` | u32 | |
| 96 | `n_bucket_idx`, `off_bucket_idx` | u32,u32 | bucket index |
| 104 | `n_litndl`, `off_litndl` | u32,u32 | literal prefilter |
| 112 | `off_litpost` | u32 | |
| 116 | `n_litpost_ref`, `off_litpost_ref` | u32,u32 | flat (rule, field, clause) postings |
| 124 | `n_litav`, `off_litav` | u32,u32 | |
| 132 | `off_rule_clauses` | u32 | `uint8 x n_rules`; 0 if absent |
| 136 | `n_fwit`, `off_fwit` | u32,u32 | numeric/CIDR CNF atoms; 0/0 on v4 |

Minimal viable output sets the bucket and litidx counts/offsets to 0. The
matcher then runs a full linear scan, which is correct, just slower on large
rulesets. The bucket index and the SIMD literal prefilter are pure accelerators;
add them once the basic path works.

## Section structs

All little-endian. `Nx` = N zero pad bytes.

```
sigma_str_t   (8)   u32 off; u32 len;                     # off,len into strpool
sigma_pred_t  (24)  u16 field_id; u16 group_id; u8 op; u8 flags; 2x;
                    u32 value_id; 4x; i64 ival;
sigma_sel_t   (8)   u32 pred_start; u32 pred_count;
sigma_ctok_t  (8)   u8 kind; 3x; u32 sel_idx;
sigma_rule_t  (32)  u32 rule_id; u32 sel_start; u32 sel_count;
                    u32 cond_start; u32 cond_count;
                    u8 verdict; u8 severity; u16 score_x100;
                    u32 name_id; u32 mitre_id;
sigma_cidr_t  (20)  u8 family; u8 prefix; 2x; u8 net[16];   # network pre-masked
sigma_bucket_t (8)  u32 idx_start; u32 idx_count;           # slice of bidx
sigma_litpost_t(8)  u32 idx_start; u32 idx_count;           # slice of litpref
sigma_litref_t (8)  u32 rule_idx; u16 field_id; u8 clause_idx; u8 pad;
                    # field_id 0xFFFF = unscoped (any field counts)
sigma_fwit_t   (16) u32 rule_idx; u16 field_id; u8 clause_idx; u8 op; i64 ival;
                    # op is GT/GTE/LT/LTE/CIDR/NUMEQ; ival is the rhs, or a
                    # cidrs-table index when op is CIDR. field_id is never 0xFFFF.
```

A posting means: this needle, found in `field_id`, satisfies witness clause
`clause_idx` of `rule_idx`. The matcher gates a rule in only once every clause
has a literal present in the field that clause names. `rclause[i]` is that
rule's clause count (0 = always-verify, never gated). `field_id` indexes the
`fields` table, or is `0xFFFF` when the posting is unscoped.

Python `struct` format strings that produce exactly these:

```
sigma_hdr_t:   "<2IQ32I"   # 144B: magic,ver,total | 8 core pairs | flags | bucket(5) | litidx(7) | fwit(2)
sigma_str_t:        "<2I"
sigma_pred_t:       "<HHBB2xI4xq"
sigma_sel_t:        "<2I"
sigma_ctok_t:       "<B3xI"
sigma_rule_t:       "<5IBBH2I"
sigma_cidr_t:       "<BB2x16s"
sigma_bucket_t:     "<2I"
sigma_litpost_t:    "<2I"
sigma_litref_t:     "<IHBB"
sigma_fwit_t:       "<IHBBq"
```

## The string pool and the field-NUL contract

`strpool` is a flat byte buffer. A `sigma_str_t {off, len}` names the bytes
`strpool[off .. off+len)`.

**Field names MUST be NUL-terminated.** For every entry of the `fields` table,
the byte at `strpool[off + len]` MUST be `\0` (the `len` still EXCLUDES the
terminator). This lets the matcher hand `strpool + off` straight to a C-string
field lookup with no copy. The loader validates this and rejects a
non-terminated artifact. Values, rule titles, MITRE strings, and bucket keys are
length-only and need no terminator (but sharing/ deduping pool bytes is fine).

## Enumerations

```
op (u8):        EQ=0 CONTAINS=1 STARTSWITH=2 ENDSWITH=3 EXISTS=4
                GT=5 GTE=6 LT=7 LTE=8 RE=9 CIDR=10 NUMEQ=11
flags (u8):     CASE=0x01 (case-sensitive)   NEGATE=0x02 (per-predicate NOT)
                FIELDREF=0x04 (operand is another FIELD's value)
verdict (u8):   ALERT=0 BENIGN=1 ESCALATE=2
cond kind (u8): SEL=0 AND=1 OR=2 NOT=3
```

- For `EXISTS`, set `value_id = 0xFFFFFFFF` (`SIGMA_NO_VALUE`).
- For the numeric ops (`GT/GTE/LT/LTE/NUMEQ`), put the operand in `ival` and set
  `value_id = 0xFFFFFFFF`. Unquoted `field: 80` is compiled as GTE+LTE for
  verify; the prefilter posts a single `NUMEQ` atom.
- For `CIDR`, `value_id` indexes the `cidrs` table (NOT `values`); pre-mask the
  network into `net` (v4 in `net[0..3]`). A CIDR field witness stores that
  same table index in `ival`.
- For `RE`, `value_id` indexes `values`; the pattern is the raw regex bytes,
  compiled by the loader with PCRE2 (CASELESS unless `CASE`).
- For `FIELDREF` (flag `0x04`), `value_id` indexes the **fields** table: it names
  the field whose value is the operand. The matcher resolves that field per event
  and applies the string op (EQ/CONTAINS/STARTSWITH/ENDSWITH) against it. Composes
  with `CASE`. The loader range-checks the operand against `n_fields`.

## The selection / condition model

Sigma map-selection semantics are encoded as **AND across predicate groups, OR
within a group**:

```
selection: { fieldA: [x, y], fieldB: z }
  => group 0 = (fieldA==x OR fieldA==y)      # two preds, same group_id
     group 1 = (fieldB==z)                   # one pred, next group_id
     selection matches iff group0 AND group1
```

The builder MUST emit a selection's predicates **contiguous and grouped by
`group_id`** (the matcher relies on this ordering). A `sigma_sel_t` is the slice
`[pred_start, pred_start+pred_count)`.

A rule owns a slice of selections `[sel_start, sel_start+sel_count)` and a slice
of condition tokens `[cond_start, cond_start+cond_count)`:

- `cond_count == 0` => the rule matches iff ALL its selections match (implicit
  AND of them). Use this for `condition: sel` and `all of them`.
- otherwise the tokens are **RPN** over the rule's LOCAL selection indices
  (`sel_idx` is `0 .. sel_count-1`): `SEL` pushes a selection's result; `AND`,
  `OR` pop two and push the combination; `NOT` inverts the top. The stack MUST
  reduce to exactly one value. Depth is bounded (64); keep conditions shallow.

Example RPN for `sel_a and not sel_b`: `SEL(0) SEL(1) NOT AND`.

## CRC32C

Append a trailing `u32` = CRC32C (Castagnoli, reflected polynomial `0x82F63B78`)
computed over the whole file `[0 .. total_size-4)`. This is the same CRC the
loader recomputes (`sigma_crc32c` in `sigma_simd.h`). A mismatch is rejected.

## Loader validation (what your output must satisfy)

The loader rejects (`SIGMA_ERR_RANGE` etc.) any artifact where: a section runs
past end-of-file or is misaligned; a field name is not NUL-terminated; a
`value_id`/`field_id`/`cidr` index/`name_id`/`mitre_id` is out of range; a
selection's pred slice or a rule's sel/cond slice runs past its table; a
condition kind is unknown; a bucket/litidx slice or pool entry is out of range;
an empty prefilter needle. Build to satisfy all of these; they are cheap
invariants that make a corrupt or hostile artifact non-exploitable.

## How to build a compiler (walkthrough)

To compile one rule `image|endswith '\mimikatz.exe' and CommandLine|contains
'-a'` with verdict alert:

1. **Intern strings.** Add field names to `strpool` NUL-terminated, record a
   `sigma_str_t` in `fields` (dedup so each field has a stable id). Add operand
   literals to `strpool` (no NUL needed), record `sigma_str_t` in `values`.
2. **Emit predicates**, grouped. For each `field|modifier: value(s)`, lower the
   modifier to an `op` (+ flags), and emit one `sigma_pred_t` per value in the
   list, all sharing one `group_id`; bump `group_id` for the next field. Lower
   Sigma value modifiers here: `contains/startswith/endswith` map directly;
   wildcards (`*foo*`) lower to `contains`/`startswith`/`endswith` or `RE`;
   `base64`/`windash` expand to literal variants; `cidr` fills the `cidrs` table.
3. **Emit a selection** covering that contiguous predicate range.
4. **Emit the rule**: point it at its selection(s); `cond_count=0` for a single
   selection; set `verdict`, `severity` (0..4), `score_x100`, `name_id`,
   `mitre_id` (or `0xFFFFFFFF`).
5. **(optional) Buckets:** group rules by every logsource token: mapped ECS
   `event.category` plus raw Sigma product/service (`linux`, `cisco`,
   `sshd`, …). Empty logsource -> always-verify key `""`. At match time the
   engine reads the bucket key from a fixed list of event fields, in order:
   `event.category`, then the product-name fields `product`, `techno`,
   `technology`, then the older ECS aliases `observer.product` /
   `event.provider` / `event.module` / `event.dataset` /
   `log.syslog.appname`. It unions every bucket those keys hit; a rule in two
   matching buckets is verified once.
6. **(optional) litidx:** for large buckets, derive each rule's necessary-atom
   CNF (a conjunction of clauses). String atoms (min length 3) post as
   `sigma_litref_t` needles; numeric and CIDR atoms post as `sigma_fwit_t`.
   Rules with no sound required atom go in `litav` and have `rclause[i] = 0`.
7. **Serialize** in section order at 8-aligned offsets, fill the header counts +
   offsets, then append the CRC32C.

Test your output by loading it with `sigma_cli` (the standalone matcher CLI) and
feeding events: `sigma_cli rules.sigmac < events.tsv`. If the loader accepts it
and matches as expected, the format is correct.

## Correlation is separate

Stateful Sigma correlation (`event_count` / `value_count` / `temporal[_ordered]`)
is NOT in the `.sigmac`. It is a separate `rules.corr.json` artifact consumed by
the folded correlation engine, keyed by the compiled rule-ids this matcher
stamps. See `classify_corr.h`.
