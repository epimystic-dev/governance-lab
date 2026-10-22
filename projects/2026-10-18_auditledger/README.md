# auditledger

**Append-only, hash-chained JSONL ledger** with `append`, `verify`, `digest`, and
`head`. One file; every row commits to the previous one via SHA-256 over a
canonical serialisation, so a reviewer can localise any tamper, reorder, deletion,
or insertion to the exact sequence number where it happened.

## The problem it solves

Governance regimes for AI agents in 2026 (EU AI Act Article 12 logging, OWASP
LLM06, enterprise AI governance playbooks) assume a tamper-evident audit trail of
what an agent decided and did, keyed to the exact row where any tampering happened.
Multiple independent 2026 implementations converge on the same shape - an
append-only JSONL where each line's integrity-hash commits to the previous one
via SHA-256 over a canonical serialisation - because the shape is small enough
to be correct, verifiable with a stdlib tool, and local-filesystem-friendly.

`auditledger` ships the primitive, nothing more: a `Ledger` facade with
`append / verify / digest / head`, a stdlib-only canonical JSON serialiser, and
a CLI that returns `rc 0` clean, `rc 2` on a broken chain, and names the first
row that fails.

## Install and run

Python 3.9 or later. No third-party dependencies.

```
python -m pip install -e .
python -m auditledger init  path/to/ledger.jsonl
python -m auditledger append  path/to/ledger.jsonl --kind decision \
     --payload '{"action":"approve"}'
python -m auditledger verify  path/to/ledger.jsonl
python -m auditledger digest  path/to/ledger.jsonl
python -m auditledger head    path/to/ledger.jsonl
```

Verify return codes:

- `0` clean
- `1` MEDIUM / LOW defects (shape only; chain still verifies cryptographically)
- `2` any HIGH defect (chain broken, missing field, bad JSON, missing file)

Append / init return codes:

- `0` success
- `2` caller error (invalid JSON payload, bad timestamp, ledger already exists)

Flags:

- `verify`: `--json`, `--disable AL-NNN`, `--include-info`
- `append`: `--kind`, `--payload JSON | --payload-file PATH`, `--ts`, `--json`
- global: `--version`, `--help`, `--print-rules`

## Library use

```python
import auditledger

L = auditledger.Ledger("agent.jsonl")
L.init()

e = L.append("tool-call", {"tool": "read_record", "args_hash": "sha256:..."})
print(e.seq, e.hash)                 # 0, 64 hex chars

L.append("decision", {"action": "approve"})

result = L.verify()                  # ScanResult
print(result.verdict)                # Verdict.HEALTHY
print(result.head_hash)              # the HEAD digest

print(L.digest())                    # HEAD hash directly
```

The public API:

| Export | What it is |
|---|---|
| `__version__` | semver string |
| `Severity` | enum: HIGH / MEDIUM / LOW / INFO |
| `Verdict` | enum: healthy / needs-attention / unhealthy / unknown |
| `Finding` | one verify defect (rule, severity, message, seq, line_number) |
| `ScanResult` | findings, verdict, entries_checked, head_hash |
| `Rule` | one entry in the rule registry |
| `ALL_RULES` | the verify rule registry (a list of Rule objects) |
| `Entry` | one ledger row (seq, ts, kind, payload, prev, hash) |
| `LedgerError` | raised on ledger-side errors (bad input, bad shape, I/O) |
| `Ledger` | facade bundling init / append / verify / digest / head |
| `append`, `verify`, `digest`, `head`, `init` | functional API |
| `canonical_bytes(obj)` | canonical JSON encoding used for hashing |

## The row shape

Every row is one JSON object per line, UTF-8, with fixed fields:

| field | type | what it is |
|---|---|---|
| `seq` | integer | zero-based, strictly `+1` per row |
| `ts` | string | RFC3339 UTC timestamp (`2026-10-18T09:30:00.000000Z`) |
| `kind` | string | user-defined row-kind tag |
| `payload` | any | arbitrary JSON-serialisable value |
| `prev` | string | hex SHA-256 of previous row's `hash`; 64 zeros for seq=0 |
| `hash` | string | hex SHA-256 of canonical({seq, ts, kind, payload, prev}) |

The canonical encoding is Python stdlib `json.dumps` with `sort_keys=True`,
`separators=(",", ":")`, `ensure_ascii=False`, `allow_nan=False`.

## The verify rules

| id | severity | title |
|---|---|---|
| `AL-001` | HIGH | line is not valid JSON |
| `AL-002` | HIGH | row is not a JSON object |
| `AL-003` | HIGH | row is missing a required field |
| `AL-004` | HIGH | `seq` is out of order |
| `AL-005` | HIGH | `prev` does not match the previous row's hash |
| `AL-006` | HIGH | `hash` does not match the row's content |
| `AL-007` | MEDIUM | `ts` is not RFC3339-shaped |
| `AL-008` | MEDIUM | `hash` or `prev` is not a 64-char lowercase hex string |
| `AL-009` | MEDIUM | `kind` is empty or not a string |

## Honest scope

What this does:

- Appends rows to a JSONL file, hashing each row with SHA-256 over its own
  content and the previous row's hash.
- Verifies the chain in one pass and reports every documented defect by rule id,
  localised to the sequence number and the line number.
- Prints an ASCII-safe text report (non-ASCII rendered as `<U+XXXX>`) or a JSON
  report.

What this does not do:

- Does not sign rows. SHA-256 alone catches *tampering by someone who could not
  rewrite the whole chain*; an attacker with write access to the ledger file can
  always rebuild the chain from any seq onwards. If you need signing, chain this
  to an HMAC or an asymmetric signature; this is the primitive, not the protocol.
- Does not synchronise concurrent writers. Open-for-append on POSIX and modern
  Windows is atomic for a single small write; two concurrent processes may
  interleave bytes. If you need concurrent writes, hold a file lock around the
  append or route writes through a single-writer queue.
- Does not back-fill or anchor to any external beacon (block chain, timestamp
  authority, witness ledger). Framed as an **audit substrate for agent systems**,
  never as a new cryptographic primitive.
- Does not certify safety or correctness of the system that wrote the ledger. A
  clean verify is **origin-valid, content-unverified**, never **verified-safe**.

False-positive modes:

- `AL-007` uses a pragmatic RFC3339 shape (regex, not calendar); exotic-but-
  valid timestamps may fire.
- `AL-008` fires on mixed-case or non-lowercase hex; a ledger produced by a
  caller that writes uppercase hex is still verifiable cryptographically, but
  this project writes and expects lowercase.

## How it is made

This project is produced by **a human-machine hybrid intelligence** under a
maker-checker discipline. The hash-chain shape is a converged pattern described
in multiple public 2026 sources (topcheer/ggcode PR 2472 abstract, hermes-agent
issue 487, chenhz01/agent-audit-trail README, and the dev.to walk-through
"hash-chained audit logs for AI agent actions, in 40 lines"). The canonical JSON
encoding is the publicly observable Python stdlib `json.dumps` parameterisation.
No reference implementation from any named repository was read, vendored, or
mirrored. **Not affiliated with or endorsed by** any of the named implementations
or any standards body.

## License

Apache-2.0. See `LICENSE`.
