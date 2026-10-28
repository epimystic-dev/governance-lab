# envelope

**Worker output envelope**: a small JSON Schema 2020-12 subset describing what an
autonomous worker returns to its host, plus a stdlib-only reference validator and a
cross-field discipline engine that catches the real failure modes - a worker that
marks `status=ok` with no checker run, a HIGH finding with no evidence, an iterated
reasoning tag without a checker role recorded.

## The problem it solves

Autonomous workers (agents, pipelines, review bots) write back structured results.
The host decides on that return value alone whether to accept, retry, escalate, or
roll back. Two gaps are consistently named on that return surface:

- **Output contracts are usually unenforced.** Tool-schema contracts validate inputs
  before a call but not outputs after; mismatches propagate through the agent's
  reasoning chain unflagged.
- **Workers routinely mark their own output verified.** That collapses the
  maker-checker separation governance regimes (EU AI Act Article 12 logging,
  OWASP LLM06, enterprise AI governance playbooks) assume exists.

`envelope` ships a small schema for the return value and a rules engine with the
cross-field discipline the schema shape alone cannot express.

## Install and run

Python 3.9 or later. No third-party dependencies.

```
python -m pip install -e .
python -m envelope path/to/envelope.json
```

Flags:

- `--json` emit a JSON report on stdout
- `--strict` any finding returns a non-zero rc (default already does this)
- `--include-info` include INFO-severity findings
- `--disable RULE` suppress a rule id (repeatable)
- `--print-rules` print the rule registry and exit
- `--print-schema` print the JSON Schema and exit
- `--help` / `--version`

Return codes:

- `0` clean
- `1` LOW or MEDIUM findings
- `2` any HIGH finding, structural (schema) failure, or unreadable input

## Library use

```python
import envelope

env = envelope.load("env.json")
envelope.validate(env)            # raises ValidationError on shape failure
result = envelope.scan(env)       # ScanResult: findings + verdict
print(result.verdict)             # Verdict.HEALTHY / NEEDS_ATTENTION / UNHEALTHY

# Or just:
result = envelope.check(env)      # validate + scan
```

The public API:

| Export | What it is |
|---|---|
| `__version__` | semver string |
| `Severity` | enum: HIGH / MEDIUM / LOW / INFO |
| `Verdict` | enum: healthy / needs-attention / unhealthy / unknown |
| `Finding` | dataclass for one rule hit |
| `ScanResult` | dataclass carrying findings and a verdict |
| `Rule` | one entry in the rule registry |
| `ALL_RULES` | the rule registry (a list of Rule objects) |
| `SCHEMA` | the JSON Schema document |
| `ValidationError` | raised on structural failure, carries `.errors` |
| `validate(env)` | structural check |
| `scan(env)` | cross-field rules check |
| `check(env)` | both |
| `load(path_or_text)` | parse a path or an inline JSON string |

## The envelope shape

```json
{
  "envelope_version": "0.1.0",
  "task_id": "example-task-001",
  "status": "ok",
  "scope": {"in": ["inputs/a"], "out": ["outputs/report.md"]},
  "findings": [],
  "evidence": [
    {"claim": "input was present",
     "kind": "file",
     "ref": "inputs/a",
     "hash": "sha256:..."}
  ],
  "reasoning_tag": "reasoning-iterated",
  "self_audit": {
    "checker_run": true,
    "checker_role": "reviewer",
    "verdict": "ok",
    "reasons": []
  },
  "timestamp": "2026-10-18T09:30:00Z"
}
```

Enums:

- `status` is one of `ok` / `partial` / `failed` / `blocked`
- `reasoning_tag` is one of `normal` / `reasoning` / `iterated` / `reasoning-iterated`
- `self_audit.verdict` is one of `ok` / `fail` / `unknown`
- finding `severity` is one of `HIGH` / `MEDIUM` / `LOW` / `INFO`
- evidence `kind` is one of `cite` / `file` / `measure` / `external`

## The rules

| id | severity | title |
|---|---|---|
| `ENV-001` | HIGH | `status=ok` requires `self_audit.checker_run=true` |
| `ENV-002` | HIGH | `reasoning_tag=iterated` or `reasoning-iterated` requires `checker_run=true` |
| `ENV-003` | HIGH | HIGH finding requires at least one evidence item |
| `ENV-004` | MEDIUM | `self_audit.verdict=ok` with non-empty `reasons[]` is inconsistent |
| `ENV-005` | HIGH | `status=failed` requires at least one finding of severity MEDIUM or HIGH |
| `ENV-006` | MEDIUM | `scope.in` and `scope.out` must be non-empty |
| `ENV-007` | HIGH | self-attestation fields (`verified_by_author`, `safe_to_merge`, ...) are forbidden |
| `ENV-008` | MEDIUM | evidence array empty while findings have severity MEDIUM or HIGH |
| `ENV-009` | MEDIUM | timestamp is not RFC3339-shaped |
| `ENV-010` | MEDIUM | `checker_run=true` requires `checker_role` to be named |
| `ENV-011` | LOW | finding `evidence_refs` point outside the `evidence` array |
| `ENV-012` | MEDIUM | `envelope_version` is not a version this validator recognises |
| `ENV-013` | HIGH | `self_audit.verdict=ok` or `fail` requires `checker_run=true` |
| `ENV-014` | HIGH | `self_audit.verdict=fail` requires at least one entry in `reasons[]` |

Rule bodies live in `envelope/rules.py`; the registry is `envelope.ALL_RULES`.

## Honest scope

What this does:

- Validates envelope shape against the shipped JSON Schema 2020-12 document.
- Flags fourteen named cross-field inconsistencies by rule id.
- Prints an ASCII-safe text report (non-ASCII rendered as `<U+XXXX>`) or a JSON report.

What this does not do:

- Does not verify that any field is true. A worker that lies about `checker_run`
  passes `ENV-001`. The rules engine checks internal consistency, not external
  truth; an envelope that passes is **origin-valid, content-unverified**, never
  **verified-safe**.
- Does not certify safety, honesty, or alignment of the system that produced the
  envelope. The schema is a contract on the return value, not a guarantee about
  the worker.
- Does not translate findings into enforcement actions. That belongs to a policy
  engine; this project is the shape and the discipline it enforces, not the gate.

False-positive modes:

- `ENV-009` uses a pragmatic RFC3339 shape (regex, not calendar); exotic-but-valid
  timestamps may still fire.
- `ENV-012` fires on any `envelope_version` the shipped validator does not know;
  a newer-than-known version is not necessarily wrong, only unverifiable here.

## How it is made

This project is produced by **a human-machine hybrid intelligence** under a
maker-checker discipline. Rule bodies are derived from the public abstract of
arXiv 2609.28216 (*From Agent Output to Authorized Transition*) and arXiv
2601.20727 (*Audit Trails for Accountability in Large Language Models*), the
publicly observable JSON Schema 2020-12 vocabulary, and reasoning-depth-tag
discipline documented in public reasoning-model literature. No reference
implementation (of any named framework, enterprise platform, or paper companion
code) was read, vendored, or mirrored. **Not affiliated with or endorsed by** the
authors of either paper, any named platform, or any standards body.

## License

Apache-2.0. See `LICENSE`.
