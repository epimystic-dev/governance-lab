# trustlabels

**Trust-label taxonomy and transition-matrix linter** for the provenance of content
entering an AI agent's reasoning context. One file; a nine-label taxonomy; a seven-edge
promotion matrix; fourteen rules under `TL-NNN` that refuse the real injection paths - a
quarantined entry grounding an action, an untrusted entry grounding an action, a promotion
recorded without a gate, a declared promotion the taxonomy does not permit.

## The problem it solves

The frontier in late 2026 keeps naming the same structural fault: injection succeeds
because there is no shared, enforceable discipline about where the content a model sees
came from. The DigitalApplied 2026 production-agent taxonomy puts it bluntly: 9 of its 10
attack classes arrive through *trusted* channels - retrieved documents, tool outputs,
memory stores, email bodies, collaborating subagents. The CSA Labs MCP tool-poisoning
research note (2026-07-01) says the same about MCP: there is "no envelope marking tool
descriptions as data-not-instructions, no signed origin, no provenance attached."

Hosts can either keep inheriting trust silently from every tool they call, or they can
declare a taxonomy: label every entry at ingress, promote only through a named gate, and
refuse any entry used as grounds for action that has not earned its label. `trustlabels`
ships that primitive, nothing more.

## Install and run

Python 3.9 or later. No third-party dependencies.

```
python -m pip install -e .
python -m trustlabels path/to/bundle.json
```

Flags:

- `--json` emit a JSON report on stdout
- `--strict` any finding returns a non-zero rc (default already does this)
- `--include-info` include INFO-severity findings
- `--disable RULE` suppress a rule id (repeatable)
- `--print-rules` print the rule registry and exit
- `--print-taxonomy` print the labels and transition matrix and exit
- `--help` / `--version`

Return codes:

- `0` clean
- `1` LOW or MEDIUM findings
- `2` any HIGH finding, structural failure, or unreadable input

## Library use

```python
import trustlabels

bundle = trustlabels.load("bundle.json")
trustlabels.validate(bundle)           # raises ValidationError on shape failure
result = trustlabels.scan(bundle)      # ScanResult: findings + verdict
print(result.verdict)                  # Verdict.HEALTHY / NEEDS_ATTENTION / UNHEALTHY

result = trustlabels.check(bundle)     # validate + scan

print(sorted(trustlabels.KNOWN_LABELS))
print(trustlabels.TRANSITIONS["quarantined:web"])
print(trustlabels.GATES[("quarantined:web", "trusted:audited")])
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
| `KNOWN_LABELS` | frozenset of accepted trust labels |
| `TRANSITIONS` | promotion matrix: label -> frozenset of valid targets |
| `GATES` | (current, target) -> frozenset of accepted gate names |
| `ValidationError` | raised on structural failure, carries `.errors` |
| `validate(bundle)` | structural check |
| `scan(bundle)` | rules check |
| `check(bundle)` | both |
| `load(path_or_text)` | parse a path or an inline JSON string |

## The bundle shape

A bundle is either a JSON list of entries, or an object with an `entries` list. Each
entry declares one piece of content that entered the agent's reasoning context:

```json
{
  "entries": [
    {
      "id": "web/vendor-docs/page-3",
      "trust_label": "quarantined:web",
      "source_ref": "https://example.com/docs/page-3",
      "grounds_for_action": false,
      "entered_at": "2026-10-25T09:30:00Z",
      "promoted_to": null,
      "promoted_by": null,
      "promotion_gate": null
    }
  ]
}
```

Only `id` and `trust_label` are structurally required; the rules check the other fields.

## The taxonomy

Four levels, nine qualifiers:

| Label | What it means |
|---|---|
| `trusted:system` | shipped as part of the host; must not derive from an external URL |
| `trusted:audited` | reviewed by a named role and gate |
| `observed:tool` | emitted by a tool call; provenance known, origin not reviewed |
| `observed:user` | emitted by a user; provenance known, origin not reviewed |
| `quarantined:web` | fetched from a URL; adversarial by default |
| `quarantined:scraped` | scraped from a document; adversarial by default |
| `quarantined:tool-output` | tool output with suspected injection |
| `untrusted:derived` | derived from an untrusted input |
| `untrusted:unknown` | provenance not recorded |

The transition matrix (only these promotions are permitted):

| From | To | Accepted gate |
|---|---|---|
| `quarantined:web` | `trusted:audited` | `reviewer` |
| `quarantined:scraped` | `trusted:audited` | `reviewer` |
| `quarantined:tool-output` | `trusted:audited` | `reviewer` |
| `observed:tool` | `trusted:audited` | `reviewer` |
| `observed:user` | `trusted:audited` | `reviewer` |
| `untrusted:derived` | `observed:tool` | `automated-sanitizer` |
| `untrusted:unknown` | `quarantined:web` | `automated-triage` |

Any pair outside this matrix is flagged `TL-003`.

## The rules

| id | severity | title |
|---|---|---|
| `TL-001` | HIGH | quarantined entry used as grounds for action without a complete and valid promotion |
| `TL-002` | HIGH | promotion recorded without a gate (`promoted_by` or `promotion_gate` missing) |
| `TL-003` | HIGH | promotion target unreachable from current label |
| `TL-004` | MEDIUM | promotion target is not a known label |
| `TL-005` | MEDIUM | `trust_label` is not a known label |
| `TL-006` | MEDIUM | `entered_at` is not RFC3339-shaped |
| `TL-007` | HIGH | `trusted:system` entry has an external `source_ref` |
| `TL-008` | LOW | `grounds_for_action` is not explicitly set |
| `TL-009` | HIGH | untrusted entry used as grounds for action without a complete and valid promotion |
| `TL-010` | HIGH | `promotion_gate` is not valid for this transition |
| `TL-011` | LOW | duplicate entry `id` in bundle |
| `TL-012` | MEDIUM | observed or quarantined entry has no `source_ref` |
| `TL-013` | HIGH | promotion target is still a hazard level (staged mid-chain promotion used as grounds) |
| `TL-014` | HIGH | `grounds_for_action` is set but is not a JSON boolean |

A "complete and valid promotion" for `TL-001` / `TL-009` means all three of `promoted_to`,
`promoted_by`, and `promotion_gate` are present, the current-label-to-target transition
is in the taxonomy's matrix, and the gate is accepted for that transition. A bare
`promoted_to` string with no `promoted_by` or `promotion_gate` is a self-awarded
promotion that `TL-002` reports structurally; `TL-001` / `TL-009` still fire so the
semantic signal (quarantined / untrusted content used as grounds) is not lost under the
structural one.

A promotion is only *hazard-clearing* when the target itself is a non-hazard level
(`trusted:*` or `observed:*`). The taxonomy allows staged promotions such as
`untrusted:unknown -> quarantined:web` via `automated-triage` as an intermediate
step; those are structurally valid (so `TL-001` / `TL-009` are silent) but still
leave the entry at a quarantined / untrusted level. `TL-013` fires on such entries
when they are used as grounds, so a single-step mid-chain promotion cannot silently
waive the hazard rules.

`grounds_for_action` must be a JSON boolean. `TL-001` / `TL-009` match on `grounds is True`
(a strict boolean check), so a string like `"yes"` or an integer `1` would silently
bypass both HIGH rules while still being read as truthy by a downstream consumer
written as `if entry.get("grounds_for_action"):`. `TL-014` closes this gap: any
non-boolean value for `grounds_for_action` fires HIGH. `TL-008` (field absent) and
`TL-014` (field present but wrong-type) partition the ways the field can be
non-declarative and never fire together.

Rule bodies live in `trustlabels/rules.py`; the registry is `trustlabels.ALL_RULES`.

## Honest scope

What this does:

- Validates bundle shape (list of entries or object with `entries`, each entry has `id`
  and `trust_label`).
- Flags fourteen named cross-field inconsistencies by rule id.
- Prints an ASCII-safe text report (non-ASCII rendered as `<U+XXXX>`) or a JSON report.

What this does not do:

- Does not detect prompt injection in content. The linter checks that the label and
  promotion history are honest, not that the content is benign.
- Does not sign entries. A caller who lies about the label passes `TL-001`. The
  taxonomy is a discipline, not a cryptographic attestation; chain this to a signer
  or an attested-provenance layer if signatures matter.
- Does not translate findings into enforcement actions. That belongs to a policy
  engine; this project is the shape and the discipline it enforces, not the gate.
- Does not certify safety, honesty, or alignment of the system that produced the
  bundle. A clean run is **origin-valid, content-unverified**, never **verified-safe**.

False-positive modes:

- `TL-006` uses a pragmatic RFC3339 shape (regex, not calendar); exotic-but-valid
  timestamps may fire.
- `TL-012` fires on observed and quarantined entries with no `source_ref`; a caller
  who legitimately cannot name a source (e.g. an in-memory buffer) should either
  switch to an untrusted label or write a stable identifier (`buffer://...`).

## How it is made

This project is produced by **a human-machine hybrid intelligence** under a
maker-checker discipline. The taxonomy and transition matrix are derived from the
converged shape described in multiple public 2026 sources: *The Landscape of Prompt
Injection Threats in LLM Agents* (arXiv 2602.10453); *Composable Trust for Language
Models* (arXiv 2607.13149); *A Trust Layer for Agent Evaluation* (arXiv 2610.07274);
the DigitalApplied 2026 production-agents taxonomy; the CSA Labs 2026-07-01 research
note on MCP tool poisoning; and the small cluster of publicly documented
host-side trust-label taxonomies that converge on a four-level shape. No reference implementation from any named repository was read, vendored,
or mirrored. **Not affiliated with or endorsed by** the authors of any paper, any
named platform, or any standards body.

## License

Apache-2.0. See `LICENSE`.
