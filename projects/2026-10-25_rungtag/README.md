# rungtag

**Reasoning-depth-tag linter** for text streams. One file; a parser that splits a
transcript into blocks; a tag grammar `(TOKEN(, TOKEN)*)`; nine rules under `RT-NNN`
that catch the real failure modes - a substantive block with no tag, an iterated
tag claimed with no checker named, a Pearl-ladder `rung-3` claim with no iterated
loop that could cause-check it, overclaims on blocks too short to require the depth
they declare.

## The problem it solves

Chain-of-thought faithfulness is a 2026 research cluster. The FaithCoT-Bench
benchmark (ICLR 2026) measures instance-level faithfulness across model families;
arXiv 2603.26410 (*Why Models Know But Don't Say*) and arXiv 2605.24286 (*Faithfulness
as Information Flow*) document the gap between a reasoning model's visible chain of
thought and the computation that produced its answer. One pragmatic mitigation is a
reasoning-depth tag discipline: ask a worker to name the depth of reasoning it just
did, and run a linter that refuses the inconsistencies which would otherwise go
unnoticed.

Sibling tool `envelope` enforces this discipline at the structured-JSON return-surface
layer (`envelope`'s `ENV-002`). `rungtag` enforces it at the free-text layer: scan a
markdown or plain-text transcript, flag the untagged substantive blocks, the
self-awarded iterated claims, the malformed tag strings, the ill-grounded rung-N
claims, and the overclaims on blocks too short to require their depth.

## Install and run

Python 3.9 or later. No third-party dependencies.

```
python -m pip install -e .
python -m rungtag path/to/transcript.md
```

Flags:

- `--json` emit a JSON report on stdout
- `--strict` any finding returns a non-zero rc (default already does this)
- `--include-info` include INFO-severity findings
- `--disable RULE` suppress a rule id (repeatable)
- `--substantive N` override the substantive-block word-count threshold
- `--trivial N` override the trivial-block (overclaim) word-count threshold
- `--print-rules` print the rule registry and exit
- `--help` / `--version`

Return codes:

- `0` clean
- `1` LOW or MEDIUM findings
- `2` any HIGH finding or unreadable input

## Library use

```python
import rungtag

text = rungtag.load("transcript.md")
result = rungtag.scan(text)
print(result.verdict)             # Verdict.HEALTHY / NEEDS_ATTENTION / UNHEALTHY

# Parse a single tag:
pt = rungtag.parse_tag("(reasoning, rung-2)")
print(pt.primary, pt.rungs)        # 'reasoning' ('rung-2',)

# Inspect blocks directly:
for block in rungtag.split_blocks(text):
    print(block.index, block.title, len(block.content.split()))
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
| `PRIMARY_TOKENS` | frozenset of accepted primary tag tokens |
| `RUNG_TOKENS` | frozenset of accepted rung-N tokens |
| `scan(text, substantive, trivial)` | rules check |
| `parse_tag(raw)` | parse a tag string |
| `split_blocks(text)` | parse blocks from a transcript |
| `load(path_or_text)` | read a path or return a string unchanged |

## Block and tag grammar

Blocks are delimited by markdown H2 lines (`## title`) or the explicit `---BLOCK---`
separator. Within the first consecutive non-blank lines of a block (its header area),
any line matching `^(tag|checker|checker_role):\s*(.+)$` is a header field. Content
begins at the first blank line or at the first non-header line.

Tag strings have the form:

```
tag: (TOKEN(, TOKEN)*)
```

Primary tokens:

- `normal` single-pass, routine
- `reasoning` extended deliberation
- `iterated` a maker-checker loop was executed (prefer `reasoning-iterated`)
- `reasoning-iterated` canonical compound

Rung dimensions (optional, Pearl ladder):

- `rung-1` associative / pattern recognition
- `rung-2` interventional - requires `reasoning` (or an iterated variant) in the tuple
- `rung-3` counterfactual - requires `iterated` or `reasoning-iterated` in the tuple

## The rules

| id | severity | title |
|---|---|---|
| `RT-001` | HIGH | substantive block has no tag header |
| `RT-002` | HIGH | iterated tag claimed without a checker named |
| `RT-003` | MEDIUM | malformed tag |
| `RT-004` | HIGH | rung dimension without the required base in the same tuple |
| `RT-005` | MEDIUM | short block tagged `reasoning` or `iterated` (overclaim) |
| `RT-006` | LOW | duplicate tag header in block |
| `RT-007` | MEDIUM | unknown rung dimension (e.g. `rung-4`) |
| `RT-008` | MEDIUM | unknown primary token |
| `RT-009` | MEDIUM | `iterated` present without `reasoning` in the same tuple |

Rule bodies live in `rungtag/rules.py`; the registry is `rungtag.ALL_RULES`.

## Honest scope

What this does:

- Splits a text stream into blocks and reads one `tag:` header per block.
- Flags nine named inconsistencies by rule id.
- Prints an ASCII-safe text report (non-ASCII rendered as `<U+XXXX>`) or a JSON report.

What this does not do:

- Does not verify that a tag is truthful. A worker that lies about doing a
  reasoning pass passes `RT-001`. The linter checks that the tag is internally
  consistent, not that the computation behind it was faithful. A clean run is
  **origin-valid, content-unverified**, never **verified-safe**.
- Does not score chain-of-thought faithfulness. That is a benchmark problem
  (FaithCoT-Bench and sibling work); this linter sits upstream of it and
  catches the easy inconsistencies before anyone has to run a benchmark.
- Does not render markdown or process its full syntax; it reads lines and
  matches a small set of regular expressions.
- Does not translate findings into enforcement actions. That belongs to a policy
  engine; this project is the shape and the discipline it enforces, not the gate.

False-positive modes:

- `RT-001` fires on any untagged block above the substantive threshold. A caller
  with a different convention (e.g. tag-at-footer) should either reshape the
  transcript or `--disable RT-001`.
- `RT-005` uses a word-count heuristic; a dense technical block below the trivial
  threshold tagged `reasoning` is a false positive. Tune `--trivial`.

## How it is made

This project is produced by **a human-machine hybrid intelligence** under a
maker-checker discipline. The tag taxonomy (normal / reasoning / iterated /
reasoning-iterated) and the rung ladder (rung-1 associative, rung-2 interventional,
rung-3 counterfactual) are drawn from the small vocabulary that appears in
several publicly documented reasoning-depth-tag conventions and the parallel
reasoning-depth vocabulary in the FaithCoT-Bench public materials (ICLR 2026). The rung ladder itself is cited to
Pearl, *The Book of Why*, chapter 1. The faithfulness motivation (a reasoning
depth that does not match the computation) is converged in multiple 2026 sources:
*Why Models Know But Don't Say* (arXiv 2603.26410), *Faithfulness as Information
Flow* (arXiv 2605.24286), *Measuring and curing reasoning rigidity* (arXiv
2603.22816), and the FaithCoT-Bench paper and benchmark. No reference
implementation from any named repository was read, vendored, or mirrored.
**Not affiliated with or endorsed by** the authors of any paper, the authors of
the FaithCoT-Bench benchmark, or any standards body.

## License

Apache-2.0. See `LICENSE`.
