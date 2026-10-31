# governance-lab

Runnable governance primitives for AI systems: the gates, ledgers, envelopes and honesty checks an ethical architecture is assembled from.

> Part of [Epimystic](https://epimystic.com) - a codex of the knowable and the unknowable.
> One of a family of labs: [`epimystic-lab`](https://github.com/epimystic-dev/epimystic-lab) / [`governance-lab`](https://github.com/epimystic-dev/governance-lab) / [`defense-lab`](https://github.com/epimystic-dev/defense-lab) / [`repro-lab`](https://github.com/epimystic-dev/repro-lab) / [`agent-guard-lab`](https://github.com/epimystic-dev/agent-guard-lab) / [`ai-ethics-lab`](https://github.com/epimystic-dev/ai-ethics-lab) / [`convergent-disciplines-lab`](https://github.com/epimystic-dev/convergent-disciplines-lab).

## What this is

A governed human-machine process scans the frontier each week and, *when something is
genuinely worth building*, produces one small, self-contained, tested artifact here. When
nothing clears the bar, it ships nothing but the radar entry - restraint is the quality gate.

- **`projects/`** - dated, self-contained micro-projects, each independently licensed,
  tested and documented.
- **`research-radar/`** - a dated digest of frontier signal: a few items each week with a
  one-line "why this matters", cited to source, and a note on what was built and why.

## What belongs here

Runnable governance primitives, each one a small part an ethical AI architecture is
assembled from: output envelopes with provenance and honesty fields, maker-checker loops,
tamper-evident ledgers, trust-label taxonomies with promotion gates, risk-class policy
engines, reasoning-depth and sycophancy checks, decision records. Libraries, specs, CLIs and
evaluation harnesses - governance that can be run and tested, not only described. Core
schemas use neutral role names (maker, checker, auditor, reviewer). Nothing here certifies
safety, honesty or alignment, and every README says so.

## The tools currently published

Each folder has its own README, tests and LICENSE; click through for install and usage.

| Tool | What it does | Layer |
|---|---|---|
| [`envelope`](projects/2026-10-18_envelope/) | Worker output envelope: JSON Schema 2020-12 subset for a worker's return value, with a stdlib-only reference validator and a twelve-rule cross-field discipline engine that catches self-awarded verification, unsupported HIGH findings, and status / finding inconsistency. | contract |
| [`auditledger`](projects/2026-10-18_auditledger/) | Append-only hash-chained JSONL ledger with `append / verify / digest / head`: one file, every row commits to the previous via SHA-256 over a canonical serialisation, verify localises any tamper to the exact sequence number. | audit-trail |
| [`trustlabels`](projects/2026-10-25_trustlabels/) | Trust-label taxonomy and transition-matrix linter for the provenance of content entering a reasoning context: a nine-label taxonomy, a seven-edge promotion matrix, and twelve rules that refuse quarantined or untrusted entries used as grounds for action, self-awarded promotions, and declared promotions the taxonomy does not permit. | ingress |
| [`rungtag`](projects/2026-10-25_rungtag/) | Reasoning-depth-tag linter for text streams: splits transcripts into blocks, parses `(TOKEN(, TOKEN)*)` tags, and flags substantive untagged blocks, iterated tags with no checker named, Pearl-ladder rung dimensions claimed without the base they extend, and overclaims on short blocks. | honesty |

*The radar publishes every Monday.*

## How it is made (and what that means)

Every artifact here is produced by **a human-machine hybrid intelligence, rooted in ethics
and philosophy**, and passes - *before* it is published - an external, deterministic policy
gate and an independent maker-checker review: a de-brand / secret gate, a clean-room rule (a
paper's method is read, never the authors' code), tests green under the public CI command,
and a claims-substantiation pass. The gate runs *outside* the builder. A passing gate means
**origin-valid, content-unverified**, never **verified-safe**. The engineering contract every
project meets is in [`docs/CONVENTIONS.md`](docs/CONVENTIONS.md).

## Honest scope

This is a research-and-utility lab, not a product. Artifacts are small by design;
reimplementations of published work are independent implementations, cited and **not
affiliated with or endorsed by the original authors**. Read each project's own README and
LICENSE.

## License

Each `projects/` artifact carries its own LICENSE (permissive; this lab's default is
Apache-2.0). The radar and this index are MIT.

---

*Produced by Epimystic, a human-machine hybrid intelligence, under maker-checker.*
