"""Rebuild the shipped example ledgers.

Run from the project root:

    python examples/build_examples.py

Writes:
- examples/healthy_ledger.jsonl   three entries, clean chain
- examples/tampered_ledger.jsonl  the same three entries with the
                                  payload of entry seq=1 mutated

The script is deterministic (fixed timestamps and payloads) so the
conformance tests can assert on exact HEAD hashes.
"""

from __future__ import annotations

import json
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
sys.path.insert(0, ROOT)

from auditledger import append, init  # noqa: E402


HEALTHY = os.path.join(HERE, "healthy_ledger.jsonl")
TAMPERED = os.path.join(HERE, "tampered_ledger.jsonl")


def _rebuild_healthy():
    if os.path.exists(HEALTHY):
        os.remove(HEALTHY)
    init(HEALTHY)
    append(HEALTHY, "boot", {"host": "worker-a", "env": "staging"},
           ts="2026-10-18T09:30:00Z")
    append(HEALTHY, "tool-call",
           {"tool": "read_record", "args_hash": "sha256:abcd1234"},
           ts="2026-10-18T09:30:01Z")
    append(HEALTHY, "decision",
           {"action": "approve", "reason": "input matched policy"},
           ts="2026-10-18T09:30:02Z")


def _rebuild_tampered():
    _rebuild_healthy()
    # Rewrite line 2's payload directly, breaking the hash chain.
    with open(HEALTHY, "r", encoding="utf-8") as f:
        lines = f.readlines()
    row = json.loads(lines[1])
    row["payload"]["tool"] = "delete_record"  # hostile edit
    lines[1] = json.dumps(row, sort_keys=True,
                          separators=(",", ":")) + "\n"
    with open(TAMPERED, "w", encoding="utf-8") as f:
        f.writelines(lines)


if __name__ == "__main__":
    _rebuild_healthy()
    _rebuild_tampered()
    print(f"wrote {HEALTHY}")
    print(f"wrote {TAMPERED}")
