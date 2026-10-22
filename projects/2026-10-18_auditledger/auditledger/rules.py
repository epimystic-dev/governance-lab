"""Verify-pass rules.

Each verify defect is a Rule with an id of the form AL-XXX. The
registry ALL_RULES is a list of Rule objects (not id strings), so a
caller can inspect ``rule.id`` directly.
"""

from __future__ import annotations

from typing import List

from .types import Rule, Severity


ALL_RULES: List[Rule] = [
    Rule(
        id="AL-001",
        severity=Severity.HIGH,
        title="line is not valid JSON",
        description=(
            "A ledger row must be a single-line JSON object. "
            "A line that fails json.loads cannot be hashed and "
            "cannot be verified."
        ),
    ),
    Rule(
        id="AL-002",
        severity=Severity.HIGH,
        title="row is not a JSON object",
        description=(
            "Each ledger line must deserialise to a JSON object with "
            "the fixed field set. Arrays, numbers, strings and nulls "
            "are rejected at verify time."
        ),
    ),
    Rule(
        id="AL-003",
        severity=Severity.HIGH,
        title="row is missing a required field",
        description=(
            "Every row must carry seq / ts / kind / payload / prev / "
            "hash. A missing field is a corruption or a hand-edit."
        ),
    ),
    Rule(
        id="AL-004",
        severity=Severity.HIGH,
        title="seq is out of order",
        description=(
            "seq is zero-based and strictly monotonically increasing "
            "by one per row. Any gap or reorder localises a tamper "
            "or a lost write."
        ),
    ),
    Rule(
        id="AL-005",
        severity=Severity.HIGH,
        title="prev does not match the previous row's hash",
        description=(
            "The prev field commits to the previous row's hash. "
            "A mismatch localises any tamper, reorder, deletion, or "
            "insertion to the exact pair of rows involved."
        ),
    ),
    Rule(
        id="AL-006",
        severity=Severity.HIGH,
        title="hash does not match the row's content",
        description=(
            "hash is sha256 over the canonical encoding of "
            "{seq, ts, kind, payload, prev}. A mismatch localises a "
            "payload or metadata edit to exactly this row."
        ),
    ),
    Rule(
        id="AL-007",
        severity=Severity.MEDIUM,
        title="ts is not RFC3339-shaped",
        description=(
            "ts must be an RFC3339-shaped UTC timestamp "
            "(YYYY-MM-DDTHH:MM:SS[.fff]Z or with +HH:MM offset). "
            "A loosely formatted timestamp still verifies "
            "cryptographically but is a human-readability defect."
        ),
    ),
    Rule(
        id="AL-008",
        severity=Severity.MEDIUM,
        title="hash field is not a 64-char lowercase hex string",
        description=(
            "hash and prev are SHA-256 hex digests. A length or "
            "case anomaly flags a hand-edit even before AL-006 fires."
        ),
    ),
    Rule(
        id="AL-009",
        severity=Severity.MEDIUM,
        title="kind is empty or not a string",
        description=(
            "kind is the user-defined tag that lets a verifier "
            "slice the ledger. A missing kind is not a tamper but "
            "it is a defect the author would want to see."
        ),
    ),
]


REGISTRY = ALL_RULES  # alias; sibling labs name their rule table REGISTRY
