"""Rule registry and scan function for trustlabels.

A bundle is a JSON file - either a list of entries, or an object with
an ``entries`` list. Each entry declares one piece of content that
entered a reasoning context, its trust label, where it came from,
whether it is grounds for action, and (if promoted) what gate it
passed through.

Rules
-----
Fourteen rules under the prefix ``TL-``. Each one is documented in the
project README; the shared contract test asserts every registry id
appears there.
"""

from __future__ import annotations

import re
from typing import Any, Dict, List

from .taxonomy import (
    is_known,
    is_quarantined,
    is_untrusted,
    requires_gate,
    valid_gates,
    valid_targets,
)
from .types import Finding, Rule, ScanResult, Severity, rollup


ALL_RULES: List[Rule] = [
    Rule(
        id="TL-001",
        severity=Severity.HIGH,
        title="quarantined entry used as grounds for action",
        description=(
            "An entry whose trust_label starts with 'quarantined:' "
            "must not be used as grounds_for_action unless its "
            "promotion is complete and valid: promoted_to, "
            "promoted_by, and promotion_gate all present, with the "
            "transition in the taxonomy matrix and the gate accepted "
            "for that transition. A bare promoted_to string does not "
            "constitute a promotion. A quarantined entry grounding "
            "an action is the injection path the taxonomy exists "
            "to close."
        ),
    ),
    Rule(
        id="TL-002",
        severity=Severity.HIGH,
        title="promotion recorded without a gate",
        description=(
            "An entry that declares promoted_to must also name "
            "promoted_by (the role) and promotion_gate (the gate "
            "name). An unnamed gate is a self-awarded promotion."
        ),
    ),
    Rule(
        id="TL-003",
        severity=Severity.HIGH,
        title="promotion target unreachable from current label",
        description=(
            "The declared promotion (trust_label -> promoted_to) is "
            "not present in the taxonomy's transition matrix. The "
            "promotion claims a transition the taxonomy does not "
            "allow."
        ),
    ),
    Rule(
        id="TL-004",
        severity=Severity.MEDIUM,
        title="promotion target is not a known label",
        description=(
            "The declared promoted_to is outside the known taxonomy "
            "and so no gate exists for it. Either use a known label "
            "or extend the taxonomy."
        ),
    ),
    Rule(
        id="TL-005",
        severity=Severity.MEDIUM,
        title="trust_label is not a known label",
        description=(
            "The entry's trust_label is outside the known taxonomy. "
            "Downstream rules cannot reason about an unknown label; "
            "the entry defaults to untrusted-level handling and this "
            "rule records the discrepancy."
        ),
    ),
    Rule(
        id="TL-006",
        severity=Severity.MEDIUM,
        title="entered_at is not RFC3339-shaped",
        description=(
            "entered_at should be RFC3339-shaped so an auditor can "
            "order entries without re-parsing. The validator checks "
            "shape (regex), not calendar validity."
        ),
    ),
    Rule(
        id="TL-007",
        severity=Severity.HIGH,
        title="trusted:system entry has an external source_ref",
        description=(
            "An entry labelled trusted:system should ship with the "
            "host and must not derive from an http:// or https:// "
            "source. A trusted:system entry sourced from the "
            "outside is a mislabelled quarantined entry."
        ),
    ),
    Rule(
        id="TL-008",
        severity=Severity.LOW,
        title="grounds_for_action is not explicitly set",
        description=(
            "grounds_for_action should be an explicit boolean. An "
            "entry that omits the field is defensible but ambiguous; "
            "declare the intent so a reviewer can see it."
        ),
    ),
    Rule(
        id="TL-009",
        severity=Severity.HIGH,
        title="untrusted entry used as grounds for action",
        description=(
            "An entry whose trust_label starts with 'untrusted:' "
            "must not be used as grounds_for_action unless its "
            "promotion is complete and valid: promoted_to, "
            "promoted_by, and promotion_gate all present, with the "
            "transition in the taxonomy matrix and the gate accepted "
            "for that transition. A bare promoted_to string does not "
            "constitute a promotion. If the content is needed, "
            "promote it (via a sanitizer or a reviewer) before using "
            "it to decide."
        ),
    ),
    Rule(
        id="TL-010",
        severity=Severity.HIGH,
        title="promotion_gate is not valid for this transition",
        description=(
            "The declared promotion_gate is not a gate the taxonomy "
            "accepts for this transition. The transition's accepted "
            "gates are listed in trustlabels/taxonomy.py."
        ),
    ),
    Rule(
        id="TL-011",
        severity=Severity.LOW,
        title="duplicate entry id in bundle",
        description=(
            "Two or more entries carry the same id. A bundle should "
            "treat id as a key so an auditor can cross-reference "
            "entries by it."
        ),
    ),
    Rule(
        id="TL-012",
        severity=Severity.MEDIUM,
        title="observed or quarantined entry has no source_ref",
        description=(
            "An entry labelled observed:* or quarantined:* should "
            "carry a source_ref that names where it came from. "
            "Provenance without a source is unfalsifiable."
        ),
    ),
    Rule(
        id="TL-013",
        severity=Severity.HIGH,
        title="promotion target is still a hazard level",
        description=(
            "A quarantined or untrusted entry used as "
            "grounds_for_action declares a complete and valid "
            "promotion whose target is itself a quarantined:* or "
            "untrusted:* level. The taxonomy allows staged "
            "promotions (e.g. untrusted:unknown -> quarantined:web "
            "via automated-triage) as an intermediate step, not as "
            "a hazard-clearing one; the entry must be promoted "
            "further to a non-hazard level (trusted:* or "
            "observed:*) before use as grounds. Without this rule, "
            "a single-step mid-chain promotion silently escapes "
            "TL-001 / TL-009."
        ),
    ),
    Rule(
        id="TL-014",
        severity=Severity.HIGH,
        title="grounds_for_action is set but not a boolean",
        description=(
            "grounds_for_action must be a JSON boolean (true or "
            "false). An entry that sets it to a string, number, "
            "list, object, or null bypasses TL-001 / TL-009 "
            "(whose guard is 'grounds is True', a strict boolean "
            "match) while still looking declared to TL-008 (which "
            "only fires on absence). A downstream reader doing "
            "`if entry.get('grounds_for_action'):` reads a truthy "
            "non-boolean as grounds, so a quarantined entry with "
            "grounds_for_action='yes' is a type-confusion path to "
            "the exact outcome TL-001 is meant to refuse."
        ),
    ),
]


REGISTRY = ALL_RULES

_RULE_BY_ID = {r.id: r for r in ALL_RULES}


_TIMESTAMP_RE = re.compile(
    r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}"
    r"(?:\.\d+)?"
    r"(?:Z|[+-]\d{2}:\d{2})$"
)


def _q(value: Any) -> str:
    """Quote a value for a rule message without Python repr-escaping.

    repr() renders non-ASCII characters as Python escapes (\\u200b),
    which hides the character the ascii-safe reporter is meant to
    expose. This helper keeps the raw character in place so the
    reporter's ascii_safe() path can render it as <U+XXXX>.
    """
    if value is None:
        return "None"
    if isinstance(value, bool):
        return "True" if value else "False"
    if isinstance(value, (int, float)):
        return str(value)
    return "'" + str(value) + "'"


def _hit(rule_id: str, message: str, where: str) -> Finding:
    rule = _RULE_BY_ID[rule_id]
    return Finding(
        rule_id=rule.id,
        severity=rule.severity,
        message=message,
        where=where,
    )


def _promotion_is_complete(label: Any, entry: Dict[str, Any]) -> bool:
    """True iff the entry's promotion claim is complete and valid.

    A quarantined/untrusted entry escapes TL-001/TL-009 only when its
    promotion claim actually passed a real gate: all three fields
    present (``promoted_to``, ``promoted_by``, ``promotion_gate``), the
    current->target transition in the taxonomy matrix, and the gate
    accepted for that transition. A bare ``promoted_to`` string with
    no ``promoted_by`` or ``promotion_gate`` is a self-awarded
    promotion that TL-002 reports structurally; TL-001 and TL-009 must
    still fire so the semantic signal (quarantined/untrusted content
    used as grounds) is not lost under the structural one.
    """
    if not isinstance(label, str):
        return False
    promoted_to = entry.get("promoted_to")
    promoted_by = entry.get("promoted_by")
    promotion_gate = entry.get("promotion_gate")
    if not promoted_to or not promoted_by or not promotion_gate:
        return False
    if not isinstance(promoted_to, str) or not isinstance(promotion_gate, str):
        return False
    if not is_known(label) or not is_known(promoted_to):
        return False
    if promoted_to not in valid_targets(label):
        return False
    if promotion_gate not in valid_gates(label, promoted_to):
        return False
    return True


def _entries_of(bundle: Any) -> List[Dict[str, Any]]:
    if isinstance(bundle, list):
        return [e for e in bundle if isinstance(e, dict)]
    if isinstance(bundle, dict):
        es = bundle.get("entries") or []
        if isinstance(es, list):
            return [e for e in es if isinstance(e, dict)]
    return []


def scan(bundle: Any) -> ScanResult:
    """Run every rule on ``bundle`` and return a ScanResult.

    ``bundle`` may be a list of entries or an object with an
    ``entries`` field. Non-dict entries are skipped silently; the
    structural validator reports those separately so a document that
    fails the schema gets rc 2 rather than a traceback.
    """
    findings: List[Finding] = []
    entries = _entries_of(bundle)

    seen_ids: Dict[str, int] = {}

    for i, e in enumerate(entries):
        where = f"entries/{i}"
        eid = e.get("id")
        label = e.get("trust_label")
        source = e.get("source_ref")
        grounds = e.get("grounds_for_action")
        promoted_to = e.get("promoted_to")
        promoted_by = e.get("promoted_by")
        promotion_gate = e.get("promotion_gate")
        entered_at = e.get("entered_at")

        # TL-001 / TL-009: quarantined / untrusted entries as grounds.
        # The guard is "promotion is complete and valid", not just
        # "promoted_to is set" - otherwise an attacker escapes a HIGH
        # rule by writing a bare promoted_to string with no gate.
        if isinstance(label, str) and is_quarantined(label):
            if grounds is True and not _promotion_is_complete(label, e):
                findings.append(_hit(
                    "TL-001",
                    f"quarantined entry {_q(eid)} is grounds_for_action "
                    f"with no complete and valid promotion recorded",
                    where,
                ))
        if isinstance(label, str) and is_untrusted(label):
            if grounds is True and not _promotion_is_complete(label, e):
                findings.append(_hit(
                    "TL-009",
                    f"untrusted entry {_q(eid)} is grounds_for_action "
                    f"with no complete and valid promotion recorded; "
                    f"promote via a gate before using as grounds",
                    where,
                ))

        # TL-013: hazard-level entry used as grounds via a
        # complete-and-valid promotion whose target is itself a
        # hazard level. The taxonomy allows untrusted:unknown ->
        # quarantined:web via automated-triage as a staged step; a
        # single-step claim stops short of a non-hazard level and
        # must not waive TL-001 / TL-009 when the target is still
        # quarantined:* or untrusted:*.
        if (
            isinstance(label, str)
            and (is_quarantined(label) or is_untrusted(label))
            and grounds is True
            and _promotion_is_complete(label, e)
            and isinstance(promoted_to, str)
            and (is_quarantined(promoted_to) or is_untrusted(promoted_to))
        ):
            findings.append(_hit(
                "TL-013",
                f"entry {_q(eid)} is grounds_for_action with promotion "
                f"{_q(label)} -> {_q(promoted_to)}; target is still a "
                f"hazard level, promote to trusted:* or observed:* "
                f"before use as grounds",
                where,
            ))

        # TL-002: promotion recorded without a gate.
        if promoted_to:
            if not promoted_by or not promotion_gate:
                missing = []
                if not promoted_by:
                    missing.append("promoted_by")
                if not promotion_gate:
                    missing.append("promotion_gate")
                findings.append(_hit(
                    "TL-002",
                    f"entry {_q(eid)} declares promoted_to={_q(promoted_to)} "
                    f"but is missing: {', '.join(missing)}",
                    where,
                ))

        # TL-003 / TL-004: promotion-matrix checks.
        if promoted_to:
            if not is_known(promoted_to):
                findings.append(_hit(
                    "TL-004",
                    f"entry {_q(eid)} promoted_to={_q(promoted_to)} is not "
                    f"a known label in the taxonomy",
                    where,
                ))
            elif isinstance(label, str) and is_known(label):
                if promoted_to not in valid_targets(label):
                    findings.append(_hit(
                        "TL-003",
                        f"entry {_q(eid)} declares promotion "
                        f"{_q(label)} -> {_q(promoted_to)} which is not "
                        f"in the transition matrix",
                        where,
                    ))

        # TL-005: unknown trust_label.
        if label is not None and (not isinstance(label, str) or not is_known(label)):
            findings.append(_hit(
                "TL-005",
                f"entry {_q(eid)} trust_label={_q(label)} is not in the "
                f"known taxonomy",
                where,
            ))

        # TL-006: entered_at shape.
        if isinstance(entered_at, str) and not _TIMESTAMP_RE.match(entered_at):
            findings.append(_hit(
                "TL-006",
                f"entry {_q(eid)} entered_at={_q(entered_at)} is not "
                f"RFC3339-shaped",
                where,
            ))

        # TL-007: trusted:system from external URL.
        if label == "trusted:system" and isinstance(source, str):
            if source.lower().startswith("http://") or source.lower().startswith("https://"):
                findings.append(_hit(
                    "TL-007",
                    f"entry {_q(eid)} is trusted:system but source_ref "
                    f"is an external URL ({_q(source)})",
                    where,
                ))

        # TL-008: grounds_for_action not explicitly set.
        if "grounds_for_action" not in e:
            findings.append(_hit(
                "TL-008",
                f"entry {_q(eid)} does not declare grounds_for_action",
                where,
            ))

        # TL-014: grounds_for_action present but not a boolean. Fires
        # on any non-bool value (string, int, list, dict, null). The
        # strict-bool guard in TL-001 / TL-009 means a truthy string
        # bypasses the HIGH semantic rules while a downstream reader
        # using Python-style truthiness would still read it as grounds,
        # so a type violation here is itself a HIGH-severity attack
        # path and must not be masked by TL-008 (which fires only on
        # absence).
        elif not isinstance(grounds, bool):
            findings.append(_hit(
                "TL-014",
                f"entry {_q(eid)} grounds_for_action={_q(grounds)} is "
                f"not a boolean (type: {type(grounds).__name__})",
                where,
            ))

        # TL-010: promotion_gate not valid for this transition.
        if (
            promoted_to
            and promotion_gate
            and isinstance(label, str)
            and is_known(label)
            and is_known(promoted_to)
            and promoted_to in valid_targets(label)
        ):
            if promotion_gate not in valid_gates(label, promoted_to):
                accepted = sorted(valid_gates(label, promoted_to))
                findings.append(_hit(
                    "TL-010",
                    f"entry {_q(eid)} promotion_gate={_q(promotion_gate)} "
                    f"is not accepted for {_q(label)} -> {_q(promoted_to)} "
                    f"(accepted: {accepted})",
                    where,
                ))

        # TL-012: observed/quarantined without source_ref.
        if isinstance(label, str) and (
            label.startswith("observed:") or label.startswith("quarantined:")
        ):
            if not source:
                findings.append(_hit(
                    "TL-012",
                    f"entry {_q(eid)} is {_q(label)} but has no source_ref",
                    where,
                ))

        # TL-011: duplicate id, deferred to a second pass.
        if isinstance(eid, str) and eid:
            seen_ids[eid] = seen_ids.get(eid, 0) + 1

    # TL-011 (post-pass): named duplicates.
    for eid, count in seen_ids.items():
        if count > 1:
            findings.append(_hit(
                "TL-011",
                f"entry id {_q(eid)} appears {count} times in bundle",
                "entries",
            ))

    # Also require that a promotion_gate is present when gate is
    # required and absent: TL-002 already covers it; nothing to add.

    # TL-002 doubling: if promotion_gate is required for this transition
    # and the entry does name promoted_by/promotion_gate but the
    # transition is unknown, the TL-003/004 branches already fired.

    _ = requires_gate  # silence unused if future refactor removes a call

    return ScanResult(findings=findings, verdict=rollup(findings))
