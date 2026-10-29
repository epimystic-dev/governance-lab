"""The trust-label taxonomy and transition matrix.

Four levels, nine qualifiers, a transition matrix that names every
promotion a bundle can legitimately claim, and the gate each promotion
requires. The taxonomy is small enough to be documented in one page;
the shapes it encodes are documented in trustlabels/README.md and
locked by tests/test_rules.py.

Levels
------
- ``trusted``        provenance known, origin reviewed
- ``observed``       provenance known, origin not reviewed
- ``quarantined``    provenance known, origin suspected adversarial
- ``untrusted``      provenance unknown or asserted-adversarial

Qualifiers
----------
- ``trusted:system``        shipped as part of the host; cannot derive
                            from an external URL (see TL-007)
- ``trusted:audited``       reviewed by a named role and gate
- ``observed:tool``         emitted by a tool call; not reviewed
- ``observed:user``         emitted by a user; not reviewed
- ``quarantined:web``       fetched from a URL; adversarial by default
- ``quarantined:scraped``   scraped from a document; adversarial by
                            default
- ``quarantined:tool-output`` tool output with suspected injection
- ``untrusted:derived``     derived from an untrusted input
- ``untrusted:unknown``     provenance not recorded
"""

from __future__ import annotations

from typing import Dict, FrozenSet, Set, Tuple


KNOWN_LABELS: FrozenSet[str] = frozenset({
    "trusted:system",
    "trusted:audited",
    "observed:tool",
    "observed:user",
    "quarantined:web",
    "quarantined:scraped",
    "quarantined:tool-output",
    "untrusted:derived",
    "untrusted:unknown",
})


# A transition is a map (current_label -> set of valid target labels).
# Any pair outside this map is TL-003.
TRANSITIONS: Dict[str, FrozenSet[str]] = {
    "quarantined:web": frozenset({"trusted:audited"}),
    "quarantined:scraped": frozenset({"trusted:audited"}),
    "quarantined:tool-output": frozenset({"trusted:audited"}),
    "observed:tool": frozenset({"trusted:audited"}),
    "observed:user": frozenset({"trusted:audited"}),
    "untrusted:derived": frozenset({"observed:tool"}),
    "untrusted:unknown": frozenset({"quarantined:web"}),
}


# Gate names each transition accepts. A promotion whose promotion_gate
# is not in this set is TL-010.
GATES: Dict[Tuple[str, str], FrozenSet[str]] = {
    ("quarantined:web", "trusted:audited"): frozenset({"reviewer"}),
    ("quarantined:scraped", "trusted:audited"): frozenset({"reviewer"}),
    ("quarantined:tool-output", "trusted:audited"): frozenset({"reviewer"}),
    ("observed:tool", "trusted:audited"): frozenset({"reviewer"}),
    ("observed:user", "trusted:audited"): frozenset({"reviewer"}),
    ("untrusted:derived", "observed:tool"): frozenset({"automated-sanitizer"}),
    ("untrusted:unknown", "quarantined:web"): frozenset({"automated-triage"}),
}


def requires_gate(current: str, target: str) -> bool:
    """True if a declared promotion must name a gate (TL-002)."""
    return (current, target) in GATES


def is_quarantined(label: str) -> bool:
    return label.startswith("quarantined:")


def is_untrusted(label: str) -> bool:
    return label.startswith("untrusted:")


def is_observed(label: str) -> bool:
    return label.startswith("observed:")


def is_trusted(label: str) -> bool:
    return label.startswith("trusted:")


def is_known(label: str) -> bool:
    return label in KNOWN_LABELS


def valid_targets(current: str) -> FrozenSet[str]:
    """Set of labels ``current`` may promote to. Empty if none."""
    return TRANSITIONS.get(current, frozenset())


def valid_gates(current: str, target: str) -> FrozenSet[str]:
    return GATES.get((current, target), frozenset())
