"""Rule registry and scan function for rungtag.

A substantive block in a reasoning transcript should name the depth
of reasoning that produced it, and that name must be internally
consistent: a block that claims ``iterated`` must either name its
checker on the same block or point to a sibling checker block; a
block that claims ``rung-3`` must claim ``iterated`` so there is a
loop that could cause-check the counterfactual claim.

Rules
-----
Nine rules under the prefix ``RT-``. Each one is documented in the
project README; the shared contract test asserts every registry id
appears there.
"""

from __future__ import annotations

from typing import Dict, List

from .patterns import (
    ALL_KNOWN_TOKENS,
    Block,
    HeaderField,
    PRIMARY_TOKENS,
    ParsedTag,
    RUNG_REQUIRES,
    RUNG_TOKENS,
    parse_tag,
    split_blocks,
    unknown_rungs,
    word_count,
)
from .types import Finding, Rule, ScanResult, Severity, rollup


ALL_RULES: List[Rule] = [
    Rule(
        id="RT-001",
        severity=Severity.HIGH,
        title="substantive block has no tag header",
        description=(
            "A block whose content word count is at least the "
            "SUBSTANTIVE threshold (default 40) should declare a "
            "reasoning-depth tag. An untagged substantive block "
            "cannot be reasoned about by downstream honesty checks."
        ),
    ),
    Rule(
        id="RT-002",
        severity=Severity.HIGH,
        title="iterated tag claimed without a checker named",
        description=(
            "A tag that includes ``iterated`` or "
            "``reasoning-iterated`` claims a maker-checker loop "
            "actually ran. The block must therefore name a "
            "``checker:`` or ``checker_role:`` header, or an "
            "earlier/sibling block must be tagged as the checker."
        ),
    ),
    Rule(
        id="RT-003",
        severity=Severity.MEDIUM,
        title="malformed tag",
        description=(
            "The tag string does not match the grammar "
            "``( TOKEN (, TOKEN)* )`` with at least one token, "
            "or contains an empty token slot."
        ),
    ),
    Rule(
        id="RT-004",
        severity=Severity.HIGH,
        title="rung dimension without required base",
        description=(
            "``rung-2`` requires ``reasoning`` (or an iterated "
            "variant) in the same tuple. ``rung-3`` requires "
            "``iterated`` or ``reasoning-iterated``. A rung "
            "claim without the base it extends is self-awarded."
        ),
    ),
    Rule(
        id="RT-005",
        severity=Severity.MEDIUM,
        title="short block tagged reasoning or iterated",
        description=(
            "A block below the TRIVIAL word threshold (default 15) "
            "is unlikely to require extended deliberation. A block "
            "that short tagged ``reasoning`` or ``iterated`` is "
            "probably overclaiming."
        ),
    ),
    Rule(
        id="RT-006",
        severity=Severity.LOW,
        title="duplicate tag header in block",
        description=(
            "A block carries more than one ``tag:`` header. The "
            "intent is ambiguous; the convention is one tag per "
            "block."
        ),
    ),
    Rule(
        id="RT-007",
        severity=Severity.MEDIUM,
        title="unknown rung dimension",
        description=(
            "A token of the form ``rung-N`` is present where N is "
            "not in the taxonomy (1, 2, or 3). The Pearl ladder "
            "stops at rung-3."
        ),
    ),
    Rule(
        id="RT-008",
        severity=Severity.MEDIUM,
        title="unknown primary token",
        description=(
            "The tag contains a token that is neither a known "
            "primary (``normal`` / ``reasoning`` / ``iterated`` / "
            "``reasoning-iterated``) nor a rung dimension."
        ),
    ),
    Rule(
        id="RT-009",
        severity=Severity.MEDIUM,
        title="iterated tag without reasoning in the same tuple",
        description=(
            "``iterated`` without ``reasoning`` in the same tuple "
            "is ambiguous; ``reasoning-iterated`` is the single "
            "canonical token for an iterated reasoning pass."
        ),
    ),
]


REGISTRY = ALL_RULES

_RULE_BY_ID = {r.id: r for r in ALL_RULES}


# Thresholds (words) for substantive vs trivial blocks. A caller can
# override these when invoking ``scan``.
DEFAULT_SUBSTANTIVE = 40
DEFAULT_TRIVIAL = 15


def _q(value) -> str:
    if value is None:
        return "None"
    return "'" + str(value) + "'"


def _qlist(values) -> str:
    """Render a sequence of strings without Python repr-escaping."""
    return "[" + ", ".join(_q(v) for v in values) + "]"


def _hit(rule_id: str, message: str, where: str) -> Finding:
    rule = _RULE_BY_ID[rule_id]
    return Finding(
        rule_id=rule.id,
        severity=rule.severity,
        message=message,
        where=where,
    )


def _tag_headers(block: Block) -> List[HeaderField]:
    return [h for h in block.headers if h.key == "tag"]


def _checker_declared(block: Block) -> bool:
    return any(h.key in ("checker", "checker_role") for h in block.headers)


def scan(
    text: str,
    substantive: int = DEFAULT_SUBSTANTIVE,
    trivial: int = DEFAULT_TRIVIAL,
) -> ScanResult:
    """Run every rule on ``text`` and return a ScanResult.

    ``text`` is the full input stream (markdown or plain text). The
    parser splits on H2 lines and ``---BLOCK---`` markers.
    """
    blocks = split_blocks(text)
    findings: List[Finding] = []

    # Pass 1: record which block indices are tagged as the checker.
    checker_block_indices = set()
    for b in blocks:
        for h in b.headers:
            if h.key == "tag":
                pt = parse_tag(h.value)
                if pt.primary in ("iterated", "reasoning-iterated"):
                    # not itself a checker; skip
                    pass
                # A block tagged with checker_role has a checker named
                if b.title and "checker" in b.title.lower():
                    checker_block_indices.add(b.index)

    for b in blocks:
        where = f"block[{b.index}]"
        tag_headers = _tag_headers(b)
        content_words = word_count(b.content)

        # RT-006: duplicate tag header
        if len(tag_headers) > 1:
            findings.append(_hit(
                "RT-006",
                f"block has {len(tag_headers)} tag headers; "
                f"the convention is one tag per block",
                where,
            ))

        # If no tag header, RT-001 fires for substantive blocks.
        if not tag_headers:
            if content_words >= substantive:
                findings.append(_hit(
                    "RT-001",
                    f"substantive block (word count {content_words}) "
                    f"has no tag header",
                    where,
                ))
            # No tag to inspect further.
            continue

        # Inspect the FIRST tag header for subsequent rules; duplicate
        # already got RT-006.
        tag_h = tag_headers[0]
        pt = parse_tag(tag_h.value)

        # RT-003: malformed tag
        if pt.malformed:
            findings.append(_hit(
                "RT-003",
                f"malformed tag {_q(tag_h.value)}; expected "
                f"'(TOKEN(, TOKEN)*)' with non-empty tokens",
                where,
            ))
            continue

        # RT-008: unknown primary token (any token not in
        # ALL_KNOWN_TOKENS and not a rung-N shape).
        if pt.unknown:
            findings.append(_hit(
                "RT-008",
                f"tag contains unknown token(s) {_qlist(pt.unknown)}; "
                f"known primary tokens: {_qlist(sorted(PRIMARY_TOKENS))}",
                where,
            ))

        # RT-007: unknown rung dimension (rung-N with N not in 1..3).
        urungs = unknown_rungs(pt)
        if urungs:
            findings.append(_hit(
                "RT-007",
                f"unknown rung dimension(s) {_qlist(urungs)}; "
                f"accepted: {_qlist(sorted(RUNG_TOKENS))}",
                where,
            ))

        # RT-004: rung dimension without required base.
        for r in pt.rungs:
            required = RUNG_REQUIRES.get(r, frozenset())
            if required and not any(t in pt.tokens for t in required):
                findings.append(_hit(
                    "RT-004",
                    f"rung dimension {_q(r)} requires one of "
                    f"{_qlist(sorted(required))} in the same tuple; "
                    f"got tokens {_qlist(pt.tokens)}",
                    where,
                ))

        # RT-002: iterated without a checker named.
        is_iterated = (
            "iterated" in pt.tokens
            or "reasoning-iterated" in pt.tokens
        )
        if is_iterated and not _checker_declared(b):
            # Allow it if a sibling block is explicitly tagged a checker
            if b.index not in checker_block_indices and not checker_block_indices:
                findings.append(_hit(
                    "RT-002",
                    f"tag claims iterated/reasoning-iterated but no "
                    f"checker is named (checker: or checker_role: "
                    f"header) and no sibling checker block",
                    where,
                ))

        # RT-005: short block tagged reasoning/iterated.
        if content_words < trivial and (
            pt.primary in ("reasoning", "iterated", "reasoning-iterated")
            or is_iterated
        ):
            findings.append(_hit(
                "RT-005",
                f"short block (word count {content_words}, below "
                f"trivial threshold {trivial}) tagged "
                f"{_q(pt.primary)}; probable overclaim",
                where,
            ))

        # RT-009: iterated present but not reasoning-iterated and
        # without reasoning sibling in tuple.
        if (
            "iterated" in pt.tokens
            and "reasoning" not in pt.tokens
            and "reasoning-iterated" not in pt.tokens
        ):
            findings.append(_hit(
                "RT-009",
                f"tag has 'iterated' alone; prefer "
                f"'reasoning-iterated' or '(reasoning, iterated)'",
                where,
            ))

    return ScanResult(findings=findings, verdict=rollup(findings))
