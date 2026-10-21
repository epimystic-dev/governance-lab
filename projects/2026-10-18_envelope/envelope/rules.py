"""Cross-field discipline rules.

The structural validator checks shape. The rules below check the
semantic consistency the schema cannot express: a worker that marks
status=ok with no checker run, a HIGH finding with no evidence, an
iterated reasoning tag without a checker role recorded.

Each rule has an id of the form ENV-XXX, a severity, a one-line title
and a documented description. The registry ALL_RULES is a list of
Rule objects so a caller can inspect ``rule.id`` directly.
"""

from __future__ import annotations

import re
from typing import Any, Dict, List

from .types import Finding, Rule, ScanResult, Severity, rollup


# ---------------------------------------------------------------------------
# Rule table. Every id must appear in the README rule table; the shared
# contract test asserts this.
# ---------------------------------------------------------------------------

ALL_RULES: List[Rule] = [
    Rule(
        id="ENV-001",
        severity=Severity.HIGH,
        title="status=ok requires checker_run=true",
        description=(
            "A worker that reports status=ok must have had its output "
            "verified by a role separate from the maker. "
            "status=ok with self_audit.checker_run=false collapses "
            "the maker-checker separation."
        ),
    ),
    Rule(
        id="ENV-002",
        severity=Severity.HIGH,
        title="iterated reasoning tag requires checker_run=true",
        description=(
            "reasoning_tag=iterated or reasoning-iterated is a claim "
            "that a maker-checker loop was executed. "
            "Claiming iterated without checker_run=true is a "
            "self-awarded verification tag."
        ),
    ),
    Rule(
        id="ENV-003",
        severity=Severity.HIGH,
        title="HIGH finding requires at least one evidence item",
        description=(
            "Every HIGH-severity finding should be grounded in at "
            "least one evidence item on the envelope. "
            "An envelope that carries HIGH findings and an empty "
            "evidence array is a bare assertion."
        ),
    ),
    Rule(
        id="ENV-004",
        severity=Severity.MEDIUM,
        title="self_audit.verdict=ok with reasons[] is inconsistent",
        description=(
            "If the checker says ok it should not carry reasons that "
            "a reviewer must infer are nonblocking. Either leave "
            "reasons empty or mark the verdict unknown and explain."
        ),
    ),
    Rule(
        id="ENV-005",
        severity=Severity.HIGH,
        title="status=failed requires at least one finding "
              "of severity MEDIUM or HIGH",
        description=(
            "A failed envelope with no findings is undetectable from "
            "an ok envelope by downstream automation. "
            "Record what failed."
        ),
    ),
    Rule(
        id="ENV-006",
        severity=Severity.MEDIUM,
        title="scope.in and scope.out must be non-empty",
        description=(
            "An envelope with empty scope.in has nothing to say about "
            "its inputs; with empty scope.out, nothing to say about "
            "its outputs. In both cases, the envelope is unactionable."
        ),
    ),
    Rule(
        id="ENV-007",
        severity=Severity.HIGH,
        title="self-attestation fields are forbidden",
        description=(
            "An envelope must not carry a field that self-attests "
            "verification (e.g. verified_by_author=true, "
            "safe_to_merge=true). The schema's additionalProperties: "
            "false catches most of these at structural layer; this "
            "rule catches the ones a lax caller allowed in via a "
            "relaxed schema fork."
        ),
    ),
    Rule(
        id="ENV-008",
        severity=Severity.MEDIUM,
        title="evidence array empty while findings have "
              "severity MEDIUM or HIGH",
        description=(
            "A worker that raises MEDIUM or HIGH findings should "
            "carry at least one evidence item on the envelope, "
            "even if no finding explicitly refers to it."
        ),
    ),
    Rule(
        id="ENV-009",
        severity=Severity.MEDIUM,
        title="timestamp is not RFC3339-shaped",
        description=(
            "An envelope's timestamp should be RFC3339-shaped "
            "(YYYY-MM-DDTHH:MM:SS with a timezone suffix of Z or "
            "+HH:MM). The validator does not enforce calendar "
            "validity; it enforces the shape so downstream parsers "
            "agree on what to parse."
        ),
    ),
    Rule(
        id="ENV-010",
        severity=Severity.MEDIUM,
        title="checker_run=true requires checker_role to be named",
        description=(
            "If the envelope claims a checker ran, it should name the "
            "checker's role so an auditor can see which separation "
            "was actually invoked."
        ),
    ),
    Rule(
        id="ENV-011",
        severity=Severity.LOW,
        title="finding evidence_refs point outside the evidence array",
        description=(
            "A finding may name evidence indices via evidence_refs. "
            "Indices that fall outside the envelope's evidence array "
            "are stale references."
        ),
    ),
    Rule(
        id="ENV-012",
        severity=Severity.MEDIUM,
        title="envelope_version is not a version this validator "
              "recognises",
        description=(
            "The reference validator knows one envelope version. "
            "A different version may be valid in itself; this rule "
            "signals that THIS validator cannot speak for it."
        ),
    ),
]


REGISTRY = ALL_RULES  # alias; sibling labs name their rule table REGISTRY

_RULE_BY_ID = {r.id: r for r in ALL_RULES}


# ---------------------------------------------------------------------------
# Rule bodies.
# ---------------------------------------------------------------------------

# Supported envelope schema versions this validator fully understands.
_KNOWN_VERSIONS = {"0.1.0"}

# A pragmatic RFC3339 shape check. Not a full calendar validator.
_TIMESTAMP_RE = re.compile(
    r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}"
    r"(?:\.\d+)?"
    r"(?:Z|[+-]\d{2}:\d{2})$"
)

# Field names that look like self-awarded verification tags. Checked
# only if an envelope slipped past structural (additionalProperties:
# false) via a relaxed schema.
_SELF_ATTEST_FIELDS = {
    "verified_by_author",
    "safe_to_merge",
    "author_verified",
    "self_verified",
    "self_approved",
}


def scan(envelope: Dict[str, Any]) -> ScanResult:
    """Run every cross-field rule on ``envelope`` and return a ScanResult."""
    findings: List[Finding] = []

    status = envelope.get("status")
    reasoning_tag = envelope.get("reasoning_tag")
    self_audit = envelope.get("self_audit") or {}
    findings_in = envelope.get("findings") or []
    evidence = envelope.get("evidence") or []
    scope = envelope.get("scope") or {}
    envelope_version = envelope.get("envelope_version")

    # The structural validator reports wrong-typed containers; these rules
    # still run on the same document and must never crash on it. Coerce each
    # container to its schema type and drop malformed items, so a document
    # that fails the schema gets its structural errors reported (rc 2)
    # rather than a traceback.
    if not isinstance(self_audit, dict):
        self_audit = {}
    if not isinstance(findings_in, list):
        findings_in = []
    findings_in = [f for f in findings_in if isinstance(f, dict)]
    if not isinstance(evidence, list):
        evidence = []
    if not isinstance(scope, dict):
        scope = {}

    checker_run = bool(self_audit.get("checker_run", False))
    checker_role = self_audit.get("checker_role")
    audit_verdict = self_audit.get("verdict")
    audit_reasons = self_audit.get("reasons") or []
    if not isinstance(audit_reasons, list):
        audit_reasons = []

    hi_findings = [f for f in findings_in
                   if f.get("severity") == "HIGH"]
    med_findings = [f for f in findings_in
                    if f.get("severity") == "MEDIUM"]

    # ENV-001
    if status == "ok" and not checker_run:
        findings.append(_hit("ENV-001",
                             "status=ok but self_audit.checker_run=false; "
                             "no independent check recorded",
                             "status"))

    # ENV-002
    if reasoning_tag in ("iterated", "reasoning-iterated") and not checker_run:
        findings.append(_hit("ENV-002",
                             f"reasoning_tag={reasoning_tag!r} but "
                             "self_audit.checker_run=false; "
                             "the iterated claim is self-awarded",
                             "reasoning_tag"))

    # ENV-003
    if hi_findings and not evidence:
        findings.append(_hit("ENV-003",
                             f"{len(hi_findings)} HIGH finding(s) with "
                             "no evidence items on the envelope",
                             "findings"))

    # ENV-004
    if audit_verdict == "ok" and audit_reasons:
        findings.append(_hit("ENV-004",
                             "self_audit.verdict=ok but "
                             f"{len(audit_reasons)} reason(s) carried; "
                             "either clear reasons or mark unknown",
                             "self_audit"))

    # ENV-005
    if status == "failed" and not hi_findings and not med_findings:
        findings.append(_hit("ENV-005",
                             "status=failed but no finding of severity "
                             "MEDIUM or HIGH explains the failure",
                             "status"))

    # ENV-006
    scope_in = scope.get("in") or []
    scope_out = scope.get("out") or []
    if not isinstance(scope_in, list):
        scope_in = []
    if not isinstance(scope_out, list):
        scope_out = []
    if not scope_in or not scope_out:
        findings.append(_hit("ENV-006",
                             "scope.in or scope.out is empty; "
                             "an envelope with no scope is unactionable",
                             "scope"))

    # ENV-007 - any top-level self-attestation key that got past structural.
    for key in envelope.keys():
        if key in _SELF_ATTEST_FIELDS:
            findings.append(_hit("ENV-007",
                                 f"forbidden self-attestation field "
                                 f"'{key}' present at envelope root",
                                 key))

    # ENV-008
    if not evidence and (hi_findings or med_findings):
        # ENV-003 may already have fired on the HIGH side; file this one
        # only when it adds information (MEDIUM-only envelopes, or
        # bundled HIGH+MEDIUM where the broader signal matters).
        if not hi_findings or med_findings:
            findings.append(_hit("ENV-008",
                                 "evidence array empty while findings "
                                 "of severity MEDIUM or HIGH exist",
                                 "evidence"))

    # ENV-009
    ts = envelope.get("timestamp")
    if isinstance(ts, str) and not _TIMESTAMP_RE.match(ts):
        findings.append(_hit("ENV-009",
                             f"timestamp {ts!r} is not RFC3339-shaped",
                             "timestamp"))

    # ENV-010
    if checker_run and not checker_role:
        findings.append(_hit("ENV-010",
                             "self_audit.checker_run=true but "
                             "checker_role is not named",
                             "self_audit"))

    # ENV-011
    for i, f in enumerate(findings_in):
        refs = f.get("evidence_refs") or []
        if not isinstance(refs, list):
            refs = [refs]
        for r in refs:
            if not isinstance(r, int) or r < 0 or r >= len(evidence):
                findings.append(_hit(
                    "ENV-011",
                    f"finding[{i}].evidence_refs contains "
                    f"out-of-range index {r!r} "
                    f"(evidence length {len(evidence)})",
                    f"findings/{i}/evidence_refs"))

    # ENV-012
    if envelope_version is not None and envelope_version not in _KNOWN_VERSIONS:
        findings.append(_hit("ENV-012",
                             f"envelope_version={envelope_version!r} is not "
                             "recognised by this validator "
                             f"(known: {sorted(_KNOWN_VERSIONS)})",
                             "envelope_version"))

    return ScanResult(findings=findings, verdict=rollup(findings))


def _hit(rule_id: str, message: str, where: str) -> Finding:
    rule = _RULE_BY_ID[rule_id]
    return Finding(
        rule_id=rule.id,
        severity=rule.severity,
        message=message,
        where=where,
    )
