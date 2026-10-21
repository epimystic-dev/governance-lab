"""Shared types for envelope.

Severity and Verdict follow the lab-wide linter convention so a reader
who has used a sibling tool needs no new vocabulary.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any, List, Optional


class Severity(str, Enum):
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"


class Verdict(str, Enum):
    HEALTHY = "healthy"
    NEEDS_ATTENTION = "needs-attention"
    UNHEALTHY = "unhealthy"
    UNKNOWN = "unknown"


@dataclass
class Finding:
    rule_id: str
    severity: Severity
    message: str
    where: Optional[str] = None

    def to_dict(self):
        d = {
            "rule_id": self.rule_id,
            "severity": self.severity.value,
            "message": self.message,
        }
        if self.where is not None:
            d["where"] = self.where
        return d


@dataclass
class Rule:
    id: str
    severity: Severity
    title: str
    description: str


@dataclass
class ScanResult:
    findings: List[Finding] = field(default_factory=list)
    verdict: Verdict = Verdict.UNKNOWN

    def to_dict(self):
        return {
            "verdict": self.verdict.value,
            "findings": [f.to_dict() for f in self.findings],
        }


class ValidationError(Exception):
    """Raised when an envelope fails structural (schema) validation.

    The ``errors`` attribute is a list of (jsonpointer, message) pairs
    so a caller can present every structural fault, not only the first.
    """

    def __init__(self, errors):
        self.errors = list(errors)
        if not self.errors:
            msg = "envelope failed structural validation"
        else:
            lines = [f"- {ptr}: {msg}" for ptr, msg in self.errors]
            msg = "envelope failed structural validation:\n" + "\n".join(lines)
        super().__init__(msg)


def rollup(findings) -> Verdict:
    """Verdict rollup used by rules.scan and the CLI."""
    hi = any(f.severity == Severity.HIGH for f in findings)
    med = any(f.severity == Severity.MEDIUM for f in findings)
    low = any(f.severity == Severity.LOW for f in findings)
    if hi:
        return Verdict.UNHEALTHY
    if med:
        return Verdict.NEEDS_ATTENTION
    if low:
        return Verdict.NEEDS_ATTENTION
    return Verdict.HEALTHY


def ascii_safe(text: Any) -> str:
    """Render arbitrary content ASCII-safe for the text report.

    Non-ASCII characters become ``<U+XXXX>`` so a Windows console on
    cp1252 cannot crash the reporter mid-write.
    """
    if not isinstance(text, str):
        text = str(text)
    out = []
    for ch in text:
        cp = ord(ch)
        if 0x20 <= cp <= 0x7E or ch in ("\n", "\t"):
            out.append(ch)
        else:
            out.append(f"<U+{cp:04X}>")
    return "".join(out)
