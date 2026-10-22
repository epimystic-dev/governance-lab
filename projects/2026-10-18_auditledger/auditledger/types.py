"""Shared types for auditledger."""

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
class Rule:
    id: str
    severity: Severity
    title: str
    description: str


@dataclass
class Finding:
    rule_id: str
    severity: Severity
    message: str
    seq: Optional[int] = None
    line_number: Optional[int] = None

    def to_dict(self):
        d = {
            "rule_id": self.rule_id,
            "severity": self.severity.value,
            "message": self.message,
        }
        if self.seq is not None:
            d["seq"] = self.seq
        if self.line_number is not None:
            d["line_number"] = self.line_number
        return d


@dataclass
class ScanResult:
    findings: List[Finding] = field(default_factory=list)
    verdict: Verdict = Verdict.UNKNOWN
    entries_checked: int = 0
    head_hash: Optional[str] = None

    def to_dict(self):
        return {
            "verdict": self.verdict.value,
            "entries_checked": self.entries_checked,
            "head_hash": self.head_hash,
            "findings": [f.to_dict() for f in self.findings],
        }


@dataclass
class Entry:
    seq: int
    ts: str
    kind: str
    payload: Any
    prev: str
    hash: str

    def to_dict(self):
        return {
            "seq": self.seq,
            "ts": self.ts,
            "kind": self.kind,
            "payload": self.payload,
            "prev": self.prev,
            "hash": self.hash,
        }


class LedgerError(Exception):
    """Base class for ledger-side errors (bad input, locking, I/O)."""


def rollup(findings) -> Verdict:
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
