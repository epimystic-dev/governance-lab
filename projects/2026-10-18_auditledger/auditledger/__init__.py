"""auditledger - append-only hash-chained JSONL ledger.

Public surface:

- ``__version__``                     semantic version
- ``Severity``                        enum: HIGH / MEDIUM / LOW / INFO
- ``Verdict``                         enum: healthy / needs-attention / unhealthy / unknown
- ``Finding``                         dataclass (one verify defect)
- ``ScanResult``                      dataclass (verify findings + verdict)
- ``Rule``                            dataclass (one verify rule)
- ``ALL_RULES``                       registry of verify rules
- ``LedgerError``                     base class for ledger-side errors
- ``Entry``                           dataclass for one ledger row
- ``Ledger``                          the ledger facade (open / append / verify / digest)
- ``append(path, kind, payload, ...)``
- ``verify(path)``                    returns ScanResult
- ``digest(path)``                    returns HEAD hash or None
- ``head(path)``                      returns the latest Entry or None
- ``init(path)``                      create a new empty ledger (no file content)
- ``canonical_bytes(obj)``            canonical JSON encoding used for hashing
"""

from __future__ import annotations

from .types import (
    Severity,
    Verdict,
    Finding,
    ScanResult,
    Rule,
    LedgerError,
    Entry,
)
from .canonical import canonical_bytes
from .rules import ALL_RULES
from .ledger import Ledger, append, verify, digest, head, init


__version__ = "0.1.0"


__all__ = [
    "__version__",
    "Severity",
    "Verdict",
    "Finding",
    "ScanResult",
    "Rule",
    "ALL_RULES",
    "LedgerError",
    "Entry",
    "Ledger",
    "append",
    "verify",
    "digest",
    "head",
    "init",
    "canonical_bytes",
]
