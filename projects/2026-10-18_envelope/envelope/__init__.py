"""envelope - worker output envelope schema and reference validator.

Public surface:

- ``__version__``                        semantic version string
- ``Severity``                           enum: HIGH, MEDIUM, LOW, INFO
- ``Verdict``                            enum: healthy, needs-attention, unhealthy, unknown
- ``Finding``                            dataclass for one rule hit
- ``ScanResult``                         dataclass carrying findings and a verdict
- ``Rule``                               dataclass naming one cross-field rule
- ``ALL_RULES``                          the rule registry (list of Rule objects)
- ``SCHEMA``                             the JSON Schema 2020-12 document
- ``ValidationError``                    raised on structural (schema) failure
- ``validate(envelope)``                 structural check, raises ValidationError on fail
- ``scan(envelope)``                     cross-field discipline check, returns ScanResult
- ``check(envelope)``                    convenience: run both; return ScanResult or raise
- ``load(path_or_text)``                 convenience loader
"""

from __future__ import annotations

from .types import (
    Severity,
    Verdict,
    Finding,
    ScanResult,
    Rule,
    ValidationError,
)
from .schema import SCHEMA
from .structural import validate
from .rules import ALL_RULES, scan
from .io_utils import load


__version__ = "0.1.0"


def check(envelope):
    """Run structural validation THEN rules scan.

    Raises ``ValidationError`` if the envelope fails schema shape.
    Returns a ``ScanResult`` otherwise. The caller inspects
    ``result.verdict`` and ``result.findings``.
    """
    validate(envelope)
    return scan(envelope)


__all__ = [
    "__version__",
    "Severity",
    "Verdict",
    "Finding",
    "ScanResult",
    "Rule",
    "ALL_RULES",
    "SCHEMA",
    "ValidationError",
    "validate",
    "scan",
    "check",
    "load",
]
