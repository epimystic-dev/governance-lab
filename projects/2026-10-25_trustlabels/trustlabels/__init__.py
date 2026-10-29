"""trustlabels - taxonomy and transition-matrix linter for the
provenance of content entering a reasoning context.

Public surface:

- ``__version__``                        semantic version string
- ``Severity``                           enum: HIGH, MEDIUM, LOW, INFO
- ``Verdict``                            enum: healthy, needs-attention, unhealthy, unknown
- ``Finding``                            dataclass for one rule hit
- ``ScanResult``                         dataclass carrying findings and a verdict
- ``Rule``                               dataclass naming one rule
- ``ALL_RULES``                          the rule registry (list of Rule objects)
- ``KNOWN_LABELS``                       frozenset of accepted trust labels
- ``TRANSITIONS``                        the promotion matrix
- ``GATES``                              transition -> accepted gate names
- ``ValidationError``                    raised on structural failure
- ``validate(bundle)``                   structural check, raises ValidationError on fail
- ``scan(bundle)``                       cross-field discipline check, returns ScanResult
- ``check(bundle)``                      convenience: run both; return ScanResult or raise
- ``load(path_or_text)``                 convenience loader
- ``main``                               CLI entry point
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
from .structural import validate
from .rules import ALL_RULES, scan
from .taxonomy import GATES, KNOWN_LABELS, TRANSITIONS
from .io_utils import load


__version__ = "0.1.0"


def check(bundle):
    """Run structural validation THEN rules scan.

    Raises ``ValidationError`` if the bundle fails schema shape.
    Returns a ``ScanResult`` otherwise.
    """
    validate(bundle)
    return scan(bundle)


__all__ = [
    "__version__",
    "Severity",
    "Verdict",
    "Finding",
    "ScanResult",
    "Rule",
    "ALL_RULES",
    "KNOWN_LABELS",
    "TRANSITIONS",
    "GATES",
    "ValidationError",
    "validate",
    "scan",
    "check",
    "load",
]
