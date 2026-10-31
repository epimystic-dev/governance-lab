"""rungtag - reasoning-depth-tag presence and consistency linter.

Public surface:

- ``__version__``                        semantic version string
- ``Severity``                           enum: HIGH, MEDIUM, LOW, INFO
- ``Verdict``                            enum: healthy, needs-attention, unhealthy, unknown
- ``Finding``                            dataclass for one rule hit
- ``ScanResult``                         dataclass carrying findings and a verdict
- ``Rule``                               dataclass naming one rule
- ``ALL_RULES``                          the rule registry (list of Rule objects)
- ``PRIMARY_TOKENS``                     frozenset of accepted primary tag tokens
- ``RUNG_TOKENS``                        frozenset of accepted rung-N tokens
- ``scan(text)``                         rules check, returns ScanResult
- ``parse_tag(raw)``                     tag parser used by scan
- ``split_blocks(text)``                 block parser used by scan
- ``load(path_or_text)``                 convenience loader
"""

from __future__ import annotations

from .types import (
    Severity,
    Verdict,
    Finding,
    ScanResult,
    Rule,
)
from .patterns import (
    ALL_KNOWN_TOKENS,
    PRIMARY_TOKENS,
    RUNG_TOKENS,
    parse_tag,
    split_blocks,
)
from .rules import ALL_RULES, scan
from .io_utils import load


__version__ = "0.1.0"


__all__ = [
    "__version__",
    "Severity",
    "Verdict",
    "Finding",
    "ScanResult",
    "Rule",
    "ALL_RULES",
    "PRIMARY_TOKENS",
    "RUNG_TOKENS",
    "ALL_KNOWN_TOKENS",
    "scan",
    "parse_tag",
    "split_blocks",
    "load",
]
