"""Core ledger: append / verify / digest.

The on-disk format is one JSON object per line (JSONL), UTF-8 encoded,
with a trailing newline after each row. Each row has exactly these
fields:

- ``seq``       integer, zero-based, strictly +1 per row
- ``ts``        RFC3339 UTC timestamp
- ``kind``      user-defined string tag
- ``payload``   arbitrary JSON-serialisable value
- ``prev``      hex SHA-256 of the previous row's ``hash``, or
                64 zeros for seq=0
- ``hash``      hex SHA-256 over canonical({seq, ts, kind,
                payload, prev})

The format is designed to be auditable with a stdlib tool a reviewer
has: ``cat`` to read, ``jq`` to slice, ``sha256sum`` to spot-check.
"""

from __future__ import annotations

import datetime
import hashlib
import io
import json
import os
import re
import tempfile
from typing import Any, List, Optional, Tuple

from .canonical import canonical_bytes
from .rules import ALL_RULES
from .types import (
    Entry,
    Finding,
    LedgerError,
    ScanResult,
    Severity,
    Verdict,
    rollup,
)


ZERO_HASH = "0" * 64

_HEX_RE = re.compile(r"^[0-9a-f]{64}$")
_RFC3339_RE = re.compile(
    r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}"
    r"(?:\.\d+)?"
    r"(?:Z|[+-]\d{2}:\d{2})$"
)

_REQUIRED_FIELDS = ("seq", "ts", "kind", "payload", "prev", "hash")


# ---------------------------------------------------------------------------
# Public functional API.
# ---------------------------------------------------------------------------

def init(path: str) -> None:
    """Create an empty ledger file at ``path``.

    If the file already exists and is non-empty, raise LedgerError
    rather than silently truncating a live ledger.
    """
    if os.path.exists(path) and os.path.getsize(path) > 0:
        raise LedgerError(
            f"ledger already exists and is non-empty: {path}"
        )
    # Ensure the directory exists before touching the file.
    d = os.path.dirname(os.path.abspath(path))
    if d and not os.path.isdir(d):
        os.makedirs(d, exist_ok=True)
    with open(path, "a", encoding="utf-8"):
        pass  # touch


def append(
    path: str,
    kind: str,
    payload: Any,
    ts: Optional[str] = None,
) -> Entry:
    """Append one row to ``path`` and return the Entry written.

    The caller supplies ``kind`` and ``payload``. ``ts`` defaults to
    the current UTC time in RFC3339 shape.
    """
    if not isinstance(kind, str) or not kind:
        raise LedgerError("kind must be a non-empty string")

    # Canonical encoding will raise if the payload is not
    # JSON-serialisable or carries NaN / Infinity. Normalise that to
    # LedgerError so a caller sees one error class on the append path.
    try:
        _ = canonical_bytes(payload)
    except (TypeError, ValueError) as e:
        raise LedgerError(f"payload is not canonically serialisable: {e}")

    if ts is None:
        ts = _now_rfc3339()
    elif not _RFC3339_RE.match(ts):
        raise LedgerError(
            f"ts {ts!r} is not RFC3339-shaped")

    # Compute seq and prev from the last row.
    last = head(path)
    seq = 0 if last is None else last.seq + 1
    prev = ZERO_HASH if last is None else last.hash

    entry_core = {
        "seq": seq,
        "ts": ts,
        "kind": kind,
        "payload": payload,
        "prev": prev,
    }
    h = hashlib.sha256(canonical_bytes(entry_core)).hexdigest()
    entry = Entry(seq=seq, ts=ts, kind=kind, payload=payload,
                  prev=prev, hash=h)

    line = json.dumps(entry.to_dict(),
                      sort_keys=True,
                      separators=(",", ":"),
                      ensure_ascii=False,
                      allow_nan=False) + "\n"

    _atomic_append(path, line)
    return entry


def verify(path: str) -> ScanResult:
    """Walk the ledger at ``path`` and return a ScanResult.

    The walk reports every defect it finds, keyed to the row that
    carries it; it does not stop on the first error.
    """
    findings: List[Finding] = []
    expected_prev = ZERO_HASH
    expected_seq = 0
    checked = 0
    head_hash: Optional[str] = None

    if not os.path.isfile(path):
        raise LedgerError(f"ledger not found: {path}")

    with open(path, "r", encoding="utf-8") as f:
        for lineno, raw in enumerate(f, start=1):
            if not raw.strip():
                continue
            try:
                obj = json.loads(raw)
            except json.JSONDecodeError as e:
                findings.append(Finding(
                    rule_id="AL-001",
                    severity=Severity.HIGH,
                    message=f"line is not valid JSON ({e.msg})",
                    line_number=lineno,
                ))
                # Cannot continue chain-walking past an unparseable
                # row; break so AL-005 does not fire with a wrong
                # expected_prev.
                break

            if not isinstance(obj, dict):
                findings.append(Finding(
                    rule_id="AL-002",
                    severity=Severity.HIGH,
                    message="row is not a JSON object",
                    line_number=lineno,
                ))
                break

            missing = [k for k in _REQUIRED_FIELDS if k not in obj]
            if missing:
                findings.append(Finding(
                    rule_id="AL-003",
                    severity=Severity.HIGH,
                    message=f"row missing required field(s): "
                            f"{', '.join(missing)}",
                    seq=obj.get("seq"),
                    line_number=lineno,
                ))
                break

            seq = obj["seq"]
            ts = obj["ts"]
            kind = obj["kind"]
            payload = obj["payload"]
            prev = obj["prev"]
            h = obj["hash"]

            if seq != expected_seq:
                findings.append(Finding(
                    rule_id="AL-004",
                    severity=Severity.HIGH,
                    message=f"expected seq {expected_seq}, "
                            f"got {seq}",
                    seq=seq,
                    line_number=lineno,
                ))
                # continue walking at the reported seq+1 so a
                # downstream reviewer still sees downstream defects
                # rather than one blanket "chain broken" that hides
                # them. The expected_prev value we had is still
                # correct relative to the actual stored prev / hash.

            if prev != expected_prev:
                findings.append(Finding(
                    rule_id="AL-005",
                    severity=Severity.HIGH,
                    message="prev does not match previous row's hash",
                    seq=seq,
                    line_number=lineno,
                ))

            if not isinstance(h, str) or not _HEX_RE.match(h):
                findings.append(Finding(
                    rule_id="AL-008",
                    severity=Severity.MEDIUM,
                    message="hash field is not a 64-char lowercase "
                            "hex string",
                    seq=seq,
                    line_number=lineno,
                ))
            if not isinstance(prev, str) or not _HEX_RE.match(prev):
                findings.append(Finding(
                    rule_id="AL-008",
                    severity=Severity.MEDIUM,
                    message="prev field is not a 64-char lowercase "
                            "hex string",
                    seq=seq,
                    line_number=lineno,
                ))

            # Hash check.
            core = {
                "seq": seq, "ts": ts, "kind": kind,
                "payload": payload, "prev": prev,
            }
            try:
                recomputed = hashlib.sha256(
                    canonical_bytes(core)
                ).hexdigest()
            except ValueError as e:
                recomputed = None
                findings.append(Finding(
                    rule_id="AL-006",
                    severity=Severity.HIGH,
                    message=f"row cannot be canonically encoded: "
                            f"{e}",
                    seq=seq,
                    line_number=lineno,
                ))

            if recomputed is not None and recomputed != h:
                findings.append(Finding(
                    rule_id="AL-006",
                    severity=Severity.HIGH,
                    message="hash does not match canonical "
                            "encoding of row content",
                    seq=seq,
                    line_number=lineno,
                ))

            if not isinstance(ts, str) or not _RFC3339_RE.match(ts):
                findings.append(Finding(
                    rule_id="AL-007",
                    severity=Severity.MEDIUM,
                    message=f"ts {ts!r} is not RFC3339-shaped",
                    seq=seq,
                    line_number=lineno,
                ))

            if not isinstance(kind, str) or not kind:
                findings.append(Finding(
                    rule_id="AL-009",
                    severity=Severity.MEDIUM,
                    message="kind is empty or not a string",
                    seq=seq,
                    line_number=lineno,
                ))

            checked += 1
            expected_prev = h if isinstance(h, str) else ZERO_HASH
            expected_seq = seq + 1
            head_hash = expected_prev if isinstance(h, str) else head_hash

    return ScanResult(
        findings=findings,
        verdict=rollup(findings),
        entries_checked=checked,
        head_hash=head_hash,
    )


def digest(path: str) -> Optional[str]:
    """Return the hex SHA-256 of the final row, or None for an empty
    ledger. Does NOT verify the chain; call verify() for that.
    """
    last = head(path)
    return None if last is None else last.hash


def head(path: str) -> Optional[Entry]:
    """Return the last ledger row as an Entry, or None if empty."""
    if not os.path.isfile(path) or os.path.getsize(path) == 0:
        return None
    last_line: Optional[str] = None
    with open(path, "r", encoding="utf-8") as f:
        for line in f:
            if line.strip():
                last_line = line
    if last_line is None:
        return None
    try:
        obj = json.loads(last_line)
    except json.JSONDecodeError as e:
        raise LedgerError(f"last row is not valid JSON: {e.msg}")
    try:
        return Entry(
            seq=obj["seq"],
            ts=obj["ts"],
            kind=obj["kind"],
            payload=obj["payload"],
            prev=obj["prev"],
            hash=obj["hash"],
        )
    except KeyError as e:
        raise LedgerError(f"last row missing field {e}")


class Ledger:
    """Convenience facade. The functional API is the primary
    interface; this class is useful when a caller wants to pass one
    object around.
    """

    def __init__(self, path: str) -> None:
        self.path = path

    def init(self) -> None:
        init(self.path)

    def append(self, kind: str, payload: Any,
               ts: Optional[str] = None) -> Entry:
        return append(self.path, kind, payload, ts=ts)

    def verify(self) -> ScanResult:
        return verify(self.path)

    def digest(self) -> Optional[str]:
        return digest(self.path)

    def head(self) -> Optional[Entry]:
        return head(self.path)

    def __repr__(self) -> str:
        return f"Ledger({self.path!r})"


# ---------------------------------------------------------------------------
# Internal helpers.
# ---------------------------------------------------------------------------

def _now_rfc3339() -> str:
    # Explicitly UTC with microseconds; keeps the format stable
    # across runs on hosts whose default timezone varies.
    now = datetime.datetime.now(datetime.timezone.utc)
    return now.strftime("%Y-%m-%dT%H:%M:%S.%fZ")


def _atomic_append(path: str, line: str) -> None:
    """Append a single JSONL line.

    Two write modes:
    - If ``path`` exists, use open-for-append; the OS appends the
      bytes to the end of the file.
    - If ``path`` does not exist, write a fresh file.

    Open-for-append on POSIX and modern Windows is atomic for a
    single write() smaller than the filesystem's atomic-write size,
    which is well above our line sizes. For callers that need stricter
    atomicity under concurrent writers, hold a file lock around the
    append.
    """
    with open(path, "a", encoding="utf-8", newline="") as f:
        f.write(line)
