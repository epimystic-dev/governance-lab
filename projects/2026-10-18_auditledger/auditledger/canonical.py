"""Canonical JSON serialisation.

The hash chain commits to the SHA-256 of a canonical byte encoding of
each row's hash-covered fields. Two implementations must produce the
same bytes for the same semantic object, or verification will fire a
false positive. The canonicalisation is deliberately small and
documented:

- UTF-8 output.
- Keys sorted lexicographically.
- No whitespace between tokens: separators are ``,`` and ``:``.
- ``ensure_ascii=False`` so a non-ASCII payload is encoded byte-for-byte
  rather than reflowed through ``\\uXXXX`` escapes.
- ``allow_nan=False`` so NaN / Infinity cannot leak into the hash
  input: they are not representable in standard JSON and two
  implementations may disagree on how to encode them.

These are a strict subset of the publicly observable Python stdlib
json options; the function below is a one-call wrapper for clarity.
"""

from __future__ import annotations

import json
from typing import Any


def canonical_bytes(obj: Any) -> bytes:
    """Return canonical UTF-8 JSON bytes for ``obj``.

    Raises ``ValueError`` if ``obj`` is not JSON-serialisable or
    contains NaN / Infinity.
    """
    return json.dumps(
        obj,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        allow_nan=False,
    ).encode("utf-8")
