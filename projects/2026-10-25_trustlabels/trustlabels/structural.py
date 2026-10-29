"""Structural checks for trustlabels bundles.

The schema is small enough to hand-roll, no third-party library. A
bundle is either a list of entries, or an object with an ``entries``
list. Every entry must be an object; every entry must carry an ``id``
field; every entry must carry a ``trust_label`` field. Extra fields
are allowed because the rule engine inspects additional fields the
schema need not enumerate.
"""

from __future__ import annotations

from typing import Any, List, Tuple

from .types import ValidationError


_REQUIRED_ENTRY_FIELDS = ("id", "trust_label")


def validate(bundle: Any) -> None:
    """Raise ValidationError if the bundle fails structural shape."""
    errors: List[Tuple[str, str]] = []

    if isinstance(bundle, list):
        entries = bundle
        base = ""
    elif isinstance(bundle, dict):
        es = bundle.get("entries")
        if es is None:
            errors.append(("", "bundle object has no 'entries' field"))
            raise ValidationError(errors)
        if not isinstance(es, list):
            errors.append(("entries", "'entries' is not a list"))
            raise ValidationError(errors)
        entries = es
        base = "entries"
    else:
        errors.append(("", f"bundle is not a list or object (got {type(bundle).__name__})"))
        raise ValidationError(errors)

    for i, e in enumerate(entries):
        where = f"{base}/{i}" if base else f"{i}"
        if not isinstance(e, dict):
            errors.append((where, f"entry is not an object (got {type(e).__name__})"))
            continue
        for key in _REQUIRED_ENTRY_FIELDS:
            if key not in e:
                errors.append((f"{where}/{key}", f"required field '{key}' missing"))

    if errors:
        raise ValidationError(errors)
