"""JSON load helper. Standard library only."""

from __future__ import annotations

import json
import os
from typing import Any


def load(path_or_text: str) -> Any:
    """Load a bundle from a filesystem path, or parse an inline JSON string.

    If ``path_or_text`` is an existing file, read and parse it; otherwise
    treat it as JSON text.
    """
    if isinstance(path_or_text, str) and os.path.isfile(path_or_text):
        with open(path_or_text, "r", encoding="utf-8") as f:
            return json.load(f)
    return json.loads(path_or_text)
