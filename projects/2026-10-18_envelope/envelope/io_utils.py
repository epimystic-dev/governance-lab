"""File / string loading helpers."""

from __future__ import annotations

import json
import os
from typing import Any


def load(path_or_text: str) -> Any:
    """Load an envelope from a path, or parse it directly from text.

    If ``path_or_text`` is a path to an existing file, read and parse
    it. Otherwise, treat the argument as the envelope's JSON text.
    """
    if isinstance(path_or_text, str) and os.path.isfile(path_or_text):
        with open(path_or_text, "r", encoding="utf-8") as f:
            return json.load(f)
    return json.loads(path_or_text)
