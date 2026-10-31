"""Text load helper. Standard library only."""

from __future__ import annotations

import os


def load(path_or_text: str) -> str:
    """Load text from a filesystem path, or return the string as-is."""
    if isinstance(path_or_text, str) and os.path.isfile(path_or_text):
        with open(path_or_text, "r", encoding="utf-8") as f:
            return f.read()
    return path_or_text
