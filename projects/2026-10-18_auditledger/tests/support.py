"""Shared test helpers for auditledger."""

from __future__ import annotations

import io
import json
import os
import tempfile
from typing import Sequence, Tuple

from auditledger.cli import main as cli_main


_PROJECT_ROOT = os.path.abspath(
    os.path.join(os.path.dirname(__file__), "..")
)
_LOCAL_TMP = os.path.join(_PROJECT_ROOT, ".pytest_tmp")
os.makedirs(_LOCAL_TMP, exist_ok=True)
tempfile.tempdir = _LOCAL_TMP


def fresh_ledger_path(prefix: str = "ledger_") -> str:
    """A path to a fresh (nonexistent) ledger file in a temp dir."""
    d = tempfile.mkdtemp(prefix=prefix)
    return os.path.join(d, "ledger.jsonl")


def run_cli(argv: Sequence[str]) -> Tuple[int, str, str]:
    out = io.StringIO()
    err = io.StringIO()
    rc = cli_main(list(argv), stdout=out, stderr=err)
    return rc, out.getvalue(), err.getvalue()


def rewrite_line(path: str, index: int, new_line: str) -> None:
    """Overwrite the 0-indexed line at ``index`` with ``new_line``.

    ``new_line`` must NOT include the trailing newline.
    """
    with open(path, "r", encoding="utf-8") as f:
        lines = f.readlines()
    lines[index] = new_line + "\n"
    with open(path, "w", encoding="utf-8") as f:
        f.writelines(lines)


def read_row(path: str, index: int) -> dict:
    with open(path, "r", encoding="utf-8") as f:
        return json.loads(f.readlines()[index])
