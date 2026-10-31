"""Shared test helpers for rungtag."""

from __future__ import annotations

import io
import os
import tempfile
from typing import Iterable, Sequence, Tuple

from rungtag.cli import main as cli_main
from rungtag.rules import scan
from rungtag.types import Finding


# Route temp files into a project-local directory so an endpoint
# scanner watching the user profile Temp folder cannot quarantine a
# fixture mid-write. The directory is dot-prefixed and git-ignored.
_PROJECT_ROOT = os.path.abspath(
    os.path.join(os.path.dirname(__file__), "..")
)
_LOCAL_TMP = os.path.join(_PROJECT_ROOT, ".pytest_tmp")
os.makedirs(_LOCAL_TMP, exist_ok=True)
tempfile.tempdir = _LOCAL_TMP


def healthy_text() -> str:
    """A tagged, consistent transcript. The lab's known-clean baseline."""
    return (
        "## block one\n"
        "tag: (reasoning)\n"
        "\n"
        + ("The scanner inspects the input and emits findings per rule. "
           "Each block declares its reasoning depth, and the lint rules "
           "check that the declaration is internally consistent across "
           "the whole stream. This paragraph exists so the word count "
           "of block one is well above the substantive threshold, which "
           "is the point of a known-clean fixture at this scale.\n")
        + "\n"
        "## block two\n"
        "tag: (reasoning, iterated)\n"
        "checker_role: reviewer\n"
        "\n"
        + ("A checker pass over block one. Because this block names its "
           "checker in the header, the iterated claim is grounded.\n")
    )


def rule_ids(findings: Iterable[Finding]) -> Tuple[str, ...]:
    return tuple(f.rule_id for f in findings)


def scan_rule_ids(text: str, **kw) -> Tuple[str, ...]:
    return rule_ids(scan(text, **kw).findings)


def write_temp(text: str, name: str = "input.md") -> Tuple[str, str]:
    d = tempfile.mkdtemp(prefix="rungtag_")
    p = os.path.join(d, name)
    with open(p, "w", encoding="utf-8") as f:
        f.write(text)
    return d, p


def run_cli(argv: Sequence[str]) -> Tuple[int, str, str]:
    out = io.StringIO()
    err = io.StringIO()
    rc = cli_main(list(argv), stdout=out, stderr=err)
    return rc, out.getvalue(), err.getvalue()
