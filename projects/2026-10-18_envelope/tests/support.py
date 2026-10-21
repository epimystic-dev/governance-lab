"""Shared test helpers for envelope.

A healthy envelope builder plus deep-copy mutators so each rule test
takes a known-clean envelope and introduces exactly the one defect
the rule under test should flag.
"""

from __future__ import annotations

import copy
import io
import json
import os
import tempfile
from typing import Any, Dict, Iterable, Sequence, Tuple

from envelope.cli import main as cli_main
from envelope.rules import scan
from envelope.types import Finding


FIXTURES = os.path.join(os.path.dirname(__file__), "fixtures")

# Route temp files into a project-local directory so an endpoint
# scanner watching the user profile Temp folder cannot quarantine a
# fixture mid-write. The directory is dot-prefixed and git-ignored.
_PROJECT_ROOT = os.path.abspath(
    os.path.join(os.path.dirname(__file__), "..")
)
_LOCAL_TMP = os.path.join(_PROJECT_ROOT, ".pytest_tmp")
os.makedirs(_LOCAL_TMP, exist_ok=True)
tempfile.tempdir = _LOCAL_TMP


def healthy() -> Dict[str, Any]:
    """A minimal, cross-field-clean envelope."""
    return {
        "envelope_version": "0.1.0",
        "task_id": "t-001",
        "status": "ok",
        "scope": {
            "in": ["inputs/a.jsonl"],
            "out": ["outputs/report.md"],
        },
        "findings": [],
        "evidence": [
            {
                "claim": "input was present",
                "kind": "file",
                "ref": "inputs/a.jsonl",
            }
        ],
        "reasoning_tag": "reasoning",
        "self_audit": {
            "checker_run": True,
            "checker_role": "reviewer",
            "verdict": "ok",
            "reasons": [],
        },
        "timestamp": "2026-10-18T09:30:00Z",
    }


def mutate(**overrides: Any) -> Dict[str, Any]:
    """Deep-copy ``healthy()``, apply ``overrides`` at the top level,
    return the result.
    """
    env = healthy()
    for k, v in overrides.items():
        env[k] = v
    return env


def deep(obj: Any) -> Any:
    return copy.deepcopy(obj)


def rule_ids(findings: Iterable[Finding]) -> Tuple[str, ...]:
    return tuple(f.rule_id for f in findings)


def write_temp(env: Dict[str, Any], name: str = "env.json") -> Tuple[str, str]:
    """Write an envelope dict to a fresh temp directory."""
    d = tempfile.mkdtemp(prefix="envelope_")
    p = os.path.join(d, name)
    with open(p, "w", encoding="utf-8") as f:
        json.dump(env, f, ensure_ascii=False, indent=2)
    return d, p


def run_cli(argv: Sequence[str]) -> Tuple[int, str, str]:
    """Invoke the CLI in-process. Returns (rc, stdout, stderr)."""
    out = io.StringIO()
    err = io.StringIO()
    rc = cli_main(list(argv), stdout=out, stderr=err)
    return rc, out.getvalue(), err.getvalue()


def scan_rule_ids(env: Dict[str, Any]) -> Tuple[str, ...]:
    return rule_ids(scan(env).findings)
