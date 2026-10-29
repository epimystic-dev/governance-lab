"""Shared test helpers for trustlabels.

A healthy entry builder plus bundle factories so each rule test takes a
known-clean bundle and introduces exactly the one defect the rule
under test should flag.
"""

from __future__ import annotations

import copy
import io
import json
import os
import tempfile
from typing import Any, Dict, Iterable, List, Sequence, Tuple

from trustlabels.cli import main as cli_main
from trustlabels.rules import scan
from trustlabels.types import Finding


# Route temp files into a project-local directory so an endpoint
# scanner watching the user profile Temp folder cannot quarantine a
# fixture mid-write. The directory is dot-prefixed and git-ignored.
_PROJECT_ROOT = os.path.abspath(
    os.path.join(os.path.dirname(__file__), "..")
)
_LOCAL_TMP = os.path.join(_PROJECT_ROOT, ".pytest_tmp")
os.makedirs(_LOCAL_TMP, exist_ok=True)
tempfile.tempdir = _LOCAL_TMP


def healthy_entry() -> Dict[str, Any]:
    """A minimal, cross-field-clean entry."""
    return {
        "id": "web/doc-1",
        "trust_label": "quarantined:web",
        "source_ref": "https://example.com/doc",
        "grounds_for_action": False,
        "entered_at": "2026-10-25T09:00:00Z",
        "promoted_to": None,
        "promoted_by": None,
        "promotion_gate": None,
    }


def healthy() -> Dict[str, Any]:
    """A minimal, cross-field-clean bundle."""
    return {
        "entries": [
            {
                "id": "sys/prompt-A",
                "trust_label": "trusted:system",
                "source_ref": "pkg://host/system.md",
                "grounds_for_action": True,
                "entered_at": "2026-10-25T09:00:00Z",
                "promoted_to": None,
                "promoted_by": None,
                "promotion_gate": None,
            },
            healthy_entry(),
        ]
    }


def mutate_entry(**overrides: Any) -> Dict[str, Any]:
    """Deep-copy ``healthy_entry()``, apply ``overrides`` at top level."""
    e = healthy_entry()
    for k, v in overrides.items():
        if v is None and k in e:
            e[k] = None
        else:
            e[k] = v
    return e


def bundle_with(entry: Dict[str, Any]) -> Dict[str, Any]:
    """Return a healthy bundle with ``entry`` appended."""
    b = healthy()
    b["entries"].append(entry)
    return b


def bundle_only(entry: Dict[str, Any]) -> Dict[str, Any]:
    """Return a bundle whose only payload is ``entry``.

    Used for per-rule tests where sibling entries would add noise.
    """
    return {"entries": [entry]}


def deep(obj: Any) -> Any:
    return copy.deepcopy(obj)


def rule_ids(findings: Iterable[Finding]) -> Tuple[str, ...]:
    return tuple(f.rule_id for f in findings)


def write_temp(bundle: Any, name: str = "bundle.json") -> Tuple[str, str]:
    """Write a bundle to a fresh temp directory."""
    d = tempfile.mkdtemp(prefix="trustlabels_")
    p = os.path.join(d, name)
    with open(p, "w", encoding="utf-8") as f:
        json.dump(bundle, f, ensure_ascii=False, indent=2)
    return d, p


def run_cli(argv: Sequence[str]) -> Tuple[int, str, str]:
    """Invoke the CLI in-process. Returns (rc, stdout, stderr)."""
    out = io.StringIO()
    err = io.StringIO()
    rc = cli_main(list(argv), stdout=out, stderr=err)
    return rc, out.getvalue(), err.getvalue()


def scan_rule_ids(bundle: Any) -> Tuple[str, ...]:
    return rule_ids(scan(bundle).findings)


def scan_rule_ids_for_entry(entry: Dict[str, Any]) -> List[str]:
    """Scan only one entry; return rule ids filtered to this entry."""
    bundle = bundle_only(entry)
    return [f.rule_id for f in scan(bundle).findings]
