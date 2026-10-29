"""CLI entry point for trustlabels.

Conforms to the lab's CLI contract:
- ``python -m trustlabels PATH``   check a bundle file
- ``--help``                        returns 0
- ``--version``                     returns 0
- An unknown flag                   returns 2
- Results on stdout, diagnostics on stderr
- Return codes: 0 clean; 1 non-blocking (LOW/MEDIUM) findings;
  2 HIGH findings or structural failure or unreadable input
"""

from __future__ import annotations

import argparse
import json
import os
import sys
from typing import List, Optional, TextIO

from . import __version__
from .io_utils import load
from .rules import ALL_RULES, scan
from .structural import validate
from .taxonomy import GATES, KNOWN_LABELS, TRANSITIONS
from .types import Severity, ValidationError, Verdict, ascii_safe


def main(
    argv: Optional[List[str]] = None,
    stdout: Optional[TextIO] = None,
    stderr: Optional[TextIO] = None,
) -> int:
    stdout = stdout if stdout is not None else sys.stdout
    stderr = stderr if stderr is not None else sys.stderr
    argv = list(sys.argv[1:] if argv is None else argv)

    parser = _parser()
    try:
        args = parser.parse_args(argv)
    except SystemExit as e:
        code = e.code
        if isinstance(code, int):
            return code
        return 2

    if args.print_rules:
        return _print_rules(stdout)
    if args.print_taxonomy:
        return _print_taxonomy(stdout)

    if args.path is None:
        stderr.write("trustlabels: no bundle path given; "
                     "run `trustlabels --help`\n")
        return 2

    return _check(args, stdout, stderr)


def _parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="trustlabels",
        description=(
            "Trust-label bundle checker: validate shape and run "
            "trust-promotion discipline rules."),
    )
    p.add_argument("--version", action="version",
                   version=f"trustlabels {__version__}")
    p.add_argument("path", nargs="?", default=None,
                   help="Path to a bundle JSON file.")
    p.add_argument("--json", action="store_true",
                   help="Emit a JSON report on stdout.")
    p.add_argument("--strict", action="store_true",
                   help="Any finding returns rc >= 1 (default behavior).")
    p.add_argument("--include-info", action="store_true",
                   help="Include INFO-severity findings in report.")
    p.add_argument("--disable", action="append", default=[],
                   metavar="RULE",
                   help="Rule id to disable (may repeat).")
    p.add_argument("--print-rules", action="store_true",
                   help="Print the rule registry and exit.")
    p.add_argument("--print-taxonomy", action="store_true",
                   help="Print the label taxonomy and transition matrix "
                        "and exit.")
    return p


def _check(args, stdout: TextIO, stderr: TextIO) -> int:
    path = args.path
    as_json = args.json
    include_info = args.include_info
    disabled = set(args.disable or [])

    if not os.path.isfile(path):
        stderr.write(f"trustlabels: cannot read {path!r}\n")
        return 2

    try:
        doc = load(path)
    except json.JSONDecodeError as e:
        stderr.write(f"trustlabels: {path} is not valid JSON "
                     f"({e.msg} at line {e.lineno} col {e.colno})\n")
        return 2
    except (UnicodeDecodeError, OSError) as e:
        # Binary or non-UTF-8 input is unreadable input: exit 2 with a message, never a traceback.
        stderr.write(f"trustlabels: cannot read {path!r} as UTF-8 JSON ({e.__class__.__name__})\n")
        return 2

    structural_errors = []
    try:
        validate(doc)
    except ValidationError as e:
        structural_errors = list(e.errors)

    result = scan(doc)

    filtered = []
    for f in result.findings:
        if f.rule_id in disabled:
            continue
        if f.severity == Severity.INFO and not include_info:
            continue
        filtered.append(f)

    if as_json:
        report = {
            "path": path,
            "version": __version__,
            "structural_errors": [
                {"pointer": ptr, "message": msg}
                for ptr, msg in structural_errors
            ],
            "findings": [f.to_dict() for f in filtered],
            "verdict": _verdict_name(filtered, structural_errors),
        }
        stdout.write(json.dumps(report, indent=2, sort_keys=True) + "\n")
    else:
        _write_text_report(path, structural_errors, filtered, stdout)

    if structural_errors:
        return 2
    if any(f.severity == Severity.HIGH for f in filtered):
        return 2
    if filtered:
        return 1
    return 0


def _print_rules(stdout: TextIO) -> int:
    for r in ALL_RULES:
        stdout.write(f"{r.id}  [{r.severity.value}]  {r.title}\n")
    return 0


def _print_taxonomy(stdout: TextIO) -> int:
    stdout.write("labels:\n")
    for label in sorted(KNOWN_LABELS):
        stdout.write(f"  {label}\n")
    stdout.write("transitions:\n")
    for current in sorted(TRANSITIONS):
        for target in sorted(TRANSITIONS[current]):
            gates = sorted(GATES.get((current, target), set()))
            stdout.write(
                f"  {current} -> {target}  gates: {gates}\n"
            )
    return 0


def _verdict_name(findings, structural_errors) -> str:
    if structural_errors:
        return Verdict.UNHEALTHY.value
    hi = any(f.severity == Severity.HIGH for f in findings)
    med = any(f.severity == Severity.MEDIUM for f in findings)
    low = any(f.severity == Severity.LOW for f in findings)
    if hi:
        return Verdict.UNHEALTHY.value
    if med or low:
        return Verdict.NEEDS_ATTENTION.value
    return Verdict.HEALTHY.value


def _write_text_report(path, structural_errors, findings, stdout) -> None:
    stdout.write(f"trustlabels {__version__}\n")
    stdout.write(f"path: {ascii_safe(path)}\n")

    if structural_errors:
        stdout.write(f"structural errors: {len(structural_errors)}\n")
        for ptr, msg in structural_errors:
            stdout.write(f"  {ascii_safe(ptr)}: {ascii_safe(msg)}\n")
    else:
        stdout.write("structural errors: 0\n")

    stdout.write(f"findings: {len(findings)}\n")
    for f in findings:
        where = f" @ {ascii_safe(f.where)}" if f.where else ""
        stdout.write(
            f"  {f.rule_id}  [{f.severity.value}]"
            f"{where}: {ascii_safe(f.message)}\n"
        )

    verdict = _verdict_name(findings, structural_errors)
    stdout.write(f"verdict: {verdict}\n")
