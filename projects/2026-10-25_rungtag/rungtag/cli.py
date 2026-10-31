"""CLI entry point for rungtag.

Conforms to the lab's CLI contract:
- ``python -m rungtag PATH``       check a text stream
- ``--help``                        returns 0
- ``--version``                     returns 0
- An unknown flag                   returns 2
- Results on stdout, diagnostics on stderr
- Return codes: 0 clean; 1 non-blocking (LOW/MEDIUM); 2 any HIGH
"""

from __future__ import annotations

import argparse
import json
import os
import sys
from typing import List, Optional, TextIO

from . import __version__
from .io_utils import load
from .rules import ALL_RULES, DEFAULT_SUBSTANTIVE, DEFAULT_TRIVIAL, scan
from .types import Severity, Verdict, ascii_safe


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

    if args.path is None:
        stderr.write("rungtag: no input path given; "
                     "run `rungtag --help`\n")
        return 2

    return _check(args, stdout, stderr)


def _parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="rungtag",
        description=(
            "Reasoning-depth-tag linter: presence and consistency "
            "checks over text streams."),
    )
    p.add_argument("--version", action="version",
                   version=f"rungtag {__version__}")
    p.add_argument("path", nargs="?", default=None,
                   help="Path to a text or markdown file.")
    p.add_argument("--json", action="store_true",
                   help="Emit a JSON report on stdout.")
    p.add_argument("--strict", action="store_true",
                   help="Any finding returns rc >= 1 (default behavior).")
    p.add_argument("--include-info", action="store_true",
                   help="Include INFO-severity findings in report.")
    p.add_argument("--disable", action="append", default=[],
                   metavar="RULE",
                   help="Rule id to disable (may repeat).")
    p.add_argument("--substantive", type=int, default=DEFAULT_SUBSTANTIVE,
                   metavar="N",
                   help=f"Word count above which a block is considered "
                        f"substantive (default {DEFAULT_SUBSTANTIVE}).")
    p.add_argument("--trivial", type=int, default=DEFAULT_TRIVIAL,
                   metavar="N",
                   help=f"Word count below which a reasoning/iterated "
                        f"tag is an overclaim (default {DEFAULT_TRIVIAL}).")
    p.add_argument("--print-rules", action="store_true",
                   help="Print the rule registry and exit.")
    return p


def _check(args, stdout: TextIO, stderr: TextIO) -> int:
    path = args.path
    as_json = args.json
    include_info = args.include_info
    disabled = set(args.disable or [])

    if not os.path.isfile(path):
        stderr.write(f"rungtag: cannot read {path!r}\n")
        return 2

    try:
        text = load(path)
    except UnicodeDecodeError as e:
        stderr.write(f"rungtag: {path} is not valid UTF-8 ({e.reason})\n")
        return 2

    result = scan(text, substantive=args.substantive, trivial=args.trivial)

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
            "findings": [f.to_dict() for f in filtered],
            "verdict": _verdict_name(filtered),
        }
        stdout.write(json.dumps(report, indent=2, sort_keys=True) + "\n")
    else:
        _write_text_report(path, filtered, stdout)

    if any(f.severity == Severity.HIGH for f in filtered):
        return 2
    if filtered:
        return 1
    return 0


def _print_rules(stdout: TextIO) -> int:
    for r in ALL_RULES:
        stdout.write(f"{r.id}  [{r.severity.value}]  {r.title}\n")
    return 0


def _verdict_name(findings) -> str:
    hi = any(f.severity == Severity.HIGH for f in findings)
    med = any(f.severity == Severity.MEDIUM for f in findings)
    low = any(f.severity == Severity.LOW for f in findings)
    if hi:
        return Verdict.UNHEALTHY.value
    if med or low:
        return Verdict.NEEDS_ATTENTION.value
    return Verdict.HEALTHY.value


def _write_text_report(path, findings, stdout) -> None:
    stdout.write(f"rungtag {__version__}\n")
    stdout.write(f"path: {ascii_safe(path)}\n")
    stdout.write(f"findings: {len(findings)}\n")
    for f in findings:
        where = f" @ {ascii_safe(f.where)}" if f.where else ""
        stdout.write(
            f"  {f.rule_id}  [{f.severity.value}]"
            f"{where}: {ascii_safe(f.message)}\n"
        )
    stdout.write(f"verdict: {_verdict_name(findings)}\n")
