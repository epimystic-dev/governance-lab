"""CLI for auditledger.

Lab CLI contract:
- ``python -m auditledger init    PATH``
- ``python -m auditledger append  PATH --kind K --payload JSON | --payload-file F``
- ``python -m auditledger verify  PATH [--json] [--disable AL-NNN]``
- ``python -m auditledger digest  PATH``
- ``python -m auditledger head    PATH``

Return codes:
- 0 clean / success
- 1 verify finds non-blocking defects (MEDIUM, LOW)
- 2 verify finds any HIGH defect, OR unreadable input, OR
      caller error on append / init
- ``--help`` returns 0; unknown flag returns 2; ``--version``
  returns 0.
"""

from __future__ import annotations

import argparse
import io
import json
import os
import sys
from typing import List, Optional, TextIO

from . import __version__
from .ledger import append, digest, head, init, verify
from .rules import ALL_RULES
from .types import LedgerError, Severity, Verdict, ascii_safe


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
        return int(e.code) if isinstance(e.code, int) else 2

    if getattr(args, "print_rules", False):
        return _print_rules(stdout)

    if args.command is None:
        stderr.write(
            "auditledger: no command given; "
            "try `auditledger --help`\n")
        return 2

    try:
        if args.command == "init":
            return _cmd_init(args, stdout, stderr)
        if args.command == "append":
            return _cmd_append(args, stdout, stderr)
        if args.command == "verify":
            return _cmd_verify(args, stdout, stderr)
        if args.command == "digest":
            return _cmd_digest(args, stdout, stderr)
        if args.command == "head":
            return _cmd_head(args, stdout, stderr)
    except LedgerError as e:
        stderr.write(f"auditledger: {ascii_safe(str(e))}\n")
        return 2

    # Unknown command (argparse would already have errored).
    stderr.write(f"auditledger: unknown command {args.command!r}\n")
    return 2


def _parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="auditledger",
        description=(
            "Append-only hash-chained JSONL ledger for agent audit "
            "trails."),
    )
    p.add_argument("--version", action="version",
                   version=f"auditledger {__version__}")
    p.add_argument("--print-rules", action="store_true",
                   help="Print the verify rule registry and exit.")
    sub = p.add_subparsers(dest="command")

    sp_init = sub.add_parser("init", help="Create an empty ledger.")
    sp_init.add_argument("path")

    sp_app = sub.add_parser("append", help="Append a row.")
    sp_app.add_argument("path")
    sp_app.add_argument("--kind", required=True,
                        help="User-defined row-kind tag.")
    group = sp_app.add_mutually_exclusive_group(required=True)
    group.add_argument("--payload",
                       help="Inline JSON payload.")
    group.add_argument("--payload-file",
                       help="Path to a JSON file holding the payload.")
    sp_app.add_argument("--ts",
                        help="Override the row timestamp "
                             "(RFC3339-shaped UTC).")
    sp_app.add_argument("--json", action="store_true",
                        help="Emit the written row as JSON on stdout.")

    sp_ver = sub.add_parser("verify",
                            help="Verify the chain and print findings.")
    sp_ver.add_argument("path")
    sp_ver.add_argument("--json", action="store_true",
                        help="Emit a JSON report on stdout.")
    sp_ver.add_argument("--disable", action="append", default=[],
                        metavar="RULE",
                        help="Rule id to disable (may repeat).")
    sp_ver.add_argument("--include-info", action="store_true",
                        help="Include INFO-severity findings.")

    sp_dig = sub.add_parser(
        "digest",
        help="Print the hex sha256 of the final row (HEAD).")
    sp_dig.add_argument("path")

    sp_hed = sub.add_parser("head",
                            help="Print the final row as JSON.")
    sp_hed.add_argument("path")

    return p


def _cmd_init(args, stdout, stderr) -> int:
    init(args.path)
    stdout.write(f"initialised empty ledger at {ascii_safe(args.path)}\n")
    return 0


def _cmd_append(args, stdout, stderr) -> int:
    if args.payload is not None:
        try:
            payload = json.loads(args.payload)
        except json.JSONDecodeError as e:
            stderr.write(
                f"auditledger: --payload is not valid JSON "
                f"({e.msg} at col {e.colno})\n")
            return 2
    else:
        if not os.path.isfile(args.payload_file):
            stderr.write(
                f"auditledger: payload file not found: "
                f"{args.payload_file!r}\n")
            return 2
        with open(args.payload_file, "r", encoding="utf-8") as f:
            try:
                payload = json.load(f)
            except json.JSONDecodeError as e:
                stderr.write(
                    f"auditledger: payload file is not valid JSON "
                    f"({e.msg})\n")
                return 2
    entry = append(args.path, args.kind, payload, ts=args.ts)
    if args.json:
        stdout.write(json.dumps(entry.to_dict(),
                                sort_keys=True) + "\n")
    else:
        stdout.write(
            f"appended seq={entry.seq} hash={entry.hash[:12]}...\n")
    return 0


def _cmd_verify(args, stdout, stderr) -> int:
    result = verify(args.path)
    disabled = set(args.disable or [])
    include_info = args.include_info

    findings = []
    for f in result.findings:
        if f.rule_id in disabled:
            continue
        if f.severity == Severity.INFO and not include_info:
            continue
        findings.append(f)

    if args.json:
        report = {
            "path": args.path,
            "version": __version__,
            "entries_checked": result.entries_checked,
            "head_hash": result.head_hash,
            "findings": [f.to_dict() for f in findings],
            "verdict": _verdict_name(findings).value,
        }
        stdout.write(json.dumps(report, indent=2, sort_keys=True) + "\n")
    else:
        _write_text_report(args.path, result, findings, stdout)

    if any(f.severity == Severity.HIGH for f in findings):
        return 2
    if findings:
        return 1
    return 0


def _cmd_digest(args, stdout, stderr) -> int:
    d = digest(args.path)
    if d is None:
        stdout.write("(empty ledger)\n")
    else:
        stdout.write(d + "\n")
    return 0


def _cmd_head(args, stdout, stderr) -> int:
    e = head(args.path)
    if e is None:
        stdout.write("(empty ledger)\n")
    else:
        stdout.write(json.dumps(e.to_dict(),
                                sort_keys=True, indent=2) + "\n")
    return 0


def _print_rules(stdout: TextIO) -> int:
    for r in ALL_RULES:
        stdout.write(
            f"{r.id}  [{r.severity.value}]  {r.title}\n"
        )
    return 0


def _verdict_name(findings) -> Verdict:
    hi = any(f.severity == Severity.HIGH for f in findings)
    med = any(f.severity == Severity.MEDIUM for f in findings)
    low = any(f.severity == Severity.LOW for f in findings)
    if hi:
        return Verdict.UNHEALTHY
    if med or low:
        return Verdict.NEEDS_ATTENTION
    return Verdict.HEALTHY


def _write_text_report(path, result, findings, stdout) -> None:
    stdout.write(f"auditledger {__version__}\n")
    stdout.write(f"path: {ascii_safe(path)}\n")
    stdout.write(f"entries checked: {result.entries_checked}\n")
    stdout.write(
        f"head hash: {result.head_hash or '(empty ledger)'}\n")
    stdout.write(f"findings: {len(findings)}\n")
    for f in findings:
        loc = []
        if f.seq is not None:
            loc.append(f"seq={f.seq}")
        if f.line_number is not None:
            loc.append(f"line={f.line_number}")
        locs = (" @ " + " ".join(loc)) if loc else ""
        stdout.write(
            f"  {f.rule_id}  [{f.severity.value}]"
            f"{locs}: {ascii_safe(f.message)}\n"
        )
    verdict = _verdict_name(findings).value
    stdout.write(f"verdict: {verdict}\n")
