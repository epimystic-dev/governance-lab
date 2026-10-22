"""Shared contract tests for auditledger.

Locks the package surface, the ENV-free rule-id convention (AL-*),
and the CLI contract against the subprocess entry.
"""

from __future__ import annotations

import os
import re
import subprocess
import sys
import unittest

from tests import support  # noqa: F401

import auditledger
from auditledger.cli import main
from auditledger.rules import ALL_RULES


PKG_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
EXAMPLES = os.path.join(PKG_DIR, "examples")
README = os.path.join(PKG_DIR, "README.md")


def _run(*args: str) -> subprocess.CompletedProcess:
    env = os.environ.copy()
    env["PYTHONPATH"] = PKG_DIR + os.pathsep + env.get("PYTHONPATH", "")
    return subprocess.run(
        [sys.executable, "-m", "auditledger", *args],
        capture_output=True,
        text=True,
        env=env,
        timeout=30,
    )


class PackageSurface(unittest.TestCase):
    def test_version(self):
        self.assertRegex(auditledger.__version__, r"^\d+\.\d+\.\d+$")

    def test_exports_present(self):
        for name in (
                "Severity", "Verdict", "Finding", "ScanResult",
                "Rule", "ALL_RULES", "Entry", "LedgerError",
                "Ledger", "append", "verify", "digest", "head",
                "init", "canonical_bytes"):
            self.assertTrue(hasattr(auditledger, name), name)

    def test_all_rules_is_list_of_rule_objects(self):
        self.assertIsInstance(auditledger.ALL_RULES, list)
        self.assertTrue(auditledger.ALL_RULES)
        for r in auditledger.ALL_RULES:
            self.assertIsInstance(r, auditledger.Rule)
            self.assertTrue(r.id.startswith("AL-"))
            self.assertIsInstance(r.severity, auditledger.Severity)

    def test_rule_ids_unique(self):
        ids = [r.id for r in ALL_RULES]
        self.assertEqual(len(ids), len(set(ids)))

    def test_main_callable(self):
        self.assertTrue(callable(main))


class CliContract(unittest.TestCase):
    def test_help(self):
        r = _run("--help")
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertIn("auditledger", r.stdout)

    def test_version(self):
        r = _run("--version")
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertEqual(r.stdout.strip(),
                         "auditledger " + auditledger.__version__)

    def test_unknown_flag_rc_two(self):
        r = _run("--definitely-not-a-flag")
        self.assertEqual(r.returncode, 2)

    def test_no_command_rc_two(self):
        r = _run()
        self.assertEqual(r.returncode, 2)

    def test_known_clean_input_returns_zero(self):
        path = os.path.join(EXAMPLES, "healthy_ledger.jsonl")
        r = _run("verify", path)
        self.assertEqual(r.returncode, 0, r.stderr)

    def test_known_dirty_input_returns_nonzero(self):
        path = os.path.join(EXAMPLES, "tampered_ledger.jsonl")
        r = _run("verify", path)
        self.assertNotEqual(r.returncode, 0)
        # The tampered fixture mutates seq=1's payload without
        # recomputing its hash: AL-006 (hash mismatch) fires.
        self.assertIn("AL-006", r.stdout + r.stderr)


class ReadmeDocumentsEveryRule(unittest.TestCase):
    def test_every_rule_in_readme(self):
        self.assertTrue(os.path.isfile(README))
        with open(README, "r", encoding="utf-8") as f:
            text = f.read()
        missing = [r.id for r in ALL_RULES
                   if not re.search(r"\b" + re.escape(r.id) + r"\b", text)]
        self.assertFalse(missing, missing)


if __name__ == "__main__":  # pragma: no cover
    unittest.main()
