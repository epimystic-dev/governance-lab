"""Shared contract tests for trustlabels.

Locks:
1. Package-surface invariants (``__version__``, ``Severity``,
   ``Verdict``, ``Finding``, ``ScanResult``, ``ALL_RULES``, ``Rule``,
   a callable ``main``), plus the TL-* rule-ID convention.
2. CLI-consumer invariants from governance-lab/docs/CONVENTIONS.md
   locked against the ``python -m trustlabels`` subprocess entry.
3. Every rule id in ALL_RULES is documented in the project README.
"""

from __future__ import annotations

import os
import re
import subprocess
import sys
import unittest

from tests import support  # noqa: F401 (import for tempdir redirect)

import trustlabels
from trustlabels.cli import main
from trustlabels.rules import ALL_RULES


PKG_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
EXAMPLES_DIR = os.path.join(PKG_DIR, "examples")
README_PATH = os.path.join(PKG_DIR, "README.md")


def _run(*args: str) -> subprocess.CompletedProcess:
    env = os.environ.copy()
    env["PYTHONPATH"] = PKG_DIR + os.pathsep + env.get("PYTHONPATH", "")
    return subprocess.run(
        [sys.executable, "-m", "trustlabels", *args],
        capture_output=True,
        text=True,
        env=env,
        timeout=30,
    )


class PackageSurfaceTests(unittest.TestCase):
    def test_version_str(self):
        self.assertIsInstance(trustlabels.__version__, str)
        self.assertRegex(trustlabels.__version__, r"^\d+\.\d+\.\d+$")

    def test_all_exports_present(self):
        for name in ("Severity", "Verdict", "Finding", "ScanResult",
                     "ALL_RULES", "Rule", "KNOWN_LABELS",
                     "TRANSITIONS", "GATES", "ValidationError",
                     "validate", "scan", "check", "load"):
            self.assertTrue(hasattr(trustlabels, name), name)

    def test_all_rules_is_list_of_rule_objects(self):
        self.assertIsInstance(trustlabels.ALL_RULES, list)
        self.assertTrue(trustlabels.ALL_RULES)
        for r in trustlabels.ALL_RULES:
            self.assertIsInstance(r, trustlabels.Rule)
            self.assertTrue(r.id.startswith("TL-"))
            self.assertIsInstance(r.severity, trustlabels.Severity)

    def test_cli_main_callable(self):
        self.assertTrue(callable(main))

    def test_rule_ids_are_unique(self):
        ids = [r.id for r in ALL_RULES]
        self.assertEqual(len(ids), len(set(ids)),
                         "duplicate rule id in registry")


class SharedContractInvariants(unittest.TestCase):
    def test_version_returns_zero(self):
        r = _run("--version")
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertEqual(r.stdout.strip(),
                         "trustlabels " + trustlabels.__version__)

    def test_help_returns_zero(self):
        r = _run("--help")
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertIn("trustlabels", r.stdout)

    def test_unknown_flag_returns_two(self):
        r = _run("--definitely-not-a-flag")
        self.assertEqual(r.returncode, 2)

    def test_known_clean_input_returns_zero(self):
        path = os.path.join(EXAMPLES_DIR, "healthy_bundle.json")
        self.assertTrue(os.path.isfile(path))
        r = _run(path)
        self.assertEqual(r.returncode, 0, r.stderr)

    def test_known_dirty_input_returns_nonzero(self):
        path = os.path.join(EXAMPLES_DIR, "invalid_bundle.json")
        self.assertTrue(os.path.isfile(path))
        r = _run(path)
        self.assertNotEqual(
            r.returncode, 0,
            "trustlabels exited 0 on a known-dirty input",
        )
        self.assertIn("TL-001", r.stdout)


class ReadmeDocumentsEveryRule(unittest.TestCase):
    def test_every_rule_appears_in_readme(self):
        self.assertTrue(os.path.isfile(README_PATH),
                        f"README missing: {README_PATH}")
        with open(README_PATH, "r", encoding="utf-8") as f:
            text = f.read()
        missing = []
        for r in ALL_RULES:
            if not re.search(r"\b" + re.escape(r.id) + r"\b", text):
                missing.append(r.id)
        self.assertFalse(
            missing,
            "the following rule ids are missing from README: "
            + ", ".join(missing),
        )


if __name__ == "__main__":  # pragma: no cover
    unittest.main()
