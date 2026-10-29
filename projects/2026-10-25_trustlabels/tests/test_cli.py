"""CLI contract tests for trustlabels.

Exercises the subprocess entry (``python -m trustlabels``) through
in-process invocation plus the real subprocess, as the lab's shared
contract requires.
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
import unittest

from tests import support  # noqa: F401
from tests.support import healthy, run_cli, write_temp

import trustlabels


PKG_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


class HelpAndVersion(unittest.TestCase):
    """help / version argparse-exit paths are covered by
    test_shared_contract.SharedContractInvariants via subprocess
    (argparse writes to real sys.stdout, not the captured one).
    Only the unknown-flag path is portable in-process.
    """

    def test_unknown_flag_rc2(self):
        rc, _, _ = run_cli(["--definitely-not-a-flag"])
        self.assertEqual(rc, 2)


class ReturnCodes(unittest.TestCase):
    def test_rc0_on_healthy_bundle(self):
        d, p = write_temp(healthy())
        rc, out, err = run_cli([p])
        self.assertEqual(rc, 0, err)
        self.assertIn("verdict: healthy", out)

    def test_rc2_on_quarantined_grounds(self):
        bad = {
            "entries": [{
                "id": "x",
                "trust_label": "quarantined:web",
                "source_ref": "https://example.com/x",
                "grounds_for_action": True,
                "entered_at": "2026-10-25T09:00:00Z",
            }]
        }
        d, p = write_temp(bad)
        rc, out, _ = run_cli([p])
        self.assertEqual(rc, 2)
        self.assertIn("TL-001", out)

    def test_rc1_on_only_medium_or_low(self):
        bad = {
            "entries": [{
                "id": "x",
                "trust_label": "quarantined:web",
                "source_ref": "https://example.com/x",
                "grounds_for_action": False,
                "entered_at": "yesterday",
            }]
        }
        d, p = write_temp(bad)
        rc, out, _ = run_cli([p])
        self.assertEqual(rc, 1)
        self.assertIn("TL-006", out)

    def test_rc2_on_missing_path(self):
        rc, _, err = run_cli(["./definitely-not-a-path.json"])
        self.assertEqual(rc, 2)
        self.assertIn("cannot read", err)

    def test_rc2_on_invalid_json(self):
        d, p = write_temp(healthy())
        with open(p, "w", encoding="utf-8") as f:
            f.write("{not valid json")
        rc, _, err = run_cli([p])
        self.assertEqual(rc, 2)
        self.assertIn("not valid JSON", err)


class JsonMode(unittest.TestCase):
    def test_json_report_parses(self):
        d, p = write_temp(healthy())
        rc, out, _ = run_cli([p, "--json"])
        self.assertEqual(rc, 0)
        report = json.loads(out)
        self.assertEqual(report["verdict"], "healthy")
        self.assertEqual(report["findings"], [])
        self.assertEqual(report["path"], p)

    def test_json_report_on_dirty_parses(self):
        bad = {
            "entries": [{
                "id": "x",
                "trust_label": "quarantined:web",
                "source_ref": "https://example.com/x",
                "grounds_for_action": True,
                "entered_at": "2026-10-25T09:00:00Z",
            }]
        }
        d, p = write_temp(bad)
        rc, out, _ = run_cli([p, "--json"])
        self.assertEqual(rc, 2)
        report = json.loads(out)
        self.assertEqual(report["verdict"], "unhealthy")
        rule_ids = [f["rule_id"] for f in report["findings"]]
        self.assertIn("TL-001", rule_ids)


class DisableFlag(unittest.TestCase):
    def test_disable_suppresses_rule(self):
        bad = {
            "entries": [{
                "id": "x",
                "trust_label": "quarantined:web",
                "source_ref": "https://example.com/x",
                "grounds_for_action": True,
                "entered_at": "2026-10-25T09:00:00Z",
            }]
        }
        d, p = write_temp(bad)
        rc, out, _ = run_cli([p, "--disable", "TL-001"])
        # TL-001 was the only HIGH defect; disabling it leaves only the
        # TL-008 that may fire on the sibling entries. Here grounds_for_action
        # is declared, so the result should be clean.
        self.assertEqual(rc, 0, out)
        self.assertNotIn("TL-001", out)


class PrintTaxonomy(unittest.TestCase):
    def test_print_taxonomy_rc0(self):
        rc, out, _ = run_cli(["--print-taxonomy"])
        self.assertEqual(rc, 0)
        self.assertIn("quarantined:web", out)
        self.assertIn("trusted:audited", out)
        self.assertIn("reviewer", out)

    def test_print_rules_rc0(self):
        rc, out, _ = run_cli(["--print-rules"])
        self.assertEqual(rc, 0)
        self.assertIn("TL-001", out)


class AsciiSafeReport(unittest.TestCase):
    """A tool that scans content provenance should NEVER crash on
    non-ASCII characters inside the content it reports. The text
    report must render non-ASCII as <U+XXXX>.
    """

    def test_report_renders_non_ascii_safely(self):
        env = os.environ.copy()
        env["PYTHONPATH"] = PKG_DIR + os.pathsep + env.get("PYTHONPATH", "")
        env["PYTHONIOENCODING"] = "cp1252"

        # Zero-width space in the entry id - a hidden character of
        # exactly the kind an injection-watching tool must handle.
        # The character is assembled from an escape so no raw non-ASCII
        # lives in the source file.
        hidden = "web/doc" + chr(0x200B) + "-1"
        bad = {
            "entries": [{
                "id": hidden,
                "trust_label": "quarantined:web",
                "source_ref": "https://example.com/x",
                "grounds_for_action": True,
                "entered_at": "2026-10-25T09:00:00Z",
            }]
        }
        d, p = write_temp(bad)
        r = subprocess.run(
            [sys.executable, "-m", "trustlabels", p],
            capture_output=True, env=env, timeout=30,
        )
        self.assertEqual(r.returncode, 2, r.stderr.decode("ascii", "replace"))
        text = r.stdout.decode("ascii", "replace")
        self.assertIn("TL-001", text)
        self.assertIn("<U+200B>", text)
        self.assertNotIn("Traceback", r.stderr.decode("ascii", "replace"))


if __name__ == "__main__":  # pragma: no cover
    unittest.main()
