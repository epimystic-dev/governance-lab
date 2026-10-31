"""CLI contract tests for rungtag."""

from __future__ import annotations

import json
import os
import subprocess
import sys
import unittest

from tests import support  # noqa: F401
from tests.support import healthy_text, run_cli, write_temp


PKG_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


class UnknownFlag(unittest.TestCase):
    def test_unknown_flag_rc2(self):
        rc, _, _ = run_cli(["--definitely-not-a-flag"])
        self.assertEqual(rc, 2)


class ReturnCodes(unittest.TestCase):
    def test_rc0_on_healthy(self):
        d, p = write_temp(healthy_text())
        rc, out, err = run_cli([p])
        self.assertEqual(rc, 0, err)
        self.assertIn("verdict: healthy", out)

    def test_rc2_on_substantive_untagged(self):
        text = "## block\n" + ("word " * 100)
        d, p = write_temp(text)
        rc, out, _ = run_cli([p])
        self.assertEqual(rc, 2)
        self.assertIn("RT-001", out)

    def test_rc1_on_only_low_or_medium(self):
        text = (
            "## block\n"
            "tag: (reasoning)\n"
            "tag: (normal)\n"
            "\n"
            + ("content so RT-001 does not fire. " * 20)
        )
        d, p = write_temp(text)
        rc, out, _ = run_cli([p])
        # RT-006 is LOW; the only HIGH-worthy rules are RT-001 and
        # RT-002, neither of which should fire here.
        self.assertEqual(rc, 1)
        self.assertIn("RT-006", out)

    def test_rc2_on_missing_path(self):
        rc, _, err = run_cli(["./definitely-not-a-path.md"])
        self.assertEqual(rc, 2)


class JsonMode(unittest.TestCase):
    def test_json_report_parses(self):
        d, p = write_temp(healthy_text())
        rc, out, _ = run_cli([p, "--json"])
        self.assertEqual(rc, 0)
        report = json.loads(out)
        self.assertEqual(report["verdict"], "healthy")
        self.assertEqual(report["findings"], [])


class DisableFlag(unittest.TestCase):
    def test_disable_suppresses_rule(self):
        text = (
            "## block\n"
            + ("word " * 100)
        )
        d, p = write_temp(text)
        rc, out, _ = run_cli([p, "--disable", "RT-001"])
        self.assertEqual(rc, 0, out)
        self.assertNotIn("RT-001", out)


class PrintRules(unittest.TestCase):
    def test_print_rules_rc0(self):
        rc, out, _ = run_cli(["--print-rules"])
        self.assertEqual(rc, 0)
        self.assertIn("RT-001", out)


class ThresholdFlags(unittest.TestCase):
    def test_substantive_threshold_tuning(self):
        text = (
            "## block\n"
            + "word " * 10
        )
        d, p = write_temp(text)
        # Default: 10 words < 40 -> no RT-001.
        rc, _, _ = run_cli([p])
        self.assertEqual(rc, 0)
        # With --substantive 5: 10 words >= 5 -> RT-001 fires.
        rc, out, _ = run_cli([p, "--substantive", "5"])
        self.assertEqual(rc, 2)
        self.assertIn("RT-001", out)


class AsciiSafeReport(unittest.TestCase):
    """A tool that scans text streams must handle non-ASCII without
    crashing or hiding the characters. The text report renders raw
    non-ASCII as <U+XXXX>.
    """

    def test_report_renders_non_ascii_safely(self):
        env = os.environ.copy()
        env["PYTHONPATH"] = PKG_DIR + os.pathsep + env.get("PYTHONPATH", "")
        env["PYTHONIOENCODING"] = "cp1252"

        # Zero-width space inside a tag value - exactly the hidden-
        # character case this tool must report, not re-hide.
        hidden_tag = "(reasoning" + chr(0x200B) + ")"
        text = (
            "## block\n"
            f"tag: {hidden_tag}\n"
            "\n"
            "short.\n"
        )
        d, p = write_temp(text)
        r = subprocess.run(
            [sys.executable, "-m", "rungtag", p],
            capture_output=True, env=env, timeout=30,
        )
        # Any finding we flagged must not have crashed the reporter.
        self.assertNotIn(b"Traceback", r.stderr,
                         r.stderr.decode("ascii", "replace"))
        text_out = r.stdout.decode("ascii", "replace")
        # RT-008 or RT-003 should fire for the hidden-char tag; the
        # text report should contain <U+200B> somewhere.
        self.assertIn("<U+200B>", text_out)


if __name__ == "__main__":  # pragma: no cover
    unittest.main()
