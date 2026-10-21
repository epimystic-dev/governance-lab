"""CLI behavioural tests.

Covers in-process rc / stdout / stderr contract. The subprocess
contract (--help, --version, unknown flag) lives in
test_shared_contract.py.
"""

from __future__ import annotations

import json
import os
import unittest

from envelope import __version__
from tests.support import healthy, run_cli, write_temp


class HealthyPathReturnsZero(unittest.TestCase):
    def test_healthy_rc_zero(self):
        _, p = write_temp(healthy())
        rc, out, err = run_cli([p])
        self.assertEqual(rc, 0, (out, err))
        self.assertIn("verdict: healthy", out)


class WeakPathReturnsTwo(unittest.TestCase):
    def test_weak_rc_two(self):
        env = healthy()
        env["self_audit"]["checker_run"] = False  # ENV-001 HIGH
        del env["self_audit"]["checker_role"]
        env["reasoning_tag"] = "iterated"  # ENV-002 HIGH
        _, p = write_temp(env)
        rc, out, err = run_cli([p])
        self.assertEqual(rc, 2, (out, err))
        self.assertIn("ENV-001", out)


class MediumOnlyReturnsOne(unittest.TestCase):
    def test_medium_only_rc_one(self):
        env = healthy()
        env["timestamp"] = "yesterday afternoon"  # ENV-009 MEDIUM
        _, p = write_temp(env)
        rc, out, err = run_cli([p])
        self.assertEqual(rc, 1, (out, err))
        self.assertIn("ENV-009", out)


class JsonOutput(unittest.TestCase):
    def test_json_output_parses(self):
        _, p = write_temp(healthy())
        rc, out, err = run_cli([p, "--json"])
        self.assertEqual(rc, 0)
        report = json.loads(out)
        self.assertEqual(report["version"], __version__)
        self.assertEqual(report["verdict"], "healthy")
        self.assertEqual(report["findings"], [])


class DisableFlag(unittest.TestCase):
    def test_disable_removes_rule(self):
        env = healthy()
        env["timestamp"] = "yesterday afternoon"
        _, p = write_temp(env)
        rc, out, _ = run_cli([p, "--disable", "ENV-009"])
        self.assertEqual(rc, 0, out)
        self.assertNotIn("ENV-009", out)


class StructuralFailureReturnsTwo(unittest.TestCase):
    def test_bad_shape_rc_two(self):
        env = healthy()
        env["status"] = "sunny"
        _, p = write_temp(env)
        rc, out, err = run_cli([p])
        self.assertEqual(rc, 2, (out, err))
        self.assertIn("structural errors", out)


class UnreadableInput(unittest.TestCase):
    def test_missing_file_rc_two(self):
        rc, out, err = run_cli(["/no/such/path/does/not/exist.json"])
        self.assertEqual(rc, 2)
        self.assertIn("cannot read", err)

    def test_non_json_file_rc_two(self):
        _, p = write_temp(healthy(), name="env.json")
        # overwrite with garbage
        with open(p, "w", encoding="utf-8") as f:
            f.write("{not valid json")
        rc, out, err = run_cli([p])
        self.assertEqual(rc, 2)
        self.assertIn("not valid JSON", err)


class PrintModes(unittest.TestCase):
    def test_print_rules(self):
        rc, out, err = run_cli(["--print-rules"])
        self.assertEqual(rc, 0)
        self.assertIn("ENV-001", out)
        self.assertIn("ENV-012", out)

    def test_print_schema(self):
        rc, out, err = run_cli(["--print-schema"])
        self.assertEqual(rc, 0)
        doc = json.loads(out)
        self.assertEqual(doc.get("title"), "Worker Output Envelope")


class NoArgsIsError(unittest.TestCase):
    def test_no_args_rc_two(self):
        rc, out, err = run_cli([])
        self.assertEqual(rc, 2)
        self.assertIn("no envelope path given", err)


class AsciiSafeReport(unittest.TestCase):
    def test_non_ascii_in_message_rendered_as_codepoint(self):
        # Inject a non-ASCII char into a weak envelope's message so
        # the text report must render it. We assemble the codepoint
        # at runtime to keep source ASCII.
        zwsp = chr(0x200B)
        env = healthy()
        env["self_audit"]["checker_run"] = False
        del env["self_audit"]["checker_role"]
        env["reasoning_tag"] = "iterated"
        env["findings"] = [{
            "id": "F-" + zwsp + "1",
            "severity": "HIGH",
            "message": "boom" + zwsp,
        }]
        _, p = write_temp(env)
        # Running the CLI will not actually include finding messages in
        # the text report (the report lists our rule messages). The
        # path echo is a stronger place to test ASCII-safety; make the
        # filename itself contain the character.
        d = os.path.dirname(p)
        new_p = os.path.join(d, "env" + zwsp + ".json")
        os.rename(p, new_p)
        rc, out, err = run_cli([new_p])
        self.assertIn("<U+200B>", out)


if __name__ == "__main__":  # pragma: no cover
    unittest.main()
