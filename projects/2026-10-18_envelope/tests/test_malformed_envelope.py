"""The validator must report a malformed envelope, never crash on one.

The project's own invalid example gives `findings` as a string. The structural
validator flags it, then the cross-field rules run on the same document; before
the fix they raised AttributeError and the user got a traceback instead of the
structural report. Every wrong-typed container is probed here through the real
CLI: each must exit 2 (structural failure) with no traceback.
"""

from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
import tempfile
import unittest

PKG_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
EXAMPLES = os.path.join(PKG_DIR, "examples")


def _run(path):
    env = os.environ.copy()
    env["PYTHONPATH"] = PKG_DIR + os.pathsep + env.get("PYTHONPATH", "")
    return subprocess.run([sys.executable, "-m", "envelope", path],
                          capture_output=True, text=True, env=env, timeout=30)


def _base():
    with open(os.path.join(EXAMPLES, "healthy_envelope.json"), encoding="utf-8") as fh:
        return json.load(fh)


class MalformedEnvelopeTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="env_malformed_")

    def tearDown(self):
        shutil.rmtree(self.tmp, ignore_errors=True)

    def _check(self, doc, label):
        p = os.path.join(self.tmp, label + ".json")
        with open(p, "w", encoding="utf-8") as fh:
            json.dump(doc, fh)
        r = _run(p)
        self.assertNotIn("Traceback", r.stderr, label + " crashed:\n" + r.stderr)
        self.assertEqual(r.returncode, 2, label + ": expected rc 2, got %d" % r.returncode)

    def test_shipped_invalid_example_is_reported_not_crashed(self):
        r = _run(os.path.join(EXAMPLES, "invalid_envelope.json"))
        self.assertNotIn("Traceback", r.stderr, r.stderr)
        self.assertEqual(r.returncode, 2)

    def test_wrong_typed_containers(self):
        cases = {
            "findings_string": ("findings", "none that I can see"),
            "findings_number": ("findings", 7),
            "findings_object": ("findings", {"severity": "HIGH"}),
            "findings_items_strings": ("findings", ["a", "b"]),
            "self_audit_list": ("self_audit", ["checker_run"]),
            "self_audit_string": ("self_audit", "ok"),
            "evidence_object": ("evidence", {"0": "x"}),
            "scope_string": ("scope", "everything"),
            "scope_in_string": ("scope", {"in": "all", "out": 3}),
            "reasons_string": ("self_audit", {"checker_run": True, "verdict": "ok", "reasons": "fine"}),
        }
        for label, (key, value) in cases.items():
            with self.subTest(label=label):
                doc = _base()
                doc[key] = value
                self._check(doc, label)

    def test_evidence_refs_not_a_list(self):
        doc = _base()
        doc["findings"] = [{"severity": "HIGH", "summary": "x", "evidence_refs": "0"}]
        self._check(doc, "evidence_refs_string")


if __name__ == "__main__":  # pragma: no cover
    unittest.main()
