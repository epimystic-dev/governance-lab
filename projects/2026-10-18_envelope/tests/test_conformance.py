"""Conformance tests over shipped examples.

The spec kind requires valid and invalid conformance examples the
tests actually run - these tests execute the shipped examples through
the validator so a regression there trips first.
"""

from __future__ import annotations

import json
import os
import unittest

from envelope import ValidationError, scan, validate


PROJECT_ROOT = os.path.abspath(
    os.path.join(os.path.dirname(__file__), "..")
)
EXAMPLES = os.path.join(PROJECT_ROOT, "examples")
SCHEMA_DIR = os.path.join(PROJECT_ROOT, "schema")


def _load(name):
    with open(os.path.join(EXAMPLES, name), "r", encoding="utf-8") as f:
        return json.load(f)


class HealthyExampleIsClean(unittest.TestCase):
    def test_structural(self):
        validate(_load("healthy_envelope.json"))

    def test_rules_zero(self):
        res = scan(_load("healthy_envelope.json"))
        self.assertEqual(res.findings, [])


class WeakExampleIsNotStructurallyInvalid(unittest.TestCase):
    def test_passes_shape(self):
        validate(_load("weak_envelope.json"))

    def test_fires_env_001(self):
        res = scan(_load("weak_envelope.json"))
        ids = tuple(f.rule_id for f in res.findings)
        self.assertIn("ENV-001", ids)
        self.assertIn("ENV-002", ids)

    def test_fires_env_009(self):
        res = scan(_load("weak_envelope.json"))
        ids = tuple(f.rule_id for f in res.findings)
        self.assertIn("ENV-009", ids)


class InvalidExampleFailsStructural(unittest.TestCase):
    def test_structural_raises(self):
        with self.assertRaises(ValidationError):
            validate(_load("invalid_envelope.json"))


class SchemaFileMatchesInMemorySchema(unittest.TestCase):
    def test_schema_file_parseable(self):
        path = os.path.join(SCHEMA_DIR, "envelope-v0.1.0.json")
        self.assertTrue(os.path.isfile(path), path)
        with open(path, "r", encoding="utf-8") as f:
            doc = json.load(f)
        self.assertEqual(doc["title"], "Worker Output Envelope")
        for req in ("envelope_version", "task_id", "status",
                    "scope", "findings", "evidence",
                    "reasoning_tag", "self_audit", "timestamp"):
            self.assertIn(req, doc["required"])


if __name__ == "__main__":  # pragma: no cover
    unittest.main()
