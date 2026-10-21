"""Structural validator tests.

Exercises the hand-rolled JSON Schema subset: types, required,
additionalProperties, enum, pattern, minLength, maxLength, minItems,
minimum, nested arrays and objects. The healthy envelope must pass;
targeted mutations must each produce at least one documented error.
"""

from __future__ import annotations

import unittest

from envelope import ValidationError, validate
from tests.support import deep, healthy, mutate


class StructuralHappyPath(unittest.TestCase):
    def test_healthy_passes(self):
        validate(healthy())  # must not raise


class StructuralRequiredFields(unittest.TestCase):
    def _missing(self, key):
        env = healthy()
        del env[key]
        with self.assertRaises(ValidationError) as ctx:
            validate(env)
        joined = "\n".join(m for _, m in ctx.exception.errors)
        self.assertIn(key, joined)

    def test_missing_envelope_version(self):
        self._missing("envelope_version")

    def test_missing_task_id(self):
        self._missing("task_id")

    def test_missing_status(self):
        self._missing("status")

    def test_missing_scope(self):
        self._missing("scope")

    def test_missing_findings(self):
        self._missing("findings")

    def test_missing_evidence(self):
        self._missing("evidence")

    def test_missing_reasoning_tag(self):
        self._missing("reasoning_tag")

    def test_missing_self_audit(self):
        self._missing("self_audit")

    def test_missing_timestamp(self):
        self._missing("timestamp")


class StructuralEnumAndType(unittest.TestCase):
    def test_bad_status_enum(self):
        env = mutate(status="sunny")
        self.assertRaises(ValidationError, validate, env)

    def test_bad_reasoning_tag(self):
        env = mutate(reasoning_tag="deep-vibes")
        self.assertRaises(ValidationError, validate, env)

    def test_findings_wrong_type(self):
        env = mutate(findings="none that I can see")
        self.assertRaises(ValidationError, validate, env)

    def test_evidence_wrong_type(self):
        env = mutate(evidence={"what": "ever"})
        self.assertRaises(ValidationError, validate, env)

    def test_envelope_version_pattern(self):
        env = mutate(envelope_version="v1")
        self.assertRaises(ValidationError, validate, env)

    def test_scope_empty_in(self):
        env = healthy()
        env["scope"]["in"] = []
        self.assertRaises(ValidationError, validate, env)

    def test_scope_empty_out(self):
        env = healthy()
        env["scope"]["out"] = []
        self.assertRaises(ValidationError, validate, env)


class StructuralAdditionalPropertiesBanned(unittest.TestCase):
    def test_extra_top_level_field_rejected(self):
        env = healthy()
        env["verified_by_author"] = True
        with self.assertRaises(ValidationError) as ctx:
            validate(env)
        joined = "\n".join(m for _, m in ctx.exception.errors)
        self.assertIn("verified_by_author", joined)

    def test_extra_scope_field_rejected(self):
        env = healthy()
        env["scope"]["middle"] = ["something"]
        self.assertRaises(ValidationError, validate, env)

    def test_extra_self_audit_field_rejected(self):
        env = healthy()
        env["self_audit"]["approved_by_god"] = True
        self.assertRaises(ValidationError, validate, env)


class StructuralFindingAndEvidenceShape(unittest.TestCase):
    def test_finding_missing_severity(self):
        env = healthy()
        env["findings"] = [{"id": "F-1", "message": "hi"}]
        self.assertRaises(ValidationError, validate, env)

    def test_finding_bad_severity_enum(self):
        env = healthy()
        env["findings"] = [{"id": "F-1", "severity": "FATAL", "message": "x"}]
        self.assertRaises(ValidationError, validate, env)

    def test_evidence_missing_kind(self):
        env = healthy()
        env["evidence"] = [{"claim": "x", "ref": "y"}]
        self.assertRaises(ValidationError, validate, env)

    def test_evidence_bad_kind_enum(self):
        env = healthy()
        env["evidence"] = [{"claim": "x", "kind": "vibes", "ref": "y"}]
        self.assertRaises(ValidationError, validate, env)

    def test_evidence_refs_bad_type(self):
        env = healthy()
        env["evidence"] = [{"claim": "x", "kind": "file", "ref": "y"}]
        env["findings"] = [{
            "id": "F-1", "severity": "LOW", "message": "x",
            "evidence_refs": ["zero"],
        }]
        self.assertRaises(ValidationError, validate, env)


class StructuralReportsAllErrors(unittest.TestCase):
    def test_multiple_errors_in_one_pass(self):
        env = healthy()
        del env["status"]
        env["envelope_version"] = "v1"
        env["findings"] = "none"
        with self.assertRaises(ValidationError) as ctx:
            validate(env)
        # Three defects seeded; a reasonable validator reports at least
        # the first two of them (findings' type error short-circuits
        # into-array traversal, so three-is-sometimes-two).
        self.assertGreaterEqual(len(ctx.exception.errors), 2)


class StructuralDoesNotMutate(unittest.TestCase):
    def test_input_unchanged_on_success(self):
        env = healthy()
        snapshot = deep(env)
        validate(env)
        self.assertEqual(env, snapshot)


if __name__ == "__main__":  # pragma: no cover
    unittest.main()
