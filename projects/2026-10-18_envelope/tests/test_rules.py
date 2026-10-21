"""Cross-field rule tests.

Each rule has: a positive case where the rule fires on a seeded
defect; a negative case where it does not fire on the healthy
envelope; and (where the rule's trigger has internal structure)
boundary cases that distinguish adjacent defects.
"""

from __future__ import annotations

import unittest

from envelope import scan
from envelope.types import Severity, Verdict
from tests.support import deep, healthy, mutate, scan_rule_ids


class HealthyEnvelopeFiresNothing(unittest.TestCase):
    def test_healthy_has_zero_findings(self):
        result = scan(healthy())
        self.assertEqual(result.findings, [])
        self.assertEqual(result.verdict, Verdict.HEALTHY)


class ENV001_StatusOkRequiresCheckerRun(unittest.TestCase):
    def test_fires_when_ok_and_no_checker(self):
        env = healthy()
        env["self_audit"]["checker_run"] = False
        env["self_audit"]["checker_role"] = ""  # not needed when not run
        del env["self_audit"]["checker_role"]  # per schema shape
        env["reasoning_tag"] = "reasoning"  # avoid ENV-002
        self.assertIn("ENV-001", scan_rule_ids(env))

    def test_silent_when_ok_and_checker_ran(self):
        self.assertNotIn("ENV-001", scan_rule_ids(healthy()))

    def test_silent_when_partial_and_no_checker(self):
        env = healthy()
        env["status"] = "partial"
        env["self_audit"]["checker_run"] = False
        del env["self_audit"]["checker_role"]
        env["reasoning_tag"] = "reasoning"
        self.assertNotIn("ENV-001", scan_rule_ids(env))


class ENV002_IteratedRequiresCheckerRun(unittest.TestCase):
    def test_fires_on_iterated_without_checker(self):
        env = healthy()
        env["self_audit"]["checker_run"] = False
        del env["self_audit"]["checker_role"]
        env["status"] = "partial"  # avoid ENV-001
        env["reasoning_tag"] = "iterated"
        self.assertIn("ENV-002", scan_rule_ids(env))

    def test_fires_on_reasoning_iterated_without_checker(self):
        env = healthy()
        env["self_audit"]["checker_run"] = False
        del env["self_audit"]["checker_role"]
        env["status"] = "partial"
        env["reasoning_tag"] = "reasoning-iterated"
        self.assertIn("ENV-002", scan_rule_ids(env))

    def test_silent_on_reasoning_without_checker(self):
        env = healthy()
        env["self_audit"]["checker_run"] = False
        del env["self_audit"]["checker_role"]
        env["status"] = "partial"
        env["reasoning_tag"] = "reasoning"
        self.assertNotIn("ENV-002", scan_rule_ids(env))

    def test_silent_on_iterated_with_checker(self):
        env = healthy()
        env["reasoning_tag"] = "iterated"
        self.assertNotIn("ENV-002", scan_rule_ids(env))


class ENV003_HighFindingRequiresEvidence(unittest.TestCase):
    def test_fires_on_high_finding_with_empty_evidence(self):
        env = healthy()
        env["findings"] = [
            {"id": "F-1", "severity": "HIGH", "message": "boom"}
        ]
        env["evidence"] = []
        env["status"] = "partial"
        self.assertIn("ENV-003", scan_rule_ids(env))

    def test_silent_on_high_finding_with_evidence(self):
        env = healthy()
        env["findings"] = [
            {"id": "F-1", "severity": "HIGH", "message": "boom"}
        ]
        # healthy evidence array is non-empty
        env["status"] = "partial"
        self.assertNotIn("ENV-003", scan_rule_ids(env))

    def test_silent_without_high_findings(self):
        env = healthy()
        env["findings"] = []
        env["evidence"] = []
        self.assertNotIn("ENV-003", scan_rule_ids(env))


class ENV004_SelfAuditOkWithReasons(unittest.TestCase):
    def test_fires(self):
        env = healthy()
        env["self_audit"]["verdict"] = "ok"
        env["self_audit"]["reasons"] = ["minor nit"]
        self.assertIn("ENV-004", scan_rule_ids(env))

    def test_silent_on_ok_without_reasons(self):
        self.assertNotIn("ENV-004", scan_rule_ids(healthy()))

    def test_silent_on_unknown_with_reasons(self):
        env = healthy()
        env["self_audit"]["verdict"] = "unknown"
        env["self_audit"]["reasons"] = ["still checking"]
        self.assertNotIn("ENV-004", scan_rule_ids(env))


class ENV005_FailedRequiresFinding(unittest.TestCase):
    def test_fires_on_failed_with_no_findings(self):
        env = healthy()
        env["status"] = "failed"
        env["findings"] = []
        self.assertIn("ENV-005", scan_rule_ids(env))

    def test_silent_on_failed_with_medium_finding(self):
        env = healthy()
        env["status"] = "failed"
        env["findings"] = [
            {"id": "F-1", "severity": "MEDIUM", "message": "boom"}
        ]
        self.assertNotIn("ENV-005", scan_rule_ids(env))

    def test_silent_on_failed_with_only_low_findings(self):
        # LOW findings do NOT justify a failed status; the rule
        # should still fire.
        env = healthy()
        env["status"] = "failed"
        env["findings"] = [
            {"id": "F-1", "severity": "LOW", "message": "nit"}
        ]
        self.assertIn("ENV-005", scan_rule_ids(env))


class ENV006_ScopeMustBeNonEmpty(unittest.TestCase):
    def test_fires_on_empty_scope_in(self):
        env = healthy()
        env["scope"]["in"] = []
        self.assertIn("ENV-006", scan_rule_ids(env))

    def test_fires_on_empty_scope_out(self):
        env = healthy()
        env["scope"]["out"] = []
        self.assertIn("ENV-006", scan_rule_ids(env))


class ENV007_SelfAttestFieldsForbidden(unittest.TestCase):
    def test_fires_on_verified_by_author(self):
        env = healthy()
        env["verified_by_author"] = True  # bypass structural
        self.assertIn("ENV-007", scan_rule_ids(env))

    def test_fires_on_safe_to_merge(self):
        env = healthy()
        env["safe_to_merge"] = True
        self.assertIn("ENV-007", scan_rule_ids(env))

    def test_silent_on_healthy(self):
        self.assertNotIn("ENV-007", scan_rule_ids(healthy()))


class ENV008_MediumFindingNeedsEvidence(unittest.TestCase):
    def test_fires_on_medium_only_with_empty_evidence(self):
        env = healthy()
        env["findings"] = [
            {"id": "F-1", "severity": "MEDIUM", "message": "note"}
        ]
        env["evidence"] = []
        env["status"] = "partial"
        self.assertIn("ENV-008", scan_rule_ids(env))

    def test_silent_on_medium_with_evidence(self):
        env = healthy()
        env["findings"] = [
            {"id": "F-1", "severity": "MEDIUM", "message": "note"}
        ]
        env["status"] = "partial"
        self.assertNotIn("ENV-008", scan_rule_ids(env))


class ENV009_TimestampShape(unittest.TestCase):
    def test_fires_on_free_text_timestamp(self):
        env = healthy()
        env["timestamp"] = "yesterday afternoon"
        self.assertIn("ENV-009", scan_rule_ids(env))

    def test_silent_on_rfc3339_with_tz(self):
        env = healthy()
        env["timestamp"] = "2026-10-18T09:30:00+05:30"
        self.assertNotIn("ENV-009", scan_rule_ids(env))

    def test_silent_on_rfc3339_z(self):
        env = healthy()
        env["timestamp"] = "2026-10-18T09:30:00Z"
        self.assertNotIn("ENV-009", scan_rule_ids(env))

    def test_fires_without_timezone(self):
        env = healthy()
        env["timestamp"] = "2026-10-18T09:30:00"
        self.assertIn("ENV-009", scan_rule_ids(env))


class ENV010_CheckerRoleRequiredWhenCheckerRan(unittest.TestCase):
    def test_fires_when_role_absent(self):
        env = healthy()
        del env["self_audit"]["checker_role"]
        self.assertIn("ENV-010", scan_rule_ids(env))

    def test_silent_when_role_present(self):
        self.assertNotIn("ENV-010", scan_rule_ids(healthy()))

    def test_silent_when_checker_did_not_run(self):
        env = healthy()
        env["self_audit"]["checker_run"] = False
        del env["self_audit"]["checker_role"]
        env["status"] = "partial"
        env["reasoning_tag"] = "reasoning"
        self.assertNotIn("ENV-010", scan_rule_ids(env))


class ENV011_EvidenceRefsOutOfRange(unittest.TestCase):
    def test_fires_on_out_of_range_ref(self):
        env = healthy()
        env["findings"] = [{
            "id": "F-1", "severity": "LOW", "message": "x",
            "evidence_refs": [5],
        }]
        env["evidence"] = [
            {"claim": "x", "kind": "file", "ref": "y"}
        ]
        self.assertIn("ENV-011", scan_rule_ids(env))

    def test_silent_on_in_range_ref(self):
        env = healthy()
        env["findings"] = [{
            "id": "F-1", "severity": "LOW", "message": "x",
            "evidence_refs": [0],
        }]
        self.assertNotIn("ENV-011", scan_rule_ids(env))


class ENV012_UnknownEnvelopeVersion(unittest.TestCase):
    def test_fires_on_unknown_version(self):
        env = mutate(envelope_version="99.0.0")
        self.assertIn("ENV-012", scan_rule_ids(env))

    def test_silent_on_known_version(self):
        self.assertNotIn("ENV-012", scan_rule_ids(healthy()))


class VerdictRollup(unittest.TestCase):
    def test_healthy(self):
        self.assertEqual(scan(healthy()).verdict, Verdict.HEALTHY)

    def test_high_leads_to_unhealthy(self):
        env = healthy()
        env["findings"] = [
            {"id": "F-1", "severity": "HIGH", "message": "x"}
        ]
        env["evidence"] = []
        env["status"] = "partial"
        self.assertEqual(scan(env).verdict, Verdict.UNHEALTHY)

    def test_medium_only_leads_to_needs_attention(self):
        env = healthy()
        env["timestamp"] = "not an rfc3339"  # MEDIUM
        self.assertEqual(scan(env).verdict, Verdict.NEEDS_ATTENTION)


class ScanDoesNotMutate(unittest.TestCase):
    def test_input_unchanged(self):
        env = healthy()
        snap = deep(env)
        scan(env)
        self.assertEqual(env, snap)


if __name__ == "__main__":  # pragma: no cover
    unittest.main()
