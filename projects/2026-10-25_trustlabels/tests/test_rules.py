"""Per-rule assertions for trustlabels.

Each test takes a known-clean bundle, introduces exactly the one defect
the rule under test should flag, and asserts the rule id fires and
other rule ids do not when they would conflict with the test's scope.
"""

from __future__ import annotations

import unittest

from tests import support
from tests.support import (
    bundle_only,
    bundle_with,
    healthy,
    mutate_entry,
    scan_rule_ids,
    scan_rule_ids_for_entry,
)

import trustlabels


class TL001_QuarantinedAsGrounds(unittest.TestCase):
    def test_fires_on_quarantined_grounds_without_promotion(self):
        e = mutate_entry(
            id="x", trust_label="quarantined:web",
            grounds_for_action=True,
        )
        ids = scan_rule_ids_for_entry(e)
        self.assertIn("TL-001", ids)

    def test_quiet_when_promoted(self):
        e = mutate_entry(
            id="x", trust_label="quarantined:web",
            grounds_for_action=True,
            promoted_to="trusted:audited",
            promoted_by="reviewer-1",
            promotion_gate="reviewer",
        )
        ids = scan_rule_ids_for_entry(e)
        self.assertNotIn("TL-001", ids)

    def test_quiet_when_not_grounds(self):
        e = mutate_entry(
            id="x", trust_label="quarantined:web",
            grounds_for_action=False,
        )
        self.assertNotIn("TL-001", scan_rule_ids_for_entry(e))

    def test_fires_when_promoted_to_set_without_gate(self):
        # The attack: claim a bare promoted_to and the pre-fix TL-001
        # treated the entry as promoted. TL-002 still fires on the
        # structural defect, but TL-001 must also fire on the semantic
        # one (quarantined content used as grounds).
        e = mutate_entry(
            id="x", trust_label="quarantined:web",
            grounds_for_action=True,
            promoted_to="trusted:audited",
            promoted_by=None,
            promotion_gate=None,
        )
        ids = scan_rule_ids_for_entry(e)
        self.assertIn("TL-001", ids)
        self.assertIn("TL-002", ids)

    def test_fires_when_promoted_to_set_without_promoted_by(self):
        e = mutate_entry(
            id="x", trust_label="quarantined:web",
            grounds_for_action=True,
            promoted_to="trusted:audited",
            promoted_by=None,
            promotion_gate="reviewer",
        )
        self.assertIn("TL-001", scan_rule_ids_for_entry(e))

    def test_fires_when_promotion_target_is_unreachable(self):
        # untrusted:derived -> trusted:audited is not in the matrix.
        # TL-003 fires on the invalid transition; TL-001 must still
        # fire because the quarantined entry's promotion is not valid.
        e = mutate_entry(
            id="x", trust_label="quarantined:web",
            grounds_for_action=True,
            promoted_to="observed:tool",
            promoted_by="reviewer-1",
            promotion_gate="reviewer",
        )
        ids = scan_rule_ids_for_entry(e)
        self.assertIn("TL-001", ids)
        self.assertIn("TL-003", ids)

    def test_fires_when_promotion_gate_is_wrong(self):
        e = mutate_entry(
            id="x", trust_label="quarantined:web",
            grounds_for_action=True,
            promoted_to="trusted:audited",
            promoted_by="reviewer-1",
            promotion_gate="automated-sanitizer",
        )
        ids = scan_rule_ids_for_entry(e)
        self.assertIn("TL-001", ids)
        self.assertIn("TL-010", ids)


class TL002_PromotionWithoutGate(unittest.TestCase):
    def test_fires_when_promoted_by_missing(self):
        e = mutate_entry(
            promoted_to="trusted:audited",
            promoted_by=None,
            promotion_gate="reviewer",
        )
        self.assertIn("TL-002", scan_rule_ids_for_entry(e))

    def test_fires_when_promotion_gate_missing(self):
        e = mutate_entry(
            promoted_to="trusted:audited",
            promoted_by="reviewer-1",
            promotion_gate=None,
        )
        self.assertIn("TL-002", scan_rule_ids_for_entry(e))

    def test_quiet_when_all_fields_present(self):
        e = mutate_entry(
            promoted_to="trusted:audited",
            promoted_by="reviewer-1",
            promotion_gate="reviewer",
        )
        self.assertNotIn("TL-002", scan_rule_ids_for_entry(e))


class TL003_UnreachableTarget(unittest.TestCase):
    def test_fires_on_disallowed_transition(self):
        e = mutate_entry(
            trust_label="untrusted:derived",
            promoted_to="trusted:audited",
            promoted_by="x",
            promotion_gate="reviewer",
        )
        ids = scan_rule_ids_for_entry(e)
        self.assertIn("TL-003", ids)

    def test_quiet_on_allowed_transition(self):
        e = mutate_entry(
            trust_label="quarantined:web",
            promoted_to="trusted:audited",
            promoted_by="rev",
            promotion_gate="reviewer",
        )
        ids = scan_rule_ids_for_entry(e)
        self.assertNotIn("TL-003", ids)


class TL004_UnknownPromotionTarget(unittest.TestCase):
    def test_fires_on_unknown_target(self):
        e = mutate_entry(
            trust_label="quarantined:web",
            promoted_to="my:new-tier",
            promoted_by="rev",
            promotion_gate="reviewer",
        )
        self.assertIn("TL-004", scan_rule_ids_for_entry(e))


class TL005_UnknownTrustLabel(unittest.TestCase):
    def test_fires_on_unknown_label(self):
        e = mutate_entry(trust_label="trusty:friendly")
        self.assertIn("TL-005", scan_rule_ids_for_entry(e))

    def test_quiet_on_known_label(self):
        e = mutate_entry(trust_label="quarantined:web")
        self.assertNotIn("TL-005", scan_rule_ids_for_entry(e))


class TL006_BadTimestamp(unittest.TestCase):
    def test_fires_on_malformed_timestamp(self):
        e = mutate_entry(entered_at="yesterday afternoon")
        self.assertIn("TL-006", scan_rule_ids_for_entry(e))

    def test_quiet_on_rfc3339(self):
        e = mutate_entry(entered_at="2026-10-25T09:00:00Z")
        self.assertNotIn("TL-006", scan_rule_ids_for_entry(e))

    def test_quiet_on_rfc3339_with_offset(self):
        e = mutate_entry(entered_at="2026-10-25T09:00:00+05:30")
        self.assertNotIn("TL-006", scan_rule_ids_for_entry(e))


class TL007_TrustedSystemExternalSource(unittest.TestCase):
    def test_fires_on_external_url(self):
        e = mutate_entry(
            id="s", trust_label="trusted:system",
            source_ref="https://third-party.example/system.txt",
            grounds_for_action=True,
        )
        ids = scan_rule_ids_for_entry(e)
        self.assertIn("TL-007", ids)

    def test_quiet_on_pkg_source(self):
        e = mutate_entry(
            id="s", trust_label="trusted:system",
            source_ref="pkg://host/system.md",
            grounds_for_action=True,
        )
        self.assertNotIn("TL-007", scan_rule_ids_for_entry(e))


class TL008_GroundsForActionNotDeclared(unittest.TestCase):
    def test_fires_when_field_omitted(self):
        e = mutate_entry()
        del e["grounds_for_action"]
        self.assertIn("TL-008", scan_rule_ids_for_entry(e))

    def test_quiet_when_declared_false(self):
        e = mutate_entry(grounds_for_action=False)
        self.assertNotIn("TL-008", scan_rule_ids_for_entry(e))

    def test_quiet_when_declared_true(self):
        e = mutate_entry(
            trust_label="trusted:system",
            source_ref="pkg://host/s.md",
            grounds_for_action=True,
        )
        self.assertNotIn("TL-008", scan_rule_ids_for_entry(e))


class TL009_UntrustedAsGrounds(unittest.TestCase):
    def test_fires_on_untrusted_grounds(self):
        e = mutate_entry(
            trust_label="untrusted:derived",
            source_ref="tool://x/raw",
            grounds_for_action=True,
        )
        self.assertIn("TL-009", scan_rule_ids_for_entry(e))

    def test_quiet_when_promoted(self):
        e = mutate_entry(
            trust_label="untrusted:derived",
            source_ref="tool://x/raw",
            grounds_for_action=True,
            promoted_to="observed:tool",
            promoted_by="sanitizer",
            promotion_gate="automated-sanitizer",
        )
        self.assertNotIn("TL-009", scan_rule_ids_for_entry(e))

    def test_fires_when_promoted_to_set_without_gate(self):
        # Mirror of the TL-001 attack path for the untrusted level.
        e = mutate_entry(
            trust_label="untrusted:derived",
            source_ref="tool://x/raw",
            grounds_for_action=True,
            promoted_to="observed:tool",
            promoted_by=None,
            promotion_gate=None,
        )
        ids = scan_rule_ids_for_entry(e)
        self.assertIn("TL-009", ids)
        self.assertIn("TL-002", ids)


class TL010_InvalidGateForTransition(unittest.TestCase):
    def test_fires_on_wrong_gate(self):
        e = mutate_entry(
            trust_label="quarantined:web",
            promoted_to="trusted:audited",
            promoted_by="x",
            promotion_gate="automated-sanitizer",
        )
        ids = scan_rule_ids_for_entry(e)
        self.assertIn("TL-010", ids)
        self.assertNotIn("TL-002", ids)

    def test_quiet_on_correct_gate(self):
        e = mutate_entry(
            trust_label="quarantined:web",
            promoted_to="trusted:audited",
            promoted_by="x",
            promotion_gate="reviewer",
        )
        self.assertNotIn("TL-010", scan_rule_ids_for_entry(e))


class TL011_DuplicateId(unittest.TestCase):
    def test_fires_on_duplicate_id(self):
        b = {
            "entries": [
                mutate_entry(id="dup/a"),
                mutate_entry(id="dup/a"),
            ]
        }
        self.assertIn("TL-011", scan_rule_ids(b))

    def test_quiet_on_unique_ids(self):
        b = {
            "entries": [
                mutate_entry(id="a"),
                mutate_entry(id="b"),
            ]
        }
        self.assertNotIn("TL-011", scan_rule_ids(b))


class TL012_ObservedOrQuarantinedWithoutSource(unittest.TestCase):
    def test_fires_on_missing_source_quarantined(self):
        e = mutate_entry(source_ref=None)
        self.assertIn("TL-012", scan_rule_ids_for_entry(e))

    def test_fires_on_missing_source_observed(self):
        e = mutate_entry(
            trust_label="observed:tool",
            source_ref=None,
        )
        self.assertIn("TL-012", scan_rule_ids_for_entry(e))

    def test_quiet_on_trusted_without_source(self):
        e = mutate_entry(
            trust_label="trusted:audited",
            source_ref=None,
        )
        self.assertNotIn("TL-012", scan_rule_ids_for_entry(e))


class HealthyBundleHasNoFindings(unittest.TestCase):
    def test_canonical_healthy_bundle_is_clean(self):
        ids = scan_rule_ids(healthy())
        self.assertEqual(
            ids, (),
            "healthy() produced findings; it must be the lab's "
            "known-clean baseline. Got: " + ", ".join(ids),
        )


if __name__ == "__main__":  # pragma: no cover
    unittest.main()
