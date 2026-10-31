"""Per-rule assertions for rungtag."""

from __future__ import annotations

import unittest

from tests import support  # noqa: F401
from tests.support import healthy_text, scan_rule_ids


class RT001_SubstantiveWithoutTag(unittest.TestCase):
    def test_fires_on_long_untagged_block(self):
        text = (
            "## block\n"
            + ("Here is a long block without any tag header. "
               * 20)
        )
        self.assertIn("RT-001", scan_rule_ids(text))

    def test_quiet_on_short_untagged_block(self):
        text = "## block\nshort note.\n"
        self.assertNotIn("RT-001", scan_rule_ids(text))


class RT002_IteratedWithoutChecker(unittest.TestCase):
    def test_fires_without_checker_header(self):
        text = (
            "## block\n"
            "tag: (reasoning, iterated)\n"
            "\n"
            + ("content that is long enough to be substantive "
               "so other rules do not interfere. " * 5)
        )
        self.assertIn("RT-002", scan_rule_ids(text))

    def test_quiet_with_checker_header(self):
        text = (
            "## block\n"
            "tag: (reasoning, iterated)\n"
            "checker: reviewer-a\n"
            "\n"
            + ("content that is long enough to be substantive "
               "so other rules do not interfere. " * 5)
        )
        self.assertNotIn("RT-002", scan_rule_ids(text))

    def test_fires_when_only_signal_is_decorative_title(self):
        # Regression: a decorative sibling block whose only tie to
        # checking is the substring "checker" in its H2 title must
        # NOT suppress RT-002. A real sibling checker declares a
        # checker_role: header.
        text = (
            "## Analysis\n"
            "tag: (reasoning, iterated)\n"
            "\n"
            + ("Substantive block that claims a maker-checker loop ran, "
               "but the block never names a checker and no header is "
               "attached. The point of RT-002 is to flag exactly this. "
               * 3)
            + "\n\n"
            + "## Checker: never happened\n"
            + "tag: (normal)\n"
            + "\n"
            + "A short unrelated note whose only tie to checking is "
            + "the word in its title.\n"
        )
        self.assertIn("RT-002", scan_rule_ids(text))

    def test_quiet_when_sibling_block_declares_checker_role(self):
        # A sibling block that carries a `checker_role:` header IS
        # a declarative sibling-checker signal and suppresses RT-002
        # (preserves the existing permissive-sibling design).
        text = (
            "## Analysis\n"
            "tag: (reasoning, iterated)\n"
            "\n"
            + ("Substantive block that claims iterated without its "
               "own checker header, but there is a sibling checker "
               "block below. " * 4)
            + "\n\n"
            + "## Review\n"
            + "tag: (normal)\n"
            + "checker_role: reviewer\n"
            + "\n"
            + "A review block that declares the checker role.\n"
        )
        self.assertNotIn("RT-002", scan_rule_ids(text))


class RT003_Malformed(unittest.TestCase):
    def test_fires_without_parens(self):
        text = (
            "## block\n"
            "tag: reasoning\n"
            "\n"
            + ("content so RT-001 does not fire. " * 20)
        )
        self.assertIn("RT-003", scan_rule_ids(text))

    def test_fires_on_empty_tuple(self):
        text = (
            "## block\n"
            "tag: ()\n"
            "\n"
            + ("content so RT-001 does not fire. " * 20)
        )
        self.assertIn("RT-003", scan_rule_ids(text))


class RT004_RungWithoutBase(unittest.TestCase):
    def test_fires_on_rung2_without_reasoning(self):
        text = (
            "## block\n"
            "tag: (normal, rung-2)\n"
            "\n"
            + ("content so RT-001 does not fire. " * 20)
        )
        self.assertIn("RT-004", scan_rule_ids(text))

    def test_fires_on_rung3_without_iterated(self):
        text = (
            "## block\n"
            "tag: (reasoning, rung-3)\n"
            "\n"
            + ("content so RT-001 does not fire. " * 20)
        )
        self.assertIn("RT-004", scan_rule_ids(text))

    def test_quiet_on_rung1(self):
        text = (
            "## block\n"
            "tag: (normal, rung-1)\n"
            "\n"
            + ("content so RT-001 does not fire. " * 20)
        )
        self.assertNotIn("RT-004", scan_rule_ids(text))


class RT005_ShortButReasoning(unittest.TestCase):
    def test_fires_on_short_block_tagged_reasoning(self):
        text = (
            "## block\n"
            "tag: (reasoning)\n"
            "\n"
            "a short line.\n"
        )
        self.assertIn("RT-005", scan_rule_ids(text))

    def test_quiet_on_short_block_tagged_normal(self):
        text = (
            "## block\n"
            "tag: (normal)\n"
            "\n"
            "a short line.\n"
        )
        self.assertNotIn("RT-005", scan_rule_ids(text))


class RT006_DuplicateTag(unittest.TestCase):
    def test_fires_on_two_tag_headers(self):
        text = (
            "## block\n"
            "tag: (reasoning)\n"
            "tag: (normal)\n"
            "\n"
            + ("content so RT-001 does not fire. " * 20)
        )
        self.assertIn("RT-006", scan_rule_ids(text))


class RT007_UnknownRung(unittest.TestCase):
    def test_fires_on_rung4(self):
        text = (
            "## block\n"
            "tag: (reasoning, rung-4)\n"
            "\n"
            + ("content so RT-001 does not fire. " * 20)
        )
        self.assertIn("RT-007", scan_rule_ids(text))


class RT008_UnknownPrimary(unittest.TestCase):
    def test_fires_on_unknown_token(self):
        text = (
            "## block\n"
            "tag: (deliberated)\n"
            "\n"
            + ("content so RT-001 does not fire. " * 20)
        )
        self.assertIn("RT-008", scan_rule_ids(text))


class RT009_IteratedAlone(unittest.TestCase):
    def test_fires_on_iterated_alone(self):
        text = (
            "## block\n"
            "tag: (iterated)\n"
            "checker: reviewer\n"
            "\n"
            + ("content so RT-001 does not fire and RT-002 does not "
               "fire. " * 20)
        )
        self.assertIn("RT-009", scan_rule_ids(text))

    def test_quiet_on_reasoning_iterated(self):
        text = (
            "## block\n"
            "tag: (reasoning-iterated)\n"
            "checker: reviewer\n"
            "\n"
            + ("content so RT-001 does not fire. " * 20)
        )
        self.assertNotIn("RT-009", scan_rule_ids(text))


class HealthyBaselineIsClean(unittest.TestCase):
    def test_canonical_healthy_text_has_no_findings(self):
        ids = scan_rule_ids(healthy_text())
        self.assertEqual(
            ids, (),
            "healthy_text() produced findings: " + ", ".join(ids),
        )


if __name__ == "__main__":  # pragma: no cover
    unittest.main()
