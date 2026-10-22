"""Conformance tests over shipped example ledgers."""

from __future__ import annotations

import os
import unittest

from auditledger import digest, verify
from auditledger.types import Verdict


EXAMPLES = os.path.abspath(
    os.path.join(os.path.dirname(__file__), "..", "examples")
)

HEALTHY = os.path.join(EXAMPLES, "healthy_ledger.jsonl")
TAMPERED = os.path.join(EXAMPLES, "tampered_ledger.jsonl")


class HealthyExample(unittest.TestCase):
    def test_file_exists(self):
        self.assertTrue(os.path.isfile(HEALTHY),
                        f"missing shipped fixture: {HEALTHY}")

    def test_verify_clean(self):
        res = verify(HEALTHY)
        self.assertEqual(res.findings, [])
        self.assertEqual(res.verdict, Verdict.HEALTHY)
        self.assertEqual(res.entries_checked, 3)

    def test_digest_pinned(self):
        # If the canonical encoding or the example-builder's inputs
        # change, this trips first so a reviewer sees it on CI
        # rather than finding it in production.
        self.assertEqual(
            digest(HEALTHY),
            "f3b349562633d8018b3073b978f0a1c93e919d7942ad6e4f99cf7b513485d3a9",
        )


class TamperedExample(unittest.TestCase):
    def test_file_exists(self):
        self.assertTrue(os.path.isfile(TAMPERED))

    def test_verify_detects_tamper(self):
        res = verify(TAMPERED)
        ids = tuple(f.rule_id for f in res.findings)
        self.assertIn("AL-006", ids)
        self.assertEqual(res.verdict, Verdict.UNHEALTHY)


if __name__ == "__main__":  # pragma: no cover
    unittest.main()
