"""Negative-shape tests for trustlabels.

A bundle that is not a list / not an object / missing entries / entry
without id / entry without trust_label must raise ValidationError at
the library layer and return rc 2 at the CLI layer.
"""

from __future__ import annotations

import json
import os
import unittest

from tests import support  # noqa: F401
from tests.support import run_cli, write_temp

import trustlabels
from trustlabels.structural import validate
from trustlabels.types import ValidationError


class ValidateRaisesOnMalformed(unittest.TestCase):
    def test_bundle_is_not_list_or_object(self):
        with self.assertRaises(ValidationError):
            validate("not a bundle")

    def test_object_without_entries(self):
        with self.assertRaises(ValidationError) as cm:
            validate({"not_entries": []})
        self.assertTrue(any("entries" in msg for _, msg in cm.exception.errors))

    def test_entries_not_a_list(self):
        with self.assertRaises(ValidationError):
            validate({"entries": "not a list"})

    def test_entry_not_an_object(self):
        with self.assertRaises(ValidationError) as cm:
            validate({"entries": [42]})
        self.assertTrue(any("not an object" in msg for _, msg in cm.exception.errors))

    def test_entry_missing_id(self):
        with self.assertRaises(ValidationError) as cm:
            validate({"entries": [{"trust_label": "quarantined:web"}]})
        self.assertTrue(any("'id'" in msg for _, msg in cm.exception.errors))

    def test_entry_missing_trust_label(self):
        with self.assertRaises(ValidationError) as cm:
            validate({"entries": [{"id": "x"}]})
        self.assertTrue(any("'trust_label'" in msg for _, msg in cm.exception.errors))

    def test_valid_list_of_entries(self):
        validate([{"id": "x", "trust_label": "quarantined:web"}])


class CliOnMalformed(unittest.TestCase):
    def test_rc2_on_entry_missing_id(self):
        d, p = write_temp({"entries": [{"trust_label": "quarantined:web"}]})
        rc, _, _ = run_cli([p])
        self.assertEqual(rc, 2)

    def test_rc2_on_entries_not_list(self):
        d, p = write_temp({"entries": "oops"})
        rc, _, _ = run_cli([p])
        self.assertEqual(rc, 2)


if __name__ == "__main__":  # pragma: no cover
    unittest.main()
