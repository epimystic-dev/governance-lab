"""Tests for the canonical JSON encoder.

The hash chain is only as reliable as the canonical encoding - two
semantically equal objects MUST produce byte-identical output.
"""

from __future__ import annotations

import unittest

from auditledger import canonical_bytes


class KeyOrderIsFixed(unittest.TestCase):
    def test_two_different_input_orders_same_output(self):
        a = {"a": 1, "b": 2, "c": 3}
        b = {"c": 3, "a": 1, "b": 2}
        self.assertEqual(canonical_bytes(a), canonical_bytes(b))

    def test_nested_order_fixed(self):
        a = {"outer": {"a": 1, "b": 2}}
        b = {"outer": {"b": 2, "a": 1}}
        self.assertEqual(canonical_bytes(a), canonical_bytes(b))


class NoWhitespace(unittest.TestCase):
    def test_no_internal_whitespace(self):
        out = canonical_bytes({"a": 1, "b": [1, 2]})
        self.assertEqual(out, b'{"a":1,"b":[1,2]}')


class NaNAndInfinityRejected(unittest.TestCase):
    def test_nan_rejected(self):
        self.assertRaises(ValueError, canonical_bytes, float("nan"))

    def test_infinity_rejected(self):
        self.assertRaises(ValueError, canonical_bytes, float("inf"))


class NonAsciiPreserved(unittest.TestCase):
    def test_non_ascii_round_trip(self):
        payload = {"name": "a" + chr(0x00E9) + "b"}  # 'aeb' with e-acute
        out = canonical_bytes(payload)
        # The e-acute must appear as its two-byte UTF-8 encoding,
        # not as its \u escape.
        self.assertIn(bytes([0xC3, 0xA9]), out)
        self.assertNotIn(b"\\u00e9", out)
        self.assertNotIn(b"\\u00E9", out)


class EqualityIsStable(unittest.TestCase):
    def test_same_object_same_bytes(self):
        payload = {"a": 1, "list": ["x", "y"], "n": None, "f": 1.5}
        self.assertEqual(canonical_bytes(payload),
                         canonical_bytes(payload))


if __name__ == "__main__":  # pragma: no cover
    unittest.main()
