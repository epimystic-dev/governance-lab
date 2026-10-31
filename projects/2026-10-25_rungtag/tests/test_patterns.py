"""Unit tests for rungtag.patterns."""

from __future__ import annotations

import unittest

from tests import support  # noqa: F401

from rungtag.patterns import (
    parse_tag,
    split_blocks,
    unknown_rungs,
    word_count,
)


class TagParser(unittest.TestCase):
    def test_single_primary(self):
        p = parse_tag("(reasoning)")
        self.assertFalse(p.malformed)
        self.assertEqual(p.primary, "reasoning")
        self.assertEqual(p.rungs, ())

    def test_compound(self):
        p = parse_tag("(reasoning, iterated)")
        self.assertFalse(p.malformed)
        self.assertEqual(p.tokens, ("reasoning", "iterated"))

    def test_with_rung(self):
        p = parse_tag("(reasoning, rung-2)")
        self.assertEqual(p.primary, "reasoning")
        self.assertEqual(p.rungs, ("rung-2",))

    def test_whitespace_tolerant(self):
        p = parse_tag("  (  reasoning,  rung-1 )  ")
        self.assertFalse(p.malformed)
        self.assertEqual(p.tokens, ("reasoning", "rung-1"))

    def test_missing_parens(self):
        self.assertTrue(parse_tag("reasoning").malformed)

    def test_empty_tuple(self):
        self.assertTrue(parse_tag("()").malformed)

    def test_trailing_comma(self):
        self.assertTrue(parse_tag("(reasoning,)").malformed)

    def test_unknown_token(self):
        p = parse_tag("(deliberated)")
        self.assertFalse(p.malformed)
        self.assertEqual(p.unknown, ("deliberated",))

    def test_unknown_rung(self):
        p = parse_tag("(reasoning, rung-5)")
        self.assertEqual(unknown_rungs(p), ("rung-5",))


class SplitBlocks(unittest.TestCase):
    def test_single_unnamed_block(self):
        bs = split_blocks("just one chunk of text")
        self.assertEqual(len(bs), 1)
        self.assertIsNone(bs[0].title)

    def test_h2_delim(self):
        bs = split_blocks("## one\nalpha\n## two\nbeta")
        self.assertEqual(len(bs), 2)
        self.assertEqual(bs[0].title, "one")
        self.assertEqual(bs[1].title, "two")

    def test_block_sep_delim(self):
        bs = split_blocks("alpha\n---BLOCK---\nbeta")
        self.assertEqual(len(bs), 2)

    def test_header_parsing(self):
        bs = split_blocks(
            "## block\n"
            "tag: (reasoning)\n"
            "checker_role: reviewer\n"
            "\n"
            "content line\n"
        )
        self.assertEqual(len(bs), 1)
        keys = [h.key for h in bs[0].headers]
        self.assertIn("tag", keys)
        self.assertIn("checker_role", keys)
        self.assertIn("content line", bs[0].content)


class WordCount(unittest.TestCase):
    def test_counts_whitespace_separated(self):
        self.assertEqual(word_count("one two three"), 3)
        self.assertEqual(word_count("  one \t two \n three "), 3)
        self.assertEqual(word_count(""), 0)


if __name__ == "__main__":  # pragma: no cover
    unittest.main()
