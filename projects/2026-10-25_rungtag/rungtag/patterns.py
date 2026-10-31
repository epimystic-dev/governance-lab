"""Grammar for the reasoning-depth tag discipline.

A tag line in a block header is of the form:

    tag: (TAG(, TAG)*)

Each TAG is one of the primary tokens below, or a rung dimension. The
primary token set is the small vocabulary that appears in several
publicly documented reasoning-depth-tag conventions and in the
parallel reasoning-depth-tag vocabulary in the FaithCoT-Bench public
materials. A caller may extend
the primary set via Patterns.extra_primary when constructing a scanner;
unknown tokens become RT-003.

Rung dimensions
---------------
The Pearl ladder extension adds a non-mandatory rung-N dimension:

- ``rung-1``  associative / pattern recognition
- ``rung-2``  interventional / what-if-we-do reasoning
- ``rung-3``  counterfactual / structural-causal-model reasoning

A tag may be ``rung-1`` on its own. ``rung-2`` requires the base
``reasoning`` in the same tuple. ``rung-3`` requires ``iterated`` or
``reasoning-iterated`` (the maker-checker loop) in the same tuple;
rung-3 reasoning without the loop that could cause-check it is the
central failure mode the convention exists to catch.

Block grammar
-------------
A block is one segment of input bounded by a markdown H2 line (``## ``)
or the explicit ``---BLOCK---`` separator or start-of-input.
Within the first consecutive non-blank lines of a block, any line
matching ``^(tag|checker|checker_role):\\s*(.+)$`` is a header field.
Content begins at the first blank line or at the first line that is
not a header field.

The parser is intentionally minimal. It does not run markdown; it
reads lines. It does not re-tokenise text; it finds blocks, counts
words, and matches a small set of regular expressions.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Dict, FrozenSet, List, Optional, Set, Tuple


PRIMARY_TOKENS: FrozenSet[str] = frozenset({
    "normal",
    "reasoning",
    "iterated",
    "reasoning-iterated",
})

RUNG_TOKENS: FrozenSet[str] = frozenset({
    "rung-1",
    "rung-2",
    "rung-3",
})

ALL_KNOWN_TOKENS: FrozenSet[str] = PRIMARY_TOKENS | RUNG_TOKENS

# Which rung requires which base in the same tuple.
RUNG_REQUIRES: Dict[str, FrozenSet[str]] = {
    "rung-1": frozenset(),  # no base required
    "rung-2": frozenset({"reasoning", "iterated", "reasoning-iterated"}),
    "rung-3": frozenset({"iterated", "reasoning-iterated"}),
}


_BLOCK_H2_RE = re.compile(r"^##\s+(.+?)\s*$")
_BLOCK_SEP_RE = re.compile(r"^-{3}BLOCK-{3}\s*$")
_HEADER_RE = re.compile(r"^(tag|checker|checker_role)\s*:\s*(.+?)\s*$")
_TAG_SHAPE_RE = re.compile(r"^\(\s*([^)]*)\s*\)\s*$")


@dataclass
class HeaderField:
    key: str
    value: str
    line_no: int  # 1-indexed


@dataclass
class ParsedTag:
    raw: str
    tokens: Tuple[str, ...]  # trimmed, lowercased
    primary: Optional[str]   # the primary token found, if any
    rungs: Tuple[str, ...]   # rung tokens found
    unknown: Tuple[str, ...] # tokens not in ALL_KNOWN_TOKENS
    malformed: bool          # True if parens or shape malformed


@dataclass
class Block:
    index: int             # 0-indexed sequence
    title: Optional[str]   # H2 title or None
    header_start_line: int # 1-indexed
    content_start_line: int
    headers: List[HeaderField] = field(default_factory=list)
    content: str = ""


def split_blocks(text: str) -> List[Block]:
    """Split ``text`` into blocks bounded by H2 lines or ---BLOCK---.

    If no delimiter is found at the start, the whole stream is one
    unnamed block starting at line 1.
    """
    lines = text.splitlines()
    starts: List[Tuple[int, Optional[str]]] = []
    for i, line in enumerate(lines):
        m = _BLOCK_H2_RE.match(line)
        if m:
            starts.append((i, m.group(1).strip()))
            continue
        if _BLOCK_SEP_RE.match(line):
            starts.append((i, None))
            continue
    if not starts or starts[0][0] != 0:
        starts.insert(0, (0, None))
        # Remove the duplicate at 0 if the first real delimiter was at 0.
        if len(starts) > 1 and starts[1][0] == 0:
            starts.pop(0)

    blocks: List[Block] = []
    for idx, (li, title) in enumerate(starts):
        end = starts[idx + 1][0] if idx + 1 < len(starts) else len(lines)
        # The delimiter line itself is NOT part of the block content
        # unless the block has no delimiter (unnamed first block).
        body_start = li + 1 if (title is not None or _is_sep_line(lines, li)) else li
        block_lines = lines[body_start:end]

        headers, header_end_rel = _parse_headers(block_lines, body_start)
        content_start = body_start + header_end_rel
        content_lines = lines[content_start:end]
        content = "\n".join(content_lines).strip()

        blocks.append(Block(
            index=idx,
            title=title,
            header_start_line=body_start + 1,
            content_start_line=content_start + 1,
            headers=headers,
            content=content,
        ))
    return blocks


def _is_sep_line(lines: List[str], i: int) -> bool:
    if 0 <= i < len(lines):
        line = lines[i]
        return bool(_BLOCK_H2_RE.match(line) or _BLOCK_SEP_RE.match(line))
    return False


def _parse_headers(body_lines, body_start) -> Tuple[List[HeaderField], int]:
    """Parse header fields from the top of a block body.

    Returns (headers, relative_offset_of_first_content_line).
    """
    headers: List[HeaderField] = []
    i = 0
    seen_non_header = False
    for i, line in enumerate(body_lines):
        if line.strip() == "":
            # Blank line ends headers. Content starts on the NEXT line.
            if headers:
                return headers, i + 1
            # No headers found yet; treat the blank as content-adjacent
            # whitespace and continue scanning.
            continue
        m = _HEADER_RE.match(line)
        if m:
            if seen_non_header:
                # Headers must be at the top of the block; after
                # content starts, no more headers.
                return headers, _first_nonblank(body_lines)
            headers.append(HeaderField(
                key=m.group(1),
                value=m.group(2).strip(),
                line_no=body_start + i + 1,
            ))
            continue
        # First non-header, non-blank line -> content starts here.
        return headers, i
    return headers, len(body_lines)


def _first_nonblank(lines: List[str]) -> int:
    for i, line in enumerate(lines):
        if line.strip() != "":
            return i
    return len(lines)


def parse_tag(raw: str) -> ParsedTag:
    """Parse a tag string. ``raw`` is the value AFTER ``tag:``."""
    stripped = raw.strip()
    m = _TAG_SHAPE_RE.match(stripped)
    if not m:
        return ParsedTag(
            raw=raw, tokens=(), primary=None,
            rungs=(), unknown=(), malformed=True,
        )
    inner = m.group(1).strip()
    if not inner:
        return ParsedTag(
            raw=raw, tokens=(), primary=None,
            rungs=(), unknown=(), malformed=True,
        )
    toks = tuple(t.strip().lower() for t in inner.split(","))
    if any(t == "" for t in toks):
        return ParsedTag(
            raw=raw, tokens=toks, primary=None,
            rungs=(), unknown=(), malformed=True,
        )
    primary: Optional[str] = None
    for t in toks:
        if t in PRIMARY_TOKENS:
            primary = t
            break
    rungs = tuple(t for t in toks if t in RUNG_TOKENS)
    # unknown includes any token that is not a known primary, not a
    # known rung, and not an unknown rung-N (which gets its own RT).
    unknown = tuple(
        t for t in toks
        if t not in ALL_KNOWN_TOKENS and not t.startswith("rung-")
    )
    return ParsedTag(
        raw=raw, tokens=toks, primary=primary,
        rungs=rungs, unknown=unknown, malformed=False,
    )


def unknown_rungs(parsed: ParsedTag) -> Tuple[str, ...]:
    """Rung-N tokens that are not in RUNG_TOKENS."""
    return tuple(
        t for t in parsed.tokens
        if t.startswith("rung-") and t not in RUNG_TOKENS
    )


def word_count(text: str) -> int:
    """Rough word count: whitespace-separated non-empty tokens."""
    return sum(1 for w in text.split() if w)
