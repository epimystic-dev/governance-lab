## block one: no tag yet substantive
This block has no tag header at all. It is well above the substantive
threshold, which means that a reasoning-depth tag ought to be declared
so a downstream honesty check can reason about it. The absence of a
tag here will cause RT-001 to fire. The point of this fixture is to
exercise the untagged-but-substantive path cleanly.

## block two: self-awarded iterated
tag: (iterated)

This block claims iterated without a checker header on the block and
without a sibling checker block. The convention says this is a self-
awarded verification tag. RT-002 should fire here, and also RT-009
because iterated alone is ambiguous.

## block three: malformed tag
tag: reasoning without parens

A tag string that does not match the grammar. RT-003 should flag it.

## block four: rung-3 without iterated
tag: (reasoning, rung-3)

The rung-3 token requires iterated in the same tuple so the maker-
checker loop is what grounds the counterfactual claim. The tuple is
missing the iterated token, so RT-004 should fire.

## block five: overclaim
tag: (reasoning)
Very short.

## block six: unknown token
tag: (deliberated, careful)

Neither token is in the known primary set. RT-008 fires for the unknown
tokens here.

## block seven: unknown rung
tag: (reasoning, rung-4)

rung-4 is outside the Pearl ladder. RT-007 fires.

## block eight: duplicate tag
tag: (normal)
tag: (reasoning)

Two tag headers in the same block are ambiguous. RT-006 fires. The
content below the headers is long enough to be substantive so no
RT-001 fires, which is intentional - we want ONLY the duplicate
to show up for this block without conflating with other rules. This
sentence is here to carry the word count above the substantive floor.
