## block one
tag: (reasoning)

The first substantive segment of this transcript. We are reasoning about
the structure of the input, enumerating the cases that the scanner has
to handle, and noting which of those cases are mutually exclusive. The
word count here is well above the substantive threshold, so the block
must declare a reasoning-depth tag, which it does.

## block two: checker pass
tag: (reasoning, iterated)
checker_role: reviewer

An iterated pass over block one. Because this block names a checker role
in its header, the iterated claim is honestly grounded; the shared
contract test accepts this as a known-clean baseline.

## block three
tag: (normal)

A short note.

## block four: rung-2 example
tag: (reasoning, rung-2)

An interventional claim about how a change in input would alter the
output. The rung-2 token is grounded by the reasoning token in the
same tuple, as the Pearl ladder convention requires.

## block five: closing
tag: (reasoning, iterated, rung-3)
checker: another-reviewer

A counterfactual claim grounded by the iterated loop; rung-3 is only
honest with iterated present. The checker is named on this block, so
the iterated claim is not self-awarded.
