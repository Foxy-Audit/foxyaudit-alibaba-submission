# Known issues — SDK

Defects found and deliberately NOT fixed in the release that found them, with the
measurement that established each one. Filed here rather than in a commit message
so that "we already know" is checkable by the next person to trip over it.

An entry leaves this file only when the defect is fixed, and the fix cites the
number.

---

## #219 — a stray separated digit in front of a card number breaks detection

**Status:** open · **Found:** 1.9.0 review (S8e) · **PRE-EXISTING, not introduced
by 1.9.0**

`"item 1 4111111111111111"` and `"line 12 4111111111111111"` report nothing.

```
                             1.8.0    1.9.0
item 1 4111111111111111       []       []
line 12 4111111111111111      []       []
ref 0 4111111111111111        card     card
```

The third row is not a fix over 1.8.0 — 1.8.0 detected it too. It is there
because the 1.9.0 review LOST it (S8b/S8c applied "no PAN starts with 0" to the
whole separator-chained candidate) and S8d restored it. Same mechanism, zero
instead of a non-zero digit.

**Mechanism.** `_CARD_CANDIDATE_RE` treats a space or hyphen as an internal
separator, so a preceding stray digit chains into the same candidate:
`1 4111111111111111` is read as one 17-digit run, which fails Luhn. `finditer`
returns non-overlapping matches, so once that candidate is consumed there is no
second attempt starting at the real PAN.

The zero case (`ref 0 …`) does not reach this, because the pattern requires the
candidate to START at `[1-9]` and the match therefore begins past a leading zero.
Both 1.8.0 and 1.9.0 detect it. A stray NON-zero digit is still swept in, and
that is #219.

**Why it was not fixed here.** It is inherited behaviour, identical in 1.8.0, and
1.9.0 was already five review rounds deep on this boundary — three of which lost
real detections. Changing the candidate's chaining again to chase it is exactly
the churn that produced those losses. It wants its own change, with the
obligation set in `sdk/tests/fixtures/identifier_corpora.py` extended first.

**⚠ WHY IT MATTERS FOR HOW 1.9.0 IS DESCRIBED.** 1.9.0's card detection is
IDENTICAL to 1.8.0's — the same 504 of 540 obligation shapes, asserted as a set
difference in both directions. A parity test cannot see an inherited bug, so
"identical to 1.8.0" must never be written in a way that reads as "complete".

**All 36 shapes both releases miss are this defect** — one per PAN per grouping:
18 `item 1 <PAN>` shapes and 18 `line 12 <PAN>` shapes.

(An earlier draft said "the letter-glued ones plus these". `PAN_SHAPES` contains
no letter-glued context at all: a PAN welded to a letter is not something the
detector is meant to find, so it belongs in the false-positive populations, not
in an obligation set. The 36 are entirely #219, and
`tests/test_stated_figures.py` re-derives that split rather than trusting this
sentence.)

---

## #220 — `explain()` never checks a row's recorded `ruleset_hash`

**Status:** open · **Found:** 1.9.0 review (S8e)

`introspect.explain()` reads `ruleset_version` from a row, loads that frozen
definition, and replays it. It never computes `ruleset.hash_of(definition)` and
compares it against the `ruleset_hash` the row also recorded.

**Consequence.** A registry edited in place — a frozen module changed after
publication, a partial upgrade, a backported definition — replays as though
nothing happened. The two provenance keys are written together precisely so the
second can verify the first, and nothing does.

This is the check that would have caught 2026.08.3 being regenerated in place
during 1.9.0's review. That was safe only because the version was unpublished;
after the 1.9.0 tag it would not be, and nothing would notice.

**Shape of the fix.** In `explain()`, after `ruleset.load(version)`: if the row
carries `ruleset_hash` and it does not equal `hash_of` the loaded definition,
return a new outcome rather than replaying — the honest answer is "this build's
copy of that ruleset is not the one that wrote this row". Needs a decision about
rows written before `ruleset_hash` existed (they carry neither key, so they
already take the `predates_provenance` path).
