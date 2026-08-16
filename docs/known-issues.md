# Known issues — SDK

Defects found and deliberately NOT fixed in the release that found them, with the
measurement that established each one. Filed here rather than in a commit message
so that "we already know" is checkable by the next person to trip over it.

An entry leaves this file only when the defect is fixed, and the fix cites the
number.


**Closed:** **#220** (`explain()` never checked a row's recorded
`ruleset_hash`) was fixed in **1.10.0** — S9. Not 1.9.0: that release was tagged
and published from a commit predating the fix, and PyPI does not accept a
re-upload. `explain()` re-hashes the definition it loads and refuses with the
status `ruleset_mismatch` when it disagrees with what the row recorded, and
`ExplainResult` carries a three-state `ruleset_verified` beside
`commitment_verified` — `None` meaning the check did not run, which is not the
same news as `False`. It verifies the **definition**, not the validator code that
definition names; see the field's docstring for the boundary. Guards, including
the hand-edited-registry re-break, are in
`sdk/tests/test_explain_verifies_the_ruleset.py`.

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

## #221 — five known limits of the stated-figures scan

**Status:** open · **Found:** 1.9.0 review (S8h) · **In:**
`sdk/tests/test_stated_figures.py`

The scan that re-derives every number stated in the shipped documentation is
itself a guard, and a guard has its own defect surface. Four of its holes were
fixed in S8h; these five are recorded rather than fixed, because the release is
otherwise finished and each is a narrowing of coverage rather than a false pass
on anything currently written.

1. **`sdk/README.md:38`'s "The 36 card shapes" is a bare scalar.** Changing it to
   40 leaves the suite green. The only `(36, 540)` claim the scan verifies lives
   in `foxy_audit/__init__.py`. This is the documented boundary — the scan
   extracts PAIRS — but it means the same figure is checked in one file and not
   in the other. Fix: reword the README sentence to state the pair.

2. **`_SCALARS` is dead.** It lost its last consumer when the "both halves are
   measured" escape hatch was removed in S8f, and now appears only at its own
   definition. Fix: delete it.

3. **`len(shipped) > 20` is toothless.** The sweep covers 60 files now that tests
   are included, so the bound has 40 files of slack. S8f's own commit message
   says "a bound with that much slack is not a bound"; the rule applies here.
   Fix: assert the real count, as `test_the_scan_actually_finds_the_claims` does.

4. **The is-this-inside-a-URL window is 60 characters.** A legitimate URL whose
   path segment sits further than that from its scheme is not recognised, so a
   `docs/...` inside it would be reported as dangling. Measured: a URL with 82
   characters between `https://` and `docs/` false-flags. No such URL is in the
   tree today. Fix: scan back to whitespace rather than a fixed window.

5. **The claim count is asserted as `== 22`** and will need a deliberate edit
   whenever a documentation sentence is added or removed. That is intentional —
   a floor was what let a regression through in S8f — but it is friction, and it
   is worth knowing before someone widens it back to `>=`.

---

## #222 — two `conftest.py` files are importable as the same top-level module

**Found 2026-08-16, while fixing a sibling of it.** `pytest sdk/tests
sdk/tests_testbed` — the combined run a developer types, and which CI never does
because it runs the two as separate steps — used to fail at COLLECTION, because
`sdk/tests/test_cli.py` (the `foxy doctor` tests, there since July) and
`sdk/tests_testbed/test_cli.py` (T1's REPL suite) share a basename and neither
directory is a package. That half is fixed: the testbed one is now
`test_repl.py`.

Underneath it sits the same defect one level down. `sdk/conftest.py` defines
`snapshot_dispatcher_paths` / `rollback_dispatcher_paths`, and
`sdk/tests_testbed/conftest.py` is a second file importable under the same
top-level name `conftest`. In a combined run the bare `import conftest` in
`test_response_policy.py::test_the_shared_dispatcher_does_not_hoard_dead_spool_paths`
resolves to the testbed one, which does not define those helpers.

**Measured on `59085de` + the rename:** combined run is `1 failed, 859 passed`;
that test alone passes; both suites separately are 635 and 225.

⚠ **Why it matters more than a red developer run.** The helpers it cannot reach
are the ones that roll back the module-level dispatcher's spool paths — the
guard's own docstring records 69 stale paths accumulating over 223 tests before
that teardown existed. A collision that silently disarms an isolation helper is
how that comes back.

**Shape of the fix.** Make the helpers importable by an unambiguous name rather
than by `conftest` — a small `sdk/tests/_dispatcher_paths.py` (or the same under
`sdk/`) that both conftests and the test import — or make the two directories
packages so pytest addresses them by dotted path. Do not simply rename the
second `conftest.py`; pytest requires that name.

⚠ **The general rule, now twice paid for:** two files with the same basename and
no package boundary are one file to Python's import system. That applies to
`conftest.py` as much as to `test_cli.py`, and it applies across sibling test
directories that CI happens to run separately.
