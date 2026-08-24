"""Every NUMBER stated in the shipped docs, re-derived from the corpora.

⚠ WHY THIS FILE EXISTS, AND WHY IT SCANS RATHER THAN LISTS.

1.9.0's review found four separate figures that no code produced: "90 of 450
real PAN shapes" (measured 108 of 540), "2 627" (2 623), "0.639" (0.642), and a
"60 of 60" whose corpus was defined and then never read by anything. Three of
them survived a verification pass that "checked the numbers by script", because
that script checked the numbers someone had remembered to list.

So this does the opposite. It EXTRACTS every figure-shaped claim from the shipped
documentation and requires each one to match a measurement — a figure nobody
thought to list still has to be true, and a figure that drifts fails here rather
than shipping to PyPI. `test_the_scan_actually_finds_the_claims` is the control
that stops the extraction quietly matching nothing.

The docs are the product here: `sdk/README.md` IS the PyPI long description, and
`__init__.py`'s changelog block is what a developer reads at the REPL. A wrong
number in either is a wrong number in an audit product's own description of
itself.

⚠ THE RULE THIS IMPOSES ON THE PROSE, and the guard's one real boundary:
**state a figure as a PAIR.** "33 in 20 000", "504 of 540", "2 849 in 10 057"
and "90 -> 0" are extracted and checked; a bare "33" standing alone in a
sentence is not, because a scan treating every integer in a comment as a claim
would flag issue numbers, regex repetitions and version strings until nobody
read it. Three figures were reworded into pairs rather than left uncovered --
measured by planting a drift in each and requiring this file to fail. If you
write a new number in these files, write it with its denominator.
"""

from __future__ import annotations

import collections
import importlib.util
import itertools
import re
import sys
from pathlib import Path

import pytest

from foxy_audit import pii, ruleset

REPO = Path(__file__).resolve().parents[2]
FIXTURES = Path(__file__).resolve().parent / "fixtures"

#: ⚠ THIS FILE SHIPS, AND THE THINGS IT READS DO NOT ALL SHIP WITH IT.
#:
#: The sdist puts 23 files — this one among them — at ``<pkg>/tests/``, so
#: ``REPO`` resolves to the unpacked tarball root, where there is no ``sdk/`` and
#: no ``docs/``. Verified by building the tarball and running pytest inside it:
#: five tests here raised FileNotFoundError or asserted on an empty sweep.
#:
#: A customer running the suite from a release deserves a clean skip and a
#: reason, not a traceback from an audit product's own tests. The MEASUREMENTS
#: still run — they need only the corpora and the installed package — because
#: those are the tests that say the detectors work; it is the documentation
#: cross-checks that have nothing to read.
_IN_A_REPO_CHECKOUT = (REPO / "sdk" / "README.md").is_file()

needs_checkout = pytest.mark.skipif(
    not _IN_A_REPO_CHECKOUT,
    reason="cross-checks the repository's documentation, which the sdist does "
           "not carry (docs/ and sdk/ live at the repo root). The measurements "
           "in this file still run.")

#: The files whose numbers ship. README goes to PyPI; the changelog block is read
#: at the REPL; pii.py's header is what the next person to touch the detectors
#: reads; the frozen module explains a version rows will name forever.
#: ⚠ THE FROZEN MODULES ARE GLOBBED, NOT LISTED. Written as a hand-list this
#: named v2026_08_3 alone, so when 1.11.0 minted v2026_08_4 — a module whose
#: docstring states 2 016, 621, 10.08%, 3.10% and 504 of 540, and which ships in
#: the wheel forever — every one of those numbers went unscanned. Each new
#: version would have had to be remembered here, which is the failure mode this
#: whole file exists to remove.
_FROZEN = sorted(
    "sdk/src/foxy_audit/rulesets/" + p.name
    for p in (REPO / "sdk/src/foxy_audit/rulesets").glob("v2026_*.py")
) if _IN_A_REPO_CHECKOUT else []

DOC_FILES = [
    "sdk/README.md",
    "sdk/src/foxy_audit/__init__.py",
    "sdk/src/foxy_audit/pii.py",
    *_FROZEN,
    "docs/known-issues.md",
]


def _load(name: str, filename: str):
    full = f"foxy_audit._{name}"
    if full in sys.modules:
        return sys.modules[full]
    spec = importlib.util.spec_from_file_location(full, FIXTURES / filename)
    module = importlib.util.module_from_spec(spec)
    sys.modules[full] = module
    spec.loader.exec_module(module)
    return module


CORPORA = _load("identifier_corpora", "identifier_corpora.py")
OLD_PII = _load("pii_1_8_0", "pii_1_8_0.py")
EVASIONS = _load("injection_evasion_corpus", "injection_evasion_corpus.py")


# ── the historical boundaries, as data ───────────────────────────────────────
# The two intermediate variants exist nowhere in the code — they were replaced.
# The SHIPPED row is read from the live module, so the row that matters is a
# measurement of the real thing rather than a restatement of it.
def _luhn(digits: str) -> bool:
    if not (13 <= len(digits) <= 19):
        return False
    total = 0
    for index, char in enumerate(reversed(digits)):
        value = int(char)
        if index % 2 == 1:
            value *= 2
            if value > 9:
                value -= 9
        total += value
    return total % 10 == 0


_VARIANTS = {
    "1.8.0": (OLD_PII._CARD_CANDIDATE_RE, _luhn),
    "letters+hyphen (S8)": (
        re.compile(r"(?<![0-9A-Za-z\-])(?:\d[ \-]?){13,19}(?![0-9A-Za-z\-])"), _luhn),
    "letters only  (S8b)": (
        re.compile(r"(?<![0-9A-Za-z])\d(?:[ \-]?\d){12,18}(?![0-9A-Za-z])"), _luhn),
    # ⚠ THE PRE-S10 GATE IS SPELLED OUT, not read from the live module. It used
    # to be the "filled from the live module" row, and 2026.08.4 silently
    # redefined what that row measured — the table then showed the NEW gate under
    # the OLD row's name and the delta the change bought vanished. A superseded
    # row is history and has to be written down like history.
    "[1-9] lead + luhn": (
        re.compile(r"(?<![0-9A-Za-z])[1-9](?:[ \-]?\d){12,18}(?![0-9A-Za-z])"),
        lambda d: len(set(d)) > 1 and _luhn(d)),
    "+ assigned IIN (S10)": (None, None),       # filled from the live module
}


def _card_hits(regex, gate, text: str) -> bool:
    return any(gate(re.sub(r"\D", "", m.group())) for m in regex.finditer(text))


#: The gates that were actually SHIPPED, oldest first. The other rows in
#: _VARIANTS are candidates that were measured and rejected, so they are not
#: eras and no document compares to them.
_SHIPPED_ERAS = ("1.8.0", "[1-9] lead + luhn", "+ assigned IIN (S10)")

#: Consecutive transitions, plus first-to-last: the comparisons a release note
#: legitimately draws.
_ERA_PAIRS = tuple(zip(_SHIPPED_ERAS, _SHIPPED_ERAS[1:])) + (
    (_SHIPPED_ERAS[0], _SHIPPED_ERAS[-1]),)

#: The row measured from the SHIPPED module rather than from a copy of it. One
#: name, in one place: when the next version supersedes this gate, this string
#: moves to the new row and the old one is spelled out in _VARIANTS above.
_LIVE_ROW = "+ assigned IIN (S10)"


def _variant(name):
    if name == _LIVE_ROW:
        return pii._CARD_CANDIDATE_RE, pii._is_card_number
    return _VARIANTS[name]


def _detected(module, corpus, label):
    return {t for t in corpus if label in module.detect_pii(t, "")}


# ── every figure, measured ───────────────────────────────────────────────────
def measured() -> dict:
    """Every figure the docs may state, keyed by a name, computed from scratch.

    Pairs are ``(numerator, denominator)`` so an ``N of M`` or ``N/M`` claim can
    be matched whole — a claim that gets the denominator right and the numerator
    wrong is the failure mode that shipped ("the same 540 card shapes").
    """
    pans, phones = CORPORA.PAN_SHAPES, CORPORA.PHONE_SHAPES
    new_cards = _detected(pii, pans, "credit_card")
    old_cards = _detected(OLD_PII, pans, "credit_card")

    figures = {
        "card recall (1.9.0)": (len(new_cards), len(pans)),
        "card recall (1.8.0)": (len(old_cards), len(pans)),
        "phone recall (1.9.0)": (len(_detected(pii, phones, "phone")), len(phones)),
        "shapes both miss": (len(pans) - len(new_cards), len(pans)),
        # The uniform-digit rule S8c briefly shipped, measured on the genuinely
        # dialable shapes ONLY — the figure item 4 of the S8e review corrected.
        "dialable lost to the uniform rule": (
            sum(1 for t in CORPORA.DIALABLE_PHONE_SHAPES
                if pii._PHONE_RE.search(t)
                and not any(len(set(re.sub(r"\D", "", m.group()))) > 1
                            for m in pii._PHONE_RE.finditer(t))),
            len(CORPORA.DIALABLE_PHONE_SHAPES)),
    }

    for population, corpus in (("sha256", CORPORA.SHA256_DIGESTS),
                               ("random uuid", CORPORA.RANDOM_UUIDS),
                               ("zero-heavy", CORPORA.ZERO_HEAVY),
                               ("zero-heavy strict", CORPORA.ZERO_HEAVY_STRICT),
                               ("hyphenated ids", CORPORA.HYPHENATED_IDS)):
        for name, (regex, gate) in ((n, _variant(n)) for n in _VARIANTS):
            figures[f"{population} / {name}"] = (
                sum(1 for t in corpus if _card_hits(regex, gate, t)), len(corpus))

    for name, corpus in (("PAN_SHAPES", pans), ("PHONE_SHAPES", phones),
                         ("DIALABLE_PHONE_SHAPES", CORPORA.DIALABLE_PHONE_SHAPES),
                         ("SHA256_DIGESTS", CORPORA.SHA256_DIGESTS),
                         ("RANDOM_UUIDS", CORPORA.RANDOM_UUIDS),
                         ("ZERO_HEAVY", CORPORA.ZERO_HEAVY),
                         ("ZERO_HEAVY_STRICT", CORPORA.ZERO_HEAVY_STRICT),
                         ("HYPHENATED_IDS", CORPORA.HYPHENATED_IDS)):
        figures[f"corpus size {name}"] = (len(corpus), None)

    for name, (regex, gate) in ((n, _variant(n)) for n in _VARIANTS):
        found = sum(1 for t in pans if _card_hits(regex, gate, t))
        figures[f"PAN recall / {name}"] = (found, len(pans))
        # The other way the docs phrase it: what a variant MISSED. "missed 108 of
        # the 540" is the sentence that corrected "90 of 450", and it was
        # invisible to the scan until the connector learned "of THE".
        figures[f"PAN missed / {name}"] = (len(pans) - found, len(pans))

    # ⚠ THE CROSS-PAIRINGS THE DOCS ACTUALLY WRITE, derived rather than allowed.
    #
    # An earlier version let any ratio through whose halves were both measured
    # numbers. That escape hatch accepted "the same 540 of 540 card shapes" —
    # the EXACT defect this file was written to catch — because 540 is a real
    # measurement twice over. So every legitimate pairing is now enumerated FROM
    # the measurements: "N in M" against a corpus size, and "before -> after"
    # between the two eras.
    populations = {
        "sha256": CORPORA.SHA256_DIGESTS,
        "random uuid": CORPORA.RANDOM_UUIDS,
        "zero-heavy": CORPORA.ZERO_HEAVY,
        "zero-heavy strict": CORPORA.ZERO_HEAVY_STRICT,
        "hyphenated ids": CORPORA.HYPHENATED_IDS,
    }
    for population, corpus in populations.items():
        for name in _VARIANTS:
            count = figures[f"{population} / {name}"][0]
            figures[f"{population} / {name} in corpus"] = (count, len(corpus))
        # ⚠ DERIVED FROM THE ERA LIST, NOT ONE HARDCODED TRANSITION. This was
        # `1.8.0 -> [1-9] lead + luhn`, written when there were two eras — so
        # 2026.08.4's "2 016 -> 621" was a legitimate sentence the scan had no
        # measurement for, and the only way to state it was to stop stating it.
        # Every transition between CONSECUTIVE shipped gates is a comparison the
        # docs may make; the rejected candidates (S8, S8b) never shipped and
        # form no era, which keeps this from becoming an escape hatch.
        for before, after in _ERA_PAIRS:
            figures[f"{population} {before} -> {after}"] = (
                figures[f"{population} / {before}"][0],
                figures[f"{population} / {after}"][0])

    # Detection ERAS, the other way a doc phrases a comparison.
    figures["card recall 1.8.0 -> shipped"] = (len(old_cards), len(new_cards))
    figures["shapes missed, both eras"] = (
        len(pans) - len(old_cards), len(pans) - len(new_cards))

    # ── the injection obligation set (SDK #230, ruleset 2026.08.5) ───────────
    #
    # ⚠ MEASURED BOTH WAYS, AND THE "BEFORE" IS A REPLAY, NOT A MEMORY.
    # v2026_08_5.py's docstring states what the corpus scored under the version
    # it supersedes. Reading that from a comment would make it exactly the kind
    # of number this file exists to catch, so it is re-derived by replaying the
    # FROZEN 2026.08.4 definition — the rules that really ran — against the same
    # prompts. If a future mint quietly reaches an evasion or loses a benign
    # prompt, the frozen docstring stops being true and this fails.
    figures.update(_injection_figures())
    return figures


def _injection_figures() -> dict:
    """The evasion / benign / already-caught counts, live and under 2026.08.4."""
    from foxy_audit import introspect, policy, ruleset as rules

    previous = rules.load("2026.08.4")

    def live(text, tag="default"):
        return {r for r in policy.evaluate(text, tag).rules
                if r.startswith("injection.")}

    def before(text, tag="default"):
        return {m.rule_id for m in introspect.replay(previous, text, tag)
                if m.rule_id.startswith("injection.")}

    def fires_anywhere(check, text):
        """Under EVERY tag the benign claim covers, not just the default one.

        ``hipaa`` adds the personal-data family; only ``injection.*`` ids are
        counted, so a benign prompt is clean here or it is a false positive.
        """
        return bool(check(text, "default") or check(text, "hipaa"))

    evasions = EVASIONS.EVASIONS
    benign = EVASIONS.BENIGN
    caught = EVASIONS.ALREADY_CAUGHT

    return {
        "evasions caught (2026.08.5)": (
            sum(1 for e in evasions if live(e.prompt)), len(evasions)),
        "evasions caught (2026.08.4)": (
            sum(1 for e in evasions if before(e.prompt)), len(evasions)),
        "benign false positives (2026.08.5)": (
            sum(1 for b in benign if fires_anywhere(live, b.prompt)), len(benign)),
        "benign false positives (2026.08.4)": (
            sum(1 for b in benign if fires_anywhere(before, b.prompt)),
            len(benign)),
        "already-caught phrasings still firing": (
            sum(1 for rule_id, text in caught if rule_id in live(text)),
            len(caught)),
    }


MEASURED = measured()

#: Every value a claim may state: each numerator, each denominator, and each
#: ``N of M`` pair. Spaces inside numbers ("2 849") are normalised away.
_SCALARS = {n for n, _ in MEASURED.values()} | {
    d for _, d in MEASURED.values() if d is not None}
_PAIRS = {(n, d) for n, d in MEASURED.values() if d is not None}

#: Numbers that appear in the docs and are NOT measurements of a corpus. Each is
#: enumerated with a reason, so the exemption list cannot quietly absorb a real
#: claim — the same discipline as policy.py's free-string tag allowlist.
#: ⚠ PAIRS ONLY. ``_claims()`` yields ``(int, int)`` and nothing else, so a
#: ``(N, None)`` key here can never match — nine of them sat unreachable,
#: 17 of 19 entries dead, and the list read as if it were doing work. An
#: exemption nobody can trip is indistinguishable from one nobody needs, and
#: ``test_every_exemption_is_reachable`` now fails on a dead entry rather than
#: letting the list rot.
#: Eight entries were removed the moment reachability was asserted. Three
#: ("1.9.0", "1.8.0", "2026.08.x") became unnecessary when ``_NUMBER`` learned to
#: refuse a digit adjacent to a dot; four regex repetitions ({12,18} and friends)
#: were never reachable because a comma is not a connector; one was the second
#: half of a pair the non-overlapping scan can never produce. Every survivor is
#: tripped by a real sentence.
_NOT_A_MEASUREMENT = {
    (96, 168): "a SUPERSEDED figure, quoted in pii.py as the wrong one it was",
    (555, 111): "phone-number literals in prose (\"reserved 555/111/222 numbers\")",
}

#: How many figure claims the shipped docs make. ONE definition, used by both
#: the assertion and its failure message — they were two literals, and the
#: message still said 22 after the assertion moved to 39, so the guard that
#: exists to catch a stale number was itself telling readers a stale one.
#: 40 -> 45 when ruleset 2026.08.5 was minted. The five new claims are all in
#: `v2026_08_5.py`'s docstring and all in `_injection_figures()`: 8 of 10
#: evasions caught, 0 of 10 under the version it supersedes, 0 of 47 benign
#: prompts firing under each, and 5 of 5 older phrasings still firing.
_EXPECTED_CLAIMS = 45

#: ``N of M``, ``N/M`` and ``N -> M``: the three shapes a figure claim takes in
#: these files. Numbers may carry thin-space grouping ("2 849", "20 000").
#: A grouped number is 1-3 digits plus AT LEAST ONE space-separated 3-digit
#: group ("2 849", "20 000"), with an ordinary or a no-break space.
#:
#: ⚠ THE "+" IS LOAD-BEARING. Written as ``\d[\d ]*\d`` the class ran greedily
#: across a whole table row: "504/540 90 33 2849 2457 2016" parsed as ONE
#: 19-digit denominator, so four table rows reported as four unexplained claims
#: while their real columns were never compared to anything. The extractor's own
#: shape is part of what this file has to get right.
#: ⚠ AND IT MUST NOT STRADDLE A DOTTED VERSION. Without the lookarounds,
#: "2026.08.3 ... during 1.9.0" extracted as the claim 3/1 -- the connector
#: happily spanning two version strings. Excluding a digit adjacent to a dot
#: also retires three exemptions that existed only to absorb "1.9.0", "1.8.0"
#: and "2026.08.x".
#: ⚠ THE TRAILING LOOKAHEAD IS TWO CHECKS, NOT ONE, AND THE ONE-CHECK VERSION
#: BROKE MORE THAN IT FIXED. Written as ``(?![.\d])`` to keep the scan from
#: straddling a dotted version, it also refused every figure whose denominator
#: ENDED A SENTENCE -- "999 of 540." extracted as nothing at all, so a planted
#: drift in that shape passed all ten tests, and the exact-count control could
#: not see it either because a sentence that never matches does not change the
#: count. It also made a space-grouped number backtrack to its first group:
#: "2 853 in 10 057." read as the phantom claim (2853, 10).
#:
#: What separates a version from a sentence-ending period is what FOLLOWS the
#: dot: "1.9.0" is dot-then-digit, "540." is dot-then-space-or-end. So the test
#: is "not followed by a digit, and not followed by a dot AND a digit" --
#: which keeps 2026.08.3 and 1.9.0 out while letting 540. and 10 057. in.
_NUMBER = r"(?<![\d.])" + r"(?:\d{1,3}(?:[  ]\d{3})+|\d+)" + r"(?!\d)(?!\.\d)"
#: The connector between the two numbers. ``/`` and ``->`` sit directly between
#: them; ``of`` and ``in`` may carry filler on EITHER SIDE.
#:
#: ⚠ BOTH SIDES, AND THE SECOND HALF WAS MISSING. Filler was allowed before the
#: preposition ("5 random UUIDs in 20 000") but not after, so the ordinary
#: English form "108 of THE 540" was invisible — including on the very figure
#: this file was written to correct, and on "36 of the 540" two lines below it.
#: Verified before the fix: rewriting it to "999 of the 540" left all eight
#: tests green. A guard that misses the claim it exists for is worse than none,
#: because it certifies it.
_FILLER = r"(?:[A-Za-z][A-Za-z'-]*\s+){0,4}"
_CONNECTOR = (r"(?:\s*(?:/|->)\s*|\s+" + _FILLER + r"(?:of|in)\s+" + _FILLER + ")")
_CLAIM = re.compile("(" + _NUMBER + ")" + _CONNECTOR + "(" + _NUMBER + ")")


def _num(raw: str) -> int:
    return int(raw.replace(" ", "").replace(" ", ""))


def _claims():
    """Every (numerator, denominator, file, snippet) figure claim in the docs."""
    found = []
    for rel in DOC_FILES:
        text = (REPO / rel).read_text(encoding="utf-8")
        for match in _CLAIM.finditer(text):
            start = max(0, match.start() - 45)
            found.append((_num(match.group(1)), _num(match.group(2)), rel,
                          " ".join(text[start:match.end() + 15].split())))
    return found


# ── the guards ───────────────────────────────────────────────────────────────
@needs_checkout
def test_every_figure_claim_in_the_docs_is_one_the_code_produces():
    """⚠ THE DELIVERABLE. Scanned, not listed.

    Each ``N of M`` / ``N/M`` / ``N -> M`` in the shipped docs must be a pair
    this module measures, or an enumerated non-measurement. A number nobody
    remembered to check still has to be true.
    """
    unexplained = []
    for numerator, denominator, rel, snippet in _claims():
        if (numerator, denominator) in _PAIRS:
            continue
        if (numerator, denominator) in _NOT_A_MEASUREMENT:
            continue
        unexplained.append(f"{rel}: {numerator}/{denominator} — ...{snippet}...")
    assert not unexplained, (
        "figure(s) stated in the shipped docs that no measurement produces:\n  "
        + "\n  ".join(unexplained)
        + "\n\nEither the code changed and the sentence did not, or the sentence "
          "was never measured. Re-derive it in measured(), or add it to "
          "_NOT_A_MEASUREMENT with a reason if it is not a measurement at all.")


@needs_checkout
def test_the_scan_actually_finds_the_claims():
    """CONTROL. An extractor that matches nothing passes the test above.

    Pinned against the specific claims this release makes, in the specific files
    that ship them, so a regex that stops matching fails here rather than
    reporting a clean sweep.
    """
    claims = _claims()
    # ⚠ THE EXACT COUNT, not a floor. A floor of 10 against a real 22 let the
    # connector lose its filler clause — the precise regression the comment
    # beside _CONNECTOR documents as having happened — while both this control
    # and the guard stayed green, because 19 is still >= 10. A bound with that
    # much slack is not a bound; it is the absence of one, written confidently.
    #
    # If this number moves, a sentence was added or removed. Read the diff and
    # update it deliberately; do not widen it.
    #
    # 22 -> 39 in 1.11.0 (S10). The release note states four before/after
    # measurements in the README and again in the changelog block, pii.py's card
    # table gained a fifth row and a re-derived cost sentence, and the README
    # gained a 1.11.0 section. Every one of the 17 new claims was checked against
    # measured() by the guard above before this line was moved.
    assert len(claims) == _EXPECTED_CLAIMS, (
        f"the extractor finds {len(claims)} claims, expected {_EXPECTED_CLAIMS}. "
        f"A doc sentence "
        f"was added or removed, or the extractor stopped matching a form: "
        f"{sorted((n, d, rel) for n, d, rel, _ in claims)}")

    files = {rel for _, _, rel, _ in claims}
    assert "sdk/README.md" in files, "the PyPI long description is not being read"
    assert "sdk/src/foxy_audit/pii.py" in files, "the detector header is not read"
    pairs = {(n, d) for n, d, _, _ in claims}
    for pair, why in [((504, 540), "the headline card figure"),
                      ((60, 60), "the dialable-phone figure"),
                      ((108, 540), "the 'N of THE M' form"),
                      ((36, 540), "the 'N of the M' form, second instance"),
                      ((5, 20000), "the 'N <words> in M' form")]:
        assert pair in pairs, f"{why} ({pair[0]}/{pair[1]}) is not being extracted"


def test_a_planted_drift_is_caught():
    """CONTROL for the control. The check must be able to FAIL.

    A guard that only ever runs against correct docs proves nothing about what it
    would do with wrong ones, so this plants the defects the reviews actually
    found and requires the extraction-plus-comparison to reject each.

    ⚠ ASSERTED AS THE GUARD'S OWN PREDICATE, not as two facts about a tuple. The
    previous version asserted ``pair not in _PAIRS`` and then, on the next line,
    ``not (... and pair in _PAIRS)`` — implied by the first and unable to fail,
    so the property it meant to show (that the guard REJECTS the planted claim)
    was never asserted at all.
    """
    def rejected(text):
        """What test_every_figure_claim... would conclude about this sentence."""
        found = _CLAIM.search(text)
        assert found, f"the extractor does not even read {text!r}"
        pair = (_num(found.group(1)), _num(found.group(2)))
        return pair not in _PAIRS and pair not in _NOT_A_MEASUREMENT

    # The S8e defect: a plausible figure whose halves are both real measurements.
    assert rejected("the same 540 of 540 card shapes")
    # The S8g defect: the "of THE" form, on the very figure it corrects.
    assert rejected("missed 999 of the 540 obligation shapes")
    # An ordinary drift.
    assert rejected("2 853 in 10 057 zero-heavy ids")

    # ...and the CONTROL for the control: a TRUE sentence must be accepted, or
    # `rejected` could simply be returning True.
    assert not rejected("missed 108 of the 540 obligation shapes")
    assert not rejected("504 of 540 card shapes")


@needs_checkout
def test_every_exemption_is_reachable():
    """CONTROL. An exemption nobody can trip is one nobody needs.

    ``_claims()`` yields ``(int, int)`` only, so a ``(N, None)`` key could never
    match — nine sat unreachable and 17 of 19 entries were dead, while the list
    read as though it were carrying the file's judgement calls. Every entry must
    now be a pair the extractor can actually produce.
    """
    for pair, reason in _NOT_A_MEASUREMENT.items():
        assert isinstance(pair, tuple) and len(pair) == 2, pair
        assert all(isinstance(half, int) for half in pair), (
            f"{pair} can never match: _claims() yields (int, int) only")
        assert reason.strip(), f"{pair} needs a stated reason"

    # And each one is REACHED by the current docs — an exemption for a sentence
    # that no longer exists is dead weight that hides the next real claim.
    live = {(n, d) for n, d, _, _ in _claims()}
    unused = set(_NOT_A_MEASUREMENT) - live
    assert not unused, (
        f"exemption(s) nothing in the docs trips: {sorted(unused)}. The sentence "
        f"they excused is gone; remove them so the list stays readable.")


@needs_checkout
def test_the_card_table_in_pii_py_is_re_measured_row_by_row():
    """The table is five variants x six columns of stated numbers.

    Parsed out of the module's own comment and re-measured, so a row cannot go
    stale while the prose around it stays confident. The SHIPPED row is measured
    from the LIVE module, not from a copy of its pattern.
    """
    source = (REPO / "sdk/src/foxy_audit/pii.py").read_text(encoding="utf-8")
    populations = [CORPORA.SHA256_DIGESTS, CORPORA.RANDOM_UUIDS,
                   CORPORA.ZERO_HEAVY, CORPORA.ZERO_HEAVY_STRICT,
                   CORPORA.HYPHENATED_IDS]
    seen = 0
    for name in _VARIANTS:
        row = [l for l in source.splitlines() if l.startswith(f"#   {name}")]
        assert len(row) == 1, f"{name}: found {len(row)} table rows, expected 1"
        stated = [int(n) for n in re.findall(r"\d+", row[0][len(name) + 4:])]

        regex, gate = _variant(name)
        expected = [sum(1 for t in CORPORA.PAN_SHAPES if _card_hits(regex, gate, t)),
                    len(CORPORA.PAN_SHAPES)]
        expected += [sum(1 for t in pop if _card_hits(regex, gate, t))
                     for pop in populations]
        assert stated == expected, (
            f"{name}: the table states {stated}, the corpora measure {expected}"
            f" -- row: {row[0]}")
        seen += 1
    assert seen == len(_VARIANTS), f"re-measured only {seen} rows"


def test_the_dialable_phone_corpus_is_actually_READ():
    """DIALABLE_PHONE_SHAPES was defined, cross-referenced, and read by nothing.

    The "60 of 60" figure in four source files was produced by no code at all —
    the corpus existed and the number beside it was a memory. This is the code
    that produces it.
    """
    numerator, denominator = MEASURED["dialable lost to the uniform rule"]
    assert denominator == len(CORPORA.DIALABLE_PHONE_SHAPES) == 60
    assert numerator == 60, (
        f"the uniform-digit rule would lose {numerator} of {denominator} shapes "
        f"built from genuinely dialable repeated-digit numbers; the docs say 60")

    # ...and every one of them is detected by what actually shipped.
    lost_now = [t for t in CORPORA.DIALABLE_PHONE_SHAPES
                if "phone" not in pii.detect_pii(t, "")]
    assert not lost_now, lost_now


def test_the_36_missed_shapes_are_all_issue_219():
    """docs/known-issues.md says so; this is what makes it a measurement.

    An earlier draft said "the letter-glued ones plus these", which was wrong in
    both halves — there is no letter-glued context in the obligation set at all.
    """
    missed = set(CORPORA.PAN_SHAPES) - _detected(pii, CORPORA.PAN_SHAPES, "credit_card")
    assert len(missed) == 36
    assert missed == set(CORPORA.PAN_SHAPES) - _detected(
        OLD_PII, CORPORA.PAN_SHAPES, "credit_card"), "1.8.0 misses a different set"

    contexts = collections.Counter()
    for text in missed:
        for pan, sep in itertools.product(CORPORA.REAL_PANS, ["", " ", "-"]):
            grouped = (sep.join(pan[i:i + 4] for i in range(0, len(pan), 4))
                       if sep else pan)
            if grouped in text:
                contexts[text.replace(grouped, "{}")] += 1
                break
    # The SPLIT, not just the set. docs/known-issues.md states "18 ... and 18",
    # and a planted 20/16 slipped past the set-only version of this assertion.
    assert dict(contexts) == {"item 1 {}": 18, "line 12 {}": 18}, dict(contexts)

    # ⚠ THE MEASUREMENT ABOVE RUNS EVERYWHERE; only the DOC cross-check needs a
    # repository. Guarded inline rather than by marking the whole test, because
    # "do the detectors still miss exactly these 36 shapes?" is worth answering
    # from an unpacked release — it is the part that says what the code does.
    if not _IN_A_REPO_CHECKOUT:
        pytest.skip("docs/known-issues.md is not in the sdist; the measurement "
                    "above ran, only the cross-check against its prose is skipped")

    stated = (REPO / "docs/known-issues.md").read_text(encoding="utf-8")
    for context, count in contexts.items():
        marker = context.replace(" {}", "").strip()
        assert f"{count} `{marker} <PAN>`" in stated, (
            f"docs/known-issues.md does not state {count} for {marker!r}; "
            f"measured {dict(contexts)}")


#: Directories that exist in the repository but NOT in the published sdist,
#: which contains ``sdk/`` alone (see pyproject's wheel/sdist configuration).
#: A shipped file naming one of these resolves to nothing for a reader on PyPI.
_NOT_IN_THE_SDIST = ("docs/", "backend/", "desktop/", "verifier/", "demo/",
                     "foxy-dashboard/", "foxy-adminpage/", "foxy-sale-page/",
                     "contracts/", "deploy/", "e2e/")


#: ⚠ THE PRIVATE REPOSITORY HOST. pyproject.toml records it plainly: "The
#: repository is `fatimaatta-09` and is PRIVATE, so no GitHub URL can be a public
#: route", which is why Source/Issues were dropped from the project metadata.
#:
#: A URL to it in a shipped file is an ACTIVE 404 on the public PyPI page —
#: strictly worse than the inert `docs/` reference it replaced. This release
#: shipped two of them, in README.md and the frozen ruleset module, because a
#: reviewer and I both reached for "just link to GitHub" without re-reading the
#: file that says why there is nothing to link to. The rule outlives the release.
#:
#: ⚠ EVERY FORM, CASE-INSENSITIVELY. The first version was an exact-string
#: match on the lower-case HTTPS path form, so a capitalised spelling or an SSH
#: clone line walked straight past it. A guard that catches only the exact
#: spelling of the mistake already made is a record of that mistake, not a
#: defence against the next one. ``[/:]`` covers both the HTTPS path separator
#: and the SSH ``user@host:owner`` colon; the optional prefix covers a scheme,
#: a ``www.`` and a bare mention someone would paste into a browser.
#:
#: The forms are deliberately NOT spelled out above: this file ships, and the
#: guard would then report its own examples — which it did, correctly, the first
#: time this comment named them.
_PRIVATE_HOST_RE = re.compile(
    r"(?:git@|https?://|www\.)?github\.com[/:]fatimaatta-09[^\s)\"'`]*",
    re.IGNORECASE)

#: A line carrying this is the guard DEFINING what it forbids, not a link to it.
_HOST_DEFINITION = "_PRIVATE_HOST_RE = re.compile("


def _shipped_files():
    """Every file the sdist carries.

    ⚠ INCLUDING tests/. An earlier version excluded them "because tests are not
    in the sdist" — they are: building the tarball and unpacking it shows 23
    files under ``tests/``, 18 of them test modules, plus 6 more under
    ``tests_testbed/``. A comment asserting the opposite is how the exclusion
    survived; an earlier draft of THIS comment said "29 test files", which was
    the two directories added together and therefore neither number.
    """
    for path in sorted((REPO / "sdk").rglob("*")):
        if not path.is_file() or path.suffix not in (".py", ".md", ".toml"):
            continue
        rel = path.relative_to(REPO).as_posix()
        if "__pycache__" in rel:
            continue
        yield rel, path


@needs_checkout
def test_no_shipped_file_links_to_the_PRIVATE_repository():
    """⚠ THE GUARD THAT WOULD HAVE CAUGHT ME, and it is not about this release.

    Replacing a dangling `docs/` reference with a GitHub URL looks like the
    obvious fix and is the wrong one here: the repository is private, so the URL
    404s on the public PyPI page while the path it replaced merely failed to
    resolve. Worse, and shipped.

    Kept separate from the dangling-path sweep because the reasoning is
    different — that one is about the sdist's contents, this one about who can
    read the repository — and because the next person to reach for a GitHub link
    should meet a sentence explaining why there isn't one.
    """
    offenders = []
    for rel, path in _shipped_files():
        text = path.read_text(encoding="utf-8")
        for match in _PRIVATE_HOST_RE.finditer(text):
            line_start = text.rfind("\n", 0, match.start()) + 1
            line_end = text.find("\n", match.end())
            line = text[line_start:line_end if line_end != -1 else None]
            # The one exemption, and it is this file naming the host it forbids.
            # A constant is not a link; without this the guard reports itself.
            if _HOST_DEFINITION in line:
                continue
            offenders.append(f"{rel}: {match.group(0)} — {line.strip()[:80]}")
    assert not offenders, (
        "shipped file(s) linking to the PRIVATE repository:\n  "
        + "\n  ".join(offenders)
        + "\n\nThat URL is a 404 for every reader of the PyPI page. State the "
          "point inline instead; pyproject.toml explains why Source and Issues "
          "were dropped from the project metadata for the same reason.")


@needs_checkout
def test_nothing_in_the_sdist_points_at_a_file_the_sdist_lacks():
    """⚠ sdk/README.md IS THE PyPI LONG DESCRIPTION.

    The sdist contains ``sdk/`` alone, so a bare reference to ``docs/`` — which
    lives at the repository ROOT — resolves to nothing for a reader on PyPI. A
    dangling reference in the published description of an audit product is the
    wrong first impression.

    Swept over EVERY shipped file rather than a list of the ones that ship
    prose: the frozen ruleset module carried the same dangling reference as the
    README, and it was not on any list.
    """
    dangling = []
    for rel, path in _shipped_files():
        text = path.read_text(encoding="utf-8")
        for prefix in _NOT_IN_THE_SDIST:
            for match in re.finditer(re.escape(prefix) + r"[A-Za-z0-9._/\-]*", text):
                line_start = text.rfind("\n", 0, match.start()) + 1
                line_end = text.find("\n", match.end())
                line = text[line_start:line_end if line_end != -1 else None]
                # ⚠ IS THIS MATCH PART OF A URL — not "does this line mention
                # one". The substring test on the whole line is the exemption
                # that blessed the two private-repo links: any line carrying a
                # URL anywhere excused every docs/ path on it, including ones
                # that were not part of the URL at all.
                head = text[max(0, match.start() - 60):match.start()]
                if re.search(r"https?://\S*$", head):
                    continue          # this path IS inside a URL
                # ⚠ A POINTER, not a mention. `verifier/foxy_verify.py` written in
                # backticks as CONTEXT is fine — the reader is not being sent
                # anywhere. A markdown link, or a "see"/"filed as"/"tracked as",
                # invites them to follow it, and that is the thing that has to
                # resolve. Widening this to every prose path would flag six
                # correct sentences and train the next person to ignore it.
                before = text[max(0, match.start() - 30):match.start()].lower()
                is_link = text[max(0, match.start() - 2):match.start()] == "]("
                is_pointer = any(word in before for word in
                                 ("see ", "filed as", "filed at", "tracked as",
                                  "tracked at", "documented in", "listed in"))
                if not (is_link or is_pointer):
                    continue
                dangling.append(f"{rel}: {match.group(0)!r} — {line.strip()[:90]}")
    assert not dangling, (
        "shipped file(s) referencing a path the sdist does not contain:\n  "
        + "\n  ".join(dangling)
        + "\n\nA reader on PyPI cannot resolve these. Use a full GitHub URL, or "
          "state the limitation inline.")


@needs_checkout
def test_the_sdist_sweep_actually_reads_the_shipped_files():
    """CONTROL. A sweep over an empty file list passes silently."""
    shipped = dict(_shipped_files())
    assert "sdk/README.md" in shipped, "the PyPI long description is not swept"
    assert "sdk/src/foxy_audit/pii.py" in shipped
    assert "sdk/src/foxy_audit/rulesets/v2026_08_3.py" in shipped, \
        "the frozen module — which carried this exact defect — is not swept"
    # EVERY frozen module, not the one someone remembered. Each ships in the
    # wheel forever and each states numbers.
    assert len(_FROZEN) == len(ruleset.known_versions()), _FROZEN
    for rel in _FROZEN:
        assert rel in shipped, rel
    # ⚠ TESTS SHIP. Building the sdist and unpacking it shows 23 files under
    # tests/ and 6 more under tests_testbed/, so excluding them here — as an
    # earlier version did, on the strength of a comment asserting the opposite —
    # left a large part of the published tarball unswept.
    assert any(r.startswith("sdk/tests/") for r in shipped), \
        "tests ARE in the sdist and must be swept like everything else"
    assert "sdk/tests/test_stated_figures.py" in shipped
    assert len(shipped) > 20, len(shipped)
