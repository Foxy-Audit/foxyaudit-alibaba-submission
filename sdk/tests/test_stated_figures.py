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

from foxy_audit import pii

REPO = Path(__file__).resolve().parents[2]
FIXTURES = Path(__file__).resolve().parent / "fixtures"

#: The files whose numbers ship. README goes to PyPI; the changelog block is read
#: at the REPL; pii.py's header is what the next person to touch the detectors
#: reads; the frozen module explains a version rows will name forever.
DOC_FILES = [
    "sdk/README.md",
    "sdk/src/foxy_audit/__init__.py",
    "sdk/src/foxy_audit/pii.py",
    "sdk/src/foxy_audit/rulesets/v2026_08_3.py",
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
    "[1-9] lead + luhn": (None, None),          # filled from the live module
}


def _card_hits(regex, gate, text: str) -> bool:
    return any(gate(re.sub(r"\D", "", m.group())) for m in regex.finditer(text))


def _variant(name):
    if name == "[1-9] lead + luhn":
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
        figures[f"PAN recall / {name}"] = (
            sum(1 for t in pans if _card_hits(regex, gate, t)), len(pans))

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
        before = figures[f"{population} / 1.8.0"][0]
        after = figures[f"{population} / [1-9] lead + luhn"][0]
        figures[f"{population} 1.8.0 -> shipped"] = (before, after)

    # Detection ERAS, the other way a doc phrases a comparison.
    figures["card recall 1.8.0 -> shipped"] = (len(old_cards), len(new_cards))
    figures["shapes missed, both eras"] = (
        len(pans) - len(old_cards), len(pans) - len(new_cards))
    return figures


MEASURED = measured()

#: Every value a claim may state: each numerator, each denominator, and each
#: ``N of M`` pair. Spaces inside numbers ("2 849") are normalised away.
_SCALARS = {n for n, _ in MEASURED.values()} | {
    d for _, d in MEASURED.values() if d is not None}
_PAIRS = {(n, d) for n, d in MEASURED.values() if d is not None}

#: Numbers that appear in the docs and are NOT measurements of a corpus. Each is
#: enumerated with a reason, so the exemption list cannot quietly absorb a real
#: claim — the same discipline as policy.py's free-string tag allowlist.
_NOT_A_MEASUREMENT = {
    (7812, None): "ISO/IEC 7812, a standard number",
    (1, 9): "version 1.9.0",
    (1, 8): "version 1.8.0",
    (2026, 8): "ruleset 2026.08.x",
    (12, 18): "the {12,18} repetition in a regex",
    (13, 19): "the {13,19} repetition in a regex",
    (1, 3): "the {1,3} repetition in a regex",
    (3, 4): "a regex repetition",
    (16, None): "the {16,} repetition in the openai-key rule",
    (20, None): "the {20,} repetition in the bearer rule",
    (215, None): "an issue number",
    (216, None): "an issue number",
    (217, None): "an issue number",
    (218, None): "an issue number",
    (219, None): "an issue number",
    (220, None): "an issue number",
    (96, 168): "a SUPERSEDED figure, quoted in pii.py as the wrong one it was",
    (555, 111): "phone-number literals in prose (\"reserved 555/111/222 numbers\")",
    (111, 222): "the same sentence's second pair",
}

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
_NUMBER = r"(?:\d{1,3}(?:[  ]\d{3})+|\d+)"
#: The connector between the two numbers. ``/`` and ``->`` sit directly
#: between them; ``of`` and ``in`` may carry a few words of subject first —
#: "5 random UUIDs in 20 000" is a claim, and a version of this pattern that
#: required the words to be absent never extracted it at all, so the figure was
#: unchecked while the file reported a clean sweep.
_CONNECTOR = r"(?:\s*(?:/|->)\s*|\s+(?:[A-Za-z][A-Za-z'-]*\s+){0,4}(?:of|in)\s+)"
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


def test_the_scan_actually_finds_the_claims():
    """CONTROL. An extractor that matches nothing passes the test above.

    Pinned against the specific claims this release makes, in the specific files
    that ship them, so a regex that stops matching fails here rather than
    reporting a clean sweep.
    """
    claims = _claims()
    # 11 at the time of writing. The bound is a floor with headroom, not the
    # current number wearing a bound's clothes — but the real control is the
    # NAMED pairs below, because a count can be satisfied by any eleven matches.
    assert len(claims) >= 10, f"the extractor found only {len(claims)} claims"
    files = {rel for _, _, rel, _ in claims}
    assert "sdk/README.md" in files, "the PyPI long description is not being read"
    assert "sdk/src/foxy_audit/pii.py" in files, "the detector header is not read"
    pairs = {(n, d) for n, d, _, _ in claims}
    assert (504, 540) in pairs, "the headline card figure is not being extracted"
    assert (60, 60) in pairs, "the dialable-phone figure is not being extracted"


def test_a_planted_drift_is_caught():
    """CONTROL for the control. The check must be able to FAIL.

    A guard that only ever runs against correct docs proves nothing about what it
    would do with wrong ones, so this plants the exact defect the S8e review
    found — a plausible figure with the wrong numerator — and requires the
    extraction-plus-comparison to reject it.
    """
    planted = "the same 540 of 540 card shapes"
    numerator, denominator = 540, 540
    assert (numerator, denominator) not in _PAIRS, \
        "540/540 is now a real measurement; plant a different drift"
    assert not (numerator in _SCALARS and denominator in _SCALARS
                and (numerator, denominator) in _PAIRS)
    # ...and it is the shape the extractor reads.
    assert _CLAIM.search(planted).groups() == ("540", "540")


def test_the_card_table_in_pii_py_is_re_measured_row_by_row():
    """The table is four variants x six columns of stated numbers.

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
    assert seen == 4, f"re-measured only {seen} rows"


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


def _shipped_files():
    """Every file the sdist carries: sdk/ minus its tests and caches."""
    for path in sorted((REPO / "sdk").rglob("*")):
        if not path.is_file() or path.suffix not in (".py", ".md", ".toml"):
            continue
        rel = path.relative_to(REPO).as_posix()
        if "__pycache__" in rel or "/tests" in rel:
            continue
        yield rel, path


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
                if "https://" in line:
                    continue          # a full URL resolves anywhere
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


def test_the_sdist_sweep_actually_reads_the_shipped_files():
    """CONTROL. A sweep over an empty file list passes silently."""
    shipped = dict(_shipped_files())
    assert "sdk/README.md" in shipped, "the PyPI long description is not swept"
    assert "sdk/src/foxy_audit/pii.py" in shipped
    assert "sdk/src/foxy_audit/rulesets/v2026_08_3.py" in shipped, \
        "the frozen module — which carried this exact defect — is not swept"
    assert not any(r.startswith("sdk/tests") for r in shipped), \
        "tests are not in the sdist and must not be swept as if they were"
    assert len(shipped) > 20, len(shipped)
