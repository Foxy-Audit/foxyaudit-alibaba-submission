"""SDK 1.11.0 / ruleset 2026.08.4 — a card number begins with an assigned issuer.

THE DEFECT
----------
Luhn is a single check digit. Roughly one in ten random 13-19 digit runs passes
it, so the card gate — Luhn plus "not one repeated digit" — reported
``credit_card`` for 2 016 of 20 000 hyphen-delimited build ids. Under ``hipaa``
that fires ``phi.credit_card``, which BLOCKS the prompt in ``mode="block"``.

A card number is not an arbitrary Luhn-passing run. Its leading digits are an
issuer identification number assigned under ISO/IEC 7812, and the assignments
are public. Requiring one is a fact about the payment system, not a heuristic —
which is why :mod:`foxy_audit.issuer_ranges` keeps it as a table.

WHAT THESE TESTS ARE FOR
------------------------
Three separable claims, and each is guarded against a DIFFERENT way of being
wrong:

1. The gate does what it says — real PANs survive, Luhn-passing non-cards do not,
   and the numbers stated in the docs are the numbers the corpora produce. (The
   figures themselves are re-derived by ``test_stated_figures.py``; here the
   PAN set is compared as a SET, because an equal count with a different
   membership is the failure that kept recurring.)
2. Old evidence still replays under the rules that produced it. 2026.08.3 rows
   record ``luhn+distinct`` and must keep meaning Luhn-plus-not-one-repeated-
   digit, INCLUDING its acceptance of what 2026.08.4 now rejects.
3. The fences hold. The phone and digest paths were already right and are not in
   scope, so they are measured every run rather than assumed.
"""

from __future__ import annotations

import json
import re

import pytest

from foxy_audit import hashing, introspect, issuer_ranges, pii, ruleset

from fixtures import identifier_corpora as CORPORA


# ── 1. the gate ──────────────────────────────────────────────────────────────
def _card_digits(text: str):
    return [re.sub(r"\D", "", m.group())
            for m in pii._CARD_CANDIDATE_RE.finditer(text)]


def _fires(text: str) -> bool:
    return any(pii._is_card_number(d) for d in _card_digits(text))


def test_every_real_PAN_in_the_corpus_still_carries_an_assigned_iin():
    """The premise of the whole change, checked rather than assumed.

    If a test card in the obligation set did NOT start with an assigned IIN, the
    gate would drop it and the recall claim below would be measuring a corpus
    that had quietly been made agreeable.
    """
    for pan in CORPORA.REAL_PANS:
        assert issuer_ranges.starts_with_assigned_iin(pan), pan


def test_the_PAN_set_is_IDENTICAL_not_merely_the_same_size():
    """⚠ THE FAILURE THAT KEPT RECURRING WAS AN EQUAL COUNT, DIFFERENT MEMBERS.

    Three consecutive rounds of the card work reported "same recall" from a
    matching total while the set had changed underneath. So this compares sets,
    in BOTH directions, against the gate as it shipped in 1.10.0.
    """
    def shipped_1_10_0(digits):                     # Luhn + not-one-repeated-digit
        return len(set(digits)) > 1 and pii._luhn_ok(digits)

    before = {t for t in CORPORA.PAN_SHAPES
              if any(shipped_1_10_0(d) for d in _card_digits(t))}
    after = {t for t in CORPORA.PAN_SHAPES if _fires(t)}

    assert not (before - after), f"the IIN gate LOST {len(before - after)} PAN shapes"
    assert not (after - before), f"the IIN gate INVENTED {len(after - before)} shapes"
    assert len(after) == 504, len(after)


@pytest.mark.parametrize("digits,why", [
    ("8108420735282737", "MII 8 is healthcare/telecom, not a card issuer"),
    ("7992739871000004", "MII 7 is petroleum"),
    ("1234567812345670", "MII 1 is airlines"),
    ("9876543210987450", "MII 9 is national assignment"),
])
def test_a_luhn_passing_run_from_a_non_card_industry_is_rejected(digits, why):
    """The gate's whole point, one case per non-financial MII.

    Each of these PASSES Luhn and is not one repeated digit, so each was reported
    as ``credit_card`` before this change.
    """
    assert pii._luhn_ok(digits), f"{digits} must pass Luhn or it proves nothing"
    assert len(set(digits)) > 1
    assert not pii._is_card_number(digits), why


@pytest.mark.parametrize("pan", CORPORA.REAL_PANS)
def test_every_issuer_in_the_corpus_survives_the_gate(pan):
    assert pii._is_card_number(pan), f"{pan} is a real test PAN and must survive"


def test_the_zero_heavy_corpus_is_now_completely_clean():
    """0 of 10 057, which is the column the change was aimed at.

    Asserted as a NAMED consequence rather than only as a rate: the survivor the
    IIN table was chosen to exclude is spelled out, so it cannot come back
    quietly under a widened table.
    """
    survivors = [t for t in CORPORA.ZERO_HEAVY if _fires(t)]
    assert survivors == [], survivors
    # The one the `81` decision turned on, named.
    assert not _fires("00000000-0000-0819-8108-420735282737")


def test_the_issuer_table_reads_like_a_table():
    """The brief's actual requirement: a fact anyone can check, not a regex.

    Guards the SHAPE, because the value of this table is that a reader can put
    it beside an issuer's published ranges. A flat blob of prefixes with no
    network names is the same behaviour and a worse artefact.
    """
    assert set(issuer_ranges.ASSIGNED_IINS) == {
        "visa", "mastercard", "amex", "discover",
        "diners", "jcb", "unionpay", "maestro"}
    for network, prefixes in issuer_ranges.ASSIGNED_IINS.items():
        assert prefixes, network
        assert all(p.isdigit() for p in prefixes), network
    # The 2-series is the one a hand-written table forgets: Mastercard has issued
    # from 2221-2720 since 2017, and a card in that range is not exotic.
    assert "2221" in issuer_ranges.ASSIGNED_IINS["mastercard"]
    assert "2720" in issuer_ranges.ASSIGNED_IINS["mastercard"]
    assert pii._is_card_number("2223003122003222"), "a real 2-series Mastercard"


def test_81_is_absent_and_recorded_as_a_deliberate_false_negative():
    """⚠ A DELIBERATE EXCLUSION MUST NOT LOOK LIKE AN OVERSIGHT — AND THE REASON
    RECORDED FOR IT MUST BE THE TRUE ONE.

    The first version of this guard enforced a WRONG reason. It asserted the
    docstring named UnionPay and 62, because the docstring claimed 81 was a
    UnionPay mislabel and reasoned from the major industry identifier. 81 is
    RuPay, India's domestic network: a real assigned range. So excluding it is
    not the removal of a bogus listing, it is a deliberate FALSE NEGATIVE ON REAL
    CARDS — and a guard that locks in the comfortable version of the reason is
    worse than no guard, because it certifies it.

    What is required now is the accurate account: the network named, the fact
    that the range is real, and the measurement the trade rests on.
    """
    assert not any(p.startswith("81")
                   for prefixes in issuer_ranges.ASSIGNED_IINS.values()
                   for p in prefixes)

    doc = issuer_ranges.__doc__
    assert "RuPay" in doc, "name the network whose cards are missed"
    assert "81" in doc
    # RuPay's other ranges, so the gap is stated in full rather than as one case.
    for other in ("60", "6521", "6522", "82", "508"):
        assert other in doc, other
    # And the two halves of an honest trade: what it costs, and that the corpus
    # containing no RuPay card is why it looks free.
    assert "false negative" in doc.lower()
    # ⚠ POSITIVE, NOT A BLOCKLIST. The first cut asserted the word "mislabel"
    # was absent — and went red on THIS module, whose paragraph uses that word to
    # disavow it. Forbidding the vocabulary of an honest correction is the same
    # mistake as forbidding a module from recounting its own near miss. What is
    # required instead is the substance a wrong version cannot carry: that the
    # range is REAL and ASSIGNED, which is the whole reason excluding it costs
    # something.
    assert "real" in doc.lower() and "assigned" in doc.lower()
    assert "deliberate" in doc.lower(), "an exclusion must not read as an oversight"
    assert "no rupay card" in doc.lower(), (
        "say that the corpus contains no RuPay card, which is why the trade "
        "looks free")


def test_the_RuPay_ranges_the_table_DOES_accept_are_stated_correctly():
    """The docstring's factual claim, executed rather than believed.

    It says 6521 and 6522 are already accepted, via Discover's ``65``, and that
    the other four are not. Both halves are checked here, because a sentence
    about which cards get through is exactly the kind that rots silently.
    """
    accepted = {"6521", "6522"}
    missed = {"60", "81", "82", "508"}
    for prefix in accepted | missed:
        padded = prefix + "0" * (16 - len(prefix))
        got = issuer_ranges.starts_with_assigned_iin(padded)
        assert got is (prefix in accepted), f"RuPay {prefix}: accepted={got}"


# ── 2. old evidence replays under its own rules ──────────────────────────────
KEY = "foxy_sk_s10_test"
EVENT = "22222222-2222-4222-8222-222222222222"
#: Luhn-passing, 8 distinct digits, NOT an assigned issuer — so 2026.08.3 called
#: it a card and 2026.08.4 does not. That disagreement is the whole test.
NON_ISSUER = "8108420735282737"
PROMPT = f"ref {NON_ISSUER} on file"


def _export(tmp_path, version):
    row = {"seq": 1, "event_id": EVENT, "commitment_alg": "hmac-sha256",
           "policy_tag": "hipaa",
           "prompt_hash": hashing.commitment_hex(PROMPT, KEY),
           "event_metadata": {"policy_rules": ["phi.credit_card"],
                              "ruleset_version": version,
                              "ruleset_hash": ruleset.hash_of(ruleset.load(version))}}
    path = tmp_path / "logs.json"
    path.write_text(json.dumps({"logs": [row]}), encoding="utf-8")
    return str(path)


def test_a_2026_08_3_row_still_replays_as_a_card(tmp_path):
    """⚠ OLD EVIDENCE STAYS INTERPRETABLE UNDER THE RULES THAT PRODUCED IT.

    This row was minted when ``luhn+distinct`` was the card validator, and under
    that name this run WAS a card. Replaying it under today's stricter gate would
    make the row look like a lie about itself — the exact failure the frozen
    registry exists to prevent, arriving through the validator instead of the
    pattern.
    """
    result = introspect.explain(PROMPT, EVENT, _export(tmp_path, "2026.08.3"), KEY)

    assert result.status == "explained", result.message
    assert result.ruleset_verified is True
    assert [m.rule_id for m in result.matches] == ["phi.credit_card"], result.message

    # ...and the live SDK, on the same text, does NOT report a card. The two
    # answers differ, both are correct, and that is what versioning buys.
    assert "credit_card" not in pii.detect_pii(PROMPT, "")


def test_the_same_row_under_2026_08_4_reports_no_card(tmp_path):
    """The other half: today's ruleset applied to today's evidence.

    Without this the test above would pass just as well if replay ignored the
    validator entirely.
    """
    result = introspect.explain(PROMPT, EVENT, _export(tmp_path, "2026.08.4"), KEY)
    assert result.status == "no_matches", result.message
    assert result.matches == []


def test_each_published_validator_name_keeps_its_own_meaning():
    """The registry's promise, asserted name by name against one input.

    ``luhn`` accepts a repeated-digit run; ``luhn+distinct`` does not but accepts
    a non-issuer run; ``luhn+iin+distinct`` accepts neither. Three names, three
    meanings, none of them redefining another.
    """
    v = introspect._VALIDATORS
    assert v["luhn"]("0000000000000000") is True
    assert v["luhn+distinct"]("0000000000000000") is False
    assert v["luhn+distinct"](NON_ISSUER) is True
    assert v["luhn+iin+distinct"](NON_ISSUER) is False
    assert v["luhn+iin+distinct"]("4111111111111111") is True


def test_the_new_version_is_registered_and_the_old_ones_are_untouched():
    """A mint adds; it never edits. The three prior digests are literals."""
    assert ruleset.CURRENT_VERSION == "2026.08.4"
    assert ruleset.drift() is None
    for version, digest in (
            ("2026.08.1", "2995b7fcc2ac83a09336fdd5047fec893c5ffe3cdd01fbc2c61cb3e7a2ab1ed0"),
            ("2026.08.2", "59888ec66b3e2b84f550412ec5f2372e9d90f4a8df66a9e5ad9193f7c17b1f62"),
            ("2026.08.3", "100daf439ccbe706e607c9be2b079ae9a2b96f2f099c0b4b5900491cc7a18753")):
        assert ruleset.hash_of(ruleset.load(version)) == digest, version
    assert ruleset.load("2026.08.3")["pii_detectors"]["credit_card"]["validator"] \
        == "luhn+distinct"
    assert ruleset.load("2026.08.4")["pii_detectors"]["credit_card"]["validator"] \
        == "luhn+iin+distinct"
    # The PATTERN did not move — only the validator name.
    assert (ruleset.load("2026.08.3")["pii_detectors"]["credit_card"]["pattern"]
            == ruleset.load("2026.08.4")["pii_detectors"]["credit_card"]["pattern"])


# ── 3. the fences ────────────────────────────────────────────────────────────
def test_the_phone_path_did_not_move():
    """OUT OF SCOPE AND MEASURED ANYWAY. 168/168, and 0.000% on both digest
    populations — re-measured every run rather than trusted to a comment."""
    detected = {t for t in CORPORA.PHONE_SHAPES if "phone" in pii.detect_pii(t, "")}
    assert len(detected) == len(CORPORA.PHONE_SHAPES) == 168

    for corpus in (CORPORA.SHA256_DIGESTS, CORPORA.RANDOM_UUIDS):
        assert not [t for t in corpus if "phone" in pii.detect_pii(t, "")]


def test_the_card_change_did_not_touch_any_other_detector():
    """The blast radius, asserted. Only ``credit_card`` may differ from 1.10.0."""
    for text in ("email a@b.co", "ssn 123-45-6789", "ip 10.0.0.1",
                 "call 415-555-0134 now"):
        labels = pii.detect_pii(text, "gdpr")
        assert "credit_card" not in labels, text
        assert labels, f"{text} must still be detected as something"


# ── 4. the honesty line ──────────────────────────────────────────────────────
#: The three surfaces the claim has to appear on. A number that improves is easy
#: to state; the limit that comes with it is what gets quietly dropped in the
#: next edit, so its presence is a test rather than an intention.
_HONESTY_SURFACES = {
    "the detector itself": "sdk/src/foxy_audit/pii.py",
    "the changelog": "sdk/src/foxy_audit/__init__.py",
    "the PyPI long description": "sdk/README.md",
    "the frozen module": "sdk/src/foxy_audit/rulesets/v2026_08_4.py",
}


@pytest.mark.parametrize("where,rel", sorted(_HONESTY_SURFACES.items()))
def test_the_corpus_limit_is_stated_wherever_the_improvement_is(where, rel, ):
    """⚠ "NO RECALL COST" IS A CORPUS RESULT, NOT A PROPERTY OF THE GATE.

    PAN_SHAPES is built from mainstream test cards, which carry valid IINs BY
    CONSTRUCTION — so the corpus is structurally incapable of showing the one
    thing this change could break: a regional or private-label issuer outside the
    table, which would now be MISSED.

    Every surface that states the improvement must state that limit beside it.
    Measured rather than trusted, because deleting the caveat is a one-line edit
    that leaves every other test in this file green — which is exactly what the
    mutation sweep found when this guard did not exist.
    """
    from pathlib import Path

    repo = Path(__file__).resolve().parents[2]
    if not (repo / "sdk" / "README.md").is_file():
        pytest.skip("cross-checks repository documentation, absent from the sdist")

    text = (repo / rel).read_text(encoding="utf-8")
    # The four parts of the claim, each in whatever words the surface uses.
    assert "by construction" in text.lower(), f"{where}: why the corpus cannot see it"
    assert "#219" in text or "219" in text, f"{where}: the standing reminder"
    # ⚠ AND THE NAMED EXAMPLE. "a regional issuer might be missed" is an
    # abstraction a reader skims; "a RuPay card on 60, 81, 82 or 508 is not
    # detected" is a fact they can act on. Deleting the name from any one
    # surface was silent until this line — measured in the mutation sweep.
    assert "rupay" in text.lower(), (
        f"{where}: name the network whose cards this actually misses")
    assert any(word in text.lower() for word in ("regional", "private-label")),         f"{where}: what would actually be missed"


def test_the_claim_the_honesty_line_qualifies_is_the_one_being_made():
    """CONTROL. The caveat is only worth guarding beside the claim it limits.

    If the improvement figure ever stops being stated, this file would be
    enforcing a disclaimer for a number nobody publishes — so the number is
    asserted here too, from the corpora, not from the prose.
    """
    from pathlib import Path

    repo = Path(__file__).resolve().parents[2]
    if not (repo / "sdk" / "README.md").is_file():
        pytest.skip("cross-checks repository documentation, absent from the sdist")

    hits = sum(1 for t in CORPORA.HYPHENATED_IDS if _fires(t))
    assert hits == 621, hits
    readme = (repo / "sdk" / "README.md").read_text(encoding="utf-8")
    assert "621" in readme, "the figure the caveat qualifies is not stated"


def test_the_detector_itself_carries_the_caveat_not_just_the_file():
    """A FILE-LEVEL CHECK IS TOO COARSE FOR "the detector's own comment".

    pii.py states the limit TWICE - beside the variant table, and inside
    ``_is_card_number``. The parametrised guard above reads the whole file, so
    deleting EITHER one left it green: measured, by removing the function's
    paragraph and watching the mutation sweep report MISSED. The copy attached to
    the function is what a reader meets when they ask what the gate does, so it
    is asserted where it lives.
    """
    import inspect

    doc = inspect.getdoc(pii._is_card_number) or ""
    assert "unproven in general" in doc, "the limit must qualify the claim here"
    assert "construction" in doc.lower(), "why the corpus cannot see it"
    assert "#219" in doc, "the standing reminder"
    assert any(w in doc.lower() for w in ("regional", "private-label")), (
        "what would actually be missed")
