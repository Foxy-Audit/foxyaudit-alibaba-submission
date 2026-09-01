"""The compliance claims register, enforced. C2 of docs/plans/compliance-program.md.

⚠ WHY THIS FILE EXISTS WHEN test_site_wide_claims.py ALREADY GUARDS CLAIMS.

That file proves the three sub-processor lists AGREE. On 2026-09-01 they agreed,
and all three were wrong: privacy.html §8, privacy.html §13 and trust.html §6 each
stated the hosting country as the **United States** while production ran in GCP
``me-central1`` — Doha, **Qatar**. Every guard on every one of those pages was
green, because a consistency check cannot be wrong about its own subject. §13 then
named the EU Standard Contractual Clauses for a United States destination the
hosted data never reaches, so the transfer actually being made — EEA to a country
with no adequacy decision — was disclosed nowhere.

So this file checks the pages against **an asserted value**, not against each
other. ``docs/compliance/claims.yaml`` holds the truth; the pages are compared to
it. If every page agrees and the value is wrong, the value is wrong in one place
and the fix is one edit — which is the property agreement-checking never has.

Four rules:

  1. the hosting country on every surface is the one asserted value;
  2. a regime word with no ``backed``/``qualified`` entry in the register fails;
  3. a retired claim that comes back fails;
  4. **every sentence in a guarded claim class is one the register approved** —
     which is rule 3 turned the right way round, and the one that survives being
     attacked with words nobody has seen before.

WHY RULE 4 EXISTS: #292
-----------------------

C2 shipped rules 1-3 and reported 12 mutations, 12 caught. MAIN broke it with one
line — injecting into faq.html:

    "Our SOC 2 Type I report is expected shortly and fieldwork is already
     underway."

as false as the sentence that had been removed, and **all nine tests stayed
green**. Rule 3 blacklists: it pins the sentence that WAS wrong. But the expected
failure mode here is *a human rewriting the sentence*, and a human rewriting it
does not reuse a banned phrase.

Rule 1 never had that hole, because it asserts positively — every hosting
statement must name Qatar, so three pages agreeing on "Germany" is three
failures. Rule 4 generalises that shape into claim classes: a `sentence_pattern`
selects the sentences a class is about, and every one of them must appear in that
class's `approved_sentences`. Novel text fails by default.

⚠ AND RULE 4 HAD THE SAME BUG ONE LEVEL DOWN. The first version keyed the classes
on vocabulary that happened to appear — `SOC 2`, `backup` — so three invented
sentences walked around them: "All copies of your data remain within Qatar at all
times" contains neither word. The classes are now keyed on the CONSTRUCTION —
a place beside a totality word; SCC/DPA/Article-46 language — which is what #289
and #294 actually had in common.

MEASURED, NOT ASSERTED
----------------------

**23 mutations, 23 caught**, each introduced into the real file, watched to fail,
and reverted, on a branch green before and after.

===============================  ==========================================
SET A — the twelve C2 mutations  all 12 still caught (no regression)
===============================  ==========================================
SET B — novel text, 11 cases
  MAIN's exact #292 sentence     class rule
  an implied date; an implied    class rule
    assessor; a readiness claim
    on a quiet page
  "All copies of your data       class rule ⚠ MISSED BY THE FIRST C2b BUILD
    remain within Qatar"           — it drove data_location_exclusivity
  "Your data never leaves        class rule
    Qatar." (five words)
  "Every US sub-processor is     class rule ⚠ MISSED BY THE FIRST C2b BUILD
    bound by the Clauses"          — it drove transfer_safeguards
  the OpenAI bullet flipped to   class rule ⚠ MISSED BY THE FIRST C2b BUILD
    "an agreement is in place"
  the EU half of the backup      orphan rule — wrong by SILENCE
    sentence quietly deleted
  a class scoped to a renamed    scope rule — it would have guarded
    page                           nothing, in silence
  the REGISTER loosened          orphan rule — the attack that edits the
    instead of the page fixed      guard rather than the page
===============================  ==========================================

The last two are the ones worth keeping in mind: a guard is also attackable
through its own configuration, and both of those mutations leave every page
untouched.

Run:  pytest foxy-sale-page -q
"""

from __future__ import annotations

import html
import pathlib
import re

import pytest
import yaml

HERE = pathlib.Path(__file__).resolve().parent
ROOT = HERE.parent
COMPLIANCE = ROOT / "docs" / "compliance"


# ── the register ────────────────────────────────────────────────────────────
def _load(name: str) -> dict:
    return yaml.safe_load((COMPLIANCE / name).read_text(encoding="utf-8"))


@pytest.fixture(scope="session")
def register() -> dict:
    return _load("claims.yaml")


@pytest.fixture(scope="session")
def crosswalk() -> dict:
    return _load("crosswalk.yaml")


# ── the scan ────────────────────────────────────────────────────────────────
#
# ⚠ A data: URI IS NOT PROSE. These pages embed base64 image payloads, and the
# letter sequences `pci`, `PDPL`, `NIST` and `LGPD` occur inside them. C0
# measured a naive grep reporting claims on pages that make none. Blanking the
# payload (rather than dropping the line) keeps every other line number honest.
_DATA_URI = re.compile(r"data:[^\"')\s]{200,}")


def _pages() -> list[pathlib.Path]:
    reg = _load("claims.yaml")
    out: list[pathlib.Path] = []
    for surface in reg["meta"]["surfaces"]:
        out.extend(sorted((ROOT / surface).rglob("*.html")))
    assert out, "no customer-facing pages found — meta.surfaces is wrong"
    return out


def _scrubbed(path: pathlib.Path) -> str:
    src = path.read_text(encoding="utf-8", errors="replace")
    return _DATA_URI.sub(lambda m: " " * len(m.group(0)), src)


def _rel(path: pathlib.Path) -> str:
    return path.relative_to(ROOT).as_posix()


def _sites(words: dict[str, str]) -> set[tuple[str, str]]:
    """Every (file, regime) a regime word actually appears at."""
    found = set()
    for path in _pages():
        text = _scrubbed(path)
        for regime, pattern in words.items():
            if re.search(pattern, text):
                found.add((_rel(path), regime))
    return found


# ── 1 · COVERAGE — a regime word nobody wrote down fails the build ──────────
def test_every_regime_word_on_a_surface_is_registered(register):
    """The rule the plan's C2 asks for, in its sharp form.

    ⚠ SET COMPARISON IN BOTH DIRECTIONS, deliberately. Checking only that every
    registered claim is still present would pass a page that GAINED a regime —
    which is how NIST arrived on passport.html and docs.html claiming the
    Compliance Passport was mapped to it while the template contained zero
    occurrences of the word."""
    on_pages = _sites(register["regime_words"])
    registered = {(c["file"], c["regime"]) for c in register["claims"]}

    unregistered = sorted(on_pages - registered)
    assert not unregistered, (
        f"a regime word appears on a customer-facing surface with no entry in "
        f"docs/compliance/claims.yaml: {unregistered}. Add an entry with a "
        f"verdict and a crosswalk row that backs it, or take the word off the "
        f"page. A regime named with nothing behind it is the asymmetry this "
        f"phase exists to remove.")

    stale = sorted(registered - on_pages)
    assert not stale, (
        f"claims.yaml registers a claim that is no longer on the page: {stale}. "
        f"If it was deliberately removed, move it to `retired` with a "
        f"must_not_match pattern — that is what proves a deletion was applied.")


def test_no_live_claim_carries_a_delete_verdict(register):
    """`delete` means the text is gone. A live entry with that verdict is a
    contradiction: either the deletion was not applied, or the verdict is
    stale. Applied deletions live in `retired`."""
    bad = [f"{c['file']}:{c['line']} ({c['regime']})"
           for c in register["claims"] if c["verdict"] == "delete"]
    assert not bad, (
        f"these claims are still on their pages and carry verdict `delete`: "
        f"{bad}. Apply the deletion and move the entry to `retired`, or change "
        f"the verdict to backed/qualified and say what backs it.")


def test_the_recorded_line_numbers_are_current(register):
    """`line` is part of the register's schema, so it is asserted rather than
    left to rot. The anchor is what locates the claim; the line number is what
    a reader jumps to, and a wrong one sends them to the wrong sentence."""
    drifted = []
    for c in register["claims"]:
        lines = (ROOT / c["file"]).read_text(encoding="utf-8").split("\n")
        at = [i for i, line in enumerate(lines, 1) if c["anchor"] in line]
        if not at:
            drifted.append(f"{c['file']}: anchor not found: {c['anchor']!r}")
        elif c["line"] not in at:
            drifted.append(f"{c['file']}:{c['line']} -> {at[0]} ({c['regime']})")
    assert not drifted, (
        "claims.yaml line numbers are stale; the correct values are on the "
        "right:\n  " + "\n  ".join(drifted))


def test_every_affirmative_claim_names_a_backing_row_that_exists(register, crosswalk):
    """An assertion needs support; an absence cannot have any.

    ⚠ NEGATIONS AND QUESTIONS ARE EXEMPT ON PURPOSE. "We do not currently hold
    SOC 2" is the most honest sentence on the site and no crosswalk row can
    support it — a row describes a requirement and a control, not the lack of a
    certificate. Demanding a backing for it would push it off the page, which is
    the opposite of what this register is for."""
    ids = {r["id"] for r in crosswalk["rows"]}
    problems = []
    for c in register["claims"]:
        if c["kind"] != "affirmative":
            continue
        if not c["backing"]:
            problems.append(f"{c['file']}:{c['line']} ({c['regime']}) names no backing row")
        for row in c["backing"]:
            if row not in ids:
                problems.append(f"{c['file']}:{c['line']} cites {row}, which is not in crosswalk.yaml")
    assert not problems, "\n  ".join([""] + problems)


# ── 2 · TRUTH — the hosting country, checked against the value, not the pages ─
#
# A sentence, not a line: the corrected §13 puts the Qatar statement and the
# United States sub-processor statement in one source line, and a line-scoped
# check cannot tell a true clause from a false one sitting beside it.
_SENTENCE = re.compile(r"(?<=[.!?])\s+")
_TAG = re.compile(r"<[^>]+>")
_HOSTING = re.compile(
    r"\bhost(?:ing|ed|s)\b|\bUbuntu VM\b|\bme-central1\b|"
    r"\bour (?:own )?(?:infrastructure|servers)\b", re.I)
#: Hosting destinations somebody could plausibly write. Deliberately not the
#: full ISO list: this is about the wrong answers that get typed, and a short
#: explicit list is one a reader can check.
_PLACES = re.compile(
    r"\bUnited States\b|\bU\.?S\.?A?\b|\bIreland\b|\bGermany\b|\bNetherlands\b|"
    r"\bBelgium\b|\bFinland\b|\bUnited Kingdom\b|\bSingapore\b|\bIndia\b|"
    r"\bJapan\b|\bAustralia\b|\bCanada\b|\bBrazil\b|\bFrance\b|\bPakistan\b|"
    r"\bEuropean Union\b|\bEEA\b|\bQatar\b|\bDoha\b")


def _prose(path: pathlib.Path) -> str:
    """Rendered-ish text: tags out, entities resolved, whitespace flattened.

    ⚠ ENTITIES ARE RESOLVED. ``Trust &amp; Security`` is ``Trust & Security`` to
    a reader, and the approved-sentence lists below are maintained by hand — a
    list full of ``&amp;`` invites someone to "fix" it and silently unapprove a
    sentence that is still on the page."""
    text = _TAG.sub(" ", _scrubbed(path))
    return re.sub(r"\s+", " ", html.unescape(text))


def test_every_hosting_statement_names_qatar(register):
    """⚠ THE RULE THAT WOULD HAVE CAUGHT THE DEFECT, AND THE ONE THAT MATTERS.

    Any sentence that both describes hosting AND names a place must name the
    asserted hosting country. It does not compare the pages to each other, so
    three pages agreeing on the wrong country is three failures, not silence."""
    asserted = register["assertions"]["hosting_country"]
    want = asserted["value"]
    # ⚠ EXEMPTIONS ARE WHOLE SENTENCES, MATCHED EXACTLY, and that is the point.
    # One sentence on privacy.html §13 says where data is NOT hosted ("no
    # customer data is currently hosted or processed on Pakistani servers"),
    # which the words alone cannot distinguish from a false claim. A rule like
    # "skip sentences containing `not`" would also wave through "our servers are
    # not in the United States, they are in Ireland". Pinning the full sentence
    # means editing so much as a comma in it re-arms the check.
    exempt = {e["sentence"] for e in asserted.get("sentence_exemptions") or []}
    wrong = []
    for path in _pages():
        for sentence in _SENTENCE.split(_prose(path)):
            sentence = sentence.strip()
            if sentence in exempt:
                continue
            if _HOSTING.search(sentence) and _PLACES.search(sentence):
                if want not in sentence:
                    wrong.append(f"{_rel(path)}: {sentence[:160]!r}")
    assert not wrong, (
        f"a hosting statement names a place that is not {want!r}. Production "
        f"runs in {asserted['detail']}:\n  " + "\n  ".join(wrong))


def test_the_pages_that_must_state_the_hosting_country_do(register):
    """The other half. A page can also be wrong by falling silent — deleting the
    sub-processor row rather than correcting it would pass the check above."""
    asserted = register["assertions"]["hosting_country"]
    for rel in asserted["must_appear_on"]:
        text = _prose(ROOT / rel)
        assert asserted["value"] in text, (
            f"{rel} no longer states the hosting country. It is required to: "
            f"the sub-processor disclosure is what GDPR Art. 44-46 hangs on.")


# ── 3 · REGRESSION — retired claims stay retired ────────────────────────────
def test_a_retired_claim_has_not_come_back(register):
    """⚠ PINNED BECAUSE ONE OF THESE IS A RECURRENCE.

    The vault's `Owner-authorised divergences from the policy documents` records
    that "the honest SOC 2 disclosure was softened or removed" once before. An
    edit fixes a page. Only a pin fixes the claim.

    `scope: source` matches the raw markup — the hosting patterns are exact
    strings from the table cell and the bullet, and tags are part of them.
    `scope: text` matches rendered prose, so a claim that comes back with
    different markup is still caught."""
    back = []
    for entry in register["retired"]:
        for path in _pages():
            body = _scrubbed(path) if entry.get("scope") == "source" else _prose(path)
            for pattern in entry["must_not_match"]:
                hit = re.search(pattern, body, re.I)
                if hit:
                    back.append(
                        f"{_rel(path)}: retired claim {entry['id']!r} is back "
                        f"({pattern!r} matched {hit.group(0)[:90]!r})")
    assert not back, (
        "\n  ".join([""] + back) + "\n\nThese claims were removed deliberately. "
        "See docs/compliance/claims.yaml `retired` for why, and what replaced them.")


def test_the_soc2_status_is_the_one_trust_html_states(register):
    """The positive half of the SOC 2 pin. Retiring "currently completing" does
    not by itself put the true sentence anywhere — a page could simply drop the
    subject. The canonical wording has to be present, and it is the one every
    other page was corrected to match."""
    canonical = ROOT / register["assertions"]["soc2_status"]["canonical_page"]
    text = _prose(canonical)
    assert "no auditor is engaged yet" in text, (
        f"{_rel(canonical)} no longer states that no auditor is engaged. That "
        f"sentence is what makes the SOC 2 disclosure on faq.html and "
        f"pricing.html true; without it they are unsupported again.")
    assert "We do not currently hold SOC 2" in text, (
        f"{_rel(canonical)}'s certifications disclosure was softened.")


def test_every_hosting_exemption_still_matches_a_real_sentence(register):
    """⚠ AN EXEMPTION LIST IS THE PART OF A GUARD THAT ROTS.

    The exempt sentence has to be present, verbatim, on some page. If it was
    reworded, the exemption stops applying (the check above re-arms, which is
    correct) AND this test says so, so nobody has to work out why an unrelated
    check went red. If it was deleted, the exemption goes with it."""
    asserted = register["assertions"]["hosting_country"]
    live = set()
    for path in _pages():
        live.update(s.strip() for s in _SENTENCE.split(_prose(path)))
    orphans = [e["sentence"][:110]
               for e in asserted.get("sentence_exemptions") or []
               if e["sentence"] not in live]
    assert not orphans, (
        "claims.yaml exempts a sentence that is not on any page any more:\n  "
        + "\n  ".join(orphans)
        + "\n\nIf the sentence was reworded, update the exemption to the new "
          "text after checking it is still a NEGATIVE hosting statement. If it "
          "was removed, delete the exemption.")
# ── 4 · CLAIM CLASSES — every sentence on the subject is one we approved ────
#
# ⚠ #292. THIS IS THE RULE THAT REPLACES BLACKLISTING, AND WHY.
#
# The first version of this file guarded SOC 2 by banning the phrases that had
# already been wrong. MAIN broke it in one line: injecting
#
#     "Our SOC 2 Type I report is expected shortly and fieldwork is already
#      underway."
#
# into faq.html left all nine tests green. It is as false as the sentence that
# was removed, in words the guard had never seen — and the expected failure mode
# here is *a human rewriting the sentence*, who will not reuse a banned phrase.
#
# The hosting-country rule never had that hole, because it asserts POSITIVELY:
# every hosting statement must name Qatar, so a consistently-wrong "Germany"
# fails. These classes generalise that shape. Every sentence matching the class
# pattern must be one the register lists. A novel sentence is an unapproved
# sentence, whatever it says.
#
# The cost is real and is the point: rewording an approved sentence fails the
# build until someone updates the register. That is a claims register doing its
# job, not friction.


def _classes(register: dict) -> dict:
    return {k: v for k, v in register["assertions"].items()
            if v.get("sentence_pattern")}


def _class_pattern(spec: dict) -> "re.Pattern":
    # ⚠ CASE-SENSITIVE FOR SOC 2, DELIBERATELY. `\bSOC ?2\b` under re.I also
    # matches the `soc2` POLICY TAG in the code samples on how-it-works.html,
    # sdk.html and install.html. Those are a different claim — a per-call tag,
    # recorded `qualified` in `claims` — and pulling them into this class would
    # force code samples into a prose approval list.
    flags = 0 if spec.get("case_sensitive") else re.I
    return re.compile(spec["sentence_pattern"], flags)


def _sentences_in_class(spec: dict) -> list[tuple[str, str]]:
    """Every sentence in this class, across the pages the class covers.

    ⚠ `scope_to` NARROWS A CLASS TO NAMED FILES, and both uses of it are load
    bearing rather than convenient:

    · `transfer_safeguards` covers privacy.html only, because dpa.html, msa.html
      and terms.html are CONTRACT instruments and are full of safeguard language
      by design. A contract states a forward obligation; privacy.html §13 states
      present fact, and it is present fact this class is about. What that leaves
      uncovered is written down rather than forgotten — see
      `open_questions.dpa_asserts_scc_reliance`.

    · `data_location_exclusivity` covers privacy.html only, because trust.html's
      sub-processor table has no sentence boundaries, so flattening it yields one
      enormous pseudo-sentence that would sit in the approval list unreadably.
      That table's Location column is guarded structurally by `hosting_country`
      instead.

    A class with no `scope_to` covers every customer-facing page, which is the
    default and the safer one."""
    pat = _class_pattern(spec)
    scope = spec.get("scope_to")
    out = []
    for path in _pages():
        rel = _rel(path)
        if scope and rel not in scope:
            continue
        for sentence in _SENTENCE.split(_prose(path)):
            sentence = sentence.strip()
            if pat.search(sentence):
                out.append((rel, sentence))
    return out


def test_every_scoped_class_names_files_that_exist(register):
    """⚠ A `scope_to` POINTING AT NOTHING SILENTLY DISABLES ITS CLASS.

    Rename a page, and a class scoped to the old name stops matching any
    sentence at all — `approved_sentences` empties, both class tests pass, and
    the guard reports success while covering nothing. That is the shape this
    whole file exists to prevent, so the scope is checked rather than trusted."""
    live = {_rel(p) for p in _pages()}
    for name, spec in _classes(register).items():
        for rel in spec.get("scope_to") or []:
            assert rel in live, (
                f"claim class {name!r} is scoped to {rel!r}, which is not a page "
                f"on any surface in meta.surfaces. The class currently guards "
                f"nothing and would pass in silence.")
        if spec.get("scope_to"):
            assert _sentences_in_class(spec), (
                f"claim class {name!r} matches no sentence anywhere in its "
                f"scope. Either the pattern or the scope is wrong; as it stands "
                f"the class is green and guarding nothing.")


def test_every_sentence_in_a_claim_class_is_one_the_register_approved(register):
    """The positive rule. A sentence the register has never seen fails, whether
    or not it repeats anything previously banned."""
    problems = []
    for name, spec in _classes(register).items():
        approved = set(spec["approved_sentences"])
        for rel, sentence in _sentences_in_class(spec):
            if sentence not in approved:
                problems.append(f"[{name}] {rel}: {sentence[:200]!r}")
    assert not problems, (
        "an unapproved sentence makes a claim in a guarded class:\n  "
        + "\n  ".join(problems)
        + "\n\nIf the sentence is TRUE and intended, add it verbatim to that "
          "class's `approved_sentences` in docs/compliance/claims.yaml — which "
          "is the moment someone has to decide whether it is true. If it is not, "
          "take it off the page.")


def test_every_approved_sentence_is_still_on_a_page(register):
    """The other direction. An approval nobody ships is an approval waiting to
    excuse text it was never written for — and it hides a deletion: if the
    honest sentence is quietly removed, only this test notices."""
    orphans = []
    for name, spec in _classes(register).items():
        live = {s for _, s in _sentences_in_class(spec)}
        for approved in spec["approved_sentences"]:
            if approved not in live:
                orphans.append(f"[{name}] {approved[:150]!r}")
    assert not orphans, (
        "claims.yaml approves a sentence that is on no page any more:\n  "
        + "\n  ".join(orphans)
        + "\n\nIt was reworded (update the approval, after deciding the new "
          "wording is true) or removed (delete the approval — and check the "
          "claim it made is not now missing).")


def test_the_soc2_answer_matches_the_canonical_page(register):
    """⚠ #292's actual fix: faq.html and pricing.html must carry trust.html's
    wording, so divergence fails rather than only known-bad strings failing.

    trust.html is the single source. Each phrase is asserted on the canonical
    page FIRST — so if someone edits trust.html, the failure names trust.html
    rather than sending them to hunt through the two pages that copy it."""
    spec = register["assertions"]["soc2_status"]
    canonical = _prose(ROOT / spec["canonical_page"])

    missing = [p for p in spec["canonical_phrases"] if p not in canonical]
    assert not missing, (
        f"{spec['canonical_page']} no longer carries the canonical SOC 2 "
        f"wording: {missing}. It is the page the others are checked against, so "
        f"fix it here first.")

    problems = []
    for rel in spec["must_carry_canonical"]:
        text = _prose(ROOT / rel)
        for phrase in spec["canonical_phrases"]:
            if phrase not in text:
                problems.append(f"{rel} is missing {phrase[:90]!r}")
    assert not problems, (
        "\n  ".join([""] + problems)
        + f"\n\nThese pages must answer the SOC 2 question in "
          f"{spec['canonical_page']}'s words. The vault records this disclosure "
          f"being softened once already; one wording in one place is the only "
          f"arrangement that cannot drift apart again.")


def test_the_backup_locations_are_both_stated(register):
    """#294. C2 corrected the hosting country and, in the same bullet, published
    "Backups are retained in the same region and do not leave Qatar." Measured
    the same day: the nightly dumps are on the VM in Qatar, but the GCP disk
    snapshots are in the `eu` multi-region — 5 of 5 sampled. Both locations are
    true and both have to be on the page, so naming only the flattering one is
    a failure rather than an omission."""
    spec = register["assertions"]["backup_locations"]
    for rel in spec["must_appear_on"]:
        text = _prose(ROOT / rel)
        missing = [m for m in spec["must_mention"] if m not in text]
        assert not missing, (
            f"{rel} states the backup arrangement without naming {missing}. "
            f"Both locations are real: {spec['detail']}")
