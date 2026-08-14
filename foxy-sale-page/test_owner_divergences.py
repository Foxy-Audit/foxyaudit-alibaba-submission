"""The six owner-authorised departures from the .docx files. (L14, 2026-08-13)

⚠ THIS FILE EXISTS BECAUSE A RE-CONVERSION WOULD SILENTLY REVERT THEM.

Eleven phases converted twelve .docx documents into published pages, and the
standing rule was to reproduce the document rather than improve it. On
2026-08-13 the owner authorised six deliberate departures from that rule. Four
of the six make a published page say something its source document does not.

If someone regenerates a page from its .docx without knowing that, legal text
the owner rejected comes back — and nothing would notice, because the source
document is the one thing everybody treats as authoritative. These guards are
what turn that from an accident into a decision: to restore the document's
wording you must first delete a test whose failure message tells you exactly
where the decision is written down and why.

⚠ EVERY ASSERTION BELOW NAMES THE VAULT NOTE. A comment would not survive being
skimmed; a failure message arrives at the moment someone is about to undo the
decision.

    G:\\My Drive\\Life\\03 Projects\\Foxy Audit\\
        Owner-authorised divergences from the policy documents.md

Run:  pytest foxy-sale-page -q
"""

from __future__ import annotations

import pathlib
import re

import pytest

from conftest import POSTAL_ADDRESS

HERE = pathlib.Path(__file__).resolve().parent
ROOT = HERE.parent

#: Named in every failure message below. The whole point of the file.
NOTE = ('OWNER DECISION 2026-08-13, recorded in the Obsidian vault at '
        '"Foxy Audit/Owner-authorised divergences from the policy documents.md". '
        'The .docx says otherwise ON PURPOSE. Read that note before changing this')


def _why(n: str, what: str) -> str:
    return f"[{n}] {what}\n\n{NOTE}."


@pytest.fixture(scope="module")
def aup(legal_dom):
    return legal_dom("acceptable-use.html")


@pytest.fixture(scope="module")
def privacy(legal_dom):
    return legal_dom("privacy.html")


# ── #193 — THE LICENCE ───────────────────────────────────────────────────────
def test_193_the_readme_does_not_claim_all_rights_reserved():
    """README.md said "All rights reserved… No license is granted". LICENSE,
    sdk/pyproject.toml, the published PyPI metadata and Privacy §16 all say MIT.
    Four sources against one — and MIT is irrevocable for every version already
    published, so the README could not have taken the grant back even if it had
    been the odd one out on purpose."""
    readme = (ROOT / "README.md").read_text(encoding="utf-8")
    assert "All rights reserved" not in readme, \
        _why("#193", "README.md claims all rights reserved again, contradicting "
                     "LICENSE, sdk/pyproject.toml, PyPI and Privacy Policy §16")
    assert "No license is granted" not in readme, \
        _why("#193", "README.md denies the licence grant again")
    assert "MIT License" in readme, \
        _why("#193", "README.md no longer states the MIT licence at all")


def test_193_the_four_sources_that_outvoted_the_readme_still_say_mit(legal_dom):
    """The control. If these drift, the divergence above loses its basis and the
    owner's decision should be revisited rather than silently inherited."""
    py = (ROOT / "sdk" / "pyproject.toml").read_text(encoding="utf-8")
    assert 'license = { text = "MIT" }' in py, "sdk/pyproject.toml no longer declares MIT"
    assert "License :: OSI Approved :: MIT License" in py, "the OSI classifier is gone"
    assert (ROOT / "LICENSE").read_text(encoding="utf-8").startswith("MIT License")
    assert "MIT" in legal_dom("privacy.html").text, "Privacy §16 no longer says MIT"


def test_193_the_sdk_ships_the_licence_text_it_declares():
    """⚠ NOT A DIVERGENCE — A FIX, and the half that is easy to call done wrongly.

    ``license = { text = "MIT" }`` sets metadata and packages nothing, so the
    sdist declared MIT and shipped no licence text. sdk/LICENSE now exists and is
    byte-identical to the repo root, same copyright line.

    Adding the file is not the same as packaging it: hatchling was measured
    building the real artifacts, and it includes the file and emits
    ``License-File: LICENSE`` without any ``license-files`` entry. This guard
    checks what it can check statically — that the file exists and matches — and
    the packaging proof lives in the L14 report."""
    root, sdk = ROOT / "LICENSE", ROOT / "sdk" / "LICENSE"
    assert sdk.is_file(), \
        "sdk/LICENSE is gone — the sdist would declare MIT and ship no licence text"
    assert sdk.read_bytes() == root.read_bytes(), \
        "sdk/LICENSE has drifted from the repo-root LICENSE; they must be identical"
    assert b"Copyright (c) 2026 Foxy Audit Contributors" in sdk.read_bytes()


# ── #194 — THE AUP / DISCLOSURE CONFLICT ─────────────────────────────────────
@pytest.mark.parametrize("place, needle", [
    ("§1 undermine-isolation", "backdate audit records or the hash chain, except as "
                               "expressly permitted by our Responsible Disclosure Policy"),
    ("§1 attack-or-disrupt", "probing another organization's is, except as expressly "
                             "permitted by our Responsible Disclosure Policy"),
    ("§3 security-research", "Where our Responsible Disclosure Policy expressly permits "
                             "conduct this section forbids, that policy governs"),
])
def test_194_each_prohibition_defers_to_the_disclosure_policy(aup, place, needle):
    """L6 published these as the .docx wrote them and recorded the conflict rather
    than harmonising it, because which of two legal documents governs is an
    owner's decision. The owner has now made it: the disclosure policy governs.

    Without this, a researcher demonstrating a tenant-isolation break is
    simultaneously inside the safe harbour and in breach of the AUP."""
    assert needle in aup.text, \
        _why("#194", f"AUP {place} no longer defers to the Responsible Disclosure "
                     f"Policy; a researcher inside the safe harbour is in breach again")


def test_194_every_carve_out_links_the_policy_it_defers_to(aup):
    """A deferral a reader cannot follow is not a deferral. Three carve-outs,
    three links, all to the same authoritative policy."""
    s1, s3 = aup.section(1), aup.section(3)
    assert s1.count('href="/report-abuse.html"') >= 2, \
        _why("#194", "AUP §1's two carve-outs no longer both link the disclosure policy")
    assert 'href="/report-abuse.html"' in s3, \
        _why("#194", "AUP §3's carve-out no longer links the disclosure policy")


def test_194_the_probe_bullet_no_longer_forbids_ordinary_integration_testing(aup):
    """⚠ THE HALF THAT IS NOT ABOUT RESEARCHERS AT ALL.

    "no attempts to overload, probe, or bypass rate limits, quotas, or security
    controls" forbade a PAYING CUSTOMER testing the rate limits on their own
    workspace — which is ordinary integration testing, and the reason to buy an
    SDK with a rate limit in the first place. It is now narrowed to what the
    disclosure policy actually excludes: volumetric denial of service, and
    testing that degrades the service for other people."""
    t = aup.text
    assert "no attempts to overload, probe, or bypass rate limits" not in t, \
        _why("#194", "the AUP again forbids probing any rate limit or security "
                     "control, which covers a customer testing their own workspace")
    assert "No volumetric denial-of-service" in t, \
        _why("#194", "the AUP's attack bullet lost its narrowing to VOLUMETRIC DoS")
    assert "no testing that degrades the service for other people" in t, \
        _why("#194", "the AUP's attack bullet lost the degradation limb")
    assert "that apply to your own workspace is not a breach of this policy" in t, \
        _why("#194", "the AUP no longer says a customer may exercise the limits on "
                     "their own workspace")


def test_194_the_aup_still_grants_no_safe_harbour_of_its_own(aup):
    """⚠ THE CARVE-OUT MUST DEFER, NOT DUPLICATE. L6's rule survives this change:
    one undertaking, in one place. Deferring to the disclosure policy is the
    opposite of restating it — if this page ever grows its own promise there are
    two to keep in step, which is the mistake L5 spent a phase undoing."""
    t = aup.text
    assert "not pursue legal action" not in t, \
        _why("#194", "the AUP now states its own safe harbour; there must be exactly one")
    assert "safe harbour" not in t.lower(), \
        _why("#194", "the AUP now uses the words 'safe harbour'; it must only point "
                     "at the policy that grants one")


# ── #191 — THE PHONE ─────────────────────────────────────────────────────────
PHONE = "3398123944"
KEEPS_THE_PHONE = {"refund.html", "terms.html", "terms-of-use.html", "sla.html",
                   "trust.html", "acceptable-use.html", "cookie-policy.html"}


def test_191_the_security_page_no_longer_publishes_the_personal_mobile(legal_dom):
    """It is the owner's personal mobile, on a machine-discoverable policy that an
    RFC 9116 security.txt points at — and a disclosure by phone cannot carry a
    proof-of-concept anyway. The email channel is the one that works."""
    dom = legal_dom("report-abuse.html")
    assert PHONE not in dom.src, \
        _why("#191", "report-abuse.html publishes the personal mobile again")
    assert "security@foxyaudit.tech" in dom.text, \
        _why("#191", "removing the phone also removed the reporting channel — the "
                     "page must still say how to reach us")


def test_191_the_phone_stays_on_exactly_the_seven_pages_it_belongs_on():
    """⚠ THE OVER-REACH THIS GUARD EXISTS TO CATCH. "Remove the phone" reads like
    a site-wide instruction and is not one: on Refund, Terms and the rest it is a
    genuine support channel the documents rely on. Asserted as an EXACT set, so
    both directions fail — deleting it everywhere, and putting it back on the
    security page."""
    actual = {p.name for p in HERE.glob("*.html") if PHONE in p.read_text(encoding="utf-8")}
    assert actual == KEEPS_THE_PHONE, _why(
        "#191", f"the phone is now on {sorted(actual)} — it must be on exactly the "
                f"seven support pages and NOT on report-abuse.html. "
                f"unexpected={sorted(actual - KEEPS_THE_PHONE)}, "
                f"lost={sorted(KEEPS_THE_PHONE - actual)}")


# ── #187 — THE CAP ───────────────────────────────────────────────────────────
def test_187_the_site_cap_states_its_own_amount(legal_dom):
    """"A nominal sum SUCH AS one hundred U.S. dollars" makes the figure
    illustrative, so the cap does not state what it is — an invitation to argue
    the number afterwards. The ToS states a real formula by contrast."""
    tou = legal_dom("terms-of-use.html").text
    assert "SUCH AS ONE HUNDRED" not in tou.upper(), \
        _why("#187", "the site cap is illustrative again ('a nominal sum such as'), "
                     "so it no longer states its own amount")
    assert "ONE HUNDRED U.S. DOLLARS (USD $100)" in tou, \
        _why("#187", "the site cap lost its stated figure")


def test_187_the_cap_still_governs_only_site_visitors(legal_dom):
    """⚠ L11 PINNED THREE CAPS TO THREE RELATIONSHIPS (#202) and this edit had to
    keep that true. This one governs SITE VISITORS — not self-serve customers
    (terms.html §11) and not signed customers (msa.html §12). Restated here so a
    future edit to the figure cannot quietly widen what it covers."""
    tou = legal_dom("terms-of-use.html").text
    assert "TO ACCESS THE SITE ITSELF" in tou, \
        _why("#187", "the site cap stopped naming the site as what it governs — it "
                     "may now overlap the ToS or MSA cap")
    assert "GREATER OF" in tou, _why("#187", "the cap's two-limb structure changed")


# ── #180 — THE COUNT ─────────────────────────────────────────────────────────
def test_180_section_8_counts_categories_not_named_providers(privacy):
    """Bullet one names TWO companies (Google LLC and OpenAI, L.L.C.) and Google
    appears in three roles, so a regulator counting legal entities gets seven
    against a claim of six — on a page that adds "No one else touches your data"."""
    t = privacy.text
    assert "Six categories of provider" in t, \
        _why("#180", "privacy.html §8 claims six NAMED PROVIDERS again, while bullet "
                     "one names two companies and Google appears in three roles")
    assert "Six named providers" not in t, \
        _why("#180", "the 'named providers' wording is back")
    assert "No one else touches your data" in t, \
        "§8 lost the sentence that makes the count matter"


def test_180_the_reason_the_wording_changed_is_still_true(privacy):
    """The divergence rests on a fact about the list. If the list is ever split so
    that six bullets name six entities, "six named providers" becomes accurate
    again and the owner's decision can be revisited — deliberately."""
    s8 = privacy.section(8)
    entities = [e for e in ("Google LLC", "OpenAI", "Paddle.com Market Ltd",
                            "Payoneer", "Brevo") if e in s8]
    bullets = len(re.findall(r"<li>", s8))
    assert bullets == 6, f"§8 now lists {bullets} bullets, not six"
    assert len(entities) >= 5 and "Google LLC" in s8 and "OpenAI" in s8, _why(
        "#180", "§8's first bullet no longer names two companies — the reason the "
                "count was changed to 'categories' may no longer hold")


# ── #182 — CANCELLATION vs DELETION ─────────────────────────────────────────
def test_182_the_policy_says_cancellation_and_deletion_are_different(privacy):
    """The Passport may be generated "at any time, including after cancellation"
    (§2) while §9 says deletion "immediately blocks further sign-in and API
    access". Both are true of DIFFERENT operations, and as written a reader could
    not tell that.

    ⚠ VERIFIED IN THE CODE BEFORE THE SENTENCE WAS WRITTEN, not assumed:
      · /v1/billing/cancel sets Stripe cancel_at_period_end and touches no column
        on the org — deleted_at stays NULL and suspended stays False.
      · auth.py's _ensure_org_access refuses only on deleted_at and suspended. It
        never consults subscription_status, so a cancelled workspace still signs
        in, and /v1/passport carries no billing gate at all.
      · /v1/account/delete sets deleted_at, and every customer auth channel then
        403s.
    So the distinction the page now states is one the product implements."""
    t = privacy.text
    assert "Cancellation and deletion are different actions." in t, \
        _why("#182", "privacy.html no longer distinguishes cancellation from "
                     "deletion, so §2's 'including after cancellation' and §9's "
                     "'immediately blocks further sign-in' read as a contradiction")
    assert "an administrator can still sign in and generate the Compliance Passport" in t, \
        _why("#182", "the sentence no longer says what survives cancellation")
    assert "at any time, including after cancellation" in t, \
        "§2's Passport definition changed; the distinction now explains nothing"
    assert "immediately blocks further sign-in and API access" in t, \
        "§9's deletion sentence changed; re-check the distinction against it"


def test_182_the_code_still_behaves_the_way_the_sentence_describes():
    """⚠ THE SENTENCE IS A CLAIM ABOUT THE PRODUCT, so it is pinned to the product.
    If a billing gate is ever added to the passport, or _ensure_org_access starts
    reading subscription_status, the published sentence becomes false and this
    fails before a customer finds out."""
    auth = (ROOT / "backend" / "app" / "auth.py").read_text(encoding="utf-8")
    passport = (ROOT / "backend" / "app" / "routers" / "passport.py").read_text(encoding="utf-8")
    account = (ROOT / "backend" / "app" / "routers" / "account.py").read_text(encoding="utf-8")
    billing = (ROOT / "backend" / "app" / "routers" / "billing.py").read_text(encoding="utf-8")

    gate = re.search(r"def _ensure_org_access.*?(?=\ndef )", auth, re.S)
    assert gate, "auth.py's _ensure_org_access is gone"
    assert "deleted_at is not None" in gate.group(0) and "org.suspended" in gate.group(0)
    assert "subscription_status" not in gate.group(0), _why(
        "#182", "the auth gate now consults subscription_status, so a CANCELLED "
                "workspace may no longer be able to sign in — privacy.html says it can")
    assert "subscription_status" not in passport, _why(
        "#182", "/v1/passport gained a billing gate; the Passport may no longer be "
                "generatable after cancellation, which privacy.html states it is")
    assert "org.deleted_at = datetime.now(timezone.utc)" in account, \
        "the delete path no longer soft-deletes via deleted_at"
    assert "cancel_at_period_end=True" in billing, \
        "the cancel path no longer cancels at period end"


# ── A1 — THE STAFF CHAIN'S WORDING, AFTER ANCHORING ─────────────────────────
#
# ⚠ THE VAULT NOTE CONTAINS A SAME-DAY CORRECTION, AND A1 IMPLEMENTS IT.
#
# The owner's first decision was "anchor the staff chain, THEN say immutable".
# MAIN then found anchor.py's own framing caution and recorded the correction in
# the same note: an anchor makes tampering "externally detectable after the next
# anchor, not impossible", the project's phrase is "tamper-evident, independently
# verifiable", and the word "immutable" appears nowhere in backend/app/ or
# verifier/ — not even about the fully-anchored customer ledger.
#
# So A1 ships the anchoring and the pages take the PROJECT PHRASE, not the
# stronger word. These guards pin that outcome to the note, because the original
# decision is the one a reader is more likely to remember.


THREE_PAGES = ("trust.html", "privacy.html", "dpa.html")


@pytest.mark.parametrize("page", THREE_PAGES)
def test_a1_the_staff_trail_wording_matches_what_anchoring_actually_earns(legal_dom, page):
    """All three describe the same mechanism, so all three move together — L10
    found this claim on three pages with only one corrected."""
    from test_site_wide_claims import _staff_sentence
    # ⚠ THE STAFF SENTENCE, NOT THE PAGE. privacy.html says "tamper-evident audit
    # ledger" twice about the CUSTOMER ledger, and a page-level check was
    # satisfied by those while the staff sentence had been reverted. Found by
    # mutation, not by reading.
    t = _staff_sentence(legal_dom(page).text)
    assert "tamper-evident" in t, _why(
        "A1", f"{page} no longer uses the project's phrase for the staff audit "
              "trail. Anchoring earns 'tamper-evident, independently verifiable'")
    assert "removed from the end" in t, _why(
        "A1", f"{page} lost the #143 upgrade — an entry removed from the END of the "
              "staff chain is now detectable, and that is what anchoring bought")
    assert "before the chain existed" in t, _why(
        "A1", f"{page} stopped stating that entries predating the chain are NOT "
              "covered by the anchor, so the claim now reaches further than the "
              "mechanism does")


@pytest.mark.parametrize("page", THREE_PAGES)
def test_a1_no_page_took_the_word_the_correction_rejected(legal_dom, page):
    """⚠ THE HALF THE ORIGINAL DECISION WOULD HAVE GOT WRONG. Anchoring is
    shipped, so the first decision would now permit "immutable". The correction
    says no, and the site-wide guard enforces it unconditionally — this states
    the reason next to the note that records it."""
    t = legal_dom(page).text.lower()
    for word in ("immutable", "tamper-proof", "unalterable"):
        assert word not in t, _why(
            "A1", f"{page} says {word!r}. Anchoring does NOT earn that word: the "
                  "window between anchors is real, pre-chain rows are not covered, "
                  "and an anchor proves what a record looked like rather than "
                  "preventing an edit")


def test_a1_the_ban_does_not_depend_on_the_chain_being_unanchored():
    """⚠ THE DEFECT A1 EXISTS TO FIX, ASSERTED AS SOURCE.

    L10's guard read `if staff_chain_is_anchored(): return` — an early exit that
    switched the ban off the moment anchoring shipped. A1 ships anchoring, so
    that line would have fired on this very commit. It is gone, and this asserts
    it stays gone: the ban must not be conditional on the thing that was supposed
    to unlock it."""
    # ⚠ PARSE THE CODE, DO NOT GREP THE TEXT. The first cut sliced the function
    # out as a string and searched it — and matched the DOCSTRING, which quotes
    # the very line it is checking is gone. That is the third time this phase
    # that a guard was satisfied by prose explaining the guard. The AST sees
    # statements; a docstring is not one of them.
    import ast as _ast
    guard = (HERE / "test_site_wide_claims.py").read_text(encoding="utf-8")
    tree = _ast.parse(guard)
    fn = next((n for n in tree.body
               if isinstance(n, _ast.FunctionDef)
               and n.name == "test_no_page_claims_more_than_either_chain_can_prove"), None)
    assert fn is not None, _why("A1", "the site-wide overclaim ban is gone entirely")
    stmts = fn.body[1:] if _ast.get_docstring(fn) is not None else fn.body
    early_exit = any(
        isinstance(node, _ast.If)
        and isinstance(node.test, _ast.Call)
        and getattr(node.test.func, "id", None) == "staff_chain_is_anchored"
        for node in stmts)
    assert not early_exit, _why(
        "A1", "the site-wide overclaim ban is conditional on anchoring again. "
              "Anchoring is shipped, so that condition switches the ban OFF")
    assert "staff_chain_is_anchored" in guard, _why(
        "A1", "the code-reading detector was deleted. It still has a job — the "
              "weaker-to-project-phrase upgrade — even though it no longer "
              "unlocks the strong word")


# ═══════════════════════════════════════════════════════════════════════════
# L15 — THE 2026-08-14 DECISIONS: THE CONTRACTS STOP CONTRADICTING EACH OTHER
# ═══════════════════════════════════════════════════════════════════════════
#
# ⚠ THESE SIX ARE A DIFFERENT KIND OF DIVERGENCE FROM THE SIX ABOVE.
#
# The 2026-08-13 set made a page say something its .docx does not. This set
# resolves places where TWO PUBLISHED DOCUMENTS said different things — an
# entire-agreement clause competing with another, a survival list citing a
# section that does not exist, a DPA whose parent disagreed with the MSA that
# claimed it, three sub-processor rosters that had drifted apart, two contracts
# with notice provisions and no notice address, and a support table that never
# said whom it bound.
#
# That makes the failure mode worse, not better. Restoring one side of a
# reconciled pair looks locally correct — the .docx agrees with you — and
# silently re-opens the contradiction on a page you are not looking at. Every
# guard below therefore names BOTH sides.
#
# L11 and L12 reported four of these and refused to fix them, because deciding
# which of two legal documents governs is an owner's call. It was made on
# 2026-08-14 and is written down in the same vault note as the first six.

NOTE_L15 = ('OWNER DECISION 2026-08-14, recorded in the Obsidian vault at '
            '"Foxy Audit/Owner-authorised divergences from the policy documents.md". '
            'Two published documents disagreed and the owner chose which governs. '
            'Read that note before changing this')


def _why15(n: str, what: str) -> str:
    return f"[{n}] {what}\n\n{NOTE_L15}."


@pytest.fixture(scope="module")
def dpa(legal_dom):
    return legal_dom("dpa.html")


@pytest.fixture(scope="module")
def msa(legal_dom):
    return legal_dom("msa.html")


@pytest.fixture(scope="module")
def terms(legal_dom):
    return legal_dom("terms.html")


# ── #201a — TWO ENTIRE-AGREEMENT CLAUSES ────────────────────────────────────
def test_201a_the_terms_yield_to_a_signed_msa(terms, msa):
    """msa.html §1 supersedes the public Terms for signing Customers. terms.html
    §15 constituted "the entire agreement" and carved out nobody, so both were
    live at once for the same customer. §15 now yields.

    ⚠ BOTH CLAUSES ARE ASSERTED. Deleting either one also "resolves" the
    conflict, and would be the wrong resolution: the public Terms still govern
    every self-serve customer, and the MSA still governs every signed one."""
    t = terms.text
    assert "constitute the entire agreement between you and us regarding the Service" in t, \
        _why15("#201a", "terms.html §15's entire-agreement clause is gone")
    assert ("For customers with a signed Master Service Agreement, that agreement "
            "and its Order Forms govern in place of these Terms") in t, \
        _why15("#201a", "terms.html §15 no longer yields to a signed MSA, so two "
                        "entire-agreement clauses govern the same customer again")

    # ⚠ THE CARVE-OUT MUST DISPLACE THE TERMS AND NOTHING ELSE. It first read
    # "govern instead", which attaches to the whole enumerated set and displaces
    # the Privacy Policy and Terms of Use too. msa.html §1 supersedes only "the
    # public Terms of Service", and the MSA incorporates only the DPA and SLA —
    # so the wide reading made the carve-out claim more than the MSA does.
    assert "govern instead" not in t, _why15(
        "#201a", "terms.html §15's carve-out is unqualified again. 'govern "
                 "instead' displaces the Privacy Policy and Terms of Use as well, "
                 "which msa.html §1 does not do")
    s15 = re.sub(r"\s+", " ", re.sub(r"<[^>]+>", " ", terms.section(15)))
    for survivor in ("Privacy Policy", "Terms of Use"):
        assert survivor in s15, _why15(
            "#201a", f"§15 stopped enumerating the {survivor}; the narrowed "
                     "carve-out exists so it stays in force for MSA customers")
    assert "is the entire agreement between the parties regarding the Service" in msa.text, \
        _why15("#201a", "msa.html's entire-agreement clause is gone — the carve-out "
                        "in terms.html now points at nothing")
    assert 'href="/msa.html"' in terms.src, \
        _why15("#201a", "terms.html names the MSA without linking it; a reader "
                        "cannot reach the agreement that displaces these Terms")


# ── #201b — A SURVIVAL LIST CITING A SECTION THAT DOES NOT EXIST ────────────
def test_201b_every_surviving_section_exists(msa):
    """msa.html §13 survived "15 (Governing Law)". The document ends at 14.

    ⚠ THE NUMBERS COME FROM THE PAGE'S HEADINGS, NOT FROM THE .docx AND NOT FROM
    THE DECISION'S OWN WORDING. The owner's note describes §14 as "Governing
    Law"; the page titles it "General provisions", with governing law as its
    first bullet. The page is what a customer reads, so the page won."""
    numbered = dict(re.findall(r'<h2 id="s(\d+)">(.*?)</h2>', msa.src))
    clause = re.search(r"Sections ([^.]+?) survive termination", msa.text)
    assert clause, _why15("#201b", "msa.html §13's survival clause is gone")
    cited = re.findall(r"\b(\d+)\b(?=\s*\()", clause.group(1))
    assert cited, _why15("#201b", "the survival clause cites no sections at all")
    dangling = [n for n in cited if n not in numbered]
    assert not dangling, _why15(
        "#201b", f"msa.html §13 survives Section(s) {dangling}, which the document "
                 f"has no heading for. It ends at {max(numbered, key=int)}")
    assert cited == ["8", "9", "12", "14"], _why15(
        "#201b", f"the survival list changed to {cited}; the decision settled 8, 9, "
                 "12, 14 — which obligations outlive the contract is not a "
                 "renumbering detail")
    assert "General provisions" in numbered["14"], _why15(
        "#201b", f"§14 is titled {numbered['14']!r} now — §13's label for it must "
                 "match the heading the page actually carries")


# ── #201c — THE DPA'S PARENT ────────────────────────────────────────────────
def test_201c_the_dpa_and_the_msa_name_the_same_parent(dpa, msa):
    """MSA §1(b) and §6 incorporated the DPA into the MSA while the DPA said it
    was part of the Terms of Service. "The Agreement" meant different documents
    on the two pages, so DPA §14 resolved differently depending on which page
    you read. The DPA's parent is now the MSA."""
    d = dpa.text
    assert "forms part of, and is incorporated by reference into, the Master Service Agreement" in d, \
        _why15("#201c", "dpa.html no longer names the MSA as its parent, "
                        "contradicting msa.html §1(b) and §6")
    assert "Data Processing Agreement (DPA)</a></strong>, incorporated by reference" in msa.src, \
        _why15("#201c", "msa.html §1(b) stopped incorporating the DPA — the DPA's "
                        "new parent clause now has nothing to match")
    # the self-serve route, which is the half that keeps the change honest
    assert "Where Customer has not signed a Master Service Agreement" in d, \
        _why15("#201c", "the DPA stopped saying which document is 'the Agreement' "
                        "for a customer who never signed an MSA")

    # ⚠ SLICED TO THE SENTENCE, NOT THE PAGE — [[a-window-is-not-a-scope]] in a
    # guard written to prevent exactly that. `'href="/terms.html"' in dpa.src`
    # was satisfied by the FOOTER, which links Terms on every legal page.
    # Measured: deleting the anchor from the fallback sentence still left
    # `-k 201c` at 2 passed.
    fallback = re.search(
        r"<p>Where Customer has not signed a Master Service Agreement.*?</p>",
        dpa.src, re.S)
    assert fallback, _why15("#201c", "the DPA's fallback sentence is gone")
    assert 'href="/terms.html"' in fallback.group(0), _why15(
        "#201c", "the DPA names the self-serve route without linking it. The "
                 "footer's Terms link does not count — a reader in the middle of "
                 "the parent clause needs the anchor there")
    # …and it points at the clause that does the incorporating, not just the page
    assert 'href="/terms.html#s5"' in fallback.group(0), _why15(
        "#201c", "the fallback no longer cites the Terms of Service section that "
                 "incorporates this DPA, so the claim rests on nothing a reader "
                 "can check")


def test_201c_the_terms_really_do_incorporate_the_dpa(terms, dpa):
    """⚠ THE CLAIM WAS ONE-SIDED, WHICH IS THE DEFECT #201c EXISTS TO FIX.

    The DPA's fallback says it "forms part of the Terms of Service". terms.html
    referenced the DPA NOWHERE — not in §5, not in §15's enumeration — so the
    only document asserting the relationship was the one that benefits from it.
    An incorporation by reference that the parent never makes is exactly the
    shape of the original #201c finding, reproduced in the fix for it.

    Resolved by making it true rather than by deleting the claim: a self-serve
    customer processing personal data needs a processor contract, and the DPA is
    published, listed on legal.html and cited by the Privacy Policy. Removing
    the claim would have left that population with no DPA at all.

    ⚠ BOTH PAGES ARE ASSERTED, AND THE PARENT'S SIDE IS ASSERTED FIRST."""
    t = terms.text
    assert ("our Data Processing Agreement governs that processing and is "
            "incorporated into these Terms by reference") in t, _why15(
        "#201c", "terms.html no longer incorporates the DPA, so the DPA's "
                 "fallback clause claims a relationship its parent does not make")
    s5 = re.sub(r"\s+", " ", re.sub(r"<[^>]+>", " ", terms.section(5)))
    assert "Data Processing Agreement" in s5, _why15(
        "#201c", "the incorporation left §5, which is the section the DPA's "
                 "fallback cites by number")
    s15 = re.sub(r"\s+", " ", re.sub(r"<[^>]+>", " ", terms.section(15)))
    assert "Data Processing Agreement" in s15, _why15(
        "#201c", "terms.html §15's entire-agreement clause stopped enumerating "
                 "the DPA while §5 still incorporates it — the two clauses on ONE "
                 "page now disagree about what the agreement consists of")
    assert 'href="/dpa.html"' in terms.src, _why15(
        "#201c", "terms.html names the DPA without linking it")


def test_201c_the_precedence_clauses_resolve_against_each_other(dpa, msa):
    """⚠ THE WARNING ATTACHED TO #201c, AND IT WAS A REAL ONE.

    Re-parenting the DPA put two precedence rules in conflict for the first
    time. MSA §1 ranks "Order Form, then this Agreement, then the DPA/SLA"; DPA
    §14 says the DPA prevails over "the Agreement". Under the old parent they
    never met, because §14 resolved against the Terms of Service.

    Both survive, each naming the other: §14 as the express exception, §1 as the
    ladder that carries it. A reader arriving from either page gets one answer.

    ⚠ ONE-SIDED WORDING IS WHAT CREATED THE DEFECT, so a one-sided fix fails."""
    assert "express exception to the general order of precedence" in dpa.text, \
        _why15("#201c", "DPA §14 no longer reconciles itself with MSA §1's ladder; "
                        "the two clauses each claim to win")

    # ⚠ THE SENTENCE MUST NOT REACH A SELF-SERVE READER. It first sent EVERY
    # reader to "Master Service Agreement Section 1", whose ladder ranks the
    # public Terms LAST — so a Terms-only customer was told their own governing
    # document sits below three they never signed. It is now conditioned.
    s14 = re.sub(r"\s+", " ", re.sub(r"<[^>]+>", " ", dpa.section(14)))
    assert "Where the Agreement is the Master Service Agreement" in s14, _why15(
        "#201c", "DPA §14's precedence sentence is unconditional again. A "
                 "self-serve customer's Agreement is the Terms of Service, and "
                 "MSA §1's ladder ranks those last — it must not be pointed at "
                 "them as if it governed their contract")
    # …and sentence one, the only part that binds a self-serve reader, still stands
    assert ("regarding the processing of personal data, this DPA prevails") in s14, \
        _why15("#201c", "DPA §14 lost the operative rule that applies to BOTH "
                        "populations; only the MSA-conditioned sentence remains")
    assert ("except that on the processing of personal data the DPA prevails "
            "over this Agreement") in msa.text, \
        _why15("#201c", "MSA §1's ladder dropped the carve-out, so it ranks the MSA "
                        "above the DPA without qualification while DPA §14 says the "
                        "opposite")


# ── #198 — THREE SUB-PROCESSOR LISTS ────────────────────────────────────────
def test_198_the_dpa_names_the_two_entities_it_was_missing(dpa):
    """privacy.html §8 and trust.html both named Payoneer and Google Cloud;
    dpa.html §5 named neither, calling the sixth an "infrastructure/hosting
    provider". The three-way comparison that would have caught this lives in
    test_site_wide_claims.py and did not exist until now — which is the actual
    finding. This pins the DPA's end of the decision."""
    d = dpa.text
    assert "Payoneer, Inc." in d, \
        _why15("#198", "dpa.html §5 dropped Payoneer again, so the DPA authorises "
                       "fewer sub-processors than the Privacy Policy discloses")
    assert "Google Cloud (Ubuntu VM)" in d, \
        _why15("#198", "dpa.html §5 no longer names the hosting entity by name")
    assert "infrastructure/hosting provider" not in d, \
        _why15("#198", "dpa.html §5 is generic about hosting again while the other "
                       "two pages name Google Cloud")


def test_198_the_three_way_guard_that_did_not_exist_now_does():
    """⚠ THE POINT OF #198 IS THE GUARD, NOT THE TWO NAMES.

    Three pages published one roster and each had its own green per-page checks.
    Nothing compared them, so they drifted and stayed drifted. If the comparison
    is ever deleted the roster silently becomes unguarded again, and the next
    drift will be as invisible as this one was.

    Read as source rather than imported, so deleting a function fails here even
    if the module still imports cleanly."""
    guard = (HERE / "test_site_wide_claims.py").read_text(encoding="utf-8")
    for fn in ("test_every_page_names_the_whole_sub_processor_roster",
               "test_no_page_names_a_sub_processor_the_others_do_not",
               "test_the_three_lists_are_the_same_length"):
        assert f"def {fn}(" in guard, _why15(
            "#198", f"{fn} was deleted. The three sub-processor rosters are "
                    "unguarded against each other again, which is exactly the "
                    "condition that let them drift")
    assert "ROSTER_SECTIONS" in guard and "dpa.html" in guard, _why15(
        "#198", "the three-way roster guard no longer covers all three pages")


# ── #200 — TWO CONTRACTS WITH NOTICE PROVISIONS AND NO NOTICE ADDRESS ───────
@pytest.mark.parametrize("page", ["dpa.html", "msa.html"])
def test_200_each_contract_states_where_notice_is_given(legal_dom, page):
    """MSA §3 requires 10 days' written notice of suspension and §13 requires 30
    days' of breach; the DPA takes written instructions, requests and objections
    throughout. Neither said where to send them. Both now name legal@, which is
    the mailbox these documents' own map assigns to contracts.

    ⚠ THE ADDRESS IS AN EXACT SET. Nothing else was authorised — in particular
    no postal address, because none is decided, and inventing one would look
    like completeness and be a fabrication."""
    dom = legal_dom(page)
    assert dom.addresses == {"legal@foxyaudit.tech"}, _why15(
        "#200", f"{page} publishes {sorted(dom.addresses)}. The decision "
                "authorised legal@foxyaudit.tech and nothing else")
    assert not POSTAL_ADDRESS.search(dom.text), _why15(
        "#200", f"{page} publishes a postal address; no registered office is "
                "decided, so any address on this page is invented")
    assert not re.search(r"\+\d[\d\s()-]{7,}", dom.text), _why15(
        "#200", f"{page} publishes a phone number, which #200 did not authorise")


def test_200_the_msa_notices_bullet_cites_customer_side_notice_provisions(msa):
    """⚠ THE SENTENCE EXISTING IS NOT THE SAME CLAIM AS THE SENTENCE BEING RIGHT.

    The first cut of this bullet cited §3 and §13. §3's only notice runs Foxy
    Audit → Customer ("Foxy Audit may suspend the Service on 10 days' written
    notice"), so a bullet about where to send notice TO Foxy Audit pointed at a
    provision under which the customer never sends anything. §4 — non-renewal,
    "unless either party gives notice" — is the one real customer-side notice in
    the document and was omitted.

    ⚠ THE CITED SECTIONS ARE RE-DERIVED AND THEIR DIRECTION IS RE-CHECKED. The
    guard that shipped asserted only that a notices sentence existed, which is
    why the wrong citation survived. This reads the numbers out of the bullet
    and asserts each names a BILATERAL notice provision, so a future edit cannot
    quietly point the reader at a one-way clause again."""
    bullet = re.search(r"<li><strong>Notices:</strong>(.*?)</li>", msa.src, re.S)
    assert bullet, _why15("#200", "msa.html's Notices bullet is gone")
    cited = re.findall(r'href="#s(\d+)"', bullet.group(1))
    assert cited == ["4", "13"], _why15(
        "#200", f"the Notices bullet cites Sections {cited}; the customer-side "
                "notice provisions are 4 (non-renewal) and 13 (breach)")
    for n in cited:
        body = re.sub(r"\s+", " ", re.sub(r"<[^>]+>", " ", msa.section(int(n))))
        assert re.search(r"either party", body, re.I), _why15(
            "#200", f"§{n} is cited as a route for notice TO Foxy Audit, but its "
                    "notice provision is not bilateral — re-read it before citing it")
    assert 'href="#s3"' not in bullet.group(1), _why15(
        "#200", "the Notices bullet cites §3 again. §3's notice runs Foxy Audit → "
                "Customer only, so it is not a provision the customer serves under")


def test_200_the_mailbox_matches_the_map_the_other_pages_use():
    """The control. legal@ is not a new mailbox minted for these two pages — it
    is the one the two Terms pages already use for contract questions. If that
    ever changes, these two should move with it rather than be left behind."""
    for page in ("terms.html", "terms-of-use.html"):
        src = (HERE / page).read_text(encoding="utf-8")
        assert "mailto:legal@foxyaudit.tech" in src, _why15(
            "#200", f"{page} no longer uses legal@ for contract questions — the "
                    "DPA and MSA were given that address to MATCH it")


# ── SLA §5 — WHOM THE SUPPORT TARGETS BIND ──────────────────────────────────
def test_sla_section_5_says_which_customers_its_targets_bind(legal_dom):
    """The SLA's header limits it to Order Form customers while §5's tables are
    keyed by plan names that pricing.html sells self-serve. L9 recorded it, L12
    proved §5 must stay plan-keyed (the Order Form template resolves a plan name
    through it), and the owner settled it with a scope line rather than a
    re-keying.

    ⚠ THE TABLES ARE UNTOUCHED AND STAY PINNED PER-CELL in test_sla_v14.py. This
    asserts only the sentence that was added."""
    t = legal_dom("sla.html").text
    assert "These response targets apply to customers under an Order Form." in t, _why15(
        "SLA §5", "the scope line is gone, so the plan-keyed tables again read as "
                  "a promise to self-serve customers the SLA's header excludes")
    # ⚠ THE FIRST WORDING OF THIS DECISION WAS WITHDRAWN ON REVIEW. It read
    # "Self-serve plans receive best-effort support via support@foxyaudit.tech",
    # which contradicted three published pages: contact.html sells Pro "1
    # business day" and Max "Priority", and pricing.html sells "Email support"
    # and "Priority support and onboarding" — to those same customers. A legal
    # page had written down a weaker promise than the site was actively making.
    # §5 now DEFERS to those pages instead of restating them.
    assert ("Self-serve plans receive the support channels and response times "
            "published on the pricing page and contact page.") in t, \
        _why15("SLA §5", "the scope line no longer points self-serve customers at "
                         "the pages that publish their support, which is the half "
                         "that keeps it from being a downgrade")
    assert "best-effort" not in t, _why15(
        "SLA §5", "the withdrawn wording is back. It promises less than "
                  "contact.html and pricing.html sell to the same customers")
    for plan in ("Pro", "Max, Premium", "Max / Premium"):
        assert plan in t, _why15(
            "SLA §5", f"§5 stopped keying off {plan!r}. The resolution KEPT the "
                      "plan keys — the Order Form template resolves through them")
