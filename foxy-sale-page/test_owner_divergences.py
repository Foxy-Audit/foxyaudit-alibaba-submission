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
