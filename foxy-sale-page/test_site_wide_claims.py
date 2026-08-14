"""Claims that must hold on EVERY page, not just the page we happened to be editing.

⚠ REGISTER #184, THIRD OCCURRENCE, AND THIS IS THE FIX FOR THE CLASS.

L8 found that trust.html claimed admin actions are recorded in an "immutable"
staff audit trail, when backend/app/admin_chain.py's own docstring forbids even
the weaker "tamper-evident" for that chain. L8b corrected trust.html and guarded
the word — with ``PAGE = "trust.html"``.

That guard was FILE-SCOPED, so it protected exactly the page we were looking at.
The identical false claim went on living in privacy.html §11 ("Every
administrative action is recorded in an immutable staff audit trail"), shipped by
L1 before anyone knew, and the DPA was about to add a third copy that CITED
privacy.html as its authority. Three pages, one claim, one guard covering one of
them.

The lesson is the same one this stream keeps paying for: a guard scoped to the
artifact in front of you is not a guard on the claim. Claims travel between
pages; guards have to travel with them. Anything asserted about the PRODUCT
belongs in this file, swept across every page, rather than in a single page's
module.

Run:  pytest foxy-sale-page -q
"""

from __future__ import annotations

import ast
import pathlib
import re

import pytest

HERE = pathlib.Path(__file__).resolve().parent
ROOT = HERE.parent


def _backend(rel: str) -> str:
    return (ROOT / "backend" / "app" / rel).read_text(encoding="utf-8")


def _staff_sentence(text: str) -> str:
    """The sentence describing the STAFF audit trail, and nothing else.

    ⚠ FOUND BY MUTATION. privacy.html says "tamper-evident audit ledger" twice
    about the CUSTOMER ledger, so a page-level `"tamper-evident" in text` check
    passed even after the staff sentence was reverted to its pre-anchor wording.
    The two chains are different claims and must be measured separately.
    """
    i = text.find("staff audit trail")
    if i < 0:
        i = text.find("staff-action log")
    assert i >= 0, "no staff-trail sentence on this page at all"
    start = max(text.rfind(". ", 0, i) + 1, 0)
    # ⚠ TWO SENTENCES, DELIBERATELY. The claim is one sentence and its LIMIT is
    # the next one ("Entries recorded before the chain existed are not covered by
    # it") — separated on purpose, because a limit buried in the same sentence as
    # the claim reads as a qualifier rather than a boundary. Scoping to one
    # sentence made the limit unassertable; scoping to the whole page let a
    # neighbouring customer-ledger claim satisfy it. Two sentences is the span
    # the claim actually occupies.
    end = text.find(". ", i)
    if end > 0:
        end2 = text.find(". ", end + 2)
        end = end2 if end2 > 0 else len(text)
    return text[start:end if end > 0 else len(text)]


def _page_text(path: pathlib.Path) -> str:
    """Page source with the embedded font stripped — the base64 blob is 21KB of
    letters and will match almost any short pattern (#192)."""
    return re.sub(r"base64,[A-Za-z0-9+/=]+", "base64,", path.read_text(encoding="utf-8"))


# ── the code-reading detector, moved here from test_trust_v17 ────────────────
def staff_chain_is_anchored() -> bool:
    """Does the staff-action chain have an EXTERNAL witness today?

    ⚠ THIS READS THE CODE, ON PURPOSE. The owner's decision (2026-08-13) is to
    anchor the staff chain and then allow "immutable" again. A plain string ban
    would have to be DELETED by whoever does that work — and a guard someone must
    remember to delete protects nothing before or after. So the guard asks the
    codebase, and flips by itself.

    Two independent signals, both required:

      1. THE ANCHORING MODULE TOUCHES THE STAFF CHAIN. anchor.py is how the
         customer ledger gets its witness: it reads ``AuditLog`` and records a
         receipt in ``ChainAnchor``. Today it does not mention the staff chain
         once. Anchoring it means that module (or an equivalent) must name the
         staff-action model.

      2. admin_chain.py HAS DROPPED ITS OWN "UNTIL IT EXISTS" RULE — the
         paragraph telling every surface to say "sequence unbroken", never
         "tamper-evident". Implementing anchoring means rewriting it or leaving
         a false instruction for the next reader.

    Signal 1 alone could fire on an unrelated mention; signal 2 alone on a
    docstring tidy-up. Together they are what shipping the feature looks like.
    """
    anchor = _backend("anchor.py")
    chain = _backend("admin_chain.py")
    touches_staff_chain = bool(re.search(r"\bAdminAction\b|admin_actions", anchor))
    rule_lifted = 'never "tamper-evident"' not in chain
    return touches_staff_chain and rule_lifted


#: Pages allowed to carry the word today, and exactly why. ⚠ A SKIP IS A PASS
#: (#195), so this is asserted to be EXACTLY this set — a page added to it
#: silently would be the #184 failure all over again.
KNOWN_EXCEPTIONS = {
    # A <meta name="description"> about the CUSTOMER audit ledger, not the staff
    # trail — a different chain, which is hash-chained and optionally anchored.
    # "tamper-proof" still overstates it (anchor.py: externally detectable after
    # the next anchor, "NOT IMPOSSIBLE"), but this is marketing copy on a page
    # the W stream owns, and correcting it here would be editing someone else's
    # surface. Reported instead. It is pinned so it cannot quietly spread.
    "book-a-demo.html": "tamper-proof AI audit trail",
}

OVERCLAIM = re.compile(
    r"\bimmutable\b|\btamper[- ]?proof\b|\bunalterable\b|"
    r"\bcannot be (?:altered|changed|modified|edited)\b|"
    r"\bimpossible to (?:alter|change|tamper)\b", re.I)


@pytest.mark.parametrize("page", sorted(p.name for p in HERE.glob("*.html")))
def test_no_page_claims_more_than_either_chain_can_prove(page):
    """⚠ SITE-WIDE, AND — A1 — NO LONGER SWITCHED OFF BY ANCHORING.

    THE DEFECT THIS REPLACES. L10 wrote this as:

        if staff_chain_is_anchored():
            return

    …so the ban lifted entirely the moment anchoring shipped. That was written
    on the owner's original decision ("anchor it, then say immutable"), and the
    premise did not survive contact with the code. anchor.py states it plainly:
    an anchor makes tampering "externally detectable after the next anchor, NOT
    IMPOSSIBLE. We say 'tamper-evident, independently verifiable'." The word
    "immutable" appears nowhere in backend/app/ or verifier/ — not about the
    staff chain and NOT ABOUT THE FULLY-ANCHORED CUSTOMER LEDGER EITHER.

    A1 ships the anchoring, which means A1 is the commit that would have tripped
    the early exit. So the ban is now UNCONDITIONAL: "immutable", "tamper-proof"
    and "unalterable" are forbidden on every page whatever the anchoring state,
    because there is no anchoring state in which they are true. Three reasons,
    all still live after A1:

      · the window between anchors is real — a change made and reverted between
        two anchors leaves no trace;
      · rows predating migration 0066 carry no hash and are not covered at all;
      · an anchor proves what a chain looked like, not that it cannot change.

    WHAT THE DETECTOR STILL DOES. ``staff_chain_is_anchored()`` is kept, and
    ``test_the_project_phrase_is_unlocked_by_anchoring`` uses it: the real
    upgrade anchoring earns is from "sequence unbroken" to the project's own
    phrase. That transition still needs no manual edit. Only the strong word
    stopped being on the other end of it."""
    found = sorted(set(m.group(0).lower() for m in OVERCLAIM.finditer(_page_text(HERE / page))))
    if page in KNOWN_EXCEPTIONS:
        # ⚠ NOT pytest.skip. A skip is a pass (#195), and this is the one page
        # where something IS expected to be found — so the excused page gets a
        # POSITIVE assertion instead: it must still carry exactly the overclaim
        # it was excused for, and nothing else. An excused page is the easiest
        # place to hide a second, unexcused claim.
        assert found == ["tamper-proof"], (
            f"{page} is excused for {KNOWN_EXCEPTIONS[page]!r}, but its overclaims "
            f"are now {found} — the exemption does not cover this")
        return
    assert not found, (
        f"{page} claims an audit trail is {found}. That is stronger than anything "
        "this product can prove, ANCHORED OR NOT: anchor.py says an anchor makes "
        "tampering 'externally detectable after the next anchor, not impossible', "
        "and the word appears nowhere in backend/app/ or verifier/. The project's "
        "phrase is 'tamper-evident, independently verifiable'.")


def test_the_known_exceptions_are_exactly_these_and_still_say_what_we_think():
    """⚠ A SKIP IS A PASS. The exception list is asserted exactly, and each entry
    is asserted to still contain the specific text it was excused for — so a page
    cannot be added silently, and an excused page cannot quietly grow a second,
    different overclaim."""
    actual = {p.name for p in HERE.glob("*.html")
              if OVERCLAIM.search(_page_text(p))}
    assert actual == set(KNOWN_EXCEPTIONS), (
        f"the set of pages carrying an overclaim changed: "
        f"unexpected={sorted(actual - set(KNOWN_EXCEPTIONS))}, "
        f"fixed={sorted(set(KNOWN_EXCEPTIONS) - actual)}")
    for page, why in KNOWN_EXCEPTIONS.items():
        text = _page_text(HERE / page)
        assert why in text, f"{page} no longer contains {why!r} — the excuse is stale"
        hits = sorted(set(m.group(0).lower() for m in OVERCLAIM.finditer(text)))
        assert hits == ["tamper-proof"], f"{page} grew a different overclaim: {hits}"


def test_the_three_pages_that_describe_the_staff_trail_agree():
    """privacy.html §11, trust.html §5 and dpa.html §7 all describe the same
    mechanism. They were allowed to drift once — trust.html was corrected while
    the other two still said "immutable", and the DPA cited privacy.html as its
    authority for the word. Pinned together so a correction to one is a
    correction to all three."""
    # ⚠ RE-AIMED IN A1. The three pages said "whose sequence is verifiable",
    # which was the strongest thing true before the staff chain had a witness.
    # It now has one, so all three move together to the project's own phrase —
    # and the tie is the point: L10 found this claim on three pages with only
    # one corrected.
    WORDING = "tamper-evident"
    # ⚠ SUBSTANCE, NOT ONE PAGE'S SENTENCE SHAPE. dpa.html §7 folds the four
    # failure modes into a single list ("edited, removed from the middle,
    # re-ordered, or removed from the end"), where trust and privacy use two
    # clauses. Pinning one page's punctuation would force the other two to copy
    # it, which is not what "these three must agree" means.
    DETAIL = "edited, removed from the middle"
    ENDS = "removed from the end"          # the #143 upgrade, on every page
    LIMIT = "before the chain existed"     # what the anchor does NOT cover
    for page in ("privacy.html", "trust.html", "dpa.html"):
        text = _page_text(HERE / page)
        staff = _staff_sentence(text)
        assert WORDING in staff, (
            f"{page} no longer uses the project's phrase for the staff trail. "
            "A1 anchored that chain, which earns 'tamper-evident, independently "
            "verifiable' and nothing stronger — see the Obsidian vault note "
            "'Owner-authorised divergences from the policy documents.md'.")
        assert DETAIL in staff, f"{page} no longer says WHAT the chain detects"
        assert ENDS in staff, (
            f"{page} lost the #143 upgrade — an entry removed from the END is now "
            "detectable, and that is the whole thing anchoring bought")
        assert LIMIT in staff, (
            f"{page} stopped stating that pre-chain entries are NOT covered; the "
            "claim would then reach further than the anchor does")


def test_no_legal_page_is_missing_from_the_shared_registries():
    """⚠ FOUND BY MUTATION, AND IT IS #184 A FOURTH TIME.

    Deleting ``"dpa.html"`` from ``test_legal_pages_rendered.PAGES`` was a green
    mutation: the page simply stopped being rendered, measured and checked, and
    nothing said so. Every registry that drives a sweep has this property — it
    protects what is listed in it, and a page dropped from the list looks exactly
    like a page that was never added.

    A hand-written "these are the legal pages" list would just be a third
    registry with the same weakness — 28 .html files live here and most are
    marketing. So the sweep is measured against something that is ALREADY the
    definition of the legal set and is maintained for its own reasons:
    **legal.html's cards**. The hub exists to link every legal document, so a
    document with a card must be swept, and a swept document must have a card.
    Each side pins the other; neither can shrink alone."""
    import test_legal_cross_links as links
    import test_legal_pages_rendered as rendered

    carded = {h.split("#")[0] for h in
              re.findall(r'<a class="gcard" href="/([^"]+)"',
                         (HERE / "legal.html").read_text(encoding="utf-8"))}
    assert carded == set(rendered.PAGES), (
        "the legal index and the rendered sweep disagree about what the legal "
        f"documents are: carded-but-unswept={sorted(carded - set(rendered.PAGES))}, "
        f"swept-but-uncarded={sorted(set(rendered.PAGES) - carded)}")
    on_disk = {p.name for p in HERE.glob("*.html")}
    assert carded <= on_disk, \
        f"legal.html cards documents that do not exist: {sorted(carded - on_disk)}"
    # legal.html is not a document but IS crawled for links, so it sits in the
    # cross-link registry and not the rendered one — that asymmetry is deliberate
    assert set(rendered.PAGES) | {"legal.html"} == set(links.PAGES), (
        "the rendered sweep and the cross-link sweep have drifted apart: "
        f"rendered-only={sorted(set(rendered.PAGES) - set(links.PAGES))}, "
        f"links-only={sorted(set(links.PAGES) - set(rendered.PAGES) - {'legal.html'})}")


def test_the_control_the_site_wide_guard_depends_on():
    """If this is wrong, everything above silently passes by wrongly believing
    anchoring exists."""
    anchor = _backend("anchor.py")
    chain = _backend("admin_chain.py")
    # ⚠ RE-AIMED IN A1 — THIS CONTROL PINNED THE STATE A1 CHANGED.
    # It asserted anchoring did NOT exist, so that a green ban above was a real
    # assertion rather than an accidental early exit. A1 shipped the anchoring,
    # so it now pins the opposite: both detector signals are TRUE, and the ban
    # above holds anyway. That is the whole point of the re-aim — the ban no
    # longer depends on this being false.
    assert re.search(r"\bAdminAction\b|admin_actions", anchor), \
        "anchor.py no longer names the staff model — was A1 reverted?"
    assert 'never "tamper-evident"' not in chain, \
        "admin_chain.py carries its 'until it exists' rule again — was A1 reverted?"
    assert staff_chain_is_anchored(), "the detector no longer sees A1's anchoring"
    # …and both register entries are still DESCRIBED. Anchoring ANSWERS them;
    # it does not delete the statement of what the chain alone cannot do.
    assert "A wholesale delete is self-healing." in chain, "#144's statement is gone"
    assert "REMOVING ENTRIES FROM THE END leaves nothing behind" in chain, "#143's statement is gone"
    assert "verify_admin_anchor" in chain, "the anchor check A1 added is gone"
    # The word appears nowhere in the code these pages describe — the page
    # invented it. Still true after A1, which is the point of the whole phase.
    #
    # ⚠ RUNTIME STRINGS, NOT PROSE. A plain substring check failed here the
    # moment A1's docstrings started EXPLAINING the ban ("does not make anything
    # immutable"). A guard satisfied by the sentence stating its own rule is the
    # oldest failure in this stream — it took L0, L5, and the backend twin of
    # this test. So the modules are parsed and only NON-DOCSTRING string
    # constants are examined: those are what can reach a response, a log, or the
    # console. Prose about the rule is exempt; a claim is not.
    for rel in ("anchor.py", "admin_chain.py", "admin_audit.py"):
        tree = ast.parse(_backend(rel))
        docs = {id(n.body[0].value) for n in ast.walk(tree)
                if isinstance(n, (ast.Module, ast.ClassDef, ast.FunctionDef,
                                  ast.AsyncFunctionDef))
                and getattr(n, "body", None)
                and ast.get_docstring(n, clean=False) is not None}
        for node in ast.walk(tree):
            if (isinstance(node, ast.Constant) and isinstance(node.value, str)
                    and id(node) not in docs):
                assert "immutable" not in node.value.lower(), (
                    f"{rel}:{node.lineno} has a RUNTIME string containing "
                    f"'immutable': {node.value[:70]!r} — the project's phrase is "
                    "'tamper-evident, independently verifiable'")


def test_the_project_phrase_is_unlocked_by_anchoring_and_the_strong_word_is_not():
    """⚠ THE FLIP THAT SURVIVED, AND THE ONE THAT DID NOT — BOTH ASSERTED.

    The detector is still worth having: anchoring genuinely upgrades what the
    staff trail may claim, from "sequence unbroken" to the project's own phrase,
    and nobody should have to remember to edit a test for that. What changed in
    A1 is the other end of the flip.

      anchored  -> "tamper-evident, independently verifiable" is PERMITTED
      anchored  -> "immutable" / "tamper-proof" is STILL FORBIDDEN

    Both halves are asserted against the live code, so this test states the
    policy rather than restating the implementation."""
    anchored = staff_chain_is_anchored()
    chain = _backend("admin_chain.py")

    # ⚠ WHITESPACE-NORMALISED. The phrase wraps across a line in the module
    # docstring, and a literal substring search cannot see a phrase that wraps.
    flat = " ".join(chain.split())
    if anchored:
        # the upgrade is real and the module says so
        assert "tamper-evident, independently verifiable" in flat, (
            "anchoring shipped but admin_chain.py never states the phrase it "
            "unlocks — the surfaces have nothing to be written against")
        pages = {p.name for p in HERE.glob("*.html")
                 if "tamper-evident, independently verifiable" in _page_text(p)}
        assert pages, ("anchoring shipped and no page uses the phrase it earns; "
                       "the upgrade exists in the code and nowhere a reader can see")
    else:
        assert 'never "tamper-evident"' in flat, \
            "unanchored, admin_chain.py must still hold its weaker rule"

    # …and the strong word stays banned either way. Measured, not assumed.
    for page in sorted(HERE.glob("*.html")):
        if page.name in KNOWN_EXCEPTIONS:
            continue
        hits = OVERCLAIM.findall(_page_text(page))
        assert not hits, (
            f"{page.name} overclaims ({hits}) with anchoring={anchored}. There is "
            "no anchoring state that permits it.")


# ── #198 — THE SUB-PROCESSOR ROSTER, DIFFED THREE WAYS ──────────────────────
#
# ⚠ THIS GUARD DID NOT EXIST, WHICH IS WHY THE THREE LISTS DRIFTED.
#
# The same roster is published in three places, in three different shapes:
# privacy.html §8 as bullets, trust.html §6 as table rows, dpa.html §5 as a
# parenthetical inside one sentence. Each page had its own guards and each was
# green, because every one of them asked whether ITS page was internally
# consistent. Nothing compared them, so dpa.html sat two entities short —
# missing Payoneer, and naming a generic "infrastructure/hosting provider" where
# the other two name Google Cloud — for as long as the three have existed.
#
# That is register #184 again, one level up: a guard scoped to a page is not a
# guard on a roster that lives on three of them. This is the comparison.

#: The entities, as the three pages must all name them. #198, owner decision
#: 2026-08-14. Six list items; Google and OpenAI share the first one.
SUB_PROCESSORS = ("Google LLC", "OpenAI, L.L.C.", "Paddle.com Market Ltd",
                  "Payoneer, Inc.", "Google Identity", "Brevo SAS", "Google Cloud")

#: Where each page keeps the roster.
ROSTER_SECTIONS = {"privacy.html": 8, "trust.html": 6, "dpa.html": 5}

#: ⚠ THE HALF A FIXED ROSTER CANNOT DO. Checking that seven known names appear
#: on all three pages says nothing about an EIGHTH appearing on one of them. A
#: new sub-processor is a company, and a company arrives with a legal suffix, so
#: the suffixes are counted as a multiset and compared across the three.
CORPORATE_SUFFIX = re.compile(
    r"(?<![\w.])(?:Inc\.|L\.L\.C\.|LLC|Ltd|SAS|GmbH|B\.V\.|S\.A\.|Corp\.|"
    r"PBC|AG|Pty|Oy|AB)(?!\w)")


def _roster_text(page: str) -> str:
    """The roster section of `page`, tags stripped, whitespace flattened.

    ⚠ SECTION-SLICED, NOT PAGE-SCOPED. privacy.html names Paddle again in §6 and
    Google again in §10; a page-wide search would be answered by those and would
    call a deleted §8 bullet present."""
    from conftest import load
    blob = load(page).section(ROSTER_SECTIONS[page])
    return re.sub(r"\s+", " ", re.sub(r"<[^>]+>", " ", blob))


@pytest.mark.parametrize("page", sorted(ROSTER_SECTIONS))
def test_every_page_names_the_whole_sub_processor_roster(page):
    """Entity for entity, all three lists, one failure per page that drifts."""
    text = _roster_text(page)
    missing = [e for e in SUB_PROCESSORS if e not in text]
    assert not missing, (
        f"{page}'s sub-processor list is missing {missing}. All three lists "
        f"(privacy.html §8, trust.html §6, dpa.html §5) must name the same "
        f"entities — that is #198, owner decision 2026-08-14.")


def test_no_page_names_a_sub_processor_the_others_do_not():
    """⚠ THE DIRECTION THE ROSTER ABOVE IS BLIND TO.

    A fixed list of expected names can only find deletions. This finds an
    ADDITION on one page by comparing what each list actually contains: the
    multiset of corporate suffixes must be identical across the three, so a new
    "Acme Ltd" on one page and not the others is a failure even though no
    expected name went missing."""
    found = {page: sorted(CORPORATE_SUFFIX.findall(_roster_text(page)))
             for page in sorted(ROSTER_SECTIONS)}
    distinct = {tuple(v) for v in found.values()}
    assert len(distinct) == 1, (
        f"the three sub-processor lists name different companies: {found}. "
        "One page gained or lost an entity the others did not.")
    # …and the one shape they agree on is the roster's, not some other set
    expected = sorted(CORPORATE_SUFFIX.findall(" ".join(SUB_PROCESSORS)))
    assert distinct.pop() == tuple(expected), (
        f"the three lists agree with each other but not with SUB_PROCESSORS "
        f"({expected}) — update the roster deliberately, or a company was added "
        "to all three at once without anyone deciding it")


def test_the_three_lists_are_the_same_length():
    """⚠ SUFFIXES MISS A SUFFIX-LESS BRAND. "Google Identity" and "Google Cloud"
    carry none, so a seventh bullet naming another such brand would pass both
    checks above. The item count catches it, and it is counted from each page's
    own markup rather than from a shared helper."""
    from conftest import load
    privacy = len(re.findall(r"<li>", load("privacy.html").section(8)))
    trust = len(re.findall(r"<tr><td>", load("trust.html").section(6)))
    # dpa.html §5's roster is one parenthetical; its items are semicolon-separated
    paren = re.search(r"\(currently: (.*?)\)\. Foxy Audit will:",
                      _roster_text("dpa.html"))
    assert paren, "dpa.html §5's sub-processor parenthetical is gone or was reshaped"
    dpa = len(paren.group(1).split(";"))
    assert privacy == trust == dpa == 6, (
        f"the three sub-processor lists have different lengths: "
        f"privacy.html={privacy}, trust.html={trust}, dpa.html={dpa} (expected 6 each)")


# ── SLA §5 vs THE PAGES THAT SELL SUPPORT ───────────────────────────────────
#
# ⚠ THIS COMPARISON DID NOT EXIST, WHICH IS HOW A DOWNGRADE GOT WRITTEN.
#
# sla.html §5 first resolved its scope with "Self-serve plans receive
# best-effort support via support@foxyaudit.tech." Every guard on the page went
# green. But contact.html sells Pro "1 business day" and Max "Priority", and
# pricing.html sells "Email support" and "Priority support and onboarding" — to
# exactly the self-serve customers that sentence was about. A legal page had
# quietly written down a weaker promise than the two pages taking the money.
#
# Nothing compared them, because §5's guards asked only whether §5 was
# internally consistent — the same shape as the three sub-processor rosters
# above. The SLA now DEFERS to those pages instead of restating them, which is
# the L14 rule ("a carve-out must defer, not duplicate") applied to a promise:
# one commitment, in one place, and the legal page points at it.

#: The self-serve plans whose support is sold on the marketing pages AND keyed
#: in sla.html §5's tables. The overlap is the whole problem — the same names
#: address two populations — so it is named once, here.
OVERLOADED_PLANS = ("Pro", "Max")

#: Wording that would make §5 state a self-serve support promise of its own
#: rather than defer. "best-effort" is the exact phrase that shipped.
SELF_SERVE_DOWNGRADE = re.compile(
    r"best[- ]effort|no response target|not guaranteed|as time permits|"
    r"without any response target|reasonable endeavours only", re.I)


def _sla_section_5() -> str:
    """sla.html §5, tags stripped. Bounded by §6, not by the end of the card."""
    from conftest import load
    return re.sub(r"\s+", " ", re.sub(r"<[^>]+>", " ", load("sla.html").section(5)))


def test_the_sla_does_not_state_a_self_serve_support_promise_of_its_own():
    """⚠ THE DEFECT THIS FILE EXISTS FOR, IN ITS NEWEST FORM.

    §5's scope line must say who its targets bind and then point at the pages
    that sell the other population's support. The moment it states that promise
    itself there are two of them to keep in step, and the legal one wins in an
    argument while the marketing one is what the customer actually bought."""
    s5 = _sla_section_5()
    hit = SELF_SERVE_DOWNGRADE.search(s5)
    assert not hit, (
        f"sla.html §5 states its own self-serve support promise ({hit.group(0)!r}). "
        "contact.html and pricing.html sell those customers a specific channel "
        "and response time; §5 must DEFER to them, not restate or weaken them.")
    assert "These response targets apply to customers under an Order Form." in s5, \
        "§5 lost the sentence that scopes its tables to Order Form customers"
    assert ("Self-serve plans receive the support channels and response times "
            "published on the") in s5, \
        "§5 no longer defers to the pages that publish self-serve support"


def test_the_sla_links_the_pages_it_defers_to():
    """A deferral a reader cannot follow is not a deferral — the same rule the
    AUP's disclosure carve-outs are held to (#194)."""
    from conftest import load
    s5_src = load("sla.html").section(5)
    for target in ("/pricing.html", "/contact.html"):
        assert f'href="{target}"' in s5_src, (
            f"sla.html §5 defers to the published support commitments but does "
            f"not link {target} from the section that defers")


@pytest.mark.parametrize("plan", OVERLOADED_PLANS)
def test_the_pages_the_sla_defers_to_actually_publish_that_plans_support(plan):
    """⚠ THE HALF THAT MAKES THE DEFERRAL REAL, AND IT IS THE DIFF.

    §5 points at pricing.html and contact.html for the self-serve promise. If
    either page stops publishing one, the pointer resolves to nothing and the
    only support commitment left for that plan is the Order Form table §5 says
    does not apply to them — which is the original defect, inverted.

    Both directions are checked: every plan §5 keys off is sold with support on
    the marketing pages, and every plan sold with support on contact.html is one
    §5 knows about."""
    from conftest import load
    s5 = _sla_section_5()
    assert re.search(rf"\b{plan}\b", s5), \
        f"sla.html §5 no longer keys off {plan!r}; the overload may be gone"

    contact = (HERE / "contact.html").read_text(encoding="utf-8")
    rows = {re.sub(r"<[^>]+>", "", c[0]).strip():
            [re.sub(r"<[^>]+>", "", x).strip() for x in c[1:]]
            for c in (re.findall(r"<span>(.*?)</span>", r)
                      for r in re.findall(r'<div class="sla-row">(.*?)</div>',
                                          contact, re.S))
            if len(c) >= 3}
    assert plan in rows, (
        f"contact.html no longer publishes a support row for {plan!r}, but "
        f"sla.html §5 defers self-serve customers to it")
    response, channel = rows[plan][0], rows[plan][1]
    assert response and channel, \
        f"contact.html's {plan!r} row publishes an empty commitment: {rows[plan]}"

    pricing = re.sub(r"\s+", " ", re.sub(r"<[^>]+>", " ",
                     (HERE / "pricing.html").read_text(encoding="utf-8")))
    assert re.search(r"\bsupport\b", pricing, re.I), \
        "pricing.html no longer sells support at all, and sla.html §5 points at it"


def test_no_self_serve_plan_is_sold_support_the_sla_has_never_heard_of():
    """The reverse direction. contact.html's table is the self-serve promise; if
    it grows a plan §5 does not key off, the two populations have diverged and
    §5's scope line no longer partitions them cleanly.

    ⚠ "Free trial" IS EXPECTED AND IS NOT A FAILURE. It is sold "Community"
    support and appears in no Order Form, so it is self-serve-only by design —
    pinned by name so a NEW unknown plan is what fails, rather than this one."""
    contact = (HERE / "contact.html").read_text(encoding="utf-8")
    plans = {re.sub(r"<[^>]+>", "", re.findall(r"<span>(.*?)</span>", r)[0]).strip()
             for r in re.findall(r'<div class="sla-row">(.*?)</div>', contact, re.S)
             if re.findall(r"<span>(.*?)</span>", r)}
    known = set(OVERLOADED_PLANS) | {"Free trial", "Plan"}
    unknown = plans - known
    assert not unknown, (
        f"contact.html publishes support for {sorted(unknown)}, which sla.html §5 "
        "does not key off. Either §5's tables or its scope line is now incomplete.")
