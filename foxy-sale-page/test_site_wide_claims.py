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

import pathlib
import re

import pytest

HERE = pathlib.Path(__file__).resolve().parent
ROOT = HERE.parent


def _backend(rel: str) -> str:
    return (ROOT / "backend" / "app" / rel).read_text(encoding="utf-8")


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
def test_no_page_claims_more_than_the_staff_chain_can_prove(page):
    """⚠ SITE-WIDE, AND IT FLIPS WITHOUT BEING EDITED.

    While the staff chain is unanchored, no page may call any audit trail
    immutable, tamper-proof or unalterable. When ``staff_chain_is_anchored()``
    goes true, the strong word is permitted everywhere — nobody has to remember
    to come back and delete a line.

    ⚠ WORTH READING BEFORE THE UPGRADE: anchor.py's own framing caution says an
    anchor makes tampering "externally detectable after the next anchor, not
    impossible", and that the project's phrase is "tamper-evident, independently
    verifiable". "Immutable" is stronger than that even with anchoring in place.
    That is the owner's call, not this test's."""
    if staff_chain_is_anchored():
        return
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
        f"{page} claims an audit trail is {found} while the staff chain is "
        'UNANCHORED. admin_chain.py:314 returns "sequence unbroken"; that is the '
        "strongest thing that is true today.")


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
    WORDING = "whose sequence is verifiable"
    DETAIL = "edited, removed from the middle, or re-ordered breaks the chain"
    for page in ("privacy.html", "trust.html", "dpa.html"):
        text = _page_text(HERE / page)
        assert WORDING in text, f"{page} no longer describes the staff trail honestly"
        assert DETAIL in text, f"{page} no longer says WHAT the chain actually detects"


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
    assert "admin" not in anchor.lower(), \
        "anchor.py now mentions the admin/staff side — has staff anchoring landed?"
    assert 'never "tamper-evident"' in chain, \
        "admin_chain.py dropped its 'until it exists' rule — has anchoring landed?"
    assert not staff_chain_is_anchored(), "the detector believes anchoring exists"
    assert "A wholesale delete is self-healing." in chain, "#144 no longer applies"
    assert "REMOVING ENTRIES FROM THE END leaves nothing behind" in chain, "#143 no longer applies"
    # the word appears nowhere in the code it describes — the page invented it
    for rel in ("anchor.py", "admin_chain.py", "admin_audit.py"):
        assert "immutable" not in _backend(rel).lower(), \
            f"{rel} now uses 'immutable' — check what changed"
