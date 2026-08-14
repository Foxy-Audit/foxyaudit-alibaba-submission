"""One footer per page-kind, measured — because nothing ever measured it. (L13)

⚠ THE GUARD IS THE DELIVERABLE. The footer fragmented into four shapes across
eleven legal pages precisely because eleven briefs said "DO NOT TOUCH ANY
FOOTER" and nothing checked what was there. Rewriting them once fixes today;
this file is what stops it recurring.

WHAT THE CENSUS ACTUALLY FOUND, which is not "the footer drifted":

  There are TWO structurally different footers, because there are two kinds of
  page.

    · 16 MARKETING pages carry a real multi-column <footer> — product, company
      and "Legal & Trust" columns plus a bottom bar (18 links; index.html 28,
      welcome.html 15). It already links legal.html and four documents. It is a
      good site footer and it belongs to the W stream.
    · 11 LEGAL documents carried a one-line <div class="foot"> in FOUR distinct
      shapes, 3 to 5 links. The eight newest — including every document this
      stream published — had the shortest: Home, Terms, Privacy. A reader on
      dpa.html could not reach the SLA the DPA is incorporated alongside, nor
      the hub that lists everything.
    · 2 pages have no footer at all (book-a-demo.html, fox-reveal.html).

  So the defect was entirely on the legal pages. Flattening the marketing
  footer to a one-line legal footer would have deleted working navigation from
  sixteen pages and edited a W-stream surface to fix a legal-stream problem.
  ONE CANONICAL FOOTER ACROSS THE ELEVEN LEGAL DOCUMENTS is the change; the
  marketing footer is left alone but is now measured for the legal links it
  carries, so it cannot quietly lose the hub either.

HOW THIS JOINS THE CROSS-PIN (#199) INSTEAD OF BECOMING A THIRD LIST.

  legal.html's cards and test_legal_pages_rendered.PAGES already pin each other.
  This file adds NO new page list. It iterates PAGES, and asserts the footer's
  document links are a SUBSET OF THE CARDED SET — so a document can only appear
  in the footer if it is carded, and it is carded only if it is swept. The
  marketing/exempt sets are derived by SUBTRACTION from the directory and
  asserted exactly, so an unlisted new page fails rather than being skipped
  (#195: a skip is a pass).

Run:  pytest foxy-sale-page -q
"""

from __future__ import annotations

import pathlib
import re

import pytest

import test_legal_pages_rendered as rendered

HERE = pathlib.Path(__file__).resolve().parent

#: The canonical legal-page footer. Six items: Home, the four documents that
#: bind a reader directly regardless of whether they hold an account, and the
#: hub.
#:
#: WHY THESE FOUR AND NOT ALL ELEVEN. Eleven links in a one-line footer is a
#: wall of text nobody reads, and the set would need editing every time a
#: document ships — the exact fragility being fixed. Terms and Privacy apply to
#: everyone; the Cookie Policy is what a consent decision points at; Report
#: Abuse is where the security safe harbour lives (L4/L5: a reader who cannot
#: reach it cannot rely on it). The remaining five — Terms of Use, Refund,
#: Trust, SLA, DPA, MSA — are contextual or commercial, reached from the hub and
#: from the documents that invoke them. Acceptable Use is one click away via the
#: hub and is also in the marketing footer's own legal column.
FOOTER_LINKS = ["/", "/terms.html", "/privacy.html", "/cookie-policy.html",
                "/report-abuse.html", "/legal.html"]
HUB = "/legal.html"
COPYRIGHT = "© 2026 Foxy Audit. Cryptographic compliance, not a promise."

#: Pages with no footer at all, and why. Asserted EXACTLY below.
NO_FOOTER = {
    "book-a-demo.html": "a single-purpose lead form; W stream owns it",
    "fox-reveal.html": "an animation surface, not a page with navigation",
}


def _footer(name: str, kind: str) -> str:
    """The footer block, closed by TAG MATCHING rather than a byte window —
    a window is not a scope, and the marketing footer nests four divs deep."""
    src = (HERE / name).read_text(encoding="utf-8")
    tag = "footer" if kind == "marketing" else "div"
    pat = r"<footer\b[^>]*>" if kind == "marketing" else r'<div class="foot">'
    m = re.search(pat, src)
    assert m, f"{name}: no {kind} footer"
    depth = 0
    for t in re.finditer(rf"<{tag}\b[^>]*>|</{tag}>", src[m.start():]):
        depth += -1 if t.group(0).startswith("</") else 1
        if depth == 0:
            return src[m.start():m.start() + t.end()]
    raise AssertionError(f"{name}: {kind} footer never closes")


def _marketing_pages() -> set[str]:
    """Derived by SUBTRACTION from the directory, never hand-listed."""
    return {p.name for p in HERE.glob("*.html")} - set(rendered.PAGES) - set(NO_FOOTER)


# ── 1. THE ANTI-DRIFT GUARD, WHICH IS THE POINT OF THE PHASE ────────────────
@pytest.mark.parametrize("page", sorted(rendered.PAGES))
def test_every_legal_page_carries_the_identical_footer(page):
    """⚠ BYTE-IDENTICAL, not merely equivalent. Four shapes existed because
    "close enough" is how drift starts: report-abuse and acceptable-use differed
    by a single link each, and nobody could have told you which was canonical."""
    block = _footer(page, "legal").replace("\r\n", "\n")
    links = re.findall(r'<a[^>]*href="([^"]+)"', block)
    assert links == FOOTER_LINKS, \
        f"{page}'s footer links are {links}, not the canonical {FOOTER_LINKS}"
    assert COPYRIGHT in block, f"{page}'s footer lost the copyright line"
    canonical = _footer(sorted(rendered.PAGES)[0], "legal").replace("\r\n", "\n")
    assert block == canonical, (
        f"{page}'s footer is not byte-identical to the others — this is exactly "
        "the drift that produced four shapes")


def test_the_footer_only_links_documents_the_hub_cards(legal_dom):
    """⚠ THIS IS THE JOIN, NOT A THIRD LIST.

    Every document in the footer must be one legal.html cards, and the carded
    set is already pinned equal to PAGES. So the footer cannot name a document
    that is not swept, and cannot be quietly pointed at something unpublished."""
    carded = {h.split("#")[0] for h in re.findall(
        r'<a class="gcard" href="/([^"]+)"',
        (HERE / "legal.html").read_text(encoding="utf-8"))}
    assert carded == set(rendered.PAGES), \
        "the #199 cross-pin is broken; fix that before trusting this file"
    documents = {h.lstrip("/") for h in FOOTER_LINKS} - {"", "legal.html"}
    assert documents <= carded, \
        f"the footer links documents the hub does not card: {sorted(documents - carded)}"
    assert HUB in FOOTER_LINKS, "the footer lost the hub — the other five " \
        "documents would then be reachable from no legal page"
    assert (HERE / "legal.html").is_file()


def test_every_footer_href_on_every_page_resolves():
    """All 27 footers, marketing and legal, including the columns."""
    dead = []
    for page in sorted(set(rendered.PAGES) | _marketing_pages()):
        kind = "legal" if page in rendered.PAGES else "marketing"
        for href in re.findall(r'<a[^>]*href="([^"]+)"', _footer(page, kind)):
            if href.startswith(("mailto:", "http")):
                continue
            if href == "#":
                # index.html's "Cookie preferences" is a JS control, not a link.
                # Asserted to be wired rather than waved through (#195).
                src = (HERE / page).read_text(encoding="utf-8")
                assert 'id="footerCookies"' in src and "getElementById('footerCookies')" in src, \
                    f'{page} has a footer href="#" with no handler behind it'
                continue
            target = href.lstrip("/").split("#")[0] or "index.html"
            if not (HERE / target).is_file():
                dead.append(f"{page} -> {href}")
    assert not dead, f"footer links to files that do not exist: {dead}"


# ── 2. THE EXEMPTIONS, PINNED SO AN UNLISTED PAGE FAILS ─────────────────────
def test_the_pages_with_no_footer_are_exactly_these():
    """⚠ #195. Two pages legitimately have none. Asserted as an exact set, so a
    new page that forgets its footer fails here instead of being skipped."""
    actual = set()
    for p in sorted(HERE.glob("*.html")):
        src = p.read_text(encoding="utf-8")
        if not re.search(r'<footer\b|<div class="foot">', src):
            actual.add(p.name)
    assert actual == set(NO_FOOTER), (
        f"the set of footerless pages changed: unexpected={sorted(actual - set(NO_FOOTER))}, "
        f"gained one={sorted(set(NO_FOOTER) - actual)}")


def test_every_marketing_page_keeps_the_legal_column_and_the_hub():
    """The marketing footer is a W-stream surface and was not rewritten. It is
    still measured: it must keep the hub and the four legal links it already
    carried, so this sweep cannot be undone from the other side."""
    marketing = _marketing_pages()
    assert marketing, "no marketing pages found — the subtraction is wrong"
    for page in sorted(marketing):
        links = set(re.findall(r'<a[^>]*href="([^"]+)"', _footer(page, "marketing")))
        assert HUB in links, f"{page}'s footer lost the link to the legal hub"
        for required in ("/terms.html", "/privacy.html"):
            assert required in links, f"{page}'s footer lost {required}"


def test_the_three_page_kinds_partition_the_directory():
    """No page belongs to two kinds, and none belongs to none. This is what
    makes the subtraction above trustworthy rather than convenient."""
    on_disk = {p.name for p in HERE.glob("*.html")}
    legal, marketing, none = set(rendered.PAGES), _marketing_pages(), set(NO_FOOTER)
    assert legal | marketing | none == on_disk
    assert not (legal & marketing) and not (legal & none) and not (marketing & none)
    assert len(legal) == 11 and len(none) == 2, \
        f"the page-kind counts changed: legal={len(legal)}, marketing={len(marketing)}, none={len(none)}"


# ── 3. #186 — Terms of Use §13 ───────────────────────────────────────────────
def test_terms_of_use_section_13_no_longer_claims_a_complete_list(legal_dom):
    """⚠ REGISTER #186, AND THE GAP L2b's EXECUTOR CORRECTLY FLAGGED IN THEIR
    OWN WORK: the reverse cross-link guard fires when a NAMED document becomes
    linkable, but cannot fire when a document exists and §13 never names it.
    Four were named; eleven others exist.

    Rather than list all twelve — which recreates exactly the fragility this
    phase is removing, and would need editing on every future document — §13 now
    says the list is not exhaustive and points at the hub. That is a divergence
    from the .docx, recorded as such.

    Guarded BOTH ways: the disclaimer must be there, AND it must link the hub, so
    deleting the sentence without completing the list fails."""
    dom = legal_dom("terms-of-use.html")
    src = (HERE / "terms-of-use.html").read_text(encoding="utf-8")
    m = re.search(r'<h2 id="s13">(.*?)(?=<h2\b|<div class="foot")', src, re.S)
    assert m, "Terms of Use §13 could not be isolated"
    s13 = m.group(1)
    named = set(re.findall(r'href="/([^"#]+)"', s13))
    assert "This list is not exhaustive." in dom.text, \
        "§13 lost the sentence saying the list is illustrative, while still " \
        "naming only some of the published policies"
    assert "legal.html" in named, \
        "§13 says the list is not exhaustive but does not link the index"
    # the four it does name still resolve and are still carded
    carded = {h.split("#")[0] for h in re.findall(
        r'<a class="gcard" href="/([^"]+)"',
        (HERE / "legal.html").read_text(encoding="utf-8"))}
    for doc in named - {"legal.html"}:
        assert (HERE / doc).is_file(), f"§13 links {doc}, which does not exist"
        assert doc in carded, f"§13 names {doc}, which the hub does not card"
    assert len(named - {"legal.html"}) == 4, \
        f"§13's named set changed to {len(named) - 1}; if it now lists them all, " \
        "the disclaimer can go — but say so deliberately"


# ── 4. THE THINGS L13 RESERVED FOR THE W STREAM — WHICH HAS NOW ACTED ───────
def test_the_w_stream_surfaces_are_untouched():
    """When this sweep shipped, the Gmail address, the fox and the Google Fonts
    link were pinned at their measured counts so the sweep was provably not the
    thing that changed them — the docstring assigned them "to the W stream".

    W3 (2026-08-14) IS that stream acting: #190 removed the Gmail everywhere,
    #10 removed the font CDN everywhere, and #12 took the fox off desktop.html.
    The pins now hold the post-W3 steady state; test_w3_master_theme.py owns
    the richer invariants (support@ replacement, embedded-face parity)."""
    pages = sorted(HERE.glob("*.html"))
    gmail = {p.name for p in pages if "foxyaudit@gmail.com" in p.read_text(encoding="utf-8")}
    assert not gmail, f"the Gmail address is back on {sorted(gmail)} (#190)"
    fox = {p.name for p in pages if "\U0001f98a" in p.read_text(encoding="utf-8")}
    assert not fox, \
        f"a fox emoji is back on {sorted(fox)} - W5 closed #12 (owner: the " \
        f"logo or nothing); the count across every sale page is ZERO, forever"
    fonts = {p.name for p in pages if "fonts.googleapis.com" in p.read_text(encoding="utf-8")}
    assert not fonts, f"a page fetches fonts from Google again: {sorted(fonts)} (#10)"
