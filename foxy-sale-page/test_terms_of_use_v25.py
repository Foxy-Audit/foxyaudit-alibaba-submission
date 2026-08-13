"""terms-of-use.html — Terms of Use v2.5.

THE DOCUMENT THE PLAN DID NOT HAVE. MAIN's plan tabled eleven documents; the zip
holds twelve. This one had no phase, and the Terms of Service had been shipped
naming it twice — including inside the entire-agreement clause — with no page to
point at. It was found by checking whether that reference resolved.

⚠ AND IT IS THE STRONGEST EVIDENCE YET FOR #179.

The document shows ZERO doubled spaces and ZERO spaces before punctuation, which
is what a whitespace check calls clean. It is missing EIGHT em-dashes.

The superseded v2.3 proves it. v2.3 carries SIX doubled spaces; v2.5 carries
none, and every one of those six positions is now a single space with the same
words either side. Between the two versions someone normalised whitespace, which
collapsed the gaps and destroyed the only machine-visible evidence that anything
had been dropped. The damage is not merely ongoing — it is being laundered.

So the restored dashes are pinned individually below. A re-convert that puts the
broken text back turns these red one by one.

Guards read the PARSED result, never a source string. The claims that need a real
browser live in test_legal_pages_rendered.py; the cross-page link direction lives
in test_legal_cross_links.py.

Run:  pytest foxy-sale-page -q
"""

from __future__ import annotations

import pathlib
import re

import pytest

from conftest import POSTAL_ADDRESS as _POSTAL

PAGE = "terms-of-use.html"
VERSION = "2.5"
PHONE = "+92 3398123944"
SUPERSEDED_PHONE = "3448123944"


@pytest.fixture(scope="module")
def dom(legal_dom):
    return legal_dom(PAGE)


# ── 1. the em-dashes v2.5 lost and v2.3 can still prove ──────────────────────
@pytest.mark.parametrize("sentence", [
    # gap 1 in v2.3 — the only one in the lead
    'at foxyaudit.tech (the "Site") — browsing, reading, and general use by anyone',
    # NO gap in v2.3 either: lost before v2.3, visible only as bad grammar
    "for lawful, informational purposes — for example, to learn about the Service",
    # gaps 2 and 3 in v2.3 — a pair. Without them "content ... are owned" does not agree
    "The Site and its content — including text, graphics, the Foxy Audit name, logo, "
    "and other marks, and the underlying code and design — are owned by us",
    # gap 4 in v2.3 closed this pair; its opening was never visible
    "through the Site — for example, via a contact form, waitlist, or newsletter "
    "signup — you confirm that the information is accurate",
    # gap 5 in v2.3 closed this pair; its opening was never visible
    "Content on the Site — including blog posts, marketing material, and general "
    "compliance commentary — is provided for general informational purposes only",
])
def test_the_restored_em_dashes_survive(dom, sentence):
    """⚠ EIGHT missing across five places, ALL invisible in v2.5.

    Five of the eight are corroborated by a doubled space in v2.3 at the same
    position. The other three — the openings in §3, §5 and §7 — were already
    single-spaced in v2.3 and are established by grammar alone: "content …
    including … design are owned" has no agreeing subject without them.

    If one fails after a re-convert, restore the dash; do not relax the guard."""
    assert sentence in dom.text, f"a restored em-dash was lost: {sentence[:70]!r}…"


def test_the_document_has_no_remaining_whitespace_gap(dom):
    """v2.3's six doubled spaces are all gone from v2.5 — collapsed, not fixed.
    This asserts the page carries none either, so the next reader cannot mistake
    a laundered gap for a clean document."""
    assert "  " not in dom.text, "a doubled space survived"
    assert not re.findall(r"\w +[,.;:](?:\s|$)", dom.text), "space before punctuation"


def test_the_dashes_that_survived_are_still_where_they_were(dom):
    """The four the .docx kept — all four inside §13's bold policy names, which
    is the whole tell: bold runs survive, running prose does not."""
    s13 = dom.section(13)
    assert s13.count("—") == 4, \
        f"section 13 should carry the document's four surviving em-dashes, has {s13.count('—')}"


# ── 2. version, contacts, phone ──────────────────────────────────────────────
def test_the_page_states_the_version_it_was_converted_from(dom):
    """Header says "Version 1.0"; the filename says v2.5 and wins (owner)."""
    line = re.search(r'class="updated">([^<]+)<', dom.src)
    assert line, "the .updated header line is gone"
    assert f"Version {VERSION}" in line.group(1), \
        f"the header line does not name Version {VERSION}: {line.group(1)!r}"
    assert "Version 1.0" not in dom.text, "the document's stale header version was published"


def test_no_address_ends_in_a_full_stop(dom):
    assert dom.mailtos, "the page publishes no contact address at all"
    for href in dom.mailtos:
        addr = href[len("mailto:"):].split("?")[0]
        assert not addr.endswith("."), f"dead mailto — trailing full stop captured: {href!r}"
        assert re.fullmatch(r"[^@\s]+@[^@\s]+\.[a-z]{2,}", addr), f"not an address: {addr!r}"


def test_the_contact_is_the_one_the_document_names(dom):
    assert dom.addresses == {"legal@foxyaudit.tech"}, f"unexpected addresses: {dom.addresses}"


def test_the_phone_number_is_the_owners(dom):
    assert SUPERSEDED_PHONE not in dom.src, "the superseded phone number was published"
    assert f"{PHONE}." in dom.text, f"the owner's number is missing or unpunctuated: {PHONE}"


# ── 3. the scope boundary this document exists to draw ───────────────────────
def test_the_page_says_it_governs_browsing_and_not_the_product(dom):
    """The ONLY substantive job of this document: it covers the marketing site,
    and the Terms of Service cover the product. If that boundary blurs, the two
    documents overlap and neither is authoritative."""
    t = dom.text
    assert "govern casual, non-account access to the Foxy Audit public website" in t
    assert "your use of the product itself is governed by our separate Terms of Service" in t
    assert "No account or payment is required to browse the Site." in t


def test_the_liability_figure_is_the_documents_own(dom):
    """USD $100 is written in the source. It is a number in a liability clause,
    so it is pinned: if the document changes it, someone reads the change."""
    t = dom.text
    assert "ONE HUNDRED U.S. DOLLARS (USD $100)" in t
    assert "UNLESS APPLICABLE LAW REQUIRES OTHERWISE" in t


def test_the_governing_law_matches_the_terms_of_service(dom):
    """The document says "matched to the Terms of Service" — so if one moves and
    the other does not, they stop matching and the page says something false."""
    tou = dom.text
    sibling = (pathlib.Path(__file__).resolve().parent / "terms.html").read_text(encoding="utf-8")
    assert "governed by the laws of the Islamic Republic of Pakistan" in tou
    assert "matched to the Terms of Service" in tou
    assert "the Islamic Republic of Pakistan" in sibling, \
        "the Terms of Service no longer names the law this page claims to match"


def test_the_disclaimer_stays_conspicuous(dom):
    assert 'THE SITE IS PROVIDED "AS IS" AND "AS AVAILABLE,"' in dom.text
    assert "text-transform:uppercase" not in dom.src, \
        "the disclaimer is only visually capitalised; the text underneath is not"


def test_no_invented_facts(dom):
    """No postal address, no second phone, no forum this document does not set.
    §11 gives governing law but names NO court — unlike the Terms of Service,
    which sets Islamabad. That silence is the document's, and is not filled in."""
    t = dom.text
    assert not _POSTAL.search(t), f"a postal address was invented: {_POSTAL.search(t).group(0)!r}"
    assert len(re.findall(r"\+92", t)) == 1, "more than one phone number appears"
    assert "exclusive jurisdiction" not in t, \
        "a forum was invented — this document sets governing law only"


# ── 4. navigation and the sibling links ──────────────────────────────────────
def test_every_in_page_anchor_lands_on_something(dom):
    frags = {a["href"][1:] for a in dom.links if a["href"].startswith("#")}
    missing = sorted(frags - set(dom.ids))
    assert not missing, f"contents links point at ids that do not exist: {missing}"
    assert len([i for i in dom.ids if re.fullmatch(r"s\d+", i)]) == 14, \
        "the page no longer has 14 numbered sections"


def test_section_13_links_all_four_policies_it_names(dom):
    """§13 is the document's map of the policy set. All four pages it names exist
    today, so all four are anchors — the reverse guard in
    test_legal_cross_links.py enforces this in general."""
    s13 = dom.section(13)
    for target in ("terms.html", "privacy.html", "cookie-policy.html", "acceptable-use.html"):
        assert f'href="/{target}"' in s13, f"section 13 names a policy but does not link {target}"


def test_the_terms_of_service_links_back(dom):
    """⚠ THE HALF THAT HAD NO GUARD (#184). terms.html names this document twice,
    including in its entire-agreement clause, and shipped both unlinked because
    the page did not exist. The general reverse guard covers this now; this is
    the specific, so the pairing cannot be broken quietly."""
    sibling = (pathlib.Path(__file__).resolve().parent / "terms.html").read_text(encoding="utf-8")
    assert sibling.count(f'href="/{PAGE}"') == 2, (
        f"terms.html should link {PAGE} from both places it names it "
        f"(the lead and the entire-agreement clause); found "
        f"{sibling.count(f'href=/{PAGE}')}")


def test_the_legal_index_lists_this_page(dom):
    index = (pathlib.Path(__file__).resolve().parent / "legal.html").read_text(encoding="utf-8")
    assert f'href="/{PAGE}"' in index, "legal.html does not list the Terms of Use"


# ── 5. the network guarantee, without a browser ──────────────────────────────
def test_no_external_url_is_reachable_from_the_markup(dom):
    fetching = re.findall(r'(?:src|href)="(https?://[^"]+)"', dom.src)
    fetching += re.findall(r"url\(\s*['\"]?(https?://[^)'\"]+)", dom.src)
    assert not fetching, f"the page fetches from the network: {fetching}"
    assert "https://" not in dom.src, "an absolute URL appeared on a legal page"


def test_the_embedded_faces_are_the_ones_the_siblings_ship(dom):
    pat = r"font-weight:(\d+);font-display:swap;src:url\(data:font/woff2;base64,([A-Za-z0-9+/=]+)\)"
    here = pathlib.Path(__file__).resolve().parent
    mine = dict(re.findall(pat, dom.src))
    sibling = dict(re.findall(pat, (here / "terms.html").read_text(encoding="utf-8")))
    assert set(mine) == {"600", "700"}, f"unexpected faces: {sorted(mine)}"
    assert mine == sibling, "the embedded Poppins has drifted from terms.html's"
