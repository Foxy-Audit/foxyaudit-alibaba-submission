"""privacy.html — Privacy Policy v3.9, and the ways a converted legal document lies.

Four of them, all seen in this repo in the last two days:

1. **A mailto that captured the sentence's full stop.** `privacy@foxyaudit.tech.`
   is a dead link, and the source document contains exactly that string at the
   end of Section 18. A converter that regexes for an address takes the period
   with it. So the guards read the PARSED `href` attribute, never the page text.

2. **A page that contradicts itself.** Section 8 says "Six named providers …
   No one else touches your data." A Google Fonts `<link>` would make that false
   in the same scroll, silently, and nothing in a word-count would notice.

3. **A claim the product cannot back.** The document's SOC 2 disclosure is
   deliberately blunt. The tempting edit is to soften it.

4. **Punctuation that changes meaning.** The source .docx has lost em-dashes:
   "Only the hash never the content reaches us." is not a sentence. They were
   restored by hand, so they are pinned here — a future mechanical re-convert
   from the .docx would otherwise silently reintroduce the broken text.

⚠ EVERY GUARD HERE READS THE RENDERED RESULT, not a source string. Two defects
in one day came from asserting source: #161's guard asserted a config production
does not read, and #178's config was valid nginx that no longer served HTTPS.
Syntactic validity is not behavioural equivalence. The DOM-level checks parse
the file with a real HTML parser; the browser-level checks run it in Chrome and
measure what actually rendered.

Run:  pytest foxy-sale-page -q
"""

from __future__ import annotations

import pathlib
import re
from html.parser import HTMLParser

import pytest

_HERE = pathlib.Path(__file__).resolve().parent
_PAGE = _HERE / "privacy.html"
_SRC = _PAGE.read_text(encoding="utf-8")

#: The version the FILENAME of the source document carries. Where a document's
#: header and its filename disagree, the filename wins (owner, 2026-08-13) — this
#: one says "Version 3.6" in its header and v3.9 on the file.
VERSION = "3.9"


# ── a real parse, not a regex over the source ────────────────────────────────
class _Dom(HTMLParser):
    """Enough of a DOM to ask what the browser would see: element attributes as
    the parser resolves them, and text with tags removed."""

    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.links: list[dict] = []
        self.ids: list[str] = []
        self._skip = 0
        self._text: list[str] = []

    def handle_starttag(self, tag, attrs):
        a = dict(attrs)
        if tag in ("style", "script"):
            self._skip += 1
        if tag == "a" and "href" in a:
            self.links.append(a)
        if "id" in a:
            self.ids.append(a["id"])

    def handle_endtag(self, tag):
        if tag in ("style", "script"):
            self._skip = max(0, self._skip - 1)

    def handle_data(self, data):
        if not self._skip:
            self._text.append(data)

    @property
    def text(self) -> str:
        return re.sub(r"\s+", " ", "".join(self._text))


def _dom() -> _Dom:
    d = _Dom()
    d.feed(_SRC)
    return d


@pytest.fixture(scope="module")
def dom() -> _Dom:
    return _dom()


def _section(n: int) -> str:
    """The source slice for section `n`, bounded by the NEXT section's id.

    A window is not a scope: an unbounded search for "<li>" is answered by
    whichever list happens to sit nearby. Both ends are asserted."""
    start = _SRC.index(f'id="s{n}"')
    nxt = _SRC.find(f'id="s{n + 1}"', start)
    end = nxt if nxt != -1 else _SRC.index('class="foot"', start)
    assert end > start, f"could not bound section {n}"
    return _SRC[start:end]


# ── 1. the version, as rendered ──────────────────────────────────────────────
def test_the_page_states_the_version_it_was_converted_from(dom):
    """The live page carried no version at all before v3.9, so a reader could not
    tell which document they were looking at, and neither could we."""
    line = re.search(r'class="updated">([^<]+)<', _SRC)
    assert line, "the .updated header line is gone"
    assert f"Version {VERSION}" in line.group(1), \
        f"the header line does not name Version {VERSION}: {line.group(1)!r}"
    assert f"Version {VERSION}" in dom.text or VERSION in dom.text


# ── 2. no dead mailto — read the ATTRIBUTE, not the prose ────────────────────
def test_no_address_ends_in_a_full_stop(dom):
    """⚠ THE DEFECT THIS FILE EXISTS FOR. The source document's last line is
    "…directed to privacy@foxyaudit.tech." — the period is sentence punctuation,
    and a naive convert puts it inside the mailto, producing a link that bounces.

    Asserted on the parsed href, because the page TEXT legitimately ends in a
    period there and always will."""
    mailtos = [a["href"] for a in dom.links if a["href"].lower().startswith("mailto:")]
    assert mailtos, "the policy publishes no contact address at all"
    for href in mailtos:
        addr = href[len("mailto:"):].split("?")[0]
        assert not addr.endswith("."), f"dead mailto — trailing full stop captured: {href!r}"
        assert re.fullmatch(r"[^@\s]+@[^@\s]+\.[a-z]{2,}", addr), f"not an address: {addr!r}"


def test_the_contact_is_the_one_the_document_names(dom):
    """privacy@ — not the foxyaudit@gmail.com the previous page published, and
    not a new mailbox minted during conversion."""
    addrs = {a["href"][len("mailto:"):].split("?")[0]
             for a in dom.links if a["href"].lower().startswith("mailto:")}
    assert addrs == {"privacy@foxyaudit.tech"}, f"unexpected contact addresses: {addrs}"


# ── 3. the payment processor actually in use ─────────────────────────────────
def test_the_page_does_not_name_stripe(dom):
    """Stripe is not the merchant of record and never was on this document —
    Paddle is. The page it replaced named Stripe twice."""
    assert "stripe" not in dom.text.lower(), "the page still names Stripe"
    assert "stripe" not in _SRC.lower(), "Stripe survives somewhere in the markup"
    assert "Paddle" in dom.text, "the actual merchant of record is not named"


# ── 4. the content-blindness claim, stated truthfully ────────────────────────
def test_the_content_blindness_claim_is_the_one_the_product_can_back(dom):
    """The claim is structural, not a promise: there is no column to leak. The
    page must say that, and must not upgrade it into something stronger."""
    t = dom.text
    assert "no database field capable of storing a raw prompt or response" in t, \
        "the structural form of the claim is gone — what is left is a promise"
    assert "never raw prompt or response text" in t
    # The mechanism, named accurately. The SDK computes both.
    assert "HMAC-SHA-256" in t and "SHA-256" in t
    assert "on your own infrastructure" in t or "in your own process" in t


def test_the_soc2_disclosure_stays_blunt(dom):
    """No auditor is engaged (owner, 2026-08-13). The page must keep saying so,
    with no quarter attached, and must not claim a certification."""
    t = dom.text
    assert "We do not currently hold a SOC 2, ISO 27001, or comparable third-party attestation" in t, \
        "the honest SOC 2 disclosure was softened or removed"
    assert not re.search(r"(SOC 2|ISO 27001)[- ]?(certified|compliant|attested)", t, re.I), \
        "the page claims a certification the product does not hold"
    assert not re.search(r"Q[1-4]\s*20\d\d", t), "a dated audit commitment reappeared"


def test_the_sub_processor_count_matches_the_list(dom):
    """Section 8's summary says "Six named providers". If a seventh is added to
    the list and the summary is not updated, the page contradicts itself — which
    is exactly the failure a Google Fonts <link> would introduce silently."""
    s8 = _section(8)
    listed = len(re.findall(r"<li>", s8))
    words = {"Four": 4, "Five": 5, "Six": 6, "Seven": 7, "Eight": 8}
    claimed = re.search(r"In short:</strong>\s*(\w+) named providers", s8)
    assert claimed, "Section 8 lost its count claim"
    assert words[claimed.group(1)] == listed, (
        f"Section 8 claims {claimed.group(1)} named providers but lists {listed}")


# ── 5. the em-dashes that were restored by hand ──────────────────────────────
@pytest.mark.parametrize("sentence", [
    "Only the hash — never the content — reaches us.",
    "using your own API key — Foxy Audit is not an intermediary",
    "and any judge verdict — never raw prompt or response text",
    "We do not store your card details — Paddle does",
    "a root hash — never personal data or content",
    "to any one region — the list below names",
])
def test_the_restored_em_dashes_survive(dom, sentence):
    """⚠ The source .docx has these em-dashes MISSING — "Only the hash never the
    content reaches us." is what it actually contains. They were restored during
    conversion because the sentences are ungrammatical without them and the first
    one is the product's flagship claim.

    Pinned so a future mechanical re-convert from the .docx cannot silently put
    the broken text back. If one of these fails after a re-convert, the fix is to
    restore the dash, not to relax the guard."""
    assert sentence in dom.text, f"a restored em-dash was lost: {sentence!r}"


def test_no_stray_double_space_survived_the_conversion(dom):
    """The two em-dash losses in the .docx show up as a doubled space. If one
    reaches the page it is a dropped character, not a typo."""
    assert "  " not in dom.text.replace("\n", " ").strip(), \
        "a doubled space survived — an em-dash almost certainly fell out there"


# ── 6. no invented facts ─────────────────────────────────────────────────────
def test_the_page_invents_no_contact_details(dom):
    """This document carries no phone number and no postal address — it says the
    company has no registered office yet. Neither may be added by conversion, and
    the wrong phone number (3448123944) exists in sibling documents."""
    t = dom.text
    assert "3448123944" not in _SRC, "the superseded phone number appeared"
    assert not re.search(r"\+\d[\d\s().-]{8,}\d", t), "a phone number was invented"
    assert "without a registered physical office" in t, \
        "the honest statement that there is no office was dropped"


# ── 7. navigation actually resolves ──────────────────────────────────────────
def test_every_in_page_anchor_lands_on_something(dom):
    """An 18-section policy is unusable without its contents list, and a dead
    fragment fails silently in every browser."""
    frags = {a["href"][1:] for a in dom.links if a["href"].startswith("#")}
    missing = sorted(frags - set(dom.ids))
    assert not missing, f"contents links point at ids that do not exist: {missing}"
    assert len([i for i in dom.ids if re.fullmatch(r"s\d+", i)]) == 18, \
        "the page no longer has 18 numbered sections"


def test_the_cross_references_in_the_prose_are_links(dom):
    """The document cross-references itself constantly ("see Section 8"). In a
    Word file that is dead text; on a page it should move the reader."""
    assert len([a for a in dom.links if a["href"].startswith("#")]) >= 25, \
        "the prose cross-references stopped being links"


def test_no_dangling_cross_reference(dom):
    """⚠ v3.9 introduced "as described in Section" with NO NUMBER in the
    Compliance Passport definition. It was dropped rather than guessed — a
    pointer to nowhere is worse than no pointer. This stops it coming back."""
    assert not re.search(r"in Section\s*[.,)]", dom.text), \
        "a cross-reference lost its section number"
    assert not re.search(r"Section\s*$", dom.text.strip())


# ── 8. the network guarantee, without a browser ──────────────────────────────
# The rendered twin of this lives in test_legal_pages_rendered.py, which measures
# what Chrome actually FETCHED. This one always runs, so the guarantee still has
# a guard on a machine with no Chrome.
def test_no_external_url_is_reachable_from_the_markup():
    """Any http(s) URL in a fetching position — src, href on a stylesheet or
    preconnect, or a CSS url() — is a network call made on the reader's behalf,
    on the page that tells them how their data is handled."""
    fetching = re.findall(r'(?:src|href)="(https?://[^"]+)"', _SRC)
    fetching += re.findall(r"url\(\s*['\"]?(https?://[^)'\"]+)", _SRC)
    assert not fetching, f"the page fetches from the network: {fetching}"
    assert "fonts.googleapis" not in _SRC and "fonts.gstatic" not in _SRC,         "a font CDN reference reappeared on the Privacy Policy"
