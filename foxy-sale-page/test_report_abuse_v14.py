"""report-abuse.html — Responsible Disclosure Policy v1.4.

⚠ L5 IS ABOUT TO MAKE THIS THE PROJECT'S OFFICIAL SECURITY POLICY. security.txt's
`Policy:` field currently points into a private repository and 404s for the
public; L5 repoints it here. After that an RFC 9116 file cites this page, so it
has to be complete and stable on its own — no dependency on a GitHub URL, no
promise the project cannot keep.

THE HONESTY IS THE FEATURE, AND IT IS THE THING MOST LIKELY TO BE "IMPROVED"

The document promises no response time, no bounty, and no PGP key. That is
deliberate: SECURITY.md states the reasoning — a promise the project cannot keep
is worse for a reporter than no promise. Every plausible invention is guarded
against below, because "we aim to acknowledge reports quickly" is exactly the
sentence someone will one day want to turn into "within 48 hours".

The safe-harbour undertaking and its four conditions are a legal commitment to a
researcher, not marketing copy, so they are pinned verbatim.

#15: A DISCLOSURE MUST NOT LAND IN THE SALES INBOX. Before this phase,
legal.html's "Found a vulnerability?" card linked to contact.html — a page that
mentions security nowhere, offers a personal Gmail address, and whose two calls
to action are the demo form that POSTs to /v1/leads. Guarded here, in both
directions.

Guards read the PARSED result, never a source string. Browser claims live in
test_legal_pages_rendered.py; cross-page links in test_legal_cross_links.py.

Run:  pytest foxy-sale-page -q
"""

from __future__ import annotations

import pathlib
import re

import pytest

from conftest import POSTAL_ADDRESS

PAGE = "report-abuse.html"
VERSION = "1.4"
PHONE = "+92 3398123944"
SUPERSEDED_PHONE = "3448123944"
SECURITY_MAILBOX = "security@foxyaudit.tech"

HERE = pathlib.Path(__file__).resolve().parent


@pytest.fixture(scope="module")
def dom(legal_dom):
    return legal_dom(PAGE)


# ── 1. WHAT MUST NEVER BE INVENTED ───────────────────────────────────────────
def test_no_response_time_is_promised(dom):
    """⚠ THE SINGLE MOST TEMPTING EDIT ON THIS PAGE. The document says "we aim to
    acknowledge reports quickly" and stops there, on purpose.

    A published SLA the project cannot keep is worse for a reporter than none:
    it converts a missed deadline into a broken commitment. If a response time is
    ever agreed, it belongs in the document first, and someone should decide it
    knowing it will be cited by an RFC 9116 file."""
    t = dom.text
    assert "We aim to acknowledge reports quickly" in t, \
        "the honest, unquantified acknowledgement sentence was removed"
    assert not re.search(r"\bwithin\s+\d+\s*(hours?|days?|business days?|hrs?)\b", t, re.I), \
        "a response-time commitment appeared"
    assert not re.search(r"\b\d+\s*(?:-|\s)?(?:hour|day|business[- ]day)s?\b(?![- ]old)", t, re.I), \
        "a time window appeared on a page that deliberately states none"
    assert not re.search(r"\b(?:SLA|service level|turnaround|response time)\b", t, re.I), \
        "a service-level promise appeared"


def test_no_bounty_or_reward_is_offered(dom):
    """Credit, yes. Money, no — and the document is explicit that recognition is
    what is on offer."""
    t = dom.text
    assert not re.search(r"\b(?:bounty|bug bounty|reward|payout|compensat\w+|"
                         r"paid|payment|swag|prize)\b", t, re.I), \
        "a reward was offered on a page that promises none"
    assert "glad to credit reporters who want recognition" in t, \
        "the credit-not-cash offer was dropped"


def test_no_pgp_key_or_fingerprint_is_published(dom):
    """A key published here would have to be one someone actually holds and
    monitors. There is none, so there is nothing to publish, and a fabricated
    fingerprint would be worse than plain email."""
    # ⚠ STRIP THE EMBEDDED FONT FIRST. The base64 blob contains "GPg" and "PgP"
    # as ordinary substrings — measured. This regex is case-SENSITIVE so it is
    # unaffected today, but the obvious "make it case-insensitive to be safe"
    # edit would turn it red on every legal page, which is how a good guard gets
    # deleted for crying wolf.
    t = dom.text + re.sub(r"base64,[A-Za-z0-9+/=]+", "base64,", dom.src)
    assert not re.search(r"BEGIN PGP|PGP|GPG|OpenPGP|fingerprint|0x[0-9A-Fa-f]{8,}", t, re.I), \
        "a PGP key or fingerprint appeared"


def test_no_address_or_figure_is_invented(dom):
    hit = POSTAL_ADDRESS.search(dom.text)
    assert not hit, f"a postal address was invented: {hit.group(0)!r}"
    assert not re.search(r"[$£€]\s?\d", dom.text), "a currency amount appeared"


# ── 2. THE SAFE-HARBOUR UNDERTAKING ──────────────────────────────────────────
def test_the_safe_harbour_commitment_is_verbatim(dom):
    """A legal undertaking to a researcher, not a slogan. If the wording changes,
    the protection someone relied on when they started testing changes with it."""
    assert ("If you research in good faith and follow this policy, we will not "
            "pursue legal action against you.") in dom.text, \
        "the safe-harbour undertaking no longer matches the document"


@pytest.mark.parametrize("condition", [
    "Give us reasonable time to investigate and fix before disclosing publicly.",
    "Only access the minimum data needed to demonstrate the issue — never view, "
    "modify, or exfiltrate other users' data.",
    "Avoid privacy violations, service degradation, denial-of-service, and any "
    "destruction of data.",
    "Do not run automated scanners against production without prior arrangement.",
])
def test_each_safe_harbour_condition_survives(dom, condition):
    """The undertaking is conditional on all four. Dropping one silently widens
    the protection; rewording one narrows it. Either way someone should have
    decided it deliberately."""
    assert condition in dom.text, f"a safe-harbour condition was lost or reworded: {condition[:52]!r}…"


# ── 3. #15 — where a disclosure actually goes ────────────────────────────────
def test_the_only_reporting_route_is_the_security_mailbox(dom):
    """Not support@ (the Refund Policy's), not legal@ (the two Terms pages'), and
    emphatically not the personal Gmail address this page published before."""
    assert dom.addresses == {SECURITY_MAILBOX}, f"unexpected addresses: {dom.addresses}"
    assert "gmail.com" not in dom.src.lower(), "a personal mailbox is published on the security page"
    for href in dom.mailtos:
        addr = href[len("mailto:"):].split("?")[0]
        assert not addr.endswith("."), f"dead mailto — trailing full stop captured: {href!r}"


def test_the_page_routes_nobody_into_sales(dom):
    """⚠ REGISTER #15. A researcher must not be handed to the demo funnel. This
    page links to no contact form, no demo booking, and nothing that POSTs a
    lead."""
    for bad in ("/contact.html", "/book-a-demo.html", "/pricing.html", "/v1/leads"):
        assert bad not in dom.src, f"the security page routes to {bad}"
    assert not re.search(r"<form\b", dom.src), "a form appeared on the disclosure page"


def test_the_legal_index_sends_vulnerabilities_here_and_not_to_contact(dom):
    """⚠ THE #15 DEFECT AS IT ACTUALLY SHIPPED. legal.html's Security card asked
    "Found a vulnerability?" and linked to contact.html — which mentions security
    nowhere, publishes a Gmail address, and whose two calls to action are the
    demo form that POSTs to /v1/leads.

    Asserted as a SLICE OF THAT CARD, not a grep of the file: legal.html links
    contact.html from other places quite legitimately, and a loose search would
    be answered by one of those."""
    index = (HERE / "legal.html").read_text(encoding="utf-8")
    start = index.index("<h3>Security</h3>")
    card_start = index.rindex('<a class="gcard"', 0, start)
    card = index[card_start:index.index("</a>", start)]
    assert "vulnerability" in card.lower(), "the Security card no longer mentions vulnerabilities"
    assert f'href="/{PAGE}' in card, \
        "the Security card does not link the disclosure policy"
    assert "contact.html" not in card and "book-a-demo" not in card, \
        "the Security card still routes a vulnerability report into the sales path"
    assert SECURITY_MAILBOX in card, "the card does not name the security mailbox"


# ── 4. the em-dashes the .docx lost ──────────────────────────────────────────
@pytest.mark.parametrize("sentence", [
    # ⚠ PROVED: v1.2 has "Tell us  we take it seriously" with a DOUBLED SPACE.
    # v1.4 collapsed it to one — the same laundering L2b found. And without the
    # dash the sentence inverts: "Tell us we take it seriously" reads as an
    # instruction to inform US that WE take it seriously.
    "Tell us — we take it seriously and we won't punish good-faith reporters.",
    "proof-of-concept — but do not include others' personal data",
    "demonstrate the issue — never view, modify, or exfiltrate other users' data",
])
def test_the_restored_em_dashes_survive(dom, sentence):
    """THREE missing, all invisible in v1.4 — the document shows zero doubled
    spaces, which is what a whitespace check calls clean.

    One is proved by the superseded v1.2, which carries the gap that v1.4
    normalised away. The other two were already single-spaced in v1.2 and rest on
    grammar: "demonstrate the issue never view" has no reading at all.

    The four dashes the document KEPT are all in bold list-item leads, which is
    the same tell as the three conversions before it."""
    assert sentence in dom.text, f"a restored em-dash was lost: {sentence[:56]!r}…"


def test_no_whitespace_gap_survived(dom):
    assert "  " not in dom.text, "a doubled space survived — a dropped character"
    assert not re.findall(r"\w +[,.;:](?:\s|$)", dom.text), "space before punctuation"


def test_the_dashes_that_survived_are_still_in_place(dom):
    """The four the .docx kept, each introducing a bold list-item lead."""
    for lead in ("Security vulnerabilities</strong> —", "Abuse of the service</strong> —",
                 "Data concerns</strong> —"):
        assert lead in dom.src, f"a surviving em-dash was lost: {lead!r}"
    assert "Responsible disclosure — our commitment" in dom.text


# ── 5. conversion hygiene ────────────────────────────────────────────────────
def test_the_page_states_the_version_it_was_converted_from(dom):
    """⚠ This is one of the five documents whose header version and filename
    AGREE — both say 1.4 — so there was no version decision to make here."""
    line = re.search(r'class="updated">([^<]+)<', dom.src)
    assert line, "the .updated header line is gone"
    assert f"Version {VERSION}" in line.group(1), \
        f"the header line does not name Version {VERSION}: {line.group(1)!r}"


def test_the_phone_number_is_the_owners(dom):
    assert SUPERSEDED_PHONE not in dom.src, "the superseded phone number was published"
    assert PHONE in dom.text, f"the owner's number is missing: {PHONE}"


def test_the_docx_page_chrome_was_not_pasted_in(dom):
    """⚠ THIS .docx IS DIFFERENT: it carries the rendered page's header and
    footer as document text. The footer in it is also the OLD one — it predates
    the Refund Policy and the Terms of Use.

    The page keeps its own incumbent footer, byte-identical, because footers are
    copy-pasted across all 21 pages and belong to L13. This asserts that no
    SECOND footer was introduced from the document."""
    assert dom.src.count('class="foot"') == 1, "a second footer was pasted in from the document"
    assert dom.src.count("Cryptographic compliance, not a promise") == 1
    assert dom.text.count("Back to home") == 1, "the document's header line was pasted in as content"


def test_the_reporting_route_is_reachable_without_reading_the_page(dom):
    """A researcher who reads one line must still leave with the right address."""
    assert 'class="route"' in dom.src, "the prominent reporting route was removed"
    lead_card = dom.src[dom.src.index('class="lead"'):dom.src.index('<h2')]
    assert SECURITY_MAILBOX in lead_card, "the mailbox is not stated above the fold"


# ── 6. the network guarantee, without a browser ──────────────────────────────
def test_no_external_url_is_reachable_from_the_markup(dom):
    fetching = re.findall(r'(?:src|href)="(https?://[^"]+)"', dom.src)
    fetching += re.findall(r"url\(\s*['\"]?(https?://[^)'\"]+)", dom.src)
    assert not fetching, f"the page fetches from the network: {fetching}"
    assert "https://" not in dom.src, "an absolute URL appeared on a legal page"


def test_the_page_depends_on_no_repository_url(dom):
    """⚠ MATTERS FOR L5. security.txt's Policy: field will cite this page BECAUSE
    the GitHub advisory URL it cites today 404s for the public — the repository
    is private. If this page grew a GitHub link it would reintroduce exactly the
    dead end L5 exists to remove.

    The document itself never mentions GitHub or advisories, unlike SECURITY.md."""
    t = dom.src.lower()
    for token in ("github", "gitlab", "advisor", "pull request", "issue tracker"):
        assert token not in t, f"the security policy now depends on {token!r}"


def test_the_embedded_faces_are_the_ones_the_siblings_ship(dom):
    pat = r"font-weight:(\d+);font-display:swap;src:url\(data:font/woff2;base64,([A-Za-z0-9+/=]+)\)"
    mine = dict(re.findall(pat, dom.src))
    sibling = dict(re.findall(pat, (HERE / "refund.html").read_text(encoding="utf-8")))
    assert set(mine) == {"600", "700"}, f"unexpected faces: {sorted(mine)}"
    assert mine == sibling, "the embedded Poppins has drifted from refund.html's"


def test_every_in_page_anchor_lands_on_something(dom):
    frags = {a["href"].split("#")[1] for a in dom.links if "#" in a["href"]}
    missing = sorted(frags - set(dom.ids))
    assert not missing, f"anchors point at ids that do not exist: {missing}"
    assert len([i for i in dom.ids if re.fullmatch(r"s\d+", i)]) == 4, \
        "the page no longer has its four sections"
