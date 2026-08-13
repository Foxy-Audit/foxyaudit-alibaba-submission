"""terms.html — Terms of Service v2.6.

THE THING THIS PAGE EXISTS TO GET RIGHT is Section 6's first bullet: who the
customer is legally buying from. Until this conversion the live page said

    "Paid plans are billed through Stripe on the terms shown at checkout."

while Paddle takes the money. That was the top blocker on the 2026-08-05 Paddle
checklist and it was still public. The replacement paragraph states that the
purchase is made FROM Paddle, names the legal entity, and was reviewed
elsewhere — so it is reproduced word for word and pinned here. A reviewer at
Paddle reads this paragraph; a paraphrase changes what it means.

The other three failure modes are the ones L1 catalogued (see test_privacy_v39):
a mailto that swallowed the sentence's full stop, a page that contradicts
itself, and punctuation that changes meaning. THE .docx IS LOSING EM-DASHES
ACROSS VERSIONS — this document had eight missing in six places, five of them
invisible to any whitespace check — so the restored ones are pinned too.

Guards read the PARSED result, never a source string. The claims that need a
real browser live in test_legal_pages_rendered.py.

Run:  pytest foxy-sale-page -q
"""

from __future__ import annotations

import pathlib
import re

import pytest

from conftest import POSTAL_ADDRESS

PAGE = "terms.html"
VERSION = "2.6"

#: The owner's number. The document ships +92 3448123944 (with a trailing space,
#: and a space before the full stop that follows it); all 12 policy documents do.
PHONE = "+92 3398123944"
SUPERSEDED_PHONE = "3448123944"


@pytest.fixture(scope="module")
def dom(legal_dom):
    return legal_dom(PAGE)


# ── 1. THE MERCHANT-OF-RECORD PARAGRAPH ──────────────────────────────────────
#: Verbatim from Foxy-Audit-Terms-of-Service-v2.6.docx §6, first bullet. The only
#: transformation applied is curly quotes to straight, matching privacy.html —
#: which touches four characters, none of them inside the entity name.
MOR = (
    "Billing and merchant of record. Paid plans are sold through Paddle.com "
    "Market Ltd (\"Paddle\"), acting as our authorized reseller and the merchant "
    "of record for your purchase. This means your purchase is made from Paddle, "
    "not directly from Foxy Audit, and Paddle's own buyer terms and checkout "
    "process apply to the transaction, including the payment methods offered, "
    "invoicing, and applicable sales tax/VAT. Foxy Audit is the provider of the "
    "Service you're purchasing access to; Paddle is the seller handling the "
    "transaction itself."
)


def test_the_merchant_of_record_paragraph_is_reproduced_word_for_word(dom):
    """⚠ DO NOT RELAX THIS INTO A KEYWORD CHECK. The paragraph is a statement
    about who the customer's counterparty is. It went through a review this
    repository did not perform, and tightening or restructuring it changes what
    it says. If it must change, change it in the document first."""
    assert MOR in dom.text, (
        "the merchant-of-record paragraph no longer matches the document verbatim")


def test_the_legal_entity_name_survived_the_conversion(dom):
    """"Paddle.com Market Ltd" — a smart quote or a dropped period inside an
    entity name is what a risk reviewer reads as carelessness. Asserted
    character by character, and asserted to be in the markup as one unbroken
    run, because splitting it across tags would break a reader's copy-paste."""
    name = "Paddle.com Market Ltd"
    assert name in dom.text, "the legal entity is no longer named"
    assert all(ord(c) < 128 for c in name)
    assert f"<strong>{name}</strong>" in dom.src, \
        "the entity name is broken across markup instead of being one run"
    assert "Paddle.com Market Ltd." not in dom.text, \
        "a full stop was appended to the entity name"
    # \s+ on BOTH sides, not \s* — `Paddle\s*\.\s*com` also matches the correct
    # spelling, so it fails on good input. It did, first run.
    assert not re.search(r"Paddle\s+\.|Paddle\.\s+com", dom.text), \
        "whitespace was introduced inside the entity name"


def test_the_page_says_the_purchase_is_from_paddle(dom):
    """The substance, guarded separately from the wording: if the paragraph is
    ever rewritten, THIS must survive the rewrite. Reseller-of-record status is
    the whole reason the sentence exists."""
    t = dom.text
    assert "your purchase is made from Paddle, not directly from Foxy Audit" in t, \
        "the page no longer says who the customer is buying from"
    assert "merchant of record" in t and "authorized reseller" in t


def test_the_page_does_not_name_stripe(dom):
    """It did, publicly, until this conversion — "billed through Stripe on the
    terms shown at checkout"."""
    assert "stripe" not in dom.text.lower(), "the page still names Stripe"
    assert "stripe" not in dom.src.lower(), "Stripe survives somewhere in the markup"


# ── 2. version, contacts, phone ──────────────────────────────────────────────
def test_the_page_states_the_version_it_was_converted_from(dom):
    """The document HEADER says "Version 1.0" and the filename says v2.6; the
    filename wins (owner, 2026-08-13). The live page showed no version at all."""
    line = re.search(r'class="updated">([^<]+)<', dom.src)
    assert line, "the .updated header line is gone"
    assert f"Version {VERSION}" in line.group(1), \
        f"the header line does not name Version {VERSION}: {line.group(1)!r}"
    assert "Version 1.0" not in dom.text, "the document's stale header version was published"


def test_no_address_ends_in_a_full_stop(dom):
    """Read the parsed href: the page TEXT legitimately ends in a period there."""
    assert dom.mailtos, "the Terms publish no contact address at all"
    for href in dom.mailtos:
        addr = href[len("mailto:"):].split("?")[0]
        assert not addr.endswith("."), f"dead mailto — trailing full stop captured: {href!r}"
        assert re.fullmatch(r"[^@\s]+@[^@\s]+\.[a-z]{2,}", addr), f"not an address: {addr!r}"


def test_the_contact_is_the_one_the_document_names(dom):
    """legal@ for the Terms — not privacy@, and not a mailbox minted here."""
    assert dom.addresses == {"legal@foxyaudit.tech"}, f"unexpected addresses: {dom.addresses}"


def test_the_phone_number_is_the_owners_and_is_punctuated(dom):
    """⚠ The document carries +92 3448123944 — wrong, in all 12 policy documents
    (owner, 2026-08-13) — and carries it as "+92 3448123944 ." with a space
    before the full stop, because a character fell out there too."""
    t = dom.text
    assert SUPERSEDED_PHONE not in dom.src, "the superseded phone number was published"
    assert PHONE in t, f"the owner's number is missing: expected {PHONE}"
    assert f"{PHONE} ." not in t, "a space survives between the number and the full stop"
    assert f"{PHONE}." in t, "the number is not terminated by its sentence's full stop"


# ── 3. the em-dashes lost by the .docx ───────────────────────────────────────
@pytest.mark.parametrize("sentence", [
    # a PAIR — the closing one showed as a doubled space, the opening one did not
    "the Foxy Audit product — the dashboard, API, foxy-audit SDK, desktop "
    "application, and related services (the \"Service\") — as a registered account holder",
    "derived from your interactions — not their raw content",
    # a PAIR, both invisible: single spaces, nothing to grep for
    "Misrepresent Foxy Audit output — for example, presenting it as a legal "
    "certification — or use it to deceive",
    # the one whose loss produced "on your behalf DSbuilding" in an earlier round
    "operate the Service on your behalf — building your audit chain",
    "Nothing is silently dropped in the meantime — the SDK spools events locally",
    "at contract time — this default applies absent a signed Order Form or MSA",
])
def test_the_restored_em_dashes_survive(dom, sentence):
    """⚠ EIGHT em-dashes are MISSING from the .docx, in six places. Five of the
    eight leave only a single space, so no whitespace check finds them; the two
    that doubled a space are the only ones a machine could have flagged.

    Every surviving em-dash in that document sits inside a bold run in §15. Every
    one in running prose was lost — the same mechanism as the Privacy Policy,
    where L1 found six. This is an ongoing regression in the source documents.

    Pinned so a re-convert cannot silently restore the broken text. If one fails
    after a re-convert, restore the dash; do not relax the guard."""
    assert sentence in dom.text, f"a restored em-dash was lost: {sentence[:60]!r}…"


def test_no_stray_double_space_survived_the_conversion(dom):
    assert "  " not in dom.text, \
        "a doubled space survived — an em-dash almost certainly fell out there"


def test_no_space_survives_before_punctuation(dom):
    """"courts of Islamabad, Pakistan , unless" and "+92 3448123944 ." — both in
    the source, both a dropped character rather than a typo."""
    bad = re.findall(r"\w +[,.;:](?:\s|$)", dom.text)
    assert not bad, f"space before punctuation: {bad}"


# ── 4. substantive terms that must not drift ─────────────────────────────────
def test_the_liability_cap_is_the_one_the_document_sets(dom):
    """A number in a limitation-of-liability clause is not prose. If the document
    changes it, this fails and someone reads the change deliberately."""
    t = dom.text
    assert "twelve (12) months preceding the event giving rise to the claim" in t
    assert "limited to the amounts you paid us for the Service" in t


def test_the_governing_law_and_forum_are_unchanged(dom):
    t = dom.text
    assert "governed by the laws of the Islamic Republic of Pakistan" in t
    assert "exclusive jurisdiction of the courts of Islamabad, Pakistan" in t


def test_the_notice_period_for_price_changes_is_stated(dom):
    assert "at least 30 days' advance notice" in dom.text


def test_no_uptime_or_refund_window_is_invented(dom):
    """⚠ The document deliberately promises NEITHER. §7 says there is no uptime
    guarantee absent a separate SLA, and §6 points at a standalone Refund Policy
    rather than stating a window. Inventing either here would publish a term
    nobody agreed to — and the Refund Policy (L3) and SLA (L9) are later phases,
    so this page must not front-run them."""
    t = dom.text
    assert "without an uptime guarantee" in t, "the honest no-SLA statement was dropped"
    assert not re.search(r"\d+(\.\d+)?\s*%\s*(uptime|availability)", t, re.I), \
        "an uptime percentage was invented"
    assert not re.search(r"\b\d+[- ]day\b.{0,30}refund", t, re.I), \
        "a refund window was invented"
    assert not re.search(r"refund(ed|able)? within \d+", t, re.I)


def test_the_disclaimer_stays_conspicuous(dom):
    """Set in capitals in the source, which is the convention that makes a
    warranty disclaimer conspicuous. Kept as written text, not text-transform, so
    a screen reader and a copy-paste both get what the document says."""
    assert 'THE SERVICE IS PROVIDED "AS IS" AND "AS AVAILABLE,"' in dom.text
    assert "text-transform:uppercase" not in dom.src, \
        "the disclaimer is only visually capitalised; the text underneath is not"


def test_no_postal_address_is_invented(dom):
    """The Privacy Policy states the company has no registered office yet.

    ⚠ The pattern this carried assumed a two-token address and missed
    "7 Blue Area Road" — measured on terms-of-use.html, where that exact string
    was inserted into the page and the guard stayed green. Shared and widened in
    conftest.POSTAL_ADDRESS; both pages use it now."""
    hit = POSTAL_ADDRESS.search(dom.text)
    assert not hit, f"a postal address was invented: {hit.group(0)!r}"


# ── 5. navigation actually resolves ──────────────────────────────────────────
def test_every_in_page_anchor_lands_on_something(dom):
    frags = {a["href"][1:] for a in dom.links if a["href"].startswith("#")}
    missing = sorted(frags - set(dom.ids))
    assert not missing, f"contents links point at ids that do not exist: {missing}"
    assert len([i for i in dom.ids if re.fullmatch(r"s\d+", i)]) == 17, \
        "the page no longer has 17 numbered sections"


def test_the_page_links_no_document_that_does_not_exist_yet(dom):
    """⚠ L0 made 404s real, so a link to a page a later phase has not built is
    now a visible dead end rather than a silent redirect to the homepage. The
    Refund Policy (L3), SLA (L9) and Terms of Use are named in the text on
    purpose and deliberately NOT linked. L3 and L9 should link them when they
    land — and this guard is what tells them the target now exists."""
    here = pathlib.Path(__file__).resolve().parent
    for a in dom.links:
        href = a["href"]
        if href.startswith("/") and href.endswith(".html"):
            assert (here / href.lstrip("/")).is_file(), \
                f"links to {href}, which does not exist — that is a 404 now"


# ── 6. the network guarantee, without a browser ──────────────────────────────
# The rendered twin measures what Chrome actually FETCHED; see
# test_legal_pages_rendered.py. This one always runs.
def test_no_external_url_is_reachable_from_the_markup(dom):
    fetching = re.findall(r'(?:src|href)="(https?://[^"]+)"', dom.src)
    fetching += re.findall(r"url\(\s*['\"]?(https?://[^)'\"]+)", dom.src)
    assert not fetching, f"the page fetches from the network: {fetching}"
    assert "https://" not in dom.src, "an absolute URL appeared on a legal page"


def test_the_embedded_faces_are_the_ones_the_sibling_page_ships(dom):
    """Lifted from privacy.html rather than re-downloaded. If they ever diverge,
    two legal pages are rendering in two different Poppins."""
    mine = dict(re.findall(
        r"font-weight:(\d+);font-display:swap;src:url\(data:font/woff2;base64,([A-Za-z0-9+/=]+)\)",
        dom.src))
    sibling = dict(re.findall(
        r"font-weight:(\d+);font-display:swap;src:url\(data:font/woff2;base64,([A-Za-z0-9+/=]+)\)",
        (pathlib.Path(__file__).resolve().parent / "privacy.html").read_text(encoding="utf-8")))
    assert set(mine) == {"600", "700"}, f"unexpected faces: {sorted(mine)}"
    assert mine == sibling, "the embedded Poppins has drifted from privacy.html's"

