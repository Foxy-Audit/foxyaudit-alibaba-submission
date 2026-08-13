"""refund.html — Refund Policy v1.2.

The content already existed inside Terms of Service section 6. The PLACEMENT was
the Paddle blocker: their domain review looks for a refund policy listed as its
own page, and "no standalone refund policy" sat on the 2026-08-05 checklist.
So this page is a placement fix, and the thing that must not happen to it is a
paraphrase.

⚠ THE STATUTORY WINDOWS ARE LEGAL FACTS, AND THEY ARE NOT OURS

They come from PADDLE'S Buyer Terms, not from anything this repository controls.
Three numbers and eleven jurisdictions, each pinned separately below, so that an
edit which moves a country between lists or rounds a number fails loudly rather
than reading fine.

⚠ AND THEY CAN GO STALE WITHOUT ANY COMMIT. If Paddle changes its Buyer Terms,
this page is wrong and nothing in this repository would know — no test here can
see paddle.net. That is a monitoring gap, not a code defect; it is written down
so the next reader does not mistake a green suite for a current page.

#179: this document has ZERO surviving em-dashes and four were restored. One of
them is PROVED rather than inferred — v1.0 carries the identical sentence WITH
the dash, and v1.2 has a doubled space in its place.

Guards read the PARSED result, never a source string. Browser claims live in
test_legal_pages_rendered.py; cross-page links in test_legal_cross_links.py.

Run:  pytest foxy-sale-page -q
"""

from __future__ import annotations

import pathlib
import re

import pytest

from conftest import POSTAL_ADDRESS

PAGE = "refund.html"
VERSION = "1.2"
PHONE = "+92 3398123944"
SUPERSEDED_PHONE = "3448123944"

HERE = pathlib.Path(__file__).resolve().parent


@pytest.fixture(scope="module")
def dom(legal_dom):
    return legal_dom(PAGE)


# ── 1. THE STATUTORY WINDOWS ─────────────────────────────────────────────────
#: Verbatim from Foxy-Audit-Refund-Policy-v1.2.docx, with one restored em-dash
#: and curly quotes straightened to match the sibling pages. 689 characters on
#: both sides, verified before this constant was written down.
STATUTORY = (
    "Because Paddle is the merchant of record for your purchase, Paddle's own "
    "Buyer Terms give you a 14-day right to withdraw from a one-time purchase, "
    "the first payment of a new subscription, or an annual renewal, if you are "
    "located in the EU, EEA, UK, Switzerland, Turkey, or Israel — you'll receive "
    "a full refund if you request it within that window, unless you've already "
    "started using the Service during that period after agreeing to immediate "
    "access. Shorter statutory windows apply in some other countries (for "
    "example, 7 days in South Korea, Brazil, China, and Canada; 5 days in "
    "Singapore). This right exists independently of anything below and is not "
    "something we can shorten or waive."
)


def test_the_statutory_paragraph_is_reproduced_word_for_word(dom):
    """⚠ DO NOT RELAX THIS INTO KEYWORD CHECKS. These are withdrawal rights that
    differ by jurisdiction. Summarising them, merging the lists or rounding a
    number changes what a reader in one of those countries is told they are
    entitled to. If it must change, change it in the document first — and check
    Paddle's Buyer Terms, because they are the source, not us."""
    assert STATUTORY in dom.text, (
        "the statutory-withdrawal paragraph no longer matches the document verbatim")


@pytest.mark.parametrize("window,countries", [
    ("14-day", ["the EU", "EEA", "UK", "Switzerland", "Turkey", "Israel"]),
    ("7 days", ["South Korea", "Brazil", "China", "Canada"]),
    ("5 days", ["Singapore"]),
])
def test_each_window_keeps_its_own_countries(dom, window, countries):
    """The lists guarded apart from the paragraph, so that a rewrite which keeps
    every word but moves Canada from the 7-day list to the 14-day one still
    fails. That is the edit most likely to look harmless and be wrong."""
    t = dom.text
    assert window in t, f"the {window} window is gone"
    for c in countries:
        assert c in t, f"{c} is no longer named in the {window} list"


def test_no_country_is_promised_two_different_windows(dom):
    """A jurisdiction in two lists is a contradiction a reader could act on."""
    t = dom.text
    lists = {
        "14-day": re.search(r"located in (.+?) —", t).group(1),
        "7 days": re.search(r"7 days in ([^;]+);", t).group(1),
        "5 days": re.search(r"5 days in ([^)]+)\)", t).group(1),
    }
    seen: dict[str, str] = {}
    for window, blob in lists.items():
        for country in re.split(r",\s*(?:and |or )?|\s+and\s+|\s+or\s+", blob):
            country = country.strip()
            if not country:
                continue
            assert country not in seen, \
                f"{country} appears in both the {seen[country]} and {window} lists"
            seen[country] = window
    assert len(seen) == 11, f"expected 11 jurisdictions, found {len(seen)}: {sorted(seen)}"


def test_no_window_or_jurisdiction_was_invented(dom):
    """The only day-counts on this page are 14, 7 and 5. Anything else is either
    a number nobody agreed to or a country moved into the wrong list."""
    found = sorted({int(n) for n in re.findall(r"\b(\d+)[- ]days?\b", dom.text)})
    assert found == [5, 7, 14], f"unexpected day-counts on the page: {found}"
    assert "30" not in re.findall(r"\b(\d+)[- ]days?\b", dom.text), \
        "the Terms' 30-day price-change notice leaked onto the refund page"


def test_the_right_is_stated_as_paddles_and_not_ours(dom):
    """Whose terms these are matters: we cannot vary them, and saying so is what
    makes the page accurate rather than merely generous."""
    t = dom.text
    assert "Paddle's own Buyer Terms" in t, "the page no longer attributes the right to Paddle"
    assert "not something we can shorten or waive" in t


# ── 2. WHO ACTUALLY PAYS — the wording, and separately the meaning ───────────
def test_the_page_says_paddle_issues_the_refund(dom):
    """The words."""
    assert ("refunds are actually issued by Paddle, not by us directly" in dom.text)
    assert "we instruct Paddle to issue it — we do not pay refunds directly ourselves" in dom.text


def test_who_pays_cannot_be_reversed_by_a_rewrite(dom):
    """The meaning, guarded apart from the wording — the same treatment the
    merchant-of-record paragraph gets in test_terms_v26. A rewrite may tidy the
    sentence; it may not quietly make Foxy Audit the payer."""
    t = dom.text
    assert re.search(r"issued by Paddle", t), "the page no longer says Paddle issues refunds"
    assert not re.search(r"we (?:will )?(?:issue|pay|process) (?:the |your )?refunds? directly(?! ourselves)", t), \
        "the page now says Foxy Audit pays refunds directly"
    assert "merchant of record" in t


def test_the_restrictive_and_discretionary_terms_both_survive(dom):
    t = dom.text
    assert "Except where required by applicable law, amounts already paid are non-refundable" in t
    assert "A duplicate or erroneous charge caused by a billing error on our side." in t
    assert "at our discretion" in t, "the exceptions stopped being discretionary"
    assert "that agreement's terms govern instead of this page" in t, \
        "a signed MSA no longer overrides this page"


# ── 3. the em-dashes the .docx lost ──────────────────────────────────────────
@pytest.mark.parametrize("sentence", [
    # ⚠ PROVED, not inferred: v1.0 carries this sentence WITH the dash, and v1.2
    # has a doubled space in exactly this position. Same words either side.
    "Cancellation stops future charges — it does not retroactively refund",
    "Turkey, or Israel — you'll receive a full refund",
    "not by us directly — the fastest path is Paddle's own buyer support",
    "we instruct Paddle to issue it — we do not pay refunds directly ourselves",
])
def test_the_restored_em_dashes_survive(dom, sentence):
    """FOUR missing, and this document had ZERO survivors — the first in the set
    with none at all. All four were visible as doubled spaces, which is the
    opposite of the Terms of Use, where six gaps had been normalised away
    between versions and eight dashes were missing behind a clean-looking file.

    The reason this one has no invisible cases: v1.2 uses PARENTHESES where the
    other documents used dash pairs ("(for example, 7 days in …)", "(including
    Service Level Agreement credits)"). Fewer dash constructions, fewer losses."""
    assert sentence in dom.text, f"a restored em-dash was lost: {sentence[:60]!r}…"


def test_no_whitespace_gap_survived(dom):
    assert "  " not in dom.text, "a doubled space survived — a dropped character"
    assert not re.findall(r"\w +[,.;:](?:\s|$)", dom.text), "space before punctuation"


def test_the_exception_bullets_are_a_list_not_run_on_prose(dom):
    """The .docx writes them inline as "- A duplicate… - A confirmed…". Those
    hyphens are BULLET MARKERS, not lost em-dashes — v1.0 has them identically —
    so they became a <ul> and must not be "restored" into dashes."""
    s3 = dom.section(3)
    assert s3.count("<li>") == 3, f"section 3 should list three exceptions, has {s3.count('<li>')}"
    assert " - A duplicate" not in dom.text, "the bullet markers were left as run-on prose"
    assert "—" not in s3, "a bullet marker was mistaken for a lost em-dash"


# ── 4. version, contacts, no invention ───────────────────────────────────────
def test_the_page_states_the_version_it_was_converted_from(dom):
    """The document's own header line says "Version 1.0"; the filename says v1.2
    and wins (owner, 2026-08-13)."""
    line = re.search(r'class="updated">([^<]+)<', dom.src)
    assert line, "the .updated header line is gone"
    assert f"Version {VERSION}" in line.group(1), \
        f"the header line does not name Version {VERSION}: {line.group(1)!r}"
    assert "Version 1.0" not in dom.text, "the document's stale header version was published"


def test_the_contact_is_support_and_not_the_legal_mailbox(dom):
    """⚠ support@, NOT legal@. The two Terms pages use legal@; this one does not,
    and that is the document's choice — a refund request is support work. Do not
    "harmonise" the four legal pages onto one address."""
    assert dom.addresses == {"support@foxyaudit.tech"}, f"unexpected addresses: {dom.addresses}"


def test_no_address_ends_in_a_full_stop(dom):
    for href in dom.mailtos:
        addr = href[len("mailto:"):].split("?")[0]
        assert not addr.endswith("."), f"dead mailto — trailing full stop captured: {href!r}"
        assert re.fullmatch(r"[^@\s]+@[^@\s]+\.[a-z]{2,}", addr), f"not an address: {addr!r}"


def test_the_phone_number_is_the_owners(dom):
    assert SUPERSEDED_PHONE not in dom.src, "the superseded phone number was published"
    assert PHONE in dom.text, f"the owner's number is missing: {PHONE}"


def test_no_fee_or_address_is_invented(dom):
    """This page states no fee of its own, and the company has no registered
    office (Privacy Policy section 1)."""
    hit = POSTAL_ADDRESS.search(dom.text)
    assert not hit, f"a postal address was invented: {hit.group(0)!r}"
    assert not re.search(r"[$£€]\s?\d", dom.text), "a currency amount was invented"
    assert not re.search(r"\b(?:processing|admin(?:istration)?|restocking)\s+fee\b", dom.text, re.I)


def test_paddles_support_host_is_named_but_not_linked(dom):
    """paddle.net is where a buyer actually goes, so the page names it. It is NOT
    an anchor: these pages fetch nothing and carry no absolute URL, and a legal
    page is not the place to start making exceptions to that."""
    assert "paddle.net" in dom.text, "the buyer-support route was dropped"
    assert "https://" not in dom.src, "an absolute URL appeared on a legal page"
    assert not re.search(r'href="[^"]*paddle\.net', dom.src), "paddle.net was turned into a link"


# ── 5. the page it was carved out of ─────────────────────────────────────────
def test_the_terms_of_service_links_here_now(dom):
    """⚠ THE POINT OF THE PHASE. terms.html section 6 said "See our standalone
    Refund Policy for full detail" with no anchor, because the page did not
    exist. L2b's reverse cross-link guard was proved by building this file in a
    scratch run and watching terms.html go red."""
    sibling = (HERE / "terms.html").read_text(encoding="utf-8")
    assert f'href="/{PAGE}"' in sibling, "terms.html still does not link the Refund Policy"
    assert "standalone <a href=\"/refund.html\">Refund Policy</a> for full detail" in sibling


def test_the_terms_of_service_still_states_no_window_of_its_own(dom):
    """The windows live HERE. The Terms point at this page and must not restate
    them — test_terms_v26 asserts that too, and this is the other half of the
    same contract, so a later edit cannot satisfy one by breaking the other."""
    sibling = (HERE / "terms.html").read_text(encoding="utf-8")
    assert not re.search(r"\b\d+[- ]day\b.{0,30}refund", sibling, re.I), \
        "a refund window was added to the Terms of Service"
    assert "amounts already paid are non-refundable" in sibling, \
        "the Terms' own refund position was dropped"


def test_the_legal_index_lists_this_page(dom):
    index = (HERE / "legal.html").read_text(encoding="utf-8")
    assert f'href="/{PAGE}"' in index, "legal.html does not list the Refund Policy"


# ── 6. the network guarantee, without a browser ──────────────────────────────
def test_no_external_url_is_reachable_from_the_markup(dom):
    fetching = re.findall(r'(?:src|href)="(https?://[^"]+)"', dom.src)
    fetching += re.findall(r"url\(\s*['\"]?(https?://[^)'\"]+)", dom.src)
    assert not fetching, f"the page fetches from the network: {fetching}"


def test_the_embedded_faces_are_the_ones_the_siblings_ship(dom):
    pat = r"font-weight:(\d+);font-display:swap;src:url\(data:font/woff2;base64,([A-Za-z0-9+/=]+)\)"
    mine = dict(re.findall(pat, dom.src))
    sibling = dict(re.findall(pat, (HERE / "terms.html").read_text(encoding="utf-8")))
    assert set(mine) == {"600", "700"}, f"unexpected faces: {sorted(mine)}"
    assert mine == sibling, "the embedded Poppins has drifted from terms.html's"


def test_the_cross_document_references_resolve(dom):
    """The lead cites two sections of two other pages by number. Deep links, so
    they land on the section rather than the top of a long document — which
    means the ids have to exist."""
    for href, target_id in (("/terms.html#s6", "s6"), ("/privacy.html#s8", "s8")):
        page, _, frag = href.partition("#")
        assert f'href="{href}"' in dom.src, f"the lead no longer deep-links {href}"
        target = (HERE / page.lstrip("/")).read_text(encoding="utf-8")
        assert f'id="{frag}"' in target, f"{page} has no {frag} to land on"
