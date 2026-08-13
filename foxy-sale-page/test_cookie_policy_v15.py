"""cookie-policy.html — Cookie Policy v1.5.

⚠⚠ THIS PAGE IS PUBLISHED WITH KNOWN INACCURACIES, PENDING THE OWNER.

A cookie policy is a list of facts about a website, so every claim in it was
checked against the code. Most hold. Four do not, and they are pinned below
rather than reworded — rewriting a policy to match the product is inventing a
disclosure, and which way the mismatch gets fixed (change the page, or change
the site) is an owner's decision. See test_the_policy_is_still_wrong_about_this_site.

The short version, all measured:

  1. book-a-demo.html loads Google reCAPTCHA **v3** unconditionally in <head>.
     It fires on page load, with no interaction and no consent gate.
  2. SEVENTEEN sale pages load fonts.googleapis.com — the same third-party
     request L1 refused for the legal pages.
  3. accounts.google.com/gsi/client is on index.html unconditionally, not
     "only if you click Sign in with Google" as the policy says.
  4. localStorage carries `foxy_onboard_dismissed` and `foxy_welcome`, which
     remember interface state — while the policy says "We don't use any
     functional cookies yet". The policy's own §1 uses "you dismissed a banner"
     as its example of exactly this.

#190: the live page published a personal Gmail address. It cannot again.

Guards read the PARSED result, never a source string. Browser claims live in
test_legal_pages_rendered.py; cross-page links in test_legal_cross_links.py.

Run:  pytest foxy-sale-page -q
"""

from __future__ import annotations

import pathlib
import re

import pytest

from conftest import POSTAL_ADDRESS

PAGE = "cookie-policy.html"
VERSION = "1.5"
PHONE = "+92 3398123944"
SUPERSEDED_PHONE = "3448123944"

HERE = pathlib.Path(__file__).resolve().parent


@pytest.fixture(scope="module")
def dom(legal_dom):
    return legal_dom(PAGE)


def _sale_page(name: str) -> str:
    return (HERE / name).read_text(encoding="utf-8")


# ── 1. THE FOUR THINGS THE POLICY GETS WRONG ─────────────────────────────────
def test_the_policy_is_still_wrong_about_this_site(dom):
    """⚠ THIS TEST RECORDS UNRESOLVED INACCURACIES. IT IS MEANT TO.

    The page claims: "The one third-party cookie on this site is Google's own,
    set only if you choose 'Sign in with Google'". Measured, that is false four
    times over — and the fix is either a disclosure the owner must word, or the
    removal of a product feature. Neither is a conversion decision.

    ⚠ WHEN IT IS RESOLVED, THIS TEST FAILS. That is the design: the resolution
    has to be deliberate, and whoever makes it should read this first.

    Each assertion below pins BOTH halves — what the policy says, and what the
    site does — so neither can drift while the question is open."""
    t = dom.text
    assert "The one third-party cookie on this site is Google's own" in t
    assert "captcha" not in t.lower(), "the policy now mentions captcha — has it been disclosed?"

    demo = _sale_page("book-a-demo.html")
    assert "recaptcha/api.js?render=" in demo, (
        "reCAPTCHA is gone from book-a-demo.html — if that was the fix, the "
        "policy's 'one third-party cookie' claim may now be true; rewrite this")
    assert "<script src=\"https://www.google.com/recaptcha/api.js?render=" in demo, \
        "the reCAPTCHA loader is no longer an unconditional <head> script"

    index = _sale_page("index.html")
    assert 'src="https://accounts.google.com/gsi/client"' in index, \
        "the Google sign-in script is gone or gated — the policy may now be right"

    fonts = [p.name for p in sorted(HERE.glob("*.html"))
             if "fonts.googleapis.com" in p.read_text(encoding="utf-8")]
    assert len(fonts) >= 10, (
        f"only {len(fonts)} pages still load Google Fonts — if they were swept, "
        "the policy's third-party claim needs revisiting")
    assert PAGE not in fonts and "privacy.html" not in fonts, \
        "a legal page started fetching a font from Google"


def test_the_functional_cookie_claim_is_still_contradicted(dom):
    """"We don't use any functional cookies yet" — while localStorage remembers
    a dismissed banner and a seen-welcome flag. The policy explicitly says it
    calls local storage a "cookie" for the purposes of this document, and its own
    §1 gives "that you dismissed a banner" as the example."""
    assert "We don't use any functional cookies yet" in dom.text
    assert 'We call all of these "cookies" below.' in dom.text
    index = _sale_page("index.html")
    for key in ("foxy_onboard_dismissed", "foxy_welcome"):
        assert key in index, f"{key} is gone — if that was the fix, rewrite this guard"
    for key in ("foxy_onboard_dismissed", "foxy_welcome"):
        assert key not in dom.text, \
            f"{key} is now disclosed — the contradiction may be resolved"


# ── 2. WHAT THE POLICY GETS RIGHT — verified against the code ───────────────
@pytest.mark.parametrize("name,expiry,flags", [
    ("session", "30 days", "HttpOnly · Secure · SameSite=Lax"),
    ("foxy_staff_session", "2 hours", "HttpOnly · Secure · SameSite=Strict"),
    ("foxy_csrf", "180 days", "Secure · SameSite=Lax"),
    ("foxy_consent", "12 months", "Secure · SameSite=Lax"),
])
def test_each_named_cookie_matches_what_the_code_sets(dom, name, expiry, flags):
    """Checked against backend/app/main.py (the two SessionMiddleware configs),
    backend/app/middleware/csrf.py, and the consent script in index.html:

      session             session_remember_max_age = 60*60*24*30   → 30 days
      foxy_staff_session  staff_session_max_age    = 60*60*2       → 2 hours
      foxy_csrf           _MAX_AGE = 60*60*24*180, httponly=False  → 180 days,
                          and correctly listed WITHOUT HttpOnly
      foxy_consent        365*864e5 ms, SameSite=Lax, Secure on https → 12 months

    A cookie table is the part of a policy most likely to rot silently, because
    nothing about a wrong expiry looks wrong."""
    # From <tr>, not from the <code> — starting mid-row eats the name cell and
    # yields four, which then fails the length check on a correct page.
    row = re.search(rf"<tr><td><code>{re.escape(name)}</code>.*?</tr>", dom.src, re.S)
    assert row, f"{name} is no longer in the cookie table"
    cells = [re.sub(r"<[^>]+>", "", c) for c in re.findall(r"<td>(.*?)</td>", row.group(0), re.S)]
    assert len(cells) == 5, f"{name}'s row has {len(cells)} cells, expected 5"
    # ⚠ EXACT CELL COMPARISON, not `in`. A substring check passes when a flag is
    # ADDED: "Secure · SameSite=Lax" is inside "HttpOnly · Secure · SameSite=Lax".
    # Measured — that mutation survived, and it matters: foxy_csrf is deliberately
    # httponly=False so the SPA can read it for double-submit, so publishing
    # HttpOnly would misstate a security flag in the direction of reassurance.
    assert cells[3].strip() == expiry, f"{name}'s published expiry is {cells[3]!r}, not {expiry!r}"
    assert cells[4].strip() == flags, f"{name}'s published flags are {cells[4]!r}, not {flags!r}"


def test_the_storage_entries_are_storage_and_not_cookies(dom):
    """foxy_vid is localStorage and foxy_sid is sessionStorage — index.html sets
    them with setItem, not document.cookie. The table says so, which matters:
    calling a storage key a cookie would misstate how a reader clears it."""
    index = _sale_page("index.html")
    assert "localStorage.setItem('foxy_vid'" in index
    assert "sessionStorage.setItem('foxy_sid'" in index
    assert "<code>foxy_vid</code> <span class=\"muted\">(local storage)</span>" in dom.src
    assert "<code>foxy_sid</code> <span class=\"muted\">(session storage)</span>" in dom.src


def test_the_analytics_claim_is_true(dom):
    """"first-party and cookieless… one-way hashed… no third-party analytics
    provider" — /v1/track is first-party, and leads.py stores ip_hash/ua_hash
    rather than the raw values."""
    t = dom.text
    assert "first-party and cookieless" in t
    assert "one-way hashed on our server and never stored raw" in t
    assert "There is no third-party analytics provider." in t
    leads = (HERE.parent / "backend" / "app" / "routers" / "leads.py").read_text(encoding="utf-8")
    assert "ip_hash=hash_key(" in leads and "ua_hash=hash_key(" in leads, \
        "the beacon no longer hashes IP and user-agent — the policy now overstates"


def test_no_cookie_is_named_that_the_product_does_not_set(dom):
    """The other direction. A policy naming a cookie nobody sets is as wrong as
    one omitting a cookie that is set — and harder to notice, because nothing
    breaks."""
    names = re.findall(r"<code>([a-z_]+)</code>", dom.src)
    assert set(names) == {"session", "foxy_staff_session", "foxy_csrf",
                          "foxy_consent", "foxy_vid", "foxy_sid", "g_state"}, \
        f"the cookie table changed: {sorted(set(names))}"
    main = (HERE.parent / "backend" / "app" / "main.py").read_text(encoding="utf-8")
    csrf = (HERE.parent / "backend" / "app" / "middleware" / "csrf.py").read_text(encoding="utf-8")
    index = _sale_page("index.html")
    assert 'session_cookie="session"' in main
    assert 'session_cookie="foxy_staff_session"' in main
    assert '_COOKIE = "foxy_csrf"' in csrf
    assert "'foxy_consent'" in index


def test_no_retention_period_or_vendor_is_invented(dom):
    """Only the vendors the product actually uses may appear."""
    t = dom.text
    vendors = set(re.findall(r"\b(Google|Paddle|Payoneer|Meta|Brevo|Stripe|Plausible|Matomo|"
                             r"Hotjar|Segment|Mixpanel|Amplitude)\b", t))
    assert vendors <= {"Google", "Paddle", "Payoneer", "Meta"}, \
        f"a vendor this product does not use was named: {sorted(vendors)}"
    assert "Meta" not in t or "no Meta" in t, "Meta is named other than as an exclusion"


# ── 3. the em-dashes the .docx lost ──────────────────────────────────────────
@pytest.mark.parametrize("sentence", [
    "no advertising or third-party tracking cookies — an auditing product has no business",
    "(Section 3) — it is functional, not advertising or tracking",
    "to remember things between requests — for example, that you're securely logged in",
])
def test_the_restored_em_dashes_survive(dom, sentence):
    """THREE missing, all invisible: the .docx has zero doubled spaces, and so
    does the superseded v1.2 — the diff method found nothing here, because both
    versions are damaged identically. Reading found all three; the systematic
    sweep found two and missed "(Section 3) it is functional".

    ⚠ Five dashes DID survive, and four are heading dashes as usual. The fifth,
    "not ours — see paddle.com", is the first running-prose survivor across six
    documents — so the rule is a strong tendency, not a law."""
    assert sentence in dom.text, f"a restored em-dash was lost: {sentence[:56]!r}…"


def test_no_whitespace_gap_survived(dom):
    assert "  " not in dom.text, "a doubled space survived — a dropped character"
    assert not re.findall(r"\w +[,.;:](?:\s|$)", dom.text), "space before punctuation"


# ── 4. #190 and conversion hygiene ───────────────────────────────────────────
def test_no_personal_mailbox_is_published(dom):
    """The live page carried foxyaudit@gmail.com — the last of the two Gmail
    pages that had a phase to fix it."""
    assert "gmail" not in dom.src.lower(), "a personal Gmail address is published"
    assert dom.addresses == {"privacy@foxyaudit.tech"}, f"unexpected addresses: {dom.addresses}"
    for href in dom.mailtos:
        addr = href[len("mailto:"):].split("?")[0]
        assert not addr.endswith("."), f"dead mailto — trailing full stop captured: {href!r}"


def test_the_page_states_the_version_it_was_converted_from(dom):
    line = re.search(r'class="updated">([^<]+)<', dom.src)
    assert line and f"Version {VERSION}" in line.group(1), \
        f"the header line does not name Version {VERSION}"
    assert "Version 1.0" not in dom.text, "the live page's stale version survived"


def test_the_phone_number_is_the_owners(dom):
    assert SUPERSEDED_PHONE not in dom.src, "the superseded phone number was published"
    assert PHONE in dom.text, f"the owner's number is missing: {PHONE}"


def test_no_address_is_invented(dom):
    hit = POSTAL_ADDRESS.search(dom.text)
    assert not hit, f"a postal address was invented: {hit.group(0)!r}"


def test_the_docx_page_chrome_was_not_pasted_in(dom):
    """The .docx carries the rendered header and footer as document text. Only
    the policy was extracted; the incumbent footer is byte-identical, and #12's
    fox emoji is left to the W stream — this pins that a SECOND one was not
    added from the document."""
    assert dom.src.count('class="foot"') == 1, "a second footer was pasted in"
    assert dom.src.count("Cryptographic compliance, not a promise") == 1
    assert dom.text.count("Back to home") == 1
    assert dom.src.count("\U0001f98a") == 1, "the document's fox emoji was added on top"


# ── 5. navigation, table shape, and the network guarantee ────────────────────
def test_every_in_page_anchor_lands_on_something(dom):
    frags = {a["href"].split("#")[1] for a in dom.links if "#" in a["href"]}
    assert not (frags - set(dom.ids)), f"dead fragments: {sorted(frags - set(dom.ids))}"
    assert len([i for i in dom.ids if re.fullmatch(r"s\d+", i)]) == 8, \
        "the page no longer has its eight sections"


def test_the_cookie_table_can_scroll_without_moving_the_page(dom):
    """Seven columns of cookie detail is wider than a phone. It scrolls inside
    its own container so the page body never scrolls sideways."""
    assert '<div class="tbl-wrap">' in dom.src
    assert "overflow-x:auto" in dom.src
    assert dom.src.count("<tr>") == 8, "the table lost or gained a row"


def test_no_external_url_is_reachable_from_the_markup(dom):
    """⚠ The page that tells readers which third parties this site contacts must
    not contact one to render itself."""
    fetching = re.findall(r'(?:src|href)="(https?://[^"]+)"', dom.src)
    fetching += re.findall(r"url\(\s*['\"]?(https?://[^)'\"]+)", dom.src)
    assert not fetching, f"the page fetches from the network: {fetching}"
    assert "https://" not in dom.src, "an absolute URL appeared on a legal page"


def test_the_embedded_faces_are_the_ones_the_siblings_ship(dom):
    pat = r"font-weight:(\d+);font-display:swap;src:url\(data:font/woff2;base64,([A-Za-z0-9+/=]+)\)"
    mine = dict(re.findall(pat, dom.src))
    sibling = dict(re.findall(pat, _sale_page("acceptable-use.html")))
    assert set(mine) == {"600", "700"}, f"unexpected faces: {sorted(mine)}"
    assert mine == sibling, "the embedded Poppins has drifted from acceptable-use.html's"
