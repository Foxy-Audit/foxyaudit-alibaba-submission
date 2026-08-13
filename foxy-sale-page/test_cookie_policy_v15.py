"""cookie-policy.html — Cookie Policy v1.5.

⚠ THIS PAGE WAS PUBLISHED-BLOCKED UNTIL THE SITE MATCHED IT.

A cookie policy is a list of facts about a website, so every claim was checked
against the code. Three did not hold, and rather than reword the policy — which
is inventing a disclosure — the owner chose to change the site:

  1. book-a-demo.html loaded Google reCAPTCHA **v3** unconditionally in <head>,
     contacting three Google-controlled hosts on page load with no interaction
     and no consent gate. REMOVED, whole mechanism, 2026-08-13. Measured before
     and after: 7 third-party requests across 4 hosts -> 4 across 2, and 3
     reCAPTCHA requests -> 0.
  2. "We don't use any functional cookies yet" while localStorage remembered a
     dismissed banner. The two storage keys are LISTED now and the claim is gone.
  3. The Google sign-in script is disclosed and remains; Google Fonts is a
     third-party request that sets no cookie, and its removal is deferred to the
     W stream by owner decision.

The guards that recorded those defects were INVERTED rather than deleted — a
guard that recorded a known defect becomes the guard that prevents its return.

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
def test_no_page_loads_a_fingerprinting_or_risk_scoring_script(dom):
    """⚠ INVERTED FROM A GUARD THAT RECORDED A DEFECT. It used to assert that
    reCAPTCHA WAS on book-a-demo.html, so it would fire when the site was fixed
    rather than only when the page was. The site is fixed, so it now asserts the
    absence — a guard that recorded a known defect becomes the guard that
    prevents its return.

    §4 of this policy says "No cross-site tracking or fingerprinting." That is a
    claim about the SITE, not this page, so it is checked against every page.
    reCAPTCHA v3 was the counter-example: its whole mechanism is behavioural
    fingerprinting to produce a risk score, and it loaded unconditionally in
    <head> for every visitor to the demo page.

    ⚠ If a captcha is ever needed again, this test is where you will find out
    that the Cookie Policy has to change in the SAME commit."""
    offenders = {}
    for page in sorted(HERE.glob("*.html")):
        src = page.read_text(encoding="utf-8")
        hits = re.findall(r"recaptcha|hcaptcha|turnstile|fingerprintjs|clarity\.ms|"
                          r"datadome|perimeterx|akamai/sensor", src, re.I)
        if hits:
            offenders[page.name] = sorted(set(h.lower() for h in hits))
    assert not offenders, f"a fingerprinting or risk-scoring script is loaded: {offenders}"
    assert "No cross-site tracking or fingerprinting." in dom.text,         "the claim this guard defends was removed from the policy"


def test_the_demo_form_still_posts_without_a_captcha_token(dom):
    """The other half of the removal: the mechanism is gone COMPLETELY, not just
    its script tag. An orphaned grecaptcha.execute() throws before the fetch, and
    a dangling token field is how the whole thing gets resurrected.

    Verified live as well as here — the real form was driven in a browser against
    a running backend and POST /v1/leads returned 200. This pins the shape."""
    demo = _sale_page("book-a-demo.html")
    for token in ("grecaptcha", "recaptcha_token", "recaptcha", "policies.google.com"):
        assert token not in demo.lower(), f"{token!r} survives in book-a-demo.html"
    assert "/v1/leads" in demo, "the demo form no longer posts anywhere"
    assert 'id="hp"' in demo, "the honeypot went with it — that was the other defence"


def test_the_third_party_claim_now_holds_for_google_sign_in(dom):
    """What the policy still says, and what is still true about it. The Google
    Identity script remains on index.html; the policy discloses it as the one
    third-party cookie, which — with reCAPTCHA gone — is now accurate for
    cookies. Google Fonts is a third-party REQUEST but sets no cookie, and its
    removal is deferred to the W stream by owner decision."""
    t = dom.text
    assert "The one third-party cookie on this site is Google's own" in t
    index = _sale_page("index.html")
    assert 'src="https://accounts.google.com/gsi/client"' in index,         "Google sign-in is gone — the policy's third-party section needs revisiting"
    assert "<code>g_state</code>" in dom.src, "the disclosed Google cookie left the table"


def test_the_functional_storage_is_listed_now(dom):
    """⚠ ALSO INVERTED. It used to assert the contradiction — that the policy
    claimed no functional cookies while localStorage remembered a dismissed
    banner. Both keys are disclosed now, so it asserts the disclosure.

    foxy_welcome is listed as NECESSARY, not functional, because it is not a
    preference: it carries the one-time API key from sign-up to the welcome page
    and welcome.html deletes it the moment it reads it. Calling that an
    interface preference would misdescribe a credential."""
    assert "don't use any functional cookies yet" not in dom.text,         "the false empty-category claim came back"
    index = _sale_page("index.html")
    welcome = _sale_page("welcome.html")
    assert "foxy_onboard_dismissed" in index and "foxy_welcome" in welcome
    row = re.search(r"<tr><td><code>foxy_onboard_dismissed</code>.*?</tr>", dom.src, re.S)
    assert row and "Functional" in row.group(0), "foxy_onboard_dismissed is not listed as Functional"
    row = re.search(r"<tr><td><code>foxy_welcome</code>.*?</tr>", dom.src, re.S)
    assert row and "Necessary" in row.group(0), "foxy_welcome is not listed as Necessary"
    assert "API key" in row.group(0), "the row does not say what foxy_welcome actually carries"


def test_every_storage_key_the_site_uses_is_in_the_table(dom):
    """BOTH DIRECTIONS, and this is the direction that was wrong. The table was
    complete for cookies and missing two storage keys, which is exactly the
    failure this page exists to avoid: a policy that omits something the site
    stores. Scanned from the source rather than from a list, so a new key added
    tomorrow fails here instead of going unmentioned."""
    keys = set()
    for page in sorted(HERE.glob("*.html")):
        src = page.read_text(encoding="utf-8")
        keys |= set(re.findall(r"(?:local|session)Storage\.(?:set|get|remove)Item\(\s*['\"]([^'\"]+)", src))
        keys |= set(re.findall(r"const\s+\w*KEY\w*\s*=\s*['\"]([^'\"]+)", src))
    listed = set(re.findall(r"<code>([a-z_]+)</code>", dom.src))
    missing = sorted(k for k in keys if k not in listed)
    assert not missing, f"the site stores keys the Cookie Policy does not list: {missing}"


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
                          "foxy_consent", "foxy_vid", "foxy_sid", "g_state",
                          # added when the SITE was changed to match the policy:
                          "foxy_onboard_dismissed", "foxy_welcome"}, \
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
    # Header + 9 entries. Seven when L7 converted the document; nine since the
    # two storage keys the site actually uses were added to make it complete.
    assert dom.src.count("<tr>") == 10, "the table lost or gained a row"


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
