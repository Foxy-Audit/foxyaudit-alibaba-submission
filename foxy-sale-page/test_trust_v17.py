"""trust.html — Trust Page v1.7. A PROCUREMENT DOCUMENT.

Its own subtitle is "for the reviewer who needs answers in five minutes", so
every sentence is a factual assertion someone will check before buying. Each one
below was checked against the code the way L7 checked the cookie table.

WHAT HELD (verified, not assumed):
  · no raw-text column — AuditLog carries prompt_hash/response_hash and nothing
    that could hold prompt or response text
  · Fernet AES-128-CBC + HMAC-SHA-256, context-bound BYOK keys
  · PostgreSQL row-level security under a confined non-superuser role
  · Sepolia by default, chain-configurable
  · MFA: emailed passcode, single use, 5-minute validity
  · OIDC SSO, domain-scoped, just-in-time provisioning
  · MIT-licensed SDK published on PyPI, sdist included
  · the OIDC client secret really IS stored in plaintext — an unusually candid
    disclosure that checks out (models.py: client_secret, String(512))

WHAT DID NOT — see the two guards below:
  · "an immutable staff audit trail" (§5) — admin_chain.py's own docstring says
    every surface reporting that chain "must say 'sequence unbroken', never
    'tamper-evident'". Immutable is stronger still. (#143/#144)
  · "structurally read-only … an undisclosed edit is detectable" (§4) — true of
    the customer ledger when anchoring is on; NOT true of the staff log, where
    truncating the tail leaves nothing behind and deleting every chained row is
    self-healing.

Both are RECORDED, not reworded. The only owner-authorised divergence from the
document is the SOC 2 date; a factual claim about a security property is the
owner's to settle, not a converter's.

Run:  pytest foxy-sale-page -q
"""

from __future__ import annotations

import pathlib
import re

import pytest

from conftest import POSTAL_ADDRESS

PAGE = "trust.html"
VERSION = "1.7"
PHONE = "+92 3398123944"
SUPERSEDED_PHONE = "3448123944"

HERE = pathlib.Path(__file__).resolve().parent
ROOT = HERE.parent


@pytest.fixture(scope="module")
def dom(legal_dom):
    return legal_dom(PAGE)


def _backend(rel: str) -> str:
    return (ROOT / "backend" / "app" / rel).read_text(encoding="utf-8")


# ── 1. THE CLAIM THE CODE CONTRADICTS ────────────────────────────────────────
def test_the_immutable_staff_trail_claim_still_overstates_the_code(dom):
    """⚠ RECORDED, NOT RESOLVED — and this one is on the page a buyer reads.

    §5 says admin actions are "recorded in an immutable staff audit trail".
    backend/app/admin_chain.py, in its own module docstring, says the opposite:

        "every surface that reports this chain must say 'sequence unbroken',
         never 'tamper-evident'. The UI copy in foxy-adminpage is written to
         that rule and guarded."

    and lists why:
      · REMOVING ENTRIES FROM THE END leaves nothing behind — "only an outside
        witness who recorded the older head would notice" (#143: the staff chain
        is not anchored, so there is no such witness)
      · deleting EVERY chained row is SELF-HEALING — chain_head returns None and
        the next write restarts at seq 1 against GENESIS (#144)
      · rows written before the mechanism shipped have no hash at all

    "Immutable" is a stronger word than "tamper-evident", which the code already
    forbids. The admin console obeys the rule and says "sequence unbroken"; this
    page does not.

    ⚠ WHEN THE WORDING IS FIXED, THIS TEST FAILS. That is the design — see the
    report for the suggested replacement."""
    assert "immutable staff audit trail" in dom.text, (
        "the claim changed — if it was corrected, rewrite this guard; the "
        "suggested wording is 'a staff audit trail whose sequence is verifiable'")
    chain = _backend("admin_chain.py")
    assert 'must say "sequence unbroken", never "tamper-evident"' in chain, \
        "admin_chain.py no longer states the rule this page breaks"
    assert "A wholesale delete is self-healing." in chain, "#144 no longer applies"
    assert "REMOVING ENTRIES FROM THE END leaves nothing behind" in chain, "#143 no longer applies"
    # the console obeys the rule the trust page does not
    admin = (HERE.parent / "foxy-adminpage" / "index.html").read_text(encoding="utf-8")
    assert "sequence unbroken" in admin, \
        "the admin console stopped using the careful wording, so the rule may have moved"


def test_the_read_only_claim_is_broader_than_the_staff_log_supports(dom):
    """§4 says the ledger, staff-action log AND anchor receipts are read-only
    such that "an undisclosed edit by our own staff is detectable". For the
    CUSTOMER ledger with anchoring enabled that is fair. For the staff log it is
    not, for the same reasons as above — and the page names all three together.

    Pinned so the over-broad sentence cannot drift while the owner decides."""
    t = dom.text
    assert "The audit ledger, staff-action log, and blockchain-anchor receipts are " \
           "structurally read-only" in t
    assert "an undisclosed edit by our own staff is detectable" in t
    assert "A wholesale delete is self-healing." in _backend("admin_chain.py")


# ── 2. THE OWNER-AUTHORISED DIVERGENCE ───────────────────────────────────────
def test_the_soc2_quarter_was_removed_and_no_date_replaced_it(dom):
    """⚠ OWNER-AUTHORISED DIVERGENCE FROM THE SOURCE DOCUMENT, 2026-08-13.

    v1.7 says "SOC 2 Type I — Q4 2026". No auditor is engaged and Q4 2026 begins
    in about seven weeks, so the quarter is removed and replaced with intent
    carrying NO date. A missed public commitment costs more with a procurement
    reviewer than a modest one, and this is the page they read it on.

    ⚠ THIS GUARD EXISTS BECAUSE A RE-CONVERSION WOULD SILENTLY RESTORE Q4 2026.
    Recorded under 'Owner-authorised divergences from the policy documents'."""
    t = dom.text
    assert "Q4 2026" not in t, "the unbacked SOC 2 quarter came back"
    assert "SOC 2 Type I" in t, "the roadmap item itself was dropped"
    assert "no auditor is engaged yet" in t, "the reason the date is absent is not stated"
    assert not re.search(r"SOC 2[^.]{0,60}\bQ[1-4]\s*20\d\d", t), \
        "a quarter was attached to SOC 2 again"
    # the ISO line keeps its date and its punctuation is repaired
    assert "ISO 27001 gap analysis — Q2 2027." in t, \
        "the ISO line lost its date or its jammed em-dash came back"
    assert "—Q2" not in t and "2027 ." not in t, "the conversion damage returned"


def test_the_blunt_disclosure_is_untouched(dom):
    """The best paragraph on the page. Softening it is the tempting edit, and it
    is the one thing a reviewer will trust the page for."""
    assert ("We do not currently hold SOC 2, ISO 27001, or a comparable third-party "
            "attestation. We consider this normal for our stage and are building toward "
            "it deliberately rather than claiming it early") in dom.text, \
        "the honest certifications disclosure was softened"
    assert "happy to complete a security questionnaire (CAIQ or your own SIG)" in dom.text


def test_no_certification_auditor_or_uptime_figure_is_invented(dom):
    """The page may state the 99.5% target the document states, and nothing more."""
    t = dom.text
    # ⚠ PER SENTENCE, AND ALLOWING FOR WHAT COMES BETWEEN. The first version
    # required the claim word to sit immediately after the standard, so
    # "SOC 2 TYPE II certified" — the most likely false claim, and the exact
    # phrase a reviewer scans for — walked through it. Measured: it survived.
    #
    # It cannot simply match the standard either: this page NAMES SOC 2 and
    # ISO 27001 in order to say it does not hold them. So each sentence that
    # pairs a standard with a claim word must also carry a negation.
    STANDARD = r"SOC ?2|ISO ?27001|HIPAA|PCI[- ]DSS|FedRAMP"
    CLAIM = r"certified|certification|compliant|attested|attestation|accredited"
    NEGATED = r"\b(?:do not|don't|no|not|never|without|rather than)\b"
    for sentence in re.split(r"(?<=[.!?])\s+", t):
        if re.search(STANDARD, sentence, re.I) and re.search(CLAIM, sentence, re.I):
            assert re.search(NEGATED, sentence, re.I), \
                f"a certification is claimed without a negation: {sentence[:120]!r}"
    pcts = sorted(set(re.findall(r"\b(\d{1,3}(?:\.\d+)?)\s*%", t)))
    assert pcts == ["99.5"], f"an uptime or other percentage was invented: {pcts}"
    assert "We target 99.5% monthly uptime" in t, "the figure stopped being a target"
    assert not re.search(r"\b(?:guarantee|guaranteed)\s+\d", t, re.I)
    hit = POSTAL_ADDRESS.search(t)
    assert not hit, f"a postal address was invented: {hit.group(0)!r}"


# ── 3. the claims that DO hold, checked against the code ────────────────────
def test_the_no_raw_column_claim_is_structurally_true(dom):
    """The flagship claim, and the one most worth checking: "our database has no
    column capable of storing raw prompt or response text"."""
    assert "our database has no column capable of storing raw prompt or response text" in dom.text
    models = _backend("models.py")
    block = models[models.index("class AuditLog"):]
    block = block[:block.index("\nclass ", 10)]
    cols = re.findall(r"^\s{4}(\w+):\s*Mapped", block, re.M)
    raw = [c for c in cols if re.search(r"prompt|response|content|text", c)
           and not re.search(r"hash|commit", c)]
    assert not raw, f"AuditLog gained a column that could hold raw text: {raw}"
    assert "prompt_hash" in cols and "response_hash" in cols


@pytest.mark.parametrize("claim,path,needle", [
    ("Fernet AES-128-CBC BYOK encryption", "crypto_secrets.py", "AES-128-CBC"),
    ("row-level security, confined role",  "config.py",        'db_app_role: str = "foxy_app"'),
    ("Sepolia by default",                 "config.py",        'anchor_evm_chain: str = "sepolia"'),
    ("5-minute one-time passcode",         "mfa.py",           "TTL = timedelta(minutes=5)"),
    ("6-digit passcode",                   "mfa.py",           "6-digit"),
])
def test_each_security_claim_matches_the_code(dom, claim, path, needle):
    """A trust page is only worth the checks behind it. These are the ones a
    reviewer would ask us to evidence."""
    assert needle in _backend(path), f"{claim}: the code no longer shows {needle!r}"


def test_the_plaintext_secret_disclosure_is_accurate(dom):
    """Unusually candid, and it checks out: the OIDC client secret really is a
    plain String column. A page that discloses its own weak spot is the page a
    reviewer believes about everything else — so it must stay true."""
    assert "the OIDC client secret and the webhook signing secret are currently stored in plaintext" \
        in dom.text
    models = _backend("models.py")
    assert re.search(r"client_secret:\s*Mapped\[str\]\s*=\s*mapped_column\(String\(\d+\)", models), \
        "the OIDC client secret is no longer a plain column — update the disclosure"


def test_the_sdk_licence_claim_holds(dom):
    assert "MIT-licensed and published on PyPI" in dom.text
    pyproject = (ROOT / "sdk" / "pyproject.toml").read_text(encoding="utf-8")
    assert 'license = { text = "MIT" }' in pyproject


# ── 4. the sub-processor list, against the Privacy Policy ───────────────────
def test_the_sub_processor_list_agrees_with_the_privacy_policy(dom):
    """Two published pages disagreeing about who processes customer data is the
    defect this stream keeps finding. Compared entity by entity AND location by
    location; the wording differs, the facts must not.

    ⚠ NOT harmonised here. privacy.html §8's "six named providers" count is
    #180 and belongs to L14 — this page states no count, so it is unaffected."""
    priv = (HERE / "privacy.html").read_text(encoding="utf-8")
    s8 = priv[priv.index('id="s8"'):priv.index('id="s9"')]
    for entity in ("Paddle.com Market Ltd", "Payoneer, Inc.", "Google Identity",
                   "Brevo SAS", "OpenAI, L.L.C.", "Google Cloud"):
        assert entity in dom.text, f"{entity} is on the Privacy Policy but not the Trust Page"
        assert entity in re.sub(r"<[^>]+>", "", s8), \
            f"{entity} is on the Trust Page but not Privacy Policy §8"
    rows = re.findall(r"<tr><td>(.*?)</td>", dom.src)
    assert len(rows) == 6, f"the sub-processor table has {len(rows)} rows, expected 6"
    for loc in ("United States", "Global (UK-headquartered)", "European Union"):
        assert loc in dom.text
    assert "six named providers" not in dom.text.lower(), \
        "this page acquired a count claim — that is #180's problem, do not import it"


def test_payoneer_not_paddle_is_the_one_that_never_touches_checkout(dom):
    """⚠ A LOST EM-DASH INVERTED A SUB-PROCESSOR DISCLOSURE. The .docx reads
    "...how we receive our own revenue from Paddle never touches customer
    checkout", which parses as a claim that PADDLE never touches checkout —
    flatly contradicting the Terms of Service, where Paddle IS the merchant of
    record and runs it.

    With the dash restored the sentence says what it means: the PAYONEER row
    never touches customer checkout, which matches Privacy Policy §8."""
    row = re.search(r"<tr><td>Payoneer, Inc\.</td>.*?</tr>", dom.src, re.S)
    assert row, "the Payoneer row is gone"
    assert "from Paddle — never touches customer checkout" in row.group(0), \
        "the restored em-dash was lost; the row now reads as a claim about Paddle"
    paddle_row = re.search(r"<tr><td>Paddle\.com Market Ltd.*?</tr>", dom.src, re.S)
    assert "merchant of record" in paddle_row.group(0), \
        "the Paddle row no longer says it is the merchant of record"
    assert "never touches customer checkout" not in paddle_row.group(0)


# ── 5. the em-dashes the .docx lost ──────────────────────────────────────────
@pytest.mark.parametrize("sentence", [
    # ⚠ PROVED: v1.4 has a DOUBLED SPACE here and v1.7 collapsed it to one.
    "That is not a policy promise — our database has no column",
    "a known gap, not an oversight in this page — it's on our roadmap to close",
    "for tenant-scoped transactions — not application logic alone",
    "administrative tools — an undisclosed edit by our own staff is detectable",
    "independent chain — currently Sepolia by default, mainnet-configurable — so you",
    "revenue from Paddle — never touches customer checkout",
    "Responsible Disclosure Policy — good-faith reporters following that process",
    "Reviewing its source — including the hashing and PII-detection logic — is the fastest way",
])
def test_the_restored_em_dashes_survive(dom, sentence):
    """TEN missing across eight places — the worst of the eight documents.

    One is PROVED: v1.4 carries "not a policy promise␣␣our database" with a
    doubled space, and v1.7 normalised it away. That one sits on the flagship
    content-blindness claim. The rest are invisible in both versions and rest on
    grammar; the systematic sweep found all eight positions independently."""
    assert sentence in dom.text, f"a restored em-dash was lost: {sentence[:58]!r}…"


def test_no_whitespace_gap_or_jammed_dash_survived(dom):
    assert "  " not in dom.text, "a doubled space survived — a dropped character"
    assert not re.findall(r"\w +[,.;:](?:\s|$)", dom.text), "space before punctuation"
    assert not re.search(r"\w—|—\w", dom.text), "an em-dash is jammed against a word"


def test_the_word_callout_bullet_was_not_rendered(dom):
    """◉ U+25C9 is a Word callout marker whose job the .card now does — L1's
    treatment, applied identically."""
    assert "◉" not in dom.src, "the Word callout bullet was rendered as content"
    assert "The short version." in dom.text


# ── 6. conversion hygiene, navigation and the network guarantee ─────────────
def test_the_page_states_the_version_the_filename_carries(dom):
    """⚠ The document header says "Version 1.0" and the filename says v1.7; the
    filename wins (owner)."""
    line = re.search(r'class="updated">([^<]+)<', dom.src)
    assert line and f"Version {VERSION}" in line.group(1), \
        f"the header line does not name Version {VERSION}"
    assert "Version 1.0" not in dom.text, "the document's stale header version was published"


def test_the_contact_is_the_security_mailbox(dom):
    assert dom.addresses == {"security@foxyaudit.tech"}, f"unexpected addresses: {dom.addresses}"
    assert SUPERSEDED_PHONE not in dom.src, "the superseded phone number was published"
    assert PHONE in dom.text
    for href in dom.mailtos:
        assert not href[len("mailto:"):].split("?")[0].endswith(".")


def test_it_links_only_documents_that_exist(dom):
    """The SLA (L9) and the Order Form (L12) are named in prose and deliberately
    NOT linked — L2b's reverse cross-link guard will say when that changes."""
    assert "Service Level Agreement" in dom.text
    assert 'href="/sla.html"' not in dom.src, "linked an SLA page that does not exist yet"
    for href in {a["href"] for a in dom.links if a["href"].startswith("/")}:
        target = href.lstrip("/").split("#")[0] or "index.html"   # "/" is the home page
        assert (HERE / target).is_file(), f"links to {href}, which does not exist"


def test_every_in_page_anchor_lands_on_something(dom):
    frags = {a["href"].split("#")[1] for a in dom.links if "#" in a["href"] and a["href"].startswith("#")}
    assert not (frags - set(dom.ids)), f"dead fragments: {sorted(frags - set(dom.ids))}"
    assert len([i for i in dom.ids if re.fullmatch(r"s\d+", i)]) == 11, \
        "the page no longer has its eleven sections"


def test_the_cross_document_deep_links_resolve(dom):
    for href in ("/privacy.html#s3", "/privacy.html#s5", "/privacy.html#s15"):
        page, _, frag = href.partition("#")
        assert f'href="{href}"' in dom.src, f"the page no longer deep-links {href}"
        assert f'id="{frag}"' in (HERE / page.lstrip("/")).read_text(encoding="utf-8"), \
            f"{page} has no {frag} to land on"


def test_no_external_url_is_reachable_from_the_markup(dom):
    fetching = re.findall(r'(?:src|href)="(https?://[^"]+)"', dom.src)
    fetching += re.findall(r"url\(\s*['\"]?(https?://[^)'\"]+)", dom.src)
    assert not fetching, f"the page fetches from the network: {fetching}"
    assert "https://" not in dom.src, "an absolute URL appeared on a legal page"


def test_the_embedded_faces_are_the_ones_the_siblings_ship(dom):
    pat = r"font-weight:(\d+);font-display:swap;src:url\(data:font/woff2;base64,([A-Za-z0-9+/=]+)\)"
    mine = dict(re.findall(pat, dom.src))
    sibling = dict(re.findall(pat, (HERE / "cookie-policy.html").read_text(encoding="utf-8")))
    assert set(mine) == {"600", "700"}, f"unexpected faces: {sorted(mine)}"
    assert mine == sibling, "the embedded Poppins has drifted from cookie-policy.html's"
