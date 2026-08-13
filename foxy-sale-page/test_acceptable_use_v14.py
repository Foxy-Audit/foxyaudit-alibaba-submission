"""acceptable-use.html — Acceptable Use Policy v1.4.

⚠ THIS IS THE SECOND DOCUMENT THAT TELLS SECURITY RESEARCHERS WHAT THEY MAY DO.

L5 made report-abuse.html the authoritative public security policy: it carries
the safe harbour, its four conditions, an in-scope list and five exclusions. This
page's §3 and §1 also grant and withhold permission to test the platform — and
they do not say the same thing. The divergence is RECORDED below, not silently
edited away, because which of two published legal documents governs is an owner's
decision and not a conversion one. See
test_the_aup_and_the_disclosure_policy_still_disagree.

#190: the live page published a personal Gmail address. It cannot again.

#179: the .docx has ZERO surviving em-dashes and THREE were restored. One of them
was found only by diffing the superseded v1.2, whose doubled space v1.4 had
collapsed to a single one — the systematic sweep could not see it.

Guards read the PARSED result, never a source string. Browser claims live in
test_legal_pages_rendered.py; cross-page links in test_legal_cross_links.py.

Run:  pytest foxy-sale-page -q
"""

from __future__ import annotations

import pathlib
import re

import pytest

from conftest import POSTAL_ADDRESS

PAGE = "acceptable-use.html"
VERSION = "1.4"
PHONE = "+92 3398123944"
SUPERSEDED_PHONE = "3448123944"

HERE = pathlib.Path(__file__).resolve().parent


@pytest.fixture(scope="module")
def dom(legal_dom):
    return legal_dom(PAGE)


@pytest.fixture(scope="module")
def disclosure(legal_dom):
    """The authoritative security policy, for comparison."""
    return legal_dom("report-abuse.html")


# ── 1. THE TWO PERMISSION GRANTS ─────────────────────────────────────────────
def test_the_aup_and_the_disclosure_policy_still_disagree(dom, disclosure):
    """⚠ THIS TEST RECORDS AN UNRESOLVED CONFLICT. IT IS MEANT TO.

    Two published documents now tell a researcher what they may do, and on three
    points the Acceptable Use Policy forbids conduct the disclosure policy
    expressly permits:

      ACCESSING OTHERS' DATA
        disclosure: "Only access the minimum data needed to demonstrate the
                     issue — never view, modify, or exfiltrate other users' data."
        AUP §3:     "Don't access data that isn't yours"
        AUP §1:     "Don't attempt to access another organization's data"
        → someone who reads one foreign record to prove a tenant-isolation break
          is inside the safe harbour and in breach of the AUP.

      AUTOMATED TOOLING
        disclosure: "Do not run automated scanners against production WITHOUT
                     PRIOR ARRANGEMENT."
        AUP §3:     "run automated attacks against production" — no carve-out.

      PROBING CONTROLS
        disclosure: excludes only VOLUMETRIC denial of service and impact-free
                    scanner output.
        AUP §1:     "no attempts to overload, PROBE, or bypass rate limits,
                     quotas, or security controls" — which is what in-scope
                     research consists of.

    The document was reproduced as written rather than harmonised: which of two
    legal documents governs is not a conversion decision. Both sides are pinned
    here so neither can drift while the conflict is open.

    ⚠ WHEN THE OWNER RESOLVES IT, THIS TEST FAILS. That is the design — the fix
    must be deliberate, and whoever makes it should read this first."""
    aup, dis = dom.text, disclosure.text

    # the AUP's absolute prohibitions
    assert "Don't access data that isn't yours" in aup
    assert "Don't attempt to access another organization's data" in aup
    assert "run automated attacks against production" in aup
    assert "no attempts to overload, probe, or bypass rate limits" in aup

    # the disclosure policy's narrower, conditional versions
    assert "Only access the minimum data needed to demonstrate the issue" in dis
    assert "Do not run automated scanners against production without prior arrangement" in dis

    # the conflict itself: the AUP grants no carve-out where the policy does
    assert "without prior arrangement" not in aup, (
        "the AUP now carries the disclosure policy's carve-out — if that was "
        "deliberate the conflict is resolved and this guard should be rewritten")
    assert "minimum data needed" not in aup, (
        "the AUP now permits minimum-necessary access — same as above")


def test_the_aup_points_at_the_authoritative_policy(dom):
    """§3 already said "our Report Abuse process". Making that reference
    resolvable is not harmonising the texts — it is the difference between a
    reader finding the safe harbour and not."""
    s3 = dom.section(3)
    assert 'href="/report-abuse.html"' in s3, \
        "§3 names the Report Abuse process but does not link it"
    assert "Good-faith security research is welcome" in dom.text
    assert "follow responsible disclosure" in dom.text


def test_the_aup_grants_no_safe_harbour_of_its_own(dom):
    """One safe harbour, in one place. If this page ever grows its own wording
    there are two undertakings to keep in step — the mistake L5 spent a phase
    undoing between SECURITY.md and the published policy."""
    t = dom.text
    assert "not pursue legal action" not in t, \
        "the AUP now states its own safe harbour; there must be exactly one"
    assert "safe harbour" not in t.lower()


# ── 2. #190 — the Gmail address ──────────────────────────────────────────────
def test_no_personal_mailbox_is_published(dom):
    """The live page carried foxyaudit@gmail.com. One of seven pages in #190,
    and one of only two with a phase to fix it."""
    assert "gmail" not in dom.src.lower(), "a personal Gmail address is published"
    assert dom.addresses == {"legal@foxyaudit.tech"}, f"unexpected addresses: {dom.addresses}"
    for href in dom.mailtos:
        addr = href[len("mailto:"):].split("?")[0]
        assert not addr.endswith("."), f"dead mailto — trailing full stop captured: {href!r}"


def test_the_contact_is_legal_and_not_the_security_mailbox(dom):
    """legal@ — this is a policy question channel, not a disclosure channel. A
    vulnerability goes to security@ via the Report Abuse page, and §3 links it."""
    assert "legal@foxyaudit.tech" in dom.text
    assert "security@foxyaudit.tech" not in dom.text, \
        "the AUP offers the security mailbox directly, bypassing the disclosure policy"


# ── 3. the em-dashes the .docx lost ──────────────────────────────────────────
@pytest.mark.parametrize("sentence", [
    # invisible in BOTH versions — single space, found only by reading
    "Foxy Audit is trust infrastructure — its value depends on the platform",
    # the one visible gap, present in v1.2 and v1.4 alike
    "raw content never reaches us — don't attempt to route raw sensitive content",
    # ⚠ v1.2 had a DOUBLED SPACE here; v1.4 collapsed it. Found only by the diff.
    "terminate the account immediately where necessary — and, where appropriate",
])
def test_the_restored_em_dashes_survive(dom, sentence):
    """THREE missing, and the .docx carries none at all — the second document in
    the set with no survivors.

    Found three different ways, and each way found something the others missed:
    reading caught the lead; the single doubled space was visible to any
    whitespace check; and the third exists ONLY in the superseded v1.2, where it
    was a gap that v1.4 normalised into ordinary prose. A sweep for the four
    dash-losing constructions found the first two and could not see the third."""
    assert sentence in dom.text, f"a restored em-dash was lost: {sentence[:58]!r}…"


def test_no_whitespace_gap_survived(dom):
    assert "  " not in dom.text, "a doubled space survived — a dropped character"
    assert not re.findall(r"\w +[,.;:](?:\s|$)", dom.text), "space before punctuation"


# ── 4. enforcement, stated without invention ─────────────────────────────────
def test_enforcement_invents_no_timeline_or_penalty(dom):
    """§4 deliberately gives no notice period, no cure window, and no fee. It
    says "immediately where necessary" and "we aim to give notice" — both
    unquantified, both on purpose."""
    s4 = dom.section(4)
    assert "we may throttle, suspend, or terminate the account" in dom.text
    assert "We aim to give notice and a chance to remedy" in dom.text
    assert not re.search(r"\b\d+\s*(?:hour|day|business[- ]day)s?\b", s4, re.I), \
        "an enforcement timeline was invented"
    assert not re.search(r"[$£€]\s?\d|\bfee of\b|\bpenalt(?:y|ies)\b", s4, re.I), \
        "a penalty or fee was invented"


def test_the_page_states_the_version_it_was_converted_from(dom):
    """⚠ One of the five documents whose header version and filename AGREE —
    both say 1.4 — so there was no version decision here."""
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


# ── 5. the .docx chrome, which this document carries again ───────────────────
def test_the_docx_page_chrome_was_not_pasted_in(dom):
    """⚠ Like L4's document, this .docx contains the rendered header and footer
    as document text — including a fox emoji and a © line. Only the policy was
    extracted; the page keeps its own incumbent footer, byte-identical.

    ⚠ #12: the owner has decided the fox emoji goes ("the logo or nothing"). It
    is incumbent in every sibling header, so it is NOT fixed here — fixing one
    page fragments the header. This pins that the document did not ADD a second
    one, which is a different thing."""
    assert dom.src.count('class="foot"') == 1, "a second footer was pasted in from the document"
    assert dom.src.count("Cryptographic compliance, not a promise") == 1
    assert dom.text.count("Back to home") == 1, "the document's header line became content"
    assert dom.src.count("\U0001f98a") == 1, \
        "the document's fox emoji was added on top of the header's"


# ── 6. navigation and the network guarantee ──────────────────────────────────
def test_every_in_page_anchor_lands_on_something(dom):
    frags = {a["href"].split("#")[1] for a in dom.links if "#" in a["href"]}
    assert not (frags - set(dom.ids)), f"anchors point at ids that do not exist: {sorted(frags - set(dom.ids))}"
    assert len([i for i in dom.ids if re.fullmatch(r"s\d+", i)]) == 5, \
        "the page no longer has its five sections"


def test_no_external_url_is_reachable_from_the_markup(dom):
    fetching = re.findall(r'(?:src|href)="(https?://[^"]+)"', dom.src)
    fetching += re.findall(r"url\(\s*['\"]?(https?://[^)'\"]+)", dom.src)
    assert not fetching, f"the page fetches from the network: {fetching}"
    assert "https://" not in dom.src, "an absolute URL appeared on a legal page"


def test_the_embedded_faces_are_the_ones_the_siblings_ship(dom):
    """⚠ #192: strip the base64 before any case-insensitive matching elsewhere —
    the blob contains "GPg" and "PgP" as ordinary substrings."""
    pat = r"font-weight:(\d+);font-display:swap;src:url\(data:font/woff2;base64,([A-Za-z0-9+/=]+)\)"
    mine = dict(re.findall(pat, dom.src))
    sibling = dict(re.findall(pat, (HERE / "report-abuse.html").read_text(encoding="utf-8")))
    assert set(mine) == {"600", "700"}, f"unexpected faces: {sorted(mine)}"
    assert mine == sibling, "the embedded Poppins has drifted from report-abuse.html's"
