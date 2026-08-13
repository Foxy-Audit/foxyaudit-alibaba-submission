"""dpa.html — Data Processing Agreement v1.4. A CONTRACT, NOT A DISCLOSURE.

Every other legal page so far describes what we do. This one is an Article 28
processing agreement: the customer counter-signs it, and their own regulator
reads it. Numbers and legal instruments in it are commitments, so they are
guarded individually rather than as a block of prose.

WHAT WAS VERIFIED AGAINST THE CODE AND THE OTHER PAGES:
  · every one of the TEN Privacy Policy cross-references resolves, and the
    section it points at says what the DPA claims it says
  · §15 of the Privacy Policy really does say "without undue delay" and contains
    no fixed hour count — so §10 here is consistent, not inventing a window
  · the Compliance Passport export that §8, §9 and §12(a) all lean on exists

THE OWNER-AUTHORISED DIVERGENCES (the same one, applied twice):
  · §7 said administrative access is subject to "an immutable staff audit
    trail (Privacy Policy Section 11)". L8 removed exactly that claim from
    trust.html; L10 removed it from privacy.html §11, the section this cites.
    Publishing the document verbatim would have restored, in a signed contract,
    the claim we had just retracted twice — and cited a page that no longer
    supports it. Rendered with the L8 wording.
  · §6 said the ledger, staff log and anchor receipts are "structurally
    read-only … such that undisclosed edits are detectable", one sentence
    covering three mechanisms of different strength. Split the way trust.html §4
    was split, for the same reason: the weakest member was setting the truth for
    all three.

WHAT WAS REPORTED, NOT FIXED:
  · §5 lists FIVE sub-processors; privacy.html §8 and trust.html list SIX. The
    DPA omits Payoneer and names a generic "infrastructure/hosting provider"
    where the other two name Google Cloud. §5 is a general authorization that
    incorporates Privacy Policy Section 8 by reference, so the lists must agree.
    Which document governs is not a conversion decision — see the L10 report.
  · No email address and no phone number appears anywhere in the document, so a
    customer with a data-protection question has no route. Reported; nothing
    invented. Guarded below so a future edit cannot quietly add one.

Run:  pytest foxy-sale-page -q
"""

from __future__ import annotations

import pathlib
import re

import pytest

from conftest import POSTAL_ADDRESS

PAGE = "dpa.html"
VERSION = "1.4"

HERE = pathlib.Path(__file__).resolve().parent


@pytest.fixture(scope="module")
def dom(legal_dom):
    return legal_dom(PAGE)


def _privacy(legal_dom):
    return legal_dom("privacy.html")


# ── 1. THE COMMITMENTS ───────────────────────────────────────────────────────
def test_the_sub_processor_notice_period_is_thirty_days(dom):
    """The only hard number in the operative text. It is a contractual notice
    period: shortening it is a change to what the customer agreed to."""
    m = re.search(r"at least\s+(\d+)\s+days.{0,120}?before adding or replacing a sub-processor",
                  dom.text, re.S)
    assert m, "the sub-processor notice sentence is gone or was restructured"
    assert m.group(1) == "30", f"the notice period changed to {m.group(1)} days"
    assert "workspace's registered administrator" in dom.text, \
        "the notice channel (who actually gets told) was dropped"
    assert "object on reasonable data-protection grounds" in dom.text
    assert "terminate the affected portion of the Service" in dom.text, \
        "the sole remedy was dropped"


def test_the_audit_frequency_is_once_per_twelve_months_with_its_exception(dom):
    m = re.search(r"no more than once per\s+(\d+)-month period\s*\(([^)]+)\)", dom.text)
    assert m, "the audit-frequency sentence is gone"
    assert m.group(1) == "12"
    assert "confirmed security incident" in m.group(2), \
        "the exception that lets a customer audit after an incident was dropped"


@pytest.mark.parametrize("instrument, needle", [
    ("EU SCCs, Module 2 specifically",
     "EU Standard Contractual Clauses"),
    ("the module — controller to processor, not processor to processor",
     "Module 2: Controller to Processor"),
    ("UK transfers",
     "UK International Data Transfer Addendum to the EU SCCs"),
    ("Swiss transfers",
     "Swiss Federal Act on Data Protection"),
])
def test_each_transfer_instrument_is_named(dom, instrument, needle):
    """§11 names three regimes. Naming the wrong module, or dropping one, is the
    kind of error a DPR reviewer rejects the contract over. Each is pinned
    separately so a failure names which one went missing."""
    assert needle in dom.text, f"§11 no longer relies on {instrument}"


def test_the_incident_window_is_without_undue_delay_and_no_number_was_invented(dom, legal_dom):
    """⚠ THE ONE MOST LIKELY TO BE 'HELPFULLY' TIGHTENED.

    GDPR Article 33 gives the CONTROLLER 72 hours. A processor's obligation is
    "without undue delay", and the customer here is the controller. Writing "72
    hours" into this page would invent a commitment the document does not make
    and the business cannot currently measure. The Privacy Policy is pinned
    alongside it, because §10 cites it and the two must not drift apart."""
    assert "without undue delay after becoming aware of a security incident" in dom.text
    for name, text in (("dpa.html", dom.text), ("privacy.html", _privacy(legal_dom).text)):
        found = re.findall(r"\b\d+\s*(?:hours?|business hours?|days?)\b(?![^.]{0,80}sub-processor)",
                           text, re.I)
        assert not re.search(r"\b72\s*hours?\b", text, re.I), \
            f"{name} now states a 72-hour incident window — that is Article 33's " \
            f"CONTROLLER deadline, not this processor's commitment (found: {found})"


def test_the_audit_ladder_keeps_all_three_rungs_in_order(dom):
    """(a) export, (b) assessment if any, (c) questionnaire — and only then is an
    on-site audit considered. The ORDER is the commitment: it is what keeps a
    systems-level audit from being the customer's first option. Positions are
    compared, so re-ordering the rungs fails even though all three words remain."""
    t = dom.text
    rungs = [("(a)", "Compliance Passport export"),
             ("(b)", "most recent third-party security assessment then held"),
             ("(c)", "mutually scheduled written questionnaire response")]
    at = []
    for label, needle in rungs:
        i = t.find(needle)
        assert i > 0, f"audit rung {label} ({needle!r}) is missing"
        at.append(i)
    assert at == sorted(at), f"the audit ladder was re-ordered: {at}"
    tail = t.find("before any on-site or systems-level audit is considered")
    assert tail > at[-1], \
        "the 'before any on-site audit' clause no longer follows the ladder"
    assert "if any" in t[at[1]:at[1] + 120], \
        "(b) lost 'if any' — it would now promise an assessment we do not hold"


def test_the_roles_are_not_reversed(dom):
    """Controller/processor the wrong way round inverts the whole agreement, and
    reads plausibly either way. Pinned to the customer side explicitly."""
    m = re.search(r"Customer is the\s+data controller.{0,60}?and Foxy Audit is the\s+data processor",
                  dom.text, re.S)
    assert m, "the controller/processor assignment was changed or reworded"
    assert "only on Customer's documented instructions" in dom.text.replace("’", "'")


def test_precedence_and_liability_point_the_way_the_document_wrote_them(dom):
    assert "this DPA prevails" in dom.text, "§14 no longer gives the DPA precedence"
    assert "subject to the limitations of liability set out in the Agreement" in dom.text, \
        "§13 no longer defers liability to the Agreement"


# ── 2. THE DIVERGENCES, RECORDED AS SUCH ─────────────────────────────────────
def test_section_7_carries_the_L8_wording_not_the_documents(dom):
    """The document said "an immutable staff audit trail (Privacy Policy Section
    11)". L8 struck that claim from trust.html; L10 struck it from privacy.html
    §11, the section cited here. The site-wide ban lives in
    test_site_wide_claims.py; this pins the positive replacement on this page."""
    t = dom.text
    assert "staff audit trail whose sequence is verifiable" in t
    assert "edited, removed from the middle, or re-ordered breaks the chain" in t
    assert "step-up authentication" in t, "the access control itself was dropped"
    assert "bound by confidentiality obligations" in t


def test_section_6_says_what_is_true_of_each_of_the_three_trails(dom):
    """The same split trust.html §4 got. One sentence covering ledger, staff log
    and anchor receipts let the weakest set the truth for all three."""
    t = dom.text
    assert "read-only within Foxy Audit's administrative tools — there is no edit path" in t
    assert "Where anchoring is enabled, the customer audit ledger goes further" in t
    assert "hash-chained but not yet anchored" in t, \
        "§6 stopped distinguishing the staff log from the anchored customer ledger"
    for measure in ("TLS in transit", "salted/peppered hashing",
                    "Fernet-encrypted", "row-level security",
                    "security-hardening HTTP headers"):
        assert measure in t, f"the measures list lost {measure!r}"


def test_the_sub_processor_delta_is_still_exactly_what_was_reported(dom, legal_dom):
    """⚠ REPORTED, NOT FIXED — and pinned so the report cannot go stale.

    §5 is a GENERAL AUTHORIZATION whose parenthetical names five sub-processors
    while incorporating Privacy Policy Section 8, which names six. If someone
    later fixes either side, this fails and the L10 report must be revisited
    rather than quietly becoming wrong."""
    dpa, privacy = dom.text, _privacy(legal_dom).text
    named_in_dpa = {n for n in ("Google LLC", "OpenAI", "Paddle", "Google Identity",
                                "Brevo", "Payoneer", "Google Cloud") if n in dpa}
    named_in_privacy = {n for n in ("Google LLC", "OpenAI", "Paddle", "Google Identity",
                                    "Brevo", "Payoneer", "Google Cloud") if n in privacy}
    assert named_in_privacy - named_in_dpa == {"Payoneer", "Google Cloud"}, (
        "the sub-processor delta between dpa.html and privacy.html changed — "
        f"dpa={sorted(named_in_dpa)}, privacy={sorted(named_in_privacy)}. "
        "The L10 report describes the old delta; re-check it.")
    assert "infrastructure/hosting provider" in dpa, \
        "§5 no longer uses the generic hosting wording the delta was reported about"
    assert "listed in Privacy Policy Section 8" in dpa, \
        "§5 stopped incorporating the Privacy Policy list — the delta now has no bridge"


# ── 3. THE CROSS-REFERENCES ──────────────────────────────────────────────────
CITED_SECTIONS = [3, 4, 6, 8, 9, 10, 11, 13, 14, 15]


@pytest.mark.parametrize("n", CITED_SECTIONS)
def test_every_privacy_policy_reference_is_a_link_that_lands(dom, legal_dom, n):
    """Ten citations. A DPA whose authority is another document is only as good
    as its pointers, and a section number is exactly the sort of thing that
    survives a renumbering while silently meaning something else."""
    href = f"/privacy.html#s{n}"
    assert href in dom.src, f"Privacy Policy Section {n} is cited but not linked to {href}"
    target = _privacy(legal_dom)
    assert f"s{n}" in target.ids, f"privacy.html has no #s{n} for the DPA to land on"


def test_no_reference_points_past_the_end_of_the_privacy_policy(dom, legal_dom):
    """A citation to a section that does not exist yet renders as a live link and
    scrolls nowhere. Measured against the sections privacy.html actually has."""
    cited = {int(m) for m in re.findall(r"Privacy Policy Sections?\s+([\d, and]+)", dom.text)
             for m in re.findall(r"\d+", m)}
    assert cited == set(CITED_SECTIONS), \
        f"the set of cited sections changed: {sorted(cited)}"
    privacy = _privacy(legal_dom)
    assert all(f"s{n}" in privacy.ids for n in cited)


# ── 4. CONTACT DETAILS: THE ABSENCE IS THE FINDING ───────────────────────────
def test_no_contact_route_was_invented(dom):
    """⚠ NOTHING WAS ADDED. The document gives no email and no phone, which is a
    real gap in an Article 28 agreement — reported, not patched. This guard's job
    is to make sure the gap stays honest: an invented address would look like a
    fix and be a fabrication."""
    text, html = dom.text, dom.src
    assert not re.search(r"[\w.+-]+@[\w-]+\.[\w.]+", text), \
        f"an email address appeared in the DPA: {re.findall(r'[a-z.+-]+@[a-z.]+', text, re.I)}"
    assert "mailto:" not in html, "a mailto: link appeared in the DPA"
    assert not re.search(r"\+\d[\d\s()-]{7,}", text), "a phone number appeared in the DPA"
    assert not POSTAL_ADDRESS.search(text), "a postal address appeared in the DPA"


def test_the_entity_line_survived_character_for_character(dom):
    """The one identity statement the document does make."""
    assert "FOXY AUDIT, a company incorporated in the Islamic Republic of Pakistan" in dom.text


def test_the_effective_date_is_not_a_fabricated_date(dom):
    """The document reads "[to be set when first executed]". Rendered without the
    drafting brackets, which read as an unfilled template on a published page —
    but the MEANING must not become a date somebody made up."""
    t = dom.text
    assert "set when first executed" in t
    assert not re.search(r"Effective date[^.]{0,60}\b(19|20)\d\d\b", t), \
        "a concrete effective date appeared — the document does not have one"


# ── 5. #179, AND THE REST OF THE CONVERSION ──────────────────────────────────
DASH = "—"


def test_the_one_restored_em_dash_survives(dom):
    """#179, AND THE LIMIT OF WHAT EVIDENCE SUPPORTS.

    v1.2 carries exactly two doubled-space scars. v1.4 REPAIRED one of them (the
    "applicable law — in which case" dash is back, which is why the em-dash count
    went 1 → 2) and LAUNDERED the other down to a single space. That laundered
    one is this sentence, and restoring it is evidence-backed.

    ⚠ TWO FURTHER RESTORATIONS WERE MADE AND THEN REVERTED. A construction sweep
    flagged "only the resulting labels not the underlying values are transmitted"
    and "…Swiss Federal Act on Data Protection together, consistent with…" as
    reading like dash damage. Checked against v1.2: the first appears there with
    no gap and no dash, character for character; the second does not appear in
    v1.2 at all, so there is no prior version to diff. Both readings are awkward,
    but awkward is not evidence, and inserting punctuation into a counter-signed
    contract on a hunch is inventing legal text. They are the document's own
    prose and were left alone — flagged to the owner as a drafting question."""
    assert f"Privacy Policy Section 4 {DASH} principally cryptographic Commitments" in dom.text
    # the two that were NOT restored, pinned as the document has them, so nobody
    # "fixes" them later without re-doing the version diff
    assert "only the resulting labels not the underlying values are transmitted" in dom.text
    assert "Swiss Federal Act on Data Protection together, consistent with" in dom.text


def test_no_whitespace_gap_or_jammed_dash_survived(dom):
    assert "  " not in dom.text, "a doubled space (an em-dash's grave) is on the page"
    assert not re.search(r"\w" + DASH + r"\w", dom.text), "an em-dash lost its spacing"
    assert dom.text.count("–") == 0, "an en-dash appeared where the source has none"


def test_the_page_states_the_version_the_filename_carries(dom):
    assert re.search(rf"Version\s*{re.escape(VERSION)}\b", dom.text), \
        f"the page does not state v{VERSION}"
    assert not re.search(r"\b1\.[0-3]\b", dom.text), "a superseded version number is on the page"


def test_the_appendix_survived_whole(dom):
    """Appendix A is the Article 30 record. Missing a row is a compliance gap, so
    all six labels are pinned."""
    for label in ("Subject matter:", "Duration:", "Nature and purpose:",
                  "Categories of data subjects:", "Categories of personal data:",
                  "Sub-processors:"):
        assert label in dom.text, f"Appendix A lost the {label!r} row"
    assert "never in plaintext" in dom.text, \
        "the appendix lost the statement that data subjects appear only as hashes"


def test_the_content_blindness_claim_is_stated_the_way_the_product_works(dom):
    assert "never the underlying prompt or response text" in dom.text
    assert "structurally never transmitted to Foxy Audit" in dom.text


# ── 6. THE PAGE ITSELF ───────────────────────────────────────────────────────
def test_no_external_url_is_reachable_from_the_markup(dom):
    urls = re.findall(r"https?://[^\s\"'<>)]+", re.sub(r"base64,[A-Za-z0-9+/=]+", "", dom.src))
    assert not urls, f"the DPA reaches off-site: {urls}"


def test_the_embedded_faces_are_the_ones_the_siblings_ship(dom):
    """Byte-identical to the sibling pages, so the display face cannot silently
    become a different cut on one page."""
    mine = dict(re.findall(r"font-weight:(\d+);font-display:swap;src:url\(data:font/woff2;base64,([A-Za-z0-9+/=]+)\)",
                           dom.src))
    sibling = dict(re.findall(r"font-weight:(\d+);font-display:swap;src:url\(data:font/woff2;base64,([A-Za-z0-9+/=]+)\)",
                              (HERE / "trust.html").read_text(encoding="utf-8")))
    assert set(mine) == {"600", "700"} and mine == sibling, \
        "the embedded Poppins faces differ from trust.html's"


def test_every_in_page_anchor_lands_on_something(dom):
    for href in re.findall(r'href="#([^"]+)"', dom.src):
        assert href in dom.ids, f"in-page link #{href} lands nowhere"
