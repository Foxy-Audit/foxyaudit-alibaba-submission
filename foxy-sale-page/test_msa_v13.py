"""msa.html — Master Service Agreement v1.3. THE DOCUMENT THAT OUTRANKS THE OTHERS.

§1 states an order of precedence that reaches across the whole legal set:

    Order Form  >  this Agreement  >  DPA / SLA  >  public Terms of Service
    "(which this Agreement supersedes for signing Customers)"

Every other page on this site sits somewhere in that chain, so a guard that only
reads msa.html is guarding a spine with no body attached. The checks in section 2
below each read TWO documents and assert they agree — that is the whole point.

WHAT HELD (verified against the published pages, both directions):
  · sla.html — "Customers with an active paid Order Form referencing this SLA",
    "incorporated by reference into the Master Service Agreement". Matches §1(c)
    and §7 exactly.
  · refund.html — a signed MSA with a negotiated refund or credit provision
    "govern[s] instead of this page". Matches §1's precedence.

WHAT DID NOT HOLD (reported, NOT harmonised — which document governs is the
owner's to settle, not a conversion decision):

  · §2 CITES A SECTION THAT DEFINES THE SERVICE DIFFERENTLY. It says the Service
    is "as defined in the Terms of Service Section 2 (the dashboard, API, SDK,
    and desktop application)". Measured: terms.html §2 contains NONE of those four
    words. It defines the Service by capability — "a tamper-evident audit ledger,
    an AI policy judge, verification tooling, and exportable compliance reports" —
    and says nothing about the staff administrative console. The parenthetical is
    the MSA's own definition wearing a citation's clothes.

  · THE DPA NAMES A DIFFERENT PARENT. MSA §1(b) and §6 incorporate the DPA into
    the MSA. dpa.html says it "forms part of, and is incorporated by reference
    into, the Terms of Service (the 'Agreement')" and never mentions the MSA. So
    "the Agreement" means the MSA in one document and the ToS in the other, and
    the DPA's own §14 ("this DPA prevails" over "the Agreement") resolves against
    a different parent than §1 of this page assumes.

  · TWO LIVE ENTIRE-AGREEMENT CLAUSES. terms.html §15 says the Terms + Privacy
    Policy + Terms of Use "constitute the entire agreement". MSA §14 says this
    Agreement + Order Forms + DPA + SLA "is the entire agreement". Neither list
    contains the other's members, and terms.html does not carve out signing
    customers. For a customer who has signed, both clauses are live and they
    contradict. terms.html's only mention of an MSA is in the FORUM clause
    ("absent a signed Order Form or MSA saying otherwise") — it never
    acknowledges being superseded generally.

  · §13 SURVIVES A SECTION THAT DOES NOT EXIST: "Sections 8 (Confidentiality),
    9 (IP), 12 (Liability), and 15 (Governing Law) survive termination." The
    document has FOURTEEN sections. Governing law is the first bullet of §14.
    Reproduced verbatim — a survival clause is not something to silently renumber.

Run:  pytest foxy-sale-page -q
"""

from __future__ import annotations

import pathlib
import re

import pytest

from conftest import POSTAL_ADDRESS

PAGE = "msa.html"
VERSION = "1.3"
REVIEWED = "8 August 2026"

HERE = pathlib.Path(__file__).resolve().parent


@pytest.fixture(scope="module")
def dom(legal_dom):
    return legal_dom(PAGE)


# ── 1. THE COMMITMENTS. EVERY ONE IS MONEY OR TIME. ──────────────────────────
def test_payment_is_due_in_thirty_days(dom):
    m = re.search(r"due within\s+(\d+)\s+days\s+of invoice date", dom.text)
    assert m, "the payment-terms sentence is gone or was restructured"
    assert m.group(1) == "30", f"payment terms changed to {m.group(1)} days"
    assert "invoiced monthly in advance" in dom.text
    assert "non-refundable except as expressly stated" in dom.text


def test_the_interest_rate_keeps_the_lesser_of(dom):
    """⚠ "THE LESSER OF" IS THE CUSTOMER'S PROTECTION.

    "interest at 1.5% per month" and "interest at the lesser of 1.5% per month or
    the maximum rate permitted by law" read almost identically and are not the
    same clause: without "the lesser of", the rate can exceed a statutory usury
    cap and the clause becomes harsher than drafted. The qualifier is asserted
    separately from the number so a failure names which half went missing."""
    m = re.search(r"interest at the lesser of\s*(?:<[^>]+>)?\s*([\d.]+)%\s*per month",
                  dom.src)
    assert m, ("the interest clause lost 'the lesser of', or the rate moved away "
               "from it — without that qualifier the rate is uncapped by law")
    assert m.group(1) == "1.5", f"the interest rate changed to {m.group(1)}%"
    assert "maximum rate permitted by law" in dom.text, \
        "the statutory ceiling that 'the lesser of' selects between is gone"


def test_suspension_needs_ten_days_notice_thirty_days_overdue_and_no_dispute(dom):
    """Three conditions, all of them the customer's protection. Any one dropped
    makes suspension easier, so each is asserted on its own."""
    t = dom.text
    m = re.search(r"suspend the Service on\s+(\d+)\s+days'\s+written notice", t)
    assert m, "the suspension sentence is gone or was restructured"
    assert m.group(1) == "10", f"suspension notice changed to {m.group(1)} days"
    m2 = re.search(r"payment more than\s+(\d+)\s+days overdue", t)
    assert m2 and m2.group(1) == "30", "the overdue threshold changed"
    assert "provided Customer has not disputed the invoice in good faith" in t, \
        "the 'unless disputed' qualifier is gone — suspension would now be " \
        "available against a disputed invoice"


def test_auto_renewal_gives_thirty_days_to_get_out(dom):
    m = re.search(r"notice of non-renewal at least\s+(\d+)\s+days\s+before", dom.text)
    assert m, "the non-renewal notice sentence is gone"
    assert m.group(1) == "30", f"the non-renewal window changed to {m.group(1)} days"
    assert "renews automatically for successive periods equal to the initial term" in dom.text


def test_material_breach_has_a_thirty_day_cure_period(dom):
    m = re.search(r"uncured material breach on\s+(\d+)\s+days'\s+written notice", dom.text)
    assert m, "the termination-for-breach sentence is gone"
    assert m.group(1) == "30", f"the cure period changed to {m.group(1)} days"
    assert "if the breach remains uncured at the end of that period" in dom.text, \
        "the clause no longer requires the breach to still be uncured — it would " \
        "now permit termination on notice alone"


def test_the_liability_window_is_twelve_months_with_its_three_carve_outs(dom):
    """§12 is the single largest number in the contract. The cap and the three
    exceptions to it are asserted separately: dropping a carve-out silently
    lowers Foxy Audit's exposure on indemnity or confidentiality."""
    t = dom.text
    m = re.search(r"IN THE\s+(\d+)\s+MONTHS PRECEDING THE CLAIM", t)
    assert m, "the liability cap sentence is gone or was restructured"
    assert m.group(1) == "12", f"the liability window changed to {m.group(1)} months"
    assert "FEES PAID OR PAYABLE BY CUSTOMER UNDER THE APPLICABLE ORDER FORM" in t, \
        "the cap's measuring base changed"
    for label, needle in [("(A) indemnification", "INDEMNIFICATION OBLIGATIONS UNDER SECTION 11"),
                          ("(B) confidentiality", "BREACH OF SECTION 8 (CONFIDENTIALITY)"),
                          ("(C) payment", "CUSTOMER'S PAYMENT OBLIGATIONS")]:
        assert needle in t, f"liability carve-out {label} was dropped"


def test_governing_law_keeps_its_order_form_escape_hatch(dom):
    t = dom.text
    assert "governed by the laws of the Islamic Republic of Pakistan" in t
    assert "without regard to conflict-of-laws principles" in t
    assert "unless the Order Form states otherwise" in t, \
        "governing law became unconditional — the Order Form can no longer vary it"


def test_the_survival_list_now_names_sections_that_exist(dom):
    """⚠ REPAIRED (#201b, OWNER DECISION 2026-08-14). L11 reproduced the defect
    and pinned it; this is the same guard re-aimed at the repair.

    §13 used to survive "Sections 8 (Confidentiality), 9 (IP), 12 (Liability),
    and 15 (Governing Law)". There is no Section 15 — the document ends at 14,
    and governing law is §14's first bullet. Renumbering a survival clause is
    not a conversion decision, which is why L11 refused to do it and why it took
    an owner decision.

    ⚠ THE NUMBER WAS VERIFIED AGAINST THE PAGE'S OWN HEADINGS, NOT THE .docx —
    and the heading disagrees with how the decision described it. The owner's
    note calls §14 "Governing Law"; the page calls it "General provisions", with
    governing law as its first bullet. The page wins, so the list reads "14
    (General provisions, including governing law)". Every assertion below
    re-derives the numbers from the headings rather than restating the string.

    See test_owner_divergences.py and the vault note it names."""
    t = dom.text
    headings = re.findall(r"<h2 id=\"s(\d+)\">(.*?)</h2>", dom.src)
    numbers = [n for n, _ in headings]
    assert numbers == [str(n) for n in range(1, 15)], \
        f"the section count changed: {numbers}"

    # ⚠ THE CITED NUMBERS ARE READ OUT OF THE CLAUSE AND CHECKED AGAINST THE
    # HEADINGS. A guard that asserted the finished sentence would be green by
    # construction and would not notice a NEW dangling number.
    clause = re.search(r"Sections ([^.]+?) survive termination", t)
    assert clause, "§13's survival clause is gone or was reworded past recognition"
    cited = re.findall(r"\b(\d+)\b(?=\s*\()", clause.group(1))
    assert cited == ["8", "9", "12", "14"], \
        f"the survival list cites {cited}; #201b settled 8, 9, 12, 14"
    assert "15" not in cited, (
        "the survival clause cites Section 15 again, which does not exist — "
        "#201b (owner decision 2026-08-14) renumbered it to 14")
    for n in cited:
        assert n in numbers, \
            f"§13 survives Section {n}, which the page has no heading for"

    # the label each number carries still matches the heading it points at
    titles = {n: h for n, h in headings}
    assert "General provisions" in titles["14"], \
        f"§14 is now titled {titles['14']!r} — re-check the survival clause's label"
    assert "General provisions, including governing law" in t, (
        "§13's label for Section 14 changed; it must name the heading the page "
        "actually has, not the .docx's 'Governing Law'")
    assert "Governing law:" in t, "governing law is still a §14 bullet, not a section"


# ── 2. THE PRECEDENCE CHAIN. EACH CHECK READS TWO DOCUMENTS. ─────────────────
def _text(legal_dom, page):
    return legal_dom(page).text


def test_the_precedence_clause_states_the_chain_in_order(dom):
    """The order is the whole clause. All four links present but permuted would
    be a different contract, so positions are compared rather than membership."""
    t = dom.text
    i = t.find("the order of precedence is:")
    assert i > 0, "§1 no longer states an order of precedence"
    tail = t[i:i + 260]
    at = []
    for link in ("Order Form", "then this Agreement", "then the DPA/SLA",
                 "then the public Terms of Service"):
        j = tail.find(link)
        assert j >= 0, f"the precedence chain lost the link {link!r}"
        at.append(j)
    assert at == sorted(at), f"the precedence chain was re-ordered: {at}"
    assert "which this Agreement supersedes for signing Customers" in t, \
        "the supersession clause — the reason the chain matters — was dropped"


def test_the_sla_scope_sentence_matches_this_pages_chain(legal_dom, dom):
    """⚠ THE GUARD L9's OPEN FINDING ASKED FOR, AND PUBLISHING THIS PAGE MAKES
    THAT FINDING SHARPER, NOT SOFTER.

    L9 established that sla.html reaches customers only through a signed Order
    Form — and that its §5 support tables are keyed by PLAN NAME (Pro, Max,
    Premium), which are the SELF-SERVE tiers. So a card-paying Pro customer reads
    "1 business hour" for a Sev 1 while the scope sentence says the SLA does not
    apply to them. §1 and §7 of this page are the incorporation that creates that
    gap.

    This ties the two sentences together so they cannot drift apart while the
    owner decides. The SLA is NOT edited here."""
    sla = _text(legal_dom, "sla.html")
    assert "Customers with an active paid Order Form referencing this SLA" in sla, \
        "sla.html's scope sentence changed — re-check it against msa.html §1"
    assert "incorporated by reference into the Master Service Agreement" in sla, \
        "sla.html no longer names the MSA as the agreement it is incorporated into"
    assert "does not apply to free-tier, trial, or evaluation use" in sla
    # the MSA side of the same joint
    assert "Service Level Agreement (SLA)</a></strong>, incorporated by reference" in dom.src
    assert "set out in the <a href=\"/sla.html\">SLA</a>, incorporated into this Agreement by reference" in dom.src
    # …and the contradiction L9 left open is still exactly as reported
    assert re.search(r"\bPro\b", sla) and re.search(r"\bMax\b", sla), \
        "the SLA support tables no longer key off self-serve plan names — the " \
        "L9 finding may be resolved; re-check it"


def test_refund_html_defers_to_a_signed_msa(legal_dom):
    """The link that HOLDS, pinned so it keeps holding."""
    refund = _text(legal_dom, "refund.html")
    assert "If you have a signed Master Service Agreement" in refund
    assert "that agreement's terms govern instead of this page" in refund, \
        "refund.html no longer defers to the MSA — that contradicts msa.html §1"


def test_the_dpa_and_the_msa_now_agree_on_the_parent(legal_dom, dom):
    """⚠ FIXED (#201c, OWNER DECISION 2026-08-14). L11's guard pinned the
    disagreement; this is it re-aimed at the agreement.

    MSA §1(b) and §6 incorporate the DPA INTO THE MSA. dpa.html used to say it
    was incorporated into the TERMS OF SERVICE and never mentioned the MSA. Both
    documents then defined "the Agreement" as their own parent, so dpa.html §14
    ("this DPA prevails" over "the Agreement") resolved against a different
    document depending on which page you were reading. The DPA's parent is now
    the MSA, matching the two clauses that were already there.

    See test_owner_divergences.py and the vault note it names."""
    dpa = _text(legal_dom, "dpa.html")
    assert "forms part of, and is incorporated by reference into, the Master Service Agreement" in dpa, \
        "dpa.html's parent clause changed — #201c settled it on the MSA"
    assert "incorporated by reference into, the Terms of Service" not in dpa, (
        "dpa.html names the Terms of Service as its parent again, which "
        "contradicts MSA §1(b) and §6")
    # ⚠ THE SELF-SERVE HALF. A customer who never signed an MSA still needs a
    # parent, and the decision required the DPA to say which one.
    assert "Where Customer has not signed a Master Service Agreement" in dpa, \
        "the DPA no longer says how a self-serve customer reaches it"
    assert '"the Agreement" means those Terms' in dpa, \
        "the DPA stopped defining 'the Agreement' for self-serve customers"
    # the MSA's side, which never moved
    assert "Data Processing Agreement (DPA)</a></strong>, incorporated by reference" in dom.src
    assert "governed by the <a href=\"/dpa.html\">DPA</a>, incorporated into this Agreement by reference" in dom.src


def test_the_two_precedence_clauses_no_longer_contradict_each_other(legal_dom, dom):
    """⚠ THE HALF #201c's OWN WARNING POINTED AT, AND IT DID NOT RESOLVE ITSELF.

    Re-parenting the DPA to the MSA put two precedence rules in direct conflict
    for the first time: MSA §1 ranks "Order Form, then this Agreement, then the
    DPA/SLA", while DPA §14 says the DPA prevails over "the Agreement". Under
    the old parent those two never met, because §14 resolved against the ToS.

    Neither clause was dropped. §14 is now stated as the express exception to
    §1's ladder, and §1 names the exception, so a reader arriving from either
    page gets the same answer: the DPA wins on the processing of personal data,
    the MSA wins on everything else.

    ⚠ BOTH SIDES ARE ASSERTED. One-sided wording is what created the defect."""
    dpa, msa = _text(legal_dom, "dpa.html"), dom.text
    assert ("In the event of a conflict between this DPA and the Agreement "
            "regarding the processing of personal data, this DPA prevails") in dpa, \
        "DPA §14's operative rule changed"
    assert "express exception to the general order of precedence" in dpa, (
        "DPA §14 no longer reconciles itself with MSA §1's ladder, so the two "
        "clauses compete again")
    assert "on every other subject matter that order governs" in dpa, \
        "DPA §14 stopped conceding everything outside data protection to the MSA"
    assert ("except that on the processing of personal data the DPA prevails "
            "over this Agreement") in msa, (
        "MSA §1's ladder no longer carries the carve-out, so it reads as ranking "
        "the MSA above the DPA without qualification")
    assert 'href="/dpa.html#s14"' in dom.src, \
        "MSA §1 names the exception but no longer links the clause that states it"


def test_terms_html_now_yields_to_the_msa_in_its_entire_agreement_clause(legal_dom, dom):
    """⚠ FIXED (#201a, OWNER DECISION 2026-08-14). L11 called this the sharpest
    of the four findings; this is its guard re-aimed at the fix.

    msa.html §1 says it supersedes the public Terms for signing Customers.
    terms.html used to mention an MSA exactly once, and only about the FORUM —
    its §15 entire-agreement clause named a different set of documents and
    carved out nobody. Two live entire-agreement clauses with non-overlapping
    membership is the first thing a counterparty's lawyer marks up. §15 now
    carries the carve-out, so only one of them is live for any given customer.

    ⚠ ASSERTED INSIDE §15, NOT PAGE-WIDE. The forum sentence in §14 already said
    "absent a signed Order Form or MSA", so a page-level search for "MSA" was
    answered by a clause that does not govern the entire agreement at all. Both
    mentions are pinned, each to its own section.

    See test_owner_divergences.py and the vault note it names."""
    dom_terms = legal_dom("terms.html")
    terms = dom_terms.text
    # ⚠ LegalDom, NOT A NAIVE STRIP. The negative assertions below ("govern
    # instead" / "entire agreement" must NOT appear) go silently green if the
    # phrase is split by an inline tag, because a stripper that spaces every tag
    # turns `<em>govern</em> instead` into "govern  instead". conftest exists to
    # get this right; for a NEGATIVE assertion the naive version fails open.
    from conftest import LegalDom
    s15 = LegalDom(dom_terms.section(15)).text

    assert "constitute the entire agreement" in s15, \
        "terms.html's entire-agreement clause left §15"
    assert ("For customers with a signed Master Service Agreement, that agreement "
            "and its Order Forms govern in place of these Terms") in s15, (
        "terms.html §15 no longer yields to the MSA, so two entire-agreement "
        "clauses compete again (#201a)")
    assert "govern instead" not in s15, (
        "§15's carve-out is unqualified again — 'govern instead' displaces the "
        "Privacy Policy and Terms of Use too, which msa.html §1 does not do")
    # ⚠ SCOPED TO §15. A page-wide check would be satisfied by any other MSA link
    # the page acquires — and §15 is the clause whose carve-out needs the anchor.
    assert 'href="/msa.html"' in dom_terms.section(15), \
        "terms.html §15 names the MSA but no longer links it from the carve-out"

    # ⚠ THE §14 MENTION IS A DIFFERENT CLAUSE ABOUT A DIFFERENT THING. Pinned so
    # a future edit cannot satisfy #201a by rewording the forum sentence.
    s14 = LegalDom(dom_terms.section(14)).text
    assert "absent a signed Order Form or MSA saying otherwise" in s14, \
        "the forum sentence's MSA mention moved or changed"
    assert "entire agreement" not in s14, \
        "§14 grew an entire-agreement clause; there must be exactly one, in §15"

    # the MSA's side of the relationship, which never moved
    assert "is the entire agreement between the parties regarding the Service" in dom.text, \
        "msa.html's entire-agreement clause changed"
    assert "which this Agreement supersedes for signing Customers" in dom.text, \
        "msa.html §1 stopped claiming supersession — #201a's carve-out answers it"


def test_the_service_definition_this_page_cites_does_not_say_what_it_claims(legal_dom, dom):
    """⚠ REPORTED, NOT FIXED. A signed contract's scope-of-service points at a
    public section that defines the Service differently.

    §2: "as defined in the Terms of Service Section 2 (the dashboard, API, SDK,
    and desktop application)". Measured: NONE of those four words appear in
    terms.html §2. It defines the Service by capability instead, and is silent on
    the staff administrative console that §2 here expressly excludes.

    The link is still rendered and still lands on §2 — pointing a reader at the
    section the contract cites is correct; that they disagree is the finding."""
    assert '<a href="/terms.html#s2">Terms of Service Section 2</a>' in dom.src, \
        "the citation is no longer a link that lands on the section it names"
    assert "s2" in legal_dom("terms.html").ids, "terms.html has no #s2 to land on"

    src = (HERE / "terms.html").read_text(encoding="utf-8")
    m = re.search(r'<h2 id="s2">(.*?)(?=<h2\b)', src, re.S)
    assert m, "terms.html §2 could not be isolated — the heading structure changed"
    s2 = re.sub(r"\s+", " ", re.sub(r"<[^>]+>", " ", m.group(1)))
    for word in ("dashboard", "API", "SDK", "desktop"):
        assert word.lower() not in s2.lower(), (
            f"terms.html §2 now contains {word!r} — the two definitions may have "
            "been reconciled; re-check the L11 finding")
    assert "tamper-evident audit ledger" in s2, "terms.html §2's own definition changed"
    # and this page still makes the claim it makes
    assert "(the dashboard, API, SDK, and desktop application)" in dom.text
    assert "does not include Foxy Audit's internal staff administrative console" in dom.text


def test_the_three_liability_caps_govern_three_different_relationships(legal_dom, dom):
    """Different caps for different relationships is correct. What would be wrong
    is two documents capping the SAME relationship at different numbers, so each
    cap is pinned together with the relationship it names.

      · msa.html §12         signed customers    fees under the ORDER FORM, 12 months
      · terms.html §11       self-serve          amounts PAID US for the Service, 12 months
      · terms-of-use.html §9 site visitors       greater of what you paid to access
                                                 THE SITE ITSELF, or a nominal USD $100

    They do not overlap: the MSA measures Order Form fees, the ToS measures
    self-serve payments and is superseded for signing customers, and the ToU
    measures access to the marketing site rather than the Service."""
    terms = _text(legal_dom, "terms.html")
    tou = _text(legal_dom, "terms-of-use.html")

    assert "UNDER THE APPLICABLE ORDER FORM IN THE 12 MONTHS PRECEDING THE CLAIM" in dom.text
    m = re.search(r"limited to the amounts you paid us for the Service in the "
                  r"twelve \((\d+)\) months preceding", terms)
    assert m and m.group(1) == "12", "terms.html's cap changed — re-compare the three"
    # ⚠ RE-AIMED IN L14. This read "A NOMINAL SUM SUCH AS ONE HUNDRED..." because
    # that is what the .docx says. #187 removed "such as": an illustrative cap does
    # not state its own amount. The figure and the two-limb structure are still
    # pinned; only the illustrative hedge is gone. See test_owner_divergences.py.
    m2 = re.search(r"GREATER OF \(A\) THE AMOUNT, IF ANY, YOU PAID US TO ACCESS "
                   r"THE SITE ITSELF, OR \(B\) ONE HUNDRED "
                   r"U\.S\. DOLLARS \(USD \$(\d+)\)", tou)
    assert m2 and m2.group(1) == "100", \
        "terms-of-use.html's cap changed — #187 states it as a figure; re-compare"
    assert "SUCH AS" not in tou.upper(), \
        "the site cap is illustrative again (#187)"
    # the relationship each names is what keeps them from colliding
    assert "ORDER FORM" in dom.text, "the MSA cap stopped naming the Order Form"
    assert "you paid us for the Service" in terms, "the ToS cap stopped naming the Service"
    assert "TO ACCESS THE SITE ITSELF" in tou, "the ToU cap stopped naming the site"


# ── 3. CONTACT DETAILS: THE ABSENCE IS THE FINDING (#200, SECOND TIME) ───────
def test_the_notice_address_is_the_legal_mailbox_and_nothing_else(dom):
    """⚠ THE GAP IS CLOSED (#200, OWNER DECISION 2026-08-14) — BUT ONLY BY ONE
    ADDRESS. L11 reported an email, a phone and a postal address all missing
    while §3 requires 10 days' WRITTEN NOTICE of suspension and §13 requires 30
    days' WRITTEN NOTICE of breach. The owner authorised the mailbox from the
    documents' own map (legal@ for contracts) and NOTHING ELSE.

    So this guard did not become weaker: it kept every prohibition it had and
    replaced one of them with an exact-match requirement. A postal address is
    still a fabrication — none is decided — and so is a phone number.

    ⚠ THE ADDRESS IS ASSERTED AS AN EXACT SET, not a substring. "an email
    appeared" and "the RIGHT email appeared" are different claims, and a
    substring check passes for both legal@ and legal@foxyaudit.tech.example.

    See test_owner_divergences.py and the vault note it names."""
    text, src = dom.text, dom.src
    assert dom.addresses == {"legal@foxyaudit.tech"}, \
        f"unexpected addresses: {dom.addresses} — #200 authorised legal@ alone"
    # ⚠ THE TRAILING PERIOD IS SENTENCE PUNCTUATION, NOT PART OF THE ADDRESS —
    # conftest's own docstring names this trap, and this guard walked into it:
    # the naive pattern matched "legal@foxyaudit.tech." and reported an
    # unauthorised mailbox. dom.addresses (parsed from the href) is the
    # authority; this sweep exists only to catch an address in PROSE that never
    # became a link, so it is normalised the way a reader would read it.
    found = {a.rstrip(".") for a in re.findall(r"[\w.+-]+@[\w-]+\.[\w.]+", text)}
    assert found == {"legal@foxyaudit.tech"}, \
        f"an unauthorised email address appeared in the MSA text: {found}"
    assert "written notice to Foxy Audit under this Agreement" in text, \
        "the notices provision lost the sentence that makes the address operative"
    assert not re.search(r"\+\d[\d\s()-]{7,}", text), "a phone number appeared"
    assert not POSTAL_ADDRESS.search(text), "a postal address appeared"
    assert "gmail.com" not in src.lower(), "a personal mailbox is published"


def test_the_entity_line_survived(dom):
    """The stray space before the comma in the source ("FOXY AUDIT , a company")
    is the document's one whitespace artifact; it is normalised here the way the
    sibling pages render the same entity. The NAME is character-for-character."""
    assert "FOXY AUDIT, a company incorporated in the Islamic Republic of Pakistan" in dom.text
    assert "FOXY AUDIT ," not in dom.text, "the stray space before the comma survived"


def test_no_fee_rate_or_plan_was_invented(dom):
    """The MSA states fees are "as stated in the applicable Order Form" and names
    no figure. The only percentage in the document is the interest rate."""
    t = dom.text
    assert "Fees are as stated in the applicable Order Form" in t
    assert not re.search(r"(?:USD|\$|PKR|€|£)\s?\d", t), \
        f"a currency figure appeared: {re.findall(r'(?:USD|[$€£])\s?[\d,]+', t)}"
    assert re.findall(r"\d+(?:\.\d+)?%", t) == ["1.5%"], \
        f"a percentage other than the interest rate appeared: {re.findall(r'[\d.]+%', t)}"


# ── 4. #179, WITH AN HONEST ACCOUNT OF WHAT THE EVIDENCE SUPPORTS ────────────
DASH, ENDASH = "—", "–"


def test_no_dash_was_invented_in_the_operative_text(dom):
    """⚠ THREE METHODS, AND A CONTROL THE BRIEF SAID I DID NOT HAVE.

    (a) READING: the document is comma-and-parenthesis drafted throughout. The
        two constructions a dash might have carried — "(the dashboard, API, SDK,
        and desktop application) which, for the avoidance of doubt, ..." and
        "Service credits, if any, are ..." — both read correctly as punctuated.

    (b) THE v1.0 DIFF: v1.0 has two doubled spaces, both collapsed in v1.3.
        Neither is dash damage. One is "invoiced monthly  in advance", where a
        dash would be ungrammatical; the other is "Foxy Audit  Customer", which
        is two SIGNATURE-TABLE CELLS flattened into one string. v1.0 also has
        zero em-dashes and zero en-dashes.

    (c) THE SWEEP found no bare appositive, no "X, not Y" contrast, no gap.

    ⚠ THE CONTROL. The brief is right that this document has no en-dash to prove
    the pipeline preserves dashes. But the question that matters — "is the zero
    real, or did my extractor eat them?" — is answerable: the same extractor run
    over the same batch of twelve .docx files recovers 49 em-dashes (23 in the
    Privacy Policy alone) and 3 en-dashes. So the zero here is a property of the
    document. What remains unprovable is whether the AUTHORING pipeline lost
    dashes before v1.0, and nothing in this document suggests it did.

    NOTHING WAS RESTORED. The only em-dashes on the page are the four in the
    Document-details list, which is the shared page template, not the contract."""
    # ⚠ SCOPE FROM THE FIRST SECTION HEADING, NOT FROM A CARD BOUNDARY. The
    # first cut of this guard split on '<div class="card">' and picked up the
    # Document-details card, whose .meta list uses "label — value" and is page
    # template rather than contract. A window is not a scope: it was measuring
    # the neighbouring block and failing on it.
    i = dom.src.index('<h2 id="s1">')
    j = dom.src.index('<div class="foot">')
    operative = re.sub(r"\s+", " ", re.sub(r"<[^>]+>", " ", dom.src[i:j]))
    assert "1. Structure" in operative and "General provisions" in operative, \
        "the operative-text window no longer covers the contract"
    assert "Document title" not in operative, \
        "the window swallowed the Document-details card again"
    assert DASH not in operative, \
        f"an em-dash appeared in the operative text: {[operative[max(0,i-60):i+40] for i in [operative.index(DASH)]]}"
    assert ENDASH not in dom.text, "an en-dash appeared; the source has none"
    assert dom.text.count(DASH) == 4, \
        f"the em-dash count changed to {dom.text.count(DASH)} (4 = the .meta template)"


def test_no_whitespace_gap_survived(dom):
    assert "  " not in dom.text, "a doubled space is on the page"
    assert not re.search(r"\s+[,;:]", dom.text), "a space before punctuation survived"


# ── 5. THE PAGE ITSELF ───────────────────────────────────────────────────────
def test_the_page_states_the_version_and_review_date_the_document_carries(dom):
    assert re.search(rf"Version\s*{re.escape(VERSION)}\b", dom.text)
    assert REVIEWED in dom.text, "the review date changed"
    assert not re.search(r"\b1\.[0-2]\b", dom.text), "a superseded version number is on the page"


def test_the_signature_block_is_present_and_unfilled(dom):
    """The document is a signable template. The block is rendered because it is
    part of the document, but it must stay a static reproduction — no form, no
    input, and no name or date filled in on a public page."""
    t = dom.text
    assert t.count("By: _________________________") == 2, "a signature line is missing"
    assert t.count("Name:") == 2 and t.count("Title:") == 2 and t.count("Date:") == 2
    assert not re.search(r"<(?:form|input|button|textarea)\b", dom.src), \
        "the signature block became an interactive form"
    # ⚠ MEASURE THE MARKUP, NOT THE FLATTENED TEXT. The first cut asserted
    # `Name:\s*\w` was absent from dom.text and failed on the document's own
    # "Name: Title:" — flattening puts the NEXT label right after the colon, so
    # the check could never distinguish a filled field from an empty one. Each
    # label is its own <li>, so the empty ones are empty in the source.
    for label in ("Name:", "Title:", "Date:"):
        cells = re.findall(rf"<li>{label}(.*?)</li>", dom.src)
        assert len(cells) == 2, f"expected 2 {label!r} lines, found {len(cells)}"
        assert all(not c.strip() for c in cells), \
            f"the signature block has a filled-in {label!r}: {cells}"


def test_no_external_url_is_reachable_from_the_markup(dom):
    urls = re.findall(r"https?://[^\s\"'<>)]+",
                      re.sub(r"base64,[A-Za-z0-9+/=]+", "", dom.src))
    assert not urls, f"the MSA reaches off-site: {urls}"


def test_the_embedded_faces_are_the_ones_the_siblings_ship(dom):
    pat = r"font-weight:(\d+);font-display:swap;src:url\(data:font/woff2;base64,([A-Za-z0-9+/=]+)\)"
    mine = dict(re.findall(pat, dom.src))
    sibling = dict(re.findall(pat, (HERE / "dpa.html").read_text(encoding="utf-8")))
    assert set(mine) == {"600", "700"} and mine == sibling, \
        "the embedded Poppins faces differ from dpa.html's"


def test_every_in_page_anchor_lands_on_something(dom):
    for href in re.findall(r'href="#([^"]+)"', dom.src):
        assert href in dom.ids, f"in-page link #{href} lands nowhere"


def test_the_contents_list_matches_the_sections(dom):
    toc = re.findall(r'<li><a href="#s(\d+)">([^<]+)</a></li>', dom.src)
    heads = re.findall(r'<h2 id="s(\d+)">(\d+)\. ([^<]+)</h2>', dom.src)
    assert [n for n, _ in toc] == [n for n, _, _ in heads], \
        "the contents list and the section headings disagree"
    for (n, label), (_, _, head) in zip(toc, heads):
        assert label.lower() == head.lower().rstrip(), \
            f"contents entry {n} says {label!r}, the section says {head!r}"
