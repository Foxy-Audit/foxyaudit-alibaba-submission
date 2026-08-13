"""The Order Form: explained in msa.html, deliberately NOT published. (L12)

THE DECISION, AND WHY.

Foxy-Audit-Order-Form-v1.1.docx is not a policy. It is a blank contract
template: 1,661 characters, of which ELEVEN are unfilled brackets —

    [fill in] · [name, email] · [date] · [e.g., 12 months from Effective Date]
    [Pro / Max / Premium] · [log volume, seats, features ...] · [$ amount]
    [Monthly / Annually] · [For enterprise customers invoiced outside Paddle's
    standard checkout, specify invoicing terms here ...] · [Pro, or Max/Premium,
    per SLA Section 5] · [Any negotiated deviation ... goes here]

— above two blank signature lines. Published as a page it would read
"Customer legal name: [fill in]" and "Fee: [$ amount]", which is
indistinguishable from an unfinished page. The site already carries one artefact
of that kind (the DPA's "Effective date set when first executed", #200) and that
is one too many. Filling any bracket would mean inventing a fee, a plan, a term
or a customer, and the standing rule is that no fake data ships.

There was also a structural reason a legal.html card was not an option: #199
pins the card set EQUAL to test_legal_pages_rendered.PAGES, so a card without a
page fails by construction. That is the cross-pin working, not an obstacle.

WHAT SHIPPED INSTEAD. msa.html §1 makes the Order Form the highest-precedence
document in the contract, and until now the site named it eleven times and
defined it nowhere. msa.html now carries an explanatory note, placed before §1
where a reader first meets the term, visually marked as editorial and outside
the contract's own numbering. Every sentence in it is traceable to MSA §1, §4,
§6, §7 or §14, or to sla.html's scope sentence. Those citations are asserted
below, in BOTH documents, so the note cannot quietly outlive what it cites.

WHAT THE TEMPLATE'S OWN CITATIONS TURNED OUT TO BE (all three verified):

  · "per the plan description at foxyaudit.tech/pricing" — HOLDS. pricing.html
    exists, lists Pro ($49), Max ($199) and Premium ("Let's talk"), and states
    credits, seats and features. Checked live by BODY, not status: both
    /pricing and /pricing.html return the real page, not the homepage (#a-200-
    means-nothing).
  · "per Terms of Service Section 6" — HOLDS. terms.html §6 is "Plans, Billing
    & Quotas" and opens "Billing and merchant of record. Paid plans are sold
    through Paddle.com Market Ltd". Unlike the MSA §2 citation L11 found, this
    one lands on a section that says what cites it.
  · "Support tier: [Pro, or Max/Premium, per SLA Section 5]" — HOLDS as a
    citation, and is the evidence #201 needed. See the guard below.

Run:  pytest foxy-sale-page -q
"""

from __future__ import annotations

import pathlib
import re

import pytest

HERE = pathlib.Path(__file__).resolve().parent


@pytest.fixture(scope="module")
def msa(legal_dom):
    return legal_dom("msa.html")


def _note(src: str) -> str:
    """The editorial note only, brace-matched by card boundary — NOT a loose
    window. A window is not a scope; the contract begins in the very next card
    and would satisfy half of these assertions on its own."""
    i = src.index('<div class="card note">')
    j = src.index('<div class="card">', i)
    return src[i:j]


# ── 1. THE DECISION ITSELF ───────────────────────────────────────────────────
def test_the_blank_template_was_not_published():
    """Asserted as an absence with a reason attached, so re-opening the decision
    is deliberate rather than accidental."""
    assert not (HERE / "order-form.html").is_file(), (
        "an order-form.html exists. L12 decided against publishing the blank "
        "template; if that is being overturned, the bar is that every one of the "
        "eleven brackets goes without anything being invented to fill it, and the "
        "page reads as a labelled specimen rather than a form")


def test_no_bracket_placeholder_reached_any_page():
    """⚠ THE FAILURE MODE THIS PHASE EXISTS TO AVOID. If any of the template's
    fill-in markers ever appears on a published page, it will look like an
    unfinished page rather than a contract awaiting signature."""
    MARKERS = [r"\[fill in\]", r"\[\$ ?amount\]", r"\[date\]", r"\[name, ?email\]",
               r"\[Monthly ?/ ?Annually\]", r"\[Pro ?/ ?Max ?/ ?Premium\]",
               r"\[e\.g\.,", r"goes here\]"]
    for page in sorted(HERE.glob("*.html")):
        text = re.sub(r"base64,[A-Za-z0-9+/=]+", "", page.read_text(encoding="utf-8"))
        for m in MARKERS:
            assert not re.search(m, text, re.I), \
                f"{page.name} contains the Order Form placeholder {m!r}"


def test_the_legal_index_did_not_grow_a_card_without_a_page():
    """#199 in its own right: the card set is pinned EQUAL to the rendered sweep,
    so an 'Order Form' card would have had to ship a page with it. Restated here
    because it is the structural reason the note went into msa.html instead."""
    carded = {h.split("#")[0] for h in re.findall(
        r'<a class="gcard" href="/([^"]+)"',
        (HERE / "legal.html").read_text(encoding="utf-8"))}
    assert "order-form.html" not in carded
    import test_legal_pages_rendered as rendered
    assert carded == set(rendered.PAGES), \
        "the legal index and the rendered sweep drifted apart"


# ── 2. THE EXPLANATION, AND EVERY SECTION IT LEANS ON ────────────────────────
def test_the_note_exists_and_is_marked_as_not_being_the_contract(msa):
    """It sits inside a contract. If a reader cannot tell the difference between
    Foxy Audit's explanation and the terms they are signing, the note is worse
    than nothing."""
    note = _note(msa.src)
    assert '<h2 id="order-form">About Order Forms</h2>' in note
    assert "A note from Foxy Audit. Not part of the Agreement." in note, \
        "the note lost the line saying it is not contract text"
    assert 'class="card note"' in note, "the note lost its distinguishing style"
    # …and it must NOT be numbered as, or listed among, the contract's sections
    assert not re.search(r'<h2 id="s\d+">About Order Forms', msa.src)
    toc = re.findall(r'<li><a href="#([^"]+)">', msa.src)
    assert "order-form" not in toc, \
        "the note was added to the contract's Contents list, which numbers sections"


def test_the_note_precedes_the_contract_and_not_the_other_way_round(msa):
    """Position is the point: the reader meets 'Order Form' in §1's first
    sentence, so the explanation has to arrive before it. It also keeps the note
    outside the operative-text window that L11's dash guard measures."""
    assert msa.src.index('id="order-form"') < msa.src.index('<h2 id="s1">'), \
        "the note moved after the contract begins"


@pytest.mark.parametrize("claim, cited, needle", [
    ("an Order Form specifies plan, fees and term",
     "s1", "specifying the subscribed plan, fees, and term"),
    ("the Order Form outranks this Agreement",
     "s1", "the order of precedence is: Order Form, then this Agreement"),
    ("it supersedes the public Terms only for signing Customers",
     "s1", "which this Agreement supersedes for signing Customers"),
    ("30 days' notice of non-renewal",
     "s4", "notice of non-renewal at least <strong>30 days</strong>"),
    ("the DPA is incorporated",
     "s6", "governed by the <a href=\"/dpa.html\">DPA</a>, incorporated into this Agreement"),
    ("the SLA is incorporated",
     "s7", "set out in the <a href=\"/sla.html\">SLA</a>, incorporated into this Agreement"),
    ("governing law yields to the Order Form",
     "s14", "unless the Order Form states otherwise"),
])
def test_every_section_the_note_cites_still_says_what_the_note_says(msa, claim, cited, needle):
    """⚠ THE NOTE IS A SUMMARY OF SECTIONS THAT COULD CHANGE UNDER IT.

    Each row asserts BOTH that the note points at the section AND that the
    section still carries the sentence the note is summarising. A summary whose
    source has moved on is worse than no summary: it reads with the contract's
    authority and none of its accuracy."""
    note = _note(msa.src)
    assert f'href="#{cited}"' in note, f"the note stopped citing #{cited} for: {claim}"
    # ⚠ MEASURE THE CONTRACT, NOT THE NOTE. Found by mutation: deleting
    # ", unless the Order Form states otherwise" from §14 left this green,
    # because the NOTE quotes that exact phrase. The guard was reading the
    # summary back to itself and calling it corroboration — precisely the
    # failure it exists to catch. The note is excised before searching.
    contract = msa.src.replace(note, "")
    assert needle not in note or needle in contract, "internal: excision failed"
    assert needle in contract, \
        f"MSA #{cited} no longer says what the note claims — {claim}"


def test_the_note_matches_the_slas_own_scope_sentence(msa, legal_dom):
    """The note tells a reader the SLA reaches them only through an Order Form.
    That is the SLA's sentence, not ours, so it is pinned in both places."""
    note = _note(msa.src)
    assert "customers with an active paid Order Form referencing it" in note
    assert "not to free-tier, trial, or evaluation use" in note
    sla = legal_dom("sla.html").text
    assert "Customers with an active paid Order Form referencing this SLA" in sla, \
        "sla.html's scope sentence changed — the msa.html note now paraphrases " \
        "something the SLA no longer says"
    assert "does not apply to free-tier, trial, or evaluation use" in sla


def test_the_note_invents_no_process_price_or_contact(msa):
    """⚠ NOTHING WAS ADDED. The template's brackets are the things a salesperson
    fills in; the note explains what an Order Form IS without inventing how one
    is obtained. No quote flow, no turnaround, no sales address, no figure."""
    note = _note(msa.src)
    text = re.sub(r"\s+", " ", re.sub(r"<[^>]+>", " ", note))
    for invented in (r"request a quote", r"contact sales", r"get in touch",
                     r"reach out", r"within \d+ (?:business )?(?:days|hours)",
                     r"our sales team", r"schedule a call"):
        assert not re.search(invented, text, re.I), \
            f"the note invented a process: {invented!r}"
    assert not re.search(r"[\w.+-]+@[\w-]+\.[\w.]+", text), "the note invented an email"
    assert not re.search(r"[$€£]\s?\d", text), "the note invented a figure"
    # ⚠ EVERY NUMBER MUST EARN ITS PLACE. The first cut of this asserted an
    # ordered literal of the digits I expected — which both restated the
    # implementation and was in the wrong order. The real invariant is that the
    # note contains no quantity of its own: each number is either the text of a
    # section link, or the 30-day notice period MSA §4 states.
    section_refs = set(re.findall(r'<a href="#s\d+">(\d+)</a>', note))
    section_refs |= set(re.findall(r'<a href="#s(\d+)">Section \1</a>', note))
    allowed = section_refs | {"30"}
    found = set(re.findall(r"\b\d+\b", text))
    assert found <= allowed, (
        f"the note states a quantity that is neither a section reference nor MSA "
        f"§4's notice period: {sorted(found - allowed)}")
    assert "30" in found, "the note lost the notice period it summarises"
    assert section_refs, "the note stopped linking any section — it cites nothing"


# ── 3. WHAT THE TEMPLATE CITES, VERIFIED ON THE PAGES IT CITES ──────────────
def test_pricing_substantiates_the_plans_the_order_form_selects(legal_dom):
    """The template's Plan row points at foxyaudit.tech/pricing "as of the
    Effective Date" for log volume, seats and features. If that page did not name
    those three plans, the Order Form would point at a page that cannot
    substantiate the thing being sold. It does."""
    page = HERE / "pricing.html"
    assert page.is_file(), "pricing.html is gone; the Order Form's Plan row cites it"
    text = re.sub(r"\s+", " ", re.sub(r"<[^>]+>", " ",
                  re.sub(r"<(style|script)\b.*?</\1>", " ",
                         page.read_text(encoding="utf-8"), flags=re.S)))
    for plan in ("Pro", "Max", "Premium"):
        assert re.search(rf"\b{plan}\b", text), f"pricing.html no longer names {plan}"
    for detail in ("credits", "seats"):
        assert detail in text.lower(), f"pricing.html stopped stating {detail}"
    assert "$49" in text and "$199" in text, "the published prices changed"
    # Premium carries no figure — it is the one negotiated on an Order Form, and
    # pricing.html says so itself. That is consistent, not a gap.
    assert "Invoiced directly, not through the card checkout" in text, \
        "pricing.html no longer says Premium is invoiced outside the card checkout"


def test_terms_section_six_is_the_paddle_section_the_order_form_names(legal_dom):
    """⚠ L11 FOUND THE MSA CITING A SECTION THAT SAID SOMETHING ELSE, so this
    citation was checked the same way rather than assumed. It holds."""
    src = (HERE / "terms.html").read_text(encoding="utf-8")
    m = re.search(r'<h2 id="s6">(.*?)(?=<h2\b)', src, re.S)
    assert m, "terms.html §6 could not be isolated"
    s6 = re.sub(r"\s+", " ", re.sub(r"<[^>]+>", " ", m.group(1)))
    assert "Plans, Billing" in s6, f"terms.html §6 is no longer the billing section: {s6[:80]}"
    # ⚠ ASSERT THE CLAUSE, NOT THE WORD. Found by mutation: rewriting "sold
    # through Paddle.com Market Ltd" to "sold through our reseller" left a bare
    # `"Paddle" in s6` green, because §6 names Paddle six times elsewhere. A
    # membership test on a word that appears throughout a section proves nothing
    # about the sentence being cited.
    assert "sold through Paddle.com Market Ltd" in s6, \
        "terms.html §6 no longer names Paddle as the seller of paid plans"
    assert "merchant of record for" in s6.lower(), \
        "terms.html §6 no longer states the merchant-of-record arrangement"


def test_the_support_tier_evidence_for_the_open_scope_finding(legal_dom):
    """⚠ THE MOST USEFUL THING THIS PHASE PRODUCED — evidence for #201.

    L9 found sla.html §5 keys support off PLAN NAMES (Pro / Max / Premium) while
    the SLA's scope sentence limits it to Order Form customers, so a card-paying
    Pro reads "1 business hour" for a Sev 1. It was unclear which side was wrong.

    The Order Form template answers it. Its own SLA row reads "Support tier:
    [Pro, or Max/Premium, per SLA Section 5]" — the Order Form SELECTS a plan
    name and defers to §5 to resolve it. So §5 is plan-keyed BY DESIGN, and
    re-keying it to "Order Form customers" would break the document that points
    at it.

    The collision is not in §5. It is that pricing.html sells Pro and Max to
    self-serve card customers under the SAME THREE NAMES the Order Form uses. The
    names are overloaded across two populations, and only one of them is in
    scope. Premium is the tell: pricing.html already says it is "Invoiced
    directly, not through the card checkout", i.e. inherently an Order Form
    customer — while Pro and Max are one-click purchases.

    This guard pins the three facts that make that argument, so the evidence is
    still there when the owner settles it."""
    sla_src = (HERE / "sla.html").read_text(encoding="utf-8")
    m = re.search(r'<h2 id="s5">(.*?)(?=<h2\b)', sla_src, re.S)
    assert m, "sla.html §5 could not be isolated"
    s5 = re.sub(r"\s+", " ", re.sub(r"<[^>]+>", " ", m.group(1)))

    # (1) §5 keys off plan names, and mentions no Order Form at all
    for plan in ("Pro", "Max", "Premium"):
        assert re.search(rf"\b{plan}\b", s5), f"SLA §5 stopped naming {plan}"
    assert "Order Form" not in s5, (
        "SLA §5 now mentions the Order Form — the #201 finding may have been "
        "resolved from this side; re-read the L12 report before trusting it")

    # (2) the scope sentence still limits the SLA to Order Form customers
    sla_text = re.sub(r"\s+", " ", re.sub(r"<[^>]+>", " ", sla_src))
    assert "Customers with an active paid Order Form referencing this SLA" in sla_text

    # (3) pricing.html still sells two of those same names self-serve
    pricing = re.sub(r"\s+", " ", re.sub(r"<[^>]+>", " ",
                     (HERE / "pricing.html").read_text(encoding="utf-8")))
    assert re.search(r"Pro \$49", pricing) or "$49" in pricing, \
        "pricing.html no longer sells Pro for a listed price — the overlap that " \
        "creates #201 may be gone; re-check the finding"
    assert "$199" in pricing, "pricing.html no longer sells Max for a listed price"
