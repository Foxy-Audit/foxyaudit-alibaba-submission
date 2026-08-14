"""sla.html — Service Level Agreement v1.4. THE FIRST PAGE HERE THAT PROMISES MONEY.

Every number below is a commitment someone can hold the company to, so each is
guarded on its own — a mutation that moves a percentage between bands, or 30
days to 60, has to fail on its own line rather than being absorbed by a
paragraph-level check.

WHO IT APPLIES TO — the document answers this itself, twice:

    "Applies to: Customers with an active paid Order Form referencing this SLA"
    "…incorporated by reference into the Master Service Agreement between Foxy
     Audit and Customer. It does not apply to free-tier, trial, or evaluation
     use of the Service."

That is what makes publishing it safe: the credits are scoped to signed accounts,
which is exactly the carve-out terms.html §7 relies on. Both statements are
rendered ABOVE the fold and guarded, because they are what stops a self-serve
reader concluding the money applies to them.

⚠ TWO THINGS THE DOCUMENT DOES NOT SETTLE — see the guards at the end and the
handoff notes: §5's support table is keyed by SELF-SERVE PLAN NAMES (Pro, Max,
Premium) while the header is keyed by Order Form; and §7 says availability is
tracked when nothing in this repository can compute a monthly percentage.

Run:  pytest foxy-sale-page -q
"""

from __future__ import annotations

import pathlib
import re

import pytest

from conftest import POSTAL_ADDRESS

PAGE = "sla.html"
VERSION = "1.4"
PHONE = "+92 3398123944"
SUPERSEDED_PHONE = "3448123944"

HERE = pathlib.Path(__file__).resolve().parent
ROOT = HERE.parent


@pytest.fixture(scope="module")
def dom(legal_dom):
    return legal_dom(PAGE)


# ── 1. WHO THE MONEY IS OWED TO ──────────────────────────────────────────────
def test_the_page_states_who_it_applies_to_above_the_fold(dom):
    """⚠ THE SENTENCE THAT MAKES THIS PAGE SAFE TO PUBLISH.

    A public URL carrying a credit schedule is a financial commitment to whoever
    can reasonably conclude it applies to them. The document scopes itself, so
    the page must too — and not only in a metadata table further down."""
    t = dom.text
    assert "Applies to: Customers with an active paid Order Form referencing this SLA." in t
    assert ("incorporated by reference into the Master Service Agreement between Foxy Audit "
            "and Customer. It does not apply to free-tier, trial, or evaluation use of the "
            "Service.") in t
    # above the fold: inside the first card, before any section heading
    first_card = dom.src[dom.src.index('<div class="card">'):dom.src.index("<h2 ")]
    assert "active paid Order Form" in first_card, \
        "the scope statement moved below the first section — it must not be scrollable-past"
    assert 'class="scope"' in dom.src


def test_the_terms_carve_out_still_matches_this_page(dom):
    """terms.html §7: "unless a separate written SLA applies to your account, the
    Service is provided without an uptime guarantee". That carve-out only works
    while this page says a written Order Form is the trigger. If either side
    moves, the pair stops being coherent."""
    terms = (HERE / "terms.html").read_text(encoding="utf-8")
    assert "without an uptime guarantee" in terms
    assert "unless a separate written SLA applies to your account" in terms
    assert "active paid Order Form referencing this SLA" in dom.text


def test_the_support_table_now_states_which_customers_it_binds(dom):
    """⚠ RESOLVED (SLA §5, OWNER DECISION 2026-08-14). This was the one thing on
    this page a self-serve customer could fairly hold the company to.

    The header scopes the whole document to Order Form customers. §5's tables
    are keyed by PLAN NAME — Pro, Max, Premium — which are also the self-serve
    tiers (PRODUCT.md: free 500/mo, pro 25k, max 250k, premium by contract). A
    Pro customer paying by card read "Pro | Email | 4 business hours" and had no
    reason to think it was not theirs.

    §5 keeps its plan keys, because the Order Form template resolves a plan name
    through §5 (see test_order_form_l12.py). It gains one scope line instead.

    ⚠ THIS GUARD'S OLD DOCSTRING SAID "WHEN IT IS RESOLVED, THIS FAILS. That is
    the design." IT DID NOT FAIL. Every assertion it made — the scope sentence,
    the plan names, the pricing cross-check — stayed true when the scope line
    was added, because none of them asserted the ABSENCE the finding was about.
    The guard that did fire was in test_order_form_l12.py, which asserted
    `"Order Form" not in s5`. Recorded here because a docstring promising a
    failure it cannot produce is worse than no promise: it was believed."""
    t = dom.text
    assert "active paid Order Form referencing this SLA" in t
    for plan in ("Pro", "Max, Premium"):
        assert plan in t, f"the support table no longer keys off the plan name {plan!r}"
    assert "Max / Premium" in t, "the response-target table no longer keys off plan names"
    # the plan names really are the self-serve tiers, which is why §5 had to say
    # which population its targets bind rather than assume the header covered it
    pricing = (HERE / "pricing.html").read_text(encoding="utf-8")
    assert re.search(r"\bPro\b", pricing) and re.search(r"\bMax\b", pricing), \
        "Pro/Max are no longer self-serve plan names — re-check whether §5's " \
        "scope line still has a population to exclude"
    assert "These response targets apply to Order Form customers." in t, \
        "§5 lost the sentence that resolves the overlap"
    assert "Self-serve plans receive best-effort support" in t, \
        "§5 no longer says what a self-serve customer actually gets"


# ── 2. EVERY COMMITMENT NUMBER, GUARDED ON ITS OWN ──────────────────────────
@pytest.mark.parametrize("band,credit", [
    ("Below 99.5%, at or above 99.0%", "5% of that month's fees"),
    ("Below 99.0%, at or above 95.0%", "10% of that month's fees"),
    ("Below 95.0%", "25% of that month's fees"),
])
def test_each_credit_band_keeps_its_own_percentage(dom, credit, band):
    """Row by row, band bound to credit. A mutation that swaps 5% and 10%, or
    moves a threshold, changes what is owed — and would pass any check that only
    asked whether the numbers appear somewhere on the page."""
    row = re.search(rf"<tr><td>{re.escape(band)}</td><td>(.*?)</td></tr>", dom.src)
    assert row, f"the credit band {band!r} is gone from the table"
    assert row.group(1) == credit, \
        f"band {band!r} now pays {row.group(1)!r}, not {credit!r}"


def test_the_credit_bands_are_exhaustive_and_do_not_overlap(dom):
    """Three bands, contiguous, covering everything below the target. A fourth
    band or a gap would leave a claim with no defined answer."""
    bands = re.findall(r"<tr><td>(Below [^<]+)</td>", dom.src)
    assert bands == ["Below 99.5%, at or above 99.0%",
                     "Below 99.0%, at or above 95.0%",
                     "Below 95.0%"], f"the credit bands changed: {bands}"
    pcts = re.findall(r"(\d{2}\.\d)%", dom.text)
    assert sorted(set(pcts), reverse=True) == ["99.5", "99.0", "95.0"], \
        f"an availability threshold was invented or removed: {sorted(set(pcts))}"


@pytest.mark.parametrize("commitment", [
    "targets 99.5% monthly uptime",
    "within 30 days of the end of the affected month",
    "sole and exclusive remedy",
    "Total credits in any month will not exceed 25% of that month's fees.",
    "at least 48 hours' advance notice",
    "Monday–Friday, 9am–6pm PKT, excluding public holidays",
])
def test_each_commitment_survives(dom, commitment):
    """The claim window, the cap, the maintenance notice, the support hours.
    Each is separately actionable, so each fails separately."""
    assert commitment in dom.text, f"a commitment changed or was lost: {commitment!r}"


@pytest.mark.parametrize("plan,channel", [
    ("Pro", "Email"),
    ("Max, Premium", "Email + priority queue"),
])
def test_each_support_channel_keeps_its_plan(dom, plan, channel):
    """⚠ THE OTHER TABLE IN §5, AND IT WAS NOT PINNED PER-CELL. L9 bound the
    response-target table row by row and left this one on a page-wide substring
    search for the plan names.

    That is not the same check. Both tables key off "Pro", so re-keying THIS
    table to "Order Form customers" left every assertion green — the page-level
    search was answered by the response-target table's column header two
    elements further down. Found by mutation while resolving §5's scope, not by
    reading, and it is register #184 yet again: a guard satisfied by a
    neighbour.

    Bound to the row now, so the plan and the channel it buys fail together."""
    row = re.search(rf"<tr><td>{re.escape(plan)}</td><td>(.*?)</td></tr>", dom.src)
    assert row, (
        f"the {plan!r} support-channel row is gone. §5's first table must stay "
        "keyed by plan name — the Order Form template resolves a plan through it")
    assert row.group(1) == channel, \
        f"{plan} now gets {row.group(1)!r} as its support channel, not {channel!r}"


@pytest.mark.parametrize("severity,pro,max_premium", [
    ("Critical (Sev 1)", "4 business hours", "1 business hour"),
    ("High (Sev 2)", "1 business day", "4 business hours"),
    ("Normal (Sev 3)", "2 business days", "1 business day"),
])
def test_each_response_target_keeps_its_severity_and_plan(dom, severity, pro, max_premium):
    """⚠ THE MOST SWAPPABLE TABLE ON THE PAGE. Pro's Sev 1 (4 business hours) and
    Max's Sev 2 (4 business hours) are the same string in different cells, so a
    row-level or page-level check cannot tell a swap from the truth. Bound to
    the severity AND the column."""
    row = re.search(rf"<tr><td>{re.escape(severity)}</td><td>(.*?)</td><td>(.*?)</td></tr>", dom.src)
    assert row, f"the {severity} row is gone"
    assert row.group(1) == pro, f"{severity} Pro target is {row.group(1)!r}, not {pro!r}"
    assert row.group(2) == max_premium, \
        f"{severity} Max/Premium target is {row.group(2)!r}, not {max_premium!r}"


def test_the_response_targets_are_faster_for_the_higher_tier(dom):
    """A structural check the individual rows cannot make: Max/Premium must never
    be slower than Pro. If a swap ever produced that, the table would still look
    plausible cell by cell."""
    order = {"1 business hour": 1, "4 business hours": 2, "1 business day": 3,
             "2 business days": 4}
    rows = re.findall(r"<tr><td>(Critical|High|Normal)[^<]*</td><td>(.*?)</td><td>(.*?)</td></tr>",
                      dom.src)
    assert len(rows) == 3
    for sev, pro, prem in rows:
        assert order[prem] < order[pro], \
            f"{sev}: the higher tier ({prem}) is not faster than Pro ({pro})"


def test_no_number_was_invented(dom):
    """The only figures on this page are the ones the document states."""
    t = dom.text
    # NB: "business" sits between the number and the unit. Without it this saw
    # only 30 and 48 and silently stopped covering every response target.
    days = sorted(set(re.findall(r"\b(\d+)\s*(?:business\s+)?(?:days?|hours?)\b", t)))
    assert days == ["1", "2", "30", "4", "48"], f"an unexpected duration appeared: {days}"
    pcts = sorted(set(re.findall(r"(\d+(?:\.\d+)?)%", t)))
    assert pcts == ["10", "25", "5", "95.0", "99.0", "99.5"], f"a percentage changed: {pcts}"
    assert not re.search(r"\b(?:24/7|24x7|around the clock|weekend)\b", t, re.I), \
        "support hours were widened beyond what the document promises"
    assert "PKT" in t and t.count("PKT") == 1, "the timezone changed or was duplicated"
    hit = POSTAL_ADDRESS.search(t)
    assert not hit, f"a postal address was invented: {hit.group(0)!r}"


def test_no_escalation_path_or_holiday_calendar_was_invented(dom):
    """The document says "excluding public holidays" and names no calendar; it
    defines three severities and no escalation ladder. Both silences are the
    document's."""
    t = dom.text
    assert "excluding public holidays" in t
    assert not re.search(r"\b(?:escalat\w+|on-call|pager|phone tree|account manager|CSM)\b", t, re.I), \
        "an escalation path was invented"
    assert not re.search(r"\bSev(?:erity)? ?4\b", t), "a fourth severity was invented"
    sevs = re.findall(r"\(Sev (\d)\)", t)
    assert sorted(set(sevs)) == ["1", "2", "3"], f"the severity set changed: {sorted(set(sevs))}"


# ── 3. what the page cannot currently substantiate ──────────────────────────
def test_the_monitoring_claim_is_still_unbacked(dom):
    """⚠ RECORDED. §7 says "Foxy Audit tracks Service availability". Nothing in
    this repository can compute a monthly availability percentage:

      · the only uptime figure is routers/health.py's ``uptime_seconds``, which
        is seconds since PROCESS START and resets on every deploy
      · Docker healthchecks decide container restarts; nothing records them
      · the deploy smoke test is one-shot, at deploy time
      · there is no availability table, no scheduled probe, and no external
        monitor (UptimeRobot, Pingdom, BetterStack, statuspage, Grafana,
        Prometheus, Sentry all absent from backend/, deploy/ and .github/)

    So a credit claim under §2 cannot be substantiated OR refuted from data. The
    document hedges — "any monitoring tooling in place at the time" — but §7's
    first clause is an assertion, and §2 puts the burden of naming dates on the
    Customer.

    ⚠ WHEN MONITORING SHIPS, THIS FAILS and should be rewritten to assert it."""
    assert "Foxy Audit tracks Service availability" in dom.text
    assert "any monitoring tooling in place at the time of the claim" in dom.text, \
        "the hedge was removed — the claim is now unqualified"
    backend = ROOT / "backend"
    health = (backend / "app" / "routers" / "health.py").read_text(encoding="utf-8")
    assert "uptime_seconds = int(time.time() - START_TIME)" in health, \
        "health.py changed — has real availability measurement landed?"
    models = (backend / "app" / "models.py").read_text(encoding="utf-8")
    assert not re.search(r"class (?:Uptime|Availability|StatusCheck|Downtime)\w*\(", models), \
        "an availability model appeared — rewrite this guard to assert monitoring exists"
    haystack = "\n".join(p.read_text(encoding="utf-8", errors="ignore")
                         for p in list((backend / "app").rglob("*.py"))
                         + list((ROOT / "deploy").glob("*")) if p.is_file())
    for vendor in ("uptimerobot", "pingdom", "betterstack", "statuspage",
                   "healthchecks.io", "prometheus", "grafana"):
        assert vendor not in haystack.lower(), \
            f"{vendor} appeared — monitoring may exist now; rewrite this guard"


# ── 4. conversion hygiene ────────────────────────────────────────────────────
def test_the_page_states_the_version_the_filename_carries(dom):
    """The document header says "Version 1.0"; the filename says v1.4 and wins."""
    line = re.search(r'class="updated">([^<]+)<', dom.src)
    assert line and f"Version {VERSION}" in line.group(1)
    assert "Version 1.0" not in dom.text, "the document's stale header version was published"


def test_the_contact_is_support_and_the_phone_is_the_owners(dom):
    """support@ — a credit claim is support work, not legal or security."""
    assert dom.addresses == {"support@foxyaudit.tech"}, f"unexpected addresses: {dom.addresses}"
    assert SUPERSEDED_PHONE not in dom.src, "the superseded phone number was published"
    assert PHONE in dom.text
    for href in dom.mailtos:
        assert not href[len("mailto:"):].split("?")[0].endswith(".")


def test_the_en_dashes_survived_and_no_em_dash_entered_the_policy(dom):
    """⚠ THE CLEANEST #179 CONTROL IN THE SET. This document has ZERO em-dashes
    and TWO en-dashes ("Monday–Friday", "9am–6pm") — and the superseded v1.2 has
    exactly the same counts. Both versions are dash-free by AUTHORSHIP, not by
    damage: had the pipeline stripped dashes generally, the en-dashes would have
    gone too. Nothing was restored here, and this pins that nothing was invented.

    The four em-dashes on the page are the Document-details chrome, which every
    sibling has."""
    t = dom.text
    assert "Monday–Friday, 9am–6pm PKT" in t, "an en dash was lost or converted"
    body = t[t.index("1. Availability commitment"):]
    assert "—" not in body, "an em dash was introduced into a document that has none"
    assert "  " not in t, "a doubled space appeared"


def test_every_in_page_anchor_lands_on_something(dom):
    frags = {a["href"].split("#")[1] for a in dom.links if a["href"].startswith("#")}
    assert not (frags - set(dom.ids)), f"dead fragments: {sorted(frags - set(dom.ids))}"
    assert len([i for i in dom.ids if re.fullmatch(r"s\d+", i)]) == 8, \
        "the page no longer has its eight sections"


def test_it_links_only_documents_that_exist(dom):
    """⚠ RE-AIMED IN L11, NOT DELETED — the same move L9 made on L8's guard.

    This pinned that the MSA and the Order Form were named in prose and NOT
    linked, because neither page existed. msa.html now does (L11), so the
    assertion is inverted rather than dropped: the incorporation statement must
    LINK the agreement it incorporates.

    A guard whose subject ships is not finished — it is aimed somewhere new."""
    assert "Master Service Agreement" in dom.text
    assert 'href="/msa.html"' in dom.src, (
        "sla.html states it is incorporated into the Master Service Agreement but "
        "does not link it, and msa.html exists now")
    assert (HERE / "msa.html").is_file(), "the MSA link has no target"

    # ⚠ THE ORDER FORM HALF, RESOLVED IN L12 RATHER THAN LEFT DANGLING.
    #
    # L12 decided NOT to publish the Order Form. It is a blank contract template
    # — eleven unfilled brackets and two signature lines — and a page reading
    # "Fee: [$ amount]" above a blank signature line is indistinguishable from an
    # unfinished page. So this half is no longer "waiting for a page": the
    # absence is a decision, and what must exist instead is the EXPLANATION in
    # msa.html. Both halves are asserted, so publishing the form later trips this
    # deliberately, and deleting the explanation trips it too.
    assert "Order Form" in dom.text
    assert 'href="/order-form.html"' not in dom.src, (
        "an Order Form page appears to exist now — L12 decided against publishing "
        "the blank template; if that was overturned, re-aim this and add the card")
    assert not (HERE / "order-form.html").is_file(), "an order-form.html appeared"
    assert 'id="order-form"' in (HERE / "msa.html").read_text(encoding="utf-8"), (
        "msa.html lost the section explaining what an Order Form is — this page's "
        "own scope sentence then depends on a term nothing on the site defines")
    for href in {a["href"] for a in dom.links if a["href"].startswith("/")}:
        target = href.lstrip("/").split("#")[0] or "index.html"
        assert (HERE / target).is_file(), f"links to {href}, which does not exist"


def test_no_external_url_is_reachable_from_the_markup(dom):
    fetching = re.findall(r'(?:src|href)="(https?://[^"]+)"', dom.src)
    fetching += re.findall(r"url\(\s*['\"]?(https?://[^)'\"]+)", dom.src)
    assert not fetching, f"the page fetches from the network: {fetching}"
    assert "https://" not in dom.src, "an absolute URL appeared on a legal page"


def test_the_embedded_faces_are_the_ones_the_siblings_ship(dom):
    pat = r"font-weight:(\d+);font-display:swap;src:url\(data:font/woff2;base64,([A-Za-z0-9+/=]+)\)"
    mine = dict(re.findall(pat, dom.src))
    sibling = dict(re.findall(pat, (HERE / "trust.html").read_text(encoding="utf-8")))
    assert set(mine) == {"600", "700"}, f"unexpected faces: {sorted(mine)}"
    assert mine == sibling, "the embedded Poppins has drifted from trust.html's"
