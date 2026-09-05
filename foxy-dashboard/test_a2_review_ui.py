"""A2 — the reviewer surface, MEASURED where a static read cannot see it.

A1 gave an escalated verdict a destination and a notice. Neither is a place a
person can act: the queue was a table and two endpoints, and the email pointed
at a ledger filter. This page is the pull surface — and the half of it that can
be wrong while every string is present is the half a `grep` cannot reach.

So this file is in two parts, and the split is deliberate:

* **Static**, in the style of `test_p6f_judge_model_ui.py` — the three touch
  points a new page has to land on. The one that gets forgotten is the mobile
  `.mnbtn` twin: the rail collapses below 820px and a destination with no
  bottom-bar entry and no drawer entry is a page that exists and cannot be
  reached. Comments are stripped first, because this repo has shipped a guard
  satisfied by its own prose three times.

* **Driven**, in headless Chrome with `fetch` stubbed — the empty state, the
  pending list, and a resolve round-trip through the real dialog to the real
  request body. A queue page's failures are almost all runtime: an empty state
  that renders as an error, a list that drops the judge's reason, a resolve
  button that posts the wrong word. `fetch` is replaced BEFORE the page's own
  scripts parse, so the shipped loader runs unmodified against it.

⚠ THE ONE ASSERTION THIS FILE EXISTS FOR is
`test_zero_pending_reads_as_the_good_state_and_invents_no_rows`. Zero pending
escalations is the GOOD outcome — the judge decided everything on its own — and
the page it is easiest to get wrong is this one: an empty worklist looks like a
broken worklist, and the reflex is either an error tone or a sample row. This
product's standing rule is honest empty states in code and in UI, and a fake
escalation on the page whose subject is a real human decision would be the
worst place in it to break that rule.
"""
from __future__ import annotations

import json
import os
import pathlib
import re
import shutil
import subprocess
import tempfile

import pytest

HTML = pathlib.Path(__file__).resolve().parent / "foxy-audit-premium.html"
SRC = HTML.read_text(encoding="utf-8")

_CHROME = (os.environ.get("CHROME_BIN")
           or shutil.which("chrome") or shutil.which("google-chrome")
           or shutil.which("google-chrome-stable")
           or next((p for p in (
               r"C:\Program Files\Google\Chrome\Application\chrome.exe",
               r"C:\Program Files (x86)\Google\Chrome\Application\chrome.exe",
           ) if pathlib.Path(p).exists()), None))

needs_chrome = pytest.mark.skipif(_CHROME is None, reason="Chrome not available")


@pytest.fixture(scope="module")
def markup() -> str:
    """The file with HTML comments stripped.

    Structural scans must not match the prose that explains them."""
    return re.sub(r"<!--.*?-->", "", SRC, flags=re.S)


# ══ 1 · the three touch points a page has to land on ═══════════════════════

def test_the_rail_has_a_review_destination(markup):
    assert 'class="dock-item" data-page="review" onclick="go(\'review\',this)"' in markup, (
        "no rail entry for the reviewer page — the queue would be unreachable")


def test_the_mobile_bar_has_the_same_destination(markup):
    """⚠ THE HALF THAT GETS FORGOTTEN. Below 820px the rail becomes a drawer and
    the bottom bar is the only nav on screen. `test_p2_responsive` enforces
    `mnbtn ⊆ dock-item`, which catches a bottom-bar entry with no drawer entry —
    it cannot catch the reverse, which is this one."""
    assert 'class="mnbtn" data-page="review" onclick="go(\'review\',this)"' in markup, (
        "the reviewer page has a rail entry and no bottom-bar entry")


def test_the_page_exists_and_the_crumb_names_it(markup):
    assert '<div class="page" id="page-review">' in markup
    assert re.search(r"PAGE_TITLE=\{[^}]*\breview:'Review'", markup, re.S), (
        "PAGE_TITLE has no entry — the crumb would read the raw page id")


def test_the_OTHER_title_map_names_it_too(markup):
    """⚠ THERE ARE TWO, AND BOTH FALL BACK RATHER THAN FAIL. `go()` sets
    `#topbarTitle` from `PAGE_TITLE`, and `setTopbarContext` — wrapped around
    `go` further down the file — immediately overwrites it from `CTX`. A page
    listed in one and missing from the other silently inherits the FALLBACK
    entry's words, which is `['Overview','Home']`: the reviewer page shipped
    reading "OVERVIEW" in the crumb, and only a render showed it.
    `test_r4_systems_ui` names this failure for `systems`; it is the same one.
    """
    assert re.search(r"CTX=\{.*?\breview:\['[^']+','Review'\]", markup, re.S), (
        "CTX has no `review` entry, so the crumb falls back to another page's "
        "words")


def test_the_page_loads_on_arrival(markup):
    """`go()` carries no per-page loader, so a page with data wraps it. Without
    this the page opens on whatever the last fetch left behind — or, on a first
    visit, on the skeleton, forever."""
    assert re.search(r"window\.go=function\(pg,el\)\{\s*g\(pg,el\);\s*"
                     r"if\(pg==='review'\)load\(false\);", markup), (
        "nothing loads the queue when the page is opened")


# ══ 2 · one escalation colour, and it is the one Q4 already chose ══════════

def test_the_page_reuses_the_shipped_escalation_colour(markup):
    """⚠ NO SECOND ESCALATION COLOUR. `--c-6` is slot 6 of the categorical
    palette and `.ltag.human_review` / `.pill.human_review` already carry it. A
    reviewer page that picked its own violet would make one product state two
    colours, and only one of them would be measured."""
    assert ".dock-pip.review{background:var(--c-6);color:#160a2e;}" in markup
    assert 'html[data-theme="light"] .dock-pip.review{color:#fff;}' in markup
    risk = markup[markup.index(".rvw-risk{"):]
    risk = risk[:risk.index("}")]
    assert "background:var(--c-6)" in risk and "color:#160a2e" in risk, risk
    assert 'html[data-theme="light"] .rvw-risk{color:#fff;}' in markup, (
        "the light theme deepens --c-6 to #6b42c8, where near-black falls to "
        "2.90:1 — the ink has to move with the fill")


def test_no_new_colour_literal_was_invented_for_this_page(markup):
    """The two inks are the pair `.ltag.human_review` already ships. Any third
    hex in this block would be a colour nobody measured."""
    block = markup[markup.index("A2 · THE REVIEW QUEUE"):markup.index(".rvw-note{")]
    hexes = {h.lower() for h in re.findall(r"#[0-9a-fA-F]{3,8}", block)}
    assert hexes <= {"#160a2e", "#fff", "#9b8cff", "#6b42c8", "#eae7e4"}, (
        "a colour literal appeared that is not one of the escalation pair or a "
        "measurement quoted in the comment: %s" % sorted(hexes))


def test_the_resolutions_are_the_endpoint_s_own_words(markup):
    """`resolution` is a regex-constrained string on the wire, not an enum. A
    word invented here is a 422 the reviewer cannot read."""
    block = markup[markup.index("var OUTCOME=["):]
    block = block[:block.index("];")]
    assert set(re.findall(r"key:'(\w+)'", block)) == {
        "confirmed_breach", "cleared", "policy_gap"}, block


def test_no_resolve_button_is_painted_as_the_expected_answer(markup):
    """Three equal buttons. Painting "Confirmed breach" `.btn danger` would
    colour the outcome before a person chose it, inside a decision that is
    written once and cannot be corrected by deciding again."""
    acts = markup[markup.index("var acts=done?''"):]
    acts = acts[:acts.index("return '<div class=\"rvw\">")]
    classes = set(re.findall(r'class="(btn[^"]*)"', acts))
    assert classes == {"btn ghost sm"}, (
        "the resolve buttons are not all the same weight: %s" % classes)


# ══ 3 · no invented rows reached the markup ════════════════════════════════

def test_the_queue_ships_empty(markup):
    """The standing rule, at the one place it is easiest to break. `#rvwList`
    holds a skeleton and nothing else until the server answers."""
    body = markup[markup.index('<div id="rvwList"'):]
    body = body[:body.index('<div id="rvwMore">')]
    assert "skel" in body, "the list has no loading state"
    assert "rvw-why" not in body and "rvw-risk" not in body, (
        "a review card is baked into the markup — that is a sample row")
    assert not re.search(r"risk \d", body), body


# ══ 4 · driven: what a static read cannot see ══════════════════════════════

_PROBE = r"""
async function probe(){
  const sleep=ms=>new Promise(r=>setTimeout(r,ms));
  const out={};
  const rows=()=>document.querySelectorAll('#page-review .rvw').length;
  const list=()=>document.getElementById('rvwList').innerHTML;

  // ── 1 · zero pending ────────────────────────────────────────────────────
  window.__page={items:[],page:{complete:true,next_after_seq:null}};
  window.go('review',null);
  await sleep(220);
  out.empty={rows:rows(), html:list(),
             pip:document.getElementById('reviewPip').style.display};

  // ── 2 · a real queue ────────────────────────────────────────────────────
  window.__page={items:[
    {id:'11111111-1111-4111-8111-111111111111', seq:1482, status:'pending',
     resolution:null, reason:'A clinical tag on a finance policy — unclear which governs.',
     risk_score:72, note:null, policy_tag:'phi-guard', agent:'billing-agent',
     event_created_at:new Date(Date.now()-7200000).toISOString(),
     created_at:new Date().toISOString(), resolved_at:null, resolved_by:null},
    {id:'22222222-2222-4222-8222-222222222222', seq:1490, status:'pending',
     resolution:null, reason:'Two rules matched and disagree.', risk_score:31,
     note:null, policy_tag:'chat', agent:null,
     event_created_at:new Date(Date.now()-600000).toISOString(),
     created_at:new Date().toISOString(), resolved_at:null, resolved_by:null}],
    page:{complete:true,next_after_seq:null}};
  window.foxReviews.reload();
  await sleep(260);
  out.pending={rows:rows(), html:list(),
               pip:document.getElementById('reviewPip').textContent,
               pipShown:document.getElementById('reviewPip').style.display!=='none',
               buttons:Array.prototype.map.call(
                 document.querySelectorAll('#page-review .rvw-acts .btn'),
                 b=>b.textContent.trim())};

  // ── 3 · the resolve round-trip, through the shipped dialog ──────────────
  window.__calls.length=0;
  document.querySelectorAll('#page-review .rvw')[0]
          .querySelectorAll('.rvw-acts .btn')[1].click();   // "Cleared"
  await sleep(120);
  const dlg=document.getElementById('foxDlg');
  out.dialog={open:dlg.classList.contains('on'),
              title:document.getElementById('foxDlgT').textContent,
              body:document.getElementById('foxDlgB').textContent,
              yes:document.getElementById('foxDlgYes').textContent};
  const note=document.getElementById('foxDlgFields').querySelector('input');
  out.dialog.hasNote=!!note;
  if(note)note.value='rule 4 does not reach a redacted field';
  document.getElementById('foxDlgYes').click();
  await sleep(320);
  out.posted=window.__calls.filter(c=>c.method==='POST');

  // ── 4 · a decision, once it is recorded ─────────────────────────────────
  window.__page={items:[
    {id:'11111111-1111-4111-8111-111111111111', seq:1482, status:'resolved',
     resolution:'cleared', reason:'A clinical tag on a finance policy.',
     risk_score:72, note:'rule 4 does not reach a redacted field',
     policy_tag:'phi-guard', agent:'billing-agent',
     event_created_at:new Date(Date.now()-7200000).toISOString(),
     created_at:new Date().toISOString(),
     resolved_at:new Date(Date.now()-60000).toISOString(),
     resolved_by:'alex@corp.test'}],
    page:{complete:true,next_after_seq:null}};
  document.querySelector('[data-rvwfilter="resolved"]').click();
  await sleep(260);
  out.resolved={rows:rows(), html:list(),
    pressed:Array.prototype.map.call(
      document.querySelectorAll('[data-rvwfilter]'),
      b=>b.getAttribute('data-rvwfilter')+'='+b.getAttribute('aria-pressed')),
    urls:window.__calls.filter(c=>c.method==='GET').map(c=>c.url)};

  // ── 5 · the empty state for a workspace that has decided nothing yet ────
  window.__page={items:[],page:{complete:true,next_after_seq:null}};
  window.foxReviews.reload();
  await sleep(240);
  out.emptyResolved={rows:rows(), html:list()};

  // ── 6 · the badge against the tile it actually sits on ─────────────────
  const item=document.querySelector('.dock-item[data-page="review"]');
  const pipEl=document.getElementById('reviewPip');
  pipEl.style.display=''; item.classList.add('active');
  void item.offsetHeight;
  const cs=getComputedStyle(pipEl);
  out.badge={fill:cs.backgroundColor, ink:cs.color, shadow:cs.boxShadow,
             tile:getComputedStyle(item).backgroundColor};

  document.documentElement.innerHTML='<pre id="a2">'+
    JSON.stringify(out).replace(/</g,'\\u003c')+'</pre>';
}
"""

# The stub is prepended so it is in place before ANY of the page's own scripts
# parse — including the CSRF wrapper, which then wraps it exactly as it wraps
# the real one. The loader under test is unmodified.
_STUB = r"""<script>
window.__calls=[];
window.__page={items:[],page:{complete:true,next_after_seq:null}};
function __res(ok,status,payload){
  return Promise.resolve({ok:ok, status:status,
    json:function(){ return Promise.resolve(payload); },
    text:function(){ return Promise.resolve(JSON.stringify(payload)); },
    headers:{get:function(){ return null; }}});
}
window.fetch=function(input,init){
  var url=String(input), method=((init&&init.method)||'GET').toUpperCase();
  var h=init&&init.headers;
  window.__calls.push({url:url, method:method,
    body:(init&&init.body)?String(init.body):null,
    csrf:(h&&h.get)?h.get('X-CSRF-Token'):null});
  if(url.indexOf('/v1/reviews')===0){
    if(method==='POST')return __res(true,200,{});
    // The pip asks for limit=10; the page asks for limit=50. One fixture
    // answers both, so a pip that read the wrong list would show it.
    return __res(true,200,window.__page);
  }
  return __res(false,404,{});
};
</script>
"""


def _run() -> dict:
    page_src = _STUB + SRC + (
        "\n<script>" + _PROBE +
        "window.addEventListener('load',function(){setTimeout(function(){"
        "probe().catch(function(e){document.documentElement.innerHTML="
        "'<pre id=\"a2\">'+JSON.stringify({error:String(e)})+'</pre>';});},300);});"
        "</script>\n")
    with tempfile.TemporaryDirectory() as tmp:
        page = pathlib.Path(tmp) / "a2.html"
        page.write_text(page_src, encoding="utf-8")
        proc = subprocess.run(
            [_CHROME, "--headless=new", "--disable-gpu", "--no-sandbox",
             "--hide-scrollbars", "--force-prefers-reduced-motion",
             "--virtual-time-budget=15000", "--window-size=1440,900",
             f"--user-data-dir={tmp}/prof", "--dump-dom", page.as_uri()],
            capture_output=True, text=True, encoding="utf-8",
            errors="replace", timeout=180)
    m = re.search(r'<pre id="a2">(.*?)</pre>', proc.stdout, re.S)
    assert m, "the probe never ran; chrome said: %s" % proc.stderr[-700:]
    data = json.loads(m.group(1).replace("\\u003c", "<"))
    assert not data.get("error"), data["error"]
    return data


@pytest.fixture(scope="module")
def run() -> dict:
    return _run()


@needs_chrome
def test_zero_pending_reads_as_the_good_state_and_invents_no_rows(run):
    """⚠ THE ASSERTION THIS FILE EXISTS FOR.

    Nothing waiting is the GOOD outcome: the judge reached every determination
    on its own. The page has to say that — not "no data", not an error tone, and
    above all not a sample escalation to show what one would look like.
    """
    empty = run["empty"]
    assert empty["rows"] == 0, "an empty queue rendered review cards"
    html = empty["html"]
    assert 'class="empty"' in html, "zero pending did not render the empty state"
    assert "No reviews waiting" in html, html[:400]
    assert "decided every graded interaction on its own" in html, (
        "the empty state does not say WHY it is empty, so it reads as a "
        "failure rather than as the good outcome: %s" % html[:400])
    for word in ("error", "failed", "Could not", "problem", "unavailable"):
        assert word not in html, (
            "the good state is worded as a failure (%r): %s" % (word, html[:400]))
    # No invented escalation, by any of the three things one would carry.
    assert "rvw-risk" not in html and "rvw-why" not in html
    assert not re.search(r"#\d{2,}", html), html[:400]
    assert empty["pip"] == "none", "the rail badge shows a count of nothing"


@needs_chrome
def test_the_pending_queue_shows_what_a_decision_needs(run):
    """A queue entry with no reason is a notification, not a review — the person
    would have nothing to act on. Seq, risk, tag, agent and the judge's own
    sentence, and the three resolutions beside them."""
    pending = run["pending"]
    assert pending["rows"] == 2, pending["rows"]
    html = pending["html"]
    assert "A clinical tag on a finance policy" in html, "the reason is missing"
    assert "risk 72" in html and "risk 31" in html, "the risk score is missing"
    assert "#1482" in html and "#1490" in html, "the ledger seq is missing"
    assert "phi-guard" in html and "billing-agent" in html
    assert pending["buttons"] == ["Confirmed breach", "Cleared", "Policy gap"] * 2, (
        "every pending row needs all three resolutions: %s" % pending["buttons"])
    assert pending["pipShown"] and pending["pip"] == "2", (
        "the rail badge does not carry the pending count: %r" % pending["pip"])


@needs_chrome
def test_resolving_confirms_first_because_it_cannot_be_undone(run):
    """`POST /v1/reviews/{id}/resolve` is first-write-wins: the evidence event is
    append-only, so a second resolve returns the standing decision and appends
    nothing. The reviewer has to be told that BEFORE the write, not after."""
    dialog = run["dialog"]
    assert dialog["open"], "resolving posted with no confirmation step"
    assert dialog["title"] == "Record: Cleared", dialog["title"]
    assert dialog["yes"] == "Record decision", dialog["yes"]
    assert "written once" in dialog["body"], dialog["body"]
    assert "cannot be changed by deciding again" in dialog["body"], dialog["body"]
    assert dialog["hasNote"], "there is nowhere to record why"
    # The note is annotation, not evidence, and the dialog has to say so — a
    # reviewer who does not know that will paste the prompt into it.
    assert "never hashed" in dialog["body"] and "never exported" in dialog["body"], (
        dialog["body"])


@needs_chrome
def test_the_resolve_reaches_the_endpoint_with_the_word_the_button_said(run):
    """The failure this catches is a button labelled one thing posting another —
    a wrong resolution on an append-only record cannot be taken back."""
    posted = run["posted"]
    assert len(posted) == 1, "expected exactly one POST, got %s" % posted
    call = posted[0]
    assert call["url"] == ("/v1/reviews/11111111-1111-4111-8111-111111111111"
                           "/resolve"), call["url"]
    body = json.loads(call["body"])
    assert body["resolution"] == "cleared", body
    assert body["note"] == "rule 4 does not reach a redacted field", body


@needs_chrome
def test_a_recorded_decision_reads_as_a_verdict_not_as_an_escalation(run):
    """Violet means "nobody has decided yet". Once somebody has, the outcome
    joins the verdict vocabulary the ledger already ships, which is why there is
    no fourth status fill on this page."""
    resolved = run["resolved"]
    assert resolved["rows"] == 1, resolved["rows"]
    html = resolved["html"]
    assert 'class="pill safe"' in html, (
        "a cleared escalation is not painted with the shipped clean verdict: %s"
        % html[:400])
    assert "rvw-risk" not in html, (
        "a decided escalation still carries the pending mark")
    assert "alex@corp.test" in html, "the record does not name who decided"
    assert "rule 4 does not reach a redacted field" in html, "the note is lost"
    assert resolved["pressed"] == ["pending=false", "resolved=true"], (
        "the filter does not show which list is on screen: %s"
        % resolved["pressed"])
    assert any("status=resolved" in u for u in resolved["urls"]), (
        "the filter never asked the server for the resolved list: %s"
        % resolved["urls"])


def _rgb(css):
    nums = [float(n) for n in re.findall(r"[\d.]+", css or "")][:3]
    assert len(nums) == 3, css
    return nums


def _ratio(a, b):
    def lum(c):
        parts = [x / 255.0 for x in _rgb(c)]
        parts = [x / 12.92 if x <= 0.03928 else ((x + 0.055) / 1.055) ** 2.4
                 for x in parts]
        return 0.2126 * parts[0] + 0.7152 * parts[1] + 0.0722 * parts[2]
    la, lb = lum(a), lum(b)
    return (max(la, lb) + 0.05) / (min(la, lb) + 0.05)


@needs_chrome
def test_the_badge_does_not_dissolve_into_the_tile_it_sits_on(run):
    """⚠ MEASURED AGAINST ITS BACKGROUND, NOT ONLY AGAINST ITS INK, and the
    background is not the one you would check first.

    The rail is `--bg`, and violet clears it comfortably. But a `.dock-item`
    that is ACTIVE is filled with `--fox`, and violet on orange is 1.06:1 — so
    on the page the reader is actually on, the disc vanishes and the numeral is
    left floating. The digit is not what fails here; the badge is. That is the
    shape of the defect this surface has already shipped once, and the reason
    the fill is measured against the tile as well as against the rail.

    A 2px ring in the page ground is what fixes it, so the ring is what this
    measures — the fill is deliberately allowed to keep failing, because the
    fill is the escalation colour and must not move.
    """
    badge = run["badge"]
    assert badge["shadow"] and badge["shadow"] != "none", (
        "the badge has no ring, so on an active tile it is a numeral with no "
        "disc: %r" % badge["shadow"])
    assert _ratio(badge["ink"], badge["fill"]) >= 4.5, (
        "the count is not readable on its own fill: %.2f"
        % _ratio(badge["ink"], badge["fill"]))
    assert _ratio(badge["shadow"], badge["tile"]) >= 3.0, (
        "the ring does not separate the badge from the active tile behind it "
        "(%.2f:1) — ring %s on tile %s"
        % (_ratio(badge["shadow"], badge["tile"]), badge["shadow"],
           badge["tile"]))


@needs_chrome
def test_nothing_decided_yet_is_also_an_honest_empty_state(run):
    """The second empty state, and it must not borrow the first one's words:
    "no reviews waiting" on the Decided tab would answer a question nobody
    asked."""
    empty = run["emptyResolved"]
    assert empty["rows"] == 0
    assert "No decisions recorded yet" in empty["html"], empty["html"][:400]
    assert "No reviews waiting" not in empty["html"], (
        "the Decided tab shows the Waiting tab's empty state")
