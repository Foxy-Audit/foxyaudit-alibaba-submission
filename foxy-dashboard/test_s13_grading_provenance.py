"""#228 (UI half) — the dashboard says who graded, and never guesses.

The backend phase (`605f7f0`) made every verdict name its author: `graded_by` is
a closed four-value vocabulary — **ai / rules / host_enforcement / none** — and
`GET /v1/stats` gained `ai_graded` and `rules_graded`. Until this phase the
dashboard read none of it while saying, flatly, that "the AI judge grades each
event". On a workspace with no reachable key that sentence was false and there
was no way for the customer to tell.

Five things this surface can get wrong in ways a diff review reads as correct.

* **A claim with nothing behind it.** Copy is the deliverable here, not the
  trimming, so the removed sentences are asserted gone from the *visible* text,
  comments stripped — a comment explaining a removal can otherwise satisfy a test
  hunting the removed phrase. That trap has landed on this file's Policy page
  three phases running.

* **A chip that is readable and invisible.** This surface shipped a pill whose
  ink cleared 4.5:1 while the pill measured 1.01:1 against the card behind it.
  Every provenance chip is therefore measured TWICE — the ink against the fill,
  and the fill against both surfaces it can sit on (``--surf``, and ``--surf2``
  on a hovered ledger row) — and inks with ``--surf`` so the two are the same
  pair by construction, exactly as R4's lifecycle chips do.

* **Colour that ranks two kinds of evidence.** The deterministic rules engine is
  not a degraded judge: it reasons over hashes, counts and policy tags and does
  not evaluate semantic content. A status hue on either chip would say otherwise
  without a word of copy admitting it, so no status token may appear in the
  block.

* **A claim painted over an absent grader.** `graded_by` absent means NOT
  RECORDED and is never a statement. Rows written before this workspace stored
  the grader carry it, nothing backfills them, and "not graded by an AI" over one
  would be the invention the field exists to end.

* **The MIXED branch nobody tests.** #273 is this same sentence in the Compliance
  Passport: `and` was mutated to `or` and all eighteen tests passed, while a
  period holding both kinds printed a count of AI-graded events and then "No
  event in this period was graded by an AI model" two lines below it. The mixed
  shape is the realistic production one and it is guarded here in both
  directions — it must claim neither extreme.

The contrast maths is imported from `test_p1_contrast`, which pins black-on-white
at 21.0 before judging anything, rather than a second copy that could be wrong in
the same direction twice. The rendered guards drive the shipped file in headless
Chrome, because a CSS comment closing early once shipped a 1.21:1 chip past
`node --check`, a green suite and balanced braces.
"""

from __future__ import annotations

import json
import os
import pathlib
import re
import shutil
import subprocess
import tempfile
from html import unescape
from functools import lru_cache
from pathlib import Path

import pytest

from test_p1_contrast import _block, _declarations, _stylesheet, ratio

HTML = Path(__file__).resolve().parent / "foxy-audit-premium.html"

AA_BODY = 4.5      # WCAG 1.4.3 — the chip's word is text
UI_FLOOR = 3.0     # WCAG 1.4.11 — the chip's fill is a UI component boundary

#: (modifier, fill token, ink token). The unmodified rule is the NAMED-author
#: chip and is also what an unrecognised `graded_by` would fall back to.
CHIPS = [("", "ink2", "surf"),
         ("unnamed", "muted", "surf")]

#: Both surfaces a chip can sit on. `.ldg-row:hover` repaints a ledger row
#: `--surf2`, and a chip that dissolves only on hover is the same defect.
CARDS = ["surf", "surf2"]


@lru_cache(maxsize=1)
def source() -> str:
    return HTML.read_text(encoding="utf-8")


def _rows(case: dict) -> str:
    """The counter block's rendered text, lowered, with one space between each
    label and its figure. The <dt> and <dd> are flex siblings with no text node
    between them, so `textContent` concatenates them — reading them apart here
    keeps the assertions legible without loosening what they check."""
    return re.sub(r"(?<=[a-z])(?=\d)", " ", case["rows"].lower())


def _flat(fragment: str) -> str:
    """Visible text of a markup fragment, whitespace-collapsed and lowered."""
    no_comments = re.sub(r"<!--.*?-->", " ", fragment, flags=re.S)
    return re.sub(r"\s+", " ", re.sub(r"<[^>]+>", " ", no_comments)).strip().lower()


@lru_cache(maxsize=1)
def graded_card() -> str:
    """The "What graded these events" card's markup, and nothing around it."""
    src = source()
    at = src.index('id="polGradedCard"')
    start = src.rindex("<div", 0, at)
    end = src.index("</div>", src.index('class="gxref"', at))
    return src[start:end]


@lru_cache(maxsize=1)
def judge_card() -> str:
    """The AI Judge settings card — the one that carried the bare claim."""
    src = source()
    at = src.index("AI Judge &amp; provider") if "AI Judge &amp; provider" in src \
        else src.index("judge provider")
    start = src.rindex('<div class="clay pad"', 0, at)
    return src[start:src.index('id="polGradedCard"')]


@lru_cache(maxsize=1)
def app_module() -> str:
    """The main application <script>, comments STRIPPED — a note about a rule
    must never be able to satisfy a test looking for the rule."""
    blocks = re.findall(r"<script(?![^>]*\bsrc=)[^>]*>(.*?)</script>",
                        source(), re.S)
    hit = [b for b in blocks if "function ledgerRow(it)" in b]
    assert len(hit) == 1, f"expected exactly one ledger module, found {len(hit)}"
    body = re.sub(r"/\*.*?\*/", "", hit[0], flags=re.S)
    return re.sub(r"(?m)//.*$", "", body)


@lru_cache(maxsize=1)
def mix_module() -> str:
    """The #228 stats module, comments stripped, for the same reason."""
    blocks = re.findall(r"<script(?![^>]*\bsrc=)[^>]*>(.*?)</script>",
                        source(), re.S)
    hit = [b for b in blocks if "window.foxGradingMix=" in b]
    assert len(hit) == 1, f"expected exactly one mix module, found {len(hit)}"
    body = re.sub(r"/\*.*?\*/", "", hit[0], flags=re.S)
    return re.sub(r"(?m)//.*$", "", body)


@pytest.fixture(scope="module")
def themes() -> dict[str, dict[str, str]]:
    css = _stylesheet()
    root = _declarations(_block(css, ":root"))
    light_over = _declarations(_block(css, 'html[data-theme="light"]'))

    def resolve(raw):
        tokens = {k: v for k, v in raw.items() if k.startswith("--")}
        for _ in range(12):
            changed = False
            for key, value in list(tokens.items()):
                hit = re.fullmatch(r"var\((--[\w-]+)\)", value.strip())
                if hit and hit.group(1) in tokens:
                    tokens[key] = tokens[hit.group(1)]
                    changed = True
            if not changed:
                break
        return {k[2:]: v for k, v in tokens.items()}

    return {"dark": resolve(root), "light": resolve({**root, **light_over})}


# ══ the chips, measured BOTH WAYS ═══════════════════════════════════════════
@pytest.mark.parametrize("theme", ["dark", "light"])
@pytest.mark.parametrize("modifier,fill,ink", CHIPS,
                         ids=[c[0] or "named(base)" for c in CHIPS])
def test_a_provenance_chip_is_readable_and_visible(themes, theme, modifier, fill, ink):
    """Ink on fill, AND fill on every surface the chip can sit on. Read out of
    the shipped stylesheet, so a re-tune cannot quietly break either direction."""
    selector = ".gchip" + (f".{modifier}" if modifier else "")
    decls = _declarations(_block(_stylesheet(), selector))
    assert decls.get("background") == f"var(--{fill})", \
        f"{selector} no longer fills with --{fill}: {decls.get('background')!r}"
    assert decls.get("color") == f"var(--{ink})", \
        f"{selector} no longer inks with --{ink}: {decls.get('color')!r}"

    tokens = themes[theme]
    readable = ratio(tokens[ink], tokens[fill])
    assert readable >= AA_BODY, (
        f"[{theme}] {selector} sets {tokens[ink]} on {tokens[fill]} — "
        f"{readable:.2f}:1, under the {AA_BODY} bar for its word.")
    for card in CARDS:
        visible = ratio(tokens[fill], tokens[card])
        assert visible >= UI_FLOOR, (
            f"[{theme}] {selector}'s fill {tokens[fill]} measures "
            f"{visible:.2f}:1 against --{card}. The word would be readable and "
            f"the chip would not be there — the 1.01:1 failure, again.")


def test_the_chip_ink_is_the_card_colour_so_the_two_cannot_diverge(themes):
    """Every chip inks with --surf, the colour of the card it sits on. That is
    what makes ink-on-fill and fill-on-card THE SAME MEASUREMENT: one cannot pass
    while the other fails. Copied from R4 rather than measured twice and hoped."""
    for _modifier, _fill, ink in CHIPS:
        assert ink == "surf", "a provenance chip stopped inking with the card's colour"
    for theme in ("dark", "light"):
        tokens = themes[theme]
        for _modifier, fill, ink in CHIPS:
            assert ratio(tokens[ink], tokens[fill]) == ratio(tokens[fill], tokens["surf"])


def test_the_base_chip_rule_carries_a_fill_and_an_edge():
    """`.gchip` unmodified is the NAMED-author chip and is also where a
    `graded_by` this build has never heard of lands. Move the fill onto a
    modifier and an unknown value renders as bare text on the card — a chip that
    is not there at all. The edge is what survives Windows High Contrast, which
    flattens the fill to Canvas and keeps border width and style."""
    decls = _declarations(_block(_stylesheet(), ".gchip"))
    assert "background" in decls and "color" in decls, (
        "the base .gchip rule stopped declaring a fill, so an unrecognised "
        "grader would dissolve into the card")
    assert decls["border"] == "var(--border-sm)", (
        "the chip's edge is what carries it in forced-colors, where the fill "
        "flattens to Canvas")


def test_authorship_never_borrows_a_status_hue():
    """Red, amber and green are reserved for status on this surface. Who graded a
    record is not a claim about how it behaved: `ai` is not a claim that anything
    is clean, and `rules` is not a warning. Painting either would rank two kinds
    of evidence without a word of copy admitting it."""
    css = _stylesheet()
    for selector in (".gchip", ".gchip.unnamed", ".gmix dt", ".gmix dd",
                     ".gsay", ".gxref", ".gby .gwhy"):
        body = str(_declarations(_block(css, selector)))
        for banned in ("--safe-bg", "--warn-bg", "--breach-bg",
                       "--safe-ink", "--warn-ink", "--breach-ink",
                       "--lv-low", "--lv-med", "--lv-high", "--lv-ultra"):
            assert banned not in body, (
                f"{selector} took {banned}. An author is not a status.")


def test_the_two_named_graders_are_visual_peers():
    """AI and rules share one chip rule with no modifier between them, so no
    weight, hue or size can encode a ranking the product does not make. The word
    is the whole distinction. A future modifier that separates them is the
    regression this catches."""
    css = _stylesheet()
    modifiers = set(re.findall(r"\.gchip\.([a-z-]+)\s*\{", css))
    assert modifiers == {"unnamed"}, (
        f"the provenance chip grew modifiers {sorted(modifiers)}. The only step "
        "this ramp is allowed to encode is named / not named.")


# ══ the copy that used to claim an AI had run ═══════════════════════════════
def test_the_removed_claims_are_gone_from_the_visible_copy():
    """Read off the visible text with comments stripped, so an explanation of a
    removal cannot satisfy the test hunting the removed phrase."""
    page = _flat(source())
    for gone in ("the ai judge grades each event against the rules you set here",
                 "after the ai judge has graded",
                 "once the judge has already found",
                 "but the judge flagged a policy breach"):
        assert gone not in page, f"the unconditional claim {gone!r} is still shipped"


def test_the_judge_settings_card_conditions_its_own_claim():
    """It may still say a model grades — it is the card where a model is chosen —
    but not that one always does, and it must point at the record."""
    flat = _flat(judge_card())
    assert "when one can be reached" in flat
    assert "deterministic rules engine grades the event instead" in flat
    assert "the record says so" in flat


def test_the_tour_names_both_graders():
    """The tour is the first thing a new customer reads, and it pointed at the
    Policy page saying an AI grades every event."""
    step = re.search(r"t:'Decide what counts as a breach',\s*b:'([^']*)'", source())
    assert step, "the tour step moved or was renamed"
    body = step.group(1).lower()
    assert "where one can be reached" in body
    assert "deterministic rules" in body
    assert "each record names which" in body


def test_the_card_says_where_its_numbers_come_from():
    flat = _flat(graded_card())
    assert "counted from your own records, not from the settings above" in flat
    assert "is not evidence that any particular event reached a model" in flat
    # The Passport says the same three things; a customer holding both documents
    # must not find two stories.
    assert "compliance passport carries this same statement" in flat


def test_the_card_shows_no_number_before_the_server_answers():
    """An empty <dl> under a heading that promises figures is the confident-wrong
    answer this product's principles forbid. It ships saying it is reading."""
    assert "Reading your records" in graded_card()
    assert not re.search(r"<dd>\s*\d", graded_card()), \
        "a literal figure is shipped in the markup — every number comes from /v1/stats"


def test_the_third_line_is_not_called_not_recorded():
    """/v1/stats gives two counters and a graded total. The remainder holds
    host-enforcement rows (which DO name their author), rows nothing graded, and
    rows written before the grader was stored — so labelling that sum "not
    recorded" would be false about the first of the three. The Passport can count
    it exactly because it walks the rows; this route cannot, so this card does not
    claim it."""
    module = mix_module()
    assert "'Neither of the above'" in module
    for invented in ("Grader not recorded", "Not recorded", "not graded by"):
        assert invented not in module, (
            f"the mix module labels its remainder {invented!r}, which is false "
            "for the host-enforcement rows inside it")


def test_the_ledger_detail_actually_calls_the_provenance_line():
    """Guard-lie #1: a definition nothing calls. Asserted on the module with
    comments stripped, and again on the rendered ledger below."""
    assert "+gradedByLine(it)" in app_module(), \
        "gradedByLine is defined and the ledger detail no longer calls it"


# ══ rendered — the only witness for anything that needs the page to run ══════
_CHROME = (os.environ.get("CHROME_BIN")
           or shutil.which("chrome") or shutil.which("google-chrome")
           or next((p for p in (
               r"C:\Program Files\Google\Chrome\Application\chrome.exe",
               r"C:\Program Files (x86)\Google\Chrome\Application\chrome.exe",
           ) if pathlib.Path(p).exists()), None))

needs_chrome = pytest.mark.skipif(_CHROME is None, reason="Chrome not available")

#: Every shape /v1/stats can hand this card. `legacy` is a workspace whose graded
#: rows are all host-enforcement or pre-#228: two counters at zero and a non-zero
#: total, which must NOT read as "nothing has been graded".
MIX_CASES = {
    "keyless":  {"ai_graded": 0, "rules_graded": 12, "grading": {"graded": 12}},
    "mixed":    {"ai_graded": 5, "rules_graded": 7,  "grading": {"graded": 12}},
    "ai_only":  {"ai_graded": 9, "rules_graded": 0,  "grading": {"graded": 9}},
    "nothing":  {"ai_graded": 0, "rules_graded": 0,  "grading": {"graded": 0}},
    "legacy":   {"ai_graded": 0, "rules_graded": 0,  "grading": {"graded": 6}},
    "keyless_with_legacy":
                {"ai_graded": 0, "rules_graded": 8,  "grading": {"graded": 12}},
    "unreachable": None,
}

#: One ledger row per `graded_by` value, plus the two the vocabulary does not
#: cover: a row written before the field existed, and one not graded yet.
BY_ROWS = {
    "ai":     {"grading_status": "graded",
               "gemini_verdict": {"graded_by": "ai", "judge_provider": "gemini"}},
    "rules":  {"grading_status": "graded", "gemini_verdict": {"graded_by": "rules"}},
    "rules_unavailable": {
        "grading_status": "graded",
        "gemini_verdict": {"graded_by": "rules",
                           "evaluator_unavailable_reason": "no_api_key"}},
    "host":   {"grading_status": "graded",
               "gemini_verdict": {"graded_by": "host_enforcement"}},
    "none":   {"grading_status": "graded", "gemini_verdict": {"graded_by": "none"}},
    "legacy": {"grading_status": "graded",
               "gemini_verdict": {"decision": "clean", "reason": "no issues found"}},
    "pending": {"grading_status": "pending", "gemini_verdict": None},
    "injected": {
        "grading_status": "graded",
        "gemini_verdict": {"graded_by": "rules",
                           "evaluator_unavailable_reason":
                               "<img src=x onerror=alert(1)>"}},
}

#: Two rows through the REAL /v1/logs render path, so the wiring is witnessed
#: rather than grepped.
_LEDGER_ROWS = [
    {"id": "11111111-1111-4111-8111-111111111111", "seq": 2,
     "chain_hash": "b" * 64, "prompt_hash": "c" * 64, "response_hash": "d" * 64,
     "token_count": 40, "policy_tag": "hipaa", "agent": "intake",
     "pii_signals": [], "grading_status": "graded",
     "created_at": "2026-08-20T10:00:00Z", "event_type": "response",
     "gemini_verdict": {"decision": "clean", "reason": "no issues found",
                        "graded_by": "rules"}},
    {"id": "22222222-2222-4222-8222-222222222222", "seq": 1,
     "chain_hash": "e" * 64, "prompt_hash": "f" * 64, "response_hash": "a" * 64,
     "token_count": 31, "policy_tag": "gdpr", "agent": "intake",
     "pii_signals": [], "grading_status": "graded",
     "created_at": "2026-08-19T10:00:00Z", "event_type": "response",
     "gemini_verdict": {"decision": "clean", "reason": "no issues found"}},
]

#: ⚠ THE RESULT COMES BACK THROUGH `textContent`, NOT `innerHTML`, AND THAT IS
#: NOT TIDINESS. One row below carries `<img src=x onerror=alert(1)>` as an
#: evaluator reason — the whole point being that the page must escape it — and
#: writing the JSON report through `innerHTML` re-parses that payload as markup
#: inside the reporting <pre>. Headless Chrome then blocks on the modal alert and
#: `--dump-dom` never returns: the harness hangs and reports a timeout, which is
#: guard-lie #6, the harness failing the same way the defect would. Measured, not
#: reasoned about: it cost three minutes a run until it was found. `textContent`
#: keeps the report inert, `--dump-dom` re-escapes it, and `html.unescape` on the
#: Python side puts it back byte for byte.
#:
#: ⚠ AND THE LEDGER IS DRIVEN EXPLICITLY. `check()` runs at parse time of the main
#: module, before a probe appended to the end of the document can replace
#: `window.fetch`, so boot always finds the auth gate. The exported
#: `applyLedgerFilters()` reaches the same loadLogs -> ledgerRow path a signed-in
#: customer does.
_PROBE = r"""
<script>
(function(){
  /* A modal dialog stops headless Chrome dead and --dump-dom never returns, so
     the ESCAPING mutant would be killed by a three-minute timeout instead of by
     the assertion written for it — the harness failing the same way the defect
     does. Neutralised here so that guard fails as a guard. */
  window.alert=function(){}; window.confirm=function(){return true;};
  window.prompt=function(){return null;};
  var LOGS={items:__LOGS__,total:__LOGS_N__};
  window.fetch=function(url){
    url=String(url); var body={};
    if(url.indexOf('/v1/logs')===0) body=LOGS;
    else if(url.indexOf('/v1/auth/me')===0) body={email:'a@example.test',role:'admin'};
    else if(url.indexOf('/v1/stats')===0) body={total_logged:2,breaches:0,clean_rate:100,
      grading:{graded:2,pending:0,in_progress:0,failed:0},activity_7d:[],
      ai_graded:0,rules_graded:1};
    return Promise.resolve({ok:true,status:200,
      json:function(){return Promise.resolve(body);},clone:function(){return this;}});
  };
  window.addEventListener('load',function(){ setTimeout(async function(){
    var out={mix:{},by:{}};
    function read(html){
      var d=document.createElement('div'); d.innerHTML=html;
      var chip=d.querySelector('.gchip');
      return {html:html,text:d.textContent.replace(/\s+/g,' ').trim(),
              chip:chip?chip.textContent:null,
              unnamed:!!d.querySelector('.gchip.unnamed')};
    }
    try{
      var CASES=__CASES__;
      Object.keys(CASES).forEach(function(k){
        window.foxGradingMix(CASES[k]);
        out.mix[k]={rows:document.getElementById('polGradedMix').textContent.replace(/\s+/g,' ').trim(),
                    note:document.getElementById('polGradedNote').textContent.replace(/\s+/g,' ').trim()};
      });
      var ROWS=__ROWS__;
      Object.keys(ROWS).forEach(function(k){ out.by[k]=read(window.foxGradedBy(ROWS[k])); });
      window.applyLedgerFilters();
      await new Promise(function(r){setTimeout(r,150);});
      out.ledger=document.getElementById('ledgerBody').innerHTML;
      out.ledgerText=document.getElementById('ledgerBody').textContent.replace(/\s+/g,' ').trim();
    }catch(e){ out.error=String(e)+' | '+((e&&e.stack)||''); }
    var pre=document.createElement('pre'); pre.id='g228';
    pre.textContent=JSON.stringify(out);
    document.documentElement.innerHTML='';
    document.documentElement.appendChild(pre);
  },400); });
})();
</script>
"""


@lru_cache(maxsize=1)
def _render() -> dict:
    probe = (_PROBE.replace("__CASES__", json.dumps(MIX_CASES))
                   .replace("__ROWS__", json.dumps(BY_ROWS))
                   .replace("__LOGS__", json.dumps(_LEDGER_ROWS))
                   .replace("__LOGS_N__", str(len(_LEDGER_ROWS))))
    with tempfile.TemporaryDirectory() as tmp:
        page_file = pathlib.Path(tmp) / "probe.html"
        page_file.write_text(source() + probe, encoding="utf-8")
        args = [_CHROME, "--headless=new", "--disable-gpu", "--no-sandbox",
                "--hide-scrollbars", "--force-prefers-reduced-motion",
                "--virtual-time-budget=9000", "--window-size=1440,900",
                f"--user-data-dir={tmp}/prof", "--dump-dom", page_file.as_uri()]
        proc = subprocess.run(args, capture_output=True, text=True,
                              encoding="utf-8", errors="replace", timeout=180)
    hit = re.search(r'<pre id="g228">(.*?)</pre>', proc.stdout, re.S)
    assert hit, "the probe never ran; chrome said: %s" % proc.stderr[-500:]
    data = json.loads(unescape(hit.group(1)))
    assert not data.get("error"), data["error"]
    return data


@pytest.fixture(scope="module")
def rendered() -> dict:
    return _render()


@needs_chrome
def test_rendered_the_probe_actually_drove_the_page(rendered):
    """The control. Without it everything below could be measuring a page that
    never rendered and a function that was never called."""
    assert set(rendered["mix"]) == set(MIX_CASES)
    assert set(rendered["by"]) == set(BY_ROWS)
    assert rendered["mix"]["keyless"]["note"], "the note rendered empty"


@needs_chrome
def test_rendered_a_keyless_workspace_says_so(rendered):
    """The whole point of #228. Every verdict came from the rules engine and the
    page has to say so in its own words, as a fact rather than an apology."""
    case = rendered["mix"]["keyless"]
    note = case["note"].lower()
    assert "no event in this workspace has been graded by an ai model" in note
    assert "a statement about what happened, not a fault" in note
    # And it must not smuggle a ranking back in through the prose.
    assert "hashes, counts and policy tags" in note
    assert "semantic content was not evaluated" in note
    rows = _rows(case)
    assert "graded by an ai model 0" in rows
    assert "graded by deterministic rules only 12" in rows
    assert "graded records in total 12" in rows


@needs_chrome
def test_rendered_the_mixed_case_claims_neither_extreme(rendered):
    """#273's lesson, on this surface. A workspace holding both kinds is the
    realistic one, and it is the branch that reads as a self-contradiction if it
    borrows either absolute. Guarded in BOTH directions, because a mutant that
    collapses the branch lands on one of them."""
    note = rendered["mix"]["mixed"]["note"].lower()
    assert "no event in this workspace has been graded by an ai model" not in note, \
        "the mixed case printed the keyless absolute beside a non-zero AI count"
    assert "every graded event here was graded by a model" not in note, \
        "the mixed case claimed every event reached a model"
    assert "different kinds of evidence" in note
    assert "should be read knowing the mix" in note
    rows = _rows(rendered["mix"]["mixed"])
    assert "graded by an ai model 5" in rows
    assert "graded by deterministic rules only 7" in rows
    assert "neither of the above" not in rows,         "5 + 7 is the whole graded total; a remainder line appeared from nowhere"


@needs_chrome
def test_rendered_an_ai_only_workspace_says_only_that(rendered):
    note = rendered["mix"]["ai_only"]["note"].lower()
    assert "every graded event here was graded by a model" in note
    assert "no event in this workspace" not in note


@needs_chrome
def test_rendered_nothing_graded_attributes_nothing(rendered):
    """An honest empty state, not a zero dressed as a finding."""
    note = rendered["mix"]["nothing"]["note"].lower()
    assert "nothing has been graded yet" in note
    for claim in ("no event in this workspace has been graded by an ai model",
                  "every graded event here was graded by a model",
                  "different kinds of evidence"):
        assert claim not in note


@needs_chrome
def test_rendered_rows_with_no_recorded_grader_are_never_described_as_ai_or_rules(rendered):
    """Both counters at zero over six GRADED records — host enforcement, or rows
    written before this workspace stored the grader. It must not read as "nothing
    has been graded", and it must not attribute them to anything."""
    case = rendered["mix"]["legacy"]
    note = case["note"].lower()
    assert "nothing here infers a grader for any of them" in note
    assert "recorded before this workspace began storing the grader" in note
    assert "nothing has been graded yet" not in note
    for claim in ("no event in this workspace has been graded by an ai model",
                  "every graded event here was graded by a model"):
        assert claim not in note
    assert "neither of the above 6" in _rows(case)


@needs_chrome
def test_rendered_the_keyless_sentence_survives_alongside_unattributed_rows(rendered):
    """Rules-graded rows AND rows carrying no grader. The absolute is still true
    of what IS attributed, and the unattributed ones get their own sentence rather
    than being folded into it."""
    note = rendered["mix"]["keyless_with_legacy"]["note"].lower()
    assert "no event in this workspace has been graded by an ai model" in note
    assert "nothing here infers a grader for any of them" in note


@needs_chrome
def test_rendered_a_failed_request_states_nothing_about_grading(rendered):
    """"We could not ask" and "nothing graded these" are different facts, and
    rendering the first as the second is how a surface starts lying."""
    case = rendered["mix"]["unreachable"]
    note = case["note"].lower()
    assert "could not reach the server" in note
    for claim in ("graded by an ai model", "deterministic rules",
                  "nothing has been graded yet"):
        assert claim not in note
    assert "could not read your records" in case["rows"].lower()


@needs_chrome
def test_rendered_each_grader_gets_its_own_word(rendered):
    by = rendered["by"]
    assert by["ai"]["chip"] == "AI model"
    assert "gemini" in by["ai"]["text"].lower()
    assert by["rules"]["chip"] == "deterministic rules"
    assert by["host"]["chip"] == "host enforcement"
    assert by["none"]["chip"] == "nothing"
    # Named authors are peers; only the two non-grades step back.
    assert by["ai"]["unnamed"] is False
    assert by["rules"]["unnamed"] is False
    assert by["host"]["unnamed"] is False
    assert by["none"]["unnamed"] is True


@needs_chrome
def test_rendered_a_rules_graded_record_is_never_shown_as_ai_graded(rendered):
    """The mutation this file exists to kill. It must also not read as a worse
    grade: the sentence beside the chip says what the rules engine reasons over
    and what it did not evaluate."""
    row = rendered["by"]["rules"]
    assert "AI model" not in row["html"]
    text = row["text"].lower()
    assert "hashes, counts and policy tags" in text
    assert "no model produced this verdict" in text


@needs_chrome
def test_rendered_a_record_with_no_grader_carries_no_claim(rendered):
    """`graded_by` absent means NOT RECORDED. Rows written before this workspace
    stored the grader carry it, nothing backfills them, and "not graded by an AI"
    over one would be manufacturing the evidence."""
    row = rendered["by"]["legacy"]
    assert row["chip"] == "not recorded"
    assert row["unnamed"] is True
    text = row["text"].lower()
    assert "the ledger holds no grader for this record" in text
    assert "nothing here infers one" in text
    for claim in ("ai model", "deterministic rules", "host enforcement",
                  "not graded by"):
        assert claim not in text


@needs_chrome
def test_rendered_a_record_that_is_not_graded_yet_gets_no_line(rendered):
    """"Pending" is already on the line above. "Not recorded" over it would
    describe a fact that has simply not happened yet."""
    assert rendered["by"]["pending"]["html"] == ""


@needs_chrome
def test_rendered_the_unavailable_reason_rides_through_and_is_escaped(rendered):
    """The structured reason is the actionable half — "graded by rules" and
    "graded by rules BECAUSE THIS TENANT'S KEY WOULD NOT DECRYPT" are different
    facts. It comes off the wire, so it is escaped."""
    assert "no model was reached: no_api_key" in \
        rendered["by"]["rules_unavailable"]["text"]
    injected = rendered["by"]["injected"]
    assert "<img" not in injected["html"], "an evaluator reason reached the DOM as markup"
    assert "onerror" in injected["text"], "the reason was dropped rather than escaped"


@needs_chrome
def test_rendered_the_ledger_detail_shows_the_grader_for_real_rows(rendered):
    """Driven through the real /v1/logs render path, so this witnesses the wiring
    rather than the definition. One rules-graded row and one written before the
    field existed — and the second must not borrow the first's word."""
    html = rendered["ledger"]
    assert 'class="gchip"' in html, "no provenance chip reached a rendered ledger row"
    text = rendered["ledgerText"].lower()
    assert "deterministic rules" in text
    assert "not recorded" in text
    assert "not graded by" not in text
