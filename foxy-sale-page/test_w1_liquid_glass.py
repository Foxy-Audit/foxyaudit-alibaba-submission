"""W1 — the liquid-glass hero, guarded.

The hero's card is no longer a tinted rectangle with a blur behind it: its
`backdrop-filter` runs an inline SVG refraction pipeline (`#hero-glass`) that
displaces the ground as it passes through the glass. That is the whole point of
the design, and it is held together by four things that are each individually
easy to break without anything looking obviously wrong in a diff:

  · **the filter and its reference.** Rename the `<filter>` id, or drop the SVG,
    and `backdrop-filter: url(#hero-glass)` silently resolves to nothing. The
    card does not fall back to a blur — it becomes plain glass. No error, no
    console warning, and a screenshot taken during the 640ms settle still looks
    plausible.

  · **declaration order.** `-webkit-backdrop-filter: blur(…)` must stay ABOVE
    `backdrop-filter: url(…)`, because the fallback works by being the last
    declaration a browser without SVG-filter backdrops understands. Reorder them
    and Safari/Firefox lose the fill entirely. Chrome aliases the two properties
    onto one another, so the CSSOM cannot answer this — see the test.

  · **the ground.** The stage carries a fixed gradient plus four drifting blobs.
    `render()` used to write a per-slide accent wash onto `stageEl.style`; the
    approved look only ever appeared because a later stylesheet outgunned it
    with `!important`. That write is gone, and this file keeps it gone — a dead
    line that "works" because something else beats it is a trap for the next
    person, who will delete the stylesheet and not the line.

  · **the cost.** Thirteen cards each forcing a render surface for an animated
    displacement map measured 11.1ms/frame median (16.7ms p95 — already missing
    60Hz) on an RTX 5060 Ti. Only the three cards you can see refract now; the
    other ten sit at opacity 0 behind the centre one with a plain blur. That is
    5.6ms median / 5.7ms p95. If a later change hands the filter back to all
    thirteen the picture is identical and the frame budget doubles, so the count
    is asserted rather than trusted.

WHY THE AT-RULES ARE READ FROM THE CSSOM AND NOT THE SOURCE

Twice this month a guard that grepped source text for an `@media` block stayed
green over a stylesheet the browser had already given up on: a comment that
closes early swallows the rule that follows it, and the source text and the brace
count both still look correct. `_cssom()` asks the browser which rules actually
parsed. For the same reason the JS claims below strip comments before searching —
this file's own explanatory comments name `--dim`, `.card:not(.is-center)` and
`backdrop-filter`, and a naive grep is answered by the comment rather than the
code.

Run:  pytest foxy-sale-page -q
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

_HERE = pathlib.Path(__file__).resolve().parent
SRC = (_HERE / "index.html").read_text(encoding="utf-8")

#: The approved refraction pipeline, as literal markup. These came from the
#: artifact the owner signed off in Chrome; they are not tuning knobs.
APPROVED_PIPELINE = (
    'baseFrequency="0.007 0.011"',
    'numOctaves="2"',
    'seed="7"',
    'scale="46"',
    'stdDeviation="2.5"',
    'type="saturate" values="1.45"',
    'dur="22s"',
)


# ── source helpers ───────────────────────────────────────────────────────────

def _strip_comments(s: str) -> str:
    """Drop /*…*/ and //… so a guard cannot be answered by prose.

    `//` is only treated as a comment when it does not follow a colon, so the
    `https://` inside string literals survives.
    """
    s = re.sub(r"/\*.*?\*/", " ", s, flags=re.S)
    return re.sub(r"(?<!:)//[^\n]*", " ", s)


def _js() -> str:
    """The page's inline script, comment-stripped. The page has exactly one."""
    blocks = re.findall(r"<script(?![^>]*\bsrc=)[^>]*>(.*?)</script>", SRC, re.S)
    assert len(blocks) == 1, f"expected one inline <script>, found {len(blocks)}"
    return _strip_comments(blocks[0])


def _css_rule(selector: str) -> str:
    """One rule's source text, brace-matched and comment-stripped.

    Anchored on the selector standing alone before its brace, so asking for
    `.card` is not answered by `.card.is-center` sitting a few lines below.
    """
    css = _strip_comments(re.search(r"<style[^>]*>(.*?)</style>", SRC, re.S).group(1))
    m = re.search(r"(?m)^\s*" + re.escape(selector) + r"\s*\{", css)
    assert m, f"no source rule for {selector}"
    depth, i = 0, css.index("{", m.start())
    while True:
        if css[i] == "{":
            depth += 1
        elif css[i] == "}":
            depth -= 1
            if depth == 0:
                return css[m.start():i + 1]
        i += 1
        assert i < len(css), f"unbalanced braces in {selector}"


def _js_function(name: str) -> str:
    """A function's body by brace matching. A window is not a scope: an
    unbounded slice from `function reflect` to the next blank line is answered
    by whatever happens to sit below it."""
    js = _js()
    start = js.index(f"function {name}(")
    depth, i = 0, js.index("{", start)
    body_start = i
    while True:
        if js[i] == "{":
            depth += 1
        elif js[i] == "}":
            depth -= 1
            if depth == 0:
                return js[body_start:i + 1]
        i += 1
        assert i < len(js), f"unbalanced braces in {name}()"


# ── the browser, once ────────────────────────────────────────────────────────

_CHROME = (os.environ.get("CHROME_BIN")
           or shutil.which("chrome") or shutil.which("google-chrome")
           or next((p for p in (
               r"C:\Program Files\Google\Chrome\Application\chrome.exe",
               r"C:\Program Files (x86)\Google\Chrome\Application\chrome.exe",
           ) if pathlib.Path(p).exists()), None))

needs_chrome = pytest.mark.skipif(_CHROME is None, reason="Chrome not available")

_PROBE = r"""
(function(){
  var out={};
  function sheets(fn){ [].forEach.call(document.styleSheets,function(sh){
    var rules; try{ rules=sh.cssRules; }catch(e){ return; }
    [].forEach.call(rules, fn); }); }

  // Rules the browser ACTUALLY parsed inside an @media block, keyed by selector.
  function media(needle){
    var got={};
    sheets(function(r){
      if(r instanceof CSSMediaRule && r.conditionText.indexOf(needle)>=0)
        [].forEach.call(r.cssRules,function(x){ got[x.selectorText]=x.style.cssText; });
    });
    return got;
  }
  out.reduced = media('prefers-reduced-motion');
  out.forced  = media('forced-colors');

  // The .card rule's own text, so declaration ORDER can be read back.
  sheets(function(r){ if(r.selectorText === '.card') out.cardRule = r.cssText; });

  out.filterEl = !!document.getElementById('hero-glass');
  out.blobs = document.querySelectorAll('.stage > .blob').length;

  var center = document.querySelector('.card.is-center');
  out.centerBackdrop = getComputedStyle(center).backdropFilter;
  out.refracting = [].filter.call(document.querySelectorAll('.card'), function(c){
    return getComputedStyle(c).backdropFilter.indexOf('url(') === 0; }).length;
  out.cards = document.querySelectorAll('.card').length;
  var back = document.querySelector('.card.is-back');
  out.backBackdrop = back ? getComputedStyle(back).backdropFilter : 'NO-BACK-CARD';

  // Reflections must be placed by layout(), not polled. Kill rAF, move the
  // carousel, and check they followed anyway.
  window.requestAnimationFrame = function(){ return 0; };
  var n = document.querySelectorAll('.card').length;
  goTo((typeof active === 'number' ? active : 0) + 2 >= n ? 0 : active + 2);
  setTimeout(function(){
    var refls = document.querySelectorAll('.card-refl');
    out.tracked = [].map.call(document.querySelectorAll('.card'), function(c,i){
      var r = refls[i]; if(!r) return 'MISSING';
      return (r.style.left === (c.style.left || '50%')
              && r.style.height === c.style.height
              && r.style.transform.indexOf('scaleY(-1)') > 0
              && Math.abs(parseFloat(r.style.opacity)
                          - parseFloat(c.style.opacity || 0) * 0.34) < 0.002);
    });
    out.reflCount = refls.length;
    out.lensCount = document.querySelectorAll('.card .card-lens').length;
    document.documentElement.innerHTML =
      '<pre id="p">' + JSON.stringify(out) + '</pre>';
  }, 900);
})();
"""

_cache: dict = {}


@pytest.fixture(scope="module")
def rendered():
    """index.html in a real browser, once. The probe is appended to a COPY, so
    the page that reaches a customer stays exactly as shipped."""
    if "d" in _cache:
        return _cache["d"]
    with tempfile.TemporaryDirectory() as tmp:
        page = pathlib.Path(tmp) / "index.html"
        page.write_text(
            SRC + "\n<script>window.addEventListener('load',function(){setTimeout("
                  "function(){try{" + _PROBE + "}catch(e){document.documentElement.innerHTML="
                  "'<pre id=\"p\">'+JSON.stringify({error:String(e)})+'</pre>';}},1500);});</script>",
            encoding="utf-8")
        # Bounded, and it kills only THIS process. Never taskkill chrome by name:
        # that closes the browser the person at the keyboard is using.
        proc = subprocess.run(
            [_CHROME, "--headless=new", "--no-sandbox",
             "--virtual-time-budget=12000", "--window-size=1440,900",
             f"--user-data-dir={tmp}/prof", "--dump-dom", page.as_uri()],
            capture_output=True, text=True, encoding="utf-8", errors="replace",
            timeout=180)
    m = re.search(r'<pre id="p">(.*?)</pre>', proc.stdout, re.S)
    assert m, f"the probe never ran; chrome said: {proc.stderr[-500:]}"
    data = json.loads(m.group(1))
    assert not data.get("error"), data["error"]
    _cache["d"] = data
    return data


# ── 1 · the refraction pipeline itself ───────────────────────────────────────

def test_the_refraction_filter_is_inline_and_declares_the_approved_pipeline():
    filters = re.findall(r'<filter\s+id="hero-glass".*?</filter>', SRC, re.S)
    assert len(filters) == 1, f"expected exactly one #hero-glass filter, got {len(filters)}"
    block = filters[0]
    for fragment in APPROVED_PIPELINE:
        assert fragment in block, (
            f"{fragment} is missing from #hero-glass — the pipeline values are "
            f"the approved ones and are not tuning knobs")
    # It must live inside the hero, and it must cost nothing to fetch.
    stage = SRC[SRC.index('<div class="stage"'):SRC.index('<div class="grain">')]
    assert '<filter id="hero-glass"' in stage, "the filter must sit inside .stage"
    assert "http" not in stage, "the hero must not add an external request"


def test_the_card_references_the_filter_by_that_exact_id():
    js_and_css = _strip_comments(SRC)
    assert "backdrop-filter:url(#hero-glass)" in js_and_css.replace(" ", ""), (
        "the card no longer references #hero-glass — a renamed filter resolves to "
        "nothing and the card silently becomes plain glass")


# ── 2 · the ground ───────────────────────────────────────────────────────────

def test_four_blobs_are_real_markup_rather_than_injected_by_script():
    stage = SRC[SRC.index('<div class="stage"'):SRC.index('<div class="grain">')]
    assert len(re.findall(r'<div class="blob blob-\d"></div>', stage)) == 4
    # nothing anywhere may manufacture one — the demo injected them from script
    assert "blob" not in _js(), (
        "blobs are markup; a script that creates them has crept back in")


def test_the_per_slide_stage_wash_is_gone_not_merely_overridden():
    js = _js()
    assert "stageEl.style.background" not in js, (
        "render() is writing the stage background inline again. In the demo this "
        "line only looked harmless because an !important stylesheet beat it.")
    assert "radial-gradient(closest-side" not in js, (
        "the per-slide accent wash is back in script")


# ── 3 · what the approval removed ────────────────────────────────────────────

def test_nothing_drags_the_stage():
    js = _js()
    for token in ("pointerdown", "mousedown", "dragstart", "draggable"):
        assert token not in js, f"drag was cut from this design; {token!r} is back"


def test_the_orphaned_accent_property_is_fully_gone():
    text = _strip_comments(SRC)
    assert "--dim" not in text, (
        "--dim lost its only consumer with the accent border; both halves of the "
        "plumbing go, or neither")
    # its siblings kept real consumers and must survive
    for live in ("--acc", "--glow", "--soft"):
        assert live in text, f"{live} still dresses the card icon and must stay"


# ── 4 · reflections are laid out, not polled ─────────────────────────────────

def test_no_frame_loop_drives_the_reflections():
    for fn in ("reflect", "layout", "settle"):
        assert "requestAnimationFrame" not in _js_function(fn), (
            f"{fn}() polls the frame clock; reflections are positioned in the "
            f"same pass that positions the cards")
    assert "reflect(i, card)" in _js_function("layout"), (
        "layout() no longer places the reflections")


@needs_chrome
def test_reflections_follow_the_cards_with_the_frame_clock_disabled(rendered):
    assert rendered["reflCount"] == rendered["cards"], "one reflection per card"
    assert rendered["lensCount"] == rendered["cards"], "one lens per card"
    bad = [i for i, ok in enumerate(rendered["tracked"]) if ok is not True]
    assert not bad, (
        f"cards {bad} left their reflection behind after requestAnimationFrame "
        f"was disabled — something still depends on a frame loop")


# ── 5 · the cascade, as the browser actually parsed it ───────────────────────

def test_the_webkit_fallback_is_declared_before_the_url_line():
    """⚠ THIS ONE CANNOT COME FROM THE CSSOM, and the obvious version did.

    Chrome treats `-webkit-backdrop-filter` as an alias of `backdrop-filter`
    rather than a separate property, so by the time the rule reaches
    `CSSStyleRule.cssText` the two declarations have collapsed into whichever
    came last and the order this test exists to check is gone — measured: the
    CSSOM version of this test reported the fallback "missing" from a rule that
    plainly declares it. The order is only observable in the source, so the rule
    is brace-matched out of the stylesheet instead.
    """
    rule = _css_rule(".card")
    webkit = rule.find("-webkit-backdrop-filter:")
    # '-webkit-backdrop-filter' CONTAINS 'backdrop-filter', so anchor the search.
    standard = re.search(r"[;{]\s*backdrop-filter:", rule)
    assert webkit >= 0, "the Safari/Firefox fallback is gone from .card"
    assert standard, "the standard backdrop-filter is gone from .card"
    assert webkit < standard.start(), (
        "the -webkit- fallback must come FIRST. Last supported declaration wins, "
        "so this order is the only thing keeping the fill in browsers without "
        "SVG-filter backdrops")


@needs_chrome
def test_the_reduced_motion_block_survived_the_cascade(rendered):
    r = rendered["reduced"]
    assert r, "no prefers-reduced-motion rules reached the CSSOM"
    assert "none" in r.get(".blob", ""), "blobs still drift under reduced motion"
    hidden = next((v for k, v in r.items() if "card-refl" in k and "card-lens" in k), "")
    assert "display: none" in hidden, "lens/reflection not hidden under reduced motion"
    card = next((v for k, v in r.items() if k.startswith(".card")
                 and "backdrop-filter" in v), "")
    assert card and "url(" not in card, (
        "the card must fall back to a still blur — the turbulence in #hero-glass "
        "animates and cannot be paused per element")


@needs_chrome
def test_the_forced_colors_block_survived_the_cascade(rendered):
    f = rendered["forced"]
    assert f, "no forced-colors rules reached the CSSOM"
    hidden = next((v for k, v in f.items() if "blob" in k), "")
    assert "display: none" in hidden, "decoration is not hidden in High Contrast"
    # the CSSOM lower-cases system colours, so compare case-insensitively
    card = next((v for k, v in f.items() if k.strip() == ".card"), "").lower()
    assert "buttonborder" in card, (
        "the card is border:none and High Contrast drops every shadow on this "
        "page, so without a system-colour border it has no edge at all")


# ── 6 · the frame budget ─────────────────────────────────────────────────────

@needs_chrome
def test_only_the_three_visible_cards_refract(rendered):
    assert rendered["filterEl"], "#hero-glass is not in the document"
    assert rendered["blobs"] == 4
    assert rendered["centerBackdrop"].startswith("url("), (
        "the centre card must refract; that is the design")
    assert rendered["refracting"] == 3, (
        f"{rendered['refracting']} of {rendered['cards']} cards are running the "
        f"refraction. Only centre/left/right are visible; handing the filter to "
        f"all of them measured 11.1ms/frame against 5.6ms, for the same picture")
    assert rendered["backBackdrop"].startswith("blur("), (
        "back cards must carry the plain blur fallback")
