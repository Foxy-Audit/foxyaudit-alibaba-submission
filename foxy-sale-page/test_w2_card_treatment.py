"""W2 — the approved card treatment, guarded.

W2 replaced W1's frosted refraction with clear glass: the card's pipeline lost
its blur primitive by owner decision (0% frost), the six-shadow rim became a
machined conic ring, the cursor lens and the ember were cut, and every card
gained a folio counter, a live marble texture and its slide's own CTA label.
The theme is the MASTER for every sale sub-page: its values live as --thm-*
tokens on :root, so a sub-page adopts the treatment by inheriting tokens.

What this file pins, and why each would fail silently without it:

  · **the absence of frost.** A well-meaning "readability fix" that re-adds
    feGaussianBlur to #hero-glass reverts the owner's central decision, and no
    screenshot comparison catches a 2.5px blur reliably.

  · **the dead code stays dead.** .card-lens and .thm-ember both existed in the
    demo as display:none nodes — thirteen of each, built every frame by a rAF
    dress() loop. The production page ships neither the elements nor the CSS.

  · **ripples live on the glass.** The band is appended INSIDE a .card so the
    card's own overflow clips it. Reparented to the stage it still *looks*
    right at rest — until one expands past a card edge as a floating ring.

  · **the tokens are the contract.** Sub-pages inherit --thm-*; a value moved
    inline breaks the master-theme mechanism invisibly on THIS page.

WHY THE AT-RULES AND RULE BODIES ARE READ FROM THE CSSOM

A comment that closes early swallows the rule after it while the source text
and the brace count both look correct — nine instances this fortnight. Every
CSS assertion here asks the browser what it parsed (cssRules), never the file
what it says. The two exceptions are deliberate: SVG filter markup is not CSS
(the CSSOM never sees it), and JS claims strip comments first because this
file's own comments name the very tokens being asserted absent.

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

#: The theme master's tokens, exactly as the owner approved them. Sub-pages
#: inherit these; the three with no consumer on index.html yet (--thm-rim,
#: --thm-flare, --thm-ripple) are part of the vocabulary and must stay.
THEME_TOKENS = {
    "--thm-fill-a": "rgba(255,255,255,.055)",
    "--thm-fill-b": "rgba(255,255,255,.012)",
    "--thm-rim": "rgba(255,255,255,.42)",
    "--thm-flare": "rgba(255,255,255,.85)",
    "--thm-ripple": "rgba(200,212,255,.20)",
    "--thm-chrome": "rgba(14,13,20,.66)",
    "--thm-chrome-line": "rgba(255,255,255,.12)",
    "--thm-ink": "rgba(244,246,252,.92)",
    "--thm-ink-soft": "rgba(226,230,240,.62)",
}


def _strip_comments(s: str) -> str:
    s = re.sub(r"/\*.*?\*/", " ", s, flags=re.S)
    return re.sub(r"(?<!:)//[^\n]*", " ", s)


def _js() -> str:
    blocks = re.findall(r"<script(?![^>]*\bsrc=)[^>]*>(.*?)</script>", SRC, re.S)
    assert len(blocks) == 1, f"expected one inline <script>, found {len(blocks)}"
    return _strip_comments(blocks[0])


def _filter_block(fid: str) -> str:
    """One <filter>'s markup. SVG is not CSS — the CSSOM never sees it, so the
    source is the only witness. Non-greedy stops at the filter's own close."""
    blocks = re.findall(rf'<filter\s+id="{fid}".*?</filter>', SRC, re.S)
    assert len(blocks) == 1, f"expected exactly one #{fid}, got {len(blocks)}"
    return blocks[0]


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

  // rule bodies, as parsed — for var() consumption and the color-mix eyebrow
  out.rules = {};
  sheets(function(r){
    if(!r.selectorText) return;
    if([':root','.topnav','.card-eyebrow','.thm-dots','.card','.card-hint',
        '.thm-ripple','footer'].indexOf(r.selectorText)>=0)
      out.rules[r.selectorText]=r.cssText;
    if(r.selectorText==='.card .card-body') out.rules['.card .card-body']=r.cssText;
  });

  var cs=getComputedStyle(document.documentElement);
  out.tokens={};
  ['--thm-fill-a','--thm-fill-b','--thm-rim','--thm-flare','--thm-ripple',
   '--thm-chrome','--thm-chrome-line','--thm-ink','--thm-ink-soft']
    .forEach(function(t){ out.tokens[t]=cs.getPropertyValue(t).trim(); });

  out.counts={
    cards:document.querySelectorAll('.card').length,
    rings:document.querySelectorAll('.card > .thm-ring').length,
    faces:document.querySelectorAll('.card > .thm-face').length,
    dots:document.querySelectorAll('.card > .thm-dots').length,
    lens:document.querySelectorAll('.card-lens').length,
    ember:document.querySelectorAll('.thm-ember').length};

  var center=document.querySelector('.card.is-center');
  out.centerBackdrop=getComputedStyle(center).backdropFilter;
  var back=document.querySelector('.card.is-back');
  out.backBackdrop=back?getComputedStyle(back).backdropFilter:'NO-BACK-CARD';
  out.dotsComputed={opacity:getComputedStyle(document.querySelector('.thm-dots')).opacity,
    filter:getComputedStyle(document.querySelector('.card.is-center .thm-dots')).filter};
  out.sideDotsFilter=getComputedStyle(
    document.querySelector('.card:not(.is-center) .thm-dots')).filter;
  out.folio=getComputedStyle(document.querySelector('.thm-face'),'::after').content;
  out.bodyTransition=getComputedStyle(center.querySelector('.card-body')).transitionProperty
    +' | '+getComputedStyle(center.querySelector('.card-body')).transitionDuration;

  // every hint carries its slide's own CTA label
  out.hints=[].map.call(document.querySelectorAll('.card .card-hint'),
    function(h){ return h.textContent; });
  out.ctaLabels=(typeof SLIDES!=='undefined')
    ? SLIDES.map(function(s){ return s && s.ctaLabel; }) : 'NO-SLIDES';

  // ── ripple behaviour, exercised for real ──────────────────────────────
  function move(el,x,y){ el.dispatchEvent(new PointerEvent('pointermove',
    {clientX:x,clientY:y,bubbles:true})); }
  var b=center.getBoundingClientRect();
  move(center, b.left+b.width/2, b.top+b.height/2);
  var first=center.querySelectorAll('.thm-ripple').length;
  move(center, b.left+b.width/3, b.top+b.height/3);   // same tick -> throttled
  var second=center.querySelectorAll('.thm-ripple').length;
  var stage=document.getElementById('stage');
  move(stage, 8, Math.round(innerHeight/2));           // bare stage -> nothing
  var r=document.querySelector('.thm-ripple');
  out.ripple={afterFirst:first, afterSecond:second,
    total:document.querySelectorAll('.thm-ripple').length,
    parentIsCard:!!(r && r.parentElement.classList.contains('card')),
    strays:[].filter.call(document.querySelectorAll('.thm-ripple'),
      function(x){ return !x.parentElement.classList.contains('card'); }).length};

  document.documentElement.innerHTML='<pre id="p">'+JSON.stringify(out)+'</pre>';
})();
"""

_cache: dict = {}


@pytest.fixture(scope="module")
def rendered():
    """index.html in a real browser, once; the probe rides a COPY."""
    if "d" in _cache:
        return _cache["d"]
    with tempfile.TemporaryDirectory() as tmp:
        page = pathlib.Path(tmp) / "index.html"
        page.write_text(
            SRC + "\n<script>window.addEventListener('load',function(){setTimeout("
                  "function(){try{" + _PROBE + "}catch(e){document.documentElement.innerHTML="
                  "'<pre id=\"p\">'+JSON.stringify({error:String(e)})+'</pre>';}},1500);});</script>",
            encoding="utf-8")
        # Bounded, and it kills only THIS process — never taskkill chrome by name.
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


# ── 1 · zero frost ───────────────────────────────────────────────────────────

def test_the_card_pipeline_has_no_blur_primitive():
    glass = _filter_block("hero-glass")
    assert "feGaussianBlur" not in glass, (
        "the frost is back. The owner cut the blur primitive from the card "
        "pipeline — the backdrop must stay readable straight through the plate")
    # the pipeline is exactly turbulence -> displacement -> saturate
    prims = re.findall(r"<fe([A-Za-z]+)", glass)
    assert prims == ["Turbulence", "DisplacementMap", "ColorMatrix"], (
        f"#hero-glass grew a primitive: {prims}")


def test_the_icon_and_marble_filters_exist_and_only_displace():
    for fid in ("hero-water", "hero-marble"):
        block = _filter_block(fid)
        prims = re.findall(r"<fe([A-Za-z]+)", block)
        assert prims == ["Turbulence", "DisplacementMap"], (
            f"#{fid} should be turbulence -> displacement only, got {prims}")


def test_the_marble_is_live():
    """The owner's addition on top of the approved spec: the texture is not a
    static pattern pushed around — its turbulence drifts AND its displacement
    scale breathes, so the marble keeps re-forming."""
    marble = _filter_block("hero-marble")
    animates = re.findall(r'attributeName="([^"]+)"', marble)
    assert "baseFrequency" in animates, "the marble's turbulence no longer drifts"
    assert "scale" in animates, (
        "the marble's displacement no longer breathes (scale 8→11→8) — the "
        "texture was made live by owner decision, not merely displaced")


# ── 2 · the dead code stays dead ─────────────────────────────────────────────

def test_no_cursor_lens_anywhere():
    text = _strip_comments(SRC)
    for token in ("card-lens", "--mx", "--my"):
        assert token not in text, (
            f"{token!r} is back. The cursor glow was cut by owner decision — "
            f"element, CSS and the pointermove writer all went together")


def test_no_ember_anywhere():
    assert "thm-ember" not in _strip_comments(SRC), (
        "the foot glow was cut; .thm-ember must not ship even as display:none")


@needs_chrome
def test_the_dom_carries_no_dead_layers(rendered):
    c = rendered["counts"]
    assert c["lens"] == 0 and c["ember"] == 0, (
        f"dead layers in the DOM: {c['lens']} lenses, {c['ember']} embers")


# ── 3 · the theme layers are template, not afterthought ──────────────────────

def test_no_frame_loop_dresses_the_cards():
    js = _js()
    m = re.search(r"function buildCards\(", js)
    assert m, "buildCards() is gone"
    # the demo's dress() re-ran on every frame; production builds layers once
    assert "function dress(" not in js, "the demo's rAF dress() loop is back"
    for cls in ("thm-dots", "thm-face", "thm-ring"):
        assert f'<div class="{cls}"></div>' in js, (
            f".{cls} is no longer part of the card template")


@needs_chrome
def test_every_card_carries_its_three_layers_once(rendered):
    c = rendered["counts"]
    assert c["cards"] > 0
    assert c["rings"] == c["cards"], f"rings {c['rings']} != cards {c['cards']}"
    assert c["faces"] == c["cards"], f"faces {c['faces']} != cards {c['cards']}"
    assert c["dots"] == c["cards"], f"dots {c['dots']} != cards {c['cards']}"


@needs_chrome
def test_the_folio_counts_the_cards(rendered):
    assert "thm-card" in rendered["folio"] and "decimal-leading-zero" in rendered["folio"], (
        f"the folio counter is gone from .thm-face::after: {rendered['folio']}")


# ── 4 · the marble is subliminal and the fallbacks are plain ─────────────────

@needs_chrome
def test_the_marble_stays_subliminal(rendered):
    assert rendered["dotsComputed"]["opacity"] == "0.05", (
        f"the marble is at {rendered['dotsComputed']['opacity']} — it is "
        f"DELIBERATELY nearly subliminal at .05; do not brighten it")
    assert 'url("#hero-marble")' in rendered["dotsComputed"]["filter"], (
        "the texture no longer flows through its live filter")


@needs_chrome
def test_only_the_centre_texture_flows(rendered):
    """The pre-approved perf mitigation, pinned. Thirteen live marble filters
    — ten inside opacity-0 cards — measured 30.4ms/frame median (94.5ms p95)
    on an RTX 5060 Ti; centre-only is 11.1ms / 16.7ms p95. Hand the water back
    to all thirteen and the picture is identical while the frame time trebles."""
    assert 'url("#hero-marble")' in rendered["dotsComputed"]["filter"], (
        "the centre card's marble must flow; that is the treatment")
    assert rendered["sideDotsFilter"] == "none", (
        f"a non-centre card's texture is running the marble filter "
        f"({rendered['sideDotsFilter']}) — twelve invisible waters measured "
        f"30.4ms/frame against 11.1ms for the same picture")


@needs_chrome
def test_back_cards_carry_the_plain_saturate(rendered):
    assert rendered["centerBackdrop"].startswith("url("), "the centre must refract"
    assert rendered["backBackdrop"] == "saturate(1.3)", (
        f"back cards should carry saturate(1.3), got {rendered['backBackdrop']}")


# ── 5 · the hint is the slide's own CTA ──────────────────────────────────────

@needs_chrome
def test_each_hint_is_its_slides_cta_label(rendered):
    labels = rendered["ctaLabels"]
    assert isinstance(labels, list), "SLIDES was not reachable from the probe"
    hints = rendered["hints"]
    assert len(hints) == len(labels)
    bad = [(i, h, l) for i, (h, l) in enumerate(zip(hints, labels))
           if l and h != l]
    assert not bad, (
        f"hints that do not carry their slide's ctaLabel: {bad[:3]} — the "
        f"generic 'Tap to explore' is only the fallback for a slide without one")


# ── 6 · ripples live on the glass ────────────────────────────────────────────

@needs_chrome
def test_ripples_spawn_on_cards_throttled_and_nowhere_else(rendered):
    r = rendered["ripple"]
    assert r["afterFirst"] == 1, "a pointermove over the card spawned no ripple"
    assert r["afterSecond"] == 1, (
        "two moves in the same tick spawned two ripples — the 650ms throttle "
        "is gone, and a busy pointer would carpet the card in bands")
    assert r["parentIsCard"], (
        "the ripple is not a child of the card — outside it, the card's "
        "overflow cannot clip the band and it expands past the edge")
    assert r["strays"] == 0, "a ripple appeared outside any card"
    assert r["total"] == 1, "the bare stage spawned a ripple; water is card-only"


@needs_chrome
def test_the_ripple_is_a_water_band_not_a_white_ring(rendered):
    assert "thm-ripple" in _js(), "the ripple spawner is gone from the script"
    rule = rendered["rules"].get(".thm-ripple", "")
    # a water band is a light crest OUTSIDE a dark trough; a white ring is
    # exactly the wrong reading of the reference and was rejected
    assert "rgba(150, 195, 235" in rule and "rgba(30, 60, 105" in rule, (
        f"the ripple lost its crest/trough pair — it must read as a water "
        f"band, not a white ring: {rule[:200]}")


# ── 7 · the tokens are the contract ──────────────────────────────────────────

@needs_chrome
def test_the_master_tokens_live_on_root(rendered):
    for name, value in THEME_TOKENS.items():
        got = rendered["tokens"].get(name, "")
        assert got == value, (
            f"{name} is {got!r}, approved {value!r} — the theme is the master "
            f"for every sale sub-page; its values live on :root, nowhere else")


@needs_chrome
def test_the_chrome_consumes_the_tokens_not_literals(rendered):
    topnav = rendered["rules"].get(".topnav", "")
    assert "var(--thm-chrome)" in topnav and "var(--thm-chrome-line)" in topnav, (
        "the topnav no longer reads the theme tokens — a literal copy breaks "
        "the master-theme contract even when the colour happens to match")
    footer = rendered["rules"].get("footer", "")
    assert "var(--thm-chrome-line)" in footer, "the footer hairline left the tokens"


@needs_chrome
def test_the_eyebrow_is_accent_tinted(rendered):
    rule = rendered["rules"].get(".card-eyebrow", "")
    assert "color-mix(" in rule and "var(--acc" in rule, (
        "the eyebrow is no longer tinted from the card's own accent")


# ── 8 · the settle and the floors, as parsed ─────────────────────────────────

@needs_chrome
def test_the_body_settles_instead_of_snapping(rendered):
    body = rendered["rules"].get(".card .card-body", "")
    assert "transform 0.55s" in body and "opacity 0.55s" in body, (
        "the .55s body settle is gone. ⚠ In the approved demo this transition "
        "was silently eaten by a higher-specificity rule and the body SNAPPED "
        "— the spec's written intent is the transition, not the accident")
    assert "transform" in rendered["bodyTransition"], (
        f"computed transition lost transform: {rendered['bodyTransition']}")


@needs_chrome
def test_reduced_motion_stills_every_water(rendered):
    r = rendered["reduced"]
    assert r, "no prefers-reduced-motion rules reached the CSSOM"
    ripple = next((v for k, v in r.items() if "thm-ripple" in k), "")
    assert "display: none" in ripple, "ripples still spawn under reduced motion"
    stilled = next((v for k, v in r.items()
                    if "card-top svg" in k and "thm-dots" in k), "")
    assert "filter: none" in stilled, (
        "the icon and marble waters still animate under reduced motion — their "
        "SMIL turbulence cannot be paused per element, so filter:none is the "
        "only still fallback")


@needs_chrome
def test_forced_colors_drops_the_whole_treatment(rendered):
    f = rendered["forced"]
    assert f, "no forced-colors rules reached the CSSOM"
    hidden = next((v for k, v in f.items()
                   if all(c in k for c in ("thm-ring", "thm-face", "thm-dots",
                                           "thm-ripple"))), "")
    assert "display: none" in hidden, (
        "the theme layers survive High Contrast — ring, face, marble and "
        "ripples are decoration and must all go")
    card = next((v for k, v in f.items() if k.strip() == ".card"), "").lower()
    assert "backdrop-filter: none" in card and "buttonborder" in card, (
        "High Contrast needs the refraction off and a system-colour edge on")
