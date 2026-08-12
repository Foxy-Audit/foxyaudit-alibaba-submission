"""G9 · #154 — the dashboard under Windows High Contrast, MEASURED.

The central guard renders the shipped file in headless Chrome with
`--force-high-contrast` and reads computed styles back. It does not check that
an `@media (forced-colors: active)` at-rule exists: three phases running, this
repo has shipped guards that were satisfiable without the behaviour being right
— tokens declared and never painted, a guard restating the code, a fixture whose
shape production never sends. An at-rule check is exactly that shape.

TWO THINGS THIS FILE LEARNED THE HARD WAY, both from its own census:

* **A computed difference is not a visible one.** The first census called the
  nav item "covered" because its background computed to `rgb(0,0,0)` while its
  sibling's was `rgba(0,0,0,0)`. That is Canvas versus transparent, and the page
  IS that black — they render identically. Everything here compares the
  EFFECTIVE background, resolved up the ancestor chain until something opaque.

* **A selection state must be compared against ITSELF.** Comparing an active nav
  item to its neighbour passes for free, because "Home" and "Threats" are
  different words whatever the colours do. So selection is tested as one element
  with the state on and off, which has no text confound. Marks that legitimately
  differ from each other — a breach pill beside a safe pill — are compared as
  siblings, where the word is a real distinguisher and is allowed to be the one
  that survives.

Chrome is not available in this repo's CI (the dashboard job is stdlib + node,
no browser), so these skip there. `test_the_at_rule_still_covers_what_was
_measured` is the cheap tripwire that does run in CI — it is a deletion alarm,
not the measurement, and it says so.
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
           or next((p for p in (
               r"C:\Program Files\Google\Chrome\Application\chrome.exe",
               r"C:\Program Files (x86)\Google\Chrome\Application\chrome.exe",
           ) if pathlib.Path(p).exists()), None))

needs_chrome = pytest.mark.skipif(_CHROME is None, reason="Chrome not available")

# Selection states: ONE element, state on versus off. No text confound.
SELECTIONS = [
    ("active nav page", ".dock-item", "class", "active"),
    ("active settings section", ".mnbtn", "class", "active"),
    ("capture status pill", ".kstatus", "class", "active"),
    ("settings switch", ".toggle", "check", ""),
]

_PROBE = r"""
(function(){
  var SEL=__SEL__;
  function opaque(c){ return c && c!=='transparent' && !/rgba\(.*,\s*0\)\s*$/.test(c); }
  function effBg(el){ var n=el;
    while(n && n!==document.documentElement){
      var c=getComputedStyle(n).backgroundColor;
      if(opaque(c)) return c;
      n=n.parentElement; }
    return getComputedStyle(document.documentElement).backgroundColor; }
  function sig(el){ var s=getComputedStyle(el);
    return {effBg:effBg(el), color:s.color,
      bTop:s.borderTopWidth+' '+s.borderTopStyle+' '+s.borderTopColor,
      bLeft:s.borderLeftWidth+' '+s.borderLeftStyle+' '+s.borderLeftColor,
      outline:s.outlineWidth+' '+s.outlineStyle+' '+s.outlineColor,
      weight:s.fontWeight, opacity:s.opacity}; }
  function diff(a,b){ var d=[]; Object.keys(a).forEach(function(k){
      if(a[k]!==b[k]) d.push(k+' :: '+a[k]+' vs '+b[k]); }); return d; }

  var out={forced:matchMedia('(forced-colors: active)').matches, selections:[]};

  SEL.forEach(function(p){
    var el=document.querySelector(p[1]);
    if(!el){ out.selections.push({label:p[0], found:false}); return; }
    var on, off;
    if(p[2]==='check'){
      var i=el.querySelector('input'), t=el.querySelector('.ttrack');
      if(!i||!t){ out.selections.push({label:p[0], found:false}); return; }
      // void t.offsetHeight forces a reflow between the two reads. Without it
      // Chrome hands back a STALE pseudo-element style and the knob measures
      // identical in both states — which reads as a defect that is not there.
      i.checked=false; void t.offsetHeight; off=sig(t);
      var knobOff=getComputedStyle(t,'::after').backgroundColor;
      i.checked=true;  void t.offsetHeight; on =sig(t);
      var knobOn=getComputedStyle(t,'::after').backgroundColor;
      out.knob={on:knobOn, off:knobOff, trackOn:on.effBg, trackOff:off.effBg};
    } else {
      p[3].split(' ').forEach(function(c){ el.classList.remove(c); });
      off=sig(el);
      p[3].split(' ').forEach(function(c){ el.classList.add(c); });
      on=sig(el);
    }
    out.selections.push({label:p[0], found:true, differs:diff(on,off)});
  });

  // Status marks: different marks, siblings. A word is allowed to be the thing
  // that survives — that is R2's rule, not a loophole.
  var host=document.querySelector('#ledgerBody')||document.body;
  host.insertAdjacentHTML('beforeend',
    '<span id="g9a" class="pill breach">breach</span>'+
    '<span id="g9b" class="pill safe">safe</span>');
  var a=document.querySelector('#g9a'), b=document.querySelector('#g9b');
  var as=getComputedStyle(a);
  out.marks={style:diff(sig(a),sig(b)),
             text:(a.textContent||'').trim()!==(b.textContent||'').trim(),
             edge:(as.borderTopStyle!=='none' && parseFloat(as.borderTopWidth)>0)};

  // Focus. :focus-visible needs a real focus, and headless honours it for a
  // keyboard-ish focus on a button.
  // A real <button>. `.dock-item` is a DIV with an onclick and no tabindex, so
  // it cannot take focus at all — a separate finding, and measuring it here
  // would report the focus RING as broken when what is missing is the focus.
  // Not just the first button: plenty of them live on pages the app has not
  // rendered, and an element that never becomes activeElement reports the
  // resting outline, which reads as a missing focus ring that is really a
  // missing focus. Take the first one that actually accepts focus.
  var fb=null, cands=document.querySelectorAll('button:not([disabled])');
  for(var ci=0; ci<cands.length; ci++){
    cands[ci].focus(); void cands[ci].offsetHeight;
    if(document.activeElement===cands[ci]){ fb=cands[ci]; break; }
  }
  if(fb){ var fs=getComputedStyle(fb);
    out.focus={tag:fb.tagName, isFocused:true, matchesFV:fb.matches(':focus-visible'),
               painted:(fs.outlineStyle!=='none' && parseFloat(fs.outlineWidth)>0),
               outline:fs.outlineWidth+' '+fs.outlineStyle+' '+fs.outlineColor}; }
  else { out.focus={isFocused:false}; }
  out.navFocusable=(function(){ var n=document.querySelector('.dock-item');
    if(!n) return null;
    return {tag:n.tagName, tabindex:n.getAttribute('tabindex'),
            role:n.getAttribute('role')}; })();

  // Does effBg actually resolve up the tree? Two boxes that LOOK the same — one
  // painting Canvas, one painting nothing — must resolve to the same effective
  // background. Reading the own background instead reports a difference that
  // does not exist, which is the false positive that fooled the first census.
  var probe=document.createElement('div');
  probe.innerHTML='<div id="g9p1" style="background:Canvas"></div>'+
                  '<div id="g9p2"></div>';
  document.body.appendChild(probe);
  out.resolver={own:getComputedStyle(document.querySelector('#g9p1')).backgroundColor
                    !==getComputedStyle(document.querySelector('#g9p2')).backgroundColor,
                effective:effBg(document.querySelector('#g9p1'))
                    ===effBg(document.querySelector('#g9p2'))};

  // Structure: does each container still draw an edge once its shadow is gone?
  // A painted edge means style is not `none` AND width is not zero — `3px none`
  // and `0px solid` both paint nothing, and an earlier version of this file
  // read the width alone and called every surface covered.
  out.structure=[];
  ['.clay','.stat','.topbar','.dock'].forEach(function(sel){
    var el=document.querySelector(sel);
    if(!el){ out.structure.push({sel:sel, found:false}); return; }
    var s=getComputedStyle(el);
    var painted=(s.borderTopStyle!=='none' && parseFloat(s.borderTopWidth)>0)
             || (s.outlineStyle!=='none' && parseFloat(s.outlineWidth)>0);
    out.structure.push({sel:sel, found:true, painted:painted,
      border:s.borderTopWidth+' '+s.borderTopStyle+' '+s.borderTopColor,
      merges:effBg(el)===getComputedStyle(document.body).backgroundColor});
  });

  // CONTROL. If forced-colors is not really on, these three do not hold, and a
  // green run would mean nothing.
  var stage=document.createElement('div'); document.body.appendChild(stage);
  var svg=document.createElementNS('http://www.w3.org/2000/svg','svg');
  svg.innerHTML='<rect id="g9r" width="10" height="10" fill="#e67e22"/>';
  stage.appendChild(svg);
  var d=document.createElement('div');
  d.style.cssText='background:#e67e22;box-shadow:0 2px 4px #e67e22;border:1px solid #e67e22;';
  stage.appendChild(d);
  var ds=getComputedStyle(d);
  out.control={svgFill:getComputedStyle(svg.querySelector('#g9r')).fill,
               htmlBg:ds.backgroundColor, htmlShadow:ds.boxShadow,
               htmlBorder:ds.borderTopColor,
               pageBg:getComputedStyle(document.body).backgroundColor};
  document.documentElement.innerHTML='<pre id="g9">'+JSON.stringify(out)+'</pre>';
})();
"""


def _render(forced: bool) -> dict:
    probe = _PROBE.replace("__SEL__", json.dumps(SELECTIONS))
    page_src = SRC + (
        "\n<script>window.addEventListener('load',function(){setTimeout(function(){try{"
        + probe + "}catch(e){document.documentElement.innerHTML="
        "'<pre id=\"g9\">'+JSON.stringify({error:String(e)})+'</pre>';}},400);});</script>\n")
    with tempfile.TemporaryDirectory() as tmp:
        page = pathlib.Path(tmp) / "probe.html"
        page.write_text(page_src, encoding="utf-8")
        args = [_CHROME, "--headless=new", "--disable-gpu", "--no-sandbox",
                "--hide-scrollbars", "--force-prefers-reduced-motion",
                "--virtual-time-budget=7000", "--window-size=1440,900",
                f"--user-data-dir={tmp}/prof", "--dump-dom", page.as_uri()]
        if forced:
            args.insert(4, "--force-high-contrast")
        # Bounded, and it kills only THIS process. Never taskkill chrome by
        # name: that closes the browser the person at the keyboard is using.
        proc = subprocess.run(args, capture_output=True, text=True,
                              encoding="utf-8", errors="replace", timeout=180)
    m = re.search(r'<pre id="g9">(.*?)</pre>', proc.stdout, re.S)
    assert m, "the probe never ran; chrome said: %s" % proc.stderr[-500:]
    data = json.loads(m.group(1))
    assert not data.get("error"), data.get("error")
    return data


@pytest.fixture(scope="module")
def hcm():
    return _render(True)


@pytest.fixture(scope="module")
def normal():
    return _render(False)


# ── the control, first: if this is wrong nothing below means anything ────────
@needs_chrome
def test_the_harness_is_really_in_high_contrast(hcm, normal):
    """Three facts this whole file rests on, re-measured every run rather than
    inherited: forced-colors is on, an HTML background collapses to the page,
    and a box-shadow is dropped. If Chrome ever stops honouring the flag, these
    fail instead of every assertion below passing for the wrong reason."""
    assert hcm["forced"] is True, "--force-high-contrast did not enable forced-colors"
    assert normal["forced"] is False, "the control run reported forced-colors active"
    assert hcm["control"]["htmlBg"] == hcm["control"]["pageBg"], \
        "an HTML background did not collapse to Canvas — this is not High Contrast"
    assert hcm["control"]["htmlShadow"] == "none", "box-shadow was not dropped"
    assert normal["control"]["htmlBg"] != normal["control"]["pageBg"], \
        "the NORMAL run also collapsed the background — the harness sees no difference"


@needs_chrome
def test_svg_fill_survives_so_the_charts_need_nothing(hcm, normal):
    """G7's hatch and G8's donut swatches were built on this and were measured
    working before G9. Asserted, not assumed, so a Chrome change that broke it
    would surface here rather than in a chart nobody can read."""
    assert hcm["control"]["svgFill"] == normal["control"]["svgFill"] == "rgb(230, 126, 34)"


# ── the guard that matters ───────────────────────────────────────────────────
@needs_chrome
@pytest.mark.parametrize("label", [s[0] for s in SELECTIONS])
def test_a_selected_control_is_distinguishable_from_itself_unselected(hcm, label):
    """THE central guard. One element, state on versus off, under High Contrast.

    Compared against ITSELF rather than a neighbour on purpose: two nav items
    have different words whatever the colour does, so a sibling comparison would
    pass while the selection was completely invisible.

    Every one of these failed before G9 — the selected item computed to Canvas
    and the unselected to transparent, which on a Canvas page is the same
    picture."""
    got = next(s for s in hcm["selections"] if s["label"] == label)
    assert got["found"], f"{label} is not in the shipped markup any more"
    assert got["differs"], (
        f"{label}: selected and unselected render identically in High Contrast")


@needs_chrome
def test_the_switch_does_not_lean_on_a_word_it_does_not_have(hcm):
    """The switch is the only control in the census with no text at all, so it
    is the one that cannot be excused by R2's "a word says it" rule. Its state
    has to be carried by something painted."""
    got = next(s for s in hcm["selections"] if s["label"] == "settings switch")
    assert any(d.startswith("effBg") for d in got["differs"]), \
        "the switch's on/off is not carried by anything visible in High Contrast"


@needs_chrome
def test_the_switch_knob_stays_visible_on_the_checked_track(hcm):
    """The track turning Highlight is only half of it. The knob sits ON that
    track, so if it keeps its unchecked fill it can land Highlight-on-Highlight
    and the switch reads as a filled bar with nothing in it. The knob has to
    change with the track."""
    knob = hcm["knob"]
    # NOT "the knob changes colour". CanvasText and HighlightText resolve to the
    # same value in the default Windows palette (measured: both rgb(220,220,220)),
    # and the state is carried by the track's fill plus the knob's POSITION,
    # which forced-colors leaves alone because transform is not a colour. What
    # must hold is that the knob is visible against whatever it is sitting on.
    assert knob["on"] != knob["trackOn"], \
        "the knob and the checked track paint the same colour — the knob vanishes"
    assert knob["off"] != knob["trackOff"], \
        "the knob and the unchecked track paint the same colour — the knob vanishes"


@needs_chrome
def test_focus_is_still_painted(hcm):
    """Focus survives High Contrast on this surface WITHOUT a rule in the block,
    and that is the finding rather than an omission: forced-colors remaps
    outline-color and keeps width and style, so an outline-based ring comes
    through. `outline: 3px none` paints nothing, so style is checked here, not
    just width."""
    assert hcm["focus"]["isFocused"], "no button on the page accepted focus"
    assert hcm["focus"]["painted"], \
        f'focus paints nothing in High Contrast ({hcm["focus"]["outline"]})'


def test_no_focus_ring_is_carried_by_a_shadow():
    """The mechanism the test above depends on, guarded at the source.

    A blanket `:focus-visible` rule inside the forced-colors block was written
    and then deleted, because mutating it away changed nothing — all 20 focus
    rules already declare a real outline. That makes THIS the load-bearing
    property: the day someone writes a focus ring as a box-shadow, it will be
    invisible in High Contrast and the rendered guard above may still pass on
    some other control. Runs without a browser, so it holds in CI too."""
    css = "\n".join(re.findall(r"<style[^>]*>(.*?)</style>", SRC, re.S))
    rules = re.findall(r"([^{}]+)\{([^{}]*)\}", css)
    focus = [(s.strip(), b.strip()) for s, b in rules if ":focus" in s]
    assert len(focus) >= 15, f"only {len(focus)} focus rules found; the scan is wrong"
    shadow_only = [s for s, b in focus
                   if not re.search(r"outline\s*:\s*(?!none)[^;]*", b)]
    assert not shadow_only, (
        "these focus rules do not declare a real outline, so their ring is "
        f"invisible in High Contrast: {shadow_only}")


@needs_chrome
def test_the_effective_background_is_resolved_not_read_off_the_element(hcm):
    """Guards the resolver itself, because everything above trusts it. Two boxes
    that render identically — one painting Canvas, one painting nothing — must
    come out equal. Reading the element's own background instead reports a
    difference that is not there, and that false positive is what made the first
    census call the nav item covered when it was invisible."""
    assert hcm["resolver"]["own"], \
        "the two probe boxes no longer differ in their OWN background; the test is moot"
    assert hcm["resolver"]["effective"], \
        "effective background is not resolving up the tree — Canvas over Canvas " \
        "is being reported as a visible difference"


@needs_chrome
def test_status_marks_keep_a_painted_edge(hcm):
    """Separate from the assertion below on purpose. The word is what carries
    the MEANING; the edge is what stops the mark dissolving into the row as bare
    text. Testing only "text or style" let the edge be deleted silently."""
    assert hcm["marks"]["edge"], "verdict pills have no painted edge in High Contrast"


@needs_chrome
def test_verdict_marks_stay_separable(hcm):
    """breach beside safe. Their hue is gone here and that is accepted — R2 says
    hue says which state and a WORD says it in text — so the word is allowed to
    be what survives. What is not allowed is neither."""
    assert hcm["marks"]["text"] or hcm["marks"]["style"], \
        "breach and safe are indistinguishable in High Contrast"


@needs_chrome
@pytest.mark.parametrize("sel", [".clay", ".stat", ".topbar", ".dock"])
def test_structure_still_has_edges_when_every_shadow_is_gone(hcm, sel):
    """52 box-shadows carry this surface's containers, and forced-colors paints
    none of them. Measured before G9: each of these sat on the page's own Canvas
    with `border: 0px none`, so the page was one undifferentiated field of text.

    "Painted" means style is not `none` AND width is not zero. An earlier draft
    of this file read the width alone, so `3px none` — which paints nothing —
    counted as an edge and every surface reported covered."""
    got = next(s for s in hcm["structure"] if s["sel"] == sel)
    assert got["found"], f"{sel} is no longer in the shipped markup"
    assert got["painted"], (
        f"{sel} has no painted edge in High Contrast ({got['border']}) and its "
        f"background is the page's own — it merges into the field")


# ── the CI tripwire — a deletion alarm, NOT the measurement ──────────────────
def test_the_at_rule_still_covers_what_was_measured():
    """This one runs without a browser, which is the only reason it exists: the
    dashboard CI job has no Chrome, so every test above skips there.

    It is a deletion alarm. It cannot tell whether the rules WORK — that is what
    the measured guards are for — only that the block and the selectors the
    census named are still present. Read it as "nobody deleted the fix", never
    as "the fix is correct"."""
    css = "\n".join(re.findall(r"<style[^>]*>(.*?)</style>", SRC, re.S))
    blocks = re.findall(r"@media\s*\(\s*forced-colors\s*:\s*active\s*\)\s*\{", css)
    assert len(blocks) == 1, f"expected exactly one forced-colors block, found {len(blocks)}"

    start = css.index("@media (forced-colors: active)")
    depth, end = 0, None
    for i in range(start, len(css)):
        if css[i] == "{":
            depth += 1
        elif css[i] == "}":
            depth -= 1
            if depth == 0:
                end = i
                break
    assert end, "the forced-colors block is unbalanced"
    block = css[start:end]

    for selector in (".dock-item.active", ".mnbtn.active", ".kstatus.active",
                     ".ttrack", ":focus-visible", ".clay", ".dock", ".topbar"):
        assert selector in block, f"{selector} left the forced-colors block"
    assert "Highlight" in block and "ButtonBorder" in block, \
        "the system-colour vocabulary is gone"


def test_no_new_palette_was_invented_for_high_contrast():
    """HCM is not a theme. If a --token turns up inside the block, somebody has
    started building a third palette instead of using the system's."""
    css = "\n".join(re.findall(r"<style[^>]*>(.*?)</style>", SRC, re.S))
    start = css.index("@media (forced-colors: active)")
    depth, end = 0, None
    for i in range(start, len(css)):
        if css[i] == "{":
            depth += 1
        elif css[i] == "}":
            depth -= 1
            if depth == 0:
                end = i
                break
    block = css[start:end]
    declared = re.findall(r"(--[a-z0-9-]+)\s*:", block)
    assert not declared, f"the forced-colors block declares tokens: {declared}"
    assert "forced-color-adjust" not in block, \
        "forced-color-adjust is a scalpel; nothing here measured a need for it"
