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

⚠ THESE RUN IN CI. G9 asserted they would skip there "because the dashboard job
is browser-free". Verified since: every job in ci.yml is `runs-on:
ubuntu-latest`, and that runner image ships `google-chrome-stable` on PATH,
which `_CHROME` finds. So the measured guards execute on every push — better
coverage than was claimed, and a real obligation: nothing here may depend on a
particular system-colour palette, because Linux need not hand back the same
values Windows does. Colours are therefore compared by CONTRAST RATIO against
the project's 3:1 floor for UI components, never by equality with a literal.

If `--force-high-contrast` turns out not to work on that runner,
`test_the_harness_is_really_in_high_contrast` fails first and names the cause,
rather than every other assertion passing for the wrong reason. That is the
intended failure: a red with a reason beats a green that measured nothing.
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
    # The range / metric / key-mode switchers. `.seg button` declares
    # `border:none`, and the pressed state was background + ink + shadow, so all
    # three of its distinguishers are overridden and the selected segment reads
    # exactly like the others.
    ("pressed segment", ".seg button", "attr", "aria-pressed=true"),
]

# Containers that must still draw an edge once their shadow is dropped.
STRUCTURE = [".clay", ".stat", ".topbar", ".dock", ".foxdlg-box"]

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
  // ── perceptual comparison ────────────────────────────────────────────────
  // Exact string inequality counts rgb(1,1,1) against rgb(0,0,0) as a
  // difference. Nobody can see that, and this file's whole point is that a
  // COMPUTED difference is not a VISIBLE one — comparing strings quietly
  // reintroduced the bug the effective-background resolver exists to prevent.
  // Colours are compared by WCAG contrast ratio against the project's own 3:1
  // floor for UI components; everything else is exact, because a border style
  // or a font weight either changed or did not.
  function rgb(c){ var m=/rgba?\(([^)]+)\)/.exec(c||''); if(!m) return null;
    var p=m[1].split(',').map(parseFloat); return [p[0],p[1],p[2]]; }
  function lum(c){ var v=rgb(c); if(!v) return null;
    var a=v.map(function(x){ x/=255;
      return x<=0.03928 ? x/12.92 : Math.pow((x+0.055)/1.055,2.4); });
    return 0.2126*a[0]+0.7152*a[1]+0.0722*a[2]; }
  function ratio(x,y){ var a=lum(x), b=lum(y);
    if(a===null||b===null) return x===y ? 1 : 99;
    return (Math.max(a,b)+0.05)/(Math.min(a,b)+0.05); }
  var UI_CONTRAST_FLOOR=3.0;
  function colourDiffers(x,y){ return ratio(x,y)>=UI_CONTRAST_FLOOR; }
  function edgeParts(v){ var p=(v||'').split(' ');
    return {shape:p[0]+' '+p[1], colour:p.slice(2).join(' ')}; }

  function sig(el){ var s=getComputedStyle(el);
    return {effBg:effBg(el), color:s.color,
      bTop:s.borderTopWidth+' '+s.borderTopStyle+' '+s.borderTopColor,
      bLeft:s.borderLeftWidth+' '+s.borderLeftStyle+' '+s.borderLeftColor,
      outline:s.outlineWidth+' '+s.outlineStyle+' '+s.outlineColor,
      weight:s.fontWeight, opacity:s.opacity}; }

  var COLOUR_KEYS={effBg:1,color:1}, EDGE_KEYS={bTop:1,bLeft:1,outline:1};
  function diff(a,b){ var d=[]; Object.keys(a).forEach(function(k){
      if(COLOUR_KEYS[k]){
        if(colourDiffers(a[k],b[k]))
          d.push(k+' :: '+a[k]+' vs '+b[k]+'  (contrast '+ratio(a[k],b[k]).toFixed(2)+':1)');
      } else if(EDGE_KEYS[k]){
        var pa=edgeParts(a[k]), pb=edgeParts(b[k]);
        if(pa.shape!==pb.shape) d.push(k+' shape :: '+pa.shape+' vs '+pb.shape);
        else if(colourDiffers(pa.colour,pb.colour))
          d.push(k+' colour :: '+pa.colour+' vs '+pb.colour);
      } else if(a[k]!==b[k]) d.push(k+' :: '+a[k]+' vs '+b[k]);
    }); return d; }

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
    } else if(p[2]==='attr'){
      var kv=p[3].split('=');
      el.removeAttribute(kv[0]); void el.offsetHeight; off=sig(el);
      el.setAttribute(kv[0], kv[1]); void el.offsetHeight; on=sig(el);
    } else {
      p[3].split(' ').forEach(function(c){ el.classList.remove(c); });
      void el.offsetHeight; off=sig(el);
      p[3].split(' ').forEach(function(c){ el.classList.add(c); });
      void el.offsetHeight; on=sig(el);
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
                  '<div id="g9p2"></div>'+
                  '';
  document.body.appendChild(probe);
  out.resolver={own:getComputedStyle(document.querySelector('#g9p1')).backgroundColor
                    !==getComputedStyle(document.querySelector('#g9p2')).backgroundColor,
                effective:effBg(document.querySelector('#g9p1'))
                    ===effBg(document.querySelector('#g9p2'))};
  // The comparator's own threshold, as a PURE FUNCTION on literal signatures.
  // Not through rendered elements: forced-colors overrides author backgrounds
  // to Canvas, so two divs painted black and white both come back black and the
  // control measures the flattening rather than the comparator. Without this,
  // loosening colourDiffers back to string inequality changes no assertion,
  // because every real state pair here differs enormously.
  function fake(c){ return {effBg:c, color:c, bTop:'0px none '+c,
    bLeft:'0px none '+c, outline:'0px none '+c, weight:'400', opacity:'1'}; }
  out.threshold={
    hair:diff(fake('rgb(0, 0, 0)'), fake('rgb(1, 1, 1)')),
    obvious:diff(fake('rgb(0, 0, 0)'), fake('rgb(255, 255, 255)'))};

  // Structure: does each container still draw an edge once its shadow is gone?
  // A painted edge means style is not `none` AND width is not zero — `3px none`
  // and `0px solid` both paint nothing, and an earlier version of this file
  // read the width alone and called every surface covered.
  out.structure=[];
  __STRUCTURE__.forEach(function(sel){
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
  // What the PARSER kept. Braces can balance while a comment that closes early
  // leaves prose behind, and CSS error-recovery then swallows whatever rule it
  // lands in the middle of. Source text cannot show that; the CSSOM can.
  out.cssom=[];
  for(var si=0; si<document.styleSheets.length; si++){
    var sheet=document.styleSheets[si], rules;
    try{ rules=sheet.cssRules; }catch(e){ continue; }
    for(var ri=0; ri<rules.length; ri++){
      var rule=rules[ri];
      if(rule.type===CSSRule.MEDIA_RULE &&
         /forced-colors/.test(rule.conditionText||rule.media.mediaText)){
        for(var mi=0; mi<rule.cssRules.length; mi++){
          out.cssom.push(rule.cssRules[mi].selectorText);
        }
      }
    }
  }

  document.documentElement.innerHTML='<pre id="g9">'+JSON.stringify(out)+'</pre>';
})();
"""

#: Every selector the block is supposed to contribute, as the PARSER should see
#: it. Written out rather than derived from the source, because deriving it from
#: the source is exactly the check that cannot see a dropped rule.
EXPECTED_CSSOM = [
    ".clay, .stat, .topbar, .dock, .foxdlg-box",
    ".stat .face",
    '.dock-item.active, .mnbtn.active, .kstatus.active, .seg button[aria-pressed="true"]',
    ".ttrack",
    ".toggle input:checked + .ttrack",
    ".ttrack::after",
    ".toggle input:checked + .ttrack::after",
]


def _render(forced: bool) -> dict:
    probe = (_PROBE.replace("__SEL__", json.dumps(SELECTIONS))
                   .replace("__STRUCTURE__", json.dumps(STRUCTURE)))
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


@needs_chrome
def test_every_rule_survived_the_parser(hcm):
    """⚠ THE ONE THAT CAUGHT A SHIPPED BUG. Read out of the CSSOM, not the file.

    G9 shipped a comment that closed early, leaving seven lines of bare prose
    inside the block. Braces still balanced, so the brace gate saw nothing; the
    source still contained `.ttrack{border:1px solid ButtonBorder;}`, so a text
    search saw nothing; and CSS error-recovery had swallowed that rule whole.
    The switch track — the control the census called the worst of the four — was
    still edgeless in High Contrast while every other guard here passed.

    A rule is only real if the PARSER kept it."""
    kept = hcm["cssom"]
    assert kept, "no forced-colors rules reached the CSSOM at all"
    missing = [s for s in EXPECTED_CSSOM if s not in kept]
    assert not missing, (
        f"the parser dropped {missing} — something before it does not parse. "
        f"It kept: {kept}")
    assert len(kept) == len(EXPECTED_CSSOM), (
        f"the block has {len(kept)} rules, expected {len(EXPECTED_CSSOM)}: {kept}")


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
    assert got["found"], "the switch markup moved; this guard measured nothing"
    assert any(d.startswith("effBg") for d in got["differs"]), \
        "the switch's on/off is not carried by anything visible in High Contrast"


@needs_chrome
def test_the_switch_knob_stays_visible_on_the_checked_track(hcm):
    """The track turning Highlight is only half of it. The knob sits ON that
    track, so if it keeps its unchecked fill it can land Highlight-on-Highlight
    and the switch reads as a filled bar with nothing in it. The knob has to
    change with the track."""
    # Read `found` first. Without it a markup refactor that loses the switch
    # raises KeyError from the harness instead of failing as the missing
    # coverage it is — and a KeyError is easy to read as a broken test.
    got = next(s for s in hcm["selections"] if s["label"] == "settings switch")
    assert got["found"], "the switch markup moved; this guard measured nothing"
    assert "knob" in hcm, "the knob was never measured"
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
def test_a_hair_of_colour_does_not_count_as_a_visible_difference(hcm):
    """The comparator's threshold, tested on values the page never produces.

    Every real state pair here differs enormously — Highlight against Canvas —
    so loosening the comparison back to exact string inequality changes none of
    the assertions above. `rgb(0,0,0)` versus `rgb(1,1,1)` is the case that
    separates a perceptual comparison from a string one, and it has to be
    supplied deliberately or the threshold is unguarded."""
    assert hcm["threshold"]["hair"] == [], (
        "a one-unit colour change is being reported as a visible difference: "
        f'{hcm["threshold"]["hair"]}')
    assert hcm["threshold"]["obvious"], \
        "black against white is not being reported as different; the comparator is broken"


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
    """The rendered half. This passed on origin/main AND with the block's own
    `.pill` rule deleted, because the base rules already declare a border — so
    it was green by construction and the rule it appeared to protect was
    removed. It stays because the RENDERED edge is still worth asserting; what
    protects the mechanism is the source-level guard below."""
    assert hcm["marks"]["edge"], "verdict pills have no painted edge in High Contrast"


def test_status_marks_declare_a_real_border():
    """The mechanism the test above actually depends on, at the source.

    forced-colors remaps border-color and keeps width and style, so a mark with
    a real border in its BASE rule survives with no forced-colors rule at all.
    That is why the block has none. The day one of these switches to a
    shadow-drawn edge — or to `border:0` plus a background — it becomes bare
    text in High Contrast, and no rule in the block would notice."""
    css = "\n".join(re.findall(r"<style[^>]*>(.*?)</style>", SRC, re.S))
    css = re.sub(r"/\*.*?\*/", "", css, flags=re.S)
    for mark in (".pill", ".seg-chip", ".vres"):
        m = re.search(re.escape(mark) + r"\s*\{([^}]*)\}", css)
        assert m, f"{mark} has no base rule any more"
        body = m.group(1)
        decl = re.search(r"(?<!-)border\s*:\s*([^;]+)", body)
        assert decl, f"{mark} declares no border; in High Contrast it is bare text"
        assert "none" not in decl.group(1) and not decl.group(1).strip().startswith("0"), \
            f"{mark}'s border paints nothing: {decl.group(1).strip()}"


@needs_chrome
def test_verdict_marks_stay_separable(hcm):
    """breach beside safe. Their hue is gone here and that is accepted — R2 says
    hue says which state and a WORD says it in text — so the word is allowed to
    be what survives. What is not allowed is neither."""
    assert hcm["marks"]["text"] or hcm["marks"]["style"], \
        "breach and safe are indistinguishable in High Contrast"


@needs_chrome
@pytest.mark.parametrize("sel", STRUCTURE)
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
    """Runs without a browser, so it still holds if Chrome is ever absent.

    It is a deletion alarm. It cannot tell whether the rules WORK — that is what
    the measured guards are for, and after the parser dropped a rule that WAS in
    the source it cannot even tell whether they exist. Read it as "nobody
    deleted the fix", never as "the fix is correct"."""
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
    # COMMENTS STRIPPED FIRST. This block is mostly prose explaining what was
    # measured, and searching it whole let the word ":focus-visible" in a
    # paragraph satisfy a check for a RULE that had been deliberately deleted.
    # The same trap as counting the word "forced-colors" instead of the at-rule.
    block = re.sub(r"/\*.*?\*/", "", css[start:end], flags=re.S)

    for selector in (".dock-item.active", ".mnbtn.active", ".kstatus.active",
                     '.seg button[aria-pressed="true"]',
                     ".ttrack", ".clay", ".dock", ".topbar", ".foxdlg-box"):
        assert selector in block, f"{selector} left the forced-colors block"
    assert "Highlight" in block and "ButtonBorder" in block, \
        "the system-colour vocabulary is gone"
    # The two rules measured redundant and removed. If either comes back, it is
    # dead CSS again and the measurement that removed it should be redone first.
    assert ":focus-visible" not in block, \
        "a focus rule is back in the block; it was measured redundant (all 20 " \
        "focus rules already declare a real outline)"
    assert ".pill" not in block, \
        "a .pill rule is back in the block; it was measured redundant (.pill " \
        "already declares border:var(--border-sm))"


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
