"""W5 — the last three: the fox leaves the legal headers, the headings get
their true weight, and the hairline lands where the cards do.

The fox-zero invariant lives in the four re-aimed guards
(test_acceptable_use_v14, test_cookie_policy_v15, test_footer_sweep,
test_w3_master_theme::test_no_fox_emoji_anywhere) — this file owns the other
two jobs, and the measurement lesson:

  · **the 800 face is proven by MEASUREMENT, not declaration.** The L1 lesson:
    document.fonts.check() returns true for faces that never loaded, and a
    stylesheet can name a weight the browser silently synthesizes. So the
    probe registers a control family carrying only the 600/700 pair and
    measures the same string at weight 800 in both families: the control
    resolves 800 → synthetic-bold-of-700; the real family resolves to the
    embedded 800. The widths differ only when a genuinely distinct 800 face
    loaded.

  · **the hairline is read from the CSSOM** — the 640px media block must carry
    .stage::after{bottom:94px} as a rule the browser actually parsed.

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
INDEX = (_HERE / "index.html").read_text(encoding="utf-8")

CARRIERS = ("index.html", "site.css", "book-a-demo.html")


def _read(name: str) -> str:
    return (_HERE / name).read_text(encoding="utf-8")


# ── source-level: the 900s are mapped, the faces are three ───────────────────

def test_no_carrier_asks_for_weight_900():
    """900 maps to the real 800 rather than shipping a fourth subset — a 900
    request over an 800 face synthetic-bolds on top of the true weight."""
    for c in CARRIERS:
        assert "font-weight:900" not in _read(c), (
            f"{c} asks for weight 900 again — W5 mapped every 900 to the "
            f"embedded 800 (index ×4: ghost, how-num, calc-price, price-amt; "
            f"site.css ×1: price-amt)")


def test_each_carrier_embeds_exactly_one_800_face():
    for c in CARRIERS:
        n = len(re.findall(r"@font-face\{[^}]*font-weight:800", _read(c)))
        assert n == 1, f"{c} embeds {n} weight-800 faces, not exactly one"


# ── rendered: the true weight and the tracked hairline ───────────────────────

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
  // ── the true-800 measurement ─────────────────────────────────────────
  // Register a CONTROL family from the page's own embedded 600/700 pair.
  // In the control, a weight-800 request synthesizes bold from 700; in the
  // page's Poppins it must resolve to the genuinely distinct embedded 800.
  var srcs=[];
  [].forEach.call(document.styleSheets,function(sh){
    var rules; try{ rules=sh.cssRules; }catch(e){ return; }
    [].forEach.call(rules,function(r){
      if(r instanceof CSSFontFaceRule){
        var w=r.style.getPropertyValue('font-weight');
        var s=r.style.getPropertyValue('src');
        srcs.push({w:w, s:s});
      }
    });
  });
  out.faceWeights = srcs.map(function(x){return x.w;}).sort();
  var css='';
  srcs.forEach(function(x){
    if(x.w==='800') return;                       // the control has no 800
    css+='@font-face{font-family:PairOnly;font-style:normal;font-weight:'+x.w+
         ';src:'+x.s+';}';
  });
  var st=document.createElement('style'); st.textContent=css;
  document.head.appendChild(st);
  document.fonts.load('800 34px PairOnly','Hashgrade').then(function(){
    return document.fonts.load('800 34px Poppins','Hashgrade');
  }).then(function(){
    var c=document.createElement('canvas').getContext('2d');
    var probe='Tamper-evident audit trails for AI 0123';
    c.font='800 34px Poppins, monospace';  out.wReal  = c.measureText(probe).width;
    c.font='800 34px PairOnly, monospace'; out.wSynth = c.measureText(probe).width;
    c.font='700 34px Poppins, monospace';  out.w700   = c.measureText(probe).width;
    // ── the hairline, from the CSSOM ─────────────────────────────────
    out.hairline='ABSENT';
    [].forEach.call(document.styleSheets,function(sh){
      var rules; try{ rules=sh.cssRules; }catch(e){ return; }
      [].forEach.call(rules,function(r){
        if(r instanceof CSSMediaRule && r.conditionText.indexOf('640px')>=0)
          [].forEach.call(r.cssRules,function(x){
            if(x.selectorText==='.stage::after') out.hairline=x.style.cssText;
          });
      });
    });
    // the desktop resting position, for the delta
    [].forEach.call(document.styleSheets,function(sh){
      var rules; try{ rules=sh.cssRules; }catch(e){ return; }
      [].forEach.call(rules,function(r){
        if(r.selectorText==='.stage::after' && r.style.bottom)
          out.desktopBottom=r.style.bottom;
      });
    });
    document.documentElement.innerHTML='<pre id="p">'+JSON.stringify(out)+'</pre>';
  }).catch(function(e){
    document.documentElement.innerHTML='<pre id="p">'+JSON.stringify({error:String(e)})+'</pre>';
  });
})();
"""

_cache: dict = {}


@pytest.fixture(scope="module")
def rendered():
    if "d" in _cache:
        return _cache["d"]
    with tempfile.TemporaryDirectory() as tmp:
        page = pathlib.Path(tmp) / "index.html"
        page.write_text(
            INDEX + "\n<script>window.addEventListener('load',function(){setTimeout("
                    "function(){try{" + _PROBE + "}catch(e){document.documentElement.innerHTML="
                    "'<pre id=\"p\">'+JSON.stringify({error:String(e)})+'</pre>';}},800);});</script>",
            encoding="utf-8")
        # Bounded, and it kills only THIS process — never taskkill chrome by name.
        proc = subprocess.run(
            [_CHROME, "--headless=new", "--no-sandbox",
             "--virtual-time-budget=10000", "--window-size=1280,900",
             f"--user-data-dir={tmp}/prof", "--dump-dom", page.as_uri()],
            capture_output=True, text=True, encoding="utf-8", errors="replace",
            timeout=180)
    m = re.search(r'<pre id="p">(.*?)</pre>', proc.stdout, re.S)
    assert m, f"the probe never ran; chrome said: {proc.stderr[-400:]}"
    data = json.loads(m.group(1))
    assert not data.get("error"), data["error"]
    _cache["d"] = data
    return data


@needs_chrome
def test_the_true_800_actually_renders(rendered):
    assert rendered["faceWeights"] == ["600", "700", "800"], (
        f"the page's parsed faces are {rendered['faceWeights']}, not the "
        f"legal pair + the true 800")
    real, synth = rendered["wReal"], rendered["wSynth"]
    assert abs(real - synth) > 0.5, (
        f"weight-800 text measures the same with and without the 800 face "
        f"({real:.2f}px vs {synth:.2f}px) — the browser is still synthesizing "
        f"bold from 700, so the embedded 800 never loaded. "
        f"document.fonts.check() would not have caught this; widths do")
    assert abs(real - rendered["w700"]) > 0.5, (
        "weight-800 measures identical to 700 — the 800 face resolved to the "
        "700 file")


@needs_chrome
def test_the_hairline_tracks_the_cards_on_mobile(rendered):
    assert rendered["hairline"] != "ABSENT", (
        "no .stage::after rule inside a 640px media block reached the CSSOM — "
        "the hairline sits 10px above the cards on mobile again")
    assert "bottom: 94px" in rendered["hairline"], (
        f"the mobile hairline moved somewhere other than the cards' 94px: "
        f"{rendered['hairline']}")
    assert rendered.get("desktopBottom") == "104px", (
        f"the desktop resting position moved: {rendered.get('desktopBottom')}")


# ── the legal headers carry the logo now ─────────────────────────────────────

LEGAL_DOCS = ("privacy.html", "terms.html", "terms-of-use.html", "refund.html",
              "report-abuse.html", "acceptable-use.html", "cookie-policy.html",
              "trust.html", "sla.html", "dpa.html", "msa.html")


def test_every_legal_header_carries_the_logo():
    for page in LEGAL_DOCS:
        src = _read(page)
        assert '<img src="/logo.png" alt=""' in src, (
            f"{page}'s header lost its logo — #12 is 'the logo or nothing', "
            f"and nothing would unbrand eleven documents")
        assert 'class="dot"' not in src, (
            f"{page} still carries the .dot chip markup the logo replaced")
        assert ".brand .dot{" not in src, (
            f"{page} keeps the orphaned .dot CSS — orphaned code is how "
            f"things resurrect")
