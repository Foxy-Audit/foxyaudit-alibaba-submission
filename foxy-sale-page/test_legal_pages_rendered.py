"""The legal pages, measured in a real browser rather than read as source.

⚠ L2–L12: ADD YOUR PAGE TO `PAGES` BELOW. Do not write a second Chrome fixture.

Everything here is parametrized over one list on purpose. The alternative — each
phase shipping its own headless-Chrome fixture in its own file — ends with twelve
browser launches in a suite that used to run in a third of a second, and twelve
copies of the same harness to keep in step. One launch per page is unavoidable;
twelve copies of the launcher is not.

WHY A BROWSER AT ALL, when the rest of this suite reads files:

  A stylesheet can name a typeface that never arrives, and the page silently
  renders the fallback. Source says Poppins; the reader sees Arial. Nothing in a
  grep can tell those apart — and the same shape of mistake shipped twice in this
  repo in two days (#161 guarded a config production does not read; #178 was
  valid nginx that no longer served HTTPS). Syntactic validity is not behavioural
  equivalence, so the claims that only rendering can settle are settled here:

    · the display face actually loaded, rather than merely being declared
    · the page fetched nothing from any third party

  The second is the privacy claim itself. These are privacy and legal documents;
  a font CDN would send the reader's IP to a third party before they had read how
  their data is handled, and would contradict the sub-processor list further down
  the same page.

Each page ALSO keeps a fast, always-on twin of the network check in its own test
module, so the guarantee still has a guard on a machine with no Chrome.

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

#: Legal pages rendered and measured. Append as each phase lands.
#:   L1 privacy.html · L2 terms.html · L3 refund.html · L4 report-abuse.html
#:   L6 acceptable-use.html · L7 cookie-policy.html · L8 trust.html
#:   L9 sla.html · L10 dpa.html · L11 msa.html
PAGES = ["privacy.html", "terms.html", "terms-of-use.html", "refund.html"]

_CHROME = (os.environ.get("CHROME_BIN")
           or shutil.which("chrome") or shutil.which("google-chrome")
           or next((p for p in (
               r"C:\Program Files\Google\Chrome\Application\chrome.exe",
               r"C:\Program Files (x86)\Google\Chrome\Application\chrome.exe",
           ) if pathlib.Path(p).exists()), None))

needs_chrome = pytest.mark.skipif(_CHROME is None, reason="Chrome not available")

_PROBE = r"""
(function(){
  var out = {};
  var cs = function(sel){ var e=document.querySelector(sel);
    return e ? getComputedStyle(e).fontFamily.split(',')[0].replace(/["']/g,'') : 'MISSING'; };
  out.h1 = cs('h1'); out.h2 = cs('h2'); out.brand = cs('.brand'); out.body = cs('.card p');
  // Does the display face actually RENDER, or was it only named in a stylesheet?
  //
  // ⚠ document.fonts.check() CANNOT ANSWER THIS. It returns true for a family
  // that does not exist anywhere, because the text remains renderable through
  // fallback — measured here and confirmed. Widths cannot be fooled that way: if
  // the face never loaded, the Poppins string measures exactly the fallback.
  var c = document.createElement('canvas').getContext('2d');
  var probe = 'Privacy Policy Sub-processors';
  c.font = '700 34px Poppins, "NoSuchFallbackXYZ"'; out.wDisplay  = c.measureText(probe).width;
  c.font = '700 34px "NoSuchFallbackXYZ"';          out.wFallback = c.measureText(probe).width;
  c.font = '700 34px "NoSuchOtherFaceABC"';         out.wControl  = c.measureText(probe).width;
  out.fetched = performance.getEntriesByType('resource').map(function(r){ return r.name; });
  out.faces = [];
  document.fonts.forEach(function(f){ out.faces.push(f.family + ':' + f.weight); });
  document.documentElement.innerHTML = '<pre id="p">' + JSON.stringify(out) + '</pre>';
})();
"""

_cache: dict[str, dict] = {}


def _render(page: str) -> dict:
    """The shipped file, in a real browser. The probe is appended to a COPY, so
    the page that reaches a customer stays script-free."""
    if page in _cache:
        return _cache[page]
    src = (_HERE / page).read_text(encoding="utf-8")
    with tempfile.TemporaryDirectory() as tmp:
        probe_page = pathlib.Path(tmp) / page
        probe_page.write_text(
            src + "\n<script>window.addEventListener('load',function(){setTimeout("
                  "function(){try{" + _PROBE + "}catch(e){document.documentElement.innerHTML="
                  "'<pre id=\"p\">'+JSON.stringify({error:String(e)})+'</pre>';}},300);});</script>",
            encoding="utf-8")
        # Bounded, and it kills only THIS process. Never taskkill chrome by name:
        # that closes the browser the person at the keyboard is using.
        proc = subprocess.run(
            [_CHROME, "--headless=new", "--disable-gpu", "--no-sandbox",
             "--virtual-time-budget=8000", "--window-size=1280,900",
             f"--user-data-dir={tmp}/prof", "--dump-dom", probe_page.as_uri()],
            capture_output=True, text=True, encoding="utf-8", errors="replace", timeout=180)
    m = re.search(r'<pre id="p">(.*?)</pre>', proc.stdout, re.S)
    assert m, f"the probe never ran for {page}; chrome said: {proc.stderr[-500:]}"
    data = json.loads(m.group(1))
    assert not data.get("error"), f"{page}: {data['error']}"
    _cache[page] = data
    return data


# ── the control, first: if this is wrong nothing below means anything ────────
@needs_chrome
@pytest.mark.parametrize("page", PAGES)
def test_the_probe_can_tell_a_real_face_from_an_invented_one(page):
    """Two families that do not exist must measure identically, because both fall
    back to the same face. If they differ, the measurement is picking up
    something other than the typeface and every assertion under it is noise."""
    r = _render(page)
    assert r["wFallback"] == r["wControl"], (
        f"{page}: two nonexistent families measured differently "
        f"({r['wFallback']} vs {r['wControl']}) — the probe is not measuring the face")
    assert r["wFallback"] > 0


@needs_chrome
@pytest.mark.parametrize("page", PAGES)
def test_the_display_face_really_renders_and_is_not_merely_declared(page):
    """#10: five of the six pages this stream rewrites did not load Poppins at
    all. Declaring a family proves nothing about what the reader sees."""
    r = _render(page)
    assert r["wDisplay"] != r["wFallback"], (
        f"{page}: Poppins was named but never loaded — the heading rendered in "
        "the fallback face")
    assert "Poppins:700" in r["faces"], f"{page}: no Poppins face registered: {r['faces']}"


@needs_chrome
@pytest.mark.parametrize("page", PAGES)
def test_poppins_is_the_display_voice_and_not_the_reading_voice(page):
    """The two sale pages that actually USE Poppins use it as --disp, never for
    body. It is a geometric display face; these are long legal documents, and the
    system UI stack is designed for exactly that reading."""
    r = _render(page)
    assert r["h1"] == "Poppins", f"{page}: h1 renders in {r['h1']}"
    assert r["h2"] == "Poppins", f"{page}: h2 renders in {r['h2']}"
    assert r["brand"] == "Poppins", f"{page}: the brand renders in {r['brand']}"
    assert r["body"] != "Poppins", \
        f"{page}: long-form legal text is set in a geometric display face"


@needs_chrome
@pytest.mark.parametrize("page", PAGES)
def test_the_legal_pages_fetch_nothing_from_anyone(page):
    """⚠ THE POINT OF EMBEDDING THE FONT. A Google Fonts <link> sends the
    reader's IP address to a third party before they have read how their data is
    handled — LG München I, 3 O 17493/20 (20 Jan 2022) awarded damages for
    exactly that. On privacy.html it would also make Section 8 false: it names
    six sub-processors and says "No one else touches your data."

    Measured as what the page FETCHED, not as the absence of a string."""
    external = [u for u in _render(page)["fetched"]
                if not u.startswith(("file:", "data:"))]
    assert not external, f"{page} contacted third parties: {external}"
