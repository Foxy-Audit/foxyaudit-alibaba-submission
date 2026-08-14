"""W3 — every marketing page wears the master theme, guarded.

W2 made index.html's --thm-* tokens the master for every sale sub-page. W3
rolls the theme out. One correction to the plan this file enforces the real
shape of: the brief said "the site has no shared stylesheet — copy-paste is
the pattern", and that premise is stale — fifteen of the sixteen themed pages
link `/site.css`, and only `book-a-demo.html` (and index itself, and the
eleven legal documents) are self-contained. So the tokens live in exactly
THREE carriers — index.html, site.css, book-a-demo.html — and the fifteen
site.css pages inherit rather than copy. What prevents drift is still the
guard, exactly as the brief ordered: the token declarations are read out of
every carrier and compared byte-for-byte, and every themed page is asserted
to actually reach a carrier.

The other invariants pinned here:

  · **no CDN font, anywhere on this surface.** The owner decision (#10) is
    that Poppins ships as the same two embedded base64 faces the legal pages
    carry — display roles only, body on the system stack. A page that quietly
    re-adds fonts.googleapis sends every visitor's IP to Google before the
    privacy policy has even loaded.

  · **the faces are THE SAME bytes everywhere.** The legal pages settled the
    two subsets (600 + 700); site.css, index and book-a-demo embed byte-equal
    copies. A "harmless" re-subset on one page is a different font on one
    page.

  · **zero @gmail.com, forever.** #190: the support address is
    support@foxyaudit.tech (L4 settled security@ is only for disclosure).

  · **the legal documents are untouched.** Their warm-charcoal document style
    is deliberate; the ~500 L-stream guards are the real fence, but the token
    guard here also asserts the theme did NOT leak into them.

Run:  pytest foxy-sale-page -q
"""

from __future__ import annotations

import pathlib
import re

import pytest

_HERE = pathlib.Path(__file__).resolve().parent

#: The three files that CARRY the token block.
CARRIERS = ("index.html", "site.css", "book-a-demo.html")

#: The fifteen themed pages that inherit the tokens by linking /site.css.
SITECSS_PAGES = (
    "about.html", "contact.html", "desktop.html", "docs.html",
    "hash-chain.html", "how-it-works.html", "judge.html", "legal.html",
    "partnerships.html", "passport.html", "pricing.html", "reviews.html",
    "sdk.html", "verify-page.html", "welcome.html",
)

#: Every page of the marketing surface (themed or not) — the no-CDN and
#: no-gmail bans are surface-wide, legal documents included.
ALL_HTML = sorted(p.name for p in _HERE.glob("*.html"))

#: The eleven legal documents the theme must NOT leak into.
LEGAL_DOCS = (
    "privacy.html", "terms.html", "terms-of-use.html", "refund.html",
    "report-abuse.html", "acceptable-use.html", "cookie-policy.html",
    "trust.html", "sla.html", "dpa.html", "msa.html",
)


def _read(name: str) -> str:
    return (_HERE / name).read_text(encoding="utf-8")


def _thm_declarations(src: str) -> tuple[str, ...]:
    """The --thm-* declarations, in order, whitespace-normalized per line —
    byte-equality of every declaration without caring how a file indents."""
    return tuple(m.strip() for m in re.findall(r"--thm-[a-z-]+\s*:[^;]+;", src))


def _font_faces(src: str) -> tuple[str, ...]:
    """Every @font-face rule, byte-for-byte (whitespace collapsed)."""
    return tuple(re.sub(r"\s+", "", f)
                 for f in re.findall(r"@font-face\s*\{.*?\}", src, re.S))


# ── 1 · the token block is one block, everywhere ─────────────────────────────

def test_the_token_block_is_byte_identical_in_every_carrier():
    master = _thm_declarations(_read("index.html"))
    assert len(master) == 9, (
        f"index.html should declare exactly the nine --thm-* tokens, "
        f"found {len(master)}: {master}")
    for carrier in CARRIERS[1:]:
        got = _thm_declarations(_read(carrier))
        assert got == master, (
            f"{carrier}'s token block has drifted from index.html's.\n"
            f"  master: {master}\n  {carrier}: {got}\n"
            f"The theme is ONE set of values; a carrier that drifts restyles "
            f"its pages silently")


def test_every_themed_page_reaches_a_carrier():
    for page in SITECSS_PAGES:
        assert re.search(r'<link[^>]+href="/site\.css"', _read(page)), (
            f"{page} no longer links /site.css — it stopped inheriting the "
            f"master theme the moment that link went")


def test_the_theme_does_not_leak_into_the_legal_documents():
    for page in LEGAL_DOCS:
        src = _read(page)
        assert not _thm_declarations(src), (
            f"{page} carries --thm-* tokens. The legal documents' "
            f"warm-charcoal style is deliberate and out of scope")
        assert "site.css" not in src, (
            f"{page} links site.css — that would restyle a legal document")


# ── 2 · the fonts are embedded, identical, and never fetched ─────────────────

def test_no_page_fetches_fonts_from_a_cdn():
    for page in ALL_HTML + ["site.css"]:
        src = _read(page)
        assert "fonts.googleapis" not in src and "fonts.gstatic" not in src, (
            f"{page} fetches fonts from Google — the owner decision (#10) is "
            f"embedded faces only; a font CDN sends the reader's IP to a "
            f"third party")


def test_the_embedded_faces_are_the_same_bytes_everywhere():
    """W5 (#212) re-aimed this: the three carriers now embed a THIRD face —
    the true Poppins 800 for display headings (fetched once at build time;
    runtime stays zero-external). The legal pages keep their settled pair
    (their headings ask for 600/700 and nothing heavier), so the invariant is:
    carriers = the legal pair + exactly one 800, all byte-equal across
    carriers."""
    reference = _font_faces(_read("privacy.html"))
    assert len(reference) == 2, (
        f"privacy.html (the settled model) should embed exactly two faces, "
        f"found {len(reference)}")
    weights = sorted(re.search(r"font-weight:(\d+)", f).group(1)
                     for f in reference)
    assert weights == ["600", "700"], f"the model's weights moved: {weights}"
    carrier_faces = {c: _font_faces(_read(c))
                     for c in ("site.css", "index.html", "book-a-demo.html")}
    for carrier, got in carrier_faces.items():
        assert len(got) == 3, (
            f"{carrier} embeds {len(got)} faces, not 3 (the legal pair + the "
            f"true 800)")
        assert all(r in got for r in reference), (
            f"{carrier} dropped one of the legal pages' settled faces")
        eight = [g for g in got if "font-weight:800" in g]
        assert len(eight) == 1, (
            f"{carrier} carries {len(eight)} weight-800 faces, not one")
    eights = {c: [g for g in fs if "font-weight:800" in g][0]
              for c, fs in carrier_faces.items()}
    assert len(set(eights.values())) == 1, (
        "the 800 face differs between carriers — one surface, one font file; "
        "a re-subset on one carrier is a different font on one page")


# ── 3 · the gmail is gone, forever ───────────────────────────────────────────

def test_zero_gmail_across_the_surface():
    offenders = [p for p in ALL_HTML if "@gmail.com" in _read(p)]
    assert not offenders, (
        f"@gmail.com is back on {offenders} — #190: the support address is "
        f"support@foxyaudit.tech, and L4 settled that security@ is only for "
        f"vulnerability disclosure")


def test_the_replacement_address_is_the_support_mailbox():
    for page, n in (("contact.html", 3), ("book-a-demo.html", 1),
                    ("partnerships.html", 1), ("index.html", 1)):
        got = _read(page).count("support@foxyaudit.tech")
        assert got >= n, (
            f"{page}: expected at least {n} support@foxyaudit.tech, found "
            f"{got} — the gmail removal must not silently drop the contact "
            f"route itself")


# ── 4 · the fox emoji is a logo now ──────────────────────────────────────────

def test_no_fox_emoji_anywhere():
    """#12, owner: "logo or nothing" — CLOSED by W5: the legal headers were
    the last carriers, and their mark became /logo.png. Zero, everywhere,
    forever."""
    offenders = [p for p in ALL_HTML if "\U0001f98a" in _read(p)]
    assert not offenders, f"the fox emoji is back on {offenders}"


# ── 5 · the chrome actually consumes the tokens (rendered, via cssRules) ─────

_CHROME_BIN = None


def _chrome():
    global _CHROME_BIN
    if _CHROME_BIN is None:
        import os, shutil
        _CHROME_BIN = (os.environ.get("CHROME_BIN")
                       or shutil.which("chrome") or shutil.which("google-chrome")
                       or next((p for p in (
                           r"C:\Program Files\Google\Chrome\Application\chrome.exe",
                           r"C:\Program Files (x86)\Google\Chrome\Application\chrome.exe",
                       ) if pathlib.Path(p).exists()), ""))
    return _CHROME_BIN


needs_chrome = pytest.mark.skipif(
    not pathlib.Path(r"C:\Program Files\Google\Chrome\Application\chrome.exe").exists()
    and not pathlib.Path(r"C:\Program Files (x86)\Google\Chrome\Application\chrome.exe").exists(),
    reason="Chrome not available")

_PROBE = r"""
(function(){
  var out={};
  function sheets(fn){ [].forEach.call(document.styleSheets,function(sh){
    var rules; try{ rules=sh.cssRules; }catch(e){ return; }
    [].forEach.call(rules, fn); }); }
  out.rules={};
  sheets(function(r){
    if(r.selectorText==='.topnav'||r.selectorText==='footer'||r.selectorText==='body'
       ||r.selectorText==='.gcard'||r.selectorText==='.footer-col a')
      out.rules[r.selectorText]=r.cssText;
  });
  var cs=getComputedStyle(document.documentElement);
  out.thmInk=cs.getPropertyValue('--thm-ink').trim();
  out.bodyBg=getComputedStyle(document.body).backgroundImage;
  // Does the display face actually RENDER? Widths cannot be fooled by
  // document.fonts.check() — if the face never loaded, the Poppins string
  // measures exactly the fallback.
  var c=document.createElement('canvas').getContext('2d');
  var probe='About Foxy Audit Compliance';
  c.font='700 34px Poppins, "NoSuchFallbackXYZ"'; out.wDisplay=c.measureText(probe).width;
  c.font='700 34px "NoSuchFallbackXYZ"';          out.wFallback=c.measureText(probe).width;
  out.fetched=performance.getEntriesByType('resource').map(function(r){return r.name;});
  document.documentElement.innerHTML='<pre id="p">'+JSON.stringify(out)+'</pre>';
})();
"""

_cache: dict = {}


@pytest.fixture(scope="module")
def rendered():
    """about.html — a representative site.css page — in a real browser, once.
    The page and site.css are copied together so the stylesheet resolves."""
    if "d" in _cache:
        return _cache["d"]
    import json, subprocess, tempfile
    with tempfile.TemporaryDirectory() as tmp:
        tmpdir = pathlib.Path(tmp)
        page = tmpdir / "about.html"
        # ⚠ the stylesheet is INLINED for the probe: a <link> under file:// is
        # cross-origin to the page, so its cssRules THROW and every CSSOM
        # assertion would silently see nothing — measured, not guessed. The
        # parsed text is identical either way.
        html = _read("about.html").replace(
            '<link rel="stylesheet" href="/site.css">',
            "<style>\n" + _read("site.css") + "\n</style>")
        assert "<style>" in html, "the site.css link was not where expected"
        page.write_text(
            html
            + "\n<script>window.addEventListener('load',function(){setTimeout("
              "function(){try{" + _PROBE + "}catch(e){document.documentElement.innerHTML="
              "'<pre id=\"p\">'+JSON.stringify({error:String(e)})+'</pre>';}},600);});</script>",
            encoding="utf-8")
        # Bounded, and it kills only THIS process — never taskkill chrome by name.
        proc = subprocess.run(
            [_chrome(), "--headless=new", "--no-sandbox",
             "--virtual-time-budget=8000", "--window-size=1280,900",
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
def test_the_subpage_chrome_reads_the_tokens(rendered):
    topnav = rendered["rules"].get(".topnav", "")
    assert "var(--thm-chrome)" in topnav and "var(--thm-chrome-line)" in topnav, (
        "the sub-page topnav no longer consumes the theme tokens")
    footer = rendered["rules"].get("footer", "")
    assert "var(--thm-chrome-line)" in footer, "the footer hairline left the tokens"
    links = rendered["rules"].get(".footer-col a", "")
    assert "var(--thm-ink-soft)" in links, "footer link ink left the tokens"
    assert rendered["thmInk"] == "rgba(244,246,252,.92)", (
        f"--thm-ink did not resolve on a sub-page: {rendered['thmInk']!r}")


@needs_chrome
def test_the_ground_is_the_indigo_family_not_the_orange_radial(rendered):
    bg = rendered["bodyBg"]
    assert "linear-gradient" in bg and "radial-gradient" not in bg, (
        f"the sub-page ground is not the W2 gradient family: {bg[:120]}")


@needs_chrome
def test_the_panels_wear_the_master_glass(rendered):
    gcard = rendered["rules"].get(".gcard", "")
    assert "var(--thm-fill-a)" in gcard and "var(--thm-chrome-line)" in gcard, (
        "the panel glass no longer reads the theme fill/rim tokens")
    assert "255, 122, 46" not in gcard and "rgba(255,122,46" not in gcard, (
        "an orange glow crept back into the panel glass")


@needs_chrome
def test_poppins_renders_from_the_embedded_faces(rendered):
    assert abs(rendered["wDisplay"] - rendered["wFallback"]) > 1.0, (
        "Poppins was named but never loaded — with the CDN gone the embedded "
        "faces are the only source, and the heading rendered in the fallback")
    third_party = [u for u in rendered["fetched"]
                   if u.startswith("http") and "fonts.g" in u]
    assert not third_party, f"the page still fetched from a font CDN: {third_party}"
