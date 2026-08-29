"""The compliance passport must not let a customer write CSS into their own evidence.

One value in ``compliance_passport.html`` lands in CSS rather than in markup: the
running footer, ``content:"… · date to date"`` inside the ``@page`` block. Jinja's
autoescape is inert there — ``<style>`` is a raw-text element, so the ``&#34;`` it
emits for a quote is five literal characters to a CSS parser and not a delimiter —
but a RAW NEWLINE ends a CSS string as a ``<bad-string>`` and everything after it
parses as CSS.

``org.name`` is customer-chosen: ``SignupRequest.name`` on the public
``POST /v1/signup`` is an unvalidated ``str | None`` kept verbatim apart from
``.strip()[:255]``. Both halves of that were true at ``50afee9``, and together they
gave a customer two things they must never have:

* a **URL the server fetches** — ``content:url(http://169.254.169.254/…)`` in the
  margin box, resolved through weasyprint's ``default_url_fetcher`` to ``urlopen``;
* a **top-level CSS rule** — ``.seal,.seal-facts{display:none}``, which removes the
  CHAIN BROKEN seal from the document an auditor is handed.

The second needs no network at all, which is why the fix is two guards and not one:
``_css_string`` closes the injection, and ``_passport_url_fetcher`` is the boundary
that still holds if a future edit reopens one. Each is tested on its own here, so a
regression in either is attributable rather than merely visible.

Deliberately dependency-free: these assertions read the rendered document with
``re`` and nothing else. ``tinycss2`` proves more but is NOT in
``backend/requirements.txt``, and a guard that needs a package CI does not install
is a guard that skips exactly where it matters (see #258 / #263 / #266).
"""
from __future__ import annotations

import re
import sys

import pytest

from app.routers.passport import _css_string, _passport_url_fetcher

NL = chr(10)
BS = chr(92)

# The two payloads that were confirmed to work against 50afee9, verbatim.
SSRF_NAME = "Acme Health" + NL + "; content:url(http://169.254.169.254/latest/meta-data/) ;"
FORGE_NAME = ("Acme Health" + NL + "}}" + NL
              + ".seal,.seal-facts,.seal-state{display:none}" + NL
              + "@page{@bottom-left{content:url(http://evil.test/x) ;")
BREAKOUT_NAME = "Acme Health</style><style>.seal,.seal-facts{display:none}"


def _stub_renderer(monkeypatch) -> dict:
    """A weasyprint stand-in that records BOTH the html and the kwargs it was given.

    The existing passport tests' stub swallows kwargs in ``**kw``; this one keeps
    them, because "was a url_fetcher actually passed?" is half of what is under
    test and a stub that discards it cannot answer.
    """
    captured: dict = {}

    class _FakeHTML:
        def __init__(self, string=None, **kw):
            captured["html"] = string
            captured["kwargs"] = kw

        def write_pdf(self):
            return b"%PDF-1.7" + NL.encode() + b"stub" + NL.encode() + b"%%EOF"

    fake = type(sys)("weasyprint")
    fake.HTML = _FakeHTML
    monkeypatch.setitem(sys.modules, "weasyprint", fake)
    return captured


def _render(client, make_org, monkeypatch, org_name):
    doc = _stub_renderer(monkeypatch)
    org = make_org(name=org_name)
    response = client.post("/v1/passport", headers=org["auth"])
    assert response.status_code == 200, response.text
    return doc


def _style_block(html: str) -> str:
    blocks = re.findall(r"<style[^>]*>(.*?)</style>", html, re.S)
    assert len(blocks) == 1, "expected exactly one <style> block, got %d" % len(blocks)
    return blocks[0]


def _footer_content_line(html: str) -> str:
    """The one line of CSS the org name is interpolated into."""
    style = _style_block(html)
    block = style[style.index("@bottom-left{"):]
    return block.split("content:", 1)[1].split(NL, 1)[0].rstrip()


def _css_outside_strings(html: str) -> str:
    """The style block with well-formed single-line string literals blanked out.

    The distinction this draws is the whole point of the fix: a URL sitting
    INSIDE a closed CSS string is text on a page footer, and a URL outside one is
    a resource the renderer resolves. The escaped payload contains the former by
    design, so a scan that cannot tell them apart flags the fix as the bug.

    Blanking a string is only sound because
    ``test_hostile_org_name_stays_inside_the_css_string`` has separately proved
    every string here opens and closes on one line — which is exactly what was
    untrue before this change.
    """
    style = _style_block(html)
    style = re.sub('"[^"' + NL + ']*"', '""', style)
    return re.sub("'[^'" + NL + "]*'", "''", style)


# ── Guard 1: the value cannot leave its CSS string ───────────────────────────

@pytest.mark.parametrize("name", [SSRF_NAME, FORGE_NAME, BREAKOUT_NAME],
                         ids=["ssrf", "forge", "breakout"])
def test_hostile_org_name_stays_inside_the_css_string(make_org, client, monkeypatch, name):
    """The footer declaration opens and closes on one line, whatever the name is.

    This is the whole defect in one assertion: at 50afee9 the line ended at the
    raw newline with the string still open, and the remainder of the name was
    parsed as CSS.
    """
    doc = _render(client, make_org, monkeypatch, name)
    line = _footer_content_line(doc["html"])
    assert line.startswith('"'), line
    assert line.endswith('";'), line
    assert NL not in line


@pytest.mark.parametrize("name", [SSRF_NAME, FORGE_NAME, BREAKOUT_NAME],
                         ids=["ssrf", "forge", "breakout"])
def test_hostile_org_name_cannot_put_a_fetchable_url_in_the_document(
        make_org, client, monkeypatch, name):
    """Every URL a passport asks the renderer to resolve is an inline ``data:`` URI.

    Two places can name one: a ``url()`` in real CSS, and a ``src``/``href`` in
    markup. The org name appears in the document body as well, as escaped text,
    and a payload quoted back there is inert — so this looks at the two fetchable
    positions rather than at every occurrence of the payload's characters.
    """
    doc = _render(client, make_org, monkeypatch, name)

    css = _css_outside_strings(doc["html"])
    assert "169.254.169.254" not in css
    assert "evil.test" not in css
    in_css = re.findall(r"""url\(([^)]{0,160})""", css)
    assert in_css, "no url() found at all — the scan is looking at the wrong text"
    for value in in_css:
        stripped = value.strip().strip("\"'")
        assert stripped == "" or stripped.startswith("data:"), value

    in_markup = (re.findall(r"""src\s*=\s*['"]([^'"]{0,160})""", doc["html"])
                 + re.findall(r"""href\s*=\s*['"]([^'"]{0,160})""", doc["html"]))
    assert in_markup, "no src/href found at all — the scan is looking at the wrong text"
    assert [u for u in in_markup if not u.startswith("data:")] == []


def test_hostile_org_name_cannot_close_the_style_element(make_org, client, monkeypatch):
    """``</style>`` in the name would end the raw-text element and start markup."""
    doc = _render(client, make_org, monkeypatch, BREAKOUT_NAME)
    _style_block(doc["html"])            # asserts exactly one <style> survives
    assert "<style>.seal" not in doc["html"]


def test_a_legible_name_survives_escaping_unmangled(make_org, client, monkeypatch):
    """The escaping is CSS escaping, not HTML escaping — and not a sanitiser.

    ``&`` is inert inside a CSS string, so an org called "A&B" must reach the
    footer as ``A&B``. It rendered as ``A&amp;B`` before this change, because the
    only escaping in play was Jinja's, in a context where Jinja's is wrong. A
    future edit that swaps ``_css_string`` back for an HTML escaper passes every
    security assertion above and fails here.
    """
    doc = _render(client, make_org, monkeypatch, "A&B Ålborg Ltd")
    line = _footer_content_line(doc["html"])
    assert "A&B Ålborg Ltd" in line
    assert "&amp;" not in line


# ── Guard 2: the renderer is told to fetch nothing ───────────────────────────

def test_the_renderer_is_handed_the_refusing_url_fetcher(make_org, client, monkeypatch):
    """weasyprint's DEFAULT fetcher reaches the whole network. It must not be used."""
    doc = _render(client, make_org, monkeypatch, "Ordinary Clinic")
    assert doc["kwargs"].get("url_fetcher") is _passport_url_fetcher


@pytest.mark.parametrize("url", [
    "http://169.254.169.254/latest/meta-data/",
    "https://example.test/x.png",
    "file:///etc/passwd",
    "ftp://example.test/x.png",
    "HTTP://EXAMPLE.TEST/x.png",
    "//example.test/x.png",
    "data.example.test/x.png",
])
def test_url_fetcher_refuses_everything_that_is_not_a_data_uri(url):
    with pytest.raises(ValueError):
        _passport_url_fetcher(url)


def test_url_fetcher_still_resolves_the_inline_assets(monkeypatch):
    """``data:`` is delegated to weasyprint, which is how the seals render at all.

    Stubbed because weasyprint is not installed in the test venv (it is
    lazy-imported for exactly that reason). This proves the delegation, not
    weasyprint's own behaviour.
    """
    seen = {}

    def _fetch(u):
        seen["url"] = u
        return {"string": b"", "mime_type": "image/png"}

    urls_mod = type(sys)("weasyprint.urls")
    urls_mod.default_url_fetcher = _fetch
    wp = type(sys)("weasyprint")
    wp.urls = urls_mod
    monkeypatch.setitem(sys.modules, "weasyprint", wp)
    monkeypatch.setitem(sys.modules, "weasyprint.urls", urls_mod)

    uri = "data:image/png;base64,iVBORw0KGgo="
    assert _passport_url_fetcher(uri) == {"string": b"", "mime_type": "image/png"}
    assert seen["url"] == uri


def test_css_string_escapes_the_control_characters_that_end_a_string():
    """The unit under the two guards above, stated directly.

    The trailing space on each escape is load-bearing: CSS consumes up to six hex
    digits and then one following whitespace, so ``A" B`` would otherwise come
    back as ``A"B``.
    """
    assert _css_string("plain name") == "plain name"
    assert _css_string("A" + NL + "B") == "A" + BS + "00000a B"
    assert _css_string('A"B') == "A" + BS + "000022 B"
    assert _css_string("A" + BS + "B") == "A" + BS + "00005c B"
    assert _css_string("A<B") == "A" + BS + "00003c B"
    # Left alone on purpose: inert inside a string literal, and mangling them
    # would corrupt ordinary names.
    assert _css_string("A&B {x} }") == "A&B {x} }"
