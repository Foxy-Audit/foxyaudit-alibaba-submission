"""W4 — thirteen cards become five, the pop-ups die, every card keeps its promise.

The homepage has carried a bubble reading "Click any card — each opens its own
page" over cards that opened a pop-up first. W4 makes the promise true: five
slides (What Foxy Audit is · How to Install · Book a Demo · See Pricing · FAQ),
each card a real <a> to a real page, and the card-detail modal removed as a
MECHANISM — handlers, markup, CSS and state — because orphaned modal code is
how it resurrects.

What survives deliberately, and why it is not a violation:

  · **the lead modal** (`leadBackdrop`). It is a conversion form the checkout
    flow depends on (#36: signed-in purchases route through it), not a card
    preview. The owner's words were "remove all mini pop-up cards. Every card
    should link directly to its page" — cards, not forms.

The other invariants:

  · **docs.html is a hub, not a placeholder.** The four cards that lost their
    slide (Hash Chain, Judge, Verify, Passport) keep their pages; docs.html
    links all of them plus sdk/how-it-works/install — real pages, honest
    one-liners, no "coming soon".

  · **judge.html never implies content reading.** backend/app/gemini.py's own
    system prompt is the truth: the judge receives two opaque commitments, a
    token count, a policy tag and optional pii_signals — "You NEVER see the
    prompt or response text." The local policy engine (before the call) and
    the judge (after) are different machines and the page must say so.

  · **the planned Copilot on pricing is unmistakably PLANNED.** A pricing page
    is a commercial promise and the hard rule is no fake data — the agent row
    carries its own planned styling and label, never flush beside shipped
    features.

  · **the FAQ's ask-a-question control reaches something real** — the same
    /v1/leads route the contact and demo forms use, with the honest
    email-us-instead fallback when the POST fails.

Run:  pytest foxy-sale-page -q
"""

from __future__ import annotations

import pathlib
import re

import pytest

_HERE = pathlib.Path(__file__).resolve().parent
INDEX = (_HERE / "index.html").read_text(encoding="utf-8")


def _strip_comments(s: str) -> str:
    s = re.sub(r"/\*.*?\*/", " ", s, flags=re.S)
    s = re.sub(r"<!--.*?-->", " ", s, flags=re.S)
    return re.sub(r"(?<!:)//[^\n]*", " ", s)


def _slides_block() -> str:
    """The SLIDES array source, brace/bracket-matched — a window is not a scope."""
    m = re.search(r"const SLIDES = \[", INDEX)
    assert m, "SLIDES is gone from index.html"
    depth, i = 0, INDEX.index("[", m.start())
    start = i
    while True:
        if INDEX[i] == "[":
            depth += 1
        elif INDEX[i] == "]":
            depth -= 1
            if depth == 0:
                return INDEX[start:i + 1]
        i += 1
        assert i < len(INDEX), "unbalanced SLIDES array"


def _read(name: str) -> str:
    p = _HERE / name
    assert p.exists(), f"{name} does not exist"
    return p.read_text(encoding="utf-8")


# ── 1 · exactly five slides, and these five ──────────────────────────────────

def test_exactly_five_slides():
    block = _slides_block()
    ghosts = re.findall(r'ghost:\s*"([^"]+)"', block)
    assert len(ghosts) == 5, (
        f"the carousel carries {len(ghosts)} slides, not five: {ghosts}. "
        f"The owner's spec names five cards; the other content lives on its "
        f"own pages, reachable through docs.html")


def test_the_five_slides_are_the_owners_five():
    block = _slides_block()
    pairs = re.findall(r'cardTitle:\s*"([^"]+)"[\s\S]*?ctaHref:\s*"([^"]+)"', block)
    titles = [t for t, _ in pairs]
    hrefs = dict(pairs)
    for title, href in (
        ("What Foxy Audit is", "/how-it-works.html"),
        ("How to install", "/install.html"),
        ("Book a demo", "/book-a-demo.html"),
        ("See Pricing", "/pricing.html"),
        ("FAQ", "/faq.html"),
    ):
        assert title in titles, f"slide {title!r} is missing (have {titles})"
        assert hrefs.get(title) == href, (
            f"slide {title!r} points at {hrefs.get(title)!r}, not {href!r}")
    # the pricing fast-forward CTA still needs its marker
    assert "isPricing" in block, "the See Pricing slide lost its isPricing marker"


def test_every_slide_links_to_a_page_that_exists():
    for href in re.findall(r'ctaHref:\s*"/([^"]+)"', _slides_block()):
        assert (_HERE / href).exists(), (
            f"a card links to /{href}, which does not exist — a dead card is "
            f"the pop-up problem wearing a different hat")


# ── 2 · the pop-up mechanism is gone, wholesale ──────────────────────────────

def test_the_card_modal_mechanism_is_gone():
    text = _strip_comments(INDEX)
    for token in ("openModal", "closeModal", "modalBackdrop", "modalCard",
                  "modalDesc", "modalTop", "modalIcon", "modalBody",
                  "openContactModal", "contactBackdrop"):
        assert token not in text, (
            f"{token!r} survives in index.html — the card modal must go as a "
            f"MECHANISM (handlers, markup, CSS, state), because orphaned modal "
            f"code is how it resurrects")


def test_the_lead_modal_survives_on_purpose():
    """The checkout flow routes through it (#36) — deleting it breaks purchases."""
    text = _strip_comments(INDEX)
    assert "openLeadModal" in text and "leadBackdrop" in text, (
        "the lead-capture modal was deleted along with the card modal — it is "
        "a conversion form the checkout flow depends on, not a card pop-up")


def test_the_promise_line_stays():
    # comment-stripped: a code comment quoting the promise must not satisfy
    # the guard for the bubble the visitor actually reads
    text = _strip_comments(INDEX)
    assert "Click any card" in text and "each opens its own page" in text, (
        "the homepage's own promise line is gone — W4 exists to make it true, "
        "not to delete the promise")


# ── 3 · the four removed cards' content is re-homed ──────────────────────────

def test_docs_is_a_hub_of_real_pages_not_a_placeholder():
    docs = _read("docs.html")
    assert "on the way" not in docs and "coming soon" not in docs.lower(), (
        "docs.html still reads as a placeholder — W4 closes it honestly with "
        "a hub of real pages")
    for target in ("/hash-chain.html", "/judge.html", "/verify-page.html",
                   "/passport.html", "/sdk.html", "/how-it-works.html"):
        assert f'href="{target}"' in docs, (
            f"docs.html does not link {target} — the four de-carded topics and "
            f"the two guides are the whole point of the hub")
        assert (_HERE / target.lstrip("/")).exists()


# ── 4 · the judge page tells the truth about the judge ───────────────────────

def test_judge_page_names_the_exact_inputs_and_denies_content_reading():
    judge = _read("judge.html")
    # gemini.py's system prompt receives: commitments, token count, policy
    # tag, pii_signals — and never the text. The page must say the same.
    for needle in ("commitment", "token count", "policy tag", "pii_signals"):
        assert needle in judge, (
            f"judge.html no longer names {needle!r} — the inputs list is the "
            f"page's proof it matches backend/app/gemini.py")
    assert re.search(r"never\s+(sees?|receives?|reads?)", judge, re.I), (
        "judge.html dropped the never-sees-the-text sentence")


def test_judge_page_separates_the_two_machines():
    judge = _read("judge.html")
    assert re.search(r"before\s+the\s+model\s+call", judge, re.I), (
        "the local policy engine (blocks/redacts BEFORE the call) is not "
        "described — the two machines must be plainly separated")
    assert re.search(r"after", judge, re.I) and "advisory" in judge.lower(), (
        "the judge grading AFTER capture, advisory and not chained, is not "
        "described")


def test_judge_page_makes_no_content_reading_claim():
    text = re.sub(r"<[^>]+>", " ", _read("judge.html"))
    # Sentences that would imply the judge reads content. Checked against a
    # tag-stripped body so markup cannot split a phrase.
    for phrase in ("reads your prompt", "reads the prompt", "reads your data",
                   "analyzes your prompt", "analyses your prompt",
                   "scans your prompt", "reviews your prompt",
                   "reads the response", "sees your prompt"):
        assert phrase not in text.lower(), (
            f"judge.html says {phrase!r} — #191: this page must never imply "
            f"content reading; gemini.py's prompt receives hashes and counts")


# ── 5 · the planned Copilot is unmistakably planned ──────────────────────────

def test_the_planned_agent_is_labelled_planned_and_set_apart():
    pricing = _read("pricing.html")
    assert "Foxy Copilot" in pricing, (
        "the planned agent is gone from the Max plan (owner: add the agent we "
        "plan to build)")
    m = re.search(r'class="planned-feature"[^>]*>([\s\S]{0,400}?)</li>', pricing)
    assert m, (
        "the Copilot row lost its own planned-feature styling — a pricing "
        "page is a commercial promise, and a planned item flush beside "
        "shipped features reads as shipped")
    row = m.group(1)
    assert "Foxy Copilot" in row and re.search(r"planned|coming", row, re.I), (
        f"the planned-feature row does not carry both the name and a planned "
        f"label: {row[:160]!r}")


# ── 6 · the FAQ control reaches something real ───────────────────────────────

def test_faq_exists_with_the_five_answerable_sections():
    faq = _read("faq.html")
    assert faq.count("faq-item") >= 5, "faq.html carries fewer than five questions"
    assert 'href="/site.css"' in faq, "faq.html does not inherit the master theme"


def test_the_ask_a_question_control_posts_to_the_leads_route():
    # comment-stripped: this file's own comments name the route, and a guard
    # answered by prose is no guard
    faq = _strip_comments(_read("faq.html"))
    assert "/v1/leads" in faq, (
        "the ask-a-question control no longer reaches /v1/leads — an input "
        "that silently drops questions is worse than a link")
    assert "support@foxyaudit.tech" in faq, (
        "the honest failure fallback (email us instead) is gone")
    assert re.search(r"source\s*:\s*'support'", faq), (
        "the question no longer arrives as a support-sourced lead — that is "
        "the source the backend notifies on")


# ── 7 · the install article is the shipped truth ─────────────────────────────

def test_install_article_teaches_the_three_readme_methods():
    install = _read("install.html")
    assert "pip install foxy-audit" in install, (
        "the install command is gone — sdk/README.md is the shipped truth")
    # the three ways in, as the README ships them
    assert "@foxy.audit" in install or "@audit" in install, (
        "method 1 (the decorator) is missing")
    assert "foxy check" in install, (
        "method 2 (the check() pre-flight, CLI/CI) is missing")
    assert "foxy explain" in install, (
        "method 3 (the explain() local replay) is missing")
    assert 'href="/site.css"' in install, "install.html is off-theme"


def test_the_install_card_and_docs_both_reach_the_article():
    assert (_HERE / "install.html").exists()
    docs = _read("docs.html")
    assert 'href="/install.html"' in docs, "docs.html does not link the install article"


# ── 8 · rendered: every card IS a link, and the maths holds at N=5 ───────────

import os
import shutil

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
  var cards=[].slice.call(document.querySelectorAll('#cards .card'));
  out.count=cards.length;
  out.tags=cards.map(function(c){return c.tagName;});
  out.hrefs=cards.map(function(c){return c.getAttribute('href');});
  // the role split the layout maths produced at N=5
  out.roles={center:document.querySelectorAll('.card.is-center').length,
             visible:[].filter.call(cards,function(c){return parseFloat(c.style.opacity)>0;}).length};
  out.refl=document.querySelectorAll('.card-refl').length;
  // advancing still works with five
  goTo(2);
  setTimeout(function(){
    out.afterGoTo=document.querySelector('.card.is-center').dataset.index;
    out.promise=(document.body.textContent.indexOf('each opens its own page')>=0);
    out.deadModal=!!document.getElementById('modalBackdrop');
    document.documentElement.innerHTML='<pre id="p">'+JSON.stringify(out)+'</pre>';
  }, 900);
})();
"""

_cache: dict = {}


@pytest.fixture(scope="module")
def rendered():
    if "d" in _cache:
        return _cache["d"]
    import json, subprocess, tempfile
    with tempfile.TemporaryDirectory() as tmp:
        page = pathlib.Path(tmp) / "index.html"
        page.write_text(
            INDEX + "\n<script>window.addEventListener('load',function(){setTimeout("
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
    assert m, f"the probe never ran; chrome said: {proc.stderr[-400:]}"
    data = json.loads(m.group(1))
    assert not data.get("error"), data["error"]
    _cache["d"] = data
    return data


@needs_chrome
def test_every_rendered_card_is_an_anchor_with_an_href(rendered):
    assert rendered["count"] == 5, f"{rendered['count']} cards rendered, not 5"
    assert rendered["tags"] == ["A"] * 5, (
        f"cards are {rendered['tags']} — every card must BE a link, not carry "
        f"a click handler that imitates one")
    for href in rendered["hrefs"]:
        assert href and href.startswith("/") and (_HERE / href.lstrip("/")).exists(), (
            f"a rendered card's href does not resolve: {href!r}")


@needs_chrome
def test_the_carousel_maths_holds_at_five(rendered):
    assert rendered["roles"]["center"] == 1, "exactly one centre card"
    # centre + left + right visible; the two back cards sit at opacity 0
    assert rendered["roles"]["visible"] == 3, (
        f"{rendered['roles']['visible']} cards visible at N=5 — roleFor/layout "
        f"were verified for N>5; this is the N=5 proof")
    assert rendered["refl"] == 5, "one reflection per card"
    assert str(rendered["afterGoTo"]) == "2", (
        f"goTo(2) centred card {rendered['afterGoTo']!r} — the modular maths "
        f"broke at N=5")


@needs_chrome
def test_the_promise_is_rendered_and_the_modal_is_not(rendered):
    assert rendered["promise"], "the promise bubble no longer renders"
    assert not rendered["deadModal"], "a #modalBackdrop element rendered"
