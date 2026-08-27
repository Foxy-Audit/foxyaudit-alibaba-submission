"""R4 — the AI-system registry page, guarded where a diff review would not look.

Five things this page can get wrong in ways that read as correct in a diff:

* **A chip that is readable and invisible.** This surface has already shipped a
  pill whose ink cleared 4.5:1 while the pill itself measured 1.01:1 against the
  card behind it and dissolved. Every lifecycle chip is therefore measured TWICE
  — the ink against the fill, and the fill against both card surfaces it can sit
  on (`--surf`, and `--surf2` on a hovered row). It very nearly happened again:
  the first draft of this page took `--warn-bg` for `draft`, whose ink clears
  6.47:1 while the fill measures **1.89:1** on the light card.

* **An empty state that invents a row.** A registry Foxy populated would be
  precisely the inferred inventory this feature exists to refuse, so the check
  is not "is there an empty state" but "is there anywhere a system-shaped row
  could come from that is not the API".

* **A retire dialog that reads like an archive.** There is no un-retire endpoint
  and there never will be. Copy that leaves a reader thinking otherwise is a lie
  about the product, and it is invisible to every other guard in this directory.

* **A promise of evidence this page cannot show.** `/v1/logs` has no `system_id`
  filter and there is no per-system aggregation endpoint. An event count or a
  "see this system's evidence" link would be a number the page cannot obtain.

* **A silent mislabel.** `PAGE_TITLE` and `CTX` both fall back rather than fail,
  so a page missing from either is titled as some other page and nothing breaks.

The contrast maths is imported from `test_p1_contrast`, which pins black-on-white
at 21.0 before judging anything — one implementation, already self-tested,
rather than a second copy that could be wrong in the same direction twice.
"""

from __future__ import annotations

import json
import os
import pathlib
import re
import shutil
import subprocess
import tempfile
from functools import lru_cache
from pathlib import Path

import pytest

from test_p1_contrast import _block, _declarations, _stylesheet, ratio

HTML = Path(__file__).resolve().parent / "foxy-audit-premium.html"

AA_BODY = 4.5      # WCAG 1.4.3 — the chip's word is text
UI_FLOOR = 3.0     # WCAG 1.4.11 — the chip's fill is a UI component boundary

#: (modifier, css fill token, css ink token). `active` is the BASE rule and
#: carries no modifier on purpose — see the note in the stylesheet.
CHIPS = [("", "muted", "surf"),
         ("draft", "ink2", "surf"),
         ("retired", "ink", "surf")]

#: Both surfaces a chip can sit on. `.dtbl tbody tr:hover` repaints the row
#: `--surf2`, and a chip that dissolves only on hover is the same defect.
CARDS = ["surf", "surf2"]


@lru_cache(maxsize=1)
def source() -> str:
    return HTML.read_text(encoding="utf-8")


@lru_cache(maxsize=1)
def page() -> str:
    """The Systems page's markup alone, so a match cannot come from elsewhere."""
    start = source().index('<div class="page" id="page-systems">')
    end = source().index('<!-- ═════════════ EXPORT ═════════════ -->', start)
    return source()[start:end]


@lru_cache(maxsize=1)
def module() -> str:
    """The R4 <script>, comments STRIPPED — a note about a rule must not be able
    to satisfy a test looking for the rule."""
    blocks = re.findall(r"<script(?![^>]*\bsrc=)[^>]*>(.*?)</script>",
                        source(), re.S)
    hit = [b for b in blocks if "window.foxSystems=" in b]
    assert len(hit) == 1, f"expected exactly one R4 module, found {len(hit)}"
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


# ══ the page exists, and is named the same thing everywhere ══════════════════
def test_the_page_is_reachable_and_named(themes):
    src = source()
    assert '<div class="page" id="page-systems">' in src
    assert 'class="dock-item" data-page="systems"' in src, \
        "the page exists with no way to reach it"
    # Both maps fall back silently, so an omission mislabels rather than fails.
    assert re.search(r"PAGE_TITLE=\{[^}]*\bsystems:'Systems'", src, re.S), \
        "PAGE_TITLE has no entry — the crumb would read the raw page id"
    assert re.search(r"var CTX=\{.*?\bsystems:\[", src, re.S), \
        "CTX has no entry — setTopbarContext falls back to ['Overview','Home'] " \
        "and the top bar names a different page entirely"


# ══ the chips, measured BOTH WAYS ═══════════════════════════════════════════
@pytest.mark.parametrize("theme", ["dark", "light"])
@pytest.mark.parametrize("modifier,fill,ink", CHIPS,
                         ids=[c[0] or "active(base)" for c in CHIPS])
def test_a_lifecycle_chip_is_readable_and_visible(themes, theme, modifier, fill, ink):
    """Ink on fill, AND fill on every card the chip can sit on.

    The declarations are read out of the shipped stylesheet, so a re-tune cannot
    quietly break either direction."""
    selector = ".syschip" + (f".{modifier}" if modifier else "")
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
    what makes ink-on-fill and fill-on-card THE SAME MEASUREMENT: one of them
    cannot pass while the other fails. Pinned because "simplifying" the ink to
    a fixed near-black would break the property while every colour still looked
    right in a screenshot."""
    for modifier, _fill, ink in CHIPS:
        assert ink == "surf", "a chip stopped inking with the card's own colour"
    for theme in ("dark", "light"):
        tokens = themes[theme]
        for modifier, fill, ink in CHIPS:
            assert ratio(tokens[ink], tokens[fill]) == ratio(tokens[fill], tokens["surf"])


def test_the_base_chip_rule_carries_a_fill(themes):
    """`active` IS the base rule, which is also what a lifecycle value this
    build has never heard of falls back to. Move the default onto a
    `.syschip.active` modifier and an unknown status renders as bare text on the
    card — a chip that is not there at all."""
    decls = _declarations(_block(_stylesheet(), ".syschip"))
    assert "background" in decls and "color" in decls, (
        "the base .syschip rule stopped declaring a fill, so an unrecognised "
        "lifecycle value would dissolve into the card")
    # The edge is what survives Windows High Contrast, which drops the fill to
    # Canvas and keeps border width and style. Same mechanism .pill relies on.
    assert decls["border"] == "var(--border-sm)", (
        "the chip's edge is what carries it in forced-colors, where the fill "
        "flattens to Canvas — measured: 1px solid, and the word survives too")


def test_lifecycle_never_borrows_a_status_hue():
    """Red, amber and green are reserved for status on this surface. A lifecycle
    is not a status: `active` is not a claim that anything is clean, and a
    critical-risk system that is behaving is not a warning. Painting one with
    --safe-bg or --warn-bg is colour asserting what the row does not state."""
    css = _stylesheet()
    for selector in (".syschip", ".syschip.draft", ".syschip.retired",
                     ".sysdata", ".sysdata.lead"):
        body = str(_declarations(_block(css, selector)))
        for banned in ("--safe-bg", "--warn-bg", "--breach-bg",
                       "--safe-ink", "--warn-ink", "--breach-ink"):
            assert banned not in body, (
                f"{selector} took {banned}. A declared property is not a state.")


# ══ the empty state — honest, and it teaches ════════════════════════════════
def test_the_empty_state_invents_no_row():
    """The register starts empty and that is NORMAL. There is no sample system
    anywhere — not in the markup, not as a fallback in the module."""
    empty = re.search(r'<div class="empty" id="sysEmpty".*?</div>\s*</div>',
                      page(), re.S)
    assert empty, "the empty state is gone"
    block = empty.group(0)
    assert "<tr" not in block and "<td" not in block, (
        "the empty state builds a table row — a placeholder row IS the invented "
        "inventory this feature exists to refuse")
    # and the module hides the table rather than filling it with a stand-in
    render = module()[module().index("function render("):]
    render = render[:render.index("function problem(")]
    assert "wrap.style.display='none'" in render, (
        "the empty branch no longer hides the table, so whatever it puts in the "
        "tbody is presented as a row of the register")
    assert "_rows.map(rowHtml)" in render, "rows come from somewhere other than _rows"
    # nothing in the file seeds _rows with anything but the API's answer
    assigns = [a.strip() for a in re.findall(r"_rows\s*=\s*([^;,]+)", module())]
    assert assigns == ["[]", "Array.isArray(data)?data:[]"], (
        f"_rows is assigned from something other than the API: {assigns}")


def test_the_empty_state_teaches_what_a_declaration_is():
    """"Nothing here" is not an empty state on a page whose whole subject is a
    thing the reader has not met yet. It has to say what a declared system IS,
    why Foxy will not guess one, and that empty is where everyone starts."""
    block = re.search(r'id="sysEmpty".*?</div>\s*</div>', page(), re.S).group(0)
    text = re.sub(r"<[^>]+>", " ", block).lower()
    assert "declared system is" in text, "it never says what a declaration is"
    assert "will not work this list out from your traffic" in text, (
        "it never says Foxy does not infer the inventory, which is the reason "
        "declaring exists at all")
    assert "every workspace starts" in text, (
        "an empty register reads as a fault unless the page says it is normal")
    assert "nothing is wrong here" in text


# ══ retirement is terminal, and the dialog has to say so ════════════════════
def test_the_retire_dialog_states_that_retirement_is_permanent():
    """There is no un-retire endpoint. PUT 409s on both edges of 'retired'. A
    dialog that reads like a reversible archive is a lie about the product."""
    body = re.search(r"retire:async function\(id\)\{(.*?)\n    \}",
                     module(), re.S)
    assert body, "the retire handler is gone or was renamed"
    copy = body.group(1)
    assert "'Retiring is permanent." in copy, \
        "the dialog no longer opens by saying it is permanent"
    assert "Nothing brings this system back" in copy
    assert "not this page, not the API" in copy, (
        "it must rule out the API too — otherwise a reader assumes support can "
        "undo it")
    assert "declare a new system, under a new id" in copy, \
        "it never says what the way forward actually is"
    # Scoped to the DIALOG's own strings. The success toast legitimately says
    # "cannot be undone", which is the same claim in the affirmative — banning
    # the substring across the whole handler would forbid the honest sentence.
    dialog = copy[copy.index("window.foxConfirm({"):copy.index("});", copy.index("window.foxConfirm({"))]
    for archival in ("archive", "Archive", "deactivate", "disable", "for now",
                     "restore", "reactivate", "can be undone", "temporar"):
        assert archival not in dialog, (
            f"the retire dialog says {archival!r} — retirement is not reversible "
            f"and the dialog may not suggest that it is")
    assert "confirm:'Retire permanently'" in copy, (
        "the confirm button no longer names the permanence; 'Retire' alone "
        "reads like a state change you could set back")


def test_the_retire_dialog_says_the_evidence_stays_and_the_name_comes_back():
    """Two true things a reader needs, or they will believe retiring destroys
    evidence, and will not know the remedy the API deliberately allows."""
    copy = re.search(r"retire:async function\(id\)\{(.*?)\n    \}",
                     module(), re.S).group(1)
    assert "keeps its place in the chain" in copy
    assert "Retiring is not deleting" in copy
    assert "nothing is removed from your evidence" in copy
    # 0069's partial index is what makes this true; if it is ever reverted the
    # copy becomes false and this is the reminder.
    assert "becomes free again" in copy, (
        "the name is released by uq_ai_system_org_name_active being partial "
        "(migration 0069) and re-declaring is the documented remedy — a "
        "customer who is not told cannot use it")


def test_retiring_asks_for_the_name_and_refuses_anything_else():
    """A terminal action a stray Enter can complete is not a terminal action.
    The typed name is compared to the system's own, and a mismatch retires
    nothing — the check has to be an equality, not a truthiness."""
    copy = re.search(r"retire:async function\(id\)\{(.*?)\n    \}",
                     module(), re.S).group(1)
    assert "input:{label:'Type \"'+s.name+'\" to confirm'" in copy
    assert "if(typed===null)return;" in copy, (
        "cancel and Escape resolve null; treating that as a falsy string would "
        "fall through to the mismatch branch and toast at somebody who cancelled")
    assert "String(typed).trim()!==s.name" in copy, \
        "the typed value is no longer compared to the name"
    guard = copy.index("String(typed).trim()!==s.name")
    call = copy.index("/retire',{method:'POST'}")
    assert guard < call, "the POST is no longer behind the name check"


def test_a_retired_row_offers_neither_retire_nor_edit():
    """Retire has no meaning twice, and edit is declined deliberately: a retired
    declaration states what was in force over a finished period, and a pencil
    against it invites rewriting history to suit the present."""
    row = re.search(r"function rowHtml\(s\)\{(.*?)\n  \}", module(), re.S)
    assert row, "rowHtml is gone"
    assert "var act=(!_admin||retired)?'':" in row.group(1), (
        "the action cell no longer suppresses itself on a retired row")


def test_retired_is_not_offered_as_something_to_declare():
    """`POST /v1/systems` takes DeclarableLifecycle ('draft' | 'active'). A
    born-retired row could never be un-retired and no DELETE exists to remove
    it, so offering the option here would be offering a 422."""
    select = re.search(r'<select class="cin" id="sysLifecycle">(.*?)</select>',
                       page(), re.S)
    assert select, "the lifecycle select is gone"
    values = re.findall(r'value="(\w+)"', select.group(1))
    assert values == ["active", "draft"], values
    assert "retired" not in select.group(1)


# ══ nothing here promises evidence this page cannot show ════════════════════
def test_the_page_promises_no_per_system_evidence():
    """`/v1/logs` has no `system_id` filter and there is no aggregation
    endpoint, so a count or a link would be a number this page cannot obtain."""
    assert "/v1/logs" not in module(), \
        "the module reached for the ledger, which cannot be filtered by system"
    assert not re.search(r"go\(\s*'ledger'", page() + module()), \
        "a link into the ledger implies a per-system filter that does not exist"
    # The row renders declared fields only. Nothing derived, nothing counted —
    # every value in a cell comes off the system object the API returned.
    row = re.search(r"function rowHtml\(s\)\{(.*?)\n  \}", module(), re.S).group(1)
    fields = set(re.findall(r"\bs\.(\w+)", row))
    allowed = {"retired", "provider", "model_name", "id", "name", "purpose",
               "owner_email", "environment", "data_classification", "risk_tier",
               "lifecycle_status"}
    assert fields <= allowed, (
        f"the row renders {sorted(fields - allowed)}, which /v1/systems does not "
        f"return — a count or a link would have to be invented here")
    for counted in ("length", "count", "Count", "events"):
        assert counted not in row, (
            f"the row mentions {counted!r}: this page cannot obtain a per-system "
            f"event count, so it must not display one")


def test_the_page_says_attribution_starts_at_sdk_1_14_0():
    """A customer on an older SDK sees systems with nothing attached. Saying so
    is the difference between a scope boundary and a broken feature."""
    claim = re.search(r'<div class="sysclaim">(.*?)</div>', page(), re.S)
    assert claim, "the standing note is gone"
    text = re.sub(r"<[^>]+>", " ", claim.group(1))
    assert "1.14.0" in text, "the SDK version the attribution needs is not stated"
    assert "does not backfill" in text, (
        "without this a reader assumes declaring a system labels the events "
        "already in their ledger")
    assert "no per-system event counts" in text, (
        "the page has to say why it shows no counts, or the absence reads as a "
        "feature that is broken")
    assert "does not infer this list" in text


# ══ the mechanics this SPA breaks if you forget them ════════════════════════
def test_every_mutation_goes_through_fetch():
    """window.fetch is patched TWICE here — the CSRF header, and the global
    step-up retry on a 403 — so a `<form action=>` post bypasses both."""
    assert "<form" not in page(), (
        "a <form> appeared on this page: a form post skips the CSRF patch and "
        "the step-up interceptor, both of which are installed on fetch")
    for method in ("'POST'", "'PUT'"):
        for hit in re.finditer(re.escape("method:" + method), module()):
            window = module()[max(0, hit.start() - 260):hit.start()]
            assert "api(" in window, f"a {method} that does not go through api()"
    assert "var api=function(p,o){return fetch(p," in module(), \
        "api() stopped calling the patched fetch"


def test_fields_are_assigned_through_setfieldvalue():
    """The house rule, and it has landed three times: `el.value = x` fires no
    change event, so everything watching the field stays stale."""
    assert "window.setFieldValue(FIELDS[k], v)" in module()
    assert not re.search(r"\$\('sys\w+'\)\.value\s*=", module()), \
        "a Systems field is assigned directly"


def test_an_edit_sends_only_what_changed():
    """`system.update`'s audit entry lists the field names it was sent. Posting
    all nine every time would record nine governance changes for a corrected
    typo and make the trail useless — which is the one thing this table is for."""
    save = re.search(r"save:async function\(\)\{(.*?)\n    \},", module(), re.S)
    assert save, "save() is gone"
    body = save.group(1)
    assert "if(v[k]===was)return;" in body, \
        "the diff against the loaded row is gone; every field would be sent"
    assert "if(!Object.keys(payload).length)" in body, (
        "an unchanged save would POST an empty body, which the API answers 422")


def test_the_form_opens_on_the_api_s_own_defaults():
    """An untouched <select> must not record a provider nobody chose. The
    defaults mirror AiSystemCreate, so the first option being OpenAI cannot turn
    into a declaration that the system runs on OpenAI."""
    defaults = re.search(r"var DEFAULTS=\{(.*?)\};", module(), re.S)
    assert defaults, "DEFAULTS is gone"
    body = defaults.group(1)
    for field, value in (("provider", "other"), ("environment", "production"),
                         ("data_classification", "internal"),
                         ("risk_tier", "medium"), ("lifecycle_status", "active")):
        assert f"{field}:'{value}'" in body, (
            f"{field} no longer opens on the API's default {value!r} — an "
            f"untouched select would declare something the customer did not say")


def test_writes_are_offered_only_to_an_admin_and_asked_of_the_server():
    """POST/PUT/retire are require_role('admin') server-side. The controls are
    REMOVED for a member rather than disabled — a disabled control still says
    there is something here for you — and the role comes from the server, not
    from a second local copy of the rule."""
    assert "_admin=!!(who&&who.role==='admin');" in module()
    assert "api('/v1/auth/me')" in module()
    assert "_me=api" in module(), "the role is re-asked per press instead of once"
    assert "d.style.display=_admin?'':'none'" in module(), \
        "the declare control is no longer hidden from a member"
    assert "disabled=_admin" not in module() and "disabled=!_admin" not in module(), \
        "a control was disabled rather than removed"


def test_a_failed_load_is_not_reported_as_an_empty_register():
    """"We could not ask" and "you have none" are different facts, and rendering
    the first as the second is how a register starts lying."""
    problem = re.search(r"function problem\(text\)\{(.*?)\n  \}", module(), re.S)
    assert problem, "the failure branch is gone"
    assert "Could not load the register" in problem.group(1)
    assert "empty.style.display='none'" in problem.group(1), (
        "a failed load falls through to the empty state, which tells the "
        "customer they have declared nothing")


# ══════════════════ RENDERED — the guards that EXECUTE ══════════════════════
#
# A static guard checks a token; it does not check behaviour. Mutation proved
# the difference here: a mutant that left `DEFAULTS` intact and reassigned
# `DEFAULTS.provider='openai'` one line later SURVIVED every text check above
# while changing what the form actually opens on. The three guards below drive
# the shipped file in headless Chrome and read what it emits.
#
# `window.fetch` is stubbed AFTER the page's own scripts, which is where the
# network is: every call site resolves `fetch` as a global at call time, so the
# stub sits underneath the CSRF patch and the step-up patch exactly as the wire
# does. Skipped where Chrome is absent; CI runs `ubuntu-latest`, which ships
# google-chrome-stable, so these execute on every push — the same arrangement
# `test_g9_forced_colors.py` documents.

_CHROME = (os.environ.get("CHROME_BIN")
           or shutil.which("chrome") or shutil.which("google-chrome")
           or next((p for p in (
               r"C:\Program Files\Google\Chrome\Application\chrome.exe",
               r"C:\Program Files (x86)\Google\Chrome\Application\chrome.exe",
           ) if pathlib.Path(p).exists()), None))

needs_chrome = pytest.mark.skipif(_CHROME is None, reason="Chrome not available")

#: One live system, so a retire dialog has something to open on. Test-only
#: fixture data served by the STUB — it never appears in the shipped file, which
#: `test_the_empty_state_invents_no_row` is what actually guards.
_STUB_ROW = {
    "id": "11111111-1111-4111-8111-111111111111", "name": "probe-system",
    "owner_email": "owner@example.test", "purpose": "A system under test.",
    "provider": "self_hosted", "model_name": None, "environment": "staging",
    "data_classification": "internal", "risk_tier": "low",
    "lifecycle_status": "active", "retired": False,
}

_PROBE = r"""
<script>
(function(){
  var ROWS=__ROWS__;
  window.fetch=function(url){
    url=String(url); var body={};
    if(url.indexOf('/v1/auth/me')===0) body={email:'a@example.test',role:'admin'};
    else if(/\/v1\/systems$/.test(url)) body=ROWS;
    return Promise.resolve({ok:true,status:200,
      json:function(){return Promise.resolve(body);},clone:function(){return this;}});
  };
  window.addEventListener('load',function(){ setTimeout(async function(){
    var out={};
    try{
      go('systems',document.querySelector('.dock-item[data-page="systems"]'));
      await window.loadSystems();
      await new Promise(function(r){setTimeout(r,120);});
      out.title=document.getElementById('topbarTitle').textContent;
      out.rows=document.querySelectorAll('#sysBody tr.sysrow').length;
      out.tableShown=getComputedStyle(document.getElementById('sysTableWrap')).display!=='none';
      out.emptyShown=getComputedStyle(document.getElementById('sysEmpty')).display!=='none';
      out.tbody=document.getElementById('sysBody').textContent.trim();
      foxSystems.declare();
      await new Promise(function(r){setTimeout(r,60);});
      out.fields={};
      ['sysName','sysOwner','sysPurpose','sysProvider','sysModel','sysEnvironment',
       'sysClassification','sysRisk','sysLifecycle'].forEach(function(id){
        out.fields[id]=document.getElementById(id).value; });
      out.lifecycleOptions=Array.prototype.map.call(
        document.getElementById('sysLifecycle').options,function(o){return o.value;});
      foxSystems.cancel();
      if(ROWS.length){
        foxSystems.retire(ROWS[0].id);
        await new Promise(function(r){setTimeout(r,120);});
        out.dialog={title:document.getElementById('foxDlgT').textContent,
                    body:document.getElementById('foxDlgB').textContent,
                    confirm:document.getElementById('foxDlgYes').textContent,
                    field:(document.querySelector('#foxDlgFields .flabel')||{}).textContent};
        document.getElementById('foxDlgNo').click();
      }
    }catch(e){ out.error=String(e); }
    document.documentElement.innerHTML='<pre id="r4">'+
      JSON.stringify(out).replace(/</g,'\u003c')+'</pre>';
  },500); });
})();
</script>
"""


def _render(rows) -> dict:
    probe = _PROBE.replace("__ROWS__", json.dumps(rows))
    with tempfile.TemporaryDirectory() as tmp:
        page_file = pathlib.Path(tmp) / "probe.html"
        page_file.write_text(source() + probe, encoding="utf-8")
        args = [_CHROME, "--headless=new", "--disable-gpu", "--no-sandbox",
                "--hide-scrollbars", "--force-prefers-reduced-motion",
                "--virtual-time-budget=9000", "--window-size=1440,900",
                f"--user-data-dir={tmp}/prof", "--dump-dom", page_file.as_uri()]
        proc = subprocess.run(args, capture_output=True, text=True,
                              encoding="utf-8", errors="replace", timeout=180)
    hit = re.search(r'<pre id="r4">(.*?)</pre>', proc.stdout, re.S)
    assert hit, "the probe never ran; chrome said: %s" % proc.stderr[-500:]
    data = json.loads(hit.group(1))
    assert not data.get("error"), data["error"]
    return data


@pytest.fixture(scope="module")
def rendered_with_a_system() -> dict:
    return _render([_STUB_ROW])


@pytest.fixture(scope="module")
def rendered_empty() -> dict:
    return _render([])


@needs_chrome
def test_rendered_the_page_loads_and_is_named(rendered_with_a_system):
    """The control. If navigation or the load failed, everything below would be
    measuring a page that never rendered."""
    assert rendered_with_a_system["title"] == "Declared AI systems"
    assert rendered_with_a_system["rows"] == 1
    assert rendered_with_a_system["tableShown"] is True
    assert rendered_with_a_system["emptyShown"] is False


@needs_chrome
def test_rendered_an_empty_register_draws_no_row(rendered_empty):
    """Driven, not read: the API answers `[]` and the DOM is asked what
    happened. The table is hidden and the tbody holds no row — not a stand-in,
    not a sample, not a dash."""
    assert rendered_empty["rows"] == 0, "a row appeared for an empty register"
    assert rendered_empty["tableShown"] is False
    assert rendered_empty["emptyShown"] is True
    assert rendered_empty["tbody"] == "", (
        f"the table body rendered {rendered_empty['tbody']!r} for a workspace "
        f"that has declared nothing")


@needs_chrome
def test_rendered_the_form_opens_on_the_api_defaults(rendered_with_a_system):
    """What the form ACTUALLY opens on, not what a literal says it opens on.
    A mutant that left DEFAULTS intact and reassigned DEFAULTS.provider one line
    later survived the static check and is killed here."""
    fields = rendered_with_a_system["fields"]
    assert fields["sysProvider"] == "other", (
        f"the provider select opens on {fields['sysProvider']!r}. An untouched "
        f"select must not declare a provider the customer never chose — the "
        f"API's own default is 'other'.")
    assert fields["sysEnvironment"] == "production"
    assert fields["sysClassification"] == "internal"
    assert fields["sysRisk"] == "medium"
    assert fields["sysLifecycle"] == "active"
    for blank in ("sysName", "sysOwner", "sysPurpose", "sysModel"):
        assert fields[blank] == "", f"{blank} opens pre-filled with {fields[blank]!r}"
    assert rendered_with_a_system["lifecycleOptions"] == ["active", "draft"], (
        "'retired' is reachable from the declare form; the API refuses it")


@needs_chrome
def test_rendered_the_retire_dialog_says_permanent(rendered_with_a_system):
    """The words a customer actually sees, read back out of the dialog."""
    dialog = rendered_with_a_system["dialog"]
    assert dialog["title"] == "Retire probe-system?"
    assert dialog["confirm"] == "Retire permanently"
    assert dialog["field"] == 'Type "probe-system" to confirm'
    body = dialog["body"]
    assert body.startswith("Retiring is permanent."), body[:80]
    assert "Nothing brings this system back" in body
    assert "Retiring is not deleting" in body
    assert "becomes free again" in body
    for archival in ("archive", "restore", "reactivate", "can be undone"):
        assert archival not in body, (
            f"the rendered dialog says {archival!r}; there is no un-retire "
            f"endpoint and the copy may not imply one")
