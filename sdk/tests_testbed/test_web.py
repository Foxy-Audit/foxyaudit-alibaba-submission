"""Guards for T2: the local page, and the two engine fixes it carried.

Everything here runs OFFLINE AND KEYLESS. The server is built on port 0, so
nothing probes for a free port first -- a probe sets SO_REUSEADDR exactly as a
listener does and therefore reports every port free, which is a trap this repo
has already been caught by.

THE THREE THINGS MOST WORTH BREAKING, in the order they would hurt:

1. The bind address. A page that renders a prospect's own prompts, served on
   0.0.0.0, is the product's central claim inverted. It is asserted from the
   source rather than only from a running socket, because a socket test passes
   on a machine with one interface.
2. The vocabulary. The page must not hold its own words for a verdict. Three
   front-ends each deciding what "blocked" means is how the
   prevention-vs-evidence conflation got rebuilt once already.
3. The measurement. `provider_is_live` must ride on the record and must not be
   re-derivable from the provider's NAME.
"""

from __future__ import annotations

import ast
import json
import pathlib
import re
import threading
import urllib.error
import urllib.request

import pytest

from foxy_testbed import cli, core, scoreboard, web
from foxy_testbed.core import Turn
from foxy_testbed.sectors import SECTOR_NAMES

WEB_SOURCE = pathlib.Path(web.__file__).read_text(encoding="utf-8")
PAGE_SOURCE = (pathlib.Path(web.__file__).parent / web.PAGE_FILENAME).read_text(
    encoding="utf-8")


# ── reading the code, and not the prose about it ──────────────────────────────
# ⚠ A COMMENT SHADOWS A GREP, AND EVERY BAN BELOW WAS CAUGHT BY ITS OWN
# DOCUMENTATION FIRST. This module's four source-level guards all went red on
# the sentences explaining why the thing they ban is banned: web.py's docstring
# names 0.0.0.0 and ThreadingHTTPServer to say it uses neither, a CSS comment
# recording a measured ratio contains the words "nothing fired", and a JS comment
# says nothing is assigned through innerHTML. A guard that cannot tell an
# instruction from a description is not measuring the file.
def _python_code(source: str) -> str:
    """``source`` with its docstrings and ``#`` comments removed."""
    tree = ast.parse(source)
    docstrings = set()
    for node in ast.walk(tree):
        if isinstance(node, (ast.Module, ast.ClassDef, ast.FunctionDef,
                             ast.AsyncFunctionDef)):
            body = getattr(node, "body", None)
            if body and isinstance(body[0], ast.Expr) and isinstance(
                    body[0].value, ast.Constant) and isinstance(
                    body[0].value.value, str):
                docstrings.add(id(body[0]))
    kept = []
    for line in source.splitlines():
        stripped = line.strip()
        if stripped.startswith("#"):
            continue
        kept.append(line.split("  #")[0])
    text = "\n".join(kept)
    # Docstrings survive the line filter, so they come out by value.
    for node in ast.walk(tree):
        if isinstance(node, ast.Expr) and id(node) in docstrings:
            text = text.replace(node.value.value, "")
    return text


def _page_code(source: str) -> str:
    """``source`` with its HTML, CSS and JavaScript comments removed."""
    text = re.sub(r"<!--.*?-->", "", source, flags=re.S)
    text = re.sub(r"/\*.*?\*/", "", text, flags=re.S)
    # Only whole-line `//` comments, so a `://` inside a value is never mangled.
    return "\n".join(line for line in text.splitlines()
                     if not line.strip().startswith("//"))


WEB_CODE = _python_code(WEB_SOURCE)
PAGE_CODE = _page_code(PAGE_SOURCE)


# ── a running server, offline and keyless ─────────────────────────────────────
@pytest.fixture(scope="module")
def server():
    """One serial server on an OS-assigned port, for the whole module."""
    built = web.build_server(web.Testbed(), port=0)
    thread = threading.Thread(target=built.serve_forever, daemon=True)
    thread.start()
    try:
        yield built
    finally:
        built.shutdown()
        built.server_close()
        thread.join(timeout=5)


def call(server, path, body=None, headers=None):
    """One request, returning ``(status, parsed-or-bytes)``.

    The ``Host`` header is set explicitly on every call because that is what the
    server checks, and urllib's default is already correct -- setting it here
    keeps the tests that deliberately send a WRONG one honest about what they
    changed.
    """
    port = server.server_address[1]
    url = "http://127.0.0.1:{0}{1}".format(port, path)
    data = json.dumps(body).encode("utf-8") if body is not None else None
    request = urllib.request.Request(url, data=data,
                                     method="POST" if data is not None else "GET")
    request.add_header("Host", "127.0.0.1:{0}".format(port))
    if data is not None:
        request.add_header("Content-Type", "application/json")
    for name, value in (headers or {}).items():
        request.add_header(name, value)
    try:
        response = urllib.request.urlopen(request, timeout=20)
        status, raw, head = response.status, response.read(), response.headers
    except urllib.error.HTTPError as exc:
        status, raw, head = exc.code, exc.read(), exc.headers
    if (head.get("Content-Type") or "").startswith("application/json"):
        return status, json.loads(raw)
    return status, raw


def ask(server, sector="healthcare", mode="block", prompt="hello", **kwargs):
    return call(server, "/turn", {"sector": sector, "mode": mode, "prompt": prompt},
                **kwargs)


# ── 1 · the bind address ──────────────────────────────────────────────────────
def test_the_bind_host_is_loopback_and_nothing_else():
    assert web.BIND_HOST == "127.0.0.1"


def test_the_source_contains_no_wildcard_bind():
    """⚠ ASSERTED FROM THE SOURCE, and that is not belt-and-braces.

    A socket test can only observe the interface it connected on, so on a
    machine with one interface a server bound to 0.0.0.0 answers on 127.0.0.1
    and every end-to-end test below still passes. The string is what would
    change, so the string is what is checked.
    """
    assert "0.0.0.0" not in WEB_CODE
    assert "0.0.0.0" not in PAGE_CODE


def test_there_is_no_flag_that_moves_the_server_off_the_loopback():
    """A flag would turn a structural property into a configurable one.

    The page says "nothing you type leaves this machine". That sentence is true
    because of where the socket is; with a ``--host`` it would instead be a claim
    about that flag's current value, and the page has no way to know it.
    """
    options = set()
    for action in web.build_parser()._actions:
        options.update(action.option_strings)
    assert "--host" not in options
    assert "--bind" not in options
    assert "--interface" not in options


def test_the_server_actually_binds_the_loopback(server):
    assert server.server_address[0] == "127.0.0.1"


def test_the_server_is_serial_rather_than_threading(server):
    """⚠ A CORRECTNESS REQUIREMENT, NOT A DEFAULT.

    ``Assistant`` records what the guard did on per-INSTANCE state --
    ``_reached`` and ``_delivered``, set by the wrapped call and read after it
    returns -- and this server holds one assistant per (sector, mode). Two turns
    in flight through one of them would read each other's observations, and those
    observations are what ``prevented``, ``prompt_enforced`` and every other
    claim the page renders are MEASURED from. Swapping in ``ThreadingHTTPServer``
    would not fail visibly; it would make the page occasionally lie.
    """
    from http.server import HTTPServer, ThreadingHTTPServer
    assert isinstance(server, HTTPServer)
    assert not isinstance(server, ThreadingHTTPServer)
    assert "ThreadingHTTPServer" not in WEB_CODE


# ── 2 · the page holds no policy logic and no vocabulary ──────────────────────
def test_the_web_module_never_imports_foxy_audit():
    """The same guard ``test_cli.py`` puts on the REPL, for the same reason.

    Not "does not use" -- cannot: there is no name from that package anywhere in
    the file, so the module could not run a policy check even by accident.
    """
    tree = ast.parse(WEB_SOURCE)
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                assert not alias.name.startswith("foxy_audit"), alias.name
        elif isinstance(node, ast.ImportFrom):
            assert not (node.module or "").startswith("foxy_audit"), node.module
    assert "foxy_audit" not in WEB_SOURCE.replace("``foxy_audit``", "").replace(
        "`foxy_audit`", "").replace("foxy_audit's", "").replace(
        "foxy_audit guard", "")


@pytest.mark.parametrize("turn_kwargs", [
    {"decision": "blocked", "reached_provider": False},
    {"decision": "blocked", "reached_provider": True},
    {"decision": "blocked_response", "reached_provider": True},
    {"decision": "blocked_response", "reached_provider": False},
    {"decision": "redacted", "reached_provider": True, "rules": ("phi.ssn",)},
    {"decision": "flagged", "reached_provider": True},
    {"decision": "allowed", "reached_provider": True},
    {"decision": "error", "reached_provider": False, "error": "X: y"},
])
def test_the_page_does_not_carry_a_second_copy_of_the_verdict_wording(turn_kwargs):
    """⚠ THE HEADLINE IS COMPUTED IN PYTHON AND SHIPPED, NEVER REIMPLEMENTED.

    A JavaScript copy of ``cli._headline`` would be the worst placed of the
    copies, because it is the one no test runs. So the assertion is that the
    words are NOT in the page: every verdict word and every sentence under it
    reaches the browser on the payload.
    """
    base = dict(sector="s", policy_tag="t", mode="block", provider="p", model="m",
                answered=False)
    base.update(turn_kwargs)
    label, sentence = cli._headline(Turn(**base))
    assert label not in PAGE_CODE
    # The sentences are long; the first clause is enough to prove a copy.
    assert sentence.split(".")[0] not in PAGE_CODE


def test_the_page_renders_the_headline_the_repl_would_have_printed(server):
    status, turn = ask(server, prompt="Confirm coverage for member SSN 900-12-3456.")
    assert status == 200
    rendered = "\n".join(cli.turn_lines(core.Turn(
        sector=turn["sector"], policy_tag=turn["policy_tag"], mode=turn["mode"],
        provider=turn["provider"], model=turn["model"], decision=turn["decision"],
        answered=turn["answered"], reached_provider=turn["reached_provider"])))
    assert "[{0}]".format(turn["headline"]) in rendered


# ── 3 · the four "no reply" sentences, against the REPL's own output ──────────
def _turn(**kwargs):
    base = dict(sector="s", policy_tag="t", mode="block", provider="p", model="m",
                decision="allowed", answered=False, reached_provider=False)
    base.update(kwargs)
    return Turn(**base)


@pytest.mark.parametrize("turn", [
    _turn(decision="blocked"),
    _turn(decision="blocked_response", reached_provider=True),
    _turn(decision="error", reached_provider=False, error="ProviderError: HTTP 500"),
    _turn(decision="allowed", reached_provider=True, empty_reply=True),
])
def test_every_no_reply_sentence_is_one_the_repl_also_prints(turn):
    """⚠ THE ANTI-DRIFT GUARD, and the only honest one available.

    These four sentences are duplicated from inside ``cli.turn_lines``'s body,
    where they are interleaved with line wrapping this surface does not do, so
    they cannot simply be imported. What CAN be checked is that the two surfaces
    still say the same thing: the sentence this module hands the page must appear
    verbatim in the REPL's rendering of the SAME turn. Reword either side and
    this goes red, instead of the two surfaces quietly disagreeing about what
    happened to somebody's prompt.
    """
    sentence = web._reply_status(turn)
    assert sentence
    rendered = " ".join(" ".join(cli.turn_lines(turn, provider_is_live=False)).split())
    assert " ".join(sentence.split()) in rendered


def test_an_answered_turn_carries_no_reply_status_at_all():
    """Every one of those four sentences is FALSE on a turn that has a reply.

    The fall-through said "the prompt reached the provider, and nothing came back
    to you" for an answered turn -- a sentence that would sit directly beside the
    reply that came back. The page never renders it in that state, but a payload
    that only reads correctly if its consumer checks another field first is a
    fabricated verdict waiting for the second consumer.
    """
    answered = _turn(reached_provider=True, answered=True, reply="hello")
    assert web._reply_status(answered) == ""
    assert web.turn_payload(answered)["reply_status"] == ""


# ── 4 · provider_is_live rides on the record ──────────────────────────────────
def test_provider_is_live_defaults_to_the_understating_direction():
    """Of the two ways to be wrong, only one is survivable.

    "mock fixture" over a real answer loses a provenance claim. "live model
    output" over a written fixture puts words in a model's mouth, in the demo of
    a product whose entire pitch is that its evidence is honest.
    """
    assert Turn.__dataclass_fields__["provider_is_live"].default is False
    assert _turn().provider_is_live is False


def test_as_dict_carries_provider_is_live():
    assert web.turn_payload(_turn(provider_is_live=True))["provider_is_live"] is True
    assert _turn(provider_is_live=True).as_dict()["provider_is_live"] is True


def test_the_engine_sets_it_from_the_provider_it_actually_called():
    live = core.Assistant("legal", provider=_AlwaysLive())
    assert live.ask("What is work product?").provider_is_live is True
    assert core.Assistant("legal").ask("What is work product?").provider_is_live is False


class _AlwaysLive(core.__dict__["_providers"].Provider):
    """A provider that is live and is called neither "mock" nor anything else.

    ⚠ THE CASE THAT MAKES NAME-MATCHING UNWORKABLE, not merely inelegant. The
    engine accepts any ``Provider`` subclass, so a surface deciding live-ness by
    testing ``turn.provider == "mock"`` would call this one a fixture -- and it
    makes no network call here only because a test must not.
    """

    name = "house-model"

    def __init__(self):
        super().__init__("house-1")

    def complete(self, system, prompt):
        return "an answer"


def test_the_page_never_matches_the_provider_name_to_decide_live_ness():
    assert '"mock"' not in PAGE_CODE
    assert "'mock'" not in PAGE_CODE
    assert "provider_is_live" in PAGE_CODE


def test_turn_lines_falls_back_to_the_record_when_it_is_not_told():
    live = _turn(reached_provider=True, answered=True, reply="hi", provider_is_live=True)
    assert "live model output" in "\n".join(cli.turn_lines(live))
    # And an explicit argument still wins, which is what every shipped call does.
    assert "mock fixture" in "\n".join(cli.turn_lines(live, provider_is_live=False))


# ── 5 · the carried-forward _field collision ──────────────────────────────────
def test_a_long_label_no_longer_welds_itself_to_its_value():
    """``_field("reached model", "yes")`` rendered ``reached modelyes``.

    ``ljust`` pads only while the label is shorter than the field, and at
    ``len(first) >= indent`` it is a no-op. ``_field`` prepends two spaces to a
    fourteen-column field, so TWELVE characters is the boundary -- see
    :func:`test_the_boundary_is_where_the_module_says_it_is`, which computes it
    rather than trusting this sentence.
    """
    lines = scoreboard._field("reached model", "yes")
    assert "reached modelyes" not in lines[0]
    assert lines[0] == "  reached model yes"


def test_the_boundary_is_where_the_module_says_it_is():
    """⚠ THE NUMBER ITSELF, MEASURED -- because it was stated wrong.

    Three places said "eleven characters", including this file, and the
    arithmetic is ``2 + len(label) >= FIELD_INDENT``, which makes it twelve: an
    eleven-character label still lands its value in column fourteen exactly.
    Nothing was broken by the wrong sentence, and that is precisely why it
    survived review twice -- a comment cannot be wrong in a way a test notices
    unless a test reads it.

    So the boundary is derived here and the prose points at this function. The
    longest label shipping today is checked too: the day one grows past the
    boundary, this is what says so.
    """
    first_colliding = next(
        n for n in range(1, 40)
        if len("  " + "x" * n) >= scoreboard.FIELD_INDENT)
    assert first_colliding == 12
    # One below the boundary still aligns exactly; the boundary itself does not.
    assert scoreboard._field("x" * 11, "V")[0].index("V") == scoreboard.FIELD_INDENT
    assert scoreboard._field("x" * 12, "V")[0].index("V") == scoreboard.FIELD_INDENT + 1

    shipping = set()
    for module in (cli, scoreboard):
        source = pathlib.Path(module.__file__).read_text(encoding="utf-8")
        body = _python_code(source)          # docstring examples are not calls
        shipping |= set(re.findall(r'_field\(\s*"([^"]+)"', body))
    assert shipping, "no _field call sites found -- has the renderer moved?"
    longest = max(shipping, key=len)
    assert len(longest) < first_colliding, (longest, len(longest))


@pytest.mark.parametrize("length", range(1, 26))
def test_there_is_always_a_separator_whatever_the_label_length(length):
    """⚠ THE PROPERTY, DERIVED FROM THE MODULE, not the one reported case.

    The bug was reported as "reached model"; testing that one string would leave
    every other over-long label unguarded. The range deliberately spans both
    sides of the boundary and the boundary is computed from ``FIELD_INDENT``
    rather than written in -- a guard that restates the implementation's own
    constant is green by construction, and a guard that restates a number a
    human worked out is green until the human was wrong.
    """
    label = "x" * length
    head = scoreboard._field(label, "VALUE")[0]
    assert head.startswith("  " + label)
    assert head[len("  " + label)] == " "
    assert "VALUE" in head
    if len("  " + label) < scoreboard.FIELD_INDENT:
        # Short labels keep the exact column: this fix must be invisible to them.
        assert head.index("VALUE") == scoreboard.FIELD_INDENT


def test_no_field_line_runs_past_the_report_width():
    """The overflow half of the same fix.

    Appending a space alone would have pushed the first line two columns past
    :data:`~foxy_testbed.scoreboard.WIDTH`, which is the rule every other line in
    a scoreboard is aligned to. ``textwrap``'s ``initial_indent`` counts inside
    the wrap width, so a long label eats into its own first line instead.
    """
    long_value = ("a survivor rule name and a long explanatory clause after it "
                  "that certainly has to wrap more than once in this column")
    for label in ("short", "reached model", "an extremely long field label"):
        for line in scoreboard._field(label, long_value):
            assert len(line) <= scoreboard.WIDTH, (label, line)


def test_the_six_scoreboards_are_byte_identical_to_the_unfixed_renderer():
    """⚠ THE INVARIANCE CLAIM, MEASURED RATHER THAN ASSERTED.

    The whole defence of this fix is that no label shipping today reaches the
    boundary, so no existing output moves. That is checked by re-rendering every
    scoreboard through the OLD head construction and requiring the two to match
    exactly -- a claim that "nothing changed" is worth nothing unless something
    recomputes the old thing.
    """
    import textwrap

    def old_wrap(text, indent, first=""):
        pad = " " * indent
        body = textwrap.wrap(" ".join(str(text).split()),
                             width=scoreboard.WIDTH - indent) or [""]
        if first:
            return ["{0}{1}".format(first.ljust(indent), body[0])] + [
                pad + line for line in body[1:]]
        return [pad + line for line in body]

    for sector in SECTOR_NAMES:
        for mode in ("block", "redact"):
            board = scoreboard.run_probes(sector, mode=mode)
            new = board.render()
            monkey = scoreboard._wrap
            scoreboard._wrap = old_wrap
            try:
                old = scoreboard.render(board)
            finally:
                scoreboard._wrap = monkey
            assert new == old, (sector, mode)


# ── 6 · the page as an artifact ───────────────────────────────────────────────
def test_the_page_ships_inside_the_package():
    """Read the way the server reads it, so a packaging change fails here.

    ``importlib.resources`` rather than ``__file__`` arithmetic: that is what
    keeps working wherever the package is imported from, and it is the call the
    server actually makes.
    """
    from importlib import resources
    text = resources.files("foxy_testbed").joinpath(web.PAGE_FILENAME).read_text(
        encoding="utf-8")
    assert text.lstrip().startswith("<!doctype html>")


def test_the_page_reaches_for_nothing_outside_this_machine():
    """No CDN, no font host, no analytics -- the rule every surface here follows.

    A page that fetched a stylesheet would announce, to whoever hosts it, that
    somebody is running a compliance testbed. On the demo of a content-blind
    product that is the wrong kind of irony.
    """
    for marker in ("http://", "https://", "//fonts.", "cdn.", "@import"):
        assert marker not in PAGE_CODE, marker


def test_the_page_has_one_style_and_one_script_and_both_balance():
    assert PAGE_SOURCE.count("<style") == PAGE_SOURCE.count("</style>") == 1
    assert PAGE_SOURCE.count("<script") == PAGE_SOURCE.count("</script>") == 1
    style = PAGE_SOURCE.split("<style", 1)[1].split("</style>", 1)[0]
    assert style.count("{") == style.count("}")


def test_nothing_on_the_page_is_assigned_through_innerhtml():
    """Two independent defences against the same mistake, and this is one.

    A reply from a live provider is arbitrary remote text and the prompt is the
    user's own; both reach the DOM through ``textContent`` only. The response's
    nonce CSP is the other defence, and neither is asked to be sufficient alone.
    """
    for banned in ("innerHTML", "outerHTML", "insertAdjacentHTML", "document.write",
                   "eval("):
        assert banned not in PAGE_CODE, banned


# ── 6b · what survives High Contrast ──────────────────────────────────────────
def _style() -> str:
    return PAGE_SOURCE.split("<style", 1)[1].split("</style>", 1)[0]


def _forced_colors_block() -> str:
    style = _style()
    start = style.index("@media (forced-colors:active)")
    depth, i = 0, style.index("{", start)
    for end in range(i, len(style)):
        if style[end] == "{":
            depth += 1
        elif style[end] == "}":
            depth -= 1
            if depth == 0:
                return style[i:end]
    raise AssertionError("the forced-colors block does not close")


def test_the_descendant_form_of_the_sector_rule_appears_nowhere():
    """⚠ THE SAME NESTED-CARD DEFECT, IN THE MODE NOBODY LOOKS AT.

    ``.sector span`` matches ``.nm`` and ``.ti`` as well as the card, so every
    sector renders as a bordered box inside a bordered box. It was fixed in the
    main stylesheet, explained in a comment there, and then written again in the
    forced-colors block -- where it shipped, because the only way to see it is to
    render High Contrast on purpose. A fix described in one comment is not a fix
    applied everywhere, so this bans the pattern rather than trusting the prose.
    """
    style = re.sub(r"/\*.*?\*/", "", _style(), flags=re.S)
    assert re.search(r"\.sector\s+span", style) is None, (
        "use `.sector > span`: the descendant form also matches .nm and .ti")


def test_every_selection_state_is_re_established_for_forced_colors():
    """⚠ HIGH CONTRAST OVERRIDES EVERY PROPERTY THE SELECTED SECTOR USED.

    Selection was carried by ``border-color`` plus ``background``, both of which
    forced-colors replaces with system colours, and the radio that would have
    said which sector is chosen is ``opacity:0``. All three rendered identically.
    Screenshot-confirmed under ``--force-high-contrast``, before and after.

    So every ``:checked`` rule must have a counterpart inside the forced-colors
    block. It is scoped to ``:checked`` deliberately: a SELECTION has no other
    carrier, whereas the verdict marks -- which also distinguish themselves by
    fill -- carry the word BLOCKED or ALLOWED inside them and lose nothing when
    the fill goes. Colour is never the only carrier on this page; this is the one
    state where it nearly was.
    """
    style = re.sub(r"/\*.*?\*/", "", _style(), flags=re.S)
    forced = _forced_colors_block()
    outside = style.replace(forced, "")
    checked = {sel.strip() for sel in re.findall(r"([^{}]*:checked[^{}]*)\{", outside)}
    assert checked, "no :checked rules found -- has the sector switch changed?"
    for selector in checked:
        assert selector in forced, (
            "{0!r} carries a selection state that High Contrast erases, and the "
            "forced-colors block does not re-establish it".format(selector))


def test_the_real_radio_is_what_carries_selection_in_forced_colors():
    """The platform draws a native radio's checked state whatever the palette.

    Dressing the state up in system colours would work too, and would keep the
    page one repaint away from the same failure. Bringing the control back is
    the repair that does not depend on this stylesheet being right.
    """
    forced = _forced_colors_block()
    assert "opacity:1" in forced.replace(" ", "")
    assert "position:static" in forced.replace(" ", "")


def test_every_response_replaces_the_nonce_placeholder(server):
    status, body = call(server, "/")
    assert status == 200
    assert web.NONCE_PLACEHOLDER.encode() not in body
    # And the placeholder really was there to replace -- on both tags.
    assert PAGE_SOURCE.count(web.NONCE_PLACEHOLDER) == 2


def test_two_page_loads_do_not_share_a_nonce(server):
    first = call(server, "/")[1]
    second = call(server, "/")[1]
    assert first != second


def test_the_csp_admits_nothing_by_default(server):
    port = server.server_address[1]
    response = urllib.request.urlopen(
        "http://127.0.0.1:{0}/".format(port), timeout=10)
    policy = response.headers["Content-Security-Policy"]
    assert policy.startswith("default-src 'none'")
    assert "'unsafe-inline'" not in policy
    assert "frame-ancestors 'none'" in policy
    assert response.headers["Cache-Control"] == "no-store"


# ── 7 · driven end to end, offline, with no key ───────────────────────────────
def test_the_session_route_describes_what_is_actually_running(server):
    status, config = call(server, "/session")
    assert status == 200
    assert config["bind"] == "127.0.0.1:{0}".format(server.server_address[1])
    assert config["provider"]["name"] == "mock"
    assert config["provider"]["is_live"] is False
    assert config["provider"]["note"]
    assert [s["name"] for s in config["sectors"]] == list(SECTOR_NAMES)
    for sector in config["sectors"]:
        assert sector["policy_note"]
        assert sector["probes"], sector["name"]


def test_a_blocked_prompt_never_reaches_the_provider(server):
    status, turn = ask(server, prompt=(
        "Confirm coverage for member SSN 900-12-3456 before the procedure "
        "is scheduled."))
    assert status == 200
    assert turn["prevented"] is True
    assert turn["reached_provider"] is False
    assert turn["answered"] is False
    assert turn["rules"]
    # What did NOT happen, stated rather than left blank.
    assert turn["reply_status"].startswith("No reply: the prompt was stopped")
    assert turn["reply"] == ""


def test_a_legitimate_prompt_is_still_answered(server):
    status, turn = ask(server, prompt=(
        "What does the HIPAA minimum necessary standard require when we share "
        "records with a billing vendor?"))
    assert status == 200
    assert turn["answered"] is True
    assert turn["prevented"] is False
    assert turn["reply"]
    assert turn["provider_is_live"] is False


def test_redact_mode_reports_per_finding(server):
    status, turn = ask(server, mode="redact",
                       prompt="Confirm coverage for member SSN 900-12-3456.")
    assert status == 200
    assert turn["rules_removed"]
    # ⚠ TRIPWIRE. Since SDK 1.9.0 the guard blocks when a finding survives its
    # own redaction (#216); a survivor here means that fix regressed.
    assert turn["rules_surviving"] == []
    assert turn["redaction_ineffective"] is False


@pytest.mark.parametrize("sector", SECTOR_NAMES)
@pytest.mark.parametrize("mode", ("observe", "block", "redact"))
def test_every_sector_and_mode_answers_without_a_key_or_a_socket(server, sector, mode):
    status, turn = ask(server, sector=sector, mode=mode, prompt="Hello, what do you do?")
    assert status == 200
    assert turn["sector"] == sector
    assert turn["mode"] == mode
    assert turn["decision"] in core.DECISIONS
    assert turn["decision"] != "error", turn["error"]


def test_switching_mode_keeps_the_same_provider(server):
    """``with_mode`` carries the client and the provider; a rebuild would not.

    A keyed session that stopped writing to its ledger the moment somebody
    changed the mode is the defect this route would otherwise reintroduce, one
    surface later.
    """
    first = ask(server, mode="block")[1]
    second = ask(server, mode="redact")[1]
    assert first["provider"] == second["provider"]
    assert first["model"] == second["model"]


# ── 8 · what the server refuses ───────────────────────────────────────────────
def test_a_cross_origin_post_is_refused_before_the_engine_runs(server):
    """⚠ A LOOPBACK LISTENER IS NOT A PRIVATE ONE.

    Any page on the internet can make a browser POST here. It cannot read the
    response -- this server sends no CORS headers -- but the SIDE EFFECT happens,
    and on a live provider that side effect spends the user's own key on a prompt
    they never typed.
    """
    status, body = ask(server, headers={"Origin": "https://evil.example"})
    assert status == 403
    assert "Nothing was run" in body["detail"]


def test_the_page_s_own_origin_is_accepted(server):
    port = server.server_address[1]
    status, _ = ask(server, headers={"Origin": "http://127.0.0.1:{0}".format(port)})
    assert status == 200


def test_a_rebound_hostname_is_refused(server):
    """DNS rebinding: a name the attacker controls, pointed at 127.0.0.1, makes
    the browser treat this server as same-origin. The socket cannot tell; the
    ``Host`` header can."""
    port = server.server_address[1]
    request = urllib.request.Request("http://127.0.0.1:{0}/session".format(port))
    request.add_header("Host", "testbed.evil.example")
    with pytest.raises(urllib.error.HTTPError) as caught:
        urllib.request.urlopen(request, timeout=10)
    assert caught.value.code == 421


def test_an_idle_connection_does_not_wedge_the_server():
    """⚠ A SERIAL SERVER HAS EXACTLY ONE REQUEST SLOT, so a stalled client is an
    outage rather than a slowdown -- and with no handler timeout it is a
    permanent one, with nothing logged and nothing raised.

    A browser's speculative preconnect opens a socket and sends nothing. So does
    a port scan. This opens one, sends nothing, and requires a NORMAL request
    made afterwards to still be answered.

    The shipped timeout is ten seconds, which no test should wait for, so this
    builds its own server with a short one. That is the only value it changes:
    the mechanism under test is the class attribute existing at all, which is
    asserted separately below.
    """
    import socket

    handler = type("Brief", (web.Handler,), {"timeout": 0.4})
    built = web.build_server(web.Testbed(), port=0)
    built.RequestHandlerClass = type(
        "BriefBound", (handler,),
        {"testbed": built.RequestHandlerClass.testbed,
         "bind": built.RequestHandlerClass.bind})
    thread = threading.Thread(target=built.serve_forever, daemon=True)
    thread.start()
    try:
        stalled = socket.create_connection(("127.0.0.1", built.server_address[1]),
                                           timeout=5)
        try:
            status, payload = call(built, "/session")
        finally:
            stalled.close()
        assert status == 200
        assert payload["provider"]["name"] == "mock"
    finally:
        built.shutdown()
        built.server_close()
        thread.join(timeout=5)


def test_the_handler_carries_a_timeout_at_all():
    assert isinstance(web.Handler.timeout, (int, float))
    assert web.Handler.timeout > 0


def test_the_body_cap_cannot_bite_before_the_prompt_cap():
    """⚠ TWO LIMITS ON ONE QUANTITY, AND THE DOCUMENTED ONE NEVER FIRED.

    The body cap was a flat 64 KiB checked against raw bytes, so a prompt of
    astral characters hit it at roughly 5,400 -- and ``MAX_PROMPT_CHARS``, the
    number a user is actually told, was unreachable for anything but Latin text.

    Asserted by ENCODING a worst-case prompt rather than by re-deriving the
    constant: ``json.dumps`` defaults to ``ensure_ascii``, which is the pessimal
    encoder and worse than any browser, so clearing it clears every real client.
    """
    worst = "\U0001f600" * web.MAX_PROMPT_CHARS       # one char, twelve bytes escaped
    body = json.dumps({"sector": "healthcare", "mode": "block", "prompt": worst})
    assert len(body.encode("utf-8")) <= web.MAX_BODY_BYTES, (
        len(body.encode("utf-8")), web.MAX_BODY_BYTES)


def test_an_over_long_non_latin_prompt_is_refused_for_the_reason_it_is_too_long(server):
    """The reason matters: a body-size refusal names a limit the user cannot see."""
    status, payload = ask(server, prompt="\U0001f600" * (web.MAX_PROMPT_CHARS + 1))
    assert status == 413
    assert payload["error"] == "prompt too long"
    assert str(web.MAX_PROMPT_CHARS) in payload["detail"]


@pytest.mark.parametrize("body,expected", [
    ({"sector": "healthcare", "mode": "block", "prompt": "   "}, 400),
    ({"sector": "healthcare", "mode": "block"}, 400),
    ({"sector": "nowhere", "mode": "block", "prompt": "hi"}, 400),
    ({"sector": "healthcare", "mode": "sideways", "prompt": "hi"}, 400),
    ({"sector": "healthcare", "mode": "block", "prompt": "x" * 20001}, 413),
])
def test_a_malformed_turn_is_named_rather_than_run(server, body, expected):
    status, payload = call(server, "/turn", body)
    assert status == expected
    assert payload["error"]


def test_an_unknown_route_says_which_ones_exist(server):
    status, payload = call(server, "/wp-login.php")
    assert status == 404
    assert "/turn" in payload["detail"]


def test_a_body_that_is_not_json_is_refused(server):
    port = server.server_address[1]
    request = urllib.request.Request(
        "http://127.0.0.1:{0}/turn".format(port), data=b"{not json",
        method="POST")
    request.add_header("Host", "127.0.0.1:{0}".format(port))
    request.add_header("Content-Type", "application/json")
    with pytest.raises(urllib.error.HTTPError) as caught:
        urllib.request.urlopen(request, timeout=10)
    assert caught.value.code == 400


def test_an_internal_failure_reports_a_type_and_never_a_message(server, monkeypatch):
    """⚠ THE ONE THING THIS SERVER MUST NEVER DO is put a prompt somewhere the
    user did not put it. An exception message can carry the text that caused it,
    so only the exception's TYPE is reported.
    """
    class Exploding:
        def ask(self, sector, mode, prompt):
            raise RuntimeError("the prompt was: SSN 900-12-3456")

    handler = type(server.RequestHandlerClass.__name__,
                   (server.RequestHandlerClass,), {})
    monkeypatch.setattr(server, "RequestHandlerClass", handler)
    monkeypatch.setattr(handler, "testbed", Exploding())
    status, payload = ask(server, prompt="anything")
    assert status == 500
    assert payload["detail"] == "RuntimeError"
    assert "900-12-3456" not in json.dumps(payload)
