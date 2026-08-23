"""D16 / T3 — the Compliance Testbed page.

Three things make this page unlike every other console section, and each one is
what the guards below are actually about:

1. **It is the only place `desktop/` imports the SDK.** The import is inside
   `TestbedSections.build`, inside a `try`, because CI installs
   `desktop/requirements.txt` and nothing else, and an import at module scope
   would fail all 884 desktop tests rather than one. The not-installed state is
   proved by MAKING `foxy_testbed` unimportable, not by asserting the happy path
   and hoping — a guard that only ever sees the working case is green from
   birth.
2. **It holds no policy logic and no verdict vocabulary.** The engine computes
   both; this file pins the desktop's sentences against `cli.turn_lines`'s own
   output, so a reword on either side goes red instead of the two surfaces
   quietly disagreeing.
3. **It runs a network call.** The turn goes on a `QThread` and the composer is
   dead while it is in flight.

⚠ WHERE THE ENGINE COMES FROM HERE. The desktop suite runs in environments that
may have `foxy-audit` installed (CI, from the wheel) or not (a dev checkout on
this machine's Python 3.13). Neither is what these guards are ABOUT: the
contract is with the engine in THIS repo, the one that will be published, so
`_engine()` reaches for `sdk/src` and restores `sys.path` immediately — the same
shape `test_guard_bridge._demo` uses for `demo/`.
"""

from __future__ import annotations

import ast
import importlib
import sys
from pathlib import Path

import pytest
from PyQt6.QtCore import QSettings, QThread
from PyQt6.QtWidgets import QApplication, QLabel, QPushButton, QWidget

import testbed_data as tbd
from foxy_tokens import BAD_RED, DARK_TX, INFO_BLUE, OK_GREEN, WARN_AMBER, WEB
from test_d15_contrast import ratio

_HERE = Path(__file__).resolve().parent
_ROOT = _HERE.parent
_SDK_SRC = _ROOT / "sdk" / "src"

#: Every desktop module, so the module-scope-import guard cannot miss a new one.
_SOURCES = sorted(p for p in _HERE.glob("*.py") if not p.name.startswith("test_"))


@pytest.fixture(scope="module")
def app():
    # RETURNED, never dropped — see test_qt_lifecycle on exit 127.
    return QApplication.instance() or QApplication([])


# ══ reaching the engine ═════════════════════════════════════════════════════
def _engine():
    """The repo's own `foxy_testbed`, or skip.

    `sys.path` is restored on the way out; the package stays in `sys.modules`,
    which is exactly what makes the page's own guarded import succeed for the
    tests below that need a working engine.
    """
    sys.path.insert(0, str(_SDK_SRC))
    try:
        for name in ("foxy_testbed", "foxy_testbed.core", "foxy_testbed.cli",
                     "foxy_testbed.sectors", "foxy_testbed.providers"):
            importlib.import_module(name)
    except Exception:                                 # noqa: BLE001
        pytest.skip("the SDK in sdk/src is not importable here")
    finally:
        sys.path.remove(str(_SDK_SRC))
    engine, problem = tbd.load_engine()
    assert engine is not None, problem
    return engine


def _turn(engine, sector: str, prompt: str, mode: str = "block"):
    return engine.core.Assistant(sector, mode=mode).ask(prompt)


def _probe(engine, sector: str, expect: str):
    for probe in engine.sectors.get_sector(sector).probes:
        if probe.expect == expect:
            return probe
    raise AssertionError(f"{sector} has no {expect} probe")


class _Blocked:
    """A meta-path finder that makes `foxy_testbed` genuinely unimportable.

    ⚠ THE POINT OF THE WHOLE FILE IS THAT THIS IS REAL. Monkeypatching
    `load_engine` to return `(None, "…")` would prove that the renderer can draw
    an error, not that the import is guarded — and the import is the thing that
    takes CI down.
    """

    def find_module(self, fullname, path=None):       # pragma: no cover — py<3.12
        return None

    def find_spec(self, fullname, path=None, target=None):
        if fullname == "foxy_testbed" or fullname.startswith("foxy_testbed."):
            raise ImportError("no module named 'foxy_testbed' (blocked by test)")
        return None


@pytest.fixture
def sdk_absent():
    """`foxy_testbed` is not installed, for the duration of one test."""
    finder = _Blocked()
    cached = {name: module for name, module in sys.modules.items()
              if name == "foxy_testbed" or name.startswith("foxy_testbed.")}
    for name in cached:
        del sys.modules[name]
    sys.meta_path.insert(0, finder)
    try:
        yield
    finally:
        sys.meta_path.remove(finder)
        sys.modules.update(cached)


def _console(app, tmp_path):
    from dashboard import DashboardWindow
    from fox_settings import FoxSettings
    from foxy_client import MemorySecretStore
    store = QSettings(str(tmp_path / "console.ini"), QSettings.Format.IniFormat)
    return DashboardWindow(settings=FoxSettings(store, MemorySecretStore()))


def _texts(root: QWidget) -> str:
    return " ".join(lbl.text() for lbl in root.findChildren(QLabel))


# ══ 1 · the section is registered ═══════════════════════════════════════════
def test_the_testbed_is_a_real_console_section(app, tmp_path):
    from console_chrome import ALL_SECTIONS, PALETTE_LABELS, palette_entries
    assert "testbed" in {s[0] for s in ALL_SECTIONS}
    assert PALETTE_LABELS["testbed"]
    rows = {r["arg"]: r["label"] for r in palette_entries("guard")
            if r["kind"] == "page"}
    assert rows.get("testbed"), \
        "the palette label lost the search terms it exists for"

    console = _console(app, tmp_path)
    try:
        assert "testbed" in console._page_index
        console.go("testbed")
        assert console.page_title.text() == "Compliance testbed"
        assert console._nav_by_id["testbed"].text_label == "Testbed"
    finally:
        console.close()


# ══ 2 · the guarded import ══════════════════════════════════════════════════
def test_no_desktop_module_imports_the_sdk_at_module_scope():
    """⚠ THE GUARD THAT PROTECTS CI, AND IT IS STRUCTURAL FOR A REASON.

    `pip install -r desktop/requirements.txt` now brings foxy-audit, so a
    module-scope import would PASS here and on CI — and then fail on the first
    developer machine, or on any environment where the wheel is absent, taking
    the entire console down instead of one page. The rule is not "the import
    works", it is "the import is deferred", so the AST is what is read.
    """
    offenders = []
    for path in _SOURCES:
        tree = ast.parse(path.read_text(encoding="utf-8"))
        for node in tree.body:                        # TOP LEVEL ONLY
            names = []
            if isinstance(node, ast.Import):
                names = [a.name for a in node.names]
            elif isinstance(node, ast.ImportFrom):
                names = [node.module or ""]
            for name in names:
                if name.split(".")[0] in ("foxy_audit", "foxy_testbed"):
                    offenders.append(f"{path.name}: {name}")
    assert offenders == [], (
        f"{offenders} import the SDK at module scope. It must be imported "
        f"inside testbed_data.load_engine, inside a try — see its docstring.")


def test_the_page_renders_an_honest_state_when_the_sdk_is_absent(
        app, tmp_path, sdk_absent):
    """No disabled button, no spinner, no fabricated turn — the sentence that
    names the fix, and the real exception underneath it."""
    console = _console(app, tmp_path)
    try:
        page = console.stack.widget(console._page_index["testbed"])
        text = _texts(page)
        assert tbd.MISSING_TITLE in text
        # ⚠ THE LITERAL, NOT `tbd.MISSING_FIX`. Comparing the constant to
        # itself is a guard that follows the defect: renaming the fix to
        # "Contact support." left this green, which is how it was caught.
        assert "pip install foxy-audit" in text, \
            "the empty state does not name the one command that fixes it"
        assert "no module named 'foxy_testbed'" in text.lower(), \
            "the empty state hides why the import failed"
        # The three things it must NOT be.
        assert not page.findChildren(QPushButton), \
            "a control on this page implies it is one click from working"
        assert not hasattr(console, "tb_prompt"), \
            "the composer was built against an engine that is not there"
        assert "loading" not in text.lower() and "…" not in text
    finally:
        console.close()


def test_the_console_still_builds_every_other_page_without_the_sdk(
        app, tmp_path, sdk_absent):
    """The blast radius of a missing SDK is ONE page. This is the assertion the
    module-scope import would have broken, stated as behaviour rather than as
    the AST rule above."""
    from console_chrome import ALL_SECTIONS
    console = _console(app, tmp_path)
    try:
        for section_id, _l, title, _c, _i in ALL_SECTIONS:
            console.go(section_id)
            assert console.page_title.text() == title
            page = console.stack.widget(console._page_index[section_id])
            assert _texts(page).strip(), f"{section_id} renders nothing"
    finally:
        console.close()


# ══ 3 · the vocabulary is the engine's ══════════════════════════════════════
@pytest.mark.parametrize("shape", ["prevented", "answered", "error",
                                   "empty_reply", "reached_no_reply"])
def test_every_no_reply_sentence_is_the_repls_own(shape):
    """⚠ THE ONE DUPLICATION IN THIS PAGE, PINNED THE WAY `web.py` PINS ITS OWN.

    The four sentences live inside `cli.turn_lines`'s body, interleaved with
    terminal wrapping this surface does not do, so they cannot be imported. What
    CAN be done is assert that each one appears verbatim in that function's
    output for the same turn — so a reword on either side goes red instead of
    the REPL and the console quietly describing the same event differently.
    """
    engine = _engine()
    core = engine.core
    base = dict(sector="healthcare", policy_tag="hipaa", mode="block",
                provider="mock", model="m", ruleset_version="x")
    turns = {
        "prevented": core.Turn(decision="blocked", answered=False,
                               reached_provider=False, **base),
        "answered": core.Turn(decision="allowed", answered=True,
                              reached_provider=True, reply="hello", **base),
        "error": core.Turn(decision="error", answered=False,
                           reached_provider=True, error="X: y", **base),
        "empty_reply": core.Turn(decision="allowed", answered=False,
                                 reached_provider=True, empty_reply=True,
                                 **base),
        "reached_no_reply": core.Turn(decision="blocked_response",
                                      answered=False, reached_provider=True,
                                      **base),
    }
    turn = turns[shape]
    sentence = tbd.reply_status(turn)
    if shape == "answered":
        assert sentence == "", "an answered turn has no reason to show"
        return
    printed = " ".join(" ".join(engine.cli.turn_lines(turn)).split())
    assert " ".join(sentence.split()) in printed, (
        f"the console's {shape} sentence is not the REPL's:\n  {sentence}")


def test_the_headline_comes_from_the_engine_not_from_here():
    """A grep, deliberately: the word BLOCKED must not be spellable from this
    package. `_headline` is imported; a Qt copy of it would be the third."""
    engine = _engine()
    import testbed_page as tbp
    turn = _turn(engine, "healthcare", _probe(engine, "healthcare",
                                              "expect_block").prompt)
    label, note = tbp._headline_of(turn)
    assert (label, note) == engine.cli._headline(turn)
    for path in (_HERE / "testbed_page.py", _HERE / "testbed_data.py"):
        source = path.read_text(encoding="utf-8")
        body = "\n".join(line for line in source.splitlines()
                         if not line.lstrip().startswith("#"))
        assert "BLOCKED" not in body and "REDACTED," not in body, (
            f"{path.name} spells a verdict word itself — every one of them "
            f"belongs to cli._headline")


def test_no_policy_name_is_re_implemented_here():
    """The testbed is a CONSUMER of the SDK, and so is this page. Nothing here
    may name a rule, a policy tag, or a sector: they come off the record and off
    `sectors.py`, which is why finance and legal can honestly say what they do
    not catch."""
    for path in (_HERE / "testbed_page.py", _HERE / "testbed_data.py"):
        source = path.read_text(encoding="utf-8")
        body = "\n".join(line for line in source.splitlines()
                         if not line.lstrip().startswith("#"))
        for token in ("hipaa", "phi.", "injection.", "secret.", "healthcare",
                      "finance", "legal"):
            assert token not in body, (
                f"{path.name} names {token!r} — the presets and their rules "
                f"live in foxy_testbed.sectors and foxy_audit.policy")


# ══ 4 · the four families, measured before labelled ═════════════════════════
def test_a_block_that_reached_the_provider_is_not_the_calm_colour():
    """⚠ THE CASE THE ORDER OF `family_of` EXISTS FOR. A turn stamped `blocked`
    whose call reached the provider anyway is a contradiction; rendering it as a
    clean block is how it would stay unreachable-LOOKING while being reached."""
    engine = _engine()
    base = dict(sector="s", policy_tag="t", mode="block", provider="mock",
                model="m")
    honest = engine.core.Turn(decision="blocked", answered=False,
                              reached_provider=False, **base)
    contradiction = engine.core.Turn(decision="blocked", answered=False,
                                     reached_provider=True, **base)
    assert tbd.family_of(honest) == tbd.FAMILY_ENFORCED
    assert tbd.family_of(contradiction) == tbd.FAMILY_FAULT


def test_a_withheld_response_that_never_left_is_not_the_calm_colour():
    """The same pairing on the other label: `blocked_response` ASSERTS the call
    happened, so a turn stamped it with `reached_provider` False is a fault."""
    engine = _engine()
    base = dict(sector="s", policy_tag="t", mode="block", provider="mock",
                model="m")
    real = engine.core.Turn(decision="blocked_response", answered=False,
                            reached_provider=True, **base)
    impossible = engine.core.Turn(decision="blocked_response", answered=False,
                                  reached_provider=False, **base)
    assert tbd.family_of(real) == tbd.FAMILY_ENFORCED
    assert tbd.family_of(impossible) == tbd.FAMILY_FAULT


def test_an_unknown_decision_never_renders_as_allowed():
    """Adding a value to `core.DECISIONS` must not make it draw green — the
    worst available failure in an audit demo."""
    engine = _engine()
    unknown = engine.core.Turn(sector="s", policy_tag="t", mode="block",
                               provider="mock", model="m",
                               decision="something_new", answered=False,
                               reached_provider=False)
    assert tbd.family_of(unknown) == tbd.FAMILY_FAULT


# ══ 5 · the record ══════════════════════════════════════════════════════════
def test_a_blocked_turn_is_the_fullest_card_on_the_page(app):
    """The thesis, asserted. A prompt that never left says so four ways: the
    verdict word, the "reached" sentence, the findings it kept back, and a rail
    whose second segment is broken."""
    engine = _engine()
    import testbed_page as tbp
    probe = _probe(engine, "healthcare", "expect_block")
    turn = _turn(engine, "healthcare", probe.prompt)
    assert turn.prevented, "the healthcare block probe stopped blocking"

    card = tbp.record_card(turn)
    text = _texts(card)
    assert "the prompt never left this machine" in text
    assert "no, the provider was never called" in text
    assert "kept back" in text and "removed" not in text
    assert "No reply: the prompt was stopped before the provider was called." \
        in text
    assert card.property("turnFamily") == tbd.FAMILY_ENFORCED

    rail = card.findChildren(tbp.DeliveryRail)[0]
    assert rail._state["breaks"] == (True, True)
    assert rail._state["nodes"][2] == "idle"


def test_an_assisted_turn_says_the_reply_is_a_fixture(app):
    """The mock's provenance rides on EVERY reply, not only on the rail panel —
    and it is read off `provider_is_live`, never off the provider's name."""
    engine = _engine()
    import testbed_page as tbp
    probe = _probe(engine, "healthcare", "expect_assist")
    turn = _turn(engine, "healthcare", probe.prompt)
    assert turn.answered and not turn.provider_is_live

    text = _texts(tbp.record_card(turn))
    assert "reply (mock fixture, not model output)" in text
    assert "yes, the provider was called with this prompt" in text
    assert "live model output" not in text


def test_a_known_gap_renders_as_allowed_and_says_nothing_fired(app):
    """A gap is a real state of this product and the card must be able to be in
    it: nothing fired, the prompt went through, and the page does not pretend
    otherwise."""
    engine = _engine()
    import testbed_page as tbp
    probe = _probe(engine, "healthcare", "known_gap")
    turn = _turn(engine, "healthcare", probe.prompt)
    card = tbp.record_card(turn)
    assert card.property("turnFamily") == tbd.FAMILY_ALLOWED
    assert "(none fired)" in _texts(card)


def test_a_sub_millisecond_turn_does_not_print_as_zero(app):
    """⚠ FOUND BY LOOKING AT IT. Whole milliseconds printed "took 0 ms" for
    every mock turn — a real measurement that reads exactly like an unfilled
    placeholder, on the one surface in this product where a placeholder is
    forbidden. One decimal, which is what `Turn.as_dict` and the web page both
    already round to."""
    engine = _engine()
    turn = engine.core.Turn(sector="s", policy_tag="t", mode="block",
                            provider="mock", model="m", decision="allowed",
                            answered=True, reached_provider=True,
                            reply="hi", latency_ms=0.23)
    took = dict((name, value) for name, value, _o in tbd.field_rows(turn))
    assert took["took"] == "0.2 ms", took["took"]


def test_the_rail_states_nothing_the_fields_do_not_also_say(app):
    """It is a second ENCODING, not a second source — which is the only reason
    it is allowed to be outside the accessibility tree."""
    engine = _engine()
    import testbed_page as tbp
    turn = _turn(engine, "healthcare",
                 _probe(engine, "healthcare", "expect_assist").prompt)
    # The card is HELD. Dropping it deletes the C++ object under the widget
    # this test is about, and the RuntimeError that follows reads nothing like
    # the finding it would be reporting.
    card = tbp.record_card(turn)
    rail = card.findChildren(tbp.DeliveryRail)[0]
    from PyQt6.QtCore import Qt as _Qt
    assert rail.focusPolicy() == _Qt.FocusPolicy.NoFocus
    assert not rail.accessibleName()


# ══ 6 · colour ══════════════════════════════════════════════════════════════
def test_the_page_introduces_no_colour_of_its_own():
    """Every colour is a foxy_tokens value. A hex literal here is a token that
    will not move when the web's :root does."""
    import re
    for path in (_HERE / "testbed_page.py", _HERE / "testbed_data.py"):
        source = path.read_text(encoding="utf-8")
        body = "\n".join(line for line in source.splitlines()
                         if not line.lstrip().startswith("#"))
        # ⚠ ONE NAMED EXCLUSION, NOT A BLANKET "IGNORE DIGITS" RULE. `SDK #216`
        # is an issue reference the engine's own copy of this sentence carries
        # verbatim, and it is three hex-shaped characters. Dropping every
        # all-numeric match instead would have quietly excused a real #123456.
        body = re.sub(r"SDK #\d+", "SDK issue", body)
        found = re.findall(
            r"#(?:[0-9a-fA-F]{8}|[0-9a-fA-F]{6}|[0-9a-fA-F]{3})\b", body)
        assert found == [], f"{path.name} hardcodes {found}"


@pytest.mark.parametrize("family,fill", [
    (tbd.FAMILY_ALLOWED, OK_GREEN), (tbd.FAMILY_ENFORCED, INFO_BLUE),
    (tbd.FAMILY_FLAGGED, WARN_AMBER), (tbd.FAMILY_FAULT, BAD_RED)])
def test_each_verdict_mark_is_measured_against_the_card_behind_it(family, fill):
    """BOTH DIRECTIONS. This surface has shipped a chip whose text cleared
    4.5:1 while the pill itself sat at 1.01:1 against the card behind it, so the
    mark dissolved and only the letters were left."""
    import testbed_page as tbp
    assert tbp.FAMILY_FILL[family] == fill
    against_card = ratio(fill, WEB["surf"])
    assert against_card >= 3.0, (
        f"the {family} mark is {against_card:.2f}:1 against the card — the "
        f"fill itself is what dissolves, not its ink")
    ink = ratio(DARK_TX, fill)
    assert ink >= 4.5, f"{family} ink is {ink:.2f}:1 on its own fill"


def test_no_live_text_on_this_page_uses_muted2():
    """`muted2` is under AA and is legitimate only on `:disabled` states."""
    source = (_HERE / "testbed_page.py").read_text(encoding="utf-8")
    for line in source.splitlines():
        if "muted2" not in line:
            continue
        assert ":disabled" in line, (
            f"muted2 on live text: {line.strip()}")


# ══ 7 · threading ═══════════════════════════════════════════════════════════
def test_the_turn_runs_off_the_gui_thread(app, tmp_path):
    """⚠ THE MOCK IS INSTANT AND THAT IS NOT WHAT THIS IS ABOUT. A live provider
    is an HTTPS round trip; on the GUI thread it freezes the whole console."""
    _engine()
    import testbed_page as tbp
    assert issubclass(tbp.TurnWorker, QThread)

    console = _console(app, tmp_path)
    try:
        seen = {}

        class _Slow:
            provider = type("P", (), {"model": "m", "note": "", "is_live": False})()

            def ask(self, prompt):
                seen["thread"] = QThread.currentThread()
                return _turn(_engine(), "healthcare", prompt)

        console._testbed._assistants[
            (console._testbed._sector, console._testbed._mode,
             console._testbed._provider)] = _Slow()
        console.tb_prompt.setPlainText("what is a deductible?")
        console._testbed.send()
        worker = console._testbed._worker
        assert isinstance(worker, tbp.TurnWorker), \
            "send() did not start a worker at all"
        worker.wait(5000)
        app.processEvents()
        assert seen["thread"] is not app.thread(), \
            "Assistant.ask ran on the GUI thread"
    finally:
        console.close()


def test_a_second_entrance_while_in_flight_runs_nothing(app, tmp_path):
    """⚠ GATED ON THE WORKER, NOT ON THE BUTTON. Ctrl+Enter reaches `send`
    without ever looking at the button, so disabling the button locks one
    entrance and leaves the other open — and on a live provider that is a second
    billed call."""
    _engine()
    console = _console(app, tmp_path)
    try:
        calls = []

        class _Counting:
            provider = type("P", (), {"model": "m", "note": "", "is_live": False})()

            def ask(self, prompt):
                calls.append(prompt)
                return _turn(_engine(), "healthcare", prompt)

        sections = console._testbed
        sections._assistants[(sections._sector, sections._mode,
                              sections._provider)] = _Counting()
        console.tb_prompt.setPlainText("what is a deductible?")
        sentinel = object()                  # as if a turn were in flight
        sections._worker = sentinel
        sections.send()
        # ⚠ ASSERTED ON THE LOCK, NOT ON `calls`. The first version of this
        # checked that `ask` had not been called — but without the lock `send`
        # starts a THREAD, and the assertion ran before that thread did. It was
        # green with the lock deleted, which is how the race was found.
        assert sections._worker is sentinel, \
            "a second entrance replaced the in-flight worker"
        assert calls == [], "a second entrance started a second turn"
    finally:
        console.close()


def test_the_composer_is_dead_while_a_turn_is_in_flight(app, tmp_path):
    _engine()
    console = _console(app, tmp_path)
    try:
        sections = console._testbed
        sections._set_busy(True)
        assert not console.tb_send.isEnabled()
        assert not console.tb_prompt.isEnabled()
        assert not console.tb_mode.isEnabled()
        assert all(not b.isEnabled() for b in console.tb_sector_buttons)
        sections._set_busy(False)
        assert console.tb_send.isEnabled() and console.tb_prompt.isEnabled()
        assert console.tb_send.text() == "Send prompt"
    finally:
        console.close()


def test_the_window_waits_for_a_turn_worker_at_close():
    """A live turn outliving its window is a thread writing into deleted
    widgets. The set has to be in the shutdown union, not merely created."""
    source = (_HERE / "dashboard.py").read_text(encoding="utf-8")
    after = source.split("    def closeEvent(", 1)
    assert len(after) == 2
    body = after[1].split("\n    def ", 1)[0]
    assert "_testbed_workers" in body, \
        "closeEvent does not wait for the testbed's own workers"


# ══ 8 · the fox is not told about a demo ════════════════════════════════════
def test_the_page_never_pings_the_fox(app, tmp_path):
    """⚠ A FOX REACTION IS A CLAIM ABOUT A REAL EVENT. `desktop_ping=True` would
    make the companion flash and tally breaches the user manufactured by playing
    with the demo, and push invented rows into the console's own live-capture
    table. Asserted on the BUILT CLIENT, not on the absence of a keyword."""
    _engine()
    console = _console(app, tmp_path)
    try:
        assistant = console._testbed._assistant()
        assert assistant._client.cfg.desktop_ping is False
        assert assistant._client.cfg.enabled is False, \
            "the testbed built a keyed client and would write to a ledger"
    finally:
        console.close()


# ══ 9 · the transcript ══════════════════════════════════════════════════════
def test_a_record_is_visible_the_moment_it_is_inserted(app, tmp_path):
    """`insertWidget` does not show its child. Every list in this console goes
    through panel_state for exactly this reason."""
    engine = _engine()
    console = _console(app, tmp_path)
    try:
        console.show()
        console.go("testbed")
        turn = _turn(engine, "healthcare",
                     _probe(engine, "healthcare", "expect_block").prompt)
        console._testbed._on_turn(turn)
        row = console.tb_stream.itemAt(0).widget()
        assert row is not None and not row.isHidden()
        assert console.tb_count.text() == "1 turn in this transcript"
        assert not console.tb_empty.isVisible()

        console._testbed.clear_transcript()
        assert console.tb_stream.count() == 0
        assert console.tb_empty.isVisible()
    finally:
        console.close()


# ══ 10 · live providers ═════════════════════════════════════════════════════
def test_a_live_provider_with_no_key_names_where_a_key_goes_here():
    """`providers` raises a ProviderError naming `--api-key`, which is a CLI
    flag this surface does not have. Naming a control that does not exist is
    worse than naming none, so the two messages differ — the fox's Settings
    dialog has an OpenAI field and no Google one."""
    assert "--api-key" not in tbd.no_key_message("openai")
    assert "Settings" in tbd.no_key_message("openai")
    assert "OPENAI_API_KEY" in tbd.no_key_message("openai")
    # ⚠ HONEST ABOUT THE GAP rather than inventing a control.
    assert "GEMINI_API_KEY" in tbd.no_key_message("gemini")
    assert "no Google field" in tbd.no_key_message("gemini")


def test_the_keychain_wins_over_the_environment():
    class _Settings:
        def api_key(self, name):
            return "  from-keychain  "
    assert tbd.provider_key("openai", _Settings(),
                            {"OPENAI_API_KEY": "from-env"}) == "from-keychain"
    assert tbd.provider_key("openai", None,
                            {"OPENAI_API_KEY": "from-env"}) == "from-env"
    assert tbd.provider_key("openai", None, {}) == ""


def test_a_provider_that_fails_renders_the_engines_error_verdict(app):
    """A live provider is a network call and it can fail. The engine stamps that
    `error` and says so; the page must not collapse it into a block."""
    engine = _engine()
    import testbed_page as tbp

    class _Broken(engine.providers.Provider):
        name = "broken"

        def complete(self, system, prompt):
            raise engine.providers.ProviderError("openai request failed with "
                                                 "HTTP 503")

    turn = engine.core.Assistant("healthcare", provider=_Broken("m")).ask(
        "what is a deductible?")
    assert turn.decision == "error"
    card = tbp.record_card(turn)
    text = _texts(card)
    assert card.property("turnFamily") == tbd.FAMILY_FAULT
    assert "the provider call failed" in text
    assert "HTTP 503" in text
    assert "No reply: the provider call failed." in text


def test_an_over_long_prompt_is_refused_before_anything_is_sent(app, tmp_path):
    _engine()
    console = _console(app, tmp_path)
    try:
        calls = []

        class _Counting:
            provider = type("P", (), {"model": "m", "note": "", "is_live": False})()

            def ask(self, prompt):
                calls.append(prompt)
        sections = console._testbed
        sections._assistants[(sections._sector, sections._mode,
                              sections._provider)] = _Counting()
        console.tb_prompt.setPlainText("x" * (tbd.MAX_PROMPT_CHARS + 1))
        sections.send()
        assert calls == []
        # `isVisible` is False for every widget in an unshown window, so what
        # this asks is whether ResultPanel un-hid ITSELF — which is what
        # `show_result` does and what a silent refusal would not.
        assert not console.tb_problem.isHidden()
        assert console.tb_problem.tone() == "bad"
        assert "too long" in console.tb_problem.title.text()
    finally:
        console.close()


# ══ 11 · packaging ══════════════════════════════════════════════════════════
def test_the_shipped_build_carries_the_sdk():
    """⚠ THE OWNER'S DECISION: the page is for everyone who installs the .exe.
    `collect_all` rather than a hiddenimport, because `foxy_testbed` ships DATA
    beside its modules and a bundle carrying only the .py files would import and
    then fail on the first resource read."""
    requirements = (_HERE / "requirements.txt").read_text(encoding="utf-8")
    assert "foxy-audit" in requirements, \
        "the desktop no longer installs the SDK its Testbed page runs"
    # ⚠ COMMENTS STRIPPED FIRST. The comment ABOVE the collect_all loop names
    # both packages, so a raw grep stayed green with `foxy_testbed` deleted from
    # the code — the repo's own comment-grep trap, caught by re-breaking it.
    spec = "\n".join(
        line.split("#")[0] for line in
        (_HERE / "omni_fox.spec").read_text(encoding="utf-8").splitlines())
    for package in ("foxy_audit", "foxy_testbed"):
        assert package in spec, f"{package} is not bundled"
    assert "collect_all" in spec, \
        "a hiddenimport does not bring page.html, which is package DATA"


def test_the_requirement_is_a_bounded_range_like_every_other_line():
    """The file states the convention in its own header: bounded, never pinned,
    because the desktop environment is not captured by CI."""
    line = [ln for ln in (_HERE / "requirements.txt").read_text(
        encoding="utf-8").splitlines()
        if ln.strip().startswith("foxy-audit")]
    assert len(line) == 1, line
    assert ">=" in line[0] and "<" in line[0], line[0]
