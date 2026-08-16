"""The chat's preflight guard — the seam, the refusal, and the receipt.

⚠ THE FIRST TEST IN THIS FILE EXISTS BECAUSE ITS ABSENCE SHIPPED A CRASH.
An earlier cut of this feature was 839 lines with nothing importing them, and
it segfaulted at launch: `glass_tokens()` reaches `QFontDatabase` through
`pick_font()`, and calling that before a QApplication exists exits 139 — on the
normal platform, not only offscreen. Every screenshot of it had been taken from
a harness that happened to build the QApplication first, which hid the fault
completely. So the gate here is not "do the functions return sensible values";
it is BUILD THE WINDOW AND OPEN IT, headless, every run.

The rest of the file guards the four claims this feature makes:

  1. a blocked prompt never reaches the model, and cannot reach it afterwards
     through an input left live under the refusal card
  2. a PROMPT block and a RESPONSE block are different events with different
     sentences — one prevented the call, the other did not
  3. a refused prompt is not written to the cleartext chat history
  4. the receipt shows what the guard returned, not what the UI recomputed
"""

from __future__ import annotations

import importlib
import json
import os
import sys
from pathlib import Path

import pytest
from PyQt6.QtCore import QSettings, Qt
from PyQt6.QtWidgets import QApplication, QWidget

HERE = Path(__file__).resolve().parent
REPO = HERE.parent


@pytest.fixture(scope="module")
def app():
    return QApplication.instance() or QApplication([])


@pytest.fixture()
def settings(tmp_path):
    from fox_settings import FoxSettings
    from foxy_client import MemorySecretStore
    store = QSettings(str(tmp_path / "guard.ini"), QSettings.Format.IniFormat)
    return FoxSettings(store, MemorySecretStore())


@pytest.fixture()
def history_file(tmp_path, monkeypatch):
    """Redirect the chat history away from the developer's real one."""
    import clay_chat_popup
    path = tmp_path / "chat_history.json"
    monkeypatch.setattr(clay_chat_popup, "_history_path", lambda: str(path))
    return path


@pytest.fixture()
def popup(app, settings, history_file, monkeypatch):
    from clay_chat_popup import ChatPopup
    # The model is a spy: every test needs to know whether it was reached.
    calls: list = []
    import ai_providers
    monkeypatch.setattr(ai_providers, "call_ai",
                        lambda hist, sysprompt, s: calls.append(hist) or "mock reply")
    host = QWidget()
    win = ChatPopup(host, settings)
    # SHOWN, not just built: isVisible() on a child is False while any ancestor
    # is hidden, so an unshown window makes "the refusal card is up" unfalsifiable.
    win.show()
    win.model_calls = calls
    yield win
    win.close()
    win.deleteLater()
    host.deleteLater()


def _send(popup, text, mode="block"):
    """Drive one whole turn synchronously — no event-queue pumping.

    The 400 ms QTimer and the worker QThread are deliberately stepped over:
    `_dispatch_ai` is what the timer calls and `_AICallWorker.run` is what the
    thread runs, so calling the guard directly exercises the same code with none
    of the cross-test event-queue damage that pumping the shared queue causes.
    """
    import foxy_guard
    popup.settings.set_guard_mode(mode)
    popup.input_field.setText(text)
    popup.send_message()
    popup._history.append({"role": "user", "content": text})
    result = foxy_guard.run(
        text,
        lambda t: __import__("ai_providers").call_ai(
            [{"role": "user", "content": t}], "sys", popup.settings),
        policy_tag=popup.settings.guard_policy(), mode=mode)
    popup._on_ai_success(result)
    return result


# ══ 1. it opens ═════════════════════════════════════════════════════════════
def test_the_window_builds_and_opens_headless(app, settings, history_file):
    """The gate the last cut did not have."""
    from clay_chat_popup import ChatPopup
    host = QWidget()
    win = ChatPopup(host, settings)
    try:
        win.show_animated()
        assert win.isVisible(), "the chat did not open"
        assert win.guard_strip.isVisible(), "the guard strip is not on the chat"
        assert win.block_overlay.isHidden(), \
            "the refusal card is up before anything was refused"
    finally:
        win.close()
        win.deleteLater()
        host.deleteLater()


def test_the_chat_modules_import_before_any_qapplication_exists():
    """The exact shape of the crash, in the place it happened.

    `glass_tokens()` -> `pick_font()` -> `QFontDatabase` segfaults when no
    QApplication exists. Constructors may call it — by then the app is up — but
    NOTHING at module level may. Re-broken by adding `_EAGER = glass_tokens()`
    to guard_widgets: this subprocess then exits 139 instead of 0.
    """
    import subprocess
    code = (
        "import sys; sys.path.insert(0, r'%s');"
        "from PyQt6.QtWidgets import QApplication;"
        "assert QApplication.instance() is None;"
        "import guard_widgets, clay_chat_popup;"
        "assert QApplication.instance() is None, 'a module built a QApplication';"
        "print('OK')" % HERE
    )
    out = subprocess.run([sys.executable, "-c", code], capture_output=True)
    assert out.returncode == 0, (
        f"importing the chat before a QApplication exits {out.returncode}: "
        + out.stderr.decode("utf-8", "replace")[-400:])


def test_the_guard_never_adopts_an_exported_key(monkeypatch):
    """`FoxyConfig.resolve` reads $FOXY_API_KEY when api_key is None, so a
    developer with that variable exported would have this chat shipping while
    the strip said "local only". Same defect as the one fixed in the demo."""
    import foxy_guard
    monkeypatch.setenv("FOXY_API_KEY", "foxy_sk_exported_elsewhere")
    foxy_guard.reset_clients()
    try:
        result = foxy_guard.run("What is the capital of France?", lambda t: "Paris",
                                policy_tag="default", mode="block", api_key="")
        client = foxy_guard._client("", "", "block")
        assert client.cfg.api_key == "", "the chat adopted an ambient key"
        assert client.cfg.enabled is False
        assert result["shipped"] is False, "an event was shipped from a keyless chat"
    finally:
        foxy_guard.reset_clients()


def test_the_guard_module_needs_no_qapplication():
    """foxy_guard must stay importable and runnable with no Qt at all.

    Re-broken by adding a Qt import to foxy_guard: this subprocess then exits
    non-zero (or 139) instead of printing OK.
    """
    import subprocess
    code = (
        "import sys; sys.path.insert(0, r'%s');"
        "import foxy_guard;"
        "r = foxy_guard.run('hello', lambda t: 'hi', policy_tag='default', mode='block');"
        "assert r['decision'] == 'allowed', r['decision'];"
        "assert 'PyQt6' not in sys.modules, 'foxy_guard dragged Qt in';"
        "print('OK')" % HERE
    )
    env = dict(os.environ, FOXY_API_KEY="", FOXY_SPOOL_PATH="")
    out = subprocess.run([sys.executable, "-c", code], capture_output=True, env=env)
    assert out.returncode == 0, out.stderr.decode("utf-8", "replace")[-800:]


# ══ 2. a blocked prompt never reaches the model ═════════════════════════════
def test_a_blocked_prompt_never_reaches_the_model(popup):
    result = _send(popup, "Patient SSN is 123-45-6789, DOB 1980-01-01.")

    assert result["decision"] == "blocked"
    assert result["llm_called"] is False
    assert popup.model_calls == [], "the model was called for a blocked prompt"
    assert popup.block_overlay.isVisible(), "nothing told the user it was blocked"
    assert "Blocked before the model saw it." in popup.block_overlay.title.text()


def test_the_input_stays_dead_under_the_refusal_card(popup):
    """A live field under an opaque overlay let a whole second turn complete
    while the card still said the last one was blocked."""
    _send(popup, "Patient SSN is 123-45-6789.")

    assert not popup.input_field.isEnabled(), \
        "the input is live under the refusal card"
    assert not popup.send_btn.isEnabled(), "send is live under the refusal card"


def test_a_second_turn_cannot_complete_behind_the_card(popup):
    """The behavioural version of the test above, and the one that matters.

    Disabling two widgets is an implementation; what was actually wrong is that
    a person could send another prompt while looking at a refusal. This drives
    the real entry point — `send_message` — and asserts nothing happened.
    """
    _send(popup, "Patient SSN is 123-45-6789.")
    bubbles_before = len(popup._bubbles)

    popup.input_field.setText("and what about this one")
    popup.send_message()

    assert len(popup._bubbles) == bubbles_before, \
        "a second turn started while the refusal card was up"


def test_the_card_holds_focus_so_escape_can_reach_it(popup):
    """Escape is only a dismissal if the card is what receives it."""
    _send(popup, "Patient SSN is 123-45-6789.")

    # focusWidget(), not hasFocus(): hasFocus() also requires the WINDOW to be
    # active, which it is for a real user and is not under a headless runner.
    # What matters is which widget this window will deliver a key press to.
    assert popup.focusWidget() is popup.block_overlay, \
        "the card never took focus — Escape goes to whatever did"


def test_dismissing_the_card_gives_the_input_back(popup):
    _send(popup, "Patient SSN is 123-45-6789.")
    popup.block_overlay.dismiss()

    assert popup.block_overlay.isHidden()
    assert popup.input_field.isEnabled()


def test_escape_closes_the_refusal_card(popup, app):
    from PyQt6.QtGui import QKeyEvent
    from PyQt6.QtCore import QEvent
    _send(popup, "Patient SSN is 123-45-6789.")

    # Delivered through Qt to whatever holds focus, NOT called on the overlay
    # directly: calling keyPressEvent by hand proves the handler works while
    # saying nothing about whether the key would ever arrive.
    app.sendEvent(popup.focusWidget(),
                  QKeyEvent(QEvent.Type.KeyPress, Qt.Key.Key_Escape,
                            Qt.KeyboardModifier.NoModifier))

    assert popup.block_overlay.isHidden(), "Escape did not dismiss the card"


# ══ 3. the two blocks are different events ═════════════════════════════════
def test_a_response_block_does_not_claim_the_model_never_ran(popup):
    """The model DID run here, and the card must not say otherwise."""
    result = {
        "policy": "default", "mode": "block", "decision": "response_blocked",
        "rules": ["response_markup.script"], "signals": ["markup"],
        "reason": "unsafe_markup", "prompt_hash": "a" * 64,
        "response_hash": "b" * 64, "llm_called": True, "response": "",
        "model_input": "x", "stage": "response", "shipped": False, "wire": None,
        "sdk_version": "", "ruleset_version": "",
    }
    popup._pending_prompt = "give me the snippet"
    popup._on_ai_success(result)

    body = popup.block_overlay.body.text()
    title = popup.block_overlay.title.text()
    assert title == "Blocked on the way back."
    assert "never called" not in body and "never left" not in body, body
    assert "did reach the model" in body


def test_the_two_blocks_do_not_share_a_sentence(popup):
    _send(popup, "Patient SSN is 123-45-6789.")
    prompt_body = popup.block_overlay.body.text()
    assert "never called" in prompt_body

    popup.block_overlay.show_for({"policy": "default", "reason": "unsafe_markup",
                                  "rules": [], "prompt_hash": "", "stage": "response"},
                                 can_redact=False)
    assert popup.block_overlay.body.text() != prompt_body


# ══ 4. a refused prompt is not written to disk ═════════════════════════════
def test_a_blocked_prompt_is_not_written_to_the_chat_history(popup, history_file):
    secret = "Patient Kowalczyk SSN 123-45-6789 needs escalation"
    _send(popup, secret)

    written = history_file.read_text(encoding="utf-8") if history_file.exists() else ""
    assert "123-45-6789" not in written, \
        "the refused prompt was persisted in cleartext"
    assert "Kowalczyk" not in written


def test_an_allowed_prompt_is_recorded_normally(popup, history_file):
    _send(popup, "What is the capital of France?")

    written = json.loads(history_file.read_text(encoding="utf-8"))
    roles = [m["role"] for s in written for m in s["messages"]]
    assert roles == ["user", "assistant"], written


def test_a_blocked_prompt_leaves_the_model_context_clean(popup):
    _send(popup, "Patient SSN is 123-45-6789.")
    assert popup._history == [], \
        "the refused prompt stayed in the history sent to the next model call"


# ══ 5. the policy is chosen, not guessed ═══════════════════════════════════
def test_hipaa_and_gdpr_cannot_be_told_apart_from_the_prompt():
    """The measurement the design rests on, kept live.

    An auto-selector was tried first and labelled every email address `phi`,
    because it evaluated hipaa before gdpr and hipaa matched. Reordering does
    not help: both tags run the SAME detector and differ only in the prefix
    they file the finding under. If a future SDK ever gives them different
    signals, this fails — and auto-selection becomes possible again.
    """
    from foxy_audit import policy
    prompt = "Email jane.doe@acme.co from 10.0.0.1 with the invoice."
    phi = policy.evaluate(prompt, "hipaa")
    pii = policy.evaluate(prompt, "gdpr")

    assert phi.signals == pii.signals, "the tags now differ — revisit the design"
    assert [r.split(".", 1)[1] for r in phi.rules] == \
           [r.split(".", 1)[1] for r in pii.rules]
    assert phi.reason == "phi" and pii.reason == "pii"


def test_the_configured_tag_is_the_one_that_judges(popup):
    popup.settings.set_guard_policy("hipaa")
    assert _send(popup, "What is the capital of France?")["policy"] == "hipaa"

    popup.settings.set_guard_policy("gdpr")
    assert _send(popup, "What is the capital of France?")["policy"] == "gdpr"


def test_the_default_tag_labels_personal_data_as_pii(settings):
    """`phi` asserts a healthcare context the app cannot know it is in."""
    assert settings.guard_policy() == "gdpr"


def test_no_auto_selector_came_back():
    """A heuristic that cannot be right is worse than none: it produces a
    confident wrong label on every row it touches."""
    import foxy_guard
    assert not hasattr(foxy_guard, "choose_policy")


# ══ 6. the receipt renders the guard's own dict ════════════════════════════
def test_the_receipt_shows_what_the_guard_returned(popup):
    from guard_widgets import GuardReceipt
    result = _send(popup, "Patient SSN is 123-45-6789.")
    rows = dict(GuardReceipt.build_rows(result, "Patient SSN is 123-45-6789."))

    assert rows["prompt_hash"] == result["prompt_hash"]
    assert rows["response_hash"] == result["response_hash"]
    assert rows["rules"] == " · ".join(result["rules"])
    assert rows["llm called?"].startswith("NO")
    assert result["decision"].upper() in rows["decision"]


def test_the_receipt_reports_no_egress_when_there_is_no_key(popup):
    from guard_widgets import GuardReceipt
    result = _send(popup, "What is the capital of France?")
    rows = dict(GuardReceipt.build_rows(result, "What is the capital of France?"))

    assert result["wire"] is None
    assert "nothing" in rows["what left this machine"]


def test_a_shipped_payload_carries_no_prompt_text():
    """Content-blindness, measured on the real payload rather than asserted."""
    import foxy_guard
    captured: list = []
    original = foxy_guard.dispatch.submit
    foxy_guard.install_tee()
    foxy_guard.reset_clients()
    try:
        foxy_guard.dispatch.submit = lambda cfg, payload, wait=False: captured.append(payload)
        prompt = "Patient Kowalczyk SSN 123-45-6789 needs escalation urgently"
        result = foxy_guard.run(prompt, lambda t: "ok", policy_tag="hipaa",
                                mode="block", api_key="foxy_sk_test_only",
                                endpoint="http://127.0.0.1:8000")
    finally:
        foxy_guard.dispatch.submit = original
        foxy_guard.reset_clients()

    assert captured, "nothing was shipped, so this proves nothing"
    body = json.dumps(captured[-1], sort_keys=True)
    from guard_widgets import leaked_words
    assert leaked_words(prompt, body) == [], "prompt text left the machine"
    assert result["prompt_hash"], "no commitment was recorded"


# ══ 7. the mock model matches the demo's ═══════════════════════════════════
def test_the_mock_model_matches_the_demos():
    """The desktop copy of MockLLM cannot drift from `demo/mock_llm.py`'s.

    A copy rather than an import because `demo/` is not shipped in the packaged
    app — but the two are shown side by side, so they have to answer alike.
    """
    sys.path.insert(0, str(REPO / "demo"))
    try:
        demo = importlib.import_module("mock_llm")
    except Exception:                       # noqa: BLE001 — demo/ absent
        pytest.skip("demo/ is not importable here")
    finally:
        sys.path.remove(str(REPO / "demo"))

    import ai_providers
    reference = demo.MockLLM()
    for prompt in ("What is the capital of France?", "hello there",
                   "summarise this", "Patient SSN is 123-45-6789", ""):
        assert ai_providers.call_mock(prompt) == reference.generate(prompt), prompt


# ══ 8. no SDK is a state, not a lie ════════════════════════════════════════
def test_without_the_sdk_the_strip_says_so(app, settings, history_file, monkeypatch):
    import clay_chat_popup
    import foxy_guard
    from clay_chat_popup import ChatPopup
    monkeypatch.setattr(foxy_guard, "SDK_AVAILABLE", False)
    host = QWidget()
    win = ChatPopup(host, settings)
    try:
        assert "unavailable" in win.guard_strip.left.text().lower(), \
            "an unguarded chat looked guarded"
    finally:
        win.close()
        win.deleteLater()
        host.deleteLater()
