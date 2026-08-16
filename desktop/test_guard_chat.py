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


# ══ 4b. no path re-sends or persists a prompt the guard rewrote ════════════
#
# ⚠ DERIVED FROM ONE TABLE, ON PURPOSE. The block path was fixed and tested
# per-case; its sibling — the redact path, and the "Retry with redaction" button
# that reaches it — kept both defects, because a per-case test covers the case
# that was reported and nothing else. Every row here is a path that can end with
# the model seeing different text from what was typed.
SENSITIVE = "Email jane.doe@acme.co about invoice 55"
SECRET_TOKEN = "jane.doe@acme.co"

REWRITING_PATHS = [
    ("redact mode", "redact"),
    ("retry after a block", "retry"),
]


def _retry(popup, text):
    """Exactly what `_retry_redacted` does, minus the QThread.

    It does NOT call `send_message`, so no second user bubble appears — the one
    already on screen from the refused turn is the one that gets rewritten. An
    earlier version of this helper sent again and produced a bubble the product
    never creates, which then failed for a reason the product did not have.
    """
    import foxy_guard
    popup._pending_prompt = text
    popup._history.append({"role": "user", "content": text})
    result = foxy_guard.run(
        text,
        lambda t: __import__("ai_providers").call_ai(
            [{"role": "user", "content": t}], "sys", popup.settings),
        policy_tag=popup.settings.guard_policy(), mode="redact",
        response_scan=popup.settings.guard_response_scan())
    popup._on_ai_success(result)
    return result


def _drive(popup, text, path):
    """Run `text` through one of the rewriting paths and hand back the turn."""
    if path == "retry":
        _send(popup, text, mode="block")            # refused first
        popup.block_overlay.dismiss()
        return _retry(popup, text)                  # what the button does
    return _send(popup, text, mode=path)


@pytest.mark.parametrize("name,path", REWRITING_PATHS)
def test_a_rewritten_prompt_is_not_carried_forward(popup, name, path):
    """What goes to the model next turn is what the model saw, not what was typed."""
    result = _drive(popup, SENSITIVE, path)
    assert result["decision"] == "redacted", f"{name}: expected a redaction"
    assert SECRET_TOKEN not in result["model_input"], f"{name}: nothing was scrubbed"

    carried = json.dumps(popup._history)
    assert SECRET_TOKEN not in carried, (
        f"{name}: the original is still in the conversation, so the NEXT turn "
        f"ships it to the provider verbatim")


@pytest.mark.parametrize("name,path", REWRITING_PATHS)
def test_a_rewritten_prompt_is_not_persisted(popup, history_file, name, path):
    """chat_history.json is cleartext on disk, and the title is the sidebar label."""
    _drive(popup, SENSITIVE, path)

    written = history_file.read_text(encoding="utf-8") if history_file.exists() else ""
    assert SECRET_TOKEN not in written, f"{name}: the original was persisted"
    for session in (json.loads(written) if written else []):
        assert SECRET_TOKEN not in session.get("title", ""), \
            f"{name}: the original became the session title"


@pytest.mark.parametrize("name,path", REWRITING_PATHS)
def test_the_window_shows_what_was_actually_sent(popup, name, path):
    result = _drive(popup, SENSITIVE, path)
    user_bubbles = [b.text() for b in popup._bubbles if b.is_user]
    assert all(SECRET_TOKEN not in t for t in user_bubbles), (
        f"{name}: the chat still displays text the model never received")
    assert any(result["model_input"] == t for t in user_bubbles)


def test_a_provider_failure_persists_nothing(popup, history_file):
    """The third writer, found by auditing every one rather than by report.

    `_on_ai_failure` receives only an error string, so it cannot know what the
    guard actually sent — and recording `_pending_prompt` there persisted the
    ORIGINAL of a prompt that had already been redacted on its way out.
    """
    popup.input_field.setEnabled(True)
    popup.input_field.setText(SENSITIVE)
    popup.send_message()
    popup._on_ai_failure("the provider exploded")

    written = history_file.read_text(encoding="utf-8") if history_file.exists() else ""
    assert SECRET_TOKEN not in written
    assert written.strip() in ("", "[]"), \
        "a turn that produced no answer still wrote a session"


def test_the_retry_reuses_the_refused_turns_bubble(popup):
    """Pins the fact the helper above relies on: the retry sends the same
    message again, it does not post a second one."""
    _send(popup, SENSITIVE, mode="block")
    popup.block_overlay.dismiss()
    before = len([b for b in popup._bubbles if b.is_user])

    _retry(popup, SENSITIVE)

    assert len([b for b in popup._bubbles if b.is_user]) == before, \
        "the retry posted the message a second time"


def test_the_retry_does_not_downgrade_enforcement_for_good(popup):
    """One click on a refusal card used to write guard_mode=redact to QSettings,
    silently running every future session in redact instead of block."""
    assert popup.settings.guard_mode() == "block"
    popup._pending_prompt = SENSITIVE
    popup._retry_redacted()

    assert popup.settings.guard_mode() == "block", \
        "a per-message retry rewrote the persistent enforcement setting"


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


# ══ 5a. the retry offer is per finding, not per byte ═══════════════════════
def test_the_retry_offer_asks_surviving_rules_not_did_the_text_change(monkeypatch):
    """#216's lesson, in the place it had not travelled to.

    "Did the text change" is satisfied by a neighbouring redaction that DID
    work: scrub an SSN sitting beside a finding that cannot be redacted and the
    bytes move, while the redact path still fail-closes and blocks. Offering the
    retry there is a dead-end loop that mints one more blocked event per click.
    """
    import foxy_guard
    from foxy_audit import policy
    prompt = "Email jane.doe@acme.co about invoice 55"

    # The text demonstrably changes, so the old per-byte test would say yes.
    assert policy.redact(prompt, "gdpr") != prompt
    assert foxy_guard.redaction_would_clear(prompt, "gdpr") is True

    # One finding survives redaction -> the retry would block again -> not offered.
    monkeypatch.setattr(policy, "surviving_rules",
                        lambda decision, redacted, tag: ["pii.presidio:date_time"])
    assert foxy_guard.redaction_would_clear(prompt, "gdpr") is False, \
        "the offer ignored what survived and only asked whether bytes moved"


def test_nothing_to_redact_is_not_offered_either(monkeypatch):
    import foxy_guard
    assert foxy_guard.redaction_would_clear("What is the capital of France?",
                                            "gdpr") is False


# ══ 5b. two questions, two settings ════════════════════════════════════════
def test_blocking_prompts_does_not_silently_block_answers(settings):
    """`response_scan` was derived from the prompt mode, so choosing "stop it
    before the model" also started discarding replies. Measured under the
    shipped gdpr default: an answer containing support@foxyaudit.tech was thrown
    away as response_pii.email."""
    import foxy_guard
    assert settings.guard_mode() == "block"
    assert settings.guard_response_scan() == "observe"

    foxy_guard.reset_clients()
    try:
        result = foxy_guard.run(
            "who do I contact about billing?",
            lambda t: "Write to support@foxyaudit.tech and they will help.",
            policy_tag=settings.guard_policy(), mode=settings.guard_mode(),
            response_scan=settings.guard_response_scan())
    finally:
        foxy_guard.reset_clients()

    assert result["decision"] != "response_blocked", \
        "blocking prompts silently discarded the answer too"
    assert "support@foxyaudit.tech" in result["response"], \
        "the answer was withheld from the person who asked for it"
    assert result["rules"], "the finding should still be recorded on the receipt"


def test_the_response_scan_still_blocks_when_asked_to(settings):
    """The other half: `block` must actually stop an answer."""
    import foxy_guard
    settings.set_guard_response_scan("block")
    foxy_guard.reset_clients()
    try:
        result = foxy_guard.run(
            "who do I contact?",
            lambda t: "Write to support@foxyaudit.tech and they will help.",
            policy_tag="gdpr", mode="block",
            response_scan=settings.guard_response_scan())
    finally:
        foxy_guard.reset_clients()

    assert result["decision"] == "response_blocked"
    assert result["stage"] == "response"
    assert result["llm_called"] is True


# ══ 5c. no fabricated activity in the console ══════════════════════════════
def test_a_keyless_turn_pings_nothing(monkeypatch):
    """The UDP ping adds a row to the Compliance Command Center's live table and
    bumps its total. With no key the event reaches NO ledger, so those rows were
    activity that never happened — and dashboard.py takes a max() of the polled
    total, so an inflated count never comes back down."""
    import foxy_guard
    pings: list = []
    monkeypatch.setattr(foxy_guard.foxy_audit.udp, "send_ping",
                        lambda payload, host=None, port=None: pings.append(payload))
    foxy_guard.reset_clients()
    try:
        foxy_guard.run("Patient SSN is 123-45-6789.", lambda t: "x",
                       policy_tag="gdpr", mode="block", api_key="")
        assert pings == [], "a keyless turn painted a row in the console"

        foxy_guard.run("Patient SSN is 123-45-6789.", lambda t: "x",
                       policy_tag="gdpr", mode="block",
                       api_key="foxy_sk_test_only", endpoint="http://127.0.0.1:8000")
        assert pings, "a keyed turn should still make the fox react"
    finally:
        foxy_guard.reset_clients()


# ══ 5d. the dependency that makes it all moot ══════════════════════════════
def _code_only(text: str) -> str:
    """The lines with their `#` comments removed.

    ⚠ A PLAIN SUBSTRING GREP DOES NOT WORK HERE, and this is the second time
    that has bitten in this repo. `assert "foxy-audit" in reqs` stayed green
    when the requirement was replaced by `# foxy-audit removed`: the mutation
    deleted the dependency and left the words behind, which is exactly what a
    real person does when they comment a line out.
    """
    return "\n".join(line.split("#", 1)[0] for line in text.splitlines())


def test_the_sdk_is_a_declared_desktop_dependency():
    """`foxy_guard` imports foxy_audit in a try/except and degrades to
    SDK_AVAILABLE = False — correct for a missing dependency, and the wrong
    thing to discover in a shipped build. A documented install brought the whole
    feature up dead with nothing noticing."""
    reqs = _code_only((HERE / "requirements.txt").read_text(encoding="utf-8"))
    declared = [line.strip() for line in reqs.splitlines()
                if line.strip().lower().replace("_", "-").startswith("foxy-audit")]
    assert declared, "the SDK is not a live requirement in desktop/requirements.txt"

    spec = _code_only((HERE / "omni_fox.spec").read_text(encoding="utf-8"))
    assert 'collect_all("foxy_audit")' in spec, \
        "the frozen build does not bundle the SDK, so the guard ships disabled"


# ══ 5e. the strip cannot advertise a policy that is not in force ═══════════
def test_both_doors_into_settings_refresh_the_strip(popup, monkeypatch):
    """The gear opens the dialog that now carries the guard controls, so it can
    leave the strip claiming a policy the next prompt will not be judged under."""
    import settings_dialog

    def change_it_and_close(self):
        self.settings.set_guard_policy("hipaa")
        return 0

    monkeypatch.setattr(settings_dialog.SettingsDialog, "exec", change_it_and_close)
    assert "gdpr" in popup.guard_strip.left.text()

    popup._open_settings()                       # the gear
    assert "hipaa" in popup.guard_strip.left.text(), \
        "the gear left the strip advertising the old policy"

    popup.settings.set_guard_policy("gdpr")
    popup._open_guard_settings()                 # the strip
    popup.settings.set_guard_policy("hipaa")
    popup._open_guard_settings()
    assert "hipaa" in popup.guard_strip.left.text()


def test_the_mock_placeholder_is_cleared_when_a_url_is_needed(app, settings):
    """Set on one branch only, "Runs in this app — no endpoint" stayed under an
    empty, required URL box after switching back."""
    import autostart as asm
    from settings_dialog import SettingsDialog
    # autostart= is not optional here, and an existing guard enforces it:
    # test_d13_companion_settings::test_no_test_in_this_tree_talks_to_the_real_login_items
    # walks every test file's AST for a SettingsDialog built without the seam,
    # because a bare one reads — and could write — the login items of whoever
    # runs the suite. It caught this test in the full run.
    dlg = SettingsDialog(settings, autostart=asm.Autostart(asm.MemoryBackend()))
    try:
        dlg._provider_combo.setCurrentIndex(
            [dlg._provider_combo.itemData(i)
             for i in range(dlg._provider_combo.count())].index("mock"))
        assert "no endpoint" in dlg._url_field.placeholderText()

        dlg._provider_combo.setCurrentIndex(
            [dlg._provider_combo.itemData(i)
             for i in range(dlg._provider_combo.count())].index("openai"))
        assert "no endpoint" not in dlg._url_field.placeholderText()
        assert dlg._url_field.isEnabled()
    finally:
        dlg.deleteLater()


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


def test_a_shipped_payload_carries_no_prompt_text(monkeypatch):
    """Content-blindness, measured on the real payload rather than asserted."""
    import foxy_guard
    captured: list = []
    # monkeypatch, not a hand-rolled save/restore: the first cut restored the
    # PRE-TEE submit and left `_TEE_INSTALLED` true, which disabled the wire tee
    # for the rest of the process and made every later "what left this machine"
    # assertion pass for the wrong reason. A test that disarms a later test is
    # worse than a missing test.
    monkeypatch.setattr(foxy_guard.dispatch, "submit",
                        lambda cfg, payload, wait=False: captured.append(payload))
    foxy_guard.reset_clients()
    try:
        prompt = "Patient Kowalczyk SSN 123-45-6789 needs escalation urgently"
        result = foxy_guard.run(prompt, lambda t: "ok", policy_tag="hipaa",
                                mode="block", api_key="foxy_sk_test_only",
                                endpoint="http://127.0.0.1:8000")
    finally:
        foxy_guard.reset_clients()

    assert captured, "nothing was shipped, so this proves nothing"
    body = json.dumps(captured[-1], sort_keys=True)
    from guard_widgets import leaked_words
    assert leaked_words(prompt, body) == [], "prompt text left the machine"
    assert result["prompt_hash"], "no commitment was recorded"


def test_the_wire_tee_survives_a_test_that_replaced_submit():
    """The tee reinstalls itself over whatever it finds.

    Re-broken by restoring the flag check (`if _TEE_INSTALLED: return`): this
    then fails, because the previous test left a foreign `submit` in place.
    """
    import foxy_guard
    foxy_guard.dispatch.submit = _plain_submit          # something that is not ours
    foxy_guard.install_tee()
    assert getattr(foxy_guard.dispatch.submit, "_foxy_tee", False), \
        "the tee did not reinstall over a replaced submit"


def _plain_submit(cfg, payload, wait=False):
    return None


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
