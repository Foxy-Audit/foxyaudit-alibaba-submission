"""The fox reacting to a block that happened in somebody else's application.

The guard does not run here. It runs inside the customer's process, and when it
refuses a prompt the SDK fires a loopback datagram at 127.0.0.1:9999. What this
file guards is the desktop side of that:

  1. the card is complete from the SDK's four ping fields ALONE — a customer
     sends nothing richer, and no sentence on it may depend on one that does
  2. a prompt block and a response block and a truncation are three different
     statements about egress
  3. the optional richer payload only ever ADDS
  4. a loopback ping never claims a ledger entry that does not exist
  5. the wake probe can actually tell a live listener from a free port
"""

from __future__ import annotations

import json
import socket
import sys
from pathlib import Path

import pytest
from PyQt6.QtCore import Qt
from PyQt6.QtWidgets import QApplication, QWidget

HERE = Path(__file__).resolve().parent
REPO = HERE.parent

#: Exactly what `sdk/src/foxy_audit/client.py` puts on the wire for a block.
#: Copied from the source rather than invented, and deliberately NOT extended:
#: every test below that renders a card renders it from this and nothing else.
SDK_PING = {
    "event": "policy_breach",
    "policy": "hipaa",
    "reason": "phi",
    "rules": ["phi.ssn_pattern"],
    "decision": "blocked",
    "ts": 1786900000.0,
}


@pytest.fixture(scope="module")
def app():
    return QApplication.instance() or QApplication([])


@pytest.fixture()
def alert(app):
    from guard_widgets import BlockAlert
    widget = BlockAlert()
    yield widget
    widget.close()
    widget.deleteLater()


# ══ 1. the card is complete from the SDK's own ping ═════════════════════════
def test_the_card_needs_nothing_the_sdk_does_not_send(alert):
    alert.show_for(dict(SDK_PING))

    assert alert.isVisible()
    assert alert.title.text() == "Blocked before the model saw it."
    body = alert.body.text()
    assert "protected health information" in body, body
    assert "hipaa" in body
    assert "phi.ssn_pattern" in alert.ev_rules.text()
    # No receipt yet: nothing richer has arrived, and the card does not pretend.
    assert alert._receipt is None


def test_an_unknown_reason_label_still_reads_as_a_sentence(alert):
    """`reason` is a free label from the SDK's own table; a future one must not
    render as a hole in the middle of the card."""
    alert.show_for(dict(SDK_PING, reason="some_new_family"))
    assert "some new family" in alert.body.text()


def test_the_card_does_not_claim_the_prompt_reached_us(alert):
    """Content-blindness across the loopback: the ping carries no text, and the
    card must not imply the desktop app has any."""
    alert.show_for(dict(SDK_PING))
    shown = " ".join([alert.title.text(), alert.body.text(), alert.ev_rules.text()])
    assert "123-45-6789" not in shown
    assert "prompt text never left" in alert.body.text()


# ══ 2. three decisions, three statements about egress ══════════════════════
@pytest.mark.parametrize("decision,title,must_say,must_not_say", [
    ("blocked", "Blocked before the model saw it.",
     "never called", "did reach the model"),
    ("blocked_response", "Blocked on the way back.",
     "did reach the model", "never called"),
    ("response_truncated", "Cut off on the way back.",
     "already been streamed", "never called"),
])
def test_each_decision_gets_its_own_sentence(alert, decision, title,
                                             must_say, must_not_say):
    """⚠ The SDK's spellings, from client.py: a response block is
    `blocked_response`, NOT `response_blocked`, and a truncation is its own
    outcome because part of the answer did reach the caller."""
    alert.show_for(dict(SDK_PING, decision=decision))

    assert alert.title.text() == title
    assert must_say in alert.body.text(), alert.body.text()
    assert must_not_say not in alert.body.text(), alert.body.text()


def test_prevention_is_claimed_only_when_nothing_was_delivered(alert):
    from guard_widgets import stage_of
    assert stage_of({"decision": "blocked"}) == "prompt"
    assert stage_of({"decision": "blocked_response"}) == "response"
    assert stage_of({"decision": "response_truncated"}) == "truncated"


# ══ 3. the richer payload only ever adds ═══════════════════════════════════
RICH = dict(SDK_PING, event="policy_breach_detail", mode="block",
            signals=["ssn_pattern"], prompt_hash="a" * 64, response_hash="b" * 64,
            llm_called=False, ruleset_version="2026.08.3", sdk_version="1.10.0",
            shipped=False, app="mock_llm demo")


def test_detail_attaches_a_receipt_to_the_card_on_screen(alert):
    alert.show_for(dict(SDK_PING))
    assert alert.attach_detail(dict(RICH)) is True

    assert alert._receipt is not None
    rows = dict(alert._receipt.rows)
    assert rows["prompt_hash"] == "a" * 64
    assert rows["llm called?"].startswith("NO")
    assert "2026.08.3" in rows["ruleset"]


def test_detail_without_a_card_changes_nothing(alert):
    """The follow-up must never open a card on its own — if the ping was lost,
    a receipt with no refusal in front of it is a claim with no event."""
    assert alert.attach_detail(dict(RICH)) is False
    assert not alert.isVisible()


def test_a_second_block_drops_the_previous_receipt(alert):
    alert.show_for(dict(SDK_PING))
    alert.attach_detail(dict(RICH))
    alert.show_for(dict(SDK_PING, reason="secret_key"))

    assert alert._receipt is None, \
        "the new refusal is showing the previous one's evidence"


def test_a_thin_payload_renders_no_empty_evidence_rows():
    """A row per missing field would read as "the commitment is empty", which is
    a different and untrue statement from "this sender did not tell us"."""
    from guard_widgets import GuardReceipt
    rows = dict(GuardReceipt.build_rows(dict(SDK_PING)))

    assert "prompt_hash" not in rows
    assert "llm called?" not in rows
    assert rows["rules"] == "phi.ssn_pattern"


def test_the_egress_line_does_not_say_the_opposite_of_the_truth():
    from guard_widgets import GuardReceipt
    local = dict(GuardReceipt.build_rows(dict(RICH, shipped=False)))
    shipped = dict(GuardReceipt.build_rows(dict(RICH, shipped=True)))

    assert "nothing" in local["what left this machine"]
    assert "nothing" not in shipped["what left this machine"]
    assert "prompt text stayed put" in shipped["what left this machine"]


# ══ 4. a ping never claims a ledger entry ══════════════════════════════════
@pytest.fixture()
def console(app, tmp_path):
    from PyQt6.QtCore import QSettings
    from dashboard import DashboardWindow
    from fox_settings import FoxSettings
    from foxy_client import MemorySecretStore
    store = QSettings(str(tmp_path / "c.ini"), QSettings.Format.IniFormat)
    win = DashboardWindow(settings=FoxSettings(store, MemorySecretStore()))
    yield win
    win.close()
    win.deleteLater()


def test_a_loopback_ping_does_not_inflate_the_ledger_count(console):
    """The hero number reads as interactions recorded in the ledger. A keyless
    guard reaches no ledger at all, and the poll takes max(), so an inflated
    figure never comes back down."""
    before = console._logs_total

    console.on_policy_breach(dict(SDK_PING))
    console.on_hash_ok({"policy": "hipaa", "tokens": 12})

    assert console._logs_total == before, \
        "a loopback ping claimed rows in the chain"
    assert console._flagged_total == 1, \
        "a block that really happened should still count as stopped"


def test_the_row_says_it_is_not_evidence_yet(console):
    console.on_policy_breach(dict(SDK_PING))

    assert console.table.rowCount() == 1
    hash_cell = console.table.item(0, 2).text()
    assert "local only" in hash_cell, hash_cell
    assert "not in the ledger" in hash_cell


def test_a_backend_row_still_shows_its_chain_hash(console):
    """The marker must not swallow the real thing: rows from /v1/logs carry a
    chain hash and have to keep showing it."""
    console.table.add_event({"time": "10:00:00", "policy": "hipaa",
                             "hash": "c" * 40, "tokens": 5, "risk": None,
                             "kind": "ok"})
    assert console.table.item(0, 2).text().startswith("cccc")


# ══ 5. the wake probe ══════════════════════════════════════════════════════
def test_the_probe_sees_a_listener_that_sets_so_reuseaddr():
    """⚠ THE PROBE MUST NOT SET SO_REUSEADDR ITSELF. sdk_bridge binds WITH it,
    and a second socket that also sets it binds the same port happily —
    measured: the probe succeeded while the listener was live, so a
    reuse-flagged probe would report "nobody home" every time and start a
    second fox on top of the running one."""
    import foxy_wake
    port = 59999
    assert foxy_wake.is_listening(port=port) is False

    listener = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    listener.bind(("127.0.0.1", port))
    try:
        assert foxy_wake.is_listening(port=port) is True, \
            "the probe cannot see a listener that asked for address reuse"
    finally:
        listener.close()

    assert foxy_wake.is_listening(port=port) is False


def test_a_live_listener_is_never_started_over():
    import foxy_wake
    port = 59998
    listener = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    listener.bind(("127.0.0.1", port))
    launched = []
    try:
        state = foxy_wake.ensure_awake(port=port,
                                       launcher=lambda cmd: launched.append(cmd))
    finally:
        listener.close()

    assert state == "already"
    assert launched == [], "a second fox was started on top of the running one"


def test_a_failed_launch_is_a_state_not_an_exception():
    """This runs inside a guard path. A desktop app that will not start is a
    cosmetic loss and must never become an exception in somebody's request."""
    import foxy_wake
    state = foxy_wake.ensure_awake(port=59997, timeout=0.1,
                                   launcher=lambda cmd: False)
    assert state == "failed"
    assert foxy_wake.EXPLANATION[state]


def test_a_launch_that_never_binds_times_out():
    import foxy_wake
    state = foxy_wake.ensure_awake(port=59996, timeout=0.4,
                                   launcher=lambda cmd: True)
    assert state == "timeout"
    assert foxy_wake.EXPLANATION[state]


def test_the_wake_starts_what_login_would_have_started():
    """One answer to "how is the fox started", not two that can disagree."""
    import autostart
    import foxy_wake
    assert foxy_wake.app_command() == list(autostart.launch_command())


# ══ 6. the bridge routes both events ═══════════════════════════════════════
def test_the_listener_routes_the_ping_and_the_detail_separately(app):
    from sdk_bridge import SDKBridgeListener
    listener = SDKBridgeListener()
    breaches, details = [], []
    listener.policy_breach.connect(breaches.append)
    listener.breach_detail.connect(details.append)

    listener._process_packet(json.dumps(SDK_PING).encode())
    listener._process_packet(json.dumps(RICH).encode())
    listener._process_packet(b"{ not json")
    listener._process_packet(json.dumps({"event": "who_knows"}).encode())

    assert len(breaches) == 1 and breaches[0]["reason"] == "phi"
    assert len(details) == 1 and details[0]["prompt_hash"] == "a" * 64


# ══ 6b. the app itself wires it, not just this test ════════════════════════
def _connect_targets(func, signal_owner, signal):
    """Every `self.<owner>.<signal>.connect(X)` inside ONE function node.

    Parsed, not grepped, and scoped to the function's own AST node — a text
    window around a match keeps getting satisfied by the neighbouring function,
    which this repo has been bitten by more than once.
    """
    import ast
    found = []
    for node in ast.walk(func):
        if not (isinstance(node, ast.Call)
                and isinstance(node.func, ast.Attribute)
                and node.func.attr == "connect"):
            continue
        sig = node.func.value
        if (isinstance(sig, ast.Attribute) and sig.attr == signal
                and isinstance(sig.value, ast.Attribute)
                and sig.value.attr == signal_owner):
            for arg in node.args:
                found.append(getattr(arg, "attr", None) or getattr(arg, "id", None))
    return found


def _fox_init():
    import ast
    tree = ast.parse((HERE / "omni_fox.py").read_text(encoding="utf-8"))
    for cls in [n for n in ast.walk(tree) if isinstance(n, ast.ClassDef)]:
        for fn in cls.body:
            if isinstance(fn, ast.FunctionDef) and fn.name == "__init__":
                if _connect_targets(fn, "sdk_bridge", "policy_breach"):
                    return fn
    raise AssertionError("no __init__ connects sdk_bridge.policy_breach at all")


def test_the_app_raises_the_card_on_a_breach_ping():
    """The wiring in the shipped class, not only in this file's fixtures."""
    assert "_show_block_alert" in _connect_targets(_fox_init(), "sdk_bridge",
                                                   "policy_breach")


def test_the_app_routes_the_richer_payload_too():
    assert "_on_breach_detail" in _connect_targets(_fox_init(), "sdk_bridge",
                                                   "breach_detail")


def test_one_refusal_does_not_open_two_windows():
    """Observed in the real run: the card AND the chat popup both came up for a
    single block — "Foxy Audit — prompt blocked" and "Foxy Audit — Copilot"
    side by side. The bubble is still written either way; only the automatic
    open is suppressed, and only while the card is actually showing."""
    import ast
    src = (HERE / "omni_fox.py").read_text(encoding="utf-8")
    tree = ast.parse(src)
    fn = next(n for n in ast.walk(tree)
              if isinstance(n, ast.FunctionDef) and n.name == "_on_policy_breach")

    # The guard must sit BEFORE the open_chat call, inside this function.
    body = ast.unparse(fn)
    assert "block_alert" in body, "nothing checks whether the card is up"
    assert body.index("isVisible") < body.index("open_chat"), \
        "the chat opens before anything checks for the card"
    # …and the bubble must still be written, so the detail is not lost.
    assert "_add_bubble" in body


def test_the_flash_survived_the_card():
    """The card is an addition. The fox's own reaction — and the console row —
    must still be connected, or a nicer popup will have quietly replaced them."""
    targets = _connect_targets(_fox_init(), "sdk_bridge", "policy_breach")
    assert "_on_policy_breach" in targets, \
        "the companion reaction (flash, toast, tally) was dropped"


# ══ 7. the demo sends no content over the loopback ═════════════════════════
def _demo():
    """Import demo/mock_llm.py fresh — it builds its client AT IMPORT."""
    import importlib
    sys.path.insert(0, str(REPO / "demo"))
    try:
        sys.modules.pop("mock_llm", None)
        return importlib.import_module("mock_llm")
    except Exception:                       # noqa: BLE001 — demo/ absent
        pytest.skip("demo/ is not importable here")
    finally:
        sys.path.remove(str(REPO / "demo"))


def test_a_block_in_the_demo_actually_reaches_the_loopback():
    """⚠ THE FLAG THE WHOLE FEATURE HANGS ON. `desktop_ping=False` in the demo
    meant the SDK's block ping never left the process, so the fox never reacted
    and every surface downstream of it was unreachable. Asserted by RUNNING a
    blocked prompt and counting datagrams, not by reading the constructor:
    the flag is a means, and what matters is that something arrives.
    """
    demo = _demo()
    assert demo.foxy.cfg.desktop_ping is True, "the demo does not ping the fox"

    sent = []
    from foxy_audit import udp
    original = udp.send_ping
    udp.send_ping = lambda payload, host=None, port=None: sent.append(payload)
    try:
        result = demo.guarded_call(
            "Patient SSN is 123-45-6789, DOB 1980-01-01.", "hipaa", "block")
    finally:
        udp.send_ping = original
        sys.modules.pop("mock_llm", None)

    assert result["decision"] == "blocked"
    events = [p.get("event") for p in sent]
    assert "policy_breach" in events, \
        "the SDK's own block ping never left the demo process"
    assert "policy_breach_detail" in events, \
        "the demo did not follow up with the read-out it already holds"


def test_the_demo_detail_carries_no_prompt_or_response_text():
    """The datagram never leaves the machine, which is not a licence to put a
    prompt on it: the desktop app has no business holding text either."""
    sys.path.insert(0, str(REPO / "demo"))
    try:
        import importlib
        sys.modules.pop("mock_llm", None)
        demo = importlib.import_module("mock_llm")
    except Exception:                       # noqa: BLE001 — demo/ absent
        pytest.skip("demo/ is not importable here")
    finally:
        sys.path.remove(str(REPO / "demo"))

    sent = []
    from foxy_audit import udp
    original = udp.send_ping
    udp.send_ping = lambda payload, host=None, port=None: sent.append(payload)
    try:
        demo._ping_detail({
            "policy": "hipaa", "mode": "block", "decision": "blocked",
            "reason": "phi", "rules": ["phi.ssn_pattern"], "signals": ["ssn_pattern"],
            "prompt_hash": "a" * 64, "response_hash": "b" * 64, "llm_called": False,
            "response": "the model's answer", "model_input": "Patient SSN 123-45-6789",
        })
    finally:
        udp.send_ping = original
        sys.modules.pop("mock_llm", None)

    assert sent, "no detail datagram was sent"
    body = json.dumps(sent[-1])
    assert "123-45-6789" not in body
    assert "model_input" not in body and "response" not in sent[-1]
    assert sent[-1]["prompt_hash"] == "a" * 64
    assert sent[-1]["event"] == "policy_breach_detail"
