"""
Foxy Audit desktop — the preflight guard, in front of the chat.
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
The chat popup called `ai_providers.call_ai()` directly: no policy, no
commitment, no evidence. The one surface carrying the fox's face was the one
place the product did not run.

This module is the bridge. It runs the REAL SDK — `policy.evaluate` for the
read-out, `@foxy.audit` for the decision — around whatever callable the chat
hands it, and returns a plain dict the UI renders and never second-guesses.

    result = foxy_guard.run(prompt, call_model, policy_tag="hipaa", mode="block")

The field names are `demo/mock_llm.py`'s `guarded_call()` verbatim, plus
`stage`, `sdk_version`, `ruleset_version`, `shipped` and `wire`. That is
deliberate: the terminal demo and this window show the same fields because they
read the same names out of the same SDK, not because two surfaces were kept in
step by hand.

⚠ NOTHING IN THIS MODULE IMPORTS Qt, and nothing in it may. It is imported by
the popup, by tests, and (in principle) by a headless caller; the moment it
touches QFontDatabase it can only run after a QApplication exists. That mistake
has already been made once on this feature and it segfaulted at launch.

⚠ CONTENT-BLINDNESS IS THE POINT. Nothing here logs, stores or transmits the
prompt. `wire` is the payload captured AT `dispatch.submit` — the actual
boundary — so the UI can show what left the machine instead of asserting it.

⚠ NO SDK IS A STATE, NOT A CRASH. If `foxy_audit` cannot be imported the chat
still works and every result says `decision="unguarded"`. It must never look
protected when it is not.
"""

from __future__ import annotations

import os
import threading

try:
    import foxy_audit
    from foxy_audit import (FoxyClient, FoxyPolicyBlocked, FoxyResponseBlocked,
                            dispatch, hashing, policy, response_policy, ruleset)
    SDK_AVAILABLE = True
    IMPORT_ERROR = ""
except Exception as exc:                    # noqa: BLE001 — any import failure
    SDK_AVAILABLE = False
    IMPORT_ERROR = f"{type(exc).__name__}: {exc}"


#: The tags this chat offers. CHOSEN BY THE CUSTOMER, NEVER GUESSED — and that
#: is a measured decision, not caution:
#:
#:     policy.evaluate("Email jane.doe@acme.co …", "hipaa")
#:         rules=['phi.email', 'phi.ip_address']  signals=['email', 'ip_address']
#:     policy.evaluate("Email jane.doe@acme.co …", "gdpr")
#:         rules=['pii.email', 'pii.ip_address']  signals=['email', 'ip_address']
#:
#: hipaa and gdpr run THE SAME DETECTOR (`policy._POLICY_EXTRA` maps both onto
#: `pii.detect_pii`) and differ only in the label they file the finding under.
#: The signals are byte-identical. So no amount of looking at the prompt can
#: tell which one is right: whether an email address is protected health
#: information or ordinary personal data is a fact about the ORGANISATION, not
#: about the text.
#:
#: `demo/mock_llm.py` guesses — hipaa, then default — and therefore labels every
#: email address `phi`. Its own `pii` scenario has to name gdpr by hand to get
#: the right answer. Adding gdpr to that list does NOT fix it, because hipaa
#: still matches first; the fix is to stop guessing. A GDPR finding filed as
#: protected health information is a mislabelled compliance record — the
#: Compliance Passport groups its statistics by policy_tag.
POLICY_TAGS = ("default", "soc2", "gdpr", "hipaa")

#: What each tag adds, in the words the settings panel shows.
POLICY_BLURB = {
    "default": "prompt-injection and secrets",
    "soc2":    "prompt-injection and secrets",
    "gdpr":    "the above, plus personal data (labelled pii)",
    "hipaa":   "the above, plus personal data (labelled phi)",
}

GUARD_MODES = ("observe", "block", "redact")

DEFAULT_ENDPOINT = "https://app.foxyaudit.tech"


def _state_dir() -> str:
    d = os.path.join(os.path.expanduser("~"), ".foxy_audit")
    try:
        os.makedirs(d, exist_ok=True)
    except OSError:
        pass
    return d


def spool_path() -> str:
    """The chat's OWN spool, and that is not tidiness.

    The default spool (`~/.foxy-audit`) is shared and DURABLE by design, so
    whatever one process leaves undelivered is flushed by the next process to
    construct a client. `demo/mock_llm.py` carries the scar in a comment: an
    offline run posted the leftovers of a live one.
    """
    return os.path.join(_state_dir(), "desktop-chat-spool.sqlite3")


# ── what actually leaves the machine ────────────────────────────────────────
# Captured at dispatch.submit, which is the real boundary: everything above it
# has the prompt, nothing below it does. Showing the captured payload is not a
# description of content-blindness, it is the evidence for it.
_WIRE: list = []
_WIRE_LOCK = threading.Lock()
_TEE_INSTALLED = False


def install_tee() -> None:
    """Tee `dispatch.submit` so `run()` can report the bytes. Idempotent.

    Called from `run()` itself rather than from any one caller's setup: a
    window opened by a different code path would otherwise report "nothing left
    this machine" while events were shipping, and a surface that under-reports
    egress is worse than one that shows none.
    """
    global _TEE_INSTALLED
    if _TEE_INSTALLED or not SDK_AVAILABLE:
        return
    original = dispatch.submit

    def submit(cfg, payload, wait=False):
        with _WIRE_LOCK:
            _WIRE.append(payload)
        return original(cfg, payload, wait=wait)

    dispatch.submit = submit
    _TEE_INSTALLED = True


# ── the client ──────────────────────────────────────────────────────────────
_CLIENTS: dict = {}
_CLIENT_LOCK = threading.Lock()


def _client(api_key: str, endpoint: str, mode: str):
    """One client per (key, endpoint, response_scan), built once and reused.

    `response_scan` is a CLIENT setting with no per-decorator override — the SDK
    chose that because a response block raises into the caller and should be a
    deployment decision. Here the mode switch IS the deployment, so the cache is
    keyed by it and `block` turns the response scan on with it. Without that,
    a response could never be stopped and the "Blocked on the way back" state
    would be unreachable.

    ⚠ `api_key or ""`, never None. `FoxyConfig.resolve` reads $FOXY_API_KEY when
    api_key is None, so a developer with that variable exported would have this
    chat shipping while the UI said "local only". Same defect as the one fixed
    in demo/mock_llm.py.
    """
    scan = "block" if mode == "block" else "observe"
    cache_key = (api_key, endpoint, scan)
    with _CLIENT_LOCK:
        client = _CLIENTS.get(cache_key)
        if client is None:
            client = FoxyClient(
                api_key=api_key or "",
                endpoint=endpoint or DEFAULT_ENDPOINT,
                spool_path=spool_path(),
                response_scan=scan,
                # ON, and the point of it: a block emits {"event":
                # "policy_breach"} to 127.0.0.1:9999, where this app's own
                # sdk_bridge listener is already waiting and the fox already
                # answers with SecurityOverlay.flash_red().
                desktop_ping=True,
            )
            _CLIENTS[cache_key] = client
    return client


def reset_clients() -> None:
    """Drop the client cache — a key or endpoint changed, or a test wants a
    clean one."""
    with _CLIENT_LOCK:
        _CLIENTS.clear()


# ── policy selection ────────────────────────────────────────────────────────
# There is deliberately no `choose_policy(prompt)` here. See POLICY_TAGS above:
# a heuristic cannot distinguish the two tags that matter, and one that appears
# to is worse than none, because it produces a confident wrong label on every
# row it touches.


def would_redaction_change(prompt: str, policy_tag: str) -> bool:
    """True when `redact` mode would actually scrub something out of this prompt.

    The overlay offers "Retry with redaction" only when the answer is yes. An
    action that provably changes nothing is a worse dead end than none.
    """
    if not SDK_AVAILABLE:
        return False
    try:
        return policy.redact(prompt, policy_tag) != prompt
    except Exception:                       # noqa: BLE001
        return False


def ruleset_version() -> str:
    if not SDK_AVAILABLE:
        return ""
    try:
        return str(ruleset.provenance().get("ruleset_version", ""))
    except Exception:                       # noqa: BLE001
        return ""


def sdk_version() -> str:
    return getattr(foxy_audit, "__version__", "") if SDK_AVAILABLE else ""


# ── the run ─────────────────────────────────────────────────────────────────
def _display_hashes(client, prompt: str, response: str):
    """Reproduce the SDK's commitments for display, with the SDK's own
    functions. Identical to what the event carries as long as no salt sidecar is
    configured, which this chat does not configure — and when a payload WAS
    shipped, `run()` prefers the hashes out of that payload, because the shipped
    value beats any re-derivation of it."""
    cfg = client.cfg
    key = cfg.commitment_key or cfg.api_key
    if key:
        return (hashing.commitment_hex(prompt, key),
                hashing.commitment_hex(response, key))
    return (hashing.sha256_hex(hashing.canonical_json(prompt)),
            hashing.sha256_hex(hashing.canonical_json(response)))


def _merge(first, second) -> list:
    out = list(first)
    out.extend(item for item in second if item not in out)
    return out


def run(prompt: str, call_model, *, policy_tag: str = "default",
        mode: str = "block", api_key: str = "", endpoint: str = "",
        agent: str | None = None) -> dict:
    """Run `call_model` behind the guard and report everything that happened.

    `call_model(text) -> str` receives whatever the guard decided the model may
    see — the original prompt under observe/block, the scrubbed one under
    redact — and is NOT called at all when the prompt is blocked.
    """
    if not SDK_AVAILABLE:
        # Unguarded, and it says so. The chat still answers.
        return _result(policy="", mode=mode, decision="unguarded",
                       reason="guard unavailable", llm_called=True,
                       response=call_model(prompt), model_input=prompt)

    install_tee()
    client = _client(api_key, endpoint, mode)
    seen: dict = {}

    @client.audit(policy=policy_tag, mode=mode, agent=agent)
    def _guarded(text: str) -> str:
        # What the model actually received — the redacted text on the redact
        # path. Captured here because this is the only place it exists.
        seen["model_input"] = text
        answer = call_model(text)
        seen["response"] = answer
        return answer

    prompt_decision = policy.evaluate(prompt, policy_tag)

    with _WIRE_LOCK:
        wire_mark = len(_WIRE)

    stage = None
    response = ""
    try:
        response = _guarded(prompt)
    except FoxyPolicyBlocked:
        # The wrapped function never ran. Nothing produced, nothing sent.
        stage = "prompt"
    except FoxyResponseBlocked:
        # ⚠ NOT THE SAME EVENT. The function DID run, the prompt DID reach the
        # provider, and tokens were spent — the SDK keeps these two exceptions
        # unrelated by inheritance precisely so this distinction cannot be lost.
        stage = "response"

    llm_called = "response" in seen
    model_output = seen.get("response", "")

    # The response is scanned for the read-out even when nothing blocked, so an
    # observe-mode turn shows its findings instead of a blank row.
    response_decision = None
    if llm_called:
        try:
            response_decision = response_policy.evaluate_response(model_output, policy_tag)
        except Exception:                   # noqa: BLE001 — display only
            response_decision = None

    rules = _merge(prompt_decision.rules,
                   response_decision.rules if response_decision else [])
    signals = _merge(prompt_decision.signals,
                     response_decision.signals if response_decision else [])

    if stage == "prompt":
        decision, committed = "blocked", ""
    elif stage == "response":
        # What was DELIVERED. On a non-streamed block that is the whole
        # response — see FoxyResponseBlocked's own docstring.
        decision, committed = "response_blocked", model_output
    elif mode == "redact" and prompt_decision.triggered:
        decision, committed = "redacted", response
    elif rules:
        decision, committed = "flagged", response      # recorded, not stopped
    else:
        decision, committed = "allowed", response

    if stage == "response" and response_decision is not None:
        reason = response_decision.reason
    elif prompt_decision.triggered:
        reason = prompt_decision.reason
    elif response_decision is not None and response_decision.triggered:
        reason = response_decision.reason
    else:
        reason = "none"

    prompt_hash, response_hash = _display_hashes(client, prompt, committed)

    with _WIRE_LOCK:
        shipped = _WIRE[wire_mark:]
    payload = shipped[-1] if shipped else None
    if payload:
        prompt_hash = payload.get("prompt_hash", prompt_hash)
        response_hash = payload.get("response_hash", response_hash)

    return _result(
        policy=policy_tag, mode=mode, decision=decision, rules=rules,
        signals=signals, reason=reason, prompt_hash=prompt_hash,
        response_hash=response_hash, llm_called=llm_called,
        response=("" if stage else response), model_input=seen.get("model_input", ""),
        stage=stage, shipped=bool(payload), wire=payload,
    )


def blocked(result: dict) -> bool:
    """One place decides what counts as a refusal, so no caller invents its own."""
    return result.get("decision") in ("blocked", "response_blocked")


def _result(**kw) -> dict:
    """Every key the UI may read, always present — a missing key is a crash in
    a renderer, and a renderer is the worst place to discover one."""
    base = {
        "policy": "", "mode": "observe", "decision": "allowed", "rules": [],
        "signals": [], "reason": "none", "prompt_hash": "", "response_hash": "",
        "llm_called": False, "response": "", "model_input": "", "stage": None,
        "shipped": False, "wire": None,
    }
    base.update(kw)
    base["sdk_version"] = sdk_version()
    base["ruleset_version"] = ruleset_version()
    return base
