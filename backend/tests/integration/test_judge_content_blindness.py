"""Nothing a caller can put in `event_metadata` reaches a judge provider (S12).

THE PROPERTY IS ASSERTED AGAINST THE BYTES EACH PROVIDER IS ACTUALLY HANDED,
not against the projection helper. An earlier version of this guard called
``openai_judge._content_blind_meta`` directly and was green while the property
was FALSE for the default provider: ``gemini.evaluate`` did ``json.dumps(meta)``
verbatim, so the whole ``event_metadata`` dict — every key ingest accepts — went
to Google in the request body. A helper that projects correctly proves nothing
about a caller that never calls it.

Why S12 made this urgent rather than merely untidy: `policy_tag_raw` is the
FIRST CALLER-CONTROLLED FREE-TEXT value in `event_metadata`. Every other key is
bounded vocabulary — rule ids, signal labels, a version string, a hex digest —
but `policy=` accepts any runtime string, so `policy=f"hipaa-{patient_id}"`
would have put a patient id in a third party's request body. Content-blindness
is the one rule this product cannot bend.

Both judges are driven through ``worker._judge_verdict``: the place the
projection now happens, and the only place either provider is called.
"""

from __future__ import annotations

import json
import sys
import types

import pytest

from app import judge_routing, openai_judge, worker

# A patient identifier smuggled in through the decorator's `policy=` argument.
# If this string appears in a provider request body, the product's central
# promise is broken.
PATIENT_ID = "MRN-4417829"
RAW_TAG = f"hipaa-{PATIENT_ID}"

_CLEAN_VERDICT = {"policy_breach": False, "reason": "nothing of note",
                  "risk_score": 0, "decision": "clean", "rules": []}


def _meta():
    """Exactly the dict ``worker._grade_one`` builds, for a judged row."""
    return {
        "prompt_hash": "a" * 64,
        "response_hash": "c" * 64,
        "token_count": 42,
        "policy_tag": "hipaa",
        "pii_signals": ["phi"],
        "event_id": "6f1a0e64-1f1a-4c39-9a1e-2b7d4c9f0011",
        "event_type": "interaction",
        "commitment_alg": "hmac-sha256",
        "event_metadata": {
            # the leak vector
            "policy_tag_raw": RAW_TAG,
            # ledger bookkeeping a provider has no reason to hold
            "policy_rules": ["phi.ssn_pattern"],
            "ruleset_version": "2026.08.4",
            "ruleset_hash": "b" * 64,
            # a SAFE key, so a projection that simply empties the dict cannot
            # pass the guard below by accident
            "model": "gpt-5.6",
        },
    }


@pytest.fixture
def sent(monkeypatch):
    """Capture the request body each provider is handed. No network either way."""
    captured: dict[str, str] = {}

    # ── gemini: google.generativeai, imported inside gemini.evaluate ──────────
    # A STAND-IN OBJECT IN sys.modules, never the real package — the same shape
    # as test_judge_model_selection._FakeGenAI, and deliberately so.
    #
    # An earlier version of this fixture used pytest.importorskip, and that one
    # line broke three tests in that file. `import google.generativeai as genai`
    # resolves getattr(google, "generativeai") FIRST and only falls back to
    # sys.modules on AttributeError. Nothing in this suite imports the package
    # for real, so that attribute does not exist and every fake lands via the
    # fallback — until importorskip imports it for real, sets the attribute on
    # the parent package, and every sys.modules fake in the session is silently
    # bypassed. Those tests then made live network calls to Google.
    #
    # So: no real import, and the parent attribute is stubbed too if some future
    # test does import it, which keeps this fixture correct in either order.
    class _FakeGenAI:
        def __init__(self):
            self.model_id = None

        def configure(self, api_key=None, **_kw):
            pass

        def GenerativeModel(self, model_id, *_a, **_kw):  # noqa: N802 — SDK's name
            self.model_id = model_id
            return types.SimpleNamespace(
                generate_content=lambda contents, **_kwargs: (
                    captured.__setitem__("gemini", contents),
                    types.SimpleNamespace(text=json.dumps(_CLEAN_VERDICT)),
                )[1])

    fake_genai = _FakeGenAI()
    monkeypatch.setitem(sys.modules, "google.generativeai", fake_genai)
    google_pkg = sys.modules.get("google")
    if google_pkg is not None:
        monkeypatch.setattr(google_pkg, "generativeai", fake_genai, raising=False)

    # ── openai: urllib, so capture the Request's own bytes ────────────────────
    class _FakeResponse:
        def __enter__(self):
            return self

        def __exit__(self, *exc):
            return False

        def read(self):
            return json.dumps({"output_text": json.dumps(_CLEAN_VERDICT)}).encode()

    def _fake_urlopen(request, timeout=None):
        captured["openai"] = request.data.decode("utf-8")
        return _FakeResponse()

    monkeypatch.setattr(openai_judge.urllib_request, "urlopen", _fake_urlopen)
    return captured


def _drive_both(monkeypatch, meta):
    """Run one grading through the real boundary with BOTH providers routed on."""
    routing = judge_routing.JudgeRouting(
        provider="both", key_mode="own",
        gemini_key="test-gemini-key", openai_key="test-openai-key",
        gemini_model="gemini-2.5-flash", openai_model="gpt-5.6",
    )
    monkeypatch.setattr(judge_routing, "resolve_judge_routing",
                        lambda db, org_id: routing)
    return worker._judge_verdict(None, "6f1a0e64-1f1a-4c39-9a1e-2b7d4c9f0012",
                                 meta, None, {})


def test_both_providers_are_really_driven(sent, monkeypatch):
    """The guards below assert about two request bodies — so first prove two
    request bodies exist. Without this, a routing change that quietly stopped
    calling a provider would make every absence assertion pass vacuously."""
    _drive_both(monkeypatch, _meta())
    assert set(sent) == {"gemini", "openai"}, sent
    assert sent["gemini"] and sent["openai"]


@pytest.mark.parametrize("provider", ["gemini", "openai"])
def test_the_typed_tag_never_reaches_a_provider(sent, monkeypatch, provider):
    """THE GUARD. The caller's free text is not in the bytes sent to either one."""
    _drive_both(monkeypatch, _meta())
    body = sent[provider]
    assert PATIENT_ID not in body, f"{provider} request body carries the patient id"
    assert RAW_TAG not in body
    assert "policy_tag_raw" not in body


@pytest.mark.parametrize("provider", ["gemini", "openai"])
def test_the_projection_keeps_what_a_judge_needs(sent, monkeypatch, provider):
    """CONTROL. A projection that dropped everything would satisfy the guard.

    The grading signal and the customer's own observability keys still travel;
    it is the ledger bookkeeping that stops here.
    """
    _drive_both(monkeypatch, _meta())
    body = sent[provider]
    assert "a" * 64 in body          # prompt_hash — the thing being graded
    assert "hmac-sha256" in body     # commitment_alg
    assert "phi" in body             # pii signals
    assert "gpt-5.6" in body         # a SAFE event_metadata key survives


@pytest.mark.parametrize("provider", ["gemini", "openai"])
def test_ledger_bookkeeping_stops_at_the_boundary(sent, monkeypatch, provider):
    """The allowlist is an allowlist, not a `policy_tag_raw` special case.

    `ruleset_hash` and the rule ids are bounded vocabulary and harmless, but a
    third party has no reason to hold them — and asserting the general property
    is what keeps the NEXT key added to ingest excluded until someone names it.
    """
    _drive_both(monkeypatch, _meta())
    body = sent[provider]
    assert "ruleset_version" not in body
    assert "b" * 64 not in body      # ruleset_hash
    assert "phi.ssn_pattern" not in body


def test_the_local_enforcement_path_still_sees_the_whole_record():
    """WHY THE PROJECTION IS AT THE BOUNDARY AND NOT WHERE `meta` IS BUILT.

    ``policy_engine.evaluate_enforcement`` reads decision / policy_rules /
    blocked_reason straight out of event_metadata, and none of those are
    safe-listed. Projecting where the worker assembles `meta` would have emptied
    the rule ids and the reason label out of every host-enforcement verdict —
    silently, because the verdict would still be well-formed. In-process readers
    get the whole record; only the WIRE is narrowed.
    """
    from app import policy_engine

    meta = _meta()
    meta["event_type"] = "blocked"
    meta["event_metadata"]["decision"] = "blocked"
    meta["event_metadata"]["blocked_reason"] = "phi"

    verdict = policy_engine.evaluate_enforcement(meta)
    assert verdict.rules == ["phi.ssn_pattern"]
    assert verdict.reason == "host_blocked_egress:phi"
