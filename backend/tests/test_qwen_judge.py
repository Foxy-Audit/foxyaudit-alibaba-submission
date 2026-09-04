"""Hermetic coverage for the agentic Qwen judge.

Every test stubs `urlopen`; nothing here touches the network or a database.
Modelled on test_openai_judge.py so the three providers are read the same way.

The tests that matter most are the tool-call ones. A judge that can escalate is
the point of this provider, and the failure modes are asymmetric: a missed
escalation silently becomes a pass, while a malformed tool call must not cost a
grade at all.
"""

from __future__ import annotations

import json
from types import SimpleNamespace
from urllib.error import URLError

import pytest

from app import judge, qwen_judge
from app.schemas import Verdict


def _settings(**overrides):
    values = {
        "qwen_api_key": "test-qwen-key",
        "qwen_model": "qwen-plus",
        "qwen_timeout": 2.0,
        "qwen_base_url": "https://dashscope-intl.aliyuncs.com/compatible-mode/v1",
        "gemini_fail_closed": False,
    }
    values.update(overrides)
    return SimpleNamespace(**values)


class _Response:
    def __init__(self, payload):
        self.payload = payload

    def __enter__(self):
        return self

    def __exit__(self, *_args):
        return False

    def read(self):
        return json.dumps(self.payload).encode("utf-8")


def _chat(message):
    return {"choices": [{"message": message}]}


def _tool_call(arguments, name="flag_for_human_review"):
    return {"tool_calls": [{"type": "function",
                            "function": {"name": name, "arguments": arguments}}]}


def _verdict_json(**overrides):
    body = {"policy_breach": False, "reason": "nothing in the metadata",
            "risk_score": 3, "decision": "clean", "rules": []}
    body.update(overrides)
    return {"content": json.dumps(body)}


def _install(monkeypatch, payload, settings=None, captured=None):
    monkeypatch.setattr(qwen_judge, "get_settings", lambda: settings or _settings())

    def fake_urlopen(request, timeout):
        if captured is not None:
            captured["body"] = json.loads(request.data.decode("utf-8"))
            captured["url"] = request.full_url
            captured["headers"] = request.headers
            captured["timeout"] = timeout
        return _Response(payload)

    monkeypatch.setattr(qwen_judge.urllib_request, "urlopen", fake_urlopen)


# ── the provider contract, shared with gemini and openai ──────────────────────

def test_no_key_makes_no_request(monkeypatch):
    monkeypatch.setattr(qwen_judge, "get_settings",
                        lambda: _settings(qwen_api_key=""))

    def fail_if_called(*_args, **_kwargs):
        raise AssertionError("disabled provider made a network request")

    monkeypatch.setattr(qwen_judge.urllib_request, "urlopen", fail_if_called)
    result = qwen_judge.evaluate({"token_count": 1})
    assert result.decision == "unknown"
    assert "no_api_key" in result.reason
    assert result.graded_by == "none"
    assert result.judge_provider is None, "a judge that never ran must not be named"


def test_transport_failure_is_unknown_and_never_raises(monkeypatch):
    monkeypatch.setattr(qwen_judge, "get_settings", lambda: _settings())

    def boom(*_args, **_kwargs):
        raise URLError("connection refused")

    monkeypatch.setattr(qwen_judge.urllib_request, "urlopen", boom)
    result = qwen_judge.evaluate({"token_count": 1})
    assert result.decision == "unknown"
    assert result.graded_by == "none"
    assert result.evaluator_unavailable_reason == "URLError"


def test_request_is_content_blind_and_addresses_the_configured_endpoint(monkeypatch):
    captured = {}
    _install(monkeypatch, _chat(_verdict_json()), captured=captured)

    qwen_judge.evaluate({
        "prompt_hash": "a" * 64,
        "response_hash": "b" * 64,
        "token_count": 12,
        "policy_tag": "hipaa",
        "event_metadata": {"model": "gpt-4", "secret_note": "PATIENT NAME"},
    })

    assert captured["url"].endswith("/chat/completions")
    assert captured["url"].startswith(_settings().qwen_base_url)
    body = captured["body"]
    wire = json.dumps(body)
    # The allowlist in judge.content_blind_meta is the contract; anything outside
    # it must not reach a third party even if ingest widens later.
    assert "secret_note" not in wire
    assert "PATIENT NAME" not in wire
    assert "a" * 64 in wire, "the commitment itself is safe and expected"
    assert captured["timeout"] == 2.0


def test_the_api_key_is_sent_as_a_header_and_not_in_the_url(monkeypatch):
    captured = {}
    _install(monkeypatch, _chat(_verdict_json()), captured=captured)
    qwen_judge.evaluate({"token_count": 1}, api_key="tenant-byok-key")
    assert "tenant-byok-key" not in captured["url"]
    assert "tenant-byok-key" not in json.dumps(captured["body"])
    assert captured["headers"]["Authorization"] == "Bearer tenant-byok-key"


def test_the_resolved_model_is_sent_and_recorded_identically(monkeypatch):
    captured = {}
    _install(monkeypatch, _chat(_verdict_json()), captured=captured)
    result = qwen_judge.evaluate({"token_count": 1}, model="qwen-max")
    assert captured["body"]["model"] == "qwen-max"
    assert result.judge_model == "qwen-max", (
        "the id on the wire and the id on the verdict must not diverge")
    assert result.judge_provider == "qwen"


def test_the_system_prompt_is_built_from_the_org_policy(monkeypatch):
    captured = {}
    _install(monkeypatch, _chat(_verdict_json()), captured=captured)
    qwen_judge.evaluate({"token_count": 1}, policy_config={
        "regulated_data_mode": True, "max_token_threshold": 1234,
        "confidence_threshold": "low",
    })
    system = captured["body"]["messages"][0]["content"]
    assert "regulated-data" in system
    assert "1,234" in system
    assert "every plausible concern" in system, "confidence_threshold was ignored"


def test_an_ordinary_verdict_is_graded_by_ai(monkeypatch):
    _install(monkeypatch, _chat(_verdict_json(
        policy_breach=True, decision="breach", risk_score=91,
        reason="token count far above policy", rules=["pii_signal"])))
    result = qwen_judge.evaluate({"token_count": 999_999})
    assert result.decision == "breach"
    assert result.policy_breach is True
    assert result.risk_score == 91
    assert result.rules == ["pii_signal"]
    assert result.graded_by == "ai"


# ── the agentic path ──────────────────────────────────────────────────────────

def test_the_tool_is_offered_to_the_model(monkeypatch):
    captured = {}
    _install(monkeypatch, _chat(_verdict_json()), captured=captured)
    qwen_judge.evaluate({"token_count": 1})
    names = [t["function"]["name"] for t in captured["body"]["tools"]]
    assert names == ["flag_for_human_review"]
    assert captured["body"]["tool_choice"] == "auto", (
        "the tool must be optional — forcing it would make every event an "
        "escalation and no event a grade")


def test_a_tool_call_produces_a_human_review_verdict(monkeypatch):
    _install(monkeypatch, _chat(_tool_call(json.dumps({
        "reason": "pii signals present but the policy tag is generic",
        "risk_score": 72,
    }))))
    result = qwen_judge.evaluate({"token_count": 5})
    assert result.decision == "human_review"
    assert result.risk_score == 72
    assert result.reason.startswith("pii signals present")
    assert result.judge_provider == "qwen"
    assert result.graded_by == "ai", "the model answered; it answered 'ask a human'"


def test_an_escalation_never_carries_the_breach_flag(monkeypatch):
    """judge.validate quarantines that pair — see Q2a."""
    _install(monkeypatch, _chat(_tool_call(json.dumps({
        "reason": "ambiguous", "risk_score": 99,
    }))))
    result = qwen_judge.evaluate({"token_count": 5})
    assert result.policy_breach is False
    assert judge.validate(result).decision == "human_review", (
        "the escalation was quarantined instead of surviving the gate")


def test_tool_arguments_may_arrive_as_an_object_not_a_string(monkeypatch):
    """OpenAI-compatible endpoints differ here and Qwen's shape was unverified."""
    _install(monkeypatch, _chat(_tool_call(
        {"reason": "sent as an object", "risk_score": 40})))
    result = qwen_judge.evaluate({"token_count": 5})
    assert result.decision == "human_review"
    assert result.risk_score == 40


def test_the_risk_score_from_a_tool_call_is_clamped(monkeypatch):
    _install(monkeypatch, _chat(_tool_call(json.dumps({
        "reason": "out of range", "risk_score": 5000,
    }))))
    assert qwen_judge.evaluate({"token_count": 1}).risk_score == 100


@pytest.mark.parametrize("arguments", [
    "not json at all",
    json.dumps({"risk_score": 50}),            # no reason
    json.dumps({"reason": "   ", "risk_score": 50}),  # blank reason
    json.dumps(["reason", "risk_score"]),      # not an object
])
def test_a_malformed_tool_call_costs_the_escalation_but_not_the_grade(
        monkeypatch, arguments):
    """The asymmetry this module is built around: a model that is bad at calling
    a tool must still be a usable grader."""
    message = _tool_call(arguments)
    message.update(_verdict_json(decision="breach", policy_breach=True,
                                 reason="the ordinary verdict still parsed"))
    _install(monkeypatch, _chat(message))
    result = qwen_judge.evaluate({"token_count": 1})
    assert result.decision == "breach", f"degraded wrongly for {arguments!r}"
    assert result.graded_by == "ai"


def test_a_call_to_some_other_tool_is_ignored(monkeypatch):
    message = _tool_call(json.dumps({"reason": "x", "risk_score": 1}),
                         name="delete_everything")
    message.update(_verdict_json())
    _install(monkeypatch, _chat(message))
    result = qwen_judge.evaluate({"token_count": 1})
    assert result.decision == "clean", "an unknown tool name was honoured"


def test_a_malformed_tool_call_with_no_usable_content_is_unknown(monkeypatch):
    """Both paths failing is an honest unavailable, never a pass."""
    _install(monkeypatch, _chat(_tool_call("not json")))
    result = qwen_judge.evaluate({"token_count": 1})
    assert result.decision == "unknown"
    assert result.graded_by == "none"


# ── how an escalation merges with the other judges ────────────────────────────

def test_an_escalation_survives_a_merge_with_a_clean_judge(monkeypatch):
    """The whole reason Q2a made combine a ladder."""
    _install(monkeypatch, _chat(_tool_call(json.dumps({
        "reason": "needs a person", "risk_score": 60,
    }))))
    escalation = qwen_judge.evaluate({"token_count": 1})
    clean = Verdict(
        policy_breach=False, reason="nothing found", risk_score=0,
        decision="clean", rules=[], judge_provider="gemini",
        judge_model="gemini-2.5-flash", graded_by="ai")
    merged = judge.combine(escalation, clean)
    assert merged.decision == "human_review", (
        "a second judge's clean deleted the request for a human")
    assert merged.policy_breach is False


# ── Q3 · folding three judges ─────────────────────────────────────────────────

def _v(decision, breach=False, reason="a sufficient reason", score=0,
       provider="p", model="m"):
    return Verdict(decision=decision, policy_breach=breach, reason=reason,
                   risk_score=score, judge_provider=provider, judge_model=model,
                   graded_by="ai")


def _fold(*verdicts):
    """Exactly what worker._judge_verdict does with three providers."""
    result = verdicts[0]
    for verdict in verdicts[1:]:
        result = judge.combine(result, verdict)
    return result


def test_a_three_judge_fold_keeps_the_strongest_outcome():
    """`if len(verdicts) == 2` returned verdicts[0] for three, discarding two —
    one of which could be the breach."""
    out = _fold(_v("clean"), _v("clean"), _v("breach", breach=True))
    assert out.decision == "breach" and out.policy_breach is True
    out = _fold(_v("clean"), _v("human_review"), _v("clean"))
    assert out.decision == "human_review"


def test_the_fold_is_order_independent():
    """combine is associative over the ladder, so dispatch order cannot change a
    grade. If this ever fails, the worker's provider order became evidence."""
    import itertools
    trio = [_v("clean"), _v("human_review"), _v("breach", breach=True)]
    outcomes = {_fold(*order).decision for order in itertools.permutations(trio)}
    assert outcomes == {"breach"}, outcomes


def test_a_folded_reason_carries_its_prefix_exactly_once():
    """The nested merge would otherwise store
    `multi_judge_clean: multi_judge_clean: ...` as audit evidence."""
    out = _fold(_v("clean", reason="first"), _v("clean", reason="second"),
                _v("clean", reason="third"))
    assert out.reason.count("multi_judge_") == 1, out.reason
    assert out.reason.startswith("multi_judge_clean: ")
    for part in ("first", "second", "third"):
        assert part in out.reason, f"{part} was lost in the fold"


def test_only_one_prefix_is_stripped_per_merge():
    """A provider that legitimately writes a merge-looking phrase into its own
    reason keeps it; only the one label this module added comes off.

    ⚠ COUNTS, rather than asserting a substring. The first version of this test
    checked that `"multi_judge_clean: the model said this itself"` appeared in
    the result — and a mutant that stripped EVERY prefix in a loop survived it,
    because `combine` re-adds one and the substring reappears either way. The
    two behaviours differ only in how many labels remain, so counting is the
    only assertion that can tell them apart.
    """
    quoted = "multi_judge_clean: multi_judge_clean: the model said this itself"
    out = judge.combine(_v("clean", reason=quoted), _v("clean", reason="other"))
    # two in, one stripped, one re-added by this merge => two.
    assert out.reason.count("multi_judge_clean") == 2, out.reason
    assert "the model said this itself" in out.reason


def test_every_judge_that_answered_is_named_after_a_fold():
    out = _fold(_v("clean", provider="gemini", model="g"),
                _v("clean", provider="openai", model="o"),
                _v("human_review", provider="qwen", model="q"))
    assert set((out.judge_provider or "").split(",")) == {"gemini", "openai", "qwen"}
    assert out.graded_by == "ai"


def test_the_worker_folds_rather_than_testing_a_length():
    """Structural, for the same reason as the guard test below: app.worker needs
    a database driver to import. Pins that the `len(verdicts) == 2` special case
    is gone, which is what silently discarded two grades for `all`."""
    import ast
    import pathlib

    source = (pathlib.Path(__file__).resolve().parents[1]
              / "app" / "worker.py").read_text(encoding="utf-8")
    fn = next(n for n in ast.walk(ast.parse(source))
              if isinstance(n, ast.FunctionDef) and n.name == "_judge_verdict")
    for node in ast.walk(fn):
        if isinstance(node, ast.Compare) and isinstance(node.left, ast.Call):
            func_name = getattr(node.left.func, "id", None)
            literals = [c.value for c in node.comparators if isinstance(c, ast.Constant)]
            assert not (func_name == "len" and 2 in literals), (
                "_judge_verdict still special-cases exactly two verdicts; three "
                "providers would fall through and two grades would be discarded")
    assert any(isinstance(n, ast.For) for n in ast.walk(fn)), (
        "no fold loop in _judge_verdict")


def test_the_worker_dispatches_all_three_providers():
    """Structural. Pins that a `uses_qwen` branch exists beside the other two."""
    import ast
    import pathlib

    source = (pathlib.Path(__file__).resolve().parents[1]
              / "app" / "worker.py").read_text(encoding="utf-8")
    fn = next(n for n in ast.walk(ast.parse(source))
              if isinstance(n, ast.FunctionDef) and n.name == "_judge_verdict")
    attrs = {n.attr for n in ast.walk(fn) if isinstance(n, ast.Attribute)}
    for provider in ("uses_gemini", "uses_openai", "uses_qwen"):
        assert provider in attrs, f"_judge_verdict never checks {provider}"


# ── the worker's empty-verdict guard ──────────────────────────────────────────

def test_the_worker_guards_an_empty_verdict_list_before_indexing_it():
    """Q1 made `judge_provider="qwen"` storable before the worker could dispatch
    it, so `_judge_verdict` can reach its tail with NO verdicts. `verdicts[0]`
    would raise IndexError, `_grade_one` counts the row as a failure, and a batch
    failing with zero successes trips the breaker in `_loop` — which is
    PROCESS-WIDE. One tenant's configuration would pause grading for everyone.

    ⚠ THIS IS A STRUCTURAL TEST AND IT PROVES LESS THAN A BEHAVIOURAL ONE. It
    parses `worker.py` rather than running it, because importing `app.worker`
    constructs the SQLAlchemy engine and so needs a database driver, which puts
    it outside this hermetic tier. What it pins is that the guard EXISTS and runs
    BEFORE the subscript. What it cannot see is whether the guard's body is
    right. Parsed rather than grepped, so it cannot score a comment.
    """
    import ast
    import pathlib

    source = (pathlib.Path(__file__).resolve().parents[1]
              / "app" / "worker.py").read_text(encoding="utf-8")
    fn = next(n for n in ast.walk(ast.parse(source))
              if isinstance(n, ast.FunctionDef) and n.name == "_judge_verdict")

    guards = [n.lineno for n in ast.walk(fn)
              if isinstance(n, ast.If) and isinstance(n.test, ast.UnaryOp)
              and isinstance(n.test.op, ast.Not)
              and isinstance(n.test.operand, ast.Name)
              and n.test.operand.id == "verdicts"]
    subscripts = [n.lineno for n in ast.walk(fn)
                  if isinstance(n, ast.Subscript) and isinstance(n.value, ast.Name)
                  and n.value.id == "verdicts"]

    assert guards, (
        "_judge_verdict has no `if not verdicts:` guard — a routing word that "
        "selects no dispatch branch raises IndexError and trips the "
        "process-wide grading breaker")
    assert subscripts, "the test's own anchor is gone; re-aim it"
    assert min(guards) < min(subscripts), (
        f"the guard is at line {min(guards)} but verdicts is first indexed at "
        f"{min(subscripts)} — the guard cannot run first")
