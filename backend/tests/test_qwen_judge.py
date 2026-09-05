"""Hermetic coverage for the agentic Qwen judge.

Every test stubs `urlopen`; nothing here touches the network or a database.
Modelled on test_openai_judge.py so the three providers are read the same way.

The tests that matter most are the tool-call ones. A judge that can escalate is
the point of this provider, and the failure modes are asymmetric: a missed
escalation silently becomes a pass, while a malformed tool call must not cost a
grade at all.

A5 adds a SECOND tool, `check_prior_reviews`, and with it a second turn. Three
properties there are load-bearing and each has a test below that fails without
its guard: the tool exists only when a lookup was supplied, the extra round trip
is capped at ONE however the model behaves, and 🔴 no reviewer note ever reaches
the wire.
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


def _lookup_call(call_id="call_abc123", name="check_prior_reviews"):
    """What the model sends when it asks what people already decided."""
    return {"tool_calls": [{"id": call_id, "type": "function",
                            "function": {"name": name, "arguments": "{}"}}]}


def _counts(**overrides):
    """What `worker._prior_reviews` returns: counts, and nothing else."""
    body = {"window_days": 30, "escalations": 4, "cleared": 3,
            "confirmed_breach": 1, "policy_gap": 0}
    body.update(overrides)
    return body


def _install_turns(monkeypatch, payloads, settings=None, sent=None):
    """Answer each successive request with the next payload, capturing bodies.

    Fails LOUDLY on an unscripted request rather than replaying the last
    payload: the cap on extra round trips is the thing several of these tests
    exist to prove, and a fixture that answered forever would hide a loop.
    """
    monkeypatch.setattr(qwen_judge, "get_settings", lambda: settings or _settings())
    remaining = list(payloads)

    def fake_urlopen(request, timeout):
        body = json.loads(request.data.decode("utf-8"))
        if sent is not None:
            sent.append(body)
        assert remaining, (
            f"the judge made request {len(sent or [])} with only "
            f"{len(payloads)} scripted — an unbounded round trip")
        return _Response(remaining.pop(0))

    monkeypatch.setattr(qwen_judge.urllib_request, "urlopen", fake_urlopen)


class _Lookup:
    """A stand-in for the callable `worker._judge_verdict` binds."""

    def __init__(self, result=None, raises=None):
        self.result = _counts() if result is None else result
        self.raises = raises
        self.calls = 0

    def __call__(self):
        self.calls += 1
        if self.raises is not None:
            raise self.raises
        return self.result


def _tool_names(body):
    return [t["function"]["name"] for t in body["tools"]]


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


def test_the_prompt_gives_escalation_a_checkable_trigger(monkeypatch):
    """The escalation criterion must name a CONDITION, not a feeling.

    ⚠ THIS GUARDS A MEASURED FAILURE, NOT A STYLE PREFERENCE. The first prompt
    said the model returned JSON "normally" and should call the tool "if — and
    only if — you cannot responsibly decide". Against the live API on 2026-09-05
    that produced grading every single time, on qwen-plus AND qwen-max, including
    on an input built to be undecidable from metadata (`policy_tag`
    "phi-restricted" with `pii_signals` empty). A model asked whether it feels
    uncertain resolves that by finding a rationale — "no pii_signals, therefore
    clean" — so the escalation path, which is the entire reason this provider
    exists, was unreachable in production.

    What fixed it was naming the condition in terms of fields the model actually
    holds, and defining the boundary by capability rather than confidence. This
    test pins the three load-bearing pieces so a later tidy-up cannot quietly
    restore a prompt that never escalates: the two outcomes must be presented as
    equals, the content-blind limit must be stated as structural, and the
    regulated-tag-without-signals trigger must survive.

    It cannot assert that the live model escalates — that needs a network call and
    a key. It asserts the only thing a hermetic test can: that the instruction
    which made it escalate is still being sent.
    """
    captured = {}
    _install(monkeypatch, _chat(_verdict_json()), captured=captured)
    qwen_judge.evaluate({"token_count": 1}, policy_config={})
    system = captured["body"]["messages"][0]["content"]

    assert "TWO ways to respond" in system, (
        "the branches must be presented as two correct outcomes; framing grading "
        "as what happens 'normally' is what made escalation unreachable")
    assert "CONTENT-BLIND" in system and "not a negative finding" in system, (
        "the model must be told its blindness is structural, or it reads an "
        "absent signal as evidence of absence and grades clean")
    assert "policy_tag" in system and "pii_signals is empty" in system, (
        "the escalation trigger must be checkable against fields the model "
        "actually receives, not phrased as a state of mind")

    tool = qwen_judge._TOOLS[0]["function"]
    assert tool["name"] == "flag_for_human_review"
    assert "reviewer who CAN see the content" in tool["description"], (
        "the tool description must define the boundary by capability — what a "
        "human could decide that this model structurally cannot")


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


# ── A5 ─ the second tool, and the one extra round trip ───────────────

def test_the_lookup_tool_is_offered_only_when_a_callable_is_supplied(monkeypatch):
    """The default has to be indistinguishable from before A5.

    A model told about a lookup nobody can serve spends its turn asking for one,
    and a turn spent on an unanswerable tool call comes back with no verdict in
    it — so offering the tool without a way to answer it does not degrade the
    grade, it loses it.
    """
    without = {}
    _install(monkeypatch, _chat(_verdict_json()), captured=without)
    qwen_judge.evaluate({"token_count": 1})
    assert _tool_names(without["body"]) == ["flag_for_human_review"], (
        "the lookup was offered with no callable to answer it")

    with_lookup = []
    _install_turns(monkeypatch, [_chat(_verdict_json())], sent=with_lookup)
    qwen_judge.evaluate({"token_count": 1}, prior_reviews=_Lookup())
    assert _tool_names(with_lookup[0]) == ["flag_for_human_review",
                                           "check_prior_reviews"]


def test_the_prompt_names_the_lookup_and_its_cap_only_when_it_is_offered(monkeypatch):
    """The prompt and the transport have to say the same thing.

    ⚠ THE CAP IS STATED AS A FACT ABOUT THE TOOL, not as a request, and that is
    the lesson of 9f9bacc applied to a limit instead of a trigger. "You may ask
    once" is a rule a model can rationalise around; "after one call it is
    withdrawn" describes what `evaluate` actually does on turn two, where the
    tool is genuinely absent from the request.
    """
    offered = []
    _install_turns(monkeypatch, [_chat(_verdict_json())], sent=offered)
    qwen_judge.evaluate({"token_count": 1}, prior_reviews=_Lookup())
    system = offered[0]["messages"][0]["content"]
    assert "check_prior_reviews" in system
    assert "ONCE" in system and "withdrawn" in system, (
        "the model was told the tool exists but not that asking twice fails")
    assert "counts only" in system, (
        "the model must be told the lookup carries no content, or it will read "
        "the absence of detail as a finding")

    silent = {}
    _install(monkeypatch, _chat(_verdict_json()), captured=silent)
    qwen_judge.evaluate({"token_count": 1})
    assert "check_prior_reviews" not in silent["body"]["messages"][0]["content"], (
        "the prompt advertised a tool that was never offered")


def test_a_lookup_is_executed_and_answered_as_a_tool_message(monkeypatch):
    """The whole point: the model asks, a human's decisions come back, it grades."""
    sent = []
    lookup = _Lookup()
    _install_turns(monkeypatch, [_chat(_lookup_call()),
                                 _chat(_verdict_json(decision="clean"))], sent=sent)

    result = qwen_judge.evaluate({"token_count": 1, "policy_tag": "hipaa"},
                                 prior_reviews=lookup)

    assert lookup.calls == 1, "the lookup was offered and then not run"
    assert len(sent) == 2, "one lookup must cost exactly one extra round trip"
    answer = sent[1]["messages"][-1]
    assert answer["role"] == "tool"
    assert answer["tool_call_id"] == "call_abc123", (
        "the tool result did not answer the call the model actually made")
    assert json.loads(answer["content"]) == {
        "window_days": 30, "escalations": 4, "cleared": 3,
        "confirmed_breach": 1, "policy_gap": 0, "policy_tag": "hipaa"}
    assert result.decision == "clean" and result.graded_by == "ai"


def test_the_second_request_carries_the_original_messages_and_the_tool_result(
        monkeypatch):
    """These endpoints hold no state.

    A tool result sent without the system prompt, the metadata and the assistant
    message it answers is a tool result answering nothing — and the failure is
    silent, because the model still replies, just without ever having seen the
    event it is grading.
    """
    sent = []
    _install_turns(monkeypatch, [_chat(_lookup_call()), _chat(_verdict_json())],
                   sent=sent)
    qwen_judge.evaluate({"token_count": 1}, prior_reviews=_Lookup())

    first, second = sent
    assert second["messages"][:2] == first["messages"], (
        "the system prompt and the metadata were dropped from the second turn")
    assert [m["role"] for m in second["messages"]] == [
        "system", "user", "assistant", "tool"]
    assistant = second["messages"][2]
    assert assistant["tool_calls"][0]["id"] == second["messages"][3]["tool_call_id"], (
        "the assistant message and the tool result reference different calls")
    assert second["model"] == first["model"]


def test_a_second_lookup_request_is_refused_rather_than_served(monkeypatch):
    """The cap, expressed as the only thing a model cannot talk its way past.

    ⚠ THE ASSERTION IS ON THE TOOL LIST, NOT ONLY ON THE CALL COUNT. A cap
    enforced by declining to execute a second call would still let the model
    spend its last turn asking, and asking is what it does when the tool is
    visible. Withdrawing it from the request is what makes the second ask
    impossible rather than merely unproductive.
    """
    sent = []
    lookup = _Lookup()
    asks_again = _chat({**_lookup_call("call_second"),
                        **_verdict_json(decision="breach", policy_breach=True)})
    _install_turns(monkeypatch, [_chat(_lookup_call()), asks_again], sent=sent)

    result = qwen_judge.evaluate({"token_count": 1}, prior_reviews=lookup)

    assert lookup.calls == 1, "the lookup ran twice for one grade"
    assert len(sent) == 2, "a second ask bought a third round trip"
    assert _tool_names(sent[1]) == ["flag_for_human_review"], (
        "the lookup was still on the table for the second turn")
    assert result.decision == "breach", (
        "a model that asked twice lost its grade; the refusal must not cost one")


def test_an_escalation_on_turn_one_still_works_when_the_lookup_is_offered(
        monkeypatch):
    """A second tool must not cost the first one its turn."""
    sent = []
    lookup = _Lookup()
    _install_turns(monkeypatch, [_chat(_tool_call(json.dumps({
        "reason": "a regulated tag with no signals", "risk_score": 80})))],
        sent=sent)

    result = qwen_judge.evaluate({"token_count": 1}, prior_reviews=lookup)

    assert result.decision == "human_review"
    assert result.risk_score == 80
    assert lookup.calls == 0, "an escalation spent a lookup it never asked for"
    assert len(sent) == 1, "an escalation is terminal and costs one round trip"


def test_a_message_asking_for_both_escalates_without_spending_the_lookup(
        monkeypatch):
    """Escalation ends the grade; a lookup only defers it.

    Serving the lookup first would spend a round trip and then throw away the
    answer the model had already given.
    """
    sent = []
    lookup = _Lookup()
    both = {"tool_calls": [
        _tool_call(json.dumps({"reason": "needs a person",
                               "risk_score": 65}))["tool_calls"][0],
        _lookup_call()["tool_calls"][0]]}
    _install_turns(monkeypatch, [_chat(both)], sent=sent)

    result = qwen_judge.evaluate({"token_count": 1}, prior_reviews=lookup)

    assert result.decision == "human_review" and result.risk_score == 65
    assert lookup.calls == 0
    assert len(sent) == 1


def test_the_model_can_escalate_after_reading_the_prior_reviews(monkeypatch):
    """A1's loop, closed: human decisions reach the agent, and it acts on them.

    This is the sequence the phase exists for — consult what people ruled, then
    decide a person should rule again. `flag_for_human_review` therefore has to
    survive into turn two, which is why the cap withdraws only the lookup.
    """
    sent = []
    lookup = _Lookup(_counts(escalations=6, cleared=0, confirmed_breach=6))
    _install_turns(monkeypatch, [
        _chat(_lookup_call()),
        _chat(_tool_call(json.dumps({"reason": "humans confirmed this tag six times",
                                     "risk_score": 88})))], sent=sent)

    result = qwen_judge.evaluate({"token_count": 1}, prior_reviews=lookup)

    assert result.decision == "human_review"
    assert result.risk_score == 88
    assert lookup.calls == 1
    assert "flag_for_human_review" in _tool_names(sent[1]), (
        "the cap withdrew the escalation tool as well as the lookup")


def test_a_lookup_that_raises_degrades_to_a_graded_verdict(monkeypatch):
    """⚠ A JUDGE THAT IS BAD AT USING A TOOL MUST NOT BECOME A JUDGE THAT CANNOT
    GRADE — this module's docstring, applied to the second tool.

    And the second turn still HAPPENS. Turn one spent itself on a tool call and
    holds no verdict to fall back on, so skipping it would turn a database blip
    into an ungraded row: exactly the degradation the rule forbids.
    """
    sent = []
    lookup = _Lookup(raises=RuntimeError("connection to the ledger dropped"))
    _install_turns(monkeypatch, [_chat(_lookup_call()),
                                 _chat(_verdict_json(decision="breach",
                                                     policy_breach=True))], sent=sent)

    result = qwen_judge.evaluate({"token_count": 1}, prior_reviews=lookup)

    assert result.decision == "breach", "a failed lookup cost the grade"
    assert result.graded_by == "ai"
    answer = json.loads(sent[1]["messages"][-1]["content"])
    assert "error" in answer and "unavailable" in answer["error"]
    assert "connection to the ledger dropped" not in json.dumps(sent[1]), (
        "the exception message reached the model; it can carry a query or a row")


def test_a_lookup_that_answers_with_a_non_mapping_degrades_to_a_graded_verdict(
        monkeypatch):
    sent = []
    _install_turns(monkeypatch, [_chat(_lookup_call()), _chat(_verdict_json())],
                   sent=sent)
    result = qwen_judge.evaluate({"token_count": 1},
                                 prior_reviews=_Lookup(result=["not", "a", "dict"]))
    assert result.decision == "clean" and result.graded_by == "ai"
    assert "error" in json.loads(sent[1]["messages"][-1]["content"])


def test_a_reviewer_note_never_reaches_the_model(monkeypatch):
    """🔴 THE ONE RULE THIS PRODUCT CANNOT BEND.

    `human_reviews.note` is the single field a human types freely — "annotation,
    not evidence" (`models.HumanReview`) — and it is why both /v1/reviews verbs
    require an authenticated user rather than an SDK key. A reviewer explaining
    why they cleared something will quote the prompt they were shown, so the note
    is raw content sitting in a column next to the counts this tool returns.

    Asserted against the BYTES OF EVERY REQUEST, not against the projection
    helper, for the reason tests/integration/test_judge_content_blindness.py
    exists: a helper that filters correctly proves nothing about a caller that
    forgets to call it, and this codebase shipped exactly that bug once, with a
    green test watching.

    The callable here returns everything a careless `SELECT *` would hand back.
    Only counts may survive.
    """
    sentinel = "MRN-4417829 the patient asked about her HIV results"
    sent = []
    leaky = _Lookup({
        **_counts(),
        "note": sentinel,
        "reason": f"escalated because {sentinel}",
        "resolved_by": "reviewer@hospital.example",
        "id": "8f2c1b7e-0000-4000-8000-000000000001",
        "resolved_at": "2026-09-04T11:02:33+00:00",
    })
    _install_turns(monkeypatch, [_chat(_lookup_call()), _chat(_verdict_json())],
                   sent=sent)

    qwen_judge.evaluate({"token_count": 1, "policy_tag": "hipaa"},
                        prior_reviews=leaky)

    wire = json.dumps(sent)
    assert sentinel not in wire, "a reviewer's note reached a third party"
    assert "reviewer@hospital.example" not in wire, "a reviewer was named on the wire"
    assert "8f2c1b7e" not in wire, "a row id reached the model"
    assert "2026-09-04T11:02:33" not in wire, (
        "a timestamp finer than the window reached the model")
    assert json.loads(sent[1]["messages"][-1]["content"]) == {
        "window_days": 30, "escalations": 4, "cleared": 3,
        "confirmed_breach": 1, "policy_gap": 0, "policy_tag": "hipaa"}, (
        "the answer is an allowlist of counts; anything else is a leak waiting "
        "for the day someone widens the query")


def test_the_answered_policy_tag_comes_from_the_metadata_not_the_lookup(monkeypatch):
    """The one string in the answer, and it is not read from the database.

    It echoes the tag the model was ALREADY sent inside `metadata`, so it adds no
    byte that was not on the wire a turn ago. Reading it from the lookup instead
    would open a string-shaped channel out of a table that holds a free-text note.
    """
    sent = []
    _install_turns(monkeypatch, [_chat(_lookup_call()), _chat(_verdict_json())],
                   sent=sent)
    qwen_judge.evaluate(
        {"token_count": 1, "policy_tag": "hipaa"},
        prior_reviews=_Lookup(_counts(policy_tag="NOT-FROM-THE-DATABASE")))
    answer = json.loads(sent[1]["messages"][-1]["content"])
    assert answer["policy_tag"] == "hipaa"
    assert "NOT-FROM-THE-DATABASE" not in json.dumps(sent)


def test_only_integers_survive_the_projection(monkeypatch):
    """Counts are coerced rather than trusted, so no string rides out as a count."""
    sent = []
    _install_turns(monkeypatch, [_chat(_lookup_call()), _chat(_verdict_json())],
                   sent=sent)
    qwen_judge.evaluate(
        {"token_count": 1},
        prior_reviews=_Lookup(_counts(cleared="three of them, per Dr Ahmed",
                                     escalations=-9, confirmed_breach=None)))
    answer = json.loads(sent[1]["messages"][-1]["content"])
    assert answer["cleared"] == 0, "a string was passed through as a count"
    assert answer["escalations"] == 0, "a negative count was not clamped"
    assert answer["confirmed_breach"] == 0
    assert "Dr Ahmed" not in json.dumps(sent)


def test_a_lookup_call_with_no_id_is_still_answerable(monkeypatch):
    """Some OpenAI-compatible endpoints omit the tool_call id, and Qwen's exact
    shape could not be verified without a live key. The `tool` message has to
    reference something, so the assistant message is rebuilt with the same id
    either way."""
    sent = []
    lookup = _Lookup()
    _install_turns(monkeypatch, [_chat(_lookup_call(call_id=None)),
                                 _chat(_verdict_json())], sent=sent)

    result = qwen_judge.evaluate({"token_count": 1}, prior_reviews=lookup)

    assert lookup.calls == 1
    assistant, answer = sent[1]["messages"][2], sent[1]["messages"][3]
    assert assistant["tool_calls"][0]["id"] == answer["tool_call_id"]
    assert answer["tool_call_id"], "the tool result referenced an empty call id"
    assert result.decision == "clean"


def test_a_lookup_call_is_ignored_when_no_callable_was_supplied(monkeypatch):
    """Defence in depth: the tool is not offered, so this should be unreachable —
    but a model that calls it anyway must not get a second turn on a lookup
    nobody can run."""
    sent = []
    message = {**_lookup_call(), **_verdict_json()}
    _install_turns(monkeypatch, [_chat(message)], sent=sent)
    result = qwen_judge.evaluate({"token_count": 1})
    assert len(sent) == 1, "an unofferable tool bought a round trip"
    assert result.decision == "clean"


def test_a_call_to_an_unknown_tool_does_not_trigger_the_lookup(monkeypatch):
    sent = []
    lookup = _Lookup()
    message = {**_lookup_call(name="drop_the_ledger"), **_verdict_json()}
    _install_turns(monkeypatch, [_chat(message)], sent=sent)
    result = qwen_judge.evaluate({"token_count": 1}, prior_reviews=lookup)
    assert lookup.calls == 0, "an unknown tool name ran the lookup"
    assert len(sent) == 1
    assert result.decision == "clean"


# ── A5 review ─ the lookup must never make grading worse ───────────

def _asks_and_answers(**verdict):
    """One message that BOTH requests the lookup and carries a parseable verdict.

    Not a hypothetical shape: it is what the live model produced under review on
    2026-09-05, and it is the shape
    `test_a_second_lookup_request_is_refused_rather_than_served` was already
    building without anyone noticing what it implied for a failed second turn.
    """
    return _chat({**_lookup_call(), **_verdict_json(**verdict)})


def test_a_verdict_given_alongside_a_lookup_call_survives_a_failed_second_turn(
        monkeypatch):
    """⚠ THE REGRESSION THE TOOL ITSELF INTRODUCED, found in review by execution.

    Turn one asked for the history AND graded. The code spent the second round
    trip and dropped the verdict, so when that second request failed, `evaluate`
    returned `unknown` and `_grade_one` substituted the deterministic engine.

    The identical response bytes gave `decision="breach", graded_by="ai"` with
    `prior_reviews=None` and `evaluator_unavailable:URLError, graded_by="none"`
    with a lookup supplied — so SUPPLYING THE LOOKUP TURNED A GOOD VERDICT INTO
    AN UNKNOWN. A second tool that makes grading worse is the one outcome this
    phase cannot ship.
    """
    calls = {"n": 0}
    monkeypatch.setattr(qwen_judge, "get_settings", lambda: _settings())

    def flaky(request, timeout):
        calls["n"] += 1
        if calls["n"] == 1:
            return _Response(_asks_and_answers(decision="breach", policy_breach=True,
                                               risk_score=77,
                                               reason="token count far above policy"))
        raise URLError("connection reset before the second turn")

    monkeypatch.setattr(qwen_judge.urllib_request, "urlopen", flaky)

    result = qwen_judge.evaluate({"token_count": 999_999}, prior_reviews=_Lookup())

    assert result.decision == "breach", (
        "the lookup cost a verdict the model had already given")
    assert result.graded_by == "ai" and result.judge_provider == "qwen"
    assert result.risk_score == 77
    assert result.evaluator_unavailable_reason is None, (
        "a verdict a model produced must not be labelled as no judge having run")


def test_the_same_bytes_grade_the_same_with_and_without_the_lookup(monkeypatch):
    """The property the finding is really about: offering the tool must not
    change the outcome for the worse on identical model output.

    Run twice over one flaky transport script — once with a lookup, once without.
    Without it there is no second turn to fail, so the verdict stands; with it,
    the second turn fails. Both must land on the same grade.
    """
    def run(prior_reviews):
        calls = {"n": 0}
        monkeypatch.setattr(qwen_judge, "get_settings", lambda: _settings())

        def flaky(request, timeout):
            calls["n"] += 1
            if calls["n"] == 1:
                return _Response(_asks_and_answers(decision="breach",
                                                   policy_breach=True, risk_score=77))
            raise URLError("connection reset")

        monkeypatch.setattr(qwen_judge.urllib_request, "urlopen", flaky)
        return qwen_judge.evaluate({"token_count": 1}, prior_reviews=prior_reviews)

    without, with_lookup = run(None), run(_Lookup())
    assert without.decision == with_lookup.decision == "breach"
    assert without.graded_by == with_lookup.graded_by == "ai"
    assert with_lookup.risk_score == without.risk_score


def test_a_turn_two_answer_beats_the_verdict_turn_one_gave(monkeypatch):
    """The captured verdict is a FALLBACK, never a preference.

    Turn two read the history; turn one had not. If the second answer arrives it
    wins — otherwise the lookup would be a round trip whose answer is discarded,
    which is worse than never asking. This is the live behaviour under review:
    clean at 15 after seeing four clears, where the same payload without the
    lookup escalated at 85.
    """
    sent = []
    _install_turns(monkeypatch, [
        _asks_and_answers(decision="breach", policy_breach=True, risk_score=85),
        _chat(_verdict_json(decision="clean", policy_breach=False, risk_score=15,
                            reason="prior reviews of this tag were all cleared"))],
        sent=sent)

    result = qwen_judge.evaluate({"token_count": 1},
                                 prior_reviews=_Lookup(_counts(escalations=4,
                                                              cleared=4,
                                                              confirmed_breach=0)))

    assert result.decision == "clean" and result.risk_score == 15, (
        "the stale turn-one verdict beat the one that had read the history")
    assert "cleared" in result.reason
    assert len(sent) == 2


def test_a_turn_two_reply_with_nothing_gradeable_falls_back_to_turn_one(monkeypatch):
    """A failed second turn is not only a dropped socket. A reply that parses as
    HTTP but carries no verdict and no escalation is the same loss."""
    _install_turns(monkeypatch, [
        _asks_and_answers(decision="breach", policy_breach=True, risk_score=60),
        _chat({"content": "I have consulted the history."})])

    result = qwen_judge.evaluate({"token_count": 1}, prior_reviews=_Lookup())

    assert result.decision == "breach" and result.risk_score == 60
    assert result.graded_by == "ai"


def test_a_failed_second_turn_with_no_turn_one_verdict_is_still_unknown(monkeypatch):
    """⚠ THE FALLBACK MUST NOT INVENT A GRADE. Where turn one carried ONLY a tool
    call, there is nothing to fall back to and the honest answer is the one this
    module has always given: `unknown`, `graded_by="none"`, for the deterministic
    engine to replace.
    """
    calls = {"n": 0}
    monkeypatch.setattr(qwen_judge, "get_settings", lambda: _settings())

    def flaky(request, timeout):
        calls["n"] += 1
        if calls["n"] == 1:
            return _Response(_chat(_lookup_call()))
        raise URLError("connection reset")

    monkeypatch.setattr(qwen_judge.urllib_request, "urlopen", flaky)

    result = qwen_judge.evaluate({"token_count": 1}, prior_reviews=_Lookup())
    assert result.decision == "unknown"
    assert result.graded_by == "none"
    assert result.evaluator_unavailable_reason == "URLError"


def test_an_unparseable_first_turn_still_reports_its_own_failure_type(monkeypatch):
    """The capture is opportunistic and must not swallow the reason a customer
    sees. With nothing gradeable anywhere, the fallback still names the exception
    type rather than a generic label."""
    _install_turns(monkeypatch, [_chat(_lookup_call()), _chat({"content": "{"})])
    result = qwen_judge.evaluate({"token_count": 1}, prior_reviews=_Lookup())
    assert result.decision == "unknown"
    assert result.evaluator_unavailable_reason == "JSONDecodeError"


def test_the_window_the_counts_cover_is_stated_before_the_model_asks(monkeypatch):
    """⚠ ALL-ZEROS MUST NOT READ AS "NEVER".

    The query bounds at `PRIOR_REVIEW_WINDOW_DAYS`; the description and the prompt
    promised counts "in this workspace" with no bound. A tag humans cleared five
    times 45 days ago comes back all zeros, and an unbounded promise makes that
    "nobody has ever escalated this" — a wrong answer wearing the shape of a
    right one, which is the exact failure the no-arguments decision refuses to
    allow from a hallucinated tag.

    The payload does carry `window_days`, but the model decides whether to ASK
    before it sees any payload, so the bound has to be in the description too.
    """
    window = str(qwen_judge.PRIOR_REVIEW_WINDOW_DAYS)
    description = qwen_judge._PRIOR_REVIEWS_TOOL["function"]["description"]
    assert window in description, (
        "the tool description does not say how far back the counts reach")
    assert "ZERO" in description and "never" in description, (
        "the description must say what all-zeros does NOT mean")

    sent = []
    _install_turns(monkeypatch, [_chat(_verdict_json())], sent=sent)
    qwen_judge.evaluate({"token_count": 1}, prior_reviews=_Lookup())
    system = sent[0]["messages"][0]["content"]
    assert window in system, "the prompt clause states no window either"


def test_the_query_and_the_promise_read_one_window_constant():
    """Structural. The bound the model is PROMISED and the bound the WHERE clause
    applies must be one number, because a drift between them would be invisible:
    both halves would go on working, and only the answer would be wrong."""
    import ast

    source = _worker_source()
    assert "qwen_judge.PRIOR_REVIEW_WINDOW_DAYS" in source, (
        "the worker declares its own window; it must read the one the tool "
        "description promises")
    fn = next(n for n in ast.walk(ast.parse(source))
              if isinstance(n, ast.FunctionDef) and n.name == "_prior_reviews")
    literals = [n.value for n in ast.walk(fn)
                if isinstance(n, ast.Constant) and isinstance(n.value, int)]
    assert not literals, (
        f"_prior_reviews carries a bare integer {literals} where the shared "
        "window constant belongs")


# ── A5 ─ the worker half, read structurally ──────────────────────

def _worker_source():
    import pathlib
    return (pathlib.Path(__file__).resolve().parents[1]
            / "app" / "worker.py").read_text(encoding="utf-8")


def test_the_prior_review_query_selects_no_reviewer_note():
    """🔴 The other half of the note guard, and the half that is nearest the
    note itself.

    `qwen_judge` narrows the lookup result at the wire boundary, but the query is
    where a `SELECT *` or a helpfully added column would put a note into the
    process in the first place. Both have to hold. Parsed rather than grepped, so
    it reads the SQL and cannot be satisfied by a comment saying the right thing.
    """
    import ast

    tree = ast.parse(_worker_source())
    sql = None
    for node in ast.walk(tree):
        if (isinstance(node, ast.Assign)
                and any(getattr(t, "id", None) == "_PRIOR_REVIEWS_SQL"
                        for t in node.targets)):
            sql = next(c.value for c in ast.walk(node)
                       if isinstance(c, ast.Constant) and isinstance(c.value, str))
    assert sql is not None, "_PRIOR_REVIEWS_SQL is gone; re-aim this test"
    lowered = sql.lower()
    assert "note" not in lowered, (
        "the prior-review query reads `note`, the one free-text field a human "
        "writes; it must never leave the database on this path")
    assert "select *" not in lowered, "a star select would pick up `note` tomorrow"
    for scope in ("hr.org_id = :oid", "al.policy_tag = :tag"):
        assert scope in sql, f"the lookup is not scoped by {scope}"
    assert "make_interval(days => :days)" in sql, "the window is unbounded"


def test_the_worker_binds_the_lookup_only_for_the_agentic_judge():
    """Structural, for the reason the other worker tests here are: importing
    `app.worker` constructs the SQLAlchemy engine and so needs a driver.

    Pins that `prior_reviews=` is passed to `qwen_judge.evaluate` and to neither
    of the others — gemini and openai cannot call a tool at all, and handing them
    a callable would be a silent no-op that reads like a feature.
    """
    import ast

    fn = next(n for n in ast.walk(ast.parse(_worker_source()))
              if isinstance(n, ast.FunctionDef) and n.name == "_judge_verdict")
    bound = {}
    for node in ast.walk(fn):
        if not isinstance(node, ast.Call) or not isinstance(node.func, ast.Attribute):
            continue
        if node.func.attr != "evaluate":
            continue
        provider = getattr(node.func.value, "id", None)
        bound[provider] = {kw.arg for kw in node.keywords}
    assert "prior_reviews" in bound.get("qwen_judge", set()), (
        "the agentic judge is offered no lookup; A1's decisions never reach it")
    for provider in ("gemini", "openai_judge"):
        assert "prior_reviews" not in bound.get(provider, set()), (
            f"{provider} was handed a lookup it has no tool to call")


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
