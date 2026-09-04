"""Evaluator availability must never be represented as a clean verdict."""

from types import SimpleNamespace


def test_health_reports_unavailable_evaluator(make_org, client, monkeypatch):
    from app.routers import health

    # Q3 · every provider is stubbed, not just gemini. _evaluator_status now
    # iterates judge_routing.JUDGE_PROVIDERS, and a stub that names one provider
    # tests a shape the code no longer has.
    monkeypatch.setattr(
        health,
        "get_settings",
        lambda: SimpleNamespace(
            gemini_api_key="", gemini_model="gemini-2.5-flash",
            openai_api_key="", openai_model="gpt-5.6",
            qwen_api_key="", qwen_model="qwen-plus"),
    )
    org = make_org()
    response = client.get("/v1/health", headers=org["auth"])

    assert response.status_code == 200
    # STILL AN EXACT DICT. The two new keys are asserted rather than tolerated:
    # `providers` is the per-provider truth Q3 added because `configured` had
    # been reading gemini's key alone — so an OpenAI-only or Qwen-only
    # deployment reported its evaluator UNAVAILABLE while that judge graded
    # every event. `models` names only providers that have a key, so with none
    # configured it is empty rather than a list of models nobody can call.
    assert response.json()["evaluator"] == {
        "providers": {"gemini": False, "openai": False, "qwen": False},
        "models": {},
        "provider": "gemini",
        "model": "gemini-2.5-flash",
        "status": "unavailable",
        "configured": False,
        "verdicts_advisory": True,
    }


def test_health_reports_a_qwen_only_deployment_as_configured(make_org, client,
                                                             monkeypatch):
    """The regression Q3 fixed, pinned so it cannot come back.

    `configured` read gemini's key alone, so this deployment — which grades
    every event with Qwen — answered "unavailable".
    """
    from app.routers import health

    monkeypatch.setattr(
        health,
        "get_settings",
        lambda: SimpleNamespace(
            gemini_api_key="", gemini_model="gemini-2.5-flash",
            openai_api_key="", openai_model="gpt-5.6",
            qwen_api_key="a-key", qwen_model="qwen-plus"),
    )
    org = make_org()
    evaluator = client.get("/v1/health", headers=org["auth"]).json()["evaluator"]

    assert evaluator["configured"] is True
    assert evaluator["status"] == "configured"
    assert evaluator["provider"] == "qwen"
    assert evaluator["model"] == "qwen-plus"
    assert evaluator["providers"] == {"gemini": False, "openai": False, "qwen": True}
    assert evaluator["models"] == {"qwen": "qwen-plus"}


def test_gemini_fallback_is_unknown_not_clean(monkeypatch):
    from app import gemini

    monkeypatch.setattr(
        gemini,
        "get_settings",
        lambda: SimpleNamespace(gemini_api_key="", gemini_fail_closed=False),
    )
    verdict = gemini.evaluate({"policy_tag": "judge_smoke", "token_count": 1})

    assert verdict.policy_breach is False
    assert verdict.decision == "unknown"
    assert verdict.reason.startswith("evaluator_unavailable:")
