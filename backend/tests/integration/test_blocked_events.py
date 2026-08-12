"""Host-side ENFORCEMENT events (blocked / redacted) as tamper-evident evidence.

The SDK emits a prevented-egress event as a normal POST /v1/logs/batch row with
event_type="blocked"|"redacted" and content-blind enforcement labels in
event_metadata (decision, blocked_reason, policy_rules). Only hashes + labels ever
leave the host — never raw text.

These tests prove such an event:
  * ingests and is folded into the tamper-evident chain (fails /v1/verify if altered),
  * is treated as terminal & locally decided — the Gemini/judge call is SKIPPED and a
    deterministic graded verdict is written instead,
  * is counted as a prevented egress, never as a model breach,
  * surfaces its enforcement counts in the compliance passport, and
  * that a malformed judge verdict is quarantined as evaluator_unknown, so a bad
    evaluator answer can never launder itself into the audit report.
"""

from __future__ import annotations

import hashlib
import sys

from sqlalchemy import text

from app.db import engine

_h = lambda s: hashlib.sha256(s.encode()).hexdigest()  # noqa: E731


def _blocked_event(seed: str = "1", *, event_type: str = "blocked",
                   decision: str | None = None,
                   blocked_reason: str = "pii_ssn_detected",
                   policy_rules=("pii.ssn", "block.egress"),
                   pii_signals=("ssn",)):
    """One enforcement row exactly as the SDK wire contract emits it.

    prompt_hash commits the original prompt; response_hash commits "" for a block
    (nothing was produced) or the real (redacted) response for a redaction.
    """
    blocked = event_type == "blocked"
    return {
        "prompt_hash": _h(f"prompt-{seed}"),
        "response_hash": _h("") if blocked else _h(f"redacted-response-{seed}"),
        "token_count": 0 if blocked else 12,
        "policy_tag": "chat",
        "event_type": event_type,
        "pii_signals": list(pii_signals),
        "event_metadata": {
            "decision": decision or event_type,
            "blocked_reason": blocked_reason,
            "policy_rules": list(policy_rules),
        },
    }


def test_blocked_event_ingests_and_is_chained_tamper_evident(make_org, client):
    """A blocked event ingests (202), verifies intact, and — because event_type,
    pii_signals and event_metadata are folded into the hash — fails /v1/verify the
    moment its enforcement label is altered. No migration, no chain-version bump."""
    org = make_org()

    r = client.post("/v1/logs/batch", headers=org["auth"], json=[_blocked_event()])
    assert r.status_code == 202, r.text
    receipt = r.json()["receipts"][0]
    assert receipt["status"] == "accepted"

    # Intact chain verifies.
    v = client.get("/v1/verify", headers=org["auth"]).json()
    assert v["ok"] is True and v["count"] == 1

    # Tamper with the enforcement label stored on the row; the chain must break.
    with engine.begin() as c:
        c.execute(
            text("UPDATE audit_logs "
                 "SET event_metadata = jsonb_set(event_metadata, "
                 "'{blocked_reason}', '\"nothing_was_blocked\"') "
                 "WHERE org_id = :o AND seq = 1"),
            {"o": org["org_id"]},
        )

    v2 = client.get("/v1/verify", headers=org["auth"]).json()
    assert v2["ok"] is False
    assert v2["first_broken_seq"] == 1


def _grade_pending(monkeypatch, *, breach_when=lambda m: False, calls=None):
    """Grade every claimed row through the REAL worker; the only fake is the LLM's
    answer. Records into `calls` every meta the judge was actually asked to grade so
    a test can prove a terminal event never reached the judge."""
    from app import worker as workermod
    from app.schemas import Verdict

    def fake_eval(meta, policy_config=None, history=None, api_key=None, model=None):
        if calls is not None:
            calls.append(meta)
        breach = breach_when(meta)
        return Verdict(
            policy_breach=breach,
            reason="policy tripped" if breach else "no issues found",
            risk_score=90 if breach else 0,
            decision="breach" if breach else "clean",
        )

    monkeypatch.setattr(workermod.gemini, "evaluate", fake_eval)
    from app.db import SessionLocal
    db = SessionLocal()
    try:
        rows = workermod._claim_batch(db, 100, 300)
        for row in rows:
            workermod._grade_one(db, row)
    finally:
        db.close()


def test_enforcement_events_skip_judge_and_grade_terminally(make_org, client, monkeypatch):
    """blocked/redacted are terminal & locally decided: the judge is never called
    (there is no model response to grade), and a deterministic graded verdict is
    written from the enforcement labels — never a model breach."""
    org = make_org()
    client.post("/v1/logs/batch", headers=org["auth"],
                json=[_blocked_event(seed="blk", event_type="blocked")])       # seq 1
    client.post("/v1/logs/batch", headers=org["auth"],
                json=[_blocked_event(seed="red", event_type="redacted")])      # seq 2

    calls = []
    _grade_pending(monkeypatch, breach_when=lambda m: True, calls=calls)

    # The judge graded NOTHING — both events were locally decided.
    assert calls == []

    rows = {r["seq"]: r for r in client.get("/v1/logs", headers=org["auth"]).json()["items"]}
    blocked, redacted = rows[1], rows[2]

    assert blocked["grading_status"] == "graded"
    assert blocked["gemini_verdict"]["decision"] == "blocked"
    assert blocked["gemini_verdict"]["policy_breach"] is False
    assert "block.egress" in blocked["gemini_verdict"]["rules"]

    assert redacted["grading_status"] == "graded"
    assert redacted["gemini_verdict"]["decision"] == "redacted"
    assert redacted["gemini_verdict"]["policy_breach"] is False


def test_blocked_event_counted_as_blocked_not_breach(make_org, client, monkeypatch,
                                                     configure_judge):
    """A prevented egress is counted separately from a model breach: it never
    appears in the breach feed and never inflates the breach stat."""
    org = make_org()
    configure_judge(org["org_id"])          # a judge key, so the non-terminal row is graded
    client.post("/v1/logs/batch", headers=org["auth"],
                json=[_blocked_event(seed="b")])                                 # seq 1 blocked
    client.post("/v1/logs/batch", headers=org["auth"], json=[{
        "prompt_hash": _h("np"), "response_hash": _h("nr"),
        "token_count": 500, "policy_tag": "chat"}])                              # seq 2 normal

    # The judge would flag EVERYTHING it grades — so if the block were counted as a
    # breach it could only be because it (wrongly) reached the judge.
    _grade_pending(monkeypatch, breach_when=lambda m: True)

    breaches = client.get("/v1/logs/breaches", headers=org["auth"]).json()
    assert [b["seq"] for b in breaches] == [2]

    stats = client.get("/v1/stats", headers=org["auth"]).json()
    assert stats["breaches"] == 1


def _grade_with_verdict(monkeypatch, verdict):
    """Grade all pending rows with a fixed (possibly malformed) judge verdict."""
    from app import worker as workermod
    monkeypatch.setattr(workermod.gemini, "evaluate",
                        lambda meta, policy_config=None, history=None, api_key=None, model=None: verdict)
    from app.db import SessionLocal
    db = SessionLocal()
    try:
        for row in workermod._claim_batch(db, 100, 300):
            workermod._grade_one(db, row)
    finally:
        db.close()


def _one_normal_event(client, org, seed="j"):
    """One ordinary (non-terminal) row. Its org must have a judge key configured
    (fixture `configure_judge`) or the per-tenant router skips the judge entirely."""
    assert client.post("/v1/logs/batch", headers=org["auth"], json=[{
        "prompt_hash": _h(f"p-{seed}"), "response_hash": _h(f"r-{seed}"),
        "token_count": 10, "policy_tag": "chat"}]).status_code == 202


def test_contradictory_judge_verdict_is_quarantined(make_org, client, monkeypatch,
                                                    configure_judge):
    """A judge answer that flags a breach yet decides "clean" is self-contradictory.
    It must NOT be trusted as a breach OR laundered into a clean pass — it is
    quarantined as evaluator_unknown so the audit report stays honest."""
    from app.schemas import Verdict
    org = make_org()
    configure_judge(org["org_id"])
    _one_normal_event(client, org)

    bad = Verdict(policy_breach=True, reason="all good, nothing to see",
                  risk_score=80, decision="clean")
    _grade_with_verdict(monkeypatch, bad)

    v = client.get("/v1/logs", headers=org["auth"]).json()["items"][0]["gemini_verdict"]
    assert v["decision"] == "unknown"
    assert v["policy_breach"] is False
    assert v["reason"].startswith("evaluator_unknown")

    stats = client.get("/v1/stats", headers=org["auth"]).json()
    assert stats["breaches"] == 0
    assert stats["evaluator_unknown"] == 1


def test_empty_reason_judge_verdict_is_quarantined(make_org, client, monkeypatch,
                                                   configure_judge):
    """An affirmative breach claim with no usable reason is low-confidence noise,
    not audit evidence — quarantine it as evaluator_unknown."""
    from app.schemas import Verdict
    org = make_org()
    configure_judge(org["org_id"])
    _one_normal_event(client, org)

    bad = Verdict(policy_breach=True, reason="   ", risk_score=70, decision="breach")
    _grade_with_verdict(monkeypatch, bad)

    v = client.get("/v1/logs", headers=org["auth"]).json()["items"][0]["gemini_verdict"]
    assert v["decision"] == "unknown"
    assert v["reason"].startswith("evaluator_unknown")
    assert client.get("/v1/stats", headers=org["auth"]).json()["breaches"] == 0


def test_valid_judge_verdicts_pass_validation(make_org, client, monkeypatch,
                                              configure_judge):
    """A clean, self-consistent judge verdict is persisted unchanged — validation
    only quarantines the malformed ones, it does not swallow honest grades."""
    from app.schemas import Verdict
    org = make_org()
    configure_judge(org["org_id"])
    _one_normal_event(client, org)

    good = Verdict(policy_breach=True, reason="pii exfiltration risk detected",
                   risk_score=88, decision="breach", rules=["pii.exfil"])
    _grade_with_verdict(monkeypatch, good)

    v = client.get("/v1/logs", headers=org["auth"]).json()["items"][0]["gemini_verdict"]
    assert v["decision"] == "breach"
    assert v["policy_breach"] is True
    assert client.get("/v1/stats", headers=org["auth"]).json()["breaches"] == 1


def _grade_each(monkeypatch, verdict_for):
    """Grade all pending rows; the judge answer for a non-terminal row comes from
    verdict_for(meta). Terminal enforcement rows never reach verdict_for."""
    from app import worker as workermod
    monkeypatch.setattr(
        workermod.gemini, "evaluate",
        lambda meta, policy_config=None, history=None, api_key=None, model=None: verdict_for(meta))
    from app.db import SessionLocal
    db = SessionLocal()
    try:
        for row in workermod._claim_batch(db, 100, 300):
            workermod._grade_one(db, row)
    finally:
        db.close()


def test_passport_shows_host_side_enforcement_counts(make_org, client, monkeypatch,
                                                     configure_judge):
    """The compliance passport carries an honest Host-Side Enforcement section:
    allowed / blocked / redacted counts, the policies actually enforced, and
    evaluator-unknown as its own honest non-pass state — never folded into a pass."""
    from app.schemas import Verdict
    # /v1/passport returns a PDF and nothing else — the HTML degrade this used to
    # read from was removed. Capture the document from the renderer's input.
    _captured: dict = {}

    class _FakeHTML:
        def __init__(self, string=None, **kw):
            _captured["html"] = string

        def write_pdf(self):
            return b"%PDF-1.7\nstub\n%%EOF"

    _fake = type(sys)("weasyprint")
    _fake.HTML = _FakeHTML
    monkeypatch.setitem(sys.modules, "weasyprint", _fake)
    org = make_org()
    configure_judge(org["org_id"])

    client.post("/v1/logs/batch", headers=org["auth"],
                json=[_blocked_event(seed="p1", event_type="blocked")])         # seq 1
    client.post("/v1/logs/batch", headers=org["auth"],
                json=[_blocked_event(seed="p2", event_type="redacted")])        # seq 2
    client.post("/v1/logs/batch", headers=org["auth"], json=[{
        "prompt_hash": _h("ok"), "response_hash": _h("okr"),
        "token_count": 10, "policy_tag": "chat"}])                              # seq 3 clean
    client.post("/v1/logs/batch", headers=org["auth"], json=[{
        "prompt_hash": _h("uk"), "response_hash": _h("ukr"),
        "token_count": 10, "policy_tag": "murky"}])                            # seq 4 -> unknown

    def verdict_for(meta):
        if meta["policy_tag"] == "murky":
            # self-contradictory -> quarantined to evaluator_unknown by the worker
            return Verdict(policy_breach=True, reason="unsure", risk_score=40, decision="clean")
        return Verdict(policy_breach=False, reason="no issues found", risk_score=0, decision="clean")

    _grade_each(monkeypatch, verdict_for)

    r = client.post("/v1/passport", headers=org["auth"])
    assert r.status_code == 200, r.text
    assert r.headers["content-type"] == "application/pdf"
    body = _captured["html"]

    assert "Host-Side Enforcement" in body
    assert "prevented from leaving the host" in body
    # Honest per-state counts (blocked/redacted/allowed/evaluator-unknown).
    assert "Prompts Blocked (prevented egress)</dt><dd>1</dd>" in body
    # "Prompts Redacted", not "Responses Redacted". redact mode scrubs the
    # PROMPT before the model sees it — client.py:_evaluate_preflight — so the
    # old label described the wrong half of the interaction in a compliance
    # document.
    assert "Prompts Redacted</dt><dd>1</dd>" in body
    assert "Prompts Allowed to Proceed</dt><dd>2</dd>" in body
    assert "Evaluator Could Not Determine</dt><dd>1</dd>" in body
    # Policies actually enforced, aggregated from event_metadata.policy_rules.
    assert "block.egress" in body
    # Evaluator-unknown must read as an honest non-pass, not a silent success.
    assert "never counted as a compliant pass" in body


def _response_blocked_event(seed: str = "rb"):
    """A response the SDK withheld from the calling application (SDK >= 1.4).

    Unlike a blocked PROMPT, response_hash commits a REAL response: the model ran
    and produced one. That difference is the whole reason it is not `blocked`."""
    return {
        "prompt_hash": _h(f"prompt-{seed}"),
        "response_hash": _h(f"withheld-response-{seed}"),
        "token_count": 42,
        "policy_tag": "chat",
        "event_type": "response_blocked",
        "pii_signals": [],
        "event_metadata": {
            "decision": "blocked_response",
            "blocked_reason": "unsafe_markup",
            "policy_rules": ["response_markup.script_tag"],
        },
    }


def test_response_blocked_skips_the_judge_and_names_the_response(make_org, client,
                                                                 monkeypatch):
    """A withheld response is terminal and locally decided like the other two —
    the judge is never asked — but its reason must say RESPONSE, not egress. The
    prompt DID egress: it reached the provider and the model answered."""
    org = make_org()
    client.post("/v1/logs/batch", headers=org["auth"], json=[_response_blocked_event()])

    calls = []
    _grade_pending(monkeypatch, breach_when=lambda m: True, calls=calls)
    assert calls == [], "a terminal enforcement row must never reach the judge"

    row = client.get("/v1/logs", headers=org["auth"]).json()["items"][0]
    v = row["gemini_verdict"]
    assert row["event_type"] == "response_blocked"
    assert v["decision"] == "response_blocked"
    assert v["policy_breach"] is False
    assert v["reason"].startswith("host_blocked_response:")
    assert not v["reason"].startswith("host_blocked_egress:"), \
        "that phrasing claims the prompt never left the host, which is false here"
    assert "response_markup.script_tag" in v["rules"]


def test_a_truncated_stream_is_graded_normally_not_as_enforcement(make_org, client,
                                                                  monkeypatch,
                                                                  configure_judge):
    """The honesty line, from the backend's side. A stream cut after chunks were
    already delivered arrives as an ordinary `stream` row carrying
    decision=response_truncated. It must be graded like any other interaction —
    if it took the enforcement path it would be recorded as prevented egress, and
    nothing was prevented."""
    org = make_org()
    configure_judge(org["org_id"])
    client.post("/v1/logs/batch", headers=org["auth"], json=[{
        "prompt_hash": _h("tp"), "response_hash": _h("tr"),
        "token_count": 30, "policy_tag": "chat", "event_type": "stream",
        "event_metadata": {"decision": "response_truncated",
                           "blocked_reason": "unsafe_markup",
                           "policy_rules": ["response_markup.script_tag"]},
    }])

    calls = []
    _grade_pending(monkeypatch, breach_when=lambda m: False, calls=calls)
    assert len(calls) == 1, "a truncated stream is an ordinary interaction to grade"

    v = client.get("/v1/logs", headers=org["auth"]).json()["items"][0]["gemini_verdict"]
    assert v["decision"] == "clean"
    assert not str(v["reason"]).startswith("host_blocked")


def test_passport_counts_a_withheld_response_apart_from_a_blocked_prompt(
        make_org, client, monkeypatch, configure_judge):
    """⚠ THE ONE THAT MATTERS. "Prompts Blocked (prevented egress)" must not
    count a withheld response — the prompt was not blocked — and a truncated
    stream must not be counted as enforcement at all, because chunks reached the
    caller and attesting prevention that did not happen is the one thing this
    document must never do."""
    from app.schemas import Verdict
    _captured: dict = {}

    class _FakeHTML:
        def __init__(self, string=None, **kw):
            _captured["html"] = string

        def write_pdf(self):
            return b"%PDF-1.7\nstub\n%%EOF"

    _fake = type(sys)("weasyprint")
    _fake.HTML = _FakeHTML
    monkeypatch.setitem(sys.modules, "weasyprint", _fake)
    org = make_org()
    configure_judge(org["org_id"])

    client.post("/v1/logs/batch", headers=org["auth"],
                json=[_blocked_event(seed="q1", event_type="blocked")])       # seq 1
    client.post("/v1/logs/batch", headers=org["auth"],
                json=[_response_blocked_event(seed="q2")])                    # seq 2
    client.post("/v1/logs/batch", headers=org["auth"], json=[{                # seq 3
        "prompt_hash": _h("q3"), "response_hash": _h("q3r"),
        "token_count": 10, "policy_tag": "chat", "event_type": "stream",
        "event_metadata": {"decision": "response_truncated",
                           "policy_rules": ["response_markup.script_tag"]},
    }])

    _grade_each(monkeypatch, lambda meta: Verdict(
        policy_breach=False, reason="no issues found", risk_score=0, decision="clean"))

    r = client.post("/v1/passport", headers=org["auth"])
    assert r.status_code == 200, r.text
    body = _captured["html"]

    assert "Prompts Blocked (prevented egress)</dt><dd>1</dd>" in body
    assert "Responses Withheld from the Application</dt><dd>1</dd>" in body
    # Two enforced (the block and the withheld response); the truncated stream is
    # NOT one of them, so it lands in "allowed to proceed" — which is the honest
    # answer, because its chunks did proceed.
    assert "Enforced in Total</dt><dd>2</dd>" in body
    assert "Prompts Allowed to Proceed</dt><dd>1</dd>" in body
    # The response-side rule id is aggregated with the rest of the enforcement.
    assert "response_markup.script_tag" in body


def test_stats_and_ledger_filter_see_a_withheld_response(make_org, client):
    """It gets its own count rather than inflating `blocked`, and the ledger can
    be filtered to it."""
    org = make_org()
    client.post("/v1/logs/batch", headers=org["auth"],
                json=[_blocked_event(seed="s1", event_type="blocked")])
    client.post("/v1/logs/batch", headers=org["auth"], json=[_response_blocked_event("s2")])

    stats = client.get("/v1/stats", headers=org["auth"]).json()
    assert stats["blocked"] == 1
    assert stats["response_blocked"] == 1

    rb = client.get("/v1/logs?verdict=response_blocked", headers=org["auth"]).json()
    assert [r["seq"] for r in rb["items"]] == [2]
    assert rb["items"][0]["event_type"] == "response_blocked"

    # Every surface badges a withheld response "blocked" (the dashboard's
    # verdictOf, the desktop's verdict_of), so the Blocked filter has to return
    # it — otherwise a row visibly labelled blocked vanishes under Blocked.
    both = client.get("/v1/logs?verdict=blocked", headers=org["auth"]).json()
    assert sorted(r["seq"] for r in both["items"]) == [1, 2], \
        "the Blocked filter must match both terminal block types"
    assert {r["event_type"] for r in both["items"]} == {"blocked", "response_blocked"}


def test_a_redacted_rows_pii_signals_do_not_make_it_a_breach(make_org, client,
                                                             monkeypatch,
                                                             configure_judge):
    """The blast radius of SDK #158, pinned end to end.

    Non-empty `pii_signals` IS a deterministic breach — but only on the path
    `policy_engine.evaluate` takes. A `redacted` row is in
    ENFORCEMENT_EVENT_TYPES, so BOTH the ingest verdict (routers/logs.py) and
    the worker's grade route to `evaluate_enforcement`, which never reads
    pii_signals and always returns policy_breach False.

    So SDK 1.5.0 folding response-side PII labels into redact rows cannot turn a
    clean row into a breach. It changes which labels are displayed and what the
    chain covers, not the breach count — and this test is what makes that a
    measurement rather than a reading of the source."""
    from app.schemas import Verdict
    org = make_org()
    configure_judge(org["org_id"])

    # Same row twice, differing only in how much PII the SDK reported.
    client.post("/v1/logs/batch", headers=org["auth"],
                json=[_blocked_event(seed="r-quiet", event_type="redacted",
                                     pii_signals=())])                       # seq 1
    client.post("/v1/logs/batch", headers=org["auth"],
                json=[_blocked_event(seed="r-loud", event_type="redacted",
                                     pii_signals=("email", "ssn_pattern",
                                                  "ip_address", "phone"))])  # seq 2
    # An ordinary interaction with the same labels, for contrast: this one DOES
    # become a breach, which is what proves the check is live at all.
    client.post("/v1/logs/batch", headers=org["auth"], json=[{
        "prompt_hash": _h("i"), "response_hash": _h("ir"),
        "token_count": 10, "policy_tag": "chat",
        "pii_signals": ["email"]}])                                          # seq 3

    _grade_each(monkeypatch, lambda meta: Verdict(
        policy_breach=False, reason="no issues found", risk_score=0, decision="clean"))

    rows = {r["seq"]: r for r in client.get("/v1/logs", headers=org["auth"]).json()["items"]}

    # BOTH verdicts, because they are produced by different code on different
    # paths: local_verdict is the deterministic one computed at ingest and bound
    # into the chain, gemini_verdict is the graded one every UI counts.
    for seq in (1, 2):
        assert rows[seq]["local_verdict"]["policy_breach"] is False, \
            f"seq {seq}: the CHAINED verdict became a breach"
        assert rows[seq]["gemini_verdict"]["policy_breach"] is False, \
            f"seq {seq}: the GRADED verdict became a breach"
        assert rows[seq]["gemini_verdict"]["decision"] == "redacted"
    assert rows[2]["pii_signals"] == ["email", "ssn_pattern", "ip_address", "phone"], \
        "the labels are still recorded; they simply do not drive the verdict"

    # The control. The SAME kind of label on a NON-enforcement row does breach
    # the deterministic verdict — so the check is live, and the two assertions
    # above are about routing rather than about a dead rule.
    assert rows[3]["local_verdict"]["policy_breach"] is True, \
        "pii_signals is no longer a breach trigger anywhere; the premise moved"
    assert "local_pii_signal" in rows[3]["local_verdict"]["rules"]

    # The graded count is what the dashboard, the breach feed and the Passport
    # all read, and no redacted row is in it.
    stats = client.get("/v1/stats", headers=org["auth"]).json()
    assert stats["breaches"] == 0, "a redacted row was counted as a breach"


def test_coverage_ids_are_not_counted_as_enforced_rules(make_org, client, monkeypatch,
                                                        configure_judge):
    """response_scan.degraded / .unreadable record what the SDK's scan COULD NOT
    READ. They belong in the ledger, and they must not appear in the Passport's
    "Policy rule enforced / Times fired" table — "we could not read the response,
    40 times" listed beside phi.ssn_pattern reads as a control that fired."""
    from app.schemas import Verdict
    _captured: dict = {}

    class _FakeHTML:
        def __init__(self, string=None, **kw):
            _captured["html"] = string

        def write_pdf(self):
            return b"%PDF-1.7\nstub\n%%EOF"

    _fake = type(sys)("weasyprint")
    _fake.HTML = _FakeHTML
    monkeypatch.setitem(sys.modules, "weasyprint", _fake)
    org = make_org()
    configure_judge(org["org_id"])

    event = _response_blocked_event(seed="cov")
    event["event_metadata"]["policy_rules"] = ["response_markup.script_tag",
                                               "response_scan.degraded",
                                               "response_scan.unreadable"]
    client.post("/v1/logs/batch", headers=org["auth"], json=[event])
    _grade_each(monkeypatch, lambda meta: Verdict(
        policy_breach=False, reason="no issues found", risk_score=0, decision="clean"))

    r = client.post("/v1/passport", headers=org["auth"])
    assert r.status_code == 200, r.text
    body = _captured["html"]

    # The real rule is tallied; the coverage ids are not.
    assert "response_markup.script_tag" in body
    assert "response_scan.degraded" not in body
    assert "response_scan.unreadable" not in body


def test_ledger_filter_surfaces_enforcement_rows_distinctly(make_org, client):
    """The ledger can be filtered to host-side enforcement rows so the record shows
    enforcement, not just observations. Each row carries event_type so the dashboard
    can badge blocked/redacted distinctly."""
    org = make_org()
    client.post("/v1/logs/batch", headers=org["auth"],
                json=[_blocked_event(seed="f1", event_type="blocked")])         # seq 1
    client.post("/v1/logs/batch", headers=org["auth"],
                json=[_blocked_event(seed="f2", event_type="redacted")])        # seq 2
    client.post("/v1/logs/batch", headers=org["auth"], json=[{
        "prompt_hash": _h("n"), "response_hash": _h("nr"),
        "token_count": 10, "policy_tag": "chat"}])                              # seq 3

    b = client.get("/v1/logs?verdict=blocked", headers=org["auth"]).json()
    assert [r["seq"] for r in b["items"]] == [1]
    assert b["items"][0]["event_type"] == "blocked"

    rd = client.get("/v1/logs?verdict=redacted", headers=org["auth"]).json()
    assert [r["seq"] for r in rd["items"]] == [2]
    assert rd["items"][0]["event_type"] == "redacted"

    # The unfiltered ledger still returns every row, enforcement rows included.
    assert client.get("/v1/logs", headers=org["auth"]).json()["total"] == 3

    # /v1/stats surfaces the enforcement counts so the dashboard never mislabels a
    # blocked/redacted event as a clean pass.
    stats = client.get("/v1/stats", headers=org["auth"]).json()
    assert stats["blocked"] == 1
    assert stats["redacted"] == 1
