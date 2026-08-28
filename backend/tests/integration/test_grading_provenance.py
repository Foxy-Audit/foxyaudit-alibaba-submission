"""#228 — the ledger says WHO graded each event, and it is not a null to interpret.

The defect this file exists to keep closed. `gemini.evaluate` returns
`_fallback("no_api_key")` when no key is reachable, and `worker._grade_one`
REPLACED that verdict wholesale with `policy_engine.evaluate`. The stored row
then read `decision: "clean"` under a confident reason, in the same column and
the same shape as an AI grade, and the only thing separating it from one was
`judge_provider` being null inside a JSON blob — a null a reader has to know to
look for, and one that is equally null on a row a judge answered badly. Every
locally graded event in this project's history was graded by rules, and nothing
in the record said so.

What is asserted here is the RECORD — the stored verdict, the exported bytes,
the rendered Passport — never a count of keys or a count of dict entries. A
guard that counted keys would stay green under a mutant that stamped every row
"ai".

⚠ THE PROMPT-BLOCKING HALF IS A DIFFERENT THING AND IS NOT WEAKENED HERE. The
host guard that stops PHI before the model call is real, and its verdicts say
`graded_by="host_enforcement"` — the host decided them, no model was involved,
and there was no model response to grade. That is a positive statement too.
"""

from __future__ import annotations

import hashlib
import importlib.util
import json
import os
import sys
import uuid
from types import SimpleNamespace

import pytest
from sqlalchemy import text

from app import chain, gemini, judge, openai_judge, policy_engine
from app import worker as workermod
from app.crypto_secrets import encrypt_secret
from app.db import SessionLocal, engine
from app.models import OrgPolicy, Organization
from app.schemas import Verdict

_h = lambda s: hashlib.sha256(s.encode()).hexdigest()  # noqa: E731

TENANT_OPENAI = "sk-proj-TENANT-OWN-OPENAI"


# ── helpers ──────────────────────────────────────────────────────────────────

def _configure(org_id, *, provider="gemini", key_mode="own",
               gemini_key=None, openai_key=None, plan_tier=None) -> None:
    db = SessionLocal()
    try:
        oid = uuid.UUID(str(org_id))
        row = db.get(OrgPolicy, oid) or OrgPolicy(org_id=oid)
        row.judge_provider = provider
        row.judge_key_mode = key_mode
        row.gemini_key_enc = encrypt_secret(gemini_key, oid, "gemini") if gemini_key else None
        row.openai_key_enc = encrypt_secret(openai_key, oid, "openai") if openai_key else None
        db.add(row)
        db.get(Organization, oid).plan_tier = plan_tier
        db.commit()
    finally:
        db.close()


def _ingest(client, org, seed="a", **extra) -> None:
    body = {"prompt_hash": _h(f"p-{seed}"), "response_hash": _h(f"r-{seed}"),
            "token_count": 42, "policy_tag": "chat"}
    body.update(extra)
    assert client.post("/v1/logs/batch", headers=org["auth"], json=[body]).status_code == 202


def _grade_all() -> None:
    db = SessionLocal()
    try:
        for row in workermod._claim_batch(db, 25, 300):
            workermod._grade_one(db, row)
    finally:
        db.close()


def _stored(org_id) -> list[dict]:
    """The verdicts as they are ON DISK, read back through SQL rather than from
    the object the worker happened to be holding."""
    with engine.begin() as conn:
        return [r[0] for r in conn.execute(text(
            "SELECT gemini_verdict FROM audit_logs WHERE org_id = :o ORDER BY seq"),
            {"o": str(org_id)}).all()]


class _Response:
    def __init__(self, payload):
        self.payload = payload

    def __enter__(self):
        return self

    def __exit__(self, *_args):
        return False

    def read(self):
        return json.dumps(self.payload).encode("utf-8")


def _real_openai_judge(monkeypatch, *, breach=False, reason="metadata looks ordinary"):
    """Route grading through the REAL openai_judge.evaluate, stubbed at the
    SOCKET rather than at the module.

    Deliberately not a fake `evaluate` returning a hand-built Verdict: that
    would assert the stub's own `graded_by`, and the line under test — the one
    that stamps "ai" — would never run. The transport is the only thing faked.
    """
    payload = {"output_text": json.dumps({
        "policy_breach": breach, "reason": reason,
        "risk_score": 90 if breach else 1,
        "decision": "breach" if breach else "clean", "rules": [],
    })}
    monkeypatch.setattr(openai_judge.urllib_request, "urlopen",
                        lambda *a, **k: _Response(payload))


# ── the core fact: a rules-graded row says so ────────────────────────────────

def test_a_row_the_ai_never_graded_says_so_in_the_stored_record(make_org, client):
    """No key anywhere → the deterministic engine grades the row, and the row
    states that, positively, instead of leaving a null to be interpreted."""
    org = make_org()
    _configure(org["org_id"], provider="gemini", key_mode="own", gemini_key=None)
    _ingest(client, org)
    _grade_all()

    verdict, = _stored(org["org_id"])
    assert verdict["graded_by"] == "rules"
    # And WHY the model never ran, structurally — not parsed back out of a string.
    assert verdict["evaluator_unavailable_reason"] == "no_byok_key"
    # The grade itself is unchanged: still a real determination of the metadata.
    assert verdict["decision"] == "clean"
    assert verdict["judge_provider"] is None


def test_a_rules_graded_row_is_not_indistinguishable_from_an_ai_graded_one(
        make_org, client, monkeypatch):
    """THE DEFECT, stated as a difference between two real rows.

    Two orgs, one batch of grading, identical payloads: one has a usable key and
    reaches a (socket-stubbed) model, the other has none. Their stored verdicts
    must differ in a way a reader can SEE — not in a null they have to know to
    look for. A mutant that makes the two records equal fails here.
    """
    graded = make_org()
    ungraded = make_org()
    _configure(graded["org_id"], provider="openai", key_mode="own",
               openai_key=TENANT_OPENAI)
    _configure(ungraded["org_id"], provider="openai", key_mode="own", openai_key=None)
    _real_openai_judge(monkeypatch)

    _ingest(client, graded, seed="same")
    _ingest(client, ungraded, seed="same")
    _grade_all()

    ai, = _stored(graded["org_id"])
    rules, = _stored(ungraded["org_id"])

    # Both are a confident clean. That is exactly why the record has to say more.
    assert ai["decision"] == rules["decision"] == "clean"
    assert ai["policy_breach"] is rules["policy_breach"] is False
    # The distinction is a stated fact, present on both rows.
    assert ai["graded_by"] == "ai"
    assert rules["graded_by"] == "rules"
    assert ai["graded_by"] != rules["graded_by"]
    # And it is not merely the old null-tell renamed: the AI row names its model.
    assert ai["judge_provider"] == "openai"
    assert ai["evaluator_unavailable_reason"] is None
    assert rules["evaluator_unavailable_reason"] == "no_byok_key"


@pytest.mark.parametrize("ciphertext,expected", [
    (None, "no_byok_key"),
    ("   ", "no_byok_key"),
    ("not-a-fernet-token", "byok_key_undecryptable"),
])
def test_the_reason_the_ai_did_not_run_survives_the_substitution(
        make_org, client, ciphertext, expected):
    """`routing.problems` already told these apart; the worker used to discard
    the verdict carrying them. Each one now reaches the stored row."""
    org = make_org()
    _configure(org["org_id"], provider="gemini", key_mode="own", gemini_key=None)
    if ciphertext is not None:
        db = SessionLocal()
        try:
            row = db.get(OrgPolicy, uuid.UUID(str(org["org_id"])))
            row.gemini_key_enc = ciphertext
            db.commit()
        finally:
            db.close()

    _ingest(client, org)
    _grade_all()

    verdict, = _stored(org["org_id"])
    assert verdict["graded_by"] == "rules"
    assert verdict["evaluator_unavailable_reason"] == expected


# ── Q2 · "rules graded it" is not the same KIND as "the judge was incoherent" ─

def test_a_refused_judge_and_the_rules_engine_do_not_look_the_same(
        make_org, client, monkeypatch):
    """A model that RAN and answered incoherently is a different event from a
    model that never ran, and both differ from a rules grade.

    An operator has to be able to see a provider returning garbage — it was
    reached, and it was billed. That must never read as "this deployment has no
    key".
    """
    incoherent = make_org()
    keyless = make_org()
    _configure(incoherent["org_id"], provider="openai", key_mode="own",
               openai_key=TENANT_OPENAI)
    _configure(keyless["org_id"], provider="openai", key_mode="own", openai_key=None)
    # policy_breach True under decision "clean" — judge.validate must refuse it.
    monkeypatch.setattr(openai_judge.urllib_request, "urlopen",
                        lambda *a, **k: _Response({"output_text": json.dumps({
                            "policy_breach": True, "reason": "fine",
                            "risk_score": 0, "decision": "clean", "rules": []})}))

    _ingest(client, incoherent)
    _ingest(client, keyless)
    _grade_all()

    refused, = _stored(incoherent["org_id"])
    rules, = _stored(keyless["org_id"])

    # Neither is a grade — but they are not the same non-grade.
    assert refused["graded_by"] == "none"
    assert rules["graded_by"] == "rules"
    # The refused one kept the provenance of the answer it threw away, and its
    # reason names the refusal rather than an absence.
    assert refused["judge_provider"] == "openai"
    assert refused["reason"].startswith("evaluator_unknown:")
    assert refused["evaluator_unavailable_reason"] is None
    # The keyless one names an absence and no provider.
    assert rules["evaluator_unavailable_reason"] == "no_byok_key"
    assert rules["judge_provider"] is None


def test_host_enforcement_verdicts_claim_the_host_and_not_a_model(make_org, client):
    """The prompt-blocking half is real and stays real — and it is honest about
    its own author: the host decided it, and no model was involved."""
    org = make_org()
    _configure(org["org_id"], provider="gemini", key_mode="own", gemini_key=None)
    _ingest(client, org, event_type="blocked",
            event_metadata={"decision": "blocked", "blocked_reason": "phi",
                            "policy_rules": ["phi.ssn_pattern"]})
    _grade_all()

    verdict, = _stored(org["org_id"])
    assert verdict["graded_by"] == "host_enforcement"
    assert verdict["decision"] == "blocked"
    assert verdict["policy_breach"] is False
    # Never conflated with the rules engine's metadata reasoning.
    assert verdict["graded_by"] != "rules"


# ── surface 1 · the exports ──────────────────────────────────────────────────

def test_the_fact_reaches_the_customers_own_export(make_org, client):
    """Both verdicts ship in `GET /v1/logs/export`; both must carry the author."""
    org = make_org()
    _configure(org["org_id"], provider="gemini", key_mode="own", gemini_key=None)
    _ingest(client, org)
    _grade_all()

    body = client.get("/v1/logs/export", headers=org["auth"]).json()
    row, = body["logs"]
    assert row["local_verdict"]["graded_by"] == "rules"
    assert row["gemini_verdict"]["graded_by"] == "rules"
    assert row["gemini_verdict"]["evaluator_unavailable_reason"] == "no_byok_key"


def test_the_fact_reaches_the_dsar_bundle_too(make_org, client, login):
    """#269 made the DSAR ledger and the log export ONE projection
    (`logs._export_row`). A fact that reached only one of them would mean the
    two had come apart again."""
    org = make_org()
    _configure(org["org_id"], provider="gemini", key_mode="own", gemini_key=None)
    _ingest(client, org)
    _grade_all()

    admin = login(org["admin_email"], org["admin_password"])
    bundle = admin.get("/v1/account/export").json()
    row, = bundle["ledger"]
    assert row["local_verdict"]["graded_by"] == "rules"
    assert row["gemini_verdict"]["graded_by"] == "rules"


# ── the chain · no version bump, and history is untouched ────────────────────

def _verifier():
    path = os.path.join(os.path.dirname(__file__), "..", "..", "..",
                        "verifier", "foxy_verify.py")
    spec = importlib.util.spec_from_file_location("foxy_verify", path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_a_row_written_before_graded_by_existed_still_verifies(make_org, client):
    """THE CLAIM THIS PHASE RESTS ON, proved by driving the real verifier.

    V4 binds `chain.verdict_hash_hex(local_verdict)` — a digest over THAT ROW'S
    OWN verdict body. So a new field changes future rows' digests
    self-consistently and cannot touch a historical row, whose body never had
    it. Argued, that is a claim; here a genuinely pre-#228 row is written back
    into the ledger — its `local_verdict` stripped of the new keys and its
    `verdict_hash` / `chain_hash` recomputed the way the old code would have —
    then exported and verified by the INDEPENDENT verifier, beside a new row.

    No chain version bump is needed and none is taken: `chain_version` stays 4
    on both rows. A control tampers with a genuinely hashed field afterwards, so
    a verifier that said "ok" to everything could not pass both halves.
    """
    org = make_org()
    _ingest(client, org, seed="legacy")
    _ingest(client, org, seed="modern")

    db = SessionLocal()
    try:
        oid = uuid.UUID(str(org["org_id"]))
        row = db.execute(text(
            "SELECT id, local_verdict, prompt_hash, response_hash, token_count, "
            "       policy_tag, seq, prev_hash, agent, chain_version, event_id, "
            "       client_id, client_seq, event_type, commitment_alg, "
            "       event_metadata, pii_signals, occurred_at "
            "FROM audit_logs WHERE org_id = :o ORDER BY seq LIMIT 1"),
            {"o": str(oid)}).mappings().first()
        legacy_verdict = {k: v for k, v in row["local_verdict"].items()
                          if k not in ("graded_by", "evaluator_unavailable_reason")}
        assert "graded_by" not in legacy_verdict          # the strip really happened
        assert row["chain_version"] == 4
        legacy_hash = chain.verdict_hash_hex(legacy_verdict)
        legacy_chain = chain.compute_chain_hash(
            org_id=oid, prompt_hash=row["prompt_hash"],
            response_hash=row["response_hash"], token_count=row["token_count"],
            policy_tag=row["policy_tag"], seq=row["seq"], prev_hash=row["prev_hash"],
            agent=row["agent"], chain_version=row["chain_version"],
            event_id=row["event_id"], client_id=row["client_id"],
            client_seq=row["client_seq"], event_type=row["event_type"],
            commitment_alg=row["commitment_alg"],
            event_metadata=row["event_metadata"], pii_signals=row["pii_signals"],
            occurred_at=row["occurred_at"], verdict_hash=legacy_hash)
        db.execute(text(
            "UPDATE audit_logs SET local_verdict = CAST(:v AS jsonb), "
            "verdict_hash = :vh, chain_hash = :ch WHERE id = :id"),
            {"v": json.dumps(legacy_verdict), "vh": legacy_hash,
             "ch": legacy_chain, "id": row["id"]})
        # Row 2 links to row 1, so its prev_hash and hash follow the rewrite.
        second = db.execute(text(
            "SELECT id, prompt_hash, response_hash, token_count, policy_tag, seq, "
            "       agent, chain_version, event_id, client_id, client_seq, "
            "       event_type, commitment_alg, event_metadata, pii_signals, "
            "       occurred_at, verdict_hash "
            "FROM audit_logs WHERE org_id = :o AND seq = 2"),
            {"o": str(oid)}).mappings().first()
        second_chain = chain.compute_chain_hash(
            org_id=oid, prompt_hash=second["prompt_hash"],
            response_hash=second["response_hash"],
            token_count=second["token_count"], policy_tag=second["policy_tag"],
            seq=second["seq"], prev_hash=legacy_chain, agent=second["agent"],
            chain_version=second["chain_version"], event_id=second["event_id"],
            client_id=second["client_id"], client_seq=second["client_seq"],
            event_type=second["event_type"],
            commitment_alg=second["commitment_alg"],
            event_metadata=second["event_metadata"],
            pii_signals=second["pii_signals"], occurred_at=second["occurred_at"],
            verdict_hash=second["verdict_hash"])
        db.execute(text(
            "UPDATE audit_logs SET prev_hash = :ph, chain_hash = :ch WHERE id = :id"),
            {"ph": legacy_chain, "ch": second_chain, "id": second["id"]})
        db.commit()
    finally:
        db.close()

    export = client.get("/v1/logs/export", headers=org["auth"]).json()
    old, new = export["logs"]
    assert "graded_by" not in old["local_verdict"]         # genuinely pre-#228
    assert new["local_verdict"]["graded_by"] == "rules"    # genuinely post
    assert old["chain_version"] == new["chain_version"] == 4

    fv = _verifier()
    result = fv.verify_export(export)
    assert result["ok"] is True, result

    # Control: the verifier is not simply agreeing with everything.
    export["logs"][1]["token_count"] = 999
    assert fv.verify_export(export)["ok"] is False


def test_the_verifier_still_catches_a_rewritten_verdict(make_org, client):
    """The new field is inside the body `verdict_hash` covers, so editing it —
    to upgrade a rules grade into an AI one, say — has to break verification.
    Otherwise the field is decoration rather than evidence."""
    org = make_org()
    _configure(org["org_id"], provider="gemini", key_mode="own", gemini_key=None)
    _ingest(client, org)
    _grade_all()

    export = client.get("/v1/logs/export", headers=org["auth"]).json()
    fv = _verifier()
    assert fv.verify_export(export)["ok"] is True

    export["logs"][0]["local_verdict"]["graded_by"] = "ai"
    assert fv.verify_export(export)["ok"] is False, (
        "a rewritten local_verdict passed verification — verdict_hash is not "
        "binding the authorship claim"
    )


# ── surface 3 · content-blindness is not widened ─────────────────────────────

def test_nothing_added_here_reaches_a_provider(monkeypatch):
    """A verdict is produced AFTER the provider call; none of it may travel with
    the metadata that goes out. Asserted against the real request body."""
    assert "graded_by" not in judge.SAFE_EVENT_METADATA
    assert "evaluator_unavailable_reason" not in judge.SAFE_EVENT_METADATA

    projected = judge.content_blind_meta({
        "prompt_hash": "a" * 64, "token_count": 5,
        "graded_by": "ai", "evaluator_unavailable_reason": "no_api_key",
        "event_metadata": {"model": "gpt-4", "graded_by": "ai"},
    })
    assert "graded_by" not in projected
    assert "evaluator_unavailable_reason" not in projected
    assert "graded_by" not in projected["event_metadata"]

    captured = {}
    monkeypatch.setattr(openai_judge, "get_settings", lambda: SimpleNamespace(
        openai_api_key="k", openai_model="gpt-5.6", openai_timeout=2.0,
        gemini_fail_closed=False))

    def capture(request, *a, **k):
        captured["body"] = request.data.decode("utf-8")
        return _Response({"output_text": json.dumps({
            "policy_breach": False, "reason": "ok", "risk_score": 0,
            "decision": "clean", "rules": []})})

    monkeypatch.setattr(openai_judge.urllib_request, "urlopen", capture)
    openai_judge.evaluate(judge.content_blind_meta(
        {"token_count": 1, "graded_by": "rules"}))
    assert "graded_by" not in captured["body"]


# ── surface 2 · the Compliance Passport ──────────────────────────────────────

def _passport_html(client, org, monkeypatch) -> str:
    """Render the real Passport and read the HTML the PDF engine was handed.

    /v1/passport answers with a PDF and nothing else, so the document is
    inspected from weasyprint's input — the same shape test_passport.py uses.
    The whole route and the whole context assembly still run.
    """
    captured: dict = {}

    class _FakeHTML:
        def __init__(self, string=None, **kw):
            captured["html"] = string

        def write_pdf(self):
            return b"%PDF-1.7 stub %%EOF"

    fake = type(sys)("weasyprint")
    fake.HTML = _FakeHTML
    monkeypatch.setitem(sys.modules, "weasyprint", fake)

    response = client.post("/v1/passport", headers=org["auth"])
    assert response.status_code == 200, response.text
    return captured["html"]


def test_the_passport_states_that_no_ai_graded_the_period(
        make_org, client, monkeypatch):
    """The sharpest instance: the document a customer hands an auditor.

    It reported a compliance rate and an "Evaluator Could Not Determine: 0"
    while every verdict behind those numbers came from the rules engine — and a
    zero there reads as "the AI judge determined all the rest".
    """
    org = make_org()
    _configure(org["org_id"], provider="gemini", key_mode="own", gemini_key=None)
    _ingest(client, org)
    _grade_all()

    html = _passport_html(client, org, monkeypatch)
    assert "What graded these events" in html
    assert "No event in this period was graded by an AI model." in html
    assert "Graded by deterministic rules only" in html


def test_the_passport_does_not_say_that_when_a_model_did_grade(
        make_org, client, monkeypatch):
    """The counterpart, and the reason the sentence above is worth anything: it
    is driven by the record, so it disappears the moment a model really grades.
    Without this, a passport hard-coded to the denial would pass the test
    above."""
    org = make_org()
    _configure(org["org_id"], provider="openai", key_mode="own",
               openai_key=TENANT_OPENAI)
    _real_openai_judge(monkeypatch)
    _ingest(client, org)
    _grade_all()

    html = _passport_html(client, org, monkeypatch)
    assert "No event in this period was graded by an AI model." not in html
    assert "Graded by an AI model" in html


# ── surface 4 · the counters a dashboard would read ──────────────────────────

def test_stats_counts_authorship_from_the_record(make_org, client, monkeypatch):
    """A number built on the deployment's key setting would be the same lie one
    layer up, so these are grouped out of `gemini_verdict.graded_by`."""
    org = make_org()
    _configure(org["org_id"], provider="openai", key_mode="own",
               openai_key=TENANT_OPENAI)
    _real_openai_judge(monkeypatch)
    _ingest(client, org, seed="ai-1")
    _grade_all()

    # Same org, key removed: the next events cannot reach a model.
    _configure(org["org_id"], provider="openai", key_mode="own", openai_key=None)
    _ingest(client, org, seed="rules-1")
    _ingest(client, org, seed="rules-2")
    _grade_all()

    response = client.get("/v1/stats", headers=org["auth"])
    assert response.status_code == 200, response.text
    stats = response.json()
    assert stats["ai_graded"] == 1
    assert stats["rules_graded"] == 2
    # The counters describe THIS org's rows, not what this deployment is
    # configured with — the field that does the latter is a separate question.
    assert stats["grading"]["graded"] == 3


def test_usage_daily_does_not_claim_an_author():
    """A deliberate no-op, pinned. `usage_daily.graded_count` names the outbox
    LIFECYCLE state, which is true whoever graded the row, so it conflates
    nothing — and a future edit making it mean "AI graded" would be #228 rebuilt
    in the rollup. The expression is asserted so that change cannot pass
    unnoticed."""
    from app import usage
    sql = str(usage._ROLLUP_SQL) + str(usage._BACKFILL_SQL)
    assert "graded_by" not in sql, (
        "usage_daily now reads the grader — if that is intended it needs a "
        "migration and a column whose NAME says which grader it counts"
    )
    assert "grading_status = 'graded'" in sql


# ── the vocabulary is total: no producer may leave it unset ──────────────────

def test_every_verdict_the_grading_path_produces_names_its_author():
    """Totality, by EXECUTION over each producer. A `graded_by` some path leaves
    None is the old null-to-interpret wearing a new field name."""
    settings = SimpleNamespace(gemini_fail_closed=False)
    produced = [
        policy_engine.evaluate({"token_count": 1}),
        policy_engine.evaluate({"token_count": 1, "pii_signals": ["ssn"]}),
        policy_engine.evaluate_enforcement({"event_type": "blocked",
                                            "event_metadata": {}}),
        judge.validate(Verdict(policy_breach=True, decision="clean", reason="x")),
        judge.combine(Verdict(decision="clean", reason="a", judge_provider="gemini"),
                      Verdict(decision="breach", policy_breach=True, reason="b",
                              judge_provider="openai")),
    ]
    for module in (gemini, openai_judge):
        original = module.get_settings
        module.get_settings = lambda: settings
        try:
            produced.append(module._fallback("no_api_key"))
        finally:
            module.get_settings = original

    assert [v.graded_by for v in produced] == [
        "rules", "rules", "host_enforcement", "none", "ai", "none", "none"]
    assert all(v.graded_by is not None for v in produced)


def test_graded_by_is_a_closed_vocabulary():
    """An unrecognised author is a 422 at construction, not a string that ends
    up in an evidence export."""
    with pytest.raises(Exception):
        Verdict(graded_by="gemini-2.5-flash")
    with pytest.raises(Exception):
        Verdict(graded_by="")
    # None stays legal — it is how a pre-#228 row round-trips, and it means
    # "not recorded", never "no AI".
    assert Verdict(graded_by=None).graded_by is None
