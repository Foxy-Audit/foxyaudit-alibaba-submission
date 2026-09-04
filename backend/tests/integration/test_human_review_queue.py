"""A1 — the escalation gets a destination, and resolving it never rewrites the chain.

`qwen_judge` can call `flag_for_human_review` and return `decision="human_review"`
(Q2a). Until this phase nothing received it. `worker._grade_one` has exactly one
post-commit notification branch and it gates on `verdict.policy_breach`, which is
`False` BY DESIGN on an escalation (`judge.py:230`, `schemas.py:339-342`), so an
escalated row notified nobody and appeared in no queue: a determination the model
made deliberately, recorded and then dropped.

⚠ THE ASSERTION THIS FILE EXISTS FOR is the last one,
`test_the_chain_hash_is_byte_identical_before_and_after_a_review_resolves`.
`chain.verdict_hash_hex` binds the LOCAL, SDK-side verdict — that is the whole
reason the worker may write an AI verdict AFTER the row is chained. A human
decision has to respect the same boundary, so it lands in two places on purpose:
a mutable `human_reviews` row (the queue) and an append-only
`AuditEvent(event_type="human_review_resolved")` (the evidence). If resolving can
move a chain hash, A1's design is wrong, not this test.

⚠ AND THIS IS THE FIRST INTEGRATION COVERAGE QWEN HAS. The three-provider fold in
`worker._judge_verdict` was pinned only by AST-parsing `worker.py`
(`tests/test_qwen_judge.py`), never by execution, because
`judge_helpers.give_judge_key()` took `gemini_key` and `openai_key` and no
`qwen_key` — so no org could be routed to Qwen at all. Grading here runs the REAL
`qwen_judge.evaluate`, stubbed at the SOCKET. A fake `evaluate` returning a
hand-built Verdict would assert the stub, and the escalation path — the tool-call
parse, the fold, the worker branch — would never run.
"""

from __future__ import annotations

import hashlib
import json
import threading
import time

import pytest
from sqlalchemy import text

from app import org_notifications, qwen_judge
from app import worker as workermod
from app.db import SessionLocal, engine

from tests.integration.judge_helpers import give_judge_key

_h = lambda s: hashlib.sha256(s.encode()).hexdigest()  # noqa: E731

TENANT_QWEN = "sk-TENANT-OWN-QWEN"


# ── driving a real escalation ────────────────────────────────────────────────

class _Response:
    def __init__(self, payload):
        self.payload = payload

    def __enter__(self):
        return self

    def __exit__(self, *_args):
        return False

    def read(self):
        return json.dumps(self.payload).encode("utf-8")


def _speak(monkeypatch, message) -> None:
    """Make the configured Qwen endpoint answer with `message`, at the socket."""
    monkeypatch.setattr(
        qwen_judge.urllib_request, "urlopen",
        lambda *_a, **_k: _Response({"choices": [{"message": message}]}))


def _tool_call(reason="a clinical tag on a finance policy — unclear which applies",
               risk_score=55):
    return {"tool_calls": [{"type": "function", "function": {
        "name": "flag_for_human_review",
        "arguments": json.dumps({"reason": reason, "risk_score": risk_score})}}]}


def _graded(decision="clean", policy_breach=False, risk_score=2):
    return {"content": json.dumps(
        {"policy_breach": policy_breach, "reason": "metadata looks ordinary",
         "risk_score": risk_score, "decision": decision, "rules": []})}


def _route_to_qwen(org_id) -> None:
    give_judge_key(org_id, provider="qwen", key_mode="own",
                   gemini_key=None, qwen_key=TENANT_QWEN)


def _ingest(client, org, seed="a") -> None:
    body = {"prompt_hash": _h(f"p-{seed}"), "response_hash": _h(f"r-{seed}"),
            "token_count": 42, "policy_tag": "chat"}
    assert client.post("/v1/logs/batch", headers=org["auth"],
                       json=[body]).status_code == 202


def _grade_all() -> None:
    db = SessionLocal()
    try:
        for row in workermod._claim_batch(db, 25, 300):
            workermod._grade_one(db, row)
    finally:
        db.close()


def _requeue_for_retry(org_id) -> None:
    """Exactly what `worker._MARK_RETRY_SQL` does after a failure: the row goes
    back to 'pending' and `_grade_one` is entered again for it."""
    with engine.begin() as conn:
        conn.execute(text("UPDATE audit_logs SET grading_status = 'pending' "
                          "WHERE org_id = :o"), {"o": str(org_id)})


# ── read-back, through SQL rather than the object under test ─────────────────

def _reviews(org_id) -> list[dict]:
    with engine.begin() as conn:
        return [dict(r) for r in conn.execute(text(
            "SELECT id, audit_log_id, status, resolution, reason, risk_score, "
            "       note, resolved_by "
            "  FROM human_reviews WHERE org_id = :o ORDER BY created_at"),
            {"o": str(org_id)}).mappings().all()]


def _chain_hashes(org_id) -> list[tuple]:
    with engine.begin() as conn:
        return [tuple(r) for r in conn.execute(text(
            "SELECT seq, prev_hash, chain_hash, verdict_hash FROM audit_logs "
            " WHERE org_id = :o ORDER BY seq"), {"o": str(org_id)}).all()]


def _event_count(org_id, event_type) -> int:
    with engine.begin() as conn:
        return conn.execute(text(
            "SELECT COUNT(*) FROM audit_events "
            " WHERE org_id = :o AND event_type = :t"),
            {"o": str(org_id), "t": event_type}).scalar_one()


@pytest.fixture
def escalated(make_org, client, monkeypatch):
    """One org whose single ledger row was escalated by a real tool call."""
    org = make_org()
    _route_to_qwen(org["org_id"])
    _speak(monkeypatch, _tool_call())
    _ingest(client, org)
    _grade_all()
    return org


# ══ 1 · the escalation lands ═════════════════════════════════════════════════

def test_an_escalated_verdict_creates_exactly_one_review_row(escalated):
    """The hole A1 closes, stated as the row that now exists.

    Asserted on the STORED row, and on the values the tool call carried — a
    queue entry with no reason and no risk score is a notification, not a
    review, and the reviewer would have nothing to act on.
    """
    rows = _reviews(escalated["org_id"])
    assert len(rows) == 1, f"expected one queued review, got {len(rows)}"
    row, = rows
    assert row["status"] == "pending"
    assert row["resolution"] is None
    assert row["risk_score"] == 55
    assert "clinical tag" in row["reason"]


# ══ 2 · and lands once, however many times the row is graded ═════════════════

def test_re_grading_the_same_row_does_not_queue_it_twice(escalated):
    """`_grade_one` is re-entered after `_handle_failure` puts a row back to
    'pending' — a timeout, a dropped connection, a restart mid-batch. Without
    the unique constraint on `audit_log_id` the reviewer's queue would grow a
    duplicate per retry, all of them pointing at one event."""
    _requeue_for_retry(escalated["org_id"])
    _grade_all()

    assert len(_reviews(escalated["org_id"])) == 1, (
        "a retry queued the same escalation a second time")


# ══ 3 · and only for an escalation ══════════════════════════════════════════

@pytest.mark.parametrize("decision,breach", [("clean", False), ("breach", True)])
def test_a_clean_and_a_breach_verdict_queue_nothing(
        make_org, client, monkeypatch, decision, breach):
    """A breach is not an escalation. The queue is the destination for a judge
    that declined to decide — a judge that DID decide has already recorded its
    answer, and a breach has its own notification path."""
    org = make_org()
    _route_to_qwen(org["org_id"])
    _speak(monkeypatch, _graded(decision=decision, policy_breach=breach,
                                risk_score=90 if breach else 2))
    _ingest(client, org)
    _grade_all()

    assert _reviews(org["org_id"]) == []


# ══ 4 · one workspace's queue is not another's ══════════════════════════════

def test_another_org_can_neither_list_nor_resolve_this_workspaces_review(
        escalated, make_org, login):
    """Tenant isolation on both verbs, not just the read. A review id is a UUID
    a neighbour cannot guess, and that is not the control — the org scope is."""
    review, = _reviews(escalated["org_id"])
    neighbour = make_org()
    other = login(neighbour["admin_email"], neighbour["admin_password"])

    listed = other.get("/v1/reviews")
    assert listed.status_code == 200, listed.text
    assert listed.json()["items"] == [], "a neighbour's queue leaked into this one"

    denied = other.post(f"/v1/reviews/{review['id']}/resolve",
                        json={"resolution": "cleared"})
    assert denied.status_code == 404, denied.text
    # And it really did not resolve — asserted on the row, not on the status code.
    assert _reviews(escalated["org_id"])[0]["status"] == "pending"


# ══ 5 · resolving is a governance act, recorded once ════════════════════════

def test_resolving_twice_does_not_double_write_the_evidence_event(escalated, login):
    """The evidence event is APPEND-ONLY, so a duplicate cannot be taken back.
    Two resolves of one review would put two contradictory-looking human
    decisions in the tamper-evident record for a single determination."""
    review, = _reviews(escalated["org_id"])
    reviewer = login(escalated["admin_email"], escalated["admin_password"])

    first = reviewer.post(f"/v1/reviews/{review['id']}/resolve",
                          json={"resolution": "confirmed_breach",
                                "note": "checked the source system by hand"})
    assert first.status_code == 200, first.text
    assert first.json()["status"] == "resolved"
    assert _event_count(escalated["org_id"], "human_review_resolved") == 1

    second = reviewer.post(f"/v1/reviews/{review['id']}/resolve",
                           json={"resolution": "cleared"})
    assert second.status_code == 200, second.text
    assert _event_count(escalated["org_id"], "human_review_resolved") == 1, (
        "a second resolve appended a second evidence event")

    row, = _reviews(escalated["org_id"])
    assert row["status"] == "resolved"
    assert row["resolution"] == "confirmed_breach", (
        "a recorded governance decision was silently rewritten by a re-resolve")
    assert row["resolved_by"] == escalated["admin_email"]


# ══ 6 · THE ONE THAT PROVES THE DESIGN ══════════════════════════════════════

def test_the_chain_hash_is_byte_identical_before_and_after_a_review_resolves(
        escalated, login):
    """A human decision NEVER mutates the chained row.

    `chain.verdict_hash_hex` binds the local, deterministic verdict decided at
    ingest; the AI grade is written afterwards precisely because it is NOT bound
    (`schemas.py:355-373`). A human resolution is a third thing arriving later
    still, and if it moved `chain_hash` every block after it would stop
    verifying and `verifier/foxy_verify.py` would report an honest ledger as
    TAMPERED.

    Compared on `prev_hash`, `chain_hash` AND `verdict_hash` together: a mutant
    that rewrote the row and re-chained it would keep the hashes self-consistent,
    and only this tuple, captured before the resolve, would notice.
    """
    before = _chain_hashes(escalated["org_id"])
    assert before, "no ledger row to prove anything about"

    review, = _reviews(escalated["org_id"])
    reviewer = login(escalated["admin_email"], escalated["admin_password"])
    resolved = reviewer.post(f"/v1/reviews/{review['id']}/resolve",
                             json={"resolution": "policy_gap",
                                   "note": "the policy does not cover this tag"})
    assert resolved.status_code == 200, resolved.text
    assert _reviews(escalated["org_id"])[0]["status"] == "resolved"

    assert _chain_hashes(escalated["org_id"]) == before, (
        "resolving a human review moved the chain — the evidence was rewritten")


# ══ the queue's paging contract is the export's, not a second one ═══════════

def test_the_queue_pages_on_the_same_seq_cursor_the_export_uses(
        make_org, client, monkeypatch, login):
    """`GET /v1/logs/export` established `after_seq` + a `page` block carrying
    `from_seq`/`to_seq`/`complete`/`next_after_seq`/`next` (#271). A second
    paging contract on a second endpoint is two things a client has to learn to
    read one product."""
    org = make_org()
    _route_to_qwen(org["org_id"])
    _speak(monkeypatch, _tool_call())
    for seed in ("a", "b", "c"):
        _ingest(client, org, seed=seed)
    _grade_all()
    assert len(_reviews(org["org_id"])) == 3

    reader = login(org["admin_email"], org["admin_password"])
    first = reader.get("/v1/reviews", params={"limit": 2}).json()
    assert [item["seq"] for item in first["items"]] == [1, 2]
    assert first["page"]["complete"] is False
    assert first["page"]["from_seq"] == 1 and first["page"]["to_seq"] == 2
    assert first["page"]["next_after_seq"] == 2
    assert "after_seq=2" in first["page"]["next"]

    rest = reader.get("/v1/reviews",
                      params={"after_seq": first["page"]["next_after_seq"]}).json()
    assert [item["seq"] for item in rest["items"]] == [3]
    assert rest["page"]["complete"] is True
    assert rest["page"]["next"] is None


# ══ 7 · two reviewers, one determination ════════════════════════════════════

def _blocked_backends() -> int:
    """How many sessions on this database are waiting on a lock."""
    with engine.begin() as conn:
        return conn.execute(text(
            "SELECT COUNT(*) FROM pg_stat_activity "
            " WHERE datname = current_database() AND wait_event_type = 'Lock'")
        ).scalar_one()


def _wait_until_blocked(timeout=20.0) -> bool:
    """Block until the in-flight request has actually reached the locked row.

    Polling the server beats sleeping a guessed interval: it is what makes this
    test deterministic rather than timing-dependent, and it works whether the
    request stops at the SELECT (with the lock) or at the UPDATE (without it) —
    all it establishes is that the request got there.
    """
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if _blocked_backends():
            return True
        time.sleep(0.05)
    return False


def test_a_resolve_that_loses_the_race_appends_no_evidence_event(escalated, login):
    """THE SEQUENTIAL IDEMPOTENCE TEST ABOVE DOES NOT COVER THIS, and the gap is
    where the guarantee actually breaks.

    Test 5 resolves twice in a row, so the second request reads a row the first
    already committed and takes the early return. This one overlaps them: a
    competing transaction holds the review row and resolves it WHILE the endpoint's
    request is in flight — two reviewers on the same queue, or one impatient
    double-click.

    Without `with_for_update` on the endpoint's SELECT, the check and the write
    are two statements with a gap between them. The plain SELECT does not wait, so
    it reads `pending`, falls through the guard, and only its UPDATE blocks — and
    when the winner commits, the loser proceeds on a decision it made against a
    row that no longer says that. It overwrites the recorded resolution AND
    appends a second `human_review_resolved` event. That event cannot be taken
    back: the record is append-only, so it would permanently hold two
    contradictory human decisions about one determination, in the product whose
    entire deliverable is that the record can be trusted.

    With the lock the loser waits in the SELECT, and Postgres hands it the row
    version the winner committed — so it sees `resolved`, returns the standing
    decision, and writes nothing.

    ⚠ THE WINNER HERE IS RAW SQL, DELIBERATELY. It resolves the row without
    appending an event, so the count this asserts is ZERO and belongs entirely to
    the endpoint. A second HTTP request as the winner would leave one event on the
    table and turn a clean 0-or-1 into a 1-or-2 that a reader has to reason about.
    """
    review, = _reviews(escalated["org_id"])
    reviewer = login(escalated["admin_email"], escalated["admin_password"])

    winner = engine.connect()
    held = winner.begin()
    winner.execute(text("SELECT id FROM human_reviews WHERE id = :i FOR UPDATE"),
                   {"i": review["id"]})

    outcome: dict = {}

    def _resolve():
        outcome["response"] = reviewer.post(
            f"/v1/reviews/{review['id']}/resolve", json={"resolution": "cleared"})

    loser = threading.Thread(target=_resolve)
    loser.start()
    try:
        assert _wait_until_blocked(), (
            "the resolve request never reached the locked row — this test proves "
            "nothing about concurrency unless the two genuinely overlap")
        # The other reviewer decides first, and commits.
        winner.execute(text(
            "UPDATE human_reviews SET status = 'resolved', "
            "       resolution = 'confirmed_breach', resolved_at = now(), "
            "       resolved_by = :by WHERE id = :i"),
            {"by": escalated["admin_email"], "i": review["id"]})
        held.commit()
    finally:
        winner.close()
        loser.join(timeout=30)
        assert not loser.is_alive(), "the losing resolve never returned"

    response = outcome["response"]
    assert response.status_code == 200, response.text
    assert response.json()["resolution"] == "confirmed_breach", (
        "the loser was told its own decision had been recorded")
    assert _reviews(escalated["org_id"])[0]["resolution"] == "confirmed_breach", (
        "the loser overwrote a governance decision that was already recorded")
    assert _event_count(escalated["org_id"], "human_review_resolved") == 0, (
        "a resolve that lost the race still appended an evidence event")


# ══ 8 · the queue is a human surface, because `note` is human text ══════════

def test_the_sdk_key_cannot_read_the_queue(escalated, client):
    """`note` is free text a reviewer typed, so it can carry anything they type —
    including the raw prompt content this product is built never to hold.

    The workspace's API key lives in application config on the customer's own
    servers, precisely so it never needs to see content, and every OTHER customer
    read here accepts it (`auth.resolve_org` takes the Bearer key OR a session).
    This one must not: resolving already requires a human session, and a read
    looser than the write it feeds is the wrong way round.
    """
    denied = client.get("/v1/reviews", headers=escalated["auth"])
    assert denied.status_code == 401, denied.text
    assert "clinical tag" not in denied.text, "the queue leaked through the SDK key"


# ══ 9 · and somebody is actually told ══════════════════════════════════════

def _notify_to(org_id, **fields) -> None:
    sets = ", ".join(f"{name} = :{name}" for name in fields)
    with engine.begin() as conn:
        conn.execute(text(f"UPDATE org_policies SET {sets} WHERE org_id = :o"),
                     {**fields, "o": str(org_id)})


def _grade_and_drain(monkeypatch):
    """Grade every pending row, then drain the notice queue as the thread does.

    Draining is a separate step in production and therefore here: `_grade_one`
    only ENQUEUES, so that a wedged mail provider can never stall the batch that
    also drives the worker heartbeat.
    """
    sent, posted = [], []
    monkeypatch.setattr(org_notifications.email_mod, "send_email",
                        lambda **kw: sent.append(kw) or True)
    monkeypatch.setattr(org_notifications.requests, "post",
                        lambda url, **kw: posted.append(kw.get("json")) or True)
    _grade_all()
    db = SessionLocal()
    try:
        org_notifications.drain_breach_notices(db)
    finally:
        db.close()
    return sent, posted


def test_an_escalation_notifies_the_workspace_and_does_not_call_it_a_breach(
        make_org, client, monkeypatch):
    """The hole A1 exists to close has TWO halves, and the queue row is only one.

    `worker._grade_one`'s single post-commit notification branch gates on
    `verdict.policy_breach`, which is False on an escalation — so before this
    phase an escalation told nobody. A `human_reviews` row that nothing announces
    is that same defect wearing a different hat: until the A2 reviewer page ships,
    this notice is the only way an escalation reaches a person at all.

    ⚠ AND IT MUST NOT ARRIVE AS A BREACH. The judge found no violation; it
    declined to decide and asked for a person, and `passport.compliant_events`
    subtracts the two separately. An integration routing on the webhook's `type`
    has to be able to tell them apart, and so does a customer reading a subject
    line at 2am.
    """
    org = make_org()
    _route_to_qwen(org["org_id"])
    _speak(monkeypatch, _tool_call())
    _notify_to(org["org_id"], notify_on_breach="immediate",
               notify_email="reviews@corp.test",
               notify_webhook_url="https://corp.test/hook")
    _ingest(client, org)

    sent, posted = _grade_and_drain(monkeypatch)

    assert [message["to"] for message in sent] == ["reviews@corp.test"], sent
    subject = sent[0]["subject"]
    assert "breach" not in subject.lower(), (
        f"an escalation was announced as a breach: {subject!r}")
    assert [payload["type"] for payload in posted] == ["human_review"], posted
    assert posted[0]["seq"] == 1


def test_a_clean_verdict_notifies_nobody(make_org, client, monkeypatch):
    """The escalation notice rides the breach notifier's queue, drain and thread.
    Sharing the transport must not share the trigger: a clean grade stays silent.
    """
    org = make_org()
    _route_to_qwen(org["org_id"])
    _speak(monkeypatch, _graded(decision="clean"))
    _notify_to(org["org_id"], notify_on_breach="immediate",
               notify_email="reviews@corp.test",
               notify_webhook_url="https://corp.test/hook")
    _ingest(client, org)

    sent, posted = _grade_and_drain(monkeypatch)
    assert sent == [] and posted == []
