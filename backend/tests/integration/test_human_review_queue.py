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
import queue
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


def _notified_at(org_id):
    """A2 · §4.6(e). NULL means no notice has reached the sender for this
    escalation, and the next regrade announces it."""
    with engine.begin() as conn:
        return conn.execute(text(
            "SELECT notified_at FROM human_reviews WHERE org_id = :o"),
            {"o": str(org_id)}).scalar_one()


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

def _is_blocked_by(holder_pid: int) -> bool:
    """Is any backend waiting specifically on `holder_pid`'s locks?

    ⚠ `pg_blocking_pids(pid)`, NOT a count of waiters. The first version of this
    helper counted every backend on the database with `wait_event_type = 'Lock'`,
    which is satisfied by ANY unrelated waiter — the `_clean_db` TRUNCATE this
    repo documents as deadlock-prone, another connection in the pool, anything.
    A stray waiter released the poll before the request under test had reached
    the row at all, the test silently degraded to the sequential case, and it
    then PASSED with `.with_for_update()` removed: a concurrency test that cannot
    fail, guarding the one guarantee this phase exists to make. Asking Postgres
    who is blocked BY OUR HOLDER answers the question actually being asked, and
    is unaffected by whatever else the suite is doing to the database.
    """
    with engine.begin() as conn:
        return bool(conn.execute(text(
            "SELECT EXISTS (SELECT 1 FROM pg_stat_activity "
            "                WHERE :holder = ANY(pg_blocking_pids(pid)))"),
            {"holder": holder_pid}).scalar_one())


def _wait_until_blocked_by(holder_pid: int, timeout=30.0) -> bool:
    """Block until the in-flight request is genuinely waiting on `holder_pid`.

    Polling the server beats sleeping a guessed interval — it is what makes this
    test deterministic rather than timing-dependent — and it works whether the
    request stops at the SELECT (with the lock) or at the UPDATE (without it).
    All it establishes is that the two transactions really do overlap on this
    row, which is the precondition without which the assertions below prove
    nothing.
    """
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if _is_blocked_by(holder_pid):
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
    holder_pid = winner.execute(text("SELECT pg_backend_pid()")).scalar_one()
    winner.execute(text("SELECT id FROM human_reviews WHERE id = :i FOR UPDATE"),
                   {"i": review["id"]})

    outcome: dict = {}

    def _resolve():
        outcome["response"] = reviewer.post(
            f"/v1/reviews/{review['id']}/resolve", json={"resolution": "cleared"})

    loser = threading.Thread(target=_resolve)
    loser.start()
    try:
        assert _wait_until_blocked_by(holder_pid), (
            "the resolve request never blocked on this transaction — this test "
            "proves nothing about concurrency unless the two genuinely overlap")
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


# ══ 10 · the DSAR bundle carries the human decision, and says so truthfully ══

def _audit_events(org_id, event_type) -> list[dict]:
    with engine.begin() as conn:
        return [dict(r) for r in conn.execute(text(
            "SELECT event_hash, payload FROM audit_events "
            " WHERE org_id = :o AND event_type = :t ORDER BY created_at"),
            {"o": str(org_id), "t": event_type}).mappings().all()]


def test_the_dsar_bundle_carries_the_resolved_review_in_full(escalated, login):
    """`EXPORT_EXCLUSIONS["audit_events"]` makes a COMPLETENESS CLAIM, and this is
    what holds it to it.

    That entry tells a customer their `human_review_resolved` rows are left out of
    the `audit_events` section because they are "carried in full under
    human_reviews instead: the resolution, who made it and when, the judge's
    reason for escalating, and that event's own event_hash". In a DSAR answer that
    is a legal statement, exactly as #252's two earlier wordings were — and it was
    the only claim in this phase with nothing asserting it. The `event_hash` in
    particular reached the bundle through a hand-written correlated subquery that
    no test executed.

    Asserted field by field rather than on a shape, and the hash is compared to
    the `audit_events` row it claims to reproduce — a projection that carries a
    DIFFERENT digest is worse than one that omits it, because the customer would
    hand an auditor a number that verifies nothing.
    """
    review, = _reviews(escalated["org_id"])
    reviewer = login(escalated["admin_email"], escalated["admin_password"])
    resolved = reviewer.post(f"/v1/reviews/{review['id']}/resolve",
                             json={"resolution": "policy_gap",
                                   "note": "the policy does not cover this tag"})
    assert resolved.status_code == 200, resolved.text

    bundle = reviewer.get("/v1/account/export")
    assert bundle.status_code == 200, bundle.text
    body = bundle.json()

    # The manifest claims the table, and the section exists to back the claim.
    assert "human_reviews" in body["export_scope"]["included_tables"]
    entries = body["human_reviews"]
    assert len(entries) == 1, (
        f"one resolved review produced {len(entries)} bundle entries — the "
        f"subquery fanned out")
    entry, = entries

    event, = _audit_events(escalated["org_id"], "human_review_resolved")
    assert entry["id"] == event["payload"]["review_id"]
    assert entry["seq"] == 1
    assert entry["status"] == "resolved"
    assert entry["resolution"] == "policy_gap"
    assert entry["resolved_by"] == escalated["admin_email"]
    assert entry["resolved_at"] is not None
    assert "clinical tag" in entry["reason"]
    assert entry["risk_score"] == 55
    assert entry["resolution_event_hash"] == event["event_hash"], (
        "the bundle's digest does not match the event it claims to carry")

    # And the note — customer-authored text, excluded from every EVIDENCE surface
    # and included HERE, which is the subject asking for their own words back.
    assert entry["note"] == "the policy does not cover this tag"
    assert entry["note"] not in json.dumps(event["payload"]), (
        "free text a reviewer typed reached the append-only evidence event")


def test_a_pending_review_is_in_the_bundle_with_no_resolution_hash(escalated, login):
    """The other half of the outer lookup. An escalation nobody has decided yet is
    still the workspace's data and still belongs in a DSAR answer — it just has no
    evidence event to point at, and must say so with a null rather than by
    vanishing from the section.
    """
    reviewer = login(escalated["admin_email"], escalated["admin_password"])
    entry, = reviewer.get("/v1/account/export").json()["human_reviews"]

    assert entry["status"] == "pending"
    assert entry["resolution"] is None
    assert entry["resolved_by"] is None
    assert entry["resolution_event_hash"] is None
    assert _audit_events(escalated["org_id"], "human_review_resolved") == []


# ══ 11 · announced once, however many times the row is graded ═══════════════

def test_a_regrade_does_not_announce_the_same_escalation_twice(
        make_org, client, monkeypatch):
    """THE UNIQUE CONSTRAINT BOUNDS THE QUEUE; IT DOES NOT BOUND THE NOTICE.

    `_grade_one` is re-entered for the same row every time `_handle_failure` puts
    it back to 'pending' — a provider timeout, a dropped connection, a restart
    mid-batch — and test 2 above proves the worklist still holds exactly one
    entry. Nothing about that constrains `org_notifications`: its queue dedupes
    nothing, so an escalation on a row that is retried three times could send
    three "A review is waiting" emails and three `type: "human_review"` webhook
    POSTs for one determination. The customer would open the queue, find a single
    entry, and have no way to tell whether the other two notices were about
    something they had missed.

    ⚠ THE GATE MOVED IN A2 AND THIS ASSERTION DID NOT, WHICH IS THE POINT.
    A1 answered "did *this* attempt file it": `ON CONFLICT DO NOTHING RETURNING
    id` returns no row when it conflicts, which separated "we filed it, so
    announce it" from "somebody already filed it". That fixed the duplicate and
    created a second defect — §4.6(e) — because it also silenced the regrade
    that used to RECOVER a notice the sender never took. A2 reads
    `human_reviews.notified_at` instead, so this test still passes for the
    reason it was written (the escalation WAS announced, so it is not announced
    again) while `test_a_dropped_notice_is_recovered_by_the_next_regrade` covers
    the case A1 could not tell apart.
    """
    org = make_org()
    _route_to_qwen(org["org_id"])
    _speak(monkeypatch, _tool_call())
    _notify_to(org["org_id"], notify_on_breach="immediate",
               notify_email="reviews@corp.test",
               notify_webhook_url="https://corp.test/hook")
    _ingest(client, org)

    sent, posted = _grade_and_drain(monkeypatch)
    assert [message["to"] for message in sent] == ["reviews@corp.test"]
    assert [payload["type"] for payload in posted] == ["human_review"]

    # Exactly what the retry path does, and then grading runs again.
    _requeue_for_retry(org["org_id"])
    resent, reposted = _grade_and_drain(monkeypatch)

    assert resent == [], (
        f"a regrade emailed the same escalation again: {resent}")
    assert reposted == [], (
        f"a regrade re-POSTed the same escalation: {reposted}")
    assert len(_reviews(org["org_id"])) == 1
    # And the reason it stayed silent is recorded rather than inferred.
    assert _notified_at(org["org_id"]) is not None, (
        "the notice went out and nothing recorded that it had — the next "
        "regrade would announce it again")


def test_a_dropped_notice_is_recovered_by_the_next_regrade(
        make_org, client, monkeypatch):
    """A2 · §4.6(e) — THE HALF A1 KNOWINGLY SHIPPED BROKEN.

    The notice path has three lossy points and none of them requeues:
    `enqueue_escalation_notice` drops silently on `queue.Full` (bounded at 2000),
    the queue is in-process memory so a restart loses it, and
    `drain_breach_notices` swallows a send exception. A1's gate was "did this
    attempt file the row", so once the row existed every later regrade
    conflicted, returned False and stayed silent: ONE dropped notice, dropped
    for good. The escalation itself was never lost — it is in
    `audit_logs.gemini_verdict`, in the `verdict` AuditEvent and in
    `human_reviews` — but the announcement was, and until A2's reviewer page
    the announcement was the only way it reached a person.

    So the gate is `notified_at`, and this drives the failure rather than
    asserting the fix: the first grade's enqueue is made to fail exactly as a
    full queue fails, and the regrade after it has to recover.

    ⚠ WRITTEN TO FAIL ON THE A1 GATE. Under "did this attempt file it" the
    second half of this test gets no email, because the INSERT conflicts.
    """
    org = make_org()
    _route_to_qwen(org["org_id"])
    _speak(monkeypatch, _tool_call())
    _notify_to(org["org_id"], notify_on_breach="immediate",
               notify_email="reviews@corp.test",
               notify_webhook_url="https://corp.test/hook")
    _ingest(client, org)

    # Exactly what a bounded queue at capacity does to `put_nowait`.
    def _full(_item):
        raise queue.Full()

    monkeypatch.setattr(org_notifications._NOTICE_QUEUE, "put_nowait", _full)
    lost, unposted = _grade_and_drain(monkeypatch)
    monkeypatch.undo()

    assert lost == [] and unposted == [], (
        "the notice was supposed to be dropped by this arrangement")
    assert len(_reviews(org["org_id"])) == 1, (
        "a dropped NOTICE must not cost the queue entry — they are separate "
        "failures and only one of them happened")
    assert _notified_at(org["org_id"]) is None, (
        "a notice the sender never took was recorded as sent, which would make "
        "the drop permanent all over again")

    # The judge is re-stubbed because monkeypatch.undo() unwound that too.
    _speak(monkeypatch, _tool_call())
    _requeue_for_retry(org["org_id"])
    recovered, reposted = _grade_and_drain(monkeypatch)

    assert [message["to"] for message in recovered] == ["reviews@corp.test"], (
        f"the dropped escalation notice was never recovered: {recovered}")
    assert [payload["type"] for payload in reposted] == ["human_review"], reposted
    assert len(_reviews(org["org_id"])) == 1, (
        "recovering the notice queued the escalation a second time")
    assert _notified_at(org["org_id"]) is not None, (
        "the recovery sent the notice and did not record it, so a third grade "
        "would send a duplicate")
