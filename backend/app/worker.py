"""Durable Gemini grading worker — a Postgres-outbox poller.

Ingest (POST /v1/logs/batch) commits each chain row synchronously with
grading_status='pending' (the column default). That commit IS the durable
enqueue: the job lives in the same row as the chain data, so a crash between the
202 response and grading cannot lose it — unlike the previous in-memory pool.

This poller claims 'pending' rows with FOR UPDATE SKIP LOCKED (safe to run in
several processes at once), grades each with the org's configured policy via
gemini.evaluate(meta, policy_config), and writes the verdict back, marking the
row 'graded'. Stuck 'in_progress' rows (a worker died mid-job) are reclaimed
after grading_stuck_seconds; after grading_max_attempts failures a row is parked
in 'failed' — a human-visible dead-letter, never silently dropped.

RLS note: the poller must connect as a role that BYPASSES RLS (the docker 'foxy'
superuser does) so its cross-org claim query sees every org's rows; the per-row
write-back also sets app.current_org defensively.
"""

from __future__ import annotations

import json
import logging
import random
import signal
import threading
import time
import uuid
import hashlib

from sqlalchemy import text
from sqlalchemy.orm import Session


from . import gemini
from . import judge
from . import judge_routing
from . import org_notifications
from . import openai_judge
from . import policy_engine
from . import qwen_judge
from . import user_notifications
from . import webhook_delivery
from .anchor import (_ANCHOR_ALERT_STATE, alert_on_anchor_problems, anchor_admin,
                     anchor_all_due)
from .config import get_settings
from .db import SessionLocal
from .models import AuditEvent, OrgPolicy
from .policy_snapshot import judge_policy_config, policy_snapshot_hash

log = logging.getLogger("foxy.worker")

# Atomically claim a batch: mark pending (or stuck in_progress) rows in_progress
# and return their metadata. FOR UPDATE SKIP LOCKED lets multiple pollers run.
_CLAIM_SQL = text(
    """
    UPDATE audit_logs
       SET grading_status     = 'in_progress',
           grading_started_at = now(),
           grading_attempts   = grading_attempts + 1
     WHERE id IN (
           SELECT id FROM audit_logs
            WHERE grading_status = 'pending'
               OR (grading_status = 'in_progress'
                   AND grading_started_at < now() - make_interval(secs => :stuck))
            ORDER BY created_at
              FOR UPDATE SKIP LOCKED
            LIMIT :batch
     )
    RETURNING id, org_id, seq, prompt_hash, response_hash,
              token_count, policy_tag, pii_signals, grading_attempts,
              chain_hash,
              event_id, client_id, client_seq, event_type, commitment_alg,
              event_metadata
    """
)

_MARK_GRADED_SQL = text(
    """
    UPDATE audit_logs
       SET gemini_verdict = CAST(:verdict AS jsonb),
           grading_status  = 'graded',
           graded_at       = now()
     WHERE id = :id
    """
)
_MARK_RETRY_SQL = text("UPDATE audit_logs SET grading_status = 'pending' WHERE id = :id")
_MARK_FAILED_SQL = text("UPDATE audit_logs SET grading_status = 'failed' WHERE id = :id")


def _policy_config(db: Session, org_id, event_metadata: dict | None = None) -> dict | None:
    """Use an event's bound policy snapshot, with a legacy-row fallback."""
    metadata = event_metadata or {}
    snapshot = metadata.get("policy_snapshot")
    stored_hash = metadata.get("policy_snapshot_hash")
    if snapshot is not None or stored_hash is not None:
        if not isinstance(snapshot, dict) or not isinstance(stored_hash, str):
            raise ValueError("policy snapshot metadata is incomplete")
        if policy_snapshot_hash(snapshot) != stored_hash:
            raise ValueError("policy snapshot hash does not match stored policy")
        config = judge_policy_config(snapshot)
        if config is None:
            raise ValueError("policy snapshot metadata is invalid")
        return config

    # Rows written before chain V3 did not retain policy snapshots. Preserve
    # their legacy behavior rather than rewriting historical evidence.
    oid = org_id if isinstance(org_id, uuid.UUID) else uuid.UUID(str(org_id))
    policy = db.get(OrgPolicy, oid)
    if policy is None:
        return None
    return {
        "pii_detection": policy.pii_detection,
        "prompt_injection": policy.prompt_injection,
        "regulated_data_mode": policy.regulated_data_mode,
        "max_token_threshold": policy.max_token_threshold,
        # No snapshot exists on these rows, so the org's CURRENT setting is the
        # only one available. Reaches the judge for the same reason as the
        # snapshot path in policy_snapshot.judge_policy_config (P4 §A).
        "confidence_threshold": policy.confidence_threshold or "balanced",
    }


def _org_history(db: Session, org_id) -> dict:
    """Compact last-7-day activity summary for the org, fed to the judge for
    temporal reasoning (5J). Aggregated from audit_logs, the append-only source
    of truth.

    This used to read the `usage_daily` rollup, which recomputes only a rolling
    48-hour window — so five of the seven days it summed held whatever partial
    counts were true when the worker last touched them. Of everywhere that
    staleness lived, this was the worst: not a chart a human can sanity-check,
    but a number handed to the AI judge as evidence, understating both the
    recent breach count and the breach rate it reasons about.

    Index `ix_audit_logs_org_created` (migration 0054) covers this predicate
    exactly, so the aggregate stays cheap enough to run per graded row."""
    oid = org_id if isinstance(org_id, uuid.UUID) else uuid.UUID(str(org_id))
    row = db.execute(text(
        "SELECT COUNT(*) FILTER "
        "         (WHERE gemini_verdict->>'policy_breach' = 'true') AS breaches, "
        "       COUNT(*) FILTER (WHERE grading_status = 'graded') AS graded "
        "FROM audit_logs "
        "WHERE org_id = :oid AND created_at >= now() - INTERVAL '7 days'"),
        {"oid": oid}).mappings().first()
    breaches, graded = int(row["breaches"]), int(row["graded"])
    return {
        "window_days": 7,
        "recent_breaches": breaches,
        "recent_graded": graded,
        "breach_rate_pct": round(100.0 * breaches / graded, 1) if graded else 0.0,
    }


#: A5 — what have HUMANS already decided about THIS tag?
#:
#: `_org_history` above answers a different question and cannot answer this
#: one: it is an ORG-WIDE 7-day count of breaches, graded rows and a breach
#: rate, so it says nothing about whether this policy_tag has ever been
#: escalated or what a reviewer ruled when it was. A tag a human has cleared
#: three times should not be escalated a fourth. Bound into a callable and
#: handed to `qwen_judge.evaluate`, which offers it to the model as the
#: `check_prior_reviews` tool — so A1's human decisions feed back into the
#: agent instead of stopping at the reviewer's screen.
#:
#: 🔴 `note` IS NOT SELECTED, AND MUST NEVER BE. It is the one field a human
#: writes freely (`models.HumanReview`: "annotation, not evidence"), it is why
#: both /v1/reviews verbs require an authenticated user rather than an SDK key,
#: and a reviewer explaining a decision will quote the prompt they were shown.
#: Every column here is a COUNT. `qwen_judge._prior_reviews_payload` narrows the
#: result again at the wire boundary, so this statement AND that allowlist both
#: have to fail before a note could move — belt and braces, deliberately, for
#: the one rule this product cannot bend.
#:
#: ⚠ THE INDEX. `ix_human_reviews_org_status_created` (0072) drives this:
#: `org_id` is its leading column, and `created_at`, though third, is still
#: evaluated inside the index, so the window costs no heap access. `status` is
#: skipped rather than unused — this counts BOTH statuses, because a pending
#: escalation is as much a fact about the tag as a resolved one. `policy_tag` is
#: not in that index and cannot be: it lives on `audit_logs`, and is reached by
#: PRIMARY KEY through `audit_log_id`, once per candidate row. The candidate set
#: is one org's escalations in 30 days, small by construction — only rows a
#: judge escalated are in this table at all. No new index, and no migration.
#:
#: ⚠ THE WINDOW IS `qwen_judge.PRIOR_REVIEW_WINDOW_DAYS`, NOT A NUMBER OF THIS
#: MODULE'S OWN. That module has to state the bound to the model in the tool
#: description, so a second constant here would be a promise and a WHERE
#: clause free to drift apart — and the drift would be invisible, because
#: both halves would still work. One constant, read by the half that queries.

_PRIOR_REVIEWS_SQL = text(
    """
    SELECT COUNT(*)                                                   AS escalations,
           COUNT(*) FILTER (WHERE hr.resolution = 'cleared')          AS cleared,
           COUNT(*) FILTER (WHERE hr.resolution = 'confirmed_breach') AS confirmed_breach,
           COUNT(*) FILTER (WHERE hr.resolution = 'policy_gap')       AS policy_gap
      FROM human_reviews hr
      JOIN audit_logs   al ON al.id = hr.audit_log_id
     WHERE hr.org_id = :oid
       AND al.policy_tag = :tag
       AND hr.created_at >= now() - make_interval(days => :days)
    """
)


#: The three columns that mean a human ACTUALLY RULED on this tag.
#:
#: ⚠ `escalations` IS DELIBERATELY ABSENT, and its presence was a bug. That
#: column is an unfiltered `COUNT(*)` over `human_reviews`, so it counts rows
#: that are still PENDING — an escalation nobody has looked at yet. Gating on it
#: offered the lookup to tags no human had ruled on at all, which is the exact
#: condition this whole change exists to withhold it for.
#:
#: 🔴 AND THE RETRY CASE IS WORSE THAN MERELY WRONG. `_handle_failure` sends a
#: failed row round again, so a row whose FIRST grade filed an escalation is
#: regraded with that escalation already in the table. Gating on `escalations`
#: would then hand the judge, as "prior review history", the note it wrote about
#: this very event — a model reading its own reasoning back to itself and
#: mistaking it for corroboration from a person. The three resolution verbs are
#: written only by `POST /v1/reviews/{id}/resolve`, so they cannot say a human
#: ruled unless one did.
#:
#: ⚠ NOT `qwen_judge._PRIOR_REVIEW_COUNTS` either, and that difference is the
#: rest of the fix. That tuple is the WIRE ALLOWLIST — what may be serialised to
#: the model — and it includes `window_days`, which is always 30. Reusing it here
#: reads as the obvious de-duplication and offers the lookup on EVERY row,
#: undoing the withholding completely while looking correct. Written first as
#: exactly that mistake and caught by
#: `test_the_window_days_field_does_not_count_as_history`.
_RESOLUTION_COUNTS = ("cleared", "confirmed_breach", "policy_gap")


def _prior_reviews(db: Session, org_id, policy_tag) -> dict:
    """How humans ruled on past escalations for this org's `policy_tag`.

    ⚠ RUN IN A SAVEPOINT, and that is not decoration — but the caller it used to
    name is gone. This ran inside `qwen_judge.evaluate`, which swallowed the
    exception; it is now called eagerly by `_prior_reviews_lookup`, which catches
    it there instead. THE SAVEPOINT IS STILL LOAD-BEARING, and the reason is
    unchanged by the move: a failed statement aborts the whole Postgres
    transaction, so catching the exception is not enough on its own. Without
    `begin_nested` the grade would be computed and the write-back would then fail
    on a poisoned session, `_handle_failure` would send the row round again, and
    a lookup blip would cost the grade it was supposed to survive.

    Said plainly because a docstring that names a caller which no longer exists
    is how the next reader concludes the savepoint is vestigial and deletes it.
    `begin_nested` rolls back to the savepoint and re-raises, so the session
    `_prior_reviews_lookup` returns to is still usable.
    """
    oid = org_id if isinstance(org_id, uuid.UUID) else uuid.UUID(str(org_id))
    with db.begin_nested():
        row = db.execute(_PRIOR_REVIEWS_SQL, {
            "oid": oid, "tag": policy_tag,
            "days": qwen_judge.PRIOR_REVIEW_WINDOW_DAYS}).mappings().first()
    return {
        "window_days": qwen_judge.PRIOR_REVIEW_WINDOW_DAYS,
        "escalations": int(row["escalations"]),
        "cleared": int(row["cleared"]),
        "confirmed_breach": int(row["confirmed_breach"]),
        "policy_gap": int(row["policy_gap"]),
    }


def _prior_reviews_lookup(db: Session, org_id, policy_tag):
    """The lookup to OFFER the agentic judge, or ``None`` when it has nothing
    to say.

    ⚠ THE QUERY RUNS UP FRONT NOW, AND THE REASON IS A MEASUREMENT, NOT A
    PREFERENCE. Same payload, same tag, same model, one variable:

        lookup WITHHELD             -> human_review, risk 85
        lookup OFFERED, all zeros   -> clean, risk 5

    A5 regressed A1's escalation. Offered a history of nothing, the model got
    LESS cautious — and all-zero is the state of every tag nobody has reviewed
    yet: a new workspace, a new tag, a fresh deployment. A compliance judge that
    relaxes because no human has looked has the logic backwards, and it fails
    hardest on exactly the tenants with no history to lean on.

    `b9cb053` tried to fix this with words — the tool description and the prompt
    now both say an all-zero result must not change the decision. Re-measured
    live, the model stopped CITING the zeros and still graded clean. So the
    suppressor is not the zeros; it is being offered the tool at all. This
    removes the bias structurally instead of asking the model not to have it.

    ⚠ AND IT IS CHEAPER THAN WHAT IT REPLACES, which is why "run the query
    eagerly" is not the pessimisation it looks like. Before, the tool was always
    offered and the model spent a whole extra round trip — network, latency and
    tokens — to be told nothing. Now one indexed query (`org_id` leading,
    `ix_human_reviews_org_status_created`) replaces that round trip in the common
    case, and when the answer IS informative the callable serves the result
    ALREADY FETCHED, so the second query never happens either. The old lazy
    callable existed to avoid a query the model might not ask for; the model
    asked for it more or less always, so laziness bought nothing and cost a turn.

    ⚠ A LOOKUP BLIP STILL MUST NOT COST THE GRADE. `evaluate` swallowed the
    callable's exception before; running it here moves that risk into the
    caller's frame, so it is caught here and answered the same way an empty
    history is — the tool is withheld and the model grades on metadata. That is
    the cautious direction: a failed read must never be able to make the judge
    more relaxed than a successful one would have.

    Do NOT "simplify" this back to a lazy callable. It would restore a measured
    regression in the one direction a compliance product cannot afford.
    """
    try:
        answer = _prior_reviews(db, org_id, policy_tag)
    except Exception as exc:                     # noqa: BLE001 — type name only
        # Type name only: a database error message can quote row values, and this
        # log line is not a place content may surface.
        log.warning("prior-review lookup failed for org %s (%s); grading without "
                    "it", org_id, type(exc).__name__)
        return None
    # ⚠ `.get`, NOT `answer[key]`, AND THE READ IS THE RISK. A KeyError here is
    # raised OUTSIDE the `except` above, so it escapes into `_grade_one` and
    # marks the row failed — and it would do that for every qwen row in the
    # batch, which trips the PROCESS-WIDE circuit breaker in `_loop` and pauses
    # grading for every tenant. A missing key means the lookup's shape changed,
    # which is precisely when this must degrade rather than detonate: absent
    # reads as zero, the tool is withheld, and the grade still happens. That is
    # the promise the docstring above makes and this line is where it was
    # quietly not kept.
    if not any(answer.get(key) for key in _RESOLUTION_COUNTS):
        return None
    return lambda: answer


def _judge_verdict(db: Session, org_id, meta: dict, policy_config: dict | None,
                   history: dict):
    """Grade with the judge(s) THIS org chose, on the key THEY pay for.

    Routing comes from the org's LIVE OrgPolicy row (judge_routing), never from
    the event's policy snapshot — a provider key must never touch the chain. A
    chosen provider with no usable key is skipped with the provider's own
    evaluator_unavailable verdict, so grading degrades honestly instead of
    crashing or quietly falling back to Foxy's platform key.

    Decrypted keys live only in this frame, for the duration of the call.
    """
    # THE OUTWARD BOUNDARY. Every provider call in this function hands `meta` to
    # a third party, so the content-blind projection happens ONCE, here, rather
    # than inside each provider module. It WAS inside one: openai_judge
    # projected, gemini.evaluate did not — it json.dumps(meta) verbatim — so the
    # DEFAULT provider received the whole event_metadata dict while a test
    # asserting content-blindness against the openai helper stayed green.
    # Projecting at the boundary closes it for both, and for the next provider
    # added below, which is the failure mode that produced this one.
    #
    # NOT where `meta` is built: policy_engine.evaluate_enforcement reads
    # decision / policy_rules / blocked_reason straight out of event_metadata
    # and none are safe-listed, so projecting there would silently empty the
    # rule ids and the reason label out of every host-enforcement verdict. The
    # in-process readers need the whole record; only the WIRE has to be narrow.
    #
    # This is also what keeps policy_tag_raw (S12) off the wire. It is the first
    # CALLER-CONTROLLED FREE-TEXT value in event_metadata — every other key is
    # bounded vocabulary: rule ids, signal labels, a version string, a hex
    # digest — and `policy=` takes any runtime string, so
    # `policy=f"hipaa-{patient_id}"` would otherwise put a patient id in a
    # third party's request body.
    #
    # ⚠ THIS NARROWED GEMINI'S GRADING INPUT, DELIBERATELY. It no longer
    # receives policy_rules or the ruleset provenance — openai never did. The
    # alternative was to exclude policy_tag_raw alone, which would have left
    # gemini structurally able to receive any key added to ingest LATER: the
    # exact hole being closed. Verdicts for gemini tenants can move as a result,
    # and the two providers now grade one event on IDENTICAL bytes, which they
    # did not before. Pinned by test_judge_content_blindness.py so nobody has to
    # rediscover it as a bug.
    meta = judge.content_blind_meta(meta)
    routing = judge_routing.resolve_judge_routing(db, org_id)
    verdicts = []
    if routing.uses_gemini:
        verdicts.append(
            gemini.evaluate(meta, policy_config, history=history,
                            api_key=routing.gemini_key,
                            model=routing.gemini_model)
            if routing.can_call("gemini")
            else gemini._fallback(routing.problems.get("gemini", "no_api_key")))
    if routing.uses_openai:
        verdicts.append(
            openai_judge.evaluate(meta, policy_config, history=history,
                                    api_key=routing.openai_key,
                                    model=routing.openai_model)
            if routing.can_call("openai")
            else openai_judge._fallback(routing.problems.get("openai", "no_api_key")))
    if routing.uses_qwen:
        # THE AGENTIC JUDGE, and the only one handed a lookup — the other two
        # cannot call a tool at all. `prior_reviews` is bound HERE, to this
        # session, this org and this row's tag, because `qwen_judge` imports no
        # database module and must not start: its `evaluate` docstring says why.
        #
        # ⚠ THE TAG COMES FROM THE PROJECTED `meta`, not from the raw row, so
        # the model is answered about exactly the tag it was shown. `policy_tag`
        # survives `judge.content_blind_meta`; `policy_tag_raw`, the
        # caller-controlled free-text one, does not — and must not become the
        # thing this query groups by, or S12's leak would reopen inside a
        # WHERE clause.
        #
        # ⚠ RESOLVED BEFORE THE CALL, and only on the branch that can actually
        # make one: an org with no usable Qwen key must not pay for a query whose
        # answer nothing will read.
        if routing.can_call("qwen"):
            verdicts.append(
                qwen_judge.evaluate(meta, policy_config, history=history,
                                    api_key=routing.qwen_key,
                                    model=routing.qwen_model,
                                    prior_reviews=_prior_reviews_lookup(
                                        db, org_id, meta.get("policy_tag"))))
        else:
            verdicts.append(
                qwen_judge._fallback(routing.problems.get("qwen", "no_api_key")))
    if not verdicts:
        # ⚠ NEVER reach `verdicts[0]` on an empty list.
        #
        # Q1 opened the policy API to `qwen` and to the combination words before
        # this dispatch learned them (Q3), so an org CAN store a routing word
        # that selects no branch above. `verdicts[0]` would then raise
        # IndexError — and the cost is not one org's grade. `_grade_one` counts
        # the row as a failure, and a batch that fails with zero successes trips
        # the breaker in `_loop`, which is PROCESS-WIDE: one tenant's
        # configuration would pause grading for every tenant.
        #
        # `_fallback` names no provider and stamps graded_by="none", so this
        # records an honest "nothing graded this row" instead of claiming gemini
        # ran. Read at gemini.py::_fallback rather than assumed.
        log.warning("no dispatchable judge for routing %r; the deterministic "
                    "engine will grade this row", routing.provider)
        return gemini._fallback(f"no_dispatchable_judge:{routing.provider}")
    # A LEFT FOLD, not a length test. `if len(verdicts) == 2` was correct while
    # two providers existed and silently wrong the moment a third could be
    # selected: `"all"` produces three verdicts, missed both branches, and fell
    # through to `return verdicts[0]` — discarding two grades, one of which
    # could be the breach. `judge.combine` is associative over its ladder
    # (breach > human_review > clean), so folding gives the same answer in any
    # order, and it stays correct for a fourth provider without editing here.
    result = verdicts[0]
    for verdict in verdicts[1:]:
        result = judge.combine(result, verdict)
    return result


#: Queue an escalated verdict, once per event however many times it is graded.
#:
#: ⚠ `ON CONFLICT DO NOTHING` IS THE POINT, not defensive decoration. `_grade_one`
#: is re-entered for the same row whenever `_handle_failure` puts it back to
#: 'pending' — a provider timeout, a dropped connection, a restart mid-batch — and
#: without this the reviewer's queue would grow one duplicate per retry, every one
#: of them pointing at a single event. The `uq_human_review_audit_log` constraint
#: (0072) is what the inference clause resolves against.
_QUEUE_REVIEW_SQL = text(
    """
    INSERT INTO human_reviews (id, org_id, audit_log_id, status, reason, risk_score)
    VALUES (:id, :org_id, :audit_log_id, 'pending', :reason, :risk_score)
    ON CONFLICT (audit_log_id) DO NOTHING
    RETURNING id
    """
)

#: A2 · §4.6(e). The escalation that is already filed and still needs announcing.
#:
#: Read only when the INSERT above conflicted. It is what turns the notice gate
#: from "did this attempt win the race" into "does this escalation still need
#: announcing" — a question about the escalation rather than about the caller.
#:
#: ⚠ `FOR UPDATE`, AND IT IS THE WHOLE POINT OF THIS STATEMENT. A plain SELECT
#: here reads `notified_at IS NULL`, returns, and lets the caller enqueue — and
#: two graders on one `audit_log_id` can both do that. That is not hypothetical:
#: `_CLAIM_SQL`'s `stuck` reclaim hands a row that has been claimed too long to a
#: second grader while the first may still be running. `ON CONFLICT` is reached
#: only by a RE-ENTRY on an already-filed row — a `_handle_failure` retry or that
#: reclaim — and the reclaim is the one that makes a re-entry CONCURRENT, so this
#: branch and the race are reached together. Both would read NULL, both enqueue,
#: and the duplicate "A review is waiting" email and duplicate `human_review`
#: webhook A1 removed would be back — under concurrency, where the sequential
#: test cannot see them. The lock serialises the read, and READ COMMITTED
#: re-evaluates this WHERE against the row version the winner committed, so the
#: loser wakes to `notified_at IS NOT NULL` and gets no row.
#:
#: ⚠ AND `status = 'pending'`, WHICH IS NOT TIDINESS. 0074 adds the column
#: nullable with no backfill, so EVERY row that existed before it — resolved ones
#: included — reads `notified_at IS NULL`. Without this clause a regrade would
#: email "A review is waiting" about an escalation a person had already closed on
#: the reviewer page, which is worse than the silence it is fixing.
_UNNOTIFIED_REVIEW_SQL = text(
    """
    SELECT id FROM human_reviews
     WHERE audit_log_id = :audit_log_id
       AND status = 'pending'
       AND notified_at IS NULL
     FOR UPDATE
    """
)

#: Stamped once the notice has reached the sender's queue.
#:
#: `notified_at IS NULL` is restated here as an invariant, not as the guard: what
#: actually makes this a one-way door is the row lock the SELECT above took and
#: this transaction still holds.
_MARK_REVIEW_NOTIFIED_SQL = text(
    """
    UPDATE human_reviews SET notified_at = now()
     WHERE id = :id AND notified_at IS NULL
    """
)


def _queue_and_announce_human_review(db: Session, row, verdict) -> None:
    """Put an escalated verdict in front of a person, and tell them. Never raises.

    ⚠ FILE → ENQUEUE → STAMP, IN ONE TRANSACTION HOLDING ONE ROW LOCK. The three
    steps were split across two transactions and that was wrong twice over: the
    conflict read took no lock, and the gap between reading "still unannounced"
    and recording "announced" was a window two graders could both pass through.
    They are one unit now, and the lock is what makes the gate mean anything.

      inserted           we filed it           → announce, stamp
      conflict, unlocked somebody already      → announce ONLY IF the locked row
      row came back      filed it                is still pending and unstamped
      conflict, no row   already announced, or → say nothing
                         already resolved
      exception          nothing was written   → say nothing

    ⚠ THE ORDER IS NOT AN IMPLEMENTATION DETAIL AND MUST NOT BE "SIMPLIFIED".
    Collapsing the read and the stamp into one `UPDATE ... WHERE notified_at IS
    NULL RETURNING id` is shorter, atomic, and WRONG: it stamps BEFORE the
    enqueue, so a crash between them loses the announcement permanently — which
    is §4.6(e) again, in the code written to close it. The loss has to fall the
    other way. A duplicate notice is noise; a missing one is the defect.

    ⚠ AND HOLDING THE LOCK ACROSS THE ENQUEUE COSTS NOTHING, which is the reason
    this shape is affordable. `enqueue_escalation_notice` is a `put_nowait` on a
    bounded in-memory queue — it never touches the network, because the whole
    point of moving the notice off the grading batch was that a wedged mail
    provider must not stall the worker heartbeat. The lock is held for two
    statements and a list append.

    ⚠ A2 · §4.6(e) MOVED THE MIDDLE CASE, AND THAT IS THE WHOLE CHANGE. A1
    answered "did *this* attempt file it", which was the right correction to a
    gate that was always True: `_grade_one` is re-entered for the same row every
    time `_handle_failure` puts it back to 'pending', the unique constraint bounds
    the QUEUE at one entry and bounds the NOTICE at nothing, so a row retried
    three times sent three "A review is waiting" emails for one determination.
    What that correction also removed, unnoticed, was the duplicate's second job:
    it was a de-facto RECOVERY. Afterwards every later regrade conflicted and
    stayed silent, so a notice dropped by a full queue was dropped for good.

    So the conflict path now asks the ROW whether it has been announced, instead
    of asking the CALLER whether it did the announcing. A regrade of an
    escalation that WAS announced still sends nothing — pinned by
    `test_a_regrade_does_not_announce_the_same_escalation_twice` — and a regrade
    of one that was not gets the announcement A1 could not give it. Under
    concurrency the same two questions are answered by
    `test_a_second_grader_that_loses_the_race_announces_nothing`, and an
    escalation a person already closed is answered by
    `test_a_regrade_does_not_announce_an_escalation_a_human_already_closed`.

    ⚠ AND THE LAST CASE IS STILL NOT FIXED BY UN-GATING. Announcing an escalation
    whose insert FAILED would email about a worklist entry that is never going to
    appear, and §4.6(a) records that nothing reconciles a dropped insert — so the
    entry stays missing and the customer searches for it. A notice pointing at
    nothing is worse than silence in a product whose claim is that the record is
    complete. The fix for that path is the reconciliation sweep in §4.6(a), which
    would file the row AND, filing it, leave `notified_at` NULL for this gate.

    ⚠ THE GRADE IS ALREADY COMMITTED WHEN THIS RUNS, and that ordering is the
    contract: exactly like the breach notifier above it, a failure here must cost
    the escalation's QUEUE ENTRY and never the verdict. The escalation itself is
    already durable and already in the append-only record — `_grade_one` wrote it
    to `audit_logs.gemini_verdict` and appended the `verdict` AuditEvent carrying
    `decision="human_review"`, its reason and its risk score — so a failed insert
    loses the worklist row, not the evidence.

    ⚠ NO SECOND AuditEvent IS APPENDED HERE. The `verdict` event above already
    records this escalation, hashed and append-only; a `human_review_queued` twin
    would be the same facts under a second name. The append-only half of A1's
    two-vehicle design is the HUMAN's decision — `human_review_resolved`, written
    by `POST /v1/reviews/{id}/resolve`, which is a fact the ledger does not
    otherwise hold.

    Re-scopes RLS: `_grade_one`'s `set_config(..., true)` is transaction-local and
    the commit before this call ended that transaction.
    """
    try:
        db.execute(text("SELECT set_config('app.current_org', :oid, true)"),
                   {"oid": str(row["org_id"])})
        filed = db.execute(_QUEUE_REVIEW_SQL,
                   {"id": uuid.uuid4(), "org_id": row["org_id"],
                    "audit_log_id": row["id"],
                    # ⚠ THE SLICE IS FOR THE MERGED CASE, NOT THE TOOL CALL, AND
                    # IT TRUNCATES RATHER THAN GUARDS. `qwen_judge._escalation`
                    # already bounds its reason at 300, so on a single-judge
                    # escalation this is a no-op. An escalation that SURVIVED
                    # `judge.combine` — qwen escalating beside gemini returning
                    # clean — carries a merged reason instead: a
                    # `multi_judge_human_review: ` prefix plus both judges'
                    # 300-character reasons. Without the slice that INSERT would
                    # raise, best-effort would swallow it, and the queue would
                    # silently lose its entry precisely when two judges
                    # disagreed — the case a person most needs to see. With it,
                    # the entry always lands and the worklist's copy of a merged
                    # reason is cut at 300 characters; the full text is on the
                    # ledger row's `gemini_verdict` either way, so nothing is
                    # lost from the record, only from the worklist's preview.
                    "reason": verdict.reason[:300],
                    "risk_score": verdict.risk_score}).scalar_one_or_none()
        if filed is None:
            # ON CONFLICT DO NOTHING fired: the row is there and an earlier
            # attempt filed it. Whether that attempt's notice ever reached the
            # sender is a recorded fact now rather than an assumption — and this
            # read LOCKS the row, so the answer cannot change between reading it
            # and acting on it.
            filed = db.execute(_UNNOTIFIED_REVIEW_SQL,
                               {"audit_log_id": row["id"]}).scalar_one_or_none()
        # The INSERT path needs no explicit lock: an uncommitted insert already
        # holds the row, so a second grader's `ON CONFLICT` waits on it and then
        # takes the conflict branch above against the committed result.
        if filed is not None and org_notifications.enqueue_escalation_notice(
                row, verdict):
            db.execute(_MARK_REVIEW_NOTIFIED_SQL, {"id": filed})
        db.commit()
    except Exception as exc:                                  # noqa: BLE001
        db.rollback()
        log.warning("queueing human review for %s failed (%s)",
                    row["id"], type(exc).__name__)


def _claim_batch(db: Session, batch: int, stuck: int) -> list:
    """Claim up to `batch` rows for grading; returns their metadata mappings."""
    rows = db.execute(_CLAIM_SQL, {"batch": batch, "stuck": stuck}).mappings().all()
    db.commit()   # release the row locks before the (possibly slow) Gemini call
    return list(rows)


def _grade_one(db: Session, row) -> None:
    """Grade one claimed row with its org's policy and persist the verdict."""
    meta = {
        "prompt_hash": row["prompt_hash"],
        "response_hash": row["response_hash"],
        "token_count": row["token_count"],
        "policy_tag": row["policy_tag"],
        "pii_signals": row["pii_signals"],
        "event_id": str(row["event_id"]) if row.get("event_id") else None,
        "event_type": row.get("event_type"),
        "commitment_alg": row.get("commitment_alg"),
        "event_metadata": row.get("event_metadata"),
    }
    if row.get("event_type") in policy_engine.ENFORCEMENT_EVENT_TYPES:
        # Terminal & locally decided (blocked/redacted): the host already enforced
        # policy and there is no model response to grade. Never call the judge —
        # write a deterministic verdict from the enforcement labels instead.
        verdict = policy_engine.evaluate_enforcement(meta)
    else:
        policy_config = _policy_config(db, row["org_id"], row.get("event_metadata"))
        history = _org_history(db, row["org_id"])
        verdict = _judge_verdict(db, row["org_id"], meta, policy_config, history)
        # Never persist a self-contradictory or empty judge answer as a confident
        # grade — quarantine it as evaluator_unknown to keep the audit report honest.
        verdict = judge.validate(verdict)
        if verdict.decision == "unknown" and verdict.reason.startswith("evaluator_unavailable"):
            # ── #228 · THE SUBSTITUTION STAYS. WHAT IT LEAVES BEHIND CHANGES. ──
            #
            # An unreachable judge must not leave the row ungraded — the
            # deterministic engine is a real grade of this metadata and dropping
            # it would be a safety regression, not a fix. What was wrong was that
            # the swap was TOTAL: the rules verdict landed in the same column, in
            # the same shape, under a confident decision, and every trace that no
            # model had run went with the verdict it replaced. `judge_provider`
            # stayed null, which is the only thing that ever distinguished this
            # row from an AI-graded one — a null inside a JSON blob, identical to
            # the null on a row whose judge answered incoherently.
            #
            # So the replacement now carries two facts forward:
            #   graded_by="rules"                 from policy_engine — the
            #                                     POSITIVE statement of authorship
            #   evaluator_unavailable_reason      from the verdict being discarded
            #                                     — WHY the AI never ran
            #
            # Both, rather than either: "graded by rules" without the reason is
            # unactionable ("is my key broken, or does this deployment just not
            # do AI grading?"), and the reason without the authorship is the old
            # defect in a new coat — a fact about a verdict nobody can see.
            #
            # ⚠ The DECISION deliberately stays the rules engine's clean/breach.
            # Forcing it back to `unknown` would drop every breach the metadata
            # rules do catch, and this really is a grade — of the metadata, by
            # rules, which is now exactly what it says.
            verdict = policy_engine.evaluate(meta, policy_config).model_copy(
                update={"evaluator_unavailable_reason":
                        verdict.evaluator_unavailable_reason})
    # Scope RLS to this row's org before the write-back (no-op under a
    # BYPASSRLS/superuser role, required under a hardened one).
    db.execute(text("SELECT set_config('app.current_org', :oid, true)"),
               {"oid": str(row["org_id"])})
    db.execute(_MARK_GRADED_SQL,
               {"id": row["id"], "verdict": json.dumps(verdict.model_dump())})
    payload = verdict.model_dump()
    event_blob = json.dumps({"audit_log_id": str(row["id"]),
                             "event_type": "verdict", "payload": payload,
                             "parent_chain_hash": row.get("chain_hash", "")},
                            sort_keys=True, separators=(",", ":"))
    db.add(AuditEvent(
        org_id=row["org_id"], audit_log_id=row["id"], event_type="verdict",
        payload=payload, event_hash=hashlib.sha256(event_blob.encode()).hexdigest(),
    ))
    db.commit()
    # Fire the breach notifier AFTER the verdict is durably committed, so a notify
    # failure can never lose the grade. Best-effort — never raises into grading.
    if verdict.policy_breach:
        # Both breach notifications are queued, never sent here.
        org_notifications.enqueue_breach_notice(row, verdict)
        # Per-user fan-out (D-S): one email per opted-in seat.
        user_notifications.enqueue_breach_alert(row, verdict)
    # ── A1 · the escalation finally has somewhere to go ──────────────────────
    #
    # ⚠ BESIDE THE BRANCH ABOVE, NEVER FOLDED INTO IT. Widening
    # `if verdict.policy_breach:` to cover an escalation would be the shortest
    # edit and the wrong one twice over: `policy_breach` is `False` on a
    # human_review BY DESIGN (`judge.py`, `schemas.py`) and `judge.validate`
    # refuses the pair, and `passport.compliant_events` subtracts breaches and
    # escalations SEPARATELY — so a human_review counted as a breach would move a
    # headline number on the artefact a customer hands to a regulator. A request
    # to look at something is not a finding.
    #
    # Read off `decision` rather than off the tool call: `judge.combine` folds
    # three providers and its ladder (breach > human_review > clean) is what
    # decides whether an escalation SURVIVED the merge. A qwen escalation beside
    # a gemini breach is a breach, and must not also queue a review.
    if verdict.decision == "human_review":
        # ⚠ AND THE ESCALATION IS ANNOUNCED, not merely filed — but ONLY IF IT
        # STILL NEEDS ANNOUNCING. A worklist row nobody is told about is the same
        # defect A1 exists to close wearing a different hat. The insert above is
        # best-effort by design, so the notice stays gated on its result: nothing
        # reconciles a dropped insert (plan §4.6(a)), and an email about a queue
        # row that will never exist sends the customer looking for something that
        # is not there. Queued, never sent here — the same contract as the breach
        # notices above.
        #
        # ⚠ THE THREE STEPS ARE ORDERED AND SERIALISED, AND THAT IS THE FIX
        # (§4.6(e)). File, then enqueue, then stamp — one transaction, one row
        # lock — so a regrade of an announced escalation is silent, a regrade of
        # a dropped one recovers it, a second grader on the same row cannot do
        # both at once, and a crash between enqueue and stamp costs a duplicate
        # notice rather than the announcement itself. A2 also removes this
        # path's monopoly: the reviewer page is a PULL surface that does not
        # depend on a notice having been delivered at all.
        _queue_and_announce_human_review(db, row, verdict)
    # Outbound webhook subscriptions (P3 §F): a signed 'graded' (and 'breach')
    # event per matching subscription. QUEUED, not delivered here — this fires
    # on EVERY graded row, and one synchronous POST per subscription inside the
    # batch was the largest remaining way for a slow third party to stall the
    # worker heartbeat and trip /health/ready.
    #
    # With this, NO outbound provider call happens inside the grading batch:
    # the two emails and the webhooks all cross a queue to their own threads.
    # (That claim was previously written above the emails alone, while this
    # call was still POSTing inline — the claim is now true of the whole path.)
    webhook_delivery.enqueue_grading(
        row["org_id"], is_breach=bool(verdict.policy_breach),
        payload={"seq": row.get("seq"), "policy_tag": row.get("policy_tag"),
                 "decision": verdict.decision, "risk_score": verdict.risk_score,
                 "chain_hash": row.get("chain_hash")})


def _handle_failure(db: Session, row, max_attempts: int, exc: Exception) -> None:
    db.rollback()
    attempts = row["grading_attempts"] or 0
    sql = _MARK_FAILED_SQL if attempts >= max_attempts else _MARK_RETRY_SQL
    try:
        db.execute(sql, {"id": row["id"]})
        db.commit()
    except Exception:
        db.rollback()
    log.warning("grading %s for %s (attempt %s): %s",
                "FAILED (dead-letter)" if attempts >= max_attempts else "retry",
                row["id"], attempts, exc)


class CircuitBreaker:
    """Trips OPEN after `threshold` consecutive systemic failures and stays open
    for `cooldown` seconds (work is skipped). After the cooldown one trial is
    allowed; a success closes + resets it, a failure slides the window forward.
    Keeps the grading poller from hammering a down Gemini / burning attempts (5E.2)."""

    def __init__(self, threshold: int, cooldown: float):
        self.threshold = threshold
        self.cooldown = cooldown
        self.failures = 0
        self.opened_at: float | None = None

    def on_success(self) -> None:
        self.failures = 0
        self.opened_at = None

    def on_failure(self, now: float) -> None:
        self.failures += 1
        if self.failures >= self.threshold:
            self.opened_at = now          # (re)open, sliding the cooldown window

    def allow(self, now: float) -> bool:
        """True if work should proceed (closed, or a half-open trial post-cooldown)."""
        return self.opened_at is None or (now - self.opened_at) >= self.cooldown


# The poller's own generator, not the shared `random` module one, so nothing
# else in the process can seed away the spread. Unseeded → OS entropy.
_jitter = random.Random()


def backoff_ceiling(failures: int, base: float, cap: float) -> float:
    """Capped exponential ceiling: base, base, 2·base, 4·base … ≤ cap.

    The undithered curve, kept as its own function because it is the property
    worth asserting — monotonic non-decreasing, and never above the cap."""
    if failures <= 0:
        return base
    return min(cap, base * (2 ** (failures - 1)))


def backoff_delay(failures: int, base: float, cap: float) -> float:
    """:func:`backoff_ceiling` with EQUAL JITTER — half fixed, half random.

    ⚠ THE REASON HERE IS NOT THE ONE THAT APPLIES TO THE SDK. The SDK's spool
    runs in every customer process, so an outage synchronises a whole fleet onto
    one curve and the thundering herd is real. This poller is a SINGLE process:
    deploy/docker-compose.prod.yml runs one `foxy-worker`, with a fixed
    container_name and no `replicas`, so there is no fleet here to spread.

    What jitter buys at this site is narrower, and worth stating rather than
    borrowing the other argument:

    * the poll cadence is otherwise perfectly periodic, so it can land in phase
      with a downstream per-minute rate-limit window and stay there, retrying
      into the same closed window every time;
    * the container restarts on failure, and an undithered sequence replays
      identically from zero each time it does;
    * and it stops being a single process the day anyone sets `replicas: 2`, at
      which point the fleet argument does apply and this is already right.

    Same scheme as the SDK so there is one answer to explain, and the same
    guaranteed floor: the poller never retries a downed judge immediately."""
    ceiling = backoff_ceiling(failures, base, cap)
    return ceiling / 2.0 + _jitter.uniform(0.0, ceiling / 2.0)


def _interruptible_sleep(stopping: dict, seconds: float) -> None:
    """Sleep up to `seconds`, waking promptly when shutdown is requested."""
    waited = 0.0
    while waited < seconds and not stopping["flag"]:
        time.sleep(min(1.0, seconds - waited))
        waited += 1.0


def _anchor_loop(stopping: dict, s) -> None:
    """Anchor each org's chain head on an interval, in its OWN thread and DB
    session. Kept off the grading poll loop so a slow chain RPC (an EVM receipt
    wait can take many seconds) can never starve grading or delay the liveness
    heartbeat — 'anchoring never blocks ingest/grading'."""
    log.info("Public-chain anchoring ON (provider=%s interval=%ss)",
             s.anchor_provider, s.anchor_interval_seconds)
    while not stopping["flag"]:
        db = SessionLocal()
        try:
            n = anchor_all_due(db, s)
            if n:
                log.info("anchored %s org(s)", n)
            # A1: the STAFF chain rides the same thread. It is platform-wide,
            # so one call, not a sweep — and it is here rather than on the
            # staff-action write path, which is already platform-serialised.
            staff_anchor = anchor_admin(db, s)
            if staff_anchor is not None:
                log.info("anchored staff chain @ seq %s (%s)",
                         staff_anchor.last_seq, staff_anchor.status)
            # 7C: page someone if anchors are failing or the chain went stale.
            alert_on_anchor_problems(db, s, _ANCHOR_ALERT_STATE)
        except Exception as exc:               # noqa: BLE001 — a bad sweep must not kill the thread
            log.warning("anchor loop error: %s", exc)
        finally:
            db.close()
        # Interruptible sleep so shutdown is prompt even on a long interval.
        waited = 0.0
        while waited < s.anchor_interval_seconds and not stopping["flag"]:
            time.sleep(min(1.0, s.anchor_interval_seconds - waited))
            waited += 1.0


def run_forever() -> None:
    """Poll the outbox until interrupted. Entry point for `app.worker_main`."""
    s = get_settings()
    log.info("Foxy grading poller started (interval=%ss batch=%s)",
             s.grading_poll_interval, s.grading_batch_size)

    stopping = {"flag": False}

    def _stop(*_):
        stopping["flag"] = True

    try:
        signal.signal(signal.SIGINT, _stop)
        signal.signal(signal.SIGTERM, _stop)
    except ValueError:
        pass   # not the main thread (e.g. a lifespan-daemon fallback)

    if s.anchor_enabled:
        threading.Thread(target=_anchor_loop, args=(stopping, s),
                         name="foxy-anchor", daemon=True).start()

    # Usage rollups + traffic-partition maintenance run in their own thread so a
    # slow rollup never stalls grading or the liveness heartbeat.
    from .usage import usage_loop
    threading.Thread(target=usage_loop, args=(stopping, s),
                     name="foxy-usage", daemon=True).start()

    # Org-policy breach notices, own thread + session. NOT gated on
    # user_notifications_enabled: that switch governs the per-user preference
    # fan-out, and using it to also silence a tenant's configured policy notice
    # would disable a paid feature by accident.
    from .org_notifications import org_notifications_loop
    threading.Thread(target=org_notifications_loop, args=(stopping, s),
                     name="foxy-org-notifications", daemon=True).start()

    # Outbound webhook subscriptions, same shape and same reason: this fires on
    # every graded row, so it must never POST from the grading batch.
    from .webhook_delivery import webhook_delivery_loop
    threading.Thread(target=webhook_delivery_loop, args=(stopping, s),
                     name="foxy-webhooks", daemon=True).start()

    # Per-user breach alerts + weekly digest + key-rotation reminders (D-S), own
    # thread + session so a slow mail provider never stalls grading.
    if s.user_notifications_enabled:
        from .user_notifications import user_notifications_loop
        threading.Thread(target=user_notifications_loop, args=(stopping, s),
                         name="foxy-user-notifications", daemon=True).start()

    # Circuit-breaker so a Gemini outage doesn't hammer the API or burn attempts:
    # when whole batches keep failing, trip open and back off (5E.2).
    breaker = CircuitBreaker(s.grading_breaker_threshold, s.grading_breaker_cooldown)
    while not stopping["flag"]:
        if not breaker.allow(time.time()):
            _interruptible_sleep(stopping, s.grading_poll_interval)   # open → wait out cooldown
            continue
        rows: list = []
        db = SessionLocal()
        try:
            rows = _claim_batch(db, s.grading_batch_size, s.grading_stuck_seconds)
            ok = fail = 0
            for row in rows:
                try:
                    _grade_one(db, row)
                    ok += 1
                except Exception as exc:   # noqa: BLE001 — never let one row kill the loop
                    _handle_failure(db, row, s.grading_max_attempts, exc)
                    fail += 1
            # Liveness heartbeat (busy OR idle) so /health/ready can detect a
            # dead/stuck worker before the grading queue backs up silently.
            db.execute(text("UPDATE worker_heartbeat SET beat_at = now() WHERE id = 1"))
            db.commit()
            if rows:
                # A whole batch failing with none graded => Gemini is likely down
                # (systemic) → trip the breaker; any success closes it.
                if ok == 0 and fail > 0:
                    breaker.on_failure(time.time())
                else:
                    breaker.on_success()
            # NOTE: public-chain anchoring runs in its own thread (_anchor_loop),
            # NOT here — a slow chain RPC must never stall grading or the heartbeat.
        except Exception as exc:           # noqa: BLE001 — claim/DB hiccup: back off
            db.rollback()
            log.warning("poll loop error: %s", exc)
        finally:
            db.close()
        # Idle → poll interval; systemic failures → capped exponential backoff.
        # Interruptible so SIGTERM drains the in-flight batch then exits promptly.
        if not rows:
            _interruptible_sleep(stopping, s.grading_poll_interval)
        elif breaker.failures > 0:
            _interruptible_sleep(
                stopping, backoff_delay(breaker.failures, s.grading_poll_interval, s.grading_max_backoff))

    log.info("Foxy grading poller stopped")
