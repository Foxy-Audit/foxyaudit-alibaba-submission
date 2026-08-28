"""POST /v1/logs/batch — ingest a batch of interactions into the hash chain.
GET  /v1/logs, /v1/logs/{seq}, /v1/stats — dashboard reads.

Durable ingest (hybrid): the batch is written to the chain SYNCHRONOUSLY — each
row lands with grading_status='pending', committed before the 202 — so a crash
can never lose it. The expensive Gemini grading is deferred to the durable poller
in app/worker.py, which claims 'pending' rows and back-fills the verdict using the
org's policy config. Chain hashing stays cheap and inline; only grading is async.
"""

from __future__ import annotations

import csv
import io
import json
import uuid
from datetime import datetime, timedelta, timezone
from typing import List

from fastapi import APIRouter, Depends, HTTPException, Query, Request, Response
from sqlalchemy import func, or_, select, text
from sqlalchemy.orm import Session
from starlette.status import HTTP_202_ACCEPTED

from .. import billing_state, export_bundle, policy_engine
from ..anchor import latest_anchor
from ..auth import require_org, resolve_org
from ..chain import (
    CHAIN_VERSION_VERDICT_V4, GENESIS_HASH, compute_chain_hash, verdict_hash_hex,
)
from ..config import get_settings
from ..db import get_db
from ..models import AiSystem, AuditLog, OrgPolicy, Organization, OrganizationSequence
from ..policy_snapshot import (
    capture_policy_snapshot, judge_policy_config, policy_snapshot_hash,
)
from ..schemas import (
    ActivityDay, GradingCounts, LogIngest, LogListItem, LogListResponse,
    StatsResponse,
)
# The one spelling of the terminal lifecycle, imported rather than repeated so
# this router and the registry that writes it cannot drift apart. `systems` does
# not import this module, so the dependency is one-way.
from .systems import RETIRED

from slowapi import Limiter
from slowapi.util import get_remote_address


def _rate_limit_key(request: Request) -> str:
    auth = request.headers.get("Authorization")
    if auth:
        return auth
    return get_remote_address(request)


limiter = Limiter(key_func=_rate_limit_key)

router = APIRouter()

# Reads filter explicitly on org_id (the app DB role is a superuser that bypasses
# RLS, so the WHERE clause is what enforces tenant isolation — as in verify.py).
_BREACH = AuditLog.gemini_verdict["policy_breach"].astext == "true"
_UNKNOWN = (
    (AuditLog.gemini_verdict["decision"].astext == "unknown")
    | (AuditLog.gemini_verdict["reason"].astext.like("evaluator_unavailable:%"))
    | (AuditLog.gemini_verdict["reason"].astext == "evaluator_unavailable")
)
# #228 · authorship, read from the stored verdict. Not `GROUP BY` on the JSON
# path: SQLAlchemy binds the key as a parameter and Postgres will not match two
# separately-bound expressions, so the group key never equals the select key.
# Filtered aggregates keep both numbers on one scan of one row set, which is the
# property that mattered.
_GRADED_BY_AI = AuditLog.gemini_verdict["graded_by"].astext == "ai"
_GRADED_BY_RULES = AuditLog.gemini_verdict["graded_by"].astext == "rules"


def _validate_system_attributions(db: Session, org: Organization, items: list) -> None:
    """Refuse an event attributed to a system this org may not attribute to (R2).

    `system_id` arrives SHAPE-CHECKED but unbound: `schemas.LogIngest` has no
    database, so all it could say is "that is the spelling of a UUID". Here it
    becomes an ATTRIBUTION — a claim that one of this customer's declared AI
    systems produced this event — and there are exactly two ways for the claim
    to be false.

    ⚠ NOT DECLARED AND NOT YOURS ARE ONE BRANCH, ON PURPOSE. A foreign tenant's
    id must be indistinguishable from one that was never declared, or POST
    /v1/logs/batch becomes an existence oracle over other customers' estates:
    guess a UUID, watch the answer change. `routers/systems.py` answers 404
    rather than 403 for the same reason — what mattered there was
    indistinguishability, not the number. Here the number cannot be 404 (see
    below), so the property is carried by the two cases sharing a code path,
    which is stronger than two messages somebody has to keep in step.

    ⚠ 422 CARRYING THE ALLOWLIST'S PHRASE — NOT A NEW PHRASE, AND NOT A 404.
    `dispatch._rejects_unsupported_fields` recognises exactly one rejection: a
    422 whose body contains "unsupported fields". And `payload: List[LogIngest]`
    is refused as ONE unit, so a message the SDK does not recognise means no
    strip-and-retry, then `raise_for_status`, then `spool.retry` re-queuing the
    whole batch — forever. Ten events lost to an eleventh naming a system
    somebody retired last week. A 404 would do the same while also reading as a
    missing endpoint.

    ⚠ WHICH SYSTEM, AND WHY. A bare "unsupported fields" sends an operator to
    the SDK version, which is the wrong place entirely: the SDK is fine, the id
    is well-formed, and a human retired the system on purpose. Naming the id is
    safe here and only here — it has passed the shape check, so it is provably
    36 characters of hex and hyphens and can carry nothing of its own.

    ⚠ NEW ITEMS ONLY. A duplicate is already chained, so refusing its resend
    would brick a spool over an event this ledger already holds, and no new
    attribution is being made either way. Retirement closes what a system may
    still RECORD; it never reaches back into what it already did.

    ⚠ `AiSystem.org_id == org.id` IS THE ISOLATION, AND NO BEHAVIOURAL TEST CAN
    GUARD IT. `require_org` runs `auth._scope_org`, which drops to the confined
    `foxy_app` role, and `ai_systems` is a posture-A table — so with the clause
    deleted, RLS still hides the other tenant's row and the cross-tenant test
    still passes. That is the design working, not a licence to drop the clause
    (staff and worker paths never take that role), so it is asserted at the
    SOURCE by
    test_the_attribution_check_filters_by_org_itself_and_does_not_lean_on_rls.
    """
    spellings = sorted({(item.event_metadata or {}).get("system_id")
                        for item in items} - {None})
    if not spellings:
        return
    # Canonical spelling is enforced upstream, so this mapping is 1:1 and the
    # sorted order carries into it — the same bad batch always names the same
    # system first.
    wanted = {uuid.UUID(spelling): spelling for spelling in spellings}
    declared = dict(db.execute(
        select(AiSystem.id, AiSystem.lifecycle_status)
        .where(AiSystem.org_id == org.id, AiSystem.id.in_(list(wanted)))
    ).all())
    for system_id, spelling in wanted.items():
        lifecycle = declared.get(system_id)
        if lifecycle is None:
            raise HTTPException(
                status_code=422,
                detail="event_metadata contains unsupported fields: system_id "
                       f"{spelling} names no AI system in this workspace. "
                       "Declare it with POST /v1/systems, or send the event "
                       "without an attribution.")
        if lifecycle == RETIRED:
            raise HTTPException(
                status_code=422,
                detail="event_metadata contains unsupported fields: system_id "
                       f"{spelling} names an AI system that has been RETIRED, "
                       "and a retired system accepts no new events. Its existing "
                       "evidence is untouched. Attribute this event to a system "
                       "still in service, or declare a new one.")


@router.post("/v1/logs/batch", status_code=HTTP_202_ACCEPTED)
@limiter.limit("60/minute")
def ingest_batch(
    request: Request,
    payload: List[LogIngest],
    org: Organization = Depends(require_org),
    db: Session = Depends(get_db),
):
    """Write the batch to the hash chain synchronously (durable). Each row lands
    grading_status='pending' (column default); the poller grades them async."""
    # The sequence row exists even for an empty ledger. Locking it avoids the
    # classic first-ingest race where two writers both choose seq=1.
    db.execute(text(
        "INSERT INTO org_sequences(org_id, next_seq) "
        "SELECT :org_id, COALESCE(MAX(seq) + 1, 1) FROM audit_logs WHERE org_id = :org_id "
        "ON CONFLICT (org_id) DO NOTHING"), {"org_id": org.id})
    sequence = db.execute(
        select(OrganizationSequence).where(OrganizationSequence.org_id == org.id)
        .with_for_update()
    ).scalar_one()

    # A retry with the same event_id returns the original receipt. A conflicting
    # payload is rejected rather than silently treating two events as one.
    existing_receipts = []
    new_items = []
    for item in payload:
        existing = None
        if item.event_id:
            existing = db.execute(
                select(AuditLog).where(AuditLog.org_id == org.id,
                                       AuditLog.event_id == item.event_id)
            ).scalar_one_or_none()
            stored_metadata = dict(existing.event_metadata or {}) if existing else {}
            stored_metadata.pop("client_seq_gap", None)
            stored_metadata.pop("policy_snapshot", None)
            stored_metadata.pop("policy_snapshot_hash", None)
            requested_metadata = dict(item.event_metadata or {})
            # Ruleset provenance is excluded from the identity comparison, on
            # BOTH sides. It describes the RULES, not the interaction, so two
            # posts of one event_id differing only here are the same event —
            # the same reasoning that already excludes the three keys above.
            #
            # Popping it is also what stops the SDK's degrade path deadlocking a
            # row. These keys are CLIENT-supplied, so unlike the server-injected
            # three they persist in the stored row: a row stored WITH provenance
            # whose spool entry outlives the POST (a crash before ack) is later
            # resent to a backend that rejects provenance — a failed deploy, a
            # mixed fleet mid-rollout, a downgrade, which is precisely the case
            # that path exists for. The SDK strips the keys and retries; without
            # this pop the resend could never match the stored row, so it would
            # 409 forever and take the other nine events in its batch down with
            # it on every retry.
            #
            # policy_tag_raw is here for that SECOND reason only. The first one
            # does not cover it: it is what the CALLER TYPED, so it describes
            # neither the rules nor the interaction. The degrade path does
            # cover it, identically — it is client-supplied, it persists in the
            # stored row, and the SDK half of S13 adds it to
            # ruleset.PROVENANCE_KEYS, the same tuple _strip_provenance walks,
            # so a resend to a backend that rejects it arrives without it and
            # would 409 against its own stored row forever. This pop lands
            # first, on purpose: the backend must forgive the stripped resend
            # before any SDK is able to strip one.
            #
            # It does not blunt the check. `policy_tag` — the CANONICAL tag —
            # is still compared below, so two events whose canonical tags
            # differ still 409. Only two SPELLINGS of one canonical tag now
            # compare equal, and those are the same event. And a resend never
            # overwrites the stored row, so nothing already recorded as
            # evidence can change either way.
            #
            # That "only two spellings" is ENFORCED, not assumed:
            # LogIngest._typed_tag_is_bounded_and_is_the_same_tag refuses a
            # policy_tag_raw that does not fold to this row's policy_tag. Before
            # it existed the sentence above was false — policy_tag="hipaa" with
            # policy_tag_raw="PCI" ingested, and this pop then made a resend
            # carrying a DIFFERENT typed tag a 202 duplicate. Relax that
            # validator and this comment goes back to being a hope.
            for _excluded_key in ("ruleset_version", "ruleset_hash", "policy_tag_raw"):
                stored_metadata.pop(_excluded_key, None)
                requested_metadata.pop(_excluded_key, None)
            # ⚠ `system_id` IS NOT ON THAT LIST, AND THE DIFFERENCE IS THE
            # DECISION, NOT AN OVERSIGHT.
            #
            # The keys above describe the RULES or the SPELLING, so two posts of
            # one event_id differing only there are the same event. `system_id`
            # is IDENTITY-BEARING: it names which of the customer's AI systems
            # produced this interaction. Two posts claiming two different
            # systems are a real disagreement about the evidence, and popping it
            # would answer the second with a 202 "duplicate" while the ledger
            # went on holding the first — a client told its attribution landed
            # when it did not. `policy_tag` is still compared for exactly that
            # reason and this is the same reason.
            #
            # But the deadlock argument that put the other three here applies to
            # it UNCHANGED: it is client-supplied, so it persists in the stored
            # row; R3 adds it to the SDK's degrade ladder; and a row stored WITH
            # an attribution whose spool entry outlives its ack (a crash before
            # the POST is acknowledged) is later resent WITHOUT one to a backend
            # that has been rolled back below R2. If the comparison counted it,
            # that resend could never match its own stored row — 409 forever,
            # taking the other nine events in the batch down on every retry.
            #
            # Both are true, so the rule is ASYMMETRIC rather than a pop:
            # compared when BOTH sides carry it, ignored when only one does.
            # Present-on-one is precisely the degrade shape — stripped on
            # resend, or degraded-then-recovered, which is the same case
            # backwards. Present-on-both-and-different is precisely the identity
            # shape. No case needs both readings, so neither has to give.
            #
            # It is not a transitive relation — {A} matches {}, {} matches {B},
            # {A} does not match {B} — and it does not need to be. The
            # comparison is always THIS stored row against THIS request, and a
            # duplicate never rewrites the stored row, so the attribution an
            # auditor reads stays the one that was chained.
            if ("system_id" in stored_metadata) != ("system_id" in requested_metadata):
                stored_metadata.pop("system_id", None)
                requested_metadata.pop("system_id", None)
            if existing and any((
                existing.prompt_hash != item.prompt_hash,
                existing.response_hash != item.response_hash,
                existing.token_count != item.token_count,
                existing.policy_tag != item.policy_tag,
                existing.agent != item.agent,
                existing.client_id != item.client_id,
                existing.client_seq != item.client_seq,
                existing.event_type != item.event_type,
                existing.commitment_alg != item.commitment_alg,
                existing.pii_signals != item.pii_signals,
                stored_metadata != requested_metadata,
                existing.occurred_at != item.occurred_at,
            )):
                raise HTTPException(status_code=409,
                                    detail=f"event_id {item.event_id} was already used with different content")
        if existing:
            existing_receipts.append({
                "event_id": str(item.event_id), "seq": existing.seq,
                "chain_hash": existing.chain_hash, "status": "duplicate",
            })
        else:
            new_items.append(item)

    # Placed with the conflict check above rather than after the billing gate,
    # because it is the same KIND of thing: a statement about the payload, which
    # is true or false before the org's account state is consulted. A customer
    # whose instrumentation still names a system somebody retired last week
    # should hear that, not hear about their card.
    _validate_system_attributions(db, org, new_items)

    now = datetime.now(timezone.utc)
    # trial_expired → subscription_inactive → the evaluation pair, in that order.
    # D1 moved the set itself into billing_state so the dashboard gate and this
    # one can no longer disagree about what "not paying" means — and so that the
    # difference between them is deliberate and written down: `past_due` and
    # `incomplete` lock the DASHBOARD and never stop capture, because evidence
    # cannot be re-created after the fact and a declined card can be. E1 moved
    # the evaluation pair in too; it was the one D1 left behind, which is why
    # /v1/billing/access could not report it.
    blocked = billing_state.capture_block(org, now, pending=len(new_items))
    if blocked is not None:
        raise HTTPException(status_code=402,
                            detail={"code": blocked.reason, "message": blocked.message})

    # Enforce credits against the ledger, not the eventually-consistent usage
    # rollup. The sequence row is already locked, so concurrent writers cannot
    # both spend the same remaining credits.
    quota = org.monthly_log_quota
    if quota is not None and new_items:
        month_start = now.replace(day=1, hour=0, minute=0, second=0, microsecond=0)
        used = db.execute(
            select(func.count()).select_from(AuditLog).where(
                AuditLog.org_id == org.id, AuditLog.created_at >= month_start)
        ).scalar_one()
        if int(used) + len(new_items) > quota:
            raise HTTPException(
                status_code=402,
                detail={"code": "credits_exhausted", "message": "Monthly audit-event credits are exhausted. Upgrade to continue capturing events.",
                        "used": int(used), "included": quota, "requested": len(new_items)},
            )

    # Freeze the policy that applies to this batch before writing any evidence.
    # The safe snapshot and its digest are included in the V3 chain payload, so a
    # later policy update cannot rewrite the configuration that was assessed.
    snapshot = None
    snapshot_hash = None
    policy_config = None
    if new_items:
        policy = db.get(OrgPolicy, org.id)
        if policy is None:
            policy = OrgPolicy(org_id=org.id)
            db.add(policy)
            db.flush()
        snapshot = capture_policy_snapshot(policy)
        snapshot_hash = policy_snapshot_hash(snapshot)
        # The same projection the worker hands a judge, so the verdict chained
        # here was decided under exactly the config the snapshot records.
        policy_config = judge_policy_config(snapshot)

    # Spend evaluation-offer credits (judge access) under a row lock so concurrent
    # batches can't overspend a capped, non-billable evaluation campaign. Existing
    # logs, exports, and verification stay available even once the credits run out.
    #
    # The RULE lives in billing_state (E1) and is re-asked here rather than
    # re-implemented: the check above ran against an unlocked read, so it can be
    # stale by the time we get the row. What is local to this router is only the
    # SPENDING — the increment, and the lock that makes it safe.
    if org.evaluation_offer_id and new_items:
        locked_org = db.execute(
            select(Organization).where(Organization.id == org.id).with_for_update()
        ).scalar_one()
        blocked = billing_state.capture_block(locked_org, now, pending=len(new_items))
        if blocked is not None:
            raise HTTPException(status_code=402,
                                detail={"code": blocked.reason, "message": blocked.message})
        locked_org.evaluation_credits_used += len(new_items)
        org = locked_org

    # Lock the org's tail row after taking the allocator lock. Legacy rows can
    # still exist, so the allocator is initialized from the observed tail above.
    prev = db.execute(
        select(AuditLog.seq, AuditLog.chain_hash)
        .where(AuditLog.org_id == org.id)
        .order_by(AuditLog.seq.desc())
        .limit(1)
        .with_for_update()
    ).first()
    prev_seq = prev.seq if prev else 0
    prev_hash = prev.chain_hash if prev else GENESIS_HASH

    rows = []
    receipts = list(existing_receipts)
    warnings = []
    client_last: dict[str, int] = {}
    for item in new_items:
        seq = int(sequence.next_seq)
        sequence.next_seq = seq + 1
        metadata = dict(item.event_metadata or {})
        metadata["policy_snapshot"] = snapshot
        metadata["policy_snapshot_hash"] = snapshot_hash
        if item.client_id and item.client_seq is not None:
            if item.client_id not in client_last:
                client_last[item.client_id] = db.execute(
                    select(func.max(AuditLog.client_seq)).where(
                        AuditLog.org_id == org.id,
                        AuditLog.client_id == item.client_id,
                    )
                ).scalar() or 0
            expected = client_last[item.client_id] + 1
            if item.client_seq != expected:
                metadata["client_seq_gap"] = {
                    "expected": expected, "received": item.client_seq,
                }
                warnings.append({"client_id": item.client_id,
                                 "expected": expected, "received": item.client_seq})
            client_last[item.client_id] = item.client_seq
        # Decide the LOCAL verdict before hashing, so V4 can bind it. Both
        # policy_engine entry points are pure — they import only `typing` and
        # `.schemas`, make no network call and reach no model — which is the only
        # reason a verdict can be produced inside the synchronous ingest path at
        # all. The AI judge's grade is NOT chained: it does not exist yet.
        #
        # The routing mirrors worker._grade_one exactly. A blocked/redacted event
        # is terminal and locally decided: `evaluate_enforcement` records it as
        # prevented egress (policy_breach False), while `evaluate` would read its
        # pii_signals and chain the word "breach" onto an interaction that never
        # left the host. Two verdicts for the same row would be worse than none.
        meta = {
            "prompt_hash": item.prompt_hash,
            "response_hash": item.response_hash,
            "token_count": item.token_count,
            "policy_tag": item.policy_tag,
            "pii_signals": item.pii_signals,
            "event_id": str(item.event_id) if item.event_id else None,
            "event_type": item.event_type,
            "commitment_alg": item.commitment_alg,
            "event_metadata": metadata or None,
        }
        if item.event_type in policy_engine.ENFORCEMENT_EVENT_TYPES:
            local_verdict = policy_engine.evaluate_enforcement(meta)
        else:
            local_verdict = policy_engine.evaluate(meta, policy_config)
        local_verdict = local_verdict.model_dump()
        row_verdict_hash = verdict_hash_hex(local_verdict)
        chain_version = CHAIN_VERSION_VERDICT_V4
        chain_hash = compute_chain_hash(
            org_id=org.id,
            prompt_hash=item.prompt_hash,
            response_hash=item.response_hash,
            token_count=item.token_count,
            policy_tag=item.policy_tag,
            seq=seq,
            prev_hash=prev_hash,
            agent=item.agent,
            chain_version=chain_version,
            event_id=item.event_id,
            client_id=item.client_id,
            client_seq=item.client_seq,
            event_type=item.event_type,
            commitment_alg=item.commitment_alg,
            event_metadata=metadata or None,
            pii_signals=item.pii_signals,
            occurred_at=item.occurred_at,
            verdict_hash=row_verdict_hash,
        )
        row = AuditLog(
            org_id=org.id, seq=seq,
            event_id=item.event_id, client_id=item.client_id,
            client_seq=item.client_seq, event_type=item.event_type,
            commitment_alg=item.commitment_alg,
            event_metadata=metadata or None, occurred_at=item.occurred_at,
            chain_version=chain_version,
            prompt_hash=item.prompt_hash, response_hash=item.response_hash,
            token_count=item.token_count, policy_tag=item.policy_tag,
            agent=item.agent,
            pii_signals=item.pii_signals,
            local_verdict=local_verdict, verdict_hash=row_verdict_hash,
            prev_hash=prev_hash, chain_hash=chain_hash,
            gemini_verdict=None,          # grading_status defaults to 'pending'
        )
        rows.append(row)
        receipts.append({
            "event_id": str(item.event_id) if item.event_id else None,
            "client_id": item.client_id, "client_seq": item.client_seq,
            "seq": seq, "chain_hash": chain_hash, "status": "accepted",
        })
        prev_seq = seq
        prev_hash = chain_hash

    db.add_all(rows)
    db.commit()
    return {"status": "pending", "count": len(payload), "receipts": receipts,
            "warnings": warnings}


@router.get("/v1/logs", response_model=LogListResponse)
def list_logs(
    org: Organization = Depends(resolve_org),
    db: Session = Depends(get_db),
    page: int = Query(default=1, ge=1, description="1-indexed page number"),
    limit: int = Query(default=50, ge=1, le=200, description="rows per page"),
    q: str | None = Query(default=None, max_length=128,
                          description="match a hash prefix or agent (substring)"),
    policy_tag: str | None = Query(default=None, max_length=64),
    agent: str | None = Query(default=None, max_length=128),
    verdict: str | None = Query(default=None,
                                description="clean | breach | unknown | pending | blocked "
                                            "(includes response_blocked) | redacted | "
                                            "response_blocked"),
    since: datetime | None = Query(default=None, description="created_at >= (ISO)"),
    until: datetime | None = Query(default=None, description="created_at <= (ISO)"),
):
    """Paginated audit rows for the caller's org (newest first), with optional
    server-side filters. All filters compose (AND) and are applied to BOTH the
    count and the page so totals stay honest."""
    conds = [AuditLog.org_id == org.id]
    if q:
        like = f"%{q.strip()}%"
        conds.append(or_(
            AuditLog.chain_hash.ilike(like), AuditLog.prompt_hash.ilike(like),
            AuditLog.response_hash.ilike(like), AuditLog.agent.ilike(like)))
    if policy_tag:
        conds.append(AuditLog.policy_tag == policy_tag.strip())
    if agent:
        conds.append(AuditLog.agent == agent.strip())
    v = (verdict or "").strip().lower()
    if v == "pending":
        conds.append(AuditLog.grading_status != "graded")
    elif v == "breach":
        conds.append(AuditLog.grading_status == "graded")
        conds.append(AuditLog.gemini_verdict["policy_breach"].astext == "true")
    elif v == "clean":
        conds.append(AuditLog.grading_status == "graded")
        conds.append(AuditLog.gemini_verdict["decision"].astext == "clean")
    elif v == "unknown":
        conds.append(AuditLog.grading_status == "graded")
        conds.append(AuditLog.gemini_verdict["decision"].astext == "unknown")
    elif v == "blocked":
        # BOTH terminal block types. Every surface badges a withheld response
        # "blocked" (the dashboard's verdictOf, the desktop's verdict_of), so a
        # filter matching only event_type="blocked" made a row visibly labelled
        # blocked vanish under the Blocked filter. `response_blocked` stays
        # available as an exact value for callers that want just that one.
        conds.append(AuditLog.event_type.in_(("blocked", "response_blocked")))
    elif v in ("redacted", "response_blocked"):
        # Host-side enforcement rows are identified by their terminal event_type,
        # so the ledger can surface prevented egress distinctly from graded verdicts.
        conds.append(AuditLog.event_type == v)
    if since:
        conds.append(AuditLog.created_at >= since)
    if until:
        conds.append(AuditLog.created_at <= until)

    offset = (page - 1) * limit
    total: int = db.execute(
        select(func.count()).select_from(AuditLog).where(*conds)
    ).scalar_one()
    rows = db.execute(
        select(AuditLog).where(*conds)
        .order_by(AuditLog.seq.desc())
        .offset(offset).limit(limit)
    ).scalars().all()
    return LogListResponse(
        items=[LogListItem.model_validate(r) for r in rows],
        total=total, page=page, limit=limit,
    )


@router.get("/v1/logs/breaches")
def list_breaches(
    org: Organization = Depends(resolve_org),
    db: Session = Depends(get_db),
    since_seq: int = Query(default=0, ge=0,
                           description="only breaches with seq > this (poller cursor)"),
    limit: int = Query(default=200, ge=1, le=500),
):
    """Graded policy breaches for the org with seq > since_seq, ascending by seq.

    The feed the desktop fox polls so it can react to a *real* backend-detected
    breach (the backend grades asynchronously and, in prod, is remote — so it can
    never push a UDP event to the desktop's localhost). The poller advances
    since_seq so a breach the fox already reacted to never re-fires. Declared
    BEFORE /v1/logs/{seq} so the literal path isn't captured as a seq int.
    """
    rows = db.execute(
        select(AuditLog)
        .where(
            AuditLog.org_id == org.id,
            AuditLog.seq > since_seq,
            AuditLog.grading_status == "graded",
            _BREACH,
        )
        .order_by(AuditLog.seq.asc())
        .limit(limit)
    ).scalars().all()
    return [
        {
            "seq": r.seq,
            "policy_tag": r.policy_tag,
            "reason": (r.gemini_verdict or {}).get("reason", ""),
            "risk_score": (r.gemini_verdict or {}).get("risk_score", 0),
        }
        for r in rows
    ]


# `verdict_hash` and `local_verdict` are not optional extras: from chain_version 4
# the verdict hash IS part of the hashed event, so an export without it cannot be
# recomputed at all, and without the verdict body a reader cannot check that the
# bound digest still describes the verdict they are being shown.
_EXPORT_COLS = ["seq", "event_id", "client_id", "client_seq", "event_type",
                "commitment_alg", "event_metadata", "chain_version", "occurred_at", "created_at",
                "policy_tag", "agent", "token_count", "prompt_hash",
                "response_hash", "pii_signals", "prev_hash", "chain_hash",
                "verdict_hash", "local_verdict",
                "gemini_verdict", "grading_status", "graded_at"]


def _export_row(r: AuditLog) -> dict:
    return {
        "seq": r.seq,
        "event_id": str(r.event_id) if r.event_id else None,
        "client_id": r.client_id,
        "client_seq": r.client_seq,
        "event_type": r.event_type,
        "commitment_alg": r.commitment_alg,
        "event_metadata": r.event_metadata,
        "chain_version": r.chain_version or 1,
        "occurred_at": r.occurred_at.isoformat() if r.occurred_at else None,
        "created_at": r.created_at.isoformat() if r.created_at else None,
        "policy_tag": r.policy_tag,
        "agent": r.agent,
        "token_count": r.token_count,
        "prompt_hash": r.prompt_hash,
        "response_hash": r.response_hash,
        "pii_signals": r.pii_signals,
        "prev_hash": r.prev_hash,
        "chain_hash": r.chain_hash,
        "verdict_hash": r.verdict_hash,
        "local_verdict": r.local_verdict,
        "gemini_verdict": r.gemini_verdict,
        "grading_status": r.grading_status,
        "graded_at": r.graded_at.isoformat() if r.graded_at else None,
    }


def _anchor_export(a) -> dict | None:
    """The org's latest anchor receipt, embedded in the JSON export so the
    open-source verifier can offline-compare it — and, with --anchor, confirm the
    root live on the public chain (Phase 6 · 6D). None when the org has no anchor."""
    if a is None:
        return None
    return {
        "chain": a.chain, "status": a.status, "root_hash": a.root_hash,
        "last_seq": a.last_seq, "tx_hash": a.tx_hash, "block_number": a.block_number,
        "anchored_at": a.anchored_at.isoformat() if a.anchored_at else None,
        "contract": get_settings().anchor_evm_contract or None,
    }


@router.get("/v1/logs/export")
@limiter.limit("6/minute")
def export_logs(
    request: Request,
    org: Organization = Depends(resolve_org),
    db: Session = Depends(get_db),
    format: str = Query(default="json", pattern="^(json|csv|bundle)$"),
    date_from: str | None = Query(default=None, description="ISO date YYYY-MM-DD, inclusive"),
    date_to: str | None = Query(default=None, description="ISO date YYYY-MM-DD, inclusive"),
):
    """Download the org's audit-log ledger (its own data) as JSON, CSV, or a
    verification bundle — data portability for the tenant. Scoped by org_id
    (+ RLS). Declared BEFORE /v1/logs/{seq} so the literal path isn't captured as
    a seq int.

    `format=bundle` returns a ZIP holding the identical JSON body plus the
    standalone verifier and its instructions (app/export_bundle.py). It exists
    because the Compliance Passport tells a third party to run that verifier and
    the product had no way to hand it over. Built in memory; nothing is archived
    server-side, matching ExportJob's contract that a re-download re-runs the
    producer.

    The date range is optional and, with neither bound, this is still the whole
    ledger. It exists because the dashboard's Export page has always shown two
    date pickers, sent them to /v1/passport, and then handed the log download a
    URL with no range on it at all — so the user picked a window and silently
    got everything. The bounds match the passport's semantics exactly
    (routers/passport.py): `date_to` is inclusive of that whole day."""
    def _parse(value: str | None):
        if not value:
            return None
        try:
            return datetime.fromisoformat(value).replace(tzinfo=timezone.utc)
        except ValueError:
            raise HTTPException(status_code=422, detail="date must be ISO YYYY-MM-DD")

    start = _parse(date_from)
    end_day = _parse(date_to)

    query = select(AuditLog).where(AuditLog.org_id == org.id)
    if start is not None:
        query = query.where(AuditLog.created_at >= start)
    if end_day is not None:
        query = query.where(AuditLog.created_at < end_day + timedelta(days=1))
    rows = db.execute(query.order_by(AuditLog.seq.asc())).scalars().all()

    if format == "csv":
        buf = io.StringIO()
        w = csv.DictWriter(buf, fieldnames=_EXPORT_COLS)
        w.writeheader()
        for r in rows:
            d = _export_row(r)
            d["pii_signals"] = "" if d["pii_signals"] is None else json.dumps(d["pii_signals"])
            d["event_metadata"] = "" if d["event_metadata"] is None else json.dumps(d["event_metadata"])
            d["gemini_verdict"] = "" if d["gemini_verdict"] is None else json.dumps(d["gemini_verdict"])
            d["local_verdict"] = "" if d["local_verdict"] is None else json.dumps(d["local_verdict"])
            w.writerow(d)
        return Response(
            content=buf.getvalue(), media_type="text/csv",
            headers={"Content-Disposition": 'attachment; filename="foxy-audit-logs.csv"'})

    # indent=2, because this is evidence someone has to READ. Without it the
    # whole ledger arrives as a single enormous line, which is valid JSON and
    # useless to the auditor who opens it. Formatting cannot affect
    # verification: verifier/foxy_verify.py json.load()s this and recomputes
    # from the parsed fields, never from the raw bytes.
    body = json.dumps(
        {"org_id": str(org.id), "count": len(rows),
         "anchor": _anchor_export(latest_anchor(db, org.id)),
         "logs": [_export_row(r) for r in rows]},
        default=str, indent=2)

    if format == "bundle":
        # The SAME bytes go into the archive, so unzipping a bundle and running
        # format=json are interchangeable inputs to the verifier.
        try:
            blob = export_bundle.build(body.encode("utf-8"))
        except export_bundle.VerifierUnavailable as exc:
            # 503, not a short bundle. An archive that quietly omits the tool it
            # exists to deliver fails at the auditor's desk instead of here.
            raise HTTPException(
                status_code=503,
                detail=("the verification bundle is unavailable — the standalone "
                        f"verifier could not be read ({exc}). Use format=json for "
                        "the ledger on its own."))
        return Response(
            content=blob, media_type="application/zip",
            headers={"Content-Disposition":
                     f'attachment; filename="{export_bundle.BUNDLE_FILENAME}"'})

    return Response(
        content=body, media_type="application/json",
        headers={"Content-Disposition": 'attachment; filename="foxy-audit-logs.json"'})


@router.get("/v1/logs/{seq}", response_model=LogListItem)
def get_log_by_seq(
    seq: int,
    org: Organization = Depends(resolve_org),
    db: Session = Depends(get_db),
):
    """Fetch a single audit log row by sequence number (RLS scopes to the org)."""
    row = db.execute(
        select(AuditLog).where(AuditLog.org_id == org.id, AuditLog.seq == seq)
    ).scalar_one_or_none()
    if row is None:
        raise HTTPException(status_code=404, detail=f"No log found for seq={seq}")
    return LogListItem.model_validate(row)


@router.get("/v1/stats", response_model=StatsResponse)
def stats(
    org: Organization = Depends(resolve_org),
    db: Session = Depends(get_db),
):
    """Aggregates for the dashboard hero/stat tiles and 7-day sparkline."""
    total = db.execute(
        select(func.count()).select_from(AuditLog).where(AuditLog.org_id == org.id)
    ).scalar_one()
    breaches = db.execute(
        select(func.count()).select_from(AuditLog)
        .where(AuditLog.org_id == org.id, AuditLog.grading_status == "graded", _BREACH)
    ).scalar_one()
    avg_tokens = db.execute(
        select(func.coalesce(func.avg(AuditLog.token_count), 0))
        .where(AuditLog.org_id == org.id)
    ).scalar_one()
    # Real average time-to-verdict (ingest → graded), in seconds; None if nothing
    # has been graded yet. Replaces the dashboard's fabricated "42ms judge latency".
    # Latency measures how long grading took, independent of the verdict content —
    # so unknown/evaluator-unavailable rows still count (the honesty filter belongs on
    # clean_rate below, computed from clean + breaches only).
    avg_verdict = db.execute(
        select(func.avg(func.extract("epoch", AuditLog.graded_at - AuditLog.created_at)))
        .where(AuditLog.org_id == org.id, AuditLog.graded_at.isnot(None))
    ).scalar_one()

    evaluator_unknown = db.execute(
        select(func.count()).select_from(AuditLog)
        .where(AuditLog.org_id == org.id, AuditLog.grading_status == "graded", _UNKNOWN)
    ).scalar_one()
    known_graded = db.execute(
        select(func.count()).select_from(AuditLog)
        .where(AuditLog.org_id == org.id, AuditLog.grading_status == "graded", ~_UNKNOWN)
    ).scalar_one()
    known_clean = db.execute(
        select(func.count()).select_from(AuditLog)
        .where(
            AuditLog.org_id == org.id,
            AuditLog.grading_status == "graded",
            ~_UNKNOWN,
            ~_BREACH,
        )
    ).scalar_one()

    # Host-side enforcement counts — prevented egress, surfaced separately so the
    # dashboard never mislabels a blocked/redacted event as a clean pass.
    blocked = db.execute(
        select(func.count()).select_from(AuditLog)
        .where(AuditLog.org_id == org.id, AuditLog.event_type == "blocked")
    ).scalar_one()
    redacted = db.execute(
        select(func.count()).select_from(AuditLog)
        .where(AuditLog.org_id == org.id, AuditLog.event_type == "redacted")
    ).scalar_one()
    # Kept OUT of `blocked` on purpose. That count means prompts stopped before
    # they reached a provider; a withheld response is a different enforcement and
    # folding it in would inflate a number the Passport also reports.
    response_blocked = db.execute(
        select(func.count()).select_from(AuditLog)
        .where(AuditLog.org_id == org.id, AuditLog.event_type == "response_blocked")
    ).scalar_one()

    gc = {"pending": 0, "in_progress": 0, "graded": 0, "failed": 0}
    for status, cnt in db.execute(
        select(AuditLog.grading_status, func.count())
        .where(AuditLog.org_id == org.id)
        .group_by(AuditLog.grading_status)
    ).all():
        if status in gc:
            gc[status] = cnt

    # #123 · PINNED TO UTC. date_trunc/::date on a timestamptz resolves in the
    # SESSION timezone, and nothing in this project pins it — so this bucketed
    # by the database server's local day. R3 fixed the same shape in usage.py;
    # activity_7d is the dashboard's seven-day bar chart, whose LAST bucket F1
    # labels "today". West of UTC an early-morning event fell into yesterday's
    # bar; east of it a late-evening one jumped into tomorrow's.
    day = func.to_char(func.timezone("UTC", AuditLog.created_at), "YYYY-MM-DD")
    activity = [
        ActivityDay(date=d, count=c, breaches=b)
        for d, c, b in db.execute(
            select(day, func.count(), func.count().filter(_BREACH))
            .where(AuditLog.org_id == org.id,
                   AuditLog.created_at >= text("now() - interval '7 days'"),
                   AuditLog.grading_status == "graded")
            .group_by(day)
            .order_by(day)
        ).all()
    ]

    clean = db.execute(
        select(func.count()).select_from(AuditLog)
        .where(AuditLog.org_id == org.id, AuditLog.grading_status == "graded",
               AuditLog.gemini_verdict["decision"].astext == "clean")
    ).scalar_one()
    determinate = clean + breaches
    clean_rate = round(100.0 * clean / determinate, 1) if determinate else None

    # #228 · WHO graded, from the ledger. `judge_model` below reads this
    # DEPLOYMENT's provider settings and therefore cannot answer this — grading is
    # a per-tenant routing decision, so a configured platform key is not evidence
    # that any of THIS org's events reached a model, and a BYOK org on a keyless
    # deployment is graded by a model that setting has never heard of. One
    # statement, so the two numbers can never come from different row sets.
    ai_graded, rules_graded = db.execute(
        select(func.count().filter(_GRADED_BY_AI),
               func.count().filter(_GRADED_BY_RULES))
        .select_from(AuditLog)
        .where(AuditLog.org_id == org.id, AuditLog.grading_status == "graded")
    ).one()
    settings = get_settings()
    judge_models = []
    if settings.gemini_api_key:
        judge_models.append(settings.gemini_model)
    if settings.openai_api_key:
        judge_models.append(settings.openai_model)
    judge_model = " + ".join(judge_models) or "local-policy"
    return StatsResponse(
        total_logged=total, breaches=breaches, clean_rate=clean_rate,
        avg_token_count=round(float(avg_tokens), 1),
        judge_model=judge_model,
        avg_seconds_to_verdict=round(float(avg_verdict), 1) if avg_verdict is not None else None,
        grading=GradingCounts(**gc), activity_7d=activity,
        evaluator_unknown=evaluator_unknown,
        blocked=blocked, redacted=redacted, response_blocked=response_blocked,
        ai_graded=ai_graded, rules_graded=rules_graded,
    )
