"""The human-review queue — where a verdict the judge declined to decide lands.

An agentic judge given `flag_for_human_review` and a reason to call it returns
`decision="human_review"` (Q2a). `worker._queue_human_review` puts that escalation
in `human_reviews`; this module is the pair of verbs a person acts on it with.

⚠ RESOLVING NEVER MUTATES THE CHAINED ROW, and that is the design rather than an
implementation detail. `chain.verdict_hash_hex` binds the LOCAL, SDK-side verdict
decided at ingest — the only reason the worker may write an AI grade after the row
is chained — so a human decision arriving later still has to stay off it. It lands
in two places instead:

  * the `human_reviews` row's mutable `status`, which is the queue;
  * an append-only `AuditEvent(event_type="human_review_resolved")`, which is the
    evidence — hashed, never rewritten, and exportable beside every other event.

`test_the_chain_hash_is_byte_identical_before_and_after_a_review_resolves` is the
assertion that holds this to it.

⚠ AND RESOLVING DOES NOT RE-ARITHMETIC HISTORY. `passport.compliant_events`
subtracts a `human_review` from the compliant count whatever the human later
decides, and it stays subtracted. Recomputing it would move a headline number on
Compliance Passports that have ALREADY BEEN ISSUED — the trap open issue #317 is
about. The resolution is recorded; nothing behind it is rewritten. `graded_by`
stays `"ai"` for the same reason: a human resolution is a new event, not a
re-grade.
"""

from __future__ import annotations

import hashlib
import json
import uuid
from datetime import datetime, timezone

from fastapi import APIRouter, Depends, HTTPException, Query, Request
from sqlalchemy import select
from sqlalchemy.orm import Session

from ..auth import require_user, resolve_org
from ..db import get_db
from ..models import AuditEvent, AuditLog, HumanReview, Organization, User
from ..schemas import ReviewListResponse, ReviewResolveRequest
from .logs import limiter          # the app's single Limiter instance

router = APIRouter()

#: Rows per page. Small beside the export's 10,000 because these are worklist
#: entries a person reads, not a ledger a machine recomputes — a workspace with
#: 200 escalations pending has an operational problem, not a paging one.
REVIEW_PAGE_MAX = 200


def _item(review: HumanReview, log: AuditLog) -> dict:
    return {
        "id": review.id,
        "seq": log.seq,
        "status": review.status,
        "resolution": review.resolution,
        "reason": review.reason,
        "risk_score": review.risk_score,
        "note": review.note,
        "policy_tag": log.policy_tag,
        "agent": log.agent,
        "event_created_at": log.created_at,
        "created_at": review.created_at,
        "resolved_at": review.resolved_at,
        "resolved_by": review.resolved_by,
    }


@router.get("/v1/reviews", response_model=ReviewListResponse)
@limiter.limit("60/minute")
def list_reviews(
    request: Request,
    org: Organization = Depends(resolve_org),
    db: Session = Depends(get_db),
    status: str | None = Query(default=None, pattern="^(pending|resolved)$",
                               description="omit for every review, resolved included"),
    after_seq: int = Query(default=0, ge=0,
                           description="resume after this seq — the `page.next_after_seq` "
                                       "of the page you already have"),
    limit: int = Query(default=REVIEW_PAGE_MAX, ge=1, le=REVIEW_PAGE_MAX),
):
    """This workspace's escalations, oldest interaction first.

    Paged on the LEDGER SEQUENCE, with the same `after_seq` cursor and the same
    `page` block `GET /v1/logs/export` established at #271. There is one paging
    contract in this product and this is it — a second one on a second endpoint is
    a second thing a client has to learn to read one product. `seq` is unique per
    workspace here as well as there, because `human_reviews.audit_log_id` is
    unique: one escalation per event, so the cursor cannot stall on a tie.

    ⚠ NO `status` FILTER BY DEFAULT. A queue endpoint that silently hides resolved
    rows answers a different question from the one asked and gives a client no way
    to notice; `?status=pending` asks for the worklist explicitly.
    """
    query = (select(HumanReview, AuditLog)
             .join(AuditLog, AuditLog.id == HumanReview.audit_log_id)
             # Its own org clause on BOTH sides rather than leaning on RLS — the
             # same rule `account_export` is held to. RLS confines the role
             # already, which is exactly why a dropped clause here would be
             # invisible to a behavioural cross-tenant test.
             .where(HumanReview.org_id == org.id, AuditLog.org_id == org.id))
    if status is not None:
        query = query.where(HumanReview.status == status)
    if after_seq:
        query = query.where(AuditLog.seq > after_seq)
    # limit + 1: one row past the page proves more remain without a second COUNT,
    # and it is discarded rather than served.
    rows = db.execute(query.order_by(AuditLog.seq.asc()).limit(limit + 1)).all()
    has_more = len(rows) > limit
    rows = rows[:limit]

    from_seq = rows[0][1].seq if rows else None
    to_seq = rows[-1][1].seq if rows else None
    return {
        "items": [_item(review, log) for review, log in rows],
        "page": {
            "from_seq": from_seq,
            "to_seq": to_seq,
            "complete": not has_more,
            "next_after_seq": to_seq if has_more else None,
            "next": (str(request.url.include_query_params(after_seq=to_seq))
                     if has_more else None),
            "max_rows_per_page": REVIEW_PAGE_MAX,
        },
    }


@router.post("/v1/reviews/{review_id}/resolve")
@limiter.limit("30/minute")
def resolve_review(
    request: Request,
    review_id: uuid.UUID,
    body: ReviewResolveRequest,
    user: User = Depends(require_user),
    db: Session = Depends(get_db),
):
    """Record what a person decided about an escalation.

    `require_user` rather than `resolve_org`: this is a governance act and the
    record has to name the human who performed it, which an SDK key cannot. The
    accountable email is read from the session, never from the request body.

    ⚠ IDEMPOTENT, AND NOT BY OVERWRITING. A second resolve returns the review as
    it already stands and appends NOTHING. The evidence event is append-only, so a
    duplicate could not be taken back: two `human_review_resolved` rows for one
    determination would read as two contradictory human decisions in a
    tamper-evident record. The FIRST decision is the one that was made.

    ⚠ AND NOTHING HERE TOUCHES `audit_logs`. See this module's docstring.
    """
    review = db.execute(
        select(HumanReview).where(HumanReview.id == review_id,
                                  HumanReview.org_id == user.org_id)
    ).scalar_one_or_none()
    if review is None:
        # 404 rather than 403 on another workspace's id: the two answers are the
        # difference between "no such review" and "a review you may not touch",
        # and the second confirms the id exists to someone who should not know.
        raise HTTPException(status_code=404, detail="No such review")

    if review.status == "resolved":
        log = db.get(AuditLog, review.audit_log_id)
        return _item(review, log)

    now = datetime.now(timezone.utc)
    review.status = "resolved"
    review.resolution = body.resolution
    review.note = body.note
    review.resolved_at = now
    review.resolved_by = user.email

    # The append-only half. Hashed exactly as the worker hashes a `verdict` event
    # — canonical JSON, sorted keys, no spaces — so one construction produces every
    # `event_hash` in this table.
    #
    # ⚠ `note` IS NOT IN THIS PAYLOAD, DELIBERATELY. It is the one free-text field
    # a human writes and it can carry anything they type, raw prompt content
    # included; this event is content-blind evidence a customer exports. The
    # structured `resolution` is what the record needs, and the note stays beside
    # it in `human_reviews` as customer-authored annotation.
    payload = {
        "review_id": str(review.id),
        "resolution": review.resolution,
        "resolved_by": review.resolved_by,
        "resolved_at": now.isoformat(),
        # What the judge asked about, so the event stands on its own in an export.
        "escalation_reason": review.reason,
        "escalation_risk_score": review.risk_score,
    }
    blob = json.dumps({"audit_log_id": str(review.audit_log_id),
                       "event_type": "human_review_resolved", "payload": payload},
                      sort_keys=True, separators=(",", ":"))
    db.add(AuditEvent(
        org_id=review.org_id, audit_log_id=review.audit_log_id,
        event_type="human_review_resolved", payload=payload,
        event_hash=hashlib.sha256(blob.encode()).hexdigest(),
    ))
    db.commit()
    db.refresh(review)
    return _item(review, db.get(AuditLog, review.audit_log_id))
