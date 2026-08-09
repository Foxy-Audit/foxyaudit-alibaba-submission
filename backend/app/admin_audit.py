"""Helper for the append-only staff audit trail (admin_actions).

Every state-changing staff action records exactly one AdminAction row IN THE SAME
transaction as the mutation, so A COMMITTED CHANGE WITHOUT A LOGGED ACTION CANNOT
HAPPEN. Callers add the row and commit together; this helper never commits on its
own, and nothing may commit before calling it — guarded by
test_nothing_commits_before_it_records, which is what makes the busy-chain 503's
"Nothing was changed" true rather than hopeful.

⚠ THE OTHER DIRECTION IS NOT GUARANTEED, AND THAT IS A DELIBERATE TRADE.
This used to claim "or a logged action without the change" as well. Since G5.2
that is false at exactly one site: auth_staff.staff_login commits the audit row
and THEN calls _establish_staff_session, which commits the session separately.
If that second commit raises, the operator gets a 500 with a chained staff.login
row and no session — an attempt recorded as though it succeeded.

It is the right way round. The alternative was the order that shipped in G5.1,
where a chain timeout left the operator genuinely signed in with NO audit row at
all — an unlogged staff sign-in, precisely the gap #79 exists to close. An audit
trail that occasionally over-reports an attempt is recoverable: the operator
retries and the next row supersedes it, and the trail still contains every
sign-in that happened. One that silently misses a successful sign-in is not.

So the contract is ASYMMETRIC on purpose: never fewer rows than there were
actions, possibly one more. test_the_login_records_before_it_establishes_the_
session pins the order with this reasoning attached, so reverting it fails
loudly rather than looking like a tidy-up.

G5 · #79 — the row is also hash-chained as it is written. See app/admin_chain.py
for what that proves and, more importantly, what it does not.
"""

from __future__ import annotations

from datetime import datetime, timezone

from fastapi import HTTPException, Request
from sqlalchemy import insert, text
from sqlalchemy.exc import OperationalError
from sqlalchemy.orm import Session

from .admin_chain import (
    ADMIN_CHAIN_GENESIS, ADMIN_CHAIN_LOCK, ADMIN_CHAIN_LOCK_TIMEOUT_MS,
    chain_head, compute_admin_chain_hash,
)
from .models import AdminAction, StaffUser


def client_ip(request: Request) -> str | None:
    """Best-effort client IP for the audit row. Trusts the first X-Forwarded-For
    hop when present (set by our own proxy), else the direct peer."""
    xff = request.headers.get("x-forwarded-for")
    if xff:
        return xff.split(",")[0].strip()[:64]
    return request.client.host[:64] if request.client else None


def record_admin_action(
    db: Session,
    staff: StaffUser,
    action: str,
    *,
    target_org_id=None,
    target_type: str | None = None,
    target_id: str | None = None,
    detail: dict | None = None,
    ip: str | None = None,
) -> None:
    """Stage an AdminAction row, chained to the one before it. Does NOT commit —
    the caller commits it together with the mutation it describes.

    ⚠ THE CHAIN IS ALLOCATED INSIDE THE CALLER'S TRANSACTION, deliberately. If
    the caller rolls back, the seq goes with it and the chain has no gap — and a
    gap is indistinguishable from a deleted row, which is the one thing this
    mechanism exists to make visible.

    ⚠ A CORE INSERT, NOT db.add(). Two records in one transaction have to chain
    to EACH OTHER, so the second must be able to SEE the first — and the session
    is autoflush=False, so a staged row is invisible to the tail query. The
    obvious fix, db.flush(), would flush the CALLER's pending objects too: in
    admin_campaigns.create_campaign that turns a duplicate-campaign IntegrityError
    from the 409 its try/except produces into an unhandled 500, because the flush
    happens outside that try. Inserting only this row moves nothing else.

    ⚠ THE CALLER MUST COMMIT SOON. The platform chain serialises here, and it
    stays serialised until the CALLER's transaction ends — see
    ADMIN_CHAIN_LOCK_TIMEOUT_MS for the measurement showing that this is a
    property of a gap-free sequence, not of the lock. Slow work after recording
    blocks every other staff action and every staff sign-in, so it is guarded:
    test_no_route_does_slow_work_after_recording_an_action.
    """
    # ⚠ POSTGRES ONLY, AND IT FAILS RATHER THAN DEGRADES. The earlier version
    # copied the `if dialect == postgresql` guard the three other advisory-lock
    # sites use, which quietly turned both the lock and the FOR UPDATE into
    # no-ops off Postgres — leaving uq_admin_actions_seq to convert a fork into
    # an IntegrityError that rolls back the mutation being audited. There is no
    # non-Postgres bind in this project (no sqlite anywhere in app/ or tests/,
    # and RLS, JSONB and advisory locks are load-bearing throughout), so a
    # different dialect is a misconfiguration, not a supported mode. An audit
    # chain that silently stops being safe is worse than one that refuses.
    dialect = db.bind.dialect.name if db.bind is not None else None
    if dialect != "postgresql":
        raise RuntimeError(
            "the staff audit chain requires PostgreSQL (advisory locks and "
            "SELECT ... FOR UPDATE); this session is bound to %r" % (dialect,))

    # Serialise the whole platform chain. Two-int advisory key so it cannot
    # collide with the single-key hashtext(offer_id) locks billing.py and
    # admin_campaigns.py already take — those are a different lock space.
    #
    # The timeout is SET LOCAL, so it is scoped to this transaction and gone at
    # commit, and it is RESET straight after the allocation rather than left
    # standing: the caller has its own statements to run and must not inherit a
    # five-second ceiling it never asked for. The pair costs +1.25ms, measured.
    #
    # ⚠ INTERPOLATED, NOT BOUND, and a bare integer. SET takes no parameters —
    # Postgres answers `SET LOCAL lock_timeout = $1` with a syntax error — and
    # `5000ms` unquoted is a second syntax error, because lock_timeout's own
    # default unit is already milliseconds. The value is an int constant from
    # this module coerced with %d, so no caller reaches it.
    db.execute(text("SET LOCAL lock_timeout = %d"
                    % int(ADMIN_CHAIN_LOCK_TIMEOUT_MS)))
    try:
        db.execute(text("SELECT pg_advisory_xact_lock(:cls, :obj)"),
                   {"cls": ADMIN_CHAIN_LOCK[0], "obj": ADMIN_CHAIN_LOCK[1]})
        tail = chain_head(db)
    except OperationalError as exc:
        # 55P03 lock_not_available. Loud and specific: a staff action that
        # cannot be audited must not commit, and "the console hung" is the
        # symptom this exists to replace.
        if getattr(getattr(exc, "orig", None), "sqlstate", None) != "55P03":
            raise
        raise HTTPException(
            status_code=503,
            detail="the staff audit chain is busy — another staff action is "
                   "holding it open. Nothing was changed; try again.") from exc
    db.execute(text("SET LOCAL lock_timeout = DEFAULT"))

    seq = (tail.seq + 1) if tail else 1
    prev_hash = tail.chain_hash if tail else ADMIN_CHAIN_GENESIS
    created_at = datetime.now(timezone.utc)

    chain_hash = compute_admin_chain_hash(
        seq=seq, prev_hash=prev_hash, staff_user_id=staff.id, action=action,
        target_org_id=target_org_id, target_type=target_type, target_id=target_id,
        detail=detail, ip=ip, created_at=created_at,
    )
    db.execute(insert(AdminAction).values(
        staff_user_id=staff.id, action=action, target_org_id=target_org_id,
        target_type=target_type, target_id=target_id, detail=detail, ip=ip,
        created_at=created_at, seq=seq, prev_hash=prev_hash, chain_hash=chain_hash,
    ))
