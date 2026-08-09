"""The staff audit trail's hash chain — one implementation, writer and verifier.

``admin_actions`` is the record of what Foxy's own staff did: who suspended a
tenant, who replayed a webhook, who revealed an org id. Until now it was an
ordinary table. Every row after this ships carries ``seq``, ``prev_hash`` and
``chain_hash``, so:

    Hn = SHA256( canonical_json(row_n) || H_{n-1} )

and a recompute from the first chained row forward re-derives every hash. An
edited field, a deleted row in the middle, a re-ordered pair — each breaks the
recompute at a nameable ``seq``.

WHAT THIS PROVES, AND WHAT IT DOES NOT
--------------------------------------
It is a chain over a table in a database Foxy controls. Anyone who can edit a
row can also recompute every hash after it, so this is NOT proof against Foxy —
it is proof against a careless edit, a partial restore, and an intruder who
changes data without knowing the scheme. Two further limits, both real:

  * REMOVING ENTRIES FROM THE END leaves nothing behind. seq 1..N-k recomputes
    perfectly; only an outside witness who recorded the older head would notice.
  * ROWS WRITTEN BEFORE THIS SHIPPED have no hash and cannot be given one that
    means anything. They stay exactly as they are — real audit rows that predate
    the mechanism. See ``verify_admin_chain``'s ``unchained`` count.

The customer-facing chain answers the first of those with ANCHORING (anchor.py
publishes each org's head to a public chain). Doing the same here is a separate
change with its own operational cost — a funded key, gas, and a failure mode
when the chain is unreachable. Until it exists, every surface that reports this
chain must say "sequence unbroken", never "tamper-evident". The UI copy in
foxy-adminpage is written to that rule and guarded.

CANONICAL FORM
--------------
The same canonical JSON the customer chain uses — ``sort_keys=True``,
``separators=(",",":")``, ``ensure_ascii=True`` — so key order can never move a
hash. Two things are normalised INSIDE this function rather than at the call
site, because a writer and a verifier that normalise differently is the classic
hash-chain bug:

  * ``created_at`` is converted to UTC before ``isoformat()``. Postgres returns
    a ``timestamptz`` in the SESSION timezone, so a database running west of UTC
    hands the verifier "…T05:34:56-07:00" for the instant the writer serialised
    as "…T12:34:56+00:00". Same moment, different string, broken chain — on
    every deployment whose DB timezone is not UTC.
  * UUID-ish fields go through ``str()`` on a parsed ``uuid.UUID``, so a caller
    passing an upper-case string hashes the same bytes the database returns.

KNOWN BOUNDARY: ``detail`` is a JSONB column, and JSONB stores numbers as
``numeric``. An integer, a bool, a string, null, a list and an ordinary float
all round-trip byte-identically through it. A float large or small enough that
``repr`` uses exponent form (1e16, 1e-7) does NOT — Postgres re-renders it in
positional form and the recompute would differ. No call site puts such a value
in ``detail`` (they carry counts, ids, statuses and short strings), and the
round-trip is guarded for the shapes that are used.
"""

from __future__ import annotations

import hashlib
import json
import uuid
from datetime import datetime, timezone

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from .models import AdminAction

ADMIN_CHAIN_GENESIS = "0" * 64
ADMIN_CHAIN_VERSION = 1

# The verify route recomputes on request, so it must stay bounded. Same posture
# as verify.py's ledger limit: over the bound, report "not verified" rather than
# spending an unbounded amount of a request on it. NEVER report it as clean.
ADMIN_CHAIN_VERIFY_LIMIT = 50_000

# Advisory-lock key for the single platform-wide chain. TWO-INT form on purpose:
# Postgres keeps two-key advisory locks in a different space from single-key
# ones, and billing.py / admin_campaigns.py already hold single-key locks keyed
# by hashtext(offer_id). Using the pair makes a collision with those impossible
# by construction rather than by choosing a lucky constant.
ADMIN_CHAIN_LOCK = (0x464F5859, 1)          # 'FOXY', chain #1

# How long a staff action waits for the chain before giving up LOUDLY.
#
# ⚠ THE LOCK IS NOT WHAT MAKES A SLOW CALLER BLOCK EVERYONE — MEASURED.
# A dense, gap-free sequence allocated inside the caller's transaction has to
# serialise across that whole transaction, whatever mechanism does it. With
# writer A holding its transaction open for 6s after recording:
#
#     pg_advisory_xact_lock + FOR UPDATE   B waited 5.70s, succeeded
#     no lock at all, unique catches forks  B waited 5.70s, IntegrityError
#
# Identical. Dropping the lock moves the wait from pg_advisory_xact_lock onto
# the insert into uq_admin_actions_seq, because B cannot see A's uncommitted
# row and picks the same seq. It trades a wait that succeeds for a wait that
# fails. So the lock stays, and the real fix is that no caller may hold its
# transaction open across slow work — enforced at the call sites and guarded by
# test_no_route_does_slow_work_after_recording_an_action.
#
# This timeout is the backstop for the caller nobody guarded. It applies to any
# lock wait, so it bounds the lock-free shape's index wait too.
ADMIN_CHAIN_LOCK_TIMEOUT_MS = 5000


def _as_uuid_str(value) -> str | None:
    """``None`` stays ``None``; anything else becomes the canonical lower-case
    UUID text Postgres will hand back to the verifier."""
    if value is None:
        return None
    return str(value if isinstance(value, uuid.UUID) else uuid.UUID(str(value)))


def _as_utc_iso(value: datetime) -> str:
    """UTC, always — see the module docstring. A naive datetime is treated as
    UTC, which is what every writer in this codebase produces."""
    if value.tzinfo is None:
        value = value.replace(tzinfo=timezone.utc)
    return value.astimezone(timezone.utc).isoformat()


def compute_admin_chain_hash(
    *,
    seq: int,
    prev_hash: str,
    staff_user_id,
    action: str,
    target_org_id=None,
    target_type: str | None = None,
    target_id: str | None = None,
    detail: dict | None = None,
    ip: str | None = None,
    created_at: datetime,
    chain_version: int = ADMIN_CHAIN_VERSION,
) -> str:
    """The one implementation. record_admin_action writes with it and
    verify_admin_chain re-derives with it; nothing else may compute this hash."""
    event = {
        "chain_version": chain_version,
        "seq": seq,
        "staff_user_id": _as_uuid_str(staff_user_id),
        "action": action,
        "target_org_id": _as_uuid_str(target_org_id),
        "target_type": target_type,
        "target_id": None if target_id is None else str(target_id),
        "detail": detail,
        "ip": ip,
        "created_at": _as_utc_iso(created_at),
    }
    blob = json.dumps(event, ensure_ascii=True, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256((blob + prev_hash).encode("utf-8")).hexdigest()


def chain_head(db: Session):
    """The newest chained row's (seq, chain_hash), or ``None`` on an empty chain.

    ``seq IS NOT NULL`` excludes the rows that predate the chain — they are real
    audit rows, they are simply older than the mechanism, and they must never be
    treated as a gap.
    """
    return db.execute(
        select(AdminAction.seq, AdminAction.chain_hash)
        .where(AdminAction.seq.isnot(None))
        .order_by(AdminAction.seq.desc())
        .limit(1)
        .with_for_update()
    ).first()


def admin_chain_coverage(db: Session) -> dict:
    """What the chain COVERS, without recomputing anything.

    Three reads — one counting pass, the first chained row, the tail — so the
    console can state coverage on arrival rather than implying the whole table
    is chained and only admitting otherwise once someone clicks. ``checked`` is
    False here on purpose: an unverified chain stays unverified, and this
    function has verified nothing.

    ⚠ ONE FILTERED PASS, NOT TWO COUNTS, and the measurement is the reason. The
    obvious shape — a count per WHERE clause — was written here first on the
    assumption that both could use the unique index on seq. Measured on 20,300
    rows (20,000 chained, 300 predating): ``seq IS NULL`` is an Index Only Scan
    at 6 buffers / 0.10ms, but ``seq IS NOT NULL`` matches almost the whole
    table, so the planner correctly picks a Seq Scan — 250 buffers, 2.14ms. The
    single filtered aggregate produces the SAME Seq Scan at 250 buffers and
    2.17ms, in one round trip instead of two. Same work, one statement.
    """
    unchained, chained = db.execute(
        select(
            func.count().filter(AdminAction.seq.is_(None)),
            func.count().filter(AdminAction.seq.isnot(None)),
        ).select_from(AdminAction)
    ).one()
    first = db.execute(
        select(AdminAction.created_at)
        .where(AdminAction.seq == 1)
    ).scalar_one_or_none()
    head = db.execute(
        select(AdminAction.seq, AdminAction.chain_hash)
        .where(AdminAction.seq.isnot(None))
        .order_by(AdminAction.seq.desc())
        .limit(1)
    ).first()
    return {
        "checked": False, "ok": None,
        "chained": int(chained), "unchained": int(unchained),
        # `kind` is None on every shape but a break. It ships on all of them so
        # the console never branches on a key that is sometimes absent.
        "kind": None,
        "first_broken_seq": None,
        "head_seq": head.seq if head else None,
        "head_hash": head.chain_hash if head else None,
        "started_at": first.isoformat() if first else None,
        "detail": "not checked",
    }


def verify_admin_chain(db: Session) -> dict:
    """Recompute the staff audit chain and report exactly what that establishes.

    ``ok=None`` means NOT KNOWN, never clean, and there are two ways to get it:
    the chain is longer than the request-time bound, or there is nothing chained
    to check. ``unchained`` counts the rows written before the chain existed;
    they are reported separately and are never a failure.
    """
    cov = admin_chain_coverage(db)
    # head/started are re-derived by the walk below, so they start empty and a
    # failure path cannot leak a stale head into a broken report.
    base = {**cov, "checked": True, "kind": None,
            "head_seq": None, "head_hash": None, "started_at": None}
    chained = cov["chained"]

    if chained == 0:
        # ⚠ NOT ok=True. G5 answered "no break was found", which is true and
        # useless: an empty chain has not been verified, it has nothing to
        # verify. It also has a sharper edge — deleting EVERY chained row lands
        # here, chain_head then returns None, and the next write restarts at
        # seq 1 against GENESIS. A wholesale delete is self-healing.
        #
        # That is the extreme of the tail-truncation limit the console copy
        # already states, so the copy is not lying; the verdict was. ok=None is
        # absence, which is what this is.
        #
        # A persisted high-water seq would make the restart detectable, and it
        # is NOT worth its cost here: it adds a write to the hot path of every
        # staff action (already +3.99ms and platform-serialised) to catch a case
        # that an operator's externally recorded head hash — which this page
        # already tells them to keep, for exactly this reason — catches better
        # and for free. A second table is also a second thing to delete. Filed,
        # not built, and the reasoning is the deliverable.
        return {**base, "ok": None, "detail": "nothing to check"}
    if chained > ADMIN_CHAIN_VERIFY_LIMIT:
        # ⚠ CARRY THE HEAD. The console tells operators to record this value
        # elsewhere so a later truncation stops being invisible, which makes it
        # load-bearing precisely when the chain is too long to recompute. G5
        # nulled it here as "conservative"; withholding the one thing the copy
        # asks for is not conservatism, it is the copy and the API disagreeing.
        # ok=None already says the chain is unverified, so nothing is endorsed.
        return {**base, "ok": None,
                "head_seq": cov["head_seq"], "head_hash": cov["head_hash"],
                "started_at": cov["started_at"],
                "detail": "chain too long to check in one request"}

    rows = db.execute(
        select(AdminAction)
        .where(AdminAction.seq.isnot(None))
        .order_by(AdminAction.seq.asc())
    ).scalars().yield_per(1000)

    prev_hash = ADMIN_CHAIN_GENESIS
    expected_seq = 1
    started_at = None
    head_seq = head_hash = None
    def broken(kind: str, seq: int, detail: str) -> dict:
        """⚠ first_broken_seq NAMES THE ENTRY THE WORDS NAME, always.

        G5.1 set it to row.seq on the missing path while the sentence named
        expected_seq — so "entry 412 is missing" pointed the console's jump at
        413, an intact row, and an operator following it concludes the tool is
        wrong. The two are one argument now: whatever the words say, the jump
        goes there.

        On a missing entry that means the jump lands on nothing, which is the
        correct answer and reads as a bug unless the console says so — it takes
        `kind` for exactly that.
        """
        return {**base, "ok": False, "kind": kind, "first_broken_seq": seq,
                "started_at": started_at.isoformat() if started_at else None,
                "detail": detail}

    for row in rows:
        if started_at is None:
            started_at = row.created_at
        if row.seq != expected_seq:
            return broken("missing", expected_seq, f"entry {expected_seq} is missing")
        if row.prev_hash != prev_hash:
            return broken("out_of_order", row.seq,
                          f"entry {row.seq} does not follow the one before it")
        expected = compute_admin_chain_hash(
            seq=row.seq, prev_hash=prev_hash, staff_user_id=row.staff_user_id,
            action=row.action, target_org_id=row.target_org_id,
            target_type=row.target_type, target_id=row.target_id,
            detail=row.detail, ip=row.ip, created_at=row.created_at,
        )
        if expected != row.chain_hash:
            return broken("modified", row.seq,
                          f"entry {row.seq} was changed after it was written")
        prev_hash = row.chain_hash
        head_seq, head_hash = row.seq, row.chain_hash
        expected_seq += 1

    return {**base, "ok": True, "detail": "sequence unbroken",
            "head_seq": head_seq, "head_hash": head_hash,
            "started_at": started_at.isoformat() if started_at else None}
