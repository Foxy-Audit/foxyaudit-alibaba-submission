"""The customer's declared AI-system inventory (R1).

Foxy records evidence but, until this exists, cannot say WHICH of a customer's
AI products produced it. This router is the inventory those answers get grouped
by; binding an event to a system is R2 (the backend accepts ``system_id``) and
R3 (the SDK sends it), and nothing here sends or stores an attribution yet.

Five endpoints, two permission levels:

    GET  /v1/systems              list    · _reader          — members AND the SDK
    GET  /v1/systems/{id}         get     · _reader          — members AND the SDK
    POST /v1/systems              create  · require_role('admin')  — dashboard only
    PUT  /v1/systems/{id}         update  · require_role('admin')  — dashboard only
    POST /v1/systems/{id}/retire  retire  · require_role('admin')  — dashboard only

Reads use ``_reader`` (which delegates to ``resolve_org``) because both
audiences need them: a member browsing the dashboard, and the SDK, which in R3
will want to check the id it is about to send. ⚠ The two do NOT see the same
thing — a machine credential gets ``AiSystemSummary`` and a dashboard session
gets the whole declaration. See ``list_systems`` for why.

Writes use ``require_role('admin')`` — a cookie session, never a Bearer
key — because declaring an accountable system is a governance act by a named
human, and ``created_by`` has to name someone. ``keys.py`` splits the same way:
the machine key may rotate itself (``require_org``), while managing the named
key list is ``require_role('admin')``.

⚠ THERE IS NO DELETE ENDPOINT, AND NONE MAY BE ADDED
----------------------------------------------------
Retiring is the only way to take a system out of service, and ``PUT`` cannot do
it: setting ``lifecycle_status='retired'`` through the general update is a 409
naming the retire endpoint, so one governance action is never filed as another.
``POST /v1/systems/{id}/retire`` sets it; the row stays,
still lists, still gets, and (from R2) keeps every event ever attributed to it
while accepting no new ones. A DELETE would orphan chained evidence — the hash
chain has already committed to that id and cannot be edited to forget it, so the
row would be gone while the evidence pointing at it remained. If a future phase
wants "remove it from my dashboard", that is a filter on lifecycle_status, not a
DELETE.

⚠ RETIREMENT IS TERMINAL — THERE IS NO UN-RETIRE, DELIBERATELY
--------------------------------------------------------------
Nothing returns a retired system to service: not ``PUT`` (409 on both edges of
'retired'), and there is no un-retire endpoint. A customer who runs the thing
again declares a NEW system — and can reuse the retired system's name, because
``uq_ai_system_org_name_active`` (migration 0069) is scoped to LIVE rows. That
part is load-bearing: without it the API refused the very remedy this message
names, and the only way out was to PUT-rename the retired row, rewriting a
historical declaration to work around a present-day constraint.

That is a decision about what evidence means, not a missing feature. From R2 a
retired system accepts no new events, so reviving an id would make it name two
operating periods separated by a gap the registry cannot describe — and the
question this table exists to answer ("what was the mortgage bot's risk tier
when it produced this event") would have two answers with nothing to choose
between them. A fresh row is the truthful statement that this is a new
deployment, and it leaves old evidence attributed to the declaration actually in
force when it was recorded.

The cost is real and accepted: retiring by mistake cannot be undone and costs a
re-declaration under a new id. That is the right way round for an audit surface
— the recoverable error is the one that leaves a record.

⚠ DECLARED, NEVER INFERRED
--------------------------
The only writer is an admin registering a system they operate. Nothing derives a
system from traffic. An inventory Foxy guessed would be Foxy's opinion about a
customer's AI estate rather than the customer's own declaration — and this
product's claim is that it does not invent what it reports.

⚠ 'retired' IS NOT DECLARABLE
-----------------------------
``POST`` takes ``DeclarableLifecycle`` ('draft' | 'active'), not the full
vocabulary. A born-retired row would be a system no governance action ever
retired, that ``PUT`` cannot revive (409 on both edges) and no ``DELETE`` can
remove — stuck, along with its name, from the moment of creation.

Content-blind like everything else: this accepts ownership and operating
context, never a prompt, a response or a credential.
"""

from __future__ import annotations

import re
import uuid
from datetime import datetime
from typing import Literal

from fastapi import APIRouter, Depends, Header, HTTPException, Request
from pydantic import BaseModel, Field, field_validator
from sqlalchemy import select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from .. import account_audit
from ..auth import require_role, resolve_org
from ..db import get_db
from ..models import AiSystem, Organization, User

router = APIRouter()

# The declared vocabulary. Duplicated as CHECK constraints in migration 0068 —
# the API is not the only writer a table gets over its life.
Provider = Literal[
    "openai", "azure_openai", "anthropic", "google", "aws_bedrock",
    "self_hosted", "other",
]
Environment = Literal["development", "staging", "production"]
DataClassification = Literal["public", "internal", "confidential", "regulated"]
RiskTier = Literal["low", "medium", "high", "critical"]
LifecycleStatus = Literal["draft", "active", "retired"]
# ⚠ What a DECLARATION may say. 'retired' is reachable only through /retire, so
# it is absent here: a born-retired row could never be created by any governance
# action, could never be un-retired (PUT 409s both edges), and could never be
# deleted — it and its name would be stuck from the moment of creation.
DeclarableLifecycle = Literal["draft", "active"]

RETIRED = "retired"

# Pragmatic, not RFC 5322. The job is to reject a value that cannot be reached —
# "risk-team" — because on this column an unreachable value is worse than a
# blank one: it looks answered. Nothing in this repo validates an email today
# and `email-validator` is not a dependency; adding one for a single field would
# be disproportionate, and a stricter regex would start rejecting real
# addresses, which on an accountability field is the more expensive error.
_EMAIL_RE = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")

# The fields whose OLD value an update must record. "Someone lowered the risk
# tier on the mortgage bot — from what, and when" is the question this registry
# exists to answer, and a trail listing only the field NAMES cannot answer it.
# Deliberately NOT every field: owner_email churn is noise, and this is an audit
# surface rather than a diff log.
_GOVERNANCE_FIELDS = ("name", "risk_tier", "data_classification",
                      "lifecycle_status")


def _validated_email(value: str | None) -> str | None:
    """`owner_email` answers "who is responsible for this system". A value that
    cannot be reached is worse than no value, because it looks answered."""
    if value is None:
        return None
    if not _EMAIL_RE.match(value):
        raise ValueError("owner_email must be an email address")
    return value


class AiSystemCreate(BaseModel):
    name: str = Field(min_length=1, max_length=120)
    owner_email: str | None = Field(default=None, min_length=1, max_length=320)
    purpose: str = Field(min_length=1, max_length=256)
    provider: Provider = "other"
    model_name: str | None = Field(
        default=None, max_length=128, pattern=r"^[A-Za-z0-9_.:/-]{1,128}$")
    environment: Environment = "production"
    data_classification: DataClassification = "internal"
    risk_tier: RiskTier = "medium"
    # ⚠ NOT LifecycleStatus — see DeclarableLifecycle.
    lifecycle_status: DeclarableLifecycle = "active"

    _check_owner_email = field_validator("owner_email")(_validated_email)

    @field_validator("name", "purpose", "owner_email", "model_name", mode="before")
    @classmethod
    def _strip_declared_metadata(cls, value):
        """Trim BEFORE `min_length`/`max_length`/`pattern` run — mode="before" is
        the whole point of this validator.

        An "after" validator runs once the constraints have already passed, so
        `model_name` (the only trimmed field carrying a `pattern`) rejected
        `" gpt-4o "` with a raw regex message while `name` and `purpose` were
        silently trimmed: the same input, two behaviours, decided by whether the
        field happened to have a pattern. Trimming first makes every trimmed
        field behave the same way — surrounding whitespace is never significant
        in a declaration, so it is removed before anything judges the value.

        Blankness is then caught by `min_length=1` on each field rather than by
        a raised ValueError here, which is why `owner_email` carries one.
        Non-strings pass through untouched so the type error stays the type
        error.
        """
        return value.strip() if isinstance(value, str) else value


class AiSystemUpdate(BaseModel):
    """Every field optional — a PUT here is a partial update of declared context.

    ``exclude_unset`` in the handler is what makes that true, so an omitted field
    keeps its stored value rather than being reset to a default.
    """

    name: str | None = Field(default=None, min_length=1, max_length=120)
    owner_email: str | None = Field(default=None, min_length=1, max_length=320)
    purpose: str | None = Field(default=None, min_length=1, max_length=256)
    provider: Provider | None = None
    model_name: str | None = Field(
        default=None, max_length=128, pattern=r"^[A-Za-z0-9_.:/-]{1,128}$")
    environment: Environment | None = None
    data_classification: DataClassification | None = None
    risk_tier: RiskTier | None = None
    lifecycle_status: LifecycleStatus | None = None

    _check_owner_email = field_validator("owner_email")(_validated_email)

    @field_validator("name", "purpose", "owner_email", "model_name", mode="before")
    @classmethod
    def _strip_declared_metadata(cls, value):
        """Trim before the constraints — see AiSystemCreate's copy for why."""
        return value.strip() if isinstance(value, str) else value


class AiSystemItem(BaseModel):
    id: str
    name: str
    owner_email: str
    purpose: str
    provider: str
    model_name: str | None = None
    environment: str
    data_classification: str
    risk_tier: str
    lifecycle_status: str
    # Explicit rather than derived from lifecycle_status by every client in turn:
    # three surfaces will ask this question and two of them are not this repo's.
    retired: bool
    created_at: datetime | None = None
    updated_at: datetime | None = None


class AiSystemSummary(BaseModel):
    """What a MACHINE credential sees. Everything R3 needs to validate an
    attribution, and nothing else — see `_reader`."""

    id: str
    name: str
    lifecycle_status: str
    retired: bool


def _reader(request: Request, authorization: str = Header(default=""),
            db: Session = Depends(get_db)) -> tuple[Organization, bool]:
    """Authenticate a read and report WHICH credential did it.

    `resolve_org` accepts either and returns only the org, so a route built on
    it alone cannot tell a browser session from an API key. Delegates to it
    rather than re-implementing auth, and mirrors its own precedence: a present
    Authorization header IS the SDK path there, so it is the SDK path here.
    """
    return resolve_org(request, authorization, db), bool(authorization)


def _serialize(system: AiSystem) -> AiSystemItem:
    return AiSystemItem(
        id=str(system.id), name=system.name, owner_email=system.owner_email,
        purpose=system.purpose, provider=system.provider, model_name=system.model_name,
        environment=system.environment, data_classification=system.data_classification,
        risk_tier=system.risk_tier, lifecycle_status=system.lifecycle_status,
        retired=(system.lifecycle_status == RETIRED),
        created_at=system.created_at, updated_at=system.updated_at,
    )


def _summarize(system: AiSystem) -> AiSystemSummary:
    return AiSystemSummary(
        id=str(system.id), name=system.name,
        lifecycle_status=system.lifecycle_status,
        retired=(system.lifecycle_status == RETIRED),
    )


def _project(system: AiSystem, machine: bool):
    return _summarize(system) if machine else _serialize(system)


# ─────────────────────── fetching one system: TWO helpers ───────────────────
#
# ⚠ THERE IS DELIBERATELY NO SINGLE `_get_system` WITH A `for_update` FLAG.
#
# There was, and the flag defaulted to False, so taking the lock was something a
# call site had to REMEMBER. `retire_system` remembered after R1d; `update_system`
# did not, and its two retired-guards then decided from a stale read — a PUT
# racing a retire passed both guards and overwrote the committed retirement,
# returning a system to service with only a `system.update` in the trail. That is
# exactly the outcome terminal retirement exists to prevent, reached through the
# back door, and it recurred one caller over because the safe thing was opt-in.
#
# So the flag is gone and the choice is made by WHICH FUNCTION YOU CALL. A new
# caller cannot inherit the unsafe default by writing less; there is no default.
# `test_no_mutating_handler_reads_without_the_lock` walks this module's AST and
# fails if a POST/PUT/PATCH/DELETE handler reaches for the read-only one.

def _system_query(org_id, system_id: uuid.UUID):
    """The org-scoped lookup both helpers share. The explicit org_id filter is
    the load-bearing isolation; the RLS policy (0068) is the second layer."""
    return select(AiSystem).where(AiSystem.id == system_id, AiSystem.org_id == org_id)


def _resolved(system: AiSystem | None) -> AiSystem:
    if system is None:
        # 404, not 403: a foreign tenant's UUID must not be distinguishable from
        # a missing one, or this is an existence oracle over other customers.
        raise HTTPException(status_code=404, detail="AI system not found")
    return system


def _load_system(db: Session, org_id, system_id: uuid.UUID) -> AiSystem:
    """Read one system. ⚠ READ-ONLY — never decide-and-write from this.

    Safe for a handler that serialises the row and returns it. NOT safe for one
    that reads `lifecycle_status`, branches on it and then writes: between the
    read and the write another transaction can commit, and the branch was taken
    against a row that no longer exists in that state. Use `_lock_system`.
    """
    return _resolved(db.execute(_system_query(org_id, system_id)).scalar_one_or_none())


def _lock_system(db: Session, org_id, system_id: uuid.UUID) -> AiSystem:
    """Read one system under `SELECT … FOR UPDATE`, for a handler that decides
    from the row and then writes.

    A concurrent writer's transaction blocks here and this one re-reads the
    committed row afterwards, so the branch is taken against current state.
    `routers/logs.py` locks `org_sequences` for the same reason. Not used by the
    list or the single read: locking those would serialise the dashboard for no
    benefit, because they decide nothing.
    """
    return _resolved(
        db.execute(_system_query(org_id, system_id).with_for_update()).scalar_one_or_none())


def _ensure_unique_name(db: Session, org_id, name: str,
                        exclude_id: uuid.UUID | None = None) -> None:
    """Names are unique PER ORG and only among LIVE systems.

    Per org, because two customers may both run a "support-bot" and neither may
    learn the other does — hence the org_id filter rather than a global index.

    Only among live systems, because retirement is terminal and the documented
    way back is to declare a new system under the same name. A retired row that
    went on reserving its name made the API refuse the remedy its own error
    message named. Mirrors `uq_ai_system_org_name_active` (migration 0069) —
    and the INDEX is the authority; this is the fast path.

    ⚠ BOTH SIDES OF THE PREDICATE, NOT JUST ONE. The index excludes retired rows
    from the uniqueness rule ENTIRELY, so a retired row may also be renamed onto
    a live sibling's name. Callers must therefore skip this check when the row
    being renamed is itself retired: asking only "is the target name taken by a
    live row" makes the pre-check STRICTER than the index it shadows, and a
    pre-check that refuses what the constraint would allow is a rule nobody
    wrote down.
    """
    stmt = select(AiSystem.id).where(AiSystem.org_id == org_id, AiSystem.name == name,
                                     AiSystem.lifecycle_status != RETIRED)
    if exclude_id is not None:
        stmt = stmt.where(AiSystem.id != exclude_id)
    if db.execute(stmt).scalar_one_or_none() is not None:
        raise _duplicate_name()


def _duplicate_name() -> HTTPException:
    return HTTPException(status_code=409,
                         detail="An AI system with that name already exists")


def _flush_or_conflict(db: Session) -> None:
    """Flush, turning a lost race for a name into the 409 the pre-check gives.

    `_ensure_unique_name` is a check-then-act with a real window: two admins
    submitting the same name — or one double-clicked form — both read "no such
    name" and both proceed, and the second one's INSERT then hits
    `uq_ai_system_org_name_active` at flush time. Without this the customer gets
    a 500 for a condition the API already has a correct answer for.

    The pre-check stays because it is the common path and gives the same 409
    without burning a transaction. The CONSTRAINT is the authority; only it is
    free of a window.

    Re-raised if it is any other IntegrityError — a CHECK violation is a bug
    here, not a conflict, and must not be reported as one.
    """
    try:
        db.flush()
    except IntegrityError as exc:
        db.rollback()
        if "uq_ai_system_org_name_active" in str(exc.orig):
            raise _duplicate_name() from exc
        raise


@router.get("/v1/systems", response_model=None)
def list_systems(
    reader: tuple[Organization, bool] = Depends(_reader),
    db: Session = Depends(get_db),
):
    """This workspace's declared AI systems. Members and the SDK may both read.

    Retired systems are INCLUDED and flagged — an inventory that hides what was
    retired cannot answer "what were you running last March", which is the
    question the evidence exists for.

    ⚠ A MACHINE CREDENTIAL GETS A NARROWER PROJECTION (id, name,
    lifecycle_status, retired) and a dashboard session gets the whole
    declaration. The reason is what the full record IS: owner emails, purposes,
    providers, risk tiers and data classifications across every product a
    customer runs — their AI governance chart, and a list of named staff. An API
    key lives in application config, gets baked into container images and CI,
    and is the credential here most likely to leak; it should not be able to
    read that. R3 needs an id, and enough to tell a live system from a retired
    one, to validate an attribution before sending it — which is exactly this.

    `response_model` is None deliberately: a union response model would let
    FastAPI validate the full item against the summary and silently return
    whichever it matched first, which is the failure this exists to prevent.
    """
    org, machine = reader
    systems = db.execute(
        select(AiSystem).where(AiSystem.org_id == org.id)
        .order_by(AiSystem.lifecycle_status.asc(), AiSystem.name.asc())
    ).scalars().all()
    return [_project(system, machine) for system in systems]


@router.get("/v1/systems/{system_id}", response_model=None)
def get_system(
    system_id: uuid.UUID,
    reader: tuple[Organization, bool] = Depends(_reader),
    db: Session = Depends(get_db),
):
    """One declared system, retired or not. Members and the SDK may both read —
    and a machine credential gets the narrow projection, as on the list."""
    org, machine = reader
    return _project(_load_system(db, org.id, system_id), machine)


@router.post("/v1/systems", response_model=AiSystemItem, status_code=201)
def create_system(
    body: AiSystemCreate,
    admin: User = Depends(require_role("admin")),
    db: Session = Depends(get_db),
):
    """Declare an AI system. Dashboard admins only — never a Bearer key.

    ``owner_email`` defaults to the declaring admin because accountability with
    nobody's name on it is not accountability.
    """
    _ensure_unique_name(db, admin.org_id, body.name)
    system = AiSystem(
        org_id=admin.org_id,
        name=body.name,
        owner_email=(body.owner_email or admin.email).lower(),
        purpose=body.purpose,
        provider=body.provider,
        model_name=body.model_name,
        environment=body.environment,
        data_classification=body.data_classification,
        risk_tier=body.risk_tier,
        lifecycle_status=body.lifecycle_status,
        created_by=admin.id,
    )
    db.add(system)
    _flush_or_conflict(db)
    account_audit.record_account_action(
        db, org_id=admin.org_id, actor_email=admin.email, action="system.create",
        target=system.name,
        detail={"system_id": str(system.id), "risk_tier": system.risk_tier,
                "environment": system.environment,
                "lifecycle_status": system.lifecycle_status},
    )
    db.commit()
    db.refresh(system)
    return _serialize(system)


@router.put("/v1/systems/{system_id}", response_model=AiSystemItem)
def update_system(
    system_id: uuid.UUID,
    body: AiSystemUpdate,
    admin: User = Depends(require_role("admin")),
    db: Session = Depends(get_db),
):
    """Update declared operating context. Dashboard admins only.

    This rewrites the DECLARATION, never the ledger: evidence already attributed
    to this system keeps pointing at the same id and the same chain hashes.

    ⚠ It CANNOT retire, and it cannot un-retire. `lifecycle_status` may only move
    between 'draft' and 'active' here; both edges of 'retired' are 409s. See
    `retire_system` for why retirement is terminal.

    ⚠ LOCKED, and the retired-guards below are why. They decide from
    `lifecycle_status`, so on an unlocked read a PUT racing a concurrent retire
    passes both and its UPDATE overwrites the committed retirement — silently
    returning the system to service with only a `system.update` recorded.
    """
    system = _lock_system(db, admin.org_id, system_id)
    values = body.model_dump(exclude_unset=True)
    if not values:
        raise HTTPException(status_code=422,
                            detail="provide at least one system field to update")
    # Every field is Optional so that omitting it means "leave it alone" — which
    # makes an EXPLICIT null indistinguishable from a default at the type level,
    # and would NULL out a NOT NULL column. Refuse it for the non-nullable ones.
    required_fields = {
        "name", "owner_email", "purpose", "provider", "environment",
        "data_classification", "risk_tier", "lifecycle_status",
    }
    if any(values.get(field) is None for field in required_fields if field in values):
        raise HTTPException(status_code=422,
                            detail="required system fields cannot be null")
    # ⚠ NEITHER EDGE OF 'retired' IS A GENERAL UPDATE.
    #
    # Retiring through here would record `system.update` for what is a
    # `system.retire` — one governance action filed as another. Un-retiring
    # through here would be worse: a system that stopped accepting evidence
    # would start again with no endpoint, no governance event, and nothing in
    # the trail saying it happened.
    if "lifecycle_status" in values:
        if values["lifecycle_status"] == RETIRED:
            raise HTTPException(
                status_code=409,
                detail="Retire a system with POST /v1/systems/{id}/retire — "
                       "retirement is a governance action and is recorded as its own")
        if system.lifecycle_status == RETIRED:
            raise HTTPException(
                status_code=409,
                detail="A retired system cannot be returned to service. Declare a "
                       "new system: its evidence must not share an id with the "
                       "period before retirement")
    # Skipped for a retired row: 0069's index does not constrain it, and a
    # pre-check stricter than its own constraint invents a rule.
    if "name" in values and system.lifecycle_status != RETIRED:
        _ensure_unique_name(db, admin.org_id, values["name"], exclude_id=system.id)
    if "owner_email" in values:
        values["owner_email"] = values["owner_email"].lower()
    # Captured BEFORE the writes, and only for the fields that actually change —
    # an entry saying `risk_tier: high -> high` is noise in an audit trail.
    previous = {field: getattr(system, field) for field in _GOVERNANCE_FIELDS
                if field in values and getattr(system, field) != values[field]}
    for field, value in values.items():
        setattr(system, field, value)
    _flush_or_conflict(db)
    account_audit.record_account_action(
        db, org_id=admin.org_id, actor_email=admin.email, action="system.update",
        target=system.name, detail={"system_id": str(system.id), "fields": sorted(values),
                                    "previous": previous},
    )
    db.commit()
    db.refresh(system)
    return _serialize(system)


@router.post("/v1/systems/{system_id}/retire", response_model=AiSystemItem)
def retire_system(
    system_id: uuid.UUID,
    admin: User = Depends(require_role("admin")),
    db: Session = Depends(get_db),
):
    """Retire a system. Dashboard admins only. THE ONLY WAY TO REMOVE ONE,
    AND IT IS ONE-WAY.

    The row stays and keeps listing; from R2 it will accept no new events while
    keeping every historical one. Idempotent — retiring an already-retired
    system returns it unchanged and records no second audit action, so a
    double-clicked button does not fabricate a second governance event.

    ⚠ There is no inverse. ``PUT`` 409s on both edges of 'retired' and no
    un-retire endpoint exists — see the module docstring for why reviving an id
    would make its evidence ambiguous.

    ⚠ THE ROW IS LOCKED (`_lock_system`), AND THAT IS WHAT MAKES "IDEMPOTENT" TRUE.
    This reads the lifecycle, decides from it, and writes — check-then-act, the
    same shape as the name race. Two concurrent retires (a double-clicked
    button) both read 'active', both pass the check and both write a
    `system.retire` account_action. A duplicated record of a governance action
    is worse than a duplicated row: it is a trail that cannot be trusted to be a
    COUNT, on the one surface whose whole value is being countable. `FOR UPDATE`
    makes the second request wait and then re-read the committed row, where it
    finds 'retired' and writes nothing. `routers/logs.py` locks `org_sequences`
    for the same reason.
    """
    system = _lock_system(db, admin.org_id, system_id)
    if system.lifecycle_status != RETIRED:
        system.lifecycle_status = RETIRED
        account_audit.record_account_action(
            db, org_id=admin.org_id, actor_email=admin.email, action="system.retire",
            target=system.name, detail={"system_id": str(system.id)},
        )
        db.commit()
        db.refresh(system)
        return _serialize(system)

    # ⚠ ALREADY RETIRED — NOTHING TO WRITE, SO END THE TRANSACTION HERE.
    #
    # Returning straight from this branch left the `SELECT … FOR UPDATE` taken
    # above held until `get_db` closed the session, which is after the response
    # has been built and sent. A polled or double-clicked retire therefore
    # blocked every concurrent PUT and retire on that row for the whole request,
    # and dropped the `last_seen_at` refresh `require_user` had staged. The lock
    # is right; holding it past the decision is not.
    #
    # `commit`, not `rollback`, so that staged session refresh persists — there
    # is nothing else pending on this path.
    #
    # `expunge` first because `expire_on_commit` defaults to True: without it the
    # commit would expire this row and `_serialize` would silently re-query it,
    # on a transaction whose RLS scope the commit has just cleared. Detaching
    # keeps the values already loaded and touches the database no further.
    db.expunge(system)
    db.commit()
    return _serialize(system)
