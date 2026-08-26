"""The customer's declared AI-system inventory (R1).

Foxy records evidence but, until this exists, cannot say WHICH of a customer's
AI products produced it. This router is the inventory those answers get grouped
by; binding an event to a system is R2 (the backend accepts ``system_id``) and
R3 (the SDK sends it), and nothing here sends or stores an attribution yet.

Five endpoints, two permission levels:

    GET  /v1/systems              list    · resolve_org      — members AND the SDK
    GET  /v1/systems/{id}         get     · resolve_org      — members AND the SDK
    POST /v1/systems              create  · require_role('admin')  — dashboard only
    PUT  /v1/systems/{id}         update  · require_role('admin')  — dashboard only
    POST /v1/systems/{id}/retire  retire  · require_role('admin')  — dashboard only

Reads use ``resolve_org`` because both audiences need them: a member browsing
the dashboard, and the SDK, which in R3 will want to check the id it is about to
send. Writes use ``require_role('admin')`` — a cookie session, never a Bearer
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
again declares a NEW system.

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

Content-blind like everything else: this accepts ownership and operating
context, never a prompt, a response or a credential.
"""

from __future__ import annotations

import uuid
from datetime import datetime
from typing import Literal

from fastapi import APIRouter, Depends, HTTPException
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

RETIRED = "retired"

# The fields whose OLD value an update must record. "Someone lowered the risk
# tier on the mortgage bot — from what, and when" is the question this registry
# exists to answer, and a trail listing only the field NAMES cannot answer it.
# Deliberately NOT every field: owner_email churn is noise, and this is an audit
# surface rather than a diff log.
_GOVERNANCE_FIELDS = ("risk_tier", "data_classification", "lifecycle_status")


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
    lifecycle_status: LifecycleStatus = "active"

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


def _serialize(system: AiSystem) -> AiSystemItem:
    return AiSystemItem(
        id=str(system.id), name=system.name, owner_email=system.owner_email,
        purpose=system.purpose, provider=system.provider, model_name=system.model_name,
        environment=system.environment, data_classification=system.data_classification,
        risk_tier=system.risk_tier, lifecycle_status=system.lifecycle_status,
        retired=(system.lifecycle_status == RETIRED),
        created_at=system.created_at, updated_at=system.updated_at,
    )


def _get_system(db: Session, org_id, system_id: uuid.UUID) -> AiSystem:
    """Fetch one system, scoped to the org. The explicit org_id filter is the
    load-bearing isolation; the RLS policy (0068) is the second layer."""
    system = db.execute(
        select(AiSystem).where(AiSystem.id == system_id, AiSystem.org_id == org_id)
    ).scalar_one_or_none()
    if system is None:
        # 404, not 403: a foreign tenant's UUID must not be distinguishable from
        # a missing one, or this is an existence oracle over other customers.
        raise HTTPException(status_code=404, detail="AI system not found")
    return system


def _ensure_unique_name(db: Session, org_id, name: str,
                        exclude_id: uuid.UUID | None = None) -> None:
    """Names are unique PER ORG. Two customers may both run a "support-bot", and
    neither may learn that the other does — hence the org_id filter here, not a
    global unique index."""
    stmt = select(AiSystem.id).where(AiSystem.org_id == org_id, AiSystem.name == name)
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
    `uq_ai_system_org_name` at flush time. Without this the customer gets a 500
    for a condition the API already has a correct answer for.

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
        if "uq_ai_system_org_name" in str(exc.orig):
            raise _duplicate_name() from exc
        raise


@router.get("/v1/systems", response_model=list[AiSystemItem])
def list_systems(
    org: Organization = Depends(resolve_org),
    db: Session = Depends(get_db),
):
    """This workspace's declared AI systems. Members and the SDK may both read.

    Retired systems are INCLUDED and flagged — an inventory that hides what was
    retired cannot answer "what were you running last March", which is the
    question the evidence exists for.
    """
    systems = db.execute(
        select(AiSystem).where(AiSystem.org_id == org.id)
        .order_by(AiSystem.lifecycle_status.asc(), AiSystem.name.asc())
    ).scalars().all()
    return [_serialize(system) for system in systems]


@router.get("/v1/systems/{system_id}", response_model=AiSystemItem)
def get_system(
    system_id: uuid.UUID,
    org: Organization = Depends(resolve_org),
    db: Session = Depends(get_db),
):
    """One declared system, retired or not. Members and the SDK may both read."""
    return _serialize(_get_system(db, org.id, system_id))


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
    """
    system = _get_system(db, admin.org_id, system_id)
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
    if "name" in values:
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
    """
    system = _get_system(db, admin.org_id, system_id)
    if system.lifecycle_status != RETIRED:
        system.lifecycle_status = RETIRED
        account_audit.record_account_action(
            db, org_id=admin.org_id, actor_email=admin.email, action="system.retire",
            target=system.name, detail={"system_id": str(system.id)},
        )
        db.commit()
        db.refresh(system)
    return _serialize(system)
