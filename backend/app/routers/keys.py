"""API key management.

Two audiences share this router:

* The **dashboard** (human admin session) manages *named* keys — list / create /
  revoke — via ``GET|POST /v1/keys`` and ``DELETE /v1/keys/{id}``. New keys are
  stored as HMAC-SHA256(server pepper, key) in the ``api_keys`` table; the
  plaintext is returned exactly once.
* The **SDK/CLI** (machine Bearer key) can still ``POST /v1/keys/rotate`` its own
  key without a dashboard login. It issues a peppered key and revokes **only the
  credential that made the call** - every sibling key stays active.

The two rotations are deliberately NOT the same act (register #249). Revoking an
organisation's whole key set is "this is compromised, burn it": a decision made
by a human who knows what else is deployed, so it lives behind
``/v1/keys/regenerate/*`` - an admin session **plus** an emailed 2FA code. The
machine endpoint has neither a human nor a second factor, and one holder of one
key being able to silently kill every other service's key WAS #249. It was
silent twice over: the caller got a 200, and the SDK spools rather than crashes,
so the orphaned services kept accepting traffic and kept writing to a spool that
could never drain.
"""

from __future__ import annotations

import hashlib
import hmac
import logging
import secrets
import uuid
from datetime import datetime, timedelta, timezone

from fastapi import APIRouter, Depends, Header, HTTPException
from pydantic import BaseModel, Field
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from .. import account_audit
from .. import email as email_mod, email_templates as et
from .. import mfa
# `_bearer_token` is imported rather than re-implemented: the rotate handler has
# to identify the SAME token `require_org` authenticated on, and a second copy of
# that parse would rotate the wrong credential the moment the two drifted.
from ..auth import (_bearer_token, hash_key, require_org, require_role,
                    require_step_up_user)
from ..config import get_settings
from ..db import get_db
from ..models import ApiKey, Organization, User

log = logging.getLogger("foxy.keys")
router = APIRouter()


def _new_key() -> tuple[str, str, str]:
    """Return (plaintext, hmac_hash, display_prefix) for a fresh key."""
    key = "foxy_sk_" + secrets.token_hex(24)
    return key, hash_key(key), key[:11] + "…" + key[-4:]   # foxy_sk_1a2…7e02


# ─────────────────────────── dashboard (admin session) ───────────────────────

class KeyItem(BaseModel):
    id: str
    name: str
    key_prefix: str
    status: str
    created_at: str
    last_used_at: str | None = None
    expires_at: str | None = None
    expired: bool = False
    revoked_at: str | None = None


class CreateKeyRequest(BaseModel):
    name: str = "unnamed key"
    expires_in_days: int | None = Field(default=None, ge=1, le=3650)  # None = never


class CreateKeyResponse(BaseModel):
    id: str
    name: str
    key_prefix: str
    api_key: str             # plaintext — shown once, never stored
    created_at: str
    message: str = "Copy this key now — it is shown once and cannot be recovered."


def _serialize(k: ApiKey) -> KeyItem:
    expired = bool(k.expires_at and k.expires_at < datetime.now(timezone.utc))
    return KeyItem(
        id=str(k.id), name=k.name, key_prefix=k.key_prefix, status=k.status,
        created_at=k.created_at.isoformat() if k.created_at else "",
        last_used_at=k.last_used_at.isoformat() if k.last_used_at else None,
        expires_at=k.expires_at.isoformat() if k.expires_at else None,
        expired=expired,
        revoked_at=k.revoked_at.isoformat() if k.revoked_at else None,
    )


@router.get("/v1/keys", response_model=list[KeyItem])
def list_keys(
    admin: User = Depends(require_role("admin")),
    db: Session = Depends(get_db),
):
    """List the org's API keys (active + revoked), newest first — admin only."""
    rows = db.execute(
        select(ApiKey).where(ApiKey.org_id == admin.org_id)
        .order_by(ApiKey.created_at.desc())
    ).scalars().all()
    return [_serialize(k) for k in rows]


@router.post("/v1/keys", response_model=CreateKeyResponse)
def create_key(
    body: CreateKeyRequest,
    admin: User = Depends(require_role("admin")),
    db: Session = Depends(get_db),
):
    """Create a named API key. Returns the plaintext once - admin only."""
    org = db.get(Organization, admin.org_id)
    key_limit = get_settings().api_key_limit_for(org.plan_tier if org else None)
    if key_limit is not None:
        active_keys = db.execute(
            select(func.count()).select_from(ApiKey).where(
                ApiKey.org_id == admin.org_id, ApiKey.status == "active")
        ).scalar_one()
        if int(active_keys) >= key_limit:
            raise HTTPException(
                status_code=402,
                detail={"code": "api_key_limit_reached", "message": "Your plan has no available active API-key slots. Upgrade to add another environment or service.",
                        "used": int(active_keys), "included": key_limit},
            )
    key, key_hash, prefix = _new_key()
    name = ((body.name or "").strip() or "unnamed key")[:120]  # whitespace-only -> default
    expires_at = (datetime.now(timezone.utc) + timedelta(days=body.expires_in_days)
                  if body.expires_in_days else None)
    row = ApiKey(org_id=admin.org_id, name=name, key_prefix=prefix, key_hash=key_hash,
                 status="active", expires_at=expires_at)
    db.add(row)
    db.flush()
    account_audit.record_account_action(
        db, org_id=admin.org_id, actor_email=admin.email, action="key.create",
        target=name, detail={"expires_in_days": body.expires_in_days})
    db.commit()
    db.refresh(row)
    log.info("Created API key %s for org %s", row.id, admin.org_id)
    return CreateKeyResponse(
        id=str(row.id), name=row.name, key_prefix=row.key_prefix,
        api_key=key, created_at=row.created_at.isoformat() if row.created_at else "",
    )


@router.delete("/v1/keys/{key_id}", dependencies=[Depends(require_step_up_user)])
def revoke_key(
    key_id: uuid.UUID,     # FastAPI validates the path -> 422 (not 500) on a non-UUID
    admin: User = Depends(require_role("admin")),
    db: Session = Depends(get_db),
):
    """Revoke one of the org's keys — admin only. Idempotent on an already-revoked key."""
    row = db.execute(
        select(ApiKey).where(ApiKey.id == key_id, ApiKey.org_id == admin.org_id)
    ).scalar_one_or_none()
    if row is None:
        raise HTTPException(status_code=404, detail="Key not found")
    if row.status != "revoked":
        row.status = "revoked"
        row.revoked_at = datetime.now(timezone.utc)
        account_audit.record_account_action(
            db, org_id=admin.org_id, actor_email=admin.email, action="key.revoke",
            target=row.name)
        db.commit()
    log.info("Revoked API key %s for org %s", row.id, admin.org_id)
    return {"status": "revoked", "id": str(row.id)}


# ─────────────────────────── SDK/CLI (machine Bearer) ────────────────────────

class RotateResponse(BaseModel):
    org_id: str
    api_key: str             # plaintext — shown once, never stored
    rotated_at: str
    # No default. The two rotations destroy different amounts and each states
    # which - a shared sentence is how "the old key is permanently invalid" came
    # to be the machine endpoint's answer while it was quietly killing four
    # other keys it never mentioned.
    message: str


def _rotate_org_key(db: Session, org: Organization) -> tuple[str, str, int]:
    """Revoke **every** active key in the org, mint a fresh peppered one, and kill
    the legacy plain-SHA256 hash.

    ⚠ THIS IS THE BURN-IT-ALL PATH AND HAS EXACTLY ONE CALLER:
    ``regenerate_confirm``, behind an admin session and an emailed 2FA code.
    Revoking an organisation's other services and environments is a deliberate
    human decision about a credential believed compromised. Do not point a
    machine-authenticated endpoint at this again - that was register #249; use
    ``_rotate_presented_key`` instead.

    Returns (plaintext_key, rotated_at_iso, revoked_count). Caller commits."""
    now = datetime.now(timezone.utc)
    key, key_hash, prefix = _new_key()
    revoked = 0
    for k in db.execute(
        select(ApiKey).where(ApiKey.org_id == org.id, ApiKey.status == "active")
    ).scalars().all():
        k.status = "revoked"
        k.revoked_at = now
        revoked += 1
    db.add(ApiKey(org_id=org.id, name="primary (rotated)", key_prefix=prefix,
                  key_hash=key_hash, status="active"))
    # Point the legacy hash at the new key too, so the old key is dead but the
    # NOT NULL column stays satisfied (the peppered path matches first anyway).
    org.api_key_hash = hashlib.sha256(key.encode("utf-8")).hexdigest()
    org.key_rotated_at = now
    return key, now.isoformat(), revoked


def _rotate_presented_key(db: Session, org: Organization,
                          token: str) -> tuple[str, str, str]:
    """Replace ONLY the credential that authenticated this request (register #249).

    ``require_org`` hands back the *organisation*, not the ``ApiKey`` row it
    matched, so the presented key is re-identified here from the same bearer
    token. That is sound rather than a guess: ``key_hash`` is UNIQUE, so
    ``hash_key(token)`` names at most one row - the very row ``require_org``
    authenticated on. Re-deriving beats widening ``require_org``'s return type
    for one endpoint's benefit; 35 modules depend on that contract.

    ⚠ ``ApiKey.org_id == org.id`` IS THE ONLY TENANT ISOLATION ON THIS QUERY.
    ``api_keys`` carries no RLS at all (``models.py`` - ``require_org`` looks a
    key up *before* the tenant GUC exists), so nothing underneath would catch
    its removal, and no behavioural cross-tenant test can either: a token can
    never resolve to an org other than the one ``require_org`` just returned for
    it. It is guarded at source instead, in ``test_keys.py``.

    Returns (plaintext_key, rotated_at_iso, rotated_key_name). Caller commits."""
    now = datetime.now(timezone.utc)
    presented_legacy_hash = hashlib.sha256(token.encode("utf-8")).hexdigest()
    # FOR UPDATE, because a concurrent DELETE /v1/keys/{id} on this same key would
    # otherwise interleave: rotate reads it active, the admin revokes it, and
    # rotate then mints a live replacement for access somebody had just
    # deliberately killed. Under READ COMMITTED the loser re-evaluates the
    # predicate once the lock frees, sees status='revoked', and falls through to
    # the 401 below. NOTE the row is ALREADY locked incidentally today -
    # `require_org`'s best-effort `last_used_at` stamp autoflushes an UPDATE on
    # it before this SELECT runs - which is precisely why the lock is written
    # down: the day that stamp becomes conditional or throttled, the safety a
    # usage counter was accidentally providing would leave with it.
    current = db.execute(
        select(ApiKey).where(
            ApiKey.org_id == org.id,
            ApiKey.key_hash == hash_key(token),
            ApiKey.status == "active",
        ).with_for_update()
    ).scalar_one_or_none()

    # The presented token can also BE the legacy plain-SHA256 org hash. Compared
    # with compare_digest because this decides whether a credential dies.
    is_legacy_key = bool(org.api_key_hash) and hmac.compare_digest(
        org.api_key_hash, presented_legacy_hash)

    if current is None and not is_legacy_key:
        # It authenticated a moment ago and is gone now - revoked between
        # `require_org` and the lock. Say so, rather than minting a replacement
        # for a credential that no longer exists.
        raise HTTPException(status_code=401,
                            detail="This API key is no longer active")

    key, key_hash, prefix = _new_key()
    if current is not None:
        current.status = "revoked"
        current.revoked_at = now
        name = current.name          # the replacement serves the same service
        # Carry the expiry FORWARD, never drop it: rotation must not lengthen a
        # credential's life, or a machine converts a bounded 30-day key into a
        # permanent one just by calling this endpoint. An expired key never
        # authenticates (`require_org`), so this date is always still ahead.
        expires_at = current.expires_at
    else:
        # A pre-A2 org whose only credential is the legacy org hash - there is no
        # api_keys row to revoke. The replacement gets one, so the NEXT rotation
        # takes the peppered path.
        name, expires_at = "primary (rotated)", None

    db.add(ApiKey(org_id=org.id, name=name, key_prefix=prefix, key_hash=key_hash,
                  status="active", expires_at=expires_at))
    if is_legacy_key:
        # ONLY when the presented token IS the legacy org hash - and that is the
        # COMMON shape, not an edge case: `/v1/signup` and the Google path both
        # register one plaintext as BOTH the peppered "primary" row AND
        # organizations.api_key_hash, so a key rotated here has to die on both
        # paths or `require_org`'s fallback keeps honouring it.
        #
        # Repointing it unconditionally would be #249 in miniature: on an org
        # whose legacy hash belongs to a DIFFERENT key, rotating a peppered
        # sibling would kill that one as a side effect. The column is NOT NULL,
        # so it is repointed at the replacement, never cleared.
        org.api_key_hash = hashlib.sha256(key.encode("utf-8")).hexdigest()
    org.key_rotated_at = now
    return key, now.isoformat(), name


@router.post("/v1/keys/rotate", response_model=RotateResponse)
def rotate_key(
    authorization: str = Header(default=""),
    org: Organization = Depends(require_org),
    db: Session = Depends(get_db),
):
    """Rotate ONLY the key that made this call (Bearer auth). Sibling keys are the
    org's other services and environments and are left active - a machine
    credential with no human behind it must not be able to revoke them. The
    burn-everything rotation lives on the 2FA-gated regenerate path.

    No key-limit check: this is net-zero on live credentials (one revoked, one
    minted), and refusing to rotate an org already at its limit would strand the
    very key it is trying to replace."""
    # `require_org` is a sub-dependency and has already rejected a missing or
    # malformed header with a 401 by the time this body runs; `_bearer_token` is
    # re-run so the extraction is identical rather than merely similar.
    key, rotated_at, name = _rotate_presented_key(
        db, org, _bearer_token(authorization))
    # NEW `action=` LITERAL - see `account_audit.record_account_action`: the
    # label lives in `desktop/settings_admin.py` AUDIT_LABELS and ships in this
    # same commit. `actor_email=None` follows `billing_state`: a machine key
    # knows an organisation rotated; it does not know which human, and naming one
    # would assert something unverified on an audit row. The mechanism, which IS
    # known, goes in `detail`.
    account_audit.record_account_action(
        db, org_id=org.id, actor_email=None, action="key.rotate", target=name,
        detail={"via": "machine_bearer", "scope": "presented_key"})
    db.commit()
    log.info("Rotated one API key for org %s", org.id)
    return RotateResponse(
        org_id=str(org.id), api_key=key, rotated_at=rotated_at,
        message="Key rotated. Copy the new key now — the key that made this call "
                "is permanently invalid. Your other keys are untouched.")


# ─────────────── dashboard: regenerate key behind an emailed 2FA code ─────────
# Keys are stored hashed and shown once, so "reveal" isn't possible — instead we
# mint a FRESH key (old one revoked), gated by a one-time code emailed to the
# logged-in admin. Keeps hash-only security; the admin always has a usable key.

class RegenConfirmRequest(BaseModel):
    code: str


@router.post("/v1/keys/regenerate/request")
def regenerate_request(
    admin: User = Depends(require_role("admin")),
    db: Session = Depends(get_db),
):
    """Step 1: email a one-time code to the admin's address (2FA even inside a
    logged-in session)."""
    code = mfa.new_otp()
    admin.mfa_code_hash = mfa.hash_code(code)
    admin.mfa_code_expires_at = datetime.now(timezone.utc) + mfa.TTL
    db.commit()
    html, plain = et.layout(
        title="Confirm API-key regeneration",
        preheader=f"Your Foxy Audit key-regeneration code is {code}",
        blocks=[
            et.paragraph("Use this one-time code to regenerate your API key. Your current key is "
                         "revoked the moment the new one is issued."),
            et.code_block(code),
            et.muted("It expires in 5 minutes. If you didn't request this, ignore this email and "
                     "change your password."),
        ],
    )
    email_mod.send_email(to=admin.email, subject="Your Foxy Audit key-regeneration code",
                         html=html, text=plain)
    return {"status": "code_sent", "email": admin.email}


@router.post("/v1/keys/regenerate/confirm", response_model=RotateResponse)
def regenerate_confirm(
    body: RegenConfirmRequest,
    admin: User = Depends(require_role("admin")),
    db: Session = Depends(get_db),
):
    """Step 2: verify the code, then rotate the org's key and return the new
    plaintext once. Wrong/expired code → 401."""
    if not mfa.code_valid(admin, (body.code or "").strip()):
        raise HTTPException(status_code=401, detail="Invalid or expired code")
    mfa.clear_code(admin)
    org = db.get(Organization, admin.org_id)
    if org is None:
        raise HTTPException(status_code=404, detail="Organization not found")
    key, rotated_at, revoked = _rotate_org_key(db, org)
    # A SECOND `action=` literal, deliberately, rather than one action carrying
    # the distinction in `detail`: `desktop/settings_admin.py:audit_rows` renders
    # action / target / actor / when and NOT `detail`, so a difference buried
    # there would be invisible to the customer reading their own history - and
    # being invisible is the half of #249 that made the blast radius silent.
    account_audit.record_account_action(
        db, org_id=admin.org_id, actor_email=admin.email, action="key.regenerate",
        target="%d active key%s" % (revoked, "" if revoked == 1 else "s"),
        detail={"via": "dashboard_2fa", "scope": "all_active_keys",
                "revoked": revoked})
    db.commit()
    log.info("Regenerated API key (2FA) for org %s by %s - %d revoked",
             org.id, admin.email, revoked)
    return RotateResponse(
        org_id=str(org.id), api_key=key, rotated_at=rotated_at,
        message="Key regenerated. Copy the new key now — EVERY previous key in "
                "this workspace is permanently invalid.")
