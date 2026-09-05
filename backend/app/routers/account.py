"""Customer-facing account reads: billing history + usage rollups (Phase 4 #2).

The customer dashboard's window onto the same `invoices` table the admin site
reads cross-org, plus per-day usage aggregated from `audit_logs` itself. Auth is resolve_org (dashboard session cookie OR
SDK Bearer key) — both paths set the RLS GUC, and every query still carries an
explicit WHERE org_id because the app-level filter is the load-bearing tenant
isolation (the docker superuser role bypasses RLS).
"""

from __future__ import annotations

import json
import logging
import pathlib
import secrets
import uuid
from datetime import date, datetime, timedelta, timezone

from fastapi import (
    APIRouter, Depends, File, HTTPException, Query, Request, Response, UploadFile,
)
from fastapi.responses import FileResponse
from pydantic import BaseModel
from sqlalchemy import Date, cast, func, select
from sqlalchemy.orm import Session

from .. import account_audit, billing_state, ip_allow
from ..anchor import latest_anchor
from ..auth import require_role, require_step_up_user, require_user, resolve_org
from ..config import get_settings
from ..db import get_db
from ..models import (
    AccountAction, AiSystem, ApiKey, AuditEvent, AuditLog, ChainAnchor, ExportJob,
    HumanReview, Invoice, LoginEvent, Notification, Organization, OrgPolicy, PaymentEvent,
    SsoConnection, StripeEvent, UsageDaily, User, WebhookSubscription,
)
from .logs import limiter          # the app's single Limiter instance
# ⚠ THE LEDGER PROJECTION IS IMPORTED, NOT RE-WRITTEN, AND THAT IS THE FIX FOR
# #269 RATHER THAN A TIDY-UP. This bundle used to carry its own nine-column
# picture of `audit_logs` while `verifier/foxy_verify.py` recomputes the hash
# over seventeen inputs — so the DSAR bundle could not be verified at all, and
# (because the verifier read `data.get("logs", [])`) reported `[OK] chain
# intact` over it having checked nothing. Two hand-maintained projections of one
# chain-bound table is the defect; one projection, shared with the export the
# verifier is documented against, is what stops it coming back. Adding a
# chain-hashed column now reaches BOTH exports or NEITHER.
#
# It does not weaken the "every section is an explicit field list" rule this
# endpoint depends on: `_export_row` is exactly such a list, over a table that
# holds no credential column, going to the same workspace that can already
# fetch it from GET /v1/logs/export.
from .logs import (
    EXPORT_PAGE_MAX, _anchor_export, _export_row, _page_export, _prev_chain_hash,
)

log = logging.getLogger("foxy.account")
router = APIRouter()


class InvoiceItem(BaseModel):
    id: str
    #: M3f — ADDITIVE. Both shipped clients (the dashboard's invoice table and
    #: `desktop/billing_data.invoice_rows`) read date/amount/currency/status/
    #: period and none of them reads `stripe_invoice_id`, so widening this
    #: response cannot break either. Checked before changing it.
    provider: str = "stripe"                 # stripe | paddle | manual
    #: What to show a customer who asks "which payment is this?" — the
    #: processor's own id, or the reference a staff member recorded.
    reference: str | None = None
    #: Optional since M3f: only a genuine Stripe invoice has one, and only a
    #: Stripe row can be resolved to a hosted PDF.
    stripe_invoice_id: str | None = None
    #: NULL when nobody recorded an amount — a staff activation records which
    #: payment was seen, not its size. Rendered as a dash, never as zero.
    amount_cents: int | None = None
    currency: str
    status: str
    period_start: str | None = None
    period_end: str | None = None
    created_at: str | None = None


class UsageDay(BaseModel):
    day: str
    logs_count: int
    tokens_sum: int
    breach_count: int
    graded_count: int
    failed_count: int
    pending_count: int


class EvaluationAccess(BaseModel):
    label: str = "Premium judge access"
    active: bool
    capture_available: bool
    expires_at: str | None = None
    credits_total: int
    credits_used: int
    credits_remaining: int


class UsageQuota(BaseModel):
    plan_tier: str | None = None
    monthly_log_quota: int | None = None   # NULL = unlimited
    used_this_month: int = 0
    remaining: int | None = None           # NULL when unlimited
    usage_pct: int | None = None           # 0..100+, NULL when unlimited
    over_quota: bool = False
    credit_unit: str = "audit_event"
    credits_included: int | None = None
    credits_used: int = 0
    credits_remaining: int | None = None
    trial_ends_at: str | None = None
    trial_active: bool = False
    seat_limit: int | None = None
    active_seats: int = 0
    api_key_limit: int | None = None
    active_api_keys: int = 0
    ingestion_blocked: bool = False


    evaluation: EvaluationAccess | None = None


class UsageResponse(BaseModel):
    quota: UsageQuota
    days: list[UsageDay]


@router.get("/v1/invoices", response_model=list[InvoiceItem])
def list_invoices(
    org: Organization = Depends(resolve_org),
    db: Session = Depends(get_db),
    limit: int = Query(default=24, ge=1, le=100),
):
    """This org's payment history, newest first.

    Every processor, and payments taken outside one. A card payment arrives from
    the Paddle webhook; a payment invoiced directly arrives when a staff member
    activates the plan and records the reference it was paid against. An org that
    has never paid gets an empty list, which is the honest answer for it.
    """
    rows = db.execute(
        select(Invoice)
        .where(Invoice.org_id == org.id)
        .order_by(Invoice.created_at.desc())
        .limit(limit)
    ).scalars().all()
    return [
        InvoiceItem(
            id=str(i.id), provider=i.provider,
            reference=i.provider_ref or i.stripe_invoice_id,
            stripe_invoice_id=i.stripe_invoice_id,
            amount_cents=i.amount_cents, currency=i.currency, status=i.status,
            period_start=i.period_start.isoformat() if i.period_start else None,
            period_end=i.period_end.isoformat() if i.period_end else None,
            created_at=i.created_at.isoformat() if i.created_at else None,
        )
        for i in rows
    ]


@router.get("/v1/usage", response_model=UsageResponse)
def get_usage(
    org: Organization = Depends(resolve_org),
    db: Session = Depends(get_db),
    days: int = Query(default=30, ge=1, le=90),
):
    """Per-day usage straight from audit_logs, plus quota headroom against
    organizations.monthly_log_quota.

    This used to read the worker-maintained `usage_daily` rollup, which
    recomputes only a rolling 48-hour window (usage.py `_ROLLUP_SQL`). That is
    correct for the day it was designed around and wrong for everything else:
    any day older than ~2 days keeps whatever partial counts were true when the
    worker last touched it, so a 30- or 90-day chart understated real history —
    silently, and always downwards. `used_this_month` below already read
    audit_logs for exactly this reason, so the same endpoint was serving a
    correct quota number beside an understated chart.

    audit_logs is append-only and org-scoped, so aggregating it is the source of
    truth. The weekly digest reached the same conclusion independently
    (user_notifications.py `_WEEK_TOTALS_SQL`); this reuses that approach with
    the rollup's own expressions, so the numbers agree by construction."""
    today = date.today()
    since = today - timedelta(days=days - 1)
    since_dt = datetime.combine(since, datetime.min.time(), tzinfo=timezone.utc)

    # #123 · PINNED TO UTC. date_trunc/::date on a timestamptz resolves in the
    # SESSION timezone, and nothing in this project pins it — so this bucketed
    # by the database server's local day. R3 fixed the same shape in usage.py;
    # this endpoint's own docstring says it reuses "the rollup's own expressions",
    # and it did not: the rollup pins UTC and this did not, so the window bound
    # below (built with tzinfo=timezone.utc) and the buckets disagreed by up to a
    # day. timezone('UTC', ts)::date IS the UTC calendar day — the idiom
    # admin_stats.py documents and admin_health/admin_security already use.
    day_col = cast(func.timezone("UTC", AuditLog.created_at), Date).label("day")
    rows = db.execute(
        select(
            day_col,
            func.count().label("logs_count"),
            func.coalesce(func.sum(AuditLog.token_count), 0).label("tokens_sum"),
            func.count().filter(
                AuditLog.gemini_verdict["policy_breach"].astext == "true"
            ).label("breach_count"),
            func.count().filter(
                AuditLog.grading_status == "graded").label("graded_count"),
            func.count().filter(
                AuditLog.grading_status == "failed").label("failed_count"),
            func.count().filter(
                AuditLog.grading_status == "pending").label("pending_count"),
        )
        .where(AuditLog.org_id == org.id, AuditLog.created_at >= since_dt)
        .group_by(day_col)
        .order_by(day_col.asc())
    ).all()

    month_start = today.replace(day=1)
    month_start_dt = datetime.combine(month_start, datetime.min.time(), tzinfo=timezone.utc)
    used_this_month = db.execute(
        select(func.count()).select_from(AuditLog)
        .where(AuditLog.org_id == org.id, AuditLog.created_at >= month_start_dt)
    ).scalar_one()

    quota = org.monthly_log_quota
    used = int(used_this_month)
    now = datetime.now(timezone.utc)
    trial_active = bool(
        (org.plan_tier or "").lower() == "free"
        and org.trial_ends_at is not None
        and now < org.trial_ends_at
    )
    # Same source of truth as the gate that actually rejects the write (D1), so
    # this widget can no longer say "capturing" while /v1/logs returns 402.
    capture_blocked = billing_state.capture_block(org, now)
    seat_limit = get_settings().seat_limit_for(org.plan_tier)
    api_key_limit = get_settings().api_key_limit_for(org.plan_tier)
    active_seats = db.execute(
        select(func.count()).select_from(User).where(
            User.org_id == org.id, User.disabled.is_(False))
    ).scalar_one()
    active_keys = db.execute(
        select(func.count()).select_from(ApiKey).where(
            ApiKey.org_id == org.id, ApiKey.status == "active")
    ).scalar_one()
    ingestion_blocked = bool(
        capture_blocked is not None
        or (quota is not None and used >= quota)
    )
    evaluation = None
    if org.evaluation_offer_id and org.evaluation_credit_limit is not None:
        active = not org.evaluation_ends_at or now < org.evaluation_ends_at
        credits_used = max(0, org.evaluation_credits_used)
        credits_remaining = (max(0, org.evaluation_credit_limit - credits_used)
                             if active else 0)
        evaluation = EvaluationAccess(
            active=active,
            capture_available=bool(active and credits_remaining > 0),
            expires_at=org.evaluation_ends_at.isoformat() if org.evaluation_ends_at else None,
            credits_total=org.evaluation_credit_limit,
            credits_used=credits_used,
            credits_remaining=credits_remaining,
        )
    return UsageResponse(
        quota=UsageQuota(
            plan_tier=org.plan_tier,
            monthly_log_quota=quota,
            used_this_month=used,
            remaining=None if quota is None else max(0, quota - used),
            usage_pct=None if not quota else round(used / quota * 100),
            over_quota=bool(quota is not None and used >= quota),
            credits_included=quota,
            credits_used=used,
            credits_remaining=None if quota is None else max(0, quota - used),
            trial_ends_at=org.trial_ends_at.isoformat() if org.trial_ends_at else None,
            trial_active=trial_active,
            seat_limit=seat_limit,
            active_seats=int(active_seats),
            api_key_limit=api_key_limit,
            active_api_keys=int(active_keys),
            ingestion_blocked=ingestion_blocked,
            evaluation=evaluation,
        ),
        days=[
            UsageDay(
                day=r.day.isoformat(), logs_count=r.logs_count,
                tokens_sum=int(r.tokens_sum),
                breach_count=r.breach_count, graded_count=r.graded_count,
                failed_count=r.failed_count, pending_count=r.pending_count,
            )
            for r in rows
        ],
    )


class DeleteWorkspaceRequest(BaseModel):
    confirm_name: str


@router.post("/v1/account/delete", dependencies=[Depends(require_step_up_user)])
def delete_workspace(
    payload: DeleteWorkspaceRequest,
    request: Request,
    admin: User = Depends(require_role("admin")),
    db: Session = Depends(get_db),
):
    """Soft-delete the caller's workspace: set organizations.deleted_at. Every auth
    path then refuses the org (SDK key, new logins, existing sessions), reversibly
    (data retained). confirm_name must match the workspace name (accident guard);
    admin-only via require_role."""
    org = db.get(Organization, admin.org_id)
    if org is None or org.deleted_at is not None:
        raise HTTPException(status_code=404, detail="workspace not found")
    if payload.confirm_name.strip() != org.name:
        raise HTTPException(status_code=400,
                            detail="confirm_name does not match the workspace name")
    org.deleted_at = datetime.now(timezone.utc)
    db.commit()
    request.session.clear()          # the admin's own session is now for a deleted org
    return {"status": "workspace_deleted", "org_id": str(org.id)}


@router.post("/v1/account/org-id", dependencies=[Depends(require_step_up_user)])
def reveal_org_id(user: User = Depends(require_user), db: Session = Depends(get_db)):
    """The workspace's organisation ID, behind an emailed step-up code (P3 §7.1).

    This is the ONLY place a session can learn its org id. `/v1/auth/me` — and
    login, MFA and the desktop handoff — deliberately no longer carry it. The
    old design shipped the id in the `me` payload and masked it in the DOM,
    which protected nothing: devtools showed it in two clicks. A reveal control
    over a value the browser already holds is decoration, and on a product that
    sells tamper-evidence a decorative security control is worse than none.

    A read, not a mutation, so it is POST purely because that is what
    `require_step_up_user` guards elsewhere in this file — and it is audited
    like the other step-up actions, because "who un-masked the workspace id,
    and when" is exactly the kind of question the account trail exists for."""
    account_audit.record_account_action(
        db, org_id=user.org_id, actor_email=user.email,
        action="account.org_id_reveal")
    db.commit()
    return {"org_id": str(user.org_id)}


class IpAllowlistRequest(BaseModel):
    allowlist: str = ""              # comma-separated IPs/CIDRs; empty clears the restriction


@router.post("/v1/account/ip-allowlist", dependencies=[Depends(require_step_up_user)])
def set_ip_allowlist(
    payload: IpAllowlistRequest,
    request: Request,
    admin: User = Depends(require_role("admin")),
    db: Session = Depends(get_db),
):
    """Set the org's DASHBOARD IP allow-list (admin-only). Refuses a non-empty
    list that wouldn't include the caller's own IP — a self-lockout guard."""
    entries = ip_allow.parse_allowlist(payload.allowlist)
    if entries and not ip_allow.ip_allowed(ip_allow.client_ip(request), entries):
        raise HTTPException(status_code=400,
                            detail="that allow-list would lock you out — include your current IP")
    org = db.get(Organization, admin.org_id)
    org.ip_allowlist = ", ".join(entries) if entries else None
    db.commit()
    return {"status": "ok", "ip_allowlist": org.ip_allowlist or ""}


@router.post("/v1/account/badge")
def mint_badge(
    request: Request,
    admin: User = Depends(require_role("admin")),
    db: Session = Depends(get_db),
):
    """Mint (or return the existing) public trust-badge token for this org — admin
    only. Embed the returned SVG URL anywhere via <img>. Aggregate status only, so
    the badge never exposes tenant data. (Phase 6 · 6C)"""
    org = db.get(Organization, admin.org_id)
    if org is None:
        raise HTTPException(status_code=404, detail="workspace not found")
    if not org.public_badge_token:
        org.public_badge_token = secrets.token_urlsafe(24)
        db.commit()
    return {"token": org.public_badge_token, "url": f"/v1/badge/{org.public_badge_token}.svg"}


@router.delete("/v1/account/badge", dependencies=[Depends(require_step_up_user)])
def revoke_badge(
    request: Request,
    admin: User = Depends(require_role("admin")),
    db: Session = Depends(get_db),
):
    """Revoke the org's public trust badge — the old token immediately 404s. (6C)"""
    org = db.get(Organization, admin.org_id)
    if org is not None and org.public_badge_token:
        org.public_badge_token = None
        db.commit()
    return {"status": "revoked"}


# ─────────────── account audit log (P2 · §D) ───────────────────────────────

class AccountActionItem(BaseModel):
    id: str
    actor_email: str | None = None
    action: str
    target: str | None = None
    detail: dict | None = None
    created_at: str | None = None


@router.get("/v1/account/audit", response_model=list[AccountActionItem])
def account_audit_log(
    admin: User = Depends(require_role("admin")),
    db: Session = Depends(get_db),
    limit: int = Query(default=100, ge=1, le=500),
):
    """The org's own account-action trail (key/policy/member/MFA changes),
    newest first — admin only, org-scoped by RLS."""
    rows = db.execute(
        select(AccountAction).where(AccountAction.org_id == admin.org_id)
        .order_by(AccountAction.created_at.desc()).limit(limit)
    ).scalars().all()
    return [AccountActionItem(
        id=str(a.id), actor_email=a.actor_email, action=a.action, target=a.target,
        detail=a.detail, created_at=a.created_at.isoformat() if a.created_at else None,
    ) for a in rows]


# ─────────────── full account / GDPR export (P2 · §H) ──────────────────────

#: Bundle section -> the table it is drawn from. `export_scope.included_tables`
#: is derived from THIS and from the sections actually built, so the manifest
#: and the contents cannot drift apart — which is the whole of #252. A count or
#: a list written in prose is a claim nobody rechecks; a list derived from the
#: bundle is one that cannot go stale silently.
EXPORT_SECTION_TABLES = {
    "organization": "organizations",
    "users": "users",
    "policy": "org_policies",
    "api_keys": "api_keys",
    "invoices": "invoices",
    "anchors": "chain_anchors",
    "ai_systems": "ai_systems",
    "account_actions": "account_actions",
    "ledger": "audit_logs",
    "login_events": "login_events",
    "notifications": "notifications",
    "webhook_subscriptions": "webhook_subscriptions",
    "sso_connections": "sso_connections",
    "usage_daily": "usage_daily",
    "export_jobs": "export_jobs",
    "payment_events": "payment_events",
    "stripe_events": "stripe_events",
    # A1 · INCLUDED RATHER THAN EXCLUDED, and there was no honest third option.
    # `test_every_org_scoped_table_is_either_exported_or_named_as_excluded`
    # forces the decision the moment a table gains an `org_id`, and none of the
    # exclusion reasons below is true of this one: it holds no credential, it is
    # not a duplicate of anything else in the bundle, and it grows one row per
    # ESCALATION rather than per interaction or per request, so it cannot move
    # the bundle's size. What it holds is the workspace's own governance record —
    # what its judge asked a person to look at and what that person decided —
    # which is data a subject would plainly recognise as theirs.
    "human_reviews": "human_reviews",
}

#: Every org-scoped table this bundle does NOT carry, with the reason, IN THE
#: BUNDLE. An honest bundle beats a complete-looking one: a DSAR answered with a
#: file that asserts completeness while silently omitting a category is a false
#: statement in a compliance product, and that is exactly what #252 was.
#:
#: ⚠ THE FIRST THREE ARE THE REASON THE OBVIOUS RULE IS WRONG. "Anything with an
#: org_id belongs in the export" would mandate serialising a session token hash,
#: a step-up code hash and a hand-off token hash — a direct violation of this
#: repo's hard rule. They are excluded because they hold a credential, not
#: because they were overlooked.
EXPORT_EXCLUSIONS = {
    # (b) auth plumbing / credentials — MUST NOT be exported.
    "user_sessions": (
        "Auth plumbing. This table exists to hold a live session credential, "
        "which is stored only as a one-way hash and is never serialised "
        "anywhere. The sign-in activity it would otherwise describe is "
        "exported in full under login_events."),
    "verification_codes": (
        "Auth plumbing. One-time step-up codes, stored only as a one-way "
        "hash, consumed within minutes and never readable even by us."),
    "auth_handoff_tokens": (
        "Auth plumbing. Single-use, short-lived tokens that hand a browser "
        "session to the desktop app, stored only as a one-way hash."),
    # (c) org-scoped, but not data about the subject.
    # ⚠ THIS REASON WAS TRUE OF ONE ROW SHAPE AND THE TABLE NOW HOLDS TWO. It
    # read "one row per graded interaction … adds nothing you do not have", which
    # A1 made FALSE the moment `human_review_resolved` started landing here: that
    # row is not a projection of any ledger column, and nothing else in the bundle
    # carried it. A stale exclusion reason is the #252 defect exactly — a
    # completeness claim that stopped describing what it excludes — so the second
    # shape is exported under `human_reviews` and this sentence now names both.
    "audit_events": (
        "Duplicate of data already in this bundle, in both of the shapes it "
        "holds. Its `verdict` rows are an append-only projection of the same "
        "grading verdict carried on every ledger row as gemini_verdict, one per "
        "graded interaction — exporting them would roughly double the largest "
        "section and add nothing you do not have. Its `human_review_resolved` "
        "rows are one per resolved escalation and are NOT a projection of any "
        "ledger column, so they are carried in full under human_reviews "
        "instead: the resolution, who made it and when, the judge's reason for "
        "escalating, and that event's own event_hash."),
    "traffic_events": (
        "Server access log, written for platform operations, abuse detection "
        "and incident response across all three sites. It DOES record which "
        "signed-in user made a request and which page they asked for, so it is "
        "excluded on volume and purpose rather than because it is anonymous: "
        "it grows per HTTP request rather than per interaction, and it is an "
        "operations record rather than part of your audit evidence. IP address "
        "and user agent are stored only as irreversible hashes, and no request "
        "bodies, headers, query strings or secrets are kept. If you want your "
        "own entries from it, ask us."),
    "org_sequences": (
        "Internal bookkeeping: a single row holding the next chain sequence "
        "number for this workspace, already implied by the ledger's last seq."),
    "evaluation_redemptions": (
        "Platform issuance and anti-abuse record for evaluation offers, "
        "keyed by a hashed email so one address cannot redeem twice. The "
        "customer-facing result of a redemption is the plan_tier and "
        "subscription_status already carried under organization."),
    # Named although it carries no org_id at all, because a reader will ask.
    "consent_events": (
        "Not workspace data. Cookie-consent decisions from the public "
        "marketing site carry no org_id, user_id or email — only a hashed IP "
        "and user agent — so they cannot be attributed to this workspace or to "
        "anyone in it."),
}

#: Sections that carry a row but deliberately withhold one column, and why.
#: `api_keys` set this precedent long before #252: a table can hold a secret and
#: still be exported, provided the secret is the part left out. That is what
#: keeps `sso_connections` and `webhook_subscriptions` in the bundle rather than
#: in the exclusions above — the table is customer configuration, and only the
#: credential column is withheld.
EXPORT_WITHHELD_FIELDS = {
    # section: (the columns actually held back, what to TELL the reader, why)
    #
    # ⚠ THE COLUMN NAMES STAY HERE AND NEVER REACH THE BUNDLE. `test_keys.py`'s
    # #249 guard scans the whole response for hash-column tokens, and its value
    # is precisely that it is blunt: it catches the next person who emits one,
    # whatever section they emit it from. Printing `key_hash` in a manifest
    # would leak nothing and would blind that guard, which is a bad trade for a
    # word a customer does not need. So the bundle says "the API key itself"
    # and the structural test reads the tuple below.
    #
    # The first two predate #252 and were always correct — they are named here
    # because the manifest is only honest if it lists every credential column
    # held back, not just the ones this phase happened to touch.
    "organization": (("api_key_hash",),
                     "the workspace's legacy API key",
                     "Stored only as a one-way hash; the key itself was shown "
                     "once, at creation."),
    "users": (("password_hash", "mfa_code_hash", "reset_token_hash"),
              "passwords, multi-factor codes and password-reset tokens",
              "Stored only as one-way hashes and never serialised anywhere."),
    # ⚠ `policy` was missing entirely until #252b, while `org_policies` holds
    # Fernet-encrypted BYOK provider keys. `grep -c key_enc` over this file
    # returned 0: the bundle withheld them correctly and said so nowhere, which
    # is the same false claim as omitting a table, one layer down.
    #
    # ⚠ AND THIS TUPLE IS EDITED IN THE SAME COMMIT AS THE COLUMN. There were two
    # keys until 0071 added `qwen_key_enc`; EXPORT_STATEMENT below claims that
    # every credential this workspace holds is named here, so a `*_key_enc`
    # column that lands without its name makes a PUBLISHED sentence false at the
    # moment the migration runs — not at the moment someone notices. The
    # structural guard is `test_every_credential_we_hold_is_named_in_the_manifest`,
    # which walks the model registry for the `_key_enc` pattern.
    "policy": (("gemini_key_enc", "openai_key_enc", "qwen_key_enc"),
               "the AI-provider keys you brought to this workspace",
               "Held encrypted at rest with a key this service never returns, "
               "and never decrypted outside the grading path."),
    "api_keys": (("key_hash",),
                 "the API key itself",
                 "Stored only as a one-way hash and shown exactly once, at "
                 "creation."),
    "sso_connections": (("client_secret",),
                        "your identity provider's client secret",
                        "A live credential."),
    "webhook_subscriptions": (("secret",),
                              "the signing key for deliveries to your endpoint",
                              "A live credential."),
    "payment_events": (("payload",),
                       "the raw webhook body as the payment provider sent it",
                       "It is their record in their own shape, it may gain "
                       "fields at their discretion, and they are a separate "
                       "controller you can ask directly. What we hold about "
                       "your billing is exported under invoices and "
                       "organization."),
    "stripe_events": (("payload",),
                      "the raw webhook body as the payment provider sent it",
                      "See payment_events."),
}

#: ⚠ THIS SENTENCE IS THE LEGAL EXPOSURE, NOT THE ROW COUNT. It is deliberately
#: a claim about the LISTS rather than about completeness, because the lists are
#: derived from the model registry and checked by
#: `test_every_org_scoped_table_is_either_exported_or_named_as_excluded`.
#: Two earlier wordings were false the moment they were written.
EXPORT_STATEMENT = (
    "This is the data Foxy Audit holds for this workspace that you would "
    "recognise as your own, summarised one section per table — not a dump of "
    "every database column. Two things about it are exact rather than "
    "editorial, and a test fails if either drifts: every table we operate that "
    "carries an org_id is named in exactly one of included_tables or "
    "excluded_tables below, each exclusion with its reason; and every "
    "credential we hold for this workspace is named in withheld_fields, with "
    "what it is and why it cannot be sent. If you need a field you do not see "
    "here, ask us and we will tell you whether we hold it. One section is "
    "bounded: the ledger carries at most the number of rows named in "
    "page.max_rows_per_page at the top of this file. That block states which "
    "seq range the rows cover and whether more remain past them; when more "
    "do, page.note names the export that will hand you the rest."
)


def _export_scope(bundle_sections, ledger_page=None) -> dict:
    """The manifest, derived from the sections actually built.

    ⚠ #271: `ledger_complete` is derived from the page block the ledger section
    was actually built with, never written separately. The manifest is where a
    reader looks to find out what this bundle claims, so a bounded ledger has to
    say so HERE as well as in `page` — a completeness manifest that omits the one
    section that can stop short is the #252 defect wearing the #252 fix.
    """
    return {
        "statement": EXPORT_STATEMENT,
        "ledger_complete": None if ledger_page is None else ledger_page["complete"],
        "ledger_note": None if ledger_page is None else ledger_page["note"],
        "included_tables": sorted(
            EXPORT_SECTION_TABLES[s] for s in bundle_sections
            if s in EXPORT_SECTION_TABLES),
        "excluded_tables": [{"table": t, "reason": r}
                            for t, r in sorted(EXPORT_EXCLUSIONS.items())],
        # `held_back` is prose on purpose — see EXPORT_WITHHELD_FIELDS.
        "withheld_fields": [{"section": s, "held_back": what, "reason": why}
                            for s, (_cols, what, why) in sorted(
                                EXPORT_WITHHELD_FIELDS.items())],
    }


@router.get("/v1/account/export")
def account_export(
    admin: User = Depends(require_role("admin")),
    db: Session = Depends(get_db),
):
    """Self-serve, machine-readable export of the workspace data a customer would
    recognise as their own: org profile, users, policy, API-key metadata (never
    the secret), invoices, anchors, declared AI systems, the account-action
    trail, the full hash-chain ledger, and — since #252 — sign-in history,
    in-app notifications, outbound webhook and SSO configuration (never their
    credentials), the daily usage rollup, the export history, and billing-event
    metadata (never the provider's raw payload). Admin only. Content-blind: the
    ledger carries only hashes, bounded labels, counts and timestamps, never
    prompt or response text.

    ⚠ AND SINCE #269 THE LEDGER IS ACTUALLY VERIFIABLE, WHICH IT WAS NOT.
    `verifier/foxy_verify.py` recomputes each chain hash over seventeen inputs.
    This bundle carried nine columns and no top-level `org_id`, so pointing the
    verifier at the file a customer had just been handed recomputed NOTHING —
    and, because the verifier read `data.get("logs", [])` and this section is
    named `ledger`, it printed `[OK] chain intact` over zero rows. Two halves,
    both fixed: the verifier now REFUSES a file it cannot read (exit 2, never
    `[OK]`) and reads `ledger` as well as `logs`; this section is now the same
    `_export_row` projection `GET /v1/logs/export` ships, plus `org_id` and the
    `anchor` receipt at the top level. A rename alone would have turned a silent
    pass into a loud failure — better, and still not verification.

    ⚠ THAT LIST IS THE CLAIM, AND IT IS NOT "EVERYTHING". IT USED TO SAY SO.
    Two earlier wordings were false: "everything this workspace holds", and then
    the stronger "anything added to this workspace's schema belongs here". The
    second was wrong to WANT, not merely inaccurate — four of the tables it
    reached hold values a hard rule forbids serialising
    (`user_sessions.token_hash`, `verification_codes.code_hash`,
    `auth_handoff_tokens.token_hash`, `sso_connections.client_secret`), and a
    fifth found while closing #252 does too (`webhook_subscriptions.secret`).
    A rule that mandates exporting a session token hash is not a rule worth
    keeping.

    ⚠ SO THE CLAIM IS ABOUT TABLES AND CREDENTIALS, NOT ABOUT COLUMNS. `#252`
    closes by classifying all 23 org-scoped tables rather than by exporting
    them: 16 are here, and the 7 that are not are named in
    `export_scope.excluded_tables` IN THE BUNDLE, each with its reason.

    ⚠ AND #252b HAD TO NARROW IT AGAIN, BECAUSE THE FIRST VERSION SAID "nothing
    is left out that is not named here" AND THAT WAS FALSE. Measured per
    section — model columns minus emitted minus declared-withheld — the bundle
    drops 101 columns nobody names. Most are surrogate keys and internal
    plumbing (`id`, `org_id`, `grading_attempts`, `paddle_customer_id`), but two
    were not: `users.full_name`, the data subject's OWN NAME, and
    `org_policies.gemini_key_enc` / `openai_key_enc`, two Fernet-encrypted BYOK
    keys withheld correctly and named nowhere — `grep -c key_enc` over this file
    returned 0. Naming all 101 would bury the four that matter under 97 rows of
    `id` and serve no data subject, so the fields that a DSAR needs were added
    instead and `EXPORT_STATEMENT` now claims only what the lists back: table
    completeness and credential completeness, both test-enforced, plus an
    explicit route for a subject who wants a column it does not carry.

    `included_tables` is derived from the sections actually built. One test
    walks the model registry to assert every org-scoped table is named in
    exactly one of included_tables or excluded_tables; its twin walks the same
    registry for the credential half. A list written in prose is a claim nobody
    rechecks; neither of these can go stale without a test going red.

    ⚠ THE FORWARD RULE, CORRECTLY SCOPED — it stays, because it is what exposed
    the gap. A table added FROM HERE that holds data the customer would
    recognise as their own, and that is not auth plumbing and not a secret,
    belongs in this bundle. Everything else belongs in `EXPORT_EXCLUSIONS` with
    a reason. `ai_systems` and `account_actions` were both added under it: the
    first holds `owner_email`, personal data about someone who need not be a
    `User` row at all, so the users section did not cover them; the second is
    the workspace's own record of who changed what.

    ⚠ EVERY SECTION IS AN EXPLICIT FIELD LIST, AND THAT IS THE SAFETY PROPERTY,
    not a style. A generic "serialise every column" helper would have shipped
    `token_hash` the day someone pointed it at `user_sessions`, and would ship
    the next secret column automatically. Adding a field here is a decision
    somebody makes; it is never a default.

    ⚠ #271 — THE LEDGER IS BOUNDED NOW, AND THE PARAGRAPH BELOW USED TO ARGUE IT
    SHOULD NOT BE. That argument was right about the danger and wrong about the
    only two options: it read "bound it" as "truncate it", and a silent
    truncation inside a completeness claim really would have been worse than the
    OOM. There is a third option and it is what shipped — bound the section AND
    state the bound in the file, in `page` at the top level (the same projection
    `GET /v1/logs/export` ships, from `logs._page_export`), in
    `export_scope.ledger_complete`, and in EXPORT_STATEMENT. `_export_row` was
    also measured again through THIS endpoint and costs 1450.3 B a row, not the
    670 B recorded below: the figure predates #269 making this section the full
    projection, so the exposure was more than twice what the paragraph claimed.

    ⚠ WHAT WAS NOT BOUNDED, AND WHY IT WAS ARGUED FOR — MEASURED THROUGH THIS
    ENDPOINT, NOT ESTIMATED. An empty bundle is 6.2 kB and a `ledger` row cost
    670 B when this was written. At the Max plan's 250,000 interactions a month,
    one year of ledger is 3,000,000 rows and about 2.0 GB, built in memory and
    returned in a single response. That is a PRE-EXISTING property of this
    endpoint which #252 does not change and does not paper over: a DSAR that
    OOMs the API is worse than one that is incomplete, and the ledger — not
    anything added here — is where that risk lives. It is filed rather than
    fixed in this phase because bounding it means paging or a job, which is a
    different endpoint, and because truncating it silently would put back the
    exact false claim #252 was.

    Against that, the sections added here cost 264 B (login_events), 341 B
    (notifications) and 256 B (usage_daily) a row, and on a deliberately
    pessimistic model — 50 seats, 500 sign-ins each, twelve breaches a day
    fanned out to every seat — come to 81 MB, about 4% of that ledger. None of
    them changes the order of magnitude. The two that WOULD are excluded above:
    `audit_events` is one row per graded interaction and would add ~970 MB of
    the same verdict this bundle already carries under `gemini_verdict`, and
    `traffic_events` grows per HTTP request rather than per interaction. A
    truncated section inside a completeness claim is the defect this docstring
    exists to prevent, so the ledger's LIMIT is declared in the bundle and
    nothing else here carries one.

    `account_actions.detail` is exported whole because every writer records THAT
    a secret changed and never the secret (`routers/policies.py` says so at the
    one call site that touches keys); if that ever stops being true, this is the
    second place it leaks.
    """
    org = db.get(Organization, admin.org_id)
    users = db.execute(select(User).where(User.org_id == admin.org_id)).scalars().all()
    policy = db.get(OrgPolicy, admin.org_id)
    keys = db.execute(select(ApiKey).where(ApiKey.org_id == admin.org_id)).scalars().all()
    invoices = db.execute(select(Invoice).where(Invoice.org_id == admin.org_id)).scalars().all()
    anchors = db.execute(select(ChainAnchor).where(ChainAnchor.org_id == admin.org_id)).scalars().all()
    systems = db.execute(
        select(AiSystem).where(AiSystem.org_id == admin.org_id)
        .order_by(AiSystem.created_at.asc())
    ).scalars().all()
    # ⚠ No LIMIT, and that is a decision. `GET /v1/account/audit` caps at 500
    # because it renders a page; this is an export, and a truncated audit trail
    # inside a completeness claim is the defect this docstring exists to
    # prevent. It is also not the size risk here: this table gains a row per
    # account mutation while `audit_logs` below gains one per interaction and is
    # already exported unbounded, so it is smaller by orders of magnitude on any
    # workspace where either is large. The whole bundle being built in memory is
    # a pre-existing property of this endpoint that account_actions does not
    # meaningfully change.
    actions = db.execute(
        select(AccountAction).where(AccountAction.org_id == admin.org_id)
        .order_by(AccountAction.created_at.asc())
    ).scalars().all()
    # One row per escalation the agentic judge raised — orders of magnitude
    # smaller than `account_actions` above, which is itself unbounded here for
    # the reason stated there.
    #
    # Joined to the ledger for `seq` rather than looked up against the `logs`
    # list below: that list is BOUNDED at EXPORT_PAGE_MAX, so a review pointing
    # past the ledger page would have silently exported a null sequence — an
    # escalation the bundle could not tie to an interaction.
    #
    # ⚠ AND IT CARRIES THE RESOLUTION EVENT'S `event_hash`. That digest is the ONLY
    # part of a `human_review_resolved` row not otherwise in this bundle, and
    # `EXPORT_EXCLUSIONS["audit_events"]` above now states that the row is carried
    # here in full. Dropping it would make that sentence false, in the file whose
    # whole subject is what it does and does not contain. Null while a review is
    # still pending — there is no event to hash yet.
    #
    # ⚠ A CORRELATED SCALAR SUBQUERY, NOT A LEFT JOIN, AND THE SHAPE IS THE POINT.
    # A join assumes at most one `human_review_resolved` per `audit_log_id`, and
    # NOTHING IN THE SCHEMA ENFORCES THAT — `audit_events` carries no unique
    # constraint, and it cannot carry a blanket one, because the retry path
    # legitimately appends a second `verdict` event for the same row. Under a join
    # a duplicate would fan ONE review into TWO entries here: two apparent
    # governance decisions about one determination, inside the artefact whose
    # subject is completeness. The endpoint's row lock is what stops the duplicate
    # being written, and this is what stops a duplicate being AMPLIFIED if one ever
    # is — a defence in the reader as well as the writer, because this reader is
    # the one a regulator holds. `LIMIT 1` on `created_at` picks the FIRST event,
    # matching the first-write-wins rule the resolve endpoint enforces. Recorded
    # as an A1 follow-up in plan §4.6, with the partial index that would end it.
    _resolution_hash = (
        select(AuditEvent.event_hash)
        .where(AuditEvent.org_id == admin.org_id,
               AuditEvent.audit_log_id == HumanReview.audit_log_id,
               AuditEvent.event_type == "human_review_resolved")
        .order_by(AuditEvent.created_at.asc())
        .limit(1)
        .scalar_subquery())
    reviews = db.execute(
        select(HumanReview, AuditLog.seq, _resolution_hash)
        .join(AuditLog, AuditLog.id == HumanReview.audit_log_id)
        .where(HumanReview.org_id == admin.org_id, AuditLog.org_id == admin.org_id)
        .order_by(HumanReview.created_at.asc())
    ).all()
    # ⚠ #271 — THE ONE SECTION THAT COULD OOM THIS ENDPOINT IS BOUNDED NOW.
    # A `ledger` row costs 1450.3 B measured through this endpoint, so a Max-plan
    # year (3,000,000 rows) was ~4.4 GB built in memory here. `limit + 1` detects
    # that more remain without a second COUNT, and the extra row is discarded
    # rather than served.
    logs = db.execute(
        select(AuditLog).where(AuditLog.org_id == admin.org_id)
        .order_by(AuditLog.seq.asc()).limit(EXPORT_PAGE_MAX + 1)
    ).scalars().all()
    ledger_has_more = len(logs) > EXPORT_PAGE_MAX
    logs = logs[:EXPORT_PAGE_MAX]
    # The SAME page projection `GET /v1/logs/export` ships, for the same reason
    # both call `_export_row` (#269): one statement of how complete a file is,
    # written once, so the two artefacts cannot disagree about the same rows.
    # This bundle is never itself paged — it is a DSAR answer, not a cursor — so
    # the continuation it names is the log export, which is.
    ledger_page = _page_export(
        logs, _prev_chain_hash(db, admin.org_id, logs[0].seq if logs else None),
        ledger_has_more,
        (f"/v1/logs/export?format=json&after_seq={logs[-1].seq}"
         if ledger_has_more else None))
    # ⚠ EVERY ONE OF THESE CARRIES ITS OWN `org_id` FILTER, AND RLS IS NOT THE
    # REASON THEY ARE SAFE. THREE of them — login_events, payment_events,
    # stripe_events — are posture C in the Database note: `org_id` is NULLABLE,
    # which structurally rules RLS out, so the clause below is the ONLY tenant
    # isolation on those rows. The rest are posture A, where a dropped clause
    # would be invisible to a behavioural cross-tenant test because
    # `auth._scope_org` has already confined the role. Both cases are asserted
    # at the SOURCE by
    # `test_the_export_filters_by_org_itself_and_does_not_lean_on_rls`.
    logins = db.execute(
        select(LoginEvent).where(LoginEvent.org_id == admin.org_id)
        .order_by(LoginEvent.created_at.asc())
    ).scalars().all()
    notes = db.execute(
        select(Notification).where(Notification.org_id == admin.org_id)
        .order_by(Notification.created_at.asc())
    ).scalars().all()
    hooks = db.execute(
        select(WebhookSubscription)
        .where(WebhookSubscription.org_id == admin.org_id)
        .order_by(WebhookSubscription.created_at.asc())
    ).scalars().all()
    sso = db.execute(
        select(SsoConnection).where(SsoConnection.org_id == admin.org_id)
        .order_by(SsoConnection.created_at.asc())
    ).scalars().all()
    usage = db.execute(
        select(UsageDaily).where(UsageDaily.org_id == admin.org_id)
        .order_by(UsageDaily.day.asc())
    ).scalars().all()
    jobs = db.execute(
        select(ExportJob).where(ExportJob.org_id == admin.org_id)
        .order_by(ExportJob.created_at.asc())
    ).scalars().all()
    payments = db.execute(
        select(PaymentEvent).where(PaymentEvent.org_id == admin.org_id)
        .order_by(PaymentEvent.received_at.asc())
    ).scalars().all()
    stripes = db.execute(
        select(StripeEvent).where(StripeEvent.org_id == admin.org_id)
        .order_by(StripeEvent.received_at.asc())
    ).scalars().all()

    def _iso(v):
        return v.isoformat() if v else None

    bundle = {
        "organization": {
            "id": str(org.id), "name": org.name, "plan_tier": org.plan_tier,
            "subscription_status": org.subscription_status,
            "contact_email": org.contact_email,
            "monthly_log_quota": org.monthly_log_quota,
            "created_at": _iso(org.created_at),
            # Added at #252b. Account state and the payment method summary are
            # things a workspace would recognise as facts about itself, and
            # `ip_allowlist` is customer-CONFIGURED — it is their rule, and the
            # forward rule above says so. Provider identifiers
            # (paddle/stripe ids, the badge token) stay out: those are handles
            # into someone else's system, not facts about this workspace.
            "approval_status": org.approval_status,
            "trial_ends_at": _iso(org.trial_ends_at),
            "suspended": org.suspended,
            "suspended_reason": org.suspended_reason,
            "deleted_at": _iso(org.deleted_at),
            "ip_allowlist": org.ip_allowlist,
            "card_on_file": org.card_on_file,
            "card_brand": org.card_brand,
            "card_last4": org.card_last4,
        } if org else None,
        # ⚠ `full_name` WAS MISSING UNTIL #252b, AND IT IS THE DATA SUBJECT'S OWN
        # NAME. `PUT /v1/account/profile` lets them set it; the bundle then did
        # not give it back. A subject-access request that omits the subject's
        # name is the defect #252 is about, at its smallest and worst.
        "users": [{"email": u.email, "full_name": u.full_name, "role": u.role,
                   "disabled": u.disabled, "mfa_enabled": u.mfa_enabled,
                   "created_at": _iso(u.created_at)} for u in users],
        "policy": {
            "pii_detection": policy.pii_detection, "prompt_injection": policy.prompt_injection,
            "regulated_data_mode": policy.regulated_data_mode,
            "max_token_threshold": policy.max_token_threshold,
            "enforcement_mode": policy.enforcement_mode,
            "notify_on_breach": policy.notify_on_breach,
            # Added at #252b: the rest of what the workspace CONFIGURED. The
            # notify addresses are personal data in their own right, and the
            # judge settings are the customer's choice about who grades their
            # evidence. The `*_key_enc` columns — three of them since 0071 added
            # Qwen — are withheld and SAID to be, in export_scope. The count is
            # not written down here on purpose: it was "two" until a migration
            # made that false, and a number in a comment beside a list is a
            # second place for the same fact to go stale.
            "confidence_threshold": policy.confidence_threshold,
            "notify_email": policy.notify_email,
            "notify_webhook_url": policy.notify_webhook_url,
            "judge_provider": policy.judge_provider,
            "judge_key_mode": policy.judge_key_mode,
            "sdk_enforcement": policy.sdk_enforcement,
        } if policy else None,
        "api_keys": [{"name": k.name, "key_prefix": k.key_prefix, "status": k.status,
                      "created_at": _iso(k.created_at), "last_used_at": _iso(k.last_used_at),
                      "expires_at": _iso(k.expires_at)} for k in keys],
        "invoices": [{"stripe_invoice_id": i.stripe_invoice_id, "amount_cents": i.amount_cents,
                      "currency": i.currency, "status": i.status,
                      "created_at": _iso(i.created_at)} for i in invoices],
        "anchors": [{"root_hash": a.root_hash, "last_seq": a.last_seq, "chain": a.chain,
                     "tx_hash": a.tx_hash, "status": a.status,
                     "anchored_at": _iso(a.anchored_at)} for a in anchors],
        # The WHOLE declaration, retired rows included. A subject-access request
        # over this workspace should see what was declared about whom, and a
        # retired system is precisely the one someone has stopped thinking about
        # — it still names an owner and still describes what ran. Every field is
        # customer-declared: nothing here is Foxy's opinion, and nothing here can
        # hold prompt or response content.
        "ai_systems": [{"id": str(s.id), "name": s.name, "owner_email": s.owner_email,
                        "purpose": s.purpose, "provider": s.provider,
                        "model_name": s.model_name, "environment": s.environment,
                        "data_classification": s.data_classification,
                        "risk_tier": s.risk_tier,
                        "lifecycle_status": s.lifecycle_status,
                        "retired": s.lifecycle_status == "retired",
                        "created_at": _iso(s.created_at),
                        "updated_at": _iso(s.updated_at)} for s in systems],
        # Who changed what, and — from R1 — what the governance values were
        # before. `detail` is customer-facing by construction: its writers record
        # that a secret changed, never the secret.
        "account_actions": [{"actor_email": a.actor_email, "action": a.action,
                             "target": a.target, "detail": a.detail,
                             "created_at": _iso(a.created_at)} for a in actions],
        # ⚠ `note` IS EXPORTED HERE AND NOWHERE ELSE, and the two are consistent.
        # It is excluded from the EVIDENCE surfaces — the `human_review_resolved`
        # event payload, the ledger export, the Compliance Passport — because it
        # is free text a reviewer typed and those artefacts are content-blind.
        # This bundle is the opposite kind of document: the subject asking for
        # their own data back, including the words they wrote themselves.
        # `id` is here because the resolution event's payload names it as
        # `review_id`, and the sentence in EXPORT_EXCLUSIONS["audit_events"] says
        # that row is carried in full. Every field of that payload is in this
        # projection: review_id, resolution, resolved_by, resolved_at,
        # escalation_reason, escalation_risk_score — and its event_hash beside
        # them. Add a field to the event and it is added here, or that sentence
        # stops being true.
        "human_reviews": [{"id": str(h.id), "seq": seq,
                           "status": h.status, "resolution": h.resolution,
                           "reason": h.reason, "risk_score": h.risk_score,
                           "note": h.note, "created_at": _iso(h.created_at),
                           "resolved_at": _iso(h.resolved_at),
                           "resolved_by": h.resolved_by,
                           "resolution_event_hash": event_hash}
                          for h, seq, event_hash in reviews],
        # ⚠ #269: THE SAME PROJECTION AS GET /v1/logs/export, NOT A SUMMARY OF IT.
        # The nine columns this used to carry could not be verified: the chain
        # hash is taken over seventeen inputs, thirteen of which were absent, so
        # `verifier/foxy_verify.py` pointed at this bundle recomputed nothing.
        # Every field added here is a hash, a bounded label, a count or a
        # timestamp — `event_metadata` is allowlisted and length-capped at ingest
        # (`schemas.LogIngest._metadata_is_content_blind`) and `local_verdict` is
        # derived from it — so content-blindness is unchanged: no prompt or
        # response text exists in this table to export.
        "ledger": [_export_row(r) for r in logs],
        # ── added closing #252 ────────────────────────────────────────────
        # Sign-in activity, and the sharpest of the omissions: `email`, `ip` and
        # `user_agent` are stored RAW here (unlike traffic_events, where both are
        # hashed), which makes this plainly personal data. Failed attempts are
        # included: "somebody tried to sign in as me from this address" is the
        # half of a sign-in trail a subject most needs.
        "login_events": [{"email": e.email, "ip": e.ip, "user_agent": e.user_agent,
                          "success": e.success,
                          "created_at": _iso(e.created_at)} for e in logins],
        # What this workspace was told, and whether anyone read it. Bodies are
        # templated from policy tags, risk scores and colleague emails — checked
        # at every writer; nothing here can carry prompt or response content.
        "notifications": [{"kind": n.kind, "title": n.title, "body": n.body,
                           "level": n.level, "target_type": n.target_type,
                           "target_id": n.target_id, "read_at": _iso(n.read_at),
                           "created_at": _iso(n.created_at)} for n in notes],
        # Customer-configured integrations. `secret` and `client_secret` are the
        # only columns withheld — the api_keys pattern, not a new one.
        "webhook_subscriptions": [{"url": w.url, "events": w.events,
                                   "active": w.active, "last_status": w.last_status,
                                   "last_delivery_at": _iso(w.last_delivery_at),
                                   "created_at": _iso(w.created_at)} for w in hooks],
        "sso_connections": [{"email_domain": s.email_domain, "issuer": s.issuer,
                             "client_id": s.client_id, "active": s.active,
                             "created_at": _iso(s.created_at)} for s in sso],
        # One row per day, so bounded by the workspace's age however busy it is.
        "usage_daily": [{"day": _iso(u.day), "logs_count": u.logs_count,
                         "tokens_sum": u.tokens_sum, "breach_count": u.breach_count,
                         "graded_count": u.graded_count, "failed_count": u.failed_count,
                         "pending_count": u.pending_count,
                         "computed_at": _iso(u.computed_at)} for u in usage],
        # Who extracted what, and when. NOT a recursion: `GET /v1/account/export`
        # writes no ExportJob — only `POST /v1/exports` does — so this bundle
        # records the compliance exports a human asked for and never itself.
        # `file_ref` is omitted because the server keeps no archive and it is
        # reserved; `params` is the range the requester chose.
        "export_jobs": [{"requested_by": j.requested_by, "type": j.type,
                         "params": j.params, "status": j.status,
                         "created_at": _iso(j.created_at),
                         "completed_at": _iso(j.completed_at)} for j in jobs],
        # That a billing event happened, not the provider's copy of it. The raw
        # `payload` is withheld and said so in export_scope: it is a third
        # party's record in a shape we do not control and cannot make a claim
        # about, and they are a separate controller you can ask directly.
        "payment_events": [{"provider": p.provider, "type": p.type,
                            "status": p.status, "received_at": _iso(p.received_at),
                            "processed_at": _iso(p.processed_at)} for p in payments],
        "stripe_events": [{"type": s.type, "status": s.status,
                           "received_at": _iso(s.received_at),
                           "processed_at": _iso(s.processed_at)} for s in stripes],
    }
    # ⚠ #269: `org_id` AND `anchor` ARE VERIFIER INPUTS, NOT DECORATION.
    # `org_id` is the FIRST field of the hashed event, so a bundle without it at
    # the top level recomputes every row against `None` and every row fails —
    # the chain would read as tampered when nothing had been touched. `anchor`
    # is the receipt the offline anchor check compares against; without it a
    # bundle that plainly carries anchor rows under `anchors` was told "no
    # anchor receipt in this export". Both are already in this workspace's own
    # data (`organization.id`, the `anchors` section); neither adds a category.
    # ⚠ #271: `page` SITS BESIDE THEM FOR THE SAME REASON — it is a verifier
    # input, not decoration. It names the seq range the `ledger` section holds and
    # the chain hash it continues from, and without it a bundle whose ledger stops
    # at EXPORT_PAGE_MAX rows is a truncated chain with nothing saying so.
    bundle = {"export_scope": _export_scope(bundle, ledger_page),
              "org_id": str(admin.org_id),
              "anchor": _anchor_export(latest_anchor(db, admin.org_id)),
              "page": ledger_page,
              **bundle}
    fname = f"foxy-account-export-{admin.org_id}.json"
    return Response(content=json.dumps(bundle, indent=2, default=str),
                    media_type="application/json",
                    headers={"Content-Disposition": f'attachment; filename="{fname}"'})


# ─────────────── invoice PDF link (P2 · §E) ────────────────────────────────

@router.get("/v1/invoices/{invoice_id}/link")
def invoice_link(
    invoice_id: str,
    admin: User = Depends(require_role("admin")),
    db: Session = Depends(get_db),
):
    """Resolve a Stripe hosted-invoice / PDF URL for one of the org's invoices.
    503 when billing isn't configured; 404 for an unknown invoice."""
    s = get_settings()
    if not s.stripe_secret_key:
        raise HTTPException(status_code=503, detail="billing not configured")
    try:
        iid = uuid.UUID(str(invoice_id))
    except ValueError:
        raise HTTPException(status_code=422, detail="invalid invoice id")
    inv = db.execute(
        select(Invoice).where(Invoice.id == iid, Invoice.org_id == admin.org_id)
    ).scalar_one_or_none()
    if inv is None:
        raise HTTPException(status_code=404, detail="invoice not found")
    try:
        import stripe
        stripe.api_key = s.stripe_secret_key
        obj = stripe.Invoice.retrieve(inv.stripe_invoice_id)
        url = obj.get("hosted_invoice_url") or obj.get("invoice_pdf")
        if not url:
            raise HTTPException(status_code=404, detail="no hosted invoice available")
        return {"url": url}
    except HTTPException:
        raise
    except Exception as exc:                 # noqa: BLE001
        log.warning("invoice link failed: %s", exc)
        raise HTTPException(status_code=502, detail="could not fetch invoice link")


# ─────────────────────────── onboarding checklist (P4) ───────────────────────
class OnboardingUpdate(BaseModel):
    dismissed: bool | None = None
    # P3 §5 · the walkthrough's own state, kept separate from the checklist's
    # `dismissed`. Two fields rather than one status string because they answer
    # different questions: `completed` retires the tutorial for good, `skipped`
    # only defers it — and §5.3 requires a skipped tour to come BACK next login.
    tutorial_completed: bool | None = None
    tutorial_skipped: bool | None = None


def _onboarding_state(user: User, db: Session) -> dict:
    """Compute the checklist live from real data (active key / first logged call / team>1) and merge
    the persisted dismissal. Never fabricated — every step reflects the org's actual data."""
    has_key = db.execute(
        select(func.count()).select_from(ApiKey)
        .where(ApiKey.org_id == user.org_id, ApiKey.status == "active")
    ).scalar_one() > 0
    logged = db.execute(
        select(func.count()).select_from(AuditLog).where(AuditLog.org_id == user.org_id)
    ).scalar_one() > 0
    team = db.execute(
        select(func.count()).select_from(User).where(User.org_id == user.org_id)
    ).scalar_one() > 1
    steps = [
        {"key": "api_key", "done": has_key, "title": "Create an API key",
         "desc": "Mint a key for your app or SDK — shown once.",
         "page": "keys", "label": "Create key"},
        {"key": "first_log", "done": logged, "title": "Log your first AI interaction",
         "desc": "Wrap a call with the @foxy.audit SDK; only hashes leave your machine.",
         "page": "keys", "label": "Get started"},
        {"key": "invite_team", "done": team, "title": "Invite your team",
         "desc": "Add a teammate so they can review the audit trail.",
         "page": "settings", "label": "Invite"},
    ]
    state = user.onboarding_state or {}
    return {
        "steps": steps,
        "done": sum(1 for s in steps if s["done"]),
        "total": len(steps),
        "complete": has_key and logged,          # essentials live → the checklist retires
        "dismissed": bool(state.get("dismissed")),
        # P3 §5 · the walkthrough, ADDITIVE. Every key above is untouched: the
        # desktop console reads this same payload (dashboard.py `_on_onboarding`)
        # and a renamed or dropped key would break a shipped client.
        #
        # `enabled` is the server-side kill switch (§5.5) — the dashboard is a
        # static file and cannot read Settings, so the flag has to reach it on a
        # response it already fetches. `completed` is the per-user, per-account
        # record that survives a new device (§5.6); `skipped` is why a deferred
        # tour is offered again on the next login (§5.3).
        "tutorial": {
            "enabled": bool(get_settings().first_run_tutorial_enabled),
            "completed": bool(state.get("tutorial_completed")),
            "skipped": bool(state.get("tutorial_skipped")),
        },
    }


@router.get("/v1/onboarding")
def get_onboarding(user: User = Depends(require_user), db: Session = Depends(get_db)):
    """The onboarding checklist (live completion + persisted dismissal)."""
    return _onboarding_state(user, db)


@router.put("/v1/onboarding")
def put_onboarding(body: OnboardingUpdate, user: User = Depends(require_user),
                   db: Session = Depends(get_db)):
    """Persist the onboarding state (currently: dismissal). Per-user UI preference."""
    state = dict(user.onboarding_state or {})
    if body.dismissed is not None:
        state["dismissed"] = bool(body.dismissed)
    if body.tutorial_completed is not None:
        state["tutorial_completed"] = bool(body.tutorial_completed)
        # Finishing clears the deferral: a completed tour is not also a pending
        # one, and leaving both set would re-offer it for ever (§5.3).
        if body.tutorial_completed:
            state["tutorial_skipped"] = False
    if body.tutorial_skipped is not None:
        state["tutorial_skipped"] = bool(body.tutorial_skipped)
    user.onboarding_state = state
    resp = _onboarding_state(user, db)   # compute BEFORE commit — require_user's RLS GUC is still set
    db.commit()
    return resp


# ─────────────────────────── export history / jobs (P11) ─────────────────────
# "logs_bundle" is /v1/logs/export?format=bundle — the ledger plus the standalone
# verifier. ExportJob.type is String(32), so it needed no migration.
_EXPORT_TYPES = {"passport", "logs_csv", "logs_json", "logs_bundle"}


class ExportCreate(BaseModel):
    type: str
    params: dict | None = None


def _export_dict(j: ExportJob) -> dict:
    return {
        "id": str(j.id), "type": j.type, "params": j.params or {}, "status": j.status,
        "requested_by": j.requested_by,
        "created_at": j.created_at.isoformat() if j.created_at else None,
        "completed_at": j.completed_at.isoformat() if j.completed_at else None,
    }


@router.post("/v1/exports")
def create_export(body: ExportCreate, user: User = Depends(require_user),
                  db: Session = Depends(get_db)):
    """Record a compliance export in the history/audit trail. The file itself is produced by the
    existing /v1/logs/export or /v1/passport endpoints — the server keeps NO archive, so this is the
    who/what/when record (also mirrored into account_actions)."""
    t = (body.type or "").strip()
    if t not in _EXPORT_TYPES:
        raise HTTPException(status_code=422, detail="unknown export type")
    now = datetime.now(timezone.utc)
    job = ExportJob(id=uuid.uuid4(), org_id=user.org_id, requested_by=user.email, type=t,
                    params=(body.params or {}), status="completed",
                    created_at=now, completed_at=now)
    db.add(job)
    account_audit.record_account_action(
        db, org_id=user.org_id, actor_email=user.email, action="export.create", target=t)
    db.commit()
    return _export_dict(job)


@router.get("/v1/exports")
def list_exports(user: User = Depends(require_user), db: Session = Depends(get_db)):
    """The org's recent export history (newest first)."""
    rows = db.execute(
        select(ExportJob).where(ExportJob.org_id == user.org_id)
        .order_by(ExportJob.created_at.desc()).limit(100)
    ).scalars().all()
    return {"items": [_export_dict(j) for j in rows]}


@router.get("/v1/exports/{export_id}")
def get_export(export_id: str, user: User = Depends(require_user), db: Session = Depends(get_db)):
    try:
        eid = uuid.UUID(export_id)
    except ValueError:
        raise HTTPException(status_code=404, detail="not found")
    j = db.get(ExportJob, eid)          # RLS-scoped by require_user → cross-org rows are invisible
    if j is None or j.org_id != user.org_id:
        raise HTTPException(status_code=404, detail="not found")
    return _export_dict(j)


# ─────────────────────────── profile + preferences (P14) ─────────────────────
class ProfileUpdate(BaseModel):
    full_name: str | None = None


@router.put("/v1/account/profile")
def update_profile(body: ProfileUpdate, user: User = Depends(require_user),
                   db: Session = Depends(get_db)):
    """Set the signed-in user's display name (identity defaults to email; uses the name once set —
    drives the avatar initial + greeting). Audited via account_actions."""
    user.full_name = (body.full_name or "").strip()[:120] or None
    account_audit.record_account_action(
        db, org_id=user.org_id, actor_email=user.email, action="account.profile_update")
    db.commit()
    return {"full_name": user.full_name}


# ───────────────────────────── avatar (P6c) ──────────────────────────────────
# THE FIRST FILE-UPLOAD SURFACE IN THIS BACKEND. Everything below treats the
# request body as hostile, because it is the only endpoint here that accepts
# bytes a user chose rather than fields a schema shaped.
#
# The threat is not "someone uploads a big file". It is that an image upload is
# the classic way to get attacker-controlled bytes written to a server's disk
# and then served back to a browser. Four things stop that, in this order:
#
#   1. A SIZE CAP BEFORE THE READ. Content-Length is checked first because it is
#      free, then the read itself is bounded — a lying or absent header must not
#      be able to pull more than the cap into memory.
#   2. DECODE, DO NOT SNIFF. The filename and the client's Content-Type are both
#      attacker-controlled and neither is consulted. Pillow decoding the bytes is
#      the only thing that establishes this is an image, and `.load()` forces the
#      actual pixel work rather than just parsing a header.
#   3. RE-ENCODE ONTO A FRESH CANVAS. The output is a NEW Image the server drew,
#      not the input with its metadata rewritten. That is what strips EXIF, ICC
#      profiles, PNG text chunks and anything hiding after the image data — a
#      polyglot file that is both a valid PNG and a valid script does not survive
#      being redrawn as pixels.
#   4. THE SERVER NAMES THE FILE. `{user_id}.png` from the session, never from
#      the request. There is no path component the caller can influence, so
#      traversal is not defended against here — it is unreachable.
#
# Rate-limited because decode is CPU work: a 5 MB image is cheap to send and
# expensive to open, which is the shape of an asymmetric DoS.
MAX_AVATAR_BYTES = 5 * 1024 * 1024
AVATAR_PX = 256
# Formats accepted AFTER decoding, by what Pillow says the bytes are.
_AVATAR_FORMATS = {"PNG", "JPEG", "WEBP"}


def _avatar_path_for(user: User) -> pathlib.Path:
    return pathlib.Path(get_settings().avatar_dir) / f"{user.id}.png"


@router.post("/v1/account/avatar")
@limiter.limit("6/minute")
async def upload_avatar(request: Request, file: UploadFile = File(...),
                        user: User = Depends(require_user),
                        db: Session = Depends(get_db)):
    """Replace the signed-in user's avatar. Audited as account.avatar_set."""
    import io as _io

    # 1 · the cap, before anything is read. The header is a claim; the bounded
    # read below is what enforces it.
    declared = request.headers.get("content-length")
    if declared and declared.isdigit() and int(declared) > MAX_AVATAR_BYTES:
        raise HTTPException(status_code=413, detail="image must be 5 MB or smaller")
    raw = await file.read(MAX_AVATAR_BYTES + 1)
    if len(raw) > MAX_AVATAR_BYTES:
        raise HTTPException(status_code=413, detail="image must be 5 MB or smaller")
    if not raw:
        raise HTTPException(status_code=400, detail="no image was uploaded")

    # 2 · decode. Anything Pillow will not open is not an image, whatever it was
    # called or claimed to be. DecompressionBombError is caught by the same
    # blanket except on purpose — a 50000x50000 PNG is a refusal, not a 500.
    try:
        from PIL import Image
    except ImportError:                                    # pragma: no cover
        log.error("Pillow is not installed; avatar upload is unavailable")
        raise HTTPException(status_code=503, detail="image processing unavailable")
    try:
        with Image.open(_io.BytesIO(raw)) as probe:
            fmt = (probe.format or "").upper()
            probe.load()
    except Exception:
        raise HTTPException(status_code=400, detail="that file is not a readable image")
    if fmt not in _AVATAR_FORMATS:
        raise HTTPException(status_code=400,
                            detail="image must be a PNG, JPEG or WebP")

    # 3 · redraw. Centre-crop to a square first so a wide photo is not squashed,
    # then paste onto a canvas this process created. The new image inherits no
    # `info` dict, which is where EXIF, ICC and PNG text chunks would have been.
    try:
        with Image.open(_io.BytesIO(raw)) as src:
            src = src.convert("RGBA")
            w, h = src.size
            side = min(w, h)
            src = src.crop(((w - side) // 2, (h - side) // 2,
                            (w - side) // 2 + side, (h - side) // 2 + side))
            src = src.resize((AVATAR_PX, AVATAR_PX), Image.LANCZOS)
            canvas = Image.new("RGBA", (AVATAR_PX, AVATAR_PX), (0, 0, 0, 0))
            canvas.paste(src, (0, 0), src)
            buf = _io.BytesIO()
            canvas.save(buf, format="PNG", optimize=True)
    except HTTPException:
        raise
    except Exception:
        raise HTTPException(status_code=400, detail="that image could not be processed")

    # 4 · write. The name comes from the session, so there is no caller-supplied
    # path component to sanitise. Written to a temp file and moved into place so
    # a crash mid-write cannot leave a half-PNG where a valid one used to be.
    dest = _avatar_path_for(user)
    try:
        dest.parent.mkdir(parents=True, exist_ok=True)
        tmp = dest.with_suffix(".png.tmp")
        tmp.write_bytes(buf.getvalue())
        tmp.replace(dest)
    except OSError:
        log.exception("could not write avatar for user %s", user.id)
        raise HTTPException(status_code=500, detail="could not save the image")

    user.avatar_path = str(dest)
    user.avatar_updated_at = datetime.now(timezone.utc)
    account_audit.record_account_action(
        db, org_id=user.org_id, actor_email=user.email, action="account.avatar_set")
    db.commit()
    return {"has_avatar": True,
            "avatar_updated_at": user.avatar_updated_at.isoformat()}


@router.delete("/v1/account/avatar")
def delete_avatar(user: User = Depends(require_user), db: Session = Depends(get_db)):
    """Remove the signed-in user's avatar. Audited as account.avatar_clear.

    The columns are cleared even if the unlink fails: the row is what the rest of
    the product reads, so a file left behind by a full disk or a permissions
    change is litter, while a row still claiming a photo is a broken image."""
    dest = _avatar_path_for(user)
    try:
        dest.unlink(missing_ok=True)
    except OSError:
        log.warning("could not unlink avatar for user %s", user.id)
    user.avatar_path = None
    user.avatar_updated_at = None
    account_audit.record_account_action(
        db, org_id=user.org_id, actor_email=user.email, action="account.avatar_clear")
    db.commit()
    return {"has_avatar": False}


@router.get("/v1/account/avatar")
def get_avatar(user: User = Depends(require_user)):
    """The signed-in user's OWN avatar, and only ever their own.

    There is no id parameter — not an ignored one, none at all. The path is
    derived from the session, so "let me see someone else's picture" is not a
    request this endpoint can express. That is deliberate: an avatar is not
    public here, and the cheapest way to never leak one across tenants is to
    give the caller no way to name a different file.

    Cached private + short: long enough that a page with the avatar in the top
    bar and the settings card does not fetch it twice, short enough that a
    removal is not still on screen minutes later. `private` keeps it out of any
    shared proxy — this is one user's photo, not a static asset."""
    dest = _avatar_path_for(user)
    if not user.avatar_path or not dest.is_file():
        raise HTTPException(status_code=404, detail="no avatar set")
    return FileResponse(dest, media_type="image/png",
                        headers={"Cache-Control": "private, max-age=60"})


# Every key here must be READ by something. notify_product_updates and
# notify_security_alerts were removed with their switches (P3 §6): nothing sent
# product updates, and after P3 §3 new-device alerts are deliberately not
# opt-out-able, so a switch offering to silence them would have been a lie.
# test_pref_switches_are_real.py fails if a key without a consumer is added back.
_ALLOWED_PREFS = {"hide_sensitive_metadata",
                  # Settings → Notifications (D-S). Consumed by app/user_notifications.py:
                  # breach alerts + weekly digest default ON (absent = deliver), key-rotation
                  # reminders are opt-in (absent = don't deliver) — matching the UI defaults.
                  "notify_breach_alerts", "notify_weekly_digest", "notify_key_rotation_reminders"}


class PreferencesUpdate(BaseModel):
    preferences: dict


@router.get("/v1/account/preferences")
def get_preferences(user: User = Depends(require_user)):
    return {"preferences": user.preferences or {}}


@router.put("/v1/account/preferences")
def update_preferences(body: PreferencesUpdate, user: User = Depends(require_user),
                       db: Session = Depends(get_db)):
    """Merge the allowed boolean preferences into the user's JSONB bag (unknown keys ignored)."""
    cur = dict(user.preferences or {})
    for k, v in (body.preferences or {}).items():
        if k in _ALLOWED_PREFS:
            cur[k] = bool(v)
    user.preferences = cur
    db.commit()
    return {"preferences": cur}


# ─────────────────────────── notifications center (P16) ──────────────────────
# Rows are GENERATED FROM REAL EVENTS via an idempotent sync-on-read (recent policy breaches, deduped
# by seq) — never fabricated. Bounded to the most recent breaches; new breaches notify on the next read.
_NOTIF_BREACH = (AuditLog.grading_status == "graded") & (
    AuditLog.gemini_verdict["policy_breach"].astext == "true")


def _sync_notifications(db: Session, user: User) -> None:
    """Stage (no commit) notification rows for recent breaches not yet notified. Runs under the
    require_user RLS GUC; the caller commits once so the GUC survives the surrounding read."""
    recent = db.execute(
        select(AuditLog.seq, AuditLog.policy_tag, AuditLog.gemini_verdict, AuditLog.created_at)
        .where(AuditLog.org_id == user.org_id, _NOTIF_BREACH)
        .order_by(AuditLog.seq.desc()).limit(20)
    ).all()
    if not recent:
        return
    seqs = [str(r.seq) for r in recent]
    seen = set(db.execute(
        select(Notification.target_id).where(
            Notification.org_id == user.org_id, Notification.kind == "breach",
            Notification.target_id.in_(seqs))
    ).scalars().all())
    for r in recent:
        tid = str(r.seq)
        if tid in seen:
            continue
        try:
            risk = int((r.gemini_verdict or {}).get("risk_score") or 0)
        except (TypeError, ValueError):
            risk = 0
        level = "critical" if risk >= 70 else ("warning" if risk >= 40 else "info")
        tag = r.policy_tag or "policy"
        db.add(Notification(
            org_id=user.org_id, user_id=None, kind="breach",
            title=f"Policy breach: {tag}",
            body=f"A '{tag}' interaction was flagged (risk {risk}). Review it under Threats.",
            level=level, target_type="ledger", target_id=tid,
            created_at=r.created_at or datetime.now(timezone.utc)))


def _notif_dict(n: Notification) -> dict:
    return {
        "id": str(n.id), "kind": n.kind, "title": n.title, "body": n.body, "level": n.level,
        "target_type": n.target_type, "target_id": n.target_id, "read": n.read_at is not None,
        "created_at": n.created_at.isoformat() if n.created_at else None,
    }


@router.get("/v1/notifications")
def list_notifications(user: User = Depends(require_user), db: Session = Depends(get_db),
                       limit: int = Query(default=30, ge=1, le=100),
                       page: int = Query(default=1, ge=1, description="1-indexed page"),
                       unread_only: bool = False):
    """The org's notifications (newest first), the unread count, and the total.

    `page` mirrors /v1/logs (1-indexed, paired with `limit`) because the
    dashboard's notifications PAGE has to reach the whole history, not just the
    newest `limit`. The top-bar panel keeps calling this with limit=30 and no
    page, which is page 1 — unchanged. `total` is additive; existing callers
    ignore it.

    Without this the page could only ever show the newest 100 rows, since limit
    is capped there, and an audit surface that silently stops at 100 is the same
    defect as one that silently stops at 30."""
    _sync_notifications(db, user)                 # stages rows (no commit)
    db.flush()                                    # autoflush is off — flush so the SELECT sees new rows
    scope = [Notification.org_id == user.org_id]
    if unread_only:
        scope.append(Notification.read_at.is_(None))
    # ONE aggregate for both counts. Two separate COUNTs would make this three
    # round trips where the endpoint used to take two, and every extra
    # statement holds the transaction — and its locks — open a little longer
    # against a test fixture that TRUNCATEs `users` and `organizations`
    # between cases.
    total_all, unread = db.execute(
        select(func.count(Notification.id),
               func.count(Notification.id).filter(Notification.read_at.is_(None)))
        .where(Notification.org_id == user.org_id)
    ).one()
    # when the caller asked for unread only, the filtered total IS the unread
    # count — otherwise the pager renders pages that cannot be reached
    total = int(unread if unread_only else total_all)
    unread = int(unread)
    rows = db.execute(
        select(Notification).where(*scope)
        .order_by(Notification.created_at.desc())
        .offset((page - 1) * limit).limit(limit)
    ).scalars().all()
    db.commit()                                   # persist the synced rows
    return {"unread": unread, "total": total, "items": [_notif_dict(n) for n in rows]}


@router.post("/v1/notifications/{note_id}/read")
def mark_notification_read(note_id: str, user: User = Depends(require_user),
                           db: Session = Depends(get_db)):
    try:
        nid = uuid.UUID(note_id)
    except ValueError:
        raise HTTPException(status_code=404, detail="not found")
    n = db.get(Notification, nid)                 # RLS-scoped → cross-org invisible
    if n is None or n.org_id != user.org_id:
        raise HTTPException(status_code=404, detail="not found")
    if n.read_at is None:
        n.read_at = datetime.now(timezone.utc)
        db.commit()
    return {"status": "ok"}


@router.post("/v1/notifications/read-all")
def mark_all_notifications_read(user: User = Depends(require_user),
                                db: Session = Depends(get_db)):
    n = db.query(Notification).filter(
        Notification.org_id == user.org_id, Notification.read_at.is_(None)
    ).update({Notification.read_at: datetime.now(timezone.utc)}, synchronize_session=False)
    db.commit()
    return {"status": "ok", "read": int(n)}
