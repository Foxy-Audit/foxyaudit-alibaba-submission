"""Org-level notices — queued by grading, sent from their own thread.

This is the notice a tenant configures in their policy
(``org_policies.notify_on_breach == "immediate"``): one email to the org's
notification address, plus an optional webhook POST.

It is a different thing
from the per-user alerts in ``user_notifications`` — that fan-out is driven by
each member's own preference bag, this one by the org's policy — and the two are
deduped against each other so no address receives the same breach twice.

**Two kinds travel this way**, dispatched on the queued item's ``kind``: a graded
BREACH, which is what this module was built for, and since A1 an ESCALATION — a
verdict the agentic judge declined to reach, asking for a person instead. They
share the queue, the drain and the thread because the delivery problem is
identical; they share nothing else, and ``send_escalation_notice`` is careful
never to announce an escalation as a finding. An item with no ``kind`` is a
breach, so notices already in flight across the A1 deploy keep their meaning.

**Why it moved out of the grading batch.** It used to be sent inline in
``worker._grade_one``: a synchronous ``send_email`` plus a 5-second webhook POST,
inside the loop that also drives the worker's liveness heartbeat. A mail
provider that accepts the connection and then hangs would stall the batch, and a
stalled batch stops the heartbeat and eventually trips ``/health/ready`` — a mail
outage taking the readiness probe down with it. Grading now only queues plain
values, exactly as the per-user path already did, and this module's thread does
the network work with no DB transaction held open across it.

Content-blind, like everything else here: seq, risk score and a truncated
reason — never prompt or response text.

Scope note, because the original version of this docstring overstated it: this
module decoupled the EMAIL. Outbound webhook subscriptions kept POSTing inline
from the grading batch until `webhook_delivery` was given the same treatment —
and since those fire on every graded row rather than only on breaches, they
were the larger heartbeat risk of the two.
"""

from __future__ import annotations

import logging
import queue
import threading
import time
import uuid

import requests
from sqlalchemy.orm import Session

from . import email as email_mod, email_templates as et
from .models import Organization, OrgPolicy

log = logging.getLogger("foxy.org_notify")

#: Bounded on purpose. If the sender is down and the queue fills, dropping the
#: oldest notices is better than growing without limit inside the worker — the
#: breach itself is already durably recorded in the ledger, which is the part
#: that must never be lost.
_QUEUE_MAX = 2000
_NOTICE_QUEUE: "queue.Queue[dict]" = queue.Queue(maxsize=_QUEUE_MAX)

WEBHOOK_TIMEOUT = 5


# ── enforcement_mode: the response to a breach the judge already found ──────
# P5 §A.2. ``org_policies.enforcement_mode`` (block|flag|monitor) modulates
# DELIVERY to humans and nothing else. It never touches the verdict, the
# AuditEvent or the chain entry — the judge does not see this field at all
# (``policy_snapshot.judge_policy_config`` drops it on its projection line).
#
#   monitor   no breach email, whatever notify_on_breach says
#   flag      today's behaviour — email only on notify_on_breach == "immediate"
#   block     "digest" is escalated to immediate as well; "none" still means none
#
# ``digest`` is the value that escalates because it sends NOTHING today: both
# breach senders gate on ``!= "immediate"``, and ``send_weekly_digests`` runs off
# the per-user ``notify_weekly_digest`` preference rather than this field, so
# ``digest`` is behaviourally identical to ``none``. ``none`` is an explicit off
# switch and is never bypassed — an escalation that overrides an off switch is a
# dark pattern, not a feature.
#
# Both senders live off these two functions rather than open-coding the rule, so
# the org-level path and the per-seat fan-out cannot drift apart;
# ``user_notifications.send_breach_alert`` imports the second one.

def breach_notice_wanted(enforcement_mode: str | None,
                         notify_on_breach: str | None) -> bool:
    """Has this tenant asked to be told about a graded breach at all?

    Separate from :func:`breach_email_allowed` because it also gates the org's
    own ``notify_webhook_url`` POST, and ``monitor`` silences people, never
    machines: a webhook is an integration contract, and one that stops firing is
    an outage rather than a quieter inbox.
    """
    return (notify_on_breach == "immediate"
            or (enforcement_mode == "block" and notify_on_breach == "digest"))


def breach_email_allowed(enforcement_mode: str | None,
                         notify_on_breach: str | None) -> bool:
    """…and may we EMAIL them about it?

    ``monitor`` means "do not email me", not "do not look". The verdict, the
    ``AuditEvent``, the chain entry and the in-app breach notification
    (``routers/account.py`` backfills it from the ledger) are all written
    regardless, so a suppressed email costs the tenant no evidence.
    """
    return (breach_notice_wanted(enforcement_mode, notify_on_breach)
            and enforcement_mode != "monitor")


def enqueue_breach_notice(row, verdict) -> None:
    """Called from worker._grade_one. Copies plain values off the grading row —
    nothing ORM- or session-bound crosses the thread boundary — never blocks and
    never raises into grading."""
    try:
        _NOTICE_QUEUE.put_nowait({
            "org_id": str(row["org_id"]),
            "seq": row.get("seq"),
            "risk": verdict.risk_score,
            "reason": (verdict.reason or "")[:200],
        })
    except queue.Full:
        log.warning("org breach-notice queue full — dropping notice for org %s "
                    "seq %s", row.get("org_id"), row.get("seq"))
    except Exception as exc:                # noqa: BLE001 — never break grading
        log.warning("could not queue org breach notice: %s", exc)


def enqueue_escalation_notice(row, verdict) -> None:
    """A1 · the same contract as :func:`enqueue_breach_notice`, for an escalation.

    ⚠ THIS IS THE HALF OF A1 THAT MAKES THE QUEUE ARRIVE. A `human_reviews` row
    nobody is told about is a worklist nobody opens, which is the defect A1 exists
    to close wearing a different hat — and until the A2 reviewer page ships, this
    email is the ONLY way an escalation reaches a person at all.

    Rides the same queue and the same drain thread as the breach notice rather
    than growing a second one: the delivery problem is identical, and a second
    thread would be a second thing that can stall the worker heartbeat. `kind`
    is what `drain_breach_notices` dispatches on; an item without it is a breach,
    so every notice already in flight when this deploys is unaffected.
    """
    try:
        _NOTICE_QUEUE.put_nowait({
            "kind": "human_review",
            "org_id": str(row["org_id"]),
            "seq": row.get("seq"),
            "risk": verdict.risk_score,
            "reason": (verdict.reason or "")[:200],
        })
    except queue.Full:
        log.warning("org notice queue full — dropping escalation notice for org "
                    "%s seq %s", row.get("org_id"), row.get("seq"))
    except Exception as exc:                # noqa: BLE001 — never break grading
        log.warning("could not queue escalation notice: %s", exc)


def send_escalation_notice(db: Session, item: dict) -> bool:
    """Tell a tenant a review is waiting. Returns True if an email went out.

    ⚠ IT IS NOT A BREACH AND MUST NOT READ AS ONE. The judge did not find a
    violation — it declined to decide and asked for a person, `policy_breach` is
    False, and `passport.compliant_events` subtracts the two separately. So the
    subject, the tone and the webhook `type` all say escalation; nothing here
    calls it a finding.

    ⚠ AND IT REUSES THE TENANT'S EXISTING PREFERENCE RATHER THAN INVENTING ONE.
    `org_policies` has no "notify me about escalations" column and A1 does not add
    a fifth policy field, a migration for it and two clients' worth of UI in a
    backend-only phase. A tenant who asked to hear about graded outcomes
    immediately hears about this one; `monitor` still suppresses the email and
    still fires the webhook; `none` still means none, because an escalation that
    overrides an off switch is a dark pattern exactly as a breach would be.
    A dedicated preference is recorded as an A1 follow-up in the plan.
    """
    oid = uuid.UUID(str(item["org_id"]))
    policy = db.get(OrgPolicy, oid)
    if policy is None:
        return False
    mode, wants = policy.enforcement_mode, policy.notify_on_breach
    if not breach_notice_wanted(mode, wants):
        return False

    seq, risk, reason = item.get("seq"), item.get("risk"), item.get("reason") or ""
    org = db.get(Organization, oid)
    sent = False
    to = policy.notify_email or (org.contact_email if org else None)
    if to and breach_email_allowed(mode, wants):
        html, plain = et.layout(
            title="A review is waiting",
            preheader=f"The AI judge asked for a human decision on record #{seq} "
                      f"(risk {risk}).",
            blocks=[
                et.paragraph(
                    f"The AI judge did not reach a verdict on record #{seq} and "
                    f"asked for a person to decide (risk {risk}). This is not a "
                    f"breach — it is a determination the model declined to make."),
                et.callout(reason, tone="warn"),
                et.muted("Open your dashboard to resolve it. Only hashes are "
                         "stored — never the prompt or response."),
            ],
            surface="customer",
        )
        email_mod.send_email(
            to=to, subject="\U0001f7e3 A review is waiting — Foxy Audit",
            html=html, text=plain)
        sent = True

    if policy.notify_webhook_url:
        try:
            requests.post(policy.notify_webhook_url, json={
                # NOT "policy_breach". An integration that routes on this string
                # must be able to tell a finding from a request to look at one.
                "type": "human_review", "seq": seq, "risk_score": risk,
                "reason": reason, "org_id": str(oid)}, timeout=WEBHOOK_TIMEOUT)
        except Exception:                   # noqa: BLE001 — webhook is best-effort
            log.warning("escalation webhook POST failed for org %s", oid)
    return sent


def send_breach_notice(db: Session, item: dict) -> bool:
    """Send one queued notice. Returns True if an email went out.

    The org's policy is re-read here rather than captured at enqueue time: a
    tenant who turns breach notices off between the grade and the send should
    not receive one. ``enforcement_mode`` is read off the same row, for the same
    reason and at no extra cost — delivery follows the tenant's CURRENT setting,
    never one frozen into an evidence snapshot months ago (P5 §A.2)."""
    oid = uuid.UUID(str(item["org_id"]))
    policy = db.get(OrgPolicy, oid)
    if policy is None:
        return False
    mode, wants = policy.enforcement_mode, policy.notify_on_breach
    if not breach_notice_wanted(mode, wants):
        return False

    seq, risk, reason = item.get("seq"), item.get("risk"), item.get("reason") or ""
    org = db.get(Organization, oid)
    sent = False
    to = policy.notify_email or (org.contact_email if org else None)
    # Split from the webhook POST below rather than widened into a single early
    # return: under `monitor` the EMAIL is suppressed and that POST still fires.
    if to and breach_email_allowed(mode, wants):
        html, plain = et.layout(
            title="Policy breach flagged",
            preheader=f"A policy breach was flagged in your audit trail (record #{seq}, risk {risk}).",
            blocks=[
                et.paragraph(f"A policy breach was flagged in your audit trail "
                             f"(record #{seq}, risk {risk})."),
                et.callout(reason, tone="bad"),
                et.muted("Open your dashboard ledger to review. Only hashes are stored — "
                         "never the prompt or response."),
            ],
            surface="customer",
        )
        email_mod.send_email(
            to=to, subject="\U0001f534 Policy breach flagged — Foxy Audit",
            html=html, text=plain)
        sent = True

    if policy.notify_webhook_url:
        try:
            requests.post(policy.notify_webhook_url, json={
                "type": "policy_breach", "seq": seq, "risk_score": risk,
                "reason": reason, "org_id": str(oid)}, timeout=WEBHOOK_TIMEOUT)
        except Exception:                   # noqa: BLE001 — webhook is best-effort
            log.warning("breach webhook POST failed for org %s", oid)
    return sent


def drain_breach_notices(db: Session, *, limit: int = 200) -> int:
    """Send every queued notice (up to `limit`). Returns emails sent.

    Named for the only kind it used to carry. It now also drains A1's escalation
    notices, dispatched on `kind` — an item without one is a breach, so nothing
    already queued changes meaning.
    """
    sent = 0
    for _ in range(limit):
        try:
            item = _NOTICE_QUEUE.get_nowait()
        except queue.Empty:
            break
        send = (send_escalation_notice if item.get("kind") == "human_review"
                else send_breach_notice)
        try:
            sent += 1 if send(db, item) else 0
        except Exception as exc:            # noqa: BLE001 — one notice must not stop the drain
            db.rollback()
            log.warning("org notice (%s) failed for org %s: %s",
                        item.get("kind", "breach"), item.get("org_id"), exc)
    return sent


def org_notifications_loop(stopping: dict, s) -> None:
    """Own thread + session, mirroring usage.usage_loop.

    Deliberately NOT gated on ``user_notifications_enabled``: that switch turns
    off the per-user preference fan-out, and using it to also silence a tenant's
    configured policy notice would disable a paid feature by accident.
    """
    from .db import SessionLocal
    log.info("Org breach notices ON (drain=%ss)", s.breach_alert_drain_interval)
    while not stopping["flag"]:
        db = SessionLocal()
        try:
            drain_breach_notices(db)
        except Exception as exc:            # noqa: BLE001 — a bad pass must not kill the thread
            log.warning("org notifications loop error: %s", exc)
        finally:
            db.close()
        waited = 0.0
        while waited < s.breach_alert_drain_interval and not stopping["flag"]:
            time.sleep(min(1.0, s.breach_alert_drain_interval - waited))
            waited += 1.0


def queue_depth() -> int:
    """For tests and the admin health surface."""
    return _NOTICE_QUEUE.qsize()
