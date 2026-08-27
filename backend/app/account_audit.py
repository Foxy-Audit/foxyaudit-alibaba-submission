"""Customer-facing account audit trail (P2 · §D).

record_account_action() STAGES an account_actions row in the caller's session so
it commits atomically with the mutation it records — a change without a logged
action (or vice-versa) can't happen. Org-scoped; never records another tenant.
"""

from __future__ import annotations

from sqlalchemy.orm import Session

from .models import AccountAction


def record_account_action(db: Session, *, org_id, actor_email: str | None,
                          action: str, target: str | None = None,
                          detail: dict | None = None) -> None:
    """Stage one `account_actions` row.

    ⚠ A NEW `action` STRING IS A TWO-DIRECTORY CHANGE. Every action recorded
    here is rendered to the customer BY NAME, and the map that names it lives
    outside this package: `desktop/settings_admin.py` → `AUDIT_LABELS`. Add the
    label in the same commit.

    `desktop/test_d11b_settings_admin.py::test_every_recorded_action_has_a_label`
    greps this package for the `action=` literals and fails without it — so an
    action added alone turns `main` red in a suite a backend-only gate never
    runs. That is register #255, and this pointer is the whole of what would
    have prevented it: nothing on this side warned that the string had a second
    home. It is a reminder and NOT a second guard, deliberately — the guard
    already exists and works; what was missing was knowing to look.

    (This docstring cannot spell the grep's pattern out in full: the regex
    accepts dots, so a literal example written here would register itself as an
    unlabelled action and fail the very test it is describing.)
    """
    db.add(AccountAction(
        org_id=org_id, actor_email=actor_email, action=action,
        target=(target[:255] if target else None), detail=detail,
    ))
