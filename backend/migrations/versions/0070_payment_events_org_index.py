"""payment_events: index (org_id, received_at) like its sibling stripe_events

⚠ WHY THIS EXISTS, AND WHY NOW. `stripe_events` has carried
`ix_stripe_events_org ON (org_id, received_at DESC)` since migration 0014.
`payment_events` — the same shape, the same guarantees, deliberately a separate
table — was created by 0062 with indexes on `provider_event_id` and
`(provider, received_at)` only. The asymmetry was harmless while nothing filtered
that table by org.

#252 made something filter it by org: `GET /v1/account/export` now reads a
workspace's billing-event metadata, and `payment_events` is platform-wide,
unpartitioned and append-only, so without this index every DSAR sequentially
scans every tenant's rows. The route is admin-only but carries no rate limit,
and it is customer-triggerable. Adding the query without the index would be
shipping a defect this phase created; mirroring the sibling's index is the
smallest correct answer.

Not declared in `models.py`: 0014 set the precedent of a migration-only index
for exactly this pair of tables, and matching it keeps the two readable side by
side.

Revision ID: 0070
Revises: 0069
"""
from alembic import op

revision = "0070"
down_revision = "0069"
branch_labels = None
depends_on = None


def upgrade() -> None:
    # Raw SQL for the DESC, exactly as 0014 does for stripe_events.
    op.execute(
        "CREATE INDEX IF NOT EXISTS ix_payment_events_org "
        "ON payment_events (org_id, received_at DESC)"
    )


def downgrade() -> None:
    op.execute("DROP INDEX IF EXISTS ix_payment_events_org")
