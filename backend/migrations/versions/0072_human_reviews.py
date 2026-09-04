"""human_reviews: the destination for a verdict the judge declined to decide

A1. Q2a gave the agentic judge a tool (`flag_for_human_review`) and a verdict
vocabulary to return through (`decision="human_review"`). Nothing received it:
there was no table, no endpoint and no notification — `worker.py`'s only
post-commit branch gates on `verdict.policy_breach`, which is `False` BY DESIGN
on an escalation. A determination the model made deliberately was recorded on the
ledger row and then acted on by nobody.

⚠ THIS TABLE IS THE QUEUE, NOT THE EVIDENCE. Those are two different jobs and
this schema deliberately does only the first:

  * the QUEUE needs a MUTABLE `status`, because "what is still pending" has to be
    one indexed lookup and an append-only log cannot answer it cheaply;
  * the EVIDENCE of a human's decision is an append-only
    `audit_events(event_type='human_review_resolved')` row, written by
    `POST /v1/reviews/{id}/resolve` in the same transaction as the status change.

Neither of them touches `audit_logs`. `chain.verdict_hash_hex` binds the LOCAL,
SDK-side verdict decided at ingest, which is the only reason the worker may write
an AI grade after the row is chained; a human decision arriving later still has to
respect the same boundary or every block after it stops verifying and
`verifier/foxy_verify.py` reports an honest ledger as TAMPERED.

⚠ `audit_log_id` IS UNIQUE, AND THAT IS LOAD-BEARING RATHER THAN TIDY.
`worker._grade_one` is RE-ENTERED for the same row after `_handle_failure` puts it
back to 'pending' — a timeout, a dropped connection, a restart mid-batch. Without
this constraint the reviewer's queue would grow one duplicate entry per retry, all
of them pointing at a single event, and the worker's insert could not be written
as the `ON CONFLICT DO NOTHING` that makes it idempotent.

`reason` and `risk_score` are carried from the tool call EXACTLY as
`qwen_judge._escalation` produced them — truncated to 300 characters and clamped
to 0-100 at `qwen_judge.py:203`. Not re-clamped here and not widened: two places
bounding one value is two places that can disagree about it.

`note` is the one free-text field a HUMAN writes, and it is annotation rather than
evidence. A reviewer can type anything into it, raw prompt content included, so it
is capped, it is never folded into any hash, and it is excluded from the evidence
payload of the `human_review_resolved` event and from the Compliance Passport. The
machine-readable outcome is `resolution`; the note is a human aid beside it.

Revision ID: 0072
Revises: 0071
"""

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects.postgresql import UUID

revision = "0072"
down_revision = "0071"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "human_reviews",
        sa.Column("id", UUID(as_uuid=True), primary_key=True),
        sa.Column("org_id", UUID(as_uuid=True),
                  sa.ForeignKey("organizations.id", ondelete="CASCADE"),
                  nullable=False),
        sa.Column("audit_log_id", UUID(as_uuid=True),
                  sa.ForeignKey("audit_logs.id", ondelete="CASCADE"),
                  nullable=False),
        sa.Column("status", sa.String(length=16), nullable=False,
                  server_default="pending"),
        sa.Column("resolution", sa.String(length=32), nullable=True),
        sa.Column("reason", sa.String(length=300), nullable=False),
        sa.Column("risk_score", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("note", sa.String(length=2000), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False,
                  server_default=sa.text("now()")),
        sa.Column("resolved_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("resolved_by", sa.String(length=320), nullable=True),
        sa.UniqueConstraint("audit_log_id", name="uq_human_review_audit_log"),
    )
    op.create_index("ix_human_reviews_org_id", "human_reviews", ["org_id"])
    # The queue's own query: one workspace's pending reviews, oldest first.
    op.create_index("ix_human_reviews_org_status_created", "human_reviews",
                    ["org_id", "status", "created_at"])

    # Posture A, exactly as `audit_events` (0035) — org-scoped rows behind the
    # `app.current_org` GUC both directions. FORCE so the table owner is subject
    # to it too; the grading worker connects as a BYPASSRLS role and additionally
    # sets the GUC itself before writing, so the two agree rather than one of
    # them being load-bearing alone.
    op.execute("ALTER TABLE human_reviews ENABLE ROW LEVEL SECURITY")
    op.execute("ALTER TABLE human_reviews FORCE ROW LEVEL SECURITY")
    op.execute("""
        CREATE POLICY human_review_isolation ON human_reviews
        USING (org_id = current_setting('app.current_org', true)::uuid)
        WITH CHECK (org_id = current_setting('app.current_org', true)::uuid)
    """)


def downgrade() -> None:
    # Dropping this destroys the queue, and with it every human resolution's
    # MUTABLE record. The evidence does not go with it: each resolution was also
    # appended to `audit_events` as `human_review_resolved`, which this migration
    # never created and therefore must not remove.
    op.execute("DROP TABLE IF EXISTS human_reviews")
