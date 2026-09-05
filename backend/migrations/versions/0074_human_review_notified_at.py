"""human_reviews.notified_at — the notice gate stops being an inference

A2 · plan §4.6(e). A1 gated the escalation notice on "did *this* attempt file
the row", which was the right correction at the time and removed a real
accident: while the gate was a bool that was always True, every regrade re-sent
the notice — duplicate spam. What it also removed, unnoticed, was that
duplicate's second job. It was a de-facto RECOVERY. Now every later regrade
conflicts on `uq_human_review_audit_log`, returns no row, and stays silent.

⚠ AND THE NOTICE PATH HAS THREE LOSSY POINTS, none of which requeues:

  * `enqueue_escalation_notice` drops silently on `queue.Full` (bounded at 2000);
  * the queue is IN-PROCESS MEMORY, so a restart before the drain loses it;
  * `drain_breach_notices` swallows a send exception, by design — one bad notice
    must not stop the drain.

A1's docstring said "the attempt that filed it sent the notice". Nothing
enforced that, because nothing recorded it. This column records it: the gate
reads a STORED FACT about the escalation instead of an inference about which
INSERT won a race.

⚠ WHAT IT PROMISES IS "HANDED TO THE SENDER", NOT "DELIVERED", and the name is
kept from the plan rather than widened to imply more. It is stamped after a
successful `put_nowait`, which closes the first lossy point outright — a full
queue now leaves the column NULL, and the next regrade of that row announces it.
The other two are narrowed rather than closed: they are the job of §4.6(a)'s
reconciliation sweep, which can then backfill a missing ROW and a missing NOTICE
through one query, because both are now expressible as NULL.

⚠ EXISTING ROWS ARE LEFT NULL, DELIBERATELY. Backfilling `created_at` would
assert that A1 announced them, which is exactly the thing A1 could not know —
that assumption is the defect. NULL says "no record that a notice went out",
which is true. The only consequence is that a regrade of a pre-0074 escalation
announces it again, and for a row where delivery is genuinely unknown a second
notice is recovery rather than spam. Silence is the failure this column exists
to end, so it is not the safer default here.

Nullable, no default, no index: the gate is always reached through
`audit_log_id`, which is already unique.

Revision ID: 0074
Revises: 0073
"""

import sqlalchemy as sa
from alembic import op

revision = "0074"
down_revision = "0073"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column(
        "human_reviews",
        sa.Column("notified_at", sa.DateTime(timezone=True), nullable=True),
    )


def downgrade() -> None:
    # Dropping this loses only the knowledge of which escalations were
    # announced. The queue rows and the append-only resolution events are
    # untouched; the gate falls back to A1's inference, which is a regression
    # rather than a data loss.
    op.drop_column("human_reviews", "notified_at")
