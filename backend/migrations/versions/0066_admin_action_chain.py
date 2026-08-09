"""hash-chain the staff audit trail — admin_actions.seq / prev_hash / chain_hash

G5 · register #79. Foxy sells tamper-evidence and its own operations log had
none. From here on every staff action is chained to the one before it, so an
edited field or a removed middle row breaks a recompute at a nameable entry.
app/admin_chain.py is the single implementation, writer and verifier.

⚠ THERE IS NO BACKFILL, AND THAT IS THE POINT
---------------------------------------------
Existing rows cannot be given hashes that mean anything. Walking them in
created_at order and chaining them would produce a column that LOOKS exactly
like evidence and proves only that this migration ran — a fabrication, and this
project's first hard rule forbids those. The three columns are nullable and stay
NULL on every pre-existing row. Those rows are still real audit rows; they are
simply older than the mechanism, and every surface reports them that way
("N earlier entries predate the chain") rather than hiding them or marking them
suspicious.

So the chain starts HERE, at the first action recorded after this runs, and its
start date is derived from the data — the created_at of seq 1 — rather than
stamped by this migration into a table nobody would ever re-derive.

WHY UNIQUE ON seq
-----------------
The writer serialises on a platform-wide advisory lock, so two concurrent staff
actions cannot both choose the same seq. The unique constraint is the second
line: it makes a fork impossible even for a writer that bypasses the helper,
turning a silent duplicate into a loud IntegrityError. Postgres unique indexes
permit many NULLs, so the pre-chain rows are unaffected by it.

A CONSTRAINT rather than a bare unique index, so it matches `unique=True` on the
model and `alembic revision --autogenerate` has nothing to propose. Its backing
b-tree is what serves the writer's tail read — measured at 4 shared buffers and
0.06ms over 5,000 rows, flat, an Index Scan Backward with no separate index to
maintain.
"""
import sqlalchemy as sa
from alembic import op

revision = "0066"
down_revision = "0065"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column("admin_actions", sa.Column("seq", sa.BigInteger(), nullable=True))
    op.add_column("admin_actions", sa.Column("prev_hash", sa.String(64), nullable=True))
    op.add_column("admin_actions", sa.Column("chain_hash", sa.String(64), nullable=True))
    op.create_unique_constraint("uq_admin_actions_seq", "admin_actions", ["seq"])


def downgrade() -> None:
    """Drops the chain columns. The audit rows themselves are untouched — a
    downgrade loses the ability to verify, not the trail."""
    op.drop_constraint("uq_admin_actions_seq", "admin_actions", type_="unique")
    op.drop_column("admin_actions", "chain_hash")
    op.drop_column("admin_actions", "prev_hash")
    op.drop_column("admin_actions", "seq")
