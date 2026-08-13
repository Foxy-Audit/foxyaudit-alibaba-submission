"""give the staff audit chain an outside witness — admin_chain_anchors

A1 · registers #143 and #144. 0066 chained ``admin_actions`` so an edited field
or a removed middle row breaks a recompute. It left two limits, and both are
about the absence of an EXTERNAL record rather than about the hashing:

  #143  removing entries from the END leaves nothing behind — seq 1..N-k
        recomputes perfectly, and "only an outside witness who recorded the
        older head would notice".
  #144  deleting EVERY chained row is self-healing: chain_head returns None and
        the next write restarts at seq 1 against GENESIS.

This table is that witness's receipt. ``app/anchor.py`` publishes the staff
chain head to the same public chain it already uses for the customer ledger, and
each row here records what was published and when. The receipt in the database
is a convenience; the thing that makes truncation detectable is the copy on the
external chain, which Foxy cannot rewrite.

⚠ A SEPARATE TABLE, NOT chain_anchors, AND THE REASON IS TENANT ISOLATION
------------------------------------------------------------------------
``chain_anchors.org_id`` is NOT NULL, carries an FK to organizations, and the
table is RLS-scoped by it. The staff chain is platform-wide and has no org. To
reuse that table the column would have to become nullable and every RLS policy
over it would have to define what a NULL org means — which is a change to the
isolation rules of a customer-facing table, made for the benefit of an internal
one. This table has no org_id, no RLS, and matches ``admin_actions``' own
posture: staff data, reached only through the staff session.

⚠ WHAT THE ANCHOR COVERS, RECORDED RATHER THAN ASSUMED
------------------------------------------------------
0066 deliberately left pre-chain rows unhashed. An anchor over "the staff chain"
therefore covers seq ``covers_from_seq``..``last_seq`` and NOTHING BEFORE IT, so
both ends are stored on the receipt: ``covers_from_seq`` (1 today, and a column
rather than a constant so a future re-genesis can say so) and
``unchained_before``, the count of rows that predate the mechanism at the moment
of anchoring. A reader of a receipt can therefore see what it does not witness
without consulting the table it came from.

No backfill, for the same reason 0066 had none: there is nothing to anchor
retrospectively that would mean anything.
"""
import sqlalchemy as sa
from alembic import op

revision = "0067"
down_revision = "0066"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "admin_chain_anchors",
        sa.Column("id", sa.dialects.postgresql.UUID(as_uuid=True),
                  primary_key=True, server_default=sa.text("gen_random_uuid()")),
        sa.Column("root_hash", sa.String(64), nullable=False),
        sa.Column("last_seq", sa.BigInteger(), nullable=False),
        # what the receipt does NOT witness — see the module docstring
        sa.Column("covers_from_seq", sa.BigInteger(), nullable=False, server_default="1"),
        sa.Column("unchained_before", sa.BigInteger(), nullable=False, server_default="0"),
        sa.Column("chain", sa.String(32), nullable=False),
        sa.Column("tx_hash", sa.String(128), nullable=True),
        sa.Column("block_number", sa.BigInteger(), nullable=True),
        sa.Column("status", sa.String(16), nullable=False, server_default="pending"),
        sa.Column("detail", sa.String(500), nullable=True),
        sa.Column("anchored_at", sa.DateTime(timezone=True), nullable=False,
                  server_default=sa.text("now()")),
        sa.Column("confirmed_at", sa.DateTime(timezone=True), nullable=True),
    )
    # The only query shape this table has: "the newest anchor, or the newest
    # confirmed one". One index serves both — status is filtered after the
    # ordering on a table that gains a row per anchor interval, not per action.
    op.create_index("ix_admin_chain_anchors_anchored_at", "admin_chain_anchors",
                    [sa.text("anchored_at DESC")])


def downgrade() -> None:
    op.drop_index("ix_admin_chain_anchors_anchored_at", table_name="admin_chain_anchors")
    op.drop_table("admin_chain_anchors")
