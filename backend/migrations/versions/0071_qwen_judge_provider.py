"""org_policies: Qwen as a third judge — its BYOK key and its model pin

Q1. `judge_provider` gained a third vendor and four combination words
(gemini+openai, gemini+qwen, openai+qwen, all). These two columns give Qwen the
same pair every other provider already has: an encrypted tenant key, and an
optional model pin.

BOTH NULLABLE, NO SERVER DEFAULT — the argument in 0058 applies unchanged. NULL
on `qwen_judge_model` means "inherit settings.qwen_model", and Qwen model ids
turn over in days, so writing today's id onto every row would freeze tenants on a
version nobody chose and make the deployment default unmovable.

NO DATA MIGRATION, AND `judge_provider` IS NOT REWRITTEN. Every org that chose
two judges before this migration holds the string "both", which has always meant
gemini+openai. It stays exactly as the customer left it: `judge_routing`
normalises it on read and on write, so a row converts itself the next time
someone saves that policy, and until then it routes the way it always did. A
migration that rewrote the column would be this table recording a choice its
owner never made — on the one table whose job is recording what they did choose.
Two shipped clients (desktop, dashboard) also still SEND "both" until Q4, so the
alias has to survive in the code regardless of what the rows say.

`judge_provider` IS String(16) AND THAT IS LOAD-BEARING, not incidental. The
longest new word is "gemini+openai" at 13 characters; the three-provider value is
spelled "all" precisely because "gemini+openai+qwen" is 18 and would not fit. A
fourth provider needs this column widened, not a longer word. No widening here
because nothing needs it yet.

⚠ `qwen_key_enc` IS A CREDENTIAL COLUMN, AND IT CHANGES A PUBLISHED CLAIM. The
DSAR bundle (routers/account.py) states that every credential this workspace
holds is named in `withheld_fields`. That sentence becomes false the moment this
migration runs unless EXPORT_WITHHELD_FIELDS["policy"] names the column, so the
two are edited in one commit. Fernet ciphertext only — the column is never
serialised by any API, never logged, and never reaches event metadata.

Revision ID: 0071
Revises: 0070
"""

import sqlalchemy as sa
from alembic import op

revision = "0071"
down_revision = "0070"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column("org_policies",
                  sa.Column("qwen_key_enc", sa.Text(), nullable=True))
    op.add_column("org_policies",
                  sa.Column("qwen_judge_model", sa.String(64), nullable=True))


def downgrade() -> None:
    # Dropping `qwen_key_enc` destroys any tenant key stored in it. That is the
    # correct behaviour for a downgrade — the column cannot be read by a schema
    # that does not know Qwen — but it is not recoverable, and re-upgrading gives
    # an empty column, not the keys back.
    op.drop_column("org_policies", "qwen_judge_model")
    op.drop_column("org_policies", "qwen_key_enc")
