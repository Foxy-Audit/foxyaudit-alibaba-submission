"""org_policies: add qwen judge provider columns (key + model pin)

Revision ID: 0071
Revises: 0070
Create Date: 2026-09-04

Two new nullable columns on org_policies so an org can configure Qwen as a
judge provider — exactly the same shape as the existing gemini_*/openai_*
pairs:

  qwen_key_enc   — Fernet ciphertext of a tenant's own (BYOK) Qwen API key,
                    or NULL for platform-key orgs and orgs that don't use Qwen.
  qwen_judge_model — which Qwen model grades this org (e.g. "qwen-plus").
                    NULL = inherit the deployment default from settings.

No data migration — every org starts with NULL in both columns and behaves as
if Qwen is not configured. Adding a provider is purely additive and does not
affect existing routing decisions.
"""
from alembic import op
import sqlalchemy as sa

revision = "0071"
down_revision = "0070"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column("org_policies",
        sa.Column("qwen_key_enc", sa.Text(), nullable=True,
                  comment="Fernet ciphertext of a BYOK Qwen API key"))
    op.add_column("org_policies",
        sa.Column("qwen_judge_model", sa.String(64), nullable=True,
                  comment="Qwen model id for grading this org; NULL = deployment default"))


def downgrade() -> None:
    op.drop_column("org_policies", "qwen_judge_model")
    op.drop_column("org_policies", "qwen_key_enc")
