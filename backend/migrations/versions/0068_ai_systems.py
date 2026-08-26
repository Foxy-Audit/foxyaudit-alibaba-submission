"""the customer's declared AI inventory — ai_systems

R1 of the AI-system registry. Foxy has always been able to prove that an
interaction happened and was not tampered with; it has never been able to say
WHICH of a customer's AI products produced it. A bank running a mortgage
chatbot, a fraud screener and an internal helpdesk gets one undifferentiated
pile of evidence and cannot answer "show me everything the mortgage bot did",
which is the first question an auditor asks. This table is the inventory those
answers will be grouped by; binding an event to a row here is R2 and R3 and is
deliberately NOT part of this migration.

⚠ DECLARED, NEVER INFERRED
--------------------------
Nothing in this system derives a row here from traffic. The only writer is a
dashboard admin registering a system they operate. That is a product decision,
not a scheduling one: an inventory Foxy guessed from the events it happened to
receive would be Foxy's opinion about a customer's AI estate, and this product's
whole claim is that it does not invent what it reports. A guessed inventory is
also silently incomplete — a system that has not sent an event yet does not
exist to it — which is precisely the system an auditor asks about.

⚠ RETIRE, DO NOT DELETE — AND THAT IS WHY THERE IS NO DELETE ANYWHERE
---------------------------------------------------------------------
``lifecycle_status`` carries 'retired', and once R2 lands a retired system will
accept no new events while keeping every historical one. There is no DELETE
endpoint in ``routers/systems.py`` and none should be added: evidence rows in
the hash chain will reference these ids, and a hash chain cannot be edited to
forget a row it already committed to. Deleting a system would leave chained
evidence pointing at nothing — evidence whose subject the vendor removed is a
worse answer to an auditor than evidence about a system that no longer runs.

The columns are the reason this is a product feature rather than a foreign key:
name, owner_email, purpose, provider, model_name, environment,
data_classification, risk_tier, lifecycle_status. That vocabulary is the shape
EU AI Act paperwork asks for. Nothing here can hold prompt or response content;
content-blindness is a schema property, not only an API one.

⚠ RLS POSTURE A — ENABLE + FORCE + org_isolation, CHOSEN DELIBERATELY
---------------------------------------------------------------------
``Database/CLAUDE.md`` documents three postures and warns that copying whichever
table you happened to open is how the wrong one spreads. This one is A, matching
``account_actions``, ``chain_anchors``, ``notifications`` and the other ten:

* ``org_id`` is NOT NULL with an FK to organizations, so the policy predicate
  can always be evaluated. That is exactly what rules posture A out for
  ``payment_events`` / ``stripe_events`` / ``traffic_events``, where a NULL
  org_id can never match a predicate and RLS would hide the rows staff need.
* Every reader and writer authenticates through ``resolve_org`` or
  ``require_role('admin')``, and BOTH call ``auth._scope_org`` before the first
  query — so ``app.current_org`` is always set on the paths that touch this
  table. That is what rules out posture C's ``organizations`` / ``users`` /
  ``api_keys`` exception, where the row must be read to establish the scope in
  the first place. Nothing here is read before the scope exists.
* It is tenant data, not platform data, so posture B (FORCE with no policy,
  which denies the confined role outright) would deny the only role that ever
  reads it.

The explicit ``WHERE org_id = …`` in ``routers/systems.py`` stays regardless.
The app connects as a superuser that BYPASSES FORCE RLS and only drops to the
confined ``foxy_app`` role inside ``_scope_org``; the filter is the load-bearing
isolation and the policy is the second layer that catches a future query which
forgets it.

⚠ UNIQUE PER ORG, NOT GLOBALLY
------------------------------
``uq_ai_system_org_name`` is ``(org_id, name)``. Two customers may each run a
system called "support-bot" and neither may see that the other does — a global
unique constraint would be a cross-tenant existence oracle reported as a 409.

⚠ created_by IS ON DELETE SET NULL, NOT CASCADE
-----------------------------------------------
The systems outlive the person who registered them. Offboarding the admin who
declared the mortgage bot must not delete the mortgage bot from the inventory —
and, once R2 lands, must not orphan the evidence attributed to it. ``org_id``
is CASCADE for the opposite reason: deleting the workspace deletes its
inventory, because there is no tenant left to own it.

The CHECK constraints duplicate the router's ``Literal`` enums on purpose. The
API is not the only writer a table gets over its life, and a value the chain
later groups by is worth constraining where it is stored.

No backfill and nothing to backfill: every organisation starts with an empty
inventory, and an empty inventory is the honest answer for a customer who has
not declared anything yet.
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects.postgresql import UUID

revision = "0068"
down_revision = "0067"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "ai_systems",
        sa.Column("id", UUID(as_uuid=True), primary_key=True,
                  server_default=sa.text("gen_random_uuid()")),
        sa.Column("org_id", UUID(as_uuid=True),
                  sa.ForeignKey("organizations.id", ondelete="CASCADE"), nullable=False),
        sa.Column("name", sa.String(length=120), nullable=False),
        sa.Column("owner_email", sa.String(length=320), nullable=False),
        sa.Column("purpose", sa.String(length=256), nullable=False),
        sa.Column("provider", sa.String(length=64), nullable=False, server_default="other"),
        sa.Column("model_name", sa.String(length=128), nullable=True),
        sa.Column("environment", sa.String(length=16), nullable=False,
                  server_default="production"),
        sa.Column("data_classification", sa.String(length=16), nullable=False,
                  server_default="internal"),
        sa.Column("risk_tier", sa.String(length=16), nullable=False, server_default="medium"),
        sa.Column("lifecycle_status", sa.String(length=16), nullable=False,
                  server_default="active"),
        # SET NULL, never CASCADE — see the module docstring.
        sa.Column("created_by", UUID(as_uuid=True),
                  sa.ForeignKey("users.id", ondelete="SET NULL"), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False,
                  server_default=sa.text("now()")),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False,
                  server_default=sa.text("now()")),
        sa.UniqueConstraint("org_id", "name", name="uq_ai_system_org_name"),
        sa.CheckConstraint(
            "provider IN ('openai', 'azure_openai', 'anthropic', 'google', "
            "'aws_bedrock', 'self_hosted', 'other')", name="ck_ai_system_provider"),
        sa.CheckConstraint(
            "environment IN ('development', 'staging', 'production')",
            name="ck_ai_system_environment"),
        sa.CheckConstraint(
            "data_classification IN ('public', 'internal', 'confidential', 'regulated')",
            name="ck_ai_system_data_classification"),
        sa.CheckConstraint(
            "risk_tier IN ('low', 'medium', 'high', 'critical')",
            name="ck_ai_system_risk_tier"),
        sa.CheckConstraint(
            "lifecycle_status IN ('draft', 'active', 'retired')",
            name="ck_ai_system_lifecycle_status"),
    )
    # The only query shape this table has: "this org's systems, by name". The
    # unique constraint's index is (org_id, name) and already serves it, but the
    # single-column index is what a future join on org_id alone will use.
    op.create_index("ix_ai_systems_org", "ai_systems", ["org_id"])
    op.execute("ALTER TABLE ai_systems ENABLE ROW LEVEL SECURITY;")
    op.execute("ALTER TABLE ai_systems FORCE ROW LEVEL SECURITY;")
    op.execute(
        """
        CREATE POLICY org_isolation ON ai_systems
            USING      (org_id = current_setting('app.current_org', true)::uuid)
            WITH CHECK (org_id = current_setting('app.current_org', true)::uuid);
        """
    )


def downgrade() -> None:
    op.execute("DROP TABLE IF EXISTS ai_systems")
