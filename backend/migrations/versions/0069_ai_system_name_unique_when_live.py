"""make the AI-system name constraint partial — a retired name is free again

R1b's gate found that the remedy the API's own error message names did not
work. Retirement is terminal (0068, and ``routers/systems.py``), and the 409 a
customer gets when they try to un-retire says:

    "A retired system cannot be returned to service. Declare a new system"

Then declaring it failed:

    retire "mortgage-bot"                  -> 200
    POST /v1/systems name="mortgage-bot"   -> 409 duplicate

``uq_ai_system_org_name`` was a plain UNIQUE (org_id, name) with no predicate,
so the row that had just been taken out of service went on reserving its name
forever. Fixing the router's pre-check alone would have changed nothing — the
CONSTRAINT was the refusal.

⚠ WHY THE NAME IS FREED RATHER THAN THE MESSAGE REWRITTEN
---------------------------------------------------------
The alternative was honest and was considered: keep names globally unique per
org and change the message to say the name is spent. It was rejected because of
what it does to the people using it. One mistaken retirement would burn the
obvious name for that system permanently, and the only escape available today is
to PUT-rename the retired row — which **rewrites a historical declaration** to
work around a present-day constraint. A design whose documented path out of a
terminal state is to falsify the record is the wrong design for an audit
product, and telling customers to do it in an error message would be worse than
the bug.

⚠ WHY TWO ROWS SHARING A NAME IS NOT AMBIGUOUS
----------------------------------------------
Evidence is attributed by ``system_id`` — a UUID — never by name. From R2 an
event names the id it came from, and the id resolves to exactly one declaration
with exactly one lifecycle. So "mortgage-bot (retired)" and "mortgage-bot
(active)" are two distinct declarations that a reader can tell apart by id,
lifecycle_status and created_at, and no query that matters resolves a name to a
system. The name is a label for what is CURRENTLY declared; the predicate says
exactly that.

A consequence worth stating rather than discovering: several retired rows may
share one name, because retiring removes a row from the index and can therefore
never collide. A system declared, retired, re-declared and retired again over
five years leaves five rows with one name and five distinct operating periods.
That is the correct shape for an inventory whose job is to say what was running
when — a list that renamed them ``mortgage-bot-2``, ``-3`` would be inventing
distinctions the customer never declared.

⚠ WHAT THIS DOES NOT LOOSEN
---------------------------
Two LIVE systems still cannot share a name in one org, which is the constraint
that was actually protecting anything. It stays per-org: two customers may each
run a "support-bot" and neither may learn the other does.

No data migration. The predicate can only ever ADMIT rows a total unique index
already permitted, so nothing existing can violate the new index and there is
nothing to backfill or clean up first.
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op

revision = "0069"
down_revision = "0068"
branch_labels = None
depends_on = None

_PREDICATE = "lifecycle_status <> 'retired'"


def upgrade() -> None:
    # The constraint and its index go together — a UNIQUE constraint owns its
    # index, so this cannot be done by dropping the index alone.
    op.drop_constraint("uq_ai_system_org_name", "ai_systems", type_="unique")
    op.create_index("uq_ai_system_org_name_active", "ai_systems", ["org_id", "name"],
                    unique=True, postgresql_where=sa.text(_PREDICATE))


def downgrade() -> None:
    # ⚠ NOT symmetrical, and it can fail — deliberately. Going back to a total
    # constraint is only possible if no org has two rows sharing a name, and
    # after this migration has been live that is a thing customers are entitled
    # to have. A downgrade that silently deleted one of them would destroy a
    # declaration; failing loudly is the honest outcome. Migrations here are
    # forward-only by policy — rollback restores code, not schema.
    op.drop_index("uq_ai_system_org_name_active", table_name="ai_systems")
    op.create_unique_constraint("uq_ai_system_org_name", "ai_systems",
                                ["org_id", "name"])
