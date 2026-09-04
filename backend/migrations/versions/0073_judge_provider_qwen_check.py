"""org_policies: the judge_provider CHECK never learned Qwen — five words 500'd

⚠ THIS IS A SHIPPED DEFECT, NOT PREPARATION FOR A1. Found by the first
integration test that ever tried to route an org to Qwen, which is the first one
that could: `judge_helpers.give_judge_key` had no `qwen_key` parameter until this
branch, so every existing Qwen test asserts against an AST parse of `worker.py`
rather than against a database.

Q1 opened `judge_provider` to five new words — `qwen`, `gemini+qwen`,
`openai+qwen`, `gemini+openai` and `all` — in `judge_routing.PROVIDERS`, in the
`Literal` on `routers/policies.py:76`, in `worker._judge_verdict`'s dispatch, and
0071 gave the provider its key and model columns. It did not touch the CHECK
constraint 0053 wrote, which still read:

    judge_provider IN ('gemini', 'openai', 'both')

So the API validated a customer's choice, accepted it, and the INSERT was refused
by Postgres. A tenant selecting Qwen in the dashboard got a 500 out of
`PUT /v1/policies`, and NO org could be routed to Qwen anywhere — the Q1-Q4 judge
was unreachable in production, not merely untested. The gap survived four phases
because no test between the API and the database existed on that path.

Widened rather than dropped. The constraint is the last thing standing between a
typo in a shipped client and a routing word `worker._judge_verdict` has no branch
for, and the worker's `if not verdicts:` guard exists precisely because such a
word can be STORED. Both are kept: this one stops the words nobody defined, that
one survives the ones that get in anyway.

`both` stays in the list permanently. It is the pre-Q1 alias for gemini+openai,
resolved at grading time by `judge_routing.normalise_provider` and never
rewritten — 0071 says why at length. Dropping it here would invalidate every row
a two-judge customer wrote before Q1.

Revision ID: 0073
Revises: 0072
"""

from alembic import op

revision = "0073"
down_revision = "0072"
branch_labels = None
depends_on = None

#: The full vocabulary, matching `judge_routing.PROVIDERS` plus the `both` alias.
#: Kept as one string so the upgrade and the downgrade cannot drift into two
#: different ideas of what the constraint said.
_PROVIDERS = (
    "'gemini', 'openai', 'qwen', "
    "'gemini+openai', 'gemini+qwen', 'openai+qwen', 'all', "
    "'both'"
)


def upgrade() -> None:
    op.drop_constraint("ck_org_policies_judge_provider", "org_policies",
                       type_="check")
    op.create_check_constraint(
        "ck_org_policies_judge_provider", "org_policies",
        f"judge_provider IN ({_PROVIDERS})")


def downgrade() -> None:
    # ⚠ THIS CAN FAIL, AND FAILING IS CORRECT. Any org that chose Qwen or a
    # combination word holds a value the 0053 constraint refuses, so Postgres
    # rejects the narrower constraint rather than silently discarding their
    # choice. Downgrading past this point means deciding what those rows become,
    # and that is a decision for whoever is downgrading — not a default this
    # migration is entitled to make on their behalf.
    op.drop_constraint("ck_org_policies_judge_provider", "org_policies",
                       type_="check")
    op.create_check_constraint(
        "ck_org_policies_judge_provider", "org_policies",
        "judge_provider IN ('gemini', 'openai', 'both')")
