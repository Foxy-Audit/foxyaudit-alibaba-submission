# Dynamic credit model — weight what a credit costs

Planned 2026-08-23. **Verified against live code, not memory** — `logs.py`,
`config.py`, `account.py`, `usage.py`, `billing_state.py`, `chain.py`.

> ⛔ **PUSH RULE, standing from 2026-08-23.** Nothing goes to `main`. The only
> push target is `https://github.com/Foxy-Audit/foxyaudit-devtool.git`, which is
> **not yet a configured remote** (`origin` is still
> `git@github.com:fatimaatta-09/Foxy-Audit.git`). Adding it is an owner action.
> Build on branches; hand the owner a paste-ready push command naming the
> devtool remote explicitly.

## The problem, in the owner's words

> *"1 per call is way too low and we are giving way too many — usage should be
> dynamic, bigger things use bigger and lower uses lower."*

Two separate complaints, and they need two separate fixes:

1. **The unit is wrong.** A 300-token blocked prompt and a 60,000-token RAG call
   both cost exactly 1 credit today. That is neither fair to the customer nor
   aligned with what either one costs us to serve.
2. **The allowances are too generous.** 500 free events and 25,000 on Pro were
   set when a credit meant nothing in particular.

---

## ⚠ What the code actually does today — verified, with line refs

| | Live behaviour |
|---|---|
| **Unit** | One row in `audit_logs` = 1 credit. `config.py:140` states it: *"One credit is one captured model call, not a token."* |
| **Gate** | `logs.py:162-174` — `count(*)` of rows since the 1st of the month; `used + len(new_items) > quota` → **402 `credits_exhausted`** |
| **Source of truth** | The **ledger**, not `usage_daily`. Deliberate — the rollup is eventually-consistent, billing cannot be. |
| **Concurrency** | The sequence row is already locked, so two writers cannot spend the same last credit. |
| **Batch shape** | **All-or-nothing.** A batch that would cross the line is rejected whole. |
| **Quota resolution** | `organizations.monthly_log_quota` (per-org) → `platform_config` override → `Settings.quota_for()`. `NULL`/`None` = **uncapped**. |
| **Plan defaults** | `config.py:221-226` — free 500 · pro 25,000 · max 250,000 · premium/guardian/enterprise `0` = **unlimited** |
| **Reporting** | `/v1/usage` reads **straight from `audit_logs`**, not the rollup (`account.py:151-161` — the rollup understated it). `usage_daily` feeds dashboards only. |

### Three live facts that shape the whole design

**1. `/v1/usage` already publishes the unit on the wire.**
`account.py:91` — `credit_unit: str = "audit_event"`. Somebody left the seam
deliberately. A weighted model flips this to `"weighted_v1"` and every client
learns the rules changed **without a breaking field rename**. Use it.

**2. There is already a SECOND credit counter, and it is not this one.**
`evaluation_credit_limit` / `evaluation_credits_used` (`models.py:108-110`) —
the evaluation-offer allowance, gated in `billing_state.py:677-686`, **also
all-or-nothing per batch**, and it runs **before** the monthly quota. Any change
here must decide what happens to that counter, or the two systems will disagree
about what a customer spent. See **Cr3**.

**3. Migration head is `0067`, not `0061`.** `CLAUDE.md` is stale
(`0065_backfill_usage_daily` · `0066_admin_action_chain` ·
`0067_admin_chain_anchor`). Re-check before writing a migration; do not trust
this line either by the time you read it.

---

## Design principles — decided, with reasons

### P1 · Everything in the formula must be knowable **at ingest**

This is the constraint that kills the obvious design. The tempting weights —
*"charge more when the AI judge runs, less when it falls back"* — are
**unbillable**, because the judge runs later in the worker and the gate runs at
ingest. You cannot charge at admission for work you have not yet decided to do.

And even if you could: **charging a customer more because our judge happened to
be reachable is indefensible.** Judge-vs-fallback is our operational problem.

✅ What IS on the wire at ingest: **`event_type`** and **`token_count`**. The
formula uses those two and nothing else.

### P2 · Integer credits from a published rate card, never an opaque float

Foxy sells *"you can verify this yourself."* A billing formula the customer
cannot recompute is off-brand in a way that costs more than it earns. Every
customer must be able to price a workload on paper before running it.

### P3 · Cheaper when the guard did its job

A blocked or redacted event is **less** work for us — enforcement events never
call the judge at all (`worker.py:207-211`, and it is a security property, not an
optimisation). It is also the behaviour we want more of. **Price it lowest.**

### P4 · Record the cost on the row, do not recompute it later

Store `credit_cost` per event. A bill that is recomputed from a formula that has
since changed is a bill nobody can audit — including us.

---

## The formula

```
credits(event) = path_base + size_steps

path_base
    blocked / redacted   (enforcement event_type)      0     ← PREVENTION IS FREE
    interaction          (observed, reached provider)  3

size_steps  — from token_count, the value already on the wire
    +1 per COMPLETE 4,000 tokens above the first 2,000
    capped at +9

    ⚠ size_steps apply ONLY when path_base > 0. A blocked event costs 0
      regardless of size — otherwise "prevention is free" is not true.
```

Maximum chargeable event = **12**. Minimum for an observed call = **3**.
Blocked and redacted events are **free**.

### ✅ Owner decision, 2026-08-23 — prevention is free

Blocked and redacted events cost **nothing**. Three reasons, and the third is the
one that matters most:

1. They are genuinely cheaper to serve — enforcement events never call the judge
   (`worker.py:207-211`).
2. It is the behaviour we want more of. Pricing `block` mode at zero is the
   strongest possible push toward customers actually using the guard.
3. **A customer who is completely out of credits is still fully protected.**
   Compliance never lapses because of billing. On a product whose subject is
   regulated-industry safety, "we stopped protecting you because your invoice
   was late" is an unacceptable sentence. This removes it.

⚠ **Free is not unmetered.** A blocked event still writes a chain row and still
costs storage forever, so an aggressive policy in `block` mode is a cheap way to
write unbounded rows. **Blocked events must still be counted — just not
charged** — against a separate abuse ceiling (recommend: a per-org daily row
limit well above any honest workload, alerting staff rather than rejecting).
Track it; do not bill it.

### Worked examples — put these in the docs verbatim

| What happened | tokens | credits |
|---|---|---|
| PHI blocked before the model call | 300 | **0** |
| PHI blocked in a huge document | 90,000 | **0** |
| Prompt redacted, call proceeded | 900 | **0** |
| Ordinary chat turn | 1,200 | **3** |
| Chat turn, slightly long | 2,500 | **3** |
| RAG call with retrieved context | 12,000 | **5** |
| Document analysis | 60,000 | **12** *(capped)* |

⚠ **The cap is doing real work.** Without it a single 500k-token call would eat
a free tier whole, and the error message would be indistinguishable from abuse.
With it, the worst case is bounded and explainable.

### Why buckets and not a linear rate

A linear `tokens / 1000` rate is fairer on paper and worse in practice: every
invoice is a different non-round number, nobody can estimate, and support answers
"why was it 3.47 credits" forever. Buckets are predictable, and a customer can
count their own credits with a calculator. **P2 wins over marginal fairness.**

---

## Repricing the allowances

Average typical event under this model ≈ **3–4 credits**. Holding the headline
number attractive while cutting real capacity ~2.8×:

| Plan | today | proposed | ≈ typical events | change |
|---|---|---|---|---|
| Free | 500 events | **600 credits** | ~180 | **−64%** |
| Pro | 25,000 events | **30,000 credits** | ~9,000 | **−64%** |
| Max | 250,000 events | **300,000 credits** | ~90,000 | **−64%** |
| Premium / Guardian / Enterprise | unlimited | **unlimited** | — | unchanged |

⚠ **The headline number goes UP on every metered plan while capacity goes down.**
That is not a trick to hide — it is the honest consequence of changing the unit,
and it must be said plainly in the changelog and the pricing page. A customer who
discovers it themselves will read it as one.

⚠ **`0` still means unlimited** in `quota_for()`. Do not "fix" that encoding in
this work; it is load-bearing in six places. Just never render it as a number.

---

## ✅ The grace trickle — owner decision, 2026-08-23

> *"If the credits are finished before the month end then after every 5 hours
> enough free credits can be given that they can use the product — 1.5 big jobs
> or 4–5 small jobs."*

**The problem it solves:** a customer who exhausts on the 20th is dead for ten
days. On a product that sells *complete* audit trails, a ten-day hole is the
worst possible failure — and it lands precisely on the customers doing the most
work. `logs.py:150-152` already reasons this way for billing failures
(*"evidence cannot be re-created after the fact"*); this extends the same
principle to exhaustion.

### The bucket

```
GRACE_REFILL   = 18 credits
GRACE_WINDOW   = 5 hours
```

Once the monthly quota is spent, an org draws from a grace bucket holding **18
credits**, reset to full every 5 hours.

**Why 18:**

| | |
|---|---|
| `18 / 12` | **exactly 1.5 maximum-size jobs** — the owner's number |
| `18 / 3` | **6 ordinary chat turns** |
| `18 > 12` | ⚠ **the load-bearing one** — see below |

⚠ **The refill must be ≥ the largest possible single event, or large-job
customers are permanently locked out.** Max event cost is 12; a 10-credit bucket
would let a chat user limp along while a document-analysis customer — the higher
paying one — could never complete a single call, forever. **Any future change to
the `+9` cap must move this number with it.** Guard the relationship, not the
constant.

**It is a bucket, not an accrual.** It resets to 18; it does not stack. Waiting
three days does not buy a 1,300-credit burst — that would defeat the pacing that
is the entire point.

**Blocked and redacted events never touch it**, because they cost 0. A customer
at zero credits with `mode="block"` is still **completely protected**. Only
observed traffic throttles.

**The spool makes rejection safe.** A batch that exceeds the bucket is rejected
whole (existing behaviour), the SDK's durable SQLite spool holds it, and it
retries at the next refill. ✅ **Nothing is lost — it waits.** Say this in the
error message, because "your evidence is queued, not dropped" is the difference
between a support ticket and a churn event.

### ⚠ The hole this opens, and how it closes

At 18 credits per 5 hours: **4.8 windows/day → ~86 credits/day → ~2,590/month.**

**That is 4.3× the entire Free plan.** Unbounded, the trickle makes Free
*bigger* than Free, and nobody ever upgrades from it. The rate alone cannot be
the only limit.

**Fix — a monthly grace pool, sized as a fraction of the plan:**

```
GRACE_POOL = 25% of the org's monthly credit quota, per calendar month
```

The two limits bind in different places, which is exactly what makes this work:

| Plan | quota | grace pool | what actually stops them |
|---|---|---|---|
| Free | 600 | **150** | **the pool** — ~8 refills, then genuinely done |
| Pro | 30,000 | 7,500 | **the rate** — a full month of trickle is only ~2,590 |
| Max | 300,000 | 75,000 | **the rate** |
| Premium | unlimited | n/a | never exhausts, so grace never engages |

✅ **The rate paces paid customers; the pool contains free ones.** One rule, no
special cases, and the numbers fall out correctly at both ends.

For Pro, the trickle is ~8.6% of plan capacity — visibly degraded, obviously
worth upgrading past, and never zero. That is the right shape.

### What it needs

- `organizations.grace_window_started_at TIMESTAMPTZ NULL`,
  `grace_credits_used_in_window INT NOT NULL DEFAULT 0`,
  `grace_credits_used_this_month INT NOT NULL DEFAULT 0`
- A **third gate** in `logs.py`, after the quota check: if over quota, roll the
  window if `now - grace_window_started_at >= 5h`, then test against both the
  bucket and the pool.
- Under the **same row lock** as the quota gate — two concurrent batches must not
  both spend the last grace credit.
- A distinct 402 code. ⚠ **Do not reuse `credits_exhausted`** — it now means two
  different things (throttled-but-recoverable vs actually finished), and the
  dashboard needs to say different sentences. Recommend `grace_throttled` with
  `retry_after` seconds, and keep `credits_exhausted` for a dry pool.
- ⚠ **UTC everywhere.** Both a 5-hour window and a calendar-month pool reset in
  the same gate — `usage.py:60-67` records what session-timezone drift cost last
  time.

---

## Anti-gaming: `token_count` is customer-supplied

The SDK puts `token_count` on the wire. Under a weighted model, under-reporting
it saves money. Three layers, in order of strength:

1. **It is already in the hash chain.** `token_count` is part of the chained
   payload (`chain.py:67`, and the legacy `data_blob` at line 87). A customer who
   under-reports is **signing a false compliance record** — and for a customer
   buying audit evidence, a falsified ledger is a catastrophically worse problem
   than the credits saved. ✅ **This is the real defence, and it is elegant: the
   product's own integrity mechanism secures its billing.** Say so.
2. **Server-side sanity bounds** — reject negative, reject absurd, and flag rows
   whose `token_count` is implausible against the metadata's stated model.
3. **Drift detection** — a per-org report of average tokens/event over time.
   A sudden collapse is a support conversation, not an automated penalty.

⚠ **Do not build an automated punitive path.** A false accusation of billing
fraud against a compliance customer is unrecoverable. Detect, surface to staff,
let a human ask.

---

## Phases

Strictly sequential. **Cr2 is the one that must not be skipped.**

### Cr0 · Freeze the rate card — owner decision, no code

The owner signs off on: the two `path_base` values, the 4,000-token step, the
`+9` cap, and the three new allowances. Everything downstream hard-codes these,
so a change after Cr3 is a re-pricing event, not an edit.

**Also decide here:** does the evaluation-offer counter weight too? (Recommended:
**yes** — two counters that disagree about "a credit" is worse than either
choice.)

### Cr1 · Compute and store `credit_cost` — shadow mode, nothing charged

- Migration (**check the head first**): `audit_logs.credit_cost SMALLINT NOT NULL
  DEFAULT 1`, `usage_daily.credits_sum BIGINT NOT NULL DEFAULT 0`.
- One pure function, `credits_for(event_type, token_count) -> int`, in its own
  module. **Both** the ingest path and any estimator import it — one
  implementation, the `chain.py` precedent (*"exactly one implementation"*).
- Ingest computes and stores it. **The gate still counts rows.** Nothing changes
  for any customer.
- Extend `_ROLLUP_SQL` **and** `_BACKFILL_SQL` with `credits_sum`. ⚠ They are
  deliberately the same shape so a change cannot fix one and miss the other
  (`usage.py:133-135`) — honour that.

### Cr2 · Dual-run — measure before repricing

**Do not reprice blind.** Run Cr1 in production for a full billing month, then
report per org: events, rows-charged-today, credits-that-would-have-charged, and
the implied ratio.

The 3–4 credit average above is an **estimate from the formula, not a
measurement**. If real traffic averages 6, the proposed allowances are a 5× cut
and every customer churns. ⚠ **Cr3 does not start until this number is real.**

### Cr3 · Flip the gate

- New column `organizations.monthly_credit_quota INT NULL`. ⚠ **Do NOT
  reinterpret `monthly_log_quota`** — silently changing what an existing number
  means re-prices every customer at deploy time. New column, explicit migration
  of values, old column retired later.
- `logs.py:165-168`: `count(*)` → `SUM(credit_cost)`. Same month bound, same
  lock, same all-or-nothing shape.
- 402 body keeps `used` / `included` / `requested` but they are now credits. Add
  `unit: "weighted_v1"` so a client can tell which regime rejected it.
- Evaluation counter weighted per the Cr0 decision.
- **Grandfather:** existing orgs get `monthly_credit_quota` set so their
  *measured* Cr2 consumption fits, not the new list price. Reprice at renewal,
  with notice — `billing_change_notice_days` is already 4 (`config.py:220`).

### Cr3b · The grace trickle

Ships **immediately after** Cr3 and before the surfaces, so no customer ever
experiences the new lower allowances *without* the trickle that makes them
humane. ⚠ **Shipping Cr3 alone would cut capacity 64% with a hard wall behind
it.** These two are one release.

- The three new columns, the third gate, the same row lock, the `grace_throttled`
  402 with `retry_after`.
- `GRACE_REFILL` / `GRACE_WINDOW` / `GRACE_POOL_PCT` as named constants beside
  the rate card — not literals in the gate.

### Cr4 · The surfaces

⚠ **`grep desktop/` before touching any `/v1` shape** — the desktop app consumes
these routes and reads the 402 `code` out of the error string.

- `/v1/usage`: flip `credit_unit` to `"weighted_v1"`; keep `credits_included` /
  `_used` / `_remaining` as credits.
- Dashboard + admin quota meters read credits. **The two honest states survive
  unchanged:** unmetered plan → *no bar* (a full bar lies about a plan that
  cannot fill); not yet rolled up → *empty track that says so*, never `0%`.
- Pricing page + docs get the rate card and the six worked examples.

**UI work loads all three frontend skills, `ui-ux-pro-max` first.**

### Cr5 · Chain the cost — **owner decision, genuinely optional**

Include `credit_cost` in a new `CHAIN_VERSION_CREDITS_V5` payload.

**For:** billing becomes tamper-evident by the same mechanism as the evidence.
*"We cannot retroactively re-bill you, and you can prove it"* is a real
differentiator no competitor can copy without our architecture.

**Against:** chain versions are frozen forever, and it couples billing to the
evidence chain. The verifier must handle V5, and `verifier/foxy_verify.py` is
**dependency-free by design** — that constraint holds.

The precedent is clean: V4 added `verdict_hash` exactly this way, and V1–V3 stay
byte-identical (`chain.py:82-84`). ⚠ Recommend **yes**, but it is the owner's
call and it is not required for the rest to ship.

### Cr6 · The estimator

`POST /v1/usage/estimate` — hand it event types and token counts, get credits
back. Plus an SDK helper so a customer prices a workload **before** running it.
Small, and it removes the single most likely support ticket.

---

## Guards — the deliverable, per this repo's rule

**Every guard must be made to fail on purpose before it is trusted.**

| Must assert | Why |
|---|---|
| `credits_for` is table-driven across the **cross-product** of event_type × size bucket | *guard the axes, not the case* — a per-case test passes while a bucket boundary is wrong |
| Both boundaries of every bucket (3,999 / 4,000 / 4,001 …) | off-by-one in a step function is invisible mid-bucket |
| The `+9` cap **fires** — not that it exists | a cap whose condition is replaced by a constant survives an exists-check |
| Blocked/redacted really costs less than an equivalent-size interaction | P3 is the design; assert the property, not the constant |
| The gate **sums** and does not **count** | mutate one row's `credit_cost` to 5 and assert the gate moves |
| All-or-nothing per batch still holds under weighting | |
| `NULL` quota is still uncapped, and `0` still means unlimited | the encoding trap, in both counters |
| The rollup and the backfill agree on `credits_sum` | they are the same shape on purpose |
| A rejected batch names its unit | so a client can tell the regimes apart |
| **`GRACE_REFILL >= max possible event cost`** | assert the *relationship*; a future cap change must not silently strand large-job customers |
| Grace does **not** accrue across skipped windows | wait 3 days, still get 18 |
| The pool binds on Free, the rate binds on Pro | the two limits are load-bearing in different places — assert both, on both plans |
| A blocked event consumes neither quota **nor** grace, at any size | "prevention is free" in both regimes |
| `grace_throttled` and `credits_exhausted` are distinct and both reachable | they mean different things to the dashboard |
| Grace spends under the same lock as quota | two concurrent batches cannot both take the last credit |
| The 5-hour window and the monthly pool both reset in **UTC** | two clocks in one gate |

⚠ **Guard the USE, not the definition.** A guard on `credits_for`'s body that
never asserts the *gate* calls it is the A6 failure this repo has already paid
for once.

⚠ **Pin UTC in every date expression.** The month bound at `logs.py:164` uses
`now.replace(day=1, ...)`; `date_trunc` resolves in the session timezone and this
machine is Asia/Karachi. `usage.py:60-67` records what that cost last time.

---

## Verification

```bash
cd backend && python -m pytest tests/integration -q -p no:randomly
python -m pytest foxy-dashboard/ -q          # Cr4 only
python -m pytest foxy-adminpage/ -q          # Cr4 only
python verifier/foxy_verify.py logs.json     # Cr5 only — V1..V4 must still verify
```

`DATABASE_URL` → `:5433/foxy_pytest`. Single Alembic head after each migration.
⚠ One test DB, two chats — check nothing else is running before a suite.

## Open questions for the owner

~~1. Do blocked events cost anything?~~ ✅ **Decided 2026-08-23: free.**
~~2. What happens at exhaustion?~~ ✅ **Decided 2026-08-23: the grace trickle.**

3. **Retroactive or renewal-only?** Recommend renewal-only with notice
   (`billing_change_notice_days` is already 4).
4. **Does the grace trickle apply to the evaluation-offer counter too?** That
   allowance is a *sales* instrument with a deliberate end, not a plan — a
   trickle may undermine the reason it expires. **My lean: no trickle on
   evaluation offers**, but it interacts with the Cr0 decision on whether that
   counter weights at all.
5. **Is 25% the right grace pool?** It is the number that makes Free work
   (~8 refills) without special-casing it. If Cr2's measurements move the
   averages, re-derive it rather than keeping 25% out of habit.

---

## What Cr2 must now also measure

Two of this plan's numbers became estimates the moment prevention went free:

- **Guard-mode customers get materially cheaper**, and we do not know by how
  much. If a large share of a customer's traffic is blocked or redacted, their
  bill drops without any allowance change. Measure the **blocked/redacted share
  per org** before setting final prices — the 64% capacity cut assumes it is
  small, and for a heavy `block`-mode customer it may not be.
- **The 3–4 credit average** now describes only *billable* events. Report both:
  credits per billable event, and credits per total captured event.
