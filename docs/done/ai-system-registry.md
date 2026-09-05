# AI-system registry — whose system produced this evidence

**Plan of record** · written 2026-08-26 against `4aa4fbf`
MAIN chat is the committer; executors build per this file.

Four phases, **R1 → R4**, with one hard deploy ordering. Rebuilt from
`origin/feat/enterprise-ai-system-registry` (2026-07-20) as a SPECIFICATION,
not ported as a diff.

---

## 1 · What this is for

Foxy records events but has no idea **which** of a customer's AI products each
one came from. A bank running a mortgage chatbot, a fraud screener and an
internal helpdesk gets one undifferentiated pile of evidence — and cannot answer
"show me everything the mortgage bot did", which is the first question any
auditor asks.

This adds a **customer-declared inventory** of AI systems, and binds each event
to one.

The abandoned branch's field list is worth keeping because it is not arbitrary —
name, owner email, purpose, provider, model, environment, **data
classification**, **risk tier**, lifecycle status. That is the shape EU AI Act
paperwork asks for, which is why this is a product feature and not a foreign key.

⚠ **Two design decisions from the branch to preserve, both load-bearing:**

- **Systems are DECLARED, never inferred from traffic.** Foxy must not invent an
  inventory of a customer's AI estate; an inventory Foxy guessed is not evidence.
- **Retire, do not delete.** A retired system accepts no new events and keeps
  every historical one. Deleting would orphan chained evidence.

## 2 · Premises, verified at `4aa4fbf`

| Premise | State |
|---|---|
| No registry exists today | ✅ no `routers/systems.py`; no `ai_system`/`system_id` in `models.py` or any router |
| The branch's migration is `0041_ai_systems.py` | ⚠ **`0041_platform_config.py` already exists.** Head is **`0067`**. Re-mint as `0068`; do not renumber by hand |
| The branch targets "V3 metadata" | ⚠ **Stale.** The chain is at **V4**, and `event_metadata` has been chain-bound since **V2** — so `system_id` riding in `event_metadata` is chain-covered with **no new chain version** |
| The branch edits `client.py`, `schemas.py`, `logs.py` | ⚠ All three rewritten repeatedly on 2026-08-24/26 by S12, S13, S14. **The diff will not apply and must not be forced** |

**The good news the branch could not have known:** because `event_metadata` is
already chain-bound and already has a strict allowlist, this feature is exactly
the S12/S13 shape — a new allowlisted key, backend deployed first, SDK second.
That path is now well worn.

## 3 · The hard ordering, and why it is not negotiable

`event_metadata` is a strict allowlist and an unknown key is a **422 on the
whole batch**. S12 paid five gate rounds learning what that means.

1. **R1 — the table and the API.** Ships and deploys alone. Nothing sends
   `system_id` yet.
2. **R2 — the backend accepts `system_id`.** Allowlist, validation, the
   duplicate-content pop, and the degrade path. **Ships AND DEPLOYS before R3.**
3. **R3 — the SDK sends it.** Only after R2 is confirmed running in the
   container.
4. **R4 — the dashboard page.** Independent of R3; can run in parallel.

⚠ **R2 must also teach `dispatch._strip_provenance` to strip `system_id`**, or a
lagging backend 422s forever and the retry is byte-identical to the request that
just failed. S13 built `TYPED_TAG_KEYS` as a sibling tuple for exactly this;
`system_id` is a third rung on `_DEGRADE_LADDER`, and **the ladder's nesting
assumption must be re-checked when it gains one** — it rests on refused key sets
being nested, which is true only because the allowlist has only ever grown.

## 4 · Phases

### R1 — the inventory

**Files:** new `backend/app/routers/systems.py` · `models.py` · new migration
**`0068_ai_systems.py`** · `main.py` (mount) · `backend/tests/integration/`

Five endpoints, from the branch: `GET /v1/systems`, `GET /v1/systems/{id}`,
`POST /v1/systems` (**dashboard admins only**), `PUT /v1/systems/{id}`,
`POST /v1/systems/{id}/retire`. Reads open to members and the SDK.

**Traps:** unique name per org, scoped per tenant — this table is RLS territory,
so read `Database\CLAUDE.md`'s three postures before choosing one. `created_by`
is `ON DELETE SET NULL`: deleting a user must not delete their systems.

### R2 — the backend accepts an attribution

**Files:** `schemas.py` · `routers/logs.py` · tests

Add `system_id` to the `event_metadata` allowlist. Validate it names a system
**belonging to this org** and **not retired**. Pop it from the duplicate-content
comparison in `logs.py` — S12's reasoning applies unchanged.

⚠ **A rejection message the SDK can degrade from.** S12e settled this: reuse
`"event_metadata contains unsupported fields"`. A phrase only the backend knows
bricks the spool.

⚠ **The 422 must not echo the value.** S12e's `RequestValidationError` handler
covers it — assert that, do not assume it.

**DONE MEANS DEPLOYED**, verified inside the running container rather than by a
status code:
`docker compose -f …/docker-compose.dev2.yml exec -T foxy-backend grep -c system_id /app/app/schemas.py`

### R3 — the SDK sends it

**Files:** `client.py` · `dispatch.py` · tests · README

`@foxy.audit(policy="hipaa", system_id="…")`, validated as a UUID **before**
anything is sent. Add the strip rung. Bump MINOR.

⚠ **Prove the unaffected path is byte-identical** — an event with no `system_id`
must produce the payload it produces today, key for key. S13's harness does
exactly this; reuse it rather than writing a new one.

### R4 — the dashboard

**Files:** `foxy-dashboard/`

⚠ **UI phase — the three frontend skills are mandatory, `ui-ux-pro-max` first**,
and `dataviz` if any chart appears. Expect the standing conflicts (navy/slate, a
green CTA, a Google-Fonts CDN) and overrule them on the record. **No CDN**: the
CSP is `default-src 'none'`.

## 5 · Blast radius

- **Nothing breaks for anyone who does not pass `system_id`.** It is optional at
  every layer. That property is this plan's safety rail — guard it, do not
  assume it.
- A retired system rejecting new events is a **new 4xx a customer can hit**. The
  message must name which system and say retirement is the cause.
- R4 adds a dashboard surface. The passport and per-system reporting that would
  make this sellable are **not** in scope and must not be smuggled in.

## 6 · Verification

Per phase, each suite alone. Baselines at `4aa4fbf`: backend **1302 passed / 3
skipped** · sdk **918** · testbed **482** · verifier **31** · desktop **941
collected** (#235 fails locally only, and is skipped in CI).

⚠ **Measure them yourself at branch time.** Three briefs this month quoted a
stale baseline and the executor caught it each time.

## 7 · The question to settle before R1

**Is per-system evidence something you intend to sell?** This is only worth four
phases if the answer is yes — otherwise it is a foreign key with paperwork. If
the answer is "not yet", file this plan, keep the branch, and spend the time on
the open reds instead.
