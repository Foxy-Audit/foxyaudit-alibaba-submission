# Alibaba Cloud AI Hackathon Pakistan 2026 — the escalation gets a destination

> **Plan of record · written 2026-09-05 @ `23cddea`.**
> Successor to `docs/plans/qwen-judge.md`, which is the plan of record for Q1–Q4
> (all four shipped; that file's §6 State column is stale — see §7 here).
>
> **Deadline: 2026-09-07, 11:59 pm PKT.** Roughly 2.5 days from this file's date.

---

## 0 · The one-paragraph version

The Qwen agentic judge can call `flag_for_human_review` and return
`decision="human_review"`. Nothing receives that escalation: no table, no endpoint,
no reviewer UI, no notification. This plan builds the destination — a review queue
(A1), a reviewer surface (A2), a demo that runs the whole loop for real (A3), and
the submission artefacts (A4) — so the product's central claim is *demonstrated*
rather than asserted.

---

## 1 · Why this is the phase

`qwen-judge.md` §3.5, written before Q2b shipped:

> The draft's §0 says the judge escalates "to a human queue instead of just scoring
> them." **That queue does not exist**, and neither the three phases nor their file
> lists build one. Shipping the tool-call without a destination would record an
> escalation nothing acts on — placeholder functionality, which the hard rules
> forbid in code as well as in UI.

Q2b shipped the tool-call. Option C (a real queue) was deferred with *"It is not a
hackathon-week phase."* It is now the hackathon week.

**Verified state of the hole at `23cddea`:**

| Surface | Exists? |
|---|---|
| `decision="human_review"` in the wire enum | ✅ `schemas.py:347-349` |
| Merge ladder `breach > human_review > clean` | ✅ `judge.py:34` |
| Ledger filter `?verdict=human_review` | ✅ `routers/logs.py:541-548` |
| Stats count, Passport subtraction | ✅ `logs.py:991-994`, `passport.py:365` |
| Dashboard violet chip + filter option | ✅ `foxy-audit-premium.html:596,615,2321` |
| **A table to escalate into** | ❌ none — no `review`/`escalation`/`queue` table among the 35 in `models.py`; `grep -rn "review" backend/migrations/versions/*.py` → 0 hits |
| **An endpoint to act on one** | ❌ none across the 39 files in `backend/app/routers/` |
| **A reviewer UI** | ❌ none |
| **A notification** | ❌ `worker.py:333` gates on `verdict.policy_breach`, which is **always `False`** for a `human_review` (`judge.py:230`) — an escalation notifies nobody |

---

## 2 · The premise correction (read before writing any submission prose)

The rules previously in play in this repo — **Track 4 "Autopilot Agent"**, the 30%
Innovation & AI Creativity weight, the "Stage One … reasonably applies the required
APIs/SDKs" clause, and the public-repo/architecture-diagram/3-min-video checklist —
belong to the **global** *Qwen Cloud Global AI Hackathon Series* on Devpost. That
event ran **May 25 – Jul 20 2026 and has ended**; winners were announced ~2026-08-29.

The live event is the **Alibaba Cloud AI Hackathon Pakistan 2026** (Bano Qabil ×
Alibaba Cloud × Cognix Solutions), `https://aihackathon.cognix-pk.com/`:

> "Submissions are open until 7 Sep 2026, 11:59 pm PKT"

with a note that the build phase was extended after the training sessions. Its
tracks are **entirely different**:

> Smart Agriculture · Financial Inclusion · Urdu & Regional Language Tech ·
> Healthcare · Education · Open Innovation

⚠ **The Pakistan site publishes no judging weights and no submission checklist.**
Do not plan against the global event's checklist — A0.3 reads the real one off the
portal.

⚠ `qwen-judge.md:1,23,34` says **"Track 4: Agentic Applications"**, sourced from
undated owner documentation. That matches **neither** event. Do not repeat it in any
submission artefact, and do not treat it as evidence of the brief.

---

## 3 · Owner decisions, 2026-09-05

| Question | Decision | Consequence |
|---|---|---|
| Track | **Open Innovation** declared; the demo covers **healthcare (PHI)** and **financial** scenarios | Both domain claims are demonstrated, not asserted. Revisit only if the portal's list differs (A0.3) |
| Repo | ⚠ **REVERSED 2026-09-05 pm — see §3.1** | Submission repo is **`foxyaudit-alibaba-submission`, made PUBLIC**. `foxyaudit-devtool` is the BUILD environment and stays private |
| Qwen key | Owner obtains **2026-09-05** | A0 is the gate; A3 degrades honestly if it slips |
| Vault | Move the 2026-09-04 devlog into the main `Devlogs\`, then remove `Alibaba Submission Changes` | See §7 — three lines in `qwen-judge.md` point at the folder being deleted |

### 3.1 · ⚠ THE REPO AND SCOPE DECISION WAS REVERSED — 2026-09-05, evening

**The owner read the submission portal. Three TBDs came back, and two of them
reopened scope this plan had excluded.**

| Portal question | Answer |
|---|---|
| Public repo required? | ✅ **YES** |
| Alibaba Cloud deployment proof required? | ✅ **YES** |
| Architecture diagram required? | ✅ **YES** |
| Video length | **3 min limit.** The demo itself will be 30–50 s — **record every beat, cut in editing** |
| Track | **Open Innovation**, owner-confirmed |

**The two repos now have different jobs:**

| Repo | Job |
|---|---|
| **`foxyaudit-devtool`** (private) | **The build and test environment, and the single source of truth for code.** Already deployed to the dev2 stack (`app2`/`admin2`/`checkout2`) — the only place this work can actually be exercised today |
| **`foxyaudit-alibaba-submission`** | **The submission.** Goes **PUBLIC**, carries the README and diagram, and is what the Alibaba Cloud deployment is made from |
| `fatimaatta-09/Foxy-Audit` | Untouched. Frozen for judging, and separately frozen until 2026-09-18 |

**Why build here and not there:** the Alibaba repo is deployed nowhere, so a change
made in it cannot be seen or tested. Hosting is bought the night of 2026-09-05.

**The port is a FAST-FORWARD — verified 2026-09-05:** the Alibaba repo is at
`23cddea`, **8 commits behind** devtool, and **zero commits exist there that are not
here** (`git merge-base --is-ancestor` confirms containment). The port is a push,
not a merge: no cherry-picking, no conflicts, no divergence.

⚠ **So make every change HERE.** Anything committed to devtool reaches the
submission repo via the port. Two copies that must agree is how they stop agreeing.

**Sequencing — owner's decision:** port **and** publish happen **at the end**, once
the build phases are done. Not incrementally.

⚠ **Watch [[#315]] right after the flip.** GitHub Actions has **never** run in
`foxyaudit-alibaba-submission` — zero runs, ever. The likely cause was private-repo
billing, and **public repos get unlimited Actions minutes, so publishing may fix it
for free.** A submission repo whose CI has never run is a bad look if a judge opens
the Actions tab.

**On publishing 764 commits:** devtool's CI runs gitleaks **blocking, `fetch-depth:
0`, on every push**, and the Alibaba repo's history is fully contained in devtool's
— so every commit that would become public has already been scanned. That is
evidence, not proof. Look deliberately before flipping.

### Now IN scope, having been excluded

- **Alibaba Cloud deployment — ECS + docker compose.** Owner's choice, and the low
  risk one: `deploy/docker-compose.prod.yml` already targets a plain Linux VM, so
  this is a re-point rather than a new deploy path. The submission's required "code
  file demonstrating Alibaba Cloud services usage" **is** that deploy config.
- **Making the submission repo public.** MIT `LICENSE` is already committed in both.

### Still out of scope

- ⛔ **Touching `deploy.yml` / `release.yml` triggers.** They stay frozen. The
  Alibaba deployment gets its **own** compose file and runbook, and must never reuse
  the workflow that SSHes to `34.18.4.58` and resets a *different* repo's clone.
- **A second judge tool** — A5, and only after A1–A4 merge.
- **Any retroactive change to the compliance rate** — §4.4.

### Superseded

*The 2026-09-05 morning scope, kept for the record — the first bullet is no
longer true:*

- **Alibaba Cloud deployment.** `deploy/` contains zero Alibaba infra; the only
  `aliyuncs.com` string in the repo is the Qwen *API* endpoint, which is a judge
  provider and not a deploy target. Standing up ECS in 2 days against a frozen
  `deploy.yml` that SSHes into a *different* repo's VM is not a 2-day task. If the
  portal requires deployment proof, that reopens as an **owner decision** — never a
  silent attempt.
- **A second judge tool** — A5, and only after A1–A4 merge.
- **Any retroactive change to the compliance rate** — §4.4.

---

## 3.5 · Status — the only place this plan records what shipped

⚠ **This table is the plan's State column, and it exists because its predecessor
did not have one.** `qwen-judge.md` §6 recorded Q1 as shipped and then stopped;
Q2b, Q3 and Q4 all landed while the file went on saying they were pending, and
nobody noticed until a session read git instead of the plan. **Update this on
every merge, or it becomes the same lie.** Written 2026-09-05, verified against
`git log ebe284b..HEAD`.

| Phase | State | SHAs / evidence |
|---|---|---|
| **A0** — prove Qwen is real | ✅ **done** | No commit. Key tested live 2026-09-05: real call, `graded_by="ai"`, `judge_provider="qwen"`, `judge_model="qwen-plus"`. Portal facts read — §3.1 |
| **A1** — the review queue | ✅ **merged** | `7f56f3a` `28ff79e` `8078a2a` `10f7d44` `24b26ee` · migrations **0072**, **0073** · 4 review rounds, 17 findings |
| *(unplanned)* escalation criteria | ✅ **merged** | `9f9bacc`. **Not in the original plan.** Found by A0: `qwen-plus` AND `qwen-max` graded every input and never called the tool, so the escalation feature — the whole point of the provider — was unreachable live |
| **A2** — the reviewer surface | ✅ **merged** | `7b0deb3` `e32a669` `31bb6a7` `d7343ff` `d588949` `138fad0` · migration **0074** · follow-ups §5.1 |
| *(aftermath)* the moved claim pin | ✅ **merged** | `bf91e60`. `main` was red on `foxy-sale-page` from `138fad0`: A2 moved a pinned claim to `:2522` and six pins still said `:2405` |
| **A3** — the demo that is also the video | ✅ **merged** | `48baa3b` `7130445` `7a583db` `cfdaeb6` · **24/24 live, all eight beats, fresh stack.** Beat 3 escalates at risk 75–85; beat 6 grades `clean` at 15 after a human cleared it. `escalated 1 / cleared by a person 1` in beat 6's preamble is direct evidence the lookup gate withheld at 3 and offered at 6 |
| *(A3 blocker)* the empty lookup | ✅ **merged** | `9d05960` `495f32d`. A5 had regressed A1: offering `check_prior_reviews` on a tag with no history made the model LESS likely to escalate — zero priors read as safety. Measured: lookup withheld → `human_review` 85, offered with zeros → `clean` 5. Fixed structurally by withholding the tool when only *resolved* reviews are absent, not by prompt-tuning |
| *(local stack)* the missing key path | ✅ **merged** | `d39513c`. `backend/docker-compose.yml` had no `QWEN_*` block — the platform-key path could not reach the judge on the stack the README tells a judge to run |
| **A4** — submission artefacts | ✅ **merged** | `72e1390` `e861e4f` `ec0b68d` · `README.md` + `docs/architecture.svg` · 7 findings in review |
| **A5** — a second tool | ✅ **merged** | `d9fec84` `059d28c` · `check_prior_reviews`, no migration · **verified LIVE 2026-09-05**: the model called it and changed its verdict because of the answer — the same payload that escalates at risk 85 without it grades `clean` at 15 with it, citing "prior reviews of this phi-restricted tag were all cleared by humans". A1's loop closes |

**Alembic head 0074.** Suites at `ec0b68d`: backend hermetic **43** · backend
integration **1586** (3 skipped) · dashboard **597** · sale-page **665**.

### What remains, in order

1. 🔴 **A3** — the only unbuilt phase, and the one that gets filmed.
2. **ECS deploy config** — owner buys the box; that config is the submission's
   required "Alibaba Cloud services" proof.
3. **Port** — fast-forward devtool → `foxyaudit-alibaba-submission` (§3.1).
4. **Record** the video.
5. **Publish** the Alibaba repo, then check its Actions tab (issue #315).

---

## 4 · Phase A1 — the review queue *(branch `feat/human-review-queue`, backend only)*

### 4.1 The design constraint that makes this safe

`chain.py:85 verdict_hash_hex()` binds the **local**, SDK-side verdict. The AI
judge's verdict is written by the worker *after* the row is chained, which is the
only reason the worker can write it at all. A human decision must follow the same
rule: **it never mutates the chained row.**

`AuditEvent`'s own docstring (`models.py:242-247`) already states the principle:

> The original `audit_logs.gemini_verdict` column is retained as a compatibility
> projection for old clients. New verdicts are also written here **so grading does
> not rewrite the evidence event itself.**

So the human decision gets **both**:

| Vehicle | Role | Why both |
|---|---|---|
| `human_reviews` table | the **queue** — mutable `status`, so "what is pending" is one indexed query | an append-only log cannot answer "pending" cheaply |
| `AuditEvent(event_type="human_review_resolved")` | the **evidence** — append-only, `event_hash`, never rewritten | the human's decision belongs in the tamper-evident record, not only in a mutable ops table |

This is the submission's strongest technical point: *even the human's decision is
appended, hashed, and independently verifiable — nothing rewrites history.*

### 4.2 Files

- **`backend/migrations/versions/0072_human_reviews.py`** — 0071 is the current
  head; keep a single head.
  Table `human_reviews`: `id` (UUID pk), `org_id` (FK `organizations.id`,
  `ondelete="CASCADE"`, indexed), `audit_log_id` (FK `audit_logs.id`,
  `ondelete="CASCADE"`, indexed), `status` (`pending`|`resolved`),
  `resolution` (nullable: `confirmed_breach`|`cleared`|`policy_gap`),
  `reason` + `risk_score` carried from the tool call (already truncated to 300 and
  clamped 0–100 at `qwen_judge.py:203` — do not re-clamp, do not widen),
  `note` (nullable, capped), `created_at`, `resolved_at`, `resolved_by`.
  Index `(org_id, status, created_at)`.
  **A unique constraint on `audit_log_id`** — one escalation per event; it makes the
  worker insert idempotent under retry, which matters because `_grade_one` can be
  re-entered after `_handle_failure`.

- **`backend/app/models.py`** — the model. Match the RLS posture `audit_events`
  uses; `Database\CLAUDE.md` documents three postures — pick the matching one, do
  not invent a fourth.

- **`backend/app/worker.py`** — in `_grade_one`, after the existing `db.commit()`
  that durably persists the verdict:
  - the notify block at `:333-337` is `if verdict.policy_breach:`. Add the
    escalation branch **beside** it, not by widening that condition. A
    `human_review` is **not** a breach and must not start being counted as one —
    `policy_breach` is `False` by design (`judge.py:230`) and the Passport
    arithmetic depends on it.
  - insert the `human_reviews` row and append the `AuditEvent`.
  - RLS: the write-back already scopes with
    `SELECT set_config('app.current_org', :oid, true)` — the new writes must be
    inside that scope.
  - **Best-effort, never raises into grading.** The comment above the notifier
    states the rule: a notify failure must never lose the grade. The same applies
    here — a queue-insert failure must not fail the row.
  - **While in this file:** delete the unreachable `return verdicts[0]` at
    `worker.py:249`. It is dead after the Q3 fold and it is exactly the line a
    future edit resurrects.

- **`backend/app/routers/reviews.py`** (new, registered on `customer_api`) —
  `GET /v1/reviews` (filter by `status`, paged — follow the **seq-cursor paging
  shape** the export endpoint uses; do not invent a second paging contract) and
  `POST /v1/reviews/{id}/resolve`. Org-scoped. Rate-limit in line with neighbours.

- **`backend/app/schemas.py`** — request/response models. `resolution` constrained
  the same way `decision` is (`:347-349` uses a regex-constrained `str`, **not** an
  Enum and **not** a `Literal` — §3.2 of `qwen-judge.md` explains why narrowing a
  `Literal` 500s an existing client; follow the established shape).

### 4.3 `note` is annotation, not evidence

A reviewer can type anything into a free-text field, including raw prompt content.
So: cap it, and make it structurally impossible to mistake for content-blind
evidence — **excluded from the Compliance Passport, excluded from the export
bundle's evidence surface, and documented as customer-authored.** The
*structured* `resolution` is the machine-readable outcome; the note is a human aid.

### 4.4 Two decisions to encode, not re-litigate

- **Resolving does not retroactively alter the compliance rate.** `human_review`
  stays subtracted from `compliant_events` (`passport.py:365`) whatever the human
  decides. Changing it would move a headline number on **already-issued** Passports
  — precisely the trap open issue **#317** is about. Record the resolution; do not
  re-arithmetic history.
- **`graded_by` stays `"ai"`.** A human resolution is a new event, not a re-grade.
  Nothing in `judge.py` changes in this phase.

### 4.5 Tests

Hermetic in `backend/tests/` where the logic allows; integration in
`backend/tests/integration/` for RLS and endpoint behaviour.

Must cover:
1. An escalated verdict creates **exactly one** `human_reviews` row.
2. Re-grading the same row (retry path) does not create a second — the unique
   constraint holds.
3. A `clean` and a `breach` verdict create **none**.
4. Another org can neither list nor resolve it (RLS).
5. Resolving is idempotent; a second resolve does not double-write the `AuditEvent`.
6. **The assertion that proves the design:** the audit row's `chain_hash` is
   **byte-identical before and after** a review resolves.

⚠ **`judge_helpers.give_judge_key()` (`backend/tests/integration/judge_helpers.py:22-25`)
has `gemini_key` and `openai_key` but no `qwen_key`** — so no integration test can
route an org to Qwen today. Add the parameter here; it is two lines and it unblocks
every later Qwen integration test. Qwen currently has **zero** integration coverage;
the three-provider fold is pinned only by AST-parsing `worker.py`, never by execution.

### 4.6 A1 follow-ups — recorded here so they are not lost

Found in review of the A1 branch, **deliberately not built in A1**. None of them
is a regression: each is a boundary A1 draws and does not cross, written down so
the next phase inherits the decision rather than rediscovering it.

**(a) A dropped queue insert is permanent — there is no reconciliation sweep.**
`_grade_one` commits the verdict *first*, so `_claim_batch` never revisits the
row: it is `graded`, and the outbox has nothing left to retry. The insert that
follows is best-effort by design (a queue failure must not cost the grade), so a
SIGTERM, a connection reset or a full disk between the commit and the insert
loses the escalation **silently and permanently** — the ledger row still says
`decision="human_review"` and nothing points at it.

The window is small and the trade was the right one at this size, but the fix is
not "make the insert non-optional": that would restore exactly the failure the
best-effort contract exists to prevent. The fix is a **reconciliation sweep** —
one periodic query for `audit_logs` rows whose verdict decision is
`human_review` and which have no `human_reviews` row, inserting the missing ones
(the unique constraint makes it idempotent). It belongs beside the anchor sweep
in the worker loop, and it is also what would backfill escalations graded
*before* A1 shipped, which A1 does not do either.

**(b) Any member can permanently close an escalation, and it leaves no account
trail.** `POST /v1/reviews/{id}/resolve` takes `require_user` and no role gate,
so a `viewer` seat resolves as freely as an admin. Because resolution is
**first-write-wins** (§4.1 — the evidence event is append-only, so a resolve
cannot be corrected by re-resolving), a wrong or malicious close is
**uncorrectable through the API**. It also writes no `AccountAction`, unlike
every other customer-facing governance write in this product — so the customer's
own audit trail (`GET /v1/account/audit`) cannot answer "who has been closing our
escalations?" even though the answer is sitting in `human_reviews.resolved_by`.

Two separable changes, and they are not the same size. The `AccountAction` write
is small and uncontroversial. The role gate is a **product decision** — whether
review is an admin act or something a compliance seat does — and it interacts
with a role model that has no "reviewer" in it. Take the account trail first.

**(c) An escalation notice rides the tenant's breach preference, because there is
no other one.** `send_escalation_notice` gates on `notify_on_breach` /
`enforcement_mode` via the same two helpers the breach notice uses. That is
defensible — a tenant who asked to hear about graded outcomes immediately hears
about this one, `monitor` still silences the email, `none` still means none — but
it is a reused field, not a chosen one: a workspace cannot ask for escalations
and not breaches, or the reverse. A dedicated `notify_on_human_review` column
means a migration, the policy API, and both shipped clients' settings UI, which
is not a backend-only phase. Revisit with A2, where the reviewer surface makes
the preference visible anyway.

**(d) Nothing in the schema stops a duplicate `human_review_resolved` event.**
`audit_events` has no unique constraint, and it cannot take a blanket one on
`(audit_log_id, event_type)`: the retry path legitimately appends a second
`verdict` event for the same ledger row. So "one resolution event per review" is
enforced only by the endpoint's row lock — application logic guarding an
append-only record.

The durable fix is a **partial** unique index,
`CREATE UNIQUE INDEX … ON audit_events (audit_log_id) WHERE event_type =
'human_review_resolved'`, which leaves the `verdict` rows alone. Not added in A1
because it is a migration on the largest table in the product, and because the
reader was hardened instead: the DSAR bundle looks the hash up through a
correlated scalar subquery rather than a `LEFT JOIN`, so a duplicate — if one
ever appeared — cannot fan one review into two apparent governance decisions in
the file whose subject is completeness.

⚠ **And the reader cannot pick the right one, only a stable one.** That subquery
orders by `created_at`, which is `server_default=func.now()` and therefore
TRANSACTION START time — so among two overlapping resolves the earliest
`created_at` is the transaction that started first, i.e. the one that would have
*lost*. No column in `audit_events` expresses write order: no sequence, no commit
timestamp. The ORDER BY buys determinism across repeated exports and nothing
else, which is enough only because the lock means the duplicate does not occur.
That is the second reason writer-side enforcement is the right end state: it is
the only end state where a reader does not have to reason about this at all.

**(e) A dropped escalation NOTICE is now unrecoverable — accepted at merge, and
A2 is the answer.** Found in the final review of `24b26ee` and merged knowingly.
Gating the notice on "did *this* attempt file it" is correct and it removed an
accident: while the bool was always `True`, a regrade re-sent the notice, which
was duplicate spam *and* a de-facto recovery. Now every later regrade conflicts →
`False` → silence. The notice path has three lossy points and none of them
requeues — `enqueue_escalation_notice` drops silently on `queue.Full` (bounded
2000), the queue is in-process memory so a restart loses it, and
`drain_breach_notices` swallows a send exception. The docstring's middle case
says "the attempt that filed it sent the notice"; nothing enforces that.

**Why it was merged anyway:** the escalation itself is never lost — it is durable
in `audit_logs.gemini_verdict`, in the `verdict` `AuditEvent`, and in
`human_reviews`. Only the *announcement* can be. A1 shipped into a product where
the email was the only way an escalation reached a person, which is exactly the
condition **A2 removes**: a reviewer page listing pending escalations is a pull
surface that does not depend on a notice having been delivered.

**So A2 carries the fix, and it is small there:** a `notified_at` column on
`human_reviews`, set after a successful enqueue and used as the gate instead of
"did this attempt insert". A2 already needs a migration-free surface, so this is
the one migration worth adding to it — and it composes with (a)'s sweep, which
can then backfill both a missing row and a missing notice.

---

## 5 · Phase A2 — the reviewer surface *(branch `feat/human-review-ui`)*

⚠ **A2 also closes §4.6(e)** — the `notified_at` column and the notice gate. See
that entry; it is the one piece of backend work this phase carries.

⚠ **Load all three frontend skills, `ui-ux-pro-max` FIRST**, then `impeccable`, then
`frontend-design`. Query the palette; never invent one.
⚠ **Measure every fill against its background, not only its ink.** This surface has
already shipped a chip whose text cleared 4.5:1 while the pill sat at 1.01:1 against
its own card and dissolved.

`foxy-dashboard/foxy-audit-premium.html` is one 9,520-line file with a `go(page)`
router. A page is an established additive pattern — three touch points:

- a `.dock-item` with `data-page="review"` (siblings `:1943-1985`) **and** its mobile
  `.mnbtn` twin (`:3373-3377`) — the desktop-only half is the one people forget;
- a `<div class="page" id="page-review">` (siblings `:2069-2916`);
- the fetch + render, following how `page-ledger` loads.

**Content:** pending queue — event seq, time, the AI's `reason`, `risk_score`, the AI
system — a resolve control writing the three resolutions, and a resolved view.

**Reuse the existing `human_review` violet `--c-6` token** from Q4 (`:596,615`). Do
not introduce a second escalation colour. Note `:176-181` — *"NO SHIPPED CALL NAMES
`violet`"* — read it before touching the token.

**Honest empty state.** Zero pending reviews is the **good** state and must read that
way: not an error, not a placeholder, no invented sample rows. Hard rule.

A pending count on the dock item follows the existing badge pattern on `analytics`
(`:1947`) and `notifications` (`:1980`).

**Tests:** `pytest foxy-dashboard` runs in CI; follow `test_p6f_judge_model_ui.py`'s
style. `node --check` every inline `<script>` touched — it is on the merge gate.

---

### 5.1 A2 follow-ups — merged knowingly, 2026-09-05

Found in the fourth review round of A2 and **not fixed before merge.** That is a
deliberate scope call by MAIN under the 2026-09-07 deadline, recorded here so it
is a decision rather than an oversight.

**Why they did not block.** All three are **display-layer accuracy on a race
between two reviewers resolving the same escalation at the same moment.** The
server is correct in every one of them: `resolve_review` takes
`with_for_update()`, is first-write-wins, appends exactly one
`human_review_resolved` event, and returns the standing decision. **No evidence
is wrong; a message about it can be.** Meanwhile A3 — the demo that gets filmed —
did not exist yet. Polishing a two-reviewer race while the centrepiece was unbuilt
would have been optimising the wrong thing.

**(a) The identity comparison is inert for any session that started signed-out.**
`window.__foxUser` is set only by `foxAvatar()` at DOMContentLoaded, and none of
the four sign-in paths repopulate it or reload. So a user who lands signed-out,
signs in, and works in that same page has `mine === ''`, the
`by && mine && by !== mine` clause can never fire, and the surface falls back to
the word-only comparison the commit exists to replace. **It degrades to the
previously-accepted behaviour rather than regressing** — but the fix is only
effective for sessions that were already authenticated at page load, which may be
the minority. Fix: repopulate `__foxUser` on each sign-in path.

**(b) No test can go red on (a).** `test_a2_review_ui.py`'s `/v1/auth/me` stub
answers 200 at boot — the one session shape where the guard works. The same line
also flipped the driven probe from a signed-out boot to a signed-in one, so every
other assertion in that file now runs against a different starting state than it
did before. Worth a look when (a) is fixed: some of those tests may be covering
less, or something else, than their names claim.

**(c) The dialog branches on whether `by` exists, not on `by === mine`.** A
reviewer who already resolved the same review in another tab is told their **own**
email "resolved this before your decision reached the record". Cosmetic, and a
genuine edge, but it is the surface telling someone a confusing thing about
themselves.

⚠ **None of this appears in the demo.** The mismatch dialog only renders when two
reviewers race, and the recording shows one reviewer. So these do not gate A3 —
but they should be fixed before this reaches a real second seat.

---

## 6 · Phase A3 — the demo that is also the video *(branch `feat/agentic-demo`)*

One runnable script producing the whole narrative, so the video is a recording of a
real run rather than a slideshow. **Extend `demo/`** (`mock_llm.py`,
`offline_demo.py`, `judge_client.py`) — do not start a parallel demo framework.

The run, in order:

1. **Healthcare** prompt carrying PHI → the SDK host-side guard **blocks before the
   model call** (`mode="block"`, `sdk/src/foxy_audit/policy.py`). *Works today.*
2. **Financial** prompt, clean → allowed, graded `clean`. *Works today.*
3. A genuinely **ambiguous** case → Qwen calls `flag_for_human_review` →
   `decision="human_review"` → lands in the A1 queue. *Needs A0's key.*
4. A human resolves it on the A2 page. *Needs A1 + A2.*
5. `python verifier/foxy_verify.py logs.json` → the chain verifies **independently**,
   dependency-free. *Works today.*
6. Tamper demo: alter one byte, re-verify, watch it fail. *Works today.*

That sequence *is* the submission argument: autonomous decision → escalation →
human → independently verifiable evidence, with raw content never leaving the host.

⚠ **If the key has not arrived, the script must SAY the judge is unavailable** and
still run 1/2/5/6 honestly. Never simulate a Qwen response — the product's entire
thesis is that you can check the evidence rather than trust the vendor.

---

## 7 · Phase A4 — submission artefacts + bookkeeping

Nothing here may repeat a claim the code does not support.

- **`README.md`** — `:17` still reads *"An OpenAI Build Week submission — category
  Developer Tools · GPT-5.6"* and `:210-238` is the Codex/GPT-5.6 disclosure. **Add**
  the Pakistan framing and an equivalent honest "built with Qwen during this period"
  section (Q1–Q4 on 2026-09-04; A1–A3 on 2026-09-05/06). **Do not delete the OpenAI
  disclosure** — both are true, and quietly rewriting history in a submission about
  tamper-evidence would be a poor look.
- **Architecture diagram** — SDK → local commitment → hash-chained ledger → worker →
  **Qwen agent (tool-calling)** → escalation → human review → export → independent
  verifier. Mark the **content-blindness boundary** explicitly; it is the thesis.
- **Track declaration** — Open Innovation, naming the healthcare and financial
  scenarios as the evidence.
- **`JUDGES.pdf` / `JUDGES.html`** are OpenAI Build Week artefacts. Regenerate or
  exclude — never submit them describing the wrong event.

**Stale facts to correct while here:**
- Root `CLAUDE.md` says Alembic head **0061**; it is **0071** (0072 after A1).
- `qwen-judge.md` §6's State column shows Q2b/Q3/Q4 pending; all four shipped
  (`04ae280`, `a050718`, `7fa7f30`, `c9d5ba5`, `1de4dd1`).
- `qwen-judge.md:521-522,840,842` point executors at
  `Alibaba Submission Changes\` in the vault, which §3 removes. **Repoint them in
  the same change** or the next executor writes to a path that no longer exists.

⚠ `ci.yml` carries `paths-ignore: ['docs/**','**/*.md','LICENSE']`, so a docs-only
commit runs **no CI at all** (open issue **#322**, and the reason `d18f391` triggered
nothing). A commit touching both docs and code needs a deliberate check.

---

## 8 · Phase A5 — a second tool *(only after A1–A4 merge)*

The agent has one tool and one turn. A second tool that changes what the system does
— the judge requesting the tenant's policy detail before deciding, say — is the
difference between "calls a function" and "acts". **Do not start it until A1–A4 are
merged.** A second tool without a destination repeats §3.5's mistake exactly.

**Built as `check_prior_reviews`** on branch `feat/qwen-prior-reviews-tool` — the
judge may ask what humans already decided about escalations on this org's
`policy_tag`, and grade or escalate with that in hand. **Verified live 2026-09-05:**
with a lookup returning 4 escalations / 4 cleared the model called the tool and
returned `clean`, risk 15, *"No PII signals detected; prior reviews of this
phi-restricted tag were all cleared by humans"* — where the identical payload
without the lookup escalates at risk 85. The loop A1 opened is closed.

### 8.1 A5 follow-ups — recorded here so they are not lost

**(a) 🟡 `/health/ready`'s `stale_after` has never known about Qwen, and A5 doubles
what it is under-sized against.** `routers/health.py:111` computes

```python
stale_after = s.grading_poll_interval * 5 + max(s.gemini_timeout, s.openai_timeout) + 10
```

— `qwen_timeout` is absent, and was absent before A5. At the defaults
(`grading_poll_interval` 2.0, timeouts 12.0, `grading_batch_size` 16) that is a
**32 s** staleness budget against a batch whose worst-case Qwen wall time was
~192 s and, with A5's second round trip, is now **~384 s** between heartbeats. So
a healthy worker grinding through a batch of slow Qwen rows can be reported
`not_ready`.

*Pre-existing under-sizing, amplified 2× by A5 — not caused by it.* **Not urgent:**
the deploy freeze holds (§9), `deploy.yml` is `workflow_dispatch`-only, and nothing
auto-rollbacks on this today. **But it must be Qwen-aware before anything deploys
again**, because `/health/ready` is exactly what the deploy smoke test reads.

Found in the A5 review, 2026-09-05. Not fixed there deliberately: it is a health
endpoint change, not a judge change, and it wants its own scope and its own test.

---

## 9 · Merge gate — every phase

Per root `CLAUDE.md` §5:

- Branch off **fresh `origin/main`**; isolate in a `git worktree` (shared-tree lock).
- Fast-forward-safe over `origin/main`.
- `node --check` every inline `<script>` in changed HTML (A2).
- Scope grep · **no fake/placeholder data** grep · **no secret** grep.
- **Single Alembic head** — A1 adds 0072 on top of 0071.
- `code-review` skill before merge.
- Merge by direct SHA push: `git push origin <sha>:refs/heads/main`.

⛔ **The deploy freeze holds.** `deploy.yml` and `release.yml` are
`workflow_dispatch`-only and **must not be run**: `deploy.yml:156` clones and
`git reset --hard`s `fatimaatta-09/Foxy-Audit` onto VM `34.18.4.58`, so one manual
run overwrites what judges see on a **different** repo. Pushing to this repo's `main`
does **not** deploy.

**Known noise — do not mistake it for a regression:** `backend-integration` was
already red at `da61819` before any Qwen work and went green with nothing targeting
it (**#321**); the full backend suite can hit a TRUNCATE deadlock — run per-file if
it trips.

---

## 10 · Verification

```bash
cd backend && python -m pytest tests --ignore=tests/integration -q   # hermetic
cd backend && python -m pytest tests/integration -q                  # per-file if the deadlock trips
python -m pytest foxy-dashboard                                      # A2 guards
python demo/<A3 script>                                              # the full narrative
python verifier/foxy_verify.py logs.json                             # independent chain check
```

End to end: escalate → row appears in `GET /v1/reviews` → resolve on the dashboard →
leaves pending → `AuditEvent` appended → **the audit row's `chain_hash` is unchanged**.
If that last one fails, A1's design is wrong, not the test.

---

## 11 · Change log

| Date | What |
|---|---|
| 2026-09-05 | Written at `23cddea`. Premise corrected: the global Devpost event ended 2026-07-20; the live one is Alibaba Cloud AI Hackathon Pakistan 2026, deadline 2026-09-07 23:59 PKT. Owner chose Open Innovation, private `foxyaudit-devtool`, key today, vault folder moved-then-removed. |
