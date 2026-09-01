# Compliance — make the claim true, useful, and ready to certify

**Plan of record** · 2026-09-01 · MAIN chat is the committer; executors build per this file.

Phases **C0 → C4**, opening the `C` series. The owner's framing: *"right now we
only claim that we are doing compliance and I don't think that claim is
correct."* He is right in places, wrong in others, and this plan says which.

⚠ **Read [[Compliance — operating facts]] in the vault first.** It carries the
hosting region, the team, the freeze date and the live-customer picture — every
fact this plan rests on that the vault did not previously record.

---

## 1 · Context

Ten regulatory regimes are named across `foxy-sale-page/`, `foxy-dashboard/` and
the passport template. The SDK ships **two** policy packs. That gap is the
owner's doubt, and it is real — but the situation is better than it looks in one
direction and worse in another.

**Better:** the vault already holds the honest line. `Issues — compliance
coverage.md` (2026-08-17) states it exactly — *"Foxy is the TOOL that helps a
customer prove compliance. Foxy the company is certified in none of these. Never
say 'we are X compliant' — say 'we help you prove your X compliance.'"* Twelve
`.docx` policy documents back the published legal pages, six owner-authorised
divergences are each pinned by a test, and a build guard already scans for
standard names. This is not a codebase that has been careless about claims.

**Worse:** there are **live customers on the real repo sending PHI, EU personal
data, and Gulf personal data today**, and:

- **no BAA exists** — searched repo, sale page and vault, 2026-09-01;
- **production runs in `me-central1-a`, GCP Doha, Qatar** — no EU adequacy
  decision, and this was recorded nowhere until today;
- **`platform_keys_allowed`** lets Foxy's own provider keys carry customer event
  metadata to OpenAI and Google under Foxy's account.

The freeze compounds the sequencing: nothing merges to the real repo before
**2026-09-18**. But the freeze blocks *code*, not *legal artefacts* — and the
obligations are live now.

---

## 2 · What the premises actually are

Read at `01e87ad`, 2026-09-01.

| # | The premise | Holds? | What is actually true |
|---|---|---|---|
| 1 | Foxy is "compliance ready" | **NO, and the vault already says so** | Foxy is the *tool*; Foxy the company is certified in nothing. `Issues — compliance coverage.md` states the correct line. The defect is that the **surfaces** do not consistently match the **vault's** honesty. |
| 2 | `policy="soc2"` does something SOC 2-ish | **NO** | [`policy.py`](../../sdk/src/foxy_audit/policy.py) `_POLICY_EXTRA` maps `"soc2": ()` — baseline only (injection + secrets), no SOC 2-specific check. The SDK's own comment says this is deliberate. **The error is the vocabulary, not the code:** SOC 2 is an organisational control regime and can never be a per-call check. |
| 3 | Content-blindness means little compliance exposure | **PARTLY — and the gap is specific** | Raw prompt/response genuinely never leave the customer process. But [`judge_routing.py:99`](../../backend/app/judge_routing.py#L99) `platform_keys_allowed(org)` lets some tiers grade on **Foxy's** keys, sending event metadata to OpenAI and Google **under Foxy's account**. BYOK does not have this problem. Whether that metadata is identifiable — and so PHI — is a legal question, **TBD**. |
| 4 | HIPAA is handled | **PARTLY** | Detection is real: `hipaa` → `phi` via `pii.detect_pii`, and `mode="block"` genuinely stops the model call. But **no BAA exists**, and a business associate handling PHI needs one *before* data flows. Detection without a BAA is a product feature, not compliance. |
| 5 | The published privacy policy covers our customers | **NO** | Per `Issues — compliance coverage.md`: it covers GDPR/CCPA/LGPD/PIPEDA/Singapore/Australia and **not PDPL**, while §7's legal bases are EEA/UK-scoped. There are live Gulf customers. |
| 6 | Data residency is understood | **NO — and worse than "unrecorded": it is PUBLISHED WRONG** | ⚠ **UPGRADED after C0, verified against the LIVE site 2026-09-01.** `me-central1-a` = GCP **Doha, Qatar**. But `privacy.html` §8 states hosting is *"United States"*, §13 states *"data is processed in the United States"*, and then invokes the **EU SCCs for an EEA → US transfer that does not happen**. `trust.html`'s subprocessor table repeats *"Google Cloud (Ubuntu VM) — United States"*. The real EEA → **Qatar** transfer is disclosed **nowhere**, and the stated transfer mechanism names the wrong country. A false statement of fact on a live legal page, not a gap. **See §9.** |
| 7 | The AI judge assesses whether something was malicious | **NO** | `Issues — provability vs privacy.md` (🔴 top priority) is explicit: the judge sees only hashes and counts, so it *"cannot judge maliciousness at all"*. Anything the Passport says about the judge must respect this. |
| 8 | PCI is covered | **NO** | Card numbers are detected by `pii`, but there is **no PCI mode**. The vault names this as an explicit overclaim trap. |
| 9 | A blocked event is tamper-evident | **HOLDS** | `event_metadata` is bound into the chain hash and [`verifier/foxy_verify.py`](../../verifier/foxy_verify.py) recomputes it with zero Foxy imports. This is the strongest genuine compliance asset in the product. |
| 10 | The claims are guarded | **PARTLY, and the guard is green on false content** | ⚠ **UPGRADED after C0.** `test_site_wide_claims.py` proves the subprocessor lists **agree across pages**. They agree, and they are wrong on every page — so a consistency guard over false content reads green. A guard that checks agreement rather than truth is the [[#286]] shape again: it cannot be wrong about its own subject. |
| 11 | The SOC 2 disclosure is honest | **NO — two pages contradict a third** | ⚠ **FOUND BY C0.** `faq.html:60` and `pricing.html:121` both say *"We're currently completing our SOC 2 Type I audit."* `trust.html:151` says *"SOC 2 Type I — intended, but no auditor is engaged yet."* Both cannot be true, and "currently completing an audit" with no auditor engaged is the false one. The vault's `Owner-authorised divergences` already records that *"the honest SOC 2 disclosure was softened or removed"* once before — this is a recurrence, so C2 needs a guard, not just an edit. |

**Register entries to allocate when syncing:** the residency gap, the missing
BAA, and the platform-key transfer are not in `Worth Noting — Issues` (which now
runs to #287). Allocate **#288 (no BAA) · #289 (residency unstated / Qatar) ·
#290 (platform keys carry metadata to third-party providers) · #291 (backups
share a failure domain with the database)**.

---

## 3 · The architectural decision this plan rests on

**Stop modelling regimes as policies. Model data classes and controls, and map
regimes onto them.**

```
  DATA CLASSES          CONTROLS                CROSSWALK
  (in the prompt)       (what Foxy does)        (clause satisfied)

  PHI ─────────┐        hash chain ───┐         HIPAA §164.312(b) ──┐
  PII ─────────┤        RLS isolation ├────────▶ GDPR Art.30 ───────┤
  special-cat ─┤        BYOK / KEK    │         SOC 2 CC7.2 ────────┤
  financial ───┘        access review ┘         PDPL Art.19 ────────┤
                                                EU AI Act Art.12 ───┘
```

One control satisfies many clauses. **Adding PDPL becomes a mapping file, not a
feature.** This is the only way "all regimes" is tractable for a two-person team,
and it is how the category error in premise 2 gets fixed properly: `soc2` stops
being a `policy=` string and becomes a set of organisational controls mapped to
evidence the ledger already produces.

⚠ **YAGNI applies to the crosswalk too.** A clause we cannot map to a real
control or a real piece of evidence gets recorded as a **gap**, not as a
half-truth. The crosswalk's value is that it is honest about what is missing.

---

## 4 · Phases

Ordered **C1 → C2 → C3 → C4** per the owner's choice, with **C0** first because
every later phase reads its output, and with **C4's evidence collection started
early** for the reason in §5.

### C0 · The crosswalk — research as a versioned artefact

**Why first:** the "intensive research" the owner asked for should not be forty
thousand tokens of chat that vanishes. It should be a file that later phases read
and that a reviewer can check.

**Deliverables**

- `docs/compliance/crosswalk.yaml` — machine-readable. For each regime, each
  clause we intend to speak to: `clause`, `requirement`, `control` (or `null`),
  `evidence` (or `null`), `status` ∈ `{met, partial, gap, not-applicable}`.
- `docs/compliance/README.md` — how to read it and how to add a regime.
- Regimes in scope: **HIPAA · SOC 2 · GDPR · EU AI Act · PDPL (Saudi/UAE) ·
  Qatar Law 13/2016 · PCI DSS · ISO 27001**, each explicitly marked for whether
  we *claim* it or merely *map* it.

⚠ **C0b — scope extended 2026-09-01, by owner decision.** `privacy.html` §14
names **LGPD (Brazil) · PIPEDA (Canada) · Singapore PDPA · Australia Privacy
Act** with zero crosswalk rows. C0 flagged the choice as "give them rows or stop
naming them". **The owner chose rows.** Add all four, plus the **PDPL** rows the
same page omits while Gulf customers are live. A regime named on a live legal
page and absent from the crosswalk is exactly the asymmetry this phase exists to
remove.
- A `not-applicable` register — SOC 1 is already established as not applicable
  (`Issues — SOC 1 is not applicable.md`); that reasoning belongs here.

**Done when:** every regime word currently on a customer-facing surface resolves
to a row in the crosswalk, or is listed as a claim to delete in C2.

⚠ **Trap:** do not write `status: met` from reading the code. `met` requires
named evidence a third party could inspect. When in doubt it is `partial`.

---

### C1 · Live obligations — the exposure that is not blocked by the freeze

**Why now:** real customers are sending PHI and EU personal data today, and none
of this touches the frozen repo.

**Deliverables**

1. **BAA draft** — HHS model language, marked `DRAFT — NOT LEGALLY REVIEWED`,
   plus a signing checklist. Gated on lawyer review before signature.
2. **GCP BAA** — Google signs BAAs for HIPAA-covered services. Establish whether
   the services in use are on Google's covered list. **Free, and blocking.**
3. **DPA + Article 46 transfer mechanism** — SCCs plus a transfer impact
   assessment for EEA → Qatar. Same `DRAFT — NOT LEGALLY REVIEWED` marking.
4. **Subprocessor list, corrected and republished.** ⚠ **My first draft of this
   list was wrong** — I read `deploy/` config and named **Stripe**, but the
   published policy names **Paddle** (merchant of record) and **Payoneer**; the
   `stripe_price_*` keys in config are the pre-Paddle remnant, and whether they
   are live is worth checking. The published §8 set is: **Google Cloud**
   (hosting), **Google (Gemini)** and **OpenAI** (judge), **Google Identity**,
   **Paddle**, **Payoneer**, **Brevo** (email, EU). Missing from it and reached
   by the code: **Alchemy/Infura** (Sepolia) and **Etherscan**. Reconcile the
   published list against what the code actually calls — and fix the country
   column, which is wrong for hosting (§9).
5. **Residency statement** — where data lives, where backups live, and what
   leaves the region. **Established 2026-09-01:** [`deploy/backup.sh`](../../deploy/backup.sh)
   writes `pg_dump` and avatar archives to `deploy/backups` **on the production
   VM itself**, 14-day retention. So backups do not leave Qatar — which answers
   residency, and raises C4's finding below.
6. **Record of processing (GDPR Art.30)** and a **breach-response plan** naming
   the processor's "without undue delay" duty to the controller.

**Done when:** each artefact exists, is marked with its review status, and the
subprocessor list matches what the code actually calls.

⚠ **Trap:** do not let a draft be signed because it looks finished. Every
unreviewed instrument carries its banner in the file itself, not just in a
commit message.

---

### C2 · Claims honesty — a register, and guards that fail the build

**Deliverables**

- `docs/compliance/claims.yaml` — every compliance claim on every customer-facing
  surface: `file`, `line`, `claim`, `backing` (a crosswalk row id), `verdict` ∈
  `{backed, qualified, delete}`.
- A **guard** extending the existing `STANDARD` scanner: a regime name appearing
  on a surface without a `backed` or `qualified` row **fails the build**.
- Apply the verdicts: qualify or delete. Expected casualties from §2 — **PCI**
  (no mode exists), **PDPL** (not covered by the policy), **ISO 27001** (not
  certified, roadmap).
- Fix the `soc2` vocabulary per §3.

**Done when:** the guard is red on a deliberately introduced unbacked claim, and
green on `main`.

⚠ **Trap — the one this repo's history is a catalogue of:** a guard that cannot
fail is worse than none. The mutation test is mandatory: add a fake claim, prove
the guard catches it, remove it.

---

### C3 · Customer-audit usefulness — the part that wins deals

**The claim to earn:** *"your auditor asks a question; Foxy answers it cold."*

**Deliverables**

- An **auditor question set** — the real questions ("every AI interaction
  touching PHI in Q3", "prove the log was not edited", "who reviewed the flagged
  ones", "what is your retention policy") mapped to what the ledger answers
  today, and what it cannot.
- Close the gaps that are genuinely close: the chain + verifier already answer
  tamper-evidence; **review/attestation of flagged events** and **retention
  policy** are the visible holes.
- **Passport as evidence map** — grouped by crosswalk clause rather than by
  `policy_tag`, so the document says *which requirement* each statistic speaks
  to. Must respect premise 7: the judge cannot assess maliciousness, so the
  Passport must not imply it does.

**Done when:** a named auditor question is answered end-to-end from an export,
with the verifier confirming the chain, and the Passport cites clauses.

⚠ **Trap:** this is UI work on the Passport and dashboard. **All three frontend
skills, `ui-ux-pro-max` first**, per `CLAUDE.md`.

---

### C4 · Foxy's own audit-readiness — everything but the auditor

**Goal, in the owner's words:** be able to *apply* the day the money exists,
without a six-month project starting then.

**Deliverables**

- Control set for **SOC 2** (and ISO 27001 where it overlaps), scoped to a
  two-person team: access control, change management, incident response, vendor
  management, onboarding/offboarding, backup/restore.
- **Evidence collection that self-evidences.** A two-person team cannot prove a
  quarterly access review from memory. Each control emits a dated artefact — a
  script's output, a signed checklist, a CI record.
- A **readiness assessment**: for each Trust Services Criterion, `implemented` /
  `partial` / `not started`, with the evidence pointer.

⚠ **A control gap already found, 2026-09-01.** [`deploy/backup.sh`](../../deploy/backup.sh)
writes every dump to `deploy/backups` **on the production VM**. The backups share
a failure domain with the database they protect: lose the VM and both go. That is
a direct finding against **SOC 2 A1.2** (availability / recovery) and **HIPAA
§164.308(a)(7)** (contingency plan), and it is the kind of thing an auditor opens
with. Off-VM, ideally off-provider, with a **restore that has actually been
tested** — an untested backup is a belief, not a control.

**Done when:** a prospective auditor could be handed the folder and give a
scoping call rather than a discovery project.

---

## 5 · The sequencing argument that is easy to get wrong

**SOC 2 Type II requires an observation window** — typically 3–12 months of
evidence that the controls *operated*, not merely existed. **That window is the
one input money cannot compress later.**

So C4's *evidence collection* starts **in parallel with C1**, not after C3. If
access reviews, change records and incident logs accumulate from now, then the
day an auditor is engaged there may already be a qualifying period behind you.
Wait, and the clock starts at zero on the day you pay.

This is the opposite of the intuitive "do compliance when we can afford it".

---

## 6 · Constraints that bind every phase

| | |
|---|---|
| **Freeze** | Nothing merges to the real repo before **2026-09-18**. Code phases build on branches here. |
| **Not greenfield** | Everything built here lands on a system with **live customers**. Schema changes and wire-contract changes need a migration path that does not break live orgs. |
| **Independently mergeable** | No long-lived mega-branch. Each phase merges on its own. |
| **Hard rules** | `CLAUDE.md` §6 — no fake data, content-blindness, no secrets. A compliance plan that violates them is self-refuting. |
| **Legal review** | Drafts carry `DRAFT — NOT LEGALLY REVIEWED` in the file. Signing is the owner's, after a lawyer. |

---

## 7 · What this plan does NOT achieve

Stated here so no one reads it as more than it is:

- **It does not make Foxy certified.** That needs an engaged auditor, money, and
  the observation window. C4 makes the application cheap; it is not the
  application.
- **It does not produce signed legal instruments.** It produces drafts. A lawyer
  reviews; the owner signs.
- **It does not make the judge able to assess maliciousness.** That is the 🔴
  provability tension, and its four candidate answers live in
  `Issues — provability vs privacy.md`. Out of scope here, and C3 must not imply
  otherwise.
- **It does not settle whether event metadata is PHI.** That is a legal question,
  and it determines how serious premise 3 is.

---

## 8 · Open questions for the owner

1. ~~Backups~~ — **answered 2026-09-01** by reading
   [`deploy/backup.sh`](../../deploy/backup.sh): same VM, 14-day retention. See
   the C4 finding.
2. **Which tiers use platform keys in production?** If no live customer grades on
   Foxy's keys, premise 3 is latent rather than live — a materially different
   risk, and worth establishing early. Answerable with one query against the
   production database; not answerable from this repo.
3. **Is PCI worth keeping at all?** Cards are detected; no PCI mode exists.
   Deleting the claim is cheap and honest; building a PCI mode is not.
4. **Is there an off-VM copy of anything today** — a manual dump, a snapshot
   schedule in GCP, anything? If GCP persistent-disk snapshots are enabled, the
   C4 finding is smaller than it reads.

---

## 9 · ⚠ C1-URGENT — two false statements are live right now

**Found by C0, verified by MAIN against the live site 2026-09-01.** These are not
roadmap items and they are not gaps. They are assertions on published pages that
are untrue, and they outrank every other item in this plan.

### 9.1 · The privacy policy states the wrong country

`https://foxyaudit.tech/privacy.html`, fetched 2026-09-01:

| where | what it says | what is true |
|---|---|---|
| §8 sub-processors | *"Infrastructure / hosting provider (Google Cloud, Ubuntu VM) — **United States**"* | GCP **`me-central1-a`, Doha, Qatar** |
| §13 transfers | *"data is processed in the **United States**"* | Qatar (plus EU for Brevo) |
| §13 mechanism | *"transferred from the EEA, UK, or Switzerland to the **United States**, we rely on the **EU Standard Contractual Clauses**"* | The EEA → **Qatar** transfer is disclosed **nowhere**, and Qatar has **no adequacy decision** |
| `trust.html` table | *"Google Cloud (Ubuntu VM) — Hosting — United States"* | same defect, second page |

⚠ **The transfer mechanism is worse than the location.** A wrong country is an
error. Naming SCCs for a destination the data never reaches means the *actual*
transfer — EEA to a non-adequate third country — has no disclosed mechanism at
all, on the page whose job is to disclose it.

### 9.2 · The SOC 2 claim contradicts itself

`faq.html:60` and `pricing.html:121`: *"We're currently completing our SOC 2 Type
I audit."* `trust.html:151`: *"no auditor is engaged yet."* One is false, and it
is the first. Verdict **delete**, not qualify — and a guard, because the vault
records this same sentence being softened once before.

### 9.3 · ⚠ DECIDED 2026-09-01 — do not raise this again

**The owner's decision, in his words: "nothing's on the frozen repo till 18,
nothing, don't ask me this again — we will merge everything once there."**

So: **option 2.** The corrections do not ship before **2026-09-18**. This is a
knowing choice by the person entitled to make it, and it is settled. Any future
session that rediscovers §9.1 or §9.2 should read this line and move on rather
than re-open it.

**What that obliges us to do instead.** If the fix cannot ship early, it must be
*finished* early, so 18 Sep is a merge and not a project:

* C2 produces the **corrected `privacy.html` §8/§13, `trust.html` table, and the
  SOC 2 sentences** as a ready branch, reviewed and guarded, sitting waiting.
* The guards land with them, so the corrected text cannot silently regress —
  particularly the SOC 2 sentence, which the vault records being softened once
  before.
* Nothing is merged to the real repo. Everything is merged **here**.

This is the same posture the owner takes to certification: have it built so the
only remaining input is the one you cannot buy — there, money; here, a date.
