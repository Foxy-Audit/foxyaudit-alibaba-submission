# Not applicable — the register

Phase **C0**, companion to [`crosswalk.yaml`](crosswalk.yaml). Written 2026-09-01
against `origin/main` `01e87ad`.

**What this file is for.** A crosswalk that silently omits a regime looks like a
regime nobody thought about. This register records the ones we *did* think about
and ruled out, with the reasoning and the trigger that would bring each back.

Being able to say *"not applicable, and here is why"* is a **stronger** position
than having the report. It is also the answer that makes a buyer's security
reviewer believe the rest of your answers.

> ⚠ Not legal advice. No entry here has been reviewed by a lawyer.

---

## 1 · SOC 1 — not applicable

**Settled 2026-08-23** after a codebase sweep; recorded in the vault as
`Issues — SOC 1 is not applicable.md` and carried here because the plan asked for
it (§4, C0) and because the question recurs.

### The rule

**SOC 1** covers controls at a service organization relevant to **user entities'
internal control over financial reporting (ICFR)** — payroll processors, payment
processors, claims administrators. **SOC 2** covers security, availability,
processing integrity, confidentiality and privacy.

⚠ **The asymmetry most people miss:** SOC 2 has predefined criteria (the Trust
Services Criteria). **SOC 1 has none — you write your own control objectives** and
the auditor opines on whether you met the objectives you wrote. An unnecessary
SOC 1 is therefore worthless, and visibly so to anyone who knows the standard.

### Why it does not apply, from the code

- **The wire payload is a closed field list and carries nothing financial:**
  `event_id`, `client_id`, `event_type`, `commitment_alg`, `prompt_hash`,
  `response_hash`, `token_count`, `policy_tag`, `pii_signals`, optional `agent`
  and `event_metadata`.
- **The stored row has no amount, no currency, no account identifier, no
  transaction reference.**
- **No money moves on a customer's behalf.** The only outbound payment path in
  the repo is Foxy charging its own customers through Paddle.
- **The policy vocabulary has no financial family.** `KNOWN_POLICY_TAGS` is
  `{default, soc2, hipaa, gdpr}` plus the aliases `hipaa_basic` and `gdpr_basic`.
  No `sox`, no `pci`.
- **The finance testbed preset refuses to invent one, in writing:** *"There is no
  PCI rule family in the SDK, and inventing one here would recreate the
  `hipaa_basic` defect."*
- **The Passport disclaims the exact assertion SOC 1 would need:** *"This is
  evidence about the SDK reporting boundary, not a claim that every model call
  was observed."* A SOC 1 auditor needs completeness over a population; Foxy
  disclaims completeness by design.

### The answer to give

> "SOC 1 covers controls over financial reporting. Our service doesn't process
> transactions or produce data that enters your financial statements, so SOC 1
> isn't applicable to us. Here's our SOC 2, which covers security, availability
> and confidentiality — that's the relevant report for what we do."

✅ When a buyer asks for SOC 1 it is almost always **procurement boilerplate**
copied from a questionnaire written for payments vendors. Ask why.

### What would make it real

A customer using Foxy to evidence controls over an AI that touches financial
reporting — invoice coding, revenue recognition, trade approval. Foxy's ledger
then becomes part of **their** ICFR chain and their financial auditor may want
assurance. ⚠ **The trigger will be a customer telling you, not a decision you
make.** Not today.

Nothing is wasted by doing SOC 2 first: SOC 1 would test the same control
discipline.

**Crosswalk row:** `SOC1-001`.

---

## 2 · PCI DSS — not applicable to Foxy as an entity; four requirements map anyway

PCI DSS is **not** wholly absent from the crosswalk, and the distinction is worth
holding: **Foxy is not a PCI entity, but four PCI requirements describe things
Foxy genuinely does for someone else.**

### Why Foxy is not in scope

- **There is no cardholder data environment.** Foxy stores no PAN, no
  authentication data, no account data of any kind (`PCI-001`, `PCI-002`).
- **Card details for Foxy's own billing are held by Paddle** as merchant of
  record — Foxy never receives them.
- The SDK's PII sweep detects **card-number patterns locally**, on the customer's
  machine, before the model call. The pattern never leaves the customer process.
  Detecting a card number is not processing one.
- **There is no `pci` policy tag.** `KNOWN_POLICY_TAGS` does not contain it.

### The overclaim trap

⚠ **Never say Foxy "does PCI."** The vault has named this as an explicit trap
since 2026-08-17: a collaborator could ask to demo a PCI feature that does not
exist. The word appears on exactly one customer-facing surface —
`foxy-dashboard/foxy-audit-premium.html:2360`, *"Any interaction tagged pci, sox,
hipaa, gdpr or eu_ai_act…"* — and three of those five tags are not SDK tags at
all. That entry is `qualify` in `surface_claims`, and C2 owns it.

### What maps anyway

`PCI-003` through `PCI-007` are real, and `PCI-004` (Req. 10.3.2, *"audit log
files are protected to prevent modifications by individuals"*) is the
**best-fitting PCI requirement in the entire standard for what Foxy actually is**
— a log-integrity requirement, not a card requirement. Worth remembering the next
time someone asks whether to build a PCI mode: the answer is that Foxy already
speaks to the logging half of PCI and will never speak to the card half.

**Crosswalk rows:** `PCI-001`, `PCI-002` are `not-applicable`; `PCI-003`–`PCI-007`
are `partial`/`gap`.

---

## 3 · EU AI Act — provider obligations are not applicable to Foxy

Foxy is **not a provider of a high-risk AI system** and **not a deployer of one**.
It is a record-keeping tool a deployer uses.

- **Art. 12 (record-keeping)** binds the *provider*. `EUAI-001` is marked
  `not-applicable` and kept in the file rather than deleted, precisely because it
  is the clause a customer-provider would use Foxy *toward*. ⚠ **Do not quote
  `EUAI-001` as Foxy satisfying Art. 12.**
- **Art. 26(6)** — the *deployer's* duty to keep automatically generated logs for
  at least six months — is the clause the product actually serves. It is
  `EUAI-002`, and it is `partial`, not `not-applicable`.

The distinction is the whole EU AI Act story: **we do not comply with the AI Act;
we hold the logs that let a customer comply with it.**

**Crosswalk rows:** `EUAI-001` is `not-applicable`; `EUAI-002`–`EUAI-005` are not.

---

## 4 · GDPR Art. 45 (adequacy) — not applicable, and that is the problem

`GDPR-008` is marked `not-applicable` for an unusual reason: **the route is
closed, not irrelevant.** There is no European Commission adequacy decision for
Qatar, and production runs in GCP `me-central1-a` (Doha).

It is recorded so that nobody proposes Art. 45 as the answer to `GDPR-007`.
**Art. 46 (appropriate safeguards — SCCs plus a transfer impact assessment) is
the only route**, and it is `GDPR-009`, a `gap`.

---

## 5 · What is *not* in this register, and must not be added to it

Recorded so the register cannot become a place to park inconvenient findings.

- **HIPAA is not here.** There are live healthcare customers sending PHI today. A
  missing BAA is a `gap` (`HIPAA-008`), not a scoping question.
- **GDPR is not here.** There are live EU/UK customers. The residency
  misstatement is a `gap` (`GDPR-007`), not a scoping question.
- **PDPL (Saudi and UAE) and Qatar Law 13/2016 are not here.** They are
  `MAPPED-ONLY` in the crosswalk because no surface names them — which is itself
  a finding, since live Gulf customers exist and the published privacy policy
  does not cover PDPL. `MAPPED-ONLY` means *"we say nothing about it"*, never
  *"it does not apply to us."*
- **ISO 27001 is not here.** Not certified is not the same as not applicable. It
  is a roadmap item with twelve `partial`/`gap` rows.

**The rule:** an entry belongs in this register only when a *structural fact about
what Foxy is* puts the requirement out of reach — no money moves, no cards are
stored, we are not the provider. *"We have not done it yet"* is a `gap` in
`crosswalk.yaml`. *"It cannot apply to us"* is an entry here. Anything ambiguous
is a `gap`.

---

## Adding an entry

1. State the regime or clause, and the **structural fact** that puts it out of
   reach. Not "we don't do that yet" — *what Foxy is* has to make it impossible.
2. Cite the evidence from the code, the schema or a published page. Every claim
   in §1 above is anchored to something a reader can open.
3. Write **the answer to give** when a buyer asks — a paragraph someone can say
   out loud in a call.
4. State **the trigger that would make it real**, and who pulls it. In §1 it is a
   customer telling you; it is almost never a decision Foxy makes alone.
5. Add the matching `not-applicable` row to `crosswalk.yaml`, with its `notes`
   pointing here. The two files must not be able to disagree.
