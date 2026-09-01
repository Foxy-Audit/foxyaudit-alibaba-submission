# Incident Response Plan — Foxy Audit

**Phase C1, deliverable 6**, of [`docs/plans/compliance-program.md`](../plans/compliance-program.md).
Written 2026-09-02 against `origin/main` at **`ac7b2f0`**. Derived from
[`auditor-questions.yaml`](auditor-questions.yaml) **AQ-023** and the eighteen
crosswalk rows it names.

> ⚠ **THIS IS NOT LEGAL ADVICE.** It is engineering research written by a
> two-person team with no legal budget. No sentence in it has been reviewed by a
> lawyer. Every deadline is cited to a source, and where a source could not be
> verified the entry says **TBD** rather than guessing — because during a real
> incident someone will act on a number in this table, and a plausible wrong
> number is worse than an admitted gap. Items marked **⚖ COUNSEL** are questions
> this document deliberately refuses to answer.

> **Status: this plan has never been exercised.** Until §10's tabletop has been
> run and its artefact dated, this is a document, not a control. That is the same
> distinction as an untested backup (`#291`) and it is not a technicality — it is
> the difference between `gap` and `partial` in the crosswalk.

---

## For future Claude

**Eighteen crosswalk rows across twelve regimes close on this one file.** That is
the highest ratio in the whole compliance programme, and it is why AQ-023 is
ranked second in `highest_value_to_close` behind only the verification bundle.

Three things about it are easy to get wrong, and all three are recorded here so
nobody has to rediscover them:

1. **There is no single deadline.** The twelve regimes genuinely disagree, and
   writing "72 hours" would be wrong for most of them — including for the one
   everybody quotes it from. See §2.
2. **Foxy is usually the *processor*, not the controller.** Most of these duties
   run to the *customer*, who then runs to their regulator. Getting this
   backwards makes the plan promise things Foxy does not owe and miss the one
   thing it does. See §1.
3. **The document already existed as a promise.** `privacy.html` §15 and
   `dpa.html` §10 were published before any plan stood behind them. §0 says
   plainly whether they were deliverable.

---

## 0 · ⚠ The published promise, and whether it was deliverable

**This is not a missing document. It is a published promise with nothing behind
it.** Two live pages already commit to breach notification:

- **`privacy.html` §15** — *"In the event of a security incident that we
  determine is reasonably likely to result in unauthorized access to, or
  disclosure of, personal data we hold, we will notify affected workspace
  administrators without undue delay and in accordance with applicable law,
  together with a description of the nature of the incident and the steps being
  taken in response."*
- **`dpa.html` §10** — *"Foxy Audit will notify Customer **without undue delay**
  after becoming aware of a security incident affecting Customer's personal data
  … and will provide information reasonably available to it about the incident's
  nature and scope, and the steps taken in response, to support Customer's own
  regulatory notification obligations."*

### The verdict, in one line

**§15 is not a false statement, and it is not deliverable as written — for a
reason that is not visible in its own text.** Take its four elements in turn:

| §15 promises | Deliverable before this document? | Why |
|---|---|---|
| *"that we determine is reasonably likely to…"* | **No** | A determination requires a severity standard. None existed. §4 supplies one. |
| *"notify affected workspace administrators"* | **Yes — mechanically** | `organizations.contact_email` and `users.email` exist, and `backend/app/email.py` sends through Brevo. The recipients and the channel were always there. |
| *"without undue delay"* | **No** | A delay clock starts at *awareness*. §6 is why awareness is the weak link. |
| *"in accordance with applicable law"* | **No** | Nobody had enumerated what applicable law required. §2 is that enumeration, and it is the element this document actually supplies. |

So the honest characterisation is: **§15 is a conditional promise whose condition
Foxy is poorly equipped to trigger.** It could be satisfied vacuously by never
detecting anything — which is a materially different defect from `privacy.html`
§8's flat misstatement of the hosting country (that one is a false statement of
fact; this one is a capability the company had not built). With §2, §4, §6 and
§10 in place, §15 becomes deliverable **in substance**; with §6's detection
dependency still open, it remains deliverable **only for incidents somebody tells
us about.**

`dpa.html` §10 is the stronger of the two and the better-drafted: it names
"becoming aware", commits to supporting the customer's own regulatory duties, and
therefore correctly describes Foxy as the upstream half of somebody else's clock.
That is exactly the posture §1 establishes. **No change is recommended to §10.**

### ⚠ Recorded for the next correction batch — NOT changed here

Both pages are frozen published surfaces and are C2's scope. This document edits
neither. Two observations for whoever opens that batch:

- **`privacy.html` §15 has no pointer to a plan and no stated clock.** The
  recommendation is a pointer, **not a number.** Publishing "we will notify you
  within N hours" creates a contractual duty tighter than any statute in §2
  imposes on Foxy, on a page that cannot be edited quickly. The wording "without
  undue delay" is correct and matches GDPR Art. 33(2) and PDPA s. 26C(3)(a) —
  keep it, and add a reference to this plan's existence.
- **§15 says "personal data we hold".** Given §3, the more accurate and more
  reassuring statement is about what Foxy holds *and does not hold*. §15 is the
  one place in the policy where content-blindness would materially reduce a
  reader's alarm and it is not mentioned. That is a drafting improvement, not a
  correction, and it is worth strictly less than the §8 residency fix already
  queued.

---

## 1 · Scope, and the posture that governs everything below

**Scope.** An *incident* is any event affecting **Foxy Audit's own systems** —
the production VM and database in GCP `me-central1-a`, the three ASGI apps, the
worker, the outbound provider calls, the staff console, or a subprocessor acting
for Foxy — that compromises, or is reasonably suspected of compromising, the
confidentiality, integrity or availability of data Foxy holds.

**Out of scope, deliberately.** The in-product policy-breach alerts a customer
configures for their own AI traffic are *not* incidents under this plan. That
distinction is already drawn in `privacy.html` §15's second paragraph and it
matters: a customer's prompt tripping a `hipaa` rule is the product working, not
a breach of Foxy.

### The posture: Foxy is usually the processor

| Data | Foxy's role | Consequence |
|---|---|---|
| **Workspace / ledger data** (commitments, metadata, verdicts) | **Processor** — GDPR/LGPD; **business associate** — HIPAA; **data intermediary** — PDPA SG | The duty runs to **the customer**, not to a regulator. The customer then owes their own regulator on their own clock. |
| **Account data** (the customer's own users, emails, billing, sign-in logs) | **Controller** | Foxy owes the data subject and, where a regime binds it, the regulator directly. |
| **Marketing / site visitors** | **Controller** | Same as account data. |

⚠ **This split is the single most consequential fact in the document.** A plan
written as though Foxy owes a supervisory authority a 72-hour notification for
workspace data would be promising something Foxy does not owe — and would miss
the duty it does owe, which is to be *fast enough that the customer can still
meet theirs*. See §2's closing paragraph.

⚖ **COUNSEL.** Whether Foxy is an "APP entity" under Australian law at all
(small-business exemption plus the Australian-link test), whether Qatar Law
13/2016 binds Foxy through hosting alone, and whether ledger metadata is
identifiable — and therefore PHI or special-category data — are open legal
questions. The crosswalk records all three as TBD and this document does not
resolve them.

---

## 2 · The duty table — twelve regimes, eighteen rows, no single number

**The rule this table is built to:** every clause and every period is quoted from
the crosswalk row that carries its verified source. Where the crosswalk says
`TBD`, this table says TBD. **Nothing here was inferred, rounded, or
remembered.**

Column meanings: **Foxy's posture** is the capacity in which the duty reaches
Foxy; **Runs to** is who must be told; **Clock** is the period *as stated in the
verified source*, not as commonly reported.

| Crosswalk row | Regime · clause | Foxy's posture | Runs to | Clock |
|---|---|---|---|---|
| **HIPAA-004** | HIPAA · 45 CFR 164.308(a)(6)(ii) — *Response and reporting* (Required) | Business associate | Internal — identify, respond, mitigate, **document** | No external period. The documentation duty is standing. |
| **HIPAA-017** | HIPAA · 45 CFR 164.410 — *Notification by a business associate* | Business associate | The **covered entity** (the customer) | *"Without unreasonable delay and in no case later than **60 calendar days** after discovery."* |
| **SOC2-006** | SOC 2 · CC7.3 — evaluate security events | The entity itself | Internal — evaluate, then act | No period. It is a control that must **exist and operate**. |
| **GDPR-006** | GDPR · Art. 33(2) | **Processor** (workspace data) | The **controller** (the customer) | *"Without undue delay after becoming aware."* ⚠ See note A. |
| **ISO-005** | ISO 27001 · A.5.24 — incident management planning | The organisation | Internal — define, establish, **communicate** roles | No period. ⚠ Secondary source. |
| **ISO-011** | ISO 27001 · A.8.16 — monitoring activities | The organisation | Internal — monitor, evaluate | No period. ⚠ Secondary source. See §6. |
| **PCI-007** | PCI DSS v4.0.1 · Req. 12.10.1 — an IR plan exists and is ready to activate | ⚠ **Not a PCI entity** — see note B | n/a | No period. |
| **UAE-003** | UAE PDPL · Federal Decree-Law 45/2021 Art. 9(3) | **Processor** | The **Controller** | *"As soon as it becomes aware of the same."* Art. 9(1)/(2) bind the Controller and defer the period to the Executive Regulations — **no inline deadline exists**. |
| **QAT-001** | Qatar Law 13/2016 · Art. 11(5) | ⚖ TBD — see note C | Internal PD management system + report breaches of protection measures | No period. |
| **QAT-003** | Qatar Law 13/2016 · Art. 14 | Controller (⚖ if in scope) | The individual **and** the Competent Department | **72 hours from detection**, per the NCSA guideline. Penalties QAR 1,000,000 (Art. 23) / 5,000,000 (Art. 24). |
| **KSA-004** | Saudi PDPL · **clause TBD** | ⚖ TBD | Competent authority + affected data subjects | **TBD.** 72 hours is widely reported and the **article number could not be verified**. See note D. |
| **LGPD-004** | LGPD · Lei 13.709/2018 Art. 48 | **Controlador** for account data; **operador** for workspace data | ANPD **and** the data subject | *"Within a reasonable period as defined by the authority"* (§1). **No fixed number in the statute.** |
| **PIPEDA-003** | PIPEDA · s. 10.1(1) and s. 10.1(3) | The organisation | The **Commissioner** and the **individual** | Trigger is *"real risk of significant harm"*. **The verified subsections state no period** — see note E. |
| **PIPEDA-004** | PIPEDA · s. 10.3 — **the register** | The organisation | Nobody — it is a **record**, not a notice | **No trigger and no clock. This obligation is live right now.** See §9. |
| **SGP-004** | Singapore PDPA · s. 26C(3)(a) | **Data intermediary** — Foxy's own duty | The **other organisation** (the customer) | *"Without undue delay."* ⚠ The PDPA row that binds Foxy directly. |
| **SGP-005** | Singapore PDPA · s. 26D(1) | The organisation (Foxy, for its **own** account data) | The **Commission** | *"As soon as is practicable, but in any case no later than **3 calendar days** after the day the organisation makes that assessment."* **Tightest period in the file.** |
| **AUS-004** | Australia Privacy Act · s. 26WH(2) | APP entity (⚖ TBD) | Internal — complete the **assessment** | *"All reasonable steps to complete… within **30 calendar days** after the day it became aware of the grounds."* |
| **AUS-005** | Australia Privacy Act · s. 26WK(2) and s. 26WL(3) | APP entity (⚖ TBD) | The **Commissioner**, then **individuals** | Statement to the Commissioner *"as soon as practicable after becoming aware"*; individuals *"as soon as practicable after completing that statement."* |

### ⚠ Notes on individual rows

**A · The 72 hours everybody quotes is not ours.** GDPR's 72-hour period is
**Art. 33(1)** — the *controller's* duty to its supervisory authority. Foxy's
duty for workspace data is **Art. 33(2)**, which has no number at all: *without
undue delay to the controller*. Writing "72 hours" into this plan would attach
the customer's deadline to Foxy and quietly drop the fact that Foxy's own
notification has to land **inside** that 72 hours for the customer to make it.

⚠ **Art. 33(1) is not one of the eighteen rows and this document does not assert
it.** For *account* data Foxy is the controller, so an Art. 33(1) duty is at
least arguable — but to which supervisory authority, given Foxy has no EU
establishment, and whether an Art. 27 representative is required first, are
questions the crosswalk does not answer. **⚖ COUNSEL.**

**B · PCI does not bind Foxy, and PCI-007 still closes.** Per
[`not-applicable.md`](not-applicable.md) §2, Foxy is not a merchant, not a
service provider in a cardholder data environment, and stores no account data —
Paddle is the merchant of record. PCI-001 and PCI-002 are `not-applicable` for
exactly that reason. **PCI-007 is in AQ-023's list anyway, and it closes not
because PCI applies but because the requirement describes a plan Foxy needs for
eleven other reasons.** Never cite this row as evidence that Foxy "does PCI" —
the vault has flagged that as an explicit trap since 2026-08-17.

**C · Qatar reaches Foxy through hosting, not through customers.** Production
runs in GCP `me-central1-a`, Doha. Whether hosting alone brings Foxy within Law
13/2016 is a legal question the crosswalk records as TBD, and this document does
not decide it. **Plan as though it does**: 72 hours from detection (QAT-003) is
the second-tightest external period in the table and the cost of assuming it
applies is low.

**D · The KSA article number is TBD, deliberately.** Two secondary sources
disagree (Art. 18 vs Art. 20) and the official SDAIA English PDF is not
machine-fetchable. C0b re-checked it and **still would not resolve it** — the
index that looked like corroboration was independently measured wrong elsewhere.
The 72-hour period is well attested; the article number is not. **Do not fill
this in from memory during an incident.** Treat the *period* as real and the
*citation* as unavailable, and resolve it from the official text or from counsel
before it is quoted to anyone.

**E · PIPEDA's period is not in the verified quote.** The crosswalk quotes
s. 10.1(1) and s. 10.1(3), and neither states a deadline. s. 10.1(2) is not in
the crosswalk and is not quoted here. **TBD** — resolve against the primary
source (Justice Laws Canada) before this row is relied on. The register duty
(PIPEDA-004) is unaffected and is the more urgent half.

### ⚠ The operational conclusion, which is not in any row

**Foxy's deadline is not Foxy's deadline. It is the customer's deadline minus
their processing time.**

Every processor-side duty in the table is worded without a number — *without
undue delay*, *as soon as it becomes aware*, *forthwith* (QAT-002). The numbers
all sit **downstream**, on the customer:

```
  Foxy becomes aware
        |
        |  <-- "without undue delay"  (GDPR 33(2), SGP 26C(3)(a), UAE 9(3))
        |      NO NUMBER. This is the part Foxy controls.
        v
  Customer becomes aware
        |
        |  <-- 72h to their supervisory authority   (GDPR 33(1))
        |  <-- 3 calendar days from assessment      (SGP 26D(1))
        |  <-- 72h from detection                   (QAT-003, if in scope)
        v
  Regulator
```

A Foxy notification that takes 48 hours has spent two thirds of a Singaporean
customer's budget before they have read the first sentence. **So the plan adopts
a self-imposed internal target that no statute requires:**

> **Target: notify affected customers within 24 hours of the severity
> determination in §4, and within 72 hours of first awareness regardless of
> whether the determination is complete.** An incomplete notification that says
> *"we are still assessing, here is what we know"* is worth more to a customer on
> a 3-day clock than a complete one that arrives after it.

⚠ **This target is internal and is deliberately NOT published.** See §0 — putting
a number on `privacy.html` creates a duty tighter than any statute above. The
target governs Foxy's own conduct and is measured in the register (§9).

---

## 3 · What a Foxy breach actually exposes

**Nobody outside this team can write this section, and it is the reason the
document is worth reading rather than filing.** Generic breach plans assume the
breached system holds the sensitive material. Foxy's does not — and the honest
statement is neither "we hold nothing" nor a generic SaaS worst case.

### The two breach classes are materially different

This is the distinction most likely to be got wrong under pressure, so it comes
first.

| | **Class DB** — database only | **Class VM** — host compromise |
|---|---|---|
| Example | stolen DB credential, SQL-layer access, a restored snapshot leaking | root on the production VM, or the GCP project |
| BYOK provider keys | **Ciphertext only.** `*_key_enc` is Fernet, org+provider-bound | ⚠ **Plaintext.** The KEK lives in `deploy/.env` **on the same VM** |
| Chain integrity | Rewritable, and the chain recomputes — see below | Same, plus the anchoring key path |
| Escalation | Bounded by what the tables hold | Unbounded within the deployment |

⚠ **The KEK and the ciphertext it protects share a host.** That is a real and
currently accepted design fact — `deploy/.env` is where the key must be for the
backend and worker to start — and it means **Class VM must be treated as full
BYOK key compromise from the first minute**, with no waiting for confirmation.
Every affected customer's Gemini and OpenAI keys are then revoke-and-rotate,
immediately, on their side. That is the single most time-critical customer action
in this entire plan and it is *not* a personal-data notification duty at all.

### What is NOT exposed — structurally, not by policy

- **Raw prompt and response text.** It is not in the schema. `audit_logs` carries
  `prompt_hash` and `response_hash` as `String(64)` and there is no column that
  could hold plaintext. `privacy.html` §3 states this publicly and it is true.
- **Plaintext API keys.** `organizations.api_key_hash` and `api_keys.key_hash`
  are peppered HMAC-SHA-256; the plaintext is shown once and not retained.
- **Passwords.** `password_hash` (bcrypt) only, customer and staff alike.
- **Session tokens.** Only SHA-256 `token_hash` is stored, for both cookie realms.
- **Card data.** None, anywhere. Paddle is the merchant of record.

### What IS exposed, in a database-only breach

Being precise here is the point. The honest blast radius is far smaller than a
typical SaaS breach, **and it is not zero.**

1. **Organisation identity.** `organizations.name`, `contact_email`, `plan_tier`,
   Paddle customer and subscription ids, `subscription_status`, and
   `past_due_since` — i.e. *that a named company was behind on payment*.
2. **User identity.** `users` — name, email, role. `staff_users` likewise.
3. **Timing and volume, at per-event resolution.** `audit_logs.occurred_at`,
   `created_at`, the per-org monotonic `seq`, `token_count`, and the
   `usage_daily` rollups. Together these are a detailed operational profile of a
   named customer's AI usage: when they run, how much, at what hours, growing or
   shrinking. This is commercially sensitive on its own.
4. **Policy verdicts and signal labels.** `policy_tag`, `pii_signals`,
   `local_verdict`, `verdict_hash`, `gemini_verdict`, and `agent`.
   ⚠ **This is the sharpest edge in the list.** It discloses *that organisation X
   was processing interactions the SDK labelled as PHI-bearing, at a stated time,
   in a stated volume* — an inference about health-related processing by an
   identified company, drawn without ever seeing a word of content.
   ⚖ **COUNSEL:** whether that inference is itself special-category data, or PHI,
   is exactly the open question the crosswalk records against `platform_keys` and
   premise 3 of the plan. **Assume it is, for response purposes.**
5. **Allow-listed event metadata.** `event_metadata` is validated at ingest
   against a fixed key list: `request_id`, `trace_id`, `session_id`, `provider`,
   `model`, `id`, `usage`, `choice_count`, `tool_names`, `retrieval_refs`,
   `client_seq_gap`, plus `decision`, `blocked_reason`, `policy_rules`.
   ⚠ **`tool_names` and `retrieval_refs` are customer-supplied strings.** They are
   bounded in *shape*, not in *sensitivity* — a customer's internal tool and
   corpus names can be commercially revealing, and the threat model already tells
   customers to treat this metadata as potentially sensitive.
6. **Sign-in telemetry with plain IPs.** `login_events` holds email, **plain
   `ip`**, `user_agent` and success/failure, 90-day retention per
   `privacy.html` §9. Staff-action logs run 365 days.
7. **Marketing and consent records.** `marketing_leads` (name, email, company,
   message), `traffic_events`, `consent_events` (IP/UA hashed).
8. **Billing records.** `invoices`, `payment_events`, Paddle identifiers.
9. **The internal audit trail.** `admin_actions` and `account_actions` — a record
   of what staff and customer admins did, which is itself a map of the system.

### ⚠ The commitment column is not uniformly opaque

`commitment_alg` takes three values, written by
[`sdk/src/foxy_audit/client.py`](../../sdk/src/foxy_audit/client.py):

| Value | What a Foxy-side attacker can do with the hash |
|---|---|
| `hmac-sha256` | **Nothing.** HMAC keyed with the customer's key, which never reaches Foxy. |
| `hmac-sha256-salted` | **Nothing**, twice over — the per-event salt lives only in the customer's local sidecar. |
| `sha256-legacy` | ⚠ **Plain SHA-256.** The threat model's guessing oracle applies: an attacker who already suspects a short, low-entropy prompt can hash candidates and compare. Not a disclosure of content — a *confirmation* of a guess. |

**Response consequence:** a notification must state which algorithm the affected
org's rows used. For a `sha256-legacy` org the honest sentence is *"an attacker
who already knows what your prompts probably said can confirm it"*, which is
weaker than disclosure and stronger than nothing. **Do not flatten the three
cases into one reassuring sentence.**

### ⚠ And the consequence that is not about disclosure at all

The threat model states it plainly: *"a database administrator with sufficient
access can rewrite both rows and locally recomputed hashes unless an
independently trusted export, root, or public anchor exists."*

So the most serious product consequence of a Foxy breach is **not that data
leaked — it is that the ledger's evidentiary value is retrospectively in
question** for every customer who holds neither an independent export nor a
confirmed anchor. That is the thing Foxy sells.

**This creates three response steps no generic plan contains** (see §7, step 6):

1. Publish the chain head (`root_hash`, `last_seq`) for every org **as recorded
   before the compromise window**, from whatever trustworthy copy exists.
2. Tell each customer to re-verify their most recent export with
   `verifier/foxy_verify.py` and to compare it against that published head.
3. For orgs with `chain_anchors.status = 'confirmed'`, point at the on-chain
   receipt — it is held by nobody at Foxy and is the strongest available evidence
   that the pre-incident chain is what Foxy says it was.

⚠ **Step 1 has a dependency nothing currently satisfies.** There is no off-host
periodic record of chain heads. The GCP snapshots (daily, `eu` multi-region,
14-day retention) are the only off-VM copy, they are crash-consistent
(`guestFlush: false`), and **no restore has ever been tested** (`#291`, AQ-024).
Anchoring is optional and per-org. **Recorded as a gap, not solved here** — it is
a C4 control and it belongs in the register of things this plan depends on and
does not provide.

---

## 4 · Severity — the determination `privacy.html` §15 requires

Four levels. The only judgement that matters is **SEV-2 vs SEV-3**, because SEV-2
starts the notification clocks in §2.

| | Definition | Examples | Consequence |
|---|---|---|---|
| **SEV-1** | Confirmed unauthorised access to production data **or** the VM. Class VM until disproved. | Root on the VM; a leaked DB credential used; a restored snapshot found readable by a third party | Everything in §7. BYOK rotation immediately. |
| **SEV-2** | Reasonable belief that personal data was accessed, disclosed, altered or lost — **the `privacy.html` §15 trigger, and the AUS-004 "grounds to suspect" trigger** | Staff account compromise with data-plane access; an org's data returned to another org; ledger rows inconsistent with the chain and not explained | Notification clocks start. Register entry. |
| **SEV-3** | A security event with **no** reasonable belief of data access | Blocked intrusion attempt; a dependency CVE patched before exploitation; credential stuffing that failed | **Register entry anyway — PIPEDA-004 requires it.** No notification. |
| **SEV-4** | Availability only, no confidentiality or integrity question | An outage; a failed deploy that rolled back | Register entry optional. Not a personal-data breach. |

⚠ **When SEV-2 and SEV-3 are genuinely arguable, it is SEV-2.** The cost of a
wrong SEV-2 is an unnecessary notification and an awkward email. The cost of a
wrong SEV-3 is a missed statutory duty across twelve regimes, discovered later,
with a dated register entry proving Foxy chose the lower grade. **The register
makes the wrong call permanent, so make the safe one.**

⚠ **AUS-004's 30 days is an assessment window, not a grace period.** It starts at
*grounds to suspect* — i.e. at SEV-2 — and it is the only place in §2 where the
law explicitly allows time to think. Do not read it as permission to be slow
anywhere else; SGP-005's three days and QAT-003's 72 hours run in parallel.

---

## 5 · Roles — written for two people, one of whom may be asleep

**The team is two: the owner (Ali) and one other person.** This plan requires no
security team, no on-call rotation, and no communications lead, because there is
nobody to fill those seats. Every role below is a *hat*, and **one person can and
often will wear all of them.**

| Hat | Who | What they own |
|---|---|---|
| **Incident Lead** | Whoever becomes aware first, until explicitly handed over | Declares the incident, assigns severity (§4), owns the clock, decides when to notify. **The Lead's job is to decide, not to fix.** |
| **Technical Responder** | The other person, or the same one | Containment, evidence preservation, the chain-head capture in §7 step 6 |
| **Recorder** | **The Lead** — not delegated | Every timestamp in §9's register, written **as it happens**, not reconstructed |
| **Notifier** | The owner (Ali) | Sends customer notifications. ⚠ Reserved to the owner because these are contractual statements to customers. |

### The rules that make it work at 3am

1. **The first person to become aware is the Lead.** No escalation step, no
   waiting for the owner to wake up. Downgrading later is fine; a two-hour pause
   waiting for permission is not.
2. **The Lead may declare SEV-2 alone.** One person, no second opinion required.
3. **Notification requires the owner.** If the owner is the Lead, no handoff. If
   not, the Lead wakes the owner — **for SEV-1 and SEV-2, at any hour.** This is
   the only escalation in the plan and it exists because §2's clocks are short and
   the owner is the only one who may speak to customers.
4. **Record first, fix second, when they conflict.** A one-line timestamp costs
   ten seconds. A reconstructed timeline three days later is the thing an auditor
   will not believe, and it is what makes the difference between an incident that
   was *handled* and one that merely *ended*.
5. **⚠ Segregation of duties is not achievable here, and pretending otherwise is
   worse than admitting it.** With two people the Lead and the Responder are often
   the same person. The compensating control is the register: contemporaneous,
   append-only, and reviewed by the other person afterwards. Say this to an
   auditor rather than drawing an org chart with empty boxes in it — auditors
   accept small-team SOC 2, and they do not accept a control set describing a
   company that does not exist.

⚠ **Named security officer.** HIPAA 164.308(a)(2) requires one, AQ-026 records
that nothing names one anywhere, and it is the cheapest row in the crosswalk.
**This plan does not close it** — the officer belongs in a security policy
document, not an IR plan, and naming a person here would be the wrong file
answering the right question. Recorded, and left open.

---

## 6 · Detection — and the dependencies it rests on

**A plan whose first step is "we become aware" must say how.** Every clock in §2
starts at awareness, so this section is load-bearing, and it is the weakest part
of the document.

### The four channels, honestly rated

| Channel | Status | Assessment |
|---|---|---|
| **A customer tells us** | Works | The most likely channel today, and it means Foxy learns second. |
| **Google tells us** | ⚠ **BROKEN — see below** | Should be first for infrastructure compromise. Currently is not. |
| **A subprocessor tells us** | Untested | OpenAI, Google, Brevo, Paddle, Payoneer, Alchemy/Infura, Etherscan. Whether each has a working contact route to Foxy is unverified. |
| **We notice** | ⚠ **Weak** | See below. |

### ⚠ Dependency 1 — GCP Essential Contacts are not set

**Google's breach and security notifications go to whoever is listed in GCP
Essential Contacts.** Task **C2** of the vault's `Compliance — owner action
checklist` records that the **Legal and Security contacts are not yet set**.

Until they are, Google's notice reaches the project's billing contact at best,
and possibly nobody who would recognise it. **This is a two-minute fix (Console →
IAM & Admin → Essential Contacts) and it is the highest-leverage single action in
this entire document**, because it is the difference between "we were told" and
"we found out from a customer" for the whole class of infrastructure incidents.

> **⚠ THIS GAP STANDS AS OF 2026-09-02 AND THE PLAN NAMES IT RATHER THAN
> ASSUMING IT AWAY.** If it is still open when this plan is next reviewed, the
> honest answer to an auditor asking "how would you learn of a breach at your
> hosting provider?" is *"we would not, reliably."*

### ⚠ Dependency 2 — nothing monitors Foxy's own infrastructure

This is ISO-011's finding and it is accurate. What exists:

- `backend/app/observability.py` — **request correlation IDs and structured
  logging.** Useful for tracing a request. It raises no alert and evaluates
  nothing.
- `deploy/docker-compose.prod.yml` — **no `logging:` stanza at all.** Container
  logs sit on the VM under Docker's default driver. They are not shipped
  anywhere, not aggregated, and not retained under a stated policy.
- `.github/workflows/deploy.yml` — a `/health/ready` smoke test with automatic
  rollback. **That is deploy-time health checking, not monitoring**, and it
  catches a bad release, not an intruder.
- `login_events` records failed sign-ins with plain IPs, and `worker_heartbeat`
  records worker liveness. **Both are queryable and neither alerts.**

⚠ **SOC2-005 must not be cited to fill this hole.** The judge monitors *customer
AI activity metadata*. It has no visibility into Foxy's own infrastructure, and
it cannot assess maliciousness at all — it sees only hashes and counts. The
crosswalk carries that warning on the row itself, and it is the correct one.

**So: Foxy's realistic detection posture is that it learns of an incident when
somebody tells it.** That is stated here rather than hidden, because §2's clocks
all start at awareness and a plan that overstates detection produces a false
sense of a clock that has not started.

⚠ **The cheapest real improvements, recorded and not built here** (C4 scope, not
docs): a daily query over `login_events` for failed-login spikes; an alert when
`worker_heartbeat` goes stale; and log shipping off the VM so a host compromise
cannot erase its own traces. **None of the three is in this document's scope, and
none should be claimed as existing.**

---

## 7 · The procedure

Nine steps. **Steps 1–3 are the ones that must happen from memory at 3am**; the
rest can be read off this page.

**1 · Declare, and start the record.** The first person aware is the Lead. Open
a register entry (§9) with the awareness timestamp **before doing anything
else.** ⚠ *The awareness timestamp is the only one that cannot be recovered
later, and every clock in §2 runs from it.*

**2 · Contain.** Stop the bleeding: revoke the compromised credential, session,
API key or staff account; take the surface offline if that is what it takes. Step
2 outranks step 3 — an incident still in progress is worse than a lost artefact.

**3 · Preserve.** Before rebuilding anything: capture container logs off the VM
(nothing ships them — see §6), snapshot the disk, and record the current
`root_hash` and `last_seq` per org from `chain_anchors` and from the live chain.
⚠ **A rebuild destroys the evidence that decides what was and was not accessed,
and therefore decides who must be notified.**

**4 · Assess severity** against §4. If SEV-1 or SEV-2 and the Lead is not the
owner, **wake the owner now.**

**5 · Scope it.** Which class — DB or VM (§3)? Which orgs? Which data categories
from §3's list? Which `commitment_alg` values? Were BYOK keys within reach — and
remember that **Class VM means yes, immediately, without waiting for
confirmation.**

**6 · The Foxy-specific step: establish what the ledger can still prove.** Publish
each affected org's pre-incident chain head; tell customers to re-verify their
most recent export against it with `verifier/foxy_verify.py`; and point orgs with
a confirmed `chain_anchors` row at their on-chain receipt. ⚠ **Do this even when
no data was disclosed.** A customer's auditor will ask whether the ledger was
altered, and "we checked, and here is the independently-held root" is an answer
only Foxy's architecture can give — while "we don't believe so" is not an answer
at all.

**7 · Notify**, per §2 and §8. Target: 24 hours from the severity determination,
72 hours from awareness regardless. **Partial beats late.**

**8 · Remediate**, and record what changed. HIPAA-004 requires mitigation *and*
documentation of the outcome, so a fix with no register entry does not discharge
the clause.

**9 · Review within seven days.** What happened, what was slow, what the plan got
wrong. ⚠ **Edit this file as part of the review.** A plan that survives an
incident unchanged was probably not consulted during it.

---

## 8 · What a notification must contain

The union of what §2's regimes ask for, so one template satisfies all of them.
`privacy.html` §15 and `dpa.html` §10 already commit to items 2 and 6.

1. **That this is a breach notification**, in the subject line. Not "an important
   security update".
2. **The nature of the incident** — what happened, plainly.
3. **When**: awareness timestamp, and the compromise window if known.
4. **What data was involved**, using §3's categories — and **what was not**.
   ⚠ *State the content-blindness fact explicitly and accurately: raw prompts and
   responses are not held by Foxy and cannot have been disclosed by Foxy. This is
   true, it is the single most reassuring sentence available, and it must be
   stated in the same breath as the things in §3 that WERE exposed. Stating only
   the first half is the failure mode.*
5. **Their `commitment_alg` posture**, per §3's table.
6. **What Foxy is doing** about it.
7. **What they must do** — rotate BYOK keys (immediately, for Class VM), rotate
   the Foxy API key, re-verify their export against the published chain head.
8. **⚠ That they may have their own notification duty, and their clock has
   started.** This is what `dpa.html` §10's *"to support Customer's own
   regulatory notification obligations"* commits to, and it is what a customer
   most needs and is least likely to be told by a vendor.
9. **A named human to reply to**, and when the next update will come.

⚠ **Templates are not written here, deliberately.** A pre-written template with
blanks invites filling in a shape that does not match the incident, and this list
is short enough to work from directly. What §10's tabletop produces instead is
one *real* notification written against one *real* scenario — worth more than a
form, and it is the artefact that proves the plan was exercised.

---

## 9 · The breach register — an obligation Foxy is failing right now

**PIPEDA s. 10.3 requires a record of *every* breach of security safeguards
involving personal information under the organisation's control.** No severity
threshold. No trigger. No breach required to bring the duty into existence.

> ⚠ **This is the only row in §2 that Foxy is in breach of on a day when nothing
> has happened.** Every other duty waits for an incident. This one does not — and
> it has been unmet for as long as the company has existed.

The register is [`breach-register.md`](breach-register.md), created empty as part
of this deliverable. Its schema and its rules live in that file.

**An empty register is the correct state and it must still exist**, because
"nothing has happened" and "we do not keep records" are indistinguishable from
outside, and only one of them is compliant.

The register also carries **SEV-3** events, which are never notified. That is the
half easiest to skip and the half s. 10.3 is actually about: the breaches below
the real-risk-of-significant-harm threshold that PIPEDA-003 never reports.

---

## 10 · The tabletop — one scenario, run end to end

**A plan nobody has exercised is a document, not a control.** Same distinction as
an untested backup (`#291`): the artefact is what makes it a control, and the
artefact is what C4 needs.

### Scenario — "the staff session that should not exist"

> On a Tuesday at **02:40**, the owner opens the admin console and the
> active-devices list on his own staff account shows a session from an IP he does
> not recognise, last seen eleven minutes ago. He was asleep. His password has
> not changed. `login_events` shows one successful sign-in for his email from
> that IP at 01:57, preceded by no failures.

**Why this scenario and not a database breach.** It is the most plausible one:
staff read **cross-org** — `require_staff` never sets `app.current_org`, and the
app's database role bypasses `FORCE` RLS — so a compromised staff account reaches
every tenant, which is the widest blast radius any single credential in the
system has. It also has no clean answer: it is Class DB, not Class VM, so BYOK
keys stay encrypted; and the staff IP allowlist is supposed to prevent it, which
forces the question of why it did not. **A scenario the plan handles smoothly
teaches nothing.**

### Run it like this

Two people, ninety minutes, no keyboard until step 3 — talk it through first.
Walk §7's nine steps in order, answering out loud. **Write the answers down as
you go; the write-up is the deliverable, not the discussion.**

The questions it must force:

1. **Who is the Lead?** The owner found it, so it is the owner. Who is the
   Recorder while the owner is investigating?
2. **What is the awareness timestamp** — 02:40 when he saw it, or 01:57 when the
   sign-in happened? *(The answer is 02:40. Every regime says "becoming aware".
   The 01:57 is the compromise window and belongs in item 3 of §8.)*
3. **Contain first: which revocation?** Staff session, staff password, staff
   account, or all three? Can the other person do it if the owner cannot?
4. **SEV-2 or SEV-3?** A staff session with cross-org read access, live for
   43 minutes. ⚠ *Argue it honestly, then apply §4's tie-break.*
5. **What did they read?** Does anything record staff **reads**, or only
   `admin_actions` writes? **If the answer is only writes, the scope question
   cannot be answered from evidence — and that is a finding the tabletop was run
   to produce.**
6. **Which orgs are affected?** If reads are not logged, is the honest answer
   "all of them"? What does that do to the notification list?
7. **Does the ledger need §7 step 6?** Staff access is a read path — but *prove*
   nothing was written, rather than assuming it.
8. **Draft the actual notification** from §8's nine items, for one real org. Not
   a sketch — real sentences. ⚠ *This is the single most valuable output of the
   exercise.*
9. **Which of §2's clocks are now running, and when does the first one expire?**

### The artefact

`docs/compliance/evidence/tabletop-<YYYY-MM-DD>.md`, containing:

- the date, the scenario, and who took part;
- the answers to all nine questions, including the ones nobody could answer;
- **every gap the exercise exposed** — those are the point, not a failure;
- the elapsed time from step 1 to a draft notification;
- the draft notification itself;
- what was changed in this plan as a result.

⚠ **The gaps are the evidence.** A tabletop write-up in which everything went
smoothly is either fiction or a scenario chosen to be easy, and an auditor reads
it as the former. `evidence/` is where the owner checklist already puts dated
artefacts, and this joins them.

**Cadence: annually, or after any SEV-1 or SEV-2.** ⚠ Running it once is what
turns this file from `gap` to `partial`; the schedule is what eventually turns it
to `met`, and only alongside the operating evidence in AQ-029.

---

## 11 · What this document does not do

- **It is not legal advice**, and no lawyer has read it. Every **⚖ COUNSEL** mark
  is a question deliberately left open: the KSA article number, whether Qatar
  13/2016 binds Foxy through hosting, whether Foxy is an APP entity, whether an
  Art. 33(1) controller duty attaches to account data and to which authority, and
  whether ledger metadata is identifiable.
- **It does not close the eighteen rows to `met`.** Per
  [`README.md`](README.md), `met` requires evidence an outsider can inspect. A
  plan is a control; the tabletop artefact is the first inspectable evidence, and
  it does not exist until §10 is run.
- **It does not build detection.** §6 names what is missing and stops there.
  Alerting is code, and this deliverable is documentation only.
- **It does not fix `privacy.html` §15 or `dpa.html` §10.** Both are frozen
  published pages and C2's scope. §0 records what should change.
- **It does not name a security officer** (HIPAA-002 / AQ-026), which belongs in
  a security policy.
- **It does not solve the off-host chain-head record** that §3 and §7 step 6
  depend on. That is a C4 control.

---

## 12 · What this moves in the crosswalk

**Nothing in `crosswalk.yaml` is edited by this deliverable.** Status words are
changed by the phase that owns the file, against evidence — and per
[`README.md`](README.md) the evidence for most of these rows is the tabletop
artefact, which does not exist yet. This section says what *should* move, and on
what.

| Row | Now | Should become | On what |
|---|---|---|---|
| HIPAA-004 | `gap` | `partial` | This plan exists; §7 step 8 gives the documentation duty a home |
| HIPAA-017 | `gap` | `partial` | The 60-day duty is now named and owned; §8 defines the notice |
| SOC2-006 | `gap` | `partial` | §4 is the evaluation standard CC7.3 asks for |
| GDPR-006 | `partial` | `partial` (**unchanged**) | Already `partial` on the published commitment. Reaching `met` needs the exercised process, not a plan |
| ISO-005 | `gap` | `partial` | A.5.24 asks for processes, roles and responsibilities defined **and communicated** — §5 and §7 |
| ISO-011 | `gap` | `gap` (**unchanged**) | ⚠ §6 documents the monitoring gap. It does not close it |
| PCI-007 | `gap` | `partial` | The plan exists and is ready to activate. ⚠ Read note B first |
| UAE-003 | `gap` | `partial` | Art. 9(3)'s processor duty is named and routed |
| QAT-001 | `gap` | `gap` (**unchanged**) | Art. 11(5) asks for an internal PD management system, which is wider than an IR plan |
| QAT-003 | `gap` | `partial` | 72h from detection is in the table and in the clock discipline |
| KSA-004 | `gap` | `gap` (**unchanged**) | ⚠ The clause is still TBD. A row whose citation cannot be verified must not be upgraded |
| LGPD-004 | `gap` | `partial` | Art. 48's dual controlador/operador posture is stated per §1 |
| PIPEDA-003 | `gap` | `partial` | ⚠ The period is TBD (note E). The recipients and the trigger are now defined |
| PIPEDA-004 | `gap` | **`partial`** | The register now exists and is empty, which is its correct state |
| SGP-004 | `gap` | `partial` | The data-intermediary duty is named as Foxy's own |
| SGP-005 | `gap` | `partial` | 3 calendar days from assessment drives §2's internal target |
| AUS-004 | `gap` | `partial` | The 30-day assessment window is bound to §4's SEV-2 trigger |
| AUS-005 | `gap` | `partial` | §8's contents map to the s. 26WK(2) statement |

**Fourteen rows gap → partial. Four stay where they are**, each for a stated
reason, and each of those reasons is a thing this document could not honestly
claim: ISO-011 needs monitoring that does not exist, QAT-001 needs a wider system
than an IR plan, KSA-004 needs a citation nobody has verified, and GDPR-006 was
already `partial`.

⚠ **None of them reaches `met`, and none should.** `met` needs evidence a third
party can inspect. The first such evidence is §10's dated tabletop artefact, and
after that the operating record in AQ-029 — which is the observation-window
argument again, and it starts the day somebody runs the exercise.
