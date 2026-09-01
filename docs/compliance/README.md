# docs/compliance — the regime crosswalk

Phases **C0**, **C0b** and **C2** of [`docs/plans/compliance-program.md`](../plans/compliance-program.md).
Written 2026-09-01 against `origin/main` at **`01e87ad`** (C0) and **`e7e1919`**
(C0b and C2). The three YAML files carry `meta.verified_against: 4466996`, re-stamped
2026-09-02 by the C1-SYNC pass that carried C1, C3a and C3b into them.

| File | What it is |
|---|---|
| [`crosswalk.yaml`](crosswalk.yaml) | Every regulatory clause we intend to speak to, the Foxy control that answers it, the evidence a third party could inspect, and an honest status. **105 rows across 15 regimes.** |
| [`claims.yaml`](claims.yaml) | **C2.** Every compliance claim on every customer-facing surface, each with a verdict and a crosswalk row that backs it — plus the claims C2 deleted, each pinning a pattern that must never come back. |
| [`auditor-questions.yaml`](auditor-questions.yaml) | **C3a.** The questions a third party actually asks, each derived from crosswalk rows, with an honest verdict on whether a customer could answer it TODAY — **37 questions: 5 `full`, 21 `partial`, 11 `no`.** Also the inverse check: which crosswalk rows no question reaches. |
| [`incident-response.md`](incident-response.md) | **C1 deliverable 6.** The breach-response plan. A duty table over **18 crosswalk rows across 12 regimes** — the highest-leverage single artefact in the programme (AQ-023) — plus what a Foxy breach actually exposes, roles for a two-person team, and a tabletop scenario. ⚠ Never exercised; until it is, it is a document, not a control. |
| [`breach-register.md`](breach-register.md) | **C1 deliverable 6.** The PIPEDA s. 10.3 register of *every* breach of security safeguards. **Empty, and empty is correct** — the duty has no trigger, so the register must exist on a day when nothing has happened. |
| [`not-applicable.md`](not-applicable.md) | Regimes and clauses that cannot bind Foxy, each with the reasoning. A register of *"we checked, and here is why not"*. |
| this file | How to read the crosswalk, and how to add a regime. |

The guard that enforces `claims.yaml` is
[`foxy-sale-page/test_compliance_claims.py`](../../foxy-sale-page/test_compliance_claims.py).
It runs in `pytest foxy-sale-page -q` and it fails the build.

> ⚠ **This is engineering research, not legal advice.** No row has been reviewed
> by a lawyer. Foxy is incorporated in Pakistan, the team is two people, and
> there is no legal budget yet — so this file exists to make the eventual legal
> engagement short, not to substitute for it.

---

## The architectural idea underneath it

From §3 of the plan: **stop modelling regimes as policies. Model data classes and
controls, and map regimes onto them.**

```
  DATA CLASSES        CONTROLS                 CROSSWALK
  (in the prompt)     (what Foxy does)         (clause satisfied)

  PHI ────────┐       hash chain ────┐         HIPAA 164.312(b) ───┐
  PII ────────┤       RLS isolation  ├────────▶ GDPR Art. 30 ──────┤
  special-cat ┤       BYOK / KEK     │         SOC 2 CC7.2 ────────┤
  financial ──┘       access review ─┘         PDPL Art. 19 ───────┤
                                               EU AI Act Art. 26(6)┘
```

One control answers many clauses. `chain.py` alone carries HIPAA-010, SOC2-014,
GDPR-005, EUAI-002, PCI-004 and ISO-006. That is the whole point: **adding PDPL
was a mapping exercise, not a feature.** Nothing was built for this phase.

It is also how the `policy="soc2"` category error gets fixed properly. `soc2`
cannot be a per-call check — SOC 2 is an organisational control regime and there
is nothing about a single prompt that is or is not SOC 2 compliant. In this file
SOC 2 is fourteen organisational controls mapped to evidence, which is what it
always was.

---

## How to read a row

```yaml
- id: HIPAA-010                     # stable; other phases cite these
  regime: HIPAA
  clause: "164.312(b)"              # VERIFIED, or the literal TBD
  requirement: "Audit controls — implement hardware, software and/or …"
  control: "Sequential per-org SHA-256 hash chain (backend/app/chain.py) …"
  evidence: "An export plus `python verifier/foxy_verify.py logs.json` …"
  status: partial
  source: "45 CFR 164.312, Cornell LII — https://… (fetched 2026-09-01)"
  notes: "…"
```

### `status`

| | Means |
|---|---|
| `met` | The requirement is discharged **and** a third party can inspect the evidence that says so. |
| `partial` | A real control exists and does real work, but it does not discharge the clause on its own, or no outsider can inspect it. |
| `gap` | No control, or a control that fails the clause. |
| `not-applicable` | The clause cannot bind Foxy. Every one of these carries its reasoning; see [`not-applicable.md`](not-applicable.md). |

### `control` vs `evidence` — the distinction the whole file turns on

- **`control`** is what Foxy *does*. It may name closed-source code.
- **`evidence`** is what an **outside party could obtain and inspect**: an export
  they can run the verifier over, a page they can read, a signed instrument, a
  CI record they are shown.

**A path into the private backend is not evidence.** `backend/app/rls.py` is a
control; nobody outside Foxy can look at it, so the row's evidence is `null`.
`verifier/foxy_verify.py` *is* evidence — it ships, it is dependency-free, and a
customer's auditor runs it without trusting us.

`evidence: null` is common here and is the honest answer. Do not fill it in with
a file path to make a row look better.

### A published commitment is a control, and it is never a `gap`

Added after [[#305]], which found `GDPR-006` and `HIPAA-017` citing the *same*
sentence of `privacy.html` §15 as their control and the *same* published policy
as their evidence, and grading it `partial` and `gap` respectively. Under the
definitions above only one of those can be right.

> **A published commitment is a control with inspectable evidence** — the
> sentence is on a page anyone can read without Foxy's cooperation — **so a row
> citing one is `partial`.** `gap` is for no control, or a control that *fails*
> the clause. **How much of a clause the commitment discharges is a `notes`
> question, never a `status` question.**

Grading the shortfall as `gap` throws away the fact that the commitment exists
and is enforceable against Foxy. The shortfall is still real and still has to be
written down — `HIPAA-017` discharges less of 45 CFR 164.410 (which wants a
60-day outer bound and a defined content set) than `GDPR-006` does of Art. 33(2)
(which wants "without undue delay", §15's exact words) — and that difference now
lives in both rows' `notes`, where it can be read rather than inferred from a
status word.

⚠ **The pattern is wider than the pair #305 named, and C1-SYNC did not chase
it.** Measured over the parsed file: **six** rows carry `status: gap` with a
non-null `evidence` — `HIPAA-017` (fixed), and `SOC2-008`, `GDPR-009`,
`KSA-005`, `UAE-006`, `PCI-006`. Each of the five needs its own clause read
before it is re-graded — `GDPR-009` in particular may be a genuine `gap`, since
Art. 46 wants an *executed* safeguard and a promise to use the SCCs is arguably
not a partial version of one. **Do not sweep them.** Read the clause, then
decide, one row at a time.

### Why nothing is `met`

**There are zero `met` rows.** 60 `partial`, 40 `gap`, 5 `not-applicable`
— counted by parsing the file, never by hand.

⚠ **The 2026-09-02 movement was 14 rows `gap` → `partial`, and not one reached
`met`.** C1 wrote [`incident-response.md`](incident-response.md), and its §12
records exactly which rows it moves and on what. **Four rows named in that
section deliberately did not move** and a later reader should not tidy them:
`ISO-011` (the plan documents the monitoring gap, it does not close it),
`QAT-001` (Art. 11(5) wants a personal-data management system, wider than an IR
plan), `KSA-004` (**the clause is still `TBD`, and a row whose citation nobody
has verified must not be upgraded however well attested its 72 hours is**), and
`GDPR-006` (already `partial`). The plan is in a private repository and has never
been exercised, so it is a control and not evidence: the first inspectable
evidence any of the fourteen will have is the dated artefact from §10's tabletop,
which nobody has run.

That is not modesty and it is not a placeholder. `met` requires named evidence a
third party could inspect, and the artefacts that would carry it — a BAA, a
record of processing, a tested restore, an auditor's opinion — do not exist yet.
Several controls are genuinely strong: the hash chain plus the standalone
verifier is a real, unusual, independently checkable integrity control, and it
still is not `met`, because integrity is one clause of many and no one outside
Foxy has been asked to check it.

When C1 lands a signed BAA, `HIPAA-008` becomes `met`. When a restore is actually
run and its output kept, `SOC2-010` becomes `met`. When somebody runs the
tabletop and keeps the output, the fourteen incident-response rows get their
first inspectable evidence. That is the shape of progress this file is built to
show. **Do not promote a row by reading the code** — and do not promote one by
reading a document either.

### `source`

Every row has one, and it names *where the clause text was verified*, not where
the control lives. Sources are graded in the text itself:

- **Primary** — the regulator's or standard-setter's own document. HIPAA
  (Cornell LII's reproduction of 45 CFR), EU AI Act (artificialintelligenceact.eu
  article pages), GDPR (gdpr-info.eu), PCI DSS v4.0.1 (the official standard PDF),
  SOC 2 (the AICPA-published red-lined TSC PDF), Qatar (the NCSA's own breach
  guideline, which quotes the Law verbatim).
- **Secondary, and it says so** — ISO/IEC 27001:2022 (the standard is paywalled;
  control *titles* verified, normative text not), Saudi PDPL and UAE PDPL (the
  official English texts were not machine-fetchable; the SDAIA PDF returns
  "Request Rejected"). Every such row carries a ⚠ in its `source`.

### `clause: TBD`

**Three** rows carry it: `NIST-001`, `KSA-004`, `QAT-004`. In each case the
*obligation* is attested but the *article number* is not, or sources disagree.

C0 had four. C0b resolved **`UAE-003`** to **Article (9)** — and found while doing
it that the row's *requirement* had also been wrong, because the secondary source
C0 was limited to gave a deadline ("immediately after having become aware") that
the official text does not contain: Art. 9(1) defers the period to the Executive
Regulations. A source good enough for the substance was not good enough for the
detail, which is the argument for primary texts in one line.

C0b did **not** resolve the other three, and `KSA-004`'s note records why the
thing that looked like corroboration was not: `saudiprivacylaw.com`'s article
index labels Art. 18 *"Data Breach Notifications"*, which would settle it — except
that the same index labels Art. 4 *"Prohibition of Certain Rights"* while the
statutory text on its own Art. 4 page **grants** rights. Its slugs are editorial
and were measured wrong at least once, so they do not count as a second source.

**TBD is a correct answer. An invented article number is a defect** — a crosswalk
with a hallucinated clause is worse than no crosswalk, because it will be read as
authoritative and quoted back at us by someone who checked.

One conflict was found and resolved rather than left TBD: Saudi cross-border
transfer is **Art. 29**, because SDAIA's own transfer regulation cites
"subparagraph (c) of paragraph (2) of Article (29) of the Law", which outranks a
secondary source that said Art. 28. `KSA-002` records both so the next reader does
not re-run the search.

---

## `surface_claims` — the bridge to C2

Separate from `rows`. It lists **every regime word on a customer-facing surface**,
with a verdict:

| verdict | Means |
|---|---|
| `backed` | A crosswalk row supports the claim as written. |
| `qualify` | True, but overclaims as written. C2 narrows it. |
| `delete` | Not true, or not supportable. C2 removes it. |

⚠ **The line numbers in `where` name a location in THIS repository**, at the SHA
in `meta.verified_against` — not on foxyaudit.tech, which still serves the
uncorrected pages until the 2026-09-18 floor. Where C2 applied a verdict and the
text is gone from this repo, `where` names the last SHA at which it was present
and says which commit removed it. The full reasoning is in
`crosswalk.yaml` `meta.line_number_semantics`; the short version is that
`git show <sha>:<path>` can check a number and nothing can check a number
attributed to a website. **Re-derive them by script, never by hand** — C2b's own
guard caught a hand-edited line number twice.

**A verdict is about the claim, not about the line.** A `delete` whose text this
repo no longer contains is still `delete`, because the live site still serves it.
Four `delete` verdicts stand today. Three of them are one defect:
**the published hosting region is wrong.** `privacy.html` §8 and §13, and the
`trust.html` subprocessor table, all state that hosting is in the **United
States**. Production runs in **GCP `me-central1-a` — Doha, Qatar**. §13 then names
the EU Standard Contractual Clauses for a US destination that is not where the
data is, so the transfer actually being made — EEA → Qatar, a country with no
adequacy decision — is disclosed nowhere. That is `GDPR-007`, and it is the most
serious row in the file.

The fourth is the SOC 2 status contradiction: `faq.html` and `pricing.html` say
*"We're currently completing our SOC 2 Type I audit"* while `trust.html` says
*"SOC 2 Type I — intended, but no auditor is engaged yet."* Both cannot be true.

Regenerate the inventory with:

```bash
grep -ril "HIPAA\|SOC 2\|GDPR\|PCI\|ISO 27001\|FedRAMP\|CCPA\|NIST" \
     foxy-sale-page/ foxy-dashboard/
```

⚠ **Then re-run per word with word boundaries.** The base64 image payloads in
these HTML files contain the letter sequences `pci`, `PDPL`, `NIST` and `LGPD`,
and a naive grep reports them as claims on pages that make none:

```bash
grep -rnE "\bPCI\b" --include=*.html foxy-sale-page/ | awk 'length($0)<400'
```

---

## The `soc2` vocabulary error, and what C2 did with it

C2 did **not** rename the `soc2` policy tag. Three code samples on the sale page
(`how-it-works.html:38`, `sdk.html:38`, `install.html:58`) are recorded in
`claims.yaml` as `qualified` instead, with the reasoning written down: the tag is
real and does what the docs say, so the samples are not false, but the NAME
implies a per-call check that cannot exist. Renaming it is an SDK change with a
live wire contract behind it, and the plan puts `sdk/` out of scope for C2.

The point of writing it down rather than fixing it is that the next phase
inherits a decision instead of rediscovering a problem.

## The three things no row may imply

1. **The AI judge cannot assess maliciousness.** It sees only hashes and counts —
   there is no content for it to read. `SOC2-005` and `EUAI-005` both carry the
   warning inline. Anything C3 builds on those rows must say so on the page.
2. **Foxy is the tool, not a certified entity.** The vault's line, and the right
   one: *never say "we are X compliant" — say "we help you prove your X
   compliance."*
3. **Content-blindness does not cover the platform-key leg.** `platform_keys_allowed()`
   lets privileged orgs grade on Foxy's own provider keys, sending customer event
   metadata to OpenAI and Google under Foxy's account. Raw prompts and responses
   still never leave the customer process — but that is a subcontractor
   relationship with no contract behind it (`HIPAA-015`).

---

## How to add a regime

1. **Add a `regimes:` entry.** Give it an `id` (SCREAMING_SNAKE), the official
   name with its instrument number, a `posture`, and `named_on` — the surfaces
   that mention it, or `[]`.

   `posture` is about what we **say**, not what we have:
   - `CLAIMED` — a customer-facing surface names this regime today.
   - `MAPPED-ONLY` — mapped here for planning; no surface names it.

   Every regime in this file is one Foxy is certified in exactly none of. Posture
   does not change that.

2. **Find the clauses, from a source you can name.** Prefer the regulator's own
   document. If you cannot reach it, use two independent secondary sources, put
   a ⚠ in `source` saying the primary was unreachable, and say why.

3. **Write rows.** Only clauses that plausibly touch what Foxy does — audit
   trails, logging and retention, security of processing, breach notification,
   subprocessors and transfers, records of processing, backup and recovery,
   change management. A crosswalk that maps every clause of every regime is a
   crosswalk nobody reads.

4. **Do not write `met`.** See above. When in doubt it is `partial`.

5. **Prefer a `gap` to a half-truth.** Per the plan's §3 warning: a clause we
   cannot map to a real control or a real piece of evidence is recorded as a
   gap. The crosswalk's value *is* that it is honest about what is missing.

6. **Check the surfaces.** If the new regime appears on a customer-facing page,
   add a `surface_claims` entry with a verdict — otherwise C2's guard has nothing
   to check it against.

7. **Validate:**

   ```bash
   python -c "import yaml; yaml.safe_load(open('docs/compliance/crosswalk.yaml'))"
   ```

   and confirm every row still has a `source`:

   ```bash
   python -c "
   import yaml
   rows = yaml.safe_load(open('docs/compliance/crosswalk.yaml'))['rows']
   print(len(rows), 'rows;', [r['id'] for r in rows if not r.get('source')], 'missing source')"
   ```

8. **Re-stamp `meta.verified_against`** with the SHA you read the repo at. A row
   without a SHA behind it is not a finding, it is a memory.

---

## What C0b added, and what it deliberately did not

**Added (2026-09-01, 25 rows, 4 regimes).** LGPD (Brazil) 6 rows · PIPEDA
(Canada) 4 · Singapore PDPA 5 · Australia Privacy Act 5 · plus `KSA-005`
(Art. 4, data subject rights) and `UAE-004` to `UAE-007` — the PDPL rows
`privacy.html` §14 omits while there are live Gulf customers.

The owner was offered *"give them rows or stop naming them"* and chose rows.

Three corrections came with it, all against primary texts C0 could not reach:

| | |
|---|---|
| `UAE-003` | `clause: TBD` → **Art. 9**, and its requirement text corrected. |
| `UAE-001`, `UAE-002` | secondary → **primary**, from the official UAE text. |
| `UAE-002` | **narrowed.** It cited Art. 22 — transfer where protection *is* adequate — for a transfer where it is not. Art. 23 is the article Foxy is actually under, and it is now `UAE-007`. |

⚠ **`UAE-002` is the one worth remembering.** The row was not wrong about the
regime, the obligation or the gap. It cited the article next door, and the two
articles have different routes out. A crosswalk is read by people who will look
the article up.

**Still deliberately not here:**

- **CCPA/CPRA** appears in `surface_claims` as `backed` — the claim made is about
  cookies and selling, and it is implemented — but it has no `rows`. Six entries
  in `claims.yaml` are backed by GDPR rows standing in, which is honest and is
  not the same as having rows. Same shape of hole as the one C0b just closed,
  one regime over.
- **A Gulf bullet in `privacy.html` §14.** `KSA-005` and `UAE-006` are `gap`
  partly because of it. Adding one is new legal copy about jurisdictions whose
  primary texts are not fully reachable, and it belongs with C1's DPA work where
  a lawyer sees it. Recorded in `claims.yaml` under `open_questions`.
- **The Compliance Passport's clause grouping.** That is C3. This file is the
  input to it: the Passport should group by crosswalk row id, not by `policy_tag`.
- **Any code change.** C0 wrote documents only. Nothing under `sdk/`, `backend/`
  or a frontend directory was touched.
