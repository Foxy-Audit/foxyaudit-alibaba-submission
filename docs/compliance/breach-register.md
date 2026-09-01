# Breach register — every breach of security safeguards

**The register PIPEDA s. 10.3 requires.** Created 2026-09-02 as part of
[`incident-response.md`](incident-response.md) (phase C1, deliverable 6). Closes
crosswalk row **PIPEDA-004**, cited by **AQ-023**.

> ⚠ **THIS IS NOT LEGAL ADVICE.** The schema below was designed from the duties
> in [`incident-response.md`](incident-response.md) §2. **s. 10.3 says the record
> must be kept *"in accordance with any prescribed requirements"*, and those
> prescribed requirements live in a regulation this document has not fetched or
> verified.** Check the schema against the regulation, or against counsel, before
> relying on it. Nothing here is invented as a quotation — where a source was not
> read, it says so.

---

## Why an empty register is the correct state, and must still exist

**PIPEDA s. 10.3, quoted from the primary source via crosswalk row PIPEDA-004:**

> *"An organization shall, in accordance with any prescribed requirements, keep
> and maintain a record of every breach of security safeguards involving personal
> information under its control."*

Three things make this different from every other duty in the programme:

1. **It has no trigger.** Every other row in `incident-response.md` §2 waits for
   an incident. This one is an obligation on a quiet Tuesday when nothing has
   happened — which is why the company has been failing it since it was founded,
   and why creating this file closes it.
2. **It covers *every* breach, not the notifiable ones.** The reporting duty
   (PIPEDA-003) fires only on a *"real risk of significant harm"*. The record
   duty has no such threshold. **The entries that will never be reported are
   precisely the ones s. 10.3 is about** — SEV-3 in §4's scale.
3. **Emptiness is not the failure mode; absence is.** *"Nothing has happened"* and
   *"we do not keep records"* are indistinguishable from outside, and only one of
   them is compliant. A register with zero rows and a dated creation is evidence.
   No register is not.

⚠ **Do not delete this file when the register is empty, and do not add a
placeholder row to make it look used.** A fabricated entry would violate the
project's no-fake-data rule and would be the worst possible thing to find in a
compliance record.

---

## Rules

1. **The Incident Lead is the Recorder** (`incident-response.md` §5). Not
   delegated.
2. **Open the entry at step 1**, before containment. The awareness timestamp is
   the only one that cannot be recovered later, and every clock in §2 runs from
   it.
3. **Append-only.** Correct a mistake by adding a dated correction line inside
   the entry, never by editing a recorded fact out of it. A register whose
   history can be rewritten is worth what an unchained ledger is worth, which is
   the argument this whole product is built on.
4. **Record SEV-3 too.** See reason 2 above. This is the rule most likely to be
   skipped and the one s. 10.3 actually turns on.
5. **All timestamps in UTC, ISO-8601**, with the offset written out. Production
   runs in Doha and the team does not; two people reconstructing a timeline from
   mixed local times is a failure mode this costs nothing to avoid.
6. **Unknown is a valid value. Guessed is not.** Write `unknown` and, where it
   matters, why it is unknown.
7. **Retention: indefinite.** s. 10.3 prescribes a period this document has not
   verified; keeping entries forever cannot be wrong under a rule that sets a
   minimum, and the register is small.

---

## Schema

One `##` section per entry, newest at the top of the log. Every field appears in
every entry, even when its value is `none` or `unknown`.

| Field | What goes in it |
|---|---|
| `id` | `IR-YYYY-NNN`, allocated in order, never reused |
| `aware_at` | UTC timestamp Foxy **became aware**. Not when the incident began |
| `detected_by` | Which of §6's four channels: customer · Google · subprocessor · internal |
| `severity` | SEV-1 / SEV-2 / SEV-3 / SEV-4 per §4, and one line on why that grade |
| `class` | `DB` or `VM` per §3, or `n/a` |
| `summary` | What happened, in two or three sentences, in plain words |
| `window` | The compromise window if known, or `unknown` |
| `data_categories` | Which of §3's nine numbered categories were within reach — and which were confirmed accessed, if that is knowable |
| `commitment_alg` | The algorithms in the affected orgs' rows: `hmac-sha256`, `hmac-sha256-salted`, `sha256-legacy`, or a mix |
| `orgs_affected` | Count and identifiers, or `unknown` with the reason |
| `individuals_affected` | Count, or `unknown` with the reason |
| `byok_exposure` | `none` / `ciphertext-only` / `plaintext-assumed`. ⚠ Class VM is `plaintext-assumed` from minute one |
| `ledger_integrity` | What was done for §7 step 6 — the chain head recorded, whether anchors were confirmed, what customers were told to verify |
| `containment` | What was done, and at what timestamp |
| `notifications` | One line per notification: who, when, under which crosswalk row. `none` if none, **with the reason** |
| `clocks` | Which of §2's periods started, when each expires, and whether each was met |
| `remediation` | What changed so it does not recur — HIPAA-004 requires the outcome, not just the response |
| `review_at` | Date of the §7 step 9 review, and what the plan changed as a result |
| `entry_opened` / `entry_closed` | Timestamps for the record itself |

### Skeleton to copy

```markdown
## IR-YYYY-NNN — <one-line title>

- **aware_at:**
- **detected_by:**
- **severity:**
- **class:**
- **summary:**
- **window:**
- **data_categories:**
- **commitment_alg:**
- **orgs_affected:**
- **individuals_affected:**
- **byok_exposure:**
- **ledger_integrity:**
- **containment:**
- **notifications:**
- **clocks:**
- **remediation:**
- **review_at:**
- **entry_opened:** / **entry_closed:**

### Timeline
<UTC timestamp> — <what happened or was done, and by whom>
```

---

## The register

**No entries.**

Opened 2026-09-02. No security incident has been recorded against Foxy Audit as
of that date.

⚠ **This line is a statement about the record, not about reality.** Given
[`incident-response.md`](incident-response.md) §6 — GCP Essential Contacts unset,
no alerting on Foxy's own infrastructure, no log aggregation — the honest reading
is *"nothing has been detected and reported to us"*, which is a weaker claim than
*"nothing has happened"*. **Do not let this file be quoted as the stronger one.**
