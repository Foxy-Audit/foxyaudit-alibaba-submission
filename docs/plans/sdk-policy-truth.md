# SDK — Policy Truth II: the tag you typed, the rules that ran, the limits we admit

**Plan of record** · original written 2026-08-12 · **re-cut 2026-08-24 against `676a908`**
MAIN chat is the committer; executors build per this file.

Phases **S12 → S16**, continuing the `S` series. S11 (`ce491e1`) was the last.

> **S3–S7 ALL SHIPPED, and four more phases landed after them.** This file
> described five phases as pending; every one is done. What follows is the
> second generation of the same defect, plus the one item S7 left behind.
> The original §1–§9 are archived in `docs/done/sdk-policy-truth-S3-S7.md`.

---

## 1 · Context

The first plan existed because the SDK's *mechanism* was sound and its *coverage
and provability* were not. That was fixed: the policy map is additive, rulesets
are frozen and versioned, `check()` and `explain()` are public, the fox no longer
invents a risk score.

**The same defect has recurred twice, in new clothes, and one admission is still
owed.**

- A developer who types `policy="HIPAA"` — the natural spelling, in the product's
  own compliance vocabulary — gets **no PHI check and PHI delivered to the
  model**, and the event is chained as `default`. This is `hipaa_basic` again,
  triggered by a shift key.
- `foxy explain` tells an auditor that a row written **today** "was written
  before SDK 1.7.0". A false statement of fact, in the tool built to establish
  facts.
- Injection detection is five English regexes. Eight evasions pass. Nothing on
  any surface says so.

The through-line is unchanged from the first plan: **the SDK claiming more than
it does.**

---

## 2 · Premises, verified at `676a908` (2026-08-24)

The original table was read at `24d3699`. Every row of it has since resolved.

| The original premise | Then | Now |
|---|---|---|
| `_POLICY_CHECKS` is exclusive, not additive | NO | ✅ **fixed** — `_BASELINE_CHECKS` + `_POLICY_EXTRA`, shipped 1.6.0 |
| `hipaa_basic` does no PHI scanning | NO | ✅ **fixed** — `_POLICY_ALIASES`, verified: `hipaa_basic` blocks a PHI prompt |
| Nothing proves a rule actually matched | NO | ✅ **fixed** — S4 (1.7.0) `ruleset_version`/`ruleset_hash`, S5 (1.8.0) `explain()`, S9 (1.10.0) verifies the ruleset it replays |
| The SDK cannot be called from a console | NO | ✅ **fixed** — `check()`/`explain()` public, `foxy check`/`foxy explain` |
| The fox renders a hardcoded 100/100 | NO | ✅ **fixed** — `score_or_none`; a score prints only when the payload carries one |
| The backend allowlist is a 422 trap | holds | ✅ **widened** — `ruleset_version`, `ruleset_hash` at `schemas.py:64` |
| S7 ships the listing | pending | ⚠️ **NOT DONE** — see §3 |

**What is true now, and is the work:**

| # | Verified at `676a908` |
|---|---|
| 🔴 **#232** | Reproduced in `mode="block"`: `policy="HIPAA"` / `"Hipaa"` / `" hipaa"` → **ALLOWED THROUGH, model called**, wire `policy_tag="default"`. `policy="hipaa"` blocks. The decorator validates with `_POLICY_RE` (`client.py:122`) and falls back at `client.py:615`; `evaluate()` and `check()` normalise internally, so **the two paths disagree**. |
| 🔴 **#239** | `explain()` on a clean row returns `predates_provenance` — "written before SDK 1.7.0" — for a row written today. Measured: allowed → `ruleset_version=None`; blocked → `'2026.08.4'`. The *behaviour* is correct per S4; the *message* is not. |
| 🟡 **#230** | Five `_INJECTION_RULES`. Eight measured evasions pass: spaced letters, one-letter typo, synonym, non-English, base64, indirect via retrieved document, polite framing, keyword-free exfiltration. |
| ⚠️ **S7 tail** | `sdk/README.md:451` — the PyPI long description — still opens Install with `pip install -e .`, the exact line S7 was written to replace. `check-version` still validates **two** of three version stamps. |

**Baselines measured** (`--collect-only`, `676a908`): `sdk/tests` **752** ·
`sdk/tests_testbed` **413** · `verifier` **31** · `desktop` **936** (2
pre-existing reds, #235/#236) · `backend/tests/integration` **1251 passed, 3
skipped** — measured at S12, correcting the 1101 this plan and
`Backend/CLAUDE.md` both carried, which was 150 tests stale. SDK version
**1.12.0, unpublished**.

---

## 3 · Owner decisions · 2026-08-24

| Question | Decision |
|---|---|
| Scope of the next series | **The full sweep**, including broadening injection detection. |
| #232's tag on the wire | **Normalise the checks, normalise the wire tag, AND preserve what the customer typed** in `event_metadata.policy_tag_raw`. |
| #230 | **Broaden the ruleset in this plan** — not merely document the limit. |
| Publishing | **No.** Nothing is tagged; `release.yml` stays disarmed. The listing work is done so a tag is one step whenever the freeze lifts. |

**One version for the whole series: 1.13.0, stamped once in S16.** The repo's
convention is one phase per version, and it is right when each phase publishes.
Nothing here publishes, so intermediate bumps would name releases that never
existed and leave the changelog describing a history PyPI cannot show. S16
stamps 1.13.0 and its changelog block names S13, S14 and S15.

---

## 4 · 🔴 The blocker nobody mentioned, and it dictates the order

**The backend rejects the very tag #232 is about.**

`backend/app/schemas.py:20`:

```python
policy_tag: str = Field(pattern=r"^[a-z0-9_]{1,32}$")
```

Measured: `hipaa` ✅ · `hipaa_basic` ✅ · `HIPAA` ❌ · `Hipaa` ❌ · `" hipaa"` ❌.

So "keep the tag the customer typed on the wire" was never available — sending
`HIPAA` would 422 every guarded event from that call site, **a total evidence
outage on exactly the events this fix exists to protect.** Today's behaviour is
not preservation either; it is a silent substitution of `default`, which is
strictly worse than case-folding.

**Therefore the wire tag is normalised, and the typed form is preserved beside
it** — which needs a new `event_metadata` key, and `event_metadata` is a strict
allowlist. The ordering is not negotiable, and it is the same trap S4 documented:

1. **The backend ships and DEPLOYS `policy_tag_raw` before any SDK sends it.**
   Reverse this and every normalised event is rejected with a 422.
2. **The SDK degrades rather than fails** on a 422 naming unsupported fields:
   retry once without the key, and record that it did. A lagging or frozen
   backend must not cost a customer their audit trail. ⚠ **Production is frozen
   and will NOT have this key** — the degrade path is the only thing standing
   between a devtool SDK pointed at prod and a total ingest failure.
3. **Send `policy_tag_raw` ONLY when normalisation changed something.** An event
   whose tag was already canonical must stay byte-for-byte what it is today.
   This is the same property S4 protected for the clean observe path, and it
   keeps the chain hash of every unaffected row identical.

**Second-order:** `event_metadata` has been chain-bound since V2, so the new key
changes the chain hash **for affected new rows only**. Old rows are untouched and
keep verifying. Prove that with a real export; do not assume it.

---

## 5 · Blast radius — read before building S13 and S15

### S13 — prompts that were allowed will now be blocked

That is the point of the fix, and it is still a behaviour change:

| Call | Before | After |
|---|---|---|
| `policy="hipaa"` | blocked | blocked — unchanged |
| `policy="HIPAA"`, `mode="block"` | **allowed, model called** | **raises `FoxyPolicyBlocked`** |
| `policy="HIPAA"`, `mode="redact"` | prompt untouched | PHI spans now scrubbed — the model sees different text |
| any miscased tag | chained as `default` | chained as the canonical tag, with `policy_tag_raw` |

A workspace whose dashboards have been quietly recording `default` for HIPAA
traffic will see those events change tag. **That is a correction, not a
regression, and it must be in the release notes** — a customer whose compliance
grouping shifts after an upgrade deserves to have been told why.

### S15 — new rules fire, on prompts that previously passed

Identical in shape to the 1.6.0 additive change, and the same three consequences:

- New `prompt_injection` labels appear in `pii_signals` on rows that had none →
  **new deterministic breaches on existing dashboards.** They are real breaches
  we were not looking for; say so.
- Under `redact`, more spans are scrubbed → **the model receives different text.**
- ⚠ **False positives are the risk that matters here**, and the testbed is
  already the harness for them: `expect_assist` probes must keep coming back
  answered, and the scoreboard's assistance column fails loudly if a broadened
  rule starts refusing ordinary work. **Run all three sectors on every iteration
  of the ruleset, not once at the end.**
- ✅ Checked: none of the six `*.gap.*` probes is injection — they are MRN, DOB,
  cardholder data, bank account, privileged document, client confidence. So no
  declared gap closes and the "2 known gaps" assertions hold.

---

## 6 · Phases

| Phase | Branch | Scope | Depends on |
|---|---|---|---|
| **S12** | `feat/policy-tag-raw-allowlist` | backend: widen the allowlist, **merge AND deploy to dev2** | — |
| **S13** | `fix/policy-tag-normalisation` | #232 — the PHI bypass | **S12 deployed** |
| **S14** | `fix/explain-unversioned-clean-row` | #239 — explain stops blaming 1.7.0 | — |
| **S15** | `feat/injection-ruleset-2026-08-5` | #230 — broaden injection detection | — |
| **S16** | `docs/sdk-1-13-0-listing` | the S7 tail + 1.13.0 stamps | **all of the above** |

**Order.** S12 → S13 is a hard chain with a deploy in the middle. **S14 and S15
are independent of both and of each other** — three executors can run at once.
S16 is last and documents whatever actually shipped.

### S12 — the backend accepts `policy_tag_raw`

**Files:** `backend/app/schemas.py` · `backend/tests/integration/`

Two changes, and the second was missing from the first cut of this plan —
found by the S12 executor, who measured the failure rather than reasoning about
it:

1. Add `policy_tag_raw` to the `event_metadata` allowlist beside
   `ruleset_version` and `ruleset_hash`.
2. **Pop it from the duplicate-content comparison** in
   `backend/app/routers/logs.py:118`, on both sides, beside the two provenance
   keys. The comment already sitting above that tuple describes this exact
   failure: a client-supplied key the SDK's degrade path strips on retry can
   never match the stored row, so the resend **409s forever and takes the other
   nine events in its batch down with it on every retry**. Measured on the
   branch: first POST 202, stripped resend 409, permanently.

   ⚠ **MAIN's decision, recorded because the executor was right to escalate it:**
   the tuple's stated principle is "describes the RULES, not the interaction",
   and `policy_tag_raw` describes neither — it is what the caller typed. Pop it
   anyway. The degrade-path reason applies identically, and **the comparison
   keeps its teeth through `policy_tag`**, which is still compared: two events
   whose canonical tags differ still 409. Only two spellings of the *same*
   canonical tag compare equal, and those are the same event. A resend never
   overwrites the stored row, so no recorded evidence can change.

**Traps:**
- **Do not add a top-level payload field.** Riding inside `event_metadata` gets
  chain coverage for free; a top-level field means touching `chain.py`'s frozen
  blob and a new `chain_version`.
- The per-key caps (≤64 items, ≤256 chars) already cover a 32-char tag.
- ⚠ **This phase is not done when it merges. It is done when it is DEPLOYED to
  the dev stack** — `docker compose -f docker-compose.dev2.yml up --build -d` in
  `/home/devops/foxy-audit-dev`, **never** `/home/devops/foxy-audit`, which
  production's workflow `git reset --hard`s. Report the deploy, not the merge.

### S13 — the tag you typed does what it says

**Files:** `sdk/src/foxy_audit/client.py` · `sdk/tests/`

```python
policy = (policy or "default").strip().lower()   # BEFORE _POLICY_RE, not after
```

Then send the canonical tag on the wire, and add
`event_metadata["policy_tag_raw"]` **only when the normalised form differs from
what was passed**.

**Traps:**
- **`evaluate()` and `check()` already normalise.** This phase makes the
  decorator agree with them; do not add a second normalisation with different
  rules. One helper, called from both, or the two drift again.
- **The 422 degrade path (§4.2) is not optional** and must be tested against a
  backend that rejects the key — production is exactly that backend.
- **Prove the unaffected path is byte-identical.** A `policy="hipaa"` event must
  produce the same payload it produces today, key for key.
- ⚠ **Reserve the key.** `_reserve_provenance` / `ruleset.PROVENANCE_KEYS`
  (`client.py:1116`) must cover `policy_tag_raw`, or a customer's own
  `event_metadata["policy_tag_raw"]` silently overwrites the SDK's and nothing
  downstream can tell which it is reading. Same collision argument as
  `ruleset_version`, same warned-once drop. *(Found by the S12 executor.)*
- ⚠ **Cap or omit it — its length is caller-controlled and unbounded.**
  `policy=` takes any string and only the *normalised* form is charset-checked,
  so `policy="x"*300` produces a 300-char raw value and **422s the whole batch**
  on the ≤256 cap. This is the one allowlisted key a caller can overflow. The
  plan's "the per-key caps already cover a 32-char tag" is true of the canonical
  tag and false of this one. *(Found by the S12 executor.)*
- ⚠ **The regression guard is the whole reason this shipped:** a decorator test
  over `{hipaa, HIPAA, Hipaa, " hipaa", "HIPAA "}` × `mode="block"` asserting the
  PHI prompt is blocked in **every** case. Today's suite exercises only the
  lowercase form, which is why nobody saw it. Add the same sweep for `redact`.

### S14 — explain stops blaming SDK 1.7.0 for a row written today

**Files:** `sdk/src/foxy_audit/introspect.py` · `sdk/tests/`

A row with `event_metadata` carrying a `decision` but no `ruleset_version` is a
**modern row where no rule fired** — not a pre-1.7.0 row. Distinguish them.

**Traps:**
- **A clean `observe` row is genuinely ambiguous**: it builds no
  `event_metadata` at all, by design, which is what keeps its payload
  byte-identical. Say "cannot be distinguished from a pre-provenance row" rather
  than guessing. Three cases, three sentences.
- **Do not stamp provenance on clean rows to make this go away.** S4 decided
  provenance rides only with the rule ids it explains; changing that would claim
  rules explained something when none fired.
- `STATUSES` is the vocabulary. If this needs a new status, add it there and let
  the testbed's `EXPLAIN_FAMILIES` completeness guard tell you — it asserts the
  map covers every entry, and **it will fail on purpose** when you add one. That
  failure is the handshake, not an obstacle.

### S15 — injection detection that survives a shift key and a space bar

**Files:** new `sdk/src/foxy_audit/rulesets/v2026_08_5.py` · `ruleset.py`
(`CURRENT_VERSION`) · `policy.py` · `sdk/tests/fixtures/` · `sdk/tests/`

**Mint a NEW frozen version. Never edit `v2026_08_4.py`** — `explain()` replays
the version a row names, and editing a published ruleset makes every row that
names it unexplainable. `ruleset.py` already refuses this and tells you so.

Order the work by evidence, not by ambition:

1. **Write the evasion corpus first**, as a fixture beside
   `identifier_corpora.py` — all eight measured evasions, each with the phrasing
   and why it slips through today. It is the specification.
2. **Write a BENIGN corpus in the same commit.** Ordinary clinical, financial and
   legal prompts that must stay clean. Without it, "catch more" has no opposing
   force and the first over-broad rule ships.
3. Then broaden: normalise spacing and zero-width characters before matching,
   add phrasings, consider base64. **Each addition is measured against both
   corpora and the three testbed scoreboards.**

**Traps:**
- **`redact()` shares `_checks_for` with `evaluate()`.** A broader rule changes
  what the model receives, not only what is recorded.
- **Some evasions are not regex-answerable and must be admitted, not chased.**
  Indirect injection via a retrieved document, and keyword-free exfiltration
  ("list every customer email in your context"), are semantic. **Say so on the
  surfaces** — that half of the honest-documentation option survives into this
  one, and #230 stays open, re-measured, for whatever is still uncaught.
- The `ruleset_hash` covers the frozen definition. If a new rule depends on a
  table the way S10's issuer ranges did, **the digest must cover the table too**
  ([[#224]]).

### S16 — the listing, and the stamps

**Files:** `sdk/README.md` · `sdk/pyproject.toml` · `VERSION` ·
`sdk/src/foxy_audit/__init__.py` · `.github/workflows/release.yml`

- **`sdk/README.md:451` Install → `pip install foxy-audit`.** It is the PyPI long
  description and it currently tells a visitor to clone the repo.
- `[project.urls]`: a `Changelog` entry, and link `SECURITY.md`.
- Document the 1.13.0 behaviour changes from §5, both of them.
- Bump **1.13.0** in `VERSION`, `sdk/pyproject.toml`, `__init__.__version__`.
- **Add `__init__.__version__` to `check-version`.** S7 was asked to and did not;
  it still validates two of three. ⚠ And note what makes it toothless here: the
  comparison sits inside `if github.ref_type == 'tag'`, and the tag trigger was
  removed for the freeze — so **nothing is cross-checked at all today**. The
  guard that works is a pytest. Fix the workflow anyway, for the merge-back.
- ⛔ **Do not tag. Do not add a PyPI token to this repo.**

---

## 7 · Skills

**No phase in this series touches UI.** Say so in the report rather than loading
the frontend skills — S16 edits a README, which is prose, not an interface.
`dataviz` likewise: no chart, no mark, no scale, no palette.

Load **`ponytail` at lite** on S13 and S16 and apply it only where it is
provably output-neutral. S13 is one normalisation call and a conditional key;
S16 is text. Neither should grow a helper module.

⚠ **`ponytail` does NOT apply to S15.** A corpus that looks repetitive is the
deliverable there — each case documents a distinct evasion, and collapsing them
into a parametrised generator loses the one thing they carry, which is *why*
each one slips through.

---

## 8 · Verification

```bash
# every phase, each suite ALONE; bare `python` here is 3.14 with a stale 1.7.0
py -3.13 -m pytest sdk/tests -q                  # 752 baseline
py -3.13 -m pytest sdk/tests_testbed -q          # 413 baseline
py -3.13 -m pytest verifier -q                   # 31
PYTHONPATH=sdk/src py -3.13 demo/mock_llm.py --scenario all
PYTHONPATH=sdk/src py -3.13 demo/offline_demo.py

# S12 — backend
cd backend && DATABASE_URL=postgresql+psycopg://foxy:foxy@localhost:5433/foxy_pytest \
  python -m pytest tests/integration -q
#   ⚠ check nothing else is on the test DB first:
#   SELECT pid, state FROM pg_stat_activity WHERE datname='foxy_pytest';

# S13 / S15 — the testbed is the false-positive harness, run it every iteration
PYTHONPATH=sdk/src py -3.13 -m foxy_testbed --sector healthcare --probe all
PYTHONPATH=sdk/src py -3.13 -m foxy_testbed --sector finance   --probe all
PYTHONPATH=sdk/src py -3.13 -m foxy_testbed --sector legal     --probe all

# S15 — the chain must still verify with a new ruleset in play
python verifier/foxy_verify.py <a real export>
```

**What must NOT move:**

- `evaluate(text, "default")` for every input — proven by loading the **old**
  module beside the new one, not by a golden file written on the branch.
- A clean `observe` call's payload, byte for byte.
- An already-canonical tag's payload, byte for byte (§4.3).
- Every historical chain hash, and every frozen ruleset under `rulesets/`.
- `sdk/tests_testbed` at 413 unless the phase deliberately moves it — and if it
  does, that is a finding to report before it is a number to update.

---

## 9 · After each merge

- **Devlog** `Devlogs/YYYY-MM-DD.md`, dated, house style.
- **Register** — close **#232** (S13), **#239** (S14) with SHAs, keeping the
  original text. **#230 stays open and is RE-MEASURED** by S15: the entry gets
  the new evasion table showing what is caught now and what is still not. An
  entry that says "eight evasions pass" must not survive a phase that fixed six
  of them, and must not be closed by a phase that fixed six of eight.
- **Re-stamp** `verified-against:` on `SDK/CLAUDE.md` (S13–S16),
  `Backend/CLAUDE.md` (S12), `Testbed/CLAUDE.md` if S15 moves any scoreboard.
- Remove the worktree, delete the branch, **printing its SHA first**.

---

## 10 · Merge gate — MAIN runs all of it

Per `START HERE` §6: `git fetch` **at push time** · `merge-base --is-ancestor`
immediately above the command that acts on it · three-dot `diff --stat` ·
**blob** EOL check · each suite **alone** · no-fake-data grep · no-secret grep ·
single Alembic head if S12 grows one (it should not — an allowlist is code) ·
`code-review` skill · and **re-break at least three of the executor's guards**.

**Two things this repo has taught, the hard way, in the last week:**

- **`print("APPLIED:", new != src)` before believing any MISSED.** Files here are
  CRLF; a multi-line pattern written with `\n` silently matches nothing. This has
  caught a false MISSED at every gate it has been used at.
- **Establish the harness is sound before reporting a red.** Three times in one
  day a red was environmental: a vendor service on a UDP port (#236), a leftover
  background server moving a file's mtime, and a socket race (#240). **Kill what
  you started before you measure.**

⚠ Merge to **`foxyaudit-devtool`** with a normal push. Never
`git push origin <sha>:refs/heads/main` on the frozen repo — that is what the
judges see, and it deploys production.
