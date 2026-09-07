# The Foxy Audit submission dataset

**No model in Foxy Audit was trained, fine-tuned or distilled.** The agent is
Qwen — `qwen-plus` by default — called zero-shot on Alibaba Cloud Model Studio
with a system prompt built at request time and two tools it may call. There is
no weights file, no fine-tuning job, no training run, and nothing in this
directory was ever fed to a model as training data.

So this is not a training set, and calling it one would be exactly the kind of
unfalsifiable claim this product exists to make detectable. What it is instead:
the **evaluation corpora** the host-side guard is measured against, the **exact
content-blind records** the agent receives for each of those prompts, the
**agent's own contract**, and the **schema of the human-review feedback** it
consults at inference time.

---

## 1 · What this is, and what it is not

Four things shape what the agent does, and all four are code, not weights:

| What shapes the agent's behaviour | Where it lives |
|---|---|
| The system prompt, rebuilt per workspace policy at call time | `_build_system_prompt` in [`backend/app/qwen_judge.py`](../backend/app/qwen_judge.py) |
| Two tool schemas: `flag_for_human_review` and `check_prior_reviews` | `_TOOLS` and `_PRIOR_REVIEWS_TOOL`, same file |
| A ten-field input allowlist — everything else is dropped before the call | `content_blind_meta` in [`backend/app/judge.py`](../backend/app/judge.py) |
| Counts of how humans already ruled on this policy tag | `_prior_reviews_payload`, and the `human_reviews` table |

The agent is **content-blind**. It never receives a prompt or a response — only
hashes and bounded structural metadata. That is the product's central claim, and
`judge_contract.json` in this directory is the machine-readable form of it: the
allowlist is what the agent may see, and it is read out of the running function
rather than transcribed.

Every label in the `.jsonl` files here is **re-measured against the real SDK at
generation time**. `build_dataset.py` refuses to write a single file if any label
disagrees with what the engine actually does, and exits 1 naming the row. A
corpus whose labels were true when someone typed them is not evidence.

## 2 · How the agent learns without training

When the metadata cannot settle a question, the agent calls
`flag_for_human_review` instead of grading, and the interaction goes to a human
compliance reviewer. When that person rules on it, the ruling is written as an
append-only `human_review_resolved` event in the same tamper-evident ledger as
everything else — so the human's decision is itself audit evidence, not a
side-channel. On a later interaction carrying the same `policy_tag`, the agent
may call `check_prior_reviews` once and read back the **aggregate** of those
rulings. A tag humans have repeatedly cleared is weak ground for escalating
again; one they have repeatedly confirmed as a breach is strong ground for
grading it a breach.

No weights move. The loop runs entirely at inference time, and the prompt tells
the model that all-zero counts carry no information and must not change its
decision — zero is the state of every tag nobody has reviewed yet.

The reviewer's queue item carries these fields (`_item` in
[`backend/app/routers/reviews.py`](../backend/app/routers/reviews.py)):

```
id · seq · status · resolution · reason · risk_score · note · policy_tag ·
agent · event_created_at · created_at · resolved_at · resolved_by
```

`resolution` is one of `confirmed_breach`, `cleared`, `policy_gap`. `note` is the
only free-text field a human writes anywhere near the ledger; it is never hashed,
is excluded from the `human_review_resolved` event payload, and never reaches a
model. What `check_prior_reviews` returns is counts only —
`escalations`, `cleared`, `confirmed_breach`, `policy_gap`, `window_days`, plus
an echo of `policy_tag` — over a 30-day window.

**No human-review rows are shipped here.** On 2026-09-07 the deployed workspace
held one pending escalation and zero resolutions. One row is not a dataset, and
padding it would be fabrication. The schema is above; the data is not.

## 3 · Files

| File | Rows | What it is |
|---|---|---|
| `guard_probes.jsonl` | 35 | The sector probe corpus: labelled prompts across healthcare, finance and legal, each with the guard verdict measured today and the record the agent would receive for it |
| `injection_corpus.jsonl` | 81 | The prompt-injection obligation set, both directions: 11 evasions, 5 phrasings the previous ruleset already caught, 65 ordinary prompts that must stay clean |
| `identifier_corpus.jsonl` | 21 | The individually asserted identifier cases: 10 that must be detected, 11 placeholders that must not be |
| `judge_contract.json` | 1 object | The agent's default system prompt, its two tool schemas, the two metadata allowlists, and the verdict shape |
| `manifest.json` | — | SDK version, ruleset version, ruleset hash, and the row counts above |

The row counts in this table are the ones in `manifest.json`, which the generator
writes from the files it just produced. `judge_contract.json` is a single JSON
object rather than rows.

## 4 · Schemas

### `guard_probes.jsonl`

One row per probe, in sector order (`healthcare`, `finance`, `legal`) then
corpus order.

| Field | Meaning |
|---|---|
| `id` | Namespaced by sector, e.g. `healthcare.block.ssn` |
| `sector` · `policy_tag` | The preset and the tag it actually runs under. `finance` and `legal` run on `default` — neither has a rule family of its own, and the preset says so rather than inventing a tag |
| `prompt` | The synthetic prompt |
| `label` | `expect_block`, `expect_assist` or `known_gap` — the corpus's own vocabulary |
| `intent` | What this probe is testing |
| `gap_reason` | Required on `known_gap`, empty otherwise. The sentence a reader needs when nothing fires |
| `measured` | `triggered`, `rules`, `signals`, `reason` from `foxy_audit.check(prompt, policy_tag)` at generation time |
| `judge_input` | Seven of the ten fields of the content-blind record the agent receives for this prompt — see below |

**What `measured` means.** It is not a copy of the label. It is a fresh call into
the policy engine, and the generator asserts the two agree: `expect_block` must
trip a rule and carry rule ids, `expect_assist` and `known_gap` must trip none.
That is the same assertion `sdk/tests_testbed/test_probes.py` makes. A gap probe
that started firing is a finding, not a relabelling job, and it fails the build.

**What `judge_input` is.** The projection the agent would receive, computed with
the same SDK functions the wire uses — `hashing.canonical_json`,
`hashing.sha256_hex`, `hashing.estimate_tokens`, `pii.detect_pii` and
`client._merge_signals`.

**It is a subset, and the missing fields are missing on purpose.** The allowlist
in `judge_contract.json` has ten entries; these rows carry seven. `event_id` and
`client_id` are omitted because they are per-run identifiers — a fresh UUID and a
workspace-specific string — and either one would make this file different on
every generation, which would destroy the only guarantee it has. `client_seq` is
omitted because a ledger sequence number is a property of a real append, and
these probes were never appended to anything. The agent does receive all three in
production.

Five more things are worth stating plainly:

- **The hashes are the keyless SHA-256 form, and `commitment_alg` says so.** In
  production `prompt_hash` is an HMAC under the customer's own key, which is why
  the ledger is content-blind in a way a public hash is not. A public dataset
  cannot carry that form without a key, and no key was minted to make these look
  more production-shaped than they are.
- **`response_hash` is the hash of the empty string.** These probes are offline;
  no model was called, so there is no response. Inventing one would be inventing
  data. The block path in the SDK does the same thing for the same reason — a
  blocked prompt never reaches a provider, so its response is genuinely empty.
- **`event_type` is `blocked` when the guard tripped and `interaction` when it
  did not**, following what the SDK emits under `mode="block"`. The SDK's full
  vocabulary also includes `redacted`, `response_blocked`, `stream` and
  `exception`; none of those can arise from an offline prompt check.
- **`pii_signals` can be non-empty on a row the guard did not block**, and the
  two `finance.gap.*` probes are the only rows in the file where that happens.
  `finance.gap.cardholder_data` carries a Luhn-valid card number: under `default`
  the card check does not run, so the prompt is not blocked — but
  `log_interaction` sweeps unconditionally, so the emitted event still carries
  `credit_card`. That gap between what was *prevented* and what was *recorded* is
  exactly what the agent sees, and flattening it would misrepresent the product.
- **A signal is a shape, not a fact about the world.** `finance.gap.bank_account`
  carries `phone`, because the twelve-digit account number in it matches the
  phone pattern. The label is what the regex found, and it is recorded as such
  rather than corrected — the agent is content-blind and receives exactly this,
  so a dataset that quietly cleaned it up would be describing a better detector
  than the one that ships.

The mock provider's `reply` strings are **excluded**. They are fixture text a
human wrote for the testbed, not anything the agent ever receives.

### `injection_corpus.jsonl`

Three kinds in one file, measured under `policy_tag="default"` unless stated. The
`kind` field says which, and decides which of the other fields are present.

| Field | On | Meaning |
|---|---|---|
| `id` · `kind` · `label` · `prompt` | every row | |
| `mechanism` | evasion | `mechanical`, `semantic` or `declined` — whether a pattern can reach it in principle, cannot, or could and was deliberately not written |
| `intent` | evasion | What the payload is trying to make the assistant do |
| `why_it_passes` | evasion | Why the previous rules did not see it. On a `mechanical` row this is the specification the fix was written against |
| `rule` | already_caught | The rule id that must fire on this sentence |
| `sector` | benign | `healthcare`, `finance`, `legal`, `insurance` or `data` |
| `near_miss` | benign | The specific rule broadening this entry exists to break. **Empty on 16 of the 65 rows** — those are ordinary prompts carried for breadth rather than against a named failure |
| `measured` | every row | See below |

| `kind` | `label` | The assertion |
|---|---|---|
| `evasion`, `mechanism: mechanical` | `must_trigger` | The live ruleset fires an `injection.*` rule **and** the frozen `2026.08.4` definition did not. Both halves, because either alone proves nothing |
| `evasion`, `mechanism: semantic` or `declined` | `must_not_trigger_today` | Still uncaught, deliberately. A pattern over the prompt cannot separate these from ordinary work, and one broad enough to try would refuse the benign rows below |
| `already_caught` | `must_trigger` | The **named** rule id is among the rules that fire — not merely that something fired. A rewritten pattern catching the same sentence under a different id would silently re-tag every affected row on a customer's dashboard |
| `benign` | `must_stay_clean` | No `injection.*` rule fires under `default`, `soc2`, `hipaa` **or** `gdpr` |

Every row carries `measured.injection_rules`. Evasion and `already_caught` rows
also carry `measured_under_2026_08_4.injection_rules` — a replay of the frozen
previous ruleset, which is what makes "this was an evasion" a measurement rather
than a memory. Benign rows carry
`measured.injection_rules_by_policy_tag`, one list per tag.

The 49 benign rows that carry a `near_miss` are the load-bearing ones: an entry
nobody would think to write proves nothing. The benign corpus carries no personal
data on purpose — under `hipaa` a phone number would fire a `phi.*` rule and make
the measurement unreadable.

### `identifier_corpus.jsonl`

| Field | Meaning |
|---|---|
| `id` | `obligation.N` or `placeholder.N` |
| `text` | The string swept |
| `label` | `must_detect` or `must_not_detect` |
| `expected_signal` | On obligations: the label `pii.detect_pii` must return |
| `forbidden_signals` | On placeholders: `credit_card` and `phone`, the two that must be absent |
| `measured.signals` | What `pii.detect_pii(text, "")` returns today |

**Only the individually asserted cases are here.** The fixture module also holds
four large generated populations, but their guarantee is a per-**set**
false-positive rate, not a per-item label. Writing `must_not_detect` on each of
20,000 generated rows would be asserting something nobody measured.

Note that the placeholder assertion is the one the test actually makes:
`credit_card` and `phone` must be absent. It is not "no signal at all". Anything
else the sweep finds is recorded in `measured.signals` rather than forbidden.

### `judge_contract.json`

Read out of the backend at generation time, never transcribed.

| Key | Notes |
|---|---|
| `provider` · `endpoint` · `model_default` | From the `Settings` **field defaults**, not from live settings — reading the environment would make the output depend on whichever machine ran the generator |
| `input_allowlist` | The ten fields `content_blind_meta` passes through, read from the compiled function's own constant |
| `event_metadata_allowlist` | The ten `event_metadata` keys that survive the same projection, sorted |
| `system_prompt` | Built with an **empty** `policy_config` |
| `tools` | `flag_for_human_review` and `check_prior_reviews`, verbatim |
| `prior_reviews_payload_keys` · `prior_review_window_days` | The shape and reach of the feedback lookup |
| `verdict` | The five keys the model returns as JSON, and the pattern `Verdict.decision` is validated against |

**The shipped prompt is the *default* prompt, not "the" prompt.** An empty
`policy_config` is falsy, so `_build_system_prompt` omits its four
policy-derived rules; a workspace with an active policy config appends rules to
the tail of what you see here. `lookup_offered=True` because the deployed worker
does supply a prior-review lookup, and a prompt that named a tool the model was
not actually given would send it asking for something nobody can answer.

**There are no expected agent verdicts anywhere in this dataset**, on any row.
The model's output is not deterministic and has never been measured per probe, so
an "expected decision" column would be inventing labels for the one thing here
that nobody has measured. One live verdict is on record: on 2026-09-07 the
deployed instance graded an event with `policy_tag=hipaa` and 51 tokens, and
`qwen-plus` returned `decision=human_review` at `risk_score=85`. That is a single
sourced example and it is not a benchmark.

## 5 · Provenance

Every prompt in this directory is **synthetic** and was written by this project
for its own tests. Nothing came from a real patient, customer or user, and no
production data of any kind is present.

The identifiers are published fixtures rather than minted fakes:

- The AWS key is that vendor's own **published documentation key**.
- The OpenAI-shaped key is the placeholder already used in `sdk/tests/test_policy.py`.
- The card number is the canonical **non-issuable Visa test PAN**.
- Phone numbers are NANP fiction ranges (`555-01xx`) or repeated-digit placeholders.
- The SSN pattern uses the `900` prefix, which was never issued.

Both credential fixtures are already on this repository's gitleaks allowlist by
line regex, so the lines carrying them are allowlisted wherever they live. No new
path allowlist was added for this directory.

Licence: **MIT**, the same as the rest of the repository. See [`LICENSE`](../LICENSE).

## 6 · Regenerate and verify

The generator needs this repository's own SDK, not whatever `foxy_audit` happens
to be on your path. From the repository root:

```bash
python -m venv .venv
.venv/Scripts/activate          # source .venv/bin/activate on POSIX
pip install -e ./sdk
pip install -r backend/requirements.txt   # for judge_contract.json only

python dataset/build_dataset.py
```

The first line of output is `foxy_audit.__file__`. Check it points inside this
checkout before trusting a single measurement.

**Do not install the SDK's `[pii]` extra in that venv.** This dataset measures
the always-on regex layer, which is what every `pip install foxy-audit` gets. The
optional Presidio detector adds `presidio:*` labels that no plain install
reproduces, and under `hipaa` it can flip a probe's verdict outright. The
generator checks for it and refuses to run rather than emit bytes another machine
cannot regenerate.

```bash
python dataset/build_dataset.py --check   # exit 1 if any file is stale
```

`--check` regenerates every file into memory and compares **bytes** against what
is on disk. It is the drift gate: if a rule changes and the committed data no
longer matches, this fails. `.gitattributes` in this directory marks these files
`-text` so git never rewrites their line endings on checkout — without it a fresh
clone on Windows gets CRLF and the check fails on data that has not drifted.

The independent proof that the labels are true is the SDK's own suite, which
owns these corpora and asserts the same things:

```bash
pytest sdk/tests_testbed -q
pytest sdk/tests/test_injection_ruleset_2026_08_5.py -q
pytest sdk/tests/test_policy_truth_1_9_0.py -q
```

If those pass and `--check` passes, every label in this directory agrees with the
code that produced it.
