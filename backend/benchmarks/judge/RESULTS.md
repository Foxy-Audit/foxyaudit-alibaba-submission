# J1 results — 2026-08-17

**Status: the harness and corpus are complete; the live half of the benchmark
is blocked on provider keys.** No judge API key of any kind exists on the
development machine — `backend/.env` carries `GEMINI_API_KEY=` **empty**, no
`OPENAI_API_KEY` anywhere, nothing in any environment scope. Publishing that
blocker as the current answer is the point of this phase: today the honest
value for every live number below is *unmeasured*, and nothing here fabricates
one.

## The four measurements

| # | Measurement | Result | Sample |
|---|---|---|---|
| 1 | Inter-provider agreement (gemini vs openai) | **not yet run** — needs both keys | 40 rows ready |
| 2 | Stability (same row, N runs) | **not yet run** — needs a key | 12 rows × 5 runs ready |
| 3 | Agreement with the deterministic path | **not yet run** — needs a key (the deterministic side is computed and checked in) | 40 rows ready |
| 4 | Labeled accuracy | **judge side not yet run**; deterministic baseline **20/20 (100%)** | 20 labeled rows |

The deterministic baseline's 100% must be read for what it is: the labels were
derived from the written policy rules, and the deterministic engine implements
those same rules, so it scores perfectly **by construction**. The labeled set
does not prove the engine right — it exists to test whether the *judge* tracks
the rules it is prompted with (boundary rows like L13/L14, config-gating rows
like L16, history-vs-event rows like L18 are exactly where a language model
can drift from the written rule). Any judge score below 100% on this set is a
real finding; the baseline's 100% is not one.

## What was measured today (no key required)

### `combine()` — executed over the full verdict-pair space (25 pairs, both orders)

Raw table: `results/run-20260817T145314Z-offline.json`. Measured behaviour:

- **Any known breach wins**, in either order, and the combined `risk_score`
  is the max of the known verdicts. Matches the docstring.
- **A self-contradictory verdict (`decision: clean` + `policy_breach: true`)
  is treated as breach** — conservative, and it also wins over a clean from
  the other provider.
- **`clean + unknown` combines to a confident `clean`** with reason prefix
  `multi_judge_clean`, even though only one judge actually answered.
  "Unknown is never clean" holds for the unknown verdict itself, but a single
  surviving judge's clean passes through unqualified. Provenance stays honest
  (`judge_provider` names only the model that answered), but the reason
  string's `multi_judge_` prefix overstates how many judges graded. Finding,
  not a fix — noted for a follow-up phase.
- **`unknown + unknown` returns the first verdict verbatim** (decision
  `unknown`), so a double outage stays an honest unknown.

### Deterministic verdicts for all 40 corpus rows

Computed offline and stored in the results file, so measurement 3 is a pure
diff the moment judge verdicts exist.

## Cost bound (stated before any sweep, as required)

Full default sweep = **88 calls per provider** (40-row main sweep + 12
stability rows × 4 extra runs), ≈ 48k input / 7k output tokens per provider:

- gemini-2.5-flash: **≈ $0.03** (or $0 on the free tier)
- gpt-5.6 (list-price estimate): **≈ $0.13**

Corpus size, stability rows, and runs are all CLI-bounded (`--rows`,
`--stability-rows`, `--stability-runs`, `--rpm`).

## To produce the live numbers (owner)

```bash
# from backend/, either locally with keys exported, or on the prod VM where
# the platform keys live:
GEMINI_API_KEY=... python benchmarks/judge/run_benchmark.py --providers gemini
GEMINI_API_KEY=... OPENAI_API_KEY=... \
  python benchmarks/judge/run_benchmark.py --providers gemini,openai
```

The script prints the call count and spend estimate before calling, throttles
to 8 requests/minute, retries transport failures so rate limits do not pollute
the unknown-rate number, and writes every raw verdict to `results/` (no key
material). Then update this file with the four numbers, whatever they are.

## Honest read so far

- The one production-shaped fact this phase established without spending a
  cent: **on this development machine the judge never runs at all** — every
  locally graded event takes the `evaluator_unavailable` → deterministic
  fallback path. Any local demo that appears to show AI grading is showing
  the deterministic engine.
- Whether the judge *earns its place* is exactly the question the unlabeled
  rows (U01–U20) will answer: they are the shapes where a judge could add
  value over the rules (hipaa tag at 3 000 tokens, replayed commitments,
  rising breach rate) — or add noise (flipping on explicit-rule rows under
  `confidence_threshold: high`). Until the sweep runs, the defensible public
  claim is: *breach detection on enforcement paths is deterministic and
  measured; AI-judge grading quality is instrumented but not yet measured.*
