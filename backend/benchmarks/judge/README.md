# J1 — AI-judge benchmark

Every other claim this product makes has a number behind it; how often the AI
judge is *right* never did. This directory measures the narrow task the judge
actually has — grading **content-blind metadata** (hashes, token_count,
policy_tag, pii_signals, 7-day history). It never sees prompt or response
text, so "did it spot the SSN" would be the wrong yardstick and is not
measured here.

**This benchmark measures. It never tunes.** If a number suggests a fix, that
is a finding for a follow-up phase, not a change on this branch.

## The four measurements

1. **Inter-provider agreement** — Gemini and GPT grade identical rows;
   % agreement on `policy_breach` and the `risk_score` gap between them.
2. **Stability** — the same row, same config, N runs; the flip rate.
3. **Agreement with the deterministic path** — `policy_engine.evaluate` on the
   same rows; every contradiction listed.
4. **Labeled accuracy** — only the small hand-labeled subset of the corpus,
   where the correct answer follows from the written policy rules alone.
   The deterministic engine is scored on the same subset as the free baseline
   the judge has to beat.

Also reported: the `evaluator_unavailable` / `evaluator_unknown` (quarantine)
rates per call, and `judge.combine()` measured by executing it over the full
verdict-pair space (plus the real per-row pairs when both providers ran).

## The corpus

`corpus.json` — 40 rows, 20 labeled, 12 flagged for the stability subset.
Hand-built from the written policy rules **before any judge run** and checked
in first, so the answers could not be assembled around what the judges said.
Rows whose correct answer is genuinely arguable (a hipaa tag at 3 000 tokens,
bad history around a clean row, a signal under `confidence_threshold: high`)
are deliberately **unlabeled** — they feed measurements 1–3 only. Commitments
are synthetic (`sha256` of the row id); the judges treat them as opaque.

## Running it

Costs real money (live provider calls) — the script prints the call count and
a spend estimate first. Full default sweep: **88 calls per provider**,
≈ $0.03 (gemini-2.5-flash) / ≈ $0.13 (gpt-5.6, list-price estimate).

```bash
cd backend
python benchmarks/judge/run_benchmark.py --estimate-only   # no calls
GEMINI_API_KEY=... python benchmarks/judge/run_benchmark.py --providers gemini
GEMINI_API_KEY=... OPENAI_API_KEY=... \
  python benchmarks/judge/run_benchmark.py --providers gemini,openai
```

Bounding knobs: `--rows N` caps the corpus, `--stability-rows` /
`--stability-runs` bound the stability sweep, `--rpm` throttles (default 8/min
— free-tier friendly). Keys are read from the environment only and are never
written by the script; raw results land in `results/` with no key material.

Measurement 1 needs both keys. If only one provider is available, run it
alone — the harness computes everything that provider supports and the
inter-provider block is simply absent.

## Reading the output

`results/run-<stamp>-<providers>.json` holds every raw verdict, so every
published number is recomputable from the file. The headline numbers live in
`RESULTS.md` next to this file.
