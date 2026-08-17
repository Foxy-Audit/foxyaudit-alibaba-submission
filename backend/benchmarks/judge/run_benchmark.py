"""J1 — measure the AI judge. This script MEASURES; it never tunes.

Four measurements over the checked-in corpus (built before any judge run):

  1. inter-provider agreement   gemini vs openai on identical metadata
  2. stability                  same row, same config, N runs per provider
  3. vs the deterministic path  policy_engine.evaluate on the same rows
  4. labeled accuracy           the small hand-labeled subset only

Plus the reliability numbers nobody had: the evaluator_unavailable /
evaluator_unknown (quarantine) rates, and judge.combine() measured by
executing it over the whole verdict-pair space rather than reading it.

The judges see ONLY metadata — hashes, token_count, policy_tag, pii_signals,
history. Nothing here measures content detection; that is the SDK's job and
would be the wrong yardstick.

Cost: this makes live provider calls. It prints the call count and a spend
estimate first; pass --estimate-only to stop there. Keys come from
GEMINI_API_KEY / OPENAI_API_KEY in the environment and are never written
anywhere by this script.

Usage (from backend/):
  python benchmarks/judge/run_benchmark.py --estimate-only
  python benchmarks/judge/run_benchmark.py --providers gemini
  python benchmarks/judge/run_benchmark.py --providers gemini,openai
"""

from __future__ import annotations

import argparse
import json
import os
import statistics
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))  # backend/

from app import gemini, judge, openai_judge, policy_engine  # noqa: E402
from app.schemas import Verdict  # noqa: E402

HERE = Path(__file__).resolve().parent

# Rough public list prices, USD per 1M tokens, for the ESTIMATE line only
# (2026-08; the printed spend estimate is advisory, not a bill).
PRICES = {"gemini": (0.30, 2.50), "openai": (1.25, 10.00)}

EVALUATORS = {"gemini": gemini.evaluate, "openai": openai_judge.evaluate}
KEY_ENV = {"gemini": "GEMINI_API_KEY", "openai": "OPENAI_API_KEY"}


def _est_tokens(row: dict) -> tuple[int, int]:
    """Very rough (input, output) token estimate for one call on one provider."""
    system = gemini._build_system_prompt(row["policy_config"], row["history"])
    payload = json.dumps({**row["meta"], "recent_history": row["history"]})
    return (len(system) // 4 + len(payload) // 4 + 40, 80)


def _call(provider: str, row: dict, key: str, retries: int, throttle: float,
          state: dict) -> dict:
    """One judged verdict with transport-failure retries and rate throttling.

    ``evaluate`` never raises — transport failures come back as
    ``evaluator_unavailable`` verdicts, which we retry (they measure our
    network/rate-limit, not the judge) and count separately.
    """
    evaluate = EVALUATORS[provider]
    attempts = 0
    while True:
        wait = state["next_at"] - time.monotonic()
        if wait > 0:
            time.sleep(wait)
        state["next_at"] = time.monotonic() + throttle
        attempts += 1
        verdict = evaluate(row["meta"], row["policy_config"],
                           history=row["history"], api_key=key)
        unavailable = (verdict.decision == "unknown"
                       and verdict.reason.startswith("evaluator_unavailable"))
        if not unavailable or attempts > retries:
            break
        time.sleep(min(60.0, 10.0 * attempts))  # backoff before the retry
    validated = judge.validate(verdict)
    return {"raw": verdict.model_dump(), "validated": validated.model_dump(),
            "attempts": attempts, "transport_failed": unavailable}


# ── metrics (pure functions over recorded verdict dicts) ─────────────────────

def _known(v: dict) -> bool:
    return v["decision"] in ("clean", "breach")


def agreement(rows: list[dict], a: str, b: str) -> dict:
    """Measurement 1: providers a and b on identical metadata."""
    both = [r for r in rows if _known(r["runs"][a][0]["validated"])
            and _known(r["runs"][b][0]["validated"])]
    same = [r for r in both if r["runs"][a][0]["validated"]["policy_breach"]
            == r["runs"][b][0]["validated"]["policy_breach"]]
    gaps = [abs(r["runs"][a][0]["validated"]["risk_score"]
                - r["runs"][b][0]["validated"]["risk_score"]) for r in both]
    return {
        "rows_both_known": len(both),
        "agree_policy_breach": len(same),
        "agree_pct": round(100 * len(same) / len(both), 1) if both else None,
        "disagreements": [r["id"] for r in both if r not in same],
        "risk_gap_mean": round(statistics.mean(gaps), 1) if gaps else None,
        "risk_gap_median": statistics.median(gaps) if gaps else None,
        "risk_gap_max": max(gaps) if gaps else None,
    }


def stability(rows: list[dict], provider: str) -> dict:
    """Measurement 2: decision flips and risk spread across repeated runs."""
    per_row, flips = [], 0
    multi = [r for r in rows if len(r["runs"].get(provider, [])) > 1]
    for r in multi:
        runs = [x["validated"] for x in r["runs"][provider]]
        known = [v for v in runs if _known(v)]
        breaches = {v["policy_breach"] for v in known}
        risks = [v["risk_score"] for v in known]
        flipped = len(breaches) > 1
        flips += flipped
        per_row.append({
            "id": r["id"], "runs": len(runs), "known": len(known),
            "flipped": flipped,
            "decisions": [v["decision"] for v in runs],
            "risk_min": min(risks) if risks else None,
            "risk_max": max(risks) if risks else None,
            "risk_spread": (max(risks) - min(risks)) if risks else None,
        })
    spreads = [p["risk_spread"] for p in per_row if p["risk_spread"] is not None]
    return {
        "rows": len(multi), "flipped_rows": flips,
        "flip_rate_pct": round(100 * flips / len(multi), 1) if multi else None,
        "risk_spread_mean": round(statistics.mean(spreads), 1) if spreads else None,
        "risk_spread_max": max(spreads) if spreads else None,
        "per_row": per_row,
    }


def vs_deterministic(rows: list[dict], provider: str) -> dict:
    """Measurement 3: where the judge contradicts the deterministic engine."""
    known = [r for r in rows if _known(r["runs"][provider][0]["validated"])]
    contradictions = []
    for r in known:
        jv = r["runs"][provider][0]["validated"]
        dv = r["deterministic"]
        if jv["policy_breach"] != dv["policy_breach"]:
            contradictions.append({
                "id": r["id"],
                "deterministic": dv["policy_breach"], "judge": jv["policy_breach"],
                "det_rules": dv["rules"], "judge_reason": jv["reason"][:160],
            })
    n = len(known)
    return {
        "rows_judge_known": n,
        "agree": n - len(contradictions),
        "agree_pct": round(100 * (n - len(contradictions)) / n, 1) if n else None,
        "contradictions": contradictions,
    }


def labeled_accuracy(rows: list[dict], provider: str) -> dict:
    """Measurement 4: the hand-labeled subset only."""
    labeled = [r for r in rows if r["expected"] is not None]
    known = [r for r in labeled if _known(r["runs"][provider][0]["validated"])]
    correct, fp, fn = [], [], []
    for r in known:
        got = r["runs"][provider][0]["validated"]["policy_breach"]
        want = r["expected"] == "breach"
        (correct if got == want else (fp if got else fn)).append(r["id"])
    return {
        "labeled_rows": len(labeled), "judge_answered": len(known),
        "correct": len(correct),
        "accuracy_pct": round(100 * len(correct) / len(known), 1) if known else None,
        "false_positives": fp, "false_negatives": fn,
        "unanswered": [r["id"] for r in labeled if r not in known],
    }


def deterministic_labeled_baseline(rows: list[dict]) -> dict:
    """The free baseline the judge must beat on the labeled set."""
    labeled = [r for r in rows if r["expected"] is not None]
    correct = [r["id"] for r in labeled
               if r["deterministic"]["policy_breach"] == (r["expected"] == "breach")]
    return {"labeled_rows": len(labeled), "correct": len(correct),
            "accuracy_pct": round(100 * len(correct) / len(labeled), 1)
            if labeled else None,
            "wrong": [r["id"] for r in labeled if r["id"] not in correct]}


def unknown_rates(rows: list[dict], provider: str) -> dict:
    """Reliability: how often a real call lands outside clean/breach."""
    calls = [run for r in rows for run in r["runs"].get(provider, [])]
    unavailable = [c for c in calls if c["transport_failed"]]
    quarantined = [c for c in calls
                   if c["validated"]["reason"].startswith("evaluator_unknown")]
    retried = [c for c in calls if c["attempts"] > 1]
    n = len(calls)
    return {
        "calls": n,
        "evaluator_unavailable_after_retries": len(unavailable),
        "evaluator_unknown_quarantined": len(quarantined),
        "unknown_rate_pct": round(100 * (len(unavailable) + len(quarantined)) / n, 1)
        if n else None,
        "calls_needing_retry": len(retried),
    }


def combine_table(rows: list[dict], providers: list[str]) -> dict:
    """judge.combine() measured by execution, not by reading.

    Exhaustive: representative verdicts for every decision shape, both orders.
    Empirical: the real per-row pairs when both providers ran.
    """
    shapes = {
        "clean": Verdict(policy_breach=False, reason="clean says ok",
                         risk_score=10, decision="clean", rules=[]),
        "breach": Verdict(policy_breach=True, reason="breach found",
                          risk_score=80, decision="breach", rules=["rule_a"]),
        "contradictory_clean": Verdict(policy_breach=True, reason="clean but flagged",
                                       risk_score=40, decision="clean", rules=["rule_b"]),
        "unknown_unavailable": Verdict(policy_breach=False,
                                       reason="evaluator_unavailable:timeout",
                                       risk_score=0, decision="unknown", rules=[]),
        "unknown_quarantined": Verdict(policy_breach=False,
                                       reason="evaluator_unknown:decision_out_of_schema",
                                       risk_score=0, decision="unknown", rules=[]),
    }
    exhaustive = {}
    for na, va in shapes.items():
        for nb, vb in shapes.items():
            out = judge.combine(va, vb)
            exhaustive[f"{na}+{nb}"] = {
                "decision": out.decision, "policy_breach": out.policy_breach,
                "risk_score": out.risk_score,
            }
    empirical = []
    if len(providers) == 2:
        a, b = providers
        for r in rows:
            va = Verdict(**r["runs"][a][0]["validated"])
            vb = Verdict(**r["runs"][b][0]["validated"])
            out = judge.combine(va, vb)
            empirical.append({"id": r["id"], "a": va.decision, "b": vb.decision,
                              "combined": out.decision,
                              "policy_breach": out.policy_breach})
    return {"exhaustive": exhaustive, "empirical": empirical}


# ── driver ───────────────────────────────────────────────────────────────────

def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--providers", default="gemini",
                    help="comma list: gemini,openai")
    ap.add_argument("--rows", type=int, default=0,
                    help="cap corpus rows (0 = all)")
    ap.add_argument("--stability-runs", type=int, default=5,
                    help="total runs per stability row (main sweep is run 1)")
    ap.add_argument("--stability-rows", type=int, default=0,
                    help="cap stability rows (0 = all flagged)")
    ap.add_argument("--retries", type=int, default=3,
                    help="retries per call on transport failure")
    ap.add_argument("--rpm", type=float, default=8.0,
                    help="max requests/minute per provider")
    ap.add_argument("--estimate-only", action="store_true")
    ap.add_argument("--corpus", default=str(HERE / "corpus.json"))
    args = ap.parse_args()

    providers = [p.strip() for p in args.providers.split(",") if p.strip()]
    for p in providers:
        if p not in EVALUATORS:
            ap.error(f"unknown provider {p!r}")

    corpus = json.loads(Path(args.corpus).read_text(encoding="utf-8"))
    rows = corpus["rows"][: args.rows or None]
    stab = [r for r in rows if r["stability"]][: args.stability_rows or None]
    stab_ids = {r["id"] for r in stab}
    extra = max(0, args.stability_runs - 1)
    calls_per_provider = len(rows) + len(stab) * extra

    est_in = est_out = 0
    for r in rows:
        i, o = _est_tokens(r)
        n = 1 + (extra if r["id"] in stab_ids else 0)
        est_in += i * n
        est_out += o * n
    print(f"corpus: {len(rows)} rows ({sum(r['expected'] is not None for r in rows)}"
          f" labeled), stability {len(stab)} rows x {args.stability_runs} runs")
    print(f"calls per provider: {calls_per_provider} "
          f"(~{est_in:,} in / ~{est_out:,} out tokens)")
    for p in providers:
        pin, pout = PRICES[p]
        print(f"  est spend {p}: ${est_in / 1e6 * pin + est_out / 1e6 * pout:.2f}")
    if args.estimate_only:
        return 0

    keys = {}
    for p in providers:
        keys[p] = os.environ.get(KEY_ENV[p], "")
        if not keys[p]:
            print(f"ERROR: {KEY_ENV[p]} is not set; cannot run provider {p}")
            return 1

    started = datetime.now(timezone.utc)
    results = []
    for r in rows:
        results.append({
            "id": r["id"], "expected": r["expected"],
            "deterministic": policy_engine.evaluate(
                r["meta"], r["policy_config"]).model_dump(),
            "runs": {},
        })

    throttle = 60.0 / args.rpm
    for p in providers:
        state = {"next_at": 0.0}
        for r, out in zip(rows, results):
            out["runs"][p] = [_call(p, r, keys[p], args.retries, throttle, state)]
            print(f"  {p} {r['id']} -> "
                  f"{out['runs'][p][0]['validated']['decision']}", flush=True)
        for run_no in range(extra):
            for r, out in zip(rows, results):
                if r["id"] not in stab_ids:
                    continue
                out["runs"][p].append(
                    _call(p, r, keys[p], args.retries, throttle, state))
                print(f"  {p} {r['id']} stability {run_no + 2}/"
                      f"{args.stability_runs} -> "
                      f"{out['runs'][p][-1]['validated']['decision']}", flush=True)

    report = {
        "started": started.isoformat(),
        "finished": datetime.now(timezone.utc).isoformat(),
        "providers": providers,
        "settings": {"stability_runs": args.stability_runs, "rpm": args.rpm,
                     "retries": args.retries},
        "corpus_rows": len(rows),
        "measurements": {},
        "rows": results,
    }
    m = report["measurements"]
    if len(providers) == 2:
        m["inter_provider_agreement"] = agreement(results, *providers)
    for p in providers:
        m[f"stability_{p}"] = stability(results, p)
        m[f"vs_deterministic_{p}"] = vs_deterministic(results, p)
        m[f"labeled_accuracy_{p}"] = labeled_accuracy(results, p)
        m[f"unknown_rates_{p}"] = unknown_rates(results, p)
    m["deterministic_labeled_baseline"] = deterministic_labeled_baseline(results)
    m["combine"] = combine_table(results, providers)

    out_dir = HERE / "results"
    out_dir.mkdir(exist_ok=True)
    stamp = started.strftime("%Y%m%dT%H%M%SZ")
    out_path = out_dir / f"run-{stamp}-{'-'.join(providers)}.json"
    out_path.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    print(f"\nwrote {out_path}")
    print(json.dumps(m, indent=2))
    return 0


if __name__ == "__main__":
    sys.exit(main())
