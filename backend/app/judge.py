"""Combine independent judge results without allowing disagreement to hide risk."""

from __future__ import annotations

import logging

from .schemas import Verdict

log = logging.getLogger("foxy.judge")

# A decision the audit report is allowed to trust from an AI judge. Host
# enforcement outcomes (blocked/redacted) are decided locally and must never arrive
# from a judge, so they are treated as out-of-schema here.
#
# `human_review` (Q2a) is an agentic judge calling `flag_for_human_review`. It is
# a DELIBERATE determination, so it belongs here — quarantining it as
# `decision_out_of_schema` would turn the one outcome the model chose on purpose
# into evidence that the model misbehaved.
_JUDGE_DECISIONS = {"clean", "breach", "human_review"}

# How judges' answers rank when they disagree. HIGHER WINS.
#
# ⚠ `human_review` OUTRANKS `clean`, and that is the whole reason this is a
# ladder and not a boolean. A judge that asked for a human did not pass the
# event; if a second judge saw nothing and returned `clean`, merging to `clean`
# would delete the request. That is #228's defect — an absence of evidence
# rendered as a confident result — reappearing one vocabulary later.
#
# `breach` outranks `human_review` because a breach is a finding, and a finding
# does not become weaker because another model wanted a second opinion.
#
# `unknown` is deliberately ABSENT: it is not a grade, and `combine` filters it
# out before ranking anything. Its handling is the early return below.
_DECISION_RANK = {"clean": 0, "human_review": 1, "breach": 2}

# The `reason` prefix each merged outcome carries, so a reader can tell a merged
# verdict from a single judge's one. Keyed by the same vocabulary as the ladder —
# a rank without a prefix would KeyError at merge time rather than silently
# picking a wrong label.
_MERGE_PREFIX = {
    "clean": "multi_judge_clean",
    "human_review": "multi_judge_human_review",
    "breach": "multi_judge_breach",
}
# A usable reason must carry at least this much signal; a blank/near-blank reason
# from an affirmative judge is low-confidence noise, not audit evidence.
_MIN_REASON_LEN = 3

# ── the content-blind projection, applied to everything leaving for a provider ─
# It lives HERE, not in a provider module, because it was in one: openai_judge
# projected and gemini did not, so the default provider received the whole
# event_metadata dict verbatim while a test asserting content-blindness against
# the openai helper stayed green. One list, one function, both judges.
#
# The allowlist is CUSTOMER OBSERVABILITY KEYS ONLY. Everything a judge needs to
# grade is above it in the projection; everything else in event_metadata is
# ledger bookkeeping that a third party has no reason to hold.
#
# ⚠ `system_id` (R2) IS DELIBERATELY ABSENT, and the reason is not "a UUID is
# harmless". Two halves:
#
#   * It buys a verdict NOTHING. Nothing in this projection tells a judge what
#     the system IS — not its purpose, its risk tier or its data classification
#     — so an opaque id is a symbol the grader cannot reason from.
#   * It costs a CORRELATION HANDLE. Unlike request_id / trace_id / session_id,
#     which are per-request or per-conversation, this value is stable for the
#     whole life of a declared system. Sending it would let a provider partition
#     one customer's traffic into their individual AI products and build a
#     longitudinal profile of each — "this bank's mortgage bot, 40k
#     interactions, these PII-signal rates". The linkage is the payload; the
#     digits carry nothing, and that is exactly why the digits are not the
#     question.
#
# If system-aware grading is ever wanted, the shape is to project the system's
# DECLARED ATTRIBUTES (risk tier, data classification) — grading signal with no
# identifier attached — and that is a decision with its own phase, not a side
# effect of widening ingest. Pinned by test_system_id.py.
SAFE_EVENT_METADATA = {
    "request_id", "trace_id", "session_id", "provider", "model", "id",
    "choice_count", "tool_names", "retrieval_refs", "client_seq_gap",
}


def content_blind_meta(meta: dict) -> dict:
    """Project metadata so accidental future fields cannot leak raw content.

    An ALLOWLIST rather than a denylist, and that is the whole point: a key
    added to the wire contract later is excluded until someone names it here,
    so widening ingest can never silently widen what reaches a provider.
    """
    safe_keys = (
        "prompt_hash", "response_hash", "token_count", "policy_tag",
        "pii_signals", "event_id", "event_type", "commitment_alg",
        "client_id", "client_seq",
    )
    projected = {key: meta.get(key) for key in safe_keys if key in meta}
    event_metadata = meta.get("event_metadata")
    if isinstance(event_metadata, dict):
        projected["event_metadata"] = {
            key: event_metadata[key]
            for key in SAFE_EVENT_METADATA
            if key in event_metadata
        }
    return projected


def _quarantine(problems: list[str], source: Verdict | None = None) -> Verdict:
    """An honest 'we could not determine this' — never a clean pass, never a breach."""
    return Verdict(
        policy_breach=False,
        reason="evaluator_unknown:" + ",".join(problems),
        risk_score=0,
        decision="unknown",
        rules=[],
        # Keep the provenance of the answer being thrown away. A model that keeps
        # returning unusable verdicts is exactly what an operator needs to see, and
        # that is unreadable once the only record says "unknown" with no author.
        judge_provider=source.judge_provider if source else None,
        judge_model=source.judge_model if source else None,
        # #228 · NOTHING graded this row. A model answered and was REFUSED, so
        # its answer is not a grade — but this is a different kind of event from
        # "the rules engine graded it", and a different kind again from "no
        # evaluator ran": here one was reached and BILLED, and it misbehaved.
        # The three stay separable — graded_by distinguishes rules from the two
        # non-grades, and `reason` (evaluator_unknown: vs evaluator_unavailable:)
        # plus the judge_provider kept two lines above distinguishes those two
        # from each other. A model returning unusable verdicts is precisely what
        # an operator needs to see, and it must never look like a deployment
        # that simply has no key.
        graded_by="none",
        # Deliberately NOT set: the evaluator was available. It answered.
        evaluator_unavailable_reason=None,
    )


def validate(verdict: Verdict) -> Verdict:
    """Gate an AI-judge verdict before it is persisted as audit evidence.

    An evaluator can hallucinate a self-contradictory or empty answer. Rather than
    launder that into a confident clean/breach grade, quarantine it as
    evaluator_unknown — an honest non-pass state that keeps the audit report from
    trusting a bad verdict. A verdict that is already an honest unknown (e.g. an
    unavailable evaluator) is returned untouched so the worker's deterministic
    fallback still applies.
    """
    if verdict.decision == "unknown":
        return verdict

    problems: list[str] = []
    if verdict.decision not in _JUDGE_DECISIONS:
        problems.append("decision_out_of_schema")
    if verdict.policy_breach and verdict.decision == "clean":
        problems.append("breach_flag_with_clean_decision")
    if not verdict.policy_breach and verdict.decision == "breach":
        problems.append("clean_flag_with_breach_decision")
    # Q2a · the same contradiction, one rung down the ladder. A judge that sets
    # the breach flag AND asks for a human has said two different things: the
    # flag is a finding, the decision is a request to look. Neither half can be
    # trusted over the other, so the pair is quarantined rather than resolved —
    # and resolving it silently is what would put a breach in the ledger under a
    # decision that never called it one.
    if verdict.policy_breach and verdict.decision == "human_review":
        problems.append("breach_flag_with_human_review_decision")
    if len((verdict.reason or "").strip()) < _MIN_REASON_LEN:
        problems.append("empty_or_low_confidence_reason")

    if problems:
        log.warning("quarantining judge verdict as evaluator_unknown: %s", problems)
        return _quarantine(problems, verdict)
    return verdict


def _decision(verdict: Verdict) -> str:
    # Treat a contradictory clean/policy_breach response conservatively.
    if verdict.decision == "clean" and verdict.policy_breach:
        return "breach"
    return verdict.decision


def combine(first: Verdict, second: Verdict) -> Verdict:
    """Merge two provider results; the strongest known outcome wins.

    `breach > human_review > clean` (:data:`_DECISION_RANK`), and `unknown` is
    still not a grade — it is filtered out before anything is ranked, so a
    single judge answering `unknown` beside one answering `clean` merges to
    `clean` exactly as it did before Q2a.
    """
    results = [(first, _decision(first)), (second, _decision(second))]
    known = [(verdict, decision) for verdict, decision in results
             if decision in _DECISION_RANK]
    if not known:
        return first

    # The strongest answer any judge gave, by the ladder. NOT `any(... ==
    # "breach")`: that shape only has room for two outcomes, and it is what
    # would have silently dropped a human_review beside a clean.
    decision = max((d for _, d in known), key=_DECISION_RANK.__getitem__)
    breach = decision == "breach"
    rules: list[str] = []
    for verdict, _ in known:
        for rule in verdict.rules:
            if rule not in rules:
                rules.append(rule)
    reasons = [verdict.reason for verdict, _ in known if verdict.reason]
    prefix = _MERGE_PREFIX[decision]
    return Verdict(
        # ⚠ TRACKS `decision`, so it is False for a human_review merge. A
        # request to look at something is not a finding, and `validate` would
        # refuse the pair anyway.
        policy_breach=breach,
        reason=f"{prefix}: " + "; ".join(reasons),
        risk_score=max(verdict.risk_score for verdict, _ in known),
        decision=decision,
        rules=rules,
        # Credit every model that contributed, in the same order `reason` merges
        # them. Only the KNOWN verdicts are named: a provider that fell over did
        # not grade this event and must not appear to have.
        judge_provider=_join(verdict.judge_provider for verdict, _ in known),
        judge_model=_join(verdict.judge_model for verdict, _ in known),
        # #228 · reached only when `known` is non-empty — i.e. at least one model
        # returned a usable clean/breach — so this merge IS an AI grade. The
        # early return above hands back `first` verbatim when no model answered,
        # which carries that verdict's own graded_by="none" and its unavailable
        # reason, so a double outage is not laundered into a grade here.
        graded_by="ai",
    )


def _join(values) -> str | None:
    """Comma-join the models that answered; None when none of them did."""
    present = [value for value in values if value]
    return ",".join(present) if present else None
