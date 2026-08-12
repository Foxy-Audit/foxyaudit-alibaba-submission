"""Deterministic, local policy checks for content-blind audit metadata.

Hashes cannot tell an evaluator whether a response contains unsafe advice or a
data leak. This engine therefore makes only claims supported by metadata and
marks the semantic part unknown unless an optional evaluator provides it.
"""

from __future__ import annotations

from typing import Any

from .schemas import Verdict

# Terminal, locally-decided event types. The host already enforced policy, so
# these are NEVER sent to an external judge — there is nothing to grade. They are
# recorded as prevented egress, not a breach.
#
# `response_blocked` (SDK >= 1.4) is a model response the SDK withheld from the
# calling application. It is a SEPARATE type from `blocked`, and both reasons are
# honesty rather than tidiness:
#
#   * `blocked` asserts the prompt never reached a provider. On a response block
#     it did — the model ran and tokens were spent.
#   * it is emitted ONLY when nothing reached the caller. A stream cut after some
#     chunks were already yielded is not prevention, so the SDK sends that as an
#     ordinary `stream` row carrying decision=response_truncated — graded
#     normally, and never counted as prevented egress in the Passport.
ENFORCEMENT_EVENT_TYPES = {"blocked", "redacted", "response_blocked"}

# Rule ids that record what the SDK's response scan COULD NOT READ
# (response_scan.degraded / .unreadable). They are real evidence and belong in
# the ledger, but they are not rules anything enforced, so they must never be
# tallied as such — "Policy rule enforced / Times fired" listing "we could not
# read the response 40 times" reads as a control that fired.
COVERAGE_RULE_PREFIX = "response_scan."


def is_coverage_rule(rule: object) -> bool:
    return isinstance(rule, str) and rule.startswith(COVERAGE_RULE_PREFIX)


def evaluate_enforcement(meta: dict[str, Any]) -> Verdict:
    """Deterministic verdict for a host-side enforcement event.

    Built only from the content-blind enforcement labels the host recorded — the
    terminal event_type, the policy rules that fired, and a short blocked_reason.
    A prevented egress is NOT a model breach: policy_breach is always False and the
    risk score is 0, because nothing unsafe was allowed to leave the host.
    """
    metadata = meta.get("event_metadata") or {}
    event_type = str(meta.get("event_type") or "")
    # event_type is the frozen wire signal that routed us here; trust it, then fall
    # back to the metadata decision label if it is somehow absent.
    decision = event_type if event_type in ENFORCEMENT_EVENT_TYPES else str(
        metadata.get("decision") or "")
    if decision not in ENFORCEMENT_EVENT_TYPES:
        decision = "blocked"
    rules = [str(rule)[:80] for rule in (metadata.get("policy_rules") or [])
             if isinstance(rule, str)]
    label = str(metadata.get("blocked_reason") or "").strip()[:200]
    if decision == "response_blocked":
        # Deliberately NOT "egress": the prompt did leave, the model did answer.
        # What was prevented is the response reaching the calling application.
        reason = (f"host_blocked_response:{label}" if label
                  else "host withheld the model response from the calling application")
    elif decision == "redacted":
        reason = (f"host_redacted_response:{label}" if label
                  else "host redacted the response before it left the host")
    else:
        reason = (f"host_blocked_egress:{label}" if label
                  else "host blocked the prompt before it left the host")
    return Verdict(
        policy_breach=False,
        reason=reason,
        risk_score=0,
        decision=decision,
        rules=rules,
    )


def evaluate(meta: dict[str, Any], policy_config: dict[str, Any] | None = None) -> Verdict:
    config = policy_config or {}
    rules: list[str] = []
    token_count = int(meta.get("token_count") or 0)
    pii_signals = [str(v) for v in (meta.get("pii_signals") or [])]
    max_tokens = int(config.get("max_token_threshold") or 50_000)

    if config.get("pii_detection", True) and pii_signals:
        rules.append("local_pii_signal")
    if token_count > max_tokens:
        rules.append("token_threshold_exceeded")

    if rules:
        return Verdict(
            policy_breach=True,
            reason="deterministic metadata policy rule matched",
            risk_score=min(100, 50 + 10 * len(rules)),
            decision="breach",
            rules=rules,
        )
    return Verdict(
        policy_breach=False,
        reason="deterministic metadata checks passed; semantic content not evaluated",
        risk_score=0,
        decision="clean",
        rules=[],
    )
