"""
Foxy Audit SDK — Governance-as-Code for AI applications.

Wrap any LLM call with the ``@audit`` decorator and every invocation is
committed locally with a customer key, the raw text is discarded, and only metadata is
streamed to the Foxy Audit backend — plus a best-effort local UDP ping that
makes the desktop "fox" companion react in real time.

Quickstart
----------
    from foxy_audit import FoxyClient

    foxy = FoxyClient(api_key="foxy_sk_...")     # or set $FOXY_API_KEY

    @foxy.audit(policy="hipaa_basic")
    def ask_model(prompt: str) -> str:
        return llm_client.generate(prompt)       # your code, unchanged

The default decorator mode does not block the wrapped function and keeps
telemetry errors out of your application. Set ``audit_required=True`` when
the application must fail closed if evidence delivery cannot be confirmed.
"""

from .client import FoxyClient, FoxyPolicyBlocked, FoxyResponseBlocked
from .config import FoxyConfig

# 1.5.0 — #158. mode="redact" now examines the RESPONSE for PII. A redact row's
# pii_signals is the union of what fired on the prompt and what the full sweep
# finds; before this the sweep was skipped on exactly those rows, so PII the
# model returned went unrecorded — in the one mode chosen because PII matters.
#
# MINOR because the emitted payload changes for a whole mode, and pii_signals is
# chain material, so rows recorded from here on cover labels earlier ones did
# not. NOT because breach counts move: they do not. A redacted row is graded by
# policy_engine.evaluate_enforcement, which never reads pii_signals, on both the
# chained local verdict and the graded one. Measured, not assumed — see
# test_a_redacted_rows_pii_signals_do_not_make_it_a_breach.
#
# 1.4.0 — response scanning (OWASP LLM05). MINOR, not patch: there is new public
# API (FoxyResponseBlocked, the response_scan setting, FOXY_RESPONSE_SCAN) and a
# new exception type an application can now see. The DEFAULT is detect-only, so
# nothing an existing caller receives changes and nothing new raises unless the
# deployment opts in — but "you can now configure a new exception into your call
# path" is a feature, and a patch release must not carry one.
#
# It also emits one NEW event_type, `response_blocked`, when response_scan=block
# withholds a response and nothing reached the caller. Against a backend older
# than that change the row still ingests — event_type is charset-validated, not
# enumerated — but is graded by the judge as an ordinary interaction instead of
# taking the deterministic enforcement path, and the Compliance Passport does not
# count it. Degraded, never broken, and only for a deployment that opted into
# blocking. Nothing is emitted under the default.
__version__ = "1.5.0"
__all__ = ["FoxyClient", "FoxyConfig", "FoxyPolicyBlocked", "FoxyResponseBlocked",
           "audit", "__version__"]

# Module-level convenience: a lazily-created client configured from the
# environment (FOXY_API_KEY / FOXY_BACKEND_URL), so `from foxy_audit import audit`
# works without explicitly constructing a client.
_default_client = None


def _client() -> FoxyClient:
    global _default_client
    if _default_client is None:
        _default_client = FoxyClient()
    return _default_client


def audit(policy: str = "default", agent: str | None = None, mode: str | None = None):
    """Decorator bound to the default environment-configured client.

    ``mode`` selects the preflight behaviour ("observe"|"block"|"redact");
    when omitted it follows the client's configured mode (FOXY_MODE)."""
    return _client().audit(policy, agent=agent, mode=mode)
