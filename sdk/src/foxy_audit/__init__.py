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

    @foxy.audit(policy="hipaa")
    def ask_model(prompt: str) -> str:
        return llm_client.generate(prompt)       # your code, unchanged

The default decorator mode does not block the wrapped function and keeps
telemetry errors out of your application. Set ``audit_required=True`` when
the application must fail closed if evidence delivery cannot be confirmed.

``policy`` selects the local checks, additively: prompt-injection and secret
detection run under EVERY tag, and ``hipaa`` / ``gdpr`` add a PHI / PII sweep on
top. ``hipaa_basic`` and ``gdpr_basic`` are accepted aliases. An unrecognised tag
runs the baseline and emits a ``UserWarning`` — it is not an error, because
``policy_tag`` is a free string customers label in their own terms, but it is no
longer silent. See ``policy.KNOWN_POLICY_TAGS`` and the SDK README.
"""

from .client import FoxyClient, FoxyPolicyBlocked, FoxyResponseBlocked
from .config import FoxyConfig
from .introspect import CheckResult, ExplainResult, check, explain

# 1.8.0 — S5. check() and explain() become public API.
#
#   check(prompt, policy=...)  -> CheckResult. "Would this trip anything?"
#   explain(prompt, event_id=..., export=..., commitment_key=...) -> ExplainResult
#   foxy check "..." --policy hipaa --json
#   foxy explain --event-id <uuid> --export logs.json --prompt-file p.txt
#
# MINOR: new public API, nothing existing changes. Until now the decorator was
# the only entry point — policy.evaluate was reachable but private, absent from
# __all__, and returned an internal dataclass — so there was no supported way to
# ask "would this prompt be blocked?" without wrapping a function.
#
# THE TWO HALVES HAVE OPPOSITE CONTENT RULES, ON PURPOSE. check() is
# content-blind: labels only, never the text, and it needs no API key, no
# network and no spool. explain() SHOWS the matched spans, because it answers
# "prove it was a real breach" on the customer's own machine against text they
# supplied — but those spans are stdout only, and ExplainResult.as_dict() omits
# them unless explicitly asked. See introspect.py's module docstring.
#
# explain() replays the row's OWN frozen ruleset, and says "I cannot" plainly in
# the three cases it must: a salted row with no sidecar salt, a row minted by a
# newer ruleset, and a row predating provenance entirely.
#
# CheckResult is a NEW type rather than the internal PolicyDecision — see its
# docstring for why.
#
# 1.7.0 — S4. Ruleset provenance. A guarded row now carries ruleset_version
# and ruleset_hash inside event_metadata, naming the FROZEN rule definitions that
# produced its policy_rules ids — so an auditor can establish what
# `injection.ignore_previous` meant on the day it matched instead of taking our
# word for it. Frozen, not current: rulesets/ holds one never-edited module per
# published version, and ruleset.drift() fails the suite if a rule is edited
# without minting a new one.
#
# MINOR because the wire gains fields. It rides INSIDE event_metadata, which has
# been chain-bound since V2, so it is tamper-evident with no new top-level field
# and no chain_version bump; old rows are untouched and still verify (proven
# through the standalone verifier against a mixed export, not asserted).
#
# ⚠ THE BACKEND HALF MUST BE DEPLOYED FIRST. event_metadata is validated against
# a strict allowlist per REQUEST, so an SDK sending these keys to a backend that
# does not know them loses the WHOLE BATCH to a 422. This SDK degrades rather
# than fail — on that specific rejection it retries once without the keys and
# records `foxy_degraded` on the spool receipt — but that is a safety net for
# self-hosted and lagging deployments, not a substitute for the ordering.
#
# Clean observe rows are byte-for-byte unchanged: provenance rides only with the
# policy_rules it explains.
#
# Ships ruleset 2026.08.2. 2026.08.1 could not explain the response_scan.*
# coverage ids that rows stamped with it already carried — an id naming a
# version that does not describe it is the failure the registry exists to
# prevent, and it landed on the ids that report MISSING COVERAGE. Both versions
# stay in the registry; frozen modules are never edited.
#
# ruleset_version/ruleset_hash are RESERVED in event_metadata: passing either is
# warned once and dropped, so they always mean "the SDK computed this".
#
# 1.6.0 — #166/#167. The policy map is ADDITIVE and hipaa_basic is a real tag.
# Injection + secret checks now run under EVERY tag instead of being replaced by
# the domain sweep, and hipaa_basic/gdpr_basic alias onto hipaa/gdpr. Before
# this, our own quickstart tag was not in the map at all: it fell through to the
# default and ran ZERO PHI detection, while the row it shipped was labelled
# hipaa_basic and the Compliance Passport grouped its statistics by that label.
#
# MINOR, and it is a behaviour change on purpose: under block/redact a hipaa or
# gdpr prompt carrying an injection pattern or a credential is now stopped or
# scrubbed where it previously passed, so a redact-mode model call can receive
# different text than it did on 1.5.x. observe mode is untouched — the preflight
# guard never runs there. Breach counts do not rise from the new pii_signals
# labels: only enforcement rows gain them, and evaluate_enforcement never reads
# that field. policy_tag is recorded verbatim; only the CHECKS resolve through
# the alias, so no historical row changes meaning.
#
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
__version__ = "1.8.0"
__all__ = ["CheckResult", "ExplainResult", "FoxyClient", "FoxyConfig",
           "FoxyPolicyBlocked", "FoxyResponseBlocked", "audit", "check",
           "explain", "__version__"]

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
