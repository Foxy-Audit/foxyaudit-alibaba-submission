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

# 1.9.0 — S8. Four defects where the guard said something that was not true.
#
# MINOR, and every item below is a BEHAVIOUR CHANGE rather than a bug fix in the
# invisible sense. Read them before upgrading a deployment that runs
# mode="block" or mode="redact"; mode="observe" (the default) is untouched.
#
#   #215 — pii._PHONE_RE / pii._CARD_CANDIDATE_RE OVER-BLOCKED.
#     Their lookarounds excluded an adjacent DIGIT but not an adjacent LETTER or
#     HYPHEN, so a digit run inside an identifier read as personal data:
#     `sk-ABCDEF0123456789ABCDEFGH`, a bare UUID, a commit sha, and 15.3% of real
#     SHA-256 digests all reported `phone` (0.45% also cleared Luhn as
#     `credit_card`). Under hipaa/gdpr in mode="block" each REFUSED A LEGITIMATE
#     PROMPT before the model call. The lookarounds now require a token boundary.
#
#     THE TWO DETECTORS TAKE DIFFERENT BOUNDARIES, and that is measured rather
#     than tidy. PHONE excludes an adjacent letter OR HYPHEN, because the bare
#     UUID carries a 12-digit run between hyphens that letters alone do not kill.
#     CARD excludes an adjacent LETTER ONLY, because excluding the hyphen there
#     deleted 90 of 450 real PAN shapes — `card-4111111111111111` and
#     `4111-1111-1111-1111-visa` among them. For a compliance product a missed
#     PAN is worse than a spurious label on an identifier.
#
#     The card candidate DOES chain across a UUID's hyphens (`[ \-]?` is a
#     separator, so `0000-0000-0000-0000` is one 16-digit run) and Luhn accepts
#     `0000000000000000`, so a NIL UUID reported credit_card. That is handled in
#     the validator rather than the boundary: a card number does not start with 0
#     (ISO/IEC 7812 assigns MII 0 to ISO/TC 68) and is not one repeated digit.
#     Both are free — neither can reject a real card — and they take the
#     zero-heavy identifier class from 2 853 in 10 120 to 2.
#     ⚠ THE COST: a PHONE glued directly to a hyphen with no separating space
#     ("Tel-4155550134") is no longer detected; a CARD glued to a LETTER
#     ("4111111111111111x") is not either. 5 random UUIDs in 20 000 still read as
#     credit_card, against 1.8.0's 33 — a residue, not a claim of zero. Every
#     phone shape the old regex accepted in a delimited context still matches
#     (56 448 generated shapes, zero lost), and every PAN shape except the
#     letter-glued ones. A card redaction also stops eating the space OR HYPHEN
#     that follows the number.
#
#   #216 — mode="redact" NOW BLOCKS when a finding survives its own redaction.
#     The guard stamped decision="redacted" without ever checking that the
#     finding had gone, so a rule redaction could not act on — a Presidio match,
#     a match spanning a structured prompt's JSON envelope, a value in a
#     non-string field — produced a ledger row claiming an enforcement action
#     that did not occur while the content reached the model. The redacted prompt
#     is now RE-EVALUATED (with the [REDACTED:…] markers neutralised), and
#     anything still matching raises FoxyPolicyBlocked with a `blocked`
#     event_type rather than a `redacted` one carrying a blocked decision.
#
#     PER FINDING, NEVER PER BYTE. "Did the text change?" is satisfied by a
#     neighbouring redaction that worked: an SSN scrubbed beside a Presidio-only
#     date of birth changes bytes, and the date of birth still goes. That is the
#     same false claim, narrower.
#     ⚠ A deployment on mode="redact" with the [pii] extra installed will see
#     prompts refused that used to go through. That is the point: they were going
#     through with the finding intact. Cost: one extra policy evaluation on the
#     guarded redact path — never on a clean prompt, never under observe.
#
#   #217 — a redaction marker no longer matches its own rule.
#     `injection.jailbreak` became `[REDACTED:jailbreak]`, which that rule's
#     pattern matches, so a customer re-checking their own redacted prompt was
#     told the finding was still there. Its marker is now
#     `[REDACTED:prompt_injection]`; the other eight prompt rules are unchanged.
#     Redaction is now a fixed point for every rule.
#
#   #218 — secret.private_key redacts the WHOLE PEM BLOCK.
#     It matched the "-----BEGIN … PRIVATE KEY-----" header alone, so redaction
#     removed the header and DELIVERED THE KEY BODY to the model. The span now
#     runs header → footer, or header → end of text when there is no footer.
#     Detection is unchanged; what a redaction removes is not.
#
# Ships ruleset 2026.08.3 — three patterns moved (#215's two detectors and
# #218's rule, the last recorded on both the prompt and response sides), the
# rule IDS are unchanged, and 2026.08.2 stays in the registry forever so rows
# naming it still replay against the rules that produced them. #217 changed a
# substitution string, which determines no rule id and is therefore outside what
# the ruleset hash covers; its guard is
# tests/test_policy_truth_1_9_0.py::test_217_every_marker_is_inert_under_every_rule.
#
# Proven against CHECKED-IN COPIES of the 1.8.0 policy and pii modules
# (sdk/tests/fixtures/), not against goldens written on the branch: every input
# that changed verdict is enumerated, and everything else is asserted identical
# across eight policy tags. The chain's data_blob
# (org_id|prompt_hash|response_hash|token_count|policy_tag|seq) is untouched, so
# nothing here can move a hash.
#
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
__version__ = "1.9.0"
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
