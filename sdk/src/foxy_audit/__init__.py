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

# 1.11.0 — S10. A card number begins with an issuer, and the card detector now
# knows that.
#
# ⚠ THIS CHANGES WHAT FIRES, so it mints ruleset 2026.08.4 and a new validator
# name. Read it before upgrading a deployment that runs mode="block" or
# mode="redact" under a policy that includes phi/pii.
#
#   The card gate was Luhn plus "not one repeated digit". Luhn is a single check
#   digit — roughly one random 13-19 digit run in ten passes it — so any
#   hyphen-delimited build id, order number or correlation id of the right
#   length had a one-in-ten chance of being reported as a credit card. Measured
#   on the checked-in obligation corpus: 2 016 of 20 000 build ids (10.08%).
#   Under `hipaa` that fires `phi.credit_card`, which BLOCKS the prompt in
#   mode="block", mangles it under mode="redact", and in observe mode lands in
#   pii_signals where one label makes the backend's deterministic verdict a
#   BREACH.
#
#   A card number is not an arbitrary Luhn-passing run: its leading digits are
#   an issuer identification number assigned under ISO/IEC 7812, and those
#   assignments are public. The gate now requires one. See
#   foxy_audit.issuer_ranges, which keeps the table as a table — Visa,
#   Mastercard (including the 2221-2720 series), Amex, Discover, Diners, JCB,
#   UnionPay and Maestro — so it can be checked against the issuers' own
#   published ranges rather than trusted.
#
#   Measured, same corpora, same run:
#
#       build-id false positives   2 016 (10.08%)  ->  621 (3.10%)
#       zero-heavy id findings             2       ->    0
#       random-UUID findings               5       ->    4
#       PAN recall                  504/540 (93.33%)  ->  504/540 (93.33%)
#
#   ⚠ "NO RECALL COST" IS TRUE ON THIS CORPUS AND UNPROVEN IN GENERAL. The
#   obligation corpus is built from mainstream test cards (4111…, 5500…, 6011…,
#   3782…) which all carry valid IINs BY CONSTRUCTION, so it cannot show what a
#   regional or private-label issuer outside the table would do — it would now
#   be MISSED.
#
#   NAMED, BECAUSE IT IS NOT HYPOTHETICAL: RuPay. India's domestic network
#   issues from 60, 6521, 6522, 81, 82 and 508, and only the two 65-prefixed
#   ranges are covered
#   (they sit inside Discover's 65). A RuPay card on 60, 81, 82 or 508 is NOT
#   detected. A deliberate trade — those ranges cost false positives, and no
#   RuPay card exists in the corpus to weigh against them — and a reversible
#   one: add the ranges, mint a ruleset, expect the build-id column to rise.
#
#   #219 is the standing reminder that a corpus only disproves what it
#   contains. If you issue or process cards outside the eight networks named
#   above, measure before you upgrade.
#
#   RULESET 2026.08.4, VALIDATOR `luhn+iin+distinct`. A new name, not a
#   redefinition: rows stamped 2026.08.3 record `luhn+distinct` and still replay
#   under Luhn-plus-not-one-repeated-digit, including its acceptance of the runs
#   this version starts rejecting. `foxy explain` on an old row is unchanged.
#   2026.08.1/.2/.3 keep their digests.
#
#   The phone and digest paths are untouched: phone recall stays 168/168, and
#   SHA-256 digests and random UUIDs stay at 0.000% on the phone detector.
#
# 1.10.0 — S9. explain() verifies the ruleset it replays, instead of trusting
# its own registry.
#
# NO WIRE CHANGE, no detector change, no change to what the guard blocks. MINOR
# rather than PATCH because `explain()` gains an outcome and `ExplainResult`
# gains a field — and because 1.9.0 is ALREADY PUBLISHED from a commit that does
# not contain this fix. PyPI refuses a re-upload of a released version, so a
# correction to a shipped release needs a number of its own. See pyproject.toml's
# note on the same trap costing 1.8.0 its testbed.
#
#   #220 — explain() now VERIFIES the ruleset rather than only naming it.
#     A guarded row records ruleset_version AND ruleset_hash, written together
#     so the second can check the first. explain() loaded the definition by
#     version NAME ALONE and never compared the digest, so `ruleset.load()`
#     returned whatever the local module happened to contain — a hand-edit, a
#     partial upgrade, a backported patch — and the replay described rules that
#     never ran while presenting itself as authoritative.
#
#     It now re-hashes the loaded definition and REFUSES on a disagreement, with
#     a new status `ruleset_mismatch`: same version name, different rules.
#     Distinct from `unknown_ruleset` (this build does not carry the version)
#     and from `hash_mismatch` (which is about the PROMPT).
#
#     ExplainResult gains `ruleset_verified`, which is THREE-STATE and not a
#     bool: True (checked, agreed), False (checked, DISAGREED), None (the check
#     did not run — the row records no digest, or explain returned before
#     reaching it). `foxy explain` renders the three distinctly, because "your
#     registry was altered" and "the check never ran" are not the same news.
#
#     ⚠ WHAT IT ASSERTS, EXACTLY: that the frozen DEFINITION — patterns, flags,
#     validator NAMES, policy map, reasons — is the one the row was written
#     against. It does NOT cover the validator IMPLEMENTATIONS those names point
#     at, which are live code in introspect.py and which no row records a digest
#     of. The field's own docstring says so, and the message says "definition",
#     never "ruleset", for that reason.
#
#     A row naming a version but recording NO hash is not refused: the version
#     is known and the commitment matched, so the replay is still the best
#     available answer. No shipped SDK produces that shape — both keys landed
#     together in 1.7.0 and provenance() returns both or neither — which the
#     message says out loud.
#
#     The hash was already emitted, already allowlisted by the backend, already
#     surviving into /v1/logs/export, already parsed into a result field.
#     Reading it was the one step missing.
#
#     ⚠ The registry's "a published ruleset is IMMUTABLE" rule was enforced by a
#     comment until now. 2026.08.3 was regenerated in place three times during
#     1.9.0's review — defensible only while it was unpublished. This is the
#     check that makes the rule observable after the tag.
#
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
#     missed 108 of the 540 obligation shapes — a fifth of them, and 72 more
#     than 1.8.0 missed — including `card-4111111111111111` and
#     `4111-1111-1111-1111-visa`. For a compliance product a missed PAN is
#     worse than a spurious label on an identifier.
#
#     The card candidate DOES chain across a UUID's hyphens (`[ \-]?` is a
#     separator, so `0000-0000-0000-0000` is one 16-digit run) and Luhn accepts
#     `0000000000000000`, so a NIL UUID reported credit_card. Two structural
#     facts fix that, each placed where it belongs:
#       * a card number does not start with 0 (ISO/IEC 7812 assigns MII 0 to
#         ISO/TC 68) — in the PATTERN's leading [1-9], because applied to the
#         assembled digit string it swept a stray preceding zero into the
#         candidate and lost the PAN outright ("ref 0 4111111111111111");
#       * a card number is not one repeated digit, and NEITHER detector accepts
#         an all-zero run — in the validators. NOT "not one repeated digit" for
#         the phone: 888-888-8888 and +7 777 777 7777 are dialable, and a
#         uniform-digit rule refused all 60 shapes built from genuinely
#         dialable repeated-digit numbers.
#     Together they take the zero-heavy identifier class from 2 849 in 10 057
#     to 2, with card and phone detection IDENTICAL to 1.8.0 — the same SETS,
#     asserted as set differences in both directions rather than as counts.
#     (Identical, not complete: 1.8.0 missed 36 of the 540 card shapes and this
#     release misses the same 36. See SDK #219.)
#     ⚠ THE COST: a PHONE glued directly to a hyphen with no separating space
#     ("Tel-4155550134") is no longer detected; a CARD glued to a LETTER
#     ("4111111111111111x") is not either, and 1.8.0 did not detect that one
#     either. 5 random UUIDs in 20 000 still read as credit_card, against
#     33 in 20 000 for 1.8.0 — a residue, not a claim of zero. A card redaction
#     also stops eating the space OR HYPHEN that follows the number.
#
#     ⚠ THIS BOUNDARY LOST REAL DETECTIONS IN THREE CONSECUTIVE REVIEW ROUNDS.
#     The recurrence was the defect, not any single loss: each round assembled
#     its corpus AFTER choosing the rule. sdk/tests/fixtures/identifier_corpora.py
#     is now one checked-in obligation set carrying BOTH directions, and every
#     future change to either detector is measured against it before a rule is
#     chosen. Read that file's header before touching either detector.
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
__version__ = "1.11.0"
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
