"""The engine: one assistant, one ``Turn`` record, three surfaces later.

:class:`Assistant` puts a sector preset behind ``foxy_audit``'s real preflight
guard and returns the same :class:`Turn` for every outcome. The CLI (T1), the
local web page (T2) and the desktop console page (T3) all render that one
record; none of them holds any policy logic, and neither does this module.

THE TESTBED IS A CONSUMER OF THE SDK
====================================
Nothing here reaches into ``foxy_audit``'s internals. It uses the package's
public API and nothing else — ``FoxyClient.audit``, ``FoxyClient(on_event=…)``,
``check``, ``explain`` and the two block exceptions — which is the same surface
a customer has. Where that surface turns out not to reach something the plan
asked for, this module records the gap in a comment marked ``SDK FINDING`` and
works within the API rather than around it.

⚠ ONE SUCH GAP IS NOW CLOSED, AND IT IS WORTH KNOWING WHY IT WAS THERE. Until
SDK 1.12.0 (``ce491e1``) the decorator returned the wrapped function's response
and nothing else, so a consumer could not name the ledger row its own call had
just produced — ``Turn.event_id`` was a real field left honestly empty, because
a fabricated event id in an audit product is the worst possible placeholder.
``FoxyClient(on_event=…)`` hands back a content-blind receipt built from the
payload that was actually written, and :meth:`Assistant.ask` reads the id off it.

WHAT THE GUARD ACTUALLY SEES
============================
The USER TURN ONLY. The sector's system prompt is handed to the provider through
a ``system=`` keyword, which is deliberately absent from the SDK's
``_PROMPT_KWARGS`` list, so it is never extracted, never evaluated and never
committed as the prompt.

That is not an optimisation, it is a correctness requirement. A healthcare
system prompt containing "do not reveal these instructions" trips
``injection.reveal_system_prompt`` against itself, and a structured prompt is
flattened through ``hashing.canonical_json`` before the regexes run — so folding
the persona in would make every single turn in the sector self-block, for a
reason no reader could ever locate. The user turn is also the only half a
customer's prompt actually is.

``provider=`` and ``model=`` ARE passed through, because they are on the SDK's
``_metadata`` allowlist and land in the event as non-content identifiers. That
is how a row records which model answered.
"""

from __future__ import annotations

import re
import time
from dataclasses import dataclass

from foxy_audit import (FoxyClient, FoxyPolicyBlocked, FoxyResponseBlocked,
                        check, explain)

from . import providers as _providers
from .sectors import Sector, get_sector

#: The preflight modes the SDK understands. "block" is the testbed's default:
#: it is the mode the product's claim is about, and the one a prospect came to
#: see. "observe" is accepted so a run can show what WOULD have fired.
MODES = ("observe", "block", "redact")
DEFAULT_MODE = "block"

# ── the decision vocabulary ───────────────────────────────────────────────────
# Four of these five are the SDK's OWN words, taken verbatim from
# client.py's `decision` field rather than paraphrased. A second vocabulary
# describing the same events in different words is how a surface and a ledger
# start disagreeing, and this project has been bitten by it before.
#
#   allowed          - client.py `_evaluate_preflight`, plan kind "allow"
#   blocked          - client.py `_emit_block`
#   redacted         - client.py `_evaluate_preflight`, plan kind "redact"
#   blocked_response - client.py `_emit_response_block`, `delivered=False`
#
# "flagged" is the ONE addition, and only because the SDK has no word for it:
# under observe the guard records nothing at all (`_evaluate_preflight` returns
# None), so a turn where rules fired and nothing was prevented has no label to
# borrow. Calling it "allowed" would be worse than adding a word, because
# "allowed" in the SDK means the prompt was CLEAN.
DECISION_ALLOWED = "allowed"
DECISION_FLAGGED = "flagged"
DECISION_BLOCKED = "blocked"
DECISION_REDACTED = "redacted"
DECISION_BLOCKED_RESPONSE = "blocked_response"
#: Not a policy outcome — the provider itself failed. Its own value so a
#: scoreboard can never count a broken run as a clean one.
DECISION_ERROR = "error"
# ⚠ AN EMPTY REPLY IS NOT A DECISION, AND MAKING IT ONE WAS A REGRESSION.
# It was briefly ``DECISION_EMPTY_REPLY``, which meant it OVERWROTE whatever the
# guard had done. Measured: under redact, a provider returning "" turned
# `caught 5 / gaps_open 2` into `caught 0 / errors 11 / gaps_open 0` — including
# known-gap probes becoming errors, which contradicts this package's own rule
# that a gap never fails a run.
#
# The reason it is wrong is that the two facts are independent. What the guard
# did to the PROMPT is fully observable from the delivered text (`rules_delivered`)
# no matter what came back, so an empty reply says nothing about enforcement. It
# is an ASSISTANCE fact and lives in that column alone — see `Turn.empty_reply`.

#: The outcomes that are about the PROVIDER rather than the policy.
PROVIDER_FAULTS = (DECISION_ERROR,)

DECISIONS = (DECISION_ALLOWED, DECISION_FLAGGED, DECISION_BLOCKED,
             DECISION_REDACTED, DECISION_BLOCKED_RESPONSE, DECISION_ERROR)

# ── re-checking the delivered text ────────────────────────────────────────────
#: The markers the SDK substitutes for redacted spans — ``pii.redact`` writes
#: ``[REDACTED:ssn]`` and friends, ``policy.redact`` writes
#: ``[REDACTED:<rule-id suffix>]``.
_REDACTION_MARKER_RE = re.compile(r"\[REDACTED:[^\]\n]*\]")

#: What a marker is replaced with before the delivered text is re-checked.
#: A BARE SPACE WOULD NOT DO: deleting a marker can splice its neighbours into a
#: match that was never in the text (``555[REDACTED:x]1234567`` -> a phone
#: number), which would report a surviving finding that does not exist. A tilde
#: appears in no rule pattern and in no separator class, so it cannot join two
#: spans and cannot match on its own.
_MARKER_STANDIN = " ~ "


def _content_of(delivered) -> str:
    """The delivered text with the SDK's own redaction markers removed.

    ⚠ WHY THIS IS NOT CHEATING, AND IS IN FACT THE ONLY CORRECT MEASUREMENT.
    The question a re-check asks is "did the offending CONTENT reach the model",
    and a ``[REDACTED:...]`` marker is the evidence that it did not.

    Leaving the markers in USED TO make one rule report itself as surviving its
    own redaction: ``policy.redact`` built the marker from the rule id's suffix,
    so ``injection.jailbreak`` became ``[REDACTED:jailbreak]`` — and that pattern
    matches the literal word ``jailbreak``. Measured across every rule the probe
    corpus exercises, it was the ONLY one that did it, which is exactly why a
    single-rule fixture would have missed it.

    ⚠ SDK #217 FIXED THAT IN 1.9.0. The marker is now
    ``[REDACTED:prompt_injection]`` and every marker the SDK emits is inert, so
    the collision this paragraph describes no longer happens. The stand-in STAYS
    anyway, for two reasons that outlive the one rule: the testbed must not
    depend on every FUTURE marker also being inert, and the SDK's own re-check
    (``policy.surviving_rules``, #216) neutralises markers for exactly the same
    reason. Two independent defences, deliberately.

    So the marker is stripped and nothing else is. If the SDK ever changes the
    marker format this stops matching, every redacted probe re-flags, and the
    scoreboard goes loudly red rather than quietly wrong — the safe direction.
    """
    return _REDACTION_MARKER_RE.sub(_MARKER_STANDIN, str(delivered))


@dataclass(frozen=True)
class Turn:
    """One interaction, whatever happened to it. The record all three surfaces render."""

    sector: str
    policy_tag: str
    mode: str
    #: The provider's NAME. An identifier, and NOT a claim about what answered:
    #: whether a reply came from a model is :attr:`provider_is_live`, which sits
    #: at the end of this list only because a defaulted field cannot precede an
    #: undefaulted one. Do not re-derive live-ness from this string.
    provider: str
    model: str

    #: What the SDK stamped. A LABEL, and treated as one: nothing in the
    #: scoreboard concludes anything about behaviour from it. See the class
    #: note below.
    decision: str
    #: Did a non-empty reply actually reach the caller? MEASURED from the
    #: returned value, not from the absence of an exception -- a provider that
    #: returns "" delivered nothing, whatever the decision says.
    answered: bool
    #: Did the wrapped function actually run? The wrapped callable sets it, so
    #: a block that failed to prevent the call could not report True.
    reached_provider: bool
    #: Did the text the provider received DIFFER from the text submitted?
    #:
    #: ⚠ TRUE, AND NOT AN ENFORCEMENT TEST. "Something changed" is not "the
    #: finding was removed": a prompt carrying a redactable SSN beside a
    #: presidio-only date of birth is delivered as
    #: ``Member SSN [REDACTED:ssn], DOB 03/14/1982`` — changed, and still
    #: carrying the DOB. Reading this as enforcement is the defect T0d fixed;
    #: read :attr:`rules_removed` / :attr:`rules_surviving` instead. Kept
    #: because it distinguishes "nothing was rewritten at all" from "rewritten,
    #: and a finding survived anyway", which are different sentences to a reader.
    prompt_changed: bool = False
    #: The call returned normally and what came back was empty.
    #:
    #: AN ASSISTANCE FACT, and only that. Set where it is observed — in the
    #: branch of ``ask`` where the wrapped call actually returned — rather than
    #: derived from ``reached_provider and not answered``, which is also true of
    #: a response WITHHELD by the response scan and would have mislabelled that
    #: as a provider fault. It is not a ``decision`` value either: letting it
    #: overwrite the decision erased five correct enforcement verdicts and
    #: turned two known gaps into errors. ``_openai_text`` returns "" for a
    #: payload with no text, so this is a live path.
    empty_reply: bool = False
    #: The rules that still fire against the text the provider ACTUALLY got —
    #: ``check()`` re-run on the delivered prompt under the same policy tag.
    #: Empty when nothing was delivered. This is the per-finding measurement
    #: that :attr:`rules_removed` and :attr:`rules_surviving` are computed from.
    rules_delivered: tuple = ()

    reply: str = ""
    #: The rules that fired against the text as SUBMITTED.
    rules: tuple = ()
    signals: tuple = ()
    #: The SDK's dominant reason label, or "none". From ``check``, which shares
    #: ``PolicyDecision.reason`` with the guard, so the two cannot disagree.
    blocked_reason: str = "none"

    ruleset_version: str = ""
    ruleset_hash: str = ""

    #: The id of the ledger row this turn produced, off the SDK's own receipt.
    #:
    #: ⚠ THIS FIELD WAS EMPTY BY NECESSITY UNTIL SDK 1.12.0. Where these lines
    #: stand there was an ``SDK FINDING`` comment recording that
    #: ``log_interaction`` minted an event id and returned it to nobody, so a
    #: consumer of the SDK — which is exactly what this package is — could not
    #: name the row its own call had just written. ``ce491e1`` closed it with
    #: ``FoxyClient(on_event=…)``; see :meth:`Assistant._receipt`.
    #:
    #: STILL EMPTY IN ONE HONEST CASE, and it is not the same as ``submitted``
    #: being False: no receipt arrived at all. The SDK documents one class of
    #: event with no receipt (``audit_required=True`` and the server receipt
    #: missed its deadline — the row IS durable and will be delivered later).
    #: An empty id therefore means "this turn cannot be traced from here", which
    #: is a different sentence from "there is no row", and the surfaces say so.
    event_id: str = ""
    #: Was the event durably enqueued and handed to the dispatcher?
    #:
    #: ⚠ ``submitted``, NOT ``delivered``, AND THE SDK CHOSE THAT WORD ON
    #: PURPOSE. Under the default ``audit_required=False`` the dispatcher writes
    #: the local spool and returns, saying nothing about the backend — with a
    #: revoked key every POST 401s and retries while the event sits in the
    #: spool, and a field called ``delivered`` would have read True throughout.
    #: Carried here under the SDK's own name rather than renamed, because a
    #: surface that calls it "delivered" re-introduces the claim the SDK
    #: deliberately refused to make.
    #:
    #: False is the DEFAULT CONFIGURATION, not a failure: the testbed builds a
    #: keyless client, so nothing is submitted and there is no row to verify.
    #: That is honest state 1, and it is readable straight off this field.
    submitted: bool = False

    latency_ms: float = 0.0
    #: The exception type and its message from a provider that RAISED, never a
    #: response body — ``providers.ProviderError`` carries a status code and an
    #: exception type by construction, so nothing the user typed can ride out
    #: through here. Empty unless ``decision`` is "error"; an empty REPLY is not
    #: a failure and leaves this empty (see :attr:`empty_reply`).
    error: str = ""

    #: Did this reply come from a real model, or is it a written fixture?
    #:
    #: ⚠ CARRIED, NEVER RE-DERIVED -- which is the whole reason it exists. The
    #: record did not hold it until now, so a surface serialising
    #: :meth:`as_dict` had exactly two options, and both are defects. Matching
    #: ``provider`` against the string "mock" is the re-derivation
    #: ``Scoreboard.provider_is_live`` was added to stop -- that field went in
    #: after a hardcoded "the replies are fixtures" printed underneath a LIVE run
    #: -- and it could not work regardless, because ``Assistant`` accepts any
    #: ``Provider`` subclass and a custom one answers to neither name. Taking it
    #: as a second argument is what ``cli.turn_lines`` does, and a JSON payload
    #: has nobody to pass it.
    #:
    #: THE DEFAULT IS False, THE UNDERSTATING DIRECTION. Only a hand-built Turn
    #: can reach it -- ``Assistant.ask`` always sets it from the provider it
    #: actually called -- and of the two ways to be wrong, printing "mock
    #: fixture" over a real answer loses a provenance claim, while printing "live
    #: model output" over a written fixture puts words in a model's mouth. In an
    #: audit product only one of those is survivable, for the same reason
    #: :attr:`prompt_enforced` takes the strict reading of a redaction.
    provider_is_live: bool = False

    # ── what the guard did, in four words that cannot be confused ─────────────
    # There was a single `blocked` property here and it covered both
    # DECISION_BLOCKED and DECISION_BLOCKED_RESPONSE. That one word spanning
    # both is precisely the prevention-vs-evidence conflation this product
    # cannot afford: a withheld RESPONSE means the prompt already reached the
    # provider and tokens were already spent, so scoring it in the same column
    # as a prompt that never left printed "[caught] ... reached the model: yes"
    # on adjacent lines. Each property below states its own scope, and the
    # ambiguous word is gone rather than redefined.

    # EVERY PROPERTY BELOW PAIRS THE LABEL WITH THE OBSERVATION THAT WOULD
    # CONTRADICT IT. The label alone says what the policy evaluation concluded;
    # the observation says what happened. Where they can disagree, the
    # observation decides — which is the rule three review rounds arrived at the
    # hard way, once per label.

    @property
    def prevented(self) -> bool:
        """Nothing left this machine.

        ``reached_provider`` is the load-bearing half: a block that somehow
        failed to stop the call cannot report prevention, whatever it was
        stamped. Both halves are needed — a provider that raised before
        returning also leaves ``reached_provider`` True, and an internal fault
        before the call leaves it False without anything having been prevented.
        """
        return self.decision == DECISION_BLOCKED and not self.reached_provider

    @property
    def response_withheld(self) -> bool:
        """The prompt DID reach the provider; only the reply was withheld.

        Real prevention of EGRESS TO THE CALLER, and the SDK counts it as such
        — but not prevention of the prompt, which is what a prompt-side probe
        asks about. Paired with ``reached_provider`` for the same reason as
        above: this outcome asserts the call happened, so it is checked.
        """
        return self.decision == DECISION_BLOCKED_RESPONSE and self.reached_provider

    @property
    def rules_removed(self) -> tuple:
        """Findings that fired on the submitted text and no longer fire on the
        delivered text. THE ENFORCEMENT, per finding.

        ⚠ EMPTY WHEN NOTHING WAS DELIVERED AND NOTHING WAS PREVENTED, which is
        the same pairing the other claims carry. Without it, a turn that failed
        before the provider was called reported every fired rule as removed —
        ``Turn(decision="error", reached_provider=False)`` told a surface an SSN
        had been scrubbed when no text had gone anywhere. A prevented turn DOES
        report them all, and truthfully: nothing reached the model.

        (``rules_surviving`` needs no such pairing: with nothing delivered it is
        already empty, which claims nothing.)
        """
        if not (self.reached_provider or self.prevented):
            return ()
        return tuple(r for r in self.rules if r not in self.rules_delivered)

    @property
    def rules_surviving(self) -> tuple:
        """Findings that fired on the submitted text AND still fire on what the
        provider actually got. THE HOLE, per finding."""
        return tuple(r for r in self.rules if r in self.rules_delivered)

    @property
    def redaction_ineffective(self) -> bool:
        """Stamped ``redacted``, delivered, and a finding survived the trip.

        ⚠ TRIPWIRE. THIS MUST NEVER FIRE AGAINST THE REAL SDK. IF IT DOES,
        SDK #216 HAS REGRESSED — DO NOT DELETE IT.

        Since SDK 1.9.0 the guard re-evaluates the redacted prompt and BLOCKS
        when any rule that fired still matches, so a turn where a finding
        survived is stamped ``blocked`` and never reaches this. That makes the
        property unreachable from a real run and turns it into the cheapest
        possible regression detector for the fix: one sweep of the probe corpus
        in redact mode asserts it stays False everywhere
        (``test_the_SDK_can_no_longer_deliver_a_surviving_finding``).

        A property that is impossible is worth more as an assertion than as a
        deletion — and uncommented dead-looking code is how a detector gets
        tidied away six months from now, which is why this paragraph exists.

        PER-RULE, not per-prompt, and that is the whole history of the defect.
        An earlier version asked "did any byte change?", which a mixed prompt
        answers Yes to while still handing the model the finding nobody could
        rewrite — so the warning this flag exists to raise was suppressed by an
        unrelated redaction succeeding beside it. #216's first spec made the same
        mistake in the SDK; the shipped one is per finding.

        Paired with ``reached_provider`` like every other claim here: a prompt
        that was never delivered cannot have an ineffective redaction, and the
        renderer says "the text delivered to the provider is byte-identical",
        which would be a statement about a delivery that did not happen.
        """
        return (self.decision == DECISION_REDACTED
                and self.reached_provider
                and bool(self.rules_surviving))

    @property
    def prompt_enforced(self) -> bool:
        """The guard acted on the PROMPT: it never left, or it left CHANGED.

        THE ONE AN ``expect_block`` PROBE MEASURES, and the third revision of
        it. The first read ``blocked``, which called every correct redaction a
        miss. The second read ``decision in (blocked, redacted)``, which called
        every INEFFECTIVE redaction a success — because the label is stamped
        from the policy evaluation, before any text is compared.

        So this one reads the label for exactly one thing, prevention, where
        the label is backed by ``reached_provider`` anyway, and MEASURES the
        other: a redaction counts only if the delivered text actually differs
        from the submitted text.
        """
        if self.decision == DECISION_BLOCKED:
            # `prevented`, not True: the block claim carries its own observation.
            return self.prevented
        if self.decision == DECISION_REDACTED:
            # EVERY finding gone, not merely some byte moved. Deliberately the
            # strict direction: a turn that scrubbed the SSN and handed over the
            # DOB is not a clean catch, and for an audit product understating
            # coverage is the safe way to be imprecise. Which rule went and
            # which stayed is not lost — the renderer prints both lists.
            #
            # ⚠ TRIPWIRE, the `rules_surviving` half. AGAINST SDK >= 1.9.0 THIS
            # CAN NO LONGER RETURN FALSE ON A REDACTED TURN: the guard blocks
            # when a finding survives its own redaction (#216), so a turn that
            # reaches here with survivors means that fix regressed. The strict
            # test STAYS — do not simplify it to `bool(self.rules)`. It is what
            # notices, and it is also what keeps this correct for a turn recorded
            # by an SDK older than 1.9.0.
            return bool(self.rules) and not self.rules_surviving
        return False

    @property
    def enforced(self) -> bool:
        """The guard did something at all — prevented, scrubbed, or withheld.

        Composed from the three measured properties rather than re-listing the
        decision constants. A fourth place matching on labels is a fourth place
        to get the family wrong, and this one would have gone stale silently:
        it named ``DECISION_REDACTED`` directly, so it would still have called
        an ineffective redaction enforcement after ``prompt_enforced`` stopped.
        """
        return self.prompt_enforced or self.response_withheld

    def as_dict(self) -> dict:
        """A plain dict for a surface to render or serialise.

        Carries the reply, which is content — the caller's own text, on the
        caller's own machine, exactly like ``introspect.explain``'s spans. It is
        never sent anywhere: the local web server in T2 is the only thing that
        will serialise this, it binds to 127.0.0.1, and Foxy is not on the other
        end of any socket in this package.
        """
        return {"sector": self.sector, "policy_tag": self.policy_tag,
                "mode": self.mode, "provider": self.provider, "model": self.model,
                # PROVENANCE TRAVELS WITH THE REPLY, for the reason spelled out
                # on the field: the alternative is a JSON consumer matching the
                # provider NAME against "mock", which is exactly the
                # re-derivation Scoreboard.provider_is_live exists to prevent.
                "provider_is_live": self.provider_is_live,
                "decision": self.decision, "answered": self.answered,
                "reached_provider": self.reached_provider,
                "prompt_changed": self.prompt_changed,
                # ⚠ TRIPWIRE. Always False against SDK >= 1.9.0 — see the
                # property. Serialised anyway, because a consumer that only ever
                # sees the honest value has no way to notice the day it stops
                # being one.
                "redaction_ineffective": self.redaction_ineffective,
                "empty_reply": self.empty_reply,
                "rules_delivered": list(self.rules_delivered),
                "rules_removed": list(self.rules_removed),
                "rules_surviving": list(self.rules_surviving),
                # Carried rather than left for each surface to re-derive from
                # `decision`. Three front-ends each writing their own version of
                # "was this prevented?" is three chances to rebuild the
                # conflation that produced defect T0b-2.
                "prevented": self.prevented,
                "response_withheld": self.response_withheld,
                "prompt_enforced": self.prompt_enforced,
                "enforced": self.enforced, "reply": self.reply,
                "rules": list(self.rules), "signals": list(self.signals),
                "blocked_reason": self.blocked_reason,
                "ruleset_version": self.ruleset_version,
                "ruleset_hash": self.ruleset_hash, "event_id": self.event_id,
                # Carried so a JSON surface can reach honest state 1 without
                # re-deriving it from the absence of something else.
                "submitted": self.submitted,
                "latency_ms": round(self.latency_ms, 1), "error": self.error}


# ── the evidence states ───────────────────────────────────────────────────────
# Three honest states, and one the plan did not know it needed. Each names a
# DIFFERENT missing thing, and collapsing any two would report the wrong fix.
#: No receipt reached the caller, so there is no id to look up. NOT "no row".
EVIDENCE_NO_RECEIPT = "no_receipt"
#: The default. `submitted=False` — no Foxy key, so nothing was ever shipped.
EVIDENCE_NO_LEDGER = "no_ledger"
#: The row exists; `explain` needs the customer's own export document.
EVIDENCE_NO_EXPORT = "no_export"
#: `explain` ran. `Evidence.status` then carries its verdict VERBATIM.
EVIDENCE_EXPLAINED = "explained"

EVIDENCE_STATES = (EVIDENCE_NO_RECEIPT, EVIDENCE_NO_LEDGER, EVIDENCE_NO_EXPORT,
                   EVIDENCE_EXPLAINED)

# ── which family an explain status belongs to ─────────────────────────────────
# ⚠ THREE FAMILIES FOR EIGHT STATUSES, AND THE SPLIT IS THE SDK'S OWN. Its
# `introspect.STATUSES` docstring says "Four of them are 'I cannot'", and those
# four are exactly the ones below: a tool that cannot answer has not failed the
# row. `salt_unavailable`'s own message spells the rule out — "this is not a
# mismatch and not a pass".
#
# ⚠ THE FAMILY IS A COLOUR, NEVER THE ANSWER. Every surface prints
# `Evidence.status` verbatim beside the mark, because eight outcomes rendered as
# three colours would be exactly the tick-and-cross collapse this phase exists to
# refuse. The family only decides which of the page's four existing status tokens
# the mark wears.
#
# ⚠ AND AN UNKNOWN STATUS FALLS TO "CANNOT", NOT TO "ANSWERED". A future SDK
# adding an outcome this map has never seen must not render green. The default is
# the understating direction, the verbatim word still prints, and
# `test_engine.py` asserts this map covers every entry of `introspect.STATUSES`
# so the day it stops being complete is a red test rather than a quiet miscolour.
FAMILY_ANSWERED = "answered"
FAMILY_CANNOT = "cannot"
FAMILY_DISAGREED = "disagreed"

EXPLAIN_FAMILIES = {
    # the replay ran and produced an answer
    "explained": FAMILY_ANSWERED,
    "no_matches": FAMILY_ANSWERED,
    # the check ran and DISAGREED
    "hash_mismatch": FAMILY_DISAGREED,
    "ruleset_mismatch": FAMILY_DISAGREED,
    # the four the SDK calls "I cannot"
    "row_not_found": FAMILY_CANNOT,
    "salt_unavailable": FAMILY_CANNOT,
    "unknown_ruleset": FAMILY_CANNOT,
    "predates_provenance": FAMILY_CANNOT,
}


def family_of_status(status: str) -> str:
    """Which mark an explain status wears. Unknown → ``cannot``."""
    return EXPLAIN_FAMILIES.get(str(status), FAMILY_CANNOT)


@dataclass(frozen=True)
class Evidence:
    """What tracing one turn to its ledger row found. The record all three
    surfaces render, exactly as :class:`Turn` is for the turn itself.

    ⚠ ``status`` IS THE SDK's WORD AND IS NEVER TRANSLATED. `explain` has eight
    outcomes and four of them mean "I cannot answer"; a surface that mapped them
    onto a tick and a cross would report a salt it could not find in the same
    shape as a commitment that did not match. The mark is a colour; the word is
    the answer.
    """

    state: str
    headline: str
    message: str
    event_id: str = ""
    #: ``ExplainResult.status``, verbatim, and empty in the three states where
    #: ``explain`` was never called.
    status: str = ""
    policy_tag: str = ""
    ruleset_version: str = ""
    commitment_verified: bool = False
    #: ⚠ THREE-STATE, AND ``None`` IS NOT ``False``. True — the digest ran and
    #: agreed. False — it ran and DISAGREED, which the SDK only ever pairs with
    #: `ruleset_mismatch`. None — IT DID NOT RUN. Collapsing the last two tells a
    #: reader their registry may have been tampered with when in fact they simply
    #: supplied the wrong prompt.
    ruleset_verified: bool = None
    #: How many spans the replay matched. ⚠ THE COUNT, NEVER THE SPANS: a span is
    #: the user's own text, and the SDK's rule is that it reaches stdout and
    #: nowhere else. `ExplainResult.as_dict()` defaults to omitting it for the
    #: same reason; `matches` below carries the objects for a stdout renderer and
    #: `as_dict` here drops their text exactly as the SDK's does.
    match_count: int = 0
    matches: tuple = ()

    @property
    def family(self) -> str:
        """Which mark this wears. Only meaningful once `explain` has run."""
        return family_of_status(self.status)

    @classmethod
    def from_explain(cls, result) -> "Evidence":
        """Wrap an :class:`~foxy_audit.ExplainResult`. Carries its own words."""
        return cls(
            state=EVIDENCE_EXPLAINED,
            # THE STATUS IS THE HEADLINE. Upper-cased for the mark and not
            # reworded: `row_not_found` reads as `ROW_NOT_FOUND`, which is the
            # value a reader can grep the SDK for.
            headline=str(result.status).upper(),
            message=result.message,
            event_id=result.event_id,
            status=result.status,
            policy_tag=result.policy_tag,
            ruleset_version=result.ruleset_version,
            commitment_verified=result.commitment_verified,
            ruleset_verified=result.ruleset_verified,
            match_count=len(result.matches),
            matches=tuple(result.matches))

    def as_dict(self) -> dict:
        """A plain dict for a surface to render or serialise.

        ⚠ NO SPAN TEXT, EVER. `matches` is deliberately absent rather than
        included-without-text: the count is what a page can say honestly, the
        offsets say nothing without the text, and the SDK's own
        `ExplainResult.as_dict` is default-safe for exactly this reason. A guard
        feeds a prompt full of PHI through a real verify and asserts no substring
        of it appears anywhere in this dict.
        """
        return {"state": self.state, "headline": self.headline,
                "message": self.message, "event_id": self.event_id,
                "status": self.status, "family": self.family,
                "policy_tag": self.policy_tag,
                "ruleset_version": self.ruleset_version,
                "commitment_verified": self.commitment_verified,
                "ruleset_verified": self.ruleset_verified,
                "match_count": self.match_count}


class Assistant:
    """A sector preset, behind the real guard, in front of a provider.

    Single-threaded by design — one REPL, one page, one console tab. The
    ``_reached`` flag below is per-instance rather than per-call for that reason,
    and a surface that ever wants concurrency should hold one Assistant per
    session rather than sharing this one.
    """

    def __init__(self, sector, mode: str = DEFAULT_MODE, provider="mock",
                 api_key: str = "", model: str = "", client=None,
                 desktop_ping: bool = False, foxy_api_key: str = "") -> None:
        self.sector = sector if isinstance(sector, Sector) else get_sector(sector)

        resolved_mode = str(mode or DEFAULT_MODE).strip().lower()
        if resolved_mode not in MODES:
            # LOUD, unlike the SDK, which logs a warning and falls back to
            # observe. In a library that is right: a typo must not break a
            # customer's production call. Here it is wrong: `--mode blcok`
            # silently demoting a demo of prevention into a demo of nothing is
            # the failure this whole testbed exists to make visible.
            raise ValueError("unknown mode {0!r}; available: {1}".format(
                mode, ", ".join(MODES)))
        self.mode = resolved_mode

        self.provider = (provider if isinstance(provider, _providers.Provider)
                         else _providers.build_provider(provider, self.sector,
                                                        api_key=api_key, model=model))

        # ⚠ api_key="" IS EXPLICIT AND LOAD-BEARING. FoxyConfig.resolve falls
        # back to $FOXY_API_KEY, so a bare FoxyClient() on a developer's machine
        # picks up their real key, registers org policy, and starts writing the
        # shared ~/.foxy-audit spool — which would make an offline probe run
        # depend on whose laptop it is. A caller who genuinely wants a keyed
        # client passes one in as `client`.
        # ⚠ TWO DIFFERENT KEYS, AND CONFLATING THEM WOULD BE THE WORST KIND OF
        # BUG HERE. `api_key` above is the PROVIDER's (OpenAI, Google) and buys
        # model output. `foxy_api_key` is the FOXY key and is the only thing
        # that makes a turn reach a ledger at all. Until T4 only the first
        # existed on any surface, so nothing the testbed ever ran had written a
        # row — which is why "no ledger" is the DEFAULT honest state and not an
        # error. Empty stays empty: `FoxyConfig.resolve` falls back to
        # $FOXY_API_KEY, so a bare FoxyClient() on a developer's machine picks
        # up their real key, registers org policy and starts writing the shared
        # ~/.foxy-audit spool — which would make an offline probe run depend on
        # whose laptop it is.
        self._client = client if client is not None else FoxyClient(
            api_key=foxy_api_key or "", desktop_ping=desktop_ping)

        #: Receipts the SDK emitted during the turn in flight. See `_receipt`.
        #:
        #: ⚠ THE HOOK IS **NOT** BOUND HERE. It is bound in :meth:`ask`, per
        #: call, and that is the fix for a defect this constructor caused. See
        #: the note there before moving it back.
        self._receipts: list = []

        self._reached = False
        self._delivered = None
        self._guarded = self._client.audit(
            policy=self.sector.policy_tag,
            agent=self.provider.model,
            mode=self.mode,
        )(self._invoke)

    def with_mode(self, mode: str) -> "Assistant":
        """This assistant again, under a different preflight ``mode``.

        ⚠ MODE IS FIXED AT CONSTRUCTION -- the guard decorator is built in
        ``__init__`` and cannot be re-decorated -- so "switching" is rebuilding,
        and rebuilding is where session state gets silently dropped. It already
        did: T1's REPL rebuilt from sector/mode/provider alone, so ``/mode`` on a
        KEYED session swapped the caller's ``client`` for a fresh keyless one and
        stopped writing to their ledger, while printing that nothing but the mode
        had changed.

        It lives HERE rather than on the surface because this class is the only
        thing that knows what an Assistant is made of. Three front-ends each
        rebuilding one is three chances to drop a different field.

        EVERYTHING THAT MATTERS IS CARRIED, and that is checkable rather than
        hopeful. Of ``__init__``'s seven parameters, ``api_key`` and ``model``
        feed ``build_provider`` ONLY, and ``desktop_ping`` feeds the
        ``FoxyClient`` constructor ONLY -- so handing over the already-built
        provider and the already-built client makes all three unreachable, by
        construction. If a parameter is ever added, ``test_cli.py`` fails on the
        signature rather than on a symptom six months later.

        ⚠ ``foxy_api_key`` IS THE FOURTH SUCH PARAMETER and needs no line here
        for the same reason: it feeds the ``FoxyClient`` constructor ONLY, and
        the client is handed over already built. What the rebuild DOES have to
        do is re-point the receipt hook at the new instance, and that happens in
        ``__init__`` — see the assignment there for what breaks without it.
        """
        return Assistant(self.sector, mode=mode, provider=self.provider,
                         client=self._client)

    def _receipt(self, receipt: dict) -> None:
        """The SDK handing back the row it just wrote. CONTENT-BLIND.

        ``FoxyClient(on_event=…)``, shipped in 1.12.0 (``ce491e1``) for exactly
        this. The receipt is built from the payload the wire actually carries, so
        every value in it is a commitment or a label and none of it is text.

        APPENDS RATHER THAN ASSIGNS, and :meth:`ask` reads the LAST one. Exactly
        one fires per turn on the path this package uses — the synchronous
        decorator emits one ``log_interaction`` per call on every branch (block,
        response-block, exception, ordinary) — so today "last" and "only" are the
        same receipt. It is written as a list because if that ever stops being
        true the terminal outcome is the one a reader is asking about, and
        silently keeping the FIRST would name a row that was superseded.

        ⚠ ONE CLASS OF EVENT ARRIVES HERE NEVER, and the SDK says so in
        ``_emit_receipt``: under ``audit_required=True`` a server receipt that
        misses its deadline raises ``AuditRequiredError`` while the row is
        already durable in the spool. The turn then carries no ``event_id`` and
        the surfaces report that it cannot be traced from here — which is true,
        and is not the same claim as "there is no row".
        """
        self._receipts.append(dict(receipt or {}))

    def verify(self, turn, prompt, export=None, commitment_key: str = "",
               salt_sidecar_path: str = "") -> "Evidence":
        """Trace one turn to its ledger row. THE VERIFY CALL LIVES HERE.

        Not in ``cli.py`` and not in ``web.py``: both are asserted by their own
        tests to contain no name from ``foxy_audit`` at all, so neither could run
        this even by accident. They render what this returns.

        ⚠ THE PROMPT IS THE ONE THE USER TYPED, not the one the provider
        received. Every branch of ``_evaluate_preflight`` commits
        ``hash_prompt=prompt`` — the ORIGINAL — so a redacted turn's row commits
        the text before redaction, and replaying the delivered text against it
        would report ``hash_mismatch`` on a perfectly intact row.

        ⚠ AND THE TURN DOES NOT CARRY IT, SO THE CALLER PASSES IT BACK IN.
        That is what keeps the prompt travelling in ONE direction: the page
        posts it, the server never sends it back, and no payload this package
        emits can contain text the user typed. Putting it on the record would
        have been simpler and would have put it in every ``as_dict``.

        Defaults are read off the client's own resolved config rather than asked
        for again: the commitment key and the salt sidecar are SDK settings, and
        a surface that prompted for them separately would be a second place for
        them to disagree with the client that wrote the row.
        """
        if not turn.event_id:
            return Evidence(
                state=EVIDENCE_NO_RECEIPT, event_id="",
                headline="NOT TRACEABLE FROM HERE",
                message=(
                    "The SDK emitted no receipt for this turn, so there is no "
                    "event id to look up. That is not the same as there being no "
                    "row: under audit_required the event can be durable in the "
                    "local spool and delivered later while the receipt missed "
                    "its deadline. Reconcile against an export, not against this "
                    "surface."))
        if not turn.submitted:
            return Evidence(
                state=EVIDENCE_NO_LEDGER, event_id=turn.event_id,
                headline="NEVER SHIPPED TO A LEDGER",
                message=(
                    "This turn was decided locally and nothing was sent "
                    "anywhere, so there is no row to verify. The guard is the "
                    "same one a keyed client runs; what is missing is a Foxy "
                    "key, not a check. Start the testbed with --foxy-key "
                    "<your key> (or FOXY_API_KEY) and the turns after it will "
                    "write rows you can trace."))
        if not export:
            return Evidence(
                state=EVIDENCE_NO_EXPORT, event_id=turn.event_id,
                headline="SHIPPED - EXPORT NEEDED TO CHECK IT",
                message=(
                    "Row {0} exists. Verifying it replays the row against the "
                    "ruleset it names, which needs your own export of the "
                    "ledger: download GET /v1/logs/export?format=json and start "
                    "the testbed with --export <that file>. Foxy never had your "
                    "prompt, so the replay happens here, on your machine, "
                    "against text you supply.".format(turn.event_id)))

        # ⚠ THE SAME RESOLUTION ORDER THE SDK COMMITS WITH, INCLUDING THE
        # `api_key` FALLBACK. `log_interaction` writes the commitment with
        # `cfg.commitment_key or cfg.api_key`, and `foxy explain` replays it
        # with `arg or cfg.commitment_key or cfg.api_key`. Stopping one term
        # short here meant replaying with a DIFFERENT key from the one the row
        # was written with.
        #
        # WHAT THAT COSTS IS THE WHOLE PHASE. A key mismatch does not surface
        # as "could not check"; it surfaces as `hash_mismatch`, which is in the
        # DISAGREED family and whose message reads "The row is intact; this is
        # simply not the prompt it covers." A false accusation against an
        # intact row, from the one surface built so that cannot happen.
        #
        # ⚠ THE TRIGGER IS AN EMPTY VALUE, NOT AN ABSENT ONE, which is why a
        # test that sets a real FOXY_COMMITMENT_KEY passes on the broken code.
        # `FoxyConfig.resolve` reads the variable with a "" default, so
        # `FOXY_COMMITMENT_KEY=` (set, empty) resolves `commitment_key` to ""
        # while `api_key` is the real key. Measured: cfg.commitment_key "",
        # committed with "realkey123", verified with "" -> hash_mismatch.
        key = (commitment_key or self._client.cfg.commitment_key
               or self._client.cfg.api_key)
        sidecar = salt_sidecar_path or self._client.cfg.salt_sidecar_path
        try:
            result = explain(prompt, turn.event_id, export, key,
                             salt_sidecar_path=sidecar)
        except Exception as exc:                      # noqa: BLE001
            # ⚠ EVERY EXCEPTION, NOT OSError AND ValueError. A hand-edited or
            # foreign export is arbitrary JSON, and `introspect._row_for`
            # calls `.get` on whatever `logs` turns out to be -- a bare array
            # gives AttributeError, which is neither of those. It escaped
            # `verify`, and `cli._handle_command` catches only
            # KeyboardInterrupt, so it took the whole REPL down with a
            # traceback instead of rendering the state below. A verify control
            # that can kill the session it runs in is worse than one that
            # cannot answer. `BaseException` is deliberately NOT caught:
            # Ctrl-C during a slow read must still abandon the turn.
            #
            # ⚠ THE TYPE ONLY. `explain` opens a path the user named and parses
            # it; a decoder error can carry a fragment of the document, and this
            # message is rendered on a page and printed to a terminal.
            return Evidence(
                state=EVIDENCE_NO_EXPORT, event_id=turn.event_id,
                headline="THE EXPORT COULD NOT BE READ",
                message=(
                    "Row {0} exists, but the export could not be opened or "
                    "parsed ({1}). Point --export at a file downloaded from "
                    "GET /v1/logs/export?format=json.".format(
                        turn.event_id, type(exc).__name__)))
        return Evidence.from_explain(result)

    # THE OBSERVATION POINT. This is the only place in the package that sees
    # what the provider was actually handed, which is why both of the
    # scoreboard's behavioural claims are taken here rather than read off a
    # label afterwards:
    #
    #   reached_provider  - this function ran at all
    #   prompt_changed    - the prompt it ran WITH differs from the one submitted
    #
    # Reached only when the guard let the prompt through, and carrying whatever
    # the guard rewrote it into.
    def _invoke(self, prompt, system=None, provider=None, model=None):
        self._reached = True
        self._delivered = prompt
        return self.provider.complete(system or "", prompt)

    def ask(self, prompt: str) -> Turn:
        """Run one turn and return what happened to it."""
        # `check` runs the same `policy.evaluate` the guard is about to run, so
        # the two cannot disagree about what fired.
        #
        # ⚠ SDK FINDING — THIS IS A SECOND EVALUATION, AND IT IS THE ONLY WAY.
        # The guard's own PolicyDecision is not returned to the caller on any
        # path: on a block it survives only as a reason label interpolated into
        # FoxyPolicyBlocked's message, and on a redact or allow it is not
        # surfaced at all. So a consumer that wants to show WHICH rules fired
        # has to ask the question twice. Cheap (pure regex, no I/O) and exact,
        # but it is duplicated work the SDK could hand back for free.
        pre = check(prompt, self.sector.policy_tag)

        self._reached = False
        self._delivered = None
        # CLEARED PER TURN, not appended to for the life of the session: the
        # id this turn is asking about is the one this turn produced.
        self._receipts = []
        # ⚠ BOUND HERE, PER CALL, AND THE CONSTRUCTOR IS THE WRONG PLACE FOR IT.
        #
        # One client is shared by every Assistant `with_mode` produces, and it
        # holds ONE `on_event`. Binding at construction means the last Assistant
        # built wins — so a surface that CACHES assistants and revisits an
        # earlier one hands turns to an instance whose hook was quietly taken
        # away. Measured against `web.Testbed`, which caches per (sector, mode):
        # block, observe, block, redact, observe produced ids for turns 1, 2 and
        # 4 and NOTHING for 3 and 5. Going back to a mode you already used is
        # the ordinary way a person drives a mode selector, and the page then
        # reported "cannot be traced from here" for a turn that had written a
        # real ledger row — a false negative about evidence, in the phase built
        # to prevent exactly that.
        #
        # PER CALL IS CORRECT BY CONSTRUCTION, and it is not a new assumption:
        # `_reached`, `_delivered` and `_receipts` above are already per-call
        # state on a class whose docstring says single-threaded and whose web
        # surface uses `HTTPServer` rather than `ThreadingHTTPServer` for that
        # very reason. The hook is the fourth member of that set and was the
        # only one left behind in `__init__`.
        #
        # THE TESTBED OWNS THIS HOOK. A caller passing their own client with
        # their own `on_event` has it replaced, not chained: chaining would grow
        # one link per rebuild, each holding a dead Assistant alive.
        self._client.on_event = self._receipt
        started = time.perf_counter()
        reply, error = "", ""
        empty_reply = False
        try:
            reply = self._guarded(
                prompt=prompt,
                system=self.sector.system_prompt,
                provider=self.provider.name,
                model=self.provider.model,
            )
        except FoxyPolicyBlocked:
            decision, answered = DECISION_BLOCKED, False
        except FoxyResponseBlocked:
            # Only reachable when the deployment set response_scan="block".
            # Not the testbed's default, but a caller's environment can turn it
            # on, and an unhandled exception in a REPL is a worse answer than a
            # labelled turn.
            decision, answered = DECISION_BLOCKED_RESPONSE, False
        except Exception as exc:                      # noqa: BLE001
            # The provider failed. Neither enforcement nor assistance happened,
            # so it gets its own decision rather than being folded into either
            # column — a probe that errored proved nothing, and the scoreboard
            # fails the run rather than scoring it.
            decision, answered = DECISION_ERROR, False
            error = "{0}: {1}".format(type(exc).__name__, exc)
        else:
            # MEASURED FROM THE RETURNED VALUE, not from "no exception was
            # raised". A provider that returns "" delivered nothing to the
            # caller, and scoring that as a successful assist would be the same
            # label-over-observation mistake in the other column.
            #
            # It does NOT touch `decision`: what the guard did to the prompt is
            # a separate, still-observable fact. See the note above DECISIONS.
            answered = bool(str(reply or "").strip())
            empty_reply = not answered
            if pre.triggered:
                decision = (DECISION_REDACTED if self.mode == "redact"
                            else DECISION_FLAGGED)
            else:
                decision = DECISION_ALLOWED
        elapsed_ms = (time.perf_counter() - started) * 1000.0

        # Guarded on _reached so a BLOCKED turn -- where nothing was delivered
        # and _delivered is None -- can never read as "the text changed".
        prompt_changed = self._reached and self._delivered != prompt

        # ⚠ THE PER-FINDING MEASUREMENT. `check` is re-run against the text the
        # provider ACTUALLY received, under the same tag, so "was this finding
        # removed?" is answered by asking the rule rather than by noticing that
        # the string is different somewhere. A redaction that scrubs an SSN
        # beside a date of birth nothing can rewrite changes the prompt and
        # removes one finding of two; only this comparison can see that.
        #
        # Skipped entirely when nothing was delivered: no text, no findings, and
        # `rules_removed` correctly becomes everything that fired.
        # The SDK's receipt for this turn. See `_receipt` on why the LAST.
        receipt = self._receipts[-1] if self._receipts else None

        rules_delivered = ()
        if self._reached:
            rules_delivered = tuple(
                check(_content_of(self._delivered), self.sector.policy_tag).rules)

        return Turn(
            sector=self.sector.name,
            policy_tag=self.sector.policy_tag,
            mode=self.mode,
            provider=self.provider.name,
            model=self.provider.model,
            # Read off the provider that was actually called on THIS turn, not
            # off a flag captured when the session started: `with_mode` hands the
            # same provider to a rebuilt Assistant, but a caller who supplies
            # their own `provider=` gets whatever they supplied, and asking the
            # object is the only reading that cannot go stale.
            provider_is_live=self.provider.is_live,
            decision=decision,
            answered=answered,
            reached_provider=self._reached,
            prompt_changed=prompt_changed,
            empty_reply=empty_reply,
            rules_delivered=rules_delivered,
            reply=reply if answered else "",
            rules=tuple(pre.rules),
            signals=tuple(pre.signals),
            blocked_reason=pre.reason,
            ruleset_version=pre.ruleset_version,
            ruleset_hash=pre.ruleset_hash,
            # ⚠ OFF THE RECEIPT THE SDK ACTUALLY EMITTED, never re-derived.
            # `_receipt` records what `log_interaction` wrote; reading it here
            # means the id names the row this turn produced and not a row we
            # believe it produced. Empty when no receipt arrived — see the
            # field, and `_receipt` for the one case where that happens.
            event_id=str(receipt.get("event_id") or "") if receipt else "",
            submitted=bool(receipt.get("submitted")) if receipt else False,
            latency_ms=elapsed_ms,
            error=error,
        )


__all__ = ["Assistant", "DECISIONS", "DECISION_ALLOWED", "DECISION_BLOCKED",
           "DECISION_BLOCKED_RESPONSE", "DECISION_ERROR", "DECISION_FLAGGED",
           "DECISION_REDACTED", "DEFAULT_MODE", "EVIDENCE_EXPLAINED",
           "EVIDENCE_NO_EXPORT", "EVIDENCE_NO_LEDGER", "EVIDENCE_NO_RECEIPT",
           "EVIDENCE_STATES", "EXPLAIN_FAMILIES", "Evidence", "FAMILY_ANSWERED",
           "FAMILY_CANNOT", "FAMILY_DISAGREED", "MODES", "PROVIDER_FAULTS",
           "Turn", "family_of_status"]
