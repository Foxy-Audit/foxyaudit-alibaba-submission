"""The engine: one assistant, one ``Turn`` record, three surfaces later.

:class:`Assistant` puts a sector preset behind ``foxy_audit``'s real preflight
guard and returns the same :class:`Turn` for every outcome. The CLI (T1), the
local web page (T2) and the desktop console page (T3) all render that one
record; none of them holds any policy logic, and neither does this module.

THE TESTBED IS A CONSUMER OF THE SDK
====================================
Nothing here reaches into ``foxy_audit``'s internals. It uses exactly three
pieces of public API — ``FoxyClient.audit``, ``check``, and the two block
exceptions — which is the same surface a customer has. Where that surface turns
out not to reach something the plan asked for, this module records the gap in a
comment marked ``SDK FINDING`` and works within the API rather than around it.

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

from foxy_audit import FoxyClient, FoxyPolicyBlocked, FoxyResponseBlocked, check

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
    and a ``[REDACTED:...]`` marker is the evidence that it did not. Leaving the
    markers in makes one rule report itself as surviving its own redaction:
    ``policy.redact`` builds the marker from the rule id's suffix, so
    ``injection.jailbreak`` becomes ``[REDACTED:jailbreak]`` — and that pattern
    matches the literal word ``jailbreak``. Measured across every rule the probe
    corpus exercises, it is the ONLY one that does this today (the other eight
    all clear), which is exactly why it would have been missed by a
    single-rule fixture.

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

    # ⚠ SDK FINDING — ALWAYS EMPTY TODAY. See the report and the note in
    # `Assistant.ask`. The SDK mints an event_id inside `log_interaction` and
    # returns it to nobody, so a consumer cannot name the ledger row its own
    # call produced. T4's "verify this turn" needs exactly this. Left as a real
    # field, honestly empty, rather than filled with an id we invented: a
    # fabricated event id in an audit product is the worst possible placeholder.
    event_id: str = ""

    latency_ms: float = 0.0
    #: The exception type and its message from a provider that RAISED, never a
    #: response body — ``providers.ProviderError`` carries a status code and an
    #: exception type by construction, so nothing the user typed can ride out
    #: through here. Empty unless ``decision`` is "error"; an empty REPLY is not
    #: a failure and leaves this empty (see :attr:`empty_reply`).
    error: str = ""

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

        PER-RULE, not per-prompt. The first version asked "did any byte
        change?", which a mixed prompt answers Yes to while still handing the
        model the finding nobody could rewrite — so the warning this flag exists
        to raise was suppressed by an unrelated redaction succeeding beside it.

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
                "decision": self.decision, "answered": self.answered,
                "reached_provider": self.reached_provider,
                "prompt_changed": self.prompt_changed,
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
                "latency_ms": round(self.latency_ms, 1), "error": self.error}


class Assistant:
    """A sector preset, behind the real guard, in front of a provider.

    Single-threaded by design — one REPL, one page, one console tab. The
    ``_reached`` flag below is per-instance rather than per-call for that reason,
    and a surface that ever wants concurrency should hold one Assistant per
    session rather than sharing this one.
    """

    def __init__(self, sector, mode: str = DEFAULT_MODE, provider="mock",
                 api_key: str = "", model: str = "", client=None,
                 desktop_ping: bool = False) -> None:
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
        self._client = client if client is not None else FoxyClient(
            api_key="", desktop_ping=desktop_ping)

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
        """
        return Assistant(self.sector, mode=mode, provider=self.provider,
                         client=self._client)

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
            event_id="",          # see the field's comment, and the SDK finding
            latency_ms=elapsed_ms,
            error=error,
        )


__all__ = ["Assistant", "DECISIONS", "DECISION_ALLOWED", "DECISION_BLOCKED",
           "DECISION_BLOCKED_RESPONSE", "DECISION_ERROR", "DECISION_FLAGGED",
           "DECISION_REDACTED", "DEFAULT_MODE", "MODES", "PROVIDER_FAULTS",
           "Turn"]
