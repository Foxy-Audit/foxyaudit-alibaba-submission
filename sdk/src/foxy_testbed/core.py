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

DECISIONS = (DECISION_ALLOWED, DECISION_FLAGGED, DECISION_BLOCKED,
             DECISION_REDACTED, DECISION_BLOCKED_RESPONSE, DECISION_ERROR)


@dataclass(frozen=True)
class Turn:
    """One interaction, whatever happened to it. The record all three surfaces render."""

    sector: str
    policy_tag: str
    mode: str
    provider: str
    model: str

    decision: str
    #: Did anything reach the caller? False for every block.
    answered: bool
    #: Did the wrapped function actually run? This is the prevention claim, and
    #: it is a measurement rather than an inference: the wrapped callable sets
    #: it, so a block that failed to prevent the call could not report True.
    reached_provider: bool

    reply: str = ""
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
    #: Provider failure detail (type + status), never a response body. Empty
    #: unless ``decision`` is "error".
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

    @property
    def prevented(self) -> bool:
        """Nothing left this machine. ``reached_provider`` is False."""
        return self.decision == DECISION_BLOCKED

    @property
    def response_withheld(self) -> bool:
        """The prompt DID reach the provider; only the reply was withheld.

        Real prevention of EGRESS TO THE CALLER, and the SDK counts it as such
        — but not prevention of the prompt, which is what a prompt-side probe
        asks about.
        """
        return self.decision == DECISION_BLOCKED_RESPONSE

    @property
    def prompt_enforced(self) -> bool:
        """The guard acted on the PROMPT: it never left, or it left scrubbed.

        THE ONE AN ``expect_block`` PROBE MEASURES. A redacted prompt is a
        success, not a miss: the offending span never reached the model, which
        is the whole claim ``mode="redact"`` makes. Scoring redaction as a
        failure had the testbed reporting the SDK's own correct behaviour as
        broken — the worst direction an audit product's demo can be wrong in.
        """
        return self.decision in (DECISION_BLOCKED, DECISION_REDACTED)

    @property
    def enforced(self) -> bool:
        """The guard did something at all — prevented, scrubbed, or withheld."""
        return self.decision in (DECISION_BLOCKED, DECISION_BLOCKED_RESPONSE,
                                 DECISION_REDACTED)

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
        self._guarded = self._client.audit(
            policy=self.sector.policy_tag,
            agent=self.provider.model,
            mode=self.mode,
        )(self._invoke)

    # The wrapped function. Reached ONLY when the guard let the prompt through,
    # which is what makes Turn.reached_provider a measurement.
    def _invoke(self, prompt, system=None, provider=None, model=None):
        self._reached = True
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
        started = time.perf_counter()
        reply, error = "", ""
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
            answered = True
            if pre.triggered:
                decision = (DECISION_REDACTED if self.mode == "redact"
                            else DECISION_FLAGGED)
            else:
                decision = DECISION_ALLOWED
        elapsed_ms = (time.perf_counter() - started) * 1000.0

        return Turn(
            sector=self.sector.name,
            policy_tag=self.sector.policy_tag,
            mode=self.mode,
            provider=self.provider.name,
            model=self.provider.model,
            decision=decision,
            answered=answered,
            reached_provider=self._reached,
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
           "DECISION_REDACTED", "DEFAULT_MODE", "MODES", "Turn"]
