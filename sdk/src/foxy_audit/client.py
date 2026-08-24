"""FoxyClient — the developer-facing decorator.

`@client.audit(policy)` wraps any function (sync or async) that calls an LLM.
After the wrapped function returns, the SDK:

  1. Creates customer-keyed HMAC-SHA-256 commitments of the prompt and response
     locally — optionally salted per event, see `sidecar.py` — then discards the
     raw text.
  2. Fires best-effort `evaluating` then `hash_ok` UDP pings to the desktop fox.
     These confirm only local hashing and queueing — not a backend verdict.
  3. Enqueues the metadata for background HTTP delivery to the backend (only
     when an API key is configured).

The wrapped function's own return value is passed through unchanged, and the
SDK's own bookkeeping can never raise into the host application.

PROMPT REDACTION FAILS CLOSED, PER FINDING
------------------------------------------
Under ``mode="redact"``, a row is stamped ``decision="redacted"`` only when the
findings that fired NO LONGER FIRE against the text that would be sent. The
redacted prompt is evaluated a second time (with the ``[REDACTED:…]`` markers
neutralised) and anything still matching means the call is BLOCKED instead, with
a ``blocked`` event_type.

The measurement is per finding, never per byte. "Did the text change?" is
satisfied by a neighbouring redaction that DID work — an SSN scrubbed beside a
Presidio-only date of birth — and the date of birth still reaches the model
under a ``redacted`` label. Findings redaction cannot act on include a Presidio
match with no regex to substitute, a match spanning a structured prompt's JSON
envelope rather than any one string leaf, and a value held in a non-string field.

The customer chose redact because they wanted that content kept away from the
model; recording an enforcement action that did not occur, in a ledger whose
whole claim is that its evidence is honest, is the one thing this must not do.
See ``policy.surviving_rules`` and the ``redact_ineffective`` branch in
:meth:`FoxyClient._evaluate_preflight`.

RESPONSE SCANNING (OWASP LLM05) — WHAT IT PROMISES, AND WHAT IT DOES NOT
-----------------------------------------------------------------------
``response_scan`` ("off" | "observe" | "block", default **observe**) inspects
what the model RETURNED. It is a separate control from ``mode``, which governs
the prompt: see ``config.DEFAULT_RESPONSE_SCAN`` for why.

* **It never rewrites a response.** There is no response-side "redact", under
  any mode, and ``mode="redact"`` scans the response exactly as ``observe``
  does. Prompt redaction changes what the MODEL sees; response redaction would
  change what the CALLER'S OWN CODE receives — their parser, their database,
  their UI — and a customer who upgrades and starts finding ``[REDACTED:ssn]``
  inside JSON they ``json.loads()`` has had their application broken by us. It
  would also be a lie for the common case: a provider response object is not a
  string, and ``policy.redact_value`` returns non-string leaves untouched, so
  "redacted" would silently mean "did nothing".
* **On a NON-streamed response, prevention is real.** The scan runs on the
  complete value before the wrapper returns it, so under
  ``response_scan="block"`` the caller never receives it.
* **On a STREAMED response, prevention is PARTIAL, and that is architectural.**
  A generator hands each chunk to the caller as it arrives; a chunk cannot be
  un-yielded. Under ``response_scan="block"`` each chunk is scanned BEFORE it is
  yielded, with a carry-over window across the boundary
  (``response_policy.StreamScanner``), and the stream is terminated at the first
  flagged chunk — so the rest never arrives, but everything already yielded has
  already been delivered. Two further bounds: a pattern whose halves land more
  than ``CARRY_CHARS`` apart is missed, and the scan adds per-chunk latency.
  Under ``observe`` a stream is scanned once, exactly, after it ends — recording
  without prevention.

  The carry window holds CONTENT, extracted by ``adapters.response_text``, not
  the serialised chunk. Carrying the serialisation put ~30 characters of
  provider envelope between two halves of a split match, and a ``<script>``
  arriving in three OpenAI chunks was delivered in full with no exception.

* **A cut stream is NOT recorded as prevented egress, in any mode.** Chunks that
  were already yielded are in the caller's application; calling that prevention
  would make the Compliance Passport attest something that did not happen. Only
  a block where NOTHING reached the caller emits
  ``event_type="response_blocked"`` (the terminal type the Passport counts). A
  stream cut after delivery is ``stream`` + ``decision="response_truncated"``
  — including under ``mode="redact"``, where borrowing the plan's ``redacted``
  type would put the row straight back into the prevented tally. The
  consequence is stated in :meth:`_emit_response_block`: such a row is not
  counted in ``redacted_events``, and the redaction stays in the evidence as its
  rule ids.

* **A shape the scanner cannot read is recorded as unread, not as clean.**
  ``response_scan.degraded`` (an envelope was scanned instead of content) and
  ``response_scan.unreadable`` (nothing was reachable) ride in ``policy_rules``
  and NOWHERE else — they never become a ``decision``, never set a
  ``blocked_reason``, and are never tallied as an enforced rule in the Passport.
  Neither ever blocks: coverage we do not have is missing evidence, not a
  finding, and "we could not read this" is not a verdict on the interaction.

* **``audit_required`` does not hide a block.** If the audit event cannot be
  durably delivered, ``FoxyResponseBlocked`` is still what is raised, carrying
  ``audit_delivery_failed=True`` — the security decision outranks the delivery
  guarantee, and a caller who set ``audit_required`` must not receive the
  response because the ledger was unreachable.

Buffering a stream to make blocking total was rejected: it would silently turn a
streaming API into a non-streaming one, which is a behaviour change nobody asked
for. Preflight blocking is a real reduction in risk, not a guarantee, and the
same is true here.
"""

from __future__ import annotations

import asyncio
import functools
import inspect
import logging
import re
import uuid

from . import (dispatch, hashing, org_policy, pii, response_policy, ruleset,
               sidecar, udp)
from . import policy as policy_engine
from .adapters import response_metadata
from .config import FoxyConfig
from .spool import EventSpool

log = logging.getLogger("foxy_audit")

_POLICY_RE = re.compile(r"^[a-z0-9_]{1,32}$")
_MODES = ("observe", "block", "redact")
_PROMPT_KWARGS = ("prompt", "user_prompt", "message", "messages", "contents",
                  "text", "input", "query")
# Prompt-side decisions that describe ENFORCEMENT the guard actually performed.
# "allowed" is deliberately absent: it says the prompt was clean, which is no
# reason to overrule a finding on the response.
_PROMPT_ENFORCED = ("blocked", "blocked_by_org_policy", "redacted")


class AuditRequiredError(RuntimeError):
    """Raised only when audit_required is enabled and durable delivery fails."""


class FoxyPolicyBlocked(RuntimeError):
    """Raised when the preflight guard blocks a prompt BEFORE the wrapped
    function runs (mode="block"). The wrapped LLM call is never made; a
    ``blocked`` audit event is emitted first. Content-blind: the message carries
    only a policy tag and a short reason label, never the offending text."""


class FoxyResponseBlocked(RuntimeError):
    """Raised when the response scan blocks a model response AFTER the wrapped
    function has already run (``response_scan="block"``). The response is never
    returned to the caller; a ``response_blocked`` audit event is emitted first.

    Its ``response_hash`` commits WHAT WAS DELIVERED, which is the honest
    statement of egress rather than of what the model produced. On a
    non-streamed block that is the whole response — a real commitment, unlike a
    prompt block, where nothing was ever produced to commit. On a stream flagged
    at its FIRST chunk it is the commitment of an empty list, because nothing
    reached the caller; on a stream cut later it covers only the chunks that
    did. (An earlier draft of this docstring claimed a real response commitment
    in every case, which the first-chunk stream contradicts.)

    Deliberately NOT a subclass of :class:`FoxyPolicyBlocked`. Code that catches
    FoxyPolicyBlocked today is entitled to assume the wrapped function never
    ran; here it did, tokens were spent, and the prompt did reach the provider.
    Silently widening that except-clause would make an upgrade change what a
    handler means. Both are RuntimeError.

    Content-blind: policy tag and a short reason label only.

    ``audit_delivery_failed`` is True when ``audit_required=True`` and the audit
    event could not be durably delivered. The block still wins and this is still
    what is raised — the security decision outranks the delivery guarantee, and
    a caller who set audit_required must not receive the response because the
    ledger was unreachable. Without this, ``AuditRequiredError`` escaped from
    inside the emit and ``except FoxyResponseBlocked`` never fired."""

    def __init__(self, message: str, audit_delivery_failed: bool = False) -> None:
        super().__init__(message)
        self.audit_delivery_failed = audit_delivery_failed


def _extract_prompt(args: tuple, kwargs: dict):
    """Best-effort extraction that preserves structured provider messages locally."""
    for key in _PROMPT_KWARGS:
        val = kwargs.get(key)
        if val is not None:
            return val
    for arg in args:
        if isinstance(arg, str):
            return arg
    return ""


def _replace_prompt(args: tuple, kwargs: dict, new_prompt):
    """Return (args, kwargs) with the prompt slot swapped for ``new_prompt``.

    Mirrors :func:`_extract_prompt`'s search order EXACTLY so redaction lands in
    the same slot it read from: the first present prompt kwarg (any type — a
    redacted structured prompt keeps its shape), else the first positional string.
    ``new_prompt`` is produced by :func:`policy.redact_value`, so it has the same
    shape as the original and never clobbers a structured provider message."""
    for key in _PROMPT_KWARGS:
        if kwargs.get(key) is not None:
            new_kwargs = dict(kwargs)
            new_kwargs[key] = new_prompt
            return args, new_kwargs
    new_args = list(args)
    for i, arg in enumerate(new_args):
        if isinstance(arg, str):
            new_args[i] = new_prompt
            return tuple(new_args), kwargs
    return args, kwargs


class FoxyClient:
    def __init__(
        self,
        api_key: str | None = None,
        endpoint: str | None = None,
        udp_host: str | None = None,
        udp_port: int | None = None,
        desktop_ping: bool = True,
        timeout: float = 5.0,
        commitment_key: str | None = None,
        salt_sidecar_path: str | None = None,
        spool_path: str | None = None,
        client_id: str | None = None,
        audit_required: bool | None = None,
        mode: str | None = None,
        response_scan: str | None = None,
        on_event=None,
    ) -> None:
        # A CONSTRUCTOR ARGUMENT, not a config field. `FoxyConfig.resolve` reads
        # the environment, and a callable cannot come from an env var — putting
        # it on the frozen config dataclass would invent a setting nobody can
        # set. See `_emit_receipt` for the contract.
        #
        # Assigned through the PROPERTY below, so construction and a later
        # `foxy.on_event = ...` are validated by the same function. As a plain
        # attribute this line was the only guarded door in a room with two.
        self.on_event = on_event
        self.cfg = FoxyConfig.resolve(
            api_key=api_key,
            endpoint=endpoint,
            udp_host=udp_host,
            udp_port=udp_port,
            desktop_ping=desktop_ping,
            timeout=timeout,
            commitment_key=commitment_key,
            salt_sidecar_path=salt_sidecar_path,
            spool_path=spool_path,
            client_id=client_id,
            audit_required=audit_required,
            mode=mode,
            response_scan=response_scan,
        )
        if self.cfg.enabled and not self.cfg.client_id:
            spool = EventSpool(self.cfg.spool_path or None)
            self.cfg = self.cfg.__class__(
                **{**self.cfg.__dict__,
                   "client_id": spool.get_or_create_client_id(
                       self.cfg.endpoint, self.cfg.api_key)}
            )
        if self.cfg.enabled:
            # Resume any events left in the local spool after a prior process exit.
            dispatch.resume(self.cfg)
            # Seed the org policy from the on-disk cache and make it eligible for
            # background refresh. Reads a small JSON file; performs no network I/O
            # and cannot fail into the caller (P4 §B2/§B3).
            org_policy.register(self.cfg)

    @property
    def on_event(self):
        """The receipt callback. See :meth:`_emit_receipt` for what it is handed."""
        return self._on_event

    @on_event.setter
    def on_event(self, value) -> None:
        """⚠ A PROPERTY BECAUSE A PLAIN ATTRIBUTE HAD ONLY ONE GUARDED DOOR.

        The constructor rejected an ``async def`` callback; ``foxy.on_event = fn``
        afterwards did not, and walked straight back into the silent
        coroutine-never-awaited failure the constructor check exists to prevent.
        Both paths now route through the same validator."""
        self._on_event = _validate_on_event(value)

    def check(self, prompt, policy: str = "default"):
        """Would this prompt trip anything, under ``policy``? LABELS ONLY.

        A thin delegation to :func:`introspect.check` so the question can be
        asked from a client you already have. It uses no client state at all —
        no key, no network, no spool — which is why the module-level
        ``foxy_audit.check`` exists too and is the one to reach for when you have
        no client. CONTENT-BLIND: never returns, logs or raises the text.
        """
        from .introspect import check as _check
        return _check(prompt, policy)

    @property
    def enabled(self) -> bool:
        return self.cfg.enabled

    def _record_host_exception(self, prompt, exc, policy, agent, metadata=None):
        """Telemetry failure must never replace the application's exception."""
        try:
            self.log_interaction(prompt, exc, policy, agent,
                                 event_type="exception", metadata=metadata)
        except AuditRequiredError:
            log.debug("foxy-audit could not capture host exception", exc_info=True)

    async def _record_async(self, *args, **kwargs):
        """Keep synchronous hashing and delivery waits off the event loop."""
        return await asyncio.to_thread(self.log_interaction, *args, **kwargs)

    # ── preflight guard ───────────────────────────────────────────────────────
    def _resolve_mode(self, decorator_mode: str | None) -> tuple[str, bool]:
        """The effective mode for THIS call, plus whether the org tightened it.

        Called once per invocation rather than captured at decoration time, so a
        workspace tightening reaches a long-running process without a restart
        (P4 §B1). Cost is a dict read; org_policy never performs I/O here."""
        return org_policy.resolve(self.cfg, decorator_mode)

    def _evaluate_preflight(self, args, kwargs, policy: str, effective_mode: str,
                            org_tightened: bool = False):
        """Run policy BEFORE the wrapped fn. Pure (no side effects): returns a
        plan dict the wrappers act on, or ``None`` for the observe path.

        plan["kind"] is one of:
          "block"  — raise after emitting a blocked event (fn must not run)
          "redact" — call fn with plan["args"]/["kwargs"] (redacted prompt)
          "allow"  — clean prompt seen under block/redact mode; record decision

        ``org_tightened`` rides along so the block message and the emitted event
        can say WHY a service whose code reads `observe` refused a prompt (§B6).
        """
        if effective_mode == "observe":
            return None
        prompt = _extract_prompt(args, kwargs)
        decision = policy_engine.evaluate(prompt, policy)
        if not decision.triggered:
            return {"kind": "allow", "hash_prompt": prompt, "args": args, "kwargs": kwargs,
                    "decision": "allowed", "rules": list(decision.rules),
                    "signals": None, "reason": None, "event_type": None,
                    "org_tightened": org_tightened}
        if effective_mode == "block":
            return {"kind": "block", "hash_prompt": prompt,
                    "rules": list(decision.rules), "signals": list(decision.signals),
                    "reason": decision.reason, "org_tightened": org_tightened,
                    # Carried so _block_message can name the value the workspace
                    # ACTUALLY set. When org_tightened is True this IS the org's
                    # sdk_enforcement — see org_policy.resolve's two tightening
                    # branches, which both return the org's own mode.
                    "effective_mode": effective_mode}
        # redact_value scrubs string leaves in a prompt of ANY shape (str or a
        # structured messages= list/dict), so the wrapped fn receives a redacted
        # prompt of the same shape — never the raw original.
        redacted = policy_engine.redact_value(prompt, policy)
        surviving = policy_engine.surviving_rules(decision, redacted, policy)
        if surviving:
            # FAIL CLOSED. A rule that fired on the prompt STILL fires against
            # the text that would be sent, so the finding the guard objected to
            # would reach the model while the row said "redacted". This module's
            # own docstring names the hazard, on the response side: "'redacted'
            # would silently mean 'did nothing'". It was live on the PROMPT side.
            #
            # PER FINDING, never per byte. "Did the text change?" is satisfied by
            # a neighbouring redaction that worked — an SSN scrubbed beside a
            # Presidio-only date of birth — and the date of birth still goes.
            # See policy.surviving_rules.
            #
            # Blocking, not allowing-and-relabelling: the customer chose redact
            # BECAUSE they wanted that content kept away from the model.
            #
            # kind="block", so the emitted row is a block ROW: a "blocked"
            # event_type from _emit_block, not this mode's "redacted" one
            # carrying a blocked decision. The event_type differs per mode, and
            # it is the TYPE — not the decision — that the Compliance Passport,
            # /v1/stats and the judge routing read.
            #
            # policy_rules stays the FULL set that fired. Nothing was delivered,
            # so every finding is honest evidence for this row; recording only
            # the survivors would understate what the guard saw. Which ones
            # survived is named in the exception, not on the wire — a new
            # event_metadata key is validated per request and would 422 the whole
            # batch against a backend that does not know it yet.
            return {"kind": "block", "hash_prompt": prompt,
                    "rules": list(decision.rules), "signals": list(decision.signals),
                    "reason": decision.reason, "org_tightened": org_tightened,
                    "effective_mode": effective_mode,
                    "redact_ineffective": surviving}
        new_args, new_kwargs = _replace_prompt(args, kwargs, redacted)
        return {"kind": "redact", "hash_prompt": prompt, "args": new_args, "kwargs": new_kwargs,
                "decision": "redacted", "rules": list(decision.rules),
                "signals": list(decision.signals), "reason": decision.reason,
                "event_type": "redacted", "org_tightened": org_tightened}

    def _emit_block(self, plan: dict, policy: str, agent: str | None) -> None:
        """Emit the blocked audit event and fire the desktop policy_breach ping.

        prompt_hash = commitment of the ORIGINAL prompt; response_hash =
        commitment of "" (the fn never ran, so there is no response)."""
        # "blocked_by_org_policy" when the workspace tightened the mode, so the
        # ledger records WHERE the decision came from and an auditor reading the
        # event later does not have to guess (§B6).
        self.log_interaction(plan["hash_prompt"], "", policy, agent,
                             event_type="blocked",
                             decision=("blocked_by_org_policy"
                                       if plan.get("org_tightened") else "blocked"),
                             policy_rules=plan["rules"], signals=plan["signals"],
                             blocked_reason=plan["reason"])
        if self.cfg.desktop_ping:
            udp.send_ping(
                {"event": "policy_breach", "policy": policy,
                 "reason": plan["reason"], "rules": plan["rules"][:8],
                 "decision": "blocked"},
                self.cfg.udp_host, self.cfg.udp_port,
            )

    # ── response scan (OWASP LLM05) ───────────────────────────────────────────
    def _scan_response(self, value, policy: str):
        """Scan a COMPLETE response; return a decision worth recording, else None.

        "Worth recording" is ANY rule id, not only a triggered one: a decision
        may carry ``response_scan.degraded`` / ``.unreadable`` with
        ``action="allow"``, and dropping those would put the silence back that
        this phase was sent back for. ``triggered`` still gates blocking.

        Never raises. A scanner fault must not take the caller's response with
        it — the whole point of the SDK is that its bookkeeping is invisible to
        the host application, and a regex that blew up on some exotic response
        shape swallowing that response would be the worst failure this file
        could have."""
        if self.cfg.response_scan == "off":
            return None
        try:
            decision = response_policy.evaluate_response(value, policy)
        except Exception as exc:                 # noqa: BLE001 — see docstring
            log.debug("foxy-audit: response scan failed (%s)", type(exc).__name__)
            return None
        return decision if decision.rules else None

    def _stream_scanner(self, policy: str):
        """A per-chunk scanner, or ``None`` when nothing would act on it.

        Only ``block`` scans per chunk. Under ``observe`` the accumulated stream
        is scanned once after it ends, which is exact — there is no boundary
        window to miss anything — and there is nothing to prevent anyway."""
        if self.cfg.response_scan != "block":
            return None
        return response_policy.StreamScanner(policy)

    def _feed_scanner(self, scanner, chunk):
        """One chunk through the scanner. Never raises, for the same reason
        :meth:`_scan_response` never raises: the caller's stream must not die of
        a fault in our bookkeeping. A scanner that fails degrades this call to
        no prevention, which is exactly what ``response_scan="off"`` already is."""
        try:
            return scanner.feed(chunk)
        except Exception as exc:                 # noqa: BLE001 — see docstring
            log.debug("foxy-audit: response chunk scan failed (%s)", type(exc).__name__)
            return None

    def _labels(self, plan: dict | None, rdec=None, outcome: str | None = None,
                terminal: bool = False) -> dict:
        """The decision/rules/signals/blocked_reason kwargs for log_interaction.

        An EMPTY dict when neither side flagged, so a clean call under observe
        emits the byte-for-byte identical payload it emitted before response
        scanning existed. That property is what makes "observe" a safe default.

        When both sides flagged, the rule ids MERGE — they are namespaced
        (``response_*``), so an auditor can see which side each came from. The
        ``decision`` label follows a precedence that used to be wrong:

        * a TERMINAL response outcome (a block) always wins. It is what actually
          happened to the caller, and nothing the prompt recorded outranks that.
        * otherwise the prompt keeps its label ONLY if it enforced something.
          ``"allowed"`` is not enforcement — it is a statement about the PROMPT
          — and letting it survive produced rows reading
          ``decision: "allowed", blocked_reason: "unsafe_markup"``, so the
          documented ``response_flagged`` never appeared for anyone using
          ``mode="block"`` or ``"redact"``.

        ``signals`` is passed through untouched and NEVER carries response-scan
        labels. It lands in the wire field ``pii_signals``, which the backend
        treats as a deterministic breach trigger (policy_engine.evaluate:
        ``if pii_signals: policy_breach=True``). Putting an ``unsafe_markup``
        there would turn every markup-emitting response into a graded breach on
        every existing customer's dashboard. The response findings ride in
        ``policy_rules`` instead, which is content-blind, already allowed by the
        ingest validator, and inert unless the event is an enforcement event.
        """
        decision = plan["decision"] if plan else None
        rules = list(plan["rules"]) if plan else []
        signals = plan["signals"] if plan else None
        reason = plan["reason"] if plan else None
        if rdec is not None:
            rules = rules + list(rdec.rules)
            # Coverage ids are RECORDED but carry no meaning beyond themselves.
            # They used to overwrite the prompt's decision and stamp
            # blocked_reason="scan_coverage" — under the DEFAULT observe, on
            # every call whose response is an opaque provider handle. "We could
            # not read this" is not a decision about the interaction and not a
            # reason anything was stopped. See response_policy.coverage_rule.
            #
            # ``outcome`` is therefore only consulted when rdec actually
            # TRIGGERED, which is why the call sites pass the literal label. A
            # helper that computed a different one for the coverage-only case
            # used to live here; it was dead by construction, and a mutation
            # proved it by changing its value with no test noticing.
            if rdec.triggered:
                if reason is None:
                    reason = rdec.reason
                if terminal or decision not in _PROMPT_ENFORCED:
                    decision = outcome
        if decision is None and not rules:
            return {}
        return {"decision": decision, "policy_rules": rules,
                "signals": signals, "blocked_reason": reason}

    def _emit_response_block(self, hash_prompt, response, policy: str,
                             agent: str | None, plan: dict | None, rdec,
                             metadata: dict | None, delivered: bool) -> bool:
        """Record the blocked response and ping the fox. Returns whether durable
        delivery of the audit event failed (``audit_required`` only).

        ``delivered`` decides the event type, and it is the honest half of this
        method. ``response_blocked`` is a terminal, locally-decided type the
        backend grades without a judge and the Compliance Passport counts as
        prevented — so it is used ONLY when nothing reached the caller. A stream
        cut after some chunks were already yielded is not prevention: those
        chunks are in the caller's application. It keeps its ordinary
        ``stream`` type, is graded normally, and is recorded as
        ``response_truncated``. Attesting prevention that did not happen, in the
        document whose whole claim is that its evidence is honest, is the one
        thing this must not do.

        ``response_blocked`` is a NEW event_type — a deliberate wire change,
        with the backend, the Passport, the dashboard and the desktop ledger
        updated to match. Reusing ``blocked`` was wrong for a second reason
        beyond the stream: it asserts the host stopped the prompt before it left,
        and on a response block the prompt DID reach the provider.

        ⚠ WHEN CHUNKS WERE DELIVERED, THE TYPE IS ``stream`` NO MATTER THE MODE.
        The first version of this wrote ``(plan and plan["event_type"]) or
        "stream"``, which under ``mode="redact"`` emitted ``redacted`` — also an
        enforcement type. So the exact bug this method exists to prevent came
        straight back through the other mode: counted as prevented egress in the
        Passport, in /v1/stats and in the enforced-rule tally, terminal so the
        judge never graded a response that HAD reached the caller, and reported
        with a reason describing only the redaction.

        The consequence is stated rather than hidden: a redacted prompt whose
        stream is then cut is NOT counted in ``redacted_events``. One row carries
        one terminal outcome, and this row's is truncation. The redaction stays
        in the evidence — its ``phi.*``/``pii.*`` rule ids are in
        ``policy_rules`` — it simply is not claimed as prevention on a row that
        delivered content."""
        if delivered:
            event_type = "stream"
            outcome = "response_truncated"
        else:
            event_type = "response_blocked"
            outcome = "blocked_response"
        delivery_failed = False
        try:
            self.log_interaction(hash_prompt, response, policy, agent,
                                 metadata=metadata, event_type=event_type,
                                 **self._labels(plan, rdec, outcome=outcome, terminal=True))
        except AuditRequiredError:
            # The security decision outranks the delivery guarantee: the caller
            # must not receive this response either way, so the block is what is
            # raised and the delivery failure rides on it. See
            # FoxyResponseBlocked.audit_delivery_failed.
            delivery_failed = True
        if self.cfg.desktop_ping:
            udp.send_ping(
                {"event": "policy_breach", "policy": policy,
                 "reason": rdec.reason, "rules": list(rdec.rules)[:8],
                 "decision": outcome},
                self.cfg.udp_host, self.cfg.udp_port,
            )
        return delivery_failed

    def _with_coverage(self, decision, coverage: str):
        """Fold a stream scanner's worst coverage into a decision's rule ids.

        A CUT stream never reaches the whole-response rescan that would
        otherwise supply this, so without it a row could say "blocked, markup"
        while staying silent that half the chunks were unreadable."""
        extra = response_policy.coverage_rule(coverage)
        if extra is None or extra in decision.rules:
            return decision
        return policy_engine.PolicyDecision(
            action=decision.action,
            rules=sorted(set(list(decision.rules) + [extra])),
            signals=list(decision.signals))

    def audit(self, policy: str = "default", agent: str | None = None,
              mode: str | None = None):
        """Return a decorator that audits the wrapped LLM-calling function.

        `agent` records which model/agent produced the interaction (e.g.
        "gpt-4o", "claude-3-opus"); the backend folds it into the tamper-evident
        hash chain so it can't be altered after the fact (6B).

        `mode` overrides the client's configured mode for this decorator:
        "observe" (default — unchanged: run the fn, then hash), "block"
        (evaluate the prompt FIRST and raise ``FoxyPolicyBlocked`` without ever
        calling the fn on a violation) or "redact" (scrub the prompt locally,
        then call the fn with the redacted prompt).

        `mode` governs the PROMPT only. What happens to the RESPONSE is the
        client's ``response_scan`` setting, which has no per-decorator override
        on purpose: a response block raises into whatever called the wrapped
        function, so it should be a deployment decision, not something scattered
        across decorators. See this module's docstring for what it promises on a
        streamed call — which is less than it promises on a normal one."""
        if not _POLICY_RE.match(policy):
            log.warning("foxy-audit: invalid policy tag %r; falling back to 'default'", policy)
            policy = "default"
        # The decorator argument is validated ONCE, at import, where a typo should
        # be noisy. The effective mode is NOT resolved here: decorators run at
        # import, so anything captured in this closure is frozen for the life of
        # the process and an org tightening could never reach it. Each wrapper
        # resolves per call instead — a dict read (P4 §B1).
        decorator_mode = mode
        if decorator_mode is not None:
            checked = str(decorator_mode).strip().lower()
            if checked not in _MODES:
                log.warning("foxy-audit: invalid mode %r; falling back to 'observe'", mode)
                checked = "observe"
            decorator_mode = checked

        def decorator(fn):
            if inspect.iscoroutinefunction(fn):
                @functools.wraps(fn)
                async def awrapper(*args, **kwargs):
                    effective_mode, org_tightened = self._resolve_mode(decorator_mode)
                    plan = self._evaluate_preflight(args, kwargs, policy, effective_mode,
                                                    org_tightened)
                    if plan and plan["kind"] == "block":
                        await asyncio.to_thread(self._emit_block, plan, policy, agent)
                        raise FoxyPolicyBlocked(_block_message(policy, plan))
                    call_args = plan["args"] if plan else args
                    call_kwargs = plan["kwargs"] if plan else kwargs
                    try:
                        response = await fn(*call_args, **call_kwargs)
                    except BaseException as exc:
                        try:
                            await self._record_async(_extract_prompt(args, kwargs), exc,
                                                     policy, agent, event_type="exception")
                        except AuditRequiredError:
                            log.debug("foxy-audit could not capture async host exception",
                                      exc_info=True)
                        raise
                    hash_prompt = plan["hash_prompt"] if plan else _extract_prompt(args, kwargs)
                    meta = _metadata(kwargs, response)
                    rdec = await asyncio.to_thread(self._scan_response, response, policy)
                    if (rdec is not None and rdec.triggered
                            and self.cfg.response_scan == "block"):
                        failed = await asyncio.to_thread(
                            self._emit_response_block, hash_prompt, response, policy,
                            agent, plan, rdec, meta, False)
                        raise FoxyResponseBlocked(
                            _response_block_message(policy, rdec, False, failed), failed)
                    await self._record_async(
                        hash_prompt, response, policy, agent, metadata=meta,
                        event_type=(plan and plan["event_type"]) or "interaction",
                        **self._labels(plan, rdec, outcome="response_flagged"))
                    return response
                return awrapper

            if inspect.isasyncgenfunction(fn):
                @functools.wraps(fn)
                async def agen_wrapper(*args, **kwargs):
                    effective_mode, org_tightened = self._resolve_mode(decorator_mode)
                    plan = self._evaluate_preflight(args, kwargs, policy, effective_mode,
                                                    org_tightened)
                    if plan and plan["kind"] == "block":
                        await asyncio.to_thread(self._emit_block, plan, policy, agent)
                        raise FoxyPolicyBlocked(_block_message(policy, plan))
                    call_args = plan["args"] if plan else args
                    call_kwargs = plan["kwargs"] if plan else kwargs
                    hash_prompt = plan["hash_prompt"] if plan else _extract_prompt(args, kwargs)
                    scanner = self._stream_scanner(policy)
                    chunks = []
                    stopped = None
                    try:
                        async for chunk in fn(*call_args, **call_kwargs):
                            if scanner is not None:
                                stopped = self._feed_scanner(scanner, chunk)
                                if stopped is not None:
                                    # Scanned BEFORE the yield, so this chunk and
                                    # every chunk after it never reach the caller.
                                    # Everything already yielded already has.
                                    break
                            chunks.append(chunk)
                            yield chunk
                    except BaseException as exc:
                        try:
                            await self._record_async(_extract_prompt(args, kwargs), exc,
                                                     policy, agent, event_type="exception",
                                                     metadata=_metadata(kwargs))
                        except AuditRequiredError:
                            log.debug("foxy-audit could not capture async stream exception",
                                      exc_info=True)
                        raise
                    if stopped is not None:
                        # ``chunks`` is what was DELIVERED — the flagged chunk is
                        # excluded because it never left the host, so the
                        # commitment states egress honestly. Whether that list is
                        # EMPTY is what decides prevented-vs-truncated.
                        stopped = self._with_coverage(stopped, scanner.coverage)
                        failed = await asyncio.to_thread(
                            self._emit_response_block, hash_prompt, chunks, policy,
                            agent, plan, stopped, _metadata(kwargs), bool(chunks))
                        raise FoxyResponseBlocked(
                            _response_block_message(policy, stopped, bool(chunks), failed),
                            failed)
                    # A completed stream is re-scanned WHOLE, in both modes. The
                    # per-chunk pass exists to prevent; this one exists to record,
                    # and it is exact — it has no carry window to miss across.
                    rdec = await asyncio.to_thread(self._scan_response, chunks, policy)
                    await self._record_async(
                        hash_prompt, chunks, policy, agent, metadata=_metadata(kwargs),
                        event_type=(plan and plan["event_type"]) or "stream",
                        **self._labels(plan, rdec, outcome="response_flagged"))
                return agen_wrapper

            @functools.wraps(fn)
            def wrapper(*args, **kwargs):
                effective_mode, org_tightened = self._resolve_mode(decorator_mode)
                plan = self._evaluate_preflight(args, kwargs, policy, effective_mode,
                                                org_tightened)
                if plan and plan["kind"] == "block":
                    self._emit_block(plan, policy, agent)
                    raise FoxyPolicyBlocked(_block_message(policy, plan))
                call_args = plan["args"] if plan else args
                call_kwargs = plan["kwargs"] if plan else kwargs
                try:
                    response = fn(*call_args, **call_kwargs)
                except BaseException as exc:
                    self._record_host_exception(_extract_prompt(args, kwargs), exc,
                                                policy, agent, _metadata(kwargs))
                    raise
                hash_prompt = plan["hash_prompt"] if plan else _extract_prompt(args, kwargs)
                event_override = (plan and plan["event_type"]) or None
                if inspect.isgenerator(response):
                    # The FOURTH shape, and the one no decoration-time check can
                    # see: a plain def that RETURNS a generator. It is detected
                    # here, at call time, and gets the same streaming treatment
                    # as the async generator above.
                    def generator():
                        scanner = self._stream_scanner(policy)
                        chunks = []
                        stopped = None
                        try:
                            for chunk in response:
                                if scanner is not None:
                                    stopped = self._feed_scanner(scanner, chunk)
                                    if stopped is not None:
                                        break
                                chunks.append(chunk)
                                yield chunk
                        except BaseException as exc:
                            self._record_host_exception(_extract_prompt(args, kwargs), exc,
                                                        policy, agent, _metadata(kwargs))
                            raise
                        if stopped is not None:
                            stopped = self._with_coverage(stopped, scanner.coverage)
                            failed = self._emit_response_block(
                                hash_prompt, chunks, policy, agent, plan, stopped,
                                _metadata(kwargs), bool(chunks))
                            raise FoxyResponseBlocked(
                                _response_block_message(policy, stopped, bool(chunks), failed),
                                failed)
                        rdec = self._scan_response(chunks, policy)
                        self.log_interaction(
                            hash_prompt, chunks, policy, agent,
                            metadata=_metadata(kwargs),
                            event_type=event_override or "stream",
                            **self._labels(plan, rdec,
                                           outcome="response_flagged"))
                    return generator()
                meta = _metadata(kwargs, response)
                rdec = self._scan_response(response, policy)
                if rdec is not None and rdec.triggered and self.cfg.response_scan == "block":
                    failed = self._emit_response_block(hash_prompt, response, policy,
                                                       agent, plan, rdec, meta, False)
                    raise FoxyResponseBlocked(
                        _response_block_message(policy, rdec, False, failed), failed)
                self.log_interaction(hash_prompt, response, policy, agent, metadata=meta,
                                     event_type=event_override or "interaction",
                                     **self._labels(plan, rdec,
                                                    outcome="response_flagged"))
                return response
            return wrapper

        return decorator

    # ── internal ──────────────────────────────────────────────────────────
    def log_interaction(self, prompt, response, policy: str, agent: str | None = None,
                        metadata: dict | None = None, event_type: str = "interaction",
                        decision: str | None = None, policy_rules=None,
                        signals=None, blocked_reason: str | None = None):
        """Perform cryptographic hashing synchronously and push to AsyncDispatcher.

        The preflight guard passes ``decision`` ("allowed"|"blocked"|"redacted"),
        the fired ``signals`` (used verbatim as ``pii_signals``), the matched
        ``policy_rules`` and the dominant ``blocked_reason``. When ``decision`` is
        None the emitted payload is byte-for-byte identical to the observe path.

        The response scan adds two more ``decision`` values —
        ``response_flagged`` (recorded, allowed through) and ``blocked_response``
        (prevented) — and appends ``response_*``-namespaced ids to
        ``policy_rules``. It never touches ``signals``: see
        :meth:`_labels` for why that field is load-bearing on the backend.
        """
        try:
            prompt_s = hashing.canonical_json(prompt)
            response_s = hashing.canonical_json(response)
            event_id = str(uuid.uuid4())
            key = self.cfg.commitment_key or self.cfg.api_key
            if key:
                # One salt per event, stored ONLY in the customer's local sidecar.
                # record_salt returns None when it could not be stored, and the
                # event then commits unsalted — a salt that exists nowhere would
                # make the commitment permanently unprovable (see sidecar.py).
                event_salt = (sidecar.record_salt(self.cfg.salt_sidecar_path, event_id)
                              if self.cfg.salt_sidecar_path else None)
                prompt_hash = hashing.commitment_hex(prompt, key, event_salt)
                response_hash = hashing.commitment_hex(response, key, event_salt)
                # "hmac-sha256" and "sha256-legacy" keep their exact historical
                # meaning; the salted rows get their own name so old rows keep
                # verifying under the recipe they were written with.
                commitment_alg = "hmac-sha256-salted" if event_salt else "hmac-sha256"
            else:
                prompt_hash = hashing.sha256_hex(prompt_s)
                response_hash = hashing.sha256_hex(response_s)
                commitment_alg = "sha256-legacy"

            # The backend owns the tamper-evident hash chain (it re-derives each
            # link server-side), so the SDK only ships the per-interaction hashes;
            # a client-side chain_hash/timestamp would just be ignored.
            payload = {
                "event_id": event_id,
                "client_id": self.cfg.client_id,
                "event_type": event_type,
                "commitment_alg": commitment_alg,
                "prompt_hash": prompt_hash,
                "response_hash": response_hash,
                "token_count": hashing.estimate_tokens(prompt_s, response_s),
                "policy_tag": policy,
                # The UNION of what the preflight guard saw and what the full
                # prompt+response sweep finds. #158: this used to be
                # `signals if signals is not None else detect_pii(...)`, so a
                # redact row — where `signals` carries the prompt's fired
                # labels — skipped the sweep entirely and the RESPONSE was never
                # examined for PII at all. Inverted in the worst direction:
                # redact is the mode chosen BECAUSE the customer cares about
                # PII, and it was the mode that looked at the response least.
                #
                # A union rather than a replacement, because the guard path's
                # signals are exact and deliberate: a redact row still carries
                # precisely what fired on the prompt. Deduped and sorted to
                # match detect_pii's own output shape — this field is chain
                # material (chain.py:68), so its ordering has to be stable.
                "pii_signals": _merge_signals(signals,
                                              pii.detect_pii(prompt_s, response_s)),
            }
            if agent:
                payload["agent"] = agent
            if decision is not None or policy_rules:
                # Thread the preflight decision into event_metadata without
                # disturbing the observe path (decision is None AND no rules
                # there). Rules can arrive WITHOUT a decision: a response-scan
                # coverage id records that a shape could not be read, which is
                # evidence about the scan and not a decision about the
                # interaction. It must still reach the ledger.
                meta = _reserve_provenance(metadata) if metadata else {}
                if decision is not None:
                    meta["decision"] = decision
                meta["policy_rules"] = list(policy_rules or [])
                if blocked_reason is not None:
                    meta["blocked_reason"] = blocked_reason
                if meta["policy_rules"]:
                    # Ruleset provenance rides ONLY with the rule ids it
                    # explains. A rule id alone is "Foxy says so"; the two
                    # together let an auditor read the pattern that actually
                    # matched out of a frozen, versioned registry.
                    #
                    # Gated on the rules being NON-EMPTY rather than merely on
                    # reaching this branch: a row can arrive here with a
                    # decision and an empty list, and stamping a ruleset on that
                    # would claim rules explained something when none fired. The
                    # clean observe path does not enter this branch at all, so
                    # its payload stays byte-for-byte what it was — the property
                    # that makes observe a safe default.
                    meta.update(ruleset.provenance())
                payload["event_metadata"] = meta
            elif metadata:
                payload["event_metadata"] = _reserve_provenance(metadata)
            # raw text goes out of scope here — never stored or transmitted

            if self.cfg.desktop_ping:
                udp.send_ping(
                    {"event": "evaluating", "policy": policy, "tokens": payload["token_count"]},
                    self.cfg.udp_host,
                    self.cfg.udp_port,
                )
            result = None
            if self.cfg.enabled:
                result = (dispatch.submit(self.cfg, payload, wait=True)
                          if self.cfg.audit_required else dispatch.submit(self.cfg, payload))
            if self.cfg.desktop_ping:
                # This confirms only local hashing and queueing. It is not a
                # backend receipt or a policy verdict.
                udp.send_ping(
                    {
                        "event": "hash_ok",
                        "policy": policy,
                        "tokens": payload["token_count"],
                        "delivery": "queued" if self.cfg.enabled else "local_only",
                    },
                    self.cfg.udp_host,
                    self.cfg.udp_port,
                )
            if self.on_event is not None:
                self._emit_receipt(payload, self.cfg.enabled)
            if self.cfg.enabled:
                return result
        except Exception as exc:  # telemetry must never break the host app
            log.debug("foxy-audit observe error: %s", exc)
            if self.cfg.audit_required:
                raise AuditRequiredError("Foxy Audit could not durably deliver the event") from exc

    def _emit_receipt(self, payload: dict, submitted: bool) -> None:
        """Hand the caller the id of the row it just wrote. CONTENT-BLIND.

        The decorator returns the wrapped function's response — a frozen public
        contract — so before this hook a consumer of the SDK could not name the
        ledger row its own call produced, and no other path exposed the id.

        BUILT FROM ``payload``, NOT FROM log_interaction's ARGUMENTS. Every value
        here is one the wire actually carries, so the receipt cannot describe an
        event different from the one recorded, and it is content-blind by
        construction: ``prompt_hash`` is a commitment, never text.

        Three properties worth stating rather than leaving to be discovered:

        * IT FIRES WHEN ``cfg.enabled`` IS FALSE TOO, with ``submitted=False``.
          The id and the decision are real even when nothing shipped, and a hook
          that only fired for keyed clients would be dead code on every offline
          run.
        * ⚠ SOME EVENTS EXIST WITH NO RECEIPT. A REAL HOLE IN THIS HOOK'S
          COVERAGE, not a wording slip. An earlier version of this docstring said
          the hook does not fire "because there is no durable row to name", and
          that is FALSE under ``audit_required=True``: ``dispatch.submit`` calls
          ``spool.enqueue``, which commits to SQLite/WAL, BEFORE it starts
          waiting. A receipt timeout therefore raises ``AuditRequiredError``
          while the row is already durable and will be delivered on a later
          flush. The caller is told the event failed, the event lands anyway, and
          no receipt was ever emitted for it — an ``event_id`` that reaches the
          ledger and that this hook can never point ``explain()`` at.

          Two classes of event have no receipt, both because this call sits after
          the submit and inside the blanket handler:

            - ``audit_required=True`` and the server receipt did not arrive
              before the deadline — spooled, delivered later, NOT reported here;
            - anything raising between the submit returning and this call (the
              ``hash_ok`` desktop ping is the only such call today) — likewise
              spooled and delivered later.

          A consumer that must account for every row cannot read "no receipt" as
          "no event". Reconcile against an export, not against this hook.
        * IT RUNS WHEREVER log_interaction RUNS. ``_record_async`` calls that
          under ``asyncio.to_thread``, so in async use the callback arrives OFF
          the event loop, on a worker thread. A Qt or Tk consumer must not touch
          widgets from it.

        Its own ``try`` because a customer's broken callback must not raise out
        of their model call — and must not reach the handler above, which would
        turn it into an ``AuditRequiredError`` about a delivery that succeeded.
        Type name only: a callback's message can carry whatever it was handed.
        """
        meta = payload.get("event_metadata") or {}
        try:
            self.on_event({
                "event_id": payload["event_id"],
                "event_type": payload["event_type"],
                "policy_tag": payload["policy_tag"],
                # From event_metadata, which the clean observe path does not
                # build at all — so these read None there, and None ("no guard
                # ran") is not [] ("the guard ran and nothing fired").
                "decision": meta.get("decision"),
                "policy_rules": meta.get("policy_rules"),
                "blocked_reason": meta.get("blocked_reason"),
                "ruleset_version": meta.get("ruleset_version"),
                "ruleset_hash": meta.get("ruleset_hash"),
                "commitment_alg": payload["commitment_alg"],
                "prompt_hash": payload["prompt_hash"],
                "response_hash": payload["response_hash"],
                "pii_signals": payload["pii_signals"],
                # ⚠ `submitted`, NOT `delivered`, AND THE DIFFERENCE IS THE
                # WHOLE POINT. Under the default `audit_required=False`,
                # `dispatch.submit` writes the local spool and returns — it says
                # nothing about the backend. With a REVOKED key every POST 401s
                # and retries forever while the event sits in the spool, and a
                # field called `delivered` would have read True on every one of
                # those. `submitted` is true in both configurations and claims
                # only what happened: the event was durably enqueued and handed
                # to the dispatcher. False means no key — nothing was submitted
                # at all.
                #
                # Under `audit_required=True` a server receipt DID come back,
                # because `submit(wait=True)` raises otherwise and this hook
                # never fires. That is a stronger guarantee than the field name
                # claims, and it is deliberately left here rather than encoded
                # in a name a reader would then over-trust in the other config.
                "submitted": submitted,
            })
        except Exception as exc:             # noqa: BLE001 — type name only
            log.debug("foxy-audit: on_event callback failed (%s)", type(exc).__name__)


def _validate_on_event(value):
    """Return ``value`` if it can serve as a receipt callback, else raise.

    ⚠ LOUD, AND THAT IS NOT A BREACH OF THE STANDING RULE. "Telemetry must never
    break the host app" governs the PER-EVENT path, where the alternative to
    swallowing is losing the customer's call. This is CONFIGURATION — and a
    mis-wired hook that only whispers at ``log.debug`` once per event is
    indistinguishable from no hook at all, which is the exact failure a receipt
    exists to remove. The mistake is here; so is the report.
    """
    if value is None:
        return None
    if not callable(value):
        raise TypeError(
            f"on_event must be callable, got {type(value).__name__}. "
            "It is invoked with one argument: the receipt dict.")
    # An `async def` callback is the mistake this SDK invites: its own decorators
    # are async-aware, so reaching for one here is natural and WRONG.
    # `_emit_receipt` calls it synchronously, so a coroutine function would
    # return a coroutine nobody awaits — the body never runs, nothing is
    # recorded, and the only trace is a RuntimeWarning about a coroutine never
    # awaited, on a line the user did not write. `__call__` is checked too:
    # `iscoroutinefunction` says False for an INSTANCE whose `__call__` is
    # `async def`, and that shape fails identically.
    if (inspect.iscoroutinefunction(value)
            or inspect.iscoroutinefunction(getattr(value, "__call__", None))):
        raise TypeError(
            "on_event must be a synchronous callable; an `async def` callback "
            "would never be awaited and its body would never run. Hand the "
            "receipt to your loop yourself — e.g. "
            "`on_event=lambda r: loop.call_soon_threadsafe(q.put_nowait, r)` — "
            "and note that from an async call site it arrives on a worker "
            "thread, not the event loop.")
    return value


def _block_message(policy: str, plan: dict) -> str:
    """Content-blind exception message: policy tag + short reason label only.

    When the workspace tightened the mode, SAY SO. A developer reading
    FoxyPolicyBlocked from code that says `observe` would otherwise have no way
    to discover the cause, and would go looking in the wrong place (§B6).

    Which means naming the field the SDK ACTUALLY reads. This sentence said
    `enforcement_mode=block` for two releases; that is the judge-response
    setting, and org_policy.py has never read it (see SDK_ENFORCEMENT_FIELD).
    Sending a blocked developer to a different control on a different page is
    the same wrong-place problem this message exists to prevent."""
    base = (f"Foxy Audit blocked a prompt under policy '{policy}' "
            f"(reason: {plan['reason']}). The wrapped function was not called.")
    if plan.get("redact_ineffective"):
        # A developer whose code says mode="redact" and who gets a BLOCK needs to
        # know it was not a misconfiguration, and WHICH finding could not be
        # removed — otherwise the only way to find out is to guess. Content-blind:
        # rule ids are the same labels the row already carries in policy_rules,
        # and nothing from the prompt appears.
        base += (" mode='redact' was requested, but {0} still matched the "
                 "redacted prompt, so the finding would have reached the model "
                 "anyway (a finding with nothing to substitute — a Presidio "
                 "match, a value in a non-string field, a match spanning a "
                 "structured prompt's envelope). Foxy Audit blocks rather than "
                 "record a redaction that did not remove the finding.".format(
                     ", ".join(plan["redact_ineffective"])))
    if plan.get("org_tightened"):
        # NAMES THE VALUE THE WORKSPACE ACTUALLY SET, not a guess at it. This
        # sentence hardcoded `sdk_enforcement=block`, which was true while a
        # tightening could only ever produce a block. The redact-noop route made
        # it reachable with `sdk_enforcement=redact` too — org_policy.resolve
        # returns ("redact", True) when the local mode is unset — so it started
        # telling customers a value their org had not set, which is the same
        # wrong-place problem this message exists to prevent.
        base += (" This block came from your Foxy Audit workspace policy "
                 "(sdk_enforcement={0}), not from this code's own mode. "
                 "Change it in Settings, or set FOXY_ORG_POLICY=off to ignore "
                 "workspace policy in this deployment.".format(
                     plan.get("effective_mode") or "block"))
    return base


#: Reserved-key collisions already reported, so a hot loop reports once.
_warned_reserved: set = set()


def _reserve_provenance(metadata) -> dict:
    """A copy of ``metadata`` with the ruleset-provenance keys removed.

    ``ruleset_version`` / ``ruleset_hash`` must mean "the SDK computed this" on
    EVERY path, or they mean nothing. Left alone, a caller's value passed
    straight through on the plain-metadata path, and on the guarded path a ``{}``
    from a degraded registry left a caller's value standing.

    The threat model is not forgery — the SDK runs in the customer's own process
    and a determined customer can always misdescribe their own trail. It is
    COLLISION: a customer who happens to use ``ruleset_version`` in their own
    metadata would silently overwrite the real one, and nothing downstream could
    tell the difference.

    The drop is WARNED, not silent, and once per process per key. Silently
    discarding a key someone deliberately passed has its own failure mode — they
    would look for their value and not find it — so the message names the key and
    says it is reserved.

    ``log.warning`` rather than ``warnings.warn`` (which policy.py uses for an
    unrecognised tag) is deliberate here: this runs inside ``log_interaction``,
    whose whole contract is that SDK bookkeeping never disturbs the host
    application, and ``warnings.warn`` can be configured to raise under
    ``-W error`` — turning a metadata collision into an application crash.
    """
    clean = dict(metadata)
    for key in ruleset.PROVENANCE_KEYS:
        if key in clean:
            del clean[key]
            if key not in _warned_reserved:
                _warned_reserved.add(key)
                log.warning(
                    "foxy-audit: event_metadata[%r] is RESERVED for ruleset "
                    "provenance and was dropped; the SDK sets it itself. Rename "
                    "your field to keep its value. Reported once per process.",
                    key)
    return clean


def _merge_signals(guard_signals, swept):
    """The wire's ``pii_signals``: the guard's labels ∪ the full sweep's.

    ``guard_signals`` is None on the observe path, where the sweep alone has
    always been the answer and stays byte-identical. On the guard path it is the
    exact list that fired on the PROMPT, which must survive verbatim — an
    auditor reading a redacted row is entitled to see what caused the redaction.

    NOT NAMESPACED, and that is a decision rather than an omission. S1 gave the
    response side a ``response_*`` vocabulary, but it lives in ``policy_rules``,
    which is metadata. This field is different in three ways that all point the
    same way:

    * it is CHAINED (chain.py:68), so two labels for one finding depending on
      the caller's mode would make cross-row analysis wrong for ever;
    * the observe path has never distinguished sides — ``detect_pii`` merges
      prompt and response into one list — so a namespace here would make a
      redact row describe the same finding differently from an observe row;
    * the question is already answerable without one. ``policy_rules`` carries
      the prompt's fired ids (``phi.email``, ``pii.ip_address``), so anything in
      ``pii_signals`` that those do not account for came from the response.

    If a reader ever needs the split explicitly, the honest place to add it is a
    new metadata key, not a second vocabulary inside chain material.
    """
    swept = list(swept or [])
    if guard_signals is None:
        return swept
    return sorted(set(guard_signals) | set(swept))


def _response_block_message(policy: str, decision, delivered: bool = False,
                            audit_delivery_failed: bool = False) -> str:
    """Content-blind exception message for a blocked RESPONSE.

    It says plainly what a prompt block does not have to: the model DID run.
    A developer who reads "blocked" and assumes no call was made will go
    looking for a bill that does not match, so the sentence states the cost and
    the control that produced it (``response_scan``, not ``mode``) — the same
    wrong-place problem :func:`_block_message` exists to prevent.

    And when part of a stream was already delivered, it SAYS SO. A developer who
    reads "blocked" and assumes their application received nothing will not go
    looking for the chunks that are already in it."""
    base = (f"Foxy Audit blocked a model response under policy '{policy}' "
            f"(reason: {decision.reason}). The wrapped function DID run and the "
            f"provider was called; the response was withheld from the caller by "
            f"response_scan=block.")
    if delivered:
        base += (" This was a STREAM and chunks yielded before the flagged one "
                 "HAVE already reached your code — the stream was cut, not "
                 "prevented. The audit event records it as response_truncated.")
    if audit_delivery_failed:
        base += (" audit_required is set and this event could not be durably "
                 "delivered; the block still applies (see "
                 "FoxyResponseBlocked.audit_delivery_failed).")
    return base


def _metadata(kwargs: dict, response=None) -> dict:
    """Keep only non-content identifiers useful to an auditor."""
    allowed = ("request_id", "trace_id", "session_id", "provider", "model",
               "tool_names", "retrieval_refs")
    result = {}
    for key in allowed:
        value = kwargs.get(key)
        if value is None:
            continue
        if key in {"tool_names", "retrieval_refs"}:
            result[key] = [str(v)[:128] for v in value] if isinstance(value, (list, tuple)) else [str(value)[:128]]
        else:
            result[key] = str(value)[:256]
    result.update(response_metadata(response) if response is not None else {})
    return result
