"""Durable, retrying background delivery for metadata-only events."""

from __future__ import annotations

import atexit
import json
import logging
import queue
import threading
import time
from collections import defaultdict

import requests

from .config import FoxyConfig
from . import ruleset
from .spool import EventSpool

log = logging.getLogger("foxy_audit")


def _endpoint(cfg: FoxyConfig) -> str:
    base = cfg.endpoint.rstrip("/")
    for suffix in ("/v1/logs/batch", "/v1/logs", "/logs/batch", "/logs"):
        if base.endswith(suffix):
            base = base[: -len(suffix)]
            break
    return f"{base}/v1/logs/batch"


class AsyncDispatcher:
    def __init__(self, batch_size: int = 10, flush_interval: float = 1.0) -> None:
        self._q: "queue.Queue[tuple[FoxyConfig, str]]" = queue.Queue()
        self._thread: threading.Thread | None = None
        self._lock = threading.Lock()
        self.batch_size = batch_size
        self.flush_interval = flush_interval
        self._shutdown = False
        self._paths: set[str | None] = set()
        atexit.register(self.flush)

    def _ensure_worker(self) -> None:
        if self._thread is not None and self._thread.is_alive():
            return
        with self._lock:
            if self._thread is None or not self._thread.is_alive():
                self._shutdown = False
                self._thread = threading.Thread(
                    target=self._run, name="foxy-audit-async-dispatch", daemon=True)
                self._thread.start()

    def submit(self, cfg: FoxyConfig, payload: dict, wait: bool = False):
        spool = EventSpool(cfg.spool_path or None)
        enriched = spool.enqueue(_endpoint(cfg), cfg.api_key, payload)
        self._paths.add(cfg.spool_path or None)
        self._ensure_worker()
        self._q.put((cfg, enriched["event_id"]))
        if wait:
            deadline = time.time() + max(1.0, cfg.timeout)
            while time.time() < deadline:
                self._flush_spool({cfg.spool_path or None})
                receipt = spool.receipt(enriched["event_id"])
                if receipt is not None:
                    return receipt
                time.sleep(0.05)
            raise TimeoutError("Foxy Audit server receipt was not received")
        return {"status": "queued", "event_id": enriched["event_id"],
                "client_seq": enriched["client_seq"]}

    def resume(self, cfg: FoxyConfig) -> None:
        """Wake delivery for a client even when no new event has arrived yet."""
        self._paths.add(cfg.spool_path or None)
        self._ensure_worker()

    def _run(self) -> None:
        while not self._shutdown or not self._q.empty():
            try:
                self._q.get(timeout=self.flush_interval)
            except queue.Empty:
                pass
            # Wrapped for the same reason the org policy tick below is: nothing
            # may stop event delivery. This call was bare, so ANY exception here
            # killed the dispatcher thread outright and every later event in the
            # process silently stopped being delivered — the spool kept them,
            # but nothing was left alive to retry. Found by the race fixed in
            # _flush_spool, which reached this line as a RuntimeError.
            try:
                self._flush_spool()
            except Exception as exc:             # noqa: BLE001 — type name only
                log.debug("foxy-audit: spool flush failed (%s)", type(exc).__name__)
            # Org policy rides THIS thread rather than getting its own (P4 §B2).
            # It is TTL-gated, so ~12 requests an hour per process, and it is
            # wrapped because a policy problem must never stop event delivery.
            try:
                from . import org_policy
                org_policy.tick()
            except Exception as exc:         # noqa: BLE001 — type name only
                log.debug("foxy-audit: org policy tick failed (%s)", type(exc).__name__)

    @staticmethod
    def _post(endpoint: str, api_key: str, body: list):
        return requests.post(
            endpoint, json=body,
            headers={"Authorization": f"Bearer {api_key}",
                     "Content-Type": "application/json"},
            timeout=10.0,
        )

    def _flush_spool(self, paths: set[str | None] | None = None) -> None:
        # SNAPSHOT. `self._paths` is mutated by `resume()` on whatever thread
        # constructed a FoxyClient, while this loop runs on the dispatcher
        # thread. Iterating it live raised "Set changed size during iteration"
        # the moment a second client was created mid-flush.
        for path in tuple(paths or self._paths or {None}):
            spool = EventSpool(path)
            rows = spool.due(self.batch_size)
            if not rows:
                continue
            grouped = defaultdict(list)
            for row in rows:
                grouped[(row["endpoint"], row["api_key"])].append(row)
            for (endpoint, api_key), batch in grouped.items():
                try:
                    body = [json.loads(row["payload"]) for row in batch]
                    # WHICH RUNGS EACH ROW CARRIES, captured before anything
                    # is stripped. Intersected at ack time with what the batch
                    # actually lost, because both halves are per-something-else:
                    # what a row HELD is per row, what was DROPPED is per batch.
                    carried = [_rungs_in(event) for event in body]
                    # Already known to be refused here: strip those rungs up
                    # front rather than spend a doomed request per batch for the
                    # rest of the retry window. ONLY those rungs — stripping a
                    # rung this endpoint never refused is how a typed-tag
                    # rejection came to cost unrelated rows their provenance.
                    stripped = [name for name, keys, _why in _DEGRADE_LADDER
                                if name in _latched_rungs(endpoint)
                                and _strip_provenance(body, keys)]
                    resp = self._post(endpoint, api_key, body)
                    # 🔴 SEMANTIC BEFORE CAPABILITY, AND WITHOUT LATCHING (#256).
                    # A refusal that NAMES one of this batch's system_ids is
                    # about THAT SYSTEM — retired, or never declared here — not
                    # about the endpoint's ability to hold an attribution. So
                    # only the rows carrying that id lose theirs, and nothing is
                    # remembered: the next batch tries again in full, because
                    # nothing has been learned about the endpoint.
                    #
                    # LOOPED, because the router raises on the FIRST bad id it
                    # meets, so a batch naming two retired systems needs two
                    # passes. Bounded twice over: each pass must drop at least
                    # one row's attribution or it stops, and there are at most
                    # as many distinct ids as rows.
                    refused = set()
                    for _ in range(len(body)):
                        named = _refused_attributions(resp, body)
                        if not named:
                            break
                        dropped = _drop_attribution(body, named)
                        if not dropped:
                            break
                        refused.update(dropped)
                        log.warning(
                            "foxy-audit: %s refused the attribution %s; "
                            "resending %d event(s) without it. The system is "
                            "retired or is not declared in this workspace — "
                            "the events are intact, and every other event in "
                            "this batch keeps its attribution.",
                            endpoint, " / ".join(named), len(dropped))
                        resp = self._post(endpoint, api_key, body)
                    # ESCALATE ONE RUNG AT A TIME, newest key set first. A
                    # blanket strip would answer "policy_tag_raw is unknown here"
                    # by also dropping ruleset provenance the backend accepts,
                    # and then latch that lie for 900 seconds. The ladder's
                    # nesting (see _DEGRADE_LADDER) makes this terminate in at
                    # most one extra POST beyond the true boundary.
                    #
                    # Each retry is bounded by _strip_provenance's return value:
                    # a rung this batch does not carry is skipped rather than
                    # re-POSTed byte-identically to the request that just failed.
                    #
                    # Ingest validates `payload: List[LogIngest]` as ONE unit, so
                    # a 422 rejects every event in the request, not just the
                    # guarded one. A provenance nicety must never cost a customer
                    # their audit trail, and a self-hosted, lagging or frozen
                    # deployment is not ours to sequence.
                    escalated = []
                    for name, keys, why in _DEGRADE_LADDER:
                        if not _rejects_unsupported_fields(resp):
                            break
                        if name in stripped or not _strip_provenance(body, keys):
                            continue
                        log.warning("foxy-audit: %s rejected %s; resending "
                                    "without %s.", endpoint, _keys_phrase(keys), why)
                        escalated.append(name)
                        resp = self._post(endpoint, api_key, body)
                    # Only NOW, and only if dropping those keys is what fixed it.
                    # "unsupported fields" is the validator's message for ANY
                    # unknown key, so a backend rejecting something else entirely
                    # — one older than `policy_rules`, say — would otherwise
                    # disable these keys for the whole retry window while the
                    # actual offender went untouched and the batch kept failing.
                    #
                    # ⚠ KNOWN LIMIT, DOCUMENTED AND NOT FIXED (R3b gate, #259).
                    # "unsupported fields" is also the prefix of the VALUE
                    # refusals — `policy_tag_raw is not a spelling of
                    # policy_tag`, `system_id is not an AI system id` — which
                    # say a key this backend KNOWS carries a bad value. Nothing
                    # here can tell those from a capability refusal, so such a
                    # 422 walks the ladder: rung 1 is stripped, the 422
                    # persists, rung 2 fixes it, and BOTH latch. `system_id` is
                    # then disabled for 900 seconds against a backend that
                    # accepts it.
                    #
                    # Left alone deliberately, and the reasoning belongs here
                    # rather than in a register nobody opens while reading this
                    # line:
                    #
                    #   * IT IS UNREACHABLE FROM THIS SDK. Every value refusal
                    #     is mirrored client-side before anything is sent —
                    #     `client._typed_tag` enforces both of the ledger's
                    #     typed-tag rules, `client._checked_system_id` enforces
                    #     the canonical spelling — so reaching this state means
                    #     a hand-edited spool or a producer that is not this
                    #     package.
                    #   * IN THAT STATE, OVER-STRIPPING IS THE CONSERVATIVE
                    #     ANSWER. The batch still lands; what degrades is
                    #     provenance, recorded in the receipt, self-healing in
                    #     15 minutes. Being precise about a state that means
                    #     something upstream is already broken would buy
                    #     accuracy nobody can reach.
                    #   * AND THE PRECISE VERSION COSTS MORE THAN IT SAVES. It
                    #     would key the latch on the message having no ": …"
                    #     suffix — a NEW wording dependency, inside the one
                    #     decision three gate rounds have already got wrong, for
                    #     a path no shipped client can take.
                    #
                    # R3 WIDENED THIS RATHER THAN CREATING IT: before the
                    # `system_id` rung, the same 422 latched `policy_tag_raw`
                    # alone — also a key the backend accepts. One rung then, two
                    # now. If it is ever fixed, fix it for both. Pinned by
                    # test_the_ladder_latches_a_rung_a_value_error_never_refused.
                    if escalated and resp.status_code < 400:
                        marked_at = time.time()
                        for name in escalated:
                            _no_provenance[(endpoint, name)] = marked_at
                        stripped.extend(escalated)
                    resp.raise_for_status()
                    try:
                        response = resp.json()
                    except ValueError:
                        response = {"status": "accepted", "http_status": resp.status_code}
                    if not isinstance(response, dict):
                        # A 202 body that is valid JSON but not an object — a
                        # proxy answering `"accepted"` or `[]`. Without this,
                        # `dict(response)` raises AFTER a successful POST and
                        # the except below re-queues an ALREADY ACCEPTED batch,
                        # turning someone else's odd proxy into duplicate
                        # delivery attempts forever.
                        response = {"status": "accepted",
                                    "http_status": resp.status_code,
                                    "body": str(response)[:256]}
                    if stripped or refused:
                        # RECORDED, not merely logged — and recorded LOCALLY, in
                        # the spool receipt, because it cannot ride on the wire:
                        # a marker key would itself be unknown to the very
                        # backend that just rejected an unknown key, so telling
                        # the ledger about the degradation would re-trigger the
                        # failure it describes.
                        by_marker = defaultdict(list)
                        for index, (row, held) in enumerate(zip(batch, carried)):
                            # What this row actually LOST: what it held, kept to
                            # what the batch dropped. A row carrying provenance
                            # in a batch where only the typed tag was stripped
                            # lost nothing and must not say it did.
                            #
                            # The semantic refusal is per ROW rather than per
                            # batch, so it joins from the index side. It can
                            # coexist with the rung: a row whose attribution was
                            # refused by name, in a batch that then met a
                            # backend refusing the key outright, honestly lost
                            # it both ways.
                            markers = tuple(n for n in held if n in stripped)
                            if index in refused:
                                markers += (_DEGRADED_ATTRIBUTION,)
                            by_marker[markers].append(row)
                        for markers, rows_for in by_marker.items():
                            spool.ack(rows_for,
                                      dict(response, foxy_degraded=list(markers))
                                      if markers else response)
                    else:
                        spool.ack(batch, response)
                except Exception as exc:
                    spool.retry(batch, f"{type(exc).__name__}: {exc}")
                    log.debug("foxy-audit POST failed; event(s) retained: %s", exc)

    def flush(self) -> None:
        self._shutdown = True
        if self._thread and self._thread.is_alive():
            self._thread.join(timeout=2.0)
        # Wrapped for the same reason the loop's call is. This one is the atexit
        # handler, so an exception here surfaces during interpreter shutdown, in
        # the customer's process, out of a library they did not call — and it
        # cannot help them: the spool is durable, so the events survive to the
        # next run either way.
        try:
            self._flush_spool()
        except Exception as exc:                 # noqa: BLE001 — type name only
            log.debug("foxy-audit: final spool flush failed (%s)", type(exc).__name__)


#: ``(endpoint, rung)`` pairs observed to be rejected, mapped to WHEN. Not
#: persisted, and not permanent either.
#:
#: ⚠ THE RUNG IN THAT KEY IS LOAD-BEARING AND WAS ADDED AT S13. This was
#: keyed by ENDPOINT ALONE while the strip removed ONE key set, and stayed that
#: way for a moment when the strip grew to two — so a backend that refuses only
#: ``policy_tag_raw``, which is exactly the FROZEN PRODUCTION one, latched on the
#: first miscased-tag row and every later batch went out with
#: ``ruleset_version``/``ruleset_hash`` pre-stripped from a backend that accepts
#: them. Silently, for 900 seconds, re-armed by the next miscased tag.
#:
#: That is worse than losing provenance. ``introspect.explain`` reads a row with
#: rule ids and no version as ``ruleset_unrecorded`` cause 1 — "the backend
#: rejected the provenance keys" — which would have been FALSE for those rows.
#: S14 and S17 spent four rounds making that sentence honest; a single-dimension
#: latch makes it lie again through a side door.
#:
#: The reasoning for not persisting was "a backend gets upgraded, and a cache
#: that outlived the process would keep stripping provenance long after the
#: reason went away" — which a never-expiring in-process latch contradicts for
#: exactly the deployments that matter. A dispatcher thread lives as long as its
#: process, so a long-running worker that met an old backend once during a
#: rollout would strip provenance for its entire lifetime, silently, with the
#: backend upgraded minutes later. Re-probing costs one 422 per endpoint per
#: window; never re-probing costs every guarded row its provenance.
_no_provenance: dict[str, float] = {}

#: How long a rejection is trusted before that rung is probed again.
PROVENANCE_RETRY_AFTER = 900.0

_DEGRADED_PROVENANCE = "ruleset_provenance_stripped"
_DEGRADED_TYPED_TAG = "policy_tag_raw_stripped"
#: This ENDPOINT cannot hold an attribution at all — a backend older than R2,
#: which does not know the key. Endpoint-wide, and latched.
_DEGRADED_SYSTEM_ID = "system_id_stripped"
#: THIS EVENT'S attribution was refused BY NAME — the system is retired, or was
#: never declared in this workspace. A different thing from the rung above, with
#: a different remedy, so it gets its own marker rather than borrowing one whose
#: meaning ("upgrade your backend") would be false. See
#: :func:`_refused_attributions`.
_DEGRADED_ATTRIBUTION = "system_id_refused"

#: The other client-supplied ``event_metadata`` key a lagging backend can reject,
#: and therefore the other one this module has to be able to strip.
#:
#: ⚠ A SECOND TUPLE RATHER THAN A WIDER ``ruleset.PROVENANCE_KEYS``, decided
#: rather than defaulted. ``policy_tag_raw`` is the spelling the CALLER TYPED; it
#: describes neither the rules nor the interaction, so putting it in a tuple
#: named for ruleset provenance would make that name false everywhere it is read
#: — and ``test_explain_verifies_the_ruleset`` asserts, correctly, that
#: ``set(ruleset.provenance()) == set(ruleset.PROVENANCE_KEYS)``, which a third
#: member would break for a reason that has nothing to do with what it guards.
#: S14 set the precedent with ``client._ENFORCEMENT_KEYS`` beside
#: ``PROVENANCE_KEYS`` rather than inside it. Here rather than in ``ruleset``
#: because stripping is THIS module's job and ``client`` already imports it,
#: while ``dispatch`` importing ``client`` would be a cycle.
#:
#: ⚠ WITHOUT THIS, S13 IS AN EVIDENCE OUTAGE, NOT A FIX. Production is frozen
#: and will never allowlist the key: it answers "unsupported fields", the
#: degrade path fires, and a strip that removes nothing makes the resend
#: BYTE-IDENTICAL to the request that just failed — which
#: :func:`_strip_provenance` correctly refuses to send. No retry, then
#: ``raise_for_status``, then ``spool.retry`` re-queues the whole batch, forever.
TYPED_TAG_KEYS = ("policy_tag_raw",)

#: The THIRD client-supplied ``event_metadata`` key a lagging backend can refuse
#: — the AI-system attribution (R3). A third tuple for the reason there is a
#: second one: it describes neither the ruleset nor the caller's typed spelling,
#: it names a row in the customer's own declared inventory, and folding it into
#: either existing name would make that name false where it is read.
#:
#: ``client._reserve_provenance`` strips a CALLER's copy for a fourth reason
#: again — the SDK validates this value at configure time and this module
#: degrades it on refusal, and a hand-set copy would slip past both.
SYSTEM_ID_KEYS = ("system_id",)

#: The client-supplied key sets a backend can refuse, as RUNGS: a name, the keys,
#: and the remedy to tell an operator. NEWEST FIRST, which is also
#: OLDEST-BACKEND-LAST, and that ordering is the whole reason escalating one rung
#: at a time terminates cheaply.
#:
#: ⚠ THE INGEST ALLOWLIST HAS ONLY EVER GROWN, so the sets a backend refuses
#: are NESTED: {} ⊂ {system_id} ⊂ {system_id, policy_tag_raw} ⊂ {system_id,
#: policy_tag_raw, ruleset_*}. A backend that knows ``system_id`` (R2)
#: necessarily knows ``policy_tag_raw`` (S12), which necessarily knows the
#: provenance keys (1.7.0-era), because each was allowlisted before the one
#: after it. So stripping the newest rung and re-probing finds the true boundary
#: in at most one extra POST, and a backend refusing nothing still pays exactly
#: one.
#:
#: ⚠ WHICH IS WHY ``system_id`` WENT IN FIRST RATHER THAN LAST. It is the
#: NEWEST key, so it is the one the most backends refuse. Appended instead, a
#: backend that refuses only ``system_id`` — every deployment older than R2,
#: including the frozen production one — would have had the typed tag stripped
#: first: a POST spent on a rung that backend was happy to take, a 422 that says
#: nothing new, and then a latch recording a refusal that never happened.
#:
#: If that nesting were ever violated — a backend refusing the ruleset keys but
#: not the typed tag — this over-strips the newer rungs for one retry window
#: rather than failing: rung 1 is applied, the 422 persists, rung 2 is applied,
#: and so on until the POST succeeds, and every rung applied latches. Degraded
#: and recorded, not broken. Stated because it is the assumption the cheapness
#: rests on, not a proof.
_DEGRADE_LADDER = (
    (_DEGRADED_SYSTEM_ID, SYSTEM_ID_KEYS,
     "the AI-system attribution. The events are intact and every other field is "
     "unchanged, but they no longer say which of your declared systems produced "
     "them; a backend that allowlists event_metadata['system_id'] restores it"),
    (_DEGRADED_TYPED_TAG, TYPED_TAG_KEYS,
     "the caller's typed policy-tag spelling. The canonical policy_tag is "
     "unaffected and the events are intact; a backend that allowlists "
     "event_metadata['policy_tag_raw'] restores the spelling"),
    (_DEGRADED_PROVENANCE, tuple(ruleset.PROVENANCE_KEYS),
     "ruleset provenance. The events are intact and keep their rule ids, but "
     "those ids no longer name the ruleset that explains them; upgrade the "
     "backend to restore it"),
)

#: Every key this module is able to remove — the default for
#: :func:`_strip_provenance`, i.e. "everything we could possibly drop".
_ALL_DEGRADE_KEYS = tuple(k for _name, keys, _why in _DEGRADE_LADDER for k in keys)


def _latched_rungs(endpoint: str) -> tuple:
    """Which rungs this endpoint is still known to refuse, in ladder order.

    Expiry is per rung, so an endpoint that refuses the typed tag can stop
    refusing it without dragging a provenance latch along, and vice versa.
    """
    live = []
    for name, _keys, _why in _DEGRADE_LADDER:
        marked = _no_provenance.get((endpoint, name))
        if marked is None:
            continue
        if time.time() - marked >= PROVENANCE_RETRY_AFTER:
            _no_provenance.pop((endpoint, name), None)
            continue
        live.append(name)
    return tuple(live)


def _rejects_unsupported_fields(resp) -> bool:
    """Is this the specific 422 that means "I do not know those keys"?

    Narrow on purpose. A blanket "422 -> drop fields and retry" would also fire
    on a genuinely malformed payload, where retrying with fewer fields is not a
    fix but a second way to be wrong. It matches the validator's own message
    (schemas.py: "event_metadata contains unsupported fields"), so a 422 about a
    bad hash or an oversized label still fails loudly and retries normally.
    """
    if getattr(resp, "status_code", None) != 422:
        return False
    try:
        return "unsupported fields" in resp.text
    except Exception:                        # noqa: BLE001 — a body we cannot read
        return False


def _keys_phrase(keys) -> str:
    """``event_metadata['a'] / event_metadata['b']`` — the keys, for a human.

    The warning is the ONLY operator-facing signal on this path, so it names the
    field that was actually refused. It used to say "rejected ruleset
    provenance" whatever had been dropped, which sent an operator to upgrade a
    backend over a key that backend had never been asked about.
    """
    return " / ".join("event_metadata[%r]" % k for k in keys)


def _refused_attributions(resp, body) -> tuple:
    """Which of THIS batch's ``system_id`` values the refusal actually NAMES.

    🔴 THE LATCH SPLIT, AND THE WHOLE REASON R3 IS NOT ONE MORE LADDER RUNG.

    R2 answers a RETIRED or FOREIGN system with the same "unsupported fields"
    phrase a capability refusal uses, and it had to: that phrase is the only one
    :func:`_rejects_unsupported_fields` recognises, and a message this module
    does not recognise means no strip-and-retry, then ``raise_for_status``, then
    ``spool.retry`` re-queuing the whole batch forever. So the two refusals are
    indistinguishable by status and by phrase — but not by CONTENT:

    * a SEMANTIC refusal names the offending id, because a human has to be told
      WHICH of their systems was retired;
    * a CAPABILITY refusal cannot, because the backend that sends it has never
      heard of the key.

    Read as capability, one retired system would latch ``system_id`` off for
    the whole ENDPOINT for 900 seconds — every healthy system's events included
    — and those rows are chain-bound, so the attribution would be permanently
    absent from the evidence rather than merely delayed. That is #256, and it is
    the defect this function exists to prevent rather than one it fixes.

    🔴 TWO CONDITIONS, AND NEITHER IS SUFFICIENT ALONE. R3 shipped with only the
    second and that was WRONG about which case is the unlucky one:

    1. ``detail`` IS A JSON STRING, not a list. This is the structural fact that
       separates the two layers, and it is a property of how each is RAISED
       rather than of how either is worded:

         * the ownership refusals are ``HTTPException(422, detail="…")``, and
           FastAPI serialises that as ``{"detail": "<the sentence>"}``;
         * every capability and value refusal comes out of a pydantic validator
           as ``RequestValidationError``, which is ALWAYS a list of error
           objects — including through ``main._validation_error_handler``, whose
           redaction keeps ``type``/``loc``/``msg`` per error and therefore
           keeps the shape.

       Measured against the running app rather than inferred: str for both
       ownership refusals, list for the unknown key, for
       ``system_id is not an AI system id`` and for the two ``policy_tag_raw``
       value errors. Guarded at the source by
       ``test_the_two_refusal_layers_have_different_detail_SHAPES``.

    2. THE SPELLING IS ONE THIS BATCH ACTUALLY SENT. Kept from R3, and still
       carrying its own weight: it is what stops a refusal about somebody else's
       id, or a reworded sentence, from being acted on.

    ⚠ WHY THE FIRST CONDITION IS NOT OPTIONAL, AND WHY "an unrelated 422 that
    happens to quote an id back" WAS THE WRONG WAY ROUND. FastAPI's STOCK
    ``RequestValidationError`` handler puts the rejected value in ``input`` —
    for a list body, the whole event — so a capability refusal about a
    completely different unknown key comes back carrying our own live
    ``system_id`` verbatim. ``main._validation_error_handler`` strips that, and
    it only exists from 2026-08-25: EVERY older deployment echoes, and that
    population includes the frozen production one. So the coincidence is the
    DEFAULT, not the accident.

    What that cost was never lost evidence and never a false latch — the
    direction R3 reasoned about was right — it was a FALSE RECEIPT: a row
    stamped ``system_id_refused`` and an operator warning saying "retired or not
    declared" about a live, healthy system, on every batch, for as long as that
    backend runs. On a product whose claim is that its evidence is honest, that
    is the harm.

    ⚠ THE SHAPE CHECK IS NOT REDUNDANT WITH READING ``detail`` RATHER THAN THE
    WHOLE BODY, though it is close, and the distance is worth stating. Against
    the two shapes FastAPI itself produces — a list of error objects, redacted
    or echoing — ``spelling in detail`` is False anyway, because ``in`` over a
    list of dicts compares whole elements. What the check buys is every OTHER
    shape: a ``detail`` that is an object KEYED by the id, or a bare list OF
    ids, where membership WOULD match. Those come from a self-hosted error
    handler or a proxy, not from us, and "a shape we do not recognise" has to
    land on the older, coarser answer rather than on a guess.

    ⚠ FAIL SAFE, UNCHANGED IN DIRECTION. An unreadable body, a body that is not
    JSON, a body that is not an object, a ``detail`` that is not a string, or no
    id of ours inside it -> ``()`` -> the caller falls through to the ladder,
    strips endpoint-wide and latches, which is exactly what 1.13.0 did. Every
    way of being unsure lands on the older, coarser answer, so the worst case is
    never worse than the previous release.

    Returns the spellings in batch order, deduped.
    """
    if not _rejects_unsupported_fields(resp):
        return ()
    try:
        detail = json.loads(resp.text).get("detail")
    except Exception:                        # noqa: BLE001 — a body we cannot read
        return ()
    # A LIST is a pydantic validation error: the allowlist, or a value refusal.
    # Neither is about a particular system, and both can quote one back.
    if not isinstance(detail, str):
        return ()
    named = []
    for event in body:
        metadata = event.get("event_metadata")
        if not isinstance(metadata, dict):
            continue
        spelling = metadata.get("system_id")
        if (isinstance(spelling, str) and spelling not in named
                and spelling in detail):
            named.append(spelling)
    return tuple(named)


def _drop_attribution(body: list, spellings) -> list:
    """Remove ``system_id`` from the rows carrying ``spellings``; their indices.

    PER ROW, not per batch, which is the entire difference from
    :func:`_strip_provenance`. Ten events from a healthy system beside one from
    a system somebody retired last week must lose nothing, and the returned
    indices are what lets the receipt say so — a marker on a row it cannot be
    true of means nothing at all.
    """
    wanted = set(spellings)
    dropped = []
    for index, event in enumerate(body):
        metadata = event.get("event_metadata")
        if isinstance(metadata, dict) and metadata.get("system_id") in wanted:
            del metadata["system_id"]
            dropped.append(index)
    return dropped


def _rungs_in(event) -> tuple:
    """Which rungs this ONE event is carrying, in ladder order.

    Captured BEFORE anything is stripped, and intersected at ack time with what
    the batch actually lost. Both halves are needed: a row can carry a rung the
    batch never had to drop, and a batch can drop a rung this row never held.

    Per row rather than per batch because ``spool.ack`` writes one receipt to
    every row it is handed. A batch-wide flag stamped ``foxy_degraded`` onto
    clean observe rows that carried nothing — and a marker appearing on rows it
    cannot be true of means nothing at all.
    """
    metadata = event.get("event_metadata")
    if not isinstance(metadata, dict):
        return ()
    return tuple(name for name, keys, _why in _DEGRADE_LADDER
                 if any(key in metadata for key in keys))


def _strip_provenance(body: list, keys=_ALL_DEGRADE_KEYS) -> bool:
    """Remove ``keys`` in place; True if anything was actually removed.

    The return value is what makes each retry safe: if nothing was stripped, the
    resend would be byte-identical to the request that just failed, so the
    caller must not make it. That turns "retry" into a real bound rather than a
    comment, and it is what stops the escalation below spending a POST per rung
    on a batch that carries none of them.

    ``keys`` defaults to every key this module can drop, which is the question
    "what could we possibly remove?" rather than any one rung. The flush loop
    passes a single rung, because stripping more than the backend refused is how
    a typed-tag rejection came to cost unrelated rows their provenance.
    """
    removed = False
    for event in body:
        metadata = event.get("event_metadata")
        if not isinstance(metadata, dict):
            continue
        for key in keys:
            if metadata.pop(key, None) is not None:
                removed = True
    return removed


_DISPATCHER = AsyncDispatcher()


def submit(cfg: FoxyConfig, payload: dict, wait: bool = False):
    """Persist an event before returning; optionally wait for a server receipt."""
    return _DISPATCHER.submit(cfg, payload, wait=wait)


def resume(cfg: FoxyConfig) -> None:
    _DISPATCHER.resume(cfg)
