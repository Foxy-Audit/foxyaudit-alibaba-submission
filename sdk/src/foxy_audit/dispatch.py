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
                    if stripped:
                        # RECORDED, not merely logged — and recorded LOCALLY, in
                        # the spool receipt, because it cannot ride on the wire:
                        # a marker key would itself be unknown to the very
                        # backend that just rejected an unknown key, so telling
                        # the ledger about the degradation would re-trigger the
                        # failure it describes.
                        by_marker = defaultdict(list)
                        for row, held in zip(batch, carried):
                            # What this row actually LOST: what it held, kept to
                            # what the batch dropped. A row carrying provenance
                            # in a batch where only the typed tag was stripped
                            # lost nothing and must not say it did.
                            by_marker[tuple(n for n in held
                                            if n in stripped)].append(row)
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

#: The client-supplied key sets a backend can refuse, as RUNGS: a name, the keys,
#: and the remedy to tell an operator. NEWEST FIRST, which is also
#: OLDEST-BACKEND-LAST, and that ordering is the whole reason escalating one rung
#: at a time terminates cheaply.
#:
#: ⚠ THE INGEST ALLOWLIST HAS ONLY EVER GROWN, so the sets a backend refuses
#: are NESTED: {} ⊂ {policy_tag_raw} ⊂ {policy_tag_raw, ruleset_*}. A backend
#: that knows ``policy_tag_raw`` (S12) necessarily knows the provenance keys
#: (1.7.0-era), because the second was allowlisted first. So stripping the newest
#: rung and re-probing finds the true boundary in at most one extra POST, and a
#: backend refusing nothing still pays exactly one.
#:
#: If that nesting were ever violated — a backend refusing the ruleset keys but
#: not the typed tag — this over-strips the typed tag for one retry window
#: rather than failing: rung 1 is applied, the 422 persists, rung 2 is applied,
#: the POST succeeds, and BOTH latch. Degraded and recorded, not broken. Stated
#: because it is the assumption the cheapness rests on, not a proof.
_DEGRADE_LADDER = (
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
