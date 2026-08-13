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
                    # WHICH ROWS actually carried provenance, captured before
                    # anything is stripped. `degraded` is a property of a ROW,
                    # not of the batch: `spool.ack` writes one receipt to every
                    # row it is given, so a single batch-wide flag stamped
                    # `foxy_degraded` onto clean observe rows that never carried
                    # provenance in the first place — and a marker that appears
                    # on rows it cannot be true of means nothing at all.
                    carried = [bool(_provenance_in(event)) for event in body]
                    # Already known to be an old backend: strip up front rather
                    # than spend a doomed request per batch for the rest of the
                    # process's life.
                    degraded = (_strip_provenance(body)
                                if _skips_provenance(endpoint) else False)
                    resp = self._post(endpoint, api_key, body)
                    if _rejects_unsupported_fields(resp) and _strip_provenance(body):
                        # A backend older than the release that learned these
                        # keys. Retry ONCE without them rather than lose the
                        # batch: ingest validates `payload: List[LogIngest]` as
                        # ONE unit, so this 422 rejects every event in the
                        # request, not just the guarded one. A provenance nicety
                        # must never cost a customer their audit trail, and a
                        # self-hosted or lagging deployment is not ours to
                        # sequence.
                        log.warning(
                            "foxy-audit: %s rejected ruleset provenance; resending "
                            "without it. Events are intact but carry no ruleset "
                            "version — upgrade the backend to restore it.", endpoint)
                        resp = self._post(endpoint, api_key, body)
                        # Only NOW, and only if dropping the keys is what fixed
                        # it. "unsupported fields" is the validator's message for
                        # ANY unknown key, so a backend rejecting something else
                        # entirely — one older than `policy_rules`, say — would
                        # otherwise disable provenance for the whole process
                        # while the actual offender went untouched and the batch
                        # kept failing.
                        if resp.status_code < 400:
                            degraded = True
                            _no_provenance[endpoint] = time.time()
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
                    if degraded:
                        # RECORDED, not merely logged — and recorded LOCALLY, in
                        # the spool receipt, because it cannot ride on the wire:
                        # a marker key would itself be unknown to the very
                        # backend that just rejected an unknown key, so telling
                        # the ledger about the degradation would re-trigger the
                        # failure it describes.
                        stripped_rows = [row for row, had in zip(batch, carried) if had]
                        intact_rows = [row for row, had in zip(batch, carried) if not had]
                        spool.ack(stripped_rows,
                                  dict(response, foxy_degraded=_DEGRADED_PROVENANCE))
                        spool.ack(intact_rows, response)
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


#: Endpoints observed to reject ruleset provenance, mapped to WHEN. Not
#: persisted, and not permanent either.
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

#: How long a rejection is trusted before the endpoint is probed again.
PROVENANCE_RETRY_AFTER = 900.0


def _skips_provenance(endpoint: str) -> bool:
    """Is this endpoint still within its "does not understand provenance" window?"""
    marked = _no_provenance.get(endpoint)
    if marked is None:
        return False
    if time.time() - marked >= PROVENANCE_RETRY_AFTER:
        _no_provenance.pop(endpoint, None)
        return False
    return True

_DEGRADED_PROVENANCE = "ruleset_provenance_stripped"


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


def _provenance_in(event) -> bool:
    """Does this ONE event carry ruleset provenance?

    Separate from :func:`_strip_provenance`, which answers the same question for
    a whole batch. The receipt marker is per-row, so it needs the per-row answer.
    """
    metadata = event.get("event_metadata")
    if not isinstance(metadata, dict):
        return False
    return any(key in metadata for key in ruleset.PROVENANCE_KEYS)


def _strip_provenance(body: list) -> bool:
    """Remove the ruleset keys in place; True if anything was actually removed.

    The return value is what makes the retry safe: if nothing was stripped, the
    resend would be byte-identical to the request that just failed, so the
    caller must not make it. That turns "retry once" into a real bound rather
    than a comment.
    """
    removed = False
    for event in body:
        metadata = event.get("event_metadata")
        if not isinstance(metadata, dict):
            continue
        for key in ruleset.PROVENANCE_KEYS:
            if metadata.pop(key, None) is not None:
                removed = True
    return removed


_DISPATCHER = AsyncDispatcher()


def submit(cfg: FoxyConfig, payload: dict, wait: bool = False):
    """Persist an event before returning; optionally wait for a server receipt."""
    return _DISPATCHER.submit(cfg, payload, wait=wait)


def resume(cfg: FoxyConfig) -> None:
    _DISPATCHER.resume(cfg)
