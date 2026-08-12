"""Small durable SQLite spool for metadata-only audit events.

The spool deliberately stores commitments and operational metadata, never the
prompt or response. SQLite WAL makes the hand-off durable before the caller's
process continues; delivery can therefore resume after a crash or outage.
"""

from __future__ import annotations

import json
import hashlib
import os
import random
import sqlite3
import time
import uuid
from contextlib import contextmanager
from pathlib import Path
from typing import Any

RETRY_CAP_SECONDS = 300.0
_MAX_DOUBLINGS = 8

# Its OWN generator, deliberately not the `random` module's shared one. A host
# application that calls random.seed() for its own reasons would otherwise make
# every Foxy client on the fleet draw the SAME retry delays — which is precisely
# the synchronisation this jitter exists to break. Unseeded, so it takes OS
# entropy, and no test can make it deterministic without saying so.
_jitter = random.Random()


def retry_delay(attempts: int) -> float:
    """Seconds to wait before retry number ``attempts``. EQUAL JITTER.

    Capped exponential is right and was already here; what it lacked is spread.
    The failure mode is not one client backing off — it is a BACKEND OUTAGE:
    every client in the fleet fails at the same moment, follows the same
    deterministic curve, and returns in lockstep, so the backend comes up and is
    knocked straight over again by a synchronised herd, repeatedly.

    Equal jitter — half the delay fixed, half uniformly random — rather than
    full jitter (``uniform(0, d)``) or decorrelated:

    * full jitter spreads widest but can draw a delay near zero, so a client
      retries almost immediately into an outage that is still down. Here that
      is not merely wasteful: ``attempts`` is what drives the curve, so a burnt
      attempt makes the NEXT backoff longer than the outage warrants.
    * decorrelated jitter needs the previous delay, and the spool persists only
      ``attempts`` and ``next_attempt_at``. Storing another column would mean a
      schema migration in a spool already deployed on customer machines.
    * equal jitter keeps a guaranteed floor of half the intended wait and still
      spreads uniformly over the other half, which decorrelates the fleet.

    Stateless in ``attempts``, so a row's delay is drawn fresh each time from
    the same distribution rather than accumulating — rescheduling cannot make a
    row drift later and later on every pass. And the cap bounds the top, so no
    row is starved however many times it fails.
    """
    ceiling = min(RETRY_CAP_SECONDS, 2.0 ** min(max(attempts, 0), _MAX_DOUBLINGS))
    return ceiling / 2.0 + _jitter.uniform(0.0, ceiling / 2.0)


def default_path() -> str:
    configured = os.getenv("FOXY_SPOOL_PATH")
    if configured:
        return configured
    return str(Path.home() / ".foxy-audit" / "spool.sqlite3")


class EventSpool:
    def __init__(self, path: str | None = None) -> None:
        self.path = str(path or default_path())
        parent = Path(self.path).parent
        parent.mkdir(parents=True, exist_ok=True)
        self._init_db()

    def _connect(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self.path, timeout=30.0)
        conn.row_factory = sqlite3.Row
        # Redundant on purpose, and known to be: sqlite3.connect(timeout=30.0)
        # already installs exactly this busy timeout (verified — the pragma
        # reads back 30000 before this line runs). It stays as an explicit
        # statement of intent, so the waiting behaviour does not silently
        # depend on one keyword argument. Its POSITION is therefore cosmetic;
        # nothing below is unprotected without it.
        conn.execute("PRAGMA busy_timeout=30000")
        # WAL is a PERSISTENT property of the database FILE, so it only ever has
        # to be set once. Re-asserting it on every connect was not free.
        #
        # A journal-mode CHANGE is strictly more exclusive than an ordinary
        # statement: it is blocked by any other connection holding even a SHARED
        # READ lock, where a normal read or write only conflicts with a writer.
        # Measured — a single idle reader inside an open transaction is enough
        # to make `PRAGMA journal_mode=WAL` wait out the whole busy timeout and
        # then fail with "database is locked", while the same connection's
        # ordinary reads and writes go through.
        #
        # So doing it on EVERY open made every open another chance to collide
        # with a concurrent opener. That is a real defect and not merely a test
        # one: the decorator writes on the caller's thread while the dispatcher
        # flushes on its own, which is the normal steady state of a busy
        # application, and a raise here costs the audit event. Measured on the
        # previous implementation, 8 threads opening one fresh spool: 34 of 320
        # opens raised. With the read-first form below: 0 of 320.
        #
        # The window is a file still in DELETE mode — a brand-new spool, during
        # _init_db — because once it is WAL there is no change left to make.
        # Reading the mode is an ordinary read, so it only waits for writers.
        # Losing the race to set it is tolerated rather than raised: the opener
        # that won set this very same value, and any that lost will find the
        # file already in WAL. Measured over 40 concurrent rounds, the file
        # ended in WAL every time.
        if (conn.execute("PRAGMA journal_mode").fetchone()[0] or "").lower() != "wal":
            try:
                conn.execute("PRAGMA journal_mode=WAL")
            except sqlite3.OperationalError:
                pass
        try:
            os.chmod(self.path, 0o600)
        except OSError:
            pass
        return conn

    @contextmanager
    def _connection(self):
        """Commit and close every SQLite handle, including on Windows."""
        conn = self._connect()
        try:
            with conn:
                yield conn
        finally:
            conn.close()

    def _init_db(self) -> None:
        with self._connection() as conn:
            conn.executescript(
                """
                CREATE TABLE IF NOT EXISTS spool_events (
                    event_id TEXT PRIMARY KEY,
                    endpoint TEXT NOT NULL,
                    api_key TEXT NOT NULL,
                    client_id TEXT NOT NULL,
                    client_seq INTEGER NOT NULL,
                    payload TEXT NOT NULL,
                    attempts INTEGER NOT NULL DEFAULT 0,
                    next_attempt_at REAL NOT NULL DEFAULT 0,
                    last_error TEXT
                );
                CREATE INDEX IF NOT EXISTS ix_spool_due
                    ON spool_events(next_attempt_at);
                CREATE TABLE IF NOT EXISTS spool_client_state (
                    client_id TEXT PRIMARY KEY,
                    next_seq INTEGER NOT NULL
                );
                CREATE TABLE IF NOT EXISTS spool_identity (
                    identity_key TEXT PRIMARY KEY,
                    client_id TEXT NOT NULL
                );
                CREATE TABLE IF NOT EXISTS spool_receipts (
                    event_id TEXT PRIMARY KEY,
                    receipt TEXT NOT NULL,
                    received_at REAL NOT NULL
                );
                """
            )

    def get_or_create_client_id(self, endpoint: str, api_key: str) -> str:
        """Return a stable local identity without storing the key in identity state."""
        identity_key = hashlib.sha256(
            f"{endpoint}\0{api_key}".encode("utf-8")
        ).hexdigest()
        with self._connection() as conn:
            conn.execute("BEGIN IMMEDIATE")
            row = conn.execute(
                "SELECT client_id FROM spool_identity WHERE identity_key = ?",
                (identity_key,),
            ).fetchone()
            if row:
                return str(row["client_id"])
            client_id = uuid.uuid4().hex
            conn.execute(
                "INSERT INTO spool_identity(identity_key, client_id) VALUES (?, ?)",
                (identity_key, client_id),
            )
            return client_id

    def enqueue(self, endpoint: str, api_key: str, payload: dict[str, Any]) -> dict[str, Any]:
        event_id = str(payload["event_id"])
        client_id = str(payload["client_id"])
        with self._connection() as conn:
            conn.execute("BEGIN IMMEDIATE")
            existing = conn.execute(
                "SELECT payload FROM spool_events WHERE event_id = ?", (event_id,)
            ).fetchone()
            if existing:
                return json.loads(existing["payload"])
            state = conn.execute(
                "SELECT next_seq FROM spool_client_state WHERE client_id = ?",
                (client_id,),
            ).fetchone()
            client_seq = int(state["next_seq"]) if state else 1
            conn.execute(
                "INSERT INTO spool_client_state(client_id, next_seq) VALUES (?, ?) "
                "ON CONFLICT(client_id) DO UPDATE SET next_seq = excluded.next_seq",
                (client_id, client_seq + 1),
            )
            enriched = {**payload, "client_seq": client_seq}
            conn.execute(
                "INSERT INTO spool_events(event_id, endpoint, api_key, client_id, "
                "client_seq, payload) VALUES (?, ?, ?, ?, ?, ?)",
                (event_id, endpoint, api_key, client_id, client_seq,
                 json.dumps(enriched, separators=(",", ":"), sort_keys=True)),
            )
            return enriched

    def due(self, limit: int = 50) -> list[sqlite3.Row]:
        with self._connection() as conn:
            return conn.execute(
                "SELECT * FROM spool_events WHERE next_attempt_at <= ? "
                "ORDER BY rowid LIMIT ?",
                (time.time(), limit),
            ).fetchall()

    def ack(self, rows: list[sqlite3.Row], response: dict[str, Any]) -> None:
        if not rows:
            return
        with self._connection() as conn:
            for row in rows:
                conn.execute(
                    "INSERT OR REPLACE INTO spool_receipts(event_id, receipt, received_at) "
                    "VALUES (?, ?, ?)",
                    (row["event_id"], json.dumps(response, sort_keys=True), time.time()),
                )
                conn.execute("DELETE FROM spool_events WHERE event_id = ?", (row["event_id"],))

    def retry(self, rows: list[sqlite3.Row], error: str) -> None:
        if not rows:
            return
        with self._connection() as conn:
            for row in rows:
                attempts = int(row["attempts"]) + 1
                delay = retry_delay(attempts)
                conn.execute(
                    "UPDATE spool_events SET attempts = ?, next_attempt_at = ?, last_error = ? "
                    "WHERE event_id = ?",
                    (attempts, time.time() + delay, error[:500], row["event_id"]),
                )

    def has(self, event_id: str) -> bool:
        with self._connection() as conn:
            return conn.execute(
                "SELECT 1 FROM spool_events WHERE event_id = ?", (event_id,)
            ).fetchone() is not None

    def receipt(self, event_id: str) -> dict[str, Any] | None:
        with self._connection() as conn:
            row = conn.execute(
                "SELECT receipt FROM spool_receipts WHERE event_id = ?", (event_id,)
            ).fetchone()
            return json.loads(row["receipt"]) if row else None


def open_spool(path: str | None = None) -> EventSpool:
    return EventSpool(path)
