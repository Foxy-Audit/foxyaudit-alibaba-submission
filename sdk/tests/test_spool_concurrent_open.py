"""The spool must survive being opened from two threads at once (#169).

This is the SDK's normal steady state, not an exotic case: the decorator writes
the event on the caller's thread while ``dispatch``'s background thread flushes
the same spool. It surfaced as a ~20% flake in this suite — a different test
each run, always ``sqlite3.OperationalError: database is locked`` raised from
``EventSpool._connect`` — which is the shape of a race, not of a broken test.

The mechanism, measured rather than guessed:

* ``PRAGMA journal_mode=WAL`` is a journal-mode CHANGE, and a change is
  strictly more exclusive than an ordinary statement: it is blocked by any
  other connection holding even a SHARED READ lock, where a normal read or
  write only conflicts with a writer. It waits out the busy timeout and then
  fails. That is why only this one line ever failed while every ordinary
  statement on the same connection went through.
* The old ``_connect`` re-asserted WAL on EVERY connection, so every open was
  another chance to lose that race.
* The window is a file still in DELETE mode — i.e. a BRAND NEW spool, during
  ``_init_db``'s CREATE TABLE. Which is exactly what every test now gets, and
  what a customer gets on first run.

Measured on the old implementation with 8 threads x 40 fresh paths: 34/320
opens raised. On the current one: 0/320, and the file still ended in WAL in
40/40 rounds.
"""

from __future__ import annotations

import os
import sqlite3
import threading

import pytest

from foxy_audit.spool import EventSpool

THREADS = 8
ROUNDS = 10


def _open_concurrently(path: str, threads: int = THREADS) -> list[BaseException]:
    """Open ``threads`` EventSpools on one fresh path simultaneously.

    A Barrier rather than bare thread starts: without it the threads trickle in
    and the first one has usually finished ``_init_db`` — and set WAL — before
    the second arrives, so the contended window is never entered and the guard
    passes against the broken code.
    """
    barrier = threading.Barrier(threads)
    errors: list[BaseException] = []
    lock = threading.Lock()

    def worker():
        try:
            barrier.wait()
            EventSpool(path)          # __init__ -> _init_db -> _connect
        except BaseException as exc:  # noqa: BLE001 — the failure IS the result
            with lock:
                errors.append(exc)

    workers = [threading.Thread(target=worker) for _ in range(threads)]
    for t in workers:
        t.start()
    for t in workers:
        t.join()
    return errors


def test_concurrent_opens_of_a_fresh_spool_never_fail(tmp_path):
    """The regression itself."""
    errors: list[BaseException] = []
    for round_no in range(ROUNDS):
        path = str(tmp_path / f"r{round_no}" / "spool.sqlite3")
        errors.extend(_open_concurrently(path))
    assert not errors, (
        f"{len(errors)}/{THREADS * ROUNDS} concurrent opens failed; "
        f"first: {type(errors[0]).__name__}: {errors[0]}"
    )


def test_wal_is_actually_reached(tmp_path):
    """INERT CONTROL for the guard above.

    A ``_connect`` that simply stopped setting WAL would sail through the
    regression test — nothing would contend, because nothing would write. So
    pin the outcome the fix has to preserve: the file really is in WAL mode.
    Without this, "never fails" is satisfiable by doing nothing.
    """
    path = str(tmp_path / "spool.sqlite3")
    EventSpool(path)
    conn = sqlite3.connect(path)
    try:
        mode = conn.execute("PRAGMA journal_mode").fetchone()[0]
    finally:
        conn.close()
    assert mode.lower() == "wal", f"spool is in {mode!r}, not WAL"


def test_a_journal_mode_change_is_blocked_by_a_mere_READER():
    """CONTROL: the premise this fix rests on, asserted rather than assumed.

    The reason ``_connect`` reads before it writes is that a journal-mode
    CHANGE is blocked by a connection that only holds a SHARED read lock, while
    the READ of the same pragma is not. If SQLite ever relaxes that, the
    read-first dance stops being necessary and this test says so — before
    someone "simplifies" ``_connect`` back to one line, or after someone
    reintroduces the unconditional write.

    Note what this deliberately does NOT claim: under a permanently held
    EXCLUSIVE lock every statement fails alike, change and read and ordinary
    write. The asymmetry that matters is the reader case, so that is what is
    pinned here.
    """
    import tempfile

    path = os.path.join(tempfile.mkdtemp(), "probe.sqlite3")
    setup = sqlite3.connect(path)
    setup.execute("CREATE TABLE t(x)")
    setup.commit()
    setup.close()

    reader = sqlite3.connect(path)
    try:
        reader.execute("BEGIN")
        reader.execute("SELECT * FROM t").fetchall()      # holds a SHARED lock

        other = sqlite3.connect(path, timeout=2.0)
        try:
            other.execute("PRAGMA busy_timeout=2000")
            # The READ goes through — this is the statement the fix relies on.
            mode = other.execute("PRAGMA journal_mode").fetchone()[0]
            assert mode.lower() == "delete"
            # The CHANGE does not, blocked by nothing but that reader.
            with pytest.raises(sqlite3.OperationalError):
                other.execute("PRAGMA journal_mode=WAL")
        finally:
            other.close()
    finally:
        reader.close()
