"""The spool's retry backoff, and why it needed jitter.

Capped exponential was already here and was already right. What it lacked is
SPREAD, and the failure mode is not one client backing off: on a backend outage
every client in the fleet fails at the same moment, follows the same
deterministic curve, and comes back in lockstep — so the backend recovers and is
knocked straight over again, repeatedly.

Asserted as PROPERTIES, over many draws and many simulated clients. An exact
delay would only pin whichever constant was picked. Nothing here seeds anything:
making the tests deterministic by making production deterministic would remove
the only thing jitter is for.

⚠ The fleet fixture is real spools doing real retries, not calls to the helper.
The delay that matters is the one that lands in next_attempt_at.
"""

from __future__ import annotations

import time

import pytest

from foxy_audit.spool import RETRY_CAP_SECONDS, EventSpool, retry_delay


def _spool(tmp_path, name="spool.sqlite3") -> EventSpool:
    return EventSpool(str(tmp_path / name))


#: The ceiling the curve actually reaches. RETRY_CAP_SECONDS is 300, but
#: `2 ** min(attempts, 8)` tops out at 256 first, so the seconds cap never
#: binds — true of this code before the jitter went in, and left alone rather
#: than "tidied", because raising the real ceiling to 300 would lengthen every
#: customer's worst-case backoff.
EFFECTIVE_CEILING = 256.0


def _enqueue(spool: EventSpool, event_id: str) -> None:
    spool.enqueue("http://127.0.0.1:9", "foxy_sk_test",
                  {"event_id": event_id, "client_id": "test-client",
                   "prompt_hash": "a" * 64, "response_hash": "b" * 64,
                   "token_count": 1, "policy_tag": "chat"})


# ── the helper's own shape ───────────────────────────────────────────────────
@pytest.mark.parametrize("attempts", [0, 1, 2, 3, 5, 8, 20])
def test_every_delay_lands_in_the_equal_jitter_band(attempts):
    ceiling = min(RETRY_CAP_SECONDS, 2.0 ** min(max(attempts, 0), 8))
    draws = [retry_delay(attempts) for _ in range(200)]
    assert all(ceiling / 2.0 <= d <= ceiling for d in draws), draws[:5]


def test_the_cap_is_respected_however_many_times_a_row_fails():
    """No row is starved: the top of the band is the cap, so a delay cannot grow
    without bound no matter how long the outage lasts."""
    for attempts in (8, 20, 100, 10_000):
        assert retry_delay(attempts) <= EFFECTIVE_CEILING


def test_there_is_always_a_floor_so_a_retry_never_fires_instantly():
    """Why equal jitter rather than full. Full jitter can draw ~0, and here a
    wasted attempt is not merely wasted — `attempts` is what drives the curve,
    so it lengthens the NEXT wait beyond what the outage warrants."""
    draws = [retry_delay(6) for _ in range(500)]
    assert min(draws) >= (2.0 ** 6) / 2.0
    assert min(draws) > 0.0


def test_the_band_grows_monotonically_with_attempts():
    """Monotonic-ish: sampled from the real distribution, so the floors are
    approached rather than hit. The claim is that waiting longer after more
    failures stays true and the curve never trends DOWNWARD — not that any
    particular draw equals any particular number."""
    lows = [min(retry_delay(a) for _ in range(300)) for a in range(0, 15)]
    for prev, nxt in zip(lows, lows[1:]):
        assert nxt >= prev * 0.9 - 0.01, (prev, nxt, lows)
    assert lows[-1] == pytest.approx(EFFECTIVE_CEILING / 2.0, rel=0.05)


def test_the_seconds_cap_is_inert_and_that_is_recorded_not_hidden():
    """RETRY_CAP_SECONDS is 300 but the doubling stops at 2**8 = 256, so the
    seconds cap never binds. Pinned so nobody "fixes" one constant believing the
    other is doing the work — and left as it is, because raising the real
    ceiling would lengthen every customer's worst-case wait."""
    assert RETRY_CAP_SECONDS == 300.0
    assert max(retry_delay(10_000) for _ in range(200)) <= EFFECTIVE_CEILING
    assert EFFECTIVE_CEILING < RETRY_CAP_SECONDS


def test_the_delay_actually_varies():
    """If this passes with one distinct value there is no jitter."""
    draws = {retry_delay(5) for _ in range(200)}
    assert len(draws) > 100, f"only {len(draws)} distinct delays in 200 draws"


# ── the property that matters: what lands in the database ────────────────────
def test_a_fleet_of_spools_does_not_reschedule_in_lockstep(tmp_path):
    """THE point. Sixty independent clients, each its own spool file, all
    failing the same delivery at the same moment — exactly a backend outage.

    Their next_attempt_at values must not coincide. Read out of SQLite rather
    than from retry_delay(), because the value that decides when the herd
    returns is the one that was persisted."""
    scheduled = []
    for i in range(60):
        spool = _spool(tmp_path, f"client-{i}.sqlite3")
        _enqueue(spool, f"11111111-1111-4111-8111-{i:012d}")
        rows = spool.due(10)
        assert rows, "the event should be due immediately on first delivery"
        spool.retry(rows, "connection refused")
        with spool._connection() as conn:
            scheduled.append(conn.execute(
                "SELECT next_attempt_at FROM spool_events").fetchone()[0])

    assert len(set(scheduled)) >= 55, \
        f"only {len(set(scheduled))} distinct wake-up times across 60 clients"
    spread = max(scheduled) - min(scheduled)
    assert spread > 0.25, f"the fleet is bunched into {spread:.3f}s"


def test_rescheduling_does_not_make_a_row_drift_later_every_pass(tmp_path):
    """The spool PERSISTS next_attempt_at, so jitter must be drawn fresh per
    scheduling rather than added on top of what is stored. Held at a fixed
    attempt count: if the delay accumulated, these would climb."""
    spool = _spool(tmp_path)
    _enqueue(spool, "22222222-2222-4222-8222-222222222222")
    deltas = []
    for _ in range(12):
        with spool._connection() as conn:
            conn.execute("UPDATE spool_events SET attempts = 4, next_attempt_at = 0")
        rows = spool.due(10)
        now = time.time()
        spool.retry(rows, "connection refused")
        with spool._connection() as conn:
            deltas.append(conn.execute(
                "SELECT next_attempt_at FROM spool_events").fetchone()[0] - now)

    # retry() stores attempts + 1, so the band pinned at attempts=4 is the one
    # for 5. Reading that off the stored value rather than assuming it is the
    # difference between a guard and a guess.
    ceiling = 2.0 ** 5
    assert all(ceiling / 2.0 <= d <= ceiling + 1.0 for d in deltas), deltas
    assert max(deltas) - min(deltas) < ceiling, "the delay is accumulating, not redrawn"
    assert deltas != sorted(deltas), \
        "twelve draws in ascending order is drift, not jitter"


def test_a_retried_row_is_still_delivered_eventually(tmp_path):
    """Bounded randomness, not unbounded: after its delay elapses the row comes
    back on the due list. Nothing is starved."""
    spool = _spool(tmp_path)
    _enqueue(spool, "33333333-3333-4333-8333-333333333333")
    spool.retry(spool.due(10), "connection refused")
    assert spool.due(10) == [], "the row should be waiting out its backoff"
    with spool._connection() as conn:
        conn.execute("UPDATE spool_events SET next_attempt_at = ?", (time.time() - 1,))
    assert len(spool.due(10)) == 1


def test_the_jitter_source_is_private_to_the_spool():
    """A host application calling random.seed() for its own reasons must not be
    able to make every Foxy client on the fleet draw the same delays — which is
    exactly the synchronisation this exists to break."""
    import random

    from foxy_audit import spool as spool_mod

    assert isinstance(spool_mod._jitter, random.Random)
    assert spool_mod._jitter is not random._inst if hasattr(random, "_inst") else True
    random.seed(1234)
    first = [retry_delay(5) for _ in range(5)]
    random.seed(1234)
    assert [retry_delay(5) for _ in range(5)] != first
