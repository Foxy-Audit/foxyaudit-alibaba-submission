"""Worker circuit-breaker + backoff on repeated Gemini failures (Phase 5 · 5E.2).

Pure logic (no DB): a Gemini outage makes whole grading batches fail; the breaker
trips OPEN so the poller stops hammering the API / burning attempts, backs off
with capped exponential delay, then half-opens for a trial.
"""

from __future__ import annotations

from app.worker import CircuitBreaker, backoff_ceiling, backoff_delay


def test_backoff_ceiling_is_capped_exponential():
    """The undithered curve. These exact values were asserted of backoff_delay
    itself until it grew jitter; they belong to the ceiling now, which is the
    part that genuinely has one right answer."""
    assert backoff_ceiling(0, 2.0, 60.0) == 2.0   # no failures → base poll interval
    assert backoff_ceiling(1, 2.0, 60.0) == 2.0
    assert backoff_ceiling(2, 2.0, 60.0) == 4.0
    assert backoff_ceiling(3, 2.0, 60.0) == 8.0
    assert backoff_ceiling(4, 2.0, 60.0) == 16.0
    assert backoff_ceiling(10, 2.0, 60.0) == 60.0  # capped


def test_backoff_delay_stays_inside_the_equal_jitter_band():
    """Half the ceiling fixed, half random — asserted as a PROPERTY over many
    draws, because an exact delay would only pin whichever constant was picked.

    Nothing is seeded: making this deterministic would mean making production
    deterministic, which removes the only thing jitter is for."""
    for failures in (0, 1, 2, 3, 4, 10):
        ceiling = backoff_ceiling(failures, 2.0, 60.0)
        draws = [backoff_delay(failures, 2.0, 60.0) for _ in range(200)]
        assert all(ceiling / 2.0 <= d <= ceiling for d in draws), (failures, draws[:5])


def test_the_floor_means_a_downed_judge_is_never_retried_immediately():
    """Why equal jitter and not full. Full jitter can draw ~0 and retry straight
    back into an outage, which here also burns a breaker failure and lengthens
    the NEXT wait beyond what the outage warrants."""
    draws = [backoff_delay(6, 2.0, 60.0) for _ in range(500)]
    assert min(draws) >= backoff_ceiling(6, 2.0, 60.0) / 2.0
    assert min(draws) > 0.0


def test_the_delay_actually_varies():
    """The point of the change. If this passes with one distinct value, the
    jitter is not there."""
    draws = {backoff_delay(5, 2.0, 60.0) for _ in range(200)}
    assert len(draws) > 100, f"only {len(draws)} distinct delays in 200 draws"


def test_growth_is_monotonic_even_though_each_draw_is_random():
    """A property that survives jitter: waiting longer after more failures is
    still true of the band, so a run of draws cannot trend downward."""
    lows = [backoff_ceiling(f, 2.0, 60.0) / 2.0 for f in range(0, 12)]
    assert lows == sorted(lows)
    assert lows[-1] == 30.0                       # the cap's floor, 60/2


def test_the_jitter_source_is_private_to_the_worker():
    """Anything else in this process calling random.seed() — a test helper, a
    dependency — must not be able to make the poller's delays reproducible. A
    deterministic jitter is not jitter."""
    import random

    from app import worker as workermod

    assert isinstance(workermod._jitter, random.Random)
    random.seed(4321)
    first = [backoff_delay(5, 2.0, 60.0) for _ in range(5)]
    random.seed(4321)
    assert [backoff_delay(5, 2.0, 60.0) for _ in range(5)] != first


def test_two_pollers_starting_together_do_not_stay_in_lockstep():
    """The fleet case, simulated. Fifty independent callers at the same failure
    count must not land on the same delay — that lockstep is what knocks a
    recovering backend straight over again."""
    fleet = [backoff_delay(8, 2.0, 60.0) for _ in range(50)]
    assert len(set(fleet)) >= 45
    spread = max(fleet) - min(fleet)
    assert spread > backoff_ceiling(8, 2.0, 60.0) / 4.0, \
        f"the fleet is bunched into {spread:.2f}s"


def test_breaker_opens_after_threshold():
    b = CircuitBreaker(threshold=3, cooldown=60.0)
    assert b.allow(now=0) is True
    b.on_failure(now=0)
    b.on_failure(now=1)
    assert b.allow(now=2) is True                 # 2 < threshold → still closed
    b.on_failure(now=3)                           # 3rd → opens
    assert b.allow(now=4) is False                # within cooldown → blocked
    assert b.allow(now=30) is False
    assert b.allow(now=63) is True                # cooldown elapsed → half-open trial


def test_breaker_success_closes_and_resets():
    b = CircuitBreaker(threshold=2, cooldown=60.0)
    b.on_failure(now=0)
    b.on_failure(now=1)                           # opens at 1
    assert b.allow(now=2) is False
    assert b.allow(now=61) is True                # half-open
    b.on_success()                                # trial passed → closed + reset
    assert b.allow(now=62) is True
    assert b.failures == 0


def test_breaker_reopens_when_trial_fails():
    b = CircuitBreaker(threshold=2, cooldown=60.0)
    b.on_failure(now=0)
    b.on_failure(now=1)                           # opens at 1
    assert b.allow(now=61) is True                # half-open trial
    b.on_failure(now=62)                          # trial failed → slides window to 62
    assert b.allow(now=63) is False
    assert b.allow(now=122) is True               # after another cooldown
