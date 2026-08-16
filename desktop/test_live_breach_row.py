"""The desktop console's LIVE breach row must not invent a risk score (#168).

``omni_fox`` fans the SDK bridge's ``policy_breach`` signal out to TWO
consumers — the fox's own popup and ``DashboardWindow.on_policy_breach``, which
appends a row to the live event table. Both read the same scoreless UDP payload,
so both had the same ``, 100)`` default and both displayed a graded-looking
number for an event nothing had graded.

The method is executed against a stand-in rather than source-sliced. A slice
would pass the moment someone moved the default one line out of the window it
happened to read, and this repo has been bitten by exactly that.
"""

from __future__ import annotations

import pytest

from dashboard import DashboardWindow

SDK_PING = {"event": "policy_breach", "policy": "hipaa",
            "reason": "prompt_injection", "decision": "blocked",
            "rules": ["injection.ignore_previous"]}


class _Console:
    """The attributes ``on_policy_breach`` actually touches, and nothing else.

    Not a ``SimpleNamespace``: a stub that silently grows whatever is asked of
    it cannot fail when the method starts reading something new. This one
    raises, so a new dependency shows up as a broken test rather than as a
    guard that quietly stopped covering the thing it names.
    """

    def __init__(self):
        self._logs_total = 0
        self._flagged_total = 0
        self.events: list[dict] = []
        self.refreshed = 0

    def _add_event(self, event):
        self.events.append(event)

    def _refresh_stats(self):
        self.refreshed += 1


def _fire(payload):
    console = _Console()
    DashboardWindow.on_policy_breach(console, payload)
    return console


def test_a_scoreless_sdk_breach_row_carries_no_risk():
    """THE DEFECT: this row used to claim risk 100."""
    console = _fire(SDK_PING)
    assert len(console.events) == 1
    assert console.events[0]["risk"] is None, "invented a score for the live row"


def test_the_row_still_records_the_breach_itself():
    """CONTROL. "No risk" must not have become "no row".

    Without this, deleting the whole method would satisfy the test above.
    """
    console = _fire(SDK_PING)
    event = console.events[0]
    assert event["kind"] == "breach"
    assert event["reason"] == "prompt_injection"
    assert event["policy"] == "hipaa"
    assert console.refreshed == 1

    # ⚠ THE COUNTERS PART SPLIT IN TWO, and this is the re-aim rather than a
    # relaxation. `_flagged_total` still rises: the guard really did stop
    # something, and "breaches stopped" is true whether or not the evidence has
    # been delivered. `_logs_total` no longer does: it drives the hero number,
    # which reads as interactions recorded IN THE LEDGER, and this event arrived
    # as a loopback datagram from a guard that — with no API key — never reaches
    # a ledger at all. The count could not correct itself either, because the
    # /v1/stats poll takes max(). See test_guard_bridge.py for the full case.
    assert console._flagged_total == 1, "a real block stopped being counted"
    assert console._logs_total == 0, \
        "a loopback ping is claiming a chain entry that may not exist"


def test_a_graded_row_still_shows_its_real_score():
    """A poller-graded payload genuinely has one, and must keep it."""
    console = _fire({"reason": "PHI", "policy": "hipaa", "risk_score": 82})
    assert console.events[0]["risk"] == 82


@pytest.mark.parametrize("value,expected", [(0, 0), ("55", 55), (None, None),
                                            ("", None), ("n/a", None)])
def test_zero_is_a_score_and_absent_is_not(value, expected):
    console = _fire({"reason": "x", "risk_score": value})
    assert console.events[0]["risk"] == expected


# ── the poller's emitted payload (the third site) ───────────────────────────
class _Client:
    """A FoxyClient stand-in returning one canned breach list."""

    def __init__(self, rows):
        self._rows = rows

    def request(self, method, path, timeout=None):
        return self._rows


def _emit(rows):
    """Run one real poll tick and collect what BreachPollWorker emitted.

    ``_poll_once`` is called unbound against a stand-in for the same reason as
    above — it is the LINE that carried the default, and a test of
    ``plan_reactions`` (which is what test_breach_poll.py covers) never sees it.
    That gap is why the poller's ``, 100)`` survived a suite of 834 tests.
    """
    from omni_fox import BreachPollWorker

    class _Worker:
        _cursor = 0
        _first_poll = False

        def __init__(self, rows):
            self._client = _Client(rows)
            self.emitted = []
            self.breach_detected = type("_Sig", (), {
                "emit": lambda _s, payload: self.emitted.append(payload)})()

    worker = _Worker(rows)
    BreachPollWorker._poll_once(worker)
    return worker.emitted


def test_a_backend_row_without_a_score_emits_no_score():
    """THE DEFECT on the poller path. A graded row normally HAS a score, so
    this default only fired when the backend omitted one — rarer than the SDK
    path, and rarer is worse, because it is the case nobody looks at."""
    emitted = _emit([{"seq": 1, "policy_tag": "hipaa", "reason": "tripped"}])
    assert len(emitted) == 1
    assert emitted[0]["risk_score"] is None, "the poller invented a score"


def test_a_normal_graded_row_still_carries_its_score():
    """CONTROL: the poller path is the one that usually DOES have a number."""
    emitted = _emit([{"seq": 1, "policy_tag": "hipaa",
                      "reason": "tripped", "risk_score": 90}])
    assert emitted[0]["risk_score"] == 90
    assert emitted[0]["reason"] == "tripped" and emitted[0]["policy"] == "hipaa"
