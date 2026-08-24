"""#242 — the desktop suite must not be able to reach anything but loopback.

The crash this guards against was not a failing assertion. It was
`Fatal Python error: Aborted` / `Segmentation fault` in CI, blamed on an
innocent test, caused by `ApiWorker` threads that outlived their test because
they were waiting on a real request to production. `desktop/conftest.py` has
the full account.

⚠ THESE GUARD THE PACKET, NOT THE MESSAGE. Asserting that the call raised
something with the right words in it would pass just as well against a
`FoxyHttp` that dialled the host first and only then complained — which is
exactly the failure being prevented, since the crash is caused by the DIAL,
not by the error. So both directions are measured at `socket.socket.connect`.
"""

from __future__ import annotations

import socket
import urllib.error

import pytest

from conftest import BLOCKED_MARKER, LOOPBACK_HOSTS
from foxy_client import ApiError, FoxyHttp


@pytest.fixture
def dialled(monkeypatch):
    """Every host:port this process actually opens a socket to."""
    seen = []
    real_connect = socket.socket.connect

    def spy(self, address):
        seen.append(address)
        return real_connect(self, address)

    monkeypatch.setattr(socket.socket, "connect", spy)
    return seen


def test_a_public_host_is_never_dialled(dialled):
    """The suite's own default: `FoxSettings.backend_url()` is
    `https://app.foxyaudit.tech`, so a console built by any test aims here."""
    http = FoxyHttp(base_url="https://app.foxyaudit.tech")
    with pytest.raises(ApiError) as caught:
        http.request("GET", "/v1/billing/plan", timeout=5)
    assert BLOCKED_MARKER in str(caught.value)
    assert dialled == [], (
        f"the suite opened a socket to {dialled} — the block reported a "
        f"failure it did not actually cause, and the worker thread that made "
        f"this call still lives as long as the network takes")


def test_the_retry_and_the_csrf_mint_are_blocked_too(dialled):
    """`_mint_csrf` opens a SECOND request straight off the opener, outside
    `request`'s try. A seam bolted onto `FoxyHttp.request` would leave it
    dialling; this one cannot, because it sits on the opener itself."""
    http = FoxyHttp(base_url="https://app.foxyaudit.tech")
    http._mint_csrf(5)                       # swallows everything, by design
    assert dialled == [], f"_mint_csrf dialled {dialled}"


def test_loopback_is_still_reachable(dialled):
    """`test_foxy_client.py` drives a real HTTP server on 127.0.0.1. Blocking
    that would trade one broken suite for another, so the guard has to prove
    the allowed direction as well as the refused one.

    Nothing is listening on the port, so the *connect* is what is measured:
    the call must get as far as the socket and be refused by the OS, not be
    turned away by the conftest."""
    with socket.socket() as probe:           # an ephemeral port, then closed
        probe.bind(("127.0.0.1", 0))
        dead_port = probe.getsockname()[1]
    http = FoxyHttp(base_url=f"http://127.0.0.1:{dead_port}")
    with pytest.raises(ApiError) as caught:
        http.request("GET", "/v1/billing/plan", timeout=5)
    assert BLOCKED_MARKER not in str(caught.value), \
        "loopback was refused by the conftest — the stub-server tests cannot run"
    assert [a for a in dialled if a[0] == "127.0.0.1"], \
        "loopback never reached the socket layer at all"


def test_the_allowlist_is_loopback_and_nothing_else():
    """A hostname added here is a hostname the suite may talk to for real."""
    assert set(LOOPBACK_HOSTS) == {"localhost", "127.0.0.1", "::1"}


def test_a_request_finishes_inside_the_drain_its_window_would_give_it(dialled):
    """The property #242 violated, measured where it broke.

    `dashboard.closeEvent` hands every tracked worker to `shutdown_workers`,
    which waits and CANNOT interrupt — best-effort by design. So the only
    thing keeping a worker from walking out of the test that owns it is the
    work being shorter than that wait, and the work is short only because
    nothing it does reaches the network. A worker that outlives its window
    goes on reading a GUI-thread `QSettings` from a worker thread, and that is
    what corrupted the heap.

    ⚠ BOTH HALVES ARE MEASURED, because either alone is satisfiable by
    accident: a warm connection also comes back inside 1.5 s, which is exactly
    how this stayed invisible on the dev machine for four merges. So the clock
    is asserted AND the socket that must never open.

    ⚠ AND IT RUNS NO QThread. The first version of this guard spawned a real
    `ApiWorker` and was itself CI's next segfault, twice: `spawn_worker` with
    no `parent` leaves the QThread owned by Python, `finished` posts a
    `deleteLater()`, and the wrapper is collected at end of test while that
    event is still queued. The request is the subject; the thread was scenery
    that could only add a second way to crash.
    """
    import inspect
    import time

    from foxy_client import shutdown_workers

    # Read from the code, not typed in: `closeEvent` calls `shutdown_workers`
    # with no `wait_ms`, so the default IS the budget, and a guard holding its
    # own copy of it would go quietly stale the day someone changed it.
    budget_ms = inspect.signature(shutdown_workers).parameters["wait_ms"].default

    http = FoxyHttp(base_url="https://app.foxyaudit.tech")
    started = time.monotonic()
    with pytest.raises(ApiError):
        # `timeout=10` is `_refresh_announcement`'s own, three times per window.
        http.request("GET", "/v1/billing/plan", timeout=10)
    elapsed_ms = (time.monotonic() - started) * 1000

    assert elapsed_ms < budget_ms, (
        f"a console request took {elapsed_ms:.0f} ms against a {budget_ms} ms "
        f"drain — the worker running it outlives the window that owns it")
    assert dialled == [], f"the request dialled {dialled} — see the docstring"
