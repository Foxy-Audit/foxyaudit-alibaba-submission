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

from conftest import BLOCKED_MARKER, LOOPBACK_HOSTS, running_workers
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


def test_a_closed_console_leaves_no_worker_thread_running(app, tmp_path):
    """The property the crash violated, stated directly.

    ⚠ AND IT IS ONLY TRUE BECAUSE THE EGRESS IS BLOCKED.
    `dashboard.closeEvent` drains through `shutdown_workers(wait_ms=1500)`,
    which is best-effort: with a real request in flight the wait expires and
    the thread walks out of the test still holding the closed window's
    `FoxyClient` and its GUI-thread `QSettings`. That is #242.
    """
    from PyQt6.QtCore import QSettings
    from dashboard import DashboardWindow
    from fox_settings import FoxSettings
    from foxy_client import MemorySecretStore

    store = QSettings(str(tmp_path / "console.ini"), QSettings.Format.IniFormat)
    console = DashboardWindow(settings=FoxSettings(store, MemorySecretStore()))
    try:
        console.show()
        console.go("home")
        app.processEvents()
    finally:
        console.close()
    app.processEvents()
    live = running_workers(console)
    assert live == [], (
        f"{len(live)} worker thread(s) outlived the console that owns them; "
        f"they keep calling QSettings off the GUI thread and the interpreter "
        f"does not always survive it")


@pytest.fixture(scope="module")
def app():
    from PyQt6.QtWidgets import QApplication
    # RETURNED, never dropped — see test_qt_lifecycle on exit 127.
    return QApplication.instance() or QApplication([])
