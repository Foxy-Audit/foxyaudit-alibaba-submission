"""Desktop test harness — the one rule the suite could not enforce per-file.

⚠ WHY THIS FILE EXISTS: THE SUITE WAS CALLING PRODUCTION, AND IT CRASHED CI
===========================================================================
Register #242. Since T3 the `desktop-compile` job did not fail — it *died*,
`Fatal Python error: Aborted` (134) on three runs and `Segmentation fault`
(139) on two, always around 61%, and always blamed on whichever test happened
to be inside `QApplication.processEvents()` at the time. That test was innocent
every time. What the faulthandler dumps actually showed, on both signals, was
two or three `ApiWorker` threads still alive and deep inside
`foxy_client.request` → `_credentials` → `fox_settings.clone` → `_respawn`:

    Thread 0x…6c0:  fox_settings.py:59 in _respawn      <- QSettings(name, fmt)
                    foxy_client.py:500 in _fresh_settings
                    foxy_client.py:686 in run           <- ApiWorker.run
    Current thread: <invalid frame>                     <- main stack corrupt

Those threads belonged to consoles the tests had already CLOSED.
`FoxSettings.backend_url()` defaults to `https://app.foxyaudit.tech`, so every
`DashboardWindow` a test builds fires real requests at production — three from
`_refresh_announcement` alone. `dashboard.closeEvent` drains them with
`shutdown_workers(wait_ms=1500)`, which is best-effort by design, and a cold
DNS + TLS attempt from a CI runner does not fit in 1.5 s. So the worker
outlived its test, and went on calling Qt (`QSettings`, `_respawn`) from a
non-GUI thread while the next test hammered Qt from the main one. `QSettings`
is reentrant, not thread-safe: that is a real data race, and it corrupted the
heap somewhere the process could not survive.

⚠ THE FIX IS THE EGRESS, NOT THE THREADS. Blocking the network collapses a
worker's lifetime from ~10 s (the request timeout) to microseconds, so the
1.5 s drain that `closeEvent` already performs always completes and nothing
survives its test. It is also simply correct on its own: a unit suite that
talks to the live backend is a suite whose results depend on whether the VM is
up, and it was sending unauthenticated GETs to production on every CI run.

⚠ WHAT THIS DID NOT FIX — CLOSED SINCE, AND THE NOTE IS KEPT SO THE DIVISION
STAYS LEGIBLE. This file removed the SUITE's exposure. The PRODUCT's was
register #244: `FoxyClient._fresh_settings` -> `FoxSettings.clone()` ->
`fox_settings._respawn` read `fileName()`, `format()`, `organizationName()`
and `applicationName()` off the GUI thread's own `QSettings` from a worker,
and `_respawn`'s docstring admitted the hazard while performing it. Two more
workers did the same through `ai_providers.call_ai` —
`clay_chat_popup._AICallWorker` and `settings_dialog._TestConnectionWorker`,
the second of which also WROTE, via `api_key()`'s legacy-plaintext scrub.

All three now take `foxy_client.settings_for_worker(...)` on the worker
thread, and `FoxSettings` snapshots its store's shape at construction, on the
owning thread, so `_respawn` is handed a `StoreSpec` and never a store.
`test_settings_threading.py` drives each path on a real `QThread` against a
QSettings that stamps every call with the thread that made it. Every
`QThread` subclass in this tree was swept at that gate; only those three read
settings, and there is no `QRunnable`, `QThreadPool`, `moveToThread` or
`threading.Thread` anywhere in `desktop/`.

⚠ SO DO NOT READ THIS FILE AS THE ONLY THING STANDING BETWEEN THE SUITE AND A
SEGFAULT ANY MORE — but do not remove it either. It is independently correct
(a unit suite must not dial production), it is what keeps a worker's lifetime
in microseconds rather than seconds, and it does NOT cover `requests`, which
`ai_providers` uses — see register #243, item 1.

⚠ LOOPBACK STAYS OPEN. `test_foxy_client.py` drives a real `ThreadingHTTPServer`
on 127.0.0.1 and must keep working — that is the one place the suite is
*supposed* to speak HTTP, and it is the reason this guard filters by host
rather than replacing the opener wholesale.
"""

from __future__ import annotations

import time
import urllib.error
import urllib.request
from urllib.parse import urlsplit

import pytest

#: Hosts the suite may reach. Everything the desktop tests legitimately talk to
#: is a stub server this process started; anything else is somebody's real box.
LOOPBACK_HOSTS = frozenset({"localhost", "127.0.0.1", "::1"})

#: In the message of the URLError raised instead of the request. Asserted by
#: `test_no_egress.py`, which is why it is a name and not an inline literal.
BLOCKED_MARKER = "desktop/conftest.py blocked egress to"


def _host_of(fullurl) -> str:
    """The host `OpenerDirector.open` is about to dial, str or Request."""
    url = fullurl if isinstance(fullurl, str) else fullurl.full_url
    return (urlsplit(url).hostname or "").lower()


@pytest.fixture(autouse=True, scope="session")
def no_egress():
    """No desktop test may open a socket to anything but loopback.

    Patched on `OpenerDirector.open` rather than on `FoxyHttp`: the client
    builds its own opener with `build_opener`, `_mint_csrf` opens a second
    request straight off it, and a future caller would get no protection from a
    seam bolted onto one method. The class is the chokepoint all three share.
    """
    real_open = urllib.request.OpenerDirector.open

    def guarded_open(self, fullurl, *args, **kwargs):
        # ⚠ `*args`/`**kwargs`, NOT a re-declared signature. `open`'s third
        # parameter defaults to `socket._GLOBAL_DEFAULT_TIMEOUT`, and spelling
        # it `timeout=None` here would silently turn every stub-server call in
        # `test_foxy_client.py` into one that can block forever.
        host = _host_of(fullurl)
        if host not in LOOPBACK_HOSTS:
            raise urllib.error.URLError(f"{BLOCKED_MARKER} {host!r}")
        return real_open(self, fullurl, *args, **kwargs)

    urllib.request.OpenerDirector.open = guarded_open
    try:
        yield
    finally:
        urllib.request.OpenerDirector.open = real_open


@pytest.fixture(autouse=True)
def drain_posted_events():
    """Let the Qt event loop turn between tests. THE SUITE SEGFAULTS WITHOUT IT.

    ⚠ WHY: A UNIT SUITE NEVER CALLS `app.exec()`, SO POSTED EVENTS NEVER EXPIRE.
    Every `deleteLater()`, every `QTimer.singleShot`, and every signal a worker
    thread emits POSTS an event to the main thread's queue instead of running
    inline. In the shipped app the event loop turns constantly, so those land
    microseconds later while the objects that own them are still alive. Here
    nothing turned the loop unless a test happened to call `processEvents()`
    itself, so the queue accumulated across the whole run — and Python garbage-
    collected the objects behind those events long before anything delivered
    them. The first `processEvents()` after that walks into freed memory:

        QApplication.processEvents()
          QCoreApplicationPrivate::sendPostedEvents
            QObject::event(QEvent*)                <- a queued QMetaCallEvent
              PyQtSlotProxy::qt_metacall
                PyQtSlot::call
                  _PyEval_EvalFrameDefault         <- SIGSEGV

    (That stack is from gdb on a real core dump; faulthandler only ever printed
    `<invalid frame>`, because by then the stack is corrupt.)

    ⚠ THIS IS NOT ABOUT THE FILE THAT CRASHED, AND MEASURING THAT MATTERS.
    `test_settings_threading.py` sorts last and is the first thing late in the
    run that pumps, so it took the blame — but on ubuntu-latest, over five runs
    each:

        pytest desktop -q                                    SIGSEGV 5/5
        pytest desktop -q  --ignore=<that file>               SIGSEGV 0/5
        pytest desktop -q  --ignore=<that file>  + ONE pump   SIGSEGV 5/5
        pytest desktop -q  with this fixture                  SIGSEGV 0/5

    The third line is the one that settles it: the other 937 tests poison the
    queue EVERY TIME, and were green only because nothing pumped after them. A
    green run without this fixture is a latent one — any future test file
    sorting after them that touches the event loop dies the same way.

    ⚠ WINDOWS NEVER SEES IT and that is not luck: a use-after-free only crashes
    once the freed block is reused, which needs the allocation churn of a few
    hundred widget-building tests plus glibc's allocator. Local Windows runs
    961/1 green on the identical tree.

    ⚠ TEARDOWN OR SETUP MAKES NO DIFFERENCE, AND THAT IS MEASURED (#276). The
    `yield` below puts the pump at THIS test's teardown. Register #276 asked
    whether that placement is load-bearing, because moving it to the NEXT test's
    setup (dropping the `yield`) leaves all six of the lifecycle guards green and
    they therefore cannot tell the two apart. Measured in the container that
    reproduces the crash — `python:3.13-slim` plus the Qt libs from `ci.yml` AND
    `libfontconfig1 libfreetype6 libx11-6 libxext6 libxrender1 libglib2.0-0` —
    five runs each, exit status read from `subprocess.run(...).returncode` and
    every variant required to prove it EXECUTED before being scored:

        no pump at all                                       SIGSEGV 5/5
        pump at THIS test's teardown (as written)            SIGSEGV 0/5
        pump at the NEXT test's setup (no `yield`)           SIGSEGV 0/5

    ⚠ SO THE GUARDS ARE RIGHT AND THE ARGUMENT FOR TEARDOWN WAS NOT. What the
    fix rests on is that the loop TURNS BETWEEN TESTS — the first line of this
    docstring — and that is exactly what
    `test_qt_lifecycle.test_the_queue_was_drained_before_this_test_began` pins.
    It does NOT rest on the pump running while this test's objects are still
    alive; that reading is in the register, never in this file, and the
    measurement does not support it. **No guard was added for the placement.**
    Inventing one would pin a property that does not matter, which is the
    failure this file's own history is a catalogue of. Teardown stays because it
    also drains the LAST test in the run, which setup cannot.

    ONE pass, and that is measured rather than assumed. `settle()` below pumps
    twice because delivering a `DeferredDelete` can post another one, so a second
    pass looked obviously right here too — but the full suite is 0/5 either way,
    and a mutation that removed the second call could not be made to fail. An
    unguardable line that changes nothing is a line to delete.
    """
    yield
    from PyQt6.QtWidgets import QApplication      # imported here so a Qt-free
    app = QApplication.instance()                 # test never pays for it
    if app is not None:
        app.processEvents()


#: What `no_clipboard` hands every test in place of the machine's clipboard.
#: Named so a failure reads `_LocalClipboard`, which is the whole diagnosis.
class _LocalClipboard:
    """`QClipboard`, minus the operating system.

    Only what this tree actually calls: `setText` and `text`. Anything else a
    future call site needs (`setMimeData`, `clear`, the signals) is absent on
    purpose — an `AttributeError` naming the missing method is a better failure
    than a stub that silently accepts it and proves nothing.

    The type contract is PyQt6's, MEASURED rather than assumed, because a stub
    that is stricter than the real thing fails correct product code and one that
    is looser hides a bug:

        setText("x")   -> "x"
        setText(None)  -> ""          (PyQt6 maps None onto a null QString)
        setText(5)     -> TypeError   (and bytes, and list, and everything else)
    """

    def __init__(self):
        self._text = ""

    def setText(self, text, mode=None):
        if text is not None and not isinstance(text, str):
            raise TypeError(
                "setText(self, text: Optional[str], mode: QClipboard.Mode = "
                "QClipboard.Mode.Clipboard): argument 1 has unexpected type "
                f"'{type(text).__name__}'")
        self._text = text or ""

    def text(self, mode=None) -> str:
        return self._text


@pytest.fixture(autouse=True)
def no_clipboard(monkeypatch):
    """No desktop test may read or write the CLIPBOARD OF THE MACHINE IT RUNS ON.

    ⚠ REGISTER #281, AND THERE IS NO POLLUTER. `test_p3_orgid_stepup` does
    `QApplication.clipboard().setText("untouched")` and reads back `''` — on
    Windows, in the full suite, never alone. It was filed as an ordering bug:
    something earlier leaves the clipboard dirty. **No test does.** The Windows
    clipboard is not this process's to own, and the failure is a collision with
    whatever else is running on the box:

        QClipboard::setText -> OleSetClipboard -> CLIPBRD_E_CANT_OPEN
          (another process has it open) -> Qt DROPS its local copy, so `text()`
          falls through to OleGetClipboard and returns the REAL clipboard —
          `''` when it is empty.

    Measured three ways on this tree at `50afee9`:

        full suite, deterministic order, twice   the test PASSED both times
        a second process holding it open 3 s     `setText` reads back `''`,
          (`user32.OpenClipboard(NULL)`)           on demand, every time
        a probe after each of the 967 tests,     the clipboard broke and then
          twice                                    recovered mid-run, at a
                                                   DIFFERENT test each time —
                                                   once inside a file that sorts
                                                   AFTER the failing one, which
                                                   no polluter could manage

    The third row settles it. A test that leaves shared state dirty breaks at the
    SAME point every run and stays broken until something resets it; this opens
    and closes a window of a couple of tests wherever the other process happened
    to land. Windows-only because the offscreen QPA plugin CI runs under keeps
    clipboard data in-process and arbitrates with nobody.

    ⚠ SO THE SHARED STATE IS NOT RESTORABLE, AND THE FIX CANNOT BE A RESET.
    No fixture can restore what another process owns. The seam is the one
    `no_egress` above uses for the network, for the same reason: a unit suite
    must not depend on a resource the whole machine shares — and must not STOMP
    one either. This suite was overwriting the developer's real clipboard five
    times a run.

    ⚠ NOT A SKIP, AND NOT A LOOSENED ASSERTION. Every guard in
    `test_p3_orgid_stepup` still drives the real product method and still reads
    back what that method wrote; only the operating system is out of the loop.
    `test_clipboard_isolation.py` re-breaks this fixture from four directions.

    Patched on `QGuiApplication`, which is where PyQt6 defines `clipboard`
    (`"clipboard" in QApplication.__dict__` is False), so a `QGuiApplication`
    call site cannot slip past it. ONE instance per test, not one per call:
    `clipboard()` is called separately to write and to read, and a fresh object
    each time would make every read return `""` and every guard here vacuous.
    Per-test rather than per-session so one test's copy can never satisfy
    another's assertion — the hazard `test_p3_orgid_stepup.fresh` exists for.
    """
    from PyQt6.QtGui import QGuiApplication
    board = _LocalClipboard()
    monkeypatch.setattr(QGuiApplication, "clipboard", staticmethod(lambda: board))
    return board


#: Every worker set `DashboardWindow` tracks. Named here rather than spelled out
#: at each call site so a new one cannot be added to `closeEvent` and forgotten
#: by the tests that wait on it.
WORKER_SETS = ("_workers", "_poll_workers", "_ann_workers", "_home_workers",
               "_oneoff_workers", "_threat_workers", "_ledger_workers",
               "_page_workers", "_testbed_workers")


def running_workers(window) -> list:
    """The worker threads `window` is tracking that have not finished."""
    live = []
    for name in WORKER_SETS:
        for worker in tuple(getattr(window, name, ()) or ()):
            try:
                if worker.isRunning():
                    live.append(worker)
            except RuntimeError:
                pass                 # C++ object already deleted; not running
    return live


def settle(window, app, timeout_ms: int = 5000):
    """Pump the event loop until every worker `window` tracks has landed.

    ⚠ A TEST THAT INJECTS PAGE DATA AND THEN NAVIGATES IS RACING ITS OWN PAGE.
    `go(<page>)` fires that page's real fetch, and several handlers react to a
    failed one by hiding the panel they cannot vouch for —
    `dashboard._on_policy_failed` hides `pol_form` outright, which moves focus
    off whatever was inside it. Before egress was blocked that failure landed
    long after the test had finished; now it lands promptly, which is the
    ordering an offline machine always had. Draining it first makes the test
    about its assertion instead of about how fast the network is.
    """
    deadline = time.monotonic() + timeout_ms / 1000
    while time.monotonic() < deadline:
        app.processEvents()
        if not running_workers(window):
            app.processEvents()      # let the queued finished/deleteLater land
            return
    raise AssertionError(
        f"{len(running_workers(window))} worker(s) still running after "
        f"{timeout_ms} ms \u2014 the suite is reaching something real")
