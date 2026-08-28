"""Register #244 — a worker thread must never touch the GUI thread's QSettings.

WHAT THIS IS ABOUT. `QSettings` is **reentrant, not thread-safe**: many
instances across many threads is fine, one instance across two threads is a
data race in C++. `FoxyClient.request()` runs on an `ApiWorker` thread and
reads the current backend URL and org key through
`FoxyClient._fresh_settings` → `FoxSettings.clone()`, so the clone happens on
the WORKER. Before this fix `clone()` asked the GUI thread's own store where it
pointed — `fileName()`, `format()`, `organizationName()`, `applicationName()` —
from that worker. Measured on this branch, at `9235b4e`, with the recorder
below:

    ini / file-backed store   -> 2 accessor calls crossed  (fileName, format)
    native / registry store   -> 4 accessor calls crossed  (all of them)

The app ships the native store, so production crossed all four on every
request. It is what aborted CI five times under #242 (`Fatal Python error:
Aborted`, then SIGSEGV, always with `ApiWorker` threads still inside
`fox_settings._respawn`), and #242's fix removed the SUITE's exposure by
blocking egress — not the product's. The real-user shape is unchanged: close
the console on a slow link with a request in flight, `shutdown_workers(
wait_ms=1500)` waits and cannot interrupt, and the worker outlives the window.

⚠ WHY THESE TESTS DRIVE A REAL THREAD INSTEAD OF READING THE SOURCE. A test
asserting "the snapshot has four fields" checks a token, not a behaviour, and
would stay green if the snapshot were taken lazily inside `clone()` — which is
the same bug with more code, because `clone()` IS the worker-thread call. So
the store is wrapped in a recorder that stamps every call with the thread that
made it, a real `QThread` performs the clone, and the assertion is about what
the GUI-owned object received. Each test also asserts the recorder saw the
main thread use that object, so none of them can pass on an empty scan.
"""

from __future__ import annotations

import threading

import pytest
from PyQt6.QtCore import QSettings, QThread

from fox_settings import APP, FoxSettings, ORG
from foxy_client import FoxyClient, MemorySecretStore

#: Every way `FoxSettings` reaches into the QSettings it was handed. The four
#: store-shape accessors are #244 proper; the value methods are here because
#: the invariant is about the OBJECT, not about one quartet of names — a
#: regression that shared the instance rather than re-reading its shape would
#: show up as `value`/`contains` crossing instead.
WATCHED = ("fileName", "format", "organizationName", "applicationName",
           "value", "contains", "setValue", "remove", "sync")

#: A registry/user-config location that is NOT the app's own
#: (`OmniAwareFox`/`DesktopPet`), so the native-format tests below cannot read
#: or damage a developer's real settings. Cleared again in a finally.
TEST_ORG, TEST_APP = "FoxyAuditTest244", "StoreShapeGuard"


class Recording(QSettings):
    """A QSettings that remembers WHICH THREAD made each call to it."""

    def _note(self, name):
        self.calls.append((name, threading.get_ident()))

    def start_recording(self):
        self.calls: list[tuple[str, int]] = []

    def fileName(self):
        self._note("fileName");         return super().fileName()

    def format(self):
        self._note("format");           return super().format()

    def organizationName(self):
        self._note("organizationName"); return super().organizationName()

    def applicationName(self):
        self._note("applicationName");  return super().applicationName()

    def value(self, *a, **k):
        self._note("value");            return super().value(*a, **k)

    def contains(self, *a, **k):
        self._note("contains");         return super().contains(*a, **k)

    def setValue(self, *a, **k):
        self._note("setValue");         return super().setValue(*a, **k)

    def remove(self, *a, **k):
        self._note("remove");           return super().remove(*a, **k)

    def sync(self, *a, **k):
        self._note("sync");             return super().sync(*a, **k)


@pytest.fixture(scope="module")
def app():
    # RETURNED, never dropped — the exit-127 rule pinned by test_qt_lifecycle.
    from PyQt6.QtWidgets import QApplication
    return QApplication.instance() or QApplication([])


@pytest.fixture(params=["ini", "native"])
def store(request, tmp_path, app):
    """The two shapes `_respawn` has to tell apart, both as recorders.

    `native` is the one the app actually ships (`QSettings(ORG, APP)` — the
    Windows registry, an XDG config file on Linux) and the one where all four
    accessors used to cross; `ini` is the shape every test in this tree
    injects. A fix that closed only one of them would close the wrong one.
    """
    if request.param == "ini":
        s = Recording(str(tmp_path / "guard.ini"), QSettings.Format.IniFormat)
        s.start_recording()
        yield s
        return
    s = Recording(TEST_ORG, TEST_APP)
    s.start_recording()
    try:
        yield s
    finally:
        s.clear()
        s.sync()


def _on_a_worker_thread(fn):
    """Run `fn` on a real QThread and return its result — the production shape.

    A `QThread`, not a `threading.Thread`, because that is what `ApiWorker` is
    and what the #242 faulthandler dumps named; the point of the test is the
    stack the crash actually had.
    """
    out = {}

    class Worker(QThread):
        def run(self):
            out["ident"] = threading.get_ident()
            try:
                out["value"] = fn()
            except BaseException as e:            # noqa: BLE001 — re-raised below
                out["error"] = e

    w = Worker()
    w.start()
    assert w.wait(20_000), "the worker thread never finished"
    if "error" in out:
        raise out["error"]
    return out["ident"], out["value"]


def _crossings(store, worker_ident):
    return [name for name, ident in store.calls if ident == worker_ident]


# ══ the defect ═════════════════════════════════════════════════════════════
def test_a_worker_cloning_never_touches_the_gui_threads_store(store):
    """THE regression test for #244, in the exact shape that crashed CI.

    Fails on `9235b4e`: `['fileName', 'format']` for the ini store and
    `['fileName', 'format', 'organizationName', 'applicationName']` for the
    native one."""
    settings = FoxSettings(store, MemorySecretStore())     # GUI thread owns it
    main_ident = threading.get_ident()

    worker_ident, twin = _on_a_worker_thread(settings.clone)

    assert worker_ident != main_ident, "the fixture did not use a real thread"
    assert _crossings(store, worker_ident) == [], (
        "a worker thread called these on the GUI thread's QSettings: "
        f"{_crossings(store, worker_ident)}")
    # ANTI-VACUITY: the recorder is wired up and the store WAS interrogated —
    # on the owning thread, at construction. Without this the assertion above
    # would also pass against a store nothing ever looked at.
    assert {name for name, ident in store.calls if ident == main_ident} >= {
        "fileName", "format", "organizationName", "applicationName"}, (
        "the snapshot was never taken on the owning thread")
    assert isinstance(twin, FoxSettings)


def test_a_worker_is_never_handed_the_instance_the_gui_thread_holds(store):
    """The other half: not merely 'no accessor calls' but 'not the object'.

    `_respawn`'s old `except Exception: return store` returned exactly this,
    and so would any fallback that re-introduced one."""
    settings = FoxSettings(store, MemorySecretStore())
    _worker_ident, twin = _on_a_worker_thread(settings.clone)
    assert twin._s is not store, "the clone shares one QSettings across threads"
    assert twin._secrets is settings._secrets, "the keychain client was rebuilt"


def test_the_credential_read_a_worker_actually_performs_stays_off_the_gui_store(store):
    """The whole production stack, not just its last frame.

    `ApiWorker.run` → `FoxyClient.request` → `_credentials` → `_fresh_settings`
    → `clone` → `_respawn` is the call chain the #242 dumps printed. Driving it
    end to end is what stops a fix that closes `clone()` while
    `_fresh_settings` quietly hands the shared object back on its own error
    path."""
    settings = FoxSettings(store, MemorySecretStore())
    settings.set_backend_url("https://cross-thread.example.test")
    settings.set_org_api_key("foxy_sk_crossthread")
    client = FoxyClient(settings)

    worker_ident, creds = _on_a_worker_thread(client._credentials)

    assert _crossings(store, worker_ident) == [], (
        "the credential read reached the GUI thread's QSettings: "
        f"{_crossings(store, worker_ident)}")
    # ...and it still read the RIGHT store, which is the thing a threading fix
    # is most likely to break on its way past.
    assert creds == ("https://cross-thread.example.test", "foxy_sk_crossthread")


# ══ the harm ordering the fix must not invert ══════════════════════════════
def test_the_clone_still_writes_through_to_the_same_store(store):
    """Same store, not a copy — for BOTH shapes.

    `_respawn`'s docstring ranks pointing at the WRONG store (data loss) above
    sharing one instance (a correctness risk). Snapshotting the shape must not
    quietly turn the fix into that data-loss bug, and the native branch — the
    app's own — is the one no other test in this tree covers."""
    settings = FoxSettings(store, MemorySecretStore())
    _ident, twin = _on_a_worker_thread(settings.clone)

    twin.set_backend_url("https://written-by-the-worker.test")
    twin._s.sync()
    store.sync()
    assert settings.backend_url() == "https://written-by-the-worker.test"


def test_the_native_store_is_reopened_by_organization_and_application(app):
    """The registry branch resolves by name, not by a guessed default.

    A snapshot that lost `organizationName()`/`applicationName()` would fall to
    `ORG`/`APP` and silently move a user's settings — green on the ini tests,
    which never take this branch."""
    from fox_settings import _respawn, _store_spec

    native = QSettings(TEST_ORG, TEST_APP)
    try:
        twin = _respawn(_store_spec(native))
        assert twin.organizationName() == TEST_ORG
        assert twin.applicationName() == TEST_APP
        assert twin.fileName() == native.fileName()
    finally:
        native.clear()
        native.sync()


def test_an_unidentifiable_store_still_resolves_to_the_apps_own(app):
    """The `Anything unrecognised` branch, unchanged: the app's real store, not
    the half-identified one it could not read."""
    from fox_settings import StoreSpec, _respawn

    twin = _respawn(StoreSpec("", QSettings.Format.IniFormat, "", ""))
    assert (twin.organizationName(), twin.applicationName()) == (ORG, APP)


def test_a_settings_double_that_is_not_a_qsettings_is_still_shared():
    """A test double has no C++ store to reopen and no threading rule to break.

    `_store_spec` returns None for it and `clone()` shares the instance —
    the same call `FoxyClient._fresh_settings` already makes for a settings
    object with no `clone()` at all."""
    from fox_settings import _store_spec

    class Bare:
        def fileName(self):
            raise AssertionError("a double must not be interrogated")

    double = Bare()
    assert _store_spec(double) is None
    settings = FoxSettings(double, MemorySecretStore())
    assert settings.clone()._s is double
