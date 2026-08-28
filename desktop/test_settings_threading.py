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
#: or damage a developer's real settings. Every value is cleared in a finally.
#: ⚠ On Windows an EMPTY `HKCU\Software\FoxyAuditTest244` container survives
#: the run: `QSettings.clear()` removes the keys it owns and Qt offers no way
#: to delete the organisation node above them. Harmless, and named here so
#: nobody mistakes it later for the app writing outside its own store.
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


class _DurableKeychain:
    """A keychain double that reports itself PERSISTENT, so the one-time
    QSettings-to-keychain migration in `_get_secret` actually runs."""

    persistent = True

    def __init__(self):
        self.data: dict[str, str] = {}

    def get(self, name):
        return self.data.get(name)

    def set(self, name, value):
        self.data[name] = value
        return True

    def delete(self, name):
        self.data.pop(name, None)

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

    ⚠ THIS ONE PASSES AGAINST 9235b4e AND IS NOT EVIDENCE OF THE DEFECT. It
    was first written claiming to guard `_respawn`'s old
    `except Exception: return store`, and it cannot: that arm only fired when
    an accessor RAISED, which a real QSettings never does, so pre-fix
    `_respawn` always returned a fresh instance and this assertion always held.
    What it guards is the forward direction — a future `clone()` that hands the
    worker the shared object (mutation M2) dies here. The guard that the
    fallback is gone for good is
    `test_respawn_is_not_given_a_store_and_so_cannot_return_one`, which does
    fail against 9235b4e."""
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
    app's own — is the one no other test in this tree covers.

    ⚠ THE WRITE HAPPENS ON THE WORKER, where the twin was born. An earlier
    version of this guard cloned on the worker and then wrote through that
    clone from the main thread, which is the very violation it exists to
    catch — one QSettings, two threads, with the roles reversed. The worker
    uses its own instance and the GUI thread reads through its own; that is the
    production shape and the only one this file should model."""
    settings = FoxSettings(store, MemorySecretStore())

    def write_from_the_worker():
        twin = settings.clone()
        twin.set_backend_url("https://written-by-the-worker.test")
        twin._s.sync()
        return twin.backend_url()

    _ident, seen_by_the_worker = _on_a_worker_thread(write_from_the_worker)

    assert seen_by_the_worker == "https://written-by-the-worker.test"
    store.sync()
    assert settings.backend_url() == "https://written-by-the-worker.test"


def test_a_clone_of_the_native_store_points_at_the_same_store(app):
    """The invariant that holds on every platform: the SAME store.

    ⚠ IT DOES NOT ASSERT `organizationName()`, AND THAT WAS A REAL BUG IN THIS
    FILE. Which branch of `_respawn` a NATIVE store takes is platform-decided:
    on Windows `fileName()` is `\\HKEY_CURRENT_USER\\...`, which the `\\HKEY`
    exclusion sends to the organisation/application branch, so the twin carries
    the org and app names. On Linux and macOS the same native store's
    `fileName()` is an ordinary path with `/` in it, so it takes the FILE
    branch — `QSettings(fileName, format)`, whose `organizationName()` is `""`.
    Both twins point at the same store, which is all `_respawn` promises; the
    earlier assertion mistook a Windows implementation detail for the contract
    and would have red-lighted CI, which runs ubuntu-latest.

    `fileName()` for the twin is read ON THE WORKER, because that is the thread
    that made it — this file must not model the violation it guards."""
    native = Recording(TEST_ORG, TEST_APP)
    native.start_recording()
    try:
        settings = FoxSettings(native, MemorySecretStore())
        worker_ident, twin_file = _on_a_worker_thread(
            lambda: settings.clone()._s.fileName())
        assert twin_file == native.fileName()
        assert _crossings(native, worker_ident) == []
    finally:
        native.clear()
        native.sync()


def test_the_windows_registry_branch_resolves_by_organization_and_application(app):
    """The branch the SHIPPED WINDOWS BUILD always takes — covered on every
    platform, on its merits.

    A platform skip alone would leave this untested exactly where CI runs:
    on Linux both the `ini` and the `native` fixture params resolve through the
    file branch, so the organisation/application branch would have no passing
    coverage at all. Driving `_respawn` with the spec Windows actually produces
    needs no registry and no Windows — the discrimination is string logic over
    a snapshot, which is the whole point of taking one.

    A snapshot that lost `organizationName()`/`applicationName()` would fall to
    `ORG`/`APP` here and silently move a user's settings."""
    from fox_settings import StoreSpec, _respawn

    windows_shape = StoreSpec(
        r"\HKEY_CURRENT_USER\Software\{0}\{1}".format(TEST_ORG, TEST_APP),
        QSettings.Format.NativeFormat, TEST_ORG, TEST_APP)
    twin = _respawn(windows_shape)
    assert (twin.organizationName(), twin.applicationName()) == (TEST_ORG, TEST_APP)


def test_a_posix_native_store_takes_the_file_branch_and_still_points_home(app):
    """The other half of the platform split, also driven from a snapshot.

    This is what CI's ubuntu-latest runner produces, asserted on a Windows
    developer machine: the file branch, reopened by path + format."""
    from fox_settings import StoreSpec, _respawn

    posix_shape = StoreSpec(
        "/home/runner/.config/{0}/{1}.conf".format(TEST_ORG, TEST_APP),
        QSettings.Format.NativeFormat, TEST_ORG, TEST_APP)
    twin = _respawn(posix_shape)
    assert twin.format() == QSettings.Format.NativeFormat
    # ...and NOT by org/app, which is exactly why the guard above cannot assert
    # `organizationName()` for a native store.
    assert twin.organizationName() == ""


def test_respawn_is_not_given_a_store_and_so_cannot_return_one(store):
    """The fallback is FORECLOSED, not merely unused — and this fails on 9235b4e.

    `_respawn`'s old `except Exception: return store` handed a worker the GUI
    thread's own QSettings on any failure. It is not enough that no current
    path reaches it: the repair is that `_respawn` is handed a `StoreSpec` and
    never holds a store at all, so the fallback is unwritable rather than
    unreached. Pre-fix, `_respawn(<a QSettings>)` is a perfectly ordinary call;
    here it cannot even be made."""
    from fox_settings import _respawn

    with pytest.raises(AttributeError):
        _respawn(store)


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


# ══ the same boundary, in the two workers that are not FoxyClient's ════════
# `ai_providers.call_ai` reads FOUR values off the FoxSettings it is handed —
# provider, key, model, url — and `api_key()` can also REMOVE a pre-keychain
# plaintext copy, so these threads read AND write. Measured at 4851957, before
# the fix: 4 `value()` calls crossed in each worker, plus a `remove()` on the
# legacy-key path.
#
# ⚠ NOTHING HERE REACHES THE NETWORK, and not by luck: the provider is `custom`
# with an empty base URL, so `_call_openai_compatible` raises "No endpoint URL
# configured" AFTER all four settings reads and BEFORE `requests.post`. That
# matters because `desktop/conftest.py` blocks egress at `urllib`, and
# `ai_providers` uses `requests` — it is not covered (register #243, item 1).

def _ai_probe_settings(store):
    """A FoxSettings whose provider cannot dial out. GUI thread owns it."""
    settings = FoxSettings(store, MemorySecretStore())
    settings.set_ai_provider("custom")
    settings.set_base_url("custom", "")
    return settings


def _run_ai_worker(worker, app):
    out = {}
    worker.failed.connect(lambda e: out.setdefault("failed", e))
    worker.succeeded.connect(lambda r: out.setdefault("succeeded", r))
    worker.start()
    assert worker.wait(20_000), "the AI worker never finished"
    app.processEvents()
    assert out.get("failed") == "No endpoint URL configured for this provider.", (
        f"the probe did not stop before the network: {out}")


def test_the_chat_worker_never_touches_the_gui_threads_store(store, app):
    """`clay_chat_popup._AICallWorker.run` — the chat popup's AI call."""
    from clay_chat_popup import _AICallWorker

    settings = _ai_probe_settings(store)
    store.start_recording()                     # GUI-side setup is done
    worker = _AICallWorker([{"role": "user", "content": "hi"}], "sys", settings)
    _run_ai_worker(worker, app)

    crossed = [name for name, ident in store.calls
               if ident != threading.get_ident()]
    assert crossed == [], f"the chat worker reached the GUI store: {crossed}"


def test_the_connection_test_worker_never_touches_the_gui_threads_store(store, app):
    """`settings_dialog._TestConnectionWorker.run` — the "Test connection"
    button, and the #244 crash shape at its sharpest: `SettingsDialog.done()`
    waits 600 ms while `ai_providers.TIMEOUT` is 30 s, so an unreachable
    provider outlives the dialog by up to fifty times the drain."""
    from settings_dialog import _TestConnectionWorker

    settings = _ai_probe_settings(store)
    store.start_recording()
    _run_ai_worker(_TestConnectionWorker(settings), app)

    crossed = [name for name, ident in store.calls
               if ident != threading.get_ident()]
    assert crossed == [], f"the connection test reached the GUI store: {crossed}"


def test_the_legacy_key_scrub_a_worker_performs_still_reaches_the_store(store, app):
    """The WRITE path, and the reason it did not need hoisting to the GUI thread.

    `api_key()` → `_get_secret` migrates a pre-keychain plaintext key into the
    keychain and then REMOVES the QSettings copy. That is a write, performed on
    a worker thread, and it is the one part of this repair where "just clone
    it" had to be argued rather than assumed. Two instances of QSettings over
    one store is the supported model — it is one instance over two threads that
    is the defect — and the scrub is idempotent, so two racing workers converge
    on the same state.

    What must not happen is the scrub silently becoming a no-op because it now
    writes through a clone the GUI thread never syncs. This drives it end to
    end: the plaintext copy is gone from the store, and the key reached the
    keychain."""
    # ⚠ A DURABLE keychain double, not `MemorySecretStore`. `_get_secret` only
    # removes the plaintext copy once the secret has landed in a PERSISTENT
    # store — `MemorySecretStore.persistent` is False, so with one of those the
    # scrub correctly never runs and this guard would test nothing. That rule
    # is `test_fox_settings.py`'s, and it is not this phase's to change.
    secrets = _DurableKeychain()
    settings = FoxSettings(store, secrets)
    settings.set_ai_provider("custom")
    settings.set_base_url("custom", "")
    store.setValue("ai/key/custom", "legacy-plaintext-key")
    store.sync()
    store.start_recording()

    from settings_dialog import _TestConnectionWorker
    _run_ai_worker(_TestConnectionWorker(settings), app)

    crossed = [name for name, ident in store.calls
               if ident != threading.get_ident()]
    assert crossed == [], f"the scrub reached the GUI store: {crossed}"
    store.sync()
    assert secrets.get("ai_key_custom") == "legacy-plaintext-key", (
        "the migration into the keychain stopped happening")
    assert not store.contains("ai/key/custom"), (
        "the plaintext copy survived — the scrub became a no-op through the clone")
