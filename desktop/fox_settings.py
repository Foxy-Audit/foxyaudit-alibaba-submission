"""
Persistent settings layer for the Foxy Audit desktop app.

FoxSettings wraps QSettings (OS-native storage: registry / plist / .ini) with
typed getters.  Design tokens / fonts / QSS live in foxy_tokens.py — the one
design source — not here.

Secrets (the org API key and per-provider AI keys) are stored in the OS
keychain via foxy_client's secret store, NEVER in QSettings.  Values written
by older builds into QSettings are migrated to the keychain on first read and
removed from QSettings.

Window geometry (pet position, console position/size, chat size) persists
under the geometry/* keys — plain coordinates, no secrets.
"""

from __future__ import annotations

import json
from collections import namedtuple

from PyQt6.QtCore import QByteArray, QPoint, QSettings, QSize

from foxy_client import default_secret_store
from foxy_tokens import resource_path  # noqa: F401  (legacy import site: `from fox_settings import resource_path`)

ORG = "OmniAwareFox"
APP = "DesktopPet"


# ─────────────────────────────────────────────────────────── AI providers ──
AI_PROVIDERS = ["anthropic", "openai", "ollama", "lmstudio", "custom"]

PROVIDER_DEFAULTS = {
    "anthropic": {"base_url": "https://api.anthropic.com/v1/messages",       "model": "claude-sonnet-4-6",  "local": False},
    "openai":    {"base_url": "https://api.openai.com/v1/chat/completions",   "model": "gpt-4o-mini",        "local": False},
    "ollama":    {"base_url": "http://localhost:11434/api/chat",               "model": "llama3",             "local": True},
    "lmstudio":  {"base_url": "http://localhost:1234/v1/chat/completions",     "model": "local-model",        "local": True},
    "custom":    {"base_url": "",                                              "model": "",                   "local": False},
}


#: Where a store points, as four plain values — everything `_respawn` needs and
#: nothing that belongs to a thread. Read ONCE, by `FoxSettings.__init__`, on
#: whichever thread built the store, then carried to workers as data.
StoreSpec = namedtuple("StoreSpec", "file_name format organization application")


def _store_spec(store) -> "StoreSpec | None":
    """Snapshot where `store` points — ON THE CALLING THREAD.

    ⚠ The four accessors below are the whole of register #244. `QSettings` is
    reentrant across INSTANCES, not one instance across threads, so asking a
    store where it points is only safe from the thread that owns it. This
    function exists so that question is asked exactly once, at construction,
    and never again from a worker.

    Returns None for anything that is not a real `QSettings` — a test double
    has no C++ store to reopen and no threading rule to break, so `clone()`
    shares it, exactly as `FoxyClient._fresh_settings` already does for a
    settings object that has no `clone()` at all.
    """
    if not isinstance(store, QSettings):
        return None
    return StoreSpec(store.fileName(), store.format(),
                     store.organizationName(), store.applicationName())


def _respawn(spec: StoreSpec) -> QSettings:
    """A second QSettings pointing at the SAME place `spec` was taken from.

    Two shapes to cover, and getting either wrong sends the copy somewhere
    else entirely: a file-backed store (what tests inject — an ini path) is
    reopened by `fileName()` + `format()`, and the app's own registry/native
    store is reopened by its organization and application names. Anything
    unrecognised still resolves to the app's OWN store rather than to a
    half-identified one, because pointing at the WRONG store is a data-loss
    risk — that ordering of harms is unchanged from the version this replaces,
    and so is every branch below it.

    ⚠ THERE IS DELIBERATELY NO `except Exception: return store` HERE, AND THAT
    IS THE FIX. The old fallback existed because this decision was made from
    LIVE accessor calls: a store that raised left nothing to go on, and a
    guessed default would have written the user's settings somewhere else. It
    ranked that data-loss risk above the correctness risk of sharing one
    instance across threads — a fair ranking, but it made the crash the
    DEFAULT outcome of any failure. Reading the shape on the owning thread
    removes both horns at once: the shape is already known, so nothing here
    can misidentify it, and this function is no longer HANDED the shared
    instance, so it cannot return it. Handing that instance to a worker was
    never a fallback; it is the crash (#244, and the five CI aborts of #242).
    """
    name, fmt = spec.file_name, spec.format
    if fmt in (QSettings.Format.IniFormat, QSettings.Format.NativeFormat) \
            and name and ("/" in name or "\\" in name) \
            and not name.startswith("\\HKEY"):
        return QSettings(name, fmt)
    return QSettings(spec.organization or ORG, spec.application or APP)


# ────────────────────────────────────────────────────────── FoxSettings ──
class FoxSettings:
    """Typed convenience wrapper around QSettings.
    Safe to instantiate many times — QSettings is cheap."""

    def __init__(self, settings: QSettings | None = None, secrets=None):
        # `settings`/`secrets` are injection seams for tests: without them a
        # test run reads AND writes the user's real store (HKCU\Software\
        # OmniAwareFox\DesktopPet on Windows), which both pollutes their app
        # and makes the suite order-dependent.
        self._s = settings if settings is not None else QSettings(ORG, APP)
        self._secrets = secrets if secrets is not None else default_secret_store()
        # ⚠ HERE, and never lazily inside `clone()`. `clone()` is called from
        # `FoxyClient._fresh_settings` ON A WORKER THREAD, so a snapshot taken
        # there would run `_store_spec`'s four accessors against the GUI
        # thread's own QSettings — which IS the defect (#244), only written out
        # more carefully. `__init__` is the one moment the object is provably
        # unshared: nothing can hold a reference to a FoxSettings that has not
        # finished being constructed, so whichever thread runs this line is the
        # thread that owns `self._s`. In the app that is the GUI thread — every
        # production construction site is a widget constructor (omni_fox.py,
        # dashboard.py, clay_chat_popup.py, settings_dialog.py, auth_windows.py)
        # — and in a clone it is the worker, whose QSettings was built one line
        # earlier on that same thread. Either way the owner is the reader.
        self._spec = _store_spec(self._s)

    def clone(self) -> "FoxSettings":
        """A same-store copy with its own QSettings, for another thread.

        `FoxyClient._fresh_settings` needs a fresh QSettings per worker thread
        — QSettings is reentrant across INSTANCES, not one instance across
        threads — and used to get it with `type(self.settings)()`, which
        rebuilds `FoxSettings` **with no arguments** and so silently drops both
        injection seams. The consequence was not theoretical: every credential
        read on a worker thread went to the developer's real keychain and real
        `HKCU\\Software\\OmniAwareFox`, and the tests only agreed because the
        injected store and the real one happened to resolve the same default
        URL. A test that reads a live secret is both a lie and a hazard.

        The QSettings is genuinely new (that is the point); the SECRET store is
        carried over by reference, because a keychain client is not the thing
        QSettings' threading rule is about and re-creating it per request would
        mean a keyring round trip on every call.

        ⚠ This runs ON THE CALLING (worker) THREAD and touches `self._s` not at
        all — only `self._spec`, four immutable values read at construction by
        the thread that owns the store. That is the whole of #244's repair:
        `_respawn` is handed DATA, never the GUI thread's object.
        """
        if self._spec is None:
            # Not a QSettings — a test double. Nothing to reopen, and no
            # threading rule to break, so sharing the instance is honest.
            return type(self)(self._s, self._secrets)
        return type(self)(_respawn(self._spec), self._secrets)

    # ── secret plumbing (keychain-first, one-time migration from QSettings) ──
    # The legacy QSettings copy is removed ONLY when the secret has landed in a
    # PERSISTENT store (the real keychain).  The in-memory fallback store also
    # reports set()=True, but destroying the only durable copy after migrating
    # into process memory would lose the key on the next launch.
    def _durable(self) -> bool:
        return getattr(self._secrets, "persistent", False)

    def _get_secret(self, name: str, legacy_key: str) -> str:
        val = self._secrets.get(name)
        if val:
            if self._durable() and self._s.contains(legacy_key):
                self._s.remove(legacy_key)  # scrub any stale plaintext copy
            return val
        legacy = self._s.value(legacy_key, "", type=str)
        if legacy:
            if self._secrets.set(name, legacy) and self._durable():
                self._s.remove(legacy_key)
            return legacy
        return ""

    def _set_secret(self, name: str, legacy_key: str, value: str) -> bool:
        """Store (or clear) a secret. Returns False when the keychain refused
        the write — the caller MUST surface that, because the value is not
        persisted and we never fall back to plaintext QSettings."""
        value = value or ""
        if value:
            stored = self._secrets.set(name, value)
            if stored and self._durable():
                self._s.remove(legacy_key)
            # A non-durable store (no keychain backend) holds the value only in
            # process memory — report that as a failure to persist.
            return bool(stored and self._durable())
        self._secrets.delete(name)
        self._s.remove(legacy_key)
        return True

    # ── AI provider / keys ──
    def ai_provider(self) -> str:
        return self._s.value("ai/provider", "anthropic", type=str)

    def set_ai_provider(self, provider: str):
        self._s.setValue("ai/provider", provider)

    def is_local_provider(self, provider: str | None = None) -> bool:
        provider = provider or self.ai_provider()
        return PROVIDER_DEFAULTS.get(provider, {}).get("local", False)

    def api_key(self, provider: str | None = None) -> str:
        provider = provider or self.ai_provider()
        return self._get_secret(f"ai_key_{provider}", f"ai/key/{provider}")

    def set_api_key(self, provider: str, key: str) -> bool:
        return self._set_secret(f"ai_key_{provider}", f"ai/key/{provider}", key)

    def model(self, provider: str | None = None) -> str:
        provider = provider or self.ai_provider()
        default = PROVIDER_DEFAULTS.get(provider, {}).get("model", "")
        return self._s.value(f"ai/model/{provider}", default, type=str)

    def set_model(self, provider: str, model: str):
        self._s.setValue(f"ai/model/{provider}", model)

    def base_url(self, provider: str | None = None) -> str:
        provider = provider or self.ai_provider()
        default = PROVIDER_DEFAULTS.get(provider, {}).get("base_url", "")
        return self._s.value(f"ai/url/{provider}", default, type=str)

    def set_base_url(self, provider: str, url: str):
        self._s.setValue(f"ai/url/{provider}", url)

    # ── Foxy Audit platform ──
    def org_api_key(self) -> str:
        return self._get_secret("org_api_key", "foxy/org_key")

    def set_org_api_key(self, key: str) -> bool:
        return self._set_secret("org_api_key", "foxy/org_key", key)

    def backend_url(self) -> str:
        return self._s.value("foxy/backend_url", "https://app.foxyaudit.tech", type=str)

    def set_backend_url(self, url: str):
        self._s.setValue("foxy/backend_url", url)

    def web_dashboard_url(self) -> str:
        """The browser dashboard (site 2), distinct from the desktop console."""
        return self._s.value("foxy/web_dashboard_url",
                             "https://app.foxyaudit.tech/dashboard", type=str)

    def set_web_dashboard_url(self, url: str):
        self._s.setValue("foxy/web_dashboard_url", url)

    # ── behaviour tuning ──
    def reaction_cooldown(self) -> float:
        return self._s.value("behavior/cooldown", 4.0, type=float)

    def set_reaction_cooldown(self, seconds: float):
        self._s.setValue("behavior/cooldown", seconds)

    def pat_sensitivity(self) -> int:
        return self._s.value("behavior/pat_sensitivity", 18, type=int)

    def set_pat_sensitivity(self, value: int):
        self._s.setValue("behavior/pat_sensitivity", value)

    def roaming_enabled(self) -> bool:
        return self._s.value("behavior/roam", False, type=bool)

    def set_roaming_enabled(self, value: bool):
        self._s.setValue("behavior/roam", value)

    def proximity_glance_enabled(self) -> bool:
        return self._s.value("behavior/glance", True, type=bool)

    def set_proximity_glance_enabled(self, value: bool):
        self._s.setValue("behavior/glance", value)

    # ── companion catalogue (D13 · plan §9.2) ──
    # Every default below is what the app ALREADY did before the control
    # existed, so adding the settings changes nothing until someone moves one.
    # The two exceptions are called out where they appear.
    #
    # `alerts/*` keys live further down with the D12 batch; startup lives in
    # the OS (see `autostart.py`) and deliberately has no key here — a copy
    # would go stale the moment the user revoked it elsewhere.
    def start_hidden(self) -> bool:
        return self._s.value("startup/hidden", False, type=bool)

    def set_start_hidden(self, value: bool):
        self._s.setValue("startup/hidden", bool(value))

    def open_console_on_launch(self) -> bool:
        return self._s.value("startup/open_console", False, type=bool)

    def set_open_console_on_launch(self, value: bool):
        self._s.setValue("startup/open_console", bool(value))

    def close_to_tray(self) -> bool:
        """The close button hides rather than quits. True is what the app did:
        `setQuitOnLastWindowClosed(False)` plus a tray icon."""
        return self._s.value("startup/close_to_tray", True, type=bool)

    def set_close_to_tray(self, value: bool):
        self._s.setValue("startup/close_to_tray", bool(value))

    def fox_scale(self) -> int:
        from companion_prefs import SCALE_DEFAULT, SCALE_MAX, SCALE_MIN
        raw = self._s.value("fox/scale", SCALE_DEFAULT, type=int)
        return max(SCALE_MIN, min(SCALE_MAX, raw))

    def set_fox_scale(self, percent: int):
        self._s.setValue("fox/scale", int(percent))

    def fox_opacity(self) -> int:
        from companion_prefs import OPACITY_DEFAULT, OPACITY_MAX, OPACITY_MIN
        raw = self._s.value("fox/opacity", OPACITY_DEFAULT, type=int)
        return max(OPACITY_MIN, min(OPACITY_MAX, raw))

    def set_fox_opacity(self, percent: int):
        self._s.setValue("fox/opacity", int(percent))

    def always_on_top(self) -> bool:
        return self._s.value("fox/always_on_top", True, type=bool)

    def set_always_on_top(self, value: bool):
        self._s.setValue("fox/always_on_top", bool(value))

    def roam_speed(self) -> int:
        """Pixels per roam tick. 2 is what `_roaming_tick` hard-coded."""
        return max(1, min(6, self._s.value("behavior/roam_speed", 2, type=int)))

    def set_roam_speed(self, value: int):
        self._s.setValue("behavior/roam_speed", int(value))

    def idle_break_frequency(self) -> str:
        from companion_prefs import DEFAULT_FREQUENCY
        return self._s.value("behavior/idle_freq", DEFAULT_FREQUENCY, type=str)

    def set_idle_break_frequency(self, key: str):
        self._s.setValue("behavior/idle_freq", str(key))

    def tip_frequency(self) -> str:
        from companion_prefs import DEFAULT_FREQUENCY
        return self._s.value("behavior/tip_freq", DEFAULT_FREQUENCY, type=str)

    def set_tip_frequency(self, key: str):
        self._s.setValue("behavior/tip_freq", str(key))

    def input_reactions_enabled(self) -> bool:
        """Typing and scroll reactions. Note these are already inert when
        pynput could not bind an input backend (headless, Wayland, macOS
        without accessibility) — this is the user's own switch, not that."""
        return self._s.value("behavior/input_reactions", True, type=bool)

    def set_input_reactions_enabled(self, value: bool):
        self._s.setValue("behavior/input_reactions", bool(value))

    def hardware_reactions_enabled(self) -> bool:
        return self._s.value("behavior/hardware_reactions", True, type=bool)

    def set_hardware_reactions_enabled(self, value: bool):
        self._s.setValue("behavior/hardware_reactions", bool(value))

    def click_action(self) -> str:
        from companion_prefs import click_action
        return click_action(self._s.value("behavior/click_action", "", type=str))

    def set_click_action(self, key: str):
        self._s.setValue("behavior/click_action", str(key))

    def remember_position(self) -> bool:
        return self._s.value("geometry/remember_pet", True, type=bool)

    def set_remember_position(self, value: bool):
        self._s.setValue("geometry/remember_pet", bool(value))

    def monitor_index(self) -> int:
        """Which screen the fox lives on. -1 = follow the primary screen,
        which is what it did before there was a picker."""
        return self._s.value("geometry/monitor", -1, type=int)

    def set_monitor_index(self, index: int):
        self._s.setValue("geometry/monitor", int(index))

    # ── window geometry (no secrets — plain coordinates) ──
    def pet_pos(self) -> QPoint | None:
        """Where the user last placed the fox, or None if never placed."""
        val = self._s.value("geometry/pet_pos")
        return val if isinstance(val, QPoint) else None

    def set_pet_pos(self, pos: QPoint):
        self._s.setValue("geometry/pet_pos", pos)

    def clear_pet_pos(self):
        self._s.remove("geometry/pet_pos")

    def console_geometry(self) -> QByteArray | None:
        val = self._s.value("geometry/console")
        return val if isinstance(val, QByteArray) and not val.isEmpty() else None

    def set_console_geometry(self, geo: QByteArray):
        self._s.setValue("geometry/console", geo)

    def chat_size(self) -> QSize | None:
        val = self._s.value("geometry/chat_size")
        return val if isinstance(val, QSize) and val.isValid() else None

    def set_chat_size(self, size: QSize):
        self._s.setValue("geometry/chat_size", size)

    # ── console chrome state (D3) — mirrors the web's localStorage keys ──
    def breach_seen_seq(self) -> int:
        """Highest breach seq the user has already looked at (web:
        `foxy_breach_seen`). Everything above it counts toward the pip."""
        return self._s.value("chrome/breach_seen_seq", 0, type=int)

    def set_breach_seen_seq(self, seq: int):
        self._s.setValue("chrome/breach_seen_seq", int(seq))

    def dismissed_announcements(self) -> dict:
        """Per-id banner dismissals (web: `foxy_dash_ann_dismissed`). A banner
        the user closed must never reappear for the same id."""
        raw = self._s.value("chrome/ann_dismissed", "", type=str)
        try:
            data = json.loads(raw) if raw else {}
        except ValueError:
            return {}
        return data if isinstance(data, dict) else {}

    def dismiss_announcement(self, ident: str):
        data = self.dismissed_announcements()
        data[str(ident)] = 1
        self._s.setValue("chrome/ann_dismissed", json.dumps(data))

    # ── companion alerts (D12; D13 gives these their Settings UI) ──
    # Every default is what the companion ALREADY did before the toggles
    # existed: react to every breach, with a beep and a native toast. The
    # three new sources default on for the same reason the web's breach-alert
    # preference does — a compliance companion that stays quiet about running
    # out of capture credits is not doing its job. Adding the keys changes no
    # behaviour on its own; D13 adds the UI that can turn them off.
    def breach_alerts_enabled(self) -> bool:
        return self._s.value("alerts/breach", True, type=bool)

    def set_breach_alerts_enabled(self, value: bool):
        self._s.setValue("alerts/breach", bool(value))

    def alert_min_risk(self) -> int:
        """Below this a breach is still real and still in the ledger — the fox
        simply does not interrupt for it. 0 = interrupt for all."""
        return max(0, min(100, self._s.value("alerts/min_risk", 0, type=int)))

    def set_alert_min_risk(self, value: int):
        self._s.setValue("alerts/min_risk", max(0, min(100, int(value))))

    def alert_sound_enabled(self) -> bool:
        return self._s.value("alerts/sound", True, type=bool)

    def set_alert_sound_enabled(self, value: bool):
        self._s.setValue("alerts/sound", bool(value))

    def native_toasts_enabled(self) -> bool:
        return self._s.value("alerts/toasts", True, type=bool)

    def set_native_toasts_enabled(self, value: bool):
        self._s.setValue("alerts/toasts", bool(value))

    def quota_alerts_enabled(self) -> bool:
        return self._s.value("alerts/quota", True, type=bool)

    def set_quota_alerts_enabled(self, value: bool):
        self._s.setValue("alerts/quota", bool(value))

    def anchor_alerts_enabled(self) -> bool:
        return self._s.value("alerts/anchor", True, type=bool)

    def set_anchor_alerts_enabled(self, value: bool):
        self._s.setValue("alerts/anchor", bool(value))

    def grading_alerts_enabled(self) -> bool:
        return self._s.value("alerts/grading", True, type=bool)

    def set_grading_alerts_enabled(self, value: bool):
        self._s.setValue("alerts/grading", bool(value))

    # D13 completes the Alerts tab. `breach_poll_seconds` is the cadence the
    # breach poller hard-coded at 10 s; the companion sweep stays at 90 s and
    # is deliberately not exposed — it feeds nothing time-critical.
    def breach_poll_seconds(self) -> int:
        from companion_prefs import POLL_DEFAULT, poll_interval
        return poll_interval(self._s.value("alerts/poll_seconds",
                                           POLL_DEFAULT, type=int))

    def set_breach_poll_seconds(self, seconds: int):
        self._s.setValue("alerts/poll_seconds", int(seconds))

    def weekly_summary_enabled(self) -> bool:
        return self._s.value("alerts/weekly_summary", True, type=bool)

    def set_weekly_summary_enabled(self, value: bool):
        self._s.setValue("alerts/weekly_summary", bool(value))

    def quiet_hours_enabled(self) -> bool:
        return self._s.value("alerts/quiet_enabled", False, type=bool)

    def set_quiet_hours_enabled(self, value: bool):
        self._s.setValue("alerts/quiet_enabled", bool(value))

    def quiet_hours(self) -> tuple[str, str]:
        from companion_prefs import DEFAULT_QUIET_FROM, DEFAULT_QUIET_TO
        return (self._s.value("alerts/quiet_from", DEFAULT_QUIET_FROM, type=str),
                self._s.value("alerts/quiet_to", DEFAULT_QUIET_TO, type=str))

    def set_quiet_hours(self, start: str, end: str):
        self._s.setValue("alerts/quiet_from", str(start))
        self._s.setValue("alerts/quiet_to", str(end))

    # ── weekly-summary counters (previously raw QSettings pokes) ──
    def weekly_breaches(self) -> int:
        return self._s.value("weekly/breaches", 0, type=int)

    def bump_weekly_breaches(self):
        self._s.setValue("weekly/breaches", self.weekly_breaches() + 1)

    def reset_weekly_breaches(self):
        self._s.setValue("weekly/breaches", 0)

    def weekly_last_summary(self) -> str:
        return self._s.value("weekly/last_summary", "", type=str)

    def set_weekly_last_summary(self, iso_ts: str):
        self._s.setValue("weekly/last_summary", iso_ts)
