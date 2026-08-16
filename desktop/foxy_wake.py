"""
Foxy Audit — wake the fox before pinging it.
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
The SDK's loopback ping is fire-and-forget by design: it is cosmetic feedback,
the authoritative record is the ledger, and a guarded call must never block on a
desktop app being up. So when the fox is not running, the datagram lands
nowhere and the person watching sees nothing at all — which, for someone whose
first contact with the product is a blocked prompt, looks exactly like a guard
that did not fire.

This module closes that gap from the DESKTOP side: probe the port, start the
app if nothing is listening, wait for it to bind, and only then let the caller
send.

⚠ IT DOES NOT LIVE IN THE SDK, AND MUST NOT. `sdk/src/` is what runs inside a
customer's application — frequently a server process, often headless, sometimes
a container. Code that spawns a windowed desktop app from inside somebody's
request path is wrong in every one of those places, and it would make the SDK's
behaviour depend on what is installed on the host. The SDK stays a sender that
does not care whether anyone is listening.

WHAT THIS MEANS FOR A REAL CUSTOMER. Two honest routes, and this module is the
second:

  1. The app runs already — the normal case. It is a companion; `autostart.py`
     registers it at login, and then the port is always bound.
  2. Something on the same machine wants the fox up before it sends. Then it
     calls `ensure_awake()`, which is what `demo/mock_llm.py` does. It only
     works locally and only when the app is installed where `autostart`
     resolves it, both of which are stated by the return value rather than
     assumed.

There is no third route where a remote process starts a GUI on somebody's
desktop, and there should not be.
"""

from __future__ import annotations

import os
import socket
import subprocess
import sys
import time

DEFAULT_HOST = "127.0.0.1"
DEFAULT_PORT = 9999


def is_listening(host: str = DEFAULT_HOST, port: int = DEFAULT_PORT) -> bool:
    """True when something already holds the ping port.

    ⚠ THE PROBE MUST NOT SET SO_REUSEADDR. `sdk_bridge` binds WITH it, and a
    second socket that also sets it binds the same port happily — measured on
    Windows: the probe succeeded while the listener was live, so a reuse-flagged
    probe reports "nobody home" every time and would start a second fox on top
    of the running one. Without the flag the bind is refused (WSAEADDRINUSE),
    which is the signal. The same rule holds on Linux and macOS, where UDP
    address reuse likewise requires every socket sharing the port to ask for it.
    """
    probe = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        probe.bind((host, port))
        return False            # bound it ourselves -> nothing was listening
    except OSError:
        return True
    finally:
        probe.close()


def app_command() -> list:
    """How to start the fox, from the one place that already knows.

    `autostart.launch_command()` is what gets registered at login, so a wake and
    a login start the same thing. Duplicating the frozen/source branch here
    would be a second answer that can disagree with the first.
    """
    try:
        from autostart import launch_command
        return list(launch_command())
    except Exception:                       # noqa: BLE001 — never break a send
        entry = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                             "omni_fox.py")
        if getattr(sys, "frozen", False):
            return [sys.executable]
        return [sys.executable, entry]


def _spawn(command: list) -> bool:
    """Start the app detached, so it outlives the process that woke it."""
    try:
        kwargs = {"cwd": os.path.dirname(os.path.abspath(__file__))}
        if os.name == "nt":
            # DETACHED_PROCESS | CREATE_NEW_PROCESS_GROUP: the fox must not die
            # with the terminal that ran the demo, and must not inherit its
            # console — a windowed app attached to a console shows a stray
            # black window behind the sprite.
            kwargs["creationflags"] = 0x00000008 | 0x00000200
        else:
            kwargs["start_new_session"] = True
        subprocess.Popen(command, **kwargs)
        return True
    except Exception:                       # noqa: BLE001
        return False


def ensure_awake(timeout: float = 20.0, host: str = DEFAULT_HOST,
                 port: int = DEFAULT_PORT, launcher=None) -> str:
    """Make sure the fox is listening. Returns what actually happened.

        "already"   it was up; nothing was started
        "started"   it was not, and it is now — the port is bound
        "timeout"   it was started but did not bind within `timeout`
        "failed"    it could not be started at all

    ⚠ RETURNS A STATE, NEVER RAISES. The caller is in the middle of reporting a
    policy decision; a wake that fails is a cosmetic loss and must not become an
    exception in somebody's guard path. Callers are expected to print the
    string, not to trust that it says "started".
    """
    if is_listening(host, port):
        return "already"
    spawn = launcher or _spawn
    if not spawn(app_command()):
        return "failed"
    deadline = time.time() + timeout
    while time.time() < deadline:
        if is_listening(host, port):
            # The port is bound, but the listener has only just come up. The
            # first datagram after a bind is the one most likely to be dropped,
            # and a dropped one here is the whole demo.
            time.sleep(0.4)
            return "started"
        time.sleep(0.25)
    return "timeout"


#: What to print when a wake did not work. Written here rather than at each call
#: site so two surfaces cannot describe the same failure two ways.
EXPLANATION = {
    "already": "",
    "started": "",
    "timeout": ("the Foxy app was started but did not answer on "
                f"{DEFAULT_HOST}:{DEFAULT_PORT} in time — it may still be opening"),
    "failed": ("could not start the Foxy desktop app — open it yourself and the "
               "block card will appear on the next prompt"),
}
