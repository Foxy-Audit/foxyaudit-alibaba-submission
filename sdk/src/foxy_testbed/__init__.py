"""Foxy Audit compliance testbed — a real assistant, behind the real guard.

One engine, three sector presets, one ``Turn`` record. The CLI, the local web
page and the desktop console page are three renderings of that record; none of
them holds policy logic.

    python -m foxy_testbed --sector healthcare              # interactive REPL
    python -m foxy_testbed --sector healthcare --probe all  # the scored corpus

Offline and keyless by default: the ``mock`` provider makes no network call and
the client is built with ``api_key=""``, so a run cannot depend on whose machine
it is or on what is in the environment.

THIS PACKAGE IS A CONSUMER OF THE SDK, NOT PART OF IT
====================================================
It uses ``foxy_audit``'s public API only — ``FoxyClient.audit``, ``check``, and
the two block exceptions. It ships inside the same wheel so that
``pip install foxy-audit`` is all a prospect needs, but nothing in
``foxy_audit/`` imports anything from here, and nothing here reaches into
``foxy_audit``'s internals. Where the public surface does not reach far enough,
the gap is recorded as a comment marked ``SDK FINDING`` and reported upward,
never patched around.

WHAT IS REAL AND WHAT IS A FIXTURE
==================================
The enforcement is real: the same preflight guard, the same ruleset, the same
rule ids a customer's production event carries. The mock provider's replies are
fixtures we wrote, and every surface renders
:data:`foxy_testbed.providers.MOCK_NOTE` beside them saying so.
"""

from __future__ import annotations

from .core import (Assistant, DECISIONS, DEFAULT_MODE, MODES, Turn)
from .providers import (MOCK_NOTE, PROVIDER_NAMES, Provider, ProviderError,
                        build_provider)
from .scoreboard import (AssistantConflict, ProbeResult, Scoreboard,
                         SectorMismatch, run_probes)
from .sectors import (EXPECT_ASSIST, EXPECT_BLOCK, KNOWN_GAP, Probe, SECTORS,
                      SECTOR_NAMES, Sector, get_sector)

__all__ = ["Assistant", "AssistantConflict", "DECISIONS", "DEFAULT_MODE", "EXPECT_ASSIST",
           "EXPECT_BLOCK", "KNOWN_GAP", "MOCK_NOTE", "MODES", "PROVIDER_NAMES",
           "Probe", "ProbeResult", "Provider", "ProviderError", "SECTORS",
           "SECTOR_NAMES", "Scoreboard", "Sector", "SectorMismatch", "Turn",
           "build_provider", "get_sector", "run_probes"]
