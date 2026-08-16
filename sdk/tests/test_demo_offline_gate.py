"""`demo/mock_llm.py`'s offline gate has to actually be offline.

The demo's headline claim, in its own words, is:

    ⚠ THE DEFAULT PATH TAKES NO API KEY AND OPENS NO SOCKET, AND MUST STAY THAT
    WAY. `--scenario all` is a merge gate and runs on machines with no stack and
    no network.

That claim was false, and the machine it was false on was specifically a machine
someone had demoed on. `FoxyConfig.resolve` reads ``$FOXY_API_KEY`` whenever
``api_key`` is None (``config.py``), the module-level client passed no api_key at
all, and the demo's own --live error message tells you to export that variable.
So on that machine the "offline" gate came up ``enabled=True`` and shipped every
scenario — including the PHI and secret prompts — to whatever backend the
variable pointed at.

The fix is one keyword. This file is the reason it cannot come back: ``""`` and
``None`` are different instructions to the SDK, and nothing but a test records
which one this line has to pass.

⚠ THE SECOND TEST IS THE REAL ONE. Asserting ``cfg.enabled is False`` checks a
field; asserting that running the gate produces ZERO payloads checks the claim.
A future refactor could satisfy the first and still ship.
"""

from __future__ import annotations

import importlib
import sys
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parents[2]
DEMO = REPO / "demo"

#: ⚠ THESE TESTS SHIP, AND CANNOT RUN WHERE THEY SHIP. ``tests/`` goes into the
#: sdist; ``demo/`` lives at the REPOSITORY root and does not. Outside a
#: checkout every test here died on ``ModuleNotFoundError: mock_llm`` — three
#: errors in the sdist self-test, which is an audit product's own suite failing
#: to install cleanly. Skipped with a stated reason instead, exactly as
#: test_stated_figures.py skips the documentation it cross-checks.
#:
#: NOT a loosening. In a checkout — where CI runs and where this gate matters —
#: every one of them still executes, and the skip is visible as a skip rather
#: than as a pass.
pytestmark = pytest.mark.skipif(
    not (DEMO / "mock_llm.py").is_file(),
    reason="exercises demo/mock_llm.py, which lives at the repository root and "
           "is not part of the sdist")


@pytest.fixture()
def demo(monkeypatch, tmp_path):
    """Import demo/mock_llm.py fresh, with a key exported and a throwaway spool.

    Fresh because the module builds its client AT IMPORT, so a copy left in
    sys.modules by another test would have been built under a different
    environment and would prove nothing about this one.

    The spool is redirected because a FoxyClient persists a generated client_id
    locally on construction, and a test has no business writing into the real
    ``~/.foxy-audit`` — the spool is durable, and the next process to build a
    client flushes whatever it finds there.
    """
    monkeypatch.setenv("FOXY_API_KEY", "foxy_sk_exported_by_a_previous_live_run")
    monkeypatch.setenv("FOXY_SPOOL_PATH", str(tmp_path / "spool.sqlite3"))
    monkeypatch.syspath_prepend(str(DEMO))
    sys.modules.pop("mock_llm", None)
    module = importlib.import_module("mock_llm")
    yield module
    sys.modules.pop("mock_llm", None)


def test_the_default_client_ignores_an_exported_key(demo):
    assert demo.foxy.cfg.api_key == ""
    assert demo.foxy.cfg.enabled is False


def test_the_scenario_gate_ships_nothing_when_a_key_is_exported(demo, monkeypatch):
    """Run the merge gate itself and count what it tried to send."""
    sent = []
    monkeypatch.setattr(demo.dispatch, "submit",
                        lambda cfg, payload, wait=False: sent.append(payload))

    rc = demo.run_scenarios(list(demo.SCENARIOS))

    assert rc == 0, "the scenarios must still all pass"
    assert sent == [], f"the offline gate shipped {len(sent)} event(s)"


def test_live_still_reads_the_environment(demo, monkeypatch):
    """The fix must not cost --live its documented convenience.

    `--api-key` defaults to $FOXY_API_KEY through argparse, so the variable is
    still how a live run is keyed — it just no longer keys a run nobody asked
    to be live.
    """
    parsed = []
    monkeypatch.setattr(demo, "enable_live",
                        lambda key, endpoint, ping: parsed.append(key))
    monkeypatch.setattr(sys, "argv",
                        ["mock_llm.py", "--live", "--scenario", "benign"])
    monkeypatch.setattr(demo, "_report_live", lambda rc: rc)

    demo.main()

    assert parsed == ["foxy_sk_exported_by_a_previous_live_run"]
