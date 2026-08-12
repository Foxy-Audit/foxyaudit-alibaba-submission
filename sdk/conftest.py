"""Make ``cd sdk && python -m pytest`` exercise THIS checkout's source.

An editable install elsewhere on the machine may add a different
``.../sdk/src`` to ``sys.path`` via a ``.pth`` file. Prepending this
worktree's own ``src`` guarantees the tests import the code under test here,
not a stale copy from another checkout.
"""

import os
import sys

import pytest

_SRC = os.path.join(os.path.dirname(os.path.abspath(__file__)), "src")
if _SRC not in sys.path:
    sys.path.insert(0, _SRC)


@pytest.fixture(autouse=True)
def _isolate_the_spool(tmp_path, monkeypatch):
    """Keep the suite out of the developer's real spool.

    A FoxyClient built with an api_key and no ``spool_path`` writes to
    ``~/.foxy-audit/spool.sqlite3`` and tries to deliver — to whatever endpoint
    the test named, usually nothing. Those rows never drain, so every later run
    inherits them, and ``dispatch.resume`` replays the backlog before the event
    the test is waiting for. Measured: with a 407-row backlog
    ``test_full_dispatch_batches_hashes_only`` times out at 8s and fails; with a
    fresh spool it passes in 0.66s. A test that a developer's home directory can
    decide is not a test.

    ``FOXY_SPOOL_PATH`` is the single lever — ``config.resolve`` and
    ``spool.default_path`` both read it, and ``org_policy``'s disk cache sits
    beside the spool, so this isolates that too. Tests that set it themselves
    (test_org_policy.py) still win: monkeypatch in a test body runs after this.

    The teardown is the other half, and it is not optional. Per-test paths
    ACCUMULATE in the module-level ``_DISPATCHER._paths`` — every FoxyClient that
    resumes adds one and nothing ever removes it — so after 223 tests the shared
    dispatcher held 69 dead tmp paths and re-opened a sqlite connection to each
    of them on every flush, for the rest of the session. Each tmp_path is gone by
    then, so EventSpool recreates the directory and the file to find it empty.
    """
    monkeypatch.setenv("FOXY_SPOOL_PATH", str(tmp_path / "spool.sqlite3"))
    before = snapshot_dispatcher_paths()
    yield
    rollback_dispatcher_paths(before)


def snapshot_dispatcher_paths() -> set:
    from foxy_audit import dispatch
    return set(dispatch._DISPATCHER._paths)


def rollback_dispatcher_paths(before: set) -> None:
    """Drop any spool path added since ``before``.

    A named pair rather than two lines inside the fixture, so the rollback can
    be asserted directly — a test cannot observe its own teardown, and a guard
    that instead waits to notice accumulation only fails when it happens to run
    late enough in the session."""
    from foxy_audit import dispatch
    dispatch._DISPATCHER._paths.intersection_update(before)
