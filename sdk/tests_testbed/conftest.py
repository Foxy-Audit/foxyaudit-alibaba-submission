"""Guards for ``foxy_testbed``, deliberately OUTSIDE ``sdk/tests``.

``pytest sdk/tests -q`` is a CI step with a pinned baseline, and the testbed is
a separate package with a separate gate (``pytest sdk/tests_testbed -q``). Adding
files to ``sdk/tests`` would move that baseline for reasons that have nothing to
do with the SDK, so these live beside it rather than inside it.

The ``sys.path`` insert mirrors ``sdk/conftest.py``: an editable install of
another checkout can put a different ``.../sdk/src`` on the path, and these
guards must exercise THIS worktree's source. It is repeated rather than relied
upon because conftest collection depends on where pytest was invoked from, and a
guard suite that silently tests a stale copy is worse than none.
"""

from __future__ import annotations

import os
import sys

import pytest

_SRC = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "src")
if _SRC not in sys.path:
    sys.path.insert(0, _SRC)


@pytest.fixture(autouse=True)
def _isolate_the_spool(tmp_path, monkeypatch):
    """Keep these guards out of the developer's real ``~/.foxy-audit`` spool.

    The testbed builds its client with ``api_key=""`` so nothing should ever be
    spooled — but "should" is what this fixture is insurance against, and a test
    that can write to a developer's home directory is a test their home
    directory can decide the result of.
    """
    monkeypatch.setenv("FOXY_SPOOL_PATH", str(tmp_path / "spool.sqlite3"))
