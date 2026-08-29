"""The rule that ends the process, not a test.

This build has hit **exit 127, no Python traceback, after every test has
already passed** several times. It cannot be caught, asserted on, or reported
by pytest — the process is gone before the summary line is written — so the
guard has to be structural: look at the source for the pattern that causes it.

**The cause: a QApplication that nothing holds.**

    def test_bad():
        QApplication.instance() or QApplication([])   # value DROPPED
        QWidget()                                     # any widget at all
        # ...the test passes, then exit 127 at interpreter shutdown

    @pytest.fixture(scope="module")
    def app():
        return QApplication.instance() or QApplication([])   # HELD -> exit 0

PyQt owns the C++ QApplication through its Python wrapper. Drop the only
reference and it is garbage-collected while widgets are still alive; the
teardown order at shutdown is what kills the process. Every test file in this
tree survives because its `app` fixture RETURNS the application and pytest
caches that value for the session — luck that became a convention, which is
why this file pins it.

**Deterministic alone, intermittent in a suite — and that is the whole
mystery.** Measured on this branch:

    the bad file, run alone, 5 runs   -> 127 127 127 127 127
    the good file, run alone, 5 runs  ->   0   0   0   0   0
    the FULL suite with the bad line  -> sometimes 127, sometimes 0

The suite is a coin flip because `QApplication.instance() or QApplication([])`
only CONSTRUCTS anything when no application exists yet. If some other
module's `app` fixture ran first and is holding one, the bare expression
short-circuits and nothing is dropped. Whether a holding fixture ran first
depends on collection order.

That settles a long-running disagreement: an executor reported an intermittent
exit-127 around `test_home_page.py` -> `test_p3_pages.py`, MAIN could not
reproduce it in nine runs and called it unconfirmed. Both observations were
correct. It is also why the guard below is structural rather than a test that
runs the suite and checks the exit code — such a test would pass most of the
time on broken code.

**What it is NOT: the worker-thread signal payload.**

The scheduled-debt item behind this file said "emitting an exception or any
custom object across the worker-thread signal boundary kills the interpreter
(bisected to the payload, not the signal type)". That does not reproduce. A
`QThread` emitting `pyqtSignal(object)` to a main-thread receiver, 200 times
each, was measured with three payloads:

    exception instance -> exit 0, 200/200 delivered
    a live QWidget     -> exit 0, 200/200 delivered
    a plain dict       -> exit 0, 200/200 delivered

So `FoxyClient.step_up_required.emit(e)` (foxy_client.py) is not the hazard it
was suspected of being, and nobody should "fix" it on the strength of the old
report. The original bisect was almost certainly confounded by a harness that
also dropped its QApplication — the same root cause wearing a different hat.
"""

from __future__ import annotations

import ast
from pathlib import Path

import pytest
from PyQt6.QtCore import QObject, Qt, pyqtSignal

_HERE = Path(__file__).resolve().parent
_TESTS = sorted(_HERE.glob("test_*.py"))


def _discarded_qapplication(path: Path) -> list[str]:
    """Statements that CREATE a QApplication and throw the value away.

    An `ast.Expr` is a bare expression statement — its value goes nowhere.
    Assignments, returns and call arguments all keep a reference and are fine.

    It matches the CONSTRUCTOR CALL, not the text: two earlier versions of
    this function matched the word "QApplication" in a dumped tree and so
    flagged their own docstring, and then their own `write_text("…")` fixture
    strings. `QApplication.instance()` on its own is also not a construction
    and is left alone.
    """
    tree = ast.parse(path.read_text(encoding="utf-8"))
    bad = []
    for node in ast.walk(tree):
        if not isinstance(node, ast.Expr):
            continue
        for inner in ast.walk(node.value):
            if (isinstance(inner, ast.Call)
                    and isinstance(inner.func, ast.Name)
                    and inner.func.id == "QApplication"):
                bad.append(f"{path.name}:{node.lineno}: "
                           f"{ast.unparse(node)[:64]}")
                break
    return bad


def test_no_test_file_drops_its_qapplication_on_the_floor():
    """The assertion this whole file exists for.

    Checked in both directions: with `test_d12_companion.py`'s bare line
    restored this fails, and the minimal case exits 127 five times out of
    five. The full suite with that same line is a coin flip — see the module
    docstring — which is precisely why the guard reads the source instead of
    trusting a green run.
    """
    offenders = [line for path in _TESTS for line in _discarded_qapplication(path)]
    assert offenders == [], (
        "a discarded QApplication kills the interpreter at shutdown "
        "(exit 127, no traceback, AFTER the tests pass):\n  "
        + "\n  ".join(offenders))


def test_the_guard_recognises_the_shape_it_is_looking_for(tmp_path):
    """A structural check that never fires is indistinguishable from one that
    cannot fire. This proves it catches the bad shape and clears the good one.
    """
    bad = tmp_path / "test_bad.py"
    bad.write_text("from PyQt6.QtWidgets import QApplication\n"
                   "def test_x():\n"
                   "    QApplication.instance() or QApplication([])\n",
                   encoding="utf-8")
    assert _discarded_qapplication(bad)

    good = tmp_path / "test_good.py"
    good.write_text('"""A docstring mentioning QApplication."""\n'
                    "from PyQt6.QtWidgets import QApplication\n"
                    "def app():\n"
                    "    return QApplication.instance() or QApplication([])\n"
                    "def other(a=QApplication.instance()):\n"
                    "    return a\n",
                    encoding="utf-8")
    assert _discarded_qapplication(good) == []


def test_the_worker_error_signal_still_carries_a_plain_string():
    """Not a crash rule — a CONTRACT rule, and worth keeping for its own sake.

    `status_of()` and `detail_of()` parse `ApiError.__str__`'s "HTTP <code>:
    <detail>" out of that string, and every handler in the app is written
    against it. Widening `failed` to carry the exception would silently break
    the two helpers rather than the process.
    """
    source = (_HERE / "foxy_client.py").read_text(encoding="utf-8")
    worker = source.split("class ApiWorker")[1].split("\nclass ")[0]
    assert "failed = pyqtSignal(str)" in worker

def _app_built_inside_a_test(path):
    """QApplication constructed in a test FUNCTION body rather than a
    module-scoped fixture.

    Binding it to a name is not enough — a local dies when the function
    returns, so the C++ application is collected while widgets are still
    alive. That is exactly how exit 127 survived the b939f3f fix: the bare
    expression became `app = ...` inside a test body, which only looked safe
    because another module's cached fixture usually still held one. Whether it
    did was decided by collection order, which is why it read as flaky.
    """
    import ast
    tree = ast.parse(open(path, encoding="utf-8").read(), filename=str(path))
    bad = []
    for node in ast.walk(tree):
        if not (isinstance(node, ast.FunctionDef) and node.name.startswith("test_")):
            continue
        for sub in ast.walk(node):
            if (isinstance(sub, ast.Call) and isinstance(sub.func, ast.Name)
                    and sub.func.id == "QApplication"):
                bad.append(f"{Path(path).name}:{sub.lineno} "
                           f"in {node.name}() — build it in a module-scoped "
                           f"`app` fixture instead")
    return bad


def test_no_test_builds_its_qapplication_inside_the_test_body():
    """The second half of the same bug, and the half that outlived the first fix.

    `test_d12_companion.py` had a bound-but-local application inside a test
    body; the suite still exited 127 on roughly one random order in four.
    Reverting this file's fixture back to that shape reproduces it.
    """
    offenders = [line for path in _TESTS for line in _app_built_inside_a_test(path)]
    assert offenders == [], (
        "a QApplication built inside a test body dies when that function "
        "returns:\n  " + "\n  ".join(offenders))


#: A file carrying the exact defect the scan hunts, used to drive its REPORTING
#: path. ⚠ THAT HALF HAD NEVER RUN (register #277). `_TESTS` is all-green by
#: design, so every execution of the guard above takes the empty branch, and the
#: line that BUILDS the message called `os.path.basename` in a module importing
#: `ast`, `pathlib.Path`, `pytest` and PyQt6 and never `os`. A guard whose only
#: unexercised line is the one that fires when it finally finds something reports
#: a `NameError` instead of the offender — it breaks at the moment it becomes
#: useful. Fixing the line without running it would leave that unchanged.
_OFFENDER_SOURCE = """from PyQt6.QtWidgets import QApplication


def test_builds_one_in_the_body():
    app = QApplication.instance() or QApplication([])
    assert app is not None
"""

#: The same file with the application moved into a module-scoped fixture. Without
#: this half, a scan hard-wired to return one line per file would satisfy the
#: assertions above it.
_CLEAN_SOURCE = """import pytest
from PyQt6.QtWidgets import QApplication


@pytest.fixture(scope="module")
def app():
    return QApplication.instance() or QApplication([])


def test_uses_the_fixture(app):
    assert app is not None
"""


def test_the_scan_can_report_what_it_finds_and_not_only_find_nothing(tmp_path):
    """Drive the branch that has never fired, on a file built to trip it."""
    offender = tmp_path / "test_offender_fixture.py"
    offender.write_text(_OFFENDER_SOURCE, encoding="utf-8")
    found = _app_built_inside_a_test(offender)

    assert len(found) == 1, f"the scan did not report the offender: {found!r}"
    line = found[0]
    assert line.startswith("test_offender_fixture.py:5 "), (
        f"the report lost the file name or the line it found: {line!r}")
    assert "in test_builds_one_in_the_body()" in line, (
        f"the report does not name the offending test: {line!r}")
    assert "module-scoped" in line and "`app` fixture" in line, (
        f"the report does not say what to do instead: {line!r}")

    clean = tmp_path / "test_clean_fixture.py"
    clean.write_text(_CLEAN_SOURCE, encoding="utf-8")
    assert _app_built_inside_a_test(clean) == [], (
        "the scan flagged a module-scoped `app` fixture, which is the shape it "
        "exists to require")


# ══ #244c · the event queue must be drained BETWEEN tests ═══════════════════
#
# The other rule that ends the process rather than a test, and the second one
# this file has had to pin. A unit suite never calls `app.exec()`, so a posted
# event sits in the main thread's queue until something pumps. Left there across
# a 962-test run, the objects behind those events are garbage-collected, and the
# next `processEvents()` — wherever it happens to be — delivers a queued
# metacall into freed memory and takes the interpreter with it (SIGSEGV, exit
# 139, `<invalid frame>`). `conftest.drain_posted_events` gives the loop the turn
# the shipped app has continuously; the docstring there carries the measurements.
#
# ⚠ GUARDED BEHAVIOURALLY, NOT STRUCTURALLY, and that is the difference from the
# exit-127 guards above. Those must read the source because the failure they
# describe is a coin flip decided by collection order. This one is not: the
# drain either happened between these two tests or it did not, and the pair
# below reads the actual queue.

#: Written by the queued slot. Module-level because the whole point is that the
#: delivery happens BETWEEN the two tests, not inside either of them.
_DELIVERED: list[str] = []
_ARMED: list[str] = []
#: The sender is kept alive on purpose. This pair measures whether the QUEUE was
#: drained, and holding the sender keeps object lifetime out of the answer.
_KEEP: list[QObject] = []


class _Sentinel(QObject):
    ping = pyqtSignal(str)


@pytest.fixture(scope="module")
def app():
    # RETURNED, never dropped — the rule the rest of this file guards.
    from PyQt6.QtWidgets import QApplication
    return QApplication.instance() or QApplication([])


def test_a_queued_event_is_left_pending_for_the_next_test(app):
    """Post a queued metacall and deliberately DO NOT pump.

    `Qt.ConnectionType.QueuedConnection` posts the call to the main thread's
    event queue instead of running it inline — the same thing `deleteLater()`,
    `QTimer.singleShot` and every worker-thread `emit` do, without needing a
    thread to demonstrate it.

    ANTI-VACUITY IS THE SECOND ASSERTION: if the connection were direct the slot
    would have run already, nothing would be pending, and the companion test
    below would pass without anything having been drained.
    """
    sentinel = _Sentinel()
    sentinel.ping.connect(_DELIVERED.append, Qt.ConnectionType.QueuedConnection)
    sentinel.ping.emit("armed")
    _KEEP.append(sentinel)
    assert _DELIVERED == [], (
        "the emit ran inline, so nothing is queued and the guard below would "
        "be vacuous")
    _ARMED.append("armed")


def test_the_queue_was_drained_before_this_test_began(app):
    """The assertion: something turned the event loop between the two tests.

    Fails with `_DELIVERED == []` if `conftest.drain_posted_events` is removed
    or made a no-op — verified by deleting the fixture and running this file.

    ⚠ IT NEEDS ITS PAIR. Selecting this test alone (`-k`, or an `-x` run that
    stopped earlier) leaves `_ARMED` empty, and the first assertion says so
    rather than letting the guard pass on a queue nobody ever armed.
    """
    assert _ARMED == ["armed"], (
        "the arming test did not run — this guard is a PAIR and cannot be "
        "selected on its own")
    assert _DELIVERED == ["armed"], (
        "a queued event survived into the next test: nothing drained the Qt "
        "event queue between them. Across a full run those pile up, their "
        "owners are collected, and the next processEvents() segfaults "
        "(register #244c). See conftest.drain_posted_events.")
