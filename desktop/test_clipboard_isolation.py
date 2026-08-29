"""#281 · the desktop suite does not touch the clipboard of the machine it runs on.

`conftest.no_clipboard` is the fix, and this file is what makes it fail on
purpose. It exists because #281 was filed as an ordering bug — *something
earlier leaves the clipboard dirty* — and no such test exists. The clipboard is
the operating system's, shared with every process on the box, and on Windows a
`setText` that collides with another process's `OpenClipboard` reads back `''`
with no error anywhere. See `no_clipboard`'s docstring for the three
measurements.

⚠ WHAT A FIX HERE MUST NOT BE. `skipif(sys.platform == "win32")` would make the
number green and delete the guard, which is the pattern this register has closed
four times (#258, #263, #276, #277). Nothing below is skipped on any platform:
the isolation is the same code everywhere, so the guards are too.
"""

from __future__ import annotations

import io
import pathlib
import re
import tokenize

import pytest
from PyQt6.QtGui import QClipboard, QGuiApplication
from PyQt6.QtWidgets import QApplication

from conftest import _LocalClipboard

#: Set by the first half of the per-test-reset pair, read by the second. A pair
#: of ordered tests can pass because the first never ran (guard-lie #5), so the
#: second asserts that it did before asserting anything else.
_WROTE = []


@pytest.fixture(scope="module", autouse=True)
def app():
    """A REAL QApplication, so `no_clipboard` is measured against the real
    `QClipboard` it displaces rather than against `None`. Returned, and so
    held for the session — see `test_qt_lifecycle` for what dropping it does."""
    return QApplication.instance() or QApplication([])


# ── the isolation is installed at all ──────────────────────────────────────

def test_the_clipboard_a_test_sees_is_not_the_machines():
    """Delete `no_clipboard` from `conftest.py` and this is what dies."""
    board = QApplication.clipboard()
    assert isinstance(board, _LocalClipboard), (
        f"a desktop test reached a real {type(board).__name__} — it is writing "
        "to the clipboard of whoever is running the suite, and #281 is back")
    assert not isinstance(board, QClipboard)


def test_both_application_classes_hand_over_the_SAME_isolated_clipboard():
    """PyQt6 defines `clipboard` on `QGuiApplication`, and product code may
    import either class. Patching only the subclass would leave one of the two
    doors open, and every call site in `desktop/` happens to use the other."""
    assert "clipboard" not in QApplication.__dict__, (
        "PyQt6 now defines `clipboard` on QApplication itself; `no_clipboard` "
        "patches QGuiApplication and would no longer cover this call path")
    assert QApplication.clipboard() is QGuiApplication.clipboard()


def test_one_instance_per_test_not_one_per_call():
    """`clipboard()` is called once to write and again to read. Hand out a fresh
    object per call and every read returns `""` — every guard in
    `test_p3_orgid_stepup` would then pass while asserting nothing."""
    QApplication.clipboard().setText("written by one call")
    assert QApplication.clipboard().text() == "written by one call"


# ── the isolation resets between tests ─────────────────────────────────────

def test_a_reset_pair_1_writes():
    QApplication.clipboard().setText("left behind by the previous test")
    _WROTE.append(True)


def test_a_reset_pair_2_starts_clean():
    """One test's copy must not be able to satisfy the next one's assertion."""
    assert _WROTE, ("the writing half of this pair did not run, so a clean "
                    "clipboard here proves nothing")
    assert QApplication.clipboard().text() == ""


# ── the stub keeps PyQt6's contract, so it cannot hide a product bug ───────

@pytest.mark.parametrize("value, expected", [("org-1234", "org-1234"),
                                             ("", ""),
                                             (None, "")])
def test_it_accepts_what_qclipboard_accepts(value, expected):
    """`setText(None)` is legal in PyQt6 and yields `""` — measured against a
    real `QClipboard`. A stub that raised here would fail correct product code."""
    board = QApplication.clipboard()
    board.setText(value)
    assert board.text() == expected


@pytest.mark.parametrize("value", [5, b"bytes", ["list"], object()])
def test_it_rejects_what_qclipboard_rejects(value):
    """And a stub that accepted these would swallow the bug it exists to catch."""
    with pytest.raises(TypeError):
        QApplication.clipboard().setText(value)


# ── nothing in the product reaches the clipboard past the seam ─────────────

#: Non-test modules only: a test file is covered by the fixture by definition.
_PRODUCT = sorted(p for p in pathlib.Path(__file__).parent.glob("*.py")
                  if not p.name.startswith(("test_", "conftest")))

#: Every way this tree is allowed to reach a clipboard. `no_clipboard` patches
#: `QGuiApplication.clipboard`, so these two — and only these two — are isolated.
_SEAM = re.compile(r"Q(?:Gui)?Application\.clipboard\(\)")

#: No word boundary: `EmptyClipboard`, `clipboardChanged` and `setClipboard`
#: are all ways to reach it, and a boundary match reads none of them. MEASURED —
#: with the boundary in, a ctypes `user32.EmptyClipboard()` planted in
#: `access_page` SURVIVED this guard (mutant M7a).
_CLIPBOARD = re.compile("clipboard", re.I)


def _code_of(path) -> dict:
    """`{lineno: the code on it}`, with comments and string literals removed.

    A guard that greps a file greps its own docstring otherwise — and every
    module here is heavily commented. Tokens are rejoined without separators,
    so `QApplication.clipboard()` survives the round trip intact."""
    lines = {}
    for tok in tokenize.generate_tokens(io.StringIO(
            path.read_text(encoding="utf-8")).readline):
        if tok.type in (tokenize.COMMENT, tokenize.STRING):
            continue
        lines.setdefault(tok.start[0], []).append(tok.string)
    return {n: "".join(parts) for n, parts in lines.items()}


def test_every_product_clipboard_access_goes_through_the_patched_seam():
    """A call site that built its own `QClipboard`, or reached one off a widget's
    `QGuiApplication.instance()`, would sit outside the fixture and put #281 back
    for that surface only — the hardest version of it to find."""
    hits = [(path.name, n, code)
            for path in _PRODUCT
            for n, code in sorted(_code_of(path).items())
            if _CLIPBOARD.search(code)]
    # ⚠ A watchlist that can empty is a guard that can pass by watching nothing
    # (#279). If the product stops copying anything, that is a decision someone
    # must take here deliberately, not a silent green.
    assert hits, ("no product line mentions the clipboard any more — if copy was "
                  "removed on purpose, delete this guard in the same commit")
    outside = [h for h in hits if not _SEAM.search(h[2])]
    assert not outside, (
        "clipboard access outside the seam `no_clipboard` patches:\n"
        + "\n".join(f"  {name}:{n}: {code}" for name, n, code in outside))
