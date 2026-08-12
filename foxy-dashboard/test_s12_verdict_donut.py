"""The verdict donut must not report a withheld response as Clean.

A `response_blocked` row (SDK >= 1.4) is terminal and locally decided, so it
reaches the ledger already `graded`. The donut derives Clean by subtracting the
non-clean states from `graded` — and `response_blocked` was not among them, so a
response the SDK withheld from the caller was drawn GREEN, on the one chart that
summarises the whole ledger.

The arithmetic is EXECUTED, not re-read. Re-deriving the expression in Python
would be green by construction whatever the page ships; running the shipped
statement in node with a known stats object is a measurement.
"""

from __future__ import annotations

import json
import re
import shutil
import subprocess
import tempfile
from pathlib import Path

import pytest

from test_p1_contrast import HTML  # noqa: F401 - the shipped dashboard

SRC = HTML.read_text(encoding="utf-8")

pytestmark = pytest.mark.skipif(shutil.which("node") is None,
                                reason="node not on PATH")


def _clean_statement() -> str:
    """The shipped `var breaches=…;` statement, whole.

    A STATEMENT, not a character window: it starts at a unique anchor and ends
    at the `;` that closes it, and there is no other `;` inside it. A window
    would drift onto the neighbouring code the moment a line is added — the
    failure mode this repo has hit three times."""
    start = SRC.index("var breaches=+s.breaches")
    end = SRC.index(";", start)
    statement = SRC[start:end + 1]
    assert statement.count("clean=") == 1, statement
    return statement


def _evaluate(stats: dict, grading: dict) -> dict:
    probe = (
        "const s = " + json.dumps(stats) + ", g = " + json.dumps(grading) + ";\n"
        + _clean_statement() + "\n"
        + "console.log(JSON.stringify({clean, blocked, redacted, unknown}));\n"
    )
    with tempfile.TemporaryDirectory() as tmp:
        path = Path(tmp) / "donut.js"
        path.write_text(probe, encoding="utf-8")
        # encoding="utf-8" on purpose: text=True alone decodes cp1252 here and
        # turns a correct run into a mystery failure.
        proc = subprocess.run([shutil.which("node"), str(path)],
                              capture_output=True, text=True, encoding="utf-8")
    assert proc.returncode == 0, proc.stderr
    return json.loads(proc.stdout.strip().splitlines()[-1])


def test_a_withheld_response_is_not_drawn_as_clean():
    out = _evaluate(
        {"breaches": 1, "blocked": 2, "response_blocked": 3, "redacted": 1,
         "evaluator_unknown": 0},
        {"graded": 10, "pending": 0, "in_progress": 0, "failed": 0})
    assert out["blocked"] == 5, \
        "response_blocked must join the Blocked slice — verdictOf badges both rows 'blocked'"
    assert out["clean"] == 10 - 1 - 5 - 1


def test_a_backend_that_never_sends_the_field_still_adds_up():
    """Older backends have no stats.response_blocked. Reading it must not turn
    the whole expression into NaN and paint an empty donut."""
    out = _evaluate({"breaches": 1, "blocked": 2, "redacted": 1,
                     "evaluator_unknown": 0},
                    {"graded": 10, "pending": 0, "in_progress": 0, "failed": 0})
    assert out["blocked"] == 2
    assert out["clean"] == 6


def test_the_slice_the_value_feeds_is_still_the_blocked_one():
    """The arithmetic above is only right if `blocked` is what the Blocked slice
    reads. Anchored on the parts array that PRECEDES the verdict donut's own
    foxChart call, so it cannot be satisfied by the other donut on the page."""
    call = SRC.index("foxChart('ledgerVerdictDonut'")
    parts = SRC.rindex("var parts=[", 0, call)
    array = SRC[parts:SRC.index("]", parts) + 1]
    labels = dict(re.findall(r"\{label:'([^']+)',value:([^,]+),", array))
    assert labels.get("Blocked") == "blocked", labels
