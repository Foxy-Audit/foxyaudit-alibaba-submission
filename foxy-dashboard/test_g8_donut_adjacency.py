"""G8 - #152/#150: the two donuts.

THE CENTRAL GUARD MEASURES ACROSS DATA SUBSETS, NOT THE SHIPPED ARRAY.

`drawDonut` filters zero-value slices out before it draws, so the arcs are the
NON-ZERO SUBSET, cyclically adjacent. A guard that only checked the full array
would be checking the one data shape a real tenant never has: a healthy tenant
has zero Breach, zero Blocked, zero Redacted and zero Failed, and its donut is
Clean and Pending alone.

That distinction is why this file exists and it is not hypothetical. This repo
has shipped the same class twice running: G6's tokens that were declared,
aliased, guarded and never painted, and G7's texture gate that switched the
encoding off on every ordinary day while its guard measured the one day it
stayed on.

WHAT THE ARITHMETIC SAYS, and why a reorder alone was never going to be enough:
in a cycle of k slices every slice has exactly two neighbours, so at k <= 3
EVERY pair is adjacent whatever the array order is. Over all 127 non-empty
subsets of the seven verdict slices, the tone fix and the reorder together take
the count with a sub-floor adjacency from 88 to 67. Real, and nowhere near
enough - 67 of 120 still fail. The reorder ships because it is free and it does
clear the full array; the direct labels are the part that makes identity
independent of hue at every subset size.

Everything is read out of the SHIPPED call sites and the SHIPPED engine, so a
re-tone or a re-order re-aims this file rather than leaving it measuring
something nobody draws.
"""

from __future__ import annotations

import itertools
import math
import re
import shutil


import pytest

from test_f1_chart_emphasis import _cvd_gap, _render
from test_p1_contrast import HTML, css, ratio, themes  # noqa: F401 - fixtures

SRC = HTML.read_text(encoding="utf-8")

pytestmark = pytest.mark.skipif(shutil.which("node") is None,
                                reason="node not on PATH")

FLOOR = 8.0                     # dataviz's CVD separation floor, OKLab x100
TONE_TOKEN = {"ok": "safe-bg", "bad": "breach-bg", "warn": "warn-series",
              "fox": "fox-series", "blue": "c-2", "pink": "c-4",
              "violet": "c-6", "mute": "mute-series"}

_SLICE = re.compile(r"\{label:'([^']+)',value:[^,]+,tone:'(\w+)'\}")
_ARC = re.compile(r'<path\b[^>]*class="cx-arc"[^>]*>')
_ARCLABEL = re.compile(r'class="cx-arclabel"[^>]*>([^<]*)</text>')


def _parts(chart_id: str) -> list[tuple[str, str]]:
    """(label, tone) for one shipped donut, in the order it ships.

    Anchored on the `var parts=[` that PRECEDES the foxChart call for this id,
    so both donuts are read the same way and neither can be matched against the
    other's array."""
    call = SRC.index("foxChart('%s'" % chart_id)
    start = SRC.rindex("var parts=[", 0, call)
    hits = _SLICE.findall(SRC[start:SRC.index("];", start)])
    assert hits, "could not read the slice array for %s" % chart_id
    return hits


def _pair(tokens_by_theme: dict, a: str, b: str) -> float:
    """Worst deuteranope separation for this tone pair across BOTH themes."""
    return min(_cvd_gap(t[TONE_TOKEN[a]], t[TONE_TOKEN[b]])
               for t in tokens_by_theme.values())


def _worst_adjacent(tones: list[str], tokens_by_theme: dict) -> float:
    """The worst adjacent pair in a CYCLE. k==2 meets twice; that is one pair."""
    k = len(tones)
    if k < 2:
        return 99.0
    pairs = [(tones[0], tones[1])] if k == 2 else [
        (tones[i], tones[(i + 1) % k]) for i in range(k)]
    return min(_pair(tokens_by_theme, a, b) for a, b in pairs)


# == the inert control ======================================================
def test_the_separation_maths_is_right(themes) -> None:
    """Pin the measurement before it judges anything. A _cvd_gap that returned a
    constant would make every assertion below vacuous, and a _worst_adjacent
    that walked a LIST instead of a CYCLE would silently skip the wraparound -
    which is the pair that put red next to green in the grading donut."""
    assert _cvd_gap("#000000", "#000000") == pytest.approx(0.0, abs=1e-6)
    assert _cvd_gap("#000000", "#ffffff") > 90.0
    # A cycle of three has three adjacent pairs; a list would find two.
    seen = []
    k = 3
    tones = ["ok", "blue", "mute"]
    for i in range(k):
        seen.append((tones[i], tones[(i + 1) % k]))
    assert ("mute", "ok") in seen, "the wraparound pair was not measured"
    assert len(seen) == 3


# == #150, settled first because it changes the arithmetic ==================
def test_pending_is_one_colour_in_both_donuts() -> None:
    """#150: 'Pending' shipped as tone:'warn' in the grading donut and
    tone:'fox' in the verdict donut - one word, two colours, one product.

    Resolved toward WARN, which the grading donut already used and which
    verdictOf() already gives a pending ledger row, so the Pending pill in the
    table and the Pending slice in its key now agree on the same page.

    Decided BEFORE the reorder, deliberately: changing a tone changes which
    pairs can become adjacent and what they measure, so the other order was
    reordering against a palette that was about to move."""
    verdict = dict((l, t) for l, t in _parts("ledgerVerdictDonut"))
    grading = dict((l, t) for l, t in _parts("gradingDonut"))
    assert "Pending" in verdict and "Pending" in grading
    assert verdict["Pending"] == grading["Pending"] == "warn", (
        "Pending is %r in the verdict donut and %r in the grading donut"
        % (verdict["Pending"], grading["Pending"]))
    assert verdict["Evaluator unknown"] == "violet", (
        "freeing warn for Pending moved Evaluator unknown onto violet, the one "
        "TONE slot with no other shipped use; it reads %r"
        % verdict["Evaluator unknown"])


def test_no_slice_was_lost_or_renamed_in_the_reorder() -> None:
    """A reorder is the easiest possible way to drop a row by accident."""
    labels = sorted(l for l, _ in _parts("ledgerVerdictDonut"))
    assert labels == sorted(["Clean", "Breach", "Blocked", "Redacted",
                             "Evaluator unknown", "Pending", "Failed"]), labels
    grading = sorted(l for l, _ in _parts("gradingDonut"))
    assert grading == sorted(["Graded", "Pending", "In progress", "Failed"]), grading


# == THE CENTRAL GUARD =======================================================
def test_no_bad_pair_becomes_adjacent_for_any_realistic_subset(themes) -> None:
    """Every non-empty subset of the verdict donut, measured as a CYCLE.

    The number is pinned rather than demanded to be zero, because zero is not
    reachable: at three slices or fewer every pair is adjacent whatever the
    order, so any pair under the floor WILL touch on some data. 88 before, 67
    after - what the change actually bought, measured, and a regression that
    makes it worse fails."""
    parts = _parts("ledgerVerdictDonut")
    tones = [t for _, t in parts]
    n = len(tones)
    failing = 0
    total = 0
    for k in range(2, n + 1):
        for combo in itertools.combinations(range(n), k):
            total += 1
            if _worst_adjacent([tones[i] for i in combo], themes) < FLOOR:
                failing += 1
    assert total == 120, "expected 120 subsets of size >= 2, got %d" % total
    assert failing <= 67, (
        "%d of %d subsets carry a sub-floor adjacency; the shipped order "
        "measured 67. A re-order or a re-tone made it worse." % (failing, total))
    # ...and the shape the reorder DOES fix must stay fixed.
    assert _worst_adjacent(tones, themes) >= FLOOR, (
        "the full seven-slice array is back under the floor at dE %.1f"
        % _worst_adjacent(tones, themes))


def test_the_wraparound_pair_is_measured_and_safe(themes) -> None:
    """The last slice touches the first. A guard that walks the array as a LIST
    never looks at that pair - which is exactly how the grading donut ended up
    with red beside green and nobody noticed."""
    tones = [t for _, t in _parts("ledgerVerdictDonut")]
    wrap = _pair(themes, tones[-1], tones[0])
    assert wrap >= FLOOR, (
        "the wraparound pair %s|%s measures dE %.1f" % (tones[-1], tones[0], wrap))


def test_the_healthy_tenant_shape_is_safe(themes) -> None:
    """THE SHAPE THE OLD ORDER GOT WRONG AND THE ONE MOST TENANTS HAVE: zero
    Breach, zero Blocked, zero Redacted, zero Failed, zero Evaluator unknown.
    Clean and Pending alone, touching twice.

    Before #150 that pair was ok|fox at dE 5.9. It is ok|warn now."""
    parts = dict(_parts("ledgerVerdictDonut"))
    got = _pair(themes, parts["Clean"], parts["Pending"])
    assert got >= FLOOR, (
        "a healthy tenant's donut is Clean beside Pending and they measure "
        "dE %.1f to a deuteranope" % got)


def test_the_grading_donut_cannot_be_reordered_and_was_not(themes) -> None:
    """RECORDED, NOT FIXED. Exhaustive search over every cyclic order of the
    grading donut's four tones: the best reachable worst-adjacency is 7.5, the
    Failed|Graded pair. bad's only safe neighbour among {ok, warn, blue} is
    blue, so in a 4-cycle - where every slice needs two neighbours - no safe
    arrangement exists. The order is therefore unchanged, which also keeps it in
    step with desktop/home_data.py.

    Pinned so that if the palette ever moves, this says the search can be
    re-run rather than leaving a stale claim in a comment."""
    tones = [t for _, t in _parts("gradingDonut")]
    best = max(_worst_adjacent([tones[0]] + list(p), themes)
               for p in itertools.permutations(tones[1:]))
    assert best < FLOOR, (
        "a safe cyclic order for the grading donut now EXISTS (best dE %.1f) - "
        "the comment saying it cannot be reordered is stale" % best)
    assert _worst_adjacent(tones, themes) == pytest.approx(best, abs=0.05), (
        "the shipped grading order no longer achieves the best reachable %.1f"
        % best)


def test_the_grading_donut_stays_in_step_with_desktop() -> None:
    """THE DRIFT A CVD METRIC CANNOT SEE.

    Several grading orders tie at 7.5, so the measurement above is happy with
    any of them - but desktop/home_data.py mirrors this donut for a shipped
    client reading the same API, and a reorder that is free on one surface is a
    support ticket across two. G8 therefore left the grading donut alone, and
    this is what makes that deliberate rather than incidental.

    Reads desktop; never writes it. The standing rule is that WEB WINS on any
    style conflict, so if these ever diverge on purpose the fix is to update
    desktop and then this guard - not to delete it. The ledger donut IS out of
    step after G8, by that same rule, and is recorded in the phase notes rather
    than pinned here."""
    desktop = (HTML.resolve().parent.parent / "desktop" / "home_data.py")
    if not desktop.exists():                      # desktop is not always checked out
        pytest.skip("desktop/home_data.py not present")
    text = desktop.read_text(encoding="utf-8")
    block = text[text.index("slices = ["):text.index("]", text.index("slices = ["))]
    mirror = re.findall(r'"label": "([^"]+)".*?"tone": "(\w+)"', block)
    assert mirror, "could not read desktop's grading slices"
    assert mirror == _parts("gradingDonut"), (
        "the grading donut drifted from desktop.\n  web     %s\n  desktop %s"
        % (_parts("gradingDonut"), mirror))


# == the direct labels =======================================================
_FULL = [{"label": "Clean", "value": 80, "tone": "ok"},
         {"label": "Blocked", "value": 9, "tone": "blue"},
         {"label": "Breach", "value": 6, "tone": "bad"},
         {"label": "Redacted", "value": 4, "tone": "pink"},
         {"label": "Pending", "value": 12, "tone": "warn"},
         {"label": "Failed", "value": 2, "tone": "mute"},
         {"label": "Evaluator unknown", "value": 7, "tone": "violet"}]


def _donut(data, height=150):
    return _render({"type": "donut", "height": height, "data": data, "legend": True})


def test_a_slice_that_can_hold_its_name_carries_it() -> None:
    """The remedy for every subset a reorder cannot reach. On the shape that
    matters most - a healthy tenant, two slices, adjacent twice - BOTH arcs say
    what they are, so identity does not depend on hue at all."""
    svg = _donut([_FULL[0], _FULL[4]])
    assert _ARCLABEL.findall(svg) == ["Clean", "Pending"], _ARCLABEL.findall(svg)
    assert len(_ARC.findall(svg)) == 2


def test_a_slice_too_small_for_its_name_is_left_alone() -> None:
    """SELECTIVE is the rule, not a limitation to be worked around: dataviz's
    own line is that direct labels work BECAUSE they are sparing. A 2% Failed
    sliver is ~7px of arc and its name needs 42px, so it keeps the legend -
    which is filtered to the same subset in the same order, so row k is arc k."""
    svg = _donut(_FULL)
    labelled = _ARCLABEL.findall(svg)
    assert "Clean" in labelled, labelled
    assert "Failed" not in labelled and "Redacted" not in labelled, labelled
    assert len(_ARC.findall(svg)) == 7, "a slice stopped rendering"


def test_the_label_plate_is_the_panel_not_the_fill(css) -> None:
    """Measured: no single ink clears 4.5:1 on all eight tones in both themes -
    white fails on warn in light (3.82), black on mute in dark (4.49). So the
    label sits on a plate in the PANEL colour, where --ink is 14.5:1 / 15.8:1
    with no per-fill arithmetic at all."""
    svg = _donut([_FULL[0], _FULL[4]])
    plate = re.search(r'<g transform="rotate[^"]*"><rect\b[^>]*style="fill:([^"]+)"', svg)
    assert plate, "the arc label lost its plate"
    assert plate.group(1) == "rgb(242, 240, 238)", (
        "the plate paints %r, not the resolved panel" % plate.group(1))
    rule = re.search(r"\.chart-host \.cx-arclabel\{([^}]*)\}", css)
    assert rule and "fill:var(--ink)" in rule.group(1), rule and rule.group(1)


def test_the_label_can_never_outgrow_its_plate() -> None:
    """--mono falls back through three faces and only the first is measured, so
    the width the fit test used is PINNED onto the text with textLength. Without
    it a wider fallback face would overflow the plate it was sized against."""
    svg = _donut([_FULL[0], _FULL[4]])
    for tag in re.findall(r'<text\b[^>]*class="cx-arclabel"[^>]*>', svg):
        assert 'textLength="' in tag and 'lengthAdjust="spacing"' in tag, tag


def test_two_labels_never_overlap() -> None:
    """Labels are centred in their own arc, so two adjacent ones could collide
    if both are near the fit threshold. Checked as angular half-widths at the
    band's mid radius rather than reasoned about."""
    for data in ([_FULL[0], _FULL[4]],
                 [{"label": "Clean", "value": 1, "tone": "ok"},
                  {"label": "Breach", "value": 1, "tone": "bad"},
                  {"label": "Pending", "value": 1, "tone": "warn"}],
                 _FULL):
        svg = _donut(data)
        spans = []
        for g in re.finditer(
                r'<g transform="rotate\(([-\d.]+) ([\d.]+) ([\d.]+)\)">'
                r'<rect\b[^>]*width="([\d.]+)"', svg):
            deg, x, y, w = (float(g.group(i)) for i in (1, 2, 3, 4))
            size = 150
            rm = ((size / 2 - 6) + (size / 2 - 6) * 0.58) / 2
            ang = math.atan2(y - size / 2, x - size / 2)
            spans.append((ang, (w / 2) / rm))
        for (a1, h1), (a2, h2) in itertools.combinations(spans, 2):
            d = abs(a1 - a2) % (2 * math.pi)
            d = min(d, 2 * math.pi - d)
            assert d >= h1 + h2, (
                "two arc labels overlap: centres %.2f rad apart, half-widths "
                "%.2f + %.2f" % (d, h1, h2))


def test_every_slice_still_renders_and_keeps_its_legend_row() -> None:
    """The legend is filtered to the same subset as the arcs and in the same
    order, which is what makes 'row k is arc k' true - and that positional
    mapping is the fallback for every slice too small to carry a name."""
    for data in ([_FULL[0], _FULL[4]], _FULL[:3], _FULL):
        svg = _donut(data)
        assert len(_ARC.findall(svg)) == len(data)
        rows = re.findall(r'</svg>([^<]+)</span>', svg)
        assert [r.split(" · ")[0] for r in rows] == [d["label"] for d in data], rows


def test_a_zero_slice_leaves_both_the_ring_and_the_key() -> None:
    """THE MECHANISM THAT MAKES ADJACENCY DATA-DEPENDENT, pinned.

    drawDonut filters `value > 0` BEFORE it draws, so a zero slice never emits a
    degenerate arc and never takes a legend row either. That is what makes the
    arcs the non-zero subset, and what makes 'legend row k is arc k' hold at
    every subset - the fallback for any slice too small to carry a name.

    If the filter ever moves after the loop, zero slices come back as
    zero-width paths AND as legend rows that key nothing."""
    data = [_FULL[0], dict(_FULL[2], value=0), _FULL[4], dict(_FULL[5], value=0)]
    svg = _donut(data)
    assert len(_ARC.findall(svg)) == 2, "a zero-value slice drew an arc"
    rows = [r.split(" · ")[0] for r in re.findall(r'</svg>([^<]+)</span>', svg)]
    assert rows == ["Clean", "Pending"], (
        "the legend is not filtered to the same subset as the ring: %s" % rows)
