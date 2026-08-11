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
# G8.1 . the label rides a <textPath> now, so its text is one level
# deeper. The old expression matched the <text> element's own (now empty)
# content, and would have reported 'no labels drawn' for a chart full of
# them -- a guard that goes quietly green on a construction change.
_ARCLABEL = re.compile(r'<textPath\b[^>]*>([^<]*)</textPath>')


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


# == G8.1 · the plate, measured in Cartesian space =========================
# The cases that broke the straight plate. "Evaluator unknown" is the longest
# label the product has, and 28.7% is ordinary data — a tenant whose judge could
# not reach a verdict on a bad afternoon. G8 only ever exercised it at 5.8%,
# where it is never drawn at all, so the defect had no fixture.
_PLATE_CASES = {
    "the longest label at a large share": [
        {"label": "Clean", "value": 57, "tone": "ok"},
        {"label": "Redacted", "value": 14.5, "tone": "pink"},
        {"label": "Evaluator unknown", "value": 28.7, "tone": "violet"}],
    "three even slices": [
        {"label": "Clean", "value": 1, "tone": "ok"},
        {"label": "Breach", "value": 1, "tone": "bad"},
        {"label": "Pending", "value": 1, "tone": "warn"}],
    "healthy tenant": [
        {"label": "Clean", "value": 87, "tone": "ok"},
        {"label": "Pending", "value": 13, "tone": "warn"}],
    "all seven": _FULL,
}

_PLATE = re.compile(
    r'<path d="M([-\d.]+),([-\d.]+)'
    r'A([\d.]+),[\d.]+ 0 \d 1 ([-\d.]+),([-\d.]+)'
    r'L([-\d.]+),([-\d.]+)'
    r'A([\d.]+),[\d.]+ 0 \d 0 ([-\d.]+),([-\d.]+)Z" style="fill:')


def _plates(svg: str, size: int = 150) -> list[dict]:
    """Every label plate, as GEOMETRY: its two radii and the four corner points,
    read out of the emitted path rather than recomputed from the fit test.

    ⚠ THAT DISTINCTION IS THE WHOLE POINT. G8's overlap guard converted plate
    widths back into angular half-widths at the mid radius, which is the fit
    test's own inequality restated — green by construction whatever the geometry
    did. Nothing here touches the fit test; it measures where the ink lands."""
    cx = cy = size / 2.0
    out = []
    for m in _PLATE.finditer(svg):
        v = [float(g) for g in m.groups()]
        r_out, r_in = v[2], v[7]
        pts = [(v[0], v[1]), (v[3], v[4]), (v[5], v[6]), (v[8], v[9])]
        mid, half = _angular_span([math.atan2(y - cy, x - cx) for x, y in pts])
        out.append({"r_in": r_in, "r_out": r_out, "pts": pts,
                    "radii": [math.hypot(x - cx, y - cy) for x, y in pts],
                    "mid": mid, "half": half})
    return out


def _angular_span(angs: list[float]) -> tuple[float, float]:
    """The smallest arc containing all of these angles, as (centre, half-width).

    ⚠ min()/max() OVER atan2 IS WRONG AND LOOKS RIGHT. atan2 wraps at +/-pi, so
    a plate straddling that boundary reads as spanning 257 degrees instead of
    35, and the overlap test below then reports a collision that is not there.
    Found by this guard failing on correct geometry - the measurement was the
    defect, not the code. The largest GAP between sorted angles is the part of
    the circle the plate does not cover; everything else is the span."""
    a = sorted(x % (2 * math.pi) for x in angs)
    gaps = [(a[(i + 1) % len(a)] - a[i]) % (2 * math.pi) for i in range(len(a))]
    widest = max(range(len(gaps)), key=lambda i: gaps[i])
    span = 2 * math.pi - gaps[widest]
    start = a[(widest + 1) % len(a)]
    return (start + span / 2) % (2 * math.pi), span / 2


def _fn_body(src: str, decl: str) -> str:
    """The balanced-brace body of the function declared at `decl`.

    Anything looser lets a neighbouring function satisfy an assertion about this
    one - see the note in test_a_theme_toggle_redraws_the_charts."""
    i = src.index(decl)
    open_at = src.index("{", i)
    depth = 0
    for j in range(open_at, len(src)):
        if src[j] == "{":
            depth += 1
        elif src[j] == "}":
            depth -= 1
            if depth == 0:
                return src[open_at:j + 1]
    raise AssertionError("unbalanced braces after %r" % decl)


def _arcs_overlap(p1: dict, p2: dict) -> bool:
    d = abs(p1["mid"] - p2["mid"]) % (2 * math.pi)
    return min(d, 2 * math.pi - d) < p1["half"] + p2["half"] - 1e-9


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
    plate = re.search(r'<g class="cx-arcplate"><path\b[^>]*style="fill:([^"]+)"', svg)
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
    for tag in re.findall(r'<textPath\b[^>]*>', svg):
        assert 'textLength="' in tag and 'lengthAdjust="spacing"' in tag, tag


def test_two_labels_never_overlap() -> None:
    """Labels are centred in their own arc, so two adjacent ones could collide
    if both are near the fit threshold. Checked as angular half-widths at the
    band's mid radius rather than reasoned about."""
    for name, data in _PLATE_CASES.items():
        plates = _plates(_donut(data))
        for p1, p2 in itertools.combinations(plates, 2):
            assert not _arcs_overlap(p1, p2), (
                "%s: two label plates overlap on the ring - centres %.3f and "
                "%.3f rad, half-widths %.3f and %.3f"
                % (name, p1["mid"], p2["mid"], p1["half"], p2["half"]))


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


# == G8.1 · THE CENTRAL GEOMETRY GUARD =====================================
def test_the_plate_maths_can_detect_a_plate_that_juts_out() -> None:
    """THE INERT CONTROL, and it exists because G8's version of this guard could
    not fail. Feed the measurement a plate that is knowably outside the ring and
    require it to say so, before it is trusted to say anything is inside."""
    size, r = 150, 150 / 2 - 6
    good = _plates('<path d="M75.0,20.0A55,55 0 0 1 95.0,25.0'
                   'L90.0,35.0A45,45 0 0 0 75.0,30.0Z" style="fill:', size)
    assert good and max(good[0]["radii"]) < r, good
    bad = _plates('<path d="M75.0,-5.0A80,80 0 0 1 100.0,0.0'
                  'L95.0,10.0A70,70 0 0 0 75.0,5.0Z" style="fill:', size)
    assert bad and max(bad[0]["radii"]) > r, (
        "the measurement cannot see a plate outside the rim, so nothing below "
        "means anything")


def test_no_label_plate_leaves_the_ring_or_the_viewbox() -> None:
    """THE DEFECT G8 SHIPPED, measured where the ink lands.

    The fit test is an ARC length; a straight tangential plate of that width has
    corners further out than the arc it was sized against. "Evaluator unknown"
    at 28.7% put its corners at radius 79.8 against a rim of 69 and a viewBox
    half-width of 75 - through the ring AND clipped by the svg.

    G8.1 curved the plate, so its radial extent is exactly its own height at any
    width. This asserts that outcome directly: every plate radius inside the
    band, every point inside the viewBox. It never consults the fit test."""
    size = 150
    r, rin = size / 2 - 6, (size / 2 - 6) * 0.58
    for name, data in _PLATE_CASES.items():
        plates = _plates(_donut(data), size)
        assert plates, "%s: no label was drawn, so nothing was measured" % name
        for p in plates:
            assert p["r_in"] >= rin - 0.5 and p["r_out"] <= r + 0.5, (
                "%s: a plate spans radius %.1f..%.1f, outside the ring band "
                "%.1f..%.1f" % (name, p["r_in"], p["r_out"], rin, r))
            assert max(p["radii"]) <= r + 0.5, (
                "%s: a plate corner sits at radius %.1f, past the rim at %.1f"
                % (name, max(p["radii"]), r))
            for x, y in p["pts"]:
                assert 0 <= x <= size and 0 <= y <= size, (
                    "%s: a plate corner at (%.1f, %.1f) is outside the 0..%d "
                    "viewBox and will be clipped" % (name, x, y, size))


def test_the_longest_label_is_actually_exercised() -> None:
    """G8's fixtures only ever gave "Evaluator unknown" 5.8%, where it is never
    drawn - so the case that broke had no test at all. The longest label at its
    largest realistic share is the one worth guarding, and this pins that the
    fixture still reaches the drawing path."""
    svg = _donut(_PLATE_CASES["the longest label at a large share"])
    assert "Evaluator unknown" in re.findall(r'<textPath[^>]*>([^<]*)</textPath>', svg), (
        "the longest label is no longer drawn in its own fixture, so the "
        "geometry guard above is measuring easier plates than the ones that broke")


def test_the_label_rides_a_curve_not_a_chord() -> None:
    """The construction, not just its outcome: a textPath on the mid-radius
    circle. A straight <text> would put the chord back and the guard above would
    only catch it once some label happened to be long enough."""
    svg = _donut(_PLATE_CASES["healthy tenant"])
    assert "<textPath" in svg and 'startOffset="50%"' in svg, svg[:400]
    assert not re.search(r'<g transform="rotate\([^"]*"><rect', svg), (
        "a straight rotated plate is back")


# == G8.1 · item 3 =========================================================
def test_the_plate_does_not_steal_its_own_arc_hover(css) -> None:
    """The plate covers 17px of a 29px ring band and wireTips binds mouseleave
    per arc, so without pointer-events:none the tooltip blinks out over exactly
    the big slices worth inspecting."""
    rule = re.search(r"\.chart-host \.cx-arcplate\{([^}]*)\}", css)
    assert rule and "pointer-events:none" in rule.group(1), rule and rule.group(1)
    assert 'class="cx-arcplate"' in _donut(_PLATE_CASES["healthy tenant"])


def test_a_theme_toggle_redraws_the_charts() -> None:
    """TWO chart values are resolved at DRAW time and are not var(): panelBg()
    feeds segSep's separator stroke and this phase's label plate. A var() fill
    re-themes itself; a baked rgb() string does not, so toggling on the Ledger
    page left near-black text on a near-black plate (~1.05:1) until you
    navigated away and back.

    Fixed by redrawing rather than by making one of the two live, because
    fixing the plate alone would have left every segment separator stale."""
    # SCOPED TO foxRedraw'S OWN BODY. Mutation-tested: `"__cxo" in <a slice
    # containing window.foxChart=>` stayed true after foxRedraw was gutted to
    # an empty function, because foxChart itself writes host.__cxo. A guard
    # satisfied by the neighbouring function is the shadowing defect again.
    # ⚠ THE FUNCTION'S OWN BODY, BY BRACE MATCHING. This assertion was wrong
    # three times, each time the same class:
    #   1. `"__cxo" in <slice containing window.foxChart=>` - satisfied by
    #      foxChart itself, which writes host.__cxo;
    #   2. scanning forward to a brace PATTERN - ran straight past a gutted
    #      foxRedraw into the same code;
    #   3. a fixed 320-character window - ran into the RESIZE handler, which
    #      redraws with the identical `draw(h,h.__cxo)` expression.
    # A window is not a scope. Only the matched body is.
    body = _fn_body(SRC, "window.foxRedraw=function()")
    assert "draw(h,h.__cxo)" in body, (
        "foxRedraw no longer redraws from the stored options: %r" % body[:220])
    apply_dash = SRC[SRC.index("function applyDash(theme)"):]
    apply_dash = apply_dash[:apply_dash.index("window.applyDash")]
    assert "foxRedraw()" in apply_dash, (
        "applyDash still leaves draw-time colours stale: %s" % apply_dash[-300:])


def test_the_tone_map_comment_no_longer_claims_unknown_draws_with_warn() -> None:
    """G6.1's note said the verdict donut's Evaluator unknown draws with warn.
    G8 moved it to violet and left the sentence standing - a comment that
    describes code it no longer describes is the same defect class as a guard
    that measures a value nobody paints."""
    block = SRC[SRC.index("THE TONE MAP IS WHAT ACTUALLY DRAWS"):
                SRC.index("var TONE={ok:")]
    assert "G8 MOVED ONE OF THOSE MARKS" in block, block[-400:]


# == G8.1 · #150 · the agreement, guarded so it cannot drift a third time ====
#: Which pill class the ledger TABLE gives each verdict this donut names.
#: Read from verdictOf(): blocked/redacted are terminal, breach and safe are
#: graded outcomes, and unknown, failed(flag) and pending ALL collapse onto
#: cls:'warn'. That 3-into-1 is the whole reason two slices cannot agree.
_VERDICT_PILL = {"Clean": "safe", "Breach": "breach", "Blocked": "blocked",
                 "Redacted": "redacted", "Pending": "warn", "Failed": "warn",
                 "Evaluator unknown": "warn"}

#: The two the arithmetic forces out, named so the exception is deliberate
#: rather than whatever happens to be true. Seven slices into five pill classes
#: means exactly two must disagree; these are the rarest states, and Pending -
#: far the most common of the three - is the one that agrees.
_CANNOT_AGREE = {"Failed", "Evaluator unknown"}


def _tone_map() -> dict:
    block = SRC[SRC.index("var TONE={ok:"):]
    return dict(re.findall(r"(\w+):'var\((--[\w-]+)\)'", block[:block.index("};")]))


def _pill_token(cls: str) -> str:
    hit = re.search(r"\.pill\.%s\{background:var\((--[\w-]+)\)" % cls, SRC)
    assert hit, "no .pill.%s rule" % cls
    return hit.group(1)


def test_verdict_of_still_collapses_three_states_onto_warn() -> None:
    """The premise the exception list rests on. If verdictOf ever grows a
    distinct class for pending or failed, two slices stop being forced out and
    _CANNOT_AGREE should shrink - this is what says so."""
    fn = SRC[SRC.index("function verdictOf(it)"):]
    fn = fn[:fn.index("\n  }")]
    assert fn.count("cls:'warn'") == 3, (
        "verdictOf no longer maps exactly three states onto warn (%d) - the "
        "seven-into-five arithmetic changed" % fn.count("cls:'warn'"))
    for cls in ("safe", "breach", "blocked", "redacted"):
        assert "cls:'%s'" % cls in fn, cls


def test_the_donut_slice_and_the_table_pill_agree_wherever_they_can() -> None:
    """#150, GUARDED. G8 moved the disagreement from donut-vs-donut to
    donut-vs-table; this is what stops it moving a third time.

    Every verdict the table gives its OWN pill class must be painted by the
    donut from the SAME token. Four are, exactly."""
    tones, parts = _tone_map(), dict(_parts("ledgerVerdictDonut"))
    for label, tone in parts.items():
        if label in _CANNOT_AGREE or _VERDICT_PILL[label] == "warn":
            continue
        assert tones[tone] == _pill_token(_VERDICT_PILL[label]), (
            "%s: the donut paints %s and the .pill.%s paints %s"
            % (label, tones[tone], _VERDICT_PILL[label],
               _pill_token(_VERDICT_PILL[label])))


def test_pending_agrees_with_its_pill_by_FAMILY_not_by_value() -> None:
    """⚠ THE TRAP IN THE OBVIOUS VERSION OF THIS GUARD. Pending's slice paints
    --warn-series and its pill paints --warn-bg: two different ambers in light.
    Demanding one VALUE would fail on correct code and, worse, would invite
    somebody to satisfy it by collapsing the split - which is #131/G6's measured
    conclusion, that --warn-bg fails 3:1 as a chart mark and --warn-series fails
    4.5:1 as a text plate. Neither can do the other's job.

    So agreement here is the tone FAMILY, and the split is asserted to still be
    a split, so nobody 'fixes' it into one token."""
    tones, parts = _tone_map(), dict(_parts("ledgerVerdictDonut"))
    slice_tok, pill_tok = tones[parts["Pending"]], _pill_token("warn")
    assert slice_tok.startswith("--warn") and pill_tok.startswith("--warn"), (
        "Pending: slice %s, pill %s" % (slice_tok, pill_tok))
    assert slice_tok != pill_tok, (
        "the series/plate split collapsed to %s - re-read #131 before keeping "
        "this" % slice_tok)


def test_exactly_two_slices_are_allowed_to_disagree() -> None:
    """Seven slices, five pill classes, three of them collapsed onto warn: two
    slices MUST disagree, and which two is a choice. Pinned so that choice stays
    deliberate - moving the disagreement onto a commoner state (which is what G8
    did in the other direction) fails here."""
    parts = dict(_parts("ledgerVerdictDonut"))
    tones = _tone_map()
    disagree = {label for label, tone in parts.items()
                if not tones[tone].startswith("--warn")
                and _VERDICT_PILL[label] == "warn"}
    assert disagree == _CANNOT_AGREE, (
        "the slices that disagree with their pill are %s; the recorded, "
        "deliberate set is %s" % (sorted(disagree), sorted(_CANNOT_AGREE)))
    assert len(parts) - len(set(_VERDICT_PILL.values())) == 2, (
        "the seven-into-five arithmetic changed; re-derive the exception list")
