"""F1 · the focal mark, the segment floor, and three fills that were not marks.

Three separate things share this file because they share one engine and one
harness. Each guard DRIVES the shipped chart helper under node and reads the SVG
it emits — C0's lesson, restated: a static grep over the source executes nothing,
and a deleted forEach once left 369 guards green.

    #112  a stacked segment had no floor, so one High-risk day in a thousand
          drew at 0.1px on the chart whose whole job is finding that day.
    lit   the proposal's "de-emphasise the bars nobody is looking at". Spent on
          type rather than on hue or opacity — see focusIndex()'s note for why
          both of the obvious channels were unavailable.
    #113  --fox and --muted2 were brand/state tokens doing duty as chart marks
          and failed 3:1 in light. --warn-bg is the third and it did NOT move;
          the guard below records the measurement that stopped it.

    python -m pytest foxy-dashboard/test_f1_chart_emphasis.py -q
"""

from __future__ import annotations

import json
import re
import shutil
import subprocess
import tempfile
from pathlib import Path

import pytest

from test_c0_chart_segments import _SHIM, _chart_source
from test_p1_contrast import HTML, css, ratio, themes  # noqa: F401 — fixtures

SRC = HTML.read_text(encoding="utf-8")

pytestmark = pytest.mark.skipif(shutil.which("node") is None,
                                reason="node not on PATH")


def _render(opts: dict) -> str:
    """The SVG the SHIPPED engine emits for these options."""
    probe = (_SHIM + _chart_source()
             + "\nvar parent=El('rgb(242, 240, 238)',null), "
               "host=El('rgba(0, 0, 0, 0)', parent);\n"
             + "window.foxChart(host, " + json.dumps(opts) + ");\n"
             + "console.log(JSON.stringify(host.innerHTML));\n")
    with tempfile.TemporaryDirectory() as tmp:
        path = Path(tmp) / "chart.js"
        path.write_text(probe, encoding="utf-8")
        # encoding="utf-8": text=True alone decodes cp1252 on this machine and
        # turns a correct render into a mystery failure. (C1's lesson.)
        proc = subprocess.run([shutil.which("node"), str(path)],
                              capture_output=True, text=True, encoding="utf-8")
    assert proc.returncode == 0, proc.stderr
    return json.loads(proc.stdout.strip().splitlines()[-1])


_BAR = re.compile(r'<rect\b[^>]*class="cx-bar"[^>]*>')


def _bars(svg: str) -> list[dict]:
    out = []
    for tag in _BAR.findall(svg):
        def attr(name, cast=str):
            hit = re.search(r'\b%s="([^"]*)"' % name, tag)
            return cast(hit.group(1)) if hit else None
        fill = re.search(r"fill:([^;\"]+)", attr("style") or "")
        out.append({"height": attr("height", float), "y": attr("y", float),
                    "fill": fill.group(1).strip() if fill else None,
                    "style": attr("style") or ""})
    assert out, "the engine emitted no bars at all"
    return out


def _texts(svg: str, cls: str) -> list[str]:
    return re.findall(r'<text\b[^>]*class="%s"[^>]*>([^<]*)</text>' % cls, svg)


# ── #112 · a rare event must not render as nothing ──────────────────────────
_ONE_IN_A_THOUSAND = {
    "type": "stacked", "height": 150, "labels": ["a", "b"],
    "series": [{"name": "high", "tone": "bad", "values": [1, 1]},
               {"name": "low", "tone": "ok", "values": [1000, 1000]}]}


def test_a_one_in_a_thousand_segment_is_still_drawable() -> None:
    """THE DEFECT. seg was (v/max)*(H-pb-pt) with no floor, so the single
    High-risk day against a thousand Low ones came out 0.1px tall — in the
    markup, absent from the screen, on "Breaches over time". C0 measured exactly
    this case and recorded it as out of its own scope; the admin engine has
    floored at Math.max(1, ...) since it was written.

    One physical device pixel is the smallest thing a screen can show, so that
    is the floor. This asserts the SHIPPED number, not that a floor exists.
    """
    thin = [b for b in _bars(_render(_ONE_IN_A_THOUSAND)) if b["height"] < 5]
    assert thin, "the 1-in-1000 case drew no small segment at all"
    for b in thin:
        assert b["height"] >= 1.0, (
            "a real High-risk day rendered %spx tall — invisible, on the chart "
            "whose entire job is finding it" % b["height"])


def test_the_floor_only_ever_lifts_a_value_that_is_already_there() -> None:
    """A floor that ran before the `v>0` test would invent a mark for a day
    with no breaches, which is worse than the defect it fixes: a fabricated
    High-risk day on a tamper-evidence product. Two bands, one of them empty on
    the second day — the second column must carry exactly one segment."""
    svg = _render({"type": "stacked", "height": 150, "labels": ["a", "b"],
                   "series": [{"name": "high", "tone": "bad", "values": [3, 0]},
                              {"name": "low", "tone": "ok", "values": [5, 5]}]})
    assert len(_bars(svg)) == 3, (
        "expected 3 segments (2 + 1); a zero drew a mark: %s" % len(_bars(svg)))


def test_the_floor_does_not_overflow_the_plot() -> None:
    """Three floored bands add at most 3px to a column. Asserted rather than
    reasoned about, because an unbounded floor would push the tallest column up
    through the chart's top padding and out of the viewBox."""
    svg = _render({"type": "stacked", "height": 150, "labels": ["a"],
                   "series": [{"name": "h", "tone": "bad", "values": [1]},
                              {"name": "m", "tone": "warn", "values": [1]},
                              {"name": "l", "tone": "ok", "values": [1000]}]})
    tops = [b["y"] for b in _bars(svg)]
    assert min(tops) >= 0, "a floored stack pushed a segment above the viewBox"


# ── the focal mark ──────────────────────────────────────────────────────────
_WEEK = {"type": "bar", "height": 120, "data": [
    {"label": "Su", "value": 4, "tone": "ok"},
    {"label": "Mo", "value": 9, "tone": "bad"},
    {"label": "Tu", "value": 6, "tone": "ok"},
    {"label": "We", "value": 2, "tone": "ok"},
    {"label": "Th", "value": 7, "tone": "bad"},
    {"label": "Fr", "value": 5, "tone": "ok"},
    {"label": "Sa", "value": 8, "tone": "ok"}]}


def test_the_focal_bar_is_named_once_and_carries_its_own_value() -> None:
    """"Spend the emphasis on the one that matters." On ana7d that is today,
    the last bar. One promoted axis label and one direct value — never a number
    on every mark, which is the thing that makes a bar chart unreadable."""
    svg = _render({**_WEEK, "focus": "last"})
    assert _texts(svg, "cx-focus") == ["Sa"], _texts(svg, "cx-focus")
    assert _texts(svg, "cx-val") == ["8"], _texts(svg, "cx-val")
    assert len(_texts(svg, "cx-axis")) == 6, (
        "the other six labels did not stay recessive: %s"
        % _texts(svg, "cx-axis"))


def test_emphasis_never_touches_a_fill() -> None:
    """THE ONE THIS PHASE EXISTS FOR. ana7d already sets tone per bar from
    breaches>0, so hue is spoken for; and de-emphasising the rest by lowering
    opacity or mixing them toward the panel composites a status fill toward the
    background and drops it under 3:1 — register #131, and the same defect #113
    is fixing four lines down. So the fills must come out byte-identical with
    and without a focus, and no bar may carry an opacity at all."""
    plain, lit = _bars(_render(_WEEK)), _bars(_render({**_WEEK, "focus": "last"}))
    assert [b["fill"] for b in plain] == [b["fill"] for b in lit], (
        "the focus repainted the bars")
    for b in lit:
        assert "opacity" not in b["style"], (
            "a bar was de-emphasised by opacity: %r" % b["style"])
        assert "color-mix" not in b["style"], (
            "a bar was mixed toward something; measure it before shipping it")


def test_a_chart_with_no_focus_renders_exactly_as_it_did() -> None:
    """Six of the seven bar charts get no focus, so the no-focus path is the
    common one and must be untouched: same padding, same heights, no stray
    empty label. Compared against an explicitly out-of-range focus, which the
    resolver rejects, so this also proves the rejection reaches the geometry."""
    assert _render(_WEEK) == _render({**_WEEK, "focus": 99}), (
        "an out-of-range focus changed the render")
    assert _render(_WEEK) == _render({**_WEEK, "focus": "today"}), (
        "a focus the resolver cannot read still changed the render")
    assert not _texts(_render(_WEEK), "cx-focus")
    assert not _texts(_render(_WEEK), "cx-val")


def test_a_stacked_focal_label_is_the_column_total() -> None:
    """A stack's bands are the tooltip's job and are already there. The number
    over the column is what the column is worth — anything else would be one
    band's value wearing the whole column's position."""
    svg = _render({"type": "stacked", "height": 180, "labels": ["a", "b"],
                   "series": [{"name": "high", "tone": "bad", "values": [1, 2]},
                              {"name": "low", "tone": "ok", "values": [4, 3]}],
                   "focus": "last"})
    assert _texts(svg, "cx-val") == ["5"], _texts(svg, "cx-val")
    assert _texts(svg, "cx-focus") == ["b"], _texts(svg, "cx-focus")


def test_a_focal_label_is_dropped_rather_than_drawn_over_its_neighbours() -> None:
    """The threats page ranges to 90 days. At that count a bar is ~2px wide and
    a two-digit number over it would sit across three of its neighbours. Below
    the width threshold the promoted axis label carries the emphasis alone."""
    wide = {"type": "bar", "height": 120, "focus": "last",
            "data": [{"label": str(i), "value": i + 1} for i in range(90)]}
    svg = _render(wide)
    assert not _texts(svg, "cx-val"), "a value label was drawn over a 2px bar"
    assert _texts(svg, "cx-focus") == ["89"], "the emphasis vanished entirely"


def test_a_ranking_chart_is_never_given_a_focus() -> None:
    """On a sorted chart the top bar is already first, so lighting it states
    what position has said. drawHBar — the engine behind "top agents" here and
    both admin rankings — takes no focus at all, and asserting that is cheaper
    than asking every future caller to remember."""
    svg = _render({"type": "hbar", "height": 120, "focus": "last", "data": [
        {"label": "a", "value": 9}, {"label": "b", "value": 4}]})
    assert not _texts(svg, "cx-focus") and not _texts(svg, "cx-val"), (
        "the ranking engine grew a focal mark")


def test_the_two_charts_that_were_given_the_treatment_actually_ask_for_it() -> None:
    """GUARD THE USE, not the definition (A6). An engine option nobody passes
    is the whole feature missing while every other guard here stays green."""
    src = SRC
    ana = src[src.index("window.foxChart('ana7d'"):][:400]
    assert "focus:'last'" in ana, "ana7d lost its focal mark: %s" % ana[:200]
    # ⚠ THE EMPTY-STATE CALL COMES FIRST and shares this prefix. A fixed 600-char
    # window off index() covered both while the call was short; G7 added
    # `legend:true` and longer series names and pushed focus:'last' out of it,
    # which reads as "the timeline lost its focal mark". Take the LAST call.
    hits = [m.start() for m in re.finditer(
        re.escape("window.foxChart('threatTimeline',{type:'stacked'"), src)]
    assert len(hits) == 2, "expected an empty-state call and a data call, got %d" % len(hits)
    timeline = src[hits[-1]:hits[-1] + 700]
    assert "series:[" in timeline and "tone:'bad'" in timeline, timeline[:200]
    assert "focus:'last'" in timeline, "the threat timeline lost its focal mark"


# ── #113 · a chart mark is not a brand token ────────────────────────────────
# every panel a chart is hosted on, not just the deepest one: --muted2
# cleared 3:1 on dark --bg and failed on dark --surf, which is where the
# threat timeline actually sits.
_PANELS = ("bg", "surf", "surf2")


# G6 ∙ #132 — the four F1 left behind. --c-2/-4/-5/-6 still aliased
# --dec1/--dec3/--warn-bg/--dec2, which are a decorative FILL and a status
# fill; measured in light against --bg they were 2.57 / 2.16 / 1.74 / 2.25.
@pytest.mark.parametrize("token", ["fox-series", "mute-series",
                                   "blue-series", "pink-series",
                                   "violet-series", "warn-series"])
def test_the_chart_mark_steps_clear_three_to_one_on_every_panel(themes, token):
    """--fox was 2.81:1 against --bg and --muted2 2.61:1, and both were data
    marks — TONE.fox / TONE.brand / --c-1, and TONE.mute. A mark carries no ink,
    so the panel behind it is the only thing it can be measured against.

    Both themes, because _token() defaults to dark and a light-mode failure
    ships green otherwise."""
    for theme, tokens in themes.items():
        for panel in _PANELS:
            got = ratio(tokens[token], tokens[panel])
            assert got >= 3.0, (
                "%s %s on --%s is %.2f:1" % (theme, token, panel, got))


def test_the_brand_and_disabled_tokens_were_left_where_they_were(themes):
    """The fix had to be local. --fox has sixty consumers and --muted2 is this
    stylesheet's declared disabled-only step ("2.61:1, disabled-only, on
    purpose", in the light block's own words) — moving either to satisfy a
    chart would repaint the product to fix six marks. Asserted so a later phase
    does not "simplify" the split back out."""
    assert themes["light"]["fox"] == "#f05700", themes["light"]["fox"]
    assert themes["light"]["muted2"] == "#988e83", themes["light"]["muted2"]
    assert themes["dark"]["fox-series"] == themes["dark"]["fox"], (
        "dark --fox is 7.14:1 on --bg and was supposed to alias through unchanged")
    # --mute-series does NOT alias in dark, and that is the finding: --muted2 is
    # 3.09:1 on dark --bg but 2.90:1 on dark --surf, so the Low band was failing
    # in dark as well. The brief called #113 a light-mode defect; it was not.
    assert themes["dark"]["mute-series"] != themes["dark"]["muted2"]


def test_the_engine_reads_the_series_steps_and_not_the_brand_ones() -> None:
    """GUARD THE BEHAVIOUR. A token nothing resolves to is C4's defect: a guard
    on the definition passes while the mark still paints from --fox. Driven,
    not grepped — the fill is read out of the emitted SVG."""
    fills = {b["fill"] for b in _bars(_render(
        {"type": "bar", "height": 120,
         "data": [{"label": "a", "value": 3, "tone": "fox"},
                  {"label": "b", "value": 2, "tone": "mute"}]}))}
    assert fills == {"var(--fox-series)", "var(--mute-series)"}, fills
    # --c-1 is the first series step, so an unlabelled series lands there too
    default = _bars(_render({"type": "bar", "height": 120,
                             "data": [{"label": "a", "value": 3}]}))
    assert default[0]["fill"] == "var(--c-1)", default[0]["fill"]


def test_the_gauge_no_longer_starts_from_a_fill_that_fails(css) -> None:
    """One element, two verdicts: the gauge is a --fox -> --fox2 gradient, and
    in light its right end cleared 4.73:1 while its left end failed at 2.81:1.
    The stop moves to the series step; --fox2 was already passing and stays."""
    grad = re.search(r'<linearGradient[^>]*>(.*?)</linearGradient>',
                     SRC[SRC.index("function drawGauge"):], re.S)
    assert grad and "--fox-series" in grad.group(1), grad.group(1) if grad else None
    assert "stop-color:var(--fox)\"" not in grad.group(1)


def test_the_threat_legend_swatch_matches_the_band_it_names() -> None:
    """RE-AIMED BY G7 (#151), NOT DELETED — ITS SUBJECT WAS REMOVED, ITS JOB WAS NOT.

    It read the hand-written legend markup and checked Low's swatch named
    --mute-series. Two things were wrong with that. It only ever covered Low, so
    it watched the one swatch that had not drifted while Medium still named
    --warn-bg; and measured in the browser, NONE of those three swatches rendered
    at all — every rule that sizes `.cx-legend i` is scoped to `.chart-host` and
    that div was the chart host's SIBLING, so the legend read
    "High (>=70)Medium (40-69)Low (<40)" with no chips and no gaps.

    G7 deleted the markup and made the engine render the legend, so there is no
    hand-written swatch left to check. The job survives: read the tones out of
    the SHIPPED call, render THAT, and assert each swatch paints exactly what its
    band paints. Now it covers all three, and it is tied to the real call rather
    than to a fixture."""
    from test_g7_band_texture import _SWATCH, _fills, _timeline_call

    call = _timeline_call()
    tones = re.findall(r"tone:'(\w+)'", call)
    assert tones == ["bad", "warn", "mute"], "the shipped bands changed: %s" % tones
    svg = _render({"type": "stacked", "height": 180, "labels": ["d1"],
                   "series": [{"name": n, "tone": t, "values": [6]}
                              for n, t in zip(("High", "Medium", "Low"), tones)],
                   "legend": True})
    assert _SWATCH.findall(svg) == _fills(svg), (
        "legend paints %s, the bands paint %s" % (_SWATCH.findall(svg), _fills(svg)))


# ── #113 · the amber that could not move ────────────────────────────────────
_WARN_PLATES = (".lockchip", ".vstatus.warn .vstatus-ic", ".ltag.warn",
                ".pill.warn", ".sev.med", ".vres.unknown", ".badge.warn")


def test_the_amber_plate_has_an_edge_that_can_be_seen(css, themes) -> None:
    """R2's finding, one console over: a chip whose text cleared 4.5:1 while the
    pill itself sat near 1:1 against the card and dissolved. Here the plate is
    1.74:1 on --bg. The seven all already carried a 1px border and it was --bc,
    the 1.03:1 hairline C0 condemned; --warn-ink replaces it."""
    rule = re.search(r"^%s\{([^}]*)\}" % re.escape(",".join(_WARN_PLATES)),
                     css, re.M)
    assert rule, "the seven amber plates no longer share an edge rule"
    assert "border:1px solid var(--warn-ink)" in rule.group(1), rule.group(1)
    for theme, tokens in themes.items():
        # dark --warn-ink IS --warn-bg, so the ring is a deliberate no-op there
        if theme == "dark":
            assert tokens["warn-ink"] == tokens["warn-bg"]
            continue
        got = ratio(tokens["warn-ink"], tokens["bg"])
        assert got >= 3.0, "light --warn-ink on --bg is %.2f:1" % got


def _deutan(hexcolour: str) -> tuple[float, float, float]:
    """Viénot-Brettel-Mollon deuteranope simulation, sRGB in and out."""
    def lin(c):
        c /= 255
        return c / 12.92 if c <= 0.04045 else ((c + 0.055) / 1.055) ** 2.4
    h = hexcolour.lstrip("#")
    r, g, b = (lin(int(h[i:i + 2], 16)) for i in (0, 2, 4))
    l = 17.8824 * r + 43.5161 * g + 4.11935 * b
    m = 3.45565 * r + 27.1554 * g + 3.86714 * b
    s = 0.0299566 * r + 0.184309 * g + 1.46709 * b
    m = 0.494207 * l + 1.24827 * s                       # the collapsed axis
    return (0.080944 * l - 0.130504 * m + 0.116721 * s,
            -0.0102485 * l + 0.0540194 * m - 0.113615 * s,
            -0.000365294 * l - 0.00412163 * m + 0.693513 * s)


def _oklab(rgb: tuple[float, float, float]) -> tuple[float, float, float]:
    r, g, b = (max(0.0, min(1.0, c)) for c in rgb)
    l = (0.4122214708 * r + 0.5363325363 * g + 0.0514459929 * b) ** (1 / 3)
    m = (0.2119034982 * r + 0.6806995451 * g + 0.1073969566 * b) ** (1 / 3)
    s = (0.0883024619 * r + 0.2817188376 * g + 0.6299787005 * b) ** (1 / 3)
    return (0.2104542553 * l + 0.7936177850 * m - 0.0040720468 * s,
            1.9779984951 * l - 2.4285922050 * m + 0.4505937099 * s,
            0.0259040371 * l + 0.7827717662 * m - 0.8086757660 * s)


def _cvd_gap(a: str, b: str) -> float:
    pa, pb = _oklab(_deutan(a)), _oklab(_deutan(b))
    return 100 * sum((x - y) ** 2 for x, y in zip(pa, pb)) ** 0.5


def test_the_medium_band_still_separates_from_the_high_one(themes) -> None:
    """WHY --warn-bg DID NOT MOVE, and the guard that keeps it that way.

    The obvious fix was R2's: the admin had the identical #F59E0B, measured it
    as a fill and deepened it to #B45309. That value cannot be lifted across,
    because here --warn-bg is also the Medium band of "Breaches over time",
    stacked directly against --breach-bg. Deepening collapses their deuteranope
    separation from dE 19 to 3, on the one chart where the two physically touch
    and the admin has no equivalent. A sweep of 63 (red, amber) pairs found none
    that clears 3:1 against this page AND still separates from the other — the
    two constraints are mutually exclusive in this hue region, so the fill keeps
    its hue and the plate got an edge instead.

    Below 8 is dataviz's floor and it is not reachable with any amber that also
    passes contrast, so failing this means somebody traded the wrong one away.

    ── RE-AIMED BY G7 (#151), NOT DELETED — IT WAS MEASURING A COLOUR NOBODY DREW.

    Everything above is the history. What it did NOT survive is G6 re-pointing
    the band from --warn-bg to --warn-series: this kept reading the old token and
    asserted dE 19.1 while the chart painted 6.6. A green suite over a shipped
    defect, and the second time this file has proved that a guard must measure
    what is EMITTED rather than what is declared.

    The invariant is still right — the two bands touch and the legend cannot undo
    that — but the answer changed. #131 closed the amber sweep, so G7 kept the
    hue and moved identity to a 45/135 deg tone-on-tone hatch. This now asserts
    the invariant in the form that shipped: the pair is distinguishable EITHER on
    hue OR by the texture channel.

    Pull the hatch while the hue still measures 6.6 and this goes red. Find an
    amber that clears 8 on hue alone and it goes green with the hatch gone —
    which is the day the hatch stops being load-bearing. The measurement of the
    ANGLE lives in test_g7_band_texture.py, which rasterises it.
    """
    from test_g7_band_texture import _patterns

    textured = set(_patterns(_render(_STACK_TOUCHING)))
    for theme, tokens in themes.items():
        gap = _cvd_gap(tokens["warn-series"], tokens["breach-bg"])
        if gap >= 8.0:
            continue                                  # hue alone still does it
        assert textured >= {"fxtex-bad-threatTimeline", "fxtex-warn-threatTimeline"}, (
            "%s: Medium and High are dE %.1f apart to a deuteranope, under the "
            "floor of 8, and the bands carry no texture either (%s). They are "
            "stacked segments that touch, and the legend cannot undo that."
            % (theme, gap, sorted(textured) or "none"))


_STACK_TOUCHING = {
    "type": "stacked", "height": 180, "labels": ["d1"],
    "series": [{"name": "High", "tone": "bad", "values": [6]},
               {"name": "Medium", "tone": "warn", "values": [6]},
               {"name": "Low", "tone": "mute", "values": [6]}],
}


def test_the_two_bands_that_touch_are_the_ones_being_measured() -> None:
    """The pair above is only worth guarding while those two tones really do
    stack. Read from the shipped call, so a re-tone of the timeline re-aims this
    file rather than leaving it measuring a pair nobody draws."""
    call = SRC[SRC.index("window.foxChart('threatTimeline',{type:'stacked'"):][:600]
    assert "tone:'bad'" in call and "tone:'warn'" in call, call[:300]


def _block_of(sheet: str, sel: str) -> str:
    """The declaration body of one selector block."""
    i = sheet.index(sel)
    return sheet[i:sheet.index("}", i)]


# ── G6 · #132 · the split F1 started, finished ─────────────────────────────

def test_every_series_slot_reads_a_series_token(css):
    """⚠ THE ALIAS IS THE SUBJECT. --c-2/-4/-5/-6 pointed straight at tokens
    with another job — --dec1/--dec3/--dec2 are decorative fills read by
    .ltag/.pill, and --warn-bg is a status fill carrying --warn-tx as text — so
    a chart could not be re-stepped for paper without repainting them.
    Asserted on the DECLARATION, so a later phase cannot quietly re-point one.
    """
    # ⚠ css is a FIXTURE yielding the stylesheet text, not a callable.
    # Calling it produced pytest's "Fixture called directly" error, which is a
    # broken guard rather than a finding.
    block = _block_of(css, ":root")
    # \u26a0 ALL SIX, WITH THE EXCEPTION NAMED. This enumerated five and skipped
    # --c-3 in silence, which is worse than covering five and saying so: a
    # reader cannot tell an exception from an oversight. --c-3 is --safe-bg,
    # a STATUS fill carrying --safe-tx, and it passes at 3.88:1 against light
    # --bg on its own — so it is left where it is, deliberately, for the same
    # reason --c-5's source was: deepening a fill to rescue a mark breaks the
    # text sitting on it. If it ever fails, it needs a --safe-series, not a
    # nudge.
    for slot, want in (("--c-1", "--fox-series"), ("--c-2", "--blue-series"),
                       ("--c-3", "--safe-bg"),
                       ("--c-4", "--pink-series"), ("--c-5", "--warn-series"),
                       ("--c-6", "--violet-series")):
        m = re.search(re.escape(slot) + r"\s*:\s*var\((--[a-z0-9-]+)\)", block)
        assert m, "%s is no longer an alias at all" % slot
        assert m.group(1) == want, (
            "%s points at %s, not %s — a chart mark reading a fill again"
            % (slot, m.group(1), want))


def test_all_six_series_clear_three_to_one_on_every_panel_in_both_themes(themes):
    """The whole point, measured end to end rather than token by token: what a
    reader sees is --c-N, whatever it is aliased to this week."""
    bad = []
    for theme, tokens in themes.items():
        for n in range(1, 7):
            for panel in _PANELS:
                got = ratio(tokens["c-%d" % n], tokens[panel])
                if got < 3.0:
                    bad.append("%s --c-%d on --%s = %.2f" % (theme, n, panel, got))
    assert not bad, "series marks below 3:1 against their panel: %s" % bad


def test_the_status_and_decorative_sources_were_left_where_they_were(themes, css):
    """The split had to be local. --dec1/2/3 are read by .ltag/.pill fills whose
    near-black ink was chosen for them, and --warn-bg carries --warn-tx on
    .ltag.warn, .pill.warn and .lockchip. Deepening either to rescue a chart
    would have broken the text sitting on it."""
    assert themes["light"]["dec1"] == "#5b8cff", themes["light"]["dec1"]
    assert themes["light"]["dec3"] == "#ff6aa8", themes["light"]["dec3"]
    assert themes["light"]["dec2"] == "#9b8cff", themes["light"]["dec2"]
    assert themes["light"]["warn-bg"] == "#F59E0B", themes["light"]["warn-bg"]
    # \u26a0 AND THE TAGS FOLLOW THE MARKS, which is the opposite of what G6
    # shipped. The verdict donut is the KEY for the ledger list, so a slice and
    # the row it explains have to be one colour; G6 left the tags on --dec* and
    # they stopped matching in light only, silently. The marks are the side with
    # a contrast floor, so the tags moved.
    block = css
    for sel in (".ltag.blocked", ".pill.blocked"):
        assert "%s{background:var(--c-2)" % sel in block, sel
    for sel in (".ltag.redacted", ".pill.redacted"):
        assert "%s{background:var(--c-4)" % sel in block, sel


@pytest.mark.parametrize("token,source", [("blue-series", "dec1"),
                                          ("pink-series", "dec3"),
                                          ("violet-series", "dec2"),
                                          ("warn-series", "warn-bg")])
def test_dark_aliases_through_so_the_dark_theme_is_byte_identical(themes, token, source):
    """F1's rule, kept: a split must not repaint the theme that was already
    right. Dark values alias exactly what they replaced; only light re-steps."""
    assert themes["dark"][token] == themes["dark"][source], (
        "dark --%s stopped aliasing --%s, so the dark theme moved when only "
        "the light one was broken" % (token, source))
    assert themes["light"][token] != themes["light"][source], (
        "light --%s aliases --%s again, which is the failure being fixed"
        % (token, source))


# ── G6.1 · A TOKEN THAT DOES NOT REACH A MARK IS NOT A FIX ─────────────────

def _g61_tone_map(css: str) -> dict:
    """The shipped TONE map — what actually decides a mark's colour."""
    body = re.search(r"var TONE=\{(.*?)\};", css if "var TONE=" in css
                     else HTML.read_text(encoding="utf-8"), re.S).group(1)
    return dict(re.findall(r"(\w+):'([^']+)'", body))


def test_every_tone_a_shipped_call_names_resolves_to_a_passing_mark(themes):
    """⚠ THE CENSUS, NOT THE DECLARATION.

    G6 declared --warn-series and --violet-series, aliased them into --c-5 and
    --c-6, and guarded both — and neither ever painted anything, because every
    series on this surface names a TONE and TONE.warn still pointed at
    --warn-bg. The amber that justified finding the fourth token kept drawing
    at 1.74:1.

    So this walks the tones SHIPPED CALLS ACTUALLY NAME and measures what each
    resolves to. A token nobody routes cannot pass here, because it is not
    reached.
    """
    src = HTML.read_text(encoding="utf-8")
    tone_map = _g61_tone_map(src)
    named = sorted(set(re.findall(r"tone:'(\w+)'", src)))
    assert named, "no shipped call names a tone — this guard is measuring nothing"
    bad = []
    for theme, tokens in themes.items():
        for t in named:
            v = tone_map.get(t)
            assert v, "a shipped call names tone %r with no TONE entry" % t
            key = re.fullmatch(r"var\((--[a-z0-9-]+)\)", v).group(1)[2:]
            for panel in _PANELS:
                r = ratio(tokens[key], tokens[panel])
                if r < 3.0:
                    bad.append("%s tone:%s -> --%s on --%s = %.2f"
                               % (theme, t, key, panel, r))
    assert not bad, "drawn marks below 3:1 against their panel: %s" % bad


def test_the_warn_tone_routes_to_the_series_step_not_the_status_fill(themes):
    """The blocker, pinned by name. --warn-bg carries --warn-tx as text on
    .ltag.warn and .lockchip, so it cannot be deepened; the chart needed its
    own step and then nothing pointed at it."""
    tone_map = _g61_tone_map(HTML.read_text(encoding="utf-8"))
    assert tone_map["warn"] == "var(--warn-series)", (
        "TONE.warn is %r — the amber the split exists for is not being drawn"
        % tone_map["warn"])
    assert tone_map.get("violet") == "var(--c-6)", (
        "there is no violet tone, so slot 6 is unreachable by name: %r"
        % tone_map.get("violet"))
    # dark must not have moved
    assert themes["dark"]["warn-series"] == themes["dark"]["warn-bg"], (
        "dark --warn-series stopped aliasing --warn-bg, so re-routing the tone "
        "repainted the theme that was already right")


def test_the_tag_ink_follows_its_fill_into_the_light_theme(themes, css):
    """The half that is easy to forget when a fill deepens.

    Near-black was chosen for a PALE tag; on the deepened light fills it
    measures 3.45:1 and 2.78:1, below AA on the ledger rows an operator reads.
    White clears 5.39:1 and 6.15:1 — the same move this theme already makes for
    every deep status fill. Asserted as a MEASUREMENT, not as the presence of a
    rule: a `color:#fff` that never wins the cascade would satisfy a grep.
    """
    assert 'html[data-theme="light"] .ltag.blocked' in css, (
        "the light-theme tag ink override is gone, so near-black sits on a "
        "mid-dark fill")
    for slot, ink in (("c-2", "#ffffff"), ("c-4", "#ffffff")):
        got = ratio(ink, themes["light"][slot])
        assert got >= 4.5, (
            "light tag ink on --%s is %.2f:1" % (slot, got))
    # and dark keeps the near-black it was chosen for
    for slot, ink in (("c-2", "#04122e"), ("c-4", "#3a0620")):
        got = ratio(ink, themes["dark"][slot])
        assert got >= 4.5, (
            "dark tag ink on --%s is %.2f:1 — the dark theme moved when only "
            "light needed to" % (slot, got))
