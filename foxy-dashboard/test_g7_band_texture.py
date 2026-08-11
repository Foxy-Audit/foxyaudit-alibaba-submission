"""G7 · #151 — the risk band stops depending on hue.

`--warn-series` #b8730d against `--breach-bg` #DC2626 is dE 3.3 to a deuteranope
by dataviz's validator, 6.6 by this repo's own Vienot `_cvd_gap`; the floor is 8.
#131 closed the search for another amber — none clears 3:1 against this panel AND
separates from breach-red - so the fill keeps its hue and identity moved to a
channel that is not colour: a tone-on-tone hatch, 45 deg for High and its 135 deg
mirror for Medium.

**THE CENTRAL GUARD IS A MEASUREMENT.** `test_the_two_bands_separate_by_stripe_
angle_to_a_deuteranope` rasterises the paint the engine actually emitted, runs
every pixel through the deuteranope simulation, and reads the dominant gradient
orientation out of the result with a structure tensor. It asserts the two bands
are 90 deg apart *in simulated-CVD space*. Nothing here asserts that a `<pattern>`
element exists.

That distinction is the whole reason this file is shaped the way it is. This
project has shipped a `--bc` separator that existed in the markup and measured
1.03:1; G6 shipped two tokens that were declared, aliased, guarded, and never
painted; and the legend this phase replaced named a token the chart had stopped
drawing while none of its three swatches rendered at all. A guard that reads a
declaration would have passed through every one of those.

Everything is parsed out of the SHIPPED engine's output via `_render`, so a
re-tone, a re-angle, or a paint that stops reaching the rect re-aims this file
rather than leaving it measuring something nobody draws.
"""

from __future__ import annotations

import math
import re
import shutil

import pytest

from test_f1_chart_emphasis import _deutan, _oklab, _render, _cvd_gap
from test_p1_contrast import HTML, css, ratio, themes  # noqa: F401 - fixtures

SRC = HTML.read_text(encoding="utf-8")

pytestmark = pytest.mark.skipif(shutil.which("node") is None,
                                reason="node not on PATH")

# The panel `_render`'s shim reports, and therefore the one segSep draws against.
PANEL_LIGHT = "#f2f0ee"

_THREE_BANDS = {
    "type": "stacked", "height": 180, "labels": ["d1", "d2"],
    "series": [{"name": "High", "tone": "bad", "values": [6, 6]},
               {"name": "Medium", "tone": "warn", "values": [6, 6]},
               {"name": "Low", "tone": "mute", "values": [6, 6]}],
    "legend": True,
}

# Anchored to the tag NAME, not to attribute order: S() emits attributes in
# object-key order, so an expression anchored to `<pattern id=...` in a fixed
# sequence silently matches nothing and reads as "the engine drew no texture".
_PATTERN = re.compile(
    r'<pattern\b(?=[^>]*\bid="(?P<id>[^"]+)")(?=[^>]*\bwidth="(?P<tile>[\d.]+)")'
    r'(?=[^>]*\bpatternTransform="rotate\((?P<angle>[\d.]+)\)")[^>]*>'
    r'\s*<rect\b(?=[^>]*\bwidth="(?P<basew>[\d.]+)")[^>]*style="fill:(?P<base>[^"]+)"\s*/>'
    r'\s*<rect\b(?=[^>]*\bwidth="(?P<barw>[\d.]+)")[^>]*style="fill:(?P<ink>[^"]+)"\s*/>'
    r'\s*</pattern>')
_BAR = re.compile(r'<rect\b[^>]*class="cx-bar"[^>]*>')
_SWATCH = re.compile(r'<svg\b[^>]*class="cx-sw"[^>]*>\s*<rect\b[^>]*style="fill:([^"]+)"\s*/>\s*</svg>')


# ══ reading what the engine emitted ═════════════════════════════════════════
def _patterns(svg: str) -> dict[str, dict]:
    out = {}
    for m in _PATTERN.finditer(svg):
        out[m["id"]] = {"tile": float(m["tile"]), "angle": float(m["angle"]),
                        "base": m["base"], "bar": float(m["barw"]), "ink": m["ink"]}
    return out


def _fills(svg: str) -> list[str]:
    """The `fill:` of every data mark, in draw order."""
    out = []
    for tag in _BAR.findall(svg):
        style = re.search(r'style="([^"]*)"', tag)
        hit = re.search(r"fill:([^;\"]+)", style.group(1) if style else "")
        out.append(hit.group(1).strip() if hit else None)
    assert out, "the engine emitted no bars at all"
    return out


def _heights(svg: str) -> list[float]:
    return [float(re.search(r'height="([\d.]+)"', t).group(1)) for t in _BAR.findall(svg)]


def _timeline_call() -> str:
    """The threatTimeline call that carries DATA.

    `window.foxChart('threatTimeline',{type:'stacked'` appears TWICE — the empty
    state fires first and has `series:[]`. An index() anchored on the shared
    prefix lands on the empty one, and every assertion about tones and labels
    then passes or fails on the wrong call."""
    hits = [m.start() for m in re.finditer(
        re.escape("window.foxChart('threatTimeline',{type:'stacked'"), SRC)]
    assert len(hits) == 2, "expected an empty-state call and a data call, got %d" % len(hits)
    call = SRC[hits[-1]:hits[-1] + 700]
    assert "tone:'bad'" in call, "the last threatTimeline call carries no series"
    return call


def _token(theme_map: dict, paint: str) -> str:
    hit = re.fullmatch(r"var\((--[\w-]+)\)", paint.strip())
    assert hit, "expected a var() paint, got %r" % paint
    return theme_map[hit.group(1).lstrip("-")]


# ══ rasterising it, exactly as SVG would ════════════════════════════════════
def _pixel(pat: dict, theme_map: dict, x: float, y: float) -> tuple[float, float, float]:
    """The colour SVG paints at (x, y) for a rect filled with this pattern.

    patternTransform rotates pattern space, so a user-space point maps into the
    tile through the INVERSE rotation; the tile then repeats on x. Composites the
    ink over the base at its own alpha, which is what makes the stripe a darker
    step of the band's own colour rather than a second hue."""
    base = _token(theme_map, pat["base"])
    r, g, b = (int(base.lstrip("#")[i:i + 2], 16) for i in (0, 2, 4))
    a = math.radians(-pat["angle"])
    u = (x * math.cos(a) - y * math.sin(a)) % pat["tile"]
    if u < pat["bar"]:
        alpha = float(re.fullmatch(r"rgba\(0,\s*0,\s*0,\s*([\d.]+)\)", pat["ink"]).group(1))
        return (r * (1 - alpha), g * (1 - alpha), b * (1 - alpha))
    return (float(r), float(g), float(b))


def _deutan_luma_field(pat: dict, theme_map: dict, n: int = 48) -> list[list[float]]:
    """An n x n patch of the band as a DEUTERANOPE sees it, in OKLab lightness."""
    field = []
    for y in range(n):
        row = []
        for x in range(n):
            px = _pixel(pat, theme_map, x, y)
            sim = _deutan("#%02x%02x%02x" % tuple(round(max(0, min(255, c))) for c in px))
            row.append(_oklab(tuple(max(0.0, min(1.0, c)) for c in sim))[0])
        field.append(row)
    return field


def _orientation(field: list[list[float]]) -> float:
    """Dominant gradient orientation in degrees, 0-180, by structure tensor.

    Stripes run perpendicular to their luminance gradient, so two hatches whose
    ARMS are 90 deg apart give gradient orientations 90 deg apart too."""
    n, jxx, jyy, jxy = len(field), 0.0, 0.0, 0.0
    for y in range(1, n - 1):
        for x in range(1, n - 1):
            gx = field[y][x + 1] - field[y][x - 1]
            gy = field[y + 1][x] - field[y - 1][x]
            jxx += gx * gx
            jyy += gy * gy
            jxy += gx * gy
    return math.degrees(0.5 * math.atan2(2 * jxy, jxx - jyy)) % 180


def _apart(a: float, b: float) -> float:
    d = abs(a - b) % 180
    return min(d, 180 - d)


def _stripe_gap(pat: dict, theme_map: dict) -> float:
    """How far the stripe is from the fill it is drawn on, to a deuteranope.

    Scanned rather than sampled at two points: the tile is rotated, so a fixed
    (x, y) pair lands inside the stripe for one angle and outside it for the
    other. That mistake reads as 'the 135 deg hatch has no ink at all'."""
    seen = {}
    for y in range(12):
        for x in range(12):
            px = _pixel(pat, theme_map, x, y)
            seen["#%02x%02x%02x" % tuple(round(max(0, min(255, c))) for c in px)] = None
    tones = list(seen)
    assert len(tones) == 2, "expected a fill and an ink, found %s" % tones
    return _cvd_gap(tones[0], tones[1])


# ══ the inert control ═══════════════════════════════════════════════════════
def test_the_orientation_maths_is_right() -> None:
    """Pin the measurement on inputs whose answer is known before it judges
    anything. A broken structure tensor tends to return a constant, which would
    make the central guard below pass on two identical hatches."""
    def synthetic(deg: float, n: int = 48) -> list[list[float]]:
        a = math.radians(-deg)
        return [[1.0 if ((x * math.cos(a) - y * math.sin(a)) % 6) < 2.1 else 0.0
                 for x in range(n)] for y in range(n)]
    assert abs(_orientation(synthetic(45.0)) - 45.0) < 2.0
    assert abs(_orientation(synthetic(135.0)) - 135.0) < 2.0
    assert _apart(_orientation(synthetic(45.0)), _orientation(synthetic(135.0))) > 85.0
    # ...and two of the SAME angle must read as no separation at all.
    assert _apart(_orientation(synthetic(45.0)), _orientation(synthetic(45.0))) < 2.0


# ══ THE CENTRAL GUARD ═══════════════════════════════════════════════════════
def test_the_two_bands_separate_by_stripe_angle_to_a_deuteranope(themes) -> None:
    """High and Medium are 90 deg apart IN SIMULATED-CVD SPACE, both themes.

    Rasterised from the emitted pattern and measured after the deuteranope
    simulation, so it fails if the hatch stops being painted, if the two angles
    converge, if the ink loses enough contrast to stop forming a gradient, or if
    a later phase points the rect at a paint that carries no texture.

    90 deg is the whole separation the channel has: 45 and its 135 mirror are the
    only two angles dataviz allows (horizontal and vertical read as gridlines and
    bars). 80 is the floor here - anything that measures below it has lost most
    of the channel, and the hue underneath it is dE 3.3."""
    svg = _render(_THREE_BANDS)
    pats = _patterns(svg)
    assert set(pats) == {"fxtex-bad-threatTimeline", "fxtex-warn-threatTimeline"}, (
        "expected exactly the High and Medium hatches, got %s" % sorted(pats))

    # ⚠ A DEFINED PATTERN IS NOT A PAINTED ONE. Mutation-tested: stubbing
    # bandPaint so no bar ever returns url(#...) left the <defs> intact and this
    # test green. That is the exact defect class this file exists for, so the
    # measurement is only allowed to proceed on patterns a bar actually uses.
    painted = {re.search(r"url\(#([^)]+)\)", f).group(1) for f in _fills(svg) if "url(" in f}
    assert painted == set(pats), (
        "the engine defines %s but the bands paint %s" % (sorted(pats), sorted(painted)))

    for theme, tokens in themes.items():
        # ⚠ ORIENTATION IS SCALE-INVARIANT. Also mutation-tested: dropping the ink
        # to rgba(0,0,0,.01) keeps the angle perfectly measurable while making the
        # stripe invisible. So the arms have to clear the same floor the hue
        # failed — a texture nobody can see is not a channel.
        for pid, pat in pats.items():
            amp = _stripe_gap(pat, tokens)
            assert amp >= 8.0, (
                "%s %s: the stripe is only dE %.1f from its own fill to a "
                "deuteranope. The angle is still 90 deg apart and completely "
                "unreadable." % (theme, pid, amp))
    for theme, tokens in themes.items():
        hi = _orientation(_deutan_luma_field(pats["fxtex-bad-threatTimeline"], tokens))
        med = _orientation(_deutan_luma_field(pats["fxtex-warn-threatTimeline"], tokens))
        gap = _apart(hi, med)
        assert gap >= 80.0, (
            "%s: High and Medium read %.1f deg and %.1f deg to a deuteranope, "
            "only %.1f deg apart. Their fills are dE %.1f apart, so the angle is "
            "all the separation there is."
            % (theme, hi, med, gap, _cvd_gap(tokens["breach-bg"], tokens["warn-series"])))


def test_the_texture_is_why_and_the_hue_still_is_not(themes) -> None:
    """RE-AIMED FROM F1, NOT DELETED. `test_the_medium_band_still_separates_from_
    the_high_one` measured `--warn-bg`, which G6 stopped drawing; it read 19.1
    while the emitted colour sat at 6.6.

    It now measures what is painted, and asserts the OPPOSITE conclusion, because
    the opposite is what shipped: the fills do NOT separate, and that is the
    documented reason the hatch exists. If some later phase finds an amber that
    clears both 3:1 and dE 8 - #131 says there is none - this is the guard that
    goes red to say the texture is no longer load-bearing."""
    for theme, tokens in themes.items():
        gap = _cvd_gap(tokens["breach-bg"], tokens["warn-series"])
        if theme == "dark":
            assert gap >= 8.0, "dark used to clear the floor on hue alone (%.1f)" % gap
            continue
        assert gap < 8.0, (
            "light High/Medium now measure dE %.1f on hue alone. If that is real, "
            "#131's conclusion has changed and the hatch is no longer required - "
            "re-read this file before deleting anything." % gap)


def test_the_textured_band_still_clears_three_to_one_on_its_panel(themes) -> None:
    """F1 refused opacity because 'it composites a status fill toward the
    background and drops it under 3:1'. A tone-on-tone hatch is a different
    operation - the ink is a DARKER step of the band's own colour, over a third
    of the area - but the objection deserves a number rather than an argument.

    Measures the band's MEAN colour once the stripe is composited in, against the
    panel it is drawn on."""
    svg = _render(_THREE_BANDS)
    pats = _patterns(svg)
    for theme, tokens in themes.items():
        panel = PANEL_LIGHT if theme == "light" else tokens["surf"]
        for pid, pat in pats.items():
            n = 24
            acc = [0.0, 0.0, 0.0]
            for y in range(n):
                for x in range(n):
                    px = _pixel(pat, tokens, x, y)
                    acc = [a + c for a, c in zip(acc, px)]
            mean = "#%02x%02x%02x" % tuple(round(c / (n * n)) for c in acc)
            got = ratio(mean, panel)
            assert got >= 3.0, (
                "%s %s: the hatched band averages %s, %.2f:1 on %s - the hatch has "
                "done exactly what F1 refused" % (theme, pid, mean, got, panel))


# ══ the thin extreme ════════════════════════════════════════════════════════
_ONE_HIGH_DAY = {
    "type": "stacked", "height": 150, "labels": ["a", "b"],
    "series": [{"name": "High", "tone": "bad", "values": [1, 0]},
               {"name": "Medium", "tone": "warn", "values": [0, 400]},
               {"name": "Low", "tone": "mute", "values": [0, 120]}],
    "legend": True,
}


def test_a_thin_band_gets_no_texture_but_still_draws() -> None:
    """One High-risk day in a thousand — MIN_SEG, #112's whole reason.

    Below TEX_MIN a hatch degrades into phase-dependent specks, so the band draws
    SOLID there and the design says so out loud. What must not happen is the
    band vanishing: a texture that silently disappeared at the size the chart
    exists for would be worse than the defect it fixes.

    Asserted together on purpose. Either half alone can be satisfied by the wrong
    fix - dropping the floor would make 'no texture' trivially true."""
    svg = _render(_ONE_HIGH_DAY)
    fills, heights = _fills(svg), _heights(svg)
    thin = [(f, h) for f, h in zip(fills, heights) if h <= 2.0]
    assert thin, "no segment was floored - this fixture no longer tests the thin case"
    for fill, h in thin:
        assert h >= 1.0, "a floored segment came out at %.2fpx - #112's false zero" % h
        assert "url(" not in fill, (
            "a %.1fpx band was painted with a hatch (%s); one tile is 6px, so this "
            "renders as specks that state nothing" % (h, fill))
        assert fill.startswith("var(--"), "expected the plain tone, got %r" % fill


def test_a_true_zero_still_draws_nothing() -> None:
    """#112's other half. A floor only ever lifts a segment that is already > 0;
    the day the floor starts inventing a band, this ledger claims a High-risk day
    that never happened."""
    svg = _render(_ONE_HIGH_DAY)
    # 2 columns x 3 series = 6 cells, of which High[0], Medium[1] and Low[1] are
    # non-zero. The other three are true zeros and must draw nothing at all.
    nonzero = sum(1 for s in _ONE_HIGH_DAY["series"] for v in s["values"] if v > 0)
    assert nonzero == 3, "fixture drifted: %d non-zero cells" % nonzero
    assert len(_fills(svg)) == nonzero, (
        "expected %d marks for %d non-zero cells, got %d - a zero drew something"
        % (nonzero, nonzero, len(_fills(svg))))


def test_the_bands_are_stacked_high_at_the_base() -> None:
    """The thin case has no in-mark channel at all, so what identifies a 1px band
    is the stack's ORDER - and the card's subtitle now states it. Guarded because
    the subtitle is a promise about draw order that lives 2000 lines away."""
    svg = _render(_THREE_BANDS)
    ys = [float(re.search(r'\by="([\d.]+)"', t).group(1)) for t in _BAR.findall(svg)]
    first_column = ys[:3]                       # High, Medium, Low of column 1
    assert first_column == sorted(first_column, reverse=True), (
        "High is no longer at the base (y descending = bottom up): %s" % first_column)
    # ⚠ SCOPED TO THE SUBTITLE ELEMENT. Mutation-tested: `"High at the base" in
    # SRC` stayed true after the subtitle lost the phrase, because the engine's
    # own comment block explains the rule in the same words. A comment shadowing
    # the thing under test is this repo's most-repeated guard defect.
    head = SRC[:SRC.index('id="threatTimeline"')]
    subtitle = head[head.rindex("Breaches over time"):]
    assert "High at the base" in subtitle, (
        "the card subtitle stopped stating the stack order: %r" % subtitle[:160])
    call = _timeline_call()
    assert call.index("tone:'bad'") < call.index("tone:'warn'") < call.index("tone:'mute'"), \
        "the series order changed but the subtitle still says High is at the base"


# ══ the legend ══════════════════════════════════════════════════════════════
def test_the_legend_swatch_paints_exactly_what_the_band_paints() -> None:
    """The drift this phase closes, made structural.

    The hand-written legend named `--warn-bg` after G6 re-pointed the band to
    `--warn-series`. The fix is not a corrected hex - it is that the swatch and
    the mark now come from the same call, so the two cannot disagree again."""
    svg = _render(_THREE_BANDS)
    swatches = _SWATCH.findall(svg)
    assert len(swatches) == 3, "expected 3 legend swatches, got %d" % len(swatches)
    drawn = _fills(svg)[:3]                     # column 1: High, Medium, Low
    assert swatches == drawn, (
        "legend paints %s, the bands paint %s" % (swatches, drawn))


def test_the_legend_never_claims_an_encoding_the_marks_do_not_carry() -> None:
    """G7.1 INVERTED THIS GUARD'S RULE, deliberately, and kept it aimed here.

    It used to assert the opposite — the swatch painted at TEX_MIN whatever the
    data did, reasoning that a key states what the band MEANS and should not
    follow a quiet week. Wrong in the one direction that matters: where no band
    of a tone clears the gate, a hatched key advertises an encoding the marks do
    not have. That is the single defect class this repo has shipped most often,
    and it is what the legend G7 deleted was doing in source.

    So the rule is now PER TONE and read off what was drawn. The fixture is the
    thin case: High=1 is below the gate and must key SOLID, Medium=400 is above
    it and must key HATCHED — in the same legend, from the same render."""
    svg = _render(_ONE_HIGH_DAY)
    swatches = _SWATCH.findall(svg)
    fills = _fills(svg)
    hatched_tones = {re.search(r"fxtex-(\w+)-", f).group(1) for f in fills if "url(" in f}
    assert hatched_tones == {"warn"}, (
        "fixture drifted: expected only Medium to clear the gate, got %s" % hatched_tones)
    assert [("url(" in s) for s in swatches] == [False, True, False], (
        "the key does not match what was drawn. bands=%s swatches=%s" % (fills, swatches))


# ══ G7.1 · the gate, measured on the shape this chart is for ════════════════
# One incident day at ~13x against ordinary days. Breach data is spiky by
# nature — if it were flat nobody would need the chart — so THIS is the typical
# window, not the extreme, and it is what the gate has to be judged on.
_SPIKY = {
    "type": "stacked", "height": 180, "focus": "last", "legend": True,
    "labels": [str(i) for i in range(30)],
    "series": [
        {"name": "High", "tone": "bad", "values":
         [3, 2, 4, 1, 3, 2, 5, 2, 3, 4, 2, 1, 3, 2, 4, 3, 2, 40, 3, 2,
          4, 1, 3, 2, 5, 2, 3, 4, 2, 3]},
        {"name": "Medium", "tone": "warn", "values":
         [4, 3, 5, 2, 4, 3, 6, 3, 4, 5, 3, 2, 4, 3, 5, 4, 3, 55, 4, 3,
          5, 2, 4, 3, 6, 3, 4, 5, 3, 4]},
        {"name": "Low", "tone": "mute", "values":
         [2, 4, 3, 5, 2, 6, 3, 2, 4, 3, 5, 2, 3, 4, 2, 5, 3, 30, 2, 4,
          3, 5, 2, 6, 3, 2, 4, 3, 5, 2]}],
}


def test_the_typical_spiky_window_mostly_carries_the_encoding() -> None:
    """THE GUARD G7 DID NOT HAVE, and the reason G7.1 exists.

    `seg` is RELATIVE — (v/max)*(H-pb-pt) — so an ABSOLUTE gate is a percentage
    of the peak column. At TEX_MIN=6 on a ~138px plot that was 4.4% of the peak,
    and on this window **4 of 60** High/Medium bands carried the hatch: absent on
    every ordinary day, present only on the day already obvious from its height.

    The number is asserted, not the threshold, because a threshold nobody
    measured is how the first one got chosen. Measured after the tile went
    6px -> 4px: 25/60. The floor is set below that so a small re-tune does not
    fail the suite, but far above the 4/60 this replaced.

    ⚠ This deliberately does NOT demand 100%. Below one tile nothing fits, and
    the honest answer there is the stack order plus a legend that stops
    claiming a hatch — see the two tests either side of this one."""
    svg = _render(_SPIKY)
    hm = [(f, h) for f, h in zip(_fills(svg), _heights(svg))
          if "mute-series" not in f]
    assert len(hm) == 60, "fixture drifted: %d High/Medium bands" % len(hm)
    got = sum(1 for f, _ in hm if "url(" in f)
    assert got >= 20, (
        "only %d of %d High/Medium bands carry the hatch (%.0f%%). The gate is "
        "an absolute px threshold on a relative quantity, so it drifts with the "
        "spikiness of the data; it was 4/60 before the tile was made finer."
        % (got, len(hm), 100.0 * got / len(hm)))


def test_the_gate_is_one_full_tile_and_the_tile_is_what_was_measured() -> None:
    """The rule is 'one full tile fits', so TEX_MIN is DERIVED from TEX_TILE
    rather than being a second constant that can drift away from the thing it
    describes.

    4px is measured, not picked: a structure tensor recovers the 90 deg
    separation down to its own 3-row stencil, which is a machine floor and says
    nothing about a person, so the ladder was rendered at 1:1 and looked at —
    2px reads as a solid line, 3px as dots with no readable lean, 4px as
    alternating dashes that visibly lean."""
    engine = SRC[SRC.index("var TEX_TILE="):SRC.index("function texId")]
    assert "var TEX_MIN=TEX_TILE;" in engine, (
        "TEX_MIN is no longer derived from the tile: %r" % engine[-200:])
    assert "var TEX_TILE=4," in engine, "the measured tile changed: %r" % engine[:60]
    # ...and the gate must actually be the tile at render time, not just in source.
    pats = _patterns(_render(_THREE_BANDS))
    tiles = {p["tile"] for p in pats.values()}
    assert tiles == {4.0}, "the emitted tile is %s" % tiles
    thin = _render({**_THREE_BANDS,
                    "series": [{**s, "values": [4, 4]} if s["tone"] == "bad"
                               else {**s, "values": [1000, 1000]}
                               for s in _THREE_BANDS["series"]]})
    heights = dict(zip(_fills(thin), _heights(thin)))
    assert any("url(" in f and h >= 4.0 for f, h in heights.items()), heights


def test_the_guards_render_the_id_production_actually_uses() -> None:
    """⚠ EVERY GUARD IN THIS FILE USED TO EXERCISE A PATH PRODUCTION NEVER TAKES.

    texId namespaces its <pattern> ids by host.id, and every foxChart call in the
    shipped file passes one. The node shim's host had none, so all of them fell
    through to texId's 'c' fallback — meaning a texDefs/bandPaint mismatch in the
    REAL path would emit an unresolvable url(#...), which SVG renders as nothing
    at all, and the suite would stay green.

    The shim carries an id now. This pins that, so nobody quietly removes it."""
    ids = set(_patterns(_render(_THREE_BANDS)))
    assert ids == {"fxtex-bad-threatTimeline", "fxtex-warn-threatTimeline"}, (
        "the guards are not rendering the production id path: %s" % sorted(ids))


def test_the_no_id_fallback_still_resolves() -> None:
    """The 'c' fallback is unreachable from the shipped calls but it is still
    live code, and an id that does not match between texDefs and bandPaint paints
    NOTHING. Kept covered explicitly rather than by accident."""
    from test_c0_chart_segments import _SHIM, _chart_source
    import json as _json, subprocess as _sp, tempfile as _tf
    from pathlib import Path as _P

    probe = (_SHIM + _chart_source()
             + "\nvar parent=El('rgb(242, 240, 238)',null), "
               "host=El('rgba(0, 0, 0, 0)', parent, '');\n"
             + "window.foxChart(host, " + _json.dumps(_THREE_BANDS) + ");\n"
             + "console.log(JSON.stringify(host.innerHTML));\n")
    with _tf.TemporaryDirectory() as tmp:
        path = _P(tmp) / "chart.js"
        path.write_text(probe, encoding="utf-8")
        proc = _sp.run([shutil.which("node"), str(path)],
                       capture_output=True, text=True, encoding="utf-8")
    assert proc.returncode == 0, proc.stderr
    svg = _json.loads(proc.stdout.strip().splitlines()[-1])
    defined = set(_patterns(svg))
    used = {re.search(r"url\(#([^)]+)\)", f).group(1)
            for f in _fills(svg) if "url(" in f}
    assert defined == {"fxtex-bad-c", "fxtex-warn-c"}, sorted(defined)
    assert used == defined, (
        "an id-less host defines %s but paints %s — an unresolvable url() renders "
        "a BLANK band" % (sorted(defined), sorted(used)))


def test_no_legend_swatch_is_an_html_background() -> None:
    """FORCED COLORS, measured rather than assumed. In headless Chrome with
    --force-high-contrast an HTML `background-color` is overridden to Canvas -
    every swatch collapses to one colour and the legend keys nothing - while an
    SVG `fill` is left alone. So every swatch the engine emits is an SVG rect.

    Asserted across the WHOLE engine, not just the stacked one: the line and
    donut legends emit from their own lines and would drift back one at a time."""
    engine = SRC[SRC.index("var TONE={ok:"):SRC.index("window.foxChart=")]
    assert "<i style=\"background:'+" not in engine and "'<i style=\"background:'" not in engine, \
        "an HTML background swatch is back in a legend emitter"
    assert engine.count("swatch(") >= 4, (
        "expected every legend emitter plus the helper to go through swatch(), "
        "found %d references" % engine.count("swatch("))


def test_the_hand_written_legend_is_gone() -> None:
    """It rendered NO swatches at all: every rule that sizes `.cx-legend i` is
    scoped to `.chart-host`, and that div was the chart host's SIBLING. Measured
    in the browser, it read 'High (>=70)Medium (40-69)Low (<40)' - three 0x0 chips
    and no gap. Deleted rather than re-parented, because a legend the engine
    renders cannot drift from the engine."""
    head = SRC[SRC.index('id="threatTimeline"') - 1400:SRC.index('id="threatTimeline"') + 200]
    assert 'class="cx-legend"' not in head, "a hand-written legend is back beside the chart"
    call = _timeline_call()
    assert "legend:true" in call, "the engine is no longer asked to render the legend"
    # Matched VERBATIM, en-dash and all: these are the copy a reader sees, and an
    # ASCII-folded anchor here rots into a MISSED without anything changing.
    for band in ("High (≥70)", "Medium (40–69)", "Low (<40)"):
        assert band in call, "the legend lost its threshold labels: %r" % band


def test_the_swatch_rule_reaches_the_swatch(css) -> None:
    """The sizing rule that the old legend missed. `.cx-sw` is inside the chart
    host now, so `.chart-host` scoping is correct - but assert it, because that
    scoping is precisely what made three swatches invisible last time."""
    rule = re.search(r"\.chart-host \.cx-legend \.cx-sw\{([^}]*)\}", css)
    assert rule, "no sizing rule for the legend swatch"
    body = rule.group(1)
    assert "width:10px" in body and "height:10px" in body, body
