"""Contrast, recomputed from ``page.html``'s own token values.

This project holds itself to WCAG AA for text and 3:1 for UI components, and it
holds itself there by MEASURING rather than asserting -- the dashboard and the
admin console both recompute their ratios from token values in CI, and this
surface joins them.

⚠ A FILL IS MEASURED AGAINST ITS BACKGROUND, NOT ONLY AGAINST ITS INK, and that
is the half this project has already got wrong in production: a chip shipped
whose text cleared 4.5:1 while the pill itself sat at 1.01:1 against the card
behind it, so the mark dissolved and only the letters remained. Every status
mark below is therefore checked twice, and the pairs are listed as pairs rather
than as a list of colours -- a token is not readable or unreadable on its own.

⚠ AND THE TINTED FILL IS CHECKED TOO. The selected sector's background was
originally ``color-mix(in srgb, var(--fox) 12%, var(--surf))``, which measured
4.39:1 under the muted text sitting on it -- a real AA failure, produced by
exactly the reasoning this file exists to stop (the fill was checked against the
card, and the text on the fill was not). It is a literal now, so these ratios are
recomputable from the file instead of from a browser: a probe that parses only
``rgb()`` measures the wrong surface and reports a plausible wrong number.
"""

from __future__ import annotations

import pathlib
import re

import pytest

from foxy_testbed import web

PAGE = (pathlib.Path(web.__file__).parent / web.PAGE_FILENAME).read_text(
    encoding="utf-8")

AA_TEXT = 4.5
AA_LARGE = 3.0
UI_COMPONENT = 3.0


def _tokens() -> dict:
    """Every ``--name:#hex`` declared in the page's ``:root`` block.

    Read out of the file rather than restated here. A guard that carries its own
    copy of the values it checks is green by construction the day the file and
    the copy diverge.
    """
    root = re.search(r":root\s*\{(.*?)\n\}", PAGE, re.S)
    assert root, "page.html has no :root block"
    found = dict(re.findall(r"(--[a-z0-9-]+)\s*:\s*(#[0-9a-fA-F]{6})\s*;",
                            root.group(1)))
    assert found, "no hex tokens found in :root"
    return found


TOKENS = _tokens()


def _luminance(hex_colour: str) -> float:
    """WCAG relative luminance."""
    value = hex_colour.lstrip("#")
    channels = [int(value[i:i + 2], 16) / 255.0 for i in (0, 2, 4)]
    linear = [c / 12.92 if c <= 0.04045 else ((c + 0.055) / 1.055) ** 2.4
              for c in channels]
    return 0.2126 * linear[0] + 0.7152 * linear[1] + 0.0722 * linear[2]


def ratio(a: str, b: str) -> float:
    first, second = _luminance(TOKENS[a]), _luminance(TOKENS[b])
    lighter, darker = max(first, second), min(first, second)
    return (lighter + 0.05) / (darker + 0.05)


#: Every ground this surface puts text on. --surf2 is the LIGHTEST of the three
#: and therefore the hardest for light ink -- which is why --muted had to be
#: lifted off the sale page's #8c8174, a value that measures 4.45:1 here.
GROUNDS = ("--bg", "--surf", "--surf2", "--sel")

#: The four verdict marks. Each is a solid fill carrying dark ink.
STATUS_FILLS = ("--st-allowed", "--st-enforced", "--st-flagged", "--st-fault")


@pytest.mark.parametrize("ground", GROUNDS)
def test_primary_text_is_readable_on_every_ground(ground):
    assert ratio("--ink", ground) >= AA_TEXT, (ground, ratio("--ink", ground))


@pytest.mark.parametrize("ground", GROUNDS)
def test_secondary_text_is_readable_on_every_ground(ground):
    """⚠ SECONDARY TEXT IS STILL TEXT and gets the full 4.5:1.

    --muted carries placeholder text, field labels, the provenance note beside
    every reply and the sector subtitles. None of that is decoration, so none of
    it takes the large-text exemption.
    """
    measured = ratio("--muted", ground)
    assert measured >= AA_TEXT, (ground, measured)


@pytest.mark.parametrize("fill", STATUS_FILLS)
def test_a_verdict_mark_is_visible_against_the_card_behind_it(fill):
    """THE HALF THAT USUALLY GETS MISSED. See the module docstring."""
    measured = ratio(fill, "--surf")
    assert measured >= UI_COMPONENT, (fill, measured)


@pytest.mark.parametrize("fill", STATUS_FILLS)
def test_a_verdict_mark_carries_readable_ink(fill):
    measured = ratio("--on-status", fill)
    assert measured >= AA_TEXT, (fill, measured)


@pytest.mark.parametrize("fill", STATUS_FILLS)
def test_a_status_colour_is_also_readable_as_text_on_the_card(fill):
    """The rail strokes and the STILL SENT field use these as ink, not as fill."""
    measured = ratio(fill, "--surf")
    assert measured >= AA_TEXT, (fill, measured)


def test_the_primary_action_is_readable_both_ways():
    """--fox is a fill under dark ink on the send button, and ink elsewhere."""
    assert ratio("--on-status", "--fox") >= AA_TEXT
    assert ratio("--fox", "--surf") >= AA_TEXT


@pytest.mark.parametrize("ground", ("--surf", "--surf2", "--sel"))
def test_a_control_edge_is_a_discernible_component(ground):
    """⚠ 3:1, BECAUSE A CONTROL'S BORDER IS THE ONLY THING THAT SAYS IT IS ONE.

    --line is the container hairline and measures about 1.3:1 against --surf,
    which is right for decoration and would be wrong here. The two are separate
    tokens precisely so that a control cannot quietly inherit the decorative one.
    """
    measured = ratio("--ctl", ground)
    assert measured >= UI_COMPONENT, (ground, measured)


def test_the_focus_ring_is_visible_on_every_ground():
    for ground in GROUNDS:
        assert ratio("--fox", ground) >= UI_COMPONENT, ground


def test_the_selected_sector_is_not_carried_by_its_fill_alone():
    """The tint is a tint: it does NOT reach 3:1 against the unselected card.

    That is fine, and stated rather than papered over, BECAUSE the state is
    carried by the --fox border as well -- which does. A guard that only checked
    the fill would either fail this correct design or pass a design where colour
    alone carried the state.
    """
    assert ratio("--sel", "--surf") < UI_COMPONENT
    assert ratio("--fox", "--sel") >= UI_COMPONENT
    assert "border-color:var(--fox)" in PAGE.replace(" ", "")


def test_no_colour_is_used_outside_the_token_system():
    """Every colour in the stylesheet is a token or a token reference.

    A literal hex in a rule is a colour no guard in this file can see, which is
    how a surface acquires an unmeasured pair.

    ⚠ IT SCANS DECLARATION BODIES, NOT THE WHOLE STYLESHEET, AND THAT IS THE
    FIX. The first version scanned everything and then tried to talk itself out
    of id selectors by discarding any match whose characters were ALL letters --
    which discards ``#eee``, ``#fff`` and ``#abcdef`` along with them.
    Mutation-proved: ``color:#eee;background:#abcdef`` passed the entire suite.
    A filter that removes false positives by removing a whole class of true ones
    is worse than no filter, because it still reads like coverage.

    Selectors and declarations are different places, so they are separated
    structurally rather than by guessing: only what sits between ``{`` and ``}``
    is scanned, and an id selector cannot appear there.
    """
    style = PAGE.split("<style", 1)[1].split("</style>", 1)[0]
    style = re.sub(r"/\*.*?\*/", "", style, flags=re.S)
    bodies = re.findall(r"\{([^{}]*)\}", style)
    assert bodies, "no rule bodies found -- has the stylesheet changed shape?"
    stray = []
    for body in bodies:
        if "--bg:" in body:      # the :root token block is where colours belong
            continue
        stray += re.findall(r"#[0-9a-fA-F]{3,8}\b", body)
    assert stray == [], stray


def test_the_sale_pages_muted_really_would_have_failed_here():
    """The divergence the token block claims, checked rather than asserted.

    ``--muted`` is lifted off ``foxy-sale-page/site.css``'s ``#8c8174``, and the
    stated reason is that the sale page's value misses AA on this surface's
    lightest fill. That reason is the whole justification for not simply
    inheriting the palette wholesale, so it is measured: if a future --surf2
    ever makes the original value fine again, this goes red and the divergence
    can be removed instead of outliving its cause.
    """
    sale_page_muted = 0.2126 * 0.2582 + 0.7152 * 0.2195 + 0.0722 * 0.1746
    surf2 = _luminance(TOKENS["--surf2"])
    measured = (max(sale_page_muted, surf2) + 0.05) / (min(sale_page_muted, surf2) + 0.05)
    assert measured < AA_TEXT, measured
    # ...and the value actually shipped clears it.
    assert ratio("--muted", "--surf2") >= AA_TEXT


#: The WCAG thresholds are constants rather than measurements, and a comment is
#: allowed to name the bar it says it clears.
THRESHOLDS = {"4.5:1", "3:1", "7:1"}

#: The one shape a claimed ratio may be written in. Anything else is invisible
#: to :func:`test_every_claimed_ratio_holds` -- which is exactly why the COUNT
#: is asserted separately below.
CLAIM_RE = re.compile(
    r"@contrast\s+(--[a-z0-9-]+)\s+on\s+(--[a-z0-9-]+)\s+([0-9]+\.[0-9]{2}):1")


def _style() -> str:
    return PAGE.split("<style", 1)[1].split("</style>", 1)[0]


def test_every_claimed_ratio_holds():
    """⚠ THE COMMENT IS CHECKED AGAINST THE ARITHMETIC.

    A stale ratio in a comment is worse than none: the next person to move a
    token reads it as a measurement when it is a memory. Ten of the first
    fourteen written here were wrong by about 1.5%, from hand arithmetic.

    These values were generated by this module's own :func:`ratio`, so this test
    does not prove the formula and is not trying to. Its job is DRIFT: it fails
    when a token moves and its annotation does not. What proves the design
    passes is the threshold tests above, and those compare against 4.5 and 3.0
    rather than against anything generated.
    """
    claims = CLAIM_RE.findall(_style())
    assert claims, "no @contrast claims found -- has the token block changed?"
    for token, ground, claimed in claims:
        measured = ratio(token, ground)
        assert abs(measured - float(claimed)) < 0.01, (
            token, ground, claimed, round(measured, 2))


def test_not_one_claimed_ratio_escapes_the_parser():
    """⚠ THE COVERAGE CLAIM, WHICH IS THE PART THAT WAS FALSE.

    The previous checker matched only ``N.NN:1 on --token``, and three of the
    fourteen annotations were written in other words -- "clears 4.83:1 on it",
    "5.07 --surf2", "6.99:1 at its worst". All three were skipped in silence;
    mutated to 9.99, 9.99 and 1.11 they stayed green. The suite was reporting
    coverage it did not have, which is worse than reporting none.

    So a ratio-shaped string the parser did not consume is a FAILURE rather than
    a gap. That makes the syntax mandatory instead of conventional: a new pair
    cannot be documented in a form nothing reads.
    """
    style = _style()
    written = [c for c in re.findall(r"[0-9]+\.?[0-9]*:1", style)
               if c not in THRESHOLDS]
    parsed = ["{0}:1".format(claim[2]) for claim in CLAIM_RE.findall(style)]
    assert sorted(written) == sorted(parsed), {
        "written but never parsed": sorted(set(written) - set(parsed)),
        "counts (written, parsed)": (len(written), len(parsed)),
    }


def test_every_ground_the_page_paints_text_on_is_claimed():
    """The other direction: a pair in play but never written down.

    The threshold tests cover the pairs THIS MODULE lists. This one starts from
    the grounds instead, so adding a surface without documenting its ratios
    fails here rather than passing by omission.
    """
    claimed = {(a, b) for a, b, _ in CLAIM_RE.findall(_style())}
    for ground in GROUNDS:
        for ink in ("--ink", "--muted"):
            assert (ink, ground) in claimed, (ink, ground)
