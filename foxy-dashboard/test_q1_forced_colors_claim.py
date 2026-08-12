"""PRODUCT.md's forced-colors sentence must match the surfaces, whichever way.

Q1 wrote this file when the sentence named the admin console as lacking
`@media (forced-colors)` while the admin console had shipped it in G2 and the
DASHBOARD had none. It was built to fail when #154 was fixed rather than to go
quietly stale — and in G9 it did exactly that, which is why it now asserts the
opposite state.

⚠ THE COUNT MUST BE OF THE AT-RULE, NOT THE WORD. The dashboard mentions
forced-colors in COMMENTS (G7's legend swatch, G8's chart shim) as well as in
its rule. A `"forced-colors" in src` check cannot tell those apart, which is the
same comments-shadow-selectors trap the admin guards hit before — so the control
below still pins the difference.

This file only checks that the DOCUMENTATION matches which surfaces have a
block. Whether the dashboard's block actually WORKS is measured against a
rendered page in test_g9_forced_colors.py.
"""

from __future__ import annotations

import re
from pathlib import Path

_ROOT = Path(__file__).resolve().parent.parent
_PRODUCT = _ROOT / "PRODUCT.md"
_DASHBOARD = _ROOT / "foxy-dashboard" / "foxy-audit-premium.html"
_ADMIN = _ROOT / "foxy-adminpage" / "index.html"
_SALE = _ROOT / "foxy-sale-page" / "index.html"
_CHECKOUT = _ROOT / "foxy-checkout" / "index.html"

_AT_RULE = re.compile(r"@media\s*\(\s*forced-colors")


def _blocks(path: Path) -> int:
    return len(_AT_RULE.findall(path.read_text(encoding="utf-8")))


def _accessibility_section() -> str:
    """The section, bounded by the NEXT heading — not a character count.

    This read `text[start:start + 1800]`, which only happened to cover the right
    prose because that section is currently last in PRODUCT.md. Add a section
    after it and the window spills into the neighbour; add prose inside it and
    the window stops short. A window is not a scope — the same failure this repo
    has hit in source-slicing guards three times."""
    text = _PRODUCT.read_text(encoding="utf-8")
    start = text.index("## Accessibility & Inclusion")
    nxt = re.search(r"^## ", text[start + 1:], re.M)
    end = start + 1 + nxt.start() if nxt else len(text)
    return text[start:end].lower()


def test_the_two_stateful_surfaces_have_forced_colors_support():
    """The admin console since G2, the dashboard since G9. Both carry controls
    whose selected state a High Contrast user has to be able to read."""
    assert _blocks(_ADMIN) >= 1, "the admin console lost its forced-colors block"
    assert _blocks(_DASHBOARD) >= 1, "the dashboard lost its forced-colors block"


def test_the_dashboard_has_exactly_one_block():
    """One block, so there is one place to read the whole policy. A second means
    two half-answers that can disagree."""
    assert _blocks(_DASHBOARD) == 1, f"found {_blocks(_DASHBOARD)} blocks"


def test_the_word_alone_would_still_measure_the_wrong_thing():
    """The control for the counter, kept from Q1 and still true in reverse: the
    dashboard contains the string more often than it contains the rule, so a
    word search reports a coverage number that is not the number of rules."""
    src = _DASHBOARD.read_text(encoding="utf-8")
    assert src.count("forced-colors") > _blocks(_DASHBOARD), \
        "the word and the at-rule now appear equally often; this control is moot"


def test_the_documented_gap_names_the_surfaces_that_still_lack_it():
    """The sentence has to keep up with the surfaces. It named the wrong one for
    a whole release, which is what this file exists to stop happening again."""
    section = _accessibility_section()
    assert _blocks(_SALE) == 0 and _blocks(_CHECKOUT) == 0, \
        "a surface gained forced-colors support; PRODUCT.md still calls it a gap"
    assert "marketing site" in section and "checkout" in section, \
        "the remaining gaps are no longer named in PRODUCT.md"
    assert not re.search(r"no `@media \(forced-colors\)` support on the customer",
                         section), \
        "PRODUCT.md still calls the dashboard a gap after G9 closed it"
