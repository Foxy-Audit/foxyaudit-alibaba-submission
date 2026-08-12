"""PRODUCT.md's forced-colors "known gap" must name the surface that has it.

It named the admin console. The admin console SHIPPED that support in G2 — one
`@media (forced-colors: active)` block — and the customer dashboard has none. So
the documented gap pointed at the one surface where it had been closed, which is
worse than no note: a reader checks the named file, finds the support, and
concludes the note is stale rather than that the real gap is elsewhere.

⚠ THE COUNT MUST BE OF THE AT-RULE, NOT THE WORD. The dashboard mentions
forced-colors twice in COMMENTS (the G7 legend swatch, the chart shim) while
having zero rules. A `"forced-colors" in src` check reports the dashboard as
covered — the same comments-shadow-selectors trap the admin guards hit before.

This is a doc-accuracy guard, so it is meant to fail when #154 is FIXED: add
support to the dashboard and this turns red until the sentence is updated.
"""

from __future__ import annotations

import re
from pathlib import Path

_ROOT = Path(__file__).resolve().parent.parent
_PRODUCT = _ROOT / "PRODUCT.md"
_DASHBOARD = _ROOT / "foxy-dashboard" / "foxy-audit-premium.html"
_ADMIN = _ROOT / "foxy-adminpage" / "index.html"

_AT_RULE = re.compile(r"@media\s*\(\s*forced-colors")


def _blocks(path: Path) -> int:
    return len(_AT_RULE.findall(path.read_text(encoding="utf-8")))


def _gap_sentence() -> str:
    text = _PRODUCT.read_text(encoding="utf-8")
    start = text.index("**Known gap:**")
    return text[start:start + 600]


def test_the_admin_console_really_does_have_forced_colors_support():
    assert _blocks(_ADMIN) >= 1, \
        "the admin console lost its forced-colors block; PRODUCT.md now needs it back"


def test_the_dashboard_really_does_not():
    """If this fails, #154 has been fixed — good. Update the PRODUCT.md sentence
    and delete this guard rather than loosening it."""
    assert _blocks(_DASHBOARD) == 0, \
        "the dashboard has forced-colors support now; PRODUCT.md still calls it a gap"


def test_the_word_alone_would_have_measured_the_wrong_thing():
    """The inert control for the counter: the dashboard DOES contain the string,
    in comments. A guard that searched for it would call the dashboard covered
    and this whole file would agree with a false sentence."""
    assert "forced-colors" in _DASHBOARD.read_text(encoding="utf-8")
    assert _blocks(_DASHBOARD) == 0


def test_the_documented_gap_names_the_dashboard_not_the_admin_console():
    sentence = _gap_sentence().lower()
    assert "dashboard" in sentence
    assert not re.search(r"no `@media \(forced-colors\)` support on the admin", sentence), \
        "PRODUCT.md is back to naming the admin console, which has the support"
