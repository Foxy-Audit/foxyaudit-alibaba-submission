"""Shared helpers for the legal-page guards.

⚠ L3–L12: USE `legal_dom("<yourpage>.html")`. Do not paste another parser.

WHY A PARSER AND NOT A REGEX OVER THE SOURCE

Every one of these pages is a converted legal document, and the two ways the
conversion goes wrong are both invisible to a grep of the file:

  · **A link that reads correctly and resolves wrongly.** The Privacy Policy's
    source ends "…directed to privacy@foxyaudit.tech." — the period is sentence
    punctuation. A converter that regexes for an address takes it with them and
    ships a mailto that bounces. The page TEXT is right either way; only the
    parsed `href` tells them apart.

  · **Markup that changes what a sentence says.** `Ltd</strong> ("<strong>Paddle`
    is one token to a reader and three to a naive tag-stripper. A fidelity check
    that inserts a space for every tag reports the merchant-of-record paragraph
    as altered when it is verbatim — measured, and it cost a false alarm.

So `text` here strips INLINE tags with no space and block tags with one, which is
what a browser does, and `links` exposes attributes as the parser resolved them.

The claims that need a real browser — did the face actually load, did the page
fetch anything — live in test_legal_pages_rendered.py.
"""

from __future__ import annotations

import pathlib
import re
from html.parser import HTMLParser

import pytest

HERE = pathlib.Path(__file__).resolve().parent

#: Tags that sit INSIDE a sentence. Removing them must not insert whitespace, or
#: `("<strong>Paddle</strong>")` stops comparing equal to `("Paddle")`.
_INLINE = ("a", "strong", "em", "b", "i", "code", "span", "sup", "sub", "small")

#: A street address none of these documents has. Foxy Audit operates with no
#: registered office (Privacy Policy §1), so any of these on a legal page is
#: invented.
#:
#: ⚠ THE OBVIOUS PATTERN IS TOO TIGHT, and was. `\d+\s+\w+\s+(Street|Road|…)`
#: assumes a two-token address, so it misses "7 Blue Area Road" — measured: that
#: exact string was inserted into a page and the guard stayed green. Real
#: addresses run to several words, and the number can follow the keyword
#: ("Suite 2") as well as precede it. Both shapes are covered now.
POSTAL_ADDRESS = re.compile(
    # \d{1,5}[A-Za-z]? — house numbers carry a letter ("221B Baker Street").
    r"\b\d{1,5}[A-Za-z]?\s+(?:[\w'-]+\s+){0,4}"
    r"(?:Street|St\.|Road|Rd\.|Avenue|Ave\.|Boulevard|Blvd\.|Lane|Ln\.|Drive|Dr\.|"
    r"Suite|Ste\.|Floor|Plaza|Tower|Block)\b"
    r"|\b(?:Suite|Ste\.|Floor|Apt\.?|Unit|Block|Tower|P\.?O\.? Box)\s+#?\d+\b",
    re.I)


class LegalDom(HTMLParser):
    """Enough of a DOM to ask what the browser would see."""

    def __init__(self, src: str) -> None:
        super().__init__(convert_charrefs=True)
        self.src = src
        self.links: list[dict] = []
        self.ids: list[str] = []
        self._skip = 0
        self._parts: list[str] = []
        self.feed(src)

    def handle_starttag(self, tag, attrs):
        a = dict(attrs)
        if tag in ("style", "script", "title"):
            self._skip += 1
        elif tag not in _INLINE:
            self._parts.append(" ")
        if tag == "a" and "href" in a:
            self.links.append(a)
        if "id" in a:
            self.ids.append(a["id"])

    def handle_endtag(self, tag):
        if tag in ("style", "script", "title"):
            self._skip = max(0, self._skip - 1)
        elif tag not in _INLINE:
            self._parts.append(" ")

    def handle_data(self, data):
        if not self._skip:
            self._parts.append(data)

    @property
    def text(self) -> str:
        return re.sub(r"\s+", " ", "".join(self._parts)).strip()

    # ── the checks every legal page needs, so no phase re-derives them ───────
    @property
    def mailtos(self) -> list[str]:
        return [a["href"] for a in self.links if a["href"].lower().startswith("mailto:")]

    @property
    def addresses(self) -> set[str]:
        return {h[len("mailto:"):].split("?")[0] for h in self.mailtos}

    def section(self, n: int) -> str:
        """The source slice for section `n`, bounded by the NEXT section's id.

        A window is not a scope: an unbounded search for "<li>" is answered by
        whichever list happens to sit nearby. Both ends are asserted."""
        start = self.src.index(f'id="s{n}"')
        nxt = self.src.find(f'id="s{n + 1}"', start)
        end = nxt if nxt != -1 else self.src.index('class="foot"', start)
        assert end > start, f"could not bound section {n}"
        return self.src[start:end]


def load(page: str) -> LegalDom:
    return LegalDom((HERE / page).read_text(encoding="utf-8"))


@pytest.fixture(scope="session")
def legal_dom():
    """`legal_dom("terms.html")` — parsed once per session, per page."""
    cache: dict[str, LegalDom] = {}
    return lambda page: cache.setdefault(page, load(page))
