"""The legal pages reference each other. This checks BOTH directions.

⚠ REGISTER #184 — WHY THE OBVIOUS GUARD IS NOT ENOUGH

`test_terms_v26.py::test_the_page_links_no_document_that_does_not_exist_yet`
iterates the links PRESENT in a page and asserts each target exists. Its
docstring claimed it would "fail when the target appears", which is how L3 and
L9 were to be told to link the Refund Policy and the SLA once they built them.

It cannot do that. A document named in prose and NOT linked has no link to
iterate, so it is invisible to a forward check. Nothing would have gone red.
That is exactly how this repository ended up shipping a Terms of Service whose
entire-agreement clause named a Terms of Use that had no page and no phase.

So the two directions are separate guards and both are needed:

  FORWARD  every link resolves to a file that exists    (no dead ends; L0 made
                                                         404s real)
  REVERSE  every document NAMED in prose, whose page    (no orphans; this file)
           now exists, is linked

The reverse one is the one that speaks to the future. When L3 adds refund.html,
terms.html §6 still says "See our standalone Refund Policy for full detail" with
no anchor, and THIS test turns red naming both files. L3 does not have to
remember; it gets told.

Run:  pytest foxy-sale-page -q
"""

from __future__ import annotations

import pathlib
import re

import pytest

from conftest import HERE, LegalDom

#: Document name as it appears in prose -> the page that carries it.
#: Entries whose file does not exist yet are not failures; they are the phases
#: still to come, and naming them in prose without an anchor is correct.
DOCUMENTS = {
    "Terms of Service": "terms.html",                  # L2
    "Terms of Use": "terms-of-use.html",               # L2b
    "Privacy Policy": "privacy.html",                  # L1
    "Cookie Policy": "cookie-policy.html",             # L7 (exists, stale)
    "Acceptable Use Policy": "acceptable-use.html",    # L6
    "Trust Center": "trust.html",                     # L8
    "Report Abuse": "report-abuse.html",               # L4/L5 — the
    #   authoritative security policy. Any page that names it must link
    #   it: it is where the safe harbour lives, and a reader who cannot
    #   reach it cannot rely on it.
    "Refund Policy": "refund.html",                    # L3
    "Service Level Agreement": "sla.html",             # L9
    "Data Processing Agreement": "dpa.html",           # L10
    "Master Service Agreement": "msa.html",            # L11
}

#: Pages that participate. Append as each phase lands.
PAGES = [
    "privacy.html", "terms.html", "terms-of-use.html",
    "refund.html", "trust.html", "cookie-policy.html", "acceptable-use.html",
    "report-abuse.html", "legal.html",
]

def _dom(page: str) -> LegalDom:
    return LegalDom((HERE / page).read_text(encoding="utf-8"))


def _real_pairs() -> list[tuple[str, str, str]]:
    """Only the relationships that ACTUALLY EXIST in the prose.

    Parametrising over the full 9x7 cross-product produced 45 skips and 13 real
    assertions — and a wall of skips is where a guard goes to hide. Collecting
    the pairs by reading each page means every case listed is a real reference
    between two documents, and the only thing that can still skip is a target no
    phase has built yet, which is a signal rather than noise."""
    out = []
    for page in PAGES:
        if not (HERE / page).is_file():
            continue
        text = _dom(page).text
        for name, target in DOCUMENTS.items():
            if target != page and re.search(rf"\b{re.escape(name)}\b", text):
                out.append((page, name, target))
    return out


_PAIRS = _real_pairs()


@pytest.mark.parametrize("page", [p for p in PAGES if (HERE / p).is_file()])
def test_every_link_resolves_to_a_file_that_exists(page):
    """FORWARD. L0 replaced the SPA catch-all with a real 404, so a link to a
    page nobody has built is now a visible dead end rather than a silent
    redirect to the marketing homepage."""
    dom = _dom(page)
    dead = sorted({a["href"] for a in dom.links
                   if a["href"].startswith("/") and a["href"].endswith(".html")
                   and not (HERE / a["href"].lstrip("/")).is_file()})
    assert not dead, f"{page} links to pages that do not exist: {dead}"


@pytest.mark.parametrize("page,name,target", _PAIRS,
                         ids=[f"{p}-names-{n.replace(' ', '')}" for p, n, _ in _PAIRS])
def test_a_document_that_exists_is_linked_by_every_page_that_names_it(page, name, target):
    """REVERSE — the half a forward check structurally cannot do.

    ⚠ IF THIS FAILS AFTER YOU ADDED A PAGE, that is the guard working: a sibling
    already talks about your document in prose and now needs an anchor. Add the
    link; do not add an exemption.

    Skipped, not failed, while the target is unbuilt — naming a future policy in
    prose is how L2 correctly referred to the Refund Policy before L3 existed."""
    if not (HERE / target).is_file():
        pytest.skip(f"{target} not built yet — {page}'s prose-only reference is correct")
    dom = _dom(page)
    assert f'href="/{target}"' in dom.src, (
        f"{page} names the {name} in prose but never links it, and {target} "
        f"exists now — add the anchor")


def test_every_card_on_the_legal_index_links_the_document_it_names():
    """⚠ THE REVERSE GUARD ABOVE IS FILE-SCOPED, AND THAT IS NOT ENOUGH HERE.

    It asks whether the page links a document ANYWHERE. legal.html links most of
    them from its footer as well as from a card, so re-pointing a card at the
    wrong page leaves the file-level check green — measured: sending the "Report
    Abuse" card to contact.html passed every guard in the suite, because the
    footer still carried the link.

    That is the #184 shape again: a guard satisfied by a neighbour. This one
    slices each card and asks whether it links the document its OWN heading
    names, which is the thing a reader clicks."""
    src = (HERE / "legal.html").read_text(encoding="utf-8")
    cards = re.findall(r'<a class="gcard" href="([^"]+)"(.*?)</a>', src, re.S)
    assert len(cards) >= 6, f"legal.html should carry the policy cards, found {len(cards)}"

    #: Card headings that are shorter than the document's own name.
    ALIASES = {"Acceptable Use": "Acceptable Use Policy"}
    #: Headings that are deliberately NOT a document. "Security" is a route into
    #: the disclosure policy's section, guarded by name in test_report_abuse_v14.
    NOT_DOCUMENTS = {"Security"}

    checked, skipped = 0, []
    for href, inner in cards:
        heading = re.search(r"<h3>([^<]+)</h3>", inner)
        assert heading, f"a card on legal.html has no heading: {href}"
        name = heading.group(1).strip()
        target = DOCUMENTS.get(ALIASES.get(name, name))
        if target is None:
            skipped.append(name)
            continue
        if not (HERE / target).is_file():
            continue                      # a card for something not yet built
        checked += 1
        assert href.split("#")[0] == f"/{target}", (
            f'the "{name}" card links {href} — it should link /{target}, which is '
            "the document its own heading names")

    # ⚠ A SKIP IS A PASS, so the skips are pinned. The "Acceptable Use" card was
    # silently skipped on the first run because the map keys it as "Acceptable
    # Use Policy" — measured: re-pointing that card at terms.html went unnoticed.
    assert set(skipped) <= NOT_DOCUMENTS, (
        f"card headings matched no document and were skipped without checking: "
        f"{sorted(set(skipped) - NOT_DOCUMENTS)} — add them to DOCUMENTS or ALIASES")
    assert checked >= 6, f"only {checked} cards were checked; the map has gone stale"


def test_the_forward_and_reverse_guards_are_not_the_same_check():
    """The control for #184.

    A page that NAMES a document without linking it has no link to iterate, so
    the forward check passes on it. If this ever stops being true the two guards
    have converged and one of them is dead weight — but it is true, and it is
    why an unlinked Terms of Use survived review."""
    pretend = LegalDom(
        '<html><body><p>See our <strong>Privacy Policy</strong> for detail.</p></body></html>')
    dead = [a for a in pretend.links
            if a["href"].startswith("/") and not (HERE / a["href"].lstrip("/")).is_file()]
    assert not dead, "the forward check should find nothing to complain about here"
    assert "Privacy Policy" in pretend.text, "…yet the document is plainly named"
    assert not pretend.links, "and there is no link for a forward check to inspect"
