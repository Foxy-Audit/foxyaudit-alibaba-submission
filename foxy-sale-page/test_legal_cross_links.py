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
    "Acceptable Use Policy": "acceptable-use.html",    # L6 (exists, stale)
    "Refund Policy": "refund.html",                    # L3
    "Service Level Agreement": "sla.html",             # L9
    "Data Processing Agreement": "dpa.html",           # L10
    "Master Service Agreement": "msa.html",            # L11
}

#: Pages that participate. Append as each phase lands.
PAGES = [
    "privacy.html", "terms.html", "terms-of-use.html",
    "cookie-policy.html", "acceptable-use.html", "report-abuse.html", "legal.html",
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
