"""#278 — the desktop console and the web dashboard tell ONE story about grading.

**This guard is worth more than the string edits it protects, because nothing
was watching.** #228 rewrote the web's grading copy; the desktop reads the same
API and kept the old absolute claims; and every suite stayed green, because no
test had ever compared the two surfaces. A customer who reads the console, the
dashboard and the Compliance Passport must not find three stories, and the only
thing that can enforce that is a test that fails when one side moves alone.

Three premise corrections found while building it, all verified at ``a8e42e8``:

1. **Only the verify string had actually drifted.** The register lists four
   desktop sites as "one phase behind". Three of them — the two "once the Judge
   processes…" empty states and ``home_page``'s copy of the first — were
   **byte-identical to the web's**, which still carried them too. They were not
   drift; they were the same false claim standing on both surfaces. Fixing only
   the desktop would have *created* the divergence this file exists to stop, so
   both sides moved together. A fourth pair (``Breaches appear here as the Judge
   flags interactions.``) was in neither the register nor the brief and is the
   same sentence again; leaving one of three identical false claims standing
   would have been the worse half of a cleanup.

2. **On a keyless workspace every one of them is false.** ``judge_routing``
   falls through to the deterministic rules when no provider key can be reached,
   and #228's own copy says so: *"by the AI judge, or by the deterministic rules
   where no judge could be reached"*. That is the vocabulary used here — the
   web's, not a third one.

3. **The breach panel's sentence is deliberately SHORTER on the desktop, and
   that divergence is the honest half.** ``GET /v1/verify/hash/{h}`` returns
   ``found / seq / chain_hash / policy_tag / agent / verified / status /
   created_at`` and **no** ``graded_by``, which is why #228 stopped the web
   naming a grader there. The web can still end *"Open it in the ledger to see
   what graded it."* because its ledger row renders a provenance chip. The
   desktop's cannot: ``graded_by`` appears **nowhere** in ``desktop/``, so that
   sentence would send a customer to look for something that is not there.

   So this file pins the **claim** both surfaces must share, not the sentence.
   That is the register's standing rule applied to a guard: where a surface
   cannot back a clause, it stops making it — it does not soften it into
   something vaguer that still implies it.

**How it avoids being green from birth.** The Python side is read through
``ast``, not ``grep``: implicit string concatenation is joined (the desktop
splits every one of these across two source lines, so a raw text search for the
whole sentence would find nothing and a naive fix would be to weaken the search)
and **docstrings are excluded**, because prose explaining a rule must never be
able to satisfy a test hunting the rule — this repo has shipped that hole three
times. The HTML side is read with comments stripped for the same reason. And the
breach claim is not only searched for: ``verify_data.record_result`` is *driven*
and its output asserted, because a static guard executes nothing.
"""

from __future__ import annotations

import ast
import pathlib
import re
import sys
from functools import lru_cache

import pytest

_HERE = pathlib.Path(__file__).resolve().parent
_ROOT = _HERE.parent
_DESKTOP = _ROOT / "desktop"
_HTML = _HERE / "foxy-audit-premium.html"


# ══ the claims ══════════════════════════════════════════════════════════════
#: Empty states. Each must appear VERBATIM on both surfaces — same words, same
#: order — because a customer moving between them is reading the same product.
SHARED_SENTENCES = {
    "grading-status empty state":
        "Grading status appears once the AI judge or the deterministic rules "
        "grade an interaction.",
    "verdict-donut empty state":
        "Verdicts appear once the AI judge or the deterministic rules grade an "
        "interaction.",
    "threat-timeline empty state":
        "Breaches appear here as the AI judge or the deterministic rules flag "
        "an interaction.",
    # The judge-card blurb. #228 rewrote the web's (html:2369) and the desktop's
    # copy (`policy_data.JUDGE_BLURB`) did not follow — found by walking that
    # commit's diff rather than the register's list, which named four sites and
    # missed this one. Only the shared CLAIM is pinned: the web's sentence ends
    # "— the card below counts both", pointing at a card the console does not
    # have, so that pointer is one surface's and not the pair's.
    "judge-card fallback claim":
        "Where none can be reached, the deterministic rules engine grades the "
        "event instead and the record says so",
}

#: The verify panel's breach sentence. Only the CLAIM is shared; see §3 of the
#: module docstring for why the web is allowed one clause more.
BREACH_CLAIM = "the record is untampered, and it is recorded as a policy breach"

#: The wordings #228 retired. Any of them reappearing on either surface is the
#: drift this file exists to catch, and the message says which surface moved.
SUPERSEDED = (
    "once the Judge processes",
    "as the Judge flags",
    "but the Judge flagged",
)

#: ⚠ A grader NAME in the verify panel is the specific invention #228 removed.
#: The endpoint does not return one, so neither surface may print one there.
GRADER_NAMES = ("the Judge", "AI judge", "deterministic rules")


# ══ reading the two surfaces ════════════════════════════════════════════════
@lru_cache(maxsize=1)
def web_scripts() -> str:
    """Every inline ``<script>`` in the shipped dashboard, comments STRIPPED.

    A note explaining why a sentence was removed must not be able to satisfy a
    test looking for the sentence. Same stripping the #228 guard uses.
    """
    src = _HTML.read_text(encoding="utf-8")
    src = re.sub(r"<!--.*?-->", " ", src, flags=re.S)
    body = "\n".join(re.findall(r"<script(?![^>]*\bsrc=)[^>]*>(.*?)</script>",
                                src, re.S))
    body = re.sub(r"/\*.*?\*/", " ", body, flags=re.S)
    return re.sub(r"(?m)//.*$", "", body)


@lru_cache(maxsize=1)
def web_markup() -> str:
    """The dashboard's markup with comments stripped — the empty states that are
    written as HTML rather than built in JS live here."""
    return re.sub(r"<!--.*?-->", " ", _HTML.read_text(encoding="utf-8"), flags=re.S)


def _docstring_ids(tree: ast.AST) -> set[int]:
    """Every string node that is a docstring, so it can be excluded."""
    out: set[int] = set()
    for node in ast.walk(tree):
        body = getattr(node, "body", None)
        if not isinstance(node, (ast.Module, ast.ClassDef,
                                 ast.FunctionDef, ast.AsyncFunctionDef)):
            continue
        if (body and isinstance(body[0], ast.Expr)
                and isinstance(body[0].value, ast.Constant)
                and isinstance(body[0].value.value, str)):
            out.add(id(body[0].value))
    return out


@lru_cache(maxsize=None)
def desktop_strings(name: str) -> tuple[str, ...]:
    """The string LITERALS of one desktop module — concatenation joined by the
    parser, comments gone with the tokens, docstrings dropped on purpose."""
    tree = ast.parse((_DESKTOP / name).read_text(encoding="utf-8"))
    skip = _docstring_ids(tree)
    return tuple(n.value for n in ast.walk(tree)
                 if isinstance(n, ast.Constant) and isinstance(n.value, str)
                 and id(n) not in skip)


@lru_cache(maxsize=1)
def desktop_modules() -> tuple[str, ...]:
    return tuple(sorted(p.name for p in _DESKTOP.glob("*.py")
                        if not p.name.startswith("test_")))


def _desktop_says(text: str) -> list[str]:
    """The desktop modules whose visible strings carry ``text``."""
    return [m for m in desktop_modules()
            if any(text in s for s in desktop_strings(m))]


# ══ the guards ══════════════════════════════════════════════════════════════
@pytest.mark.parametrize("where", sorted(SHARED_SENTENCES))
def test_both_surfaces_say_the_same_thing_about_who_grades(where):
    """The pair moves together or this dies naming the side that moved."""
    sentence = SHARED_SENTENCES[where]
    on_web = sentence in web_scripts() or sentence in web_markup()
    on_desktop = _desktop_says(sentence)
    assert on_web and on_desktop, (
        f"the {where} has drifted: the web "
        f"{'has' if on_web else 'DOES NOT have'} it and the desktop "
        f"{'has' if on_desktop else 'DOES NOT have'} it.\n"
        f"  expected on both: {sentence!r}\n"
        f"Change both surfaces or neither — that is what this file is for. If "
        f"the wording is genuinely improving, update SHARED_SENTENCES in the "
        f"same commit as BOTH files, never as a way past a red test.")


def test_the_breach_claim_is_shared_and_the_desktop_one_is_driven_not_grepped():
    """The verify panel's claim, on both surfaces — and executed on the desktop.

    A static guard proves a literal exists, not that anything emits it. This one
    calls the function the panel calls.
    """
    assert BREACH_CLAIM in web_scripts(), (
        f"the dashboard's verify panel stopped saying {BREACH_CLAIM!r}")

    sys.path.insert(0, str(_DESKTOP))
    try:
        for stale in ("verify_data", "home_data"):
            sys.modules.pop(stale, None)
        import verify_data                      # Qt-free by design
    finally:
        sys.path.remove(str(_DESKTOP))

    tone, title, detail = verify_data.record_result(
        {"found": True, "verified": True, "status": "breach", "seq": 42})
    assert tone == "warn", "a breach is not a verification failure"
    assert BREACH_CLAIM in detail, (
        f"the console's verify panel no longer makes the web's claim.\n"
        f"  emitted: {detail!r}\n  expected to contain: {BREACH_CLAIM!r}")
    assert "42" in detail, "the sentence stopped naming the sequence number"


def test_neither_verify_panel_names_a_grader_it_cannot_know():
    """``/v1/verify/hash/{h}`` returns no ``graded_by``. Both panels must say so
    by saying nothing — this is the exact invention #228 removed, and the reason
    the desktop's sentence is a clause shorter than the web's."""
    sys.path.insert(0, str(_DESKTOP))
    try:
        for stale in ("verify_data", "home_data"):
            sys.modules.pop(stale, None)
        import verify_data
    finally:
        sys.path.remove(str(_DESKTOP))

    _, _, detail = verify_data.record_result(
        {"found": True, "verified": True, "status": "breach", "seq": 9})
    for name in GRADER_NAMES:
        assert name not in detail, (
            f"the console's breach panel names {name!r} as the grader. The "
            f"endpoint behind it does not return one — see this test's docstring.")

    # The web's own sentence, isolated so the rest of the file's judge copy
    # (which IS backed) cannot mask a regression here.
    #
    # ⚠ CAPTURE THE WHOLE ARGUMENT, NOT THE FIRST QUOTED RUN. The detail is a JS
    # concatenation — `'Seq '+d.seq+' — the record …'` — so a `'([^']*)'` group
    # stops at `Seq ` and every assertion below then passes over four characters.
    # That is the guard that is green because it is looking at nothing.
    hit = re.search(r"panel\('warn','✓','Record intact · policy breach',(.+?)\);",
                    web_scripts())
    assert hit, "the dashboard's breach panel could not be located"
    detail = hit.group(1)
    assert "the record is untampered" in detail and len(detail) > 60, (
        f"the breach panel's detail did not come back whole: {detail!r}")
    for name in GRADER_NAMES:
        assert name not in detail, (
            f"the dashboard's breach panel names {name!r} again: {detail!r}")


def test_no_retired_wording_survives_on_either_surface():
    """The half that makes a one-sided revert die loudly instead of quietly."""
    for phrase in SUPERSEDED:
        assert phrase not in web_scripts() and phrase not in web_markup(), (
            f"the dashboard has gone back to {phrase!r} — that claim is false "
            f"on a workspace with no reachable judge key")
        offenders = _desktop_says(phrase)
        assert not offenders, (
            f"the desktop has gone back to {phrase!r} in {offenders} — that "
            f"claim is false on a workspace with no reachable judge key")


def test_the_guard_is_reading_real_files_and_not_an_empty_string():
    """⚠ Every assertion above is a substring search, and a substring search over
    nothing passes the negative half and fails silently on the positive half in
    ways that read like a copy change. Pin the inputs."""
    assert len(web_scripts()) > 100_000, "the dashboard's scripts came back short"
    assert "function ledgerRow(it)" in web_scripts(), "wrong script text"
    assert len(desktop_modules()) > 30, "the desktop module list came back short"
    for name in ("dashboard.py", "home_page.py", "verify_data.py"):
        assert name in desktop_modules(), f"{name} vanished from desktop/"
        assert desktop_strings(name), f"{name} parsed to no strings at all"
    # The docstring exclusion must actually exclude something, or it is a no-op
    # that would let a comment satisfy every test above.
    ledger = (_DESKTOP / "ledger_data.py").read_text(encoding="utf-8")
    assert "recorded as a policy breach" in ledger, "docstring fixture moved"
    assert not any("refusal to collapse" in s
                   for s in desktop_strings("ledger_data.py")), (
        "docstrings are reaching the string list — every guard in this file "
        "could then be satisfied by a comment about the rule")
