"""#263 — a pass count means nothing without the skip count beside it.

**The measurement that started this.** CI run `33126957825`: `1437 passed,
4 skipped`. The same commit on a developer machine: `1438 passed, 3 skipped`.
Total 1441 both ways, so exactly one test that runs on a dev box skips on
`ubuntu-latest` — and nobody could say which. Three instances of that family
landed in three days (#258: four PyYAML-gated packaging guards skip on the
runner and hid a genuine red; #266: a dev venv patched where CI is vulnerable),
so the standing lesson is that **the gate's ENVIRONMENT is part of the gate**.

**It is `test_passport_render.py::test_a_broken_renderer_returns_500_not_html_
with_a_200`, and it is correct that it skips.** That test asserts the passport
route fails loudly when weasyprint cannot render. It skips when a PDF comes
back — i.e. when the host CAN render. `backend/requirements.txt` pins
`weasyprint>=62,<64`, but weasyprint is a binding to pango / cairo / gdk-pixbuf,
and those native libraries are present on `ubuntu-latest` and absent on the
Windows dev box. So the failure path is the real one locally and unreachable in
CI. Making it run in CI would mean breaking the renderer there on purpose; the
deliverable is that the difference is **known and recorded**, not erased.

**What this file guards is the inventory, not the answer.** Every skip mechanism
in this tree is declared below with where it fires, so:

* a new skip cannot be added without someone stating whether it fires in CI,
  locally, or both — which is the fact that was missing for two days;
* a declared entry that no longer matches any real skip site fails, so this
  registry cannot rot into a list of retired conditions;
* the one environment-divergent skip is pinned by name, so a second one arriving
  is a red test rather than another arithmetic puzzle.

⚠ READ THROUGH `ast`, NOT `grep`. `test_judge_content_blindness.py` carries two
COMMENTS about `pytest.importorskip` explaining why the fixture stopped using
it. A regex would count those as skip sites and this registry would then be
describing prose. Parsing means a comment cannot be a finding.
"""

from __future__ import annotations

import ast
import pathlib

import pytest

_HERE = pathlib.Path(__file__).resolve().parent

#: Where a skip site fires. The value is the thing that was missing from #263:
#: not "why is this skipped" (the `reason=` already says that) but "on which of
#: the two machines whose counts we compare".
BOTH = "both — the condition holds in CI and on a dev machine"
NEITHER = "neither — the condition is false in CI and on a dev machine"
CI_ONLY = "CI ONLY — runs on a dev machine, skips on ubuntu-latest"
SOMETIMES = "sometimes — the condition is neither environmental nor stable"

#: Every skip mechanism in `backend/tests/integration`, keyed by the file and a
#: distinctive fragment of the skip EXPRESSION.
#:
#: ⚠ Keyed by the expression, never by a line number. Half this register's wrong
#: citations are line numbers quoted from a file that later phases have edited;
#: a fragment of the condition moves with it.
SKIP_SITES = {
    ("test_account_avatar.py", "importorskip('PIL'"): (
        NEITHER, "backend/requirements.txt pins pillow==12.3.0, so it is "
                 "installed by `pip install -r` in CI and in a dev venv built "
                 "the same way"),
    ("test_admin_org_quota.py", "the month is younger than the rollup window"): (
        SOMETIMES, "date-dependent: fires on any machine during the first ~2 "
                   "days of a month, on neither for the other ~27"),
    ("test_export_bundle.py", "not REAL_VERIFIER.exists()"): (
        NEITHER, "verifier/ is in the same checkout on both — four sites"),
    ("test_export_paging.py", "not REAL_VERIFIER.exists()"): (
        NEITHER, "as above, for #271's paged export — eleven sites. These shell "
                 "out to the REAL verifier rather than importing it, because "
                 "what they prove is that a customer holding N page files and "
                 "one command gets `chain intact`, and the exit code is half of "
                 "that claim. If verifier/ ever stops being in this checkout "
                 "they skip, and the disposition below is what says so out loud"),
    ("test_optional_integrations.py", "os.environ.get('GEMINI_API_KEY')"): (
        BOTH, "no live provider key is set in CI or locally, by design"),
    ("test_optional_integrations.py", "os.environ.get('OPENAI_API_KEY')"): (
        BOTH, "as above"),
    ("test_optional_integrations.py", "os.environ.get('ANCHOR_PROVIDER')"): (
        BOTH, "ANCHOR_PROVIDER is unset in CI and locally"),
    ("test_passport_render.py", "weasyprint renders on this host"): (
        CI_ONLY, "⚠ THE #263 ANSWER. Skips where weasyprint's native stack "
                 "(pango/cairo/gdk-pixbuf) is present — ubuntu-latest — and "
                 "RUNS where it is absent, which is the Windows dev box. That "
                 "is the whole 1437+4 vs 1438+3 difference."),
    ("test_timezone_independence.py", "shutil.which('bash') is None"): (
        NEITHER, "/bin/bash in CI, Git Bash on the dev box"),
    ("test_timezone_independence.py", "bash on PATH but not usable"): (
        NEITHER, "the guard's own proof-of-execution fallback; fires only where "
                 "bash resolves but cannot start (an unprovisioned WSL stub)"),
}

#: The count each key stands for, where one expression appears more than once.
_EXPECTED_OCCURRENCES = {
    ("test_export_bundle.py", "not REAL_VERIFIER.exists()"): 4,
    ("test_export_paging.py", "not REAL_VERIFIER.exists()"): 11,
}


def _skip_sites() -> list[tuple[str, str]]:
    """Every `pytest.skip` / `pytest.importorskip` call and every `skipif`
    decorator in this tree, as (file, unparsed expression)."""
    found: list[tuple[str, str]] = []
    for path in sorted(_HERE.rglob("*.py")):
        if path.name == pathlib.Path(__file__).name:
            continue
        tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
        for node in ast.walk(tree):
            if isinstance(node, ast.Call) and ast.unparse(node.func) in (
                    "pytest.skip", "pytest.importorskip", "pytest.xfail"):
                found.append((path.name, ast.unparse(node)))
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
                for deco in node.decorator_list:
                    text = ast.unparse(deco)
                    if text.startswith("pytest.mark.skipif"):
                        found.append((path.name, text))
    return found


def _matches(key: tuple[str, str], sites: list[tuple[str, str]]) -> list[str]:
    name, fragment = key
    return [expr for f, expr in sites if f == name and fragment in expr]


def test_the_registry_is_not_empty_and_every_entry_says_where_it_fires():
    """⚠ ANTI-VACUITY FIRST. Everything below iterates `SKIP_SITES`; emptying it
    would turn this file green while it described nothing — the exact shape
    #279 was filed for, one directory along."""
    assert len(SKIP_SITES) >= 9, (
        f"SKIP_SITES has shrunk to {len(SKIP_SITES)} entries. Every loop in this "
        f"file iterates it, so a short list is a quiet one.")
    dispositions = {BOTH, NEITHER, CI_ONLY, SOMETIMES}
    for key, (where, why) in SKIP_SITES.items():
        assert where in dispositions, f"{key} has an undeclared disposition"
        assert why.strip(), f"{key} says where it fires but not why"


def test_every_declared_skip_site_still_exists():
    """The half that stops the registry rotting into retired conditions."""
    sites = _skip_sites()
    assert sites, "the AST scan found no skip sites at all — it is reading nothing"
    for key in SKIP_SITES:
        hits = _matches(key, sites)
        expected = _EXPECTED_OCCURRENCES.get(key, 1)
        assert len(hits) == expected, (
            f"{key[0]} no longer carries {expected} skip site(s) matching "
            f"{key[1]!r} — found {len(hits)}. Either the skip moved and this "
            f"entry needs updating, or it is gone and the entry should be too.")


def test_no_skip_in_this_tree_is_undeclared():
    """The half that makes a NEW skip a decision somebody records.

    A skip added without a line here is a test that silently stops running on
    one machine and not the other, which is #263 and #258 both.
    """
    undeclared = [
        (name, expr) for name, expr in _skip_sites()
        if not any(f == name and frag in expr for (f, frag) in SKIP_SITES)]
    assert undeclared == [], (
        "these skip sites are not in SKIP_SITES:\n  "
        + "\n  ".join(f"{n}: {e[:110]}" for n, e in undeclared)
        + "\nAdd each with where it fires (CI, locally, both, neither). A pass "
          "count is only readable next to the skips it does not include.")


def test_exactly_one_skip_differs_between_ci_and_a_dev_machine():
    """The #263 answer, pinned so a second divergence is a red test.

    Not a claim that the divergence is wrong — that test SHOULD skip where the
    renderer works. A claim that it is the only one, and that it is known.
    """
    divergent = {k for k, (where, _) in SKIP_SITES.items() if where == CI_ONLY}
    assert divergent == {("test_passport_render.py",
                          "weasyprint renders on this host")}, (
        f"the set of environment-divergent skips changed: {sorted(divergent)}.\n"
        f"CI and a dev machine now disagree about a different test than #263 "
        f"identified. Re-measure both counts before editing this expectation.")


def test_the_divergent_skip_is_decided_by_the_renderer_and_by_nothing_else(
        make_org, client):
    """Driven, not asserted about the source.

    A static registry can say where a skip fires; only running the thing can
    show that the reason it fires is the reason claimed. This asks the process
    two questions — can weasyprint be imported, and does `/v1/passport` hand
    back a PDF — and requires the answers to agree.

    Both answers are correct. That is the whole point of #263: `ubuntu-latest`
    has pango / cairo / gdk-pixbuf and the Windows dev box does not, so one host
    exercises the success path and the other exercises the failure path, and
    neither count is wrong. A THIRD outcome — importable but not rendering, or
    rendering without importing — would mean the divergence is keyed to
    something other than the native stack, and this test is where that surfaces
    instead of arriving as an unexplained count.
    """
    import importlib

    try:
        importlib.import_module("weasyprint")
        importable = True
    except Exception:
        importable = False

    r = client.post("/v1/passport", headers=make_org()["auth"], json={})
    renders = r.headers.get("content-type") == "application/pdf"

    assert renders == importable, (
        f"weasyprint importable={importable} but /v1/passport "
        f"{'rendered a PDF' if renders else f'answered {r.status_code}'}. The "
        f"registry claims this skip is decided by whether the native renderer "
        f"is present; on this host it is not, so the CI-vs-local skip count is "
        f"explained by something else and #263's answer needs re-measuring.")
