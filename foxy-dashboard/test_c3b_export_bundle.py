"""The Export page's four download paths: the bundle is reachable, and no path
presents a truncated export as complete.

Two register entries, one surface.

**AQ-002 / the bundle.** `GET /v1/logs/export?format=bundle` returns
`foxy-audit-export.zip` — the ledger, the standalone verifier and VERIFY.txt in
one archive. It is the strongest evidence asset the product has and it appeared
on no customer surface: a grep over `foxy-dashboard/` and `foxy-sale-page/`
returned one hit, an HTML comment. Meanwhile this file at the offline-check note
tells the reader to "Download the verification bundle from Export", and the
Compliance Passport tells the AUDITOR to ask for `foxy-audit-export.zip` by
filename. Two documents instructed people to obtain a download the product did
not offer.

**#284 / completeness.** Since `1007a02` an export is capped at
`EXPORT_PAGE_MAX` (10,000) rows and carries a `page` block saying so, with the
URL of the next page. Every download here was an `<a href>` click, so no
JavaScript ever read the body: the FILE said it was page 1 of 300 and the screen
said "export started". Four paths had the defect — the dropdown's CSV, JSON and
(new) bundle routes, and Settings → Data & privacy.

⚠ THE TRAP THIS FILE EXISTS FOR. The format mapping was
`var fmt=(type==='logs_csv')?'csv':'json'` — every value it did not name became
`json`. Adding a bundle option without touching that line would have downloaded
JSON under a label saying bundle: a new false surface inside the phase whose
purpose is removing false surfaces. `test_the_format_map_is_a_table_not_a_guess`
is the guard against it coming back.

MUTATION RESULTS — 13 introduced, 13 caught, 2026-09-02. Recorded here rather
than in a chat because a guard nobody has tried to break is a guard nobody knows
the strength of:

  dropped the bundle <option>              -> test_the_export_dropdown_offers_the_bundle
  restored the silent format ternary       -> test_the_format_map_is_a_table_not_a_guess
  promoted the bundle to default           -> test_the_passport_is_still_the_default_export
  notice edge back to the 1.03:1 hairline  -> test_the_notice_carries_a_real_border
  removed role/aria-live from the notice   -> test_the_notice_regions_exist_and_announce_themselves
  dashboard wrote its own page sentence    -> test_the_notice_is_the_files_own_sentence
  added a fifth <a href> download path     -> test_every_ledger_download_goes_through_one_function
  dropped the server-chosen filename       -> test_the_server_chosen_filename_is_kept
  history table lost the bundle label      -> test_the_export_history_can_label_a_bundle_row
  unknown export type fell through quietly -> test_an_unmapped_export_type_downloads_nothing
  isPartial forgot the from_seq>1 case     -> test_a_partial_export_is_defined_the_way_the_backend_defines_it
  Settings button said CSV again           -> test_the_settings_button_names_the_format_it_produces
  bundle page 2 downloaded as a bundle     -> test_the_next_page_of_a_bundle_is_a_json_page
"""
from __future__ import annotations

import io
import pathlib
import re

import pytest

HTML = pathlib.Path(__file__).with_name("foxy-audit-premium.html")


@pytest.fixture(scope="module")
def html() -> str:
    return io.open(HTML, encoding="utf-8").read()


@pytest.fixture(scope="module")
def export_js(html: str) -> str:
    """The one inline <script> that owns every ledger download."""
    blocks = re.findall(
        r"<script(?![^>]*\bsrc=)[^>]*>(.*?)</script>", html, re.S)
    owning = [b for b in blocks if "window.runExportFlow" in b]
    assert len(owning) == 1, (
        f"{len(owning)} inline scripts define runExportFlow; there must be "
        f"exactly one, or two of them can disagree about what a download is")
    # ⚠ COMMENTS STRIPPED, and that is register #52's lesson applied to a guard
    # rather than to a page: a comment EXPLAINING a banned expression trips a
    # grep for it exactly as a live one does. These tests read code.
    body = owning[0]
    body = re.sub(r"/\*.*?\*/", "", body, flags=re.S)
    body = re.sub(r"^\s*//.*$", "", body, flags=re.M)
    return body


# ───────────────────────────── the bundle is reachable ─────────────────────

def test_the_export_dropdown_offers_the_bundle(html):
    """AQ-002. The strongest evidence asset the product has was reachable only
    by hand-editing a URL."""
    select = re.search(r'<select id="exportType">(.*?)</select>', html, re.S)
    assert select, "the export-type <select> is gone"
    values = re.findall(r'<option value="([^"]+)"', select.group(1))
    assert "logs_bundle" in values, (
        "the Export dropdown does not offer the verification bundle. The "
        "offline-check note in this same file, and the Compliance Passport, "
        "both tell a reader to obtain foxy-audit-export.zip")


def test_the_passport_is_still_the_default_export(html):
    """Owner decision: the bundle is ADDED as a choice, never promoted. The
    first <option> is what a customer gets without touching the control."""
    select = re.search(r'<select id="exportType">(.*?)</select>', html, re.S)
    first = re.search(r'<option value="([^"]+)"', select.group(1))
    assert first.group(1) == "passport", (
        f"the default export type is now {first.group(1)!r}. The passport is "
        f"the default by decision, not by accident")


def test_the_bundle_option_is_described_where_it_is_offered(html):
    """A control named "Verification bundle · ZIP" and nothing else is a control
    only the person who built it understands."""
    assert "foxy-audit-export.zip" in html, (
        "the Export page never names the file the bundle option produces — "
        "which is the name the Compliance Passport tells auditors to ask for")
    assert "standalone verifier" in html


def test_the_export_history_can_label_a_bundle_row(export_js):
    """A row the table cannot name renders its raw type string. The backend
    already accepts `logs_bundle` (routers/account.py `_EXPORT_TYPES`), so this
    would have shipped visible the first time anyone used the new option."""
    types = re.search(r"var TYPE=\{(.*?)\};", export_js, re.S)
    assert types and "logs_bundle:" in types.group(1), (
        "the export-history table has no label for logs_bundle rows")


# ─────────────────────── the mapping that silently lied ────────────────────

def test_the_format_map_is_a_table_not_a_guess(export_js):
    """⚠ THE ONE THAT COST THE MOST TO FIND. A ternary defaulting to json meant
    any option the mapping did not name downloaded JSON *while appearing to
    work*. A table has no default."""
    assert "(type==='logs_csv')?'csv':'json'" not in export_js, (
        "the silent format ternary is back. Anything it does not name becomes "
        "json, so a new <option> downloads the wrong file and says nothing")
    table = re.search(r"var FORMAT_OF=\{(.*?)\};", export_js)
    assert table, "no FORMAT_OF table — how is the export type mapped now?"
    body = table.group(1)
    for export_type, fmt in (("logs_csv", "csv"), ("logs_json", "json"),
                             ("logs_bundle", "bundle")):
        assert f"{export_type}:'{fmt}'" in body, (
            f"FORMAT_OF does not map {export_type} to {fmt}")


def test_an_unmapped_export_type_downloads_nothing(export_js):
    """The whole point of a table over a ternary: the unknown case is refused,
    in the open, rather than resolved to whatever the fallback happened to be."""
    assert "Unknown export type" in export_js, (
        "runExportFlow does not refuse a type FORMAT_OF cannot map; it is "
        "guessing again")


# ──────────────────────────── #284 · completeness ──────────────────────────

def test_every_ledger_download_goes_through_one_function(html, export_js):
    """Four surfaces, one implementation — because there was one defect. A
    second `<a href='/v1/logs/export…'>` anywhere is a fifth path that has to
    learn the same lesson separately."""
    hrefs = re.findall(r"\.href\s*=\s*'(/v1/logs/export[^']*)'", html)
    assert not hrefs, (
        f"a ledger download bypasses foxLedgerDownload and so never reads the "
        f"page block: {hrefs}")
    assert "window.foxLedgerDownload=downloadLedger" in export_js
    assert "window.foxLedgerDownload({" in html, (
        "the Settings ledger export no longer uses the shared downloader")


def test_the_notice_is_the_files_own_sentence(export_js):
    """⚠ NOT A SECOND DESCRIPTION OF COMPLETENESS. `_page_export` lives in one
    place in the backend precisely so two descriptions of one file cannot
    disagree; copying its wording into the dashboard would put the second one
    back, in a place no backend test can see."""
    assert "esc(page.note||'')" in export_js, (
        "the notice no longer renders page.note verbatim — if the dashboard is "
        "writing its own completeness sentence, it can drift from the file's")
    for invented in ("THIS IS NOT THE WHOLE LEDGER",
                     "Download the next page from the",
                     "rows 1-"):
        assert invented not in export_js, (
            f"the dashboard has its own copy of the backend's page note "
            f"({invented!r}). One sentence, one place")


def test_the_download_reads_the_page_block_of_what_it_downloaded(export_js):
    """JSON carries `page`; CSV carries the same note in leading `#` lines and
    carries none at all when the file is whole; a ZIP carries neither, so the
    bundle path reads the JSON it is built from. All three are here."""
    assert "function pageOfJson" in export_js
    assert "function pageOfCsv" in export_js
    assert "withFormat('json')" in export_js, (
        "the bundle path no longer reads a page block from anywhere — a ZIP "
        "has none to read, so it must ask for the JSON it is built from")


def test_a_partial_export_is_defined_the_way_the_backend_defines_it(export_js):
    """`partial = rows and not (complete and from_seq == 1)`. A file that starts
    at seq 500 proves its own rows and nothing before them, and that is worth
    saying even though nothing was truncated."""
    fn = re.search(r"function isPartial\(page\)\{(.*?)\n  \}", export_js, re.S)
    assert fn, "isPartial is gone"
    body = fn.group(1)
    assert "complete===false" in body and "from_seq>1" in body, (
        "isPartial no longer covers both halves of the backend's own "
        f"definition: {body.strip()!r}")


def test_the_next_page_of_a_bundle_is_a_json_page(export_js):
    """VERIFY.txt's own instruction, and the reason is a filename: every bundle
    downloads as foxy-audit-export.zip, because the Compliance Passport names
    that file in writing. Offering page 2 as a second bundle hands the customer
    a download that overwrites page 1 — so the next-page control switches to
    JSON, which arrives named for the seq range it holds."""
    assert "var nextFmt=(o.format==='bundle')?'json':o.format;" in export_js, (
        "the next-page control no longer switches a bundle to JSON; every page "
        "would download as foxy-audit-export.zip and overwrite the last")


def test_the_notice_regions_exist_and_announce_themselves(html):
    """Visual-only is not enough: an export that is page 1 of 300 is a fact, not
    a decoration, so the region is a live region on both surfaces."""
    for element_id in ("exportNotice", "wsExportNotice"):
        m = re.search(r'<div id="%s"[^>]*>' % element_id, html)
        assert m, f"#{element_id} is gone; a download path has nowhere to say it"
        tag = m.group(0)
        assert 'class="expnote"' in tag, f"#{element_id} is not an .expnote"
        assert 'role="status"' in tag and 'aria-live' in tag, (
            f"#{element_id} is not announced: {tag}")


def test_the_notice_carries_a_real_border(html):
    """#113 · the amber plate measures 1.74:1 against the light surface, so
    without an edge this block has no boundary at all. The same declaration is
    what keeps it visible in Windows High Contrast, where forced-colors remaps
    the colour and preserves width and style (see test_g9_forced_colors.py)."""
    rule = re.search(r"\n\.expnote\{([^}]*)\}", html)
    assert rule, ".expnote has no base rule"
    border = re.search(r"(?<!-)border\s*:\s*([^;]+)", rule.group(1))
    assert border, ".expnote declares no border; in High Contrast it is bare text"
    assert "--warn-ink" in border.group(1), (
        f"the notice's edge is {border.group(1).strip()!r}. --bc is the 1.03:1 "
        f"hairline #113 condemned; the amber plate needs --warn-ink")


def test_the_server_chosen_filename_is_kept(export_js):
    """The backend names a partial page for the seq range it holds so that 300
    of them land side by side in one folder — VERIFY.txt tells the auditor
    exactly that. A hardcoded `download` attribute made every page arrive as
    foxy-audit-logs.json, overwriting the last."""
    assert "content-disposition" in export_js, (
        "the download no longer reads the filename the server chose, so paged "
        "exports all land under one name and overwrite each other")


def test_the_settings_button_names_the_format_it_produces(html):
    """It said "export ledger (CSV)" and has always fetched format=json."""
    m = re.search(r'onclick="exportWorkspaceData\(this\)"[^>]*>([^<]+)<', html)
    assert m, "the Settings ledger-export button is gone or no longer passes `this`"
    assert "CSV" not in m.group(1).upper() or "JSON" in m.group(1).upper(), (
        f"the button says {m.group(1)!r} and downloads JSON")
