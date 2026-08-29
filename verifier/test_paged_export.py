"""#271 — a paged export, verified without a backend.

`backend/tests/integration/test_export_paging.py` proves the REAL endpoint's
pages verify. This file proves the recipe underneath, stdlib only: what a page
asserts about the chain, what it may not assert, and every way two pages can fail
to join. No Postgres, no FastAPI — `pytest verifier/` alone runs it, which is
what CI does.

⚠ The single property everything here defends: a page proves ITS OWN rows and
nothing outside them. `[OK] chain intact` is said only over a set of pages that
runs from seq 1 to the end of the ledger; anything less is `segment intact` and
exit 3.
"""

from __future__ import annotations

import json
import os
import subprocess
import sys

import pytest

sys.path.insert(0, os.path.dirname(__file__))

import foxy_verify as fv  # noqa: E402

ORG = "11111111-2222-3333-4444-555555555555"


def _rows(n):
    rows, prev = [], fv.GENESIS_HASH
    for i in range(1, n + 1):
        row = {"seq": i, "prompt_hash": f"{i:064d}", "response_hash": f"{i:064x}",
               "token_count": 10 * i, "policy_tag": "chat", "prev_hash": prev}
        row["chain_hash"] = fv.compute_chain_hash(
            org_id=ORG, prompt_hash=row["prompt_hash"],
            response_hash=row["response_hash"], token_count=row["token_count"],
            policy_tag=row["policy_tag"], seq=i, prev_hash=prev)
        rows.append(row)
        prev = row["chain_hash"]
    return rows


def _paginate(rows, size, anchor_at=None, org=ORG):
    """The exact page shape `logs._page_export` emits, built here from the
    verifier's own recipe so this file stays independent of the backend."""
    pages = []
    for i in range(0, len(rows), size):
        chunk = rows[i:i + size]
        has_more = i + size < len(rows)
        page = {"org_id": org, "count": len(chunk),
                "page": {"from_seq": chunk[0]["seq"], "to_seq": chunk[-1]["seq"],
                         "prev_chain_hash": chunk[0]["prev_hash"],
                         "complete": not has_more,
                         "next_after_seq": chunk[-1]["seq"] if has_more else None,
                         "next": "https://example.invalid/next" if has_more else None,
                         "max_rows_per_page": size, "note": "..."},
                "logs": chunk}
        if anchor_at is not None:
            page["anchor"] = {
                "chain": "stub", "status": "confirmed",
                "root_hash": rows[anchor_at - 1]["chain_hash"], "last_seq": anchor_at,
                "tx_hash": "0xabc", "block_number": 1, "anchored_at": None,
                "contract": None}
        pages.append(page)
    return pages


# ══ what a complete set of pages asserts ═══════════════════════════════════

def test_every_page_together_is_the_whole_chain():
    res = fv.verify_pages(_paginate(_rows(7), 2))
    assert res["ok"] is True and res["complete"] is True
    assert res["detail"] == "chain intact"
    assert res["count"] == 7 and res["pages"] == 4
    assert res["from_seq"] == 1 and res["to_seq"] == 7


def test_the_order_the_pages_are_handed_over_does_not_matter():
    """A customer with 300 files will not hand them over sorted."""
    pages = _paginate(_rows(6), 2)
    assert fv.verify_pages(list(reversed(pages)))["complete"] is True
    assert fv.verify_pages([pages[2], pages[0], pages[1]])["complete"] is True


def test_one_page_is_a_segment_and_never_an_intact_chain():
    """⚠ THE #252 TRAP POINTED AT THE VERIFIER. Page 1 of 4 recomputes clean, and
    calling that "chain intact" is a completeness claim over a quarter of the
    evidence, made by the tool that exists to check such claims."""
    res = fv.verify_pages(_paginate(_rows(8), 2)[:1])
    assert res["ok"] is True, "the page's own rows are intact and that is worth saying"
    assert res["complete"] is False
    assert res["detail"] == "segment intact"
    assert "continues past seq 2" in res["incomplete_reason"]


def test_all_but_the_last_page_is_still_a_segment():
    """The tail is the easiest page to forget, and losing it silently is losing
    the most recent evidence."""
    res = fv.verify_pages(_paginate(_rows(8), 2)[:-1])
    assert res["ok"] is True and res["complete"] is False
    assert res["to_seq"] == 6


# ══ page-to-page continuity ════════════════════════════════════════════════

def test_a_page_dropped_from_the_middle_is_not_a_join():
    pages = _paginate(_rows(8), 2)
    res = fv.verify_pages([pages[0], pages[2], pages[3]])
    assert res["ok"] is False and res["refused"] is False
    assert "do not join" in res["detail"]
    assert res["first_broken_seq"] == 5


def test_a_page_that_lies_about_what_it_continues_from_is_not_a_join():
    """The seqs can run perfectly while the hashes do not meet. Without this,
    `prev_chain_hash` is a field nobody reads and a forger can set freely."""
    pages = _paginate(_rows(6), 2)
    pages[1]["page"]["prev_chain_hash"] = "f" * 64
    res = fv.verify_pages(pages)
    assert res["ok"] is False
    assert "do not join at seq 3" in res["detail"]


def test_two_copies_of_the_same_page_are_not_a_chain():
    pages = _paginate(_rows(4), 2)
    res = fv.verify_pages([pages[0], pages[0]])
    assert res["ok"] is False and "do not join" in res["detail"]


def test_pages_from_two_workspaces_are_named_as_such_not_as_tampering():
    """org_id is the FIRST field of the hashed event, so this would otherwise
    surface as a hash mismatch with no hint of the real cause."""
    a = _paginate(_rows(4), 2)
    b = _paginate(_rows(4), 2, org="99999999-2222-3333-4444-555555555555")
    res = fv.verify_pages([a[0], b[1]])
    assert res["ok"] is False
    assert "different org_id" in res["detail"]


def test_tampering_on_a_later_page_is_still_named_at_its_own_seq():
    pages = _paginate(_rows(8), 2)
    pages[2]["logs"][0]["token_count"] = 999          # seq 5
    res = fv.verify_pages(pages)
    assert res["ok"] is False and res["first_broken_seq"] == 5
    assert "chain hash mismatch" in res["detail"]


# ══ a page block must describe its own rows ════════════════════════════════

def test_trimming_rows_off_the_front_of_a_page_contradicts_its_block():
    """⚠ THE CHEAPEST FORGERY A PAGED EXPORT INVITES. Delete the rows you dislike
    from one file and change nothing else. The block says which seqs the file
    holds, so the file now contradicts itself — and without this check the
    recompute would simply start one row later and report the rest intact."""
    pages = _paginate(_rows(6), 3)
    pages[0]["logs"] = pages[0]["logs"][1:]
    res = fv.verify_pages(pages)
    assert res["ok"] is False
    assert "declares it starts at seq 1" in res["detail"]


def test_trimming_rows_off_the_end_of_a_page_contradicts_its_block():
    pages = _paginate(_rows(6), 3)
    pages[1]["logs"] = pages[1]["logs"][:-1]
    res = fv.verify_pages(pages)
    assert res["ok"] is False
    assert "declares it ends at seq 6" in res["detail"]


def test_a_page_declaring_genesis_it_does_not_start_at_cannot_report_complete():
    """Belt and braces on the completeness verdict: it is taken from the rows,
    not from the number the file asserts about itself."""
    pages = _paginate(_rows(4), 4)
    pages[0]["logs"] = pages[0]["logs"][1:]
    pages[0]["page"]["from_seq"] = 2                 # block and rows agree again
    pages[0]["page"]["prev_chain_hash"] = pages[0]["logs"][0]["prev_hash"]
    res = fv.verify_pages(pages)
    assert res["ok"] is True and res["complete"] is False, (
        "a ledger missing its first row was reported whole")


# ══ an export that starts mid-ledger ═══════════════════════════════════════

def test_a_mid_ledger_export_is_a_segment_not_a_broken_chain():
    """⚠ A PRE-EXISTING DEFECT CLOSED IN PASSING. Before `page`, an export that
    did not start at seq 1 — a date-ranged one, which the dashboard's own pickers
    have always been able to produce — was recomputed from genesis, mismatched on
    its first row and reported `[FAIL] CHAIN BROKEN`. An honest export accused of
    forgery for where it began."""
    pages = _paginate(_rows(6), 6)
    pages[0]["logs"] = pages[0]["logs"][2:]
    pages[0]["page"].update(from_seq=3, to_seq=6,
                            prev_chain_hash=pages[0]["logs"][0]["prev_hash"])
    res = fv.verify_pages(pages)
    assert res["ok"] is True, res["detail"]
    assert res["complete"] is False
    assert "starts at seq 3" in res["incomplete_reason"]
    assert "rows 1-2 are not in it" in res["incomplete_reason"].replace("Rows", "rows")


def test_a_mid_ledger_export_with_no_page_block_still_verifies_its_own_rows():
    """The same file as produced BEFORE paging existed: no block, rows starting
    at 3. The first row's own `prev_hash` seeds the recompute — used, but never
    believed, so the result can never be `complete`."""
    rows = _rows(6)[2:]
    res = fv.verify_pages([{"org_id": ORG, "count": len(rows), "logs": rows}])
    assert res["ok"] is True and res["complete"] is False
    assert res["from_seq"] == 3


def test_a_seedless_mid_ledger_export_is_refused_rather_than_guessed():
    """No block and no prev_hash on the first row: there is nothing to recompute
    against. Guessing genesis would produce a mismatch, which this tool reports
    as TAMPERING — an accusation manufactured out of a missing field."""
    rows = _rows(6)[2:]
    rows[0] = {k: v for k, v in rows[0].items() if k != "prev_hash"}
    res = fv.verify_pages([{"org_id": ORG, "count": len(rows), "logs": rows}])
    assert res["refused"] is True and res["ok"] is False
    assert "nothing to recompute the first row against" in res["detail"]


# ══ backward compatibility ═════════════════════════════════════════════════

def test_an_export_written_before_paging_verifies_exactly_as_it_did():
    """An export downloaded years ago carries no `page` block. It must still be
    an intact chain, with the same wording and the same exit code."""
    rows = _rows(5)
    res = fv.verify_pages([{"org_id": ORG, "count": 5, "logs": rows}])
    assert res["ok"] is True and res["complete"] is True
    assert res["detail"] == "chain intact"


def test_verify_export_is_still_the_single_file_entry_point():
    """Every existing caller — the backend suites, the bundled copy — passes one
    dict and reads `ok`. That signature does not move."""
    export = {"org_id": ORG, "count": 3, "logs": _rows(3)}
    assert fv.verify_export(export) == fv.verify_pages([export])


# ══ the anchor over a partial export ═══════════════════════════════════════

def test_a_segment_is_not_accused_of_an_anchor_mismatch():
    """The offline check recomputes the head at the anchored seq FROM GENESIS.
    Over a segment that recompute is meaningless, and printing `DOES NOT MATCH`
    reads as tampering — so `matches` is None and it says why."""
    pages = _paginate(_rows(6), 2, anchor_at=6)
    off = fv.check_anchor_offline(pages[2])
    assert off["matches"] is None and off["checked"] is False
    assert "starts at seq 5" in off["detail"]


def test_an_early_page_does_not_reach_the_checkpoint_and_says_so():
    pages = _paginate(_rows(6), 2, anchor_at=6)
    off = fv.check_anchor_offline(pages[0])
    assert off["matches"] is None
    assert "past the last row given (seq 2)" in off["detail"]


def test_the_anchor_is_checked_once_every_page_is_present():
    """And it is not simply switched off — reassembled, it must be checked and
    must match."""
    pages = _paginate(_rows(6), 2, anchor_at=6)
    merged = fv.merge_pages(pages)
    off = fv.check_anchor_offline(merged)
    assert off["checked"] is True and off["matches"] is True


def test_a_reassembled_export_still_catches_a_wrong_anchor_root():
    pages = _paginate(_rows(6), 2, anchor_at=6)
    pages[0]["anchor"]["root_hash"] = "0" * 64
    off = fv.check_anchor_offline(fv.merge_pages(pages))
    assert off["checked"] is True and off["matches"] is False


def test_a_complete_export_that_stops_before_the_checkpoint_is_still_broken():
    """The check that a partial export is now excused from must still fire on one
    that CLAIMS to be whole."""
    pages = _paginate(_rows(4), 4, anchor_at=4)
    pages[0]["anchor"]["last_seq"] = 9
    res = fv.verify_pages(pages)
    assert res["ok"] is False
    assert "stops before the anchored checkpoint" in res["detail"]


# ══ the CLI: the exit codes are the contract ═══════════════════════════════

def _cli(tmp_path, pages, extra=()):
    names = []
    for i, p in enumerate(pages, 1):
        f = tmp_path / f"page{i}.json"
        f.write_text(json.dumps(p), encoding="utf-8")
        names.append(str(f))
    proc = subprocess.run(
        [sys.executable, os.path.join(os.path.dirname(__file__), "foxy_verify.py"),
         *names, *extra],
        capture_output=True, env={**os.environ, "PYTHONIOENCODING": "utf-8"},
        timeout=120)
    return proc.returncode, proc.stdout.decode("utf-8", "replace")


def test_cli_exit_0_only_for_the_whole_ledger(tmp_path):
    code, out = _cli(tmp_path, _paginate(_rows(6), 2))
    assert code == 0
    assert "chain intact - 6 rows verified from genesis" in out


def test_cli_exit_3_for_a_segment_and_the_word_is_never_intact(tmp_path):
    """⚠ 3, NOT 0. A CI job that treats a segment as a pass is asserting
    completeness over rows it never saw."""
    code, out = _cli(tmp_path, _paginate(_rows(6), 2)[:1])
    assert code == 3, out
    assert "segment intact" in out
    assert "chain intact" not in out
    assert "INCOMPLETE" in out and "NOT the whole ledger" in out


def test_cli_exit_1_when_the_pages_do_not_join(tmp_path):
    pages = _paginate(_rows(8), 2)
    code, out = _cli(tmp_path, [pages[0], pages[2], pages[3]])
    assert code == 1, out
    assert "segment intact" not in out and "chain intact" not in out


@pytest.mark.parametrize("n_pages,expected", [(1, 3), (2, 3), (3, 3), (4, 0)])
def test_cli_only_the_full_set_ever_exits_0(tmp_path, n_pages, expected):
    """Walked the whole way: exit 0 appears exactly once, at the point the pages
    actually cover the ledger."""
    code, _ = _cli(tmp_path, _paginate(_rows(8), 2)[:n_pages])
    assert code == expected


def test_cli_json_mode_carries_the_completeness_verdict(tmp_path):
    code, out = _cli(tmp_path, _paginate(_rows(6), 2)[:2], extra=("--json",))
    assert code == 3
    report = json.loads(out)
    assert report["chain"]["ok"] is True
    assert report["chain"]["complete"] is False
    assert report["chain"]["incomplete_reason"]
