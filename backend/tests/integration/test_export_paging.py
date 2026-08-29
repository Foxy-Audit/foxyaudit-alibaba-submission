"""#271 — the export is bounded, it SAYS when it stops, and the pages verify.

`GET /v1/logs/export?format=json` used to load every matching row and serialise
the lot. At 1782.9-2169.6 B a row, a Max-plan workspace's year (3,000,000 rows)
was one 5.3-6.5 GB allocation in the API process. It comes back in pages now.
`test_export_size_measured.py` takes those numbers; the range is real and is
explained at EXPORT_PAGE_MAX.

⚠ THE BOUND IS ONLY ACCEPTABLE BECAUSE THE FILE STATES IT. Stopping quietly at
the cap would reinstate the false completeness claim #252 exists to end, inside
the artefact a customer hands to a regulator. Every test below that proves a
bound has a twin proving the file says so.

⚠ AND THE PAGES MUST STILL VERIFY, TOGETHER. A paged export whose pages cannot
be recomputed as one chain — or can be, but only if a human reassembles them in
the right order — is worse than a big one. `verifier/foxy_verify.py` takes them
all in one command and requires each to join the one before it at BOTH the
sequence and the hash.
"""

from __future__ import annotations

import hashlib
import json
import os
import pathlib
import subprocess
import sys
from urllib.parse import urlparse

import pytest

REPO_ROOT = pathlib.Path(__file__).resolve().parents[3]
REAL_VERIFIER = REPO_ROOT / "verifier" / "foxy_verify.py"


def _h(s: str) -> str:
    return hashlib.sha256(s.encode()).hexdigest()


def _ingest(client, org, n: int) -> None:
    rows = [{"prompt_hash": _h(f"{org['org_id']}p{i}"),
             "response_hash": _h(f"{org['org_id']}r{i}"),
             "token_count": 100 + i, "policy_tag": "chat"} for i in range(n)]
    assert client.post("/v1/logs/batch", json=rows,
                       headers=org["auth"]).status_code == 202


@pytest.fixture
def admin(make_org, login):
    """An org with a signed-in admin session AND ledger rows — the DSAR bundle is
    admin-only and its ledger section is what this file is about."""
    org = make_org()
    session = login(org["admin_email"], org["admin_password"])
    return org, session


def _path_and_query(url: str) -> str:
    """`page.next` is absolute (it is a URL a human pastes into a browser); the
    TestClient wants the path."""
    u = urlparse(url)
    return u.path + ("?" + u.query if u.query else "")


def _walk(client, org, first: str) -> list[dict]:
    """Follow `page.next` to the end, exactly as the note in the file tells a
    customer to. Returns the page bodies, in the order they arrived."""
    pages, url, seen = [], first, 0
    while url is not None:
        r = client.get(url, headers=org["auth"])
        assert r.status_code == 200, r.text
        body = r.json()
        pages.append(body)
        seen += 1
        assert seen <= 50, "page.next never stopped — the walk does not terminate"
        url = _path_and_query(body["page"]["next"]) if body["page"]["next"] else None
    return pages


def _write(tmp_path, pages) -> list[str]:
    out = []
    for i, body in enumerate(pages, 1):
        f = tmp_path / f"page{i}.json"
        f.write_text(json.dumps(body, indent=2), encoding="utf-8")
        out.append(f.name)
    return out


def _verify(tmp_path, names, extra=()):
    proc = subprocess.run(
        [sys.executable, str(REAL_VERIFIER), *names, *extra],
        cwd=tmp_path, capture_output=True,
        env={**os.environ, "PYTHONIOENCODING": "utf-8"}, timeout=120)
    out = proc.stdout.decode("utf-8", "replace") + proc.stderr.decode("utf-8", "replace")
    return proc.returncode, out


# ══ the bound ══════════════════════════════════════════════════════════════

def test_the_response_is_bounded_and_the_ceiling_cannot_be_raised(make_org, client):
    """The whole defect in one assertion: no caller can make this endpoint build
    an arbitrarily large response, and the cap is not advisory."""
    from app.routers.logs import EXPORT_PAGE_MAX

    org = make_org()
    _ingest(client, org, 3)
    over = client.get(f"/v1/logs/export?limit={EXPORT_PAGE_MAX + 1}", headers=org["auth"])
    assert over.status_code == 422, (
        "a caller could ask for more rows than the cap, so the cap is decoration")
    assert client.get("/v1/logs/export?limit=0", headers=org["auth"]).status_code == 422


def test_the_shipped_default_is_the_cap_not_unbounded(make_org, client):
    """⚠ THE REGRESSION THIS PHASE EXISTS TO PREVENT is someone restoring the old
    behaviour by changing one default, which no round-trip test would notice on a
    three-row ledger. The declaration itself is asserted, and so is the value the
    endpoint reports back, so the two cannot disagree."""
    import inspect

    from app.routers.logs import EXPORT_PAGE_MAX, export_logs

    limit = inspect.signature(export_logs).parameters["limit"].default
    assert limit.default == EXPORT_PAGE_MAX, (
        "the rows-per-page default is no longer the cap — a caller who sends no "
        "`limit` is back to an unbounded response")
    ceiling = [c.le for c in limit.metadata if hasattr(c, "le")]
    assert ceiling == [EXPORT_PAGE_MAX], (
        f"the rows-per-page ceiling is {ceiling}, not the cap — a caller can ask "
        f"for a bigger response than EXPORT_PAGE_MAX")
    assert EXPORT_PAGE_MAX <= 10_000, (
        f"EXPORT_PAGE_MAX is {EXPORT_PAGE_MAX}: at the dearest measured row "
        f"(2169.6 B) that is {EXPORT_PAGE_MAX * 2169.6 / 1e6:.0f} MB in one "
        f"response")

    org = make_org()
    _ingest(client, org, 2)
    body = client.get("/v1/logs/export", headers=org["auth"]).json()
    assert body["page"]["max_rows_per_page"] == EXPORT_PAGE_MAX


def test_a_ledger_that_fits_is_unchanged_and_says_it_is_whole(make_org, client):
    """The ordinary case must not acquire a caveat. A workspace under the cap gets
    the same file it always got, and the page block says plainly that it is the
    whole ledger rather than leaving the reader to infer it."""
    org = make_org()
    _ingest(client, org, 4)
    body = client.get("/v1/logs/export", headers=org["auth"]).json()
    page = body["page"]
    assert body["count"] == 4 and len(body["logs"]) == 4
    assert page == {
        "from_seq": 1, "to_seq": 4, "prev_chain_hash": "0" * 64,
        "complete": True, "next_after_seq": None, "next": None,
        "max_rows_per_page": page["max_rows_per_page"], "note": page["note"],
    }
    assert "whole ledger" in page["note"]
    assert "NOT THE WHOLE LEDGER" not in page["note"]


# ══ a partial export SAYS it is partial ════════════════════════════════════

def test_a_page_that_stops_short_says_so_in_the_file(make_org, client):
    """⚠ SILENT TRUNCATION IS THE THING THIS PHASE MAY NOT SHIP. Three separate
    statements, because a reader may only look at one: the machine-readable
    flag, the cursor to resume from, and a sentence naming what is missing."""
    org = make_org()
    _ingest(client, org, 5)
    body = client.get("/v1/logs/export?limit=2", headers=org["auth"]).json()

    page = body["page"]
    assert len(body["logs"]) == 2 and body["count"] == 2
    assert page["complete"] is False, "a page that withheld rows reports itself complete"
    assert page["from_seq"] == 1 and page["to_seq"] == 2
    assert page["next_after_seq"] == 2
    assert page["next"] and "after_seq=2" in page["next"]
    assert "NOT THE WHOLE LEDGER" in page["note"]
    assert "seq 2" in page["note"], "the note does not say where the file stops"
    assert "foxy_verify.py" in page["note"], (
        "the note tells a customer the file is partial without telling them what "
        "to do about it")


def test_the_next_url_carries_the_date_range_it_was_asked_for(make_org, client):
    """A cursor that silently drops the filter hands the customer a different
    query's rows on page 2 and calls them the same export."""
    from datetime import datetime, timedelta, timezone
    today = datetime.now(timezone.utc).strftime("%Y-%m-%d")
    tomorrow = (datetime.now(timezone.utc) + timedelta(days=1)).strftime("%Y-%m-%d")

    org = make_org()
    _ingest(client, org, 4)
    body = client.get(f"/v1/logs/export?limit=2&date_from={today}&date_to={tomorrow}",
                      headers=org["auth"]).json()
    nxt = body["page"]["next"]
    assert f"date_from={today}" in nxt and f"date_to={tomorrow}" in nxt
    assert "limit=2" in nxt, "page 2 would come back at a different size"


def test_walking_the_pages_yields_every_row_exactly_once(make_org, client):
    """Paging that loses or repeats a row at the seam is a ledger defect, not a
    pagination defect."""
    org = make_org()
    _ingest(client, org, 7)
    pages = _walk(client, org, "/v1/logs/export?limit=2")
    seqs = [row["seq"] for body in pages for row in body["logs"]]
    assert seqs == list(range(1, 8)), seqs
    assert pages[-1]["page"]["complete"] is True
    assert all(p["page"]["complete"] is False for p in pages[:-1])


def test_paging_is_still_tenant_scoped(make_org, client):
    """after_seq is a cursor into the caller's own chain, not into the table."""
    a, b = make_org(), make_org()
    _ingest(client, a, 4)
    _ingest(client, b, 4)
    body = client.get("/v1/logs/export?after_seq=2", headers=a["auth"]).json()
    assert body["org_id"] == a["org_id"]
    assert [r["seq"] for r in body["logs"]] == [3, 4]


# ══ and they verify — the part that makes paging acceptable ════════════════

@pytest.mark.skipif(not REAL_VERIFIER.exists(), reason="verifier/ not checked out")
def test_a_real_multipage_export_verifies_as_one_chain(make_org, client, tmp_path):
    """THE PROOF. Page a real ledger out of the real endpoint, hand every file to
    the real verifier in one command, and get `chain intact` over the lot."""
    org = make_org()
    _ingest(client, org, 7)
    pages = _walk(client, org, "/v1/logs/export?limit=2")
    assert len(pages) == 4, "the ledger did not actually page"

    code, out = _verify(tmp_path, _write(tmp_path, pages))
    assert code == 0, out
    assert "chain intact" in out and "7 rows verified from genesis" in out, out


@pytest.mark.skipif(not REAL_VERIFIER.exists(), reason="verifier/ not checked out")
def test_the_pages_verify_in_any_order(make_org, client, tmp_path):
    """A customer with 300 files will not hand them over sorted, and a proof that
    depends on their shell's glob order is not a proof."""
    org = make_org()
    _ingest(client, org, 6)
    names = _write(tmp_path, _walk(client, org, "/v1/logs/export?limit=2"))
    code, out = _verify(tmp_path, list(reversed(names)))
    assert code == 0, out
    assert "chain intact" in out, out


@pytest.mark.skipif(not REAL_VERIFIER.exists(), reason="verifier/ not checked out")
def test_one_page_alone_is_a_segment_and_never_reports_the_ledger_intact(
        make_org, client, tmp_path):
    """⚠ THE #252 TRAP, POINTED AT THE VERIFIER. Page 1 of 4 recomputes clean,
    and saying `chain intact` over it would be a completeness claim over a
    quarter of the evidence — made by the tool that exists to check such claims.
    It gets its own word and its own exit code, and 0 is not available."""
    org = make_org()
    _ingest(client, org, 7)
    names = _write(tmp_path, _walk(client, org, "/v1/logs/export?limit=2"))

    code, out = _verify(tmp_path, names[:1])
    assert code == 3, f"a single page exited {code}, not 3:\n{out}"
    assert "segment intact" in out, out
    assert "chain intact" not in out, (
        "the verifier called one page of four an intact chain")
    assert "INCOMPLETE" in out and "NOT the whole ledger" in out, out


@pytest.mark.skipif(not REAL_VERIFIER.exists(), reason="verifier/ not checked out")
def test_a_missing_middle_page_cannot_pass_as_a_join(make_org, client, tmp_path):
    """Page-to-page continuity. Drop page 2 and hand over 1, 3, 4: the seqs no
    longer run and the hashes no longer meet, and either alone must be fatal."""
    org = make_org()
    _ingest(client, org, 8)
    names = _write(tmp_path, _walk(client, org, "/v1/logs/export?limit=2"))
    assert len(names) == 4

    code, out = _verify(tmp_path, [names[0], names[2], names[3]])
    assert code == 1, f"a ledger missing rows 3-4 exited {code}:\n{out}"
    assert "chain intact" not in out and "segment intact" not in out, out
    assert "do not join" in out, out
    # ⚠ AND IT MUST SAY WHICH FILE. Mutation C1 (drop the sequence-join check and
    # let the hash-join check catch it instead) SURVIVED everything above: both
    # checks refuse, both exit 1, both say "do not join". The difference is that
    # only the sequence check names the file, and with 300 pages on an auditor's
    # desk "which one is missing" is the whole of the answer.
    assert names[2] in out, (
        f"the diagnosis does not name the file that failed to join:\n{out}")


@pytest.mark.skipif(not REAL_VERIFIER.exists(), reason="verifier/ not checked out")
def test_a_page_that_lies_about_where_it_continues_from_is_caught(
        make_org, client, tmp_path):
    """The seqs can run perfectly while the hashes do not meet. `prev_chain_hash`
    is checked against the hash the previous page actually ended on, so it cannot
    be a decorative field nobody reads."""
    org = make_org()
    _ingest(client, org, 6)
    pages = _walk(client, org, "/v1/logs/export?limit=2")
    pages[1]["page"]["prev_chain_hash"] = "f" * 64
    code, out = _verify(tmp_path, _write(tmp_path, pages))
    assert code == 1, out
    assert "do not join" in out, out


@pytest.mark.skipif(not REAL_VERIFIER.exists(), reason="verifier/ not checked out")
def test_trimming_rows_out_of_a_page_is_caught_by_its_own_page_block(
        make_org, client, tmp_path):
    """The cheapest forgery a paged export invites: delete the rows you dislike
    from one file and leave everything else alone. The page block says which seqs
    that file holds, so the file contradicts itself."""
    org = make_org()
    _ingest(client, org, 6)
    pages = _walk(client, org, "/v1/logs/export?limit=3")
    pages[0]["logs"] = pages[0]["logs"][1:]          # rows 2-3, block still says 1-3
    code, out = _verify(tmp_path, _write(tmp_path, pages))
    assert code == 1, out
    assert "declares it starts at seq 1" in out, out


@pytest.mark.skipif(not REAL_VERIFIER.exists(), reason="verifier/ not checked out")
def test_tampering_is_still_caught_across_a_page_boundary(make_org, client, tmp_path):
    """Paging must not become a place to hide. Edit a row on page 3 and the
    recompute — which now runs across four files — still names its seq."""
    org = make_org()
    _ingest(client, org, 8)
    pages = _walk(client, org, "/v1/logs/export?limit=2")
    pages[2]["logs"][0]["token_count"] = 999          # seq 5
    code, out = _verify(tmp_path, _write(tmp_path, pages), extra=("--json",))
    assert code == 1, out
    report = json.loads(out[out.index("{"):])
    assert report["chain"]["ok"] is False
    assert report["chain"]["first_broken_seq"] == 5, report["chain"]


@pytest.mark.skipif(not REAL_VERIFIER.exists(), reason="verifier/ not checked out")
def test_pages_from_two_workspaces_are_not_one_export(make_org, client, tmp_path):
    """org_id is the FIRST field of the hashed event, so concatenating two
    workspaces' pages would otherwise fail as tampering with no hint of why."""
    a, b = make_org(), make_org()
    _ingest(client, a, 3)
    _ingest(client, b, 3)
    pages = [client.get("/v1/logs/export?limit=2", headers=a["auth"]).json(),
             client.get("/v1/logs/export?limit=2&after_seq=2", headers=b["auth"]).json()]
    code, out = _verify(tmp_path, _write(tmp_path, pages))
    assert code == 1, out
    assert "different org_id" in out, out


# ══ the export that was never verifiable, and now is ═══════════════════════

@pytest.mark.skipif(not REAL_VERIFIER.exists(), reason="verifier/ not checked out")
def test_an_export_that_starts_midledger_is_a_segment_not_a_forgery(
        make_org, client, tmp_path):
    """⚠ A PRE-EXISTING DEFECT THIS PHASE CLOSES IN PASSING. An export that does
    not start at seq 1 — `?after_seq=`, or the date range the dashboard's own
    pickers have always sent — was recomputed from genesis, mismatched on its
    first row, and reported `[FAIL] CHAIN BROKEN`. An honest export was accused
    of forgery for where it began. `page.prev_chain_hash` is what that recompute
    was missing; the answer is a segment, and a segment is exit 3.
    """
    org = make_org()
    _ingest(client, org, 6)
    body = client.get("/v1/logs/export?after_seq=3", headers=org["auth"]).json()
    assert [r["seq"] for r in body["logs"]] == [4, 5, 6]
    assert body["page"]["from_seq"] == 4
    assert body["page"]["prev_chain_hash"] != "0" * 64
    assert "rows 1-3 are not in it" in body["page"]["note"]

    code, out = _verify(tmp_path, _write(tmp_path, [body]))
    assert code == 3, f"a mid-ledger export exited {code}:\n{out}"
    assert "segment intact" in out and "CHAIN BROKEN" not in out, out
    assert "starts at seq 4" in out, out


@pytest.mark.skipif(not REAL_VERIFIER.exists(), reason="verifier/ not checked out")
def test_a_segment_does_not_report_the_anchor_as_mismatched(make_org, client, tmp_path):
    """The same accusation from the other side. The offline anchor check
    recomputes the head at the anchored seq FROM GENESIS; over a segment that
    recompute is meaningless, and printing `anchor receipt DOES NOT MATCH` reads
    as tampering. Not-checked is the third answer and the honest one."""
    import uuid

    from app.anchor import anchor_org
    from app.db import SessionLocal

    org = make_org()
    _ingest(client, org, 6)
    db = SessionLocal()
    try:
        anchor_org(db, uuid.UUID(org["org_id"]), force=True)
    finally:
        db.close()

    body = client.get("/v1/logs/export?after_seq=3", headers=org["auth"]).json()
    assert body["anchor"] is not None
    code, out = _verify(tmp_path, _write(tmp_path, [body]))
    assert code == 3, out
    assert "DOES NOT MATCH" not in out, (
        "a segment was accused of an anchor mismatch it cannot be checked for")
    assert "not checked" in out, out


@pytest.mark.skipif(not REAL_VERIFIER.exists(), reason="verifier/ not checked out")
def test_the_anchor_still_matches_once_every_page_is_present(make_org, client, tmp_path):
    """And the check is not simply switched off: reassemble the whole ledger and
    the anchor receipt must be checked, and must match."""
    import uuid

    from app.anchor import anchor_org
    from app.db import SessionLocal

    org = make_org()
    _ingest(client, org, 6)
    db = SessionLocal()
    try:
        anchor_org(db, uuid.UUID(org["org_id"]), force=True)
    finally:
        db.close()

    pages = _walk(client, org, "/v1/logs/export?limit=2")
    code, out = _verify(tmp_path, _write(tmp_path, pages))
    assert code == 0, out
    assert "anchor receipt matches the chain @ seq 6" in out, out


# ══ CSV has nowhere to put a page block, and still may not be silent ═══════

def test_a_partial_csv_carries_the_notice_and_a_whole_one_does_not(make_org, client):
    """CSV has no field a reader can notice missing, so a truncated one opens as
    a complete one. The notice goes in leading `#` comments — which pandas and R
    skip and every other reader shows as a visibly wrong first row. A complete
    export carries none, so the ordinary file is byte-for-byte what it was."""
    org = make_org()
    _ingest(client, org, 5)

    whole = client.get("/v1/logs/export?format=csv", headers=org["auth"]).text
    assert whole.splitlines()[0].startswith("seq,"), "a whole CSV grew a preamble"

    part = client.get("/v1/logs/export?format=csv&limit=2", headers=org["auth"])
    lines = part.text.strip().splitlines()
    assert lines[0].startswith("#"), "a truncated CSV opens as a complete one"
    preamble = "\n".join(l for l in lines if l.startswith("#"))
    assert "NOT THE WHOLE LEDGER" in preamble
    assert "next:" in preamble and "after_seq=2" in preamble
    body = [l for l in lines if not l.startswith("#")]
    assert body[0].startswith("seq,") and len(body) == 3
    assert "seq-1-2" in part.headers["content-disposition"], (
        "300 downloads all named foxy-audit-logs.csv")


# ══ the DSAR bundle is the same projection, so it is bounded the same way ══

def test_the_dsar_ledger_is_bounded_and_the_manifest_says_so(admin, monkeypatch):
    """#269 made the DSAR ledger CALL `logs._export_row`, so the two artefacts
    are one projection and cannot drift. The bound has to reach both, and the
    manifest a regulator reads has to carry it — a completeness manifest that
    omits the one section which can stop short is the #252 defect wearing the
    #252 fix."""
    from app.routers import account

    org, session = admin
    _ingest(session, org, 5)
    monkeypatch.setattr(account, "EXPORT_PAGE_MAX", 2)
    bundle = session.get("/v1/account/export").json()

    assert len(bundle["ledger"]) == 2
    page = bundle["page"]
    assert page["complete"] is False
    assert page["from_seq"] == 1 and page["to_seq"] == 2
    assert "NOT THE WHOLE LEDGER" in page["note"]
    assert "/v1/logs/export" in page["next"] and "after_seq=2" in page["next"]

    scope = bundle["export_scope"]
    assert scope["ledger_complete"] is False, (
        "the manifest still reads as though the bundle carried the whole ledger")
    assert scope["ledger_note"] == page["note"]
    assert "page.max_rows_per_page" in scope["statement"]


def test_an_unbounded_dsar_ledger_reports_itself_whole(admin):
    """The other side of the same guard: a workspace under the cap must not be
    handed a caveat it has not earned."""
    org, session = admin
    _ingest(session, org, 3)
    bundle = session.get("/v1/account/export").json()
    assert bundle["page"]["complete"] is True
    assert bundle["page"]["from_seq"] == 1
    assert bundle["export_scope"]["ledger_complete"] is True
    assert "NOT THE WHOLE LEDGER" not in bundle["page"]["note"]


def test_both_artefacts_state_completeness_through_the_same_projection():
    """The #269 lesson, applied to the second half. Two descriptions of how
    complete a file is, written in two places, are two things that can disagree
    about the same file — so both call `logs._page_export`, and this fails if
    either grows its own."""
    import inspect

    from app.routers import account, logs

    assert account._page_export is logs._page_export, (
        "the DSAR bundle no longer shares the log export's page projection")
    src = inspect.getsource(account.account_export)
    assert "_page_export(" in src, (
        "the DSAR bundle builds its page block some other way")


# ══ the bound is in the QUERY, not only in the response ════════════════════

def test_the_ledger_query_itself_carries_a_limit(make_org, client):
    """⚠ THE ONE TEST THIS PHASE COULD NOT DO WITHOUT, AND IT TOOK A SURVIVING
    MUTANT TO FIND. Mutation T6 deleted `.limit(limit + 1)` from the export query
    and the ENTIRE suite still passed — 84 green — because the route slices in
    Python afterwards, so the response bytes are identical either way. The defect
    #271 is about is not the response: it is that the endpoint LOADS the whole
    ledger into memory to build it. A suite that only reads responses cannot see
    that, and every other test in this file was blind to the exact regression it
    was written to prevent.

    So this one reads the SQL. The statement that selects the ledger rows must
    carry a LIMIT, and the bound must be the requested page size plus the one
    extra row that detects "more remain".
    """
    import re

    from sqlalchemy import event

    from app.db import engine

    seen = []

    def record(conn, cursor, statement, parameters, context, executemany):
        if "FROM audit_logs" in statement:
            seen.append((statement, parameters))

    org = make_org()
    _ingest(client, org, 6)

    event.listen(engine, "before_cursor_execute", record)
    try:
        r = client.get("/v1/logs/export?limit=2", headers=org["auth"])
    finally:
        event.remove(engine, "before_cursor_execute", record)
    assert r.status_code == 200
    assert seen, "no query over audit_logs was observed at all"

    limited = [(st, p) for st, p in seen if re.search(r"\bLIMIT\b", st, re.I)]
    assert limited, (
        "the export selected audit_logs with NO LIMIT — it is reading the whole "
        "ledger into memory and slicing it in Python afterwards, which is exactly "
        "the unbounded build #271 is about. Statements seen:\n"
        + "\n".join(" | " + " ".join(st.split())[-160:] for st, _ in seen))

    bounds = set()
    for st, params in limited:
        if isinstance(params, dict):
            bounds |= {v for v in params.values() if isinstance(v, int)}
        elif isinstance(params, (list, tuple)):
            bounds |= {v for v in params if isinstance(v, int)}
    assert 3 in bounds, (
        f"the ledger query's LIMIT is not the requested page size + 1 (expected 3 "
        f"for ?limit=2); integer bind parameters seen were {sorted(bounds)}. A "
        f"limit not derived from the page size does not bound the page.")
