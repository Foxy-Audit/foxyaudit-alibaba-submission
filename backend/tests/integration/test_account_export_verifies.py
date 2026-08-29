"""Register #269 — the DSAR bundle must actually verify, not merely look like it.

`GET /v1/account/export` is the file a customer, an auditor or a regulator is
handed when they ask for their data. `verifier/foxy_verify.py` is the tool the
product tells them to run on it. Until this phase the two did not meet:

  * the bundle named its chain section `ledger`, and the verifier read
    `data.get("logs", [])` in all three of its call sites — so the natural action
    (run the verifier on the file you were just given) printed
    `[OK] chain intact - 0 rows verified from genesis` and exited 0, having
    recomputed nothing at all;
  * and the section carried nine columns — seq, prompt_hash, response_hash,
    policy_tag, agent, chain_hash, grading_status, gemini_verdict, created_at —
    while `chain.compute_chain_hash` takes the hash over seventeen inputs. So
    teaching the verifier the alias, on its own, would have converted a silent
    false pass into a loud false ACCUSATION: `CHAIN BROKEN`, on an export nobody
    had touched.

⚠ WHY EVERY TEST HERE RECOMPUTES A HASH RATHER THAN COUNTING KEYS. A test that
asserted `set(row) == {...}` would pass against an export whose values were all
wrong, and would go green the moment somebody updated the expected set — which
is precisely how a field-list drifts. These load the real
`verifier/foxy_verify.py` by path and recompute the chain from genesis, so a
dropped field kills them by arithmetic.

⚠ AND THE VERIFIER IS LOADED BY PATH, NOT IMPORTED FROM `app`. Using
`app.chain` here would prove the export agrees with the writer, which is the one
thing an independent verifier exists not to assume.
"""

from __future__ import annotations

import copy
import hashlib
import importlib.util
import json
import pathlib
from datetime import timedelta

import pytest

REPO_ROOT = pathlib.Path(__file__).resolve().parents[3]
REAL_VERIFIER = REPO_ROOT / "verifier" / "foxy_verify.py"

#: Every field `compute_chain_hash` reads that the DSAR ledger did NOT carry
#: before #269, plus `prev_hash` (the link) and `token_count` (bound since V1).
#: Each one is asserted non-null on the seeded rows below and then removed from
#: the shipped bundle to prove the recompute notices — a mutant that drops any
#: of them from `_export_row` dies here.
CHAIN_BOUND_FIELDS = ("token_count", "chain_version", "event_id", "client_id",
                      "client_seq", "event_type", "commitment_alg",
                      "event_metadata", "pii_signals", "occurred_at",
                      "verdict_hash", "prev_hash", "chain_hash")


def _verifier():
    spec = importlib.util.spec_from_file_location("foxy_verify_real", REAL_VERIFIER)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _h(s: str) -> str:
    return hashlib.sha256(s.encode()).hexdigest()


def _session_zone_times(n):
    """`occurred_at` values expressed in the DATABASE SESSION's own timezone.

    ⚠ THIS WORKED AROUND A REAL DEFECT THAT IS NOW FIXED — register #272, closed
    by chain V5. Ingest used to hash `occurred_at.isoformat()` of the value the
    CLIENT SENT, while PostgreSQL returns a `timestamptz` rendered in the reading
    session's `TimeZone`. On a deployment whose session zone was not UTC, an event
    sent as `2026-08-21T10:00:00+00:00` read back as `2026-08-21T15:00:00+05:00`,
    so every recompute over the stored row yielded a different hash and the ledger
    read as TAMPERED with nothing having been touched. Sending the offset the
    session would render in made the two strings agree, which is what this helper
    is for, and it is why the tests below could measure #269 on a machine in any
    timezone instead of inheriting a failure that was not theirs.

    From chain_version 5 the fold normalises to UTC, so the offset sent no longer
    matters. The helper is kept because these tests are about #269 and there is no
    reason for them to change; the fix itself is measured by
    `test_chain_v5_occurred_at.py`, which exports under three session zones and
    carries the V4 control that proves the failure was real.
    """
    from sqlalchemy import text as sa_text

    from app.db import SessionLocal
    db = SessionLocal()
    try:
        now = db.execute(sa_text("SELECT now()")).scalar()
    finally:
        db.close()
    base = now.replace(microsecond=0)
    return [base - timedelta(seconds=60 * (n - i)) for i in range(1, n + 1)]


def _ingest(client, org, n=3):
    """Rows with EVERY chain-bound field populated.

    ⚠ THE NON-NULL PART IS THE TEST, NOT THE SETUP. A field that is None in the
    seed hashes identically whether it is exported or dropped, so a bundle of
    minimal rows would let `test_every_chain_bound_field...` pass over a ledger
    that carries none of them. `test_the_seeded_rows_actually_exercise_every_
    chain_bound_field` asserts that separately rather than trusting this.
    """
    occurred = _session_zone_times(n)
    rows = []
    for i in range(1, n + 1):
        rows.append({
            "prompt_hash": _h(f"{org['org_id']}-p{i}"),
            "response_hash": _h(f"{org['org_id']}-r{i}"),
            "token_count": 10 * i + 5,
            "policy_tag": "hipaa_basic",
            "agent": "gpt-4o",
            "pii_signals": ["email", "mrn"],
            "event_id": f"aaaaaaaa-aaaa-aaaa-aaaa-{i:012d}",
            "client_id": "sdk-node-a",
            "client_seq": i,
            "event_type": "interaction",
            "commitment_alg": "hmac-sha256",
            "event_metadata": {"request_id": f"req-{i}", "provider": "openai",
                               "model": "gpt-4o", "choice_count": 1},
            "occurred_at": occurred[i - 1].isoformat(),
        })
    # ⚠ ONE ROW MUST NOT CARRY THE DEFAULT `event_type`, or the field is not
    # separable. `compute_chain_hash` folds it as `event_type or "interaction"`,
    # so removing "interaction" from an export hashes identically to leaving it
    # in — by design, and it means a ledger of ordinary interactions cannot prove
    # the field is being read. A host-side enforcement row is what the SDK really
    # sends for a redaction, and it makes the seed representative as well as
    # separable.
    rows[1]["event_type"] = "redacted"
    rows[1]["event_metadata"].update(
        {"decision": "redacted", "blocked_reason": "phi_detected",
         "policy_rules": ["pii.mrn", "pii.email"]})
    r = client.post("/v1/logs/batch", json=rows, headers=org["auth"])
    assert r.status_code == 202, r.text


@pytest.fixture
def seeded(make_org, login, client):
    org = make_org()
    _ingest(client, org, 3)
    return org, login(org["admin_email"], org["admin_password"])


def _bundle(session_client) -> dict:
    r = session_client.get("/v1/account/export")
    assert r.status_code == 200, r.text
    return json.loads(r.content)


# ══ the bundle a customer is handed now verifies ═══════════════════════════

def test_the_dsar_bundle_verifies_end_to_end_under_the_real_verifier(seeded):
    """The whole of #269 in one assertion: fetch the DSAR bundle and recompute
    its chain from genesis with the standalone script, no Foxy code involved in
    the recompute."""
    _, session = seeded
    bundle = _bundle(session)
    fv = _verifier()

    result = fv.verify_export(bundle)
    assert result["ok"] is True, result["detail"]
    assert result["refused"] is False
    assert result["count"] == 3, "the verifier did not read all three rows"
    assert result["section"] == "ledger"
    assert result["head"] == bundle["ledger"][-1]["chain_hash"]
    assert result["head_seq"] == 3


def test_the_bundle_carries_the_org_id_the_chain_is_hashed_against(seeded):
    """`org_id` is the FIRST field of the hashed event. A bundle without it at
    the top level recomputes every row against None, and every row fails — the
    chain reads as tampered when nothing was touched."""
    org, session = seeded
    bundle = _bundle(session)
    assert bundle["org_id"] == org["org_id"]

    fv = _verifier()
    without = {k: v for k, v in bundle.items() if k != "org_id"}
    assert fv.verify_export(without)["ok"] is False, (
        "the recompute ignores org_id, so the top-level field proves nothing")


def test_the_seeded_rows_actually_exercise_every_chain_bound_field(seeded):
    """⚠ ANTI-VACUITY. A None field hashes the same whether it is exported or
    dropped, so a bundle of minimal rows would make the removal test below pass
    while proving nothing. This is the third register entry in a row where a
    helper reported success by doing nothing; assert the inputs are real."""
    _, session = seeded
    rows = _bundle(session)["ledger"]
    assert len(rows) == 3
    for field in CHAIN_BOUND_FIELDS:
        for n, row in enumerate(rows, 1):
            if field == "prev_hash" and n == 1:
                continue                      # seq 1 links to genesis by design
            assert field in row, f"the ledger stopped carrying {field}"
            assert row[field] is not None, (
                f"{field} is null on seq {n}, so removing it could not change a "
                f"hash and the removal test would pass vacuously")
    assert rows[0]["chain_version"] == 5, (
        "the seed is no longer writing the version ingest writes — this asserts\n"
        "what routers/logs.py stamps, so it moves with every chain version")
    assert rows[0]["local_verdict"] is not None


def test_every_chain_bound_field_the_ledger_carries_is_load_bearing(seeded):
    """Remove one field from the shipped bundle and the recompute must notice.

    This is the guard that kills the obvious regression: someone trimming
    `_export_row`, or reverting the ledger section to its own nine-column
    projection. It fails by arithmetic rather than by comparing key sets, so it
    cannot be satisfied by updating an expected list.
    """
    _, session = seeded
    bundle = _bundle(session)
    fv = _verifier()
    assert fv.verify_export(bundle)["ok"] is True, "the unmutated bundle must verify"

    for field in CHAIN_BOUND_FIELDS:
        broken = copy.deepcopy(bundle)
        for row in broken["ledger"]:
            row.pop(field, None)
        result = fv.verify_export(broken)
        assert result["ok"] is False, (
            f"the whole ledger can lose {field!r} and still verify - either the "
            f"export carries it for nothing, or the recompute is not reading it")


def test_a_rewritten_local_verdict_is_caught_in_the_dsar_bundle_too(seeded):
    """The chain binds the verdict's DIGEST, so editing the body alone leaves
    every chain hash valid. Exporting `local_verdict` is what lets a reader
    re-derive the digest and catch that — without the body the V4 binding is
    decorative in this bundle."""
    _, session = seeded
    bundle = _bundle(session)
    fv = _verifier()

    bundle["ledger"][1]["local_verdict"] = dict(
        bundle["ledger"][1]["local_verdict"], decision="clean", policy_breach=False,
        reason="nothing to see here")
    result = fv.verify_export(bundle)
    assert result["ok"] is False
    assert result["first_broken_seq"] == 2
    assert "verdict" in result["detail"]


def test_a_tampered_ledger_row_is_reported_as_tampering_not_as_unreadable(seeded):
    """The refusal must not swallow real findings. A row edited after the fact
    exits 1 and names the seq — the answer the product actually sells."""
    _, session = seeded
    bundle = _bundle(session)
    fv = _verifier()

    bundle["ledger"][2]["token_count"] = 999_999
    result = fv.verify_export(bundle)
    assert result["ok"] is False
    assert result["refused"] is False
    assert result["first_broken_seq"] == 3


def test_the_bundle_carries_an_anchor_receipt_the_verifier_can_compare(seeded):
    """`anchors` was in the bundle and `anchor` was not, so the verifier told a
    reader "no anchor receipt in this export" over a file that plainly listed
    them. With a real anchor the offline check now recomputes the head at the
    anchored seq and compares it against the receipt."""
    import uuid as _uuid

    from app.anchor import anchor_org
    from app.db import SessionLocal

    org, session = seeded
    db = SessionLocal()
    try:
        anchor_org(db, _uuid.UUID(org["org_id"]), force=True)
    finally:
        db.close()

    bundle = _bundle(session)
    assert bundle["anchor"] is not None and bundle["anchor"]["last_seq"] == 3
    fv = _verifier()
    offline = fv.check_anchor_offline(bundle, fv.verify_export(bundle))
    assert offline is not None and offline["matches"] is True, offline

    bundle["anchor"]["root_hash"] = "0" * 64
    assert fv.check_anchor_offline(bundle, None)["matches"] is False, (
        "the offline anchor check passes whatever it is given")


# ══ the verifier still refuses what it cannot read ═════════════════════════

def test_the_verifier_refuses_a_file_with_no_chain_section():
    """Held here as well as in `verifier/test_verify.py`, because this suite is
    what gates a backend merge and the export bundle ships that file. (CI does
    run `pytest verifier -q` — ci.yml added the step; the older note saying it
    does not is stale.) If this ever passes, the bundle ships a verifier that
    lies."""
    fv = _verifier()
    result = fv.verify_export({"org_id": "x", "count": 0})
    assert result["refused"] is True
    assert result["ok"] is False
    assert result["head"] is None


def test_the_shipped_bundled_copy_refuses_too():
    """⚠ THE COPY IS THE ONE A CUSTOMER RUNS. `backend/app/bundled/
    foxy_verify.py` is what goes inside `GET /v1/logs/export?format=bundle`, so
    a fix that reached only `verifier/` would leave the false pass alive exactly
    where it matters most. The byte-identity guard in `test_export_bundle.py`
    keeps them equal; this proves the behaviour through the copy itself.
    """
    from app import export_bundle

    spec = importlib.util.spec_from_file_location(
        "foxy_verify_bundled", export_bundle.VERIFIER_PATH)
    bundled = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(bundled)

    assert bundled.verify_export({"ledger": [{"seq": 1, "chain_hash": "x"}]})["refused"] is True
    assert bundled.verify_export({"logs": []})["refused"] is True
    assert bundled.CHAIN_SECTION_KEYS == ("logs", "ledger")
