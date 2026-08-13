"""The staff-action chain gets an outside witness. (A1)

WHAT THIS CLOSES.

``admin_chain.py`` states two limits of a chain over a table its owner controls,
and both are about the ABSENCE OF AN EXTERNAL RECORD, not about the hashing:

  #143  "REMOVING ENTRIES FROM THE END leaves nothing behind. seq 1..N-k
        recomputes perfectly; only an outside witness who recorded the older
        head would notice."
  #144  deleting EVERY chained row is self-healing — ``chain_head`` returns
        None and the next write restarts at seq 1 against GENESIS.

An anchor IS that outside witness. Once the head is published, a recorded
(root_hash, last_seq) pair sits somewhere Foxy cannot rewrite, and a truncated
tail stops recomputing cleanly against it.

WHAT IT DOES NOT EARN. anchor.py says it in its own words: an anchor makes
tampering "externally detectable after the next anchor, not impossible. We say
'tamper-evident, independently verifiable'." The word "immutable" appears
nowhere in backend/app/ or verifier/ — not about this chain and not about the
fully-anchored customer ledger. See test_the_project_never_calls_anything_immutable.

Run with DATABASE_URL=postgresql+psycopg://…@localhost:5433/foxy_pytest
"""
from __future__ import annotations

import uuid
from datetime import datetime, timezone

import pytest
from sqlalchemy import text

from app import admin_chain
from app import anchor as anchor_mod
from app.config import get_settings
from app.db import SessionLocal


def _clear():
    db = SessionLocal()
    try:
        db.execute(text("DELETE FROM admin_chain_anchors"))
        db.execute(text("DELETE FROM admin_actions"))
        db.commit()
    finally:
        db.close()


def _staff_id():
    db = SessionLocal()
    try:
        row = db.execute(text("SELECT id FROM staff_users LIMIT 1")).first()
        if row:
            return row[0]
        sid = uuid.uuid4()
        db.execute(text(
            "INSERT INTO staff_users (id, email, password_hash, platform_role, created_at)"
            " VALUES (:i, :e, 'x', 'viewer', now())"),
            {"i": sid, "e": f"a1-{sid.hex[:8]}@example.invalid"})
        db.commit()
        return sid
    finally:
        db.close()


def _record(n: int, staff_id):
    """n chained staff actions through the real writer, so the hashes are real."""
    from app import admin_audit
    from app.models import StaffUser
    db = SessionLocal()
    try:
        staff = db.get(StaffUser, staff_id)
        for i in range(n):
            admin_audit.record_admin_action(
                db, staff, f"a1.test.{i}",
                target_type="test", target_id=str(i), detail={"i": i}, ip="127.0.0.1")
        db.commit()
    finally:
        db.close()


def _truncate_tail(k: int):
    """Remove k entries from the END — the #143 attack. Everything left still
    recomputes perfectly, which is the whole problem."""
    db = SessionLocal()
    try:
        db.execute(text(
            "DELETE FROM admin_actions WHERE seq IS NOT NULL AND seq > "
            "(SELECT max(seq) - :k FROM admin_actions WHERE seq IS NOT NULL)"),
            {"k": k})
        db.commit()
    finally:
        db.close()


@pytest.fixture
def chain():
    _clear()
    sid = _staff_id()
    yield sid
    _clear()


# ── #143: A TRUNCATED TAIL IS NOW DETECTABLE ────────────────────────────────
def test_143_a_truncated_tail_recomputes_clean_but_fails_against_the_anchor(chain):
    """⚠ THE TEST THAT HAD TO FAIL BEFORE THE ANCHOR EXISTED.

    Both halves matter, and the first is the reason the second is needed:

      1. after truncation the chain STILL VERIFIES — verify_admin_chain returns
         ok=True, "sequence unbroken", because seq 1..N-k is internally perfect.
         That is #143 exactly, and no amount of hashing fixes it.
      2. checked against a recorded anchor, the same truncation is caught: the
         anchor holds last_seq=N and the table now ends at N-k.
    """
    _record(6, chain)
    db = SessionLocal()
    try:
        anchor = anchor_mod.anchor_admin(db, get_settings(), force=True)
        assert anchor is not None, "nothing was anchored"
        assert anchor.status == "confirmed", anchor.detail
        assert anchor.last_seq == 6
    finally:
        db.close()

    _truncate_tail(2)

    db = SessionLocal()
    try:
        # 1. the chain alone still says everything is fine — #143
        internal = admin_chain.verify_admin_chain(db)
        assert internal["ok"] is True, internal
        assert internal["detail"] == "sequence unbroken"
        assert internal["head_seq"] == 4

        # 2. against the anchor it does not
        v = admin_chain.verify_admin_anchor(db)
        assert v["ok"] is False, v
        assert v["kind"] == "truncated", v
        assert v["anchored_seq"] == 6 and v["head_seq"] == 4, v
        assert "removed from the end" in v["detail"].lower(), v["detail"]
    finally:
        db.close()


def test_144_a_wholesale_delete_no_longer_self_heals(chain):
    """admin_chain.py: "deleting EVERY chained row lands here, chain_head then
    returns None, and the next write restarts at seq 1 against GENESIS. A
    wholesale delete is self-healing."

    It is not self-healing once an anchor exists: the anchor still holds
    last_seq=N, and a chain that restarts at 1 cannot satisfy it."""
    _record(4, chain)
    db = SessionLocal()
    try:
        assert anchor_mod.anchor_admin(db, get_settings(), force=True).last_seq == 4
    finally:
        db.close()

    db = SessionLocal()
    try:
        db.execute(text("DELETE FROM admin_actions WHERE seq IS NOT NULL"))
        db.commit()
    finally:
        db.close()
    _record(1, chain)          # the restart: a fresh seq 1 against GENESIS

    db = SessionLocal()
    try:
        internal = admin_chain.verify_admin_chain(db)
        assert internal["ok"] is True, "the restarted chain is internally perfect — that IS #144"
        v = admin_chain.verify_admin_anchor(db)
        assert v["ok"] is False and v["kind"] == "truncated", v
        assert v["anchored_seq"] == 4 and v["head_seq"] == 1, v
    finally:
        db.close()


def test_a_modified_row_before_the_anchor_is_caught_by_the_root(chain):
    """Truncation is caught by the seq comparison. An EDIT inside the anchored
    range is caught by the root hash — the anchored root no longer recomputes."""
    _record(5, chain)
    db = SessionLocal()
    try:
        anchored = anchor_mod.anchor_admin(db, get_settings(), force=True)
        root = anchored.root_hash
    finally:
        db.close()

    db = SessionLocal()
    try:
        db.execute(text("UPDATE admin_actions SET ip = '10.0.0.1' WHERE seq = 2"))
        db.commit()
    finally:
        db.close()

    db = SessionLocal()
    try:
        v = admin_chain.verify_admin_anchor(db)
        assert v["ok"] is False, v
        assert v["kind"] in ("modified", "root_mismatch"), v
        assert v["anchored_root"] == root
        assert v["recomputed_root"] != root, "the root did not change on an edit"
    finally:
        db.close()


def test_an_intact_chain_verifies_against_its_anchor(chain):
    """The control. If this cannot pass, the failures above prove nothing."""
    _record(3, chain)
    db = SessionLocal()
    try:
        anchor_mod.anchor_admin(db, get_settings(), force=True)
        v = admin_chain.verify_admin_anchor(db)
        assert v["ok"] is True, v
        assert v["kind"] is None
        assert v["anchored_seq"] == v["head_seq"] == 3
        assert v["anchored_root"] == v["recomputed_root"]
    finally:
        db.close()


# ── THE UNHASHED PREFIX: STATED, NOT PAPERED OVER ───────────────────────────
def test_the_anchor_states_what_it_does_not_cover(chain):
    """admin_chain.py's third limit: rows written before the mechanism carry no
    hash. The anchor covers seq 1..N and NOTHING BEFORE IT, and the receipt says
    so rather than letting a reader assume the whole table is witnessed."""
    db = SessionLocal()
    try:
        db.execute(text(
            "INSERT INTO admin_actions (id, staff_user_id, action, created_at)"
            " VALUES (gen_random_uuid(), :s, 'a1.predates.chain', now())"),
            {"s": chain})
        db.commit()
    finally:
        db.close()
    _record(3, chain)

    db = SessionLocal()
    try:
        a = anchor_mod.anchor_admin(db, get_settings(), force=True)
        assert a.covers_from_seq == 1, "the anchor must name where its coverage starts"
        assert a.unchained_before == 1, \
            "the anchor must record how many rows predate the chain it witnesses"
        v = admin_chain.verify_admin_anchor(db)
        assert v["ok"] is True
        assert v["unchained_before"] == 1, v
        assert "do not carry a hash" in v["coverage"].lower(), v["coverage"]
    finally:
        db.close()


# ── THE ANCHOR MUST NOT BECOME A SILENT-FAILURE PATH ────────────────────────
def test_an_unreachable_chain_records_a_visible_failure_and_does_not_block_staff(chain, monkeypatch):
    """anchor.py's posture, matched rather than reinvented: a provider failure is
    persisted as status='failed' with a redacted detail — a visible receipt —
    and never silently dropped. The staff chain keeps working regardless, because
    anchoring is a worker sweep and is not on the staff-action write path."""
    _record(2, chain)

    # ⚠ _redact strips the secrets it KNOWS — settings.anchor_evm_rpc_url and
    # ...private_key. A first cut of this test invented a URL that was in no
    # setting, so nothing was redacted and the test blamed the code for its own
    # premise. Point the setting at the URL the provider will leak.
    leaky = "https://rpc.example/v2/SUPERSECRET"
    s = get_settings()
    monkeypatch.setattr(s, "anchor_evm_rpc_url", leaky, raising=False)

    def boom(root_hash, settings):
        raise RuntimeError(f"rpc unreachable at {leaky}")

    monkeypatch.setitem(anchor_mod._PROVIDERS, "stub", boom)
    db = SessionLocal()
    try:
        row = anchor_mod.anchor_admin(db, s, force=True)
        assert row is not None, "a failed anchor must still leave a receipt"
        assert row.status == "failed"
        assert "SUPERSECRET" not in (row.detail or ""), \
            "the RPC secret leaked into a persisted, operator-visible receipt"
    finally:
        db.close()

    # …and a staff action still records, with the chain intact
    _record(1, chain)
    db = SessionLocal()
    try:
        assert admin_chain.verify_admin_chain(db)["ok"] is True
        assert admin_chain.verify_admin_anchor(db)["ok"] is None, \
            "a failed anchor is not a witness; the verdict must be 'not known'"
    finally:
        db.close()


def test_no_anchor_at_all_reports_absence_not_success(chain):
    """⚠ ok=None IS NOT ok=True. The same rule verify_admin_chain already follows:
    an unwitnessed chain has not been checked against anything."""
    _record(2, chain)
    db = SessionLocal()
    try:
        v = admin_chain.verify_admin_anchor(db)
        assert v["ok"] is None, v
        assert v["kind"] is None
        assert "no anchor" in v["detail"].lower(), v["detail"]
    finally:
        db.close()


# ── THE WORD ────────────────────────────────────────────────────────────────
def test_the_project_never_calls_anything_immutable():
    """⚠ THE POINT OF THE PHASE. Anchoring earns "tamper-evident, independently
    verifiable" — the project's own phrase — and nothing stronger. If this fails,
    a surface somewhere is about to be allowed to overclaim.

    ⚠ IT SCANS RUNTIME STRINGS, NOT PROSE — AND THE FIRST CUT DID NOT.

    A plain substring sweep failed on admin_chain.py, whose docstring now says
    "It may NOT say 'immutable' or 'tamper-proof'". The guard was matching the
    sentence that states the rule: a check satisfied by its own comment, which
    is the oldest failure in this stream (it took L0 and L5 as well).

    So the sweep parses each module and looks only at string constants that are
    NOT docstrings — the ones that can reach an API response, a log line, or the
    console. Prose explaining the rule is exempt; a claim is not."""
    import ast
    import pathlib
    root = pathlib.Path(__file__).resolve().parents[3]
    WORDS = ("immutable", "tamper-proof", "tamperproof")
    checked = 0
    for sub in ("backend/app", "verifier"):
        for f in sorted((root / sub).rglob("*.py")):
            tree = ast.parse(f.read_text(encoding="utf-8"))
            doc_nodes = set()
            for node in ast.walk(tree):
                if isinstance(node, (ast.Module, ast.ClassDef, ast.FunctionDef,
                                     ast.AsyncFunctionDef)):
                    body = getattr(node, "body", None)
                    if body and ast.get_docstring(node, clean=False) is not None:
                        doc_nodes.add(id(body[0].value))
            for node in ast.walk(tree):
                if (isinstance(node, ast.Constant) and isinstance(node.value, str)
                        and id(node) not in doc_nodes):
                    checked += 1
                    low = node.value.lower()
                    for word in WORDS:
                        assert word not in low, (
                            f"{f.relative_to(root)}:{node.lineno} has a RUNTIME string "
                            f"containing {word!r}: {node.value[:80]!r}. The project's "
                            "phrase is 'tamper-evident, independently verifiable'; "
                            "anchor.py says why anything stronger is false.")
    assert checked > 500, \
        f"the sweep examined only {checked} strings — it is not reaching the code"
