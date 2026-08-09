"""G5 · #79 — the staff audit trail is hash-chained.

WHAT THESE GUARD, AND HOW THEY TRY NOT TO LIE
---------------------------------------------
Every test here DRIVES the shipped writer (``record_admin_action``) and the
shipped verifier (``verify_admin_chain``) — no test recomputes a hash with its
own copy of the canonical form, because a guard that reimplements the thing it
checks is green from birth and stays green through the exact divergence it
exists to catch.

Two of them go through a real HTTP route rather than the helper, because the
helper is a primitive and exercising a primitive does not guard its 42 callers.

One of them asserts a LIMIT rather than a capability: tail truncation is NOT
detectable by recomputation, and a guard that pins the limitation is what makes
a later "tamper-evident" claim in the UI fail out loud.
"""
from __future__ import annotations

import threading
import time
import uuid
from datetime import datetime, timedelta, timezone

import pytest
from sqlalchemy import text

from app.admin_audit import record_admin_action
from app.admin_chain import ADMIN_CHAIN_GENESIS, verify_admin_chain
from app.db import SessionLocal
from app.models import AdminAction, StaffUser


# ── helpers ─────────────────────────────────────────────────────────────────

def _staff(db, staff_id) -> StaffUser:
    return db.get(StaffUser, uuid.UUID(staff_id))


def _write(staff_id, n=1, action="test.action", **kw):
    """Drive the SHIPPED writer n times, each in its own transaction."""
    for i in range(n):
        db = SessionLocal()
        try:
            record_admin_action(db, _staff(db, staff_id), action,
                                detail={"i": i}, **kw)
            db.commit()
        finally:
            db.close()


def _verify():
    db = SessionLocal()
    try:
        return verify_admin_chain(db)
    finally:
        db.close()


def _rows():
    db = SessionLocal()
    try:
        return db.execute(
            text("SELECT seq, prev_hash, chain_hash, action, detail, created_at "
                 "FROM admin_actions ORDER BY seq NULLS FIRST")
        ).all()
    finally:
        db.close()


# ── 1 · writer and verifier agree ───────────────────────────────────────────

def test_a_written_row_verifies_with_the_shipped_verifier(make_staff):
    """The whole mechanism in one line: what the writer stored is what the
    verifier re-derives. Driven end to end — nothing here knows the field order,
    so a change to the canonical form breaks this without being restated."""
    s = make_staff()
    _write(s["id"], n=1)
    r = _verify()
    assert r["ok"] is True, r
    assert r["chained"] == 1 and r["unchained"] == 0
    assert r["detail"] == "sequence unbroken"

    row = _rows()[0]
    assert row.seq == 1
    assert row.prev_hash == ADMIN_CHAIN_GENESIS, "seq 1 must chain to genesis"
    assert row.chain_hash == r["head_hash"]
    assert len(row.chain_hash) == 64


def test_a_chain_of_many_rows_verifies_and_each_links_to_the_last(make_staff):
    s = make_staff()
    _write(s["id"], n=12)
    r = _verify()
    assert r["ok"] is True and r["chained"] == 12 and r["head_seq"] == 12
    rows = _rows()
    assert [x.seq for x in rows] == list(range(1, 13))
    for prev, cur in zip(rows, rows[1:]):
        assert cur.prev_hash == prev.chain_hash, f"entry {cur.seq} does not follow {prev.seq}"


def test_created_at_is_set_by_the_writer_not_left_to_the_server_default(make_staff):
    """Trap 1. server_default=func.now() fills at INSERT, which is after the
    writer must hash the row — a timestamp the hash cannot see is a timestamp an
    editor can move for free. Proven by MOVING it and watching the chain break,
    not by reading the model."""
    s = make_staff()
    _write(s["id"], n=3)
    assert _verify()["ok"] is True

    db = SessionLocal()
    try:
        db.execute(text("UPDATE admin_actions SET created_at = created_at + interval "
                        "'9 hours' WHERE seq = 2"))
        db.commit()
    finally:
        db.close()

    r = _verify()
    assert r["ok"] is False
    assert r["first_broken_seq"] == 2, r
    assert "changed after it was written" in r["detail"]


# ── 2 · an edited field breaks it, and the report NAMES the row ─────────────

@pytest.mark.parametrize("column,value", [
    ("action", "'org.enable'"),
    ("ip", "'203.0.113.9'"),
    ("target_type", "'organization'"),
    ("target_id", "'somewhere-else'"),
    ("detail", """'{"i": 99}'::jsonb"""),
])
def test_editing_one_field_of_one_middle_row_breaks_the_chain_at_that_row(
        make_staff, column, value):
    s = make_staff()
    _write(s["id"], n=7)
    assert _verify()["ok"] is True

    db = SessionLocal()
    try:
        db.execute(text(f"UPDATE admin_actions SET {column} = {value} WHERE seq = 4"))
        db.commit()
    finally:
        db.close()

    r = _verify()
    assert r["ok"] is False, f"editing {column} went unnoticed"
    assert r["first_broken_seq"] == 4, f"named entry {r['first_broken_seq']}, not 4"
    assert r["head_hash"] is None, "a broken chain must not report a head"


def test_editing_the_stored_prev_hash_alone_is_detected(make_staff):
    """⚠ THE ONE THING ONLY THE LINK CHECK CATCHES, and it was untested until a
    mutation went MISSED.

    The recompute derives each hash from the PREVIOUS ROW's chain_hash, never
    from the stored prev_hash column — so an edit to prev_hash by itself leaves
    every recomputed digest matching, and the `row.prev_hash != prev_hash`
    comparison is the only thing standing between that and a clean report. A
    forged prev_hash is exactly how someone would try to splice a chain.
    """
    s = make_staff()
    _write(s["id"], n=6)
    assert _verify()["ok"] is True

    db = SessionLocal()
    try:
        db.execute(text("UPDATE admin_actions SET prev_hash = "
                        "'%s' WHERE seq = 4" % ("ab" * 32)))
        db.commit()
    finally:
        db.close()

    r = _verify()
    assert r["ok"] is False, "a forged prev_hash went unnoticed"
    assert r["first_broken_seq"] == 4, r
    assert "does not follow" in r["detail"], r["detail"]


def test_reordering_two_entries_is_detected(make_staff):
    """Swapping two rows' contents keeps every hash and every seq present, so a
    guard that only counted rows would pass."""
    s = make_staff()
    _write(s["id"], n=5)
    db = SessionLocal()
    try:
        db.execute(text(
            "UPDATE admin_actions a SET chain_hash = b.chain_hash, "
            "prev_hash = b.prev_hash FROM admin_actions b "
            "WHERE a.seq = 2 AND b.seq = 3"))
        db.commit()
    finally:
        db.close()
    r = _verify()
    assert r["ok"] is False and r["first_broken_seq"] == 2, r


# ── 3 · a deleted middle row is detected — the reason this exists ───────────

def test_deleting_a_middle_row_is_detected_and_named(make_staff):
    s = make_staff()
    _write(s["id"], n=6)
    assert _verify()["ok"] is True

    db = SessionLocal()
    try:
        db.execute(text("DELETE FROM admin_actions WHERE seq = 3"))
        db.commit()
    finally:
        db.close()

    r = _verify()
    assert r["ok"] is False
    # ⚠ 3, NOT 4. G5.1 named the first SURVIVING row while the sentence named
    # the missing one, so the console's jump landed on an intact entry and an
    # operator following it concludes the tool is wrong.
    assert r["first_broken_seq"] == 3, r
    assert r["kind"] == "missing", r
    assert r["detail"] == "entry 3 is missing"
    assert str(r["first_broken_seq"]) in r["detail"], (
        "the number the words name and the number the console jumps to have "
        "drifted apart again: %r" % r)
    assert r["chained"] == 5


@pytest.mark.parametrize("kind,seq,words,break_it", [
    ("missing", 4, "entry 4 is missing",
     "DELETE FROM admin_actions WHERE seq = 4"),
    ("out_of_order", 4, "entry 4 does not follow the one before it",
     "UPDATE admin_actions SET prev_hash = '%s' WHERE seq = 4" % ("ab" * 32)),
    ("modified", 4, "entry 4 was changed after it was written",
     "UPDATE admin_actions SET ip = '203.0.113.9' WHERE seq = 4"),
])
def test_each_break_kind_is_named_and_points_at_the_entry_it_names(
        make_staff, staff_login, kind, seq, words, break_it):
    """⚠ THREE DIFFERENT EVENTS, AND THE CONSOLE HAD STOPPED SHOWING WHICH.

    A deletion, a splice and an edit call for different responses. G5 showed
    the reason; G5.1 collapsed all three into "sequence breaks at entry N" and
    dropped the detail entirely. `kind` carries it now, and it is driven
    end to end: the incident reaches the API, and the number in the words is
    the number the console's jump uses — with the row it lands on checked.
    """
    s = make_staff()
    _write(s["id"], n=7)
    assert _verify()["ok"] is True

    db = SessionLocal()
    try:
        db.execute(text(break_it))
        db.commit()
    finally:
        db.close()

    r = _verify()
    assert r["ok"] is False, r
    assert r["kind"] == kind, r
    assert r["detail"] == words, r
    assert r["first_broken_seq"] == seq, (
        "the jump would land on %s while the words name %d"
        % (r["first_broken_seq"], seq))

    # end to end: the seq the words name is what the audit list resolves
    c = staff_login(s["email"], s["password"])
    d = c.get("/admin/v1/audit/chain?verify=1").json()
    assert d["kind"] == kind and d["first_broken_seq"] == seq, d
    rows = c.get("/admin/v1/audit?seq=%d" % d["first_broken_seq"]).json()
    if kind == "missing":
        assert rows["total"] == 0, (
            "the chain says entry %d is missing and the list found one — the "
            "two disagree about the same number" % seq)
    else:
        assert rows["total"] == 1 and rows["items"][0]["seq"] == seq, rows


def test_removing_entries_from_the_END_is_NOT_detected(make_staff):
    """⚠ A LIMIT, ASSERTED ON PURPOSE.

    Truncating the tail leaves 1..N-k recomputing perfectly — nothing in the
    stored data says how long the chain was. Only an outside witness that
    recorded the older head would notice, and there is none: this chain is not
    anchored anywhere Foxy does not control.

    This test exists so the limitation cannot be quietly forgotten. If anchoring
    later closes it, this test is what has to be rewritten — and the UI copy
    guard in foxy-adminpage is what has to change with it.
    """
    s = make_staff()
    _write(s["id"], n=8)
    db = SessionLocal()
    try:
        db.execute(text("DELETE FROM admin_actions WHERE seq > 5"))
        db.commit()
    finally:
        db.close()

    r = _verify()
    assert r["ok"] is True, "the recompute cannot see a truncated tail"
    assert r["chained"] == 5 and r["head_seq"] == 5


# ── 4 · a rolled-back caller leaves no gap ──────────────────────────────────

def test_a_rolled_back_caller_leaves_no_seq_gap(make_staff):
    """Trap 2. A gap is indistinguishable from a deleted row, so a seq consumed
    by an abandoned transaction would be a permanent false alarm."""
    s = make_staff()
    _write(s["id"], n=2)

    db = SessionLocal()
    try:
        record_admin_action(db, _staff(db, s["id"]), "test.rolled_back")
        db.rollback()
    finally:
        db.close()

    _write(s["id"], n=1, action="test.after")
    r = _verify()
    assert r["ok"] is True, r
    assert r["chained"] == 3
    assert [x.seq for x in _rows()] == [1, 2, 3]
    assert not any(x.action == "test.rolled_back" for x in _rows())


# ── 5 · two actions in ONE transaction chain to EACH OTHER ─────────────────

def test_two_actions_in_one_transaction_chain_to_each_other(make_staff):
    """⚠ THE SESSION IS autoflush=False, so the second call cannot see a staged
    row — which is why the writer does a Core INSERT rather than db.add(). If it
    reverted to db.add(), both rows would read the same tail, both would claim
    the same seq, and the unique index would turn it into an IntegrityError.
    """
    s = make_staff()
    _write(s["id"], n=1)

    db = SessionLocal()
    try:
        staff = _staff(db, s["id"])
        record_admin_action(db, staff, "test.first", detail={"n": 1})
        record_admin_action(db, staff, "test.second", detail={"n": 2})
        db.commit()
    finally:
        db.close()

    r = _verify()
    assert r["ok"] is True, r
    assert r["chained"] == 3
    rows = {x.seq: x for x in _rows()}
    assert rows[2].action == "test.first" and rows[3].action == "test.second"
    assert rows[3].prev_hash == rows[2].chain_hash, \
        "the second row chained to the tail before the first, not to the first"


def test_the_writer_does_not_flush_the_callers_pending_objects(make_staff):
    """The reason for the Core insert, stated as a behaviour.

    db.flush() inside the writer would also flush whatever the CALLER staged —
    turning a deferred IntegrityError into one raised inside record_admin_action,
    outside the caller's try/except. admin_campaigns.create_campaign converts
    exactly that error into a 409; a flush here would make it a 500.
    """
    s = make_staff()
    db = SessionLocal()
    try:
        staff = _staff(db, s["id"])
        # A staged row that CANNOT be inserted (duplicate email on staff_users).
        db.add(StaffUser(email=staff.email, password_hash="x", platform_role="viewer"))
        record_admin_action(db, staff, "test.with_pending")
        assert db.new, "the caller's staged object was flushed by the writer"
        db.rollback()
    finally:
        db.close()


# ── 6 · concurrent writers do not collide ──────────────────────────────────

def test_concurrent_writers_do_not_fork_the_chain(make_staff, monkeypatch):
    """Trap 4, driven: 8 threads writing at once.

    ⚠ THE WINDOW IS HELD OPEN ON PURPOSE. The first version just started eight
    threads and hoped they collided — and in one run they did not, so deleting
    the advisory lock left this GREEN over code that had no lock in it. A race
    guard that fires only when the race happens to occur reports "no bug" for
    "no collision".

    So the tail read is wrapped with a short sleep, on the TEST's side, which
    makes every writer read before any writer inserts. With the lock this is
    invisible — they queue on it and each sees the previous row. Without it
    they all read the same tail and uq_admin_actions_seq fires.
    """
    import threading

    from app import admin_audit

    real_head = admin_audit.chain_head

    def slow_head(db):
        row = real_head(db)
        time.sleep(0.25)          # hold the read/insert window open
        return row

    monkeypatch.setattr(admin_audit, "chain_head", slow_head)

    s = make_staff()
    staff_id = s["id"]
    errors: list[BaseException] = []
    start = threading.Barrier(8)

    def worker(i):
        try:
            start.wait(timeout=20)
            _write(staff_id, n=1, action=f"test.concurrent{i}")
        except BaseException as exc:                      # noqa: BLE001
            errors.append(exc)

    threads = [threading.Thread(target=worker, args=(i,)) for i in range(8)]
    for t in threads:
        t.start()
    for t in threads:
        t.join(timeout=60)

    assert not errors, errors
    r = _verify()
    assert r["ok"] is True, r
    assert r["chained"] == 8
    assert sorted(x.seq for x in _rows()) == list(range(1, 9))


# ── 7 · pre-chain rows are pre-chain, never broken ─────────────────────────

def _seed_pre_chain(staff_id, n, when=None):
    """A row exactly as it looked before 0066: no seq, no hashes. Written with
    raw SQL because the shipped writer can no longer produce one."""
    db = SessionLocal()
    try:
        for i in range(n):
            db.execute(text(
                "INSERT INTO admin_actions (id, staff_user_id, action, created_at) "
                "VALUES (:id, :sid, :a, :t)"),
                {"id": uuid.uuid4(), "sid": uuid.UUID(staff_id), "a": f"legacy.{i}",
                 "t": (when or datetime.now(timezone.utc)) - timedelta(days=n - i)})
        db.commit()
    finally:
        db.close()


def test_rows_written_before_the_chain_are_reported_as_pre_chain_not_broken(make_staff):
    s = make_staff()
    _seed_pre_chain(s["id"], 4)
    r = _verify()
    # G5.1 · ok is None, not True. Nothing was verified because there was
    # nothing to verify, and the pre-chain rows are still not a failure — the
    # two are different answers and used to be the same one.
    assert r["ok"] is None, "an empty chain must not report as verified"
    assert r["ok"] is not False, "pre-chain rows must never read as a failure"
    assert r["unchained"] == 4 and r["chained"] == 0
    assert r["detail"] == "nothing to check"

    _write(s["id"], n=3)
    r = _verify()
    assert r["ok"] is True and r["chained"] == 3 and r["unchained"] == 4
    assert r["head_seq"] == 3
    assert r["started_at"] is not None, "the start date is derived from seq 1"


def test_deleting_every_chained_row_is_not_reported_as_verified(make_staff):
    """⚠ THE EXTREME OF THE TRUNCATION LIMIT, and G5 answered it wrong.

    Delete every chained row and the writer restarts at seq 1 against GENESIS,
    so a recompute is spotless. The copy already names tail truncation as
    undetectable, so the words were not lying — but ok=True was. It says
    "nothing to check" now, which is what an empty chain is.

    This is NOT closed, and this test is where that is written down: an
    operator's externally recorded head hash is what would catch it, which is
    why the console tells them to keep one.
    """
    s = make_staff()
    _write(s["id"], n=6)
    assert _verify()["ok"] is True

    db = SessionLocal()
    try:
        db.execute(text("DELETE FROM admin_actions WHERE seq IS NOT NULL"))
        db.commit()
    finally:
        db.close()

    r = _verify()
    assert r["ok"] is None, (
        "a wholesale delete reported as verified: %r" % r)
    assert r["detail"] == "nothing to check"
    assert r["chained"] == 0

    # and the writer really does restart, which is the part that cannot be seen
    _write(s["id"], n=1, action="test.after_wipe")
    assert [x.seq for x in _rows()] == [1]
    assert _verify()["ok"] is True, (
        "the restarted chain does not verify, which would mean this test is "
        "measuring something other than the self-healing it describes")


def test_a_chain_too_long_to_check_still_reports_its_head(make_staff, monkeypatch):
    """The console tells operators to record the head elsewhere so a later
    truncation stops being invisible. That makes it load-bearing exactly when
    the chain is too long to recompute, and G5 nulled it there."""
    from app import admin_chain

    s = make_staff()
    _write(s["id"], n=4)
    monkeypatch.setattr(admin_chain, "ADMIN_CHAIN_VERIFY_LIMIT", 2)

    r = _verify()
    assert r["ok"] is None and "too long" in r["detail"]
    assert r["head_seq"] == 4, r
    assert r["head_hash"] and len(r["head_hash"]) == 64, (
        "the one value the copy asks operators to keep is withheld exactly "
        "when they cannot verify without it")
    assert r["started_at"], r


def test_a_blocked_staff_action_fails_fast_instead_of_hanging(make_staff, monkeypatch):
    """⚠ THE BACKSTOP FOR THE CALLER NOBODY GUARDED.

    The chain lock lives as long as the caller's transaction, and a caller that
    does slow work holds every other staff action and every staff sign-in. The
    AST guard catches the shapes it can see; this is what happens when one gets
    past it: the blocked action fails in seconds with a sentence, rather than
    hanging for as long as the other transaction lasts.
    """
    import threading

    from app import admin_audit
    from fastapi import HTTPException

    monkeypatch.setattr(admin_audit, "ADMIN_CHAIN_LOCK_TIMEOUT_MS", 300)
    s = make_staff()
    _write(s["id"], n=1)

    holding = threading.Event()
    release = threading.Event()

    def hold():
        db = SessionLocal()
        try:
            record_admin_action(db, _staff(db, s["id"]), "test.slow_holder")
            holding.set()
            release.wait(timeout=20)
            db.commit()
        finally:
            db.close()

    t = threading.Thread(target=hold)
    t.start()
    try:
        assert holding.wait(timeout=20)
        started = time.perf_counter()
        db = SessionLocal()
        try:
            with pytest.raises(HTTPException) as exc:
                record_admin_action(db, _staff(db, s["id"]), "test.blocked")
            waited = time.perf_counter() - started
            assert exc.value.status_code == 503, exc.value.detail
            assert "busy" in str(exc.value.detail).lower(), exc.value.detail
            assert waited < 5.0, (
                "waited %.1fs — the timeout did not apply, so a slow caller "
                "still hangs everyone" % waited)
        finally:
            db.rollback()
            db.close()
    finally:
        release.set()
        t.join(timeout=25)

    # and the holder's own row is intact: the timeout is the BLOCKED writer's
    # problem, not a way to break the one that got there first.
    assert _verify()["ok"] is True
    assert any(x.action == "test.slow_holder" for x in _rows())
    assert not any(x.action == "test.blocked" for x in _rows())


def _commit_before_record(app_dir):
    """Call sites where something commits BEFORE record_admin_action.

    Module-aware on purpose: a bare-name pass reported four and three were
    phantoms — `notify.broadcast` resolving to admin_config.broadcast, once as
    a self-reference. `module.func()` resolves against that module's file when
    the module is one of ours; unqualified names fall back to the bare index
    and are reported as such.
    """
    import ast

    by_qual, by_name, trees = {}, {}, {}
    for path in sorted(app_dir.rglob("*.py")):
        try:
            trees[path] = ast.parse(path.read_text(encoding="utf-8"))
        except SyntaxError:                      # pragma: no cover
            continue
        for node in ast.walk(trees[path]):
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                by_qual[(path.stem, node.name)] = node
                by_name.setdefault(node.name, set()).add(path.stem)
    modules = {p.stem for p in trees}

    def resolve(call, here):
        f = call.func
        if isinstance(f, ast.Attribute):
            if isinstance(f.value, ast.Name) and f.value.id in modules:
                return (f.value.id, f.attr)
            return (None, f.attr)
        if isinstance(f, ast.Name):
            return ((here, f.id) if (here, f.id) in by_qual else (None, f.id))
        return (None, "")

    def commits(node):
        return any(isinstance(c, ast.Call) and isinstance(c.func, ast.Attribute)
                   and c.func.attr == "commit" for c in ast.walk(node))

    committing = {k for k, n in by_qual.items() if commits(n)}
    for _ in range(8):
        grew = False
        for (mod, name), node in by_qual.items():
            if (mod, name) in committing:
                continue
            for c in ast.walk(node):
                if not isinstance(c, ast.Call):
                    continue
                m, n2 = resolve(c, mod)
                if (m, n2) == (mod, name):       # never its own caller
                    continue
                if ({(m, n2)} if m else {(x, n2) for x in by_name.get(n2, ())}) & committing:
                    committing.add((mod, name))
                    grew = True
                    break
        if not grew:
            break

    def dead_before(fn, call, rec_line):
        """True when `call` sits in a branch that leaves before the record.

        ⚠ ONE SHAPE, NAMED: an if/try BODY whose last statement is a return or
        a raise, ending before the record's line. That is auth_staff's MFA
        branch — it commits an OTP and returns, so it can never reach the
        record and is not the hazard this guard is about. Anything more
        elaborate (a loop that always breaks, a helper that raises) is beyond
        a syntax check and would be reported.
        """
        for blk in ast.walk(fn):
            bodies = []
            if isinstance(blk, ast.If):
                bodies = [blk.body, blk.orelse]
            elif isinstance(blk, ast.Try):
                bodies = [blk.body, blk.orelse] + [h.body for h in blk.handlers]
            for body in bodies:
                if not body or not isinstance(body[-1], (ast.Return, ast.Raise)):
                    continue
                lo, hi = body[0].lineno, body[-1].end_lineno or body[-1].lineno
                if lo <= call.lineno <= hi < rec_line:
                    return True
        return False

    out, recorded = [], 0
    for path, tree in trees.items():
        for node in ast.walk(tree):
            if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                continue
            cs = [c for c in ast.walk(node) if isinstance(c, ast.Call)]
            recs = [c for c in cs if resolve(c, path.stem)[1] == "record_admin_action"]
            if not recs:
                continue
            recorded += len(recs)
            first = min(recs, key=lambda c: c.lineno)
            inside = {id(x) for x in ast.walk(first)}
            for c in cs:
                if id(c) in inside or c.lineno >= first.lineno:
                    continue
                m, n2 = resolve(c, path.stem)
                if (m, n2) == (path.stem, node.name):
                    continue
                direct = isinstance(c.func, ast.Attribute) and c.func.attr == "commit"
                hits = ({(m, n2)} if m else {(x, n2) for x in by_name.get(n2, ())})
                if not (direct or (hits & committing)):
                    continue
                if dead_before(node, c, first.lineno):
                    continue
                out.append("%s:%d %s() -> %s()"
                           % (path.name, c.lineno, node.name, n2))
    return out, recorded


def test_nothing_commits_before_it_records():
    """⚠ THIS IS WHAT MAKES THE 503's WORDS TRUE.

    record_admin_action's timeout answers "Nothing was changed; try again."
    That sentence is only true while no caller has already committed by the
    time it runs — and auth_staff.staff_login had: _establish_staff_session
    commits the session row and stamps last_login_at, so a 503 left the
    operator signed in, with no staff.login row, under a message saying
    nothing happened. An unlogged staff sign-in is the gap #79 exists to close.

    So the message is guarded against the STATE, not the status code: derive
    every call site where anything commits first, and there must be none.

    ⚠ WHAT THIS CANNOT SEE: a commit reached through a registry or a variable,
    through getattr, or through a bare name that collides with a committing
    function in another module (the fallback reports those, it does not resolve
    them). Reachability is one shape only — an if/try body ending in return or
    raise, which is auth_staff's MFA branch; anything cleverer is reported
    rather than reasoned about. It is the same closure the slow-work guard uses
    and the same limits apply — a floor, not a proof.
    """
    import pathlib

    app_dir = pathlib.Path(__file__).resolve().parents[2] / "app"
    offenders, recorded = _commit_before_record(app_dir)
    assert recorded >= 40, (
        f"only {recorded} record_admin_action call sites found — this guard "
        f"walks the app package, and finding almost none means it is walking "
        f"the wrong directory and proving nothing")
    assert not offenders, (
        "these call sites commit BEFORE recording, so a chain timeout leaves a "
        "committed mutation with no audit row while the 503 says nothing was "
        "changed: %s" % offenders)


def test_the_caller_does_not_inherit_the_chains_lock_timeout(make_staff):
    """The timeout is the CHAIN's, not the caller's.

    SET LOCAL is transaction-scoped, so without the reset every statement the
    caller runs after recording — its flush, its own queries — would sit under
    a five-second ceiling nobody asked for and fail in a way that looks like
    the audit chain's fault. Driven by reading the setting back, because
    "there is a reset statement" is a claim about source and this is a claim
    about the session.
    """
    s = make_staff()
    db = SessionLocal()
    try:
        before = db.execute(text("SHOW lock_timeout")).scalar_one()
        record_admin_action(db, _staff(db, s["id"]), "test.timeout_scope")
        after = db.execute(text("SHOW lock_timeout")).scalar_one()
        db.commit()
    finally:
        db.close()
    assert after == before, (
        "the caller inherited the chain's lock timeout: %r before, %r after — "
        "every statement it runs from here fails after %s instead of waiting"
        % (before, after, after))


def test_a_sign_in_blocked_by_the_chain_leaves_nothing_signed_in(
        make_staff, client, monkeypatch):
    """⚠ THE STATE, NOT THE STATUS CODE.

    G5.1's timeout said "Nothing was changed; try again." On staff_login that
    was false: _establish_staff_session had already committed the session row
    and stamped last_login_at, and the cookie was set — so the operator was
    signed in, with no staff.login row, under a message saying nothing
    happened. An unlogged staff sign-in is the gap #79 exists to close, and it
    was NEW in G5.1.

    Driven through the real route with the chain held by another writer: the
    503 must come with no session, no cookie and no last_login_at.
    """
    import threading

    from app import admin_audit

    monkeypatch.setattr(admin_audit, "ADMIN_CHAIN_LOCK_TIMEOUT_MS", 300)
    s = make_staff()
    _write(s["id"], n=1)

    def _state():
        db = SessionLocal()
        try:
            row = db.execute(text(
                "SELECT (SELECT count(*) FROM staff_sessions WHERE staff_user_id=:i),"
                "       (SELECT last_login_at FROM staff_users WHERE id=:i),"
                "       (SELECT count(*) FROM admin_actions WHERE action='staff.login')"),
                {"i": uuid.UUID(s["id"])}).one()
            return {"sessions": row[0], "last_login": row[1], "logins": row[2]}
        finally:
            db.close()

    before = _state()
    holding, release = threading.Event(), threading.Event()

    def hold():
        db = SessionLocal()
        try:
            record_admin_action(db, _staff(db, s["id"]), "test.holding_the_chain")
            holding.set()
            release.wait(timeout=25)
            db.commit()
        finally:
            db.close()

    t = threading.Thread(target=hold)
    t.start()
    try:
        assert holding.wait(timeout=20)
        r = client.post("/admin/v1/auth/login",
                        json={"email": s["email"], "password": s["password"]})
    finally:
        release.set()
        t.join(timeout=30)

    assert r.status_code == 503, r.text
    assert "nothing was changed" in r.text.lower(), r.text

    after = _state()
    assert after["logins"] == before["logins"], (
        "no staff.login row was written, which is correct — but this asserts it "
        "so the rest of the check cannot pass vacuously")
    assert after["sessions"] == before["sessions"], (
        "the session row was COMMITTED while the response said nothing was "
        "changed: %s -> %s" % (before["sessions"], after["sessions"]))
    assert after["last_login"] == before["last_login"], (
        "last_login_at moved while the response said nothing was changed")
    # ⚠ THE SESSION COOKIE, not "no cookies". foxy_csrf is a double-submit
    # token the middleware sets on every response including this one; asserting
    # an empty jar failed on it and would have been a guard measuring the wrong
    # thing. foxy_staff_session (app/main.py:215) is what signs an operator in.
    assert "foxy_staff_session" not in r.cookies, (
        "a session cookie was set on a sign-in the operator was told did not "
        "happen: %s" % dict(r.cookies))

    # and the operator really is not signed in
    assert client.get("/admin/v1/auth/me").status_code == 401


def test_the_login_records_before_it_establishes_the_session():
    """⚠ AN ASYMMETRIC TRADE, PINNED SO IT CANNOT BE UNDONE AS A TIDY-UP.

    staff_login records the audit row and commits it, THEN establishes the
    session. That order is deliberate and it is not free:

      · what it buys — a chain timeout leaves nothing committed and nothing
        signed in, so the 503's "Nothing was changed" is true. The reverse
        order shipped in G5.1 and left the operator genuinely signed in with
        NO staff.login row: an unlogged staff sign-in, which is the exact gap
        #79 exists to close.
      · what it costs — if _establish_staff_session then raises, the operator
        gets a 500 with a chained staff.login row and no session: an attempt
        recorded as though it succeeded.

    Over-reporting is recoverable — the operator retries and the next row
    supersedes it, and the trail still contains every sign-in that happened.
    Under-reporting is not. So the direction is chosen, not accidental, and
    this is where that is written down.

    Read from the AST rather than by eye: a reordering is a two-line diff that
    looks like housekeeping, and the module docstring of app/admin_audit.py
    names this test as the thing that stops it.
    """
    import ast
    import pathlib

    src = (pathlib.Path(__file__).resolve().parents[2]
           / "app/routers/auth_staff.py").read_text(encoding="utf-8")
    fn = next(n for n in ast.walk(ast.parse(src))
              if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef))
              and n.name == "staff_login")

    def line_of(name):
        hits = [c.lineno for c in ast.walk(fn) if isinstance(c, ast.Call)
                and getattr(c.func, "attr", getattr(c.func, "id", "")) == name]
        assert hits, "staff_login no longer calls %s()" % name
        return min(hits)

    rec = line_of("record_admin_action")
    est = line_of("_establish_staff_session")
    commits = sorted(c.lineno for c in ast.walk(fn) if isinstance(c, ast.Call)
                     and isinstance(c.func, ast.Attribute) and c.func.attr == "commit")

    assert rec < est, (
        "staff_login establishes the session BEFORE recording again (record at "
        "line %d, session at line %d). That is the G5.1 order: the session and "
        "the cookie commit first, so a busy-chain 503 signs the operator in "
        "with no staff.login row while telling them nothing was changed."
        % (rec, est))
    assert any(rec < ln < est for ln in commits), (
        "the audit row is no longer committed between recording and "
        "establishing the session, so a failure in the session leaves the "
        "record uncommitted — which is the under-reporting direction this "
        "order exists to avoid (record at %d, session at %d, commits at %s)"
        % (rec, est, commits))


def test_the_staff_list_reports_the_login_column_not_the_audit_proxy(
        make_staff, staff_login):
    """The staff list said "last login" and meant "the newest staff.login audit
    row", which is a proxy. Since G5.2 they can disagree — the audit row commits
    before the session — so the column now reads staff_users.last_login_at,
    stamped beside the session it commits with.

    Driven by making them disagree: a staff.login audit row far in the future
    with no session behind it must NOT move the column.
    """
    import uuid as _uuid

    s = make_staff()
    c = staff_login(s["email"], s["password"])
    row = next(x for x in c.get("/admin/v1/staff").json() if x["email"] == s["email"])
    real = row["last_login"]
    assert real is not None, "a real sign-in did not reach the column"

    # a staff.login row the session never backed — the shape G5.2 made possible
    db = SessionLocal()
    try:
        db.execute(text(
            "INSERT INTO admin_actions (id, staff_user_id, action, created_at) "
            "VALUES (:i, :s, 'staff.login', now() + interval '10 years')"),
            {"i": _uuid.uuid4(), "s": _uuid.UUID(s["id"])})
        db.commit()
    finally:
        db.close()

    again = next(x for x in c.get("/admin/v1/staff").json()
                 if x["email"] == s["email"])["last_login"]
    assert again == real, (
        "an audit row with no session behind it moved the staff list's last "
        "login: %r -> %r. The column is derived from the trail again, so it "
        "reports sign-ins that did not happen." % (real, again))


def test_a_non_postgres_bind_refuses_rather_than_degrading(make_staff):
    """The dialect check used to make the advisory lock and the FOR UPDATE both
    no-ops off Postgres, leaving the unique constraint to turn a fork into an
    IntegrityError that rolls back the mutation being audited. An audit chain
    that silently stops being safe is worse than one that refuses."""
    class _Fake:
        class dialect:
            name = "sqlite"

    s = make_staff()
    db = SessionLocal()
    try:
        staff = _staff(db, s["id"])
        db.get_bind()                       # real bind, so the fixture is sane
        object.__setattr__(db, "bind", _Fake)
        with pytest.raises(RuntimeError) as exc:
            record_admin_action(db, staff, "test.wrong_dialect")
        assert "PostgreSQL" in str(exc.value), exc.value
        assert "sqlite" in str(exc.value), (
            "the refusal does not name the dialect it got, so nobody can tell "
            "what is misconfigured: %s" % exc.value)
    finally:
        db.rollback()
        db.close()


def test_the_audit_list_filters_by_seq(make_staff, staff_login):
    """The console's break verdict jumps here. Without it, "sequence breaks at
    entry N" names a row an operator cannot reach."""
    s = make_staff()
    _write(s["id"], n=6, action="test.filterable")
    c = staff_login(s["email"], s["password"])

    d = c.get("/admin/v1/audit?seq=4").json()
    assert d["total"] == 1, d
    assert d["items"][0]["seq"] == 4

    assert c.get("/admin/v1/audit?seq=999").json()["total"] == 0
    assert c.get("/admin/v1/audit?seq=0").status_code == 422, (
        "seq is 1-based; 0 should be rejected rather than silently matching "
        "nothing")
    # and it composes with the other filters rather than replacing them
    assert c.get("/admin/v1/audit?seq=4&action=nope").json()["total"] == 0


def test_the_chain_starts_at_one_even_with_older_rows_present(make_staff):
    """No backfill, so the first CHAINED row is seq 1 regardless of how much
    history sits beside it."""
    s = make_staff()
    _seed_pre_chain(s["id"], 5)
    _write(s["id"], n=1)
    seqs = [x.seq for x in _rows()]
    assert seqs.count(None) == 5
    assert [x for x in seqs if x is not None] == [1]


def test_deleting_a_pre_chain_row_does_not_break_the_chain(make_staff):
    """Honest about the boundary: the mechanism starts where it starts. If this
    ever failed it would mean pre-chain rows had been folded in, which is the
    fabrication the migration refuses to do."""
    s = make_staff()
    _seed_pre_chain(s["id"], 3)
    _write(s["id"], n=4)
    db = SessionLocal()
    try:
        db.execute(text("DELETE FROM admin_actions WHERE seq IS NULL"))
        db.commit()
    finally:
        db.close()
    r = _verify()
    assert r["ok"] is True and r["chained"] == 4 and r["unchained"] == 0


# ── 8 · the canonical form survives the round trip ─────────────────────────

def test_a_realistic_detail_payload_round_trips_through_jsonb(make_staff):
    """detail is JSONB — key order is not preserved, so the canonical form has
    to be order-independent. Driven with the shapes the 42 call sites actually
    use, plus the ones most likely to move a hash."""
    s = make_staff()
    nasty = {
        "zeta": "last by name, first by nothing",
        "alpha": 1,
        "nested": {"z": True, "a": [1, 2, {"k": None}]},
        "unicode": "naïve — ✓ 日本語",
        "float": 0.25,
        "empty": {},
        "list": [],
        "false": False,
        "null": None,
    }
    db = SessionLocal()
    try:
        record_admin_action(db, _staff(db, s["id"]), "test.detail", detail=nasty)
        db.commit()
    finally:
        db.close()

    r = _verify()
    assert r["ok"] is True, f"a detail payload broke the round trip: {r}"
    assert _rows()[0].detail == nasty


def test_the_chain_verifies_when_the_database_session_is_not_utc(make_staff):
    """⚠ timestamptz COMES BACK IN THE SESSION TIMEZONE.

    Nothing pins TimeZone in this project (#123), so a deployment whose cluster
    sits west of UTC hands the verifier a different ISO string for the same
    instant than the writer serialised. compute_admin_chain_hash normalises to
    UTC for exactly this reason; without it every chain breaks off-UTC.
    """
    s = make_staff()
    _write(s["id"], n=4)

    for zone in ("America/Los_Angeles", "Asia/Karachi", "UTC"):
        db = SessionLocal()
        try:
            db.execute(text(f"SET TIME ZONE '{zone}'"))
            r = verify_admin_chain(db)
        finally:
            db.close()
        assert r["ok"] is True, f"the chain does not verify under {zone}: {r}"


# ── 9 · through a real route, not just the primitive ───────────────────────

def test_a_real_audited_route_chains_its_action(make_staff, staff_login, make_org):
    """Exercising the writer does not guard its 42 callers. This one goes over
    HTTP: suspend a tenant, then verify the chain the route wrote."""
    org = make_org()
    s = make_staff()
    c = staff_login(s["email"], s["password"])
    r = c.post(f"/admin/v1/organizations/{org['org_id']}/suspend",
               json={"reason": "chained by a route, not by the helper"})
    assert r.status_code == 200, r.text

    v = _verify()
    assert v["ok"] is True, v
    # ⚠ NAME THE ROUTE'S OWN ROW. staff_login grants a step-up, which is itself
    # audited — so "the chain is non-empty" would have passed with the suspend
    # deleted, and did on the first run of this test.
    written = [x for x in _rows() if x.action == "org.suspend"]
    assert len(written) == 1, "the route's own action is not in the chain"
    assert written[0].seq is not None and written[0].chain_hash


def test_the_chain_endpoint_reports_the_state_and_is_staff_gated(
        make_staff, staff_login, client, make_org):
    assert client.get("/admin/v1/audit/chain").status_code == 401

    org = make_org()
    s = make_staff()
    c = staff_login(s["email"], s["password"])
    assert c.post(f"/admin/v1/organizations/{org['org_id']}/suspend",
                  json={"reason": "x"}).status_code == 200

    # ── the DEFAULT: coverage, and explicitly not a verdict ──────────────
    d = c.get("/admin/v1/audit/chain").json()
    assert d["checked"] is False
    assert d["ok"] is None, (
        "arriving on the audit page returned a verdict without recomputing "
        "anything — the console would paint an unchecked chain as a clean one")
    assert d["chained"] >= 1 and d["unchained"] == 0
    assert d["head_hash"] and len(d["head_hash"]) == 64
    assert d["started_at"]

    # ── ?verify=1: the recompute, and the only place ok is a verdict ─────
    d = c.get("/admin/v1/audit/chain?verify=1").json()
    assert d["checked"] is True and d["ok"] is True
    assert d["detail"] == "sequence unbroken"
    assert d["head_hash"] and len(d["head_hash"]) == 64

    # and the list carries seq, so the console can name the entry a break points at
    items = c.get("/admin/v1/audit").json()["items"]
    assert items and items[0]["seq"] is not None


def test_the_chain_endpoint_reports_a_break_without_pretending_it_is_clean(
        make_staff, staff_login):
    s = make_staff()
    _write(s["id"], n=4)
    db = SessionLocal()
    try:
        db.execute(text("DELETE FROM admin_actions WHERE seq = 2"))
        db.commit()
    finally:
        db.close()

    c = staff_login(s["email"], s["password"])
    # coverage alone cannot see the break, and does not pretend to
    cov = c.get("/admin/v1/audit/chain").json()
    assert cov["ok"] is None and cov["checked"] is False

    d = c.get("/admin/v1/audit/chain?verify=1").json()
    assert d["ok"] is False
    assert d["first_broken_seq"] == 2, d          # the missing entry, not its neighbour
    assert d["kind"] == "missing" and "entry 2 is missing" in d["detail"], d
    assert d["head_hash"] is None


# ── 10 · the unique index is the second line of defence ────────────────────

def test_a_duplicate_seq_cannot_be_written_even_bypassing_the_helper(make_staff):
    """The advisory lock serialises the helper. The unique index is what stops a
    fork written by anything else — a loud IntegrityError instead of two rows
    silently claiming the same position."""
    import sqlalchemy.exc

    s = make_staff()
    _write(s["id"], n=2)
    db = SessionLocal()
    try:
        with pytest.raises(sqlalchemy.exc.IntegrityError):
            db.execute(text(
                "INSERT INTO admin_actions (id, staff_user_id, action, seq, created_at) "
                "VALUES (:id, :sid, 'test.fork', 2, now())"),
                {"id": uuid.uuid4(), "sid": uuid.UUID(s["id"])})
        db.rollback()
    finally:
        db.close()


#: Primitives that make a transaction long. Narrow ON PURPOSE: the first
#: version included `get`, `post` and `request`, and dict.get / db.get /
#: headers.get collide with the network ones by name alone. A marker that
#: matches everything measures nothing.
_SLOW_PRIMITIVES = {
    "wait_for_transaction_receipt", "send_raw_transaction", "get_balance",
    "send_email", "urlopen", "sleep",
    # a second lock is a wait on somebody else, which is the same problem
    "with_for_update", "pg_advisory_xact_lock",
}

#: ⚠ SEEDED BY HAND, WITH THE REASON. anchor_org reaches the 180s receipt wait
#: through `_PROVIDERS[settings.anchor_provider](root, settings)` — a dict
#: lookup and a variable call. No name-based scan can follow that, so the
#: closure below stops and would report reanchor clean. Naming it here is the
#: guard admitting its blind spot rather than hiding it.
_SLOW_SEED = {"anchor_org", "anchor_all_due", "run_provider",
              "run_validated_provider"}


def _slow_function_names(app_dir):
    """Every function in app/ that does slow work, to a fixed point.

    Round 0: a function whose body names a slow primitive, or contains a loop
    with a database call in it (a fan-out — notify.broadcast inserts one row
    per active staff member). Later rounds add anything that calls one.
    """
    import ast

    bodies = {}
    for path in sorted(app_dir.rglob("*.py")):
        try:
            tree = ast.parse(path.read_text(encoding="utf-8"))
        except SyntaxError:                       # pragma: no cover
            continue
        for node in ast.walk(tree):
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                bodies[node.name] = node

    def called_names(node):
        return {getattr(c.func, "attr", getattr(c.func, "id", ""))
                for c in ast.walk(node) if isinstance(c, ast.Call)}

    def loops_over_db(node):
        for sub in ast.walk(node):
            if not isinstance(sub, (ast.For, ast.AsyncFor, ast.While)):
                continue
            for inner in ast.walk(sub):
                if (isinstance(inner, ast.Call)
                        and isinstance(inner.func, ast.Attribute)
                        and isinstance(inner.func.value, ast.Name)
                        and inner.func.value.id == "db"):
                    return True
        return False

    slow = set(_SLOW_SEED)
    for name, node in bodies.items():
        if called_names(node) & _SLOW_PRIMITIVES or loops_over_db(node):
            slow.add(name)
    for _ in range(8):                            # fixed point, bounded
        grew = False
        for name, node in bodies.items():
            if name not in slow and called_names(node) & slow:
                slow.add(name)
                grew = True
        if not grew:
            break
    return slow


def _work_after_recording(app_dir, slow):
    """Calls that sit between a record_admin_action and the transaction's end."""
    import ast

    out, recorded = [], 0
    for path in sorted(app_dir.rglob("*.py")):
        src = path.read_text(encoding="utf-8")
        if "record_admin_action" not in src:
            continue
        for node in ast.walk(ast.parse(src)):
            if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                continue
            calls = [c for c in ast.walk(node) if isinstance(c, ast.Call)]
            recs = [c for c in calls
                    if getattr(c.func, "attr", getattr(c.func, "id", "")) == "record_admin_action"]
            if not recs:
                continue
            recorded += len(recs)
            rec = min(recs, key=lambda c: c.lineno)
            # ARGUMENTS ARE NOT "AFTER". client_ip(request) is evaluated to
            # build the record call, and on a wrapped call its lineno is
            # greater than the record's — 40 false positives in the first pass.
            inside = {id(c) for c in ast.walk(rec)}
            # THE WINDOW ENDS AT THE TRANSACTION. Work after commit/rollback
            # holds no lock: admin_billing sends its credentials email there.
            ends = [c.lineno for c in calls
                    if getattr(c.func, "attr", "") in ("commit", "rollback")
                    and c.lineno > (rec.end_lineno or rec.lineno)]
            close = min(ends) if ends else 10 ** 9
            for c in calls:
                if id(c) in inside or c.lineno <= (rec.end_lineno or rec.lineno):
                    continue
                if c.lineno >= close:
                    continue
                name = getattr(c.func, "attr", getattr(c.func, "id", ""))
                if name in slow or name in _SLOW_PRIMITIVES:
                    out.append(f"{path.name}:{c.lineno} {node.name}() -> {name}()")
    return out, recorded


def test_no_route_does_slow_work_after_recording_an_action():
    """⚠ THE CHAIN LOCK LIVES AS LONG AS THE CALLER'S TRANSACTION.

    G5's version looked for a ROW LOCK taken after recording, on the theory
    that a lock-order inversion was the risk. It was aimed at the wrong thing
    and passed while admin_anchors.reanchor held the platform-wide chain lock
    across anchor.py's wait_for_transaction_receipt(timeout=180) — every staff
    action and every staff sign-in queued behind one re-anchor for minutes.

    So it looks for WORK now: a network call, a fan-out loop, a second lock, or
    a call to anything that transitively reaches one, between the record and
    the commit.

    ⚠ WHAT THIS CAN SEE
      · a slow primitive called directly in the same function
      · a loop containing a `db.` call
      · a call to any app/ function reaching one of those through plain named
        calls, to a fixed point. That includes the helper-held lock case:
        user_notifications.record_upgrade_request takes FOR UPDATE, so its
        callers are classed slow without naming them here

    ⚠ WHAT IT CANNOT SEE, and no literal scan can
      · dispatch through a registry or a variable — anchor.py's
        `_PROVIDERS[provider](root, settings)` is exactly that, which is why
        _SLOW_SEED names anchor_org by hand
      · getattr / dynamic attribute calls
      · NAME COLLISIONS, in both directions, AND ONE ALREADY BIT. Functions
        are keyed by bare name across the whole package. `notify.broadcast`
        resolved to admin_config.broadcast — a ROUTE that sends email — so this
        guard reported three fan-out sites as slow for a reason that was not
        true of the function it meant. notify.broadcast stages rows with
        db.add and its module contains no commit at all. The moves those
        findings prompted are still small improvements (they relocate one
        SELECT) and the comments at those sites now say so; the guard's reason
        was wrong
      · STAGED-THEN-FLUSHED WORK, which is most of what a route does. db.add
        and db.delete only mark the session; the INSERT or DELETE executes at
        the commit flush, inside the lock window wherever the statement sits.
        So a fan-out of N db.adds after a record is invisible here — correctly,
        because moving it would change nothing
      · anything slow that is not a call — a large in-memory loop, a regex over
        a big document
      · ⚠ AND THE ONE THAT MATTERS MOST: a mutation STAGED before the record
        still executes at the COMMIT FLUSH, inside the lock's window. Only work
        that runs immediately — a query, a network call — actually moves when
        you reorder it. admin_data.delete_row reads like a violation for that
        reason and is not one, and no reordering there would buy anything.

    A floor, not a proof. The property is stated in record_admin_action's
    docstring: the caller must commit soon.
    """
    import pathlib

    app_dir = pathlib.Path(__file__).resolve().parents[2] / "app"
    slow = _slow_function_names(app_dir)

    # ⚠ THIS USED TO ASSERT `"broadcast" in slow` AND WAS TRUE FOR THE WRONG
    # REASON — bare-name collision with admin_config.broadcast, a route that
    # sends email. A self-check that passes via the bug it is meant to exclude
    # is worse than none. issue_reset is unambiguous: one definition, and it
    # sends a password-reset email.
    assert "issue_reset" in slow, (
        "the closure no longer reaches issue_reset, which sends an email — so "
        "the email primitive or the closure has stopped working and this guard "
        "measures nothing")
    assert "anchor_org" in slow, "the hand-seeded blind spot fell out"
    assert "client_ip" not in slow, (
        "client_ip is classed slow again — it reads a request header. The "
        "first version had it, via `get`, and reported 40 phantom offenders")

    offenders, recorded = _work_after_recording(app_dir, slow)
    assert recorded >= 40, (
        f"only {recorded} record_admin_action call sites found — this guard "
        f"walks the app package, and finding almost none means it is walking "
        f"the wrong directory and proving nothing")
    assert not offenders, (
        "these call sites do slow work between staging an audit action and "
        "committing it. The platform chain lock is transaction-scoped, so "
        "every other staff action and every staff sign-in waits that long: %s"
        % offenders)


def test_the_model_never_serializes_a_secret(make_staff, staff_login, make_org):
    """The audit row now carries hashes. None of them is a credential, and the
    response must not have acquired one along the way."""
    org = make_org()
    s = make_staff()
    c = staff_login(s["email"], s["password"])
    assert c.post(f"/admin/v1/organizations/{org['org_id']}/suspend",
                  json={"reason": "x"}).status_code == 200
    body = c.get("/admin/v1/audit").text + c.get("/admin/v1/audit/chain").text
    for banned in ("password_hash", "key_hash", "token_hash", "_key_enc"):
        assert banned not in body, f"{banned} leaked into an audit response"


def test_every_admin_action_column_is_bound_by_the_hash(make_staff):
    """⚠ A CENSUS, so a column added to AdminAction later cannot quietly sit
    OUTSIDE the chain. Every column except the primary key and the three chain
    columns themselves must appear in the hashed payload; a new one fails here
    until it is either hashed or explicitly listed as deliberately excluded.
    """
    import inspect

    from app import admin_chain

    hashed = set(inspect.signature(admin_chain.compute_admin_chain_hash).parameters)
    # id: a random uuid4 with no meaning; the position IS seq. chain_hash cannot
    # be inside its own digest. prev_hash is not excluded — it IS bound, as the
    # suffix the digest is taken over.
    excluded = {"id", "chain_hash"}
    columns = {c.name for c in AdminAction.__table__.columns}
    unbound = columns - hashed - excluded
    assert not unbound, (
        f"{sorted(unbound)} is stored on admin_actions but not bound by the "
        f"chain — it could be edited without breaking a recompute")
