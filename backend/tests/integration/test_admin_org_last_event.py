"""G3 · #71 · `last_event_at` on the organisations list row.

The list had eleven fields describing what a workspace IS — plan, subscription,
access, contact, quota, usage — and not one that answers "is something wrong
with it". This adds the one operational fact the ledger gives for free: when we
last heard from the tenant.

What matters is not that a timestamp comes back, but that:

  * NULL means NEVER CAPTURED and is distinguishable from a quiet workspace,
    because the console draws two different states from that difference;
  * it is the MAX and not the first or the newest-of-some-window;
  * it is UTC, like every other date boundary on this platform;
  * and the whole list still costs ONE query, not one per tenant — the list is
    unpaginated server-side, so a per-org MAX would be one query per tenant
    against the busiest table on the platform.

Run with DATABASE_URL pointing at :5433/foxy_pytest — conftest defaults to 5432
and its preflight will tell you so.
"""
from __future__ import annotations

import hashlib
import uuid
from datetime import datetime, timedelta, timezone

from sqlalchemy import text

from app.db import SessionLocal

URL = "/admin/v1/organizations"


def _seed_at(oid, at, seq0=0, n=1):
    """n ledger rows at a fixed instant, in one statement."""
    db = SessionLocal()
    try:
        db.execute(text(
            "INSERT INTO audit_logs (id, org_id, seq, prompt_hash, response_hash,"
            " token_count, policy_tag, prev_hash, chain_hash, agent, grading_status,"
            " created_at) SELECT gen_random_uuid(), :oid, :seq0 + g,"
            " md5(g::text)||md5(g::text), md5(g::text)||md5(g::text), 5, 'test',"
            " md5(g::text)||md5(g::text), md5(g::text)||md5(g::text), 'agent-x',"
            " 'graded', :at FROM generate_series(1, :n) g"),
            {"oid": oid, "at": at, "seq0": seq0, "n": n})
        db.commit()
    finally:
        db.close()


def _row(client, org_id):
    rows = client.get(URL).json()
    match = [r for r in rows if r["id"] == str(org_id)]
    assert match, "org %s is not in the list" % org_id
    return match[0]


def test_a_workspace_that_never_captured_reports_null_not_a_zero(
        make_staff, staff_login, make_org):
    """THE STATE THE COLUMN EXISTS FOR. "has never captured anything" and "has
    been quiet a while" are different operational facts and the console renders
    them differently — one is a brand-new workspace mid-integration, the other
    is a tenant whose capture has stopped. An epoch, a zero or the org's own
    created_at here would collapse them into one, and the console would have no
    way back to the distinction."""
    org = make_org()
    s = make_staff()
    c = staff_login(s["email"], s["password"])
    r = _row(c, org["org_id"])
    assert "last_event_at" in r, "the field is not on the list row at all"
    assert r["last_event_at"] is None, (
        "a workspace with an empty ledger reported %r; the console cannot tell "
        "'never captured' from 'quiet' any more" % r["last_event_at"])


def test_the_field_reports_the_newest_event_not_the_first(
        make_staff, staff_login, make_org):
    """MAX, not MIN and not "some row". A first-event timestamp would make every
    long-running tenant look abandoned — the exact inversion of what this column
    is for."""
    org = make_org()
    oid = uuid.UUID(str(org["org_id"]))
    now = datetime.now(timezone.utc)
    old = now - timedelta(days=400)
    mid = now - timedelta(days=90)
    new = now - timedelta(days=3)
    _seed_at(oid, old, seq0=0, n=5)
    _seed_at(oid, new, seq0=10, n=1)      # newest written in the MIDDLE of the
    _seed_at(oid, mid, seq0=20, n=5)      # insert order, so seq order != time order
    s = make_staff()
    c = staff_login(s["email"], s["password"])
    got = datetime.fromisoformat(_row(c, org["org_id"])["last_event_at"])
    assert abs((got - new).total_seconds()) < 2, (
        "reported %s, expected the newest event at %s" % (got, new))


def test_the_timestamp_is_utc_like_every_other_boundary_here(
        make_staff, staff_login, make_org):
    """F4 pinned three day-boundary bugs on this platform and every one of them
    was a timestamp resolved in somebody's session timezone. A naive string
    here would be read by the console as local and could shift a tenant's
    dormancy by a day at either end of the world."""
    org = make_org()
    at = datetime(2026, 3, 1, 23, 30, tzinfo=timezone.utc)
    _seed_at(uuid.UUID(str(org["org_id"])), at)
    s = make_staff()
    c = staff_login(s["email"], s["password"])
    raw = _row(c, org["org_id"])["last_event_at"]
    parsed = datetime.fromisoformat(raw)
    assert parsed.tzinfo is not None, (
        "the timestamp carries no offset, so the console reads it as local: " + raw)
    assert parsed.astimezone(timezone.utc) == at, (
        "%s did not round-trip to %s" % (raw, at))


def test_the_field_is_not_confined_to_this_month(
        make_staff, staff_login, make_org):
    """The neighbouring `usage_this_month` IS month-to-date, and reusing its
    predicate here would report NULL for every tenant that has been quiet since
    the 1st — turning the dormancy column into a column that can only ever say
    "recent" or "never"."""
    org = make_org()
    at = datetime.now(timezone.utc) - timedelta(days=200)
    _seed_at(uuid.UUID(str(org["org_id"])), at)
    s = make_staff()
    c = staff_login(s["email"], s["password"])
    r = _row(c, org["org_id"])
    assert r["usage_this_month"] == 0, "the fixture leaked into this month"
    assert r["last_event_at"] is not None, (
        "a 200-day-old event reported as never captured — the field inherited "
        "the month filter from the column beside it")


def test_the_whole_list_costs_one_last_event_query(
        make_staff, staff_login, make_org):
    """N+1 IS THE FAILURE MODE, and it is not hypothetical: the obvious
    implementation is a MAX per row, and this list is unpaginated server-side.

    Counted by echo rather than by timing — a timing assertion is flaky and
    would not say what went wrong. The shape was chosen by measurement
    (EXPLAIN ANALYZE, 1.5M rows, 40 orgs): a correlated scalar driven from
    `organizations` runs 40 index-only seeks at 0.18-0.29ms, while
    `GROUP BY org_id` over audit_logs is a parallel seq scan at 132-137ms and
    never uses the index. Both are ONE statement; this guard is what keeps it
    one when somebody reaches for the obvious per-row version.
    """
    orgs = [make_org() for _ in range(4)]
    now = datetime.now(timezone.utc)
    for i, o in enumerate(orgs):
        _seed_at(uuid.UUID(str(o["org_id"])), now - timedelta(days=i + 1))
    s = make_staff()
    c = staff_login(s["email"], s["password"])

    seen = []
    from sqlalchemy import event
    from app.db import engine

    def _rec(conn, cursor, statement, params, context, executemany):
        low = statement.lower()
        if "audit_logs" in low and "max(" in low:
            seen.append(statement)

    event.listen(engine, "before_cursor_execute", _rec)
    try:
        rows = c.get(URL).json()
    finally:
        event.remove(engine, "before_cursor_execute", _rec)

    ours = {str(o["org_id"]) for o in orgs}
    assert len([r for r in rows if r["id"] in ours]) == 4
    assert len(seen) == 1, (
        "the list issued %d last-event queries for 4 tenants; it must not scale "
        "with the number of tenants: %s" % (len(seen), seen))
    # and it has to be the measured shape, not a grouped scan that happens to
    # also be one statement
    assert "group by" not in seen[0].lower(), (
        "the last-event query is a GROUP BY over the ledger — one statement, "
        "but a parallel seq scan of every event on the platform:\n" + seen[0])


def test_org_detail_still_answers_now_that_the_field_moved_up(
        make_staff, staff_login, make_org):
    """OrgDetail inherits OrgListItem. C3 shipped a TypeError on every
    org-detail read the last time a field moved onto the parent, so this is the
    same guard for the same reason."""
    org = make_org()
    _seed_at(uuid.UUID(str(org["org_id"])),
             datetime.now(timezone.utc) - timedelta(days=2))
    s = make_staff()
    c = staff_login(s["email"], s["password"])
    r = c.get(f"{URL}/{org['org_id']}")
    assert r.status_code == 200, r.text
    # the detail route does not compute it, so it must report the honest
    # default rather than a stale or invented value
    assert "last_event_at" in r.json()


def test_a_deleted_tenant_still_reports_its_last_event(
        make_staff, staff_login, make_org):
    """include_deleted exists so staff can audit an offboarded tenant, and "when
    did this workspace stop capturing" is exactly the question an offboarding
    review asks. A join that dropped soft-deleted orgs would answer it with
    silence."""
    org = make_org()
    oid = uuid.UUID(str(org["org_id"]))
    _seed_at(oid, datetime.now(timezone.utc) - timedelta(days=5))
    db = SessionLocal()
    try:
        db.execute(text("UPDATE organizations SET deleted_at = now() WHERE id = :i"),
                   {"i": oid})
        db.commit()
    finally:
        db.close()
    s = make_staff()
    c = staff_login(s["email"], s["password"])
    rows = c.get(URL + "?include_deleted=true").json()
    match = [r for r in rows if r["id"] == str(oid)]
    assert match, "the offboarded tenant is missing from the audited view"
    assert match[0]["deleted"] is True
    assert match[0]["last_event_at"] is not None, (
        "an offboarded tenant reports no last event, so an offboarding review "
        "cannot see when it went quiet")
