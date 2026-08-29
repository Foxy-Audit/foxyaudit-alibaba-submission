"""Register #272 — a non-UTC session zone must not make an honest ledger read as tampered.

THE DEFECT. `chain.compute_chain_hash` bound `occurred_at.isoformat()`, offset
included. At ingest that offset is the CLIENT's; on every later read PostgreSQL
renders the same `timestamptz` in the READING SESSION's `TimeZone`. One row, two
strings, two hashes — so `GET /v1/logs/export` handed a customer a file that
`verifier/foxy_verify.py` called BROKEN at seq 1 with nothing having been touched.
`verify_chain` and `anchor_org` refused the same chain for the same reason.
Nothing in this project pins the session zone (#123, deliberately), and the
developer's own cluster reports `Asia/Karachi`.

THE FIX IS A CHAIN VERSION, NOT A CONFIG PIN. From V5 the field is folded as the
UTC INSTANT it names, so the recompute no longer depends on where the reader
sits. V1-V4 keep folding the text verbatim, defect and all, because a row already
written must keep verifying forever — `verifier/test_verify.py::
test_only_v5_normalises_the_offset` is the guard on that half.

⚠ WHY NO EXISTING TEST SAW THIS. Not one of them sets `occurred_at`. NULL folds
to `null` in every timezone on earth, so the whole suite was green over the only
field that could not be. Every test here sets it, with an offset no reading
session used, and `test_the_seeded_rows_really_carry_occurred_at` refuses to let
that quietly stop being true.

⚠ AND THE CONTROL IS THE POINT. `test_the_same_journey_still_fails_at_v4` runs
this exact flow with ingest forced back to V4 and asserts it FAILS. Without it,
every assertion below would also pass on a build where `occurred_at` had simply
stopped being hashed.
"""

from __future__ import annotations

import hashlib
import importlib.util
import pathlib
import uuid
from datetime import datetime, timedelta, timezone

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import text

from app.db import SessionLocal, get_db
from app.main import app, customer_api

REPO_ROOT = pathlib.Path(__file__).resolve().parents[3]
REAL_VERIFIER = REPO_ROOT / "verifier" / "foxy_verify.py"

#: One zone each side of UTC plus UTC itself — the same three #123 uses. Karachi
#: is the developer's database, Los_Angeles is what CI runs.
ZONES = ("UTC", "America/Los_Angeles", "Asia/Karachi")

#: The offset the CLIENT sends. Deliberately +05:30, which is none of the three
#: zones above: if the client's own rendering happened to match a reader's, a
#: broken build would still pass for that reader.
CLIENT_TZ = timezone(timedelta(hours=5, minutes=30))


def _verifier():
    """Load the shipped script by path. Importing `app.chain` here would prove the
    export agrees with the writer, which is the one thing an independent verifier
    exists not to assume."""
    spec = importlib.util.spec_from_file_location("foxy_verify_272", REAL_VERIFIER)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _h(s: str) -> str:
    return hashlib.sha256(s.encode()).hexdigest()


@pytest.fixture
def in_zone():
    """Drive a request with its own DB session pinned to `zone`.

    Returns (client_factory, seen). `seen` records the zone each overridden
    session ACTUALLY reported, so a test can prove the override fired rather than
    assume it — F3 shipped an override on the wrong ASGI app and its guard passed
    while proving nothing (#123). The override goes on `customer_api`, not `app`:
    main.py is a three-ASGI split and `/v1/*` lives on the mounted child.
    """
    seen: list[str] = []

    def _client(zone: str) -> TestClient:
        def _db():
            db = SessionLocal()
            try:
                # SET takes no bind parameter; `zone` comes from ZONES and is
                # checked against it before interpolation. SET LOCAL, so a pooled
                # connection can never return to the pool carrying a foreign zone.
                assert zone in ZONES, zone
                db.execute(text(f"SET LOCAL TimeZone = '{zone}'"))
                seen.append(db.execute(text("SHOW TimeZone")).scalar_one())
                yield db
            finally:
                db.rollback()
                db.close()
        customer_api.dependency_overrides[get_db] = _db
        return TestClient(app)

    yield _client, seen
    customer_api.dependency_overrides.pop(get_db, None)


def _assert_probe_fired(seen: list[str], zone: str) -> None:
    assert seen, ("the dependency override never ran — the request used an "
                  "unpinned session and this assertion proves nothing")
    assert seen[-1] == zone, (
        "asked for %s, the request's session reported %s" % (zone, seen[-1]))


def _rows(org, n=3, *, aware=True, client_tz=None):
    """Ingest payloads with `occurred_at` set on every row.

    ⚠ THE NON-NULL PART IS THE TEST, NOT THE SETUP. A NULL `occurred_at` folds to
    `null` under every timezone, so a seed that left it out would let every
    assertion in this file pass over a build that had not been fixed at all.

    `client_tz` is the offset the CLIENT sends. It defaults to +05:30, which no
    reading session below uses — the V4 control overrides it, because a pre-V5 row
    was only ever verifiable by a session that rendered the client's own offset.
    """
    client_tz = client_tz or CLIENT_TZ
    base = datetime(2026, 7, 18, 9, 30, tzinfo=timezone.utc)
    out = []
    for i in range(1, n + 1):
        when = base + timedelta(minutes=i)
        out.append({
            "prompt_hash": _h(f"{org['org_id']}-p{i}"),
            "response_hash": _h(f"{org['org_id']}-r{i}"),
            "token_count": 10 * i + 5,
            "policy_tag": "hipaa_basic",
            "agent": "gpt-4o",
            "pii_signals": ["email"],
            "event_id": str(uuid.uuid4()),
            "client_id": "sdk-node-a",
            "client_seq": i,
            "event_type": "interaction",
            "commitment_alg": "hmac-sha256",
            "event_metadata": {"request_id": f"req-{i}", "provider": "openai"},
            "occurred_at": (when.astimezone(client_tz).isoformat() if aware
                            else when.replace(tzinfo=None).isoformat()),
        })
    return out


def _ingest(session_client, org, n=3, *, aware=True, client_tz=None):
    r = session_client.post("/v1/logs/batch",
                            json=_rows(org, n, aware=aware, client_tz=client_tz),
                            headers=org["auth"])
    assert r.status_code == 202, r.text
    return r


def _export(session_client, org):
    r = session_client.get("/v1/logs/export?format=json", headers=org["auth"])
    assert r.status_code == 200, r.text
    return r.json()


# ══ the premise ═════════════════════════════════════════════════════════════

def test_the_three_zones_really_do_render_the_row_differently(make_org, in_zone):
    """THE PREMISE, MEASURED IN THE DATABASE UNDER TEST. If the three sessions
    rendered `occurred_at` identically there would be no skew to be independent
    of, and every guard below would pass for the wrong reason."""
    mk, seen = in_zone
    org = make_org()
    _ingest(mk("UTC"), org)

    rendered = {}
    for zone in ZONES:
        rendered[zone] = [r["occurred_at"] for r in _export(mk(zone), org)["logs"]]
        _assert_probe_fired(seen, zone)
    assert len({tuple(v) for v in rendered.values()}) == len(ZONES), (
        "the sessions all rendered the same text, so nothing here is being "
        "tested: %r" % rendered)


def test_the_seeded_rows_really_carry_occurred_at(make_org, in_zone):
    """⚠ ANTI-VACUITY. `occurred_at` is the ONLY field these tests are about, and
    a NULL one hashes identically everywhere. If the seed ever stops setting it,
    this file goes green while measuring nothing."""
    mk, _ = in_zone
    org = make_org()
    _ingest(mk("UTC"), org)
    rows = _export(mk("Asia/Karachi"), org)["logs"]
    assert len(rows) == 3
    for row in rows:
        assert row["occurred_at"], "a seeded row carries no occurred_at"


# ══ the fix ═════════════════════════════════════════════════════════════════

def test_new_rows_are_written_at_chain_version_5(make_org, in_zone):
    """EVERY new row, not only the ones carrying `occurred_at`. `chain_version` is
    itself hashed from V3 on, so a V4 and a V5 row with a NULL timestamp already
    differ — writing V4 for those would buy no byte-compatibility and would leave
    the ledger interleaving two versions on a rule enforced by nothing."""
    mk, _ = in_zone
    org = make_org()
    _ingest(mk("UTC"), org)
    for row in _export(mk("UTC"), org)["logs"]:
        assert row["chain_version"] == 5, row

    # ...including a row with no timestamp at all.
    plain = [dict(r) for r in _rows(org, 1)]
    plain[0].pop("occurred_at")
    plain[0]["event_id"] = str(uuid.uuid4())
    plain[0]["client_seq"] = 99
    assert mk("UTC").post("/v1/logs/batch", json=plain,
                          headers=org["auth"]).status_code == 202
    assert _export(mk("UTC"), org)["logs"][-1]["chain_version"] == 5


def test_an_export_verifies_in_every_session_zone(make_org, in_zone):
    """#272 IN ONE ASSERTION, ON THE DOCUMENTED PATH. Written by one session,
    exported by three others, recomputed from genesis by the standalone script
    with no Foxy code involved in the recompute."""
    mk, seen = in_zone
    org = make_org()
    _ingest(mk("UTC"), org)
    fv = _verifier()

    for zone in ZONES:
        body = _export(mk(zone), org)
        _assert_probe_fired(seen, zone)
        result = fv.verify_export(body)
        assert result["ok"] is True, (
            "an untouched ledger read as tampered when exported under %s: %s"
            % (zone, result["detail"]))
        assert result["refused"] is False
        assert result["count"] == 3


def test_the_export_is_still_tamper_evident_across_zones(make_org, in_zone):
    """⚠ THE FIX MUST NOT BE 'STOP HASHING IT'. V5 normalises the RENDERING, not
    the instant: move the moment and the chain still breaks."""
    mk, _ = in_zone
    org = make_org()
    _ingest(mk("UTC"), org)
    body = _export(mk("Asia/Karachi"), org)
    fv = _verifier()

    moved = datetime.fromisoformat(body["logs"][1]["occurred_at"]) + timedelta(seconds=1)
    body["logs"][1]["occurred_at"] = moved.isoformat()
    result = fv.verify_export(body)
    assert result["ok"] is False, "a rewritten occurred_at went unnoticed"
    assert result["first_broken_seq"] == 2


def test_the_internal_recompute_agrees_across_zones(make_org, in_zone):
    """`GET /v1/verify` is the second implementation of the same recompute — the
    one the dashboard renders and the one `anchor_org` shares. It reads the stored
    `datetime`, where the verifier reads the exported string, so it can fail while
    the export passes."""
    mk, seen = in_zone
    org = make_org()
    _ingest(mk("UTC"), org)
    for zone in ZONES:
        body = mk(zone).get("/v1/verify", headers=org["auth"]).json()
        _assert_probe_fired(seen, zone)
        assert body["ok"] is True, (
            "the server called its own chain broken under %s: %s" % (zone, body))
        assert body["count"] == 3, body


def test_an_offsetless_occurred_at_is_hashed_as_the_instant_it_is_stored_at(
        make_org, in_zone):
    """A naive timestamp names no instant. `schemas.LogIngest` attaches UTC before
    it is hashed OR stored, so the moment written and the moment read back are the
    same one. Without that the row would hash against the client's wall clock and
    be stored at whatever PostgreSQL's session zone made of it — unverifiable from
    the first read, on any server not sitting at UTC."""
    mk, _ = in_zone
    org = make_org()
    _ingest(mk("Asia/Karachi"), org, 2, aware=False)
    fv = _verifier()
    for zone in ZONES:
        body = _export(mk(zone), org)
        assert fv.verify_export(body)["ok"] is True, zone
    # and the stored instant is the naive wall clock read as UTC, not as Karachi
    stored = datetime.fromisoformat(_export(mk("UTC"), org)["logs"][0]["occurred_at"])
    assert stored == datetime(2026, 7, 18, 9, 31, tzinfo=timezone.utc), stored


def test_an_offsetless_retry_is_a_duplicate_not_a_conflict(make_org, in_zone):
    """Falling out of the same fix: the idempotency check pits the submitted value
    against the aware one the database returns, and a naive datetime compares
    unequal to every aware one. An honest retry of a naive-timestamped event used
    to be rejected as a 409."""
    mk, _ = in_zone
    org = make_org()
    rows = _rows(org, 1, aware=False)
    assert mk("UTC").post("/v1/logs/batch", json=rows,
                          headers=org["auth"]).status_code == 202
    again = mk("Asia/Karachi").post("/v1/logs/batch", json=rows, headers=org["auth"])
    assert again.status_code == 202, again.text
    assert again.json()["receipts"][0]["status"] == "duplicate", again.text


# ══ the control: this file can fail ═════════════════════════════════════════

def test_the_same_journey_still_fails_at_v4(make_org, in_zone, monkeypatch):
    """⚠ THE ANTI-VACUITY GUARD FOR THE WHOLE FILE, AND THE MEASUREMENT THE
    REGISTER ENTRY RECORDS.

    Force ingest back to V4 and run the identical flow. It MUST fail — that is
    #272, reproduced. If this ever passes, either the defect was never there or
    something above stopped hashing `occurred_at`, and every other assertion in
    this file has been decorative.

    A mutant that skips the V5 normalisation dies on the tests above; a mutant
    that applies it at every version dies here.
    """
    from app.routers import logs as logs_router

    mk, _ = in_zone
    monkeypatch.setattr(logs_router, "CHAIN_VERSION_UTC_V5", 4)
    org = make_org()
    # ⚠ THE CLIENT MUST SEND THE OFFSET THE READING SESSION RENDERS. A pre-V5 row
    # was only ever verifiable by a session whose zone happened to match the text
    # the client sent — which is the defect stated from the other side, and which
    # is why the seed's ordinary +05:30 would fail here for a SECOND reason and
    # make the control prove less than it claims.
    _ingest(mk("UTC"), org, client_tz=timezone.utc)

    body = _export(mk("UTC"), org)
    assert body["logs"][0]["chain_version"] == 4, "the monkeypatch did not take"

    fv = _verifier()
    assert fv.verify_export(body)["ok"] is True, (
        "a V4 row must still verify for the session that wrote it — otherwise "
        "this control is measuring a different failure")

    skewed = _export(mk("Asia/Karachi"), org)
    result = fv.verify_export(skewed)
    assert result["ok"] is False, (
        "#272 did not reproduce at V4, so nothing above proves it was fixed")
    assert result["first_broken_seq"] == 1
