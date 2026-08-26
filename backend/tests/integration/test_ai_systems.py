"""The declared AI-system inventory — /v1/systems (R1).

R1 builds the inventory ONLY. Nothing sends or stores an attribution yet; that
is R2 (the backend accepts `system_id`) and R3 (the SDK sends it). So there is
deliberately nothing here about `event_metadata`.

The five guards these tests exist for, and each is re-broken rather than assumed:

  * a member/SDK credential READS but cannot create, update or retire
  * a retired system still lists and still gets, flagged retired
  * two orgs may each hold a system named "support-bot"; one org may not
  * deleting the creating user leaves the system standing
  * one tenant's UUID is a 404 to another, not a 403 (no existence oracle)

⚠ Every permission test first proves the credential it is testing is LIVE — a
member client that can read, a Bearer key that can read — before asserting the
write is refused. A 401/403 from a client that was never authenticated at all is
the shape that has cost this repo real coverage.
"""

from __future__ import annotations

import uuid

import pytest
from sqlalchemy import text

from app.db import SessionLocal
from app.models import AiSystem, User


def _payload(name: str = "mortgage-bot", **over):
    body = {
        "name": name,
        "purpose": "Answers mortgage eligibility questions for retail customers",
        "provider": "openai",
        "model_name": "gpt-5.6",
        "environment": "production",
        "data_classification": "regulated",
        "risk_tier": "high",
    }
    body.update(over)
    return body


@pytest.fixture
def admin(make_org, login):
    """(org dict, an admin TestClient) — the only credential that may write."""
    org = make_org()
    return org, login(org["admin_email"], org["admin_password"])


# ───────────────────────────── the happy path ────────────────────────────────

def test_an_admin_declares_a_system_and_it_comes_back_whole(admin):
    org, client = admin
    r = client.post("/v1/systems", json=_payload())
    assert r.status_code == 201, r.text
    body = r.json()
    assert body["name"] == "mortgage-bot"
    assert body["purpose"].startswith("Answers mortgage")
    assert body["provider"] == "openai"
    assert body["model_name"] == "gpt-5.6"
    assert body["environment"] == "production"
    assert body["data_classification"] == "regulated"
    assert body["risk_tier"] == "high"
    assert body["lifecycle_status"] == "active"
    assert body["retired"] is False
    # owner_email defaults to the declaring admin — accountability with nobody's
    # name on it is not accountability.
    assert body["owner_email"] == org["admin_email"].lower()
    uuid.UUID(body["id"])                       # a real UUID, not an int id

    got = client.get(f"/v1/systems/{body['id']}")
    assert got.status_code == 200
    assert got.json() == body


def test_an_update_rewrites_the_declaration_and_leaves_the_id_alone(admin):
    _, client = admin
    created = client.post("/v1/systems", json=_payload()).json()
    r = client.put(f"/v1/systems/{created['id']}",
                   json={"risk_tier": "critical", "owner_email": "Risk@Bank.EXAMPLE"})
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["id"] == created["id"]          # evidence keeps pointing at it
    assert body["risk_tier"] == "critical"
    assert body["owner_email"] == "risk@bank.example"
    assert body["purpose"] == created["purpose"], "an omitted field was reset"


def test_an_empty_update_is_refused_rather_than_silently_doing_nothing(admin):
    _, client = admin
    created = client.post("/v1/systems", json=_payload()).json()
    assert client.put(f"/v1/systems/{created['id']}", json={}).status_code == 422


def test_an_explicit_null_cannot_blank_a_required_field(admin):
    """Every field is Optional so omitting it means "leave it alone" — which makes
    an explicit null look identical to a default at the type level, and would NULL
    a NOT NULL column."""
    _, client = admin
    created = client.post("/v1/systems", json=_payload()).json()
    r = client.put(f"/v1/systems/{created['id']}", json={"purpose": None})
    assert r.status_code == 422, r.text
    assert client.get(f"/v1/systems/{created['id']}").json()["purpose"] \
        == created["purpose"]


def test_the_inventory_is_empty_before_anything_is_declared(admin):
    """An honest empty state, not a seeded example. Nothing infers a system from
    traffic, so a customer who has declared nothing has nothing."""
    _, client = admin
    r = client.get("/v1/systems")
    assert r.status_code == 200
    assert r.json() == []


# ───────────────────── guard 1 · who may write, who may read ─────────────────

def test_a_member_may_read_the_inventory_but_may_not_write_to_it(admin, add_user, login):
    org, admin_client = admin
    created = admin_client.post("/v1/systems", json=_payload()).json()
    add_user(org["org_id"], "member@test.dev", "memberpass123", role="member")
    member = login("member@test.dev", "memberpass123")

    # THE CREDENTIAL IS LIVE — this is what makes the 403s below mean something.
    listed = member.get("/v1/systems")
    assert listed.status_code == 200, listed.text
    assert [s["id"] for s in listed.json()] == [created["id"]]
    assert member.get(f"/v1/systems/{created['id']}").status_code == 200

    assert member.post("/v1/systems", json=_payload("second-bot")).status_code == 403
    assert member.put(f"/v1/systems/{created['id']}",
                      json={"risk_tier": "low"}).status_code == 403
    assert member.post(f"/v1/systems/{created['id']}/retire").status_code == 403

    # and nothing changed
    after = admin_client.get(f"/v1/systems/{created['id']}").json()
    assert after == created
    assert len(admin_client.get("/v1/systems").json()) == 1


def test_the_sdk_bearer_key_may_read_the_inventory_but_may_not_write_to_it(admin):
    """R3 will want the SDK to check an id before sending it, so reads take the
    machine key. Declaring a system is a governance act by a named human, and
    `created_by` has to name someone — so writes never do."""
    org, admin_client = admin
    created = admin_client.post("/v1/systems", json=_payload()).json()
    auth = org["auth"]

    from fastapi.testclient import TestClient

    from app.main import app
    sdk = TestClient(app)                       # its own cookie jar: no session

    # THE KEY IS LIVE.
    listed = sdk.get("/v1/systems", headers=auth)
    assert listed.status_code == 200, listed.text
    assert [s["id"] for s in listed.json()] == [created["id"]]
    assert sdk.get(f"/v1/systems/{created['id']}", headers=auth).status_code == 200

    # A Bearer request carries no session cookie, so CSRF is skipped and the
    # refusal below comes from require_role, which is the thing under test.
    assert sdk.post("/v1/systems", json=_payload("sdk-bot"),
                    headers=auth).status_code == 401
    assert sdk.put(f"/v1/systems/{created['id']}", json={"risk_tier": "low"},
                   headers=auth).status_code == 401
    assert sdk.post(f"/v1/systems/{created['id']}/retire",
                    headers=auth).status_code == 401
    assert len(admin_client.get("/v1/systems").json()) == 1


def test_no_credential_at_all_reads_nothing(client, admin):
    _, admin_client = admin
    created = admin_client.post("/v1/systems", json=_payload()).json()
    assert client.get("/v1/systems").status_code == 401
    assert client.get(f"/v1/systems/{created['id']}").status_code == 401


def test_there_is_no_delete_endpoint_and_none_may_be_added(admin):
    """Retire is the only removal. A DELETE would orphan chained evidence: the
    hash chain has already committed to the id and cannot be edited to forget
    it, so the row would be gone while the evidence pointing at it remained."""
    import inspect

    from app.routers import systems

    _, client = admin
    created = client.post("/v1/systems", json=_payload()).json()
    assert client.delete(f"/v1/systems/{created['id']}").status_code == 405

    src = inspect.getsource(systems)
    assert "router.delete" not in src, "a DELETE endpoint appeared on the registry"
    assert "NO DELETE ENDPOINT" in systems.__doc__, (
        "the docstring that tells the next author not to add one is gone")


# ───────────────────── guard 2 · retire, never delete ────────────────────────

def test_a_retired_system_still_lists_and_still_gets_and_is_flagged(admin):
    """An inventory that hides what was retired cannot answer "what were you
    running last March", which is the question the evidence exists for."""
    _, client = admin
    created = client.post("/v1/systems", json=_payload()).json()

    r = client.post(f"/v1/systems/{created['id']}/retire")
    assert r.status_code == 200, r.text
    assert r.json()["lifecycle_status"] == "retired"
    assert r.json()["retired"] is True

    listed = client.get("/v1/systems").json()
    assert [s["id"] for s in listed] == [created["id"]], "retirement removed the row"
    assert listed[0]["retired"] is True
    got = client.get(f"/v1/systems/{created['id']}").json()
    assert got["retired"] is True and got["lifecycle_status"] == "retired"

    with SessionLocal() as db:
        assert db.get(AiSystem, uuid.UUID(created["id"])) is not None


def test_retiring_twice_is_idempotent_and_records_one_governance_action(admin):
    org, client = admin
    created = client.post("/v1/systems", json=_payload()).json()
    first = client.post(f"/v1/systems/{created['id']}/retire").json()
    second = client.post(f"/v1/systems/{created['id']}/retire").json()
    assert second["retired"] is True
    assert second["lifecycle_status"] == first["lifecycle_status"]

    audit = client.get("/v1/account/audit")
    assert audit.status_code == 200, audit.text
    actions = [a["action"] for a in audit.json()]
    assert actions.count("system.retire") == 1, actions


# ─────────────── guard 3 · names are unique per ORG, not globally ────────────

def test_two_orgs_may_each_run_a_support_bot_but_one_org_may_not(make_org, login):
    """A global unique constraint would be a cross-tenant existence oracle
    reported as a 409."""
    a, b = make_org(), make_org()
    ca = login(a["admin_email"], a["admin_password"])
    cb = login(b["admin_email"], b["admin_password"])

    assert ca.post("/v1/systems", json=_payload("support-bot")).status_code == 201
    assert cb.post("/v1/systems", json=_payload("support-bot")).status_code == 201

    dup = ca.post("/v1/systems", json=_payload("support-bot"))
    assert dup.status_code == 409, dup.text

    # and each org sees exactly its own one
    assert len(ca.get("/v1/systems").json()) == 1
    assert len(cb.get("/v1/systems").json()) == 1


def test_a_rename_onto_a_sibling_name_is_refused_but_onto_its_own_is_not(admin):
    _, client = admin
    one = client.post("/v1/systems", json=_payload("bot-one")).json()
    two = client.post("/v1/systems", json=_payload("bot-two")).json()
    assert client.put(f"/v1/systems/{two['id']}",
                      json={"name": "bot-one"}).status_code == 409
    # renaming a system to the name it already has must not collide with itself
    assert client.put(f"/v1/systems/{one['id']}",
                      json={"name": "bot-one", "risk_tier": "low"}).status_code == 200


# ──────────────── guard 4 · created_by is ON DELETE SET NULL ─────────────────

def test_deleting_the_creating_user_leaves_the_system_standing(admin, add_user, login):
    """The systems outlive the person who registered them. CASCADE here would
    delete a bank's mortgage-bot inventory entry because an employee left."""
    org, client = admin
    add_user(org["org_id"], "declarer@test.dev", "declarerpass123", role="admin")
    declarer = login("declarer@test.dev", "declarerpass123")
    created = declarer.post("/v1/systems", json=_payload()).json()

    with SessionLocal() as db:
        row = db.get(AiSystem, uuid.UUID(created["id"]))
        assert row.created_by is not None, "created_by was never set"
        user = db.execute(
            text("SELECT id FROM users WHERE email = :e"),
            {"e": "declarer@test.dev"}).scalar_one()
        # Several other tables reference users with a plain FK and no ON DELETE
        # rule (login_events 0025, user_sessions 0045, …), so a user who has
        # logged in cannot be deleted while those rows stand. Clear EVERY child
        # except ai_systems — enumerated from the catalog rather than hand-listed
        # so a future FK cannot quietly turn this guard into a test of
        # login_events. What is left is exactly the reference under test.
        children = db.execute(text("""
            SELECT c.conrelid::regclass::text, a.attname
              FROM pg_constraint c
              JOIN pg_attribute a ON a.attrelid = c.conrelid AND a.attnum = c.conkey[1]
             WHERE c.contype = 'f' AND c.confrelid = 'users'::regclass
        """)).all()
        assert ("ai_systems", "created_by") in [tuple(r) for r in children], children
        for table, column in children:
            if table == "ai_systems":
                continue
            db.execute(text(f"DELETE FROM {table} WHERE {column} = :u"), {"u": user})
        db.delete(db.get(User, user))
        db.commit()

    with SessionLocal() as db:
        row = db.get(AiSystem, uuid.UUID(created["id"]))
        assert row is not None, "deleting the user deleted their system"
        assert row.created_by is None, "created_by was not SET NULL"

    still = client.get(f"/v1/systems/{created['id']}")
    assert still.status_code == 200
    assert still.json()["name"] == created["name"]


# ───────────────── guard 5 · tenant isolation, both layers ───────────────────

def test_another_tenants_system_is_a_404_and_never_a_403(make_org, login):
    a, b = make_org(), make_org()
    ca = login(a["admin_email"], a["admin_password"])
    cb = login(b["admin_email"], b["admin_password"])
    mine = ca.post("/v1/systems", json=_payload("theirs-to-find")).json()

    assert cb.get(f"/v1/systems/{mine['id']}").status_code == 404
    assert cb.put(f"/v1/systems/{mine['id']}",
                  json={"risk_tier": "low"}).status_code == 404
    assert cb.post(f"/v1/systems/{mine['id']}/retire").status_code == 404
    # untouched
    assert ca.get(f"/v1/systems/{mine['id']}").json()["risk_tier"] == "high"


def test_rls_posture_a_hides_the_row_from_the_confined_role(make_org, login):
    """The RLS layer on its own, with the app's superuser dropped for the confined
    `foxy_app` role — which is what migration 0068's policy actually protects. If
    the policy were lost, the router's explicit WHERE would still hide the row,
    and this is the guard that would notice."""
    a, b = make_org(), make_org()
    login(a["admin_email"], a["admin_password"]).post(
        "/v1/systems", json=_payload("rls-MINE"))
    login(b["admin_email"], b["admin_password"]).post(
        "/v1/systems", json=_payload("rls-THEIRS"))

    db = SessionLocal()
    try:
        db.execute(text("SELECT set_config('app.current_org', :oid, true)"),
                   {"oid": str(a["org_id"])})
        db.execute(text('SET LOCAL ROLE "foxy_app"'))
        seen = [r[0] for r in db.execute(text("SELECT name FROM ai_systems")).all()]
    finally:
        db.rollback()
        db.close()
    assert seen == ["rls-MINE"], f"RLS let the confined role see {seen}"


def test_the_confined_role_cannot_write_a_row_into_another_tenant(make_org, login):
    """FORCE RLS from the WRITE side: scoped to org B, an INSERT naming org A
    fails the policy's WITH CHECK. The read-side half is the test above; this is
    the half that stops a confined session planting a row somewhere else.

    ⚠ Deliberately scoped to a real org rather than run with NO scope at all.
    `set_config('app.current_org', …, true)` is transaction-local and its RESET
    value for a custom GUC is the empty string, not NULL — so on a pooled
    connection that was scoped earlier, `current_setting(…, true)::uuid` raises
    `invalid input syntax for type uuid: ""` instead of denying. That is true of
    all thirteen posture-A tables and is not something 0068 introduces; a guard
    written on the no-scope path would be asserting a connection's history.
    """
    from sqlalchemy.exc import ProgrammingError

    a, b = make_org(), make_org()
    login(a["admin_email"], a["admin_password"]).post(
        "/v1/systems", json=_payload("a-side-probe"))

    db = SessionLocal()
    try:
        db.execute(text("SELECT set_config('app.current_org', :oid, true)"),
                   {"oid": str(b["org_id"])})
        db.execute(text('SET LOCAL ROLE "foxy_app"'))
        # This SELECT succeeding at all is what proves the role HAS the grant —
        # otherwise the refusal below would be a missing GRANT wearing an RLS
        # costume, and this guard would be green for the wrong reason.
        assert db.execute(text("SELECT count(*) FROM ai_systems")).scalar_one() == 0
        with pytest.raises(ProgrammingError) as caught:
            db.execute(
                text("INSERT INTO ai_systems (org_id, name, owner_email, purpose) "
                     "VALUES (:oid, 'smuggled', 'x@test.dev', 'p')"),
                {"oid": str(a["org_id"])})
        assert "row-level security policy" in str(caught.value), (
            f"the INSERT was refused by something other than the policy: {caught.value}")
    finally:
        db.rollback()
        db.close()


def test_the_router_filters_by_org_itself_and_does_not_lean_on_rls(admin):
    """Isolation is TWO layers and the explicit filter is the first one. Removing
    the `WHERE org_id` survives every behavioural guard above, because a customer
    request runs under the confined role and RLS catches it — which is the design
    working, not a reason to drop the clause. Staff and worker paths do not run
    under that role. So this asserts the clause itself, at the source."""
    import inspect

    from app.routers import systems

    assert "AiSystem.org_id == org_id" in inspect.getsource(systems._get_system)
    assert "AiSystem.org_id == org.id" in inspect.getsource(systems.list_systems)
    assert "AiSystem.org_id == org_id" in inspect.getsource(systems._ensure_unique_name)


# ─────────────────────── declared, never inferred ────────────────────────────

def test_ingesting_events_never_conjures_a_system(make_org, login):
    """Foxy must not derive an inventory from traffic. An inventory Foxy guessed
    is not evidence — and it is silently incomplete, because a system that has
    not sent an event yet does not exist to it."""
    org = make_org()
    r = client_post_batch(org)
    assert r.status_code == 202, r.text
    admin_client = login(org["admin_email"], org["admin_password"])
    assert admin_client.get("/v1/systems").json() == []


def client_post_batch(org):
    from fastapi.testclient import TestClient

    from app.main import app
    sdk = TestClient(app)
    return sdk.post("/v1/logs/batch", headers=org["auth"], json=[{
        "prompt_hash": "a" * 64,
        "response_hash": "b" * 64,
        "token_count": 42,
        "policy_tag": "hipaa",
        "agent": "mortgage-bot",
    }])


# ───────────────────────── the declared vocabulary ───────────────────────────

@pytest.mark.parametrize("field,value", [
    ("provider", "not-a-provider"),
    ("environment", "prod"),
    ("data_classification", "top-secret"),
    ("risk_tier", "extreme"),
    ("lifecycle_status", "deleted"),
])
def test_a_value_outside_the_declared_vocabulary_is_refused(admin, field, value):
    _, client = admin
    r = client.post("/v1/systems", json=_payload(**{field: value}))
    assert r.status_code == 422, r.text


def test_a_blank_name_or_purpose_is_not_a_declaration(admin):
    _, client = admin
    assert client.post("/v1/systems", json=_payload("   ")).status_code == 422
    assert client.post("/v1/systems",
                       json=_payload(purpose="  ")).status_code == 422


def test_the_check_constraints_hold_independently_of_the_api(make_org):
    """The router's Literal enums are duplicated as CHECK constraints in 0068 on
    purpose: the API is not the only writer a table gets over its life."""
    from sqlalchemy.exc import IntegrityError

    org = make_org()
    db = SessionLocal()
    try:
        with pytest.raises(IntegrityError) as caught:
            db.execute(
                text("INSERT INTO ai_systems (org_id, name, owner_email, purpose, "
                     "risk_tier) VALUES (:oid, 'raw', 'x@test.dev', 'p', 'extreme')"),
                {"oid": str(org["org_id"])})
        assert "ck_ai_system_risk_tier" in str(caught.value), caught.value
    finally:
        db.rollback()
        db.close()


# ─────────── gate round 1 · retirement is terminal, and PUT cannot do it ─────
#
# Driven through the ENDPOINTS, not asserted against the schema: a model-level
# check ("lifecycle_status is absent from AiSystemUpdate") would pass whichever
# way the refusal is implemented, and would still pass if the field came back
# with a handler that quietly allowed it.

def test_put_cannot_retire_a_system(admin):
    """Retiring through the general update would file `system.update` for what is
    a `system.retire` — one governance action recorded as another."""
    _, client = admin
    created = client.post("/v1/systems", json=_payload()).json()

    r = client.put(f"/v1/systems/{created['id']}", json={"lifecycle_status": "retired"})
    assert r.status_code == 409, r.text
    assert "/retire" in r.json()["detail"], r.json()

    after = client.get(f"/v1/systems/{created['id']}").json()
    assert after["retired"] is False, "PUT retired it anyway"
    assert after["lifecycle_status"] == "active"
    actions = [a["action"] for a in client.get("/v1/account/audit").json()]
    assert "system.retire" not in actions
    assert actions.count("system.update") == 0, (
        f"a refused update was still recorded: {actions}")


def test_put_cannot_revive_a_retired_system(admin):
    """The worse half: a system that stopped accepting evidence must not start
    again with no endpoint, no governance event and nothing in the trail."""
    _, client = admin
    created = client.post("/v1/systems", json=_payload()).json()
    assert client.post(f"/v1/systems/{created['id']}/retire").status_code == 200

    for revive in ("active", "draft"):
        r = client.put(f"/v1/systems/{created['id']}",
                       json={"lifecycle_status": revive})
        assert r.status_code == 409, f"{revive}: {r.text}"
        assert "cannot be returned to service" in r.json()["detail"]
        assert client.get(f"/v1/systems/{created['id']}").json()["retired"] is True

    actions = [a["action"] for a in client.get("/v1/account/audit").json()]
    assert actions.count("system.retire") == 1, actions
    assert "system.update" not in actions, "a revival was recorded as an update"


def test_there_is_no_un_retire_endpoint(admin):
    """Retirement is terminal by decision. If a future phase adds a way back it
    must be its own endpoint with its own governance event — and this guard is
    what makes that a deliberate act rather than a side effect."""
    import inspect

    from app.routers import systems

    _, client = admin
    created = client.post("/v1/systems", json=_payload()).json()
    client.post(f"/v1/systems/{created['id']}/retire")

    for path in ("unretire", "un-retire", "reactivate", "restore"):
        assert client.post(f"/v1/systems/{created['id']}/{path}").status_code == 404

    src = inspect.getsource(systems)
    assert "RETIREMENT IS TERMINAL" in systems.__doc__, (
        "the docstring recording the decision is gone")
    for verb in ("unretire", "reactivate"):
        assert f'/{verb}"' not in src, f"an un-retire endpoint appeared: {verb}"


def test_a_retired_systems_declaration_can_still_be_corrected(admin):
    """Terminal lifecycle, not a frozen row. The owner of a retired system can
    still change jobs, and the inventory should be able to say so."""
    _, client = admin
    created = client.post("/v1/systems", json=_payload()).json()
    client.post(f"/v1/systems/{created['id']}/retire")

    r = client.put(f"/v1/systems/{created['id']}",
                   json={"owner_email": "new.owner@bank.example"})
    assert r.status_code == 200, r.text
    assert r.json()["owner_email"] == "new.owner@bank.example"
    assert r.json()["retired"] is True, "correcting a field revived it"


def test_put_may_still_move_a_draft_into_service(admin):
    """The transition PUT keeps. Refusing every lifecycle_status change would
    strand 'draft' with no way out."""
    _, client = admin
    created = client.post("/v1/systems",
                          json=_payload(lifecycle_status="draft")).json()
    assert created["lifecycle_status"] == "draft"
    r = client.put(f"/v1/systems/{created['id']}", json={"lifecycle_status": "active"})
    assert r.status_code == 200, r.text
    assert r.json()["lifecycle_status"] == "active"
    assert r.json()["retired"] is False


# ──────── gate round 1 · a lost race for a name is a 409, never a 500 ────────

def test_losing_the_race_for_a_name_is_a_409_not_a_500(admin, monkeypatch):
    """`_ensure_unique_name` is check-then-act with a real window: two admins
    submitting the same name, or one double-clicked form, both read "no such
    name" and the second INSERT hits the constraint at flush time.

    The window is driven directly — neutering the pre-check is what puts the
    request in the state a lost race leaves it in. Without the handler this is a
    500 for a condition the API already answers correctly.
    """
    from app.routers import systems

    _, client = admin
    assert client.post("/v1/systems", json=_payload("raced-bot")).status_code == 201

    monkeypatch.setattr(systems, "_ensure_unique_name",
                        lambda *a, **k: None)          # the race, deterministically
    r = client.post("/v1/systems", json=_payload("raced-bot"))
    assert r.status_code == 409, f"a lost race returned {r.status_code}: {r.text}"
    assert "already exists" in r.json()["detail"]
    assert len(client.get("/v1/systems").json()) == 1


def test_losing_the_race_on_a_rename_is_a_409_too(admin, monkeypatch):
    from app.routers import systems

    _, client = admin
    client.post("/v1/systems", json=_payload("bot-a"))
    other = client.post("/v1/systems", json=_payload("bot-b")).json()

    monkeypatch.setattr(systems, "_ensure_unique_name", lambda *a, **k: None)
    r = client.put(f"/v1/systems/{other['id']}", json={"name": "bot-a"})
    assert r.status_code == 409, f"a lost race returned {r.status_code}: {r.text}"
    assert client.get(f"/v1/systems/{other['id']}").json()["name"] == "bot-b"


def test_a_check_violation_is_not_reported_as_a_name_conflict():
    """The conflict handler must not swallow every IntegrityError. A CHECK
    violation is a bug here, not a duplicate name, and answering 409 would send a
    developer hunting a name that is not the problem.

    Driven at `_flush_or_conflict` directly with a session whose flush raises,
    because that IS the discrimination under test — patching the function itself
    (the first version of this guard) proved only that a raise propagates.
    """
    from fastapi import HTTPException
    from sqlalchemy.exc import IntegrityError

    from app.routers import systems

    class _Session:
        def __init__(self, message):
            self._message = message
            self.rolled_back = False

        def flush(self):
            raise IntegrityError("stmt", {}, Exception(self._message))

        def rollback(self):
            self.rolled_back = True

    # the duplicate name -> the 409 the pre-check would have given
    dup = _Session('duplicate key value violates unique constraint '
                   '"uq_ai_system_org_name"')
    with pytest.raises(HTTPException) as caught:
        systems._flush_or_conflict(dup)
    assert caught.value.status_code == 409
    assert dup.rolled_back, "the failed transaction was left open"

    # anything else -> straight back out, uncaught
    other = _Session('new row violates check constraint "ck_ai_system_risk_tier"')
    with pytest.raises(IntegrityError):
        systems._flush_or_conflict(other)

    # and the clean path stays quiet
    class _Ok:
        def flush(self):
            self.flushed = True

    ok = _Ok()
    systems._flush_or_conflict(ok)
    assert ok.flushed


# ──────── gate round 1 · the audit records WHAT IT WAS, not just which ───────

def test_an_update_records_the_previous_governance_values(admin):
    """"Someone lowered the risk tier on the mortgage bot — from what?" is the
    question this registry exists to answer, and field names alone cannot."""
    _, client = admin
    created = client.post("/v1/systems",
                          json=_payload(risk_tier="critical",
                                        data_classification="regulated")).json()
    r = client.put(f"/v1/systems/{created['id']}",
                   json={"risk_tier": "low", "data_classification": "public"})
    assert r.status_code == 200, r.text

    entry = next(a for a in client.get("/v1/account/audit").json()
                 if a["action"] == "system.update")
    assert entry["detail"]["previous"] == {
        "risk_tier": "critical", "data_classification": "regulated"}, entry["detail"]
    assert sorted(entry["detail"]["fields"]) == ["data_classification", "risk_tier"]
    assert entry["detail"]["system_id"] == created["id"]


def test_the_audit_does_not_keep_a_diff_of_every_field(admin):
    """An audit surface, not a diff log. owner_email churn is noise, and a trail
    that records everything is one nobody reads."""
    _, client = admin
    created = client.post("/v1/systems", json=_payload()).json()
    client.put(f"/v1/systems/{created['id']}",
               json={"owner_email": "someone.else@bank.example",
                     "purpose": "A different purpose entirely",
                     "risk_tier": "low"})
    entry = next(a for a in client.get("/v1/account/audit").json()
                 if a["action"] == "system.update")
    assert set(entry["detail"]["previous"]) == {"risk_tier"}, entry["detail"]


def test_an_unchanged_governance_field_is_not_recorded_as_a_change(admin):
    """`risk_tier: high -> high` is noise. Only real transitions belong here."""
    _, client = admin
    created = client.post("/v1/systems", json=_payload(risk_tier="high")).json()
    client.put(f"/v1/systems/{created['id']}",
               json={"risk_tier": "high", "purpose": "Reworded, same risk"})
    entry = next(a for a in client.get("/v1/account/audit").json()
                 if a["action"] == "system.update")
    assert entry["detail"]["previous"] == {}, entry["detail"]


def test_moving_a_draft_into_service_records_what_it_was(admin):
    """lifecycle_status is a governance field, so the one transition PUT still
    performs carries its before-value like the others."""
    _, client = admin
    created = client.post("/v1/systems",
                          json=_payload(lifecycle_status="draft")).json()
    client.put(f"/v1/systems/{created['id']}", json={"lifecycle_status": "active"})
    entry = next(a for a in client.get("/v1/account/audit").json()
                 if a["action"] == "system.update")
    assert entry["detail"]["previous"] == {"lifecycle_status": "draft"}, entry["detail"]


# ──── gate round 1 · trimming is one behaviour, not one per field ────────────

@pytest.mark.parametrize("field,sent,stored", [
    ("name", "  padded-bot  ", "padded-bot"),
    ("purpose", "  Answers questions  ", "Answers questions"),
    ("model_name", "  gpt-4o  ", "gpt-4o"),
    ("owner_email", "  Owner@Bank.Example  ", "owner@bank.example"),
])
def test_surrounding_whitespace_is_trimmed_on_every_trimmed_field(admin, field,
                                                                  sent, stored):
    """`model_name` carries a `pattern` and the other three do not. With an
    "after" validator that alone decided the answer: " gpt-4o " 422'd on the raw
    regex while " padded-bot " was silently accepted. Same input, two
    behaviours."""
    _, client = admin
    r = client.post("/v1/systems", json=_payload(**{field: sent}))
    assert r.status_code == 201, f"{field}: {r.text}"
    assert r.json()[field] == stored


@pytest.mark.parametrize("field", ["name", "purpose", "owner_email", "model_name"])
def test_a_whitespace_only_value_is_not_a_declaration_on_any_field(admin, field):
    _, client = admin
    r = client.post("/v1/systems", json=_payload(**{field: "   "}))
    assert r.status_code == 422, f"{field} accepted whitespace: {r.text}"


def test_trimming_applies_to_an_update_too(admin):
    _, client = admin
    created = client.post("/v1/systems", json=_payload()).json()
    r = client.put(f"/v1/systems/{created['id']}", json={"model_name": "  gpt-5.6  "})
    assert r.status_code == 200, r.text
    assert r.json()["model_name"] == "gpt-5.6"
