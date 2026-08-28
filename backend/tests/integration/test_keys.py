"""API keys: HMAC-with-pepper storage, create/use/revoke, legacy sha256 fallback,
peppered rotate, and input validation.

The block from `test_the_machine_rotate_leaves_sibling_keys_alive` down is
register #249: `POST /v1/keys/rotate` is machine Bearer auth with no human
present, and it used to share `_rotate_org_key` with the 2FA-gated dashboard
path - so one service rotating its own credential revoked every other key the
organisation held, and was answered 200.
"""

from __future__ import annotations

import hashlib
import hmac
import uuid
from datetime import datetime, timedelta, timezone

import app.mfa as mfa
import app.routers.keys as keys_router
from sqlalchemy import select

from app.auth import hash_key
from app.config import get_settings
from app.db import SessionLocal
from app.models import AccountAction, ApiKey, Organization


def _auth(key):
    return {"Authorization": f"Bearer {key}"}


def _alive(client, key):
    """Does this key still authenticate? The only question that matters here."""
    return client.get("/v1/health", headers=_auth(key)).status_code == 200


def _regenerate(c, monkeypatch, code="424242"):
    """Drive the 2FA dashboard path end to end. Mirrors test_keys_regenerate."""
    monkeypatch.setattr(keys_router.email_mod, "send_email", lambda **kw: True)
    monkeypatch.setattr(mfa, "new_otp", lambda: code)
    assert c.post("/v1/keys/regenerate/request").status_code == 200
    r = c.post("/v1/keys/regenerate/confirm", json={"code": code})
    assert r.status_code == 200, r.text
    return r.json()


def test_create_use_revoke(make_org, login, client):
    org = make_org()
    c = login(org["admin_email"], org["admin_password"])
    created = c.post("/v1/keys", json={"name": "ci key"}).json()
    newkey = created["api_key"]

    assert client.get("/v1/health",
                      headers={"Authorization": f"Bearer {newkey}"}).status_code == 200
    assert c.delete(f"/v1/keys/{created['id']}").status_code == 200
    assert client.get("/v1/health",
                      headers={"Authorization": f"Bearer {newkey}"}).status_code == 401


def test_key_stored_as_hmac_not_plain_sha256(make_org, login):
    org = make_org()
    c = login(org["admin_email"], org["admin_password"])
    key = c.post("/v1/keys", json={"name": "h"}).json()["api_key"]

    db = SessionLocal()
    try:
        row = db.execute(
            select(ApiKey).where(ApiKey.key_hash == hash_key(key))
        ).scalar_one_or_none()
        assert row is not None                                    # HMAC match found
        assert row.key_hash != hashlib.sha256(key.encode()).hexdigest()  # not plain sha256
        # The pepper must actually be mixed in: a DIFFERENT pepper yields a
        # different hash (proves it's HMAC-with-pepper, not just "some HMAC").
        wrong = hmac.new((get_settings().api_key_pepper + "X").encode(),
                         key.encode(), hashlib.sha256).hexdigest()
        assert row.key_hash != wrong
    finally:
        db.close()


def test_legacy_only_key_still_authenticates(client):
    """A pre-A2 org that has ONLY the plain-sha256 org hash (no api_keys row) must
    still authenticate via the legacy fallback in require_org."""
    key = "foxy_sk_" + uuid.uuid4().hex + uuid.uuid4().hex
    db = SessionLocal()
    try:
        db.add(Organization(id=uuid.uuid4(), name="Legacy Co",
                            api_key_hash=hashlib.sha256(key.encode()).hexdigest()))
        db.commit()
    finally:
        db.close()
    assert client.get("/v1/health",
                      headers={"Authorization": f"Bearer {key}"}).status_code == 200


def test_invalid_key_401(client):
    assert client.get("/v1/health",
                      headers={"Authorization": "Bearer foxy_sk_not_a_real_key"}).status_code == 401


def test_delete_bad_uuid_returns_422(make_org, login):
    org = make_org()
    c = login(org["admin_email"], org["admin_password"])
    assert c.delete("/v1/keys/not-a-uuid").status_code == 422


def test_whitespace_name_defaults(make_org, login):
    org = make_org()
    c = login(org["admin_email"], org["admin_password"])
    assert c.post("/v1/keys", json={"name": "    "}).json()["name"] == "unnamed key"


def test_rotate_invalidates_old_key(make_org, client):
    org = make_org()
    old = org["api_key"]
    new = client.post("/v1/keys/rotate", headers=org["auth"]).json()["api_key"]
    assert client.get("/v1/health",
                      headers={"Authorization": f"Bearer {new}"}).status_code == 200
    assert client.get("/v1/health",
                      headers={"Authorization": f"Bearer {old}"}).status_code == 401


# ═══ register #249 — the machine endpoint's blast radius ════════════════════

def test_the_machine_rotate_leaves_sibling_keys_alive(make_org, login, client):
    """THE REGRESSION GUARD, and the reason it asserts survival rather than 200.

    A customer runs three services on three keys. One of them calls
    POST /v1/keys/rotate to replace its own credential. Before #249 was fixed the
    other two were revoked, nobody was told, and the caller got a 200 - so a test
    that merely asserted the status code passed throughout. What must hold is
    that B and C still AUTHENTICATE afterwards.
    """
    org = make_org()
    c = login(org["admin_email"], org["admin_password"])
    b = c.post("/v1/keys", json={"name": "service-b"}).json()["api_key"]
    d = c.post("/v1/keys", json={"name": "service-c"}).json()["api_key"]
    assert _alive(client, b) and _alive(client, d)

    r = client.post("/v1/keys/rotate", headers=org["auth"])
    assert r.status_code == 200, r.text
    fresh = r.json()["api_key"]

    assert not _alive(client, org["api_key"]), "the rotated key survived"
    assert _alive(client, fresh), "the replacement does not authenticate"
    assert _alive(client, b), "#249: rotating one key revoked service-b"
    assert _alive(client, d), "#249: rotating one key revoked service-c"


def test_the_machine_rotate_replaces_exactly_one_row(make_org, login, client):
    """Counted at the table, not inferred from the HTTP answers: three active
    keys in, three active keys out, and the one that rotated is the only
    revocation."""
    org = make_org()
    c = login(org["admin_email"], org["admin_password"])
    c.post("/v1/keys", json={"name": "service-b"})
    c.post("/v1/keys", json={"name": "service-c"})
    assert client.post("/v1/keys/rotate", headers=org["auth"]).status_code == 200

    db = SessionLocal()
    try:
        rows = db.execute(select(ApiKey).where(
            ApiKey.org_id == uuid.UUID(org["org_id"]))).scalars().all()
        active = [k for k in rows if k.status == "active"]
        revoked = [k for k in rows if k.status == "revoked"]
        assert len(active) == 3, [(k.name, k.status) for k in rows]
        assert len(revoked) == 1 and revoked[0].key_hash == hash_key(org["api_key"])
        assert revoked[0].revoked_at is not None
        # The replacement keeps the rotated key's NAME: it serves the same
        # service. `f"{name} (rotated)"` would grow without bound across repeat
        # rotations against a String(120) column.
        assert sorted(k.name for k in active) == ["primary", "service-b", "service-c"]
    finally:
        db.close()


def test_the_2fa_regenerate_still_revokes_every_key(make_org, login, client,
                                                    monkeypatch):
    """THE CONTROL, and without it the guard above is worthless: "fix" #249 by
    making nothing ever revoke anything and both tests go green.

    Revoke-all is not a bug. It is the right answer to "I think a key leaked" -
    behind an admin session AND an emailed 2FA code, decided by a human who
    knows what else is deployed. It must survive the fix intact.
    """
    org = make_org()
    c = login(org["admin_email"], org["admin_password"])
    b = c.post("/v1/keys", json={"name": "service-b"}).json()["api_key"]
    d = c.post("/v1/keys", json={"name": "service-c"}).json()["api_key"]

    fresh = _regenerate(c, monkeypatch)["api_key"]

    assert _alive(client, fresh)
    assert not _alive(client, org["api_key"])
    assert not _alive(client, b), "the 2FA path stopped burning sibling keys"
    assert not _alive(client, d), "the 2FA path stopped burning sibling keys"


def test_machine_rotate_does_not_repoint_the_legacy_hash_of_another_key(
        make_org, login, client):
    """THE SUBTLE HALF. `_rotate_org_key` repoints organizations.api_key_hash at
    the new key, killing the legacy plain-SHA256 credential as a side effect.

    On the presented-key path that would be #249 in miniature: the fixture key
    (like every /v1/signup and Google org) is registered BOTH as the peppered
    "primary" row and as the legacy org hash, so repointing the column while
    rotating an unrelated peppered sibling would kill it without saying so.
    """
    org = make_org()
    c = login(org["admin_email"], org["admin_password"])
    b = c.post("/v1/keys", json={"name": "service-b"}).json()["api_key"]

    db = SessionLocal()
    try:
        before = db.get(Organization, uuid.UUID(org["org_id"])).api_key_hash
    finally:
        db.close()

    assert client.post("/v1/keys/rotate", headers=_auth(b)).status_code == 200

    db = SessionLocal()
    try:
        after = db.get(Organization, uuid.UUID(org["org_id"])).api_key_hash
    finally:
        db.close()
    assert after == before, "rotating a peppered sibling moved the legacy org hash"
    assert _alive(client, org["api_key"]), "rotating service-b killed the primary key"


def test_machine_rotate_of_the_dual_registered_key_kills_it_on_both_paths(
        make_org, client):
    """The mirror of the test above, and why the condition is `presented token IS
    the legacy hash` rather than `never touch it`.

    The fixture key is the peppered "primary" AND the legacy org hash - the shape
    /v1/signup and the Google path both produce. Revoking only the api_keys row
    would leave require_org's legacy fallback still honouring the very key that
    was just rotated.
    """
    org = make_org()
    old = org["api_key"]
    db = SessionLocal()
    try:
        assert db.get(Organization, uuid.UUID(org["org_id"])).api_key_hash \
            == hashlib.sha256(old.encode()).hexdigest()      # premise, verified
    finally:
        db.close()

    fresh = client.post("/v1/keys/rotate", headers=org["auth"]).json()["api_key"]

    assert not _alive(client, old), "the legacy fallback still honours the old key"
    db = SessionLocal()
    try:
        org_row = db.get(Organization, uuid.UUID(org["org_id"]))
        assert org_row.api_key_hash == hashlib.sha256(fresh.encode()).hexdigest()
        assert org_row.key_rotated_at is not None
    finally:
        db.close()


def test_machine_rotate_of_a_legacy_only_org_mints_a_row(client):
    """A pre-A2 org whose ONLY credential is organizations.api_key_hash: there is
    no api_keys row to revoke. The replacement gets one, the column stays
    satisfied (it is NOT NULL), and the old key dies."""
    old = "foxy_sk_" + uuid.uuid4().hex + uuid.uuid4().hex
    org_id = uuid.uuid4()
    db = SessionLocal()
    try:
        db.add(Organization(id=org_id, name="Legacy Rotator",
                            api_key_hash=hashlib.sha256(old.encode()).hexdigest()))
        db.commit()
    finally:
        db.close()

    r = client.post("/v1/keys/rotate", headers=_auth(old))
    assert r.status_code == 200, r.text
    fresh = r.json()["api_key"]

    assert _alive(client, fresh) and not _alive(client, old)
    db = SessionLocal()
    try:
        rows = db.execute(select(ApiKey).where(ApiKey.org_id == org_id)).scalars().all()
        assert len(rows) == 1 and rows[0].status == "active"
        assert rows[0].key_hash == hash_key(fresh)
        assert rows[0].expires_at is None
        org_row = db.get(Organization, org_id)
        assert org_row.api_key_hash == hashlib.sha256(fresh.encode()).hexdigest()
    finally:
        db.close()


def test_machine_rotate_carries_the_expiry_forward(make_org, login, client):
    """Rotation must not LENGTHEN a credential's life, or a machine turns a
    bounded 30-day key into a permanent one just by calling this endpoint."""
    org = make_org()
    c = login(org["admin_email"], org["admin_password"])
    made = c.post("/v1/keys", json={"name": "bounded", "expires_in_days": 5}).json()
    fresh = client.post("/v1/keys/rotate",
                        headers=_auth(made["api_key"])).json()["api_key"]

    db = SessionLocal()
    try:
        old_row = db.execute(select(ApiKey).where(
            ApiKey.id == uuid.UUID(made["id"]))).scalar_one()
        new_row = db.execute(select(ApiKey).where(
            ApiKey.key_hash == hash_key(fresh))).scalar_one()
        assert new_row.expires_at is not None, "rotation made a bounded key permanent"
        assert abs((new_row.expires_at - old_row.expires_at).total_seconds()) < 1
        assert new_row.expires_at > datetime.now(timezone.utc) + timedelta(days=4)
    finally:
        db.close()


def test_a_key_that_vanishes_between_auth_and_the_lock_is_not_replaced(
        make_org, login, client, monkeypatch):
    """The narrow race the FOR UPDATE exists for: an admin's DELETE /v1/keys/{id}
    lands between require_org authenticating the key and the rotate handler
    locking it.

    Driven by patching `app.routers.keys.hash_key` alone - keys.py imported the
    name into its own module namespace, so `app.auth.hash_key` (and therefore
    require_org) stays real. The handler then sees exactly what it would see if
    the row had gone: no match. It must refuse, not mint a replacement for a
    credential that no longer exists.
    """
    org = make_org()
    c = login(org["admin_email"], org["admin_password"])
    b = c.post("/v1/keys", json={"name": "service-b"}).json()["api_key"]
    monkeypatch.setattr(keys_router, "hash_key", lambda t: "0" * 64)

    r = client.post("/v1/keys/rotate", headers=_auth(b))
    assert r.status_code == 401, r.text

    monkeypatch.undo()
    db = SessionLocal()
    try:
        active = db.execute(select(ApiKey).where(
            ApiKey.org_id == uuid.UUID(org["org_id"]),
            ApiKey.status == "active")).scalars().all()
        assert len(active) == 2, "a replacement was minted for a key that was gone"
    finally:
        db.close()


def test_both_rotations_are_recorded_and_read_differently(make_org, login, client,
                                                          monkeypatch):
    """Neither rotation was audited at all before #249 - a customer's own account
    history showed key creates and revokes but never a rotation, which is half of
    what made the blast radius silent.

    Two ACTION literals, not one with the difference in `detail`:
    `desktop/settings_admin.py:audit_rows` renders action / target / actor / when
    and NOT detail, so a distinction buried there is invisible to the person
    reading their history.
    """
    org = make_org()
    c = login(org["admin_email"], org["admin_password"])
    assert client.post("/v1/keys/rotate", headers=org["auth"]).status_code == 200
    _regenerate(c, monkeypatch)

    trail = c.get("/v1/account/audit").json()
    by_action = {a["action"]: a for a in trail}
    assert "key.rotate" in by_action, [a["action"] for a in trail]
    assert "key.regenerate" in by_action, [a["action"] for a in trail]
    assert by_action["key.rotate"]["action"] != by_action["key.regenerate"]["action"]

    machine = by_action["key.rotate"]
    assert machine["target"] == "primary"
    assert machine["detail"]["scope"] == "presented_key"
    # No human acted. Naming one would assert something unverified on an audit
    # row - the same call `billing_state.end_evaluation` makes.
    assert machine["actor_email"] is None

    burn = by_action["key.regenerate"]
    assert burn["detail"]["scope"] == "all_active_keys"
    assert burn["actor_email"] == org["admin_email"]
    assert burn["detail"]["revoked"] >= 1
    assert burn["target"].endswith("key") or burn["target"].endswith("keys")


def test_the_two_rotation_responses_each_say_what_they_destroyed(
        make_org, login, client, monkeypatch):
    """The shared default said "the old key is permanently invalid" on a call that
    had just revoked four. A message is a promise; these two are not the same
    promise."""
    org = make_org()
    c = login(org["admin_email"], org["admin_password"])
    machine = client.post("/v1/keys/rotate", headers=org["auth"]).json()["message"]
    burn = _regenerate(c, monkeypatch)["message"]

    assert "other keys are untouched" in machine
    assert "EVERY" not in machine
    assert "EVERY previous key" in burn
    assert machine != burn


def test_the_presented_key_lookup_filters_by_org_itself_and_does_not_lean_on_rls():
    """SOURCE-LEVEL, and it has to be.

    `api_keys` carries NO RLS - require_org looks a key up BEFORE the tenant GUC
    exists, so the table is posture C and the explicit org filter is the only
    tenant isolation on this query. A behavioural test cannot prove it is there:
    key_hash is UNIQUE, so a bearer token can never resolve to an org other than
    the one require_org just returned for it, and deleting the filter changes no
    observable response. The docstring is stripped first so the guard reads the
    CODE and not the prose next to it.
    """
    import inspect

    from app.routers import keys as kr

    body = inspect.getsource(kr._rotate_presented_key).split('"""')[2]
    assert "ApiKey.org_id == org.id" in body, (
        "the org filter is gone; nothing underneath api_keys will catch that")


def test_the_presented_key_row_is_locked_before_it_is_replaced():
    """SOURCE-LEVEL for the same reason: the row is ALSO locked incidentally
    today, because require_org's best-effort `last_used_at` stamp autoflushes an
    UPDATE on it first. So a behavioural race test would pass with the explicit
    lock deleted - and would keep passing right up until that stamp became
    conditional or throttled."""
    import inspect

    from app.routers import keys as kr

    body = inspect.getsource(kr._rotate_presented_key).split('"""')[2]
    assert "with_for_update()" in body
    # and the read-side helpers it must not be confused with stay unlocked
    assert "with_for_update" not in inspect.getsource(kr.list_keys)


def test_the_two_rotation_paths_stay_wired_to_different_helpers():
    """#249 WAS one helper serving two audiences. Checked at the AST so a future
    handler cannot quietly reach for the burn-it-all one again - which is the
    exact regression, and it is a one-word edit."""
    import ast
    import pathlib

    from app.routers import keys as kr

    tree = ast.parse(pathlib.Path(kr.__file__).read_text(encoding="utf-8"))
    calls = {n.name: {c.func.id for c in ast.walk(n)
                      if isinstance(c, ast.Call) and isinstance(c.func, ast.Name)}
             for n in ast.walk(tree) if isinstance(n, ast.FunctionDef)}

    assert "_rotate_presented_key" in calls["rotate_key"]
    assert "_rotate_org_key" not in calls["rotate_key"], (
        "#249 is back: the machine endpoint revokes every key in the org again")
    assert "_rotate_org_key" in calls["regenerate_confirm"]
    assert "_rotate_presented_key" not in calls["regenerate_confirm"]
    # The guard is live — it must actually be finding the callers it names.
    burners = sorted(f for f, c in calls.items() if "_rotate_org_key" in c)
    assert burners == ["regenerate_confirm"], (
        f"_rotate_org_key revokes EVERY active key and is 2FA-gated by its only "
        f"caller; it now has these callers: {burners}")


def test_the_export_names_api_keys_but_never_their_hashes(make_org, login, client):
    """The GDPR bundle already carries `api_keys`, and rotation now writes rows
    into it from a path with no human. A key's plaintext is shown once and never
    stored; its hash must never leave either."""
    org = make_org()
    c = login(org["admin_email"], org["admin_password"])
    assert client.post("/v1/keys/rotate", headers=org["auth"]).status_code == 200

    r = c.get("/v1/account/export")
    assert r.status_code == 200, r.text
    bundle = r.json()
    assert bundle["api_keys"], "the export lost the keys section"
    assert set(bundle["api_keys"][0]) == {
        "name", "key_prefix", "status", "created_at", "last_used_at", "expires_at"}
    for banned in ("key_hash", "api_key_hash", "password_hash", "token_hash",
                   "_key_enc"):
        assert banned not in r.text, banned


def test_rotation_never_lands_an_account_action_on_another_org(make_org, client):
    """account_actions is RLS posture A, but the INSERT still names an org_id in
    application code. A machine rotation must file its record against the org
    that authenticated, and nowhere else."""
    a, b = make_org(), make_org()
    assert client.post("/v1/keys/rotate", headers=a["auth"]).status_code == 200

    db = SessionLocal()
    try:
        rows = db.execute(select(AccountAction).where(
            AccountAction.action == "key.rotate")).scalars().all()
        orgs = {str(r.org_id) for r in rows}
        assert a["org_id"] in orgs
        assert b["org_id"] not in orgs
    finally:
        db.close()
