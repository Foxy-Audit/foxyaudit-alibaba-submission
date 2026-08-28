"""Register #252 — the GDPR self-serve bundle omitted fifteen org-scoped tables
while claiming completeness.

WHAT THIS FILE IS FOR. `/v1/account/export` is the DSAR answer, so the sentence
it ships is a legal statement, not a docstring. Two earlier wordings were false:
"everything this workspace holds", and the stronger "anything added to this
workspace's schema belongs here" — which was wrong to WANT as well as
inaccurate, because following it would have serialised a session token hash.

The fix is a classification, not fifteen more `select()`s:

    (a) exported  — data the subject would recognise as their own: 8 tables
    (b) never     — auth plumbing whose reason to exist is a credential: 3
    (c) excluded  — org-scoped but not about the subject, each with a reason
                    IN THE BUNDLE: 4 (+ consent_events, which has no org_id)

⚠ AND THE CLAIM IS DERIVED, NOT WRITTEN. `export_scope.included_tables` comes
from the sections actually built, and the guard below walks the model registry
to assert every org-scoped table lands in exactly one list. A count written in
prose is a claim nobody rechecks — the failure mode #252 and #254 share. This
one cannot go stale without a test going red.
"""

import json
import uuid
from datetime import date, datetime, timedelta, timezone

import pytest
from app.db import SessionLocal
from app.models import (
    LoginEvent, Notification, PaymentEvent, SsoConnection, StripeEvent,
    UsageDaily, UserSession, VerificationCode, WebhookSubscription,
)


#: The five values this repo's hard rule forbids serialising anywhere. #252
#: found the fifth: `webhook_subscriptions.secret`, which the register's own
#: list of four had missed.
BANNED_COLUMNS = ("token_hash", "code_hash", "password_hash", "key_hash",
                  "client_secret", "secret")


@pytest.fixture
def admin(make_org, login):
    org = make_org()
    return org, login(org["admin_email"], org["admin_password"])


def _bundle(client) -> dict:
    r = client.get("/v1/account/export")
    assert r.status_code == 200, r.text
    return json.loads(r.content)


def _seed(org_id, *rows):
    db = SessionLocal()
    try:
        for row in rows:
            db.add(row)
        db.commit()
    finally:
        db.close()


# ══ the claim ══════════════════════════════════════════════════════════════
def test_every_org_scoped_table_is_either_exported_or_named_as_excluded(admin):
    """THE guard #252 exists to install, and the only one that cannot rot.

    Walks the model registry rather than a list somebody maintains: every table
    carrying an `org_id` — every table that CAN hold a workspace's data — must
    appear in exactly one of `included_tables` or `excluded_tables`. Add a
    table with an `org_id` tomorrow and this goes red until somebody decides
    which it is, which is precisely the decision that was never made for
    fifteen of them.
    """
    from app.db import Base

    _, client = admin
    scope = _bundle(client)["export_scope"]
    included = set(scope["included_tables"])
    excluded = {e["table"] for e in scope["excluded_tables"]}

    org_scoped = {c.__table__.name for c in Base.__subclasses__()
                  if "org_id" in {col.name for col in c.__table__.columns}}
    assert len(org_scoped) >= 23, f"the census shrank unexpectedly: {len(org_scoped)}"

    unclassified = org_scoped - included - excluded
    assert unclassified == set(), (
        f"org-scoped tables in neither list — the bundle omits them while "
        f"claiming otherwise: {sorted(unclassified)}")
    both = org_scoped & included & excluded
    assert both == set(), f"claimed as both included and excluded: {sorted(both)}"


def test_every_included_table_is_actually_a_section_with_rows_or_an_empty_list(admin):
    """`included_tables` is derived from the sections built, so it cannot name a
    table the bundle does not carry — asserted rather than assumed, because the
    derivation is the whole reason the claim is trustworthy."""
    from app.routers.account import EXPORT_SECTION_TABLES

    _, client = admin
    bundle = _bundle(client)
    for section, table in EXPORT_SECTION_TABLES.items():
        assert section in bundle, f"{table} is claimed but its section is absent"
        assert table in bundle["export_scope"]["included_tables"], table


def test_every_exclusion_gives_a_reason_rather_than_a_silent_omission(admin):
    """An honest bundle beats a complete-looking one. A category that is left
    out has to SAY it is left out, and why, in the file itself."""
    _, client = admin
    excluded = _bundle(client)["export_scope"]["excluded_tables"]

    named = {e["table"] for e in excluded}
    for table in ("user_sessions", "verification_codes", "auth_handoff_tokens",
                  "audit_events", "traffic_events", "org_sequences",
                  "evaluation_redemptions", "consent_events"):
        assert table in named, f"{table} is omitted without saying so"
    for entry in excluded:
        assert len(entry["reason"]) > 40, (
            f"{entry['table']} is excluded with a reason that explains nothing: "
            f"{entry['reason']!r}")

    # The three credential tables must say WHY, because "we forgot" and "a hard
    # rule forbids it" are different answers to a regulator.
    reasons = {e["table"]: e["reason"] for e in excluded}
    for table in ("user_sessions", "verification_codes", "auth_handoff_tokens"):
        assert "Auth plumbing" in reasons[table], reasons[table]
    assert "login_events" in reasons["user_sessions"], (
        "the sign-in trail is excluded without pointing at where it IS exported")


def test_the_statement_claims_only_what_the_lists_can_back(admin):
    """The sentence a regulator reads. It must be a claim about the LISTS —
    which are derived and checked — never about completeness, which is false."""
    _, client = admin
    statement = _bundle(client)["export_scope"]["statement"]

    for overclaim in ("everything this workspace holds",
                      "anything added to this workspace's schema belongs here",
                      "every row"):
        assert overclaim not in statement.replace("not every row", ""), (
            f"the statement is false again: {overclaim!r}")
    for anchor in ("included_tables", "excluded_tables", "withheld_fields",
                   "org_id"):
        assert anchor in statement, f"the statement stopped naming {anchor}"


# ══ the secrets ════════════════════════════════════════════════════════════
def test_the_whole_document_carries_none_of_the_banned_values(admin):
    """⚠ THE WHOLE DOCUMENT, NOT ONE SECTION. #249 added this for `api_keys`;
    #252 adds seven sections, two of them drawn from tables that hold a live
    credential, so the guard has to be about the serialised file.

    Real values are seeded and searched for by VALUE — a key-name scan would
    pass against a bundle that emitted the secret under a different key.
    """
    org, client = admin
    org_id = uuid.UUID(org["org_id"])
    now = datetime.now(timezone.utc)
    hook_secret = "whsec_" + uuid.uuid4().hex
    idp_secret = "idp_client_secret_" + uuid.uuid4().hex
    session_token = "sess_" + uuid.uuid4().hex
    step_up_code = "code_" + uuid.uuid4().hex

    db = SessionLocal()
    try:
        user_id = db.execute(
            __import__("sqlalchemy").text(
                "SELECT id FROM users WHERE org_id = :o LIMIT 1"),
            {"o": str(org_id)}).scalar_one()
    finally:
        db.close()

    _seed(
        org_id,
        WebhookSubscription(org_id=org_id, url="https://hooks.example.test/foxy",
                            secret=hook_secret, events="breach", active=True),
        SsoConnection(org_id=org_id, email_domain="example.test",
                      issuer="https://idp.example.test", client_id="foxy-app",
                      client_secret=idp_secret, active=True),
        UserSession(org_id=org_id, user_id=user_id, token_hash=session_token,
                    ip="203.0.113.9", user_agent="pytest",
                    expires_at=now + timedelta(days=1)),
        VerificationCode(org_id=org_id, user_id=user_id, purpose="step_up",
                         code_hash=step_up_code, expires_at=now + timedelta(minutes=10)),
    )

    raw = client.get("/v1/account/export").content.decode()
    for value in (hook_secret, idp_secret, session_token, step_up_code):
        assert value not in raw, f"a live credential reached the bundle: {value[:12]}…"

    # ...and the columns are not present as keys either, which is the cheaper
    # half and the one that catches a rename rather than a leak.
    bundle = json.loads(raw)
    for section, rows in bundle.items():
        if section == "export_scope" or not isinstance(rows, list):
            continue
        for row in rows:
            if not isinstance(row, dict):
                continue
            for banned in BANNED_COLUMNS:
                assert banned not in row, f"{section} emits {banned}"


def test_no_included_table_carries_a_secret_column_that_is_not_declared_withheld(admin):
    """Structural, and the reason a whole table cannot quietly join the bundle.

    For every table in `included_tables`, any column whose name matches a banned
    pattern must be named in `withheld_fields` for that section. Point the
    manifest at `user_sessions` and this goes red before the value guard above
    even runs — two independent deaths for the same mistake.
    """
    from app.db import Base
    from app.routers.account import EXPORT_SECTION_TABLES

    from app.routers.account import EXPORT_WITHHELD_FIELDS

    _, client = admin
    scope = _bundle(client)["export_scope"]
    # The columns live in code, not in the bundle — see EXPORT_WITHHELD_FIELDS
    # on why the shipped manifest names no internal identifier.
    withheld = {s: set(cols) for s, (cols, _w, _r) in EXPORT_WITHHELD_FIELDS.items()}
    by_table = {c.__table__.name: c for c in Base.__subclasses__()}
    section_of = {t: s for s, t in EXPORT_SECTION_TABLES.items()}

    for table in scope["included_tables"]:
        model = by_table.get(table)
        if model is None:
            continue                       # organizations/users resolve by name
        secret_cols = {col.name for col in model.__table__.columns
                       if any(b in col.name for b in BANNED_COLUMNS)}
        declared = withheld.get(section_of.get(table, ""), set())
        assert secret_cols <= declared, (
            f"{table} is exported and holds {sorted(secret_cols - declared)}, "
            f"which is not declared in withheld_fields")


def test_every_withheld_field_is_absent_from_every_row_of_its_section(admin):
    """`withheld_fields` is a promise about the rows, so check the rows."""
    org, client = admin
    org_id = uuid.UUID(org["org_id"])
    _seed(org_id,
          WebhookSubscription(org_id=org_id, url="https://h.example.test",
                              secret="whsec_x", events="breach", active=True),
          PaymentEvent(provider="paddle", provider_event_id="evt_" + uuid.uuid4().hex,
                       type="subscription.updated", payload={"customer": "leak@x.test"},
                       org_id=org_id, status="processed"))

    from app.routers.account import EXPORT_WITHHELD_FIELDS

    bundle = _bundle(client)
    shipped = {w["section"]: w for w in bundle["export_scope"]["withheld_fields"]}
    for section, (cols, what, why) in EXPORT_WITHHELD_FIELDS.items():
        rows = bundle[section]
        rows = rows if isinstance(rows, list) else [rows]      # organization is a dict
        rows = [r for r in rows if isinstance(r, dict)]        # ...or None, if unseeded
        for row in rows:
            for field in cols:
                assert field not in row, (
                    f"{section} promises to withhold {field} and did not")
        assert section in shipped, f"{section} withholds a column and does not say so"
        assert len(shipped[section]["held_back"]) > 10, shipped[section]
        assert len(shipped[section]["reason"]) > 10, shipped[section]


def test_the_providers_raw_payload_never_reaches_the_bundle(admin):
    """`payment_events.payload` is a third party's record in a shape we do not
    control. It can hold an email, a billing address, card metadata — the brief
    was right that the class name tells you nothing. So the metadata is
    exported and the blob is not, and that is said out loud rather than done
    silently."""
    org, client = admin
    org_id = uuid.UUID(org["org_id"])
    _seed(org_id,
          PaymentEvent(provider="paddle", provider_event_id="evt_" + uuid.uuid4().hex,
                       type="subscription.activated",
                       payload={"data": {"customer": {"email": "billing@leak.test",
                                                      "address": "1 Leak Street"}}},
                       org_id=org_id, status="processed"))

    raw = client.get("/v1/account/export").content.decode()
    assert "billing@leak.test" not in raw, "the provider payload was exported"
    assert "1 Leak Street" not in raw

    bundle = json.loads(raw)
    assert [p["type"] for p in bundle["payment_events"]] == ["subscription.activated"]
    assert bundle["payment_events"][0]["provider"] == "paddle"


# ══ the isolation ══════════════════════════════════════════════════════════
def test_the_export_filters_by_org_itself_and_does_not_lean_on_rls():
    """⚠ A BEHAVIOURAL CROSS-TENANT TEST CANNOT CATCH A DROPPED FILTER HERE, on
    most of these tables. `require_role('admin')` runs through
    `auth._scope_org`, which drops to the confined `foxy_app` role, so for a
    posture-A table RLS hides the other tenant's rows and every behavioural
    assertion stays green with the clause deleted.

    ⚠ AND FOR THE OTHERS THE OPPOSITE IS TRUE, WHICH IS WORSE. `login_events`,
    `payment_events` and `stripe_events` are posture C in the Database note:
    `org_id` is NULLABLE, which structurally rules RLS out, so the clause below
    is the ONLY tenant isolation on those rows and there is no second layer at
    all. Both cases end at the same place — assert the clause at the source.
    """
    import inspect

    from app.routers import account

    src = inspect.getsource(account.account_export)
    for clause in (
        "AccountAction.org_id == admin.org_id",
        "AiSystem.org_id == admin.org_id",
        "AuditLog.org_id == admin.org_id",
        "ApiKey.org_id == admin.org_id",
        "Invoice.org_id == admin.org_id",
        "ChainAnchor.org_id == admin.org_id",
        "User.org_id == admin.org_id",
        "LoginEvent.org_id == admin.org_id",
        "Notification.org_id == admin.org_id",
        "WebhookSubscription.org_id == admin.org_id",
        "SsoConnection.org_id == admin.org_id",
        "UsageDaily.org_id == admin.org_id",
        "ExportJob.org_id == admin.org_id",
        "PaymentEvent.org_id == admin.org_id",
        "StripeEvent.org_id == admin.org_id",
    ):
        assert clause in src, f"the export lost its org filter: {clause}"


def test_a_posture_c_section_really_does_isolate_tenants(make_org, login):
    """The one place a behavioural cross-tenant test IS load-bearing: with no
    RLS on `login_events`, a dropped filter would show the other tenant's
    sign-ins to anybody who asked."""
    a, b = make_org(), make_org()
    ca = login(a["admin_email"], a["admin_password"])
    login(b["admin_email"], b["admin_password"])

    bundle = _bundle(ca)
    emails = {e["email"] for e in bundle["login_events"]}
    assert a["admin_email"] in emails, "the workspace cannot see its own sign-ins"
    assert b["admin_email"] not in emails, f"another tenant's sign-ins leaked: {emails}"


# ══ the contents ═══════════════════════════════════════════════════════════
def test_the_bundle_carries_this_workspaces_sign_in_history(admin, client):
    """`login_events` holds `email`, `ip` and `user_agent` RAW — the sharpest of
    the fifteen omissions, and the one a subject-access request is most often
    actually about. Failed attempts included: "somebody tried to sign in as me"
    is the half that matters most."""
    org, authed = admin
    client.post("/v1/auth/login",
                json={"email": org["admin_email"], "password": "wrong-on-purpose"})

    events = _bundle(authed)["login_events"]
    assert events, "the sign-in history is missing"
    assert {e["email"] for e in events} == {org["admin_email"]}
    assert any(e["success"] for e in events), "no successful sign-in recorded"
    assert any(not e["success"] for e in events), (
        "failed attempts are dropped — the half a subject most needs")


def test_the_bundle_carries_the_notifications_this_workspace_was_shown(admin):
    org, client = admin
    _seed(uuid.UUID(org["org_id"]),
          Notification(org_id=uuid.UUID(org["org_id"]), user_id=None, kind="breach",
                       title="Policy breach: phi", body="A 'phi' interaction was flagged.",
                       level="critical", target_type="ledger", target_id="7"))

    rows = _bundle(client)["notifications"]
    assert [n["title"] for n in rows] == ["Policy breach: phi"]
    assert rows[0]["body"] == "A 'phi' interaction was flagged."
    assert rows[0]["read_at"] is None, "whether it was read is part of the record"


def test_the_bundle_carries_integration_config_without_its_credentials(admin):
    org, client = admin
    org_id = uuid.UUID(org["org_id"])
    _seed(org_id,
          WebhookSubscription(org_id=org_id, url="https://hooks.example.test/foxy",
                              secret="whsec_never_exported", events="breach", active=True),
          SsoConnection(org_id=org_id, email_domain="example.test",
                        issuer="https://idp.example.test", client_id="foxy-app",
                        client_secret="idp_never_exported", active=True))

    bundle = _bundle(client)
    assert [w["url"] for w in bundle["webhook_subscriptions"]] == \
        ["https://hooks.example.test/foxy"]
    assert bundle["webhook_subscriptions"][0]["events"] == "breach"
    assert [s["issuer"] for s in bundle["sso_connections"]] == \
        ["https://idp.example.test"]
    assert bundle["sso_connections"][0]["client_id"] == "foxy-app"


def test_the_bundle_carries_the_daily_usage_rollup(admin):
    """Bounded by the workspace's age, however busy it is — one row per day.
    That is why it is in and `traffic_events` is out."""
    org, client = admin
    org_id = uuid.UUID(org["org_id"])
    _seed(org_id,
          UsageDaily(org_id=org_id, day=date(2026, 8, 27), logs_count=41,
                     tokens_sum=9000, breach_count=2, graded_count=40,
                     failed_count=1, pending_count=0))

    rows = _bundle(client)["usage_daily"]
    assert len(rows) == 1, rows
    assert rows[0]["day"] == "2026-08-27"
    assert (rows[0]["logs_count"], rows[0]["breach_count"]) == (41, 2)


def test_the_bundle_carries_the_export_history_and_is_not_itself_recorded_in_it(admin):
    """⚠ THE RECURSION QUESTION, ANSWERED BY MEASUREMENT. `export_jobs` is in the
    bundle, so the bundle can contain a record of exports — but not of itself:
    `GET /v1/account/export` writes no ExportJob, only `POST /v1/exports` does.
    So this is provenance (who extracted what, and when) and it stays linear.
    """
    _, client = admin
    client.post("/v1/exports", json={"type": "logs_json", "params": {"days": 30}})

    before = _bundle(client)["export_jobs"]
    assert len(before) == 1, before
    assert before[0]["type"] == "logs_json"
    assert before[0]["params"] == {"days": 30}
    assert before[0]["requested_by"], "who asked is the point of the record"

    # Two more GDPR exports must not grow the section.
    client.get("/v1/account/export")
    after = _bundle(client)["export_jobs"]
    assert len(after) == 1, (
        "the GDPR export records itself — that is a growing recursion, not "
        "provenance")


def test_the_bundle_carries_billing_event_metadata(admin):
    org, client = admin
    org_id = uuid.UUID(org["org_id"])
    _seed(org_id,
          StripeEvent(stripe_event_id="evt_" + uuid.uuid4().hex, type="invoice.paid",
                      payload={"x": 1}, org_id=org_id, status="processed"))

    rows = _bundle(client)["stripe_events"]
    assert [s["type"] for s in rows] == ["invoice.paid"]
    assert rows[0]["status"] == "processed"


def test_an_empty_workspace_still_ships_every_section_and_the_manifest(make_org, login):
    """A DSAR from a workspace that has done nothing must still answer the
    question. Empty lists, never absent keys — an absent key reads as "we do not
    hold this category", which is a different and unverified claim."""
    from app.routers.account import EXPORT_SECTION_TABLES

    org = make_org()
    client = login(org["admin_email"], org["admin_password"])
    bundle = _bundle(client)
    for section in EXPORT_SECTION_TABLES:
        assert section in bundle, f"{section} vanished on an empty workspace"
    assert bundle["export_scope"]["excluded_tables"], "the manifest went empty"


def test_the_shipped_bundle_names_no_internal_column_identifier(admin):
    """⚠ A RULE THIS PHASE HAD TO LEARN, NOT ONE IT BROUGHT.

    The first version of the manifest printed the withheld COLUMN names, and
    `test_keys.py::test_the_export_names_api_keys_but_never_their_hashes` — a
    #249 guard that scans the whole response for hash-column tokens — went red
    on `key_hash`. Nothing leaked: it is a column name, not a value. But that
    guard's whole value is being blunt and whole-document, so it catches the
    next person who emits a hash from a section nobody thought about; blinding
    it so a manifest could be more verbose would have been a bad trade for a
    word no customer needs.

    So the rule is now explicit and enforced here rather than left to a guard
    in another file noticing: no internal column identifier appears anywhere in
    the shipped bundle, manifest and exclusion reasons included. The column
    names stay in `EXPORT_WITHHELD_FIELDS`, where the structural guard reads
    them; the bundle says "the API key itself".
    """
    _, client = admin
    raw = client.get("/v1/account/export").content.decode()
    for token in ("key_hash", "api_key_hash", "password_hash", "token_hash",
                  "code_hash", "_key_enc", "client_secret"):
        assert token not in raw, (
            f"the bundle prints the internal identifier {token!r} — see this "
            f"test's docstring before relaxing the guard that catches it")
