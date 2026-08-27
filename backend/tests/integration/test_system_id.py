"""The backend accepts an ATTRIBUTION — `event_metadata["system_id"]` (R2).

R1 built the inventory. This is the half that binds an event to one of its rows,
and it MUST BE DEPLOYED BEFORE R3 ships the SDK that sends it: `event_metadata`
is a strict allowlist and ``payload: List[LogIngest]`` is validated as ONE unit,
so an upgraded SDK talking to a backend without this key does not lose one event
— it loses the whole batch to a 422, forever, on precisely the guarded rows the
product exists to preserve.

Four surfaces a new `event_metadata` key touches, and what this file asserts
about each:

  1. the INGEST ALLOWLIST (schemas.py) — widened, and still an allowlist
  2. the DUPLICATE-CONTENT comparison (logs.py) — ASYMMETRIC, not a pop: see
     ``test_a_different_system_on_one_event_id_still_conflicts`` beside
     ``test_a_stripped_resend_is_a_duplicate_not_a_conflict``, which are the two
     halves that a plain pop cannot both satisfy
  3. the JUDGE PROJECTION (judge.py) — NOT widened, deliberately, and driven
     against the bytes each provider is handed rather than against the helper
  4. the SDK DEGRADE LADDER (dispatch.py) — R2 asserted only that the SDK
     RECOGNISES each refusal; R3 shipped the rung and the latch split, so the
     RECOVERY is now driven end-to-end here, the shipped SDK against the shipped
     router. The nesting assumption the ladder rests on is asserted here too,
     because this phase is what keeps it true.

The claim that makes the whole feature safe is that nothing changes for anyone
who does not send a `system_id`. That is guarded, not assumed —
``test_an_event_with_no_attribution_is_the_event_we_accepted_yesterday``.
"""

from __future__ import annotations

import uuid

import pytest
from sqlalchemy import text

from app.db import SessionLocal, engine
from app.models import AiSystem

CANONICAL_TAG = "hipaa"


def _event(**overrides):
    event = {
        "event_id": str(uuid.uuid4()),
        "prompt_hash": "a" * 64,
        "response_hash": "c" * 64,
        "token_count": 7,
        "policy_tag": CANONICAL_TAG,
        "event_type": "interaction",
        "pii_signals": ["phi"],
        "event_metadata": {"model": "gpt-5.6"},
    }
    event.update(overrides)
    return event


def _attributed(system_id: str, **overrides):
    event = _event(**overrides)
    event["event_metadata"] = dict(event["event_metadata"], system_id=system_id)
    return event


def _payload(name: str = "mortgage-bot", **over):
    body = {
        "name": name,
        "purpose": "Answers mortgage eligibility questions for retail customers",
        "provider": "openai",
        "environment": "production",
        "data_classification": "regulated",
        "risk_tier": "high",
    }
    body.update(over)
    return body


@pytest.fixture
def declared(make_org, login):
    """(org dict, admin client, a live system's id) — the ordinary starting state.

    The system is declared through the REAL endpoint rather than inserted, so a
    change to R1's create path that stopped producing usable ids shows up here.
    """
    org = make_org()
    admin = login(org["admin_email"], org["admin_password"])
    created = admin.post("/v1/systems", json=_payload())
    assert created.status_code == 201, created.text
    return org, admin, created.json()["id"]


# ─────────────────────────── surface 1 · the allowlist ───────────────────────

def test_an_attributed_event_ingests(declared, client):
    """THE DEPLOY GATE. Without the widened allowlist this is a 422, and R3
    cannot ship until it is a 202 inside the running container."""
    org, _admin, system_id = declared
    response = client.post("/v1/logs/batch", headers=org["auth"],
                           json=[_attributed(system_id)])
    assert response.status_code == 202, response.text
    assert response.json()["receipts"][0]["status"] == "accepted"


def test_the_attribution_survives_the_round_trip(declared, client):
    """Stored as sent, in event_metadata, under the id the registry gave out."""
    org, _admin, system_id = declared
    client.post("/v1/logs/batch", headers=org["auth"], json=[_attributed(system_id)])
    with engine.begin() as connection:
        rows = connection.execute(
            text("SELECT event_metadata FROM audit_logs WHERE org_id = :o"),
            {"o": org["org_id"]},
        ).mappings().all()
    assert len(rows) == 1
    assert rows[0]["event_metadata"]["system_id"] == system_id


def test_an_unknown_metadata_key_is_still_rejected(declared, client):
    """CONTROL. The allowlist was WIDENED, not opened.

    Without this, adding a key is indistinguishable from deleting the validator
    — and that validator is what keeps raw content out of the ledger.
    """
    org, _admin, system_id = declared
    bad = _attributed(system_id)
    bad["event_metadata"]["prompt_text"] = "the patient's SSN is 123-45-6789"
    response = client.post("/v1/logs/batch", headers=org["auth"], json=[bad])
    assert response.status_code == 422
    assert "unsupported fields" in response.text


def test_an_event_with_no_attribution_is_the_event_we_accepted_yesterday(
        make_org, client):
    """THE BLAST-RADIUS RAIL, GUARDED RATHER THAN ASSUMED.

    The plan's safety property is that nothing changes for anyone who does not
    send a `system_id`. An org with NO declared systems at all posts the payload
    it posted before R2 existed, and it must be accepted, chained and verify —
    the new query must not fire, and its absence must not be reachable as a
    refusal.
    """
    org = make_org()
    response = client.post("/v1/logs/batch", headers=org["auth"], json=[_event()])
    assert response.status_code == 202, response.text
    assert response.json()["receipts"][0]["status"] == "accepted"
    assert client.get("/v1/verify", headers=org["auth"]).json()["ok"] is True

    with engine.begin() as connection:
        stored = connection.execute(
            text("SELECT event_metadata FROM audit_logs WHERE org_id = :o"),
            {"o": org["org_id"]},
        ).scalar_one()
    assert "system_id" not in stored


def test_the_attribution_is_chain_bound(declared, client):
    """It rides INSIDE event_metadata, chain-bound since V2 — so it gets
    tamper-evidence for free, with no new top-level field, no change to
    chain.py's frozen blob and no chain_version bump.

    Proven by tampering: re-point the recorded attribution in the database at a
    different system and /v1/verify must fail. If this passed while the row was
    altered, "which system produced this" would be decorative — an auditor could
    not rely on it, which is the entire point of recording it.
    """
    org, _admin, system_id = declared
    client.post("/v1/logs/batch", headers=org["auth"], json=[_attributed(system_id)])
    assert client.get("/v1/verify", headers=org["auth"]).json()["ok"] is True

    with engine.begin() as connection:
        connection.execute(
            text("UPDATE audit_logs "
                 "SET event_metadata = jsonb_set(event_metadata, '{system_id}', "
                 "to_jsonb(CAST(:other AS text))) "
                 "WHERE org_id = :o AND seq = 1"),
            {"o": org["org_id"], "other": str(uuid.uuid4())},
        )

    assert client.get("/v1/verify", headers=org["auth"]).json()["ok"] is False


def test_a_mixed_export_verifies_through_the_standalone_verifier(declared, client):
    """Old-style rows keep verifying after the wire gains a field.

    event_metadata has been chain-bound since V2, so the new key changes the row
    hash for NEW ROWS ONLY. Asserting that is not proving it, so this drives a
    REAL export through ``verifier/foxy_verify.py`` — the hand-written SECOND
    implementation of the chain recipe. If that copy needed a change to accept
    these rows the two implementations would have diverged, which is the classic
    hash-chain bug and a finding in its own right.

    Interleaved on purpose — plain, attributed, plain, attributed — so a
    verifier that coped only with a clean prefix of legacy rows, or that treated
    the first attributed row as the start of a new regime, still fails.
    """
    import importlib.util
    from pathlib import Path

    org, _admin, system_id = declared
    batch = [_event(), _attributed(system_id), _event(), _attributed(system_id)]
    response = client.post("/v1/logs/batch", headers=org["auth"], json=batch)
    assert response.status_code == 202, response.text

    export = client.get("/v1/logs/export?format=json", headers=org["auth"]).json()
    assert len(export["logs"]) == 4
    carried = [bool((row.get("event_metadata") or {}).get("system_id"))
               for row in sorted(export["logs"], key=lambda r: r["seq"])]
    assert carried == [False, True, False, True], carried

    path = Path(__file__).resolve().parents[3] / "verifier" / "foxy_verify.py"
    spec = importlib.util.spec_from_file_location("foxy_verify_systemid", path)
    verifier = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(verifier)

    assert verifier.verify_export(export)["ok"] is True

    # CONTROL — a verifier that returned ok for everything satisfies the line
    # above. Alter the attribution on an exported row and the independent
    # implementation must reject the chain: the offline half of the claim, in an
    # export a customer verifies themselves rather than inside our own /v1/verify.
    export["logs"][0]["event_metadata"] = dict(
        export["logs"][0].get("event_metadata") or {}, system_id=str(uuid.uuid4()))
    assert verifier.verify_export(export)["ok"] is False


# ────────────────────────── the shape of an identifier ───────────────────────

@pytest.mark.parametrize("value", [
    "not-a-uuid",
    "",
    12345,
    None,
    ["6f1a0e64-1f1a-4c39-9a1e-2b7d4c9f0011"],
    {"id": "6f1a0e64-1f1a-4c39-9a1e-2b7d4c9f0011"},
])
def test_a_value_that_is_not_an_identifier_is_refused(declared, client, value):
    """A `system_id` is refused before anything asks the database about it.

    `None` is in this list on purpose: JSON `null` is not "absent" — the key is
    present and carries a value that is not an id — and reading it as absent
    would let a client send the key with no attribution and be told nothing.
    """
    org, _admin, _system_id = declared
    bad = _event()
    bad["event_metadata"]["system_id"] = value
    response = client.post("/v1/logs/batch", headers=org["auth"], json=[bad])
    assert response.status_code == 422, response.text
    assert "unsupported fields" in response.text


def test_only_the_canonical_spelling_of_an_id_is_accepted(declared, client):
    """`uuid.UUID` accepts five spellings of one id; the ledger accepts one.

    Braces, the URN form, undashed hex and upper case all parse — and this value
    is CHAIN-BOUND and is what per-system reporting groups by, so five spellings
    would be five chain hashes for one attribution and five systems on that
    surface. Refused rather than normalised: rewriting what the caller sent
    would put a spelling in the evidence that nobody typed.

    Note the id used here is a REAL, LIVE system of this org — so a refusal
    cannot be coming from the ownership check, and this test cannot pass for the
    wrong reason.
    """
    org, _admin, system_id = declared
    assert client.post("/v1/logs/batch", headers=org["auth"],
                       json=[_attributed(system_id)]).status_code == 202

    for spelling in ("{%s}" % system_id, f"urn:uuid:{system_id}",
                     system_id.replace("-", ""), system_id.upper()):
        response = client.post("/v1/logs/batch", headers=org["auth"],
                               json=[_attributed(spelling)])
        assert response.status_code == 422, f"{spelling} was accepted"
        assert "unsupported fields" in response.text


def test_the_rejection_does_not_echo_a_malformed_system_id(declared, client):
    """THE ECHO, ASSERTED AGAINST THE RESPONSE BODY RATHER THAN ASSUMED.

    S12e added `main._validation_error_handler` to strip pydantic's `input` —
    which for a list body is the WHOLE item — out of the 422, because a
    validator that rejects a value and then quotes it has moved the value from
    the ledger into the response body, the proxy access log and any dashboard
    toast. That handler is general, so this field inherits it; the brief for
    this phase says to ASSERT that it holds and not to assume it, and this is
    that assertion. A shape rejection is by definition a rejection of something
    that is not a UUID, so it can be any string the caller put there.
    """
    org, _admin, _system_id = declared
    leaky = _event()
    leaky["event_metadata"]["system_id"] = "MRN-4417829"
    response = client.post("/v1/logs/batch", headers=org["auth"], json=[leaky])
    assert response.status_code == 422
    assert "MRN-4417829" not in response.text, response.text


# ────────────────── the attribution has to be one this org can make ──────────

def test_an_undeclared_system_id_is_refused(declared, client):
    """Nothing is inferred from traffic. An id nobody declared names nothing,
    and an event may not claim a system that does not exist."""
    org, _admin, _system_id = declared
    response = client.post("/v1/logs/batch", headers=org["auth"],
                           json=[_attributed(str(uuid.uuid4()))])
    assert response.status_code == 422, response.text
    assert "names no AI system in this workspace" in response.text


def test_another_orgs_system_is_refused_and_is_indistinguishable_from_nothing(
        declared, make_org, login, client):
    """CROSS-TENANT, and the refusal must not confirm the id exists.

    If a foreign id answered differently from an undeclared one, POST
    /v1/logs/batch would be an existence oracle over other customers' estates:
    guess a UUID, watch the answer change. `routers/systems.py` chose 404 over
    403 for this reason, and what mattered there was indistinguishability rather
    than the number.

    Asserted as EQUALITY of the two response bodies with the ids substituted
    out, not as two substring checks — two messages that merely both mention
    "no AI system" can still differ in a way that separates the cases.

    ⚠ The other org's system is REAL AND LIVE, which is what makes this mean
    something: a 422 against a system that did not exist anywhere would pass
    while cross-tenant lookup was wide open.
    """
    org, _admin, _mine = declared
    other = make_org()
    other_admin = login(other["admin_email"], other["admin_password"])
    theirs = other_admin.post("/v1/systems", json=_payload("their-bot"))
    assert theirs.status_code == 201, theirs.text
    foreign_id = theirs.json()["id"]

    # it really is live, in ITS OWN org
    assert other_admin.get(f"/v1/systems/{foreign_id}").json()["retired"] is False

    unknown_id = str(uuid.uuid4())
    foreign = client.post("/v1/logs/batch", headers=org["auth"],
                          json=[_attributed(foreign_id)])
    unknown = client.post("/v1/logs/batch", headers=org["auth"],
                          json=[_attributed(unknown_id)])
    assert foreign.status_code == unknown.status_code == 422
    assert foreign.text.replace(foreign_id, "<id>") \
        == unknown.text.replace(unknown_id, "<id>")

    # and nothing was written under either id
    assert client.get("/v1/logs", headers=org["auth"]).json()["total"] == 0


def test_the_attribution_check_filters_by_org_itself_and_does_not_lean_on_rls():
    """⚠ THE CROSS-TENANT TEST ABOVE CANNOT CATCH A DROPPED `org_id` FILTER.

    `require_org` runs `auth._scope_org`, which drops to the confined `foxy_app`
    role, and `ai_systems` is a posture-A table (ENABLE + FORCE + org_isolation,
    migration 0068). So with `AiSystem.org_id == org.id` deleted from the query,
    RLS still hides the other tenant's row, the lookup still misses, and the
    cross-tenant assertions stay green.

    That is the design working, and the Database note is explicit that it is not
    a reason to drop the clause: staff and worker paths do not run under that
    role. So the clause is asserted at the SOURCE, the same way R1's
    `test_the_export_filters_by_org_itself_and_does_not_lean_on_rls` and
    `test_the_router_filters_by_org_itself_and_does_not_lean_on_rls` do. This is
    the fourth time this shape has come up.

    ⚠ AND IT IS ASSERTED AGAINST THE CODE, NOT THE SOURCE TEXT — because the
    first version of this test was not. `inspect.getsource` returns the
    docstring too, and that function's docstring QUOTES the clause it guards, so
    a plain substring check was satisfied by the prose ABOUT the filter while
    the filter itself was gone. Measured: deleting the clause left this test
    green and the whole file green. That is "checks a token, not the behaviour",
    and it is the trap the house rules name as *a guard that greps a file greps
    its own comment*.

    `ast.unparse` over the body with the docstring dropped removes BOTH comment
    syntaxes at once — `#` lines never survive parsing, and the docstring is
    discarded explicitly below — so what is searched can only be executable
    code. The mutation that deletes the clause now fails exactly this test and
    nothing else, which is the finding: RLS absorbs everything behavioural.
    """
    import ast
    import inspect
    import textwrap

    from app.routers import logs

    tree = ast.parse(textwrap.dedent(
        inspect.getsource(logs._validate_system_attributions)))
    function = tree.body[0]
    body = function.body
    if (isinstance(body[0], ast.Expr) and isinstance(body[0].value, ast.Constant)
            and isinstance(body[0].value.value, str)):
        body = body[1:]                      # the docstring, which quotes the clause
    code = "\n".join(ast.unparse(node) for node in body)
    assert "AiSystem.org_id == org.id" in code, \
        "the attribution check lost its org filter"
    # ANTI-VACUITY: prove the lookup this clause belongs to is still in the code
    # that was searched. Without it, gutting the function entirely would fail
    # this test for the right reason by accident and pass it the moment somebody
    # re-added a differently-named query.
    assert "AiSystem.id.in_" in code, "the attribution lookup is gone entirely"


def test_a_retired_system_accepts_no_new_events(declared, client):
    """R1'S WHOLE POINT, ARRIVING. Retiring is the only way to take a system out
    of service, and this is what "out of service" means.

    The refusal names WHICH system and says retirement is the cause: a bare
    "unsupported fields" sends an operator to the SDK version, which is the
    wrong place entirely — the SDK is fine, the id is well-formed, and a human
    retired the system on purpose.
    """
    org, admin, system_id = declared
    assert client.post("/v1/logs/batch", headers=org["auth"],
                       json=[_attributed(system_id)]).status_code == 202

    assert admin.post(f"/v1/systems/{system_id}/retire").status_code == 200

    response = client.post("/v1/logs/batch", headers=org["auth"],
                           json=[_attributed(system_id)])
    assert response.status_code == 422, response.text
    assert system_id in response.text, "the refusal does not say WHICH system"
    assert "RETIRED" in response.text, "the refusal does not name the cause"
    # the event before the retirement is still there; the one after was not written
    assert client.get("/v1/logs", headers=org["auth"]).json()["total"] == 1


def test_retiring_a_system_leaves_its_existing_evidence_alone(declared, client):
    """"Retire, do not delete" — the row stays, the chain stays, and every event
    already attributed to it still reads and still verifies. A retirement that
    disturbed history would orphan chained evidence, which is why there is no
    DELETE endpoint in the first place."""
    org, admin, system_id = declared
    client.post("/v1/logs/batch", headers=org["auth"], json=[_attributed(system_id)])
    before = client.get("/v1/logs", headers=org["auth"]).json()

    admin.post(f"/v1/systems/{system_id}/retire")

    after = client.get("/v1/logs", headers=org["auth"]).json()
    assert after == before
    assert client.get("/v1/verify", headers=org["auth"]).json()["ok"] is True
    with engine.begin() as connection:
        stored = connection.execute(
            text("SELECT event_metadata FROM audit_logs WHERE org_id = :o"),
            {"o": org["org_id"]},
        ).scalar_one()
    assert stored["system_id"] == system_id


def test_a_live_sibling_still_ingests_after_a_retirement(declared, client):
    """CONTROL for the refusal above — it is about ONE system, not the org.

    Without this, a check that refused every attributed event once anything was
    retired would pass every retirement test in this file.
    """
    org, admin, retired_id = declared
    live = admin.post("/v1/systems", json=_payload("fraud-screener"))
    assert live.status_code == 201, live.text
    live_id = live.json()["id"]
    assert admin.post(f"/v1/systems/{retired_id}/retire").status_code == 200

    response = client.post("/v1/logs/batch", headers=org["auth"],
                           json=[_attributed(live_id)])
    assert response.status_code == 202, response.text
    assert response.json()["receipts"][0]["status"] == "accepted"


def test_one_bad_attribution_refuses_the_whole_batch(declared, client):
    """STATED, BECAUSE IT IS THE COST OF THE DESIGN AND NOT AN ACCIDENT.

    ``payload: List[LogIngest]`` is accepted or refused as one unit — the chain
    is sequential and a partially-applied batch would need a per-item receipt
    vocabulary that does not exist. So an eleventh event naming a retired system
    costs the other ten their POST. That is survivable ONLY because the refusal
    is degradable (below): the SDK strips the attribution and the ten land.
    """
    org, admin, system_id = declared
    admin.post(f"/v1/systems/{system_id}/retire")
    batch = [_event(), _event(), _attributed(system_id)]
    response = client.post("/v1/logs/batch", headers=org["auth"], json=batch)
    assert response.status_code == 422, response.text
    assert client.get("/v1/logs", headers=org["auth"]).json()["total"] == 0


def test_a_resend_is_not_refused_by_a_retirement_that_happened_afterwards(
        declared, client):
    """NEW ITEMS ONLY, and this is why.

    A duplicate is already chained. Refusing its resend would brick a spool over
    an event this ledger already holds, and no new attribution is being made
    either way — the stored row is not rewritten by a duplicate. Retirement
    closes what a system may still RECORD; it must not reach back into what it
    already did, or an SDK whose ack was lost can never drain.
    """
    org, admin, system_id = declared
    event = _attributed(system_id)
    first = client.post("/v1/logs/batch", headers=org["auth"], json=[event])
    assert first.status_code == 202, first.text

    assert admin.post(f"/v1/systems/{system_id}/retire").status_code == 200

    resend = client.post("/v1/logs/batch", headers=org["auth"], json=[event])
    assert resend.status_code == 202, resend.text
    assert resend.json()["receipts"][0]["status"] == "duplicate"


# ───────────── surface 2 · the duplicate-content comparison, asymmetric ──────

def _without_system_id(event):
    """The same event as the SDK's degrade path would resend it."""
    stripped = dict(event)
    stripped["event_metadata"] = {key: value
                                  for key, value in event["event_metadata"].items()
                                  if key != "system_id"}
    return stripped


def test_a_stripped_resend_is_a_duplicate_not_a_conflict(declared, client):
    """THE DEADLOCK GUARD — half one of the asymmetric rule.

    A row stored WITH an attribution, resent WITHOUT one. Not hypothetical:
    `system_id` is client-supplied so it persists in the stored row, and R3 adds
    it to the SDK's degrade ladder. A spool entry that outlives its POST (a
    crash before the ack) is later resent to a backend rolled back below R2; the
    SDK strips the key and retries. If the comparison counted it, that resend
    could never match its own stored row: 409 forever, taking the other nine
    events in the batch down on every retry, and the spool never drains.
    """
    org, _admin, system_id = declared
    event = _attributed(system_id)
    first = client.post("/v1/logs/batch", headers=org["auth"], json=[event])
    assert first.status_code == 202, first.text

    resend = client.post("/v1/logs/batch", headers=org["auth"],
                         json=[_without_system_id(event)])
    assert resend.status_code == 202, resend.text
    assert resend.json()["receipts"][0]["status"] == "duplicate"


def test_an_attribution_arriving_late_is_a_duplicate_too(declared, client):
    """The other direction, because the rule is symmetric about ABSENCE.

    Stored WITHOUT, resent WITH — an SDK that degraded and then recovered, or a
    row written by an older SDK and retried by a newer one. Handling only the
    stored side would leave this one 409ing.
    """
    org, _admin, system_id = declared
    event = _attributed(system_id)
    first = client.post("/v1/logs/batch", headers=org["auth"],
                        json=[_without_system_id(event)])
    assert first.status_code == 202, first.text

    resend = client.post("/v1/logs/batch", headers=org["auth"], json=[event])
    assert resend.status_code == 202, resend.text
    assert resend.json()["receipts"][0]["status"] == "duplicate"


def test_a_different_system_on_one_event_id_still_conflicts(declared, client):
    """THE HALF A PLAIN POP CANNOT DELIVER, and the reason the rule is asymmetric.

    `system_id` is IDENTITY-BEARING, unlike the three keys that ARE popped: two
    posts of one event_id claiming two different AI systems are a real
    disagreement about the evidence. Popping it outright would answer the second
    with a 202 "duplicate" while the ledger went on holding the first — a client
    told its attribution landed when it did not, on the one surface whose value
    is being able to trust what it says.

    So: ignored when only ONE side carries it (the degrade shape, above),
    compared when BOTH do (this).
    """
    org, admin, system_id = declared
    second = admin.post("/v1/systems", json=_payload("fraud-screener"))
    assert second.status_code == 201, second.text

    event = _attributed(system_id)
    assert client.post("/v1/logs/batch", headers=org["auth"],
                       json=[event]).status_code == 202

    reattributed = dict(event)
    reattributed["event_metadata"] = dict(event["event_metadata"],
                                          system_id=second.json()["id"])
    response = client.post("/v1/logs/batch", headers=org["auth"],
                           json=[reattributed])
    assert response.status_code == 409, response.text
    assert "already used with different content" in response.text


def test_a_stripped_resend_does_not_rewrite_the_stored_attribution(declared, client):
    """The claim that makes the asymmetry safe for EVIDENCE, asserted.

    A duplicate returns the original receipt; it never writes. So the attribution
    an auditor reads is the one from the POST that was chained, and no resend —
    stripped or not — can quietly replace it or move the chain.
    """
    org, _admin, system_id = declared
    event = _attributed(system_id)
    original = client.post("/v1/logs/batch", headers=org["auth"],
                           json=[event]).json()["receipts"][0]

    duplicate = client.post("/v1/logs/batch", headers=org["auth"],
                            json=[_without_system_id(event)]).json()["receipts"][0]
    assert duplicate["seq"] == original["seq"]
    assert duplicate["chain_hash"] == original["chain_hash"]

    with engine.begin() as connection:
        stored = connection.execute(
            text("SELECT event_metadata FROM audit_logs WHERE org_id = :o"),
            {"o": org["org_id"]},
        ).scalar_one()
    assert stored["system_id"] == system_id
    assert client.get("/v1/verify", headers=org["auth"]).json()["ok"] is True


def test_the_other_three_keys_are_still_popped(declared, client):
    """CONTROL. The asymmetric rule was ADDED, not swapped in for the pop.

    Without this, replacing the pop loop with the new rule passes every test
    above while `policy_tag_raw` and the ruleset keys go back to deadlocking a
    stripped resend — the failure S12 spent five gate rounds on.
    """
    org, _admin, system_id = declared
    event = _attributed(system_id)
    event["event_metadata"].update({"policy_tag_raw": "HIPAA",
                                    "ruleset_version": "2026.08.4",
                                    "ruleset_hash": "b" * 64,
                                    "policy_rules": ["phi.ssn_pattern"]})
    assert client.post("/v1/logs/batch", headers=org["auth"],
                       json=[event]).status_code == 202

    stripped = dict(event)
    stripped["event_metadata"] = {
        key: value for key, value in event["event_metadata"].items()
        if key not in ("policy_tag_raw", "ruleset_version", "ruleset_hash")}
    resend = client.post("/v1/logs/batch", headers=org["auth"], json=[stripped])
    assert resend.status_code == 202, resend.text
    assert resend.json()["receipts"][0]["status"] == "duplicate"


# ───────────── surface 3 · the judge projection is NOT widened ───────────────

def test_the_attribution_never_reaches_a_judge_provider(monkeypatch):
    """THE DECISION, DRIVEN AGAINST THE BYTES EACH PROVIDER IS HANDED.

    Asserted through ``worker._judge_verdict`` — the boundary where the
    projection happens and the only place either provider is called — rather
    than against the projection helper. A guard that called the helper was green
    for months while `gemini.evaluate` json.dumps'd the whole event_metadata
    dict to Google (#246 §1), so the helper proves nothing about a caller that
    never calls it. That file's own DRIVER is imported rather than re-written
    here, for the same reason: this file must not grow a second idea of how the
    boundary is reached.

    ⚠ WHY OMITTED RATHER THAN ADDED. It buys a verdict nothing — nothing in the
    projection tells a judge what the system IS, so an opaque id is a symbol the
    grader cannot reason from. And it costs a correlation handle: unlike
    request_id / trace_id / session_id, this value is stable for the whole life
    of a declared system, so it would let a provider partition one customer's
    traffic into their individual AI products and profile each over time. The
    linkage is the payload; the digits carry nothing, which is why "it is only a
    UUID" is not the question.
    """
    from tests.integration.test_judge_content_blindness import _drive_both

    system_id = str(uuid.uuid4())
    meta = {
        "prompt_hash": "a" * 64, "response_hash": "c" * 64, "token_count": 42,
        "policy_tag": "hipaa", "pii_signals": ["phi"],
        "event_id": str(uuid.uuid4()), "event_type": "interaction",
        "commitment_alg": "hmac-sha256",
        # a SAFE key beside it, so a projection that simply empties the dict
        # cannot satisfy this guard by accident
        "event_metadata": {"system_id": system_id, "model": "gpt-5.6"},
    }
    captured = _judge_capture(monkeypatch)
    _drive_both(monkeypatch, meta)
    assert set(captured) == {"gemini", "openai"}, captured
    for provider, body in captured.items():
        assert system_id not in body, f"{provider} was handed the attribution"
        assert "system_id" not in body
        assert "gpt-5.6" in body, f"{provider} lost the keys a judge does need"


def test_the_projection_allowlist_does_not_contain_the_attribution():
    """The same decision at the list, so a future reader sees it was decided.

    Cheap and static — the test above is the one that proves the property. This
    one fails loudly if someone adds the key to the list without reading why it
    is not there.
    """
    from app.judge import SAFE_EVENT_METADATA

    assert "system_id" not in SAFE_EVENT_METADATA


# ───────────── surface 4 · the SDK's degrade ladder stays usable ─────────────

def _sdk_probe():
    """The REAL dispatch._rejects_unsupported_fields, not a copy of its rule.

    Imported from sdk/src rather than reimplemented here: a copy would keep
    agreeing with itself after the SDK changed, which is the exact failure this
    guards. The SDK is stdlib-only, so it imports cleanly into the backend venv.
    """
    import pathlib
    import sys

    sdk_src = pathlib.Path(__file__).resolve().parents[3] / "sdk" / "src"
    if str(sdk_src) not in sys.path:
        sys.path.insert(0, str(sdk_src))
    from foxy_audit.dispatch import _rejects_unsupported_fields

    return _rejects_unsupported_fields


def _sdk_dispatch():
    """The REAL dispatch MODULE, not just its probe.

    Imported from sdk/src rather than reimplemented here, for the reason
    `_sdk_probe` gives: a copy would keep agreeing with itself after the SDK
    changed, which is the exact failure this guards. The SDK is stdlib-only, so
    it imports cleanly into the backend venv.
    """
    import pathlib
    import sys

    sdk_src = pathlib.Path(__file__).resolve().parents[3] / "sdk" / "src"
    if str(sdk_src) not in sys.path:
        sys.path.insert(0, str(sdk_src))
    from foxy_audit import dispatch

    return dispatch


def _degrade_through_the_sdk(tmp_path, http, headers, events):
    """Drive the REAL SDK degrade path against the REAL backend.

    `AsyncDispatcher._post` is redirected at the HTTP boundary — the one seam
    between the two halves — so everything above it is the shipped SDK and
    everything below it is the shipped router. Nothing about either refusal is
    simulated.

    Returns (every body POSTed, the spool, the endpoint).
    """
    import json

    dispatch = _sdk_dispatch()
    from foxy_audit.spool import EventSpool

    endpoint = "http://backend.test/v1/logs/batch"
    spool = EventSpool(str(tmp_path / "spool.sqlite3"))
    for event in events:
        spool.enqueue(endpoint, "foxy_sk_test", event)

    posted = []

    def _post(_endpoint, _api_key, body):
        posted.append(json.loads(json.dumps(body)))
        return http.post("/v1/logs/batch", headers=headers, json=body)

    # ⚠ A PRIVATE DISPATCHER AND AN INSTANCE ATTRIBUTE, never the module
    # singleton and never a class-level patch. The singleton runs a background
    # thread as soon as anything calls `submit`/`resume`, and that thread loops
    # on `_flush_spool()` with no argument — so a class patch is live for it
    # too, and it will wander into another spool and append to `posted`. Green
    # in isolation, intermittently red in a suite, blaming whichever test the
    # thread reached. A fresh instance starts no thread.
    dispatcher = dispatch.AsyncDispatcher()
    dispatcher._post = _post
    dispatcher._paths = {str(tmp_path / "spool.sqlite3")}
    dispatch._no_provenance.clear()
    dispatcher._flush_spool({str(tmp_path / "spool.sqlite3")})
    return posted, spool, endpoint


def _spooled(system_id=None, **overrides):
    """An event shaped for the spool: it needs a `client_id` to sequence on."""
    event = (_attributed(system_id, **overrides) if system_id is not None
             else _event(**overrides))
    event["client_id"] = "c" * 32
    return event


def test_every_attribution_refusal_is_one_the_sdk_can_degrade_from(declared, client):
    """THE SPOOL. A 422 the probe does not recognise re-queues the batch forever.

    ``payload: List[LogIngest]`` is refused as ONE unit, and
    dispatch._rejects_unsupported_fields decides whether to strip and retry by
    matching "unsupported fields" in the body. If it says no, raise_for_status
    raises and spool.retry re-queues everything — the same evidence outage the
    duplicate rule above exists to prevent, arriving through the rejection door
    instead.

    So EVERY refusal this phase can produce is driven through the REAL probe:
    the shape refusal (pydantic), and both ownership refusals (the router). They
    come from two different layers and only one of them inherits schemas.py's
    wording by construction.

    ⚠ RECOGNITION ONLY. That is all this asserts, and the name says so: the
    probe returns True, which means the SDK will *attempt* a degrade. Whether
    the attempt SUCCEEDS is a property of the ladder, which lives in the SDK —
    and it is asserted end-to-end by
    ``test_the_sdk_actually_recovers_from_every_attribution_refusal`` below.
    Until R3 the ladder could not recover from any of these, so this test's
    older prose — which promised recovery — described something no version of
    the SDK then did.
    """
    org, admin, system_id = declared
    retired = admin.post("/v1/systems", json=_payload("legacy-bot"))
    admin.post(f"/v1/systems/{retired.json()['id']}/retire")

    malformed = _event()
    malformed["event_metadata"]["system_id"] = "not-a-uuid"
    cases = {
        "malformed": malformed,
        "undeclared": _attributed(str(uuid.uuid4())),
        "retired": _attributed(retired.json()["id"]),
    }
    probe = _sdk_probe()
    for label, event in cases.items():
        response = client.post("/v1/logs/batch", headers=org["auth"], json=[event])
        assert response.status_code == 422, f"{label}: {response.text}"
        assert probe(response), f"the SDK would brick its spool on {label}"


def test_the_sdk_actually_recovers_from_every_attribution_refusal(
        declared, client, tmp_path):
    """RECOVERY, END TO END — the shipped SDK against the shipped router.

    The test above proves the SDK RECOGNISES each refusal. Recognising it is
    only half: a strip that removes nothing makes the resend byte-identical to
    the request that just failed, which `_strip_provenance` correctly refuses to
    send — so the batch would still re-queue forever, having merely looked at
    the 422 first. Until R3's rung existed, that was the SDK's actual behaviour
    on every one of these.

    Each case therefore ends where it has to end: a 202, the events chained, and
    the spool EMPTY.
    """
    org, admin, live = declared
    retired = admin.post("/v1/systems", json=_payload("legacy-bot"))
    retired_id = retired.json()["id"]
    admin.post(f"/v1/systems/{retired_id}/retire")

    for label, bad in (("retired", _spooled(retired_id)),
                       ("undeclared", _spooled(str(uuid.uuid4())))):
        healthy = _spooled(live)
        posted, spool, _endpoint = _degrade_through_the_sdk(
            tmp_path / label, client, org["auth"], [healthy, bad])

        assert len(posted) == 2, f"{label}: expected one refusal and one resend"
        assert spool.due(10) == [], f"{label}: the batch re-queued — a spool brick"
        # 🔴 #256, AT THE ONLY LAYER THAT CAN PROVE IT. The healthy system's
        # event keeps its attribution: only the named system's is dropped, and
        # nothing is latched, so the next batch is not degraded either.
        #
        # Keyed by event_id rather than by position: what the spool hands back
        # is the spool's business, and an assertion that quietly depended on it
        # would be anchored to an order rather than to an event.
        resent = {event["event_id"]: event for event in posted[-1]}
        assert resent[healthy["event_id"]]["event_metadata"]["system_id"] == live
        assert "system_id" not in resent[bad["event_id"]]["event_metadata"], label
        assert not _sdk_dispatch()._no_provenance, (
            f"{label}: one refused system latched the whole endpoint")

    with SessionLocal() as db:
        stored = db.execute(text(
            "SELECT event_metadata FROM audit_logs WHERE org_id = :o"),
            {"o": org["org_id"]}).scalars().all()
    attributions = sorted((m or {}).get("system_id") or "" for m in stored)
    assert attributions == ["", "", live, live], attributions


def test_a_malformed_attribution_degrades_through_the_capability_branch(
        declared, client, tmp_path):
    """THE FAIL-SAFE, WHERE IT IS ACTUALLY REACHED.

    `schemas._system_id_is_a_system_identifier` refuses a bad SHAPE without
    quoting the value — it must, since the value is by definition not a UUID and
    could be anything a caller put there. So the message names no id, and the
    SDK reads it as what it looks like: this endpoint cannot hold an attribution.
    It strips endpoint-wide and latches.

    That is a coarser outcome than the semantic branch, and it is the RIGHT one
    here: a shape this bad means nothing about the batch can be trusted to name
    a system. The SDK never produces it — `client._checked_system_id` refuses
    the spelling at configure time — so the only way in is a hand-edited spool,
    which is exactly what this drives.
    """
    org, _admin, live = declared
    malformed = _spooled(live)
    malformed["event_metadata"]["system_id"] = "not-a-uuid"
    posted, spool, endpoint = _degrade_through_the_sdk(
        tmp_path, client, org["auth"], [malformed])

    assert spool.due(10) == [], "the batch re-queued — a spool brick"
    assert "system_id" not in posted[-1][0]["event_metadata"]
    dispatch = _sdk_dispatch()
    assert list(dispatch._no_provenance) == [
        (endpoint, dispatch._DEGRADED_SYSTEM_ID)], dispatch._no_provenance
    dispatch._no_provenance.clear()

def test_the_two_refusal_layers_have_different_detail_SHAPES(declared, client):
    """🔴 R3b — THE PREMISE THE SDK'S LATCH SPLIT RESTS ON, GUARDED AT ITS SOURCE.

    From 1.14.0 the SDK tells a SEMANTIC refusal (this system is retired or is
    not yours) from a CAPABILITY refusal (this backend cannot hold the key) by
    the SHAPE of `detail`, because the two are raised differently:

      * the ownership refusals are `HTTPException(422, detail="…")`, which
        FastAPI serialises as `{"detail": "<a string>"}`;
      * everything the pydantic validators refuse — the unknown key, and the
        VALUE errors for `system_id` and `policy_tag_raw` — arrives as
        `RequestValidationError`, which is ALWAYS a list of error objects, and
        `main._validation_error_handler` keeps that shape while redacting.

    ⚠ IT CANNOT BE THE MESSAGE, AND THAT IS WHY THIS TEST IS HERE. Both layers
    must carry "unsupported fields" or `dispatch._rejects_unsupported_fields`
    stops recognising the refusal and `spool.retry` re-queues the batch forever
    — so the wording is deliberately identical and can never be the
    discriminator. And a body naming an id is NOT rare: FastAPI's stock handler
    echoes the rejected event in `input`, this workspace's `system_id` included,
    on every deployment older than `eeed428`. An SDK matching on "does the body
    mention one of my ids" therefore reads a capability refusal about an
    unrelated key as "your system is retired" — a false receipt about a healthy
    system, on every batch.

    So: change how a refusal here is RAISED and this breaks, loudly, in the
    phase that owns the message rather than in a customer's spool.
    """
    org, admin, live = declared
    retired = admin.post("/v1/systems", json=_payload("legacy-bot"))
    retired_id = retired.json()["id"]
    admin.post(f"/v1/systems/{retired_id}/retire")

    unknown = _event()
    unknown["event_metadata"]["totally_unknown_key"] = "x"
    bad_shape = _event()
    bad_shape["event_metadata"]["system_id"] = "not-a-uuid"
    bad_spelling = _event()
    bad_spelling["event_metadata"]["policy_tag_raw"] = "PCI"

    #: label -> (event, the type `detail` must have)
    cases = {
        "ownership/retired": (_attributed(retired_id), str),
        "ownership/undeclared": (_attributed(str(uuid.uuid4())), str),
        "capability/unknown-key": (unknown, list),
        "value/system_id-shape": (bad_shape, list),
        "value/policy_tag_raw-fold": (bad_spelling, list),
    }
    probe = _sdk_probe()
    for label, (event, shape) in cases.items():
        response = client.post("/v1/logs/batch", headers=org["auth"],
                               json=[event])
        assert response.status_code == 422, f"{label}: {response.text}"
        # Still recognisable, or the spool bricks — the older guarantee, which
        # the shape split must not have quietly traded away.
        assert probe(response), f"{label} is no longer degradable"
        detail = response.json()["detail"]
        assert isinstance(detail, shape), (
            f"{label}: detail is {type(detail).__name__}, not {shape.__name__} "
            "— the SDK's latch split reads this shape")

    # And the SDK agrees, driven rather than restated: only the string-shaped
    # refusals name a system the SDK may act on.
    dispatch = _sdk_dispatch()
    for label, (event, shape) in cases.items():
        response = client.post("/v1/logs/batch", headers=org["auth"],
                               json=[event])
        named = dispatch._refused_attributions(response, [event])
        assert bool(named) is (shape is str), f"{label}: {named}"


def test_a_capability_refusal_quotes_the_attribution_only_when_it_is_stripped(
        declared, client):
    """The echo `eeed428` closed, asserted from the SDK's side of it.

    This deployment redacts `input`, so a capability refusal here does NOT quote
    the id — which is exactly why an SDK relying on that absence would work in
    this test suite and fail in the field, against every older deployment. The
    SDK's guard is the SHAPE, so it does not care either way; this pins what
    THIS backend does so a regression in the redaction is caught here.
    """
    org, _admin, live = declared
    event = _attributed(live)
    event["event_metadata"]["totally_unknown_key"] = "x"
    response = client.post("/v1/logs/batch", headers=org["auth"], json=[event])

    assert response.status_code == 422
    assert live not in response.text, (
        "the 422 echoed the attribution back — main._validation_error_handler "
        "has stopped stripping `input`")


def test_a_genuinely_malformed_payload_is_still_not_degradable(declared, client):
    """THE CONTROL, and the reason the probe is narrow.

    A bad hash must NOT look like "strip some keys and retry" — retrying with
    fewer fields is not a fix there, it is a second way to be wrong. If this
    phase's messages had been written broadly enough to make every 422
    degradable, this is what would catch it.
    """
    org, _admin, system_id = declared
    response = client.post("/v1/logs/batch", headers=org["auth"],
                           json=[_attributed(system_id, prompt_hash="z" * 64)])
    assert response.status_code == 422
    assert not _sdk_probe()(response), response.text


def test_the_allowlist_only_grew_so_the_ladder_stays_nested(declared, client):
    """WHAT R3 IS ALLOWED TO RELY ON, ASSERTED HERE RATHER THAN THERE.

    `dispatch._DEGRADE_LADDER` escalates one rung at a time on the assumption
    that the key sets a backend can refuse are NESTED — {} ⊂ {system_id} ⊂
    {system_id, policy_tag_raw} ⊂ {system_id, policy_tag_raw, ruleset_*} —
    which holds only because the ingest allowlist has never had a key taken
    away. R3 added `system_id` as the FIRST rung, because it is the newest key
    and therefore the one the most backends refuse, and inherits that
    assumption.

    This phase is what keeps it true, so this is where it is guarded, and it is
    guarded BEHAVIOURALLY: one event carrying every degradable key at once must
    be accepted, in the ladder's own order. A backend that knows `system_id` therefore necessarily knows
    the older keys, which is precisely the nesting the ladder rests on. A source
    grep for the string would pass on a key that only appears in a comment.
    """
    org, _admin, system_id = declared
    event = _attributed(system_id)
    every_rung = [key for _name, keys, _why in _sdk_dispatch()._DEGRADE_LADDER
                  for key in keys]
    assert every_rung[0] == "system_id", every_rung
    event["event_metadata"].update({"policy_tag_raw": "HIPAA",
                                    "ruleset_version": "2026.08.4",
                                    "ruleset_hash": "b" * 64})
    assert set(every_rung) <= set(event["event_metadata"]), (
        "a rung this event does not carry: %s" % every_rung)
    response = client.post("/v1/logs/batch", headers=org["auth"], json=[event])
    assert response.status_code == 202, response.text
    assert response.json()["receipts"][0]["status"] == "accepted"


# ────────────────────────────── the registry itself ─────────────────────────

def test_an_attribution_can_name_a_draft_system(declared, client):
    """Only RETIREMENT closes a system to new events — `draft` does not.

    'draft' is a declaration a customer has not finished writing, not a system
    that must not record: refusing it would make the obvious way to try Foxy
    against a new product ("declare it, point the SDK at it, see what comes
    back") fail with a message about retirement. Stated because it is a
    decision, and because the alternative is one line away.
    """
    org, admin, _live = declared
    draft = admin.post("/v1/systems", json=_payload("pilot-bot",
                                                    lifecycle_status="draft"))
    assert draft.status_code == 201, draft.text
    response = client.post("/v1/logs/batch", headers=org["auth"],
                           json=[_attributed(draft.json()["id"])])
    assert response.status_code == 202, response.text


def test_the_check_reads_the_committed_lifecycle_not_a_cached_row(declared, client):
    """The refusal follows the DATABASE, not a value captured at declaration.

    Retirement happens on a different request, through a different session, so a
    check that trusted anything cached would keep accepting events for a system
    a human retired minutes ago. Driven by mutating the row underneath the API,
    which is also the shape a future admin-side or migration writer would take.
    """
    org, _admin, system_id = declared
    db = SessionLocal()
    try:
        system = db.get(AiSystem, uuid.UUID(system_id))
        system.lifecycle_status = "retired"
        db.commit()
    finally:
        db.close()

    response = client.post("/v1/logs/batch", headers=org["auth"],
                           json=[_attributed(system_id)])
    assert response.status_code == 422, response.text
    assert "RETIRED" in response.text


def _judge_capture(monkeypatch):
    """Capture the request body each judge provider is handed — no network.

    A local copy of test_judge_content_blindness's `sent` fixture body, because
    a fixture cannot be imported and used as one from another module. The
    DRIVER (`_drive_both`) IS imported, which is the half that matters: this
    file must not grow its own idea of how the boundary is reached.
    """
    import json
    import sys
    import types

    from app import openai_judge

    captured: dict[str, str] = {}
    clean = {"policy_breach": False, "reason": "nothing of note",
             "risk_score": 0, "decision": "clean", "rules": []}

    class _FakeGenAI:
        def configure(self, api_key=None, **_kw):
            pass

        def GenerativeModel(self, model_id, *_a, **_kw):  # noqa: N802 — SDK's name
            return types.SimpleNamespace(
                generate_content=lambda contents, **_kwargs: (
                    captured.__setitem__("gemini", contents),
                    types.SimpleNamespace(text=json.dumps(clean)),
                )[1])

    fake_genai = _FakeGenAI()
    monkeypatch.setitem(sys.modules, "google.generativeai", fake_genai)
    google_pkg = sys.modules.get("google")
    if google_pkg is not None:
        monkeypatch.setattr(google_pkg, "generativeai", fake_genai, raising=False)

    class _FakeResponse:
        def __enter__(self):
            return self

        def __exit__(self, *exc):
            return False

        def read(self):
            return json.dumps({"output_text": json.dumps(clean)}).encode()

    def _fake_urlopen(request, timeout=None):
        captured["openai"] = request.data.decode("utf-8")
        return _FakeResponse()

    monkeypatch.setattr(openai_judge.urllib_request, "urlopen", _fake_urlopen)
    return captured
