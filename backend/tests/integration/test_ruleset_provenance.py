"""Ruleset provenance keys are accepted, chained, and still content-blind (S4).

This is the half that MUST DEPLOY FIRST. `event_metadata` is validated against a
strict allowlist, and `payload: List[LogIngest]` is validated as ONE unit, so an
SDK sending these keys to a backend without them does not lose one event — it
loses the whole batch to a 422, on precisely the guarded rows the product exists
to preserve.

These tests are therefore the deploy gate for that ordering: they fail on a
backend that has not widened the allowlist.
"""

from __future__ import annotations

import json
import uuid

from sqlalchemy import text

from app.db import engine

RULESET_VERSION = "2026.08.1"
RULESET_HASH = "b" * 64          # opaque to the backend; the SDK owns its meaning


def _event(**overrides):
    event = {
        "event_id": str(uuid.uuid4()),
        "prompt_hash": "a" * 64,
        "response_hash": "c" * 64,
        "token_count": 0,
        "policy_tag": "hipaa",
        "event_type": "blocked",
        "pii_signals": ["prompt_injection"],
        "event_metadata": {
            "decision": "blocked",
            "blocked_reason": "prompt_injection",
            "policy_rules": ["injection.ignore_previous"],
            "ruleset_version": RULESET_VERSION,
            "ruleset_hash": RULESET_HASH,
        },
    }
    event.update(overrides)
    return event


def test_a_row_carrying_ruleset_provenance_ingests(make_org, client):
    """THE DEPLOY GATE. Without the widened allowlist this is a 422."""
    org = make_org()
    response = client.post("/v1/logs/batch", headers=org["auth"], json=[_event()])
    assert response.status_code == 202, response.text
    assert response.json()["receipts"][0]["status"] == "accepted"


def test_the_provenance_survives_the_round_trip(make_org, client):
    """Stored verbatim — an auditor reads these two strings out of the export."""
    org = make_org()
    client.post("/v1/logs/batch", headers=org["auth"], json=[_event()])

    rows = client.get("/v1/logs", headers=org["auth"]).json()["items"]
    metadata = rows[0]["event_metadata"]
    assert metadata["ruleset_version"] == RULESET_VERSION
    assert metadata["ruleset_hash"] == RULESET_HASH


def test_provenance_is_chain_bound(make_org, client):
    """It rides INSIDE event_metadata, which has been chain-bound since V2 — so
    it gets tamper-evidence for free, with no new top-level field, no change to
    chain.py's frozen blob and no chain_version bump.

    Proven by tampering: flip the recorded hash in the database and /v1/verify
    must fail. If this passes while the row is altered, the provenance is
    decorative and an auditor could not rely on it.
    """
    org = make_org()
    client.post("/v1/logs/batch", headers=org["auth"], json=[_event()])
    assert client.get("/v1/verify", headers=org["auth"]).json()["ok"] is True

    with engine.begin() as connection:
        connection.execute(
            text("UPDATE audit_logs "
                 "SET event_metadata = jsonb_set(event_metadata, "
                 "'{ruleset_hash}', '\"deadbeef\"') "
                 "WHERE org_id = :o AND seq = 1"),
            {"o": org["org_id"]},
        )

    assert client.get("/v1/verify", headers=org["auth"]).json()["ok"] is False


def test_an_unknown_metadata_key_is_still_rejected(make_org, client):
    """CONTROL. The allowlist was WIDENED, not opened.

    Without this, adding the two keys is indistinguishable from deleting the
    validator — and that validator is what keeps raw text out of the ledger.
    """
    org = make_org()
    bad = _event()
    bad["event_metadata"]["prompt_text"] = "the patient's SSN is 123-45-6789"
    response = client.post("/v1/logs/batch", headers=org["auth"], json=[bad])
    assert response.status_code == 422
    assert "unsupported fields" in response.text


def test_one_bad_row_still_rejects_the_whole_batch(make_org, client):
    """CONTROL for the deploy ordering, and the reason it matters.

    This pins the behaviour the ordering argument rests on: validation is
    per-REQUEST, so a single unacceptable event takes every event beside it
    down. If this ever became per-item, the "must deploy first" rule could be
    relaxed — and until then it must not be.
    """
    org = make_org()
    good = _event()
    bad = _event()
    bad["event_metadata"]["nope"] = "x"
    response = client.post("/v1/logs/batch", headers=org["auth"], json=[good, bad])
    assert response.status_code == 422

    rows = client.get("/v1/logs", headers=org["auth"]).json()["items"]
    assert rows == [], "the good row in a rejected batch must not have landed"


def test_provenance_is_size_bounded_like_every_other_label(make_org, client):
    """The existing 256-char guard covers the new keys for free — asserted, so
    a future refactor cannot quietly exempt them."""
    org = make_org()
    oversized = _event()
    oversized["event_metadata"]["ruleset_version"] = "v" * 300
    response = client.post("/v1/logs/batch", headers=org["auth"], json=[oversized])
    assert response.status_code == 422
    assert "too large" in response.text


# ── §4 · old rows and new rows verify side by side, through the REAL verifier ──
def test_a_mixed_export_verifies_through_the_standalone_verifier(make_org, client):
    """Old-style rows keep verifying after the wire gains fields.

    event_metadata has been chain-bound since V2, so new keys change the row
    hash for NEW ROWS ONLY. That is the claim, and asserting it is not the same
    as proving it — so this drives a REAL export through
    ``verifier/foxy_verify.py``, the hand-written SECOND implementation of the
    chain recipe. If that copy needed a change to accept these rows, the two
    implementations would have diverged, which is the classic hash-chain bug and
    a finding in its own right. It did not.

    The chain is deliberately interleaved — old, new, old, new — so a verifier
    that only coped with a clean prefix of legacy rows, or that treated the
    first provenance-bearing row as the start of a new regime, still fails.
    """
    import importlib.util
    from pathlib import Path

    org = make_org()

    legacy = {
        "event_id": str(uuid.uuid4()),
        "prompt_hash": "1" * 64, "response_hash": "2" * 64,
        "token_count": 11, "policy_tag": "hipaa", "event_type": "interaction",
        "pii_signals": [],
        "event_metadata": {"decision": "blocked", "blocked_reason": "phi",
                           "policy_rules": ["phi.ssn_pattern"]},
    }

    def _legacy():
        row = dict(legacy)
        row["event_id"] = str(uuid.uuid4())
        return row

    batch = [_legacy(), _event(), _legacy(), _event()]
    response = client.post("/v1/logs/batch", headers=org["auth"], json=batch)
    assert response.status_code == 202, response.text

    export = client.get("/v1/logs/export?format=json", headers=org["auth"]).json()
    assert len(export["logs"]) == 4

    # Both styles really are present in what we are about to verify.
    carried = [bool((row.get("event_metadata") or {}).get("ruleset_version"))
               for row in sorted(export["logs"], key=lambda r: r["seq"])]
    assert carried == [False, True, False, True], carried

    path = Path(__file__).resolve().parents[3] / "verifier" / "foxy_verify.py"
    spec = importlib.util.spec_from_file_location("foxy_verify_probe", path)
    verifier = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(verifier)

    result = verifier.verify_export(export)
    assert result["ok"] is True, result
    assert result["count"] == 4


def test_the_verifier_still_catches_a_tampered_provenance_row(make_org, client):
    """CONTROL for the test above.

    A verifier that returned ok for everything would satisfy it. Alter the
    provenance on an exported row and the independent implementation must
    reject the chain — which is also the second, offline half of the
    tamper-evidence claim: it holds in an export a customer verifies
    themselves, not only inside our own /v1/verify.
    """
    import importlib.util
    from pathlib import Path

    org = make_org()
    client.post("/v1/logs/batch", headers=org["auth"], json=[_event()])
    export = client.get("/v1/logs/export?format=json", headers=org["auth"]).json()

    path = Path(__file__).resolve().parents[3] / "verifier" / "foxy_verify.py"
    spec = importlib.util.spec_from_file_location("foxy_verify_probe2", path)
    verifier = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(verifier)

    assert verifier.verify_export(export)["ok"] is True
    export["logs"][0]["event_metadata"]["ruleset_hash"] = "0" * 64
    broken = verifier.verify_export(export)
    assert broken["ok"] is False
    assert broken["first_broken_seq"] == 1


# ── the degrade path must not deadlock a stored row ──────────────────────────
def test_a_stripped_resend_of_a_stored_row_is_not_a_409(make_org, client):
    """THE DEADLOCK. A row stored WITH provenance, resent WITHOUT it.

    This is not hypothetical bookkeeping. The SDK spools an event, POSTs it, and
    acks only after the receipt — so a process that dies in between leaves a row
    that is already stored server-side and still spooled locally. If the backend
    it next meets rejects provenance (a failed deploy, a mixed fleet
    mid-rollout, a downgrade — exactly what the SDK's degrade path exists for),
    the SDK strips the two keys and retries.

    Before the pop, that resend could never equal the stored metadata, so it
    409'd forever. And because the dispatcher batches ten events per request, a
    single poisoned row took nine innocent events down with it on every retry,
    permanently.
    """
    org = make_org()
    event = _event()

    first = client.post("/v1/logs/batch", headers=org["auth"], json=[event])
    assert first.status_code == 202, first.text

    stripped = json.loads(json.dumps(event))
    stripped["event_metadata"].pop("ruleset_version")
    stripped["event_metadata"].pop("ruleset_hash")

    second = client.post("/v1/logs/batch", headers=org["auth"], json=[stripped])
    assert second.status_code == 202, second.text
    assert second.json()["receipts"][0]["status"] in ("duplicate", "accepted")

    # Still ONE row: the resend was recognised as the same event, not a new one.
    assert len(client.get("/v1/logs", headers=org["auth"]).json()["items"]) == 1


def test_the_reverse_direction_is_also_tolerated(make_org, client):
    """Stored WITHOUT provenance, resent WITH it — an SDK upgraded mid-backlog.

    The pop is applied to BOTH sides for this reason. Popping only the stored
    side would leave this direction still 409ing.
    """
    org = make_org()
    plain = _event()
    plain["event_metadata"].pop("ruleset_version")
    plain["event_metadata"].pop("ruleset_hash")

    assert client.post("/v1/logs/batch", headers=org["auth"],
                       json=[plain]).status_code == 202

    enriched = json.loads(json.dumps(plain))
    enriched["event_metadata"]["ruleset_version"] = RULESET_VERSION
    enriched["event_metadata"]["ruleset_hash"] = RULESET_HASH

    assert client.post("/v1/logs/batch", headers=org["auth"],
                       json=[enriched]).status_code == 202
    assert len(client.get("/v1/logs", headers=org["auth"]).json()["items"]) == 1


def test_a_real_content_conflict_is_STILL_a_409(make_org, client):
    """CONTROL. The comparison was narrowed by exactly two keys, not disabled.

    Reusing an event_id for a genuinely different interaction must still be
    refused — that check is what stops two events being silently treated as one.
    """
    org = make_org()
    event = _event()
    assert client.post("/v1/logs/batch", headers=org["auth"],
                       json=[event]).status_code == 202

    conflicting = json.loads(json.dumps(event))
    conflicting["event_metadata"]["blocked_reason"] = "something_else_entirely"
    response = client.post("/v1/logs/batch", headers=org["auth"], json=[conflicting])
    assert response.status_code == 409
    assert "already used with different content" in response.text
