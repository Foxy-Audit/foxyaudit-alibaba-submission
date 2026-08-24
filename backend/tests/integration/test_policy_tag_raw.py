"""`policy_tag_raw` is accepted, chained, and still content-blind (S12).

This is the FIRST HALF of the #232 fix, and it must be DEPLOYED before the SDK
half ships. `event_metadata` is validated against a strict allowlist, and
``payload: List[LogIngest]`` is validated as ONE unit, so an SDK sending this
key to a backend without it does not lose one event — it loses the whole batch
to a 422, on precisely the guarded rows the product exists to preserve.

Why the key exists at all is the point of
``test_the_tag_the_caller_typed_still_cannot_travel_as_itself`` below:
`policy_tag` is charset-locked to ``^[a-z0-9_]{1,32}$``, so `policy="HIPAA"`
can never ride the wire as itself. The SDK normalises it to `hipaa` and puts
what the developer actually typed here, beside it.

These tests are the deploy gate for that ordering: they fail on a backend that
has not widened the allowlist.
"""

from __future__ import annotations

import uuid

from sqlalchemy import text

from app.db import engine

RAW_TAG = "HIPAA"                # what the developer typed
CANONICAL_TAG = "hipaa"          # what the wire is allowed to carry


def _event(**overrides):
    event = {
        "event_id": str(uuid.uuid4()),
        "prompt_hash": "a" * 64,
        "response_hash": "c" * 64,
        "token_count": 0,
        "policy_tag": CANONICAL_TAG,
        "event_type": "blocked",
        "pii_signals": ["phi"],
        "event_metadata": {
            "decision": "blocked",
            "blocked_reason": "phi",
            "policy_rules": ["phi.ssn_pattern"],
            "policy_tag_raw": RAW_TAG,
        },
    }
    event.update(overrides)
    return event


def test_a_row_carrying_the_typed_tag_ingests(make_org, client):
    """THE DEPLOY GATE. Without the widened allowlist this is a 422."""
    org = make_org()
    response = client.post("/v1/logs/batch", headers=org["auth"], json=[_event()])
    assert response.status_code == 202, response.text
    assert response.json()["receipts"][0]["status"] == "accepted"


def test_the_tag_the_caller_typed_still_cannot_travel_as_itself(make_org, client):
    """THE REASON THIS KEY EXISTS, pinned.

    `policy_tag` is charset-locked, so "preserve what the customer typed" was
    never available on that field — sending `HIPAA` there 422s the whole batch.
    If someone later relaxes that pattern, this test fails and they are made to
    decide deliberately rather than leaving two spellings of one tag grouping
    apart on every dashboard.
    """
    org = make_org()
    response = client.post("/v1/logs/batch", headers=org["auth"],
                           json=[_event(policy_tag=RAW_TAG)])
    assert response.status_code == 422, response.text
    # …and REJECTED FOR THAT REASON. Asserting the status alone would pass on a
    # backend that had never heard of `policy_tag_raw`, because the metadata key
    # would 422 the same request — the guard would be green from birth.
    assert "policy_tag" in response.text
    assert "unsupported fields" not in response.text


def test_the_typed_tag_survives_the_round_trip(make_org, client):
    """Stored verbatim — an auditor reads this string out of the export and can
    say why the `hipaa` rules ran."""
    org = make_org()
    client.post("/v1/logs/batch", headers=org["auth"], json=[_event()])

    rows = client.get("/v1/logs", headers=org["auth"]).json()["items"]
    assert rows[0]["policy_tag"] == CANONICAL_TAG
    assert rows[0]["event_metadata"]["policy_tag_raw"] == RAW_TAG


def test_the_typed_tag_is_chain_bound(make_org, client):
    """It rides INSIDE event_metadata, which has been chain-bound since V2 — so
    it gets tamper-evidence for free, with no new top-level field, no change to
    chain.py's frozen blob and no chain_version bump.

    Proven by tampering: rewrite the recorded value in the database and
    /v1/verify must fail. If this passed while the row was altered, the
    preserved tag would be decorative and an auditor could not rely on it.
    """
    org = make_org()
    client.post("/v1/logs/batch", headers=org["auth"], json=[_event()])
    assert client.get("/v1/verify", headers=org["auth"]).json()["ok"] is True

    with engine.begin() as connection:
        connection.execute(
            text("UPDATE audit_logs "
                 "SET event_metadata = jsonb_set(event_metadata, "
                 "'{policy_tag_raw}', '\"PCI\"') "
                 "WHERE org_id = :o AND seq = 1"),
            {"o": org["org_id"]},
        )

    assert client.get("/v1/verify", headers=org["auth"]).json()["ok"] is False


def test_an_unknown_metadata_key_is_still_rejected(make_org, client):
    """CONTROL. The allowlist was WIDENED, not opened.

    Without this, adding the key is indistinguishable from deleting the
    validator — and that validator is what keeps raw text out of the ledger.
    """
    org = make_org()
    bad = _event()
    bad["event_metadata"]["prompt_text"] = "the patient's SSN is 123-45-6789"
    response = client.post("/v1/logs/batch", headers=org["auth"], json=[bad])
    assert response.status_code == 422
    assert "unsupported fields" in response.text


def test_the_typed_tag_is_size_bounded_like_every_other_label(make_org, client):
    """The existing 256-char guard covers the new key for free — asserted, so a
    future refactor cannot quietly exempt it. `policy_tag_raw` is the one key
    here whose value a caller chooses freely: `policy=` takes any string, and
    only the NORMALISED form is charset-checked."""
    org = make_org()
    oversized = _event()
    oversized["event_metadata"]["policy_tag_raw"] = "v" * 300
    response = client.post("/v1/logs/batch", headers=org["auth"], json=[oversized])
    assert response.status_code == 422
    assert "too large" in response.text


def test_the_typed_tag_never_reaches_a_judge_provider(make_org, client):
    """CONTENT-BLINDNESS, second layer. `openai_judge._content_blind_meta`
    re-projects metadata through its OWN narrower allowlist before anything
    leaves for a provider, so a new ingest key cannot leak by being added here.

    A decorator argument is not sensitive, but the property that matters is that
    widening ingest does NOT widen what is sent outward, and it is only true
    while the two lists stay separate.
    """
    from app.openai_judge import _content_blind_meta

    projected = _content_blind_meta({
        "policy_tag": CANONICAL_TAG,
        "event_metadata": {"model": "gpt-5.6", "policy_tag_raw": RAW_TAG},
    })
    assert projected["event_metadata"] == {"model": "gpt-5.6"}


# ── old rows and new rows verify side by side, through the REAL verifier ──────
def test_a_mixed_export_verifies_through_the_standalone_verifier(make_org, client):
    """Old-style rows keep verifying after the wire gains a field.

    event_metadata has been chain-bound since V2, so the new key changes the row
    hash for NEW ROWS ONLY. That is the claim, and asserting it is not proving
    it — so this drives a REAL export through ``verifier/foxy_verify.py``, the
    hand-written SECOND implementation of the chain recipe. If that copy needed
    a change to accept these rows, the two implementations would have diverged,
    which is the classic hash-chain bug and a finding in its own right.

    The chain is deliberately interleaved — old, new, old, new — so a verifier
    that only coped with a clean prefix of legacy rows, or that treated the
    first tag-carrying row as the start of a new regime, still fails.
    """
    import importlib.util
    from pathlib import Path

    org = make_org()

    def _legacy():
        return {
            "event_id": str(uuid.uuid4()),
            "prompt_hash": "1" * 64, "response_hash": "2" * 64,
            "token_count": 11, "policy_tag": CANONICAL_TAG,
            "event_type": "interaction", "pii_signals": [],
            "event_metadata": {"decision": "blocked", "blocked_reason": "phi",
                               "policy_rules": ["phi.ssn_pattern"]},
        }

    batch = [_legacy(), _event(), _legacy(), _event()]
    response = client.post("/v1/logs/batch", headers=org["auth"], json=batch)
    assert response.status_code == 202, response.text

    export = client.get("/v1/logs/export?format=json", headers=org["auth"]).json()
    assert len(export["logs"]) == 4

    # Both styles really are present in what we are about to verify.
    carried = [bool((row.get("event_metadata") or {}).get("policy_tag_raw"))
               for row in sorted(export["logs"], key=lambda r: r["seq"])]
    assert carried == [False, True, False, True], carried

    path = Path(__file__).resolve().parents[3] / "verifier" / "foxy_verify.py"
    spec = importlib.util.spec_from_file_location("foxy_verify_tagraw", path)
    verifier = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(verifier)

    result = verifier.verify_export(export)
    assert result["ok"] is True, result
    assert result["count"] == 4


def test_the_verifier_still_catches_a_tampered_typed_tag(make_org, client):
    """CONTROL for the test above.

    A verifier that returned ok for everything would satisfy it. Alter the
    preserved tag on an exported row and the independent implementation must
    reject the chain — the second, offline half of the tamper-evidence claim:
    it holds in an export a customer verifies themselves, not only inside our
    own /v1/verify.
    """
    import importlib.util
    from pathlib import Path

    org = make_org()
    client.post("/v1/logs/batch", headers=org["auth"], json=[_event()])
    export = client.get("/v1/logs/export?format=json", headers=org["auth"]).json()

    path = Path(__file__).resolve().parents[3] / "verifier" / "foxy_verify.py"
    spec = importlib.util.spec_from_file_location("foxy_verify_tagraw2", path)
    verifier = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(verifier)

    assert verifier.verify_export(export)["ok"] is True
    export["logs"][0]["event_metadata"]["policy_tag_raw"] = "PCI"
    broken = verifier.verify_export(export)
    assert broken["ok"] is False
    assert broken["first_broken_seq"] == 1


# ── the duplicate-content comparison ignores the typed tag, on both sides ─────
def _without_raw(event):
    """The same event as the SDK's degrade path would resend it."""
    stripped = {key: value for key, value in event.items() if key != "event_metadata"}
    stripped["event_metadata"] = {key: value
                                  for key, value in event["event_metadata"].items()
                                  if key != "policy_tag_raw"}
    return stripped


def test_a_stripped_resend_is_a_duplicate_not_a_conflict(make_org, client):
    """THE DEADLOCK GUARD. A row stored WITH the typed tag, resent WITHOUT it.

    That is not a hypothetical: `policy_tag_raw` is client-supplied, so it
    persists in the stored row, and the SDK half of S13 puts it in
    ``ruleset.PROVENANCE_KEYS`` — the tuple its degrade path strips when a
    backend rejects the key. A spool entry that outlives its POST (a crash
    before the ack) is later resent to a backend that has been rolled back or
    never upgraded; the SDK strips the key and retries. If the comparison in
    ``logs.py`` still counted the tag, that resend could never match its own
    stored row: 409 forever, taking every other event in the batch with it on
    every retry, and the spool never drains.
    """
    org = make_org()
    event = _event()

    first = client.post("/v1/logs/batch", headers=org["auth"], json=[event])
    assert first.status_code == 202, first.text
    assert first.json()["receipts"][0]["status"] == "accepted"

    resend = client.post("/v1/logs/batch", headers=org["auth"],
                         json=[_without_raw(event)])
    assert resend.status_code == 202, resend.text
    assert resend.json()["receipts"][0]["status"] == "duplicate"


def test_the_tag_arriving_late_is_a_duplicate_too(make_org, client):
    """The other direction, because the pop is on BOTH sides.

    Stored WITHOUT the tag, resent WITH it — an SDK that degraded, then
    recovered, or a row written by an older SDK and retried by a newer one.
    Popping only the stored side would leave this one 409ing.
    """
    org = make_org()
    event = _event()

    first = client.post("/v1/logs/batch", headers=org["auth"],
                        json=[_without_raw(event)])
    assert first.status_code == 202, first.text
    assert first.json()["receipts"][0]["status"] == "accepted"

    resend = client.post("/v1/logs/batch", headers=org["auth"], json=[event])
    assert resend.status_code == 202, resend.text
    assert resend.json()["receipts"][0]["status"] == "duplicate"


def test_a_different_canonical_tag_on_one_event_id_still_conflicts(make_org, client):
    """CONTROL, and the one that stops the pop from widening.

    Excluding a key from the identity comparison is one edit away from
    excluding the comparison. Without this, "never 409" passes the two tests
    above and stays green while two genuinely different events silently
    collapse into one row. `policy_tag` — the CANONICAL tag — is still
    compared, so only two SPELLINGS of one tag are allowed to match.
    """
    org = make_org()
    event = _event()

    first = client.post("/v1/logs/batch", headers=org["auth"], json=[event])
    assert first.status_code == 202, first.text

    conflicting = _without_raw(event)
    conflicting["policy_tag"] = "pci"
    response = client.post("/v1/logs/batch", headers=org["auth"], json=[conflicting])
    assert response.status_code == 409, response.text
    assert "already used with different content" in response.text


def test_a_stripped_resend_does_not_rewrite_the_stored_row(make_org, client):
    """The claim that makes the pop safe for EVIDENCE, asserted.

    A duplicate returns the original receipt; it never writes. So the tag an
    auditor reads is the one from the POST that was chained, and no resend —
    stripped or not — can quietly replace it or move the chain.
    """
    org = make_org()
    event = _event()

    first = client.post("/v1/logs/batch", headers=org["auth"], json=[event])
    original = first.json()["receipts"][0]

    resend = client.post("/v1/logs/batch", headers=org["auth"],
                         json=[_without_raw(event)])
    duplicate = resend.json()["receipts"][0]
    assert duplicate["seq"] == original["seq"]
    assert duplicate["chain_hash"] == original["chain_hash"]

    rows = client.get("/v1/logs", headers=org["auth"]).json()["items"]
    assert len(rows) == 1
    assert rows[0]["event_metadata"]["policy_tag_raw"] == RAW_TAG
    assert client.get("/v1/verify", headers=org["auth"]).json()["ok"] is True
