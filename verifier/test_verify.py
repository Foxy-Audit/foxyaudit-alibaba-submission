"""Tests for the standalone Foxy Audit verifier (Phase 6 · 6D).

Pure Python, stdlib only — no backend, no Postgres, no network. Runnable with
just `pytest verifier/`. The `test_matches_backend_recipe` case cross-checks the
verifier's independent hash recipe against the backend's real chain.py, proving
byte-for-byte parity (skipped if the backend tree isn't alongside)."""

from __future__ import annotations

import json
import os
import sys

import pytest

sys.path.insert(0, os.path.dirname(__file__))

import foxy_verify as fv  # noqa: E402

ORG = "11111111-2222-3333-4444-555555555555"


def _make_export(specs, anchor_at=None):
    """Build a VALID export from row specs, using the verifier's own recipe so the
    chain is self-consistent. Each spec: prompt_hash/response_hash/token_count/
    policy_tag/(agent)."""
    rows, prev = [], fv.GENESIS_HASH
    for i, s in enumerate(specs, start=1):
        ch = fv.compute_chain_hash(
            org_id=ORG, prompt_hash=s["prompt_hash"], response_hash=s["response_hash"],
            token_count=s["token_count"], policy_tag=s["policy_tag"], seq=i,
            prev_hash=prev, agent=s.get("agent"))
        rows.append({"seq": i, "prev_hash": prev, "chain_hash": ch, **s})
        prev = ch
    export = {"org_id": ORG, "count": len(rows), "logs": rows}
    if anchor_at is not None:
        export["anchor"] = {
            "chain": "stub", "status": "confirmed",
            "root_hash": rows[anchor_at - 1]["chain_hash"], "last_seq": anchor_at,
            "tx_hash": "0xabc", "block_number": 1, "anchored_at": None, "contract": None}
    return export


_SPECS = [
    {"prompt_hash": "a" * 64, "response_hash": "b" * 64, "token_count": 10, "policy_tag": "chat"},
    {"prompt_hash": "c" * 64, "response_hash": "d" * 64, "token_count": 25, "policy_tag": "hipaa_basic",
     "agent": "gpt-4o"},
    {"prompt_hash": "e" * 64, "response_hash": "f" * 64, "token_count": 40, "policy_tag": "soc2"},
]


def test_intact_export_verifies():
    res = fv.verify_export(_make_export(_SPECS))
    assert res["ok"] is True
    assert res["count"] == 3
    assert res["first_broken_seq"] is None


def test_tampered_row_caught_at_that_seq():
    export = _make_export(_SPECS)
    export["logs"][1]["token_count"] = 999          # edit seq 2 after the fact
    res = fv.verify_export(export)
    assert res["ok"] is False
    assert res["first_broken_seq"] == 2


def test_tampered_agent_caught():
    export = _make_export(_SPECS)
    export["logs"][1]["agent"] = "claude-3-opus"     # seq 2's agent was bound into the hash
    res = fv.verify_export(export)
    assert res["ok"] is False
    assert res["first_broken_seq"] == 2


def test_offline_anchor_receipt_matches():
    export = _make_export(_SPECS, anchor_at=3)
    res = fv.verify_export(export)
    anc = fv.check_anchor_offline(export, res)
    assert anc is not None
    assert anc["matches"] is True
    assert anc["last_seq"] == 3


def test_offline_anchor_receipt_detects_forged_root():
    export = _make_export(_SPECS, anchor_at=3)
    export["anchor"]["root_hash"] = "0" * 64          # receipt doesn't match the chain
    anc = fv.check_anchor_offline(export, fv.verify_export(export))
    assert anc["matches"] is False


def test_matches_backend_recipe():
    """The verifier's independent recipe must equal the backend's chain.py exactly
    (incl. the 6B agent rule) — else a real export would falsely fail."""
    import importlib.util
    backend_chain = os.path.join(os.path.dirname(__file__), "..", "backend", "app", "chain.py")
    if not os.path.isfile(backend_chain):
        import pytest
        pytest.skip("backend tree not alongside the verifier")
    spec = importlib.util.spec_from_file_location("backend_chain", backend_chain)
    bc = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(bc)
    common = dict(org_id=ORG, prompt_hash="a" * 64, response_hash="b" * 64,
                  token_count=7, policy_tag="chat", seq=1, prev_hash=fv.GENESIS_HASH)
    assert fv.compute_chain_hash(**common) == bc.compute_chain_hash(**common)
    assert (fv.compute_chain_hash(**common, agent="gpt-4o")
            == bc.compute_chain_hash(**common, agent="gpt-4o"))
    assert fv.GENESIS_HASH == bc.GENESIS_HASH


def _backend_chain():
    """Load backend/app/chain.py by path, or skip. It imports only hashlib+json,
    so this needs no FastAPI, no SQLAlchemy and no database."""
    import importlib.util

    import pytest
    path = os.path.join(os.path.dirname(__file__), "..", "backend", "app", "chain.py")
    if not os.path.isfile(path):
        pytest.skip("backend tree not alongside the verifier")
    spec = importlib.util.spec_from_file_location("backend_chain", path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


_PARITY_ARGS = dict(
    org_id=ORG, prompt_hash="a" * 64, response_hash="b" * 64, token_count=100,
    policy_tag="hipaa_basic", seq=1, prev_hash=fv.GENESIS_HASH, agent="gpt-4o",
    event_id="aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa", client_id="sdk-a",
    client_seq=7, event_type="interaction", commitment_alg="hmac-sha256",
    event_metadata={"policy_snapshot_hash": "c" * 64, "request_id": "req-1"},
    pii_signals=["email"],
)

#: ⚠ NOT ONE UTC STRING. `occurred_at` was pinned at `+00:00` here, and
#: normalising a value that is already UTC is a no-op — so a writer that had
#: started normalising at V2 agreed with a verifier that had not, and the parity
#: test passed while every historical row's hash had moved. Measured: that exact
#: mutant SURVIVED. Every rendering below now goes through both implementations
#: at every version.
OCCURRED_RENDERINGS = (
    None,
    "2026-07-18T18:00:00+00:00",      # a UTC session
    "2026-07-18T23:00:00+05:00",      # Asia/Karachi — the developer's cluster
    "2026-07-18T11:00:00-07:00",      # America/Los_Angeles — CI
    "2026-07-18T18:00:00Z",           # a client that writes Z
    "2026-07-18T18:00:00",            # no offset at all: names no instant
    "not a timestamp",                # and something that is not one either
)


def test_writer_and_verifier_agree_at_every_version():
    """The chain has two implementations by design — this one, and the backend's.
    They drift silently, and when they do a genuine export fails to verify at a
    customer's desk with no test having said anything. So: identical inputs into
    both, at every version the product has ever written, including V4 with and
    without a verdict and V5 with its UTC-normalised occurred_at."""
    bc = _backend_chain()
    for version in (1, 2, 3, 4, 5):
        for verdict_hash in (None, "d" * 64):
            for occurred in OCCURRED_RENDERINGS:
                args = dict(_PARITY_ARGS, chain_version=version,
                            verdict_hash=verdict_hash, occurred_at=occurred)
                assert fv.compute_chain_hash(**args) == bc.compute_chain_hash(**args), (
                    f"writer/verifier disagree at chain_version {version} "
                    f"(verdict_hash={'set' if verdict_hash else 'None'}, "
                    f"occurred_at={occurred!r})")


def test_the_two_verdict_digests_agree():
    """`verdict_hash` is only meaningful if both sides derive it the same way."""
    bc = _backend_chain()
    verdict = {"policy_breach": False, "reason": "checks passed", "risk_score": 0,
               "decision": "clean", "rules": [], "judge_provider": None,
               "judge_model": None}
    assert fv.verdict_hash_hex(verdict) == bc.verdict_hash_hex(verdict)


# ── V4: the verdict is inside the chain ──────────────────────────────────────

_V4_VERDICT = {"policy_breach": False, "reason": "deterministic metadata checks passed",
               "risk_score": 0, "decision": "clean", "rules": []}


def _v4_export(verdict=None):
    verdict = _V4_VERDICT if verdict is None else verdict
    row = {
        "seq": 1, "prev_hash": fv.GENESIS_HASH,
        "prompt_hash": "a" * 64, "response_hash": "b" * 64,
        "token_count": 10, "policy_tag": "chat", "agent": None,
        "event_id": None, "client_id": None, "client_seq": None,
        "event_type": "interaction", "commitment_alg": "hmac-sha256",
        "event_metadata": None, "pii_signals": None, "occurred_at": None,
        "chain_version": 4,
        "local_verdict": verdict, "verdict_hash": fv.verdict_hash_hex(verdict),
    }
    row["chain_hash"] = fv.compute_chain_hash(
        org_id=ORG, prev_hash=fv.GENESIS_HASH, **{k: row[k] for k in (
            "prompt_hash", "response_hash", "token_count", "policy_tag", "seq",
            "agent", "event_id", "client_id", "client_seq", "event_type",
            "commitment_alg", "event_metadata", "pii_signals", "occurred_at",
            "chain_version", "verdict_hash")})
    return {"org_id": ORG, "count": 1, "logs": [row]}


def test_v4_export_verifies():
    assert fv.verify_export(_v4_export())["ok"] is True


def test_v4_catches_a_swapped_verdict_hash():
    """Editing the bound digest breaks the chain hash itself."""
    export = _v4_export()
    export["logs"][0]["verdict_hash"] = "d" * 64
    res = fv.verify_export(export)
    assert res["ok"] is False
    assert res["first_broken_seq"] == 1


def test_v4_catches_a_rewritten_verdict_body():
    """The chain binds the DIGEST, so rewriting the verdict alone leaves the chain
    hash valid. Re-deriving the digest from the exported body is what catches it —
    without that check this tampering would pass, and V4 would be decorative."""
    export = _v4_export()
    export["logs"][0]["local_verdict"] = dict(_V4_VERDICT, decision="breach",
                                              policy_breach=True)
    res = fv.verify_export(export)
    assert res["ok"] is False
    assert res["first_broken_seq"] == 1
    assert "verdict" in res["detail"]


def test_a_v3_row_is_unaffected_by_the_verdict_columns():
    """A pre-V4 row carries no verdict, and must verify exactly as it always did
    even sitting in an export whose schema now has the columns."""
    row = {"seq": 1, "prev_hash": fv.GENESIS_HASH, "prompt_hash": "a" * 64,
           "response_hash": "b" * 64, "token_count": 10, "policy_tag": "chat",
           "event_id": None, "client_id": None, "client_seq": None,
           "event_type": "interaction", "commitment_alg": "sha256-legacy",
           "event_metadata": None, "pii_signals": None, "occurred_at": None,
           "chain_version": 3, "local_verdict": None, "verdict_hash": None}
    row["chain_hash"] = fv.compute_chain_hash(
        org_id=ORG, prev_hash=fv.GENESIS_HASH, **{k: row[k] for k in (
            "prompt_hash", "response_hash", "token_count", "policy_tag", "seq",
            "event_id", "client_id", "client_seq", "event_type", "commitment_alg",
            "event_metadata", "pii_signals", "occurred_at", "chain_version")})
    assert fv.verify_export({"org_id": ORG, "count": 1, "logs": [row]})["ok"] is True


def test_capture_v2_export_includes_all_chain_fields():
    fields = {
        "event_id": "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa",
        "client_id": "sdk-a", "client_seq": 1,
        "event_type": "interaction", "commitment_alg": "hmac-sha256",
        "event_metadata": {"request_id": "req-1"},
        "pii_signals": ["email"], "occurred_at": "2026-07-18T18:00:00+00:00",
        "chain_version": 2,
    }
    row = {"seq": 1, "prev_hash": fv.GENESIS_HASH,
           "prompt_hash": "a" * 64, "response_hash": "b" * 64,
           "token_count": 10, "policy_tag": "chat", **fields}
    row["chain_hash"] = fv.compute_chain_hash(
        org_id=ORG, prev_hash=fv.GENESIS_HASH, **{k: row[k] for k in (
            "prompt_hash", "response_hash", "token_count", "policy_tag", "seq",
            "event_id", "client_id", "client_seq", "event_type", "commitment_alg",
            "event_metadata", "pii_signals", "occurred_at", "chain_version")})
    assert fv.verify_export({"org_id": ORG, "count": 1, "logs": [row]})["ok"] is True


def test_policy_v3_export_binds_the_chain_version_and_snapshot_metadata():
    fields = {
        "event_id": None, "client_id": None, "client_seq": None,
        "event_type": "interaction", "commitment_alg": "sha256-legacy",
        "event_metadata": {
            "policy_snapshot": {
                "schema": "foxy-policy-v1", "pii_detection": True,
                "prompt_injection": True, "regulated_data_mode": False,
                "max_token_threshold": 50000,
            },
            "policy_snapshot_hash": "c" * 64,
        },
        "pii_signals": None, "occurred_at": None, "chain_version": 3,
    }
    row = {"seq": 1, "prev_hash": fv.GENESIS_HASH,
           "prompt_hash": "a" * 64, "response_hash": "b" * 64,
           "token_count": 10, "policy_tag": "chat", **fields}
    row["chain_hash"] = fv.compute_chain_hash(
        org_id=ORG, prev_hash=fv.GENESIS_HASH, **{key: row[key] for key in (
            "prompt_hash", "response_hash", "token_count", "policy_tag", "seq",
            "event_id", "client_id", "client_seq", "event_type", "commitment_alg",
            "event_metadata", "pii_signals", "occurred_at", "chain_version")})
    assert fv.verify_export({"org_id": ORG, "count": 1, "logs": [row]})["ok"] is True

    row["chain_version"] = 2
    assert fv.verify_export({"org_id": ORG, "count": 1, "logs": [row]})["ok"] is False


def test_customer_key_verifies_known_event_sidecar():
    key = "customer-secret"
    event_id = "bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb"
    row = {
        "seq": 1, "prev_hash": fv.GENESIS_HASH, "event_id": event_id,
        "client_id": "sdk-a", "client_seq": 1, "event_type": "interaction",
        "commitment_alg": "hmac-sha256", "event_metadata": None,
        "pii_signals": None, "occurred_at": None, "chain_version": 2,
        "prompt_hash": fv.commitment_hex("prompt", key),
        "response_hash": fv.commitment_hex("response", key),
        "token_count": 2, "policy_tag": "chat",
    }
    row["chain_hash"] = fv.compute_chain_hash(
        org_id=ORG, prev_hash=fv.GENESIS_HASH, **{k: row[k] for k in (
            "prompt_hash", "response_hash", "token_count", "policy_tag", "seq",
            "event_id", "client_id", "client_seq", "event_type", "commitment_alg",
            "event_metadata", "pii_signals", "occurred_at", "chain_version")})
    data = {"org_id": ORG, "logs": [row]}
    assert fv.verify_known_events(data, {event_id: {"prompt": "prompt", "response": "response"}}, key) == {
        "ok": True, "checked": 1, "unprovable": []}


# ── H2: the per-event salt ───────────────────────────────────────────────────

SALT = "0123456789abcdef0123456789abcdef"


def _row(key, event_id, salt=None, prompt="prompt", response="response"):
    alg = "hmac-sha256-salted" if salt else "hmac-sha256"
    row = {
        "seq": 1, "prev_hash": fv.GENESIS_HASH, "event_id": event_id,
        "client_id": "sdk-a", "client_seq": 1, "event_type": "interaction",
        "commitment_alg": alg, "event_metadata": None,
        "pii_signals": None, "occurred_at": None, "chain_version": 2,
        "prompt_hash": fv.commitment_hex(prompt, key, salt),
        "response_hash": fv.commitment_hex(response, key, salt),
        "token_count": 2, "policy_tag": "chat",
    }
    row["chain_hash"] = fv.compute_chain_hash(
        org_id=ORG, prev_hash=fv.GENESIS_HASH, **{k: row[k] for k in (
            "prompt_hash", "response_hash", "token_count", "policy_tag", "seq",
            "event_id", "client_id", "client_seq", "event_type", "commitment_alg",
            "event_metadata", "pii_signals", "occurred_at", "chain_version")})
    return row


def test_an_unsalted_commitment_is_unchanged_by_the_salt_parameter():
    """Every row written before H2 must keep verifying under the recipe it was
    written with. If this moves, every historical sidecar breaks at once."""
    assert fv.commitment_hex("prompt", "k") == fv.commitment_hex("prompt", "k", None)
    assert fv.commitment_hex("prompt", "k") == (
        "b67d0748d80ea2dbe77507ad876a7b2ba8687889079116724d2b9d55fcf6ce4b")


def test_two_salts_give_two_commitments_for_the_same_text():
    a = fv.commitment_hex("prompt", "k", "aa" * 16)
    b = fv.commitment_hex("prompt", "k", "bb" * 16)
    assert a != b != fv.commitment_hex("prompt", "k")


def test_a_salted_event_round_trips_through_the_sidecar():
    key, event_id = "customer-secret", "cccccccc-cccc-cccc-cccc-cccccccccccc"
    data = {"org_id": ORG, "logs": [_row(key, event_id, SALT)]}
    sidecar = {event_id: {"prompt": "prompt", "response": "response", "salt": SALT}}
    assert fv.verify_known_events(data, sidecar, key) == {
        "ok": True, "checked": 1, "unprovable": []}


def test_a_salted_event_without_its_salt_reports_honestly():
    """Not a pass (we proved nothing) and not a mismatch (we accused nobody):
    the event is named as unprovable and left out of `checked`."""
    key, event_id = "customer-secret", "dddddddd-dddd-dddd-dddd-dddddddddddd"
    data = {"org_id": ORG, "logs": [_row(key, event_id, SALT)]}
    result = fv.verify_known_events(
        data, {event_id: {"prompt": "prompt", "response": "response"}}, key)
    assert result == {"ok": True, "checked": 0, "unprovable": [event_id]}


def test_a_salted_event_with_the_wrong_salt_is_a_mismatch():
    key, event_id = "customer-secret", "eeeeeeee-eeee-eeee-eeee-eeeeeeeeeeee"
    data = {"org_id": ORG, "logs": [_row(key, event_id, SALT)]}
    result = fv.verify_known_events(
        data, {event_id: {"prompt": "prompt", "response": "response",
                          "salt": "ff" * 16}}, key)
    assert result["ok"] is False and result["field"] == "prompt_hash"


def test_a_salted_event_with_the_wrong_text_is_still_caught():
    """The salt must not become a way to make tampering unverifiable."""
    key, event_id = "customer-secret", "aaaaaaa1-aaaa-aaaa-aaaa-aaaaaaaaaaaa"
    data = {"org_id": ORG, "logs": [_row(key, event_id, SALT)]}
    result = fv.verify_known_events(
        data, {event_id: {"prompt": "a different prompt", "response": "response",
                          "salt": SALT}}, key)
    assert result["ok"] is False and result["field"] == "prompt_hash"


def test_an_unsalted_row_ignores_a_salt_left_in_the_sidecar():
    """`commitment_alg` decides the recipe, not the sidecar. A stale salt beside
    a pre-H2 row must not turn a good commitment into a false alarm."""
    key, event_id = "customer-secret", "aaaaaaa2-aaaa-aaaa-aaaa-aaaaaaaaaaaa"
    data = {"org_id": ORG, "logs": [_row(key, event_id)]}
    sidecar = {event_id: {"prompt": "prompt", "response": "response", "salt": SALT}}
    assert fv.verify_known_events(data, sidecar, key)["ok"] is True


def test_commitment_alg_round_trips_through_the_chain_hash():
    """`commitment_alg` is itself hashed, so an attacker cannot relabel a salted
    row as unsalted to make it verify against unsalted content."""
    key, event_id = "customer-secret", "aaaaaaa3-aaaa-aaaa-aaaa-aaaaaaaaaaaa"
    row = _row(key, event_id, SALT)
    assert row["commitment_alg"] == "hmac-sha256-salted"
    assert fv.verify_export({"org_id": ORG, "count": 1, "logs": [row]})["ok"] is True
    row["commitment_alg"] = "hmac-sha256"
    assert fv.verify_export({"org_id": ORG, "count": 1, "logs": [row]})["ok"] is False


# ── the sidecar loader ───────────────────────────────────────────────────────

def test_the_loader_reads_the_jsonl_the_sdk_appends(tmp_path):
    path = tmp_path / "salts.jsonl"
    path.write_text(
        '{"event_id": "e1", "salt": "aa"}\n'
        '{"event_id": "e2", "salt": "bb"}\n'
        '{"event_id": "e1", "prompt": "hello", "response": "hi"}\n',
        encoding="utf-8")
    assert fv._load_sidecar(str(path)) == {
        "e1": {"salt": "aa", "prompt": "hello", "response": "hi"},
        "e2": {"salt": "bb"}}


def test_the_loader_still_reads_a_hand_written_json_object(tmp_path):
    path = tmp_path / "events.json"
    path.write_text('{"e1": {"prompt": "hello", "response": "hi"}}', encoding="utf-8")
    assert fv._load_sidecar(str(path)) == {"e1": {"prompt": "hello", "response": "hi"}}


def test_a_single_jsonl_line_is_not_mistaken_for_an_event_map(tmp_path):
    """One line is valid JSON on its own; a top-level "event_id" is what tells
    the two shapes apart."""
    path = tmp_path / "salts.jsonl"
    path.write_text('{"event_id": "e1", "salt": "aa"}\n', encoding="utf-8")
    assert fv._load_sidecar(str(path)) == {"e1": {"salt": "aa"}}


def test_a_salted_event_verifies_end_to_end_from_the_sdk(tmp_path):
    """The real round trip: the SDK salts and records, the verifier reads that
    exact file back. The two implementations are written independently, which is
    the only reason this proves anything."""
    # Same escape hatch as test_matches_backend_recipe: run standalone without
    # the repo alongside and this one case skips, everything else still runs.
    sdk_src = os.path.join(os.path.dirname(os.path.dirname(__file__)), "sdk", "src")
    if os.path.isdir(sdk_src) and sdk_src not in sys.path:
        sys.path.insert(0, sdk_src)
    sdk_hashing = pytest.importorskip("foxy_audit.hashing")
    sdk_sidecar = pytest.importorskip("foxy_audit.sidecar")

    key, event_id = "customer-secret", "aaaaaaa4-aaaa-aaaa-aaaa-aaaaaaaaaaaa"
    path = tmp_path / "salts.jsonl"
    salt = sdk_sidecar.record_salt(str(path), event_id)

    row = _row(key, event_id, salt)
    assert row["prompt_hash"] == sdk_hashing.commitment_hex("prompt", key, salt)

    with open(path, "a", encoding="utf-8") as fh:
        fh.write(json.dumps({"event_id": event_id, "prompt": "prompt",
                             "response": "response"}) + "\n")

    loaded = fv._load_sidecar(str(path))
    assert fv.verify_known_events({"org_id": ORG, "logs": [row]}, loaded, key) == {
        "ok": True, "checked": 1, "unprovable": []}


# ── #269: a file this tool cannot read is REFUSED, never passed ──────────────
#
# The reproduction, verbatim from the register — this is what shipped:
#
#     $ echo '{"ledger":[{"seq":1,"chain_hash":"x"}]}' > f.json
#     $ python foxy_verify.py f.json
#     [OK]   chain intact - 0 rows verified from genesis
#     [--]   no anchor receipt in this export
#     EXIT=0
#
# Three call sites read `data.get("logs", [])`, so a file with no `logs` key
# verified clean over zero rows. On the one artefact whose entire purpose is
# "check it yourself, without trusting us", reporting SUCCESS over a file that
# was never read is the worst available failure.
#
# ⚠ EVERY CASE BELOW ASSERTS BOTH HALVES: a non-zero exit AND the absence of the
# string "[OK]" from what a human actually sees. The exit code alone would leave
# the sentence that lies to an auditor on screen; the text alone would leave a
# green CI step. And they run through main(), so they execute the CLI a customer
# runs rather than a function only the tests call.

def _run_cli(tmp_path, payload, name="export.json"):
    import contextlib
    import io

    path = tmp_path / name
    path.write_text(json.dumps(payload), encoding="utf-8")
    out = io.StringIO()
    with contextlib.redirect_stdout(out):
        code = fv.main([str(path)])
    return code, out.getvalue()


def test_the_register_269_reproduction_is_refused_and_not_reported_as_intact(tmp_path):
    """The exact file from the register. It used to print [OK] and exit 0."""
    code, out = _run_cli(tmp_path, {"ledger": [{"seq": 1, "chain_hash": "x"}]})
    assert code == 2, out
    assert "[OK]" not in out, f"a file it could not read still reported success:\n{out}"
    assert "[REFUSED]" in out
    assert "nothing was verified" in out


def test_a_file_with_no_chain_section_at_all_is_refused(tmp_path):
    code, out = _run_cli(tmp_path, {"org_id": ORG, "count": 0, "notes": "hello"})
    assert code == 2
    assert "[OK]" not in out
    assert "no chain section" in out
    # It says what it looked at, so the reader can see it was handed the wrong file.
    assert "count" in out and "notes" in out


def test_an_empty_chain_section_is_refused_rather_than_called_intact(tmp_path):
    """"0 rows verified" and "verified 0 rows because there were none" are
    different statements. Only one of them is honest, and it is not a pass."""
    code, out = _run_cli(tmp_path, {"org_id": ORG, "count": 0, "logs": []})
    assert code == 2
    assert "[OK]" not in out
    assert "present but empty" in out


def test_a_json_file_that_is_not_even_an_object_is_refused(tmp_path):
    code, out = _run_cli(tmp_path, [1, 2, 3])
    assert code == 2
    assert "[OK]" not in out


def test_every_refusal_names_an_artefact_that_IS_verifiable(tmp_path):
    """"This is not a chain" is half an answer. A reader holding the wrong file
    needs to be told which one to fetch."""
    for payload in ({"ledger": [{"seq": 1, "chain_hash": "x"}]},
                    {"org_id": ORG, "logs": []},
                    {"org_id": ORG}):
        _, out = _run_cli(tmp_path, payload)
        assert "/v1/logs/export" in out, out
        assert "format=bundle" in out, out


def test_a_refused_file_never_reports_a_head(tmp_path):
    """The old code substituted GENESIS_HASH for the head when there were no
    rows, which is how "0 rows verified" acquired a chain head to print."""
    result = fv.verify_export({"org_id": ORG})
    assert result["refused"] is True
    assert result["ok"] is False
    assert result["head"] is None and result["head_seq"] is None
    assert result["count"] == 0


def test_json_mode_refuses_too_and_says_nothing_about_an_intact_chain(tmp_path):
    import contextlib
    import io

    path = tmp_path / "f.json"
    path.write_text(json.dumps({"ledger": [{"seq": 1}]}), encoding="utf-8")
    out = io.StringIO()
    with contextlib.redirect_stdout(out):
        code = fv.main([str(path), "--json"])
    assert code == 2
    payload = json.loads(out.getvalue())
    assert payload["chain"]["refused"] is True
    assert payload["chain"]["ok"] is False
    assert payload["chain"]["detail"].startswith("nothing was verified")
    assert "chain intact" not in out.getvalue()


def test_a_refusal_does_not_also_accuse_the_anchor_receipt(tmp_path):
    """A refusal stops. Running the offline anchor check over no rows compares a
    receipt against None and reports a MISMATCH — which reads as tampering, on a
    file nobody verified."""
    code, out = _run_cli(tmp_path, {
        "org_id": ORG, "ledger": [{"seq": 1, "chain_hash": "x"}],
        "anchor": {"chain": "stub", "status": "confirmed", "root_hash": "0" * 64,
                   "last_seq": 1, "tx_hash": "0xabc", "block_number": 1,
                   "anchored_at": None, "contract": None}})
    assert code == 2
    assert "[FAIL]" not in out, f"a refusal accused the export of tampering:\n{out}"
    assert "[OK]" not in out


# ── #269, the other half: the DSAR bundle's key is read, and is not a bypass ──

def test_the_dsar_bundles_ledger_key_is_read_as_a_chain(tmp_path):
    """GET /v1/account/export names its chain section `ledger`. Running this on
    the file a customer was just handed is the most natural action available, and
    it is what produced the false pass."""
    export = _make_export(_SPECS)
    export["ledger"] = export.pop("logs")
    result = fv.verify_export(export)
    assert result["ok"] is True
    assert result["refused"] is False
    assert result["count"] == 3
    assert result["section"] == "ledger"

    code, out = _run_cli(tmp_path, export)
    assert code == 0
    assert "3 rows verified from genesis" in out


def test_the_alias_is_not_a_way_to_smuggle_a_tampered_row_past(tmp_path):
    """Accepting a second key would be worthless — worse than worthless — if the
    rows under it were checked any less."""
    export = _make_export(_SPECS)
    export["ledger"] = export.pop("logs")
    export["ledger"][1]["token_count"] = 999
    result = fv.verify_export(export)
    assert result["ok"] is False
    assert result["refused"] is False           # tampering FOUND, not "unreadable"
    assert result["first_broken_seq"] == 2

    code, out = _run_cli(tmp_path, export)
    assert code == 1, "a tampered ledger must exit 1, not the refusal code"
    assert "[FAIL] CHAIN BROKEN at seq 2" in out


def test_logs_wins_when_a_file_somehow_carries_both(tmp_path):
    """`logs` is the documented input, so it decides. Stated rather than left to
    dict ordering, because a file with both is exactly what a merge of the two
    exports would produce."""
    export = _make_export(_SPECS)
    export["ledger"] = [{"seq": 1, "chain_hash": "junk"}]
    assert fv.find_chain_section(export) == "logs"
    assert fv.verify_export(export)["ok"] is True


def test_a_ledger_row_missing_the_recompute_fields_is_refused_not_failed(tmp_path):
    """⚠ THE CASE THAT MAKES THE ALIAS SAFE TO ADD. Before its own half of #269,
    the DSAR ledger carried nine columns while the hash is taken over seventeen.
    Reading that file as a chain would report CHAIN BROKEN — accusing an untouched
    export of tampering because the reader was handed the wrong shape. "I cannot
    check this" is the only true answer, and it is not a tamper finding."""
    code, out = _run_cli(tmp_path, {"org_id": ORG, "ledger": [
        {"seq": 1, "prompt_hash": "a" * 64, "response_hash": "b" * 64,
         "policy_tag": "chat", "agent": None, "chain_hash": "c" * 64,
         "grading_status": "pending", "gemini_verdict": None,
         "created_at": "2026-08-28T00:00:00+00:00"}]})
    assert code == 2
    assert "[OK]" not in out
    assert "[FAIL] CHAIN BROKEN" not in out, (
        "a wrong-shaped export was reported as tampering rather than as unreadable")
    assert "token_count" in out, "the refusal does not say which fields are missing"


# ── REQUIRED_ROW_FIELDS: the constant that decides what "unreadable" means ──
#
# ⚠ THE LIST ABOVE IS A WATCHLIST, AND IT WAS UNGUARDED. `find_chain_section`
# and `CHAIN_SECTION_KEYS` are pinned by a closed-list test; `REQUIRED_ROW_FIELDS`
# was not, and the case above only ever omits `token_count`. Dropping any other
# entry left every one of these tests green while the tool lost the ability to
# say "I cannot check this file". Measured before this block existed: with
# `response_hash` removed from the tuple, a ledger row without it stopped being
# refused and `foxy_verify.py` died with an uncaught `KeyError: 'response_hash'`
# traceback — a verdict degrading into a stack trace.
#
# It fails CLOSED, so #269 does not return: `chain_hash` is the one entry whose
# loss is silent rather than loud, and it is the worse half — `row.get(
# "chain_hash")` returns None, the recompute disagrees, and the tool reports
# CHAIN BROKEN. That is an accusation of tampering levelled at an untouched
# export because the reader was handed the wrong shape, which is the exact lie
# the constant's own docstring exists to prevent.

#: ⚠ WRITTEN OUT HERE, NOT READ FROM THE MODULE. Parametrising over
#: `fv.REQUIRED_ROW_FIELDS` would shrink to nothing the moment the constant did
#: — zero cases, green run, the defect being tested for. This list is taken from
#: `_row_hash`, which reads `prompt_hash`, `response_hash`, `token_count`,
#: `policy_tag` and `seq` with no default, plus the `chain_hash` every row is
#: compared against and the `seq` the sort key needs.
_RECOMPUTE_READS_WITH_NO_DEFAULT = ("seq", "prompt_hash", "response_hash",
                                    "token_count", "policy_tag", "chain_hash")


def test_the_required_field_list_is_exactly_what_a_recompute_reads():
    """The closed list, in the shape of `test_the_accepted_keys_are_a_closed_list`.

    Equality, not `issuperset`: an entry too many refuses files the tool could
    have verified, and an entry too few is what the cases below catch.
    """
    assert fv.REQUIRED_ROW_FIELDS == _RECOMPUTE_READS_WITH_NO_DEFAULT, (
        "REQUIRED_ROW_FIELDS no longer matches what a recompute reads. Adding a "
        "field to the hash recipe means adding it here; removing one from this "
        "tuple means the rows missing it are no longer refused.")


@pytest.mark.parametrize("field", _RECOMPUTE_READS_WITH_NO_DEFAULT)
def test_a_row_missing_one_required_field_is_refused_and_never_crashes(field, tmp_path):
    """One field at a time, over an otherwise VALID export.

    The existing ledger-shape case omits five fields at once, so it stays green
    while five of the six entries are dropped from the constant. This drops
    exactly one, which is the only shape that can tell them apart.
    """
    export = _make_export(_SPECS)
    del export["logs"][1][field]

    result = fv.verify_export(export)
    assert result["refused"] is True, (
        f"a row missing {field!r} was not refused: {result['detail']!r}. The "
        f"recompute reads that field with no default, so what came back is "
        f"either a crash or a verdict about a file that was never read.")
    assert result["ok"] is False
    assert field in result["detail"], (
        f"the refusal does not name the missing field: {result['detail']!r}")

    code, out = _run_cli(tmp_path, export)
    assert code == 2, f"expected the refusal exit code, got {code}:\n{out}"
    assert "[OK]" not in out, f"a row it could not read reported success:\n{out}"
    assert "[FAIL] CHAIN BROKEN" not in out, (
        f"a row missing {field!r} was reported as TAMPERING. The export is "
        f"untouched; the reader was handed the wrong shape. Accusing it of "
        f"tampering is #269 pointed the other way:\n{out}")
    assert "Traceback" not in out and field in out


def test_the_refusal_survives_a_row_missing_every_required_field(tmp_path):
    """The degenerate case, so the per-field loop cannot be the only cover: a row
    carrying none of them must still be a refusal naming all six."""
    export = _make_export(_SPECS)
    export["logs"][0] = {"note": "not a chain row"}
    result = fv.verify_export(export)
    assert result["refused"] is True, result["detail"]
    for field in _RECOMPUTE_READS_WITH_NO_DEFAULT:
        assert field in result["detail"], (
            f"{field!r} is missing from the refusal: {result['detail']!r}")


def test_the_known_content_check_reads_the_alias_too(tmp_path):
    """All three `data.get("logs", [])` sites moved, not just the one in
    verify_export. A sidecar check that silently iterated nothing would report
    `checked: 0` as a pass — the same shape of lie, one function along."""
    key, event_id = "customer-secret", "aaaaaaa5-aaaa-aaaa-aaaa-aaaaaaaaaaaa"
    data = {"org_id": ORG, "ledger": [_row(key, event_id)]}
    assert fv.verify_known_events(
        data, {event_id: {"prompt": "prompt", "response": "response"}}, key) == {
        "ok": True, "checked": 1, "unprovable": []}


def test_the_offline_anchor_check_reads_the_alias_too():
    export = _make_export(_SPECS, anchor_at=3)
    export["ledger"] = export.pop("logs")
    anchor = fv.check_anchor_offline(export, fv.verify_export(export))
    assert anchor["matches"] is True, (
        "recompute_head_upto still looked for `logs`, so the receipt compared "
        "against a head computed from nothing")


def test_the_accepted_keys_are_a_closed_list():
    """A third key must be a decision somebody makes, not something a plausible
    name falls into. `data.get(<anything>)` is how #269 happened."""
    assert fv.CHAIN_SECTION_KEYS == ("logs", "ledger")
    assert fv.find_chain_section({"entries": [{"seq": 1}]}) is None
    assert fv.find_chain_section({"logs": "not a list"}) is None

# ── V5: the same INSTANT hashes the same, wherever it was rendered ───────────
#
# ⚠ V5 IS NOT LIKE V2, V3 OR V4, AND THAT IS WHAT THESE GUARD. Each of those
# ADDED a key under a `chain_version >=` test, so every earlier payload stayed
# byte-identical for free — you could not break history without deleting a line.
# V5 changes how an EXISTING key (`occurred_at`) is RENDERED, so byte-identity is
# no longer free and has to be asserted: `test_only_v5_normalises_the_offset`
# below pins the pre-V5 behaviour, defect and all, because a historical row must
# keep verifying forever.

#: One instant, written three ways. `+00:00` is what a UTC session renders,
#: `+05:00` what the developer's Asia/Karachi cluster renders, `Z` what a
#: hand-written export or a non-Python client emits. All three name 09:30 UTC.
_SAME_INSTANT = ("2026-07-18T09:30:00+00:00",
                 "2026-07-18T14:30:00+05:00",
                 "2026-07-18T02:30:00-07:00",
                 "2026-07-18T09:30:00Z")


def _v5(**over):
    args = dict(_PARITY_ARGS, chain_version=5, verdict_hash="d" * 64)
    args.update(over)
    return fv.compute_chain_hash(**args)


def test_v5_hashes_one_instant_identically_however_it_was_rendered():
    """REGISTER #272, THE WHOLE OF IT IN ONE ASSERTION.

    PostgreSQL renders a `timestamptz` in the READING session's `TimeZone`, so
    the four strings below are what one stored row looks like to four readers.
    Before V5 each produced a different chain hash and the reader who was not
    the writer was told the ledger had been tampered with."""
    digests = {s: _v5(occurred_at=s) for s in _SAME_INSTANT}
    assert len(set(digests.values())) == 1, (
        "the same instant still hashes differently by rendering: %r" % digests)


def test_only_v5_normalises_the_offset():
    """⚠ THE BYTE-IDENTITY GUARD, STATED AS BEHAVIOUR RATHER THAN A GOLDEN FILE.

    A stored vector only proves a branch agrees with itself. What must be true is
    that V1-V4 still fold `occurred_at` the way they always did — VERBATIM, offset
    and all — so every row ever written keeps its hash. Under V4 two renderings of
    one instant therefore MUST disagree: that is the frozen defect, and freezing it
    is the price of not rewriting history.

    ⚠ AND IT ASSERTS ON BOTH IMPLEMENTATIONS. Pointed at this file alone it
    missed the mutant that normalised from V2 inside `backend/app/chain.py` — the
    two copies still agreed with each other, and agreeing on the wrong hash is
    exactly what a hand-duplicated recipe fails as. Measured: that mutant SURVIVED
    until the backend was named here.

    A mutant that applies the V5 normalisation at every version dies here."""
    bc = _backend_chain()
    utc, karachi = _SAME_INSTANT[0], _SAME_INSTANT[1]
    for impl in (fv, bc):
        for version in (2, 3, 4):
            args = dict(_PARITY_ARGS, chain_version=version, verdict_hash="d" * 64)
            assert (impl.compute_chain_hash(**dict(args, occurred_at=utc))
                    != impl.compute_chain_hash(**dict(args, occurred_at=karachi))), (
                "%s normalised the offset at V%d — every historical row's hash "
                "just moved" % (impl.__name__, version))
        v5 = dict(_PARITY_ARGS, chain_version=5, verdict_hash="d" * 64)
        assert (impl.compute_chain_hash(**dict(v5, occurred_at=utc))
                == impl.compute_chain_hash(**dict(v5, occurred_at=karachi)))


def test_v5_reads_an_offsetless_timestamp_as_utc():
    """A value with no offset names no instant. Ingest attaches UTC before storing
    it (schemas.LogIngest), so the fold has to make the same choice or the row it
    wrote would not be the row it reads back.

    ⚠ BOTH IMPLEMENTATIONS, for the same reason as the guard above: a writer that
    read an offsetless value as the machine's LOCAL time survived every check that
    asked only this file, and the machine this was written on is UTC+5."""
    naive, utc = "2026-07-18T09:30:00", _SAME_INSTANT[0]
    for impl in (fv, _backend_chain()):
        args = dict(_PARITY_ARGS, chain_version=5, verdict_hash="d" * 64)
        assert (impl.compute_chain_hash(**dict(args, occurred_at=naive))
                == impl.compute_chain_hash(**dict(args, occurred_at=utc))), (
            "%s did not read an offsetless timestamp as UTC" % impl.__name__)
        assert impl.normalize_occurred_at(naive) == utc


def test_v5_folds_an_unreadable_timestamp_unchanged():
    """⚠ AND UNCHANGED MEANS THE ORIGINAL TEXT, NOT THE `Z`-SWAPPED ONE. Refusing
    a value here — or silently rewriting it — turns "I cannot read this field"
    into a hash mismatch, which this tool reports to a customer as TAMPERING."""
    assert fv.normalize_occurred_at("not a timestamp") == "not a timestamp"
    assert fv.normalize_occurred_at("ZZZ") == "ZZZ"
    assert fv.normalize_occurred_at(None) is None
    assert _v5(occurred_at="not a timestamp") != _v5(occurred_at="ZZZ")


def test_v5_agrees_across_the_datetime_and_string_asymmetry():
    """⚠ THE TWO IMPLEMENTATIONS DO NOT START FROM THE SAME THING, AND THIS IS
    WHERE V5 WOULD GO WRONG.

    `backend/app/chain.py` folds the `datetime` SQLAlchemy hands it; this file
    folds the STRING that datetime was exported as. `test_writer_and_verifier_
    agree_at_every_version` passes one shared value to both and so cannot see the
    asymmetry at all. Here the backend is given the object and the verifier is
    given its `isoformat()` — rendered in a DIFFERENT zone from the one the object
    carries, which is exactly what an export from a non-UTC session contains."""
    from datetime import datetime, timedelta, timezone

    bc = _backend_chain()
    written = datetime(2026, 7, 18, 9, 30, tzinfo=timezone.utc)
    read_back = written.astimezone(timezone(timedelta(hours=5)))   # Asia/Karachi
    assert read_back.isoformat() != written.isoformat(), "the premise: two texts"

    args = dict(_PARITY_ARGS, chain_version=5, verdict_hash="d" * 64)
    args.pop("occurred_at", None)
    backend_digest = bc.compute_chain_hash(**args, occurred_at=written)
    verifier_digest = fv.compute_chain_hash(**args, occurred_at=read_back.isoformat())
    assert backend_digest == verifier_digest, (
        "the writer folded a datetime and the verifier folded its exported "
        "string, and they disagree — which is #272 with extra steps")
    # and the backend must not be quietly self-consistent either: hand IT the
    # string the export carries and it has to land on the same digest.
    assert bc.compute_chain_hash(**args, occurred_at=read_back.isoformat()) == backend_digest


def test_a_v5_export_verifies_after_the_offset_is_re_rendered():
    """End to end through `verify_export`, not just the hash function: re-render
    every row's `occurred_at` into another zone — which is all a different reading
    session does — and the chain must still recompute clean."""
    from datetime import datetime, timedelta, timezone

    export = _v4_export()
    row = export["logs"][0]
    row["chain_version"] = 5
    row["occurred_at"] = _SAME_INSTANT[0]
    row["chain_hash"] = fv.compute_chain_hash(
        org_id=ORG, prev_hash=fv.GENESIS_HASH, **{k: row[k] for k in (
            "prompt_hash", "response_hash", "token_count", "policy_tag", "seq",
            "agent", "event_id", "client_id", "client_seq", "event_type",
            "commitment_alg", "event_metadata", "pii_signals", "occurred_at",
            "chain_version", "verdict_hash")})
    assert fv.verify_export(export)["ok"] is True

    other = dict(export, logs=[dict(row, occurred_at=datetime.fromisoformat(
        row["occurred_at"]).astimezone(timezone(timedelta(hours=5))).isoformat())])
    assert other["logs"][0]["occurred_at"] != row["occurred_at"], "premise"
    assert fv.verify_export(other)["ok"] is True, (
        "the same rows read in another session zone were called tampered")

    # and V5 is still tamper-evident: a different INSTANT must break it.
    moved = dict(export, logs=[dict(row, occurred_at="2026-07-18T09:31:00+00:00")])
    assert fv.verify_export(moved)["ok"] is False
    assert fv.verify_export(moved)["first_broken_seq"] == 1
