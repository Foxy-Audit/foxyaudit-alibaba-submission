"""SDK #239 — ``explain`` stops telling an auditor a row written today is old.

THE DEFECT
----------
``explain`` had ONE answer for a row that names no ruleset::

    "Row <id> carries no ruleset_version: it was written before SDK 1.7.0..."

Three different rows reach that branch, and for two of them that sentence is a
FALSE STATEMENT OF FACT — produced by the tool whose entire purpose is to
establish facts, about the most ordinary row a guarded workload writes:

* **a guarded row where nothing fired.** ``decision="allowed"``,
  ``policy_rules=[]``, and no provenance, because provenance rides only with the
  rule ids it explains (``client.py``). Written today, by the current SDK.
* **a clean ``observe`` row.** No ``event_metadata`` at all — that absence is
  what keeps an observe payload byte-identical, and it is indistinguishable from
  a pre-1.7.0 row.
* **an actual pre-1.7.0 row.** Rule ids recorded, no version. Only a pre-1.7.0
  SDK writes that pair, because from 1.7.0 the branch that writes a non-empty
  ``policy_rules`` writes the provenance beside it.

⚠ THE BEHAVIOUR IS CORRECT AND DOES NOT CHANGE HERE. S4 decided provenance
rides only with the rule ids it explains, and stamping a ruleset on a clean row
would claim rules explained something when none fired. The defect was the
sentence, and ``test_the_fix_did_not_stamp_provenance_on_a_clean_row`` is what
stops a future reading of this file "solving" it the wrong way.

WHY THE ROWS HERE COME OUT OF THE DECORATOR
-------------------------------------------
The first two cases are driven through ``@client.audit`` and the export is built
from the receipt the SDK itself emitted, not hand-written. A hand-written row is
a claim about what ``log_interaction`` assembles; these are the assembly. The
third case IS hand-written, and has to be — no current SDK can produce it.
"""

from __future__ import annotations

import json

import pytest

from foxy_audit import hashing, introspect
from foxy_audit.client import FoxyClient

KEY = "foxy_sk_s14_test"
EVENT = "22222222-2222-4222-8222-222222222222"
PHI = "Patient SSN 123-45-6789 needs a follow-up."
CLEAN = "What does minimum necessary require for a vendor?"

#: Nothing is delivered anywhere. Port 9 is discard; the spool is redirected to
#: a tmp_path by the autouse fixture in ``sdk/conftest.py``.
DEAD_ENDPOINT = "http://127.0.0.1:9/never"


def _client(tmp_path, receipts):
    return FoxyClient(api_key=KEY, endpoint=DEAD_ENDPOINT,
                      spool_path=str(tmp_path / "spool.db"),
                      on_event=receipts.append)


def _export_from_receipt(receipt, tmp_path):
    """The row the backend would store, assembled the way ``log_interaction``
    assembles ``event_metadata``: a key lands only when it has a value."""
    metadata = {key: receipt[key]
                for key in ("decision", "policy_rules", "blocked_reason",
                            "ruleset_version", "ruleset_hash")
                if receipt[key] is not None}
    row = {"seq": 1, "event_id": receipt["event_id"],
           "policy_tag": receipt["policy_tag"],
           "commitment_alg": receipt["commitment_alg"],
           "prompt_hash": receipt["prompt_hash"]}
    if metadata:
        row["event_metadata"] = metadata
    path = tmp_path / "export.json"
    path.write_text(json.dumps({"org_id": "o", "logs": [row]}), encoding="utf-8")
    return str(path)


def _hand_written(tmp_path, metadata, prompt: str = PHI) -> str:
    """A row this SDK cannot produce — the genuinely pre-provenance shape."""
    row = {"seq": 1, "event_id": EVENT, "commitment_alg": "hmac-sha256",
           "policy_tag": "hipaa",
           "prompt_hash": hashing.commitment_hex(prompt, KEY),
           "event_metadata": metadata}
    path = tmp_path / "legacy.json"
    path.write_text(json.dumps({"org_id": "o", "logs": [row]}), encoding="utf-8")
    return str(path)


def _run(tmp_path, prompt, mode):
    """One real decorated call; returns its receipt."""
    receipts = []
    client = _client(tmp_path, receipts)

    @client.audit(policy="hipaa", mode=mode)
    def answer(prompt):
        return "a reply that trips nothing"

    answer(prompt)
    return receipts[-1]


# ══ 1 · the guarded row where nothing fired ═════════════════════════════════
def test_a_clean_guarded_row_is_not_called_old(tmp_path):
    """🔴 THE REGRESSION, AND THE COMMONEST ROW IN A GUARDED WORKLOAD.

    ``decision="allowed"`` with no rule ids means the guard RAN and matched
    nothing. It is not an old row, and until 1.13.0 that is exactly what an
    auditor was told about it.
    """
    receipt = _run(tmp_path, CLEAN, "block")
    assert receipt["decision"] == "allowed"
    assert receipt["policy_rules"] == []
    assert receipt["ruleset_version"] is None, (
        "a clean row started recording provenance -- that is S4 being undone, "
        "not this defect being fixed")

    result = introspect.explain(CLEAN, receipt["event_id"],
                                _export_from_receipt(receipt, tmp_path), KEY)

    assert result.status == "no_rules_fired"
    assert "before SDK 1.7.0" not in result.message, result.message
    assert "nothing matched" in result.message
    # It says WHY there is no version, so the reader does not read the absence
    # as a gap in their evidence.
    assert "by design" in result.message
    # And it does not pretend to have replayed anything.
    assert result.matches == []
    assert result.ruleset_version == ""


def test_the_fix_did_not_stamp_provenance_on_a_clean_row(tmp_path):
    """⚠ THE WRONG FIX, FENCED OFF.

    The easy way to stop `explain` misdating a clean row is to make the clean
    row carry a ruleset. That would claim rules explained something when none
    fired, and it would change the observe payload S4 kept byte-identical. This
    asserts the PAYLOAD, not the message: the whole of what a clean guarded row
    puts in ``event_metadata`` is a decision and an empty rule list.
    """
    receipt = _run(tmp_path, CLEAN, "block")
    assert receipt["ruleset_version"] is None
    assert receipt["ruleset_hash"] is None

    observed = _run(tmp_path, CLEAN, "observe")
    assert observed["decision"] is None, (
        "the observe path built event_metadata -- its payload is no longer "
        "byte-identical to the pre-guard one")
    assert observed["policy_rules"] is None


# ══ 2 · the observe row, which genuinely cannot be dated ════════════════════
def test_an_observe_row_is_reported_as_undecidable_not_guessed(tmp_path):
    """The case the tool must NOT resolve.

    A clean observe row builds no ``event_metadata`` at all, and neither did a
    pre-1.7.0 row. Both possibilities are named; neither is chosen.
    """
    receipt = _run(tmp_path, CLEAN, "observe")
    assert receipt["decision"] is None

    result = introspect.explain(CLEAN, receipt["event_id"],
                                _export_from_receipt(receipt, tmp_path), KEY)

    assert result.status == "provenance_ambiguous"
    # BOTH candidates are named, and the refusal is explicit.
    assert "observe" in result.message
    assert "1.7.0" in result.message
    assert "will not guess" in result.message
    assert result.matches == []


def test_metadata_without_a_decision_is_also_undecidable(tmp_path):
    """⚠ NOT "no event_metadata" — "no DECISION".

    A caller can pass their own ``metadata=`` under observe, and then the row
    HAS an ``event_metadata`` while still recording no guard run. Keying the
    branch on the dict's presence instead of on ``decision`` would send this row
    down the wrong arm, and it is the SDK's own rule that says which: "None (no
    guard ran) is not [] (the guard ran and nothing fired)" — ``client.py``.
    """
    export = _hand_written(tmp_path, {"request_id": "r-1", "policy_rules": []})
    result = introspect.explain(PHI, EVENT, export, KEY)
    assert result.status == "provenance_ambiguous"


# ══ 3 · the row that really does predate 1.7.0 ══════════════════════════════
def test_rule_ids_without_a_version_still_reports_predates_provenance(tmp_path):
    """The one shape only a pre-1.7.0 SDK can have written, and the ONE case
    where the original sentence was true all along.

    It now names the ids it is talking about, so the claim carries its own
    evidence rather than asking the reader to take it.
    """
    export = _hand_written(tmp_path, {"decision": "blocked",
                                      "policy_rules": ["phi.ssn_pattern"]})
    result = introspect.explain(PHI, EVENT, export, KEY)

    assert result.status == "predates_provenance"
    assert "before SDK 1.7.0" in result.message
    assert "phi.ssn_pattern" in result.message


def test_rule_ids_without_a_version_do_not_need_a_decision(tmp_path):
    """A response-scan coverage id reaches the ledger with rule ids and NO
    decision (``client.py``: "Rules can arrive WITHOUT a decision"). Recorded
    ids with no version is a pre-1.7.0 row whether or not a decision rode with
    them, so the rules arm is tested first and does not consult ``decision``."""
    export = _hand_written(tmp_path, {"policy_rules": ["response_scan.degraded"]})
    result = introspect.explain(PHI, EVENT, export, KEY)
    assert result.status == "predates_provenance"


# ══ the three are one branch, and must stay three answers ═══════════════════
@pytest.mark.parametrize("status", ["no_rules_fired", "provenance_ambiguous",
                                    "predates_provenance"])
def test_each_no_version_answer_is_in_the_published_vocabulary(status):
    """``STATUSES`` is what every consumer switches on — the testbed's family
    map is checked against it, and a status absent from it is one no surface can
    render deliberately."""
    assert status in introspect.STATUSES


def test_the_three_messages_are_actually_different(tmp_path):
    """⚠ THE COLLAPSE THIS PHASE EXISTS TO UNDO, asserted directly.

    Three statuses whose sentences were copies of each other would be the same
    defect wearing new labels.
    """
    clean = introspect.explain(
        PHI, EVENT,
        _hand_written(tmp_path, {"decision": "allowed", "policy_rules": []}), KEY)
    ambiguous = introspect.explain(
        PHI, EVENT, _hand_written(tmp_path, {"policy_rules": []}), KEY)
    legacy = introspect.explain(
        PHI, EVENT,
        _hand_written(tmp_path, {"decision": "blocked",
                                 "policy_rules": ["phi.ssn_pattern"]}), KEY)

    messages = {clean.message, ambiguous.message, legacy.message}
    assert len(messages) == 3
    statuses = {clean.status, ambiguous.status, legacy.status}
    assert statuses == {"no_rules_fired", "provenance_ambiguous",
                        "predates_provenance"}

    # All three got past the commitment, so none of them is a hidden refusal
    # about the prompt, and none claims a digest check it never ran.
    for result in (clean, ambiguous, legacy):
        assert result.commitment_verified is True
        assert result.ruleset_verified is None
        assert result.ok is False, (
            "these answer from the ROW's record, not from a replay -- `ok` "
            "means the replay ran")


def test_both_new_messages_survive_a_cp1252_console(tmp_path):
    """The messages are PRINTED, and a Windows console is cp1252. A message
    that cannot be encoded is the tool failing to say anything at all — the one
    outcome this module promises never to produce. These two are the newest
    sentences in it and the ones no console has ever rendered."""
    for metadata in ({"decision": "allowed", "policy_rules": []},
                     {"policy_rules": []}):
        result = introspect.explain(PHI, EVENT,
                                    _hand_written(tmp_path, metadata), KEY)
        result.message.encode("cp1252")
