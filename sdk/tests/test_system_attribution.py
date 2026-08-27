"""R3 — the SDK SENDS an AI-system attribution (`event_metadata["system_id"]`).

R1 built the inventory, R2 taught the wire to accept an attribution, and this is
the half that produces one. Six surfaces, and this file is organised by them:

  1. THE LADDER AND THE LATCH (dispatch.py) — the `system_id` rung goes FIRST
     because it is the newest key, and a refusal that NAMES an id is resolved
     PER SYSTEM and never latched. That split is #256, and it is the reason this
     phase is not one more rung.
  2. THE CALLER'S API (client.py) — client-level default, decorator override,
     and the spelling validated at every configure-time door.
  3. THE RESERVATION — `system_id` is SDK-managed, so a caller's `metadata=`
     copy is dropped like the guard's and the ruleset's.
  4. BYTE-IDENTITY OF THE UNAFFECTED PATH — proved against the FROZEN 1.13.0
     client, not asserted.
  5. OLD SPOOL ROWS — a spool written before this release flushes clean.
  6. (the backend half of the sixth surface lives in
     backend/tests/integration/test_system_id.py, where the refusals are made.)

Run with:  cd sdk && python -m pytest tests/test_system_attribution.py -q
"""

from __future__ import annotations

import asyncio
import hashlib
import importlib.util
import json
import sqlite3
import sys
import uuid
from pathlib import Path

import pytest

from foxy_audit import FoxyClient, FoxyPolicyBlocked
from foxy_audit import client as client_module
from foxy_audit import dispatch, hashing

#: Two canonical ids, so "the healthy one kept its attribution" is a statement
#: about a DIFFERENT system rather than about the same one twice.
LIVE = "3f2504e0-4f89-41d3-9a0c-0305e82c3301"
RETIRED = "9c5b94b1-35ad-49bb-b118-8e8fc24abf80"
OTHER_RETIRED = "1b4e28ba-2fa1-11d2-883f-0016d3cca427"

FIXTURES = Path(__file__).resolve().parent / "fixtures"


def _load(name: str, filename: str):
    """Import a frozen fixture inside the package namespace.

    Loaded as ``foxy_audit._<name>`` so its relative ``from . import dispatch,
    hashing, …`` resolves against the real package — which is exactly what is
    wanted here: the only module being compared across eras is this one.
    """
    full = f"foxy_audit._{name}"
    if full in sys.modules:
        return sys.modules[full]
    spec = importlib.util.spec_from_file_location(full, FIXTURES / filename)
    module = importlib.util.module_from_spec(spec)
    sys.modules[full] = module
    spec.loader.exec_module(module)
    return module


OLD_CLIENT = _load("client_1_13_0", "client_1_13_0.py")


# ───────────────────────────── the harness ───────────────────────────────────

class _Response:
    def __init__(self, status_code, text="", payload=None):
        self.status_code = status_code
        self.text = text
        self._payload = payload if payload is not None else {"status": "accepted"}

    def json(self):
        return self._payload

    def raise_for_status(self):
        if self.status_code >= 400:
            raise RuntimeError("HTTP %s" % self.status_code)


#: R2's OWN WORDING, copied from `routers/logs.py:_validate_system_attributions`
#: rather than paraphrased. The whole latch split turns on this message naming
#: the id, so a test that invented a friendlier sentence would be guarding a
#: message the backend does not send.
_RETIRED_DETAIL = (
    "event_metadata contains unsupported fields: system_id {id} names an AI "
    "system that has been RETIRED, and a retired system accepts no new events. "
    "Its existing evidence is untouched. Attribute this event to a system still "
    "in service, or declare a new one.")
#: The other semantic refusal — undeclared, or another tenant's. One branch on
#: purpose (an existence oracle otherwise), and it names the id too.
_UNDECLARED_DETAIL = (
    "event_metadata contains unsupported fields: system_id {id} names no AI "
    "system in this workspace. Declare it with POST /v1/systems, or send the "
    "event without an attribution.")
#: A CAPABILITY refusal: `schemas.py`'s allowlist message, which cannot name an
#: id because the backend sending it has never heard of the key.
_CAPABILITY_DETAIL = "event_metadata contains unsupported fields"


def _backend(seen, refuse=None, capability=()):
    """A backend that answers with REAL R2 shapes, at the HTTP boundary.

    ``refuse`` maps a system id to the message template that refuses it —
    SEMANTIC, and only the FIRST offending id in the batch is named, because
    `_validate_system_attributions` raises on the first one it meets.
    ``capability`` names event_metadata keys this backend does not know at all.
    """
    refuse = refuse or {}

    def post(endpoint, api_key, body):
        seen.append(json.loads(json.dumps(body)))
        for event in body:
            metadata = event.get("event_metadata") or {}
            for key in capability:
                if key in metadata:
                    return _Response(422, text=json.dumps(
                        {"detail": _CAPABILITY_DETAIL}))
        for event in body:
            metadata = event.get("event_metadata") or {}
            spelling = metadata.get("system_id")
            if spelling in refuse:
                return _Response(422, text=json.dumps(
                    {"detail": refuse[spelling].format(id=spelling)}))
        return _Response(202, payload={"status": "accepted", "receipts": []})
    return post


def _row(seq, metadata):
    return {
        "event_id": "00000000-0000-4000-8000-%012d" % seq,
        "client_id": "c" * 32, "client_seq": seq,
        "event_type": "interaction", "commitment_alg": "hmac-sha256",
        "prompt_hash": "a" * 64, "response_hash": "b" * 64,
        "token_count": 3, "policy_tag": "hipaa", "pii_signals": [],
        "event_metadata": metadata,
    }


def _enqueue(path, endpoint, *payloads):
    from foxy_audit.spool import EventSpool
    spool = EventSpool(path)
    for payload in payloads:
        spool.enqueue(endpoint, "foxy_sk_test", payload)
    return spool


def _receipts(path):
    conn = sqlite3.connect(path)
    conn.row_factory = sqlite3.Row
    try:
        return [json.loads(r["receipt"])
                for r in conn.execute(
                    "SELECT receipt, event_id FROM spool_receipts "
                    "ORDER BY event_id").fetchall()]
    finally:
        conn.close()


@pytest.fixture(autouse=True)
def _clean_latch(monkeypatch):
    """No latch may leak between tests — it is process-global by design."""
    monkeypatch.setattr(dispatch, "_no_provenance", {})


def _payloads(tmp_path, module=client_module, **kwargs):
    """A client whose events are captured instead of dispatched."""
    sent = []
    client = module.FoxyClient(
        api_key="foxy_sk_test", endpoint="https://ledger.example.test",
        desktop_ping=False, spool_path=str(tmp_path / "spool.sqlite3"),
        client_id="c" * 32, **kwargs)
    return client, sent


def _capture(monkeypatch, sent):
    monkeypatch.setattr(dispatch, "submit",
                        lambda cfg, payload, wait=False: sent.append(payload))


# ══ surface 1 · the ladder, and the latch ════════════════════════════════════

def test_the_system_id_rung_is_first_because_it_is_the_newest_key():
    """ORDER IS CORRECTNESS HERE, NOT TIDINESS.

    The ladder escalates on the assumption that the key sets a backend can
    refuse are NESTED — {} ⊂ {system_id} ⊂ {system_id, policy_tag_raw} ⊂ {…,
    ruleset_*} — which holds because the ingest allowlist has only ever grown.
    `system_id` is the NEWEST key, so it is the one the most backends refuse.

    Appended instead of prepended, a backend that refuses only `system_id` —
    every deployment older than R2, the frozen production one included — would
    have had the TYPED TAG stripped first: a POST spent on a rung that backend
    was happy to take, and then a latch recording a refusal that never happened.
    """
    names = [name for name, _keys, _why in dispatch._DEGRADE_LADDER]
    assert names == [dispatch._DEGRADED_SYSTEM_ID,
                     dispatch._DEGRADED_TYPED_TAG,
                     dispatch._DEGRADED_PROVENANCE], names


def test_a_backend_that_cannot_hold_an_attribution_loses_only_that_rung(tmp_path):
    """A PRE-R2 BACKEND: strip `system_id`, keep everything else, latch once.

    This is the CAPABILITY branch, and it is 1.13.0's behaviour extended by one
    rung — the endpoint genuinely cannot hold the key, so remembering that is
    right and cheap. What must NOT happen is the typed tag or the ruleset keys
    going with it: that is the single-dimension latch S13 paid for, in a new
    coat.
    """
    seen = []
    dispatch.AsyncDispatcher._post = staticmethod(
        _backend(seen, capability=("system_id",)))
    path = str(tmp_path / "spool.sqlite3")
    endpoint = "https://pre-r2.example.test/v1/logs/batch"
    _enqueue(path, endpoint, _row(1, {"system_id": LIVE,
                                      "policy_tag_raw": "HIPAA",
                                      "ruleset_version": "2026.08.5"}))
    try:
        dispatch._DISPATCHER._flush_spool({path})
    finally:
        del dispatch.AsyncDispatcher._post

    assert len(seen) == 2, "expected one rejected POST and exactly one retry"
    assert "system_id" in seen[0][0]["event_metadata"]
    assert "system_id" not in seen[1][0]["event_metadata"]
    # The other two rungs are untouched: this backend never refused them.
    assert seen[1][0]["event_metadata"]["policy_tag_raw"] == "HIPAA"
    assert seen[1][0]["event_metadata"]["ruleset_version"] == "2026.08.5"
    assert list(dispatch._no_provenance) == [
        (endpoint, dispatch._DEGRADED_SYSTEM_ID)], dispatch._no_provenance
    assert _receipts(path)[0]["foxy_degraded"] == [dispatch._DEGRADED_SYSTEM_ID]


@pytest.mark.parametrize("detail", [_RETIRED_DETAIL, _UNDECLARED_DETAIL])
def test_one_retired_system_does_not_cost_the_estate_its_attribution(
        tmp_path, detail):
    """🔴 #256, AND THE REASON THIS PHASE HAS A DESIGN RATHER THAN A RUNG.

    R2 answers a retired or foreign system with the SAME "unsupported fields"
    phrase a capability refusal uses — it had to, because that phrase is the
    only one `_rejects_unsupported_fields` recognises and anything else
    re-queues the batch forever. Read as capability, ONE retired system would
    latch `system_id` off for the whole ENDPOINT for 900 seconds, healthy
    systems included, and those rows are chain-bound: the attribution would be
    permanently absent from the evidence, not merely delayed.

    So: three events, two from a live system and one from a retired one. The
    retired one loses its attribution. The other two keep theirs. And NOTHING
    IS LATCHED — the endpoint has not been shown to be incapable of anything.
    """
    seen = []
    dispatch.AsyncDispatcher._post = staticmethod(
        _backend(seen, refuse={RETIRED: detail}))
    path = str(tmp_path / "spool.sqlite3")
    endpoint = "https://ledger.example.test/v1/logs/batch"
    _enqueue(path, endpoint,
             _row(1, {"system_id": LIVE}),
             _row(2, {"system_id": RETIRED}),
             _row(3, {"system_id": LIVE}))
    try:
        dispatch._DISPATCHER._flush_spool({path})
    finally:
        del dispatch.AsyncDispatcher._post

    assert len(seen) == 2, "one refusal, one targeted resend"
    resent = seen[1]
    assert [e["event_metadata"].get("system_id") for e in resent] == [
        LIVE, None, LIVE], resent
    assert not dispatch._no_provenance, (
        "a semantic refusal LATCHED: one retired system just disabled "
        "attribution for every system on this endpoint — %r"
        % (dispatch._no_provenance,))


def test_only_the_refused_row_says_it_lost_an_attribution(tmp_path):
    """A marker on a row it cannot be true of means nothing at all.

    The receipt is the only local record that an attribution was dropped, and
    the rows that kept theirs must not carry it. It is also a DIFFERENT marker
    from the rung's: "your system is retired" and "your backend cannot hold an
    attribution" have different remedies, and `_keys_phrase` already paid for
    the lesson that a message naming the wrong remedy sends an operator to the
    wrong control.
    """
    seen = []
    dispatch.AsyncDispatcher._post = staticmethod(
        _backend(seen, refuse={RETIRED: _RETIRED_DETAIL}))
    path = str(tmp_path / "spool.sqlite3")
    _enqueue(path, "https://ledger.example.test/v1/logs/batch",
             _row(1, {"system_id": LIVE}),
             _row(2, {"system_id": RETIRED}))
    try:
        dispatch._DISPATCHER._flush_spool({path})
    finally:
        del dispatch.AsyncDispatcher._post

    marks = [r.get("foxy_degraded") for r in _receipts(path)]
    assert marks == [None, [dispatch._DEGRADED_ATTRIBUTION]], marks
    assert dispatch._DEGRADED_ATTRIBUTION != dispatch._DEGRADED_SYSTEM_ID


def test_two_refused_systems_in_one_batch_both_resolve(tmp_path):
    """The router raises on the FIRST bad id it meets, so one pass is not enough.

    Without the loop, the second retired system's 422 falls through to the
    ladder — which strips `system_id` endpoint-wide and latches, delivering
    exactly the estate-wide outage the split exists to prevent, one batch later.
    """
    seen = []
    dispatch.AsyncDispatcher._post = staticmethod(_backend(seen, refuse={
        RETIRED: _RETIRED_DETAIL, OTHER_RETIRED: _UNDECLARED_DETAIL}))
    path = str(tmp_path / "spool.sqlite3")
    _enqueue(path, "https://ledger.example.test/v1/logs/batch",
             _row(1, {"system_id": RETIRED}),
             _row(2, {"system_id": LIVE}),
             _row(3, {"system_id": OTHER_RETIRED}))
    try:
        dispatch._DISPATCHER._flush_spool({path})
    finally:
        del dispatch.AsyncDispatcher._post

    assert len(seen) == 3, "two refusals, and one resend each"
    assert [e["event_metadata"].get("system_id") for e in seen[-1]] == [
        None, LIVE, None]
    assert not dispatch._no_provenance
    marks = [r.get("foxy_degraded") for r in _receipts(path)]
    assert marks == [[dispatch._DEGRADED_ATTRIBUTION], None,
                     [dispatch._DEGRADED_ATTRIBUTION]], marks


def test_a_semantic_refusal_teaches_the_next_batch_nothing(tmp_path):
    """NOT LATCHING IS THE POINT, and this is what "not latched" has to mean.

    A retired system says nothing about the endpoint, so the very next batch
    must go out carrying its attributions in full. One wasted POST per batch
    that names a retired system is the correct price; fifteen minutes of
    unattributed evidence for every OTHER system is not.
    """
    seen = []
    dispatch.AsyncDispatcher._post = staticmethod(
        _backend(seen, refuse={RETIRED: _RETIRED_DETAIL}))
    path = str(tmp_path / "spool.sqlite3")
    endpoint = "https://ledger.example.test/v1/logs/batch"
    try:
        _enqueue(path, endpoint, _row(1, {"system_id": RETIRED}))
        dispatch._DISPATCHER._flush_spool({path})
        _enqueue(path, endpoint, _row(2, {"system_id": LIVE}))
        dispatch._DISPATCHER._flush_spool({path})
    finally:
        del dispatch.AsyncDispatcher._post

    assert seen[-1][0]["event_metadata"]["system_id"] == LIVE, (
        "the second batch was pre-stripped by a latch that must not exist")


def test_a_reworded_refusal_falls_back_to_the_capability_branch(tmp_path):
    """⚠ THE FAIL-SAFE, ASSERTED RATHER THAN HOPED FOR.

    The split reads a message R2 owns and may reword. The question is therefore
    not "will the wording hold" — it is "what happens when it does not", and the
    answer has to be a direction rather than a coin toss.

    A refusal that does NOT name a spelling this batch sent is treated as a
    capability refusal: strip endpoint-wide, latch, exactly as 1.13.0's ladder
    would. The attribution is lost for the retry window, which is bad — and it
    is precisely today's behaviour, so the worst case of a reworded message is
    never worse than the release before it.

    The other direction is guarded by construction rather than by wording:
    `_refused_attributions` only ever matches ids THIS BATCH PUT ON THE WIRE.
    """
    seen = []
    dispatch.AsyncDispatcher._post = staticmethod(_backend(seen, refuse={
        RETIRED: "event_metadata contains unsupported fields: that AI system "
                 "has been retired"}))
    path = str(tmp_path / "spool.sqlite3")
    endpoint = "https://reworded.example.test/v1/logs/batch"
    _enqueue(path, endpoint,
             _row(1, {"system_id": LIVE}), _row(2, {"system_id": RETIRED}))
    try:
        dispatch._DISPATCHER._flush_spool({path})
    finally:
        del dispatch.AsyncDispatcher._post

    assert all("system_id" not in e["event_metadata"] for e in seen[-1])
    assert list(dispatch._no_provenance) == [
        (endpoint, dispatch._DEGRADED_SYSTEM_ID)], dispatch._no_provenance


def test_a_refusal_naming_an_id_this_batch_never_sent_is_not_ours_to_act_on():
    """The match is against what THIS BATCH SENT, never against a UUID shape.

    A body quoting an id this batch does not carry cannot be a refusal of this
    batch's attribution, so acting on it would strip nothing and spend a POST
    proving it. It falls to the ladder instead.
    """
    body = [_row(1, {"system_id": LIVE})]
    resp = _Response(422, text=_RETIRED_DETAIL.format(id=RETIRED))
    assert dispatch._refused_attributions(resp, body) == ()
    resp = _Response(422, text=_RETIRED_DETAIL.format(id=LIVE))
    assert dispatch._refused_attributions(resp, body) == (LIVE,)


def test_a_422_that_is_not_a_field_refusal_is_never_read_as_one():
    """THE CONTROL, and the reason the probe stays narrow.

    A bad hash must not look like "drop the attribution and retry" — retrying
    with fewer fields there is not a fix, it is a second way to be wrong. The
    id being quoted back changes nothing: the phrase gate runs first.
    """
    body = [_row(1, {"system_id": LIVE})]
    resp = _Response(422, text="prompt_hash is not hexadecimal (%s)" % LIVE)
    assert dispatch._refused_attributions(resp, body) == ()
    assert dispatch._refused_attributions(_Response(500, text=LIVE), body) == ()


# ══ surface 2 · the caller's API, and the spelling ═══════════════════════════

def test_the_client_attributes_every_event_it_records(tmp_path, monkeypatch):
    """CLIENT-LEVEL IS THE DEFAULT, because one process is usually one system.

    Set once, on the client or in `FOXY_SYSTEM_ID`, and every row this process
    writes says which declared system produced it — no decorator has to repeat
    it and none of them can forget to.
    """
    client, sent = _payloads(tmp_path, system_id=LIVE)
    _capture(monkeypatch, sent)
    client.log_interaction("a prompt", "a response", "hipaa")
    assert sent[-1]["event_metadata"] == {"system_id": LIVE}


def test_the_environment_configures_it_too(tmp_path, monkeypatch):
    """`FOXY_SYSTEM_ID`, because a DEPLOYMENT sets this, not a source file.

    The id comes out of the workspace, so the same code points at a different
    system in staging and in production. Code-only would force a rebuild to
    re-point it.
    """
    monkeypatch.setenv("FOXY_SYSTEM_ID", LIVE)
    client, sent = _payloads(tmp_path)
    _capture(monkeypatch, sent)
    client.log_interaction("a prompt", "a response", "hipaa")
    assert sent[-1]["event_metadata"]["system_id"] == LIVE


def test_the_decorator_overrides_the_client(tmp_path, monkeypatch):
    """⚠ THE OVERRIDE EARNS ITS KEEP; IT IS NOT SPECULATIVE FLEXIBILITY.

    The registry's own motivating case is one customer with SEVERAL AI products
    — a mortgage bot, a fraud screener, an internal helpdesk — and a monolith
    serving two of them from one process has no other way to say so short of
    building a second `FoxyClient`. `agent=` is a per-decorator argument for the
    identical reason and set the precedent, and the plan of record specifies
    this spelling.

    Client-level stays the DEFAULT: the override is for the process that hosts
    more than one system, not for the ordinary one that hosts exactly one.
    """
    client, sent = _payloads(tmp_path, system_id=LIVE)
    _capture(monkeypatch, sent)

    @client.audit(policy="hipaa", system_id=OTHER_RETIRED)
    def helpdesk(prompt):
        return "an answer"

    @client.audit(policy="hipaa")
    def mortgage_bot(prompt):
        return "an answer"

    helpdesk("a question")
    mortgage_bot("a question")
    assert [p["event_metadata"]["system_id"] for p in sent] == [
        OTHER_RETIRED, LIVE]


#: Every spelling of one id that `uuid.UUID` accepts and the ledger does not.
#: Five strings naming one system, and the value is CHAIN-BOUND — so five
#: spellings would be five chain hashes for one attribution.
NEAR_MISSES = (
    "{3f2504e0-4f89-41d3-9a0c-0305e82c3301}",       # braced
    "urn:uuid:3f2504e0-4f89-41d3-9a0c-0305e82c3301",
    "3F2504E0-4F89-41D3-9A0C-0305E82C3301",         # upper-case
    "3f2504e04f8941d39a0c0305e82c3301",             # undashed
)
NOT_IDS = ("not-a-uuid", "mortgage-bot", 12345, object())


@pytest.mark.parametrize("bad", NEAR_MISSES + NOT_IDS)
def test_a_spelling_the_ledger_would_refuse_is_never_sent(bad, tmp_path):
    """REFUSED AT EVERY CONFIGURE-TIME DOOR, and refused rather than repaired.

    ⚠ THE NEAR MISSES ARE THE POINT. `uuid.UUID` swallows braced, URN, undashed
    and upper-case forms, so "it parses as a UUID" is not the ledger's rule —
    `str(uuid.UUID(raw)) == raw` is, and this asks the same question the same
    way rather than writing a pattern that can drift from it.

    Repairing a near miss would be worse than refusing it, for the reason
    `_typed_tag` refuses a policy spelling it could have trimmed: the value is
    bound into a hash chain that by design cannot be edited afterwards, so
    sending an id the caller never typed puts a fabricated attribution in the
    evidence.
    """
    with pytest.raises(ValueError):
        FoxyClient(api_key="foxy_sk_test", desktop_ping=False,
                   spool_path=str(tmp_path / "spool.sqlite3"), system_id=bad)

    client, _sent = _payloads(tmp_path)
    with pytest.raises(ValueError):
        client.audit(policy="hipaa", system_id=bad)
    with pytest.raises(ValueError):
        client.log_interaction("a prompt", "a response", "hipaa", system_id=bad)


def test_an_empty_system_id_is_no_attribution_rather_than_a_bad_one(tmp_path,
                                                                    monkeypatch):
    """`""` IS "UNSET", NOT "MALFORMED", and the difference is a startup crash.

    `FOXY_SYSTEM_ID=` in a compose file, or an unset variable interpolated into
    one, is how "no attribution" is spelled in a deployment. Reading that as a
    typo would refuse to construct a client over the customer's decision NOT to
    attribute — the opposite of what the validation is for.
    """
    monkeypatch.setenv("FOXY_SYSTEM_ID", "   ")
    client, sent = _payloads(tmp_path)
    _capture(monkeypatch, sent)
    client.log_interaction("a prompt", "a response", "hipaa")
    assert "event_metadata" not in sent[-1]


def test_the_environment_is_a_door_a_typo_lives_in_too(tmp_path, monkeypatch):
    """FOXY_SYSTEM_ID is judged by the same rule as the kwarg.

    Validating the kwarg alone would leave unchecked the one place a value is
    most likely to be pasted by hand.
    """
    monkeypatch.setenv("FOXY_SYSTEM_ID", "3F2504E0-4F89-41D3-9A0C-0305E82C3301")
    with pytest.raises(ValueError):
        FoxyClient(api_key="foxy_sk_test", desktop_ping=False,
                   spool_path=str(tmp_path / "spool.sqlite3"))


def test_the_refusal_never_quotes_the_value_back():
    """Local, but a message reaches a log aggregator — and this is the argument
    a caller puts something unexpected in. The RULE is named; the value is not.
    """
    with pytest.raises(ValueError) as excinfo:
        client_module._checked_system_id("secret-looking-token", "@audit(...)")
    assert "secret-looking-token" not in str(excinfo.value)
    assert "GET /v1/systems" in str(excinfo.value)


def test_the_local_rule_is_the_ledgers_rule():
    """The SDK's check and `schemas._system_id_is_a_system_identifier` must
    agree, or a value that passes here 422s the batch anyway — which is the
    round trip, and the spooled retry loop, that validating locally avoids.

    Stated as the ledger's own predicate rather than as a pattern of our own.
    """
    for good in (LIVE, RETIRED, OTHER_RETIRED, str(uuid.uuid4())):
        assert client_module._checked_system_id(good, "x") == good
        assert str(uuid.UUID(good)) == good
    for bad in NEAR_MISSES:
        assert str(uuid.UUID(bad)) != bad, bad


def _drive_every_flavour(client, system_id):
    """Every wrapper flavour and every terminal event type, driven for real.

    ⚠ THE ATTRIBUTION GOES ON THE DECORATOR, NEVER ON THE CLIENT. The
    client-level value is picked up by `log_interaction`'s own fallback even if
    every threading site were missed, so a sweep configured that way cannot see
    the defect it exists to catch. An override can only arrive by being carried.
    """
    @client.audit(policy="hipaa", system_id=system_id)
    def sync_call(prompt):
        return "an answer"

    @client.audit(policy="hipaa", system_id=system_id)
    async def async_call(prompt):
        return "an answer"

    @client.audit(policy="hipaa", system_id=system_id)
    def sync_stream(prompt):
        yield "a"
        yield "b"

    @client.audit(policy="hipaa", system_id=system_id)
    async def async_stream(prompt):
        yield "a"
        yield "b"

    @client.audit(policy="hipaa", system_id=system_id)
    def raiser(prompt):
        raise RuntimeError("the host's own error")

    @client.audit(policy="hipaa", system_id=system_id)
    async def async_raiser(prompt):
        raise RuntimeError("the host's own error")

    @client.audit(policy="hipaa", system_id=system_id)
    async def async_stream_raiser(prompt):
        yield "a"
        raise RuntimeError("the host's own error")

    @client.audit(policy="hipaa", system_id=system_id)
    def sync_stream_raiser(prompt):
        yield "a"
        raise RuntimeError("the host's own error")

    @client.audit(policy="hipaa", mode="block", system_id=system_id)
    def blocked(prompt):
        return "never reached"

    sync_call("a clean question")
    asyncio.run(async_call("a clean question"))
    list(sync_stream("a clean question"))

    async def _drain(gen):
        return [chunk async for chunk in gen]
    asyncio.run(_drain(async_stream("a clean question")))

    for boom in (raiser, sync_stream_raiser):
        with pytest.raises(RuntimeError):
            result = boom("a clean question")
            if hasattr(result, "__iter__"):
                list(result)
    with pytest.raises(RuntimeError):
        asyncio.run(async_raiser("a clean question"))
    with pytest.raises(RuntimeError):
        asyncio.run(_drain(async_stream_raiser("a clean question")))
    with pytest.raises(FoxyPolicyBlocked):
        blocked("Patient MRN 4417829, email bob@example.com")


def _drive_every_response_block(client, system_id):
    """The four `_emit_response_block` sites: sync, async, and both streams."""
    from foxy_audit.client import FoxyResponseBlocked

    flagged = "<script>alert(1)</script>"

    @client.audit(policy="hipaa", system_id=system_id)
    def sync_call(prompt):
        return flagged

    @client.audit(policy="hipaa", system_id=system_id)
    async def async_call(prompt):
        return flagged

    @client.audit(policy="hipaa", system_id=system_id)
    def sync_stream(prompt):
        yield flagged

    @client.audit(policy="hipaa", system_id=system_id)
    async def async_stream(prompt):
        yield flagged

    async def _drain(gen):
        return [chunk async for chunk in gen]

    with pytest.raises(FoxyResponseBlocked):
        sync_call("a clean question")
    with pytest.raises(FoxyResponseBlocked):
        asyncio.run(async_call("a clean question"))
    with pytest.raises(FoxyResponseBlocked):
        list(sync_stream("a clean question"))
    with pytest.raises(FoxyResponseBlocked):
        asyncio.run(_drain(async_stream("a clean question")))


@pytest.mark.parametrize("sweep,expected", [
    (_drive_every_flavour, {"interaction", "stream", "exception", "blocked"}),
    (_drive_every_response_block, {"response_blocked"}),
])
def test_every_wrapper_flavour_and_terminal_event_carries_it(
        tmp_path, monkeypatch, sweep, expected):
    """🔴 THE GUARD AGAINST A MISSED THREADING SITE, AND THERE ARE FIFTEEN.

    The decorator's override reaches `log_interaction` through `_emit_block`,
    `_record_host_exception`, `_record_async` and `_emit_response_block`, across
    four wrapper flavours. A test that drove only the plain synchronous path
    would be green while a BLOCKED event — the row an auditor cares about most —
    went out saying no system produced it.
    """
    client, sent = _payloads(tmp_path, response_scan="block")
    _capture(monkeypatch, sent)
    sweep(client, LIVE)

    assert sent, "the sweep recorded nothing at all"
    assert {p["event_type"] for p in sent} >= expected
    missing = sorted({p["event_type"] for p in sent
                      if (p.get("event_metadata") or {}).get("system_id") != LIVE})
    assert not missing, "these event types went out unattributed: %s" % missing


# ══ surface 3 · the reservation ══════════════════════════════════════════════

def test_a_callers_own_system_id_is_dropped(tmp_path, monkeypatch, caplog):
    """`system_id` IS SDK-MANAGED FROM 1.14.0, so a hand-set copy is reserved.

    A caller who can still set it by hand bypasses BOTH halves of this phase:
    the configure-time validation that keeps a malformed id off the wire, and
    the degrade logic that knows which rows carry which attribution. It also
    bypasses the override rule — `metadata=` is merged before the SDK's own
    value is set, so a caller's copy would have won over `@audit(system_id=)`.

    ⚠ A BEHAVIOUR CHANGE FOR ANYONE ALREADY DOING IT. In 1.13.0 the key was not
    reserved, so a hand-set value passed straight through and chained. Named in
    the release notes rather than left to be discovered.
    """
    client_module._warned_reserved.clear()
    client, sent = _payloads(tmp_path)
    _capture(monkeypatch, sent)
    with caplog.at_level("WARNING", logger="foxy_audit"):
        client.log_interaction("a prompt", "a response", "hipaa",
                               metadata={"system_id": RETIRED,
                                         "model": "gpt-5.6"})

    assert sent[-1]["event_metadata"] == {"model": "gpt-5.6"}
    assert "RESERVED" in caplog.text
    # ⚠ THE REMEDY HAS TO BE THE ONE THAT FITS THIS KEY. "Pass it through
    # decision / policy_rules / blocked_reason" is right for the guard's three
    # keys and nonsense here, and a message naming the wrong control is how an
    # operator ends up in the wrong place — the lesson `_keys_phrase` records.
    assert "FOXY_SYSTEM_ID" in caplog.text


def test_the_configured_attribution_wins_over_a_hand_set_one(tmp_path,
                                                             monkeypatch):
    """Dropped, then replaced — never merged. The SDK's value is the one that
    has provably been validated and is the one `dispatch` can degrade."""
    client, sent = _payloads(tmp_path, system_id=LIVE)
    _capture(monkeypatch, sent)
    client.log_interaction("a prompt", "a response", "hipaa",
                           metadata={"system_id": RETIRED})
    assert sent[-1]["event_metadata"]["system_id"] == LIVE


def test_the_reservation_covers_the_guarded_path_too(tmp_path, monkeypatch):
    """`_reserve_provenance` runs on BOTH branches into `event_metadata`.

    A blocked row builds its metadata through the decision branch rather than
    the plain-metadata one, and a key reserved on only one of them is reserved
    on neither in practice.
    """
    client, sent = _payloads(tmp_path, system_id=LIVE)
    _capture(monkeypatch, sent)
    client.log_interaction("a prompt", "", "hipaa", event_type="blocked",
                           decision="blocked", policy_rules=["phi.email"],
                           metadata={"system_id": RETIRED})
    assert sent[-1]["event_metadata"]["system_id"] == LIVE


# ══ surface 4 · byte-identity of the unaffected path ═════════════════════════

#: The events an ordinary customer produces, spanning every branch into
#: `event_metadata`: none at all, caller metadata, the guard's decision, the
#: ruleset that explains it, and the typed tag on the clean observe path.
#:
#: ⚠ `policy="HIPAA"` IS IN HERE ON PURPOSE. It is the branch S13 added, and it
#: is the one a new fourth branch is most likely to disturb, because it is the
#: only other place that reaches `event_metadata` by `setdefault`.
UNAFFECTED = (
    dict(prompt="Summarise last quarter's revenue.", response="Revenue rose.",
         policy="hipaa"),
    dict(prompt="Summarise last quarter's revenue.", response="Revenue rose.",
         policy="HIPAA"),
    dict(prompt="a prompt", response="a response", policy="hipaa",
         agent="gpt-5.6"),
    dict(prompt="a prompt", response="a response", policy="hipaa",
         metadata={"model": "gpt-5.6", "trace_id": "t-1"}),
    dict(prompt="Patient MRN 4417829", response="", policy="hipaa",
         event_type="blocked", decision="blocked",
         policy_rules=["phi.email"], signals=["email"],
         blocked_reason="phi"),
    dict(prompt="a prompt", response="a response", policy="gdpr",
         event_type="stream", decision="allowed", policy_rules=[]),
)


def _one_payload(module, tmp_path, monkeypatch, call):
    """One event, built by ``module``'s client, with every nondeterminism pinned.

    `event_id` is a fresh uuid4 and `client_id` comes out of the spool, so
    neither can be compared across two runs unless both are held still. Pinned
    rather than filtered out: a phase that added a key would not be caught by a
    comparison that had learnt to ignore fields.
    """
    sent = []
    monkeypatch.setattr(uuid, "uuid4",
                        lambda: uuid.UUID("00000000-0000-4000-8000-000000000001"))
    monkeypatch.setattr(dispatch, "submit",
                        lambda cfg, payload, wait=False: sent.append(payload))
    client = module.FoxyClient(
        api_key="foxy_sk_test", endpoint="https://ledger.example.test",
        desktop_ping=False, spool_path=str(tmp_path / "spool.sqlite3"),
        client_id="c" * 32)
    client.log_interaction(**call)
    assert len(sent) == 1
    return sent[0]


def test_the_frozen_1_13_0_client_is_actually_the_pre_change_code():
    """INERT CONTROL, first, because the comparison below is vacuous without it.

    A bad copy, a stale fixture, or an import that silently resolved to the live
    module would leave the byte-identity proof passing while proving nothing.
    The frozen client must NOT know this phase exists.
    """
    assert OLD_CLIENT is not client_module, "the fixture resolved to the live module"
    assert not hasattr(OLD_CLIENT, "_checked_system_id")
    assert "system_id" not in OLD_CLIENT.FoxyClient.audit.__code__.co_varnames
    assert "system_id" not in OLD_CLIENT.FoxyClient.log_interaction.__code__.co_varnames
    # …and the live one must, or this is a comparison of two identical things.
    assert "system_id" in client_module.FoxyClient.audit.__code__.co_varnames


@pytest.mark.parametrize("call", UNAFFECTED, ids=range(len(UNAFFECTED)))
def test_an_unconfigured_sdk_sends_the_1_13_0_payload_byte_for_byte(
        call, tmp_path, monkeypatch):
    """⚠ THE SAFETY RAIL OF THE WHOLE PLAN, PROVED RATHER THAN ASSERTED.

    "Nothing breaks for anyone who does not pass a `system_id`" is the property
    that lets this feature ship at all — and `event_metadata` has been chain
    material since V2, so a key appearing on a row that did not need it changes
    that row's chain hash for no reason at all.

    So the payload is built TWICE — once by the frozen 1.13.0 client, once by
    today's with nothing configured — serialised through the SDK's own
    `canonical_json`, and compared as BYTES and as a SHA-256 digest. Not
    key-by-key: a comparison that walks keys cannot see a reordering, and
    `canonical_json` sorts, so equal digests are equal chain material.
    """
    old = _one_payload(OLD_CLIENT, tmp_path / "old", monkeypatch, dict(call))
    new = _one_payload(client_module, tmp_path / "new", monkeypatch, dict(call))

    old_bytes = hashing.canonical_json(old).encode("utf-8")
    new_bytes = hashing.canonical_json(new).encode("utf-8")
    assert hashlib.sha256(new_bytes).hexdigest() == \
        hashlib.sha256(old_bytes).hexdigest(), (
            "1.14.0 changed the payload of an event that carries no "
            "attribution:\n  1.13.0: %s\n  1.14.0: %s" % (old_bytes, new_bytes))
    assert new_bytes == old_bytes


def test_the_proof_can_fail(tmp_path, monkeypatch):
    """The comparison above is only worth its assertion if it can go red.

    An SDK that IS configured must produce a different payload — one extra key
    and a different digest. Without this, a harness that quietly compared
    something other than the payload would pass both ways.
    """
    call = dict(prompt="a prompt", response="a response", policy="hipaa")
    old = _one_payload(OLD_CLIENT, tmp_path / "old", monkeypatch, dict(call))
    new = _one_payload(client_module, tmp_path / "new", monkeypatch,
                       dict(call, system_id=LIVE))
    assert new != old
    assert new["event_metadata"] == {"system_id": LIVE}
    assert hashing.canonical_json(new) != hashing.canonical_json(old)


def test_an_unattributed_event_carries_no_key_rather_than_a_null(tmp_path,
                                                                 monkeypatch):
    """ABSENT, NEVER `null` — and the backend can tell the difference.

    `schemas._system_id_is_a_system_identifier` asks whether the KEY is present
    rather than whether `.get` came back None, so `{"system_id": null}` is a
    422 on the whole batch: a row claiming the field while holding nothing.
    """
    client, sent = _payloads(tmp_path)
    _capture(monkeypatch, sent)
    client.log_interaction("a prompt", "a response", "hipaa",
                           metadata={"model": "gpt-5.6"})
    assert "system_id" not in sent[-1]["event_metadata"]
    client.log_interaction("a prompt", "a response", "hipaa")
    assert "event_metadata" not in sent[-1]


# ══ surface 5 · spool rows written by another release ════════════════════════

def test_a_spool_written_by_1_13_0_flushes_clean(tmp_path):
    """THE UPGRADE. Rows already in the spool have no attribution, and must not
    acquire one, be rejected for lacking one, or be treated as degraded.

    The attribution is decided when the event is RECORDED, not when it is
    delivered — so a row spooled yesterday describes yesterday's configuration
    and this release must leave it exactly as it found it.
    """
    seen = []
    dispatch.AsyncDispatcher._post = staticmethod(_backend(seen))
    path = str(tmp_path / "spool.sqlite3")
    _enqueue(path, "https://ledger.example.test/v1/logs/batch",
             _row(1, {"model": "gpt-5.6"}),
             _row(2, {"policy_tag_raw": "HIPAA"}))
    try:
        dispatch._DISPATCHER._flush_spool({path})
    finally:
        del dispatch.AsyncDispatcher._post

    assert len(seen) == 1, "an unattributed batch cost an extra POST"
    assert seen[0][0]["event_metadata"] == {"model": "gpt-5.6"}
    assert all(r.get("foxy_degraded") is None for r in _receipts(path))
    assert not dispatch._no_provenance


def test_an_upgraded_spool_mixes_attributed_and_unattributed_rows(tmp_path):
    """The realistic upgrade: yesterday's rows beside today's, in ONE batch.

    `_flush_spool` groups by (endpoint, api_key), not by shape, so the first
    batch after an upgrade genuinely carries both. A row with no
    `event_metadata` at all must survive the semantic pass untouched — the
    branch `_drop_attribution` guards with `isinstance(metadata, dict)`.
    """
    seen = []
    dispatch.AsyncDispatcher._post = staticmethod(
        _backend(seen, refuse={RETIRED: _RETIRED_DETAIL}))
    path = str(tmp_path / "spool.sqlite3")
    old_row = _row(1, {"model": "gpt-5.6"})
    del old_row["event_metadata"]
    _enqueue(path, "https://ledger.example.test/v1/logs/batch",
             old_row, _row(2, {"system_id": RETIRED}), _row(3, {"system_id": LIVE}))
    try:
        dispatch._DISPATCHER._flush_spool({path})
    finally:
        del dispatch.AsyncDispatcher._post

    assert "event_metadata" not in seen[-1][0]
    assert "system_id" not in seen[-1][1]["event_metadata"]
    assert seen[-1][2]["event_metadata"]["system_id"] == LIVE
    marks = [r.get("foxy_degraded") for r in _receipts(path)]
    assert marks == [None, [dispatch._DEGRADED_ATTRIBUTION], None], marks


def test_a_stripped_resend_never_expects_the_attribution_back(tmp_path):
    """WHAT R2 DECIDED, AND WHAT THE RETRY MUST THEREFORE NOT ASSUME.

    R2's duplicate rule lets a stored-without / resent-with event return 202
    while silently keeping NO attribution
    (`test_an_attribution_arriving_late_is_a_duplicate_too`). So once a row has
    been resent without its attribution, the attribution is gone from the
    evidence for good — it is not merely delayed, and no later retry recovers
    it.

    The retry is designed for that: a stripped row is acked, its receipt says
    what it lost, and nothing re-queues it in the hope of a second chance. This
    drives the whole path and asserts the row LEAVES the spool.
    """
    seen = []
    dispatch.AsyncDispatcher._post = staticmethod(
        _backend(seen, refuse={RETIRED: _RETIRED_DETAIL}))
    path = str(tmp_path / "spool.sqlite3")
    endpoint = "https://ledger.example.test/v1/logs/batch"
    spool = _enqueue(path, endpoint, _row(1, {"system_id": RETIRED}))
    try:
        dispatch._DISPATCHER._flush_spool({path})
        dispatch._DISPATCHER._flush_spool({path})
    finally:
        del dispatch.AsyncDispatcher._post

    assert len(seen) == 2, "the acked row was re-POSTed: it never left the spool"
    assert spool.due(10) == []
    receipt = _receipts(path)[0]
    assert receipt["foxy_degraded"] == [dispatch._DEGRADED_ATTRIBUTION]
