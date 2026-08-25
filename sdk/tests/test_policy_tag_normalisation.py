"""S13 / #232 — ``policy="HIPAA"`` must mean HIPAA, on both paths and on the wire.

The decorator validated the tag AS TYPED against ``client._POLICY_RE``
(``^[a-z0-9_]{1,32}$``) and fell back to ``default`` on a miss, while
``policy.evaluate`` and ``introspect.check`` had folded case and whitespace all
along. So the guard's two entry points disagreed about which policy the caller
had asked for, and the one a developer actually types was the one that lost::

    @foxy.audit(policy="HIPAA", mode="block")   ->  NO PHI check ran
                                                    the PHI reached the model
                                                    the row chained as `default`

A compliance report attesting a ``default`` call that was meant to be HIPAA.

⚠ THE SWEEP IS THE POINT. Every guard here runs the SAME assertion over
:data:`SPELLINGS` — five spellings of one tag — because the suite that shipped
this exercised only the lowercase one. A test that pins ``"hipaa"`` cannot see
this defect no matter how carefully it is written, which is why one existed and
this did not.

Run with:  cd sdk && python -m pytest tests/test_policy_tag_normalisation.py -q
"""

from __future__ import annotations

import json
import re
import sqlite3

import pytest

from foxy_audit import FoxyClient, FoxyPolicyBlocked
from foxy_audit import client as client_module
from foxy_audit import dispatch, policy as policy_engine, ruleset
from foxy_audit.introspect import check

#: One tag, five ways a human types it. ``"hipaa"`` is the control: it is the
#: only one of the five whose behaviour must NOT have changed.
SPELLINGS = ("hipaa", "HIPAA", "Hipaa", " hipaa", "HIPAA ")

PHI_PROMPT = "Patient John Doe, SSN 123-45-6789, was admitted for chest pain."
SSN = "123-45-6789"


def _client(tmp_path, mode, name="s"):
    """A client that hashes and records but never reaches a network."""
    return FoxyClient(api_key="", spool_path=str(tmp_path / (name + ".sqlite3")),
                      desktop_ping=False, mode=mode)


def _payloads(tmp_path, mode, name):
    """A KEYED client plus the payloads it hands the dispatcher.

    `cfg.enabled` is False without a key and `FoxyConfig` is frozen, so the wire
    payload — the thing `policy_tag` and `policy_tag_raw` actually live on — is
    only reachable from a client that has one. Nothing is posted: `submit` is
    replaced, so the batch never leaves the process.
    """
    sent = []
    client = FoxyClient(api_key="foxy_sk_test",
                        spool_path=str(tmp_path / (name + ".sqlite3")),
                        desktop_ping=False, mode=mode)
    return client, sent


def _drive(client, tag, mode, prompt=PHI_PROMPT):
    """Run one decorated call. Returns (what the fn saw, the recorded receipt)."""
    seen = {}
    recorded = []
    client.on_event = recorded.append

    @client.audit(policy=tag, mode=mode)
    def call(prompt):
        seen["prompt"] = prompt
        return "a response"

    try:
        call(prompt)
        seen["raised"] = None
    except FoxyPolicyBlocked as exc:
        seen["raised"] = exc
    return seen, (recorded[-1] if recorded else None)


# -- the security property ----------------------------------------------------

@pytest.mark.parametrize("tag", SPELLINGS)
def test_block_mode_refuses_the_phi_prompt_under_every_spelling(tmp_path, tag):
    """The measured defect, inverted into an assertion.

    Measured on `main` before this phase: `hipaa` blocked, the other four
    reached the model. That the fn was never CALLED is asserted too — an
    exception raised after the call would be a different bug wearing this one's
    clothes, and the PHI would already have left the process.
    """
    seen, _ = _drive(_client(tmp_path, "block", tag.strip()), tag, "block")
    assert isinstance(seen["raised"], FoxyPolicyBlocked), (
        "policy=%r let a PHI prompt through in mode='block'" % (tag,))
    assert "prompt" not in seen, (
        "policy=%r called the model before refusing" % (tag,))


@pytest.mark.parametrize("tag", SPELLINGS)
def test_redact_mode_scrubs_the_phi_prompt_under_every_spelling(tmp_path, tag):
    """BLAST RADIUS, ASSERTED RATHER THAN DESCRIBED.

    Under `redact` the model now receives DIFFERENT TEXT for four of these five
    spellings. That is the fix working, and it is a behaviour change a customer
    has to be told about rather than left to discover in a model's output.
    """
    seen, _ = _drive(_client(tmp_path, "redact", tag.strip()), tag, "redact")
    assert seen["raised"] is None
    assert SSN not in seen["prompt"], (
        "policy=%r handed the model an unredacted SSN in mode='redact'" % (tag,))


@pytest.mark.parametrize("mode", ("observe", "block", "redact"))
@pytest.mark.parametrize("tag", SPELLINGS)
def test_every_spelling_chains_the_canonical_tag(tmp_path, tag, mode):
    """The evidence half. A row that says `default` for HIPAA traffic is a
    compliance report about a call that never happened."""
    _, row = _drive(_client(tmp_path, mode, tag.strip()), tag, mode,
                    prompt="Summarise last quarter's revenue.")
    assert row["policy_tag"] == "hipaa", (
        "policy=%r chained as %r" % (tag, row["policy_tag"]))


@pytest.mark.parametrize("tag", SPELLINGS)
def test_the_decorator_and_check_agree_under_every_spelling(tag):
    """ONE HELPER, NOT TWO — the property that stops this recurring.

    `check()` is the supported way to ask "would this prompt be blocked?". When
    it and the decorator fold differently, the answer it gives is about a
    different policy than the one that will actually run, and a developer has no
    way to find that out.
    """
    assert check(PHI_PROMPT, tag).triggered is True
    assert policy_engine.normalise_policy_tag(tag) == "hipaa"


# -- the typed spelling, and what must not change -----------------------------

def test_an_already_canonical_tag_adds_nothing_at_all(tmp_path):
    """THE UNAFFECTED PATH IS A CONTRACT.

    `event_metadata` has been chain-bound since V2, so a key appearing on a row
    that did not need it changes that row's chain hash for no reason. A clean
    observe row under an already-canonical tag builds no `event_metadata` at all.
    """
    _, row = _drive(_client(tmp_path, "observe"), "hipaa", "observe",
                    prompt="Summarise last quarter's revenue.")
    assert row["policy_tag"] == "hipaa"
    assert row["decision"] is None and row["policy_rules"] is None

    assert client_module._wire_policy("hipaa") == ("hipaa", None)


@pytest.mark.parametrize("tag", [s for s in SPELLINGS if s != "hipaa"])
def test_the_typed_spelling_rides_beside_the_canonical_one(tag):
    """What the caller typed is preserved — beside the tag, never instead of it."""
    assert client_module._wire_policy(tag) == ("hipaa", tag)


def test_a_miscased_observe_row_carries_the_typed_tag_and_nothing_else(tmp_path):
    """The third way into `event_metadata`, driven rather than asserted at the
    helper. A miscased tag under `observe` fires no rule and carries no caller
    metadata, so neither existing branch runs — and without a third one the row
    would record a tag nobody typed with nothing anywhere saying so."""
    client, sent = _payloads(tmp_path, "observe", "miscased")
    original = dispatch.submit
    dispatch.submit = lambda cfg, payload, wait=False: sent.append(payload)
    try:
        client.log_interaction("Summarise last quarter's revenue.", "a response",
                               "HIPAA")
    finally:
        dispatch.submit = original

    assert sent[-1]["policy_tag"] == "hipaa"
    assert sent[-1]["event_metadata"] == {"policy_tag_raw": "HIPAA"}


@pytest.mark.parametrize("bad", [
    "x" * 65,                       # over the ledger's 64-char charset cap
    "x" * 300,                      # the unbounded case: `policy=` takes any string
    "hipaa\n",                      # `$` matches before a trailing newline; `.strip()`
                                    # would then fold it to a tag that compares equal
    "hipaa​",                  # outside [A-Za-z0-9 _-]
    "hipaa;DROP",                   # ditto
])
def test_a_spelling_the_ledger_would_refuse_is_never_sent(bad):
    """REFUSED, NOT TRIMMED.

    `policy_tag_raw` is charset-locked to `[A-Za-z0-9 _-]{1,64}` and must fold
    back to this row's own `policy_tag`; a value that cannot satisfy that 422s
    the WHOLE batch, because ingest validates `payload: List[LogIngest]` as one
    unit. This is the one allowlisted key whose length a caller controls.

    Trimming it into something acceptable is the worse answer, not the safer
    one: it would store a spelling nobody typed, in a hash chain that by design
    cannot be edited afterwards.
    """
    assert client_module._wire_policy(bad)[1] is None, (
        "%r would have been sent as policy_tag_raw" % (bad,))


def test_an_identifier_smuggled_into_the_tag_never_leaves_the_process(tmp_path):
    """CONTENT-BLINDNESS, DRIVEN END TO END — the shape #246 named.

    `policy=f"hipaa-{mrn}"` is the one way a caller can put free text where a
    bounded field is expected, and this phase is what makes such a tag reach a
    NEW wire field at all. It must not: the fold leaves the hyphen in place,
    `_POLICY_RE` refuses it, the decorator substitutes `default` as it always
    has, and `_typed_tag` declines because the fold does not equal that tag.

    Asserted on the PAYLOAD rather than on the helper. The helper returning None
    proves the helper; only the payload proves that nothing else on the way to
    the dispatcher picked the value up.
    """
    mrn = "4417829"
    client, sent = _payloads(tmp_path, "observe", "mrn")
    original = dispatch.submit
    dispatch.submit = lambda cfg, payload, wait=False: sent.append(payload)
    try:
        @client.audit(policy="hipaa-" + mrn, mode="observe")
        def call(prompt):
            return "a response"
        call("Summarise last quarter's revenue.")
    finally:
        dispatch.submit = original

    assert sent, "the call recorded no event at all"
    assert sent[-1]["policy_tag"] == "default"
    assert mrn not in json.dumps(sent[-1]), sent[-1]


def test_everything_we_send_satisfies_the_ledgers_own_rule():
    """The deployed validator, re-implemented from `backend/app/schemas.py` and
    run over a corpus.

    This is the guard that survives `_POLICY_RE` being widened later — the
    others would all still pass while ingest started 422ing every batch.
    """
    charset = re.compile(r"[A-Za-z0-9 _-]{1,64}")        # _RAW_TAG_PATTERN
    separators = re.compile(r"[ -]")                     # _RAW_TAG_SEPARATORS

    corpus = list(SPELLINGS) + [
        "GDPR", " gdpr ", "Default", "SOC2", "HIPAA_BASIC", "hipaa__basic",
        "HIPAA BASIC", "hipaa-basic", "x" * 32, "X" * 32, "x" * 33,
        "", " ", "\t", "hipaa\t", "HIPAA\n", "hipaa​", None, 7, b"hipaa",
    ]
    for value in corpus:
        tag, typed = client_module._wire_policy(value)
        if typed is None:
            continue
        assert charset.fullmatch(typed), (value, typed)
        assert separators.sub("_", typed.strip().lower()) == tag, (value, typed, tag)
        assert client_module._POLICY_RE.match(tag), (value, tag)


def test_the_fold_check_holds_when_the_tag_pattern_is_widened(monkeypatch):
    """RE-AIMED AFTER A MISSED MUTATION, AND THE DIAGNOSIS IS THE POINT.

    Deleting `_typed_tag`'s fold check left all 46 guards green. That is not a
    guard lying — it is a branch today's `_POLICY_RE` makes unreachable: a tag
    matching `^[a-z0-9_]{1,32}$` holds no space and no hyphen, so the ledger's
    separator fold is a no-op on it and the equality is true by construction.

    The check exists for the day `_POLICY_RE` widens, so THAT is what this
    drives. Widen it to admit a space, and `policy="HIPAA BASIC"` folds on our
    side to `hipaa basic` and on the ledger's to `hipaa_basic` — two different
    tags. Sending the typed spelling then 422s the whole batch, because
    `LogIngest._typed_tag_is_bounded_and_is_the_same_tag` refuses a raw tag that
    does not fold to this row's `policy_tag`. Without the check, one widened
    pattern would take ingest down for every miscased multi-word tag.
    """
    monkeypatch.setattr(client_module, "_POLICY_RE",
                        re.compile(r"^[a-z0-9_ -]{1,32}$"))
    tag, typed = client_module._wire_policy("HIPAA BASIC")
    assert tag == "hipaa basic", tag
    assert typed is None, (
        "a spelling folding to %r was offered for a %r row"
        % (re.sub(r"[ -]", "_", "hipaa basic"), tag))

    # CONTROL, in the same widened world: a spelling that DOES fold back still
    # rides, so the assertion above is not an always-skip wearing a new coat.
    assert client_module._wire_policy("HIPAA") == ("hipaa", "HIPAA")


def test_a_callers_own_policy_tag_raw_is_dropped(tmp_path):
    """RESERVED.

    The ledger stops a caller writing `PCI` on a `hipaa` row. What it cannot
    stop is a caller writing a DIFFERENT legal spelling of the same tag over the
    one the SDK computed, leaving nothing downstream able to say which of the
    two it is reading.
    """
    clean = client_module._reserve_provenance(
        {"policy_tag_raw": "HiPaA", "provider": "openai"})
    assert clean == {"provider": "openai"}

    client, sent = _payloads(tmp_path, "observe", "reserved")
    original = dispatch.submit
    dispatch.submit = lambda cfg, payload, wait=False: sent.append(payload)
    try:
        client.log_interaction("a prompt", "a response", "HIPAA",
                               metadata={"policy_tag_raw": "HiPaA"})
    finally:
        dispatch.submit = original

    assert sent[-1]["event_metadata"]["policy_tag_raw"] == "HIPAA"


# -- the degrade path: production is frozen and will never allowlist this -----

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


def _frozen_backend(seen):
    """A backend that rejects `policy_tag_raw` exactly as the FROZEN production
    one does — with the allowlist's own message, at the HTTP boundary.

    Driven here rather than by stubbing the SDK's decision one layer up: the
    thing under test is whether the SDK reacts to a REAL rejection shape.
    """
    def post(endpoint, api_key, body):
        seen.append(json.loads(json.dumps(body)))
        for event in body:
            if "policy_tag_raw" in (event.get("event_metadata") or {}):
                return _Response(
                    422,
                    text='{"detail":"event_metadata contains unsupported fields"}')
        return _Response(202, payload={"status": "accepted", "receipts": []})
    return post


def _enqueue(path, endpoint, *payloads):
    """Put several events in the spool by hand, so ONE flush sees ONE batch."""
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
                    "SELECT receipt FROM spool_receipts").fetchall()]
    finally:
        conn.close()


def _row(seq, metadata):
    return {
        "event_id": "00000000-0000-4000-8000-%012d" % seq,
        "client_id": "c" * 32, "client_seq": seq,
        "event_type": "interaction", "commitment_alg": "hmac-sha256",
        "prompt_hash": "a" * 64, "response_hash": "b" * 64,
        "token_count": 3, "policy_tag": "hipaa", "pii_signals": [],
        "event_metadata": metadata,
    }


def test_a_frozen_backend_gets_the_events_without_the_typed_tag(monkeypatch,
                                                                tmp_path):
    """THE WHOLE PHASE TURNS ON THIS.

    Production is frozen and will never allowlist `policy_tag_raw`. If
    `_strip_provenance` does not walk the key, the retry is BYTE-IDENTICAL to
    the request that just failed — which that function correctly refuses to send
    — so no retry fires, `raise_for_status` raises, and `spool.retry` re-queues
    the whole batch forever. A total evidence outage, produced by the fix for a
    PHI bypass.
    """
    seen = []
    monkeypatch.setattr(dispatch.AsyncDispatcher, "_post",
                        staticmethod(_frozen_backend(seen)))
    monkeypatch.setattr(dispatch, "_no_provenance", {})
    path = str(tmp_path / "spool.sqlite3")
    _enqueue(path, "https://frozen.example.test/v1/logs/batch",
             _row(1, {"policy_tag_raw": "HIPAA"}))

    dispatch._DISPATCHER._flush_spool({path})

    assert len(seen) == 2, "expected one rejected POST and exactly one retry"
    assert "policy_tag_raw" in seen[0][0]["event_metadata"]
    assert "policy_tag_raw" not in seen[1][0]["event_metadata"]
    assert seen[0] != seen[1], "the retry must not repeat the request that failed"
    # The event is intact: the canonical tag is the part the ledger needed.
    assert seen[1][0]["policy_tag"] == "hipaa"
    assert len(_receipts(path)) == 1


def _typed_tag_only_backend(seen):
    """The FROZEN PRODUCTION backend: refuses `policy_tag_raw`, accepts ruleset
    provenance. That asymmetry is the whole point — it is the shape that made a
    single-dimension latch strip keys this backend was happy to take.
    """
    def post(endpoint, api_key, body):
        seen.append(json.loads(json.dumps(body)))
        for event in body:
            if "policy_tag_raw" in (event.get("event_metadata") or {}):
                return _Response(
                    422,
                    text='{"detail":"event_metadata contains unsupported fields"}')
        return _Response(202, payload={"status": "accepted", "receipts": []})
    return post


def test_a_typed_tag_rejection_does_not_cost_the_next_batch_its_provenance(
        monkeypatch, tmp_path):
    """🔴 THE LATCH IS PER (ENDPOINT, RUNG), AND THIS IS WHY.

    `_no_provenance` was keyed by ENDPOINT ALONE while the strip removed one key
    set. When the strip grew to two, a backend refusing ONLY `policy_tag_raw` —
    exactly the frozen production one — latched on the first miscased-tag row,
    and every later batch went out with `ruleset_version`/`ruleset_hash`
    pre-stripped from a backend that accepts them. For 900 seconds, silently,
    re-armed by the next miscased tag.

    ⚠ AND IT WOULD HAVE CORRUPTED `explain`. A row with rule ids and no version
    reads as `ruleset_unrecorded` cause 1 — "the backend rejected the provenance
    keys" — which is FALSE for such a row. S14 and S17 spent four rounds making
    that sentence honest.

    ⚠ DRIVEN THROUGH `_flush_spool`, IN TWO SEPARATE FLUSHES, NOT ASSERTED ON
    THE LATCH. A unit test on `_latched_rungs` passes on the broken code: the
    defect is not that the latch stores the wrong thing, it is that the STRIP
    consults it without the rung. Only a second batch can see that.
    """
    seen = []
    monkeypatch.setattr(dispatch.AsyncDispatcher, "_post",
                        staticmethod(_typed_tag_only_backend(seen)))
    monkeypatch.setattr(dispatch, "_no_provenance", {})
    endpoint = "https://frozen.example.test/v1/logs/batch"
    path = str(tmp_path / "spool.sqlite3")

    # Batch 1: a miscased tag. Rejected, stripped, accepted — and it latches.
    _enqueue(path, endpoint, _row(1, {"policy_tag_raw": "HIPAA"}))
    dispatch._DISPATCHER._flush_spool({path})
    assert dispatch._no_provenance, "the rejection did not latch at all"
    assert list(dispatch._no_provenance) == [(endpoint, "policy_tag_raw_stripped")], (
        "the latch does not name WHICH key set was refused: %r"
        % (dispatch._no_provenance,))

    # Batch 2: an ordinary blocked row, no typed tag, carrying provenance this
    # backend has never once objected to.
    seen.clear()
    _enqueue(path, endpoint, _row(2, dict({"decision": "blocked",
                                           "policy_rules": ["phi.ssn_pattern"]},
                                          **ruleset.provenance())))
    dispatch._DISPATCHER._flush_spool({path})

    assert len(seen) == 1, "a batch carrying no refused key was retried anyway"
    sent = seen[0][0]["event_metadata"]
    assert "ruleset_version" in sent and "ruleset_hash" in sent, (
        "a typed-tag rejection stripped provenance from a backend that accepts "
        "it — and `explain` would then read this row as cause 1: %r" % (sent,))

    # The receipt must not claim a loss either.
    assert all(not r.get("foxy_degraded") for r in _receipts(path)[1:])


def test_the_escalation_stops_at_the_rung_that_was_actually_refused(
        monkeypatch, tmp_path):
    """One rung at a time, newest first, and no further than it has to go.

    A blanket strip would answer "policy_tag_raw is unknown here" by also
    dropping provenance the backend accepts. Two POSTs is the bound for this
    shape: the original, and one retry without the typed tag.
    """
    seen = []
    monkeypatch.setattr(dispatch.AsyncDispatcher, "_post",
                        staticmethod(_typed_tag_only_backend(seen)))
    monkeypatch.setattr(dispatch, "_no_provenance", {})
    path = str(tmp_path / "spool.sqlite3")
    _enqueue(path, "https://frozen.example.test/v1/logs/batch",
             _row(1, dict({"decision": "blocked",
                           "policy_rules": ["phi.ssn_pattern"],
                           "policy_tag_raw": "HIPAA"}, **ruleset.provenance())))

    dispatch._DISPATCHER._flush_spool({path})

    assert len(seen) == 2, "expected the original POST and exactly one retry"
    kept = seen[1][0]["event_metadata"]
    assert "policy_tag_raw" not in kept, "the refused key survived the retry"
    assert "ruleset_version" in kept, (
        "the escalation over-stripped: provenance went with a typed-tag "
        "rejection: %r" % (kept,))
    assert _receipts(path)[0]["foxy_degraded"] == ["policy_tag_raw_stripped"]


def test_an_older_backend_still_gets_both_rungs_dropped(monkeypatch, tmp_path):
    """CONTROL for the escalation. "One rung at a time" must not have become
    "never reaches the second rung" — that would be the pre-1.7.0 evidence
    outage the degrade path was built for, reintroduced as a fix for this one.

    Two retries here, not one, and that is the stated cost: the ladder finds the
    true boundary in at most one POST beyond it.
    """
    seen = []

    def ancient(endpoint, api_key, body):
        seen.append(json.loads(json.dumps(body)))
        for event in body:
            meta = event.get("event_metadata") or {}
            if any(k in meta for k in ("policy_tag_raw", "ruleset_version",
                                       "ruleset_hash")):
                return _Response(
                    422,
                    text='{"detail":"event_metadata contains unsupported fields"}')
        return _Response(202, payload={"status": "accepted", "receipts": []})

    monkeypatch.setattr(dispatch.AsyncDispatcher, "_post", staticmethod(ancient))
    monkeypatch.setattr(dispatch, "_no_provenance", {})
    endpoint = "https://ancient.example.test/v1/logs/batch"
    path = str(tmp_path / "spool.sqlite3")
    _enqueue(path, endpoint, _row(1, dict({"decision": "blocked",
                                           "policy_rules": ["phi.ssn_pattern"],
                                           "policy_tag_raw": "HIPAA"},
                                          **ruleset.provenance())))

    dispatch._DISPATCHER._flush_spool({path})

    assert len(seen) == 3, "expected the original POST and two escalating retries"
    assert seen[2][0]["event_metadata"] == {"decision": "blocked",
                                            "policy_rules": ["phi.ssn_pattern"]}
    assert sorted(dispatch._no_provenance) == sorted([
        (endpoint, "policy_tag_raw_stripped"),
        (endpoint, "ruleset_provenance_stripped")]), dispatch._no_provenance
    assert _receipts(path)[0]["foxy_degraded"] == ["policy_tag_raw_stripped",
                                                   "ruleset_provenance_stripped"]


def test_the_warning_names_the_key_that_was_actually_refused(
        monkeypatch, tmp_path, caplog):
    """The ONLY operator-facing signal on this path.

    It said "rejected ruleset provenance ... upgrade the backend to restore it"
    whatever had been dropped — so a typed-tag rejection sent an operator to
    upgrade a backend over a key it had never been asked about, while the row
    that actually lost something went unmentioned.
    """
    seen = []
    monkeypatch.setattr(dispatch.AsyncDispatcher, "_post",
                        staticmethod(_typed_tag_only_backend(seen)))
    monkeypatch.setattr(dispatch, "_no_provenance", {})
    path = str(tmp_path / "spool.sqlite3")
    _enqueue(path, "https://frozen.example.test/v1/logs/batch",
             _row(1, {"policy_tag_raw": "HIPAA"}))

    with caplog.at_level("WARNING", logger="foxy_audit"):
        dispatch._DISPATCHER._flush_spool({path})

    messages = [r.getMessage() for r in caplog.records]
    assert any("policy_tag_raw" in m for m in messages), messages
    assert not any("upgrade the backend" in m for m in messages), (
        "a typed-tag rejection told the operator to upgrade the backend: %r"
        % (messages,))


def test_a_refused_spelling_is_warned_rather_than_chained_in_silence(caplog):
    """FINDING 4. The fold still happens — it must, or #232 walks back in — but
    a row where the typed spelling could not be recorded chains
    indistinguishably from one where the caller typed the tag exactly.

    A tag nobody typed with nothing saying so is what the third `event_metadata`
    branch exists to prevent; where the ledger will not hold the spelling, the
    log is the honest limit. Once per canonical tag, so a hot loop is not noise.
    """
    client_module._warned_untypable.discard("gdpr")
    with caplog.at_level("WARNING", logger="foxy_audit"):
        tag, typed = client_module._wire_policy("gdpr\t")
        assert (tag, typed) == ("gdpr", None)
        first = len([r for r in caplog.records if "gdpr" in r.getMessage()])
        client_module._wire_policy("GDPR\n")
        again = len([r for r in caplog.records if "gdpr" in r.getMessage()])

    assert first == 1, "the dropped spelling was never reported"
    assert again == 1, "reported more than once for one tag"


def test_the_receipt_names_what_this_row_actually_lost(monkeypatch, tmp_path):
    """A miscased tag under `observe` fires no rule, so its `event_metadata`
    carries ONLY `policy_tag_raw` — no ruleset provenance rides with it.
    Stamping `ruleset_provenance_stripped` on that row would name a key it never
    held, which is the marker-that-cannot-be-true failure the per-row split
    exists to prevent.

    All three rows go in ONE batch on purpose: the distinction is per-row, and a
    batch of one makes every per-row bug invisible.
    """
    seen = []
    monkeypatch.setattr(dispatch.AsyncDispatcher, "_post",
                        staticmethod(_frozen_backend(seen)))
    monkeypatch.setattr(dispatch, "_no_provenance", {})
    path = str(tmp_path / "spool.sqlite3")
    _enqueue(path, "https://frozen.example.test/v1/logs/batch",
             _row(1, {"policy_tag_raw": "HIPAA"}),
             _row(2, dict({"decision": "blocked",
                           "policy_rules": ["phi.ssn_pattern"],
                           "policy_tag_raw": "HIPAA"}, **ruleset.provenance())),
             _row(3, {"provider": "openai", "model": "gpt-4o"}))

    dispatch._DISPATCHER._flush_spool({path})

    marks = sorted(str(r.get("foxy_degraded")) for r in _receipts(path))
    assert marks == ["None",
                     "['policy_tag_raw_stripped']",
                     "['policy_tag_raw_stripped']"], marks

    # ⚠ A LIST, ALWAYS, EVEN FOR ONE RUNG — decided, not fallen into.
    # `foxy_degraded` is user-visible: `submit(wait=True)` returns the receipt
    # under `audit_required`. It was a bare constant while only one key set could
    # be stripped; two made it a set of things, and the two shapes that keep it a
    # string — a comma-joined value, or the first rung only — are a parsing trap
    # and a lie respectively. Order is LADDER order, not sort order, so it stays
    # stable as rungs are added.
    for receipt in _receipts(path):
        assert receipt.get("foxy_degraded") is None or isinstance(
            receipt["foxy_degraded"], list), receipt

    # And the ROW THAT KEPT ITS PROVENANCE says so. Only the typed-tag rung was
    # refused here, so row 2 lost its spelling and NOT its ruleset version — a
    # receipt claiming otherwise would send a reader to the wrong cause.
    assert all("ruleset_provenance_stripped" not in (r.get("foxy_degraded") or [])
               for r in _receipts(path))
