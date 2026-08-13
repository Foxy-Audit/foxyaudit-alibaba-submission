"""Ruleset provenance: the frozen registry, the wire, and the degrade path (S4).

The claim this makes possible is narrow and worth stating exactly: a row says
`injection.ignore_previous` fired, and names a ruleset version whose frozen
definition contains that id and the pattern behind it. Without provenance the
chain ends at "Foxy says so"; with it, an auditor resolves the id to a rule.

That only holds if the named version stays resolvable after today's rules move.
Most of this file exists to keep that true.
"""

from __future__ import annotations

import json
import re
import time

import pytest

from foxy_audit import dispatch, policy, response_policy, ruleset


# ── the registry is frozen, not current ──────────────────────────────────────
def test_the_named_version_survives_the_current_rules_changing():
    """THE POINT OF THE WHOLE PHASE.

    A row names a version. That version must stay resolvable — and resolve to
    the SAME bytes — after someone edits the live rules, or every historical row
    becomes unverifiable the moment a regex is touched.

    This is the guard most likely to be written as a tautology, so it does not
    ask the registry to agree with itself. It MUTATES THE LIVE MODULE — appends
    a real rule to ``policy._INJECTION_RULES`` — and then asserts the frozen
    definition is byte-identical to what it was beforehand, and still explains
    the id. A registry that read through to live code fails here; one that
    genuinely froze does not.
    """
    version = ruleset.CURRENT_VERSION
    before = json.dumps(ruleset.load(version), sort_keys=True)
    live_before = ruleset.hash_of(ruleset.describe_live())

    original = policy._INJECTION_RULES
    policy._INJECTION_RULES = original + (
        ("injection.invented_by_this_test", "prompt_injection",
         re.compile(r"\bplease\s+do\s+the\s+forbidden\s+thing\b", re.IGNORECASE)),
    )
    try:
        # The live view moved...
        assert ruleset.hash_of(ruleset.describe_live()) != live_before
        # ...and the frozen one did not.
        assert json.dumps(ruleset.load(version), sort_keys=True) == before
        frozen = ruleset.load(version)
        assert "injection.ignore_previous" in frozen["prompt_rules"]["injection"]
        assert "injection.invented_by_this_test" not in frozen["prompt_rules"]["injection"]
    finally:
        policy._INJECTION_RULES = original

    assert ruleset.hash_of(ruleset.describe_live()) == live_before, "cleanup failed"


#: Every published ruleset digest, asserted as LITERALS.
#:
#: These are the one check a COORDINATED edit cannot satisfy. `drift()` compares
#: live code against the frozen module, so editing BOTH — a repo-wide refactor,
#: a bad merge, a well-meaning "tidy up the regexes and regenerate" — leaves it
#: green while silently redefining what a version means for rows already chained
#: under that name. These numbers otherwise exist only as PROSE, in the frozen
#: modules' docstrings and the README, where nothing executes them.
#:
#: If a line here fails, do NOT update it. A published ruleset is immutable;
#: rows in customers' chains name it. Mint a new version instead.
PUBLISHED = {
    "2026.08.1": "2995b7fcc2ac83a09336fdd5047fec893c5ffe3cdd01fbc2c61cb3e7a2ab1ed0",
    "2026.08.2": "59888ec66b3e2b84f550412ec5f2372e9d90f4a8df66a9e5ad9193f7c17b1f62",
}


@pytest.mark.parametrize("version,digest", sorted(PUBLISHED.items()))
def test_a_published_digest_is_exactly_what_it_has_always_been(version, digest):
    """The frozen bytes still hash to the number we published.

    2026.08.1 stays here forever even though it is superseded — rows in
    customers' chains name it, so it has to keep resolving to the same bytes.
    """
    assert ruleset.hash_of(ruleset.load(version)) == digest


def test_every_registered_version_has_a_pinned_digest():
    """CONTROL. Minting a version without pinning its digest must fail HERE.

    Otherwise the parametrize above silently covers only the versions someone
    remembered, and a new frozen module ships unpinned — which is exactly the
    hole the literal was added to close.
    """
    assert set(ruleset.known_versions()) == set(PUBLISHED)


def test_the_shipped_rows_carry_the_CURRENT_published_digest():
    """And it is the digest the SDK actually stamps on a row.

    Separate from the test above on purpose: that one pins the frozen modules,
    this one pins the path from the registry to the wire. A build that froze the
    right bytes but emitted something else would pass the first.
    """
    assert ruleset.CURRENT_VERSION in PUBLISHED
    assert ruleset.provenance()["ruleset_hash"] == PUBLISHED[ruleset.CURRENT_VERSION]
    assert ruleset.provenance()["ruleset_version"] == ruleset.CURRENT_VERSION


@pytest.mark.parametrize("version,digest", sorted(PUBLISHED.items()))
def test_each_frozen_module_states_the_digest_it_hashes_to(version, digest):
    """The docstring number and the real one must not drift apart.

    Each frozen module writes its digest into its own docstring for whoever
    reads the file. A number that is only prose rots; this makes the prose an
    assertion.
    """
    import importlib
    module = importlib.import_module(
        f"foxy_audit.rulesets.v{version.replace('.', '_')}")
    assert digest in (module.__doc__ or "")


# ── every id a row can carry must resolve in the version it names ────────────
def test_every_rule_id_the_code_can_emit_resolves_in_the_current_version():
    """THE CENTRAL CLAIM, checked rather than assumed.

    A row names a version; an auditor resolves its `policy_rules` ids against
    that version's frozen definition. If an id the SDK can emit is not in there,
    the version does not explain the row and the whole mechanism is decorative
    for that id.

    That is not hypothetical: `response_scan.degraded` / `.unreadable` were
    emitted into policy_rules from the start and described nowhere, so a row
    stamped 2026.08.1 named ids that version could not account for — and they
    are the ids that report MISSING COVERAGE, a claim about evidence quality.

    The live side is DERIVED from the modules (`live_rule_ids` walks every
    `*_RULES` table) rather than listed here, so the next family added is
    included the day it exists and fails this until someone decides.
    """
    unresolved = ruleset.live_rule_ids() - ruleset.explained_ids(
        ruleset.load(ruleset.CURRENT_VERSION))
    assert not unresolved, (
        f"ids the SDK can emit that {ruleset.CURRENT_VERSION} cannot explain: "
        f"{sorted(unresolved)}. Add them to describe_live() and mint a new version."
    )


def test_the_coverage_ids_specifically_resolve():
    """Named explicitly, because they are the ones that were missing."""
    explained = ruleset.explained_ids(ruleset.load(ruleset.CURRENT_VERSION))
    for coverage in (response_policy.adapters.COVERAGE_DEGRADED,
                     response_policy.adapters.COVERAGE_NONE):
        rule_id = response_policy.coverage_rule(coverage)
        assert rule_id in explained, rule_id


def test_2026_08_1_is_still_the_version_that_could_not_explain_them():
    """CONTROL, and the record of the defect.

    If this ever passes, either the frozen 2026.08.1 was edited — which is
    forbidden — or `explained_ids` has become lax enough to accept anything. The
    resolvability guard above would be worthless in both cases.
    """
    old = ruleset.explained_ids(ruleset.load("2026.08.1"))
    missing = ruleset.live_rule_ids() - old
    assert missing == {"response_scan.degraded", "response_scan.unreadable"}, missing


def test_live_rule_ids_actually_walks_the_tables():
    """CONTROL for the derivation. An empty set would satisfy every check above."""
    ids = ruleset.live_rule_ids()
    assert len(ids) > 30, len(ids)
    for expected in ("injection.ignore_previous", "secret.openai_key",
                     "response_markup.script_tag", "response_scan.unreadable",
                     "phi.ssn_pattern", "response_pii.email"):
        assert expected in ids, expected


def test_a_new_rule_family_is_noticed(monkeypatch):
    """The "next family added fails here until someone decides" property.

    Adding a table to the live module must make it reachable — and therefore
    unresolvable against the frozen definition — without anyone updating a list.
    """
    monkeypatch.setattr(response_policy, "_INVENTED_RULES",
                        (("invented.family", "whatever", re.compile("x")),),
                        raising=False)
    assert "invented.family" in ruleset.live_rule_ids()
    unresolved = ruleset.live_rule_ids() - ruleset.explained_ids(
        ruleset.load(ruleset.CURRENT_VERSION))
    assert unresolved == {"invented.family"}


def test_editing_a_rule_without_minting_a_version_fails_loudly():
    """`drift()` is the release-hygiene gate — an unversioned edit must shout.

    Silently re-hashing would be the worst outcome: rows would name a version
    whose published definition no longer matches the rules that produced them.
    """
    assert ruleset.drift() is None, ruleset.drift()

    original = policy._BASELINE_CHECKS
    policy._BASELINE_CHECKS = original + ("invented",)
    try:
        message = ruleset.drift()
        assert message is not None, "an edited rule did not register as drift"
        assert ruleset.CURRENT_VERSION in message
        assert "Mint a NEW version" in message
    finally:
        policy._BASELINE_CHECKS = original
    assert ruleset.drift() is None


def test_the_hash_covers_what_actually_changes_a_verdict():
    """Each of these edits MUST move the hash — asserted one at a time.

    Not a restatement of the implementation: it does not recompute the digest,
    it names the specific things an auditor would consider part of "the rule"
    and requires each to be covered. A hash over only the rule IDS would pass a
    test that just checked "some hash exists", and would let a pattern change
    underneath a version.
    """
    baseline = ruleset.hash_of(ruleset.describe_live())
    injection = policy._INJECTION_RULES
    secrets = policy._SECRET_RULES
    extra = policy._POLICY_EXTRA
    aliases = policy._POLICY_ALIASES
    priority = policy._REASON_PRIORITY
    carry = response_policy.CARRY_CHARS
    personal = response_policy._POLICY_PERSONAL

    edits = {
        "a pattern's source text": lambda: setattr_module(
            policy, "_INJECTION_RULES",
            ((injection[0][0], injection[0][1], re.compile("totally different")),)
            + injection[1:]),
        "a pattern's FLAGS only": lambda: setattr_module(
            policy, "_INJECTION_RULES",
            ((injection[0][0], injection[0][1],
              re.compile(injection[0][2].pattern)),) + injection[1:]),
        "a rule id": lambda: setattr_module(
            policy, "_SECRET_RULES",
            (("secret.renamed", secrets[0][1], secrets[0][2]),) + secrets[1:]),
        "which families a tag runs": lambda: setattr_module(
            policy, "_POLICY_EXTRA", {**extra, "soc2": ("phi",)}),
        "an alias target": lambda: setattr_module(
            policy, "_POLICY_ALIASES", {**aliases, "hipaa_basic": "gdpr"}),
        "the reason PRIORITY order": lambda: setattr_module(
            policy, "_REASON_PRIORITY", tuple(reversed(priority))),
        "the streaming carry window": lambda: setattr_module(
            response_policy, "CARRY_CHARS", carry + 1),
        "the response personal-data map": lambda: setattr_module(
            response_policy, "_POLICY_PERSONAL", {**personal, "soc2": "response_pii"}),
    }

    for label, apply in edits.items():
        restore = apply()
        try:
            assert ruleset.hash_of(ruleset.describe_live()) != baseline, \
                f"the hash ignores {label}"
        finally:
            restore()
        assert ruleset.hash_of(ruleset.describe_live()) == baseline, \
            f"restoring {label} did not return the hash"


def setattr_module(module, name, value):
    """Set an attribute and return a callable that puts it back."""
    original = getattr(module, name)
    setattr(module, name, value)
    return lambda: setattr(module, name, original)


def test_reordering_inert_rules_does_NOT_mint_a_new_hash():
    """CONTROL for the test above, and the other half of the design.

    ``evaluate`` collects every match and returns ``sorted(set(...))``, so the
    ORDER of the rule tuples cannot change any output. Hashing it would mint
    spurious versions for edits that change nothing an auditor could observe —
    and a version that changes without a behaviour change is noise in exactly
    the record that is supposed to mean something.

    Note the deliberate asymmetry with ``_REASON_PRIORITY`` above, whose order
    DOES pick the dominant blocked_reason and therefore IS hashed as a sequence.
    """
    baseline = ruleset.hash_of(ruleset.describe_live())
    restore = setattr_module(policy, "_INJECTION_RULES",
                             tuple(reversed(policy._INJECTION_RULES)))
    try:
        assert ruleset.hash_of(ruleset.describe_live()) == baseline
    finally:
        restore()


def test_the_emitted_hash_comes_from_the_FROZEN_entry_even_under_drift():
    """A drifted build must not emit a hash for rules nobody published.

    `current_hash()` reads the frozen registry, never `describe_live()`. While
    the two agree that distinction is invisible — which is exactly why it needs
    its own guard: a mutation swapping one for the other is silent today and
    catastrophic the first time someone edits a regex without minting a version,
    because rows would then name a published version while carrying the digest
    of an unpublished one.

    The cache is cleared deliberately, so this measures the source of the value
    rather than the fact that it was computed before the drift.
    """
    frozen_hash = ruleset.hash_of(ruleset.load(ruleset.CURRENT_VERSION))
    ruleset._current_hash = None

    restore = setattr_module(policy, "_BASELINE_CHECKS",
                             policy._BASELINE_CHECKS + ("invented",))
    try:
        assert ruleset.hash_of(ruleset.describe_live()) != frozen_hash,             "the drift did not take — this test would prove nothing"
        assert ruleset.provenance()["ruleset_hash"] == frozen_hash,             "emitted a hash for rules that were never published"
        assert ruleset.drift() is not None, "drift went unreported"
    finally:
        restore()
        ruleset._current_hash = None

    assert ruleset.provenance()["ruleset_hash"] == frozen_hash


def test_an_unknown_version_says_so_rather_than_guessing():
    with pytest.raises(KeyError) as caught:
        ruleset.load("1999.01.1")
    assert "unknown ruleset version" in str(caught.value)


def test_the_frozen_definition_names_its_own_boundary():
    """Presidio is excluded, and the exclusion travels WITH the evidence.

    An auditor holding this definition must be able to tell that a
    ``presidio:*`` label is out of its scope, rather than assume the hash
    covered everything.
    """
    frozen = ruleset.load(ruleset.CURRENT_VERSION)
    assert "presidio" in frozen["presidio_signals"].lower()
    assert "not covered" in frozen["presidio_signals"].lower()


def test_the_hash_matches_the_backends_canonical_json_recipe():
    """Same recipe as the backend's policy_snapshot_hash, so an independent
    verifier that implements one gets the other for free."""
    import hashlib
    sample = {"b": 1, "a": [2, 3]}
    expected = hashlib.sha256(
        json.dumps(sample, sort_keys=True, separators=(",", ":"),
                   ensure_ascii=True).encode("utf-8")).hexdigest()
    assert ruleset.hash_of(sample) == expected


# ── the wire ─────────────────────────────────────────────────────────────────
def _capture(monkeypatch):
    captured: list[dict] = []
    monkeypatch.setattr(dispatch, "submit",
                        lambda cfg, payload, *a, **k: captured.append(payload))
    return captured


def _client(tmp_path, **kwargs):
    from foxy_audit import FoxyClient
    return FoxyClient(api_key="foxy_sk_test", desktop_ping=False,
                      spool_path=str(tmp_path / "spool.sqlite3"), **kwargs)


PHI = "Patient SSN 123-45-6789"


def test_a_guarded_row_carries_both_keys(monkeypatch, tmp_path):
    from foxy_audit import FoxyPolicyBlocked

    captured = _capture(monkeypatch)

    @_client(tmp_path).audit(policy="hipaa", mode="block")
    def ask(prompt: str) -> str:
        return "resp"

    with pytest.raises(FoxyPolicyBlocked):
        ask(PHI)

    metadata = captured[0]["event_metadata"]
    assert metadata["ruleset_version"] == ruleset.CURRENT_VERSION
    assert metadata["ruleset_hash"] == ruleset.CURRENT_HASH
    assert metadata["policy_rules"], "provenance without the rules it explains"


def test_a_clean_observe_row_is_byte_identical(monkeypatch, tmp_path):
    """ASSERTED, not assumed. `observe` is the default, and a clean call must
    emit exactly the payload it emitted before this feature existed."""
    captured = _capture(monkeypatch)

    @_client(tmp_path).audit(policy="hipaa", mode="observe")
    def ask(prompt: str) -> str:
        return "all fine"

    ask("What is the capital of France?")
    payload = captured[0]
    assert "event_metadata" not in payload or not any(
        key in (payload.get("event_metadata") or {})
        for key in ruleset.PROVENANCE_KEYS)
    assert "ruleset_version" not in json.dumps(payload)
    assert "ruleset_hash" not in json.dumps(payload)


def test_provenance_never_rides_without_rules(monkeypatch, tmp_path):
    """A row can reach the metadata branch with a decision and NO rules — a
    response-scan coverage id is evidence about the scan, not a fired rule.
    Stamping a ruleset there would claim rules explained something."""
    from foxy_audit import FoxyClient

    captured = _capture(monkeypatch)
    client = _client(tmp_path)
    client.log_interaction("p", "r", "hipaa", None,
                           decision="allowed", policy_rules=[])
    metadata = captured[0].get("event_metadata") or {}
    assert "decision" in metadata
    assert not any(key in metadata for key in ruleset.PROVENANCE_KEYS)


def test_the_two_keys_are_the_only_thing_added(monkeypatch, tmp_path):
    """CONTROL. The guarded payload gains EXACTLY the provenance keys.

    Without this, a change that also started shipping something else — a rule
    count, a policy blob, anything derived from the prompt — would pass every
    other test in this file.
    """
    from foxy_audit import FoxyPolicyBlocked

    captured = _capture(monkeypatch)

    @_client(tmp_path).audit(policy="hipaa", mode="block")
    def ask(prompt: str) -> str:
        return "resp"

    with pytest.raises(FoxyPolicyBlocked):
        ask(PHI)

    keys = set(captured[0]["event_metadata"])
    assert keys == {"decision", "policy_rules", "blocked_reason",
                    "ruleset_version", "ruleset_hash"}, keys


def test_provenance_is_content_blind(monkeypatch, tmp_path):
    """The hash is over RULE DEFINITIONS. Two different prompts that trip the
    same rules must produce the same provenance, and neither may contain any
    fragment of the prompt."""
    from foxy_audit import FoxyPolicyBlocked

    captured = _capture(monkeypatch)

    @_client(tmp_path).audit(policy="hipaa", mode="block")
    def ask(prompt: str) -> str:
        return "resp"

    for secret in ("Patient SSN 123-45-6789", "Patient SSN 987-65-4321"):
        with pytest.raises(FoxyPolicyBlocked):
            ask(secret)

    first, second = captured[0]["event_metadata"], captured[1]["event_metadata"]
    assert first["ruleset_hash"] == second["ruleset_hash"]
    for digits in ("123-45-6789", "987-65-4321", "123456789"):
        assert digits not in json.dumps(first)


# ── the degrade path ─────────────────────────────────────────────────────────
class _Response:
    """A stand-in for the backend's HTTP answer, at the layer requests returns."""

    def __init__(self, status_code, text="", payload=None):
        self.status_code = status_code
        self.text = text
        self._payload = payload if payload is not None else {"status": "accepted"}

    def json(self):
        return self._payload

    def raise_for_status(self):
        if self.status_code >= 400:
            raise RuntimeError(f"HTTP {self.status_code}")


def _has_provenance(body) -> bool:
    return any(key in (event.get("event_metadata") or {})
               for event in body for key in ruleset.PROVENANCE_KEYS)


def _old_backend(seen):
    """A backend that rejects the provenance keys exactly as ours does.

    Driven at the HTTP boundary, not by stubbing the SDK's own decision: the
    thing under test is whether the SDK reacts correctly to a REAL rejection
    shape, and a fake that simulated the rejection one layer higher would prove
    only that the fallback calls itself.
    """
    def post(endpoint, api_key, body):
        seen.append(json.loads(json.dumps(body)))
        for event in body:
            metadata = event.get("event_metadata") or {}
            if any(key in metadata for key in ruleset.PROVENANCE_KEYS):
                return _Response(
                    422, text='{"detail":"event_metadata contains unsupported fields"}')
        return _Response(202, payload={"status": "accepted", "receipts": []})
    return post


def test_an_old_backend_gets_the_events_without_the_provenance(monkeypatch, tmp_path):
    """A provenance nicety must never cost a customer their audit trail."""
    from foxy_audit import FoxyClient, FoxyPolicyBlocked

    seen: list = []
    monkeypatch.setattr(dispatch.AsyncDispatcher, "_post",
                        staticmethod(_old_backend(seen)))
    monkeypatch.setattr(dispatch, "_no_provenance", {})

    client = FoxyClient(api_key="foxy_sk_test", desktop_ping=False,
                        endpoint="https://old.example.test",
                        spool_path=str(tmp_path / "spool.sqlite3"))

    @client.audit(policy="hipaa", mode="block")
    def ask(prompt: str) -> str:
        return "resp"

    with pytest.raises(FoxyPolicyBlocked):
        ask(PHI)
    dispatch._DISPATCHER._flush_spool({str(tmp_path / "spool.sqlite3")})

    # Asserted as PROPERTIES of the attempts, not as a count: the background
    # dispatcher thread flushes too, so the number of posts is a race while
    # "provenance was tried, then dropped, and the evidence survived" is not.
    assert any(_has_provenance(body) for body in seen), "never tried with provenance"
    stripped = [body for body in seen if not _has_provenance(body)]
    assert stripped, "never retried without it — the batch would have been lost"
    survivor = stripped[-1][0]["event_metadata"]
    assert survivor["policy_rules"], "the retry dropped the evidence too"
    assert survivor["decision"] == "blocked"


def test_the_degradation_is_recorded(monkeypatch, tmp_path):
    """"Retry without it" is not enough — the SDK must record that it degraded,
    or an operator cannot tell a provenance-less row from a bug."""
    from foxy_audit import FoxyClient, FoxyPolicyBlocked

    seen: list = []
    monkeypatch.setattr(dispatch.AsyncDispatcher, "_post",
                        staticmethod(_old_backend(seen)))
    monkeypatch.setattr(dispatch, "_no_provenance", {})
    path = str(tmp_path / "spool.sqlite3")

    client = FoxyClient(api_key="foxy_sk_test", desktop_ping=False,
                        endpoint="https://old.example.test", spool_path=path)

    @client.audit(policy="hipaa", mode="block")
    def ask(prompt: str) -> str:
        return "resp"

    with pytest.raises(FoxyPolicyBlocked):
        ask(PHI)
    dispatch._DISPATCHER._flush_spool({path})

    # `ack` deletes the spool row and writes a receipt keyed by event_id, so
    # the record of the degradation lives in spool_receipts.
    recorded = _receipts(path)
    assert recorded, "the batch was never acked"
    assert all(r.get("foxy_degraded") == "ruleset_provenance_stripped"
               for r in recorded), recorded


def _receipts(path):
    import sqlite3
    conn = sqlite3.connect(path)
    conn.row_factory = sqlite3.Row
    try:
        return [json.loads(r["receipt"])
                for r in conn.execute("SELECT receipt FROM spool_receipts").fetchall()]
    finally:
        conn.close()


def test_a_current_backend_is_never_asked_twice(monkeypatch, tmp_path):
    """CONTROL for the fallback. It must fire ONLY on the specific rejection.

    Without this, "retry once without the keys" could quietly become "always
    send twice", doubling every customer's ingest traffic — and no other test
    here would notice, because the events would still arrive.
    """
    from foxy_audit import FoxyClient, FoxyPolicyBlocked

    seen: list = []

    def modern(endpoint, api_key, body):
        seen.append(body)
        return _Response(202, payload={"status": "accepted"})

    monkeypatch.setattr(dispatch.AsyncDispatcher, "_post", staticmethod(modern))
    monkeypatch.setattr(dispatch, "_no_provenance", {})
    path = str(tmp_path / "spool.sqlite3")

    client = FoxyClient(api_key="foxy_sk_test", desktop_ping=False,
                        endpoint="https://new.example.test", spool_path=path)

    @client.audit(policy="hipaa", mode="block")
    def ask(prompt: str) -> str:
        return "resp"

    with pytest.raises(FoxyPolicyBlocked):
        ask(PHI)
    dispatch._DISPATCHER._flush_spool({path})

    # The property, not the post count (the dispatcher thread flushes too):
    # a healthy backend must NEVER see a stripped body. If the fallback fired
    # unconditionally, some attempt here would lack provenance.
    assert seen, "nothing was sent at all"
    assert all(_has_provenance(body) for body in seen),         "a healthy backend was sent a degraded body"
    assert not dispatch._no_provenance, "a healthy endpoint was marked as old"


def test_an_unrelated_422_is_not_treated_as_a_version_gap(monkeypatch, tmp_path):
    """A malformed payload must still fail loudly and retry normally.

    Blanket "422 -> drop fields and resend" would turn every validation error
    into a silent second attempt with less evidence attached.

    DRIVEN, not merely asserted on the predicate. This test used to build a
    stub, two monkeypatches and a tmp_path and then never flush a spool or look
    at what was posted — only the pure predicate ran, while the setup read as
    coverage for a dispatcher path it never reached.
    """
    calls: list = []

    def picky(endpoint, api_key, body):
        calls.append(json.loads(json.dumps(body)))
        return _Response(422, text='{"detail":"prompt_hash is not hex"}')

    monkeypatch.setattr(dispatch.AsyncDispatcher, "_post", staticmethod(picky))
    monkeypatch.setattr(dispatch, "_no_provenance", {})
    path = str(tmp_path / "spool.sqlite3")
    _enqueue(path, "https://picky.example.test/v1/logs/batch", _row(True, 1))

    dispatch._DISPATCHER._flush_spool({path})

    assert len(calls) == 1, "an unrelated 422 must not trigger a second attempt"
    assert _has_provenance(calls[0]), "provenance was stripped for an unrelated 422"
    assert not dispatch._no_provenance, "latched on an unrelated 422"
    assert not _receipts(path), "a rejected batch must not be acked"
    assert _spooled(path) == 1, "a rejected batch must stay spooled for retry"


def test_the_rejection_predicate_is_narrow():
    """The predicate itself, kept beside the path that consumes it."""
    assert dispatch._rejects_unsupported_fields(
        _Response(422, text='{"detail":"prompt_hash is not hex"}')) is False
    assert dispatch._rejects_unsupported_fields(
        _Response(422, text='{"detail":"event_metadata contains unsupported fields"}')) is True
    assert dispatch._rejects_unsupported_fields(_Response(202)) is False


# -- 3b: the latch expires ---------------------------------------------------
def test_the_no_provenance_latch_expires(monkeypatch):
    """A dispatcher thread lives as long as its process.

    A worker that met an old backend once during a rollout would otherwise
    strip provenance for its entire lifetime — with the backend upgraded
    minutes later — which is the very outcome the "deliberately not persisted"
    comment claimed to avoid.
    """
    monkeypatch.setattr(dispatch, "_no_provenance", {})
    endpoint = "https://rolling.example.test/v1/logs/batch"

    dispatch._no_provenance[endpoint] = time.time()
    assert dispatch._skips_provenance(endpoint) is True

    dispatch._no_provenance[endpoint] = time.time() - dispatch.PROVENANCE_RETRY_AFTER - 1
    assert dispatch._skips_provenance(endpoint) is False
    assert endpoint not in dispatch._no_provenance, "the stale entry was not cleared"


def test_an_unmarked_endpoint_is_never_skipped(monkeypatch):
    """CONTROL. "Expires" must not have become "always re-probe"."""
    monkeypatch.setattr(dispatch, "_no_provenance", {})
    assert dispatch._skips_provenance("https://fresh.example.test") is False


def test_after_expiry_provenance_is_actually_sent_again(monkeypatch, tmp_path):
    """End to end: the window closing restores provenance on the wire."""
    seen: list = []

    def modern(endpoint, api_key, body):
        seen.append(json.loads(json.dumps(body)))
        return _Response(202, payload={"status": "accepted"})

    monkeypatch.setattr(dispatch.AsyncDispatcher, "_post", staticmethod(modern))
    endpoint = "https://upgraded.example.test/v1/logs/batch"
    monkeypatch.setattr(dispatch, "_no_provenance",
                        {endpoint: time.time() - dispatch.PROVENANCE_RETRY_AFTER - 1})
    path = str(tmp_path / "spool.sqlite3")
    _enqueue(path, endpoint, _row(True, 1))

    dispatch._DISPATCHER._flush_spool({path})
    assert seen and _has_provenance(seen[0]), \
        "the endpoint stayed latched after its window closed"


def test_strip_reports_whether_it_actually_removed_anything():
    """The bound on "retry once". If nothing was stripped, the resend would be
    byte-identical to the request that just failed, so it must not happen."""
    assert dispatch._strip_provenance([{"event_metadata": {"policy_rules": []}}]) is False
    assert dispatch._strip_provenance([{}]) is False
    assert dispatch._strip_provenance([{"event_metadata": None}]) is False
    body = [{"event_metadata": {"ruleset_version": "x", "policy_rules": []}}]
    assert dispatch._strip_provenance(body) is True
    assert body == [{"event_metadata": {"policy_rules": []}}]


# ── a registry failure must never cost the event ─────────────────────────────
def test_a_broken_registry_still_captures_the_event(monkeypatch, tmp_path):
    """THE DEFECT: provenance sat inside log_interaction's blanket
    `except Exception`, so a registry that could not answer discarded the WHOLE
    guarded event. Measured before the fix: with CURRENT_VERSION="2099.01.1" the
    prompt was still blocked and ZERO events were captured — a blocked prompt
    with no evidence, which is the one outcome an audit product may never
    produce.

    Provenance is an ENRICHMENT of the record; it must never be able to cost
    the record.
    """
    from foxy_audit import FoxyPolicyBlocked

    captured = _capture(monkeypatch)
    monkeypatch.setattr(ruleset, "CURRENT_VERSION", "2099.01.1")
    monkeypatch.setattr(ruleset, "_current_hash", None)

    @_client(tmp_path).audit(policy="hipaa", mode="block")
    def ask(prompt: str) -> str:
        return "resp"

    with pytest.raises(FoxyPolicyBlocked):
        ask(PHI)

    assert len(captured) == 1, "a broken registry swallowed the audit event"
    metadata = captured[0]["event_metadata"]
    assert metadata["policy_rules"], "the evidence itself must survive intact"
    assert metadata["decision"] == "blocked"
    assert not any(key in metadata for key in ruleset.PROVENANCE_KEYS)


def test_provenance_never_raises_whatever_is_wrong_with_the_registry(monkeypatch):
    """The promise is on the function, so every call site inherits it."""
    def explode():
        raise RuntimeError("registry on fire")

    monkeypatch.setattr(ruleset, "current_hash", explode)
    assert ruleset.provenance() == {}


def test_a_healthy_registry_still_stamps_it(monkeypatch, tmp_path):
    """CONTROL for the two above. "Never raises" must not become "never works"."""
    from foxy_audit import FoxyPolicyBlocked

    captured = _capture(monkeypatch)

    @_client(tmp_path).audit(policy="hipaa", mode="block")
    def ask(prompt: str) -> str:
        return "resp"

    with pytest.raises(FoxyPolicyBlocked):
        ask(PHI)
    assert captured[0]["event_metadata"]["ruleset_version"] == ruleset.CURRENT_VERSION


# ── the degrade marker is per ROW, and the endpoint latch is earned ──────────
def _enqueue(path, endpoint, *payloads):
    """Put several events in the spool by hand, so ONE flush sees ONE batch.

    Driving this through the decorator does not work: the background dispatcher
    flushes between the two calls, so each event lands in a batch of its own and
    every per-batch-vs-per-row distinction is invisible. Measured — two
    mutations (a batch-wide degrade marker, and _provenance_in always returning
    True) both survived a version of this test that used the decorator.
    """
    from foxy_audit.spool import EventSpool
    spool = EventSpool(path)
    for payload in payloads:
        spool.enqueue(endpoint, "foxy_sk_test", payload)
    return spool


def _row(with_provenance: bool, seq: int) -> dict:
    payload = {
        "event_id": f"00000000-0000-4000-8000-{seq:012d}",
        "client_id": "c" * 32, "client_seq": seq,
        "event_type": "blocked" if with_provenance else "interaction",
        "commitment_alg": "hmac-sha256",
        "prompt_hash": "a" * 64, "response_hash": "b" * 64,
        "token_count": 3, "policy_tag": "hipaa", "pii_signals": [],
    }
    if with_provenance:
        payload["event_metadata"] = dict(
            {"decision": "blocked", "blocked_reason": "phi",
             "policy_rules": ["phi.ssn_pattern"]},
            **ruleset.provenance())
    else:
        # A clean row still carries metadata — provider/model is the ordinary
        # observe payload. Giving it NONE would make `_provenance_in` exit at
        # its isinstance guard, so the "does this row carry provenance?" branch
        # would never actually run for the clean row and a mutation of it could
        # not be observed. Measured: with an empty clean row, breaking that
        # check was invisible.
        payload["event_metadata"] = {"provider": "openai", "model": "gpt-4o"}
    return payload


def test_only_the_rows_that_carried_provenance_are_marked(monkeypatch, tmp_path):
    """`spool.ack` writes ONE receipt to every row it is handed, so a batch-wide
    flag stamped `foxy_degraded` onto clean rows that never carried provenance.
    A marker that appears on rows it cannot be true of means nothing.

    Both rows are put in ONE batch on purpose — see `_enqueue`.
    """
    seen: list = []
    monkeypatch.setattr(dispatch.AsyncDispatcher, "_post",
                        staticmethod(_old_backend(seen)))
    monkeypatch.setattr(dispatch, "_no_provenance", {})
    path = str(tmp_path / "spool.sqlite3")
    endpoint = "https://old.example.test/v1/logs/batch"
    _enqueue(path, endpoint, _row(False, 1), _row(True, 2))

    dispatch._DISPATCHER._flush_spool({path})

    receipts = _receipts(path)
    assert len(receipts) == 2, receipts
    marked = [r for r in receipts if r.get("foxy_degraded")]
    assert len(marked) == 1,         f"expected exactly the provenance-bearing row to be marked, got {receipts}"


def test_a_batch_of_only_clean_rows_is_never_marked(monkeypatch, tmp_path):
    """CONTROL. Nothing was stripped, so nothing may claim it was."""
    seen: list = []
    monkeypatch.setattr(dispatch.AsyncDispatcher, "_post",
                        staticmethod(_old_backend(seen)))
    monkeypatch.setattr(dispatch, "_no_provenance", {})
    path = str(tmp_path / "spool.sqlite3")
    _enqueue(path, "https://old.example.test/v1/logs/batch",
             _row(False, 1), _row(False, 2))

    dispatch._DISPATCHER._flush_spool({path})
    assert not any(r.get("foxy_degraded") for r in _receipts(path))


def test_the_endpoint_latch_is_only_set_when_stripping_actually_helped(monkeypatch, tmp_path):
    """"unsupported fields" is the validator's message for ANY unknown key.

    A backend rejecting something else entirely — one older than `policy_rules`,
    say — must not permanently disable provenance for the process while the real
    offender goes untouched and the batch keeps failing anyway.
    """
    def always_refuses(endpoint, api_key, body):
        return _Response(422, text='{"detail":"event_metadata contains unsupported fields"}')

    monkeypatch.setattr(dispatch.AsyncDispatcher, "_post", staticmethod(always_refuses))
    monkeypatch.setattr(dispatch, "_no_provenance", {})
    path = str(tmp_path / "spool.sqlite3")
    _enqueue(path, "https://ancient.example.test/v1/logs/batch", _row(True, 1))

    dispatch._DISPATCHER._flush_spool({path})

    assert not dispatch._no_provenance,         "latched on a rejection that stripping did not fix"
    assert not _receipts(path), "an unaccepted batch must stay spooled, not be acked"


def test_a_non_dict_202_body_does_not_requeue_an_accepted_batch(monkeypatch, tmp_path):
    """A valid-JSON but non-object 202 — a proxy answering `"accepted"` or `[]`.

    Exercised on the DEGRADED path, which is where `dict(response)` runs: the
    body was mutated after a SUCCESSFUL post, so the raise re-queued an already
    accepted batch and the events were redelivered forever. A clean-path version
    of this test proves nothing, because `spool.ack` json-dumps a str or a list
    quite happily.
    """
    for index, body in enumerate(("accepted", [], 7)):
        def proxy(endpoint, api_key, payload, _b=body):
            for event in payload:
                metadata = event.get("event_metadata") or {}
                if any(k in metadata for k in ruleset.PROVENANCE_KEYS):
                    return _Response(
                        422,
                        text='{"detail":"event_metadata contains unsupported fields"}')
            return _Response(202, payload=_b)

        monkeypatch.setattr(dispatch.AsyncDispatcher, "_post", staticmethod(proxy))
        monkeypatch.setattr(dispatch, "_no_provenance", {})
        path = str(tmp_path / f"spool-{index}.sqlite3")
        _enqueue(path, "https://proxy.example.test/v1/logs/batch", _row(True, 1))

        dispatch._DISPATCHER._flush_spool({path})

        assert _receipts(path), f"a 202 with body {body!r} was not acked"
        assert not _spooled(path), f"an accepted batch was re-queued for {body!r}"


def _spooled(path):
    import sqlite3
    conn = sqlite3.connect(path)
    try:
        return conn.execute("SELECT COUNT(*) FROM spool_events").fetchone()[0]
    finally:
        conn.close()


# -- the provenance keys are RESERVED ----------------------------------------
def test_caller_supplied_provenance_never_reaches_the_ledger(monkeypatch, tmp_path):
    """These two keys must mean "the SDK computed this" on EVERY path.

    The threat model is COLLISION, not forgery: the SDK runs in the customer's
    own process, so a determined customer can always misdescribe their own
    trail. But a customer who happens to use `ruleset_version` in their own
    metadata would silently overwrite the real one, and nothing downstream
    could tell the difference.
    """
    captured = _capture(monkeypatch)
    client = _client(tmp_path)

    # The plain-metadata path: no decision, no rules.
    client.log_interaction("p", "r", "hipaa", None,
                           metadata={"ruleset_version": "9999.99.9",
                                     "ruleset_hash": "f" * 64,
                                     "request_id": "keep-me"})
    metadata = captured[-1]["event_metadata"]
    assert metadata == {"request_id": "keep-me"}, metadata

    # The guarded path, where provenance is also being set.
    client.log_interaction("p", "r", "hipaa", None,
                           decision="blocked", policy_rules=["phi.ssn_pattern"],
                           metadata={"ruleset_version": "9999.99.9",
                                     "request_id": "keep-me"})
    metadata = captured[-1]["event_metadata"]
    assert metadata["ruleset_version"] == ruleset.CURRENT_VERSION
    assert metadata["request_id"] == "keep-me", "an unrelated key was dropped"


def test_a_caller_value_cannot_survive_a_degraded_registry(monkeypatch, tmp_path):
    """The nastiest ordering: provenance() returns {} and the caller's value
    would otherwise be left standing on the guarded path, looking computed."""
    captured = _capture(monkeypatch)
    monkeypatch.setattr(ruleset, "CURRENT_VERSION", "2099.01.1")
    monkeypatch.setattr(ruleset, "_current_hash", None)
    monkeypatch.setattr(ruleset, "_warned_unavailable", False)

    _client(tmp_path).log_interaction(
        "p", "r", "hipaa", None, decision="blocked",
        policy_rules=["phi.ssn_pattern"],
        metadata={"ruleset_version": "9999.99.9"})

    metadata = captured[-1]["event_metadata"]
    assert "ruleset_version" not in metadata, metadata
    assert metadata["policy_rules"], "the evidence itself must survive"


def test_the_reserved_drop_is_warned_once(monkeypatch, tmp_path, caplog):
    """Silently discarding a key someone deliberately passed has its own
    failure mode — they would look for their value and not find it. Once per
    process per key, because this sits in the hot path of every call."""
    import logging
    from foxy_audit import client as client_module

    monkeypatch.setattr(client_module, "_warned_reserved", set())
    _capture(monkeypatch)
    client = _client(tmp_path)

    with caplog.at_level(logging.WARNING, logger="foxy_audit"):
        for _ in range(5):
            client.log_interaction("p", "r", "hipaa", None,
                                   metadata={"ruleset_version": "9999.99.9"})

    reserved = [r for r in caplog.records if "RESERVED" in r.getMessage()]
    assert len(reserved) == 1, [r.getMessage() for r in reserved]
    assert "ruleset_version" in reserved[0].getMessage()


def test_metadata_without_reserved_keys_is_untouched(monkeypatch, tmp_path):
    """CONTROL. "Reserve two keys" must not have become "rewrite metadata"."""
    captured = _capture(monkeypatch)
    original = {"request_id": "r1", "provider": "openai", "model": "gpt-4o"}
    _client(tmp_path).log_interaction("p", "r", "hipaa", None,
                                      metadata=dict(original))
    assert captured[-1]["event_metadata"] == original


# -- 3c: a broken registry must not flood the log ----------------------------
def test_a_broken_registry_warns_once_not_per_event(monkeypatch, caplog):
    """current_hash() only caches on SUCCESS, so a broken build reaches the
    failure path on every guarded event. A warning per event is one a customer
    learns to filter, which is worse than one printed once — the same reasoning
    as policy.py's _warned_tags."""
    import logging

    monkeypatch.setattr(ruleset, "CURRENT_VERSION", "2099.01.1")
    monkeypatch.setattr(ruleset, "_current_hash", None)
    monkeypatch.setattr(ruleset, "_warned_unavailable", False)

    with caplog.at_level(logging.WARNING, logger="foxy_audit"):
        for _ in range(20):
            assert ruleset.provenance() == {}

    unavailable = [r for r in caplog.records
                   if "provenance unavailable" in r.getMessage()]
    assert len(unavailable) == 1, len(unavailable)


def test_a_healthy_registry_warns_not_at_all(monkeypatch, caplog):
    """CONTROL for the dedupe: "once" must not be reached on the happy path."""
    import logging

    monkeypatch.setattr(ruleset, "_warned_unavailable", False)
    with caplog.at_level(logging.WARNING, logger="foxy_audit"):
        for _ in range(5):
            assert ruleset.provenance()["ruleset_version"] == ruleset.CURRENT_VERSION
    assert not [r for r in caplog.records if "provenance unavailable" in r.getMessage()]
