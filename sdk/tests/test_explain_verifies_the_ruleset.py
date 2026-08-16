"""SDK #220 — a row names a ruleset, and now something checks it is the one that ran.

THE DEFECT, AND WHY IT WAS A GAP RATHER THAN A MISSING FEATURE
--------------------------------------------------------------
The chain was already complete except for its last step. The SDK emits
``ruleset_version`` AND ``ruleset_hash`` (``ruleset.PROVENANCE_KEYS``); the
backend allowlists both (``schemas.py``); both survive into
``/v1/logs/export`` (``logs.py``); ``introspect`` parses both into a result.
Then ``explain()`` loaded the definition by VERSION NAME ALONE and never
compared the hash — so ``ruleset.load()`` returned whatever this build's copy of
that module happened to contain, and a replay against altered rules was reported
as authoritative.

The row recorded a digest precisely so that could be caught. Nothing caught it.

⚠ AND IT IS NOT HYPOTHETICAL. ``2026.08.3`` was regenerated in place three times
during 1.9.0's review. That was defensible only because it was unpublished — the
rule that makes it indefensible afterwards ("a published ruleset is IMMUTABLE;
rows in customers' chains name it") was, until this, enforced by a comment in a
docstring. This is the check that makes it observable where it matters.

WHY THE RE-BREAK IS THE TEST
----------------------------
A guard that only ever sees the agreeing case tests nothing: before this change,
every row in the suite had a hash that matched, and the whole defect was that
nobody compared them. So the tests here HAND-EDIT a frozen definition, mint a row
under the original, and require the new status. If the comparison is removed, the
mutation is silent — which is exactly how the defect survived four releases.
"""

from __future__ import annotations

import copy
import json

import pytest

from foxy_audit import hashing, introspect, ruleset

PHI = "Patient SSN 123-45-6789 needs a follow-up."
KEY = "foxy_sk_s9_test"
EVENT = "11111111-1111-4111-8111-111111111111"


def _row(metadata: dict, prompt: str = PHI, key: str = KEY) -> dict:
    """One exported row, with whatever provenance the caller wants to test."""
    return {"seq": 1, "event_id": EVENT, "commitment_alg": "hmac-sha256",
            "policy_tag": "hipaa", "prompt_hash": hashing.commitment_hex(prompt, key),
            "event_metadata": metadata}


def _export(tmp_path, metadata, prompt: str = PHI, key: str = KEY) -> str:
    path = tmp_path / "logs.json"
    path.write_text(json.dumps({"org_id": "o", "logs": [_row(metadata, prompt, key)]}),
                    encoding="utf-8")
    return str(path)


def _honest_metadata(version: str | None = None) -> dict:
    """What a real guarded row carries: the version AND its digest."""
    version = version or ruleset.CURRENT_VERSION
    return {"policy_rules": ["phi.ssn_pattern"],
            "ruleset_version": version,
            "ruleset_hash": ruleset.hash_of(ruleset.load(version))}


# ── the control: the agreeing case still works, and now SAYS it verified ──────
@pytest.mark.parametrize("version", sorted(ruleset.known_versions()))
def test_a_row_whose_digest_matches_replays_and_reports_it_verified(tmp_path, version):
    """Every published version, not only the current one.

    A row in a customer's chain can name any of them, and the check has to hold
    for all — including the two that are superseded and will never be current
    again.
    """
    result = introspect.explain(PHI, EVENT, _export(tmp_path, _honest_metadata(version)),
                                KEY)
    assert result.status in ("explained", "no_matches"), result.message
    assert result.ok
    assert result.commitment_verified is True
    assert result.ruleset_verified is True, (
        "the row's digest matches this build's copy; that must be reported")
    assert result.ruleset_version == version


# ── THE RE-BREAK ─────────────────────────────────────────────────────────────
def _tamper(monkeypatch, version: str, mutate):
    """Hand-edit this build's copy of a frozen definition.

    ⚠ THE REGISTRY IS EDITED, NOT THE ROW. That is the shape of the real defect:
    the row is honest and immutable in a hash chain, and the LOCAL module is what
    drifted — a hand-edit, a partial upgrade, a backported patch. Patching
    ``ruleset.load`` reproduces it without touching a file that must never be
    touched (S9's fence: do not "fix" a frozen module to make hashes line up).
    """
    original = ruleset.load

    def loader(name):
        definition = copy.deepcopy(original(name))
        if name == version:
            mutate(definition)
        return definition

    monkeypatch.setattr(ruleset, "load", loader)


def test_an_ALTERED_registry_is_caught_and_named(tmp_path, monkeypatch):
    """⚠ THE POINT OF #220, driven end to end.

    The row is minted against the real 2026.08.3. This build's copy is then
    edited — one character of one pattern — and the replay must refuse.
    """
    metadata = _honest_metadata()          # digest taken BEFORE the tamper

    def widen_the_phone(definition):
        definition["pii_detectors"]["phone"]["pattern"] += "?"

    _tamper(monkeypatch, ruleset.CURRENT_VERSION, widen_the_phone)

    result = introspect.explain(PHI, EVENT, _export(tmp_path, metadata), KEY)

    assert result.status == "ruleset_mismatch", result.status
    assert result.ok is False, "an unverifiable replay is not a pass"
    assert result.matches == [], "a refused replay must not report spans"
    # The commitment DID verify — the prompt and the row belong together; it is
    # the rules that cannot be trusted, and the message has to separate those.
    assert result.commitment_verified is True
    assert result.ruleset_verified is False
    assert "DIFFERENT RULES" in result.message
    assert "immutable" in result.message
    assert metadata["ruleset_hash"][:12] in result.message, \
        "the message must show the digest the ROW recorded"


@pytest.mark.parametrize("field_path", [
    ("pii_detectors", "credit_card", "validator"),
    ("prompt_rules", "injection", "injection.jailbreak", "pattern"),
    ("policy_map", "baseline"),
    ("reason", "priority"),
])
def test_ANY_altered_field_is_caught_not_just_a_pattern(tmp_path, monkeypatch, field_path):
    """The hash covers the whole definition, so the guard must too.

    Parametrised across four different KINDS of edit — a validator name, a rule
    pattern, which families a tag runs, and the reason PRIORITY ORDER — because
    a check that only noticed pattern text would miss three of them while
    looking like it worked.
    """
    metadata = _honest_metadata()

    def edit(definition):
        node = definition
        for key in field_path[:-1]:
            node = node[key]
        leaf = field_path[-1]
        node[leaf] = (node[leaf] + ["invented"] if isinstance(node[leaf], list)
                      else str(node[leaf]) + "-edited")

    _tamper(monkeypatch, ruleset.CURRENT_VERSION, edit)
    result = introspect.explain(PHI, EVENT, _export(tmp_path, metadata), KEY)
    assert result.status == "ruleset_mismatch", f"{field_path} went unnoticed"


def test_the_tamper_helper_actually_tampers(tmp_path, monkeypatch):
    """CONTROL. If ``_tamper`` silently did nothing, every test above would pass
    while proving the opposite of what it claims."""
    before = ruleset.hash_of(ruleset.load(ruleset.CURRENT_VERSION))
    _tamper(monkeypatch, ruleset.CURRENT_VERSION,
            lambda d: d["pii_detectors"]["phone"].__setitem__("pattern", "x"))
    after = ruleset.hash_of(ruleset.load(ruleset.CURRENT_VERSION))
    assert before != after, "the tamper did not take; the re-break tests are vacuous"

    # ...and a DIFFERENT version is untouched, so the guard is reacting to the
    # edit rather than to the monkeypatch existing.
    other = next(v for v in ruleset.known_versions() if v != ruleset.CURRENT_VERSION)
    result = introspect.explain(PHI, EVENT,
                                _export(tmp_path, _honest_metadata(other)), KEY)
    assert result.status != "ruleset_mismatch", result.message


# ── a row with a version and NO hash: unconfirmed, not refused ────────────────
def test_a_row_with_no_ruleset_hash_still_replays_but_says_it_is_unconfirmed(tmp_path):
    """⚠ NOT A FAILURE, and the distinction is deliberate.

    The version is known and the commitment matched, so the replay is the best
    available answer and refusing would be worse than useless. What changes is
    that nobody can confirm this build's copy is the definition that ran — so
    the result carries ``ruleset_verified=False`` and the message says so.
    """
    metadata = {"policy_rules": ["phi.ssn_pattern"],
                "ruleset_version": ruleset.CURRENT_VERSION}
    result = introspect.explain(PHI, EVENT, _export(tmp_path, metadata), KEY)

    assert result.status in ("explained", "no_matches"), result.status
    assert result.ok is True, "an unconfirmed ruleset is not a refusal"
    assert result.ruleset_verified is False
    assert "no ruleset_hash" in result.message
    assert "could not confirm" in result.message


def test_no_shipped_SDK_emits_a_version_without_its_hash():
    """The claim the message above makes, asserted rather than believed.

    ``provenance()`` returns BOTH keys or NEITHER — one dict literal inside one
    try/except — and both landed in the same commit (1.7.0). So a row carrying a
    version and no hash was not written by a released foxy-audit, which is what
    the message tells the reader.
    """
    provenance = ruleset.provenance()
    assert set(provenance) == set(ruleset.PROVENANCE_KEYS), provenance
    assert all(provenance.values()), provenance

    # And the degrade path removes them TOGETHER, so it cannot produce the
    # half-populated shape either.
    from foxy_audit import dispatch
    body = [{"event_metadata": dict(provenance, policy_rules=["phi.email"])}]
    assert dispatch._strip_provenance(body) is True
    assert body[0]["event_metadata"] == {"policy_rules": ["phi.email"]}


# ── the vocabulary, and the surfaces that render it ──────────────────────────
def test_the_new_status_is_in_the_documented_vocabulary():
    """A status absent from ``STATUSES`` is one no consumer can switch on."""
    assert "ruleset_mismatch" in introspect.STATUSES
    assert "ruleset_mismatch" not in ("explained", "no_matches")
    # ...and it is NOT ok, because the whole point is that the answer is refused.
    refused = introspect.ExplainResult("ruleset_mismatch", "x")
    assert refused.ok is False


def test_as_dict_carries_the_new_field(tmp_path):
    """``--json`` is a consumer too. A field the serialiser drops is invisible."""
    result = introspect.explain(PHI, EVENT, _export(tmp_path, _honest_metadata()), KEY)
    payload = result.as_dict()
    assert payload["ruleset_verified"] is True
    assert set(payload) >= {"status", "message", "ruleset_version",
                            "commitment_verified", "ruleset_verified"}


def test_the_CLI_renders_the_verification_state(tmp_path, capsys):
    """⚠ A STATUS NOTHING RENDERS IS A STATUS NOBODY SEES.

    Both halves through the real entry point: the verified case says so, and the
    tampered case exits non-zero with the refusal on stdout. The ruleset digest
    was recorded, parsed into the result and displayed NOWHERE before this.
    """
    from foxy_audit import cli

    export = _export(tmp_path, _honest_metadata())
    prompt_file = tmp_path / "p.txt"
    prompt_file.write_text(PHI, encoding="utf-8")
    argv = ["explain", "--event-id", EVENT, "--export", export,
            "--prompt-file", str(prompt_file), "--commitment-key", KEY]

    assert cli.main(argv) == 0
    out = capsys.readouterr().out
    assert f"{ruleset.CURRENT_VERSION} (verified)" in out, out


def test_the_CLI_exits_nonzero_and_explains_on_a_tampered_registry(
        tmp_path, capsys, monkeypatch):
    """The other half of the CLI claim, and the one a customer would meet."""
    from foxy_audit import cli

    export = _export(tmp_path, _honest_metadata())
    prompt_file = tmp_path / "p.txt"
    prompt_file.write_text(PHI, encoding="utf-8")
    _tamper(monkeypatch, ruleset.CURRENT_VERSION,
            lambda d: d["pii_detectors"]["ssn_pattern"].__setitem__("pattern", "zzz"))

    code = cli.main(["explain", "--event-id", EVENT, "--export", export,
                     "--prompt-file", str(prompt_file), "--commitment-key", KEY])
    out = capsys.readouterr().out

    assert code == 1, "a refused replay must not exit 0"
    assert "DIFFERENT RULES" in out
    assert "NOT VERIFIED" in out
    assert "123-45-6789" not in out, \
        "a refused replay must not print spans it did not legitimately compute"


# ── the fence: no frozen module disagrees with itself ─────────────────────────
@pytest.mark.parametrize("version", sorted(ruleset.known_versions()))
def test_every_frozen_module_hashes_to_the_digest_its_docstring_states(version):
    """S9's fence, asserted rather than assumed.

    If a published module's stored digest disagreed with ``hash_of()`` of
    itself, that would be the first real instance of this bug and a finding —
    NOT something to paper over by regenerating the module. Checked here as well
    as in test_ruleset.py because this is the file that acts on the answer.
    """
    import importlib
    module = importlib.import_module(
        f"foxy_audit.rulesets.v{version.replace('.', '_')}")
    digest = ruleset.hash_of(ruleset.load(version))
    assert digest in (module.__doc__ or ""), (
        f"{version} hashes to {digest}, which its own docstring does not state. "
        f"Do NOT regenerate the module: a published ruleset is immutable and "
        f"rows name it. Investigate which of the two is wrong.")


# ── the messages are printed, so they have to be printable ───────────────────
def test_every_explain_message_survives_a_cp1252_console(tmp_path, monkeypatch):
    """⚠ A MESSAGE THAT CANNOT BE PRINTED IS WORSE THAN NO MESSAGE.

    `explain`'s product is its sentence, and `foxy explain` prints it to a
    console that on Windows is cp1252. The first draft of the unverified-ruleset
    note opened with U+26A0 — the warning sign this module's own COMMENTS use
    freely — and `foxy explain` died with UnicodeEncodeError. Comments are never
    printed; messages are, and the tool failing to say anything is the one
    outcome this module promises never to produce.

    Every reachable status is driven, because the defect was in the one branch
    nobody had exercised through the CLI.
    """
    honest = _honest_metadata()
    cases = [
        (PHI, honest),
        ("nothing here trips a rule at all", honest),
        ("a completely different prompt", honest),
        (PHI, {"policy_rules": []}),                          # predates_provenance
        (PHI, {"ruleset_version": "2099.01.1", "ruleset_hash": "f" * 64}),
        (PHI, {"ruleset_version": ruleset.CURRENT_VERSION}),  # no hash recorded
    ]
    seen = set()
    for prompt, metadata in cases:
        result = introspect.explain(prompt, EVENT,
                                    _export(tmp_path, metadata, prompt=PHI), KEY)
        seen.add(result.status)
        result.message.encode("cp1252")          # the assertion

    # ...and the refusal, which is the longest message and the newest one.
    def edit(definition):
        definition["pii_detectors"]["phone"]["pattern"] += "?"
    _tamper(monkeypatch, ruleset.CURRENT_VERSION, edit)
    refused = introspect.explain(PHI, EVENT, _export(tmp_path, honest), KEY)
    assert refused.status == "ruleset_mismatch"
    refused.message.encode("cp1252")
    seen.add(refused.status)

    # CONTROL: the sweep actually reached several distinct statuses, so a single
    # encodable message cannot stand in for the rest.
    assert len(seen) >= 5, sorted(seen)


def test_the_row_not_found_and_salt_messages_are_printable_too(tmp_path):
    """The two remaining statuses, which the sweep above cannot reach."""
    export = _export(tmp_path, _honest_metadata())
    introspect.explain(PHI, "00000000-0000-4000-8000-000000000000", export,
                       KEY).message.encode("cp1252")

    salted = dict(_honest_metadata())
    path = tmp_path / "salted.json"
    row = _row(salted)
    row["commitment_alg"] = "hmac-sha256-salted"
    path.write_text(json.dumps({"logs": [row]}), encoding="utf-8")
    result = introspect.explain(PHI, EVENT, str(path), KEY)
    assert result.status == "salt_unavailable"
    result.message.encode("cp1252")
