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

    The row is minted against the real CURRENT_VERSION — whichever that is;
    ``_honest_metadata`` reads it, and this sentence used to name 2026.08.3 as
    though it were fixed. That is the staleness class the test twelve lines
    below now avoids by reading the validator name from the definition, and it
    had already happened here.

    This build's copy is then edited — one character of one pattern — and the
    replay must refuse.
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
    the result carries ``ruleset_verified=None`` — NOT ``False``, which is
    reserved for a digest that ran and disagreed — and the message says so.
    """
    metadata = {"policy_rules": ["phi.ssn_pattern"],
                "ruleset_version": ruleset.CURRENT_VERSION}
    result = introspect.explain(PHI, EVENT, _export(tmp_path, metadata), KEY)

    assert result.status in ("explained", "no_matches"), result.status
    assert result.ok is True, "an unconfirmed ruleset is not a refusal"
    assert result.ruleset_verified is None, (
        "None means the check did not run; False would report this hand-edited "
        "export in the same words as a tampered registry")
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
    assert f"{ruleset.CURRENT_VERSION} (definition verified)" in out, out
    assert "NOT VERIFIED" not in out


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
    assert "DEFINITION ALTERED" in out
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
        # the three answers on the no-version branch, all reachable and all
        # printed by the CLI — S14's two are the newest messages in the module
        # and the ones no console had ever rendered.
        (PHI, {"decision": "blocked",
               "policy_rules": ["phi.ssn_pattern"]}),         # ruleset_unrecorded
        (PHI, {"decision": "allowed", "policy_rules": []}),   # no_rules_fired
        (PHI, {"policy_rules": []}),                          # provenance_ambiguous
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


# ═══════════════════════════════════════════════════════════════════════════════
# S9b — the three states, and the boundary of what "verified" claims
# ═══════════════════════════════════════════════════════════════════════════════
def _salted_export(tmp_path, metadata):
    row = _row(metadata)
    row["commitment_alg"] = "hmac-sha256-salted"
    path = tmp_path / "salted.json"
    path.write_text(json.dumps({"logs": [row]}), encoding="utf-8")
    return str(path)


@pytest.mark.parametrize("status,expected,build", [
    # ran and AGREED
    ("explained", True, lambda t: (PHI, _export(t, _honest_metadata()))),
    # ran and DISAGREED — the tamper is applied by the body below
    ("ruleset_mismatch", False, None),
    # DID NOT RUN: the row records no digest
    ("explained", None,
     lambda t: (PHI, _export(t, {"policy_rules": ["phi.ssn_pattern"],
                                 "ruleset_version": ruleset.CURRENT_VERSION}))),
    # DID NOT RUN: an earlier answer came first — the WRONG PROMPT...
    ("hash_mismatch", None,
     lambda t: ("not the committed text", _export(t, _honest_metadata()))),
    # ...and a MISSING SALT. Both still print a ruleset line.
    ("salt_unavailable", None,
     lambda t: (PHI, _salted_export(t, _honest_metadata()))),
    # DID NOT RUN: no version at all. THREE ROWS REACH THAT BRANCH AND S14 GAVE
    # THEM THREE ANSWERS. ⚠ This comment used to add that rule ids without a
    # version "can only come from a pre-1.7.0 SDK", which contradicts the
    # doctrine the same phase established one file over: a CURRENT SDK produces
    # that shape whenever the backend rejects the provenance keys
    # (`dispatch._strip_provenance` leaves `policy_rules` standing) or the
    # ruleset registry cannot answer. The row records ids and no definition; it
    # does not record why, which is what `ruleset_unrecorded` is named for.
    ("ruleset_unrecorded", None,
     lambda t: (PHI, _export(t, {"decision": "blocked",
                                 "policy_rules": ["phi.ssn_pattern"]}))),
    ("no_rules_fired", None,
     lambda t: (PHI, _export(t, {"decision": "allowed", "policy_rules": []}))),
    ("provenance_ambiguous", None,
     lambda t: (PHI, _export(t, {"policy_rules": []}))),
    # DID NOT RUN: a version this build does not carry
    ("unknown_ruleset", None,
     lambda t: (PHI, _export(t, {"ruleset_version": "2099.01.1",
                                 "ruleset_hash": "f" * 64}))),
])
def test_ruleset_verified_is_three_state_over_every_reachable_status(
        tmp_path, monkeypatch, status, expected, build):
    """⚠ None IS NOT False, AND THE DIFFERENCE IS THE DIAGNOSIS.

    The first cut of this field was a bool, so everything that was not a
    confirmed match reported ``False`` — including ``hash_mismatch`` and
    ``salt_unavailable``, where the digest check NEVER RAN and the row's hash in
    fact AGREES with this build. A reader who had simply supplied the wrong
    prompt was told, in the same words as a real tamper, that their ruleset was
    not verified.

    A table over every status ``explain`` can return, rather than a guard for the
    two reported cases: they were wrong because nobody enumerated the axis.
    """
    if build is None:
        # MINT FIRST, THEN TAMPER. _honest_metadata() hashes whatever
        # ruleset.load returns, so tampering first makes the row record the
        # TAMPERED digest — the two then agree and the case tests nothing.
        prompt, export = PHI, _export(tmp_path, _honest_metadata())
        _tamper(monkeypatch, ruleset.CURRENT_VERSION,
                lambda d: d["pii_detectors"]["ssn_pattern"].__setitem__("pattern", "zzz"))
    else:
        prompt, export = build(tmp_path)

    result = introspect.explain(prompt, EVENT, export, KEY)
    assert result.status == status, result.message
    assert result.ruleset_verified is expected, (
        f"{status}: expected {expected!r}, got {result.ruleset_verified!r}. "
        f"True = checked and agreed, False = checked and DISAGREED, "
        f"None = the check did not run.")
    # ...and --json carries the same three-way answer, not a flattened bool.
    assert result.as_dict()["ruleset_verified"] is expected


@pytest.mark.parametrize("status,fragment,build", [
    ("explained", "(definition verified)",
     lambda t: (PHI, _export(t, _honest_metadata()))),
    ("ruleset_mismatch", "(DEFINITION ALTERED", None),
    ("hash_mismatch", "(definition not checked)",
     lambda t: ("not the committed text", _export(t, _honest_metadata()))),
    ("salt_unavailable", "(definition not checked)",
     lambda t: (PHI, _salted_export(t, _honest_metadata()))),
])
def test_the_CLI_renders_the_three_states_distinguishably(
        tmp_path, capsys, monkeypatch, status, fragment, build):
    """The reader's half of the same claim: three states, three renderings.

    A field nothing renders is a field nobody sees — and two states rendered
    with ONE string are two states nobody can tell apart.
    """
    from foxy_audit import cli

    if build is None:
        prompt, export = PHI, _export(tmp_path, _honest_metadata())  # mint, THEN tamper
        _tamper(monkeypatch, ruleset.CURRENT_VERSION,
                lambda d: d["pii_detectors"]["ssn_pattern"].__setitem__("pattern", "zzz"))
    else:
        prompt, export = build(tmp_path)
    prompt_file = tmp_path / "p.txt"
    prompt_file.write_text(prompt, encoding="utf-8")

    cli.main(["explain", "--event-id", EVENT, "--export", export,
              "--prompt-file", str(prompt_file), "--commitment-key", KEY])
    out = capsys.readouterr().out
    assert fragment in out, out

    # It is printed, so it has to be printable — on the RULESET LINE, which is
    # what this change added. Not the whole of stdout: `cli._pick` already
    # downgrades the decorative ✅/❌/→ marks when the console cannot take them,
    # and under capsys (a utf-8 buffer) it correctly picks the wide ones. An
    # assertion over all of stdout measures that mechanism instead of this one.
    line = next(l for l in out.splitlines() if "ruleset   :" in l)
    line.encode("cp1252")


def test_the_three_CLI_renderings_are_actually_distinct():
    """The control for the table above: three states, three DIFFERENT strings.

    Asserting each case shows ITS fragment cannot catch two cases sharing one —
    which is exactly the defect, "NOT VERIFIED" for both a tamper and a wrong
    prompt.

    ⚠ THE STRINGS ARE EXTRACTED FROM THE CODE, NOT LISTED HERE. A first cut
    wrote them out as a literal and asserted that literal had three distinct
    members — comparing a hardcoded list to ITSELF, green by construction, and
    unable to fail however the CLI was changed. Collapsing two states in
    ``cli._explain`` now fails here, which is the only thing this test is for.
    """
    import inspect
    import re
    from foxy_audit import cli
    # ⚠ COMMENTS SHADOW A SELECTOR. An earlier cut grepped the raw source for
    # "NOT VERIFIED" and failed — on the comment ABOVE the fix explaining why
    # that wording was wrong. Only executable lines are searched.
    source = " ".join(line for line in inspect.getsource(cli._explain).splitlines()
                      if not line.lstrip().startswith("#"))

    rendered = re.findall(r'state = "([^"]+)"', source)
    assert len(rendered) == 3, (
        f"expected three renderings of the ruleset state, found {rendered}")
    assert len(set(rendered)) == 3, (
        f"two states share one rendering, so a reader cannot tell them apart: "
        f"{rendered}")

    # Each says which of the three it is, and none reuses the flattened wording
    # that could not distinguish an altered registry from an unchecked one.
    assert all("definition" in r.lower() for r in rendered), rendered
    assert {"verified", "altered", "checked"} == {
        next(w for w in ("verified", "altered", "checked") if w in r.lower())
        for r in rendered}, rendered
    assert "NOT VERIFIED" not in source


def test_the_unknown_validator_path_keeps_the_verdict_it_computed(tmp_path, monkeypatch):
    """⚠ A PATH PAST THE CHECK MUST CARRY ITS ANSWER, not fall back to a default.

    ``UnknownValidator`` is raised by ``replay``, which runs AFTER the digest
    comparison — so by then ``explain`` holds a real verdict. Returning without
    it threw away an answer already computed and reported a VERIFIED definition
    as unchecked. The distinction is the diagnosis: a verified definition naming
    a validator this build lacks means "upgrade the SDK", while the same message
    unchecked leaves open that the definition is not what it claims to be.
    """
    original = ruleset.load
    tampered = copy.deepcopy(original(ruleset.CURRENT_VERSION))
    tampered["pii_detectors"]["ssn_pattern"]["validator"] = "no-such-validator"
    monkeypatch.setattr(
        ruleset, "load",
        lambda name: copy.deepcopy(tampered) if name == ruleset.CURRENT_VERSION
        else original(name))
    # The row records the digest of THAT definition, so the comparison PASSES and
    # the unknown validator is what stops the replay.
    metadata = {"policy_rules": ["phi.ssn_pattern"],
                "ruleset_version": ruleset.CURRENT_VERSION,
                "ruleset_hash": ruleset.hash_of(tampered)}

    result = introspect.explain(PHI, EVENT, _export(tmp_path, metadata), KEY)
    assert result.status == "unknown_ruleset"
    assert result.ruleset_verified is True, (
        "the digest agreed three lines earlier; defaulting discards that")
    assert result.as_dict()["ruleset_verified"] is True


def test_the_digest_does_NOT_cover_the_validator_implementations(tmp_path, monkeypatch):
    """⚠ THE LIMIT OF THE CLAIM, ASSERTED SO IT CANNOT BE QUIETLY OVERSTATED.

    ``ruleset_hash`` is ``hash_of()`` of the frozen DEFINITION. The definition
    NAMES its validators; the CODE behind those names lives in ``introspect``,
    ships with the SDK rather than with the ruleset, and no row records a digest
    of it — so there is nothing a local copy could be compared against, and a
    check would compare this build to itself and pass unconditionally.

    Here the gap is made to bite: with the definition byte-identical and
    ``ruleset_verified`` True, swapping a validator's implementation CHANGES THE
    REPLAY'S RESULT. This test does not ask for that to be fixed — it pins the
    boundary, and requires the documentation to state it, because the
    alternative is a customer quoting "verified" for something never checked.
    """
    text = "Card 4111111111111111 on file"
    export = _export(tmp_path, _honest_metadata(), prompt=text)
    baseline = introspect.explain(text, EVENT, export, KEY)
    assert baseline.ruleset_verified is True
    assert [m.rule_id for m in baseline.matches] == ["phi.credit_card"], baseline.message

    # Same definition, same digest, DIFFERENT live code behind the same name.
    #
    # ⚠ THE NAME IS READ FROM THE DEFINITION, NOT TYPED HERE. It was hardcoded
    # as "luhn+distinct" and went stale the moment 2026.08.4 renamed the card
    # validator — the test then swapped an implementation the current ruleset no
    # longer names, and failed for a reason that had nothing to do with its
    # subject. Reading the name back from the row's own ruleset makes this hold
    # across every future mint.
    definition = ruleset.load(ruleset.CURRENT_VERSION)
    validator = definition["pii_detectors"]["credit_card"]["validator"]
    assert validator in introspect._VALIDATORS, validator
    monkeypatch.setitem(introspect._VALIDATORS, validator, lambda digits: False)
    after = introspect.explain(text, EVENT, export, KEY)

    assert after.ruleset_verified is True, "the definition really is unchanged"
    assert after.matches == [], (
        "if this ever stops differing, the digest has grown to cover validator "
        "code and the narrowing in the docs can be relaxed")

    # ...and the documentation says so, in the place a reader looks first.
    assert "_VALIDATORS" in introspect.__doc__, \
        "the module docstring must name what the digest does not cover"
    # ⚠ The field's own documentation is `#:` comments, which never reach
    # __doc__ — asserting against ExplainResult.__doc__ measured the CLASS
    # docstring and would stay green with the limit deleted. Read the source.
    import inspect as _inspect
    field_docs = _inspect.getsource(introspect.ExplainResult)
    assert "does NOT assert" in field_docs and "IMPLEMENTATIONS" in field_docs, \
        "the field must state the limit where a reader of the field will look"


def test_the_shipped_version_strings_agree_and_are_not_the_published_1_9_0():
    """⚠ FOUR STRINGS, AND THE ONE WRONG ANSWER THAT IS ALREADY ON PyPI.

    1.9.0 was tagged and published from a commit that does NOT contain #220's
    fix, and PyPI refuses a re-upload — so shipping this as 1.9.0 is not merely
    untidy, it is impossible. The four strings are checked against each other
    and against that specific wrong answer.
    """
    import re
    from pathlib import Path
    from foxy_audit import __version__

    # ⚠ THESE TESTS SHIP IN THE sdist, where the layout is not the repo's:
    # `tests/` sits beside `pyproject.toml` and `src/` at the archive root, with
    # no `sdk/` above them. Anchoring on parents[1] resolves in BOTH — anchoring
    # on the repo root does not, and a guard that only runs in the repo is not
    # guarding the thing customers install.
    here = Path(__file__).resolve().parents[1]
    pyproject = (here / "pyproject.toml").read_text(encoding="utf-8")
    init = (here / "src" / "foxy_audit" / "__init__.py").read_text(encoding="utf-8")

    declared = re.search(r'^version = "([^"]+)"', pyproject, re.M).group(1)
    assert declared == __version__, (declared, __version__)
    assert declared != "1.9.0", \
        "1.9.0 is published without this fix; PyPI rejects a re-upload"

    # The string that gets forgotten: the changelog block must OPEN with it.
    changelog = re.search(r"^# (\d+\.\d+\.\d+) — ", init, re.M).group(1)
    assert changelog == declared, (changelog, declared)

    # The fourth is the repository-root VERSION file, which is CI's input and
    # deliberately does not ship. Checked when it is there, and its absence is
    # the sdist rather than a miss — asserted, not assumed.
    root_version = here.parent / "VERSION"
    if root_version.exists():
        assert root_version.read_text(encoding="utf-8").strip() == declared
    else:
        assert not (here / "docs").exists(), \
            "no root VERSION and no sdist layout either — the anchor is wrong"


def test_no_shipped_file_credits_220_to_the_wrong_release():
    """The claim that would be false on every install, hunted by scan.

    A FROZEN module's docstring carries this claim, and frozen modules ship in
    the wheel forever. Editing that prose is allowed — it reaches no digest,
    which is the rule ``ruleset.py`` now states in full — but only if it is
    right everywhere, and a scan is how "everywhere" stops being a hope.

    ⚠ TWO THINGS THIS GUARD LEARNED THE HARD WAY.

    LINES ARE NOT SENTENCES. The first cut required ``#220`` and ``1.9.0`` on
    the SAME LINE — and the prose this very branch wrote wraps that pair across
    two lines, so a future writer wrapping the false claim the same way would
    reintroduce it GREEN, while reflowing an honest correction onto one line
    would trip it falsely. Whitespace is normalised across the whole file first,
    so the wrap is irrelevant.

    IT ASKS A POSITIVE QUESTION. Not "does 1.9.0 appear near #220" — a module
    that honestly RECOUNTS the near miss says both, and blocklisting the wrong
    answer would forbid the true sentence. What is required instead is that
    every claim of the form "#220 … fixed in <version>" names the release it was
    actually fixed in, and it does not police history.

    ⚠ THAT RELEASE IS A CONSTANT, NOT ``__version__``. The first cut compared
    against the current version and claimed it would "keep working at 1.11.0
    without an edit" — which was exactly backwards. It went red on the FIRST
    release after the fix, because #220 was fixed in 1.10.0 and stays fixed in
    1.10.0 no matter what ships next. "The release that fixed it" and "the
    release being built" are the same number for one release only, and writing
    a guard that assumes they always coincide is how a true sentence gets
    reported as a defect.
    """
    import re
    from pathlib import Path

    #: The release #220's fix actually shipped in. HISTORY, so it is a literal:
    #: it can never legitimately change, and anything that makes this line look
    #: wrong is a claim to check rather than a number to update.
    FIXED_IN = "1.10.0"

    # The claim, in either order, across at most ~120 characters of any kind —
    # newlines included, since they are already spaces by the time this runs.
    claim = re.compile(r"#220.{0,120}?fixed in (\d+\.\d+\.\d+)"
                       r"|fixed in (\d+\.\d+\.\d+).{0,120}?#220")

    src = Path(__file__).resolve().parents[1] / "src"
    offenders = []
    for path in sorted(src.rglob("*.py")):
        flat = re.sub(r"\s+", " ", path.read_text(encoding="utf-8"))
        for found in claim.finditer(flat):
            named = found.group(1) or found.group(2)
            if named != FIXED_IN:
                offenders.append(f"{path.name}: ...{found.group(0).strip()}...")

    assert not offenders, "#220 shipped in %s:\n  %s" % (
        __version__, "\n  ".join(offenders))
