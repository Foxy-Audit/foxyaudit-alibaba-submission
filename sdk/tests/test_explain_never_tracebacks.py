"""SDK #245 (S17) — ``foxy explain`` ANSWERS. It does not traceback.

THE PROMISE THIS FILE GUARDS
----------------------------
``introspect``'s own words: *"a traceback out of ``foxy explain`` would be the
tool failing to say 'I cannot', which is the one thing this module promises."*
``_printable`` was written for that promise and applied to four values; twelve
message sites bypassed it, and ``_row_for`` reached ``.get`` on whatever the
file's top level happened to be.

⚠ ``!r`` DOES NOT ESCAPE NON-ASCII IN PYTHON 3. That is why five ``{version!r}``
sites LOOKED guarded and were not. ``repr("x" + chr(0x130))`` keeps the
character verbatim, and a cp1252 console cannot encode it. Every measurement
below was taken by running the public function and encoding the message it
returned, never by reading the source: a table of sites is not evidence that any
of them raised.

⚠ AND THE VALUE MUST STILL BE SHOWN. Escaped, not dropped — a reader has to be
able to see that the id, path or version was not what they expected. Every test
here asserts the escape is PRESENT as well as the message being printable, so a
future "fix" that strips hostile characters turns these red.

WHAT NEEDS A HAND-EDITED REGISTRY, AND WHY THAT IS NOT CHEATING
---------------------------------------------------------------
Five of these arms sit PAST a successful ``ruleset.load``, so the version they
print is by construction a key of this build's registry — ASCII, unless the
registry itself was edited. That is not a contrived state: it is the exact
scenario those arms exist to REPORT (``ruleset_mismatch``'s message names "a
hand-edit, a partial upgrade, a backported patch" in so many words, and
``UnknownValidator`` is "a definition from a newer release backported without
its code"). The tests that need it say so in their own docstrings and restore
the registry in a ``finally``.
"""

from __future__ import annotations

import copy

import pytest

from foxy_audit import hashing, introspect, ruleset
from foxy_audit import rulesets as registry

KEY = "foxy_sk_s17"
EVENT = "22222222-2222-4222-8222-222222222222"
#: U+0130. Legal in JSON, legal in a Windows path, unencodable in cp1252.
ODD = chr(0x130)
#: What ``_printable`` must leave behind. Built from ``chr(92)`` because a
#: literal escape in a test is one more thing to typo.
ESC = chr(92) + "u0130"
PHI = "Patient SSN 123-45-6789 needs a follow-up."
CLEAN = "What does minimum necessary require for a vendor?"

CURRENT = ruleset.CURRENT_VERSION
CURRENT_HASH = ruleset.hash_of(ruleset.load(CURRENT))


def _row(**over) -> dict:
    row = {"seq": 1, "event_id": EVENT, "policy_tag": "hipaa",
           "commitment_alg": "hmac-sha256",
           "prompt_hash": hashing.commitment_hex(PHI, KEY)}
    row.update(over)
    return row


def _export(*rows) -> dict:
    return {"org_id": "o", "logs": list(rows)}


#: A backslash-u that got escaped TWICE. Every message these tests produce is
#: checked against it, because the single-escaped form is a substring of the
#: doubled one and a containment check alone therefore passes under both
#: renderings — the way the first cut of this file did.
DOUBLED = chr(92) + chr(92) + "u"


def _printable_message(result) -> str:
    """The assertion, and it is the ENCODE rather than an inspection of the
    string: cp1252 is what a Windows console actually does to it.

    ⚠ IT ALSO PINS ONE LAYER OF ESCAPING, centrally, because every test in
    this file goes through it. `{_printable(x)!r}` renders a hostile value
    with a DOUBLED backslash, which is printable and still wrong: a reader
    cannot tell it from a value that really held one.
    """
    result.message.encode("cp1252")
    assert DOUBLED not in result.message, (
        "escaped twice — a sentence is applying `!r` to a value "
        "`_printable` has already handled: " + result.message)
    return result.message


# ══ 1 · the export is not a ledger ══════════════════════════════════════════
def test_a_top_level_list_export_answers_instead_of_raising():
    """🔴 MEASURED AT THE S14 GATE: ``explain('x', 'id', [1, 2, 3], key)``
    raised AttributeError from ``_row_for``, before the ``isinstance(export,
    dict)`` guard S14d added could produce the answer it was written for."""
    result = introspect.explain(PHI, "id", [1, 2, 3], KEY)

    assert result.status == "export_unreadable"
    assert "COULD NOT BE READ" in _printable_message(result)
    assert "list" in result.message, "the reader is not told what they handed us"


def test_a_logs_that_is_not_a_list_answers_instead_of_raising():
    """``export.get("logs", []) or []`` handed an int straight to ``for``. The
    old guard could not have caught it either: it only ever asked whether the
    ENTRIES were rows."""
    result = introspect.explain(PHI, "id", {"logs": 5}, KEY)

    assert result.status == "export_unreadable"
    assert "int" in _printable_message(result)


def test_a_document_with_no_logs_key_at_all_is_not_a_ledger():
    """``/v1/logs/export`` emits ``{"org_id": ..., "logs": [...]}``. A JSON
    object without that key is some other document, and saying "check your
    event_id" about it points the reader at the wrong half of their problem."""
    result = introspect.explain(PHI, "id", {"org_id": "o"}, KEY)

    assert result.status == "export_unreadable"
    assert "absent" in _printable_message(result)


def test_an_empty_logs_list_is_still_row_not_found():
    """⚠ THE CONTROL FOR THE SPLIT, AND THE LINE S17 DELIBERATELY DID NOT CROSS.

    ``{"logs": []}`` is a WELL-FORMED export that covers no rows. It is
    readable; what is wrong is the reader's RANGE, and "export a range that
    covers it" is the right advice. Widening ``export_unreadable`` to swallow it
    would be the mirror-image wrong steer — telling someone to re-export a file
    that is perfectly good.
    """
    result = introspect.explain(PHI, EVENT, {"org_id": "o", "logs": []}, KEY)

    assert result.status == "row_not_found"
    assert "export a range" in _printable_message(result)
    assert "COULD NOT BE READ" not in result.message


def test_export_unreadable_is_in_the_vocabulary_and_is_a_refusal():
    """The status is public, so the tuple every consumer switches on has to
    carry it. ``ExplainResult.ok`` must stay False for it: nothing was
    checked."""
    assert "export_unreadable" in introspect.STATUSES
    assert not introspect.ExplainResult("export_unreadable", "m").ok


# ══ 2 · the values a hostile export carries ═════════════════════════════════
def test_a_non_ascii_sidecar_path_prints(tmp_path):
    """⚠ THE ONE MESSAGE WHOSE WHOLE JOB IS TO STOP A READER TAKING "could not
    check" FOR "did not match" — and a Windows user with a non-ASCII home
    directory got a traceback instead of it."""
    export = _export(_row(commitment_alg="hmac-sha256-salted"))

    result = introspect.explain(PHI, EVENT, export, KEY,
                                str(tmp_path / ("C" + ODD) / "salts.jsonl"))

    assert result.status == "salt_unavailable"
    assert ESC in _printable_message(result), "the path was dropped, not escaped"
    assert "CANNOT be recomputed" in result.message


def test_a_non_ascii_commitment_alg_prints():
    """The alg is a row value and the salt message names it verbatim."""
    export = _export(_row(commitment_alg="hmac-" + ODD + "-salted"))

    result = introspect.explain(PHI, EVENT, export, KEY)

    assert result.status == "salt_unavailable"
    assert ESC in _printable_message(result)


def test_a_non_ascii_ruleset_version_prints():
    """``{version!r}`` on the unknown-ruleset arm. ``!r`` quotes it; it does not
    escape it."""
    export = _export(_row(event_metadata={"ruleset_version": "2026.08." + ODD,
                                          "policy_rules": ["phi.ssn"]}))

    result = introspect.explain(PHI, EVENT, export, KEY)

    assert result.status == "unknown_ruleset"
    # EXACT, not "contains the escape": the quotes belong to the sentence now
    # that `!r` is gone, and this is the rendering a reader actually gets.
    assert "ruleset '2026.08." + ESC + "'," in _printable_message(result)


def test_a_non_ascii_recorded_digest_prints():
    """``recorded_hash[:12]`` is a row value too, and the mismatch message is
    the loudest thing ``explain`` can say."""
    export = _export(_row(event_metadata={
        "ruleset_version": CURRENT, "ruleset_hash": "dead" + ODD + "beef",
        "policy_rules": ["phi.ssn"]}))

    result = introspect.explain(PHI, EVENT, export, KEY)

    assert result.status == "ruleset_mismatch"
    assert result.ruleset_verified is False
    assert ESC in _printable_message(result)


def _clean_row_export(policy_rules):
    return _export(_row(prompt_hash=hashing.commitment_hex(CLEAN, KEY),
                        event_metadata={"ruleset_version": CURRENT,
                                        "ruleset_hash": CURRENT_HASH,
                                        "policy_rules": policy_rules}))


def test_no_matches_survives_rule_ids_that_are_not_strings():
    """🔴 ``policy_rules: [1, 2]`` -> ``', '.join(...)`` -> TypeError.
    ``_rule_ids`` was written to replace exactly this idiom and this arm still
    held a copy of it — the last one in the module."""
    result = introspect.explain(CLEAN, EVENT, _clean_row_export([1, 2]), KEY)

    assert result.status == "no_matches"
    assert "1, 2" in _printable_message(result), "the recorded ids vanished"


def test_no_matches_survives_a_non_ascii_rule_id():
    result = introspect.explain(CLEAN, EVENT,
                                _clean_row_export(["phi." + ODD]), KEY)

    assert result.status == "no_matches"
    assert ESC in _printable_message(result)


def test_a_dict_under_policy_rules_is_not_reported_as_its_keys():
    """``list({"a": 1})`` is ``["a"]``, so the old idiom would have named ``a``
    as a rule id nobody recorded. ``_rule_ids`` renders the value instead."""
    result = introspect.explain(CLEAN, EVENT, _clean_row_export({"a": 1}), KEY)

    assert result.status == "no_matches"
    _printable_message(result)
    assert "the row recorded" in result.message
    assert "the row recorded a." not in result.message


# ══ 3 · the arms that report a hand-edited registry ═════════════════════════
@pytest.fixture
def tampered_registry():
    """Publish a definition under a chosen version for one test, then undo it.

    ⚠ THIS IS THE STATE THESE ARMS EXIST TO REPORT, not a contrivance. Their
    own messages name "a hand-edit, a partial upgrade, a backported patch" as
    the thing being diagnosed, and past a successful ``ruleset.load`` there is
    no other way for a non-ASCII version, validator or transform name to reach
    a sentence.
    """
    saved = dict(registry._REGISTRY)

    def publish(version, definition):
        registry._REGISTRY[version] = definition

    try:
        yield publish
    finally:
        registry._REGISTRY.clear()
        registry._REGISTRY.update(saved)


def _tampered_export(version, definition=None, prompt=PHI):
    metadata = {"ruleset_version": version}
    if definition is not None:
        metadata["ruleset_hash"] = ruleset.hash_of(definition)
    return _export(_row(prompt_hash=hashing.commitment_hex(prompt, KEY),
                        event_metadata=metadata))


def test_a_non_ascii_version_prints_from_the_arms_past_the_load(tampered_registry):
    """THREE sentences at once: the mismatch message names the version twice,
    the unverified note names it, and so does the ``explained`` line."""
    bad = "2026.08." + ODD
    live = ruleset.load(CURRENT)
    tampered_registry(bad, live)

    mismatch = introspect.explain(
        PHI, EVENT, _export(_row(prompt_hash=hashing.commitment_hex(PHI, KEY),
                                 event_metadata={"ruleset_version": bad,
                                                 "ruleset_hash": "0" * 64})),
        KEY)
    assert mismatch.status == "ruleset_mismatch"
    assert ESC in _printable_message(mismatch)

    unverified = introspect.explain(PHI, EVENT, _tampered_export(bad), KEY)
    assert unverified.ruleset_verified is None
    assert "could not confirm" in _printable_message(unverified)
    assert ESC in unverified.message

    explained = introspect.explain(PHI, EVENT, _tampered_export(bad, live), KEY)
    assert explained.status == "explained"
    assert ESC in _printable_message(explained)


def test_a_non_ascii_validator_name_prints(tampered_registry):
    """⚠ AN ASCII VERSION ON PURPOSE, so the only unencodable value in the
    message is the validator name — otherwise this test would pass on the
    version escape and prove nothing about the arm it is named for."""
    version = "2026.08.9"
    definition = copy.deepcopy(ruleset.load(CURRENT))
    for label in definition.get("pii_detectors", {}):
        definition["pii_detectors"][label]["validator"] = "luhn-" + ODD
    tampered_registry(version, definition)

    result = introspect.explain(PHI, EVENT,
                                _tampered_export(version, definition), KEY)

    assert result.status == "unknown_ruleset"
    assert "validator" in _printable_message(result)
    assert ESC in result.message


def test_a_non_ascii_transform_name_prints(tampered_registry):
    """Same isolation, for the views arm."""
    version = "2026.08.9"
    definition = copy.deepcopy(ruleset.load(CURRENT))
    definition["prompt_views"]["derived"][0]["transforms"][0]["name"] = (
        "strip-" + ODD)
    tampered_registry(version, definition)
    prompt = "ignore all previous instructions"

    result = introspect.explain(
        prompt, EVENT, _tampered_export(version, definition, prompt), KEY)

    assert result.status == "unknown_ruleset"
    assert ESC in _printable_message(result)


def test_the_list_of_known_versions_prints(tampered_registry):
    """The unknown-ruleset message lists what this build DOES carry, and after
    a hand-edit that list is the hostile value. The version asked for is ASCII
    here, again so the assertion can only be satisfied by the listing."""
    tampered_registry("2026.08." + ODD, ruleset.load(CURRENT))

    result = introspect.explain(
        PHI, EVENT,
        _export(_row(event_metadata={"ruleset_version": "9999.1",
                                     "policy_rules": ["phi.ssn"]})), KEY)

    assert result.status == "unknown_ruleset"
    assert ESC in _printable_message(result)


# ══ 4 · the two rules the fix itself must obey ══════════════════════════════
def test_printable_escapes_and_never_drops():
    """⚠ THE FIX MUST NOT BECOME A FILTER. A reader has to be able to see that
    the value was not what they expected; dropping the character would leave
    ``2026.08.`` and ``2026.08.X`` looking identical."""
    assert introspect._printable("2026.08." + ODD) == "2026.08." + ESC
    assert introspect._printable(7) == "7"
    assert introspect._printable(None) == "None"


def test_the_module_keeps_its_own_em_dashes():
    """⚠ ``_printable`` IS FOR VALUES, NEVER FOR SENTENCES. These messages use
    em dashes deliberately and they are cp1252-safe; escaping a whole message to
    fix a value would mangle every one of them. S14d's executor tripped on
    exactly this, so it is pinned rather than remembered."""
    assert introspect._printable("—") != "—", "the helper does escape em dashes"

    salted = introspect.explain(PHI, EVENT,
                                _export(_row(commitment_alg="a-salted")), KEY)
    assert "—" in salted.message, "a sentence was escaped, not just its values"
    _printable_message(salted)


def test_printable_escapes_control_characters_too():
    """⚠ ASCII IS NOT THE SAME PROMISE AS PRINTABLE, and dropping ``!r`` from
    the quoted sites is what made the difference matter.

    ``!r`` used to escape a newline and a terminal escape sequence for free at
    the six sites that had it. Once the value arrives pre-escaped, ``!r``
    escapes the escape, so the sentences carry their own quotes instead — and
    this pass has to cover what ``!r`` was covering. A ``ruleset_version``
    holding ``ESC[2J`` is a value out of a file the reader handed us, and it
    would clear the console of the person auditing it.
    """
    assert introspect._printable("a" + chr(10) + "b") == "a" + chr(92) + "nb"
    assert introspect._printable(chr(27) + "[2J") == chr(92) + "x1b[2J"
    assert introspect._printable("a" + chr(9)) == "a" + chr(92) + "t"
    # A SPACE IS PRINTABLE and must survive: escaping it would turn every
    # multi-word value into an unreadable run.
    assert introspect._printable("two words") == "two words"


def test_a_message_stays_one_line_whatever_the_export_holds():
    """The other half of the same rule, driven through the public function:
    a version carrying a newline used to break the sentence across lines."""
    export = _export(_row(event_metadata={
        "ruleset_version": "2026.08" + chr(10) + "INJECTED",
        "policy_rules": ["phi.ssn"]}))

    result = introspect.explain(PHI, EVENT, export, KEY)

    assert result.status == "unknown_ruleset"
    assert chr(10) not in _printable_message(result)
    assert chr(92) + "nINJECTED" in result.message


# ══ 5 · the guard tests the RAW value, never the printable one ══════════════
def test_no_sidecar_reads_the_same_whether_it_is_none_or_empty():
    """🔴 A REGRESSION S17 ITSELF INTRODUCED, CAUGHT AT THE GATE.

    The branch moved from ``if salt_sidecar_path`` to ``if sidecar_shown``, and
    ``_printable(None)`` is the string ``"None"`` — TRUTHY. A caller passing
    ``salt_sidecar_path=None``, which is the natural way to say "no sidecar"
    through the public ``explain()``, was told the salt "was not found in None".

    ⚠ `foxy explain` COULD NOT HAVE FOUND THIS. The CLI guards with
    ``is not None`` and ``cfg.salt_sidecar_path`` defaults to ``""``, so the
    None never reaches here from the tool — running it proves nothing about the
    API, which is the surface the defect lived on. And this is the ONE message
    whose whole job is stopping a reader read "could not check" as "did not
    match"; a sentence naming a path the caller never gave is that message
    losing the reader.
    """
    export = _export(_row(commitment_alg="hmac-sha256-salted"))

    for absent in (None, ""):
        result = introspect.explain(PHI, EVENT, export, KEY, absent)

        assert result.status == "salt_unavailable"
        assert "(no --sidecar given)" in _printable_message(result), absent
        assert "in None" not in result.message, absent
