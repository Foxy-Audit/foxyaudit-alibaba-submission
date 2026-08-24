"""T4 — tracing one turn to its ledger row, and the four honest states.

The phase this file guards exists because a verify control that fakes a result
is the worst thing an audit product could ship. So the guards are almost all
about REFUSING to answer: that `explain`'s eight outcomes reach a reader as
eight words and not as a tick and a cross, that "no key" and "no export" and "no
receipt" stay three different sentences, and that the one field the SDK made
three-state does not collapse into a boolean on the way to a screen.

⚠ EVERY STATE HERE IS REACHED BY DRIVING THE ENGINE, not by constructing an
`Evidence` and asserting its fields back. A hand-built record proves the
renderer can draw a shape; only a real turn proves the shape is ever produced.
"""

from __future__ import annotations

import json
import pathlib

import pytest

from foxy_audit import FoxyClient
from foxy_audit.introspect import STATUSES
from foxy_testbed.core import (Assistant, EVIDENCE_EXPLAINED,
                               EVIDENCE_NO_EXPORT, EVIDENCE_NO_LEDGER,
                               EVIDENCE_NO_RECEIPT, EVIDENCE_STATES,
                               EXPLAIN_FAMILIES, Evidence, FAMILY_ANSWERED,
                               FAMILY_CANNOT, FAMILY_DISAGREED,
                               family_of_status)
from foxy_testbed.sectors import get_sector

#: Carries a PHI identifier the `hipaa` tag really does detect, so a real replay
#: has a real span to match. The address is a documentation domain (RFC 2606).
PHI_PROMPT = "Draft a note for the patient at alice@example.org about their MRI."


def _keyed(tmp_path, sector="healthcare"):
    """An assistant whose client has a key, so the SDK reports ``submitted``.

    ⚠ THE SPOOL IS CHOSEN AT CONSTRUCTION, NOT SWAPPED AFTERWARDS. A keyed
    ``FoxyClient`` opens its spool, persists a client_id, and runs
    ``dispatch.resume`` / ``org_policy.register`` INSIDE ``__init__`` -- so
    replacing ``cfg`` on the built client, which is what this helper used to do,
    redirects everything except the part that already happened. It looked safe
    only because a sibling ``conftest`` fixture sets ``FOXY_SPOOL_PATH``; strip
    that away and the helper writes to the developer's home directory, and a
    test their home directory can influence is a test whose result it can
    decide. Passing the client in is the seam ``Assistant`` documents for
    exactly this ("a caller who genuinely wants a keyed client passes one in").
    """
    client = FoxyClient(api_key="test-key-not-a-real-one",
                        spool_path=str(tmp_path / "spool.db"))
    return Assistant(sector, client=client)


def _export_from_receipt(assistant, tmp_path):
    """A `/v1/logs/export?format=json` document for the turn just run.

    Built from the RECEIPT the SDK actually emitted rather than hand-written, so
    the row and the event it describes cannot drift apart — which is the whole
    reason the receipt is built from the payload and not from the arguments.
    """
    receipt = assistant._receipts[-1]
    document = {"logs": [{
        "event_id": receipt["event_id"],
        "policy_tag": receipt["policy_tag"],
        "commitment_alg": receipt["commitment_alg"],
        "prompt_hash": receipt["prompt_hash"],
        "event_metadata": {"ruleset_version": receipt["ruleset_version"],
                           "ruleset_hash": receipt["ruleset_hash"],
                           "policy_rules": receipt["policy_rules"]},
    }]}
    path = tmp_path / "export.json"
    path.write_text(json.dumps(document), encoding="utf-8")
    return path, document


# ══ the suite stays out of the developer's home ═════════════════════════════
def test_a_keyed_helper_never_opens_the_real_spool(tmp_path, monkeypatch):
    """⚠ OBSERVED ON WHAT THE CONSTRUCTOR OPENED, not on where `cfg` ends up.

    A keyed `FoxyClient` opens its spool, persists a client_id and runs
    `dispatch.resume` / `org_policy.register` INSIDE `__init__`. The helper used
    to build the client and THEN replace `cfg`, which redirects everything except
    the part that already happened -- and `cfg.spool_path` reads correct
    afterwards either way, so asserting on it proves nothing. Every `EventSpool`
    built during the call is recorded instead.

    ⚠ AND `FOXY_SPOOL_PATH` IS UNSET FOR THE DURATION. The sibling conftest
    fixture sets it, which is what made the old helper LOOK safe; with it gone
    the post-hoc swap falls back to `Path.home()/".foxy-audit"` and this fires.
    Removing that env var is the whole reason this test can see the defect.

    ⚠ IT ASSERTS ON PATHS, NOT ON FILE MTIMES. A guard that stats the real spool
    is a guard any other process holding a keyed client can fail -- which is
    exactly what happened while this finding was being investigated, and is the
    same non-determinism as the hardcoded-port trap (#236).
    """
    from foxy_audit import spool as spool_module

    monkeypatch.delenv("FOXY_SPOOL_PATH", raising=False)
    opened = []
    original = spool_module.EventSpool.__init__

    def record(self, path=None):
        original(self, path)
        opened.append(str(self.path))

    monkeypatch.setattr(spool_module.EventSpool, "__init__", record)

    assistant = _keyed(tmp_path)
    assistant.ask(PHI_PROMPT)

    assert opened, "no spool was opened at all; this guard would prove nothing"
    # ⚠ `~/.foxy-audit`, NOT `~`. On Windows `tmp_path` lives UNDER the home
    # directory, so a guard written against `Path.home()` fails a correct
    # implementation -- caught by running it. The SDK's own default
    # location is the thing that must never be opened.
    real = pathlib.Path.home() / ".foxy-audit"
    for path in opened:
        assert str(tmp_path) in path, (
            "a spool was opened at {0!r}, outside the test's tmp_path -- the "
            "client was built before the path was chosen".format(path))
        assert str(real) not in path, (
            "the suite opened the real spool: {0!r}".format(path))


# ══ the receipt ═════════════════════════════════════════════════════════════
def test_a_keyless_turn_still_names_its_row_but_says_nothing_shipped():
    """Honest state 1, and the distinction it rests on.

    The id is REAL — the SDK mints one whether or not the event ships — so a
    surface that read "there is an event_id" as "there is a row" would report a
    ledger row for every offline turn this testbed has ever run.
    """
    assistant = Assistant(get_sector("healthcare"))
    turn = assistant.ask(PHI_PROMPT)
    assert turn.event_id
    assert turn.submitted is False

    evidence = assistant.verify(turn, PHI_PROMPT)
    assert evidence.state == EVIDENCE_NO_LEDGER
    assert evidence.status == "", "no explain ran, so there is no status to show"
    # It names the fix. An empty state that only reports a failure leaves the
    # reader with nothing to do, and this one has a one-flag answer.
    assert "--foxy-key" in evidence.message


def test_a_turn_with_no_receipt_is_not_reported_as_having_no_row(tmp_path):
    """⚠ THE FOURTH STATE, AND THE PLAN DID NOT KNOW IT NEEDED ONE.

    The SDK documents one class of event that emits no receipt at all: under
    `audit_required=True` a server receipt that misses its deadline raises while
    the row is ALREADY durable in the spool and will be delivered later. Calling
    that "never shipped to a ledger" would be a false claim about a row that
    exists — so it is its own state, with its own sentence.
    """
    assistant = _keyed(tmp_path)
    turn = assistant.ask(PHI_PROMPT)
    receiptless = type(turn)(**{**turn.__dict__, "event_id": ""})

    evidence = assistant.verify(receiptless, PHI_PROMPT)
    assert evidence.state == EVIDENCE_NO_RECEIPT
    assert evidence.state != EVIDENCE_NO_LEDGER
    lowered = evidence.message.lower()
    assert "not the same as there being no row" in lowered


def test_the_receipt_is_read_off_the_sdk_and_not_re_derived(tmp_path):
    """The id on the turn is the id the SDK put in the payload it wrote."""
    assistant = _keyed(tmp_path)
    turn = assistant.ask(PHI_PROMPT)
    assert assistant._receipts, "the SDK emitted no receipt at all"
    assert turn.event_id == assistant._receipts[-1]["event_id"]
    assert turn.submitted == assistant._receipts[-1]["submitted"] is True


def test_the_receipts_do_not_accumulate_across_turns(tmp_path):
    """Cleared per turn: the id this turn asks about is the one it produced."""
    assistant = _keyed(tmp_path)
    first = assistant.ask(PHI_PROMPT)
    second = assistant.ask("What does minimum necessary require?")
    assert len(assistant._receipts) == 1
    assert second.event_id != first.event_id


# ══ the three states, driven ════════════════════════════════════════════════
def test_a_shipped_turn_with_no_export_asks_for_the_document_by_name(tmp_path):
    """Honest state 2. Naming the endpoint is the whole content of it."""
    assistant = _keyed(tmp_path)
    turn = assistant.ask(PHI_PROMPT)
    assert turn.submitted is True

    evidence = assistant.verify(turn, PHI_PROMPT)
    assert evidence.state == EVIDENCE_NO_EXPORT
    assert "/v1/logs/export?format=json" in evidence.message
    assert "--export" in evidence.message


def test_an_export_present_runs_the_real_replay(tmp_path):
    """Honest state 3, against a document built from the SDK's own receipt."""
    assistant = _keyed(tmp_path)
    turn = assistant.ask(PHI_PROMPT)
    export, _ = _export_from_receipt(assistant, tmp_path)

    evidence = assistant.verify(turn, PHI_PROMPT, export=str(export))
    assert evidence.state == EVIDENCE_EXPLAINED
    assert evidence.status == "explained"
    assert evidence.commitment_verified is True
    assert evidence.ruleset_verified is True
    assert evidence.match_count >= 1
    assert evidence.family == FAMILY_ANSWERED


def test_an_unreadable_export_is_not_reported_as_a_verdict(tmp_path):
    """A file that will not parse says nothing about the row.

    ⚠ AND THE MESSAGE CARRIES THE EXCEPTION TYPE, NEVER ITS TEXT. A JSON decoder
    quotes the fragment it choked on, and this sentence is rendered on a page and
    printed to a terminal — an export is the customer's own ledger.
    """
    assistant = _keyed(tmp_path)
    turn = assistant.ask(PHI_PROMPT)
    broken = tmp_path / "broken.json"
    broken.write_text('{"logs": [ THIS IS NOT JSON', encoding="utf-8")

    evidence = assistant.verify(turn, PHI_PROMPT, export=str(broken))
    assert evidence.state == EVIDENCE_NO_EXPORT
    assert evidence.status == "", "nothing was replayed, so there is no status"
    assert "THIS IS NOT JSON" not in evidence.message
    # ⚠ PINNED TO "THE TYPE, AND ONLY THE TYPE". Asserting the absence of the
    # document text alone could not fail: `str(JSONDecodeError)` reports a line
    # and a column and never the bytes it choked on (measured). So the shape is
    # what is pinned -- swapping `type(exc).__name__` for `exc` puts the
    # decoder's own words into a message rendered on a page, and THAT is the
    # change this notices.
    assert "JSONDecodeError" in evidence.message
    assert "Expecting value" not in evidence.message


def test_a_clean_row_records_no_ruleset_and_explain_says_so(tmp_path):
    """⚠ AN SDK FINDING, PINNED RATHER THAN PAPERED OVER.

    A BLOCKED turn's row carries ``ruleset_version`` and ``ruleset_hash``; an
    ALLOWED one carries neither, because the clean path builds no
    ``event_metadata`` at all. So `explain` on a clean row returns
    ``predates_provenance``, whose message says the row "was written before SDK
    1.7.0" -- and the row was written today, by 1.12.0.

    The testbed does NOT correct this. `Turn.ruleset_version` is populated (from
    `check`), so it would have been easy to substitute it into the export and get
    a green `explained` -- and that would be inventing evidence about which rules
    a ledger row recorded, which is the one thing this phase must never do. The
    surfaces render what the tool actually returned.

    Pinned in both directions: the day the SDK starts recording provenance on the
    clean path, this fails and the message the surfaces show changes with it.
    """
    assistant = _keyed(tmp_path)

    allowed = assistant.ask("What does minimum necessary require for a vendor?")
    assert allowed.decision == "allowed"
    clean_receipt = assistant._receipts[-1]
    assert clean_receipt["ruleset_version"] is None
    assert clean_receipt["ruleset_hash"] is None
    # the ENGINE knows the version; the ROW does not record it
    assert allowed.ruleset_version

    blocked = assistant.ask(PHI_PROMPT)
    assert blocked.decision == "blocked"
    assert assistant._receipts[-1]["ruleset_version"], (
        "a blocked row stopped recording provenance -- that is a regression, "
        "not the gap this test documents")


def test_verify_replays_with_the_key_the_row_was_committed_with(tmp_path,
                                                                monkeypatch):
    """🔴 A CONFIDENT WRONG VERDICT, AND THE WORST ONE THIS SURFACE CAN GIVE.

    `log_interaction` commits with `cfg.commitment_key or cfg.api_key`, and
    `foxy explain` replays with `arg or cfg.commitment_key or cfg.api_key`.
    `verify` stopped one term short, so it replayed with a DIFFERENT key from the
    one the row was written with -- and a key mismatch does not surface as "could
    not check". It surfaces as `hash_mismatch`, which is in the DISAGREED family
    and whose message reads "The row is intact; this is simply not the prompt it
    covers." A false accusation against an intact row, from the phase built so
    that cannot happen.

    ⚠ THE TRIGGER IS AN EMPTY VALUE, NOT AN ABSENT ONE. `FoxyConfig.resolve`
    reads `FOXY_COMMITMENT_KEY` with a "" default, so setting it EMPTY gives
    `commitment_key == ""` while `api_key` holds the real key. A test that
    exports a real commitment key passes on the broken code, because then the
    two resolutions agree -- which is why this one sets it empty and asserts the
    resolution order rather than only the outcome.
    """
    monkeypatch.setenv("FOXY_COMMITMENT_KEY", "")
    monkeypatch.delenv("FOXY_SALT_SIDECAR", raising=False)

    assistant = _keyed(tmp_path)
    cfg = assistant._client.cfg
    assert cfg.commitment_key == "", "the empty-variable case was not reached"
    assert cfg.api_key, "there is no api_key to fall back to; nothing is proved"

    turn = assistant.ask(PHI_PROMPT)
    export, _ = _export_from_receipt(assistant, tmp_path)
    evidence = assistant.verify(turn, PHI_PROMPT, export=str(export))

    assert evidence.status != "hash_mismatch", (
        "verify replayed with a different key from the one the row was "
        "committed with, and accused an intact row")
    assert evidence.status == "explained"
    assert evidence.commitment_verified is True

    # and an explicit argument still wins over both, as it does in `foxy explain`
    wrong = assistant.verify(turn, PHI_PROMPT, export=str(export),
                             commitment_key="a-different-key-entirely")
    assert wrong.status == "hash_mismatch", (
        "an explicit commitment_key stopped being honoured")


# ══ the vocabulary ══════════════════════════════════════════════════════════
def test_every_status_the_sdk_can_return_has_a_family():
    """⚠ THE GUARD THAT KEEPS A NEW SDK OUTCOME FROM RENDERING AS NOTHING.

    `introspect.STATUSES` is the SDK's own list and it is the authority. The map
    is checked against it rather than against a copy written here, because a
    second list of the eight would be a second list to go stale — and the day
    the SDK adds a ninth, this is what says so.
    """
    assert set(EXPLAIN_FAMILIES) == set(STATUSES), (
        "foxy_audit.introspect.STATUSES and EXPLAIN_FAMILIES disagree. Decide "
        "which family the new outcome belongs to; do not let it default.")


def test_the_four_the_sdk_calls_i_cannot_are_the_four_marked_cannot():
    """The split is the SDK's, not ours. Its own docstring says "Four of them
    are 'I cannot'", and `salt_unavailable`'s message spells out the rule: "this
    is not a mismatch and not a pass"."""
    cannot = {s for s, f in EXPLAIN_FAMILIES.items() if f == FAMILY_CANNOT}
    assert cannot == {"row_not_found", "salt_unavailable", "unknown_ruleset",
                      "predates_provenance"}
    answered = {s for s, f in EXPLAIN_FAMILIES.items() if f == FAMILY_ANSWERED}
    assert answered == {"explained", "no_matches"}
    disagreed = {s for s, f in EXPLAIN_FAMILIES.items() if f == FAMILY_DISAGREED}
    assert disagreed == {"hash_mismatch", "ruleset_mismatch"}


def test_an_unmapped_status_falls_to_cannot_and_never_to_answered():
    """The understating direction. A future outcome this build has never seen
    must not draw the calm mark."""
    assert family_of_status("something_the_sdk_added_later") == FAMILY_CANNOT
    assert family_of_status("") == FAMILY_CANNOT


def test_the_status_is_carried_verbatim_and_never_translated(tmp_path):
    """Two outcomes that a tick-and-cross would have collapsed into one."""
    assistant = _keyed(tmp_path)
    turn = assistant.ask(PHI_PROMPT)
    export, document = _export_from_receipt(assistant, tmp_path)

    wrong_text = assistant.verify(turn, "an entirely different prompt",
                                  export=str(export))
    assert wrong_text.status == "hash_mismatch"
    assert wrong_text.family == FAMILY_DISAGREED

    document["logs"][0]["event_id"] = "not-the-row-you-asked-for"
    export.write_text(json.dumps(document), encoding="utf-8")
    absent = assistant.verify(turn, PHI_PROMPT, export=str(export))
    assert absent.status == "row_not_found"
    # ⚠ A MISSING ROW IS NOT A FAILED CHECK. Same panel, different family, and
    # the two must never wear the same mark.
    assert absent.family == FAMILY_CANNOT
    assert absent.family != wrong_text.family


def test_ruleset_verified_stays_three_state_through_the_payload(tmp_path):
    """⚠ ``None`` IS NOT ``False``, all the way to the JSON.

    True — the digest ran and agreed. False — it ran and DISAGREED. None — it did
    not run. Collapsing the last two tells a reader their ruleset registry may
    have been tampered with when in fact `explain` answered before it got there.
    """
    assistant = _keyed(tmp_path)
    turn = assistant.ask(PHI_PROMPT)
    export, document = _export_from_receipt(assistant, tmp_path)

    agreed = assistant.verify(turn, PHI_PROMPT, export=str(export))
    assert agreed.ruleset_verified is True
    assert agreed.as_dict()["ruleset_verified"] is True

    # A row naming a version but recording no digest: the check cannot run.
    document["logs"][0]["event_metadata"].pop("ruleset_hash")
    export.write_text(json.dumps(document), encoding="utf-8")
    unchecked = assistant.verify(turn, PHI_PROMPT, export=str(export))
    assert unchecked.ruleset_verified is None, "None collapsed into False"
    assert unchecked.as_dict()["ruleset_verified"] is None
    assert json.loads(json.dumps(unchecked.as_dict()))["ruleset_verified"] is None

    # A digest that disagrees: the check ran and refused.
    document["logs"][0]["event_metadata"]["ruleset_hash"] = "0" * 64
    export.write_text(json.dumps(document), encoding="utf-8")
    disagreed = assistant.verify(turn, PHI_PROMPT, export=str(export))
    assert disagreed.status == "ruleset_mismatch"
    assert disagreed.ruleset_verified is False


def test_every_state_is_one_of_the_named_four(tmp_path):
    """No surface has to handle a state this module can produce and has not
    named — the renderers switch on these."""
    assistant = _keyed(tmp_path)
    turn = assistant.ask(PHI_PROMPT)
    export, _ = _export_from_receipt(assistant, tmp_path)
    for evidence in (assistant.verify(turn, PHI_PROMPT),
                     assistant.verify(turn, PHI_PROMPT, export=str(export)),
                     Assistant(get_sector("legal")).verify(
                         Assistant(get_sector("legal")).ask("hello"), "hello")):
        assert evidence.state in EVIDENCE_STATES


# ══ the spans ═══════════════════════════════════════════════════════════════
def test_no_matched_span_reaches_the_serialised_payload(tmp_path):
    """⚠ A SPAN IS THE USER'S OWN TEXT, AND THE SDK'S RULE IS STDOUT ONLY.

    `ExplainResult.as_dict` omits it by default for exactly this reason. Checked
    against the PROMPT rather than against the word "text": the failure this
    prevents is a payload containing the customer's content, whatever key it
    arrived under.
    """
    assistant = _keyed(tmp_path)
    turn = assistant.ask(PHI_PROMPT)
    export, _ = _export_from_receipt(assistant, tmp_path)
    evidence = assistant.verify(turn, PHI_PROMPT, export=str(export))
    assert evidence.match_count >= 1, "nothing matched, so this proves nothing"

    serialised = json.dumps(evidence.as_dict())
    # every run of 8+ characters from the prompt, the same corpus shape the SDK's
    # own content-blindness guard uses
    for start in range(0, len(PHI_PROMPT) - 8):
        fragment = PHI_PROMPT[start:start + 8]
        if not fragment.strip():
            continue
        assert fragment not in serialised, fragment
    assert "matches" not in evidence.as_dict()


def test_the_engine_still_hands_the_spans_to_a_stdout_renderer(tmp_path):
    """The other half: they are OMITTED from the payload, not discarded.

    Without this, `as_dict` dropping them would look identical to `explain`
    never having returned any — and the CLI, which is allowed to print them,
    would silently have nothing to print.
    """
    assistant = _keyed(tmp_path)
    turn = assistant.ask(PHI_PROMPT)
    export, _ = _export_from_receipt(assistant, tmp_path)
    evidence = assistant.verify(turn, PHI_PROMPT, export=str(export))
    assert evidence.matches
    assert len(evidence.matches) == evidence.match_count
    assert any(m.text for m in evidence.matches)


# ══ the wiring the surfaces depend on ═══════════════════════════════════════
def test_the_foxy_key_is_a_different_key_from_the_provider_key(tmp_path):
    """Conflating them would send a provider key to Foxy, or the reverse."""
    assistant = Assistant("healthcare", api_key="provider-key-only")
    assert assistant._client.cfg.api_key == "", (
        "the PROVIDER key reached the Foxy client")
    assert assistant.ask("hello").submitted is False

    keyed = _keyed(tmp_path)
    assert keyed._client.cfg.api_key == "test-key-not-a-real-one"


def test_a_stray_foxy_api_key_still_cannot_enable_a_default_assistant(monkeypatch):
    """T4 added a way to pass the key; it did not add a way to inherit one.

    `FoxyConfig.resolve` falls back to `$FOXY_API_KEY`, and the keyless default
    is what keeps an offline probe run from depending on whose laptop it is.
    """
    monkeypatch.setenv("FOXY_API_KEY", "placeholder-not-a-real-key")
    assert Assistant(get_sector("legal"))._client.cfg.enabled is False


def test_every_message_survives_a_cp1252_console(tmp_path):
    """⚠ THE SDK ALREADY PAID FOR THIS ONE. `foxy explain` died with
    UnicodeEncodeError on a Windows console, which is the tool failing to say
    anything at all — and these messages are printed by the same kind of REPL.

    Every state, driven, and every message encoded the way a cp1252 terminal
    would encode it.
    """
    assistant = _keyed(tmp_path)
    turn = assistant.ask(PHI_PROMPT)
    export, _ = _export_from_receipt(assistant, tmp_path)
    produced = [
        assistant.verify(turn, PHI_PROMPT),
        assistant.verify(turn, PHI_PROMPT, export=str(export)),
        assistant.verify(type(turn)(**{**turn.__dict__, "event_id": ""}),
                         PHI_PROMPT),
        Assistant(get_sector("legal")).verify(
            Assistant(get_sector("legal")).ask("hello"), "hello"),
    ]
    assert len(produced) == len(EVIDENCE_STATES)
    for evidence in produced:
        for text in (evidence.headline, evidence.message):
            text.encode("cp1252")   # raises UnicodeEncodeError on a bad char
