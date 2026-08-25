"""The scoreboard: concrete tallies, and the failures it has to report.

The counts here are LITERAL. Recomputing them from the corpus would make this
green by construction -- the guard would restate the implementation's own
arithmetic and pass however wrong both were. If a probe is added, these numbers
change and somebody has to look at the new one.
"""

from __future__ import annotations

import socket

import pytest

from foxy_testbed.core import Assistant, Turn
from foxy_testbed.providers import Provider, ProviderError
from foxy_testbed.scoreboard import (OUTCOME_ASSISTED, OUTCOME_CAUGHT,
                                     OUTCOME_ERROR, OUTCOME_GAP_CLOSED,
                                     OUTCOME_GAP_OPEN, OUTCOME_MISSED,
                                     OUTCOME_OVER_BLOCKED, AssistantConflict,
                                     SectorMismatch, classify, run_probes)
from foxy_testbed.sectors import (EXPECT_ASSIST, EXPECT_BLOCK, KNOWN_GAP, Probe,
                                  Sector, get_sector)

#: sector -> (caught, enforcement_total, assisted, assistance_total, gaps_open)
#:
#: ⚠ THE ASSISTANCE TOTALS MOVED 4 -> 6 IN EVERY SECTOR, AND THAT WAS THE POINT.
#: T5 added two over-blocking probes per sector, drawn from the two shapes that
#: blocked ordinary work in the first cut of ruleset 2026.08.5. A column
#: reporting a flawless 4/4 over a population containing none of the failure is
#: exactly what let three green scoreboards sit on top of that regression. See
#: sectors.py's docstring and test_overblock_probes.py.
EXPECTED = {
    "healthcare": (5, 5, 6, 6, 2),
    "finance": (3, 3, 6, 6, 2),
    "legal": (3, 3, 6, 6, 2),
}


@pytest.mark.parametrize("sector_name", sorted(EXPECTED))
def test_each_sector_scores_exactly_what_it_should(sector_name):
    caught, enf_total, assisted, asst_total, gaps = EXPECTED[sector_name]
    board = run_probes(sector_name)

    assert (board.caught, board.enforcement_total) == (caught, enf_total)
    assert (board.assisted, board.assistance_total) == (assisted, asst_total)
    assert board.gaps_open == gaps
    assert board.missed == 0
    assert board.over_blocked == 0
    assert board.errors == 0
    assert board.gaps_closed == 0
    assert board.ok is True


@pytest.mark.parametrize("sector_name", sorted(EXPECTED))
def test_redact_mode_scores_exactly_what_block_mode_does(sector_name):
    """A scrubbed prompt is enforcement, not a miss.

    THE GUARD THAT WAS MISSING. Every scoreboard test ran the default mode, so
    ``--mode redact`` -- where all five healthcare enforcement probes come back
    ``redacted`` with their spans replaced before the model saw them -- printed
    ``FAIL | enforcement 0/5`` and exited 1. The testbed reported the SDK's own
    correct behaviour as broken, and nothing measured the mode it happened in.
    """
    caught, enf_total, assisted, asst_total, gaps = EXPECTED[sector_name]
    board = run_probes(sector_name, mode="redact")

    assert (board.caught, board.missed) == (caught, 0)
    assert (board.assisted, board.over_blocked) == (assisted, 0)
    assert board.gaps_open == gaps
    assert board.ok is True

    # ...and it really is the redact path, not block wearing its name.
    enforced = [r.turn.decision for r in board.results if r.probe.expect == EXPECT_BLOCK]
    assert set(enforced) == {"redacted"}, enforced
    assert all(r.turn.reached_provider for r in board.results
               if r.probe.expect == EXPECT_BLOCK), (
        "redact does not prevent the call -- it scrubs what the call carries")


@pytest.mark.parametrize("sector_name", sorted(EXPECTED))
def test_observe_mode_reports_zero_enforcement_and_says_why(sector_name):
    """Observe prevents nothing, and the scoreboard says so rather than passing.

    Not a special case: observe genuinely enforces nothing, so 0/N is the true
    number and the run is not a pass. What it must not do is leave a reader to
    guess whether the guard broke, so the enforcement section names the mode as
    the cause.
    """
    caught, enf_total, _assisted, _asst_total, _gaps = EXPECTED[sector_name]
    board = run_probes(sector_name, mode="observe")

    assert board.caught == 0
    assert board.missed == enf_total
    assert board.ok is False
    text = _flat(board.render())
    assert "mode=observe records but never prevents" in text


@pytest.mark.parametrize("sector_name", sorted(EXPECTED))
def test_a_run_is_byte_identical_to_the_one_before_it(sector_name):
    """The scoreboard is a CI gate, so it has to be reproducible.

    This is what forbids ``random``, a clock-derived seed, and printing latency:
    each of those passes every other test in this file and fails only here.
    """
    assert run_probes(sector_name).render() == run_probes(sector_name).render()


@pytest.mark.parametrize("sector_name", sorted(EXPECTED))
def test_the_rendered_scoreboard_is_7_bit_ascii(sector_name):
    """Not merely cp1252-encodable -- see the matching guard in test_probes.py
    for why the weaker check would pass an em dash a CI log still mangles."""
    run_probes(sector_name).render().encode("ascii")


def _flat(text: str) -> str:
    """Collapse whitespace, so a wrapped line still matches its source sentence.

    The renderer hard-wraps at 78 columns, so a plain substring assertion
    against a preset's prose passes only for sentences short enough not to wrap
    -- i.e. it would silently stop checking the long ones, which are the ones
    that carry the limits.
    """
    return " ".join(text.split())


@pytest.mark.parametrize("sector_name", sorted(EXPECTED))
def test_the_scoreboard_states_the_presets_limits_and_the_fixture_disclaimer(sector_name):
    text = _flat(run_probes(sector_name).render())
    sector = get_sector(sector_name)

    assert "WHAT THIS PRESET ENFORCES, AND WHAT IT DOES NOT" in text
    # The WHOLE note, not its first sentence: the limits live at the end of it.
    assert _flat(sector.policy_note) in text
    assert "fixtures" in text, "a mock reply is never presented as model output"
    assert "KNOWN GAPS" in text
    for probe in sector.probes_expecting(KNOWN_GAP):
        assert _flat(probe.gap_reason) in text, (
            "{0}'s reason must reach the reader, not just the source".format(probe.id))


# ── classify: every branch, with a literal outcome ────────────────────────────
def _turn(decision, answered, reached, changed=False, rules=(), delivered=()):
    """A REAL Turn, not a stub.

    A hand-rolled double used to stand in here, exposing the three attributes
    ``classify`` happened to read. It passed while the property it faked was
    being removed from the real class, which is the whole failure mode of a
    stub: it tests the double's idea of the record. Building the frozen
    dataclass costs nothing and means ``prompt_enforced`` here is the same
    property production computes.
    """
    return Turn(sector="s", policy_tag="t", mode="block", provider="mock",
                model="m", decision=decision, answered=answered,
                reached_provider=reached, prompt_changed=changed,
                rules=rules, rules_delivered=delivered)


BLOCKED = _turn("blocked", answered=False, reached=False,
                rules=("phi.ssn_pattern",))
#: Stamped redacted, and the finding no longer fires on what was delivered.
REDACTED = _turn("redacted", answered=True, reached=True, changed=True,
                 rules=("phi.ssn_pattern",), delivered=())
#: Stamped redacted, delivered, and the finding STILL fires. What
#: `pip install foxy-audit[pii]` produces for a presidio-only detection,
#: because pii.redact has no presidio pass.
REDACTED_INEFFECTIVE = _turn("redacted", answered=True, reached=True, changed=False,
                             rules=("phi.presidio:date_time",),
                             delivered=("phi.presidio:date_time",))
#: ⚠ THE MIXED CASE. One finding genuinely removed, one delivered intact, on the
#: SAME turn -- so `prompt_changed` is True and the prompt is NOT enforced.
#: A single-finding fixture cannot see this.
REDACTED_MIXED = _turn("redacted", answered=True, reached=True, changed=True,
                       rules=("phi.presidio:date_time", "phi.ssn_pattern"),
                       delivered=("phi.presidio:date_time",))
ALLOWED = _turn("allowed", answered=True, reached=True)
FLAGGED = _turn("flagged", answered=True, reached=True)
WITHHELD = _turn("blocked_response", answered=False, reached=True)
ERRORED = _turn("error", answered=False, reached=True)


@pytest.mark.parametrize("expect,turn,outcome", [
    # Prompt enforcement: prevented OR scrubbed. Both stopped the offending
    # span from reaching the model, which is what the probe asks about.
    (EXPECT_BLOCK, BLOCKED, OUTCOME_CAUGHT),
    (EXPECT_BLOCK, REDACTED, OUTCOME_CAUGHT),
    (EXPECT_BLOCK, ALLOWED, OUTCOME_MISSED),
    (EXPECT_BLOCK, FLAGGED, OUTCOME_MISSED),
    # The label says redacted; the delivered findings say otherwise. They win.
    (EXPECT_BLOCK, REDACTED_INEFFECTIVE, OUTCOME_MISSED),
    # ...and "something changed" does not rescue it either.
    (EXPECT_BLOCK, REDACTED_MIXED, OUTCOME_MISSED),
    # A withheld RESPONSE is not prompt enforcement -- the prompt reached the
    # provider, so this column must not claim it.
    (EXPECT_BLOCK, WITHHELD, OUTCOME_MISSED),

    (EXPECT_ASSIST, ALLOWED, OUTCOME_ASSISTED),
    (EXPECT_ASSIST, FLAGGED, OUTCOME_ASSISTED),
    (EXPECT_ASSIST, BLOCKED, OUTCOME_OVER_BLOCKED),
    # ...but from the USER's seat a withheld reply IS an over-block: they got
    # nothing back. Different question, different property, deliberately.
    (EXPECT_ASSIST, WITHHELD, OUTCOME_OVER_BLOCKED),

    (KNOWN_GAP, ALLOWED, OUTCOME_GAP_OPEN),
    (KNOWN_GAP, BLOCKED, OUTCOME_GAP_CLOSED),
    # A gap closing under redact closes by being SCRUBBED...
    (KNOWN_GAP, REDACTED, OUTCOME_GAP_CLOSED),
    # ...and a gap whose detection has no redaction rule is STILL OPEN. This is
    # the false [CLOSED] that printed over a DOB delivered verbatim.
    (KNOWN_GAP, REDACTED_INEFFECTIVE, OUTCOME_GAP_OPEN),
    # A gap is not closed by a NEIGHBOURING finding being redacted.
    (KNOWN_GAP, REDACTED_MIXED, OUTCOME_GAP_OPEN),

    (EXPECT_BLOCK, ERRORED, OUTCOME_ERROR),
    (EXPECT_ASSIST, ERRORED, OUTCOME_ERROR),
    (KNOWN_GAP, ERRORED, OUTCOME_ERROR),
])
def test_classify_maps_each_expectation_and_outcome(expect, turn, outcome):
    assert classify(Probe(id="p", expect=expect, prompt="x", intent="y",
                          gap_reason="z" if expect == KNOWN_GAP else ""),
                    turn) == outcome


def test_the_turn_vocabulary_keeps_prevention_and_evidence_apart():
    """The distinction defect T0b-2 collapsed, asserted directly on the record."""
    assert BLOCKED.prevented and not BLOCKED.response_withheld
    assert WITHHELD.response_withheld and not WITHHELD.prevented

    # Prompt enforcement: prevented, or delivered CHANGED.
    assert BLOCKED.prompt_enforced and REDACTED.prompt_enforced
    assert not WITHHELD.prompt_enforced, (
        "a withheld reply does not mean the prompt was enforced -- it reached "
        "the provider")
    assert not ALLOWED.prompt_enforced and not FLAGGED.prompt_enforced

    # The label alone is not enough, in either direction.
    assert not REDACTED_INEFFECTIVE.prompt_enforced, (
        "'redacted' with the finding still firing is not enforcement")
    assert REDACTED_INEFFECTIVE.redaction_ineffective
    assert not REDACTED.redaction_ineffective
    assert not BLOCKED.redaction_ineffective, (
        "a prevented prompt was never delivered, so it cannot have an "
        "ineffective redaction")

    # ...and neither is "a byte changed". The mixed turn is the case that
    # separates a per-prompt test from a per-finding one.
    assert REDACTED_MIXED.prompt_changed is True
    assert not REDACTED_MIXED.prompt_enforced
    assert REDACTED_MIXED.redaction_ineffective
    assert REDACTED_MIXED.rules_removed == ("phi.ssn_pattern",)
    assert REDACTED_MIXED.rules_surviving == ("phi.presidio:date_time",)

    # `enforced` is the broader "the guard did something at all".
    assert WITHHELD.enforced and BLOCKED.enforced and REDACTED.enforced
    assert not ALLOWED.enforced and not FLAGGED.enforced


# ── the failures the board must actually report ───────────────────────────────
def _sector_with(probes):
    return Sector(name="healthcare", title="t", policy_tag="hipaa",
                  system_prompt="s", policy_note="test double. NOT a real preset.",
                  probes=tuple(probes))


def test_a_miss_fails_the_run():
    """A prompt labelled expect_block that nothing catches. Verified by
    constructing the failure rather than by trusting the arithmetic."""
    board = run_probes(_sector_with([
        Probe(id="healthcare.block.nothing_fires", expect=EXPECT_BLOCK,
              prompt="A completely ordinary question about clinic opening hours.",
              intent="deliberately not caught by anything"),
    ]))
    assert board.missed == 1
    assert board.caught == 0
    assert board.ok is False


def test_an_over_block_fails_the_run():
    """The column that stops an assistant scoring well by refusing everything."""
    board = run_probes(_sector_with([
        Probe(id="healthcare.assist.actually_blocked", expect=EXPECT_ASSIST,
              prompt="Email the summary to nurse.ada@example.org please.",
              intent="deliberately caught by phi.email", reply="never reached"),
    ]))
    assert board.over_blocked == 1
    assert board.assisted == 0
    assert board.ok is False


def test_a_gap_that_closes_is_reported_and_does_not_fail_the_run():
    """Good news must not go red, or the gate gets ignored."""
    board = run_probes(_sector_with([
        Probe(id="healthcare.gap.now_covered", expect=KNOWN_GAP,
              prompt="Email the record to ada@example.org.",
              intent="a gap the SDK has since closed",
              gap_reason="nothing caught this when the corpus was written"),
    ]))
    assert board.gaps_closed == 1
    assert board.gaps_open == 0
    assert board.ok is True
    assert "CLOSED" in board.render()


def test_a_provider_error_fails_the_run_rather_than_scoring_it():
    class BrokenProvider(Provider):
        name = "broken"

        def __init__(self):
            super().__init__("broken-1")

        def complete(self, system, prompt):
            raise ProviderError("openai request failed with HTTP 503")

    sector = _sector_with([
        Probe(id="healthcare.assist.will_error", expect=EXPECT_ASSIST,
              prompt="An ordinary question about clinic opening hours.",
              intent="the provider is down", reply="never reached"),
    ])
    board = run_probes(sector, assistant=Assistant(sector, provider=BrokenProvider()))

    assert board.errors == 1
    assert board.assisted == 0
    assert board.ok is False
    text = board.render()
    assert "ERRORED" in text
    assert "HTTP 503" in text


# ── the scoreboard must describe the assistant that produced it ───────────────
def test_a_sector_that_disagrees_with_its_assistant_is_refused():
    """The mislabelling defect, refused at the door.

    Reading ``sector`` for the probes and the rendered note while ``assistant``
    supplied the verdicts let a finance scoreboard -- "cardholder data is NOT
    blocked here" -- report both finance gaps CLOSED because ``hipaa`` had
    judged them. One preset's limits over another's verdicts is exactly the
    ``hipaa_basic`` shape.
    """
    healthcare = Assistant(get_sector("healthcare"))

    with pytest.raises(SectorMismatch) as excinfo:
        run_probes("finance", assistant=healthcare)

    message = str(excinfo.value)
    # It names BOTH sides, so the caller can see which one they got wrong.
    for token in ("finance", "default", "healthcare", "hipaa"):
        assert token in message


def test_the_mismatch_is_refused_rather_than_silently_resolved():
    """Neither side wins by default. Picking one would hide the caller's bug."""
    with pytest.raises(SectorMismatch):
        run_probes(get_sector("legal"), assistant=Assistant(get_sector("finance")))


@pytest.mark.parametrize("kwargs", [
    {"mode": "redact"},
    {"mode": "observe"},
    {"provider": "mock"},
    {"api_key": "placeholder-not-a-real-key"},
    {"model": "gpt-5.6"},
    {"mode": "redact", "model": "gpt-5.6"},
])
def test_an_argument_the_assistant_already_answers_is_refused(kwargs):
    """The mismatch defect, finished for EVERY argument rather than one.

    ``sector`` was refused while ``mode``, ``provider``, ``api_key`` and
    ``model`` were still dropped on the floor: ``run_probes(hc, mode="redact",
    assistant=Assistant(hc, mode="block"))`` returned ``board.mode == "block"``
    and raised nothing, so the caller got a report of a configuration that never
    ran -- the same defect, one argument over.
    """
    sector = get_sector("healthcare")
    with pytest.raises(AssistantConflict) as excinfo:
        run_probes(sector, assistant=Assistant(sector, mode="block"), **kwargs)

    message = str(excinfo.value)
    for name in kwargs:
        assert repr(name) in message, "the refusal names the argument at fault"
    # ...and what the assistant actually is, so the caller can see the clash.
    assert "'block'" in message


def test_the_dropped_argument_really_was_silent_before():
    """The old behaviour, pinned as the thing that must not come back.

    Without a prebuilt assistant the same kwarg is honoured -- so the refusal
    above is about the CONFLICT, not about the argument being unsupported.
    """
    assert run_probes("healthcare", mode="redact").mode == "redact"


def test_a_matching_argument_is_still_refused_rather_than_waved_through():
    """``mode="block"`` alongside a block-mode assistant is still a conflict.

    Deliberately strict: accepting it would mean the rule is "we compare when we
    can", and a caller would learn that passing both is fine -- right up to the
    day the values differ. There is exactly one place to configure an Assistant.
    """
    sector = get_sector("legal")
    with pytest.raises(AssistantConflict):
        run_probes(sector, assistant=Assistant(sector, mode="block"), mode="block")


def test_the_conflict_exceptions_are_importable_from_the_module_that_raises_them():
    """``except SectorMismatch`` after a star-import used to raise NameError.

    Both names were exported from the package ``__init__`` but neither was in
    ``scoreboard.__all__`` -- an exception you cannot catch from the module
    that raises it.
    """
    namespace = {}
    exec("from foxy_testbed.scoreboard import *", namespace)  # noqa: S102

    assert "SectorMismatch" in namespace
    assert "AssistantConflict" in namespace
    assert issubclass(namespace["SectorMismatch"], namespace["AssistantConflict"])
    # And it really does catch what run_probes raises.
    with pytest.raises(namespace["AssistantConflict"]):
        run_probes("finance", assistant=Assistant(get_sector("healthcare")))


def test_an_assistant_alone_needs_no_sector_argument():
    board = run_probes(None, assistant=Assistant(get_sector("finance")))
    assert board.sector_name == "finance"
    assert board.gaps_open == 2 and board.ok


def test_a_matching_sector_is_accepted():
    sector = get_sector("legal")
    board = run_probes(sector, assistant=Assistant(sector))
    assert board.sector_name == "legal"

    # By VALUE, not identity: an equal preset rebuilt elsewhere is the same
    # preset, and rejecting it would be a false alarm.
    twin = Sector(name=sector.name, title=sector.title, policy_tag=sector.policy_tag,
                  system_prompt=sector.system_prompt, policy_note=sector.policy_note,
                  probes=sector.probes)
    assert run_probes(twin, assistant=Assistant(sector)).ok


def test_everything_rendered_comes_from_the_assistant_not_the_argument():
    """Structural, not incidental: the report cannot name a preset that did not run."""
    finance = get_sector("finance")
    board = run_probes(finance, assistant=Assistant(finance))
    assert board.policy_tag == "default"
    assert _flat(finance.policy_note) in _flat(board.render())


# ── the provenance sentence must follow the provider ──────────────────────────
class _LiveProvider(Provider):
    """A provider that reports itself live. ``Provider.is_live`` defaults True."""

    name = "openai"

    def __init__(self):
        super().__init__("gpt-5.6")

    def complete(self, system, prompt):
        return "a reply that did not come from a fixture"

    @property
    def note(self):
        return "live provider -- this prompt is sent to OpenAI under YOUR key."


def test_a_live_run_does_not_call_its_replies_fixtures():
    """Two contradictory provenance claims about the same replies, in an audit
    product's own demo, is the failure this closes."""
    sector = get_sector("legal")
    board = run_probes(sector, assistant=Assistant(sector, provider=_LiveProvider()))
    text = _flat(board.render())

    assert "fixtures" not in text, (
        "a live run must not describe real model output as fixtures")
    assert "under your own key" in text
    assert "openai (gpt-5.6)" in text
    # The half that is true either way survives.
    assert "nothing here reads the content of a reply" in text


def test_a_mock_run_still_says_its_replies_are_fixtures():
    text = _flat(run_probes("legal").render())
    assert "The replies are fixtures, not model output." in text
    assert "under your own key" not in text


@pytest.mark.parametrize("provider,is_live", [(None, False), (_LiveProvider(), True)])
def test_provenance_travels_with_the_numbers_in_as_dict(provider, is_live):
    """A JSON surface must not re-derive live-vs-mock from the provider name.

    ``provider_is_live`` reached the text renderer but not ``as_dict``, so every
    non-text surface would have had to guess -- the same re-derivation hazard
    ``Turn.as_dict`` carries its measured flags to avoid, and the same one that
    produced the hardcoded "the replies are fixtures" on a live run.
    """
    sector = get_sector("legal")
    board = (run_probes(sector) if provider is None
             else run_probes(sector, assistant=Assistant(sector, provider=provider)))
    payload = board.as_dict()

    assert payload["provider_is_live"] is is_live
    assert payload["provider_note"] == board.provider_note
    assert payload["provider_note"], "the provenance sentence is not empty"


# ── offline, and provably so ──────────────────────────────────────────────────
def test_a_full_probe_run_opens_no_socket(monkeypatch):
    """The default path is offline. Proven by removing the ability to be online.

    ``demo/mock_llm.py``'s no-key path is a merge gate for the same reason: CI
    runs on machines with no stack and no network, and a testbed that quietly
    needed one would fail there and nowhere else.
    """
    def _forbidden(*args, **kwargs):
        raise AssertionError("the offline testbed opened a socket")

    monkeypatch.setattr(socket, "socket", _forbidden)
    for sector_name in sorted(EXPECTED):
        assert run_probes(sector_name).ok


def test_the_offline_path_never_reaches_for_an_http_client(monkeypatch):
    """Belt to the socket test's braces, and it names the seam.

    ``requests`` is imported lazily inside ``providers._requests`` precisely so
    that "did the offline path try to make an HTTP call" is a question with a
    single place to ask it.
    """
    from foxy_testbed import providers

    def _forbidden():
        raise AssertionError("the offline testbed imported an HTTP client")

    monkeypatch.setattr(providers, "_requests", _forbidden)
    assert run_probes("healthcare").ok
