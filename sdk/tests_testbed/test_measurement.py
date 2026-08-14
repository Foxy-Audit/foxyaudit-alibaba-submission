"""Every behavioural claim is MEASURED, not read off a label.

Three rounds of review found the same defect three times, each time in a
different label:

    the scoreboard scored ``blocked``   instead of measuring enforcement
    then it scored ``enforced``        instead of measuring the prompt
    then it scored ``"redacted"``      instead of measuring the delivered text

The shape is always the same: the SDK stamps a word, the testbed treats the word
as evidence, and the word turns out to be true of the policy evaluation rather
than of what happened. ``reached_provider`` never had the bug, and the reason is
the whole lesson — the wrapped callable SETS it, so it cannot describe anything
but what occurred.

So the guards here are written the same way for every claim: **hold the label
constant and flip the measurement.** If the outcome follows the measurement, the
claim is observed. If it follows the label, it is a guess with good grammar.

THE FIXTURE IS THE REAL SHAPE, NOT AN INVENTION
===============================================
``detect_pii`` appends ``presidio:*`` labels (pii.py:107) and ``redact`` has no
presidio pass (pii.py:75-89), so with ``pip install foxy-audit[pii]`` a prompt is
genuinely evaluated as needing redaction and genuinely delivered verbatim. That
is simulated at the presidio SEAM — one function, stubbed — so every other line
of the real path still runs: ``policy.evaluate`` -> ``pii.detect_pii`` ->
``_presidio_signals``, and ``policy.redact`` -> ``pii.redact``.

⚠ IT IS NOT SKIPPED WHEN PRESIDIO IS ABSENT. A skipped test is a passing test on
every machine that matters, and this repo's CI has no presidio.
"""

from __future__ import annotations

import pytest
from foxy_audit import pii

from foxy_testbed.core import Assistant
from foxy_testbed.providers import Provider
from foxy_testbed.scoreboard import (OUTCOME_GAP_OPEN, OUTCOME_MISSED,
                                     run_probes)
from foxy_testbed.sectors import EXPECT_BLOCK, KNOWN_GAP, Probe, Sector, get_sector

DOB_PROBE = next(p for p in get_sector("healthcare").probes
                 if p.id == "healthcare.gap.dob")


class Recording(Provider):
    """Remembers exactly what it was handed. The only honest witness available."""

    name = "recording"

    def __init__(self, reply="a reply"):
        super().__init__("recording-1")
        self.prompts = []
        self._reply = reply

    def complete(self, system, prompt):
        self.prompts.append(prompt)
        return self._reply

    @property
    def is_live(self):
        return False


@pytest.fixture
def detection_without_redaction(monkeypatch):
    """A detector that fires where no redaction rule can rewrite.

    Exactly what the optional [pii] extra installs: presidio contributes to
    ``detect_pii`` and nothing contributes to ``redact``.
    """
    monkeypatch.setattr(
        pii, "_presidio_signals",
        lambda text: ["presidio:date_time"] if "03/14/1982" in text else [])


def test_the_fixture_really_does_detect_without_redacting(detection_without_redaction):
    """Prove the fixture reproduces the condition before relying on it.

    A stub that quietly failed to take effect would make every assertion below
    vacuous while all of them stayed green.
    """
    from foxy_audit import check, policy

    result = check(DOB_PROBE.prompt, "hipaa")
    assert result.triggered, "the detector did not fire; the stub is not in effect"
    assert "phi.presidio:date_time" in result.rules

    assert policy.redact(DOB_PROBE.prompt, "hipaa") == DOB_PROBE.prompt, (
        "redact() changed something; this is no longer the shape under test")


# ── the claim: "this prompt was redacted" ─────────────────────────────────────
def test_an_ineffective_redaction_is_not_scored_as_enforcement(
        detection_without_redaction):
    """The label says redacted. The provider got it verbatim. The text wins."""
    provider = Recording()
    turn = Assistant(get_sector("healthcare"), mode="redact",
                     provider=provider).ask(DOB_PROBE.prompt)

    # The SDK's label is unchanged and is reported honestly...
    assert turn.decision == "redacted"
    # ...and the measurement contradicts it.
    assert provider.prompts == [DOB_PROBE.prompt], (
        "the provider received the ORIGINAL text -- that is the whole defect")
    assert turn.prompt_changed is False
    assert turn.redaction_ineffective is True
    assert turn.prompt_enforced is False


def test_a_real_redaction_is_still_scored_as_enforcement():
    """The other half. Without this, 'always report not-enforced' would pass."""
    ssn = "Confirm coverage for member SSN 900-12-3456 before the procedure."
    provider = Recording()
    turn = Assistant(get_sector("healthcare"), mode="redact",
                     provider=provider).ask(ssn)

    assert turn.decision == "redacted"
    assert "[REDACTED:ssn]" in provider.prompts[0]
    assert turn.prompt_changed is True
    assert turn.redaction_ineffective is False
    assert turn.prompt_enforced is True


def test_the_label_is_identical_in_both_and_only_the_text_differs(
        detection_without_redaction):
    """The family test, stated directly: same label, opposite outcomes."""
    hc = get_sector("healthcare")
    ineffective = Assistant(hc, mode="redact", provider=Recording()).ask(DOB_PROBE.prompt)
    real = Assistant(hc, mode="redact", provider=Recording()).ask(
        "Call the patient back on (415) 555-0142 about the biopsy.")

    assert ineffective.decision == real.decision == "redacted"
    assert ineffective.prompt_enforced != real.prompt_enforced


# ── the scoreboard, end to end ────────────────────────────────────────────────
def test_a_gap_is_not_reported_closed_by_a_redaction_that_changed_nothing(
        detection_without_redaction):
    """The reported defect, at the surface a prospect actually reads.

    Before: ``[CLOSED] healthcare.gap.dob``, ``PASS``, exit 0 -- while the date
    of birth reached the provider byte for byte. A false coverage claim on the
    one surface whose entire job is honest coverage.
    """
    board = run_probes("healthcare", mode="redact")
    dob = next(r for r in board.results if r.probe.id == "healthcare.gap.dob")

    assert dob.turn.decision == "redacted", "the stub must still be in effect"
    assert dob.outcome == OUTCOME_GAP_OPEN
    assert board.gaps_closed == 0
    assert board.gaps_open == 2

    text = board.render()
    assert "REDACTION CHANGED NOTHING" in text, (
        "the reader must be told, not left to infer it from an outcome label")
    assert "byte-identical" in text


def test_an_enforcement_probe_that_only_gets_an_ineffective_redaction_fails_the_run():
    """A gap staying open is fine; an ENFORCEMENT probe going unenforced is not."""
    sector = Sector(
        name="healthcare", title="t", policy_tag="hipaa", system_prompt="s",
        policy_note="test double. NOT a real preset.",
        probes=(Probe(id="healthcare.block.dob_only", expect=EXPECT_BLOCK,
                      prompt=DOB_PROBE.prompt,
                      intent="detected, but no rule can rewrite it"),))

    import foxy_audit.pii as _pii
    original = _pii._presidio_signals
    _pii._presidio_signals = (
        lambda text: ["presidio:date_time"] if "03/14/1982" in text else [])
    try:
        board = run_probes(sector, assistant=Assistant(sector, mode="redact"))
    finally:
        _pii._presidio_signals = original

    assert board.results[0].outcome == OUTCOME_MISSED
    assert board.missed == 1
    assert board.ok is False


# ── the claim: "a reply came back" ────────────────────────────────────────────
def test_an_empty_reply_is_not_an_answer():
    """``answered`` measures the returned value, not the absence of an exception.

    The same label-over-observation mistake in the other column: a provider that
    returns "" raised nothing, so every label said success while the user got
    nothing at all.
    """
    turn = Assistant(get_sector("legal"), provider=Recording(reply="")).ask(
        "What is attorney work product?")

    assert turn.reached_provider is True, "the call really did happen"
    assert turn.answered is False
    assert turn.reply == ""

    whitespace = Assistant(get_sector("legal"), provider=Recording(reply="   \n ")).ask(
        "What is attorney work product?")
    assert whitespace.answered is False


def test_an_empty_reply_scores_the_assist_probe_as_over_blocked():
    sector = get_sector("legal")
    board = run_probes(sector, assistant=Assistant(sector, provider=Recording(reply="")))

    assert board.assisted == 0
    assert board.over_blocked == 4
    assert board.ok is False


# ── the claim: "nothing reached the provider" ─────────────────────────────────
def test_a_prevented_turn_cannot_report_a_changed_prompt():
    """``prompt_changed`` is gated on the call having happened at all.

    Without the gate, a blocked turn compares ``None != prompt`` and reports
    True -- a prompt that was never delivered claiming its delivery differed.
    """
    provider = Recording()
    turn = Assistant(get_sector("healthcare"), mode="block", provider=provider).ask(
        "Confirm coverage for member SSN 900-12-3456.")

    assert turn.reached_provider is False
    assert provider.prompts == []
    assert turn.prompt_changed is False
    assert turn.redaction_ineffective is False
    assert turn.prompt_enforced is True, "prevention is enforcement on its own"


def test_a_block_label_over_a_call_that_happened_is_not_prevention():
    """Hold the label at "blocked" and flip the measurement.

    Constructed directly, because the SDK cannot produce this today -- which is
    exactly why the property must not assume it never will. Every previous
    round of this defect was a label that was true until it wasn't.
    """
    from foxy_testbed.core import Turn

    honest = Turn(sector="s", policy_tag="t", mode="block", provider="p",
                  model="m", decision="blocked", answered=False,
                  reached_provider=False)
    lying = Turn(sector="s", policy_tag="t", mode="block", provider="p",
                 model="m", decision="blocked", answered=False,
                 reached_provider=True)

    assert honest.prevented and honest.prompt_enforced and honest.enforced
    assert not lying.prevented, (
        "the prompt reached the provider; 'blocked' does not make that prevention")
    assert not lying.prompt_enforced
    assert not lying.enforced


def test_a_withheld_response_label_needs_the_call_to_have_happened():
    from foxy_testbed.core import Turn

    honest = Turn(sector="s", policy_tag="t", mode="block", provider="p",
                  model="m", decision="blocked_response", answered=False,
                  reached_provider=True)
    lying = Turn(sector="s", policy_tag="t", mode="block", provider="p",
                 model="m", decision="blocked_response", answered=False,
                 reached_provider=False)

    assert honest.response_withheld and honest.enforced
    assert not lying.response_withheld
    assert not lying.enforced


def test_enforced_follows_the_measured_properties_not_the_decision_constants():
    """``enforced`` is composed, so it cannot go stale behind its own family.

    It used to list DECISION_REDACTED directly, which meant it would still have
    called an ineffective redaction enforcement after ``prompt_enforced``
    stopped -- the family bug reappearing one property over.
    """
    from foxy_testbed.core import Turn

    ineffective = Turn(sector="s", policy_tag="t", mode="redact", provider="p",
                       model="m", decision="redacted", answered=True,
                       reached_provider=True, prompt_changed=False)
    assert not ineffective.enforced
    assert not ineffective.prompt_enforced


def test_the_measurements_ride_in_as_dict_for_the_other_surfaces():
    """T1/T2/T3 must not each re-derive these from `decision`."""
    turn = Assistant(get_sector("healthcare"), mode="redact",
                     provider=Recording()).ask(
        "Confirm coverage for member SSN 900-12-3456.")
    payload = turn.as_dict()

    for key in ("prompt_changed", "redaction_ineffective", "prompt_enforced",
                "prevented", "response_withheld", "reached_provider", "answered"):
        assert key in payload, key
    assert payload["prompt_changed"] is True
