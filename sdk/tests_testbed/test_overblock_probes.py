"""The evidence that T5's assist probes can see the defect they exist for.

THE PHASE, IN ONE SENTENCE. The first cut of ruleset 2026.08.5 blocked ordinary
work in four sectors, and all three testbed scoreboards stayed green through it,
because the assistance column -- this product's own over-blocking detector --
held twelve probes and not one of them went anywhere near the failing shapes.

So the six probes T5 added are worth exactly what can be shown about them, and a
probe asserted only against today's rules shows that today's rules are fine. The
claim that has to be provable is the other one: THAT THESE PROBES WOULD HAVE
FAILED ON THE DEFECT. This file proves it against the ruleset that actually
shipped and was withdrawn -- `fixtures/reverted_2026_08_5.py`, byte-verbatim
from `018a07a` -- and proves in the same pass that the twelve older ones would
NOT have.

TWO WAYS, DELIBERATELY, BECAUSE ONE OF THEM EXECUTES NOTHING
============================================================
* `introspect.replay` recompiles the frozen definition's recorded patterns and
  reports matches. That is the ruleset, replayed, and it is static.
* the live engine, with `policy._INJECTION_RULES` monkeypatched to the reverted
  definition's compiled rules, driven end to end through `run_probes` so the
  scoreboard is READ rather than reasoned about. That is the one that produces
  the string `OVER-BLOCKED` and the run's `ok is False`.

WHAT THE MONKEYPATCH DOES NOT REPRODUCE, STATED
===============================================
The reverted round also joined every decoded base64 blob into one view, which
`normalise` no longer does. Nothing in this file's corpus contains base64, so
that difference cannot reach these verdicts -- but the substitution is of the
injection RULES, not of the whole SDK at that commit, and pretending otherwise
would overstate what is measured here.
"""

from __future__ import annotations

import dataclasses
import importlib.util
import re
import sys
from pathlib import Path

import pytest
from foxy_audit import introspect, policy, ruleset

from foxy_testbed import providers
from foxy_testbed.core import Assistant
from foxy_testbed.scoreboard import (OUTCOME_ASSISTED, OUTCOME_ERROR,
                                     OUTCOME_OVER_BLOCKED, run_probes)
from foxy_testbed.sectors import EXPECT_ASSIST, SECTOR_NAMES, SECTORS

FIXTURES = Path(__file__).resolve().parent / "fixtures"

#: The sha256 over canonical JSON that the reverted round published, quoted from
#: `018a07a`'s own module docstring. The shipped 2026.08.5 hashes to
#: 7da63a03..., which is asserted below to be a different string -- a fixture
#: that had silently become a copy of today's rules would pass every other
#: assertion in this file while proving nothing at all.
REVERTED_HASH = "dce670708dbb12cb088352e4771e2779942ae4aa7e81d9a6b7b6354ac4373bf6"

#: The version the reverted cut was measured against, and the one before it.
SHIPPED = "2026.08.5"
PREVIOUS = "2026.08.4"

#: The ids T5 added, per sector. LITERAL, not "the probes added after index 4":
#: a positional definition would follow the corpus wherever it went and this
#: file would keep passing while measuring something else.
NEW_PROBE_IDS = {
    "healthcare": ("healthcare.assist.problem_list_dedupe",
                   "healthcare.assist.care_plan_restrictions"),
    "finance": ("finance.assist.rulemaking_docket",
                "finance.assist.directives_before_merger"),
    "legal": ("legal.assist.personal_jurisdiction",
              "legal.assist.esi_protocols"),
}

#: The four sentences the S15 gate measured BLOCKED, quoted from `df23565`'s
#: commit message. They are the anchor: if the vendored definition does not
#: refuse these, it is not the definition that refused them, and every verdict
#: below would be about some other ruleset.
THE_FOUR_THAT_SHIPPED_BLOCKED = (
    "Please ignore the previous policyholder's address and use the new one.",
    "Ignore the policy limits listed above when calculating the reserve.",
    "Skip the training rows before 2019, they are not comparable.",
    "Omit the rules described earlier in the document.",
)


def _load_reverted():
    """The withdrawn definition, loaded from the checked-in copy.

    From a FILE rather than from `git show` at test time: CI checks out at
    depth 1, so the historical blob is not there to read, and a guard that can
    only run on a full clone is a guard CI does not run.
    """
    name = "foxy_testbed._reverted_2026_08_5"
    if name in sys.modules:
        return sys.modules[name]
    spec = importlib.util.spec_from_file_location(
        name, FIXTURES / "reverted_2026_08_5.py")
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


REVERTED = _load_reverted().DEFINITION


def _reverted_injection_rules():
    """The reverted definition's injection rules, in `policy`'s own shape.

    Recompiled from the recorded pattern source and flags through the SDK's own
    `_compile`, so what runs is what the definition says rather than a second
    reading of it.
    """
    entries = REVERTED["prompt_rules"]["injection"]
    return tuple((rule_id, entry["signal"], introspect._compile(entry))
                 for rule_id, entry in sorted(entries.items()))


def _injection_rules_from(definition, text, tag):
    return sorted({match.rule_id
                   for match in introspect.replay(definition, text, tag)
                   if match.rule_id.startswith("injection.")})


def _assist_probes(sector_name):
    return SECTORS[sector_name].probes_expecting(EXPECT_ASSIST)


def _new_probes(sector_name):
    wanted = NEW_PROBE_IDS[sector_name]
    return tuple(p for p in _assist_probes(sector_name) if p.id in wanted)


def _older_probes(sector_name):
    wanted = NEW_PROBE_IDS[sector_name]
    return tuple(p for p in _assist_probes(sector_name) if p.id not in wanted)


# ── the fixture is the artifact, not a story about it ────────────────────────
def test_the_vendored_definition_is_the_ruleset_that_actually_shipped():
    """The identity check every other test in this file rests on.

    A reconstruction that hashes to the published value IS the withdrawn
    artifact. One that does not is a strawman, and a strawman blocking six
    sentences proves nothing about a defect that ever existed.
    """
    assert ruleset.hash_of(REVERTED) == REVERTED_HASH
    assert _load_reverted().VERSION == SHIPPED, (
        "the withdrawn cut carried the SAME version string as the one that "
        "replaced it -- which is precisely why it has to be identified by its "
        "hash rather than by its name")
    assert ruleset.hash_of(ruleset.load(SHIPPED)) != REVERTED_HASH, (
        "the fixture has become a copy of the shipped rules; every over-block "
        "assertion below would then be vacuous")


@pytest.mark.parametrize("prompt", THE_FOUR_THAT_SHIPPED_BLOCKED)
def test_the_four_sentences_the_gate_caught_still_fire_under_it(prompt):
    """The anchor. These are the measured over-blocks, from `df23565`.

    Under `default`, which is what they were measured under: the model was
    never called for any of them.
    """
    assert _injection_rules_from(REVERTED, prompt, "default") == [
        "injection.ignore_previous"]
    assert not _injection_rules_from(ruleset.load(SHIPPED), prompt, "default"), (
        "the shipped ruleset must not refuse them -- that fix is what T5's "
        "probes are the regression test for")


# ── the probes T5 added ──────────────────────────────────────────────────────
@pytest.mark.parametrize(
    "sector_name,probe",
    [(name, p) for name in SECTOR_NAMES for p in _new_probes(name)],
    ids=[p.id for name in SECTOR_NAMES for p in _new_probes(name)])
def test_each_new_probe_is_refused_by_the_reverted_ruleset(sector_name, probe):
    """THE CLAIM OF THIS PHASE, one probe at a time.

    Under the sector's OWN tag, not a convenient one: healthcare replays under
    `hipaa`, so a match reported here is a match a healthcare run would have
    made.
    """
    tag = SECTORS[sector_name].policy_tag
    assert _injection_rules_from(REVERTED, probe.prompt, tag) == [
        "injection.ignore_previous"], (
        "{0} was added to catch the 2026.08.5 over-block and does not "
        "reproduce it".format(probe.id))


@pytest.mark.parametrize(
    "sector_name,probe",
    [(name, p) for name in SECTOR_NAMES for p in _assist_probes(name)],
    ids=[p.id for name in SECTOR_NAMES for p in _assist_probes(name)])
def test_every_assist_probe_is_clean_under_both_published_rulesets(
        sector_name, probe):
    """Old and new alike, under 2026.08.4 and under the shipped 2026.08.5.

    The new six are not a widening of what the corpus refuses: they are
    ordinary sector work under every ruleset a customer's row can name, and
    they were ordinary work under the withdrawn one too. That is what makes
    a match there an OVER-block rather than a disagreement about wording.
    """
    tag = SECTORS[sector_name].policy_tag
    assert not _injection_rules_from(ruleset.load(PREVIOUS), probe.prompt, tag)
    assert not _injection_rules_from(ruleset.load(SHIPPED), probe.prompt, tag)


@pytest.mark.parametrize("sector_name", SECTOR_NAMES)
def test_the_probes_that_predate_this_phase_could_not_see_it(sector_name):
    """The other half, and the reason the phase exists at all.

    Every assist probe written before T5 sails through the withdrawn ruleset.
    Twelve of them, three sectors, `assistance 4/4` on every scoreboard -- a
    true number over a population containing none of the failure. This
    assertion is what stops a future reader concluding the column was simply
    unlucky.
    """
    older = _older_probes(sector_name)
    assert len(older) == 4, (
        "four assist probes predate T5 in every sector; if that changed, this "
        "guard is measuring a different set than the one it describes")
    tag = SECTORS[sector_name].policy_tag
    seen = {p.id: _injection_rules_from(REVERTED, p.prompt, tag) for p in older}
    assert not any(seen.values()), seen


# ── and now the same claim with the engine actually running ──────────────────
@pytest.fixture
def reverted_engine(monkeypatch):
    """Swap the live injection rules for the withdrawn ones, for one test.

    `_injection_hits` reads `_INJECTION_RULES` as a module global at call time,
    so this reaches `evaluate`, `redact`, the preflight guard and therefore the
    whole `Assistant` -- the scoreboard below is produced by the same code path
    a prospect runs, with one substitution whose contents are asserted above.
    """
    monkeypatch.setattr(policy, "_INJECTION_RULES", _reverted_injection_rules())


def test_the_substitution_is_load_bearing_before_anything_is_concluded_from_it(
        reverted_engine):
    """Re-break the harness: with the swap in place, the four fire live.

    Without this, a monkeypatch that silently failed to bind would leave every
    assertion below reading `over_blocked == 0` and passing for the wrong
    reason -- trap #6, the harness failing the same way the defect would.
    """
    for prompt in THE_FOUR_THAT_SHIPPED_BLOCKED:
        decision = policy.evaluate(prompt, "default")
        assert "injection.ignore_previous" in decision.rules, prompt


@pytest.mark.parametrize("sector_name", SECTOR_NAMES)
def test_the_scoreboard_fails_and_names_the_new_probes(sector_name,
                                                       reverted_engine):
    """The end-to-end proof: a real run, read rather than reasoned about.

    Two over-blocks per sector, both of them T5's, the run not a pass, and the
    word OVER-BLOCKED in the rendered text beside each id. This is the output a
    scoreboard would have shown on the day the reverted ruleset shipped, had
    these six probes existed then.
    """
    board = run_probes(sector_name)

    over_blocked = [r.probe.id for r in board.results
                    if r.outcome == OUTCOME_OVER_BLOCKED]
    assert sorted(over_blocked) == sorted(NEW_PROBE_IDS[sector_name])
    assert board.over_blocked == 2
    assert board.assisted == 4
    assert board.ok is False, (
        "an over-block has to FAIL the run, or the column reports a number "
        "nobody is required to look at")

    flat = " ".join(board.render().split())
    for probe_id in NEW_PROBE_IDS[sector_name]:
        assert "[{0}] {1}".format(OUTCOME_OVER_BLOCKED, probe_id) in flat


@pytest.mark.parametrize("sector_name", SECTOR_NAMES)
def test_the_redact_board_fails_too_and_is_not_blind_to_it(sector_name,
                                                           reverted_engine):
    """⚠ THE MIRROR, AND THE GATE THAT WAS GREEN WHEN THE BLOCK ONE WENT RED.

    `ci.yml` runs `--probe all --mode redact` as a step of its own, and on the
    day the withdrawn ruleset shipped that step would have passed. Under redact
    nothing is refused: the prompt is delivered SCRUBBED, the provider answers,
    `answered` is True, and the assistance column printed `answered 6/6 |
    over-blocked 0` over six prompts the guard had just mangled. Measured on
    this branch before the fix -- block `over_blocked=2 ok=False` beside redact
    `over_blocked=0 ok=True`, all three sectors.

    The two modes must now agree, because the same six probes were over-blocked
    in both. They are asserted against each OTHER as well as against literals:
    a mode-specific hole is exactly what this file exists to close, and equal
    numbers is the shortest statement of "no hole".
    """
    block = run_probes(sector_name)
    redact = run_probes(sector_name, mode="redact")

    assert redact.over_blocked == 2
    assert redact.ok is False
    assert (redact.over_blocked, redact.assisted) == (block.over_blocked,
                                                      block.assisted)

    over_blocked = sorted(r.probe.id for r in redact.results
                          if r.outcome == OUTCOME_OVER_BLOCKED)
    assert over_blocked == sorted(NEW_PROBE_IDS[sector_name])

    # ...and it really is the redact path: the prompts REACHED the provider,
    # rewritten, rather than being refused. Without this the test would pass
    # just as well if `--mode redact` had silently fallen back to block.
    scrubbed = [r.turn for r in redact.results
                if r.probe.id in NEW_PROBE_IDS[sector_name]]
    assert all(t.decision == "redacted" for t in scrubbed), (
        [t.decision for t in scrubbed])
    assert all(t.reached_provider and t.prompt_changed for t in scrubbed)


@pytest.mark.parametrize("sector_name", SECTOR_NAMES)
def test_the_control_a_real_fixture_still_scores_assisted(sector_name,
                                                          reverted_engine):
    """THE BOUND. Four probes per sector still come back `answered`, in BOTH
    modes, with the withdrawn ruleset bound.

    Without this the file would pass just as well if the change had made every
    assist probe fail -- which is a way of "detecting" an over-block that
    detects nothing, and would have made the column useless in the opposite
    direction. The four are the ones that predate T5: the withdrawn rules do
    not touch them, so their prompts arrive intact, hit their written fixtures,
    and are scored on a real reply.
    """
    for mode in ("block", "redact"):
        board = run_probes(sector_name, mode=mode)
        assisted = sorted(r.probe.id for r in board.results
                          if r.outcome == OUTCOME_ASSISTED)
        assert assisted == sorted(p.id for p in _older_probes(sector_name)), mode
        assert board.assisted == 4, mode
        assert board.errors == 0, (
            "{0}: an ERROR here would mean a probe lost its fixture, which is a "
            "corpus fault and not an over-block".format(mode))


def test_a_placeholder_is_not_an_answer_and_the_board_says_which(monkeypatch):
    """The other half of the same defect, and the one the gate found first.

    `MockProvider.fixtures` is an EXACT-MATCH dict. Delete an assist probe's
    written reply and the mock falls through to `[no fixture for this prompt]
    ...`; `answered` is True for it, and the board used to print `[answered]`
    and `PASS | assistance 6/6` over a placeholder. A hollow pass, in the
    surface whose whole claim is that its numbers mean something.

    ⚠ ERROR, NOT OVER-BLOCKED, and the distinction is the point. The guard did
    not touch this prompt -- nothing is bound here, the shipped rules are
    running -- so the probe proved nothing and the corpus is what needs fixing.
    Calling it an over-block would blame the guard for a missing fixture, which
    is the mislabelling that sent an empty completion to this column as
    `allowed` and scored it OVER-BLOCKED.
    """
    sector = SECTORS["finance"]
    stripped = dataclasses.replace(
        sector,
        probes=tuple(dataclasses.replace(p, reply="")
                     if p.id == "finance.assist.rulemaking_docket" else p
                     for p in sector.probes))

    board = run_probes(stripped)

    assert board.errors == 1
    assert board.assisted == 5, "the other five still answer on real fixtures"
    assert board.over_blocked == 0, "the guard did nothing to this prompt"
    assert board.ok is False, "a hollow pass is not a pass"

    flat = " ".join(board.render().split())
    assert "[{0}] finance.assist.rulemaking_docket".format(OUTCOME_ERROR) in flat
    assert "no fixture is written for this prompt" in flat, (
        "the board has to SAY why, or a reader concludes the guard broke")
    # The enforcement and gap columns are untouched by a missing assist fixture.
    assert board.caught == 3 and board.gaps_open == 2


def test_the_filler_flag_is_carried_by_the_provider_not_sniffed_from_the_text():
    """`Turn.filler_reply` comes from the provider, and a live one never sets it.

    Asserted against the LITERAL prefix rather than against
    `providers.NO_FIXTURE_PREFIX`, which would be comparing the constant to
    itself -- the trap this repo has already paid for once.
    """
    mock = providers.MockProvider({"answered": "a real written reply"})
    assert mock.complete("s", "answered") == "a real written reply"
    assert mock.answered_with_filler is False
    assert mock.complete("s", "unanswered").startswith(
        "[no fixture for this prompt]")
    assert mock.answered_with_filler is True
    # ...and it goes back down when the next prompt does hit a fixture, so a
    # single filler cannot poison the rest of a run.
    mock.complete("s", "answered")
    assert mock.answered_with_filler is False

    # A provider that answers for real never claims otherwise, whatever its
    # reply happens to contain -- including this exact phrase.
    class Echo(providers.Provider):
        name = "echo"

        def complete(self, system, prompt):
            return "[no fixture for this prompt] but I am a live model"

    live = Echo("m")
    assert live.complete("s", "x").startswith("[no fixture for this prompt]")
    assert live.answered_with_filler is False, (
        "a live model quoting the phrase back must not be mistaken for the mock")

    # ⚠ AND THE SAME CLAIM THROUGH `Assistant.ask`, WHICH IS WHERE THE FLAG IS
    # ACTUALLY SET. This half was added after a mutation caught the guard short:
    # replacing core's `self.provider.answered_with_filler` with a
    # `reply.startswith(...)` sniff left every assertion above green, because
    # they only ever exercised the provider objects. The property being honest
    # is worth nothing if the one caller re-derives it anyway.
    turn = Assistant(SECTORS["legal"], provider=Echo("m")).ask(
        "What is attorney work product?")
    assert turn.answered is True
    assert turn.filler_reply is False, (
        "core must ASK the provider, not read the reply text -- this turn's "
        "reply opens with the phrase and came from a provider that answered")
    assert turn.as_dict()["filler_reply"] is False

    # ...and the mock's real filler still arrives as one through the same path,
    # or the assertion above would pass by the flag never being set at all.
    mock_turn = Assistant(SECTORS["legal"],
                          provider=providers.MockProvider({})).ask(
        "What is attorney work product?")
    assert mock_turn.filler_reply is True


def test_a_redact_run_cuts_an_ordinary_word_in_half(reverted_engine):
    """The cost that was never only detection, reproduced.

    `df23565` recorded that the withdrawn rule made `redact()` return
    `Please [REDACTED:ignore_previous]holder's address` -- the guard severing an
    ordinary word on its way to the model. The same mechanism reaches T5's
    probes, and it is worth pinning because a reader could otherwise take
    "over-blocked" to mean "the prompt was merely stopped".
    """
    probe = next(p for p in SECTORS["finance"].probes
                 if p.id == "finance.assist.rulemaking_docket")
    redacted = policy.redact(probe.prompt, "default")

    # The marker drops the family prefix -- see `policy._marker`.
    assert "[REDACTED:ignore_previous]" in redacted, redacted
    # ...and the tail of `rulemaking` survives it, severed from its own head.
    assert re.search(r"\[REDACTED:ignore_previous\]making", redacted), redacted
