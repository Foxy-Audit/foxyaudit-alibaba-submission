"""Run a sector's probe corpus and report BOTH columns.

Anyone can show a blocked prompt. The number that makes this worth building is
the second one: an assistant that refuses everything scores a perfect
enforcement rate and is useless, so a run that reports only blocks flatters us.
Every scoreboard therefore carries three tallies —

* **enforcement** — caught vs missed, over the ``expect_block`` probes;
* **assistance** — answered vs over-blocked, over the ``expect_assist`` probes;
* **known gaps** — counted, named, and given a reason, over the ``KNOWN_GAP``
  probes. Without this third tally the two sectors running on the baseline would
  print a flawless 100% while the risk their sector is actually about was simply
  missing from the corpus.

A gap is never a failure. It is stated in advance and asserted to still be open;
if one starts blocking, the run says CLOSED and keeps passing, because a gap
closing is good news and a scoreboard that goes red on good news gets ignored.
What fails a run is a MISS, an OVER-BLOCK, or an ERROR.

ASCII ONLY, DELIBERATELY
========================
Every string this module prints is 7-bit. A Windows console is cp1252 and a
captured pytest/CI stream frequently is too, so a single box-drawing character
or em dash here turns a passing gate into a UnicodeEncodeError whose traceback
points at the print rather than at the character. Measured on this repo's own
machine, not assumed.

DETERMINISTIC BY OMISSION
=========================
Latency is on every :class:`~foxy_testbed.core.Turn` and appears on NO
scoreboard. It is the one value in the record that changes between two identical
runs, and this output is a CI gate whose whole job is to be byte-stable.
"""

from __future__ import annotations

import textwrap
from dataclasses import dataclass

from .core import Assistant, DECISION_ERROR, DEFAULT_MODE, Turn
from .sectors import EXPECT_ASSIST, EXPECT_BLOCK, KNOWN_GAP, get_sector

WIDTH = 78

# Per-probe outcomes. The first four decide pass/fail; the last two are the gap
# column, which reports and never fails.
OUTCOME_CAUGHT = "caught"
OUTCOME_MISSED = "MISSED"
OUTCOME_ASSISTED = "answered"
OUTCOME_OVER_BLOCKED = "OVER-BLOCKED"
OUTCOME_GAP_OPEN = "open"
OUTCOME_GAP_CLOSED = "CLOSED"
OUTCOME_ERROR = "ERROR"

#: The outcomes that fail a run.
FAILING = (OUTCOME_MISSED, OUTCOME_OVER_BLOCKED, OUTCOME_ERROR)


@dataclass(frozen=True)
class ProbeResult:
    probe: object
    turn: Turn
    outcome: str

    @property
    def failed(self) -> bool:
        return self.outcome in FAILING


def classify(probe, turn: Turn) -> str:
    """The outcome for one probe, given what actually happened to it.

    ``prompt_enforced``, NOT "was it blocked". The two differ in both modes that
    matter and the difference is not cosmetic:

    * under ``--mode redact`` every enforcement probe comes back ``redacted``
      with its offending span replaced before the model saw it. That is the
      guard working exactly as documented, and scoring it on blocked-ness alone
      printed ``FAIL | enforcement 0/5`` over five correct redactions.
    * a withheld RESPONSE is not prompt enforcement — the prompt reached the
      provider. Counting it here put ``[caught]`` directly above the same
      probe's own ``reached the model: yes``.
    """
    # THE ONE DELIBERATE LABEL READ IN THIS FUNCTION, and it is not the same
    # kind: DECISION_ERROR is stamped by THIS package from an exception IT
    # caught, so the label and the observation are the same event. Every other
    # branch below goes through a measured property.
    if turn.decision == DECISION_ERROR:
        return OUTCOME_ERROR
    if probe.expect == EXPECT_BLOCK:
        return OUTCOME_CAUGHT if turn.prompt_enforced else OUTCOME_MISSED
    if probe.expect == EXPECT_ASSIST:
        # `answered` rather than `prompt_enforced`: this column is about what
        # the USER got back, and a reply withheld by the response scan is an
        # over-block from where they are sitting even though the prompt was
        # never touched.
        return OUTCOME_ASSISTED if turn.answered else OUTCOME_OVER_BLOCKED
    # KNOWN_GAP: asserted still open. Closing is reported, never punished — and
    # a gap that closes under redact closes by being SCRUBBED, so this needs the
    # same property as the enforcement column or a closed gap reads as open.
    return OUTCOME_GAP_CLOSED if turn.prompt_enforced else OUTCOME_GAP_OPEN


@dataclass(frozen=True)
class Scoreboard:
    sector_name: str
    policy_tag: str
    policy_note: str
    mode: str
    provider: str
    model: str
    provider_note: str
    ruleset_version: str
    #: Whether the replies came from a real model. The assistance blurb follows
    #: this rather than assuming the mock — see :func:`_assistance_blurb`.
    provider_is_live: bool = False
    results: tuple = ()

    def _of(self, expectation):
        return tuple(r for r in self.results if r.probe.expect == expectation)

    def _count(self, outcome) -> int:
        return sum(1 for r in self.results if r.outcome == outcome)

    @property
    def caught(self) -> int:
        return self._count(OUTCOME_CAUGHT)

    @property
    def missed(self) -> int:
        return self._count(OUTCOME_MISSED)

    @property
    def assisted(self) -> int:
        return self._count(OUTCOME_ASSISTED)

    @property
    def over_blocked(self) -> int:
        return self._count(OUTCOME_OVER_BLOCKED)

    @property
    def gaps_open(self) -> int:
        return self._count(OUTCOME_GAP_OPEN)

    @property
    def gaps_closed(self) -> int:
        return self._count(OUTCOME_GAP_CLOSED)

    @property
    def errors(self) -> int:
        return self._count(OUTCOME_ERROR)

    @property
    def enforcement_total(self) -> int:
        return len(self._of(EXPECT_BLOCK))

    @property
    def assistance_total(self) -> int:
        return len(self._of(EXPECT_ASSIST))

    @property
    def ok(self) -> bool:
        """A gap does not fail a run; a miss, an over-block or an error does."""
        return not any(r.failed for r in self.results)

    def as_dict(self) -> dict:
        return {"sector": self.sector_name, "policy_tag": self.policy_tag,
                "mode": self.mode, "provider": self.provider, "model": self.model,
                # PROVENANCE TRAVELS WITH THE NUMBERS. Omitting these left a
                # JSON surface to re-derive live-vs-mock from the provider name
                # -- the same re-derivation hazard Turn.as_dict carries
                # `prevented`/`prompt_enforced` to avoid, and the same one that
                # let a hardcoded "the replies are fixtures" print on a live run.
                "provider_is_live": self.provider_is_live,
                "provider_note": self.provider_note,
                "ruleset_version": self.ruleset_version,
                "caught": self.caught, "missed": self.missed,
                "enforcement_total": self.enforcement_total,
                "assisted": self.assisted, "over_blocked": self.over_blocked,
                "assistance_total": self.assistance_total,
                "gaps_open": self.gaps_open, "gaps_closed": self.gaps_closed,
                "errors": self.errors, "ok": self.ok}

    def render(self) -> str:
        return render(self)


class AssistantConflict(ValueError):
    """An argument to :func:`run_probes` describes something the supplied
    ``assistant`` does not, so honouring both is impossible.

    Every one of these is the same defect wearing a different argument: the
    caller states a configuration, a different one runs, and the report is
    written as though the stated one had. Refused rather than resolved.
    """


class SectorMismatch(AssistantConflict):
    """``sector`` and ``assistant`` describe different presets.

    Kept as its own name because it is the one with a consequence beyond the
    caller's confusion: the wrong POLICY judges the probes, so the scoreboard
    states one preset's limits over another's verdicts.
    """


#: Arguments that configure an Assistant. Passing any of them ALONGSIDE a
#: prebuilt assistant is a conflict, because the assistant already answers each
#: one and nothing here can retro-fit them onto it.
_ASSISTANT_ARGS = ("mode", "provider", "api_key", "model")


def _conflicting_args(*values) -> list:
    """Which of :data:`_ASSISTANT_ARGS` the caller actually supplied.

    ``None`` means "not given". That is why the signature's defaults are None
    rather than the real ones -- see the note in :func:`run_probes`.
    """
    return [name for name, value in zip(_ASSISTANT_ARGS, values) if value is not None]


def run_probes(sector, mode=None, provider=None, api_key=None,
               model=None, assistant=None) -> Scoreboard:
    """Run every probe in ``sector``'s corpus and tally the three columns.

    ⚠ WHEN ``assistant`` IS SUPPLIED IT IS THE AUTHORITY, AND A DISAGREEMENT IS
    REFUSED. Both arguments used to be read independently: the probes and the
    rendered policy note came from ``sector`` while the verdicts came from
    whatever tag ``assistant`` was actually built with. So
    ``run_probes("finance", assistant=Assistant("healthcare"))`` printed
    finance's "cardholder data is NOT blocked here" note above both finance gaps
    reported CLOSED — because ``hipaa`` had judged them. A scoreboard describing
    one policy while reporting another's verdicts is the ``hipaa_basic``
    mislabelling defect in a new place, and T1/T2/T3 are exactly the callers
    that hold one long-lived Assistant per session.

    The fix is the refusal: the mismatch RAISES rather than resolving silently
    to either side — a caller who asked for finance and would have got
    healthcare has a bug, and picking a winner for them hides it.

    Reading everything from ``assistant.sector`` afterwards is DEFENCE IN DEPTH,
    not a second fix, and is worth stating honestly: with the refusal in place
    the two reads are provably identical, because ``Sector`` is a frozen
    dataclass whose every field participates in ``==``. Measured — no test can
    tell them apart, and one deliberately written to try is an equivalent
    mutant. Its value is future-tense: if the comparison is ever loosened (to
    name and tag, say, so a caller may pass a customised note), this line is
    what keeps the report following what actually ran instead of silently
    reintroducing the defect.

    Sectors are compared by VALUE. ``Sector`` and ``Probe`` are frozen
    dataclasses, so two structurally identical presets are interchangeable and
    comparing by identity would reject a caller who rebuilt an equal one.
    """
    if isinstance(sector, str):
        sector = get_sector(sector)

    if assistant is None:
        # The defaults live HERE rather than in the signature, so that "not
        # given" and "given the default value" stay distinguishable above.
        # Collapsing them is what let `mode="redact"` be silently dropped: with
        # `mode="block"` as the signature default there was no way to tell a
        # caller who wanted block from one who said nothing.
        assistant = Assistant(sector, mode=mode or DEFAULT_MODE,
                              provider=provider or "mock",
                              api_key=api_key or "", model=model or "")
    elif _conflicting_args(mode, provider, api_key, model):
        supplied = _conflicting_args(mode, provider, api_key, model)
        raise AssistantConflict(
            "run_probes was given both a prebuilt assistant and {0}, which "
            "only apply when this function builds the assistant itself. The "
            "assistant already runs mode={1!r} with provider={2!r} ({3!r}), and "
            "nothing here can change that after the fact -- so the run would "
            "have reported the configuration you asked for while executing a "
            "different one. Configure the Assistant, or drop the "
            "argument{4}.".format(
                " and ".join(repr(n) for n in supplied),
                assistant.mode, assistant.provider.name, assistant.provider.model,
                "" if len(supplied) == 1 else "s"))
    elif sector is not None and sector != assistant.sector:
        raise SectorMismatch(
            "run_probes was asked for sector {0!r} (policy_tag={1!r}) but the "
            "assistant supplied runs {2!r} (policy_tag={3!r}). The scoreboard "
            "would state one preset's limits while reporting the other's "
            "verdicts. Pass the assistant alone, or build it from this "
            "sector.".format(sector.name, sector.policy_tag,
                             assistant.sector.name, assistant.sector.policy_tag))

    # From here on the ASSISTANT is the single source of truth: its sector
    # supplies the probes and every line the report renders.
    sector = assistant.sector

    results = []
    ruleset_version = ""
    for probe in sector.probes:
        turn = assistant.ask(probe.prompt)
        ruleset_version = ruleset_version or turn.ruleset_version
        results.append(ProbeResult(probe, turn, classify(probe, turn)))

    return Scoreboard(
        sector_name=sector.name,
        policy_tag=sector.policy_tag,
        policy_note=sector.policy_note,
        mode=assistant.mode,
        provider=assistant.provider.name,
        model=assistant.provider.model,
        provider_note=assistant.provider.note,
        provider_is_live=assistant.provider.is_live,
        ruleset_version=ruleset_version,
        results=tuple(results),
    )


# ── rendering ─────────────────────────────────────────────────────────────────
def _rule(char: str = "-") -> str:
    return char * WIDTH


def _wrap(text: str, indent: int, first: str = "") -> list:
    """Wrap ``text`` into WIDTH columns, hanging-indented by ``indent``."""
    pad = " " * indent
    body = textwrap.wrap(" ".join(str(text).split()), width=WIDTH - indent) or [""]
    if first:
        head = "{0}{1}".format(first.ljust(indent), body[0])
        return [head] + [pad + line for line in body[1:]]
    return [pad + line for line in body]


def _field(label: str, value: str) -> list:
    return _wrap(value, 14, first="  " + label)


def _probe_lines(result) -> list:
    probe, turn = result.probe, result.turn
    lines = ["  [{0}] {1}".format(result.outcome, probe.id)]
    lines += _wrap(probe.intent, 10)
    if turn.decision == DECISION_ERROR:
        lines += _wrap("error: " + turn.error, 10)
        return lines
    # " | " rather than runs of spaces: _wrap normalises whitespace, so any
    # column alignment built out of spaces is collapsed the moment a line wraps.
    detail = "decision: {0} | rules: {1} | reason: {2} | reached the model: {3}".format(
        turn.decision,
        ", ".join(turn.rules) if turn.rules else "(none fired)",
        turn.blocked_reason,
        "yes" if turn.reached_provider else "no",
    )
    lines += _wrap(detail, 10)
    if turn.redaction_ineffective:
        # The loudest line this renderer produces, because it is the one a
        # reader would otherwise never suspect: the SDK said "redacted" and the
        # provider got the text unchanged. Silence here is what let a false
        # [CLOSED] print over a DOB delivered verbatim.
        lines += _wrap(
            "REDACTION CHANGED NOTHING: the policy flagged this prompt and the "
            "SDK stamped it 'redacted', but the text delivered to the provider "
            "is byte-identical to the text submitted. A rule detected it that "
            "no redaction rule can rewrite. Scored as NOT enforced, on the "
            "measured text rather than the label.", 10)
    if probe.gap_reason:
        lines += _wrap("why nothing catches it: " + probe.gap_reason, 10)
    return lines


def _assistance_blurb(board: Scoreboard) -> str:
    """What 'answered' means HERE — which depends on what actually answered.

    This sentence used to hardcode "with the mock provider the replies are
    fixtures" and printed it unchanged on a live run, three lines under a header
    already saying the prompt went to OpenAI under the user's own key. Two
    contradictory provenance claims about the same replies, in the demo of a
    product whose entire pitch is that its evidence is honest.

    The half that does NOT change is the second sentence: neither variant claims
    to grade an answer. Nothing in this package reads a reply's content, so the
    column measures over-blocking under any provider.
    """
    common = ("'answered' means the guard let the prompt through and a reply "
              "came back. It is NOT a claim that the answer was good -- nothing "
              "here reads the content of a reply, so this column measures "
              "whether the guard over-blocks, not model quality.")
    if board.provider_is_live:
        return ("{0} The replies came from {1} ({2}), under your own key.".format(
            common, board.provider, board.model))
    return "{0} The replies are fixtures, not model output.".format(common)


def render(board: Scoreboard) -> str:
    """The scoreboard, as 7-bit text. See the module docstring for why."""
    out = [_rule("="),
           "  Foxy Audit -- compliance testbed",
           _rule("=")]
    out += _field("sector", "{0} (policy_tag={1}, mode={2})".format(
        board.sector_name, board.policy_tag, board.mode))
    out += _field("provider", "{0} ({1})".format(board.provider, board.model))
    out += _field("ruleset", board.ruleset_version or "(not reported)")
    if board.provider_note:
        out += _field("note", board.provider_note)
    out.append("")
    out += _wrap("WHAT THIS PRESET ENFORCES, AND WHAT IT DOES NOT", 2)
    out += _wrap(board.policy_note, 4)

    out += ["", _rule(),
            "  ENFORCEMENT -- did the guard stop what it should have?",
            _rule()]
    if board.mode == "observe":
        # 0/N here is TRUE, not a regression, and saying so beats letting a
        # reader conclude the guard is broken. Stated rather than special-cased:
        # the run still does not pass, because nothing was prevented.
        out += _wrap(
            "mode=observe records but never prevents, so nothing below can be "
            "caught. That is what observe means. Run with --mode block or "
            "--mode redact to measure enforcement.", 2)
        out.append("")
    for result in board._of(EXPECT_BLOCK):
        out += _probe_lines(result)
    out.append("  caught {0}/{1} | missed {2}".format(
        board.caught, board.enforcement_total, board.missed))

    out += ["", _rule(),
            "  ASSISTANCE -- is it still useful with the guard on?",
            _rule()]
    out += _wrap(_assistance_blurb(board), 2)
    out.append("")
    for result in board._of(EXPECT_ASSIST):
        out += _probe_lines(result)
    out.append("  answered {0}/{1} | over-blocked {2}".format(
        board.assisted, board.assistance_total, board.over_blocked))

    gaps = board._of(KNOWN_GAP)
    if gaps:
        out += ["", _rule(),
                "  KNOWN GAPS -- real risk in this sector that nothing catches today",
                _rule()]
        out += _wrap(
            "Stated, not enforced. These are counted so this scoreboard cannot "
            "read as full coverage. A gap is not a failure and does not fail "
            "the run; if one starts blocking it is reported as CLOSED.", 2)
        out.append("")
        for result in gaps:
            out += _probe_lines(result)
        out.append("  {0} open | {1} closed".format(board.gaps_open, board.gaps_closed))

    if board.errors:
        out += ["", "  {0} probe(s) ERRORED -- the run proved nothing about them.".format(
            board.errors)]

    out += ["", _rule("=")]
    out += _wrap(
        "{0} | enforcement {1}/{2} | assistance {3}/{4} | {5} known gap(s) open".format(
            "PASS" if board.ok else "FAIL",
            board.caught, board.enforcement_total,
            board.assisted, board.assistance_total,
            board.gaps_open), 2)
    out.append(_rule("="))
    return "\n".join(out)


# The EXCEPTIONS BELONG HERE. They were exported from the package __init__ but
# not from this module, so `from foxy_testbed.scoreboard import *` followed by
# `except SectorMismatch` raised NameError -- an exception you cannot catch from
# the module that raises it.
__all__ = ["AssistantConflict", "FAILING", "OUTCOME_ASSISTED", "OUTCOME_CAUGHT",
           "OUTCOME_ERROR", "OUTCOME_GAP_CLOSED", "OUTCOME_GAP_OPEN",
           "OUTCOME_MISSED", "OUTCOME_OVER_BLOCKED", "ProbeResult", "Scoreboard",
           "SectorMismatch", "WIDTH", "classify", "render", "run_probes"]
