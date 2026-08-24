"""Guards for the interactive REPL (phase T1).

WHAT THESE ARE ACTUALLY DEFENDING
=================================
Three things, and only the first is about the REPL working:

1. **It runs end-to-end offline, with no key.** That is the phase's whole
   premise -- CI runs this surface, and a REPL that needs a live provider is a
   REPL CI cannot drive. Every test here uses the mock provider or a stub.
2. **It holds no policy logic.** Enforced structurally rather than by review:
   :func:`test_the_repl_cannot_reach_the_sdk_at_all` walks ``cli.py``'s AST and
   fails on any import from ``foxy_audit``. The REPL can only render what the
   engine measured, because it has nothing else to read.
3. **It renders the measurement, not the label.** Three review rounds put
   ``prevented`` / ``prompt_enforced`` / ``rules_surviving`` on ``Turn`` so that
   no surface would re-derive them from ``decision``. A surface that then prints
   "BLOCKED" off the label alone has rebuilt the defect one layer up, so the
   contradictory shapes are constructed by hand here and the rendering is
   asserted against them.
"""

from __future__ import annotations

import ast
import io

import pytest

from foxy_testbed import cli
from foxy_testbed.core import (Assistant, DECISION_ALLOWED, DECISION_BLOCKED,
                               DECISION_BLOCKED_RESPONSE, DECISION_ERROR,
                               DECISION_FLAGGED, DECISION_REDACTED, DECISIONS,
                               Turn)
from foxy_testbed.providers import MOCK_NOTE, Provider
from foxy_testbed.sectors import get_sector

# The two probe prompts used as live inputs below, taken from the corpus rather
# than written fresh: their expectations are already pinned by test_probes.py
# against the real `foxy_audit.check`, so a rule change breaks the probe suite
# loudly instead of breaking these quietly.
BLOCKED_PROMPT = "Confirm coverage for member SSN 900-12-3456 before the procedure is scheduled."
ASSIST_PROMPT = ("What does the HIPAA minimum necessary standard require when we share "
                 "records with a billing vendor?")


class Stub(Provider):
    """A provider that counts and records. ``calls`` is the measurement.

    ``name`` and ``is_live`` are settable independently on purpose: one guard
    below needs a provider CALLED "mock" that is nonetheless live, which is the
    shape that catches a surface re-deriving provenance from the name.
    """

    def __init__(self, reply="a stub reply.", live=False, name="stub",
                 model="stub-1", note="") -> None:
        super().__init__(model)
        self.name = name
        self.reply = reply
        self.calls = 0
        self.prompts = []
        self._live = live
        self._note = note

    def complete(self, system, prompt):
        self.calls += 1
        self.prompts.append(prompt)
        return self.reply

    @property
    def is_live(self) -> bool:
        return self._live

    @property
    def note(self) -> str:
        return self._note


class Cp1252Stream:
    """A stream that refuses what a Windows console refuses.

    ``io.StringIO`` accepts every code point, so it cannot reproduce the failure
    this exists for: ``sys.stdout`` on a cp1252 console raises inside ``write``
    for a character it cannot encode, and the traceback points at the write
    rather than at the character.
    """

    encoding = "cp1252"

    def __init__(self) -> None:
        self.chunks = []

    def write(self, text) -> None:
        text.encode(self.encoding)          # the console's own failure
        self.chunks.append(text)

    def flush(self) -> None:
        pass

    def getvalue(self) -> str:
        return "".join(self.chunks)


def drive(assistant, lines, banner=True, out=None):
    """Run a whole session from a script. Returns (exit code, transcript)."""
    out = out if out is not None else io.StringIO()
    feed = iter(lines)

    def read_line():
        try:
            return next(feed)
        except StopIteration:
            raise EOFError from None

    return cli.repl(assistant, read_line=read_line, out=out, banner=banner), out.getvalue()


def turn(**overrides) -> Turn:
    """A hand-built Turn, for the shapes a real run cannot produce.

    Same technique the measurement suite uses for ``prevented`` and
    ``response_withheld``: the contradictory combinations are unreachable
    through ``Assistant.ask`` today, which is exactly why a renderer that
    mishandles them would never be caught by driving one.
    """
    fields = dict(sector="healthcare", policy_tag="hipaa", mode="block",
                  provider="stub", model="stub-1", decision=DECISION_ALLOWED,
                  answered=False, reached_provider=False)
    fields.update(overrides)
    return Turn(**fields)


# ── 1 · the phase's premise: it runs offline, keyless, end to end ─────────────
def test_a_whole_session_runs_offline_with_no_key():
    """THE CI PATH, and the gate the phase is defined by.

    One long-lived Assistant, the default mock provider, no key, no socket: a
    blocked turn, an allowed turn, a mode switch, a redacted turn, the
    scoreboard, and a clean exit -- driven the way a pipe drives it.
    """
    session = Assistant(get_sector("healthcare"))
    code, text = drive(session, [
        BLOCKED_PROMPT,
        ASSIST_PROMPT,
        "/mode redact",
        BLOCKED_PROMPT,
        "/probe",
        "/quit",
    ])

    assert code == 0

    # The banner states the preset's limits and the provider's provenance,
    # rather than leaving either to be inferred.
    assert MOCK_NOTE in " ".join(text.split())
    assert "policy_tag=hipaa, mode=block" in text
    assert "WHERE YOUR TEXT GOES: nowhere." in text

    assert "[BLOCKED]" in text
    assert "[ALLOWED]" in text
    assert "[REDACTED]" in text
    # The scoreboard ran through this session's own assistant and, having been
    # switched, ran under redact -- not under the mode the session started in.
    assert "mode=redact" in text
    assert "PASS" in text
    assert text.rstrip().endswith("bye.")


def test_no_part_of_an_offline_session_reaches_the_http_seam(monkeypatch):
    """The offline claim, asserted at the seam rather than inferred from a mock.

    ⚠ WHAT THIS DELIBERATELY DOES NOT DO is check ``sys.modules`` for
    ``requests``. It is there whatever the REPL does: ``dispatch.py`` imports it
    at module level, so ``import foxy_audit`` pulls it in before a single test
    runs, and a guard written that way passes for a reason that has nothing to
    do with the session. Measured, not assumed.

    ``providers._requests`` is the one function both live providers call to get
    the library, and it is called at request time. Breaking it turns any attempt
    to leave this machine into a loud failure -- across a whole session,
    including ``/probe``, which is the command that makes eleven calls.
    """
    from foxy_testbed import providers

    def refuse():
        raise AssertionError("an offline session tried to make an HTTP request")

    monkeypatch.setattr(providers, "_requests", refuse)

    code, text = drive(Assistant(get_sector("legal")),
                       [BLOCKED_PROMPT, ASSIST_PROMPT, "/probe", "/quit"])
    assert code == 0
    assert "PASS" in text

    # And the seam is the real one: a live provider genuinely goes through it.
    with pytest.raises(AssertionError, match="tried to make an HTTP request"):
        providers.OpenAIProvider("not-a-key").complete("sys", "hello")


# ── 2 · it holds no policy logic ──────────────────────────────────────────────
def test_the_repl_cannot_reach_the_sdk_at_all():
    """Structural, not a promise in a docstring.

    The REPL renders verdicts, so the failure mode is that it starts deciding
    them: one ``check()`` here to answer a question the engine did not, and the
    surface and the ledger have begun to disagree. There is nothing to review if
    the name is not importable in the first place.

    LIMIT, STATED: this reads the AST's import statements. A dynamic
    ``__import__`` would slip past it, so the assertion below also refuses the
    two names that would be needed to write one.
    """
    source = open(cli.__file__, "r", encoding="utf-8").read()
    tree = ast.parse(source)

    imported = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            imported += [alias.name for alias in node.names]
        elif isinstance(node, ast.ImportFrom) and node.level == 0:
            imported.append(node.module or "")
        elif isinstance(node, ast.Name):
            assert node.id not in ("__import__", "importlib"), (
                "a dynamic import in the REPL would defeat this guard")

    offenders = [name for name in imported if name.split(".")[0] == "foxy_audit"]
    assert offenders == [], (
        "cli.py imports {0} -- the REPL must render the engine's measurements, "
        "not compute its own".format(offenders))

    # And the guard is not vacuous: the engine it renders DOES import the SDK.
    from foxy_testbed import core
    core_imports = [n.module for n in ast.walk(ast.parse(
        open(core.__file__, "r", encoding="utf-8").read()))
        if isinstance(n, ast.ImportFrom) and n.level == 0]
    assert "foxy_audit" in core_imports, (
        "the engine stopped importing the SDK; this guard is now measuring "
        "nothing")


# ── 3 · the rendering follows the measurement, not the label ─────────────────
def test_every_decision_has_a_rendering_of_its_own():
    """A new decision must not silently render as an existing one.

    The fallback branch prints the raw value and says it has no rendering. That
    is the honest failure, and it is only honest if no REAL decision reaches it
    -- so every member of ``core.DECISIONS`` is checked, and the fallback is
    then shown to be reachable so this is not asserting an empty set.
    """
    shapes = {
        DECISION_ALLOWED: {},
        DECISION_FLAGGED: {"reached_provider": True},
        DECISION_BLOCKED: {"reached_provider": False, "rules": ("phi.ssn_pattern",)},
        DECISION_REDACTED: {"reached_provider": True, "rules": ("phi.ssn_pattern",)},
        DECISION_BLOCKED_RESPONSE: {"reached_provider": True},
        DECISION_ERROR: {"error": "ProviderError: HTTP 503"},
    }
    assert set(shapes) == set(DECISIONS), (
        "core.DECISIONS moved; this guard has to move with it")

    labels = {}
    for decision, shape in shapes.items():
        label, sentence = cli._headline(turn(decision=decision, **shape))
        assert "no rendering in the REPL yet" not in sentence, decision
        labels[decision] = label

    assert len(set(labels.values())) == len(DECISIONS), (
        "two decisions render as the same word: {0}".format(labels))

    # The fallback really is reachable -- otherwise the assertions above hold
    # for a branch that could never have fired.
    label, sentence = cli._headline(turn(decision="teleported"))
    assert label == "TELEPORTED" and "no rendering in the REPL yet" in sentence


#: Every decision for which ``core.Turn`` exposes a property that PAIRS the
#: label with the observation that would contradict it, and the two shapes that
#: property separates. The values are (clean, contradicting).
#:
#: ⚠ THE THREE HERE ARE THE WHOLE SET, and that is a statement about
#: ``core.Turn``, not a convenience. ``prevented``, ``response_withheld`` and
#: ``prompt_enforced`` are the only properties core defines by pairing a label
#: with ``reached_provider``; ``allowed``, ``flagged`` and ``error`` have no such
#: property, and a renderer inventing a pairing for them would be the surface
#: deciding what the engine meant -- the one thing this module must not do. If
#: core ever grows a fourth, it belongs in this table the same day.
PAIRED = {
    DECISION_BLOCKED: (
        {"reached_provider": False, "rules": ("phi.ssn_pattern",)},
        {"reached_provider": True, "rules": ("phi.ssn_pattern",)},
    ),
    DECISION_BLOCKED_RESPONSE: (
        {"reached_provider": True},
        {"reached_provider": False},
    ),
    DECISION_REDACTED: (
        {"reached_provider": True, "rules": ("phi.ssn_pattern",)},
        {"reached_provider": True, "rules": ("phi.ssn_pattern",),
         "rules_delivered": ("phi.ssn_pattern",)},
    ),
}


@pytest.mark.parametrize("decision", sorted(PAIRED))
def test_a_label_backed_by_an_observation_renders_the_contradiction(decision):
    """THE RULE, STATED ONCE INSTEAD OF PER BRANCH -- and the guard that was
    missing.

    Two of the three families had a contradiction branch and were tested
    individually; ``blocked_response`` had neither, and the per-decision guard
    above pinned ``reached_provider: True`` for it, so the shape that mattered
    was never constructed. A renderer that reads the label alone then printed
    "the prompt DID reach the provider and tokens were spent" three lines above
    "reached: no, the provider was never called".

    Written over the table so that adding a family cannot quietly skip it: the
    property under test is "when the paired observation disagrees, the reader is
    told", and it is asserted for every member at once.
    """
    clean_shape, contradicting_shape = PAIRED[decision]

    clean_label, _ = cli._headline(turn(decision=decision, **clean_shape))
    broken_label, broken_sentence = cli._headline(
        turn(decision=decision, **contradicting_shape))

    assert clean_label != broken_label, (
        "{0} renders identically whether or not the observation backs the "
        "label".format(decision))
    # And it says so, rather than merely picking a different noun.
    assert any(word in broken_sentence.lower()
               for word in ("disagree", "still firing")), broken_sentence


def test_a_withheld_response_that_never_reached_the_provider_says_so():
    """The specific shape, rendered whole -- the label alone is not the bug.

    A headline that reads correctly above a detail block that contradicts it is
    still a contradiction on screen, so this asserts against the full render
    rather than against ``_headline``'s return value.
    """
    impossible = turn(decision=DECISION_BLOCKED_RESPONSE, reached_provider=False,
                      rules=("phi.ssn_pattern",))
    assert impossible.response_withheld is False

    rendered = "\n".join(cli.turn_lines(impossible, provider_is_live=False))
    assert "RESPONSE WITHHELD, BUT NOTHING WAS SENT" in rendered
    assert "tokens were spent" not in rendered, (
        "the render claimed a spend for a call that never happened")
    assert "no, the provider was never called" in rendered

    # The honest shape still renders as a plain withheld response.
    real = turn(decision=DECISION_BLOCKED_RESPONSE, reached_provider=True)
    real_rendered = "\n".join(cli.turn_lines(real, provider_is_live=False))
    assert "\n  [RESPONSE WITHHELD]\n" in real_rendered
    assert "tokens were spent" in real_rendered


def test_the_reply_block_reads_no_decision_either():
    """The same defect, one function further down, found looking for the first.

    ``turn_lines`` ended its reply block on "everything else is a prompt that
    was stopped before the provider was called" -- which is every withheld
    RESPONSE, where the prompt reached the model and the tokens were spent.
    ``reached_provider`` was available the whole time.
    """
    withheld = turn(decision=DECISION_BLOCKED_RESPONSE, reached_provider=True)
    rendered = "\n".join(cli.turn_lines(withheld, provider_is_live=False))

    assert "stopped before the provider was called" not in rendered
    assert "the prompt reached the provider, and nothing came back to you" in rendered

    # A genuinely prevented turn still gets the sentence that is true of it.
    prevented = turn(decision=DECISION_BLOCKED, reached_provider=False,
                     rules=("phi.ssn_pattern",))
    assert "stopped before the provider was called" in "\n".join(
        cli.turn_lines(prevented, provider_is_live=False))


def test_a_block_that_reached_the_provider_is_not_rendered_as_a_block():
    """The label says prevented. The observation says delivered.

    Unreachable as the SDK stands. A renderer that reads ``decision`` alone
    prints a clean "[BLOCKED]" over a call that happened, which is the one
    failure this product cannot survive shipping -- and it would look exactly
    like a working demo.
    """
    contradiction = turn(decision=DECISION_BLOCKED, reached_provider=True,
                         rules=("phi.ssn_pattern",))
    assert contradiction.prevented is False

    label, sentence = cli._headline(contradiction)
    assert label == "BLOCKED, BUT THE CALL WAS MADE"
    assert "disagree" in sentence

    rendered = "\n".join(cli.turn_lines(contradiction, provider_is_live=False))
    assert "yes, the provider was called" in rendered
    assert "\n  [BLOCKED]\n" not in rendered, (
        "the contradiction was rendered as a clean block")

    # The honest shape still renders as one, so this is not just refusing the word.
    clean = turn(decision=DECISION_BLOCKED, reached_provider=False,
                 rules=("phi.ssn_pattern",))
    assert cli._headline(clean)[0] == "BLOCKED"


def test_an_ineffective_redaction_is_rendered_as_incomplete_and_names_the_finding():
    """The loudest thing the REPL prints, and the reason it exists.

    ``redacted`` with a finding still firing against the delivered text is the
    T0d defect. The renderer has to name the surviving rule, not merely decline
    to call it enforced -- "which one got through" is the only actionable half.
    """
    leaky = turn(decision=DECISION_REDACTED, reached_provider=True, answered=True,
                 reply="answered anyway.", prompt_changed=True,
                 rules=("phi.ssn_pattern", "phi.presidio:date_time"),
                 rules_delivered=("phi.presidio:date_time",))
    assert leaky.redaction_ineffective is True

    rendered = "\n".join(cli.turn_lines(leaky, provider_is_live=False))
    assert "[REDACTED, INCOMPLETELY]" in rendered
    assert "STILL SENT" in rendered
    assert "phi.presidio:date_time" in rendered
    # BOTH lists: the rule that really was scrubbed is reported too, or the
    # render understates the guard exactly as the old one overstated it.
    assert "removed" in rendered and "phi.ssn_pattern" in rendered
    # ...AND IT SAYS THIS IS A REGRESSION. Since SDK 1.9.0 the guard blocks a
    # turn whose finding survived its own redaction (SDK #216), so this render
    # is unreachable from a real session -- `leaky` above is hand-built, which
    # is precisely why it still works. A reader who somehow meets these lines
    # must learn they mean the fix regressed, not that this prompt was unlucky.
    assert "SDK #216" in rendered
    assert "regression of that fix" in rendered
    rendered.encode("ascii")           # 7-bit, like everything else here

    # A redaction that worked is still rendered as one.
    clean = turn(decision=DECISION_REDACTED, reached_provider=True, answered=True,
                 reply="ok.", prompt_changed=True, rules=("phi.ssn_pattern",))
    assert "[REDACTED]" in "\n".join(cli.turn_lines(clean, provider_is_live=False))


def test_a_prevented_turn_does_not_claim_its_findings_were_removed():
    """``rules_removed`` is true on a prevented turn and 'removed' is the wrong
    word for it: nothing was rewritten, because nothing was delivered.
    """
    prevented = turn(decision=DECISION_BLOCKED, reached_provider=False,
                     rules=("phi.ssn_pattern",))
    assert prevented.rules_removed == ("phi.ssn_pattern",)

    rendered = "\n".join(cli.turn_lines(prevented, provider_is_live=False))
    assert "kept back" in rendered
    assert "removed" not in rendered

    delivered = turn(decision=DECISION_REDACTED, reached_provider=True,
                     answered=True, reply="ok.", rules=("phi.ssn_pattern",))
    assert "removed" in "\n".join(cli.turn_lines(delivered, provider_is_live=False))


def test_reply_provenance_follows_is_live_and_not_the_providers_name():
    """The re-derivation hazard, in the place it would next be rebuilt.

    ``Scoreboard.provider_is_live`` was added after a hardcoded "the replies are
    fixtures" printed under a live run. Matching ``turn.provider == "mock"``
    here would reintroduce it, and a custom Provider -- which the engine accepts
    -- is called neither "mock" nor anything else this file knows.
    """
    answered = turn(decision=DECISION_ALLOWED, reached_provider=True,
                    answered=True, reply="an answer.", provider="mock")

    live = "\n".join(cli.turn_lines(answered, provider_is_live=True))
    assert "live model output" in live
    assert "fixture" not in live, (
        "a live reply was labelled a fixture because the provider is CALLED mock")

    mocked = "\n".join(cli.turn_lines(answered, provider_is_live=False))
    assert "mock fixture, not model output" in mocked


# ── 4 · a blocked prompt really does not reach the provider ──────────────────
def test_a_blocked_prompt_never_increments_the_provider_call_count():
    """Prevention as a MEASUREMENT taken outside the engine.

    The engine's own ``reached_provider`` is set by the wrapped callable; this
    counts from the other side, on the provider object itself, so a turn stamped
    blocked whose call happened could not pass both.
    """
    provider = Stub()
    session = Assistant(get_sector("healthcare"), provider=provider)

    code, text = drive(session, [BLOCKED_PROMPT, "/quit"])
    assert code == 0
    assert "[BLOCKED]" in text
    assert provider.calls == 0
    assert provider.prompts == []

    # And the counter does move when the guard lets something through, so the
    # assertion above is not simply of a provider that is never called.
    drive(Assistant(get_sector("healthcare"), provider=provider),
          [ASSIST_PROMPT, "/quit"])
    assert provider.calls == 1
    assert provider.prompts == [ASSIST_PROMPT]


@pytest.mark.parametrize("line", ["/help", "/policy", "/badcommand", "   ", "\t "])
def test_a_command_or_a_blank_line_is_never_sent_to_the_provider(line):
    """A mistyped command must not become a billable call -- or a ledger row.

    ``/probe`` is excluded deliberately: it is the one command that IS meant to
    reach the provider, and it says so before it does.
    """
    provider = Stub(live=True)
    code, text = drive(Assistant(get_sector("finance"), provider=provider),
                       [line, "/quit"])

    assert code == 0
    assert provider.calls == 0
    if line.strip().startswith("/badcommand"):
        # Whitespace-normalised: the message is wrapped to the shared width, so
        # the sentence is split across lines at whatever column it lands on.
        assert "Nothing was sent to the provider." in " ".join(text.split())


# ── 5 · the session survives what a session runs into ────────────────────────
def test_a_reply_the_console_cannot_encode_does_not_end_the_session():
    """A live model's em dash must not be the end of a demo.

    ``print`` raises ``UnicodeEncodeError`` from inside the write on a cp1252
    console, and the traceback points at the print rather than at the character
    -- so the failure reads as a bug in the REPL. Replacing the glyph loses a
    character; raising loses the session.
    """
    stream = Cp1252Stream()
    # BOTH characters on purpose. cp1252 encodes the em dash perfectly well --
    # it is 0x97 -- and only the snowman is unencodable, so a test written
    # around the dash alone would pass against a REPL with no fallback at all.
    provider = Stub(reply="Here — the answer ☃ you asked for.", live=True)

    code, _ = drive(Assistant(get_sector("legal"), provider=provider),
                    [ASSIST_PROMPT, "/quit"], out=stream)

    assert code == 0
    text = stream.getvalue()
    assert "bye." in text, "the session did not survive the reply"
    assert "☃" not in text and "Here — the answer ? you asked for." in text, (
        "only the unencodable character should have been degraded")

    # The stream really would have refused it, so this is not passing on a
    # stream that accepts everything.
    with pytest.raises(UnicodeEncodeError):
        stream.write("☃")


def test_ctrl_c_cancels_the_line_and_ctrl_d_ends_the_session():
    """Every REPL behaves this way, and getting it backwards is the annoying
    kind of wrong: Ctrl-C mid-thought must not throw away the session.
    """
    provider = Stub()
    lines = iter(["ignored"])

    def read_line():
        try:
            next(lines)
        except StopIteration:
            raise EOFError from None
        raise KeyboardInterrupt

    out = io.StringIO()
    assert cli.repl(Assistant(get_sector("legal"), provider=provider),
                    read_line=read_line, out=out, banner=False) == 0
    assert provider.calls == 0
    assert out.getvalue().rstrip().endswith("bye.")


def test_ctrl_c_during_probe_abandons_the_command_and_not_the_session():
    """The longest-running command was the one place with no interrupt guard.

    ``read_line`` and ``ask`` were both protected; ``/probe`` was not, and
    ``Assistant.ask`` catches ``Exception`` while ``KeyboardInterrupt`` is a
    ``BaseException`` -- so a Ctrl-C partway through nine to eleven provider
    calls escaped every handler and ended the session. On a live key each of
    those calls can sit on a 30-second timeout, which makes it the command a
    user is most likely to abandon.
    """
    class Impatient(Stub):
        def complete(self, system, prompt):
            self.calls += 1
            if self.calls == 2:
                raise KeyboardInterrupt
            return "ok."

    provider = Impatient(live=True)
    code, text = drive(Assistant(get_sector("legal"), provider=provider),
                       ["/probe", ASSIST_PROMPT, "/quit"])

    assert code == 0, "the interrupt took the whole session with it"
    flat = " ".join(text.split())
    assert "The scoreboard is abandoned" in flat
    # No half-scored board: a corpus scored halfway is not a score.
    assert "enforcement" not in text
    # And the session really did keep going -- the prompt after it was answered.
    assert "[ALLOWED]" in text

    # ⚠ AND IT DISCLOSES WHAT THE INTERRUPT DID NOT UNDO. Saying only that the
    # command stopped reads as though nothing happened; two probes had already
    # been sent, billed on a live key, and written through the SDK -- whose
    # wrapper catches BaseException and records an event_type="exception" row
    # before re-raising, so the abort is on the record too. The single-turn
    # handler discloses the same class of thing, and this command makes nine to
    # eleven calls.
    assert provider.calls == 3, (
        "two probes were sent before the abort -- the second one raised -- plus "
        "the turn typed after it; the disclosure is about those first two")
    assert "WHAT ALREADY RAN IS NOT UNDONE" in flat
    assert "it was billed" in flat
    assert "recorded too, as an exception event" in flat


def test_a_provider_that_fails_is_reported_and_the_session_continues():
    """A provider fault is not evidence about the guard, and not fatal here.

    The probe runner exits 1 on an error because it is a gate. A REPL is a
    person reading verdicts; the turn is labelled and the next prompt is taken.
    """
    class Broken(Stub):
        def complete(self, system, prompt):
            raise RuntimeError("upstream is down")

    provider = Broken(live=True)
    code, text = drive(Assistant(get_sector("legal"), provider=provider),
                       [ASSIST_PROMPT, ASSIST_PROMPT, "/quit"])

    assert code == 0, "a provider error must not fail an interactive session"
    assert text.count("[ERROR]") == 2
    assert "RuntimeError: upstream is down" in text
    assert "says nothing about what the guard would have done" in text


# ── 6 · /probe and /mode ──────────────────────────────────────────────────────
def test_probe_runs_through_the_sessions_own_assistant():
    """The shape ``AssistantConflict`` exists to protect.

    ``run_probes`` refuses a configuration passed beside a prebuilt assistant,
    because the report would then describe one run while printing another's
    verdicts. The REPL passes the assistant ALONE -- and the proof is that the
    board reports the mode the session was switched to, not the one it started
    in and not the engine default.
    """
    code, text = drive(Assistant(get_sector("healthcare"), mode="observe"),
                       ["/probe", "/quit"])

    assert code == 0
    assert "mode=observe" in text
    assert "mode=block" not in text
    # observe prevents nothing, and the board says so rather than reading as a
    # broken guard. That sentence appearing here proves the board was rendered
    # under the session's mode.
    assert "mode=observe records but never prevents" in text


def test_probe_warns_before_spending_a_live_providers_budget():
    provider = Stub(live=True)
    _, live_text = drive(Assistant(get_sector("legal"), provider=provider),
                         ["/probe", "/quit"])
    assert "against a LIVE provider, under your key" in live_text
    assert str(len(get_sector("legal").probes)) in live_text

    _, mock_text = drive(Assistant(get_sector("legal")), ["/probe", "/quit"])
    assert "LIVE provider" not in mock_text


def test_switching_mode_keeps_the_provider_and_the_sector():
    """``/mode`` rebuilds the assistant, because the guard decorator is built in
    ``__init__`` and the mode cannot be reassigned. Everything else must survive
    -- rebuilding the provider would re-read a live key and rebuild the mock's
    fixture map under the user.
    """
    provider = Stub()
    session = cli.Session(Assistant(get_sector("finance"), mode="block",
                                    provider=provider))
    before = session.assistant

    session.switch_mode("redact")

    assert session.assistant is not before
    assert session.assistant.mode == "redact"
    assert session.assistant.provider is provider, "the provider was rebuilt"
    assert session.assistant.sector == get_sector("finance")


def test_switching_mode_carries_the_whole_session_not_only_the_provider():
    """⚠ ``/mode`` USED TO CHANGE WHICH LEDGER THE SESSION WROTE TO.

    ``switch_mode`` rebuilt the Assistant from sector/mode/provider, so a
    caller-supplied ``client`` -- a KEYED one, writing to their org's chain and
    firing desktop pings -- was replaced by a fresh keyless ``FoxyClient``. The
    session went on printing verdicts and silently stopped recording any of
    them, under a message saying the sector, the policy tag and the provider
    were unchanged.
    """
    class SpyClient:
        def __init__(self):
            self.audits = 0

        def audit(self, **kwargs):
            self.audits += 1
            return lambda fn: fn

    spy = SpyClient()
    session = cli.Session(Assistant(get_sector("legal"), mode="block",
                                    client=spy, desktop_ping=True))
    assert session.assistant._client is spy

    session.switch_mode("redact")

    assert session.assistant._client is spy, (
        "the caller's client was dropped: this session has changed ledgers")
    assert spy.audits == 2, "the new assistant was decorated by the SAME client"
    assert session.assistant.mode == "redact"


def test_with_mode_carries_every_constructor_argument_that_can_matter():
    """The completeness claim, checked against the constructor rather than
    trusted.

    ``with_mode`` passes sector, mode, provider and client, and argues that the
    remaining four (``api_key``, ``model``, ``desktop_ping``, ``foxy_api_key``)
    are unreachable because each feeds only something already being handed over
    built. That argument is true of TODAY's signature and says nothing about
    tomorrow's -- so a ninth parameter fails here, naming the decision to make,
    rather than being dropped in silence the way ``client`` was.

    ⚠ T4 ADDED ``foxy_api_key`` AND THIS WENT RED, WHICH IS THE POINT. The
    decision it forced: the Foxy key feeds the ``FoxyClient`` constructor only,
    and ``with_mode`` hands the client over already built, so the key survives a
    mode switch without being listed. The list is widened only after answering
    that -- and the SECOND assertion below is what T4 owed on top of it, because
    a parameter can be carried and still be broken.
    """
    import inspect

    parameters = list(inspect.signature(Assistant.__init__).parameters)
    assert parameters == ["self", "sector", "mode", "provider", "api_key",
                          "model", "client", "desktop_ping",
                          "foxy_api_key"], (
        "Assistant.__init__ changed. Decide whether with_mode must carry the "
        "new parameter across, then update this list. Do not just widen it: "
        "dropping `client` here is what made /mode change ledgers.")


def test_a_mode_switch_does_not_stop_turns_naming_their_row():
    """The half a signature check cannot see.

    The receipt hook is bound to an INSTANCE (`self._receipt`), and `with_mode`
    hands the shared client to a NEW Assistant. Without a rebind the hook keeps
    pointing at the discarded one, every later turn appends to a list nobody
    reads, and `event_id` comes back empty -- so `/verify` would report "cannot
    be traced from here" for turns that traced perfectly well before the switch.
    Nothing in the signature list above would have noticed.
    """
    first = Assistant(get_sector("healthcare"), mode="block", provider=Stub())
    before = first.ask("What is a deductible?")
    assert before.event_id

    second = first.with_mode("observe")
    after = second.ask("What is a deductible?")
    assert after.event_id, "the receipt hook was left on the discarded assistant"
    assert after.event_id != before.event_id


def test_an_unknown_mode_leaves_the_session_running_and_unchanged():
    """The engine refuses it loudly; the REPL reports the refusal and carries on.

    ``Assistant`` raising rather than falling back to observe is a deliberate
    T0 decision -- a silent demotion turns a demo of prevention into a demo of
    nothing. A REPL that swallowed the exception would undo it.
    """
    provider = Stub()
    # healthcare, because BLOCKED_PROMPT is an SSN and only `hipaa` adds the PHI
    # family -- under `default` it is correctly allowed through, which would
    # make this guard pass for a reason that has nothing to do with the mode.
    session = Assistant(get_sector("healthcare"), mode="block", provider=provider)
    code, text = drive(session, ["/mode blcok", BLOCKED_PROMPT, "/quit"])

    assert code == 0
    assert "unknown mode" in text
    # Still enforcing under the mode it started in.
    assert "[BLOCKED]" in text
    assert provider.calls == 0


def test_mode_with_no_argument_reports_the_current_one():
    _, text = drive(Assistant(get_sector("legal"), mode="redact"), ["/mode", "/quit"])
    assert "mode is redact" in text


# ── 7 · everything this module prints is 7-bit ───────────────────────────────
def test_the_repls_own_output_is_ascii():
    """Same rule as the scoreboard, and for the same measured reason: a Windows
    console is cp1252 and a captured CI stream frequently is too. The reply is
    not this module's string and is exempt -- see the encode fallback.
    """
    session = Assistant(get_sector("healthcare"))
    owned = cli.banner_lines(session) + cli.help_lines()
    for decision in DECISIONS:
        owned += cli.turn_lines(turn(decision=decision, reached_provider=True,
                                     rules=("phi.ssn_pattern",),
                                     rules_delivered=("phi.ssn_pattern",)),
                                provider_is_live=False)

    for line in owned:
        line.encode("ascii")            # raises on the first non-ASCII byte


def test_no_rendered_line_runs_past_the_scoreboards_width():
    """The two surfaces print into the same terminal, one under the other --
    ``/probe`` renders a board directly beneath a turn. A REPL wrapping at a
    different width makes them read as two programs.
    """
    from foxy_testbed.scoreboard import WIDTH

    session = Assistant(get_sector("finance"))
    lines = cli.banner_lines(session) + cli.help_lines() + cli.turn_lines(
        turn(decision=DECISION_ALLOWED, reached_provider=True, answered=True,
             reply="A paragraph long enough to need wrapping. " * 6),
        provider_is_live=False)

    overlong = [line for line in lines if len(line) > WIDTH]
    assert overlong == [], overlong


# ── 8 · the command line ──────────────────────────────────────────────────────
def test_no_probe_flag_now_starts_the_repl(monkeypatch, capsys):
    """T0 printed "the interactive REPL is not built yet" here and exited 2.

    Driven through ``main`` with a real stdin so the default reader is the thing
    under test, not the injected one every other guard uses.
    """
    from foxy_testbed.__main__ import main

    monkeypatch.setattr("sys.stdin", io.StringIO("/policy\n/quit\n"))
    assert main(["--sector", "finance"]) == 0

    text = capsys.readouterr().out
    assert "not built yet" not in text
    # Off a terminal the reader echoes, so a piped session reads as a transcript
    # rather than as a list of unanswered prompts.
    assert "{0}/policy".format(cli.PROMPT) in text
    assert "cardholder data and bank account numbers are NOT blocked here" in " ".join(
        text.split())


class FakeStream(io.StringIO):
    """A stream that can lie about being a terminal, in either direction."""

    def __init__(self, tty=False, data="") -> None:
        super().__init__(data)
        self._tty = tty

    def isatty(self) -> bool:
        return self._tty


TYPED = "hello there"

#: EVERY COMBINATION OF THE THREE THINGS THAT MATTER, because two rounds of
#: single-case fixes each got the case they were named after right and its
#: sibling wrong. The axes are independent and the code must treat them so:
#:
#:   stdin_tty     -- does the TERMINAL echo what is typed?
#:   out_is_stdout -- does ``input()``'s prompt land in ``out``?
#:   out_tty       -- is ``out`` the terminal that would be doing the echoing?
#:
#: The expectations are hand-written per row, not derived: a table whose
#: expected values are computed from the same booleans the implementation reads
#: proves only that two copies of one expression agree.
#:
#: (label, stdin_tty, out_is_stdout, out_tty, prompt passed to input(), out)
READER_TABLE = [
    ("terminal, stdout IS the terminal",
     True, True, True, cli.PROMPT, ""),
    ("terminal, stdout redirected to a file (`> transcript.txt`)",
     True, True, False, "", cli.PROMPT + TYPED + "\n"),
    ("terminal, out= another tty (`out=sys.stderr`)",
     True, False, True, "", cli.PROMPT),
    ("terminal, out= a caller's file",
     True, False, False, "", cli.PROMPT + TYPED + "\n"),
    ("piped stdin, stdout is a terminal",
     False, True, True, None, cli.PROMPT + TYPED + "\n"),
    ("piped stdin, stdout redirected (the CI path)",
     False, True, False, None, cli.PROMPT + TYPED + "\n"),
    ("piped stdin, out= another tty",
     False, False, True, None, cli.PROMPT + TYPED + "\n"),
    ("piped stdin, out= a caller's file",
     False, False, False, None, cli.PROMPT + TYPED + "\n"),
]


@pytest.mark.parametrize(
    "label,stdin_tty,out_is_stdout,out_tty,expect_prompt,expect_out",
    READER_TABLE, ids=[row[0] for row in READER_TABLE])
def test_the_reader_produces_one_prompt_and_one_line_in_every_combination(
        monkeypatch, label, stdin_tty, out_is_stdout, out_tty, expect_prompt,
        expect_out):
    """⚠ THE TWO SHAPES THAT SHIPPED BROKEN ARE ROWS 2 AND 3.

    Row 2: ``out is sys.stdout`` was read as "the terminal is handling this",
    but under ``> transcript.txt`` stdout is a FILE -- so ``input(PROMPT)`` put
    the prompt in the file and the terminal echoed the typed line to the
    screen, and the transcript was a column of prompts with nothing after them.

    Row 3: the same test read ``out=sys.stderr`` as "nothing echoes", but
    stderr IS the terminal, which echoes -- so every typed line printed twice.

    One flag cannot answer both questions, and each previous fix was a third
    single case. This is all eight.
    """
    typed = []

    def fake_input(prompt=""):
        typed.append(prompt)
        return TYPED

    stdin = FakeStream(tty=stdin_tty, data="" if stdin_tty else TYPED + "\n")
    out = FakeStream(tty=out_tty)
    monkeypatch.setattr("sys.stdin", stdin)
    monkeypatch.setattr("sys.stdout", out if out_is_stdout else FakeStream(tty=True))
    monkeypatch.setattr("builtins.input", fake_input)

    assert cli._default_reader(out)() == TYPED
    assert out.getvalue() == expect_out, label
    assert typed == ([] if expect_prompt is None else [expect_prompt]), label

    # THE PROPERTY THE TABLE IS AN INSTANCE OF, checked from the row's declared
    # inputs: counting what the terminal itself puts on the screen, the user
    # sees the prompt exactly once and their own line exactly once. Neither
    # zero (a transcript that lost them) nor twice (a doubled line).
    terminal_echoes_the_line = stdin_tty and out_tty
    assert out.getvalue().count(cli.PROMPT) + int(expect_prompt == cli.PROMPT) == 1
    assert out.getvalue().count(TYPED) + int(terminal_echoes_the_line) == 1


def test_a_session_that_cannot_start_still_exits_2(monkeypatch, capsys):
    """The one failure both paths share. A REPL that opened a session against a
    provider it has no key for would fail on the first prompt instead of on the
    command line.
    """
    from foxy_testbed.__main__ import main

    monkeypatch.delenv("OPENAI_API_KEY", raising=False)
    monkeypatch.setattr("sys.stdin", io.StringIO(""))

    assert main(["--sector", "healthcare", "--provider", "openai"]) == 2
    assert "Could not start" in capsys.readouterr().err


def test_the_repl_path_reads_the_key_from_the_environment(monkeypatch):
    """The env fallback moved above the branch, so both paths honour it.

    One flag meaning two things -- ``--provider openai`` picking up
    ``OPENAI_API_KEY`` under ``--probe`` and ignoring it without -- is the kind
    of difference nobody finds until it is a support ticket.
    """
    from foxy_testbed.__main__ import main

    # Deliberately NOT key-shaped. `OpenAIProvider` only asks whether the key is
    # non-empty, so nothing here needs a string that looks like a credential --
    # and a repo whose secret scanner has already had to be taught about two
    # test fixtures does not need a third one minted for no reason.
    monkeypatch.setenv("OPENAI_API_KEY", "not-a-key")
    monkeypatch.setattr("sys.stdin", io.StringIO("/quit\n"))

    # It starts, which it could not do without a key, and it is never used:
    # /quit sends nothing.
    assert main(["--sector", "healthcare", "--provider", "openai"]) == 0
