"""``python -m foxy_testbed --sector healthcare`` — the interactive REPL.

The first of the three surfaces. You type a prompt, the real ``foxy_audit``
preflight guard sees it, and whatever happened comes back as one rendered
:class:`~foxy_testbed.core.Turn` — the same record the scoreboard scores and the
same one T2's page and T3's console tab will render.

THIS MODULE HOLDS NO POLICY LOGIC, AND CANNOT
=============================================
It does not import ``foxy_audit``. Not "does not use" — cannot: there is no name
from that package in this file, and ``test_cli.py`` walks the AST to keep it that
way. Every sentence printed below is read off a field or a property of the
``Turn`` the engine handed back. Where the engine measured something (was it
prevented, which findings survived), this file renders the measurement; where it
did not, this file says nothing rather than inferring.

That matters more here than it sounds. Three front-ends each deciding for
themselves what "blocked" means is exactly how the prevention-vs-evidence
conflation got rebuilt once already, which is why ``Turn.as_dict`` carries
``prevented`` and ``prompt_enforced`` instead of leaving each surface to
re-derive them from ``decision``.

THE LABEL AND THE OBSERVATION ARE RENDERED SEPARATELY
====================================================
:func:`_headline` reads a measured property wherever one exists, and where a
label and an observation can disagree it prints the disagreement rather than
picking a winner. A turn stamped ``blocked`` whose call reached the provider
anyway does not print "BLOCKED"; it prints that both things happened. That case
should be unreachable — and a surface that renders it as a clean block is how it
would stay unreachable-looking while being reached.

ASCII ONLY, FOR THE SAME REASON THE SCOREBOARD IS
=================================================
Every string this module owns is 7-bit; a Windows console is cp1252 and so is a
captured CI stream. What this module does NOT own is the reply, which on a live
provider is arbitrary text — so :func:`_write` degrades an unencodable character
instead of letting a ``UnicodeEncodeError`` end the session. A REPL that dies on
an em dash in a model's answer is a REPL that dies in front of a prospect.

WHERE THE TEXT GOES
===================
Nowhere near Foxy. This module binds nothing to a socket and is not a server;
the banner says so, and with the default mock provider it is literally true that
nothing leaves the process. Under a live provider the prompt goes to the model
the user chose, under the user's own key, from the user's own machine — the same
thing an SDK customer's own code does.
"""

from __future__ import annotations

import sys

from .core import (Assistant, DECISION_ALLOWED, DECISION_BLOCKED,
                   DECISION_BLOCKED_RESPONSE, DECISION_ERROR, DECISION_FLAGGED,
                   DECISION_REDACTED, MODES)
# Private, and deliberately: they are this package's own wrapping discipline,
# and importing them is what keeps the REPL and the scoreboard from wrapping the
# same policy_note to two different widths in the same session -- `/probe`
# prints one directly under the other.
from .scoreboard import _field, _rule, _wrap, run_probes

#: What the user sees before their own text. ASCII, short, and not a unicode
#: arrow: this is printed on the same cp1252 console as everything else.
PROMPT = "you> "

#: Anything starting with this is a command and is NEVER sent to a provider.
#: A mistyped command must not become a billable call, and must not become a
#: prompt in an audit ledger either.
COMMAND_PREFIX = "/"

#: Returned by :func:`_handle_command` when the session should end.
_QUIT = object()


# ── output ────────────────────────────────────────────────────────────────────
def _write(out, text: str = "") -> None:
    """One line to ``out``, surviving text this module did not write.

    The fallback is not defensive padding. ``sys.stdout`` on a Windows console
    is cp1252; a live model's reply routinely contains an em dash or a curly
    quote; and ``print`` on an unencodable character raises
    ``UnicodeEncodeError`` from inside the write, killing the session with a
    traceback that points at the print rather than at the character. Replacing
    the character loses a glyph. Raising loses the session.
    """
    try:
        out.write(text + "\n")
    except UnicodeEncodeError:
        encoding = getattr(out, "encoding", None) or "ascii"
        out.write(text.encode(encoding, "replace").decode(encoding, "replace") + "\n")


def _write_all(out, lines) -> None:
    for line in lines:
        _write(out, line)


def _default_reader(out):
    """A line of input, and a readable transcript either way.

    ⚠ THIS IS TWO INDEPENDENT QUESTIONS AND EVERY EARLIER VERSION ASKED ONE.
    Collapsing them is what made each fix correct for the case it was named
    after and wrong for that case's sibling, twice:

      Q1  Does the PROMPT already reach ``out``?  Only when ``input()`` writes
          it there -- ``input`` prints to ``sys.stdout`` and nowhere else.
      Q2  Does the TYPED LINE already reach ``out``?  Only when the terminal
          echoes it there, which needs stdin to BE a terminal and ``out`` to be
          that same terminal.

    They come apart in both directions, and both were shipped broken:

      * ``python -m foxy_testbed > transcript.txt`` from a terminal. ``out`` IS
        ``sys.stdout``, so an identity test says "the terminal handles it" --
        but stdout is a FILE. ``input(PROMPT)`` wrote the prompt into the file
        and the terminal echoed the typed line to the screen, so the transcript
        was a column of ``you> `` with nothing after them.
      * ``repl(out=sys.stderr)`` on a terminal. ``out`` is not ``sys.stdout``,
        so the same test says "nothing echoes" -- but stderr IS the terminal,
        which echoes the typed line, and writing it again printed every line
        twice.

    So ``out is sys.stdout`` answers Q1 and ``isatty`` answers Q2, and neither
    answers the other. ``input()`` is still used wherever stdin is a terminal,
    because that is what gives the platform's line editing (and GNU readline
    where it exists); it is simply called bare when the prompt has already been
    written somewhere else.
    """
    def _isatty(stream) -> bool:
        # A detached or replaced stream (pythonw, some CI runners, a StringIO)
        # may have no isatty at all. "Not a terminal" is the safe answer: it
        # makes this echo, and a duplicated line is a worse transcript while a
        # missing one is a broken record.
        try:
            return bool(stream.isatty())
        except Exception:                             # noqa: BLE001
            return False

    is_tty = _isatty(sys.stdin)
    prompt_via_input = is_tty and out is sys.stdout and _isatty(out)   # Q1
    echo_the_line = not (is_tty and _isatty(out))                      # Q2

    def read_line() -> str:
        if prompt_via_input:
            line = input(PROMPT)
        else:
            out.write(PROMPT)
            out.flush()
            if is_tty:
                line = input()
            else:
                line = sys.stdin.readline()
                if line == "":
                    raise EOFError
                line = line.rstrip("\n").rstrip("\r")
        if echo_the_line:
            _write(out, line)
        return line

    return read_line


# ── rendering one turn ────────────────────────────────────────────────────────
def _headline(turn):
    """The word a reader takes away, and the sentence under it.

    ⚠ EVERY BRANCH THAT CAN BE MEASURED IS MEASURED. ``decision`` selects the
    family; a property decides what is claimed inside it. The two redact
    branches and the two block branches exist for that reason alone, and the
    final fallback exists so that adding a value to ``core.DECISIONS`` cannot
    make it render as something it is not -- an unrecognised decision printing
    "ALLOWED" is the worst available failure in an audit demo.
    """
    if turn.decision == DECISION_ERROR:
        return ("ERROR",
                "the provider call failed. This turn is evidence about the "
                "provider and about nothing else -- it says nothing about what "
                "the guard would have done.")
    if turn.decision == DECISION_BLOCKED:
        if turn.prevented:
            return ("BLOCKED",
                    "the prompt never left this machine. The provider was not "
                    "called, so there was no reply to withhold.")
        # Unreachable as the SDK stands, and printed in full if it ever is not.
        return ("BLOCKED, BUT THE CALL WAS MADE",
                "the SDK stamped this prompt blocked AND the provider was "
                "reached anyway. The label and the observation disagree; the "
                "observation is that your text was delivered. Report this.")
    if turn.decision == DECISION_BLOCKED_RESPONSE:
        if turn.response_withheld:
            return ("RESPONSE WITHHELD",
                    "the prompt DID reach the provider and tokens were spent; "
                    "it is the reply that was withheld from you. Real "
                    "prevention of what you would have received, not of what "
                    "the model saw.")
        # THE BRANCH THAT WAS MISSING, and it was the only decision family here
        # without one. `response_withheld` pairs the label with
        # `reached_provider` precisely because this outcome ASSERTS the call
        # happened -- and reading the label alone printed "the prompt DID reach
        # the provider and tokens were spent" three lines above "reached: no,
        # the provider was never called", in the renderer whose whole argument
        # is that a label never outranks an observation.
        return ("RESPONSE WITHHELD, BUT NOTHING WAS SENT",
                "the SDK stamped this turn as a withheld RESPONSE, which means "
                "a reply came back and was kept from you -- and the provider "
                "was never called, so there was no reply to withhold. The "
                "label and the observation disagree and neither explains this "
                "turn. Report this.")
    if turn.decision == DECISION_REDACTED:
        if turn.prompt_enforced:
            return ("REDACTED",
                    "every finding that fired was gone from the text the "
                    "provider actually received.")
        return ("REDACTED, INCOMPLETELY",
                "the SDK stamped this prompt redacted, but re-running the "
                "policy against the text actually delivered shows a finding "
                "still firing. Scored as NOT enforced, on the measurement "
                "rather than on the label.")
    if turn.decision == DECISION_FLAGGED:
        return ("FLAGGED, NOT PREVENTED",
                "mode=observe records and never prevents, so this prompt was "
                "delivered exactly as you typed it. Run with --mode block or "
                "--mode redact to prevent.")
    if turn.decision == DECISION_ALLOWED:
        return ("ALLOWED",
                "nothing fired. The prompt was delivered as typed.")
    return (str(turn.decision).upper(),
            "this decision has no rendering in the REPL yet. It is printed "
            "verbatim rather than guessed at -- see foxy_testbed.core.DECISIONS.")


def _reply_lines(text, indent: int = 6) -> list:
    """The reply, paragraph by paragraph.

    ``_wrap`` normalises whitespace inside what it is given, which is right for
    a sentence and wrong for an answer: the fixtures and real model replies both
    separate paragraphs with a blank line, and handing the whole thing over at
    once would run four paragraphs into one block. So the split happens here and
    ``_wrap`` still owns the wrapping.
    """
    lines = []
    for paragraph in str(text).split("\n\n"):
        if not paragraph.strip():
            continue
        if lines:
            lines.append("")
        lines += _wrap(paragraph, indent)
    return lines


def turn_lines(turn, provider_is_live: bool) -> list:
    """One turn, rendered. The whole of what a surface has to do.

    ⚠ ``provider_is_live`` IS A SECOND ARGUMENT BECAUSE THE TURN DOES NOT CARRY
    IT, and it is not derived from ``turn.provider`` here. Matching the provider
    NAME against ``"mock"`` is precisely the re-derivation that
    ``Scoreboard.provider_is_live`` exists to stop -- it was added after a
    hardcoded "the replies are fixtures" printed under a live run -- and a
    custom ``Provider`` subclass, which the engine accepts, has neither name.
    The session holds the provider and therefore holds the answer; it passes it.
    Reported upward as an engine gap: see the T1 findings.
    """
    label, sentence = _headline(turn)
    lines = ["", _rule(), "  [{0}]".format(label)]
    lines += _wrap(sentence, 2)
    lines.append("")

    lines += _field("rules", ", ".join(turn.rules) if turn.rules else "(none fired)")
    lines += _field("reason", turn.blocked_reason)
    # Spelled out rather than "yes"/"no". This is the single most consequential
    # fact on the screen and the label above it is four characters long; a bare
    # "no" beside "reached" is exactly the line a reader skims past.
    lines += _field("reached", "yes, the provider was called with this prompt"
                    if turn.reached_provider
                    else "no, the provider was never called")

    # ⚠ THE PER-FINDING LISTS, AND ONLY WHERE THEY CLAIM SOMETHING. Both are
    # empty on a clean turn, and an empty "removed:" line under a prompt that
    # never had a finding in it reads as a guard that did work it did not do.
    if turn.rules_removed:
        # TWO WORDS FOR ONE PROPERTY, because the property spans two events.
        # `rules_removed` is "findings that did not reach the model", and on a
        # PREVENTED turn that is true because nothing was sent at all -- calling
        # that "removed" describes a rewrite of a prompt that was never
        # delivered, which is the same kind of statement-about-a-delivery-that-
        # did-not-happen `redaction_ineffective` is paired against.
        lines += _field("kept back" if turn.prevented else "removed",
                        ", ".join(turn.rules_removed))
    if turn.rules_surviving:
        # The loudest line the REPL prints, because it is the one a reader
        # would otherwise never suspect: the SDK's own label says this prompt
        # was handled, and these findings were handed to the model anyway.
        #
        # ⚠ TRIPWIRE ON A `redacted` TURN, AND NOT DEAD CODE. Since SDK 1.9.0
        # the guard re-evaluates the redacted prompt and BLOCKS when any finding
        # still fires (SDK #216), so a redacted turn reaching this line means
        # that fix regressed. Keep it: it costs nothing, it is the only thing
        # that would SAY so, and on a PREVENTED turn `rules_surviving` is empty
        # so this line does not print at all.
        lines += _field("STILL SENT", ", ".join(turn.rules_surviving))
    if turn.redaction_ineffective and not turn.prompt_changed:
        # The narrower half of the same tripwire — see Turn.redaction_ineffective.
        lines += _wrap("Nothing was rewritten at all: the text delivered to the "
                       "provider is byte-identical to the text you typed.", 4)
    if turn.redaction_ineffective:
        lines += _wrap("NOTE: SDK >= 1.9.0 is supposed to BLOCK this turn (SDK "
                       "#216), so this means either an SDK older than 1.9.0 or "
                       "a regression of that fix.", 4)
    lines += _field("ruleset", turn.ruleset_version or "(not reported)")
    if turn.error:
        # ProviderError carries a type and a status by construction and never a
        # response body, so nothing typed here can ride back out through it.
        lines += _field("error", turn.error)

    lines.append("")
    if turn.answered:
        # The provenance rides on every reply, not only on the banner. The
        # banner scrolls away; a session is long; and "is this thing making up
        # answers?" is the question a prospect asks on turn nine, not turn one.
        lines += _wrap("reply ({0}):".format(
            "live model output" if provider_is_live else "mock fixture, not model output"), 2)
        lines += _reply_lines(turn.reply)
    elif turn.empty_reply:
        lines += _wrap("The provider returned an empty reply, so there is nothing "
                       "to show. What the guard did to your prompt is unaffected "
                       "and is reported above.", 2)
    # ⚠ NOT ONE DECISION READ IN THIS BLOCK, AND IT USED TO END ON ONE. The
    # final branch said "the prompt was stopped before the provider was called"
    # for everything that was not answered, not empty and not an error -- which
    # includes a withheld RESPONSE, where the prompt reached the model and the
    # tokens were spent. The same defect as the headline above it, one function
    # further down, and `reached_provider` was sitting right there.
    elif turn.error:
        lines += _wrap("No reply: the provider call failed.", 2)
    elif turn.reached_provider:
        lines += _wrap("No reply: the prompt reached the provider, and nothing "
                       "came back to you.", 2)
    else:
        lines += _wrap("No reply: the prompt was stopped before the provider was "
                       "called.", 2)
    lines.append(_rule())
    return lines


# ── the session ───────────────────────────────────────────────────────────────
def _provenance(provider) -> str:
    """Where the text goes, in the only two shapes this can take."""
    if provider.is_live:
        return ("WHERE YOUR TEXT GOES: the guard runs here, in this process. A "
                "prompt it lets through goes to {0} under YOUR key, from this "
                "machine, and nowhere else. Foxy holds no key here and is on "
                "the other end of no socket -- this program is not a client of "
                "any server we run.".format(provider.name))
    return ("WHERE YOUR TEXT GOES: nowhere. The mock provider makes no network "
            "call at all, so nothing you type leaves this process. The guard "
            "in front of it is the real one either way, which is the half that "
            "the demo is actually about.")


def banner_lines(assistant) -> list:
    sector, provider = assistant.sector, assistant.provider
    lines = [_rule("="),
             "  Foxy Audit -- compliance testbed (interactive)",
             _rule("=")]
    lines += _field("sector", "{0} -- {1}".format(sector.name, sector.title))
    lines += _field("policy", "policy_tag={0}, mode={1}".format(
        sector.policy_tag, assistant.mode))
    lines += _field("provider", "{0} ({1})".format(provider.name, provider.model))
    if provider.note:
        lines += _field("note", provider.note)
    lines.append("")
    lines += _wrap("WHAT THIS PRESET ENFORCES, AND WHAT IT DOES NOT", 2)
    lines += _wrap(sector.policy_note, 4)
    lines.append("")
    lines += _wrap(_provenance(provider), 2)
    lines.append("")
    lines += _wrap("Type a prompt and press enter. /help lists the commands; "
                   "/quit or Ctrl-D leaves.", 2)
    lines.append(_rule("="))
    return lines


def help_lines() -> list:
    lines = ["", "  commands"]
    for name, what in (
        ("/help", "this list"),
        ("/policy", "what this preset enforces, and what it does not"),
        ("/probe", "run this sector's probe corpus and print the scoreboard"),
        # The modes are interpolated rather than spelled out: `core.MODES` is
        # the list, and a second copy of it in help text is a second copy to go
        # stale. The NAME is padded to fit `_wrap`'s hanging indent, which is
        # why it is "<mode>" here and the values live in the description.
        ("/mode <mode>", "switch the preflight mode ({0})".format(", ".join(MODES))),
        ("/quit", "leave (Ctrl-D does the same)"),
    ):
        lines += _wrap(what, 20, first="    " + name)
    lines.append("")
    lines += _wrap("Anything not starting with {0!r} is sent to the guard as a "
                   "prompt.".format(COMMAND_PREFIX), 2)
    return lines


class Session:
    """One assistant, held for the length of the session.

    ONE ASSISTANT, NOT ONE PER TURN. Rebuilding per turn would re-resolve the
    SDK config and rebuild the provider on every line typed, and would make the
    mock's fixture map -- which is built from the sector's own corpus -- a thing
    that gets reconstructed under the user rather than a fixed part of the run.

    ``/mode`` is the one thing that replaces it, and has to: the guard decorator
    is built in ``Assistant.__init__``, so the mode is fixed at construction and
    cannot be reassigned afterwards. What survives that rebuild is
    ``Assistant.with_mode``'s problem and not this class's -- see below.
    """

    def __init__(self, assistant) -> None:
        self.assistant = assistant

    def switch_mode(self, mode: str) -> None:
        """Rebuild the assistant under ``mode``. Raises ValueError on a typo.

        ⚠ DELEGATED, AND THAT IS THE FIX. This method used to call the
        ``Assistant`` constructor itself with sector/mode/provider, which
        silently dropped a caller-supplied ``client`` and ``desktop_ping``: a
        KEYED session stopped writing to the caller's ledger and stopped firing
        desktop pings the moment somebody typed ``/mode``, while this same
        command printed that the session was otherwise unchanged. A surface
        cannot be trusted to know what an Assistant is made of, so it no longer
        has to -- ``with_mode`` carries the state and the guard that keeps it
        complete lives beside the constructor it mirrors.

        The ValueError is the engine's too, not a second validation written
        here: ``Assistant.__init__`` refuses an unknown mode loudly rather than
        falling back to observe, and a REPL that re-listed the valid modes would
        be a second place for that list to go stale.
        """
        self.assistant = self.assistant.with_mode(mode)


def _handle_command(session, text: str, out):
    """One ``/command``. Returns :data:`_QUIT` to end the session, else None."""
    parts = text[len(COMMAND_PREFIX):].split()
    name = parts[0].lower() if parts else ""
    argument = parts[1] if len(parts) > 1 else ""

    if name in ("quit", "exit", "q"):
        return _QUIT

    if name in ("help", "h"):
        _write_all(out, help_lines())
    elif name == "policy":
        sector = session.assistant.sector
        _write(out, "")
        _write_all(out, _wrap("WHAT THIS PRESET ENFORCES, AND WHAT IT DOES NOT", 2))
        _write_all(out, _wrap(sector.policy_note, 4))
    elif name == "probe":
        assistant = session.assistant
        if assistant.provider.is_live:
            _write_all(out, _wrap(
                "{0} probe(s), against a LIVE provider, under your key. Every "
                "one the guard does not stop is a billable call.".format(
                    len(assistant.sector.probes)), 2))
        # ⚠ THE ASSISTANT ALONE, AND NOT ONE FLAG BESIDE IT. `run_probes` takes
        # a configuration OR a prebuilt assistant, and passing both raises --
        # deliberately, because the two can disagree and the report would then
        # describe one run while printing another's verdicts. This session's
        # assistant is the authority on its own sector, mode and provider, so
        # there is nothing left to pass.
        _write(out, run_probes(None, assistant=assistant).render())
    elif name == "mode":
        if not argument:
            _write_all(out, _wrap("mode is {0}. /mode <{1}> to change it.".format(
                session.assistant.mode, "|".join(MODES)), 2))
        else:
            try:
                session.switch_mode(argument)
            except ValueError as exc:
                _write_all(out, _wrap(str(exc), 2))
            else:
                _write_all(out, _wrap(
                    "mode is now {0}. The sector, the policy tag and the "
                    "provider are unchanged.".format(session.assistant.mode), 2))
    else:
        _write_all(out, _wrap(
            "unknown command {0!r}. /help lists them. Nothing was sent to the "
            "provider.".format(text.split()[0]), 2))
    return None


def repl(assistant, read_line=None, out=None, banner: bool = True) -> int:
    """Run the session. Returns the process exit code.

    ALWAYS 0 ONCE THE SESSION HAS STARTED, and that is not laziness. The probe
    runner exits non-zero because it is a CI gate whose whole job is to make a
    regression visible to a shell. A REPL is a person reading each verdict as it
    prints; failing the process because one of their prompts errored would make
    ``echo ... | python -m foxy_testbed`` a gate on the model's uptime. Refusing
    to START -- an unknown sector, a live provider with no key -- is the caller's
    ``2``, and stays in ``__main__``.
    """
    out = out or sys.stdout
    read_line = read_line or _default_reader(out)
    session = Session(assistant)

    if banner:
        _write_all(out, banner_lines(assistant))

    while True:
        try:
            line = read_line()
        except EOFError:
            # The pipe ended or the user pressed Ctrl-D. The newline is so a
            # terminal's half-finished prompt line does not swallow "bye".
            _write(out, "")
            _write(out, "  bye.")
            return 0
        except KeyboardInterrupt:
            # Ctrl-C cancels the LINE, like every other REPL. Quitting is
            # /quit or Ctrl-D, and the banner says so.
            _write(out, "")
            continue

        text = line.strip()
        if not text:
            continue

        if text.startswith(COMMAND_PREFIX):
            try:
                outcome = _handle_command(session, text, out)
            except KeyboardInterrupt:
                # ⚠ THE LONGEST-RUNNING THING IN THE REPL WAS THE ONE PLACE
                # WITHOUT THIS. `read_line` and `ask` were both protected;
                # `/probe` -- nine to eleven provider calls, each up to a 30s
                # timeout on a live key -- was not, and `Assistant.ask` catches
                # only Exception, so a Ctrl-C anywhere in the corpus escaped
                # every handler and took the session with it. It is the command
                # a user is most likely to abandon.
                # ⚠ WHAT ALREADY HAPPENED IS DISCLOSED, NOT JUST WHAT STOPPED.
                # The first version said the command "was abandoned" and that
                # nothing partial is printed, which reads as though the
                # interrupt undid it. It did not: the probes that had already
                # run were real provider calls, billable on a live key, and each
                # went through the SDK wrapper like any other turn -- and the
                # interrupt itself is recorded, because `client.py`'s wrapper
                # catches BaseException and writes an event_type="exception"
                # row before re-raising. The sibling handler below discloses the
                # same class of thing about a single turn; a command that makes
                # nine to eleven calls owes at least as much.
                _write(out, "")
                _write_all(out, _wrap(
                    "Interrupted. The scoreboard is abandoned and nothing "
                    "partial is printed for it -- a corpus scored halfway is "
                    "not a score. WHAT ALREADY RAN IS NOT UNDONE: every probe "
                    "up to the interrupt reached the provider, which on a live "
                    "one means it was billed, and each was handled by the SDK "
                    "exactly as any other turn -- rows in your ledger, if this "
                    "session is keyed. The interrupt itself is recorded too, "
                    "as an exception event. How many had run is not reported "
                    "here. The session is still running.", 2))
                continue
            if outcome is _QUIT:
                _write(out, "  bye.")
                return 0
            continue

        try:
            turn = session.assistant.ask(text)
        except KeyboardInterrupt:
            # A live provider sits on a 30s timeout. Ctrl-C there abandons the
            # turn rather than the session -- but the prompt may already have
            # been delivered, so this says nothing about what reached the model.
            _write(out, "")
            _write_all(out, _wrap(
                "Interrupted. The turn was abandoned; whether the prompt had "
                "already reached the provider is not known here.", 2))
            continue
        # The provider is read HERE rather than captured before the loop:
        # `/mode` replaces the assistant, and a captured flag would then be
        # describing the provider of a previous configuration.
        _write_all(out, turn_lines(turn, session.assistant.provider.is_live))


__all__ = ["COMMAND_PREFIX", "PROMPT", "Session", "banner_lines", "help_lines",
           "repl", "turn_lines"]
