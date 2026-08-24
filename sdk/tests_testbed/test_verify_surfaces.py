"""T4 — what the REPL and the local page do with an :class:`Evidence`.

Two rules this file exists to keep true, both of which a verify control makes it
newly easy to break:

* **Neither surface may compute a verdict.** `cli.py` and `web.py` are already
  asserted to contain no name from `foxy_audit`; the verify call is the first
  thing either of them has ever had a reason to reach for it, so the guard is
  restated here against the SAME source those tests read.
* **The prompt travels one way.** It goes up to `/verify` because `explain`
  recomputes the commitment from text the caller supplies. Nothing that comes
  back — payload, access log, or exception — may carry it.
"""

from __future__ import annotations

import ast
import io
import json
import pathlib
import sys

import pytest

from foxy_audit import FoxyClient
from foxy_testbed import cli, web
from foxy_testbed.core import (Assistant, EVIDENCE_NO_LEDGER, FAMILY_ANSWERED,
                               FAMILY_CANNOT, FAMILY_DISAGREED)
from foxy_testbed.sectors import get_sector

_PKG = pathlib.Path(web.__file__).resolve().parent
WEB_SOURCE = io.open(_PKG / "web.py", encoding="utf-8").read()
CLI_SOURCE = io.open(_PKG / "cli.py", encoding="utf-8").read()
PAGE_SOURCE = io.open(_PKG / "page.html", encoding="utf-8").read()

PHI_PROMPT = "Draft a note for the patient at alice@example.org about their MRI."


def _strip_js_comments(text: str) -> str:
    """`//` lines removed. Every guard here that greps the page needs this:
    the comments quote the defects they replaced, verbatim and on purpose."""
    return chr(10).join(line for line in text.splitlines()
                      if not line.strip().startswith("//"))


def _verify_code() -> str:
    """`wireVerify`'s body, comments stripped."""
    return _strip_js_comments(
        PAGE_SOURCE.split("function wireVerify")[1].split("function ")[0])


def _evidence_code() -> str:
    """`renderEvidence`'s body, comments stripped."""
    return _strip_js_comments(
        PAGE_SOURCE.split("function renderEvidence")[1].split("function ")[0])


def _keyed(tmp_path):
    """See ``test_evidence._keyed``: built with the spool, never swapped after.

    Duplicated rather than shared because these two files are already separate
    guards -- but the isolation itself is asserted ONCE, in
    ``test_evidence.py``, against whatever paths the constructor actually opens.
    """
    client = FoxyClient(api_key="test-key-not-a-real-one",
                        spool_path=str(tmp_path / "spool.db"))
    return Assistant("healthcare", client=client)


def _export(assistant, tmp_path):
    """⚠ THE SECOND COPY OF `test_evidence._export_from_receipt`, and it has to
    stay faithful for the same reason. Keys land only when the receipt has a
    value, exactly as `client.log_interaction` writes them — `decision`
    included, because from S14 it is what separates a guarded-but-clean row from
    an observe row and a document without it is a row the backend never stores.
    """
    receipt = assistant._receipts[-1]
    metadata = {key: receipt[key]
                for key in ("decision", "policy_rules", "blocked_reason",
                            "ruleset_version", "ruleset_hash")
                if receipt[key] is not None}
    row = {"event_id": receipt["event_id"], "policy_tag": receipt["policy_tag"],
           "commitment_alg": receipt["commitment_alg"],
           "prompt_hash": receipt["prompt_hash"]}
    if metadata:
        row["event_metadata"] = metadata
    path = tmp_path / "export.json"
    path.write_text(json.dumps({"logs": [row]}), encoding="utf-8")
    return str(path)


# ══ no policy logic on either surface ═══════════════════════════════════════
# ⚠ PARAMETRISED ON THE NAME, NEVER THE SOURCE. Passing the file contents as
# the parameter puts the whole module into the test id, so one failure prints
# a hundred and fifty kilobytes of unrelated file before the assertion.
# Measured, on the first run of this suite.
@pytest.mark.parametrize("name", ["web.py", "cli.py"])
def test_neither_surface_can_reach_foxy_audit_even_by_accident(name):
    """The verify call belongs in `core.py`, and this is what keeps it there.

    T4 is the first phase that gave either file a REASON to import
    `foxy_audit` — `explain` lives there — so the rule is restated against the
    same source their own suites read rather than trusted to hold.
    """
    tree = ast.parse({"web.py": WEB_SOURCE, "cli.py": CLI_SOURCE}[name])
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                assert not alias.name.startswith("foxy_audit"), alias.name
        elif isinstance(node, ast.ImportFrom):
            assert not (node.module or "").startswith("foxy_audit"), node.module


def test_the_page_holds_no_second_copy_of_the_status_vocabulary():
    """⚠ EIGHT OUTCOMES, RENDERED FROM THE SERVER'S WORD.

    The page prints `status` and `message` as it receives them. A JavaScript
    switch over the eight would be a second vocabulary — the one nobody runs the
    engine's tests against — and it is exactly how a tick and a cross get back
    in. Only `explained`, which selects whether a MARK is drawn at all, may
    appear; the other seven must not be spellable from this file.
    """
    from foxy_audit.introspect import STATUSES
    for status in STATUSES:
        if status == "explained":
            continue
        assert status not in PAGE_SOURCE, (
            "page.html names the outcome {0!r}. The status is rendered from the "
            "payload; naming one here is the start of a second copy.".format(
                status))


# ══ the prompt travels one way ══════════════════════════════════════════════
def test_the_access_log_cannot_see_a_prompt():
    """DRIVEN, not grepped. `log_message` is called with a path carrying a query
    and the line it writes is read back.

    ⚠ THE FIRST VERSION ASSERTED THE TOKEN `split("?", 1)[0]` APPEARED IN THE
    SOURCE, which is guard-lie #4 -- and it failed a correct implementation the
    moment it read the source through `ast.unparse`, which normalises the quotes
    to `split('?', 1)[0]`. A guard that breaks on how the code is SPELLED was
    never checking what it does. `/verify` carries the prompt in a body, so what
    matters is that nothing but a method and a bare path is ever written.
    """
    import types

    written = []
    handler = types.SimpleNamespace(
        command="POST",
        path="/verify?prompt=Patient+SSN+is+900-12-3456&x=secret")
    stderr = io.StringIO()
    saved, sys.stderr = sys.stderr, stderr
    try:
        web.Handler.log_message(handler, "%s", "ignored")
    finally:
        sys.stderr = saved
    written = stderr.getvalue()

    assert "/verify" in written and "POST" in written
    assert "prompt=" not in written
    assert "900-12-3456" not in written
    assert "?" not in written


def test_a_verify_response_carries_no_prompt(tmp_path):
    """End to end through the server object, not through the renderer.

    ⚠ THE 8-CHARACTER SWEEP, not a search for the whole prompt. A payload that
    leaked half a sentence would pass a whole-string check.
    """
    testbed = web.Testbed(export="", salt_sidecar_path="")
    payload = testbed.ask("healthcare", "block", PHI_PROMPT)
    assert payload["event_id"]

    verified = testbed.verify(payload["event_id"], PHI_PROMPT)
    serialised = json.dumps(verified)
    for start in range(0, len(PHI_PROMPT) - 8):
        fragment = PHI_PROMPT[start:start + 8]
        if fragment.strip():
            assert fragment not in serialised, fragment


def test_an_unknown_event_id_is_not_answered_with_an_outcome():
    """A turn this server did not run has no verdict, and inventing one — even
    `row_not_found`, which is a real `explain` status — would be reporting on a
    row nobody looked for."""
    testbed = web.Testbed()
    assert testbed.verify("no-such-turn", PHI_PROMPT) is None


def test_the_server_remembers_a_bounded_number_of_turns():
    """Bounded, and the page is told when an id has aged out rather than being
    answered as though the turn never existed."""
    testbed = web.Testbed()
    ids = []
    for index in range(web.Testbed.MAX_REMEMBERED + 5):
        payload = testbed.ask("healthcare", "block",
                              "question number {0}".format(index))
        ids.append(payload["event_id"])
    assert len(testbed._turns) == web.Testbed.MAX_REMEMBERED
    assert testbed.verify(ids[0], "question number 0") is None, "oldest kept"
    assert testbed.verify(ids[-1], "question number {0}".format(
        len(ids) - 1)) is not None, "newest dropped"


# ══ the REPL ════════════════════════════════════════════════════════════════
def test_verify_before_any_turn_says_so_rather_than_answering(tmp_path):
    session = cli.Session(_keyed(tmp_path))
    out = io.StringIO()
    assert cli._handle_command(session, "/verify", out) is None
    assert "Nothing to verify yet" in out.getvalue()


def test_the_repl_renders_the_state_it_is_actually_in(tmp_path):
    """Honest state 1, DRIVEN THROUGH `repl` rather than through `Session`.

    ⚠ THE FIRST VERSION CALLED `session.record` ITSELF and then asked `/verify`
    what it saw, so deleting the recording call site in the REPL loop left it
    green -- guard-lie #1, a guard on a definition nothing calls. Typing the
    prompt and then the command is what actually proves the loop remembers the
    turn a user just sent.
    """
    assistant = Assistant(get_sector("healthcare"))
    out = io.StringIO()
    lines = iter([PHI_PROMPT, "/verify", "/quit"])
    assert cli.repl(assistant, read_line=lambda: next(lines), out=out,
                    banner=False) == 0
    text = out.getvalue()
    assert "[BLOCKED]" in text, "the turn itself did not run"
    assert "NEVER SHIPPED TO A LEDGER" in text
    assert "--foxy-key" in text


def test_the_repl_prints_the_status_verbatim_and_the_three_state_ruleset(tmp_path):
    """Honest state 3, and the field the SDK made three-state.

    ⚠ THE SPANS ARE PRINTED HERE, and that is the one place they belong: a
    terminal on the user's own machine showing the user their own prompt. The
    payload guard above asserts the other half.
    """
    assistant = _keyed(tmp_path)
    turn = assistant.ask(PHI_PROMPT)
    export = _export(assistant, tmp_path)
    session = cli.Session(assistant, export=export)
    session.record(turn, PHI_PROMPT)

    out = io.StringIO()
    cli._handle_command(session, "/verify", out)
    text = out.getvalue()
    assert "explained" in text, "the status is not printed verbatim"
    assert "[ANSWERED]" in text
    assert "definition verified against the digest" in text
    assert "alice@example.org" in text, "the matched span never reached stdout"


def test_the_repl_help_lists_verify():
    """⚠ EVERY COMMAND THE HELP LISTS MUST BE ONE THE DISPATCHER ANSWERS.

    The first version asserted `"/verify" in line`, which `/verifyX` satisfies
    -- a substring check that passes for a command the REPL does not have. Both
    directions are checked instead: the help names it, and typing it does
    something other than falling through to "unknown command".
    """
    listed = [line for line in cli.help_lines() if "/verify" in line]
    assert listed, "the help does not mention /verify at all"
    assert any("/verify [file]" in line for line in listed), listed

    out = io.StringIO()
    cli._handle_command(cli.Session(Assistant(get_sector("legal"))),
                        "/verify", out)
    assert "unknown command" not in out.getvalue()


def test_every_repl_line_survives_a_cp1252_console(tmp_path):
    """The renderer, not just the engine's messages. `_FAMILY_MARK` is ASCII on
    purpose and this is what keeps it that way."""
    assistant = _keyed(tmp_path)
    turn = assistant.ask(PHI_PROMPT)
    export = _export(assistant, tmp_path)
    for evidence in (assistant.verify(turn, PHI_PROMPT),
                     assistant.verify(turn, PHI_PROMPT, export=export),
                     assistant.verify(turn, "a different prompt", export=export)):
        for line in cli.evidence_lines(evidence):
            line.encode("cp1252")


def test_the_three_marks_stay_three_distinct_words():
    """A mark is a heading, never the answer — but two families sharing one
    word would put a refusal and a pass under the same heading."""
    marks = {cli._FAMILY_MARK[f] for f in
             (FAMILY_ANSWERED, FAMILY_CANNOT, FAMILY_DISAGREED)}
    assert len(marks) == 3


# ══ the page ════════════════════════════════════════════════════════════════
def test_the_page_never_renders_a_mark_for_a_state_nothing_replayed():
    """⚠ COLOUR MEANS A REPLAY HAPPENED. "No key, so no row" is the default
    configuration, not a finding, and a coloured pill on it would put four
    surface states on the same footing as the eight the SDK computes."""
    assert 'if (evidence.state === "explained") {' in PAGE_SOURCE
    assert 'head.appendChild(el("span", "ev-mark"' in PAGE_SOURCE


def test_the_page_reads_the_three_state_flag_through_a_string_key():
    """`false` and `null` must not collapse. A `? :` on this field is the exact
    mistake the SDK made it three-state to prevent.

    ⚠ THE CALL SITE, NOT JUST THE TABLE. This asserted only that
    `String(...)` appeared SOMEWHERE in the file -- which stayed true when
    the call site was replaced by a ternary, because the helper still
    contained it. Found by re-breaking. Where the value is read is the
    thing that decides whether the three states survive.
    """
    assert "String(value)" in PAGE_SOURCE, "the table is not string-keyed"
    assert "rulesetWords(evidence.ruleset_verified)" in PAGE_SOURCE, (
        "the ruleset field is no longer read through the three-state helper")
    assert "evidence.ruleset_verified ?" not in PAGE_SOURCE, (
        "a ternary on ruleset_verified collapses false and null")
    assert '"null": "not checked' in PAGE_SOURCE
    assert '"false": "DIGEST DISAGREED' in PAGE_SOURCE


def test_the_page_asks_for_no_span_text():
    """It renders `match_count`. Asking for the spans would mean the server
    sending the user's own prompt back down to it."""
    assert "match_count" in PAGE_SOURCE
    assert "include_text" not in PAGE_SOURCE
    # ⚠ THE PAYLOAD KEY, NOT THE SUBSTRING ".text". The first version matched
    # `textContent` on the very next line and failed a correct file. What a
    # leak would actually look like is this page READING the spans, so that is
    # what is asserted -- and `Evidence.as_dict` never sends them.
    assert "evidence.matches" not in PAGE_SOURCE
    assert ".match_count" in PAGE_SOURCE


def test_the_verify_control_is_absent_when_there_is_nothing_to_look_up():
    """A button that reports the same refusal every time it is pressed is worse
    than one sentence saying it once."""
    body = PAGE_SOURCE.split("function wireVerify")[1]
    assert "if (!turn.event_id)" in body
    assert "removeChild(button)" in body


# ══ T4b · the gate's five findings ══════════════════════════════════════════
def test_going_back_to_a_mode_you_already_used_does_not_lose_the_turn():
    """THE ONE THAT BLOCKED THE GATE, DRIVEN AS THE SEQUENCE THAT FOUND IT.

    One client is shared by every Assistant `with_mode` produces and it holds ONE
    `on_event`. Bound at construction, the last Assistant built won -- so
    `Testbed`, which CACHES an assistant per (sector, mode), handed turns to
    instances whose hook had been taken away. Measured on the branch before the
    fix: block, observe, block, redact, observe gave ids for 1, 2 and 4 and
    NOTHING for 3 and 5, and the page reported "cannot be traced from here" for
    turns that had written real ledger rows.

    ⚠ THE SEQUENCE, NOT THE BINDING. A unit test on where the hook is assigned
    would have passed on the broken build -- the assignment was there and it was
    correct; what was wrong was WHEN. Revisiting a mode is the ordinary way a
    person drives a mode selector, so that is what is driven.
    """
    testbed = web.Testbed()
    sequence = [("healthcare", "block"), ("healthcare", "observe"),
                ("healthcare", "block"), ("healthcare", "redact"),
                ("healthcare", "observe")]
    seen = []
    for index, (sector, mode) in enumerate(sequence):
        payload = testbed.ask(sector, mode, "question number {0}".format(index))
        assert payload["event_id"], (
            "turn {0} ({1} {2}) came back with no event_id -- the cached "
            "assistant lost the receipt hook, and the page will deny evidence "
            "that exists".format(index + 1, sector, mode))
        seen.append(payload["event_id"])

    assert len(set(seen)) == len(sequence), "two turns reported the same row"
    # and every one is verifiable THROUGH THE SERVER, which is the claim the
    # page actually makes when it offers the control
    for index, event_id in enumerate(seen):
        assert testbed.verify(event_id,
                              "question number {0}".format(index)) is not None


def test_a_mode_round_trip_in_the_repl_keeps_naming_rows():
    """The same defect reachable from the other surface: `/mode` rebuilds through
    `with_mode` too, so a user who switches away and back is doing by hand what
    the web cache does by itself."""
    assistant = Assistant(get_sector("healthcare"), mode="block")
    session = cli.Session(assistant)
    ids = []
    for command in ("first question", "/mode observe", "second question",
                    "/mode block", "third question"):
        if command.startswith("/"):
            cli._handle_command(session, command, io.StringIO())
            continue
        turn = session.assistant.ask(command)
        assert turn.event_id, "a turn after a /mode round trip lost its row"
        ids.append(turn.event_id)
    assert len(set(ids)) == 3


@pytest.mark.parametrize("flag,value", [("--foxy-key", "a-key"),
                                        ("--export", "export.json"),
                                        ("--sidecar", "salt.json")])
def test_a_flag_the_scoreboard_cannot_use_is_refused_not_ignored(flag, value,
                                                                 capsys):
    """They were validated and then consumed only by the REPL branch, so
    `--probe all --foxy-key K` ran KEYLESS while the comment above the check said
    the flags are refused loudly rather than degraded. A flag accepted and
    ignored is worse than one refused: the user believes the run was keyed."""
    from foxy_testbed.__main__ import main

    assert main(["--sector", "healthcare", "--probe", "all", flag, value]) == 2
    err = capsys.readouterr().err
    assert flag in err and "no effect with --probe" in err


def test_a_plain_probe_run_is_untouched(capsys):
    """The refusal must not catch a run that passed none of them -- this is the
    CI gate, and it is what all three sectors are scored by."""
    from foxy_testbed.__main__ import main

    assert main(["--sector", "healthcare", "--probe", "all"]) == 0
    assert "PASS" in capsys.readouterr().out


def test_an_export_that_is_valid_json_but_not_a_ledger_does_not_kill_the_repl(
        tmp_path):
    """`introspect._row_for` calls `.get` on whatever `logs` turns out to be, so
    a bare array raises AttributeError -- neither OSError nor ValueError, which
    was all `verify` caught. It escaped into `_handle_command`, which catches
    only KeyboardInterrupt, and took the whole session down with a traceback.

    ⚠ DRIVEN THROUGH `repl`, because the blast radius IS the loop. Calling
    `verify` directly would prove the exception is caught and say nothing about
    whether the session survives it.
    """
    bare = tmp_path / "bare.json"
    bare.write_text('{"logs": [1, 2, 3]}', encoding="utf-8")

    assistant = _keyed(tmp_path)
    out = io.StringIO()
    lines = iter([PHI_PROMPT, "/verify {0}".format(bare), "/quit"])
    assert cli.repl(assistant, read_line=lambda: next(lines), out=out,
                    banner=False) == 0, "the REPL died on a malformed export"
    text = out.getvalue()
    assert "THE EXPORT COULD NOT BE READ" in text
    assert "AttributeError" in text, "the type is what the message may carry"
    assert "bye." in text, "the session never reached /quit"


def test_a_ruleset_verified_value_this_build_does_not_know_degrades():
    """It was a bare `{...}[value]` lookup, which raises KeyError on anything
    outside the three -- the same REPL-killing blast radius. `page.html` keys
    through `String(...)` so an unknown value degrades to a printed oddity; the
    REPL it is supposed to agree with now does the same."""
    from foxy_testbed.core import EVIDENCE_EXPLAINED, Evidence

    odd = Evidence(state=EVIDENCE_EXPLAINED, headline="EXPLAINED", message="m",
                   event_id="e", status="explained",
                   ruleset_verified="not-a-tristate")
    rendered = " ".join(cli.evidence_lines(odd))
    assert "not reported" in rendered
    assert "not-a-tristate" in rendered

    # and the three real states are still three DISTINCT sentences
    said = set()
    for value in (True, False, None):
        one = Evidence(state=EVIDENCE_EXPLAINED, headline="EXPLAINED",
                       message="m", event_id="e", status="explained",
                       ruleset_verified=value)
        said.add(" ".join(cli.evidence_lines(one)))
    assert len(said) == 3


def test_a_verify_path_with_spaces_reaches_explain_whole(tmp_path):
    """`split()` handed `/verify` only the text up to the first space, so a
    Windows path under a folder like "Al Smith" arrived truncated and the failure
    named a path the user had never typed.

    ⚠ ASSERTED ON WHAT `verify` WAS GIVEN, not on the absence of an error. A
    truncated path and a correct one both fail against an empty ledger; only the
    argument tells them apart.
    """
    spaced = tmp_path / "Al Smith" / "export.json"
    spaced.parent.mkdir(parents=True, exist_ok=True)
    spaced.write_text(json.dumps({"logs": []}), encoding="utf-8")

    assistant = _keyed(tmp_path)
    turn = assistant.ask(PHI_PROMPT)
    session = cli.Session(assistant)
    session.record(turn, PHI_PROMPT)

    seen = {}
    original = type(assistant).verify

    def spy(self, turn_, prompt_, export=None, **kwargs):
        seen["export"] = export
        return original(self, turn_, prompt_, export=export, **kwargs)

    type(assistant).verify = spy
    try:
        cli._handle_command(session, "/verify {0}".format(spaced), io.StringIO())
    finally:
        type(assistant).verify = original

    assert seen["export"] == str(spaced), "the path was truncated at a space"
    assert "Al Smith" in seen["export"]


def test_other_commands_still_take_a_single_token():
    """The argument became the rest of the line; `/mode` must not start accepting
    one. Trailing whitespace has to keep meaning nothing."""
    session = cli.Session(Assistant(get_sector("healthcare"), mode="block"))
    out = io.StringIO()
    cli._handle_command(session, "/mode  observe  ", out)
    assert session.assistant.mode == "observe"
    assert "unknown mode" not in out.getvalue()


# ══ T4c · the gate's four findings ══════════════════════════════════════════
def test_a_bare_foxy_key_under_probe_is_refused_for_the_right_reason(capsys,
                                                                     monkeypatch):
    """The flag was refused on its VALUE, and the value was resolved first -- so
    `--probe all --foxy-key` with the variable unset answered "FOXY_API_KEY is
    not set", sending the user to set a variable that would then have been
    refused anyway. What is wrong with that command line is that the flag was
    typed at all.

    ⚠ BOTH ENVIRONMENTS, because the old code got one of them right. With the
    variable SET it already produced the correct refusal, so a test that only
    exported a value passes on the broken build.
    """
    from foxy_testbed.__main__ import main

    monkeypatch.delenv("FOXY_API_KEY", raising=False)
    assert main(["--sector", "healthcare", "--probe", "all", "--foxy-key"]) == 2
    err = capsys.readouterr().err
    assert "no effect with --probe" in err
    assert "is not set" not in err, (
        "the refusal still talks about the environment variable")

    monkeypatch.setenv("FOXY_API_KEY", "a-real-looking-key")
    assert main(["--sector", "healthcare", "--probe", "all", "--foxy-key"]) == 2
    assert "no effect with --probe" in capsys.readouterr().err

    # ⚠ AND AN EMPTY VALUE IS STILL PRESENCE. `--export ""` is a flag the
    # user typed; testing it for truthiness rather than for `is not None`
    # lets exactly that case through to be silently dropped, which is the
    # original shape of this finding. Found by re-breaking: the mutation
    # from `is not None` to a bare truthiness test survived without it.
    assert main(["--sector", "healthcare", "--probe", "all",
                 "--export", ""]) == 2
    assert "--export" in capsys.readouterr().err


def test_a_bare_foxy_key_outside_probe_still_reports_the_missing_variable(
        capsys, monkeypatch):
    """The other half: where the flag CAN be used, an unset variable is still the
    thing to say. Refusing on presence must not swallow that."""
    from foxy_testbed.__main__ import main

    monkeypatch.delenv("FOXY_API_KEY", raising=False)
    monkeypatch.setattr("sys.stdin", io.StringIO(""))
    assert main(["--sector", "healthcare", "--foxy-key"]) == 2
    assert "FOXY_API_KEY is not set" in capsys.readouterr().err


def test_the_page_and_the_repl_both_degrade_on_an_unknown_ruleset_value():
    """⚠ THE PARITY THIS PAIR CLAIMS, ASSERTED IN BOTH DIRECTIONS.

    T4b gave `cli.py` a fallback with a comment saying it matched `page.html`.
    It did not: the page keyed through `String(...)` but had NO fallback, so a
    value outside the three rendered as an EMPTY ROW there while the REPL printed
    a sentence. The claim was false in the code and in the commit message.

    Keyed through a string is only half of it -- that is what stops `false` and
    `null` collapsing. The fallback is what stops an unrecognised value rendering
    as nothing at all, on the one panel whose job is refusing to leave a reader
    guessing.
    """
    assert "String(value)" in PAGE_SOURCE or \
        "String(evidence.ruleset_verified)" in PAGE_SOURCE
    assert '"null": "not checked' in PAGE_SOURCE
    assert '"false": "DIGEST DISAGREED' in PAGE_SOURCE
    # the fallback, on both surfaces, in the same words
    assert "not reported (" in PAGE_SOURCE, "page.html has no fallback"
    assert "is not a value this build knows" in PAGE_SOURCE
    assert "is not a value this build knows" in CLI_SOURCE
    # and the page must not go back to a bare subscript
    assert "RULESET_WORDS[String(evidence.ruleset_verified)]" not in PAGE_SOURCE


# ══ T4d · the page must not announce a row it has not looked for ════════════
def test_the_page_reads_submitted_and_never_promises_a_row():
    """🔴 THE PAGE CONTRADICTED ITSELF IN THE OFFLINE DEMO A PROSPECT SEES FIRST.

    The hint under every record with an id read `"row " + turn.event_id` --
    including the keyless default, where nothing was shipped and no row exists.
    `submitted` rode in the payload and was read by NOTHING in this file, so the
    page announced a row and then, one click later, said "NEVER SHIPPED TO A
    LEDGER" in the panel directly beneath it.

    ⚠ THE WORD "row" IS BANNED FROM THE PRE-CLICK HINT, not merely made
    conditional. Nothing has looked for a row at that point on any path, so
    there is no branch on which it is the right word.
    """
    # ⚠ COMMENTS STRIPPED. The comment explaining the fix QUOTES the defect it
    # replaced -- `"row " + turn.event_id` -- so the first version of this guard
    # read its own explanation as the violation and failed a correct file. The
    # repo's oldest trap, in a third syntax.
    body = _verify_code()
    assert "turn.submitted" in body, (
        "the hint still does not read `submitted`; it is in the payload and "
        "the page was ignoring it")
    assert '"row "' not in body, "the pre-click hint still promises a row"
    assert '"event "' in body


def test_the_two_hints_say_different_things():
    """Reading `submitted` is only half of it -- the two branches have to
    DIVERGE, or the field is read and thrown away."""
    body = _verify_code()
    assert "enqueued" in body
    assert "not shipped" in body
    # and "enqueued", not "shipped", for the same reason core.verify says so:
    # a successful spool enqueue is not a delivery.
    assert '" \\u00b7 shipped"' not in body


def test_the_page_never_calls_an_enqueue_a_delivery():
    """The word `core.verify` refuses is refused in the verify code too.

    ⚠ SCOPED TO THE VERIFY CODE, NOT THE WHOLE FILE. "delivered" is correct
    English elsewhere on this page and says nothing about a ledger -- the
    observe hint reads "Prompts are delivered exactly as typed", which is about
    the PROVIDER. A blanket ban failed that correct sentence.
    """
    assert "delivered" not in _verify_code()
    assert "delivered" not in _evidence_code()
