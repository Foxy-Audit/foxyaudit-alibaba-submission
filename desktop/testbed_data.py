"""Foxy Audit desktop — compliance testbed shaping (T3).

The Qt-free half of the console's Testbed page, following the same split every
other section uses: `testbed_page.py` builds widgets, this module shapes what
they say, and neither holds any policy logic.

⚠ THE DESKTOP HAS NEVER IMPORTED THE SDK, AND THIS IS THE ONLY PLACE IT DOES
=============================================================================
Nothing else under `desktop/` imports `foxy_audit` or `foxy_testbed`. The
console talks to the backend over HTTP; the fox learns about the guard over a
UDP ping (`sdk_bridge`), never by importing it. Two consequences shaped this
file:

* `desktop/requirements.txt` did not list `foxy-audit` before T3, and CI
  installs only that file. An import at MODULE scope here would have failed all
  884 desktop tests. So the import lives inside :func:`load_engine`, inside a
  `try`, and a checkout that has not installed the SDK gets an honest state
  naming the fix — not a disabled button, not a spinner, and never a fabricated
  turn.
* The shipped `.exe` must carry it, so `foxy-audit` is now in
  `desktop/requirements.txt` and `omni_fox.spec` collects both packages. The
  guard stays anyway: a dev checkout that skipped `pip install` must degrade,
  not crash the console.

THE TESTBED IS THE ASSISTANT. THE SANDBOX IS THE VERIFIER.
==========================================================
`dashboard._page_sandbox` is the VERIFICATION sandbox — paste a prompt and a
response, hash them locally, compare to the ledger. This page is the assistant:
you type a prompt and watch `foxy_audit`'s real preflight guard decide what
happens to it before any model is called. Two different things one row apart in
the sidebar, so the titles are deliberately unalike.

NO POLICY LOGIC, AND NO SECOND VERDICT VOCABULARY
=================================================
The verdict word and the sentence under it come from `foxy_testbed.cli`'s
`_headline`, reached for exactly the way `foxy_testbed.web` reaches for it and
for the same reason: three front-ends each deciding what "blocked" means is how
the prevention-vs-evidence conflation got rebuilt once already, and a fourth
copy written in Qt would be the one nobody runs the engine's tests against.

The four "no reply" sentences in :func:`reply_status` are the one duplication,
and it is the duplication `web._reply_status` already made — those strings live
inside `cli.turn_lines`'s body, interleaved with terminal line-wrapping this
surface does not do. `test_d16_testbed.py` closes the gap the only way it can be
closed honestly: for each of the four shapes it asserts the sentence appears
VERBATIM in `cli.turn_lines`'s own output for the same turn.
"""

from __future__ import annotations

import os
from dataclasses import dataclass

# ── the guarded import ───────────────────────────────────────────────────────
#: What the page says when the SDK is not importable. It names the fix, because
#: an empty state that only reports a failure leaves the reader with nothing to
#: do — and this one has a one-line fix.
MISSING_TITLE = "The compliance testbed is not installed."
MISSING_BODY = (
    "This page runs the same foxy_audit preflight guard the SDK ships — there "
    "is no separate desktop copy of the policy, which is the whole point of it. "
    "Without the package there is nothing here to run, and showing you a "
    "console that answers anyway would be showing you a lie."
)
MISSING_FIX = "pip install foxy-audit"
MISSING_AFTER = "Then reopen the console. Nothing else needs configuring."


@dataclass(frozen=True)
class Engine:
    """The four `foxy_testbed` modules this page uses, and nothing else.

    ⚠ `foxy_testbed.web` IS DELIBERATELY NOT AMONG THEM. It is the newest module
    in the package and is absent from wheels that carry the other four — the
    published 1.11.0 wheel has `core`, `cli`, `sectors` and `providers` and no
    `web.py`. Importing it here would make an installed SDK that works render
    the not-installed state, which is the worst available failure for a guard
    whose whole job is telling those two apart.
    """

    core: object
    cli: object
    sectors: object
    providers: object


def load_engine():
    """→ (:class:`Engine`, "") or (None, "why not").

    ⚠ NEVER CALL THIS AT MODULE SCOPE. See the module docstring: the desktop
    test suite and CI both run against environments that may not have the SDK,
    and an import at import time takes the whole console down with it.

    Everything is caught, not just ImportError. A half-installed package raises
    whatever its own import raised, and the page has the same job either way:
    say what happened and name the fix.
    """
    try:
        from foxy_testbed import cli, core, providers, sectors
    except Exception as exc:                          # noqa: BLE001 — see above
        return None, "{0}: {1}".format(type(exc).__name__, exc)
    return Engine(core=core, cli=cli, sectors=sectors, providers=providers), ""


# ── the four visual families ─────────────────────────────────────────────────
FAMILY_ALLOWED = "allowed"
FAMILY_ENFORCED = "enforced"
FAMILY_FLAGGED = "flagged"
FAMILY_FAULT = "fault"


def family_of(turn) -> str:
    """Which of four colours a verdict wears. `page.html`'s `familyOf`, ported.

    ⚠ MEASURED FIRST, LABEL LAST, and the order is the whole point.
    `prevented` and `response_withheld` each pair the SDK's stamp with the
    observation that would contradict it, so a turn stamped "blocked" whose call
    reached the provider anyway does NOT get the calm colour — it falls through
    to the fault family, and the headline the engine computed says both things
    happened. That case should be unreachable; a surface that renders it as a
    clean block is how it would stay unreachable-LOOKING while being reached.
    """
    if turn.decision == "error":
        return FAMILY_FAULT
    if turn.prevented or turn.response_withheld or turn.prompt_enforced:
        return FAMILY_ENFORCED
    if turn.decision == "allowed":
        return FAMILY_ALLOWED
    if turn.decision == "flagged":
        return FAMILY_FLAGGED
    return FAMILY_FAULT


# ── the record's field list ──────────────────────────────────────────────────
def field_rows(turn) -> list:
    """→ [(label, value, {"mono": bool, "loud": bool}), …]

    `page.html`'s `fillFields`, in its order and with its labels. Rows that
    would claim nothing are absent rather than empty: an empty "removed" line
    under a prompt that never had a finding in it reads as a guard that did work
    it did not do.
    """
    rows = [
        ("rules", ", ".join(turn.rules) if turn.rules else "(none fired)",
         {"mono": True}),
        ("reason", turn.blocked_reason, {"mono": True}),
        # Spelled out rather than yes/no. This is the single most consequential
        # fact on the card and the label above it is seven characters long.
        ("reached",
         "yes, the provider was called with this prompt" if turn.reached_provider
         else "no, the provider was never called", {}),
    ]
    if turn.rules_removed:
        # TWO WORDS FOR ONE PROPERTY, because the property spans two events. On
        # a PREVENTED turn the findings did not reach the model because nothing
        # was sent at all, and calling that "removed" describes a rewrite of a
        # prompt that was never delivered.
        rows.append((("kept back" if turn.prevented else "removed"),
                     ", ".join(turn.rules_removed), {"mono": True}))
    if turn.rules_surviving:
        # ⚠ TRIPWIRE ON A `redacted` TURN, AND NOT DEAD MARKUP. Since SDK 1.9.0
        # the guard re-evaluates the redacted prompt and BLOCKS when any finding
        # still fires (SDK #216), so a redacted turn reaching this line means
        # that fix regressed. On a PREVENTED turn the list is empty and nothing
        # prints.
        rows.append(("STILL SENT", ", ".join(turn.rules_surviving),
                     {"mono": True, "loud": True}))
    if turn.redaction_ineffective:
        rows.append(("note",
                     "SDK >= 1.9.0 is supposed to BLOCK this turn (SDK #216), "
                     "so this means either an SDK older than 1.9.0 or a "
                     "regression of that fix.", {"loud": True}))
    rows.append(("ruleset", turn.ruleset_version or "(not reported)",
                 {"mono": True}))
    # ONE DECIMAL, WHICH IS `Turn.as_dict`'s OWN ROUNDING AND THE WEB PAGE'S.
    # Whole milliseconds printed "took 0 ms" for every mock turn — a real
    # measurement that reads exactly like an unfilled placeholder.
    rows.append(("took", "{0:.1f} ms".format(turn.latency_ms), {"mono": True}))
    if turn.error:
        # ProviderError carries a type and a status by construction and never a
        # response body, so nothing typed here can ride back out through it.
        rows.append(("error", turn.error, {"mono": True, "loud": True}))
    return rows


def reply_status(turn) -> str:
    """Why there is no reply to show, in the REPL's own words.

    ⚠ NOT ONE DECISION IS READ HERE, and the order of the branches is the whole
    point. `cli.turn_lines` ends on the same four sentences and arrived at them
    the hard way: its final branch used to say "the prompt was stopped before
    the provider was called" for everything unanswered, which includes a
    withheld RESPONSE — where the prompt reached the model and the tokens were
    spent.

    Empty when the turn WAS answered. Every branch below is a sentence about why
    there is no reply; on a turn that has one they are all false.
    """
    if turn.answered:
        return ""
    if turn.empty_reply:
        return ("The provider returned an empty reply, so there is nothing to "
                "show. What the guard did to your prompt is unaffected and is "
                "reported above.")
    if turn.error:
        return "No reply: the provider call failed."
    if turn.reached_provider:
        return ("No reply: the prompt reached the provider, and nothing came "
                "back to you.")
    return "No reply: the prompt was stopped before the provider was called."


def reply_source(turn) -> str:
    """The provenance line above a reply.

    Read off the RECORD, never re-derived by matching the provider name against
    "mock" — the engine carries `provider_is_live` precisely to stop that, and a
    custom `Provider` subclass answers to neither name.
    """
    return "reply ({0})".format(
        "live model output" if turn.provider_is_live
        else "mock fixture, not model output")


# ── the delivery rail ────────────────────────────────────────────────────────
#: The four points a prompt passes, left to right. Labels only — the states are
#: computed by :func:`rail_state`.
RAIL_LABELS = ("your prompt", "the guard", "the provider", "back to you")


def rail_state(turn) -> dict:
    """The rail's three segments and four nodes, as names a painter can use.

    ⚠ THIS DIAGRAM STATES NOTHING THE FIELD LIST DOES NOT ALSO STATE IN WORDS.
    It is a second encoding of `reached_provider` / `prompt_changed` /
    `answered`, not a second source of them, which is why the widget that draws
    it is not in the accessibility tree and why a break is drawn as a SHAPE —
    two crossed strokes where the line stops — rather than as a colour.
    """
    seg2 = seg3 = "off"
    node3 = node4 = "idle"
    if turn.reached_provider:
        seg2 = "changed" if turn.prompt_changed else "on"
        node3 = "changed" if turn.prompt_changed else "on"
    if turn.answered:
        seg3 = "on"
        node4 = "on"
    if turn.decision == "error":
        node3 = "fault"
    return {"segments": ("on", seg2, seg3),
            "nodes": ("on", "on", node3, node4),
            "breaks": (seg2 == "off", seg3 == "off")}


# ── provider keys ────────────────────────────────────────────────────────────
#: Where each live provider's key is read from when the keychain has none. The
#: vendors' own variable names, and the same two `foxy_testbed` itself reads.
KEY_ENV = {"openai": "OPENAI_API_KEY", "gemini": "GEMINI_API_KEY"}

#: How a user actually supplies each key ON THIS SURFACE. ⚠ The fox's Settings
#: dialog has an API-key field for OpenAI (AI Brain → Provider) and none for
#: Google — its provider list is anthropic / openai / ollama / lmstudio — so the
#: two sentences differ, because naming a control that does not exist is worse
#: than naming none.
_NO_KEY = {
    "openai": ("No OpenAI key is stored. Add one under the fox's Settings, on "
               "the AI Brain tab, or set OPENAI_API_KEY before starting Foxy."),
    "gemini": ("No Google key is stored. Set GEMINI_API_KEY before starting "
               "Foxy — the Settings dialog has no Google field yet."),
}


def provider_key(name: str, settings=None, environ=None) -> str:
    """The key for a live provider: the OS keychain first, then the vendor's
    own environment variable.

    The keychain wins because it is the one a user can change from inside the
    app. `settings` is optional so this stays callable without a FoxSettings.
    """
    environ = os.environ if environ is None else environ
    stored = ""
    if settings is not None:
        try:
            stored = (settings.api_key(name) or "").strip()
        except Exception:                             # noqa: BLE001
            # A keychain that refuses to answer is not a reason to fail the
            # page; the environment is still a real source.
            stored = ""
    return stored or (environ.get(KEY_ENV.get(name, ""), "") or "").strip()


def no_key_message(name: str) -> str:
    """What to say when a live provider has no key, naming the fix on THIS
    surface. Falls back to the variable name for a provider added later."""
    return _NO_KEY.get(name, "No key is stored for {0}.".format(name))


def provider_needs_key(name: str) -> bool:
    return name in KEY_ENV


# ── the composer ─────────────────────────────────────────────────────────────
def transcript_count(turns: int) -> str:
    return ("1 turn in this transcript" if turns == 1
            else "{0} turns in this transcript".format(turns))


#: The bound the engine's own web surface puts on one prompt, in characters, so
#: the two front-ends refuse the same thing. Bigger than any probe by two orders
#: of magnitude and the limit a person can actually hit.
MAX_PROMPT_CHARS = 20_000


__all__ = [
    "Engine", "FAMILY_ALLOWED", "FAMILY_ENFORCED", "FAMILY_FAULT",
    "FAMILY_FLAGGED", "KEY_ENV", "MAX_PROMPT_CHARS", "MISSING_AFTER",
    "MISSING_BODY", "MISSING_FIX", "MISSING_TITLE", "RAIL_LABELS",
    "family_of", "field_rows", "load_engine", "no_key_message",
    "provider_key", "provider_needs_key", "rail_state", "reply_source",
    "reply_status", "transcript_count",
]
