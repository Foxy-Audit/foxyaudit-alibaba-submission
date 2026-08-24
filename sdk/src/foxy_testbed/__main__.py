"""``python -m foxy_testbed`` — the REPL, or the probe scoreboard.

    python -m foxy_testbed --sector healthcare                 # interactive
    python -m foxy_testbed --sector healthcare --probe all
    python -m foxy_testbed --sector finance   --probe all --mode redact
    python -m foxy_testbed --sector legal     --probe all --provider openai

``--probe`` is the switch between the two. Without it you get
:mod:`foxy_testbed.cli`'s interactive session; with it, one scored pass over the
sector's corpus. Both are offline and keyless by default, and the REPL is driven
end-to-end by the mock provider — a surface that only works with a live key is a
surface CI cannot run, and this is the phase CI runs.

EXIT CODES
==========
``0`` every probe met its expectation, or an interactive session ended. ``1`` a
miss, an over-block or a provider error — the probe runner is a CI gate, so a
regression has to be visible to a shell. ``2`` the run could not START (bad
sector, bad mode, missing key), which is the one failure both paths share. A
known gap staying open is expected and exits ``0``: see
:mod:`foxy_testbed.scoreboard`.

⚠ A REPL SESSION NEVER RETURNS ``1``, and that asymmetry is deliberate. Its
verdicts are read by a person as they print, so failing the process because one
typed prompt hit a provider error would make ``echo ... | python -m
foxy_testbed`` a gate on a model's uptime. See :func:`foxy_testbed.cli.repl`.
"""

from __future__ import annotations

import argparse
import os
import sys

from .cli import repl
from .core import Assistant, DEFAULT_MODE, MODES
from .providers import PROVIDER_NAMES, ProviderError
from .scoreboard import run_probes
from .sectors import SECTOR_NAMES

#: Where each live provider's key is read from when --api-key is not given.
_KEY_ENV = {"openai": "OPENAI_API_KEY", "gemini": "GEMINI_API_KEY"}

#: `--foxy-key` with no value. A sentinel and not "" so that "the user asked
#: for the environment and it was empty" stays distinguishable from "the user
#: passed an empty string", which are different mistakes and get different
#: messages.
_FROM_ENV = "<from FOXY_API_KEY>"

#: Where the Foxy key is read from when `--foxy-key` is given with no value.
#: The same variable `FoxyConfig.resolve` reads, so one name means one thing.
_FOXY_KEY_ENV = "FOXY_API_KEY"


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="python -m foxy_testbed",
        description=("Talk to a sector assistant sitting behind the real Foxy Audit "
                     "preflight guard, and see what the guard did to every turn. "
                     "With --probe all, run the sector's labelled corpus instead "
                     "and score BOTH columns: did it block what it should, and is "
                     "it still useful. Offline and keyless by default."),
    )
    parser.add_argument("--sector", required=True, choices=SECTOR_NAMES,
                        help="which sector preset to run")
    parser.add_argument("--probe", choices=("all",),
                        help=("run the sector's probe corpus and print the "
                              "scoreboard; omit it for the interactive REPL"))
    # ⚠ EVERY CONFIGURATION FLAG DEFAULTS TO None, AND THAT IS LOAD-BEARING.
    # argparse otherwise MANUFACTURES a value the user never typed, and
    # "block"/"mock" are indistinguishable from a deliberate choice once parsed.
    # A surface that holds its own Assistant and forwards its parsed args --
    # which is exactly what T1's REPL does -- then hands run_probes a full
    # configuration beside a prebuilt assistant and gets AssistantConflict on
    # every run, for flags nobody passed.
    #
    # The real defaults live in run_probes, which is the one place that knows
    # whether it is building the Assistant. They are named in the help text so
    # `--help` still tells the truth.
    parser.add_argument("--mode", default=None, choices=MODES,
                        help="preflight mode (default: {0})".format(DEFAULT_MODE))
    parser.add_argument("--provider", default=None, choices=PROVIDER_NAMES,
                        help=("mock is offline, deterministic and needs no key "
                              "(default: mock)"))
    parser.add_argument("--model", default=None,
                        help="override the provider's default model id")
    parser.add_argument("--api-key", default=None,
                        help=("key for a live PROVIDER; falls back to "
                              "OPENAI_API_KEY / GEMINI_API_KEY"))

    # ── T4: reaching a ledger, and then checking the row ──────────────
    # ⚠ A DIFFERENT KEY FROM --api-key, AND THE HELP SAYS SO IN THE FIRST
    # FOUR WORDS. Until T4 the only key any surface took was the
    # provider's, so no turn this testbed ever ran had written a ledger
    # row -- which is why "never shipped to a ledger" is the DEFAULT
    # state of the verify control and not an error.
    #
    # ⚠ `nargs="?"` SO THE FLAG CAN CARRY THE KEY OR NAME THE ENVIRONMENT,
    # and `default=None` so its ABSENCE still means keyless. The
    # environment is read only when the user typed the flag: `FoxyConfig`
    # would happily fall back to $FOXY_API_KEY on its own, and a probe run
    # that silently started writing to whoever's ledger the machine
    # happens to be configured for is the one thing the keyless default
    # exists to prevent. Opt-in, never inherited.
    parser.add_argument("--foxy-key", nargs="?", default=None,
                        const=_FROM_ENV, metavar="KEY",
                        help=("your FOXY key -- the one that makes a turn "
                              "reach a ledger at all. Bare --foxy-key "
                              "reads FOXY_API_KEY. Without it nothing is "
                              "shipped anywhere (the default)"))
    parser.add_argument("--export", default=None, metavar="FILE",
                        help=("your own GET /v1/logs/export?format=json "
                              "document, so /verify can replay a row"))
    parser.add_argument("--sidecar", default=None, metavar="FILE",
                        help=("the salt sidecar the SDK wrote, for rows "
                              "committed with a per-event salt"))
    return parser


def main(argv=None) -> int:
    args = build_parser().parse_args(argv)

    # The env fallback applies only to a provider the user actually named; with
    # --provider absent there is no live provider and nothing to look up.
    # ABOVE THE BRANCH, because both paths need it: the REPL builds the same
    # provider from the same key, and a --provider openai session that silently
    # ignored OPENAI_API_KEY while --probe honoured it would be one flag
    # meaning two things.
    api_key = args.api_key
    if api_key is None and args.provider in _KEY_ENV:
        api_key = os.getenv(_KEY_ENV[args.provider]) or None

    # ⚠ RESOLVED BEFORE EITHER BRANCH, and refused loudly rather than degraded.
    # A user who typed --foxy-key and got a keyless session anyway would watch
    # every turn report "never shipped to a ledger" and have no way to tell that
    # from the offline default they were trying to leave.
    foxy_key = args.foxy_key
    if foxy_key == _FROM_ENV:
        foxy_key = os.getenv(_FOXY_KEY_ENV) or ""
        if not foxy_key:
            print("Could not start: --foxy-key was given with no value and "
                  "{0} is not set. Pass the key, or set that variable."
                  .format(_FOXY_KEY_ENV), file=sys.stderr)
            return 2
    elif foxy_key is not None and not foxy_key.strip():
        print("Could not start: --foxy-key was given an empty value. Omit the "
              "flag to run offline, which is the default.", file=sys.stderr)
        return 2

    if args.probe is None:
        # ⚠ ONE ASSISTANT, BUILT HERE, HELD FOR THE SESSION. Every argument
        # arrives as None when the user did not type it, and `Assistant` already
        # resolves each of those to the same default `run_probes` would have
        # applied -- `mode or DEFAULT_MODE`, `str(name or "mock")`, `model or
        # <provider default>`. So the "not given" discipline the flags were
        # given None defaults for survives all the way to the engine, and this
        # function does not become a second place that decides what "not given"
        # means.
        try:
            assistant = Assistant(args.sector, mode=args.mode,
                                  provider=args.provider, api_key=api_key,
                                  model=args.model,
                                  foxy_api_key=foxy_key or "")
        except (ProviderError, ValueError) as exc:
            print("Could not start: {0}".format(exc), file=sys.stderr)
            return 2
        # The verify inputs travel WITH the session rather than being asked for
        # at `/verify` time: they are properties of this run, and a REPL that
        # prompted for a file path mid-session would be asking the user to type
        # a path into the same box that sends prompts to a guard.
        return repl(assistant, export=args.export or "",
                    salt_sidecar_path=args.sidecar or "")

    # ⚠ REFUSED, NOT DROPPED, AND THE COMMENT ABOVE IS WHY. All three flags are
    # validated before this branch and then consumed only by the REPL, so
    # `--probe all --foxy-key K` ran keyless while the user believed otherwise --
    # a flag accepted and ignored is worse than one refused.
    #
    # REFUSED RATHER THAN WIRED THROUGH, deliberately, and each for its own
    # reason. `--export` and `--sidecar` are inputs to a verify control that the
    # scoreboard does not have, so there is nothing here for them to act on.
    # `--foxy-key` COULD be wired to `run_probes`, and that is exactly why it is
    # not: a probe run is a CI gate that sends nine to eleven synthetic PHI
    # prompts through the guard, and quietly writing that corpus into whichever
    # ledger the key names is a surprise no scoreboard should be able to spring.
    # A run that wants ledger rows is a REPL session. If probe-mode capture is
    # ever wanted it should be asked for by its own flag, not inherited.
    unusable = [name for name, value in (("--foxy-key", foxy_key),
                                         ("--export", args.export),
                                         ("--sidecar", args.sidecar))
                if value]
    if unusable:
        print("Could not start: {0} {1} no effect with --probe. The scoreboard "
              "does not ship events and has no verify control; drop the flag, or "
              "run the interactive session instead."
              .format(", ".join(unusable),
                      "has" if len(unusable) == 1 else "have"),
              file=sys.stderr)
        return 2

    try:
        board = run_probes(args.sector, mode=args.mode, provider=args.provider,
                           api_key=api_key, model=args.model)
    except (ProviderError, ValueError) as exc:
        print("Could not start: {0}".format(exc), file=sys.stderr)
        return 2

    print(board.render())
    return 0 if board.ok else 1


if __name__ == "__main__":
    sys.exit(main())
