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
                        help=("key for a live provider; falls back to "
                              "OPENAI_API_KEY / GEMINI_API_KEY"))
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
                                  model=args.model)
        except (ProviderError, ValueError) as exc:
            print("Could not start: {0}".format(exc), file=sys.stderr)
            return 2
        return repl(assistant)

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
