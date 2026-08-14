"""``python -m foxy_testbed`` — the probe scoreboard.

    python -m foxy_testbed --sector healthcare --probe all
    python -m foxy_testbed --sector finance   --probe all --mode redact
    python -m foxy_testbed --sector legal     --probe all --provider openai

T0 ships the probe runner only. The interactive REPL is T1 and lands in
``cli.py``; running with no ``--probe`` says so plainly rather than printing a
usage blob that implies the REPL is there and broken.

EXIT CODES
==========
``0`` every probe met its expectation. ``1`` a miss, an over-block or a provider
error — this is a CI gate, so a regression has to be visible to a shell. ``2``
the run could not start (bad sector, bad mode, missing key). A known gap staying
open is expected and exits ``0``: see :mod:`foxy_testbed.scoreboard`.
"""

from __future__ import annotations

import argparse
import os
import sys

from .core import DEFAULT_MODE, MODES
from .providers import PROVIDER_NAMES, ProviderError
from .scoreboard import run_probes
from .sectors import SECTOR_NAMES

#: Where each live provider's key is read from when --api-key is not given.
_KEY_ENV = {"openai": "OPENAI_API_KEY", "gemini": "GEMINI_API_KEY"}


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="python -m foxy_testbed",
        description=("Run a sector assistant behind the real Foxy Audit preflight "
                     "guard and score BOTH columns: did it block what it should, "
                     "and is it still useful."),
    )
    parser.add_argument("--sector", required=True, choices=SECTOR_NAMES,
                        help="which sector preset to run")
    parser.add_argument("--probe", choices=("all",),
                        help="run the sector's probe corpus and print the scoreboard")
    parser.add_argument("--mode", default=DEFAULT_MODE, choices=MODES,
                        help="preflight mode (default: %(default)s)")
    parser.add_argument("--provider", default="mock", choices=PROVIDER_NAMES,
                        help=("mock is offline, deterministic and needs no key "
                              "(default: %(default)s)"))
    parser.add_argument("--model", default="",
                        help="override the provider's default model id")
    parser.add_argument("--api-key", default="",
                        help=("key for a live provider; falls back to "
                              "OPENAI_API_KEY / GEMINI_API_KEY"))
    return parser


def main(argv=None) -> int:
    args = build_parser().parse_args(argv)

    if args.probe is None:
        print("Nothing to run: pass --probe all for the scoreboard.\n"
              "The interactive REPL is not built yet -- it arrives in phase T1.",
              file=sys.stderr)
        return 2

    api_key = args.api_key or os.getenv(_KEY_ENV.get(args.provider, ""), "")

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
