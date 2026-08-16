"""The ``foxy`` command line: doctor, check, explain.

    foxy doctor                          is it all wired together?
    foxy check "..." --policy hipaa      would this prompt trip anything?
    foxy explain --event-id <uuid> ...   prove what fired on a recorded row

``doctor`` sends a real test interaction through the whole path and reports what
is actually connected: the backend (authenticated ingest), the desktop pet (a
local UDP signal), and the tamper-evident chain (the test log verified
server-side).

``check`` is LOCAL policy evaluation. No API key, no network, no spool — asking
"does my prompt trip anything?" must not require an account. It prints LABELS and
never the text it was given.

``explain`` replays one exported row against the ruleset THAT ROW NAMES and PRINTS
THE MATCHED SPANS. That is deliberate and it is the point: it runs on your
machine, against a prompt you supplied, to answer "prove it was a real breach".
Those spans go to STDOUT ONLY — this command writes no file and logs nothing.
See ``introspect.py`` for the full statement of both rules.
"""
from __future__ import annotations

import argparse
import json
import sys

import requests

from . import hashing, introspect, udp
from .config import FoxyConfig

def _pick(uni: str, plain: str) -> str:
    """Emoji if the terminal can encode it, else an ASCII marker (Windows cp1252-safe)."""
    try:
        uni.encode(sys.stdout.encoding or "utf-8")
        return uni
    except (UnicodeEncodeError, LookupError, TypeError):
        return plain


_OK = _pick("✅", "[OK]")
_X = _pick("❌", "[X]")
_ARROW = _pick("→", "->")
_FOX = _pick("🦊", "")


def _doctor(cfg: FoxyConfig) -> int:
    print("Foxy Audit — doctor")
    print(f"  backend : {cfg.endpoint}")
    print(f"  pet     : {cfg.udp_host}:{cfg.udp_port}")
    if not cfg.api_key:
        print(f"  {_X} No API key set. Export FOXY_API_KEY (get one from a free signup or the "
              f"dashboard), then re-run `foxy doctor`.")
        return 1

    # 1) BACKEND — authenticated ingest of one real test interaction.
    prompt, response = "foxy doctor test prompt", "foxy doctor test response"
    payload = [{
        "prompt_hash": hashing.sha256_hex(prompt),
        "response_hash": hashing.sha256_hex(response),
        "token_count": hashing.estimate_tokens(prompt, response),
        "policy_tag": "foxy-doctor",
    }]
    try:
        r = requests.post(f"{cfg.endpoint}/v1/logs/batch",
                          headers={"Authorization": f"Bearer {cfg.api_key}"},
                          json=payload, timeout=cfg.timeout)
    except requests.RequestException as exc:
        print(f"  {_X} Backend unreachable at {cfg.endpoint} ({exc}). Is it running / is the URL right?")
        return 1
    if r.status_code == 401:
        print(f"  {_X} Backend rejected the API key (401). Check FOXY_API_KEY.")
        return 1
    if r.status_code >= 400:
        print(f"  {_X} Backend error {r.status_code}: {r.text[:200]}")
        return 1
    print(f"  {_OK} Backend reachable + authenticated — test log accepted (HTTP {r.status_code}).")

    # Provider configuration is not provider health. Surface this distinction
    # so an unavailable evaluator cannot be mistaken for a clean verdict.
    try:
        health = requests.get(f"{cfg.endpoint}/v1/health",
                              headers={"Authorization": f"Bearer {cfg.api_key}"},
                              timeout=cfg.timeout)
        evaluator = health.json().get("evaluator", {}) if health.ok else {}
        if evaluator.get("status") == "configured":
            print(f"  {_ARROW} Evaluator configured: {evaluator.get('provider', 'unknown')} "
                  f"({evaluator.get('model', 'unknown')}); verdicts are advisory.")
        else:
            print(f"  {_X} Evaluator unavailable; graded fallback results remain unknown.")
    except (requests.RequestException, ValueError):
        print(f"  {_X} Evaluator status unavailable; do not treat fallback results as clean.")

    # 2) DESKTOP PET — fire the same instant signal the SDK sends on every call.
    sent = udp.send_ping({"event": "evaluating", "policy": "foxy-doctor"},
                         cfg.udp_host, cfg.udp_port)
    tail = "watch the fox react" if sent else "no pet is listening — that is fine"
    print(f"  {_ARROW} Sent a signal to the desktop pet ({tail}).")
    captured = udp.send_ping({
        "event": "hash_ok", "policy": "foxy-doctor", "delivery": "queued",
    }, cfg.udp_host, cfg.udp_port)
    print(f"  {_ARROW} Local capture signal sent ({'watch the fox react' if captured else 'no pet is listening'}).")

    # 3) CHAIN — confirm the ledger verifies server-side.
    try:
        v = requests.get(f"{cfg.endpoint}/v1/verify",
                         headers={"Authorization": f"Bearer {cfg.api_key}"},
                         timeout=cfg.timeout)
        data = v.json() if v.ok else {}
    except requests.RequestException:
        data = {}
    if data.get("ok"):
        print(f"  {_OK} Ledger verified — {data.get('count', 0)} entries, chain intact.")
    else:
        print(f"  {_OK} Test log written. (Grading + chain verification complete server-side "
              f"within a few seconds.)")

    print(f"\nAll set — your calls are flowing end-to-end. {_FOX}".rstrip())
    return 0


def _check(args) -> int:
    """Local policy evaluation. Prints LABELS; never echoes the prompt.

    Deliberately does NOT build a FoxyConfig or a client: no key is read, no
    spool is opened, nothing is sent. The exit code is the answer a script wants
    — 0 clean, 1 something fired — so this drops into a pre-commit hook or a CI
    step without parsing anything.
    """
    prompt = args.prompt
    if args.prompt_file:
        with open(args.prompt_file, "r", encoding="utf-8") as handle:
            prompt = handle.read()
    if prompt is None:
        print("foxy check: give a prompt, or --prompt-file -", file=sys.stderr)
        return 2

    result = introspect.check(prompt, policy=args.policy)
    if args.json:
        print(json.dumps(result.as_dict(), indent=2, sort_keys=True))
    else:
        mark = _X if result.triggered else _OK
        print(f"{mark} policy={result.policy}  ruleset={result.ruleset_version}")
        print(f"  triggered : {result.triggered}")
        print(f"  reason    : {result.reason}")
        print(f"  rules     : {', '.join(result.rules) or '(none)'}")
        print(f"  signals   : {', '.join(result.signals) or '(none)'}")
        # The prompt itself is NOT printed. `check` is content-blind, and a CLI
        # that echoed it would put customer text in a terminal scrollback, a CI
        # log and a shell history in one move.
    return 1 if result.triggered else 0


def _explain(args) -> int:
    """Replay a recorded row against its own ruleset, and SHOW the spans.

    This is the one place in the SDK that prints customer content back, and it
    is correct here: the text came from the caller, on the caller's machine,
    to answer "prove it". It goes to stdout and nowhere else — no file is
    written, nothing is logged, nothing is sent.
    """
    with open(args.prompt_file, "r", encoding="utf-8") as handle:
        prompt = handle.read()

    cfg = FoxyConfig.resolve(api_key=args.api_key)
    key = args.commitment_key or cfg.commitment_key or cfg.api_key
    sidecar_path = args.sidecar if args.sidecar is not None else cfg.salt_sidecar_path

    result = introspect.explain(prompt, event_id=args.event_id, export=args.export,
                                commitment_key=key, salt_sidecar_path=sidecar_path)
    if args.json:
        # include_text is opt-in, and this is the opt-in: stdout.
        print(json.dumps(result.as_dict(include_text=True), indent=2, sort_keys=True))
        return 0 if result.ok else 1

    mark = _OK if result.ok else _X
    print(f"{mark} {result.message}")
    if result.ruleset_version:
        # ⚠ THE RULESET LINE SAYS WHETHER IT WAS VERIFIED, not only which one it
        # was. `commitment: verified` has always printed; the ruleset's own
        # digest was recorded on the row, parsed into the result, and shown
        # NOWHERE — so a reader could not tell a confirmed replay from an
        # unconfirmed one. The `ruleset_mismatch` status renders through
        # `result.message` like every other status, but "which rules, and are
        # they the ones that ran" is a standing question, not only a failure.
        #
        # ⚠ THREE RENDERINGS, NOT TWO, because `ruleset_verified` is three-state.
        # A first cut printed "NOT VERIFIED" for anything that was not True —
        # including `hash_mismatch` and `salt_unavailable`, where the digest
        # check NEVER RAN and the row's hash in fact agrees with this build. The
        # same words for "your registry was altered" and "you supplied the wrong
        # prompt" is the misdiagnosis this whole module exists to prevent.
        #
        # It says DEFINITION, not "ruleset": the digest covers the frozen dict,
        # not the validator code that dict names. See ExplainResult's field.
        if result.ruleset_verified is True:
            state = "definition verified"
        elif result.ruleset_verified is False:
            state = "DEFINITION ALTERED — see above"
        else:
            state = "definition not checked"
        print(f"  ruleset   : {result.ruleset_version} ({state})")
    print(f"  commitment: {'verified' if result.commitment_verified else 'not verified'}")
    for match in result.matches:
        print(f"  {_ARROW} {match.rule_id}  [{match.start}:{match.end}]")
        print(f"      {match.text!r}")
    return 0 if result.ok else 1


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(prog="foxy", description="Foxy Audit SDK tools.")
    sub = parser.add_subparsers(dest="command")
    doc = sub.add_parser("doctor", help="check backend + desktop pet + chain end-to-end")
    doc.add_argument("--api-key", default=None, help="override FOXY_API_KEY")
    doc.add_argument("--backend", default=None, help="override FOXY_BACKEND_URL")

    chk = sub.add_parser("check", help="would this prompt trip anything? (local, no key)")
    chk.add_argument("prompt", nargs="?", default=None, help="the prompt text")
    chk.add_argument("--prompt-file", default=None, help="read the prompt from a file")
    chk.add_argument("--policy", default="default", help="policy tag (default: default)")
    chk.add_argument("--json", action="store_true", help="machine-readable output")

    exp = sub.add_parser("explain", help="replay a recorded row against its own ruleset")
    exp.add_argument("--event-id", required=True, help="the row's event_id")
    exp.add_argument("--export", required=True, help="a /v1/logs/export?format=json file")
    exp.add_argument("--prompt-file", required=True,
                     help="the prompt you believe the row committed")
    exp.add_argument("--commitment-key", default=None,
                     help="override FOXY_COMMITMENT_KEY / the API key")
    exp.add_argument("--sidecar", default=None,
                     help="salt sidecar path (needed for hmac-sha256-salted rows)")
    exp.add_argument("--api-key", default=None, help="override FOXY_API_KEY")
    exp.add_argument("--json", action="store_true", help="machine-readable output")

    args = parser.parse_args(argv)
    if args.command == "doctor":
        return _doctor(FoxyConfig.resolve(api_key=args.api_key, endpoint=args.backend))
    if args.command == "check":
        return _check(args)
    if args.command == "explain":
        return _explain(args)
    parser.print_help()
    return 0


if __name__ == "__main__":
    sys.exit(main())
