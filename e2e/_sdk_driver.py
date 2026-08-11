"""Drive the INSTALLED foxy-audit SDK against a live backend.

Launched by run_e2e.py inside the isolated venv; never imported. It runs as its
own process on purpose — the SDK registers an ``atexit`` flush, so "the process
exited 0 with an empty spool" is part of what the delivery path promises, and a
caller that stayed alive would not have tested it.

  python _sdk_driver.py <spec.json> <result.json>

The API key arrives in the environment (FOXY_E2E_API_KEY), never in the spec
file, so no file on disk holds it.

Content note: this module sees raw prompt text — it is the customer process.
What it REPORTS is derived facts (did the stub run, does the redacted prompt
still carry the SSN), plus the redacted prompt itself, which is by construction
already scrubbed.
"""

from __future__ import annotations

import json
import os
import sqlite3
import sys
import time
import traceback


def _receipts(spool_path: str) -> tuple[list[dict], int, list[dict]]:
    """Read the SDK's own durable spool: what the server acknowledged, and what
    is still undelivered. Undelivered rows are the interesting half — a green
    run must leave none."""
    conn = sqlite3.connect(spool_path)
    conn.row_factory = sqlite3.Row
    try:
        acked: list[dict] = []
        for row in conn.execute("SELECT event_id, receipt FROM spool_receipts"):
            body = json.loads(row["receipt"])
            for r in (body.get("receipts") or []):
                acked.append(r)
        pending = [dict(r) for r in conn.execute(
            "SELECT event_id, attempts, last_error FROM spool_events")]
        return acked, len(pending), pending
    finally:
        conn.close()


def run(spec: dict, result: dict) -> None:
    import foxy_audit
    from foxy_audit import FoxyClient
    from foxy_audit.client import FoxyPolicyBlocked, FoxyResponseBlocked

    result["sdk"] = {
        "version": getattr(foxy_audit, "__version__", None),
        "module_path": os.path.abspath(foxy_audit.__file__),
    }

    api_key = os.environ.get("FOXY_E2E_API_KEY", "")
    if not api_key:
        raise RuntimeError("FOXY_E2E_API_KEY is not set")

    client = FoxyClient(
        api_key=api_key,
        endpoint=spec["endpoint"],
        desktop_ping=False,          # no desktop fox in this harness
        audit_required=True,         # submit(wait=True): block until the server receipts it
        spool_path=spec["spool_path"],
        timeout=float(spec.get("timeout", 30.0)),
    )
    if not client.enabled:
        raise RuntimeError("SDK resolved to disabled — no API key reached FoxyConfig")

    agents = spec["agents"]
    prompts = spec["prompts"]
    responses = spec["responses"]
    # The response scan is a per-client setting, not a per-decorator one, so the
    # blocking case needs its own client. Same key, same endpoint, same spool —
    # its events land in the same chain as the other three.
    rscan_client = FoxyClient(
        api_key=api_key,
        endpoint=spec["endpoint"],
        desktop_ping=False,
        audit_required=True,
        spool_path=spec["spool_path"],
        timeout=float(spec.get("timeout", 30.0)),
        response_scan="block",
    )

    seen: dict[str, list] = {"clean": [], "blocked": [], "redact": [], "rscan": []}

    # ── the three calls. The "LLM" is a local stub: the seam under test is
    # SDK → HTTP → backend, not any model provider. Each stub records exactly
    # what the SDK handed it, which is how "block never called it" and "redact
    # scrubbed it" become assertions rather than claims.
    @client.audit(policy="default", agent=agents["clean"], mode="observe")
    def call_clean(prompt):
        seen["clean"].append(prompt)
        return responses["clean"]

    @client.audit(policy="default", agent=agents["blocked"], mode="block")
    def call_blocked(prompt):
        seen["blocked"].append(prompt)
        return "THE WRAPPED FUNCTION RAN — the preflight guard did not block"

    @client.audit(policy="hipaa", agent=agents["redact"], mode="redact")
    def call_redact(prompt):
        seen["redact"].append(prompt)
        return responses["redact"]

    # OWASP LLM05. The prompt is clean, so anything that happens is the RESPONSE
    # scan's doing. The stub returns markup that will be rendered; the caller
    # must never receive it, and none of it may reach the wire.
    @rscan_client.audit(policy="default", agent=agents["rscan"], mode="observe")
    def call_rscan(prompt):
        seen["rscan"].append(prompt)
        return responses["rscan"]

    t0 = time.time()
    call_clean(prompt=prompts["clean"])
    result["steps"]["clean"] = {"elapsed_s": round(time.time() - t0, 3)}

    t0 = time.time()
    blocked_raised = None
    try:
        call_blocked(prompt=prompts["blocked"])
    except FoxyPolicyBlocked as exc:
        blocked_raised = str(exc)
    result["steps"]["blocked"] = {
        "elapsed_s": round(time.time() - t0, 3),
        "raised_FoxyPolicyBlocked": blocked_raised is not None,
        "message": blocked_raised,
        "stub_invocations": len(seen["blocked"]),
    }

    t0 = time.time()
    call_redact(prompt=prompts["redact"])
    received = seen["redact"][0] if seen["redact"] else None
    result["steps"]["redact"] = {
        "elapsed_s": round(time.time() - t0, 3),
        "stub_invocations": len(seen["redact"]),
        # The scrubbed prompt verbatim — safe to record, and the point of the step.
        "model_received": received,
        "has_redaction_marker": bool(received and "[REDACTED" in received),
        "still_contains_ssn": bool(received and prompts["redact_ssn"] in received),
        "still_contains_email": bool(received and prompts["redact_email"] in received),
        "still_contains_sentinel": bool(received and spec["sentinels"]["redact_prompt"] in received),
    }

    t0 = time.time()
    rscan_raised, rscan_returned = None, None
    try:
        rscan_returned = call_rscan(prompt=prompts["rscan"])
    except FoxyResponseBlocked as exc:
        rscan_raised = str(exc)
    result["steps"]["rscan"] = {
        "elapsed_s": round(time.time() - t0, 3),
        "raised_FoxyResponseBlocked": rscan_raised is not None,
        "message": rscan_raised,
        "stub_invocations": len(seen["rscan"]),
        # The caller must have received NOTHING. Recording the flag rather than
        # the value: the value is the flagged response.
        "caller_received_a_response": rscan_returned is not None,
        # The exception message is content-blind by contract; assert it here
        # rather than trusting it, and record only the derived facts.
        "message_carries_response_text": bool(
            rscan_raised and (spec["sentinels"]["rscan_response"] in rscan_raised
                              or "<script>" in rscan_raised)),
    }

    result["steps"]["clean_stub_received_prompt_unchanged"] = bool(
        seen["clean"] and seen["clean"][0] == prompts["clean"])

    acked, pending_count, pending = _receipts(spec["spool_path"])
    result["receipts"] = acked
    result["spool_undelivered"] = pending_count
    result["spool_pending_rows"] = pending


def main() -> int:
    with open(sys.argv[1], encoding="utf-8") as fh:
        spec = json.load(fh)
    result: dict = {"ok": False, "steps": {}, "error": None}
    try:
        run(spec, result)
        result["ok"] = True
    except Exception:
        result["error"] = traceback.format_exc()
    with open(sys.argv[2], "w", encoding="utf-8") as fh:
        json.dump(result, fh, indent=2, default=str)
    return 0 if result["ok"] else 1


if __name__ == "__main__":
    sys.exit(main())
