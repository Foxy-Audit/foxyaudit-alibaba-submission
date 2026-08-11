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

    seen: dict[str, list] = {"clean": [], "blocked": [], "redact": [],
                             "rscan": [], "rstream": []}

    class _Delta:
        def __init__(self, content):
            self.content = content

    class _Choice:
        def __init__(self, content):
            self.index = 0
            self.delta = _Delta(content)

    class _Chunk:
        """The shape a customer streaming from OpenAI actually receives.

        NOT a hand-written dict that happens to work: the defect this exists to
        catch was that the scanner serialised the chunk and carried the JSON
        envelope, so two halves of a split match ended up ~30 characters apart
        and rejoined nothing. A plain dict would have hidden it."""

        def __init__(self, content):
            self.id = "chatcmpl-e2e"
            self.object = "chat.completion.chunk"
            self.model = "stub-stream"
            self.choices = [_Choice(content)]

        def model_dump(self):
            return {"id": self.id, "object": self.object, "model": self.model,
                    "choices": [{"index": c.index,
                                 "delta": {"content": c.delta.content}}
                                for c in self.choices]}

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

    # The same scan on a STREAM of provider-shaped chunks, with the markup split
    # across a chunk boundary. The first fragment is delivered before the match
    # completes, so this is truncation, not prevention.
    @rscan_client.audit(policy="default", agent=agents["rstream"], mode="observe")
    def call_rstream(prompt):
        seen["rstream"].append(prompt)
        for part in responses["rstream_parts"]:
            yield _Chunk(part)

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
    rscan_raised, rscan_returned, rscan_exc = None, None, None
    try:
        rscan_returned = call_rscan(prompt=prompts["rscan"])
    except FoxyResponseBlocked as exc:
        rscan_raised, rscan_exc = str(exc), exc
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
        # This client runs audit_required=True. The block must still be what the
        # caller sees, and the flag must report delivery honestly.
        "audit_delivery_failed": (rscan_exc.audit_delivery_failed
                                  if rscan_exc is not None else None),
    }

    t0 = time.time()
    delivered, rstream_raised = [], None
    try:
        for chunk in call_rstream(prompt=prompts["rstream"]):
            delivered.append(chunk)
    except FoxyResponseBlocked as exc:
        rstream_raised = str(exc)
    result["steps"]["rstream"] = {
        "elapsed_s": round(time.time() - t0, 3),
        "raised_FoxyResponseBlocked": rstream_raised is not None,
        "message": rstream_raised,
        "stub_invocations": len(seen["rstream"]),
        # The whole point: something DID arrive before the cut. Count only —
        # the chunks themselves are response content.
        "chunks_delivered": len(delivered),
        "chunks_offered": len(responses["rstream_parts"]),
        "message_says_chunks_were_delivered": bool(
            rstream_raised and "already reached your code" in rstream_raised),
        "message_carries_response_text": bool(
            rstream_raised and (spec["sentinels"]["rstream_response"] in rstream_raised
                                or "<script>" in rstream_raised)),
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
