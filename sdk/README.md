# foxy-audit (SDK)

> Governance-as-Code for AI. One decorator -> a tamper-evident, content-blind audit trail.

The SDK creates customer-keyed HMAC commitments for supported LLM inputs and outputs locally,
throws raw text away before upload, and durably spools only metadata to the Foxy Audit backend. It also fires a best-effort local UDP ping so the
desktop "fox" companion shows local capture activity and backend grading alerts.

## Install

```bash
pip install -e .            # from this sdk/ folder, for local development
```

Runtime dependency: `requests` only.

## Use

```python
import os
from foxy_audit import FoxyClient

foxy = FoxyClient(api_key=os.getenv("FOXY_API_KEY"))   # or just rely on the env var

@foxy.audit(policy="hipaa_basic")
def ask_model(prompt: str) -> str:
    return llm_client.generate(prompt)     # your existing code — unchanged
```

Every call to `ask_model` is now hashed, logged, and graded. Or use the module-level decorator,
which builds a client from the environment:

```python
from foxy_audit import audit

@audit(policy="soc2")
def summarize(text: str) -> str:
    ...
```

### Attributing the model (`agent`)

Pass `agent=` to record *which* model produced the interaction. The backend folds it into the
tamper-evident hash chain, so the attribution can't be altered after the fact:

```python
@foxy.audit(policy="soc2", agent="gpt-4o")
def ask_model(prompt: str) -> str:
    ...
```

`agent` is optional — rows logged without it hash exactly as before, so existing chains keep
verifying.

### Scanning the response (OWASP LLM05 — Improper Output Handling)

`mode` governs the **prompt**. `response_scan` governs what came **back**: markup that will be
rendered, a SQL statement the caller might execute, an SSRF-shaped URL, a secret the model
echoed, and — under `hipaa`/`gdpr` — personal data the model returned that the prompt never
contained.

| `response_scan` | What happens |
|---|---|
| `"observe"` *(default)* | Detect and record the rule ids. Nothing is prevented, nothing is rewritten. |
| `"block"` | The caller never receives a flagged response; `FoxyResponseBlocked` is raised instead. |
| `"off"` | No scan at all. |

```python
foxy = FoxyClient(api_key=..., response_scan="block")   # or FOXY_RESPONSE_SCAN=block
```

**It never rewrites a response.** There is no response-side "redact" under any mode, and
`mode="redact"` scans the response exactly as `observe` does. Prompt redaction changes what the
*model* sees; response redaction would change what *your* parser, database and UI receive — and
for a provider response object, which is not a string, it would silently do nothing at all.

**On a streamed response, blocking is partial. This is architectural, not a bug.** A generator
hands each chunk to you as it arrives and a chunk cannot be un-yielded. Under
`response_scan="block"` each chunk is scanned *before* it is yielded, with a 256-character
carry-over window so a match split across a boundary is still caught, and the stream is
terminated at the first flagged chunk — so the rest never arrives, but **everything already
yielded has already been delivered**. Two bounds follow: a pattern whose halves land further
apart than that window is not prevented, and the scan adds per-chunk latency. A completed
stream is re-scanned whole in both modes, so the evidence record is exact even where prevention
was not. Buffering the whole stream would make blocking total and would silently turn a
streaming API into a non-streaming one, so the SDK does not do it.

**A cut stream is recorded as truncated, never as prevented.** Chunks you already received are
in your application, so calling that "prevented egress" would put a false statement in your
Compliance Passport. Only a block where *nothing* reached you is recorded as
`event_type: response_blocked`; a stream cut after delivery is an ordinary `stream` event with
`decision: response_truncated`, and the exception says so in as many words.

**What the scan reads, and what it admits it cannot.** Response *content* is extracted from the
provider's own shape — OpenAI `choices[].delta.content` / `choices[].message.content`, Anthropic
content blocks and `delta.text`, the Gemini `candidates[].content.parts[]`, the Responses API
`output[]`/`output_text` — plus plain strings and `bytes` (decoded UTF-8, `errors="replace"`, so
raw SSE is covered). An unrecognised but serialisable shape is scanned as a serialised envelope
and recorded as `response_scan.degraded`; an object whose content cannot be reached at all is
recorded as `response_scan.unreadable`. **Neither ever blocks** — coverage you do not have is
missing evidence, not a finding — but neither is silently reported as a clean scan.

**`audit_required` does not hide a block.** If the audit event cannot be durably delivered, you
still get `FoxyResponseBlocked`, with `audit_delivery_failed=True` on it. The security decision
outranks the delivery guarantee.

**Upgrading from 1.3.x changes nothing you receive.** The default detects and records; it never
raises and never rewrites. A response that trips nothing emits the identical payload it emitted
before. Turning on prevention is a deliberate `response_scan="block"`.

These are regexes, not a parser — a model *explaining* SQL will trip `response_sql.destructive`.
That is exactly why prevention is opt-in.

## Configuration

| Setting        | Kwarg          | Env var             | Default                  |
|----------------|----------------|---------------------|--------------------------|
| API key        | `api_key`      | `FOXY_API_KEY`      | _(none → HTTP disabled)_ |
| Backend URL    | `endpoint`     | `FOXY_BACKEND_URL`  | `http://127.0.0.1:8000`  |
| Desktop ping   | `desktop_ping` | —                   | `True` (127.0.0.1:9999)  |
| Commitment key | `commitment_key` | `FOXY_COMMITMENT_KEY` | API key when omitted |
| Salt sidecar | `salt_sidecar_path` | `FOXY_SALT_SIDECAR` | _(none → commitments unsalted)_ |
| Durable spool | `spool_path` | `FOXY_SPOOL_PATH` | `~/.foxy-audit/spool.sqlite3` |
| Stable client id | `client_id` | `FOXY_CLIENT_ID` | persisted in the local spool when omitted |
| Required capture | `audit_required` | `FOXY_AUDIT_REQUIRED` | `False` |
| Prompt guard mode | `mode` | `FOXY_MODE` | `observe` (`block` / `redact` enforce before the call) |
| Response scan | `response_scan` | `FOXY_RESPONSE_SCAN` | `observe` (`block` prevents, `off` disables) |

### Salted commitments (optional)

Set `salt_sidecar_path` and each event gets a fresh 128-bit salt, mixed into the HMAC
canonically — `HMAC(key, {"s": salt, "v": <canonical text>})`, never by concatenation.
The salt is appended to that local JSONL file and **never leaves your process**: not the
wire, not our database, not a response, not a log line. Those rows report
`commitment_alg: "hmac-sha256-salted"`; leave the setting unset and commitments are
byte-identical to what the SDK has always produced.

The trade: lose that sidecar and you lose the ability to prove *which* text those
commitments cover (`foxy_verify.py --commitment-key --events` reports them as not
checked). You keep chain verification either way — tamper-evidence is recomputed from
stored fields and never needs the salt.

With no API key the SDK is a **graceful no-op for the cloud path**: it still runs your function and
still pings the desktop fox, but skips the HTTP upload. In the default mode, delivery is best-effort;
for regulated workflows, set `audit_required=True` so the decorator waits for a server receipt and
raises when durable delivery cannot be confirmed.

## Guarantees

- **Default path is asynchronous** — the HTTP upload runs on a background daemon thread after a local durable enqueue.
- **Retries do not discard events** — failed uploads remain in the SQLite/WAL spool.
- **Content-blind by design** — commitments, token counts, policy tags, and bounded identifiers leave the host; raw text is not sent by the SDK. The response scan is no exception: it emits rule ids such as `response_markup.script_tag`, never the matched text, never an offset, never a length.
- Works with **sync, async, sync-generator and async-generator** functions. Host return values are passed through unchanged — the one exception is `response_scan="block"`, which raises `FoxyResponseBlocked` instead of returning a flagged response, and which is off unless you turn it on.

## What gets sent

To the backend (`POST /v1/logs`, `Authorization: Bearer <key>`):

```json
{"event_id": "<uuid>", "client_id": "...", "client_seq": 1, "commitment_alg": "hmac-sha256", "prompt_hash": "<64 hex>", "response_hash": "<64 hex>", "token_count": 123, "policy_tag": "hipaa_basic"}
```

To the desktop fox (UDP `127.0.0.1:9999`):

```json
{"event": "hash_ok", "policy": "hipaa_basic", "tokens": 123, "ts": 1719300000}
{"event": "policy_breach", "reason": "...", "risk_score": 87, "policy": "hipaa_basic", "ts": ...}
```
