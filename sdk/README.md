# foxy-audit (SDK)

> Governance-as-Code for AI. One decorator -> a tamper-evident, content-blind audit trail.

The SDK creates customer-keyed HMAC commitments for supported LLM inputs and outputs locally,
throws raw text away before upload, and durably spools only metadata to the Foxy Audit backend. It also fires a best-effort local UDP ping so the
desktop "fox" companion shows local capture activity and backend grading alerts.

## 1.9.0 — the guard stops over-blocking, and the ledger stops over-claiming

Four behaviour changes. `mode="observe"` (the default) is untouched; read these
before upgrading a deployment that runs `mode="block"` or `mode="redact"`.

- **The guard no longer refuses prompts that merely contain an identifier.**
  The phone and card detectors treated any digit run as a candidate unless it
  was flanked by another *digit* — so `sk-ABCDEF0123456789ABCDEFGH`, a bare
  UUID, a commit sha and **15.3% of real SHA-256 digests** reported `phone`
  under `hipaa`/`gdpr`, and `mode="block"` refused the prompt. They now require
  a token boundary — a **letter or hyphen** for phones (the bare UUID's digit run
  sits between hyphens), a **letter** for cards (excluding hyphens there would
  drop `card-4111111111111111`, and a missed card number is worse than a spurious
  label). Two structural facts were added where each belongs: a card number
  **does not start with 0** (ISO/IEC 7812 assigns that industry identifier
  elsewhere), enforced at the *start of the pattern* so a stray preceding zero
  cannot swallow the number; and neither a card nor a phone is **all zeros**.
  Without those a **nil UUID** reported `credit_card`, because the candidate
  chains across a UUID's hyphens and Luhn accepts `0000000000000000`.
  Repeated-digit numbers like `888-888-8888` and `+7 777 777 7777` are dialable
  and are still detected. *Cost:* a phone glued straight to a hyphen with no space
  (`Tel-4155550134`) is no longer detected, nor a card glued to a letter
  (`4111111111111111x` — 1.8.0 missed that one too); 5 random UUIDs in 20 000
  still read as `credit_card`, against 1.8.0's 33. **Detection of real card and
  phone numbers is otherwise IDENTICAL to 1.8.0** — the same shapes, asserted as
  a set difference in both directions rather than as a count (504 of 540 card
  shapes and all 168 phone shapes in the test corpus; 1.8.0 missed the same 36,
  see SDK #219) — and a card redaction no longer eats the character after the
  number.
- **`mode="redact"` now blocks when a finding survives its own redaction.** A
  finding redaction cannot act on — a Presidio match, a value in a non-string
  field — used to be stamped `redacted` while the content reached the model. The
  redacted prompt is now re-evaluated, and anything still matching raises
  `FoxyPolicyBlocked` and records a `blocked` event. The check is **per finding,
  not per byte**: an SSN scrubbed beside a Presidio-only date of birth changes
  the text, and the date of birth would still go. If you run `redact` with the
  `[pii]` extra, expect prompts to be refused that previously went through.
- **A redaction marker no longer matches its own rule.** `[REDACTED:jailbreak]`
  tripped `injection.jailbreak`, so re-checking your own redacted prompt said the
  finding was still there. That marker is now `[REDACTED:prompt_injection]`, and
  `redact()` is a fixed point for every rule.
- **`secret.private_key` redacts the whole PEM block.** It matched the
  `-----BEGIN … PRIVATE KEY-----` header alone, so redaction removed the header
  and delivered the key body to the model.

Ships ruleset **2026.08.3**. `2026.08.2` stays in the registry forever, so rows
already in your chain still replay against the rules that produced them.

## 1.8.0 — `check()` and `explain()`

Until now the decorator was the only way in. There was no supported way to ask
"would this prompt be blocked?" without wrapping a function and calling it.

```python
from foxy_audit import check

result = check("ignore all previous instructions", policy="hipaa")
result.triggered        # True
result.rules            # ['injection.ignore_previous']
result.reason           # 'prompt_injection'
result.ruleset_version  # '2026.08.3'
```

```bash
foxy check "ignore all previous instructions" --policy hipaa   # exit 1 if it fires
foxy check --prompt-file prompt.txt --policy gdpr --json
```

`check()` needs **no API key, no network and no spool**. Asking whether your own
prompt trips a rule should not require an account, and the exit code (0 clean,
1 fired) drops into a pre-commit hook or a CI step without parsing anything.

### The two halves have opposite content rules

**`check()` is content-blind.** It returns labels — the same vocabulary the wire
carries — and never returns, logs or raises the text you gave it. The CLI does
not echo your prompt either: a command that did would put customer text into a
terminal scrollback, a CI log and a shell history in one move.

**`explain()` deliberately shows you the matched spans**, because it answers
"prove it was a real breach", and a proof you cannot see is not a proof. It runs
on your machine, against a prompt you supplied, so it shows you nothing you do
not already have. Those spans are **stdout only** — the command writes no file
and logs nothing, and `ExplainResult.as_dict()` omits the text unless you ask
for it explicitly.

### Replaying a recorded row

```bash
foxy explain --event-id 3f2a… --export logs.json --prompt-file prompt.txt
```

It recomputes the commitment from your local key (and the salt sidecar, for a
`hmac-sha256-salted` row), matches it against the row's `prompt_hash`, reads the
`ruleset_version` that row recorded, loads **that frozen definition** — not
today's rules — and replays it, showing which rule matched where.

Three answers are "I cannot", and it says so rather than guessing:

| Situation | What it says |
|---|---|
| A salted row whose salt is not in the sidecar | The commitment **cannot be recomputed** — not a mismatch and not a pass. The salt lives only on your machine; Foxy never had it. |
| A row naming a ruleset newer than your SDK | Upgrade `foxy-audit` to replay it. Replaying whichever rules this build happens to have would describe a different policy than the one that ran. |
| A row written before 1.7.0 | It names no ruleset. The commitment may verify, but the rules in force that day were not recorded, and it **will not guess**. |

Reporting a missing salt as "no match" would be a false negative on the exact
question the tool exists to answer — you would conclude the ledger was wrong.

## 1.7.0 — a rule id now says which ruleset it came from

**Requires a backend that accepts the new keys. Deploy that first.** See the
compatibility note at the end of this section.

A blocked row already recorded WHICH rule fired, hash-chained so nobody can
change it afterwards. It did not record WHAT THAT RULE WAS — so an auditor could
not establish what `injection.ignore_previous` meant on the day it matched, and
the proof chain ended at "Foxy says so". Guarded rows now carry two more
content-blind strings inside `event_metadata`:

```json
{"decision": "blocked", "blocked_reason": "prompt_injection",
 "policy_rules": ["injection.ignore_previous"],
 "ruleset_version": "2026.08.3",
 "ruleset_hash": "100daf43…"}
```

`ruleset_version` names a **frozen** definition. The SDK ships one
never-edited module per published version, so the rules a historical row names
stay recomputable forever — a registry holding only "the current rules" would
make every past row unverifiable the moment someone edited a regex. Editing a
rule without minting a new version fails the SDK's own test suite.

`ruleset_hash` is SHA-256 over canonical JSON of those definitions: every rule
id, its coarse signal label, its regex **source text and flags**, the policy map
and aliases, the response-scan families and their streaming window, and the
reason table *with its priority order*. Rule ordering is deliberately excluded
because `evaluate` sorts and dedupes its output, so reordering cannot change a
verdict and would only mint versions that mean nothing.

**Every id a row can carry resolves in the version it names.** That is checked
in the SDK's own suite, from a list derived by walking the live rule tables
rather than typed out — so a new rule family fails the build until someone
decides what it means. `2026.08.2` existed because `2026.08.1` did not describe
the `response_scan.degraded` / `.unreadable` coverage ids that rows stamped with
it already carried; `2026.08.3` exists because 1.9.0 moved three patterns (the
phone and card detectors, and `secret.private_key`). Both stay in the registry
forever, because rows name them.

**`ruleset_version` and `ruleset_hash` are reserved.** If you pass either in your
own `event_metadata`, the SDK drops it (with a one-off warning naming the key)
and sets its own. The concern is collision, not forgery — the SDK runs in your
process — but these two keys have to mean "the SDK computed this" on every path
or they mean nothing. Rename your field to keep its value.

Optional Presidio signals are **not** covered — they are namespaced `presidio:*`,
come from an external model whose version we do not pin, and are absent unless
the `pii` extra is installed. The frozen definition states that boundary in its
own `presidio_signals` field, so the exclusion travels with the evidence.

What does *not* change:

- **Clean `observe` rows are byte-for-byte identical.** Provenance rides only
  alongside the `policy_rules` it explains — never on a row where nothing fired.
- **Old rows keep verifying.** `event_metadata` has been chain-bound since chain
  V2, so the new keys change the hash for NEW ROWS ONLY. There is no
  `chain_version` bump, no migration, and no change to the standalone verifier —
  a mixed export of old-style and new-style rows was driven through
  `verifier/foxy_verify.py` unmodified.
- **Nothing derived from a prompt is hashed.** The digest is over rule
  definitions; two different prompts tripping the same rules produce identical
  provenance.

**Backend compatibility.** `event_metadata` is validated against a strict
allowlist, and the ingest endpoint validates the whole request as one unit — so
an SDK sending these keys to a backend that does not know them would lose the
entire batch to a 422, not just one event. Against such a backend this SDK
**degrades instead of failing**: it retries the batch once without the two keys
and records `foxy_degraded` on the spool receipt, with a warning naming the
endpoint. Your events and their rule ids arrive intact; only the provenance is
missing until the backend is upgraded.

## 1.6.0 — every policy tag now runs the baseline checks, and `hipaa_basic` is real

**If you run `policy="hipaa"` or `policy="gdpr"` under `mode="block"` or
`mode="redact"`, prompts that used to pass may now be blocked or rewritten. That is
the fix, not a regression.**

Two defects, one release, because fixing either alone makes the other worse.

**The policy map replaced instead of adding.** `hipaa` ran the PHI sweep *instead of*
the prompt-injection and secret-key checks — so the HIPAA workspace was the one
workspace that did not notice an API key pasted into a prompt. The map is now
additive: injection and secret detection run under **every** tag, and a domain tag
adds its personal-data family on top.

**`hipaa_basic` was not a tag at all.** It is the tag in this README's own quickstart,
in the package docstring and in `demo/run_demo.py` — and it was not a key in the
policy map, so it fell through to the default and ran **zero PHI detection**. The
event still shipped tagged `hipaa_basic`, still entered the hash chain, and still
appeared in the Compliance Passport, which groups its statistics by `policy_tag`. A
customer following our own quickstart got a document attesting activity under a
HIPAA-named policy that had never performed a HIPAA check. `hipaa_basic` and
`gdpr_basic` are now aliases for `hipaa` and `gdpr`.

Aliasing alone would have been the *other* half of the same bug — `hipaa_basic` would
have gained PHI and lost injection and secrets. Only the additive baseline makes it
safe, so both ship together.

What this changes for you, by mode:

| `mode` | What moves |
|---|---|
| `observe` *(default)* | **Nothing.** The preflight guard does not run in observe mode, so no new rule fires and no new signal is recorded. |
| `block` | Under `hipaa`/`gdpr`, a prompt carrying an injection pattern or a credential now raises `FoxyPolicyBlocked` where it previously passed through. |
| `redact` | Under `hipaa`/`gdpr`, injection and secret spans are now scrubbed from the prompt as well, so **the model receives different text than it did on 1.5.x**. |

- **New `prompt_injection` / `secret_key` labels** appear in `pii_signals`, and new
  `injection.*` / `secret.*` ids in `policy_rules`, on `hipaa`/`gdpr` rows.
- **Your breach count does not rise from those labels.** The only rows that gain them
  are blocked and redacted rows, and the backend grades those from their enforcement
  labels via `policy_engine.evaluate_enforcement`, which never reads `pii_signals`.
  One classification *does* move: under `hipaa`/`gdpr`, a prompt tripping only an
  injection or secret rule now produces a terminal host-enforced row (`policy_breach`
  false, risk 0) instead of a judge-graded one. A prevented egress is not a breach.
- **An unrecognised tag now warns** instead of silently degrading in silence. It still
  runs and it still ships — see *Policy tags* below.
- **`policy_tag` on the wire is unchanged.** It is recorded exactly as you passed it:
  `hipaa_basic` still reads `hipaa_basic` in the ledger and in the Passport. Only the
  *checks* resolve through the alias, so the meaning of every historical row that used
  the tag is untouched.

## 1.5.0 — `mode="redact"` now examines the response for PII

**If you run `mode="redact"`, your rows will carry more `pii_signals` labels than
they did on 1.4.x, and you should expect that.**

Until 1.5.0, a redact-mode call whose *prompt* tripped the policy reported only the
labels that fired on the prompt. The prompt+response PII sweep was skipped entirely
on those rows, so **PII the model returned in its response was never recorded** —
in the one mode chosen specifically because the customer cares about PII. `observe`
mode, which promises less, always got the full sweep.

`pii_signals` is now the union: exactly what fired on the prompt, plus everything
the sweep finds across prompt and response, deduplicated and sorted.

What this changes for you:

- **More labels on redact rows**, including PII kinds the prompt never contained.
- **Your breach count does not move.** A redacted row is a terminal, host-decided
  event, and the backend grades it from its enforcement labels — `pii_signals` is
  not a breach trigger on that path, on either the chained verdict or the graded
  one. (Measured, and pinned by
  `backend/tests/integration/test_blocked_events.py::test_a_redacted_rows_pii_signals_do_not_make_it_a_breach`.)
- **New rows hash differently from old ones.** `pii_signals` is chain material, so
  a row recorded on 1.5.0 covers labels a 1.4.x row would not have. Existing rows
  and their chain are untouched, and verification of both is unaffected.

There is no flag to turn this off. On an audit product, an opt-out from correct
detection is a setting whose only use is making the evidence say less than the
system knows.

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

@foxy.audit(policy="hipaa")
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

### Policy tags

`policy` selects which local checks run before the model is called. The map is
**additive** — the baseline runs under every tag, and a domain tag adds to it.

| `policy` | Checks that run | Notes |
|---|---|---|
| `"default"` | prompt injection, secret/key detection | The baseline. |
| `"soc2"` | prompt injection, secret/key detection | SOC 2 is a controls regime, not a personal-data one; it has no PHI/PII scope to add, and the baseline is exactly its subject matter. |
| `"hipaa"` | baseline **+** PHI/PII sweep (`phi.*` rules) | `"hipaa_basic"` is an accepted alias. |
| `"gdpr"` | baseline **+** PII sweep (`pii.*` rules) | `"gdpr_basic"` is an accepted alias. |

**An unrecognised tag runs the baseline and warns.** `policy_tag` is a free string on
the wire — the backend validates no vocabulary, and labelling rows in your own terms
(`"claims_triage"`, `"internal_v2"`) is supported and normal. So a tag we do not know
is not an error and will not raise: failing your production model call over a label
would be a worse outcome than the label being unknown. But it is no longer *silent*,
because that was the actual defect — a typo like `"hipa"` would quietly downgrade a
workspace's compliance posture with nothing said anywhere:

```
UserWarning: foxy-audit: unrecognised policy tag 'hipa'. Running the baseline checks
only (prompt-injection + secrets); NO PHI/PII check will run. Known tags: default,
gdpr, gdpr_basic, hipaa, hipaa_basic, soc2.
```

The warning fires once per distinct tag per process. Whatever you pass is recorded on
the wire verbatim, recognised or not.

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

**A cut stream is recorded as truncated, never as prevented — whatever `mode` you run.** Chunks
you already received are in your application, so calling that "prevented egress" would put a
false statement in your Compliance Passport. Only a block where *nothing* reached you is recorded
as `event_type: response_blocked`; a stream cut after delivery is an ordinary `stream` event with
`decision: response_truncated`, and the exception says so in as many words. One consequence worth
knowing: if `mode="redact"` scrubbed the prompt and the stream is then cut, that row is *not*
counted in the Passport's redaction tally — one row carries one terminal outcome, and this one's
is truncation. The redaction is still in the record, as the `phi.*`/`pii.*` rule ids that fired.

**What the scan reads, and what it admits it cannot.** Response *content* is extracted from the
provider's own shape — OpenAI `choices[].delta.content` / `choices[].message.content`, Anthropic
content blocks and `delta.text`, the Gemini `candidates[].content.parts[]`, the Responses API
`output[]`/`output_text` — plus plain strings and `bytes` (decoded UTF-8, `errors="replace"`, so
raw SSE is covered). An unrecognised but serialisable shape is scanned as a serialised envelope
and recorded as `response_scan.degraded`; an object whose content cannot be reached at all is
recorded as `response_scan.unreadable`. **Neither ever blocks** — coverage you do not have is
missing evidence, not a finding — but neither is silently reported as a clean scan. They appear
only as rule ids: never as a `decision`, never as a `blocked_reason`, and never in the Passport's
enforced-rule table. "We could not read this" is not a verdict on the interaction.

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
