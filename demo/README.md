# Foxy Audit Demo

There are three honest test paths.

## Offline verifier demo

Use this when you have no database, API key, or LLM. It uses clearly labelled
synthetic events but real customer-keyed commitments, chain construction,
anchor receipt checking, and tamper detection.

```powershell
python offline_demo.py
```

## Real SDK and backend demo

This path requires PostgreSQL, the backend, an organization API key, and the
SDK. Follow [../backend/README.md](../backend/README.md) to start the backend,
then run:

```powershell
pip install -e ..\sdk
$env:FOXY_API_KEY = "foxy_sk_your_key"
$env:FOXY_BACKEND_URL = "http://127.0.0.1:8000"
python run_demo.py
```

The decorated functions in `run_demo.py` are local stand-ins for a customer's
existing model call. They prove the SDK-to-backend behavior without claiming
that a model was contacted. Replace the function body with the customer's
actual provider call for a client integration test.

With no provider key, capture, chain verification, and deterministic metadata
rules still work. To exercise a real optional judge, set one or both keys in
the backend environment and restart the worker:

```text
GEMINI_API_KEY=...
OPENAI_API_KEY=...
OPENAI_MODEL=gpt-5.6
```

The judges receive hashes and bounded metadata only. They never receive the
raw prompt or response. The real opt-in integration test is documented in
`backend/tests/integration/test_optional_integrations.py`.

## Live GPT-5.6 client demo

Use this path when a judge needs to see a real model call and the actual Foxy
pipeline. It calls the OpenAI Responses API with the chosen model, requires a
durable SDK receipt, waits for the backend worker's genuine metadata verdict,
and verifies the server-owned chain. It never manufactures a provider result.

Start the stack with the same provider key available to the backend and worker:

```powershell
# From the repository root, in Terminal 1.
cd backend
$env:OPENAI_API_KEY = "your_openai_key"
$env:OPENAI_MODEL = "gpt-5.6"
docker compose up --build -d
docker compose logs foxy-seed
```

Then, in a second terminal, use the API key printed by `foxy-seed`:

```powershell
# From the repository root, in Terminal 2.
pip install -e .\sdk
$env:OPENAI_API_KEY = "your_openai_key"
$env:OPENAI_MODEL = "gpt-5.6"
$env:FOXY_API_KEY = "foxy_sk_key_printed_by_the_seed_service"
$env:FOXY_BACKEND_URL = "http://127.0.0.1:8000"
python demo\live_openai_client.py
```

Use non-sensitive content for the demo prompt: the selected OpenAI model sees
it as the customer's provider, while Foxy receives only commitments and bounded
metadata. See [../docs/OPENAI_BUILD_WEEK_SUBMISSION.md](../docs/OPENAI_BUILD_WEEK_SUBMISSION.md)
for the complete judge runbook.

## The agentic loop, end to end (`agentic_demo.py`)

One runnable script that produces the whole narrative **in order**, so a demo
video is a screen recording of a real run rather than a slideshow. It drives the
real SDK against a real local stack, a real hash chain, the real worker and a
real Qwen judge. **Nothing in it is simulated.**

```powershell
# From the repository root. Needs Docker, and QWEN_API_KEY in backend/.env.
python demo/agentic_demo.py
```

Eight beats, each with its own on-screen boundary so they can be cut apart in
editing:

| # | Beat | What you watch happen |
|---|---|---|
| 1 | **GUARD** | PHI under `hipaa`, `mode="block"` — the SDK stops it **before** the model call, and the model function runs zero times. The event that went on the wire is printed verbatim: no prompt, no response, just commitments and bounded metadata. |
| 2 | **CLEAN** | An ordinary prompt. Allowed, and graded `clean` by the AI judge. |
| 3 | **ESCALATE** | The ambiguous case — a `phi_restricted` tag with **empty** `pii_signals`. Qwen calls `flag_for_human_review` and returns `decision="human_review"`. |
| 4 | **QUEUE** | It appears in `GET /v1/reviews`; the pending count goes 0 → 1. |
| 5 | **HUMAN** | A person resolves it `cleared`. The chained row's `chain_hash` is **byte-identical** before and after — the decision is appended, never written over. |
| 6 | **THE LOOP CLOSES** | The same shape again. Qwen calls `check_prior_reviews`, sees that a human cleared this tag, and grades `clean` **instead of** escalating. The agent escalated, a human ruled, the agent learned. |
| 7 | **VERIFY** | Export the ledger and recompute it with `verifier/foxy_verify.py` — stdlib only, zero Foxy imports, intact from genesis. |
| 8 | **TAMPER** | Change one hex character of one `prompt_hash`, re-verify, and watch it fail at exactly that sequence. |

### Re-recording one beat

```powershell
python demo/agentic_demo.py --beats 6          # just the finale
python demo/agentic_demo.py --beats 3-6        # the loop, without the setup
python demo/agentic_demo.py --beats 1,2 --pause
```

`--beats` implies `--reuse-stack`: a partial run acts on state the earlier beats
left behind, so it must not begin by wiping the database. `--pause` waits for
Enter between beats, which is what you want with a recorder running. `--fresh`
forces the wipe anyway, `--no-build` skips the image rebuild, and `--down` tears
the stack down at the end (by default it is left up, because the dashboard is
usually still wanted).

Beat 6 is the second half of beat 5 and **cannot stand alone**: if no human has
cleared a `phi_restricted` escalation yet, it says so and fails rather than
quietly showing a different story. Likewise, if you re-record beat 3 on a stack
that already has cleared reviews, the script warns that it is no longer a clean
slate — `check_prior_reviews` may legitimately stop the very escalation that beat
is there to show.

### The key

`QWEN_API_KEY` is read from `backend/.env` (gitignored) or the environment, and
is stored through `PUT /v1/policies` as an ordinary BYOK key, encrypted at rest
exactly as a customer's would be. It is never printed and never written to an
artifact.

**With no key, the script says so and runs beats 1, 2, 7 and 8 anyway.** Beats
3–6 need a live model, and they are **skipped, never simulated** — there is no
canned Qwen response in that file and there must never be one. The product's
whole thesis is that you can check the evidence instead of trusting the vendor.

Artifacts (the export, the tampered copy, a `summary.json`) land in
`e2e/.artifacts/agentic/run-<id>/`, which is gitignored. The script shares
`e2e/run_e2e.py`'s stack plumbing and its `pip install ./sdk` venv rather than
growing a second copy of either.

### If the judge says it is unavailable but the key is fine

The script tells you which of the two it is. When it reports that the worker
could not open a verified TLS connection, something on the machine is
intercepting HTTPS and re-signing it with a root the **container** has never
heard of. The host is unaffected — Windows trusts it — so this shows up only
inside Docker. It is the same condition that makes `up --build` die on
`CERTIFICATE_VERIFY_FAILED` from PyPI; see
[../e2e/README.md](../e2e/README.md) for the image-build half of it.

Drop the interceptor's root CA, appended to a normal `certifi` bundle, at
`e2e/.artifacts/agentic/ca-bundle.pem`. If that file exists the demo mounts it
into the backend and the worker as their `SSL_CERT_FILE`. The path is gitignored
and nothing machine-specific reaches the repo.

⚠ **That will not rescue every interceptor.** The backend image runs Python
3.13, which turns on `VERIFY_X509_STRICT` by default, so a root that violates
RFC 5280 is refused however you supply it. Norton's "Web/Mail Shield" root is
one of these — its `basicConstraints` extension is not marked critical, and
`openssl s_client -CAfile` accepts it while Python 3.13 does not. On a machine
running that, the only way to reach a live provider is to turn the product's
HTTPS scanning off for the run.

The script never pretends otherwise: with the provider unreachable it says so,
skips beats 3–6, and runs 1, 2, 7 and 8 for real.

## What to show a judge

1. Run `offline_demo.py` and show all four PASS checks.
2. Run `live_openai_client.py` against the local backend and show its four
   actual checks: provider response, receipt, queued verdict, and verification.
3. Open the dashboard ledger and verify the chain.
4. Mutate a test row and rerun verification to show the first broken sequence.
5. Explain that the offline sample is synthetic, while the GPT-5.6 client path
   is a real provider and SDK/backend integration.
