# Full-stack E2E — one prompt, all the way through

```bash
python e2e/run_e2e.py
```

That is the whole command. It brings the local stack up, drives the real SDK
over HTTP, waits for the worker, asserts the customer API, screenshots the
dashboard, and prints a machine-readable summary. Exit code 0 = pass.

This is a **test, not a feature.** It does not move the product; it tells us
whether the seam works.

---

## Why it exists

Everything in this repo was already proven from one side or the other:

| already covered | by |
|---|---|
| ingest → chain → verify, including tamper | `backend/tests/integration`, in CI against a real Postgres |
| policy → judge wiring | same |
| anchoring | same, stub provider |
| SDK block/redact decisions | `sdk/tests/test_policy.py` — block never calls the wrapped fn, across sync, async, both generator forms, and the no-API-key path |
| dashboard rendering | 407 guards in `foxy-dashboard/` |

**Two seams had nothing.** Every backend test injects synthetic input straight
into the app, so nothing had ever gone over the wire from the real client. And
the judge pipeline was only ever asserted from the database side, never from the
surface a customer actually reads.

---

## What it proves

Each line below is a check the script fails on. `summary.json` in the run's
artifact directory carries them all with their detail.

**The SDK → HTTP seam**
- The SDK **as `pip install` produces it** — see [Which SDK](#which-sdk) — reaches
  the backend over real HTTP with a real bearer key, and the backend receipts
  all three events.
- The SDK's durable spool is **empty** afterwards: nothing was left undelivered
  and quietly counted as sent.
- The call **order** survives the wire (`client_seq` 1, 2, 3).

**Host-side enforcement, from the customer's process**
- `mode="block"`: `FoxyPolicyBlocked` is raised and **the wrapped function never
  ran** — asserted from inside the wrapped function, which records every call it
  receives, so "0 invocations" is a measurement rather than a claim.
- `mode="redact"`: the model **was** called, and what it received carries
  `[REDACTED:…]` markers and **no longer contains the SSN or the email address**
  that were in the original prompt.
- Observe mode passes the prompt through unchanged.
- Each lands in the ledger typed correctly (`blocked` / `redacted` /
  `interaction`) with its decision and PHI signals.

**The worker → judge → surface seam**
- Every row leaves `pending` and reaches a real terminal state, polled with a
  bounded timeout. On timeout it prints the state each row was actually in.
- With no provider key (the default) **no provider is called and nothing is
  billed** — `judge_provider` and `judge_model` are NULL on every row. That is
  the claim, and it is asserted directly rather than inferred from a reason
  string.
- ⚠ **`evaluator_unavailable` never reaches the ledger**, and the run asserts that
  it does not. It is real inside `judge_routing` / `_judge_verdict`, but the
  worker converts it twice over: `worker.py:205` sends `blocked` and `redacted`
  events to `policy_engine.evaluate_enforcement` without ever asking a judge, and
  `worker.py:217` catches an unavailable verdict on every other row and replaces
  it with `policy_engine.evaluate`. So the observable terminal state of a keyless
  run is a **deterministic local verdict** — `host_blocked_egress:…`,
  `host_redacted_response:…`, and `clean / "deterministic metadata checks passed;
  semantic content not evaluated"` — each of which is asserted by name. This
  contradicted the plan this test was written from; see
  [docs/plans/full-stack-e2e.md](../docs/plans/full-stack-e2e.md).
- `/v1/verify` recomputes the chain intact.
- Every endpoint the dashboard reads answers 200 over **both** auth paths (the
  SDK bearer key and the dashboard session cookie), and the cookie session
  resolves to the **same org** as the key — compared by chain head, because
  `/v1/auth/me` deliberately carries no org id.
- The dashboard renders that ledger, signed in, in a real browser.

**Content-blindness — the assertion that matters most**
- 11 needles (each raw prompt and response in full, each sentinel token, the
  SSN, the email address) are searched for in:
  - every `/v1/*` response body, over both auth paths;
  - `/v1/logs/export` as JSON and as CSV;
  - `/v1/logs/export?format=bundle`, **decompressed** — a ZIP searched as bytes
    would find nothing whether or not the string is in there;
  - **every column of every table** in the database. The query renders each row
    with `t::text`, so it covers columns nobody thought to list, including ones
    added later;
  - the **rendered dashboard DOM**, captured from the live browser.
- A **negative control** runs beside it, every run: a string that IS stored (the
  agent name) must be **found** by each sweep. A search that returns nothing
  because it is broken looks exactly like a search that returns nothing because
  the product is content-blind. This is the check that tells them apart.

---

## What it does NOT prove

Being precise here is the point of the exercise — the test exists to close an
honesty gap, so overclaiming in its own docs would defeat it.

- **It does not test a real model provider.** The "LLM" inside each wrapped
  function is a local stub that records what it was handed. The seam under test
  is SDK → backend; the stub is what makes "block never called it" and "redact
  scrubbed it" *measurable*. Nothing here says anything about OpenAI or Gemini
  behaviour.
- **It does not test production.** It runs `backend/docker-compose.yml` on
  localhost. Prod differs in at least TLS, the reverse proxy, cookie `secure`
  flags, `ADMIN_IP_ALLOWLIST`, and real anchoring.
- **It does not prove content-blindness for prompts unlike these three.** It
  proves that *these* strings are absent from *these* surfaces. It is a
  falsification test, not a proof. A leak through a path none of these three
  prompts exercises would not be caught.
- **It does not search the screenshot.** A PNG cannot be grepped. The DOM the
  browser rendered is captured separately and swept instead; that is the honest
  equivalent, and it is what the negative control is measured against too.
- **It does not test the judge's judgement.** Default: no key, no call. With
  `--live-judge`: exactly one real call, and only the *shape* of the verdict is
  asserted — a real judge is non-deterministic, and asserting its content would
  be asserting today's mood.
- **It does not test multi-tenancy or RLS isolation.** One org, one key. The
  database sweep deliberately runs as the superuser so it can see *every* org's
  rows — that makes the leak search complete, and it means the run says nothing
  about whether tenant A can read tenant B.
- **It does not test the anchoring path, retries, quota/billing gates, MFA, or
  the admin console.** Those have their own coverage.
- **It is not CI.** Actions minutes are exhausted and deploys are already manual.
  It is written CI-shaped — no interactive steps, real exit codes, a
  machine-readable summary, no reliance on a developer's local state (every
  `FOXY_*` variable in the ambient environment is stripped from child processes,
  since a stray `FOXY_MODE` would silently change the decision under test) — so
  promoting it later should be a workflow file, not a rewrite.

---

## Requirements

- Docker Desktop / a Docker daemon, and ports **8000** and **5432** free.
- Python 3.10+ and **network access on the first run** — it builds `./sdk` with
  hatchling and installs `requests` + `websockets` into an isolated venv at
  `e2e/.artifacts/venv`.
- Google Chrome, for the screenshot. Set `E2E_CHROME` if it is somewhere
  unusual, or pass `--no-screenshot`.

⚠ **This is not the pytest database.** It runs the `backend/docker-compose.yml`
stack on `foxy`/`5432`. `backend/tests/` uses a separate native Postgres on
`5433`/`foxy_pytest` and is untouched.

**If `up --build` dies on `CERTIFICATE_VERIFY_FAILED` from PyPI**, something on
the machine is intercepting TLS and the *container* does not trust it. On the
machine this was written on that was Norton's "Web/Mail Shield" — every
`pip install` inside every Docker build fails, including this repo's, and
including `docker run --rm python:3.11-slim pip install fastapi`. That is a local
environment condition, not a repo problem, and the fix does not belong in the
committed `Dockerfile`. Build the image once out of band, then run with
`--no-build`:

```bash
sed 's#RUN pip install --no-cache-dir#RUN pip install --no-cache-dir \
  --trusted-host pypi.org --trusted-host files.pythonhosted.org#' \
  backend/Dockerfile > /tmp/Dockerfile.local
docker build -f /tmp/Dockerfile.local \
  -t backend-foxy-backend -t backend-foxy-migrate \
  -t backend-foxy-seed -t backend-foxy-worker backend
python e2e/run_e2e.py --no-build
```

Keep `/tmp/Dockerfile.local` out of the repo. CI and the VM deploy build the real
`Dockerfile` unmodified.

---

## Flags

| flag | effect |
|---|---|
| *(none)* | cold start: `compose down -v`, then `up --build`. Deterministic and idempotent. |
| `--reuse-stack` | run against the stack already up, **exactly as it is** — no `down`, no `up`. See [Re-seeding](#re-seeding). |
| `--no-build` | `up -d` without `--build`. Faster, and the escape hatch when the image cannot be built here — see [Requirements](#requirements). |
| `--no-screenshot` | skip step 8. The API assertions are the gate; the screenshot is the artifact. |
| `--live-judge` | one real, **billed** grading call. See below. |
| `--grading-timeout` | seconds to wait for the worker (default 120). |
| `--ready-timeout` | seconds to wait for `/health/ready` (default 300). |

### `--live-judge`

Off by default, never in a committed env file, and it costs money.

It needs `E2E_GEMINI_API_KEY` or `E2E_OPENAI_API_KEY` in the environment. Two
things about it are worth knowing before you run it:

1. **The committed compose sets no `PROVIDER_KEY_ENCRYPTION_KEY`**, so the stack
   as shipped cannot store a BYOK key at all — `PUT /v1/policies` answers 503.
   The flag generates a run-scoped KEK into a compose *override* under
   `.artifacts/` (gitignored) and brings the stack up with it. The committed file
   is never modified.
2. **Exactly one call is made**, and the run asserts the split rather than
   assuming it. The key is stored *after* the first three events are already
   graded, then three more are sent — of which only the plain `interaction` row
   reaches a provider, because `worker.py:205` routes the `blocked` and
   `redacted` rows to the deterministic evaluator and never asks a judge. The run
   checks that both of those still carry a NULL `judge_provider`, and that the
   interaction row carries the provider and model it actually used.

---

## Re-seeding

`foxy-seed` prints the plaintext API key **exactly once**; only its SHA-256 is
stored, and it cannot be re-derived.

`seed_org.py` **does not dedupe by name**, and `docker compose up` restarts the
exited one-shot `foxy-seed` container. So **every `up` against a kept volume
mints another "Demo Corp"** — another org, another key, and another admin row
carrying the same email and the same password. `POST /v1/auth/login`
authenticates against every candidate and lets the password select the org; with
two identical passwords, the winner is index-scan order.

This is not theoretical. An earlier draft of this script had a `--no-reset` flag
that skipped only the `down -v`, and the first two failure demos written against
it both went red *for the wrong reason*: the `up` had handed the run a brand new,
empty, unbroken org, so the corrupted row and the revoked key were invisible. The
check that caught it is the one below.

How this script handles it:

- **Default** — `compose down -v`, then up. Exactly one org exists. The run is
  idempotent: run it twice in a row and both are green.
- **`--reuse-stack`** — touches compose *not at all*, so nothing re-seeds. This is
  the flag the break-it-on-purpose recipes need.
- **Either way**, the run takes the **newest** printed key, warns when it sees
  more than one, and asserts that the cookie session and the API key resolve to
  the **same chain head**. If a duplicate org wins the login, that goes red rather
  than silently screenshotting the wrong workspace.

The dashboard screenshot never depends on this: it signs in with a
`/v1/auth/handoff` token minted **with the API key**, which is the path the
desktop app uses, and which binds the browser session to the same org the SDK
just wrote to.

---

## Which SDK

The script builds `./sdk` and `pip install`s it into a fresh venv at
`e2e/.artifacts/venv`, then re-execs itself inside it. It reports the version and
the resolved module path in its output.

That is deliberate, and it is not the same as either alternative:

- **Not `import` from `sdk/src/`** — that would skip packaging entirely. A module
  missing from the wheel would pass here and fail at a customer's desk.
- **Not whatever is already installed.** On the machine this was written on,
  `backend/.venv` held foxy-audit **1.2.0**, missing `org_policy.py` and
  `sidecar.py` — two modules the 1.3.0 source tree has. Driving that would have
  tested code this repo no longer contains.

`pip install ./sdk` is what a customer of *this commit* gets, and it exercises
the packaging config on the way.

---

## Artifacts

Each run writes to `e2e/.artifacts/run-<id>/` (gitignored):

```
summary.json          every check, pass/fail, with detail
sdk_spec.json         the prompts the run used
sdk_result.json       what the SDK did, and what each stub received
spool.sqlite3         the SDK's own durable spool -- holds the live API key
dashboard-ledger.png  the screenshot
dashboard-dom.html    the rendered DOM, which is what the sweep actually searched
chrome_result.json    what the browser reported
```

⚠ **The printed API key must never be committed.** It is passed to the SDK driver
through the environment, never through a file — but the SDK's own spool stores it
by design, so `.artifacts/` is gitignored in full. Do not move anything out of it
without looking first.

The seeded credentials (`admin@demo.test` / `adminpass123`) are dev-only and
already in `backend/docker-compose.yml`. They are not a secret and are not
treated as one.

---

## Making it fail on purpose

A test you have never watched go red is not evidence. All four of these were run,
and the message each produced is quoted. Start from a green run (which leaves the
stack up), break one thing, then re-run with **`--reuse-stack`** — plain
`--no-build` would `up` the stack and re-seed a fresh org, hiding the break.

```bash
python e2e/run_e2e.py                       # green; leaves the stack running
export CF=backend/docker-compose.yml
```

**1 · Corrupt a chain row.**

```bash
docker compose -f $CF exec -T db psql -U foxy -d foxy \
  -c "UPDATE audit_logs SET token_count = token_count + 1 WHERE seq = 2"
python e2e/run_e2e.py --reuse-stack
#   FAIL  /v1/verify recomputes the chain intact
#         count=6 detail=chain hash mismatch at seq 2
```

**2 · Revoke the API key.** Both paths, or it still authenticates:
`auth.require_org` falls back to the legacy `organizations.api_key_hash` when the
peppered `api_keys` row does not match.

```bash
docker compose -f $CF exec -T db psql -U foxy -d foxy -c \
  "UPDATE api_keys SET status='revoked'; \
   UPDATE organizations SET api_key_hash = 'revoked-'||id::text;"
python e2e/run_e2e.py --reuse-stack
#   FAIL  SDK driver completed
#         foxy_audit.client.AuditRequiredError: Foxy Audit could not durably
#         deliver the event  ...  "Foxy Audit server receipt was not received"
```

**3 · Stop the grading worker.**

```bash
docker compose -f $CF stop foxy-worker
python e2e/run_e2e.py --reuse-stack
#   FAIL  all three rows reached a terminal grading state
#         actual: {"66cef384-...": "pending", "db1ccead-...": "pending", ...}
docker compose -f $CF start foxy-worker
```

Step 4 is what catches it, and it prints the state each row was *actually* in.
(If the worker has been down for more than ~35s before you start — the heartbeat
staleness window — step 1's `/health/ready` wait fails first instead, printing
the container states.)

**4 · Break the sweep itself.** This is the one the negative control exists for.
Point `db_find` at a needle that cannot match and re-run:

```
  PASS  no raw prompt/response text in ANY database column (11 needles x 37 tables)
  FAIL  negative control: the DB sweep FINDS a string that is present
        e2e-clean-ccfajltgqqnj found in []
```

The content-blindness check keeps reading green — of course it does, a broken
search finds nothing — and the control takes the run red anyway. Without it,
sabotaging the sweep would look exactly like a clean bill of health.

Each demo leaves the stack dirty on purpose. A plain `python e2e/run_e2e.py`
resets it.

---

## The machine-readable summary

The last line of stdout is always:

```
E2E_SUMMARY {"result":"PASS","run":"…","checks_total":41,"checks_failed":0,…}
```

with `grading_wall_seconds`, the per-row `created_at → graded_at` latency
straight from the database, the SDK version and module path actually used, the
content-blindness counts, and any hits. Exit code follows `result`.
