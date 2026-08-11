# Full-stack E2E — one prompt, all the way through

Planned 2026-08-11 against `main` @ `ea248fc`. Closes the only genuine coverage
gap on the product, identified in a teammate review and confirmed against the
repo.

## Why this exists

Nobody has watched a prompt go **SDK → HTTP → backend → chain → worker → judge →
the surfaces a customer reads**, on a running stack. Everything today is proven
from one side or the other:

| already covered | by |
|---|---|
| ingest → chain → verify, incl. tamper | `backend/tests/integration` in CI, against real Postgres |
| policy → judge wiring | same |
| anchoring | same, stub provider |
| SDK block/redact decisions | `sdk/tests/test_policy.py` — block never calls fn across sync, async, both generator forms, and no-API-key |
| dashboard rendering | 407 guards in `foxy-dashboard/` |

**The two seams nobody tests:** SDK → HTTP (every backend test injects synthetic
input directly, never over the wire from the real client), and worker → judge →
what the dashboard actually reads (asserted from the DB side, never from the
surface).

⚠ **This is a TEST, not a feature.** It does not move the product; it tells us
whether the seam works. That distinction was the one substantive disagreement
with the review that prompted it.

## Owner decisions, taken 2026-08-11

1. **Judge: both.** Default run needs no key and no money — the event lands on
   the *designed* `evaluator_unavailable` terminal state (`judge_routing.py`:
   with no own key a provider is *"simply skipped (an honest
   `evaluator_unavailable`), never silently billed"*). A `--live-judge` flag
   makes exactly one real grading call for the full claim.
2. **Dashboard: API assertions plus one screenshot.** The API assertions are the
   gate. The screenshot is the artifact you can show someone.
3. **Local script with a documented command.** Not CI — Actions minutes are
   exhausted and deploys are already manual. Written CI-shaped (no interactive
   steps, real exit codes, machine-readable summary) so promoting it later is a
   workflow file, not a rewrite.

## What the stack gives you

`backend/docker-compose.yml` — five services: `db`, `foxy-migrate`, `foxy-seed`,
`foxy-backend`, `foxy-worker`.

`foxy-seed` runs
`seed_org.py --name "Demo Corp" --admin-email admin@demo.test --admin-password adminpass123`
and **prints the plaintext API key exactly once** — only its SHA-256 is stored,
so it must be scraped from the seed logs, never re-derived.

The dashboard reads `/v1/logs`, `/v1/logs/breaches`, `/v1/verify`,
`/v1/analytics/*`.

## The shape

1. Bring the stack up; wait on `/health/ready`, not on a sleep.
2. Scrape the API key from `docker compose logs foxy-seed`.
3. Drive the **real installed SDK** — three calls: one clean, one that must be
   blocked before the model call, one that must be redacted.
4. Poll until the worker has moved the rows off `pending`.
5. Assert the customer API: the events exist, the chain verifies, the blocked
   one never produced a model call, and no raw prompt text is anywhere in any
   response.
6. Log into the dashboard as the seeded admin and screenshot the ledger.
7. Print a machine-readable summary and exit non-zero on any failure.

## Hard rules this test must not break

- **Content-blindness is the product.** The test must assert that the raw prompt
  and response text appear **nowhere** in any API response or database column.
  That assertion is more valuable than everything else in the script.
- **No fake data.** If a step cannot run, it fails loudly. It never fabricates a
  row, a verdict, or a green.
- **Never `taskkill` chrome by name** — it closes the owner's real browser.
  Bound the render subprocess instead.
- The seeded credentials are dev-only and already in the compose file; they are
  not a secret and must not be treated as one, but the printed API key must not
  be committed.

## Open risks, named

- **`--live-judge` is non-deterministic.** It can assert the *shape* of a
  verdict, never its content.
- **A screenshot proves less than it looks like it does** unless what it shows
  is also asserted through the API. The API assertions are the gate; the image
  is an artifact.
- **The worker is asynchronous.** Any wait must poll a real terminal state with
  a bounded timeout, never sleep a guessed number of seconds.

---

## Built 2026-08-11 — `e2e/run_e2e.py`, branch `test/full-stack-e2e`

Shipped as `e2e/run_e2e.py` + `e2e/_sdk_driver.py` + `e2e/_chrome.py`, with
`e2e/README.md` covering what it proves **and what it does not**. 56 checks,
green twice in a row from a cold `compose down -v`, and watched go red four
different ways.

### Corrections to this plan, found by reading and running the code

**1 · `evaluator_unavailable` is not the terminal state.** This plan (and the
prompt it came from) said a keyless run lands on
`decision=unknown / evaluator_unavailable:…`. It does not, and it cannot: the
worker converts that verdict away twice over before it is ever written.

- `worker.py:205` — a `blocked` or `redacted` event goes to
  `policy_engine.evaluate_enforcement` and **the judge is never asked**. The
  ledger records `host_blocked_egress:prompt_injection` /
  `host_redacted_response:phi`, `decision` = the event type, `policy_breach`
  false.
- `worker.py:217` — on every other row, an `evaluator_unavailable` verdict from
  `_judge_verdict` is caught and **replaced** with `policy_engine.evaluate`.
  A clean interaction therefore reads `decision=clean`, reason
  `"deterministic metadata checks passed; semantic content not evaluated"`.

The `judge_routing.py` docstring quoted in this plan is accurate *about
`judge_routing`* — the plan's mistake was reading a module docstring as a
statement about the ledger. The claim worth asserting is the one underneath it,
and the test asserts that instead: **`judge_provider` and `judge_model` are NULL
on every row, so no provider was called and nothing was billed.** It also asserts
that `evaluator_unavailable` never surfaces, so if that ever changes it is
noticed here.

Arguably the shipped behaviour is better than the plan assumed — a customer is
never shown a blank "we could not evaluate this".

**2 · `--live-judge` cannot work against the committed compose file.**
`backend/docker-compose.yml` passes no `PROVIDER_KEY_ENCRYPTION_KEY`, so the
stack as shipped cannot store a BYOK key at all — `PUT /v1/policies` answers 503
from `_store_key`. The flag generates a run-scoped KEK into a compose *override*
under the gitignored `.artifacts/` and brings the stack up with it; the committed
file is untouched. And "exactly one call" needed asserting rather than assuming,
because of correction 1: three more events are sent and only the `interaction`
row reaches a provider.

**3 · The dashboard's CSRF path was not the obstacle; page routing was.**
`CSRFMiddleware` only enforces on non-GET requests *that carry a session cookie*,
and everything the dashboard reads is a GET — so scripting the reads needed
nothing special. The double-submit token is only needed for the one write
`--live-judge` makes. What was actually hard is that the SPA has **no URL route
for its pages**: `go('ledger')` is a JS call and nothing restores it from the
location, so `chrome --screenshot=` can only ever capture the overview. The test
drives Chrome over CDP instead, and signs in with a `/v1/auth/handoff` token
minted from the SDK key — the desktop app's path, and the only one that
guarantees the browser lands on the same org the SDK just wrote to.

**4 · `compose up` re-seeds, every time.** `seed_org.py` does not dedupe by name
and `up -d` restarts the exited one-shot, so every `up` against a kept volume
mints another "Demo Corp" — another org, another key, another admin row with the
same email and password. The first draft had a `--no-reset` flag that skipped
only `down -v`; the first two failure demos written against it both went red for
the *wrong reason*, because `up` had handed the run a fresh empty org and the
break was invisible. Replaced with `--reuse-stack`, which touches compose not at
all. The "cookie session and API key resolve to the same chain head" assertion is
what caught it.

**5 · The export bundle is a ZIP, so searching its bytes proves nothing.**
Compressed content cannot be substring-matched. The sweep decompresses every
member first — otherwise the one surface that ships the ledger to a third party
would have been the one surface the content-blindness check silently lied about.

### Measured

- Worker latency, `created_at → graded_at`, per row: **0.03 s – 2.1 s** across
  runs (`grading_poll_interval` is 2.0 s, so a row waits at most one poll).
  Wall-clock from the SDK's last call to all three terminal: **1.1 – 2.3 s**.
- Whole run: **~47 s** cold, ~25 s with `--reuse-stack`.
- Content-blindness: **11 needles × 23 HTTP surfaces** and **11 × 37 tables**,
  zero hits. All three negative controls found the string that is present.

### Not covered, and deliberately

One org (says nothing about RLS isolation), a local stub in place of a model
provider, localhost rather than prod, and a falsification test rather than a
proof — three prompts cannot show content-blindness for a fourth. `e2e/README.md`
carries the full list.
