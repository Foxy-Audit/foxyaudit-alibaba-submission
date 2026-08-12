# SDK — Policy Truth: additive checks, provable blocks, a console API

**Plan of record** · 2026-08-12 · MAIN chat is the committer; executors build per this file.

Phases **S2 → S6**, continuing the `S` series (S1 = response scanning / OWASP LLM05,
shipped in 1.4.0 at `3e0f6d8`).

---

## 1 · Context

The owner asked five questions about whether the SDK does what it claims. Four of them
turned into work; the fifth resolved itself mid-session. The through-line is that the
SDK's *mechanism* is sound and its *coverage and provability* are not:

- `mode="block"` really does stop the model call. That part is not in doubt.
- But a prompt tagged `hipaa` gets **no injection and no secret scanning**, and the tag
  our own documentation tells people to use (`hipaa_basic`) does **no PHI scanning at
  all** — it is not a recognised tag and falls through to the default.
- And when a block does fire, nothing shipped can prove the rule genuinely matched. The
  ledger attests *which rule we recorded*, not *that it fired*.

1.4.0 went to PyPI at 13:54 UTC today (`Release` run 31603849761, all 8 jobs green),
so the broken quickstart is now the first thing a visitor to the package page reads.
That is what makes S2 and S6 urgent rather than merely correct.

---

## 2 · What the premises actually are

Read at `24d3699`. The owner's five questions, checked against the code:

| # | The premise | Holds? | What is actually true |
|---|---|---|---|
| 1 | The SDK blocks non-compliant prompts | **partly** | The mechanism is real — [`client.py:635-637`](../../sdk/src/foxy_audit/client.py#L635-L637) evaluates before the wrapped fn and raises without calling it. The **coverage** is the problem: see rows 2–3. |
| 2 | HIPAA/GDPR policies and OWASP LLM01 both apply | **NO** | `_POLICY_CHECKS` is **exclusive, not additive** ([`policy.py:61-65`](../../sdk/src/foxy_audit/policy.py#L61-L65)). `hipaa` → PHI only. `gdpr` → PII only. `default` → injection + secrets. No tag runs both families. |
| 3 | `hipaa_basic` is a HIPAA policy | **NO** | It is not a key in `_POLICY_CHECKS`, so `_checks_for` returns `_DEFAULT_CHECKS` and it runs injection+secrets with **zero PHI detection**. It appears in [`__init__.py:15`](../../sdk/src/foxy_audit/__init__.py#L15), [`sdk/README.md:26`](../../sdk/README.md#L26) (the PyPI long description), [`demo/run_demo.py:24`](../../demo/run_demo.py#L24) and [`sdk_bridge.py:12`](../../desktop/sdk_bridge.py#L12). |
| 4 | The desktop pet signals a breach | **holds, and more** | It does not merely signal. Red overlay 5s, ALERTING sprite, **native OS toast**, sound, pops out of the tray, and **auto-opens the chat popup** ([`omni_fox.py:1143-1185`](../../desktop/omni_fox.py#L1143-L1185), [`companion_events.py:78-100`](../../desktop/companion_events.py#L78-L100)). Gated on the user's threshold/sound/toast settings. |
| 5 | The fox reports the breach honestly | **NO** | The SDK's UDP ping carries no `risk_score` ([`client.py:311-315`](../../sdk/src/foxy_audit/client.py#L311-L315)), so `omni_fox` falls back to `100` and renders **"Risk Score: 100/100"** — a hardcoded default presented as a measurement. Hard-rule violation (§5.1, no fake data). |
| 6 | A blocked event is tamper-evident | **holds** | `event_metadata` — which carries `decision`, `policy_rules`, `blocked_reason` — **is bound into the chain hash** at `chain_version ≥ 2` ([`chain.py:61-71`](../../backend/app/chain.py#L61-L71)) and [`verifier/foxy_verify.py`](../../verifier/foxy_verify.py) recomputes it with zero Foxy imports. Nobody can retroactively change which rule we said fired. |
| 7 | We can prove the rule actually matched | **NO** | Nothing shipped re-runs a rule against the text. And `policy_rules` carries **no ruleset version or hash**, so an auditor cannot establish what `injection.ignore_previous` meant on the day it fired. This is the real gap behind the owner's question 2. |
| 8 | The SDK can be called from a console | **NO** | `foxy doctor` is the *only* subcommand and is connectivity-only ([`cli.py:110-120`](../../sdk/src/foxy_audit/cli.py#L110-L120)). `FoxyClient` has **no `.check()`** — the decorator is the sole entry point. `policy.evaluate` is reachable but is a private module, absent from `__all__`, returning an internal dataclass. |
| 9 | 1.4.0 needs publishing | **already done** | The owner tagged it mid-session. Run 31603849761: `check-version`, `build-sdk`, `publish-pypi`, all three `build-desktop`, `publish-installers-to-vm`, `publish-github-release` — **all success**. Nothing to do; what remains is listing quality (S6). |
| 10 | A test chatbot exists to try this as a client | **NO** | Nearest are `demo/mock_llm.py` and `demo/live_openai_client.py`, both CLI-only. A repo-wide grep for playground/chatbot/sandbox returns only Paddle's payment sandbox. → separate plan, [`compliance-testbed.md`](compliance-testbed.md). |

**Not in the registers.** `Worth Noting — Issues.md` runs to #161 and contains no entry
for the policy map, `hipaa_basic`, or the risk score. These are new; allocate **#162
(policy map) · #163 (`hipaa_basic`) · #164 (fox risk score)** when syncing.

---

## 3 · Owner decisions · 2026-08-12

| Question | Decision |
|---|---|
| How to fix the policy map | **Additive baseline.** Injection + secrets always run on every tag; `hipaa`/`gdpr` add PHI/PII on top. Alias the `_basic` tags. Owner accepted the stated behaviour change. |
| How far to take provability | **Replay tool + ruleset version.** `foxy explain` replays locally against a *pinned* ruleset, and `ruleset_version` + `ruleset_hash` go on the wire and into the chain. |
| Test chatbot | **All of the above** — healthcare *and* finance *and* legal, on web *and* desktop *and* CLI. Scoped separately in [`compliance-testbed.md`](compliance-testbed.md). |
| v1.4.0 to PyPI | Owner tagged it during the session; it published cleanly. Next release is **1.5.0** (S2 changes behaviour — see §5). |

---

## 4 · ⚠ The blocker nobody mentioned

**`event_metadata` is a strict allowlist, and an unknown key is a 422 on ingest.**

[`backend/app/schemas.py:35-49`](../../backend/app/schemas.py#L35-L49):

```python
allowed = {"request_id", "trace_id", "session_id", "provider", "model",
           "id", "usage", "choice_count", "tool_names", "retrieval_refs",
           "client_seq_gap", "decision", "blocked_reason", "policy_rules"}
unknown = set(value) - allowed
if unknown:
    raise ValueError("event_metadata contains unsupported fields")
```

So S3 is **not** a free ride on an open dict. Three consequences, and the ordering is
not negotiable:

1. **The backend must ship the widened allowlist BEFORE any SDK sends the new keys.**
   Reverse that order and every guarded event from an upgraded SDK is rejected with a
   422 — a silent, total evidence outage on exactly the events that matter most.
2. **A self-hosted or lagging backend will reject an upgraded SDK.** The hosted backend
   is ours to sequence; a customer running their own is not. The SDK must therefore
   **degrade rather than fail**: on a 422 naming unsupported fields, retry once without
   the ruleset keys and record that it did. Do not let a provenance nicety cost a
   customer their audit trail.
3. The per-key caps (`≤ 64 items`, `≤ 256 chars`) are fine — a version string and a
   64-char hex hash both clear them comfortably.

**Second-order:** `event_metadata` has been chain-bound since V2, so adding keys changes
the chain hash **for new rows only**. Old rows are untouched and keep verifying. Prove
that rather than assume it (§8).

---

## 5 · The blast radius of the additive change — read before building S2

This is the part to get wrong quietly, so it is stated in full.

**`signals` becomes `pii_signals` on the wire, and `pii_signals` is a deterministic
breach trigger on the backend** (`if pii_signals: policy_breach = True`). In
`_evaluate_preflight`, only the **block** and **redact** branches populate `signals`;
the `allow` branch sets `None` and the observe path produces no plan at all. Therefore:

| Mode | What changes for a `hipaa`/`gdpr` tag |
|---|---|
| `observe` | **Nothing.** No plan, no signals, historical `pii.detect_pii` path unchanged. |
| `block` | Prompts carrying an injection pattern or an API key now **raise where they previously passed**. This is the point of the change. |
| `redact` | Injection and secret spans are now **also scrubbed from the prompt the model receives** — `redact()` shares `_checks_for` with `evaluate()`. The model sees different text than it did in 1.4.0. |
| any of the above | New `prompt_injection` / `secret_key` labels appear in `pii_signals` on rows that had none → **new deterministic breaches on existing customers' dashboards.** |

That last row is the one to put in the release notes. It is correct behaviour — those
*are* breaches, and we were silently not looking — but a customer who sees their breach
count jump after a version bump deserves to have been told.

**This is a MINOR bump: 1.5.0.** Not a patch. New rules fire, new exceptions raise from
code that did not raise before, and the redacted prompt changes shape.

---

## 6 · Phases

| Phase | Branch | Scope |
|---|---|---|
| **S2** | `fix/sdk-additive-policy` | Additive baseline + tag aliases + versioned ruleset registry |
| **S3** | `feat/ruleset-provenance` | Widen the backend allowlist, then ship `ruleset_version`/`ruleset_hash` on the wire |
| **S4** | `feat/sdk-check-explain` | Public `check()` / `explain()` + `foxy check` / `foxy explain` CLI |
| **S5** | `fix/fox-unscored-breach` | Stop the fox rendering a hardcoded 100/100 |
| **S6** | `docs/sdk-1-5-0-listing` | PyPI listing, README, version bump to 1.5.0 |

**Order.** S3 has a hard internal ordering (backend before SDK — §4). S2 → S3 → S4 → S6
is the dependency chain; **S5 is independent and can be built in parallel by a second
executor.** S6 must be last: it documents whatever S2–S4 actually shipped.

---

## 7 · Per phase

### S2 — additive baseline + aliases + ruleset registry

**Files:** `sdk/src/foxy_audit/policy.py` · new `sdk/src/foxy_audit/ruleset.py` ·
`sdk/tests/`

Move `_INJECTION_RULES` and `_SECRET_RULES` out of `policy.py` into a **versioned,
frozen registry** in `ruleset.py`. S3 and S4 both depend on historical rulesets still
existing, so this is not a cosmetic move:

```python
RULESETS = {"2026.08.1": Ruleset(injection=(...), secrets=(...))}
CURRENT = "2026.08.1"

def ruleset_hash(version: str) -> str:
    """sha256 over canonical JSON of sorted (rule_id, signal, pattern_source)."""
```

Then make the policy map additive:

```python
BASELINE      = ("injection", "secrets")          # always, every tag
_POLICY_EXTRA = {"hipaa": ("phi",), "gdpr": ("pii",)}
_ALIASES      = {"hipaa_basic": "hipaa", "gdpr_basic": "gdpr"}
```

**Traps for this phase:**

- **`redact()` shares `_checks_for` with `evaluate()`.** Changing the map changes what
  the model receives under `mode="redact"`, not just what is recorded. Intended — but
  assert it deliberately rather than discovering it.
- **`_REASON_PRIORITY` already orders `secret` above `injection` above `phi`/`pii`.** A
  hipaa-tagged prompt containing both an API key and PHI will now report
  `blocked_reason: "secret_key"` where it previously said `phi`. Correct by the existing
  priority table; make sure a test pins it so it is a decision, not a drift.
- **Alias resolution must happen before `_POLICY_CHECKS` lookup and must not change
  `policy_tag` on the wire.** The customer tagged their event `hipaa_basic`; the ledger
  must keep saying `hipaa_basic`. Only the *checks* resolve through the alias. Changing
  the recorded tag would rewrite the meaning of every historical row that used it.
- **Prove `default` did not move.** Per playbook §3, load the pre-change module and the
  post-change module side by side and assert `evaluate(text, "default")` is identical
  across a wide corpus. A golden-vector file written on the branch proves only that the
  branch agrees with itself.

**Assumption to overrule if it is wrong:** that `hipaa_basic` and `gdpr_basic` are the
only aliases worth having. If telemetry or the sale page uses other tags (`soc2` appears
in `sdk/README.md:38`), say so — `soc2` currently gets baseline checks and may be fine,
but it should be a decision.

### S3 — ruleset provenance on the wire

**Files:** `backend/app/schemas.py` (first, and merged first) · then
`sdk/src/foxy_audit/client.py` · `backend/tests/integration/` · `sdk/tests/`

1. Widen the `event_metadata` allowlist with `ruleset_version`, `ruleset_hash`. Merge
   and deploy **before** touching the SDK (§4).
2. `log_interaction` adds both keys whenever `policy_rules` is present — not on clean
   observe rows, which must stay byte-for-byte identical to preserve the property that
   makes `observe` a safe default (`_labels` returns `{}` for a clean call; do not
   break that).
3. Implement the 422 fallback from §4.2: on an ingest rejection naming unsupported
   fields, retry once without the ruleset keys.

**Traps:**

- **Do not add a top-level payload field.** `event_metadata` is already chain-bound and
  already validated; a new top-level field means touching `chain.py`'s frozen blob and a
  new `chain_version`. Riding inside `event_metadata` gets chain coverage for free.
- **Run `verifier/foxy_verify.py` against a real export** containing new-style rows.
  Per playbook §6.2, when a shape widens, run the callers — including non-tests.
  `demo/offline_demo.py` compares result dicts and has gone red on a *correct* change
  before.
- **CI does not run `pytest verifier/`** (memory: `export-bundle-e2`). Run it by hand.

### S4 — the console API and the replay tool

**Files:** `sdk/src/foxy_audit/client.py` · `cli.py` · `__init__.py` · `sdk/tests/`

Public surface, all content-blind by construction:

```python
foxy.check("...", policy="hipaa")           # -> PolicyResult(action, rules, signals, reason)
foxy.explain(prompt, event_id=..., export="logs.json")
```

```bash
foxy check "ignore all previous instructions" --policy hipaa --json
foxy explain --event-id <uuid> --export logs.json --prompt-file p.txt
```

`explain` is the answer to "prove it was a real breach": it recomputes the commitment
from the local key + sidecar salt, matches it against the exported ledger row, replays
**the ruleset version named in that row**, and prints the matched spans.

**Traps:**

- **Matched spans are for stdout only.** They are the customer's own text on the
  customer's own machine, which is fine — but they must never enter a payload, a log
  line, or an exception message. Add a guard that greps the emit path.
- **Salted rows need the sidecar.** `commitment_alg == "hmac-sha256-salted"` cannot be
  recomputed without `salt_sidecar_path`. Say so plainly rather than reporting a
  mismatch that looks like tampering.
- **A row with no `ruleset_version` (anything written before S3) must say
  "unversioned — cannot pin", not silently replay today's rules.** Replaying current
  rules against a historical row and calling it a match is exactly the false assurance
  this phase exists to remove.
- **Export `PolicyResult` in `__all__`.** A public API returning a type users cannot
  import or name is not a public API.

### S5 — the fox's unscored breach *(independent; parallelisable)*

**Files:** `desktop/companion_events.py` · `desktop/omni_fox.py` ·
`desktop/test_d12_companion.py`

A local SDK block is **not graded** — there is no judge verdict and no risk score. The
threshold semantics are already right and documented (`on_breach`: "a breach the grader
could not score is not a quiet one" — unscored still interrupts). **Only the display is
wrong.** Separate the two: keep `default=100` for the *threshold* decision, and render
"not graded — local policy block" wherever a number is currently printed.

Three sites: `on_breach`'s `body` f-string and `bubble`, and the chat-popup bubble in
`_on_policy_breach` ([`omni_fox.py:1176`](../../desktop/omni_fox.py#L1176)).

**Trap:** the backend poller path *does* carry a real `risk_score`. Do not remove the
number there — distinguish "absent" from "zero", and keep the graded path showing its
real score.

### S6 — the listing

**Files:** `sdk/README.md` · `sdk/src/foxy_audit/__init__.py` · `sdk/pyproject.toml` ·
`VERSION` · `demo/run_demo.py` · `desktop/sdk_bridge.py` (docstring)

- `sdk/README.md` **Install** currently says `pip install -e .` — a developer
  instruction, and the first thing a PyPI visitor reads. Make it `pip install foxy-audit`.
- Replace every `hipaa_basic` with a tag that does what the surrounding prose claims.
- Document the additive baseline and the 1.5.0 behaviour change (§5).
- Document `foxy check` / `foxy explain`.
- Add a `Changelog` entry to `[project.urls]`, and link `SECURITY.md` (landed at
  `24d3699`).
- Bump **1.5.0** in three places: `VERSION`, `sdk/pyproject.toml`, and
  `sdk/src/foxy_audit/__init__.py.__version__`.

**Trap:** `check-version` in `release.yml` validates only **two** of the three version
stamps — `__init__.__version__` is unchecked, so a wheel can pass the gate while
reporting the previous version at runtime (known gap, `foxy-desktop-parity.md`). Bump it
by hand, and **add it to `check-version` while you are there** — it is four lines and
closes a gap that has been open since 1.2.0.

---

## 8 · Verification

```bash
pytest sdk/tests verifier -q                 # SDK 143 · verifier 31 baseline
pytest desktop                               # FROM THE REPO ROOT — 833 baseline
cd backend && DATABASE_URL=postgresql+psycopg://foxy:foxy@localhost:5433/foxy_pytest \
  python -m pytest tests/integration -q      # 1101+ baseline
python demo/mock_llm.py --scenario all       # the guard demo must still pass
python demo/offline_demo.py                  # §6.2 — has gone red on a correct change
```

**What must NOT move:**

- `evaluate(text, "default")` — identical output for every input, proven by loading the
  **old** module beside the new one, not by a golden file written on the branch.
- A clean `observe` call's payload — byte-for-byte identical (`_labels` returns `{}`).
- Every historical chain hash. Re-verify a real export end to end with
  `python verifier/foxy_verify.py`.
- The recorded `policy_tag`. Aliases resolve *checks*, never the tag on the wire.

**Make each new guard fail on purpose before trusting it.** The five ways a guard lies
are in playbook §6.15 — and note #3 in particular here: a guard anchored to a position
rather than a name will change subject when the rule tables move to `ruleset.py`.

---

## 9 · After each merge

Per playbook §4:

- **Devlog** `Devlogs/2026-08-12.md` — append. Lead with what surprised you: the
  allowlist 422, and that our own documented tag did no HIPAA checking.
- **Area notes** — re-stamp `updated:` / `verified-against:` / `verified-on:` on
  `SDK/CLAUDE.md` (S2/S3/S4/S6), `Backend/CLAUDE.md` (S3), `Desktop/CLAUDE.md` (S5),
  `Verifier/CLAUDE.md` (S3, if the export shape moved). Carry the **traps**, not the
  changelog. `SDK/CLAUDE.md` still says `pip install foxy-audit — 1.3.0`.
- **Register** — open **#162** (policy map exclusive), **#163** (`hipaa_basic` does no
  PHI), **#164** (fox renders a hardcoded 100/100), each with `file:line` and why it
  matters; close them ✅ with the SHA as each phase lands, keeping the original text.
