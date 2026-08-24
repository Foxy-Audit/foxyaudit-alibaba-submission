# Compliance Testbed — a real assistant you can try, in three sectors, on three surfaces

**COMPLETE — 2026-08-24 at `61ce009`.** Written 2026-08-12, re-cut 2026-08-24.
All five phases shipped: T0 `7a4f672` · T1 `768a2ed` · T2 `50e704c` · T3 `fc59cc2`
· T4 `61ce009`, plus the prerequisite S11 `ce491e1`.

> **T0, T1 and T2 have MERGED.** This file was written before any of them existed and
> described all five phases as pending. It has been re-cut against what is actually on
> disk. Everything below §2 is current; the history is in §11.

Companion plan: [`sdk-policy-truth.md`](sdk-policy-truth.md) (S3–S7, all shipped).

---

## 1 · Context

The owner asked for "an LLM chatbot for an important or sensitive sector, with an
interface, so that as a client I can test whether it is actually assisting as intended."

**What this is, and what it is not.** It is not the demo. `demo/` holds scripted CLI
showcases — `mock_llm.py`, `offline_demo.py`, `live_openai_client.py` — that print a
canned scenario for a judge. The testbed is an assistant a person **drives**, shipped
inside the `foxy-audit` wheel, so `pip install foxy-audit` is all a prospect needs. They
share the same real preflight guard and both run offline with no key.

Two audiences, one build:

- a **prospect** who wants to see a HIPAA breach get stopped before it reaches a model;
- the **owner**, who needs to answer "is the assistant still helpful once the guard is
  on?" — the question a block-rate metric cannot answer. An assistant that refuses
  everything scores perfectly and is worthless.

That second audience is why the testbed records **assist quality alongside enforcement**
(§5), and it is the thing that survived contact with the build: the shipped scoreboard
reports over-blocking as its own column.

---

## 2 · Premises, re-verified at `2ad2b7c` (2026-08-24)

The 2026-08-12 table was read at `24d3699`. Six of its ten rows have since changed
state. **Read this table, not that one.**

| The premise (as the plan had it) | Then | Now | What is actually true at `2ad2b7c` |
|---|---|---|---|
| A chatbot demo exists | NO | **YES** | `sdk/src/foxy_testbed/` — 8 modules, 2 859 lines, plus `page.html`. `python -m foxy_testbed.web` serves a working page on 127.0.0.1:8787. |
| A web page could call an LLM directly | NO | NO | Unchanged, and §3's answer shipped: the server is one the user starts. |
| We could host the chat backend | must not | must not | Unchanged and non-negotiable. `web.py` has no `--host` flag and a guard asserts its absence. |
| The SDK can enforce in a demo | holds | holds | `client.py:613-615` — the block branch raises without calling the wrapped fn. |
| Demos must run offline | holds | holds, **and CI enforces it** | `ci.yml:116-152` runs the testbed guards, three probe scoreboards, a redact run and a piped REPL session, all keyless. |
| The sector presets exist | NO | **YES, with the gap stated on the surface** | `sectors.py`: healthcare → `policy_tag="hipaa"`; finance and legal → `policy_tag="default"`, each carrying prose that says the baseline is all that runs, plus `*.gap.*` probes that measure exactly what is not caught. This is the honest-empty-state resolution T0 was asked for. |
| T4 depends on S5 | pending | **S5 shipped** (1.8.0), hardened by S9 (1.10.0) | `check()` / `explain()` are public API; `foxy check` / `foxy explain` are CLI subcommands. `explain()` verifies the ruleset it replays and carries a three-state `ruleset_verified`. |
| — | — | **🔴 NEW: T4 is blocked by an SDK gap** | See §3. This is the finding that reshapes the rest of this plan. |
| — | — | **🔴 NEW: the desktop cannot reach the SDK** | See §4. |
| Register #161 is the high-water mark | — | **#232 is** | Testbed entries: ✅#226 (T2's contrast/double-submit fixes), 🟢#227. Live and relevant: 🔴#232 (`policy="HIPAA"` uppercase silently drops to `default`), 🔴#228, 🟡#230. |

**Baselines measured, not quoted** (`--collect-only` at `2ad2b7c`):
`sdk/tests` **710** · `sdk/tests_testbed` **354** · `desktop` **884**.
On this machine PyQt6 lives on **Python 3.13** and the desktop suite runs as
`QT_QPA_PLATFORM=offscreen py -3.13 -m pytest desktop`. Python 3.14 has no pytest and
carries a **stale foxy_audit 1.7.0** in site-packages; the repo is at **1.11.0**.

---

## 3 · 🔴 The blocker for T4 — the SDK gives the caller no event id

T4 is "verify this turn": press a control, and the turn you just watched is traced to
its ledger row. It cannot be built as written, and the reason is not in the old plan.

**`log_interaction` mints the event id and returns it to nobody.**

```
client.py:794     event_id = str(uuid.uuid4())
client.py:818     payload = {"event_id": event_id, ...}
client.py:883-901 result = dispatch.submit(...); return result   # the submit result, not the id
```

The decorator's return value is the wrapped function's response — that is the frozen
public contract and must not move. So a consumer of the SDK, which is exactly what the
testbed is, **cannot name the ledger row its own call produced**. `core.py:204-209`
already records this in-code as an `SDK FINDING` and leaves `Turn.event_id` honestly
empty rather than inventing one; that comment was right and this plan is the escalation
it asked for.

`introspect.explain(prompt, event_id=..., export=..., commitment_key=...)` requires that
id. Without it there is no turn-to-row link, only a row a human pastes in by hand.

**A second fact that shapes the honest states.** The testbed builds
`FoxyClient(api_key="")` deliberately (`core.py:465-466`), so `cfg.enabled` is False and
`dispatch.submit` never runs: **in the default configuration no ledger row exists at
all.** And `--api-key` on the CLI is the *provider* key (`__main__.py:77`), not a Foxy
key — nothing the testbed has ever run has reached a ledger.

**Owner decision · 2026-08-24: add S11 first.** An additive, content-blind receipt hook.
Spec in §6. Register this as **#233**.

---

## 4 · 🔴 The blocker for T3 — the desktop has never imported the SDK

Nothing in `desktop/` imports `foxy_audit` outside one test
(`test_guard_bridge.py:489`). The console talks to the backend over HTTP; the fox learns
about the guard over a **UDP ping** (`sdk_bridge.py`), not by importing it.

Consequences, both verified:

- `desktop/requirements.txt` does not list `foxy-audit`, and `ci.yml:316` installs only
  that file. A page that imports `foxy_testbed` at module scope **fails all 884 desktop
  tests in CI**.
- `omni_fox.spec` bundles PyQt6 and keyring via `collect_all` and nothing else. A user of
  the shipped `.exe` has no `foxy_testbed`.

**Owner decision · 2026-08-24: bundle it.** The page is for everyone who installs the
`.exe`, so `foxy-audit` joins `desktop/requirements.txt` and the spec — *and* the import
is still guarded, because a dev checkout that has not installed it must degrade to an
honest empty state rather than crash the console. Register this as **#234**.

---

## 5 · The part that makes it worth building *(shipped — stated here so it is not lost)*

| Column | What it answers |
|---|---|
| **Enforcement** | Did the guard stop what it should have? Each sector ships probes labelled `expect_block` / `expect_assist` / `known_gap`. |
| **Assistance** | Is it still useful? `expect_assist` probes must come back **answered**, and a run reports *both* rates. |

`scoreboard.py` reports blocked-correctly, missed **and over-blocked**. An assistant that
refuses everything scores visibly badly.

**No fabricated verdicts.** With the mock provider the replies are fixtures, and
`providers.MOCK_NOTE` says so on every surface — while the enforcement is genuinely real,
because the guard is the same one a production event goes through. `Turn.provider_is_live`
carries that distinction rather than re-deriving it from a provider name.

---

## 6 · Phases — what is left

| Phase | Branch | Scope | State |
|---|---|---|---|
| T0 | `feat/testbed-core` | engine, sectors, providers, probes, scoreboard | ✅ `5dbbabc` → `7a4f672` |
| T1 | `feat/testbed-cli` | interactive REPL | ✅ `337f0e6` → `768a2ed` |
| T2 | `feat/testbed-web` | local server + page | ✅ `b4a08ca`, `50e704c` |
| **S11** | `feat/sdk-event-receipt` | the SDK hands back the id of the row it wrote | **ready — do first** |
| **T3** | `feat/testbed-desktop` | console page — **UI phase, skills block mandatory** | **ready — parallel with S11** |
| **T4** | `feat/testbed-evidence` | "verify this turn" — wires the evidence pane to `explain()` | **blocked on S11** |

**Order.** S11 and T3 are independent of each other and can run in two executor chats at
once — they share no file. T4 lands last. **T4's scope is the engine, the CLI and the web
page only**; if T3 has merged by then, its evidence pane is a follow-up (T4b), so that T3
and T4 never edit `desktop/` at the same time.

### S11 — the SDK hands back the id of the row it wrote

**Files:** `sdk/src/foxy_audit/client.py` · `sdk/tests/` · `sdk/README.md` ·
`VERSION` · `sdk/pyproject.toml` · `sdk/src/foxy_audit/__init__.py` (`__version__` + changelog)

**Shape — one kwarg, one dict, no new type.**

```python
FoxyClient(..., on_event=lambda receipt: ...)
```

Fired from inside `log_interaction`, from the **payload that was actually built**, never
from the caller's arguments. The receipt is a plain dict:

```
event_id · event_type · policy_tag · decision · policy_rules · blocked_reason
ruleset_version · ruleset_hash · commitment_alg · prompt_hash · response_hash
pii_signals · delivered
```

Every one of those is already a field of `payload`, so the receipt is content-blind by
construction: `prompt_hash` is a commitment, not text.

**Design rules, each with the reason:**

- **It is a constructor argument, not config.** A callable cannot come from an env var,
  and `FoxyConfig.resolve` reads the environment. Putting it on the frozen config
  dataclass would invent a setting nobody can set. Store it on the client.
- **It fires when `cfg.enabled` is False too**, with `delivered=False`. The id and the
  decision are real even when nothing shipped — and that state is precisely the honest
  empty state T4 needs. A hook that only fires for keyed clients would be dead code on
  every offline run, which is guard-lie #1 in a new coat.
- **It fires for every event type** — `interaction`, `blocked`, `blocked_by_org_policy`,
  the redact path, `exception`, and the response-scan decisions. Wiring only the happy
  path gives the testbed a receipt for exactly the turns nobody needs to verify.
- **It never propagates.** Its own `try/except` logging at debug, matching the method's
  standing rule that telemetry must never break the host app. A customer's broken
  callback must not raise out of their model call.
- **It fires after the submit attempt, inside the existing `try`.** If `audit_required`
  is set and delivery fails, the outer handler raises `AuditRequiredError` and **no
  receipt is emitted** — correct, because the event did not durably land. Say so in the
  docstring rather than leaving it to be discovered.

**Traps:**

- **`_record_async` runs `log_interaction` under `asyncio.to_thread`**, so in async use
  the callback runs **off the event loop, on a worker thread**. Document it: a Qt
  consumer must not touch widgets from it. This is a real future footgun for T3's page.
- **Do not change what `log_interaction` returns.** It returns `dispatch.submit`'s result
  today when enabled; callers exist. The hook is additive beside it.
- **Prove the receipt is content-blind with a corpus, not an eyeball.** Feed prompts
  carrying PHI, a card number, an API key and an injection string; assert no substring of
  length ≥ 8 from any of them appears anywhere in the serialised receipt.
- **Make the guard fail on purpose.** Delete the hook call and watch the test go red; a
  hook asserted only by "the callback was defined" is guard-lie #1.

**Version: 1.12.0 — MINOR.** New public surface, no behaviour change to existing calls.
Bump `VERSION`, `sdk/pyproject.toml`, and `__init__.__version__`, and **check whether
`check-version` in `release.yml` still validates only two of the three stamps** — S7 was
asked to close that and the executor must verify rather than assume.

**Assumption to overrule:** that the testbed also needs a way to *send* events to a
ledger. It does — `--api-key` is the provider key and there is no Foxy-key flag — but that
is T4's surface work, not S11's. S11 changes `foxy_audit/` and nothing else.

### T3 — the desktop console page

**Files:** new `desktop/testbed_page.py` · `desktop/console_chrome.py` ·
`desktop/dashboard.py` · `desktop/requirements.txt` · `desktop/omni_fox.spec` ·
new `desktop/test_d16_testbed.py`

**Follow the existing page contract exactly.** `VerifySections` / `PolicySections` /
`LedgerSections` are classes taking the shell and exposing `.build(t) -> QWidget`;
`dashboard.py:707-716` holds the `builders` dict and `console_chrome.EXTRA_SECTIONS`
holds the desktop-only sidebar rows (`system`, `sandbox` today). A new `testbed` row goes
there, with its `PALETTE_LABELS` entry and a `QUICK_NAV` letter — **check the letter is
not already taken** (`h d a l v p e k b s` are in use; read the map, do not guess).

**Do not confuse it with the Sandbox page.** `_page_sandbox` is the *verification*
sandbox — paste a prompt and response, hash them locally, compare to the ledger. The
testbed page is the assistant. Two different things one letter apart in the sidebar; the
titles must not read alike.

**The guarded import, and what it says.** `import foxy_testbed` goes inside the build, in
a `try`, and its failure renders an honest state naming the fix
(`pip install foxy-audit`) — not a disabled button, not a spinner, not a fake turn.

**The turn must not run on the GUI thread.** The mock provider is instant, but a live one
is a network call and would freeze the console. Run `Assistant.ask` on a worker
(`QThreadPool`/`QRunnable` or a `QThread`) and disable the composer while in flight. And
note S11's trap above: a receipt callback also arrives off the GUI thread.

**Packaging.** Add `foxy-audit` to `desktop/requirements.txt` (bounded range, matching
the file's stated convention) and `collect_all("foxy_audit")` **and**
`collect_all("foxy_testbed")` to the spec — `page.html` is a data file inside the package
and `collect_all` is what brings data across. **Read `test_d14_packaging.py` first**: it
may assert the spec's contents, and a packaging test that goes red is the whole point of
it existing.

**Style.** Reuse `foxy_tokens`; introduce no colour. **Web wins on any style conflict.**
Measure a fill against its background, not only its ink.

### T4 — evidence *(unblocked: S11 merged at `ce491e1`)*

**Files:** `sdk/src/foxy_testbed/core.py` · `cli.py` · `web.py` · `page.html` ·
`__main__.py` · `sdk/tests_testbed/`

Wire S11's receipt into `Turn.event_id`. The hook is
`FoxyClient(on_event=…)`, handing back a dict with `event_id`, `submitted`,
`decision`, `policy_rules`, `blocked_reason`, `ruleset_version`, `ruleset_hash`,
`commitment_alg`, `prompt_hash`, `response_hash`, `pii_signals`, `event_type`.
Delete the `SDK FINDING` comment at `core.py:204-209`, citing `ce491e1` where it
stood, add a Foxy-key opt-in so a turn
can reach a ledger at all, and render a verify control.

**Three honest states, and the page must be able to be in each of them:**

1. **No ledger.** The default, and now readable straight off the receipt:
   `submitted=False` means there is no row. "This turn was never shipped to a
   ledger — nothing to verify," plus the one line that changes it. Not an error, and not a disabled control
   with no explanation.
2. **Shipped, no export.** The row exists; `explain()` needs a
   `/v1/logs/export?format=json` document. Say which file and how to get it.
3. **Export present.** Run `explain()` and render `ExplainResult.status` **verbatim** —
   `ok`, `row_not_found`, `hash_mismatch`, `salt_unavailable`, `predates_provenance`,
   `ruleset_mismatch` — with its own message. Do not collapse them into a green tick and
   a red cross. `salt_unavailable` in particular "is not a mismatch and not a pass", and
   `ruleset_verified` is three-state on purpose: `None` is not `False`.

**A verify button that fakes a result is the worst possible thing to ship in an audit
product.** If a state cannot be reached honestly, it renders as the state it is in.

**Traps:**
- **Matched spans are the user's own text.** The page is 127.0.0.1-only, which is the
  same boundary `explain`'s stdout already has — but they must never enter a log line, a
  payload or an exception. `web.py`'s access-log line already strips the query; assert
  the spans cannot reach it.
- **No new runtime dependency**, and no policy logic in `web.py` or `cli.py` —
  `test_web.py` walks the AST to enforce that and will catch a stray `foxy_audit` name.
  The verify call belongs in `core.py`.

---

## 7 · MANDATORY SKILLS — paste verbatim into the T3 prompt

```
Before writing any UI, load ALL THREE frontend skills, in this order:
  1. ui-ux-pro-max   — the FACT BASE. Query it. Never invent a palette, a font
                       pairing, or a motion preset.
  2. impeccable      — the CRAFT. Hierarchy, accessibility, responsive behaviour,
                       error and empty states, UX copy, motion.
  3. frontend-design — the DIRECTION. Aesthetic intent; do not ship a templated default.
Loading one of them is not loading the rule.

Two qualifiers:
- These skills do NOT override this project's settled decisions (the warm-orange
  palette, the R1 reversals, R2's status vocabulary, `.eyebrow` staying). Where they
  conflict, the project wins — and say so in your report.
- Expect the standing conflicts and overrule them on the record: ui-ux-pro-max
  returned navy/slate with a green CTA and a Google-Fonts CDN for T2 and was
  overruled on both; the `flat-type-hierarchy` warning is open and deliberate.

Measure a fill against its background, not only its ink. This surface has shipped a
chip whose text cleared 4.5:1 while the pill itself sat at 1.01:1 against the card
behind it. `--muted2` is 3.01:1 dark / 2.71:1 light and must never carry live text.

Any chart or tile: load `dataviz` BEFORE the first line of chart code. If the phase
touches no chart, mark, scale or palette, say so rather than loading it.
```

---

## 8 · Verification

```bash
# S11
py -3.13 -m pytest sdk/tests -q                    # 710 baseline, must only grow
py -3.13 -m pytest sdk/tests_testbed -q            # 354 baseline, must NOT move
py -3.13 -m pytest verifier -q                     # the export shape must not move
python demo/mock_llm.py --scenario all
python demo/offline_demo.py                        # has gone red on a correct change

# T3
QT_QPA_PLATFORM=offscreen py -3.13 -m pytest desktop -q    # 884 baseline, FROM THE REPO ROOT
python -m compileall -q desktop

# T4
python -m foxy_testbed --sector healthcare --probe all     # scoreboard, offline, no key
python -m foxy_testbed --sector finance   --probe all
python -m foxy_testbed --sector legal     --probe all
node --check <each inline script in page.html>             # into the scratchpad
```

**What must NOT move:** the SDK's public API as it stands, the wire contract, the
`observe` path's byte-for-byte payload, every existing suite's baseline, and the recorded
`policy_tag`. The testbed is a **consumer** of the SDK — after S11, if a phase here needs
another change inside `foxy_audit/`, that is a finding to report, not a change to make.

---

## 9 · After each merge

- **Devlog** — append to `Devlogs/YYYY-MM-DD.md`, dated, in house style.
- **🔴 `Testbed/CLAUDE.md` does not exist.** §9 of the original plan asked for it after
  T0 and it was never created. It is now three merged phases overdue. Create it at the
  T3 gate: the sector→policy_tag mapping and why finance and legal are `default`, the
  127.0.0.1-only constraint as a property of the socket, the `Turn` contract, and the
  three-front-ends-hold-no-policy-logic rule with the AST guard that enforces it.
- **Register** — open **#233** (the SDK returns no event id to its caller) and **#234**
  (the desktop cannot reach the SDK; packaging), each with `file:line`; close them with
  the SHA as S11 and T3 land, keeping the original text.
- **Re-stamp** `verified-against:` on `SDK/CLAUDE.md` (S11), `Desktop/CLAUDE.md` (T3),
  and the new `Testbed/CLAUDE.md`.
- Remove the worktree and delete the branch, **printing its SHA first**.

---

## 10 · Merge gate — MAIN runs all of it

Per `START HERE` §6: `git fetch` **at push time** · `merge-base --is-ancestor` ·
three-dot `diff --stat` for scope · **blob** EOL check (`core.autocrlf=true`, no
`.gitattributes` — a 111-line change once committed as 6 734 lines) · each suite run
**alone** · `node --check` every inline `<script>` · no-fake-data grep · no-secret grep ·
`code-review` skill · and **re-break at least three of the executor's guards myself**.

⚠ Merge to **`foxyaudit-devtool`** with a normal push. Never
`git push origin <sha>:refs/heads/main` — that idiom belongs to the frozen repo, which is
what the judges see and which deploys production on push.

---

## 10b · Gate outcome, 2026-08-24

**T3 merged at `d73ac4b`.** desktop 884 → 923. MAIN re-broke four guards, four
killed. Register: ✅#234 closed · 🔴#235, 🟡#236 (both **pre-existing on
`2ad2b7c`**, verified before review) · 🟡#237 (T3b).

⚠ **`pytest desktop` is red on `main` and was before T3** — #235 (a freeze-era
CI-policy mismatch) and #236 (a test that hardcodes UDP 59999, which an unrelated
vendor service holds on this machine). Every future desktop phase must state its
baseline as "N passed, 2 pre-existing failures" until they are closed, and #236
means **failure membership is not stable between runs**.

**S11 built at `1a034ca` and HELD**, not merged. sdk 710 → 736, testbed 354
unmoved, verifier 31, both demos green, four mutations killed. Held on four
review findings; the load-bearing one is that **`delivered` is `cfg.enabled`** —
with a revoked key every POST 401s and retries forever while every receipt still
reads `delivered: True`. That is public API in an audit product and is worth one
short round before it lands. See S11b.

### S11b — the four gate findings

1. **`delivered` overstates.** Rename to **`submitted`** — true in both configs,
   claims nothing about the backend. Under `audit_required=True` a server receipt
   did come back; say that in the docstring rather than in the field name.
2. **An `async def` callback is silently dropped** — the coroutine is created and
   discarded, body never runs, only a Python `RuntimeWarning`. Reject it at
   construction, where the mistake is.
3. **A non-callable `on_event` is accepted** and fails per-event at `log.debug`,
   so a mis-wired hook is indistinguishable from no hook. `TypeError` at
   construction.
4. **`sdk/README.md:31` omits `redacted`** from the `event_type` list, which the
   receipt does emit; `__init__.py`'s changelog lists it, so the two disagree.

---

## 11 · What changed in this re-cut, and why

Written 2026-08-12 at `24d3699`; re-cut 2026-08-24 at `2ad2b7c`.

- T0/T1/T2 marked shipped with their SHAs; their scope text collapsed to one line each.
- The premise table re-verified. Six rows changed state.
- **Two blockers added that the original could not have known** — §3 (no event id
  reaches the caller) and §4 (the desktop has never imported the SDK). Both were found by
  reading the code, not by reading the plan.
- **S11 added** as a prerequisite for T4, on the owner's decision of 2026-08-24.
- T3's packaging decision recorded: bundle, on the owner's decision of 2026-08-24.
- Baselines replaced with measured counts; the Python 3.13 / 3.14 split recorded.
- The merge idiom corrected for the devtool repo.

**2026-08-24, second pass (post-gate):** T3 marked merged; S11 marked held with
S11b specified; T3b added; the two pre-existing desktop reds recorded so no
future phase re-derives them; the blob-EOL rule corrected — **every committed
blob in this repo is CRLF**, measured on six blobs across both branches, so
`START HERE` §6's stated direction is inverted here.

---

## 12 · Closed — 2026-08-24

Every phase merged. Open findings the plan produced and did not fix, each with a
measurement in `Worth Noting — Issues`:

| | |
|---|---|
| 🔴 #239 | an allowed row records no ruleset, so `explain()` tells an auditor a row written today "predates SDK 1.7.0". Behaviour is correct per S4; the message is not. Wants its own SDK phase. |
| 🔴 #241 | the testbed suite POSTs 61 real events to the default endpoint and leaks 24 dispatcher paths. Test-only, developer-machine. |
| 🟡 #238 | four residual findings on the desktop page, three in its own guards. |
| 🟡 #240 | the cross-origin web guard is flaky. |
| 🔴 #235 · 🟡 #236 | `pytest desktop` has two pre-existing reds unrelated to this plan. |

**T4b remains unbuilt and unscoped**: the desktop console has no evidence pane.
It was deferred so T3 and T4 never edited `desktop/` at once, and nothing depends
on it.

**What this plan actually cost, and what it bought.** Nine merges across five
phases and eleven gate rounds. Every executor round found premises in its brief
that did not hold — including two vocabularies MAIN invented rather than read
(`ok` as an explain status, a ≥8-character leak rule) and one measurement MAIN
contaminated with its own leftover processes. The register grew from #232 to
#241. What shipped is an assistant a prospect can drive on three surfaces, behind
the real guard, that reports over-blocking as loudly as blocking and can trace a
turn to its ledger row without ever claiming more than it knows.
