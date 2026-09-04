# Qwen Agentic Judge — Track 4 hackathon feature

**Plan of record** · written 2026-09-04 @ `12a9ade` · **revised 2026-09-04 @ `d4c3dde`**.

> **Revision note.** The first draft was written from the owner's Qwen
> documentation and a read of the judge path. Re-verified against the tree at
> `d4c3dde`, most of its cites hold — but it planned against a **two-provider
> shape that the code encodes in more places than the draft opened**, and its
> headline feature (`decision="human_review"`) is rejected by the `Verdict`
> schema. §3 is the list. Nothing was built against the first draft, so nothing
> has to be unwound.

Model IDs are explicitly volatile — the code defaults from `settings`, never
from a hardcoded string.

---

## 0 · The one-paragraph version

Add **Qwen** (Alibaba Cloud's LLM) as a third AI judge provider with **agentic
tool-calling**: the judge can call `flag_for_human_review` during grading and
escalate an event to a human instead of only scoring it. This targets the
hackathon's **Track 4: Agentic Applications** criterion — it turns a text-grading
LLM into an agent that makes a decision and invokes a tool. Four phases:
generalise the provider dispatch and add the plumbing (Q1), the provider module
(Q2), worker dispatch and N-way combine (Q3), and the two shipped clients that
would otherwise silently reset an org's routing (Q4). No new pip dependency —
`urllib`, matching `openai_judge.py`.

---

## 1 · Context

The hackathon scores **"custom skills, MCP integrations"** under Track 4. The
product has two AI judges (Gemini, GPT-5.6) that receive content-blind metadata
and return JSON verdicts — both passive text graders. A third provider that can
**call a tool** during evaluation turns grading into an agentic decision.

**Why Qwen:** the hackathon is an Alibaba Cloud event. Qwen exposes an
OpenAI-compatible `/chat/completions` endpoint at
`https://dashscope-intl.aliyuncs.com/compatible-mode/v1` and supports
OpenAI-style function-calling via `tools` (owner's dated documentation,
2026-09-04).

**Why tool-calling matters:** a judge that returns a verdict is "we called an
LLM." A judge that **decides to escalate** is "we built an agent."

⚠ **And that is exactly why §3.4 and §3.5 are blocking.** The escalation has to
land somewhere real. An escalation the product records and then does nothing
with is placeholder functionality, which the hard rules forbid in code as well
as in UI.

---

## 2 · The premises — re-verified at `d4c3dde`

The first draft's table, re-checked one row at a time. **Where a row was checked
by filename, count or memory, it is re-checked by opening the thing.**

| Premise | Verdict | Evidence at `d4c3dde` |
|---|---|---|
| Qwen has an OpenAI-compatible `/chat/completions` endpoint | **Holds (owner-sourced)** | Owner doc 2026-09-04. **Not independently verified from this machine** and not verifiable from the repo |
| Qwen supports function-calling via `tools` | **Holds (owner-sourced)** | same source, same caveat |
| Qwen supports `response_format` with a JSON schema | **TBD — verify at build time** | If not, fall back to system-prompt JSON enforcement, as `gemini.py` does |
| Model IDs change fast — must not be hardcoded | **Holds** | Owner's caveat. Code defaults from `settings.qwen_model` |
| Adding a provider needs a DB migration | **Holds** | `OrgPolicy` (`models.py`, `class OrgPolicy`) needs `qwen_key_enc` + `qwen_judge_model` |
| `judge_provider` Literal is `gemini \| openai \| both` | **Holds** | `routers/policies.py`, `class PolicyConfig`, field `judge_provider` |
| `openai` SDK is NOT in `requirements.txt` | **Holds** | `grep -in openai requirements.txt` → no match. ⚠ `google-generativeai==0.8.6` **is** pinned, so "no LLM SDKs" would be false; the accurate claim is that the OpenAI path uses `urllib`, and Qwen matches that path |
| The worker dispatches on `routing.uses_*` | **Holds** | `worker.py`, `_judge_verdict` — `if routing.uses_gemini:` / `if routing.uses_openai:` |
| `judge.content_blind_meta()` is the shared projection | **Holds** | `judge.py`, `def content_blind_meta`. Applied **once at the boundary** in `_judge_verdict`, not inside provider modules — Qwen inherits it for free and **must not re-implement it** |
| `crypto_secrets.decrypt_secret()` handles BYOK generically | **Holds — cite corrected** | The call is inside `judge_routing._decrypt_optional`, not at `judge_routing.py:197` (that line is the `try:`). **Cite the function, not the line** |
| Migration head is 0070 | **Holds — evidence corrected** | The draft proved it by filename. Actually proved: `0070_payment_events_org_index.py` has `revision = "0070"`, `down_revision = "0069"`, and no file anywhere has `down_revision = "0070"` |

### Premises the first draft did not state, and needed to

| Fact | Why it matters | Evidence |
|---|---|---|
| `allowed_models()` and `resolve_model()` each pick the default with a **two-way ternary** on `provider` | A third provider silently resolves to the **OpenAI** default — §3.1 | `judge_routing.py`, both functions: `settings.gemini_model if provider == "gemini" else settings.openai_model` |
| `PolicyConfig` is used for **both** the request body and the response, and `_to_config` feeds it the **raw stored** `judge_provider` | Narrowing the Literal 500s the read path for existing orgs — §3.2 | `routers/policies.py`, `_to_config` → `judge_provider=row.judge_provider` |
| The DSAR bundle publishes a **credential-completeness claim** and a registry-walking test enforces it | A new `*_key_enc` column makes a published statement false — §3.3 | `routers/account.py`, `EXPORT_WITHHELD_FIELDS["policy"]` + `EXPORT_STATEMENT`; `tests/integration/test_account_export_scope.py`, `test_every_credential_we_hold_is_named_in_the_manifest` |
| `Verdict.decision` is a **regex-pinned closed vocabulary** | `decision="human_review"` cannot be constructed — §3.4 | `schemas.py`, `class Verdict`: `pattern=r"^(clean\|breach\|unknown\|blocked\|redacted\|response_blocked)$"` |
| Nothing in the product implements a human-review queue | The escalation has no destination — §3.5 | `grep -rn "human_review\|review_queue\|escalat" app/` → only unrelated prose and `admin_staff` privilege text |
| The desktop and the dashboard both **coerce an unknown `judge_provider` back to `"gemini"`** | Any new value is silently reset on the next policy save — §3.6 | `desktop/policy_data.py` `_choice(d.get("judge_provider"), PROVIDERS, "gemini")`; `foxy-dashboard/foxy-audit-premium.html:5241` + `:5379` |
| `judge.combine()` is strictly **pairwise**, and the worker returns `verdicts[0]` for any count that is not 2 | Three verdicts would drop two — §3.7 | `worker.py`, `_judge_verdict` tail: `if len(verdicts) == 2: ... return verdicts[0]` |
| Both existing providers build their system prompt from `policy_config` | A hardcoded prompt ignores the tenant's policy — §3.8 | `openai_judge._build_system_prompt` / `_CONFIDENCE_RULES`, mirroring `gemini._CONFIDENCE_RULES` |
| Judge routing is **deliberately absent** from the policy snapshot | Adding a provider has **zero chain impact** — the one thing that is safe here | `grep -n judge_provider app/policy_snapshot.py` → no match |

---

## 3 · What the first draft missed

Eight findings. **1–5 would each have shipped a defect**; 1, 3 and 4 would have
shipped one the draft's own verification steps report as green.

### 3.1 🔴 A Qwen org would grade on the OpenAI default model

`allowed_models()` and `resolve_model()` both resolve the deployment default as:

```python
default = settings.gemini_model if provider == "gemini" else settings.openai_model
```

Two branches, and **everything that is not `"gemini"` takes the second one**. The
draft calls `resolve_model("qwen", …)` in `resolve_judge_routing` *and*
`allowed_models("qwen")` in `policies._to_config`, and never touches either
function. Consequences, all silent:

* an org with no Qwen pin resolves its model to **`gpt-5.6`**, which is then sent
  to dashscope as the `model` field;
* the verdict records `judge_provider="qwen"`, `judge_model="gpt-5.6"` — a
  **false provenance line in the audit ledger**, which is the one thing this
  product sells;
* `allowed_models("qwen")` returns `("gpt-5.6", "qwen-plus", …)`, so
  `_checked_model` **accepts `gpt-5.6` as a valid Qwen pin**.

⚠ This is the same shape as the C3b export bug — `(type==='logs_csv')?'csv':'json'`,
where every type the ternary did not name became `json`. The draft named that
trap for `"both"` and then walked past three more instances of it. **The fix is
a per-provider mapping that refuses an unknown provider, not a third branch.**

⚠ And the draft's Q1 verification step 3 — *"`PROVIDERS` shows 7 values"* — is
green while all of the above is true. That is §7 lie #4: *checks a token, not
the behaviour.*

### 3.2 🔴 Narrowing the `judge_provider` Literal 500s `GET /v1/policies`

The draft replaces the Literal with the seven named combinations and states:
*"No DB update, no migration of existing rows,"* with the compatibility shim in
`resolve_judge_routing()`.

But `PolicyConfig` is **one model used for both directions**, and `_to_config`
constructs it straight from the stored row:

```python
judge_provider=row.judge_provider,     # raw column value
```

Every org whose row says `"both"` — the stored value for every org that ever
chose two judges — would raise a pydantic `ValidationError` **on read**. The
shim never runs, because the policies router does not call
`resolve_judge_routing`.

**Fix:** `"both"` stays in the accepted vocabulary as a deprecated alias. It is
normalised on write and mapped at resolve time; no row is migrated, and no
tenant loses their policy page.

### 3.3 🔴 A new `*_key_enc` column makes a published claim false

`org_policies` will gain `qwen_key_enc`. The DSAR bundle publishes:

> *"every credential we hold for this workspace is named in `withheld_fields`,
> with what it is and why it cannot be sent"*

backed by `EXPORT_WITHHELD_FIELDS["policy"] = (("gemini_key_enc",
"openai_key_enc"), …)` and enforced by a registry-walking test. Adding the
column without adding the name makes `EXPORT_STATEMENT` **false at the moment of
the migration** — the exact defect class (#252b) that block of code exists to
prevent, and the failure mode #294 recorded: a stated fact that stops being true
underneath its own guard.

⚠ **The guard exists and would go red — and it does not run here.** The owner's
no-suites exception means `test_every_credential_we_hold_is_named_in_the_manifest`
will not be the thing that catches this. It has to be done by hand, in the same
commit as the migration, and re-broken by hand at the gate.

The draft never names `routers/account.py`.

### 3.4 🔴 `decision="human_review"` cannot be constructed — the headline feature

`Verdict.decision` carries a regex:

```python
pattern=r"^(clean|breach|unknown|blocked|redacted|response_blocked)$"
```

So `Verdict(decision="human_review", …)` raises `ValidationError` **inside
`qwen_judge.evaluate`**, where the module's own `except (… ValueError)` would
swallow it and return `_fallback("ValidationError")`. The agentic path would
degrade to "evaluator unavailable" and look like a network problem.

Two more collisions behind it, either of which is independently fatal:

* `judge.validate()` (called by the worker on every verdict) tests
  `decision not in {"clean", "breach"}` and **quarantines** anything else as
  `decision_out_of_schema`;
* `judge.combine()` filters to `decision in {"clean", "breach"}` before merging,
  so for any multi-provider org the escalation is **dropped on the floor**.

The feature that makes this Track 4 is the one part of the draft that cannot be
built as written. **The escalation must not ride the `decision` field** — see the
open decision in §4.

### 3.5 🔴 There is no human-review queue to escalate into

`grep -rn "human_review\|review_queue\|escalat" backend/app/` returns nothing
that implements one. The nearest real surfaces are `org_notifications` (the
breach email/digest path) and `enforcement_mode`, which decides whether a graded
breach emails a human.

The draft's §0 says the judge escalates "to a human queue instead of just scoring
them." **That queue does not exist**, and neither the three phases nor their file
lists build one. Shipping the tool-call without a destination would record an
escalation nothing acts on — placeholder functionality, which the hard rules
forbid in code as well as in UI.

### 3.6 🟠 "No UI changes" is false — both clients silently reset the org's provider

The draft's §9: *"No UI in any phase — this is backend-only work."* Two shipped
clients read `judge_provider` and coerce anything they do not recognise:

| Surface | The line | What happens to `judge_provider="gemini+qwen"` |
|---|---|---|
| Desktop | `desktop/policy_data.py` — `_choice(d.get("judge_provider"), PROVIDERS, "gemini")` | falls back to **`"gemini"`**, and the next save **writes that back** |
| Dashboard | `foxy-audit-premium.html:5241` `…value = p.judge_provider \|\| 'gemini'`, then `:5379` `(…\|\|{}).value \|\| 'gemini'` | a `<select>` set to a value with no matching `<option>` reads back `""`, so the save sends **`"gemini"`** |

So an org configured for Qwen loses that configuration the next time anyone saves
the policy page from either surface — **silent, and it looks like the backend
forgot.** The vault's what-breaks-what table names this exactly: *"any `/v1/*`
response shape → check `desktop/`, the one people forget."*

There is a second, smaller one in the same file:
`key_field()` computes `used = mode == "own" and judge_provider in (provider, "both")`,
which is `False` for every combination name — so the desktop would tell an org
its Qwen key is unused while the backend is using it.

**This is a phase, not a footnote.** It is Q4, and it needs the three frontend
skills for the dashboard half.

### 3.7 🟡 Three verdicts, and the worker returns one

```python
if len(verdicts) == 2:
    return judge.combine(verdicts[0], verdicts[1])
return verdicts[0]
```

With `"all"` selected this returns the **first** verdict and discards two —
including a possible breach. The draft *does* fix this with a `functools.reduce`
-shaped loop, and that is right; it is listed here because the draft files it
under "no change to `judge.py` needed", and one consequence does need deciding:

nesting `combine` **doubles the reason prefix** —
`combine(combine(g, o), q)` yields `"multi_judge_clean: multi_judge_clean: …"`
in a stored audit reason. Cosmetic, but it is evidence text a customer exports.
**Decision: strip a leading `multi_judge_*` prefix when re-merging**, in
`combine`, so the prefix appears exactly once regardless of provider count.

### 3.8 🟡 A hardcoded system prompt would ignore the tenant's policy

The draft's Q2 sketch: `_SYSTEM_PROMPT = "You are a strict AI-compliance evaluator..."  # same as gemini`.

It is not the same as gemini. Both existing providers **build** the prompt from
`policy_config` — `pii_detection`, `prompt_injection`, `regulated_data_mode`,
`max_token_threshold` and `confidence_threshold` each add or change a rule. A
static string would make Qwen the one judge that ignores every policy toggle the
customer set, while the dashboard goes on showing those toggles as active.

`qwen_judge` builds its prompt the same way, from the same inputs.

---

## 4 · Owner decisions

### Carried from 2026-09-04, unchanged

| Decision | Chosen | Why |
|---|---|---|
| Multi-provider model | **Named combinations** | `"gemini"`, `"openai"`, `"qwen"`, `"gemini+openai"`, `"gemini+qwen"`, `"openai+qwen"`, `"all"`. Stored `"both"` maps to `"gemini+openai"` |
| Tool-calling | **Yes — agentic judge** | Track 4: "custom skills, MCP integrations" |
| API key | **Build first, owner adds key later** | With no key the provider returns `evaluator_unavailable`, exactly as Gemini and OpenAI do today |

Setting the key, once the owner has one (carried verbatim from the first draft):

```bash
# 1. Get a key from qwencloud.com
#    (hackathon voucher: qwencloud.com/challenge/hackathon/voucher-application)
# 2. Add it to backend/.env:
echo "QWEN_API_KEY=sk-XXXXXXXXXXXXXXXX" >> backend/.env
#
# 3. Or as a deployment environment variable, in the Alibaba Cloud console:
#    your app -> Environment Variables -> QWEN_API_KEY = sk-XXXXXXXXXXXXXXXX
```

⚠ **`judge_provider` is `String(16)`.** The longest name above is
`"gemini+openai"` at 13 characters. `"all"` exists *because* the spelled-out
triple would be 18 and would not fit. A future fourth provider needs a column
widening, not a longer name.

### OPEN — blocking Q2, not Q1

**How does an escalation get recorded, and where does it go?** §3.4 rules out the
drafted answer and §3.5 says there is no queue. Three shapes, materially
different work:

| | Shape | Cost | Honest? |
|---|---|---|---|
| **A (recommended)** | `Verdict` gains `human_review_requested: bool` + `human_review_reason`; `decision` stays `clean`/`breach`. The escalation rides the **existing** breach-notification path (`org_notifications`) | small — one schema field, one notifier branch | Yes. The "queue" is the notification surface that already exists, and we say so |
| **B** | Widen the `decision` enum to include `human_review` | wide — `validate()`, `combine()`, and every reader of `decision`: dashboard, desktop, passport, exports, verifier docs | Risky. `decision` is evidence vocabulary; `local_verdict` is hashed (V4 `verdict_hash`) |
| **C** | Build a real review queue — table, migration, endpoints, dashboard page | large — its own two or three phases | Yes, and it is what "queue" actually means |

**Recommendation: A.** It satisfies Track 4 — the model calls a tool and the
tool changes what the system does — without putting a new value into the
vocabulary the chain and four surfaces read, and without claiming a queue that
does not exist. C is the right eventual answer if human review becomes a
product feature; it is not a hackathon-week phase.

⚠ Q1 does not depend on this. Q2 does not start until it is answered.

---

## 5 · The traps

**"Both" is a lie in a three-provider world.** Stored `"both"` means
gemini+openai. It stays an accepted, deprecated alias — normalised on write,
mapped at resolve time, never migrated in the database, and **never removed from
the Literal** (§3.2).

**Model IDs are volatile.** `qwen-plus`, `qwen3.5-plus`, `qwen3.7-max-preview`
change in days. The default comes from `settings.qwen_model`; org pins validate
against `JUDGE_MODELS["qwen"]`; an unknown stored value falls back to the
deployment default, as Gemini and OpenAI already do. **Never hardcode a model id
in the provider module** — and never let a *provider* fall through to another
provider's default (§3.1).

**Tool-calling must not break grading.** A tool-call is optional. No call →
grading proceeds normally. A malformed or unparseable tool-call must return
`_fallback()`, never raise into the worker.

**Content-blindness is already handled — do not re-implement it.**
`_judge_verdict` projects `meta` **once, at the boundary**, before any provider
is called. `qwen_judge.evaluate` receives already-projected metadata. Adding a
second projection inside the module would be harmless today and would rot into
the drift the boundary comment exists to prevent.

---

## 6 · Phases

| Phase | Branch | Scope | Blocked on |
|---|---|---|---|
| **Q1** | `feat/qwen-judge-routing` | Migration 0071 · per-provider default mapping · `config.py` · `models.py` · `judge_routing.py` · `policies.py` · **`account.py` withheld fields** | — |
| **Q2** | `feat/qwen-judge-provider` | `qwen_judge.py` + tests | **the §4 open decision** |
| **Q3** | `feat/qwen-judge-worker` | `worker.py` dispatch · `judge.py` N-way combine + prefix fix | Q1, Q2 |
| **Q4** | `feat/qwen-judge-surfaces` | `desktop/policy_data.py` + dashboard provider `<select>` | Q1 |

**After each merge:** update §10 with the SHA, append a devlog entry to
`G:\My Drive\Life\03 Projects\Foxy Audit\Alibaba Submission Changes\Devlogs\`,
and re-stamp `Alibaba Submission Changes/CLAUDE.md`.

---

## 7 · Phase Q1 — plumbing, and the ternary that has to die

### Files

| File | Change |
|---|---|
| `backend/migrations/versions/0071_qwen_judge_provider.py` | **new** — two nullable columns |
| `backend/app/config.py` | `qwen_api_key`, `qwen_model`, `qwen_timeout`, `qwen_base_url` |
| `backend/app/models.py` | `OrgPolicy.qwen_key_enc`, `OrgPolicy.qwen_judge_model` |
| `backend/app/judge_routing.py` | `PROVIDERS`, `JUDGE_MODELS`, **`_PROVIDER_DEFAULTS`**, `allowed_models`, `resolve_model`, `JudgeRouting`, `resolve_judge_routing` |
| `backend/app/routers/policies.py` | `PolicyConfig`, `_to_config`, PUT handler |
| `backend/app/routers/account.py` | **`EXPORT_WITHHELD_FIELDS["policy"]`** — §3.3 |

### The default mapping — replacing both ternaries

```python
# One place that answers "what is this provider's deployment default model".
# A mapping, not a chain of ternaries: an unknown provider must RAISE here
# rather than silently inherit another provider's default. That is exactly how
# a third provider would otherwise grade on `settings.openai_model` and record
# a false judge_model on the verdict.
_PROVIDER_DEFAULTS = {
    "gemini": lambda s: s.gemini_model,
    "openai": lambda s: s.openai_model,
    "qwen":   lambda s: s.qwen_model,
}


def default_model(provider: str) -> str:
    settings = get_settings()
    try:
        return _PROVIDER_DEFAULTS[provider](settings)
    except KeyError:
        raise ValueError(f"no deployment default for judge provider {provider!r}")
```

`allowed_models()` and `resolve_model()` both call `default_model(provider)`.
Their bodies are otherwise unchanged — the fallback posture (an unknown *stored
pin* degrades to the default, it does not fail the grade) is deliberate and stays.

### The provider vocabulary

```python
PROVIDERS = ("gemini", "openai", "qwen",
             "gemini+openai", "gemini+qwen", "openai+qwen", "all")

# Stored before qwen existed; still written by any client that has not been
# updated. NOT migrated in the database and NOT removed from the API vocabulary
# — see the plan's §3.2.
PROVIDER_ALIASES = {"both": "gemini+openai"}

_PROVIDER_MEMBERS = {
    "gemini": {"gemini"}, "openai": {"openai"}, "qwen": {"qwen"},
    "gemini+openai": {"gemini", "openai"},
    "gemini+qwen": {"gemini", "qwen"},
    "openai+qwen": {"openai", "qwen"},
    "all": {"gemini", "openai", "qwen"},
}


def normalise_provider(value: str | None) -> str:
    resolved = PROVIDER_ALIASES.get(value, value)
    return resolved if resolved in PROVIDERS else DEFAULT_PROVIDER
```

`JudgeRouting.uses_gemini` / `uses_openai` / `uses_qwen` all read
`_PROVIDER_MEMBERS[self.provider]`, so a new combination cannot be added to
`PROVIDERS` and forgotten in three properties. `key_for` / `model_for` become
dict lookups over `{"gemini": …, "openai": …, "qwen": …}` for the same reason.

### `policies.py`

* the Literal gains the seven names **and keeps `"both"`** (deprecated alias);
* `_to_config` passes `normalise_provider(row.judge_provider)` so a stored
  `"both"` reads back as `"gemini+openai"` and the response validates;
* the PUT handler stores `normalise_provider(body.judge_provider)`, so writing
  `"both"` converts the row on the next save without a data migration;
* `qwen_api_key` (write-only), `qwen_key_set` (read-only), `judge_qwen_model`
  (writable) mirror the existing pairs exactly — `_store_key` and
  `_checked_model` are reused unchanged;
* `judge_models` and `judge_models_available` gain a `"qwen"` key. Both are
  additive dicts; `desktop/dashboard.py` takes named keys from them, so a new
  key is inert there (Q4 is about `judge_provider`, not these).

### `account.py` — the credential claim

```python
    "policy": (("gemini_key_enc", "openai_key_enc", "qwen_key_enc"),
               "the AI-provider keys you brought to this workspace",
               ...)
```

The prose is already plural and provider-neutral, so only the tuple changes.
**In the same commit as the migration.**

### Migration 0071

Two nullable columns, `revision = "0071"`, `down_revision = "0070"`, no data
migration, no server default — matching 0058's reasoning for the existing model
columns (NULL means "inherit the deployment default").

### Verification — behaviour, not tokens

The draft's *"`PROVIDERS` shows 7 values"* is green while §3.1 is broken. These
are the checks that can fail:

1. `python -m py_compile` on every changed file.
2. `alembic heads` returns exactly **one** head, `0071`.
3. **`default_model("qwen") == settings.qwen_model`**, and
   `default_model("qwen") != settings.openai_model` with the two set to
   different values — the §3.1 regression, stated as an inequality.
4. **`default_model("nope")` raises `ValueError`** — the refusal is the point.
5. `"gpt-5.6" not in allowed_models("qwen")`.
6. `normalise_provider("both") == "gemini+openai"`, and a `JudgeRouting` built
   from it reports `uses_gemini and uses_openai and not uses_qwen`.
7. **`PolicyConfig(judge_provider="both")` constructs** — the §3.2 regression.
8. `"qwen_key_enc"` is in `EXPORT_WITHHELD_FIELDS["policy"][0]`, and
   `grep -c "_key_enc" app/routers/account.py` accounts for it.
9. Scope: `git diff --stat origin/main...feat/qwen-judge-routing` names the six
   files plus the migration, and nothing else.

⚠ **Re-break three of these by hand before trusting them** (`START HERE` §7):
revert `default_model` to the old ternary and confirm 3 goes red; drop `"both"`
from the Literal and confirm 7 goes red; remove `"qwen_key_enc"` from the tuple
and confirm 8 goes red.

---

## 8 · Phase Q2 — the provider module ⛔ blocked on the §4 decision

`backend/app/qwen_judge.py`, structurally a sibling of `openai_judge.py`:

* `urllib` only, no new dependency, POST to
  `{settings.qwen_base_url}/chat/completions`;
* `_build_system_prompt(policy_config, history)` built the same way as the other
  two, from the same policy toggles and the same `_CONFIDENCE_RULES` contract
  (§3.8) — **not a static string**;
* the metadata it receives is already content-blind (§5);
* `judge_provider="qwen"`, `judge_model=model_id`, `graded_by="ai"` stamped on
  the success path **only**, matching `openai_judge`;
* `_fallback(reason)` honouring `settings.gemini_fail_closed`, same as the other
  two;
* the `tools` array carrying `flag_for_human_review`;
* tool-call handling **in whatever shape the §4 decision settles on** — and
  parsing that never raises into the worker.

⚠ `response_format` support is TBD (§2). If Qwen rejects a JSON schema, the
fallback is system-prompt JSON enforcement, which is what `gemini.py` does today.

Tests: clean · breach · no key · network failure · malformed tool-call ·
content-blindness (the projection reaching the wire carries no unexpected key) ·
and the escalation path, once its shape exists.

---

## 9 · Phase Q3 — worker dispatch and N-way combine

`worker._judge_verdict` gains the Qwen branch, in the same shape as the other
two (`routing.can_call("qwen")` or `qwen_judge._fallback(...)`), and the tail
becomes a left fold:

```python
result = verdicts[0]
for verdict in verdicts[1:]:
    result = judge.combine(result, verdict)
return result
```

`judge.combine` gains **one** change beyond that: strip a leading
`multi_judge_breach: ` / `multi_judge_clean: ` from a reason it is re-merging, so
a three-provider grade reads with the prefix once (§3.7).

⚠ `verdicts` is never empty — every value in `PROVIDERS` names at least one
member — but `verdicts[0]` on an empty list is an `IndexError` in the worker, so
the fold asserts non-empty rather than assuming it.

---

## 10 · Phase Q4 — the two clients that would undo the feature

**Desktop** (`desktop/policy_data.py`): `PROVIDERS` gains the new names so
`_choice` stops coercing them to `"gemini"`, and `key_field()`'s
`judge_provider in (provider, "both")` becomes a membership test over the same
`_PROVIDER_MEMBERS` shape the backend uses.

**Dashboard** (`foxy-dashboard/foxy-audit-premium.html`): the provider `<select>`
gains the new options; the save path stops defaulting a missing value to
`"gemini"`.

⚠ **The dashboard half is UI work.** Load all three frontend skills, in order —
`ui-ux-pro-max`, then `impeccable`, then `frontend-design` — before touching the
markup. No chart is involved, so `dataviz` is not loaded, and this sentence is
the record of that decision.

---

## 11 · Mandatory skills

Q1–Q3 are backend-only: no frontend skills. **Q4 is not** — see §10.
`code-review` before every merge. `security-review` on Q1, which adds a
credential column and touches the DSAR credential manifest.

---

## 12 · Where to write after each merge

| What | Where |
|---|---|
| Devlog | `G:\My Drive\Life\03 Projects\Foxy Audit\Alibaba Submission Changes\Devlogs\YYYY-MM-DD.md` (append `## Q<N>`) |
| Plan update | **this file**, §13 |
| Hub note | `Alibaba Submission Changes/CLAUDE.md` — bump `verified-against:` |
| Area note | `Backend/CLAUDE.md` — re-stamp, add the Qwen section |
| Anything noticed and not fixed | `Worth Noting — Issues`, with its normal number |

---

## 13 · Log of changes to this plan

| Date | SHA | What |
|---|---|---|
| 2026-09-04 | `d4c3dde` | Plan written at `12a9ade`. Three phases, owner decisions captured |
| 2026-09-04 | *(this revision)* | Re-verified every premise at `d4c3dde`. Eight findings (§3): the provider ternary that resolves Qwen to the OpenAI default · the Literal that 500s the policy read · the DSAR credential claim · `decision="human_review"` rejected by the schema in three places · no human-review queue exists · both shipped clients silently reset the provider · pairwise `combine` · a static system prompt. Phases go 3 → 4 (Q4: the clients). Q2 now blocked on an open owner decision about the escalation's shape |
