# Qwen Agentic Judge — Track 4 hackathon feature

**Plan of record** · 2026-09-04 · owner decisions captured same day.

Base `12a9ade`. Repo facts read at that SHA; Qwen Cloud endpoint verified from
owner's dated documentation (see owner message 2026-09-04). **Model IDs are
explicitly volatile** — the plan says "check console before build" and the code
defaults from `settings`, never from a hardcoded string.

---

## 0 · The one-paragraph version

Add **Qwen** (Alibaba Cloud's LLM) as a third AI judge provider with **agentic
tool-calling** ability. The judge can call `flag_for_human_review` during grading,
escalating high-risk or ambiguous events to a human queue instead of just scoring
them. This targets the hackathon's **Track 4: Agentic Applications** criterion
("custom skills, MCP integrations, agents") — it turns a text-grading LLM into an
agent that makes decisions and invokes tools. The integration is three phases:
routing plumbing (Q1), the provider module (Q2), worker dispatch (Q3). No UI
changes. No new pip dependency (uses `urllib` like `openai_judge.py`).

---

## 1 · Context

The hackathon scores **"custom skills, MCP integrations"** under Track 4. Right
now the product has two AI judges (Gemini, GPT-5.6) that receive content-blind
metadata and return JSON verdicts — both are passive text graders. Adding a third
provider that can **call tools** during evaluation turns it into an agent: the
model decides whether to escalate, not just what score to give.

**Why Qwen:** the hackathon is an Alibaba Cloud event. Using Qwen's model on
Alibaba infrastructure is the proof-of-deployment the judges look for. The owner's
documentation confirms Qwen has an OpenAI-compatible `/chat/completions` endpoint
at `https://dashscope-intl.aliyuncs.com/compatible-mode/v1` and supports standard
OpenAI-style function-calling via the `tools` parameter.

**Why tool-calling matters:** a judge that returns a verdict is "we called an LLM."
A judge that **decides to escalate** via tool-call is "we built an agent." That's
the distinction Track 4's criteria care about.

---

## 2 · The premises — verified at `12a9ade`

| Premise | Holds? | Evidence |
|---|---|---|
| Qwen has an OpenAI-compatible `/chat/completions` endpoint | **Yes** | Owner doc: `dashscope-intl.aliyuncs.com/compatible-mode/v1` |
| Qwen supports function-calling via `tools` parameter | **Yes** | Owner's Step 3 code — standard OpenAI-style |
| Qwen supports `response_format` with JSON schema | **TBD — verify at test time** | If not, fall back to system-prompt JSON enforcement (same as Gemini) |
| Model IDs change fast — must not be hardcoded | **Yes** | Owner's explicit caveat: "check console before build." Code defaults from `settings.qwen_model` |
| Adding a provider needs a DB migration | **Yes** | `OrgPolicy` needs `qwen_key_enc` + `qwen_judge_model` columns |
| `judge_provider` Literal needs expanding | **Yes** | Currently `"gemini" \| "openai" \| "both"` — owner chose named combinations |
| `openai` SDK is NOT in requirements.txt | **Yes** | `openai_judge.py` uses `urllib` (stdlib). We match that — no new dependency |
| The worker dispatches by `routing.uses_*` properties | **Yes** | `worker.py:199-215` — branch on `uses_gemini` / `uses_openai` |
| `judge.content_blind_meta()` is the shared projection | **Yes** | `judge.py:54` — one allowlist, both providers use it. Qwen inherits it |
| `crypto_secrets.decrypt_secret()` handles BYOK keys | **Yes** | `judge_routing.py:197` — generic, provider-agnostic |
| Migration head is 0070 | **Yes** | `0070_payment_events_org_index.py` is the latest |

⚠ **One thing I could not verify:** whether Qwen's function-calling returns
`tool_calls` in the same JSON shape as OpenAI's Responses API (which uses `output`
arrays with `type: "function_call"`). The provider module must handle both shapes
or verify the exact one at test time. Recorded as TBD.

---

## 3 · Owner decisions — 2026-09-04

| Decision | Chosen | Why |
|---|---|---|
| Multi-provider model | **Named combinations** | `"gemini"`, `"openai"`, `"qwen"`, `"gemini+openai"`, `"gemini+qwen"`, `"openai+qwen"`, `"all"`. Old `"both"` maps to `"gemini+openai"` at resolve time |
| Tool-calling | **Yes — agentic judge** | Hackathon criterion: "custom skills, MCP integrations" |
| API key | **Build first, owner adds key later** | Code falls back to `evaluator_unavailable` when no key is set |

### Commands to set the API key (owner runs these after getting the key)

```bash
# 1. Get a key from qwencloud.com (hackathon voucher: $40 at qwencloud.com/challenge/hackathon/voucher-application)
# 2. Add it to backend/.env:
echo "QWEN_API_KEY=sk-XXXXXXXXXXXXXXXX" >> backend/.env

# 3. Or set it as a deployment environment variable (Alibaba Cloud):
#    In the Alibaba Cloud console → your app → Environment Variables:
#    QWEN_API_KEY = sk-XXXXXXXXXXXXXXXX
```

---

## 4 · The trap that looks easy

**"Both" is a lie in a three-provider world.** Today `judge_provider="both"` means
gemini+openai. With qwen, `"both"` is ambiguous — does it mean gemini+qwen?
openai+qwen? all three? The fix: expand to named combinations, and add a resolve-
time shim that maps stored `"both"` to `"gemini+openai"`. No DB update, no
migration of existing rows. The shim lives in `resolve_judge_routing()`.

**Model IDs are volatile.** `qwen-plus`, `qwen3.5-plus`, `qwen3.7-max-preview`,
`qwen3.8-max` — these change in days. The default comes from `settings.qwen_model`
(owner sets in `.env`), org pins are validated against `JUDGE_MODELS["qwen"]`, and
an unknown stored value falls back to the deployment default (same as gemini/openai
do today). **Never hardcode a model ID in the provider module.**

**Tool-calling must not break grading.** The judge's tool-calls are **optional** —
if the model doesn't call a tool, grading proceeds normally. If it does call
`flag_for_human_review`, the verdict carries `decision="human_review"`. A provider
that errors on tool-call parsing must not crash the worker — it must return
`_fallback()` like every other provider.

---

## 5 · Phases

| Phase | Branch | Scope | Files |
|---|---|---|---|
| **Q1** | `feat/qwen-judge-routing` | Migration + routing plumbing | Migration 0071, `config.py`, `models.py`, `judge_routing.py`, `policies.py` |
| **Q2** | `feat/qwen-judge-provider` | Qwen provider module + tests | `qwen_judge.py`, `tests/test_qwen_judge.py` |
| **Q3** | `feat/qwen-judge-worker` | Worker dispatch + combine | `worker.py`, `judge.py` (3-provider combine) |

**After each merge:** update this plan file with the SHA, append a devlog entry in
`G:\My Drive\Life\03 Projects\Foxy Audit\Alibaba Submission Changes\Devlogs\`, and
re-stamp `Alibaba Submission Changes/CLAUDE.md`.

---

## 6 · Phase Q1: DB migration + routing

### Files to change

- `backend/migrations/versions/0071_qwen_judge_provider.py` — **new**
- `backend/app/config.py:27-35` — add qwen settings
- `backend/app/models.py:442-450` — add qwen columns to `OrgPolicy`
- `backend/app/judge_routing.py:45-62` — expand PROVIDERS, JUDGE_MODELS, JudgeRouting
- `backend/app/judge_routing.py:214-254` — expand `resolve_judge_routing()`
- `backend/app/routers/policies.py:62-77` — expand `PolicyConfig` schema
- `backend/app/routers/policies.py:243-276` — expand PUT handler

### Migration 0071

```python
"""add qwen judge provider columns to org_policies

Revision ID: 0071
Revises: 0070
Create Date: 2026-09-04
"""
from alembic import op
import sqlalchemy as sa

revision = "0071"
down_revision = "0070"
branch_labels = None
depends_on = None

def upgrade():
    op.add_column("org_policies",
        sa.Column("qwen_key_enc", sa.Text(), nullable=True))
    op.add_column("org_policies",
        sa.Column("qwen_judge_model", sa.String(64), nullable=True))

def downgrade():
    op.drop_column("org_policies", "qwen_judge_model")
    op.drop_column("org_policies", "qwen_key_enc")
```

Both columns are nullable — every org starts with no Qwen key and inherits the
deployment default model. No data migration needed.

### config.py additions (after line 35)

```python
    qwen_api_key: str = ""
    qwen_model: str = "qwen-plus"
    qwen_timeout: float = 12.0
    qwen_base_url: str = "https://dashscope-intl.aliyuncs.com/compatible-mode/v1"
```

### judge_routing.py changes

```python
# Line 45:
PROVIDERS = ("gemini", "openai", "qwen",
             "gemini+openai", "gemini+qwen", "openai+qwen", "all")

# Line 59-62: add to JUDGE_MODELS
JUDGE_MODELS = {
    "gemini": ("gemini-2.5-flash", "gemini-2.5-pro", "gemini-2.0-flash"),
    "openai": ("gpt-5.6", "gpt-5.6-mini", "chat-latest"),
    "qwen": ("qwen-plus", "qwen3.5-plus"),
}

# Backwards-compat shim (inside resolve_judge_routing, after line 227):
# "both" was gemini+openai before qwen existed. Map it at resolve time.
_provider_compat = {"both": "gemini+openai"}
provider = _provider_compat.get(provider, provider)

# JudgeRouting dataclass gains:
    qwen_key: str | None = None
    qwen_model: str | None = None

    @property
    def uses_qwen(self) -> bool:
        return self.provider in ("qwen", "gemini+qwen", "openai+qwen", "all")

    def key_for(self, provider: str) -> str | None:
        if provider == "qwen":
            return self.qwen_key
        return self.gemini_key if provider == "gemini" else self.openai_key

    def model_for(self, provider: str) -> str | None:
        if provider == "qwen":
            return self.qwen_model
        return self.gemini_model if provider == "gemini" else self.openai_model

# resolve_judge_routing() gains qwen decryption (after line 249):
    qwen_model = resolve_model("qwen", policy.qwen_judge_model)
    # ... in BYOK path:
    qwen_key = (_decrypt_optional(policy.qwen_key_enc, oid, "qwen", problems)
                if provider in ("qwen", "gemini+qwen", "openai+qwen", "all") else None)
```

### policies.py changes

```python
# Line 62:
    judge_provider: Literal["gemini", "openai", "qwen",
                            "gemini+openai", "gemini+qwen", "openai+qwen", "all"] = "gemini"

# After line 67:
    qwen_api_key: str | None = Field(default=None, max_length=512, exclude=True)
    qwen_key_set: bool = False
    judge_qwen_model: str | None = Field(default=None, max_length=64)

# In _to_config() — add to judge_models and judge_models_available dicts:
    "qwen": resolve_model("qwen", row.qwen_judge_model),
    # ...
    "qwen_key_set": bool((row.qwen_key_enc or "").strip()),
    # ...
    judge_models_available={..., "qwen": list(allowed_models("qwen"))}

# In PUT handler — after openai_key_enc storage:
    row.qwen_key_enc = _store_key(body.qwen_api_key, row.qwen_key_enc, org.id, "qwen")
    if "judge_qwen_model" in body.model_fields_set:
        row.qwen_judge_model = _checked_model("qwen", body.judge_qwen_model,
                                              row.qwen_judge_model)
```

### Verification

1. `python -m py_compile` on all 5 modified files
2. `alembic upgrade head` succeeds (one head: 0071)
3. `python -c "from backend.app import judge_routing; print(judge_routing.PROVIDERS)"` shows 7 values
4. `git diff --stat origin/main...feat/qwen-judge-routing` — only the 5 files + migration
5. Backwards-compat: org with `judge_provider="both"` resolves to `uses_gemini=True` and `uses_openai=True`

### Executor prompt for Q1

```
Build Phase Q1 per docs/plans/qwen-judge.md at SHA 12a9ade.

Branch: feat/qwen-judge-routing (from origin/main via worktree)
Scope: Migration 0071, config.py, models.py, judge_routing.py, policies.py
Do NOT touch: worker.py, gemini.py, openai_judge.py, judge.py, or any test file.

Key rules:
- "both" backwards-compat shim in resolve_judge_routing(), NOT in the DB
- qwen model defaults from settings.qwen_model, never hardcoded
- _store_key and _decrypt_optional handle encryption — reuse exactly
- All 7 provider values in the Literal type

Verify: py_compile on all files, alembic upgrade head, PROVIDERS shows 7 values.
Report: what you built, what in the plan you found wrong, the revision ID, diff stat.
```

---

## 7 · Phase Q2: Qwen provider module

### Files

- `backend/app/qwen_judge.py` — **new**, same contract as `gemini.py` / `openai_judge.py`
- `backend/tests/test_qwen_judge.py` — **new**, unit tests

### qwen_judge.py structure

```python
"""Qwen compliance judge with agentic tool-calling.

Uses the OpenAI-compatible endpoint at settings.qwen_base_url with standard
urllib (no openai SDK dependency). Supports function-calling for escalation
to human review.
"""

_BASE_URL = None  # resolved from settings at call time
_SYSTEM_PROMPT = "You are a strict AI-compliance evaluator..."  # same as gemini
_TOOLS = [{
    "type": "function",
    "function": {
        "name": "flag_for_human_review",
        "description": "Escalate to human reviewer when metadata is ambiguous or high-risk",
        "parameters": {
            "type": "object",
            "properties": {
                "reason": {"type": "string"},
                "risk_score": {"type": "integer", "minimum": 0, "maximum": 100}
            },
            "required": ["reason", "risk_score"]
        }
    }
}]

def evaluate(meta, policy_config=None, history=None, api_key=None, model=None) -> Verdict:
    # 1. Resolve key: api_key (BYOK) or settings.qwen_api_key (platform)
    # 2. If no key: return _fallback("no_api_key")
    # 3. Build messages: system prompt + user message with metadata JSON
    # 4. POST to {qwen_base_url}/chat/completions with tools + response_format
    # 5. Parse response: check for tool_calls in response
    # 6. If tool_call to flag_for_human_review: verdict.decision = "human_review"
    # 7. Return Verdict with judge_provider="qwen", judge_model=model_id
    # 8. On failure: return _fallback(type(exc).__name__)
```

### System prompt additions for agentic context

Added to the base system prompt (after the policy-aware rules):

```
"You MAY call flag_for_human_review when: (1) risk_score >= 70 and the evidence
is ambiguous, (2) repeated breaches from the same session, or (3) the metadata
suggests a pattern that requires human context. If you call this tool, the
verdict will be escalated to a human compliance reviewer for final determination."
```

### Tool-call handling

The Qwen endpoint returns tool-calls in the response. The provider module must:
1. Check if `response.choices[0].message.tool_calls` is non-empty
2. If a `flag_for_human_review` call exists, extract its arguments
3. Build the verdict with `decision="human_review"` and the tool's reason/risk_score
4. If no tool-call, proceed with normal JSON verdict parsing

⚠ **TBD: verify the exact response shape.** OpenAI's Responses API uses `output`
arrays with `type: "function_call"`. Qwen's `/chat/completions` may use the
standard OpenAI Chat Completions shape (`message.tool_calls`). The module must
handle whichever shape Qwen actually returns.

### Tests

- `test_qwen_evaluate_clean()` — metadata with no breach signals → clean verdict
- `test_qwen_evaluate_breach()` — high token count + hipaa tag → breach verdict
- `test_qwen_evaluate_human_review()` — ambiguous metadata triggers tool-call → human_review verdict
- `test_qwen_no_key()` — no API key → evaluator_unavailable fallback
- `test_qwen_content_blind()` — verify metadata projection matches `judge.content_blind_meta()`
- `test_qwen_failure()` — network error → _fallback, never raises

### Verification

1. `python -m py_compile backend/app/qwen_judge.py`
2. All 6 tests pass
3. `python -c "from backend.app import qwen_judge; v = qwen_judge.evaluate({'token_count': 100}); print(v.decision)"` — works or returns _fallback (no key)
4. No `import openai` in the module (stdlib only)

---

## 8 · Phase Q3: Worker dispatch + 3-provider combine

### Files

- `backend/app/worker.py:196-215` — add Qwen branch in `_judge_verdict`
- `backend/app/judge.py:142-177` — extend `combine()` for 3+ providers (already handles 2, generalize)

### worker.py changes

After line 212 (openai verdict), add:

```python
if routing.uses_qwen:
    verdicts.append(
        qwen_judge.evaluate(meta, policy_config, history=history,
                            api_key=routing.qwen_key,
                            model=routing.qwen_model)
        if routing.can_call("qwen")
        else qwen_judge._fallback(routing.problems.get("qwen", "no_api_key")))
```

Replace line 213-215:

```python
# Old:
if len(verdicts) == 2:
    return judge.combine(verdicts[0], verdicts[1])
return verdicts[0]

# New:
result = verdicts[0]
for v in verdicts[1:]:
    result = judge.combine(result, v)
return result
```

### judge.py combine() — already handles N=2

The current `combine(first, second)` works for any two verdicts. The worker now
calls it iteratively: `combine(combine(gemini, openai), qwen)`. No change to
`judge.py` needed — the existing logic (breach wins, unknown is not clean, max
risk_score, join providers/models) works for any pair.

### Verification

1. `python -m py_compile backend/app/worker.py`
2. Import check: `python -c "from backend.app import worker"` succeeds
3. `git diff --stat origin/main...feat/qwen-judge-worker` — only worker.py changed
4. No test suites (owner rules), but `alembic heads` still returns one (0071)

---

## 9 · MANDATORY SKILLS

⚠ **No UI in any phase** — this is backend-only work. No frontend skills needed.

Before any merge: `code-review` skill (if available in this session).

---

## 10 · Where to write after each merge

| What | Where |
|---|---|
| Devlog | `G:\My Drive\Life\03 Projects\Foxy Audit\Alibaba Submission Changes\Devlogs\2026-09-04.md` (append `## Q<N>`) |
| Plan update | **This file** — add the merge SHA, what changed, what was found |
| Hub note | `Alibaba Submission Changes/CLAUDE.md` — bump `verified-against:` |
| Vault area note | `Backend/CLAUDE.md` — re-stamp `verified-against:`, add Qwen section |

---

## 11 · Log of changes to this plan

| Date | SHA | What |
|---|---|---|
| 2026-09-04 | *(not yet committed)* | Plan written. Awaiting Q1 build. |
