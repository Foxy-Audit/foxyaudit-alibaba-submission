# Desktop guarded chat — the mock-LLM sandbox, inside the fox

Planned 2026-08-16 against `main` @ `750126d`. Moves `demo/mock_llm.py`'s
interactive experience — the preflight guard, the blocked decision, and the
whole terminal read-out — into the desktop companion's chat popup, where a
person can see it instead of reading a console.

> **Built 2026-08-16** on `feat/desktop-guarded-chat` (`f44dca9`, `7657328`),
> off `920ed3f`. Two things below were WRONG and the branch does not follow
> them:
>
> 1. **The policy is a setting, not an auto-selection.** `hipaa` and `gdpr` run
>    the same detector and differ only in whether a finding is filed as `phi` or
>    `pii` — measured, identical signals — so no heuristic reading the prompt can
>    choose between them. Ordering the list `hipaa → gdpr → default` still
>    labels every email address `phi`. `FoxSettings.guard_policy()` now holds the
>    tag (default `gdpr`), and `foxy_guard` has no `choose_policy` at all.
> 2. **The API key stays in Settings › Foxy Audit**, where it already lived. The
>    strip opens that tab instead of carrying a second key field, so the two
>    cannot disagree about what the key is.
>
> The separate one-line demo defect found while building is on
> `fix/demo-offline-gate` (`50f38af`) and does not depend on this branch.

## Why this exists

`demo/mock_llm.py` already does the right thing: it runs the **real** SDK guard
in front of a deterministic model, then prints the decision, the rules and
signals that fired, both commitment hashes, and whether the model was called at
all. It is the clearest demonstration the product has. It is also a terminal,
which means the audience is one person with a keyboard.

The desktop app already carries every piece needed to show that to somebody:
a chat popup (`desktop/clay_chat_popup.py`), a UDP listener that already
understands `policy_breach` (`desktop/sdk_bridge.py`), a fox that already
flashes red on one (`desktop/security_overlay.py`), and an overlay-card pattern
built for exactly this shape of statement (`chrome_widgets.LockOverlay`).

Nothing connects them. The chat calls `ai_providers.call_ai()` directly — **no
guard, no policy, no commitment, no evidence**. The one surface that carries the
fox's face is the one surface where the product does not run.

## What ships

1. **The guard runs in front of every chat message.** Prompt → `policy.evaluate`
   → `@foxy.audit` → the model → response scan. The same SDK, the same rules,
   the same hashes as the demo.
2. **A blocked prompt raises an in-window overlay** that states what was blocked,
   under which policy, on which rules — and whether the model ran.
3. **Every turn gets a receipt** under the reply: the terminal's exact fields,
   collapsed to one line, expandable to all of them.
4. **A Foxy key lives in the chat**, so events can ship to the ledger without
   opening Settings.
5. **A `mock` provider**, so all of the above runs with no key, no network and
   no model bill — the demo's own guarantee, kept.

## Owner decisions taken here (say so if any is wrong)

1. **Default guard mode is `block`, with the policy auto-selected** the way the
   demo does it (`hipaa` → `gdpr` → `default`, first tag that fires). This is
   the setting that makes the popup happen, and this chat is the demo surface.
   It also means an ordinary chat message containing an email address will be
   blocked. The guard strip states the mode and switches it in one click.
2. **`desktop_ping` stays on** for the chat's client. A block already emits
   `{"event": "policy_breach", …}`, `sdk_bridge` already routes it, and
   `SecurityOverlay.flash_red()` already answers it — so the fox reacts to the
   chat's own block for free. Verified at `sdk/src/foxy_audit/client.py:382`.
3. **The SDK, `demo/mock_llm.py` and the wire contract are not touched.** No new
   `event_type`, no new `event_metadata` key (that would need a backend-first
   deploy), no change to the demo that gates merges.

## The shape

### Files

| | file | what |
|---|---|---|
| new | `desktop/foxy_guard.py` | the guard bridge — one function, returns the demo's dict |
| new | `desktop/guard_widgets.py` | `GuardReceipt`, `BlockOverlay`, `GuardStrip` |
| new | `desktop/test_guard_chat.py` | the guards below |
| edit | `desktop/clay_chat_popup.py` | strip, key page, receipts, overlay, worker |
| edit | `desktop/ai_providers.py` | the `mock` provider |
| edit | `desktop/fox_settings.py` | `mock` in `AI_PROVIDERS`/`PROVIDER_DEFAULTS`; `guard_mode()` |
| edit | `desktop/settings_dialog.py` | `mock` hides the key/URL rows like other local providers |
| edit | `desktop/requirements.txt` | `foxy-audit>=1.10` |

### `desktop/foxy_guard.py`

One public call, returning **the same field names `demo/mock_llm.guarded_call`
returns**, so the UI never re-derives a verdict:

```python
run(prompt, call_model, *, policy_tag, mode, settings) -> dict
#  policy, mode, decision, rules, signals, reason,
#  prompt_hash, response_hash, llm_called, response, model_input,
#  stage, sdk_version, ruleset_version, shipped, wire
```

- `stage` is `"prompt"` | `"response"` | `None`. It is the field the copy keys
  off, and it is why `FoxyPolicyBlocked` and `FoxyResponseBlocked` are caught
  **separately** — the SDK made them siblings on purpose
  (`client.py:157`: *"here it did [run], tokens were spent, and the prompt did
  reach the provider"*).
- `choose_policy(text)` — first of `("hipaa", "gdpr", "default")` whose
  `policy.evaluate` triggers, else `"default"`. The demo's `_AUTODETECT_POLICIES`
  plus `gdpr`, which its own `pii` scenario needs.
- The client is built once per `(key, endpoint)` and **always** takes an explicit
  `spool_path` under `~/.foxy_audit/`. Never share the default `~/.foxy-audit`
  spool: a durable spool is flushed by the next process to construct a client,
  which is how a live run once posted from an offline one
  (`demo/mock_llm.py:75-84`).
- `wire` is captured by teeing `dispatch.submit`, exactly as `--show-wire` does.
  It is the evidence for the content-blindness claim, not a description of it.
- The whole module is import-guarded. `SDK_AVAILABLE = False` must degrade to a
  chat that says the guard is off — never to a chat that looks protected.

### `desktop/ai_providers.py` — the `mock` provider

Deterministic, mirroring `demo/mock_llm.MockLLM.generate` exactly: France →
Paris, `summar` → the safe summary, `hello`/`hi` → the no-network line, else
`MockLLM deterministic response [<sha256[:8]>]`. Local provider, no key, no URL.
A test asserts parity with the demo's class whenever `demo/` is importable, so
the two cannot drift inside the repo.

## The UI

Operate mode. The incumbent world is preserved wholesale — `glass_tokens()`,
`PANEL_WASH`, fox-orange `#c96a2f`, Unbounded + Space Mono, 22px radius, the
glass pill at `rgba(255,255,255,18)` over a `rgba(255,255,255,52)` rim. Nothing
here introduces a palette, a face or a radius that is not already on this
surface.

**The one bold move is the receipt**, and everything else stays quiet. The
product's whole claim is that evidence exists and you can read it; so the
evidence gets the mono type, the status edge and the expandable detail, and the
chat around it does not change at all.

### 1. Guard strip — between the header and the messages

```
┌──────────────────────────────────────────────┐
│  ⬡ hipaa · block            ● Local only  ›  │   30px, glass pill
└──────────────────────────────────────────────┘
```

- Left: the policy and mode **actually in force** for the next message.
- Right: key state — `Local only` (no key: nothing leaves this machine) or
  `Shipping to <host>` (key set). Both are facts, not badges.
- Clicking either opens the guard page. The whole strip is one control with an
  accessible name; it is not two icon-only buttons.
- No SDK → the strip reads `Guard unavailable · pip install foxy-audit` in
  muted ink, and no status dot. An honest empty state, per the project's rule.

### 2. Guard page — `content_stack` index 2

Reached from the strip, back-chevron to the chat, same navigation grammar the
history page already uses.

- `FOXY KEY` caption. A **visible label** above a password field (the DB's
  `Input Labels` rule: placeholder is not a label), a "Save key" button, and a
  status line under the field that reports what actually happened:
  `set_org_api_key()` returns `False` when the machine has no durable keychain,
  and the line must say so rather than claim a save.
- Endpoint field, defaulted from `settings.backend_url()`.
- Mode: three segmented options — `observe` · `block` · `redact` — with one line
  of plain copy each ("record only" / "stop it before the model" / "scrub, then
  send"). Writes `guard_mode()`.
- Model: a read-only line naming the active provider, and where to change it
  (Settings › AI Brain). One job per element; the key field is not also a
  provider picker.

### 3. Receipt — under every reply

Collapsed (one row, 26px):

```
▏ ALLOWED · default · block · no rules fired          Evidence ⌄
```

Expanded:

```
▏ policy / mode    hipaa / block
▏ decision         BLOCKED   (reason: phi)
▏ rules            phi.ssn · phi.presidio:date_time
▏ signals          phi
▏ prompt_hash      5aa762ae383fbb727af3c7a36d4940a5b8c40a989452d2304fc958ff3f354e7a
▏ response_hash    b0428e8c75adcb5926f2047b4d9b697b1414cc567cbcf493ac2139fd01e4d56c
▏ LLM called?      NO  (blocked before the model ran)
▏ what left        { … }   ← only when a key is set
```

- The left rule is 2px, coloured by decision from the existing status tokens
  (`OK_GREEN` / `WARN_AMBER` / `BAD_RED`, fox for redacted). It is the only
  colour the receipt carries.
- Hashes in Space Mono, selectable, with a copy control. They wrap; they are
  never truncated with an ellipsis — a partial commitment is not a commitment.
- Every value comes from the `foxy_guard.run()` dict. The UI computes nothing.

### 4. Block overlay — modelled on `chrome_widgets.LockOverlay`

Covers the chat panel with a scrim and one card. Structure and accessible-name
discipline are ported from `LockOverlay`, which was built for exactly this: a
card that has to state a refusal without making the app look broken.

**Prompt block** (`stage == "prompt"`):
> **PREFLIGHT GUARD**
> ## Blocked before the model saw it.
> This prompt matched **{reason}** under the **{policy}** policy. The model was
> never called, and the text never left this machine.

**Response block** (`stage == "response"`) — different copy, and this is not
cosmetic:
> **RESPONSE SCAN**
> ## Blocked on the way back.
> The model answered; the scan stopped the answer before it reached you. The
> prompt did reach the provider and tokens were spent.

Claiming prevention on a response block is the exact false statement the SDK
separates two exception classes to avoid. A test pins both strings.

Actions:
- **Edit prompt** (primary) — restores the text to the input, focused. This is
  the recovery path the UX rules ask for; a refusal with no next step is a dead
  end.
- **Retry with redaction** (secondary, shown only when `policy.redact` actually
  changes the prompt) — re-runs in `redact` mode. If findings survive redaction
  the SDK blocks again, and that is the correct, interesting outcome to show.
- **Close.**

Escape closes it, focus lands on the primary button, the fade honours
`_reduced_motion()`.

## Threading

`_AICallWorker` runs `foxy_guard.run()` — guard, model call and scan all off the
UI thread — and emits the result **dict** (`succeeded = pyqtSignal(dict)`). Keep
the existing `_cleanup()` disconnect discipline; do not pump the shared event
queue anywhere in the tests.

## The guards (`desktop/test_guard_chat.py`, run from the repo root)

1. A blocked prompt shows the overlay, `llm_called is False`, and a spy provider
   records **zero** calls.
2. A response block shows the other title, and its body does **not** contain
   "never called".
3. Every receipt field equals the `foxy_guard.run()` dict — assert the widget's
   rendered text against the dict, so the UI cannot re-derive a verdict.
4. Content-blindness: with `dispatch.submit` stubbed, no word of ≥6 characters
   from the prompt appears in the captured payload.
5. `set_org_api_key()` returning `False` produces the "not saved" line, not a
   success line. Use a non-durable store, the way `test_fox_settings.py` does.
6. Mock-provider parity with `demo/mock_llm.MockLLM` over a fixed corpus,
   skipped only when `demo/` is not importable.
7. Contrast: every new fill measured **against the surface behind it**, ≥3:1 for
   UI marks and 4.5:1 for text. Measure the pill, not only its ink.
8. Reduced motion: with it on, the overlay lands opaque and in place.

Re-break each guard before believing it.

## Explicit non-goals

- No change to `sdk/`, `demo/mock_llm.py`, the wire contract, or any event type.
- No new backend field; nothing here needs a deploy.
- No second theme, no chat skin, no new palette.
- No "send anyway" escape hatch on the overlay. The guard is the product.
