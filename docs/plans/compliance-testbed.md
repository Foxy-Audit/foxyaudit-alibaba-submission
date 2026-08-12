# Compliance Testbed — a real assistant you can try, in three sectors, on three surfaces

**Plan of record** · 2026-08-12 · MAIN chat is the committer; executors build per this file.

Phases **T0 → T4**. Companion plan: [`sdk-policy-truth.md`](sdk-policy-truth.md) (S2–S6).
T4 depends on **S4**; everything else is independent of it.

---

## 1 · Context

The owner asked for "an LLM chatbot for an important or sensitive sector, with an
interface, so that as a client I can test whether it is actually assisting as intended."

Today there is nothing to click. `demo/mock_llm.py` and `demo/live_openai_client.py` are
both CLI-only scripts; a repo-wide grep for playground / chatbot / sandbox returns only
Paddle's payment sandbox. Every claim the sale page makes about blocking is, for a
visitor, a screenshot.

The owner asked for **all three sectors and all three surfaces**. That is affordable only
because it is one engine with three presets and three thin front-ends — see §4.

**What this is actually for.** Two audiences, one build:

- a **prospect** who wants to see a HIPAA breach get stopped before it reaches a model;
- the **owner**, who needs to answer "is the assistant still helpful once the guard is
  on?" — the question a block-rate metric cannot answer. An assistant that refuses
  everything scores perfectly and is worthless.

That second audience is why the testbed records **assist quality alongside enforcement**,
and why §5 exists.

---

## 2 · What the premises actually are

Read at `24d3699`.

| The premise | Holds? | What is actually true |
|---|---|---|
| A chatbot demo exists | **NO** | CLI scripts only; no interface of any kind. |
| A web page could call an LLM directly | **NO** | Every web surface is CSP-safe with no CDN and no inline network config; a browser page needs a server to hold a provider key. See §3 — this constraint has a good answer. |
| We could host the chat backend | **must not** | Raw prompt text reaching a Foxy-operated server breaks the product's central claim (hard rule §5.2, content-blindness). Non-negotiable, and it shapes the whole design. |
| The SDK can enforce in a demo | **holds** | `@foxy.audit(policy=..., mode="block")` is real prevention ([`client.py:635-637`](../../sdk/src/foxy_audit/client.py#L635-L637)). |
| Demos must run offline | **holds** | `demo/mock_llm.py` runs with no key and no network, and CI depends on that. The testbed must keep the property. |
| The sector presets exist | **NO** | `policy.py` knows `hipaa` and `gdpr` and nothing else. Finance and legal have **no rule families today** — see §6, T0. |

---

## 3 · ⚠ The blocker nobody mentioned

**A hosted web demo would violate the product's own central claim.**

The three existing web surfaces are static. A browser chat page needs a server to hold
the provider key and make the model call — and if that server is ours, every word a
prospect types into the "HIPAA assistant" arrives on Foxy infrastructure. That is the
exact thing the SDK exists to prevent, demonstrated in reverse, on the sale path.

**The answer, and it is better than the problem:** the web testbed ships as a **local**
server the user starts themselves —

```bash
pip install foxy-audit
python -m foxy_testbed.web          # http://127.0.0.1:8787
```

Text never leaves the user's machine except to *their own* model provider, under their
own key. The demo does not merely describe content-blindness; it is structurally
incapable of breaking it, and the page can say so truthfully in one line. Bind to
`127.0.0.1` only, never `0.0.0.0`.

**Consequence for the sale page:** it links to instructions and a recording, not to a
hosted URL. Confirm with the owner before writing sale-page copy — a "Try it" button
that opens a terminal instruction is a real conversion trade, and that call is theirs.

---

## 4 · Shape

One engine, three presets, three front-ends. The front-ends hold no policy logic.

```
sdk/src/foxy_testbed/          (ships in the wheel; no new runtime deps)
  core.py       the assistant: build prompt, call provider, return turn + evidence
  sectors.py    healthcare | finance | legal — system prompt, policy tag, probe set
  providers.py  OpenAI · Gemini · mock (default, offline, deterministic)
  cli.py        python -m foxy_testbed          — interactive REPL
  web.py        python -m foxy_testbed.web      — local server + one static page
```

Desktop is a page inside the existing fox console (`desktop/testbed_page.py`), reusing
`console_chrome` and `foxy_tokens` exactly as the other pages do.

**Every turn returns the same `Turn` record** regardless of surface: the reply (or the
block), `decision`, `rules`, `blocked_reason`, `event_id`, `policy_tag`, and latency.
Three front-ends rendering one record is what keeps this affordable.

---

## 5 · The part that makes it worth building

Anyone can show a blocked prompt. The testbed's value is showing **both columns at once**:

| Column | What it answers |
|---|---|
| **Enforcement** | Did the guard stop what it should have? Each sector ships a probe set of prompts labelled `expect_block` / `expect_assist`. |
| **Assistance** | Is it still useful? `expect_assist` probes must come back **answered**, and a run reports *both* rates. |

A run prints a scoreboard: blocked-correctly, missed, **and over-blocked**. An assistant
that refuses everything must score visibly badly. Without the second column this is a
toy that flatters us.

**No fabricated verdicts** (hard rule §5.1). With the mock provider the replies are
canned and the page must say "mock provider — replies are fixtures, enforcement is real",
because the enforcement genuinely is: the guard runs identically whichever provider is
behind it. That distinction is the honest claim and must be visible on every surface.

---

## 6 · Phases

| Phase | Branch | Scope |
|---|---|---|
| **T0** | `feat/testbed-core` | Engine, three sector presets, providers, probe sets + scoreboard |
| **T1** | `feat/testbed-cli` | Interactive REPL |
| **T2** | `feat/testbed-web` | Local server + page — **UI phase, skills block mandatory** |
| **T3** | `feat/testbed-desktop` | Console page — **UI phase, skills block mandatory** |
| **T4** | `feat/testbed-evidence` | "Verify this turn" — wires the evidence pane to S4's `foxy explain` |

T0 first and alone; T1/T2/T3 are then parallelisable across executors. T4 last, and
**only after S4 has merged**.

### T0 — engine, sectors, probes

Finance and legal have **no rule families in `policy.py` today**. Decide deliberately
rather than inventing tags that fall through to baseline (that is exactly the
`hipaa_basic` defect in [`sdk-policy-truth.md`](sdk-policy-truth.md) §2):

- **healthcare** → `policy="hipaa"` — exists after S2, with PHI + baseline.
- **finance** → PCI-shaped. The card check already exists (`pii._has_card`, Luhn-gated)
  and `secret.*` covers keys. Ship as `policy="default"` for now and **say so in the
  preset**, or propose a `pci` family to the owner. Do not invent `policy="finance"`.
- **legal** → privilege/confidentiality has no detector at all. Ship as `default` and
  state the gap on the surface. **An honest empty state beats a fake rule family.**

**Assumption to overrule:** that shipping finance and legal on baseline checks is
acceptable for a demo. If the owner wants real PCI or privilege families, that is a
policy-engine phase in the other plan, not a testbed phase — say so rather than
inventing rules here.

**Traps:** keep the mock provider deterministic (no `random`) or the scoreboard flakes in
CI. No new runtime dependencies — `providers.py` uses `requests`, already the SDK's only
dependency.

### T1 — CLI

`python -m foxy_testbed --sector healthcare --mode block`. Interactive REPL plus
`--probe all` for the scoreboard. This is the phase CI runs, so it must work offline.

### T2 — local web · T3 — desktop page

Both render the same `Turn`. Both need the skills block in §7 pasted into the prompt
verbatim.

**Traps:**
- The web page follows the existing surfaces: **inline SVG, embedded fonts, no CDN**.
  `node --check` every inline `<script>`; balance every `<style>`.
- A blocked turn is an **error state**, and error states are where this UI earns its
  keep: show the rule ids, the reason, and the event id — not a red box.
- Desktop: **web wins on any style conflict** (hard rule §5.7). Reuse `foxy_tokens`;
  do not introduce a colour.
- Desktop tests run **from the repo root** (`pytest desktop`), never from inside it.

### T4 — evidence

A "verify this turn" control that runs S4's `explain` path against the turn's
`event_id` and shows: this prompt → this commitment → this ledger row → these rules,
under this ruleset version. It closes the loop from the owner's second question and is
the single most persuasive thing in the build.

**Blocked on S4.** Do not stub it — a verify button that fakes a result is the worst
possible thing to ship in an audit product.

---

## 7 · MANDATORY SKILLS — paste verbatim into the T2 and T3 prompts

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
- The `impeccable` detector WILL flag R2's status mark as `side-tab`. That is
  register #83, a pinned owner decision. Report it, never "fix" it.

Measure a fill against its background, not only its ink. This surface has shipped a
chip whose text cleared 4.5:1 while the pill itself sat at 1.01:1 against the card
behind it. `--muted2` is 3.01:1 dark / 2.71:1 light and must never carry live text.

Any chart or tile: load `dataviz` BEFORE the first line of chart code.
```

---

## 8 · Verification

```bash
python -m foxy_testbed --sector healthcare --probe all    # scoreboard, offline, no key
python -m foxy_testbed --sector finance   --probe all
python -m foxy_testbed --sector legal     --probe all
pytest sdk/tests -q
pytest desktop                                            # FROM THE REPO ROOT (T3)
node --check <each inline script>                         # T2, into the scratchpad
```

**What must NOT move:** the SDK's public API, the wire contract, and every existing
suite's baseline. The testbed is a **consumer** of the SDK — if a phase here needs a
change inside `foxy_audit/`, that is a finding to report, not a change to make.

---

## 9 · After each merge

Per playbook §4: append to `Devlogs/2026-08-12.md`; create a new vault note
`Testbed/CLAUDE.md` (create freely — do not edit the MOC without asking) carrying the
sector/policy mapping and the local-only web constraint from §3; register any gap found
and not fixed, with `file:line` and what was ruled out.
