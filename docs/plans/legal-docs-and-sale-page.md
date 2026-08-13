# Legal documents v2, the security contacts, and the sale-page restructure

Planned 2026-08-13, MAIN chat. Base: `origin/main` @ `c6c95bc`.

Supersedes the standalone **S7** brief (PyPI listing quality). S7 is not
cancelled — it is **folded into L1 §C**, because researching it turned up the
fact that made the original brief wrong. See §"Why S7 moved" below.

---

## Why this plan exists

Three separate things converged on the same files:

1. **Twelve updated policy documents** landed
   (`Foxy-Audit-Policy-Docs-Updated (2).zip`, 2026-08-13) — the teammate's
   response to [[Policy docs v2 — what must change before Paddle verification]],
   which has been blocking Paddle since 2026-08-05.
2. **The owner's sale-page note**
   (`Sale Page\Main sales page.md` in the vault) — a homepage restructure.
3. **S7 / the security contacts** — the published disclosure channel points into
   a repo that is private and staying private.

They collide on `foxy-sale-page/`, and specifically on the footer, which is
**copy-pasted into all 21 HTML pages with no include**.

---

## ⚠ What I verified, so nobody re-derives it

Measured 2026-08-13 against `c6c95bc` and the live site. **Not assumed.**

### The new docs fixed all four Paddle blockers

| Vault blocker (2026-08-05) | Status in the new set |
|---|---|
| Stripe named as the payment processor (DPA §sub-processors, Trust Page §6) | **Gone** — 0 occurrences across all 12 docs; Paddle appears in 7 |
| Placeholder to-do inside the published Privacy Policy | **Gone** — rewritten as a proper sentence |
| No phone number anywhere in 10 docs or 23 live pages | **Present** in 8 docs |
| No standalone refund policy | **Exists** — `Refund-Policy-v1.2` |

Plus a new `Order-Form-v1.1`. **Paddle is unblocked on document content.**

### Three defects the new docs still carry

- **7 of 12 have a header version contradicting the filename** — the exact
  defect the vault flagged on 2026-08-05, still unfixed. Privacy is `v3.9` in
  the name and says *"Version 3.6"* inside; ToS is `v2.6` and says *"Version
  1.0"*. Same for SLA `v1.4`, Terms-of-Use `v2.5`, Trust Page `v1.7`, Refund
  `v1.2`, Order Form `v1.1`.
- **Trust Page v1.7 still promises "SOC 2 Type I — Q4 2026"** while the same
  page says no attestation is held. Q4 begins ~7 weeks from planning.
- **`privacy@foxyaudit.tech.`** — trailing period in one doc. A mechanical
  conversion turns that into a dead `mailto:`.

### ⚠ The phone numbers disagree, and the docs are the wrong ones

- Every one of the 12 docs says **`+92 3448123944`**.
- The owner's sale-page note says change it to **`+92 3398123944`**.

**The owner's note wins.** The docs must be corrected at conversion.

### The live pages are two generations stale

`privacy` / `terms` — 13 July 2026. `cookie-policy` / `acceptable-use` /
`report-abuse` — *"Version 1.0"*, 16 July 2026. The Aug 8 doc set
(`Foxy-Audit-Policy-Doc/`, untracked in the repo root) **was never published**
and is itself now superseded. **Ignore that folder.**

### Emails in the new docs — all four confirmed live by the owner

`legal@` (3 docs) · `privacy@` (2) · `security@` (2) · `support@` (4 on the
current site). All receive mail — owner, 2026-08-13.

### The security contacts are unreachable

```
repo fatimaatta-09/Foxy-Audit  isPrivate = TRUE   (and staying private)
https://github.com/alikamran21/Foxy-Audit                    404  wrong owner
https://github.com/fatimaatta-09/Foxy-Audit                  404  private
.../security/advisories/new                                  unreachable
https://foxyaudit.tech/.well-known/security.txt              200  live
https://foxyaudit.tech/report-abuse.html                     200  live
https://foxyaudit.tech/docs                                  200  (extensionless OK)
```

| File | Line | Problem |
|---|---|---|
| `foxy-sale-page/security.txt` | 14 | `Contact:` GitHub advisory URL — unreachable, **and listed first** |
| `foxy-sale-page/security.txt` | 20 | `Policy:` `SECURITY.md` blob — unreachable |
| `SECURITY.md` | 7 | tells the reporter to open an advisory they cannot open |
| `sdk/pyproject.toml` | 36-37 | `Source`/`Issues` name `alikamran21` — wrong owner **and** 404 |

⚠ **RFC 9116 §2.5.3: multiple `Contact:` fields are in order of preference.**
The unreachable route is listed first, so a researcher's tooling reads it as
preferred. And `security.txt` says `support@` while the authoritative
Responsible Disclosure Policy v1.4 says `security@` — the two contradict.

### Already checked — do NOT chase these

- **"Help Center should lead to the docs" / "desktop pet → new website"**
  (owner's note): `https://foxyaudit.tech/docs` returns **200** (Caddy serves
  extensionless) and `desktop/settings_data.py:361` already points there.
  **Not broken.**

---

## Owner decisions — settled 2026-08-13, do not reopen

1. **The repo stays private.** Nobody makes it public.
2. **All four mailboxes work** — publish `legal@` / `privacy@` / `security@` /
   `support@` as the docs use them.
3. **Phone is `+92 3398123944`**, not the `+92 3448123944` in the docs.
4. **Filename version wins** over the document header, in all 7 mismatches.
5. **No SOC 2 auditor is engaged** — remove the Q4 2026 date, keep an honest
   statement of intent with no quarter. The *"we do not currently hold SOC 2"*
   disclosure stays exactly as blunt as it is.
6. **Both streams run in parallel**, with the footer rule below.
7. **The sale-page redesign requires an approved design first** — the owner
   reviews a proposal before any executor builds. (Owner, 2026-08-13.)

---

## ⚠ The footer rule — the collision between the two streams

> The footer is **copy-pasted into all 21 pages**. There is no include, no JS
> injection. Confirmed: 21 files carry `"Cryptographic compliance, not a
> promise"`.

- **Stream L owns the footer.** It adds Refund / SLA / DPA / Trust links to all
  21 pages.
- **Stream W must not edit any footer**, on any page, for any reason.
- If a page disappears under L at rebase time, W removed it deliberately —
  **take the deletion, do not restore it.**

Same family as the admin phase-stacking rule: parallel work on one shared
artifact silently reverts.

---

## Phases

### Stream L · One document per phase — ⚠ STRICTLY SEQUENTIAL

**Owner instruction, 2026-08-13: the 12 pages are done one after another, each
fixed and finished before the next begins.** Not one bulk conversion.

Each phase: its own branch off **fresh `origin/main`**, its own gate, its own
merge. MAIN reviews and merges before issuing the next. This is the same
discipline the admin console needed — parallel work on shared files silently
reverts, and a bulk conversion hides which document introduced a defect.

| # | Document | Target page | Notes |
|---|---|---|---|
| **L1** | Privacy Policy **v3.9** | `privacy.html` (update) | ⚠ **Sets the pattern for all 11 that follow** |
| **L2** | Terms of Service **v2.6** | `terms.html` (update) | merchant-of-record wording — Paddle-critical |
| **L3** | Refund Policy **v1.2** | `refund.html` (**new**) | Paddle explicitly wants this as its own page |
| **L4** | Responsible Disclosure **v1.4** | `report-abuse.html` (update) | ⚠ **unblocks L5** |
| **L5** | *(no document)* | `security.txt` · `SECURITY.md` · `sdk/README.md` · `sdk/pyproject.toml` | **the old S7** — depends on L4 |
| **L6** | Acceptable Use **v1.4** | `acceptable-use.html` (update) | |
| **L7** | Cookie Policy **v1.5** | `cookie-policy.html` (update) | |
| **L8** | Trust Page **v1.7** | `trust.html` (**new**) | ⚠ the SOC 2 softening lands here |
| **L9** | Service Level Agreement **v1.4** | `sla.html` (**new**) | ⚠ no invented uptime numbers |
| **L10** | Data Processing Agreement **v1.4** | `dpa.html` (**new**) | sub-processor table — verify Paddle's legal entity name |
| **L11** | Master Service Agreement **v1.3** | `msa.html` (**new**) | |
| **L12** | Order Form **v1.1** | **decide** | ⚠ a contract template, not a policy — may not belong on a public site at all |
| **L13** | *(no document)* | `legal.html` + footer × 21 | **last**, once every page exists |

**Why this order:** L1 first because it is the largest document and the most-read
page, so it establishes the house pattern every later phase copies. L4 before L5
because `report-abuse.html` is what `security.txt`'s `Policy:` will point at —
L5 cannot be correct until L4 has shipped. L13 last so the footer is edited
**once** across 21 files rather than twelve times, which also shrinks the
collision window with Stream W.

#### Rules every L phase obeys

⚠ **These are restated in each prompt. They are not optional.**

- **Filename version wins** over the document header (7 docs disagree).
- **Phone is `+92 3398123944`.** The docs' `+92 3448123944` is wrong.
  `grep -r "3448123944"` must return **zero** at every gate.
- ⚠ **Match the existing house style** — read `privacy.html` first.
  Self-contained page, inline `<style>`, warm-charcoal tokens (`--bg:#17120f`,
  `--fox:#ff7a2e`), `.wrap` max-width 820px, `.card`, mono `.updated` line.
  **No CDN, no external font** — the site is CSP-safe and stays so.
- ⚠ **Proofread the rendered HTML, not the Word file.** The previous conversion
  produced `"on your behalf DSbuilding"` from a mangled em-dash. Stray `ã`, `ç`
  and `◉` are present in Privacy v3.9 and Trust Page v1.7 — find what they were
  meant to be rather than deleting them blind.
- ⚠ **Every `mailto:` is checked for the trailing-period defect**
  (`privacy@foxyaudit.tech.` appears in one doc and becomes a dead link).
- **Each phase adds its own link to `legal.html`** — a small file, low collision
  risk. **No phase touches the footer** except L13.
- **No fake data, no invented SLA, address, or certification.**

#### L5 in detail — the old S7

The **policy document is the source of truth**, not the current file:

- `Contact: mailto:security@foxyaudit.tech` **first**; drop the advisory URL.
- `Policy:` must resolve for a stranger — **`report-abuse.html` is the published
  disclosure policy and is already live at 200.** Point at it.
- `SECURITY.md` and `sdk/README.md` §Security must agree.
  ⚠ `SECURITY.md:10` asserts these are *"the same two channels the README
  names"* and a **Q1 guard pins that correspondence**. Change all three
  together. A guard relaxed until it passes is not a guard.
- `sdk/pyproject.toml` `Source`/`Issues`: wrong owner **and** 404. **A link that
  404s is worse than an absent field.** Removing them is legitimate; a broken
  link is not.

⚠ **Keep `SECURITY.md`'s honesty** — no bug bounty, no guaranteed response time,
no stale PGP key. A contacts edit must not sand that into boilerplate.

⚠ **Do not break the renewal test.** `Expires: 2027-08-12` and
`foxy-sale-page/test_security_txt.py` fails CI 30 days before it. Re-break it on
purpose to prove it still bites.

#### Register issues assigned to specific L phases

| # | What | Phase |
|---|---|---|
| **#10** | Six sale pages don't load Poppins, so **the legal pages render in a different typeface** | **L1** — fix it where the pattern is set, and every later page inherits |
| **#15** | A security disclosure may land in the sales inbox | **L4** |
| **#161** | The security contact is published where tools look, and expires on a test | **L5** |
| **#8** | `docs.html` is a **placeholder** that `pyproject` advertises as `Documentation`. ⚠ It returns 200 — a status code is not evidence of content. I got this wrong in the original S7 brief. | **L5** |
| **#11** | `foxy-sale-page/README.md` contradicts itself about paid CTAs | **L13** |

#### Gates — every L phase, without exception

`pytest foxy-sale-page -q` (38 baseline, **must rise** — a new page needs
guards) · `pytest desktop -q` (853, **from the repo root** — desktop links to
`privacy.html`) · `node --check` every inline `<script>` ·
`grep -r "3448123944"` → **zero** · `grep -r Stripe foxy-sale-page/` → report ·
every `mailto:` and `href` curl'd with status pasted · no secrets ·
`--is-ancestor` **at push time**.

**No version bump on any L phase** — this is content, not a release.

---

### W0 · The sale-page design proposal — ⚠ OWNER-APPROVAL GATE

**MAIN produces this, not an executor. No build starts until the owner approves.**

Source of truth: the owner's `Sale Page\Main sales page.md`.

All three frontend skills, `ui-ux-pro-max` first. Findings so far:

- **Pattern match:** *Real-Time / Operations Landing* (ops/security products —
  hero with live status, key indicators, how it works, CTA) crossed with
  *Feature-Rich Showcase*, whose rule is literally **"one key message per
  card."**
- **The fact base backs the owner's pop-up instruction with evidence:**
  Navigation → *Deep Linking* — *"URLs should reflect current state for sharing.
  Don't: static URLs for dynamic content."* A pop-up has no URL; a page does.
- **"No emoji as icons — use SVG"** is an explicit anti-pattern, and is
  independently register **#12**.
- ⚠ **The recommended palette (`#15803D` on `#0F172A`) is REJECTED.** The
  project's warm-charcoal + fox-orange wins — settled project decisions beat
  generic skill advice, and the report must say so rather than split the
  difference.
- ⚠ **`context.mjs` reports `INCUMBENT_WORLD_UNDOCUMENTED`** — PRODUCT.md
  exists, **DESIGN.md does not**, and the code carries the real visual
  decisions. This is an **extension that documents and preserves** the
  code-defined world, *not* a replacement of it.

Deliverable: a rendered proposal in the site's own tokens and embedded
typefaces, so the look is judged rather than described — the same method that
got the admin card layer approved.

---

### W1+ · Build the approved design

**Blocked on W0.** Scope, from the owner's note:

1. Cards 1–5 → *What Foxy Audit is* (full page) · *How to Install* (3 methods,
   article-quality) · *Book a Demo* · *See Pricing* · *FAQ* + ask-a-question.
   ⚠ "Ask a question" must reach something real; an input that drops questions
   is worse than a link.
2. Remove 4 cards — Hash Chain · Metadata · Verify Chain (live) · Compliance
   Passport. ⚠ **Remove the cards, keep the content** — the owner wants them
   re-homed as docs/blog with a link through. `hash-chain.html`,
   `passport.html`, `verify-page.html` hold real explanations.
3. Kill **every** mini pop-up; each card links straight to its page. ⚠ Remove
   the mechanism wholesale — orphaned JS is how it comes back.
4. "Metadata Policy Judge" page → explain how the AI judge works. ⚠ **Verify
   against `backend/app/judge.py`, `judge_routing.py`, `gemini.py`,
   `openai_judge.py` first.** The judge grades bounded *metadata*, never
   content — a page implying it reads prompts contradicts the core claim.
5. "About Foxy Audit" card → a button under each specific mention.
6. **Contact Us "doesn't work"** — ⚠ diagnose before fixing. `contact.html`
   returns 200. Report the cause, not just the patch.
7. Pricing: the future agent joins the Max plan. ⚠ **Roadmap, not shipped.** A
   pricing page is a commercial promise and the project's hardest rule is no
   fake data. It must be unmistakably labelled as planned — never flush beside
   features that exist today.

**Also in this territory:** **#12** (emoji as UI marks, against the sale page's
own written rule) · **#14** (the Linux AppImage link may 404 — only Windows has
ever been built) · **#163** (no `@media (forced-colors)` on the sale page or
checkout; `context.mjs` names this as a known gap).

**Gates:** as L1, plus screenshots with `--force-prefers-reduced-motion` and an
absolute `--screenshot` path · `detect.mjs --json` once at the end ·
⚠ **never `taskkill` chrome by name** — it closes the owner's real browser.

---

### R · The two open 🔴 defects — neither is cosmetic

Currently unscheduled. **#157 outranks everything else in this plan** on
product-correctness grounds.

- **#157 — `AsyncDispatcher` can die silently and stop delivering every later
  event.** On an audit product this is silent evidence loss. Register carries no
  fix text.
- **#162 — a comment terminator deleted a shipped CSS rule, and every gate was
  blind.**

⚠ **#172 is actually fixed** (S4, `9cbe743`) but was never re-tiered from 🔴.
Correct it at the next vault sync.

---

## Backlog this plan does not cover

Tracked so it is not lost: **#170** (avg-risk gauge tooltip asserts a score the
gauge declines to show) · **#174** (the e2e cannot tell "provenance works" from
"provenance was stripped" — blocked by
[[norton-breaks-docker-pip]]) · **T0–T4** compliance testbed (`docs/plans/
compliance-testbed.md`; T4 depended on S5, which shipped in `8fa454c`).

Register status at planning: **3 🔴** (one mis-tiered), **46 🟡**, **61 🟢**.

---

## Why S7 moved

The original S7 brief told an executor to make `support@` the primary security
contact and to invent a way to serve `SECURITY.md` publicly.

Both were wrong, and researching the brief is what proved it:

- The **Responsible Disclosure Policy v1.4** is the authoritative document and
  names **`security@foxyaudit.tech`**, not `support@`.
- `report-abuse.html` **already publishes that policy at 200** — so no new
  serving mechanism was needed at all.
- And I cleared `Documentation` as fine because it returned 200, when register
  **#8** already recorded that it points at a **placeholder**.

⚠ **The lesson, for the register:** *a status code is not evidence of content*,
and *the authoritative document outranks the file you happen to be editing.*
Both belong in `Where Claude Was Wrong`.

---

## Related

- `Policy docs v2 — what must change before Paddle verification` (vault) — the
  2026-08-05 checklist this plan discharges
- `Sale Page\Main sales page.md` (vault) — the owner's restructure note
- `Payments — leaving Stripe for a Merchant of Record` — what Paddle unblocks
- `docs/plans/compliance-testbed.md` — T0–T4, not covered here
