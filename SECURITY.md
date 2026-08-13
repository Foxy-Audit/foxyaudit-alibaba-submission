# Security Policy

> **The published policy is <https://foxyaudit.tech/report-abuse.html>.**
> That page is public, it is what `/.well-known/security.txt` cites under
> `Policy:`, and it carries the safe-harbour undertaking, the scope, and the
> reporting route. **It is authoritative.** This file is the contributor-facing
> companion: it adds what only someone with access to this repository can use,
> and deliberately does not restate the policy — two copies of a policy is how
> they drift.

## Reporting a vulnerability

Please don't open a public issue. **Email <security@foxyaudit.tech>.**

That is the same single channel the published policy and `security.txt` name.

> ⚠ **This repository is private, so a GitHub security advisory is not a route
> anyone outside it can take.** This file used to offer one, `security.txt`
> listed it *first* — and RFC 9116 §2.5.3 makes multiple `Contact:` fields an
> order of preference, so tooling read a URL that 404s for every outsider as the
> preferred way to reach us. Both now name the mailbox. If the repository is
> ever made public, the advisory flow can come back as a *second* channel; it
> must not come back as the first, and it must not be the only one.

**There is no bug bounty, and no guaranteed response time.** This is a small
project and the honest answer is that reports are read and acted on as fast as a
small team can. Saying otherwise would be a promise the project cannot keep,
which is worse for you than no promise at all.

If you want to encrypt, say so in your first message and we'll arrange a key —
there is no published PGP key today rather than a stale one.

## Scope

The published policy states scope in terms an outside researcher can act on:
the four deployed hostnames and the released SDK on PyPI. See
[What is in scope](https://foxyaudit.tech/report-abuse.html#s4) and
[What is out of scope](https://foxyaudit.tech/report-abuse.html#s5).

What follows is the repository-side view of the same surfaces — useful only if
you can read this tree, which is why it lives here and not on the public page.

| Area | Path |
|---|---|
| Python SDK (`foxy-audit` on PyPI) | `sdk/` |
| Backend API and grading worker | `backend/` |
| Independent verifier | `verifier/` |
| Anchoring contract | `contracts/` |
| Customer dashboard | `foxy-dashboard/` |
| Staff admin console | `foxy-adminpage/` |
| Marketing site | `foxy-sale-page/` |
| Checkout page | `foxy-checkout/` |
| Desktop companion app | `desktop/` |
| Deployment and CI configuration | `deploy/`, `.github/workflows/` |

Reports are welcome against the current `main` and the most recent published SDK
release. Older tags are not maintained.

## What an attacker does not get from our servers

This is the product's central claim, so it belongs on this page — stated as the
architecture, not as a guarantee that the system cannot be broken.

Raw prompt and response text **never leave the customer's process**. The SDK
hashes them locally into customer-keyed HMAC-SHA-256 commitments and ships only
those commitments plus bounded metadata; the backend has no column to put the
text in, and never receives it. So a full compromise of the Foxy Audit backend
does not yield customer prompt or response content — there is none there to
yield. That property is continuously tested rather than asserted: `e2e/run_e2e.py`
sweeps known sentinels across every HTTP surface, the export bundle, the rendered
dashboard DOM and every database table, with negative controls proving the sweep
can find a string that IS present.

What that does **not** mean:

- The metadata that is stored is real data. Token counts, policy tags, coarse
  signal labels (`phi`, `secret_key`, `unsafe_markup`), model and agent names,
  timings and hash chains all exist server-side and are worth protecting.
- A commitment is not anonymised text. Anyone holding the customer's commitment
  key can test a guess against a hash, which is exactly what makes the evidence
  provable — and why the key and the optional salt sidecar stay on the
  customer's machine.
- Secrets that ARE held server-side — password hashes, API key hashes, and BYOK
  provider keys encrypted under `PROVIDER_KEY_ENCRYPTION_KEY` — are in scope and
  we want to hear about anything that reaches them.

## Machine-readable

`https://foxyaudit.tech/.well-known/security.txt` ([RFC 9116](https://www.rfc-editor.org/rfc/rfc9116)),
served from `foxy-sale-page/security.txt` by the explicit route in
`deploy/nginx-foxyaudit.conf`. It carries an `Expires` date, and
`foxy-sale-page/test_security_txt.py` turns CI red a month before that date so it
gets renewed rather than quietly rotting. The same suite pins that this file,
`README.md`, `security.txt` and the published policy all name the same mailbox,
because four places to state one address is four places for it to drift.
