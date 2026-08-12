# Security Policy

## Reporting a vulnerability

Please don't open a public issue. Instead:

- open a private [security advisory](https://github.com/fatimaatta-09/Foxy-Audit/security/advisories/new), or
- email **support@foxyaudit.tech**.

Those are the same two channels the [README](README.md#-security) names; this file
exists so GitHub surfaces them in the Security tab and in the "Report a
vulnerability" flow, not to open a third one.

**There is no bug bounty, and no guaranteed response time.** This is a small
project and the honest answer is that reports are read and acted on as fast as a
small team can. Saying otherwise would be a promise the project cannot keep,
which is worse for you than no promise at all.

If you want to encrypt, say so in your first message and we'll arrange a key —
there is no published PGP key today rather than a stale one.

## What is in scope

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

Deployed: `foxyaudit.tech`, `app.foxyaudit.tech`, `admin.foxyaudit.tech`,
`checkout.foxyaudit.tech`.

Reports are welcome against the current `main` and the most recent published SDK
release. Older tags are not maintained.

## What is out of scope

- Third-party services the product integrates with rather than operates —
  Paddle, Brevo, Google OAuth, the model providers, GitHub itself. Report those
  to them; tell us too if our integration is what makes the issue reachable.
- Volumetric denial of service, and any testing that degrades the service for
  other people.
- Social engineering, physical access, and attacks on the operator's own
  machines or accounts.
- Automated scanner output with no demonstrated impact, including missing
  hardening headers on static pages where you cannot show what they enable.
- Self-XSS, and issues that need a victim to paste attacker-supplied content
  into their own developer console.

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
served from `foxy-sale-page/security.txt`. It carries an `Expires` date, and
`foxy-sale-page/test_security_txt.py` turns CI red a month before that date so it
gets renewed rather than quietly rotting.
