# Foxy Audit — open-source verifier

Independently re-verify a Foxy Audit log export **without trusting Foxy**. A single,
dependency-free Python script that re-implements the hash-chain recipe from scratch and
recomputes your entire ledger from genesis, reporting the first tampered row (if any).

If Foxy — or anyone with database access — altered a historical interaction, the
recomputed chain hash for that row no longer matches the stored one, and every row after
it breaks too (avalanche effect). This tool proves that using only the public recipe
below and the export you downloaded — nothing else, no network, no Foxy code.

## Requirements

Python 3.9+ (standard library only). `web3` is optional — needed **only** for the live
`--anchor` on-chain check.

## Usage

1. In the dashboard, **Ledger → Export → JSON** (or `GET /v1/logs/export?format=json`) to
   download `foxy-audit-logs.json`.
2. Run:

```bash
python foxy_verify.py foxy-audit-logs.json
```

```
✓ chain intact — 512 rows verified from genesis
  head @ seq 512 = a3f9c17e…
✓ anchor receipt matches the chain @ seq 512
  root a3f9c17e… (chain=sepolia)
```

Exit code is `0` when intact, `1` when tampering or an anchor mismatch is found, and `2`
when **nothing was verified** — so it drops straight into CI. Add `--json` for
machine-readable output.

### What it will not do

**It will never report success over a file it did not read.** A file with no chain in it,
an empty chain section, or rows missing the columns the hash is taken over is a
`[REFUSED]` and exit `2`, naming what the file actually contained and which export *is*
verifiable. *"0 rows verified"* and *"verified 0 rows because there were none to find"*
are different statements and only one of them is honest, so this tool never prints `[OK]`
for the second.

It reads the chain under `logs` (what `GET /v1/logs/export` writes) or under `ledger`
(what the GDPR bundle from `GET /v1/account/export` writes), so either file you are
handed can be checked. Anything else is refused rather than passed.

### Live on-chain check (optional)

The offline check confirms the export's chain matches the anchor receipt **Foxy
included**. To confirm against the **public chain** instead of Foxy's word, verify the
anchoring transaction really emitted the root:

```bash
pip install web3
python foxy_verify.py foxy-audit-logs.json --anchor --rpc https://rpc.sepolia.org
```

This fetches the anchor transaction named in the export and confirms it emitted
`Anchored(root)` on the `AnchorRegistry` contract. It only applies to EVM-anchored orgs
(a stub-anchored export has no on-chain transaction to check).

## The recipe (versioned, and frozen at every version)

Each row declares its own `chain_version`, and **each version is frozen forever**: what
a version hashes, and how, never changes once rows have been written under it. An
export downloaded years ago still verifies with today's script.

Versions 2, 3 and 4 each only **added** a field, which left every earlier payload
byte-identical for free. Version 5 is the first that changes how an **existing** field
(`occurred_at`) is rendered — so it is frozen the same way, one version at a time, and
a row written at version 4 still hashes exactly as version 4 always did.

`chain_version` 1 — the original pipe-delimited blob:

```
Hₙ = SHA256( "org_id|prompt_hash|response_hash|token_count|policy_tag|seq"  [+ "|agent=<agent>"]  +  Hₙ₋₁ )
H₀ = "0" × 64   (genesis)
```

The `|agent=<agent>` segment is appended **only when the row has an agent**, so rows
logged before agent attribution hash identically.

`chain_version` 2 and up — canonical JSON of the event, then the same construction:

```
Hₙ = SHA256( json(event, sort_keys, separators=(",",":"), ensure_ascii)  +  Hₙ₋₁ )
```

| Version | Adds to the event |
|---------|-------------------|
| 2 | `event_id`, `client_id`, `client_seq`, `event_type`, `commitment_alg`, `event_metadata`, `pii_signals`, `occurred_at` |
| 3 | `chain_version` itself (so the declared format is bound too) |
| 4 | `verdict_hash` — `SHA256(json(local_verdict))` |
| 5 | *adds nothing.* `occurred_at` is hashed as the **UTC instant** it names — `datetime.fromisoformat(...)`, converted to UTC, re-rendered with `isoformat()` — instead of as the text it arrived in. A value with no offset is read as UTC; a value that is not a timestamp at all is hashed unchanged |

### Why version 5 exists

PostgreSQL returns a `timestamptz` rendered in the reading session's own timezone, so
up to version 4 the same stored row hashed differently depending on where it was read.
An untouched export could be reported as **tampered** for no reason but the reader's
clock. From version 5 the instant is hashed rather than its rendering, so re-rendering
`occurred_at` into another offset — which is all a different session does — cannot
change the result. Moving the moment still breaks the chain, as it must.

⚠ If you reimplement this: parse the timestamp back into an instant and re-render it,
rather than editing the text. The two sides of this recipe start from different things
— the writer holds a `datetime`, you hold the string it was exported as — and only a
parse makes them agree.

Only the SHA-256 hashes of your prompt/response are ever stored — never the raw text.

### Which verdict version 4 binds

`local_verdict` is the **deterministic** verdict, decided by policy rules on the row's
metadata at the moment it was recorded. That is what `verdict_hash` covers, and editing
it afterwards breaks the chain.

`gemini_verdict` is the row's later grade. It is not bound, and cannot be: the chain hash
is fixed when the row is written, and grading happens asynchronously afterwards. Binding
it would mean re-hashing rows after the fact — which would invalidate every row after
them. So the chain covers what the system *decided*; the later grade sits beside it,
labelled, and this script does not check it.

### Who graded a row — read `graded_by`, do not assume

⚠ **`gemini_verdict` is named for the first provider this product shipped with. The name
is not evidence that a model produced what is in it** — a verdict stored there may have
been reached with no model called at all. Every verdict says which:

| `graded_by` | What it means |
|---|---|
| `"ai"` | a model answered; `judge_provider` / `judge_model` name it |
| `"rules"` | the deterministic metadata engine graded the row and no model was called. Where that is because a judge could not be reached, `evaluator_unavailable_reason` says why (`no_api_key`, `no_byok_key`, `byok_key_undecryptable`, or the failure type) |
| `"host_enforcement"` | the row is a prompt your own host blocked or redacted before it left. Nothing was sent, so there was no model response to grade |
| `"none"` | nothing graded the row — either no evaluator ran, or one answered and its answer was refused as self-contradictory |
| *absent* | the row predates the field. It records **no claim** about who graded it, and nothing was written in afterwards to invent one |

On `local_verdict` this field sits inside the bytes `verdict_hash` covers, so on a
`chain_version` 4 row an authorship claim cannot be edited without this script noticing.

## Optional: prove *which* text a commitment covers

Chain verification never needs your prompts — it recomputes from the stored field values
alone. Separately, and only if you want it, you can prove that a given row commits to a
specific piece of text you still hold:

```bash
python foxy_verify.py foxy-audit-logs.json --commitment-key "$FOXY_COMMITMENT_KEY" \
                                           --events my-sidecar.jsonl
```

The sidecar is **yours** — it never goes to Foxy, and Foxy has no copy. Two shapes work:

* a JSON object keyed by `event_id`, values holding `prompt` / `response` / `salt`; or
* JSON Lines, one `{"event_id": …, …}` per line, merged per event, later lines winning.
  This is the shape the SDK appends to when `FOXY_SALT_SIDECAR` is set.

### Salted commitments

A commitment is `HMAC-SHA-256(your key, canonical_json(text))`. With `FOXY_SALT_SIDECAR`
set, the SDK also mixes a fresh 128-bit per-event salt into that HMAC — canonically,
`HMAC(key, {"s": salt, "v": <canonical text>})`, never by concatenation — and records the
salt in your sidecar. Those rows declare `commitment_alg: "hmac-sha256-salted"`; rows
written without a salt keep `"hmac-sha256"` and hash exactly as they always did.

**The trade, stated plainly.** The salt exists only in your sidecar. Lose it and you lose
the ability to demonstrate which text those commitments cover — this script reports them
as *not checked* rather than passing or failing them. You do **not** lose chain
verification: tamper-evidence is recomputed from stored fields and never needs the salt.

## Trust model

| Check | When | Proves |
|-------|------|--------|
| Chain integrity | always | no historical row was altered (pure recompute) |
| Verdict binding | `chain_version` ≥ 4 | the row's local verdict is the one that was recorded — the digest is in the chain, and the verdict body still matches it |
| Known content (`--commitment-key --events`) | opt-in, needs your sidecar | a row's commitment covers the exact text you hold — and, for salted rows, only with the salt your SDK recorded locally |
| Anchor, offline | if a receipt is present | the export's chain matches the anchored root Foxy recorded |
| Anchor, on-chain (`--anchor`) | opt-in | that root really exists on a public chain, independent of Foxy |

`verifier/test_verify.py` cross-checks this script's recipe against the backend's real
`chain.py` on every run, so the two can never silently drift.
