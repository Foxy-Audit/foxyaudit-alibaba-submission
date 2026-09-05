# Key rotation must not kill the keys it was not asked about

**Plan of record** · written 2026-08-26 against `4aa4fbf`
MAIN chat is the committer; the executor builds per this file.

One phase, backend-only. Closes 🔴 **#249**.

---

## 1 · The defect, measured

`backend/app/routers/keys.py` `_rotate_org_key` selects **every active key in
the organisation** and revokes all of them, then mints one replacement named
`"primary (rotated)"`:

```python
for k in db.execute(
    select(ApiKey).where(ApiKey.org_id == org.id, ApiKey.status == "active")
).scalars().all():
    k.status = "revoked"
```

A customer runs three services with three keys. One service calls
`POST /v1/keys/rotate` to rotate its own credential. **The other two are
revoked.** Nobody is told.

⚠ **And they fail silently.** The SDK spools rather than crashing, so those two
services keep accepting traffic and keep writing to a spool that can never
drain — the failure this product exists to prevent, caused by the product.

## 2 · Premises, verified at `4aa4fbf`

| Premise | Holds? |
|---|---|
| `_rotate_org_key` revokes all active org keys | ✅ read in the code, not the docstring |
| `POST /v1/keys/rotate` is machine Bearer auth, no human | ✅ `Depends(require_org)` |
| **There are exactly TWO callers** | ✅ and this is what makes the fix clean |
| A fix exists on an abandoned branch | ✅ `6f8df60`, 2026-07-20, unmerged five weeks |

**The two callers, and why the split is already built for us:**

| caller | auth | should it revoke siblings? |
|---|---|---|
| `POST /v1/keys/rotate` (line ~190) | machine Bearer, **no human** | **NO** |
| `regenerate_confirm` (line ~253) | dashboard admin **+ a 2FA code** | **YES** |

The dashboard path already requires `require_role("admin")` *and* a valid MFA
code. That is a human, in a session, who has just proved possession of a second
factor — exactly the context in which "burn every key, something is compromised"
is the right action. The machine path has none of that and should not be able to
do it.

⚠ **The module docstring already frames these as two audiences.** It gave them
the same rotation semantics anyway. This phase makes the behaviour match the
framing that is already written down.

## 3 · The change

Add `_rotate_presented_key(db, org, token)` beside `_rotate_org_key`: revoke
**only** the key that authenticated this request, mint its replacement, leave
every sibling active. Point `POST /v1/keys/rotate` at it.
`regenerate_confirm` keeps `_rotate_org_key` unchanged.

The abandoned branch has a working version (`origin/fix/market-readiness-integrity`,
`6f8df60`). ⚠ **Read it as a reference, do not cherry-pick it** — it is five
weeks behind and `keys.py` has moved.

## 4 · Traps

- **The legacy plain-SHA256 org hash.** `_rotate_org_key` repoints
  `org.api_key_hash` at the new key so the old one dies. The presented-key path
  must decide this deliberately: repointing it there would kill the legacy key
  as a side effect of rotating an unrelated peppered one. The branch handles the
  "presented key IS the legacy org key" case separately — read why before
  copying.
- **`api_key_hash` is NOT NULL.** Whatever the new path does, that column must
  stay satisfied.
- **Identify the presented key by hash, never by name.** `hash_key(token)` for
  the peppered path; the legacy path compares the plain SHA-256.
- **The response says "the old key is permanently invalid."** If the new path
  only kills one key, that sentence is now wrong for the machine endpoint. Fix
  the wording — this repo has spent a week on messages that claim more than they
  know.
- **The docstring at the top of `keys.py` describes the old behaviour** in
  detail. It becomes false with this change.

## 5 · Guards

- **The regression guard is the point:** three active keys, rotate via
  `POST /v1/keys/rotate` authenticated as key A → A is revoked, **B and C are
  still active and still authenticate**. Today that test fails.
- The dashboard path still revokes everything: `regenerate_confirm` with a valid
  2FA code → all three revoked. ⚠ Without this control, "fix" the machine path
  by making nothing ever revoke and both tests pass.
- The rotated key really is dead: the old token no longer authenticates.
- The legacy-key case, whichever way it is decided, asserted explicitly.

## 6 · Verification

```bash
SELECT pid, state FROM pg_stat_activity WHERE datname='foxy_pytest';   # idle first
cd backend && DATABASE_URL=postgresql+psycopg://foxy:foxy@localhost:5433/foxy_pytest \
  python -m pytest tests/integration -q      # 1302 passed, 3 skipped at 4aa4fbf
py -3.13 -m pytest sdk/tests -q               # 918, must NOT move
```

Backend-only. No migration. No SDK change. No wire-contract change. No deploy
ordering — this ships and deploys on its own.

## 7 · After the merge

Close **#249** with the SHA. Re-stamp `Backend/CLAUDE.md`. Devlog.
⚠ And delete `origin/fix/market-readiness-integrity` **only after this merges** —
it is the only copy of that reasoning until then. Its second commit is already
dead (see `docs/plans/` history: checkout shipped, and the sale page now
deliberately refuses to file a failed purchase as a lead).
