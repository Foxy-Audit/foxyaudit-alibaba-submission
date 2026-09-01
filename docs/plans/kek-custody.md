# KEK custody — getting the crown jewel off the host

**Design of record** · 2026-09-02 · closes [[#302]] · **DESIGN ONLY — no code in this branch.**

Base `94d66fd`. Repo facts read at that SHA; GCP facts measured live in project
`prod-45412` on 2026-09-02 with read-only `gcloud` calls, and every command that
produced a fact is quoted so it can be re-run.

⚠ **No key value appears anywhere in this document.** Not a real one, not a
redacted one, not an illustrative one. Every placeholder below is the literal
string `<KEK>` or `<NEW-KEK>` and those are not keys. `CLAUDE.md` §6.

---

## 0 · The one-paragraph version

`PROVIDER_KEY_ENCRYPTION_KEY` lives in `deploy/.env` on the production VM, on the
same host and the same disk as the Postgres holding the `*_key_enc` ciphertext it
protects. The recommendation is **Google Secret Manager**, read once at process
start and cached for the process lifetime, with the existing environment variable
kept as a fallback so the cutover and the rollback are both trivial. This does
**not** stop an attacker who reaches code execution inside the container — that
process can fetch the key exactly as the app does. What it removes is the key
*at rest*: from the disk, from `deploy/.env`, and from every disk snapshot. The
snapshots are real, they are in the EU, and there are fourteen of them —
**confirmed, with one important correction to how they expire.**

---

## 1 · What was verified, and what the finding got wrong

Read at `94d66fd`. Measured against GCP `prod-45412` on 2026-09-02.

| # | The premise, as filed in [[#302]] | Holds? | What is actually true |
|---|---|---|---|
| 1 | `deploy/docker-compose.prod.yml:59` sources the KEK from `deploy/.env` on the VM | **HOLDS** | Line 59 is exactly `- PROVIDER_KEY_ENCRYPTION_KEY=${PROVIDER_KEY_ENCRYPTION_KEY:-}`, and the file header prescribes `--env-file deploy/.env`. `.github/workflows/deploy.yml` hard-fails the deploy if `deploy/.env` is absent. |
| 2 | The same stack runs `db: image: postgres:16` holding the ciphertext | **HOLDS** | `deploy/docker-compose.prod.yml` `services.db`, volume `foxy_pgdata`, on the same host. |
| 3 | Whoever reads the database can read the key that decrypts it | **HOLDS** | Both are readable by anyone with host-level access to the `devops` VM. |
| 4 | Only `:59` is affected | **INCOMPLETE — there are two** | The KEK is also injected at **`deploy/docker-compose.prod.yml:165`** for `foxy-worker`, which is the service that actually *decrypts* BYOK keys at grading time. Any design that changes only the API service breaks grading. Also `deploy/docker-compose.dev2.yml:55` and `:165` for the app2 stack, **which runs on the same VM**. |
| 5 | `crypto_secrets.py` accepts a comma-separated list; `MultiFernet` encrypts with the first and decrypts with all | **HOLDS** | `_load_keys()` at [crypto_secrets.py:57](../../backend/app/crypto_secrets.py#L57) splits on `,`; `_multifernet()` at [:65](../../backend/app/crypto_secrets.py#L65) wraps them in `MultiFernet`. |
| 6 | `_load_keys()` at `:57` is the seam | **HOLDS, and it is the *only* seam** | Every path — `encrypt_secret`, `decrypt_secret`, `encryption_configured`, `encryption_status` — reaches key material through `_multifernet()` → `_load_keys()`. Nothing else reads `get_settings().provider_key_encryption_key`. Confirmed by grep: the only non-`crypto_secrets` references are `config.py:42` (the field) and `judge_routing.py:200` (catching the exception). |
| 7 | The daily GCP snapshots carry the key, retained 14 days, stored in the `eu` multi-region | **HOLDS — see §2, with a correction to "14 days"** | Verified independently today. |
| 8 | "Production is already on GCP, which has Secret Manager and Cloud KMS" | **HOLDS, but the VM cannot reach either today** | ⚠ **The single most important thing this design found.** See §3. |

### What [[#302]] under-states

**It names the API service and not the worker.** The worker is the service that
decrypts. Fixing only `:59` would leave grading broken and BYOK saves working —
the worst possible split, because the failure would surface as
`evaluator_unavailable` on events rather than as an error on the change that
caused it.

**It treats the KEK as the only secret in that file.** `deploy/.env` also holds
`API_KEY_PEPPER`, `SESSION_SECRET`, `STAFF_SESSION_SECRET`, `POSTGRES_PASSWORD`,
`ANCHOR_EVM_PRIVATE_KEY`, and — relevant to [[#290]] — Foxy's own
`GEMINI_API_KEY` / `OPENAI_API_KEY`, plus `PADDLE_API_KEY` and
`PADDLE_WEBHOOK_SECRET`. This design moves **one** of them. That is the right
scope for a first move (the KEK is the one `CLAUDE.md` §6 names, and it is the
one whose loss is unrecoverable) but the document should not pretend the file is
clean afterwards. The mechanism generalises; the decision to generalise it is a
later phase and the owner's call.

---

## 2 · The snapshots: the claim holds, and expiry is conditional

**The claim in the brief is correct.** Measured 2026-09-02, project `prod-45412`:

```
$ gcloud compute instances list --project=prod-45412 \
    --format="table(name,zone.basename(),status,networkInterfaces[0].accessConfigs[0].natIP)"
devops   me-central1-a   RUNNING   34.18.4.58
```

`34.18.4.58` is the address named in the header of `.github/workflows/deploy.yml`
("VM at 34.18.4.58"). **The production VM is `devops`, definitively.**

```
$ gcloud compute instances describe devops --zone=me-central1-a --project=prod-45412
disks:
- boot: true
  deviceName: devops
  source: .../zones/me-central1-a/disks/devops
```

One disk, and it is the boot disk. The repo checkout lives on it — `deploy.yml`
clones to `/home/$VM_USER1/foxy-audit` — so **`deploy/.env` is on the boot disk
and nowhere else.**

```
$ gcloud compute snapshots list --project=prod-45412 \
    --filter="sourceDisk~devops$" \
    --format="csv(name,creationTimestamp,storageLocations,autoCreated)"
→ 14 rows, all storageLocations=eu, all autoCreated=True,
  creationTimestamps 2026-08-18 … 2026-08-31
```

```
$ gcloud compute resource-policies list --project=prod-45412 \
    --format="table(name,region.basename(),
      snapshotSchedulePolicy.retentionPolicy.maxRetentionDays,
      snapshotSchedulePolicy.retentionPolicy.onSourceDiskDelete,
      snapshotSchedulePolicy.snapshotProperties.storageLocations)"
default-schedule-1  us-central1              14  KEEP_AUTO_SNAPSHOTS  (empty)
default-schedule-1  northamerica-northeast1  14  KEEP_AUTO_SNAPSHOTS  (empty)
default-schedule-1  me-central1              14  KEEP_AUTO_SNAPSHOTS  (empty)
```

**Verdict: the crown jewel is replicated off-region nightly, fourteen live copies
at a time, into a location no policy document mentions. Confirmed.** Severity as
filed stands.

### ⚠ But "they age out in 14 days" is conditional, and the counter-example is in the same project

`maxRetentionDays: 14` deletes by age **only while the source disk exists**.
`onSourceDiskDelete: KEEP_AUTO_SNAPSHOTS` means that when a source disk is
deleted, its snapshots are **frozen, not expired**. Two proofs, both in
`prod-45412` today:

| Source disk | Snapshots | Newest | Age today | Disk exists? |
|---|---|---|---|---|
| `devops-1` | 14 | 2025-11-27 | ~9 months | **no** |
| `test` | 14 | 2025-10-02 | ~11 months | **no** |

Both sets are 9–11 months past a 14-day retention and are still there. **So the
retirement clock stops the moment the disk is replaced.** That is not a
hypothetical: rebuilding the VM, resizing to a new boot disk, or a migration to a
new instance would each freeze the fourteen KEK-bearing snapshots permanently.

⚠ **A second observation, which is not this design's problem but should be
recorded.** The newest `devops` snapshot is **2026-08-31**, while `erp-vm` and
`hackathon` (both `us-central1`) have **2026-09-01**. Every `me-central1` disk
stops at 08-31. The `me-central1` schedule appears to have missed a run. This is
worth an owner check for backup-coverage reasons — it does **not** change the KEK
analysis, and it is not evidence of anything else. Filed for the register, not
acted on here.

**Consequence for §7 below: waiting out the snapshots is not a control you can
rely on. Rotation is.**

---

## 3 · ⚠ THE BLOCKER: the VM cannot call Secret Manager or KMS today

```
$ gcloud compute instances describe devops --zone=me-central1-a --project=prod-45412 \
    --format="yaml(serviceAccounts)"
serviceAccounts:
- email: 173142282473-compute@developer.gserviceaccount.com
  scopes:
  - https://www.googleapis.com/auth/devstorage.read_only
  - https://www.googleapis.com/auth/logging.write
  - https://www.googleapis.com/auth/monitoring.write
  - https://www.googleapis.com/auth/service.management.readonly
  - https://www.googleapis.com/auth/servicecontrol
  - https://www.googleapis.com/auth/trace.append
```

This is the **default Compute Engine service account with the legacy default
scopes**. GCE access scopes are a restriction applied *on top of* IAM: a token
minted by the metadata server carries only these scopes, and an API call outside
them fails **regardless of what IAM roles the service account holds.**

- Secret Manager requires `https://www.googleapis.com/auth/cloud-platform`.
- Cloud KMS accepts `.../auth/cloudkms` or `.../auth/cloud-platform`.

**Neither is present.** So step zero of *any* runtime-fetch design is changing the
VM's access scopes — and **`gcloud compute instances set-service-account` and
`--scopes` both require the instance to be TERMINATED.**

### ⚠ This contradicts the brief's "assume no maintenance window"

There is one VM, no load balancer, and no second instance. **Stopping it stops
the product.** Estimated outage: VM stop + start on an `e2-medium`, then
`docker compose up -d` bringing Postgres, migrate, backend and worker back to
healthy — realistically **3–8 minutes**, and the whole of foxyaudit.tech,
app.foxyaudit.tech and admin.foxyaudit.tech is down for it. Exact figure **TBD**;
it must be measured on the dev2 stack's own VM restart, not guessed.

**I am not going to design around this by pretending it is free.** The three
honest options:

| | Option | Downtime | Key at rest afterwards |
|---|---|---|---|
| **A** | **Stop the VM once, add `cloud-platform` (or `cloudkms`) scope, start it.** | ~3–8 min, once, scheduled | **none** |
| **B** | Put a **service-account JSON key file** on the VM and mount it into the containers. No VM stop. | zero | a *credential* is at rest instead of the *key* |
| **C** | Do nothing; accept and document the risk. | zero | the KEK, as today |

**Recommendation: A**, scheduled, announced, at the lowest-traffic hour. It is a
single planned minutes-long stop against a permanent removal of the crown jewel
from disk and from every snapshot, and it is the only option that reaches
"none" in the right-hand column.

**Option B is the fallback if the owner will not take the stop**, and it is
genuinely better than today rather than theatre: an SA key file is *revocable in
one click*, *rotatable without touching any ciphertext*, and *every use of it is
IAM-audited*, whereas the KEK on disk is none of those — a leaked KEK is silent,
permanent, and can only be retired by re-encrypting every BYOK row. But it is
strictly worse than A, because the file still lands in `deploy/`-adjacent
storage and therefore in the snapshots. **If B is chosen, say so on the record
and keep A as the target.**

⚠ **The scope requirement above must be re-verified in the console immediately
before execution.** GCE scope semantics are stable but this design should not be
the last word on a fact that gates a production stop. Treat the `cloudkms`
narrow-scope claim in particular as **verify-before-use**.

---

## 4 · Where the KEK lives instead — Secret Manager vs Cloud KMS

### The two shapes

**Secret Manager** stores the Fernet key material itself. The app calls
`AccessSecretVersion` and gets back exactly the string that sits in `deploy/.env`
today — including, unchanged, a comma-separated list. `_load_keys()` swaps its
source and **every other line of `crypto_secrets.py` is untouched**.

**Cloud KMS (envelope)** stores a key that *wraps* the Fernet key. The wrapped
blob is not secret and can sit in `deploy/.env`, in a file, or in a table; the
app calls `Decrypt` on it at startup to recover the Fernet key. KMS key material
never leaves KMS.

### The comparison that actually matters here

| | Secret Manager | Cloud KMS envelope |
|---|---|---|
| KEK on the VM disk / in snapshots | **no** | **no** |
| KEK in the app process's memory | yes — unavoidable, `MultiFernet` needs it | yes — identically unavoidable |
| Attacker with code execution in the container | **gets the KEK** | **gets the KEK** |
| Attacker with only the SA token (e.g. SSRF to the metadata server) | gets the KEK, permanently, in one call | can only ask KMS to decrypt a blob they must also steal; access is revocable and every call is logged |
| Someone can print the KEK to a terminal | yes (`gcloud secrets versions access`) | **no** — there is no such command |
| Artefacts to manage | one secret | one key **plus** a wrapped blob that must be stored, deployed and versioned |
| Change to `crypto_secrets.py` | one function's source | one function's source **plus** a blob-location config, plus a rewrap step in every rotation |
| Rotation compatibility with the existing comma-list | **exact** — the list is the payload | works, but the list must be re-wrapped on every rotation |
| Access scope needed on the VM | `cloud-platform` only | `cloudkms` (narrower) or `cloud-platform` |

### Recommendation: **Secret Manager**

Three reasons, in order of weight.

1. **The threat this phase exists to close is closed identically by both.** The
   finding is *key at rest on a disk that is snapshotted off-region*. Both
   options remove it completely. The extra protection KMS buys applies to a
   narrower scenario — a credential leaking *without* container code execution —
   and in this deployment the metadata server and the container are the same
   blast radius for almost every realistic path.

2. **`_load_keys()` returns a list, and Secret Manager's payload is a string.**
   The comma-separated rotation vocabulary that makes §6 zero-downtime survives
   the move byte-for-byte. KMS would introduce a second artefact (the wrapped
   blob) that has to be kept in sync with the key, deployed to two services and
   two stacks, and re-wrapped on every rotation — new failure modes in the module
   `CLAUDE.md` calls a crown jewel, bought for a marginal threat reduction.

3. **Two people run this.** Operational simplicity is a security property, not a
   convenience. A design with one artefact and one command to inspect it is a
   design that will still be correct in six months.

**Being fair to the rejected option.** KMS's real advantage is not cryptographic,
it is *human*: with Secret Manager there exists a single command that prints the
crown jewel to somebody's terminal, into their shell history, and possibly into a
screenshot. This project's own history contains exactly that class of accident.
That is a genuine argument and it is why the mitigation in §5 (Data Access audit
logs on the secret, alert on any human principal reading it) is **not optional**
— it is the compensating control that makes this recommendation defensible.
**If the owner would rather pay the extra complexity to make that command not
exist, KMS is a defensible choice and the rest of this document is unchanged
except for §6 step 1.**

### Cost

**TBD — not guessed.** Both are billed on the same two axes and the volume here
is tiny (one secret, one version, a handful of reads per container start):

- Secret Manager: **per active secret version per month** + **per access
  operation** (SKU family "Secret Manager").
- Cloud KMS: **per active key version per month** + **per cryptographic
  operation** (SKU family "Cloud Key Management Service"; software-protected
  keys, not HSM).

Look both up in the GCP pricing calculator at execution time. Neither is
plausibly a decision input at this volume, and a number written here that is
wrong is worse than the `TBD`. Same rule as the clause citations.

---

## 5 · How the app authenticates, and what this does NOT fix

### Authentication

**Service account identity from the GCE metadata server.** Concretely, on a
Compute Engine VM running docker compose:

1. **A dedicated service account** — not the default compute SA, which today is
   attached to every VM in the project. Create
   `foxy-prod-runtime@prod-45412.iam.gserviceaccount.com` (name TBD, owner's
   call).
2. **One IAM binding, on the secret, not on the project:**
   `roles/secretmanager.secretAccessor` granted **at the secret resource level**.
   Nothing else. The service account must not be able to list, create, modify or
   destroy secrets, and must not have the role project-wide.
3. **Attach it to the `devops` instance with `cloud-platform` scope** — the stop/
   start of §3 option A does both changes at once, so it is one outage, not two.
4. **In the containers**, `google-auth` finds the credential automatically via
   Application Default Credentials → the metadata server. **No key file, no
   `GOOGLE_APPLICATION_CREDENTIALS`, no new value in `deploy/.env`.** The compose
   files gain one variable naming the secret's *resource path* — which is not a
   secret and is safe in git and in the snapshots.

⚠ **Workload Identity Federation is not applicable here** and a design that
reached for it would be wrong: WIF exchanges an *external* IdP's token for a
Google one. On GCE the attached service account already *is* the workload
identity. Anything mentioning GKE Workload Identity is likewise inapplicable —
there is no cluster.

⚠ **`--scopes=cloud-platform` on the default compute SA would be a mistake.** The
default SA holds broad project permissions by legacy; widening its scope on a VM
that is internet-facing widens far more than Secret Manager. Doing the dedicated
SA and the scope change in the same stop is what keeps this a net reduction in
privilege rather than an increase.

### ⚠ What this does NOT fix — read this before claiming anything

**An attacker who achieves code execution inside the running container is
unaffected by this change.** That process holds the same service-account
identity, calls the same API, and gets the same key — or simply reads it out of
the already-populated in-memory cache. The Fernet key must exist in plaintext in
the process that uses it; there is no version of this design where it does not.
The same is true of Cloud KMS.

Precisely what is removed, and nothing more:

| | Before | After |
|---|---|---|
| KEK readable from the VM's filesystem | **yes** — `deploy/.env` | no |
| KEK present in the 14 EU disk snapshots | **yes** | no *(new snapshots only — see §7)* |
| KEK obtainable from a stolen/restored disk image | **yes** | no |
| KEK obtainable by an operator with VM shell access | **yes**, by `cat` | only by minting a token as the SA — **and it is audit-logged** |
| KEK obtainable by code execution inside the container | yes | **yes — unchanged** |
| KEK obtainable by someone who can read the database | yes *(same host)* | **no** — this is the two-factor structure the design implied and the deployment did not have |
| Foxy's *other* secrets in `deploy/.env` | at rest on disk | **at rest on disk — unchanged** |

**Row 5 is the whole value of the change, and row 6 is the whole limit of it.**
Anyone summarising this work — in the register, in a devlog, on a trust page, to
an auditor — must carry both rows or they are overselling it, which is the same
defect this programme exists to find.

**Compensating control, required, not optional.** Enable **Data Access audit
logs** for the Secret Manager API (they are off by default) and alert on any
`AccessSecretVersion` whose principal is **not** the runtime service account.
That converts "a human could print the crown jewel" from an invisible event into
a paged one, and it is the control that closes the gap §4 conceded to KMS.

### Failure behaviour — preserving fail-closed without inventing an outage

The module fails closed today: no usable key → `SecretsNotConfigured` →
HTTP 503 on `POST` of a BYOK key ([policies.py:166](../../backend/app/routers/policies.py#L166))
and `byok_encryption_unavailable` → `evaluator_unavailable` in the worker
([judge_routing.py:199](../../backend/app/judge_routing.py#L199)). **That contract
does not change.** But `_multifernet()` calls `_load_keys()` on *every* encrypt
and decrypt — turning that into a network round-trip per graded event would be
both a latency disaster and an availability one.

**Design:**

- **Fetch once, at first use, into a module-level cache.** Not per call.
- **Cache for the process lifetime, refreshed on a TTL** (proposal: 15 minutes;
  the exact value is not load-bearing).
- **A failed refresh never evicts the cache.** Last-good keys are kept and used.
  A Secret Manager blip is then completely invisible to the product — which is
  the requirement the brief sets, and the trap it names.
- **A failed *initial* fetch is treated exactly as "unset" is today** —
  `encryption_status()` returns `unset`, the existing startup log fires, BYOK
  saves 503 and grading returns `evaluator_unavailable`. No new failure mode, no
  silent plaintext downgrade, no crash. `main.py:105` already reports this at
  boot and needs no change.
- **Add a third status.** `encryption_status()` should be able to say
  `unavailable` (fetch failed) as distinct from `unset` (deliberately blank) and
  `malformed` (a typo). All three must remain subclasses of the existing
  exception so every `except SecretsNotConfigured` handler in the codebase keeps
  working unchanged. This is the same distinction `SecretsMisconfigured` already
  draws, for the same reason.

**Is a cached key in memory acceptable, and for how long?** Yes, and the
justification is that **it adds no new exposure at all**: today
`get_settings()` is `lru_cache`d and holds the KEK in a `SecretStr` for the
entire process lifetime. An in-memory cache is not a new residency for the key —
it is the same residency, reached differently. Process lifetime is therefore the
correct bound.

**What the cache costs.** A revoked or rotated secret stays usable in a running
process until the next successful refresh (≤ TTL), and if Secret Manager is
unreachable, indefinitely. That is a deliberate trade: an emergency revocation is
completed by restarting the containers, which is a two-command operation on this
VM, and it is the right side of the trade against turning a transient API blip
into a total BYOK outage.

---

## 6 · The migration — zero downtime, no re-encryption

**The load-bearing insight: the KEK's *value* does not change during the
cutover.** Only where the app reads it from changes. So **nothing is
re-encrypted, and no ciphertext is at risk at any point in steps 1–5.** The
`MultiFernet` comma-list is not needed to make the *cutover* safe — it is what
makes the **rotation** in §7 zero-downtime, which is a separate, later, and
genuinely riskier operation.

### The code seam

One function. `_load_keys()` at [crypto_secrets.py:57](../../backend/app/crypto_secrets.py#L57)
gains a source, in this precedence:

```
keys = secret_manager_keys()   if a secret resource path is configured and readable
       else env_var_keys()     the current behaviour, unchanged
```

Both sources yield "a comma-separated string of Fernet keys". Everything
downstream — `_multifernet()`, `encrypt_secret`, `decrypt_secret`,
`encryption_configured`, `encryption_status` — is **untouched**. That is the
whole change, and the fact that it is this small is the argument for Secret
Manager over KMS.

**A new config value**, `PROVIDER_KEY_ENCRYPTION_SECRET` (name TBD), carrying the
secret's resource path, e.g. `projects/<n>/secrets/<name>/versions/latest`. **Not
a secret.** It goes in `deploy/.env` and must be added to the `environment:`
allowlist of **all four** service blocks: `foxy-backend` and `foxy-worker` in
both `docker-compose.prod.yml` and `docker-compose.dev2.yml`. ⚠ The compose
`environment:` block is an allowlist — a value in `deploy/.env` not named there
never reaches the container. This exact omission has already cost this project
once (the `PADDLE_*` comment at `docker-compose.prod.yml:74`), and it would cost
it again here as a silent fallback to the env var. **A guard must assert the
variable is present in all four blocks.**

### The steps

Each step is independently revertible, and **nothing is destroyed until step 5.**

| # | Step | Downtime | Reversible by |
|---|---|---|---|
| **0** | **Stop the VM. Create the dedicated SA, attach it with `cloud-platform` scope. Start the VM.** | **~3–8 min, scheduled** | another stop/start; harmless to leave in place |
| 1 | Create the secret and one version whose payload is **byte-identical** to the current `deploy/.env` value. Grant `secretAccessor` **on the secret only**. | none | delete the version; nothing reads it yet |
| 2 | Merge the `_load_keys()` change + the four compose allowlist entries. **Do not yet set `PROVIDER_KEY_ENCRYPTION_SECRET`.** Redeploy. | none | `git reset --hard` + redeploy |
| 3 | Set `PROVIDER_KEY_ENCRYPTION_SECRET` in `deploy/.env`. Redeploy. **The app now reads Secret Manager; the env var is still present and still identical.** | none | unset the variable + redeploy |
| 4 | **Verify** (see §8) that the live source is Secret Manager, on **both** the API and the worker, and that a BYOK save and a BYOK grading both still succeed. | none | — |
| 5 | Remove `PROVIDER_KEY_ENCRYPTION_KEY` from `deploy/.env`. Redeploy. Then `docker system prune -f`. | none | paste the value back — **see §7 rollback preconditions** |
| 6 | *(Later, separately)* Rotate the KEK. **This one does re-encrypt.** See §7. | none | see §7 |

**Why step 2 and step 3 are separate.** Step 2 ships code whose behaviour is
provably identical to today (the new source is not configured, so the fallback
runs). If anything is wrong with the deploy, it is wrong for reasons unrelated to
this change, and you find that out before the behaviour switches. Step 3 is then
a one-variable change with a one-variable undo.

**Why step 5 is separate from step 3.** Between them, both sources hold the same
value, so the system is correct under either. That window is where the
verification in §8 runs, and it can be as long as you like — hours, a day.

**Why there is no downtime in steps 1–5.** `docker compose up -d` recreates
containers one service at a time; the API is behind nginx on the same host and
the gap is the container's own restart. That is the same exposure every deploy on
this VM already has and it is not new. **Step 0 is the only real outage, and it
is a scope change, not this design's mechanism.**

---

## 7 · Rollback, and retiring the fourteen snapshots

### Rollback at 3am — the sequence, in order

**Read the top line first, then start at the step matching where you are.**

> ⛔ **STOP. Has step 6 (the KEK rotation) run yet?**
> **If NO** — everything below works. The original KEK value is still in
> `deploy/.env` (before step 5) or in Secret Manager (after it), and every
> `*_key_enc` row in the database was encrypted with it.
> **If YES** — do **not** paste the old value back. Rows re-encrypted under the
> new key will not decrypt with it. Go to "After rotation" at the bottom.

```
# You are on the VM, in the repo root (/home/<user>/foxy-audit).

# 1. Which step are you undoing?

#    Undoing step 3 (app started reading Secret Manager and something broke):
     nano deploy/.env            # delete the PROVIDER_KEY_ENCRYPTION_SECRET line
     docker compose -f deploy/docker-compose.prod.yml --env-file deploy/.env \
       up --build -d --remove-orphans
     # The env-var fallback takes over. Value unchanged. Done.

#    Undoing step 2 (the code change itself is suspect):
     git log --oneline -5                       # find the pre-change SHA
     git reset --hard <pre-change-sha>
     docker compose -f deploy/docker-compose.prod.yml --env-file deploy/.env \
       up --build -d --remove-orphans
     # Back to exactly today's behaviour. Done.

#    Undoing step 5 (the env var has already been removed):
     gcloud secrets versions access latest --secret=<secret-name> --project=prod-45412
     # ⚠ This PRINTS THE CROWN JEWEL to your terminal and into shell history.
     #   Do it only if you must, and clear the history afterwards.
     nano deploy/.env            # restore PROVIDER_KEY_ENCRYPTION_KEY=<KEK>
                                 # and delete PROVIDER_KEY_ENCRYPTION_SECRET
     docker compose -f deploy/docker-compose.prod.yml --env-file deploy/.env \
       up --build -d --remove-orphans

# 2. Confirm.
     curl -fsS http://127.0.0.1:8085/health/ready
     docker compose -f deploy/docker-compose.prod.yml logs --tail=40 foxy-backend \
       | grep -i PROVIDER_KEY_ENCRYPTION_KEY
     # No "not set" and no "NOT a valid Fernet key" line = the KEK loaded.

# 3. Prove a BYOK key still decrypts before you go back to bed.
#    See §8's smoke check. A green /health/ready does NOT prove this.
```

**Step 0 (the scope change) does not need rolling back** and should not be. It
grants the VM the *ability* to read one secret; with `PROVIDER_KEY_ENCRYPTION_SECRET`
unset, nothing uses it. Leaving it in place means the retry needs no second outage.

### What must not have happened yet for rollback to work

1. **The rotation (step 6) must not have run.** This is the hard boundary. After
   it, the old value is not the key any more.
2. **The Secret Manager version must not have been destroyed.** Do not destroy
   any version during the cutover. Disable if you must; destroy never.
3. **Someone must be able to reach the value.** Before step 5, keep an
   **out-of-band break-glass copy** of the KEK — offline, off this VM, off GCP,
   in the owner's password manager. If Secret Manager and `deploy/.env` are the
   only two copies and both become unreachable, every stored BYOK key is
   unrecoverable, which is exactly the availability risk `CLAUDE.md` §6 names.
   **This is the single most important sentence in the rollback section.**

### After rotation

If step 6 has run and you must go back to environment variables, put the **new**
key in `deploy/.env`, not the old one — and understand that doing so re-creates
the finding, because the new key is now on disk and will be in tonight's
snapshot. Prefer fixing forward.

### The fourteen snapshots that already carry the key — answered

**They do not clean themselves, and time is not the control.**

- **What removing the value from `deploy/.env` (step 5) achieves:** every snapshot
  taken *after* it is clean. Nothing else.
- **What the 14 existing snapshots retain:** the KEK, in `deploy/.env`, in the
  `eu` multi-region, until each expires 14 days after its own creation. So the
  last one expires roughly **14 days after the day step 5 completes**.
- ⚠ **And only if the `devops` disk still exists that whole time.** §2 proves
  `KEEP_AUTO_SNAPSHOTS` freezes snapshots permanently when the source disk is
  deleted, with two live counter-examples in this project ~9 and ~11 months past
  retention. If the VM is rebuilt or the disk replaced in that window, those
  fourteen copies become permanent.
- ⚠ **`deploy/.env` is not the only place on that disk.** The env var is also
  baked into each container's config under `/var/lib/docker`, on the same
  snapshotted disk. `docker compose up --build -d` recreates the containers, and
  the `docker system prune -f` in step 5 clears stopped ones — **that prune is
  load-bearing, not tidiness.** Also sweep for the value in root's and the deploy
  user's shell history.

**Therefore: rotating the KEK is what actually retires them.** Waiting retires
the *copies*; rotation retires the *value*, and it is the only step that makes
the question closed regardless of what copies exist anywhere — snapshots, an old
backup, a laptop, a scrollback buffer.

**Sequence, and the order is not negotiable:**

```
step 5 complete  ──► the env var is gone; new snapshots are clean
       │
       ├─► (a) generate <NEW-KEK> — crypto_secrets.generate_encryption_key(),
       │       run on an operator machine, never written to the VM disk
       │
       ├─► (b) Secret Manager: add a NEW VERSION whose payload is
       │       "<NEW-KEK>,<KEK>"  — new first, old second.
       │       MultiFernet: encrypts with the FIRST, decrypts with ALL.
       │       No restart needed at the moment of the change; the TTL refresh
       │       picks it up, or redeploy to take it immediately.
       │       ⚠ EVERY RUNNING PROCESS MUST HOLD BOTH KEYS BEFORE (c).
       │       Confirm on BOTH foxy-backend and foxy-worker.
       │
       ├─► (c) re-encrypt every *_key_enc row: decrypt (old key still present,
       │       so this works) then encrypt (new key is first, so this uses it).
       │       Idempotent, resumable, row-at-a-time, plaintext never logged and
       │       never leaving the process. Rehearsed on dev2 first.
       │       Zero downtime: at every instant, every row is decryptable by
       │       one of the two keys the processes hold.
       │
       ├─► (d) verify NO row still decrypts under <KEK> alone
       │
       └─► (e) Secret Manager: add a version whose payload is "<NEW-KEK>" alone.
               ⚠ THIS IS THE POINT OF NO RETURN. After (e) the old key is
               retired and every copy of it — including all fourteen snapshots
               and any that were frozen — is worthless.
               Keep the old version DISABLED, not destroyed, for 30 days.
```

**Timing.** (a)–(e) can run at any point after step 5. Running it *immediately*
retires the snapshot exposure without waiting 14 days and removes the "what if
the disk gets replaced" hazard entirely — **that is the recommendation.** The
14-day wait is then a belt-and-braces coincidence, not a control.

**Before (c), measure the work:**

```sql
SELECT count(*) FILTER (WHERE gemini_key_enc IS NOT NULL) AS gemini,
       count(*) FILTER (WHERE openai_key_enc IS NOT NULL) AS openai
FROM org_policies;
```

If that is a handful of rows the re-encryption is a minute's work. If it is not,
it needs batching and a progress marker. **Do not write the script before running
the count.**

---

## 8 · How this is tested before production

### Unit — in `backend/tests/`

Extend the existing `test_crypto_secrets.py`, which already covers rotation and
context binding.

1. **Source precedence.** With a faked Secret Manager client: secret path
   configured → keys come from the secret; not configured → keys come from the
   env var; configured but the fetch raises → falls back to the env var (step 3's
   safety net) or, if the env var is also blank, `encryption_status() == "unavailable"`.
2. **The comma-list survives the new source.** A two-key payload from Secret
   Manager must produce a `MultiFernet` that encrypts with the first and decrypts
   with both — the identical assertions the env-var path already has.
3. **Caching.** `encrypt_secret` called N times performs **exactly one** fetch.
   This is the test that stops a per-event network call reaching production.
4. **A failed refresh does not evict.** Prime the cache, make the client raise,
   assert `decrypt_secret` still works.
5. **Fail-closed is preserved.** No key from any source → `SecretsNotConfigured`
   → the existing 503 and `evaluator_unavailable` tests must still pass
   **unmodified**. If they need editing, the contract changed and the design is
   wrong.
6. **Nothing logs the key.** Assert on captured log records across every failure
   path, including the new one. `gemini.py`'s log-leak is the precedent.

### Integration

The existing BYOK integration tests must pass unchanged against a
Secret-Manager-sourced key. **Run each suite alone** — `tests/integration` shares
one database and two concurrent runs corrupt each other.

### ⚠ Guards — and make each one fail on purpose before trusting it

- **The compose allowlist guard.** Assert `PROVIDER_KEY_ENCRYPTION_SECRET` appears
  in all **four** service blocks (`foxy-backend` + `foxy-worker` × prod + dev2).
  **Break it by deleting one entry and confirm it goes red** — a guard that only
  checks the prod backend is the [[#302]] blind spot restated.
- **A no-plaintext-KEK guard** over `deploy/.env.example` and the compose files.
- ⚠ **Do not write a guard that checks `_load_keys()` mentions Secret Manager.**
  That is a token check, not a behaviour check — the fourth way a guard lies.
  Drive the function and assert on the keys it returns.

### Rehearsal on dev2 — the whole point

`docker-compose.dev2.yml` runs a second Foxy on the **same VM** (`127.0.0.1:8086`,
database `foxy_dev`). It shares the host, the service account and the scopes, so
it is a genuinely representative target rather than a lookalike.

1. Do **step 0 once** — it serves both stacks, and it is the only outage.
2. Run steps 1→5 against dev2 with its own secret and its own resource path.
3. **Save a BYOK key through the dev2 API, then confirm an event actually grades
   with it.** A green `/health/ready` proves nothing here: the API can be healthy
   while the *worker* cannot decrypt, and that is precisely the failure mode
   [[#302]]'s single-line framing would produce.
4. **Rehearse the full rotation (a)–(e) on dev2**, with throwaway BYOK values, and
   confirm zero failed gradings across the window.
5. **Measure the VM stop→healthy time** during step 0 so the production window is
   a number, not the estimate in §3.

### The production smoke check, for step 4 and for rollback

```
# 1. Both services loaded a key — the absence of the startup warnings.
docker compose -f deploy/docker-compose.prod.yml logs --tail=80 foxy-backend foxy-worker \
  | grep -iE "PROVIDER_KEY_ENCRYPTION_KEY|not a valid Fernet|is not set"
#    Expect NOTHING. Any hit means the key did not load in that service.

# 2. The worker is alive and grading.
curl -fsS http://127.0.0.1:8085/health/ready

# 3. THE ONE THAT MATTERS: an end-to-end BYOK round trip on a test org —
#    save a key, emit an event, confirm the verdict is not evaluator_unavailable.
#    Steps 1 and 2 can both be green while decryption is broken.
```

---

## 9 · Register consequences

| Entry | What this design does to it |
|---|---|
| [[#302]] | Stays open; this is its design, not its fix. **Amend it:** the worker at `docker-compose.prod.yml:165` is also affected, and the VM's service account lacks the scope to reach either service (§3). |
| [[#291]] | Corroborated and **extended**: `KEEP_AUTO_SNAPSHOTS` freezes snapshots permanently once the source disk is deleted — two live examples in `prod-45412`, ~9 and ~11 months past a 14-day retention. "Retained 14 days" is conditional on the disk existing. |
| [[#294]] | Untouched by this design. Pinning `storageLocations: me-central1` on the `me-central1` policy would make the withdrawn sentence true and would also shrink this finding's geography — **adjacent, and the owner's call**, not this phase's. |
| [[#290]] | Unchanged and worth stating: Foxy's own `GEMINI_API_KEY` / `OPENAI_API_KEY` sit in the same `deploy/.env` and the same snapshots. This design moves the KEK only. |
| **new** | The `me-central1` snapshot schedule appears to have missed 2026-09-01 while `us-central1` did not (§2). Backup-coverage question, not a KEK question. Worth an owner check. |

---

## 10 · Open questions for the owner

1. **§3 option A vs B** — is a single scheduled 3–8 minute outage acceptable to
   get the key off the disk permanently? **A is recommended.** B is the honest
   fallback and is still better than today.
2. **Secret Manager vs Cloud KMS** — §4 recommends Secret Manager. KMS is
   defensible if the "no command prints the key" property is worth the extra
   artefact and the rotation complexity.
3. **When to rotate.** §7 recommends immediately after step 5 rather than waiting
   out the 14 days, because the wait is not a control.
4. **Where the break-glass copy lives.** §7's precondition 3. This must be
   answered before step 5, not after.
5. **Scope creep, deliberately not taken:** the other secrets in `deploy/.env`.
   Same mechanism, later phase, owner's call.
