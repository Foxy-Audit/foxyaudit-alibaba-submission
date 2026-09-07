# Runbook — the Alibaba Cloud AI Hackathon Pakistan 2026 submission stack

> **As-planned, 2026-09-07.** Every command below runs **on the VM** as `devops`.
> Nothing here touches production's compose project, its nginx file, its
> database, its certificate, or its avatar volume.

---

## What this is, and the one thing it is not

| | |
|---|---|
| **Alibaba Cloud usage** | **Real.** The agentic compliance judge — [`backend/app/qwen_judge.py`](../backend/app/qwen_judge.py) — calls **Alibaba Cloud Model Studio** (Qwen) at `https://dashscope-intl.aliyuncs.com/compatible-mode/v1`, with two tools: `flag_for_human_review` and `check_prior_reviews`. `QWEN_API_KEY` is **required** by this stack's compose file. |
| **Hosting** | ⚠ **Google Cloud, not Alibaba Cloud.** Owner decision 2026-09-07: the Alibaba ECS instance was not purchased. This runs on the project's existing GCE VM. **Do not describe this deployment as running on Alibaba Cloud anywhere** — not in the README, not on the submission form, not in the video. |

**The VM:** instance `devops`, project `prod-45412`, zone `me-central1-a`,
external IP `34.18.4.58`. Reverse DNS `58.4.18.34.bc.googleusercontent.com`.

---

## The three stacks that will be on this box

| | prod (**FROZEN**) | dev2 | **this** |
|---|---|---|---|
| Hosts | foxyaudit.tech, www, app, admin, checkout | app2, admin2, checkout2 | **app- / admin- / checkout-alibaba-submission** |
| Backend port | `127.0.0.1:8085` | `127.0.0.1:8086` | **`127.0.0.1:8087`** |
| Checkout dir | `/home/devops/foxy-audit` | `/home/devops/foxy-audit-dev` | **`/home/devops/foxy-audit-alibaba`** |
| Compose project | `foxy-prod` | `foxy-dev` | **`foxy-alibaba`** |
| Compose file | `docker-compose.prod.yml` | `docker-compose.dev2.yml` | **`docker-compose.alibaba.yml`** |
| Database | `foxy` (role `foxy`, superuser) | `foxy_dev` | **`foxy_alibaba`** |
| RLS role | `foxy_app` | `foxy_app_dev` | **`foxy_app_alibaba`** |
| Avatar volume | `foxy-prod_foxy_avatars` | `foxy-dev_foxy_dev_avatars` | **`foxy-alibaba_foxy_alibaba_avatars`** |
| nginx file | `foxyaudit.conf` | `foxyaudit-dev2.conf` | **`foxyaudit-alibaba.conf`** |

⚠ **There is no `db` container in this stack.** It uses the `foxy_alibaba`
database inside the existing `foxy-prod-db-1`, reached by joining
`foxy-prod_default` as an external network.

---

## Step 0 · Baseline production BEFORE touching anything

Compare **by body size, not status code** — a 200 means nothing on this domain.

```bash
for h in foxyaudit.tech www.foxyaudit.tech app.foxyaudit.tech \
         admin.foxyaudit.tech checkout.foxyaudit.tech; do
  printf "%-28s " "$h"
  curl -sS -o /dev/null -w "HTTP %{http_code} %{size_download}b\n" "https://$h"
done | tee ~/foxy-baseline-alibaba-before.txt

# Production cert expiry — proves certbot never touched it later
sudo certbot certificates 2>/dev/null | grep -A3 "foxyaudit.tech"
```

**Expected (measured from off-box, 2026-09-07):**

```
foxyaudit.tech               HTTP 200 327691b
www.foxyaudit.tech           HTTP 200 327691b
app.foxyaudit.tech           HTTP 302    154b
admin.foxyaudit.tech         HTTP 302    154b
checkout.foxyaudit.tech      HTTP 200  43000b
```

Then three capacity checks. This is a **shared box**, and the ways a third stack
hurts production are resource exhaustion, not config bleed.

```bash
# 1 · Swap. The box runs four businesses' containers and a docker build spikes.
free -h            # expect ~2Gi swap. If 0, STOP and add it before building.

# 2 · Disk. The backend image is ~1-2GB (weasyprint) and shares a disk with
#     production's foxy_pgdata volume. A full disk corrupts Postgres, not just
#     the build.
df -h /var/lib/docker /   # want several GB free before building

# 3 · Postgres connection budget. THIS IS THE ONE THAT CAN TAKE PRODUCTION DOWN.
#     A third stack adds two more SQLAlchemy QueuePools (pool_size 5 +
#     max_overflow 10 each) against the SAME postgres container, which ships
#     with max_connections=100.
docker exec foxy-prod-db-1 psql -U foxy -c \
  "SELECT current_setting('max_connections') AS max,
          (SELECT count(*) FROM pg_stat_activity) AS in_use;"
```

⚠ If `max - in_use` is under ~40, **stop and raise `max_connections` before
starting this stack** — production hitting `FATAL: sorry, too many clients
already` is exactly the outcome this whole parallel-stack design exists to
avoid.

---

## Step 1 · Clone the submission repo

```bash
cd /home/devops
git clone https://github.com/Foxy-Audit/foxyaudit-alibaba-submission.git foxy-audit-alibaba
cd foxy-audit-alibaba && git log --oneline -1
```

⚠ While the repo is **private** this prompts for credentials. Easiest order is
to flip the repo public first (it is on the checklist anyway), then clone
anonymously. Otherwise use a PAT.

---

## Step 2 · Database and roles

Run as the `foxy` superuser inside the production db container.

🔴 **`foxy_alibaba` must NEVER be granted `foxy_app`.** `PUBLIC` holds `CONNECT`
on every database by default, so membership in production's confined role would
let this credential connect to `foxy` and do DML on production's tables. That is
exactly why `foxy_app_alibaba` exists.

```bash
# The secrets directory must exist BEFORE anything writes into it.
mkdir -p ~/foxy-alibaba-secrets && chmod 700 ~/foxy-alibaba-secrets

# ⚠ hex, NOT base64. This password is pasted into a URL-form DATABASE_URL, and
# base64's alphabet includes `/` and `+` — roughly two in five generated
# passwords would silently corrupt the connection string.
openssl rand -hex 24 > ~/foxy-alibaba-secrets/db_password
chmod 600 ~/foxy-alibaba-secrets/db_password
PW=$(cat ~/foxy-alibaba-secrets/db_password)

docker exec -i foxy-prod-db-1 psql -U foxy -d postgres <<SQL
CREATE ROLE foxy_alibaba LOGIN PASSWORD '$PW' BYPASSRLS;
CREATE ROLE foxy_app_alibaba NOLOGIN NOBYPASSRLS;
GRANT foxy_app_alibaba TO foxy_alibaba;
CREATE DATABASE foxy_alibaba OWNER foxy_alibaba;
SQL
```

**Prove the isolation before going further** — this must FAIL:

```bash
docker exec -i foxy-prod-db-1 \
  psql "postgresql://foxy_alibaba:$PW@localhost/foxy" \
  -c "SELECT count(*) FROM organizations"
# EXPECT: ERROR: permission denied for table organizations
```

If that returns a number instead of an error, **stop and fix the roles.**

✅ Migrations need no superuser: `pgcrypto` is a *trusted* extension in PG13+ so
a database owner can create it, and migration 0021's `CREATE ROLE` is guarded by
an `IF NOT EXISTS` check.

---

## Step 3 · Secrets and the env file

The directory already exists from Step 2. `db_password` is already in it.

```bash
cd ~/foxy-alibaba-secrets
openssl rand -hex 32   > session
openssl rand -hex 32   > staff_session
openssl rand -hex 32   > api_pepper
openssl rand -hex 24   > staff_password    # the ops-console login, used in Step 6
# A valid Fernet key — its OWN, never production's. crypto_secrets.py uses
# MultiFernet, so a merge-back appends this key to prod's list rather than
# copying prod's crown jewel to a second place.
python3 -c "import base64,os;print(base64.urlsafe_b64encode(os.urandom(32)).decode())" > kek
chmod 600 *
```

Now write `deploy/.env.alibaba`. **`QWEN_API_KEY` is your Alibaba Cloud Model
Studio key — it is required, and it is never committed.**

```bash
cd /home/devops/foxy-audit-alibaba/deploy
cat > .env.alibaba <<ENVEOF
DATABASE_URL=postgresql+psycopg://foxy_alibaba:$(cat ~/foxy-alibaba-secrets/db_password)@db:5432/foxy_alibaba
DB_APP_ROLE=foxy_app_alibaba
SESSION_SECRET=$(cat ~/foxy-alibaba-secrets/session)
STAFF_SESSION_SECRET=$(cat ~/foxy-alibaba-secrets/staff_session)
API_KEY_PEPPER=$(cat ~/foxy-alibaba-secrets/api_pepper)
PROVIDER_KEY_ENCRYPTION_KEY=$(cat ~/foxy-alibaba-secrets/kek)

# ── Alibaba Cloud Model Studio — the submission's Alibaba usage ──
QWEN_API_KEY=PASTE_YOUR_MODEL_STUDIO_KEY_HERE
ENVEOF
chmod 600 .env.alibaba
```

Then edit `.env.alibaba` and paste the real key in place of the placeholder.

✅ **Everything else is deliberately left to the compose file's defaults** — Brevo
blank so this stack cannot email real customers, Paddle blank and sandbox,
anchoring off, and `DEMO_APPROVAL_REQUIRED=false` so a judge who signs up is not
stuck in a queue. Read the comments in `docker-compose.alibaba.yml` before
overriding any of them.

🔴 **`QWEN_API_KEY` here is NOT, by itself, enough to make Qwen grade anything.**
This is the single easiest way to end up with a live deployment that quietly
demonstrates nothing, so it is worth stating flatly:

- `org_policies.judge_provider` has server default **`gemini`** and
  `judge_key_mode` has server default **`own`** (`models.py:526`). A freshly
  seeded org is therefore configured for *Gemini, on its own BYOK key* — and it
  has no Gemini key, so grading returns `evaluator_unavailable`.
- Setting `judge_key_mode="platform"` does **not** rescue it either:
  `platform_keys_allowed` (`judge_routing.py:199`) gates on tier *and* on
  `entitlement_is_earned`, which a seeded `pro` org does not satisfy.

**Each org that should demonstrate the Alibaba judge must have its policy set
explicitly** — provider `qwen`, key mode `own`, and the Model Studio key stored
as that org's BYOK key. That is exactly what the verified demo does
(`demo/agentic_demo.py:1207`). **Step 6b** below does it.

⚠ `.env.alibaba` must never be committed. Confirm: `git check-ignore -v deploy/.env.alibaba`

---

## Step 4 · Build and start

```bash
cd /home/devops/foxy-audit-alibaba/deploy
docker compose -f docker-compose.alibaba.yml --env-file .env.alibaba up --build -d
docker compose -f docker-compose.alibaba.yml --env-file .env.alibaba ps
```

If `QWEN_API_KEY` is missing, compose **refuses to start** and says so. That is
deliberate — see the file header.

Confirm the API is up on its own port, and that the other two are untouched:

```bash
curl -sS localhost:8087/health/ready ; echo
ss -ltnp | grep -E '808[567]'    # expect all three, each on 127.0.0.1
```

Confirm Alembic reached the same head as the repo:

```bash
docker compose -f docker-compose.alibaba.yml --env-file .env.alibaba \
  run --rm foxy-migrate alembic current
# EXPECT: 0074 (head)
```

---

## Step 5 · 🔴 Grant the confined role — migrations DO NOT do this

**Do not skip this, and do not defer it.** Migration 0021 hardcodes
`ROLE = "foxy_app"` (`0021_confined_app_role.py:28`). Run against the
`foxy_alibaba` database it grants DML to **production's** `foxy_app` and creates
nothing for `foxy_app_alibaba` — which therefore exists with **zero
privileges**.

`auth._scope_org` issues `SET LOCAL ROLE foxy_app_alibaba` on every org-scoped
transaction. The `SET ROLE` succeeds (the login role is a member), and then every
statement fails `permission denied`. ⚠ **Seeding and `/health/ready` both pass
without touching this**, so the stack looks healthy and only breaks when a judge
logs in and loads the dashboard.

Grants are **per-database**, so everything below is confined to `foxy_alibaba`
and cannot reach production.

```bash
docker exec -i foxy-prod-db-1 psql -U foxy -d foxy_alibaba <<'SQL'
-- Mirror exactly what 0021 grants foxy_app, onto this stack's own role.
GRANT USAGE ON SCHEMA public TO foxy_app_alibaba;
GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA public TO foxy_app_alibaba;
GRANT USAGE, SELECT ON ALL SEQUENCES IN SCHEMA public TO foxy_app_alibaba;
ALTER DEFAULT PRIVILEGES IN SCHEMA public
  GRANT SELECT, INSERT, UPDATE, DELETE ON TABLES TO foxy_app_alibaba;
ALTER DEFAULT PRIVILEGES IN SCHEMA public
  GRANT USAGE, SELECT ON SEQUENCES TO foxy_app_alibaba;

-- Tidiness, not a live exposure: 0021 handed prod's foxy_app rights in THIS
-- database. foxy_app is NOLOGIN and foxy_alibaba is not a member of it, so
-- nothing can assume it here — but leaving it contradicts the isolation this
-- stack claims, so take it back.
REVOKE ALL ON ALL TABLES IN SCHEMA public FROM foxy_app;
REVOKE ALL ON ALL SEQUENCES IN SCHEMA public FROM foxy_app;
REVOKE USAGE ON SCHEMA public FROM foxy_app;
SQL
```

**Verify the role can actually read, under RLS** — this must return a number,
not an error:

```bash
docker exec -i foxy-prod-db-1 psql -U foxy -d foxy_alibaba -c \
  "SET ROLE foxy_app_alibaba; SELECT count(*) FROM organizations;"
```

⚠ If a later `alembic upgrade` adds tables, re-run the two `GRANT ... ON ALL`
lines. The `ALTER DEFAULT PRIVILEGES` above covers tables created by the
migration superuser, which is the normal path.

---

## Step 6 · Seed the accounts a judge will use

```bash
cd /home/devops/foxy-audit-alibaba/deploy
CMP="docker compose -f docker-compose.alibaba.yml --env-file .env.alibaba"

# Five judge logins, 20,000 credits each, pro tier. Idempotent + self-healing.
$CMP exec foxy-backend python scripts/seed_judges.py

# The staff ops console superadmin (first one only; guarded against re-use).
$CMP exec foxy-backend python scripts/seed_staff.py \
  --email alikamran1223@gmail.com --password "$(cat ~/foxy-alibaba-secrets/staff_password)"
```

`seed_judges.py` prints each API key **once**, on first creation only. Capture
that output. (`staff_password` was generated in Step 3.)

---

## Step 6b · 🔴 Point every judge org at the Alibaba Cloud judge

Without this the deployment demonstrates **nothing** — see the red block in
Step 3. Each org needs `judge_provider="qwen"`, `judge_key_mode="own"`, and the
Model Studio key stored as that org's BYOK key, encrypted with this stack's KEK.

This uses the app's own `crypto_secrets.encrypt_secret`, the same path
`PUT /v1/policies` uses — it is not a second encryption scheme.

```bash
cd /home/devops/foxy-audit-alibaba/deploy
CMP="docker compose -f docker-compose.alibaba.yml --env-file .env.alibaba"

$CMP exec foxy-backend python - <<'PY'
import os
from sqlalchemy import select
from app.db import SessionLocal
from app.models import Organization, OrgPolicy
from app.crypto_secrets import encrypt_secret

key = os.environ["QWEN_API_KEY"]          # the platform key, from .env.alibaba
db = SessionLocal()
for org in db.execute(select(Organization)).scalars():
    pol = db.execute(
        select(OrgPolicy).where(OrgPolicy.org_id == org.id)
    ).scalar_one_or_none()
    if pol is None:
        pol = OrgPolicy(org_id=org.id)
        db.add(pol)
    pol.judge_provider = "qwen"
    pol.judge_key_mode = "own"            # BYOK: this org's own stored key
    pol.qwen_key_enc = encrypt_secret(key, org.id, "qwen")
    print(f"  {org.name}: judge_provider=qwen, qwen key stored")
db.commit()
db.close()
PY
```

⚠ `judge_provider` is `String(16)` and the CHECK constraint from migration 0073
allows `gemini`, `openai`, `qwen`, `gemini+openai`, `gemini+qwen`, `openai+qwen`
and `all`. Anything else raises an IntegrityError rather than being stored.

⚠ Re-run this after seeding any NEW org, including one a judge creates by
signing up — a self-signed-up org gets the `gemini` default and will grade
`evaluator_unavailable` until pointed at Qwen.

---

## Step 7 · nginx vhosts — HTTP first, TLS second

⚠ **Never open `sites-available/foxyaudit.conf`.** On 2026-08-13 copying the
repo template over the live file discarded every TLS block and took HTTPS down
on all four production vhosts — and `nginx -t` **passed** on the result.

```bash
cd /home/devops/foxy-audit-alibaba
sudo cp deploy/nginx-foxyaudit-alibaba.conf \
        /etc/nginx/sites-available/foxyaudit-alibaba.conf
sudo ln -s /etc/nginx/sites-available/foxyaudit-alibaba.conf /etc/nginx/sites-enabled/
sudo nginx -t && sudo systemctl reload nginx
```

Verify over **HTTP** before asking certbot for anything:

```bash
curl -sS -o /dev/null -w "%{http_code}\n" http://app-alibaba-submission.foxyaudit.tech/
# EXPECT: 302  (→ /dashboard)
```

⚠ A **wildcard DNS record** exists, so a mistyped hostname serves a registrar
parking page instead of failing. If you get something odd, check the spelling
before debugging nginx.

Then, and only then, TLS — **these three names alone**:

```bash
sudo certbot --nginx \
  -d app-alibaba-submission.foxyaudit.tech \
  -d admin-alibaba-submission.foxyaudit.tech \
  -d checkout-alibaba-submission.foxyaudit.tech
```

🔴 **Do not add the production names or the dev2 names to that certbot run.**
They are on their own certificates and must stay there.

---

## Step 8 · Verify — what a judge will actually see

```bash
for h in app-alibaba-submission admin-alibaba-submission checkout-alibaba-submission; do
  printf "%-34s " "$h"
  curl -sS -o /dev/null -w "HTTP %{http_code}\n" "https://$h.foxyaudit.tech/"
done
```

Expect `302` · `302` · `200`.

**Then log in as a judge would**, at
`https://app-alibaba-submission.foxyaudit.tech/` with `judge1@foxyaudit.tech` /
`Foxy-Judge-2026`, and confirm the dashboard renders.

**Confirm the Alibaba Cloud judge is the one grading** — this is the submission's
whole claim, so verify it rather than assuming:

```bash
$CMP logs foxy-worker --tail 50 | grep -i qwen
$CMP exec foxy-backend python -c \
  "from app.db import SessionLocal; from sqlalchemy import text; \
   s=SessionLocal(); print(s.execute(text('SELECT judge_provider, count(*) FROM audit_logs GROUP BY 1')).all())"
```

⚠ `URLError` in the logs means **transport, not a bad key** — a real auth
failure is `HTTPError 401`. Test the endpoint directly:

```bash
docker run --rm curlimages/curl:latest -sS -o /dev/null -w "HTTP %{http_code}\n" \
  https://dashscope-intl.aliyuncs.com/compatible-mode/v1/models
# HTTP 401 = reachable and clear.  HTTP 000 = something is intercepting TLS.
```

---

## Step 9 · Confirm production never moved

```bash
for h in foxyaudit.tech www.foxyaudit.tech app.foxyaudit.tech \
         admin.foxyaudit.tech checkout.foxyaudit.tech; do
  printf "%-28s " "$h"
  curl -sS -o /dev/null -w "HTTP %{http_code} %{size_download}b\n" "https://$h"
done > ~/foxy-baseline-alibaba-after.txt

diff ~/foxy-baseline-alibaba-before.txt ~/foxy-baseline-alibaba-after.txt && echo "PRODUCTION UNCHANGED"
```

Also re-check that production's certificate expiry is the same value you
recorded in Step 0 — that proves certbot never touched it.

---

## Rollback (complete, at any point)

```bash
cd /home/devops/foxy-audit-alibaba/deploy
docker compose -f docker-compose.alibaba.yml --env-file .env.alibaba down
sudo rm -f /etc/nginx/sites-enabled/foxyaudit-alibaba.conf
sudo nginx -t && sudo systemctl reload nginx
```

Production is untouched by all of the above.

---

## 🔴 Teardown, after judging

A parallel stack left running is a second attack surface and a second thing to
patch. In this order:

1. `docker compose -f docker-compose.alibaba.yml --env-file .env.alibaba down -v`
   (the `-v` drops `foxy-alibaba_foxy_alibaba_avatars` — export anything wanted first)
2. `sudo rm /etc/nginx/sites-enabled/foxyaudit-alibaba.conf && sudo nginx -t && sudo systemctl reload nginx`
3. `sudo certbot delete --cert-name app-alibaba-submission.foxyaudit.tech`
4. `DROP DATABASE foxy_alibaba;` then `DROP ROLE foxy_alibaba; DROP ROLE foxy_app_alibaba;`
5. Remove the three DNS records at get.tech
6. `rm -rf /home/devops/foxy-audit-alibaba ~/foxy-alibaba-secrets`
7. **Rotate `QWEN_API_KEY`** — it will have been in at least three places

⚠ **Do NOT remove the swap file.** It predates this exercise and should be there
regardless.
