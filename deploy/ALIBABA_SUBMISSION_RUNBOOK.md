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

Also confirm swap exists — the box runs four businesses' containers and a
docker build spikes:

```bash
free -h   # expect ~2Gi swap. If 0, STOP and add it before building.
```

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
# Pick a strong password and keep it — you need it in Step 3.
PW=$(openssl rand -base64 24)
echo "$PW" | tee ~/foxy-alibaba-secrets/db_password   # create the dir first, see Step 3

docker exec -i foxy-prod-db-1 psql -U foxy -d postgres <<SQL
CREATE ROLE foxy_alibaba LOGIN PASSWORD '$PW' BYPASSRLS;
CREATE ROLE foxy_app_alibaba NOLOGIN;
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

```bash
mkdir -p ~/foxy-alibaba-secrets && chmod 700 ~/foxy-alibaba-secrets
cd ~/foxy-alibaba-secrets
openssl rand -hex 32   > session
openssl rand -hex 32   > staff_session
openssl rand -hex 32   > api_pepper
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

✅ **Everything else is deliberately left to the compose file's defaults** —
Gemini/OpenAI blank so routing goes to Qwen, Brevo blank so this stack cannot
email real customers, Paddle blank and sandbox, anchoring off, and
`DEMO_APPROVAL_REQUIRED=false` so a judge who signs up is not stuck in a queue.
Read the comments in `docker-compose.alibaba.yml` before overriding any of them.

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

## Step 5 · Seed the accounts a judge will use

```bash
cd /home/devops/foxy-audit-alibaba/deploy
CMP="docker compose -f docker-compose.alibaba.yml --env-file .env.alibaba"

# Five judge logins, 20,000 credits each, pro tier. Idempotent + self-healing.
$CMP exec foxy-backend python scripts/seed_judges.py

# The staff ops console superadmin (first one only; guarded against re-use).
$CMP exec foxy-backend python scripts/seed_staff.py \
  --email alikamran1223@gmail.com --password "$(cat ~/foxy-alibaba-secrets/staff_password)"
```

Create `staff_password` first (`openssl rand -base64 24 > ~/foxy-alibaba-secrets/staff_password && chmod 600 $_`).

`seed_judges.py` prints each API key **once**, on first creation only. Capture
that output.

---

## Step 6 · nginx vhosts — HTTP first, TLS second

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

## Step 7 · Verify — what a judge will actually see

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

## Step 8 · Confirm production never moved

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
