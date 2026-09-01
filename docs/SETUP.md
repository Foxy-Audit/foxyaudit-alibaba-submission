# SETUP — a working machine from a fresh clone

Everything here is **machine-local**: nothing in the repo creates it, and no
test will tell you it is missing until a count comes out wrong. Verified on
Windows against `1007a02`, 2026-08-30; re-verified on a second Windows machine
against `8498ce0`, 2026-09-01, which is where §2's last two notes and §4's third
come from.

---

## 1 · PostgreSQL — the one non-obvious step

The integration suite needs a **real PostgreSQL on port `5433`** (not the
default 5432) with a **superuser** role. `conftest` only runs
`alembic upgrade head` into it; it does not create the server, the role or the
database.

```
server    PostgreSQL 16+          (18.4 on the reference machine)
port      5433
role      foxy / foxy             SUPERUSER — required
database  foxy_pytest
```

Create it once:

```sql
CREATE ROLE foxy WITH LOGIN SUPERUSER PASSWORD 'foxy';
CREATE DATABASE foxy_pytest OWNER foxy;
```

> **Why superuser.** `conftest` resets state with
> `TRUNCATE … RESTART IDENTITY CASCADE` across every table. Row-level security
> is enabled and FORCEd on eighteen of them, so a confined role cannot clear
> other orgs' rows and the reset silently under-deletes.

Run the suite:

```bash
cd backend
DATABASE_URL=postgresql+psycopg://foxy:foxy@localhost:5433/foxy_pytest \
  python -m pytest tests/integration -q
```

### ⚠ One suite at a time

That `TRUNCATE` is why **two concurrent runs corrupt each other and deadlock.**
Before a full run:

```sql
SELECT pid, state, pg_blocking_pids(pid), left(query,60)
FROM pg_stat_activity WHERE datname='foxy_pytest';
```

* one row (yours) → go
* `idle in transaction` older than two minutes → a stray;
  `SELECT pg_terminate_backend(<pid>);` is the right fix
* two **active** runs blocking each other → contention, not a stray. Terminating
  anything just moves the wedge; stop one run instead.

---

## 2 · Toolchain

| need | for | absent means |
|---|---|---|
| Python 3.13 | everything | — |
| venv from `backend/requirements.txt` + `pytest httpx==0.28.1` | backend suite | — |
| PyQt6 | `desktop/` | suite cannot run |
| Node | `node --check` on inline `<script>` blocks | a syntax error ships |
| **Chrome** | the rendered dashboard guards | **they skip silently** |
| **Git Bash before `system32` on PATH** | the timezone-independence guards | **they skip silently** |
| `gh` (+ `gh auth login`) | checking CI before merging | — |
| Docker | the Linux desktop repro only | — |

**Chrome matters more than it looks.** The R4 and #228 guards drive the shipped
page in headless Chrome and read the DOM back. They once caught a CSS comment
that closed early — balanced braces, green `node --check`, green suite, and a
chip shipping at 1.21:1 contrast. Only the browser saw it.

**Check the installed versions, not just that `pip install -r` ran.** On a
machine that otherwise looked complete, two of `backend/requirements.txt`'s
twenty pins were wrong: `python-multipart` was **absent** and `pillow` was
12.0.0 against a 12.3.0 pin. The first is not a test failure — the avatar route
in `routers/account.py` needs it at import time, so the whole suite dies at
collection with `RuntimeError: Form data requires "python-multipart"` and no
count is produced at all.

**Which `bash` wins is part of the gate.** `shutil.which("bash")` finds
`C:\Windows\system32\bash.EXE` — the WSL launcher — ahead of Git Bash on any
Windows box where WSL is present but unprovisioned. The four
`test_timezone_independence.py` guards then **skip**, with *"bash on PATH but
not usable"*, and the backend reads **1563 passed / 7 skipped** where it should
read 1567 / 3. Put Git Bash first for the run:

```powershell
$env:PATH = "C:\Program Files\Git\bin;$env:PATH"
```

Not permanently: that directory also ships `find.exe` and `sort.exe`, which
shadow the Windows ones and break unrelated scripts. `test_skip_inventory.py`
declares this site as `NEITHER` — "false in CI and on a dev machine" — which
this machine disproves; the registry checks that a declaration exists, not that
it is true.

---

## 3 · Expected counts at `1007a02`

Always quote the SHA with a count. These move whenever `main` does.

| suite | command | expected |
|---|---|---|
| backend | `pytest tests/integration -q` (from `backend/`) | **1567 passed / 3 skipped** |
| verifier | `pytest verifier -q` | **90** |
| dashboard | `pytest foxy-dashboard -q` | **558** |
| desktop | `pytest desktop -q` | **979 passed / 1 failed** |
| SDK | `pytest sdk/tests -q` | **983** |
| SDK (all) | `pytest sdk -q` | **1465** — write the path you used |
| migrations | `alembic heads` | single head **0070** |

**The desktop's 1 failure is expected**: `test_d14_packaging::test_the_release_
workflow_never_runs_on_a_plain_commit`. It is a pending *decision* about whether
manual-only release is permanent, not a defect. It skips in CI, which has no
PyYAML.

---

## 4 · Differences that are correct, not broken

**weasyprint does not work on Windows** — it binds to pango/cairo/gdk-pixbuf and
raises `OSError: cannot load library … libgobject-2.0-0.dll`. That is *why*
`test_passport_render::test_a_broken_renderer_returns_500_not_html_with_a_200`
runs locally and **skips in CI**. On a machine with working GTK your count
differs by one and that is right. `test_skip_inventory.py` pins every skip site
and fails if an undeclared one appears.

**Three `test_account.py` quota tests fail for the first hours of a month.**
The one entry in this section that is genuinely broken rather than merely
different — but it is filed as #30 and predates you, so do not chase it.
`/v1/usage` takes `date.today()`, which is server-**local**, and stamps that
date with `tzinfo=timezone.utc`; east of UTC the month boundary then sits in the
future and `used_this_month` reads 0. At `Asia/Karachi` the window is local
midnight to 05:00 on the 1st, where the count reads **1564 passed / 3 failed**
— and 1564 + 3 is the expected 1567. Latent in production, which runs UTC, and
it fails open.

**The Postgres session timezone is deliberately unpinned.** CI runs
`America/Los_Angeles`; the reference machine ran `Asia/Karachi`. Four
timezone-independence guards exist precisely to catch UTC-blind bucketing, and
they become self-fulfilling on a UTC machine. Do not "fix" this by pinning it.

---

## 5 · Before you push

`main` is deployed by pulling it, so treat it as production for the dev stack.

```bash
git fetch origin
git merge-base --is-ancestor origin/main <sha>   # fast-forward-safe
gh run list --branch main --limit 1              # the PREVIOUS merge must be green
```

Checking CI **before** writing the next change is not optional: four consecutive
merges once rode on top of a red `main` because only local suites were read.
