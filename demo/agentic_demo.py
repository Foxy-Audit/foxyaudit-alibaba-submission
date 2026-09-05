#!/usr/bin/env python3
"""The agentic loop, end to end, in eight beats — the demo that is also the video.

    python demo/agentic_demo.py                 # all eight, against a fresh stack
    python demo/agentic_demo.py --beats 6       # re-record ONE beat, stack as-is
    python demo/agentic_demo.py --beats 3-6 --pause

Phase A3. One runnable script that produces the whole submission narrative IN
ORDER, so the video is a screen recording of a real run rather than a slideshow:

    1 GUARD     PHI under `hipaa`, mode="block" — stopped BEFORE the model call
    2 CLEAN     an ordinary prompt — allowed, graded `clean` by the AI judge
    3 ESCALATE  the ambiguous case — Qwen calls flag_for_human_review
    4 QUEUE     it appears in GET /v1/reviews; the count goes 0 -> 1
    5 HUMAN     a person resolves it `cleared` — and the chained row does NOT move
    6 FINALE    the SAME shape again — Qwen calls check_prior_reviews and grades
                `clean` instead of escalating. The agent escalated, a human ruled,
                the agent learned.
    7 VERIFY    export the ledger, recompute it with the dependency-free verifier
    8 TAMPER    alter one byte, re-verify, watch it fail at the right sequence

⚠ NOTHING HERE IS SIMULATED. There is no canned Qwen response anywhere in this
file and there must never be one. If the key is missing or dashscope is
unreachable, beats 3-6 report THE JUDGE IS UNAVAILABLE and are skipped, and the
run still does 1, 2, 7 and 8 honestly. The product's whole thesis is that you can
check the evidence instead of trusting the vendor; a faked demo of tamper-evidence
would be the one unrecoverable mistake.

RUNS LOCALLY, against `docker compose`, never the VM — because the claim in the
video is "you can run this yourself", and a judge can only run the local one.
`docker-compose.prod.yml` is never read, written or referenced.

WHERE THE PLUMBING COMES FROM. `e2e/run_e2e.py` already solves the hard parts —
bringing the stack up, waiting on /health/ready rather than on a sleep, scraping
the one-time seed key, building ./sdk into an isolated venv — and this imports
them rather than growing a second stack driver that would drift from the first.
What is new here is only the agentic loop, which run_e2e.py does not touch at all.

THE KEY. `QWEN_API_KEY` is read from `backend/.env` (gitignored) or the
environment, and is stored through PUT /v1/policies as an ordinary BYOK key —
encrypted at rest, exactly as a customer's would be. It is never printed, never
written to an artifact, and never reaches a committed file.
"""

from __future__ import annotations

import argparse
import base64
import json
import os
import secrets
import string
import subprocess
import sys
import time

HERE = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.dirname(HERE)
E2E_DIR = os.path.join(REPO, "e2e")

# The stack driver is e2e/run_e2e.py's, not a copy of it. `e2e/` has no
# __init__.py — it is a directory of scripts, not a package — so the path goes on
# sys.path and the module is imported by name.
sys.path.insert(0, E2E_DIR)
import run_e2e as e2e                                            # noqa: E402

BASE_URL = e2e.BASE_URL
SEED_EMAIL = e2e.SEED_EMAIL
SEED_PASSWORD = e2e.SEED_PASSWORD
VERIFIER = os.path.join(REPO, "verifier", "foxy_verify.py")

#: Artifacts live under e2e/.artifacts/ because that path is ALREADY gitignored
#: and already holds the shared venv. `demo/.artifacts/` is not ignored, and a
#: demo that drops an export bundle into a tracked directory is one `git add -A`
#: away from committing a ledger.
ART = os.path.join(e2e.ARTIFACTS, "agentic")

#: One KEK for the demo stack, generated once and kept, NOT regenerated per run.
#: The Qwen key is stored encrypted under it, so a per-run KEK would make every
#: `--reuse-stack` run — which is every re-recording of a single beat — unable to
#: decrypt the key the previous run stored. Gitignored, dev-only, never deployed.
KEK_PATH = os.path.join(ART, "kek")
COMPOSE_OVERRIDE = os.path.join(ART, "compose.demo.yml")

#: OPTIONAL, and only some machines need it. If a PEM bundle is sitting here, it
#: is mounted into the backend and the worker as their `SSL_CERT_FILE`.
#:
#: Why this exists: corporate and consumer TLS interception (on the machine this
#: was written on, Norton's "Web/Mail Shield") re-signs every HTTPS connection
#: with a root the CONTAINER has never heard of. The host is fine — Windows
#: trusts it — so the failure shows up only inside Docker, as
#: `qwen evaluate failed (URLError)` and a row that quietly falls back to the
#: deterministic grade. That is a local environment condition, not a repo
#: problem, so the fix does not belong in the committed compose or Dockerfile —
#: exactly the line `e2e/README.md` already draws for the same interception
#: breaking `pip` inside `up --build`. A gitignored file the demo picks up if it
#: is there keeps it out of the repo and out of everyone else's way.
CA_BUNDLE = os.path.join(ART, "ca-bundle.pem")
CA_MOUNT = "/etc/foxy-demo-ca.pem"

#: ⚠ MEASURED, AND THE SPELLING IS NOT A FREE CHOICE. What makes beat 3 escalate
#: is a policy_tag naming a regulated context while `pii_signals` is EMPTY: the
#: local guard found nothing, so a reviewer who can see the content might still
#: find something, and that gap is the criterion `qwen_judge` states. A payload
#: carrying obvious PII grades `breach` at ~95 instead and never reaches a human,
#: so it is deliberately NOT used here.
#:
#: ⚠ AND IT IS `phi_restricted`, NOT `phi-restricted`. The live A5 measurement
#: used the hyphen, but the LEDGER's charset is `^[a-z0-9_]{1,32}$`
#: (`schemas.py`, mirrored at `client._POLICY_RE`), so the SDK's decorator would
#: quietly substitute `default` for a hyphenated tag and this beat would be
#: showing a different story under the same name. The underscore is the closest
#: spelling the wire can actually carry, and it reads as the same regulated
#: healthcare context to the model. Verified live before this file was committed.
POLICY_TAG = "phi_restricted"

#: How long to wait for the worker to move a row off `pending`. Generous on
#: purpose: with A5 a Qwen grade can take TWO round trips (`qwen_timeout` is 12s
#: each) and the worker polls on `grading_poll_interval`. Never a sleep of a
#: guessed length — a bounded poll with a visible clock.
GRADING_TIMEOUT = 240.0

#: Read-only, derived fields on GET /v1/policies that PUT /v1/policies refuses.
#: Building the PUT body by subtraction rather than by enumeration, so a field
#: added to the policy model tomorrow is carried through instead of silently
#: reset to its default by a body that never mentioned it.
POLICY_READ_ONLY = ("gemini_key_set", "openai_key_set", "qwen_key_set",
                    "plan_tier", "platform_keys_allowed",
                    "judge_models", "judge_models_available")


# ──────────────────────────── the screen ─────────────────────────────────────
def _tty() -> bool:
    try:
        return sys.stdout.isatty()
    except Exception:                                            # noqa: BLE001
        return False


def banner(n: int, title: str, blurb: str) -> None:
    """A beat's boundary, and it is load-bearing rather than decoration: the
    owner records every beat and cuts in editing, so each one has to START at an
    unmistakable frame."""
    bar = "═" * 74
    print(f"\n\n╔{bar}╗")
    print(("║  BEAT %d · %s" % (n, title)).ljust(75) + "║")
    print(("║  " + blurb).ljust(75) + "║")
    print(f"╚{bar}╝", flush=True)


def say(text: str = "") -> None:
    print("   " + text if text else "", flush=True)


def field(label: str, value) -> None:
    print(f"   {label:<22} {value}", flush=True)


def note(text: str) -> None:
    print(f"\n   → {text}", flush=True)


def waiting(text: str) -> None:
    """One line that updates in place on a terminal, one line per second-ish
    elsewhere. A recording wants a live clock; a piped log wants readable text."""
    if _tty():
        sys.stdout.write("\r   … " + text + " " * 12)
        sys.stdout.flush()
    else:
        print("   … " + text, flush=True)


def waiting_done() -> None:
    if _tty():
        sys.stdout.write("\r" + " " * 78 + "\r")
        sys.stdout.flush()


# ─────────────────────────── the ingredients ─────────────────────────────────
def read_qwen_key() -> str:
    """The key, from the environment or from `backend/.env`. NEVER RETURNED TO
    THE SCREEN by any caller — it goes straight into the PUT body."""
    key = (os.environ.get("QWEN_API_KEY") or "").strip()
    if key:
        return key
    env_path = os.path.join(REPO, "backend", ".env")
    if not os.path.isfile(env_path):
        return ""
    with open(env_path, encoding="utf-8") as fh:
        for line in fh:
            line = line.strip()
            if line.startswith("QWEN_API_KEY="):
                return line.split("=", 1)[1].strip().strip('"').strip("'")
    return ""


def scrubbed(text: str, secret: str) -> str:
    """`text` with the key removed.

    ⚠ NOT PARANOIA. A 422 out of `PUT /v1/policies` is a Pydantic error body, and
    Pydantic error bodies quote the INPUT that failed validation — so a key one
    character too long would put itself on screen, into `summary.json`, and into
    whatever terminal recording was running at the time. Every response body this
    script prints or stores goes through here first.
    """
    if not secret or not text:
        return text
    return text.replace(secret, "<QWEN_API_KEY redacted>")


def kek() -> str:
    """The demo stack's key-encryption key: generated on first use, then kept.

    The committed compose passes no PROVIDER_KEY_ENCRYPTION_KEY, so the stack AS
    SHIPPED cannot store a BYOK key at all — PUT /v1/policies 503s. This adds one
    through a run-scoped override file that never touches the committed compose.
    """
    os.makedirs(ART, exist_ok=True)
    if not os.path.isfile(KEK_PATH):
        with open(KEK_PATH, "w", encoding="utf-8") as fh:
            fh.write(base64.urlsafe_b64encode(os.urandom(32)).decode())
        os.chmod(KEK_PATH, 0o600)
    with open(KEK_PATH, encoding="utf-8") as fh:
        return fh.read().strip()


def compose_override() -> str:
    """Write the override that carries the KEK — and, if one is sitting in the
    artifacts directory, a CA bundle — into the backend and the worker."""
    # Forward slashes even on Windows: compose reads this as a bind-mount source
    # and a backslash path in YAML is a quoting problem waiting to happen.
    ca = CA_BUNDLE.replace("\\", "/") if os.path.isfile(CA_BUNDLE) else None
    with open(COMPOSE_OVERRIDE, "w", encoding="utf-8") as fh:
        fh.write("# Generated by demo/agentic_demo.py. Gitignored, dev-only.\n"
                 "# NOT docker-compose.prod.yml, which this demo never touches.\n"
                 "services:\n")
        for svc in ("foxy-backend", "foxy-worker"):
            fh.write(f"  {svc}:\n    environment:\n"
                     f"      - PROVIDER_KEY_ENCRYPTION_KEY={kek()}\n")
            if ca:
                fh.write(f"      - SSL_CERT_FILE={CA_MOUNT}\n"
                         f"      - REQUESTS_CA_BUNDLE={CA_MOUNT}\n"
                         f"    volumes:\n      - {ca}:{CA_MOUNT}:ro\n")
    return COMPOSE_OVERRIDE


def token() -> str:
    """A per-run marker for agent names. LETTERS ONLY — a digit run can trip the
    SDK's own card-number detector and change the very decision on display."""
    return "".join(secrets.choice(string.ascii_lowercase) for _ in range(6))


def parse_beats(spec: str) -> list[int]:
    """`1,2,3` · `3-6` · `2,5-8`. The flag that saves the recording session."""
    if not spec:
        return list(range(1, 9))
    out: set[int] = set()
    for part in spec.replace(" ", "").split(","):
        if not part:
            continue
        if "-" in part:
            lo, hi = part.split("-", 1)
            out.update(range(int(lo), int(hi) + 1))
        else:
            out.add(int(part))
    bad = sorted(b for b in out if not 1 <= b <= 8)
    if bad:
        raise SystemExit(f"no such beat: {bad} — the beats are 1..8")
    return sorted(out)


# ────────────────────────── talking to the stack ─────────────────────────────
def wait_for_grade(ctx: dict, seq: int, what: str) -> dict:
    """Poll one ledger row until the worker has finished with it.

    ⚠ A BOUNDED POLL ON THE ROW'S OWN SEQ, not a sleep and not a page scan. The
    worker grades asynchronously; a guessed interval is how a demo becomes flaky
    on the one machine that matters, and `/v1/logs?limit=200` would start missing
    rows on a stack that has been re-recorded into a few hundred events.
    """
    import requests
    t0 = time.time()
    last = "<no row yet>"
    while time.time() - t0 < GRADING_TIMEOUT:
        r = requests.get(f"{BASE_URL}/v1/logs/{seq}", headers=ctx["headers"], timeout=30)
        if r.status_code == 200:
            row = r.json()
            last = row.get("grading_status")
            if last in ("graded", "failed"):
                waiting_done()
                say(f"the worker finished with seq {seq} in {time.time() - t0:.1f}s "
                    f"(status: {last})")
                return row
        waiting(f"waiting for {what}… {time.time() - t0:4.1f}s   (seq {seq}: {last})")
        time.sleep(0.5)
    waiting_done()
    raise e2e.Fatal(f"seq {seq} never left '{last}' within {GRADING_TIMEOUT:.0f}s. "
                    f"The worker may be down: `docker compose -f backend/"
                    f"docker-compose.yml logs foxy-worker`.")


def verdict_of(row: dict) -> dict:
    """The AI judge's verdict as the customer API returns it."""
    return row.get("gemini_verdict") or {}


def show_verdict(row: dict) -> dict:
    v = verdict_of(row)
    field("decision", v.get("decision"))
    field("risk score", v.get("risk_score"))
    field("policy breach", v.get("policy_breach"))
    field("graded by", f"{v.get('graded_by')}  ·  provider={v.get('judge_provider')}"
                       f"  ·  model={v.get('judge_model')}")
    field("reason", v.get("reason"))
    return v


def prior_reviews(ctx: dict) -> dict:
    """The same counts `check_prior_reviews` answers with — so the script can SAY
    what state it is starting from instead of silently showing a different story.

    ⚠ READ THROUGH `GET /v1/reviews`, NOT THROUGH psql, AND THE REASON IS
    SCOPING. `psql` here runs as the compose superuser, which bypasses RLS, and
    `docker compose up` mints another "Demo Corp" every time it runs against a
    kept volume — so a SQL count would silently pool several workspaces' reviews
    into one number on any machine that has run the stack more than once. The
    endpoint is scoped to the reviewer's session by construction.

    ⚠ AND IT IS NOT WINDOWED. `check_prior_reviews` counts the last
    `PRIOR_REVIEW_WINDOW_DAYS`; this counts everything the queue holds. On a demo
    stack those are the same set, and where they could differ this OVER-reports —
    which fails towards warning about contamination, never towards hiding it.
    """
    import requests
    r = requests.get(f"{BASE_URL}/v1/reviews?limit=200",
                     cookies=ctx["session"].cookies, timeout=30)
    if r.status_code != 200:
        return {"escalations": 0, "cleared": 0}
    mine = [i for i in r.json().get("items", []) if i.get("policy_tag") == POLICY_TAG]
    return {"escalations": len(mine),
            "pending": len([i for i in mine if i.get("status") == "pending"]),
            "cleared": len([i for i in mine if i.get("resolution") == "cleared"])}


def chain_hash_of(ctx: dict, seq: int) -> str:
    """This row's chain hash, as the customer API serves it.

    `seq` is per-ORG, so a `WHERE seq = n` against the database would match one
    row per workspace on a stack that has been seeded twice. The bearer key
    resolves exactly one.
    """
    import requests
    r = requests.get(f"{BASE_URL}/v1/logs/{seq}", headers=ctx["headers"], timeout=30)
    return (r.json().get("chain_hash") or "") if r.status_code == 200 else ""


def handoff_url(ctx: dict) -> str | None:
    """A ~2-minute single-use token that signs the browser in as this org's
    admin — the same path the desktop app uses, and the only one guaranteed to
    land on the SAME org the SDK just wrote to."""
    import requests
    r = requests.post(f"{BASE_URL}/v1/auth/handoff", headers=ctx["headers"], timeout=30)
    if r.status_code != 200:
        return None
    return f"{BASE_URL}/dashboard?handoff={r.json().get('token')}"


#: Run INSIDE the worker container, which is the process that actually calls the
#: provider — asking from the host would answer a different question, and on a
#: machine where the host trusts an interceptor and the container does not, it
#: would answer it wrongly and confidently.
#:
#: A TLS HANDSHAKE, NOT A REQUEST: no key leaves anything, no token is spent, and
#: the failure this is looking for is a certificate failure. The base URL is read
#: from the container's own settings so this cannot drift from what the judge
#: dials.
_REACH_PROBE = (
    "import ssl,socket\n"
    "from urllib.parse import urlparse\n"
    "from app.config import get_settings\n"
    "h=urlparse(get_settings().qwen_base_url).hostname\n"
    "try:\n"
    "    ssl.create_default_context().wrap_socket("
    "socket.create_connection((h,443),timeout=10),server_hostname=h).close()\n"
    "    print('REACHABLE '+h)\n"
    "except Exception as e:\n"
    "    print('UNREACHABLE '+h+' '+type(e).__name__+': '+str(e)[:120])\n"
)


def judge_reachable(ctx: dict) -> tuple[bool | None, str]:
    """Can the worker open a VERIFIED TLS connection to the provider?

    Three answers, and the third one matters. `True` and `False` are the probe's
    verdict; `None` means the probe itself did not run — a typo in it, an older
    image, a container that is not up — and that is NOT the same as "the provider
    is unreachable". The first draft returned False for all three and printed a
    confident paragraph about TLS interception over what was really its own
    ImportError. A diagnosis this script cannot support is worse than no
    diagnosis, so it now says which one it has.
    """
    proc = e2e.compose("exec", "-T", "foxy-worker", "python", "-c", _REACH_PROBE,
                       check=False, timeout=90, files=ctx["files"])
    out = (proc.stdout or "").strip().splitlines()
    line = next((x for x in out if x.startswith(("REACHABLE", "UNREACHABLE"))), "")
    if line.startswith("REACHABLE"):
        return True, line
    if line:
        return False, line
    detail = ((proc.stderr or "") + (proc.stdout or "")).strip().splitlines()
    return None, ("the reachability probe did not run: "
                  + (detail[-1] if detail else "no output"))


# ───────────────────────────── the SDK client ────────────────────────────────
def sdk_client(ctx: dict):
    """One real FoxyClient, built from the wheel that `pip install ./sdk` produces.

    `audit_required=True` so every call blocks until the SERVER has receipted the
    event: a demo that raced its own ledger would be a demo of a race.
    """
    from foxy_audit import FoxyClient
    return FoxyClient(
        api_key=ctx["api_key"],
        endpoint=BASE_URL,
        desktop_ping=False,
        audit_required=True,
        spool_path=os.path.join(ctx["run_dir"], "spool.sqlite3"),
        timeout=30.0,
    )


def install_wire_capture(ctx: dict) -> None:
    """Capture every event at `dispatch.submit` — the single seam every event
    crosses on its way to the network.

    This is how beat 1 can show the payload VERBATIM rather than describing it.
    Reading it back from the ledger would prove only what was stored; this is
    what was sent, which is the claim content-blindness actually makes.
    """
    from foxy_audit import dispatch
    if getattr(dispatch.submit, "_foxy_demo_capture", False):
        return
    original = dispatch.submit

    def capturing(cfg, payload, wait=False):
        result = original(cfg, payload, wait=wait)
        seq = None
        for receipt in ((result or {}).get("receipts") or []):
            if str(receipt.get("event_id")) == str(payload.get("event_id")):
                seq = receipt.get("seq")
        ctx["wire"].append({"payload": payload, "seq": seq})
        return result

    capturing._foxy_demo_capture = True
    dispatch.submit = capturing


def last_wire(ctx: dict) -> dict:
    if not ctx["wire"]:
        raise e2e.Fatal("no event reached dispatch.submit — the SDK sent nothing")
    return ctx["wire"][-1]


# ═══════════════════════════════ THE BEATS ═══════════════════════════════════
def beat_1(ctx: dict) -> None:
    banner(1, "GUARD", "PHI under `hipaa` — stopped BEFORE the model is called")
    from foxy_audit.client import FoxyPolicyBlocked

    prompt = ("Patient intake for review: SSN 123-45-6789, DOB 1980-01-01, "
              "requesting a refill of her prescription.")
    calls = {"n": 0}

    # This is the customer's own model call. The decorator is the whole
    # integration — nothing else about their code changes.
    @ctx["client"].audit(policy="hipaa", agent=ctx["agents"]["guard"], mode="block")
    def ask_the_model(prompt: str) -> str:
        calls["n"] += 1
        return "THE MODEL RAN — the host-side guard did not stop this call"

    say("the prompt the application tried to send:")
    say(f'  "{prompt}"')
    say("")

    raised = None
    try:
        ask_the_model(prompt=prompt)
    except FoxyPolicyBlocked as exc:
        raised = str(exc)

    ctx["ck"].check("GUARD: FoxyPolicyBlocked was raised in the caller's process",
                    raised is not None, raised or "nothing was raised")
    ctx["ck"].check("GUARD: the model function ran ZERO times — no provider was "
                    "called, and nothing was billed", calls["n"] == 0,
                    f"model invocations = {calls['n']}")

    note("The check ran locally, before the network. No provider saw this prompt.")

    # ── content-blindness, SHOWN rather than asserted ─────────────────────────
    wire = last_wire(ctx)
    say("")
    say("What Foxy received — the event VERBATIM, captured at dispatch.submit,")
    say("the one seam every event crosses on its way to the wire:")
    say("")
    for line in json.dumps(wire["payload"], indent=2, default=str).splitlines():
        print("     " + line, flush=True)
    say("")
    blob = json.dumps(wire["payload"], default=str)
    leaked = [needle for needle in ("123-45-6789", "1980-01-01", "prescription",
                                    "Patient intake")
              if needle in blob]
    ctx["ck"].check("CONTENT-BLINDNESS: not one word of the prompt is in what "
                    "went on the wire", not leaked, f"found: {leaked}")
    note("`prompt_hash` is a customer-keyed HMAC commitment, not text. "
         "Foxy cannot read it back.")
    ctx["seqs"]["guard"] = wire["seq"]


def beat_2(ctx: dict) -> None:
    banner(2, "CLEAN", "an ordinary prompt — allowed, and graded by the AI judge")

    prompt = "Summarise this quarter's compliance findings for the board pack."

    @ctx["client"].audit(policy="default", agent=ctx["agents"]["clean"], mode="observe")
    def ask_the_model(prompt: str) -> str:
        return "Three findings, all remediated; no open items carried forward."

    say(f'the prompt: "{prompt}"')
    ask_the_model(prompt=prompt)
    seq = last_wire(ctx)["seq"]
    ctx["seqs"]["clean"] = seq
    say(f"the guard allowed it; the event chained at seq {seq}")
    say("")

    row = wait_for_grade(ctx, seq, "the judge")
    say("")
    v = show_verdict(row)
    # ⚠ BELT AND BRACES WITH THE PRE-FLIGHT PROBE. The probe answers "can the
    # worker open a socket"; this answers "did a model actually grade this row",
    # which is the question, and it is the one a provider that accepts the
    # connection and then refuses the key would answer differently.
    if ctx["judge"] == "qwen" and v.get("judge_provider") is None:
        ctx["judge"] = None
        ctx["judge_note"] = ("the row came back graded by the worker's own "
                             "deterministic rules, so no provider was called")
        note("⚠ THE JUDGE IS UNAVAILABLE after all — " + ctx["judge_note"] + ".")
    ctx["ck"].check("CLEAN: the judge graded it `clean`", v.get("decision") == "clean",
                    f"{v.get('decision')} — {v.get('reason')}")
    if ctx["judge"] == "qwen":
        ctx["ck"].check("CLEAN: it was graded by Qwen, live",
                        v.get("judge_provider") == "qwen" and bool(v.get("judge_model")),
                        f"provider={v.get('judge_provider')} model={v.get('judge_model')}")
    else:
        note("THE JUDGE IS UNAVAILABLE, so this verdict is the worker's own "
             "deterministic metadata grade, not a model's. `judge_provider` is "
             "null above: no provider was called and nothing was billed.")


def beat_3(ctx: dict) -> None:
    banner(3, "ESCALATE", "the ambiguous case — the agent declines to decide alone")

    before = prior_reviews(ctx)
    ctx["pending_before"] = before
    if before["escalations"]:
        note(f"⚠ THIS IS NOT A CLEAN SLATE. {before['escalations']} escalation(s) of "
             f"`{POLICY_TAG}` already exist in this workspace, {before['cleared']} of "
             f"them cleared. A5's `check_prior_reviews` may legitimately stop the "
             f"escalation this beat is here to show. Re-run WITHOUT --reuse-stack "
             f"for the recorded take.")

    prompt = ("Draft the standard discharge-instruction template our care team "
              "sends after an outpatient procedure.")

    @ctx["client"].audit(policy=POLICY_TAG, agent=ctx["agents"]["escalate"],
                         mode="observe")
    def ask_the_model(prompt: str) -> str:
        return ("Follow-up in 7 days; call the clinic for fever above 38C or "
                "bleeding that does not stop with pressure.")

    say(f'the prompt: "{prompt}"')
    ask_the_model(prompt=prompt)
    seq = last_wire(ctx)["seq"]
    ctx["seqs"]["escalate"] = seq
    say("")
    say("This is what the judge is given. All of it. Nothing else exists to send:")
    payload = last_wire(ctx)["payload"]
    field("  policy_tag", payload.get("policy_tag"))
    field("  pii_signals", payload.get("pii_signals"))
    field("  token_count", payload.get("token_count"))
    field("  prompt_hash", str(payload.get("prompt_hash"))[:32] + "…")
    say("")
    note("A tag naming a regulated context, and a local scan that found NOTHING. "
         "That gap is the whole question: the guard cannot see what a person "
         "could. So the agent asks for one.")
    say("")

    row = wait_for_grade(ctx, seq, "the judge")
    say("")
    v = show_verdict(row)
    ctx["verdicts"]["escalate"] = v
    ok = ctx["ck"].check("ESCALATE: Qwen called flag_for_human_review and returned "
                         "decision=\"human_review\"",
                         v.get("decision") == "human_review",
                         f"{v.get('decision')} — {v.get('reason')}")
    ctx["ck"].check("ESCALATE: the escalation came from the live model, not a "
                    "local fallback", v.get("judge_provider") == "qwen",
                    f"provider={v.get('judge_provider')} model={v.get('judge_model')}")
    if not ok:
        note("A live model is not a fixture, and this run is reporting what it "
             "actually returned. Beats 4-6 need an escalation to act on.")


def beat_4(ctx: dict) -> None:
    banner(4, "QUEUE", "it lands in front of a person — GET /v1/reviews")
    import requests

    before = ctx.get("pending_before")
    r = requests.get(f"{BASE_URL}/v1/reviews?status=pending&limit=200",
                     cookies=ctx["session"].cookies, timeout=30)
    ctx["ck"].check("QUEUE: GET /v1/reviews -> 200", r.status_code == 200,
                    r.text[:300])
    if r.status_code != 200:
        return
    items = r.json()["items"]
    mine = [i for i in items if i.get("policy_tag") == POLICY_TAG]

    if before is not None:
        # ⚠ BOTH NUMBERS ARE PENDING COUNTS. `before` also knows the total and the
        # cleared tally, and reading the total here would put a count of
        # everything beside a count of the queue — a beat whose whole content is
        # "0 becomes 1" cannot have its two numbers mean different things.
        say(f"pending escalations of `{POLICY_TAG}` before beat 3: "
            f"{before['pending']}")
        say(f"pending escalations of `{POLICY_TAG}` now:             {len(mine)}")
    else:
        note("beat 3 did not run in this session, so there is no before-count to "
             "show. This is the queue as it stands.")
        say(f"pending escalations of `{POLICY_TAG}`: {len(mine)}")
    say("")

    ctx["ck"].check("QUEUE: an escalation is waiting for a human", bool(mine),
                    f"{len(mine)} pending with policy_tag={POLICY_TAG}")
    if not mine:
        return

    # The one this run produced if beat 3 ran, else the newest waiting.
    want = ctx["seqs"].get("escalate")
    item = next((i for i in mine if i["seq"] == want), mine[-1])
    ctx["review"] = item
    field("review id", item["id"])
    field("ledger seq", item["seq"])
    field("status", item["status"])
    field("risk score", item["risk_score"])
    field("policy tag", item["policy_tag"])
    field("the agent's reason", item["reason"])
    say("")
    note("A worklist entry, not a copy of the interaction. The reviewer opens the "
         "ledger row beside it; the queue itself carries no content.")


def beat_5(ctx: dict) -> None:
    banner(5, "HUMAN", "a person rules on it — and history does not move")
    import requests

    item = ctx.get("review")
    if item is None:
        r = requests.get(f"{BASE_URL}/v1/reviews?status=pending&limit=200",
                         cookies=ctx["session"].cookies, timeout=30)
        pending = [i for i in r.json().get("items", [])
                   if i.get("policy_tag") == POLICY_TAG] if r.status_code == 200 else []
        if not pending:
            ctx["ck"].check("HUMAN: there is an escalation to resolve", False,
                            f"nothing pending with policy_tag={POLICY_TAG} — "
                            f"run beats 3,4 first")
            return
        item = ctx["review"] = pending[-1]

    seq = item["seq"]
    before_hash = chain_hash_of(ctx, seq)

    # ⚠ SCOPED TO THIS REVIEW'S OWN LEDGER ROW, not to `event_type` alone. `psql`
    # runs as the compose superuser and bypasses RLS, so an unscoped count would
    # pool every workspace on a stack that has been seeded more than once — and
    # `docker compose up` seeds another one every time. The review id is a UUID
    # and resolves to exactly one row.
    def resolved_events() -> int:
        out = e2e.psql(
            "SELECT count(*) FROM audit_events WHERE "
            "event_type = 'human_review_resolved' AND audit_log_id = "
            f"(SELECT audit_log_id FROM human_reviews WHERE id = '{item['id']}')",
            files=ctx["files"]).strip()
        return int(out or 0)

    before_events = resolved_events()

    url = handoff_url(ctx)
    if url:
        say("The reviewer's own page. Open it and click Review in the rail:")
        say("")
        print("     " + url, flush=True)
        say("")
    if ctx["pause"]:
        try:
            input("   [ press Enter when the Review page is on screen ] ")
        except EOFError:
            pass

    say(f"resolving review {item['id']} as `cleared`…")
    r = requests.post(
        f"{BASE_URL}/v1/reviews/{item['id']}/resolve",
        json={"resolution": "cleared",
              "note": "Template content, no patient identifiers. Cleared by the "
                      "compliance reviewer."},
        cookies=ctx["session"].cookies,
        headers={"X-CSRF-Token": ctx["session"].cookies.get("foxy_csrf", "")},
        timeout=30)
    ctx["ck"].check("HUMAN: POST /v1/reviews/{id}/resolve -> 200",
                    r.status_code == 200, r.text[:300])
    if r.status_code != 200:
        return
    out = r.json()
    say("")
    field("status", out["status"])
    field("resolution", out["resolution"])
    field("resolved by", out["resolved_by"])
    field("resolved at", out["resolved_at"])
    ctx["ck"].check("HUMAN: the review is resolved `cleared`, and the record names "
                    "the person who did it",
                    out["status"] == "resolved" and out["resolution"] == "cleared"
                    and bool(out["resolved_by"]),
                    json.dumps(out)[:300])

    # ⚠ THE POINT OF THE BEAT, and the one thing A1's design would be wrong about
    # if it failed. A human decision is APPENDED; it never rewrites the evidence.
    after_hash = chain_hash_of(ctx, seq)
    after_events = resolved_events()
    appended = e2e.psql(
        "SELECT event_hash FROM audit_events WHERE "
        "event_type = 'human_review_resolved' AND audit_log_id = "
        f"(SELECT audit_log_id FROM human_reviews WHERE id = '{item['id']}')",
        files=ctx["files"]).strip().splitlines()
    say("")
    field("chain_hash before", (before_hash or "")[:32] + "…")
    field("chain_hash after", (after_hash or "")[:32] + "…")
    if appended:
        field("appended event_hash", appended[0][:32] + "…")
    ctx["ck"].check("HUMAN: the chained row is BYTE-IDENTICAL — resolving rewrote "
                    "no history", bool(before_hash) and before_hash == after_hash,
                    f"{before_hash} vs {after_hash}")
    ctx["ck"].check("HUMAN: the decision was APPENDED as a hashed "
                    "`human_review_resolved` event",
                    after_events == before_events + 1,
                    f"{before_events} -> {after_events}")
    note("The human's ruling is evidence too: hashed, append-only, and in the "
         "same export a customer hands their auditor.")


def beat_6(ctx: dict) -> None:
    banner(6, "THE LOOP CLOSES", "the same question again — and the agent has learned")

    priors = prior_reviews(ctx)
    if not priors["cleared"]:
        ctx["ck"].check("FINALE: a human has already cleared this tag, so there is "
                        "something for the agent to learn", False,
                        f"no cleared reviews of `{POLICY_TAG}` exist. This beat is "
                        f"the second half of beat 5 and cannot stand alone — run "
                        f"`--beats 3-6`, or the whole script.")
        return
    say(f"what a human has already decided about `{POLICY_TAG}` in this workspace:")
    field("escalated", priors["escalations"])
    field("cleared by a person", priors["cleared"])
    say("")
    note("`check_prior_reviews` will answer with exactly those counts — numbers, "
         "never the reviewer's note, never a word of content.")
    say("")

    # The SAME shape: same policy_tag, same empty pii_signals. A different agent
    # name only so the two rows are told apart on screen.
    prompt = ("Draft the standard pre-operative instruction sheet our care team "
              "gives before an outpatient procedure.")

    @ctx["client"].audit(policy=POLICY_TAG, agent=ctx["agents"]["finale"],
                         mode="observe")
    def ask_the_model(prompt: str) -> str:
        return ("Nothing to eat after midnight; bring your medication list and a "
                "person who can drive you home.")

    say(f'the prompt: "{prompt}"')
    ask_the_model(prompt=prompt)
    seq = last_wire(ctx)["seq"]
    ctx["seqs"]["finale"] = seq
    payload = last_wire(ctx)["payload"]
    field("  policy_tag", payload.get("policy_tag"))
    field("  pii_signals", payload.get("pii_signals"))
    say("")
    note("The same tag. The same empty scan. The same question that escalated in "
         "beat 3.")
    say("")

    row = wait_for_grade(ctx, seq, "the judge")
    say("")
    v = show_verdict(row)

    was = ctx["verdicts"].get("escalate")
    say("")
    rule = "\u2500" * 62
    print(f"   \u250c{rule}\u2510", flush=True)
    if was:
        left = (f"BEAT 3   {was.get('decision')}   risk {was.get('risk_score')}"
                f"   \u2014 the agent asked a person")
    else:
        left = "BEAT 3   (not run in this session \u2014 see the queue above)"
    right = (f"BEAT 6   {v.get('decision')}   risk {v.get('risk_score')}"
             f"   \u2014 the agent decided for itself")
    for row in (left, right):
        print("   \u2502 " + row.ljust(60) + " \u2502", flush=True)
    print(f"   \u2514{rule}\u2518", flush=True)
    say("")

    ctx["ck"].check("FINALE: the agent graded it `clean` INSTEAD of escalating",
                    v.get("decision") == "clean",
                    f"{v.get('decision')} — {v.get('reason')}")
    ctx["ck"].check("FINALE: and it was the live model that decided",
                    v.get("judge_provider") == "qwen",
                    f"provider={v.get('judge_provider')} model={v.get('judge_model')}")
    note("The agent escalated. A human ruled. The agent asked what people had "
         "already decided, and did not escalate again.")
    if v.get("decision") != "clean":
        note("A live model is not a fixture. This run is reporting what Qwen "
             "actually returned, which is the only thing this script is allowed "
             "to do.")


def beat_7(ctx: dict) -> None:
    banner(7, "VERIFY", "recompute the whole chain — without trusting Foxy")
    import requests

    r = requests.get(f"{BASE_URL}/v1/logs/export?format=json",
                     headers=ctx["headers"], timeout=180)
    ctx["ck"].check("VERIFY: the ledger exported", r.status_code == 200, r.text[:300])
    if r.status_code != 200:
        return
    path = os.path.join(ctx["run_dir"], "logs.json")
    with open(path, "wb") as fh:
        fh.write(r.content)
    body = json.loads(r.content.decode("utf-8"))
    ctx["export"] = path
    field("rows exported", body.get("count"))
    field("written to", path)
    say("")
    say(f"$ python verifier/foxy_verify.py {os.path.basename(path)}")
    say("")

    proc = subprocess.run([sys.executable, VERIFIER, path],
                          capture_output=True, text=True, encoding="utf-8",
                          errors="replace", timeout=300)
    for line in (proc.stdout or "").splitlines():
        print("     " + line, flush=True)
    ctx["ck"].check("VERIFY: the chain recomputes intact from genesis — exit 0",
                    proc.returncode == 0,
                    f"exit {proc.returncode}\n{(proc.stdout or '')[-800:]}"
                    f"{(proc.stderr or '')[-400:]}")
    note("That file imports nothing from Foxy and nothing from PyPI. Anyone can "
         "run it, on any machine, forever.")


def beat_8(ctx: dict) -> None:
    banner(8, "TAMPER", "alter one byte — and watch it fail at the right sequence")

    path = ctx.get("export")
    if not path or not os.path.isfile(path):
        ctx["ck"].check("TAMPER: there is an export to tamper with", False,
                        "beat 7 did not produce logs.json — run `--beats 7,8`")
        return
    with open(path, encoding="utf-8") as fh:
        body = json.load(fh)
    logs = body.get("logs") or []
    if len(logs) < 2:
        ctx["ck"].check("TAMPER: the ledger has enough rows to tamper with",
                        False, f"{len(logs)} row(s)")
        return

    # A row in the middle, so the failure is visibly NOT the last one — a chain
    # that only catches the final row would catch nothing worth catching.
    target = logs[len(logs) // 2]
    seq = target["seq"]
    original = target["prompt_hash"]
    # One hex character. Not a rewritten row, not a deleted one: the smallest
    # possible change anyone could make.
    flipped = ("1" if original[0] != "1" else "2") + original[1:]
    target["prompt_hash"] = flipped

    tampered = os.path.join(ctx["run_dir"], "logs-tampered.json")
    with open(tampered, "w", encoding="utf-8") as fh:
        json.dump(body, fh)

    say(f"changed ONE hex character of `prompt_hash` at seq {seq}:")
    field("  before", original[:24] + "…")
    field("  after", flipped[:24] + "…")
    say("")
    say(f"$ python verifier/foxy_verify.py {os.path.basename(tampered)}")
    say("")

    proc = subprocess.run([sys.executable, VERIFIER, tampered],
                          capture_output=True, text=True, encoding="utf-8",
                          errors="replace", timeout=300)
    for line in (proc.stdout or "").splitlines():
        print("     " + line, flush=True)
    ctx["ck"].check("TAMPER: the verifier REFUSED the tampered export — exit 1",
                    proc.returncode == 1, f"exit {proc.returncode}")
    # ⚠ THE SEQ COMES OFF `--json`, NOT out of the printed prose. `str(seq) in
    # stdout` would pass on seq 3 because the report happens to contain "13" — a
    # check that cannot fail is not a check, and this one is the difference
    # between "verification failed" and "verification found the RIGHT row".
    machine = subprocess.run([sys.executable, VERIFIER, tampered, "--json"],
                             capture_output=True, text=True, encoding="utf-8",
                             errors="replace", timeout=300)
    try:
        chain = json.loads(machine.stdout or "{}").get("chain") or {}
    except ValueError:
        chain = {}
    ctx["ck"].check(f"TAMPER: and it named seq {seq}, the row that was altered",
                    chain.get("first_broken_seq") == seq and chain.get("ok") is False,
                    f"first_broken_seq={chain.get('first_broken_seq')} "
                    f"ok={chain.get('ok')}")
    note("Nobody had to be trusted for that. The evidence checks itself.")


BEATS = {1: beat_1, 2: beat_2, 3: beat_3, 4: beat_4,
         5: beat_5, 6: beat_6, 7: beat_7, 8: beat_8}
#: Which beats need a live model. Everything else runs whatever the key situation.
NEEDS_JUDGE = (3, 4, 5, 6)


# ═══════════════════════════════ the run ═════════════════════════════════════
def main() -> int:
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    except Exception:                                            # noqa: BLE001
        pass

    ap = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--beats", default="",
                    help="re-record part of the run: `6`, `1,2,3`, `3-6`. Implies "
                         "--reuse-stack, because wiping the database would destroy "
                         "the state the later beats act on.")
    ap.add_argument("--reuse-stack", action="store_true",
                    help="use the stack that is already up, exactly as it is.")
    ap.add_argument("--fresh", action="store_true",
                    help="force `down -v` + `up` even with --beats. WIPES the "
                         "local demo Postgres volume.")
    ap.add_argument("--no-build", action="store_true",
                    help="reuse the images already built instead of `up --build`.")
    ap.add_argument("--pause", action="store_true",
                    help="wait for Enter between beats, so a recording can be "
                         "started and stopped on each one.")
    ap.add_argument("--down", action="store_true",
                    help="tear the stack down (`down -v`) when the run finishes. "
                         "Off by default: the dashboard is usually still wanted "
                         "after the last beat.")
    args = ap.parse_args()

    beats = parse_beats(args.beats)
    # A partial run acts on state the earlier beats left behind, so it must not
    # begin by deleting it. This is the flag that saves the recording session.
    reuse = args.reuse_stack or (bool(args.beats) and not args.fresh)

    os.makedirs(ART, exist_ok=True)
    if not os.environ.get("FOXY_E2E_BOOTSTRAPPED"):
        # The SAME venv run_e2e.py builds, and the SAME `pip install ./sdk` — a
        # demo of the SDK has to be a demo of the wheel a customer installs.
        e2e.bootstrap_and_reexec(sys.argv, script=os.path.abspath(__file__))

    import requests

    ck = e2e.Checks()
    run = token()
    run_dir = os.path.join(ART, f"run-{run}")
    os.makedirs(run_dir, exist_ok=True)
    ctx: dict = {"ck": ck, "run": run, "run_dir": run_dir, "files": [],
                 "wire": [], "seqs": {}, "verdicts": {}, "judge": None,
                 "judge_note": None,
                 "pause": args.pause, "review": None,
                 "agents": {k: f"demo-{k}-{run}"
                            for k in ("guard", "clean", "escalate", "finale")}}
    started = time.time()

    print("\n" + "─" * 76)
    print("  FOXY AUDIT — the agentic loop, end to end")
    print(f"  beats {','.join(str(b) for b in beats)}   ·   artifacts -> {run_dir}")
    print("─" * 76, flush=True)

    try:
        # ── the stack ────────────────────────────────────────────────────────
        e2e.step("stack up, waiting on /health/ready (never on a sleep)")
        ctx["files"] = [compose_override()]
        if reuse:
            say("--reuse-stack: using the running stack as it is — no down, no up.")
        else:
            say("docker compose down -v — this WIPES the local demo Postgres "
                "volume.")
            e2e.compose("down", "-v", timeout=600, check=False, files=ctx["files"])
            e2e.compose(*(["up", "-d"] + ([] if args.no_build else ["--build"])),
                        timeout=2400, files=ctx["files"])
        ready = e2e.wait_for_ready(300.0, ctx["files"])
        ck.check("the stack reached /health/ready", True, f"{ready:.1f}s")

        # ── the key, and the human session ───────────────────────────────────
        e2e.step("credentials: the SDK's key, and the reviewer's session")
        ctx["api_key"] = e2e.scrape_api_key(ctx["files"])
        ctx["headers"] = {"Authorization": f"Bearer {ctx['api_key']}"}
        ck.check("the one-time API key was scraped from the foxy-seed logs", True,
                 f"{ctx['api_key'][:11]}…{ctx['api_key'][-4:]}")

        sess = requests.Session()
        lr = sess.post(f"{BASE_URL}/v1/auth/login",
                       json={"email": SEED_EMAIL, "password": SEED_PASSWORD},
                       timeout=30)
        ck.check("the seeded reviewer can sign in", lr.status_code == 200,
                 f"{lr.status_code} {lr.text[:200]}")
        ctx["session"] = sess

        # ── the judge ────────────────────────────────────────────────────────
        e2e.step("the judge: is there a live model, or is there not?")
        qwen_key = read_qwen_key()
        reachable, probe = (True, "") if not qwen_key else judge_reachable(ctx)
        if qwen_key and reachable is None:
            # The probe broke, which says nothing about the provider. Carry on
            # and let the grade itself answer — beat 2's backstop reads
            # `judge_provider`, which is the fact rather than an inference.
            say("(the reachability probe did not run — " + probe + ")")
            say("carrying on: whether a provider was actually called is read off "
                "the first verdict, not guessed here.")
            reachable = True
        if qwen_key and not reachable:
            # ⚠ THE SECOND WAY THE JUDGE CAN BE UNAVAILABLE, and until this ran it
            # was the confusing one. A key that is present but a provider that
            # cannot be dialled produced a `clean` verdict from the worker's
            # deterministic fallback, four beats failing for four different
            # reasons, and nothing anywhere saying "the model was never asked".
            # The probe costs no tokens and turns that into one sentence.
            ctx["judge"] = None
            ctx["judge_note"] = ("the provider could not be reached from the "
                                 "worker container: " + probe)
        if not qwen_key or not reachable:
            ctx["judge"] = None
            say("⚠ THE JUDGE IS UNAVAILABLE.")
            if not qwen_key:
                say("  No QWEN_API_KEY in the environment or in backend/.env.")
            else:
                say("  " + probe)
                say("  The key is fine — the worker cannot verify the TLS "
                    "connection. Something on this")
                say("  machine is intercepting HTTPS with a root the CONTAINER "
                    "does not trust. See the")
                say("  demo README: drop that CA in "
                    "e2e/.artifacts/agentic/ca-bundle.pem and re-run.")
            say("  Beats 1, 2, 7 and 8 still run, for real. Beats 3-6 need a live "
                "model and are")
            say("  SKIPPED rather than simulated — there is no canned Qwen "
                "response in this file,")
            say("  and there must never be one.")
        else:
            cur = sess.get(f"{BASE_URL}/v1/policies", timeout=30).json()
            body = {k: v for k, v in cur.items() if k not in POLICY_READ_ONLY}
            body["judge_provider"] = "qwen"
            body["judge_key_mode"] = "own"
            body["qwen_api_key"] = qwen_key
            pr = sess.put(f"{BASE_URL}/v1/policies", json=body, timeout=30,
                          headers={"X-CSRF-Token": sess.cookies.get("foxy_csrf", "")})
            stored = pr.status_code == 200 and pr.json().get("qwen_key_set") is True
            ck.check("the Qwen key is stored for this workspace, encrypted at rest",
                     stored,
                     f"{pr.status_code} {scrubbed(pr.text, qwen_key)[:300]}")
            if not stored:
                raise e2e.Fatal(
                    "the Qwen key could not be stored ("
                    + scrubbed(pr.text, qwen_key)[:200] + "). A 503 here means "
                    "the stack is running without PROVIDER_KEY_ENCRYPTION_KEY — "
                    "re-run WITHOUT --reuse-stack so the demo's compose override "
                    "is applied.")
            ctx["judge"] = "qwen"
            say(f"the provider answers a TLS handshake from the worker "
                f"({probe.split()[1] if len(probe.split()) > 1 else 'ok'})")
            say(f"judge_provider=qwen  model="
                f"{(pr.json().get('judge_models') or {}).get('qwen')}  "
                f"key_mode=own (the key is never printed and never committed)")

        skipped: list[int] = []

        # ── the SDK ──────────────────────────────────────────────────────────
        e2e.step("the SDK: one real client, built from ./sdk")
        import foxy_audit
        ctx["client"] = sdk_client(ctx)
        install_wire_capture(ctx)
        if not ctx["client"].enabled:
            raise e2e.Fatal("the SDK resolved to disabled — no API key reached "
                            "FoxyConfig")
        say(f"foxy-audit {getattr(foxy_audit, '__version__', '?')} from "
            f"{os.path.dirname(os.path.abspath(foxy_audit.__file__))}")

        # ── the beats ────────────────────────────────────────────────────────
        first = True
        for n in beats:
            # ⚠ CHECKED HERE, not against a list decided before the run started.
            # `ctx["judge"]` can go false DURING the run — beat 2's backstop
            # flips it the moment a row comes back graded by nothing but the
            # worker's own rules — and a beat that needs a model it now knows it
            # does not have must not be attempted.
            if n in NEEDS_JUDGE and ctx["judge"] != "qwen":
                skipped.append(n)
                continue
            if args.pause and not first:
                try:
                    input("\n   [ press Enter for the next beat ] ")
                except EOFError:
                    pass
            first = False
            BEATS[n](ctx)

        if skipped:
            bar = "═" * 74
            print(f"\n\n╔{bar}╗")
            print("║  NOT RUN — and not simulated either".ljust(75) + "║")
            print(f"╚{bar}╝", flush=True)
            say(f"beats {','.join(str(b) for b in skipped)} need a live model, and "
                f"this run had none.")
            if ctx.get("judge_note"):
                say(ctx["judge_note"])
            say("Nothing was substituted for them. Set QWEN_API_KEY in "
                "backend/.env and re-run.")

    except e2e.Fatal as exc:
        waiting_done()
        print(f"\nFATAL: {exc}", flush=True)
        ck.rows.append({"name": "the run completed", "ok": False,
                        "detail": str(exc)[:600]})
    except Exception:                                            # noqa: BLE001
        import traceback
        waiting_done()
        print("\nUNEXPECTED:\n" + traceback.format_exc(), flush=True)
        ck.rows.append({"name": "the run completed", "ok": False,
                        "detail": traceback.format_exc()[-600:]})
    finally:
        if args.down:
            e2e.step("tearing the stack down (--down)")
            e2e.compose("down", "-v", timeout=600, check=False, files=ctx["files"])

    result = "PASS" if ck.rows and not ck.failed else "FAIL"
    print("\n" + "─" * 76)
    print(f"  {result}   {len(ck.rows) - len(ck.failed)}/{len(ck.rows)} checks   "
          f"{time.time() - started:.0f}s")
    for row in ck.failed:
        print(f"  FAILED: {row['name']} — {row['detail']}", flush=True)
    if not args.down:
        print("  the stack is still up. `docker compose -f backend/"
              "docker-compose.yml down -v` when you are done,")
        print("  or re-run with --down.")
    print("─" * 76, flush=True)

    try:
        with open(os.path.join(run_dir, "summary.json"), "w", encoding="utf-8") as fh:
            json.dump({"result": result, "beats": beats, "judge": ctx.get("judge"),
                       "seqs": ctx.get("seqs"), "checks": ck.rows},
                      fh, indent=2, default=str)
    except OSError:
        pass
    return 0 if result == "PASS" else 1


if __name__ == "__main__":
    sys.exit(main())
