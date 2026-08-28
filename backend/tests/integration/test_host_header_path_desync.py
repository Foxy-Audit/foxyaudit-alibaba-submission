"""#262 — a crafted ``Host`` must not move the path a security gate reads.

**The mechanism (PYSEC-2026-161, starlette 0.49.3 — this repo's pin).**
``starlette.datastructures.URL.__init__`` rebuilds the URL as
``f"{scheme}://{host_header}{path}"`` and re-parses it, so a ``Host`` carrying a
``/``, ``?`` or ``#`` moves the path boundary::

    Host: testserver/v1/auth/   +   GET /v1/logs
        -> "http://testserver/v1/auth//v1/logs"  ->  url.path == "/v1/auth//v1/logs"

Routing dispatches on ``scope["path"]``, which is untouched — so the real
endpoint runs while ``request.url.path`` claims to be somewhere else. Two gates
in this app were making an AUTHORIZATION decision on that reconstructed value:
the billing lock (``auth._enforce_dashboard_gates``) and the CSRF exemption
(``middleware.csrf``). Both now read ``request.scope["path"]``.

**Why these tests patch starlette.** The fix has to hold on the version this
repo PINS (0.49.3, vulnerable — and what CI installs) and on any version someone
installs later (1.0.1+, which validates the header and is not vulnerable). A
test that merely sends a crafted ``Host`` proves nothing on a patched starlette:
it passes whether or not the gate was fixed, so a mutant reverting a gate to
``request.url.path`` would survive it. So the desync is reinstated explicitly,
and the fixture that reinstates it ASSERTS IT IS LIVE before any test leans on
it. ``..._on_the_installed_starlette`` is the unpatched counterpart of the same
drive, run against whatever is actually installed.
"""

from __future__ import annotations

import uuid
from datetime import datetime, timedelta, timezone

import pytest
import starlette.datastructures as sds

from app.config import get_settings
from app.db import SessionLocal
from app.middleware import traffic as traffic_mw
from app.models import Organization, TrafficEvent

CRAFTED_HOST = "testserver/v1/auth/"              # billing lock: prefix match
CRAFTED_HOST_CSRF = "testserver/v1/auth/login?"   # CSRF: exact match


def _lock(org_id) -> None:
    """As locked as an org gets — an evaluation whose window shut. The same
    condition `test_lock_scope_and_audit` uses, so the fixture is known-good."""
    with SessionLocal() as db:
        o = db.get(Organization, uuid.UUID(str(org_id)))
        o.plan_tier = "premium"
        o.evaluation_offer_id = "offer-262"
        o.evaluation_credit_limit = 10
        o.evaluation_ends_at = datetime.now(timezone.utc) - timedelta(days=1)
        db.commit()


def _vulnerable_url_init(self, url="", scope=None, **components):
    """starlette 0.49.3's ``URL.__init__``, reproduced in behaviour.

    Reproduced rather than imported: the point is to hold the gates to the
    semantics of the version ``backend/requirements.txt`` pins, on whatever
    starlette the test environment happens to have."""
    if scope is not None:
        assert not url and not components
        scheme = scope.get("scheme", "http")
        server = scope.get("server", None)
        path = scope["path"]
        query_string = scope.get("query_string", b"")
        host_header = None
        for key, value in scope["headers"]:
            if key == b"host":
                host_header = value.decode("latin-1")
                break
        if host_header is not None:
            url = f"{scheme}://{host_header}{path}"
        elif server is None:
            url = path
        else:
            host, port = server
            default_port = {"http": 80, "https": 443, "ws": 80, "wss": 443}[scheme]
            url = (f"{scheme}://{host}{path}" if port == default_port
                   else f"{scheme}://{host}:{port}{path}")
        if query_string:
            url += "?" + query_string.decode()
    elif components:
        assert not url
        url = sds.URL("").replace(**components).components.geturl()
    self._url = url


@pytest.fixture
def desynced(monkeypatch):
    """Reinstate the 0.49.3 reconstruction, then PROVE it is live.

    The two assertions below are the whole reason this fixture exists: without
    them, a patched starlette would make every test that uses it vacuous."""
    monkeypatch.setattr(sds.URL, "__init__", _vulnerable_url_init, raising=True)

    def _url_path(host: str, path: str) -> str:
        return sds.URL(scope={
            "type": "http", "scheme": "http", "server": ("testserver", 80),
            "path": path, "query_string": b"",
            "headers": [(b"host", host.encode())],
        }).path

    assert _url_path(CRAFTED_HOST, "/v1/logs") == "/v1/auth//v1/logs", (
        "the desync is not live — everything downstream would prove nothing")
    assert _url_path(CRAFTED_HOST_CSRF, "/v1/keys") == "/v1/auth/login"
    return _url_path


# ── the billing lock (AUTHORIZATION) ────────────────────────────────────────

def _drive_the_lock(make_org, login):
    """Lock an org, confirm it IS locked, then ask for a gated route under a
    crafted Host. Returns the crafted response."""
    org = make_org()
    _lock(org["org_id"])
    c = login(org["admin_email"], org["admin_password"])
    assert c.get("/v1/logs").status_code == 402, (
        "the org is not actually locked, so nothing downstream proves anything")
    return c.get("/v1/logs", headers={"Host": CRAFTED_HOST})


def test_a_crafted_host_cannot_lift_the_billing_lock(make_org, login, desynced):
    """The bypass #262 describes, driven end to end against the real app.

    `/v1/logs` is behind the lock; `/v1/auth/` is exempt. Under the desync the
    reconstructed path begins `/v1/auth/`, so a gate reading `request.url.path`
    exempts a request routing still dispatches to `/v1/logs`."""
    r = _drive_the_lock(make_org, login)
    assert r.status_code == 402, (
        f"the billing lock was lifted by a Host header (got {r.status_code}); "
        "the gate is reading the reconstructed URL, not the routed path")
    assert r.json()["detail"]["code"] == "evaluation_expired"


def test_a_crafted_host_cannot_lift_the_lock_on_the_cookie_read_path(
        make_org, login, desynced):
    """`resolve_org` runs the same gate for cookie-authenticated reads, and it is
    a SECOND call site — a fix applied to `require_user` alone would still pass
    the test above."""
    org = make_org()
    _lock(org["org_id"])
    c = login(org["admin_email"], org["admin_password"])
    assert c.get("/v1/stats").status_code == 402, (
        "/v1/stats is not gated, so this proves nothing")
    assert c.get("/v1/stats", headers={"Host": CRAFTED_HOST}).status_code == 402


def test_a_crafted_host_does_not_withhold_what_the_lock_may_not_withhold(
        make_org, login, desynced):
    """The other direction, and the reason this is not a one-way check: `#`
    truncates the reconstructed path to `""`, which matches no exempt prefix. A
    gate reading the raw path still lets a locked customer reach their own
    evidence (#49's guarantee)."""
    org = make_org()
    _lock(org["org_id"])
    c = login(org["admin_email"], org["admin_password"])
    r = c.get("/v1/logs/export", headers={"Host": "testserver#"})
    assert r.status_code == 200, (
        "a Host header took the customer's own evidence away from them")


# ── the CSRF exemption (AUTHORIZATION) ──────────────────────────────────────

def test_a_crafted_host_cannot_buy_a_csrf_exemption(make_org, login, desynced):
    """`_EXEMPT_PATHS` is an EXACT match, and `Host: testserver/v1/auth/login?`
    makes the reconstructed path exactly `/v1/auth/login`, with the real route
    pushed into the query."""
    org = make_org()
    c = login(org["admin_email"], org["admin_password"])
    c.headers.pop("X-CSRF-Token", None)          # a forged cross-site POST has none

    assert c.post("/v1/keys", json={"name": "x"}).status_code == 403, (
        "/v1/keys is not CSRF-protected, so this proves nothing")

    r = c.post("/v1/keys", json={"name": "x"}, headers={"Host": CRAFTED_HOST_CSRF})
    assert r.status_code == 403, (
        f"CSRF enforcement was skipped because of a Host header "
        f"(got {r.status_code})")
    assert r.json()["detail"] == "CSRF token missing or invalid"


def test_the_real_csrf_exemption_still_works(make_org, login, desynced):
    """The fix must not close the exemptions that are meant to be open — login
    runs pre-session and cannot carry a token."""
    org = make_org()
    c = login(org["admin_email"], org["admin_password"])
    c.headers.pop("X-CSRF-Token", None)
    r = c.post("/v1/auth/login", json={"email": org["admin_email"],
                                       "password": org["admin_password"]})
    assert r.status_code == 200, r.text


# ── the two sites that are NOT authorization ────────────────────────────────
# Changed on their own merits, so guarded on their own merits: without these,
# reverting either one to `request.url.path` costs nothing and the change is
# decoration.

def test_a_crafted_host_cannot_choose_which_body_size_ceiling_applies(
        client, desynced):
    """`_BODY_LIMIT_OVERRIDES` is keyed by ROUTE. `/v1/account/avatar` may send
    5 MB; ingest is capped at the 2 MB default because it is the unbounded path
    the middleware exists for. Under the desync, `Host: h/v1/account/avatar?`
    reconstructs to exactly `/v1/account/avatar` and hands ingest the photo
    ceiling."""
    body = b"x" * (get_settings().max_request_bytes + 1024)   # over 2 MB, under 5

    assert client.post("/v1/logs/batch", content=body).status_code == 413, (
        "the default ceiling is not being applied, so this proves nothing")

    r = client.post("/v1/logs/batch", content=body,
                    headers={"Host": "testserver/v1/account/avatar?"})
    assert r.status_code == 413, (
        f"a Host header lifted ingest's body ceiling to the avatar route's "
        f"(got {r.status_code})")


def test_a_crafted_host_cannot_write_its_own_path_into_traffic_accounting(
        make_org, login, desynced):
    """Accounting, not authorization — but `traffic_events.path` is read by the
    admin timeseries, and a caller must not be able to choose what lands in it.
    Under the desync this recorded `/v1/auth//v1/stats`."""
    s = get_settings()
    org = make_org()
    c = login(org["admin_email"], org["admin_password"])

    s.traffic_tracking_enabled = True
    try:
        assert c.get("/v1/stats", headers={"Host": CRAFTED_HOST}).status_code == 200
        traffic_mw.flush(timeout=3.0)
    finally:
        s.traffic_tracking_enabled = False

    with SessionLocal() as db:
        paths = [r.path for r in db.query(TrafficEvent).all()]
    assert "/v1/stats" in paths, (
        f"the routed path was not what got counted; recorded {paths!r}")


# ── the environment itself ──────────────────────────────────────────────────

def test_a_crafted_host_cannot_lift_the_billing_lock_on_the_installed_starlette(
        make_org, login):
    """The same drive, UNPATCHED, against whatever starlette is installed.

    A REAL guard on the pinned 0.49.3 — which is what CI installs from
    `backend/requirements.txt`, and what production runs — and a tautology on
    1.0.1+, which validates the Host header itself. Asserted either way rather
    than skipped: a silent skip is how #258 hid a genuine failure, and if the
    pin ever moves backwards this is the test that notices."""
    import starlette
    r = _drive_the_lock(make_org, login)
    assert r.status_code == 402, (
        f"starlette {starlette.__version__}: the billing lock was lifted by a "
        f"Host header (got {r.status_code})")
