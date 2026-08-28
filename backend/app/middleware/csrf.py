"""Double-submit CSRF protection for cookie-authenticated browser requests.

The threat is only real for requests the browser authenticates *automatically* via a
session cookie. So we enforce a token ONLY when a session cookie is present:

  * SDK ingest (Bearer, no cookie)            -> skipped (already CSRF-immune)
  * Stripe webhook (server-to-server, no cookie) -> skipped
  * public marketing POSTs (/v1/leads,/track,/consent,/signup,checkout; SameSite=Lax
    means the session cookie isn't sent cross-site anyway) -> skipped
  * dashboard / admin actions (session cookie present)     -> ENFORCED

On any response lacking the cookie we mint `foxy_csrf` (JS-readable, so the SPA can
echo it in the `X-CSRF-Token` header). The token is compared in constant time.
"""
from __future__ import annotations

import secrets

from starlette.middleware.base import BaseHTTPMiddleware
from starlette.responses import JSONResponse

_SAFE_METHODS = {"GET", "HEAD", "OPTIONS", "TRACE"}
_SESSION_COOKIES = ("session", "foxy_staff_session")
_COOKIE = "foxy_csrf"
_MAX_AGE = 60 * 60 * 24 * 180   # 180 days

# Session-ESTABLISHING / token-based auth flows are exempt: they run pre-session
# (login, mfa, forgot/reset) or authenticate via an unguessable single-use token
# (handoff/redeem, google) — a stolen/planted session cookie can't forge those.
# NOTE: logged-in state changes like /v1/auth/change-password and /v1/auth/users*
# deliberately stay protected.
#
# ⚠ CORRECTION (#262, MEASURED). This block used to say "paths are sub-app-relative
# (the /admin mount prefix is already stripped), so one set covers both the customer
# and admin auth routers." It does not. On starlette 0.49.3 (this repo's pin) AND on
# 1.3.1, a `Mount` sets `root_path="/admin"` and leaves the path WHOLE, so inside
# admin_api both `scope["path"]` and `request.url.path` are `/admin/v1/auth/login`
# and NOTHING in this set matches an admin request. The set covers the customer API
# only. That is harmless today — the flows listed here run pre-session, so with no
# session cookie the cookie clause in `dispatch` is already False — but it is not
# what the comment claimed, and nobody should add an admin path here expecting a
# bare `/v1/...` spelling to work. Left as-is otherwise: #262 is not the place
# to change which admin routes enforce CSRF.
_EXEMPT_PATHS = frozenset({
    "/v1/auth/login", "/v1/auth/logout", "/v1/auth/mfa",
    "/v1/auth/forgot-password", "/v1/auth/reset-password",
    "/v1/auth/handoff", "/v1/auth/handoff/redeem", "/v1/auth/google",
})


class CSRFMiddleware(BaseHTTPMiddleware):
    def __init__(self, app, secure: bool = False):
        super().__init__(app)
        self._secure = secure

    async def dispatch(self, request, call_next):
        token = request.cookies.get(_COOKIE)
        # ⚠ #262 · `scope["path"]` (the RAW routed path), never `request.url.path`.
        # `request.url` is rebuilt from the client's `Host` header and re-parsed
        # (PYSEC-2026-161, starlette 0.49.3 — the pin), so `Host:
        # testserver/v1/auth/login?` makes the reconstructed path EXACTLY
        # `/v1/auth/login` — a member of _EXEMPT_PATHS — with the real route
        # pushed into the query. Measured: that bought a CSRF exemption on
        # `POST /v1/keys` and minted an API key with no token at all. Routing is
        # unaffected, so the exempt check and the dispatch must read the same
        # value or they decide about different endpoints.
        enforce = (
            request.method not in _SAFE_METHODS
            and request.scope["path"] not in _EXEMPT_PATHS
            and any(c in request.cookies for c in _SESSION_COOKIES)
        )
        if enforce:
            sent = request.headers.get("x-csrf-token", "")
            if not token or not sent or not secrets.compare_digest(sent, token):
                return JSONResponse({"detail": "CSRF token missing or invalid"}, status_code=403)

        response = await call_next(request)
        if not token:
            response.set_cookie(
                _COOKIE, secrets.token_urlsafe(32), max_age=_MAX_AGE,
                httponly=False, secure=self._secure, samesite="lax", path="/",
            )
        return response
