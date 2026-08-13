"""security.txt (RFC 9116) — and the two ways a security.txt goes wrong.

It rots, or nothing serves it.

An expired file is worse than no file: it advertises a reporting channel and
then says the channel is stale. So the expiry is a TEST, not a calendar
reminder — CI turns red a month before the date, which is the only renewal
mechanism this project actually has.

And a file in the repo that no route serves is decoration. The route is asserted
against the real deploy/Caddyfile, not described.

Everything here reads the SHIPPED files. Run:  pytest foxy-sale-page -q
"""

from __future__ import annotations

import re
from datetime import datetime, timedelta, timezone
from pathlib import Path

_HERE = Path(__file__).resolve().parent
_ROOT = _HERE.parent
_TXT = _HERE / "security.txt"
_CADDY = _ROOT / "deploy" / "Caddyfile"
#: The config that ACTUALLY serves production. See test_a_route_actually_serves_it.
_NGINX = _ROOT / "deploy" / "nginx-foxyaudit.conf"
_README = _ROOT / "README.md"
_POLICY = _ROOT / "SECURITY.md"

#: How long before Expires this suite starts failing. Long enough to notice and
#: renew without a rush, short enough that the file is not red for most of its
#: life.
RENEW_WINDOW = timedelta(days=30)


def _fields() -> dict[str, list[str]]:
    """RFC 9116 name/value fields, comments and blanks dropped. Names are
    case-insensitive per §2.2, so they are lowercased here."""
    out: dict[str, list[str]] = {}
    for line in _TXT.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        name, _, value = line.partition(":")
        out.setdefault(name.strip().lower(), []).append(value.strip())
    return out


def test_the_file_parses_as_rfc9116_name_value_fields():
    fields = _fields()
    assert fields, "no parsable fields — a comment-only security.txt serves nothing"
    assert "contact" in fields, "Contact is REQUIRED (RFC 9116 §2.5.3)"
    assert len(fields.get("expires", [])) == 1, \
        "Expires is REQUIRED and MUST appear exactly once (RFC 9116 §2.5.5)"


def test_expires_is_far_enough_away_that_it_can_still_be_renewed():
    """⚠ IF THIS IS THE TEST THAT FAILED: nothing is broken. The published
    security.txt is inside a month of expiring. Renew it — push the Expires date
    in foxy-sale-page/security.txt out by another year, confirm the contacts in
    it are still the ones you want, and commit. This failing in CI is the
    mechanism working."""
    raw = _fields()["expires"][0]
    expires = datetime.fromisoformat(raw.replace("Z", "+00:00"))
    assert expires.tzinfo is not None, "Expires must carry a timezone (RFC 3339)"
    now = datetime.now(timezone.utc)
    assert expires > now, f"the published security.txt EXPIRED on {raw}"
    assert expires - now > RENEW_WINDOW, (
        f"security.txt expires {raw}, within {RENEW_WINDOW.days} days — renew it now")


def test_expires_is_not_further_out_than_a_year():
    """RFC 9116 §2.5.5: "less than a year". A ten-year expiry would silence the
    test above by making the promise meaningless."""
    expires = datetime.fromisoformat(_fields()["expires"][0].replace("Z", "+00:00"))
    assert expires - datetime.now(timezone.utc) < timedelta(days=366)


def test_the_contacts_are_the_ones_the_README_already_publishes():
    """No new channel is minted here. A contact that exists only in security.txt
    is a mailbox nobody watches."""
    readme = _README.read_text(encoding="utf-8")
    contacts = _fields()["contact"]
    assert "mailto:support@foxyaudit.tech" in contacts
    assert "support@foxyaudit.tech" in readme, \
        "the README no longer names this address — the two have drifted"
    advisory = [c for c in contacts if "/security/advisories/new" in c]
    assert advisory, "the private advisory channel the README points at is missing"
    assert "security/advisories/new" in readme


def test_the_policy_link_points_at_a_file_that_exists():
    policy = _fields().get("policy", [])
    assert policy, "Policy should point at SECURITY.md"
    assert policy[0].endswith("SECURITY.md")
    assert _POLICY.is_file(), "SECURITY.md is missing, so Policy is a dead link"


def _block(text: str, opener: str) -> str:
    """The slice from `opener` to its matching close brace.

    Every config here repeats itself across sites — the checkout site has its own
    root/file_server pair, its own `alias`, and its own `try_files ... =404`. A
    grep of the whole file is answered by the WRONG site and passes. So the
    window has to be a real scope: match braces."""
    start = text.index(opener)
    depth = 0
    for i in range(start, len(text)):
        if text[i] == "{":
            depth += 1
        elif text[i] == "}":
            depth -= 1
            if depth == 0:
                return text[start:i]
    raise AssertionError(f"could not find the end of the block opened by {opener!r}")


def _directives(block: str) -> str:
    """`block` with every nginx `#` comment removed.

    ⚠ NOT COSMETIC. The marketing block is heavily commented, and those comments
    QUOTE the directives they explain — the note above the catch-all spells out
    `$uri.html`, and the note above the alias spells out `types { }`. Asserting
    against the raw text therefore passes on a config where the directive has
    been deleted and only the prose survives: measured, two mutations that broke
    real behaviour stayed green until this stripper existed. Assert on what nginx
    executes, never on what the file says."""
    return "\n".join(line.split("#", 1)[0] for line in block.splitlines())


def _marketing_vhost() -> str:
    """The nginx server block for foxyaudit.tech — the one that reaches a
    researcher. `server {` alone appears four times, so the block is found by its
    server_name and then walked BACKWARDS to the `server {` that opens it."""
    conf = _NGINX.read_text(encoding="utf-8")
    name = conf.index("server_name foxyaudit.tech www.foxyaudit.tech;")
    return _directives(_block(conf[conf.rindex("server {", 0, name):], "server {"))


def test_a_route_actually_serves_it():
    """The half that makes this more than a file in a repo.

    ⚠ THIS ASSERTED ONLY THE CADDYFILE, AND THE CADDYFILE DOES NOT SERVE
    PRODUCTION. The shared VM runs its own nginx (deploy/nginx-foxyaudit.conf);
    the caddy service is behind `profiles: ["edge"]` and is never started. So
    this test was green, and reviewed, and marked delivered, for the whole time
    /.well-known/security.txt was actually returning the marketing homepage as
    text/html. A guard aimed at the wrong file is worse than no guard: it reports
    that something was checked.

    Both edges are asserted now. nginx first — it is the one that is live."""
    nginx = _marketing_vhost()

    assert "location = /.well-known/security.txt {" in nginx, \
        "nginx serves nothing at the canonical RFC 9116 path — the file is decoration"
    # Exact match, not a prefix: `location /.well-known/` would also swallow
    # /.well-known/acme-challenge/ and break certbot renewal.
    assert "location /.well-known/ {" not in nginx and "location /.well-known {" not in nginx, \
        "a PREFIX .well-known location shadows acme-challenge and breaks cert renewal"
    assert 'default_type "text/plain; charset=utf-8"' in nginx, \
        "RFC 9116 §3 requires text/plain; nginx must state it, not infer it from the suffix"
    assert "types { }" in nginx, \
        "without an emptied MIME map the .txt suffix wins and default_type never applies"

    root = re.search(r"^\s*root\s+(\S+);", nginx, re.M)
    alias = re.search(r"^\s*alias\s+(\S+/security\.txt);", nginx, re.M)
    assert root and alias, "the marketing vhost lost its root or its security.txt alias"
    assert alias.group(1) == f"{root.group(1)}/security.txt", (
        f"the alias ({alias.group(1)}) points outside the deployed site root "
        f"({root.group(1)}) — the canonical URL would 404 on the VM")

    caddy = _block(_CADDY.read_text(encoding="utf-8"), "foxyaudit.tech, www.foxyaudit.tech {")
    assert "handle /.well-known/security.txt {" in caddy, \
        "nothing serves the canonical RFC 9116 path on the apex host"
    assert "rewrite * /security.txt" in caddy
    assert "root * /srv/sale" in caddy


def test_the_marketing_site_does_not_answer_a_missing_page_with_the_homepage():
    """A static multi-page site behind an SPA catch-all.

    `try_files $uri $uri/ /index.html` answered EVERY unknown URL with the
    homepage and 200 OK. That is what hid the defect above: tooling fetching
    /.well-known/security.txt got 200 and a page, and only a reader comparing the
    BODY could tell it was the wrong one. It also meant no dead link anywhere on
    this domain could be noticed, by a person or a crawler.

    An absence pin, like test_it_promises_no_bounty_and_no_response_time — the
    tempting edit is to put the fallback back the next time someone wants a
    pretty error page, and a pretty error page is a `location` of its own, not a
    200."""
    nginx = _marketing_vhost()
    catch_all = _block(nginx[nginx.index("location / {"):], "location / {")

    assert "/index.html;" not in catch_all, (
        "the marketing catch-all falls back to the homepage: every dead URL is "
        "200 OK and no 404 exists anywhere on foxyaudit.tech")
    assert "=404" in catch_all, "the catch-all must end in a real 404"
    assert "$uri.html" in catch_all, (
        "extensionless URLs stop resolving — desktop/settings_data.py ships "
        "https://foxyaudit.tech/docs and would land on a 404")


def test_the_served_directory_is_the_one_this_file_lives_in():
    """The rewrite targets /security.txt under /srv/sale, and /srv/sale is a bind
    mount of foxy-sale-page. If that mount moves, the route serves a 404 and the
    only thing that would notice is a researcher."""
    compose = (_ROOT / "deploy" / "docker-compose.prod.yml").read_text(encoding="utf-8")
    assert "../foxy-sale-page:/srv/sale:ro" in compose
    assert _TXT.is_file() and _TXT.parent.name == "foxy-sale-page"


def test_it_promises_no_bounty_and_no_response_time():
    """A published promise the project cannot keep is worse than no file. This
    pins the absence, because the tempting edit is to add one."""
    policy = _POLICY.read_text(encoding="utf-8").lower()
    assert "no bug bounty" in policy
    assert "no guaranteed response time" in policy
