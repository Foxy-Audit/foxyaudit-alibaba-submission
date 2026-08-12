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


def test_a_route_actually_serves_it():
    """The half that makes this more than a file in a repo.

    Read out of the real Caddyfile: the apex site must handle the canonical
    RFC 9116 path, and it must resolve to the file committed here. Asserted as a
    SLICE OF THE APEX SITE BLOCK, not a grep of the whole file — the checkout
    site further down also has a root/file_server pair and would satisfy a
    loose search."""
    caddy = _CADDY.read_text(encoding="utf-8")
    start = caddy.index("foxyaudit.tech, www.foxyaudit.tech {")
    depth, end = 0, None
    for i in range(start, len(caddy)):
        if caddy[i] == "{":
            depth += 1
        elif caddy[i] == "}":
            depth -= 1
            if depth == 0:
                end = i
                break
    assert end is not None, "could not find the end of the apex site block"
    apex = caddy[start:end]

    assert "handle /.well-known/security.txt {" in apex, \
        "nothing serves the canonical RFC 9116 path on the apex host"
    assert "rewrite * /security.txt" in apex
    assert "root * /srv/sale" in apex


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
