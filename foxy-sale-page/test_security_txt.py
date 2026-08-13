"""security.txt (RFC 9116) — and the two ways a security.txt goes wrong.

It rots, or nothing serves it.

An expired file is worse than no file: it advertises a reporting channel and
then says the channel is stale. So the expiry is a TEST, not a calendar
reminder — CI turns red a month before the date, which is the only renewal
mechanism this project actually has.

And a file in the repo that no route serves is decoration. The route is asserted
against the real deploy/nginx-foxyaudit.conf, not described.

⚠ A THIRD WAY, found the hard way: every field can be well-formed, served, and
in date, and still be USELESS — because it points somewhere the reader cannot
go. This file listed a GitHub advisory URL first and a private-repo blob as its
Policy, and both 404 for everyone outside a repository that is private and
staying private. RFC 9116 §2.5.3 makes multiple Contact fields an order of
preference, so the dead route was the PREFERRED one. Reachability is now
asserted too, across all four surfaces that state the address.

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
#: The PUBLISHED policy — public, live, and what `Policy:` now cites. See
#: test_the_published_policy_is_the_one_that_is_reachable.
_PUBLIC_POLICY = _HERE / "report-abuse.html"

#: The one mailbox all four surfaces must name. Four places to state one address
#: is four places for it to drift.
SECURITY_MAILBOX = "security@foxyaudit.tech"

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


def test_all_four_surfaces_name_the_same_mailbox():
    """The correspondence guard, re-aimed. It used to pin support@ plus a GitHub
    advisory URL across security.txt and the README, and it passed the whole time
    BOTH of those were unreachable to anyone outside a private repository.

    ⚠ THE OLD VERSION WAS SATISFIED BY A DEAD CHANNEL. Pinning that two files
    agree is worth nothing if what they agree on cannot be reached. So the set is
    now four — and it includes the PUBLISHED page, which is the only one of them
    a stranger can actually open."""
    contacts = _fields()["contact"]
    assert contacts == [f"mailto:{SECURITY_MAILBOX}"], (
        f"security.txt should name exactly one reachable contact, has: {contacts}")

    readme = _README.read_text(encoding="utf-8")
    policy_md = _POLICY.read_text(encoding="utf-8")
    public = _PUBLIC_POLICY.read_text(encoding="utf-8")
    for name, blob in (("README.md", readme), ("SECURITY.md", policy_md),
                       ("report-abuse.html", public)):
        assert SECURITY_MAILBOX in blob, \
            f"{name} no longer names {SECURITY_MAILBOX} — the four have drifted"

    # …and none of them may re-offer a route that only works inside the private
    # repository. This is the specific regression, not a general tidiness rule.
    for name, blob in (("security.txt", _TXT.read_text(encoding="utf-8")),
                       ("README.md", readme),
                       ("report-abuse.html", public)):
        assert "security/advisories/new" not in blob, (
            f"{name} offers a GitHub security advisory again — the repository is "
            "private, so that URL 404s for every outside reporter")


def test_no_surface_publishes_a_url_into_the_private_repository():
    """Any github.com/<owner>/Foxy-Audit link is unreachable to the public. The
    SDK's own metadata carried two, under the WRONG owner besides, and they are
    rendered on the PyPI page where strangers click them."""
    for path in (_TXT, _README, _POLICY, _PUBLIC_POLICY,
                 _ROOT / "sdk" / "pyproject.toml"):
        blob = path.read_text(encoding="utf-8")
        # Strip comments in the two files whose comments EXPLAIN the dead links —
        # a note about a 404 is not a 404. Everything else is asserted as-is.
        if path.suffix in (".toml", ".txt"):
            blob = "\n".join(l.split("#", 1)[0] for l in blob.splitlines())
        elif path.name == "SECURITY.md":
            blob = blob.replace("> ", "")
        bad = re.findall(r"https?://(?:www\.)?github\.com/[\w.-]+/Foxy-Audit\S*", blob)
        assert not bad, f"{path.name} publishes a private-repo URL: {bad}"


def test_the_policy_link_points_at_something_the_public_can_open():
    """⚠ `Policy:` pointed at a SECURITY.md blob inside the private repo — a 404
    for the researcher the field exists to serve. It now cites the published
    page, and that page must actually be the disclosure policy rather than any
    page that happens to exist."""
    policy = _fields().get("policy", [])
    assert policy, "Policy is missing"
    assert policy == ["https://foxyaudit.tech/report-abuse.html"], \
        f"Policy should cite the published disclosure policy, has: {policy}"
    assert _PUBLIC_POLICY.is_file(), "report-abuse.html is missing, so Policy is a dead link"
    published = _PUBLIC_POLICY.read_text(encoding="utf-8")
    assert "we will not pursue legal action against you" in published, \
        "Policy cites a page that no longer carries the safe-harbour undertaking"
    assert "What is in scope" in published and "What is out of scope" in published, \
        "Policy cites a page that does not state its scope"


def test_the_repo_side_policy_defers_rather_than_restating():
    """#191. Two copies of a policy is how they drift, so SECURITY.md points at
    the public page and keeps only what needs repository access. If it ever grows
    its own safe-harbour wording again, there are two of them."""
    md = _POLICY.read_text(encoding="utf-8")
    assert "https://foxyaudit.tech/report-abuse.html" in md, \
        "SECURITY.md no longer points at the authoritative published policy"
    assert "authoritative" in md.lower()
    assert "we will not pursue legal action" not in md, \
        "SECURITY.md restates the safe harbour instead of deferring to it"


def test_the_honesty_survived_the_contacts_edit():
    """⚠ A contacts change must not sand these into boilerplate. Each is a
    deliberate absence with a stated reason, and each is the kind of line an
    editor tidies away."""
    md = _POLICY.read_text(encoding="utf-8")
    assert "There is no bug bounty, and no guaranteed response time." in md
    assert "worse for you than no promise at all" in md, "the REASON was removed"
    assert "no published PGP key today rather than a stale one" in md


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


def test_the_nginx_template_warns_that_it_carries_no_tls():
    """#178 — the config is a booby trap, and it already fired.

    deploy/nginx-foxyaudit.conf is a PRE-CERTBOT template: every server block is
    `listen 80;` with no ssl_certificate. The file in production is certbot's
    rewritten descendant. Copying the template over it discards every TLS block,
    which took HTTPS down on all four vhosts on 2026-08-13.

    ⚠ `nginx -t` PASSES on the result — it is valid nginx that does not speak
    HTTPS — and port 80 keeps answering 200, so the config test and a naive
    health check both report success.

    This guard pins the CORRESPONDENCE between the file's state and its own
    warning, which is the only thing a repo-side test can honestly check:

      * while the template has no TLS, the warning must be there and must name
        the certbot step and the back-up-first step;
      * if someone ever adds TLS blocks here, the warning becomes false and this
        goes red so they rewrite it rather than leaving a lie at the top.

    It cannot verify the live server. Only `curl -sI https://foxyaudit.tech`,
    on the https scheme and from off the box, can do that."""
    conf = _NGINX.read_text(encoding="utf-8")
    header = conf[:conf.index("# ── Site 1")]
    # ⚠ STRIP COMMENTS BEFORE ASKING WHETHER THE FILE HAS TLS. The header
    # above WARNS that there is "NO ssl_certificate", so a raw-text search for
    # that directive is answered by the warning about its absence and reports
    # TLS present. Measured: this guard failed on its first run for exactly that
    # reason. Ask what nginx would execute, never what the file says.
    directives = "\n".join(l.split("#", 1)[0] for l in conf.splitlines())
    has_tls = "ssl_certificate" in directives

    if not has_tls:
        assert "DOES NOT SPEAK HTTPS" in header,             "the template has no TLS and no longer says so at the top"
        assert "certbot --nginx" in header,             "the header does not name the step that puts TLS back"
        assert "cp /etc/nginx/sites-available/foxyaudit.conf" in header,             "the header does not tell you to back up the live file FIRST"
        assert header.index("cp /etc/nginx/sites-available/foxyaudit.conf")                < header.index("cp deploy/nginx-foxyaudit.conf"),             "the backup step must come BEFORE the copy that overwrites the live file"
        assert "nginx -t" in header and "https://" in header,             "the header must say that nginx -t is not sufficient and how to verify"
    else:
        assert "DOES NOT SPEAK HTTPS" not in header, (
            "the template now carries TLS blocks, but its header still warns that "
            "it does not — fix the header, it is the thing people act on")


def test_the_dead_edge_config_says_it_is_dead():
    """The Caddyfile describes the same four sites and serves none of them. It
    says so at the top; this keeps it saying so, because the last time a file in
    this repo described a deployment that was not the real one, the security.txt
    header sent readers to the wrong config for months."""
    caddy = _CADDY.read_text(encoding="utf-8")
    assert "THIS FILE DOES NOT SERVE PRODUCTION" in caddy
    assert "nginx-foxyaudit.conf" in caddy, "it does not name what DOES serve production"


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
