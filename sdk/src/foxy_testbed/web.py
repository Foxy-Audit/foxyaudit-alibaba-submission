"""``python -m foxy_testbed.web`` — the local page.

The second of the three surfaces. You open a page, type a prompt, and watch the
real ``foxy_audit`` preflight guard decide what happens to it. The page renders
the SAME :class:`~foxy_testbed.core.Turn` the REPL renders and the scoreboard
scores; ``core.py`` holds the logic and the page holds none of it.

⚠ 127.0.0.1 ONLY, AND THAT IS THE PRODUCT'S OWN CLAIM, NOT A DEV CONVENIENCE
============================================================================
:data:`BIND_HOST` is ``"127.0.0.1"`` and there is no flag to change it. A hosted
version of this page would put every prospect's typed prompt on Foxy
infrastructure — the exact thing the SDK exists to prevent, demonstrated in
reverse, on the sale path. The plan (``docs/plans/compliance-testbed.md`` §3)
calls that "the blocker nobody mentioned", and the answer is better than the
problem: because the server is one the user started on their own machine, the
page can say "nothing you type leaves this machine" and be structurally
incapable of doing otherwise. It is not a promise the page makes; it is a
property of where the socket is.

That is also why ``--host`` does not exist. A flag would turn a structural
property into a configurable one, and the page's own sentence would become a
claim about the flag's current value rather than about the program.

NO NEW RUNTIME DEPENDENCY, AND NO FRAMEWORK
===========================================
``http.server`` is in the standard library. ``requests`` is the SDK's only
dependency and stays that way — it is not imported here at all, because the
providers import it lazily and only a live one ever does.

THIS MODULE HOLDS NO POLICY LOGIC, AND CANNOT
=============================================
Exactly like :mod:`foxy_testbed.cli`, and asserted the same way: there is no
name from ``foxy_audit`` in this file, and ``test_web.py`` walks the AST to keep
it that way. Every sentence the page renders is read off a field or a property
of the ``Turn`` the engine handed back.

THE PAGE DOES NOT OWN THE VOCABULARY EITHER
===========================================
The verdict word and the sentence under it come from :func:`cli._headline`,
imported rather than reimplemented. Three front-ends each deciding for
themselves what "blocked" means is how the prevention-vs-evidence conflation got
rebuilt once already; a JavaScript copy of that function would be the third
copy. Reaching into ``cli``'s private name is deliberate and has precedent in
this package — ``cli`` imports ``scoreboard``'s ``_field``/``_rule``/``_wrap``
for the same reason, so that two surfaces cannot wrap the same policy note to
two different widths.

WHAT THE PAGE IS ALLOWED TO ASK FOR
===================================
Three routes and nothing else. A request whose ``Host`` is not this server's own
address is refused before it reaches the engine, and so is a cross-origin
``Origin`` — a page on the public internet can otherwise POST to a listener on
your loopback, and here that would mean spending the user's own provider key.
"""

from __future__ import annotations

import argparse
import json
import os
import secrets
import sys
import webbrowser
from http.server import BaseHTTPRequestHandler, HTTPServer
from importlib import resources

# Private, and deliberately — see the module docstring. The REPL's wording for a
# verdict is already correct and already reviewed; a second one written in
# JavaScript is a second one to drift.
from .cli import _headline
from .core import Assistant, DEFAULT_MODE, MODES
from .providers import PROVIDER_NAMES, ProviderError
from .sectors import SECTOR_NAMES, get_sector

#: ⚠ NOT CONFIGURABLE, ON PURPOSE. See the module docstring. Binding 0.0.0.0
#: would put a page that renders the user's own prompts on every interface the
#: machine has, which is the one thing this demo must not do.
BIND_HOST = "127.0.0.1"
DEFAULT_PORT = 8787

#: The page itself, beside this module and shipped inside the wheel. Read
#: through ``importlib.resources`` rather than assembled from ``__file__`` so it
#: keeps working wherever the package is imported from.
PAGE_FILENAME = "page.html"

#: Substituted with a fresh random nonce on every response, so the page's one
#: ``<style>`` and one ``<script>`` are the only ones its CSP admits.
NONCE_PLACEHOLDER = "__CSP_NONCE__"

#: A bound on the prompt, in CHARACTERS. Bigger than any probe in the corpus by
#: two orders of magnitude, and the limit a person can actually hit.
MAX_PROMPT_CHARS = 20_000

#: The most bytes one character can become inside a JSON request body. A Python
#: ``str`` counts an astral character as ONE, and the pessimal encoder --
#: ``json.dumps`` with its default ``ensure_ascii`` -- writes it as an escaped
#: surrogate pair, ``\uXXXX\uXXXX``, which is twelve bytes. A browser's
#: ``JSON.stringify`` sends raw UTF-8 and never exceeds four.
_WORST_JSON_BYTES_PER_CHAR = 12

#: A bound on the whole request body, so a local listener cannot be made to read
#: an arbitrary amount into memory.
#:
#: ⚠ DERIVED FROM THE PROMPT LIMIT RATHER THAN CHOSEN, BECAUSE THE TWO WERE
#: MEASURING THE SAME THING AND DISAGREEING. It was a flat 64 KiB, checked first
#: against raw bytes -- so a prompt of emoji hit the byte cap at about 5,400
#: characters and :data:`MAX_PROMPT_CHARS` was unreachable for anything but
#: Latin text. Two limits on one quantity, where the one a user is told about is
#: the one that never fires. Now the body cap cannot bite before the character
#: cap does, whatever the script; ``test_web.py`` asserts the derivation by
#: encoding a worst-case prompt rather than trusting this arithmetic.
MAX_BODY_BYTES = MAX_PROMPT_CHARS * _WORST_JSON_BYTES_PER_CHAR + 4096

#: Where each live provider's key is read from when --api-key is not given.
#: The same map ``__main__`` uses, so one flag cannot mean two things.
_KEY_ENV = {"openai": "OPENAI_API_KEY", "gemini": "GEMINI_API_KEY"}

#: `--foxy-key` with no value; and where it then reads from. Both spelled the
#: same way as in `__main__`, so one flag means one thing on both entry points.
_FROM_ENV = "<from FOXY_API_KEY>"
_FOXY_KEY_ENV = "FOXY_API_KEY"


# ── the sentences the page renders ────────────────────────────────────────────
def _reply_status(turn) -> str:
    """Why there is no reply to show, in the REPL's own words.

    ⚠ NOT ONE DECISION IS READ HERE, and the order of the branches is the whole
    point. ``cli.turn_lines`` ends on the same four sentences and arrived at them
    the hard way: its final branch used to say "the prompt was stopped before the
    provider was called" for everything unanswered, which includes a withheld
    RESPONSE — where the prompt reached the model and the tokens were spent.

    These strings are duplicated from that function rather than imported,
    because they live inside its body and are interleaved with line wrapping this
    surface does not do. ``test_web.py`` closes that gap the only way it can be
    closed honestly: for each of the four shapes it asserts this sentence appears
    verbatim in ``cli.turn_lines``'s own output for the same turn. If either side
    is reworded, the guard goes red rather than the two surfaces quietly
    disagreeing.

    ⚠ EMPTY WHEN THE TURN WAS ANSWERED, and that is not a shortcut for the
    renderer's benefit. Every branch below is a sentence about why there is no
    reply; on a turn that HAS one they are all false, and the fall-through said
    "the prompt reached the provider, and nothing came back to you" directly
    beside the reply that came back. The page never renders it in that state --
    but a payload that only reads correctly if its consumer remembers to check
    another field is a fabricated verdict waiting for the second consumer, and
    this is an audit product. It is empty because it has nothing to say.
    """
    if turn.answered:
        return ""
    if turn.empty_reply:
        return ("The provider returned an empty reply, so there is nothing to "
                "show. What the guard did to your prompt is unaffected and is "
                "reported above.")
    if turn.error:
        return "No reply: the provider call failed."
    if turn.reached_provider:
        return ("No reply: the prompt reached the provider, and nothing came "
                "back to you.")
    return "No reply: the prompt was stopped before the provider was called."


def turn_payload(turn) -> dict:
    """The record, plus the two sentences the engine does not carry.

    Everything else is :meth:`Turn.as_dict`, unaltered — including
    ``provider_is_live``, which is why this payload does not need to be told
    separately whether a reply came from a model. Before that field existed a
    JSON surface had to match the provider NAME against "mock", which is the
    re-derivation ``Scoreboard.provider_is_live`` exists to prevent.
    """
    label, sentence = _headline(turn)
    payload = turn.as_dict()
    payload["headline"] = label
    payload["headline_note"] = sentence
    payload["reply_status"] = _reply_status(turn)
    return payload


def _sector_payload(name: str) -> dict:
    """One preset, and the corpus that measures it.

    The probes ride along so the page can offer them as starters. They are the
    repository's own labelled corpus, carried verbatim with their expectation
    and their intent — an ``expect_block`` starter is presented as one, and a
    ``known_gap`` starter carries the reason nothing catches it. Nothing here is
    written for the page.
    """
    sector = get_sector(name)
    return {
        "name": sector.name,
        "title": sector.title,
        "policy_tag": sector.policy_tag,
        "policy_note": sector.policy_note,
        "probes": [{"id": p.id, "expect": p.expect, "prompt": p.prompt,
                    "intent": p.intent, "gap_reason": p.gap_reason}
                   for p in sector.probes],
    }


# ── the session ───────────────────────────────────────────────────────────────
class Testbed:
    """One assistant per (sector, mode), built from one provider configuration.

    ONE PER SECTOR AT STARTUP, then :meth:`Assistant.with_mode` for the rest.
    Building at startup is what makes a bad key fail before the browser opens
    rather than on the first prompt, and ``with_mode`` is what keeps a mode
    switch from silently dropping the client — it exists because T1's REPL
    rebuilt from sector/mode/provider alone and swapped a keyed session's client
    for a fresh keyless one.

    The mock provider's fixtures are built from the sector's own corpus, so the
    per-sector assistant is not an optimisation: one shared provider would answer
    healthcare's probes with finance's fixture map.
    """

    def __init__(self, provider: str = "mock", api_key: str = "",
                 model: str = "", mode: str = DEFAULT_MODE,
                 foxy_api_key: str = "", export: str = "",
                 salt_sidecar_path: str = "") -> None:
        self.mode = str(mode or DEFAULT_MODE).strip().lower()
        #: Where `/verify` reads the customer's own export, and the salt
        #: sidecar. Properties of the RUN, given on the command line --
        #: never asked for through the page, which would mean typing a
        #: filesystem path into a browser that then posts it back here.
        self.export = export
        self.salt_sidecar_path = salt_sidecar_path
        #: event_id -> (Turn, the Assistant that produced it).
        #:
        #: ⚠ THE SERVER REMEMBERS WHAT IT RECORDED; THE PAGE DOES NOT TELL
        #: IT. `/verify` could have taken `submitted` from the request and
        #: saved this dict -- and then a front-end would be asserting
        #: whether a row reached a ledger, which is precisely the class of
        #: decision no surface in this package is allowed to make. The page
        #: sends an id and the prompt; every claim comes from here.
        self._turns = {}
        self._assistants = {}
        for name in SECTOR_NAMES:
            self._assistants[(name, self.mode)] = Assistant(
                name, mode=self.mode, provider=provider,
                api_key=api_key, model=model, foxy_api_key=foxy_api_key)
        # Every sector shares one provider CONFIGURATION, so any of them answers
        # for it. Read off an assistant rather than off the constructor's
        # arguments: `Assistant` resolves "" and None to real defaults, and the
        # page must report what is actually running.
        self.provider = self._assistants[(SECTOR_NAMES[0], self.mode)].provider

    def assistant(self, sector: str, mode: str):
        key = (sector, mode)
        found = self._assistants.get(key)
        if found is None:
            found = self._assistants[(sector, self.mode)].with_mode(mode)
            self._assistants[key] = found
        return found

    #: How many turns stay verifiable. A page session is short and this is a
    #: local process, but an unbounded dict fed by a loop is still a leak.
    #: Oldest out first, and the page is told when an id has aged out
    #: rather than being answered as though the turn never existed.
    MAX_REMEMBERED = 50

    def ask(self, sector: str, mode: str, prompt: str) -> dict:
        assistant = self.assistant(sector, mode)
        turn = assistant.ask(prompt)
        if turn.event_id:
            self._turns[turn.event_id] = (turn, assistant)
            while len(self._turns) > self.MAX_REMEMBERED:
                self._turns.pop(next(iter(self._turns)))
        return turn_payload(turn)

    def verify(self, event_id: str, prompt: str) -> dict:
        """Trace one remembered turn to its row. → a plain dict, or None.

        None means this server has no such turn, which the caller reports
        as a 404 rather than inventing an outcome for it. The DECISION is
        `Assistant.verify`'s; this only looks the turn up.
        """
        found = self._turns.get(str(event_id))
        if found is None:
            return None
        turn, assistant = found
        return assistant.verify(
            turn, prompt, export=self.export,
            salt_sidecar_path=self.salt_sidecar_path).as_dict()

    def config(self, bind: str) -> dict:
        provider = self.provider
        return {
            "bind": bind,
            "modes": list(MODES),
            "mode": self.mode,
            "provider": {"name": provider.name, "model": provider.model,
                         # Carried, never re-derived from the name — the same
                         # rule Turn.provider_is_live is here to enforce.
                         "is_live": provider.is_live, "note": provider.note},
            "sectors": [_sector_payload(name) for name in SECTOR_NAMES],
        }


# ── the server ────────────────────────────────────────────────────────────────
def _page_source() -> str:
    return resources.files(__package__).joinpath(PAGE_FILENAME).read_text(
        encoding="utf-8")


class Handler(BaseHTTPRequestHandler):
    """Three routes. Everything else is a 404, including every path a browser
    asks for speculatively.

    ``testbed`` and ``bind`` are set on the class by :func:`build_server`.
    """

    testbed = None
    bind = ""

    server_version = "foxy-testbed"
    sys_version = ""

    #: ⚠ WITHOUT THIS A SINGLE IDLE CONNECTION WEDGES THE WHOLE SERVER, silently.
    #: :func:`build_server` is deliberately serial (see its docstring), so the
    #: one request in progress is the only one there is -- and a client that
    #: opens a socket and sends nothing leaves ``readline`` blocked forever with
    #: no error anywhere. That is not a hypothetical: a browser's speculative
    #: preconnect does exactly this, and so does any port scan.
    #:
    #: ``socketserver.StreamRequestHandler.setup`` applies it to the connection,
    #: and ``BaseHTTPRequestHandler.handle_one_request`` already treats the
    #: resulting timeout as a closed connection rather than an error. Generous,
    #: because a human pasting into a textarea is not the slow client here.
    timeout = 10

    # ── guards ────────────────────────────────────────────────────────────────
    def _origin_ok(self) -> bool:
        """Refuse a request some other page told the browser to make.

        ⚠ A LOOPBACK LISTENER IS NOT A PRIVATE ONE. Any page on the internet can
        make a browser POST to 127.0.0.1:8787; it cannot read the response
        without CORS headers, which this server never sends, but the SIDE EFFECT
        still happens — and on a live provider that side effect spends the
        user's own key on a prompt they did not type. So the request is refused
        before it reaches the engine.

        An absent ``Origin`` is allowed: a same-origin GET does not carry one,
        and neither does ``curl``, which is how the offline gate drives this.
        A same-origin POST from the page DOES carry one, and it matches.
        """
        origin = self.headers.get("Origin")
        if origin is None:
            return True
        return origin in ("http://{0}".format(self.bind),
                          "http://localhost:{0}".format(self.bind.rsplit(":", 1)[-1]))

    def _host_ok(self) -> bool:
        """Refuse a name that resolves here but is not here.

        DNS rebinding: a hostname the attacker controls, pointed at 127.0.0.1,
        makes the browser treat this server as same-origin with their page. The
        socket cannot tell the difference; the ``Host`` header can.
        """
        host = (self.headers.get("Host") or "").strip()
        port = self.bind.rsplit(":", 1)[-1]
        return host in (self.bind, "localhost:{0}".format(port))

    # ── responses ─────────────────────────────────────────────────────────────
    def _headers(self, status: int, content_type: str, length: int,
                 nonce: str = "") -> None:
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(length))
        # No CDN, nothing external, and no way for a scriptable payload to
        # arrive: `default-src 'none'` denies every fetch this page does not
        # make, and the nonce means even an injected inline <script> would not
        # run. Nothing on the page is ever assigned through innerHTML either --
        # two independent defences, deliberately.
        self.send_header(
            "Content-Security-Policy",
            "default-src 'none'; "
            "script-src 'nonce-{0}'; style-src 'nonce-{0}'; "
            "img-src 'self' data:; connect-src 'self'; "
            "base-uri 'none'; form-action 'none'; frame-ancestors 'none'".format(
                nonce or "none"))
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("Referrer-Policy", "no-referrer")
        # A demo whose whole subject is what reached the model must not have a
        # stale verdict served back to it from a cache.
        self.send_header("Cache-Control", "no-store")
        self.end_headers()

    def _send_json(self, status: int, payload: dict) -> None:
        body = json.dumps(payload).encode("utf-8")
        self._headers(status, "application/json; charset=utf-8", len(body))
        self.wfile.write(body)

    def _send_page(self) -> None:
        nonce = secrets.token_urlsafe(16)
        body = _page_source().replace(NONCE_PLACEHOLDER, nonce).encode("utf-8")
        self._headers(200, "text/html; charset=utf-8", len(body), nonce=nonce)
        self.wfile.write(body)

    # ── routes ────────────────────────────────────────────────────────────────
    def do_GET(self) -> None:                          # noqa: N802 — stdlib name
        if not self._host_ok():
            self._send_json(421, {"error": "wrong host",
                                  "detail": "this server answers only to "
                                            "{0}".format(self.bind)})
            return
        path = self.path.split("?", 1)[0]
        if path == "/":
            self._send_page()
        elif path == "/session":
            self._send_json(200, self.testbed.config(self.bind))
        else:
            self._send_json(404, {"error": "no such route",
                                  "detail": "this server serves /, /session, "
                                            "/turn and /verify."})

    def do_POST(self) -> None:                         # noqa: N802 — stdlib name
        if not self._host_ok():
            self._send_json(421, {"error": "wrong host",
                                  "detail": "this server answers only to "
                                            "{0}".format(self.bind)})
            return
        if not self._origin_ok():
            self._send_json(403, {"error": "cross-origin request refused",
                                  "detail": "another page asked your browser to "
                                            "send this. Nothing was run."})
            return
        route = self.path.split("?", 1)[0]
        if route not in ("/turn", "/verify"):
            self._send_json(404, {"error": "no such route",
                                  "detail": "this server serves /, /session, "
                                            "/turn and /verify."})
            return

        try:
            length = int(self.headers.get("Content-Length") or 0)
        except ValueError:
            length = -1
        if length < 0 or length > MAX_BODY_BYTES:
            self._send_json(413, {"error": "request too large",
                                  "detail": "the body must be at most {0} "
                                            "bytes.".format(MAX_BODY_BYTES)})
            return
        try:
            body = json.loads(self.rfile.read(length).decode("utf-8") or "{}")
        except (UnicodeDecodeError, ValueError):
            self._send_json(400, {"error": "the body was not JSON"})
            return
        if not isinstance(body, dict):
            self._send_json(400, {"error": "the body was not a JSON object"})
            return

        if route == "/verify":
            self._do_verify(body)
            return

        sector = str(body.get("sector") or "")
        mode = str(body.get("mode") or "")
        prompt = body.get("prompt")
        if not isinstance(prompt, str) or not prompt.strip():
            self._send_json(400, {"error": "no prompt",
                                  "detail": "send a non-empty prompt."})
            return
        if len(prompt) > MAX_PROMPT_CHARS:
            self._send_json(413, {"error": "prompt too long",
                                  "detail": "at most {0} characters.".format(
                                      MAX_PROMPT_CHARS)})
            return
        if sector not in SECTOR_NAMES:
            self._send_json(400, {"error": "unknown sector",
                                  "detail": "one of {0}.".format(
                                      ", ".join(SECTOR_NAMES))})
            return
        if mode not in MODES:
            self._send_json(400, {"error": "unknown mode",
                                  "detail": "one of {0}.".format(", ".join(MODES))})
            return

        try:
            payload = self.testbed.ask(sector, mode, prompt)
        except Exception as exc:                       # noqa: BLE001
            # ⚠ THE ENGINE ALREADY CATCHES A PROVIDER FAILURE and returns it as
            # a Turn with decision="error", which is a rendered verdict rather
            # than a broken page. Reaching here means something else went wrong,
            # so it reports the exception TYPE and no message: a message could
            # carry text the user typed, and the one thing this server must
            # never do is put a prompt somewhere the user did not put it.
            self._send_json(500, {"error": "the turn could not be run",
                                  "detail": type(exc).__name__})
            return
        self._send_json(200, payload)

    def _do_verify(self, body: dict) -> None:
        """Trace one turn to its ledger row.

        ⚠ THE PROMPT COMES BACK UP AND NEVER GOES BACK DOWN. `explain`
        recomputes the commitment from the text the user supplies -- Foxy never
        had it -- so the page has to send it again. Nothing in the response
        carries it: `Evidence.as_dict` omits the matched spans for the same
        reason the SDK's own `ExplainResult.as_dict` does, and the access log
        below never sees a body at all.
        """
        event_id = body.get("event_id")
        prompt = body.get("prompt")
        if not isinstance(event_id, str) or not event_id.strip():
            self._send_json(400, {"error": "no event id",
                                  "detail": "send the event_id of a turn this "
                                            "server ran."})
            return
        if not isinstance(prompt, str) or not prompt.strip():
            self._send_json(400, {"error": "no prompt",
                                  "detail": "verifying replays the text you "
                                            "sent, so it has to be sent again."})
            return
        if len(prompt) > MAX_PROMPT_CHARS:
            self._send_json(413, {"error": "prompt too long",
                                  "detail": "at most {0} characters.".format(
                                      MAX_PROMPT_CHARS)})
            return
        try:
            payload = self.testbed.verify(event_id, prompt)
        except Exception as exc:                       # noqa: BLE001
            # The TYPE only, exactly as /turn does: a message could carry the
            # text the user typed, and putting a prompt somewhere the user did
            # not put it is the one thing this server must never do.
            self._send_json(500, {"error": "the check could not be run",
                                  "detail": type(exc).__name__})
            return
        if payload is None:
            # ⚠ NOT AN OUTCOME. This server does not know that turn -- it aged
            # out, or came from a different run -- and answering with any
            # `explain` status would be inventing one.
            self._send_json(404, {
                "error": "this server did not run that turn",
                "detail": "only the most recent turns of THIS session can be "
                          "traced from here. Send the prompt again and verify "
                          "the new turn."})
            return
        self._send_json(200, payload)

    def log_message(self, fmt, *args) -> None:
        """One line per request, on stderr, and never the query string.

        The default handler writes ``self.requestline``, which is the raw
        request line. Nothing this page sends puts a prompt in a URL — the turn
        goes in a POST body — but a log line is exactly the kind of place a
        prompt ends up by accident, so the path is truncated at "?" rather than
        trusted to stay clean.
        """
        sys.stderr.write("  {0} {1}\n".format(
            self.command or "-", (self.path or "-").split("?", 1)[0]))


def build_server(testbed: Testbed, port: int = DEFAULT_PORT):
    """An ``HTTPServer`` on the loopback, wired to ``testbed``.

    ⚠ ``HTTPServer``, NOT ``ThreadingHTTPServer``, AND THAT IS A CORRECTNESS
    REQUIREMENT RATHER THAN A DEFAULT. ``Assistant`` is single-threaded by
    design: it records what the guard did on a per-INSTANCE flag
    (``_reached``/``_delivered``, set by the wrapped call and read after it
    returns), so two turns running at once through one assistant would read each
    other's observations — and those observations are what every enforcement
    claim on the page is measured from. A serial server makes that impossible
    instead of guarding against it. ``test_web.py`` pins the class.

    ``port=0`` asks the OS for a free one, which is why ``bind`` is filled in
    AFTER the socket exists rather than formatted from the argument: with 0 the
    argument is not the port, and a ``Host`` guard comparing against
    ``127.0.0.1:0`` would refuse every request. Asking the bound socket also
    means nothing here has to probe for a free port first -- a probe that sets
    SO_REUSEADDR, as a listener does, reports every port free.
    """
    # A subclass per server rather than mutating `Handler` itself, so two
    # servers in one process (which the tests build) cannot take each other's
    # testbed.
    handler = type("BoundHandler", (Handler,), {"testbed": testbed, "bind": ""})
    server = HTTPServer((BIND_HOST, port), handler)
    handler.bind = "{0}:{1}".format(BIND_HOST, server.server_address[1])
    return server


# ── entry point ───────────────────────────────────────────────────────────────
def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="python -m foxy_testbed.web",
        description=("Serve the compliance testbed on http://127.0.0.1:8787 -- "
                     "a page where you type a prompt and watch the real Foxy "
                     "Audit guard decide what happens to it. The server is "
                     "local and there is no flag to make it otherwise: nothing "
                     "you type leaves this machine except to your own model "
                     "provider, under your own key. Offline and keyless by "
                     "default."),
    )
    # The same "not given" discipline as `__main__`: every configuration flag
    # defaults to None so that the engine's defaults stay the single source of
    # what "not given" means. `--sector` is absent on purpose — the page picks
    # the sector, and all three are built at startup.
    parser.add_argument("--port", type=int, default=DEFAULT_PORT,
                        help="port on 127.0.0.1 (default: {0})".format(DEFAULT_PORT))
    parser.add_argument("--mode", default=None, choices=MODES,
                        help="preflight mode the page opens on (default: {0})".format(
                            DEFAULT_MODE))
    parser.add_argument("--provider", default=None, choices=PROVIDER_NAMES,
                        help=("mock is offline, deterministic and needs no key "
                              "(default: mock)"))
    parser.add_argument("--model", default=None,
                        help="override the provider's default model id")
    parser.add_argument("--api-key", default=None,
                        help=("key for a live provider; falls back to "
                              "OPENAI_API_KEY / GEMINI_API_KEY"))
    # ── T4: reaching a ledger, and then checking the row ──────────────────
    # See `__main__.build_parser` for why the environment is read only when
    # the flag is typed. One flag, one meaning, in both entry points.
    parser.add_argument("--foxy-key", nargs="?", default=None,
                        const=_FROM_ENV, metavar="KEY",
                        help=("your FOXY key -- the one that makes a turn "
                              "reach a ledger at all. Bare --foxy-key reads "
                              "FOXY_API_KEY. Without it nothing is shipped "
                              "anywhere (the default)"))
    parser.add_argument("--export", default=None, metavar="FILE",
                        help=("your own GET /v1/logs/export?format=json "
                              "document, so the page can verify a row"))
    parser.add_argument("--sidecar", default=None, metavar="FILE",
                        help=("the salt sidecar the SDK wrote, for rows "
                              "committed with a per-event salt"))
    parser.add_argument("--no-browser", action="store_true",
                        help="do not open a browser window")
    return parser


def serve(server, open_browser: bool = True) -> int:
    host, port = server.server_address[0], server.server_address[1]
    url = "http://{0}:{1}/".format(host, port)
    print("  Foxy Audit -- compliance testbed")
    print("  {0}".format(url))
    print("  Local only. Nothing you type leaves this machine except to your")
    print("  own model provider, under your own key. Ctrl-C to stop.")
    if open_browser:
        try:
            webbrowser.open(url)
        except Exception:                              # noqa: BLE001
            # A machine with no browser is a normal way to run this (a server, a
            # container, a session over ssh). The URL is already printed.
            pass
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("")
        print("  bye.")
    finally:
        server.server_close()
    return 0


def main(argv=None) -> int:
    args = build_parser().parse_args(argv)

    api_key = args.api_key
    if api_key is None and args.provider in _KEY_ENV:
        api_key = os.getenv(_KEY_ENV[args.provider]) or None

    # Refused loudly rather than degraded: a user who typed --foxy-key and
    # got a keyless server anyway would watch every turn report "never
    # shipped to a ledger" with no way to tell that from the offline
    # default they were trying to leave.
    foxy_key = args.foxy_key
    if foxy_key == _FROM_ENV:
        foxy_key = os.getenv(_FOXY_KEY_ENV) or ""
        if not foxy_key:
            print("Could not start: --foxy-key was given with no value and "
                  "{0} is not set. Pass the key, or set that variable."
                  .format(_FOXY_KEY_ENV), file=sys.stderr)
            return 2
    elif foxy_key is not None and not foxy_key.strip():
        print("Could not start: --foxy-key was given an empty value. Omit "
              "the flag to run offline, which is the default.",
              file=sys.stderr)
        return 2

    try:
        testbed = Testbed(provider=args.provider or "mock", api_key=api_key or "",
                          model=args.model or "", mode=args.mode or DEFAULT_MODE,
                          foxy_api_key=foxy_key or "",
                          export=args.export or "",
                          salt_sidecar_path=args.sidecar or "")
    except (ProviderError, ValueError) as exc:
        print("Could not start: {0}".format(exc), file=sys.stderr)
        return 2
    try:
        server = build_server(testbed, port=args.port)
    except OSError as exc:
        # Almost always "port already in use", and almost always a testbed the
        # user forgot they left running. Named rather than tracebacked.
        print("Could not listen on {0}:{1}: {2}".format(BIND_HOST, args.port, exc),
              file=sys.stderr)
        return 2
    return serve(server, open_browser=not args.no_browser)


if __name__ == "__main__":
    sys.exit(main())


__all__ = ["BIND_HOST", "DEFAULT_PORT", "Handler", "MAX_PROMPT_CHARS",
           "PAGE_FILENAME", "Testbed", "build_parser", "build_server", "main",
           "serve", "turn_payload"]
