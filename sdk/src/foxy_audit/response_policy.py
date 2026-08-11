"""Response-side policy evaluation — OWASP **LLM05, Improper Output Handling**.

`evaluate_response(value, policy_tag)` inspects what the model RETURNED and
returns a :class:`policy.PolicyDecision` — the same content-blind shape the
prompt side already uses: rule ids and coarse signal labels, never the matched
text, never an offset, never a length. Raw response text never leaves this
module, exactly as raw prompt text never leaves ``policy.py``.

WHY THIS IS NOT THE PROMPT'S RULE SET RUN BACKWARDS
---------------------------------------------------
The prompt rules answer "what is being SENT to the model". LLM05 asks "what
will the caller DO with what came back", and the two lists only partly overlap:

  reused as-is
    ``secret``  a model that echoes an API key or a private key back into its
                answer has leaked one just as surely as a prompt that carried
                it. Same regexes, re-identified ``response_secret.*``.
    ``phi``/``pii``
                regurgitated personal data is the response-side case the prompt
                side cannot see: the prompt need never have contained it.
                ``pii.detect_pii`` verbatim, re-identified ``response_phi.*`` /
                ``response_pii.*``.

  deliberately NOT ported — and this is the honest answer, not an oversight
    ``injection``
                "ignore all previous instructions" in a RESPONSE is the model
                quoting the phrase, summarising an article about it, or being
                asked to explain it. The genuine response-side hazard is the
                model having *complied* with an injection, and compliance has
                no regex — it is a semantic judgement, which is what the
                backend judge is for. Porting these rules would add noise and
                no signal, so they are not ported.

  new here, because nothing on the prompt side covers them
    ``response_markup``  markup that will be rendered — the canonical LLM05
                         case (script tag, iframe, an ``on*=`` handler, a
                         ``javascript:`` URI in an attribute, ``data:text/html``).
    ``response_sql``     a statement the caller might execute.
    ``response_url``     an SSRF-shaped URL: loopback, RFC1918, link-local
                         (169.254.169.254 is the cloud metadata endpoint), or
                         ``file://``.

WHAT THE RULES DO NOT PROMISE
-----------------------------
These are regexes, not a parser. A model *explaining* SQL will trip
``response_sql.destructive``; that is why the default posture is to RECORD a
signal rather than to prevent anything (see ``FoxyConfig.response_scan``).
Blocking on these is opt-in precisely because a false positive on the response
side raises into the caller's own code.

Structured responses (a provider object, a list of stream chunks) are scanned
through :func:`scan_text`, i.e. their canonical-JSON form. The ASCII patterns
here survive that encoding; a rule that needed to match non-ASCII would not, and
none does. An object whose content is not reachable scans as "" — see
:func:`scan_text` for why scanning its repr would be actively harmful.
"""

from __future__ import annotations

import re

from . import pii, policy
from .policy import PolicyDecision

# ── markup that will be rendered (the canonical LLM05 case) ──────────────────
_MARKUP_RULES = (
    ("response_markup.script_tag", "unsafe_markup", re.compile(r"<\s*script[\s/>]", re.IGNORECASE)),
    ("response_markup.iframe", "unsafe_markup", re.compile(r"<\s*iframe[\s/>]", re.IGNORECASE)),
    # An inline event handler on any tag: <img src=x onerror=alert(1)>. Bounded
    # so a pathological line cannot make this quadratic.
    ("response_markup.event_handler", "unsafe_markup", re.compile(
        r"<\s*[a-z][^<>]{0,512}\son[a-z]{3,15}\s*=", re.IGNORECASE)),
    # Only inside an attribute. Bare "javascript:" appears in ordinary prose
    # ("JavaScript: the good parts") and flagging that is noise, not signal.
    ("response_markup.javascript_uri", "unsafe_markup", re.compile(
        r"(?:href|src|action|formaction)\s*=\s*[\"']?\s*javascript\s*:", re.IGNORECASE)),
    ("response_markup.data_html_uri", "unsafe_markup", re.compile(
        r"data:\s*text/html", re.IGNORECASE)),
)

# ── a statement the caller might execute ─────────────────────────────────────
_SQL_RULES = (
    ("response_sql.destructive", "unsafe_sql", re.compile(
        r"\b(?:drop\s+(?:table|database|schema)|truncate\s+table|delete\s+from|alter\s+table)\b",
        re.IGNORECASE)),
    ("response_sql.tautology", "unsafe_sql", re.compile(
        r"\bor\s+(?:1\s*=\s*1|'1'\s*=\s*'1'|\"1\"\s*=\s*\"1\")", re.IGNORECASE)),
    ("response_sql.stacked_statement", "unsafe_sql", re.compile(
        r";\s*(?:drop|delete|update|insert|truncate|alter)\b", re.IGNORECASE)),
)

# ── SSRF-shaped URLs ─────────────────────────────────────────────────────────
_URL_RULES = (
    ("response_url.private_host", "unsafe_url", re.compile(
        r"https?://(?:localhost|127\.\d{1,3}\.\d{1,3}\.\d{1,3}|0\.0\.0\.0"
        r"|10\.\d{1,3}\.\d{1,3}\.\d{1,3}"
        r"|192\.168\.\d{1,3}\.\d{1,3}"
        r"|172\.(?:1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3}"
        r"|169\.254\.\d{1,3}\.\d{1,3}"
        r"|\[::1\]|metadata\.google\.internal)", re.IGNORECASE)),
    ("response_url.file_scheme", "unsafe_url", re.compile(r"\bfile://", re.IGNORECASE)),
)

# Secret detection is the prompt side's, re-identified for the response.
_SECRET_RULES = tuple(
    (f"response_secret.{rule_id.split('.', 1)[1]}", signal, regex)
    for rule_id, signal, regex in policy._SECRET_RULES
)

# LLM05 is about what the CALLER does with the output, which does not depend on
# which compliance regime the workspace runs under — so these run for every
# policy tag. Personal data does depend on it, and follows the prompt side's map.
_ALWAYS = _MARKUP_RULES + _SQL_RULES + _URL_RULES + _SECRET_RULES
_POLICY_PERSONAL = {"hipaa": "response_phi", "gdpr": "response_pii"}

# How much of the previous chunk a streaming scan carries forward. A rule can
# only match across a boundary if the two halves are closer together than this.
CARRY_CHARS = 256


def _personal_prefix(policy_tag: str) -> str | None:
    return _POLICY_PERSONAL.get((policy_tag or "").strip().lower())


def _is_serialisable(value) -> bool:
    """Whether ``hashing.canonical_json`` can reach this object's CONTENT."""
    return (hasattr(value, "model_dump")
            or (hasattr(value, "dict") and callable(value.dict))
            or (hasattr(value, "to_dict") and callable(value.to_dict)))


def scan_text(value) -> str:
    """The text a response rule actually sees.

    NOT ``policy._as_text``, and the difference is a bug rather than a taste.
    That helper falls back to ``str(value)`` for an object it cannot serialise,
    which for an opaque provider object means its repr —
    ``<Foo object at 0x1234567890>``. That string contains no response content
    and DOES contain a memory address, which is a random run of digits, which
    ``pii._PHONE_RE`` matches whenever the run comes out the right length. Under
    ``response_scan="block"`` that is a real response blocked at random, on a
    schedule set by the allocator. Scanning an address is worse than scanning
    nothing, so an unreachable object scans as "".

    Every mainstream provider object IS reachable — the OpenAI and Anthropic
    SDKs return pydantic models (``model_dump``), Gemini exposes ``to_dict`` —
    so this costs coverage only where there was no content to cover.
    """
    if isinstance(value, str):
        return value
    if _is_serialisable(value):
        return policy._as_text(value)
    if isinstance(value, dict):
        return "\n".join(scan_text(v) for v in value.values())
    if isinstance(value, (list, tuple)):
        return "\n".join(scan_text(v) for v in value)
    return ""


def evaluate_response(value, policy_tag: str = "default") -> PolicyDecision:
    """Evaluate a model response under ``policy_tag``; return labels only."""
    text = scan_text(value)
    rules: list[str] = []
    signals: list[str] = []

    prefix = _personal_prefix(policy_tag)
    if prefix:
        for label in pii.detect_pii(text, ""):
            rules.append(f"{prefix}.{label}")
            signals.append(label)

    for rule_id, signal, regex in _ALWAYS:
        if regex.search(text):
            rules.append(rule_id)
            signals.append(signal)

    return PolicyDecision(action="flag" if rules else "allow",
                          rules=sorted(set(rules)),
                          signals=sorted(set(signals)))


class StreamScanner:
    """Scan a stream chunk by chunk, with a carry-over window.

    A rule can match ACROSS a chunk boundary — an SSN arriving as ``"123-45"``
    then ``"-6789"`` is invisible to a scanner that only ever sees one chunk at
    a time. So each scan covers ``tail(everything scanned so far) + chunk``,
    where the tail is :data:`CARRY_CHARS` long.

    Carrying a clean tail cannot manufacture a false positive: the tail was
    part of a window that already came back clean, so no rule matched inside it
    alone, and any match in ``tail + chunk`` therefore involves at least one
    character of ``chunk``.

    It CAN still miss: a pattern whose halves land more than ``CARRY_CHARS``
    apart is not detected. That bound is the price of not buffering the whole
    stream, and it is stated in the SDK docs rather than papered over.
    """

    __slots__ = ("_policy_tag", "_carry")

    def __init__(self, policy_tag: str = "default") -> None:
        self._policy_tag = policy_tag
        self._carry = ""

    def feed(self, chunk) -> PolicyDecision | None:
        """Return a triggered decision for this chunk, or ``None`` if clean."""
        text = self._carry + scan_text(chunk)
        decision = evaluate_response(text, self._policy_tag)
        self._carry = text[-CARRY_CHARS:]
        return decision if decision.triggered else None
