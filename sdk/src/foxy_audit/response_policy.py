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

WHAT THE RULES ARE APPLIED TO
----------------------------
Response CONTENT, extracted by ``adapters.response_text`` — the delta text of a
provider chunk, not the JSON envelope around it. Scanning the envelope was the
defect this module shipped with: two halves of a split match ended up ~30
characters apart and the streaming carry window rejoined nothing.

When the shape cannot be read, that is recorded as degraded coverage rather
than passed off as a clean scan. Coverage never blocks — an unfamiliar object
is missing evidence, not a finding.
"""

from __future__ import annotations

import re

from . import adapters, pii, policy
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

# Keyed by the CANONICAL tag and resolved through policy.resolve_policy_tag, so
# an alias means the same thing on both sides. This map is why the alias fix is
# not a one-line change to the prompt side: `hipaa_basic` resolving to PHI on
# the prompt while this map still matched a literal `hipaa_basic` would leave
# the response half of a HIPAA workspace with no personal-data scan at all.
_POLICY_PERSONAL = {"hipaa": "response_phi", "gdpr": "response_pii"}

# How much of the previous chunk a streaming scan carries forward. A rule can
# only match across a boundary if the two halves are closer together than this.
CARRY_CHARS = 256


def _personal_prefix(policy_tag: str) -> str | None:
    # `_resolve_or_warn`, not the silent `resolve_policy_tag`, so an unrecognised
    # tag is still reported under mode="observe" — where the prompt guard never
    # runs and this is the only side that resolves the tag at all. The warning
    # dedupes per tag per process, so the two call sites cannot double-report.
    return _POLICY_PERSONAL.get(policy._resolve_or_warn(policy_tag))


def scan_source(value) -> tuple[str, str]:
    """(text, coverage) for one response value — see ``adapters.response_text``.

    A thin alias so the scan has one name for "what am I actually reading", and
    so nothing in this module ever calls ``policy._as_text``. That helper
    serialises to canonical JSON, which is right for a prompt and wrong twice
    over for a response: it wraps content fragments in ~30 characters of
    envelope, so a stream's carry window rejoins nothing; and it falls back to
    ``str(value)``, so an opaque object is scanned as its repr — a memory
    address, a random digit run, matched by the phone detector whenever it comes
    out the right length."""
    return adapters.response_text(value)


def _match(text: str, policy_tag: str) -> tuple[list[str], list[str]]:
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
    return rules, signals


_COVERAGE_RULES = {
    adapters.COVERAGE_DEGRADED: ("response_scan.degraded", "scan_degraded"),
    adapters.COVERAGE_NONE: ("response_scan.unreadable", "scan_unreadable"),
}


def coverage_rule(coverage: str) -> str | None:
    """The informational rule id for a coverage level, or None when it is full."""
    pair = _COVERAGE_RULES.get(coverage)
    return pair[0] if pair else None


def evaluate_response(value, policy_tag: str = "default") -> PolicyDecision:
    """Evaluate a model response under ``policy_tag``; return labels only.

    Degraded or absent coverage is recorded as an INFORMATIONAL rule id
    (``response_scan.degraded`` / ``response_scan.unreadable``) while ``action``
    stays ``"allow"``. Both halves of that matter. Recording it means a shape the
    scanner could not read shows up in the evidence as unread rather than as
    clean — silence there is the failure mode this phase was sent back for. And
    not flagging it means an unfamiliar provider object cannot start raising
    ``FoxyResponseBlocked`` on responses that contain nothing wrong: coverage we
    do not have is not a finding.
    """
    text, coverage = scan_source(value)
    rules, signals = _match(text, policy_tag)
    action = "flag" if rules else "allow"
    informational = _COVERAGE_RULES.get(coverage)
    if informational:
        rules.append(informational[0])
        signals.append(informational[1])
    return PolicyDecision(action=action,
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

    __slots__ = ("_policy_tag", "_carry", "coverage")

    def __init__(self, policy_tag: str = "default") -> None:
        self._policy_tag = policy_tag
        self._carry = ""
        #: Worst coverage seen across every chunk fed so far. A stream is only
        #: as well-scanned as its least-readable chunk.
        self.coverage = adapters.COVERAGE_FULL

    def feed(self, chunk) -> PolicyDecision | None:
        """Return a triggered decision for this chunk, or ``None`` if clean.

        The carry holds CONTENT, not the serialised chunk. That is the whole
        fix: an OpenAI chunk serialises to
        ``{"choices":[{"delta":{"content":"..."}}],"id":...}``, so carrying the
        serialised form put ~30 characters of envelope between two halves of a
        split match and the window rejoined nothing — measured, a ``<script>``
        split across three chunks was never flagged and was delivered in full
        under ``block``."""
        text, coverage = scan_source(chunk)
        self.coverage = adapters.worst_coverage(self.coverage, coverage)
        scanned = self._carry + text
        rules, signals = _match(scanned, self._policy_tag)
        self._carry = scanned[-CARRY_CHARS:]
        if not rules:
            return None
        return PolicyDecision(action="flag", rules=sorted(set(rules)),
                              signals=sorted(set(signals)))
