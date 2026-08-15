"""Host-side policy evaluation for the preflight guard.

`evaluate(prompt_text, policy_tag)` inspects a prompt LOCALLY and returns a
`PolicyDecision(action, rules, signals)`. `redact(prompt_text, policy_tag)`
returns a locally-redacted copy of the prompt. Both run in-process, alongside
`pii.detect_pii` — the only place raw text is ever seen — and return SIGNAL
LABELS / rule ids ONLY. Raw offending text never leaves this module.

Policy map (which check families each policy tag runs). The map is ADDITIVE: a
domain tag adds its personal-data family ON TOP of the baseline, it does not
replace it.

    every tag      -> prompt-injection + secret/key detection   (the baseline)
    hipaa          -> ...plus PHI/PII (via pii.detect_pii, rules prefixed ``phi.``)
    gdpr           -> ...plus PII     (via pii.detect_pii, rules prefixed ``pii.``)
    default, soc2  -> the baseline alone

Before 1.6.0 the map REPLACED rather than added: ``hipaa`` ran PHI *instead of*
the baseline, so a HIPAA workspace was the one workspace that did not check for
a leaked API key. Additive is the fix, and it is what makes the aliases below
safe — aliasing ``hipaa_basic`` onto a replacing ``hipaa`` would only have
traded a missing PHI check for a missing secrets check.

The rule id vocabulary (``<family>.<name>``) and the coarse signal labels are
part of the frozen wire contract's ``policy_rules`` / ``pii_signals`` fields.
``policy_tag`` itself is NOT resolved through the alias table on the wire: the
customer tagged the event ``hipaa_basic`` and the ledger keeps saying
``hipaa_basic``. Only the CHECKS resolve. Rewriting the recorded tag would
change the meaning of every historical row that already used it.
"""

from __future__ import annotations

import re
import warnings
from dataclasses import dataclass, field

from . import hashing, pii

# ── prompt-injection rules ────────────────────────────────────────────────────
# Each entry: (rule_id, coarse_signal_label, compiled_regex). Rules are matched
# against the prompt text; only the label/id ever leaves the host.
_INJECTION_RULES = (
    ("injection.ignore_previous", "prompt_injection", re.compile(
        r"ignore\s+(?:all\s+|any\s+)?(?:previous|prior|earlier|above|preceding)\s+"
        r"(?:instructions?|prompts?|messages?|directions?|context)", re.IGNORECASE)),
    ("injection.override_instructions", "prompt_injection", re.compile(
        r"(?:disregard|forget|override|bypass|discard)\s+"
        r"(?:all\s+|your\s+|the\s+|any\s+)?"
        r"(?:previous\s+|prior\s+|above\s+|safety\s+|system\s+)?"
        r"(?:instructions?|rules?|guidelines?|guardrails?|filters?|restrictions?|policy|policies)",
        re.IGNORECASE)),
    ("injection.reveal_system_prompt", "prompt_injection", re.compile(
        r"(?:reveal|show|print|repeat|display|expose|leak|disclose|tell)\s+"
        r"(?:me\s+)?(?:your\s+|the\s+)?"
        r"(?:system|initial|original|developer|hidden|secret)\s+"
        r"(?:prompt|message|instructions?)", re.IGNORECASE)),
    ("injection.jailbreak", "prompt_injection", re.compile(
        r"\b(?:do\s+anything\s+now|jailbreak|developer\s+mode|unfiltered\s+mode)\b",
        re.IGNORECASE)),
    # DAN is matched case-sensitively so the ordinary name "Dan" is not flagged.
    ("injection.dan", "prompt_injection", re.compile(r"\bDAN\b")),
)

# ── secret / key rules ────────────────────────────────────────────────────────
_SECRET_RULES = (
    ("secret.openai_key", "secret_key", re.compile(r"\bsk-[A-Za-z0-9_\-]{16,}\b")),
    ("secret.aws_access_key", "secret_key", re.compile(r"\bAKIA[0-9A-Z]{16}\b")),
    ("secret.private_key", "secret_key", re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----")),
    ("secret.bearer_token", "secret_key", re.compile(
        r"\bbearer\s+[A-Za-z0-9._\-]{20,}", re.IGNORECASE)),
)

# ── policy → check families ───────────────────────────────────────────────────
# The baseline every tag runs. Prompt injection and a leaked credential are not
# a property of the compliance regime the workspace is under — they are wrong in
# all of them — so no tag opts out of these.
_BASELINE_CHECKS = ("injection", "secrets")

# What a tag adds ON TOP of the baseline. An empty tuple is a real, deliberate
# entry, not a placeholder: it says "this tag is recognised and the baseline is
# all it needs", which is what keeps `resolve` from warning about it.
#
# soc2 -> (): SOC 2 is a controls regime (access, confidentiality, integrity),
# not a personal-data one. It has no PHI/PII scope to add, and the baseline —
# injection and credential leakage — is exactly its subject matter. Decided, not
# left over: it was already reaching the baseline before 1.6.0, and it is listed
# here so that stays true on purpose and so the vocabulary guard accepts it.
_POLICY_EXTRA = {
    "default": (),
    "soc2": (),
    "hipaa": ("phi",),   # PHI/PII via pii.detect_pii
    "gdpr": ("pii",),    # PII via pii.detect_pii
}

# Documented spellings that resolve to a real tag. `hipaa_basic` is the tag in
# our own PyPI quickstart, so until 1.6.0 the copy-paste path ran NO PHI check
# while the event it shipped — and the Compliance Passport that groups its
# statistics by policy_tag — was labelled HIPAA.
_POLICY_ALIASES = {
    "hipaa_basic": "hipaa",
    "gdpr_basic": "gdpr",
}

#: Every spelling the SDK recognises. The documentation-vocabulary guard reads
#: this, so a README example using a tag absent here fails the build.
KNOWN_POLICY_TAGS = frozenset(_POLICY_EXTRA) | frozenset(_POLICY_ALIASES)

# One warning per distinct unknown tag per process — the tag sits inside the
# hot path of a decorated call, and a warning per invocation would be noise a
# customer learns to filter.
_warned_tags: set[str] = set()

# Priority order for the single "dominant" blocked_reason label.
#
# The ``response_*`` families come from response_policy.py (OWASP LLM05). They
# live in THIS table because one interaction can carry rules from both sides and
# `reason` has to pick a single label out of the merged list. Rule ids are
# ``<family>.<name>`` on both sides, so the response families are ordinary
# entries here rather than a special case — which is why response_policy names
# them ``response_markup.*`` and not ``response.markup.*``.
_REASON_LABEL = {
    "secret": "secret_key",
    "response_secret": "secret_key",
    "injection": "prompt_injection",
    "response_markup": "unsafe_markup",
    "response_sql": "unsafe_sql",
    "response_url": "unsafe_url",
    "phi": "phi",
    "response_phi": "phi",
    "pii": "pii",
    "response_pii": "pii",
    # Informational, and LAST on purpose: "we could not read the response" must
    # never be the dominant label on a row where a real rule also fired.
    "response_scan": "scan_coverage",
}
_REASON_PRIORITY = ("secret", "response_secret", "injection",
                    "response_markup", "response_sql", "response_url",
                    "phi", "response_phi", "pii", "response_pii",
                    "response_scan")


@dataclass(frozen=True)
class PolicyDecision:
    """Outcome of a local policy evaluation. Content-blind by construction."""
    action: str                       # "allow" (nothing fired) | "flag" (a rule matched)
    rules: list[str] = field(default_factory=list)     # matched rule ids
    signals: list[str] = field(default_factory=list)   # coarse signal labels that fired

    @property
    def triggered(self) -> bool:
        return self.action != "allow"

    @property
    def reason(self) -> str:
        """Short, dominant reason label for the audit event / desktop ping."""
        families = {r.split(".", 1)[0] for r in self.rules}
        for family in _REASON_PRIORITY:
            if family in families:
                return _REASON_LABEL[family]
        return next(iter(families)) if families else "none"


def _as_text(prompt) -> str:
    """Coerce an extracted prompt (str or structured provider messages) to text."""
    if isinstance(prompt, str):
        return prompt
    try:
        return hashing.canonical_json(prompt)
    except Exception:
        return str(prompt)


def resolve_policy_tag(policy_tag: str) -> str | None:
    """Canonical tag for ``policy_tag``, or ``None`` if it is not recognised.

    Resolves aliases (``hipaa_basic`` -> ``hipaa``). This is the ONE place the
    tag vocabulary is interpreted; :mod:`response_policy` calls it too, so the
    prompt side and the response side can never disagree about what a tag means.
    It does NOT warn — callers that act on the result do, so that merely asking
    what a tag resolves to (the vocabulary guard, a test) stays silent.
    """
    tag = (policy_tag or "").strip().lower()
    tag = _POLICY_ALIASES.get(tag, tag)
    return tag if tag in _POLICY_EXTRA else None


def _resolve_or_warn(policy_tag: str) -> str | None:
    """:func:`resolve_policy_tag`, but an unrecognised tag is made LOUD.

    Warn rather than refuse, deliberately. ``policy_tag`` is a free string on
    the wire — the backend validates no vocabulary, and customers legitimately
    label rows in their own terms (``claims_triage``, ``internal_v2``). Raising
    would turn a label we happen not to know into a hard failure of the
    customer's production model call, which is a worse outcome than the label
    being unknown.

    What is NOT acceptable is the old silence. An unrecognised tag still runs
    the baseline and still ships a row carrying that tag, so a typo like
    ``hipa_basic`` used to downgrade a workspace's compliance posture with
    nothing said anywhere. The typo is not the defect; the silence was.
    """
    resolved = resolve_policy_tag(policy_tag)
    if resolved is None:
        tag = (policy_tag or "").strip().lower()
        if tag not in _warned_tags:
            _warned_tags.add(tag)
            warnings.warn(
                f"foxy-audit: unrecognised policy tag {policy_tag!r}. Running the "
                f"baseline checks only (prompt-injection + secrets); NO PHI/PII "
                f"check will run. Known tags: "
                f"{', '.join(sorted(KNOWN_POLICY_TAGS))}.",
                UserWarning, stacklevel=3,
            )
    return resolved


def _checks_for(policy_tag: str) -> tuple[str, ...]:
    """The check families for a tag: the baseline, plus whatever the tag adds."""
    resolved = _resolve_or_warn(policy_tag)
    return _BASELINE_CHECKS + _POLICY_EXTRA.get(resolved, ())


def evaluate(prompt_text, policy_tag: str = "default") -> PolicyDecision:
    """Evaluate ``prompt_text`` under ``policy_tag``; return labels only."""
    text = _as_text(prompt_text)
    checks = _checks_for(policy_tag)
    rules: list[str] = []
    signals: list[str] = []

    if "phi" in checks or "pii" in checks:
        prefix = "phi" if "phi" in checks else "pii"
        for label in pii.detect_pii(text, ""):
            rules.append(f"{prefix}.{label}")
            signals.append(label)

    if "injection" in checks:
        for rule_id, signal, regex in _INJECTION_RULES:
            if regex.search(text):
                rules.append(rule_id)
                signals.append(signal)

    if "secrets" in checks:
        for rule_id, signal, regex in _SECRET_RULES:
            if regex.search(text):
                rules.append(rule_id)
                signals.append(signal)

    action = "flag" if rules else "allow"
    return PolicyDecision(action=action,
                          rules=sorted(set(rules)),
                          signals=sorted(set(signals)))


def redact(prompt_text, policy_tag: str = "default") -> str:
    """Return a locally-redacted copy of the prompt for the active policy.

    Applies the same check families as :func:`evaluate`, replacing offending
    spans with content-blind ``[REDACTED:<label>]`` markers so the wrapped
    function receives a scrubbed prompt while raw text never leaves the host.
    """
    out = _as_text(prompt_text)
    checks = _checks_for(policy_tag)

    if "phi" in checks or "pii" in checks:
        out = pii.redact(out)

    if "injection" in checks:
        for rule_id, _signal, regex in _INJECTION_RULES:
            out = regex.sub(f"[REDACTED:{rule_id.split('.', 1)[1]}]", out)

    if "secrets" in checks:
        for rule_id, _signal, regex in _SECRET_RULES:
            out = regex.sub(f"[REDACTED:{rule_id.split('.', 1)[1]}]", out)

    return out


def redact_value(value, policy_tag: str = "default"):
    """Recursively redact string leaves in a prompt of ANY shape.

    A plain string is redacted directly; a structured provider prompt (e.g. an
    OpenAI ``messages=[{"role":..., "content":...}]`` list) is walked and every
    string leaf is scrubbed, so the wrapped function receives a redacted prompt of
    the SAME shape instead of the raw original. Non-string leaves pass through
    unchanged. This keeps redact mode honest for structured prompts — ``redact()``
    alone returns a string, which cannot be substituted back into a list/dict slot.
    """
    if isinstance(value, str):
        return redact(value, policy_tag)
    if isinstance(value, dict):
        return {k: redact_value(v, policy_tag) for k, v in value.items()}
    if isinstance(value, list):
        return [redact_value(v, policy_tag) for v in value]
    if isinstance(value, tuple):
        return tuple(redact_value(v, policy_tag) for v in value)
    return value
