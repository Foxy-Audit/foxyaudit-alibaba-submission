"""Client-side PII detection (Phase 5 · 5J).

Runs in the SDK — the ONLY place that ever sees raw prompt/response text (the
backend receives hashes + signals only). A lightweight, dependency-free regex
layer runs ALWAYS; Microsoft Presidio (deep NLP: names, locations, MRNs) is used
ONLY when the optional extra is installed (`pip install foxy-audit[pii]`), so the
base SDK stays tiny. Detection emits SIGNAL LABELS (never the raw values), which
ride along in the audit metadata for the judge to weigh.
"""

from __future__ import annotations

import re

# A phone or card number is a STANDALONE TOKEN, not a fragment of a longer one.
#
# The old lookarounds — ``(?<!\d)`` / ``(?!\d)`` — excluded an adjacent DIGIT but
# not an adjacent LETTER or HYPHEN, so a 10–13 digit run sitting inside an
# alphanumeric identifier read as personal data. Measured on 1.8.0:
#
#   * ``sk-ABCDEF0123456789ABCDEFGH``          -> ['phone']
#   * ``550e8400-e29b-41d4-a716-446655440000`` -> ['phone']  (a bare UUID)
#   * 20 000 real SHA-256 digests -> 15.3% 'phone', 0.45% 'credit_card'
#   * 20 000 random UUIDs         -> 2.8% flagged
#
# Under ``hipaa``/``gdpr`` in ``mode="block"`` every one of those REFUSED A
# LEGITIMATE PROMPT before the model call — the guard over-blocking on an API
# key, a request id or a commit sha.
#
# The fix tightens the LOOKAROUNDS and nothing else. No UUID/hex/base64
# exclusion: each would be a new rule that can itself be wrong, and what was
# actually wrong here is that a token boundary was defined as "not a digit" when
# identifiers are made of letters and hyphens too.
#
# THE TWO DETECTORS NEED DIFFERENT BOUNDARIES, and treating them as one cost a
# fifth of the real card shapes. They are separated here, each with the
# measurement that decides it.
#
# PHONE excludes an adjacent hyphen as well as a letter, because the bare UUID
# that motivated this — ``550e8400-e29b-41d4-a716-446655440000`` — carries a
# 12-digit run BETWEEN HYPHENS, and the optional country-code prefix absorbs it.
# Letters alone do not kill it. THE COST: a phone glued directly to a hyphen with
# no separating space (``Tel-4155550134``) is no longer detected. Every shape the
# old regex accepted in a DELIMITED context still matches — 56 448 generated
# phone shapes across 21 surrounding contexts, zero lost.
#
# CARD excludes an adjacent LETTER ONLY. The hyphen bought it nothing and cost it
# a great deal, measured over 450 generated PAN shapes (6 issuers x 3 groupings x
# 25 contexts) and four 20 000-item false-positive populations:
#
#   boundary            PANs found   sha256   uuid   hyphenated 13-15 digit ids
#   1.8.0                 450/450       90     33         1996 / 20 000
#   letters + hyphen      324/450        0      0            0
#   letters only          414/450        0      5         1996 / 20 000
#
# No UUID can ever be a card candidate on its own — its longest digit group is
# 12, below the 13 minimum — so the hyphen was defending against nothing here
# while deleting 90 real PAN shapes: ``card-4111111111111111`` and
# ``4111-1111-1111-1111-visa`` were detected by 1.8.0 and were NOT by the first
# version of this fix. For a compliance product a missed PAN is worse than a
# spurious label on a hex digest, and that trade is not symmetric.
#
# The hyphenated-id column is the reason letters-only is not a regression: it is
# IDENTICAL to 1.8.0's. A Luhn-passing 13-19 digit run written with hyphen
# separators is what a PAN looks like, and flagging it is the base rate this
# detector has always had — not something #215 introduced or promised to remove.
# An IIN-prefix rule (``[2-6]``) was measured and rejected: it only halved that
# column (1996 -> 1110), recovered no additional PAN, and would miss any card
# outside the mainstream ranges.
#
# THE CARD COST, STATED RATHER THAN HIDDEN: a PAN glued directly to a LETTER
# (``4111111111111111x``) is not detected, and 5 UUIDs in 20 000 still read as
# ``credit_card`` where 1.8.0 flagged 33. test_pii.py and
# test_policy_truth_1_9_0.py regenerate both corpora rather than trusting these
# sentences.
_PHONE_BEFORE = r"(?<![0-9A-Za-z\-])"
_PHONE_AFTER = r"(?![0-9A-Za-z\-])"
_CARD_BEFORE = r"(?<![0-9A-Za-z])"
_CARD_AFTER = r"(?![0-9A-Za-z])"

_EMAIL_RE = re.compile(r"[\w.\-]+@[\w\-]+\.\w+")
_SSN_RE = re.compile(r"\b\d{3}-\d{2}-\d{4}\b")
_PHONE_RE = re.compile(
    _PHONE_BEFORE + r"(?:\+?\d{1,3}[ .\-]?)?\(?\d{3}\)?[ .\-]?\d{3}[ .\-]?\d{4}"
    + _PHONE_AFTER)
_IPV4_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
# The card candidate carried the IDENTICAL lookarounds, and 0.45% of real
# SHA-256 digests cleared Luhn on a run inside them. Fixing only the phone would
# have left the same over-block firing under a different label — but it needs the
# LETTER boundary only, for the reasons measured above.
_CARD_CANDIDATE_RE = re.compile(
    _CARD_BEFORE + r"(?:\d[ \-]?){13,19}" + _CARD_AFTER)


def _luhn_ok(digits: str) -> bool:
    """Standard Luhn checksum — separates real card numbers from any 13–19 digit run."""
    if not (13 <= len(digits) <= 19):
        return False
    total = 0
    for i, ch in enumerate(reversed(digits)):
        n = int(ch)
        if i % 2 == 1:                       # double every second digit from the right
            n *= 2
            if n > 9:
                n -= 9
        total += n
    return total % 10 == 0


def _has_card(text: str) -> bool:
    for m in _CARD_CANDIDATE_RE.finditer(text):
        if _luhn_ok(re.sub(r"\D", "", m.group())):
            return True
    return False


# ── optional Presidio (deep NLP) — only if the [pii] extra is installed ───────
_PRESIDIO = None   # None = not tried yet, False = unavailable, else the engine


def _presidio_signals(text: str) -> list[str]:
    global _PRESIDIO
    if _PRESIDIO is None:
        try:
            from presidio_analyzer import AnalyzerEngine
            _PRESIDIO = AnalyzerEngine()
        except Exception:                    # not installed / model missing → never retry
            _PRESIDIO = False
    if not _PRESIDIO:
        return []
    try:
        results = _PRESIDIO.analyze(text=text, language="en")
        return [f"presidio:{r.entity_type.lower()}" for r in results if r.score >= 0.5]
    except Exception:
        return []


# Ordered so multi-digit spans (cards) are handled before the narrower patterns.
# Reuses the exact regexes above so redaction and detection never drift apart.
_REDACTIONS = (
    (_SSN_RE, "ssn"),
    (_PHONE_RE, "phone"),
    (_EMAIL_RE, "email"),
    (_IPV4_RE, "ip_address"),
)

#: The card label lives here rather than inline in :func:`redact` so
#: :data:`REDACTION_LABELS` can be DERIVED. A hand-written list would be the one
#: place someone forgets, and what depends on it is a security check — see
#: ``policy._MARKER_RE``.
_CARD_LABEL = "credit_card"

#: Every label :func:`redact` can put inside a ``[REDACTED:…]`` marker.
REDACTION_LABELS = tuple(label for _regex, label in _REDACTIONS) + (_CARD_LABEL,)


def redact(text: str) -> str:
    """Replace detected PII spans with content-blind ``[REDACTED:<label>]`` markers.

    Runs entirely in-process on the host (like detection); the raw values never
    leave. Credit cards are Luhn-gated exactly as in detection so we never mangle
    an unrelated long digit run.
    """
    def _card_sub(match: "re.Match[str]") -> str:
        digits = re.sub(r"\D", "", match.group())
        return f"[REDACTED:{_CARD_LABEL}]" if _luhn_ok(digits) else match.group()

    out = _CARD_CANDIDATE_RE.sub(_card_sub, str(text))
    for regex, label in _REDACTIONS:
        out = regex.sub(f"[REDACTED:{label}]", out)
    return out


def detect_pii(prompt_s: str, response_s: str) -> list[str]:
    """De-duplicated PII SIGNAL labels (never raw values) for prompt+response.
    Lightweight regex always; Presidio signals appended when the extra is present."""
    combined = f"{prompt_s} {response_s}"
    signals: list[str] = []
    if _EMAIL_RE.search(combined):
        signals.append("email")
    if _SSN_RE.search(combined):
        signals.append("ssn_pattern")
    if _PHONE_RE.search(combined):
        signals.append("phone")
    if _IPV4_RE.search(combined):
        signals.append("ip_address")
    if _has_card(combined):
        signals.append("credit_card")
    signals.extend(_presidio_signals(combined))
    return sorted(set(signals))
