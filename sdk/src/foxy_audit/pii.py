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
#   boundary                 PANs    sha256  random uuid  ZERO-HEAVY  hyphen ids
#   1.8.0                  450/450     90        33          2853        2022
#   letters + hyphen       324/450      0         0           411           0
#   letters only           414/450      0         5          2627        2022
#   + _is_card_number      414/450      0         5             2        2022
#
# ⚠ THE HYPHEN WAS DEFENDING AGAINST SOMETHING, and an earlier version of this
# comment claimed otherwise — "no UUID can ever be a card candidate, its longest
# digit group is 12". THAT IS FALSE. ``[ \-]?`` is a SEPARATOR, so a candidate
# chains straight across a UUID's hyphens: ``0000-0000-0000-0000`` is one 16-digit
# run. The 0-vs-5 column above says so, and the ZERO-HEAVY column says it loudly.
# What the hyphen was defending against is now handled where it belongs — in
# :func:`_is_card_number`, at no cost to PAN recall — instead of by a boundary
# that also deleted 90 real PAN shapes. ``card-4111111111111111`` and
# ``4111-1111-1111-1111-visa`` were detected by 1.8.0 and were NOT by the first
# version of this fix. For a compliance product a missed PAN is worse than a
# spurious label on an identifier, and that trade is not symmetric.
#
# The hyphen-ids column is the reason letters-only is not a regression: it is
# IDENTICAL to 1.8.0's. A Luhn-passing 13-19 digit run written with hyphen
# separators is what a PAN looks like, and flagging it is the base rate this
# detector has always had — not something #215 introduced or promised to remove.
# An IIN-prefix rule (``[2-6]``) was measured and rejected: it only halved that
# column (2022 -> ~1110), recovered no additional PAN, and would miss any card
# outside the mainstream ranges.
#
# THE CARD COST, STATED RATHER THAN HIDDEN: a PAN glued directly to a LETTER
# (``4111111111111111x``) is not detected; 5 random UUIDs in 20 000 and 2 of
# 10 120 zero-heavy ids still read as ``credit_card`` (1.8.0: 33 and 2 853), and
# those residues are 16-digit, 8-distinct-digit Luhn-passing runs no content-free
# rule separates from a PAN. tests/fixtures/identifier_corpora.py checks in every
# population above, and test_policy_truth_1_9_0.py regenerates the PAN shapes,
# rather than trusting these sentences.
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
#
# ``\d(?:[ \-]?\d){12,18}`` rather than ``(?:\d[ \-]?){13,19}``: same 13–19
# digits, but a separator can only appear BETWEEN two digits. The old shape let
# the final ``[ \-]?`` swallow the character AFTER the number, so
# ``redact("6011111111111117- ok")`` returned ``"[REDACTED:credit_card] ok"``
# with the customer's hyphen gone. The space half of that was fixed by accident
# in 1.9.0 (the new lookahead forced a backtrack); this fixes the whole class on
# purpose.
_CARD_CANDIDATE_RE = re.compile(
    _CARD_BEFORE + r"\d(?:[ \-]?\d){12,18}" + _CARD_AFTER)


def _is_uniform(digits: str) -> bool:
    """A run of ONE repeated digit — ``0000000000``, ``1111111111111``.

    Never a phone number and never a card number, in any scheme; always a
    placeholder someone typed. Shared by both detectors because fixing one and
    not the other is how this file ends up with two boundaries again.
    """
    return len(set(digits)) == 1


def _is_phone_number(digits: str) -> bool:
    """The phone detector's one structural test.

    The phone rule has no checksum — any delimited 10-13 digit run is
    phone-shaped, which is correct and is why ``4155550134`` is caught. It also
    made ``0000000000000`` a phone, so a bare placeholder run blocked the prompt
    under ``hipaa``. Measured: 10 of 10 120 zero-heavy identifiers.

    Free: no real phone number is one repeated digit, and the 56 448 generated
    phone shapes are unaffected.
    """
    return not _is_uniform(digits)


def _is_card_number(digits: str) -> bool:
    """Luhn, PLUS the two structural facts Luhn alone does not know.

    ⚠ LUHN ACCEPTS RUBBISH. ``_luhn_ok("0000000000000000")`` is True, and the
    card candidate can chain across a UUID's hyphens (``[ \\-]?`` is a separator,
    so ``0000-0000-0000-0000`` is one 16-digit run). Together those made A NIL
    UUID — one of the most common placeholder values in software — report
    ``credit_card``:

        "patient record 00000000-0000-0000-0000-000000000000 not found"

    Under ``hipaa`` that fires ``phi.credit_card``: it blocks the prompt, mangles
    it under redact, and under OBSERVE it lands in ``pii_signals``, where one
    label makes the backend's deterministic verdict a BREACH. ``response_policy``
    shares this detector, so a response echoing a nil UUID did it too.

    The two extra tests are free — neither can reject a real card:

    * **No PAN starts with 0.** ISO/IEC 7812 assigns major industry identifier 0
      to ISO/TC 68; no payment network issues from it. This is what kills the
      zero-padded and sequential-id class (``0000-000000000018`` and friends).
    * **No PAN is one repeated digit.** ``2222…``, ``4444…``, ``6666…`` and
      ``8888…`` pass Luhn at some lengths and are not card numbers.

    Measured over 10 120 zero-heavy ids (nil UUIDs, sequential UUIDs, zero-padded
    counters, uniform runs): 2 853 fired on 1.8.0, 2 627 after the 1.9.0 boundary
    change, and 2 here — and those 2 are 16-digit, 8-distinct-digit Luhn-passing
    runs that no content-free rule could separate from a PAN. PAN recall is
    unchanged at 414/450 generated shapes.

    Kept SEPARATE from :func:`_luhn_ok` on purpose. That function stays the plain
    checksum because ``introspect.replay`` reimplements it to replay rows written
    under rulesets 2026.08.1 and 2026.08.2, whose frozen definitions record
    ``"validator": "luhn"`` and must keep meaning exactly that.
    """
    return digits[:1] != "0" and not _is_uniform(digits) and _luhn_ok(digits)


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


def _has_phone(text: str) -> bool:
    for m in _PHONE_RE.finditer(text):
        if _is_phone_number(re.sub(r"\D", "", m.group())):
            return True
    return False


def _has_card(text: str) -> bool:
    for m in _CARD_CANDIDATE_RE.finditer(text):
        if _is_card_number(re.sub(r"\D", "", m.group())):
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
    leave.

    ⚠ EVERY GATE DETECTION APPLIES IS APPLIED HERE TOO, through the SAME
    functions. Cards go through :func:`_is_card_number` and phones through
    :func:`_is_phone_number`, so redaction cannot rewrite a span detection would
    not have reported — which would hand the model a mangled prompt for a finding
    the ledger never recorded, and is the drift ``_REDACTIONS`` exists to prevent
    by reusing the same regexes.
    """
    def _sub_if(gate, label):
        def _sub(match: "re.Match[str]") -> str:
            digits = re.sub(r"\D", "", match.group())
            return f"[REDACTED:{label}]" if gate(digits) else match.group()
        return _sub

    out = _CARD_CANDIDATE_RE.sub(_sub_if(_is_card_number, _CARD_LABEL), str(text))
    for regex, label in _REDACTIONS:
        if regex is _PHONE_RE:
            out = regex.sub(_sub_if(_is_phone_number, label), out)
        else:
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
    if _has_phone(combined):
        signals.append("phone")
    if _IPV4_RE.search(combined):
        signals.append("ip_address")
    if _has_card(combined):
        signals.append("credit_card")
    signals.extend(_presidio_signals(combined))
    return sorted(set(signals))
