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

from . import hashing, normalise, pii


def _one_deletion(word: str) -> str:
    """``word``, and exactly its single-deletion variants. Nothing else.

    ``Ignore all previus instructions`` reached the model under 2026.08.4
    (SDK #230): a model reads the typo as the word, a literal alternative does
    not. Enumerating the misspellings a human might make is whack-a-mole; every
    string one deletion away is a closed, finite set, and this is it.

    ⚠ AN ENUMERATION, AND IT MUST NOT BE THE CLEVER FORM. The first version of
    this helper was ``(?=[A-Za-z]{n-1,n}\\b)`` followed by the word with every
    character optional — shorter, and it looked provable. It matched THE EMPTY
    STRING at any word boundary the lookahead happened to accept, because
    nothing forced the optional chain to consume what the lookahead had
    asserted. ``override the statement of work`` and ``Disregard the duplicated
    line item`` both fired ``injection.override_instructions`` against a
    zero-width match, and both are ordinary work in the sectors this SDK is
    sold into. Caught by the benign corpus on its first run, which is what the
    benign corpus is for.

    ⚠ SEVEN-LETTER FLOOR, DELIBERATE. A short word's deletions land on real
    words far too easily. Callers pass short words as literals; this raises
    rather than silently widening them.

    It does NOT tolerate an INSERTION, a SUBSTITUTION or a TRANSPOSITION —
    ``instrcutions`` still passes. Stated so the limit travels with the fix.
    Nor does it tolerate a deletion in a word written as a literal: ``prior``
    stays exact.

    The trailing ``\\b`` is load-bearing. ``previou`` is a variant of
    ``previous``, and without a boundary it matches inside ``previously``.
    """
    if len(word) < 7:
        raise ValueError(
            f"{word!r} is too short for one-deletion tolerance: its variants "
            f"collide with real words. Write it as a literal.")
    variants = {word[:index] + word[index + 1:] for index in range(len(word))}
    variants.discard(word)
    ordered = [word] + sorted(variants)
    return r"(?:{0})\b".format("|".join(ordered))


# ── the vocabulary the injection rules are built from ────────────────────────
#
# Named fragments rather than one long literal per rule, because the SAME noun
# lists are the difference between catching an override and refusing ordinary
# work, and they have to be reviewable in one place. What reaches the ruleset
# hash is the COMPOSED pattern source, so this costs the frozen definition
# nothing and `ruleset.drift()` still sees every change.

#: Words marking an instruction as belonging to the conversation's past.
#: ``previous`` carries one-deletion tolerance; ``prior`` is five letters and is
#: therefore a literal (see :func:`_one_deletion`).
_PRIOR = ("(?:{0}|prior|preceding|preceeding|earlier|above|foregoing|former|"
          "initial|original|last)").format(_one_deletion("previous"))

#: Nouns that can only mean "the directives you are operating under". These get
#: the wider determiner set, because ``ignore the previous instructions`` is an
#: override in every context a compliance assistant runs in.
_STRONG_OBJECT = (
    "(?:{0}|{1}|prompts?|guardrails?|rules?|restrictions?|constraints?|"
    "limitations?|directives?|guidance|policy|policies|protocols?|"
    "programming|training|conditioning|persona|configuration)"
).format(_one_deletion("instructions"), _one_deletion("guidelines"))

#: Nouns usually about ORDINARY CONTENT and only sometimes about the
#: assistant's directives. ⚠ THEY KEEP 2026.08.4'S TIGHT DETERMINER SET — only
#: ``all`` and ``any`` — because ``please ignore my earlier message`` is the
#: commonest correction a human types at an assistant, and a guard that refuses
#: it has made the product worse in exchange for nothing.
_WEAK_OBJECT = "(?:messages?|directions?|context|notes?)"

#: Determiners allowed in front of a STRONG object.
_DETERMINER = (r"(?:all\s+|any\s+|the\s+|these\s+|those\s+|your\s+|its\s+|"
               r"my\s+|our\s+)?")

#: The assistant's OWN directives, named as such. No prior-word is needed: the
#: possessive, or the ``system``/``safety`` qualifier, already says whose
#: instructions are meant.
_SELF_DIRECTIVE = (
    r"(?:(?:system|safety|initial|original|developer|hidden|base|core|"
    r"underlying|built-?in)\s+(?:prompt|message|{0}|{1}|rules?|policy|policies)"
    r"|guardrails?"
    r"|(?:your|its)\s+{2})"
).format(_one_deletion("instructions"), _one_deletion("guidelines"),
         _STRONG_OBJECT)

#: A phrase marking the object as something the assistant was handed. This is
#: what reaches ``the guidance you were given earlier`` and ``the constraints
#: you were configured with`` — the synonym and polite-framing evasions, where
#: the verb is ordinary and the SELF-REFERENCE is the signal.
_PREVIOUSLY_GIVEN = (
    r"(?:you\s+(?:were\s+|have\s+been\s+|had\s+been\s+)?"
    r"(?:given|told|received|configured|instructed|set\s+up|programmed)"
    r"|above|earlier|before|previously|at\s+the\s+start"
    r"|in\s+this\s+(?:conversation|session|chat|thread))")

#: Verbs meaning "stop attending to". ⚠ EVERY ONE IS FOLLOWED BY A MANDATORY
#: OBJECT TEST. ``Disregard the duplicated line item`` and ``Ignore rounding
#: differences under one cent`` are the assistant's actual job.
_STOP_ATTENDING = (
    r"(?:ignore|ignoring|skip|omit|overlook|neglect|"
    r"pay\s+no\s+attention\s+to|take\s+no\s+notice\s+of|"
    r"set\s+aside|put\s+aside|leave\s+aside|"
    r"stop\s+following|no\s+longer\s+follow|(?:do\s+not|don'?t)\s+follow)")

# ── prompt-injection rules ────────────────────────────────────────────────────
# Each entry: (rule_id, coarse_signal_label, compiled_regex). Rules are matched
# against the prompt text AND against the derived views in :mod:`normalise` —
# see :func:`_injection_hits`. Only the label/id ever leaves the host.
_INJECTION_RULES = (
    ("injection.ignore_previous", "prompt_injection", re.compile(
        _STOP_ATTENDING + r"\s+(?:"
        # (a) 2026.08.4's shape for the ambiguous nouns, determiners and all.
        r"(?:all\s+|any\s+)?" + _PRIOR + r"\s+" + _WEAK_OBJECT
        # (b) the same shape for the unambiguous ones, with more determiners.
        + r"|" + _DETERMINER + _PRIOR + r"\s+" + _STRONG_OBJECT
        # (c) the assistant's own directives, no prior-word required.
        + r"|" + _SELF_DIRECTIVE
        # (d) an object marked as previously given, up to four words away.
        + r"|" + _DETERMINER + _STRONG_OBJECT + r"(?:\s+\w+){0,4}?\s+"
        + _PREVIOUSLY_GIVEN
        + r")", re.IGNORECASE)),
    ("injection.override_instructions", "prompt_injection", re.compile(
        r"(?:disregard|forget|override|bypass|circumvent|discard|suspend|"
        r"turn\s+off|switch\s+off)\s+"
        r"(?:all\s+|your\s+|the\s+|any\s+|these\s+|those\s+)?"
        r"(?:previous\s+|prior\s+|above\s+|safety\s+|system\s+|content\s+)?"
        + ("(?:{0}|{1}|rules?|guardrails?|filters?|restrictions?|policy|"
           "policies|guidance|constraints?|limitations?|directives?|"
           "protocols?)").format(_one_deletion("instructions"),
                                 _one_deletion("guidelines")),
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
    # ⚠ A NAMED, BOUNDED LIST OF LANGUAGES — NOT "non-English".
    #
    # Every other rule here is English and the model is not: a multilingual
    # assistant follows `Ignorez toutes les instructions précédentes` exactly as
    # it follows the English sentence, and 2026.08.4 saw a string with no
    # keyword in it (SDK #230). The honest fix cannot be "other languages", only
    # "these ones" — French, Spanish, Portuguese, German, Italian, Dutch,
    # Russian, Chinese and Japanese. Arabic, Hindi, Korean, Polish, Turkish and
    # every other language on earth are NOT covered, and that is recorded in
    # the ruleset's own docstring rather than left to be discovered.
    #
    # VERB AND OBJECT, never the object alone. `instructions précédentes` on its
    # own appears in any French document a legal assistant is asked to
    # summarise, and flagging that would refuse the job.
    ("injection.multilingual_override", "prompt_injection", re.compile(
        # French
        r"(?:ignore[zr]?|oublie[zr]?|ne\s+tenez?\s+pas\s+compte\s+(?:de|des))"
        r"\s+(?:[^\W\d_]+[\s'’-]+){0,3}instructions?\s+"
        r"(?:précédentes?|precedentes?|antérieures?|anterieures?)"
        # Spanish
        r"|(?:ignora|ignore|olvida|olvide|haz\s+caso\s+omiso\s+(?:a|de))"
        r"\s+(?:[^\W\d_]+[\s'’-]+){0,3}instrucciones\s+"
        r"(?:anteriores|previas)"
        # Portuguese
        r"|(?:ignore|ignora|esqueça|esqueca|desconsidere)"
        r"\s+(?:[^\W\d_]+[\s'’-]+){0,3}instruções\s+"
        r"(?:anteriores|prévias|previas)"
        # German
        r"|(?:ignoriere|ignorieren\s+sie|vergiss|vergessen\s+sie|missachte)"
        r"\s+(?:[^\W\d_]+[\s'’-]+){0,3}"
        r"(?:vorherigen|vorigen|bisherigen|obigen)\s+"
        r"(?:anweisungen|anleitungen|vorgaben|instruktionen)"
        # Italian
        r"|(?:ignora|ignorate|dimentica|dimenticate)"
        r"\s+(?:[^\W\d_]+[\s'’-]+){0,3}istruzioni\s+precedenti"
        # Dutch
        r"|(?:negeer|vergeet)\s+(?:[^\W\d_]+[\s'’-]+){0,3}"
        r"(?:vorige|eerdere|voorgaande)\s+(?:instructies|aanwijzingen)"
        # Russian
        r"|(?:игнорируй(?:те)?|"
        r"забудь(?:те)?)"
        r"\s+(?:[^\W\d_]+[\s'’-]+){0,3}"
        r"предыдущие\s+"
        r"(?:инструкции|"
        r"указания)"
        # Chinese — no word separators, so verb and object are adjacent.
        r"|忽略(?:所有)?"
        r"(?:之前的|以前的|先前的|上面的)?"
        r"(?:指令|指示|提示|要求)"
        # Japanese
        r"|(?:これまでの|以前の|先の|"
        r"上記の)(?:指示|命令)を?無視",
        re.IGNORECASE)),
)

# ── secret / key rules ────────────────────────────────────────────────────────
_SECRET_RULES = (
    ("secret.openai_key", "secret_key", re.compile(r"\bsk-[A-Za-z0-9_\-]{16,}\b")),
    ("secret.aws_access_key", "secret_key", re.compile(r"\bAKIA[0-9A-Z]{16}\b")),
    # THE WHOLE PEM BLOCK, not just the header. Matching the header alone meant
    # `redact` replaced `-----BEGIN … PRIVATE KEY-----` and then DELIVERED THE
    # KEY BODY to the model: the rule stopped firing while the secret went
    # through, so the guard reported a redaction it had not performed.
    #
    # Detection is unchanged — `evaluate` only asks whether anything matched, and
    # the header is still the thing that starts a match. What moves is the SPAN,
    # and therefore what `redact` removes: header → footer, or header → end of
    # text when there is no footer. Redacting to the end of an unterminated block
    # is deliberate. If we cannot see where a private key stops, everything after
    # it is suspect, and the alternative is guessing what a key body looks like —
    # a new rule that can itself be wrong — or delivering it.
    ("secret.private_key", "secret_key", re.compile(
        r"-----BEGIN [A-Z ]*PRIVATE KEY-----"
        r"[\s\S]*?(?:-----END [A-Z ]*PRIVATE KEY-----|\Z)")),
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


#: Rules whose marker cannot be derived from their own id.
#:
#: A redaction marker must be INERT — re-checking a redacted prompt must not
#: report the finding as still present. The marker is normally the rule id's
#: suffix, and ``injection.jailbreak``'s own pattern contains the literal word
#: ``jailbreak``, so ``[REDACTED:jailbreak]`` MATCHED THE RULE THAT PRODUCED IT.
#: A customer re-checking their own redacted prompt was told the finding had
#: survived its own redaction.
#:
#: All ten prompt rules are swept — nine at 1.9.0, and
#: ``injection.multilingual_override`` since 2026.08.5 — and this is still the
#: only one that collides. Not asserted here: the guard named below builds every
#: marker and re-evaluates it under every tag, so a rule added tomorrow whose
#: marker matches its own pattern fails there rather than shipping. It is
#: overridden to
#: the rule's coarse SIGNAL label rather than renamed to something invented, so
#: the marker still says which family was removed.
#:
#: The map is the data; the guard is
#: ``tests/test_policy_truth_1_9_0.py::test_217_every_marker_is_inert_under_every_rule``,
#: which builds every marker and re-evaluates it under every tag. A future rule
#: that collides fails there instead of shipping.
_MARKER_OVERRIDE = {"injection.jailbreak": "prompt_injection"}


def _marker(rule_id: str) -> str:
    """The ``[REDACTED:…]`` text that stands in for ``rule_id``'s match."""
    return "[REDACTED:{0}]".format(
        _MARKER_OVERRIDE.get(rule_id, rule_id.split(".", 1)[1]))


def _as_text(prompt) -> str:
    """Coerce an extracted prompt (str or structured provider messages) to text."""
    if isinstance(prompt, str):
        return prompt
    try:
        return hashing.canonical_json(prompt)
    except Exception:
        return str(prompt)


#: Every label that can appear inside a marker THIS SDK emits — the prompt rules'
#: (via :func:`_marker`) and the personal-data detectors' (``pii``). DERIVED from
#: the rule tables rather than typed out, so a rule added tomorrow is covered the
#: day it exists.
_MARKER_LABELS = frozenset(
    [_MARKER_OVERRIDE.get(rule_id, rule_id.split(".", 1)[1])
     for rule_id, _s, _r in _INJECTION_RULES + _SECRET_RULES]
) | frozenset(pii.REDACTION_LABELS)

#: ⚠ A CLOSED SET, AND THAT IS A SECURITY PROPERTY, NOT TIDINESS.
#:
#: This was ``\[REDACTED:[^\]\n]*\]`` — any bracketed span, CONTENT AND ALL. So
#: :func:`surviving_rules` re-evaluated a copy of the prompt with that text
#: deleted, and a customer could defeat the check by typing brackets around the
#: offending value. Measured: under ``hipaa`` + ``mode="redact"``,
#:
#:     note [REDACTED: dob 03/14/1982] end
#:
#: fired ``phi.presidio:date_time``, was delivered BYTE-IDENTICAL, and
#: ``surviving_rules`` returned ``[]`` — no block, date of birth to the model,
#: row stamped ``redacted``. Exactly the defect #216 exists to close, reachable
#: by anyone who guesses the marker format.
#:
#: Matching only the exact labels means the neutralised span can contain NOTHING
#: BUT a fixed word from our own vocabulary. A customer may still type
#: ``[REDACTED:ssn]`` verbatim, and it is then replaced by the stand-in — which
#: is harmless, because there is no room inside for a finding to hide.
_MARKER_RE = re.compile(
    r"\[REDACTED:(?:{0})\]".format("|".join(re.escape(label)
                                            for label in sorted(_MARKER_LABELS))))

#: What a marker becomes before the redacted prompt is RE-EVALUATED.
#:
#: NOT a deletion. Deleting a marker splices its neighbours into a match that was
#: never in the text — ``555[REDACTED:x]1234567`` becomes a ten-digit run — which
#: would report a finding as surviving its own redaction when it did not. A tilde
#: appears in no rule pattern and in no separator class, so it can neither join
#: two spans nor match on its own.
_MARKER_STANDIN = " ~ "


def surviving_rules(decision, redacted_prompt, policy_tag: str = "default") -> list[str]:
    """Which of ``decision``'s rules STILL fire against the redacted prompt.

    THE MEASUREMENT THAT MATTERS IS PER FINDING, NEVER PER BYTE. "Did any byte
    change?" is satisfied by a neighbouring redaction that DID work: a prompt
    carrying a redactable SSN beside a Presidio-only date of birth has its SSN
    scrubbed, so the text moved — and the date of birth still reaches the model
    while the row says ``redacted``. That is the same false claim as a total
    no-op, only narrower and harder to see.

    So the redacted prompt is evaluated again and the result is INTERSECTED with
    what fired originally. Intersected rather than taken whole: a rule that only
    appears AFTER redaction was not the customer's finding, and blocking on it
    would let the redaction machinery invent its own reasons to refuse a prompt.

    ⚠ THE MARKERS ARE NEUTRALISED FIRST, and that is load-bearing rather than
    cosmetic. A marker is the EVIDENCE the content was removed, so leaving one in
    place lets a rule report itself as surviving its own redaction — which
    ``injection.jailbreak`` did until 1.9.0 (see :data:`_MARKER_OVERRIDE`). That
    rule is fixed and every marker is now inert, but a re-check that depended on
    every FUTURE marker also being inert would block correctly-redacted prompts
    the first time one was not. Two independent defences, deliberately.

    COST: one extra :func:`evaluate` on the guarded redact path, which with the
    ``[pii]`` extra installed means a second Presidio pass. It runs only when a
    rule already fired under ``mode="redact"``, never on a clean prompt and never
    under ``observe``.
    """
    text = _MARKER_RE.sub(_MARKER_STANDIN, _as_text(redacted_prompt))
    return sorted(set(decision.rules) & set(evaluate(text, policy_tag).rules))


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


def _redact_derived_injection(text: str) -> str:
    """Replace the spans only a DERIVED view found, right to left.

    Right to left so each substitution leaves the offsets of the ones still to
    come untouched — the standard reason, stated because doing it left to right
    fails silently on the second match rather than loudly on the first.

    Overlapping derived spans keep the LEFTMOST and widest. Two rules can match
    the same span — a base64 blob whose plaintext trips both
    ``ignore_previous`` and ``reveal_system_prompt`` is in the corpus — and the
    second write would then slice a string the first one already shortened.
    ⚠ MEASURED, because the obvious corpus entry hides it: that blob sits at the
    END of its prompt, so ``text[end:]`` is empty and the second substitution
    overwrites the first harmlessly. Move the blob into the middle of a sentence
    and EVERYTHING AFTER IT IS DELETED — the model receives a truncated prompt
    and nothing reports it. `test_two_derived_matches_in_one_prompt_are_both_
    removed_intact` pins both shapes.

    ⚠ AND ONE HONEST NOTE ABOUT `raw_spans`. Filtering out derived spans that
    overlap a raw match is DEFENCE IN DEPTH, not load-bearing: removing it
    changed no output across 132 inputs, because the transforms only delete
    characters or replace whole blobs, so a derived span is always either
    identical to a raw one (the raw loop writes the same marker at the same
    place) or disjoint from it. It is kept because that reasoning is about
    TODAY'S transforms, and the next one may not delete-only — but it is not
    claimed as a guard, and no test asserts it.
    """
    raw_spans = [(start, end) for _r, _s, start, end, view
                 in _injection_hits(text) if view == "raw"]
    derived = sorted(
        ((start, end, rule_id) for rule_id, _s, start, end, view
         in _injection_hits(text)
         if view != "raw" and end > start
         and not any(start < raw_end and raw_start < end
                     for raw_start, raw_end in raw_spans)),
        key=lambda item: (item[0], -item[1]))

    applied = []
    for start, end, rule_id in derived:
        if applied and start < applied[-1][1]:
            continue
        applied.append((start, end, rule_id))

    for start, end, rule_id in reversed(applied):
        text = text[:start] + _marker(rule_id) + text[end:]
    return text


def _injection_hits(text: str) -> list:
    """Every injection match, as ``(rule_id, signal, start, end, view)``.

    Spans are into ``text`` — the ORIGINAL prompt — even for a match found in a
    derived view, because :mod:`normalise` carries the index map. That is what
    lets :func:`redact` remove the spaced-out run or the base64 blob rather than
    a slice of a transformed copy that never existed on the wire.

    ⚠ THE RAW VIEW IS FIRST AND ITS MATCHES ARE UNCHANGED. Everything a
    2026.08.4 build found, this finds, at the same span, from the same pattern.
    The derived views can only ADD.
    """
    hits = []
    for view in normalise.views_for(text, normalise.describe()):
        for rule_id, signal, regex in _INJECTION_RULES:
            for found in regex.finditer(view.text):
                start, end = view.origin(*found.span())
                hits.append((rule_id, signal, start, end, view.name))
    return hits


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
        for rule_id, signal, _start, _end, _view in _injection_hits(text):
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

    ⚠ TWO PASSES OVER THE INJECTION FAMILY, IN THIS ORDER, AND THE ORDER IS THE
    WHOLE REASON EVERY UNAFFECTED PROMPT STAYS BYTE-IDENTICAL.

    A match found only in a derived view has a span in the ORIGINAL text, so it
    must be substituted while the offsets are still the original's — before
    ``pii.redact`` and before the raw pattern loop move anything. Derived spans
    that OVERLAP a raw match are dropped: the raw loop is about to handle those,
    and applying both would produce a marker inside a marker.

    The consequence worth stating: when nothing matches in a derived view, this
    function is byte-for-byte 2026.08.4's. That is asserted, not assumed —
    ``test_policy_vocabulary`` compares it against a frozen 1.5.0 module across
    the whole corpus.
    """
    out = _as_text(prompt_text)
    checks = _checks_for(policy_tag)

    if "injection" in checks:
        out = _redact_derived_injection(out)

    if "phi" in checks or "pii" in checks:
        out = pii.redact(out)

    if "injection" in checks:
        for rule_id, _signal, regex in _INJECTION_RULES:
            out = regex.sub(_marker(rule_id), out)

    if "secrets" in checks:
        for rule_id, _signal, regex in _SECRET_RULES:
            out = regex.sub(_marker(rule_id), out)

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
