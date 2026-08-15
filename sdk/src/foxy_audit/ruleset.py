"""Frozen, versioned rule definitions — the provenance behind a `policy_rules` id.

A blocked row already records WHICH rule fired, hash-chained so nobody can
change it afterwards. It did not record WHAT THAT RULE WAS, so an auditor could
not establish what ``injection.ignore_previous`` meant on the day it matched and
the proof chain ended at "Foxy says so". This module closes that.

THE REGISTRY IS FROZEN, NOT CURRENT
-----------------------------------
``rulesets/`` holds one module per published version, each a plain dict literal
that is written once and NEVER EDITED. A registry that only held "the current
rules" would make every historical row unverifiable the moment someone touched a
regex — the exact failure this phase exists to prevent, arriving one release
later. Replaying the version named in a row therefore means importing that
frozen module, not re-reading today's code.

:func:`describe_live` re-derives the same structure from the modules actually
loaded. It exists for exactly one purpose: to be compared against the frozen
entry, so editing a rule WITHOUT minting a version fails loudly (see
:func:`drift`, and the guard in ``tests/test_ruleset.py``). At runtime the SDK
emits the FROZEN hash, never a recomputed one — a build that has drifted should
be caught by a red test, not paper over itself by silently emitting a hash for
rules nobody published.

WHAT THE HASH COVERS, AND WHY
-----------------------------
Everything that determines WHICH RULE IDS CAN APPEAR on a row, and nothing else:

* the prompt-side injection and secret rules — id, coarse signal label, and the
  regex SOURCE TEXT plus its flags. Source text rather than the compiled object
  because a compiled pattern has no stable serialisation; flags because
  ``re.IGNORECASE`` changes what matches as surely as the pattern does.
* the response-side (OWASP LLM05) families, which emit ids into the very same
  ``policy_rules`` field, plus ``CARRY_CHARS`` — the streaming window is a real
  bound on what a scan can detect.
* the built-in PII/PHI detectors, since ``phi.*`` / ``pii.*`` ids come from them.
* the policy map, aliases and baseline: which families run under which tag.
* the reason table AND its priority ORDER.

Ordering is treated with deliberate asymmetry. Rules are stored as a SORTED
mapping because ``evaluate`` collects every match and returns
``sorted(set(...))`` — reordering the rule tuples cannot change any output, so
including their order would mint spurious versions for inert edits. But
``_REASON_PRIORITY`` IS order-sensitive — it picks the single dominant
``blocked_reason`` — so it is hashed as an ordered list.

NOT covered, and said out loud rather than quietly omitted: optional Presidio
signals. They are namespaced ``presidio:*``, come from an external model whose
version we neither pin nor control, and are absent unless the ``pii`` extra is
installed. Folding them in would make the "version" differ per installation,
which is the opposite of a version. The definition records that boundary in its
own ``presidio_signals`` field so the exclusion travels with the evidence.
"""

from __future__ import annotations

import hashlib
import json
import logging
import re

log = logging.getLogger("foxy_audit")

#: Bumped by hand when the rules change. Date-based rather than semver: this
#: numbers a body of RULES, not an API, and "which rules were live in August
#: 2026" is the question an auditor actually asks.
CURRENT_VERSION = "2026.08.3"

_SCHEMA = "foxy-ruleset-v1"


def _flags(regex) -> list[str]:
    """The compile flags that affect matching, as stable names.

    Only the flags a rule here could plausibly carry are named. UNICODE is
    excluded deliberately: it is implicit for ``str`` patterns in Python 3, so
    including it would record a constant.
    """
    names = []
    for flag, name in ((re.IGNORECASE, "IGNORECASE"), (re.MULTILINE, "MULTILINE"),
                       (re.DOTALL, "DOTALL"), (re.VERBOSE, "VERBOSE"),
                       (re.ASCII, "ASCII")):
        if regex.flags & flag:
            names.append(name)
    return names


def _rules(entries) -> dict:
    """``(id, signal, regex)`` triples -> a sorted {id: {...}} mapping."""
    return {rule_id: {"signal": signal,
                      "pattern": regex.pattern,
                      "flags": _flags(regex)}
            for rule_id, signal, regex in sorted(entries)}


def describe_live() -> dict:
    """Re-derive the ruleset structure from the modules currently loaded.

    Compared against the frozen entry to detect an unversioned edit. It is NOT
    what goes on the wire — see the module docstring.
    """
    from . import pii, policy, response_policy

    return {
        "schema": _SCHEMA,
        "prompt_rules": {
            "injection": _rules(policy._INJECTION_RULES),
            "secret": _rules(policy._SECRET_RULES),
        },
        "response_rules": {
            "always": _rules(response_policy._ALWAYS),
            "personal_by_policy": dict(sorted(response_policy._POLICY_PERSONAL.items())),
            "carry_chars": response_policy.CARRY_CHARS,
            # Coverage ids reach `policy_rules` like any other id, so a row can
            # name `response_scan.unreadable` — and until 2026.08.2 the version
            # it named contained no entry explaining it. They are INFORMATIONAL
            # (they never block and never become a decision), but they are a
            # claim about the QUALITY OF THE EVIDENCE — "this shape could not be
            # read" — which is the last thing that should be unresolvable.
            "coverage": {rule_id: {"signal": signal, "coverage": coverage,
                                   "informational": True}
                         for coverage, (rule_id, signal)
                         in sorted(response_policy._COVERAGE_RULES.items())},
        },
        "pii_detectors": {
            "email": {"pattern": pii._EMAIL_RE.pattern, "flags": _flags(pii._EMAIL_RE)},
            "ssn_pattern": {"pattern": pii._SSN_RE.pattern, "flags": _flags(pii._SSN_RE)},
            "phone": {"pattern": pii._PHONE_RE.pattern, "flags": _flags(pii._PHONE_RE)},
            "ip_address": {"pattern": pii._IPV4_RE.pattern, "flags": _flags(pii._IPV4_RE)},
            "credit_card": {"pattern": pii._CARD_CANDIDATE_RE.pattern,
                            "flags": _flags(pii._CARD_CANDIDATE_RE),
                            "validator": "luhn"},
        },
        "policy_map": {
            "baseline": sorted(policy._BASELINE_CHECKS),
            "extra": {tag: sorted(families)
                      for tag, families in sorted(policy._POLICY_EXTRA.items())},
            "aliases": dict(sorted(policy._POLICY_ALIASES.items())),
        },
        "reason": {
            "labels": dict(sorted(policy._REASON_LABEL.items())),
            # ORDERED: this one decides the single dominant blocked_reason.
            "priority": list(policy._REASON_PRIORITY),
        },
        "presidio_signals": (
            "namespaced presidio:* — optional external model, NOT covered by "
            "this hash or this version"),
    }


def explained_ids(definition: dict) -> set:
    """Every ``policy_rules`` id this definition can account for.

    Some ids are stored directly (``injection.*``, ``response_markup.*``,
    ``response_scan.*``); the personal-data ones are COMPOSED at emit time as
    ``<prefix>.<label>`` — ``phi.ssn_pattern``, ``response_pii.email`` — from a
    prefix in the policy map and a label from the detector set. So they are
    composed here the same way rather than stored twice, which keeps one source
    of truth for what a version explains.
    """
    ids: set = set()
    for family in definition.get("prompt_rules", {}).values():
        ids |= set(family)
    response = definition.get("response_rules", {})
    ids |= set(response.get("always", {}))
    ids |= set(response.get("coverage", {}))

    labels = set(definition.get("pii_detectors", {}))
    prefixes = {"phi", "pii"} | set(response.get("personal_by_policy", {}).values())
    for prefix in prefixes:
        ids |= {f"{prefix}.{label}" for label in labels}
    return ids


def live_rule_ids() -> set:
    """Every id the LIVE code can put in ``policy_rules``, gathered from the
    modules rather than typed out.

    Derived, deliberately. A hand-written list of families would have to be
    remembered at exactly the moment someone is thinking about something else —
    which is how the coverage family came to be emitted for three releases
    without ever being described. Walking every ``*_RULES`` table means the
    NEXT family added is included here the day it exists, and fails the
    resolvability guard until someone decides what it means.
    """
    from . import policy, response_policy

    ids: set = set()
    for module in (policy, response_policy):
        for name in dir(module):
            if not name.endswith("_RULES"):
                continue
            table = getattr(module, name)
            if isinstance(table, dict):
                # {coverage: (rule_id, signal)} — the coverage table's shape.
                ids.update(entry[0] for entry in table.values()
                           if isinstance(entry, tuple) and entry)
            elif isinstance(table, tuple):
                # (rule_id, signal, regex) triples.
                ids.update(entry[0] for entry in table
                           if isinstance(entry, tuple) and entry)

    labels = set(describe_live()["pii_detectors"])
    prefixes = {"phi", "pii"} | set(response_policy._POLICY_PERSONAL.values())
    for prefix in prefixes:
        ids |= {f"{prefix}.{label}" for label in labels}
    return ids


def hash_of(definition: dict) -> str:
    """SHA-256 over canonical JSON.

    Byte-identical in form to the backend's ``policy_snapshot_hash`` — same
    ``sort_keys``/``separators``/``ensure_ascii`` — so any independent verifier
    reimplementing either one gets the other for free.
    """
    canonical = json.dumps(definition, sort_keys=True, separators=(",", ":"),
                           ensure_ascii=True)
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def load(version: str) -> dict:
    """The FROZEN definition published under ``version``.

    Raises ``KeyError`` for a version this build does not carry — which is the
    honest answer. An SDK asked to explain a row minted by a newer release
    cannot, and saying so beats replaying the wrong rules.
    """
    from . import rulesets
    return rulesets.get(version)


def known_versions() -> tuple[str, ...]:
    from . import rulesets
    return rulesets.versions()


def drift() -> str | None:
    """``None`` when the live code matches :data:`CURRENT_VERSION`, else why not.

    This is the "someone edited a regex without bumping" detector. It returns a
    message rather than raising so the caller decides how loud to be — the test
    suite fails on it; the runtime does not, because a customer's process is the
    wrong place to discover a release-hygiene problem.
    """
    frozen = load(CURRENT_VERSION)
    live = describe_live()
    if hash_of(live) == hash_of(frozen):
        return None
    return (
        f"live rules no longer match frozen ruleset {CURRENT_VERSION!r}\n"
        f"  frozen: {hash_of(frozen)}\n"
        f"  live:   {hash_of(live)}\n"
        f"A published ruleset is IMMUTABLE — rows already in customers' chains "
        f"name it. Do not edit "
        f"rulesets/{CURRENT_VERSION.replace('.', '_')}.py. Mint a NEW version: "
        f"write the output of describe_live() to a new frozen module and point "
        f"CURRENT_VERSION at it."
    )


_current_hash: str | None = None
#: Whether the "provenance unavailable" warning has already been emitted.
_warned_unavailable = False


def current_hash() -> str:
    """The hash a guarded row carries: the FROZEN entry's, never a live recompute.

    Cached after the first call. Computed lazily rather than at import for a
    practical reason — it is what lets a brand-new version be generated by a
    script that imports this module before its frozen counterpart exists.
    """
    global _current_hash
    if _current_hash is None:
        _current_hash = hash_of(load(CURRENT_VERSION))
    return _current_hash


def __getattr__(name: str):
    # PEP 562: `ruleset.CURRENT_HASH` still reads as a constant to callers while
    # staying lazy underneath.
    if name == "CURRENT_HASH":
        return current_hash()
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")


def provenance() -> dict:
    """The two ``event_metadata`` keys a guarded row carries — or ``{}``.

    NEVER RAISES, and that is a correctness requirement rather than politeness.
    This is called while assembling a guarded event, inside ``log_interaction``'s
    blanket ``except Exception``. A registry that could not answer — a
    ``CURRENT_VERSION`` pointing at a module this build does not carry, a
    half-applied upgrade, a corrupted install — therefore used to discard THE
    WHOLE EVENT: measured, with ``CURRENT_VERSION = "2099.01.1"`` a prompt was
    still blocked and zero events were captured. A blocked prompt with no
    evidence is the one outcome an audit product may never produce.

    Provenance is an ENRICHMENT of the record. It must never be able to cost the
    record. Degrading to "no provenance" loses a nicety; raising loses the
    evidence, which is the thing itself.

    The failure is logged rather than swallowed silently, and ``drift()`` plus
    the test suite still catch a broken registry loudly at the time it is
    introduced — this is the last line of defence, not the first.
    """
    global _warned_unavailable
    try:
        return {"ruleset_version": CURRENT_VERSION, "ruleset_hash": current_hash()}
    except Exception as exc:                 # noqa: BLE001 — type name only
        # ONCE per process. current_hash() only caches on success, so a broken
        # build reaches this on EVERY guarded event — and a warning printed per
        # event is one a customer learns to filter, which is worse than one
        # printed once. Same reasoning, and the same shape, as policy.py's
        # _warned_tags.
        if not _warned_unavailable:
            _warned_unavailable = True
            log.warning(
                "foxy-audit: ruleset provenance unavailable (%s); events are being "
                "recorded WITHOUT it. The audit trail is intact — the rule ids on "
                "these rows simply do not name their ruleset. This is reported "
                "once per process.", type(exc).__name__)
        return {}


#: The keys :mod:`dispatch` strips when a backend rejects them (see its
#: degrade path). Named here so the two modules cannot disagree about the set.
PROVENANCE_KEYS = ("ruleset_version", "ruleset_hash")

__all__ = ["CURRENT_HASH", "CURRENT_VERSION", "PROVENANCE_KEYS", "describe_live",
           "drift", "hash_of", "known_versions", "load", "provenance"]
