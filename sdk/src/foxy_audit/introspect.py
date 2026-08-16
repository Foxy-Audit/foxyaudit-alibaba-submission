"""``check()`` and ``explain()`` — ask the policy a question, and replay a row.

TWO FUNCTIONS, TWO OPPOSITE CONTENT RULES. THAT IS THE DESIGN.
==============================================================

**``check()`` is CONTENT-BLIND BY CONSTRUCTION.** It answers "would this prompt
trip anything?" and returns LABELS ONLY — the rule ids and coarse signals the
wire already carries. It never returns, logs, or raises the text it was given.
It is the same promise the decorator makes, in a form you can call directly, so
adding it cannot widen what the SDK is willing to say about a prompt.

**``explain()`` DELIBERATELY SHOWS THE MATCHED SPANS, and that is correct.** It
exists to answer "prove it was a real breach", and a proof you cannot see is not
a proof. It runs on the customer's own machine, against a prompt the customer
supplied, where the raw text already lives — so showing them their own text
back reveals nothing they do not have.

THE BOUNDARY THAT MAKES THAT SAFE: spans are **stdout only**. They never enter a
payload, a log line, an exception message, a spool row, or a file this tool
writes. :meth:`ExplainResult.as_dict` therefore omits the matched text unless
asked for it explicitly — the default-safe direction, so any future code that
serialises a result gets the content-blind form without having to know to ask.
The CLI opts in, once, on its way to stdout.

If you are reading this because ``explain`` printed a prompt at you and it
looked wrong: that is the intended behaviour, and the paragraph above is why.

WHAT ``explain`` REPLAYS
========================
The row's OWN ruleset, never today's. A row records ``ruleset_version``; that
version's frozen definition is loaded and its patterns recompiled from their
recorded source text and flags. Replaying current rules against an old row and
presenting the result as "what fired" would be the fabrication this whole line
of work exists to remove.

AND THE ROW'S RULESET IS VERIFIED, NOT JUST NAMED
=================================================
A guarded row records TWO provenance keys, and they are written together for a
reason: ``ruleset_version`` says which definition ran, and ``ruleset_hash`` is
what lets a reader check that the copy in front of them IS that definition.
Loading by name alone trusts this build's registry to be untouched — and
``ruleset.load`` returns whatever the local module happens to contain, so a
hand-edit, a partial upgrade or a backported patch would make the replay
describe rules that never ran, and report it as authoritative.

So the loaded definition is re-hashed and compared. The frozen registry's
"never edit a published version" rule was, until this, enforced by a comment;
this is the check that makes it observable at the point it matters. See
``ruleset.py``'s "THE REGISTRY IS FROZEN, NOT CURRENT".

THE FOUR ANSWERS THAT ARE "I CANNOT"
====================================
Each is a real answer, reported plainly, never a traceback and never a silent
fallback:

* ``salt_unavailable`` — a salted row whose sidecar entry is missing. The
  commitment cannot be recomputed at all. Reporting "no match" would be a false
  negative on the exact question the tool exists to answer, and the reader would
  conclude the ledger was wrong. Same convention as the verifier's
  ``unprovable``: could-not-run is its own answer.
* ``unknown_ruleset`` — a row minted by a newer SDK than this one. Saying so
  beats replaying the wrong rules.
* ``ruleset_mismatch`` — this build HAS that version name and the bytes under it
  are not the ones the row was written against. Distinct from
  ``unknown_ruleset`` (we do not have it) and from ``hash_mismatch`` (which is
  about the PROMPT): here the registry itself is not what it claims to be, and
  the replay would be confidently wrong rather than absent.
* ``predates_provenance`` — a row written before 1.7.0, which names no ruleset.

``ruleset_verified`` is a FIELD rather than a fifth status, and it is
THREE-STATE: ``True`` checked and agreed, ``False`` checked and disagreed (which
is the ``ruleset_mismatch`` refusal above), ``None`` NOT CHECKED. A row that
names a version but records no hash is not a failure — the version is known and
the commitment matched, so the replay is still the best available answer — but
the answer is weaker, and the field plus a sentence in the message is how the
reader learns that instead of being told nothing. The third state exists because
"your registry was altered" and "the check never ran" are opposite news, and one
``False`` for both would hand a reader the wrong alarm.

WHAT THE DIGEST COVERS, AND WHAT IT DOES NOT
============================================
``ruleset_hash`` is ``hash_of()`` of the frozen DEFINITION: pattern sources and
flags, validator NAMES, the policy map, the reasons. Verifying it proves the
loaded definition is the one that ran — and stops exactly there.

It does not reach ``_VALIDATORS``. Those implementations are live code in this
module, versioned with the SDK rather than with the ruleset, and no row records
a digest of them: there is nothing a local copy could be compared against, so
extending the check would compare this build to itself and pass unconditionally.
The partial-upgrade case this module names can therefore still change a replay's
result through the validator code while the definition verifies.

Two rules bound that gap rather than closing it: a validator name's meaning is
FIXED FOREVER — new behaviour takes a NEW name, never a redefinition (see
:func:`replay`) — and a name this build does not implement raises rather than
silently skipping the check. Both are SDK-side discipline, not something the row
can prove, which is why every message here says "definition" where it would be
easy and wrong to say "ruleset".
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field

from . import hashing, policy as policy_engine, ruleset
# ⚠ THE ONE PLACE THIS MODULE SHARES CODE WITH THE LIVE DETECTOR, and it is
# deliberate. `replay` recompiles PATTERNS from the frozen definition rather than
# importing `pii`'s — that is what makes it a replay. Validator implementations
# are different: the definition records only a NAME, so the code behind each name
# has to live somewhere, and a second copy of the issuer table would be a second
# thing to get wrong. The table is data; the names above are what is versioned.
from .issuer_ranges import starts_with_assigned_iin

#: Compile-flag names, as recorded in a frozen definition, back to the flags.
_FLAGS = {"IGNORECASE": re.IGNORECASE, "MULTILINE": re.MULTILINE,
          "DOTALL": re.DOTALL, "VERBOSE": re.VERBOSE, "ASCII": re.ASCII}


# ── check ────────────────────────────────────────────────────────────────────
@dataclass(frozen=True)
class CheckResult:
    """What the local policy says about a prompt. LABELS ONLY — never the text.

    A NEW public type rather than the internal :class:`policy.PolicyDecision`,
    deliberately:

    * ``PolicyDecision`` is shared with the response side and has changed in
      three of the last four releases. Exporting it would freeze a structure the
      SDK still needs to evolve internally.
    * Its ``action`` vocabulary (``"allow"`` / ``"flag"``) is internal. A caller
      asking "would this be blocked?" wants a boolean and the reason, not a word
      whose meaning depends on the mode they did not pass.
    * The fields here ARE a contract we are willing to keep: they are the ones
      that already travel on the wire.
    """

    policy: str
    triggered: bool
    rules: list = field(default_factory=list)
    signals: list = field(default_factory=list)
    reason: str = "none"
    ruleset_version: str = ""
    ruleset_hash: str = ""

    def as_dict(self) -> dict:
        """A plain dict, safe to print or serialise. Carries no prompt text."""
        return {"policy": self.policy, "triggered": self.triggered,
                "rules": list(self.rules), "signals": list(self.signals),
                "reason": self.reason,
                "ruleset_version": self.ruleset_version,
                "ruleset_hash": self.ruleset_hash}


def check(prompt, policy: str = "default") -> CheckResult:
    """Would this prompt trip anything, under ``policy``, with today's rules?

    CONTENT-BLIND: returns labels, never the text. Needs no API key, no network
    and no spool — this is local policy evaluation, and requiring an account to
    ask "does my prompt trip anything?" would be absurd.

    ``triggered`` says a rule matched. Whether that BLOCKS depends on the mode
    the caller runs the decorator under, which is not this function's business:
    under ``observe`` nothing is ever blocked, and this still tells you what
    fired.

    The ruleset named in the result is the CURRENT one — ``check`` asks about
    today's rules by definition. Use :func:`explain` to replay a historical row.
    """
    decision = policy_engine.evaluate(prompt, policy)
    provenance = ruleset.provenance()
    return CheckResult(
        policy=policy,
        triggered=decision.triggered,
        rules=list(decision.rules),
        signals=list(decision.signals),
        reason=decision.reason,
        ruleset_version=provenance.get("ruleset_version", ""),
        ruleset_hash=provenance.get("ruleset_hash", ""),
    )


# ── explain ──────────────────────────────────────────────────────────────────
@dataclass(frozen=True)
class Match:
    """One rule match, WITH the span it matched. Stdout only — see the module
    docstring."""

    rule_id: str
    start: int
    end: int
    text: str

    def as_dict(self, include_text: bool = False) -> dict:
        out = {"rule_id": self.rule_id, "start": self.start, "end": self.end}
        if include_text:
            out["text"] = self.text
        return out


#: Every status :func:`explain` can return. Four of them are "I cannot".
STATUSES = ("explained", "no_matches", "hash_mismatch", "row_not_found",
            "salt_unavailable", "unknown_ruleset", "ruleset_mismatch",
            "predates_provenance")


@dataclass(frozen=True)
class ExplainResult:
    """The outcome of replaying one exported row against its own ruleset.

    ``message`` is the product here as much as the data is: in the three cases
    the tool cannot answer, the sentence is what stops a reader drawing the
    wrong conclusion.
    """

    status: str
    message: str
    event_id: str = ""
    policy_tag: str = ""
    ruleset_version: str = ""
    commitment_verified: bool = False
    #: Did the loaded DEFINITION hash to what the row recorded? Three-state.
    #:
    #: * ``True``  — the digest check ran and AGREED.
    #: * ``False`` — the digest check ran and DISAGREED. Always accompanied by
    #:   the ``ruleset_mismatch`` status, because then the replay would be
    #:   confidently wrong rather than merely unconfirmed.
    #: * ``None``  — THE CHECK DID NOT RUN. Either the row records no
    #:   ``ruleset_hash`` (no shipped SDK emits one without the other, so that is
    #:   a hand-edited export), or ``explain`` answered before reaching it —
    #:   ``row_not_found``, ``hash_mismatch``, ``salt_unavailable``,
    #:   ``predates_provenance``, an unknown version.
    #:
    #: ⚠ NOT A BOOL, and the third state is the point. Collapsing "altered" and
    #: "never checked" into one ``False`` tells a reader their registry may have
    #: been tampered with when in fact they simply supplied the wrong prompt.
    #:
    #: ⚠ WHAT ``True`` ASSERTS, AND WHAT IT DOES NOT. It asserts that the frozen
    #: DEFINITION — every pattern source and flag, every validator NAME, the
    #: policy map, the reasons — is byte-identical, canonically, to the one the
    #: row was written against. That is the whole of what ``ruleset_hash``
    #: covers, because it is ``hash_of()`` of that dict and nothing else.
    #:
    #: It does NOT assert that the validator IMPLEMENTATIONS behind those names
    #: are the same code. ``_VALIDATORS`` lives in this module and is versioned
    #: with the SDK, not with the ruleset; a row records no digest of it, so
    #: there is nothing to compare a local copy against — a check would compare
    #: this build to itself and always pass. What holds instead is a rule this
    #: SDK keeps: a validator name's meaning is FIXED FOREVER and a new
    #: behaviour gets a new name (see :func:`replay`), and a name this build
    #: cannot implement RAISES rather than silently skipping. Those bound the
    #: gap; they do not close it, and this field does not claim they do.
    ruleset_verified: bool | None = None
    matches: list = field(default_factory=list)

    @property
    def ok(self) -> bool:
        """Did the replay actually answer the question?"""
        return self.status in ("explained", "no_matches")

    def as_dict(self, include_text: bool = False) -> dict:
        """Serialise. **Omits the matched text unless explicitly asked.**

        Default-safe on purpose: a span is raw customer content, and the rule is
        that it reaches stdout and nowhere else. Making the safe form the default
        means code that serialises a result without thinking about it gets the
        content-blind version.
        """
        return {"status": self.status, "message": self.message,
                "event_id": self.event_id, "policy_tag": self.policy_tag,
                "ruleset_version": self.ruleset_version,
                "commitment_verified": self.commitment_verified,
                "ruleset_verified": self.ruleset_verified,
                "matches": [m.as_dict(include_text) for m in self.matches]}


def _row_for(export: dict, event_id: str) -> dict | None:
    for row in export.get("logs", []) or []:
        if str(row.get("event_id")) == str(event_id):
            return row
    return None


def _resolve_tag(definition: dict, policy_tag: str) -> tuple:
    """Which check families the ROW's ruleset ran for its tag.

    Resolved through the FROZEN definition's own alias and policy maps, not
    through today's ``policy.py``. The alias table is part of what a version
    means — ``hipaa_basic`` resolved to nothing at all before 1.6.0 — so reading
    it from live code would replay the wrong policy for an old row.
    """
    policy_map = definition.get("policy_map", {})
    tag = (policy_tag or "").strip().lower()
    tag = policy_map.get("aliases", {}).get(tag, tag)
    baseline = tuple(policy_map.get("baseline", ()))
    extra = tuple(policy_map.get("extra", {}).get(tag, ()))
    return baseline + extra


def _compile(entry: dict):
    flags = 0
    for name in entry.get("flags", ()) or ():
        flags |= _FLAGS.get(name, 0)
    return re.compile(entry["pattern"], flags)


def _luhn_ok(digits: str) -> bool:
    total, alt = 0, False
    for char in reversed(digits):
        if not char.isdigit():
            return False
        value = int(char)
        if alt:
            value *= 2
            if value > 9:
                value -= 9
        total += value
        alt = not alt
    return total % 10 == 0 and len(digits) >= 13


#: Every validator name a frozen definition can record, and what it MEANT.
#:
#: ⚠ EACH NAME KEEPS ITS OWN MEANING FOREVER. A row stamped 2026.08.1 or .2
#: records ``"luhn"`` and must replay under the plain checksum that ran on the
#: day it was written — including its acceptance of ``0000000000000000``.
#: Redefining ``"luhn"`` to today's stricter gate would make those rows look like
#: lies about themselves.
#:
#: A dict rather than a chain of ``if``s so an UNKNOWN name is a lookup failure
#: rather than a silent pass. It is raised as :class:`UnknownValidator`, and the
#: PUBLIC paths turn that into an answer — see :func:`explain`'s
#: ``unknown_ruleset`` branch. A traceback out of ``foxy explain`` would be the
#: tool failing to say "I cannot", which is the one thing this module promises.
#: ⚠ AND AGAIN AT 2026.08.4. ``luhn+iin+distinct`` adds "begins with an issuer
#: identification number a card network actually issues from". It is a THIRD
#: entry, not an edit to the second: a 2026.08.3 row records ``luhn+distinct``
#: and replays under Luhn-plus-not-one-repeated-digit — INCLUDING its acceptance
#: of the Luhn-passing runs 2026.08.4 starts rejecting. That acceptance is not a
#: bug in the replay; it is what those rows' rules were.
_VALIDATORS = {
    "luhn": lambda digits: _luhn_ok(digits),
    "luhn+distinct": lambda digits: _luhn_ok(digits) and len(set(digits)) > 1,
    "luhn+iin+distinct": lambda digits: (_luhn_ok(digits)
                                         and len(set(digits)) > 1
                                         and starts_with_assigned_iin(digits)),
    "not-all-zero": lambda digits: set(digits) != {"0"},
}


class UnknownValidator(LookupError):
    """A frozen definition names a validator this build does not implement.

    Raised by :func:`replay`, which is a low-level function whose caller decides
    how loud to be. :func:`explain` catches it and answers ``unknown_ruleset``:
    a row written by a newer SDK cannot be replayed honestly by an older one, and
    saying so is the correct outcome — the same answer that function already
    gives when the VERSION itself is unknown.
    """


def replay(definition: dict, text: str, policy_tag: str) -> list:
    """Every match the ROW's ruleset finds in ``text``, with spans.

    Recompiled from the frozen definition's recorded pattern source and flags —
    which is what makes this a replay of that version rather than of today's
    code.
    """
    families = _resolve_tag(definition, policy_tag)
    matches: list = []

    if "injection" in families:
        for rule_id, entry in sorted(definition["prompt_rules"]["injection"].items()):
            for found in _compile(entry).finditer(text):
                matches.append(Match(rule_id, found.start(), found.end(), found.group()))
    if "secrets" in families:
        for rule_id, entry in sorted(definition["prompt_rules"]["secret"].items()):
            for found in _compile(entry).finditer(text):
                matches.append(Match(rule_id, found.start(), found.end(), found.group()))

    prefix = "phi" if "phi" in families else ("pii" if "pii" in families else None)
    if prefix:
        for label, entry in sorted(definition.get("pii_detectors", {}).items()):
            for found in _compile(entry).finditer(text):
                # The definition NAMES each detector's validator, so honour the
                # one THIS ROW's ruleset recorded — otherwise the replay reports
                # a match the SDK itself would have discarded, or discards one it
                # kept.
                #
                # ⚠ EACH NAME KEEPS ITS OWN MEANING FOREVER. Rows stamped
                # 2026.08.1 / .2 record "luhn" and replay under the plain
                # checksum, which is what ran on the day they were written —
                # including its acceptance of `0000000000000000`. From 2026.08.3
                # the card gate ALSO rejects a single repeated digit, and the
                # phone gate (recorded for the first time) rejects an all-zero
                # run. Those are DIFFERENT names, never redefinitions.
                #
                # An unrecognised name RAISES rather than skipping the check.
                # Applying no validator would over-report — a plausible-looking
                # answer that is wrong — and this function's whole purpose is to
                # replay what actually ran. `explain` turns it into an
                # `unknown_ruleset` answer.
                validator = entry.get("validator")
                if validator:
                    if validator not in _VALIDATORS:
                        raise UnknownValidator(validator)
                    digits = re.sub(r"\D", "", found.group())
                    if not _VALIDATORS[validator](digits):
                        continue
                matches.append(Match(f"{prefix}.{label}", found.start(),
                                     found.end(), found.group()))

    return sorted(matches, key=lambda m: (m.start, m.rule_id))


def _load_salt(sidecar_path: str, event_id: str) -> str | None:
    from . import sidecar
    return sidecar.read_salt(sidecar_path, event_id)


def explain(prompt, event_id: str, export, commitment_key: str,
            salt_sidecar_path: str = "") -> ExplainResult:
    """Replay one exported row against the ruleset IT names.

    ``export`` is a parsed ``/v1/logs/export?format=json`` document or a path to
    one. ``prompt`` is the text the caller believes the row committed — supplied
    by them, because Foxy never had it.

    SHOWS THE MATCHED SPANS. See the module docstring for why that is correct
    here and wrong in :func:`check`, and for the stdout-only boundary.
    """
    if isinstance(export, (str, bytes)):
        with open(export, "r", encoding="utf-8") as handle:
            export = json.load(handle)

    row = _row_for(export, event_id)
    if row is None:
        return ExplainResult(
            "row_not_found",
            f"No row with event_id {event_id} in this export. Check the id, or "
            f"export a range that covers it.",
            event_id=event_id)

    policy_tag = str(row.get("policy_tag") or "default")
    metadata = row.get("event_metadata") or {}
    version = metadata.get("ruleset_version")

    # ── the commitment ───────────────────────────────────────────────────────
    salted = str(row.get("commitment_alg") or "").endswith("-salted")
    salt = None
    if salted:
        salt = _load_salt(salt_sidecar_path, event_id) if salt_sidecar_path else None
        if not salt:
            return ExplainResult(
                "salt_unavailable",
                f"Row {event_id} was committed with a per-event salt "
                f"({row.get('commitment_alg')}), and no salt for it was found"
                + (f" in {salt_sidecar_path}" if salt_sidecar_path
                   else " (no --sidecar given)")
                + ". Its commitment CANNOT be recomputed without that salt, so "
                  "this is not a mismatch and not a pass — the check could not "
                  "run. The salt lives only on your machine; Foxy never had it. "
                  "Point --sidecar at the file the SDK wrote (config "
                  "salt_sidecar_path / FOXY_SALT_SIDECAR).",
                event_id=event_id, policy_tag=policy_tag,
                ruleset_version=str(version or ""))

    recomputed = hashing.commitment_hex(prompt, commitment_key, salt)
    if recomputed != row.get("prompt_hash"):
        return ExplainResult(
            "hash_mismatch",
            f"The text you supplied does not match what row {event_id} "
            f"committed. The row is intact; this is simply not the prompt it "
            f"covers. (If you expected a match, check the commitment key.)",
            event_id=event_id, policy_tag=policy_tag,
            ruleset_version=str(version or ""))

    # ── the ruleset ──────────────────────────────────────────────────────────
    if not version:
        return ExplainResult(
            "predates_provenance",
            f"Row {event_id} carries no ruleset_version: it was written before "
            f"SDK 1.7.0, when rows began naming the rules that produced them. "
            f"The commitment MATCHES, so this is the right prompt — but the "
            f"rules in force that day were not recorded, and replaying today's "
            f"rules would tell you what would fire NOW, not what fired then. "
            f"That distinction is the whole point of the version, so this tool "
            f"will not guess.",
            event_id=event_id, policy_tag=policy_tag, commitment_verified=True)

    try:
        definition = ruleset.load(str(version))
    except KeyError:
        return ExplainResult(
            "unknown_ruleset",
            f"Row {event_id} names ruleset {version!r}, which this SDK does not "
            f"carry (it has: {', '.join(ruleset.known_versions())}). The row was "
            f"minted by a NEWER release. Upgrade foxy-audit to replay it — "
            f"replaying the rules this build happens to have would describe a "
            f"different policy than the one that actually ran.",
            event_id=event_id, policy_tag=policy_tag,
            ruleset_version=str(version), commitment_verified=True)

    # ── is the definition we loaded the one the row was written against? ─────
    #
    # ⚠ #220. Until this, `explain` loaded by VERSION NAME ALONE. The row records
    # a hash precisely so a reader can check that the local copy of that version
    # is the one that ran, and nothing read it — so a hand-edited, partially
    # upgraded or backported registry produced a replay of the WRONG RULES,
    # reported as authoritative.
    #
    # Not hypothetical: 2026.08.3 was regenerated in place three times during
    # 1.9.0's review. That was safe only because it was unpublished, and the
    # rule that makes it unsafe afterwards was a comment in a docstring.
    recorded_hash = str(metadata.get("ruleset_hash") or "")
    loaded_hash = ruleset.hash_of(definition)
    if recorded_hash and recorded_hash != loaded_hash:
        return ExplainResult(
            "ruleset_mismatch",
            f"Row {event_id} names ruleset {version!r} and records the digest "
            f"{recorded_hash[:12]}…, but this build's copy of {version!r} hashes "
            f"to {loaded_hash[:12]}…. Same name, DIFFERENT RULES. A published "
            f"ruleset is immutable — rows in customers' chains name it — so one "
            f"of the two has been altered: either this install's registry (a "
            f"hand-edit, a partial upgrade, a backported patch) or the row's "
            f"recorded digest. Replaying would describe rules that did not run, "
            f"so this tool will not. The commitment MATCHED, so the prompt and "
            f"the row do belong together; it is the rules that cannot be "
            f"trusted.",
            event_id=event_id, policy_tag=policy_tag,
            ruleset_version=str(version), commitment_verified=True,
            ruleset_verified=False)

    # A row can name a version and record no hash. No shipped SDK emits one
    # without the other — both keys landed together in 1.7.0 and `provenance()`
    # returns them as one dict or not at all — so this is a hand-edited export
    # or a non-Foxy producer. It is NOT a refusal: the version is known and the
    # commitment matched, so the replay is still the best available answer. What
    # changes is that it is unconfirmed, which `ruleset_verified` and the closing
    # sentence of the message both say out loud.
    #
    # ⚠ THE NOTE IS cp1252-SAFE, and that is not cosmetic. A first draft opened
    # it with U+26A0 (the warning sign this file's own comments use freely).
    # Comments are never printed; MESSAGES ARE, and a Windows console is cp1252 —
    # `foxy explain` died with UnicodeEncodeError on that path, which is the tool
    # failing to say anything at all. Guarded by
    # test_every_explain_message_survives_a_cp1252_console.
    #
    # None, NOT False: the check did not run. `False` is reserved for a digest
    # that ran and DISAGREED, which is the refusal above. See the field's
    # docstring — collapsing the two would report a hand-edited export in the
    # same words as a tampered registry.
    ruleset_verified = True if recorded_hash else None
    unverified_note = "" if ruleset_verified else (
        f" NOTE: the row records no ruleset_hash, so this SDK could not confirm "
        f"that its copy of {version!r} is the definition that actually ran. "
        f"Every SDK from 1.7.0 records one; a row without it was not written by "
        f"a released foxy-audit, or was edited after export.")

    try:
        matches = replay(definition, str(prompt), policy_tag)
    except UnknownValidator as unknown:
        # ⚠ THE PUBLIC PATH ANSWERS; IT DOES NOT RAISE. A row can name a ruleset
        # this build CARRIES while that definition names a VALIDATOR it does not
        # implement — a partial upgrade, a hand-edited registry, a definition
        # from a newer release backported without its code. Before this, that
        # escaped `foxy explain` as a KeyError traceback: the tool failing to say
        # "I cannot" is the one outcome this module promises never to produce.
        #
        # Reported as `unknown_ruleset` rather than a new outcome because it is
        # the same situation from the caller's side — this SDK cannot honestly
        # replay this row — and `OUTCOMES` is a documented vocabulary that
        # surfaces (the CLI, ExplainResult consumers) already switch on.
        return ExplainResult(
            "unknown_ruleset",
            f"Row {event_id} names ruleset {version!r}, whose definition uses "
            f"the validator {str(unknown)!r} — this SDK does not implement it "
            f"(it has: {', '.join(sorted(_VALIDATORS))}). Upgrade foxy-audit to "
            f"replay this row. Replaying it without that validator would report "
            f"matches the SDK which wrote the row had discarded.",
            event_id=event_id, policy_tag=policy_tag,
            ruleset_version=str(version), commitment_verified=True,
            # ⚠ THIS PATH IS PAST THE DIGEST CHECK, so it carries the verdict
            # rather than dropping back to the default. The distinction is the
            # whole diagnosis here: a VERIFIED definition naming a validator
            # this build lacks means "upgrade the SDK", while the same message
            # with the digest unchecked leaves open that the definition itself
            # is not what it claims. Defaulting would have thrown away an
            # answer already computed three lines up.
            ruleset_verified=ruleset_verified)
    recorded = list((metadata.get("policy_rules") or []))
    if not matches:
        return ExplainResult(
            "no_matches",
            f"The commitment matches and ruleset {version} replayed cleanly, but "
            f"no rule in it matches this text"
            + (f", while the row recorded {', '.join(recorded)}. That is worth "
               f"investigating: the row's rules and its own ruleset disagree."
               if recorded else ". The row recorded no rules either, so the two "
                                "agree.")
            + unverified_note,
            event_id=event_id, policy_tag=policy_tag,
            ruleset_version=str(version), commitment_verified=True,
            ruleset_verified=ruleset_verified)

    return ExplainResult(
        "explained",
        f"Commitment verified against row {event_id}, and ruleset {version} "
        f"— whose definition matches the digest the row recorded — matches "
        f"{len(matches)} span(s) under policy {policy_tag!r}."
        if ruleset_verified else
        f"Commitment verified against row {event_id}, and ruleset {version} "
        f"matches {len(matches)} span(s) under policy {policy_tag!r}."
        + unverified_note,
        event_id=event_id, policy_tag=policy_tag,
        ruleset_version=str(version), commitment_verified=True,
        ruleset_verified=ruleset_verified, matches=matches)


#: ``UnknownValidator`` is exported because ``replay`` is, and ``replay`` RAISES
#: it — its own docstring tells a caller to catch it. An exception a public
#: function can raise but that the module does not name is one a caller can only
#: reach by importing a private symbol.
__all__ = ["CheckResult", "ExplainResult", "Match", "STATUSES",
           "UnknownValidator", "check", "explain", "replay"]
