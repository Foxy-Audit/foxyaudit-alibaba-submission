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

THE SIX ANSWERS THAT ARE "I CANNOT"
===================================
Each is a real answer, reported plainly, never a traceback and never a silent
fallback:

* ``export_unreadable`` — the file handed to us is not a
  ``/v1/logs/export`` document: its top level is not an object, or its ``logs``
  is not a list, or that list holds entries none of which is a row. ⚠ IT IS NOT
  ``row_not_found``, and the split is S17's decision — see :func:`explain`,
  which carries the reasoning at the point the two part.
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
* ``ruleset_unrecorded`` — a row that RECORDS RULE IDS and names no ruleset:
  the rules that fired were written down and the definition behind them was
  not. ⚠ THE ROW DOES NOT SAY WHY, and this status is named for what is missing
  rather than for a cause, because the tool cannot read one. Three live paths
  produce it and a CURRENT SDK walks two of them:

  1. ``dispatch._strip_provenance`` removes ``ruleset.PROVENANCE_KEYS`` and
     ``dispatch.TYPED_TAG_KEYS``, and leaves ``policy_rules`` standing, so any
     backend that 422s the provenance keys — a lagging deploy, a self-hosted install, the frozen
     production one — takes a resend in exactly this shape.
  2. ``ruleset.provenance()`` returns ``{}`` when the registry cannot answer,
     deliberately: "provenance is an ENRICHMENT of the record. It must never be
     able to cost the record."
  3. an SDK older than 1.7.0, which recorded no provenance at all.

  ⚠ IT WAS CALLED ``predates_provenance`` UNTIL 1.13.0, and that name asserted
  a date none of the three can be read off a row — the same defect as the old
  message, one layer up, in the token every surface prints and every consumer
  switches on. Cause (1) also gets MORE common: S13 sends ``policy_tag_raw`` to
  a production backend that will never allowlist it. What separates the three is
  the reader's delivery logs and SDK version, so the message points there
  instead of choosing.
* ``provenance_ambiguous`` — a row that records NO DECISION. Two very different
  rows look exactly like this and nothing in the row tells them apart: a clean
  ``observe`` row, where no preflight ran and the clean path builds no
  ``event_metadata`` at all (that absence is what keeps an observe payload
  byte-identical), and a pre-1.7.0 row, where rules may have run and gone
  unrecorded. Guessing between "nothing was checked" and "something may have
  fired and was not written down" is the one thing this tool must not do.

THE ANSWER THAT NEEDS NO REPLAY
===============================
``no_rules_fired`` — the row records a ``decision`` and NO rule ids. Nothing
fired on it, so no ruleset was recorded, and that absence is the design rather
than a gap: provenance rides only with the rule ids it explains (see
``client.py``'s "Ruleset provenance rides ONLY with the rule ids it explains").
There is nothing to replay, and saying "this row predates 1.7.0" about it — as
this tool did until 1.13.0 — is a false statement of fact in the one place built
to establish facts.

⚠ IT IS STILL NOT ``no_matches``. ``no_matches`` means a replay RAN, against the
definition the row named, and matched nothing. Here no replay ran at all: what
is reported is the ROW'S OWN RECORD that nothing fired. The news is good and the
evidence for it is weaker, so it wears the understating mark — see
``foxy_testbed.core.EXPLAIN_FAMILIES``.

``ruleset_verified`` is a FIELD rather than a status, and it is
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

from . import hashing, normalise, policy as policy_engine, ruleset
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


#: Every status :func:`explain` can return. SIX of them are "I cannot", and
#: ``no_rules_fired`` is the one answer that needs no replay — see the module
#: docstring for both groups.
#:
#: ⚠ THIS TUPLE IS THE VOCABULARY AND THE AUTHORITY. `foxy_testbed.core`'s
#: `EXPLAIN_FAMILIES` is checked against it rather than against a copy, so
#: adding a member here turns that completeness guard red until someone decides
#: which family the new outcome belongs to. That failure is the handshake.
STATUSES = ("explained", "no_matches", "hash_mismatch", "row_not_found",
            "export_unreadable", "salt_unavailable", "unknown_ruleset",
            "ruleset_mismatch", "ruleset_unrecorded", "no_rules_fired",
            "provenance_ambiguous")


@dataclass(frozen=True)
class ExplainResult:
    """The outcome of replaying one exported row against its own ruleset.

    ``message`` is the product here as much as the data is: in the cases
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
    #:   ``row_not_found``, ``export_unreadable``, ``hash_mismatch``,
    #:   ``salt_unavailable``, ``ruleset_unrecorded``, ``no_rules_fired``,
    #:   ``provenance_ambiguous``,
    #:   an unknown version. The last three all sit on the no-version branch,
    #:   which returns before a definition is ever loaded, so there is nothing
    #:   to have hashed.
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


def _entries(export) -> list | None:
    """The rows an export offers, or ``None`` when this is not an export.

    ⚠ THE TWO ANSWERS ARE DIFFERENT NEWS AND THIS IS THE ONE PLACE THEY PART.
    ``[]`` is a well-formed export that carries no rows — the reader's RANGE is
    wrong. ``None`` is a file that is not a ``/v1/logs/export`` document at all
    — the reader's FILE is wrong. Both callers read the distinction off this
    return value rather than re-deriving it, because the second copy of this
    shape test is how the two drifted apart in the first place: `_row_for`
    tested one thing, the arm that reports the news tested another, and a
    top-level-list export raised `AttributeError` out of `_row_for` before the
    arm could answer at all.

    ⚠ EVERY BRANCH HERE IS A SHAPE A READER'S FILE CAN LEGALLY HOLD. `explain`
    parses arbitrary JSON, so ``export`` may be a list, a number or a string,
    and ``logs`` may be anything at all — including an int, which the old
    ``export.get("logs", []) or []`` handed straight to ``for`` as a TypeError.
    """
    if not isinstance(export, dict):
        return None
    logs = export.get("logs")
    if not isinstance(logs, (list, tuple)):
        return None
    return list(logs)


def _logs_kind(export) -> str:
    """What the file offers under ``logs``, as a type name or ``"absent"``.

    A TYPE NAME, NEVER THE VALUE. The point of the sentence this feeds is to
    tell a reader what shape their file is, and printing the value would put
    arbitrary file content into a message for no gain — the name is what
    identifies the mistake. It also needs no `_printable` pass: these are
    Python type names, produced here, ASCII by construction.
    """
    if not isinstance(export, dict) or "logs" not in export:
        return "absent"
    return type(export["logs"]).__name__


def _row_for(export, event_id: str) -> dict | None:
    """The row with this event_id, or None. ARBITRARY JSON IN, no traceback out.

    ⚠ `logs` is whatever the reader's file contains. `{"logs": ["not-a-row"]}`
    reached `.get` on a string and raised AttributeError out of the public path
    — two lines above the non-dict `event_metadata` guard, and the same class as
    it. A non-dict entry is not a row, so it is skipped, and the caller turns
    the absence into an answer.
    """
    for row in _entries(export) or ():
        if isinstance(row, dict) and str(row.get("event_id")) == str(event_id):
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
    code. From 2026.08.5 that includes the VIEWS the definition records: which
    text the patterns ran against is as much a part of "the rules" as the
    patterns themselves.
    """
    families = _resolve_tag(definition, policy_tag)
    matches: list = []

    if "injection" in families:
        # ⚠ THE VIEWS THE ROW'S OWN RULESET RECORDS, NOT TODAY'S. A definition
        # published before 2026.08.5 has no ``prompt_views`` key at all, and
        # ``views_for(text, None)`` returns the raw view alone — which is
        # exactly what those versions did. Reading the live
        # ``normalise.describe()`` here instead would replay a 2026.08.4 row
        # against a normalised copy of its prompt and report matches the SDK
        # that wrote the row never made.
        views = normalise.views_for(text, definition.get("prompt_views"))
        seen = set()
        for rule_id, entry in sorted(definition["prompt_rules"]["injection"].items()):
            regex = _compile(entry)
            for view in views:
                for found in regex.finditer(view.text):
                    start, end = view.origin(*found.span())
                    # The span — and therefore the text an auditor is shown — is
                    # in the PROMPT: the spaced-out run or the base64 blob that
                    # really was there, never the transformed copy. Two views
                    # finding the same override at the same span is one finding,
                    # not two, so identical spans collapse.
                    if (rule_id, start, end) in seen:
                        continue
                    seen.add((rule_id, start, end))
                    matches.append(Match(rule_id, start, end, text[start:end]))
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


def _printable(value) -> str:
    """One untrusted value, rendered so the MESSAGE can always be printed.

    ⚠ MESSAGES ARE PRINTED AND EXPORTS ARE FILES THE READER HANDS US. Every
    sentence here interpolates values that came out of a row — rule ids, the
    policy tag, the version name, a decision label — and a Windows console is
    cp1252. One non-ASCII character anywhere in a hand-edited or foreign export
    turned ``foxy explain`` into a ``UnicodeEncodeError``, which is the tool
    failing to say anything at all: the one outcome this module promises never
    to produce. ``test_every_explain_message_survives_a_cp1252_console`` did not
    catch it because every id it feeds is ASCII.

    ESCAPED, NOT DROPPED, and to **ASCII** rather than to cp1252. Escaping keeps
    the information — a reader still sees ``\\u0130`` and can tell the id was not
    what they expected — and ASCII is a subset of every encoding a terminal
    uses, so this is encodable on consoles cp1252 has never heard of.

    ⚠ CONTROL CHARACTERS TOO, AND THAT IS WHY THE MESSAGES DROPPED ``!r``.
    Every quoted site used to read ``{value!r}``, which escaped a newline and
    a terminal escape sequence for free. Once the value arrives here already
    escaped, ``!r`` escapes the escape — ``2026.08.İ`` rendered with a
    DOUBLED backslash, and a reader cannot tell that from a value that really
    contained one. So the sentences carry their own quotes and this pass does
    the whole job: a value out of an export can otherwise smear a message
    across three lines, or carry an ANSI escape and clear the console of the
    person auditing it. ASCII IS NOT THE SAME PROMISE AS PRINTABLE.

    ⚠ IT IS APPLIED TO INTERPOLATED VALUES ONLY, NEVER TO A WHOLE MESSAGE. The
    sentences here contain em dashes on purpose; those are this module's own
    literals, already proven printable, and escaping them would mangle every
    message to fix a value.
    """
    ascii_only = str(value).encode("ascii", "backslashreplace").decode("ascii")
    return "".join(
        char if char.isprintable() else
        char.encode("unicode_escape").decode("ascii") for char in ascii_only)


def _rule_ids(metadata: dict) -> list:
    """The rule ids a row records, as strings, from ARBITRARY JSON.

    ⚠ AN EXPORT IS A FILE THE READER HANDS US, and a hand-edited or foreign one
    can put anything under ``policy_rules``. The first cut of the no-version
    branch did ``list(metadata.get("policy_rules") or [])`` and then
    ``", ".join(...)`` on the result, which raises ``TypeError`` on an int and
    on a list of ints — turning the branch that promises never to produce a
    traceback into one. ``list()`` on a dict also silently yields its KEYS,
    which would report a rule id nobody recorded.

    A non-empty value of the wrong shape is still evidence that rules WERE
    recorded, so it is rendered rather than discarded: reading it as "no rules"
    would send the row down the wrong arm and have this tool assert that nothing
    fired.
    """
    raw = metadata.get("policy_rules")
    if isinstance(raw, (list, tuple)):
        return [_printable(rule) for rule in raw]
    return [_printable(raw)] if raw else []


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

    # ⚠ NORMALISED AFTER THE LOOKUP AND BEFORE EVERY MESSAGE, and the ORDER is
    # the whole trick. `event_id` appears in ALL SIX sentences below, so leaving
    # it raw left `_printable` guarding the values it was written for while the
    # one value every message carries went through unescaped — measured: an
    # export with `event_id = "ev-İ-1"` raised UnicodeEncodeError on a
    # cp1252 console from every reachable arm, including the three this phase
    # wrote. Doing it here rather than at each interpolation is deliberate: it
    # cannot be forgotten by the next sentence somebody adds, and it cannot
    # break the ROW lookup, which has already happened one line up against
    # the caller's real value.
    #
    # 🔴 IT DOES BREAK A DIFFERENT ONE. `_load_salt` is called with this
    # rebound value further down, and the sidecar is keyed by the id the SDK
    # wrote — so a salted row with a non-ASCII event_id reports
    # `salt_unavailable` with the salt sitting in the file. Measured; see the
    # block at that call. This sentence used to end "cannot break the lookup",
    # singular, which was a claim about all of them.
    event_id = _printable(event_id)
    if row is None:
        # ⚠ TWO DIFFERENT PIECES OF NEWS, AND SENDING BOTH AS "check the id"
        # STEERS THE READER AT THE WRONG THING. A file whose `logs` holds no
        # rows — or which has no `logs` list at all — is not a ledger export;
        # telling someone to check their event_id when their FILE is the
        # problem is the kind of confidently-unhelpful answer this module
        # exists to avoid.
        #
        # This distinction used to be carried by an AttributeError — `_row_for`
        # called `.get` on whatever it found — which the testbed caught broadly
        # and rendered as "THE EXPORT COULD NOT BE READ". That worked there and
        # nowhere else: `foxy explain` has no such catch, so the same file gave
        # a CLI user a traceback. The news is kept; the crash is not.
        #
        # ⚠ S17 · IT IS A STATUS OF ITS OWN NOW, AND THAT WAS THE DECISION.
        # S14d gave this arm the right SENTENCE under the token `row_not_found`,
        # and left the two halves disagreeing: the message says "your file is
        # not an export", the status says "this export has no such row". A
        # reader gets the message; a CONSUMER gets the token, and a consumer
        # switching on `row_not_found` retries with a different event_id —
        # which can never succeed against a file that is not a ledger. The
        # remedy differs (re-export, not re-check the id), so the token must.
        #
        # THE COUNTER-ARGUMENT IS REAL AND IS RECORDED HERE RATHER THAN WON:
        # `row_not_found` is literally true of these files, and it already sits
        # in the `cannot` family, so nothing renders wrongly today. Both hold.
        # They are answers about the READER and the COLOUR; the objection above
        # is about the CONSUMER, and #239 is the precedent — that phase changed
        # a status NAME, not a behaviour, precisely because "a name is what
        # every surface prints and every consumer switches on". This is the
        # same defect one layer down, and fixing the sentence while leaving the
        # token was fixing the half that was already least wrong.
        #
        # ⚠ AN EMPTY `logs` IS NOT THIS. `{"logs": []}` is a well-formed export
        # that covers no rows: readable, honest, and the reader's RANGE is what
        # is wrong. It keeps `row_not_found` and the "export a range that covers
        # it" advice. `_entries` is where that line is drawn, once.
        entries = _entries(export)
        if entries is None:
            return ExplainResult(
                "export_unreadable",
                f"THE EXPORT COULD NOT BE READ as a ledger: a /v1/logs/export "
                f"document is a JSON object with a `logs` list, and this file "
                f"is a {type(export).__name__} whose `logs` is "
                f"{_logs_kind(export)}. Nothing here can be checked against "
                f"event_id {event_id} — re-export rather than editing this "
                f"file.",
                event_id=event_id)
        if entries and not any(isinstance(entry, dict) for entry in entries):
            return ExplainResult(
                "export_unreadable",
                f"THE EXPORT COULD NOT BE READ as a ledger: its `logs` holds "
                f"{len(entries)} entr{'y' if len(entries) == 1 else 'ies'} and "
                f"none of them is a row. This is valid JSON but not a "
                f"/v1/logs/export document, so nothing here can be checked "
                f"against event_id {event_id} — re-export rather than editing "
                f"this file.",
                event_id=event_id)
        return ExplainResult(
            "row_not_found",
            f"No row with event_id {event_id} in this export. Check the id, or "
            f"export a range that covers it.",
            event_id=event_id)

    # Same reasoning, one line instead of two interpolations: the tag is read
    # once and every message downstream is safe by construction.
    policy_tag = _printable(row.get("policy_tag") or "default")
    # ⚠ A DICT OR NOTHING. `or {}` alone let a truthy non-dict through — an
    # export with `"event_metadata": [1, 2]` reached `.get` and raised
    # AttributeError out of the public path, which is the same class of defect
    # as `_rule_ids` and two lines earlier than any of the arms that read it.
    metadata = row.get("event_metadata")
    metadata = metadata if isinstance(metadata, dict) else {}
    # ⚠ SAME MOVE AS `event_id` ABOVE, FOR THE VALUE THAT RIDES IN NINE
    # SENTENCES. `version_key` keeps the row's own bytes, because the registry
    # has to be asked for what the row actually says; `version` from here down
    # is the PRINTABLE rendering, and every message below interpolates that.
    # Normalising here rather than at each `{version!r}` is the whole of the
    # trick — `!r` does NOT escape non-ASCII in Python 3, so five sentences
    # looked guarded and were not, and the next sentence somebody adds cannot
    # forget a step that has already happened. A falsy value stays falsy, so
    # the no-version branch below still reads it unchanged.
    version = metadata.get("ruleset_version")
    version_key = str(version) if version else ""
    version = _printable(version) if version else ""

    # ── the commitment ───────────────────────────────────────────────────────
    # ⚠ READ AND NORMALISED ONCE, and the suffix test is unaffected by it:
    # `_printable` only ever rewrites a non-ASCII character into an ASCII
    # backslash-u escape, which can neither create nor destroy a `-salted`
    # ending.
    commitment_alg = _printable(row.get("commitment_alg") or "")
    salted = commitment_alg.endswith("-salted")
    salt = None
    if salted:
        salt = _load_salt(salt_sidecar_path, event_id) if salt_sidecar_path else None
        if not salt:
            # ⚠ THE PATH IS NORMALISED AFTER ITS READ, NEVER BEFORE IT.
            # `_load_salt` opened it one line up against the caller's real
            # value; what follows only prints it. A Windows home directory with
            # a non-ASCII name is an ordinary thing to own, and it turned the
            # ONE message whose job is to stop a reader taking "could not
            # check" for "did not match" into a UnicodeEncodeError.
            #
            # 🔴 AND THE SAME IS NOT TRUE OF `event_id` ON THIS CALL — DO NOT
            # READ THE PARAGRAPH ABOVE AS A CLAIM THAT THE ORDERING IS SAFE.
            # `event_id` was rebound to its PRINTABLE form far above, so
            # `_load_salt` is asked for the salt of `ev-` + an escape sequence,
            # and the sidecar is keyed by the id the SDK actually wrote.
            # MEASURED on this branch:
            #
            #   sidecar.read_salt(path, real_id)      -> the salt
            #   sidecar.read_salt(path, printable_id) -> None
            #   explain(...)                          -> salt_unavailable
            #
            # So a salted row whose event_id is non-ASCII is told its salt is
            # missing while the salt sits in the file. It is a WRONG ANSWER,
            # not a traceback, and the safe direction of wrong — "could not
            # check", never "did not match". Filed rather than fixed here: the
            # fix changes what the lookup is given, which is a behaviour change
            # this phase was scoped out of. The comment above `event_id`'s own
            # normalisation says the rebinding "cannot break the lookup"; that
            # is true of the ROW lookup on the line above it and false of this
            # one, fifty lines down.
            # ⚠ ONE DECISION, TAKEN ON THE RAW VALUE, AND THE PRINTABLE FORM
            # CANNOT EXIST WITHOUT IT. This shipped for one round as
            # `if sidecar_shown`, where `sidecar_shown` was already through
            # `_printable` — and `_printable(None)` is the string "None",
            # TRUTHY. A caller passing `salt_sidecar_path=None`, which is the
            # natural way to say "no sidecar" through the public `explain()`,
            # was told the salt "was not found in None".
            #
            # ⚠ AND THE FIRST FIX FOR IT WAS TWO FIXES, WHICH IS WHY IT LOOKS
            # LIKE THIS NOW. That round both tested the raw value AND wrote
            # `_printable(path or "")`, so either change alone was enough and
            # neither was load-bearing: reverting the guard changed nothing a
            # test could see. A mutation SURVIVED and said so. Computing the
            # rendering inside the branch that uses it leaves exactly one
            # place the question is asked.
            #
            # `foxy explain` could not have found any of this: the CLI guards
            # with `is not None` and `cfg.salt_sidecar_path` defaults to "",
            # so the None never reaches here from the tool. The defect lived
            # on the API, and only reading the branch reaches the API.
            where = (f" in {_printable(salt_sidecar_path)}"
                     if salt_sidecar_path else " (no --sidecar given)")
            return ExplainResult(
                "salt_unavailable",
                f"Row {event_id} was committed with a per-event salt "
                f"({commitment_alg}), and no salt for it was found" + where
                + ". Its commitment CANNOT be recomputed without that salt, so "
                  "this is not a mismatch and not a pass — the check could not "
                  "run. The salt lives only on your machine; Foxy never had it. "
                  "Point --sidecar at the file the SDK wrote (config "
                  "salt_sidecar_path / FOXY_SALT_SIDECAR).",
                event_id=event_id, policy_tag=policy_tag,
                ruleset_version=version)

    recomputed = hashing.commitment_hex(prompt, commitment_key, salt)
    if recomputed != row.get("prompt_hash"):
        return ExplainResult(
            "hash_mismatch",
            f"The text you supplied does not match what row {event_id} "
            f"committed. The row is intact; this is simply not the prompt it "
            f"covers. (If you expected a match, check the commitment key.)",
            event_id=event_id, policy_tag=policy_tag,
            ruleset_version=version)

    # ── the ruleset ──────────────────────────────────────────────────────────
    #
    # ⚠ #239. THREE ROWS ARRIVE HERE AND THEY ARE NOT THE SAME ROW. Until
    # 1.13.0 all three were told "it was written before SDK 1.7.0" — a false
    # statement of fact about a row written today, produced by the tool built to
    # establish facts, and the most common of the three is the ordinary clean
    # row every guarded workload produces all day.
    #
    # What tells them apart is already settled doctrine in this SDK, in
    # `client.py`'s own words at the `on_event` hook: metadata the clean observe
    # path does not build at all reads None, and "None (no guard ran) is not []
    # (the guard ran and nothing fired)". So:
    #
    #   rule ids recorded, no version  -> the rules were recorded and the
    #                                     definition behind them was not, AND
    #                                     THE ROW DOES NOT SAY WHY. Three live
    #                                     causes; see below.
    #   a decision, no rule ids        -> nothing fired. Provenance rides only
    #                                     with the ids it explains, so its
    #                                     absence is the design.
    #   no decision at all             -> a clean observe row or a pre-1.7.0
    #                                     row, and NOTHING IN THE ROW SAYS
    #                                     WHICH. Say that; do not guess.
    #
    # ⚠ THE FIRST ARM WAS `ruleset_unrecorded` AND THAT NAME WAS ALSO A DATE
    # THIS TOOL CANNOT READ — the same defect as the message, one layer up, and
    # a name is what every surface prints and every consumer switches on. Three
    # CURRENT paths write rule ids with no version:
    #
    #   1. `dispatch._strip_provenance` pops `ruleset.PROVENANCE_KEYS` and
    #      `dispatch.TYPED_TAG_KEYS`, and leaves `policy_rules` standing — the
    #      rule ids survive with nothing naming the ruleset that explains them.
    #      A current SDK talking to a backend
    #      that 422s the provenance keys — a lagging deploy, a self-hosted
    #      install, the frozen production backend — stores exactly this shape.
    #   2. `ruleset.provenance()` returns `{}` on a degraded registry, on
    #      purpose: "provenance is an ENRICHMENT of the record. It must never be
    #      able to cost the record."
    #   3. an SDK older than 1.7.0.
    #
    # None of the three leaves a marker IN THE ROW — the degrade is recorded on
    # the receipt and in a process-local map, neither of which survives into an
    # export. So the honest answer names what is missing, not when it was
    # written. ⚠ And (1) gets MORE common, not less: S13 sends `policy_tag_raw`
    # to a production backend that will never allowlist it.
    #
    # ⚠ THE BEHAVIOUR DOES NOT CHANGE AND MUST NOT. The fix is that the sentence
    # stops asserting an age the row does not record. Stamping a ruleset on a
    # clean row to make this go away would claim rules explained something when
    # none fired — S4 decided that, and it is still right.
    if not version:
        recorded_rules = _rule_ids(metadata)
        decision = metadata.get("decision")
        if recorded_rules:
            return ExplainResult(
                "ruleset_unrecorded",
                f"Row {event_id} records the rule ids "
                f"{', '.join(recorded_rules)} but no ruleset_version, so the "
                f"ids were written down and the definition that gave them "
                f"meaning was not. The commitment MATCHES, so this is the right "
                f"prompt — but replaying today's rules would tell you what they "
                f"mean NOW, not what they meant then, and this tool will not "
                f"guess. "
                f"THE ROW DOES NOT RECORD WHY the version is missing, and there "
                f"are three live causes: the backend rejected the provenance "
                f"keys and the SDK resent without them, this SDK's ruleset "
                f"registry could not answer when the row was written, or the row "
                f"predates SDK 1.7.0. Your delivery logs and SDK version can "
                f"tell those apart; the row alone cannot.",
                event_id=event_id, policy_tag=policy_tag,
                commitment_verified=True)
        if decision is not None:
            return ExplainResult(
                "no_rules_fired",
                f"Row {event_id} records decision='{_printable(decision)}' and no rule "
                f"ids: the guard ran on this prompt and nothing matched. A row "
                f"that fired nothing carries no ruleset_version by design — "
                f"provenance rides only with the rule ids it explains — so its "
                f"absence here is expected and says nothing about which SDK "
                f"wrote the row. There is nothing to replay, and the commitment "
                f"MATCHES, so this is the right prompt. To ask what TODAY's "
                f"rules make of this text, use `foxy check`.",
                event_id=event_id, policy_tag=policy_tag,
                commitment_verified=True)
        return ExplainResult(
            "provenance_ambiguous",
            f"Row {event_id} records no decision, so nothing in it says whether "
            f"a guard ran at all — and two very different rows look exactly like "
            f"this. Under `observe` no preflight runs and the clean path builds "
            f"no event_metadata by design, which is what keeps an observe "
            f"payload byte-identical, and there would be nothing to replay; a "
            f"row written before SDK 1.7.0 also names no ruleset, and there "
            f"rules may have run and gone unrecorded. The commitment MATCHES, so "
            f"this is the right prompt — but this tool cannot tell those two "
            f"apart, and will not guess which one you are holding.",
            event_id=event_id, policy_tag=policy_tag, commitment_verified=True)

    try:
        definition = ruleset.load(version_key)
    except KeyError:
        return ExplainResult(
            "unknown_ruleset",
            f"Row {event_id} names ruleset '{version}', which this SDK does not "
            f"carry (it has: "
            f"{', '.join(_printable(known) for known in ruleset.known_versions())}"
            f"). The row was "
            f"minted by a NEWER release. Upgrade foxy-audit to replay it — "
            f"replaying the rules this build happens to have would describe a "
            f"different policy than the one that actually ran.",
            event_id=event_id, policy_tag=policy_tag,
            ruleset_version=version, commitment_verified=True)

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
    # The RECORDED digest is a row value and is normalised like every other
    # one; escaping cannot change the comparison below, because a non-ASCII
    # value was never going to equal a hexdigest either way. `loaded_hash`
    # needs no such pass and deliberately does not get one: `ruleset.hash_of`
    # is a SHA-256 hexdigest computed here, ASCII by construction, and wrapping
    # it would assert a risk that does not exist.
    recorded_hash = _printable(str(metadata.get("ruleset_hash") or ""))
    loaded_hash = ruleset.hash_of(definition)
    if recorded_hash and recorded_hash != loaded_hash:
        return ExplainResult(
            "ruleset_mismatch",
            f"Row {event_id} names ruleset '{version}' and records the digest "
            f"{recorded_hash[:12]}…, but this build's copy of '{version}' hashes "
            f"to {loaded_hash[:12]}…. Same name, DIFFERENT RULES. A published "
            f"ruleset is immutable — rows in customers' chains name it — so one "
            f"of the two has been altered: either this install's registry (a "
            f"hand-edit, a partial upgrade, a backported patch) or the row's "
            f"recorded digest. Replaying would describe rules that did not run, "
            f"so this tool will not. The commitment MATCHED, so the prompt and "
            f"the row do belong together; it is the rules that cannot be "
            f"trusted.",
            event_id=event_id, policy_tag=policy_tag,
            ruleset_version=version, commitment_verified=True,
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
        f"that its copy of '{version}' is the definition that actually ran. "
        f"Every SDK from 1.7.0 records one; a row without it was not written by "
        f"a released foxy-audit, or was edited after export.")

    try:
        matches = replay(definition, str(prompt), policy_tag)
    except normalise.UnknownTransform as unknown:
        # ⚠ THE SAME ANSWER AS AN UNKNOWN VALIDATOR, FOR THE SAME REASON, and
        # it is a SEPARATE branch because the two failures have different
        # remedies to state. A definition can name a text transform this build
        # does not implement — a row written by a newer SDK whose views this one
        # has never heard of. Replaying it against the raw text alone would
        # report a CLEAN prompt where the ledger recorded a finding, which is
        # the row looking like a lie about itself. Skipping a transform is not
        # a smaller version of replaying it; it is a different replay.
        return ExplainResult(
            "unknown_ruleset",
            f"Row {event_id} names ruleset '{version}', whose definition "
            f"matches the injection rules against a view built by "
            f"'{_printable(unknown)}' — this SDK does not implement it (it has: "
            f"{', '.join(sorted(normalise.TRANSFORMS))}). Upgrade foxy-audit to "
            f"replay this row. Replaying it against the raw prompt alone would "
            f"report no match where the SDK which wrote the row found one.",
            event_id=event_id, policy_tag=policy_tag,
            ruleset_version=version, commitment_verified=True,
            ruleset_verified=ruleset_verified)
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
            f"Row {event_id} names ruleset '{version}', whose definition uses "
            f"the validator '{_printable(unknown)}' — this SDK does not implement it "
            f"(it has: {', '.join(sorted(_VALIDATORS))}). Upgrade foxy-audit to "
            f"replay this row. Replaying it without that validator would report "
            f"matches the SDK which wrote the row had discarded.",
            event_id=event_id, policy_tag=policy_tag,
            ruleset_version=version, commitment_verified=True,
            # ⚠ THIS PATH IS PAST THE DIGEST CHECK, so it carries the verdict
            # rather than dropping back to the default. The distinction is the
            # whole diagnosis here: a VERIFIED definition naming a validator
            # this build lacks means "upgrade the SDK", while the same message
            # with the digest unchecked leaves open that the definition itself
            # is not what it claims. Defaulting would have thrown away an
            # answer already computed three lines up.
            ruleset_verified=ruleset_verified)
    # ⚠ `_rule_ids`, NOT THE IDIOM IT WAS WRITTEN TO REPLACE. This line was
    # the last `list(metadata.get("policy_rules") or [])` in the module, and it
    # feeds a `', '.join(...)` four lines down: `policy_rules: [1, 2]` raised
    # TypeError, and a dict there silently yielded its KEYS as rule ids nobody
    # recorded. Same file, same defect, two arms apart.
    recorded = _rule_ids(metadata)
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
            ruleset_version=version, commitment_verified=True,
            ruleset_verified=ruleset_verified)

    return ExplainResult(
        "explained",
        f"Commitment verified against row {event_id}, and ruleset {version} "
        f"— whose definition matches the digest the row recorded — matches "
        f"{len(matches)} span(s) under policy '{policy_tag}'."
        if ruleset_verified else
        f"Commitment verified against row {event_id}, and ruleset {version} "
        f"matches {len(matches)} span(s) under policy '{policy_tag}'."
        + unverified_note,
        event_id=event_id, policy_tag=policy_tag,
        ruleset_version=version, commitment_verified=True,
        ruleset_verified=ruleset_verified, matches=matches)


#: ``UnknownValidator`` is exported because ``replay`` is, and ``replay`` RAISES
#: it — its own docstring tells a caller to catch it. An exception a public
#: function can raise but that the module does not name is one a caller can only
#: reach by importing a private symbol.
__all__ = ["CheckResult", "ExplainResult", "Match", "STATUSES",
           "UnknownValidator", "check", "explain", "replay"]
