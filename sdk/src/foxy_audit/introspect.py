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

THE THREE ANSWERS THAT ARE "I CANNOT"
=====================================
Each is a real answer, reported plainly, never a traceback and never a silent
fallback:

* ``salt_unavailable`` — a salted row whose sidecar entry is missing. The
  commitment cannot be recomputed at all. Reporting "no match" would be a false
  negative on the exact question the tool exists to answer, and the reader would
  conclude the ledger was wrong. Same convention as the verifier's
  ``unprovable``: could-not-run is its own answer.
* ``unknown_ruleset`` — a row minted by a newer SDK than this one. Saying so
  beats replaying the wrong rules.
* ``predates_provenance`` — a row written before 1.7.0, which names no ruleset.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field

from . import hashing, policy as policy_engine, ruleset

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


#: Every status :func:`explain` can return. Three of them are "I cannot".
STATUSES = ("explained", "no_matches", "hash_mismatch", "row_not_found",
            "salt_unavailable", "unknown_ruleset", "predates_provenance")


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
#: A dict rather than a chain of ``if``s because an UNKNOWN name must be a loud
#: KeyError, not a silent pass: a build asked to replay a validator it does not
#: carry cannot honestly report anything, and :func:`explain` already has a
#: ``unknown_ruleset`` answer for exactly that situation.
_VALIDATORS = {
    "luhn": lambda digits: _luhn_ok(digits),
    "luhn+distinct": lambda digits: _luhn_ok(digits) and len(set(digits)) > 1,
    "not-all-zero": lambda digits: set(digits) != {"0"},
}


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
                # The definition NAMES the card detector's validator, so honour
                # the one THIS ROW's ruleset recorded — otherwise the replay
                # reports a match the SDK itself would have discarded, or
                # discards one it kept.
                #
                # ⚠ EACH NAME KEEPS ITS OWN MEANING FOREVER. Rows stamped
                # 2026.08.1 / .2 record "luhn" and replay under the plain
                # checksum, which is what ran on the day they were written —
                # including its acceptance of `0000000000000000`. From 2026.08.3
                # the gate also rejects a leading zero and a single repeated
                # digit (pii._is_card_number), so it is a DIFFERENT name rather
                # than a redefinition of the old one. An unknown name applies no
                # validator, which over-reports rather than silently under-
                # reporting: a replay from a newer SDK should look too eager, not
                # falsely clean.
                validator = entry.get("validator")
                if validator:
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

    matches = replay(definition, str(prompt), policy_tag)
    recorded = list((metadata.get("policy_rules") or []))
    if not matches:
        return ExplainResult(
            "no_matches",
            f"The commitment matches and ruleset {version} replayed cleanly, but "
            f"no rule in it matches this text"
            + (f", while the row recorded {', '.join(recorded)}. That is worth "
               f"investigating: the row's rules and its own ruleset disagree."
               if recorded else ". The row recorded no rules either, so the two "
                                "agree."),
            event_id=event_id, policy_tag=policy_tag,
            ruleset_version=str(version), commitment_verified=True)

    return ExplainResult(
        "explained",
        f"Commitment verified against row {event_id}, and ruleset {version} "
        f"matches {len(matches)} span(s) under policy {policy_tag!r}.",
        event_id=event_id, policy_tag=policy_tag,
        ruleset_version=str(version), commitment_verified=True,
        matches=matches)


__all__ = ["CheckResult", "ExplainResult", "Match", "STATUSES", "check",
           "explain", "replay"]
