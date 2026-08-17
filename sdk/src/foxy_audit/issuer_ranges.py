"""Assigned issuer identification numbers (IINs), as a fact about the card system.

A payment card number is not an arbitrary Luhn-passing digit run. Its leading
digits are an ISSUER IDENTIFICATION NUMBER assigned under ISO/IEC 7812, and the
assignments are public and stable. A 16-digit run that passes Luhn but begins
``8108`` is not a card number that this SDK failed to recognise — it is not a
card number.

WHY THIS IS ITS OWN MODULE
--------------------------
Buried inside ``pii.py`` as a regex alternation, this reads as a heuristic
somebody tuned. It is not: it is a table anyone can check against the issuers'
own published ranges, and it should be legible as one. Keeping it here also
means the guard in ``tests/`` can read the SAME table it is testing rather than
restating it — a restated table is a second copy that drifts.

It lives in the PACKAGE rather than beside the corpora in ``tests/fixtures/``
because ``pii`` imports it at runtime and ``tests/`` does not ship as an
importable package in the wheel.

THE MAJOR INDUSTRY IDENTIFIER
-----------------------------
The first digit is the MII. Only some are financial, which is why the table has
holes rather than being a range:

    0  ISO/TC 68              5  banking and financial (Mastercard)
    1  airlines               6  merchandising and banking (Discover, UnionPay)
    2  airlines and financial 7  petroleum
    3  travel and entertainment (Amex, Diners, JCB)
    4  banking and financial (Visa)
    8  healthcare, telecommunications
    9  national assignment

⚠ ``81`` IS RuPay, AND IT IS DELIBERATELY ABSENT. Getting this label right
matters more than the decision does. An earlier draft of this paragraph called
81 a UnionPay mislabel and reasoned from the MII: WRONG. 81 is a real, assigned
range belonging to **RuPay**, India's domestic card network — so excluding it is
not the removal of a bogus listing, it is a **deliberate false negative on real
cards**, and the next reader has to see it as that.

RuPay's ranges are 60, 6521, 6522, 81, 82 and 508. Two of them, 6521 and 6522,
are ALREADY ACCEPTED here — they fall under Discover's ``65``. The other four
are not, so a RuPay PAN outside 65xxxx is missed.

The trade stands on the measurement: adding 81 detects no PAN in the obligation
corpus and costs 20 build-id false positives plus the ONE zero-heavy false
positive that keeps that column at zero,
``00000000-0000-0819-8108-420735282737``. So it buys nothing measurable and
costs something measurable — but there is NO RuPay CARD ANYWHERE IN THE CORPUS,
so "buys nothing" is a statement about the fixtures and not about the world.
That is exactly the blind spot :func:`starts_with_assigned_iin` warns about. If RuPay
coverage matters to you, add 60, 81, 82 and 508, mint a ruleset, and expect the
build-id column to rise. That is a product decision, not a fact about the
payment system, and it is recorded here so it stays a decision.

⚠ THIS TABLE IS AN INPUT TO THE FROZEN RULESET, AND IT IS NOW HASHED INTO IT.
It did not used to be. The ruleset recorded the validator NAME
``luhn+iin+distinct`` and nothing more, so adding one prefix here flipped
``replay(load("2026.08.4"), …)`` from no match to ``phi.credit_card`` while the
ruleset digest stayed ``13569591…`` and ``drift()`` stayed None — a sealed
ruleset whose meaning moved with its fingerprint unmoved. That is SDK #220 one
layer down: 1.10.0 exists to make the digest identify the rules, and a rule that
consults unhashed data is not identified by it.

:data:`TABLE_DIGEST` closes it. ``describe_live`` records the digest inside the
``credit_card`` entry, so it reaches ``hash_of`` like any pattern: an edit here
moves the ruleset hash, ``drift()`` goes non-None, and a row minted under a
different table is caught by ``explain``'s existing ``ruleset_mismatch`` rather
than replayed under rules that were never its own. A change to this table is
still a change to what the validator MEANS, and still takes a new validator name
and a new ruleset version — but now nothing has to remember that for it to hold.
"""

from __future__ import annotations

import hashlib
import json


def _span(low: int, high: int) -> tuple[str, ...]:
    """Every prefix from ``low`` to ``high`` inclusive, as strings of equal width."""
    return tuple(str(n) for n in range(low, high + 1))


#: Issuer -> the prefixes it has been assigned. Grouped by network so the table
#: can be checked against each issuer's own published ranges one row at a time.
ASSIGNED_IINS: dict[str, tuple[str, ...]] = {
    # Visa is the whole of MII 4.
    "visa": ("4",),
    # Mastercard's original 51-55, plus the 2-series opened in 2017.
    "mastercard": _span(51, 55) + _span(2221, 2720),
    "amex": ("34", "37"),
    "discover": ("6011", "65") + _span(644, 649),
    # Diners Club International; 3095 sits outside the 300-305 block.
    "diners": _span(300, 305) + ("3095", "36", "38", "39"),
    "jcb": _span(3528, 3589),
    # UnionPay: 62. See the module docstring on why 81 is not here.
    "unionpay": ("62",),
    "maestro": ("5018", "5020", "5038", "5893",
                "6304", "6759", "6761", "6762", "6763"),
}

#: Flattened and deduplicated, in a stable order.
#:
#: ⚠ THE ORDER IS FOR READERS AND DIFFS, NOT FOR MATCHING, and the first draft of
#: this comment said otherwise — "longest first, so a lookup tests the most
#: specific prefix it can". That is not what happens. ``str.startswith`` with a
#: tuple asks whether ANY member matches; there is no most-specific-wins rule to
#: exploit and no ambiguity to resolve, because every question here is a yes/no
#: about membership rather than a lookup of which network. Reversing this sort
#: changes nothing, which is exactly why the sentence had to go: a comment that
#: claims a mechanism the code does not have is a lie a reader will act on.
_PREFIXES: tuple[str, ...] = tuple(sorted(
    {prefix for prefixes in ASSIGNED_IINS.values() for prefix in prefixes},
    key=lambda p: (-len(p), p)))


#: SHA-256 over the canonical JSON of the SORTED FLAT PREFIX SET — the thing
#: that actually decides an answer.
#:
#: Deliberately NOT over ``ASSIGNED_IINS``. The grouping by network is for
#: readers: moving ``37`` from ``amex`` to ``visa`` would be wrong and confusing
#: and would change no verdict, so hashing the grouped mapping would mint a
#: ruleset version for an edit that alters nothing. Same asymmetry ``ruleset.py``
#: already applies to rule ordering, and for the same reason — a version that
#: moves on inert edits teaches people to ignore it moving.
#:
#: Same recipe as :func:`ruleset.hash_of` so an independent verifier
#: reimplementing one gets the other for free.
TABLE_DIGEST: str = hashlib.sha256(
    json.dumps(sorted(_PREFIXES), sort_keys=True, separators=(",", ":"),
               ensure_ascii=True).encode("utf-8")).hexdigest()


def starts_with_assigned_iin(digits: str) -> bool:
    """Do these digits begin with a prefix any card network actually issues?

    ⚠ WHAT A FALSE HERE MEANS, AND WHAT IT DOES NOT. It means no network in
    :data:`ASSIGNED_IINS` issues from that prefix. It does NOT mean the number is
    definitely not a card: a regional or private-label issuer outside this table
    would be rejected here and its card would go undetected. That is a real
    limit, it is stated in the README and the changelog beside the number it
    improves, and it is why this table is grouped and sourced rather than
    minimised — a prefix dropped for tidiness is a card that leaks.
    """
    return digits.startswith(_PREFIXES)


__all__ = ["ASSIGNED_IINS", "TABLE_DIGEST", "starts_with_assigned_iin"]
