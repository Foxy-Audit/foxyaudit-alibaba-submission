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

⚠ ``81`` IS DELIBERATELY ABSENT. It is listed as UnionPay by several secondary
sources, but MII 8 is healthcare and telecommunications, and UnionPay's own
assignment is 62. Measured on the checked-in corpora, including it changed no
PAN detection (nothing in ``REAL_PANS`` begins 81) and cost 20 extra build-id
false positives plus the ONE zero-heavy false positive that keeps that column at
zero: ``00000000-0000-0819-8108-420735282737``. Excluded on the evidence, and
recorded here rather than silently, because a genuinely-assigned range excluded
from this table becomes a MISSED CARD — see the limit stated in
:func:`starts_with_assigned_iin`.

⚠ THIS TABLE IS AN INPUT TO A FROZEN RULESET. It is not itself hashed — the
ruleset records the VALIDATOR NAME ``luhn+iin+distinct``, and this table is the
code behind that name. Widening or narrowing it changes what fires without
changing any digest, which is precisely the gap ``introspect``'s
``ruleset_verified`` field documents. A change here is a change to what the
validator MEANS, so it takes a NEW validator name and a NEW ruleset version.
"""

from __future__ import annotations


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


__all__ = ["ASSIGNED_IINS", "starts_with_assigned_iin"]
