"""THE OBLIGATION SET for the phone and card detectors. Both directions, one file.

⚠ READ THIS BEFORE CHANGING EITHER DETECTOR, AND MEASURE AGAINST IT BEFORE
CHOOSING A RULE — not after.

The card boundary lost real card numbers in THREE CONSECUTIVE ROUNDS:

* hyphen-glued PANs (``card-4111111111111111``) when the boundary excluded an
  adjacent hyphen;
* the same class differently when the boundary was re-derived;
* ``ref 0 4111111111111111`` when "no PAN starts with 0" was applied to the whole
  separator-chained candidate instead of to the PAN's own first digit.

No single one of those was the defect. THE RECURRENCE WAS. Each round assembled
its corpus after picking a rule, so each corpus could only confirm the rule that
had already been chosen — and each round's false-positive measurement looked
excellent while a real detection quietly disappeared.

So this file carries BOTH DIRECTIONS as ONE set:

* ``PAN_SHAPES`` / ``PHONE_SHAPES`` — things that MUST be detected. Losing one is
  a leaked card number or phone number, which is the worst outcome available.
* ``ZERO_HEAVY*`` / ``RANDOM_UUIDS`` / ``SHA256_DIGESTS`` / ``HYPHENATED_IDS`` —
  things that must NOT be, each with its own bound and its own reasoning.
* ``UNIFORM_NONZERO_RUNS`` — a deliberate ASYMMETRY: the phone must accept these
  and the card must reject them. See its own note.

Rules for changing this file, learned the expensive way:

1. Never adjust a population and the assertion that reads it in the same change.
   If a population is genuinely wrong, replace it in its own commit with its own
   reasoning, so the two decisions can be judged apart.
2. Never dismiss a population for looking skewed. The zero-heavy UUIDs looked
   degenerate and were the only ones testing the real world.
3. A bound one step above the measured value is not a bound. State the measured
   number in the test and leave real headroom, or assert equality.
"""

from __future__ import annotations

import hashlib
import itertools
import random
import uuid

_MIX = 0x9E3779B97F4A7C15


# ── DIRECTION 1: things that MUST be detected ────────────────────────────────
#: Test PANs from the six mainstream issuers, all Luhn-valid.
REAL_PANS = [
    "4111111111111111", "4532015112830366", "5425233430109903",
    "374245455400126", "6011111111111117", "3530111333300000",
]

#: How a card number appears in text. The last group is the one that keeps
#: breaking: a stray number in FRONT of the PAN, which separator-chaining can
#: sweep into the same candidate and take the whole finding down with it.
_PAN_CONTEXTS = [
    "{}", "card {}", "Card: {}.", "PAN={}", "({})", "[{}]", '"{}"', "{},",
    "{}\n", "pay with {} today", "{}!", "#{}", "{};", "'{}'", "\t{}\t",
    "card-{}", "{}-visa", "pan-{}-exp", "-{}", "{}-", "{}_", "_{}",
    # ⚠ LEADING SEPARATED DIGITS — the S8c loss, and the reason this list exists.
    "ref 0 {}", "ref 0-{}", "ref 00 {}", "item 1 {}", "line 12 {}",
    "qty 0 - {}", "0 {}", "acct 000 {}",
]


def _grouped(pan: str, sep: str) -> str:
    return sep.join(pan[i:i + 4] for i in range(0, len(pan), 4)) if sep else pan


#: Every PAN, in every grouping, in every context. 540 shapes.
PAN_SHAPES = sorted({context.format(_grouped(pan, sep))
                     for pan, sep, context
                     in itertools.product(REAL_PANS, ["", " ", "-"], _PAN_CONTEXTS)})

#: ⚠ GENUINELY DIALABLE, and the ONLY numbers a "these are real" argument may
#: cite. ``+7 777`` is a live Kazakh mobile prefix and ``888`` is a real NANP
#: toll-free area code, so every one of these is an assignable number that
#: happens to repeat a digit. A uniform-digit rule refused ALL 60 shapes built
#: from them — see :data:`DIALABLE_PHONES` usage in test_policy_truth_1_9_0.py.
DIALABLE_PHONES = [
    "888-888-8888", "(888) 888-8888",
    "+7 777 777 7777", "7777777777", "+7 (777) 777-7777",
]

#: RESERVED OR FICTIONAL, and labelled so on purpose. ``555-01xx`` is the NANP
#: range set aside for fiction; ``555-5555``, ``111-1111`` and ``222-2222`` are
#: placeholder patterns, not assignable numbers.
#:
#: ⚠ THEY ARE STILL OBLIGATIONS. A 555 number written in a clinical note is
#: phone-shaped personal data, 1.8.0 detected it, and losing it would be a
#: regression — the detector has no way to know a number is fictional and should
#: not try. What they may NOT do is be counted as evidence that "real numbers"
#: were lost. An earlier draft of this file called all fourteen "real, dialable",
#: which inflated the justification figure for loosening the phone gate from
#: 60/60 to 96/168. The decision was right; the number was not.
FICTIONAL_PHONES = [
    "415-555-0134", "(415) 555-0134", "+1 415 555 0134", "4155550134",
    "415.555.0134", "1-800-555-0134",
    "555-555-5555", "111-111-1111", "(222) 222-2222",
]

#: Everything the phone detector must find, whatever its provenance.
REAL_PHONES = DIALABLE_PHONES + FICTIONAL_PHONES

_PHONE_CONTEXTS = ["{}", "call {} now", "Phone: {}.", "[{}]", '"{}"', "tel:{}",
                   "{},", "{}\n", "({})", "Fax: {}", "{}!", "{};"]

#: Every phone, in every context. 168 shapes.
PHONE_SHAPES = sorted({context.format(phone) for phone, context
                       in itertools.product(REAL_PHONES, _PHONE_CONTEXTS)})

#: The 60 shapes built from genuinely dialable numbers. Split out so a claim
#: about "real numbers lost" can be measured against real numbers only.
DIALABLE_PHONE_SHAPES = sorted({context.format(phone) for phone, context
                                in itertools.product(DIALABLE_PHONES,
                                                     _PHONE_CONTEXTS)})


# ── DIRECTION 2: things that must NOT be detected ────────────────────────────
def _seeded(count: int, bits) -> list:
    """Fixed seed, so a bound means the same thing on every run."""
    rng = random.Random(5)
    return [tuple(rng.getrandbits(b) for b in bits) for _ in range(count)]


#: Uniformly-random v4-shaped UUIDs. THE EASY CASE — a random 32-hex string
#: rarely holds a long enough all-digit run to chain across the hyphens.
RANDOM_UUIDS = ["%08x-%04x-%04x-%04x-%012x" % parts
                for parts in _seeded(20000, (32, 16, 16, 16, 48))]

#: ⚠ THE REAL WORLD, and the population a random-UUID corpus cannot see. Nil
#: UUIDs, low-integer UUIDs (a fixture, a migration, a "not found" path),
#: zero-padded counters and hyphen-grouped sequences. Every digit run here is a
#: placeholder, so the bound is EXACTLY ZERO for both detectors.
ZERO_HEAVY_STRICT = (
    [str(uuid.UUID(int=0))] * 50
    + [str(uuid.UUID(int=i)) for i in range(2000)]
    + ["%016d" % i for i in range(2000)]
    + ["0000-0000-0000-%04d" % i for i in range(2000)]
    + ["0" * length for length in range(13, 20)]
)

#: The strict set plus UUIDs with a zero PREFIX and a RANDOM TAIL. Those tails
#: are genuine 16-digit, 8-distinct-digit Luhn-passing runs, which no
#: content-free rule separates from a card number — so this one gets a small
#: bound and a reason, never a pretence of zero.
ZERO_HEAVY = (ZERO_HEAVY_STRICT
              + [str(uuid.UUID(int=i * _MIX % (1 << 128))) for i in range(1, 4001)])

#: ⚠ A DELIBERATE ASYMMETRY, and the two detectors disagree about it ON PURPOSE.
#: ``2222222222222222`` passes Luhn and is not a card number, so the card must
#: reject every entry here. ``888-888-8888`` is a dialable phone number, so the
#: phone must ACCEPT them. Kept as its own list precisely so neither rule can be
#: "tidied up" into the other.
UNIFORM_NONZERO_RUNS = [digit * length
                        for digit in "123456789" for length in range(13, 20)]

#: Real SHA-256 digests — the population #215 was reported against.
SHA256_DIGESTS = [hashlib.sha256(str(i).encode()).hexdigest()
                  for i in range(20000)]

#: Hyphen-delimited 13-15 digit ids. NOT a regression class: 1.8.0 flagged these
#: at the same rate, because a Luhn-passing hyphen-separated run is what a card
#: number looks like. Kept so that stays measured rather than assumed.
HYPHENATED_IDS = ["build-%d-rc1" % ((n * _MIX) % 10 ** 15 + 10 ** 12)
                  for n in range(1, 20001)]

#: Named cases from the reviews, asserted individually as well as by rate. A rate
#: can drift; a named case cannot come back quietly.
NAMED_PLACEHOLDERS = [
    "patient record 00000000-0000-0000-0000-000000000000 not found",
    "id 12345678-0000-0000-0000-000000000000",
    "0000-0000-0000-0000",
    "0000000000000000",
    "account 000000000000000 pending",
    "seq 0000-0000-0000-0001",
    "trace 00000000-0000-4000-8000-000000000000",
    "order 00000000000000000000 shipped",
    "0000000000000",
    "0000000000",
    "call 000-000-0000 now",
]

#: Named cases from the reviews that MUST be detected, paired with the label they
#: must carry. The other half of NAMED_PLACEHOLDERS, and the half that was
#: missing each time a real detection was lost.
NAMED_OBLIGATIONS = [
    ("ref 0 4111111111111111", "credit_card"),
    ("ref 0-4111111111111111", "credit_card"),
    ("ref 00 4111111111111111", "credit_card"),
    ("card-4111111111111111", "credit_card"),
    ("4111-1111-1111-1111-visa", "credit_card"),
    ("Card 4532015112830366 on file.", "credit_card"),
    ("888-888-8888", "phone"),
    ("(888) 888-8888", "phone"),
    ("+7 777 777 7777", "phone"),
    ("call 415-555-0134 now", "phone"),
]
