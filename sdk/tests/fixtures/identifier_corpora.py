"""Identifier populations the PII detectors must NOT fire on, checked in.

⚠ WHY THIS FILE EXISTS, AND IT IS A PROCESS FAILURE MORE THAN A TECHNICAL ONE.

1.9.0's card fix was measured against uniformly-random UUIDs and reported five
false positives in twenty thousand. The number was true and the corpus was
wrong: real software is full of NIL UUIDs, zero-padded counters and sequential
ids, and those are exactly the shapes that chain across a UUID's hyphens into a
Luhn-passing run. `00000000-0000-0000-0000-000000000000` reported `credit_card`.

The corpus that would have caught it EXISTED — an earlier draft used a
multiplicative sequence, full of leading zeros — and it was swapped out for the
random one in the same commit that loosened the assertion it had just made red.
Both decisions may have been defensible; taken together and in one step, neither
was reviewable.

So: BOTH classes live here, checked in, each with its own bound asserted
separately, and the file is the thing a future change has to argue with. The two
rules are not interchangeable and must never be collapsed into one number —
`RANDOM_UUIDS` is the easy case and `ZERO_HEAVY` is the real world.

Do not "clean up" a population because it looks unrepresentative. If one is
genuinely wrong, replace it in its own commit, with its own reasoning, so the
corpus change and the assertion change can be judged apart.
"""

from __future__ import annotations

import hashlib
import random
import uuid

_MIX = 0x9E3779B97F4A7C15


def _seeded(n: int, bits) -> list:
    """A fixed-seed generator, so a bound means the same thing on every run."""
    rng = random.Random(5)
    return [tuple(rng.getrandbits(b) for b in bits) for _ in range(n)]


#: Uniformly-random v4-shaped UUIDs. THE EASY CASE — a random 32-hex string
#: rarely holds a long enough all-digit run to chain.
RANDOM_UUIDS = ["%08x-%04x-%04x-%04x-%012x" % parts
                for parts in _seeded(20000, (32, 16, 16, 16, 48))]

#: ⚠ THE REAL WORLD. Nil UUIDs, low-integer UUIDs (what a fixture, a migration or
#: a "not found" path emits), zero-padded counters, hyphen-grouped sequences, and
#: runs of a single repeated digit. Every one of these is a placeholder a
#: developer types without thinking, and the class the 1.9.0 boundary change
#: re-broke.
ZERO_HEAVY = (
    [str(uuid.UUID(int=0))] * 50
    + [str(uuid.UUID(int=i)) for i in range(2000)]
    + [str(uuid.UUID(int=i * _MIX % (1 << 128))) for i in range(1, 4001)]
    + ["%016d" % i for i in range(2000)]
    + ["0000-0000-0000-%04d" % i for i in range(2000)]
    + [digit * length for digit in "0123456789" for length in range(13, 20)]
)

#: The subset with NO random tail: every digit run in these is zero-padded,
#: sequential or uniform. The bound on this one is ZERO, exactly — anything that
#: fires here is a placeholder being read as personal data.
ZERO_HEAVY_STRICT = (
    [str(uuid.UUID(int=0))] * 50
    + [str(uuid.UUID(int=i)) for i in range(2000)]
    + ["%016d" % i for i in range(2000)]
    + ["0000-0000-0000-%04d" % i for i in range(2000)]
    + [digit * length for digit in "0123456789" for length in range(13, 20)]
)

#: Real SHA-256 digests — the population #215 was reported against.
SHA256_DIGESTS = [hashlib.sha256(str(i).encode()).hexdigest()
                  for i in range(20000)]

#: Hyphen-delimited 13-15 digit ids. NOT a regression class: 1.8.0 flagged these
#: at the same rate, because a Luhn-passing hyphen-separated run is what a card
#: number looks like. Kept so that stays measured rather than assumed.
HYPHENATED_IDS = ["build-%d-rc1" % ((n * _MIX) % 10 ** 15 + 10 ** 12)
                  for n in range(1, 20001)]

#: The named cases from the S8c review, so they are asserted by name as well as
#: by rate. A rate can drift; a named case cannot come back quietly.
NAMED_PLACEHOLDERS = [
    "patient record 00000000-0000-0000-0000-000000000000 not found",
    "id 12345678-0000-0000-0000-000000000000",
    "0000-0000-0000-0000",
    "0000000000000000",
    "account 000000000000000 pending",
    "seq 0000-0000-0000-0001",
    "trace 00000000-0000-4000-8000-000000000000",
    "22222222222222222",
    "8888888888888888",
    "order 00000000000000000000 shipped",
]

#: Real PANs in the shapes people write them. Detection of these is the thing all
#: of the above must not be bought at the expense of.
REAL_PANS = [
    "4111111111111111", "4532015112830366", "5425233430109903",
    "374245455400126", "6011111111111117", "3530111333300000",
]
