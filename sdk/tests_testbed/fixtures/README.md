# The reverted ruleset

`reverted_2026_08_5.py` is `sdk/src/foxy_audit/rulesets/v2026_08_5.py` as it
stood at commit `018a07a` — the first cut of that ruleset, extracted with
`git show` and checked in unedited. It is **not** the 2026.08.5 the SDK ships:
`df23565` rewrote that module in place after the gate measured four ordinary
sentences BLOCKED by it, in four sectors, with the model never called.

Two defects, both in the injection family:

* the widened noun lists had no trailing `\b`, so `policy` matched inside
  `policyholder` and `rules` inside `ruleset`;
* shape (d) accepted a bare `above|earlier|before|previously` after up to four
  filler words, so any reference to an earlier part of a **document** read as an
  override of the assistant's own instructions.

## Why it is here

`test_overblock_probes.py` is the evidence that T5's six new `expect_assist`
probes can see the defect they were added for. It replays them against this
definition and drives the live engine with its rules monkeypatched in, and the
six come back OVER-BLOCKED — while the twelve assist probes that predate the
phase come back clean, which is exactly why three green scoreboards sat on top
of the regression.

A probe asserted only against today's rules proves the rules are fine today. It
proves nothing about whether the probe would have caught anything.

## It proves its own identity

The reverted round published
`dce670708dbb12cb088352e4771e2779942ae4aa7e81d9a6b7b6354ac4373bf6` as the
sha256 over its canonical JSON, and `ruleset.hash_of(DEFINITION)` on this file
returns that string — asserted, first test in the file. A reconstruction that
hashes to the published value is the shipped artifact; one that does not is a
strawman, and the difference decides whether the rest of the file means
anything.

Do not edit it. It is not a ruleset; it is a record of a ruleset that was
withdrawn.
