# Frozen reference modules

`policy_1_5_0.py` is `sdk/src/foxy_audit/policy.py` as it stood at commit
`b651a62` (release 1.5.0) — the same source, extracted with `git show` and
subject to git's usual line-ending normalisation like every other file. It is
checked in, not fetched from git at test time, on purpose.

`test_policy_vocabulary.py` loads it side by side with the live module and
asserts that `evaluate(text, "default")` and `redact(text, "default")` are
identical across a wide corpus — the 1.6.0 policy map became additive, and the
`default` path had to come through that untouched.

A golden-vector file generated on the branch would only prove the branch agrees
with itself. A `git show` at test time would prove nothing once this work is on
`main`, because the reference would become the change. A frozen copy of the
actual pre-change module is the only form of that check that stays meaningful
after the merge.

Do not edit it. It is not the SDK's policy module; it is a record of what the
SDK's policy module used to do.

## The 1.8.0 pair

`policy_1_8_0.py` and `pii_1_8_0.py` are the same two modules as they stood at
commit `2eff344` (release 1.8.0), extracted the same way, for the four truth
fixes in 1.9.0 (SDK #215–#218). `test_policy_truth_1_9_0.py` loads them side by
side with the live modules and enumerates *every* input whose verdict changed,
asserting everything else is identical across eight policy tags.

**They come as a PAIR, and the test rebinds one onto the other.** `policy_1_8_0`
does `from . import pii`, which resolves against the real package — so without
`OLD_POLICY.pii = OLD_PII` the frozen policy would use *today's* detectors and
the #215 change would be invisible in a comparison that looked thorough.

The single-module `policy_1_5_0.py` above has no such pair because the 1.6.0
change it records was in the policy map alone; sharing today's `pii` was
deliberate there, and it is why that fixture keeps working unchanged.
