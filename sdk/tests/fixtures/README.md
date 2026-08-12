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
