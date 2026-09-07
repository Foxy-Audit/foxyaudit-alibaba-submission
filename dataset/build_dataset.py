#!/usr/bin/env python3
"""Generate the submission dataset from the corpora that already live in this repo.

WARNING -- NOTHING HERE WAS TRAINED. This script does not fit, tune or distil
anything. It exports four files: the labelled prompt corpora the host-side guard
is measured against, the exact content-blind records the AI judge receives for
each of those prompts, and the judge's own contract. See ``dataset/README.md``.

THE RULE THIS SCRIPT ENFORCES
=============================
Every label written to disk is RE-MEASURED against the real SDK at generation
time, and a disagreement is a hard exit(1) naming the row. A corpus whose labels
were true when someone typed them is not evidence; a corpus that refuses to be
written unless it still agrees with the engine is.

The assertions are copied from the tests that already own these corpora --
``sdk/tests_testbed/test_probes.py``,
``sdk/tests/test_injection_ruleset_2026_08_5.py`` and
``sdk/tests/test_policy_truth_1_9_0.py``. Where this script and those tests
disagree, the tests are right and this script has a bug.

DETERMINISM
===========
No timestamps, no git SHAs, no environment. Sorted keys, ``ensure_ascii=False``,
LF endings, and ``--check`` compares BYTES against what is on disk -- so a CRLF
checkout cannot pass by accident. Run it twice; the second run changes nothing.

RUN IT IN A VENV THAT HAS THIS WORKTREE'S SDK. ``pip install -e ./sdk`` from the
repository root. The first line of output is ``foxy_audit.__file__`` for exactly
this reason: a ruleset hash measured against some other checkout of the SDK is a
dataset about some other product.
"""

from __future__ import annotations

import argparse
import importlib.util
import json
import sys
import warnings
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parent

# The backend is not an installed package; the judge contract is read from the
# source tree the same way the backend's own tests read it.
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

import foxy_audit  # noqa: E402
from foxy_audit import hashing, introspect, pii, policy, ruleset  # noqa: E402
from foxy_audit.client import _merge_signals  # noqa: E402
from foxy_testbed.sectors import SECTOR_NAMES, SECTORS  # noqa: E402

#: The ruleset version the injection corpus's "before" column replays. Named in
#: ``test_injection_ruleset_2026_08_5.PREVIOUS``; an evasion is an evasion
#: because THIS definition missed it, and the live one is what caught it.
PREVIOUS_RULESET = "2026.08.4"

#: Every tag whose baseline includes the injection family. Four, not three --
#: ``test_no_ordinary_prompt_trips_an_injection_rule`` parametrises over exactly
#: these, and a benign prompt has to stay clean under all of them.
BENIGN_TAGS = ("default", "soc2", "hipaa", "gdpr")

FIXTURES = ROOT / "sdk" / "tests" / "fixtures"

JSONL_FILES = ("guard_probes.jsonl", "injection_corpus.jsonl",
               "identifier_corpus.jsonl")


class LabelDisagreement(Exception):
    """A label on disk no longer matches what the SDK does. Never silenced."""


def _require_regex_only_pii() -> None:
    """Refuse to run with the optional deep-NLP detector active.

    ``pii.detect_pii`` calls Presidio whenever ``foxy-audit[pii]`` is installed,
    and Presidio adds ``presidio:*`` labels that the always-on regex layer never
    produces. That would break this dataset in two ways at once: the bytes would
    differ from one venv to the next, so ``--check`` would fail on another
    machine for a reason that is not drift; and under ``hipaa`` a Presidio hit
    can flip an ``expect_assist`` or ``known_gap`` probe to triggered, so the
    build would exit 1 reporting a label disagreement that is really an optional
    dependency.

    So the dataset is defined against the ALWAYS-ON layer, and this says so out
    loud rather than letting the extra decide. ``_PRESIDIO`` is resolved lazily,
    hence the one throwaway call to settle it before reading it.
    """
    pii._presidio_signals("")
    if pii._PRESIDIO:
        raise LabelDisagreement(
            "the optional [pii] extra is installed and Presidio is active in "
            "this venv. This dataset measures the SDK's always-on regex layer, "
            "which is what every install gets; Presidio would add presidio:* "
            "labels that no other machine reproduces. Regenerate in a venv "
            "built with `pip install -e ./sdk` and no [pii] extra.")


def _load_fixture(module_name: str):
    """Load a corpus module by path -- ``sdk/tests/fixtures`` is not a package.

    Same mechanism as the tests' own ``_load`` helper, for the same reason: there
    is no ``__init__.py`` and adding one would change how the suite imports.
    """
    full = "foxy_dataset._" + module_name
    if full in sys.modules:
        return sys.modules[full]
    spec = importlib.util.spec_from_file_location(
        full, FIXTURES / (module_name + ".py"))
    module = importlib.util.module_from_spec(spec)
    sys.modules[full] = module
    spec.loader.exec_module(module)
    return module


def _live_injection_rules(text: str, tag: str = "default") -> list:
    """The ``injection.*`` rules today's ruleset fires on ``text``.

    Filtered to the injection family and warnings suppressed, exactly as the
    ruleset test's ``_live`` does -- a personal-data rule firing under ``hipaa``
    is a true finding about the prompt and a distraction from the question this
    corpus asks.
    """
    with warnings.catch_warnings():
        warnings.simplefilter("ignore")
        fired = policy.evaluate(text, tag).rules
    return sorted(r for r in fired if r.startswith("injection."))


def _previous_injection_rules(text: str, tag: str = "default") -> list:
    """The same question, asked of the FROZEN ``2026.08.4`` definition.

    A replay of the rules that actually ran, not a sentence about them -- the
    ruleset test's ``_under``.
    """
    return sorted({m.rule_id
                   for m in introspect.replay(ruleset.load(PREVIOUS_RULESET), text, tag)
                   if m.rule_id.startswith("injection.")})


def _judge_input(prompt: str, triggered: bool, guard_signals,
                 policy_tag: str) -> dict:
    """The content-blind record the judge receives for this prompt.

    Reproduced with the SDK's OWN functions rather than by re-deriving them, so
    a change to the wire contract shows up here as a diff instead of as a lie:

    * ``prompt_s`` / ``response_s`` are the canonical forms ``client.py`` hashes
      and sweeps in ``log_interaction``, not the raw strings.
    * the hashes are the KEYLESS SHA-256 form. In production these are HMACs
      under the customer's key, and a public dataset cannot carry that form
      without the key. ``commitment_alg`` names the recipe that produced them.
    * ``response`` is the empty string. No model was called for an offline
      probe, and inventing an answer would be inventing data.
    * ``event_type`` follows ``client._evaluate_preflight``: a tripped guard
      under ``mode="block"`` emits ``blocked`` and never reaches a provider,
      an untripped one emits ``interaction``.
    * ``pii_signals`` is the union the wire carries -- the guard's own labels
      (``None`` on the allow path, where the sweep alone has always been the
      answer) merged with the full sweep, via the SDK's ``_merge_signals``.
    """
    prompt_s = hashing.canonical_json(prompt)
    response_s = hashing.canonical_json("")
    return {
        "prompt_hash": hashing.sha256_hex(prompt_s),
        "response_hash": hashing.sha256_hex(response_s),
        "commitment_alg": "sha256-legacy",
        "token_count": hashing.estimate_tokens(prompt_s, response_s),
        "policy_tag": policy_tag,
        "pii_signals": _merge_signals(guard_signals,
                                      pii.detect_pii(prompt_s, response_s)),
        "event_type": "blocked" if triggered else "interaction",
    }


# -- guard_probes.jsonl ------------------------------------------------------
def build_guard_probes(failures: list) -> list:
    """The 35 sector probes, each re-checked against the engine it claims to test.

    The assertion is ``test_every_probe_gets_the_verdict_its_label_claims``:
    ``expect_block`` must trip a rule and carry rule ids; ``expect_assist`` and
    ``known_gap`` must trip none. A gap probe that started firing is not a
    relabelling job -- it is a finding, and it fails here.

    ``reply`` is deliberately absent. It is a canned string a human wrote for the
    mock provider, not anything the agent ever receives.
    """
    rows = []
    for sector_name in SECTOR_NAMES:
        sector = SECTORS[sector_name]
        for probe in sector.probes:
            result = introspect.check(probe.prompt, sector.policy_tag)
            expects_block = probe.expect == "expect_block"
            if expects_block and not (result.triggered and result.rules):
                failures.append(
                    "{0}: labelled expect_block but nothing fired".format(probe.id))
            if not expects_block and result.triggered:
                failures.append(
                    "{0}: labelled {1} but fired {2}".format(
                        probe.id, probe.expect, sorted(result.rules)))
            # The SHAPE assertions from the same test file. `gap_reason` is the
            # deliverable of a gap probe -- without it the row says "nothing
            # fired" and a reader concludes the guard is broken rather than that
            # the rule family does not exist. Asserted here because the README
            # states it as a property of the shipped data.
            if probe.expect == "known_gap" and not probe.gap_reason.strip():
                failures.append(
                    "{0}: labelled known_gap and must say why nothing catches "
                    "it".format(probe.id))
            if probe.expect != "known_gap" and probe.gap_reason:
                failures.append(
                    "{0}: carries a gap_reason but is not a gap probe".format(
                        probe.id))
            if not probe.intent.strip():
                failures.append(
                    "{0}: every probe says what it is testing".format(probe.id))
            if not probe.id.startswith(sector_name + "."):
                failures.append(
                    "{0}: probe ids are namespaced by sector".format(probe.id))
            rows.append({
                "id": probe.id,
                "sector": sector_name,
                "policy_tag": sector.policy_tag,
                "prompt": probe.prompt,
                "label": probe.expect,
                "intent": probe.intent,
                "gap_reason": probe.gap_reason,
                "measured": {
                    "triggered": result.triggered,
                    "rules": sorted(result.rules),
                    "signals": sorted(result.signals),
                    "reason": result.reason or "",
                },
                "judge_input": _judge_input(
                    probe.prompt, result.triggered,
                    list(result.signals) if result.triggered else None,
                    sector.policy_tag),
            })
    return rows


# -- injection_corpus.jsonl --------------------------------------------------
def build_injection_corpus(failures: list) -> list:
    """The prompt-injection obligation set, both directions, 81 rows.

    THE LABEL DEPENDS ON THE MECHANISM, and this is where the plan of record was
    wrong. ``2026.08.5`` CATCHES the eight ``mechanical`` evasions -- the test
    asserts both halves, that the live ruleset fires and that the frozen
    ``2026.08.4`` definition did not. Only the ``semantic`` and ``declined``
    entries are still uncaught, and they are uncaught ON PURPOSE: a pattern over
    the prompt cannot separate them from ordinary work, and one broad enough to
    try would refuse the benign corpus below.
    """
    corpus = _load_fixture("injection_evasion_corpus")
    previous_key = "measured_under_" + PREVIOUS_RULESET.replace(".", "_")
    rows = []

    for evasion in corpus.EVASIONS:
        live = _live_injection_rules(evasion.prompt)
        previous = _previous_injection_rules(evasion.prompt)
        answerable = evasion.kind == corpus.MECHANICAL
        label = "must_trigger" if answerable else "must_not_trigger_today"
        if answerable:
            if not live:
                failures.append(
                    "{0}: mechanical evasion no longer caught. Why it used to "
                    "pass: {1}".format(evasion.id, evasion.why_it_passes))
            if previous:
                failures.append(
                    "{0}: already caught by {1}, so it is not an evasion and "
                    "the before/after pair proves nothing".format(
                        evasion.id, PREVIOUS_RULESET))
        elif live:
            failures.append(
                "{0} ({1}) is now caught: {2}. Read the corpus entry before "
                "relabelling it -- this is either a real advance that needs its "
                "own reasoning, or a rule broad enough to refuse ordinary "
                "work.".format(evasion.id, evasion.kind, live))
        rows.append({
            "id": evasion.id,
            "kind": "evasion",
            "mechanism": evasion.kind,
            "prompt": evasion.prompt,
            "intent": evasion.intent,
            "why_it_passes": evasion.why_it_passes,
            "label": label,
            "measured": {"injection_rules": live},
            previous_key: {"injection_rules": previous},
        })

    for rule_id, text in corpus.ALREADY_CAUGHT:
        live = _live_injection_rules(text)
        previous = _previous_injection_rules(text)
        if rule_id not in live:
            failures.append(
                "caught.{0}: no longer fires that rule (fired {1}). A "
                "broadening that loses a detection is a regression in a "
                "costume.".format(rule_id, live))
        if rule_id not in previous:
            failures.append(
                "caught.{0}: {1} did not fire it either, so the before column "
                "on every evasion above measures nothing".format(
                    rule_id, PREVIOUS_RULESET))
        rows.append({
            "id": "caught." + rule_id,
            "kind": "already_caught",
            "rule": rule_id,
            "prompt": text,
            "label": "must_trigger",
            "measured": {"injection_rules": live},
            previous_key: {"injection_rules": previous},
        })

    for entry in corpus.BENIGN:
        measured = {tag: _live_injection_rules(entry.prompt, tag)
                    for tag in BENIGN_TAGS}
        for tag in BENIGN_TAGS:
            if measured[tag]:
                failures.append(
                    "{0} ({1}) now refuses under tag={2!r}: {3}{4}".format(
                        entry.id, entry.sector, tag, measured[tag],
                        "; this entry exists because: " + entry.near_miss
                        if entry.near_miss else ""))
        rows.append({
            "id": entry.id,
            "kind": "benign",
            "sector": entry.sector,
            "prompt": entry.prompt,
            "near_miss": entry.near_miss,
            "label": "must_stay_clean",
            "measured": {"injection_rules_by_policy_tag": measured},
        })

    return rows


# -- identifier_corpus.jsonl -------------------------------------------------
def build_identifier_corpus(failures: list) -> list:
    """The 21 INDIVIDUALLY asserted identifier cases.

    ONLY THE NAMED SETS. ``identifier_corpora.py`` also holds four large
    generated populations, but their guarantee is a per-SET false-positive rate,
    not a per-item label -- writing ``must_not_detect`` on each of 20,000 rows
    would be asserting something nobody measured.

    The placeholder assertion is the one the test makes and NOT "no signal at
    all": ``credit_card`` and ``phone`` must be absent. Anything else the sweep
    finds is recorded rather than forbidden.
    """
    corpus = _load_fixture("identifier_corpora")
    rows = []

    for index, (text, label) in enumerate(corpus.NAMED_OBLIGATIONS):
        signals = sorted(pii.detect_pii(text, ""))
        if label not in signals:
            failures.append(
                "obligation.{0}: {1} lost on {2!r} (found {3})".format(
                    index, label, text, signals))
        rows.append({
            "id": "obligation.{0}".format(index),
            "text": text,
            "label": "must_detect",
            "expected_signal": label,
            "measured": {"signals": signals},
        })

    forbidden = ["credit_card", "phone"]
    for index, text in enumerate(corpus.NAMED_PLACEHOLDERS):
        signals = sorted(pii.detect_pii(text, ""))
        for signal in forbidden:
            if signal in signals:
                failures.append(
                    "placeholder.{0}: {1} came back on {2!r}".format(
                        index, signal, text))
        rows.append({
            "id": "placeholder.{0}".format(index),
            "text": text,
            "label": "must_not_detect",
            "forbidden_signals": list(forbidden),
            "measured": {"signals": signals},
        })

    return rows


# -- judge_contract.json -----------------------------------------------------
def _allowlist_from(function) -> list:
    """The ``safe_keys`` tuple, read out of the compiled function itself.

    ``content_blind_meta`` keeps its allowlist in a local constant, so there is
    nothing to import. Reading it from ``__code__.co_consts`` measures the list
    that actually runs instead of copying one into this file, where it would
    drift silently. If the constant is not there, that is a hard failure -- an
    input allowlist reconstructed from memory would be the wrong kind of guess.
    """
    for const in function.__code__.co_consts:
        if isinstance(const, tuple) and "prompt_hash" in const:
            return list(const)
    raise LabelDisagreement(
        "could not read the input allowlist out of content_blind_meta; it is no "
        "longer a constant tuple, and this script must be updated rather than "
        "left to guess what the judge is allowed to see")


def build_judge_contract() -> dict:
    """The agent's contract: its system prompt, its two tools, what it may see.

    Imported from the backend, never transcribed. Three deliberate choices:

    * the system prompt is built with an EMPTY ``policy_config``, which is the
      deployment-default path -- ``_build_system_prompt`` skips its four
      policy-derived rules when the config is falsy, so this is the DEFAULT
      prompt and not "the" prompt. A per-org config appends rules to it.
    * ``lookup_offered=True``, because the deployed worker supplies a
      prior-review lookup and the prompt must name a tool it is actually given.
    * the endpoint and model come from the ``Settings`` FIELD DEFAULTS, not from
      ``get_settings()``. Reading live settings would make the output depend on
      whichever environment ran the generator, and ``--check`` would then fail
      on another machine for no reason at all.
    """
    from backend.app import qwen_judge
    from backend.app.config import Settings
    from backend.app.judge import SAFE_EVENT_METADATA, content_blind_meta
    from backend.app.schemas import Verdict

    defaults = Settings.model_fields
    decision = Verdict.model_fields["decision"]
    pattern = next((m.pattern for m in decision.metadata
                    if hasattr(m, "pattern")), None)
    if not pattern:
        raise LabelDisagreement(
            "Verdict.decision no longer carries a pattern constraint")

    return {
        "provider": "qwen",
        "endpoint": defaults["qwen_base_url"].default.rstrip("/") + "/chat/completions",
        "model_default": defaults["qwen_model"].default,
        "model_note": (
            "The deployed model id is settings.qwen_model at deploy time. Model "
            "ids are volatile and are never hardcoded in the judge."),
        "input_allowlist": _allowlist_from(content_blind_meta),
        "event_metadata_allowlist": sorted(SAFE_EVENT_METADATA),
        "system_prompt": qwen_judge._build_system_prompt(
            {}, None, lookup_offered=True),
        "system_prompt_note": (
            "Built with an empty policy_config, which is the deployment default. "
            "A workspace with an active policy config appends rules to this "
            "prompt; see _build_system_prompt in backend/app/qwen_judge.py."),
        "tools": [qwen_judge._TOOLS[0], qwen_judge._PRIOR_REVIEWS_TOOL],
        "prior_reviews_payload_keys": sorted(
            set(qwen_judge._PRIOR_REVIEW_COUNTS) | {"policy_tag"}),
        "prior_review_window_days": qwen_judge.PRIOR_REVIEW_WINDOW_DAYS,
        "verdict": {
            "returned_as_json": ["policy_breach", "reason", "risk_score",
                                 "decision", "rules"],
            "decision_pattern": pattern,
            "decision_note": (
                "The judge returns clean or breach in its JSON. human_review is "
                "recorded when it calls flag_for_human_review instead, and "
                "unknown when the grade could not be used at all. blocked, "
                "redacted and response_blocked are the deterministic engine's "
                "own outcomes, carried on the same field."),
        },
    }


# -- serialisation -----------------------------------------------------------
def _jsonl_bytes(rows: list) -> bytes:
    # One trailing newline after the LAST row, and nothing at all for an empty
    # list -- so a corpus that emptied out reports 0 rows in the manifest rather
    # than 1, which is what joining then appending would have said.
    return "".join(
        json.dumps(row, sort_keys=True, ensure_ascii=False,
                   separators=(",", ": ")) + "\n"
        for row in rows).encode("utf-8")


def _json_bytes(value) -> bytes:
    return (json.dumps(value, sort_keys=True, ensure_ascii=False,
                       indent=2) + "\n").encode("utf-8")


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(
        description="Regenerate the submission dataset from this repo's corpora.")
    parser.add_argument(
        "--check", action="store_true",
        help="regenerate into memory and compare BYTES against what is on disk; "
             "exit 1 on any difference. This is the drift gate.")
    args = parser.parse_args(argv)

    # FIRST LINE OF OUTPUT, ALWAYS. A measurement is only as trustworthy as the
    # checkout it was taken against, and this machine has more than one.
    print("foxy_audit.__file__ = {0}".format(foxy_audit.__file__))
    print("foxy_audit version  = {0}".format(foxy_audit.__version__))

    failures: list = []
    counts: dict = {}
    try:
        _require_regex_only_pii()
        corpora = {
            "guard_probes.jsonl": build_guard_probes(failures),
            "injection_corpus.jsonl": build_injection_corpus(failures),
            "identifier_corpus.jsonl": build_identifier_corpus(failures),
        }
        counts = {name: len(rows) for name, rows in corpora.items()}
        artefacts = {name: _jsonl_bytes(rows) for name, rows in corpora.items()}
        artefacts["judge_contract.json"] = _json_bytes(build_judge_contract())
    except LabelDisagreement as exc:
        print("FAILED: {0}".format(exc), file=sys.stderr)
        return 1

    if failures:
        print("\n{0} label(s) no longer agree with the SDK. Nothing was "
              "written.\n".format(len(failures)), file=sys.stderr)
        for line in failures:
            print("  - {0}".format(line), file=sys.stderr)
        print("\nThe corpus is not the authority here; the engine is. Fix the "
              "rule or argue for the relabelling, in that order.",
              file=sys.stderr)
        return 1

    provenance = ruleset.provenance()
    manifest = {
        "sdk_version": foxy_audit.__version__,
        "ruleset_version": provenance.get("ruleset_version", ""),
        "ruleset_hash": provenance.get("ruleset_hash", ""),
        "rows": {name: counts[name] for name in JSONL_FILES},
        "judge_contract.json": (
            "one JSON object, not rows: the judge's system prompt, its two tool "
            "schemas, and the two metadata allowlists"),
    }
    artefacts["manifest.json"] = _json_bytes(manifest)

    if args.check:
        drifted = []
        for name in sorted(artefacts):
            path = HERE / name
            if not path.exists():
                drifted.append("{0}: missing".format(name))
            elif path.read_bytes() != artefacts[name]:
                drifted.append("{0}: differs from a fresh generation".format(name))
        if drifted:
            print("\nDATASET IS STALE:", file=sys.stderr)
            for line in drifted:
                print("  - {0}".format(line), file=sys.stderr)
            print("\nRun `python dataset/build_dataset.py` and commit the "
                  "result.", file=sys.stderr)
            return 1
        print("check: {0} files match a fresh generation".format(len(artefacts)))
        return 0

    for name in sorted(artefacts):
        with open(HERE / name, "wb") as handle:
            handle.write(artefacts[name])
    for name in JSONL_FILES:
        print("wrote {0:<24} {1} rows".format(name, manifest["rows"][name]))
    print("wrote {0:<24} 1 object".format("judge_contract.json"))
    print("wrote {0:<24} ruleset {1} {2}".format(
        "manifest.json", manifest["ruleset_version"],
        manifest["ruleset_hash"][:12]))
    return 0


if __name__ == "__main__":
    sys.exit(main())
