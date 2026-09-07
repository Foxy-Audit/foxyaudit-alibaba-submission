#!/usr/bin/env python3
"""Generate the submission dataset from the corpora that already live in this repo.

WARNING -- NOTHING HERE WAS TRAINED. This script does not fit, tune or distil
anything. It exports four files: the labelled prompt corpora the host-side guard
is measured against, the content-blind record the ledger receives for each of
those prompts (marked by whether the AI judge or the deterministic engine grades
it), and the judge's own contract. See ``dataset/README.md``.

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

WHICH SDK IS MEASURED. This checkout's, by construction: ``sdk/src`` is put at
the front of ``sys.path`` before anything is imported, and the script exits if
``foxy_audit`` still resolved elsewhere. The first line of output is
``foxy_audit.__file__`` so the reader can see it too -- a ruleset hash measured
against some other checkout of the SDK is a dataset about some other product.

PREREQUISITES. The SDK's own dependency (``pip install -e ./sdk``) for the three
corpora, plus ``pip install -r backend/requirements.txt`` for
``judge_contract.json``, which imports the backend's pydantic models and the
``OrgPolicy`` table definition. No database is opened.
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
# source tree the same way the backend's own tests read it. The SDK is read from
# THIS checkout's src layout, ahead of anything pip installed, so the venv cannot
# decide which product gets measured.
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "sdk" / "src"))

import foxy_audit  # noqa: E402
from foxy_audit import hashing, introspect, pii, policy, ruleset  # noqa: E402
from foxy_audit.client import _merge_signals  # noqa: E402
from foxy_testbed.sectors import EXPECTATIONS, SECTOR_NAMES, SECTORS  # noqa: E402

if not Path(foxy_audit.__file__).resolve().is_relative_to(ROOT):
    sys.exit("foxy_audit resolved to {0}, outside this checkout; refusing to "
             "measure another product".format(foxy_audit.__file__))

#: The ruleset version the injection corpus's "before" column replays: the one
#: minted immediately before the current one, read from the registry rather
#: than typed here. An evasion is an evasion because THIS definition missed it,
#: and the live one is what caught it. ``test_injection_ruleset_2026_08_5``
#: names the same version as ``PREVIOUS``.
_VERSIONS = ruleset.known_versions()
PREVIOUS_RULESET = _VERSIONS[_VERSIONS.index(ruleset.CURRENT_VERSION) - 1]

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


def _wire_record(prompt: str, triggered: bool, guard_signals,
                 policy_tag: str) -> dict:
    """The content-blind record the ledger receives for this prompt.

    NOT every one of these reaches the AI judge. ``backend/app/worker.py``
    routes an enforcement event (``blocked`` / ``redacted`` /
    ``response_blocked``) to the deterministic ``policy_engine`` and never calls
    a model for it; only an ``interaction`` is graded by the judge. The row's
    ``graded_by`` says which, using the worker's own vocabulary (``rules`` /
    ``ai``), so a reader cannot mistake a blocked row for agent input.

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
            if probe.expect not in EXPECTATIONS:
                failures.append(
                    "{0}: label {1!r} is not one of {2}".format(
                        probe.id, probe.expect, list(EXPECTATIONS)))
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
                "content_blind_record": _wire_record(
                    probe.prompt, result.triggered,
                    list(result.signals) if result.triggered else None,
                    sector.policy_tag),
                # worker.py: an enforcement event is graded by policy_engine
                # ("rules") and never shown to a judge; an interaction is
                # graded by the AI judge ("ai"). Same strings the worker stamps.
                "graded_by": "rules" if result.triggered else "ai",
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

    ONLY THE NAMED SETS. ``identifier_corpora.py`` also holds several large
    generated populations -- hundreds of card and phone shapes that must be
    detected, and thousands of placeholder, digest and id shapes that must not
    be, some asserted at exactly zero and some against a per-set bound. The SDK
    suite (``test_policy_truth_1_9_0.py``) measures all of them; this file
    exports only the named cases, which the README says plainly. It is a strict
    subset of what is measured, not the whole obligation set.

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


def _deployment_default_policy_config() -> dict:
    """The policy flags every graded event carries unless a workspace changed one.

    Ingest (``routers/logs.py``) creates an ``OrgPolicy`` row with its column
    defaults for any workspace that has none, freezes a snapshot of it into
    every event, and the worker projects that snapshot through
    ``judge_policy_config`` before calling a judge. So "no config" is not the
    deployed default -- the column defaults are. Read them off the table
    definition and run the SAME projection, rather than typing the values here.
    """
    from backend.app.models import OrgPolicy
    from backend.app.policy_snapshot import (POLICY_SNAPSHOT_SCHEMA,
                                             judge_policy_config)

    columns = OrgPolicy.__table__.c
    snapshot = {"schema": POLICY_SNAPSHOT_SCHEMA}
    for name in ("pii_detection", "prompt_injection", "regulated_data_mode",
                 "max_token_threshold"):
        snapshot[name] = columns[name].default.arg
    server = columns["confidence_threshold"].server_default.arg
    snapshot["confidence_threshold"] = server if isinstance(server, str) else server.text
    config = judge_policy_config(snapshot)
    if config is None:
        raise LabelDisagreement(
            "judge_policy_config rejected a snapshot built from OrgPolicy's own "
            "column defaults; the snapshot contract moved and this script must "
            "follow it")
    return config


def build_judge_contract() -> dict:
    """The agent's contract: its system prompt, its tools, what it may see.

    Imported from the backend, never transcribed. Four deliberate choices, each
    checked against ``backend/app/worker.py`` rather than assumed:

    * ``policy_config`` is the DEPLOYMENT DEFAULT, built from ``OrgPolicy``'s
      column defaults and projected by the backend's own function (above). An
      empty config would describe a prompt no live workspace receives.
    * ``history`` is present, because the worker builds a seven-day aggregate
      for EVERY graded row and passes it unconditionally. The prompt reads only
      its presence, so a zero-count aggregate in the worker's own shape is what
      is passed here.
    * TWO prompts, because the worker offers ``check_prior_reviews`` only when
      the tag already has at least one non-zero human-ruling count and withholds
      it otherwise. ``system_prompt`` is the prompt every new tag gets (one
      tool); ``system_prompt_with_prior_reviews`` is the prompt once humans have
      ruled (two tools). Shipping only the second would describe the minority
      path as the norm.
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

    policy_config = _deployment_default_policy_config()
    # worker._org_history's shape at zero activity. Only its presence reaches
    # the prompt ("Use recent_history only as an aggregate risk signal").
    history = {"window_days": 7, "recent_breaches": 0, "recent_graded": 0,
               "breach_rate_pct": 0.0}

    return {
        "provider": "qwen",
        "endpoint": defaults["qwen_base_url"].default.rstrip("/") + "/chat/completions",
        "model_default": defaults["qwen_model"].default,
        "model_note": (
            "The deployed model id is settings.qwen_model at deploy time. Model "
            "ids are volatile and are never hardcoded in the judge."),
        "input_allowlist": _allowlist_from(content_blind_meta),
        "event_metadata_allowlist": sorted(SAFE_EVENT_METADATA),
        "policy_config_default": policy_config,
        "system_prompt": qwen_judge._build_system_prompt(
            policy_config, history, lookup_offered=False),
        "system_prompt_with_prior_reviews": qwen_judge._build_system_prompt(
            policy_config, history, lookup_offered=True),
        "system_prompt_note": (
            "Both prompts are built with the deployment-default policy config "
            "(policy_config_default, read from OrgPolicy's column defaults and "
            "projected by judge_policy_config) and with the seven-day history "
            "aggregate the worker always supplies. A workspace that changed a "
            "policy setting gets different rule sentences at the tail. "
            "system_prompt is what every tag receives until a human has ruled "
            "on it; system_prompt_with_prior_reviews is what the worker sends "
            "once check_prior_reviews would return a non-zero count. See "
            "_build_system_prompt in backend/app/qwen_judge.py and "
            "_prior_reviews_lookup in backend/app/worker.py."),
        "tools_always": list(qwen_judge._TOOLS),
        "tools_when_prior_reviews_exist": [qwen_judge._PRIOR_REVIEWS_TOOL],
        "tools_note": (
            "flag_for_human_review is offered on every call. check_prior_reviews "
            "is offered only when the workspace already holds at least one human "
            "ruling on this policy_tag inside the window; with all counts zero the "
            "worker withholds it, so a new workspace's judge has one tool."),
        "prior_reviews_payload_keys": sorted(
            set(qwen_judge._PRIOR_REVIEW_COUNTS) | {"policy_tag"}),
        # The OTHER shape the tool can return: when the lookup itself fails the
        # model is answered with this and told to grade without it. A contract
        # that named only the success shape would reject every real answer
        # produced while the database was unreachable.
        "prior_reviews_unavailable_payload": dict(qwen_judge._LOOKUP_UNAVAILABLE),
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

    # The manifest names the FROZEN ruleset; every label above was measured
    # against the LIVE regexes. The two are only the same thing if nobody edited
    # a pattern without minting a version -- the same invariant the SDK suite
    # pins with `assert ruleset.drift() is None`. An empty provenance is the
    # other way to stamp a hash nothing produced.
    drift = ruleset.drift()
    if drift is not None:
        print("FAILED: live rules do not match ruleset {0}: {1}".format(
            ruleset.CURRENT_VERSION, drift), file=sys.stderr)
        return 1
    provenance = ruleset.provenance()
    if not provenance.get("ruleset_version") or not provenance.get("ruleset_hash"):
        print("FAILED: ruleset.provenance() returned no version/hash; refusing "
              "to write a manifest with a blank provenance", file=sys.stderr)
        return 1
    manifest = {
        "sdk_version": foxy_audit.__version__,
        "ruleset_version": provenance.get("ruleset_version", ""),
        "ruleset_hash": provenance.get("ruleset_hash", ""),
        "rows": {name: counts[name] for name in JSONL_FILES},
        "judge_contract.json": (
            "one JSON object, not rows: the judge's system prompts, its tool "
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
