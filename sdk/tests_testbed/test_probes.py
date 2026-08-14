"""The probe corpus is only worth anything if its labels are TRUE.

Every claim in ``sectors.py`` is a claim about what ``foxy_audit.policy``
actually does, so each one is pinned here against the real detector rather than
against a description of it. If the SDK's rules change under us, these fail and
name the probe — which is the point: a corpus that drifts out of agreement with
the engine turns the scoreboard into decoration.
"""

from __future__ import annotations

import dataclasses

import pytest
from foxy_audit import check

from foxy_testbed.sectors import (EXPECT_ASSIST, EXPECT_BLOCK, EXPECTATIONS,
                                  KNOWN_GAP, SECTOR_NAMES, SECTORS, get_sector)

ALL_PROBES = [(s.name, p) for name in SECTOR_NAMES
              for s in (SECTORS[name],) for p in s.probes]
IDS = ["{0}:{1}".format(sector, p.id) for sector, p in ALL_PROBES]


@pytest.mark.parametrize("sector_name,probe", ALL_PROBES, ids=IDS)
def test_every_probe_gets_the_verdict_its_label_claims(sector_name, probe):
    """The corpus, checked against the engine it is a corpus for.

    ``expect_block`` must trip a rule; ``expect_assist`` and ``known_gap`` must
    trip none. A gap probe failing here is the good kind of failure -- something
    in the SDK started catching it, and the preset's prose needs to catch up.
    """
    result = check(probe.prompt, SECTORS[sector_name].policy_tag)
    if probe.expect == EXPECT_BLOCK:
        assert result.triggered, (
            "{0} is labelled expect_block but nothing fired".format(probe.id))
        assert result.rules
    else:
        assert not result.triggered, (
            "{0} is labelled {1} but fired {2}".format(
                probe.id, probe.expect, result.rules))


@pytest.mark.parametrize("sector_name,probe", ALL_PROBES, ids=IDS)
def test_every_probe_is_shaped_the_way_its_label_requires(sector_name, probe):
    assert probe.expect in EXPECTATIONS
    assert probe.id.startswith(sector_name + "."), (
        "probe ids are namespaced by sector so a scoreboard line is unambiguous")
    assert probe.intent.strip(), "every probe says what it is testing"

    if probe.expect == KNOWN_GAP:
        # The reason IS the deliverable for a gap probe. Without it the
        # scoreboard says "nothing fired" and the reader concludes the guard is
        # broken rather than that the rule family does not exist.
        assert probe.gap_reason.strip(), (
            "{0} is a known gap and must say why nothing catches it".format(probe.id))
    else:
        assert not probe.gap_reason

    if probe.expect == EXPECT_ASSIST:
        assert probe.reply.strip(), (
            "{0} needs a fixture reply, or the assistance column measures "
            "nothing but the fallback".format(probe.id))
    else:
        # A block never reaches a provider, so a canned answer for one would be
        # a reply to a prompt that was stopped -- words in a model's mouth for
        # an interaction that never happened.
        assert not probe.reply, (
            "{0} is not an assist probe and must carry no fixture reply".format(probe.id))


def test_probe_ids_are_unique_across_every_sector():
    ids = [p.id for _sector, p in ALL_PROBES]
    assert len(ids) == len(set(ids))


@pytest.mark.parametrize("sector_name", SECTOR_NAMES)
def test_every_sector_has_all_three_columns(sector_name):
    """Both columns, plus the gaps. A sector with no assist probes would score a
    perfect enforcement rate while proving nothing about usefulness, which is
    the exact failure the second column exists to prevent."""
    sector = SECTORS[sector_name]
    assert sector.probes_expecting(EXPECT_BLOCK), "no enforcement probes"
    assert sector.probes_expecting(EXPECT_ASSIST), "no assistance probes"
    assert sector.probes_expecting(KNOWN_GAP), (
        "no gap probes -- every preset here has uncovered sector risk, and a "
        "sector claiming none would need that claim proven, not assumed")


@pytest.mark.parametrize("sector_name", SECTOR_NAMES)
def test_every_preset_states_its_own_limits(sector_name):
    sector = SECTORS[sector_name]
    note = sector.policy_note
    assert sector.policy_tag in note, (
        "the note names the tag it is describing, so a reader can check it")
    assert "NOT" in note, (
        "every preset says what it does NOT cover; 'this is complete' is not "
        "true of any of the three")


def test_the_two_baseline_sectors_say_so_rather_than_inventing_a_tag():
    """finance and legal run on ``default``, and the preset admits it.

    Pinned because the tempting fix is to write ``policy="pci"`` or
    ``policy="finance"``, which would fall through the policy map to the
    baseline anyway while labelling the ledger row as though a domain check had
    run. That is the ``hipaa_basic`` defect, and this is where it comes back.
    """
    for name in ("finance", "legal"):
        sector = SECTORS[name]
        assert sector.policy_tag == "default"
        assert "BASELINE ONLY" in sector.policy_note


def test_the_finance_preset_states_the_card_gap_rather_than_implying_coverage():
    """The card check exists, is real, and does NOT run under ``default``.

    Measured rather than asserted from the docstring: the same prompt is checked
    under both tags, and the two answers are what the preset has to describe.
    """
    card_probe = next(p for p in SECTORS["finance"].probes
                      if p.id == "finance.gap.cardholder_data")

    assert not check(card_probe.prompt, "default").triggered
    assert "pii.credit_card" in check(card_probe.prompt, "gdpr").rules
    assert "phi.credit_card" in check(card_probe.prompt, "hipaa").rules

    note = SECTORS["finance"].policy_note
    assert "NOT blocked" in note
    assert "pii_signals" in note, (
        "the note distinguishes the sweep that RECORDS a card from the guard "
        "that would have PREVENTED it; conflating them is the whole defect")


def test_the_legal_preset_claims_no_confidentiality_coverage_at_all():
    note = SECTORS["legal"].policy_note
    assert "no detector" in note
    for probe in SECTORS["legal"].probes_expecting(KNOWN_GAP):
        assert not check(probe.prompt, "default").rules


def test_get_sector_names_the_alternatives_when_it_fails():
    with pytest.raises(ValueError) as excinfo:
        get_sector("insurance")
    message = str(excinfo.value)
    for name in SECTOR_NAMES:
        assert name in message


# ── the cp1252 guard ──────────────────────────────────────────────────────────
def _rendered_strings():
    """Every string in the presets that reaches a terminal."""
    for sector in SECTORS.values():
        for field in dataclasses.fields(sector):
            value = getattr(sector, field.name)
            if isinstance(value, str):
                yield "{0}.{1}".format(sector.name, field.name), value
        for probe in sector.probes:
            for field in dataclasses.fields(probe):
                value = getattr(probe, field.name)
                if isinstance(value, str):
                    yield "{0}.{1}".format(probe.id, field.name), value


def test_no_preset_string_can_break_a_cp1252_console():
    """7-bit only, and this is not hypothetical.

    A Windows console and a captured CI stream are both cp1252 here. Writing an
    em dash or a warning sign into a field that gets printed raises
    UnicodeEncodeError inside ``print``, so the gate fails with a traceback
    pointing at the renderer instead of at the character. It happened while this
    corpus was being written; encoding to cp1252 is the check that would have
    caught it in the first place.
    """
    offenders = []
    for where, value in _rendered_strings():
        try:
            value.encode("cp1252")
        except UnicodeEncodeError as exc:
            offenders.append("{0}: {1!r}".format(where, value[exc.start:exc.end]))
    assert not offenders, "non-cp1252-encodable text in printed fields: " + "; ".join(offenders)
