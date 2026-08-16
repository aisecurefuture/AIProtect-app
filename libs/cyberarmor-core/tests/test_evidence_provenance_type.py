"""Unit tests for cyberarmor_core.evidence.

HONESTY NOTE ON WHAT THESE PROVE. This file was written alongside a NEW module
and passed on its first run. It therefore proves that the type behaves as
specified -- it does NOT prove that a defect was fixed, because there was never
a red state for it to go green from. The red-to-green evidence for this change
lives in the two degraded-differs gates:

    services/compliance/tests/test_evidence_provenance_degraded_differs.py
    services/control-plane/tests/test_compliance_evidence_provenance_degraded_differs.py

What these tests DO buy is regression cover on the four properties the fix
rests on, each of which could be quietly removed by a later edit without any
gate noticing:

    1. offer() cannot let a weaker claim overwrite a stronger one.
    2. A non-bool value cannot become evidence.
    3. Omitting provenance is a TypeError, not a default.
    4. A degraded collection record cannot be attached to a set that then
       serialises like a clean one.
"""

from __future__ import annotations

import sys
import unittest
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent.parent.parent
sys.path.insert(0, str(REPO / "libs" / "cyberarmor-core"))

from cyberarmor_core.evidence import (  # noqa: E402
    PROVENANCE_ABSENT,
    PROVENANCE_ASSERTED,
    PROVENANCE_ATTESTED,
    PROVENANCE_INDETERMINATE,
    PROVENANCE_OBSERVED,
    EvidenceItem,
    EvidenceSet,
    EvidenceValueError,
    MissingEvidence,
)
from cyberarmor_core.health_record import (  # noqa: E402
    EFFECT_EVIDENCE_LOST,
    HealthRecord,
    UnavailableCheck,
)

TS = "2026-07-30T00:00:00+00:00"


def _item(key, satisfied, provenance):
    return EvidenceItem(key, satisfied, provenance, f"unit test: {provenance}", TS)


class TestOfferRanksInsteadOfOverwriting(unittest.TestCase):
    """`{**derived, **caller}` made the LAST writer win. offer() ranks."""

    def test_asserted_cannot_displace_observed(self):
        es = EvidenceSet()
        es.offer(_item("mfa_enabled", True, PROVENANCE_OBSERVED))
        es.offer(_item("mfa_enabled", False, PROVENANCE_ASSERTED))

        self.assertIs(es["mfa_enabled"].satisfied, True)
        self.assertEqual(es["mfa_enabled"].provenance, PROVENANCE_OBSERVED)

    def test_the_loser_is_recorded_not_dropped(self):
        """The examiner-facing sentence: 'they claimed it, we ignored it'."""
        es = EvidenceSet()
        es.offer(_item("encryption_at_rest", True, PROVENANCE_OBSERVED))
        es.offer(_item("encryption_at_rest", False, PROVENANCE_ASSERTED))

        losers = [(i.key, i.provenance, winner) for i, winner in es.superseded]
        self.assertEqual(
            [("encryption_at_rest", PROVENANCE_ASSERTED, PROVENANCE_OBSERVED)],
            losers)

    def test_observed_does_displace_asserted_regardless_of_order(self):
        es = EvidenceSet()
        es.offer(_item("asset_inventory", False, PROVENANCE_ASSERTED))
        es.offer(_item("asset_inventory", True, PROVENANCE_OBSERVED))
        self.assertEqual(es["asset_inventory"].provenance, PROVENANCE_OBSERVED)

    def test_attestation_outranks_assertion_but_not_observation(self):
        for weaker, stronger in ((PROVENANCE_ASSERTED, PROVENANCE_ATTESTED),
                                 (PROVENANCE_ATTESTED, PROVENANCE_OBSERVED)):
            with self.subTest(weaker=weaker, stronger=stronger):
                es = EvidenceSet()
                es.offer(_item("k", True, stronger))
                es.offer(_item("k", True, weaker))
                self.assertEqual(es["k"].provenance, stronger)

    def test_a_tie_goes_to_the_incumbent(self):
        es = EvidenceSet()
        first = EvidenceItem("k", True, PROVENANCE_ASSERTED, "first", TS)
        es.offer(first)
        es.offer(EvidenceItem("k", False, PROVENANCE_ASSERTED, "second", TS))
        self.assertIs(es["k"].satisfied, True)
        self.assertEqual(es["k"].source, "first")

    def test_offer_refuses_a_bare_value(self):
        es = EvidenceSet()
        with self.assertRaises(TypeError):
            es.offer(True)


class TestAValueMustBeAClaimAboutTheWorld(unittest.TestCase):
    """The `0`-buys-a-pass hole, closed at the type.

    Against shipped HEAD every value below PASSED a control: the presence check
    was ``val is None or val is False or val == ""``, and ``0 is False`` is
    False (identity, not equality) while ``[] == ""`` is False.
    """

    def test_values_that_used_to_buy_a_pass_are_rejected(self):
        for bad in (0, 0.0, 1, [], {}, ["nothing"], "yes", 3.14):
            with self.subTest(value=bad):
                with self.assertRaises(EvidenceValueError) as caught:
                    EvidenceItem.coerce(
                        "mfa_enabled", bad, provenance=PROVENANCE_ASSERTED,
                        source="unit test", recorded_at=TS)
                self.assertEqual("mfa_enabled", caught.exception.key)

    def test_bools_are_accepted(self):
        for good in (True, False):
            with self.subTest(value=good):
                item = EvidenceItem.coerce(
                    "mfa_enabled", good, provenance=PROVENANCE_ASSERTED,
                    source="unit test", recorded_at=TS)
                self.assertIs(item.satisfied, good)

    def test_none_and_empty_string_read_as_unsatisfied(self):
        """Same outcome the old presence check gave -- the control fails -- but
        recorded as 'we looked and the answer was no' rather than as silence."""
        for absent in (None, ""):
            with self.subTest(value=absent):
                item = EvidenceItem.coerce(
                    "mfa_enabled", absent, provenance=PROVENANCE_ASSERTED,
                    source="unit test", recorded_at=TS)
                self.assertIs(item.satisfied, False)

    def test_an_unlabelled_mapping_is_refused(self):
        """A dict value passed the old presence check and scored as though the
        platform had observed it. It must not be silently readable now."""
        with self.assertRaises(EvidenceValueError):
            EvidenceItem.coerce(
                "mfa_enabled", {"looks": "structured"},
                provenance=PROVENANCE_ASSERTED, source="unit test",
                recorded_at=TS)


class TestOmittingProvenanceIsAnError(unittest.TestCase):
    """The HealthRecord mechanism: undefaulted positional honesty fields."""

    def test_every_field_is_required(self):
        with self.assertRaises(TypeError):
            EvidenceItem("mfa_enabled", True)          # no provenance at all

    def test_an_unknown_provenance_word_is_refused(self):
        with self.assertRaises(EvidenceValueError):
            EvidenceItem("k", True, "probably_fine", "unit test", TS)

    def test_absent_is_not_constructible_as_an_item(self):
        """`absent` and `indeterminate` must not be expressible as a satisfied
        claim -- mirrors HealthRecord's STATUS_NOT_APPLICABLE."""
        for word in (PROVENANCE_ABSENT, PROVENANCE_INDETERMINATE):
            with self.subTest(provenance=word):
                with self.assertRaises(EvidenceValueError):
                    EvidenceItem("k", True, word, "unit test", TS)

    def test_a_blank_source_is_refused(self):
        with self.assertRaises(EvidenceValueError):
            EvidenceItem("k", True, PROVENANCE_OBSERVED, "   ", TS)

    def test_missing_evidence_has_no_satisfied_field(self):
        m = MissingEvidence("k", PROVENANCE_ABSENT, "nothing produced it")
        self.assertIs(m.satisfied, False)
        with self.assertRaises(Exception):
            m.satisfied = True                          # frozen, and derived


class TestResolutionDistinguishesAbsentFromUnknown(unittest.TestCase):

    def test_absent_key_resolves_absent(self):
        self.assertEqual(PROVENANCE_ABSENT, EvidenceSet().resolve("k").provenance)

    def test_key_lost_to_a_collector_outage_resolves_indeterminate(self):
        es = EvidenceSet()
        es.mark_unresolved("access_control_policy", "policy service unreachable")
        resolved = es.resolve("access_control_policy")
        self.assertEqual(PROVENANCE_INDETERMINATE, resolved.provenance)
        self.assertIn("unreachable", resolved.reason)

    def test_an_independently_observed_key_beats_its_unresolved_marker(self):
        """Downgrading a key another collector really did observe would
        understate what the platform proved."""
        es = EvidenceSet()
        es.mark_unresolved("data_classification", "policy service unreachable")
        es.offer(_item("data_classification", True, PROVENANCE_OBSERVED))
        self.assertEqual(PROVENANCE_OBSERVED, es.resolve("data_classification").provenance)

    def test_an_unresolved_reason_may_not_be_blank(self):
        with self.assertRaises(EvidenceValueError):
            EvidenceSet().mark_unresolved("k", "  ")


class TestCollectionRecordCannotLie(unittest.TestCase):

    def _degraded(self):
        return HealthRecord(
            "compliance.evidence_collection", ("telemetry",),
            (UnavailableCheck("policy_inventory", "connection refused",
                              EFFECT_EVIDENCE_LOST),))

    def test_a_degraded_record_survives_the_round_trip(self):
        es = EvidenceSet()
        es.set_collection(self._degraded())
        self.assertEqual("degraded", es.to_wire()["collection"]["status"])

    def test_a_hand_rolled_clean_record_with_failures_is_refused(self):
        """The exact shape the fix exists to prevent, arriving over a wire."""
        with self.assertRaises(ValueError):
            EvidenceSet().set_collection({
                "schema": "cyberarmor.health/1",
                "status": "ok",
                "degraded": False,
                "checks_unavailable": [
                    {"check": "policy_inventory", "reason": "refused",
                     "effect": EFFECT_EVIDENCE_LOST}],
            })

    def test_an_unrecognised_schema_is_refused_not_read(self):
        with self.assertRaises(ValueError):
            EvidenceSet().set_collection(
                {"schema": "someone.elses/9", "status": "ok"})

    def test_a_degraded_set_does_not_compare_equal_to_a_clean_one(self):
        """EvidenceSet.__eq__ is value-based on purpose. Identity equality
        would make every degraded-differs assertion pass no matter what."""
        clean, degraded = EvidenceSet(), EvidenceSet()
        clean.set_collection(HealthRecord(
            "compliance.evidence_collection", ("policy_inventory", "telemetry"), ()))
        degraded.set_collection(self._degraded())
        self.assertNotEqual(clean, degraded)

    def test_two_identically_built_sets_do_compare_equal(self):
        """The other half of the same point: if __eq__ were identity-based the
        assertNotEqual above would pass vacuously."""
        a, b = EvidenceSet(), EvidenceSet()
        for es in (a, b):
            es.offer(_item("mfa_enabled", True, PROVENANCE_OBSERVED))
        self.assertEqual(a, b)


class TestWireRoundTrip(unittest.TestCase):

    def test_labels_survive_the_envelope(self):
        es = EvidenceSet()
        es.offer(_item("mfa_enabled", True, PROVENANCE_OBSERVED))
        es.offer(_item("security_training", True, PROVENANCE_ATTESTED))
        es.mark_unresolved("access_control_policy", "policy service unreachable")

        back = EvidenceSet.from_wire(
            es.to_wire(), default_provenance=PROVENANCE_ASSERTED,
            default_source="round trip", recorded_at=TS)

        self.assertEqual(PROVENANCE_OBSERVED, back["mfa_enabled"].provenance)
        self.assertEqual(PROVENANCE_ATTESTED, back["security_training"].provenance)
        self.assertEqual(PROVENANCE_INDETERMINATE,
                         back.resolve("access_control_policy").provenance)

    def test_a_legacy_flat_dict_is_asserted_never_observed(self):
        """The residue rule. Unknown provenance is a claim -- coercing historical
        rows to observed would reintroduce the defect across every one of them."""
        back = EvidenceSet.from_wire(
            {"mfa_enabled": True, "asset_inventory": True},
            default_provenance=PROVENANCE_ASSERTED,
            default_source="legacy row", recorded_at=TS)
        self.assertEqual(
            {PROVENANCE_ASSERTED},
            {i.provenance for i in back.values()})

    def test_an_unknown_envelope_version_is_refused(self):
        with self.assertRaises(ValueError):
            EvidenceSet.from_wire(
                {"schema": "cyberarmor.evidence/99", "items": {}},
                default_provenance=PROVENANCE_ASSERTED,
                default_source="x", recorded_at=TS)

    def test_honour_labels_false_downgrades_and_records_the_downgrade(self):
        es = EvidenceSet()
        es.offer(_item("mfa_enabled", True, PROVENANCE_OBSERVED))
        back = EvidenceSet.from_wire(
            es.to_wire(), default_provenance=PROVENANCE_ASSERTED,
            default_source="untrusted channel", recorded_at=TS,
            honour_labels=False)
        self.assertEqual(PROVENANCE_ASSERTED, back["mfa_enabled"].provenance)
        self.assertTrue(back.superseded)

    def test_every_honesty_key_is_present_even_when_empty(self):
        wire = EvidenceSet().to_wire()
        for key in ("schema", "items", "superseded", "unresolved",
                    "by_provenance", "collection"):
            self.assertIn(key, wire)


if __name__ == "__main__":
    unittest.main(verbosity=2)


class TestAPayloadCannotLabelItself(unittest.TestCase):
    """honour_label=False. The bypass that defeated the whole fix.

    A provenance-carrying value is a mapping with a ``provenance`` key -- so a
    caller can simply write one. Every channel whose callers are not the
    platform must strip the label.
    """

    def test_a_self_declared_observation_is_demoted(self):
        item = EvidenceItem.coerce(
            "mfa_enabled",
            {"satisfied": True, "provenance": PROVENANCE_OBSERVED,
             "source": "trust me", "recorded_at": TS},
            provenance=PROVENANCE_ASSERTED, source="request body",
            recorded_at=TS, honour_label=False)
        self.assertEqual(PROVENANCE_ASSERTED, item.provenance)
        self.assertIn("claimed platform_observed", item.source)
        self.assertIs(True, item.satisfied)

    def test_an_evidence_item_object_is_demoted_too(self):
        original = EvidenceItem("k", True, PROVENANCE_OBSERVED, "telemetry", TS)
        item = EvidenceItem.coerce(
            "k", original, provenance=PROVENANCE_ASSERTED,
            source="request body", recorded_at=TS, honour_label=False)
        self.assertEqual(PROVENANCE_ASSERTED, item.provenance)

    def test_honour_label_true_keeps_the_label(self):
        """The control-plane channel still carries real observations."""
        item = EvidenceItem.coerce(
            "k", {"satisfied": True, "provenance": PROVENANCE_OBSERVED,
                  "source": "telemetry", "recorded_at": TS},
            provenance=PROVENANCE_ASSERTED, source="x", recorded_at=TS)
        self.assertEqual(PROVENANCE_OBSERVED, item.provenance)
