"""The taxonomy must cover what the product actually emits.

WHY A CONFORMANCE TEST AND NOT ONLY UNIT TESTS
----------------------------------------------
A unit test proves ``classify("mcp_config_finding")`` returns what I wrote in
the table. It cannot prove the table covers the events this product SENDS --
and that is the only property that matters for search. A new emitter added next
quarter with no mapping would classify as ``unknown``, every unit test would
still pass, and the telemetry search would quietly stop being complete.

So this greps the repository for event types that are actually emitted and
fails when one has no classification. Same shape as the policy field registry's
conformance test, and for the same reason: the dangerous drift is a surface
nobody remembered to update, which no behavioural test can see.

It is deliberately a SOURCE scan rather than a fixed list. A fixed list is
another thing to forget.
"""

from __future__ import annotations

import re
import subprocess
import sys
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(REPO / "libs" / "cyberarmor-core"))

from cyberarmor_core.event_taxonomy import (  # noqa: E402
    ACTIONS,
    CATEGORIES,
    EVENT_CLASSES,
    SOURCES,
    UNKNOWN,
    classify,
    known_event_types,
    unclassified_event_types,
)

#: Emitters that are not real product events.
_IGNORED = {
    "test",       # siem-connector's self-test endpoint
    "generic",    # the SecurityEvent default
    "telemetry",  # a fallback label, not an emitted type
    # Collected by the broadened line-scan below, which pulls EVERY snake_case
    # literal off an event-type line. These are field names, dict keys and
    # ordinary words that share those lines -- not event types. Listing them
    # explicitly is the cost of a scan that no longer misses emitters written
    # as expressions, and it is the right trade: an extra name to dismiss here
    # is visible, an emitter the scan cannot see is not.
    "count", "event", "event_type", "keyword", "type",
    # Field names and identifiers that sit on or beside an emit line.
    "agent_id", "event_id", "tenant_id", "user_id", "occurred_at",
    "schema_version", "server_count", "source_detail", "stored_state",
    "amount_minor_units", "product_name", "vendor_name",
    # `source` VALUES, not event types -- these name where an event came from.
    "endpoint_agent", "endpoint_clipboard_helper", "admin_dashboard",
    "control_plane",
    # A monitor MODULE name (monitors/ai_tool_detector.py) used as a logger or
    # source label, not an event type.
    "ai_tool_detector",
}

#: Lines that assign an event type, in any of the shapes this repo uses.
#:
#: DELIBERATELY TWO STEPS: find the LINE, then pull every snake_case string
#: literal off it. An earlier version matched only a literal sitting directly
#: after `"event_type":`, and the moment an emitter was written as an
#: expression --
#:
#:     "event_type": "privilege_escalation" if escalation else "privileged_action",
#:
#: -- BOTH names became invisible to the scan, silently. The coverage
#: assertion still passed, because it can only check what it can see. A
#: guard that stops seeing new emitters is worse than no guard: it reports
#: complete coverage of a shrinking set.
#: `emit_event(...)` is included because the SDK's emit API takes the type
#: POSITIONALLY -- `emit_event("agent_scope_violation", payload={...})` -- so no
#: `event_type` token appears on the line at all. That is the third distinct
#: shape this scan has been blind to (literal-after-key, conditional
#: expression, positional argument), and the lesson is that a text scan is a
#: floor rather than a proof: it catches what it has been taught to look for.
#: When a new emit helper appears, teach it here.
_EVENT_TYPE_LINE = re.compile(r'"event_type"\s*:|event_type\s*=|emit_event\(')
#: Requires at least one underscore. Every event type this product emits is
#: snake_case with a verb or noun phrase in it; the bulk of what a
#: context-window scan drags in is single-word dict keys and values ("action",
#: "severity", "payload", "high"). Demanding an underscore removes most of that
#: noise without hiding a single real emitter. What survives and still is not
#: an event type is listed in _IGNORED.
_STRING_LITERAL = re.compile(r"[\"']([a-z][a-z0-9.-]*_[a-z0-9_.-]+)[\"']")


#: Directories that are not this product's source. Without these exclusions the
#: scan walks node_modules, java target/ and the .claude worktrees, which took
#: it past a two-minute timeout and would have made this test useless in CI.
_EXCLUDE_DIRS = (
    "node_modules", ".git", "worktrees", "target", "dist", "build",
    "__pycache__", ".venv", "venv", "site-packages",
    # Tests are not product emitters. They deliberately fabricate unmapped
    # event types to prove the UNKNOWN path works -- counting those as
    # emissions makes this test demand a classification for a name that exists
    # only to be unclassified. (It caught them immediately, which is the test
    # doing its job from the wrong input.)
    "tests",
)

#: Belt and braces for a test file living outside a tests/ directory.
_EXCLUDE_FILES = ("test_*.py", "*_test.py", "conftest.py")

#: Only source files emit events. Scanning .json/.map/.lock is pure cost.
_INCLUDE_GLOBS = ("*.py", "*.js", "*.mjs", "*.ts", "*.go", "*.java", "*.cs")


def _emitted_event_types() -> set[str]:
    """Every event_type literal the product emits, read from source."""
    scan_roots = ["services", "agents", "libs", "extensions", "sdks"]
    # -A2: an emit call is frequently wrapped, putting the type on the line
    # AFTER the one that matched --
    #
    #     self._ca_client.emit_event(
    #         "agent_scope_violation",
    #
    # -- which a strictly line-based scan cannot see. Two lines of trailing
    # context covers the wrapped forms in this repo without pulling in whole
    # function bodies.
    cmd = ["grep", "-rhE", "-A2", _EVENT_TYPE_LINE.pattern]
    for d in _EXCLUDE_DIRS:
        cmd.append(f"--exclude-dir={d}")
    for f in _EXCLUDE_FILES:
        cmd.append(f"--exclude={f}")
    for g in _INCLUDE_GLOBS:
        cmd.append(f"--include={g}")
    cmd += [str(REPO / r) for r in scan_roots if (REPO / r).is_dir()]

    out = subprocess.run(cmd, capture_output=True, text=True, timeout=60).stdout
    found: set[str] = set()
    for line in out.splitlines():
        # Every snake_case literal on an event-type line, not just one sitting
        # directly after the key. Over-collects slightly -- a nearby unrelated
        # string can slip in -- and that is the safe direction: the cost is one
        # extra name to classify, versus an emitter nobody ever notices.
        found.update(_STRING_LITERAL.findall(line))
    return {e for e in found if e and e not in _IGNORED}


class TestTheTaxonomyCoversTheProduct:
    def test_every_emitted_event_type_is_classified(self):
        """THE POINT OF THIS FILE."""
        emitted = _emitted_event_types()
        assert emitted, "the source scan found no event types at all -- the scan is broken"
        missing = unclassified_event_types(emitted)
        assert not missing, (
            f"these event types are emitted by the product and have no "
            f"classification: {sorted(missing)}. They will appear in telemetry "
            f"search as category='unknown', so a search that looks complete "
            f"will be missing them. Add them to _TABLE in event_taxonomy.py."
        )

    def test_the_scan_actually_finds_known_emitters(self):
        """Guards the guard. A broken grep would make the test above vacuous.

        These three are emitted from PRODUCT source, verified by hand:
        agent.py for the first two, the proxy for the third. An earlier version
        of this test also probed for `session_heartbeat`, which turned out to
        exist only in test fixtures -- see
        TestAnticipatedEntriesAreNotEvidence.
        """
        emitted = _emitted_event_types()
        for expected in ("privileged_action", "mcp_config_finding", "proxy_traffic"):
            assert expected in emitted, (
                f"the source scan did not find {expected!r}, which IS emitted "
                f"by product source -- the scan is not working, so the "
                f"coverage assertion above proves nothing"
            )


class TestTheTableIsInternallyValid:
    """Every value in the table must be one of the declared dimensions.

    A typo like ``category="secuirty"`` is invisible at runtime -- it just
    produces a category nothing searches for.
    """

    @pytest.mark.parametrize("event_type", sorted(known_event_types()))
    def test_category_and_class_are_declared_values(self, event_type):
        c = classify(event_type)
        assert c.category in CATEGORIES, f"{event_type}: {c.category!r} is not a declared category"
        assert c.event_class in EVENT_CLASSES, f"{event_type}: {c.event_class!r} is not a declared class"

    def test_no_dimension_contains_a_general_bucket(self):
        """'general' is how a taxonomy stops discriminating.

        An event with no source is a bug, not a category -- and a catch-all
        value is where every event nobody thought about ends up.
        """
        for dimension in (SOURCES, CATEGORIES, EVENT_CLASSES, ACTIONS):
            assert "general" not in dimension
            assert "other" not in dimension
            assert "misc" not in dimension


class TestUnknownIsExplicitNeverGuessed:
    def test_an_unrecognised_type_is_unknown(self):
        c = classify("something_invented_next_quarter")
        assert c.category == UNKNOWN
        assert c.event_class == UNKNOWN

    def test_no_ocsf_id_is_invented_for_an_unknown_type(self):
        """A wrong class_uid is worse than a missing one: it looks right, and a
        SIEM rule keyed on it silently matches the wrong events."""
        c = classify("something_invented_next_quarter")
        assert c.ocsf_class_uid == 0
        assert c.ocsf_category_uid == 0

    @pytest.mark.parametrize("value", ["", None, "   "])
    def test_empty_input_is_unknown_not_a_crash(self, value):
        assert classify(value).category == UNKNOWN

    def test_whitespace_is_tolerated_on_a_known_type(self):
        assert classify("  privileged_action  ").event_class == "privilege"


class TestThePackEventTypesAreDocumentedAsMissing:
    """The compliance packs name event types NOTHING emits.

    31 leaf rules across the shipped packs key on event.event_type. Not one of
    the five values they use is produced anywhere in the product -- measured
    2026-08-01. This is scoped as E4 in
    docs/specs/event-taxonomy-and-policy-evaluated-events.md.

    Note what this is NOT. An earlier version of this test asserted a
    "near miss" -- that the packs say `heartbeat` while the agent emits
    `session_heartbeat`. That was wrong: `session_heartbeat` appears only in
    test fixtures, and the claim came from a source scan that included tests.
    The truth is simpler and worse for the packs -- there is no producer at
    all, near or otherwise.
    """

    #: Every event type the shipped packs key on.
    PACK_EVENT_TYPES = {
        "login_no_mfa", "privilege_escalation",
        "agent_scope_violation", "heartbeat", "page_visit",
    }

    #: Those that now have a real producer. Moved here in the SAME change that
    #: landed the producer -- that is the protocol, and this test enforces it
    #: from both sides.
    PACK_EVENT_TYPES_WITH_PRODUCERS = {
        # control-plane `_emit_login_no_mfa`, from the two code-login paths
        # (customer portal and MSP console) that issue a session with no
        # second factor. Deliberately NOT emitted for SSO: the IdP may have
        # performed MFA and this service cannot see that without parsing AMR,
        # so claiming a violation there would be worse than silence.
        "login_no_mfa",
        # endpoint agent `_privileged_audit`, when privileged_actions.execute()
        # rejects an op that is not in its allowlist -- a caller reaching past
        # what it is permitted to do. attempt/succeeded/failed stay
        # `privileged_action`; only the refusal is an escalation.
        "privilege_escalation",
    }

    #: A producer EXISTS IN CODE but cannot currently fire. Tracked apart from
    #: the live ones deliberately: "we wrote the emitter" and "the control
    #: works" are different claims, and folding the first into the second is
    #: precisely the overclaim this repo corrected for `resolves_on`.
    PACK_EVENT_TYPES_WITH_INERT_PRODUCERS = {
        # Python SDK, LangChain on_tool_start. Compares the tool against the
        # agent's server-issued allowlist -- which it cannot read, because no
        # route exposes agent-identity to an SDK caller and the service binds
        # to 127.0.0.1. The handler warns once that scope is unchecked and
        # emits nothing. Unblocking it is decision S2 in
        # docs/specs/sdk-policy-evaluation-integration.md.
        "agent_scope_violation",
    }

    def test_types_with_producers_really_are_emitted(self):
        """A producer claimed here must exist in product source."""
        emitted = _emitted_event_types()
        missing = self.PACK_EVENT_TYPES_WITH_PRODUCERS - emitted
        assert not missing, (
            f"{sorted(missing)} is listed as having a producer but no product "
            f"source emits it. Either the producer was removed or it was never "
            f"landed -- and a compliance control whose signal does not exist is "
            f"exactly what E4 is about."
        )

    def test_inert_producers_exist_in_source_but_are_tracked_apart(self):
        """An emitter that cannot fire must not be counted as a working one."""
        emitted = _emitted_event_types()
        missing = self.PACK_EVENT_TYPES_WITH_INERT_PRODUCERS - emitted
        assert not missing, (
            f"{sorted(missing)} is listed as having an inert producer but no "
            f"source emits it at all -- the emitter was removed, or was never "
            f"written."
        )
        overlap = (
            self.PACK_EVENT_TYPES_WITH_INERT_PRODUCERS
            & self.PACK_EVENT_TYPES_WITH_PRODUCERS
        )
        assert not overlap, (
            f"{sorted(overlap)} is listed as BOTH live and inert. When the "
            f"blocker clears, move it -- do not add it."
        )

    def test_the_rest_still_have_none(self):
        """The remaining two. This is the honest state of E4."""
        expected_missing = (
            self.PACK_EVENT_TYPES
            - self.PACK_EVENT_TYPES_WITH_PRODUCERS
            - self.PACK_EVENT_TYPES_WITH_INERT_PRODUCERS
        )
        emitted = _emitted_event_types()
        newly_emitted = expected_missing & emitted
        assert not newly_emitted, (
            f"{sorted(newly_emitted)} is now emitted. Move it into "
            f"PACK_EVENT_TYPES_WITH_PRODUCERS and classify it -- those pack "
            f"rules can finally enforce something."
        )

    def test_no_near_miss_for_the_ones_still_missing(self):
        """A similarly-named producer is a TRAP, not a solution.

        `not_equals` against a near-miss name is always true, which would move
        those rules from "cannot run" to "runs and always matches" -- the same
        shape as the route.destination outage.
        """
        emitted = _emitted_event_types()
        still_missing = (
            self.PACK_EVENT_TYPES
            - self.PACK_EVENT_TYPES_WITH_PRODUCERS
            - self.PACK_EVENT_TYPES_WITH_INERT_PRODUCERS
        )
        for pack_type in still_missing:
            near = {e for e in emitted if pack_type in e or e in pack_type}
            assert not near, (
                f"{sorted(near)} resembles the pack event type {pack_type!r} "
                f"but is not it. Reconcile the NAMES before wiring these rules "
                f"up, or they will run and always match."
            )


class TestAnticipatedEntriesAreNotEvidence:
    """The table classifies more types than the product emits, on purpose.

    Five entries name real product concepts but were found only in test
    fixtures, reason strings, or consumer-side matching lists. Keeping them
    costs nothing; CONFLATING them with observed emissions cost a false
    conclusion once already, so the two sets are kept separate and this test
    holds the line.
    """

    def test_anticipated_entries_are_genuinely_not_emitted(self):
        from cyberarmor_core.event_taxonomy import ANTICIPATED_NOT_OBSERVED
        emitted = _emitted_event_types()
        wrongly_listed = ANTICIPATED_NOT_OBSERVED & emitted
        assert not wrongly_listed, (
            f"{sorted(wrongly_listed)} IS emitted by product source but is "
            f"listed as anticipated-only. Move it out of "
            f"ANTICIPATED_NOT_OBSERVED -- the set is a claim about reality and "
            f"this one is now false."
        )

    def test_every_emitted_type_is_outside_the_anticipated_set(self):
        """The inverse: the observed set and the anticipated set must not
        overlap, in either direction."""
        from cyberarmor_core.event_taxonomy import ANTICIPATED_NOT_OBSERVED
        assert not (_emitted_event_types() & ANTICIPATED_NOT_OBSERVED)

    def test_anticipated_entries_are_still_classified(self):
        """They are unobserved, not unmapped -- classification still applies
        the moment something starts emitting them."""
        from cyberarmor_core.event_taxonomy import ANTICIPATED_NOT_OBSERVED
        for event_type in ANTICIPATED_NOT_OBSERVED:
            assert classify(event_type).category != UNKNOWN


if __name__ == "__main__":
    raise SystemExit(pytest.main([__file__, "-v"]))
