"""Rotating the signing key must not make old records unverifiable.

FOUND 2026-08-12, by reading scripts/security/rotate_audit_signing_key.py before
running it on production.

The scheme had two slots, ACTIVE and NEXT. Rotation promoted NEXT to ACTIVE and
minted a new NEXT. THE OUTGOING KEY WAS SIMPLY DROPPED -- there was no third
slot and nothing wrote it anywhere. Meanwhile _verify_signature_result skips any
candidate whose kid does not match the one in the signature::

    for candidate_kid, candidate_secret in candidate_keys:
        if kid != candidate_kid:
            continue

So after any rotation, every record signed with the previous key matched no
candidate and came back ``valid: false / SIGNATURE_MISMATCH``.

WHY THAT IS THE WORST POSSIBLE FAILURE HERE. It does not look like a
misconfiguration. It looks like MASS TAMPERING -- an entire audit trail
reporting that its records have been altered, in the artifact whose only purpose
is to be trustworthy after the fact, in front of an examiner at a
SEC/FINRA-regulated firm. And it would be triggered by the one operation
security guidance most encourages: rotating your keys.

It cost nothing when found, because production held exactly one throwaway
record. That was luck of timing, not design.

A LIST, NOT A SINGLE "PREVIOUS" SLOT. One slot survives exactly one rotation and
then resumes orphaning -- it moves the cliff rather than removing it.
AUDIT_RETENTION_DAYS defaults to 365, so several keys must stay verifiable at
once.

RETIRED KEYS ARE VERIFY-ONLY. A retired key can never sign again: _sign_event
reads AUDIT_SIGNING_KEY and only that. And a record verified by one is reported
as SIGNATURE_MATCH_RETIRED_KEY rather than SIGNATURE_MATCH, because rotation is
often a response to suspected compromise -- such a record is authentic-looking
without being trustworthy, and an investigator needs to be told which key so
they can ask why it was retired.
"""

from __future__ import annotations

import importlib
import os
import subprocess
import sys
import unittest
from pathlib import Path

_SVC = Path(__file__).resolve().parents[1]
_REPO = _SVC.parent.parent
sys.path.insert(0, str(_SVC))

import main as audit  # noqa: E402


def _reload_with(**env):
    """Re-import the audit module with a given signing-key environment.

    The keys are read at import time (main.py:31 onward), which is exactly why
    a rotation needs a container recreation and not just a file edit.
    """
    saved = {k: os.environ.get(k) for k in env}
    os.environ.update({k: v for k, v in env.items() if v is not None})
    for k, v in env.items():
        if v is None:
            os.environ.pop(k, None)
    try:
        # Dispose the engine the previous import built before replacing it.
        # main.py:116 creates one at module scope, so every reload would
        # otherwise leave a live connection pool behind against the shared
        # in-memory SQLite. Ten reloads, ten orphaned pools — and this suite
        # runs before others in a repo-wide run, where a pool-exhaustion test
        # already sits on a knife edge. Not observed to cause a failure; it is
        # this test's litter either way.
        old_engine = getattr(audit, "engine", None)
        if old_engine is not None:
            old_engine.dispose()
        return importlib.reload(audit)
    finally:
        for k, v in saved.items():
            if v is None:
                os.environ.pop(k, None)
            else:
                os.environ[k] = v


def _event(mod, event_id="evt_1"):
    return {
        "event_id": event_id, "trace_id": "tr", "span_id": "sp",
        "parent_span_id": None, "tenant_id": "t1", "agent_id": "ag",
        "agent_token_id": None, "human_initiator_id": None,
        "delegation_chain": [], "event_type": "ai_request", "provider": "openai",
        "model": "gpt-4", "framework": None, "action": None,
        "policy_decision": None, "data_classification": [], "outcome": "success",
        "latency_ms": 1, "cost_usd": 0.0,
        "timestamp": mod.datetime(2026, 8, 12, tzinfo=mod.timezone.utc),
        "prev_event_id": None, "prev_signature": None,
    }


class ARecordSurvivesARotation(unittest.TestCase):
    """The defect itself, end to end through the module's own config."""

    def test_a_record_signed_with_the_old_key_still_verifies_after_rotation(self):
        old = _reload_with(CYBERARMOR_AUDIT_SIGNING_KEY="old-key-value",
                           CYBERARMOR_AUDIT_SIGNING_KEY_ID="k1",
                           CYBERARMOR_AUDIT_RETIRED_KEYS="")
        ev = _event(old)
        sig = old._sign_event(ev)

        rotated = _reload_with(CYBERARMOR_AUDIT_SIGNING_KEY="new-key-value",
                               CYBERARMOR_AUDIT_SIGNING_KEY_ID="k2",
                               CYBERARMOR_AUDIT_RETIRED_KEYS="k1:old-key-value")
        result = rotated._verify_signature_result(ev, sig)
        self.assertTrue(
            result.valid,
            "a record signed before the rotation no longer verifies. Every "
            "record in the trail would report SIGNATURE_MISMATCH — "
            "indistinguishable from mass tampering.",
        )

    def test_it_is_reported_as_retired_not_as_a_normal_match(self):
        old = _reload_with(CYBERARMOR_AUDIT_SIGNING_KEY="old-key-value",
                           CYBERARMOR_AUDIT_SIGNING_KEY_ID="k1",
                           CYBERARMOR_AUDIT_RETIRED_KEYS="")
        ev = _event(old)
        sig = old._sign_event(ev)
        rotated = _reload_with(CYBERARMOR_AUDIT_SIGNING_KEY="new-key-value",
                               CYBERARMOR_AUDIT_SIGNING_KEY_ID="k2",
                               CYBERARMOR_AUDIT_RETIRED_KEYS="k1:old-key-value")
        result = rotated._verify_signature_result(ev, sig)
        self.assertEqual(result.reason, rotated._SIG_MATCH_RETIRED_KEY)
        self.assertEqual(
            result.key_id, "k1",
            "the verdict does not say WHICH retired key verified it, so an "
            "investigator cannot tell whether that rotation was routine or a "
            "response to compromise",
        )

    def test_a_record_signed_with_the_new_key_is_a_plain_match(self):
        rotated = _reload_with(CYBERARMOR_AUDIT_SIGNING_KEY="new-key-value",
                               CYBERARMOR_AUDIT_SIGNING_KEY_ID="k2",
                               CYBERARMOR_AUDIT_RETIRED_KEYS="k1:old-key-value")
        ev = _event(rotated)
        sig = rotated._sign_event(ev)
        result = rotated._verify_signature_result(ev, sig)
        self.assertEqual(result.reason, rotated._SIG_MATCH)
        self.assertEqual(result.key_id, "k2")

    def test_several_rotations_stay_verifiable(self):
        """A single PREVIOUS slot passes the first test and fails this one."""
        mods = {}
        sigs = {}
        for kid in ("k1", "k2", "k3"):
            m = _reload_with(CYBERARMOR_AUDIT_SIGNING_KEY=f"{kid}-value",
                             CYBERARMOR_AUDIT_SIGNING_KEY_ID=kid,
                             CYBERARMOR_AUDIT_RETIRED_KEYS="")
            ev = _event(m, event_id=f"evt_{kid}")
            sigs[kid] = (ev, m._sign_event(ev))
            mods[kid] = m

        current = _reload_with(
            CYBERARMOR_AUDIT_SIGNING_KEY="k4-value",
            CYBERARMOR_AUDIT_SIGNING_KEY_ID="k4",
            CYBERARMOR_AUDIT_RETIRED_KEYS="k1:k1-value,k2:k2-value,k3:k3-value")
        for kid, (ev, sig) in sigs.items():
            with self.subTest(signed_with=kid):
                self.assertTrue(
                    current._verify_signature_result(ev, sig).valid,
                    f"records signed under {kid} are orphaned after three "
                    f"rotations — a single PREVIOUS slot only moves the cliff",
                )


class RetiredKeysNeverSign(unittest.TestCase):

    def test_signing_uses_the_active_key_only(self):
        mod = _reload_with(CYBERARMOR_AUDIT_SIGNING_KEY="active-value",
                           CYBERARMOR_AUDIT_SIGNING_KEY_ID="k9",
                           CYBERARMOR_AUDIT_RETIRED_KEYS="k1:old-key-value")
        ev = _event(mod)
        self.assertTrue(
            mod._sign_event(ev).startswith("k9:"),
            "a new record was signed with something other than the active key",
        )


class MalformedRetiredEntriesAreNeverSilent(unittest.TestCase):
    """A retired key that fails to parse produces SIGNATURE_MISMATCH on real
    records — the same output as tampering. It may not be swallowed."""

    def test_an_entry_without_a_separator_is_reported(self):
        keys, problems = audit._parse_retired_keys("k1:good,garbage,k2:also-good")
        self.assertEqual([k for k, _ in keys], ["k1", "k2"])
        self.assertEqual(len(problems), 1, problems)
        self.assertIn("garbage" if "garbage" in problems[0] else "':'", problems[0])

    def test_a_duplicate_kid_is_reported_not_silently_shadowed(self):
        keys, problems = audit._parse_retired_keys("k1:first,k1:second")
        self.assertEqual(len(keys), 1)
        self.assertTrue(any("duplicate" in p for p in problems), problems)

    def test_an_empty_value_is_reported(self):
        _, problems = audit._parse_retired_keys("k1:")
        self.assertTrue(problems)

    def test_blank_and_whitespace_entries_are_not_problems(self):
        """Trailing commas are ordinary in hand-edited env files and must not
        be reported as a blind spot — crying wolf trains an operator to ignore
        the field that matters."""
        keys, problems = audit._parse_retired_keys(" k1:a , , k2:b ,")
        self.assertEqual([k for k, _ in keys], ["k1", "k2"])
        self.assertEqual(problems, [])

    def test_the_key_alphabet_cannot_collide_with_the_separators(self):
        """The parser is only safe because minted keys never contain ':' or
        ','. If the generator changes, this fails before the corruption does."""
        src = (_REPO / "scripts" / "security" / "rotate_audit_signing_key.py").read_text()
        self.assertIn(
            "token_urlsafe", src,
            "the rotation script no longer mints keys with token_urlsafe, whose "
            "alphabet is [A-Za-z0-9_-]. If the new generator can emit ':' or "
            "',', CYBERARMOR_AUDIT_RETIRED_KEYS parses back wrong and orphans "
            "records silently.",
        )


class TheRotationScriptRetiresTheOutgoingKey(unittest.TestCase):
    """The script had no test at all, while being the thing that orphaned the
    trail. Driven as a subprocess, against a real temp env file."""

    SCRIPT = _REPO / "scripts" / "security" / "rotate_audit_signing_key.py"

    def _rotate(self, env_text: str) -> dict:
        import tempfile
        with tempfile.TemporaryDirectory() as d:
            p = Path(d) / "audit.env"
            p.write_text(env_text, encoding="utf-8")
            r = subprocess.run([sys.executable, str(self.SCRIPT), "--env-file", str(p)],
                               capture_output=True, text=True)
            self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
            out = {}
            for line in p.read_text(encoding="utf-8").splitlines():
                if "=" in line:
                    k, v = line.split("=", 1)
                    out[k] = v
            return out

    def test_the_outgoing_key_lands_in_the_retired_list(self):
        after = self._rotate(
            "CYBERARMOR_AUDIT_SIGNING_KEY=outgoing-secret\n"
            "CYBERARMOR_AUDIT_SIGNING_KEY_ID=k1\n"
        )
        self.assertIn(
            "k1:outgoing-secret", after.get("CYBERARMOR_AUDIT_RETIRED_KEYS", ""),
            "the outgoing key was dropped, so every record it signed is now "
            "unverifiable — this is the original defect",
        )

    def test_the_active_key_actually_changes(self):
        after = self._rotate(
            "CYBERARMOR_AUDIT_SIGNING_KEY=outgoing-secret\n"
            "CYBERARMOR_AUDIT_SIGNING_KEY_ID=k1\n"
        )
        self.assertNotEqual(after["CYBERARMOR_AUDIT_SIGNING_KEY"], "outgoing-secret")

    def test_rotating_twice_keeps_both_old_keys(self):
        first = self._rotate(
            "CYBERARMOR_AUDIT_SIGNING_KEY=first-secret\n"
            "CYBERARMOR_AUDIT_SIGNING_KEY_ID=k1\n"
        )
        text = "\n".join(f"{k}={v}" for k, v in first.items())
        second = self._rotate(text)
        retired = second.get("CYBERARMOR_AUDIT_RETIRED_KEYS", "")
        self.assertIn("k1:first-secret", retired,
                      f"the first key was lost on the second rotation: {retired}")
        self.assertIn(first["CYBERARMOR_AUDIT_SIGNING_KEY_ID"] + ":", retired,
                      f"the second key was not retired: {retired}")

    def test_it_refuses_when_the_outgoing_key_would_corrupt_the_list(self):
        """The active key predates this script on real deployments — it
        defaulted to a hand-set AUDIT_API_SECRET, which may contain anything."""
        import tempfile
        with tempfile.TemporaryDirectory() as d:
            p = Path(d) / "audit.env"
            p.write_text("CYBERARMOR_AUDIT_SIGNING_KEY=has:colon,and-comma\n"
                         "CYBERARMOR_AUDIT_SIGNING_KEY_ID=k1\n", encoding="utf-8")
            before = p.read_text(encoding="utf-8")
            r = subprocess.run([sys.executable, str(self.SCRIPT), "--env-file", str(p)],
                               capture_output=True, text=True)
            self.assertNotEqual(r.returncode, 0, "it rotated anyway: " + r.stdout)
            self.assertIn("ROTATION_ABORTED", r.stdout)
            self.assertEqual(p.read_text(encoding="utf-8"), before,
                             "the file was modified despite aborting")


def tearDownModule():
    """Leave the module as the rest of the suite expects to find it."""
    importlib.reload(audit)


if __name__ == "__main__":
    unittest.main()
