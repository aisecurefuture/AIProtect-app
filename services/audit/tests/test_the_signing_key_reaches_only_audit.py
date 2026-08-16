"""The audit signing key must reach the audit service and nothing else.

MEASURED ON PRODUCTION 2026-08-12, in this order:

  1. CYBERARMOR_AUDIT_SIGNING_KEY was UNSET, so services/audit/main.py fell back
     to AUDIT_API_SECRET -- the shared inter-service auth credential. Every
     service that could WRITE an audit event held the key that "proved" one
     authentic. HMAC is symmetric, so that is not tamper-evidence against any
     component of this system; it is only tamper-evidence against an outsider.

  2. Rotating gave audit its own key. But scripts/security/rotate_audit_signing_key.py
     writes to the env file it is pointed at, and on that box the file is
     /etc/cyberarmor/demo.env -- the file 19 SERVICES SHARE. The key went
     straight back in front of all of them.

  3. Checked immediately afterwards, the policy container reported::

         policy service has the audit signing key: False

     That looked like isolation. It was not. Containers receive their
     environment at CREATION time, and that container predated the rotation. The
     next routine rebuild would have flipped it to True, silently.

Point 3 is the reason this file exists. A security property that expires on the
next deploy is worse than one you never had: a check run today returns a
reassuring answer, and nothing announces the moment it stops being true. The
compose wiring is the durable statement, so the compose wiring is what is
pinned here -- not a runtime probe, which can only ever describe one moment.

WHAT THIS DOES AND DOES NOT ESTABLISH. It proves the key is not DISTRIBUTED to
other services. It does not make the audit service the sole party able to sign:
HMAC is symmetric, so anyone who reads the file can forge a record, and the
founder holds a copy in a password manager as the only backup. Real
non-repudiation needs the asymmetric migration (hybrid Ed25519 + ML-DSA-87),
where the private half never leaves this service and verification needs only the
public half. Until then the honest claim is "attributable to whoever holds the
audit key", not "attributable to the audit service".
"""

from __future__ import annotations

import unittest
from pathlib import Path

import yaml

REPO = Path(__file__).resolve().parents[3]
COMPOSE = REPO / "infra" / "docker-compose.yml"

#: The variable that selects the audit-only env file.
AUDIT_ENV_VAR = "CYBERARMOR_AUDIT_ENV_FILE"

#: The variable that selects the env file every service shares.
SHARED_ENV_VAR = "CYBERARMOR_ENV_FILE"


def _entries(service: dict) -> list:
    """env_file normalised to a list of path strings.

    Compose accepts three shapes: a bare string, a list of strings, and a list
    of {path, required} mappings. All three appear in the wild and a test that
    understands only one silently passes on the others.
    """
    raw = service.get("env_file")
    if raw is None:
        return []
    if isinstance(raw, str):
        return [raw]
    out = []
    for item in raw:
        if isinstance(item, str):
            out.append(item)
        elif isinstance(item, dict) and "path" in item:
            out.append(str(item["path"]))
    return out


class TheAuditEnvFileIsAuditOnly(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        cls.compose = yaml.safe_load(COMPOSE.read_text(encoding="utf-8"))
        cls.services = cls.compose.get("services") or {}

    def test_the_compose_file_parses_and_has_an_audit_service(self):
        """Guards every assertion below: if the service is renamed or the file
        restructured, the rest of this class would pass against nothing."""
        self.assertIn("audit", self.services,
                      "no 'audit' service in the compose file; this test is stale")

    def test_exactly_one_service_reads_the_audit_env_file(self):
        readers = sorted(
            name for name, svc in self.services.items()
            if isinstance(svc, dict)
            and any(AUDIT_ENV_VAR in e for e in _entries(svc))
        )
        self.assertEqual(
            readers, ["audit"],
            f"{readers} read the audit-only env file. The audit signing key "
            f"must reach exactly one service — any other holder can forge a "
            f"record that verifies, because HMAC is symmetric.",
        )

    def test_the_audit_service_actually_reads_it(self):
        entries = _entries(self.services["audit"])
        self.assertTrue(
            any(AUDIT_ENV_VAR in e for e in entries),
            f"the audit service does not reference {AUDIT_ENV_VAR}; its env "
            f"files are {entries}. Without it the service falls back to the "
            f"shared secret, which is the defect this split removed.",
        )

    def test_the_audit_service_still_reads_the_shared_env_file(self):
        """It needs DATABASE_URL, REDIS_URL, AUDIT_API_SECRET and the TLS
        settings from there. Splitting the signing key out must not orphan the
        service from everything else."""
        entries = _entries(self.services["audit"])
        self.assertTrue(
            any(SHARED_ENV_VAR in e for e in entries),
            f"the audit service no longer reads the shared env file; its env "
            f"files are {entries}. It will start without a database URL.",
        )

    def test_the_audit_env_file_is_optional(self):
        """required: false, so local dev and CI — where the file does not exist
        — still run. A hard requirement here would break every developer
        machine to protect a production secret, and the real backstop is
        CYBERARMOR_ENFORCE_SECURE_SECRETS in services/audit/main.py."""
        raw = self.services["audit"].get("env_file")
        self.assertIsInstance(
            raw, list,
            "audit env_file must be the long list form so 'required' can be set",
        )
        audit_entry = next(
            (e for e in raw if isinstance(e, dict) and AUDIT_ENV_VAR in str(e.get("path", ""))),
            None,
        )
        self.assertIsNotNone(
            audit_entry,
            f"the {AUDIT_ENV_VAR} entry is not in the long {{path, required}} "
            f"form, so it is implicitly required and will break any environment "
            f"without the file",
        )
        self.assertIs(
            audit_entry.get("required"), False,
            f"the audit env file entry is required={audit_entry.get('required')!r}; "
            f"it must be False or compose refuses to start wherever the file is "
            f"absent, which is every dev machine and CI",
        )


class TheSharedEnvFileIsStillSharedByMany(unittest.TestCase):
    """Context for the assertions above, and a canary.

    The reason the key could not stay in the shared file is that so many
    services read it. If that number collapses, the threat model changed and
    whoever changed it should revisit this split rather than inherit it.
    """

    @classmethod
    def setUpClass(cls):
        cls.services = (yaml.safe_load(COMPOSE.read_text(encoding="utf-8"))
                        .get("services") or {})

    def test_more_than_one_service_shares_the_main_env_file(self):
        """RE-DERIVED FOR THIS REPOSITORY, 2026-08-16.

        The inherited version asserted >= 10 sharers, because in CyberArmor.ai
        ~19 services read the shared env file and that is what made keeping the
        signing key in it untenable. AIProtect runs three. The test said, in
        its own docstring, that a collapse in that number means the threat
        model changed and whoever changed it should re-derive rather than
        inherit -- so this is the re-derivation.

        The split still holds, and the reason has nothing to do with 19. HMAC
        is symmetric: any service holding the signing key can forge a record
        that verifies against it. With three services, two of them holding the
        key is still two forgers, and the audit log is the one artifact whose
        whole value is that it cannot be quietly rewritten. The threshold that
        matters is therefore not "many" -- it is "more than the one service
        that needs it".

        Kept as a canary rather than deleted: if the shared file ever drops to
        a single reader, the shared/private distinction has stopped meaning
        anything and this split should be reconsidered on purpose.
        """
        sharers = [
            name for name, svc in self.services.items()
            if isinstance(svc, dict)
            and any(SHARED_ENV_VAR in e for e in _entries(svc))
        ]
        self.assertGreater(
            len(sharers), 1,
            f"only {len(sharers)} service(s) read the main env file "
            f"({sorted(sharers)}). If nothing shares it, 'shared' and "
            f"'audit-only' describe the same blast radius and this split "
            f"should be re-derived rather than inherited a second time.",
        )


if __name__ == "__main__":
    unittest.main()
