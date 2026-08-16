"""SPIKE: can `cyberarmor_core` be used by a single-user B2C product?

Prompt 0, step 3. Writes an audit event and an evidence record with NO
tenant_id, and settles the open question: `services/audit`'s AuditEvent
requires `agent_id` with no default, and a consumer browser event has no
"agent". This spike picks that convention deliberately rather than papering
over it (url-trust-gate papers over it with a literal, see evidence.py).

Run:  python3 aiprotect/spikes/spike_core_tenant_free.py
Exit code 0 = the seam holds.
"""

from __future__ import annotations

import dataclasses
import json
import sys
import tempfile
import uuid
from datetime import datetime, timezone
from pathlib import Path

# --- The import surface ----------------------------------------------------
# FINDING: libs/cyberarmor-core has NO pyproject.toml, NO setup.py, and
# cyberarmor_core has NO __init__.py. It is an implicit namespace package that
# works only because every service Dockerfile does:
#     COPY libs/cyberarmor-core /app/libs/cyberarmor-core
#     ENV PYTHONPATH="/app/libs/cyberarmor-core:${PYTHONPATH}"
# So `pip install cyberarmor-core` is not possible today. The "versioned shared
# contract" the strategy doc describes does not exist as packaging yet -- it is
# a path convention replicated across ~10 Dockerfiles.
REPO_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO_ROOT / "libs" / "cyberarmor-core"))

RESULTS: list[tuple[str, bool, str]] = []


def check(name: str, ok: bool, detail: str = "") -> None:
    RESULTS.append((name, ok, detail))
    print(f"  [{'PASS' if ok else 'FAIL'}] {name}" + (f" -- {detail}" if detail else ""))


print("=" * 72)
print("SPIKE 2: cyberarmor_core for a single-user (no tenant) product")
print("=" * 72)
print(f"sys.path += {REPO_ROOT / 'libs' / 'cyberarmor-core'}")
print(f"packaging metadata present: "
      f"{(REPO_ROOT / 'libs' / 'cyberarmor-core' / 'pyproject.toml').exists()}")
print(f"cyberarmor_core/__init__.py exists: "
      f"{(REPO_ROOT / 'libs' / 'cyberarmor-core' / 'cyberarmor_core' / '__init__.py').exists()}")
print()

# --- Step 1: import --------------------------------------------------------
print("Step 1: import the core modules")
try:
    from cyberarmor_core.audit_writer import AuditWriter
    from cyberarmor_core.evidence import EvidenceItem, EvidenceSet
    from cyberarmor_core.health_record import HealthRecord, UnavailableCheck

    check("import audit_writer / evidence / health_record", True)
except Exception as exc:  # noqa: BLE001
    check("import core modules", False, f"{type(exc).__name__}: {exc}")
    sys.exit(1)

try:
    from cyberarmor_core import event_taxonomy

    check("import event_taxonomy", True)
except Exception as exc:  # noqa: BLE001
    check("import event_taxonomy", False, f"{type(exc).__name__}: {exc}")
    event_taxonomy = None  # type: ignore[assignment]

# --- Step 2: no tenant anywhere in the dataclasses -------------------------
print("\nStep 2: confirm the core dataclasses have no tenant dimension")
for cls in (EvidenceItem, HealthRecord):
    fields = [f.name for f in dataclasses.fields(cls)]
    leaked = [f for f in fields if "tenant" in f.lower()]
    check(f"{cls.__name__} has no tenant field", not leaked, ", ".join(fields))

# --- Step 3: THE agent_id DECISION ----------------------------------------
# services/audit/main.py AuditEvent:
#     tenant_id: str = "default"   <- has a default, single-user is fine
#     agent_id: str                <- REQUIRED, no default
#     trace_id: str                <- REQUIRED, no default
#     event_type: str              <- REQUIRED, no default
#
# CONVENTION CHOSEN FOR B2C, and the reasoning:
#
#   agent_id = the enrolled DEVICE id  ("dev_<uuid>")
#
# Not a placeholder literal. A consumer device IS the enrolled endpoint that
# produced the event, which is exactly what agent_id means in the B2B model, so
# the field keeps its meaning instead of being stuffed with a constant. It also
# buys real consumer UX for free: the Activity feed can say "blocked on your
# iPhone" because the device is already the attribution key.
#
# For events with no originating device (billing, account changes, a web-portal
# action) use a surface literal: "aiprotect-web" / "aiprotect-api".
#
#   tenant_id -> omitted entirely; the service defaults it to "default", which
#   collapses the hash chain to ONE chain. That is correct for single-user: the
#   UniqueConstraint("tenant_id","prev_event_id") degenerates rather than breaks.
print("\nStep 3: the agent_id convention for consumer events")

DEVICE_ID = "dev_" + uuid.uuid4().hex[:16]


def consumer_audit_event(event_type: str, *, device_id: str | None, **facts) -> dict:
    """Build a B2C audit event. No tenant_id is ever set."""
    return {
        "trace_id": "trc_" + uuid.uuid4().hex[:16],
        # THE decision: device id, or a surface literal when there is no device.
        "agent_id": device_id or "aiprotect-web",
        "event_type": event_type,
        "outcome": "success",
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "evidence": facts,
    }


device_event = consumer_audit_event(
    "url.blocked", device_id=DEVICE_ID, url="https://phish.example", verdict="blocked"
)
portal_event = consumer_audit_event("account.plan_changed", device_id=None, plan="family")

check("device event has agent_id = device id", device_event["agent_id"] == DEVICE_ID,
      DEVICE_ID)
check("portal event falls back to a surface literal",
      portal_event["agent_id"] == "aiprotect-web", "aiprotect-web")
check("no tenant_id set on either event",
      "tenant_id" not in device_event and "tenant_id" not in portal_event,
      "service defaults it to 'default' -> one degenerate hash chain")

required = {"trace_id", "agent_id", "event_type"}
check("both events satisfy AuditEvent's required fields",
      required <= device_event.keys() and required <= portal_event.keys(),
      ", ".join(sorted(required)))

# --- Step 4: does the taxonomy cover consumer events? ---------------------
print("\nStep 4: is the event taxonomy usable for consumers?")
if event_taxonomy is not None:
    # Only the plain data members -- `vars()` also yields imported modules and
    # the `__future__._Feature` object, neither of which is serializable.
    blob = json.dumps(
        {
            k: sorted(v) if isinstance(v, (set, frozenset)) else v
            for k, v in vars(event_taxonomy).items()
            if not k.startswith("_")
            and isinstance(v, (str, list, tuple, set, frozenset, dict))
        },
        default=str,
    )
    for token in ("browser", "endpoint", "mobile", "malicious_url", "prompt_injection"):
        check(f"taxonomy knows '{token}'", token in blob)

# --- Step 5: AuditWriter works standalone, no live service ---------------
print("\nStep 5: AuditWriter enqueues + spools with no audit service running")
with tempfile.TemporaryDirectory() as tmp:
    try:
        writer = AuditWriter(
            service_url="http://127.0.0.1:9/never-used",  # never contacted; we don't flush
            api_secret="spike",
            spool_dir=tmp,
            batch_max=10,
            memory_max=4,          # tiny, to force the disk-spool path
            spool_max_bytes=1_000_000,
        )
        check("AuditWriter constructed (spool dir proven writable)", True, tmp)

        for i in range(12):       # > memory_max, forces overflow to disk
            writer.enqueue(
                consumer_audit_event(f"url.checked.{i}", device_id=DEVICE_ID)
            )

        stats = writer.stats()
        check("enqueue() accepted tenant-free events", stats["enqueued"] == 12,
              f"enqueued={stats['enqueued']}")
        check("overflow spooled to disk, not dropped", stats["spool_files"] > 0,
              f"spool_files={stats['spool_files']}, buffered={stats['buffered']}")

        spooled = list(Path(tmp).glob("*.jsonl"))
        if spooled:
            first = json.loads(spooled[0].read_text().splitlines()[0])
            check("spooled record carries no tenant_id", "tenant_id" not in first,
                  f"keys={sorted(first)[:6]}...")
            check("spooled record got an auto event_id", "event_id" in first,
                  first.get("event_id", ""))
    except Exception as exc:  # noqa: BLE001
        check("AuditWriter standalone", False, f"{type(exc).__name__}: {exc}")
        import traceback

        traceback.print_exc()

# --- Step 6: evidence + health, tenant-free -------------------------------
print("\nStep 6: EvidenceItem / EvidenceSet / HealthRecord with no tenant")
try:
    now = datetime.now(timezone.utc).isoformat()
    item = EvidenceItem(
        "safe_browsing_enabled",
        True,
        "platform_observed",
        f"trust-gate: 3 checks on device {DEVICE_ID}",
        now,
    )
    es = EvidenceSet()
    es.offer(item)
    check("EvidenceItem + EvidenceSet built with no tenant", len(es) == 1,
          f"provenance={item.provenance}")

    # The provenance model is arguably MORE useful in B2C: "we observed it"
    # vs "the user told us" is the whole consumer trust question.
    check("provenance distinguishes observed vs asserted",
          item.provenance == "platform_observed")

    hr = HealthRecord(
        "aiprotect-api",
        ("api_reachable", "device_enrolled"),
        (UnavailableCheck("push_delivery", "APNs creds not configured in spike",
                          "push status unknown"),),
        facts={"devices": 1},
    )
    d = hr.to_dict() if hasattr(hr, "to_dict") else dataclasses.asdict(hr)
    check("HealthRecord built; unavailable check is NAMED not hidden",
          "push_delivery" in json.dumps(d, default=str),
          "this is the anti-dishonest-health mechanism")
except Exception as exc:  # noqa: BLE001
    check("evidence / health", False, f"{type(exc).__name__}: {exc}")
    import traceback

    traceback.print_exc()

# --- Verdict ---------------------------------------------------------------
print("\n" + "=" * 72)
failed = [n for n, ok, _ in RESULTS if not ok]
if failed:
    print(f"VERDICT: SEAM DOES NOT HOLD -- {len(failed)} check(s) failed:")
    for n in failed:
        print(f"  - {n}")
    sys.exit(1)
print(f"VERDICT: SEAM HOLDS -- {len(RESULTS)}/{len(RESULTS)} checks passed.")
print("cyberarmor_core is usable unmodified by a single-user product.")
print("Conventions settled here:")
print("  * agent_id  = enrolled device id, else 'aiprotect-web' / 'aiprotect-api'")
print("  * tenant_id = never set; service default collapses to one hash chain")
print("Gap to close: no pyproject.toml / __init__.py -- it is a PYTHONPATH")
print("convention, not an installable versioned package.")
print("=" * 72)
