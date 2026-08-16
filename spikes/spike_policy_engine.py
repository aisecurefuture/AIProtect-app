"""SPIKE: can `policy_engine` be imported and used as a LIBRARY?

Prompt 0, step 2. Nothing in this repo imports the policy engine as a library --
every call site goes through `services/policy/main.py` (FastAPI + SQLAlchemy +
tenant CRUD). The B2C product wants the engine WITHOUT any of that: three
hardcoded consumer presets (Standard / Strict / Kids) evaluated in-process.

This spike proves or disproves that. It uses:
  * no FastAPI, no SQLAlchemy, no database, no HTTP
  * no tenant_id anywhere in the context
  * a preset expressed as a plain List[dict], the shape `evaluate()` takes

Run:  python3 aiprotect/spikes/spike_policy_engine.py
Exit code 0 = the seam holds. Non-zero = it does not.
"""

from __future__ import annotations

import os
import sys
import traceback
from pathlib import Path

# --- The import surface ----------------------------------------------------
# policy_engine.py uses FLAT local imports (`import opa_client`,
# `from conditions_guard import ...`, `from policy_fields import ...`), not
# package-relative ones. So the directory itself must be on sys.path; you
# cannot `from services.policy import policy_engine`. This is finding #1.
REPO_ROOT = Path(__file__).resolve().parents[1]
POLICY_DIR = REPO_ROOT / "libs" / "policy-engine"
sys.path.insert(0, str(POLICY_DIR))

# OPA is a sidecar the consumer product will not run. The engine defaults
# OPA_ENABLED=true, so a library caller MUST turn it off explicitly or every
# evaluate() pays a urllib timeout against http://opa:8181 before falling back.
# This is finding #2.
os.environ["OPA_ENABLED"] = "false"

RESULTS: list[tuple[str, bool, str]] = []


def check(name: str, ok: bool, detail: str = "") -> None:
    RESULTS.append((name, ok, detail))
    print(f"  [{'PASS' if ok else 'FAIL'}] {name}" + (f" -- {detail}" if detail else ""))


print("=" * 72)
print("SPIKE 1: policy_engine as a library (no FastAPI / no DB / no tenant)")
print("=" * 72)
print(f"repo root : {REPO_ROOT}")
print(f"sys.path += {POLICY_DIR}")
print(f"OPA_ENABLED = {os.environ['OPA_ENABLED']}")
print()

# --- Step 1: does it even import? ------------------------------------------
print("Step 1: import")
try:
    from policy_engine import EvaluationContext, PolicyEngine, PolicyEvalResult

    check("import policy_engine", True, "EvaluationContext, PolicyEngine")
except Exception as exc:  # noqa: BLE001 - the whole point is to see what breaks
    check("import policy_engine", False, f"{type(exc).__name__}: {exc}")
    traceback.print_exc()
    sys.exit(1)

try:
    import conditions_guard  # noqa: F401

    check("import conditions_guard", True)
except Exception as exc:  # noqa: BLE001
    check("import conditions_guard", False, f"{type(exc).__name__}: {exc}")

# policy_fields loads shared/policy-fields.json off disk at import time.
try:
    import policy_fields  # noqa: F401

    check("import policy_fields (reads shared/policy-fields.json)", True)
except Exception as exc:  # noqa: BLE001
    check("import policy_fields", False, f"{type(exc).__name__}: {exc}")

# --- Step 2: the consumer preset -------------------------------------------
# A preset is just a List[dict] sorted by priority. No DB, no tenant.
# Lower `priority` number = evaluated first (matches the B2B convention).
print("\nStep 2: build the 'Standard' consumer preset as a plain List[dict]")

STANDARD_PRESET: list[dict] = [
    {
        "id": "consumer-std-001",
        "name": "Block secrets going to any AI service",
        "enabled": True,
        "priority": 10,
        "action": "block",
        "conditions": {
            "operator": "AND",
            "rules": [
                {"field": "content.has_secrets", "operator": "equals", "value": True},
            ],
        },
    },
    {
        "id": "consumer-std-002",
        "name": "Warn before sending personal info to an AI chatbot",
        "enabled": True,
        "priority": 20,
        "action": "warn",
        "conditions": {
            "operator": "AND",
            "rules": [
                {"field": "content.has_pii", "operator": "equals", "value": True},
                {
                    "field": "request.domain",
                    "operator": "in",
                    "value": ["openai.com", "anthropic.com", "gemini.google.com"],
                },
            ],
        },
    },
    {
        "id": "consumer-std-003",
        "name": "Monitor everything else",
        "enabled": True,
        "priority": 100,
        "action": "monitor",
        # Explicit match-all. conditions_guard requires you to SAY match-all
        # rather than expressing it as an empty rule list.
        "conditions": {
            "operator": "AND",
            "rules": [{"field": "*", "operator": "matches", "value": "*"}],
        },
    },
]
check("preset is a plain List[dict]", isinstance(STANDARD_PRESET, list),
      f"{len(STANDARD_PRESET)} rules, no tenant_id key on any of them")

# --- Step 3: build a context with NO tenant --------------------------------
print("\nStep 3: build EvaluationContext with no tenant field")
try:
    ctx = EvaluationContext(
        request={
            "url": "https://chat.openai.com/backend-api/conversation",
            "host": "chat.openai.com",
            "hostname": "chat.openai.com",
            "domain": "openai.com",
            "path": "/backend-api/conversation",
            "method": "POST",
        },
        content={
            "has_pii": True,
            "has_secrets": False,
            "classification": "personal",
        },
        user={},        # consumer: no department/role/org
        endpoint={"surface": "browser"},
        metadata={},
    )
    has_tenant = hasattr(ctx, "tenant_id") or "tenant" in getattr(ctx, "metadata", {})
    check("EvaluationContext built without tenant", not has_tenant,
          "dataclass has no tenant_id field at all")
except Exception as exc:  # noqa: BLE001
    check("build EvaluationContext", False, f"{type(exc).__name__}: {exc}")
    traceback.print_exc()
    sys.exit(1)

# --- Step 4: evaluate ------------------------------------------------------
print("\nStep 4: evaluate the preset (the actual seam)")
try:
    engine = PolicyEngine()
    problems: list[dict] = []
    results = engine.evaluate(STANDARD_PRESET, ctx, problems)
    check("PolicyEngine().evaluate() ran", True, f"{len(results)} result(s)")
except Exception as exc:  # noqa: BLE001
    check("PolicyEngine().evaluate() ran", False, f"{type(exc).__name__}: {exc}")
    traceback.print_exc()
    sys.exit(1)

matched = [r for r in results if getattr(r, "matched", False)]
print(f"\n  problems reported: {problems if problems else 'none'}")
print("  results:")
for r in results:
    print(f"    - {r.policy_id:<18} matched={str(r.matched):<5} "
          f"action={r.action:<8} reason={r.reason!r}")

# The PII-into-openai.com rule SHOULD fire; the secrets rule should NOT.
ids_matched = {r.policy_id for r in matched}
check("std-002 (PII -> AI chatbot) matched", "consumer-std-002" in ids_matched)
check("std-001 (secrets) did NOT match", "consumer-std-001" not in ids_matched,
      "has_secrets was False")

# --- Step 5: first-match, the shape a consumer enforcement point wants ------
print("\nStep 5: evaluate_first_match (what a client actually calls)")
try:
    first = engine.evaluate_first_match(STANDARD_PRESET, ctx, problems)
    ok = first is not None
    check("evaluate_first_match() ran", ok,
          f"-> {first.policy_id} / action={first.action}" if ok else "returned None")
except Exception as exc:  # noqa: BLE001
    check("evaluate_first_match() ran", False, f"{type(exc).__name__}: {exc}")

# --- Step 6: does the engine leak tenant into the result? ------------------
print("\nStep 6: confirm no tenant leaks into results")
leaked = [f for f in PolicyEvalResult.__dataclass_fields__ if "tenant" in f.lower()]
check("PolicyEvalResult has no tenant field", not leaked, str(leaked) if leaked else "")

# --- Step 7: THE HAZARD -- fields are not validated ------------------------
# The engine resolves `content.foo` by looking up "foo" in whatever dict the
# caller passed. It does NOT check the field against shared/policy-fields.json
# (that registry drives the policy-builder UI's suggestions, not enforcement).
#
# Consequence, and it is the important output of this spike: a TYPO in a
# consumer preset does not raise, does not warn, and does not appear in
# `problems`. It silently never matches. On a "block" rule that is a silent
# hole in protection -- a rule that looks configured and never fires.
#
# This is the [dishonest health] defect class in a new costume, so the B2C
# presets need a companion test asserting every rule fires on a known-positive
# fixture. The check below is the seed of that test.
print("\nStep 7: HAZARD CHECK -- unvalidated field names")

typo_rule = {
    "id": "typo-demo",
    "name": "Block secrets (with a typo in the field name)",
    "enabled": True,
    "priority": 10,
    "action": "block",
    "conditions": {
        "operator": "AND",
        # `has_secrets` misspelled. A human reviewer would not catch this.
        "rules": [{"field": "content.has_secretz", "operator": "equals", "value": True}],
    },
}
typo_ctx = EvaluationContext(
    request={"domain": "openai.com"}, content={"has_secrets": True}
)
typo_problems: list[dict] = []
typo_results = engine.evaluate([typo_rule], typo_ctx, typo_problems)
typo_matched = any(r.matched for r in typo_results)

print(f"  a 'block' rule with a typo'd field: matched={typo_matched}, "
      f"problems={typo_problems if typo_problems else 'none'}")
check(
    "typo'd block rule silently fails to fire (documents the hazard)",
    (not typo_matched) and (not typo_problems),
    "engine does NOT validate fields -> B2C presets REQUIRE known-positive tests",
)

# The flip side is genuinely useful: because resolution is dynamic, the consumer
# product can define its OWN field vocabulary without touching the B2B registry.
consumer_vocab_rule = {
    "id": "vocab-demo",
    "name": "Consumer-only field the B2B registry has never heard of",
    "enabled": True,
    "priority": 10,
    "action": "warn",
    "conditions": {
        "operator": "AND",
        "rules": [{"field": "content.kid_unsafe", "operator": "equals", "value": True}],
    },
}
vocab_ctx = EvaluationContext(request={}, content={"kid_unsafe": True})
vocab_matched = any(r.matched for r in engine.evaluate([consumer_vocab_rule], vocab_ctx))
check("consumer-defined field resolves without registry changes", vocab_matched,
      "'content.kid_unsafe' is not in shared/policy-fields.json -- Kids preset is free")

# --- Verdict ---------------------------------------------------------------
print("\n" + "=" * 72)
failed = [n for n, ok, _ in RESULTS if not ok]
if failed:
    print(f"VERDICT: SEAM DOES NOT HOLD -- {len(failed)} check(s) failed:")
    for n in failed:
        print(f"  - {n}")
    sys.exit(1)
print(f"VERDICT: SEAM HOLDS -- {len(RESULTS)}/{len(RESULTS)} checks passed.")
print("policy_engine is usable as a library with two required accommodations:")
print("  1. libs/policy-engine must be on sys.path (flat imports, not a package)")
print("  2. OPA_ENABLED must be set false explicitly, or every call pays a timeout")
print("=" * 72)
