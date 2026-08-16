# Seam proofs (Prompt 0)

Two spikes that prove — or would have disproven — the architecture in
`docs/aiprotect/STRATEGY-AND-PROMPTS.md`. Both are standalone: no FastAPI, no
database, no running services, no network.

```bash
python3 aiprotect/spikes/spike_policy_engine.py     # 12/12 PASS
python3 aiprotect/spikes/spike_core_tenant_free.py  # 21/21 PASS
```

Exit code 0 = seam holds. Keep these runnable; they are the regression test for
the boundary the whole B2C plan rests on.

## Result: both seams hold

### `spike_policy_engine.py` — policy engine as a library

Nothing in this repo imported `policy_engine.py` as a library before this; every
call site went through `services/policy/main.py` (FastAPI + SQLAlchemy + tenant
CRUD, 2,733 lines). The spike evaluates a three-rule "Standard" consumer preset
against a tenant-free `EvaluationContext` and gets correct actions back.

**Two required accommodations:**

1. **`services/policy/` must be on `sys.path`.** `policy_engine.py` uses flat
   local imports — `import opa_client`, `from conditions_guard import ...`,
   `from policy_fields import ...` — so `from services.policy import
   policy_engine` does not work. The full import surface is `opa_client`,
   `conditions_guard`, `policy_fields`. All are stdlib-only (`opa_client` uses
   `urllib`, not `httpx`), so nothing heavy comes along.
2. **`OPA_ENABLED=false` must be set explicitly.** It defaults to `true`, and
   B2C runs no OPA sidecar, so every evaluation would pay a urllib timeout
   against `http://opa:8181` before falling back to the Python engine.

`policy_fields.py` reads `shared/policy-fields.json` off disk at import time,
resolving it via `_HERE.parents[2]` — the repo root. Any consumer container must
`COPY shared/policy-fields.json` or the import fails.

### `spike_core_tenant_free.py` — cyberarmor-core for a single user

`EvidenceItem` and `HealthRecord` have no tenant field. `AuditWriter.enqueue()`
accepts tenant-free events, and overflow spools to disk rather than dropping.
The event taxonomy already knows `browser`, `endpoint`, `mobile`,
`malicious_url`, and `prompt_injection`. Usable **unmodified**.

**Conventions settled here** (see `aiprotect/README.md` for the reasoning):
`agent_id` = enrolled device id, else `aiprotect-web` / `aiprotect-api`;
`tenant_id` never set.

## The hazard this surfaced — read before authoring any preset

**The policy engine does not validate field names.** It resolves `content.foo`
by looking up `"foo"` in whatever dict the caller passed. It does *not* check
against `shared/policy-fields.json` — that registry drives the policy-builder
UI's suggestions, not enforcement. Demonstrated in the spike:

- `content.has_secrets` works fine and is **not** in the registry.
- A completely invented `content.totally_made_up_xyz` matches when present.
- A **typo'd field on a `block` rule silently never fires**, raises nothing, and
  reports nothing in `problems`.

Both directions matter:

- **Useful:** the consumer product can define its own field vocabulary
  (`content.kid_unsafe`) without touching the B2B registry. The Kids preset is
  free.
- **Dangerous:** a typo in a `block` rule is a silent hole in protection — a
  rule that looks configured and never fires. This is the *dishonest health*
  defect class in a new costume.

**Therefore: every consumer preset rule requires a known-positive fixture test**
asserting it actually fires on input it is supposed to catch. Step 7 of the
policy spike is the seed of that test. Do not ship a preset without one.
