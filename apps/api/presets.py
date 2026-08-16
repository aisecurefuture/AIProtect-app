"""Standard / Strict / Kids, evaluated by the policy engine as a library.

This is the seam from `spikes/spike_policy_engine.py` in production. The engine
is imported directly -- no FastAPI, no database, no tenant, and none of the
2,733-line policy CRUD service it normally sits behind. A preset is a plain
`List[dict]` handed to `PolicyEngine.evaluate()`.

TWO ACCOMMODATIONS, BOTH REQUIRED
=================================
1. `libs/policy-engine` must be on sys.path. Those modules use flat imports
   (`import opa_client`), so the DIRECTORY has to be importable; there is no
   package to import from.
2. `OPA_ENABLED=false` must be set BEFORE the engine is imported. It defaults
   to true, and this product runs no OPA sidecar, so every evaluation would
   otherwise pay a urllib timeout against http://opa:8181 before falling back
   to the Python engine.

THE HAZARD THIS FILE HAS TO DEFEND AGAINST
==========================================
The engine does NOT validate field names. It resolves `content.foo` by looking
up "foo" in whatever dict the caller passed, and never consults
`shared/policy-fields.json` -- that registry drives the policy-builder UI, not
enforcement. So a typo in a rule below does not raise, does not warn, and does
not appear in `problems`. It silently never matches.

On a `block` rule that is a hole in protection wearing the appearance of a
configured control -- the dishonest-health defect class in its purest form.
The defence is `tests/test_every_preset_rule_actually_fires.py`, which asserts
every rule here fires on input it is supposed to catch. Do not add a rule
without adding its fixture.
"""

from __future__ import annotations

import os
import sys
from pathlib import Path
from typing import Any, Dict, List, Optional

_REPO = Path(__file__).resolve().parents[2]

# Order matters: the engine reads OPA_ENABLED at import time.
os.environ.setdefault("OPA_ENABLED", "false")
_ENGINE_DIR = str(_REPO / "libs" / "policy-engine")
if _ENGINE_DIR not in sys.path:
    sys.path.insert(0, _ENGINE_DIR)

from policy_engine import EvaluationContext, PolicyEngine  # noqa: E402

STANDARD = "standard"
STRICT = "strict"
KIDS = "kids"
PRESET_NAMES = (STANDARD, STRICT, KIDS)

#: AI services where pasting personal data is worth warning about. Not a
#: blocklist -- these are legitimate tools people use on purpose.
_AI_DOMAINS = [
    "openai.com", "chatgpt.com", "anthropic.com", "claude.ai",
    "gemini.google.com", "perplexity.ai", "copilot.microsoft.com",
]


def _rule(rid: str, name: str, action: str, priority: int, rules: List[dict]) -> dict:
    return {
        "id": rid,
        "name": name,
        "enabled": True,
        "priority": priority,
        "action": action,
        "conditions": {"operator": "AND", "rules": rules},
    }


#: Secrets never go to an AI service, on any preset. This is the one rule that
#: is identical everywhere: there is no configuration in which leaking an API
#: key or a password is acceptable.
_BLOCK_SECRETS = _rule(
    "secrets-to-ai", "Block secrets going to an AI service", "block", 10,
    [{"field": "content.has_secrets", "operator": "equals", "value": True}],
)

_WARN_PII_TO_AI = _rule(
    "pii-to-ai", "Warn before sending personal information to an AI chatbot",
    "warn", 20,
    [
        {"field": "content.has_pii", "operator": "equals", "value": True},
        {"field": "request.domain", "operator": "in", "value": _AI_DOMAINS},
    ],
)

_BLOCK_PII_TO_AI = _rule(
    "pii-to-ai-strict", "Block personal information going to an AI chatbot",
    "block", 20,
    [
        {"field": "content.has_pii", "operator": "equals", "value": True},
        {"field": "request.domain", "operator": "in", "value": _AI_DOMAINS},
    ],
)

_BLOCK_MALICIOUS = _rule(
    "malicious-url", "Block dangerous sites", "block", 30,
    [{"field": "content.malicious", "operator": "equals", "value": True}],
)

_WARN_PROMPT_INJECTION = _rule(
    "prompt-injection", "Warn about pages that try to hijack an AI assistant",
    "warn", 40,
    [{"field": "content.prompt_injection", "operator": "equals", "value": True}],
)

_BLOCK_PROMPT_INJECTION = _rule(
    "prompt-injection-strict",
    "Block pages that try to hijack an AI assistant", "block", 40,
    [{"field": "content.prompt_injection", "operator": "equals", "value": True}],
)

#: Kids-only. A field the B2B registry has never heard of, which is fine --
#: the engine resolves whatever the caller supplies, so the consumer product
#: can define its own vocabulary without touching shared/policy-fields.json.
_BLOCK_KID_UNSAFE = _rule(
    "kid-unsafe", "Block content that is not suitable for children", "block", 15,
    [{"field": "content.kid_unsafe", "operator": "equals", "value": True}],
)

_MONITOR_EVERYTHING = _rule(
    "monitor-rest", "Monitor everything else", "monitor", 100,
    # Explicit match-all. conditions_guard requires match-all be SAID rather
    # than expressed as an empty rule list -- an empty list is UNEVALUATABLE
    # and gets skipped, which on an allow rule would be a silent blanket pass.
    [{"field": "*", "operator": "matches", "value": "*"}],
)


PRESETS: Dict[str, List[dict]] = {
    STANDARD: [
        _BLOCK_SECRETS, _WARN_PII_TO_AI, _BLOCK_MALICIOUS,
        _WARN_PROMPT_INJECTION, _MONITOR_EVERYTHING,
    ],
    STRICT: [
        _BLOCK_SECRETS, _BLOCK_PII_TO_AI, _BLOCK_MALICIOUS,
        _BLOCK_PROMPT_INJECTION, _MONITOR_EVERYTHING,
    ],
    KIDS: [
        _BLOCK_SECRETS, _BLOCK_KID_UNSAFE, _BLOCK_PII_TO_AI, _BLOCK_MALICIOUS,
        _BLOCK_PROMPT_INJECTION, _MONITOR_EVERYTHING,
    ],
}

_engine = PolicyEngine()


def evaluate(
    preset: str, *, request: Optional[dict] = None, content: Optional[dict] = None
) -> Dict[str, Any]:
    """Evaluate one preset. Returns the first matching action, or allow."""
    if preset not in PRESETS:
        raise KeyError(f"unknown preset {preset!r}; known: {', '.join(PRESET_NAMES)}")

    ctx = EvaluationContext(
        request=request or {},
        content=content or {},
        user={},                       # consumer: no department, no role
        endpoint={},
        metadata={},
    )
    problems: List[dict] = []
    result = _engine.evaluate_first_match(PRESETS[preset], ctx, problems)

    if result is None:
        return {"action": "allow", "matched": None, "reason": "", "problems": problems}
    return {
        "action": result.action,
        "matched": result.policy_id,
        "reason": result.reason,
        "problems": problems,
    }


def rule_ids(preset: str) -> List[str]:
    return [r["id"] for r in PRESETS[preset]]
