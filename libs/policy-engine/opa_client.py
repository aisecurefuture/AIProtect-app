"""OPA (Open Policy Agent) REST API Client.

Provides a thin synchronous wrapper around the OPA v1 REST API.

Endpoints used:
  GET  /health                     – liveness check
  PUT  /v1/policies/{id}           – upload / replace a Rego module
  DELETE /v1/policies/{id}         – remove a Rego module
  POST /v1/data/{package}/{rule}   – evaluate a rule
  PUT  /v1/data/{path}             – push data documents

OPA is expected to run as a sidecar (see docker-compose) at OPA_URL.
All calls have a short timeout (OPA_TIMEOUT_SECONDS) so that a slow or
unavailable OPA never blocks the policy service – callers must fall back
to the built-in Python engine when this client returns None / False.
"""

from __future__ import annotations

import json
import logging
import os
import urllib.error
import urllib.request
from typing import Any, Dict, Optional

logger = logging.getLogger("policy.opa_client")

OPA_URL = os.getenv("OPA_URL", "http://opa:8181").rstrip("/")
OPA_TIMEOUT = int(os.getenv("OPA_TIMEOUT_SECONDS", "5"))
OPA_ENABLED = os.getenv("OPA_ENABLED", "true").strip().lower() in {
    "1", "true", "yes", "on"
}

# ---------------------------------------------------------------------------
# Low-level HTTP helpers
# ---------------------------------------------------------------------------


def _do(
    method: str,
    path: str,
    body: Optional[bytes] = None,
    content_type: str = "application/json",
) -> Optional[Any]:
    """Execute a single HTTP request against OPA.  Returns parsed JSON body or None."""
    url = f"{OPA_URL}{path}"
    headers: Dict[str, str] = {}
    if body is not None:
        headers["Content-Type"] = content_type
    req = urllib.request.Request(url, data=body, headers=headers, method=method)
    try:
        with urllib.request.urlopen(req, timeout=OPA_TIMEOUT) as resp:
            raw = resp.read()
            if raw:
                return json.loads(raw.decode("utf-8"))
            return {}
    except urllib.error.HTTPError as exc:
        logger.debug("OPA HTTP %s %s → %s", method, path, exc.code)
        return None
    except Exception as exc:
        logger.debug("OPA request failed %s %s: %s", method, path, exc)
        return None


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------


def is_available() -> bool:
    """Return True if OPA is reachable and reports healthy."""
    if not OPA_ENABLED:
        return False
    result = _do("GET", "/health")
    return result is not None


def put_policy(policy_id: str, rego_text: str) -> bool:
    """Upload (or replace) a Rego module identified by *policy_id*.

    OPA identifies modules by an arbitrary string ID.  We use the CyberArmor
    policy UUID so each policy maps 1-to-1 to an OPA module.
    """
    if not OPA_ENABLED:
        return False
    # OPA expects plain-text Rego, not JSON
    result = _do(
        "PUT",
        f"/v1/policies/{policy_id}",
        body=rego_text.encode("utf-8"),
        content_type="text/plain",
    )
    if result is None:
        logger.warning("OPA put_policy failed for policy_id=%s", policy_id)
        return False
    logger.debug("OPA put_policy ok policy_id=%s", policy_id)
    return True


def delete_policy(policy_id: str) -> bool:
    """Remove a Rego module from OPA."""
    if not OPA_ENABLED:
        return False
    result = _do("DELETE", f"/v1/policies/{policy_id}")
    if result is None:
        logger.debug("OPA delete_policy skipped (404 or unavailable) policy_id=%s", policy_id)
        return False
    return True


def put_data(path: str, data: Any) -> bool:
    """Push a data document to OPA at the given path (e.g. 'cyberarmor/tenants/default').

    This is used to pass tenant policy sets to the base Rego evaluation module.
    """
    if not OPA_ENABLED:
        return False
    result = _do(
        "PUT",
        f"/v1/data/{path.lstrip('/')}",
        body=json.dumps(data).encode("utf-8"),
    )
    return result is not None


def evaluate(package_rule_path: str, input_data: Dict[str, Any]) -> Optional[Any]:
    """Query OPA for the value of a rule.

    *package_rule_path* is a slash-separated OPA data path,
    e.g. "cyberarmor/policy/decision".

    Returns the ``result`` field from the OPA response, or None if OPA is
    unavailable or the rule is undefined.
    """
    if not OPA_ENABLED:
        return None
    body = json.dumps({"input": input_data}).encode("utf-8")
    response = _do("POST", f"/v1/data/{package_rule_path.lstrip('/')}", body=body)
    if response is None:
        return None
    # OPA wraps the rule value in {"result": ...}
    return response.get("result")


def load_base_policy(rego_text: str) -> bool:
    """Upload the base cyberarmor evaluation Rego module.

    This is called once at policy service startup.
    The module ID is fixed so it is idempotently replaced on every restart.
    """
    return put_policy("cyberarmor_base", rego_text)
