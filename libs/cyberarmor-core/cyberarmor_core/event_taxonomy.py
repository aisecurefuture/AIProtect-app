"""The event taxonomy — orthogonal dimensions, mapped to OCSF.

WHAT THIS IS FOR
----------------
Every CyberArmor surface emits events, and until now ``event_type`` was a
free-form string: 21 distinct values across the product, no vocabulary, nothing
to search on beyond exact-matching a name you had to already know.

This gives those events dimensions that COMPOSE. "Shadow-AI events from IDEs at
high severity" becomes three clauses instead of a name you have to guess.

WHY DIMENSIONS AND NOT ONE ENUM
-------------------------------
The obvious design is a single richer ``event_type`` enum: ``ide_shadow_ai``,
``browser_shadow_ai``, ``ide_prompt_injection``... That multiplies. Every new
source needs an entry per class per action, and it is unusable by about thirty
values -- which is roughly where this product already is.

Split, they stay small and answer different questions:

    source        where did this come from      endpoint, browser, ide, proxy...
    source_detail which one                     "vscode", "chrome"
    category      what domain                   security, policy, identity, data
    event_class   what kind of thing            shadow_ai, data_exfil, privilege
    action        what the product DID          blocked, redacted, detected
    severity      how bad                       existing enum

``event_type`` is KEPT alongside them, not replaced. 31 leaf rules in the
shipped compliance packs are written against it, and a taxonomy that
invalidates the rules it exists to support has solved the wrong problem. The
new dimensions are strictly additive.

WHY OCSF
--------
A SEC/FINRA customer's SOC ingests into Splunk or Sentinel; both speak OCSF
natively. Emitting it makes the SIEM connector a passthrough rather than a
translator, and turns "what schema do you emit" from a project into an answer.
The AI-specific classes (shadow AI, agentic AI, prompt injection) have no good
home in standard OCSF, so they are mapped to the closest standard class and
carry their specificity in ``event_class`` -- mislabelling them as something
they are not would be worse than extending.

THE RULE THIS MODULE ENFORCES
-----------------------------
An event type this module does not recognise is classified ``UNKNOWN``, never
guessed into a plausible-looking category. A telemetry search that silently
mis-files new events is worse than one that shows them as unclassified: the
first looks complete and is not. :func:`unclassified_event_types` exists so a
test can fail when a new emitter appears without a mapping.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Dict, Iterable, Optional, Set, Tuple

__all__ = [
    "SOURCES",
    "CATEGORIES",
    "EVENT_CLASSES",
    "ACTIONS",
    "UNKNOWN",
    "Classification",
    "classify",
    "known_event_types",
    "unclassified_event_types",
    "ANTICIPATED_NOT_OBSERVED",
]

#: Sentinel for anything this module cannot place. Never a plausible guess.
UNKNOWN = "unknown"

#: WHERE the event came from. Deliberately excludes "general": an event with no
#: source is a bug, not a category.
SOURCES: Tuple[str, ...] = (
    "endpoint",       # the endpoint agent on a workstation
    "browser",        # chromium/firefox/safari extension
    "proxy",          # MITM proxy, server-side or local
    "kernel",         # macOS EndpointSecurity / Windows driver
    "ide",            # VS Code, JetBrains, Claude Code hooks
    "sdk",            # an application instrumented with a CyberArmor SDK
    "rasp",           # in-process runtime protection
    "mobile",
    "office",         # Word/Excel/Outlook add-ins
    "ros",            # ROS2 robot agents
    "control_plane",  # the platform itself
)

#: WHAT DOMAIN the event belongs to.
CATEGORIES: Tuple[str, ...] = (
    "security",      # a threat, or a control acting on one
    "policy",        # a tenant rule matched or was enforced
    "identity",      # authentication, authorisation, privilege
    "data",          # sensitive data moving
    "compliance",    # evidence, attestation, inventory
    "availability",  # health, heartbeats, reachability
)

#: WHAT KIND of thing it is. This is where the AI-specific vocabulary lives.
EVENT_CLASSES: Tuple[str, ...] = (
    "shadow_ai",         # unsanctioned AI use
    "ai_usage",          # SANCTIONED AI use, observed through instrumentation
    "agentic_ai",        # autonomous agent behaviour, MCP, tool use
    "malware",           # malicious or suspicious binaries and command lines
    "ransomware",        # encryption-for-extortion, specifically
    "destruction",       # data destroyed rather than taken
    "prompt_injection",
    "data_exfil",
    "malicious_url",
    "privilege",
    "auth",
    "payment",           # payment-instruction attestation
    "inventory",
    "attestation",
    "telemetry",         # heartbeats and other liveness signal
    "decision",          # a policy/runtime verdict with no narrower class
)

#: WHAT THE PRODUCT DID about it. Not what the user did.
ACTIONS: Tuple[str, ...] = (
    "blocked",
    "allowed",
    "redacted",
    "detected",       # observed and recorded; no enforcement taken
    "quarantined",
    "escalated",
)


@dataclass(frozen=True)
class Classification:
    """The intrinsic dimensions of an event type.

    ``source`` and ``action`` are NOT here on purpose. Both are properties of
    the individual event, not of its type: the same ``policy_block`` can come
    from the proxy or the browser, and ``clipboard_sensitive_data`` may have
    been redacted on one host and blocked on another. Baking either into the
    type table would mean recording a value nobody observed.
    """

    category: str
    event_class: str
    #: OCSF class_uid. 0 where no standard class fits and the event is carried
    #: by event_class alone -- see the module docstring.
    ocsf_class_uid: int = 0
    ocsf_category_uid: int = 0


# OCSF category_uid values used below:
#   1 System Activity   2 Findings   3 Identity & Access   4 Network Activity
#   6 Application Activity
#
# class_uid 0 means "no standard OCSF class is a good fit". It is recorded as 0
# rather than forced into an approximate class: a SIEM rule keyed on the wrong
# class_uid is worse than one keyed on a missing one, because it looks right.
_TABLE: Dict[str, Classification] = {
    # -- AI traffic and shadow AI ------------------------------------------
    "ai_traffic_inspection":        Classification("security", "shadow_ai", 4001, 4),
    "ai_router_inference":          Classification("security", "shadow_ai", 6003, 6),
    "proxy_traffic":                Classification("security", "shadow_ai", 4001, 4),
    "claude_code_prompt_policy_match": Classification("policy", "shadow_ai", 6003, 6),

    # -- SDK-instrumented AI calls -----------------------------------------
    #
    # Emitted by the Python SDK's provider wrapper on every call it audits.
    # Distinct from shadow_ai: an application calling AI THROUGH the SDK is
    # sanctioned use being observed, not unsanctioned use being caught.
    #
    # Both were invisible until 2026-08-01: the emitter writes them as a
    # conditional (`"ai_call_error" if error else "ai_call_completed"`), and the
    # taxonomy's coverage scan only matched a literal sitting directly after
    # the key -- so the entire SDK surface went unclassified while the guard
    # reported full coverage.
    "ai_call_completed":            Classification("security", "ai_usage", 6003, 6),
    "ai_call_error":                Classification("security", "ai_usage", 6003, 6),

    # A multipart upload reached an AI host that is NOT in the built-in
    # pattern catalog. Discovery of an upload surface nobody had catalogued --
    # inventory, and the input to the pattern-promotion flow.
    "upload_endpoint_discovered":   Classification("compliance", "inventory", 5001, 5),

    # FALLBACK LABEL, not a real event type: control-plane stamps this when an
    # agent posts telemetry with no event_type at all
    # (`event.get("event_type") or "endpoint_event"`). Classified rather than
    # ignored because it is genuinely written to the database and shows up in
    # search. A rising count here means an agent is emitting untyped telemetry
    # and should be fixed at the source.
    "endpoint_event":               Classification("availability", "telemetry", 0, 0),

    # -- agentic / MCP ------------------------------------------------------
    "mcp_config_finding":           Classification("security", "agentic_ai", 2001, 2),
    # An agent invoked a tool outside its SERVER-ISSUED allowlist. The emitter
    # lives in the Python SDK's LangChain callback and is INERT today: it
    # cannot read the allowlist, because no route exposes agent-identity to an
    # SDK caller. Classified anyway so that the day the route lands, the event
    # is already searchable rather than arriving as category='unknown'.
    "agent_scope_violation":        Classification("security", "agentic_ai", 2001, 2),
    "mcp_server_inventory":         Classification("compliance", "inventory", 5001, 5),

    # -- data movement ------------------------------------------------------
    "clipboard_sensitive_data":          Classification("data", "data_exfil", 4001, 4),
    "clipboard_sensitive_data_redacted": Classification("data", "data_exfil", 4001, 4),
    "clipboard_sensitive_data_blocked":  Classification("data", "data_exfil", 4001, 4),

    # -- URL reputation -----------------------------------------------------
    "url_trust_gate_verdict":       Classification("security", "malicious_url", 4001, 4),
    "url_trust_gate_feedback":      Classification("security", "malicious_url", 0, 0),

    # -- policy / runtime verdicts -----------------------------------------
    "runtime_decision":             Classification("policy", "decision", 0, 0),

    # The enforcement point's own audit record, one per inspected request.
    # Added 2026-08-12 with the proxy's audit writer: before that this file
    # classified events the proxy emitted to TELEMETRY, while the proxy wrote
    # nothing whatsoever to the audit trail.
    "ai_traffic_decision":          Classification("policy", "decision", 4001, 4),

    # -- proxy coverage and connectivity ------------------------------------
    # These four were emitted by the product and classified nowhere, so they
    # searched as category "unknown": a filter that looked complete while
    # silently omitting them. Red in
    # libs/cyberarmor-core/tests/test_event_taxonomy_covers_what_is_emitted.py
    # since before this session.
    "ai_traffic_coverage_gap":          Classification("security", "shadow_ai", 4001, 4),
    "ai_traffic_coverage_extended":     Classification("security", "shadow_ai", 0, 0),
    "ai_traffic_proxy_stranded":        Classification("availability", "telemetry", 4001, 4),
    "ai_traffic_connectivity_restored": Classification("availability", "telemetry", 0, 0),

    # -- identity and privilege --------------------------------------------
    "privileged_action":            Classification("identity", "privilege", 3005, 3),
    # A caller reached PAST the privileged-actions allowlist: it asked the
    # endpoint agent for an operation that is not in _OPERATIONS at all, so the
    # broker refused before touching host state. Emitted by the endpoint agent
    # since 2026-08-01; the shipped least-privilege-access control in four packs
    # has keyed on it since long before a producer existed.
    "privilege_escalation":         Classification("identity", "privilege", 3005, 3),
    # A session issued with no second factor. Emitted by control-plane since
    # 2026-08-01; four shipped compliance packs have keyed
    # require-mfa-tenant-access on it since long before a producer existed.
    # OCSF 3002 = Authentication, under Identity & Access Management.
    "login_no_mfa":                 Classification("identity", "auth", 3002, 3),

    # -- payment attestation (the SEC/FINRA path) --------------------------
    "out_of_band_verification_attestation":
                                    Classification("compliance", "attestation", 0, 0),

    # -- endpoint monitors --------------------------------------------------
    #
    # agents/endpoint-agent/monitors/. None of these is a new emitter -- they
    # have shipped all along and were simply invisible to the coverage scan.
    # They go through a wrapped `await self._emit_event(\n "name",` call, so
    # the type sits on the line AFTER the one the scan matched.
    #
    # Seventeen event types from the product's own endpoint sensors,
    # unclassified while the guard reported complete coverage -- the exact
    # failure this taxonomy exists to prevent, found inside the tool built to
    # prevent it.
    "ai_tool_process_detected":       Classification("security", "shadow_ai", 1001, 1),
    "ai_tool_process_exited":         Classification("security", "shadow_ai", 1001, 1),
    "ai_tool_installed":              Classification("security", "shadow_ai", 1001, 1),
    "unauthorized_ai_tool_detected":  Classification("security", "shadow_ai", 2001, 2),
    "zero_day_ai_tool_detected":      Classification("security", "shadow_ai", 2001, 2),
    "ai_model_file_detected":         Classification("security", "shadow_ai", 1001, 1),
    "ai_service_connection_detected": Classification("security", "shadow_ai", 4001, 4),
    "mcp_connection_detected":        Classification("security", "agentic_ai", 4001, 4),

    # Data movement observed on the endpoint.
    "exfiltration_pattern_detected":  Classification("data", "data_exfil", 2001, 2),
    "large_archive_created":          Classification("data", "data_exfil", 1001, 1),

    # Destructive activity. Ransomware's encrypt-and-delete phase, and a
    # departing insider clearing their tracks, both land here.
    #
    # Deletions were not observed AT ALL before 2026-08-01 -- the file monitor
    # handled created/modified/moved and had no on_deleted handler, so a file
    # going away produced nothing anywhere in the product.
    "mass_deletion_detected":         Classification("data", "destruction", 1001, 1),
    "mass_encryption_suspected":      Classification("security", "ransomware", 2001, 2),

    # Binary and command-line threats. OCSF 2001 = Security Finding.
    "malware_signature_detected":     Classification("security", "malware", 2001, 2),
    "suspicious_cmdline_detected":    Classification("security", "malware", 2001, 2),
    "rce_guard_binary_flagged":       Classification("security", "malware", 2001, 2),
    "rce_guard_binary_quarantined":   Classification("security", "malware", 2001, 2),
    "sandbox_binary_suspicious":      Classification("security", "malware", 2001, 2),
    "sandbox_binary_quarantined":     Classification("security", "malware", 2001, 2),

    # The verification CHECK, distinct from the attestation record it produces.
    "out_of_band_verification":       Classification("compliance", "attestation", 0, 0),

    # -- inventory ----------------------------------------------------------
    "discovery_snapshot_completed": Classification("compliance", "inventory", 5001, 5),

    # -- ANTICIPATED, NOT OBSERVED -----------------------------------------
    #
    # Everything above this line was found emitted by product source on
    # 2026-08-01. Everything below appears ONLY in test fixtures, as a reason
    # string, or in a consumer-side matching list -- no product code path was
    # found that sends it as an `event_type`.
    #
    # They are kept because each names a real product concept and classifying
    # it in advance costs nothing. They are SEPARATED because "we classify
    # this" and "we emit this" are different claims, and an earlier version of
    # this file conflated them: a source scan that included tests reported
    # `session_heartbeat` as a product emission, and a conclusion was drawn
    # from it that was simply false.
    #
    # The conformance test asserts coverage of what is EMITTED, so entries
    # here are never required to be exercised -- they just must not be
    # mistaken for evidence that the event exists.
    "payment_instruction":          Classification("security", "payment", 0, 0),
    "vendor_bank_detail_change":    Classification("security", "payment", 0, 0),
    "account_access_change":        Classification("identity", "auth", 3001, 3),
    "policy_block":                 Classification("policy", "decision", 0, 0),
    "session_heartbeat":            Classification("availability", "telemetry", 0, 0),
}

#: Entries above that no product code path was observed to emit. Kept honest
#: so nothing downstream reads the table as proof an event exists.
ANTICIPATED_NOT_OBSERVED: frozenset = frozenset({
    "payment_instruction",
    "vendor_bank_detail_change",
    "account_access_change",
    "policy_block",
    "session_heartbeat",
})

#: A classification that asserts nothing. Returned for an unrecognised type.
_UNCLASSIFIED = Classification(UNKNOWN, UNKNOWN, 0, 0)


def classify(event_type: Optional[str]) -> Classification:
    """The dimensions for ``event_type``, or an explicitly UNKNOWN one.

    Never guesses. A new emitter that nobody added here shows up as
    ``category="unknown"`` in search, which is visible and fixable -- unlike
    being quietly filed under ``security`` because that is the common case.
    """
    if not event_type:
        return _UNCLASSIFIED
    return _TABLE.get(event_type.strip(), _UNCLASSIFIED)


def known_event_types() -> Set[str]:
    """Every event type this taxonomy can place."""
    return set(_TABLE)


def unclassified_event_types(emitted: Iterable[str]) -> Set[str]:
    """Which of ``emitted`` this module cannot place.

    For a conformance test: grep the event types the product actually emits,
    pass them here, and fail when the set is non-empty. That is what stops the
    taxonomy silently rotting as new emitters are added -- the same shape as
    the policy field registry's conformance test.
    """
    return {e for e in emitted if e and e.strip() not in _TABLE}
