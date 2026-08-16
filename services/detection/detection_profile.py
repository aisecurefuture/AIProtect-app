"""Serving profiles: which detectors this deployment is CONFIGURED to run.

WHY THIS EXISTS
===============
One codebase serves two products with opposite economics.

  * B2B (CyberArmor.ai) -- ~800 paid seats, traffic only ever reaching 27
    AI-provider hosts. Measured on production 2026-08-07: 5.24 GiB resident,
    ~3.58 s per /scan, five transformer models. Correct for that shape.
  * B2C (AIProtect.app) -- a consumer free tier. At ~14 core-seconds per scan
    that config is both unaffordable and trivially DoS-able.

The cheap tier is not a different service. It is the same detectors with a
narrower set switched on, so a fix lands in both products at once.

THE THIRD STATE, AND WHY IT IS THE WHOLE POINT
==============================================
A detector can be in three states, and collapsing any two of them reintroduces
the defect class this repo keeps paying for:

  ran            -> produced a verdict. `scan_complete` unaffected.
  FAILED         -> `detector_unavailable`, `scan_complete` false. A FAULT.
  not configured -> never asked to run. NOT a fault, and NOT a clean verdict.

Building the cheap tier by simply not loading a model would take the second
branch: ``_scan_output_safety`` emits ``detector_unavailable`` when the
zero-shot pipeline is missing, so every consumer scan would report
``scan_complete: false`` forever -- a permanent, meaningless alarm that also
starves the result cache (which refuses to cache incomplete scans).

So a profile does not break models. It declines to ASK, and it says out loud
which questions it did not ask, on every single response, via
``checks_skipped_by_profile``. Same shape as ``HealthRecord(checks_run,
checks_unavailable)`` and ``conditions_guard``'s UNEVALUATABLE: a thing that did
not happen must never render as a thing that happened and found nothing.
"""

from __future__ import annotations

import hashlib
import os
from typing import Dict, FrozenSet, List

#: Every detector this service can run. Names match the ``_scan_*`` helpers in
#: main.py and are part of the /ready and scan-response contract.
ALL_DETECTORS: FrozenSet[str] = frozenset(
    {"prompt_injection", "sensitive_data", "output_safety", "toxicity"}
)

#: Logical model names (keys of ml_models.MODEL_IDS) each detector needs. A
#: model no enabled detector needs is never declared, never warmed, and -- this
#: is the point -- never counted as degraded on /ready, because a model this
#: deployment deliberately does not run is not a model that is missing.
_DETECTOR_MODELS: Dict[str, FrozenSet[str]] = {
    "prompt_injection": frozenset({"prompt_injection"}),
    "sensitive_data": frozenset({"ner_pii", "ner_phi"}),
    "output_safety": frozenset({"zero_shot"}),
    "toxicity": frozenset({"toxicity"}),
}

#: PROFILES[name] = detectors enabled.
#:
#: consumer: drops output_safety. That single removal is ~75% of the measured
#: latency (bart-large-mnli, 2 forward passes, 2.72 s of a 3.58 s scan) and
#: ~1.6 GB of the footprint. It also drops ner_phi -- a clinical
#: de-identification model (~1.4 GB) whose HIPAA Safe Harbor identifiers no
#: consumer product has any use for. Remaining: prompt-injection, PII, toxicity
#: -- which is exactly the consumer feature set (AI Safety + Privacy Guard).
PROFILES: Dict[str, FrozenSet[str]] = {
    "full": ALL_DETECTORS,
    "consumer": frozenset({"prompt_injection", "sensitive_data", "toxicity"}),
}

#: Models a profile drops even though an enabled detector could use them.
#: sensitive_data keeps working on ner_pii + the regex catalog; PHI spans are
#: additive and documented as not affecting `complete` (see _redact_text).
_PROFILE_MODEL_OVERRIDES: Dict[str, FrozenSet[str]] = {
    "consumer": frozenset({"ner_phi"}),
}

_DEFAULT_PROFILE = "full"


def _read_profile() -> str:
    raw = os.getenv("CYBERARMOR_DETECTION_PROFILE", _DEFAULT_PROFILE).strip().lower()
    if raw not in PROFILES:
        # Deliberately not a silent fallback to "full": a typo'd profile that
        # quietly serves the expensive config is a bill, and a typo'd profile
        # that quietly serves the cheap one is missing coverage. Neither should
        # be discoverable only from a graph.
        raise ValueError(
            f"CYBERARMOR_DETECTION_PROFILE={raw!r} is not a known profile. "
            f"Known: {', '.join(sorted(PROFILES))}"
        )
    return raw


PROFILE: str = _read_profile()
ENABLED_DETECTORS: FrozenSet[str] = PROFILES[PROFILE]


def is_enabled(detector: str) -> bool:
    return detector in ENABLED_DETECTORS


def skipped_detectors() -> List[str]:
    """Detectors this deployment is configured NOT to run. Never None, never
    omitted from a response -- an empty list is itself the honest answer."""
    return sorted(ALL_DETECTORS - ENABLED_DETECTORS)


def required_models() -> FrozenSet[str]:
    """Logical model names the enabled detectors actually need."""
    needed: set[str] = set()
    for det in ENABLED_DETECTORS:
        needed |= _DETECTOR_MODELS.get(det, frozenset())
    return frozenset(needed - _PROFILE_MODEL_OVERRIDES.get(PROFILE, frozenset()))


def models_for_profile(profile: str, model_ids: Dict[str, str]) -> Dict[str, str]:
    """Which models `profile` would load, independent of THIS process's profile.

    Exists so a test can ask "what does the deployment in docker-compose.yml
    load?" without being the deployment. Without it, a test comparing compose
    against the running process's MODEL_IDS is really comparing two different
    profiles and calling the difference a drift.
    """
    if profile not in PROFILES:
        raise ValueError(f"unknown profile {profile!r}")
    needed: set[str] = set()
    for det in PROFILES[profile]:
        needed |= _DETECTOR_MODELS.get(det, frozenset())
    needed -= _PROFILE_MODEL_OVERRIDES.get(profile, frozenset())
    return {name: mid for name, mid in model_ids.items() if name in needed}


def filter_model_ids(model_ids: Dict[str, str]) -> Dict[str, str]:
    """Narrow a MODEL_IDS mapping to what this profile will actually load."""
    keep = required_models()
    return {name: mid for name, mid in model_ids.items() if name in keep}


def config_fingerprint(extra: str = "") -> str:
    """Short digest of everything that could change a scan verdict.

    Mixed into every cache key so a threshold or model change cannot serve a
    verdict computed under the old configuration. Cheap insurance: the failure
    it prevents is a stale *security* answer.
    """
    parts = [
        PROFILE,
        ",".join(sorted(ENABLED_DETECTORS)),
        ",".join(sorted(required_models())),
        extra,
    ]
    return hashlib.sha256("|".join(parts).encode("utf-8")).hexdigest()[:16]


def describe() -> Dict[str, object]:
    """Profile facts for /ready and /health. Reported always, so a reader never
    has to infer the serving shape from which models happen to be resident."""
    return {
        "profile": PROFILE,
        "detectors_enabled": sorted(ENABLED_DETECTORS),
        "detectors_skipped_by_profile": skipped_detectors(),
        "models_required": sorted(required_models()),
    }
