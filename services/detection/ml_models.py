"""ML Model Registry for CyberArmor Detection Service.

Open-source models used (all run locally, no external API calls):
  Prompt Injection : protectai/deberta-v3-base-prompt-injection-v2
  PII / NER        : dslim/bert-base-NER
  PHI / de-id      : obi/deid_roberta_i2b2   (clinical; additive to the phi.*
                     regexes, never their sole source -- see _redact_text)
  Toxicity         : unitary/toxic-bert
  Zero-Shot        : facebook/bart-large-mnli
  Local LLM        : Ollama  (llama3.2:3b, mistral:7b, phi3:mini, etc.)

All HuggingFace models are loaded from the local cache directory
(TRANSFORMERS_CACHE / HF_HOME) and never phone home during inference.
Set TRANSFORMERS_OFFLINE=1 to hard-block any outbound HF network access.

Ollama is an optional sidecar that serves a locally-downloaded quantised
model.  The judge is only called for high-ambiguity cases and gracefully
no-ops if Ollama is unreachable.
"""

from __future__ import annotations

import json
import logging
import os
import threading
import time
import urllib.error
import urllib.request
from typing import Any, Dict, List, NamedTuple, Optional, Tuple

import detection_profile

logger = logging.getLogger("detection.ml_models")

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

MODELS_CACHE_DIR = os.getenv(
    "TRANSFORMERS_CACHE",
    os.getenv("HF_HOME", "/tmp/cyberarmor_models"),
)

# Primary prompt-injection classifier.
# protectai/deberta-v3-base-prompt-injection-v2 is purpose-built for this task.
# Alternative: deepset/deberta-v3-base-injection
ML_PROMPT_INJECTION_MODEL = os.getenv(
    "ML_PROMPT_INJECTION_MODEL",
    "protectai/deberta-v3-base-prompt-injection-v2",
)

# NER model for structured PII extraction.
# Alternative: Jean-Baptiste/roberta-large-ner-english (more accurate, heavier)
ML_NER_PII_MODEL = os.getenv("ML_NER_PII_MODEL", "dslim/bert-base-NER")

# PHI needs a DIFFERENT model, not a bigger threshold on the PII one.
# dslim/bert-base-NER is CoNLL-2003: its label set is PER/LOC/ORG/MISC and
# nothing else. It cannot emit a medical-record-number or health-plan entity
# at any confidence, because no such class exists in it -- so pointing the PHI
# classes at it would produce a detector that is permanently, silently clean.
# The default here is a clinical de-identification model trained on the
# i2b2/UTHealth corpus, whose label set is the PHI categories themselves.
# Override per deployment; the box already runs its own DeBERTa for prompt
# injection, so a locally-hosted de-id model is the expected production value.
ML_NER_PHI_MODEL = os.getenv("ML_NER_PHI_MODEL", "obi/deid_roberta_i2b2")

# Toxicity classifier.
# Alternative: martin-ha/toxic-comment-model
ML_TOXICITY_MODEL = os.getenv("ML_TOXICITY_MODEL", "unitary/toxic-bert")

# Zero-shot classifier (MNLI).
# Used for flexible, label-free threat categorisation.
ML_ZERO_SHOT_MODEL = os.getenv("ML_ZERO_SHOT_MODEL", "facebook/bart-large-mnli")

# Ollama local LLM configuration.
OLLAMA_BASE_URL = os.getenv("OLLAMA_BASE_URL", "http://ollama:11434")
OLLAMA_MODEL = os.getenv("OLLAMA_MODEL", "llama3.2:3b")
OLLAMA_ENABLED = os.getenv("OLLAMA_ENABLED", "true").strip().lower() in {
    "1", "true", "yes", "on"
}
OLLAMA_TIMEOUT = int(os.getenv("OLLAMA_TIMEOUT_SECONDS", "10"))

# Per-detector confidence thresholds (env-overridable)
PROMPT_INJECTION_ML_THRESHOLD = float(
    os.getenv("ML_PROMPT_INJECTION_THRESHOLD", "0.62")
)
TOXICITY_ML_THRESHOLD = float(os.getenv("ML_TOXICITY_THRESHOLD", "0.70"))
NER_PII_CONFIDENCE_THRESHOLD = float(os.getenv("ML_NER_CONFIDENCE_THRESHOLD", "0.75"))
ZERO_SHOT_THREAT_THRESHOLD = float(os.getenv("ML_ZERO_SHOT_THRESHOLD", "0.60"))

# Bounded retry for transient model-load failures (see MLModelRegistry._load).
# Retrying on every call would hammer a broken model path under load, so a
# failed load is retried at most MODEL_LOAD_MAX_ATTEMPTS times, and never more
# often than the cooldown.
MODEL_LOAD_MAX_ATTEMPTS = int(os.getenv("ML_MODEL_LOAD_MAX_ATTEMPTS", "3"))
MODEL_LOAD_RETRY_COOLDOWN_SECONDS = float(
    os.getenv("ML_MODEL_LOAD_RETRY_COOLDOWN_SECONDS", "60")
)

# Load-state vocabulary. These strings are part of the /ready contract.
#   loaded        – the pipeline object exists in this process, right now
#   not_attempted – lazy-loaded and nothing has needed it yet (not an error)
#   unavailable   – permanently impossible here (transformers not installed)
#   failed        – a load was attempted and raised; may still be retried
MODEL_STATUS_LOADED = "loaded"
MODEL_STATUS_NOT_ATTEMPTED = "not_attempted"
MODEL_STATUS_UNAVAILABLE = "unavailable"
MODEL_STATUS_FAILED = "failed"

# Logical model name → configured model id. The single source of truth for
# which models this service expects to have; /ready reports every entry,
# including ones nothing has asked for yet.
#: Declared models, BEFORE the serving profile narrows them. Kept as its own
#: name so /ready can say what was configured away rather than pretending the
#: dropped models were never part of the design.
ALL_MODEL_IDS: Dict[str, str] = {
    "prompt_injection": ML_PROMPT_INJECTION_MODEL,
    "ner_pii": ML_NER_PII_MODEL,
    "ner_phi": ML_NER_PHI_MODEL,
    "toxicity": ML_TOXICITY_MODEL,
    "zero_shot": ML_ZERO_SHOT_MODEL,
}

# The profile decides which of those this deployment actually loads. Filtering
# HERE -- at the single source of truth -- is what keeps a deliberately absent
# model from being reported as a degraded one: /ready derives `degraded` from
# the status of every entry in MODEL_IDS, so an entry that was never declared
# is never missing. A model the profile drops is a choice; a model that failed
# to load is a fault; the two must not render identically.
MODEL_IDS: Dict[str, str] = detection_profile.filter_model_ids(ALL_MODEL_IDS)

#: What the profile removed, so the fact stays reportable instead of implicit.
MODELS_DISABLED_BY_PROFILE: Dict[str, str] = {
    name: mid for name, mid in ALL_MODEL_IDS.items() if name not in MODEL_IDS
}

# ---------------------------------------------------------------------------
# Optional transformers import
# ---------------------------------------------------------------------------

try:
    from transformers import pipeline as hf_pipeline  # type: ignore[import]

    _TRANSFORMERS_AVAILABLE = True
except ImportError:  # pragma: no cover
    hf_pipeline = None  # type: ignore[assignment]
    _TRANSFORMERS_AVAILABLE = False
    logger.warning(
        "transformers library not installed; ML model detectors disabled. "
        "Install with: pip install transformers torch"
    )


# ---------------------------------------------------------------------------
# Model Registry  (lazy-loading singleton)
# ---------------------------------------------------------------------------


class MLModelRegistry:
    """Thread-safe lazy-loading registry for HuggingFace pipeline objects.

    Each model is loaded on first use and cached in-process. Load failures are
    logged and `None` is returned so callers can degrade gracefully — but the
    *reason* is retained (see `model_status`) instead of being flattened away.
    """

    _instance: Optional["MLModelRegistry"] = None
    _new_lock = threading.Lock()

    def __new__(cls) -> "MLModelRegistry":
        # The singleton construction raced too: two threads could both find
        # `_instance is None` and build separate registries, and the loser's
        # loaded models would be silently dropped along with its state.
        with cls._new_lock:
            if cls._instance is None:
                inst = super().__new__(cls)
                inst._models: Dict[str, Any] = {}
                inst._state: Dict[str, Dict[str, Any]] = {}
                # Serialises LOADS, not lookups -- see the double-check in
                # _load. Deliberately one lock rather than one per model:
                # loading is rare, and letting five transformer models
                # materialise at once is how an 8 GiB container dies on a
                # 15 GiB host running thirty others.
                inst._load_lock = threading.Lock()
                os.makedirs(MODELS_CACHE_DIR, exist_ok=True)
                cls._instance = inst
        return cls._instance

    def _load(self, name: str, model_id: str, task: str, **kwargs: Any) -> Optional[Any]:
        """Return the pipeline for `name`, loading it on first use.

        The defect this replaces: any failure cached ``None`` forever
        ("already attempted (may be None on failure)"). A *permanent*
        condition (transformers not installed) and a *transient* one (memory
        pressure at boot, a network blip pulling weights) were recorded
        identically, so one unlucky moment permanently degraded the service —
        no retry, and nothing anywhere reported that a model was missing. The
        two cases are now distinct:

          * transformers missing  → cached permanently; retrying cannot help.
          * load raised           → retryable, bounded by attempt cap +
                                    cooldown so a broken model path is not
                                    re-hammered on every request, and logged
                                    at error because this model was expected
                                    to exist.
        """
        # Fast path, deliberately outside the lock: once a model is resident
        # every request reads it, and serialising inference behind a load lock
        # would cost far more than the load ever did.
        pipe = self._models.get(name)
        if pipe is not None:
            return pipe

        # SLOW PATH UNDER A LOCK. This class called itself "Thread-safe" in
        # its own docstring while importing no lock at all, and the check
        # above is a check-then-construct-then-assign. `def scan(...)` is a
        # sync route, so FastAPI runs it in a 40-slot threadpool against this
        # shared singleton -- N concurrent first requests each built their own
        # copy of the model. For bart-large-mnli that is ~1.6 GiB apiece
        # inside `mem_limit: 8g`. Never observed because a cold start was
        # usually one request wide; the startup warmup below makes several
        # first-loads genuinely concurrent, so the claim has to become true
        # before the thread that relies on it exists.
        with self._load_lock:
            pipe = self._models.get(name)
            if pipe is not None:
                return pipe          # another thread loaded it while we waited
            return self._load_locked(name, model_id, task, **kwargs)

    def _load_locked(self, name: str, model_id: str, task: str,
                     **kwargs: Any) -> Optional[Any]:
        """The body of `_load`, called with `_load_lock` held."""
        state = self._state.get(name)
        if state is not None:
            if state["status"] == MODEL_STATUS_UNAVAILABLE:
                return None  # permanent: no retry can succeed
            if state["status"] == MODEL_STATUS_FAILED and not self._retry_due(state):
                return None  # transient, but not due for another attempt yet

        if not _TRANSFORMERS_AVAILABLE:
            self._record(
                name,
                model_id,
                MODEL_STATUS_UNAVAILABLE,
                error="transformers library not installed",
            )
            return None

        attempts = (state or {}).get("attempts", 0) + 1
        try:
            logger.info(
                "Loading ML model [%s] %s (attempt %d/%d) …",
                name, model_id, attempts, MODEL_LOAD_MAX_ATTEMPTS,
            )
            pipe = hf_pipeline(
                task,
                model=model_id,
                device=-1,  # CPU; set CUDA_VISIBLE_DEVICES + device=0 for GPU
                model_kwargs={"cache_dir": MODELS_CACHE_DIR},
                **kwargs,
            )
        except Exception as exc:
            # error, not warning: transformers is installed, so this model is
            # expected to exist. A detector silently running without its model
            # is exactly the failure that must not look like a quiet success.
            logger.error(
                "Failed to load ML model [%s] %s (attempt %d/%d): %s",
                name, model_id, attempts, MODEL_LOAD_MAX_ATTEMPTS, exc,
            )
            self._record(
                name, model_id, MODEL_STATUS_FAILED, error=str(exc), attempts=attempts
            )
            return None

        self._models[name] = pipe
        self._record(name, model_id, MODEL_STATUS_LOADED, attempts=attempts)
        logger.info("ML model [%s] loaded successfully", name)
        return pipe

    # ------------------------------------------------------------------
    # Load-state bookkeeping
    # ------------------------------------------------------------------

    def _record(
        self,
        name: str,
        model_id: str,
        status: str,
        *,
        error: Optional[str] = None,
        attempts: Optional[int] = None,
    ) -> None:
        prev = self._state.get(name, {})
        self._state[name] = {
            "model": model_id,
            "status": status,
            "attempts": attempts if attempts is not None else prev.get("attempts", 0),
            "last_error": error,
            "last_attempt_ts": time.time(),
        }

    @staticmethod
    def _retry_due(state: Dict[str, Any]) -> bool:
        """Whether a previously-failed load may be attempted again now."""
        if int(state.get("attempts", 0)) >= MODEL_LOAD_MAX_ATTEMPTS:
            return False
        elapsed = time.time() - float(state.get("last_attempt_ts", 0.0))
        return elapsed >= MODEL_LOAD_RETRY_COOLDOWN_SECONDS

    def model_status(self) -> Dict[str, Dict[str, Any]]:
        """Report what is ACTUALLY loaded in this process, right now.

        Pure read of in-process state — it never calls `_load`, so a readiness
        probe can never trigger a model download or a cold load as a side
        effect. Models nothing has needed yet report `not_attempted`, which is
        deliberately not the same as `failed`.
        """
        out: Dict[str, Dict[str, Any]] = {}
        for name, model_id in MODEL_IDS.items():
            state = self._state.get(name)
            if state is None:
                out[name] = {
                    "model": model_id,
                    "status": (
                        MODEL_STATUS_NOT_ATTEMPTED
                        if _TRANSFORMERS_AVAILABLE
                        else MODEL_STATUS_UNAVAILABLE
                    ),
                    "attempts": 0,
                    "last_error": (
                        None
                        if _TRANSFORMERS_AVAILABLE
                        else "transformers library not installed"
                    ),
                    "retryable": False,
                }
                continue
            status = state["status"]
            out[name] = {
                "model": state.get("model", model_id),
                "status": status,
                "attempts": int(state.get("attempts", 0)),
                "last_error": state.get("last_error"),
                "retryable": (
                    status == MODEL_STATUS_FAILED
                    and int(state.get("attempts", 0)) < MODEL_LOAD_MAX_ATTEMPTS
                ),
            }
        return out

    # ------------------------------------------------------------------
    # Accessors
    # ------------------------------------------------------------------

    def prompt_injection_pipeline(self) -> Optional[Any]:
        return self._load(
            "prompt_injection",
            ML_PROMPT_INJECTION_MODEL,
            "text-classification",
            truncation=True,
            max_length=512,
        )

    def ner_pipeline(self) -> Optional[Any]:
        return self._load(
            "ner_pii",  # key matches MODEL_IDS so /ready can report this model
            ML_NER_PII_MODEL,
            "ner",
            aggregation_strategy="simple",
        )

    def ner_phi_pipeline(self) -> Optional[Any]:
        """Clinical de-identification model. Separate load from ner_pii.

        Kept as its own registry entry so /ready reports it independently: a
        deployment can have PII detection healthy and PHI detection missing,
        and a HIPAA tenant needs to be told that rather than shown a clean
        scan produced by a model that was never loaded.
        """
        return self._load(
            "ner_phi",  # key matches MODEL_IDS so /ready can report this model
            ML_NER_PHI_MODEL,
            "ner",
            # "first", NOT "simple". "simple" groups adjacent same-label
            # tokens but does no word-level aggregation, so an identifier
            # split across subwords stays split: 4451227 comes back as
            # "44512" (0.984) and "27" (0.424), and only the first clears
            # NER_PII_CONFIDENCE_THRESHOLD. "first" merges the subwords of a
            # word before grouping and assigns the merged entity the LEADING
            # token's label and score -- the confident one here.
            #
            # This is defence in depth, not the guarantee. redact_spans
            # expands every span to token bounds regardless, so a model or
            # transformers version that aggregates differently still cannot
            # emit a partial identifier. See _expand_span_to_token_bounds.
            aggregation_strategy="first",
        )

    def toxicity_pipeline(self) -> Optional[Any]:
        return self._load(
            "toxicity",
            ML_TOXICITY_MODEL,
            "text-classification",
            truncation=True,
            max_length=512,
        )

    def zero_shot_pipeline(self) -> Optional[Any]:
        return self._load(
            "zero_shot",
            ML_ZERO_SHOT_MODEL,
            "zero-shot-classification",
        )


# Module-level singleton
_registry = MLModelRegistry()


#: Warm the models at startup rather than on a customer's request.
WARM_MODELS_AT_STARTUP = os.getenv(
    "DETECTION_WARM_MODELS", "true").strip().lower() in {"1", "true", "yes", "on"}

#: Observable state of that warmup. It exists so /ready can tell three things
#: apart that all looked identical before: a model nothing has needed yet, a
#: model the warmup has not reached, and a model the warmup tried and failed.
_WARMUP: Dict[str, Any] = {
    "enabled": WARM_MODELS_AT_STARTUP,
    "state": "not_started",     # not_started | running | finished | disabled
    "started_at": None,
    "finished_at": None,
    "pending": [],
}
_WARMUP_LOCK = threading.Lock()


def warmup_status() -> Dict[str, Any]:
    """A pure read, like model_status(). Never triggers a load."""
    with _WARMUP_LOCK:
        return dict(_WARMUP)


def _warm_models() -> None:
    for name in MODEL_IDS:
        try:
            load_pipeline(name)
        except Exception as exc:                       # noqa: BLE001
            # A warmup that can kill the process is worse than no warmup: the
            # container would crash-loop on a bad model path instead of
            # serving on heuristic fallbacks, which is what the whole
            # degraded-but-answering design exists to avoid. _load already
            # records the reason; this is the last-resort net.
            logger.error("model warmup failed for %s: %s", name, exc)
        finally:
            with _WARMUP_LOCK:
                if name in _WARMUP["pending"]:
                    _WARMUP["pending"].remove(name)
    with _WARMUP_LOCK:
        _WARMUP["state"] = "finished"
        _WARMUP["finished_at"] = time.time()
    logger.info("model warmup finished; status=%s", model_status())


def start_model_warmup() -> None:
    """Load every declared model in the background, off the request path.

    MEASURED on the box 2026-08-07: the first /scan after a container restart
    paid +1.73s to load weights, and the first scan of the demo corpus through
    the public path took 5307ms against the proxy's 5.0s INSPECTION_TIMEOUT --
    over budget, and the proxy fails closed. Steady state was 1.8-2.1s. So the
    request most likely to be blocked was the first one anybody made.

    IN A THREAD, NOT INLINE. detection's healthcheck hits /health every 10s
    with 3 retries and NO start_period, and three other services gate on
    `condition: service_healthy`. Blocking uvicorn's startup for the ~2s of
    loading would eat most of that 30s budget for no benefit, and on a cold
    page cache it would cascade.

    It consumes one of MODEL_LOAD_MAX_ATTEMPTS (3) per model. That is
    deliberate and leaves two for the request path: a model that cannot load
    at startup is overwhelmingly one that will not load at request time
    either, and the retry cooldown still applies.
    """
    if not WARM_MODELS_AT_STARTUP:
        with _WARMUP_LOCK:
            _WARMUP["state"] = "disabled"
        return
    with _WARMUP_LOCK:
        if _WARMUP["state"] != "not_started":
            return                      # idempotent: never two warmup threads
        _WARMUP["state"] = "running"
        _WARMUP["started_at"] = time.time()
        _WARMUP["pending"] = list(MODEL_IDS)
    threading.Thread(target=_warm_models, name="model-warmup",
                     daemon=True).start()


#: Registry name → the accessor that loads it. Not derivable from the name
#: (`ner_pii` is served by `ner_pipeline`), so it is written out and pinned by
#: test_every_model_is_declared_and_seeded.py against MODEL_IDS.
PIPELINE_ACCESSORS: Dict[str, str] = {
    "prompt_injection": "prompt_injection_pipeline",
    "ner_pii":          "ner_pipeline",
    "ner_phi":          "ner_phi_pipeline",
    "toxicity":         "toxicity_pipeline",
    "zero_shot":        "zero_shot_pipeline",
}


def load_pipeline(name: str) -> Optional[Any]:
    """Load one model BY REGISTRY NAME, through the service's own accessor.

    Exists so the seeding script can verify a model the exact way the service
    loads it, rather than by making its own `pipeline(task, model=id)` call.
    That distinction is not academic -- it was a live defect. The seeder's
    verification step built its own call, which resolved the cache from the
    environment (`HF_HOME=/models` → `/models/hub`) while the service passes
    `cache_dir=/models` explicitly and the models actually live at `/models`.
    Every model "failed to load offline" while the running service was loading
    all five without complaint.

    Anything checking whether a model is loadable must go through here, so it
    inherits the real task, the real aggregation strategy and the real cache
    directory. A verifier that disagrees with the thing it verifies is worse
    than no verifier -- this is the same two-sources-of-truth shape as the
    half-parameterised entity map in redact_spans.
    """
    accessor = PIPELINE_ACCESSORS.get(name)
    if accessor is None:
        raise KeyError(
            f"no pipeline accessor for {name!r}; known: "
            f"{sorted(PIPELINE_ACCESSORS)}"
        )
    return getattr(_registry, accessor)()


def model_status() -> Dict[str, Dict[str, Any]]:
    """Load-state of every configured model. Never triggers a load.

    Exposed for the readiness probe: /ready must report the models that are
    really resident, not the ones the service intends to have.
    """
    return _registry.model_status()


# ---------------------------------------------------------------------------
# Prompt Injection ML Detector
# ---------------------------------------------------------------------------

# Label names used by protectai/deberta-v3-base-prompt-injection-v2
_INJECTION_POSITIVE_LABELS = {"INJECTION", "LABEL_1", "1"}


class PromptInjectionMLDetector:
    """Fine-tuned DeBERTa classifier for prompt injection detection.

    Primary model: protectai/deberta-v3-base-prompt-injection-v2
    Returns ``None`` when the model is unavailable (callers fall back to heuristics).
    """

    def detect(self, text: str) -> Optional[Dict[str, Any]]:
        pipe = _registry.prompt_injection_pipeline()
        if pipe is None:
            return None
        try:
            raw = pipe(text[:1024] or "")
            item = raw[0] if isinstance(raw[0], dict) else raw[0][0]
            label = str(item.get("label", "")).upper()
            score = float(item.get("score", 0.0))
            is_injection = label in _INJECTION_POSITIVE_LABELS
            confidence = score if is_injection else (1.0 - score)
            return {
                "available": True,
                "label": label,
                "confidence": round(confidence, 4),
                "is_injection": is_injection,
                "model": ML_PROMPT_INJECTION_MODEL,
            }
        except Exception as exc:
            # available=False, not True. The caller treats an available detector
            # as authoritative and blends its confidence at 0.75 weight against
            # the heuristic's 0.25. Reporting available=True with confidence 0.0
            # therefore caps the ensemble at 0.25 against a 0.66 threshold: a
            # crashing model made prompt-injection detection mathematically
            # unable to fire, no matter how blatant the attack, while a merely
            # *missing* model fell back to heuristics and detected it. Failing
            # loudly here restores the heuristic fallback path.
            logger.error("Prompt injection ML inference error: %s", exc)
            return {
                "available": False,
                "confidence": 0.0,
                "is_injection": False,
                "error": str(exc),
            }


# ---------------------------------------------------------------------------
# NER-based PII Detector
# ---------------------------------------------------------------------------

# Standard CoNLL entity types → CyberArmor PII category
_NER_PII_GROUPS: Dict[str, str] = {
    "PER": "person_name",
    "PERSON": "person_name",
    "LOC": "location",
    "LOCATION": "location",
    "ORG": "organization",
    "ORGANIZATION": "organization",
    "GPE": "geopolitical_entity",
}

# Extended sensitive entity types (from models that produce these labels)
_NER_SENSITIVE_GROUPS: Dict[str, str] = {
    "CREDIT_CARD": "credit_card",
    "SSN": "ssn",
    "PHONE_NUM": "phone_number",
    "PHONE": "phone_number",
    "EMAIL": "email_address",
    "IP_ADDRESS": "ip_address",
    "IBAN_CODE": "iban",
    "CRYPTO": "crypto_address",
    "URL": "url",
}

# Path B (Step 2 follow-up): NER groups → redact-catalog class names. The
# regex catalog in services/detection/main.py covers structured patterns
# (emails, SSNs, credit cards, etc) precisely. NER catches the unstructured
# variants the regex misses — person names, organization names, geographic
# locations, free-form addresses. Redact policies opt in by listing these
# classes in `redact_classes`.
NER_GROUP_TO_REDACT_CLASS: Dict[str, str] = {
    "PER":          "pii.person_name",
    "PERSON":       "pii.person_name",
    "LOC":          "pii.location",
    "LOCATION":     "pii.location",
    "GPE":          "pii.location",
    "ORG":          "pii.organization",
    "ORGANIZATION": "pii.organization",
    "IP_ADDRESS":   "pii.ip_address",
    "URL":          "pii.url",
    "CRYPTO":       "pii.crypto_address",
}

# Inverse — redact_class → list of NER groups that produce it. Used by the
# redact pipeline to know which entities to extract for each requested class.
REDACT_CLASS_TO_NER_GROUPS: Dict[str, List[str]] = {}
for _g, _c in NER_GROUP_TO_REDACT_CLASS.items():
    REDACT_CLASS_TO_NER_GROUPS.setdefault(_c, []).append(_g)


# ---------------------------------------------------------------------------
# PHI entity groups → redact-catalog classes.
#
# WHAT THE ML LAYER ADDS OVER THE REGEX LAYER, SPECIFICALLY.
# The phi.* regexes in main.py are precise but literal: phi.mrn only fires
# when the string "MRN" (or a listed synonym) sits next to the value, because
# an institution-assigned record number has no national format and a bare
# digit run cannot be told from an invoice number. Clinical prose does not
# oblige -- "admitted under record 4451227 on the 3rd" carries an identifier
# with no label the regex knows. A de-identification model reads the sentence
# instead of the neighbourhood, which is exactly the unstructured case the
# NER layer was introduced for on the PII side.
#
# Group names are unioned across the label conventions of the common i2b2-
# derived de-id models (obi/deid_roberta_i2b2, and the older i2b2-2014 tag
# set), because the deployment can swap ML_NER_PHI_MODEL and the mapping
# should not silently stop matching. An unrecognised group is ignored, never
# guessed at.
NER_PHI_GROUP_TO_REDACT_CLASS: Dict[str, str] = {
    # Record / identifier numbers
    "MEDICALRECORD":  "phi.mrn",
    "MEDICAL_RECORD": "phi.mrn",
    "IDNUM":          "phi.mrn",
    "ID":             "phi.mrn",
    # Health plan / beneficiary identifiers
    "HEALTHPLAN":     "phi.health_plan_id",
    "HEALTH_PLAN":    "phi.health_plan_id",
    "BIOID":          "phi.health_plan_id",
}

# DELIBERATELY phi.* ONLY, AND THIS COST A ROUND OF FAILING TESTS TO LEARN.
#
# The clinical model also emits DOCTOR, PATIENT, HOSPITAL, LOCATION, DATE and
# friends, and mapping those onto pii.person_name / pii.organization /
# pii.location looked like free recall. It was not free: this map is what
# redact_spans uses to decide which requested classes DEPEND on the model, and
# therefore which classes go unredacted when it is missing. Mapping pii.*
# through it made every policy asking for pii.person_name depend on BOTH
# models, so a deployment without the PHI model reported regex-only redactions
# as incomplete -- failing closed on work that had actually been done
# correctly. test_regex_only_policy_still_redacts_without_a_ner_model and
# test_incomplete_response_names_what_it_could_not_mask both caught it.
#
# The PII model already covers names, organisations and locations, so nothing
# is lost by scoping this map to the classes for which the clinical model is
# the ONLY source. Recovering the clinical model's extra recall on pii.*
# classes needs a second map used for span extraction but NOT for the
# dependency calculation -- worth doing, deliberately not smuggled in here.

REDACT_CLASS_TO_NER_PHI_GROUPS: Dict[str, List[str]] = {}
for _g, _c in NER_PHI_GROUP_TO_REDACT_CLASS.items():
    REDACT_CLASS_TO_NER_PHI_GROUPS.setdefault(_c, []).append(_g)

# Cap NER input size for redaction calls. The pipeline truncates at the
# model's max_position_embeddings (typically 512 tokens ≈ 2048 chars)
# anyway. Going past that wastes time and may raise tokenizer warnings.
MAX_NER_INPUT_CHARS = 2048

#: Longest entity we expect to straddle a window seam. Consecutive windows
#: overlap by this much so an entity lying across the boundary is seen whole by
#: at least one pass -- without it, a name split by the seam is invisible to
#: both. Generous on purpose: an over-long overlap costs a little duplicate
#: inference, a short one costs a leaked identifier.
NER_WINDOW_OVERLAP_CHARS = int(os.getenv("NER_WINDOW_OVERLAP_CHARS", "256"))

#: Ceiling on windows per redaction, i.e. on inference passes. The proxy will
#: hand over bodies up to MAX_BODY_SIZE (10 MB), which at 2 KB a window is
#: 5,000 passes -- minutes of CPU inside a 5 second budget. Beyond this the
#: result is reported INCOMPLETE rather than quietly truncated, which makes
#: /scan/redact fail closed instead of returning text it never finished
#: masking.
MAX_NER_WINDOWS = int(os.getenv("MAX_NER_WINDOWS", "24"))


def _ner_char_ceiling() -> int:
    """Characters the window budget can actually reach.

    NOT MAX_NER_WINDOWS * MAX_NER_INPUT_CHARS. Consecutive windows overlap, so
    each one after the first advances by only `stride`. At the defaults that is
    43,264 characters, not 49,152 -- and the error message quoted the larger,
    wrong figure until this was computed instead of multiplied.
    """
    stride = max(1, MAX_NER_INPUT_CHARS - NER_WINDOW_OVERLAP_CHARS)
    return (MAX_NER_WINDOWS - 1) * stride + MAX_NER_INPUT_CHARS


def _ner_windows(text: str) -> List[Tuple[int, str]]:
    """Split `text` into overlapping (offset, chunk) pairs the model can read.

    WHY THIS EXISTS. redact_spans used to run the model over
    ``text[:MAX_NER_INPUT_CHARS]`` and return ``complete=True`` regardless, so
    everything past 2,048 characters was never looked at -- and this is the
    REDACTION path, whose output the proxy sets as the outbound request body.
    A customer name at character 3,000 was forwarded to the model provider in
    the clear, with ``redaction_complete: true`` in the response.

    The cap itself is legitimate: it is roughly the model's token window. The
    defect was treating "more than the model can read at once" as "the rest
    does not exist".

    Returns at most MAX_NER_WINDOWS windows; the caller checks whether they
    cover the whole string and reports incomplete when they do not.
    """
    if not text:
        return []
    # No fast path for short text: the loop below already emits exactly one
    # window for anything under MAX_NER_INPUT_CHARS, because the first stride
    # steps past the end. A sabotage run proved the branch redundant -- deleting
    # it failed no test, which for a special case is the right answer and the
    # reason not to keep it.
    stride = max(1, MAX_NER_INPUT_CHARS - NER_WINDOW_OVERLAP_CHARS)
    windows: List[Tuple[int, str]] = []
    offset = 0
    while offset < len(text) and len(windows) < MAX_NER_WINDOWS:
        windows.append((offset, text[offset:offset + MAX_NER_INPUT_CHARS]))
        # Stop as soon as a window reaches the end. Without this, any body
        # longer than the stride but shorter than the window -- 1,793 to 2,048
        # characters -- paid a second inference pass over a tail the first
        # window had already read.
        if offset + MAX_NER_INPUT_CHARS >= len(text):
            break
        offset += stride
    return windows


def _ner_windows_cover(text: str, windows: List[Tuple[int, str]]) -> bool:
    """Did those windows actually reach the end of the text?"""
    if not text:
        return True
    if not windows:
        return False
    last_offset, last_chunk = windows[-1]
    return last_offset + len(last_chunk) >= len(text)


# Characters that may sit INSIDE an identifier without ending it. A run of
# alphanumerics is the common case; these three appear inside real identifiers
# (MBI 1EG4-TE5-MK73, ICD-10 E11.9, snake_case keys) and count as internal
# ONLY when alphanumerics flank them on both sides — so a sentence-final "."
# or a trailing dash never drags a span outward into prose.
_IDENTIFIER_INNER_PUNCT = frozenset("-_.")


def _expand_span_to_token_bounds(
    text: str, start: int, end: int
) -> Tuple[int, int]:
    """Grow (start, end) outward until neither edge sits mid-token.

    THE INVARIANT: no redaction span may end in the middle of an identifier.

    Subword tokenizers split on statistical boundaries, not semantic ones.
    obi/deid_roberta_i2b2 splits the record number 4451227 into "44512"
    (score 0.984) and "27" (score 0.424), and only the first clears the
    confidence threshold. Redacting that span alone emits

        record [REDACTED:phi.mrn]27

    — a string that LOOKS redacted while still carrying part of the
    identifier, which is worse than an obvious miss because nothing
    downstream flags it. DATE splits the same way (04/ + 12/2024), so this
    is a property of subword tokenization, not a quirk of one value.

    Widening is always the safe direction here: over-redaction costs recall
    on benign text, under-redaction discloses PHI to an external provider.

    Deliberately INDEPENDENT of the pipeline's aggregation_strategy. That
    setting is the first line of defence, but it can be mis-set, overridden
    per deployment, or quietly changed by a transformers upgrade. This is
    the guarantee that does not depend on it, and it holds for any model
    whose tokenizer splits an identifier the same way.
    """
    n = len(text)
    start = max(0, min(start, n))
    end = max(start, min(end, n))
    if start == end:
        # Degenerate or out-of-range input. An empty span covers no token, so
        # there is nothing to be in the middle of — expanding it would invent
        # coverage out of a bad offset. redact_spans rejects start >= end
        # before calling, so this is belt-and-braces.
        return start, end

    def _alnum_at(i: int) -> bool:
        return 0 <= i < n and text[i].isalnum()

    while start > 0:
        prev = text[start - 1]
        if prev.isalnum() or (
            prev in _IDENTIFIER_INNER_PUNCT and _alnum_at(start - 2)
        ):
            start -= 1
        else:
            break

    while end < n:
        nxt = text[end]
        if nxt.isalnum() or (
            nxt in _IDENTIFIER_INNER_PUNCT and _alnum_at(end + 1)
        ):
            end += 1
        else:
            break

    return start, end


class RedactSpanResult(NamedTuple):
    """Outcome of a NER redaction-span extraction.

    `redact_spans` used to return a bare ``List[tuple]``, which made these
    three situations indistinguishable to the caller:

      * the model ran and found no maskable entities         (spans == [])
      * the model was never loaded                           (spans == [])
      * inference raised part-way through the entity loop    (spans == the
        entities collected before the raise)

    The third is the dangerous one. `_redact_text` merged whatever came back
    with the regex spans and returned text the caller then forwarded to an
    external model provider. A partial span set produces text that *looks*
    redacted — some entities masked, the rest passed through in the clear —
    and the caller had no field to check.

    `complete` is that field. It is True only when the NER stage did every
    piece of work the requested classes needed. `spans` is still populated on
    a partial failure (a genuine PII location does not stop being one because
    the next one raised), but it may not be treated as the whole answer.
    """

    spans: List[Tuple[int, int, str]]
    complete: bool
    reason: Optional[str] = None
    error: Optional[str] = None
    model: Optional[str] = None
    # The subset of the caller's requested classes that only NER can produce.
    # Empty when the request needed nothing from NER — in which case a missing
    # NER model does not make the redaction incomplete.
    ner_classes: Tuple[str, ...] = ()


class NERPIIDetector:
    """Token-classification NER model for PII entity extraction.

    Primary model: dslim/bert-base-NER
    Never raises.

    Like ToxicityDetector, `detect` has three distinguishable outcomes:
      * ``[]``                                  – ran, found no PII (clean)
      * findings carrying ``available: True``   – ran, found PII
      * a member carrying ``available: False``  – did NOT run; nothing was
        assessed. Callers must surface this rather than reading the absence
        of findings as an absence of PII.
    """

    # Parameterised so NERPHIDetector can reuse every line of the
    # fail-closed logic below against a clinical de-identification model.
    # Defaults are the PII values, so NERPIIDetector() is unchanged.
    #
    # BOTH directions of the mapping must be overridden together. _group_map
    # (class -> groups) decides which entities to ask for; _class_map
    # (group -> class) decides what a returned entity becomes. redact_spans
    # used to parameterise only the first and hardcode the PII map for the
    # second, so every PHI entity passed the group filter and the confidence
    # threshold and was then dropped by a lookup that could not contain it.
    _model_id = ML_NER_PII_MODEL
    _status_key = "ner_pii"
    _group_map = REDACT_CLASS_TO_NER_GROUPS
    _class_map = NER_GROUP_TO_REDACT_CLASS

    def _pipeline(self):
        return _registry.ner_pipeline()

    def _unavailable(self, reason: str, error: Optional[str]) -> Dict[str, Any]:
        return {
            "available": False,
            "reason": reason,
            "error": error,
            "model": self._model_id,
            "detector": "ner_model",
        }

    def detect(self, text: str) -> List[Dict[str, Any]]:
        pipe = self._pipeline()
        if pipe is None:
            # Previously ``return []`` — byte-identical to "scanned this text
            # and it contains no PII". /scan/sensitive-data reported a clean
            # DLP verdict for content the PII model never saw.
            state = _registry.model_status().get(self._status_key, {})
            return [self._unavailable("model_not_loaded", state.get("last_error"))]
        # Bound before the try: the except handler returns the findings
        # collected so far, and `pipe(...)` itself is the most likely thing to
        # raise — at which point nothing inside the try has run yet.
        findings: List[Dict[str, Any]] = []
        try:
            entities = pipe(text[:2048] or "")
            for ent in entities or []:
                group = str(
                    ent.get("entity_group", ent.get("entity", ""))
                ).upper()
                word = str(ent.get("word", ""))
                score = float(ent.get("score", 0.0))
                if score < NER_PII_CONFIDENCE_THRESHOLD:
                    continue
                if group in _NER_PII_GROUPS:
                    findings.append(
                        {
                            "available": True,
                            "type": "sensitive_data",
                            "subtype": self._status_key,
                            "entity_type": _NER_PII_GROUPS[group],
                            "value": word[:120],
                            "confidence": round(score, 4),
                            "severity": "medium",
                            "detector": "ner_model",
                            "model": self._model_id,
                        }
                    )
                elif group in _NER_SENSITIVE_GROUPS:
                    findings.append(
                        {
                            "available": True,
                            "type": "sensitive_data",
                            "subtype": "ner_sensitive",
                            "entity_type": _NER_SENSITIVE_GROUPS[group],
                            "value": word[:120],
                            "confidence": round(score, 4),
                            "severity": "high",
                            "detector": "ner_model",
                            "model": self._model_id,
                        }
                    )
            return findings
        except Exception as exc:
            # error, not warning: the model is loaded, so this is a real
            # inference failure and the PII coverage for this text is gone.
            logger.error("NER PII detection error: %s", exc)
            # Whatever entities were collected before the raise are kept —
            # they are true positives and adding them can only surface more
            # PII. The unavailable marker rides along so the caller can never
            # read the result as a complete assessment. (Contrast
            # `redact_spans`, where partial output is NOT safe: there a
            # partial answer becomes text the caller believes is masked.)
            return findings + [self._unavailable("inference_error", str(exc))]

    def redact_spans(
        self, text: str, requested_classes: List[str]
    ) -> RedactSpanResult:
        """Return the (start, end, redact_class) spans for NER entities
        matching the requested redact classes, plus whether the NER stage
        actually completed.

        Used by the /scan/redact pipeline to mask NER-detected PII (person
        names, locations, organizations, etc.) that the regex catalog can't
        catch. The aggregation_strategy="simple" config used by the NER
        pipeline gives us per-entity character offsets directly.

        This is a REDACTION path, not a detection path, and that changes what
        a failure means. A detector that misses something produces a missed
        alert. A redactor that misses something produces *text the caller
        believes is safe to send onward* — and `_redact_text`'s output is set
        as the outbound request body by the proxy, so it leaves the tenant
        boundary and reaches an external model provider. The old signature
        (a bare list) could not express "I did not finish", so the caller had
        no way to refuse. `complete` is that expression; see RedactSpanResult.
        """
        # Which NER groups do we need to extract for these classes?
        wanted_groups: set = set()
        ner_classes: List[str] = []
        for cls in requested_classes or []:
            groups = self._group_map.get(cls, [])
            if groups:
                ner_classes.append(cls)
            for g in groups:
                wanted_groups.add(g)

        if not text or not requested_classes or not wanted_groups:
            # Nothing here depends on NER, so NER cannot have failed to do it.
            # This is a genuine "complete" — the distinction matters, because
            # a policy redacting only pii.email and pii.ssn must keep working
            # on a host with no NER model at all.
            return RedactSpanResult(
                spans=[], complete=True, model=self._model_id,
                ner_classes=tuple(ner_classes),
            )

        pipe = self._pipeline()
        if pipe is None:
            # The caller asked for classes only NER can produce and NER is not
            # here. Previously this returned [] — indistinguishable from "the
            # text contains no person names", so the redacted body went out
            # with every name in it and class_counts said the job was done.
            state = _registry.model_status().get(self._status_key, {})
            logger.error(
                "NER redaction unavailable: model not loaded; classes=%s err=%s",
                ",".join(sorted(ner_classes)), state.get("last_error"),
            )
            return RedactSpanResult(
                spans=[],
                complete=False,
                reason="model_not_loaded",
                error=state.get("last_error"),
                model=self._model_id,
                ner_classes=tuple(ner_classes),
            )

        spans: List[Tuple[int, int, str]] = []
        # WINDOWED, not truncated. See _ner_windows: the old code passed
        # text[:MAX_NER_INPUT_CHARS] and claimed complete=True, so anything
        # past 2,048 characters was forwarded to the provider unmasked while
        # the response said the redaction had finished.
        windows = _ner_windows(text)
        covered = _ner_windows_cover(text, windows)
        try:
            for window_offset, chunk in windows:
                entities = pipe(chunk or "")
                for ent in entities or []:
                    group = str(
                        ent.get("entity_group", ent.get("entity", ""))
                    ).upper()
                    if group not in wanted_groups:
                        continue
                    score = float(ent.get("score", 0.0))
                    if score < NER_PII_CONFIDENCE_THRESHOLD:
                        continue
                    start = ent.get("start")
                    end = ent.get("end")
                    if start is None or end is None or start >= end:
                        continue
                    cls = self._class_map.get(group)
                    if cls and cls in requested_classes:
                        # OFFSETS ARE WINDOW-RELATIVE and must be mapped back
                        # before anything downstream touches them. A span left
                        # in window coordinates does not merely miss the
                        # identifier, it masks whatever sits at that offset in
                        # the full text -- corrupting the prompt AND leaking
                        # the name.
                        abs_start = window_offset + int(start)
                        abs_end = window_offset + int(end)
                        # Never hand back a span that stops mid-identifier; see
                        # _expand_span_to_token_bounds. Expansion is against the
                        # FULL text, not the window the model saw, because
                        # these offsets are applied to the full text downstream.
                        s, e = _expand_span_to_token_bounds(
                            text, abs_start, abs_end
                        )
                        # Two subword fragments of one value expand to the SAME
                        # span, and overlapping windows now see the same entity
                        # twice by design. Collapse here so the span list stays
                        # a set of distinct locations for every caller, not just
                        # for _redact_text (which dedupes again on its merged
                        # list).
                        if (s, e, cls) not in spans:
                            spans.append((s, e, cls))
        except Exception as exc:
            # The defect: this handler swallowed the exception and fell
            # through to `return spans`, handing back however much of the
            # entity list had been processed before the raise — with no way
            # to tell it apart from a finished pass. `_redact_text` then
            # produced text containing unmasked names that the caller was
            # told had been redacted.
            logger.error("NER redact_spans error: %s", exc)
            return RedactSpanResult(
                spans=spans,       # partial: real hits, but NOT the whole set
                complete=False,
                reason="inference_error",
                error=str(exc),
                model=self._model_id,
                ner_classes=tuple(ner_classes),
            )
        if not covered:
            # The body needed more windows than MAX_NER_WINDOWS allows, so a
            # tail of it was never read. `spans` holds real hits and is kept --
            # a genuine PII location does not stop being one because the body
            # was long -- but this is NOT the whole answer, and /scan/redact
            # fails closed on complete=False rather than returning text it did
            # not finish masking. Reporting this truthfully is the entire point:
            # the previous code returned complete=True here and the unread tail
            # crossed the tenant boundary.
            logger.error(
                "NER redaction incomplete: %d chars exceeded %d windows of %d "
                "chars; the tail was NOT inspected",
                len(text), MAX_NER_WINDOWS, MAX_NER_INPUT_CHARS,
            )
            return RedactSpanResult(
                spans=spans,
                complete=False,
                reason="input_too_long",
                error=(f"{len(text)} characters exceeds the "
                       f"{_ner_char_ceiling()}-character redaction ceiling"),
                model=self._model_id,
                ner_classes=tuple(ner_classes),
            )
        return RedactSpanResult(
            spans=spans, complete=True, model=self._model_id,
            ner_classes=tuple(ner_classes),
        )


# ---------------------------------------------------------------------------
# Toxicity Detector
# ---------------------------------------------------------------------------

class NERPHIDetector(NERPIIDetector):
    """Clinical de-identification model for PHI entity extraction.

    Every line of the fail-closed logic is inherited: the three
    distinguishable outcomes (clean / found / did-not-run), the bounded
    partial-failure handling in redact_spans, and the refusal to report an
    unloaded model as a clean scan. Only the model, the /ready key and the
    entity-group map differ.

    Why a separate model rather than a tuned threshold on the PII one is
    documented at ML_NER_PHI_MODEL: dslim/bert-base-NER's label set is
    PER/LOC/ORG/MISC, so it cannot emit a medical-record entity at any
    confidence. A PHI detector pointed at it would be permanently, silently
    clean -- which for a HIPAA tenant is the worst possible failure shape,
    because the compliance control reads green off the back of it.
    """

    _model_id = ML_NER_PHI_MODEL
    _status_key = "ner_phi"
    _group_map = REDACT_CLASS_TO_NER_PHI_GROUPS
    _class_map = NER_PHI_GROUP_TO_REDACT_CLASS

    def _pipeline(self):
        return _registry.ner_phi_pipeline()


_TOXIC_POSITIVE_LABELS = {"TOXIC", "LABEL_1", "1"}


class ToxicityDetector:
    """Binary toxicity classifier.

    Primary model: unitary/toxic-bert

    Three distinguishable outcomes — the caller must be able to tell them apart:
      * finding dict with ``available: True``  – ran, text is toxic
      * ``None``                               – ran, text is below threshold (clean)
      * dict with ``available: False``         – did NOT run; nothing was assessed
    """

    def detect(self, text: str) -> Optional[Dict[str, Any]]:
        pipe = _registry.toxicity_pipeline()
        if pipe is None:
            # The model never loaded. Previously this returned None, which the
            # caller rendered as "no toxicity findings" — identical to a clean
            # verdict. Report the gap instead; the registry has already logged
            # the load failure at error level.
            state = _registry.model_status().get("toxicity", {})
            return {
                "available": False,
                "reason": "model_not_loaded",
                "error": state.get("last_error"),
                "model": ML_TOXICITY_MODEL,
            }
        try:
            raw = pipe(text[:512] or "")
            item = raw[0] if isinstance(raw[0], dict) else raw[0][0]
            label = str(item.get("label", "")).upper()
            score = float(item.get("score", 0.0))
            is_toxic = label in _TOXIC_POSITIVE_LABELS
            confidence = score if is_toxic else (1.0 - score)
            if confidence < TOXICITY_ML_THRESHOLD:
                return None  # ran, and the text really is clean
            return {
                "available": True,
                "type": "harmful_content",
                "subtype": "toxicity",
                "label": label,
                "confidence": round(confidence, 4),
                "threshold": TOXICITY_ML_THRESHOLD,
                "severity": "high" if confidence >= 0.90 else "medium",
                "detector": "toxicity_model",
                "model": ML_TOXICITY_MODEL,
            }
        except Exception as exc:
            # Same latent defect the prompt-injection detector carried (fixed
            # in 65a340b): the exception handler produced the *clean* answer.
            # An inference crash returned None, exactly like a benign text, so
            # a toxicity model that crashed on every request looked like a
            # service that never saw anything toxic. available=False + error
            # level makes the crash impossible to mistake for a pass.
            logger.error("Toxicity ML inference error: %s", exc)
            return {
                "available": False,
                "reason": "inference_error",
                "error": str(exc),
                "model": ML_TOXICITY_MODEL,
            }


# ---------------------------------------------------------------------------
# Zero-Shot Threat Classifier
# ---------------------------------------------------------------------------

#: The labels this detector is asked to score -- and, by construction, exactly
#: the labels its one consumer acts on.
#:
#: THIS LIST USED TO HAVE FIVE ENTRIES AND COST 1.6 SECONDS PER SCAN.
#:
#: MEASURED on the box 2026-08-07, per detector, warm median at a 2,000-char
#: body, against the local proxy's 5.0s INSPECTION_TIMEOUT:
#:
#:     output-safety (bart-large-mnli)   2.72s      <- 75% of the whole scan
#:     sensitive-data (bert-NER)         0.42s
#:     prompt-injection (deberta-v3)     0.33s
#:     toxicity (toxic-bert)             0.14s
#:     WHOLE /scan                       3.58s
#:
#: HuggingFace's zero-shot pipeline runs one NLI forward pass per candidate
#: label, so cost is linear in the length of this list. Three of the five
#: labels were paying for a forward pass and then being thrown away:
#:
#:   * "safe benign request" was discarded inside detect() itself, by the
#:     guard below. Vestigial from a multi_label=False design, where it would
#:     have been the softmax absorber.
#:   * "prompt injection attack" and "jailbreak attempt" were dropped by the
#:     only consumer, _scan_output_safety (main.py), whose allow-list keeps
#:     the two below and nothing else. Both threats are already covered by a
#:     dedicated detector -- a fine-tuned DeBERTa classifier plus a heuristic
#:     ensemble -- so the bart-large opinion was a third, unread implementation
#:     of a decision two other paths were already making.
#:
#: That is this repo's recurring defect exactly: a mapping written in two
#: directions with nothing holding them together. So it is written once now,
#: here, and main.py derives its filter from this list instead of restating
#: it. test_the_labels_asked_for_are_the_labels_consumed.py fails if the two
#: drift apart again.
#:
#: THE PRECONDITION, stated because the saving is only free while it holds:
#: multi_label=True below. In that mode each label gets its own softmax over
#: its own (contradiction, entailment) pair, so the scores of these two do not
#: depend on what else is in the list, and removing the other three cannot
#: move them. If multi_label were ever ignored -- it arrives as a **kwargs key
#: and HuggingFace silently drops kwargs it does not recognise -- scoring
#: becomes one softmax across the candidate set, the absorber's mass would
#: redistribute onto these two, and a fixed 0.60 threshold would start
#: flagging ordinary business content. VERIFIED on the box against the
#: installed transformers 5.14.1 (`transformers` is unpinned in the
#: Dockerfile, so this is a real risk, not a hypothetical):
#: scripts/diagnostics/is_multi_label_actually_honoured.py, exit 0.
ZERO_SHOT_THREAT_LABELS = [
    "data exfiltration attempt",
    "harmful content generation request",
]

#: The label the old five-entry list carried as a softmax absorber. Never a
#: candidate now, so nothing can return it -- but see the guard in detect().
ZERO_SHOT_BENIGN_LABEL = "safe benign request"


class ZeroShotThreatDetector:
    """Multi-label zero-shot threat categoriser.

    Primary model: facebook/bart-large-mnli
    Skips the "safe benign request" label and returns only findings above
    the confidence threshold.

    Three distinguishable outcomes, same contract as ToxicityDetector and
    NERPIIDetector:
      * ``[]``                                  – ran, nothing above threshold
      * findings carrying ``available: True``   – ran, classified a threat
      * a member carrying ``available: False``  – did NOT run; nothing assessed
    """

    def _unavailable(self, reason: str, error: Optional[str]) -> Dict[str, Any]:
        return {
            "available": False,
            "reason": reason,
            "error": error,
            "model": ML_ZERO_SHOT_MODEL,
            "detector": "zero_shot_classifier",
        }

    def detect(self, text: str) -> List[Dict[str, Any]]:
        pipe = _registry.zero_shot_pipeline()
        if pipe is None:
            # Previously ``return []``. _scan_output_safety turned that into
            # "no dangerous output", so /scan/output-safety certified content
            # its primary classifier had never looked at.
            state = _registry.model_status().get("zero_shot", {})
            return [self._unavailable("model_not_loaded", state.get("last_error"))]
        # Bound before the try — see the matching note in NERPIIDetector.detect.
        findings: List[Dict[str, Any]] = []
        try:
            result = pipe(
                text[:512] or "",
                candidate_labels=ZERO_SHOT_THREAT_LABELS,
                multi_label=True,
            )
            for label, score in zip(
                result.get("labels", []), result.get("scores", [])
            ):
                # KEPT DELIBERATELY, THOUGH IT IS NOW UNREACHABLE VIA
                # candidate_labels. A pipeline is free to return whatever it
                # likes, and this file's own test double does exactly that:
                # _Benign (test_zero_shot_failure_is_not_clean.py) ignores the
                # candidate list and answers "safe benign request" at 0.97,
                # which without this guard clears the 0.60 threshold and turns
                # the healthy-classifier test red. That failure would read as
                # a stale fixture and invite someone to weaken the assertion
                # rather than restore the guard. It also costs nothing: one
                # string comparison against a label that should never arrive.
                if label == ZERO_SHOT_BENIGN_LABEL:
                    continue
                if float(score) >= ZERO_SHOT_THREAT_THRESHOLD:
                    findings.append(
                        {
                            "available": True,
                            "type": "threat_classification",
                            "subtype": "zero_shot",
                            "label": label,
                            "confidence": round(float(score), 4),
                            "threshold": ZERO_SHOT_THREAT_THRESHOLD,
                            "severity": "high" if score >= 0.85 else "medium",
                            "detector": "zero_shot_classifier",
                            "model": ML_ZERO_SHOT_MODEL,
                        }
                    )
            return findings
        except Exception as exc:
            # error, not warning — same reasoning as the toxicity handler:
            # the model is loaded, so a raise here means output-safety
            # coverage for this text silently vanished.
            logger.error("Zero-shot threat detection error: %s", exc)
            return findings + [self._unavailable("inference_error", str(exc))]


# ---------------------------------------------------------------------------
# Ollama Local LLM Security Judge
# ---------------------------------------------------------------------------

_OLLAMA_SYSTEM_PROMPT = (
    "You are a cybersecurity AI safety classifier. "
    "Analyze the user input for security threats. "
    "Respond ONLY with valid JSON — no markdown, no explanation:\n"
    '{"threat_type":"none|prompt_injection|jailbreak|data_exfiltration|harmful_content|other",'
    '"confidence":0.0,"severity":"none|low|medium|high","reasoning":"brief explanation"}'
)


class OllamaSecurityJudge:
    """High-accuracy local LLM security judge via Ollama REST API.

    Used as a second-pass verifier for ambiguous or high-risk inputs.
    Supported models: llama3.2:3b, llama3.1:8b, mistral:7b, phi3:mini, gemma:7b.

    Falls back silently when:
      - OLLAMA_ENABLED is false
      - Ollama is unreachable
      - The response cannot be parsed as JSON
    """

    def is_available(self) -> bool:
        if not OLLAMA_ENABLED:
            return False
        try:
            req = urllib.request.Request(
                f"{OLLAMA_BASE_URL}/api/tags", method="GET"
            )
            with urllib.request.urlopen(req, timeout=2) as resp:
                return resp.status == 200
        except Exception:
            return False

    def analyze(self, text: str) -> Optional[Dict[str, Any]]:
        if not OLLAMA_ENABLED:
            return None
        payload = json.dumps(
            {
                "model": OLLAMA_MODEL,
                "prompt": f"Analyze for security threats:\n\n{text[:2000]}",
                "system": _OLLAMA_SYSTEM_PROMPT,
                "stream": False,
                "format": "json",
                "options": {"temperature": 0.0, "num_predict": 256},
            }
        ).encode("utf-8")
        try:
            req = urllib.request.Request(
                f"{OLLAMA_BASE_URL}/api/generate",
                data=payload,
                headers={"Content-Type": "application/json"},
                method="POST",
            )
            with urllib.request.urlopen(req, timeout=OLLAMA_TIMEOUT) as resp:
                body = json.loads(resp.read().decode("utf-8"))
            result = json.loads(body.get("response", "{}"))
            threat_type = result.get("threat_type", "none")
            confidence = float(result.get("confidence", 0.0))
            severity = result.get("severity", "none")
            reasoning = str(result.get("reasoning", ""))
            if threat_type == "none" or severity == "none":
                return None
            return {
                "type": "llm_threat_analysis",
                "subtype": threat_type,
                "confidence": round(confidence, 4),
                "severity": severity,
                "reasoning": reasoning[:500],
                "detector": "ollama_llm",
                "model": OLLAMA_MODEL,
            }
        except Exception as exc:
            logger.debug("Ollama analysis skipped: %s", exc)
            return None


# ---------------------------------------------------------------------------
# Module-level detector singletons
# ---------------------------------------------------------------------------

prompt_injection_detector = PromptInjectionMLDetector()
ner_pii_detector = NERPIIDetector()
ner_phi_detector = NERPHIDetector()
toxicity_detector = ToxicityDetector()
zero_shot_detector = ZeroShotThreatDetector()
ollama_judge = OllamaSecurityJudge()
