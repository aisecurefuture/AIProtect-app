"""CyberArmor Detection Service – ML-based edition.

Detection pipeline (in priority order):
  1. Adversarial text normalisation (unicode, zero-width chars, homoglyphs, base64/hex decode)
  2. Prompt Injection – ML primary (protectai/deberta-v3-base-prompt-injection-v2)
                      + heuristic ensemble (secondary / tiebreaker)
                      + legacy regex (optional compat flag)
  3. Promptware session tracker (multi-turn attack chain correlation)
  4. Sensitive Data / DLP – NER model primary (dslim/bert-base-NER)
                           + regex fallback for structured patterns (SSN, CC, AWS keys …)
                           + semantic vector DLP (credential/PII concept prototypes)
  5. Output Safety – ML zero-shot classifier primary
                   + regex fallback for known dangerous patterns
  6. Toxicity – ML classifier (unitary/toxic-bert)
  7. Ollama LLM Judge – optional second-pass for high-ambiguity / high-risk inputs

All ML models run fully locally; no external API calls.
Model downloads happen on first use and are cached in TRANSFORMERS_CACHE.
Set TRANSFORMERS_OFFLINE=1 after initial download to prevent any HF network access.
"""

import base64
import functools
import binascii
import hashlib
import json
import logging
import math
import os
import re
import time
import unicodedata
from contextlib import asynccontextmanager
from collections import deque
from threading import BoundedSemaphore, Lock
from typing import Any, Dict, List, Optional

from fastapi import Depends, FastAPI, Header, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import PlainTextResponse
from pydantic import BaseModel, Field
from cyberarmor_core.crypto import get_public_key_info, verify_shared_secret

# Serving controls. All three default to the B2B behaviour that predates them
# (profile=full, cache off, rate limit off), so importing them changes nothing
# until a deployment opts in. See aiprotect/infra for the consumer opt-in.
import detection_profile
from rate_limit import SCAN_LIMITER
from scan_cache import SCAN_CACHE

# ML detector singletons (lazy-loaded on first inference call)
from ml_models import (
    MODEL_IDS,
    MODELS_DISABLED_BY_PROFILE,
    MODEL_STATUS_LOADED,
    MODEL_STATUS_NOT_ATTEMPTED,
    NER_PII_CONFIDENCE_THRESHOLD,
    OLLAMA_ENABLED,
    PROMPT_INJECTION_ML_THRESHOLD,
    REDACT_CLASS_TO_NER_GROUPS,
    ZERO_SHOT_THREAT_LABELS,
    model_status,
    start_model_warmup,
    warmup_status,
    ner_pii_detector,
    ner_phi_detector,
    ollama_judge,
    prompt_injection_detector,
    toxicity_detector,
    zero_shot_detector,
)

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(name)s %(message)s",
)
logger = logging.getLogger("detection_service")

# ---------------------------------------------------------------------------
# Runtime secrets / configuration
# ---------------------------------------------------------------------------

DETECTION_API_SECRET = os.getenv("DETECTION_API_SECRET", "change-me-detection")
ENFORCE_SECURE_SECRETS = (
    os.getenv("CYBERARMOR_ENFORCE_SECURE_SECRETS", "false").strip().lower()
    in {"1", "true", "yes", "on"}
)
ALLOW_INSECURE_DEFAULTS = (
    os.getenv("CYBERARMOR_ALLOW_INSECURE_DEFAULTS", "false").strip().lower()
    in {"1", "true", "yes", "on"}
)


def _enforce_secure_secrets() -> None:
    if not ENFORCE_SECURE_SECRETS or ALLOW_INSECURE_DEFAULTS:
        return
    lowered = (DETECTION_API_SECRET or "").strip().lower()
    if not lowered or lowered.startswith("change-me") or "changeme" in lowered:
        raise RuntimeError(
            "Refusing startup with insecure defaults in strict secret mode. "
            "Set strong value for DETECTION_API_SECRET. "
            "For local dev only, set CYBERARMOR_ALLOW_INSECURE_DEFAULTS=true."
        )


_enforce_secure_secrets()

# ---------------------------------------------------------------------------
# Detector thresholds / feature flags
# ---------------------------------------------------------------------------

# Prompt injection (ML primary)
_PI_ML_THRESHOLD = float(
    os.getenv("PROMPT_INJECTION_MODEL_THRESHOLD", str(PROMPT_INJECTION_ML_THRESHOLD))
)
_PI_ENSEMBLE_THRESHOLD = float(os.getenv("PROMPT_INJECTION_ENSEMBLE_THRESHOLD", "0.66"))
_LEGACY_PROMPT_REGEX_ENABLED = (
    os.getenv("CYBERARMOR_ENABLE_LEGACY_PROMPT_REGEX", "false").strip().lower()
    in {"1", "true", "yes", "on"}
)
_PI_RISK_BASE = float(os.getenv("PROMPT_INJECTION_RISK_BASE", "0.32"))
_PI_RISK_MULTIPLIER = float(os.getenv("PROMPT_INJECTION_RISK_MULTIPLIER", "0.85"))
_PI_RISK_CAP = float(os.getenv("PROMPT_INJECTION_RISK_CAP", "0.85"))

# DLP / semantic
_SEMANTIC_DLP_THRESHOLD = float(os.getenv("SEMANTIC_DLP_THRESHOLD", "0.62"))

# Promptware session
_PROMPTWARE_SESSION_ENABLED = (
    os.getenv("CYBERARMOR_PROMPTWARE_SESSION_ENABLED", "true").strip().lower()
    in {"1", "true", "yes", "on"}
)
_PROMPTWARE_SESSION_WINDOW_SECONDS = int(
    os.getenv("PROMPTWARE_SESSION_WINDOW_SECONDS", "1800")
)
_PROMPTWARE_SESSION_MAX_EVENTS = int(os.getenv("PROMPTWARE_SESSION_MAX_EVENTS", "20"))
#: Hard ceiling on tracked sessions. The deques were always bounded
#: (maxlen); the DICT holding them never was, and that is what grew.
_PROMPTWARE_MAX_SESSIONS = int(os.getenv("PROMPTWARE_MAX_SESSIONS", "5000"))
_PROMPTWARE_CHAIN_WARN_THRESHOLD = float(
    os.getenv("PROMPTWARE_CHAIN_WARN_THRESHOLD", "0.55")
)
_PROMPTWARE_CHAIN_BLOCK_THRESHOLD = float(
    os.getenv("PROMPTWARE_CHAIN_BLOCK_THRESHOLD", "0.85")
)

# Ollama second-pass judge: only invoked when combined risk >= this threshold
_OLLAMA_JUDGE_RISK_TRIGGER = float(os.getenv("OLLAMA_JUDGE_RISK_TRIGGER", "0.45"))

# ---------------------------------------------------------------------------
# Request / Response models
# ---------------------------------------------------------------------------


class GenericScanRequest(BaseModel):
    content: str = ""
    direction: str = "request"
    content_type: str = "text/plain"
    source_url: Optional[str] = None
    tenant_id: str = "default"
    session_id: Optional[str] = None
    local_findings: List[Dict[str, Any]] = Field(default_factory=list)


class TextRequest(BaseModel):
    text: str
    session_id: Optional[str] = None


# Path B (Step 2): redact request/response payloads.
class RedactRequest(BaseModel):
    text: str
    targets: List[str] = Field(default_factory=list)
    tenant_id: str = "default"
    session_id: Optional[str] = None


# ---------------------------------------------------------------------------
# Adversarial text normalisation
# ---------------------------------------------------------------------------

_ZERO_WIDTH_RE = re.compile(r"[\u200b\u200c\u200d\u2060\ufeff]")
_B64_TOKEN_RE = re.compile(r"\b[A-Za-z0-9+/]{24,}={0,2}\b")
_HEX_TOKEN_RE = re.compile(r"\b[0-9a-fA-F]{24,}\b")
_HOMOGLYPH_MAP = str.maketrans(
    {
        # Greek → Latin lookalikes
        "Α": "A", "Β": "B", "Ε": "E", "Ζ": "Z", "Η": "H",
        "Ι": "I", "Κ": "K", "Μ": "M", "Ν": "N", "Ο": "O",
        "Ρ": "P", "Τ": "T", "Υ": "Y", "Χ": "X",
        # Cyrillic → Latin lookalikes
        "а": "a", "е": "e", "о": "o", "р": "p", "с": "c",
        "у": "y", "х": "x", "і": "i", "ј": "j", "ѕ": "s",
    }
)


def _normalize_adversarial_text(text: str) -> str:
    t = text or ""
    t = unicodedata.normalize("NFKC", t)
    t = _ZERO_WIDTH_RE.sub("", t)
    t = t.translate(_HOMOGLYPH_MAP)
    return t


def _decode_obfuscated_segments(text: str) -> str:
    """Append decoded base64 / hex segments to the original text."""
    out = [text or ""]
    for token in _B64_TOKEN_RE.findall(text or "")[:12]:
        try:
            decoded = base64.b64decode(
                token + ("=" * ((4 - len(token) % 4) % 4)), validate=False
            )
            decoded_txt = decoded.decode("utf-8", errors="ignore")
            if 6 <= len(decoded_txt) <= 800:
                out.append(decoded_txt)
        except Exception:
            pass
    for token in _HEX_TOKEN_RE.findall(text or "")[:12]:
        if len(token) % 2 != 0:
            continue
        try:
            decoded = binascii.unhexlify(token)
            decoded_txt = decoded.decode("utf-8", errors="ignore")
            if 6 <= len(decoded_txt) <= 800:
                out.append(decoded_txt)
        except Exception:
            pass
    return "\n".join(out)


# ---------------------------------------------------------------------------
# Heuristic helpers  (used as ensemble signal alongside ML)
# ---------------------------------------------------------------------------

def _tokenize(text: str) -> List[str]:
    t = (text or "").strip().lower()
    buf: List[str] = []
    out: List[str] = []
    for ch in t:
        if ch.isalnum() or ch in {"_", "-", ":"}:
            buf.append(ch)
        else:
            if buf:
                out.append("".join(buf))
                buf = []
    if buf:
        out.append("".join(buf))
    return out


def _prompt_injection_heuristics(text: str) -> Dict[str, Any]:
    """Return heuristic signals used as ensemble input alongside the ML score."""
    t = (text or "").lower()
    patterns = {
        "instruction_override": (
            r"\b(ignore|bypass|override|forget|disregard)\b.{0,40}"
            r"\b(instruction(?:s)?|policy|guardrail(?:s)?|rule(?:s)?|prompt)\b"
        ),
        "system_prompt_exfil": (
            r"\b(reveal|show|print|dump|expose|give|return)\b.{0,60}"
            r"\b(system prompt|developer prompt|hidden prompt|secret|source code|codebase|internal code)\b"
        ),
        "role_hijack": (
            r"\b(you are now|act as|pretend to be)\b.{0,50}"
            r"\b(root|admin|unrestricted|developer mode)\b"
        ),
        "tool_injection": (
            r"\b(use tool|call tool|invoke tool|execute command)\b.{0,60}"
            r"\b(ignore checks|without validation|silently)\b"
        ),
        "indirect_doc_injection": (
            r"\b(from document|in the file|retrieved context|quoted text)\b.{0,80}"
            r"\b(ignore|override|follow these instructions)\b"
        ),
    }
    matched = [name for name, pat in patterns.items() if re.search(pat, t, flags=re.IGNORECASE | re.DOTALL)]
    signal_weights = {
        "instruction_override": 0.45,
        "system_prompt_exfil": 0.45,
        "role_hijack": 0.35,
        "tool_injection": 0.35,
        "indirect_doc_injection": 0.30,
    }
    weighted_score = sum(signal_weights.get(name, 0.2) for name in matched)
    return {
        "matched_signals": matched,
        "heuristic_score": round(min(1.0, weighted_score), 4),
    }


def _extract_promptware_indicators(text: str) -> Dict[str, float]:
    tokens = _tokenize(text)
    if not tokens:
        return {"override": 0.0, "exfil": 0.0, "policy_evasion": 0.0, "tool_abuse": 0.0}
    override_terms = {"ignore", "bypass", "override", "disable", "forget", "evade", "jailbreak"}
    exfil_terms = {"reveal", "dump", "print", "exfiltrate", "secret", "token", "apikey", "password", "credential"}
    policy_terms = {"policy", "guardrail", "safety", "system", "instruction", "rule"}
    tool_terms = {"curl", "bash", "powershell", "exec", "shell", "command", "terminal", "sudo"}
    n = max(len(tokens), 1)

    def ratio(term_set: set) -> float:
        return sum(1 for t in tokens if t in term_set) / n

    return {
        "override": ratio(override_terms),
        "exfil": ratio(exfil_terms),
        "policy_evasion": ratio(policy_terms),
        "tool_abuse": ratio(tool_terms),
    }


# ---------------------------------------------------------------------------
# Semantic DLP (vector similarity against concept prototypes)
# ---------------------------------------------------------------------------

def _embed_text(text: str, dim: int = 256) -> List[float]:
    tokens = _tokenize(text)
    vec = [0.0] * dim
    for tok in tokens:
        idx = int(hashlib.sha256(tok.encode("utf-8")).hexdigest()[:8], 16) % dim
        vec[idx] += 1.0
    norm = math.sqrt(sum(v * v for v in vec)) or 1.0
    return [v / norm for v in vec]


def _cosine_similarity(a: List[float], b: List[float]) -> float:
    if not a or not b or len(a) != len(b):
        return 0.0
    return float(sum(x * y for x, y in zip(a, b)))


_SEMANTIC_DLP_PROTOTYPES: Dict[str, List[str]] = {
    "credential_exfiltration": [
        "api key secret token password private credential dump",
        "print hidden credentials and secrets",
    ],
    "pii_exposure": [
        "social security number personal identifiable information",
        "credit card customer pii dump",
    ],
    "financial_sensitive": [
        "bank account routing number payment card details",
        "financial records and account statements",
    ],
    "source_code_secret_leak": [
        "source code with embedded secret keys",
        "repository private key configuration secret leak",
    ],
}
_SEMANTIC_DLP_EMBEDDINGS: Dict[str, List[List[float]]] = {
    k: [_embed_text(text) for text in vals]
    for k, vals in _SEMANTIC_DLP_PROTOTYPES.items()
}


def _scan_semantic_dlp(text: str) -> List[Dict[str, Any]]:
    findings: List[Dict[str, Any]] = []
    if not text or not text.strip():
        return findings
    emb = _embed_text(text)
    for concept, prototypes in _SEMANTIC_DLP_EMBEDDINGS.items():
        sims = [_cosine_similarity(emb, p) for p in prototypes]
        best = max(sims) if sims else 0.0
        if best >= _SEMANTIC_DLP_THRESHOLD:
            findings.append(
                {
                    "type": "sensitive_data",
                    "subtype": "semantic_dlp",
                    "concept": concept,
                    "similarity": round(best, 4),
                    "threshold": _SEMANTIC_DLP_THRESHOLD,
                    "severity": "high" if best >= 0.78 else "medium",
                }
            )
    return findings


# ---------------------------------------------------------------------------
# Regex fallback patterns (structured PII / dangerous output)
# ---------------------------------------------------------------------------

# These are kept as complementary signals when the NER model is unavailable
# or for patterns it doesn't reliably detect (e.g. exact AWS key format).
_SENSITIVE_REGEX_PATTERNS = [
    ("ssn", re.compile(r"\b\d{3}-\d{2}-\d{4}\b")),
    # EIN (Employer Identification Number, also called FEIN). Distinct
    # NN-NNNNNNN format — no overlap with SSN's NNN-NN-NNNN — so the
    # structured form is a reliable signal on its own.
    ("ein", re.compile(r"\b\d{2}-\d{7}\b")),
    # Driver's license — letter-prefix state formats. The shape is
    # distinctive enough to run always-on:
    #   - MD/FL dashed or spaced:  L 3-digit  4-digit  4-digit  → K400-6737-9051
    #   - MD/FL compact (no sep):  L + 12 digits                → K400673790512
    #   - IL compact:              L + 11 digits                → K40067379051
    #   - WI compact:              L + 13 digits                → K4006737905123
    # The letter prefix + tight length range (11-13 digits) rules out most
    # tech-writing alphanumerics (AWS account IDs are 12 pure digits with
    # no letter; container IDs are hex without uppercase; UUIDs are longer).
    # Other state formats (CA's L+7 digits, TX's 8 digits, NY's 9 digits)
    # are too short to disambiguate from random IDs and remain behind the
    # CYBERARMOR_DETECTION_DL_STATES opt-in.
    (
        "drivers_license",
        re.compile(
            r"\b[A-Z](?:\d{3}[\s-]\d{4}[\s-]\d{4}|\d{11,13})\b",
            re.IGNORECASE,
        ),
    ),
    (
        "credit_card",
        re.compile(
            r"\b(?:4\d{3}|5[1-5]\d{2}|3[47]\d{2}|6(?:011|5\d{2}))[- ]?"
            r"\d{4}[- ]?\d{4}[- ]?\d{4}\b"
        ),
    ),
    ("aws_key", re.compile(r"AKIA[0-9A-Z]{16}")),
    ("gcp_api_key", re.compile(r"\bAIza[0-9A-Za-z\-_]{35}\b")),
    ("github_token", re.compile(r"\bgh[pousr]_[A-Za-z0-9_]{36,255}\b")),
    ("openai_api_key", re.compile(r"\b(?:sk-(?:proj|svcacct)-[A-Za-z0-9_\-]{20,}|sk-[A-Za-z0-9]{32,})\b")),
    ("anthropic_api_key", re.compile(r"\bsk-ant-[A-Za-z0-9\-_]{60,}\b")),
    ("slack_token", re.compile(r"\bxox[bpoa]-[0-9A-Za-z\-]{10,}\b")),
    ("stripe_key", re.compile(r"\b(?:sk|pk)_(?:live|test)_[A-Za-z0-9]{20,}\b")),
    (
        "generic_api_key",
        re.compile(
            r"\b(?:[A-Za-z0-9]+_)*(?:api[_\-]?key|apikey|secret[_\-]?key|access[_\-]?token)"
            r"\s*[:=]\s*['\"]?([A-Za-z0-9_\-]{16,})['\"]?",
            re.IGNORECASE,
        ),
    ),
    (
        "password_field",
        re.compile(r"(?:password|passwd|pwd)\s*[:=]\s*['\"]?([^\s'\"]{6,})['\"]?", re.IGNORECASE),
    ),
    (
        "private_key",
        re.compile(r"-----BEGIN (?:RSA |EC |DSA )?PRIVATE KEY-----"),
    ),
]

_CONTEXTUAL_SSN_PATTERNS = [
    # Match natural-language SSN disclosures:
    #   "My ssn is 123456789", "ssn: 123456789", "social security number = …",
    # as well as "123456789 is my ssn". The gap between the label and the
    # number tolerates short connecting words ("is", "was", "for me", …) by
    # allowing up to 15 non-digit characters. Cap at 15 so we don't bridge
    # to unrelated 9-digit values further down a paragraph.
    re.compile(
        r"\b(?:ssn|social\s+security(?:\s+number)?|taxpayer\s+id)\b"
        r"[^\d]{0,15}(\d{9})\b",
        re.IGNORECASE,
    ),
    re.compile(
        r"\b(\d{9})\b[^\d]{0,15}"
        r"(?:ssn|social\s+security(?:\s+number)?|taxpayer\s+id)\b",
        re.IGNORECASE,
    ),
]

_CONTEXTUAL_EIN_PATTERNS = [
    # Same shape as SSN but matches "EIN", "FEIN", or the long form.
    # Captures both the structured "NN-NNNNNNN" and bare 9-digit forms
    # so "EIN is 12-3456789" and "EIN is 123456789" both surface.
    re.compile(
        r"\b(?:f?ein|employer\s+id(?:entification)?(?:\s+number)?|"
        r"federal\s+(?:tax\s+)?id(?:entification)?(?:\s+number)?)\b"
        r"[^\d]{0,15}(\d{2}-?\d{7})\b",
        re.IGNORECASE,
    ),
    re.compile(
        r"\b(\d{2}-?\d{7})\b[^\d]{0,15}"
        r"(?:f?ein|employer\s+id(?:entification)?(?:\s+number)?|"
        r"federal\s+(?:tax\s+)?id(?:entification)?(?:\s+number)?)\b",
        re.IGNORECASE,
    ),
]

# Driver's license is contextual-only because state formats vary too widely
# (Maryland: 1 letter + 12 digits; California: 1 letter + 7 digits; Texas:
# 8 digits; etc.). A bare regex over all of those would false-positive on
# every SKU and ticket ID in tech writing.
#
# Label vocabulary requires either the long form ("driver's license"),
# the abbreviation "DLN", or "DL" *followed by* a disambiguating connector
# (so bare "DL release v1" doesn't trigger). The gap between label and
# value accepts an optional short connector word ("is", "no.", etc.) so
# natural English ("My driver's license is D1234567") matches.
_DL_LABEL = (
    r"(?:driver(?:'?s)?\s+license(?:\s+(?:number|no\.?|#))?|DLN|"
    r"DL\s+(?:number|is)|DL\s*[#:=])"
)
_DL_GAP = r"\s*(?:number|no\.?|#|is|=|of|:)?\s*[^A-Za-z0-9]{0,5}"
_CONTEXTUAL_DRIVERS_LICENSE_PATTERNS = [
    # No trailing \b after the label group: some label suffixes ("DL #",
    # "DL:") end in non-word chars, and \b only fires between word/non-word
    # boundaries — so "DL # X1234567" failed previously. The gap pattern
    # below already enforces separation.
    re.compile(
        r"\b" + _DL_LABEL + _DL_GAP + r"([A-Za-z0-9-]{5,15})\b",
        re.IGNORECASE,
    ),
    re.compile(
        r"\b([A-Za-z0-9-]{5,15})\b" + _DL_GAP +
        r"\b(?:driver(?:'?s)?\s+license(?:\s+(?:number|no\.?|#))?|DLN)\b",
        re.IGNORECASE,
    ),
]

# Passport numbers vary internationally (US is 9 alphanumeric; many EU
# countries 8-9). Anchor on context to avoid false-flagging short IDs.
_PP_LABEL = r"(?:passport(?:\s+(?:number|no\.?|#))?|US\s+passport)"
_PP_GAP = r"\s*(?:number|no\.?|#|is|=|:)?\s*[^A-Za-z0-9]{0,5}"
_CONTEXTUAL_PASSPORT_PATTERNS = [
    re.compile(
        r"\b" + _PP_LABEL + r"\b" + _PP_GAP + r"([A-Za-z0-9]{6,9})\b",
        re.IGNORECASE,
    ),
    re.compile(
        r"\b([A-Za-z0-9]{6,9})\b" + _PP_GAP + r"\b" + _PP_LABEL + r"\b",
        re.IGNORECASE,
    ),
]

# ABA routing numbers are always 9 digits. Bare "routing:" is recognised as
# a label (a 9-digit + routing context is a strong signal even without
# "number"); standalone 9-digit values with no nearby label do not match.
_ABA_LABEL = (
    r"(?:ABA(?:\s+routing(?:\s+number)?)?|"
    r"routing\s+(?:number|no\.?|#)|routing\s*[:=]|"
    r"wire\s+routing|bank\s+routing|ACH\s+routing)"
)

# ---------------------------------------------------------------------------
# PHI — the HIPAA Safe Harbor identifiers the pii.* classes do not cover.
#
# WHY THESE ARE SEPARATE FROM pii.*
# §164.514(b)(2) lists 18 identifier categories that must be removed to
# de-identify under Safe Harbor. The pii.* registry covers nine of them
# (names, geography, dates, phone, email, SSN, URL, IP, licence numbers). The
# nine it did not cover are the ones specific to healthcare, and a covered
# entity redacting only pii.* would have been shipping medical record numbers
# and Medicare IDs to an AI provider while a HIPAA control read green. These
# close that gap. services/compliance/frameworks/hipaa.py documents the
# boundary from the compliance side.
#
# PRECISION FIRST, BECAUSE FALSE POSITIVES HAVE ALREADY COST US ONCE.
# Scanning misfired at production scale before (transparent_proxy.py's note on
# Outlook EWS, iCloud and Teams traffic false-positiving a classifier), and a
# redactor that mangles legitimate text gets switched off, which protects
# nobody. So each pattern here is either structurally distinctive enough to
# stand alone, or it is context-anchored and matches nothing without its
# label. Nothing here matches a bare run of digits.
#
# NOT COVERED, DELIBERATELY: biometric identifiers, full-face photographs, and
# §164.514(b)(2)(R)'s catch-all "any other unique identifying number,
# characteristic, or code". The first two are not text, and the third is not
# expressible as a pattern. HIPAA-PHI-2 therefore still requires a
# de-identification attestation -- these detectors reduce exposure, they do not
# by themselves establish Safe Harbor.

# Medicare Beneficiary Identifier. CMS fixes the format exactly: 11 characters,
# position-typed, and the letters S, L, O, I, B and Z are never used (they are
# too easily confused with digits). That makes it self-identifying -- no label
# needed -- and effectively impossible to hit by accident. Commonly written
# with or without hyphens: 1EG4-TE5-MK73.
_MBI_ALPHA = r"[ACDEFGHJKMNPQRTUVWXY]"
_MBI_ALNUM = r"[ACDEFGHJKMNPQRTUVWXY0-9]"
_MBI_RE = re.compile(
    r"\b[1-9]" + _MBI_ALPHA + _MBI_ALNUM + r"\d-?"
    + _MBI_ALPHA + _MBI_ALNUM + r"\d-?"
    + _MBI_ALPHA + _MBI_ALPHA + r"\d{2}\b"
)

# ICD-10-CM diagnosis code. The DOTTED form is required on purpose: bare "I10"
# or "E11" collides with ordinary identifiers, form labels and part numbers,
# while "I10.9"/"S72.001A" is distinctive. Category letter excludes U (reserved
# for provisional/emergency codes).
_ICD10_RE = re.compile(r"\b[A-TV-Z]\d[0-9A-TV-Z]\.[0-9A-TV-Z]{1,4}\b")

# Institution-assigned identifiers with no fixed national format. These are
# context-anchored ONLY -- a bare number never matches, because at these digit
# lengths it is indistinguishable from an invoice, ticket or order number.
_MRN_LABEL = (
    r"(?:MRN|M\.R\.N\.|medical\s+record\s+(?:number|no\.?|#)|"
    r"patient\s+(?:id|identifier|record\s+(?:number|no\.?|#))|chart\s+(?:number|no\.?|#))"
)
_CONTEXTUAL_MRN_PATTERNS = [
    re.compile(r"\b" + _MRN_LABEL + r"[^A-Za-z0-9]{0,15}([A-Z]{0,3}\d{5,12})\b", re.IGNORECASE),
    re.compile(r"\b([A-Z]{0,3}\d{5,12})\b[^A-Za-z0-9,;\n]{0,15}" + _MRN_LABEL + r"\b", re.IGNORECASE),
]

_HEALTH_PLAN_LABEL = (
    r"(?:health\s+plan\s+(?:id|number|no\.?|#)|member\s+(?:id|number|no\.?|#)|"
    r"subscriber\s+(?:id|number|no\.?|#)|policy\s+(?:id|number|no\.?|#)|"
    r"insurance\s+(?:id|number|no\.?|#)|group\s+number|medicaid\s+(?:id|number))"
)
_CONTEXTUAL_HEALTH_PLAN_PATTERNS = [
    re.compile(r"\b" + _HEALTH_PLAN_LABEL + r"[^A-Za-z0-9]{0,15}([A-Z0-9][A-Z0-9-]{5,17})\b", re.IGNORECASE),
    re.compile(r"\b([A-Z0-9][A-Z0-9-]{5,17})\b[^A-Za-z0-9,;\n]{0,15}" + _HEALTH_PLAN_LABEL + r"\b", re.IGNORECASE),
]

# NPI is ten digits — far too generic bare, so label-anchored. DEA is two
# letters then seven digits, which is distinctive enough that the label is a
# guard rather than the whole signal, but it stays anchored for consistency.
_NPI_LABEL = r"(?:NPI|national\s+provider\s+(?:id|identifier|number|no\.?|#))"
_CONTEXTUAL_NPI_PATTERNS = [
    re.compile(r"\b" + _NPI_LABEL + r"[^\d]{0,15}([12]\d{9})\b", re.IGNORECASE),
    re.compile(r"\b([12]\d{9})\b[^\d,;\n]{0,15}" + _NPI_LABEL + r"\b", re.IGNORECASE),
]

_DEA_LABEL = r"(?:DEA(?:\s+(?:registration|number|no\.?|#))?)"
_CONTEXTUAL_DEA_PATTERNS = [
    re.compile(r"\b" + _DEA_LABEL + r"[^A-Za-z0-9]{0,15}([ABFGMPRX][A-Z]\d{7})\b", re.IGNORECASE),
    re.compile(r"\b([ABFGMPRX][A-Z]\d{7})\b[^A-Za-z0-9,;\n]{0,15}" + _DEA_LABEL + r"\b", re.IGNORECASE),
]

# MBI and ICD-10 are always-on rather than context-anchored, for the reason
# given at _SENSITIVE_REGEX_PATTERNS: both are structurally distinctive enough
# to stand alone. Registered here rather than in the list literal above only
# because they depend on the character-class helpers defined in this block;
# the scan loop reads the list, so appending is what puts them in service.
_SENSITIVE_REGEX_PATTERNS.extend([
    ("mbi",   _MBI_RE),
    ("icd10", _ICD10_RE),
])
_CONTEXTUAL_ABA_ROUTING_PATTERNS = [
    re.compile(
        r"\b" + _ABA_LABEL + r"[^\d]{0,15}(\d{9})\b",
        re.IGNORECASE,
    ),
    re.compile(
        r"\b(\d{9})\b[^\d]{0,15}" + _ABA_LABEL + r"\b",
        re.IGNORECASE,
    ),
]

# Date of birth — common US (MM/DD/YYYY) and ISO (YYYY-MM-DD) numeric
# forms only. "Born on January 5, 1980" written form is intentionally
# skipped to keep false positives low; PHI/HIPAA workflows that need it
# can layer on NER.
_CONTEXTUAL_DOB_PATTERNS = [
    re.compile(
        r"\b(?:DOB|date\s+of\s+birth|birth\s*date|birthdate|born\s+on)\b"
        r"[^/\d-]{0,15}"
        r"(\d{1,2}[/-]\d{1,2}[/-]\d{2,4}|\d{4}-\d{2}-\d{2})\b",
        re.IGNORECASE,
    ),
]

# ---- State-specific driver's license formats (opt-in) -----------------
# These patterns are too generic to be on by default — TX (8 digits) and
# NY (9 digits) overlap with bare order numbers, AWS account IDs, SSN /
# EIN / ABA routing candidates, and others. CA (1 letter + 7 digits) is
# marginally safer thanks to the letter prefix. Operators with a known
# regional customer base can enable specific states via:
#
#   CYBERARMOR_DETECTION_DL_STATES=CA          # CA only
#   CYBERARMOR_DETECTION_DL_STATES=CA,TX,NY    # all three
#
# Empty / unset (default) → no additional state-specific structured
# matching beyond the MD/FL L+12 dashed/spaced form in
# _SENSITIVE_REGEX_PATTERNS, which is distinctive enough to be always-on.
_DL_STATE_PATTERNS: Dict[str, "re.Pattern[str]"] = {
    "CA": re.compile(r"\b[A-Z]\d{7}\b", re.IGNORECASE),
    "TX": re.compile(r"\b\d{8}\b"),
    "NY": re.compile(r"\b\d{9}\b"),
}
_DL_STATE_HIGH_FP_WARNING = {"TX", "NY"}

_DL_ENABLED_STATES = {
    s.strip().upper()
    for s in os.getenv("CYBERARMOR_DETECTION_DL_STATES", "").split(",")
    if s.strip()
}
_ENABLED_DL_STATE_PATTERNS = [
    (s, _DL_STATE_PATTERNS[s]) for s in sorted(_DL_ENABLED_STATES) if s in _DL_STATE_PATTERNS
]
if _ENABLED_DL_STATE_PATTERNS:
    logger.info(
        "Driver's license state-specific detection enabled: %s",
        [s for s, _ in _ENABLED_DL_STATE_PATTERNS],
    )
    for s, _ in _ENABLED_DL_STATE_PATTERNS:
        if s in _DL_STATE_HIGH_FP_WARNING:
            logger.warning(
                "DL state %s uses a bare-digit pattern with high false-positive risk "
                "(collides with order numbers, account IDs, SSN/EIN candidates). "
                "Review findings with this in mind.",
                s,
            )

_ENTITY_REGEX_PATTERNS = [
    ("email", re.compile(r"\b[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[A-Za-z]{2,}\b")),
    (
        "phone",
        re.compile(
            r"\b(?:\+?1[-.\s]?)?(?:\(?\d{3}\)?[-.\s]?)\d{3}[-.\s]?\d{4}\b"
        ),
    ),
    ("iban", re.compile(r"\b[A-Z]{2}\d{2}[A-Z0-9]{11,30}\b")),
    (
        "jwt",
        re.compile(
            r"\beyJ[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}\b"
        ),
    ),
    (
        "generic_api_key",
        re.compile(r"\b(?:sk|api|token)[_\-][A-Za-z0-9]{12,}\b", re.IGNORECASE),
    ),
]

# Dangerous output patterns (command injection, XSS, browser data exfil).
# The zero-shot ML model is the primary detector; these patterns act as
# high-confidence supplementary signals.
_DANGEROUS_OUTPUT_PATTERNS = [
    re.compile(r"\brm\s+-rf\b", re.IGNORECASE),
    re.compile(r"\bcurl\b.*\|\s*(?:bash|sh)", re.IGNORECASE),
    re.compile(r"powershell\s+-enc", re.IGNORECASE),
    re.compile(
        r"<\s*script\b[^>]*>.*?<\s*/\s*script\s*>", re.IGNORECASE | re.DOTALL
    ),
    re.compile(r"\bon\w+\s*=\s*['\"].*?['\"]", re.IGNORECASE),
    re.compile(r"javascript\s*:\s*[^\s]+", re.IGNORECASE),
    re.compile(
        r"(?:document\.cookie|localStorage|sessionStorage|innerHTML\s*=)",
        re.IGNORECASE,
    ),
]

# Ransomware behavior-combination patterns. _scan_output_safety's zero-shot
# label ("harmful content generation request") is tuned for natural-language
# requests, not generated code, and has no signal dedicated to this specific
# combination -- verified empirically that a "write me a backup tool that
# encrypts a folder" style request doesn't reliably trip it. Any ONE of
# these primitives alone is extremely common in legitimate code (backup
# tools walk directories and encrypt files too), so this only fires when
# MULTIPLE primitives co-occur -- that combination, not any single piece of
# it, is what's actually distinctive about ransomware.
_RANSOMWARE_FILE_ENUM_RE = re.compile(
    r"\b(?:os\.walk|glob\.glob|Directory\.GetFiles|Get-ChildItem\s+-Recurse|"
    r"find\s+\S+\s+-type\s+f)\b",
    re.IGNORECASE,
)
_RANSOMWARE_ENCRYPT_RE = re.compile(
    r"\b(?:Fernet\(|AES\.new|Cipher\(algorithms|CryptoStream|RSA\.encrypt|"
    r"pyAesCrypt|encrypt_file|ChaCha20)\b",
    re.IGNORECASE,
)
_RANSOMWARE_NOTE_OR_WIPE_RE = re.compile(
    r"(?:ransom[_\s-]?note|your\s+files\s+(?:have\s+been|are)\s+encrypted|"
    r"README_DECRYPT|HOW_TO_DECRYPT|decrypt(?:ion)?\s+key.{0,20}(?:payment|bitcoin)|"
    r"\bos\.remove\b.{0,60}\bfor\b|\bshutil\.rmtree\b|send2trash|"
    r"Remove-Item\s+-Recurse\s+-Force)",
    re.IGNORECASE | re.DOTALL,
)

# Optional legacy prompt-injection regex (disabled by default)
_LEGACY_PROMPT_PATTERNS = [
    re.compile(r"ignore\\s+(all\\s+)?previous\\s+instructions", re.IGNORECASE),
    re.compile(r"jailbreak", re.IGNORECASE),
    re.compile(r"reveal\\s+(your|the)\\s+system\\s+prompt", re.IGNORECASE),
]

# ---------------------------------------------------------------------------
# Promptware session tracker
# ---------------------------------------------------------------------------


class PromptwareSessionTracker:
    def __init__(self) -> None:
        # OrderedDict so eviction is oldest-touched-first. A plain dict grew
        # without limit: _prune() empties a deque but never removes its KEY, so
        # every session ever seen stayed resident.
        from collections import OrderedDict
        self._sessions: "OrderedDict[str, deque]" = OrderedDict()
        self._lock = Lock()

    def _prune(self, q: deque, now_ts: float) -> None:
        while q and (now_ts - q[0]["ts"]) > _PROMPTWARE_SESSION_WINDOW_SECONDS:
            q.popleft()

    def _compute_chain_state(self, events: List[Dict[str, Any]]) -> Dict[str, Any]:
        chain = 0.0
        weight = 1.0
        decay = 0.86
        combined: Dict[str, float] = {
            "override": 0.0, "exfil": 0.0, "policy_evasion": 0.0, "tool_abuse": 0.0
        }
        for ev in reversed(events):
            chain += ev["event_score"] * weight
            for k in combined:
                combined[k] += ev["indicators"][k] * weight
            weight *= decay
        chain = max(0.0, min(1.0, chain))
        for k in combined:
            combined[k] = round(max(0.0, min(1.0, combined[k])), 4)
        return {
            "event_count": len(events),
            "chain_confidence": round(chain, 4),
            "indicators": combined,
            "warn_threshold": _PROMPTWARE_CHAIN_WARN_THRESHOLD,
            "block_threshold": _PROMPTWARE_CHAIN_BLOCK_THRESHOLD,
        }

    def observe(
        self,
        session_key: str,
        text: str,
        pi_confidence: float,
    ) -> Optional[Dict[str, Any]]:
        if not session_key:
            return None
        indicators = _extract_promptware_indicators(text)
        now_ts = time.time()
        event_score = min(
            1.0,
            max(
                0.0,
                (0.62 * max(0.0, min(1.0, pi_confidence)))
                + (0.20 * indicators["override"])
                + (0.10 * indicators["exfil"])
                + (0.05 * indicators["policy_evasion"])
                + (0.03 * indicators["tool_abuse"]),
            ),
        )
        with self._lock:
            bucket = self._sessions.setdefault(
                session_key, deque(maxlen=_PROMPTWARE_SESSION_MAX_EVENTS)
            )
            bucket.append(
                {
                    "ts": now_ts,
                    "event_score": event_score,
                    "pi_confidence": max(0.0, min(1.0, pi_confidence)),
                    "indicators": indicators,
                }
            )
            self._prune(bucket, now_ts)
            events = list(bucket)
            self._sessions.move_to_end(session_key)
            # SWEEP DEAD SESSIONS BY AGE, from the least-recently-touched end.
            #
            # An earlier version dropped the bucket only `if not bucket` after
            # prune -- dead code, because observe() APPENDS before it prunes, so
            # the just-added event always leaves the deque non-empty. Nothing
            # was ever reclaimed and only the hard cap below bound anything,
            # which would still hold thousands of long-expired keys on a quiet
            # system.
            #
            # OrderedDict keeps the LRU end first, so this is O(1) amortised:
            # stop at the first session still inside the window.
            while self._sessions:
                oldest_key = next(iter(self._sessions))
                if oldest_key == session_key:
                    break
                oldest = self._sessions[oldest_key]
                if oldest and (now_ts - oldest[-1]["ts"]) <= _PROMPTWARE_SESSION_WINDOW_SECONDS:
                    break
                self._sessions.pop(oldest_key, None)
            # Ceiling regardless of key quality: a wide fleet, or an attacker
            # varying paths, must not be able to grow this without bound.
            while len(self._sessions) > _PROMPTWARE_MAX_SESSIONS:
                evicted, _ = self._sessions.popitem(last=False)
                logger.debug("promptware_session_evicted key=%s total=%s",
                             evicted[:80], len(self._sessions))
        if len(events) < 2:
            return None
        state = self._compute_chain_state(events)
        chain = float(state["chain_confidence"])
        if chain < _PROMPTWARE_CHAIN_WARN_THRESHOLD:
            return None
        return {
            "type": "promptware_attack_chain",
            "detector": "session_correlation",
            "session_id": session_key,
            "event_count": state["event_count"],
            "confidence": chain,
            "warn_threshold": state["warn_threshold"],
            "block_threshold": state["block_threshold"],
            "indicators": state["indicators"],
            "severity": "high" if chain >= _PROMPTWARE_CHAIN_BLOCK_THRESHOLD else "medium",
        }

    def snapshot(self, session_key: str) -> Dict[str, Any]:
        empty: Dict[str, Any] = {
            "session_id": session_key or "",
            "event_count": 0,
            "chain_confidence": 0.0,
            "indicators": {
                "override": 0.0, "exfil": 0.0,
                "policy_evasion": 0.0, "tool_abuse": 0.0,
            },
            "warn_threshold": _PROMPTWARE_CHAIN_WARN_THRESHOLD,
            "block_threshold": _PROMPTWARE_CHAIN_BLOCK_THRESHOLD,
        }
        if not session_key:
            return empty
        with self._lock:
            bucket = self._sessions.get(session_key)
            if not bucket:
                return empty
            self._prune(bucket, time.time())
            events = list(bucket)
        state = self._compute_chain_state(events)
        return {
            "session_id": session_key,
            "event_count": state["event_count"],
            "chain_confidence": state["chain_confidence"],
            "indicators": state["indicators"],
            "warn_threshold": state["warn_threshold"],
            "block_threshold": state["block_threshold"],
        }


_PROMPTWARE_TRACKER = PromptwareSessionTracker()


def _derive_session_key(
    tenant_id: str,
    direction: str,
    source_url: Optional[str],
    session_id: Optional[str],
) -> str:
    if session_id and session_id.strip():
        base = session_id.strip()
    elif source_url and source_url.strip():
        # scheme://host/path ONLY. The raw URL was used here, and the proxy
        # sends the full one -- query string included:
        #
        #   .../ces/v1/telemetry/intake?ddforward=...&dd-request-id=b8e3f43a-...
        #   .../rsc-action/...?payload=%7B%22requestId%22...      (2000+ chars)
        #
        # Those are unique per request, so every request minted its own session
        # whose key WAS the URL. Two failures from one line:
        #
        #   1. The dict grew by one multi-KB entry per request, forever. It was
        #      measured at 7.3 GiB against an 8 GiB cap after 27 hours, with the
        #      service pinned at 371% CPU and answering neither /health nor
        #      /scan.
        #   2. Correlation could never fire. observe() returns None below until
        #      a session has TWO events, and a key used once never reaches two.
        #      The promptware attack-chain detector has therefore never produced
        #      a finding for enforcement-point traffic.
        #
        # The endpoint is the session grain that was intended: repeated posts to
        # chatgpt.com/backend-api/conversation are one conversation to correlate,
        # not N unrelated ones.
        base = _session_base_from_url(source_url.strip())
    else:
        base = "anonymous"
    return f"{tenant_id}:{direction}:{base}"


def _session_base_from_url(raw: str) -> str:
    """scheme://host/path, with the query and fragment dropped."""
    try:
        from urllib.parse import urlsplit
        parts = urlsplit(raw)
        if parts.scheme and parts.netloc:
            return f"{parts.scheme}://{parts.netloc}{parts.path or '/'}"
    except Exception:  # noqa: BLE001 -- a malformed URL must not break scanning
        pass
    # Unparseable: truncate rather than key on an unbounded string.
    return raw[:200]


# ---------------------------------------------------------------------------
# Core detection functions
# ---------------------------------------------------------------------------


def _scan_prompt_injection(text: str) -> List[Dict[str, Any]]:
    """Detect prompt injection attacks.

    Pipeline:
      1. ML classifier (DeBERTa fine-tuned) → primary
      2. Heuristic ensemble (complements ML score)
      3. Legacy regex (optional, compat flag)
    """
    findings: List[Dict[str, Any]] = []
    normalized = _normalize_adversarial_text(text or "")
    expanded = _decode_obfuscated_segments(normalized)

    heur = _prompt_injection_heuristics(expanded)
    heur_score = float(heur.get("heuristic_score", 0.0))

    # --- ML primary ---
    ml_result = prompt_injection_detector.detect(expanded)
    if ml_result and ml_result.get("available"):
        prob = float(ml_result.get("confidence", 0.0))
        if ml_result.get("is_injection") and prob >= _PI_ML_THRESHOLD:
            findings.append(
                {
                    "type": "prompt_injection",
                    "detector": "ml_classifier",
                    "model": ml_result.get("model"),
                    "confidence": prob,
                    "threshold": _PI_ML_THRESHOLD,
                    "rationale": heur.get("matched_signals", []),
                    "severity": "high" if prob >= 0.82 else "medium",
                }
            )
        # Ensemble: blend ML confidence + heuristic signal
        ensemble_conf = max(
            0.0, min(1.0, (0.75 * prob) + (0.25 * heur_score))
        )
        if ensemble_conf >= _PI_ENSEMBLE_THRESHOLD:
            findings.append(
                {
                    "type": "prompt_injection",
                    "detector": "ensemble",
                    "model": ml_result.get("model"),
                    "confidence": round(ensemble_conf, 4),
                    "threshold": _PI_ENSEMBLE_THRESHOLD,
                    "signals": heur.get("matched_signals", []),
                    "severity": "high" if ensemble_conf >= 0.82 else "medium",
                }
            )
    else:
        # ML unavailable – fall back to heuristics alone
        if heur_score >= _PI_ENSEMBLE_THRESHOLD:
            findings.append(
                {
                    "type": "prompt_injection",
                    "detector": "heuristic_fallback",
                    "confidence": round(heur_score, 4),
                    "signals": heur.get("matched_signals", []),
                    "severity": "high" if heur_score >= 0.82 else "medium",
                }
            )

    # --- Legacy regex (optional compat flag) ---
    if _LEGACY_PROMPT_REGEX_ENABLED:
        for pattern in _LEGACY_PROMPT_PATTERNS:
            match = pattern.search(text)
            if match:
                findings.append(
                    {
                        "type": "prompt_injection",
                        "detector": "legacy_regex",
                        "pattern": pattern.pattern,
                        **_match_evidence(match),
                        "severity": "medium",
                    }
                )
    return findings


def _match_evidence(match: Any, value: Optional[str] = None) -> Dict[str, Any]:
    """Non-reversible evidence about a matched sensitive value.

    The matched text is deliberately NOT returned. These findings travel from
    the endpoint proxy into TrafficLogEntry.detections, out through
    emit_telemetry() to POST /telemetry/ingest, and land in
    TelemetryRecord.payload — so anything recorded here is persisted
    server-side, today on an unencrypted volume.

    Writing the raw value made the DLP detector a DLP violation: credit-card
    numbers, SSNs, private keys, cloud credentials, passports and bank routing
    numbers were being stored in plaintext by the very code whose job is to
    find them. The `context` field was worse still — it carried the
    surrounding text including the value.

    Offset and length are what a consumer actually needs: locate the hit and
    size it. Nothing in the codebase read the raw value; it was pure exposure.
    Correlation across sightings would need a keyed HMAC, not a bare hash — a
    SHA-256 of an SSN is brute-forceable across the whole 10^9 keyspace — so
    it is deliberately not offered here until a key exists to do it properly.
    """
    matched = value if value is not None else match.group(0)
    return {"match_offset": match.start(), "match_length": len(matched)}


def _scan_sensitive_data(text: str) -> List[Dict[str, Any]]:
    """Detect sensitive data / PII.

    Pipeline:
      1. NER model (primary) – dslim/bert-base-NER
      2. Regex fallback for structured patterns (SSN, CC, AWS key, private key)
      3. Semantic DLP vector similarity
      4. Entity regex (email, phone, IBAN, JWT, generic API keys)
      5. Exfiltration intent signals
    """
    findings: List[Dict[str, Any]] = []
    normalized = _normalize_adversarial_text(text or "")
    expanded = _decode_obfuscated_segments(normalized)

    # 1. NER-based PII (primary ML detector).
    # _ml_detector_findings translates an `available: False` member into a
    # detector_unavailable finding. Without it, a NER model that never loaded
    # or crashed mid-inference contributed nothing to `findings` and the DLP
    # verdict read "no PII" for text the PII model never saw. The regex passes
    # below still run, so coverage degrades rather than disappearing — but a
    # degraded scan must say so.
    findings.extend(
        _ml_detector_findings("ner_pii_model", ner_pii_detector.detect(expanded))
    )

    # 2. Regex fallback for structured patterns that NER may miss
    for name, pattern in _SENSITIVE_REGEX_PATTERNS:
        for match in pattern.finditer(expanded):
            findings.append(
                {
                    "type": "sensitive_data",
                    "subtype": name,
                    **_match_evidence(match),
                    "severity": "high" if name in {"private_key", "aws_key"} else "medium",
                    "detector": "regex_fallback",
                }
            )

    # 2b. Context-aware compact SSN detection.
    # We intentionally avoid treating every bare 9-digit value as an SSN
    # because that would create noisy false positives for IDs and invoice
    # numbers. This path only triggers when nearby context strongly suggests
    # an SSN-style field.
    for pattern in _CONTEXTUAL_SSN_PATTERNS:
        for match in pattern.finditer(expanded):
            compact_value = next((g for g in match.groups() if g), match.group(0))
            findings.append(
                {
                    "type": "sensitive_data",
                    "subtype": "ssn",
                    "severity": "medium",
                    "detector": "regex_contextual",
                    **_match_evidence(match, compact_value),
                }
            )

    # 2c. Context-aware EIN detection. Covers both the structured
    # "NN-NNNNNNN" form and bare 9 digits when nearby context names
    # the value as an EIN/FEIN/Federal Tax ID.
    for pattern in _CONTEXTUAL_EIN_PATTERNS:
        for match in pattern.finditer(expanded):
            compact_value = next((g for g in match.groups() if g), match.group(0))
            findings.append(
                {
                    "type": "sensitive_data",
                    "subtype": "ein",
                    "severity": "medium",
                    "detector": "regex_contextual",
                    **_match_evidence(match, compact_value),
                }
            )

    # 2d. Context-aware driver's license, passport, ABA routing, DOB, and the
    # institution-assigned PHI identifiers (MRN, health plan / member id, NPI,
    # DEA). All contextual-only: bare alphanumerics or digit runs without a
    # nearby label create too many false positives. For the PHI four this is
    # not a tuning preference -- an MRN is whatever the hospital says it is,
    # so the label IS the signal.
    for subtype, patterns in (
        ("drivers_license", _CONTEXTUAL_DRIVERS_LICENSE_PATTERNS),
        ("passport",        _CONTEXTUAL_PASSPORT_PATTERNS),
        ("bank_routing",    _CONTEXTUAL_ABA_ROUTING_PATTERNS),
        ("date_of_birth",   _CONTEXTUAL_DOB_PATTERNS),
        ("mrn",             _CONTEXTUAL_MRN_PATTERNS),
        ("health_plan_id",  _CONTEXTUAL_HEALTH_PLAN_PATTERNS),
        ("npi",             _CONTEXTUAL_NPI_PATTERNS),
        ("dea",             _CONTEXTUAL_DEA_PATTERNS),
    ):
        for pattern in patterns:
            for match in pattern.finditer(expanded):
                compact_value = next((g for g in match.groups() if g), match.group(0))
                findings.append(
                    {
                        "type": "sensitive_data",
                        "subtype": subtype,
                        "severity": "medium",
                        "detector": "regex_contextual",
                        **_match_evidence(match, compact_value),
                    }
                )

    # 2e. Opt-in state-specific driver's license formats. Only runs when
    # CYBERARMOR_DETECTION_DL_STATES is set; disabled by default because
    # the bare digit forms (TX 8 digits, NY 9 digits) collide with too many
    # non-DL identifiers.
    for state, pattern in _ENABLED_DL_STATE_PATTERNS:
        for match in pattern.finditer(expanded):
            findings.append(
                {
                    "type": "sensitive_data",
                    "subtype": "drivers_license",
                    **_match_evidence(match),
                    "severity": "low" if state in _DL_STATE_HIGH_FP_WARNING else "medium",
                    "detector": f"regex_state_{state.lower()}",
                }
            )

    # 3. Semantic DLP
    findings.extend(_scan_semantic_dlp(expanded))

    # 4. Entity-aware regex (email, phone, IBAN, JWT, API keys)
    for name, pat in _ENTITY_REGEX_PATTERNS:
        for m in pat.finditer(text):
            findings.append(
                {
                    "type": "sensitive_data",
                    "subtype": "entity_dlp",
                    "entity": name,
                    "match": m.group(0)[:120],
                    "severity": "medium" if name in {"email", "phone"} else "high",
                    "detector": "entity_regex",
                }
            )

    # 5. Exfiltration intent
    findings.extend(_scan_exfil_intent(expanded))
    return findings


# ---------------------------------------------------------------------------
# Path B (Step 2): client-facing DLP redaction.
#
# Maps the internal regex/entity names to a stable client-facing class
# vocabulary that policies use in their `redact_classes` field. The
# Policy Builder UI (step 3) populates its multi-select from this map.
# ---------------------------------------------------------------------------

# class_name -> list of (internal_name, compiled_pattern, capture_group_or_None)
# capture_group is the regex group whose span we redact (None = whole match)
# Reference the sensitive-regex entries by name rather than position so the
# map doesn't silently break when the patterns list reorders. Built once at
# module-load.
_SENSITIVE_REGEX_BY_NAME: Dict[str, "re.Pattern[str]"] = {n: p for n, p in _SENSITIVE_REGEX_PATTERNS}
_ENTITY_REGEX_BY_NAME:    Dict[str, "re.Pattern[str]"] = {n: p for n, p in _ENTITY_REGEX_PATTERNS}

_REDACT_CLASS_MAP: Dict[str, List[tuple]] = {
    # ── PHI (HIPAA Safe Harbor identifiers not covered by pii.*) ──────────
    # A redact policy naming these classes is what actually keeps a medical
    # record number out of an AI prompt. Without an entry here a pattern
    # above would be DETECTED and reported but never REDACTED -- visible in a
    # finding, still in the payload.
    "phi.mbi":              [("mbi",            _SENSITIVE_REGEX_BY_NAME["mbi"],            None)],
    "phi.icd10":            [("icd10",          _SENSITIVE_REGEX_BY_NAME["icd10"],          None)],
    "phi.mrn":              [
        ("mrn",             _CONTEXTUAL_MRN_PATTERNS[0],              1),
        ("mrn",             _CONTEXTUAL_MRN_PATTERNS[1],              1),
    ],
    "phi.health_plan_id":   [
        ("health_plan_id",  _CONTEXTUAL_HEALTH_PLAN_PATTERNS[0],      1),
        ("health_plan_id",  _CONTEXTUAL_HEALTH_PLAN_PATTERNS[1],      1),
    ],
    "phi.npi":              [
        ("npi",             _CONTEXTUAL_NPI_PATTERNS[0],              1),
        ("npi",             _CONTEXTUAL_NPI_PATTERNS[1],              1),
    ],
    "phi.dea":              [
        ("dea",             _CONTEXTUAL_DEA_PATTERNS[0],              1),
        ("dea",             _CONTEXTUAL_DEA_PATTERNS[1],              1),
    ],
    "pii.email":            [("email",          _ENTITY_REGEX_BY_NAME["email"],             None)],
    "pii.phone":            [("phone",          _ENTITY_REGEX_BY_NAME["phone"],             None)],
    "pii.iban":             [("iban",           _ENTITY_REGEX_BY_NAME["iban"],              None)],
    "pii.ssn":              [
        ("ssn",             _SENSITIVE_REGEX_BY_NAME["ssn"],          None),
        ("ssn",             _CONTEXTUAL_SSN_PATTERNS[0],              1),
        ("ssn",             _CONTEXTUAL_SSN_PATTERNS[1],              1),
    ],
    "pii.ein":              [
        ("ein",             _SENSITIVE_REGEX_BY_NAME["ein"],          None),
        ("ein",             _CONTEXTUAL_EIN_PATTERNS[0],              1),
        ("ein",             _CONTEXTUAL_EIN_PATTERNS[1],              1),
    ],
    "pii.drivers_license":  [
        ("drivers_license", _SENSITIVE_REGEX_BY_NAME["drivers_license"], None),
        ("drivers_license", _CONTEXTUAL_DRIVERS_LICENSE_PATTERNS[0],  1),
        ("drivers_license", _CONTEXTUAL_DRIVERS_LICENSE_PATTERNS[1],  1),
        # State-specific patterns are appended only when enabled via env.
        # Redact policies pick them up automatically without code changes.
        *[(f"drivers_license_{s.lower()}", p, None) for s, p in _ENABLED_DL_STATE_PATTERNS],
    ],
    "pii.passport":         [
        ("passport",        _CONTEXTUAL_PASSPORT_PATTERNS[0],         1),
        ("passport",        _CONTEXTUAL_PASSPORT_PATTERNS[1],         1),
    ],
    "pii.bank_routing":     [
        ("bank_routing",    _CONTEXTUAL_ABA_ROUTING_PATTERNS[0],      1),
        ("bank_routing",    _CONTEXTUAL_ABA_ROUTING_PATTERNS[1],      1),
    ],
    "pii.date_of_birth":    [
        ("date_of_birth",   _CONTEXTUAL_DOB_PATTERNS[0],              1),
    ],
    "pii.credit_card":      [("credit_card",    _SENSITIVE_REGEX_BY_NAME["credit_card"],    None)],
    "secret.aws_access_key":[("aws_key",        _SENSITIVE_REGEX_BY_NAME["aws_key"],        None)],
    "secret.gcp_api_key":   [("gcp_api_key",    _SENSITIVE_REGEX_BY_NAME["gcp_api_key"],    None)],
    "secret.github_token":  [("github_token",   _SENSITIVE_REGEX_BY_NAME["github_token"],   None)],
    "secret.openai_key":    [("openai_api_key", _SENSITIVE_REGEX_BY_NAME["openai_api_key"], None)],
    "secret.anthropic_key": [("anthropic_key",  _SENSITIVE_REGEX_BY_NAME["anthropic_api_key"], None)],
    "secret.slack_token":   [("slack_token",    _SENSITIVE_REGEX_BY_NAME["slack_token"],    None)],
    "secret.stripe_key":    [("stripe_key",     _SENSITIVE_REGEX_BY_NAME["stripe_key"],     None)],
    "secret.api_key":       [
        ("generic_api_key", _SENSITIVE_REGEX_BY_NAME["generic_api_key"], 1),
        ("entity_api_key",  _ENTITY_REGEX_BY_NAME.get("api_key") or _ENTITY_REGEX_PATTERNS[4][1], None),
    ],
    "secret.password":      [("password",       _SENSITIVE_REGEX_BY_NAME["password_field"], 1)],
    "secret.private_key":   [("private_key",    _SENSITIVE_REGEX_BY_NAME["private_key"],    None)],
    "secret.jwt":           [("jwt",            _ENTITY_REGEX_BY_NAME.get("jwt") or _ENTITY_REGEX_PATTERNS[3][1], None)],
}

# Path B follow-up: NER-only classes (no regex patterns; spans come from
# the dslim/bert-base-NER model via NERPIIDetector.redact_spans). Listed
# in the catalog so the Policy Builder can offer them, with empty regex
# lists so the regex pass yields nothing — NER does the work.
_NER_ONLY_CLASSES = [
    "pii.person_name", "pii.location", "pii.organization",
    "pii.ip_address", "pii.url", "pii.crypto_address",
]
for _cls in _NER_ONLY_CLASSES:
    _REDACT_CLASS_MAP.setdefault(_cls, [])

# Public class catalog for the Policy Builder. Keep keys human-orderable.
REDACT_CLASS_CATALOG = sorted(_REDACT_CLASS_MAP.keys())


REDACTION_COMPLETE: Dict[str, Any] = {
    "complete": True,
    "reason": None,
    "error": None,
    "model": None,
    "unredacted_classes": [],
}


def _redact_text(
    text: str, targets: List[str]
) -> tuple[str, Dict[str, int], Dict[str, Any]]:
    """Replace matches of the requested DLP classes with [REDACTED:<class>].

    Returns (redacted_text, class_counts, status). class_counts is the
    per-class count of matches replaced — never the matched content itself,
    so it's safe to log. `status` reports whether every requested class was
    actually processed; see the fail-closed note on `scan_redact`.

    Spans are collected from regex patterns AND the NER detector (for
    pii.person_name / pii.location / pii.organization / pii.ip_address /
    pii.url / pii.crypto_address — entities the regex catalog can't
    catch). Both span sources are merged, sorted, deduped (keep the
    first match by start position; later overlapping ones are dropped),
    and replaced right-to-left to preserve indices.

    When the NER stage does not complete, `redacted_text` here is the
    regex-only result. It is a partial redaction and MUST NOT be handed to a
    caller as finished work — `status["complete"]` is False and the endpoint
    withholds the text. This function returns it so the count of what *was*
    masked stays available for logging.
    """
    if not text or not targets:
        return text or "", {}, dict(REDACTION_COMPLETE)

    # Collect (start, end, class_name) for every match.
    spans: List[tuple] = []
    counts: Dict[str, int] = {}
    for cls in targets:
        for _internal, pattern, group in _REDACT_CLASS_MAP.get(cls, []):
            for m in pattern.finditer(text):
                if group is not None and m.group(group):
                    s, e = m.span(group)
                else:
                    s, e = m.span()
                if s == e:
                    continue
                spans.append((s, e, cls))

    # Path B follow-up: NER-derived spans for unstructured PII.
    status: Dict[str, Any] = dict(REDACTION_COMPLETE)
    try:
        ner_result = ner_pii_detector.redact_spans(text, targets)
        # PHI spans come from a different model; union them in. Spans are
        # merged, not replaced -- an identifier either model finds must be
        # removed, because in a REDACTION path a miss is text the caller
        # believes is safe to forward onward.
        phi_result = ner_phi_detector.redact_spans(text, targets)
        spans.extend(ner_result.spans)
        spans.extend(phi_result.spans)
        # PHI spans are ADDITIVE and deliberately do not affect `complete`.
        # Every phi.* class has a regex floor in _REDACT_CLASS_MAP, so the
        # clinical model is never the sole source for one -- it adds recall on
        # identifiers sitting in prose with no adjacent label. Marking the
        # result incomplete when it is absent would fail closed on redaction
        # the regex layer actually performed, and would degrade every scan in
        # every non-healthcare tenant that never asked for PHI.
        # IF A NER-ONLY phi.* CLASS IS EVER ADDED (one with an empty regex
        # entry, as the six pii.* NER-only classes have), this stops being true
        # and phi_result must join the completeness calculation below.
        incomplete = [r for r in (ner_result,) if not r.complete]
        if incomplete:
            # NOT "non-fatal — NER is additive". For the NER-only classes NER
            # is the ONLY source of spans, so an incomplete NER stage means
            # those classes were not redacted at all, in text the caller is
            # about to send to an external provider.
            first = incomplete[0]
            unredacted: set = set()
            for r in incomplete:
                unredacted |= set(r.ner_classes)
            status = {
                "complete": False,
                "reason": first.reason,
                "error": first.error,
                "model": ", ".join(r.model for r in incomplete if r.model),
                "unredacted_classes": sorted(unredacted),
            }
    except Exception as exc:
        # An unexpected raise (redact_spans handles inference errors itself).
        # Previously logged at warning and ignored, which produced exactly the
        # silent partial redaction this whole path now refuses to emit.
        logger.error("ner_redact_spans_error err=%s", exc)
        status = {
            "complete": False,
            "reason": "redact_spans_error",
            "error": str(exc),
            "model": None,
            "unredacted_classes": sorted(
                c for c in targets if c in REDACT_CLASS_TO_NER_GROUPS
            ),
        }

    if not spans:
        return text, {}, status

    # Sort by start, drop overlaps (keep first), then sort right-to-left
    # for in-place replacement.
    spans.sort(key=lambda x: (x[0], -x[1]))
    deduped: List[tuple] = []
    last_end = -1
    for s, e, cls in spans:
        if s < last_end:
            continue   # overlaps a span already kept
        deduped.append((s, e, cls))
        last_end = e

    deduped.sort(key=lambda x: x[0], reverse=True)

    out = text
    for s, e, cls in deduped:
        out = out[:s] + f"[REDACTED:{cls}]" + out[e:]
        counts[cls] = counts.get(cls, 0) + 1

    return out, counts, status


def _scan_exfil_intent(text: str) -> List[Dict[str, Any]]:
    findings: List[Dict[str, Any]] = []
    t = (text or "").lower()
    intent_patterns = [
        r"\b(export|send|transmit|leak|exfiltrat\w*)\b.{0,40}\b(data|records|credentials|tokens|customer)\b",
        r"\b(upload|post|paste)\b.{0,40}\b(external|public|gist|pastebin|webhook)\b",
        r"\bcopy\b.{0,20}\b(all|entire)\b.{0,40}\b(database|table|customer|invoice|email)\b",
    ]
    hits = sum(
        1
        for pat in intent_patterns
        if re.search(pat, t, flags=re.IGNORECASE | re.DOTALL)
    )
    if hits > 0:
        findings.append(
            {
                "type": "sensitive_data",
                "subtype": "semantic_exfil_intent",
                "intent_score": round(min(1.0, hits * 0.38), 4),
                "severity": "high" if hits >= 2 else "medium",
            }
        )
    return findings


def _scan_output_safety(text: str) -> List[Dict[str, Any]]:
    """Detect dangerous output (command injection, XSS, browser data exfil).

    Pipeline:
      1. Zero-shot ML classifier (facebook/bart-large-mnli) – primary
      2. Regex patterns – supplementary high-confidence fallback
    """
    findings: List[Dict[str, Any]] = []

    # 1. Zero-shot ML (primary)
    zs_findings = zero_shot_detector.detect(text)
    # DERIVED, NOT RESTATED. This was a literal 2-label set sitting opposite a
    # literal 5-label candidate list in ml_models.py, with nothing keeping the
    # two in agreement -- and they did not agree. Three labels were scored by a
    # 406M-parameter model and dropped right here, unread, for 1.6 seconds of
    # every scan against a 5.0s fail-closed budget. The list is now written
    # once, where the detector is asked, and this reads it.
    #
    # The filter is kept rather than deleted: `detect` returns whatever the
    # pipeline returned, and a pipeline is not obliged to answer only the
    # labels it was asked about.
    _output_labels = set(ZERO_SHOT_THREAT_LABELS)
    for f in zs_findings:
        if f.get("available") is False:
            # Must be checked BEFORE the label filter: an unavailable marker
            # carries no `label`, so the filter below would drop it and the
            # response would again claim a clean output-safety verdict from a
            # classifier that never ran.
            findings.append(_detector_unavailable("zero_shot_classifier", f))
            continue
        if f.get("label") in _output_labels:
            f["type"] = "dangerous_output"
            findings.append(f)

    # 2. Regex supplementary patterns
    for pattern in _DANGEROUS_OUTPUT_PATTERNS:
        match = pattern.search(text)
        if match:
            findings.append(
                {
                    "type": "dangerous_output",
                    "pattern": pattern.pattern,
                    # Matched text withheld for the same reason as the DLP
                    # paths: model output can carry anything, including
                    # credentials it was asked to echo, and this record is
                    # persisted. `pattern` already identifies the threat
                    # class. If analysts need the literal text for triage it
                    # should reach them through an access-controlled path,
                    # not the general telemetry payload.
                    **_match_evidence(match),
                    "severity": "high",
                    "detector": "regex_supplementary",
                }
            )

    # 3. Ransomware behavior-combination pattern (see comment above the
    # regexes) -- a dedicated signal the zero-shot label above doesn't
    # reliably cover for generated code specifically.
    findings.extend(_scan_dangerous_code_generation(text))
    return findings


def _scan_dangerous_code_generation(text: str) -> List[Dict[str, Any]]:
    """Flag the specific ransomware behavior combination in generated code:
    bulk file enumeration + encryption + note-drop/mass-deletion. Any one
    primitive alone is common in legitimate backup/archival code, so this
    only escalates when multiple co-occur.
    """
    hits = {
        "file_enumeration": bool(_RANSOMWARE_FILE_ENUM_RE.search(text)),
        "encryption": bool(_RANSOMWARE_ENCRYPT_RE.search(text)),
        "note_or_mass_wipe": bool(_RANSOMWARE_NOTE_OR_WIPE_RE.search(text)),
    }
    hit_count = sum(hits.values())
    if hit_count < 2:
        return []
    return [
        {
            "type": "dangerous_code_generation",
            "subtype": "ransomware_behavior_pattern",
            "matched_primitives": [k for k, v in hits.items() if v],
            "severity": "critical" if hit_count == 3 else "high",
            "detector": "regex_pattern_combination",
        }
    ]


DETECTOR_UNAVAILABLE_TYPE = "detector_unavailable"


def _detector_unavailable(detector: str, result: Dict[str, Any]) -> Dict[str, Any]:
    """Build the finding that says "this check did not run".

    Deliberately carries severity "info" and scores 0.0 risk (see _risk_score):
    a check that could not run is a *gap in coverage*, not evidence of a
    threat. Inflating the risk score here would fabricate detections and
    block benign traffic; staying silent would claim a clean result nobody
    verified. The honest third option is to say so in the payload.
    """
    return {
        "type": DETECTOR_UNAVAILABLE_TYPE,
        "subtype": detector,
        "detector": detector,
        "assessed": False,
        "reason": result.get("reason", "unknown"),
        "error": result.get("error"),
        "model": result.get("model"),
        "severity": "info",
    }


def _ml_detector_findings(
    detector: str, results: List[Dict[str, Any]]
) -> List[Dict[str, Any]]:
    """Translate a list-returning ML detector's output into scan findings.

    The list-returning detectors (NER PII, zero-shot) express "I did not run"
    as a member carrying ``available: False`` — the list analogue of the
    single-result contract ToxicityDetector uses. This maps those members onto
    the same `detector_unavailable` finding the toxicity path emits, so one
    helper (`_detectors_unavailable`) still summarises every gap and one
    branch in `_risk_score` still keeps gaps from fabricating risk.

    Real findings pass through untouched, including the ``available: True``
    they now carry.
    """
    out: List[Dict[str, Any]] = []
    for r in results:
        if r.get("available") is False:
            out.append(_detector_unavailable(detector, r))
        else:
            out.append(r)
    return out


def _scan_toxicity(text: str) -> List[Dict[str, Any]]:
    """Detect toxic / harmful content via ML classifier.

    Returns ``[]`` ONLY when the classifier ran and found the text clean.

    The defect this replaces: `return [result] if result else []` mapped a
    falsy result to an empty list, and detect() returned None for *both* "the
    text is clean" and "the model was missing or crashed". Toxicity scanning
    that never happened was reported to /scan and /scan/all callers as
    toxicity scanning that found nothing — the caller had no way to tell, and
    an evidence record was written as if the content had been assessed. A
    failed check now shows up in `detections` as its own finding.
    """
    result = toxicity_detector.detect(text)
    if result is None:
        return []  # ran, clean
    if result.get("available") is False:
        return [_detector_unavailable("toxicity_model", result)]
    return [result]


def _detectors_unavailable(findings: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """Summarise the checks that did not run, for the top level of a response.

    Additive: the same information is already inside `detections`. Lifting it
    out means a caller making a security or evidence decision does not have to
    walk the findings list to learn that its scan was incomplete.
    """
    return [
        {
            "detector": f.get("detector"),
            "reason": f.get("reason"),
            "model": f.get("model"),
        }
        for f in findings
        if f.get("type") == DETECTOR_UNAVAILABLE_TYPE
    ]


def _scan_ollama_judge(text: str, pre_score: float) -> List[Dict[str, Any]]:
    """Optional Ollama LLM second-pass judge.

    Only invoked when the pre-scan risk score exceeds OLLAMA_JUDGE_RISK_TRIGGER
    so that latency is not added to clearly benign requests.
    """
    if not OLLAMA_ENABLED or pre_score < _OLLAMA_JUDGE_RISK_TRIGGER:
        return []
    result = ollama_judge.analyze(text)
    return [result] if result else []


# ---------------------------------------------------------------------------
# Risk scoring
# ---------------------------------------------------------------------------


#: A promptware chain corroborates; it does not convict.
#:
#: MEASURED IN PRODUCTION 2026-08-06, and this is why the cap exists:
#:
#:     content: "Tea is a drink."
#:     -> promptware_attack_chain(1.00), risk=0.9, action=block
#:
#: Three words about tea, blocked. Every probe sent that day was blocked,
#: including a page on brewing temperatures, because the chain alone scored
#: 0.45 + 0.45*1.00 = 0.90 against a 0.70 block threshold. The request's own
#: content contributed nothing; the verdict came entirely from what the
#: "session" had done earlier.
#:
#: And that session was not a session: _derive_session_key falls back to
#: `source_url` when no session_id is supplied, and the local proxy supplies
#: none -- so the bucket was `tenant:request:https://api.anthropic.com/...`,
#: shared by every user in the tenant. One person's testing blocked everyone's
#: AI traffic for ~10 requests or 30 minutes. That is the mechanism behind the
#: Claude Code 403s on 2026-08-06: hours of conversation about prompt
#: injection kept the chain pinned at 1.0, so every subsequent request was
#: blocked by our own block page.
#:
#: So the chain is capped so that BY ITSELF it can reach "warn" but never
#: "block". With any content-derived finding present it adds its uplift
#: normally and can push a genuinely suspicious request over the line -- which
#: is the job it was written for. Escalating evidence, not standalone proof.
#: The two lines every scan is judged against. They were literals inside
#: scan() and separately inside this module's cap, so "one hundredth under the
#: block line" was a number that had to be kept in step with a different number
#: by hand. Written once, derived everywhere.
RISK_BLOCK_THRESHOLD = 0.70
RISK_WARN_THRESHOLD = 0.35

_CHAIN_CANNOT_CONVICT_ALONE = RISK_BLOCK_THRESHOLD - 0.01


def _risk_score(findings: List[Dict[str, Any]]) -> float:
    if not findings:
        return 0.0
    score = 0.0
    for f in findings:
        ftype = f.get("type", "")
        detector = f.get("detector", "")

        if ftype == DETECTOR_UNAVAILABLE_TYPE:
            # A detector that could not run contributes no risk — it found
            # nothing because it never looked. It must still be carried in
            # `detections` so the caller knows its coverage was incomplete.
            # (Explicit branch: without it the generic severity fallback below
            # would score this finding and quietly nudge scans toward "warn".)
            continue

        if ftype == "prompt_injection" and detector in {
            "ml_classifier", "ensemble", "heuristic_fallback",
        }:
            confidence = float(f.get("confidence", 0.0))
            threshold = float(f.get("threshold", _PI_ML_THRESHOLD))
            margin = max(0.0, confidence - threshold)
            score += min(_PI_RISK_BASE + (_PI_RISK_MULTIPLIER * margin), _PI_RISK_CAP)
            continue

        if ftype == "promptware_attack_chain":
            # SCORED SEPARATELY, BELOW. A chain describes what this SESSION has
            # done over the last half hour; it is not evidence about the bytes
            # in front of us. Adding it into the same pot let it convict a
            # request whose own content scored zero -- see the block comment on
            # _CHAIN_CANNOT_CONVICT_ALONE.
            continue

        if ftype == "dangerous_code_generation":
            # "critical" (all 3 primitives) scores enough alone to cross
            # the block threshold (0.70) -- that combination is not
            # something legitimate code plausibly needs together.
            # "high" (2 of 3) lands solidly in warn territory (>=0.35) but
            # not block alone, since e.g. "encrypt a backup then delete
            # the originals" is a real, legitimate pattern on its own.
            sev = f.get("severity", "high")
            score += 0.8 if sev == "critical" else 0.45
            continue

        if ftype == "llm_threat_analysis":
            confidence = float(f.get("confidence", 0.0))
            sev = f.get("severity", "medium")
            base = {"high": 0.55, "medium": 0.35, "low": 0.15}.get(sev, 0.25)
            score += base + (0.3 * confidence)
            continue

        sev = f.get("severity", "low")
        if sev == "high":
            score += 0.35
        elif sev == "medium":
            score += 0.20
        else:
            score += 0.10

    # -- the chain, scored last and separately ---------------------------
    chain_conf = max((float(f.get("confidence", 0.0))
                      for f in findings
                      if f.get("type") == "promptware_attack_chain"), default=0.0)
    if chain_conf > 0.0:
        uplift = min(0.45 + (0.45 * max(0.0, min(1.0, chain_conf))), 0.95)
        if score < RISK_WARN_THRESHOLD:
            # THIS REQUEST'S OWN CONTENT DID NOT EVEN REACH "WARN", so the
            # chain may raise concern but may not decide. Capped below the
            # block line: a request like this can warn on session history,
            # never block on it.
            #
            # THE CLIFF THIS REPLACES, and it shipped: the test was
            # `score <= 0.0`, so ANY non-zero content finding unlocked the
            # full uplift. MEASURED against production 2026-08-07, after the
            # first fix was live:
            #
            #     benign.html -> sensitive_data + promptware_attack_chain
            #                 -> risk 1.0, action=block
            #
            # 800 characters about oxidising tea leaves. Its own content
            # scored 0.2 -- an organisation name tripping a DLP pattern, well
            # under the 0.35 warn line and correctly `allow` on its own. The
            # chain then added 0.74 and blocked it. A rule that treats 0.0 and
            # 0.0001 as different in kind is not a rule, it is a cliff, and it
            # let the chain go on convicting as long as something, anything,
            # scored first.
            score = min(score + uplift, _CHAIN_CANNOT_CONVICT_ALONE)
        else:
            # The request earned "warn" on its own evidence. Corroboration
            # from the session can now carry it over the line -- the job the
            # chain was written for.
            score += uplift
    return min(score, 1.0)


# ---------------------------------------------------------------------------
# Auth helper
# ---------------------------------------------------------------------------


def _verify_api_key(api_key: Optional[str]) -> None:
    verify_shared_secret(api_key, DETECTION_API_SECRET, service_name="detection")


# ---------------------------------------------------------------------------
# FastAPI application
# ---------------------------------------------------------------------------

@asynccontextmanager
async def _lifespan(_app: FastAPI):
    """Warm the ML models off the request path, then serve.

    `lifespan` rather than `@app.on_event("startup")` because on_event is
    deprecated and this image installs FastAPI unpinned.

    start_model_warmup() returns immediately -- it spawns a daemon thread --
    so nothing here delays uvicorn binding its port. That matters: the
    container healthcheck polls /health every 10s with 3 retries and no
    start_period, and three services gate on `condition: service_healthy`.
    """
    start_model_warmup()
    yield


app = FastAPI(title="CyberArmor Detection Service", version="0.3.0",
              lifespan=_lifespan)
SERVICE_STARTED_AT = time.time()

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=False,
    allow_methods=["*"],
    allow_headers=["*"],
)


# ── Scan concurrency: bounded, and shed fast when full ────────────────────────
#
# MEASURED TWICE ON PRODUCTION (2026-08-11 and 2026-08-14). This service runs
# one uvicorn process with sync-def endpoints, so every request -- scans AND the
# healthcheck -- shares one FastAPI threadpool. Under scan load, torch saturates
# the CPU, /health queues behind the inference backlog, times out (HTTP 000
# after 20s on the 11th), docker marks the container unhealthy, and the watchdog
# restarts it -- which RELOADS ~4 GiB of models while traffic keeps arriving.
# Three restarts in 180 minutes on the 14th, none of which fixed anything,
# because saturation is not a fault. The restart was the only lever the outside
# world had, and it was the wrong one.
#
# Two changes, one honest idea:
#   * /health is async: it runs on the EVENT LOOP, not the shared threadpool,
#     so it answers while every pool thread is busy -- and reports the
#     saturation as data. Liveness and load are different facts; conflating
#     them is what turned "busy" into a restart loop.
#   * scans acquire a bounded slot, and when none frees up within
#     _SCAN_SHED_AFTER_S they fail fast with 503 instead of queueing into a
#     timeout. Callers already apply their own fail mode to detection being
#     unavailable; a fast honest 503 and a slow timeout produce the same
#     enforcement outcome, but only one of them also takes /health down.
#
# WHAT A SHED MEANS, said plainly: with a fail-open tenant, that request passes
# UNINSPECTED -- exactly as it did during yesterday's silent 20-second stalls,
# but now counted, logged, and visible on /health instead of buried in latency.

_SCAN_MAX_CONCURRENT = int(os.getenv(
    "CYBERARMOR_DETECTION_MAX_CONCURRENT_SCANS", str(max(2, os.cpu_count() or 2))))
_SCAN_SHED_AFTER_S = float(os.getenv("CYBERARMOR_DETECTION_SHED_AFTER_S", "2.0"))

_SCAN_SLOTS = BoundedSemaphore(_SCAN_MAX_CONCURRENT)
_scan_slots_in_use = 0
_scan_sheds_total = 0
_scan_slot_lock = Lock()


def _sheds_when_saturated(fn):
    """Bound an endpoint's concurrency; 503 fast instead of queueing forever."""
    @functools.wraps(fn)
    def wrapper(*args, **kwargs):
        global _scan_slots_in_use, _scan_sheds_total
        if not _SCAN_SLOTS.acquire(timeout=_SCAN_SHED_AFTER_S):
            with _scan_slot_lock:
                _scan_sheds_total += 1
                shed_n = _scan_sheds_total
            # Every shed is an uninspected request (under fail-open) or a
            # blocked one (fail-closed). Log the first and then every 50th:
            # a burst must be visible without the log itself becoming load.
            if shed_n == 1 or shed_n % 50 == 0:
                logging.getLogger("detection").warning(
                    "scan_shed_saturated total=%s limit=%s wait_s=%s -- "
                    "requests are passing UNINSPECTED under fail-open tenants",
                    shed_n, _SCAN_MAX_CONCURRENT, _SCAN_SHED_AFTER_S,
                )
            raise HTTPException(
                status_code=503,
                detail={
                    "reason": "detector_saturated",
                    "detail": (
                        f"all {_SCAN_MAX_CONCURRENT} scan slots busy for "
                        f"{_SCAN_SHED_AFTER_S}s; shedding rather than queueing. "
                        "Apply your fail mode; nothing was scanned."
                    ),
                },
            )
        with _scan_slot_lock:
            _scan_slots_in_use += 1
        try:
            return fn(*args, **kwargs)
        finally:
            with _scan_slot_lock:
                _scan_slots_in_use -= 1
            _SCAN_SLOTS.release()
    return wrapper


def _rate_limited(
    x_api_key: Optional[str] = Header(default=None, alias="x-api-key"),
    x_client_id: Optional[str] = Header(default=None, alias="x-client-id"),
) -> None:
    """Per-client token bucket, attached as a route dependency.

    A dependency rather than a decorator so endpoint signatures are untouched:
    FastAPI builds the request model from the signature, and wrapping these
    handlers to read headers would mean restating every parameter.

    Disabled unless CYBERARMOR_DETECTION_RATE_LIMIT_RPM > 0, so the B2B
    deployment is unaffected until it opts in.
    """
    allowed, retry_after = SCAN_LIMITER.check(
        SCAN_LIMITER.identity(x_api_key, x_client_id)
    )
    if allowed:
        return
    raise HTTPException(
        status_code=429,
        detail={
            "reason": "rate_limited",
            "detail": (
                "per-client scan rate exceeded; nothing was scanned. "
                "Apply your fail mode."
            ),
            "retry_after_seconds": retry_after,
        },
        headers={"Retry-After": str(max(1, int(retry_after + 0.999)))},
    )


#: Applied to every scan route. One list so a new endpoint cannot be added
#: without a deliberate decision to leave it unlimited.
_SCAN_DEPS = [Depends(_rate_limited)]


def _profile_skip_payload(detector: str) -> Dict[str, Any]:
    """The response for a single-detector route the profile does not run.

    HTTP 501, not 200-with-no-findings. A consumer deployment that dropped the
    zero-shot model must not answer "output safety: clean" for a check it never
    performed -- that is the exact defect `detector_unavailable` exists to
    prevent, and a silent 200 here would smuggle it back in through the one
    path that bypasses the findings list.
    """
    return {
        "reason": "detector_not_enabled_in_profile",
        "detail": (
            f"detector {detector!r} is not enabled in serving profile "
            f"{detection_profile.PROFILE!r}; nothing was scanned. This is "
            "configuration, not a fault -- the model is absent by design."
        ),
        "profile": detection_profile.PROFILE,
        "detectors_enabled": sorted(detection_profile.ENABLED_DETECTORS),
    }


def _require_detector(detector: str) -> None:
    if not detection_profile.is_enabled(detector):
        raise HTTPException(status_code=501, detail=_profile_skip_payload(detector))


def _cached_scan(namespace: str, text: str, extra: str = ""):
    """Return (cache_key, cached_response_or_None).

    `extra` folds any non-text input into the key. A scan is only a pure
    function of its text once everything else that can change the answer is
    part of the identity -- see the promptware guard at the /scan call site for
    the input that is NOT foldable and disables caching outright.
    """
    key = SCAN_CACHE.key(
        namespace, text, detection_profile.config_fingerprint(extra)
    )
    return key, SCAN_CACHE.get(key)


def _with_profile_markers(payload: Dict[str, Any], *, cached: bool) -> Dict[str, Any]:
    """Stamp every scan response with what was skipped and whether it is fresh.

    `checks_skipped_by_profile` is present even when empty. An always-present
    key is readable; a key that appears only in the narrow configuration is one
    a caller learns about the first time it matters.
    """
    payload["profile"] = detection_profile.PROFILE
    payload["checks_skipped_by_profile"] = detection_profile.skipped_detectors()
    payload["cached"] = cached
    return payload


@app.get("/health")
async def health():
    """Alive-ness, answered from the EVENT LOOP.

    async on purpose, and it is the fix, not a style choice: sync-def handlers
    share one threadpool with the scans, so under saturation this endpoint
    queued behind torch inference and timed out -- and docker read "busy" as
    "dead" and restarted the container into a model-reload loop. The event
    loop stays responsive while the pool is pegged, so this answers, and
    carries the saturation numbers so "alive but shedding" is observable
    instead of invisible.
    """
    with _scan_slot_lock:
        in_use = _scan_slots_in_use
        sheds = _scan_sheds_total
    return {
        "status": "ok",
        "version": "0.3.0",
        "profile": detection_profile.PROFILE,
        "scan_slots": {
            "limit": _SCAN_MAX_CONCURRENT,
            "in_use": in_use,
            "saturated": in_use >= _SCAN_MAX_CONCURRENT,
            "sheds_total": sheds,
        },
        # Same reasoning as scan_slots: load and liveness are different facts,
        # and a cache hit rate that has collapsed is the earliest warning that
        # the cheap tier has stopped being cheap.
        "scan_cache": SCAN_CACHE.stats(),
        "rate_limit": SCAN_LIMITER.stats(),
    }


@app.get("/ready")
def ready():
    """Readiness probe.

    The defect this replaces: the response hardcoded the four model names and
    reported "ready" unconditionally. It described the models the service
    *intends* to have — a service whose ML models had all failed to load
    returned a payload byte-identical to a fully healthy one.

    Two constraints shape the fix:

      * This is a container probe. `model_status()` is a pure read of
        in-process load state, so nothing here can trigger a download or a
        cold load; a probe must never be the thing that pulls model weights.
      * A missing ML model does NOT make the service unready. Every ML
        detector has a heuristic/regex fallback and the service keeps serving
        real answers without it, so failing the probe would take down working
        capacity. It reports "degraded" instead — honest about reduced
        coverage, still accepting traffic. HTTP stays 200 so probes and
        orchestrators behave as before.
    """
    statuses = model_status()
    warm = warmup_status()
    # `not_attempted` MEANS SOMETHING DIFFERENT ONCE A WARMUP EXISTS, and the
    # comment that used to sit here -- "lazy-loading working as designed, not
    # a fault" -- stopped being true the moment one was added. Three cases now
    # hide under that one status, and they are not the same claim:
    #
    #   warmup running  -> not reached yet. Expected, transient, will resolve.
    #   warmup finished -> the warmup touched every declared model, so a model
    #                      still untouched is a model the warmup did not know
    #                      about. That is a real fault and it must not read as
    #                      lazy loading working correctly.
    #   warmup disabled -> genuine lazy loading, the original meaning.
    #
    # Collapsing them would put this probe back in the exact class of defect
    # it was written to fix: a payload that looks identical whether the thing
    # it describes is healthy or broken.
    unattempted = [name for name, s in statuses.items()
                   if s.get("status") == MODEL_STATUS_NOT_ATTEMPTED]
    stragglers = unattempted if warm.get("state") == "finished" else []
    degraded = [
        name
        for name, s in statuses.items()
        if s.get("status") not in (MODEL_STATUS_LOADED, MODEL_STATUS_NOT_ATTEMPTED)
    ] + stragglers
    return {
        # "degraded" = serving on heuristic fallbacks with reduced ML coverage.
        "status": "degraded" if degraded else "ready",
        # Stable machine-readable signal for probes that parse the body:
        # this service is always ready to accept traffic if it answers at all.
        "ready": True,
        "service": "detection",
        "version": "0.3.0",
        # Unchanged shape: the CONFIGURED model ids. Not a health claim —
        # see ml_model_status for what is actually resident.
        "ml_models": dict(MODEL_IDS),
        "ml_model_status": statuses,
        "degraded_models": degraded,
        # THE SERVING PROFILE, AND WHY IT IS REPORTED SEPARATELY FROM
        # `degraded_models`. Both describe a model this process is not running,
        # and they are not the same claim: `degraded` means a model that was
        # expected did not load -- a fault, someone should look. This means a
        # model was never asked for -- a deployment choice, nothing is wrong.
        # A reader that cannot tell them apart either pages for a configuration
        # or ignores a real outage, and both have happened in this codebase.
        **detection_profile.describe(),
        "models_disabled_by_profile": dict(MODELS_DISABLED_BY_PROFILE),
        # Additive: without it, "not_attempted" is unreadable -- a caller
        # cannot tell a model the warmup has not reached from one it never
        # knew about.
        "warmup": warm,
        "detail": (
            (
                "ML models unavailable; serving on heuristic fallbacks: "
                + ", ".join(sorted(degraded))
            )
            if degraded
            else (
                "warming models in the background; "
                f"{len(warm.get('pending') or [])} still to load"
                if warm.get("state") == "running"
                else "all configured ML models loaded or awaiting first use"
            )
        ),
        "ollama_enabled": OLLAMA_ENABLED,
        "ollama_judge": ollama_judge.is_available(),
        "scan_cache": SCAN_CACHE.stats(),
        "rate_limit": SCAN_LIMITER.stats(),
    }


@app.get("/metrics")
def metrics():
    uptime = round(time.time() - SERVICE_STARTED_AT, 3)
    return PlainTextResponse(
        "\n".join(
            [
                "# HELP cyberarmor_detection_uptime_seconds Service uptime in seconds",
                "# TYPE cyberarmor_detection_uptime_seconds gauge",
                f'cyberarmor_detection_uptime_seconds{{service="detection",version="0.3.0"}} {uptime}',
            ]
        )
        + "\n",
        media_type="text/plain",
    )


@app.get("/pki/public-key")
def pki_public_key():
    return get_public_key_info("detection")


@app.post("/scan", dependencies=_SCAN_DEPS)
@_sheds_when_saturated
def scan(
    payload: GenericScanRequest,
    x_api_key: Optional[str] = Header(default=None, alias="x-api-key"),
):
    _verify_api_key(x_api_key)
    text = payload.content or ""

    # ---- Result cache -----------------------------------------------------
    # Only consult it when this scan really is a pure function of its inputs.
    # The promptware tracker carries state ACROSS requests -- the same text can
    # legitimately produce a chain finding on the fifth call and none on the
    # first -- so with session tracking on, a cached verdict would be wrong,
    # not merely stale. `local_findings` arrive from the caller and are merged
    # into the result, so they are folded into the key rather than ignored.
    cacheable = not _PROMPTWARE_SESSION_ENABLED
    cache_key = None
    if cacheable:
        extra = json.dumps(payload.local_findings, sort_keys=True, default=str)
        cache_key, hit = _cached_scan("scan", text, extra)
        if hit is not None:
            # Echoed request fields are re-stamped from THIS request: they
            # identify the caller, not the verdict, and serving another
            # request's tenant_id back would be a cross-caller leak.
            hit["tenant_id"] = payload.tenant_id
            hit["direction"] = payload.direction
            return _with_profile_markers(hit, cached=True)

    findings: List[Dict[str, Any]] = list(payload.local_findings)

    # Prompt injection + ensemble
    findings.extend(_scan_prompt_injection(text))

    # Promptware session correlation
    if _PROMPTWARE_SESSION_ENABLED:
        ml_conf = max(
            (
                float(f.get("confidence", 0.0))
                for f in findings
                if f.get("type") == "prompt_injection"
                and f.get("detector") == "ml_classifier"
            ),
            default=0.0,
        )
        session_key = _derive_session_key(
            payload.tenant_id, payload.direction, payload.source_url, payload.session_id
        )
        chain_finding = _PROMPTWARE_TRACKER.observe(
            session_key=session_key, text=text, pi_confidence=ml_conf
        )
        if chain_finding is not None:
            findings.append(chain_finding)

    # Sensitive data / DLP
    if detection_profile.is_enabled("sensitive_data"):
        findings.extend(_scan_sensitive_data(text))

    # Output safety. Skipped entirely under a profile that drops it -- NOT run
    # against a missing model, which would append a detector_unavailable
    # finding and make every response claim an incomplete scan forever. What
    # was skipped is named in `checks_skipped_by_profile` on the way out.
    if detection_profile.is_enabled("output_safety"):
        findings.extend(_scan_output_safety(text))

    # Toxicity
    if detection_profile.is_enabled("toxicity"):
        findings.extend(_scan_toxicity(text))

    # Intermediate risk score (before Ollama second pass)
    pre_score = _risk_score(findings)

    # Optional Ollama LLM judge (high-risk second pass)
    findings.extend(_scan_ollama_judge(text, pre_score))

    score = _risk_score(findings)
    action = "allow"
    reason = ""
    if score >= RISK_BLOCK_THRESHOLD:
        action = "block"
        reason = "high_risk_content_detected"
    elif score >= RISK_WARN_THRESHOLD:
        action = "warn"
        reason = "medium_risk_content_detected"

    unavailable = _detectors_unavailable(findings)
    result = {
        "action": action,
        "reason": reason,
        "risk_score": score,
        "detections": findings,
        "tenant_id": payload.tenant_id,
        "direction": payload.direction,
        # Additive fields: a risk_score of 0.0 from a scan whose detectors all
        # ran and a 0.0 from a scan where one never loaded are not the same
        # claim, and the caller records this response as evidence.
        "scan_complete": not unavailable,
        "detectors_unavailable": unavailable,
    }
    # put() refuses incomplete scans on its own; the guard is restated here
    # because the rule matters more than the layering -- a degraded verdict
    # pinned in front of a recovered model outlives the fault that caused it.
    if cache_key is not None and not unavailable:
        SCAN_CACHE.put(cache_key, result)
    return _with_profile_markers(result, cached=False)


@app.post("/scan/prompt-injection", dependencies=_SCAN_DEPS)
@_sheds_when_saturated
def scan_prompt(
    payload: TextRequest,
    x_api_key: Optional[str] = Header(default=None, alias="x-api-key"),
):
    _verify_api_key(x_api_key)
    _require_detector("prompt_injection")
    key, hit = _cached_scan("prompt-injection", payload.text)
    if hit is not None:
        return _with_profile_markers(hit, cached=True)
    findings = _scan_prompt_injection(payload.text)
    result = {"risk_score": _risk_score(findings), "detections": findings}
    SCAN_CACHE.put(key, result)
    return _with_profile_markers(result, cached=False)


# Deliberately NOT cached. The tracker is stateful across requests by design:
# the same text yields a chain finding on the fifth observation and none on the
# first, so a memoised verdict here would be wrong rather than stale.
@app.post("/scan/promptware", dependencies=_SCAN_DEPS)
@_sheds_when_saturated
def scan_promptware(
    payload: TextRequest,
    x_api_key: Optional[str] = Header(default=None, alias="x-api-key"),
):
    _verify_api_key(x_api_key)
    findings = _scan_prompt_injection(payload.text)
    session_key = _derive_session_key("default", "request", None, payload.session_id)
    chain_finding = None
    if _PROMPTWARE_SESSION_ENABLED:
        ml_conf = max(
            (
                float(f.get("confidence", 0.0))
                for f in findings
                if f.get("type") == "prompt_injection"
                and f.get("detector") == "ml_classifier"
            ),
            default=0.0,
        )
        chain_finding = _PROMPTWARE_TRACKER.observe(
            session_key=session_key, text=payload.text, pi_confidence=ml_conf
        )
        if chain_finding is not None:
            findings.append(chain_finding)
    return {
        "risk_score": _risk_score(findings),
        "detections": findings,
        "session_state": _PROMPTWARE_TRACKER.snapshot(session_key),
        "session_tracking_enabled": _PROMPTWARE_SESSION_ENABLED,
        "chain_detection": chain_finding,
    }


@app.post("/scan/sensitive-data", dependencies=_SCAN_DEPS)
@_sheds_when_saturated
def scan_sensitive(
    payload: TextRequest,
    x_api_key: Optional[str] = Header(default=None, alias="x-api-key"),
):
    _verify_api_key(x_api_key)
    _require_detector("sensitive_data")
    key, hit = _cached_scan("sensitive-data", payload.text)
    if hit is not None:
        return _with_profile_markers(hit, cached=True)
    findings = _scan_sensitive_data(payload.text)
    unavailable = _detectors_unavailable(findings)
    result = {
        "risk_score": _risk_score(findings),
        "detections": findings,
        # Same additive contract as /scan, /scan/toxicity and /scan/all: a
        # DLP scan whose NER model never ran is not a DLP scan that found no
        # PII, and the caller records this response as evidence.
        "scan_complete": not unavailable,
        "detectors_unavailable": unavailable,
    }
    if not unavailable:
        SCAN_CACHE.put(key, result)
    return _with_profile_markers(result, cached=False)


# ---- Path B (Step 2): client-facing redaction --------------------------

@app.get("/scan/redact/targets")
def list_redact_targets(
    x_api_key: Optional[str] = Header(default=None, alias="x-api-key"),
):
    """Return the catalog of redaction class names the policy builder can
    use in `redact_classes`. Stable identifiers, ordered alphabetically."""
    _verify_api_key(x_api_key)
    return {"targets": REDACT_CLASS_CATALOG}


# Shed + rate limit, but deliberately NOT cached. This endpoint's output is not
# an opinion about the text, it IS the text (see the fail-closed rationale in
# the docstring), and holding user plaintext in a process-wide cache is a
# retention decision this service should not make on its own. It is also the
# heaviest path here -- up to 24 NER windows x 2 models -- so it is exactly the
# endpoint that most needed the bounded-concurrency slot it never had.
@app.post("/scan/redact", dependencies=_SCAN_DEPS)
@_sheds_when_saturated
def scan_redact(
    payload: RedactRequest,
    x_api_key: Optional[str] = Header(default=None, alias="x-api-key"),
):
    """Redact requested DLP classes from `text`. FAILS CLOSED.

    Success response:
      {
        "redacted_text": "...with [REDACTED:pii.email] substitutions...",
        "class_counts":  {"pii.email": 2, "pii.ssn": 1},
        "any_redacted":  true,
        "redaction_complete": true
      }

    Incomplete response — note there is NO `redacted_text` key:
      {
        "redaction_complete": false,
        "any_redacted": true,
        "class_counts": {"pii.email": 2},
        "unredacted_classes": ["pii.person_name"],
        "reason": "model_not_loaded" | "inference_error" | "redact_spans_error",
        "error": "...", "model": "dslim/bert-base-NER", "detector": "ner_pii_model"
      }

    The response NEVER contains the original matched values. Callers should
    log only `class_counts` (and optionally a content HMAC — see the
    redact-telemetry path for that).

    ---- Why this path fails closed, unlike every detector above it ----

    Everywhere else in this service a broken model degrades to a visible gap:
    the response carries a `detector_unavailable` finding, `scan_complete`
    goes false, and traffic keeps flowing. That is right for detection — a
    missed detection is a missed alert, and blocking all traffic because a
    classifier died would be a self-inflicted outage.

    Redaction is not detection. This endpoint's output is not an opinion about
    the text, it IS the text: services/proxy/transparent_proxy.py and
    agents/endpoint-agent/local_proxy/transparent_proxy.py take
    `redacted_text`, call `flow.request.set_content(...)` with it, and forward
    it to OpenAI/Anthropic. It crosses the tenant boundary. A partially
    redacted body is not reduced coverage; it is a disclosure that already
    happened, to a third party, in a form the caller was told was masked — and
    for an SEC/FINRA-regulated buyer that is the failure the product exists to
    prevent. So: if this service cannot mask everything the policy asked for,
    it does not hand back text at all.

    Two mechanics matter, and both are deliberate:

      * The failure is reported with HTTP 200, not 5xx. Both proxies treat a
        non-200 from this endpoint as "no redaction result" and forward the
        ORIGINAL body — a 503 here would fail *open*, and leak more than the
        bug being fixed. A 200 whose `redacted_text` is absent makes the
        proxies' `redact_result["redacted_text"]` raise, which lands in their
        existing fail-closed handler and blocks the request.
      * `any_redacted` is true on the incomplete path. Its meaning is "the
        original text is not safe to forward as-is", which is exactly true
        here. A caller reading only that field still refuses to send the raw
        body.

    Scope of the closed door: only classes NER alone can produce
    (pii.person_name, pii.location, pii.organization, pii.ip_address,
    pii.url, pii.crypto_address). A policy redacting only regex-backed
    classes — SSN, credit card, email, API keys — is unaffected by a missing
    NER model and still returns 200 with text.
    """
    _verify_api_key(x_api_key)
    if not payload.targets:
        return {
            "redacted_text": payload.text,
            "class_counts": {},
            "any_redacted": False,
            "redaction_complete": True,
        }
    redacted, counts, status = _redact_text(payload.text, payload.targets)

    if not status.get("complete"):
        logger.error(
            "redact_incomplete_failing_closed tenant=%s reason=%s "
            "unredacted_classes=%s masked_class_counts=%s err=%s",
            payload.tenant_id,
            status.get("reason"),
            status.get("unredacted_classes"),
            counts,
            status.get("error"),
        )
        return {
            "redaction_complete": False,
            # "the original text is not safe to forward as-is"
            "any_redacted": True,
            # What DID get masked, for telemetry. Counts only, never values.
            "class_counts": counts,
            "unredacted_classes": status.get("unredacted_classes", []),
            "reason": status.get("reason"),
            "error": status.get("error"),
            "model": status.get("model"),
            "detector": "ner_pii_model",
        }

    return {
        "redacted_text": redacted,
        "class_counts": counts,
        "any_redacted": bool(counts),
        "redaction_complete": True,
    }


@app.post("/scan/output-safety", dependencies=_SCAN_DEPS)
@_sheds_when_saturated
def scan_output(
    payload: TextRequest,
    x_api_key: Optional[str] = Header(default=None, alias="x-api-key"),
):
    _verify_api_key(x_api_key)
    # 501 under a profile without the zero-shot model. Answering 200 with an
    # empty findings list would be this service reporting "clean" for a check
    # it never ran -- the one failure mode every other path here is built to
    # refuse.
    _require_detector("output_safety")
    key, hit = _cached_scan("output-safety", payload.text)
    if hit is not None:
        return _with_profile_markers(hit, cached=True)
    findings = _scan_output_safety(payload.text)
    unavailable = _detectors_unavailable(findings)
    result = {
        "risk_score": _risk_score(findings),
        "detections": findings,
        "scan_complete": not unavailable,
        "detectors_unavailable": unavailable,
    }
    if not unavailable:
        SCAN_CACHE.put(key, result)
    return _with_profile_markers(result, cached=False)


@app.post("/scan/toxicity", dependencies=_SCAN_DEPS)
@_sheds_when_saturated
def scan_toxicity(
    payload: TextRequest,
    x_api_key: Optional[str] = Header(default=None, alias="x-api-key"),
):
    _verify_api_key(x_api_key)
    _require_detector("toxicity")
    key, hit = _cached_scan("toxicity", payload.text)
    if hit is not None:
        return _with_profile_markers(hit, cached=True)
    findings = _scan_toxicity(payload.text)
    unavailable = _detectors_unavailable(findings)
    result = {
        "risk_score": _risk_score(findings),
        "detections": findings,
        "scan_complete": not unavailable,
        "detectors_unavailable": unavailable,
    }
    if not unavailable:
        SCAN_CACHE.put(key, result)
    return _with_profile_markers(result, cached=False)


@app.post("/scan/all", dependencies=_SCAN_DEPS)
@_sheds_when_saturated
def scan_all(
    payload: TextRequest,
    x_api_key: Optional[str] = Header(default=None, alias="x-api-key"),
):
    _verify_api_key(x_api_key)
    key, hit = _cached_scan("all", payload.text)
    if hit is not None:
        return _with_profile_markers(hit, cached=True)

    findings: List[Dict[str, Any]] = []
    # Each detector runs only if the profile enables it. A disabled detector
    # contributes nothing rather than contributing a detector_unavailable
    # finding; `checks_skipped_by_profile` on the response carries the fact.
    if detection_profile.is_enabled("prompt_injection"):
        findings.extend(_scan_prompt_injection(payload.text))
    if detection_profile.is_enabled("sensitive_data"):
        findings.extend(_scan_sensitive_data(payload.text))
    if detection_profile.is_enabled("output_safety"):
        findings.extend(_scan_output_safety(payload.text))
    if detection_profile.is_enabled("toxicity"):
        findings.extend(_scan_toxicity(payload.text))
    pre_score = _risk_score(findings)
    findings.extend(_scan_ollama_judge(payload.text, pre_score))
    unavailable = _detectors_unavailable(findings)
    result = {
        "risk_score": _risk_score(findings),
        "detections": findings,
        "scan_complete": not unavailable,
        "detectors_unavailable": unavailable,
    }
    if not unavailable:
        SCAN_CACHE.put(key, result)
    return _with_profile_markers(result, cached=False)
