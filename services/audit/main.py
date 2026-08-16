"""CyberArmor Audit & Action Graph Service.

Append-only audit log with HMAC-SHA256-signed events and AI action graph.
Port: 8011

NOT PQC-SIGNED. This line previously read "Immutable audit log with PQC-signed
events". Nothing in this service has ever used a post-quantum signature, or any
asymmetric signature: see _sign_event. ML-DSA-87 does exist in this product
(libs/cyberarmor-core/cyberarmor_core/crypto/pqc_sign.py) but its callers are
the endpoint agent's update and corpus manifests, not the audit trail.
Corrected 2026-08-12.
"""

import hashlib
import json
import logging
import os
import random
import time
from datetime import datetime, timezone, timedelta
from typing import Any, Dict, List, NamedTuple, Optional
from uuid import uuid4

from fastapi import Depends, FastAPI, Header, HTTPException, Query
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import PlainTextResponse
from pydantic import BaseModel, Field
from sqlalchemy import (
    Column, String, Integer, Float, DateTime, Text, JSON, Index,
    UniqueConstraint, create_engine, inspect, text,
)
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import Session, sessionmaker
from cyberarmor_core.crypto import get_public_key_info, verify_shared_secret

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s %(message)s")
logger = logging.getLogger("audit_service")

AUDIT_API_SECRET = os.getenv("AUDIT_API_SECRET", "change-me-audit")
DATABASE_URL = os.getenv("DATABASE_URL", "postgresql://cyberarmor:cyberarmor@postgres:5432/cyberarmor")
REDIS_URL = os.getenv("REDIS_URL", "redis://redis:6379")
AUDIT_SIGNING_KEY = os.getenv("CYBERARMOR_AUDIT_SIGNING_KEY", AUDIT_API_SECRET)
AUDIT_SIGNING_KEY_ID = os.getenv("CYBERARMOR_AUDIT_SIGNING_KEY_ID", "k1")
AUDIT_NEXT_SIGNING_KEY = os.getenv("CYBERARMOR_AUDIT_NEXT_SIGNING_KEY")
AUDIT_NEXT_SIGNING_KEY_ID = os.getenv("CYBERARMOR_AUDIT_NEXT_SIGNING_KEY_ID", "k2")

#: Keys this service has ROTATED AWAY FROM. Verify-only, never used to sign.
#:
#: WHY THIS EXISTS. Before 2026-08-12 there was no such slot. Rotation promoted
#: NEXT to ACTIVE, minted a new NEXT, and DROPPED THE OUTGOING KEY -- while
#: _verify_signature_result skips any candidate whose kid does not match. So
#: every rotation permanently orphaned every record signed before it, and the
#: failure would have presented as mass tampering: valid=false, reason
#: SIGNATURE_MISMATCH, across the whole trail, with no way to tell it from the
#: real thing. An audit log you must never rotate the key of is not one you can
#: operate for the 365 days AUDIT_RETENTION_DAYS defaults to.
#:
#: A LIST, not a single PREVIOUS slot. One slot survives exactly one rotation
#: and then starts orphaning again -- it moves the cliff rather than removing
#: it. Retention is a year by default, so several keys must stay verifiable at
#: once.
#:
#: Format: "kid:key,kid:key". Safe because keys are minted with
#: secrets.token_urlsafe (scripts/security/rotate_audit_signing_key.py), whose
#: alphabet is [A-Za-z0-9_-] -- no colons, no commas. Pinned by a test, because
#: the day that stops being true this parser starts silently truncating keys.
AUDIT_RETIRED_KEYS_RAW = os.getenv("CYBERARMOR_AUDIT_RETIRED_KEYS", "")


def _parse_retired_keys(raw: str) -> tuple[List[tuple[str, str]], List[str]]:
    """Returns (usable keys, problems). Problems are NEVER swallowed.

    A malformed entry means some set of historical records silently stops
    verifying. That is precisely the failure this whole slot exists to prevent,
    so a bad entry is reported at ERROR on startup and surfaced on
    /integrity/signing-key/status rather than dropped.
    """
    keys: List[tuple[str, str]] = []
    problems: List[str] = []
    seen: set = set()
    for index, entry in enumerate(raw.split(",")):
        entry = entry.strip()
        if not entry:
            continue
        if ":" not in entry:
            problems.append(
                f"entry {index}: no ':' separator, expected 'kid:key' -- records "
                f"signed with this key cannot be verified"
            )
            continue
        kid, key = entry.split(":", 1)
        kid, key = kid.strip(), key.strip()
        if not kid or not key:
            problems.append(f"entry {index}: empty kid or key")
            continue
        if kid in seen:
            problems.append(
                f"entry {index}: duplicate kid {kid!r} -- the later value is "
                f"unreachable, so records signed with it will not verify"
            )
            continue
        seen.add(kid)
        keys.append((kid, key))
    return keys, problems


AUDIT_RETIRED_KEYS, AUDIT_RETIRED_KEY_PROBLEMS = _parse_retired_keys(AUDIT_RETIRED_KEYS_RAW)

for _problem in AUDIT_RETIRED_KEY_PROBLEMS:
    # ERROR, at import, once per problem. A retired key that fails to parse is
    # indistinguishable at verify time from a forged record, so this may not be
    # a DEBUG line nobody reads -- that is how this repo's tracked defects
    # survive. Also surfaced on /integrity/signing-key/status.
    logger.error("audit_retired_key_unusable %s", _problem)
AUDIT_RETENTION_DAYS = int(os.getenv("AUDIT_RETENTION_DAYS", "365"))
AUDIT_MIN_RETENTION_DAYS = int(os.getenv("AUDIT_MIN_RETENTION_DAYS", "90"))
ENFORCE_IMMUTABLE_RETENTION = os.getenv("CYBERARMOR_ENFORCE_IMMUTABLE_RETENTION", "false").strip().lower() in {"1", "true", "yes", "on"}
ENFORCE_SECURE_SECRETS = os.getenv("CYBERARMOR_ENFORCE_SECURE_SECRETS", "false").strip().lower() in {"1", "true", "yes", "on"}
ALLOW_INSECURE_DEFAULTS = os.getenv("CYBERARMOR_ALLOW_INSECURE_DEFAULTS", "false").strip().lower() in {"1", "true", "yes", "on"}
ENFORCE_MTLS = os.getenv("CYBERARMOR_ENFORCE_MTLS", "false").strip().lower() in {"1", "true", "yes", "on"}
TLS_CA_FILE = os.getenv("CYBERARMOR_TLS_CA_FILE")
TLS_CERT_FILE = os.getenv("CYBERARMOR_TLS_CERT_FILE")
TLS_KEY_FILE = os.getenv("CYBERARMOR_TLS_KEY_FILE")


def _enforce_secure_secrets() -> None:
    if not ENFORCE_SECURE_SECRETS or ALLOW_INSECURE_DEFAULTS:
        return

    def _bad(value: Optional[str]) -> bool:
        if not value:
            return True
        lowered = value.strip().lower()
        return lowered.startswith("change-me") or "changeme" in lowered

    failing = []
    if _bad(AUDIT_API_SECRET):
        failing.append("AUDIT_API_SECRET")
    if _bad(AUDIT_SIGNING_KEY):
        failing.append("CYBERARMOR_AUDIT_SIGNING_KEY")
    if failing:
        raise RuntimeError(
            "Refusing startup with insecure defaults in strict secret mode. "
            f"Set strong values for: {', '.join(failing)}. "
            "For local dev only, set CYBERARMOR_ALLOW_INSECURE_DEFAULTS=true."
        )


_enforce_secure_secrets()


def _enforce_mtls_config() -> None:
    if not ENFORCE_MTLS:
        return
    missing = []
    for env_name, value in [
        ("CYBERARMOR_TLS_CA_FILE", TLS_CA_FILE),
        ("CYBERARMOR_TLS_CERT_FILE", TLS_CERT_FILE),
        ("CYBERARMOR_TLS_KEY_FILE", TLS_KEY_FILE),
    ]:
        if not value:
            missing.append(f"{env_name}(unset)")
        elif not os.path.exists(value):
            missing.append(f"{env_name}({value} missing)")
    if missing:
        raise RuntimeError(
            "Refusing startup: mTLS enforced but TLS artifacts are missing. "
            f"Fix: {', '.join(missing)}"
        )


_enforce_mtls_config()


def _enforce_immutability_retention_policy() -> None:
    if not ENFORCE_IMMUTABLE_RETENTION:
        return
    if AUDIT_RETENTION_DAYS < AUDIT_MIN_RETENTION_DAYS:
        raise RuntimeError(
            "Refusing startup: immutable retention enforcement requires "
            f"AUDIT_RETENTION_DAYS >= AUDIT_MIN_RETENTION_DAYS ({AUDIT_MIN_RETENTION_DAYS})."
        )


_enforce_immutability_retention_policy()

# ── DB ────────────────────────────────────────────────────────────────────────

engine = create_engine(DATABASE_URL, pool_pre_ping=True)
SessionLocal = sessionmaker(bind=engine)
Base = declarative_base()


class AuditEventModel(Base):
    __tablename__ = "audit_events"
    event_id = Column(String(64), primary_key=True)
    trace_id = Column(String(64), nullable=False, index=True)
    span_id = Column(String(48), nullable=False)
    parent_span_id = Column(String(48), nullable=True)
    tenant_id = Column(String(64), nullable=False, index=True)
    agent_id = Column(String(64), nullable=False, index=True)
    agent_token_id = Column(String(64), nullable=True)
    human_initiator_id = Column(String(255), nullable=True)
    delegation_chain = Column(JSON, default=list)
    event_type = Column(String(64), nullable=False, index=True)
    provider = Column(String(64), nullable=True)
    model = Column(String(255), nullable=True)
    framework = Column(String(64), nullable=True)
    action = Column(JSON, nullable=True)
    policy_decision = Column(JSON, nullable=True)
    data_classification = Column(JSON, default=list)
    #: Producer-specific evidence, signed along with everything else.
    #:
    #: ADDED 2026-08-12 because AuditEvent silently DROPS unknown fields
    #: (pydantic's default extra='ignore'). url-trust-gate had been POSTing
    #: {"kind": ..., "data": {...}} and getting 422 on the missing required
    #: fields; adding only those fields would have turned the 422 into a 201
    #: that discarded the URL, scores, IOCs, decision and redirect chain --
    #: a loud failure replaced by a silent one. Evidence with nowhere to live
    #: is evidence that does not exist.
    detail = Column(JSON, default=dict)
    outcome = Column(String(32), nullable=False, default="success", index=True)
    latency_ms = Column(Integer, default=0)
    cost_usd = Column(Float, default=0.0)
    timestamp = Column(DateTime(timezone=True), nullable=False, index=True)
    signature = Column(Text, nullable=True)
    prev_event_id = Column(String(64), nullable=True)
    prev_signature = Column(Text, nullable=True)
    chain_hash = Column(Text, nullable=True)

    __table_args__ = (
        Index("ix_audit_tenant_agent", "tenant_id", "agent_id"),
        Index("ix_audit_tenant_time", "tenant_id", "timestamp"),
        # THE CHAIN CANNOT FORK. Added 2026-08-12.
        #
        # ingest_event reads _latest_tenant_event and then inserts, with no
        # lock between them. Two concurrent appends for one tenant therefore
        # both read the same predecessor and both link to it -- and each
        # branch VERIFIES PERFECTLY, because every signature is intact and
        # every prev_signature matches a real record. A fork is invisible to
        # /integrity/verify. Silently losing one of two concurrent records is
        # exactly the failure an audit trail exists to make impossible.
        #
        # docs/specs/pilot-capacity-model.md:349 already described these two
        # constraints by name, and derived a 100-150 appends/s planning ceiling
        # from them. A repo-wide grep for uq_audit_chain returned that one
        # sentence and nothing else: the control was documented, costed, and
        # never built. The capacity number was derived from a constraint that
        # did not exist.
        #
        # Two constraints, because there are two ways to fork:
        #   uq_audit_chain_link    two records claiming the same predecessor
        #   uq_audit_chain_genesis two records claiming to be first
        # Postgres treats NULLs as distinct in a UNIQUE index, so the genesis
        # case needs its own partial index -- without it, unlimited records
        # could each claim prev_event_id IS NULL and be the tenant's first.
        UniqueConstraint("tenant_id", "prev_event_id", name="uq_audit_chain_link"),
        Index(
            "uq_audit_chain_genesis", "tenant_id",
            unique=True,
            postgresql_where=text("prev_event_id IS NULL"),
            sqlite_where=text("prev_event_id IS NULL"),
        ),
    )


# ── Helpers ───────────────────────────────────────────────────────────────────

def _wait_for_db(max_wait_s: int = 45):
    start = time.time()
    attempt = 0
    while True:
        attempt += 1
        try:
            with engine.connect() as conn:
                conn.exec_driver_sql("SELECT 1")
            return
        except Exception as e:
            elapsed = time.time() - start
            if elapsed >= max_wait_s:
                raise
            sleep_s = min(0.25 * (1.4 ** (attempt - 1)), 2.0)
            logger.warning("DB not ready, retry %.2fs: %s", sleep_s, e)
            time.sleep(sleep_s)


def _ensure_chain_columns() -> None:
    """Migrate older audit schema to include chain fields if missing."""
    try:
        inspector = inspect(engine)
        if not inspector.has_table("audit_events"):
            return
        existing = {col["name"] for col in inspector.get_columns("audit_events")}
        needed = {
            "prev_event_id": "VARCHAR(64)",
            "prev_signature": "TEXT",
            "chain_hash": "TEXT",
            # JSON is portable across the Postgres deployment and the SQLite
            # used by tests; SQLAlchemy's JSON type reads either.
            "detail": "JSON",
        }
        for name, ddl in needed.items():
            if name in existing:
                continue
            with engine.begin() as conn:
                # Safe here: both column names and DDL fragments come from the fixed `needed` map above.
                conn.exec_driver_sql(f"ALTER TABLE audit_events ADD COLUMN {name} {ddl}")
            logger.info("Added missing audit_events column via runtime migration: %s", name)
    except Exception as exc:
        logger.warning("Failed to apply audit chain migration: %s", exc)


#: Whether the database refuses UPDATE and DELETE on audit_events to the role
#: this service authenticates as. None means "could not be determined" -- which
#: is reported as null, never as True.
APPEND_ONLY_ENFORCED: Optional[bool] = None


def _detect_append_only_enforcement() -> Optional[bool]:
    """Ask the database, rather than asserting.

    A claim of append-only storage is only worth what the database will
    actually refuse. This asks Postgres directly whether the CURRENT role holds
    UPDATE or DELETE on audit_events; append-only means it holds neither.

    Returns None on any database that cannot answer (SQLite in tests has no
    has_table_privilege), because an unknown must never be reported as a
    guarantee. That is the whole reason this function exists: the value it
    replaces was a hardcoded True.
    """
    try:
        with engine.connect() as conn:
            mutable = conn.execute(text(
                "SELECT has_table_privilege(current_user, 'audit_events', 'UPDATE')"
                " OR has_table_privilege(current_user, 'audit_events', 'DELETE')"
            )).scalar()
        return not bool(mutable)
    except Exception as exc:
        logger.info(
            "append_only_enforcement_undetermined err=%s -- reporting null, "
            "not true", exc.__class__.__name__,
        )
        return None


def _latest_tenant_event(db: Session, tenant_id: str) -> Optional[AuditEventModel]:
    return (
        db.query(AuditEventModel)
        .filter(AuditEventModel.tenant_id == tenant_id)
        .order_by(AuditEventModel.timestamp.desc(), AuditEventModel.event_id.desc())
        .first()
    )


def _get_batch_previous_for_tenant(
    db: Session,
    previous_by_tenant: Dict[str, Optional[AuditEventModel]],
    tenant_id: str,
) -> Optional[AuditEventModel]:
    if tenant_id not in previous_by_tenant:
        previous_by_tenant[tenant_id] = _latest_tenant_event(db, tenant_id)
    return previous_by_tenant[tenant_id]


def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


def verify_api_key(api_key: str | None = Header(default=None, alias="x-api-key")):
    verify_shared_secret(api_key, AUDIT_API_SECRET, service_name="audit")


#: Attempts before an append gives up and fails closed. Named in
#: docs/specs/pilot-capacity-model.md:349, which derived a 100-150 appends/s
#: per-tenant planning ceiling from a constraint that did not exist until
#: 2026-08-12. The ceiling is real now; the spec's arithmetic finally describes
#: the system.
_CHAIN_MAX_ATTEMPTS = int(os.getenv("CYBERARMOR_AUDIT_CHAIN_MAX_ATTEMPTS", "8"))
_CHAIN_BACKOFF_BASE_S = 0.01
_CHAIN_BACKOFF_CAP_S = 0.4


def _chain_backoff_seconds(attempt: int) -> float:
    """Exponential backoff with full jitter.

    Jitter is not decoration here: without it, two writers that collide will
    sleep for identical durations and collide again on every retry, which is a
    livelock that looks exactly like contention.
    """
    ceiling = min(_CHAIN_BACKOFF_CAP_S, _CHAIN_BACKOFF_BASE_S * (2 ** (attempt - 1)))
    return random.uniform(0.0, ceiling)


def _compute_chain_hash(signature: str, previous_signature: str | None) -> str:
    base = f"{previous_signature or ''}|{signature}".encode()
    return hashlib.sha256(base).hexdigest()


def _sign_event(event_dict: dict, prev_signature: str | None = None) -> str:
    """Sign event payload with HMAC-SHA256.

    HMAC ONLY. There is no Ed25519 branch and no PQC branch in this function,
    and there never has been -- the previous version of this docstring claimed
    "(Ed25519/PQC if keys available)" over a body that has only ever computed
    hmac.new(...). Corrected 2026-08-12.

    WHAT THIS DOES AND DOES NOT ESTABLISH. HMAC is symmetric, so a valid
    signature proves only that SOMEONE holding AUDIT_SIGNING_KEY produced this
    record. It is tamper-evidence against a party without the key; it is NOT
    non-repudiation. Worse, AUDIT_SIGNING_KEY defaults to AUDIT_API_SECRET
    (see the module constants), so on a default deployment every service that
    can WRITE an audit event holds the key that "proves" one authentic.
    Replacing this with hybrid Ed25519 + ML-DSA-87 is planned; until it lands,
    do not describe these records as signed in the non-repudiation sense.
    """
    def _json_default(value):
        if isinstance(value, datetime):
            return value.isoformat()
        return str(value)

    payload_dict = dict(event_dict)
    payload_dict.pop("signature", None)
    payload_dict.pop("chain_hash", None)
    if prev_signature is not None and "prev_signature" not in payload_dict:
        payload_dict["prev_signature"] = prev_signature
    payload = json.dumps(payload_dict, sort_keys=True, default=_json_default).encode()
    signing_key = AUDIT_SIGNING_KEY.encode()
    import hmac
    digest = hmac.new(signing_key, payload, hashlib.sha256).hexdigest()
    return f"{AUDIT_SIGNING_KEY_ID}:{digest}"


class SignatureVerification(NamedTuple):
    """Why a signature was accepted, not merely whether.

    A bare bool cannot distinguish "verified against the payload we write
    today" from "verified against the payload an older build wrote". Both are
    genuine, but only the first says the record was produced by current code,
    and a compliance report that blurs them is asserting more than it checked.
    """
    valid: bool
    reason: str
    #: Which key verified it. Matters most when that key is RETIRED: rotation
    #: is often a response to suspected compromise, and a record signed with a
    #: compromised key is authentic-looking without being trustworthy. An
    #: investigator needs the kid to decide, so it travels with the verdict.
    key_id: Optional[str] = None


_SIG_MATCH = "SIGNATURE_MATCH"
_SIG_MISMATCH = "SIGNATURE_MISMATCH"

#: Raw-hex signature with no key-id prefix, written before key ids existed.
_SIG_MATCH_LEGACY_UNPREFIXED = "SIGNATURE_MATCH_LEGACY_UNPREFIXED"

#: Verified against a key this service has ROTATED AWAY FROM. The record is
#: genuine, but rotation is frequently a response to suspected compromise, and a
#: record signed with a compromised key is authentic-looking without being
#: trustworthy. Reported distinctly so an investigator can ask WHY that key was
#: retired rather than reading a bare "valid".
_SIG_MATCH_RETIRED_KEY = "SIGNATURE_MATCH_RETIRED_KEY"

#: A genesis row written before 2026-08-12, when the genesis branch of
#: ingest_event set prev_event_id/prev_signature WITHOUT re-signing. Its
#: signature legitimately covers 20 fields rather than 22. Verifying it means
#: reconstructing the message that signer actually produced -- NOT re-signing
#: the record, which would fabricate evidence. Reported distinctly so nobody
#: can mistake an old record for one written by current code.
_SIG_MATCH_LEGACY_GENESIS = "SIGNATURE_MATCH_LEGACY_GENESIS"


def _canonical_payload_bytes(payload_dict: dict) -> bytes:
    """Byte-identical to the serialization in :func:`_sign_event`.

    DO NOT REFORMAT. No ``separators=``, no ``ensure_ascii=``. Every signature
    in production was computed over ``json.dumps`` defaults, which put a space
    after each ``,`` and ``:``. Adding compact separators here would silently
    invalidate the entire audit history.
    """
    return json.dumps(
        payload_dict,
        sort_keys=True,
        default=lambda value: value.isoformat() if isinstance(value, datetime) else str(value),
    ).encode()


def _verify_signature_result(event_dict: dict, signature: str) -> SignatureVerification:
    prev_signature = event_dict.get("prev_signature") if isinstance(event_dict, dict) else None
    import hmac

    # Backward-compat: legacy signatures were raw hex (no key id prefix).
    if ":" not in signature:
        expected_legacy = hmac.new(
            AUDIT_SIGNING_KEY.encode(),
            _canonical_payload_bytes({
                **{k: v for k, v in event_dict.items() if k not in {"signature", "chain_hash"}},
                **({"prev_signature": prev_signature} if prev_signature and "prev_signature" not in event_dict else {}),
            }),
            hashlib.sha256,
        ).hexdigest()
        if hmac.compare_digest(expected_legacy, signature):
            return SignatureVerification(
                True, _SIG_MATCH_LEGACY_UNPREFIXED, AUDIT_SIGNING_KEY_ID)
        return SignatureVerification(False, _SIG_MISMATCH)

    kid, digest = signature.split(":", 1)

    # Reconstruct canonical payload exactly like _sign_event.
    payload_dict = dict(event_dict)
    payload_dict.pop("signature", None)
    payload_dict.pop("chain_hash", None)
    if prev_signature is not None and "prev_signature" not in payload_dict:
        payload_dict["prev_signature"] = prev_signature

    #: (payload, reason-if-it-matches), most-current shape FIRST so a record
    #: written today can never be reported as legacy.
    candidate_payloads: List[tuple[bytes, str]] = [
        (_canonical_payload_bytes(payload_dict), _SIG_MATCH),
    ]

    # The pre-2026-08-12 genesis shape: signed before prev_event_id and
    # prev_signature were attached, so those two keys were absent entirely.
    # Attempted ONLY on a row that really is a genesis row -- both pointers
    # null -- so this can never be used to launder a chained record whose
    # pointers were stripped by an attacker.
    if payload_dict.get("prev_event_id") is None and payload_dict.get("prev_signature") is None:
        legacy_genesis = {
            k: v for k, v in payload_dict.items()
            if k not in ("prev_event_id", "prev_signature")
        }
        if len(legacy_genesis) != len(payload_dict):
            candidate_payloads.append(
                (_canonical_payload_bytes(legacy_genesis), _SIG_MATCH_LEGACY_GENESIS)
            )

    #: (kid, secret, is_retired). Retired keys are VERIFY-ONLY: nothing here is
    #: ever used to sign. _sign_event reads AUDIT_SIGNING_KEY and only that, so
    #: a retired key can never come back into service by being listed here.
    candidate_keys: List[tuple[str, str, bool]] = [
        (AUDIT_SIGNING_KEY_ID, AUDIT_SIGNING_KEY, False),
    ]
    if AUDIT_NEXT_SIGNING_KEY:
        candidate_keys.append((AUDIT_NEXT_SIGNING_KEY_ID, AUDIT_NEXT_SIGNING_KEY, False))
    candidate_keys.extend((kid_, secret_, True) for kid_, secret_ in AUDIT_RETIRED_KEYS)

    for payload, reason in candidate_payloads:
        for candidate_kid, candidate_secret, retired in candidate_keys:
            # kid still gates the comparison, so listing more keys does not
            # widen what a forged signature can match: an attacker must still
            # produce a valid HMAC under the exact key the record names.
            if kid != candidate_kid:
                continue
            expected = hmac.new(candidate_secret.encode(), payload, hashlib.sha256).hexdigest()
            if hmac.compare_digest(expected, digest):
                # The retired fact OUTRANKS the payload-shape fact. Both are
                # true, but "signed with a key we rotated away from" is the one
                # that decides whether to trust the record; the payload shape
                # only says which build wrote it. key_id carries the detail.
                return SignatureVerification(
                    True,
                    _SIG_MATCH_RETIRED_KEY if retired else reason,
                    candidate_kid,
                )
    return SignatureVerification(False, _SIG_MISMATCH, kid)


def _verify_signature(event_dict: dict, signature: str) -> bool:
    """Bool-only wrapper. Prefer :func:`_verify_signature_result`, which says
    WHICH payload shape matched -- a caller that only sees True cannot tell a
    record written today from one written by a build with a known defect."""
    return _verify_signature_result(event_dict, signature).valid


# ── Pydantic Models ───────────────────────────────────────────────────────────

class ActionRecord(BaseModel):
    type: str = "llm_call"
    prompt_hash: Optional[str] = None
    prompt_tokens: int = 0
    completion_tokens: int = 0
    tool_name: Optional[str] = None
    tool_input_hash: Optional[str] = None
    target_system: Optional[str] = None


class PolicyDecisionRecord(BaseModel):
    decision: str
    policy_id: Optional[str] = None
    reason_code: str = ""
    risk_score: float = 0.0
    latency_ms: int = 0
    redaction_targets: List[str] = []


class AuditEvent(BaseModel):
    event_id: str = Field(default_factory=lambda: "evt_" + str(uuid4()).replace("-", "")[:20])
    trace_id: str
    span_id: str = Field(default_factory=lambda: "spn_" + str(uuid4()).replace("-", "")[:16])
    parent_span_id: Optional[str] = None
    tenant_id: str = "default"
    agent_id: str
    agent_token_id: Optional[str] = None
    human_initiator_id: Optional[str] = None
    delegation_chain: List[str] = []
    event_type: str
    provider: Optional[str] = None
    model: Optional[str] = None
    framework: Optional[str] = None
    action: Optional[ActionRecord] = None
    policy_decision: Optional[PolicyDecisionRecord] = None
    data_classification: List[str] = []
    outcome: str = "success"
    latency_ms: int = 0
    cost_usd: float = 0.0
    timestamp: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    #: Producer-specific evidence. Declared, so it is NOT dropped by pydantic's
    #: default extra='ignore', and so it is covered by the signature -- an audit
    #: record whose evidence is unsigned is not evidence.
    #:
    #: THIS CHANGES THE SIGNED PAYLOAD SHAPE. Records written before this field
    #: existed signed one fewer key and will report SIGNATURE_MISMATCH. That was
    #: acceptable exactly once: when this shipped, production held two
    #: deliberate test rows and nothing else, so no real evidence was orphaned.
    #: A third payload era for two throwaway rows was not worth the complexity
    #: that _SIG_MATCH_LEGACY_GENESIS already demonstrates. IF YOU ADD ANOTHER
    #: SIGNED FIELD LATER, that calculus is different -- by then the trail will
    #: hold real records, and you will need a versioned canonical payload
    #: instead of a fourth special case.
    detail: Dict[str, Any] = {}
    signature: Optional[str] = None


class BatchIngestRequest(BaseModel):
    events: List[AuditEvent]


class EventQuery(BaseModel):
    agent_id: Optional[str] = None
    tenant_id: Optional[str] = None
    provider: Optional[str] = None
    event_type: Optional[str] = None
    outcome: Optional[str] = None
    since: Optional[datetime] = None
    until: Optional[datetime] = None
    limit: int = 100
    offset: int = 0


# ── App ───────────────────────────────────────────────────────────────────────

app = FastAPI(
    title="CyberArmor Audit & Action Graph Service",
    version="1.0.0",
    description="Immutable audit log with AI action graph for forensics and compliance",
)
app.add_middleware(CORSMiddleware, allow_origins=["*"], allow_methods=["*"], allow_headers=["*"])


@app.on_event("startup")
def on_startup():
    logger.info("Audit Service starting...")
    _wait_for_db()
    Base.metadata.create_all(bind=engine)
    _ensure_chain_columns()
    global APPEND_ONLY_ENFORCED
    APPEND_ONLY_ENFORCED = _detect_append_only_enforcement()
    if APPEND_ONLY_ENFORCED is False:
        # WARNING, every boot, on purpose. This service's whole value is that
        # its records can be trusted afterwards, and right now the role writing
        # them can also rewrite them.
        logger.warning(
            "append_only_NOT_enforced: this service's database role holds "
            "UPDATE and/or DELETE on audit_events, so stored records can be "
            "altered or removed by the same credential that writes them. "
            "POST /events reports append_only=false accordingly."
        )
    logger.info("Audit Service ready on port 8011")


# ── Event Ingestion ───────────────────────────────────────────────────────────

@app.post("/events", status_code=201)
def ingest_event(
    event: AuditEvent,
    db: Session = Depends(get_db),
    _: None = Depends(verify_api_key),
):
    """Ingest a single audit event.

    RETRIES ON CHAIN COLLISION. The predecessor is read and then inserted
    against with no lock in between, so two concurrent appends for one tenant
    both link to the same record. uq_audit_chain_link makes the second one fail
    instead of forking; this loop re-reads the new head, RE-SIGNS against it,
    and tries again. Re-signing is not optional -- prev_signature is inside the
    signed payload, so a retry that reused the old signature would store a
    record that cannot verify.
    """
    for attempt in range(1, _CHAIN_MAX_ATTEMPTS + 1):
        try:
            return _ingest_one(event, db)
        except IntegrityError:
            # Someone else won the race for this predecessor. Roll back, wait a
            # jittered moment so two racers do not resynchronise into a
            # livelock, and re-derive from the new head.
            db.rollback()
            if attempt == _CHAIN_MAX_ATTEMPTS:
                logger.error(
                    "audit_chain_contention_exhausted tenant=%s attempts=%s",
                    event.tenant_id, attempt,
                )
                # FAIL CLOSED. Returning success here would mean the caller
                # believes an event was recorded that was not -- the exact
                # shape of defect this service keeps being audited for.
                raise HTTPException(
                    status_code=503,
                    detail=(
                        "audit chain contention: could not append after "
                        f"{attempt} attempts. Nothing was stored; retry."
                    ),
                )
            time.sleep(_chain_backoff_seconds(attempt))
    raise AssertionError("unreachable")  # pragma: no cover


def _ingest_one(event: AuditEvent, db: Session) -> Dict:
    event_dict = event.model_dump()
    if not event.signature:
        event_dict["signature"] = _sign_event(event_dict)
        event.signature = event_dict["signature"]

    previous = _latest_tenant_event(db, event.tenant_id)
    prev_signature = previous.signature if previous else None
    if previous:
        event_dict["prev_event_id"] = previous.event_id
        event_dict["prev_signature"] = prev_signature
        event_dict["signature"] = _sign_event(event_dict, prev_signature=prev_signature)
        event.signature = event_dict["signature"]
    else:
        event_dict["prev_event_id"] = None
        event_dict["prev_signature"] = None
        # RE-SIGN, exactly as the chained branch above does.
        #
        # MEASURED 2026-08-12, before this line existed: the genesis row of
        # every tenant reported SIGNATURE_MISMATCH from /integrity/verify.
        # The first _sign_event call above runs on the bare model_dump(), which
        # AuditEvent defines without prev_event_id or prev_signature -- 20
        # fields. These two assignments then added two more WITHOUT re-signing,
        # while verification always reconstructs 22. 20 != 22, so the signature
        # could never match. Only the FIRST record of a tenant took this path,
        # which is why it survived: it is also the record an auditor is most
        # likely to spot-check, being the oldest.
        #
        # An audit trail that calls a genuine record tampered is worse than one
        # that cannot check at all -- it manufactures a finding against the
        # customer. Records written before this fix are still verifiable; see
        # _SIG_MATCH_LEGACY_GENESIS in _verify_signature_result.
        event_dict["signature"] = _sign_event(event_dict)
        event.signature = event_dict["signature"]

    event_dict["chain_hash"] = _compute_chain_hash(event_dict["signature"], prev_signature)
    event.signature = event_dict["signature"]

    model = AuditEventModel(
        event_id=event.event_id,
        trace_id=event.trace_id,
        span_id=event.span_id,
        parent_span_id=event.parent_span_id,
        tenant_id=event.tenant_id,
        agent_id=event.agent_id,
        agent_token_id=event.agent_token_id,
        human_initiator_id=event.human_initiator_id,
        delegation_chain=event.delegation_chain,
        event_type=event.event_type,
        provider=event.provider,
        model=event.model,
        framework=event.framework,
        action=event.action.model_dump() if event.action else None,
        policy_decision=event.policy_decision.model_dump() if event.policy_decision else None,
        data_classification=event.data_classification,
        detail=event.detail,
        outcome=event.outcome,
        latency_ms=event.latency_ms,
        cost_usd=event.cost_usd,
        timestamp=event.timestamp,
        signature=event.signature,
        prev_event_id=event_dict.get("prev_event_id"),
        prev_signature=event_dict.get("prev_signature"),
        chain_hash=event_dict.get("chain_hash"),
    )
    existing = db.query(AuditEventModel).filter(AuditEventModel.event_id == event.event_id).first()
    if existing:
        raise HTTPException(status_code=409, detail=f"Event '{event.event_id}' already exists (append-only)")
    db.add(model)
    db.commit()
    return {
        "event_id": event.event_id,
        "stored": True,
        # MEASURED, NOT ASSERTED. This was the literal `True`, published as a
        # schema field (docs/api/openapi.yaml, AuditEventIngestResponse), so
        # every integrator and every due-diligence questionnaire read "true"
        # from a service whose database role OWNS the table and can UPDATE or
        # DELETE any row in it. The value now comes from asking the database
        # what this role may actually do; see _detect_append_only_enforcement.
        #
        # Expect FALSE on the current hosted stack. That is the honest answer
        # until the writer role is demoted, and the field going false is the
        # point -- it was never true.
        "append_only": APPEND_ONLY_ENFORCED,
    }


@app.post("/events/batch", status_code=202)
def ingest_batch(
    body: BatchIngestRequest,
    db: Session = Depends(get_db),
    _: None = Depends(verify_api_key),
):
    """Batch ingest audit events.

    THREE DEFECTS FIXED HERE 2026-08-12, all of which the single-event path had
    already been corrected for. Fixing one endpoint and leaving its sibling
    carrying the identical bug is how this service accumulated them.

    1. GENESIS ROWS NEVER RE-SIGNED. The else: branch set prev_event_id and
       prev_signature and did not re-sign, so the first record of every tenant
       written through THIS endpoint signed 20-odd fields while verification
       reconstructs more, and reported SIGNATURE_MISMATCH forever. Identical to
       the ingest_event defect; see _SIG_MATCH_LEGACY_GENESIS.

    2. detail WAS DROPPED. The model was built without it, so evidence sent in
       a batch vanished while the endpoint reported it stored.

    3. ONE COLLISION POISONED THE WHOLE BATCH. Each event was wrapped in
       `except Exception: log`, then db.commit() ran at the end. After an
       IntegrityError -- now reachable, because uq_audit_chain_link exists --
       the session is in a failed state, so that final commit raises
       PendingRollbackError and EVERY event in the batch is lost while the
       handler has already logged each one as an individual warning. Each event
       now writes inside a SAVEPOINT, so a failure rolls back only itself.

    Failures are REPORTED, not just counted. A caller that receives
    {"stored": 3, "total": 5} learns two events are missing and nothing about
    which or why, which is indistinguishable from silent loss.
    """
    stored = 0
    failed: List[Dict[str, str]] = []
    ordered = sorted(body.events, key=lambda evt: (evt.tenant_id, evt.timestamp, evt.event_id))
    previous_by_tenant: Dict[str, Optional[AuditEventModel]] = {}

    for event in ordered:
        tenant_id = event.tenant_id
        last_error: Optional[str] = None

        for attempt in range(1, _CHAIN_MAX_ATTEMPTS + 1):
            previous = _get_batch_previous_for_tenant(db, previous_by_tenant, tenant_id)
            event_dict = event.model_dump()
            event_dict["signature"] = _sign_event(event_dict)

            if previous:
                event_dict["prev_event_id"] = previous.event_id
                event_dict["prev_signature"] = previous.signature
                event_dict["signature"] = _sign_event(
                    event_dict, prev_signature=previous.signature)
            else:
                event_dict["prev_event_id"] = None
                event_dict["prev_signature"] = None
                # RE-SIGN. Defect 1 above.
                event_dict["signature"] = _sign_event(event_dict)

            event.signature = event_dict["signature"]
            event_dict["chain_hash"] = _compute_chain_hash(
                event_dict["signature"], event_dict.get("prev_signature"))

            model = AuditEventModel(
                event_id=event.event_id,
                trace_id=event.trace_id,
                span_id=event.span_id,
                parent_span_id=event.parent_span_id,
                tenant_id=event.tenant_id,
                agent_id=event.agent_id,
                agent_token_id=event.agent_token_id,
                human_initiator_id=event.human_initiator_id,
                delegation_chain=event.delegation_chain,
                event_type=event.event_type,
                provider=event.provider,
                model=event.model,
                framework=event.framework,
                action=event.action.model_dump() if event.action else None,
                policy_decision=event.policy_decision.model_dump() if event.policy_decision else None,
                data_classification=event.data_classification,
                detail=event.detail,          # defect 2 above
                outcome=event.outcome,
                latency_ms=event.latency_ms,
                cost_usd=event.cost_usd,
                timestamp=event.timestamp,
                signature=event.signature,
                prev_event_id=event_dict.get("prev_event_id"),
                prev_signature=event_dict.get("prev_signature"),
                chain_hash=event_dict.get("chain_hash"),
            )

            existing = db.query(AuditEventModel).filter(
                AuditEventModel.event_id == event.event_id).first()
            if existing:
                last_error = "duplicate event_id (append-only)"
                logger.warning("Duplicate event rejected event_id=%s", event.event_id)
                break

            try:
                # SAVEPOINT per event. Defect 3 above: without this, one
                # IntegrityError leaves the session unusable and the batch's
                # final commit takes every other event down with it.
                with db.begin_nested():
                    db.add(model)
                    db.flush()
            except IntegrityError as exc:
                # The cached head for this tenant is stale — someone appended
                # between our read and our insert. Drop it so the next attempt
                # re-reads, and re-sign against the real head.
                previous_by_tenant.pop(tenant_id, None)
                last_error = f"chain contention: {exc.__class__.__name__}"
                if attempt < _CHAIN_MAX_ATTEMPTS:
                    time.sleep(_chain_backoff_seconds(attempt))
                    continue
                logger.error(
                    "audit_batch_chain_contention_exhausted tenant=%s event_id=%s",
                    tenant_id, event.event_id,
                )
                break
            except Exception as exc:  # noqa: BLE001 - reported, never swallowed
                last_error = f"{exc.__class__.__name__}: {exc}"
                logger.warning(
                    "Batch event ingest failed event_id=%s err=%s", event.event_id, exc)
                break

            previous_by_tenant[tenant_id] = model
            stored += 1
            last_error = None
            break

        if last_error:
            failed.append({"event_id": event.event_id, "error": last_error})

    db.commit()
    if failed:
        # WARNING with the reasons. "stored: 3, total: 5" tells a caller that
        # two events are gone and nothing about which or why.
        logger.warning(
            "audit_batch_partial stored=%s total=%s failed=%s",
            stored, len(body.events), failed,
        )
    return {"stored": stored, "total": len(body.events), "failed": failed}


# ── Event Queries ─────────────────────────────────────────────────────────────

@app.get("/events")
def query_events(
    agent_id: Optional[str] = None,
    tenant_id: Optional[str] = None,
    provider: Optional[str] = None,
    event_type: Optional[str] = None,
    outcome: Optional[str] = None,
    since: Optional[datetime] = None,
    until: Optional[datetime] = None,
    limit: int = Query(default=100, le=1000),
    offset: int = 0,
    db: Session = Depends(get_db),
    _: None = Depends(verify_api_key),
):
    q = db.query(AuditEventModel)
    if agent_id:
        q = q.filter(AuditEventModel.agent_id == agent_id)
    if tenant_id:
        q = q.filter(AuditEventModel.tenant_id == tenant_id)
    if provider:
        q = q.filter(AuditEventModel.provider == provider)
    if event_type:
        q = q.filter(AuditEventModel.event_type == event_type)
    if outcome:
        q = q.filter(AuditEventModel.outcome == outcome)
    if since:
        q = q.filter(AuditEventModel.timestamp >= since)
    if until:
        q = q.filter(AuditEventModel.timestamp <= until)

    q = q.order_by(AuditEventModel.timestamp.desc(), AuditEventModel.event_id.desc())
    total = q.count()
    events = q.offset(offset).limit(limit).all()
    return {"total": total, "offset": offset, "limit": limit, "events": [_model_to_dict(e) for e in events]}


@app.get("/events/{event_id}")
def get_event(event_id: str, db: Session = Depends(get_db), _: None = Depends(verify_api_key)):
    evt = db.query(AuditEventModel).filter(AuditEventModel.event_id == event_id).first()
    if not evt:
        raise HTTPException(status_code=404, detail="Event not found")
    return _model_to_dict(evt)


@app.get("/traces/{trace_id}")
def get_trace(trace_id: str, db: Session = Depends(get_db), _: None = Depends(verify_api_key)):
    """Get all events in a trace, ordered by timestamp."""
    events = db.query(AuditEventModel).filter(
        AuditEventModel.trace_id == trace_id
    ).order_by(AuditEventModel.timestamp.asc(), AuditEventModel.span_id.asc(), AuditEventModel.event_id.asc()).all()
    return {"trace_id": trace_id, "span_count": len(events), "events": [_model_to_dict(e) for e in events]}


# ── Action Graph ──────────────────────────────────────────────────────────────

@app.get("/graph/agent/{agent_id}")
def agent_action_graph(
    agent_id: str,
    hours: int = 24,
    db: Session = Depends(get_db),
    _: None = Depends(verify_api_key),
):
    """Build action graph for an agent."""
    since = datetime.now(timezone.utc) - timedelta(hours=hours)
    events = db.query(AuditEventModel).filter(
        AuditEventModel.agent_id == agent_id,
        AuditEventModel.timestamp >= since,
    ).order_by(AuditEventModel.timestamp.asc()).all()

    return _build_graph(agent_id, events, "agent")


@app.get("/graph/human/{human_id}")
def human_action_graph(
    human_id: str,
    hours: int = 24,
    db: Session = Depends(get_db),
    _: None = Depends(verify_api_key),
):
    """Build action graph for a human initiator (through their agents)."""
    since = datetime.now(timezone.utc) - timedelta(hours=hours)
    events = db.query(AuditEventModel).filter(
        AuditEventModel.human_initiator_id == human_id,
        AuditEventModel.timestamp >= since,
    ).order_by(AuditEventModel.timestamp.asc()).all()

    return _build_graph(human_id, events, "human")


def _build_graph(root_id: str, events: List[AuditEventModel], root_type: str) -> Dict:
    """Build a directed graph from audit events."""
    nodes: Dict[str, Dict] = {}
    edges: List[Dict] = []
    edge_counts: Dict[str, int] = {}

    def add_node(node_id: str, node_type: str, label: str):
        nodes[node_id] = {"id": node_id, "type": node_type, "label": label}

    add_node(root_id, root_type, root_id)

    for evt in events:
        agent_node = evt.agent_id
        add_node(agent_node, "agent", agent_node)

        if evt.human_initiator_id and root_type == "human":
            edge_key = f"{evt.human_initiator_id}→{agent_node}:initiated"
            edge_counts[edge_key] = edge_counts.get(edge_key, 0) + 1

        provider = evt.provider or "unknown"
        provider_node = f"provider:{provider}"
        add_node(provider_node, "provider", provider)
        if evt.model:
            model_node = f"model:{evt.model}"
            add_node(model_node, "model", evt.model)
            edge_key = f"{agent_node}→{model_node}:llm_call"
            edge_counts[edge_key] = edge_counts.get(edge_key, 0) + 1

        action = evt.action or {}
        if isinstance(action, dict) and action.get("tool_name"):
            tool_node = f"tool:{action['tool_name']}"
            add_node(tool_node, "tool", action["tool_name"])
            edge_key = f"{agent_node}→{tool_node}:tool_call"
            edge_counts[edge_key] = edge_counts.get(edge_key, 0) + 1

    for edge_key, count in edge_counts.items():
        parts = edge_key.split("→")
        if len(parts) == 2:
            from_node, rest = parts
            to_node, action = rest.split(":", 1)
            edges.append({
                "from": from_node, "to": to_node,
                "action": action, "count": count,
                "timestamp": events[-1].timestamp.isoformat() if events else "",
            })

    return {
        "root_id": root_id,
        "root_type": root_type,
        "event_count": len(events),
        "nodes": list(nodes.values()),
        "edges": edges,
    }


@app.get("/timeline")
def get_timeline(
    hours: int = 24,
    tenant_id: Optional[str] = None,
    limit: int = 50,
    db: Session = Depends(get_db),
    _: None = Depends(verify_api_key),
):
    """Human-readable action timeline."""
    since = datetime.now(timezone.utc) - timedelta(hours=hours)
    q = db.query(AuditEventModel).filter(AuditEventModel.timestamp >= since)
    if tenant_id:
        q = q.filter(AuditEventModel.tenant_id == tenant_id)
    events = q.order_by(AuditEventModel.timestamp.desc()).limit(limit).all()

    timeline = []
    for evt in events:
        action = evt.action or {}
        tool = action.get("tool_name") if isinstance(action, dict) else None
        model = evt.model or "unknown"
        desc = f"[{evt.event_type}] Agent {evt.agent_id[:12]}... called {tool or model}"
        if evt.outcome == "blocked":
            desc += " → BLOCKED"
        pd = evt.policy_decision or {}
        reason = pd.get("reason_code") if isinstance(pd, dict) else None
        if reason:
            desc += f" ({reason})"
        timeline.append({
            "timestamp": evt.timestamp.isoformat(),
            "event_id": evt.event_id,
            "agent_id": evt.agent_id,
            "description": desc,
            "outcome": evt.outcome,
            "provider": evt.provider,
            "cost_usd": evt.cost_usd,
            "latency_ms": evt.latency_ms,
        })
    return {"hours": hours, "count": len(timeline), "events": timeline}


@app.post("/export")
def export_events(
    body: EventQuery,
    fmt: str = "json",
    _: None = Depends(verify_api_key),
    db: Session = Depends(get_db),
):
    """Export events to SIEM format."""
    export_id = "exp_" + str(uuid4()).replace("-", "")[:16]
    q = db.query(AuditEventModel)
    if body.agent_id:
        q = q.filter(AuditEventModel.agent_id == body.agent_id)
    if body.tenant_id:
        q = q.filter(AuditEventModel.tenant_id == body.tenant_id)
    count = q.count()
    return {
        "export_id": export_id,
        "format": fmt,
        "events_count": count,
        "status": "queued",
        "download_url": f"/export/{export_id}/download",
    }


@app.get("/integrity/verify/{event_id}")
def verify_event_integrity(
    event_id: str,
    db: Session = Depends(get_db),
    _: None = Depends(verify_api_key),
):
    """Verify event signature for tamper detection."""
    evt = db.query(AuditEventModel).filter(AuditEventModel.event_id == event_id).first()
    if not evt:
        raise HTTPException(status_code=404, detail="Event not found")

    event_dict = _model_to_dict(evt)
    stored_sig = event_dict.pop("signature", None)

    if not stored_sig:
        return {"valid": False, "event_id": event_id, "reason": "NO_SIGNATURE"}

    verification = _verify_signature_result(event_dict, stored_sig)
    valid = verification.valid

    chain_valid = True
    chain_reason = None
    if (evt.prev_event_id and not evt.prev_signature) or (evt.prev_signature and not evt.prev_event_id):
        chain_valid = False
        chain_reason = "CHAIN_POINTER_INCOMPLETE"
    elif evt.prev_event_id:
        previous = db.query(AuditEventModel).filter(AuditEventModel.event_id == evt.prev_event_id).first()
        if not previous:
            chain_valid = False
            chain_reason = "MISSING_PREVIOUS_EVENT"
        elif previous.signature != evt.prev_signature:
            chain_valid = False
            chain_reason = "PREVIOUS_SIGNATURE_MISMATCH"
        elif evt.chain_hash != _compute_chain_hash(stored_sig, evt.prev_signature):
            chain_valid = False
            chain_reason = "CHAIN_HASH_MISMATCH"
    return {
        "valid": valid,
        "event_id": event_id,
        "algorithm": "HMAC-SHA256",
        "verified_at": datetime.now(timezone.utc).isoformat(),
        # The specific reason, not a bool re-rendered as a string. A caller
        # needs to be able to tell SIGNATURE_MATCH_LEGACY_GENESIS (genuine, but
        # written by a build with a known defect) from SIGNATURE_MATCH, and
        # SIGNATURE_MATCH_RETIRED_KEY (genuine, but signed with a key we have
        # rotated away from -- possibly because it was compromised) from both.
        "reason": verification.reason,
        # WHICH key verified it. An investigator holding a
        # SIGNATURE_MATCH_RETIRED_KEY verdict needs to know which retired key,
        # to decide whether that rotation was routine or a response to
        # compromise. Never the key material, only its id.
        "key_id": verification.key_id,
        "chain_valid": chain_valid,
        "chain_reason": chain_reason,
    }


@app.get("/integrity/signing-key/status")
def signing_key_status(
    _: None = Depends(verify_api_key),
):
    return {
        "active_key_id": AUDIT_SIGNING_KEY_ID,
        "next_key_configured": bool(AUDIT_NEXT_SIGNING_KEY),
        "next_key_id": AUDIT_NEXT_SIGNING_KEY_ID if AUDIT_NEXT_SIGNING_KEY else None,
        # Verify-only keys. Their IDS are reported, never their material.
        "retired_key_ids": [kid for kid, _ in AUDIT_RETIRED_KEYS],
        # Entries that could not be parsed. A record signed with one of these
        # will report SIGNATURE_MISMATCH -- indistinguishable from tampering --
        # so this is stated plainly rather than left to a startup log nobody
        # re-reads. Non-empty here means the trail has a blind spot.
        "retired_key_problems": list(AUDIT_RETIRED_KEY_PROBLEMS),
        "retired_keys_healthy": not AUDIT_RETIRED_KEY_PROBLEMS,
        "retention_days": AUDIT_RETENTION_DAYS,
        "immutable_retention_enforced": ENFORCE_IMMUTABLE_RETENTION,
    }


# ── Health & Metrics ──────────────────────────────────────────────────────────

@app.get("/health")
def health():
    return {"status": "ok", "service": "audit", "version": "1.0.0"}


@app.get("/ready")
def ready(db: Session = Depends(get_db)):
    try:
        db.connection().exec_driver_sql("SELECT 1")
        return {"status": "ready"}
    except Exception:
        raise HTTPException(status_code=503, detail="Database not ready")


@app.get("/metrics", response_class=PlainTextResponse)
def metrics(db: Session = Depends(get_db)):
    try:
        total = db.query(AuditEventModel).count()
        blocked = db.query(AuditEventModel).filter(AuditEventModel.outcome == "blocked").count()
        success = db.query(AuditEventModel).filter(AuditEventModel.outcome == "success").count()
    except Exception:
        total = blocked = success = 0
    lines = [
        "# HELP cyberarmor_audit_events_total Total audit events",
        "# TYPE cyberarmor_audit_events_total gauge",
        f"cyberarmor_audit_events_total {total}",
        f'cyberarmor_audit_events_by_outcome{{outcome="blocked"}} {blocked}',
        f'cyberarmor_audit_events_by_outcome{{outcome="success"}} {success}',
    ]
    return PlainTextResponse("\n".join(lines) + "\n", media_type="text/plain")


@app.get("/pki/public-key")
def pki_public_key():
    return get_public_key_info("audit")


# ── Private helpers ───────────────────────────────────────────────────────────

def _model_to_dict(evt: AuditEventModel) -> Dict:
    return {
        "event_id": evt.event_id,
        "trace_id": evt.trace_id,
        "span_id": evt.span_id,
        "parent_span_id": evt.parent_span_id,
        "tenant_id": evt.tenant_id,
        "agent_id": evt.agent_id,
        "agent_token_id": evt.agent_token_id,
        "human_initiator_id": evt.human_initiator_id,
        "delegation_chain": evt.delegation_chain or [],
        "event_type": evt.event_type,
        "provider": evt.provider,
        "model": evt.model,
        "framework": evt.framework,
        "action": evt.action,
        "policy_decision": evt.policy_decision,
        "data_classification": evt.data_classification or [],
        # `or {}` matches the `or []` treatment of the JSON list columns above:
        # a row written before this column existed reads back None, and the
        # signed payload used {} for it.
        "detail": evt.detail or {},
        "outcome": evt.outcome,
        "latency_ms": evt.latency_ms,
        "cost_usd": evt.cost_usd,
        "prev_event_id": evt.prev_event_id,
        "prev_signature": evt.prev_signature,
        "chain_hash": evt.chain_hash,
        "timestamp": evt.timestamp.isoformat() if evt.timestamp else None,
        "signature": evt.signature,
    }
