"""AIProtect consumer API — api.aiprotect.app.

Owns identity, accounts, subscriptions, devices and settings. Nothing else.
All ML and URL analysis is delegated over HTTP to consumer-dedicated
deployments of services/detection and services/url-trust-gate; this service
stays thin on purpose.

Every response is built to serve BOTH the responsive web portal and the React
Native app, so nothing here assumes a browser.
"""

from __future__ import annotations

import os
from typing import Any, Dict, List, Optional

import httpx
from fastapi import Depends, FastAPI, Header, HTTPException, Request
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session as DbSession

import auth
import billing
import devices as dv
import entitlements
import presets
from db import get_db, init_db
from models import Account, Device, Subscription

DETECTION_URL = os.getenv("AIPROTECT_DETECTION_URL", "http://detection:8002")
DETECTION_SECRET = os.getenv("DETECTION_API_SECRET", "")
TRUST_GATE_URL = os.getenv("AIPROTECT_TRUST_GATE_URL", "http://url-trust-gate:8005")
TRUST_GATE_SECRET = os.getenv("URL_TRUST_GATE_API_SECRET", "")
UPSTREAM_TIMEOUT_S = float(os.getenv("AIPROTECT_UPSTREAM_TIMEOUT_S", "8.0"))

app = FastAPI(title="AIProtect API", version="0.1.0")
app.add_middleware(
    CORSMiddleware,
    allow_origins=[o for o in os.getenv("AIPROTECT_CORS_ORIGINS", "").split(",") if o],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.on_event("startup")
def _startup() -> None:
    init_db()


# ---------------------------------------------------------------------------
# Auth plumbing
# ---------------------------------------------------------------------------


def current_account(
    db: DbSession = Depends(get_db),
    authorization: Optional[str] = Header(default=None),
) -> Account:
    token = (authorization or "").removeprefix("Bearer ").strip()
    account = auth.resolve_session(db, refresh_token=token) if token else None
    if account is None:
        raise HTTPException(status_code=401, detail={"reason": "not_signed_in"})
    return account


def subscription_of(db: DbSession, account: Account) -> Subscription:
    sub = account.subscription
    if sub is None:
        raise HTTPException(status_code=409, detail={"reason": "no_subscription"})
    return sub


def entitlement_of(sub: Subscription) -> entitlements.Entitlement:
    return entitlements.resolve(
        state=sub.state,
        tier_name=sub.tier,
        trial_ends_at=sub.trial_ends_at,
        grace_ends_at=sub.grace_ends_at,
    )


def require_protection(
    db: DbSession = Depends(get_db), account: Account = Depends(current_account)
) -> entitlements.Entitlement:
    """Gate the protection features on an entitlement that still protects.

    402 rather than 403: this is "your subscription needs attention", not "you
    are not allowed". The reason is always populated, because a client that can
    only say "not protected" cannot tell the person how to fix it.
    """
    ent = entitlement_of(subscription_of(db, account))
    if not ent.protected:
        raise HTTPException(
            status_code=402,
            detail={"reason": "not_protected", "detail": ent.reason,
                    "entitlement": ent.to_dict()},
        )
    return ent


# ---------------------------------------------------------------------------
# Schemas
# ---------------------------------------------------------------------------


class EmailIn(BaseModel):
    email: str


class VerifyIn(BaseModel):
    email: str
    code: str


class EnrollIn(BaseModel):
    name: str
    surface: str = Field(description="browser-extension | desktop-agent | mobile-app")
    platform: Optional[str] = None
    machine_hint: Optional[str] = None


class JoinIn(BaseModel):
    code: str
    surface: str


class CheckIn(BaseModel):
    url: Optional[str] = None
    text: Optional[str] = None


# ---------------------------------------------------------------------------
# Health
# ---------------------------------------------------------------------------


@app.get("/health")
async def health() -> Dict[str, Any]:
    return {"status": "ok", "service": "aiprotect-api", "version": "0.1.0"}


# ---------------------------------------------------------------------------
# Sign in
# ---------------------------------------------------------------------------


@app.post("/auth/request-code")
def request_code(payload: EmailIn, db: DbSession = Depends(get_db)) -> Dict[str, Any]:
    try:
        code = auth.request_login_code(db, email=payload.email)
    except auth.AuthError as exc:
        raise HTTPException(status_code=400, detail={"reason": str(exc)}) from exc
    db.commit()
    # TODO(prompt-9): hand to the mailer. Returned only when explicitly enabled
    # for local development -- returning it in production would make the code
    # pointless, since anyone who can call the endpoint would receive it.
    out: Dict[str, Any] = {"sent": True}
    if os.getenv("AIPROTECT_RETURN_LOGIN_CODE", "false").lower() in {"1", "true"}:
        out["code"] = code
    return out


@app.post("/auth/verify-code")
def verify_code(
    payload: VerifyIn,
    db: DbSession = Depends(get_db),
    user_agent: Optional[str] = Header(default=None, alias="user-agent"),
) -> Dict[str, Any]:
    try:
        account = auth.verify_login_code(db, email=payload.email, code=payload.code)
    except auth.AuthError as exc:
        raise HTTPException(status_code=401, detail={"reason": str(exc)}) from exc
    _session, token = auth.create_session(db, account=account, user_agent=user_agent)
    db.commit()
    return {
        "token": token,
        "account": {"id": account.id, "email": account.email},
        "entitlement": entitlement_of(subscription_of(db, account)).to_dict(),
    }


@app.post("/auth/sign-out-everywhere")
def sign_out_everywhere(
    db: DbSession = Depends(get_db), account: Account = Depends(current_account)
) -> Dict[str, Any]:
    revoked = auth.revoke_all_sessions(db, account=account)
    db.commit()
    return {"sessions_revoked": revoked}


# ---------------------------------------------------------------------------
# Subscription
# ---------------------------------------------------------------------------


@app.get("/me")
def me(
    db: DbSession = Depends(get_db), account: Account = Depends(current_account)
) -> Dict[str, Any]:
    sub = subscription_of(db, account)
    ent = entitlement_of(sub)
    return {
        "account": {"id": account.id, "email": account.email},
        "entitlement": ent.to_dict(),
        "devices_in_use": dv.active_device_count(db, sub.id),
    }


@app.get("/tiers")
def tiers() -> Dict[str, Any]:
    """The plans, read from shared/tiers.json.

    Served rather than hardcoded in the clients for the same reason the API
    reads it: a price on a pricing page that disagrees with the entitlement
    check is a customer billed for one thing and given another.
    """
    return {
        "tiers": {
            name: {
                "display_name": entitlements.tier(name)["display_name"],
                "devices": entitlements.device_limit(name),
                "people": entitlements.people_limit(name),
                "price_monthly": entitlements.tier(name)["price_monthly"],
                "price_annual": entitlements.tier(name)["price_annual"],
            }
            for name in entitlements.tier_names()
        },
        "upgrade_path": entitlements.tier_names(),
        "trial_days": entitlements.trial_days(),
    }


# ---------------------------------------------------------------------------
# Devices
# ---------------------------------------------------------------------------


def _device_out(db: DbSession, device: Device) -> Dict[str, Any]:
    return {
        "id": device.id,
        "name": device.name,
        "platform": device.platform,
        "enrolled_at": device.enrolled_at.isoformat() if device.enrolled_at else None,
        "last_seen_at": device.last_seen_at.isoformat() if device.last_seen_at else None,
        # Surfaces, not devices. Shown so a person can see that their laptop's
        # extension and agent are one device with two installs.
        "surfaces": [
            {"kind": s.kind, "active": s.active,
             "last_seen_at": s.last_seen_at.isoformat() if s.last_seen_at else None}
            for s in dv.surfaces_of(db, device)
        ],
    }


@app.get("/devices")
def list_devices(
    db: DbSession = Depends(get_db), account: Account = Depends(current_account)
) -> Dict[str, Any]:
    sub = subscription_of(db, account)
    ent = entitlement_of(sub)
    active = dv.active_devices(db, sub.id)
    return {
        "devices": [_device_out(db, d) for d in active],
        "devices_in_use": len(active),
        "devices_allowed": ent.devices_allowed,
    }


@app.post("/devices")
def enroll(
    payload: EnrollIn,
    db: DbSession = Depends(get_db),
    account: Account = Depends(current_account),
) -> Dict[str, Any]:
    sub = subscription_of(db, account)

    # Rule 2: offer a match before consuming a slot. Offered, never decided --
    # a wrong automatic match merges two real machines invisibly.
    candidate = dv.suggest_existing_device(
        db, subscription_id=sub.id, machine_hint=payload.machine_hint
    )
    if candidate is not None:
        return {
            "needs_confirmation": True,
            "question": (
                f"Is this the same device as “{candidate.name}”, "
                f"which you removed earlier?"
            ),
            "candidate_device_id": candidate.id,
        }

    try:
        enrolled = dv.enroll_device(
            db, subscription=sub, name=payload.name, surface_kind=payload.surface,
            platform=payload.platform, machine_hint=payload.machine_hint,
        )
    except dv.EnrollmentRefused as exc:
        # 409, and the body carries the upgrade target. With no per-device
        # add-on an upgrade is the ONLY route to more devices, so a refusal
        # without one is a dead end.
        raise HTTPException(status_code=409, detail=exc.decision.to_dict()) from exc
    except ValueError as exc:
        raise HTTPException(status_code=400, detail={"reason": str(exc)}) from exc

    db.commit()
    return {
        "device": _device_out(db, enrolled.device),
        # Shown once. Only the hash is stored.
        "credential": enrolled.credential,
    }


@app.post("/devices/{device_id}/reclaim")
def reclaim(
    device_id: str,
    payload: EnrollIn,
    db: DbSession = Depends(get_db),
    account: Account = Depends(current_account),
) -> Dict[str, Any]:
    """Confirm the offer from POST /devices — this IS the old device."""
    sub = subscription_of(db, account)
    device = db.get(Device, device_id)
    if device is None or device.subscription_id != sub.id:
        raise HTTPException(status_code=404, detail={"reason": "no_such_device"})
    enrolled = dv.reclaim_device(db, device=device, surface_kind=payload.surface)
    db.commit()
    return {
        "device": _device_out(db, enrolled.device),
        "credential": enrolled.credential,
    }


@app.post("/devices/{device_id}/join-code")
def join_code(
    device_id: str,
    db: DbSession = Depends(get_db),
    account: Account = Depends(current_account),
) -> Dict[str, Any]:
    """Issue a code so a SECOND surface can join this device.

    This is how the extension and the agent on one laptop arrive at the same
    device_id, which is what makes them share a subscription slot and a
    rate-limit bucket. docs/MULTI-DEVICE.md question 4.
    """
    sub = subscription_of(db, account)
    device = db.get(Device, device_id)
    if device is None or device.subscription_id != sub.id or not device.active:
        raise HTTPException(status_code=404, detail={"reason": "no_such_device"})
    code = dv.create_join_code(db, device=device)
    db.commit()
    return {"code": code.code, "expires_at": code.expires_at.isoformat()}


@app.post("/devices/join")
def join(
    payload: JoinIn,
    db: DbSession = Depends(get_db),
    account: Account = Depends(current_account),
) -> Dict[str, Any]:
    sub = subscription_of(db, account)
    try:
        enrolled = dv.join_surface(
            db, subscription_id=sub.id, code=payload.code, surface_kind=payload.surface
        )
    except dv.JoinFailed as exc:
        raise HTTPException(status_code=400, detail={"reason": str(exc)}) from exc
    except ValueError as exc:
        raise HTTPException(status_code=400, detail={"reason": str(exc)}) from exc
    db.commit()
    return {
        "device": _device_out(db, enrolled.device),
        "credential": enrolled.credential,
        # Said explicitly so a client can reassure the person.
        "consumed_a_device_slot": False,
    }


@app.delete("/devices/{device_id}")
def remove_device(
    device_id: str,
    db: DbSession = Depends(get_db),
    account: Account = Depends(current_account),
) -> Dict[str, Any]:
    """Remove a device and EVERY surface on it. Rule 4.

    A lost laptop is lost entirely. Revoking surface-by-surface is how one gets
    missed, and a missed surface is a live credential behind a screen that says
    the device was removed.
    """
    sub = subscription_of(db, account)
    device = db.get(Device, device_id)
    if device is None or device.subscription_id != sub.id:
        raise HTTPException(status_code=404, detail={"reason": "no_such_device"})
    revoked = dv.revoke_device(db, device=device)
    db.commit()
    return {"removed": True, "surfaces_revoked": revoked}


# ---------------------------------------------------------------------------
# Billing
# ---------------------------------------------------------------------------


class CheckoutIn(BaseModel):
    tier: str
    price_id: str


@app.post("/billing/checkout")
def checkout(
    payload: CheckoutIn,
    db: DbSession = Depends(get_db),
    account: Account = Depends(current_account),
) -> Dict[str, Any]:
    sub = subscription_of(db, account)
    if payload.tier not in entitlements.tier_names():
        raise HTTPException(status_code=400, detail={"reason": "unknown_tier"})
    try:
        out = billing.create_checkout_session(
            account_email=account.email, tier=payload.tier,
            price_id=payload.price_id, subscription_id=sub.id,
        )
    except Exception as exc:  # noqa: BLE001 - surfaced, not swallowed
        raise HTTPException(
            status_code=503, detail={"reason": "billing_unavailable"}
        ) from exc
    return out


@app.post("/billing/portal")
def portal(
    db: DbSession = Depends(get_db), account: Account = Depends(current_account)
) -> Dict[str, Any]:
    """Stripe's hosted portal: payment method, invoices, and cancellation.

    Not a bespoke cancel flow. Click-to-cancel rules require cancelling be as
    easy as subscribing, and Stripe's portal is already built to that standard.
    """
    sub = subscription_of(db, account)
    if not sub.stripe_customer_id:
        raise HTTPException(status_code=409, detail={"reason": "no_billing_account"})
    try:
        return billing.create_portal_session(stripe_customer_id=sub.stripe_customer_id)
    except Exception as exc:  # noqa: BLE001
        raise HTTPException(
            status_code=503, detail={"reason": "billing_unavailable"}
        ) from exc


@app.post("/billing/webhook")
async def stripe_webhook(
    request: Request,
    db: DbSession = Depends(get_db),
    stripe_signature: Optional[str] = Header(default=None, alias="stripe-signature"),
) -> Dict[str, Any]:
    """Receive Stripe events.

    The ONLY unauthenticated endpoint on this API, which is why the first thing
    it does is verify a signature over the RAW body -- parsing and
    re-serialising first would check a signature against bytes Stripe never
    signed.

    Failure modes are chosen deliberately:
      * bad signature      -> 400. Never processed, never acknowledged.
      * unknown event type -> 200. Stripe sends many events; 2xx keeps the ones
                              we do not use out of the three-day retry queue.
      * no matching row    -> 200. Retrying cannot conjure a subscription, and
                              a permanently-failing endpoint gets disabled by
                              Stripe, taking the events we DO need with it.
      * unexpected error   -> 500, so Stripe retries. Idempotency makes that
                              safe.
    """
    raw = await request.body()
    try:
        billing.verify_signature(
            payload=raw,
            signature_header=stripe_signature or "",
            secret=billing.STRIPE_WEBHOOK_SECRET,
        )
        event = billing.parse_event(raw)
    except billing.WebhookError as exc:
        raise HTTPException(
            status_code=400, detail={"reason": "invalid_webhook", "detail": str(exc)}
        ) from exc

    outcome = billing.handle_event(db, event)
    db.commit()
    return outcome.to_dict()


# ---------------------------------------------------------------------------
# Protection settings
# ---------------------------------------------------------------------------


@app.get("/presets")
def list_presets() -> Dict[str, Any]:
    return {
        "presets": [
            {"id": name, "rules": presets.rule_ids(name)}
            for name in presets.PRESET_NAMES
        ]
    }


# ---------------------------------------------------------------------------
# Protection features (thin proxies to the engines)
# ---------------------------------------------------------------------------


def _upstream_headers(*, secret: str, account: Account, device_id: Optional[str]):
    """The headers that make the two-level rate limit work.

    x-client-id is the DEVICE, never the surface: a laptop's extension and
    agent share one bucket. x-account-id is the subscription, so many devices
    cannot sum past the plan's ceiling. See docs/MULTI-DEVICE.md.
    """
    headers = {"x-api-key": secret, "x-account-id": account.id}
    if device_id:
        headers["x-client-id"] = device_id
    return headers


@app.post("/safe-links")
async def safe_links(
    payload: CheckIn,
    account: Account = Depends(current_account),
    _ent: entitlements.Entitlement = Depends(require_protection),
    x_device_id: Optional[str] = Header(default=None, alias="x-device-id"),
) -> Dict[str, Any]:
    if not payload.url:
        raise HTTPException(status_code=400, detail={"reason": "url_required"})
    try:
        async with httpx.AsyncClient(timeout=UPSTREAM_TIMEOUT_S) as client:
            resp = await client.post(
                f"{TRUST_GATE_URL.rstrip('/')}/evaluate",
                json={
                    "url": payload.url,
                    "source": "aiprotect-api",
                    "device_id": x_device_id,
                    "depth": "fast",
                },
                headers=_upstream_headers(
                    secret=TRUST_GATE_SECRET, account=account, device_id=x_device_id
                ),
            )
    except httpx.HTTPError as exc:
        raise HTTPException(
            status_code=503,
            detail={"reason": "trust_gate_unavailable",
                    "detail": "We could not check this link just now."},
        ) from exc
    body = resp.json()
    # Hand back the consumer block the gate already builds. `safe` there is a
    # bounded claim -- "nothing we checked came back bad" -- with
    # checks_performed alongside it. Do not flatten it into a boolean.
    return {"consumer": body.get("consumer", {}), "device_id": body.get("device_id")}


@app.post("/privacy-check")
async def privacy_check(
    payload: CheckIn,
    account: Account = Depends(current_account),
    _ent: entitlements.Entitlement = Depends(require_protection),
    x_device_id: Optional[str] = Header(default=None, alias="x-device-id"),
) -> Dict[str, Any]:
    if not payload.text:
        raise HTTPException(status_code=400, detail={"reason": "text_required"})
    try:
        async with httpx.AsyncClient(timeout=UPSTREAM_TIMEOUT_S) as client:
            resp = await client.post(
                f"{DETECTION_URL.rstrip('/')}/scan/sensitive-data",
                json={"text": payload.text},
                headers=_upstream_headers(
                    secret=DETECTION_SECRET, account=account, device_id=x_device_id
                ),
            )
    except httpx.HTTPError as exc:
        raise HTTPException(
            status_code=503,
            detail={"reason": "detection_unavailable",
                    "detail": "We could not check this text just now."},
        ) from exc
    if resp.status_code == 429:
        # Pass the scope through: "this device is going too fast" and "another
        # of your devices is using the plan's capacity" need different UI.
        raise HTTPException(status_code=429, detail=resp.json().get("detail", {}))
    body = resp.json()
    return {
        "found": body.get("detections", []),
        # Carried through, never dropped: a scan whose detector did not run is
        # not a scan that found nothing.
        "scan_complete": body.get("scan_complete", True),
        "checks_skipped_by_profile": body.get("checks_skipped_by_profile", []),
    }
