"""Consumer sign-in. Written fresh, not adapted from the B2B service.

WHY NOT FORK services/dashboard-auth
====================================
It is operator-coupled, not tenant-coupled: an email ALLOWLIST with no
registration path at all, plus a 16-target authenticated reverse proxy to
other services, plus peer-operator account management. About 100-150 of its
1,245 lines survive contact with a consumer product, and every one of its
assumptions points the wrong way -- it is a vendor admin console, not a way for
a member of the public to make an account.

What is reused is the part worth reusing: `cyberarmor_core.crypto.totp`, so the
TOTP implementation is shared rather than written twice.

THE MODEL
=========
Passwordless email codes are the baseline: no password to choose, forget,
reuse, or leak, and no password reset flow to attack. Apple and Google
sign-in are seams, wired when the mobile app needs them (Apple is mandatory
on iOS if Google is offered). TOTP is opt-in for people who want a second
factor on top.
"""

from __future__ import annotations

import hashlib
import hmac
import os
import secrets
from datetime import datetime, timedelta, timezone
from typing import Optional, Tuple

from sqlalchemy import select
from sqlalchemy.orm import Session as DbSession

from models import Account, LoginCode, Session, Subscription

import entitlements

#: Codes are short because people type them from an email. That makes the
#: attempt cap and the TTL the things standing between a 6-digit space and an
#: attacker, so neither is negotiable.
CODE_TTL_MINUTES = int(os.getenv("AIPROTECT_LOGIN_CODE_TTL_MINUTES", "10"))
CODE_MAX_ATTEMPTS = int(os.getenv("AIPROTECT_LOGIN_CODE_MAX_ATTEMPTS", "5"))
#: How many codes one address may request per window, so the endpoint cannot be
#: used to spam somebody else's inbox.
CODE_REQUESTS_PER_HOUR = int(os.getenv("AIPROTECT_LOGIN_CODES_PER_HOUR", "5"))

SESSION_TTL_DAYS = int(os.getenv("AIPROTECT_SESSION_TTL_DAYS", "90"))

_PEPPER = os.getenv("AIPROTECT_AUTH_PEPPER", "")


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _hash(value: str) -> str:
    return hashlib.sha256((_PEPPER + value).encode("utf-8")).hexdigest()


def normalise_email(email: str) -> str:
    return (email or "").strip().lower()


class AuthError(Exception):
    """Deliberately one exception type with generic messages.

    Distinguishing "no such account" from "wrong code" turns sign-in into an
    account-existence oracle, which for a security product is a list of who
    uses it.
    """


# ---------------------------------------------------------------------------
# Passwordless email codes
# ---------------------------------------------------------------------------


def request_login_code(db: DbSession, *, email: str) -> str:
    """Create a sign-in code. Returns it so a mailer can send it.

    The code is returned, never stored: only its hash is written. A database
    read must not yield a working credential.
    """
    email = normalise_email(email)
    if not email or "@" not in email:
        raise AuthError("Enter a valid email address.")

    recent = db.scalars(
        select(LoginCode).where(
            LoginCode.email == email,
            LoginCode.created_at >= _now() - timedelta(hours=1),
        )
    ).all()
    if len(recent) >= CODE_REQUESTS_PER_HOUR:
        raise AuthError("Too many sign-in requests. Try again later.")

    code = f"{secrets.randbelow(1_000_000):06d}"
    db.add(LoginCode(
        email=email,
        code_hash=_hash(code),
        expires_at=_now() + timedelta(minutes=CODE_TTL_MINUTES),
    ))
    db.flush()
    return code


def verify_login_code(db: DbSession, *, email: str, code: str) -> Account:
    """Consume a code and return the account, creating it on first sign-in."""
    email = normalise_email(email)
    row = db.scalars(
        select(LoginCode)
        .where(LoginCode.email == email, LoginCode.consumed_at.is_(None))
        .order_by(LoginCode.created_at.desc())
    ).first()

    if row is None:
        raise AuthError("That code is not valid.")
    if _now() >= row.expires_at:
        raise AuthError("That code has expired. Request a new one.")
    if row.attempts >= CODE_MAX_ATTEMPTS:
        raise AuthError("Too many attempts. Request a new code.")

    row.attempts += 1
    db.flush()

    # Constant-time: a timing difference here leaks the code one byte at a
    # time, and the code is the entire credential.
    if not hmac.compare_digest(row.code_hash, _hash(code or "")):
        raise AuthError("That code is not valid.")

    row.consumed_at = _now()
    account = db.scalars(select(Account).where(Account.email == email)).first()
    if account is None:
        account = _create_account(db, email=email)
    db.flush()
    return account


def _create_account(db: DbSession, *, email: str) -> Account:
    """First sign-in creates the account AND starts the trial.

    There is no free tier, so an account without a subscription is not a
    meaningful state -- it would be a person who signed in and can do nothing.
    """
    account = Account(email=email)
    db.add(account)
    db.flush()
    db.add(Subscription(
        owner_account_id=account.id,
        tier="personal",
        state=entitlements.TRIALING,
        trial_ends_at=_now() + timedelta(days=entitlements.trial_days()),
    ))
    db.flush()
    return account


# ---------------------------------------------------------------------------
# Sessions
# ---------------------------------------------------------------------------


def create_session(
    db: DbSession, *, account: Account, user_agent: Optional[str] = None
) -> Tuple[Session, str]:
    """Returns (session, refresh_token). The token is never stored raw."""
    token = secrets.token_urlsafe(40)
    session = Session(
        account_id=account.id,
        refresh_token_hash=_hash(token),
        expires_at=_now() + timedelta(days=SESSION_TTL_DAYS),
        user_agent=user_agent,
    )
    db.add(session)
    db.flush()
    return session, token


def resolve_session(db: DbSession, *, refresh_token: str) -> Optional[Account]:
    session = db.scalars(
        select(Session).where(Session.refresh_token_hash == _hash(refresh_token or ""))
    ).first()
    if session is None or session.revoked_at is not None:
        return None
    if _now() >= session.expires_at:
        return None
    return db.get(Account, session.account_id)


def revoke_session(db: DbSession, *, session: Session) -> None:
    session.revoked_at = _now()
    db.flush()


def revoke_all_sessions(db: DbSession, *, account: Account) -> int:
    """Sign out everywhere. The lever a person reaches for when they think
    somebody else has access, so it must reach every session including the
    one making the request."""
    revoked = 0
    for session in db.scalars(
        select(Session).where(
            Session.account_id == account.id, Session.revoked_at.is_(None)
        )
    ):
        session.revoked_at = _now()
        revoked += 1
    db.flush()
    return revoked
