"""
portal_auth.py
--------------
Credential + session helpers for the partner portal.

Humans log into the portal with an email + password (verified here); their
institution's systems authenticate to the detection API with an API key. Both
map to the same `integrations` row, but they are separate credentials.

No third-party deps: PBKDF2 for password hashing, HMAC-signed stateless tokens
for sessions. The signing secret comes from PORTAL_SECRET (dev fallback provided).
"""
from __future__ import annotations

import base64
import hashlib
import hmac
import os
import secrets
import time
from typing import Optional

_SECRET = os.getenv("PORTAL_SECRET", "dev-portal-secret-change-in-production").encode()
_ITERATIONS = 200_000
TOKEN_TTL = 12 * 3600  # 12 hours


# ─── Passwords ────────────────────────────────────────────────────────────────

def hash_password(password: str) -> str:
    salt = secrets.token_bytes(16)
    dk = hashlib.pbkdf2_hmac("sha256", password.encode(), salt, _ITERATIONS)
    return f"pbkdf2${_ITERATIONS}${salt.hex()}${dk.hex()}"


def verify_password(password: str, stored: Optional[str]) -> bool:
    if not stored:
        return False
    try:
        algo, iters, salt_hex, hash_hex = stored.split("$")
        if algo != "pbkdf2":
            return False
        dk = hashlib.pbkdf2_hmac("sha256", password.encode(), bytes.fromhex(salt_hex), int(iters))
        return hmac.compare_digest(dk.hex(), hash_hex)
    except Exception:
        return False


# ─── Session tokens (stateless, signed) ──────────────────────────────────────

def issue_token(kind: str, subject_id: int) -> str:
    """Issue a signed session token for a subject of a given kind ("staff" or
    "partner"). Tokens of one kind are not accepted where the other is expected."""
    exp = int(time.time()) + TOKEN_TTL
    payload = f"{kind}:{subject_id}:{exp}"
    sig = hmac.new(_SECRET, payload.encode(), hashlib.sha256).hexdigest()
    return base64.urlsafe_b64encode(f"{payload}|{sig}".encode()).decode()


def verify_token(token: str, expected_kind: str) -> Optional[int]:
    """Return the subject id if the token is valid, unexpired and of expected_kind."""
    try:
        raw = base64.urlsafe_b64decode(token.encode()).decode()
        payload, sig = raw.rsplit("|", 1)
        expected = hmac.new(_SECRET, payload.encode(), hashlib.sha256).hexdigest()
        if not hmac.compare_digest(sig, expected):
            return None
        kind, subject_id, exp = payload.split(":")
        if kind != expected_kind:
            return None
        if int(exp) < int(time.time()):
            return None
        return int(subject_id)
    except Exception:
        return None
