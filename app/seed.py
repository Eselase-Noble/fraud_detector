"""
seed.py
-------
Idempotent demo accounts so both sides can be tested before real enrollment.

Creates (only if missing, matched by email):
  - one operator staff login for the console (/platform)
  - two partner institutions with portal logins for the portal (/)

Safe to run on every startup — existing rows are never overwritten.
"""
from __future__ import annotations

import hashlib
import secrets

from app.database import _get_pool
from app.portal_auth import hash_password

# ── Demo credentials (dev only — change in production) ────────────────────────
STAFF = {"email": "operator@sentinel.local", "password": "operator123", "name": "Sentinel Operator", "role": "admin"}
PARTNERS = [
    {
        "partner_name": "Accra Commercial Bank", "institution_type": "bank",
        "connection_method": "rest_api", "webhook_url": "https://acb.demo/hooks/sentinel",
        "contact_email": "risk@acb.demo", "notify_on": ["BLOCK", "REVIEW"],
        "portal_email": "bank@demo.africode", "portal_password": "partner123",
    },
    {
        "partner_name": "PayFlow Fintech", "institution_type": "fintech",
        "connection_method": "database", "webhook_url": "https://payflow.demo/hooks",
        "contact_email": "ops@payflow.demo", "notify_on": ["BLOCK", "REVIEW", "ALLOW"],
        "portal_email": "fintech@demo.africode", "portal_password": "partner123",
    },
]


async def ensure_seed() -> None:
    pool = await _get_pool()
    async with pool.acquire() as conn:
        # Operator staff account
        exists = await conn.fetchval("SELECT 1 FROM staff_users WHERE email = $1", STAFF["email"])
        if not exists:
            await conn.execute(
                "INSERT INTO staff_users (email, password_hash, name, role) VALUES ($1, $2, $3, $4)",
                STAFF["email"], hash_password(STAFF["password"]), STAFF["name"], STAFF["role"],
            )

        # Demo partner institutions (matched by portal_email)
        for p in PARTNERS:
            present = await conn.fetchval(
                "SELECT 1 FROM integrations WHERE portal_email = $1", p["portal_email"]
            )
            if present:
                continue
            raw_key = secrets.token_hex(32)  # discarded — demo partners sign in via the portal
            key_hash = hashlib.sha256(raw_key.encode()).hexdigest()
            await conn.execute(
                """
                INSERT INTO integrations
                    (partner_name, webhook_url, api_key_hash, notify_on,
                     institution_type, connection_method, contact_email,
                     portal_email, portal_password_hash)
                VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
                """,
                p["partner_name"], p["webhook_url"], key_hash, p["notify_on"],
                p["institution_type"], p["connection_method"], p["contact_email"],
                p["portal_email"], hash_password(p["portal_password"]),
            )
