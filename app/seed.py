"""
seed.py
-------
Idempotent demo data so both sides can be tested before real enrollment.

On startup (only when missing):
  - one operator staff login for the console (/platform)
  - two partner institutions with portal logins for the portal (/)
  - a partner_users admin for every institution that has a portal login
    (migrates the legacy single portal_email into the multi-user table)
  - a handful of detected transactions per demo partner, so their portal
    dashboard, analytics and transactions views are populated

Safe to run on every startup — existing rows are never overwritten.
"""
from __future__ import annotations

import hashlib
import json
import secrets
from datetime import datetime, timedelta, timezone

from app.database import _get_pool
from app.portal_auth import hash_password

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

# (amount, currency, location, category, decision, score, reason, signals, user)
_DEMO_TXNS = [
    (120.00, "GHS", "Accra, GH", "retail", "ALLOW", 0.08, "Low-risk retail purchase in home region.", [], "cust_1001"),
    (25000.00, "GHS", "Lagos, NG", "crypto", "BLOCK", 0.93, "High-value crypto purchase from a new geo; matches known mule pattern.", ["large_amount", "geo_mismatch", "crypto"], "cust_1002"),
    (4800.00, "GHS", "Kumasi, GH", "electronics", "REVIEW", 0.52, "Amount above the customer's normal range; manual review advised.", ["amount_anomaly"], "cust_1003"),
    (60.00, "GHS", "Accra, GH", "food", "ALLOW", 0.05, "Routine low-value transaction.", [], "cust_1001"),
    (18000.00, "GHS", "Dubai, AE", "jewelry", "BLOCK", 0.88, "Cross-border high-value purchase inconsistent with history.", ["large_amount", "geo_mismatch"], "cust_1004"),
    (900.00, "GHS", "Tema, GH", "fuel", "ALLOW", 0.11, "Normal fuel purchase.", [], "cust_1005"),
    (7300.00, "GHS", "Accra, GH", "atm", "REVIEW", 0.47, "Multiple withdrawals in a short window.", ["velocity"], "cust_1002"),
    (240.00, "GHS", "Accra, GH", "retail", "ALLOW", 0.09, "Low-risk purchase.", [], "cust_1006"),
]


async def _ensure_demo_transactions(conn, integration_id: int) -> None:
    existing = await conn.fetchval(
        "SELECT COUNT(*) FROM transactions WHERE integration_id = $1", integration_id
    )
    if existing:
        return
    now = datetime.now(timezone.utc)
    for i, (amount, cur, loc, cat, decision, score, reason, signals, user) in enumerate(_DEMO_TXNS):
        ts = now - timedelta(days=i, hours=i * 2)
        txn_id = f"seed_{integration_id}_{i}"
        await conn.execute(
            """
            INSERT INTO transactions
                (transaction_id, user_id, amount, currency, merchant_category, location, timestamp, integration_id)
            VALUES ($1,$2,$3,$4,$5,$6,$7,$8)
            ON CONFLICT (transaction_id) DO NOTHING
            """,
            txn_id, user, amount, cur, cat, loc, ts, integration_id,
        )
        await conn.execute(
            """
            INSERT INTO fraud_results (transaction_id, score, decision, reason, signals, processed_at)
            VALUES ($1,$2,$3,$4,$5::jsonb,$6)
            ON CONFLICT (transaction_id) DO NOTHING
            """,
            txn_id, score, decision, reason, json.dumps(signals), ts,
        )


async def ensure_seed() -> None:
    pool = await _get_pool()
    async with pool.acquire() as conn:
        # Operator staff account
        if not await conn.fetchval("SELECT 1 FROM staff_users WHERE email = $1", STAFF["email"]):
            await conn.execute(
                "INSERT INTO staff_users (email, password_hash, name, role) VALUES ($1,$2,$3,$4)",
                STAFF["email"], hash_password(STAFF["password"]), STAFF["name"], STAFF["role"],
            )

        # Demo partner institutions (matched by portal_email)
        for p in PARTNERS:
            if await conn.fetchval("SELECT 1 FROM integrations WHERE portal_email = $1", p["portal_email"]):
                continue
            raw_key = secrets.token_hex(32)
            key_hash = hashlib.sha256(raw_key.encode()).hexdigest()
            await conn.execute(
                """
                INSERT INTO integrations
                    (partner_name, webhook_url, api_key_hash, notify_on,
                     institution_type, connection_method, contact_email,
                     portal_email, portal_password_hash)
                VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9)
                """,
                p["partner_name"], p["webhook_url"], key_hash, p["notify_on"],
                p["institution_type"], p["connection_method"], p["contact_email"],
                p["portal_email"], hash_password(p["portal_password"]),
            )

        # Migrate every institution's portal login into partner_users (admin),
        # so multi-user management works and existing logins keep functioning.
        integ_rows = await conn.fetch(
            "SELECT id, partner_name, portal_email, portal_password_hash FROM integrations "
            "WHERE portal_email IS NOT NULL AND portal_password_hash IS NOT NULL"
        )
        for r in integ_rows:
            if await conn.fetchval("SELECT 1 FROM partner_users WHERE email = $1", r["portal_email"]):
                continue
            await conn.execute(
                """
                INSERT INTO partner_users (integration_id, email, password_hash, name, role)
                VALUES ($1,$2,$3,$4,'admin')
                ON CONFLICT (email) DO NOTHING
                """,
                r["id"], r["portal_email"], r["portal_password_hash"], "Primary admin",
            )

        # Demo transactions for the two demo partners
        for p in PARTNERS:
            iid = await conn.fetchval("SELECT id FROM integrations WHERE portal_email = $1", p["portal_email"])
            if iid:
                await _ensure_demo_transactions(conn, iid)
