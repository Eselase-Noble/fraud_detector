"""
routers/admin.py
----------------
Admin endpoints for:
  - Managing bank/fintech partner integrations (webhooks)
  - Analyst case review (CONFIRM_FRAUD, CLEAR, ESCALATE)
  - Audit log access
  - Manual risk tier updates on users
"""
from __future__ import annotations

import hashlib
import secrets
from datetime import datetime, timezone
from typing import List, Optional

from fastapi import APIRouter, HTTPException, Query
from pydantic import BaseModel, HttpUrl

from app.database import _get_pool
from app.portal_auth import hash_password

router = APIRouter( tags=["Admin"])


# ─── Models ───────────────────────────────────────────────────────────────────

# Any financial institution — not just banks.
INSTITUTION_TYPES = {"bank", "fintech", "psp", "microfinance", "mobile_money", "sacco", "exchange", "other"}
# How the institution feeds transaction data to Sentinel.
CONNECTION_METHODS = {"rest_api", "batch_api", "database", "file_sftp"}

class IntegrationCreate(BaseModel):
    partner_name: str
    webhook_url: str
    notify_on: List[str] = ["BLOCK", "REVIEW"]
    institution_type: str = "bank"
    connection_method: str = "rest_api"
    contact_email: Optional[str] = None
    # Optional human portal login provisioned at registration.
    portal_email: Optional[str] = None
    portal_password: Optional[str] = None

class IntegrationResponse(BaseModel):
    id: int
    partner_name: str
    webhook_url: str
    is_active: bool
    notify_on: List[str]
    institution_type: str = "bank"
    connection_method: str = "rest_api"
    contact_email: Optional[str] = None
    portal_email: Optional[str] = None
    created_at: datetime
    last_used_at: Optional[datetime] = None
    # api_key returned only at creation / rotation time, never again
    api_key: Optional[str] = None

class PortalCredentials(BaseModel):
    portal_email: str
    portal_password: str

class ReviewAction(BaseModel):
    analyst_id: str
    action: str              # CONFIRM_FRAUD | CLEAR | ESCALATE | NOTE
    new_decision: Optional[str] = None
    note: Optional[str] = None

class UserRiskUpdate(BaseModel):
    risk_tier: str           # standard | elevated | high
    is_flagged: Optional[bool] = None
    notes: Optional[str] = None

class AuditEntry(BaseModel):
    id: int
    transaction_id: str
    analyst_id: Optional[str]
    action: str
    previous_decision: Optional[str]
    new_decision: Optional[str]
    note: Optional[str]
    created_at: datetime


# ─── Integrations ─────────────────────────────────────────────────────────────

@router.post("/integrations", response_model=IntegrationResponse,
             summary="Register a new bank/partner webhook integration")
async def create_integration(body: IntegrationCreate):
    """
    Registers a partner (bank, fintech, PSP) to receive real-time webhook
    notifications for fraud decisions. Returns a one-time API key — store it
    securely, it is never shown again.
    """
    valid_decisions = {"ALLOW", "REVIEW", "BLOCK"}
    invalid = set(body.notify_on) - valid_decisions
    if invalid:
        raise HTTPException(400, detail=f"Invalid notify_on values: {invalid}")
    if body.institution_type not in INSTITUTION_TYPES:
        raise HTTPException(400, detail=f"institution_type must be one of {sorted(INSTITUTION_TYPES)}")
    if body.connection_method not in CONNECTION_METHODS:
        raise HTTPException(400, detail=f"connection_method must be one of {sorted(CONNECTION_METHODS)}")

    # Generate a secure API key — shown once, stored as a hash
    raw_key = secrets.token_hex(32)
    key_hash = hashlib.sha256(raw_key.encode()).hexdigest()

    pw_hash = hash_password(body.portal_password) if (body.portal_email and body.portal_password) else None

    pool = await _get_pool()
    async with pool.acquire() as conn:
        row = await conn.fetchrow(
            f"""
            INSERT INTO integrations
                (partner_name, webhook_url, api_key_hash, notify_on,
                 institution_type, connection_method, contact_email,
                 portal_email, portal_password_hash)
            VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
            RETURNING {_INTEGRATION_COLS_INLINE}
            """,
            body.partner_name,
            body.webhook_url,
            key_hash,
            body.notify_on,
            body.institution_type,
            body.connection_method,
            body.contact_email,
            body.portal_email,
            pw_hash,
        )
        # Mirror the portal login into partner_users so it works immediately
        # (partner login authenticates against partner_users, not integrations).
        if body.portal_email and pw_hash:
            await conn.execute(
                """
                INSERT INTO partner_users (integration_id, email, password_hash, name, role)
                VALUES ($1, $2, $3, 'Primary admin', 'admin')
                ON CONFLICT (email) DO UPDATE SET
                    integration_id = EXCLUDED.integration_id,
                    password_hash  = EXCLUDED.password_hash
                """,
                row["id"], body.portal_email.strip().lower(), pw_hash,
            )

    return IntegrationResponse(**dict(row), api_key=raw_key)


# Columns safe to return to clients — never the api_key_hash or portal_password_hash.
_INTEGRATION_COLS_INLINE = (
    "id, partner_name, webhook_url, is_active, notify_on, "
    "institution_type, connection_method, contact_email, portal_email, "
    "created_at, last_used_at"
)
_INTEGRATION_COLS = _INTEGRATION_COLS_INLINE


@router.get("/integrations", response_model=List[IntegrationResponse],
            summary="List all registered integrations")
async def list_integrations():
    pool = await _get_pool()
    async with pool.acquire() as conn:
        rows = await conn.fetch(
            f"SELECT {_INTEGRATION_COLS} FROM integrations ORDER BY created_at DESC"
        )
    return [IntegrationResponse(**dict(r)) for r in rows]


@router.post("/integrations/{integration_id}/rotate", response_model=IntegrationResponse,
             summary="Rotate a partner's API key (invalidates the old one)")
async def rotate_integration_key(integration_id: int):
    """Issues a fresh API key and invalidates the previous one. The new key is
    returned once — the partner must update their credential store immediately."""
    raw_key = secrets.token_hex(32)
    key_hash = hashlib.sha256(raw_key.encode()).hexdigest()
    pool = await _get_pool()
    async with pool.acquire() as conn:
        row = await conn.fetchrow(
            f"UPDATE integrations SET api_key_hash = $1 WHERE id = $2 RETURNING {_INTEGRATION_COLS}",
            key_hash, integration_id,
        )
    if not row:
        raise HTTPException(404, detail="Integration not found.")
    return IntegrationResponse(**dict(row), api_key=raw_key)


@router.post("/integrations/{integration_id}/portal_credentials",
             response_model=IntegrationResponse,
             summary="Set or reset a partner's portal login (email + password)")
async def set_portal_credentials(integration_id: int, body: PortalCredentials):
    """Provisions the human login used to sign into the partner portal. Distinct
    from the machine API key. Re-calling replaces the previous credentials."""
    pw_hash = hash_password(body.portal_password)
    pool = await _get_pool()
    async with pool.acquire() as conn:
        try:
            row = await conn.fetchrow(
                f"UPDATE integrations SET portal_email = $1, portal_password_hash = $2 "
                f"WHERE id = $3 RETURNING {_INTEGRATION_COLS}",
                body.portal_email.strip().lower(), pw_hash, integration_id,
            )
            if row:
                await conn.execute(
                    """
                    INSERT INTO partner_users (integration_id, email, password_hash, name, role)
                    VALUES ($1, $2, $3, 'Primary admin', 'admin')
                    ON CONFLICT (email) DO UPDATE SET
                        integration_id = EXCLUDED.integration_id,
                        password_hash  = EXCLUDED.password_hash
                    """,
                    integration_id, body.portal_email.strip().lower(), pw_hash,
                )
        except Exception:
            raise HTTPException(409, detail="That portal email is already in use.")
    if not row:
        raise HTTPException(404, detail="Integration not found.")
    return IntegrationResponse(**dict(row))


@router.patch("/integrations/{integration_id}/toggle",
              summary="Enable or disable a partner integration")
async def toggle_integration(integration_id: int):
    pool = await _get_pool()
    async with pool.acquire() as conn:
        row = await conn.fetchrow(
            "UPDATE integrations SET is_active = NOT is_active WHERE id = $1 "
            "RETURNING id, partner_name, is_active",
            integration_id,
        )
    if not row:
        raise HTTPException(404, detail="Integration not found.")
    return {"id": row["id"], "partner_name": row["partner_name"], "is_active": row["is_active"]}


@router.delete("/integrations/{integration_id}", summary="Remove a partner integration")
async def delete_integration(integration_id: int):
    pool = await _get_pool()
    async with pool.acquire() as conn:
        result = await conn.execute("DELETE FROM integrations WHERE id = $1", integration_id)
    if result == "DELETE 0":
        raise HTTPException(404, detail="Integration not found.")
    return {"status": "deleted", "id": integration_id}


# ─── Analyst Review ───────────────────────────────────────────────────────────

@router.post("/review/{transaction_id}", summary="Analyst reviews and acts on a fraud case")
async def review_transaction(transaction_id: str, body: ReviewAction):
    """
    Allows a fraud analyst to override or confirm a machine decision.
    All actions are written to the immutable audit_log.
    """
    valid_actions = {"CONFIRM_FRAUD", "CLEAR", "ESCALATE", "NOTE"}
    if body.action not in valid_actions:
        raise HTTPException(400, detail=f"Action must be one of {valid_actions}")

    if body.new_decision and body.new_decision not in {"ALLOW", "REVIEW", "BLOCK"}:
        raise HTTPException(400, detail="new_decision must be ALLOW, REVIEW, or BLOCK")

    pool = await _get_pool()
    async with pool.acquire() as conn:
        # Fetch current decision
        current = await conn.fetchrow(
            "SELECT decision FROM fraud_results WHERE transaction_id = $1",
            transaction_id,
        )
        if not current:
            raise HTTPException(404, detail=f"No fraud result found for {transaction_id}")

        previous_decision = current["decision"]

        # Write audit entry
        await conn.execute(
            """
            INSERT INTO audit_log
                (transaction_id, analyst_id, action, previous_decision, new_decision, note, created_at)
            VALUES ($1, $2, $3, $4, $5, $6, $7)
            """,
            transaction_id,
            body.analyst_id,
            body.action,
            previous_decision,
            body.new_decision,
            body.note,
            datetime.now(timezone.utc),
        )

        # Optionally update the decision
        if body.new_decision and body.new_decision != previous_decision:
            await conn.execute(
                "UPDATE fraud_results SET decision = $1 WHERE transaction_id = $2",
                body.new_decision, transaction_id,
            )

    return {
        "status": "recorded",
        "transaction_id": transaction_id,
        "action": body.action,
        "previous_decision": previous_decision,
        "new_decision": body.new_decision or previous_decision,
    }


# ─── Audit Log ────────────────────────────────────────────────────────────────

@router.get("/audit_log", response_model=List[AuditEntry], summary="Query the audit log")
async def get_audit_log(
    transaction_id: Optional[str] = Query(None),
    analyst_id: Optional[str] = Query(None),
    limit: int = Query(50, ge=1, le=500),
    offset: int = Query(0, ge=0),
):
    conditions = []
    params: list = []
    idx = 1

    if transaction_id:
        conditions.append(f"transaction_id = ${idx}"); params.append(transaction_id); idx += 1
    if analyst_id:
        conditions.append(f"analyst_id = ${idx}"); params.append(analyst_id); idx += 1

    where = ("WHERE " + " AND ".join(conditions)) if conditions else ""
    params += [limit, offset]

    pool = await _get_pool()
    async with pool.acquire() as conn:
        rows = await conn.fetch(
            f"SELECT * FROM audit_log {where} ORDER BY created_at DESC LIMIT ${idx} OFFSET ${idx+1}",
            *params,
        )
    return [AuditEntry(**dict(r)) for r in rows]


# ─── User Risk Management ─────────────────────────────────────────────────────

@router.patch("/users/{user_id}/risk", summary="Update a user's risk tier")
async def update_user_risk(user_id: str, body: UserRiskUpdate):
    valid_tiers = {"standard", "elevated", "high"}
    if body.risk_tier not in valid_tiers:
        raise HTTPException(400, detail=f"risk_tier must be one of {valid_tiers}")

    pool = await _get_pool()
    async with pool.acquire() as conn:
        row = await conn.fetchrow(
            """
            INSERT INTO users (user_id, risk_tier, is_flagged, notes)
            VALUES ($1, $2, $3, $4)
            ON CONFLICT (user_id) DO UPDATE SET
                risk_tier  = EXCLUDED.risk_tier,
                is_flagged = COALESCE(EXCLUDED.is_flagged, users.is_flagged),
                notes      = COALESCE(EXCLUDED.notes, users.notes)
            RETURNING user_id, risk_tier, is_flagged, notes
            """,
            user_id,
            body.risk_tier,
            body.is_flagged,
            body.notes,
        )
    return dict(row)