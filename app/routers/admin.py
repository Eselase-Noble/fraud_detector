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

router = APIRouter(prefix="/admin", tags=["Admin"])


# ─── Models ───────────────────────────────────────────────────────────────────

class IntegrationCreate(BaseModel):
    partner_name: str
    webhook_url: str
    notify_on: List[str] = ["BLOCK", "REVIEW"]

class IntegrationResponse(BaseModel):
    id: int
    partner_name: str
    webhook_url: str
    is_active: bool
    notify_on: List[str]
    created_at: datetime
    last_used_at: Optional[datetime] = None
    # api_key returned only at creation time, never again
    api_key: Optional[str] = None

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

    # Generate a secure API key — shown once, stored as a hash
    raw_key = secrets.token_hex(32)
    key_hash = hashlib.sha256(raw_key.encode()).hexdigest()

    pool = await _get_pool()
    async with pool.acquire() as conn:
        row = await conn.fetchrow(
            """
            INSERT INTO integrations (partner_name, webhook_url, api_key_hash, notify_on)
            VALUES ($1, $2, $3, $4)
            RETURNING id, partner_name, webhook_url, is_active, notify_on, created_at, last_used_at
            """,
            body.partner_name,
            body.webhook_url,
            key_hash,
            body.notify_on,
        )

    return IntegrationResponse(**dict(row), api_key=raw_key)


@router.get("/integrations", response_model=List[IntegrationResponse],
            summary="List all registered integrations")
async def list_integrations():
    pool = await _get_pool()
    async with pool.acquire() as conn:
        rows = await conn.fetch(
            "SELECT id, partner_name, webhook_url, is_active, notify_on, created_at, last_used_at "
            "FROM integrations ORDER BY created_at DESC"
        )
    return [IntegrationResponse(**dict(r)) for r in rows]


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