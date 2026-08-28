"""
routers/portal.py
-----------------
Self-service portal for partner financial institutions.

Each institution has multiple portal users (partner_users) who sign in with email
+ password and receive a "partner"-kind session token. Their systems authenticate
to detection with the institution API key (X-API-Key). Portal endpoints accept a
Bearer session token OR the API key; user-management is limited to admin users
(or the master API key). Everything is scoped to the caller's own integration.
"""
from __future__ import annotations

import hashlib
from datetime import datetime, timezone
from typing import List, Optional

from fastapi import APIRouter, Header, HTTPException
from pydantic import BaseModel

from app.database import (
    _get_pool, get_partner_transaction_rows, get_partner_transactions, get_partner_usage,
    get_user_history, save_fraud_result,
)
from app.fraud_detector import detect_fraud
from app.models import Transaction, FraudResult
from app.portal_auth import hash_password, issue_token, verify_password, verify_token
from app.routers.admin import IntegrationResponse, _INTEGRATION_COLS
from app.routers.analytics import (
    _compute_stats, _compute_timeseries, _compute_top_users,
    _compute_locations, _compute_signals, _filter_txns, DashboardSummary,
)

router = APIRouter(tags=["Partner Portal"])

_PU_COLS = "id, integration_id, email, name, role, is_active, created_at"
VALID_ROLES = {"admin", "analyst", "viewer"}


# ─── Models ───────────────────────────────────────────────────────────────────

class LoginRequest(BaseModel):
    email: str
    password: str


class ConfigUpdate(BaseModel):
    webhook_url: Optional[str] = None
    notify_on: Optional[List[str]] = None


class PartnerUser(BaseModel):
    id: int
    integration_id: int
    email: str
    name: Optional[str] = None
    role: str = "admin"
    is_active: bool = True
    created_at: datetime


class PortalProfile(BaseModel):
    integration: IntegrationResponse
    user: Optional[PartnerUser] = None
    usage: dict


class LoginResponse(BaseModel):
    token: str
    profile: PortalProfile


class UserCreate(BaseModel):
    email: str
    password: str
    name: Optional[str] = None
    role: str = "analyst"


class UserUpdate(BaseModel):
    name: Optional[str] = None
    role: Optional[str] = None
    is_active: Optional[bool] = None
    password: Optional[str] = None


# ─── Auth resolution ─────────────────────────────────────────────────────────

async def _resolve(authorization: Optional[str], x_api_key: Optional[str]):
    """Return (integration_row, current_user_or_None) for the caller."""
    pool = await _get_pool()
    async with pool.acquire() as conn:
        if authorization and authorization.lower().startswith("bearer "):
            user_id = verify_token(authorization[7:].strip(), "partner")
            if user_id is None:
                raise HTTPException(401, detail="Session expired. Please sign in again.")
            user = await conn.fetchrow(f"SELECT {_PU_COLS} FROM partner_users WHERE id = $1", user_id)
            if not user or not user["is_active"]:
                raise HTTPException(403, detail="Your access has been disabled.")
            integ = await conn.fetchrow(
                f"SELECT {_INTEGRATION_COLS} FROM integrations WHERE id = $1", user["integration_id"]
            )
            if not integ or not integ["is_active"]:
                raise HTTPException(403, detail="This institution is suspended. Contact Sentinel support.")
            await conn.execute("UPDATE integrations SET last_used_at = $1 WHERE id = $2",
                               datetime.now(timezone.utc), integ["id"])
            return integ, user
        elif x_api_key and x_api_key.strip():
            key_hash = hashlib.sha256(x_api_key.strip().encode()).hexdigest()
            integ = await conn.fetchrow(
                f"SELECT {_INTEGRATION_COLS} FROM integrations WHERE api_key_hash = $1", key_hash
            )
            if not integ:
                raise HTTPException(401, detail="Invalid API key.")
            if not integ["is_active"]:
                raise HTTPException(403, detail="This integration is suspended.")
            return integ, None
        raise HTTPException(401, detail="Sign in to the portal or provide an API key.")


def _require_admin(user):
    """Master API-key callers (user is None) and admins may mutate; others may not."""
    if user is not None and user["role"] != "admin":
        raise HTTPException(403, detail="Only admins can perform this action.")


async def _profile(integ, user) -> PortalProfile:
    usage = await get_partner_usage(integ["id"])
    return PortalProfile(
        integration=IntegrationResponse(**dict(integ)),
        user=PartnerUser(**dict(user)) if user else None,
        usage=usage,
    )


# ─── Auth ─────────────────────────────────────────────────────────────────────

@router.post("/login", response_model=LoginResponse, summary="Sign in to the partner portal")
async def portal_login(body: LoginRequest):
    email = body.email.strip().lower()
    pool = await _get_pool()
    async with pool.acquire() as conn:
        user = await conn.fetchrow(
            f"SELECT {_PU_COLS}, password_hash FROM partner_users WHERE email = $1", email
        )
        if not user or not verify_password(body.password, user["password_hash"]):
            raise HTTPException(401, detail="Incorrect email or password.")
        if not user["is_active"]:
            raise HTTPException(403, detail="Your access has been disabled.")
        integ = await conn.fetchrow(
            f"SELECT {_INTEGRATION_COLS} FROM integrations WHERE id = $1", user["integration_id"]
        )
        if not integ or not integ["is_active"]:
            raise HTTPException(403, detail="This institution is suspended. Contact Sentinel support.")
    token = issue_token("partner", user["id"])
    return LoginResponse(token=token, profile=await _profile(integ, user))


@router.post("/session", response_model=PortalProfile, summary="Current session profile + usage")
async def portal_session(authorization: Optional[str] = Header(None),
                         x_api_key: Optional[str] = Header(None, alias="X-API-Key")):
    integ, user = await _resolve(authorization, x_api_key)
    return await _profile(integ, user)


# ─── Config ───────────────────────────────────────────────────────────────────

@router.patch("/config", response_model=IntegrationResponse,
              summary="Update your webhook URL and notification events")
async def portal_update_config(body: ConfigUpdate, authorization: Optional[str] = Header(None),
                               x_api_key: Optional[str] = Header(None, alias="X-API-Key")):
    integ, user = await _resolve(authorization, x_api_key)
    _require_admin(user)

    sets, params, idx = [], [], 1
    if body.webhook_url is not None:
        sets.append(f"webhook_url = ${idx}"); params.append(body.webhook_url); idx += 1
    if body.notify_on is not None:
        invalid = set(body.notify_on) - {"ALLOW", "REVIEW", "BLOCK"}
        if invalid:
            raise HTTPException(400, detail=f"Invalid notify_on values: {invalid}")
        sets.append(f"notify_on = ${idx}"); params.append(body.notify_on); idx += 1
    if not sets:
        raise HTTPException(400, detail="Nothing to update.")
    params.append(integ["id"])
    pool = await _get_pool()
    async with pool.acquire() as conn:
        updated = await conn.fetchrow(
            f"UPDATE integrations SET {', '.join(sets)} WHERE id = ${idx} RETURNING {_INTEGRATION_COLS}",
            *params,
        )
    return IntegrationResponse(**dict(updated))


# ─── Transactions (scoped to the caller's institution) ───────────────────────

@router.get("/transactions", summary="List detected transactions for your institution")
async def portal_transactions(
    authorization: Optional[str] = Header(None),
    x_api_key: Optional[str] = Header(None, alias="X-API-Key"),
    decision: Optional[str] = None, search: Optional[str] = None,
    limit: int = 100, offset: int = 0,
):
    integ, _ = await _resolve(authorization, x_api_key)
    return await get_partner_transaction_rows(
        integ["id"], limit=min(limit, 500), offset=offset,
        decision=decision if decision in {"ALLOW", "REVIEW", "BLOCK"} else None,
        search=search,
    )


# ─── Partner detect (attributes the transaction to this institution) ─────────

@router.post("/detect", response_model=FraudResult, summary="Run a detection as this institution")
async def portal_detect(transaction: Transaction, authorization: Optional[str] = Header(None),
                        x_api_key: Optional[str] = Header(None, alias="X-API-Key")):
    integ, _ = await _resolve(authorization, x_api_key)
    history = await get_user_history(transaction.user_id)
    result = await detect_fraud(transaction, history)
    # Attribute to this partner so it lands in their transactions/analytics only.
    await save_fraud_result(result, transaction, integ["id"])
    return result


# ─── Partner analytics (real-time, scoped to this institution) ───────────────

@router.get("/analytics", response_model=DashboardSummary,
            summary="Real-time analytics scoped to your institution")
async def portal_analytics(authorization: Optional[str] = Header(None),
                           x_api_key: Optional[str] = Header(None, alias="X-API-Key"),
                           days: int = 30):
    integ, _ = await _resolve(authorization, x_api_key)
    days = max(1, min(days, 365))
    txns = _filter_txns(await get_partner_transactions(integ["id"], limit=10_000), days)
    return DashboardSummary(
        stats=_compute_stats(txns),
        recent_timeseries=_compute_timeseries(txns)[-14:],
        top_risky_users=_compute_top_users(txns, 8),
        location_breakdown=_compute_locations(txns, 10),
        signal_frequency=_compute_signals(txns, 12),
    )


# ─── Team (partner users) ─────────────────────────────────────────────────────

@router.get("/users", response_model=List[PartnerUser], summary="List your institution's portal users")
async def portal_list_users(authorization: Optional[str] = Header(None),
                            x_api_key: Optional[str] = Header(None, alias="X-API-Key")):
    integ, _ = await _resolve(authorization, x_api_key)
    pool = await _get_pool()
    async with pool.acquire() as conn:
        rows = await conn.fetch(
            f"SELECT {_PU_COLS} FROM partner_users WHERE integration_id = $1 ORDER BY created_at",
            integ["id"],
        )
    return [PartnerUser(**dict(r)) for r in rows]


@router.post("/users", response_model=PartnerUser, summary="Add a portal user")
async def portal_create_user(body: UserCreate, authorization: Optional[str] = Header(None),
                             x_api_key: Optional[str] = Header(None, alias="X-API-Key")):
    integ, user = await _resolve(authorization, x_api_key)
    _require_admin(user)
    role = body.role if body.role in VALID_ROLES else "analyst"
    pool = await _get_pool()
    async with pool.acquire() as conn:
        try:
            row = await conn.fetchrow(
                f"""INSERT INTO partner_users (integration_id, email, password_hash, name, role)
                    VALUES ($1, $2, $3, $4, $5) RETURNING {_PU_COLS}""",
                integ["id"], body.email.strip().lower(), hash_password(body.password),
                body.name, role,
            )
        except Exception:
            raise HTTPException(409, detail="That email is already in use.")
    return PartnerUser(**dict(row))


@router.patch("/users/{user_id}", response_model=PartnerUser, summary="Update a portal user")
async def portal_update_user(user_id: int, body: UserUpdate, authorization: Optional[str] = Header(None),
                             x_api_key: Optional[str] = Header(None, alias="X-API-Key")):
    integ, actor = await _resolve(authorization, x_api_key)
    _require_admin(actor)
    sets, params, idx = [], [], 1
    if body.name is not None:
        sets.append(f"name = ${idx}"); params.append(body.name); idx += 1
    if body.role is not None:
        if body.role not in VALID_ROLES:
            raise HTTPException(400, detail=f"role must be one of {sorted(VALID_ROLES)}")
        sets.append(f"role = ${idx}"); params.append(body.role); idx += 1
    if body.is_active is not None:
        sets.append(f"is_active = ${idx}"); params.append(body.is_active); idx += 1
    if body.password:
        sets.append(f"password_hash = ${idx}"); params.append(hash_password(body.password)); idx += 1
    if not sets:
        raise HTTPException(400, detail="Nothing to update.")
    params += [user_id, integ["id"]]
    pool = await _get_pool()
    async with pool.acquire() as conn:
        row = await conn.fetchrow(
            f"UPDATE partner_users SET {', '.join(sets)} "
            f"WHERE id = ${idx} AND integration_id = ${idx + 1} RETURNING {_PU_COLS}",
            *params,
        )
    if not row:
        raise HTTPException(404, detail="User not found.")
    return PartnerUser(**dict(row))


@router.delete("/users/{user_id}", summary="Remove a portal user")
async def portal_delete_user(user_id: int, authorization: Optional[str] = Header(None),
                             x_api_key: Optional[str] = Header(None, alias="X-API-Key")):
    integ, actor = await _resolve(authorization, x_api_key)
    _require_admin(actor)
    if actor is not None and actor["id"] == user_id:
        raise HTTPException(400, detail="You can't remove your own account.")
    pool = await _get_pool()
    async with pool.acquire() as conn:
        result = await conn.execute(
            "DELETE FROM partner_users WHERE id = $1 AND integration_id = $2", user_id, integ["id"]
        )
    if result == "DELETE 0":
        raise HTTPException(404, detail="User not found.")
    return {"status": "deleted", "id": user_id}
