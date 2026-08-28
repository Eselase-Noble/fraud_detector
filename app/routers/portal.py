"""
routers/portal.py
-----------------
Self-service portal for partner financial institutions.

Two credentials, one institution:
  - Humans sign in with email + password  → receive a session token (Bearer).
  - Their systems authenticate to detection with the API key (X-API-Key).

Portal endpoints accept EITHER a Bearer session token OR the API key, so the
same views work whether a person or a script is calling. The raw API key is
never stored — we match on its SHA-256 hash.
"""
from __future__ import annotations

import hashlib
from datetime import datetime, timezone
from typing import List, Optional

from fastapi import APIRouter, Header, HTTPException
from pydantic import BaseModel

from app.database import _get_pool
from app.portal_auth import issue_token, verify_password, verify_token
from app.routers.admin import IntegrationResponse, _INTEGRATION_COLS

router = APIRouter(tags=["Partner Portal"])


class LoginRequest(BaseModel):
    email: str
    password: str


class ConfigUpdate(BaseModel):
    webhook_url: Optional[str] = None
    notify_on: Optional[List[str]] = None


class PortalProfile(BaseModel):
    integration: IntegrationResponse
    usage: dict


class LoginResponse(BaseModel):
    token: str
    profile: PortalProfile


async def _load_active(conn, integration_id: int):
    row = await conn.fetchrow(
        f"SELECT {_INTEGRATION_COLS} FROM integrations WHERE id = $1", integration_id
    )
    if not row:
        raise HTTPException(401, detail="Account not found.")
    if not row["is_active"]:
        raise HTTPException(403, detail="This integration is suspended. Contact Sentinel support.")
    return row


async def _resolve(authorization: Optional[str], x_api_key: Optional[str]):
    """Resolve the calling institution from a Bearer session token or an API key."""
    pool = await _get_pool()
    async with pool.acquire() as conn:
        # Human session token
        if authorization and authorization.lower().startswith("bearer "):
            token = authorization[7:].strip()
            integration_id = verify_token(token, "partner")
            if integration_id is None:
                raise HTTPException(401, detail="Session expired. Please sign in again.")
            row = await _load_active(conn, integration_id)
        # Machine API key
        elif x_api_key and x_api_key.strip():
            key_hash = hashlib.sha256(x_api_key.strip().encode()).hexdigest()
            row = await conn.fetchrow(
                f"SELECT {_INTEGRATION_COLS} FROM integrations WHERE api_key_hash = $1", key_hash
            )
            if not row:
                raise HTTPException(401, detail="Invalid API key.")
            if not row["is_active"]:
                raise HTTPException(403, detail="This integration is suspended.")
        else:
            raise HTTPException(401, detail="Sign in to the portal or provide an API key.")

        await conn.execute(
            "UPDATE integrations SET last_used_at = $1 WHERE id = $2",
            datetime.now(timezone.utc), row["id"],
        )
    return row


async def _usage() -> dict:
    pool = await _get_pool()
    async with pool.acquire() as conn:
        stats = await conn.fetchrow(
            """
            SELECT COUNT(*)                                    AS scored,
                   COUNT(*) FILTER (WHERE decision = 'BLOCK')  AS blocked,
                   COUNT(*) FILTER (WHERE decision = 'REVIEW') AS reviewed
            FROM fraud_results
            """
        )
    return {
        "scored": stats["scored"] if stats else 0,
        "blocked": stats["blocked"] if stats else 0,
        "reviewed": stats["reviewed"] if stats else 0,
    }


@router.post("/login", response_model=LoginResponse,
             summary="Sign in to the partner portal with email + password")
async def portal_login(body: LoginRequest):
    email = body.email.strip().lower()
    pool = await _get_pool()
    async with pool.acquire() as conn:
        row = await conn.fetchrow(
            f"SELECT {_INTEGRATION_COLS}, portal_password_hash FROM integrations "
            f"WHERE portal_email = $1", email,
        )
    if not row or not verify_password(body.password, row["portal_password_hash"]):
        raise HTTPException(401, detail="Incorrect email or password.")
    if not row["is_active"]:
        raise HTTPException(403, detail="This account is suspended. Contact Sentinel support.")

    token = issue_token("partner", row["id"])
    data = {k: v for k, v in dict(row).items() if k != "portal_password_hash"}
    profile = PortalProfile(integration=IntegrationResponse(**data), usage=await _usage())
    return LoginResponse(token=token, profile=profile)


@router.post("/session", response_model=PortalProfile,
             summary="Fetch the signed-in institution's profile + usage")
async def portal_session(
    authorization: Optional[str] = Header(None),
    x_api_key: Optional[str] = Header(None, alias="X-API-Key"),
):
    row = await _resolve(authorization, x_api_key)
    return PortalProfile(integration=IntegrationResponse(**dict(row)), usage=await _usage())


@router.patch("/config", response_model=IntegrationResponse,
              summary="Update your own webhook URL and notification events")
async def portal_update_config(
    body: ConfigUpdate,
    authorization: Optional[str] = Header(None),
    x_api_key: Optional[str] = Header(None, alias="X-API-Key"),
):
    row = await _resolve(authorization, x_api_key)

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

    params.append(row["id"])
    pool = await _get_pool()
    async with pool.acquire() as conn:
        updated = await conn.fetchrow(
            f"UPDATE integrations SET {', '.join(sets)} WHERE id = ${idx} RETURNING {_INTEGRATION_COLS}",
            *params,
        )
    return IntegrationResponse(**dict(updated))
