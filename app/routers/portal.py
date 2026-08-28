"""
routers/portal.py
-----------------
Self-service portal for partner financial institutions.

Unlike /admin (operated by Sentinel staff), these endpoints are authenticated by
the institution's own API key. A partner signs in with their key and can:
  - view their integration profile (type, connection method, status, endpoint)
  - update their webhook URL and notification preferences
  - see how much of their traffic Sentinel has scored

The raw key is never stored — we match on its SHA-256 hash, exactly as issued.
"""
from __future__ import annotations

import hashlib
from datetime import datetime, timezone
from typing import List, Optional

from fastapi import APIRouter, Header, HTTPException
from pydantic import BaseModel

from app.database import _get_pool
from app.routers.admin import IntegrationResponse, _INTEGRATION_COLS

router = APIRouter(tags=["Partner Portal"])


class ConfigUpdate(BaseModel):
    webhook_url: Optional[str] = None
    notify_on: Optional[List[str]] = None


class PortalProfile(BaseModel):
    integration: IntegrationResponse
    usage: dict


async def _authenticate(api_key: str):
    """Resolve an active integration from its API key, stamping last_used_at."""
    if not api_key or not api_key.strip():
        raise HTTPException(401, detail="Provide your API key via the X-API-Key header.")
    key_hash = hashlib.sha256(api_key.strip().encode()).hexdigest()
    pool = await _get_pool()
    async with pool.acquire() as conn:
        row = await conn.fetchrow(
            f"SELECT {_INTEGRATION_COLS} FROM integrations WHERE api_key_hash = $1", key_hash
        )
        if not row:
            raise HTTPException(401, detail="Invalid API key.")
        if not row["is_active"]:
            raise HTTPException(403, detail="This integration is suspended. Contact Sentinel support.")
        await conn.execute(
            "UPDATE integrations SET last_used_at = $1 WHERE id = $2",
            datetime.now(timezone.utc), row["id"],
        )
    return row


@router.post("/session", response_model=PortalProfile,
             summary="Sign in to the partner portal with an API key")
async def portal_session(x_api_key: str = Header(..., alias="X-API-Key")):
    row = await _authenticate(x_api_key)
    pool = await _get_pool()
    async with pool.acquire() as conn:
        # Best-effort usage snapshot across all scored traffic.
        stats = await conn.fetchrow(
            """
            SELECT
                COUNT(*)                                        AS scored,
                COUNT(*) FILTER (WHERE decision = 'BLOCK')      AS blocked,
                COUNT(*) FILTER (WHERE decision = 'REVIEW')     AS reviewed
            FROM fraud_results
            """
        )
    usage = {
        "scored": stats["scored"] if stats else 0,
        "blocked": stats["blocked"] if stats else 0,
        "reviewed": stats["reviewed"] if stats else 0,
    }
    return PortalProfile(integration=IntegrationResponse(**dict(row)), usage=usage)


@router.patch("/config", response_model=IntegrationResponse,
              summary="Update your own webhook URL and notification events")
async def portal_update_config(body: ConfigUpdate, x_api_key: str = Header(..., alias="X-API-Key")):
    row = await _authenticate(x_api_key)

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
