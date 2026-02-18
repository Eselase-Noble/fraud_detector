"""
services/webhook.py
--------------------
Delivers real-time fraud decisions to registered bank/fintech partners
via HTTP webhooks. Called as a background task after every detection.

Features:
  - HMAC-SHA256 request signing (partners verify authenticity)
  - Exponential backoff retry (3 attempts)
  - Delivery logged to audit_log
  - Partner filter: only notify on decisions the partner opted into
"""
from __future__ import annotations

import hashlib
import hmac
import json
import logging
import time
from datetime import datetime, timezone

import httpx

from app.models import FraudResult

logger = logging.getLogger(__name__)

MAX_RETRIES = 3
RETRY_DELAYS = [1, 3, 8]   # seconds between retries
TIMEOUT = 10                # seconds per request


async def notify_partners(result: FraudResult) -> None:
    """
    Fetch all active integrations from DB and POST the fraud result
    to each partner whose notify_on list includes this decision.
    """
    from app.database import _get_pool  # avoid circular import at module load

    pool = await _get_pool()
    async with pool.acquire() as conn:
        rows = await conn.fetch(
            """
            SELECT id, partner_name, webhook_url, api_key_hash, notify_on
            FROM integrations
            WHERE is_active = TRUE
            """,
        )

    if not rows:
        return

    payload = _build_payload(result)

    for row in rows:
        notify_on: list[str] = row["notify_on"] or ["BLOCK", "REVIEW"]
        if result.decision not in notify_on:
            continue

        await _deliver(
            integration_id=row["id"],
            partner_name=row["partner_name"],
            webhook_url=row["webhook_url"],
            api_key_hash=row["api_key_hash"],
            payload=payload,
            result=result,
        )


def _build_payload(result: FraudResult) -> dict:
    return {
        "event":          "fraud_decision",
        "transaction_id": result.transaction_id,
        "decision":       result.decision,
        "score":          result.score,
        "signals":        result.signals,
        "processed_at":   result.processed_at.isoformat(),
    }


def _sign_payload(payload_bytes: bytes, api_key_hash: str) -> str:
    """HMAC-SHA256 signature partners use to verify the request origin."""
    return hmac.new(
        api_key_hash.encode(),
        payload_bytes,
        hashlib.sha256,
    ).hexdigest()


async def _deliver(
    integration_id: int,
    partner_name: str,
    webhook_url: str,
    api_key_hash: str,
    payload: dict,
    result: FraudResult,
) -> None:
    payload_bytes = json.dumps(payload, default=str).encode()
    signature = _sign_payload(payload_bytes, api_key_hash)

    headers = {
        "Content-Type":       "application/json",
        "X-Sentinel-Sig":     signature,
        "X-Sentinel-Version": "2",
    }

    success = False
    status_code = None

    async with httpx.AsyncClient(timeout=TIMEOUT) as client:
        for attempt, delay in enumerate(RETRY_DELAYS, start=1):
            try:
                resp = await client.post(webhook_url, content=payload_bytes, headers=headers)
                status_code = resp.status_code

                if resp.is_success:
                    logger.info(
                        "Webhook delivered to %s (attempt %d) — %d",
                        partner_name, attempt, status_code,
                    )
                    success = True
                    break
                else:
                    logger.warning(
                        "Webhook to %s returned %d on attempt %d",
                        partner_name, status_code, attempt,
                    )

            except httpx.RequestError as e:
                logger.warning("Webhook to %s failed (attempt %d): %s", partner_name, attempt, e)

            if attempt < MAX_RETRIES:
                time.sleep(delay)

    await _log_delivery(
        integration_id=integration_id,
        transaction_id=result.transaction_id,
        success=success,
        status_code=status_code,
        partner_name=partner_name,
    )

    if success:
        await _update_last_used(integration_id)


async def _log_delivery(
    integration_id: int,
    transaction_id: str,
    success: bool,
    status_code: int | None,
    partner_name: str,
) -> None:
    from app.database import _get_pool
    pool = await _get_pool()
    async with pool.acquire() as conn:
        await conn.execute(
            """
            INSERT INTO audit_log (transaction_id, action, note, created_at)
            VALUES ($1, $2, $3, $4)
            """,
            transaction_id,
            "WEBHOOK_DELIVERED" if success else "WEBHOOK_FAILED",
            f"Partner: {partner_name} | HTTP {status_code or 'N/A'}",
            datetime.now(timezone.utc),
        )


async def _update_last_used(integration_id: int) -> None:
    from app.database import _get_pool
    pool = await _get_pool()
    async with pool.acquire() as conn:
        await conn.execute(
            "UPDATE integrations SET last_used_at = NOW() WHERE id = $1",
            integration_id,
        )