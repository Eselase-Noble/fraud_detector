"""
analytics.py
------------
Analytics & reporting endpoints for the fraud detection dashboard.

Key improvements over previous version:
  - Single DB fetch per request (was fetching up to 5× on /dashboard)
  - _filter_txns() shared helper — one place to apply cutoff + to_utc
  - /dashboard fetches once, passes data to each aggregator directly
  - Removed __import__("asyncio") hack
  - Removed debug print() statements
"""
from __future__ import annotations

import asyncio
from collections import Counter, defaultdict
from datetime import datetime, timedelta, timezone
from typing import List, Optional

from fastapi import APIRouter, Query
from pydantic import BaseModel

from app.database import get_all_transactions
from app.models import Transaction
from app.utils import to_utc

router = APIRouter(tags=["Analytics"])


# ─── Response Models ──────────────────────────────────────────────────────────

class FraudStats(BaseModel):
    total_transactions: int
    blocked: int
    reviewed: int
    allowed: int
    fraud_rate: float
    review_rate: float
    total_flagged_amount: float
    avg_flagged_amount: float

class TimeSeries(BaseModel):
    date: str
    total: int
    blocked: int
    reviewed: int
    allowed: int
    total_amount: float

class LocationRisk(BaseModel):
    location: str
    transaction_count: int
    blocked_count: int
    total_amount: float
    risk_score: float

class TopUser(BaseModel):
    user_id: str
    transaction_count: int
    blocked_count: int
    total_amount: float
    risk_score: float

class SignalFrequency(BaseModel):
    signal: str
    count: int
    pct: float

class DashboardSummary(BaseModel):
    stats: FraudStats
    recent_timeseries: List[TimeSeries]
    top_risky_users: List[TopUser]
    location_breakdown: List[LocationRisk]
    signal_frequency: List[SignalFrequency]


# ─── Shared Helpers ───────────────────────────────────────────────────────────

def _safe_rate(num: int, denom: int) -> float:
    return round(num / denom, 4) if denom else 0.0


def _cutoff(days: int) -> datetime:
    """UTC-aware cutoff datetime for the given lookback window."""
    return datetime.now(timezone.utc) - timedelta(days=days)


def _filter_txns(txns: List[Transaction], days: int) -> List[Transaction]:
    """
    Return only transactions within the lookback window.
    Uses to_utc() so naive DB timestamps never cause a TypeError.
    """
    cutoff = _cutoff(days)
    return [t for t in txns if t.timestamp and to_utc(t.timestamp) >= cutoff]


# ─── Pure Aggregators (no DB calls — accept pre-filtered list) ────────────────

def _compute_stats(txns: List[Transaction]) -> FraudStats:
    total    = len(txns)
    blocked  = sum(1 for t in txns if getattr(t, "decision", None) == "BLOCK")
    reviewed = sum(1 for t in txns if getattr(t, "decision", None) == "REVIEW")
    allowed  = total - blocked - reviewed

    flagged_amounts = [
        t.amount for t in txns
        if getattr(t, "decision", None) in ("BLOCK", "REVIEW")
    ]
    total_flagged = sum(flagged_amounts)
    avg_flagged   = total_flagged / len(flagged_amounts) if flagged_amounts else 0.0

    return FraudStats(
        total_transactions=total,
        blocked=blocked,
        reviewed=reviewed,
        allowed=allowed,
        fraud_rate=_safe_rate(blocked, total),
        review_rate=_safe_rate(reviewed, total),
        total_flagged_amount=round(total_flagged, 2),
        avg_flagged_amount=round(avg_flagged, 2),
    )


def _compute_timeseries(txns: List[Transaction]) -> List[TimeSeries]:
    buckets: dict[str, dict] = defaultdict(lambda: {
        "total": 0, "blocked": 0, "reviewed": 0, "allowed": 0, "total_amount": 0.0
    })
    for t in txns:
        day_key  = to_utc(t.timestamp).strftime("%Y-%m-%d")
        b        = buckets[day_key]
        decision = getattr(t, "decision", None) or "ALLOW"
        b["total"]        += 1
        b["total_amount"] += float(t.amount)
        if decision == "BLOCK":
            b["blocked"] += 1
        elif decision == "REVIEW":
            b["reviewed"] += 1
        else:
            b["allowed"] += 1

    return [
        TimeSeries(date=date, **data)
        for date, data in sorted(buckets.items())
    ]


def _compute_top_users(txns: List[Transaction], limit: int = 10) -> List[TopUser]:
    user_data: dict[str, dict] = defaultdict(lambda: {
        "transaction_count": 0, "blocked_count": 0, "total_amount": 0.0
    })
    for t in txns:
        d = user_data[t.user_id]
        d["transaction_count"] += 1
        d["total_amount"]      += float(t.amount)
        if getattr(t, "decision", None) == "BLOCK":
            d["blocked_count"] += 1

    results = [
        TopUser(
            user_id=uid,
            risk_score=_safe_rate(d["blocked_count"], d["transaction_count"]),
            **d,
        )
        for uid, d in user_data.items()
    ]
    results.sort(key=lambda x: x.risk_score, reverse=True)
    return results[:limit]


def _compute_locations(txns: List[Transaction], limit: int = 10) -> List[LocationRisk]:
    loc_data: dict[str, dict] = defaultdict(lambda: {
        "transaction_count": 0, "blocked_count": 0, "total_amount": 0.0
    })
    for t in txns:
        loc = t.location or "Unknown"
        d   = loc_data[loc]
        d["transaction_count"] += 1
        d["total_amount"]      += float(t.amount)
        if getattr(t, "decision", None) == "BLOCK":
            d["blocked_count"] += 1

    results = [
        LocationRisk(
            location=loc,
            risk_score=_safe_rate(d["blocked_count"], d["transaction_count"]),
            **d,
        )
        for loc, d in loc_data.items()
    ]
    results.sort(key=lambda x: x.risk_score, reverse=True)
    return results[:limit]


def _compute_signals(txns: List[Transaction], limit: int = 20) -> List[SignalFrequency]:
    counter: Counter = Counter()
    for t in txns:
        for signal in (getattr(t, "signals", None) or []):
            counter[signal] += 1

    total = sum(counter.values()) or 1
    return [
        SignalFrequency(signal=sig, count=cnt, pct=round(cnt / total * 100, 2))
        for sig, cnt in counter.most_common(limit)
    ]


# ─── Endpoints ────────────────────────────────────────────────────────────────

@router.get("/stats", response_model=FraudStats, summary="Overall fraud statistics")
async def fraud_stats(days: int = Query(30, ge=1, le=365)):
    txns = _filter_txns(await get_all_transactions(), days)
    return _compute_stats(txns)


@router.get("/timeseries", response_model=List[TimeSeries], summary="Daily transaction breakdown")
async def timeseries(days: int = Query(30, ge=1, le=365)):
    txns = _filter_txns(await get_all_transactions(), days)
    return _compute_timeseries(txns)


@router.get("/top_users", response_model=List[TopUser], summary="Users with the highest fraud risk")
async def top_users(
    limit: int = Query(10, ge=1, le=100),
    days:  int = Query(30, ge=1, le=365),
):
    txns = _filter_txns(await get_all_transactions(), days)
    return _compute_top_users(txns, limit=limit)


@router.get("/locations", response_model=List[LocationRisk], summary="Geographic fraud breakdown")
async def location_risk(days: int = Query(30, ge=1, le=365)):
    txns = _filter_txns(await get_all_transactions(), days)
    return _compute_locations(txns)


@router.get("/signals", response_model=List[SignalFrequency], summary="Most common fraud signals")
async def signal_frequency(days: int = Query(30, ge=1, le=365)):
    txns = _filter_txns(await get_all_transactions(), days)
    return _compute_signals(txns)


@router.get("/dashboard", response_model=DashboardSummary, summary="Full dashboard data in one call")
async def dashboard(days: int = Query(30, ge=1, le=90)):
    """
    Fetches transactions ONCE, then runs all five aggregators in parallel
    against the same in-memory list. No redundant DB queries.
    """
    txns = _filter_txns(await get_all_transactions(limit=10_000), days)

    stats, ts, users, locs, sigs = await asyncio.gather(
        asyncio.to_thread(_compute_stats,      txns),
        asyncio.to_thread(_compute_timeseries, txns),
        asyncio.to_thread(_compute_top_users,  txns, 10),
        asyncio.to_thread(_compute_locations,  txns, 10),
        asyncio.to_thread(_compute_signals,    txns, 20),
    )

    return DashboardSummary(
        stats=stats,
        recent_timeseries=ts[-14:],
        top_risky_users=users,
        location_breakdown=locs,
        signal_frequency=sigs,
    )