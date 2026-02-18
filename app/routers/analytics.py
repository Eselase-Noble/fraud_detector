"""
analytics.py
------------
Analytics & reporting endpoints for the fraud detection dashboard.
Provides rich aggregated insights over transaction data.
"""
from __future__ import annotations

from collections import Counter, defaultdict
from datetime import datetime, timedelta, timezone
from typing import List, Optional

from fastapi import APIRouter, Query
from pydantic import BaseModel

from app.database import get_all_transactions

router = APIRouter( tags=["Analytics"])


# ─── Response Models ──────────────────────────────────────────────────────────

class FraudStats(BaseModel):
    total_transactions: int
    blocked: int
    reviewed: int
    allowed: int
    fraud_rate: float          # BLOCK / total
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


# ─── Helpers ──────────────────────────────────────────────────────────────────

def _safe_rate(num: int, denom: int) -> float:
    return round(num / denom, 4) if denom else 0.0


# ─── Endpoints ────────────────────────────────────────────────────────────────

@router.get("/stats", response_model=FraudStats, summary="Overall fraud statistics")
async def fraud_stats(
    days: int = Query(30, ge=1, le=365, description="Lookback period in days"),
):
    txns = await get_all_transactions()
    cutoff = datetime.now(timezone.utc) - timedelta(days=days)
    # txns = [t for t in txns if t.timestamp and t.timestamp >= cutoff]
    txns = [
        t for t in txns
        if t.timestamp and t.timestamp.replace(tzinfo=timezone.utc) >= cutoff
    ]
    total = len(txns)
    blocked = sum(1 for t in txns if getattr(t, "decision", None) == "BLOCK")
    reviewed = sum(1 for t in txns if getattr(t, "decision", None) == "REVIEW")
    allowed = total - blocked - reviewed

    flagged = [t for t in txns if getattr(t, "decision", None) in ("BLOCK", "REVIEW")]
    flagged_amounts = [t.amount for t in flagged]
    total_flagged_amt = sum(flagged_amounts)
    avg_flagged_amt = total_flagged_amt / len(flagged_amounts) if flagged_amounts else 0.0

    return FraudStats(
        total_transactions=total,
        blocked=blocked,
        reviewed=reviewed,
        allowed=allowed,
        fraud_rate=_safe_rate(blocked, total),
        review_rate=_safe_rate(reviewed, total),
        total_flagged_amount=round(total_flagged_amt, 2),
        avg_flagged_amount=round(avg_flagged_amt, 2),
    )


@router.get("/timeseries", response_model=List[TimeSeries], summary="Daily transaction breakdown")
async def timeseries(
    days: int = Query(30, ge=1, le=365),
):
    txns = await get_all_transactions()
    cutoff = datetime.now(timezone.utc) - timedelta(days=days)
    txns = [t for t in txns if t.timestamp and t.timestamp >= cutoff]

    buckets: dict[str, dict] = defaultdict(lambda: {
        "total": 0, "blocked": 0, "reviewed": 0, "allowed": 0, "total_amount": 0.0
    })

    for t in txns:
        day_key = t.timestamp.strftime("%Y-%m-%d")
        b = buckets[day_key]
        b["total"] += 1
        b["total_amount"] += t.amount
        decision = getattr(t, "decision", "ALLOW")
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


@router.get("/top_users", response_model=List[TopUser], summary="Users with the highest fraud risk")
async def top_users(
    limit: int = Query(10, ge=1, le=100),
    days: int = Query(30, ge=1, le=365),
):
    txns = await get_all_transactions()
    cutoff = datetime.now(timezone.utc) - timedelta(days=days)
    txns = [t for t in txns if t.timestamp and t.timestamp >= cutoff]

    user_data: dict[str, dict] = defaultdict(lambda: {
        "transaction_count": 0, "blocked_count": 0, "total_amount": 0.0
    })

    for t in txns:
        uid = t.user_id
        user_data[uid]["transaction_count"] += 1
        user_data[uid]["total_amount"] += t.amount
        if getattr(t, "decision", None) == "BLOCK":
            user_data[uid]["blocked_count"] += 1

    results = []
    for uid, d in user_data.items():
        risk = _safe_rate(d["blocked_count"], d["transaction_count"])
        results.append(TopUser(user_id=uid, risk_score=risk, **d))

    results.sort(key=lambda x: x.risk_score, reverse=True)
    return results[:limit]


@router.get("/locations", response_model=List[LocationRisk], summary="Geographic fraud breakdown")
async def location_risk(days: int = Query(30, ge=1, le=365)):
    txns = await get_all_transactions()
    cutoff = datetime.now(timezone.utc) - timedelta(days=days)
    txns = [t for t in txns if t.timestamp and t.timestamp >= cutoff]

    loc_data: dict[str, dict] = defaultdict(lambda: {
        "transaction_count": 0, "blocked_count": 0, "total_amount": 0.0
    })

    for t in txns:
        loc = t.location or "Unknown"
        loc_data[loc]["transaction_count"] += 1
        loc_data[loc]["total_amount"] += t.amount
        if getattr(t, "decision", None) == "BLOCK":
            loc_data[loc]["blocked_count"] += 1

    results = []
    for loc, d in loc_data.items():
        risk = _safe_rate(d["blocked_count"], d["transaction_count"])
        results.append(LocationRisk(location=loc, risk_score=risk, **d))

    results.sort(key=lambda x: x.risk_score, reverse=True)
    return results


@router.get("/signals", response_model=List[SignalFrequency], summary="Most common fraud signals")
async def signal_frequency(days: int = Query(30, ge=1, le=365)):
    txns = await get_all_transactions()
    cutoff = datetime.now(timezone.utc) - timedelta(days=days)
    txns = [t for t in txns if t.timestamp and t.timestamp >= cutoff]

    counter: Counter = Counter()
    for t in txns:
        signals = getattr(t, "signals", []) or []
        for s in signals:
            counter[s] += 1

    total = sum(counter.values()) or 1
    return [
        SignalFrequency(signal=sig, count=cnt, pct=round(cnt / total * 100, 2))
        for sig, cnt in counter.most_common(20)
    ]


@router.get("/dashboard", response_model=DashboardSummary, summary="Full dashboard data in one call")
async def dashboard(days: int = Query(30, ge=1, le=90)):
    """Single endpoint that returns all data needed for the analytics dashboard."""
    stats, ts, users, locs, sigs = await __import__("asyncio").gather(
        fraud_stats(days=days),
        timeseries(days=days),
        top_users(limit=10, days=days),
        location_risk(days=days),
        signal_frequency(days=days),
    )
    return DashboardSummary(
        stats=stats,
        recent_timeseries=ts[-14:],  # Last 14 days of time series
        top_risky_users=users,
        location_breakdown=locs[:10],
        signal_frequency=sigs,
    )