"""
fraud_detector.py  (updated for bank-grade integration)
---------------------------------------------------------
Added: user risk_tier lookup from users table — elevated/high users
get a higher base score before signals are evaluated.
"""
from __future__ import annotations

import os
import asyncio
from datetime import datetime, timezone
from typing import Optional
from dotenv import load_dotenv

from langchain_openai import ChatOpenAI
from langchain_classic.chains.retrieval_qa.base import RetrievalQA
from langchain_community.tools.tavily_search import TavilySearchResults

from app.models import Transaction, FraudResult
from app.vector_store import load_vector_store
from app.external import load_risk_data

load_dotenv()

OPENAI_API_KEY = os.getenv("OPENAI_API_KEY")
TAVILY_API_KEY = os.getenv("TAVILY_API_KEY")

if not OPENAI_API_KEY:
    raise ValueError("OPENAI_API_KEY not set in environment!")

llm = ChatOpenAI(model="gpt-4.1", temperature=0)
vector_store = load_vector_store()

_tavily: Optional[TavilySearchResults] = None
if TAVILY_API_KEY:
    _tavily = TavilySearchResults(max_results=3, tavily_api_key=TAVILY_API_KEY)

RISK_TIER_BASE = {
    "standard": 0.05,
    "elevated": 0.15,
    "high":     0.30,
}


async def _get_user_risk_tier(user_id: str) -> str:
    try:
        from app.database import _get_pool
        pool = await _get_pool()
        async with pool.acquire() as conn:
            row = await conn.fetchrow(
                "SELECT risk_tier, is_flagged FROM users WHERE user_id = $1", user_id
            )
        if row:
            if row["is_flagged"]:
                return "high"
            return row["risk_tier"] or "standard"
    except Exception:
        pass
    return "standard"


def _to_utc(dt: datetime) -> datetime:
    """Normalise to UTC-aware. Naive datetimes are assumed to be UTC."""
    if dt.tzinfo is None:
        return dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc)


def _hours_between(a: datetime, b: datetime) -> float:
    """Hours between two datetimes, safe for mixed naive/aware inputs."""
    return abs((_to_utc(a) - _to_utc(b)).total_seconds()) / 3600


def _velocity_signals(txn: Transaction, history: list[Transaction]) -> tuple[list[str], float]:
    signals: list[str] = []
    delta = 0.0
    if not history:
        return signals, delta
    now = txn.timestamp or datetime.now(timezone.utc)
    recent_1h = [h for h in history if _hours_between(now, h.timestamp) <= 1]
    if len(recent_1h) >= 5:
        signals.append(f"High velocity: {len(recent_1h)} transactions in last hour")
        delta += 0.25
    recent_24h = [h for h in history if _hours_between(now, h.timestamp) <= 24]
    if len(recent_24h) >= 20:
        signals.append(f"Very high daily volume: {len(recent_24h)} transactions in 24h")
        delta += 0.15
    if len(history) >= 3:
        avg_amount = sum(h.amount for h in history[:10]) / min(len(history), 10)
        if txn.amount > avg_amount * 3:
            signals.append(f"Amount spike: {txn.amount:.2f} vs avg {avg_amount:.2f}")
            delta += 0.2
    return signals, delta


def _device_signals(txn: Transaction, history: list[Transaction]) -> tuple[list[str], float]:
    signals: list[str] = []
    delta = 0.0
    if not history or not txn.device_id:
        return signals, delta
    known_devices = {h.device_id for h in history if h.device_id}
    if txn.device_id not in known_devices:
        signals.append("New/unrecognized device")
        delta += 0.15
    return signals, delta


async def _fetch_online_intelligence(txn: Transaction) -> str:
    if not _tavily or not txn.location:
        return ""
    query = f"financial fraud risk alerts {txn.location} {datetime.now().year}"
    try:
        results = await asyncio.to_thread(_tavily.invoke, query)
        if isinstance(results, list):
            return "\n".join(r.get("content", "") for r in results[:3])
    except Exception:
        pass
    return ""


async def detect_fraud(txn: Transaction, history: list[Transaction]) -> FraudResult:
    risks = load_risk_data()
    signals: list[str] = []

    risk_tier = await _get_user_risk_tier(txn.user_id)
    score = RISK_TIER_BASE.get(risk_tier, 0.05)
    if risk_tier != "standard":
        signals.append(f"User risk tier: {risk_tier}")

    if txn.amount > 10_000:
        signals.append(f"Very high amount: ${txn.amount:,.2f}")
        score += 0.45
    elif txn.amount > 1_000:
        signals.append(f"High amount: ${txn.amount:,.2f}")
        score += 0.2
    elif txn.amount > 500:
        signals.append(f"Elevated amount: ${txn.amount:,.2f}")
        score += 0.05

    if history:
        last_location = history[0].location
        if txn.location and last_location and txn.location != last_location:
            signals.append(f"Location change: {last_location} -> {txn.location}")
            score += 0.2
            if history[0].timestamp:
                hours = _hours_between(
                    txn.timestamp or datetime.now(timezone.utc), history[0].timestamp
                )
                if hours < 2:
                    signals.append("Impossible travel: location changed within 2 hours")
                    score += 0.25

    v_signals, v_delta = _velocity_signals(txn, history)
    signals.extend(v_signals)
    score += v_delta

    d_signals, d_delta = _device_signals(txn, history)
    signals.extend(d_signals)
    score += d_delta

    for r in risks:
        if r.get("country") == txn.location:
            level = r.get("risk_level", "")
            if level == "high":
                signals.append(f"High-risk jurisdiction: {txn.location}")
                score += 0.3
            elif level == "medium":
                signals.append(f"Medium-risk jurisdiction: {txn.location}")
                score += 0.1

    HIGH_RISK_CATEGORIES = {"crypto", "gambling", "wire_transfer", "gift_cards", "forex"}
    if txn.merchant_category and txn.merchant_category.lower() in HIGH_RISK_CATEGORIES:
        signals.append(f"High-risk merchant category: {txn.merchant_category}")
        score += 0.2

    score = round(min(score, 1.0), 4)
    decision = "BLOCK" if score > 0.75 else "REVIEW" if score > 0.4 else "ALLOW"

    online_intel_task = asyncio.create_task(_fetch_online_intelligence(txn))

    history_context = [
        {"amount": h.amount, "location": h.location, "timestamp": h.timestamp.isoformat()}
        for h in history[:5]
    ]

    rag_prompt = f"""
You are a senior fraud detection analyst at a bank.

Transaction: {txn.model_dump()}
User Risk Tier: {risk_tier}
Recent History (last 5): {history_context}
Risk Signals: {signals}
Score: {score:.2f} | Decision: {decision}

Provide a clear 3-5 sentence explanation referencing specific signals.
Focus on what a fraud analyst needs to act on this case.
"""

    retriever = vector_store.as_retriever(search_kwargs={"k": 5})
    qa_chain = RetrievalQA.from_chain_type(llm=llm, retriever=retriever, return_source_documents=False)

    rag_task = asyncio.to_thread(qa_chain.invoke, rag_prompt)
    rag_result, online_intel = await asyncio.gather(rag_task, online_intel_task)

    reason = rag_result["result"] if isinstance(rag_result, dict) else str(rag_result)
    if online_intel:
        reason += f"\n\n**Live Threat Intelligence:** {online_intel[:500]}..."

    return FraudResult(
        transaction_id=txn.transaction_id,
        score=score,
        decision=decision,
        reason=reason,
        signals=signals,
    )