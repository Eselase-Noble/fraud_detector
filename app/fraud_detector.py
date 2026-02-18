"""
fraud_detector.py
-----------------
Core fraud detection engine combining:
  1. Rule-based deterministic signals
  2. ML-style heuristic scoring
  3. Online intelligence (live news / threat feeds via Tavily)
  4. RAG over local knowledge base
  5. LLM reasoning layer (GPT-4.1)
"""
from __future__ import annotations

import os
import asyncio
from datetime import datetime, timezone
from dotenv import load_dotenv
from typing import Optional

from langchain_openai import ChatOpenAI
from langchain_classic.chains.retrieval_qa.base import RetrievalQA
from langchain_community.tools.tavily_search import TavilySearchResults

from app.models import Transaction, FraudResult
from app.vector_store import load_vector_store
from app.external import load_risk_data

load_dotenv()

# ─── Clients ─────────────────────────────────────────────────────────────────

OPENAI_API_KEY = os.getenv("OPENAI_API_KEY")
TAVILY_API_KEY = os.getenv("TAVILY_API_KEY")  # for online RAG enrichment

if not OPENAI_API_KEY:
    raise ValueError("OPENAI_API_KEY not set in environment!")

llm = ChatOpenAI(model="gpt-4.1", temperature=0, streaming=False)
vector_store = load_vector_store()

# Tavily for real-time threat intelligence (optional)
_tavily: Optional[TavilySearchResults] = None
if TAVILY_API_KEY:
    _tavily = TavilySearchResults(max_results=3, tavily_api_key=TAVILY_API_KEY)


# ─── Helpers ──────────────────────────────────────────────────────────────────

def _hours_between(a: datetime, b: datetime) -> float:
    """Return absolute difference in hours between two datetimes."""
    return abs((a - b).total_seconds()) / 3600


def _velocity_signals(txn: Transaction, history: list[Transaction]) -> tuple[list[str], float]:
    """
    Detect unusual transaction velocity patterns.
    Returns (signals, score_delta).
    """
    signals: list[str] = []
    delta = 0.0

    if not history:
        return signals, delta

    now = txn.timestamp or datetime.now(timezone.utc)

    # Count txns in last 1h
    recent_1h = [h for h in history if _hours_between(now, h.timestamp) <= 1]
    if len(recent_1h) >= 5:
        signals.append(f"High velocity: {len(recent_1h)} transactions in last hour")
        delta += 0.25

    # Count txns in last 24h
    recent_24h = [h for h in history if _hours_between(now, h.timestamp) <= 24]
    if len(recent_24h) >= 20:
        signals.append(f"Very high daily volume: {len(recent_24h)} transactions in 24h")
        delta += 0.15

    # Rapid amount escalation
    if len(history) >= 3:
        avg_amount = sum(h.amount for h in history[:10]) / min(len(history), 10)
        if txn.amount > avg_amount * 3:
            signals.append(f"Amount spike: {txn.amount:.2f} vs avg {avg_amount:.2f}")
            delta += 0.2

    return signals, delta


def _device_signals(txn: Transaction, history: list[Transaction]) -> tuple[list[str], float]:
    """Detect device/IP anomalies."""
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
    """
    Query Tavily for real-time fraud intelligence about the transaction location/merchant.
    Returns a summary string or empty string if unavailable.
    """
    if not _tavily or not txn.location:
        return ""

    query = f"financial fraud risk alerts {txn.location} {datetime.now().year}"
    try:
        results = await asyncio.to_thread(_tavily.invoke, query)
        if isinstance(results, list):
            snippets = [r.get("content", "") for r in results[:3]]
            return "\n".join(snippets)
    except Exception:
        pass
    return ""


# ─── Main Detection Function ──────────────────────────────────────────────────

async def detect_fraud(txn: Transaction, history: list[Transaction]) -> FraudResult:
    """
    Full fraud detection pipeline:
      1. Deterministic rules → base score
      2. Velocity analysis
      3. Device/IP anomaly
      4. External risk data
      5. Online intelligence (Tavily)
      6. RAG + LLM reasoning
    """
    risks = load_risk_data()
    signals: list[str] = []
    score = 0.05  # Base low score

    # ── 1. Amount thresholds ──────────────────────────────────────────────────
    if txn.amount > 10_000:
        signals.append(f"Very high amount: ${txn.amount:,.2f}")
        score += 0.45
    elif txn.amount > 1_000:
        signals.append(f"High amount: ${txn.amount:,.2f}")
        score += 0.2
    elif txn.amount > 500:
        signals.append(f"Elevated amount: ${txn.amount:,.2f}")
        score += 0.05

    # ── 2. Location anomaly ───────────────────────────────────────────────────
    if history:
        last_location = history[0].location
        if txn.location and last_location and txn.location != last_location:
            signals.append(f"Location change: {last_location} → {txn.location}")
            score += 0.2

            # Impossible travel check
            if len(history) >= 1 and history[0].timestamp:
                hours = _hours_between(
                    txn.timestamp or datetime.now(timezone.utc),
                    history[0].timestamp
                )
                if hours < 2:
                    signals.append("Impossible travel: location changed within 2 hours")
                    score += 0.25

    # ── 3. Velocity checks ────────────────────────────────────────────────────
    v_signals, v_delta = _velocity_signals(txn, history)
    signals.extend(v_signals)
    score += v_delta

    # ── 4. Device anomaly ─────────────────────────────────────────────────────
    d_signals, d_delta = _device_signals(txn, history)
    signals.extend(d_signals)
    score += d_delta

    # ── 5. External risk country data ─────────────────────────────────────────
    for r in risks:
        if r.get("country") == txn.location:
            level = r.get("risk_level", "")
            if level == "high":
                signals.append(f"High-risk jurisdiction: {txn.location}")
                score += 0.3
            elif level == "medium":
                signals.append(f"Medium-risk jurisdiction: {txn.location}")
                score += 0.1

    # ── 6. Merchant category risk ─────────────────────────────────────────────
    HIGH_RISK_CATEGORIES = {"crypto", "gambling", "wire_transfer", "gift_cards", "forex"}
    if txn.merchant_category and txn.merchant_category.lower() in HIGH_RISK_CATEGORIES:
        signals.append(f"High-risk merchant category: {txn.merchant_category}")
        score += 0.2

    # Clamp score
    score = round(min(score, 1.0), 4)

    # ── Decision ──────────────────────────────────────────────────────────────
    if score > 0.75:
        decision = "BLOCK"
    elif score > 0.4:
        decision = "REVIEW"
    else:
        decision = "ALLOW"

    # ── 7. Online intelligence (async, non-blocking) ──────────────────────────
    online_intel_task = asyncio.create_task(_fetch_online_intelligence(txn))

    # ── 8. RAG from local knowledge base ─────────────────────────────────────
    history_context = [
        {"amount": h.amount, "location": h.location, "timestamp": h.timestamp.isoformat()}
        for h in history[:5]
    ]

    rag_prompt = f"""
You are a senior fraud detection analyst. Analyze the transaction below using retrieved knowledge.

### Transaction Details
{txn.model_dump()}

### User Transaction History (last 5)
{history_context}

### Detected Risk Signals
{signals}

### Preliminary Score & Decision
Score: {score:.2f} | Decision: {decision}

Provide a clear, concise explanation (3-5 sentences) of the fraud risk, referencing specific signals.
Focus on actionable insights for a fraud analyst reviewing this case.
"""

    retriever = vector_store.as_retriever(search_kwargs={"k": 5})
    qa_chain = RetrievalQA.from_chain_type(
        llm=llm,
        retriever=retriever,
        return_source_documents=False,
    )

    # Run RAG and online intel concurrently
    rag_task = asyncio.to_thread(qa_chain.invoke, rag_prompt)
    rag_result, online_intel = await asyncio.gather(rag_task, online_intel_task)

    reason = rag_result["result"] if isinstance(rag_result, dict) else str(rag_result)

    # Append online intel if available
    if online_intel:
        reason += f"\n\n**Live Intelligence:** {online_intel[:500]}..."

    return FraudResult(
        transaction_id=txn.transaction_id,
        score=score,
        decision=decision,
        reason=reason,
        signals=signals,
    )