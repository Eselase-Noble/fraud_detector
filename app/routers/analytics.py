from fastapi import APIRouter
from app.database import get_all_transactions
from collections import Counter

router = APIRouter()

@router.get("/fraud_stats")
async def fraud_stats():
    txns = await get_all_transactions()
    total = len(txns)
    blocked = sum(1 for t in txns if t.amount > 1000)  # simple proxy for fraud
    return {"total_transactions": total, "suspicious_transactions": blocked, "fraud_rate": blocked/total}

@router.get("/top_users")
async def top_users(limit: int = 10):
    txns = await get_all_transactions()
    counter = Counter(t.user_id for t in txns if t.amount > 500)
    return counter.most_common(limit)
