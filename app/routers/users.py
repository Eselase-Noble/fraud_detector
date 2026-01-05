from typing import List

from fastapi import APIRouter
from app.models import Transaction
from app.database import get_user_history

router = APIRouter()

# Get recent transactions for a user
@router.get("/history/{user_id}", response_model=List[Transaction])
async def user_history(user_id: str, limit: int = 10):
    history = await get_user_history(user_id, limit=limit)
    return history

# Get risk profile (aggregated)
@router.get("/risk_profile/{user_id}")
async def risk_profile(user_id: str):
    history = await get_user_history(user_id)
    risk_score = sum(txn.amount for txn in history if txn.amount > 500) / max(1, len(history))
    return {"user_id": user_id, "risk_score": risk_score, "total_transactions": len(history)}
