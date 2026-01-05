from typing import List

from fastapi import APIRouter, HTTPException
from app.models import Transaction, FraudResult, BatchTransaction
from app.fraud_detector import detect_fraud
from app.database import get_user_history, get_transaction_by_id

router = APIRouter()

# Single transaction detection
@router.post("/detect", response_model=FraudResult)
async def detect(transaction: Transaction):
    history = await get_user_history(transaction.user_id)
    result = detect_fraud(transaction, history)
    return result

# Batch transaction detection
@router.post("/batch_detect", response_model=List[FraudResult])
async def batch_detect(batch: BatchTransaction):
    results = []
    for txn in batch.transactions:
        history = await get_user_history(txn.user_id)
        result = detect_fraud(txn, history)
        results.append(result)
    return results

# Get single transaction
@router.get("/{transaction_id}", response_model=Transaction)
async def get_transaction(transaction_id: str):
    txn = await get_transaction_by_id(transaction_id)
    if not txn:
        raise HTTPException(status_code=404, detail="Transaction not found")
    return txn
