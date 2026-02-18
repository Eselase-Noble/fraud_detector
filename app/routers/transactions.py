from typing import List
import asyncio
from fastapi import APIRouter, HTTPException, BackgroundTasks, Query
from app.models import Transaction, FraudResult, BatchTransaction, BatchFraudResult
from app.fraud_detector import detect_fraud
from app.database import get_user_history, get_transaction_by_id, save_fraud_result, get_all_transactions

router = APIRouter( tags=["Transactions"])


# ─── Single Transaction Detection ────────────────────────────────────────────

@router.post("/detect", response_model=FraudResult, summary="Detect fraud on a single transaction")
async def detect(transaction: Transaction, background_tasks: BackgroundTasks):
    history = await get_user_history(transaction.user_id)
    result = await detect_fraud(transaction, history)

    # Persist result asynchronously without blocking response
    background_tasks.add_task(save_fraud_result, result)
    return result


# ─── Batch Transaction Detection ─────────────────────────────────────────────

@router.post("/batch_detect", response_model=BatchFraudResult, summary="Detect fraud on multiple transactions concurrently")
async def batch_detect(batch: BatchTransaction, background_tasks: BackgroundTasks):
    if len(batch.transactions) > 500:
        raise HTTPException(status_code=400, detail="Batch size exceeds limit of 500 transactions.")

    async def process(txn: Transaction) -> FraudResult:
        history = await get_user_history(txn.user_id)
        return await detect_fraud(txn, history)

    results: List[FraudResult] = await asyncio.gather(*[process(txn) for txn in batch.transactions])

    background_tasks.add_task(_persist_batch, results)

    blocked = sum(1 for r in results if r.decision == "BLOCK")
    reviewed = sum(1 for r in results if r.decision == "REVIEW")
    allowed = sum(1 for r in results if r.decision == "ALLOW")

    return BatchFraudResult(
        total=len(results),
        blocked=blocked,
        reviewed=reviewed,
        allowed=allowed,
        results=results,
    )


async def _persist_batch(results: List[FraudResult]):
    await asyncio.gather(*[save_fraud_result(r) for r in results])


# ─── Get Single Transaction ───────────────────────────────────────────────────

@router.get("/{transaction_id}", response_model=Transaction, summary="Retrieve a transaction by ID")
async def get_transaction(transaction_id: str):
    txn = await get_transaction_by_id(transaction_id)
    if not txn:
        raise HTTPException(status_code=404, detail=f"Transaction '{transaction_id}' not found.")
    return txn


# ─── List Transactions ────────────────────────────────────────────────────────

@router.get("/", response_model=List[Transaction], summary="List all transactions with optional filters")
async def list_transactions(
    limit: int = Query(50, ge=1, le=1000),
    offset: int = Query(0, ge=0),
    user_id: str = Query(None),
    decision: str = Query(None, pattern="^(ALLOW|REVIEW|BLOCK)$"),
):
    txns = await get_all_transactions(limit=limit, offset=offset, user_id=user_id, decision=decision)
    return txns