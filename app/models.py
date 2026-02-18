"""
models.py
---------
Pydantic models for the fraud detection system.
"""
from __future__ import annotations

from datetime import datetime, timezone
from typing import List, Optional
from pydantic import BaseModel, Field, validator
import uuid


def _now() -> datetime:
    return datetime.now(timezone.utc)


class Transaction(BaseModel):
    transaction_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    user_id: str
    amount: float = Field(..., ge=0, description="Transaction amount in USD")
    currency: str = Field(default="USD", max_length=3)
    location: Optional[str] = None
    merchant_id: Optional[str] = None
    merchant_category: Optional[str] = None
    device_id: Optional[str] = None
    ip_address: Optional[str] = None
    timestamp: datetime = Field(default_factory=_now)

    class Config:
        json_encoders = {datetime: lambda v: v.isoformat()}


class FraudResult(BaseModel):
    transaction_id: str
    score: float = Field(..., ge=0.0, le=1.0, description="Fraud probability score")
    decision: str = Field(..., regex="^(ALLOW|REVIEW|BLOCK)$")
    reason: str
    signals: List[str] = Field(default_factory=list)
    processed_at: datetime = Field(default_factory=_now)

    class Config:
        json_encoders = {datetime: lambda v: v.isoformat()}


class BatchTransaction(BaseModel):
    transactions: List[Transaction] = Field(..., min_items=1, max_items=500)


class BatchFraudResult(BaseModel):
    total: int
    blocked: int
    reviewed: int
    allowed: int
    results: List[FraudResult]
    processed_at: datetime = Field(default_factory=_now)