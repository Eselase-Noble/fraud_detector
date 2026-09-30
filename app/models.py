"""
models.py
---------
Pydantic v2 compatible models for the fraud detection system.
"""
from __future__ import annotations

import uuid
from datetime import datetime, timezone
from typing import Annotated, List, Optional

from pydantic import BaseModel, Field


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

    model_config = {"json_encoders": {datetime: lambda v: v.isoformat()}}


class FraudResult(BaseModel):
    transaction_id: str
    score: float = Field(..., ge=0.0, le=1.0, description="Fraud probability score")
    decision: str = Field(..., pattern="^(ALLOW|REVIEW|BLOCK)$")
    reason: str
    signals: List[str] = Field(default_factory=list)
    model_score: Optional[float] = Field(
        default=None, ge=0.0, le=1.0,
        description="Raw probability from the online-learning model (before blending).",
    )
    features: List[float] = Field(
        default_factory=list,
        description="Feature vector captured at scoring time, used to train the online model on feedback.",
    )
    processed_at: datetime = Field(default_factory=_now)

    model_config = {"json_encoders": {datetime: lambda v: v.isoformat()}}


class FeedbackRequest(BaseModel):
    """A labelled outcome for a scored transaction, used for online learning."""
    is_fraud: bool = Field(..., description="True if the transaction was truly fraudulent.")
    source: Optional[str] = Field(default="analyst", description="Who/what supplied the label.")


class BatchTransaction(BaseModel):
    # Pydantic v2: min_length / max_length via Annotated
    transactions: Annotated[List[Transaction], Field(min_length=1, max_length=500)]


class BatchFraudResult(BaseModel):
    total: int
    blocked: int
    reviewed: int
    allowed: int
    results: List[FraudResult]
    processed_at: datetime = Field(default_factory=_now)