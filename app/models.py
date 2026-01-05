from pydantic import BaseModel, Field
from datetime import datetime
from typing import Optional, List

class Transaction(BaseModel):
    transaction_id: str
    user_id: str
    amount: float
    currency: str
    merchant: Optional[str]
    location: Optional[str]
    timestamp: datetime

class FraudResult(BaseModel):
    transaction_id: str
    score: float = Field(ge=0, le=1)
    decision: str
    reason: str
    signals: List[str]

class BatchTransaction(BaseModel):
    transactions: List[Transaction]