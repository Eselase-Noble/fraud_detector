"""
learning.py (router)
--------------------
Observability + ingestion for the online-learning pipeline.

  POST /learning/publish   feed a batch of labelled events into the stream
  GET  /learning/metrics   prequential accuracy / precision / recall / F1 + learning curve
  GET  /learning/events    recent (anonymized) learning steps
  GET  /learning/status    broker + consumer health, throughput, PII key fingerprint
"""
from __future__ import annotations

from typing import List, Optional

from fastapi import APIRouter
from pydantic import BaseModel, Field

from app import learning_stream
from app.database import (
    get_learning_metrics, get_learning_curve, get_recent_training_events, count_by_source,
)
from app.online_model import get_model

router = APIRouter(tags=["Learning"])


class LabeledEvent(BaseModel):
    label: int = Field(..., ge=0, le=1, description="1 = fraud, 0 = legitimate")
    transaction_id: Optional[str] = Field(None, description="Links to a scored transaction (features looked up).")
    subject: Optional[str] = Field(None, description="Raw identifier; pseudonymized before storage.")
    features: Optional[List[float]] = Field(None, description="Optional precomputed feature vector.")
    source: str = Field("api", description="Origin of the label (e.g. analyst_review, public_dataset).")


class PublishRequest(BaseModel):
    events: List[LabeledEvent] = Field(..., min_length=1, max_length=5000)


@router.post("/publish", summary="Publish labelled events into the learning stream")
async def publish_events(body: PublishRequest):
    n = await learning_stream.publish_many([e.model_dump() for e in body.events])
    return {"status": "queued", "count": n, "note": "Identities are pseudonymized before entering the stream."}


@router.get("/metrics", summary="Prequential metrics + learning curve for the online model")
async def learning_metrics(window: int = 500, buckets: int = 20):
    metrics = await get_learning_metrics(window=window)
    curve = await get_learning_curve(buckets=buckets)
    sources = await count_by_source()
    model = await get_model()
    return {"metrics": metrics, "curve": curve, "by_source": sources, "model": model.stats()}


@router.get("/events", summary="Recent anonymized learning steps")
async def learning_events(limit: int = 25):
    return await get_recent_training_events(limit=limit)


@router.get("/status", summary="Learning stream broker + consumer health")
async def learning_status():
    return await learning_stream.status()
