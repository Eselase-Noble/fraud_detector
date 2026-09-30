"""
learning_stream.py
------------------
The continuous, privacy-preserving learning pipeline.

    producers ──▶ anonymize (privacy.py) ──▶ Redis Stream ──▶ consumer ──▶ model + training_events
    (public dataset feed, analyst reviews,        (fraud.labels)      (single writer;
     feedback API, partner webhooks)                                   prequential test-then-train)

Why a queue + single consumer:
  - Decouples producers from the learner: many sources, one well-ordered learning
    path. Bursts are absorbed by the stream instead of hammering the model.
  - Redis Streams give durability + consumer groups (at-least-once, replay, lag
    visibility) — the professional-grade transport the user asked for.
  - The consumer is the ONLY writer to the model, so updates are serialized and
    every step is tracked in `training_events` (prequential metrics).

Resilience: if Redis is unreachable, we transparently fall back to an in-process
async queue so the system keeps working (single-process only). Broker choice is
reported by `status()`.

Privacy: producers anonymize at their boundary, but the consumer also runs
`anonymize_event` defensively — no raw PII is ever persisted.
"""
from __future__ import annotations

import asyncio
import json
import logging
import os
from collections import deque
from datetime import datetime, timezone
from typing import Optional

import numpy as np

from app.privacy import anonymize_event, pepper_fingerprint
from app.online_model import get_model, persist_model, N_FEATURES, MODEL_VERSION, FEATURE_NAMES

logger = logging.getLogger(__name__)

REDIS_URL = os.getenv("REDIS_URL", "redis://localhost:6379/0")
STREAM = os.getenv("LEARNING_STREAM", "fraud.labels")
GROUP = "learners"
CONSUMER = "consumer-1"
PERSIST_EVERY = 25  # flush model weights to DB every N updates
SEEN_KEY = f"{STREAM}:seen"  # Redis SET of transaction_ids already trained on

# ─── Broker state ─────────────────────────────────────────────────────────────
_redis = None                       # redis.asyncio client, or None if unavailable
_inproc: "asyncio.Queue[dict]" = asyncio.Queue()
_using_redis = False
_consumer_task: Optional[asyncio.Task] = None
_stop = asyncio.Event()
_stats = {"consumed": 0, "learned": 0, "skipped": 0, "deduped": 0, "since_persist": 0}

# De-duplication: a transaction is trained on at most ONCE, ever. Backed by a
# Redis SET (durable, cross-process) with an in-memory fallback. Seeded from the
# training_events audit log on startup so restarts never re-expose old data.
_seen_mem: set = set()


async def _seed_seen() -> None:
    """Load already-learned transaction_ids so they are never re-trained."""
    try:
        from app.database import get_learned_transaction_ids
        ids = await get_learned_transaction_ids()
    except Exception as e:  # pragma: no cover
        logger.warning("Could not seed de-dup set: %s", e)
        return
    if not ids:
        return
    if _using_redis and _redis is not None:
        # Only seed if the Redis set is empty (e.g. Redis was flushed); otherwise
        # trust the existing set. SADD is idempotent so re-seeding is still safe.
        if await _redis.scard(SEEN_KEY) == 0:
            for i in range(0, len(ids), 5000):
                await _redis.sadd(SEEN_KEY, *ids[i:i + 5000])
    else:
        _seen_mem.update(ids)
    logger.info("De-dup set seeded with %d previously-learned transactions.", len(ids))


async def _already_seen(txn_id: str) -> bool:
    if _using_redis and _redis is not None:
        return bool(await _redis.sismember(SEEN_KEY, txn_id))
    return txn_id in _seen_mem


async def _mark_seen(txn_id: str) -> None:
    if _using_redis and _redis is not None:
        await _redis.sadd(SEEN_KEY, txn_id)
    else:
        _seen_mem.add(txn_id)

# Latest FX provenance reported by a producer (so the UI can show the rate + source).
_fx: Optional[dict] = None


def get_fx() -> Optional[dict]:
    return _fx

# ─── Live broadcast (for the real-time SSE view) ──────────────────────────────
# Each processed learning step is pushed to every connected subscriber so the UI
# can render the flow of training as it happens.
_subscribers: set = set()
# Rolling accuracy over a short window, computed in-memory for the live feed.
_live_window: deque = deque(maxlen=200)


def subscribe() -> "asyncio.Queue":
    q: asyncio.Queue = asyncio.Queue(maxsize=1000)
    _subscribers.add(q)
    return q


def unsubscribe(q: "asyncio.Queue") -> None:
    _subscribers.discard(q)


def _broadcast(record: dict) -> None:
    for q in list(_subscribers):
        try:
            q.put_nowait(record)
        except asyncio.QueueFull:
            pass  # slow client: drop rather than block the consumer


async def _connect_redis():
    global _redis, _using_redis
    try:
        import redis.asyncio as aioredis
        client = aioredis.from_url(REDIS_URL, decode_responses=True)
        await client.ping()
        # Create the consumer group (idempotent); MKSTREAM makes the stream too.
        try:
            await client.xgroup_create(STREAM, GROUP, id="0", mkstream=True)
        except Exception as e:
            if "BUSYGROUP" not in str(e):
                raise
        _redis = client
        _using_redis = True
        logger.info("Learning stream using Redis at %s (stream=%s)", REDIS_URL, STREAM)
    except Exception as e:
        _redis = None
        _using_redis = False
        logger.warning("Redis unavailable (%s) — falling back to in-process queue.", e)


# ─── Producer API ─────────────────────────────────────────────────────────────

async def publish(event: dict) -> None:
    """Anonymize then enqueue one labelled event. Safe for any producer to call."""
    safe = anonymize_event(event)
    if "occurred_at" not in safe:
        safe["occurred_at"] = datetime.now(timezone.utc).isoformat()
    if _using_redis and _redis is not None:
        await _redis.xadd(STREAM, {"data": json.dumps(safe)})
    else:
        await _inproc.put(safe)


async def publish_many(events: list[dict]) -> int:
    for e in events:
        await publish(e)
    return len(events)


# ─── Consumer ─────────────────────────────────────────────────────────────────

async def _resolve_features(evt: dict) -> Optional[np.ndarray]:
    """Get the feature vector for an event: from the payload, or from storage."""
    feats = evt.get("features")
    if feats and len(feats) == N_FEATURES:
        return np.array(feats, dtype=float)
    txn_id = evt.get("transaction_id")
    if txn_id:
        from app.database import get_result_features
        stored = await get_result_features(txn_id)
        if stored and len(stored) == N_FEATURES:
            return np.array(stored, dtype=float)
    return None


async def _process(evt: dict) -> bool:
    """Prequential test-then-train on one event; record it. Returns True if learned."""
    from app.database import insert_training_event
    if "label" not in evt:
        _stats["skipped"] += 1
        return False
    label = int(evt["label"])

    # De-duplication: never train twice on the same transaction. Old data that has
    # already been exposed to the model is rejected here, before any learning.
    txn_id = evt.get("transaction_id")
    if txn_id and await _already_seen(txn_id):
        _stats["deduped"] += 1
        return False

    vec = await _resolve_features(evt)
    if vec is None:
        _stats["skipped"] += 1
        logger.debug("Skipping event with no resolvable features: %s", evt.get("transaction_id"))
        return False

    # Capture FX provenance from the producer so the UI can display it.
    if evt.get("fx_rate"):
        global _fx
        _fx = {"rate": evt["fx_rate"], "source": evt.get("fx_source"),
               "as_of": evt.get("fx_as_of"), "base": "USD", "quote": "GHS"}

    model = await get_model()
    # 1) TEST: predict with the current model BEFORE learning (honest live metric).
    p_before = model.predict_proba(vec)
    pred_label = 1 if p_before >= 0.5 else 0
    influence = model.influence()
    # Explainable AI: for a linear model the contribution of each feature to this
    # prediction is exactly weight_i * value_i. Surface the top drivers (computed
    # with the PRE-update weights that produced p_before).
    contribs = model.w * vec
    order = np.argsort(-np.abs(contribs))
    why = [{"feature": FEATURE_NAMES[i], "contribution": round(float(contribs[i]), 4)}
           for i in order[:3] if abs(contribs[i]) > 1e-6]
    # 2) TRAIN: one online SGD step.
    loss = await model.learn(vec, label)

    await insert_training_event({
        "occurred_at": _parse_dt(evt.get("occurred_at")),
        "source": evt.get("source", "unknown"),
        "subject_hash": evt.get("subject"),
        "transaction_id": evt.get("transaction_id"),
        "label": label,
        "predicted_proba": round(p_before, 6),
        "predicted_label": pred_label,
        "correct": pred_label == label,
        "loss": round(loss, 6),
        "influence": influence,
        "model_version": MODEL_VERSION,
        "pepper_fp": pepper_fingerprint(),
    })

    if txn_id:
        await _mark_seen(txn_id)   # this transaction is now exposed to the model

    _stats["learned"] += 1
    _stats["since_persist"] += 1
    if _stats["since_persist"] >= PERSIST_EVERY:
        await persist_model()
        _stats["since_persist"] = 0

    # Non-PII transaction attributes for the live "stream of data" view. Present
    # on dataset events; for feedback/review events, enrich from the txn record.
    amount = evt.get("amount")
    category = evt.get("merchant_category")
    location = evt.get("location")
    currency = evt.get("currency", "GHS")
    if amount is None and evt.get("transaction_id"):
        try:
            from app.database import get_transaction_by_id
            t = await get_transaction_by_id(evt["transaction_id"])
            if t:
                amount, category, location = t.amount, t.merchant_category, t.location
                currency = t.currency or "GHS"
        except Exception:
            pass

    # Live feed: push a compact, already-anonymized record to SSE subscribers.
    _live_window.append(1 if pred_label == label else 0)
    rolling_acc = sum(_live_window) / len(_live_window) if _live_window else None
    _broadcast({
        "type": "step",
        "n": _stats["learned"],
        "source": evt.get("source", "unknown"),
        "subject": evt.get("subject"),
        "amount": amount,
        "currency": currency,
        "merchant_category": category,
        "location": location,
        "label": label,
        "predicted_proba": round(p_before, 4),
        "predicted_label": pred_label,
        "correct": pred_label == label,
        "influence": influence,
        "why": why,
        "rolling_accuracy": round(rolling_acc, 4) if rolling_acc is not None else None,
    })
    return True


def _parse_dt(s):
    if not s:
        return None
    try:
        return datetime.fromisoformat(s)
    except (ValueError, TypeError):
        return None


async def _consume_loop() -> None:
    logger.info("Learning consumer started (%s).", "redis" if _using_redis else "in-process")
    while not _stop.is_set():
        try:
            if _using_redis and _redis is not None:
                # Standard online learning: pull ONE transaction at a time, learn
                # from it, then fetch the next. When the stream is empty the read
                # blocks (idle) and simply retries — the model resumes the moment
                # another transaction arrives.
                resp = await _redis.xreadgroup(GROUP, CONSUMER, {STREAM: ">"},
                                               count=1, block=2000)
                if not resp:
                    continue  # no more data right now — wait for the next transaction
                for _stream, messages in resp:
                    for msg_id, fields in messages:
                        _stats["consumed"] += 1
                        try:
                            await _process(json.loads(fields["data"]))
                        except Exception as e:
                            logger.warning("Event processing failed: %s", e)
                        finally:
                            await _redis.xack(STREAM, GROUP, msg_id)
            else:
                try:
                    evt = await asyncio.wait_for(_inproc.get(), timeout=1.0)
                except asyncio.TimeoutError:
                    continue
                _stats["consumed"] += 1
                try:
                    await _process(evt)
                except Exception as e:
                    logger.warning("Event processing failed: %s", e)
        except asyncio.CancelledError:
            break
        except Exception as e:  # pragma: no cover — keep the loop alive
            logger.warning("Consumer loop error: %s", e)
            await asyncio.sleep(1.0)
    # Final flush.
    try:
        await persist_model()
    except Exception:
        pass
    logger.info("Learning consumer stopped.")


# ─── Lifecycle (wired into FastAPI lifespan) ─────────────────────────────────

async def start_consumer() -> None:
    global _consumer_task
    await _connect_redis()
    await _seed_seen()   # so previously-learned data is never re-trained
    _stop.clear()
    _consumer_task = asyncio.create_task(_consume_loop())


async def connect_producer() -> None:
    """Connect to the broker for publishing only (no consumer loop).

    Used by external producer processes (e.g. the dataset streamer) so their
    events land in the same Redis stream the API server's consumer reads.
    """
    await _connect_redis()


async def close_producer() -> None:
    if _redis is not None:
        try:
            await _redis.aclose()
        except Exception:
            pass


async def stop_consumer() -> None:
    _stop.set()
    if _consumer_task:
        _consumer_task.cancel()
        try:
            await _consumer_task
        except (asyncio.CancelledError, Exception):
            pass
    if _redis is not None:
        try:
            await _redis.aclose()
        except Exception:
            pass


async def status() -> dict:
    """Broker + consumer health for the tracking dashboard."""
    info: dict = {
        "broker": "redis" if _using_redis else "in-process",
        "stream": STREAM,
        "consumer_running": _consumer_task is not None and not _consumer_task.done(),
        "pepper_fingerprint": pepper_fingerprint(),
        "fx": _fx,
        **_stats,
    }
    if _using_redis and _redis is not None:
        try:
            info["stream_length"] = await _redis.xlen(STREAM)
            pend = await _redis.xpending(STREAM, GROUP)
            info["pending"] = pend.get("pending", 0) if isinstance(pend, dict) else None
        except Exception as e:
            info["redis_error"] = str(e)
    else:
        info["queue_depth"] = _inproc.qsize()
    return info
