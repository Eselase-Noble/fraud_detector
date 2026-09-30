"""
online_model.py
---------------
Lightweight ONLINE-LEARNING model for fraud detection.

Why this exists
===============
The core `detect_fraud` scorer is deterministic (hand-written rules). Rules never
improve on their own. This module adds a model that *learns from feedback*: every
time an analyst confirms or clears a case (or a partner sends a labelled outcome),
the model takes a single gradient step and immediately gets a little better. That
is "online learning" in the strict sense — the model is updated one example at a
time, in place, with no offline batch retraining.

Design goals
============
- **No heavy dependencies.** Pure `numpy` (already installed). No river / sklearn.
- **True incremental updates.** `learn(vec, label)` does one SGD step of logistic
  regression — O(n_features), constant memory.
- **Durable.** Weights live in the `model_state` table (JSONB) and are reloaded on
  startup, so learning accumulates across restarts and workers.
- **Safe by default.** Until the model has seen enough labels it stays out of the
  way; its influence on the final score grows gradually with the number of updates.
- **Interpretable.** Feature names are fixed and ordered, so weights can be shown.

The model is a binary logistic regressor:  p = sigmoid(w · x + b),  label 1 = fraud.
"""
from __future__ import annotations

import asyncio
import logging
import math
import os
from datetime import datetime, timezone
from typing import Optional

import numpy as np

logger = logging.getLogger(__name__)

# ─── Feature schema ───────────────────────────────────────────────────────────
# Fixed order. Feature vectors are built by `build_features()` below. Keeping the
# names here (rather than in the caller) means persisted weights always line up
# with the right feature, and lets us expose "which signals the model weighs".
FEATURE_NAMES: list[str] = [
    "amount_log",            # log10(amount + 1) / 5   (~0..1 for normal amounts)
    "amount_gt_500",         # tiered amount flags
    "amount_gt_1000",
    "amount_gt_10000",
    "velocity_1h",           # txns in last hour / 10   (capped at 1)
    "velocity_24h",          # txns in last 24h  / 30   (capped at 1)
    "amount_spike",          # amount > 3x recent average
    "location_change",       # location differs from last txn
    "impossible_travel",     # location changed within 2 hours
    "new_device",            # device not seen in history
    "high_risk_category",    # crypto / gambling / wire_transfer / gift_cards / forex
    "high_risk_jurisdiction",# country risk_level == high
    "med_risk_jurisdiction", # country risk_level == medium
    "risk_tier",             # standard=0, elevated=0.5, high=1.0
    "night_hour",            # transaction hour in [0,6)
]
N_FEATURES = len(FEATURE_NAMES)

# ─── Hyper-parameters ─────────────────────────────────────────────────────────
LEARNING_RATE = 0.08
L2 = 1e-4
# Fraud is highly imbalanced (often <1% of transactions). Without correction an
# online model just learns to predict "legit" always. We up-weight the gradient
# of positive (fraud) examples so the minority class actually moves the boundary.
POS_WEIGHT = float(os.getenv("FRAUD_POS_WEIGHT", "15"))
# The model must observe at least this many labels before it influences scoring.
MIN_SAMPLES_TO_TRUST = 20
# Its maximum share of the blended score, reached gradually as more labels arrive.
MAX_INFLUENCE = 0.5
INFLUENCE_RAMP = 200.0   # updates needed to approach MAX_INFLUENCE

MODEL_NAME = "fraud_logreg_v1"
MODEL_VERSION = f"{MODEL_NAME}+f{N_FEATURES}"


def _sigmoid(z: float) -> float:
    if z >= 0:
        return 1.0 / (1.0 + math.exp(-z))
    ez = math.exp(z)
    return ez / (1.0 + ez)


def build_features(
    *,
    amount: float,
    velocity_1h: int,
    velocity_24h: int,
    amount_spike: bool,
    location_change: bool,
    impossible_travel: bool,
    new_device: bool,
    high_risk_category: bool,
    jurisdiction_risk: str,      # "", "medium", or "high"
    risk_tier: str,              # "standard" | "elevated" | "high"
    hour: int,
) -> np.ndarray:
    """Assemble a fixed-order numeric feature vector from raw signals.

    The caller (`detect_fraud`) already computes most of these signals for its
    rule engine, so this just normalises and orders them — no duplicated logic.
    """
    tier_map = {"standard": 0.0, "elevated": 0.5, "high": 1.0}
    vec = np.array([
        min(math.log10(amount + 1) / 5.0, 1.5),
        1.0 if amount > 500 else 0.0,
        1.0 if amount > 1000 else 0.0,
        1.0 if amount > 10000 else 0.0,
        min(velocity_1h / 10.0, 1.0),
        min(velocity_24h / 30.0, 1.0),
        1.0 if amount_spike else 0.0,
        1.0 if location_change else 0.0,
        1.0 if impossible_travel else 0.0,
        1.0 if new_device else 0.0,
        1.0 if high_risk_category else 0.0,
        1.0 if jurisdiction_risk == "high" else 0.0,
        1.0 if jurisdiction_risk == "medium" else 0.0,
        tier_map.get(risk_tier, 0.0),
        1.0 if 0 <= hour < 6 else 0.0,
    ], dtype=float)
    return vec


class OnlineFraudModel:
    """In-place, incrementally-trained logistic regression.

    Not persisted here directly — persistence is handled by the caller via
    `to_state()` / `load_state()` against the `model_state` table so this class
    stays free of any DB import.
    """

    def __init__(self) -> None:
        self.w = np.zeros(N_FEATURES, dtype=float)
        self.b = 0.0
        self.n_updates = 0
        self.n_pos = 0
        self.n_neg = 0
        self._lock = asyncio.Lock()

    # ── Inference ────────────────────────────────────────────────────────────
    def predict_proba(self, vec: np.ndarray) -> float:
        return _sigmoid(float(np.dot(self.w, vec)) + self.b)

    def influence(self) -> float:
        """How much weight the model's probability gets in the blended score.

        0.0 until MIN_SAMPLES_TO_TRUST labels, then ramps toward MAX_INFLUENCE.
        """
        if self.n_updates < MIN_SAMPLES_TO_TRUST:
            return 0.0
        ramp = 1.0 - math.exp(-self.n_updates / INFLUENCE_RAMP)
        return round(MAX_INFLUENCE * ramp, 4)

    def blend(self, rule_score: float, vec: np.ndarray) -> tuple[float, float, float]:
        """Combine the deterministic rule score with the learned probability.

        Returns (blended_score, model_prob, influence). While the model is still
        cold this returns the rule score unchanged.
        """
        model_prob = self.predict_proba(vec)
        alpha = self.influence()
        blended = (1.0 - alpha) * rule_score + alpha * model_prob
        return min(max(blended, 0.0), 1.0), model_prob, alpha

    # ── Learning (one online SGD step) ───────────────────────────────────────
    def _step(self, vec: np.ndarray, label: int) -> float:
        p = self.predict_proba(vec)
        error = p - label                      # gradient of log-loss wrt logit
        sw = POS_WEIGHT if label == 1 else 1.0  # up-weight rare fraud examples
        self.w -= LEARNING_RATE * (sw * error * vec + L2 * self.w)
        self.b -= LEARNING_RATE * sw * error
        self.n_updates += 1
        if label == 1:
            self.n_pos += 1
        else:
            self.n_neg += 1
        return abs(error)

    async def learn(self, vec: np.ndarray, label: int) -> float:
        """Update the model with a single labelled example (thread-safe)."""
        async with self._lock:
            return self._step(vec, int(label))

    # ── Serialisation ────────────────────────────────────────────────────────
    def to_state(self) -> dict:
        return {
            "weights": self.w.tolist(),
            "bias": self.b,
            "n_updates": self.n_updates,
            "n_pos": self.n_pos,
            "n_neg": self.n_neg,
            "feature_names": FEATURE_NAMES,
        }

    def load_state(self, state: dict) -> None:
        w = state.get("weights")
        if w and len(w) == N_FEATURES:
            self.w = np.array(w, dtype=float)
        self.b = float(state.get("bias", 0.0))
        self.n_updates = int(state.get("n_updates", 0))
        self.n_pos = int(state.get("n_pos", 0))
        self.n_neg = int(state.get("n_neg", 0))

    def stats(self) -> dict:
        return {
            "name": MODEL_NAME,
            "n_updates": self.n_updates,
            "n_fraud_labels": self.n_pos,
            "n_legit_labels": self.n_neg,
            "influence": self.influence(),
            "is_trusted": self.n_updates >= MIN_SAMPLES_TO_TRUST,
            "min_samples_to_trust": MIN_SAMPLES_TO_TRUST,
            "weights": {name: round(float(w), 4) for name, w in zip(FEATURE_NAMES, self.w)},
            "bias": round(self.b, 4),
        }


# ─── Module-level singleton ───────────────────────────────────────────────────
# One shared model per process. Loaded from the DB on first use so every request
# and every feedback event acts on the same accumulating weights.
_model: Optional[OnlineFraudModel] = None
_init_lock = asyncio.Lock()


async def get_model() -> OnlineFraudModel:
    global _model
    if _model is not None:
        return _model
    async with _init_lock:
        if _model is None:
            m = OnlineFraudModel()
            try:
                from app.database import load_model_state
                state = await load_model_state(MODEL_NAME)
                if state:
                    m.load_state(state)
                    logger.info("Online model restored: %d updates so far.", m.n_updates)
            except Exception as e:  # pragma: no cover
                logger.warning("Could not restore online model state: %s", e)
            _model = m
    return _model


async def persist_model() -> None:
    """Write the current weights back to the DB."""
    if _model is None:
        return
    try:
        from app.database import save_model_state
        await save_model_state(MODEL_NAME, _model.to_state())
    except Exception as e:  # pragma: no cover
        logger.warning("Could not persist online model state: %s", e)


async def learn_from_feedback(transaction_id: str, is_fraud: bool) -> Optional[dict]:
    """Train the online model on one labelled transaction, then persist.

    Loads the feature vector captured when the transaction was scored, takes a
    single SGD step (label 1 = fraud, 0 = legitimate) and saves the new weights.
    Returns updated model stats, or None if the transaction has no stored
    features (e.g. it was scored before this feature existed).
    """
    from app.database import get_result_features
    raw = await get_result_features(transaction_id)
    if not raw or len(raw) != N_FEATURES:
        return None
    vec = np.array(raw, dtype=float)
    model = await get_model()
    await model.learn(vec, 1 if is_fraud else 0)
    await persist_model()
    return model.stats()


def utc_now() -> datetime:
    return datetime.now(timezone.utc)
