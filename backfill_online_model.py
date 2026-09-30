"""
backfill_online_model.py
------------------------
Warm-start the online-learning model from historical analyst decisions.

The online model normally learns one label at a time as analysts review cases.
But you almost certainly already have a backlog of labelled outcomes in the
`audit_log` table (every CONFIRM_FRAUD / CLEAR an analyst has ever recorded).
This script replays that history so the model doesn't start from zero.

For each labelled transaction it:
  1. Reloads the transaction and its prior history,
  2. Recomputes the exact feature vector via `detect_fraud` (feature parity with
     live scoring — no separate, drift-prone feature code),
  3. Takes one online SGD step (CONFIRM_FRAUD -> fraud=1, CLEAR -> legit=0).

Only the LATEST audit action per transaction is used, so a case that was
escalated then cleared trains on "cleared". Idempotent-ish: re-running simply
trains further on the same labels (a few extra epochs won't hurt a calibrated
logistic model, but you normally run it once).

Usage:
    .venv/bin/python backfill_online_model.py            # replay once
    .venv/bin/python backfill_online_model.py --epochs 3 # replay 3x (more fit)
"""
from __future__ import annotations

import argparse
import asyncio
import logging

from app.database import init_db, close_db, _get_pool, get_user_history
from app.fraud_detector import detect_fraud
from app.online_model import get_model, persist_model, N_FEATURES
import numpy as np

logging.basicConfig(level=logging.WARNING)

LABELS = {"CONFIRM_FRAUD": 1, "CLEAR": 0}


async def _latest_labels() -> list[tuple[str, int]]:
    """Return (transaction_id, label) for the most recent labelling action each."""
    pool = await _get_pool()
    async with pool.acquire() as conn:
        rows = await conn.fetch(
            """
            SELECT DISTINCT ON (transaction_id) transaction_id, action
            FROM audit_log
            WHERE action IN ('CONFIRM_FRAUD', 'CLEAR')
            ORDER BY transaction_id, created_at DESC
            """
        )
    return [(r["transaction_id"], LABELS[r["action"]]) for r in rows]


async def backfill(epochs: int = 1) -> None:
    await init_db()
    try:
        labels = await _latest_labels()
        if not labels:
            print("No CONFIRM_FRAUD / CLEAR entries in audit_log — nothing to backfill.")
            return

        model = await get_model()
        print(f"Found {len(labels)} labelled transactions. Training {epochs} epoch(s)...")

        trained = skipped = 0
        for epoch in range(epochs):
            for txn_id, label in labels:
                # Reconstruct the transaction and the history it was scored against.
                from app.database import get_transaction_by_id
                txn = await get_transaction_by_id(txn_id)
                if txn is None:
                    skipped += 1
                    continue
                history = [h for h in await get_user_history(txn.user_id)
                           if h.transaction_id != txn_id]
                result = await detect_fraud(txn, history)
                if not result.features or len(result.features) != N_FEATURES:
                    skipped += 1
                    continue
                await model.learn(np.array(result.features, dtype=float), label)
                trained += 1
            print(f"  epoch {epoch + 1}/{epochs} done "
                  f"(updates so far: {model.n_updates})")

        await persist_model()
        stats = model.stats()
        print("\nBackfill complete.")
        print(f"  training steps : {trained}   (skipped {skipped})")
        print(f"  fraud labels   : {stats['n_fraud_labels']}")
        print(f"  legit labels   : {stats['n_legit_labels']}")
        print(f"  model trusted  : {stats['is_trusted']}  (influence {stats['influence']})")
    finally:
        await close_db()


if __name__ == "__main__":
    ap = argparse.ArgumentParser(description="Warm-start the online model from audit_log history.")
    ap.add_argument("--epochs", type=int, default=1, help="Number of passes over the labelled history.")
    args = ap.parse_args()
    asyncio.run(backfill(args.epochs))
