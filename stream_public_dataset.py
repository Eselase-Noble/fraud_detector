"""
stream_public_dataset.py
------------------------
Stream a real, public fraud dataset into the online-learning pipeline as a
*live feed* — to test the whole system end-to-end with realistic data.

Source: `santosh3110/credit_card_fraud_transactions` on Hugging Face — a mirror
of the widely-used Sparkov simulated credit-card dataset. Its schema
(cc_num, merchant, category, amt, city/state, unix_time, is_fraud) maps cleanly
onto our Transaction model, and it carries real identifier fields (cc_num,
name) so it also exercises the pseudonymization boundary.

We read it page-by-page over Hugging Face's public `/rows` API (no download, no
auth), and for each row:
  1. map columns -> our transaction fields,
  2. compute the model's feature vector (with light per-card velocity state so
     the behavioural features are meaningful),
  3. PSEUDONYMIZE the card number and drop names at the boundary,
  4. publish {features, label, subject, source='public_dataset'} to the stream.

The running API server's consumer then trains on the feed and tracks every step.

Usage:
    .venv/bin/python stream_public_dataset.py --limit 2000 --delay 0
    .venv/bin/python stream_public_dataset.py --limit 500 --delay 0.05   # simulate live rate
"""
from __future__ import annotations

import argparse
import asyncio
from collections import defaultdict, deque
from datetime import datetime, timezone

import requests

from app.online_model import build_features
from app.privacy import pseudonymize
from app import learning_stream

DATASET = "santosh3110/credit_card_fraud_transactions"
ROWS_API = "https://datasets-server.huggingface.co/rows"
PAGE = 100  # HF /rows max length

# Per-card recent activity, to derive velocity / amount-spike features on the fly.
# Keyed by pseudonymized subject so we never key state on raw PII.
_recent: dict[str, deque] = defaultdict(lambda: deque(maxlen=50))


def _fetch_page(offset: int, length: int) -> list[dict]:
    params = {"dataset": DATASET, "config": "default", "split": "train",
              "offset": offset, "length": length}
    r = requests.get(ROWS_API, params=params, timeout=30)
    r.raise_for_status()
    return [row["row"] for row in r.json().get("rows", [])]


def _hour_of(row: dict) -> int:
    ut = row.get("unix_time")
    if ut:
        return datetime.fromtimestamp(int(ut), tz=timezone.utc).hour
    return 12


def _build_event(row: dict) -> dict:
    subject = pseudonymize(str(row.get("cc_num")), "subj")
    unix_time = int(row.get("unix_time") or 0)
    amount = float(row.get("amt") or 0.0)

    # Derive velocity / spike features from this card's recent history.
    hist = _recent[subject]
    v_1h = sum(1 for (t, _a) in hist if 0 <= unix_time - t <= 3600)
    v_24h = sum(1 for (t, _a) in hist if 0 <= unix_time - t <= 86400)
    amounts = [a for (_t, a) in hist][-10:]
    avg_amt = (sum(amounts) / len(amounts)) if amounts else 0.0
    amount_spike = bool(avg_amt and amount > avg_amt * 3)
    hist.append((unix_time, amount))

    features = build_features(
        amount=amount,
        velocity_1h=v_1h,
        velocity_24h=v_24h,
        amount_spike=amount_spike,
        location_change=False,        # not tracked cross-row for this feed
        impossible_travel=False,
        new_device=False,             # dataset has no device field
        high_risk_category=False,     # Sparkov categories aren't in our set
        jurisdiction_risk="",         # US-state locations aren't in country risk data
        risk_tier="standard",
        hour=_hour_of(row),
    )
    return {
        "source": "public_dataset",
        "subject": subject,                       # already pseudonymized
        "transaction_id": row.get("trans_num"),
        "label": int(row.get("is_fraud") or 0),
        "features": features.tolist(),
        "occurred_at": datetime.fromtimestamp(unix_time, tz=timezone.utc).isoformat()
                        if unix_time else None,
    }


async def run(limit: int, offset: int, delay: float) -> None:
    await learning_stream.connect_producer()
    sent = frauds = 0
    while sent < limit:
        page = _fetch_page(offset + sent, min(PAGE, limit - sent))
        if not page:
            break
        for row in page:
            evt = _build_event(row)
            frauds += evt["label"]
            await learning_stream.publish(evt)
            sent += 1
            if delay:
                await asyncio.sleep(delay)
        print(f"  streamed {sent}/{limit}  (frauds so far: {frauds})", flush=True)
    print(f"\nDone. Published {sent} labelled events ({frauds} fraud, "
          f"{sent - frauds} legit) to stream '{learning_stream.STREAM}'.")
    print("The API server's consumer is training on them; check GET /learning/metrics.")
    await learning_stream.close_producer()


if __name__ == "__main__":
    ap = argparse.ArgumentParser(description="Stream the public Sparkov fraud dataset into the learning pipeline.")
    ap.add_argument("--limit", type=int, default=2000, help="How many rows to stream.")
    ap.add_argument("--offset", type=int, default=0, help="Starting row offset in the dataset.")
    ap.add_argument("--delay", type=float, default=0.0, help="Seconds between events (simulate live rate).")
    args = ap.parse_args()
    asyncio.run(run(args.limit, args.offset, args.delay))
