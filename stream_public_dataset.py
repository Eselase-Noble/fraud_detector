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
import os
import time
from collections import defaultdict, deque
from datetime import datetime, timezone

import requests

# The public dataset is US data in USD. This is a Ghana-based service, so amounts
# are converted to Ghana Cedis for display. The rate is fetched live from a named
# FX source at startup (falling back to the static USD_TO_GHS env value if the
# lookup fails). The model's features are computed on the ORIGINAL USD amount so
# its learned thresholds stay valid — only the displayed amount is converted.
FX_API = "https://open.er-api.com/v6/latest/USD"
_FX = {
    "rate": float(os.getenv("USD_TO_GHS", "13.5")),
    "source": "static config (USD_TO_GHS)",
    "as_of": None,
    "base": "USD",
    "quote": "GHS",
}


def fetch_fx() -> dict:
    """Fetch the live USD->GHS rate and record its source + timestamp."""
    try:
        r = requests.get(FX_API, timeout=15)
        r.raise_for_status()
        d = r.json()
        rate = d.get("rates", {}).get("GHS")
        if d.get("result") == "success" and rate:
            _FX.update({
                "rate": round(float(rate), 4),
                "source": d.get("provider", "exchangerate-api.com"),
                "as_of": d.get("time_last_update_utc"),
            })
            print(f"FX: 1 USD = {_FX['rate']} GHS  (source: {_FX['source']}, as of {_FX['as_of']})")
            return _FX
    except Exception as e:
        print(f"FX lookup failed ({e}); using static rate {_FX['rate']} GHS/USD.")
    return _FX

from app.online_model import build_features
from app.privacy import pseudonymize
from app import learning_stream

DATASET = "santosh3110/credit_card_fraud_transactions"
ROWS_API = "https://datasets-server.huggingface.co/rows"
PAGE = 100  # HF /rows max length

# Per-card recent activity, to derive velocity / amount-spike features on the fly.
# Keyed by pseudonymized subject so we never key state on raw PII.
_recent: dict[str, deque] = defaultdict(lambda: deque(maxlen=50))


def _fetch_page(offset: int, length: int, max_retries: int = 6) -> list[dict]:
    """Fetch one page, backing off on Hugging Face rate limits (HTTP 429)."""
    params = {"dataset": DATASET, "config": "default", "split": "train",
              "offset": offset, "length": length}
    delay = 2.0
    for attempt in range(max_retries):
        r = requests.get(ROWS_API, params=params, timeout=30)
        if r.status_code == 429 or r.status_code >= 500:
            wait = float(r.headers.get("Retry-After", delay))
            print(f"    rate-limited ({r.status_code}); waiting {wait:.0f}s "
                  f"(attempt {attempt + 1}/{max_retries})", flush=True)
            time.sleep(wait)
            delay = min(delay * 2, 30)
            continue
        r.raise_for_status()
        return [row["row"] for row in r.json().get("rows", [])]
    raise RuntimeError(f"Gave up after {max_retries} retries at offset {offset}")


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
    city = (row.get("city") or "").strip()
    state = (row.get("state") or "").strip()
    location = ", ".join(p for p in (city, state) if p)
    return {
        "source": "public_dataset",
        "subject": subject,                       # already pseudonymized
        "transaction_id": row.get("trans_num"),
        "label": int(row.get("is_fraud") or 0),
        "features": features.tolist(),            # computed on ORIGINAL USD amount
        # Non-PII transaction attributes, shown in the live "stream of data" view.
        # Amount converted USD -> GHS at the live rate for this Ghana-based service.
        "amount": round(amount * _FX["rate"], 2),
        "currency": "GHS",
        # FX provenance travels with the event so the UI can show the rate + source.
        "fx_rate": _FX["rate"],
        "fx_source": _FX["source"],
        "fx_as_of": _FX["as_of"],
        "merchant_category": row.get("category"),
        "location": location or None,
        "occurred_at": datetime.fromtimestamp(unix_time, tz=timezone.utc).isoformat()
                        if unix_time else None,
    }


async def run(limit: int, offset: int, delay: float) -> None:
    fetch_fx()   # resolve the live USD->GHS rate before streaming
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
    print(f"\nNo more transactions in this run. Published {sent} events "
          f"({frauds} fraud, {sent - frauds} legit) to stream '{learning_stream.STREAM}'.")
    print("Producer ending. The consumer trains on each transaction one-by-one and now "
          "idles — it will resume automatically when more transactions arrive.")
    await learning_stream.close_producer()


if __name__ == "__main__":
    ap = argparse.ArgumentParser(description="Stream the public Sparkov fraud dataset into the learning pipeline.")
    ap.add_argument("--limit", type=int, default=2000, help="How many rows to stream.")
    ap.add_argument("--offset", type=int, default=0, help="Starting row offset in the dataset.")
    ap.add_argument("--delay", type=float, default=0.1,
                    help="Seconds between transactions (one-by-one live rate). Default 0.1 = ~10/s.")
    args = ap.parse_args()
    asyncio.run(run(args.limit, args.offset, args.delay))
