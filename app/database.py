"""
database.py
-----------
Async PostgreSQL data access layer using asyncpg with:
  - Connection pooling (no per-call connect/close overhead)
  - Full support for updated Transaction & FraudResult models
  - save_fraud_result() for persisting detection outputs
  - get_all_transactions() with filters (limit, offset, user_id, decision)
  - Bulk CSV ingestion via executemany
"""
from __future__ import annotations

import csv
import io
import json
import logging
import os
from typing import List, Optional

import asyncpg
from dotenv import load_dotenv

from app.models import FraudResult, Transaction

load_dotenv()

DB_URL: str = os.getenv("DB_URL", "")
if not DB_URL:
    raise ValueError("DB_URL is not set in environment!")

logger = logging.getLogger(__name__)

# ─── Connection Pool ──────────────────────────────────────────────────────────
# Initialise once at startup via init_db() called from main.py lifespan.

_pool: Optional[asyncpg.Pool] = None


async def init_db() -> None:
    """Create the connection pool and ensure tables exist. Call on app startup."""
    global _pool
    _pool = await asyncpg.create_pool(DB_URL, min_size=2, max_size=10)
    await _create_tables()
    logger.info("Database pool initialised.")


async def close_db() -> None:
    """Gracefully close the pool. Call on app shutdown."""
    if _pool:
        await _pool.close()
        logger.info("Database pool closed.")


async def _get_pool() -> asyncpg.Pool:
    if _pool is None:
        raise RuntimeError("Database pool not initialised. Call init_db() at startup.")
    return _pool


# ─── Schema Bootstrap ─────────────────────────────────────────────────────────

async def _create_tables() -> None:
    pool = await _get_pool()
    async with pool.acquire() as conn:
        await conn.execute("""
            CREATE TABLE IF NOT EXISTS transactions (
                transaction_id   TEXT PRIMARY KEY,
                user_id          TEXT NOT NULL,
                amount           DOUBLE PRECISION NOT NULL,
                currency         TEXT NOT NULL DEFAULT 'USD',
                merchant_id      TEXT,
                merchant_category TEXT,
                location         TEXT,
                device_id        TEXT,
                ip_address       TEXT,
                timestamp        TIMESTAMPTZ NOT NULL DEFAULT NOW()
            );

            CREATE TABLE IF NOT EXISTS fraud_results (
                transaction_id   TEXT PRIMARY KEY,
                score            DOUBLE PRECISION NOT NULL,
                decision         TEXT NOT NULL,
                reason           TEXT,
                signals          JSONB NOT NULL DEFAULT '[]',
                processed_at     TIMESTAMPTZ NOT NULL DEFAULT NOW(),
                FOREIGN KEY (transaction_id) REFERENCES transactions(transaction_id) ON DELETE CASCADE
            );

            CREATE INDEX IF NOT EXISTS idx_txn_user_id    ON transactions(user_id);
            CREATE INDEX IF NOT EXISTS idx_txn_timestamp  ON transactions(timestamp DESC);
            CREATE INDEX IF NOT EXISTS idx_fr_decision    ON fraud_results(decision);
        """)


# ─── Transactions ─────────────────────────────────────────────────────────────

async def get_user_history(user_id: str, limit: int = 20) -> List[Transaction]:
    pool = await _get_pool()
    async with pool.acquire() as conn:
        rows = await conn.fetch(
            """
            SELECT t.*, f.decision, f.score, f.signals
            FROM transactions t
            LEFT JOIN fraud_results f USING (transaction_id)
            WHERE t.user_id = $1
            ORDER BY t.timestamp DESC
            LIMIT $2
            """,
            user_id, limit,
        )
    logger.debug("get_user_history: %d rows for user %s", len(rows), user_id)
    return [_row_to_transaction(r) for r in rows]


async def get_transaction_by_id(transaction_id: str) -> Optional[Transaction]:
    pool = await _get_pool()
    async with pool.acquire() as conn:
        row = await conn.fetchrow(
            """
            SELECT t.*, f.decision, f.score, f.signals
            FROM transactions t
            LEFT JOIN fraud_results f USING (transaction_id)
            WHERE t.transaction_id = $1
            """,
            transaction_id,
        )
    if row:
        return _row_to_transaction(row)
    return None


async def get_all_transactions(
    limit: int = 200,
    offset: int = 0,
    user_id: Optional[str] = None,
    decision: Optional[str] = None,
) -> List[Transaction]:
    """
    Fetch transactions joined with their fraud result.
    Supports filtering by user_id and/or decision (ALLOW | REVIEW | BLOCK).
    """
    pool = await _get_pool()

    conditions = []
    params: list = []
    idx = 1

    if user_id:
        conditions.append(f"t.user_id = ${idx}")
        params.append(user_id)
        idx += 1

    if decision:
        conditions.append(f"f.decision = ${idx}")
        params.append(decision)
        idx += 1

    where_clause = ("WHERE " + " AND ".join(conditions)) if conditions else ""

    params += [limit, offset]
    query = f"""
        SELECT t.*, f.decision, f.score, f.signals
        FROM transactions t
        LEFT JOIN fraud_results f USING (transaction_id)
        {where_clause}
        ORDER BY t.timestamp DESC
        LIMIT ${idx} OFFSET ${idx + 1}
    """

    async with pool.acquire() as conn:
        rows = await conn.fetch(query, *params)

    return [_row_to_transaction(r) for r in rows]


async def save_transaction(txn: Transaction) -> None:
    """Upsert a single transaction record."""
    pool = await _get_pool()
    async with pool.acquire() as conn:
        await conn.execute(
            """
            INSERT INTO transactions (
                transaction_id, user_id, amount, currency,
                merchant_id, merchant_category, location,
                device_id, ip_address, timestamp
            )
            VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)
            ON CONFLICT (transaction_id) DO UPDATE SET
                amount            = EXCLUDED.amount,
                merchant_category = EXCLUDED.merchant_category,
                location          = EXCLUDED.location,
                device_id         = EXCLUDED.device_id
            """,
            txn.transaction_id,
            txn.user_id,
            txn.amount,
            txn.currency,
            txn.merchant_id,
            txn.merchant_category,
            txn.location,
            txn.device_id,
            txn.ip_address,
            txn.timestamp,
        )


# ─── Fraud Results ────────────────────────────────────────────────────────────

async def save_fraud_result(result: FraudResult, txn: Optional[Transaction] = None) -> None:
    """
    Persist a FraudResult atomically.

    The FK constraint requires transactions.transaction_id to exist BEFORE
    fraud_results can reference it.  We solve this by:
      1. Upserting the Transaction first (if provided).
      2. Upserting the FraudResult second.
    Both writes share the same connection and are wrapped in a single
    database transaction so they succeed or fail together.

    The `txn` argument should always be supplied from the router layer.
    If it is somehow omitted, we attempt a bare SELECT to verify the parent
    row exists and raise a clear error rather than letting Postgres surface a
    cryptic FK violation.
    """
    pool = await _get_pool()
    async with pool.acquire() as conn:
        async with conn.transaction():          # ← atomic: both writes or neither

            # ── Step 1: guarantee the parent row exists ──────────────────────
            if txn is not None:
                await conn.execute(
                    """
                    INSERT INTO transactions (
                        transaction_id, user_id, amount, currency,
                        merchant_id, merchant_category, location,
                        device_id, ip_address, timestamp
                    )
                    VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)
                    ON CONFLICT (transaction_id) DO UPDATE SET
                        amount            = EXCLUDED.amount,
                        merchant_category = EXCLUDED.merchant_category,
                        location          = EXCLUDED.location,
                        device_id         = EXCLUDED.device_id
                    """,
                    txn.transaction_id,
                    txn.user_id,
                    txn.amount,
                    txn.currency,
                    txn.merchant_id,
                    txn.merchant_category,
                    txn.location,
                    txn.device_id,
                    txn.ip_address,
                    txn.timestamp,
                )
            else:
                # No Transaction object supplied — verify the row already exists
                exists = await conn.fetchval(
                    "SELECT 1 FROM transactions WHERE transaction_id = $1",
                    result.transaction_id,
                )
                if not exists:
                    raise ValueError(
                        f"Cannot save FraudResult: transaction '{result.transaction_id}' "
                        f"does not exist in the transactions table. "
                        f"Pass the original Transaction object to save_fraud_result()."
                    )

            # ── Step 2: upsert the fraud result ──────────────────────────────
            await conn.execute(
                """
                INSERT INTO fraud_results (
                    transaction_id, score, decision, reason, signals, processed_at
                )
                VALUES ($1, $2, $3, $4, $5::jsonb, $6)
                ON CONFLICT (transaction_id) DO UPDATE SET
                    score        = EXCLUDED.score,
                    decision     = EXCLUDED.decision,
                    reason       = EXCLUDED.reason,
                    signals      = EXCLUDED.signals,
                    processed_at = EXCLUDED.processed_at
                """,
                result.transaction_id,
                result.score,
                result.decision,
                result.reason,
                json.dumps(result.signals),
                result.processed_at,
            )

    logger.debug(
        "Saved transaction + fraud result for %s: %s (%.2f)",
        result.transaction_id, result.decision, result.score,
    )


# ─── CSV Ingestion ────────────────────────────────────────────────────────────

async def save_csv_to_db(filename: str, content: bytes) -> int:
    """
    Parse an uploaded CSV and insert rows one by one.
    Returns the number of rows inserted.
    Columns accepted: transaction_id, user_id, amount, currency,
                      merchant_id, merchant_category, location,
                      device_id, ip_address, timestamp
    """
    reader = csv.DictReader(io.StringIO(content.decode("utf-8")))
    count = 0

    pool = await _get_pool()
    async with pool.acquire() as conn:
        for row in reader:
            try:
                await conn.execute(
                    """
                    INSERT INTO transactions (
                        transaction_id, user_id, amount, currency,
                        merchant_id, merchant_category, location,
                        device_id, ip_address, timestamp
                    )
                    VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)
                    ON CONFLICT (transaction_id) DO NOTHING
                    """,
                    row["transaction_id"],
                    row["user_id"],
                    float(row["amount"]),
                    row.get("currency", "USD"),
                    row.get("merchant_id") or row.get("merchant"),
                    row.get("merchant_category"),
                    row.get("location"),
                    row.get("device_id"),
                    row.get("ip_address"),
                    row["timestamp"],
                )
                count += 1
            except Exception as e:
                logger.warning("Skipping row in %s: %s — %s", filename, row.get("transaction_id"), e)

    logger.info("%s: %d rows inserted", filename, count)
    return count


async def save_bulk_csv_to_db(filename: str, content: bytes) -> int:
    """
    High-performance bulk CSV insert using executemany.
    Returns the number of records prepared for insertion.
    """
    reader = csv.DictReader(io.StringIO(content.decode("utf-8")))

    records = []
    for row in reader:
        try:
            records.append((
                row["transaction_id"],
                row["user_id"],
                float(row["amount"]),
                row.get("currency", "USD"),
                row.get("merchant_id") or row.get("merchant"),
                row.get("merchant_category"),
                row.get("location"),
                row.get("device_id"),
                row.get("ip_address"),
                row["timestamp"],
            ))
        except (KeyError, ValueError) as e:
            logger.warning("Skipping malformed row in %s: %s", filename, e)

    if not records:
        logger.warning("%s: no valid rows to insert", filename)
        return 0

    pool = await _get_pool()
    async with pool.acquire() as conn:
        await conn.executemany(
            """
            INSERT INTO transactions (
                transaction_id, user_id, amount, currency,
                merchant_id, merchant_category, location,
                device_id, ip_address, timestamp
            )
            VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)
            ON CONFLICT (transaction_id) DO NOTHING
            """,
            records,
        )

    logger.info("%s: %d rows bulk-inserted", filename, len(records))
    return len(records)


async def load_csv_transactions(
    csv_file: str = "data/fraud_docs/csv/transactions_10000.csv",
) -> None:
    """Load transactions from a file path on disk (used for seeding/testing)."""
    with open(csv_file, "r", encoding="utf-8") as f:
        content = f.read().encode("utf-8")

    count = await save_bulk_csv_to_db(os.path.basename(csv_file), content)
    print(f"Loaded {count} transactions from {csv_file}.")


# ─── Row Mapper ───────────────────────────────────────────────────────────────

def _row_to_transaction(row: asyncpg.Record) -> Transaction:
    """
    Map a DB row (transactions JOIN fraud_results) to a Transaction model.
    Extra columns from the join (decision, score, signals) are attached
    as dynamic attributes so the analytics layer can read them.
    """
    data = dict(row)

    # Pull out fraud_results columns before feeding into Transaction
    decision = data.pop("decision", None)
    score = data.pop("score", None)
    raw_signals = data.pop("signals", None)

    signals: list[str] = []
    if isinstance(raw_signals, str):
        try:
            signals = json.loads(raw_signals)
        except json.JSONDecodeError:
            signals = []
    elif isinstance(raw_signals, list):
        signals = raw_signals

    txn = Transaction(**data)

    # Attach fraud result data as extra attributes for analytics use
    txn.__dict__["decision"] = decision
    txn.__dict__["score"] = score
    txn.__dict__["signals"] = signals

    return txn