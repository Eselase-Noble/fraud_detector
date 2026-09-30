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

            -- Feature vector captured at scoring time so the online model can be
            -- trained later (on analyst feedback) against the exact same inputs.
            ALTER TABLE fraud_results ADD COLUMN IF NOT EXISTS features JSONB;

            -- Durable weights for the online-learning model. One row per model.
            CREATE TABLE IF NOT EXISTS model_state (
                name        TEXT PRIMARY KEY,
                state       JSONB NOT NULL,
                updated_at  TIMESTAMPTZ NOT NULL DEFAULT NOW()
            );

            -- Append-only log of every online-learning step. This is how the
            -- learning is *tracked*: each row stores the model's PRE-update
            -- prediction vs. the true label (prequential / test-then-train),
            -- so rolling accuracy/precision/recall can be computed over time.
            -- It holds ONLY pseudonymous subject tokens — no raw PII.
            CREATE TABLE IF NOT EXISTS training_events (
                id               BIGSERIAL PRIMARY KEY,
                event_time       TIMESTAMPTZ NOT NULL DEFAULT NOW(),
                occurred_at      TIMESTAMPTZ,
                source           TEXT NOT NULL,
                subject_hash     TEXT,
                transaction_id   TEXT,
                label            SMALLINT NOT NULL,
                predicted_proba  DOUBLE PRECISION,
                predicted_label  SMALLINT,
                correct          BOOLEAN,
                loss             DOUBLE PRECISION,
                influence        DOUBLE PRECISION,
                model_version    TEXT,
                pepper_fp        TEXT
            );
            CREATE INDEX IF NOT EXISTS idx_train_evt_time ON training_events(event_time DESC);
            CREATE INDEX IF NOT EXISTS idx_train_evt_src  ON training_events(source);

            CREATE TABLE IF NOT EXISTS users (
                user_id     TEXT PRIMARY KEY,
                created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW(),
                risk_tier   TEXT DEFAULT 'standard',
                is_flagged  BOOLEAN NOT NULL DEFAULT FALSE,
                notes       TEXT
            );

            CREATE TABLE IF NOT EXISTS audit_log (
                id                BIGSERIAL PRIMARY KEY,
                transaction_id    TEXT NOT NULL,
                analyst_id        TEXT,
                action            TEXT NOT NULL,
                previous_decision TEXT,
                new_decision      TEXT,
                note              TEXT,
                created_at        TIMESTAMPTZ NOT NULL DEFAULT NOW()
            );

            CREATE TABLE IF NOT EXISTS knowledge_documents (
                id           BIGSERIAL PRIMARY KEY,
                filename     TEXT NOT NULL,
                file_type    TEXT NOT NULL,
                size_bytes   BIGINT,
                source       TEXT DEFAULT 'upload',
                ingested_at  TIMESTAMPTZ NOT NULL DEFAULT NOW(),
                vector_count INT,
                notes        TEXT
            );

            -- Sentinel staff (operator console login). Separate from partner logins.
            CREATE TABLE IF NOT EXISTS staff_users (
                id            BIGSERIAL PRIMARY KEY,
                email         TEXT UNIQUE NOT NULL,
                password_hash TEXT NOT NULL,
                name          TEXT,
                role          TEXT NOT NULL DEFAULT 'operator',
                is_active     BOOLEAN NOT NULL DEFAULT TRUE,
                created_at    TIMESTAMPTZ NOT NULL DEFAULT NOW()
            );

            CREATE TABLE IF NOT EXISTS integrations (
                id           BIGSERIAL PRIMARY KEY,
                partner_name TEXT NOT NULL,
                webhook_url  TEXT NOT NULL,
                api_key_hash TEXT NOT NULL,
                is_active    BOOLEAN NOT NULL DEFAULT TRUE,
                notify_on    TEXT[] DEFAULT ARRAY['BLOCK', 'REVIEW'],
                created_at   TIMESTAMPTZ NOT NULL DEFAULT NOW(),
                last_used_at TIMESTAMPTZ
            );

            -- Partner registry serves any financial institution (bank, fintech, PSP,
            -- microfinance, mobile money, SACCO…) and records how they feed us data.
            ALTER TABLE integrations ADD COLUMN IF NOT EXISTS institution_type  TEXT DEFAULT 'bank';
            ALTER TABLE integrations ADD COLUMN IF NOT EXISTS connection_method TEXT DEFAULT 'rest_api';
            ALTER TABLE integrations ADD COLUMN IF NOT EXISTS contact_email     TEXT;
            -- Human portal login (distinct from the machine API key).
            ALTER TABLE integrations ADD COLUMN IF NOT EXISTS portal_email         TEXT;
            ALTER TABLE integrations ADD COLUMN IF NOT EXISTS portal_password_hash TEXT;
            CREATE UNIQUE INDEX IF NOT EXISTS idx_integrations_portal_email
                ON integrations(portal_email) WHERE portal_email IS NOT NULL;

            -- Partner staff: multiple users per institution, managed in the portal.
            CREATE TABLE IF NOT EXISTS partner_users (
                id             BIGSERIAL PRIMARY KEY,
                integration_id BIGINT NOT NULL REFERENCES integrations(id) ON DELETE CASCADE,
                email          TEXT UNIQUE NOT NULL,
                password_hash  TEXT NOT NULL,
                name           TEXT,
                role           TEXT NOT NULL DEFAULT 'admin',  -- admin | analyst | viewer
                is_active      BOOLEAN NOT NULL DEFAULT TRUE,
                created_at     TIMESTAMPTZ NOT NULL DEFAULT NOW()
            );
            CREATE INDEX IF NOT EXISTS idx_partner_users_integration ON partner_users(integration_id);

            -- Attribute each scored transaction to the partner whose key produced it.
            ALTER TABLE transactions ADD COLUMN IF NOT EXISTS integration_id BIGINT;
            CREATE INDEX IF NOT EXISTS idx_txn_integration ON transactions(integration_id);

            CREATE INDEX IF NOT EXISTS idx_txn_user_id    ON transactions(user_id);
            CREATE INDEX IF NOT EXISTS idx_txn_timestamp  ON transactions(timestamp DESC);
            CREATE INDEX IF NOT EXISTS idx_fr_decision    ON fraud_results(decision);
            CREATE INDEX IF NOT EXISTS idx_audit_txn      ON audit_log(transaction_id);
            CREATE INDEX IF NOT EXISTS idx_audit_analyst  ON audit_log(analyst_id);
            CREATE INDEX IF NOT EXISTS idx_audit_created  ON audit_log(created_at DESC);
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
    include_partner: bool = False,
) -> List[Transaction]:
    """
    Fetch transactions joined with their fraud result.
    Supports filtering by user_id and/or decision (ALLOW | REVIEW | BLOCK).

    By default this EXCLUDES partner-attributed transactions (integration_id set):
    the operator console must not see partners' private transaction data. Partner
    data is served only through the tenant-scoped portal endpoints.
    """
    pool = await _get_pool()

    conditions = []
    params: list = []
    idx = 1

    if not include_partner:
        conditions.append("t.integration_id IS NULL")

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


async def get_partner_transactions(
    integration_id: int, limit: int = 100, offset: int = 0,
    decision: Optional[str] = None, search: Optional[str] = None,
) -> List[Transaction]:
    """Transactions attributed to a single partner integration, with their decisions."""
    conditions = ["t.integration_id = $1"]
    params: list = [integration_id]
    idx = 2
    if decision:
        conditions.append(f"f.decision = ${idx}"); params.append(decision); idx += 1
    if search:
        conditions.append(f"(t.user_id ILIKE ${idx} OR t.transaction_id ILIKE ${idx})")
        params.append(f"%{search}%"); idx += 1
    where = "WHERE " + " AND ".join(conditions)
    params += [limit, offset]
    query = f"""
        SELECT t.*, f.decision, f.score, f.signals
        FROM transactions t
        LEFT JOIN fraud_results f USING (transaction_id)
        {where}
        ORDER BY t.timestamp DESC
        LIMIT ${idx} OFFSET ${idx + 1}
    """
    pool = await _get_pool()
    async with pool.acquire() as conn:
        rows = await conn.fetch(query, *params)
    return [_row_to_transaction(r) for r in rows]


async def get_partner_transaction_rows(
    integration_id: int, limit: int = 100, offset: int = 0,
    decision: Optional[str] = None, search: Optional[str] = None,
) -> list:
    """Raw transaction+decision rows (incl. reason) for the portal list view."""
    conditions = ["t.integration_id = $1"]
    params: list = [integration_id]
    idx = 2
    if decision:
        conditions.append(f"f.decision = ${idx}"); params.append(decision); idx += 1
    if search:
        conditions.append(f"(t.user_id ILIKE ${idx} OR t.transaction_id ILIKE ${idx})")
        params.append(f"%{search}%"); idx += 1
    where = "WHERE " + " AND ".join(conditions)
    params += [limit, offset]
    query = f"""
        SELECT t.transaction_id, t.user_id, t.amount, t.currency, t.location,
               t.merchant_category, t.timestamp,
               f.decision, f.score, f.reason, f.signals
        FROM transactions t
        LEFT JOIN fraud_results f USING (transaction_id)
        {where}
        ORDER BY t.timestamp DESC
        LIMIT ${idx} OFFSET ${idx + 1}
    """
    pool = await _get_pool()
    async with pool.acquire() as conn:
        rows = await conn.fetch(query, *params)
    out = []
    for r in rows:
        d = dict(r)
        sig = d.get("signals")
        if isinstance(sig, str):
            try: d["signals"] = json.loads(sig)
            except json.JSONDecodeError: d["signals"] = []
        if d.get("amount") is not None:
            d["amount"] = float(d["amount"])
        out.append(d)
    return out


async def get_partner_usage(integration_id: int) -> dict:
    """Decision counts + flagged amount for one partner integration."""
    pool = await _get_pool()
    async with pool.acquire() as conn:
        row = await conn.fetchrow(
            """
            SELECT
                COUNT(*)                                            AS scored,
                COUNT(*) FILTER (WHERE f.decision = 'BLOCK')        AS blocked,
                COUNT(*) FILTER (WHERE f.decision = 'REVIEW')       AS reviewed,
                COUNT(*) FILTER (WHERE f.decision = 'ALLOW')        AS allowed,
                COALESCE(SUM(t.amount) FILTER (WHERE f.decision IN ('BLOCK','REVIEW')), 0) AS flagged_amount
            FROM transactions t
            LEFT JOIN fraud_results f USING (transaction_id)
            WHERE t.integration_id = $1
            """,
            integration_id,
        )
    return {
        "scored": row["scored"] or 0, "blocked": row["blocked"] or 0,
        "reviewed": row["reviewed"] or 0, "allowed": row["allowed"] or 0,
        "flagged_amount": float(row["flagged_amount"] or 0),
    }


async def resolve_integration_id_by_key(api_key: str) -> Optional[int]:
    """Return the integration id for a raw API key (used to attribute detections)."""
    import hashlib
    key_hash = hashlib.sha256(api_key.strip().encode()).hexdigest()
    pool = await _get_pool()
    async with pool.acquire() as conn:
        return await conn.fetchval(
            "SELECT id FROM integrations WHERE api_key_hash = $1 AND is_active", key_hash
        )


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

async def save_fraud_result(result: FraudResult, txn: Optional[Transaction] = None,
                            integration_id: Optional[int] = None) -> None:
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
                        device_id, ip_address, timestamp, integration_id
                    )
                    VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11)
                    ON CONFLICT (transaction_id) DO UPDATE SET
                amount            = EXCLUDED.amount,
                merchant_category = EXCLUDED.merchant_category,
                location          = EXCLUDED.location,
                device_id         = EXCLUDED.device_id,
                integration_id    = COALESCE(EXCLUDED.integration_id, transactions.integration_id)
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
                    integration_id,
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
                    transaction_id, score, decision, reason, signals, features, processed_at
                )
                VALUES ($1, $2, $3, $4, $5::jsonb, $6::jsonb, $7)
                ON CONFLICT (transaction_id) DO UPDATE SET
                    score        = EXCLUDED.score,
                    decision     = EXCLUDED.decision,
                    reason       = EXCLUDED.reason,
                    signals      = EXCLUDED.signals,
                    features     = EXCLUDED.features,
                    processed_at = EXCLUDED.processed_at
                """,
                result.transaction_id,
                result.score,
                result.decision,
                result.reason,
                json.dumps(result.signals),
                json.dumps(result.features) if result.features else None,
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
                    ON CONFLICT (transaction_id) DO UPDATE SET
                    score        = EXCLUDED.score,
                    decision     = EXCLUDED.decision,
                    reason       = EXCLUDED.reason,
                    signals      = EXCLUDED.signals,
                    processed_at = EXCLUDED.processed_at
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
            ON CONFLICT (transaction_id) DO UPDATE SET
                    score        = EXCLUDED.score,
                    decision     = EXCLUDED.decision,
                    reason       = EXCLUDED.reason,
                    signals      = EXCLUDED.signals,
                    processed_at = EXCLUDED.processed_at
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


# ─── Online-Learning Model State & Feedback ───────────────────────────────────

async def load_model_state(name: str) -> Optional[dict]:
    """Return the persisted weights/state for an online model, or None."""
    pool = await _get_pool()
    async with pool.acquire() as conn:
        raw = await conn.fetchval("SELECT state FROM model_state WHERE name = $1", name)
    if raw is None:
        return None
    if isinstance(raw, str):
        try:
            return json.loads(raw)
        except json.JSONDecodeError:
            return None
    return raw


async def save_model_state(name: str, state: dict) -> None:
    """Persist (upsert) the online model's weights/state."""
    pool = await _get_pool()
    async with pool.acquire() as conn:
        await conn.execute(
            """
            INSERT INTO model_state (name, state, updated_at)
            VALUES ($1, $2::jsonb, NOW())
            ON CONFLICT (name) DO UPDATE SET
                state = EXCLUDED.state,
                updated_at = NOW()
            """,
            name, json.dumps(state),
        )


async def insert_training_event(evt: dict) -> None:
    """Record one online-learning step for tracking/observability."""
    pool = await _get_pool()
    async with pool.acquire() as conn:
        await conn.execute(
            """
            INSERT INTO training_events (
                occurred_at, source, subject_hash, transaction_id, label,
                predicted_proba, predicted_label, correct, loss, influence,
                model_version, pepper_fp
            ) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12)
            """,
            evt.get("occurred_at"), evt["source"], evt.get("subject_hash"),
            evt.get("transaction_id"), evt["label"], evt.get("predicted_proba"),
            evt.get("predicted_label"), evt.get("correct"), evt.get("loss"),
            evt.get("influence"), evt.get("model_version"), evt.get("pepper_fp"),
        )


async def get_learning_metrics(window: int = 500) -> dict:
    """Prequential metrics over the most recent `window` learning events.

    Because each row holds the pre-update prediction, this is an honest
    test-then-train estimate of live model quality (no train/test leakage).
    """
    pool = await _get_pool()
    async with pool.acquire() as conn:
        total = await conn.fetchval("SELECT COUNT(*) FROM training_events")
        row = await conn.fetchrow(
            """
            WITH recent AS (
                SELECT * FROM training_events ORDER BY id DESC LIMIT $1
            )
            SELECT
                COUNT(*)                                                   AS n,
                AVG(CASE WHEN correct THEN 1.0 ELSE 0.0 END)               AS accuracy,
                COUNT(*) FILTER (WHERE label = 1)                          AS actual_pos,
                COUNT(*) FILTER (WHERE predicted_label = 1)                AS pred_pos,
                COUNT(*) FILTER (WHERE label = 1 AND predicted_label = 1)  AS tp,
                COUNT(*) FILTER (WHERE label = 0 AND predicted_label = 1)  AS fp,
                COUNT(*) FILTER (WHERE label = 1 AND predicted_label = 0)  AS fn,
                AVG(loss)                                                  AS avg_loss
            FROM recent
            """,
            window,
        )
    tp, fp, fn = (row["tp"] or 0), (row["fp"] or 0), (row["fn"] or 0)
    precision = tp / (tp + fp) if (tp + fp) else None
    recall = tp / (tp + fn) if (tp + fn) else None
    f1 = (2 * precision * recall / (precision + recall)
          if precision and recall else None)
    return {
        "total_events": total or 0,
        "window": window,
        "window_count": row["n"] or 0,
        "accuracy": round(row["accuracy"], 4) if row["accuracy"] is not None else None,
        "precision": round(precision, 4) if precision is not None else None,
        "recall": round(recall, 4) if recall is not None else None,
        "f1": round(f1, 4) if f1 is not None else None,
        "avg_loss": round(row["avg_loss"], 4) if row["avg_loss"] is not None else None,
        "fraud_labels": row["actual_pos"] or 0,
    }


async def get_learning_curve(buckets: int = 20, window: int = 2000) -> list[dict]:
    """Rolling accuracy across `buckets` chunks of the recent event stream.

    Returns oldest→newest so the frontend can draw a learning curve.
    """
    pool = await _get_pool()
    async with pool.acquire() as conn:
        rows = await conn.fetch(
            """
            WITH recent AS (
                SELECT id, correct, label, predicted_label
                FROM training_events ORDER BY id DESC LIMIT $2
            ), numbered AS (
                SELECT *, ntile($1) OVER (ORDER BY id) AS bucket FROM recent
            )
            SELECT bucket,
                   COUNT(*)                                       AS n,
                   AVG(CASE WHEN correct THEN 1.0 ELSE 0.0 END)   AS accuracy,
                   MIN(id)                                        AS from_id
            FROM numbered GROUP BY bucket ORDER BY bucket
            """,
            buckets, window,
        )
    return [{"bucket": r["bucket"], "n": r["n"],
             "accuracy": round(r["accuracy"], 4) if r["accuracy"] is not None else None}
            for r in rows]


async def get_recent_training_events(limit: int = 25) -> list[dict]:
    """Most recent learning steps (already anonymized — safe to display)."""
    pool = await _get_pool()
    async with pool.acquire() as conn:
        rows = await conn.fetch(
            """
            SELECT event_time, source, subject_hash, transaction_id, label,
                   predicted_proba, predicted_label, correct, influence, model_version
            FROM training_events ORDER BY id DESC LIMIT $1
            """,
            limit,
        )
    out = []
    for r in rows:
        d = dict(r)
        if d.get("predicted_proba") is not None:
            d["predicted_proba"] = round(float(d["predicted_proba"]), 4)
        out.append(d)
    return out


async def count_by_source() -> list[dict]:
    """How many learning events each source has contributed."""
    pool = await _get_pool()
    async with pool.acquire() as conn:
        rows = await conn.fetch(
            "SELECT source, COUNT(*) AS n FROM training_events GROUP BY source ORDER BY n DESC"
        )
    return [{"source": r["source"], "count": r["n"]} for r in rows]


async def get_result_features(transaction_id: str) -> Optional[list]:
    """Fetch the feature vector captured when a transaction was scored.

    Needed to train the online model on analyst feedback against the exact
    inputs the model saw at decision time.
    """
    pool = await _get_pool()
    async with pool.acquire() as conn:
        raw = await conn.fetchval(
            "SELECT features FROM fraud_results WHERE transaction_id = $1", transaction_id
        )
    if raw is None:
        return None
    if isinstance(raw, str):
        try:
            return json.loads(raw)
        except json.JSONDecodeError:
            return None
    return raw


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

    # ✅ Convert IPv4Address -> string
    if data.get("ip_address") is not None:
        data["ip_address"] = str(data["ip_address"])

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