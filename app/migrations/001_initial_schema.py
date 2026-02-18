"""
migrations/001_initial_schema.py
---------------------------------
Run once to create the full production schema.

Usage:
    python -m migrations.001_initial_schema
    or via the Makefile:
    make migrate
"""
from __future__ import annotations

import os
import csv
import logging
from datetime import datetime, timezone

import psycopg2
from psycopg2.extras import execute_values
from dotenv import load_dotenv

load_dotenv()

logger = logging.getLogger(__name__)
logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")

DB_URL = os.getenv("DB_URL")
if not DB_URL:
    raise ValueError("DB_URL is not set in environment!")

# ─── Schema ───────────────────────────────────────────────────────────────────

SCHEMA_SQL = """
-- ============================================================
-- SENTINEL FRAUD DETECTION — PRODUCTION SCHEMA
-- ============================================================

-- Extension for UUID generation
CREATE EXTENSION IF NOT EXISTS "pgcrypto";


-- ─── Core: Transactions ──────────────────────────────────────
CREATE TABLE IF NOT EXISTS transactions (
    transaction_id      TEXT            PRIMARY KEY,
    user_id             TEXT            NOT NULL,
    amount              NUMERIC(18, 4)  NOT NULL CHECK (amount >= 0),
    currency            CHAR(3)         NOT NULL DEFAULT 'USD',
    merchant_id         TEXT,
    merchant_name       TEXT,
    merchant_category   TEXT,
    location            TEXT,
    country_code        CHAR(2),
    device_id           TEXT,
    ip_address          INET,
    channel             TEXT            DEFAULT 'online',   -- online | atm | pos | mobile
    timestamp           TIMESTAMPTZ     NOT NULL DEFAULT NOW(),
    created_at          TIMESTAMPTZ     NOT NULL DEFAULT NOW()
);

-- ─── Fraud Results ────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS fraud_results (
    id                  BIGSERIAL       PRIMARY KEY,
    transaction_id      TEXT            NOT NULL REFERENCES transactions(transaction_id) ON DELETE CASCADE,
    score               NUMERIC(5, 4)   NOT NULL CHECK (score BETWEEN 0 AND 1),
    decision            TEXT            NOT NULL CHECK (decision IN ('ALLOW', 'REVIEW', 'BLOCK')),
    reason              TEXT,
    signals             JSONB           NOT NULL DEFAULT '[]',
    model_version       TEXT            DEFAULT 'v2',
    processed_at        TIMESTAMPTZ     NOT NULL DEFAULT NOW(),
    UNIQUE (transaction_id)             -- one result per transaction
);

-- ─── Users (lightweight profile for history tracking) ────────
CREATE TABLE IF NOT EXISTS users (
    user_id             TEXT            PRIMARY KEY,
    created_at          TIMESTAMPTZ     NOT NULL DEFAULT NOW(),
    risk_tier           TEXT            DEFAULT 'standard',  -- standard | elevated | high
    is_flagged          BOOLEAN         NOT NULL DEFAULT FALSE,
    notes               TEXT
);

-- ─── Audit Log (immutable, append-only) ──────────────────────
-- Records every action taken on a fraud result by a human analyst
CREATE TABLE IF NOT EXISTS audit_log (
    id                  BIGSERIAL       PRIMARY KEY,
    transaction_id      TEXT            NOT NULL,
    analyst_id          TEXT,
    action              TEXT            NOT NULL,   -- CONFIRM_FRAUD | CLEAR | ESCALATE | NOTE
    previous_decision   TEXT,
    new_decision        TEXT,
    note                TEXT,
    created_at          TIMESTAMPTZ     NOT NULL DEFAULT NOW()
);

-- ─── Knowledge Base Metadata ──────────────────────────────────
-- Tracks every document ingested into the FAISS vector store
CREATE TABLE IF NOT EXISTS knowledge_documents (
    id                  BIGSERIAL       PRIMARY KEY,
    filename            TEXT            NOT NULL,
    file_type           TEXT            NOT NULL,
    size_bytes          BIGINT,
    source              TEXT            DEFAULT 'upload',  -- upload | web_scrape | manual
    ingested_at         TIMESTAMPTZ     NOT NULL DEFAULT NOW(),
    vector_count        INT,
    notes               TEXT
);

-- ─── Webhook / Integration Registry ──────────────────────────
-- Banks/partners register a webhook to receive real-time fraud decisions
CREATE TABLE IF NOT EXISTS integrations (
    id                  BIGSERIAL       PRIMARY KEY,
    partner_name        TEXT            NOT NULL,
    webhook_url         TEXT            NOT NULL,
    api_key_hash        TEXT            NOT NULL,
    is_active           BOOLEAN         NOT NULL DEFAULT TRUE,
    notify_on           TEXT[]          DEFAULT ARRAY['BLOCK', 'REVIEW'],
    created_at          TIMESTAMPTZ     NOT NULL DEFAULT NOW(),
    last_used_at        TIMESTAMPTZ
);


-- ============================================================
-- INDEXES
-- ============================================================

-- Transactions: most common query patterns
CREATE INDEX IF NOT EXISTS idx_txn_user_id       ON transactions(user_id);
CREATE INDEX IF NOT EXISTS idx_txn_timestamp     ON transactions(timestamp DESC);
CREATE INDEX IF NOT EXISTS idx_txn_location      ON transactions(location);
CREATE INDEX IF NOT EXISTS idx_txn_device        ON transactions(device_id);
CREATE INDEX IF NOT EXISTS idx_txn_merchant_cat  ON transactions(merchant_category);
CREATE INDEX IF NOT EXISTS idx_txn_country       ON transactions(country_code);
CREATE INDEX IF NOT EXISTS idx_txn_user_time     ON transactions(user_id, timestamp DESC);

-- Fraud results: dashboard queries
CREATE INDEX IF NOT EXISTS idx_fr_decision       ON fraud_results(decision);
CREATE INDEX IF NOT EXISTS idx_fr_score          ON fraud_results(score DESC);
CREATE INDEX IF NOT EXISTS idx_fr_processed_at   ON fraud_results(processed_at DESC);

-- Audit log
CREATE INDEX IF NOT EXISTS idx_audit_txn         ON audit_log(transaction_id);
CREATE INDEX IF NOT EXISTS idx_audit_analyst     ON audit_log(analyst_id);
CREATE INDEX IF NOT EXISTS idx_audit_created     ON audit_log(created_at DESC);


-- ============================================================
-- VIEWS (convenience for analytics queries)
-- ============================================================

CREATE OR REPLACE VIEW v_transaction_decisions AS
SELECT
    t.transaction_id,
    t.user_id,
    t.amount,
    t.currency,
    t.merchant_name,
    t.merchant_category,
    t.location,
    t.country_code,
    t.device_id,
    t.channel,
    t.timestamp,
    f.score,
    f.decision,
    f.signals,
    f.processed_at,
    f.model_version
FROM transactions t
LEFT JOIN fraud_results f USING (transaction_id);


CREATE OR REPLACE VIEW v_daily_fraud_summary AS
SELECT
    DATE_TRUNC('day', t.timestamp)  AS day,
    COUNT(*)                         AS total_transactions,
    COUNT(*) FILTER (WHERE f.decision = 'BLOCK')   AS blocked,
    COUNT(*) FILTER (WHERE f.decision = 'REVIEW')  AS reviewed,
    COUNT(*) FILTER (WHERE f.decision = 'ALLOW')   AS allowed,
    ROUND(AVG(f.score)::NUMERIC, 4)  AS avg_score,
    SUM(t.amount)                    AS total_amount,
    SUM(t.amount) FILTER (WHERE f.decision = 'BLOCK') AS blocked_amount
FROM transactions t
LEFT JOIN fraud_results f USING (transaction_id)
GROUP BY DATE_TRUNC('day', t.timestamp)
ORDER BY day DESC;
"""

# ─── Seed Data ────────────────────────────────────────────────────────────────

SEED_USERS_SQL = """
INSERT INTO users (user_id, risk_tier) VALUES
    ('user_123',  'standard'),
    ('user_456',  'elevated'),
    ('user_789',  'high')
ON CONFLICT (user_id) DO NOTHING;
"""

SEED_TRANSACTIONS_SQL = """
INSERT INTO transactions (
    transaction_id, user_id, amount, currency,
    merchant_name, merchant_category, location, country_code,
    device_id, channel, timestamp
) VALUES
-- Normal spending pattern
('txn_001', 'user_123', 25.00,   'USD', 'Amazon',          'retail',       'New York, US',  'US', 'dev_iphone14_a1b2', 'online',  NOW() - INTERVAL '5 days'),
('txn_002', 'user_123', 30.00,   'USD', 'Starbucks',        'food_delivery','New York, US',  'US', 'dev_iphone14_a1b2', 'pos',     NOW() - INTERVAL '4 days'),
('txn_003', 'user_123', 27.00,   'USD', 'Uber',             'travel',       'New York, US',  'US', 'dev_iphone14_a1b2', 'mobile',  NOW() - INTERVAL '3 days'),
('txn_004', 'user_123', 29.00,   'USD', 'Netflix',          'retail',       'New York, US',  'US', 'dev_iphone14_a1b2', 'online',  NOW() - INTERVAL '2 days'),

-- High-risk: large amount, new location, different device
('txn_005', 'user_123', 2500.00, 'USD', 'Unknown Merchant', 'wire_transfer','Moscow, RU',    'RU', 'dev_unknown_x9z1',  'online',  NOW() - INTERVAL '1 hour'),

-- Elevated user: moderate risk
('txn_006', 'user_456', 150.00,  'USD', 'Walmart',          'retail',       'Chicago, US',   'US', 'dev_android_c3d4',  'pos',     NOW() - INTERVAL '6 days'),
('txn_007', 'user_456', 890.00,  'USD', 'Crypto Exchange',  'crypto',       'London, GB',    'GB', 'dev_android_c3d4',  'online',  NOW() - INTERVAL '1 day'),

-- High-risk user: multiple suspicious patterns
('txn_008', 'user_789', 5000.00, 'USD', 'Wire Service',     'wire_transfer','Lagos, NG',     'NG', 'dev_unknown_y8w2',  'online',  NOW() - INTERVAL '3 hours'),
('txn_009', 'user_789', 4800.00, 'USD', 'Gift Card Store',  'gift_cards',   'Lagos, NG',     'NG', 'dev_unknown_y8w2',  'online',  NOW() - INTERVAL '2 hours'),
('txn_010', 'user_789', 4900.00, 'USD', 'Forex Exchange',   'forex',        'Lagos, NG',     'NG', 'dev_unknown_y8w2',  'online',  NOW() - INTERVAL '1 hour')
ON CONFLICT (transaction_id) DO NOTHING;
"""

SEED_FRAUD_RESULTS_SQL = """
INSERT INTO fraud_results (transaction_id, score, decision, signals) VALUES
('txn_001', 0.06, 'ALLOW',  '[]'),
('txn_002', 0.05, 'ALLOW',  '[]'),
('txn_003', 0.07, 'ALLOW',  '[]'),
('txn_004', 0.05, 'ALLOW',  '[]'),
('txn_005', 0.92, 'BLOCK',  '["High amount: $2500.00", "Location change: New York, US → Moscow, RU", "Impossible travel: location changed within 2 hours", "High-risk jurisdiction: RU", "High-risk merchant category: wire_transfer", "New/unrecognized device"]'),
('txn_006', 0.12, 'ALLOW',  '[]'),
('txn_007', 0.55, 'REVIEW', '["High amount: $890.00", "Location change: Chicago, US → London, GB", "High-risk merchant category: crypto"]'),
('txn_008', 0.88, 'BLOCK',  '["Very high amount: $5000.00", "High-risk merchant category: wire_transfer"]'),
('txn_009', 0.86, 'BLOCK',  '["Very high amount: $4800.00", "High-risk merchant category: gift_cards", "High velocity: 3 transactions in last hour"]'),
('txn_010', 0.87, 'BLOCK',  '["Very high amount: $4900.00", "High-risk merchant category: forex", "High velocity: 3 transactions in last hour"]')
ON CONFLICT (transaction_id) DO NOTHING;
"""


# ─── CSV Loader ───────────────────────────────────────────────────────────────

def load_csv_seed(conn, csv_file: str) -> int:
    """
    Load transactions from a CSV file into the database.
    Expected columns (extra columns are ignored):
        transaction_id, user_id, amount, currency,
        merchant_name (or merchant), merchant_category,
        location, country_code, device_id, channel, timestamp
    """
    if not os.path.exists(csv_file):
        logger.warning("CSV seed file not found: %s — skipping.", csv_file)
        return 0

    with open(csv_file, "r", encoding="utf-8") as f:
        reader = csv.DictReader(f)
        rows = []
        for row in reader:
            rows.append((
                row["transaction_id"],
                row["user_id"],
                float(row["amount"]),
                row.get("currency", "USD"),
                row.get("merchant_name") or row.get("merchant"),
                row.get("merchant_category"),
                row.get("location"),
                row.get("country_code"),
                row.get("device_id"),
                row.get("channel", "online"),
                row["timestamp"],
            ))

    if not rows:
        return 0

    cur = conn.cursor()
    execute_values(
        cur,
        """
        INSERT INTO transactions (
            transaction_id, user_id, amount, currency,
            merchant_name, merchant_category, location, country_code,
            device_id, channel, timestamp
        )
        VALUES %s
        ON CONFLICT (transaction_id) DO NOTHING
        """,
        rows,
    )
    conn.commit()
    cur.close()
    logger.info("CSV seed: inserted %d rows from %s", len(rows), csv_file)
    return len(rows)


# ─── Runner ───────────────────────────────────────────────────────────────────

def run(csv_seed_file: str | None = None):
    logger.info("Connecting to database…")
    conn = psycopg2.connect(DB_URL)

    try:
        cur = conn.cursor()

        logger.info("Running schema migration…")
        cur.execute(SCHEMA_SQL)
        conn.commit()
        logger.info("Schema created/verified ✓")

        logger.info("Seeding users…")
        cur.execute(SEED_USERS_SQL)
        conn.commit()

        logger.info("Seeding transactions…")
        cur.execute(SEED_TRANSACTIONS_SQL)
        conn.commit()

        logger.info("Seeding fraud results…")
        cur.execute(SEED_FRAUD_RESULTS_SQL)
        conn.commit()

        cur.close()
        logger.info("Seed data inserted ✓")

        if csv_seed_file:
            load_csv_seed(conn, csv_seed_file)

        logger.info("Migration complete ✓")

    except Exception as e:
        conn.rollback()
        logger.error("Migration failed: %s", e)
        raise

    finally:
        conn.close()


if __name__ == "__main__":
    import sys
    csv_path = sys.argv[1] if len(sys.argv) > 1 else "data/fraud_docs/csv/transactions_10000.csv"
    run(csv_seed_file=csv_path)