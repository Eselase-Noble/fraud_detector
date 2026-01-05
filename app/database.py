import os

import asyncpg
import csv
from typing import List
from app.models import Transaction
from dotenv import load_dotenv

load_dotenv()  # loads variables from .env file
DB_URL = os.getenv("DB_URL")


# ----------------------------
# Existing helper: user history
# ----------------------------
async def get_user_history(user_id: str, limit: int = 20) -> List[Transaction]:
    conn = await asyncpg.connect(DB_URL)
    rows = await conn.fetch(
        """
        SELECT * FROM transactions
        WHERE user_id=$1
        ORDER BY timestamp DESC
        LIMIT $2
        """,
        user_id, limit
    )
    await conn.close()
    return [Transaction(**dict(r)) for r in rows]


# ----------------------------
# Get all transactions
# ----------------------------
async def get_all_transactions() -> List[Transaction]:
    conn = await asyncpg.connect(DB_URL)
    rows = await conn.fetch("SELECT * FROM transactions ORDER BY timestamp DESC")
    await conn.close()
    return [Transaction(**dict(r)) for r in rows]


# ----------------------------
# Get a transaction by ID
# ----------------------------
async def get_transaction_by_id(transaction_id: str) -> Transaction | None:
    conn = await asyncpg.connect(DB_URL)
    row = await conn.fetchrow(
        "SELECT * FROM transactions WHERE transaction_id=$1", transaction_id
    )
    await conn.close()
    if row:
        return Transaction(**dict(row))
    return None


# ----------------------------
# Load transactions from CSV
# ----------------------------
async def load_csv_transactions(csv_file: str = "data/fraud_docs/csv/transactions_10000.csv"):
    conn = await asyncpg.connect(DB_URL)
    # Optional: truncate table first
    #await conn.execute("TRUNCATE TABLE transactions;")

    with open(csv_file, "r") as f:
        reader = csv.DictReader(f)
        for row in reader:
            await conn.execute(
                """
                INSERT INTO transactions(transaction_id, user_id, amount, currency, merchant, location, timestamp)
                VALUES($1,$2,$3,$4,$5,$6,$7)
                ON CONFLICT (transaction_id) DO NOTHING
                """,
                row["transaction_id"],
                row["user_id"],
                float(row["amount"]),
                row["currency"],
                row.get("merchant"),
                row.get("location"),
                row["timestamp"]
            )

    await conn.close()
    print(f"CSV {csv_file} loaded into the database successfully.")
