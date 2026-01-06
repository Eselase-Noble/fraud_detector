import psycopg2
import csv

# PostgreSQL connection parameters
DB_NAME = "fraud_database"
DB_USER = "fraud_user"
DB_PASS = "FraudUser202612"
DB_HOST = "143.198.235.150"
DB_PORT = "5432"

csv_file = "transactions_10000.csv"

# Connect to PostgreSQL
conn = psycopg2.connect(
    dbname=DB_NAME,
    user=DB_USER,
    password=DB_PASS,
    host=DB_HOST,
    port=DB_PORT
)
cur = conn.cursor()

# Optional: truncate table first if you want to reload fresh data
#cur.execute("TRUNCATE TABLE transactions;")
# Create table
cur.execute("""
CREATE TABLE IF NOT EXISTS transactions (
    transaction_id VARCHAR PRIMARY KEY,
    user_id VARCHAR NOT NULL,
    amount NUMERIC NOT NULL,
    currency VARCHAR(3),
    merchant VARCHAR,
    location VARCHAR,
    timestamp TIMESTAMP NOT NULL
);
""")

conn.commit()

# Insert data
cur.execute("""
INSERT INTO transactions (
    transaction_id, user_id, amount, currency, merchant, location, timestamp
) VALUES
('txn_001', 'user_123', 25.00, 'USD', 'Amazon', 'US', NOW() - INTERVAL '5 days'),
('txn_002', 'user_123', 30.00, 'USD', 'Starbucks', 'US', NOW() - INTERVAL '4 days'),
('txn_003', 'user_123', 27.00, 'USD', 'Uber', 'US', NOW() - INTERVAL '3 days'),
('txn_004', 'user_123', 29.00, 'USD', 'Netflix', 'US', NOW() - INTERVAL '2 days'),
('txn_005', 'user_123', 2500.00, 'USD', 'Unknown Merchant', 'RU', NOW() - INTERVAL '1 hour');
""")

conn.commit()

# Read CSV and insert
with open(csv_file, "r") as f:
    reader = csv.DictReader(f)
    for row in reader:
        cur.execute("""
            INSERT INTO transactions (transaction_id, user_id, amount, currency, merchant, location, timestamp)
            VALUES (%s, %s, %s, %s, %s, %s, %s)
            ON CONFLICT (transaction_id) DO NOTHING;
        """, (
            row["transaction_id"],
            row["user_id"],
            row["amount"],
            row["currency"],
            row["merchant"],
            row["location"],
            row["timestamp"]
        ))

conn.commit()
cur.close()
conn.close()
print("All transactions inserted into PostgreSQL successfully.")
