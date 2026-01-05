import psycopg2
import csv

# PostgreSQL connection parameters
DB_NAME = "db"
DB_USER = "postgres"
DB_PASS = "password"
DB_HOST = "localhost"
DB_PORT = "5432"

csv_file = "data/fraud_docs/csv/transactions_10000.csv"

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
#conn.commit()

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
