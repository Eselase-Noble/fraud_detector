import random
import csv
from datetime import datetime, timedelta

NUM_USERS = 500
NUM_TRANSACTIONS = 10000

users = [f"user_{i:03d}" for i in range(1, NUM_USERS + 1)]

merchants = {
    "low": ["Amazon", "Starbucks", "Uber", "Netflix", "McDonalds", "Spotify"],
    "medium": ["Electronics Hub", "TravelHub", "Local Grocery", "Software Store"],
    "high": ["LuxuryStore", "AdultWorld", "QuickLoans", "Exotic Jewelry", "Online Gaming Co"]
}

locations = ["US", "GB", "NG", "RU", "CN", "IN", "BR"]
currency = "USD"

transactions = []

for txn_id in range(1, NUM_TRANSACTIONS + 1):
    user = random.choice(users)

    # 85% normal transactions, 15% suspicious
    is_suspicious = random.random() < 0.15

    if is_suspicious:
        merchant = random.choice(merchants["high"])
        amount = round(random.uniform(500, 5000), 2)
        loc = random.choice(["NG", "RU", "CN", "BR"])  # High-risk countries
        time_offset = timedelta(hours=random.randint(0, 48))
    else:
        merchant = random.choice(merchants["low"] + merchants["medium"])
        amount = round(random.uniform(5, 100), 2)
        loc = random.choice(["US", "GB", "IN"])
        time_offset = timedelta(days=random.randint(0, 90), hours=random.randint(0, 23))

    txn_time = datetime.now() - time_offset
    txn_id_str = f"txn_{txn_id:05d}"

    transactions.append({
        "transaction_id": txn_id_str,
        "user_id": user,
        "amount": amount,
        "currency": currency,
        "merchant": merchant,
        "location": loc,
        "timestamp": txn_time.isoformat()
    })

# -----------------------------
# Save to CSV
# -----------------------------
csv_file = "data/fraud_docs/csv/transactions_10000.csv"
with open(csv_file, "w", newline="") as f:
    writer = csv.DictWriter(f, fieldnames=transactions[0].keys())
    writer.writeheader()
    for txn in transactions:
        writer.writerow(txn)

print(f"Generated {len(transactions)} transactions -> {csv_file}")
