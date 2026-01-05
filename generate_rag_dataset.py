import os
import json
from fpdf import FPDF
import csv
from pathlib import Path
import zipfile

# ----------------------------
# Paths
# ----------------------------
base_dir = Path("data/fraud_docs")
txt_dir = base_dir / "txt"
csv_dir = base_dir / "csv"
pdf_dir = base_dir / "pdf"
json_dir = base_dir / "json"
zip_path = Path("fraud_rag_dataset.zip")

# Create directories
for d in [txt_dir, csv_dir, pdf_dir, json_dir]:
    d.mkdir(parents=True, exist_ok=True)

# ----------------------------
# TXT Files
# ----------------------------
txt_files = {
    "geo_anomaly.txt": """Geographical anomalies include:
- Transactions occurring far from the user's usual location
- Impossible travel scenarios
- High-risk foreign countries flagged by international fraud reports
- IP and billing location mismatches
- Suspicious VPN usage
- Transactions at unusual times of day compared to typical behavior

Industry Notes:
- Banks use GeoIP and device fingerprinting to detect these anomalies
- Rapid location switches are a key indicator of account compromise
""",
    "velocity_fraud.txt": """Velocity fraud patterns:
- Rapid sequence of transactions on the same card/account
- Increasing transaction amounts in short intervals
- Multiple merchants or categories in a short window
- Multiple declined attempts followed by retries
- Sudden changes in spending patterns

Industry Notes:
- Velocity monitoring is critical for online banking
- Real-time scoring engines flag accounts exceeding thresholds
""",
    "stolen_cards.txt": """Stolen card fraud:
- Card numbers reported stolen or leaked online
- Unauthorized use at multiple merchants quickly
- Purchases inconsistent with cardholder behavior
- Small transactions followed by high-value transactions (testing)
- Transactions immediately after card loss report

Industry Notes:
- Real-time monitoring and velocity + geo analysis detect stolen card activity
""",
    "merchant_risk.txt": """Merchant risk patterns:
- Merchants with high historical chargebacks
- New or recently registered merchants
- High-risk industries: Gaming, Adult, Gambling, Jewelry
- Merchants in unusual locations compared to user
- Unusual MCC codes

Industry Notes:
- Merchant scoring is part of payment processor risk evaluation
""",
    "aml_red_flags.txt": """AML Red Flags:
- Transactions just below reporting thresholds
- Rapid transfers to multiple accounts
- Frequent international wire transfers
- Inconsistent identification or KYC info
- Structured transactions to avoid detection
- Multi-currency rapid transfers

Industry Notes:
- Suspicious transactions reported to authorities (SARs)
- Combining historical data and regulatory alerts improves detection
""",
    "card_testing.txt": """Card testing patterns:
- Multiple small-value transactions to verify validity
- Fast sequence of transactions in a short time window
- Transactions across different merchant categories
- Often associated with stolen or leaked card data

Industry Notes:
- Detecting testing quickly prevents larger fraud losses
- Usually combined with velocity rules
""",
    "case_studies_target.txt": """Target 2013 Data Breach:
- Hackers stole 40M credit and debit card accounts
- Malware installed via vendor credentials
- Attack detected via unusual transaction patterns
- Lessons: monitor third-party access, POS security, anomaly detection

Signals:
- Unexpected spikes in POS activity
- Geographic anomalies in transactions
- Rapid transaction velocity
""",
    "public_advisories.txt": """Consumer Fraud Advisories:
- Avoid sharing card details online
- Monitor monthly statements for anomalies
- Use alerts for foreign or online transactions
- Keep devices secured with multi-factor authentication
""",
    "case_studies_capitalone.txt": """Capital One 2019 Breach:
- 100M accounts exposed via cloud misconfiguration
- Hackers accessed sensitive customer info
- Key lessons: monitor cloud access, enforce MFA, audit permissions
- Fraud signals: unusual API activity, abnormal transaction patterns
"""
}

for fname, content in txt_files.items():
    with open(txt_dir / fname, "w") as f:
        f.write(content)

# ----------------------------
# CSV Files
# ----------------------------
csv_files = {
    "high_risk_merchants.csv": [
        ["merchant_id","merchant_name","merchant_category","risk_level"],
        ["merch_001","Online Gaming Co","Gaming","high"],
        ["merch_002","XYZ Electronics","Retail","medium"],
        ["merch_003","Exotic Jewelry","Jewelry","high"],
        ["merch_004","Local Grocery","Retail","low"],
        ["merch_005","TravelHub","Travel","medium"],
        ["merch_006","AdultWorld","Adult","high"],
        ["merch_007","QuickLoans","Finance","high"]
    ],
    "country_risk_scores.csv": [
        ["country_code","country_name","risk_level"],
        ["US","United States","low"],
        ["NG","Nigeria","high"],
        ["RU","Russia","high"],
        ["GB","United Kingdom","medium"],
        ["IN","India","medium"],
        ["CN","China","medium"],
        ["BR","Brazil","high"]
    ],
    "aml_thresholds.csv": [
        ["transaction_type","threshold_usd"],
        ["wire_transfer","10000"],
        ["cash_deposit","10000"],
        ["international_transfer","5000"],
        ["online_payment","2000"],
        ["crypto_transfer","1000"]
    ],
    "mcc_codes.csv": [
        ["mcc","category"],
        ["5812","Eating Places"],
        ["7995","Gambling"],
        ["5734","Computer Software"],
        ["6011","Financial Services"],
        ["4111","Transportation"],
        ["7999","High-Risk Services"]
    ]
}

for fname, rows in csv_files.items():
    with open(csv_dir / fname, "w", newline="") as f:
        writer = csv.writer(f)
        writer.writerows(rows)

# ----------------------------
# JSON Files
# ----------------------------
risk_data = [
    {"country": "NG", "risk_level": "high"},
    {"country": "RU", "risk_level": "high"},
    {"country": "US", "risk_level": "low"},
    {"country": "IN", "risk_level": "medium"},
    {"country": "GB", "risk_level": "medium"},
    {"country": "BR", "risk_level": "high"}
]

transactions = [
    {"transaction_id": "txn_0001", "user_id": "user_001", "amount": 150.50, "currency": "USD", "merchant": "merch_001", "location": "US", "timestamp": "2025-01-01T10:30:00"},
    {"transaction_id": "txn_0002", "user_id": "user_002", "amount": 2500.00, "currency": "USD", "merchant": "merch_002", "location": "NG", "timestamp": "2025-01-01T11:00:00"},
    {"transaction_id": "txn_0003", "user_id": "user_003", "amount": 15.75, "currency": "USD", "merchant": "merch_004", "location": "GB", "timestamp": "2025-01-01T12:00:00"},
    {"transaction_id": "txn_0004", "user_id": "user_001", "amount": 5000.00, "currency": "USD", "merchant": "merch_003", "location": "NG", "timestamp": "2025-01-01T12:30:00"}
]

with open(json_dir / "risk_data.json", "w") as f:
    json.dump(risk_data, f, indent=2)

with open(json_dir / "transactions.json", "w") as f:
    json.dump(transactions, f, indent=2)

# ----------------------------
# PDF Files
# ----------------------------
pdf_files = {
    "pci_dss_guidelines.pdf": "PCI DSS v4.0 Guidelines:\n- Protect cardholder data\n- Maintain secure networks\n- Implement access control\n- Monitor and test networks\n- Maintain security policy",
    "fatf_guidance.pdf": "FATF Recommendations:\n- Customer Due Diligence\n- Transaction Monitoring\n- Reporting Suspicious Transactions\n- Cross-border controls",
    "fraud_whitepaper_2025.pdf": "Fraud Whitepaper 2025:\n- Trends in online payment fraud\n- Use of AI and ML\n- Case studies and mitigation strategies"
}

for fname, content in pdf_files.items():
    pdf = FPDF()
    pdf.add_page()
    pdf.set_font("Arial", size=12)
    pdf.multi_cell(0, 10, content)
    pdf.output(pdf_dir / fname)

# ----------------------------
# Create ZIP
# ----------------------------
with zipfile.ZipFile(zip_path, "w", zipfile.ZIP_DEFLATED) as zipf:
    for folder, _, files in os.walk(base_dir):
        for file in files:
            file_path = Path(folder) / file
            zipf.write(file_path, arcname=file_path.relative_to(base_dir.parent))

print(f"Enterprise-grade RAG dataset ZIP created: {zip_path}")
