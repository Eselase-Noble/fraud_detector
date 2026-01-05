import json

def load_risk_data():
    with open("data/risk_data.json") as f:
        return json.load(f)
