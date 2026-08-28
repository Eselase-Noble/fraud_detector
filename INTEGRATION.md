# Sentinel ⇄ AfriCore Bank — Integration Notes

Sentinel is a **standalone** AI fraud service. The bank integrates with it **over its
REST API only** — no shared database, no shared code.

## How the pieces connect
```
AfriCore bank (Go, :8080)  ──POST /transactions/detect──▶  Sentinel (FastAPI, :8099)
        ▲                                                        │
        └──────── FraudResult {score, decision, signals} ◀───────┘
```
- After a transaction posts, the bank calls `POST /transactions/detect`.
- The bank merges Sentinel's `decision` (ALLOW/REVIEW/BLOCK) + `score` + `signals`
  with its own rule flags into a **RiskAlert** (`source = rules | ai | rules+ai`);
  `BLOCK` → high severity + compliance notification.
- If Sentinel is unset/unreachable, the bank silently falls back to rules-only (4s timeout).

## Run Sentinel
```bash
cd m_fraud/fraud_detector
python3 -m venv .venv && ./.venv/bin/pip install -r requirements.txt   # one-time
# edit .env  (already points DB_URL at the 'sentinel' database, postgres/postgres)
#   OPENAI_API_KEY=...     # optional — enables LLM/RAG explanations
#   TAVILY_API_KEY=...     # optional — enables live threat intel
./.venv/bin/python -m uvicorn app.main:app --host 127.0.0.1 --port 8099
```
- **Score & decision are rule-based** and work **without** any keys.
- With `OPENAI_API_KEY`, the `reason` field is written by the LLM/RAG; otherwise it's a
  deterministic signals summary. (Tailored so the service never hard-fails on a missing key.)

## Point the bank at Sentinel
In `Banking-Backend/core-banking/.env`:
```
FRAUD_SERVICE_URL=http://localhost:8099
```
Restart the bank; posted transactions are now scored by Sentinel too.

## Databases (separate by design)
- Bank: `banking`  ·  Sentinel: `sentinel`  (both postgres/postgres, localhost:5432)

## Sentinel Console (fraud_detector_ui)
Enterprise Vue console for the fraud service — sidebar shell + Dashboard, Transactions,
Users & Risk, Detect, Analytics, Knowledge Base, Admin & Audit.
```bash
cd m_fraud/fraud_detector_ui
npm install            # one-time
# .env -> VITE_API_BASE_URL=http://localhost:8099  (points at Sentinel)
npm run dev            # http://localhost:5173
```
The console reads Sentinel's REST endpoints (analytics/stats, transactions, users,
knowledge, admin) — so bank transactions scored by Sentinel show up here for the org.
