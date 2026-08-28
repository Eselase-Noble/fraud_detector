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

## Partner institutions (any financial institution consuming the API)
Sentinel is multi-tenant over its API. Register a partner — **bank, fintech, PSP,
microfinance, mobile money, SACCO or exchange** — under **Partners → Institutions**
(or `POST /admin/integrations`). Each registration captures the institution type and
its **connection method**, issues a one-time API key, and streams webhook callbacks
on the decisions it opts into (`BLOCK`/`REVIEW`/`ALLOW`).

### Connection methods (how they feed transaction data)
- `rest_api`  — real-time `POST /transactions/detect` (synchronous decision)
- `batch_api` — `POST /transactions/batch_detect` (bulk / periodic)
- `database`  — scheduled read-only connector against their transactions table
- `file_sftp` — CSV drop on SFTP (or portal upload), scored per file

### One app, two worlds (confidentiality by login)
A single Vue app (`fraud_detector_ui`) serves both audiences on **one origin/port**,
split by path and each gated by its **own login**:
- **`/`** — partner/client portal. Institutions sign in with a partner email + password.
- **`/platform`** — operator console (Sentinel staff). Separate staff login; partner
  tokens are rejected here and vice-versa, so neither side can reach the other's tooling
  or data. (Run `npm run dev` → both live on `:5173`.)

### Tenant isolation (partner data is private)
Every scored transaction is attributed to the partner whose API key produced it
(`transactions.integration_id`). The **operator console never sees partner
transactions** — its lists and analytics filter to platform-owned rows
(`integration_id IS NULL`). Each partner sees only their own transactions,
analytics and team, enforced server-side on every `/portal/*` call. The portal
has its own **Overview, Transactions, Analytics, Detect, Team and Connection**
views; partner `Detect` calls are attributed to that institution.

### User management (both sides)
- Partners manage their own team in the portal (`/portal/users`, roles
  admin / analyst / viewer; only admins mutate).
- Operators manage staff in the console (`/staff/users`, roles admin / operator
  / viewer). Destructive actions (remove, disable, revoke, rotate, suspend) all
  require confirmation.

### Portal login (human) vs API key (machine)
Institutions **sign in with email + password** (`POST /portal/login` → signed
session token; portal sends it as `Authorization: Bearer …`). Their *systems*
authenticate to detection with the **API key** (`X-API-Key`). Both map to the same
partner but are separate credentials — a lost password never exposes the key and
vice-versa. Passwords are PBKDF2-hashed; tokens are HMAC-signed (`PORTAL_SECRET`).

Operators provision a partner's login from **Partners → Institutions** (fields at
registration, or the per-row *Set / Reset login* action →
`POST /admin/integrations/{id}/portal_credentials`). In the portal a signed-in
institution sees usage, copy-paste connection samples for all four methods, edits
its webhook URL and events (`PATCH /portal/config`), and runs a live test call.
Operators can rotate the API key (`POST /admin/integrations/{id}/rotate`) — the old
key dies immediately — or suspend/revoke a partner (a suspended partner cannot log
in: `403`).

On startup Sentinel self-provisions its full schema (transactions, fraud_results,
users, audit_log, knowledge_documents, integrations incl. institution_type /
connection_method / contact_email), so no manual migration step is needed.

## Front-end (fraud_detector_ui — one app, both worlds)
```bash
cd m_fraud/fraud_detector_ui
npm install            # one-time
# .env -> VITE_API_BASE_URL=http://localhost:8099  (points at Sentinel)
npm run dev
#   partner portal   → http://localhost:5173/
#   operator console → http://localhost:5173/platform
```
- Partner portal (`/`): email/password login, usage, connection guide (all four
  methods), credentials info, webhook/event editing and a live connection test.
- Operator console (`/platform`): Dashboard, Transactions, Users & Risk, Detect,
  Analytics, Knowledge Base, Partners → Institutions, Admin & Audit.

### Seeded test accounts (dev only — change in production)
Sentinel provisions these on startup if missing, so you can try both sides before
enrolling real partners:
| Where | Email | Password |
|-------|-------|----------|
| Operator console `/platform` | `operator@sentinel.local` | `operator123` |
| Partner portal `/` (bank) | `bank@demo.africode` | `partner123` |
| Partner portal `/` (fintech) | `fintech@demo.africode` | `partner123` |

Passwords are PBKDF2-hashed; the seed is idempotent (existing rows are never
overwritten). Operators add real partners under Partners → Institutions.
