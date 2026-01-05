
from fastapi import FastAPI
from app.routers import transactions, users, docs, analytics, admin
from fastapi.middleware.cors import CORSMiddleware

app = FastAPI(title="Fraud Detection Service", version="1.0")



# ✅ CORS CONFIGURATION
app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        "http://localhost:5173",      # Vue (Vite)
        "http://127.0.0.1:5173",
    ],
    allow_credentials=True,
    allow_methods=["*"],             # GET, POST, PUT, DELETE, OPTIONS
    allow_headers=["*"],             # Authorization, Content-Type, etc
)


# Include routers
app.include_router(transactions.router, prefix="/transactions", tags=["Transactions"])
app.include_router(users.router, prefix="/users", tags=["Users"])
app.include_router(docs.router, prefix="/docs", tags=["Documents"])
app.include_router(analytics.router, prefix="/analytics", tags=["Analytics"])
app.include_router(admin.router, prefix="/admin", tags=["Admin"])



# from fastapi import FastAPI
#
# from app.models import Transaction
# from app.database import get_user_history
# from app.fraud_detector import detect_fraud
#
# app = FastAPI(title="Fraud Detection Service")
#
# @app.post("/detect", response_model=dict)
# async def detect(transaction: Transaction):
#     history = await get_user_history(transaction.user_id)
#     result = detect_fraud(transaction, history)
#     return result.dict()
