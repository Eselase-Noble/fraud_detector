"""
main.py
-------
FastAPI application entrypoint.
"""
from __future__ import annotations

import logging
from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from app.database import init_db, close_db
from app.routers import transactions, users, docs, analytics, admin, knowledge, portal, staff
from app.seed import ensure_seed

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
)


@asynccontextmanager
async def lifespan(app: FastAPI):
    # ── Startup ──────────────────────────────────────────────────────────────
    await init_db()
    await ensure_seed()
    yield
    # ── Shutdown ─────────────────────────────────────────────────────────────
    await close_db()


app = FastAPI(
    title="Sentinel — Fraud Detection Service",
    description="AI-powered transaction fraud detection with RAG and live threat intelligence.",
    version="2.0.0",
    lifespan=lifespan,
)

# ─── CORS ─────────────────────────────────────────────────────────────────────
app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        "http://localhost:5173",
        "http://127.0.0.1:5173",
        "http://localhost:5174",
        "http://127.0.0.1:5174",
        "http://fraud-detector.africodelab.net",
        "https://fraud-detector.africodelab.net",
    ],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# ─── Routers ──────────────────────────────────────────────────────────────────
app.include_router(transactions.router, prefix="/transactions", tags=["Transactions"])
app.include_router(users.router,        prefix="/users",        tags=["Users"])
app.include_router(docs.router,         prefix="/docs",         tags=["Documents"])
app.include_router(analytics.router,    prefix="/analytics",    tags=["Analytics"])
app.include_router(admin.router,        prefix="/admin",        tags=["Admin"])
app.include_router(knowledge.router,        prefix="/knowledge",        tags=["Knowledge Base"])
app.include_router(portal.router,           prefix="/portal",           tags=["Partner Portal"])
app.include_router(staff.router,            prefix="/staff",            tags=["Staff"])


# ─── Health Check ─────────────────────────────────────────────────────────────
@app.get("/health", tags=["System"])
async def health():
    return {"status": "ok", "service": "sentinel-fraud-api", "version": "2.0.0"}