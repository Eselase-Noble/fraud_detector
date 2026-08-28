"""
routers/staff.py
----------------
Authentication for Sentinel staff — the operator console at /platform.

Staff sign in with email + password and receive a "staff"-kind session token,
distinct from partner tokens (a partner token is rejected here and vice-versa).
This gates the operator console so partners/clients can't reach operator tooling.
"""
from __future__ import annotations

from typing import Optional

from fastapi import APIRouter, Header, HTTPException
from pydantic import BaseModel

from app.database import _get_pool
from app.portal_auth import issue_token, verify_password, verify_token

router = APIRouter(tags=["Staff"])


class StaffLogin(BaseModel):
    email: str
    password: str


class StaffUser(BaseModel):
    id: int
    email: str
    name: Optional[str] = None
    role: str = "operator"


class StaffLoginResponse(BaseModel):
    token: str
    user: StaffUser


async def _current_staff(authorization: Optional[str]) -> StaffUser:
    if not authorization or not authorization.lower().startswith("bearer "):
        raise HTTPException(401, detail="Sign in to the operator console.")
    staff_id = verify_token(authorization[7:].strip(), "staff")
    if staff_id is None:
        raise HTTPException(401, detail="Session expired. Please sign in again.")
    pool = await _get_pool()
    async with pool.acquire() as conn:
        row = await conn.fetchrow(
            "SELECT id, email, name, role, is_active FROM staff_users WHERE id = $1", staff_id
        )
    if not row or not row["is_active"]:
        raise HTTPException(403, detail="This staff account is disabled.")
    return StaffUser(**{k: row[k] for k in ("id", "email", "name", "role")})


@router.post("/login", response_model=StaffLoginResponse,
             summary="Sign in to the operator console")
async def staff_login(body: StaffLogin):
    email = body.email.strip().lower()
    pool = await _get_pool()
    async with pool.acquire() as conn:
        row = await conn.fetchrow(
            "SELECT id, email, name, role, is_active, password_hash FROM staff_users WHERE email = $1",
            email,
        )
    if not row or not verify_password(body.password, row["password_hash"]):
        raise HTTPException(401, detail="Incorrect email or password.")
    if not row["is_active"]:
        raise HTTPException(403, detail="This staff account is disabled.")
    token = issue_token("staff", row["id"])
    return StaffLoginResponse(
        token=token,
        user=StaffUser(**{k: row[k] for k in ("id", "email", "name", "role")}),
    )


@router.get("/me", response_model=StaffUser, summary="Current staff session")
async def staff_me(authorization: Optional[str] = Header(None)):
    return await _current_staff(authorization)
