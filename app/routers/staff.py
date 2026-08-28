"""
routers/staff.py
----------------
Authentication for Sentinel staff — the operator console at /platform.

Staff sign in with email + password and receive a "staff"-kind session token,
distinct from partner tokens (a partner token is rejected here and vice-versa).
This gates the operator console so partners/clients can't reach operator tooling.
"""
from __future__ import annotations

from typing import List, Optional

from fastapi import APIRouter, Header, HTTPException
from pydantic import BaseModel

from app.database import _get_pool
from app.portal_auth import hash_password, issue_token, verify_password, verify_token

router = APIRouter(tags=["Staff"])

STAFF_ROLES = {"admin", "operator", "viewer"}


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


# ─── Staff user management (admins only) ─────────────────────────────────────

class StaffCreate(BaseModel):
    email: str
    password: str
    name: Optional[str] = None
    role: str = "operator"


class StaffUpdate(BaseModel):
    name: Optional[str] = None
    role: Optional[str] = None
    is_active: Optional[bool] = None
    password: Optional[str] = None


class StaffUserFull(StaffUser):
    is_active: bool = True


async def _require_admin(authorization: Optional[str]) -> StaffUser:
    me = await _current_staff(authorization)
    if me.role != "admin":
        raise HTTPException(403, detail="Only admins can manage staff.")
    return me


@router.get("/users", response_model=List[StaffUserFull], summary="List staff users")
async def list_staff(authorization: Optional[str] = Header(None)):
    await _require_admin(authorization)
    pool = await _get_pool()
    async with pool.acquire() as conn:
        rows = await conn.fetch(
            "SELECT id, email, name, role, is_active FROM staff_users ORDER BY created_at"
        )
    return [StaffUserFull(**dict(r)) for r in rows]


@router.post("/users", response_model=StaffUserFull, summary="Add a staff user")
async def create_staff(body: StaffCreate, authorization: Optional[str] = Header(None)):
    await _require_admin(authorization)
    role = body.role if body.role in STAFF_ROLES else "operator"
    pool = await _get_pool()
    async with pool.acquire() as conn:
        try:
            row = await conn.fetchrow(
                "INSERT INTO staff_users (email, password_hash, name, role) "
                "VALUES ($1,$2,$3,$4) RETURNING id, email, name, role, is_active",
                body.email.strip().lower(), hash_password(body.password), body.name, role,
            )
        except Exception:
            raise HTTPException(409, detail="That email is already in use.")
    return StaffUserFull(**dict(row))


@router.patch("/users/{user_id}", response_model=StaffUserFull, summary="Update a staff user")
async def update_staff(user_id: int, body: StaffUpdate, authorization: Optional[str] = Header(None)):
    await _require_admin(authorization)
    sets, params, idx = [], [], 1
    if body.name is not None:
        sets.append(f"name = ${idx}"); params.append(body.name); idx += 1
    if body.role is not None:
        if body.role not in STAFF_ROLES:
            raise HTTPException(400, detail=f"role must be one of {sorted(STAFF_ROLES)}")
        sets.append(f"role = ${idx}"); params.append(body.role); idx += 1
    if body.is_active is not None:
        sets.append(f"is_active = ${idx}"); params.append(body.is_active); idx += 1
    if body.password:
        sets.append(f"password_hash = ${idx}"); params.append(hash_password(body.password)); idx += 1
    if not sets:
        raise HTTPException(400, detail="Nothing to update.")
    params.append(user_id)
    pool = await _get_pool()
    async with pool.acquire() as conn:
        row = await conn.fetchrow(
            f"UPDATE staff_users SET {', '.join(sets)} WHERE id = ${idx} "
            f"RETURNING id, email, name, role, is_active",
            *params,
        )
    if not row:
        raise HTTPException(404, detail="Staff user not found.")
    return StaffUserFull(**dict(row))


@router.delete("/users/{user_id}", summary="Remove a staff user")
async def delete_staff(user_id: int, authorization: Optional[str] = Header(None)):
    me = await _require_admin(authorization)
    if me.id == user_id:
        raise HTTPException(400, detail="You can't remove your own account.")
    pool = await _get_pool()
    async with pool.acquire() as conn:
        result = await conn.execute("DELETE FROM staff_users WHERE id = $1", user_id)
    if result == "DELETE 0":
        raise HTTPException(404, detail="Staff user not found.")
    return {"status": "deleted", "id": user_id}
