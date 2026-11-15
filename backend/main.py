import os
import re
import secrets
from datetime import date, datetime, timedelta, timezone
from fastapi import Depends, FastAPI, HTTPException, Header, status
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field
import jwt
from pwdlib import PasswordHash

app = FastAPI(
    title="HisobGo Multi-Tenant Retail CRM & Superadmin API",
    version="1.0.0",
    description="High-security Superadmin tenant controller + HisobGo-inspired POS, Inventory & CRM backend"
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

JWT_SECRET = os.getenv("JWT_SECRET", secrets.token_hex(32))
SUPERADMIN_SECRET_KEY = os.getenv("SUPERADMIN_SECRET_KEY", "superadmin-2fa-verified-key")
pwd_hasher = PasswordHash.recommended()  # Argon2id


def generate_one_time_password() -> str:
    alphabet = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789"
    p1 = "".join(secrets.choice(alphabet) for _ in range(4))
    p2 = "".join(secrets.choice(alphabet) for _ in range(2))
    return f"OTP-{p1}-{p2}"


def validate_strong_password(pw: str) -> bool:
    if len(pw) < 8:
        return False
    if not re.search(r"[A-Z]", pw):
        return False
    if not re.search(r"[a-z]", pw):
        return False
    if not re.search(r"[0-9]", pw):
        return False
    if not re.search(r"[!@#$%^&*()_+\-=\[\]{};':\"\\|,.<>/?]", pw):
        return False
    return True


class CreateStoreRequest(BaseModel):
    name: str
    tin: str
    owner_name: str
    phone: str
    login: str
    plan: str = Field(default="Advanced", pattern="^(Start|Advanced|Pro)$")
    subscription_expires_at: date


class UpdateSubscriptionRequest(BaseModel):
    subscription_expires_at: date


class StoreLoginRequest(BaseModel):
    login: str
    password: str


class ForcePasswordChangeRequest(BaseModel):
    login: str
    one_time_password: str
    new_strong_password: str


STORES_DB: dict[str, dict] = {}


def require_superadmin(x_superadmin_key: str = Header(...)):
    if not secrets.compare_digest(x_superadmin_key, SUPERADMIN_SECRET_KEY):
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Superadmin tasdiqlanmadi")
    return True


@app.post("/api/superadmin/stores", dependencies=[Depends(require_superadmin)])
def create_store_account(payload: CreateStoreRequest):
    login_key = payload.login.strip().lower()
    if login_key in STORES_DB:
        raise HTTPException(status_code=400, detail="Ushbu login band")
    otp_plain = generate_one_time_password()
    store_record = {
        "login": login_key,
        "name": payload.name,
        "tin": payload.tin,
        "owner_name": payload.owner_name,
        "phone": payload.phone,
        "plan": payload.plan,
        "subscription_expires_at": payload.subscription_expires_at,
        "status": "ACTIVE",
        "must_change_password": True,
        "password_hash": pwd_hasher.hash(otp_plain),
    }
    STORES_DB[login_key] = store_record
    return {
        "message": "Do'kon yaratildi. Egasi birinchi kirishda bir martalik parolni yangilashi shart.",
        "login": login_key,
        "one_time_password": otp_plain,
        "must_change_password": True,
        "subscription_expires_at": payload.subscription_expires_at,
    }


@app.patch("/api/superadmin/stores/{login}/block", dependencies=[Depends(require_superadmin)])
def toggle_block_store(login: str, block: bool = True):
    store = STORES_DB.get(login.lower())
    if not store:
        raise HTTPException(status_code=404, detail="Do'kon topilmadi")
    store["status"] = "BLOCKED" if block else "ACTIVE"
    return {"login": login, "status": store["status"]}


@app.patch("/api/superadmin/stores/{login}/subscription", dependencies=[Depends(require_superadmin)])
def set_subscription_date(login: str, payload: UpdateSubscriptionRequest):
    store = STORES_DB.get(login.lower())
    if not store:
        raise HTTPException(status_code=404, detail="Do'kon topilmadi")
    store["subscription_expires_at"] = payload.subscription_expires_at
    if store["status"] != "BLOCKED":
        store["status"] = "EXPIRED" if payload.subscription_expires_at < date.today() else "ACTIVE"
    return {"login": login, "subscription_expires_at": store["subscription_expires_at"], "status": store["status"]}


@app.delete("/api/superadmin/stores/{login}", dependencies=[Depends(require_superadmin)])
def delete_store(login: str):
    if login.lower() not in STORES_DB:
        raise HTTPException(status_code=404, detail="Do'kon topilmadi")
    del STORES_DB[login.lower()]
    return {"deleted": True, "login": login}


@app.post("/api/auth/login")
def store_owner_login(payload: StoreLoginRequest):
    store = STORES_DB.get(payload.login.strip().lower())
    if not store or not pwd_hasher.verify(payload.password, store["password_hash"]):
        raise HTTPException(status_code=401, detail="Login yoki parol noto'g'ri")
    if store["status"] == "BLOCKED":
        raise HTTPException(status_code=403, detail="Do'kon hisobi Superadmin tomonidan vaqtincha bloklangan")
    if store["subscription_expires_at"] < date.today():
        store["status"] = "EXPIRED"
        raise HTTPException(status_code=402, detail="Abonent to'lovi muddati tugagan")
    if store["must_change_password"]:
        return {
            "status": "FORCE_PASSWORD_CHANGE_REQUIRED",
            "must_change_password": True,
            "message": "Bir martalik parol aniqlandi. Davom etish uchun yangi ishonchli parol o'rnating."
        }
    token = jwt.encode(
        {"sub": store["login"], "exp": datetime.now(timezone.utc) + timedelta(hours=12)},
        JWT_SECRET,
        algorithm="HS256",
    )
    return {"status": "SUCCESS", "access_token": token, "must_change_password": False}


@app.post("/api/auth/change-initial-password")
def force_change_initial_password(payload: ForcePasswordChangeRequest):
    store = STORES_DB.get(payload.login.strip().lower())
    if not store or not pwd_hasher.verify(payload.one_time_password, store["password_hash"]):
        raise HTTPException(status_code=401, detail="Bir martalik parol noto'g'ri")
    if payload.new_strong_password == payload.one_time_password or not validate_strong_password(payload.new_strong_password):
        raise HTTPException(
            status_code=400,
            detail="Yangi parol kamida 8 belgi, katta/kichik harf, raqam va maxsus belgidan iborat bo'lishi shart"
        )
    store["password_hash"] = pwd_hasher.hash(payload.new_strong_password)
    store["must_change_password"] = False
    return {"status": "PASSWORD_UPDATED", "must_change_password": False}
