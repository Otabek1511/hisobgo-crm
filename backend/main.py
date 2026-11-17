import csv
import io
import logging
import os
import re
import secrets
from contextlib import asynccontextmanager
from datetime import date, datetime, timedelta, timezone
from fractions import Fraction
from typing import Literal

import jwt
import pyotp
from fastapi import BackgroundTasks, Body, Depends, FastAPI, Header, HTTPException, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import Response
from pwdlib import PasswordHash
from pydantic import BaseModel, Field
from sqlalchemy import case, func, or_, select, text
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from db import engine, get_db
import telegram_bot as tg
from models import Base, Customer, Employee, EmployeeAdvance, Product, SaleItem, SaleReceipt, SecurityAuditLog, StoreTenant, TelegramLink

# ---------------------------------------------------------------------------
# Sozlamalar
# ---------------------------------------------------------------------------
log = logging.getLogger("hisobgo")
ENV = os.getenv("ENV", "production").lower()
IS_DEV = ENV in ("dev", "development", "test")


def _required_secret(name: str, dev_default: str) -> str:
    value = os.getenv(name)
    if value:
        return value
    if IS_DEV:
        return dev_default
    raise RuntimeError(f"{name} muhit o'zgaruvchisi o'rnatilmagan (ENV=dev bilan sinab ko'rish mumkin)")


JWT_SECRET = _required_secret("JWT_SECRET", "dev-only-jwt-secret-change-me-0123456789")
SUPERADMIN_SECRET_KEY = _required_secret("SUPERADMIN_SECRET_KEY", "dev-only-superadmin-key")
SUPERADMIN_TOTP_SECRET = os.getenv("SUPERADMIN_TOTP_SECRET")  # base32; berilsa 2FA majburiy
CORS_ORIGINS = [o.strip() for o in os.getenv("CORS_ORIGINS", "").split(",") if o.strip()]
JWT_TTL_HOURS = int(os.getenv("JWT_TTL_HOURS", "12"))
MAX_FAILED_LOGINS = 5
LOCK_MINUTES = 15
PUBLIC_URL = os.getenv("PUBLIC_URL", "https://hisobgo-api.onrender.com")
CRON_KEY = os.getenv("CRON_KEY", "")

pwd_hasher = PasswordHash.recommended()  # Argon2id
_DUMMY_HASH = pwd_hasher.hash("dummy-password-for-timing")  # mavjud bo'lmagan login uchun vaqt tenglashtirish


_MIGRATIONS = [
    "ALTER TABLE sale_receipts ADD COLUMN IF NOT EXISTS customer_id INTEGER",
    "ALTER TABLE sale_receipts ADD COLUMN IF NOT EXISTS refunded_at TIMESTAMPTZ",
    "ALTER TABLE sale_receipts ADD COLUMN IF NOT EXISTS refunded_uzs BIGINT NOT NULL DEFAULT 0",
    "ALTER TABLE sale_receipts ADD COLUMN IF NOT EXISTS idem_key VARCHAR(64)",
    "ALTER TABLE sale_items ADD COLUMN IF NOT EXISTS refunded_qty INTEGER NOT NULL DEFAULT 0",
    "ALTER TABLE stores ADD COLUMN IF NOT EXISTS token_version INTEGER NOT NULL DEFAULT 0",
    "ALTER TABLE customers DROP COLUMN IF EXISTS cashback_uzs",
    "CREATE UNIQUE INDEX IF NOT EXISTS uq_receipt_code ON sale_receipts (store_id, receipt_code)",
    "CREATE UNIQUE INDEX IF NOT EXISTS uq_receipt_idem ON sale_receipts (store_id, idem_key)",
]


@asynccontextmanager
async def lifespan(_: FastAPI):
    Base.metadata.create_all(bind=engine)
    if engine.dialect.name == "postgresql":  # mavjud jadvallarga yangi ustun/indeks (create_all buni qilmaydi)
        for stmt in _MIGRATIONS:
            try:  # har biri alohida: bittasi muvaffaqiyatsiz bo'lsa ham server ishga tushadi
                with engine.begin() as conn:
                    conn.execute(text(stmt))
            except Exception:
                log.exception("Migratsiya bajarilmadi: %s", stmt)
    yield


app = FastAPI(
    title="HisobGo Multi-Tenant Retail CRM & Superadmin API",
    version="1.1.0",
    description="Superadmin tenant boshqaruvi + POS, Ombor va CRM backend",
    lifespan=lifespan,
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=CORS_ORIGINS or (["*"] if IS_DEV else []),
    allow_credentials=False,  # Bearer/header ishlatiladi, cookie yo'q
    allow_methods=["GET", "POST", "PATCH", "DELETE"],
    allow_headers=["Authorization", "Content-Type", "Idempotency-Key", "X-Superadmin-Key", "X-Superadmin-TOTP"],
)


# ---------------------------------------------------------------------------
# Yordamchi funksiyalar
# ---------------------------------------------------------------------------
def utcnow() -> datetime:
    return datetime.now(timezone.utc)


def generate_one_time_password() -> str:
    alphabet = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789"
    p1 = "".join(secrets.choice(alphabet) for _ in range(4))
    p2 = "".join(secrets.choice(alphabet) for _ in range(4))
    return f"OTP-{p1}-{p2}"


def validate_strong_password(pw: str) -> bool:
    return (
        len(pw) >= 8
        and re.search(r"[A-Z]", pw) is not None
        and re.search(r"[a-z]", pw) is not None
        and re.search(r"[0-9]", pw) is not None
        and re.search(r"[^A-Za-z0-9]", pw) is not None
    )


def audit(db: Session, actor: str, action: str, detail: str) -> None:
    db.add(SecurityAuditLog(actor=actor, action=action, detail=detail))


def effective_status(store: StoreTenant) -> str:
    if store.status == "BLOCKED":
        return "BLOCKED"
    return "EXPIRED" if store.subscription_expires_at < date.today() else "ACTIVE"


def _aware(dt: datetime) -> datetime:
    return dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)


def get_store_by_login(db: Session, login: str) -> StoreTenant | None:
    return db.scalar(select(StoreTenant).where(StoreTenant.login == login.strip().lower()))


def store_public(store: StoreTenant) -> dict:
    return {
        "login": store.login,
        "slug": store.slug,
        "name": store.name,
        "tin": store.tin,
        "owner_name": store.owner_name,
        "phone": store.phone,
        "plan": store.plan,
        "status": effective_status(store),
        "must_change_password": store.must_change_password,
        "subscription_expires_at": store.subscription_expires_at,
    }


# ---------------------------------------------------------------------------
# Sxemalar
# ---------------------------------------------------------------------------
class CreateStoreRequest(BaseModel):
    name: str = Field(min_length=2, max_length=120)
    tin: str = Field(default="", pattern=r"^(\d{9,14})?$")  # STIR ixtiyoriy
    owner_name: str = Field(min_length=2, max_length=120)
    phone: str = Field(min_length=7, max_length=32)
    login: str = Field(pattern=r"^[A-Za-z0-9_.-]{3,64}$")
    plan: Literal["Start", "Advanced", "Pro"] = "Advanced"
    subscription_expires_at: date


class UpdateSubscriptionRequest(BaseModel):
    subscription_expires_at: date


class StoreLoginRequest(BaseModel):
    login: str = Field(max_length=64)
    password: str = Field(max_length=256)


class ForcePasswordChangeRequest(BaseModel):
    login: str = Field(max_length=64)
    one_time_password: str = Field(max_length=256)
    new_strong_password: str = Field(max_length=256)


class ProductIn(BaseModel):
    sku: str = Field(default="", max_length=64)  # ixtiyoriy; bo'sh bo'lsa avtomatik yaratiladi
    name: str = Field(min_length=1, max_length=160)
    category: str = Field(default="", max_length=80)  # ixtiyoriy
    cost_uzs: int = Field(ge=0, le=10**12)
    price_uzs: int = Field(ge=0, le=10**12)
    stock_qty: int = Field(default=0, ge=0, le=10**7)


class ProductUpdate(BaseModel):
    sku: str | None = Field(default=None, max_length=64)
    name: str | None = Field(default=None, min_length=1, max_length=160)
    category: str | None = Field(default=None, max_length=80)
    cost_uzs: int | None = Field(default=None, ge=0, le=10**12)
    price_uzs: int | None = Field(default=None, ge=0, le=10**12)
    stock_qty: int | None = Field(default=None, ge=0, le=10**7)


class RestockRequest(BaseModel):
    qty: int = Field(gt=0, le=10**6)


class CustomerIn(BaseModel):
    full_name: str = Field(min_length=2, max_length=120)
    phone: str = Field(min_length=7, max_length=32)


class PayDebtRequest(BaseModel):
    amount_uzs: int = Field(gt=0, le=10**12)


class SaleItemIn(BaseModel):
    sku: str = Field(max_length=64)
    qty: int = Field(gt=0, le=10**5)


class SaleRequest(BaseModel):
    items: list[SaleItemIn] = Field(min_length=1, max_length=200)
    payment_method: Literal["Naqd", "Uzcard/Humo", "Click/Payme", "Nasiya"]
    discount_pct: int = Field(default=0, ge=0, le=50)
    customer_id: int | None = None


# ---------------------------------------------------------------------------
# Superadmin autentifikatsiyasi
# ---------------------------------------------------------------------------
def require_superadmin(
    x_superadmin_key: str = Header(...),
    x_superadmin_totp: str | None = Header(default=None),
) -> bool:
    if not secrets.compare_digest(x_superadmin_key.encode(), SUPERADMIN_SECRET_KEY.encode()):
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Superadmin tasdiqlanmadi")
    if SUPERADMIN_TOTP_SECRET:
        if not x_superadmin_totp or not pyotp.TOTP(SUPERADMIN_TOTP_SECRET).verify(x_superadmin_totp, valid_window=1):
            raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="2FA kodi noto'g'ri")
    return True


# ---------------------------------------------------------------------------
# Tenant (do'kon egasi) autentifikatsiyasi — har so'rovda holat qayta tekshiriladi
# ---------------------------------------------------------------------------
def current_store(
    authorization: str | None = Header(default=None),
    db: Session = Depends(get_db),
) -> StoreTenant:
    if not authorization or not authorization.lower().startswith("bearer "):
        raise HTTPException(status_code=401, detail="Token talab qilinadi")
    token = authorization[7:].strip()
    try:
        data = jwt.decode(token, JWT_SECRET, algorithms=["HS256"])
    except jwt.PyJWTError:
        raise HTTPException(status_code=401, detail="Token yaroqsiz yoki muddati tugagan")
    store = db.scalar(select(StoreTenant).where(StoreTenant.id == data.get("sid")))
    if not store:
        raise HTTPException(status_code=401, detail="Do'kon topilmadi")
    st = effective_status(store)
    if st == "BLOCKED":
        raise HTTPException(status_code=403, detail="Do'kon hisobi Superadmin tomonidan vaqtincha bloklangan")
    if st == "EXPIRED":
        raise HTTPException(status_code=402, detail="Abonent to'lovi muddati tugagan")
    if int(data.get("tv", 0)) != (store.token_version or 0):
        raise HTTPException(status_code=401, detail="Sessiya bekor qilingan. Qayta kiring")
    if store.must_change_password:
        raise HTTPException(status_code=403, detail="Avval bir martalik parolni almashtiring")
    return store


@app.get("/health")
def health():
    return {"status": "ok"}


# ---------------------------------------------------------------------------
# Superadmin endpointlari
# ---------------------------------------------------------------------------
@app.get("/api/superadmin/stores", dependencies=[Depends(require_superadmin)])
def list_stores(db: Session = Depends(get_db)):
    stores = db.scalars(select(StoreTenant).order_by(StoreTenant.created_at)).all()
    return [store_public(s) for s in stores]


@app.get("/api/superadmin/audit-logs", dependencies=[Depends(require_superadmin)])
def list_audit_logs(limit: int = 100, db: Session = Depends(get_db)):
    limit = max(1, min(limit, 500))
    rows = db.scalars(select(SecurityAuditLog).order_by(SecurityAuditLog.id.desc()).limit(limit)).all()
    return [
        {"id": r.id, "actor": r.actor, "action": r.action, "detail": r.detail, "created_at": r.created_at}
        for r in rows
    ]


@app.post("/api/superadmin/stores", dependencies=[Depends(require_superadmin)], status_code=201)
def create_store_account(payload: CreateStoreRequest, db: Session = Depends(get_db)):
    login_key = payload.login.strip().lower()
    if get_store_by_login(db, login_key):
        raise HTTPException(status_code=400, detail="Ushbu login band")
    otp_plain = generate_one_time_password()
    store = StoreTenant(
        slug="TENANT-" + secrets.token_hex(4).upper(),
        name=payload.name.strip(),
        tin=payload.tin,
        owner_name=payload.owner_name.strip(),
        phone=payload.phone.strip(),
        login=login_key,
        password_hash=pwd_hasher.hash(otp_plain),
        must_change_password=True,
        plan=payload.plan,
        status="ACTIVE",
        subscription_expires_at=payload.subscription_expires_at,
    )
    db.add(store)
    audit(db, "superadmin", "CREATE_STORE", f"'{store.name}' ({login_key}) yaratildi")
    db.commit()
    return {
        "message": "Do'kon yaratildi. Egasi birinchi kirishda bir martalik parolni yangilashi shart.",
        "login": login_key,
        "slug": store.slug,
        "one_time_password": otp_plain,  # faqat shu javobda bir marta ko'rsatiladi
        "must_change_password": True,
        "subscription_expires_at": payload.subscription_expires_at,
    }


@app.post("/api/superadmin/stores/{login}/reset-otp", dependencies=[Depends(require_superadmin)])
def reset_store_otp(login: str, db: Session = Depends(get_db)):
    store = get_store_by_login(db, login)
    if not store:
        raise HTTPException(status_code=404, detail="Do'kon topilmadi")
    otp_plain = generate_one_time_password()
    store.password_hash = pwd_hasher.hash(otp_plain)
    store.must_change_password = True
    store.token_version = (store.token_version or 0) + 1  # eski sessiyalar bekor
    store.failed_logins = 0
    store.locked_until = None
    audit(db, "superadmin", "ISSUE_OTP", f"'{store.name}' uchun yangi OTP berildi")
    db.commit()
    return {"login": store.login, "one_time_password": otp_plain, "must_change_password": True}


@app.patch("/api/superadmin/stores/{login}/block", dependencies=[Depends(require_superadmin)])
def toggle_block_store(login: str, block: bool = True, db: Session = Depends(get_db)):
    store = get_store_by_login(db, login)
    if not store:
        raise HTTPException(status_code=404, detail="Do'kon topilmadi")
    store.status = "BLOCKED" if block else "ACTIVE"
    audit(db, "superadmin", "BLOCK_STORE" if block else "UNBLOCK_STORE", f"'{store.name}'")
    db.commit()
    return {"login": store.login, "status": effective_status(store)}


@app.patch("/api/superadmin/stores/{login}/subscription", dependencies=[Depends(require_superadmin)])
def set_subscription_date(login: str, payload: UpdateSubscriptionRequest, db: Session = Depends(get_db)):
    store = get_store_by_login(db, login)
    if not store:
        raise HTTPException(status_code=404, detail="Do'kon topilmadi")
    store.subscription_expires_at = payload.subscription_expires_at
    audit(db, "superadmin", "SET_SUBSCRIPTION", f"'{store.name}' -> {payload.subscription_expires_at}")
    db.commit()
    return {
        "login": store.login,
        "subscription_expires_at": store.subscription_expires_at,
        "status": effective_status(store),
    }


@app.delete("/api/superadmin/stores/{login}", dependencies=[Depends(require_superadmin)])
def delete_store(login: str, db: Session = Depends(get_db)):
    store = get_store_by_login(db, login)
    if not store:
        raise HTTPException(status_code=404, detail="Do'kon topilmadi")
    name = store.name
    db.delete(store)
    audit(db, "superadmin", "DELETE_STORE", f"'{name}' ({login}) o'chirildi")
    db.commit()
    return {"deleted": True, "login": login}


# ---------------------------------------------------------------------------
# Do'kon egasi autentifikatsiyasi
# ---------------------------------------------------------------------------
def _register_failure(db: Session, store: StoreTenant) -> None:
    store.failed_logins += 1
    if store.failed_logins >= MAX_FAILED_LOGINS:
        store.locked_until = utcnow() + timedelta(minutes=LOCK_MINUTES)
        store.failed_logins = 0
        audit(db, store.login, "LOGIN_LOCKED", f"{LOCK_MINUTES} daqiqaga bloklandi (ketma-ket xato urinishlar)")
    db.commit()


def _check_credentials(db: Session, login: str, password: str) -> StoreTenant:
    """Login/parolni tekshiradi; xato urinishlarni hisoblaydi va vaqtinchalik bloklaydi."""
    store = get_store_by_login(db, login)
    if not store:
        pwd_hasher.verify(password, _DUMMY_HASH)  # timing tenglashtirish
        raise HTTPException(status_code=401, detail="Login yoki parol noto'g'ri")
    if store.locked_until and _aware(store.locked_until) > utcnow():
        raise HTTPException(status_code=429, detail="Juda ko'p xato urinish. Birozdan keyin qayta urinib ko'ring")
    if not pwd_hasher.verify(password, store.password_hash):
        _register_failure(db, store)
        raise HTTPException(status_code=401, detail="Login yoki parol noto'g'ri")
    if store.failed_logins or store.locked_until:
        store.failed_logins = 0
        store.locked_until = None
        db.commit()
    return store


def issue_token(store: StoreTenant) -> str:
    now = utcnow()
    return jwt.encode(
        {"sub": store.login, "sid": store.id, "tv": store.token_version or 0, "iat": now, "exp": now + timedelta(hours=JWT_TTL_HOURS)},
        JWT_SECRET,
        algorithm="HS256",
    )


@app.post("/api/auth/login")
def store_owner_login(payload: StoreLoginRequest, db: Session = Depends(get_db)):
    store = _check_credentials(db, payload.login, payload.password)
    st = effective_status(store)
    if st == "BLOCKED":
        raise HTTPException(status_code=403, detail="Do'kon hisobi Superadmin tomonidan vaqtincha bloklangan")
    if st == "EXPIRED":
        raise HTTPException(status_code=402, detail="Abonent to'lovi muddati tugagan")
    if store.must_change_password:
        return {
            "status": "FORCE_PASSWORD_CHANGE_REQUIRED",
            "must_change_password": True,
            "message": "Bir martalik parol aniqlandi. Davom etish uchun yangi ishonchli parol o'rnating.",
        }
    token = issue_token(store)
    return {"status": "SUCCESS", "access_token": token, "token_type": "bearer", "must_change_password": False}


@app.post("/api/auth/change-initial-password")
def force_change_initial_password(payload: ForcePasswordChangeRequest, db: Session = Depends(get_db)):
    store = _check_credentials(db, payload.login, payload.one_time_password)
    if not store.must_change_password:
        raise HTTPException(status_code=400, detail="Bu hisobda bir martalik parol faol emas")
    if payload.new_strong_password == payload.one_time_password or not validate_strong_password(
        payload.new_strong_password
    ):
        raise HTTPException(
            status_code=400,
            detail="Yangi parol kamida 8 belgi, katta/kichik harf, raqam va maxsus belgidan iborat bo'lishi shart",
        )
    store.password_hash = pwd_hasher.hash(payload.new_strong_password)
    store.token_version = (store.token_version or 0) + 1
    store.must_change_password = False
    audit(db, store.login, "OTP_PASSWORD_CHANGED", f"'{store.name}' egasi parolni almashtirdi")
    db.commit()
    return {"status": "PASSWORD_UPDATED", "must_change_password": False}


class ChangePasswordRequest(BaseModel):
    current_password: str = Field(max_length=256)
    new_password: str = Field(max_length=256)


@app.post("/api/store/change-password")
def change_password(payload: ChangePasswordRequest, store: StoreTenant = Depends(current_store), db: Session = Depends(get_db)):
    # 401/402/403 frontendni tizimdan chiqarib yuboradi, shuning uchun xatolar uchun 400
    if not pwd_hasher.verify(payload.current_password, store.password_hash):
        _register_failure(db, store)
        raise HTTPException(status_code=400, detail="Joriy parol noto'g'ri")
    if payload.new_password == payload.current_password or not validate_strong_password(payload.new_password):
        raise HTTPException(
            status_code=400,
            detail="Yangi parol joriyidan farq qilishi va kamida 8 belgi, katta/kichik harf, raqam va maxsus belgidan iborat bo'lishi shart",
        )
    store.password_hash = pwd_hasher.hash(payload.new_password)
    store.token_version = (store.token_version or 0) + 1  # boshqa qurilmalardagi sessiyalar bekor bo'ladi
    audit(db, store.login, "PASSWORD_CHANGED", f"'{store.name}' egasi parolni almashtirdi")
    db.commit()
    return {"status": "PASSWORD_UPDATED", "access_token": issue_token(store), "token_type": "bearer"}


@app.post("/api/store/logout")
def store_logout(store: StoreTenant = Depends(current_store), db: Session = Depends(get_db)):
    """Barcha qurilmalardagi joriy tokenlarni serverda bekor qiladi."""
    store.token_version = (store.token_version or 0) + 1
    db.commit()
    return {"status": "LOGGED_OUT"}


# ---------------------------------------------------------------------------
# Do'kon CRM: tovarlar (har bir so'rov faqat o'z do'koni ma'lumotiga ega)
# ---------------------------------------------------------------------------
def product_out(p: Product) -> dict:
    return {
        "id": p.id, "sku": p.sku, "name": p.name, "category": p.category,
        "cost_uzs": p.cost_uzs, "price_uzs": p.price_uzs, "stock_qty": p.stock_qty,
    }


def customer_out(c: Customer) -> dict:
    return {
        "id": c.id, "full_name": c.full_name, "phone": c.phone,
        "total_spent_uzs": c.total_spent_uzs, "debt_uzs": c.debt_uzs,
    }


def employee_out(e: Employee) -> dict:
    return {
        "id": e.id,
        "first_name": e.first_name,
        "last_name": e.last_name,
        "phone": e.phone,
        "salary_uzs": e.salary_uzs,
        "advance_uzs": e.advance_uzs,
        "payable_uzs": e.salary_uzs - e.advance_uzs,
    }


def receipt_out(r: SaleReceipt) -> dict:
    return {
        "receipt_code": r.receipt_code, "customer_id": r.customer_id, "customer_name": r.customer_name, "items": r.items_summary,
        "payment_method": r.payment_method, "total_uzs": r.total_uzs, "profit_uzs": r.profit_uzs,
        "created_at": r.created_at, "refunded": r.refunded_at is not None, "refunded_at": r.refunded_at,
        "refunded_uzs": r.refunded_uzs or 0, "original_total_uzs": r.total_uzs + (r.refunded_uzs or 0),
    }


@app.get("/api/store/me")
def store_me(store: StoreTenant = Depends(current_store)):
    return store_public(store)


@app.get("/api/store/products")
def list_products(
    q: str | None = None, limit: int = 2000, offset: int = 0,
    store: StoreTenant = Depends(current_store), db: Session = Depends(get_db),
):
    stmt = select(Product).where(Product.store_id == store.id)
    if q and q.strip():
        like = f"%{q.strip().lower()}%"
        stmt = stmt.where(or_(func.lower(Product.name).like(like), func.lower(Product.sku).like(like)))
    rows = db.scalars(stmt.order_by(Product.name, Product.id).limit(max(1, min(limit, 5000))).offset(max(0, offset))).all()
    return [product_out(p) for p in rows]


@app.post("/api/store/products", status_code=201)
def create_product(payload: ProductIn, store: StoreTenant = Depends(current_store), db: Session = Depends(get_db)):
    data = payload.model_dump()
    data["sku"] = data["sku"].strip() or "P-" + secrets.token_hex(4).upper()
    data["category"] = data["category"].strip() or "Umumiy"
    exists = db.scalar(select(Product).where(Product.store_id == store.id, Product.sku == data["sku"]))
    if exists:
        raise HTTPException(status_code=400, detail="Bu SKU/shtrixkod allaqachon mavjud")
    p = Product(store_id=store.id, **data)
    db.add(p)
    db.commit()
    return product_out(p)


@app.post("/api/store/products/{sku}/restock")
def restock_product(
    sku: str, payload: RestockRequest, store: StoreTenant = Depends(current_store), db: Session = Depends(get_db)
):
    p = db.scalar(select(Product).where(Product.store_id == store.id, Product.sku == sku).with_for_update())
    if not p:
        raise HTTPException(status_code=404, detail="Tovar topilmadi")
    p.stock_qty += payload.qty
    db.commit()
    return product_out(p)


@app.patch("/api/store/products/{sku}")
def update_product(
    sku: str, payload: ProductUpdate, store: StoreTenant = Depends(current_store), db: Session = Depends(get_db)
):
    p = db.scalar(select(Product).where(Product.store_id == store.id, Product.sku == sku).with_for_update())
    if not p:
        raise HTTPException(status_code=404, detail="Tovar topilmadi")
    data = payload.model_dump(exclude_unset=True)
    if "sku" in data:
        new_sku = (data["sku"] or "").strip()
        if not new_sku:
            raise HTTPException(status_code=400, detail="SKU bo'sh bo'lishi mumkin emas")
        if new_sku != p.sku and db.scalar(select(Product.id).where(Product.store_id == store.id, Product.sku == new_sku)):
            raise HTTPException(status_code=400, detail="Bu SKU/shtrixkod allaqachon mavjud")
        p.sku = new_sku
    if "name" in data:
        p.name = data["name"].strip()
        if not p.name:
            raise HTTPException(status_code=400, detail="Tovar nomi bo'sh bo'lishi mumkin emas")
    if "category" in data:
        p.category = (data["category"] or "").strip() or "Umumiy"
    for f in ("cost_uzs", "price_uzs", "stock_qty"):
        if data.get(f) is not None:
            setattr(p, f, data[f])
    audit(db, store.login, "UPDATE_PRODUCT", f"{p.sku}: {', '.join(sorted(data))}")
    db.commit()
    return product_out(p)


@app.delete("/api/store/products/{sku}")
def delete_product(sku: str, store: StoreTenant = Depends(current_store), db: Session = Depends(get_db)):
    p = db.scalar(select(Product).where(Product.store_id == store.id, Product.sku == sku).with_for_update())
    if not p:
        raise HTTPException(status_code=404, detail="Tovar topilmadi")
    audit(db, store.login, "DELETE_PRODUCT", f"{p.sku} ({p.name}), qoldiq {p.stock_qty}")
    db.delete(p)  # eski cheklardagi nom/summalar SaleItem'da saqlanib qoladi
    db.commit()
    return {"deleted": True}


# ---------------------------------------------------------------------------
# Mijozlar
# ---------------------------------------------------------------------------
@app.get("/api/store/customers")
def list_customers(
    q: str | None = None, limit: int = 2000, offset: int = 0,
    store: StoreTenant = Depends(current_store), db: Session = Depends(get_db),
):
    stmt = select(Customer).where(Customer.store_id == store.id)
    if q and q.strip():
        like = f"%{q.strip().lower()}%"
        stmt = stmt.where(or_(func.lower(Customer.full_name).like(like), Customer.phone.like(like)))
    rows = db.scalars(stmt.order_by(Customer.full_name, Customer.id).limit(max(1, min(limit, 5000))).offset(max(0, offset))).all()
    return [customer_out(c) for c in rows]


class CustomerUpdate(BaseModel):
    full_name: str | None = Field(default=None, min_length=2, max_length=120)
    phone: str | None = Field(default=None, min_length=7, max_length=32)


@app.patch("/api/store/customers/{customer_id}")
def update_customer(
    customer_id: int, payload: CustomerUpdate, store: StoreTenant = Depends(current_store), db: Session = Depends(get_db)
):
    c = db.scalar(select(Customer).where(Customer.id == customer_id, Customer.store_id == store.id).with_for_update())
    if not c:
        raise HTTPException(status_code=404, detail="Mijoz topilmadi")
    data = payload.model_dump(exclude_unset=True)
    if data.get("full_name") is not None:
        c.full_name = data["full_name"].strip()
    if data.get("phone") is not None:
        c.phone = data["phone"].strip()
    audit(db, store.login, "UPDATE_CUSTOMER", f"#{c.id} {c.full_name}")
    db.commit()
    return customer_out(c)


@app.delete("/api/store/customers/{customer_id}")
def delete_customer(customer_id: int, store: StoreTenant = Depends(current_store), db: Session = Depends(get_db)):
    c = db.scalar(select(Customer).where(Customer.id == customer_id, Customer.store_id == store.id).with_for_update())
    if not c:
        raise HTTPException(status_code=404, detail="Mijoz topilmadi")
    if c.debt_uzs > 0:
        raise HTTPException(status_code=400, detail="Qarzi bor mijozni o'chirib bo'lmaydi. Avval qarzni so'ndiring")
    audit(db, store.login, "DELETE_CUSTOMER", f"#{c.id} {c.full_name}")
    db.delete(c)  # eski cheklarda mijoz nomi saqlanib qoladi
    db.commit()
    return {"deleted": True}


@app.post("/api/store/customers", status_code=201)
def create_customer(payload: CustomerIn, store: StoreTenant = Depends(current_store), db: Session = Depends(get_db)):
    c = Customer(store_id=store.id, full_name=payload.full_name.strip(), phone=payload.phone.strip())
    db.add(c)
    db.commit()
    return customer_out(c)


@app.post("/api/store/customers/{customer_id}/pay-debt")
def pay_customer_debt(
    customer_id: int, payload: PayDebtRequest, store: StoreTenant = Depends(current_store), db: Session = Depends(get_db)
):
    c = db.scalar(select(Customer).where(Customer.id == customer_id, Customer.store_id == store.id).with_for_update())
    if not c:
        raise HTTPException(status_code=404, detail="Mijoz topilmadi")
    if payload.amount_uzs > c.debt_uzs:
        raise HTTPException(status_code=400, detail="To'lov summasi qarzdan oshib ketdi")
    c.debt_uzs -= payload.amount_uzs
    audit(db, store.login, "PAY_DEBT", f"{c.full_name}: {payload.amount_uzs} so'm to'landi, qoldi {c.debt_uzs}")
    db.commit()
    return customer_out(c)


# ---------------------------------------------------------------------------
# Xodimlar: ism, telefon, oylik va olingan avans
# ---------------------------------------------------------------------------
class EmployeeIn(BaseModel):
    first_name: str = Field(min_length=2, max_length=80)
    last_name: str = Field(min_length=2, max_length=80)
    phone: str = Field(min_length=7, max_length=32)
    salary_uzs: int = Field(default=0, ge=0, le=10**12)
    advance_uzs: int = Field(default=0, ge=0, le=10**12)


class EmployeeUpdate(BaseModel):
    first_name: str | None = Field(default=None, min_length=2, max_length=80)
    last_name: str | None = Field(default=None, min_length=2, max_length=80)
    phone: str | None = Field(default=None, min_length=7, max_length=32)
    salary_uzs: int | None = Field(default=None, ge=0, le=10**12)
    advance_uzs: int | None = Field(default=None, ge=0, le=10**12)


@app.get("/api/store/employees")
def list_employees(
    q: str | None = None, limit: int = 2000, offset: int = 0,
    store: StoreTenant = Depends(current_store), db: Session = Depends(get_db),
):
    stmt = select(Employee).where(Employee.store_id == store.id)
    if q and q.strip():
        like = f"%{q.strip().lower()}%"
        stmt = stmt.where(or_(
            func.lower(Employee.first_name).like(like),
            func.lower(Employee.last_name).like(like),
            Employee.phone.like(like),
        ))
    rows = db.scalars(stmt.order_by(Employee.last_name, Employee.first_name, Employee.id).limit(max(1, min(limit, 5000))).offset(max(0, offset))).all()
    return [employee_out(e) for e in rows]


@app.post("/api/store/employees", status_code=201)
def create_employee(payload: EmployeeIn, store: StoreTenant = Depends(current_store), db: Session = Depends(get_db)):
    e = Employee(
        store_id=store.id,
        first_name=payload.first_name.strip(),
        last_name=payload.last_name.strip(),
        phone=payload.phone.strip(),
        salary_uzs=payload.salary_uzs,
        advance_uzs=payload.advance_uzs,
    )
    if len(e.first_name) < 2 or len(e.last_name) < 2 or len(e.phone) < 7:
        raise HTTPException(status_code=400, detail="Ism, familiya va telefon to'liq kiriting")
    db.add(e)
    db.flush()
    if e.advance_uzs > 0:
        db.add(EmployeeAdvance(store_id=store.id, employee_id=e.id, amount_uzs=e.advance_uzs, kind="initial", note="Boshlang'ich avans"))
    audit(db, store.login, "CREATE_EMPLOYEE", f"{e.last_name} {e.first_name}, oylik {e.salary_uzs}, avans {e.advance_uzs}")
    db.commit()
    return employee_out(e)


@app.patch("/api/store/employees/{employee_id}")
def update_employee(
    employee_id: int, payload: EmployeeUpdate, store: StoreTenant = Depends(current_store), db: Session = Depends(get_db)
):
    e = db.scalar(select(Employee).where(Employee.id == employee_id, Employee.store_id == store.id).with_for_update())
    if not e:
        raise HTTPException(status_code=404, detail="Xodim topilmadi")
    data = payload.model_dump(exclude_unset=True)
    if "first_name" in data:
        e.first_name = data["first_name"].strip()
    if "last_name" in data:
        e.last_name = data["last_name"].strip()
    if "phone" in data:
        e.phone = data["phone"].strip()
    if len(e.first_name) < 2 or len(e.last_name) < 2 or len(e.phone) < 7:
        raise HTTPException(status_code=400, detail="Ism, familiya va telefon to'liq kiriting")
    if data.get("salary_uzs") is not None:
        e.salary_uzs = data["salary_uzs"]
    if data.get("advance_uzs") is not None and data["advance_uzs"] != e.advance_uzs:
        diff = data["advance_uzs"] - e.advance_uzs
        db.add(EmployeeAdvance(store_id=store.id, employee_id=e.id, amount_uzs=diff, kind="adjust", note="Qo'lda tuzatish"))
        e.advance_uzs = data["advance_uzs"]
    audit(db, store.login, "UPDATE_EMPLOYEE", f"#{e.id} {e.last_name} {e.first_name}: oylik {e.salary_uzs}, avans {e.advance_uzs}")
    db.commit()
    return employee_out(e)


class AdvanceIn(BaseModel):
    amount_uzs: int = Field(gt=0, le=10**10)
    note: str = Field(default="", max_length=200)


def _advance_out(a: EmployeeAdvance) -> dict:
    return {"id": a.id, "amount_uzs": a.amount_uzs, "note": a.note, "kind": a.kind, "created_at": a.created_at}


def _employee_for_update(db: Session, store: StoreTenant, employee_id: int) -> Employee:
    e = db.scalar(select(Employee).where(Employee.id == employee_id, Employee.store_id == store.id).with_for_update())
    if not e:
        raise HTTPException(status_code=404, detail="Xodim topilmadi")
    return e


@app.get("/api/store/employees/{employee_id}/advances")
def list_advances(employee_id: int, store: StoreTenant = Depends(current_store), db: Session = Depends(get_db)):
    e = db.scalar(select(Employee).where(Employee.id == employee_id, Employee.store_id == store.id))
    if not e:
        raise HTTPException(status_code=404, detail="Xodim topilmadi")
    rows = db.scalars(
        select(EmployeeAdvance).where(EmployeeAdvance.employee_id == e.id).order_by(EmployeeAdvance.id.desc()).limit(300)
    ).all()
    return {"employee": employee_out(e), "advances": [_advance_out(a) for a in rows]}


@app.post("/api/store/employees/{employee_id}/advances", status_code=201)
def give_advance(
    employee_id: int, payload: AdvanceIn, store: StoreTenant = Depends(current_store), db: Session = Depends(get_db)
):
    e = _employee_for_update(db, store, employee_id)
    e.advance_uzs += payload.amount_uzs
    note = payload.note.strip()
    db.add(EmployeeAdvance(store_id=store.id, employee_id=e.id, amount_uzs=payload.amount_uzs, kind="advance", note=note))
    audit(db, store.login, "GIVE_ADVANCE", f"{e.last_name} {e.first_name}: +{payload.amount_uzs} som avans")
    db.commit()
    return employee_out(e)


@app.delete("/api/store/employees/{employee_id}/advances/{advance_id}")
def delete_advance(
    employee_id: int, advance_id: int, store: StoreTenant = Depends(current_store), db: Session = Depends(get_db)
):
    e = _employee_for_update(db, store, employee_id)
    a = db.scalar(select(EmployeeAdvance).where(EmployeeAdvance.id == advance_id, EmployeeAdvance.employee_id == e.id))
    if not a:
        raise HTTPException(status_code=404, detail="Avans yozuvi topilmadi")
    e.advance_uzs = max(0, e.advance_uzs - a.amount_uzs)  # xato kiritilgan yozuv bekor qilinadi
    audit(db, store.login, "DELETE_ADVANCE", f"{e.last_name} {e.first_name}: {a.amount_uzs} som yozuvi o'chirildi")
    db.delete(a)
    db.commit()
    return employee_out(e)


@app.delete("/api/store/employees/{employee_id}")
def delete_employee(employee_id: int, store: StoreTenant = Depends(current_store), db: Session = Depends(get_db)):
    e = db.scalar(select(Employee).where(Employee.id == employee_id, Employee.store_id == store.id).with_for_update())
    if not e:
        raise HTTPException(status_code=404, detail="Xodim topilmadi")
    audit(db, store.login, "DELETE_EMPLOYEE", f"#{e.id} {e.last_name} {e.first_name}")
    db.delete(e)
    db.commit()
    return {"deleted": True}


# ---------------------------------------------------------------------------
# Savdo (POS): narx va qoldiq serverda hisoblanadi, bitta tranzaksiyada
# ---------------------------------------------------------------------------
def _new_receipt_code(db: Session, store_id: str) -> str:
    for _ in range(10):
        code = "CHK-" + secrets.token_hex(4).upper()
        if not db.scalar(select(SaleReceipt.id).where(SaleReceipt.store_id == store_id, SaleReceipt.receipt_code == code)):
            return code
    raise HTTPException(status_code=500, detail="Chek raqamini yaratib bo'lmadi")


@app.post("/api/store/sales", status_code=201)
def create_sale(
    payload: SaleRequest,
    background: BackgroundTasks,
    store: StoreTenant = Depends(current_store),
    db: Session = Depends(get_db),
    idempotency_key: str | None = Header(default=None, alias="Idempotency-Key", max_length=64),
):
    # Bir xil SKU takrorlansa birlashtiriladi; deadlock oldini olish uchun tartiblanadi
    qty_by_sku: dict[str, int] = {}
    for it in payload.items:
        qty_by_sku[it.sku] = qty_by_sku.get(it.sku, 0) + it.qty

    products = db.scalars(
        select(Product)
        .where(Product.store_id == store.id, Product.sku.in_(sorted(qty_by_sku)))
        .order_by(Product.id)
        .with_for_update()
    ).all()
    by_sku = {p.sku: p for p in products}
    idem = (idempotency_key or "").strip() or None
    if idem:  # tovarlar bloklangandan keyin tekshiriladi: parallel takroriy so'rov birinchisini kutadi
        prev = db.scalar(select(SaleReceipt).where(SaleReceipt.store_id == store.id, SaleReceipt.idem_key == idem))
        if prev:
            return receipt_out(prev)
    missing = [s for s in qty_by_sku if s not in by_sku]
    if missing:
        raise HTTPException(status_code=404, detail=f"Tovar topilmadi: {', '.join(missing)}")

    customer = None
    if payload.customer_id is not None:
        customer = db.scalar(
            select(Customer).where(Customer.id == payload.customer_id, Customer.store_id == store.id).with_for_update()
        )
        if not customer:
            raise HTTPException(status_code=404, detail="Mijoz topilmadi")
    if payload.payment_method == "Nasiya" and customer is None:
        raise HTTPException(status_code=400, detail="Nasiya savdo uchun mijoz tanlanishi shart")

    subtotal = cost_total = 0
    parts: list[str] = []
    sold: list[tuple[Product, int]] = []
    for sku, qty in qty_by_sku.items():
        p = by_sku[sku]
        if p.stock_qty < qty:
            raise HTTPException(status_code=400, detail=f"'{p.name}' omborda yetarli emas (qoldiq: {p.stock_qty})")
        subtotal += p.price_uzs * qty
        cost_total += p.cost_uzs * qty
        parts.append(f"{p.name} x{qty}")
        sold.append((p, qty))
    for sku, qty in qty_by_sku.items():
        by_sku[sku].stock_qty -= qty

    discount = subtotal * payload.discount_pct // 100
    total = subtotal - discount
    profit = total - cost_total

    if customer is not None:
        customer.total_spent_uzs += total
        if payload.payment_method == "Nasiya":
            customer.debt_uzs += total

    receipt_code = _new_receipt_code(db, store.id)
    receipt = SaleReceipt(
        store_id=store.id,
        idem_key=idem,
        receipt_code=receipt_code,
        customer_name=customer.full_name if customer else "Umumiy xaridor",
        customer_id=customer.id if customer else None,
        items_summary=", ".join(parts)[:2000],
        payment_method=payload.payment_method,
        total_uzs=total,
        profit_uzs=profit,
    )
    db.add(receipt)
    db.flush()  # receipt.id kerak
    for p, qty in sold:
        db.add(SaleItem(receipt_id=receipt.id, store_id=store.id, sku=p.sku, name=p.name, qty=qty, line_total_uzs=p.price_uzs * qty))
    try:
        db.commit()
    except IntegrityError:
        db.rollback()
        prev = db.scalar(select(SaleReceipt).where(SaleReceipt.store_id == store.id, SaleReceipt.idem_key == idem)) if idem else None
        if prev:
            return receipt_out(prev)
        raise HTTPException(status_code=409, detail="Sotuvni saqlashda to'qnashuv. Qayta urinib ko'ring")

    # Omborga xabar: sotuv javobini kechiktirmaslik uchun fon vazifasi
    background.add_task(tg.notify_sale, store.id, {
        "receipt_code": receipt.receipt_code,
        "time": datetime.now(tg.TZ).strftime("%H:%M"),
        "customer": receipt.customer_name,
        "payment_method": receipt.payment_method,
        "total": total,
        "lines": [{"name": p.name, "qty": qty, "stock_left": p.stock_qty} for p, qty in sold],
    })
    return receipt_out(receipt)


@app.get("/api/store/sales")
def list_sales(
    limit: int = 100, offset: int = 0, q: str | None = None,
    store: StoreTenant = Depends(current_store), db: Session = Depends(get_db),
):
    limit = max(1, min(limit, 500))
    stmt = select(SaleReceipt).where(SaleReceipt.store_id == store.id)
    if q and q.strip():
        like = f"%{q.strip().lower()}%"
        stmt = stmt.where(or_(func.lower(SaleReceipt.receipt_code).like(like), func.lower(SaleReceipt.customer_name).like(like)))
    rows = db.scalars(stmt.order_by(SaleReceipt.id.desc()).limit(limit).offset(max(0, offset))).all()
    return [receipt_out(r) for r in rows]


def _receipt_detail(db: Session, r: SaleReceipt) -> dict:
    items = db.scalars(select(SaleItem).where(SaleItem.receipt_id == r.id).order_by(SaleItem.id)).all()
    return {
        **receipt_out(r),
        "lines": [
            {"sku": i.sku, "name": i.name, "qty": i.qty, "refunded_qty": i.refunded_qty or 0, "line_total_uzs": i.line_total_uzs}
            for i in items
        ],
    }


@app.get("/api/store/sales/{receipt_code}")
def sale_detail(receipt_code: str, store: StoreTenant = Depends(current_store), db: Session = Depends(get_db)):
    r = db.scalar(select(SaleReceipt).where(SaleReceipt.store_id == store.id, SaleReceipt.receipt_code == receipt_code))
    if not r:
        raise HTTPException(status_code=404, detail="Chek topilmadi")
    return _receipt_detail(db, r)


class RefundItemIn(BaseModel):
    sku: str = Field(max_length=64)
    qty: int = Field(gt=0, le=10**5)


class RefundRequest(BaseModel):
    items: list[RefundItemIn] | None = Field(default=None, max_length=200)  # bo'sh bo'lsa: qolgan hammasi


@app.post("/api/store/sales/{receipt_code}/refund")
def refund_sale(
    receipt_code: str,
    payload: RefundRequest | None = None,
    store: StoreTenant = Depends(current_store),
    db: Session = Depends(get_db),
):
    """To'liq yoki qisman qaytarish: ombor va mijoz hisobi (xarid yoki nasiya) tiklanadi."""
    r = db.scalar(
        select(SaleReceipt)
        .where(SaleReceipt.store_id == store.id, SaleReceipt.receipt_code == receipt_code)
        .with_for_update()
    )
    if not r:
        raise HTTPException(status_code=404, detail="Chek topilmadi")
    if r.refunded_at is not None:
        raise HTTPException(status_code=409, detail="Bu chek allaqachon to'liq qaytarilgan")

    items = db.scalars(select(SaleItem).where(SaleItem.receipt_id == r.id).order_by(SaleItem.id).with_for_update()).all()
    wanted = payload.items if payload and payload.items else None
    stock_ok = True

    if not items:  # tovar qatorlari saqlanmagan eski chek: faqat to'liq qaytariladi
        if wanted:
            raise HTTPException(status_code=400, detail="Eski chekni faqat to'liq qaytarish mumkin")
        amt, profit_cut, all_done, plan = r.total_uzs, r.profit_uzs, True, []
        stock_ok = False
    else:
        by_sku = {i.sku: i for i in items}
        req: dict[str, int] = {}
        if wanted:
            for w in wanted:
                req[w.sku] = req.get(w.sku, 0) + w.qty
        else:
            req = {i.sku: i.qty - (i.refunded_qty or 0) for i in items if i.qty - (i.refunded_qty or 0) > 0}
        if not req:
            raise HTTPException(status_code=409, detail="Qaytariladigan tovar qolmagan")
        gross_before = Fraction(0)
        gross_ref = Fraction(0)
        for sku, q in req.items():
            it = by_sku.get(sku)
            if it is None:
                raise HTTPException(status_code=400, detail=f"Chekda bunday tovar yo'q: {sku}")
            if q > it.qty - (it.refunded_qty or 0):
                raise HTTPException(status_code=400, detail=f"'{it.name}': qaytariladigan miqdor oshib ketdi")
            gross_ref += Fraction(it.line_total_uzs * q, it.qty)
        for it in items:
            gross_before += Fraction(it.line_total_uzs * (it.qty - (it.refunded_qty or 0)), it.qty)
        all_done = all(req.get(i.sku, 0) == i.qty - (i.refunded_qty or 0) for i in items)
        if all_done:
            amt, profit_cut = r.total_uzs, r.profit_uzs
        elif gross_before > 0:
            share = gross_ref / gross_before
            amt, profit_cut = int(r.total_uzs * share), int(r.profit_uzs * share)
        else:
            amt = profit_cut = 0
        plan = [(by_sku[sku], q) for sku, q in sorted(req.items())]

    for it, q in plan:
        it.refunded_qty = (it.refunded_qty or 0) + q
        p = db.scalar(select(Product).where(Product.store_id == store.id, Product.sku == it.sku).with_for_update())
        if p:
            p.stock_qty += q
        else:
            stock_ok = False  # tovar o'chirilgan

    if r.customer_id is not None:
        c = db.scalar(select(Customer).where(Customer.id == r.customer_id, Customer.store_id == store.id).with_for_update())
        if c:
            c.total_spent_uzs = max(0, c.total_spent_uzs - amt)
            if r.payment_method == "Nasiya":
                c.debt_uzs = max(0, c.debt_uzs - amt)

    r.total_uzs -= amt
    r.profit_uzs -= profit_cut
    r.refunded_uzs = (r.refunded_uzs or 0) + amt
    if all_done:
        r.refunded_at = utcnow()
    kind = "toliq" if all_done else "qisman"
    audit(db, store.login, "REFUND_SALE", f"{r.receipt_code}: {amt} som ({kind}), {r.payment_method}")
    db.commit()
    return {**_receipt_detail(db, r), "stock_restored": stock_ok, "had_items": bool(items), "refund_uzs": amt}


@app.get("/api/store/dashboard")
def dashboard(store: StoreTenant = Depends(current_store), db: Session = Depends(get_db)):
    inv_value, sku_count = db.execute(
        select(func.coalesce(func.sum(Product.price_uzs * Product.stock_qty), 0), func.count(Product.id)).where(Product.store_id == store.id)
    ).one()
    debt_total, debtor_count, customer_count = db.execute(
        select(
            func.coalesce(func.sum(Customer.debt_uzs), 0),
            func.coalesce(func.sum(case((Customer.debt_uzs > 0, 1), else_=0)), 0),
            func.count(Customer.id),
        ).where(Customer.store_id == store.id)
    ).one()
    low_products = db.scalars(
        select(Product).where(Product.store_id == store.id, Product.stock_qty <= 10).order_by(Product.stock_qty, Product.name).limit(50)
    ).all()

    # So'nggi 14 kun (Toshkent kunlari): 7 kunlik grafik + oldingi hafta bilan solishtirish
    today = datetime.now(tg.TZ).date()
    first_day = today - timedelta(days=13)
    since = datetime.combine(first_day, datetime.min.time(), tzinfo=tg.TZ).astimezone(timezone.utc)
    recent = db.scalars(select(SaleReceipt).where(SaleReceipt.store_id == store.id, SaleReceipt.created_at >= since, SaleReceipt.refunded_at.is_(None))).all()
    per_day: dict[date, list[int]] = {}
    for r in recent:
        d = _aware(r.created_at).astimezone(tg.TZ).date()
        cell = per_day.setdefault(d, [0, 0])
        cell[0] += r.total_uzs
        cell[1] += r.profit_uzs
    weekly = []
    for k in range(6, -1, -1):
        d = today - timedelta(days=k)
        rev, prof = per_day.get(d, [0, 0])
        weekly.append({"date": d.isoformat(), "revenue_uzs": rev, "profit_uzs": prof})
    week_revenue = sum(x["revenue_uzs"] for x in weekly)
    week_profit = sum(x["profit_uzs"] for x in weekly)
    prev_week_revenue = sum(per_day.get(today - timedelta(days=k), [0, 0])[0] for k in range(7, 14))

    # Jami to'lov turlari bo'yicha (butun tarix)
    by_method: dict[str, int] = {}
    for method, total in db.execute(
        select(SaleReceipt.payment_method, func.sum(SaleReceipt.total_uzs))
        .where(SaleReceipt.store_id == store.id, SaleReceipt.refunded_at.is_(None))
        .group_by(SaleReceipt.payment_method)
    ).all():
        by_method[method] = int(total or 0)

    return {
        "week_revenue_uzs": week_revenue,
        "week_profit_uzs": week_profit,
        "prev_week_revenue_uzs": prev_week_revenue,
        "margin_pct": round(week_profit * 100 / week_revenue, 1) if week_revenue else 0,
        "weekly": weekly,
        "by_method": by_method,
        "inventory_value_uzs": int(inv_value),
        "sku_count": int(sku_count),
        "total_debt_uzs": int(debt_total),
        "debtor_count": int(debtor_count),
        "customer_count": int(customer_count),
        "low_stock": [product_out(p) for p in low_products],
    }


# ---------------------------------------------------------------------------
# CSV eksport (Excel uchun UTF-8 BOM bilan)
# ---------------------------------------------------------------------------
def _csv_cell(v):
    if isinstance(v, str) and v[:1] in ("=", "+", "-", "@", "\t", "\r"):
        return "'" + v  # formula in'ektsiyasidan himoya
    return v


def _csv_response(filename: str, header: list[str], rows) -> Response:
    buf = io.StringIO()
    w = csv.writer(buf, delimiter=";")
    w.writerow(header)
    for row in rows:
        w.writerow([_csv_cell(v) for v in row])
    return Response(
        content="\ufeff" + buf.getvalue(),
        media_type="text/csv; charset=utf-8",
        headers={"Content-Disposition": f'attachment; filename="{filename}"'},
    )


@app.get("/api/store/export/{kind}")
def export_csv(
    kind: Literal["sales", "products", "customers"],
    from_date: date | None = None,
    to_date: date | None = None,
    store: StoreTenant = Depends(current_store),
    db: Session = Depends(get_db),
):
    stamp = datetime.now(tg.TZ).strftime("%Y%m%d")
    if kind == "products":
        rows = db.scalars(select(Product).where(Product.store_id == store.id).order_by(Product.name).limit(50000)).all()
        return _csv_response(
            f"tovarlar-{stamp}.csv",
            ["SKU", "Nomi", "Toifa", "Tannarx", "Sotuv narxi", "Qoldiq"],
            [(p.sku, p.name, p.category, p.cost_uzs, p.price_uzs, p.stock_qty) for p in rows],
        )
    if kind == "customers":
        rows = db.scalars(select(Customer).where(Customer.store_id == store.id).order_by(Customer.full_name).limit(50000)).all()
        return _csv_response(
            f"mijozlar-{stamp}.csv",
            ["Ism", "Telefon", "Jami xarid", "Nasiya qarzi"],
            [(c.full_name, c.phone, c.total_spent_uzs, c.debt_uzs) for c in rows],
        )
    stmt = select(SaleReceipt).where(SaleReceipt.store_id == store.id)
    if from_date:
        stmt = stmt.where(SaleReceipt.created_at >= datetime.combine(from_date, datetime.min.time(), tzinfo=tg.TZ).astimezone(timezone.utc))
    if to_date:
        stmt = stmt.where(SaleReceipt.created_at < datetime.combine(to_date + timedelta(days=1), datetime.min.time(), tzinfo=tg.TZ).astimezone(timezone.utc))
    rows = db.scalars(stmt.order_by(SaleReceipt.id.desc()).limit(50000)).all()
    return _csv_response(
        f"cheklar-{stamp}.csv",
        ["Chek", "Vaqt (Toshkent)", "Mijoz", "Tovarlar", "To'lov turi", "Summa", "Foyda", "Qaytarilgan summa", "Holat"],
        [
            (
                r.receipt_code, _aware(r.created_at).astimezone(tg.TZ).strftime("%d.%m.%Y %H:%M"), r.customer_name,
                r.items_summary, r.payment_method, r.total_uzs, r.profit_uzs, r.refunded_uzs or 0,
                "Qaytarilgan" if r.refunded_at else ("Qisman qaytarilgan" if r.refunded_uzs else "Sotilgan"),
            )
            for r in rows
        ],
    )



@app.get("/api/store/customers/{customer_id}/history")
def customer_history(customer_id: int, store: StoreTenant = Depends(current_store), db: Session = Depends(get_db)):
    c = db.scalar(select(Customer).where(Customer.id == customer_id, Customer.store_id == store.id))
    if not c:
        raise HTTPException(status_code=404, detail="Mijoz topilmadi")
    rows = db.scalars(
        select(SaleReceipt)
        .where(
            SaleReceipt.store_id == store.id,
            (SaleReceipt.customer_id == c.id) | ((SaleReceipt.customer_id.is_(None)) & (SaleReceipt.customer_name == c.full_name)),
        )
        .order_by(SaleReceipt.id.desc())
        .limit(10)
    ).all()
    return {"last_visit": rows[0].created_at if rows else None, "receipts": [receipt_out(r) for r in rows]}


# ---------------------------------------------------------------------------
# Telegram botlar
# ---------------------------------------------------------------------------
BotName = Literal["sales", "report"]


@app.post("/api/telegram/{bot}")
def telegram_webhook(
    bot: BotName,
    update: dict = Body(...),
    x_telegram_bot_api_secret_token: str | None = Header(default=None),
    db: Session = Depends(get_db),
):
    secret = tg.WEBHOOK_SECRET
    if not secret or not x_telegram_bot_api_secret_token or not secrets.compare_digest(
        x_telegram_bot_api_secret_token.encode(), secret.encode()
    ):
        raise HTTPException(status_code=403, detail="Forbidden")
    try:
        tg.handle_update(db, bot, update)
    except Exception:  # Telegram qayta-qayta yubormasligi uchun har doim 200
        log.exception("Telegram webhook xatosi (bot=%s)", bot)
        db.rollback()
    return {"ok": True}


@app.post("/api/superadmin/telegram/setup", dependencies=[Depends(require_superadmin)])
def telegram_setup():
    return tg.setup_webhooks(PUBLIC_URL)


@app.post("/api/internal/daily-report")
def cron_daily_report(x_cron_key: str | None = Header(default=None), db: Session = Depends(get_db)):
    """Har kuni 20:00 (Toshkent) tashqi jadval (GitHub Actions) chaqiradi."""
    if not CRON_KEY:
        raise HTTPException(status_code=503, detail="CRON_KEY o'rnatilmagan")
    if not x_cron_key or not secrets.compare_digest(x_cron_key.encode(), CRON_KEY.encode()):
        raise HTTPException(status_code=403, detail="Forbidden")
    return tg.send_daily_reports(db)


def _bot_state(db: Session, store: StoreTenant, bot: str) -> dict:
    links = tg.chats_for(db, store.id, bot)
    return {
        "configured": tg.configured(bot),
        "username": tg.bot_username(bot) if tg.configured(bot) else None,
        "links": [{"id": l.id, "chat_title": l.chat_title, "created_at": l.created_at} for l in links],
    }


@app.get("/api/store/bots")
def store_bots(store: StoreTenant = Depends(current_store), db: Session = Depends(get_db)):
    return {bot: _bot_state(db, store, bot) for bot in tg.BOTS}


@app.post("/api/store/bots/{bot}/link-code")
def store_bot_link_code(bot: BotName, store: StoreTenant = Depends(current_store), db: Session = Depends(get_db)):
    if not tg.configured(bot):
        raise HTTPException(status_code=503, detail="Bu bot hali sozlanmagan (administrator tokenni kiritishi kerak)")
    username = tg.bot_username(bot)
    if not username:
        raise HTTPException(status_code=503, detail="Telegram bilan bog'lanib bo'lmadi, birozdan keyin urinib ko'ring")
    code = tg.new_link_code(db, store.id, bot)
    return {
        "code": code,
        "expires_in_min": tg.CODE_TTL_MIN,
        "username": username,
        "link": f"https://t.me/{username}?start={code}",
        "group_link": f"https://t.me/{username}?startgroup={code}",
    }


@app.delete("/api/store/bots/links/{link_id}")
def store_bot_unlink(link_id: int, store: StoreTenant = Depends(current_store), db: Session = Depends(get_db)):
    link = db.scalar(select(TelegramLink).where(TelegramLink.id == link_id, TelegramLink.store_id == store.id))
    if not link:
        raise HTTPException(status_code=404, detail="Ulanish topilmadi")
    db.delete(link)
    db.commit()
    return {"deleted": True}


@app.post("/api/store/bots/{bot}/test")
def store_bot_test(bot: BotName, store: StoreTenant = Depends(current_store), db: Session = Depends(get_db)):
    links = tg.chats_for(db, store.id, bot)
    if not links:
        raise HTTPException(status_code=400, detail="Avval botni ulang")
    if bot == "sales":
        text = tg.sale_message(store.name, {
            "receipt_code": "CHK-TEST", "time": datetime.now(tg.TZ).strftime("%H:%M"), "customer": "Sinov",
            "payment_method": "Naqd", "total": 0, "lines": [{"name": "Sinov xabari", "qty": 1, "stock_left": 99}],
        })
    else:
        text = tg.build_daily_report(db, store, tg.today_local())
    sent = sum(1 for l in links if tg.send(bot, l.chat_id, text))
    if not sent:
        raise HTTPException(status_code=502, detail="Xabar yuborilmadi. Bot sozlamalari yoki chat ulanishini tekshiring")
    return {"sent": sent}
