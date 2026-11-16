import os
import re
import secrets
from contextlib import asynccontextmanager
from datetime import date, datetime, timedelta, timezone
from typing import Literal

import jwt
import pyotp
from fastapi import BackgroundTasks, Body, Depends, FastAPI, Header, HTTPException, status
from fastapi.middleware.cors import CORSMiddleware
from pwdlib import PasswordHash
from pydantic import BaseModel, Field
from sqlalchemy import func, select, text
from sqlalchemy.orm import Session

from db import engine, get_db
import telegram_bot as tg
from models import Base, Customer, Product, SaleItem, SaleReceipt, SecurityAuditLog, StoreTenant, TelegramLink

# ---------------------------------------------------------------------------
# Sozlamalar
# ---------------------------------------------------------------------------
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
CASHBACK_RATE_PCT = 3
PUBLIC_URL = os.getenv("PUBLIC_URL", "https://hisobgo-api.onrender.com")
CRON_KEY = os.getenv("CRON_KEY", "")

pwd_hasher = PasswordHash.recommended()  # Argon2id
_DUMMY_HASH = pwd_hasher.hash("dummy-password-for-timing")  # mavjud bo'lmagan login uchun vaqt tenglashtirish


@asynccontextmanager
async def lifespan(_: FastAPI):
    Base.metadata.create_all(bind=engine)
    if engine.dialect.name == "postgresql":  # mavjud jadvalga yangi ustun (create_all buni qilmaydi)
        with engine.begin() as conn:
            conn.execute(text("ALTER TABLE sale_receipts ADD COLUMN IF NOT EXISTS customer_id INTEGER"))
            conn.execute(text("ALTER TABLE sale_receipts ADD COLUMN IF NOT EXISTS refunded_at TIMESTAMPTZ"))
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
    allow_headers=["Authorization", "Content-Type", "X-Superadmin-Key", "X-Superadmin-TOTP"],
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
    now = utcnow()
    token = jwt.encode(
        {"sub": store.login, "sid": store.id, "iat": now, "exp": now + timedelta(hours=JWT_TTL_HOURS)},
        JWT_SECRET,
        algorithm="HS256",
    )
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
    store.must_change_password = False
    audit(db, store.login, "OTP_PASSWORD_CHANGED", f"'{store.name}' egasi parolni almashtirdi")
    db.commit()
    return {"status": "PASSWORD_UPDATED", "must_change_password": False}


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
        "total_spent_uzs": c.total_spent_uzs, "cashback_uzs": c.cashback_uzs, "debt_uzs": c.debt_uzs,
    }


def receipt_out(r: SaleReceipt) -> dict:
    return {
        "receipt_code": r.receipt_code, "customer_id": r.customer_id, "customer_name": r.customer_name, "items": r.items_summary,
        "payment_method": r.payment_method, "total_uzs": r.total_uzs, "profit_uzs": r.profit_uzs,
        "created_at": r.created_at, "refunded": r.refunded_at is not None, "refunded_at": r.refunded_at,
    }


@app.get("/api/store/me")
def store_me(store: StoreTenant = Depends(current_store)):
    return store_public(store)


@app.get("/api/store/products")
def list_products(store: StoreTenant = Depends(current_store), db: Session = Depends(get_db)):
    rows = db.scalars(select(Product).where(Product.store_id == store.id).order_by(Product.name)).all()
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
def list_customers(store: StoreTenant = Depends(current_store), db: Session = Depends(get_db)):
    rows = db.scalars(select(Customer).where(Customer.store_id == store.id).order_by(Customer.full_name)).all()
    return [customer_out(c) for c in rows]


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
    db.commit()
    return customer_out(c)


# ---------------------------------------------------------------------------
# Savdo (POS): narx va qoldiq serverda hisoblanadi, bitta tranzaksiyada
# ---------------------------------------------------------------------------
@app.post("/api/store/sales", status_code=201)
def create_sale(
    payload: SaleRequest,
    background: BackgroundTasks,
    store: StoreTenant = Depends(current_store),
    db: Session = Depends(get_db),
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
        else:
            customer.cashback_uzs += total * CASHBACK_RATE_PCT // 100

    receipt = SaleReceipt(
        store_id=store.id,
        receipt_code="CHK-" + secrets.token_hex(3).upper(),
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
    db.commit()

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
def list_sales(limit: int = 100, store: StoreTenant = Depends(current_store), db: Session = Depends(get_db)):
    limit = max(1, min(limit, 500))
    rows = db.scalars(
        select(SaleReceipt).where(SaleReceipt.store_id == store.id).order_by(SaleReceipt.id.desc()).limit(limit)
    ).all()
    return [receipt_out(r) for r in rows]


@app.post("/api/store/sales/{receipt_code}/refund")
def refund_sale(receipt_code: str, store: StoreTenant = Depends(current_store), db: Session = Depends(get_db)):
    """Chekni to'liq qaytarish: ombor, mijoz hisobi (xarid, nasiya yoki keshbek) tiklanadi."""
    r = db.scalar(
        select(SaleReceipt)
        .where(SaleReceipt.store_id == store.id, SaleReceipt.receipt_code == receipt_code)
        .with_for_update()
    )
    if not r:
        raise HTTPException(status_code=404, detail="Chek topilmadi")
    if r.refunded_at is not None:
        raise HTTPException(status_code=409, detail="Bu chek allaqachon qaytarilgan")

    items = db.scalars(select(SaleItem).where(SaleItem.receipt_id == r.id)).all()
    restored = 0
    for it in sorted(items, key=lambda i: i.sku):
        p = db.scalar(select(Product).where(Product.store_id == store.id, Product.sku == it.sku).with_for_update())
        if p:  # tovar o'chirilgan bo'lsa, qoldiq tiklanmaydi
            p.stock_qty += it.qty
            restored += 1

    if r.customer_id is not None:
        c = db.scalar(select(Customer).where(Customer.id == r.customer_id, Customer.store_id == store.id).with_for_update())
        if c:
            c.total_spent_uzs = max(0, c.total_spent_uzs - r.total_uzs)
            if r.payment_method == "Nasiya":
                c.debt_uzs = max(0, c.debt_uzs - r.total_uzs)
            else:
                c.cashback_uzs = max(0, c.cashback_uzs - r.total_uzs * CASHBACK_RATE_PCT // 100)

    r.refunded_at = utcnow()
    audit(db, store.login, "REFUND_SALE", f"{r.receipt_code}: {r.total_uzs} so'm, {r.payment_method}")
    db.commit()
    return {**receipt_out(r), "stock_restored": bool(items) and restored == len(items), "had_items": bool(items)}


@app.get("/api/store/dashboard")
def dashboard(store: StoreTenant = Depends(current_store), db: Session = Depends(get_db)):
    products = db.scalars(select(Product).where(Product.store_id == store.id)).all()
    customers = db.scalars(select(Customer).where(Customer.store_id == store.id)).all()

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
        "inventory_value_uzs": sum(p.price_uzs * p.stock_qty for p in products),
        "sku_count": len(products),
        "total_debt_uzs": sum(c.debt_uzs for c in customers),
        "debtor_count": sum(1 for c in customers if c.debt_uzs > 0),
        "customer_count": len(customers),
        "low_stock": [product_out(p) for p in products if p.stock_qty <= 10],
    }


class BonusRequest(BaseModel):
    amount_uzs: int = Field(gt=0, le=10**9)


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


@app.post("/api/store/customers/{customer_id}/bonus")
def give_customer_bonus(
    customer_id: int, payload: BonusRequest, store: StoreTenant = Depends(current_store), db: Session = Depends(get_db)
):
    c = db.scalar(select(Customer).where(Customer.id == customer_id, Customer.store_id == store.id).with_for_update())
    if not c:
        raise HTTPException(status_code=404, detail="Mijoz topilmadi")
    c.cashback_uzs += payload.amount_uzs
    audit(db, store.login, "GIVE_BONUS", f"{c.full_name}: +{payload.amount_uzs} so'm keshbek")
    db.commit()
    return customer_out(c)


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
