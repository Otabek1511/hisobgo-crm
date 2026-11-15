import os
import re
import secrets
from contextlib import asynccontextmanager
from datetime import date, datetime, timedelta, timezone
from typing import Literal

import jwt
import pyotp
from fastapi import Depends, FastAPI, Header, HTTPException, status
from fastapi.middleware.cors import CORSMiddleware
from pwdlib import PasswordHash
from pydantic import BaseModel, Field
from sqlalchemy import select
from sqlalchemy.orm import Session

from db import engine, get_db
from models import Base, Customer, Product, SaleReceipt, SecurityAuditLog, StoreTenant

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

pwd_hasher = PasswordHash.recommended()  # Argon2id
_DUMMY_HASH = pwd_hasher.hash("dummy-password-for-timing")  # mavjud bo'lmagan login uchun vaqt tenglashtirish


@asynccontextmanager
async def lifespan(_: FastAPI):
    Base.metadata.create_all(bind=engine)
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
    sku: str = Field(min_length=1, max_length=64)
    name: str = Field(min_length=1, max_length=160)
    category: str = Field(min_length=1, max_length=80)
    cost_uzs: int = Field(ge=0, le=10**12)
    price_uzs: int = Field(ge=0, le=10**12)
    stock_qty: int = Field(default=0, ge=0, le=10**7)


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
        "receipt_code": r.receipt_code, "customer_name": r.customer_name, "items": r.items_summary,
        "payment_method": r.payment_method, "total_uzs": r.total_uzs, "profit_uzs": r.profit_uzs,
        "created_at": r.created_at,
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
    exists = db.scalar(select(Product).where(Product.store_id == store.id, Product.sku == payload.sku))
    if exists:
        raise HTTPException(status_code=400, detail="Bu SKU/shtrixkod allaqachon mavjud")
    p = Product(store_id=store.id, **payload.model_dump())
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
def create_sale(payload: SaleRequest, store: StoreTenant = Depends(current_store), db: Session = Depends(get_db)):
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
    for sku, qty in qty_by_sku.items():
        p = by_sku[sku]
        if p.stock_qty < qty:
            raise HTTPException(status_code=400, detail=f"'{p.name}' omborda yetarli emas (qoldiq: {p.stock_qty})")
        subtotal += p.price_uzs * qty
        cost_total += p.cost_uzs * qty
        parts.append(f"{p.name} x{qty}")
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
        items_summary=", ".join(parts)[:2000],
        payment_method=payload.payment_method,
        total_uzs=total,
        profit_uzs=profit,
    )
    db.add(receipt)
    db.commit()
    return receipt_out(receipt)


@app.get("/api/store/sales")
def list_sales(limit: int = 100, store: StoreTenant = Depends(current_store), db: Session = Depends(get_db)):
    limit = max(1, min(limit, 500))
    rows = db.scalars(
        select(SaleReceipt).where(SaleReceipt.store_id == store.id).order_by(SaleReceipt.id.desc()).limit(limit)
    ).all()
    return [receipt_out(r) for r in rows]


@app.get("/api/store/dashboard")
def dashboard(store: StoreTenant = Depends(current_store), db: Session = Depends(get_db)):
    products = db.scalars(select(Product).where(Product.store_id == store.id)).all()
    customers = db.scalars(select(Customer).where(Customer.store_id == store.id)).all()
    receipts = db.scalars(select(SaleReceipt).where(SaleReceipt.store_id == store.id)).all()
    revenue = sum(r.total_uzs for r in receipts)
    profit = sum(r.profit_uzs for r in receipts)
    return {
        "revenue_uzs": revenue,
        "profit_uzs": profit,
        "margin_pct": round(profit * 100 / revenue, 1) if revenue else 0,
        "inventory_value_uzs": sum(p.price_uzs * p.stock_qty for p in products),
        "sku_count": len(products),
        "total_debt_uzs": sum(c.debt_uzs for c in customers),
        "customer_count": len(customers),
        "low_stock": [product_out(p) for p in products if p.stock_qty <= 10],
    }
