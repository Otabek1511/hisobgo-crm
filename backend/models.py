import uuid
from datetime import date, datetime
from sqlalchemy import Boolean, Date, DateTime, ForeignKey, Integer, Numeric, String, Text, func
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, relationship


class Base(DeclarativeBase):
    pass


class StoreTenant(Base):
    __tablename__ = "stores"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    slug: Mapped[str] = mapped_column(String(32), unique=True, index=True)
    name: Mapped[str] = mapped_column(String(120), nullable=False)
    tin: Mapped[str] = mapped_column(String(20), nullable=False)
    owner_name: Mapped[str] = mapped_column(String(120), nullable=False)
    phone: Mapped[str] = mapped_column(String(32), nullable=False)
    login: Mapped[str] = mapped_column(String(64), unique=True, index=True, nullable=False)
    password_hash: Mapped[str] = mapped_column(String(255), nullable=False)
    must_change_password: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)
    plan: Mapped[str] = mapped_column(String(32), default="Start", nullable=False)
    status: Mapped[str] = mapped_column(String(20), default="ACTIVE", nullable=False)  # ACTIVE | BLOCKED | EXPIRED
    subscription_expires_at: Mapped[date] = mapped_column(Date, nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())

    products: Mapped[list["Product"]] = relationship(back_populates="store", cascade="all, delete-orphan")
    customers: Mapped[list["Customer"]] = relationship(back_populates="store", cascade="all, delete-orphan")
    receipts: Mapped[list["SaleReceipt"]] = relationship(back_populates="store", cascade="all, delete-orphan")


class Product(Base):
    __tablename__ = "products"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    store_id: Mapped[str] = mapped_column(ForeignKey("stores.id", ondelete="CASCADE"), index=True, nullable=False)
    sku: Mapped[str] = mapped_column(String(64), index=True, nullable=False)
    name: Mapped[str] = mapped_column(String(160), nullable=False)
    category: Mapped[str] = mapped_column(String(80), nullable=False)
    cost_uzs: Mapped[int] = mapped_column(Numeric(14, 0), nullable=False)
    price_uzs: Mapped[int] = mapped_column(Numeric(14, 0), nullable=False)
    stock_qty: Mapped[int] = mapped_column(Integer, default=0, nullable=False)

    store: Mapped["StoreTenant"] = relationship(back_populates="products")


class Customer(Base):
    __tablename__ = "customers"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    store_id: Mapped[str] = mapped_column(ForeignKey("stores.id", ondelete="CASCADE"), index=True, nullable=False)
    full_name: Mapped[str] = mapped_column(String(120), nullable=False)
    phone: Mapped[str] = mapped_column(String(32), nullable=False)
    total_spent_uzs: Mapped[int] = mapped_column(Numeric(14, 0), default=0, nullable=False)
    cashback_uzs: Mapped[int] = mapped_column(Numeric(14, 0), default=0, nullable=False)
    debt_uzs: Mapped[int] = mapped_column(Numeric(14, 0), default=0, nullable=False)

    store: Mapped["StoreTenant"] = relationship(back_populates="customers")


class SaleReceipt(Base):
    __tablename__ = "sale_receipts"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    store_id: Mapped[str] = mapped_column(ForeignKey("stores.id", ondelete="CASCADE"), index=True, nullable=False)
    receipt_code: Mapped[str] = mapped_column(String(32), index=True, nullable=False)
    customer_name: Mapped[str] = mapped_column(String(120), default="Umumiy xaridor")
    payment_method: Mapped[str] = mapped_column(String(32), nullable=False)  # Naqd | Uzcard/Humo | Click/Payme | Nasiya
    total_uzs: Mapped[int] = mapped_column(Numeric(14, 0), nullable=False)
    profit_uzs: Mapped[int] = mapped_column(Numeric(14, 0), nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())

    store: Mapped["StoreTenant"] = relationship(back_populates="receipts")


class SecurityAuditLog(Base):
    __tablename__ = "security_audit_logs"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    actor: Mapped[str] = mapped_column(String(64), nullable=False)
    action: Mapped[str] = mapped_column(String(64), nullable=False)
    detail: Mapped[str] = mapped_column(Text, nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())
