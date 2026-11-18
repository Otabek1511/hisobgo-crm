import uuid
from datetime import date, datetime

from sqlalchemy import (
    BigInteger,
    Boolean,
    Date,
    DateTime,
    ForeignKey,
    Index,
    Integer,
    String,
    Text,
    UniqueConstraint,
    func,
)
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
    token_version: Mapped[int] = mapped_column(Integer, default=0, server_default="0", nullable=False)
    failed_logins: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    locked_until: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    plan: Mapped[str] = mapped_column(String(32), default="Start", nullable=False)
    status: Mapped[str] = mapped_column(String(20), default="ACTIVE", nullable=False)  # ACTIVE | BLOCKED | EXPIRED
    subscription_expires_at: Mapped[date] = mapped_column(Date, nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())

    products: Mapped[list["Product"]] = relationship(back_populates="store", cascade="all, delete-orphan")
    customers: Mapped[list["Customer"]] = relationship(back_populates="store", cascade="all, delete-orphan")
    employees: Mapped[list["Employee"]] = relationship(back_populates="store", cascade="all, delete-orphan")
    receipts: Mapped[list["SaleReceipt"]] = relationship(back_populates="store", cascade="all, delete-orphan")


class Product(Base):
    __tablename__ = "products"
    __table_args__ = (UniqueConstraint("store_id", "sku", name="uq_products_store_sku"),)

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    store_id: Mapped[str] = mapped_column(ForeignKey("stores.id", ondelete="CASCADE"), index=True, nullable=False)
    sku: Mapped[str] = mapped_column(String(64), index=True, nullable=False)
    name: Mapped[str] = mapped_column(String(160), nullable=False)
    category: Mapped[str] = mapped_column(String(80), nullable=False)
    cost_uzs: Mapped[int] = mapped_column(BigInteger, nullable=False)
    price_uzs: Mapped[int] = mapped_column(BigInteger, nullable=False)
    stock_qty: Mapped[int] = mapped_column(Integer, default=0, nullable=False)

    store: Mapped["StoreTenant"] = relationship(back_populates="products")
    entries: Mapped[list["StockEntry"]] = relationship(back_populates="product", cascade="all, delete-orphan")


class StockEntry(Base):
    """Omborga kirim: qancha dona va qachon."""

    __tablename__ = "stock_entries"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    store_id: Mapped[str] = mapped_column(ForeignKey("stores.id", ondelete="CASCADE"), index=True, nullable=False)
    product_id: Mapped[int] = mapped_column(ForeignKey("products.id", ondelete="CASCADE"), index=True, nullable=False)
    qty: Mapped[int] = mapped_column(Integer, nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)

    product: Mapped["Product"] = relationship(back_populates="entries")


class Customer(Base):
    __tablename__ = "customers"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    store_id: Mapped[str] = mapped_column(ForeignKey("stores.id", ondelete="CASCADE"), index=True, nullable=False)
    full_name: Mapped[str] = mapped_column(String(120), nullable=False)
    phone: Mapped[str] = mapped_column(String(32), nullable=False)
    total_spent_uzs: Mapped[int] = mapped_column(BigInteger, default=0, nullable=False)
    debt_uzs: Mapped[int] = mapped_column(BigInteger, default=0, nullable=False)

    store: Mapped["StoreTenant"] = relationship(back_populates="customers")


class Employee(Base):
    """Do'kon xodimi: ism, telefon, oylik va olingan avans."""

    __tablename__ = "employees"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    store_id: Mapped[str] = mapped_column(ForeignKey("stores.id", ondelete="CASCADE"), index=True, nullable=False)
    first_name: Mapped[str] = mapped_column(String(80), nullable=False)
    last_name: Mapped[str] = mapped_column(String(80), nullable=False)
    phone: Mapped[str] = mapped_column(String(32), nullable=False)
    salary_uzs: Mapped[int] = mapped_column(BigInteger, default=0, nullable=False)
    advance_uzs: Mapped[int] = mapped_column(BigInteger, default=0, nullable=False)

    store: Mapped["StoreTenant"] = relationship(back_populates="employees")


class StaffUser(Base):
    """Do'kon sotuvchisi (kassir): faqat sotuv paneliga kira oladi, foyda/mijoz/xodim ma'lumotini ko'rmaydi."""

    __tablename__ = "staff_users"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    store_id: Mapped[str] = mapped_column(ForeignKey("stores.id", ondelete="CASCADE"), index=True, nullable=False)
    login: Mapped[str] = mapped_column(String(64), unique=True, index=True, nullable=False)  # do'kon loginlari bilan ham takrorlanmaydi
    full_name: Mapped[str] = mapped_column(String(120), nullable=False)
    password_hash: Mapped[str] = mapped_column(String(255), nullable=False)
    role: Mapped[str] = mapped_column(String(16), default="seller", nullable=False)
    active: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)
    must_change_password: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)
    failed_logins: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    locked_until: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    token_version: Mapped[int] = mapped_column(Integer, default=0, server_default="0", nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())
    last_login_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)


class EmployeeAdvance(Base):
    """Xodimga berilgan avans yozuvi (kimga, qancha, qachon). Manfiy summa: tuzatish."""

    __tablename__ = "employee_advances"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    store_id: Mapped[str] = mapped_column(ForeignKey("stores.id", ondelete="CASCADE"), index=True, nullable=False)
    employee_id: Mapped[int] = mapped_column(ForeignKey("employees.id", ondelete="CASCADE"), index=True, nullable=False)
    amount_uzs: Mapped[int] = mapped_column(BigInteger, nullable=False)
    note: Mapped[str] = mapped_column(String(200), default="", nullable=False)
    kind: Mapped[str] = mapped_column(String(12), default="advance", nullable=False)  # advance | initial | adjust
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())


class SaleReceipt(Base):
    __tablename__ = "sale_receipts"
    __table_args__ = (
        Index("uq_receipt_code", "store_id", "receipt_code", unique=True),
        Index("uq_receipt_idem", "store_id", "idem_key", unique=True),
    )

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    store_id: Mapped[str] = mapped_column(ForeignKey("stores.id", ondelete="CASCADE"), index=True, nullable=False)
    receipt_code: Mapped[str] = mapped_column(String(32), index=True, nullable=False)
    customer_name: Mapped[str] = mapped_column(String(120), default="Umumiy xaridor")
    customer_id: Mapped[int | None] = mapped_column(Integer, nullable=True, index=True)
    items_summary: Mapped[str] = mapped_column(Text, default="", nullable=False)
    payment_method: Mapped[str] = mapped_column(String(32), nullable=False)  # Naqd | Uzcard/Humo | Click/Payme | Nasiya
    total_uzs: Mapped[int] = mapped_column(BigInteger, nullable=False)
    profit_uzs: Mapped[int] = mapped_column(BigInteger, nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())
    refunded_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)  # to'liq qaytarilgan chek
    refunded_uzs: Mapped[int] = mapped_column(BigInteger, default=0, server_default="0", nullable=False)  # jami qaytarilgan summa
    idem_key: Mapped[str | None] = mapped_column(String(64), nullable=True)  # takroriy yuborishdan himoya
    staff_id: Mapped[int | None] = mapped_column(Integer, nullable=True, index=True)  # sotuvchi (None: do'kon egasi)
    seller_name: Mapped[str] = mapped_column(String(120), default="", server_default="", nullable=False)

    store: Mapped["StoreTenant"] = relationship(back_populates="receipts")


class SecurityAuditLog(Base):
    __tablename__ = "security_audit_logs"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    actor: Mapped[str] = mapped_column(String(64), nullable=False)
    action: Mapped[str] = mapped_column(String(64), nullable=False)
    detail: Mapped[str] = mapped_column(Text, nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())


class SaleItem(Base):
    """Chekdagi har bir tovar qatori (hisobotlarda 'eng ko'p sotilgan' uchun)."""

    __tablename__ = "sale_items"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    receipt_id: Mapped[int] = mapped_column(ForeignKey("sale_receipts.id", ondelete="CASCADE"), index=True, nullable=False)
    store_id: Mapped[str] = mapped_column(ForeignKey("stores.id", ondelete="CASCADE"), index=True, nullable=False)
    sku: Mapped[str] = mapped_column(String(64), nullable=False)
    name: Mapped[str] = mapped_column(String(160), nullable=False)
    qty: Mapped[int] = mapped_column(Integer, nullable=False)
    line_total_uzs: Mapped[int] = mapped_column(BigInteger, nullable=False)
    refunded_qty: Mapped[int] = mapped_column(Integer, default=0, server_default="0", nullable=False)


class TelegramLink(Base):
    """Telegram chat (shaxsiy yoki guruh) ning do'kon va bot turiga ulanishi."""

    __tablename__ = "telegram_links"
    __table_args__ = (UniqueConstraint("store_id", "bot", "chat_id", name="uq_tg_store_bot_chat"),)

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    store_id: Mapped[str] = mapped_column(ForeignKey("stores.id", ondelete="CASCADE"), index=True, nullable=False)
    bot: Mapped[str] = mapped_column(String(10), nullable=False)  # sales | report
    chat_id: Mapped[int] = mapped_column(BigInteger, index=True, nullable=False)
    chat_title: Mapped[str] = mapped_column(String(160), default="", nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())


class LinkCode(Base):
    """Botni ulash uchun bir martalik, qisqa muddatli kod."""

    __tablename__ = "telegram_link_codes"

    code: Mapped[str] = mapped_column(String(16), primary_key=True)
    store_id: Mapped[str] = mapped_column(ForeignKey("stores.id", ondelete="CASCADE"), index=True, nullable=False)
    bot: Mapped[str] = mapped_column(String(10), nullable=False)
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
