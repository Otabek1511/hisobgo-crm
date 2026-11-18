"""Telegram botlar: sotuv -> ombor xabari va kunlik hisobot.

Ikki bot (har biri alohida token):
  sales  — har bir sotuvda ulangan omborchilarga xabar yuboradi
  report — har kuni 20:00 (Toshkent) da do'kon egasiga kunlik hisobot yuboradi

Chatni ulash: do'kon egasi CRM'dan bir martalik kod oladi, Telegram'da botga
`/start KOD` yuboradi.
"""
import html
import logging
import os
import re
import secrets
import time as _time
from datetime import date, datetime, time, timedelta, timezone

import httpx
from sqlalchemy import delete, func, select
from sqlalchemy.orm import Session

from db import SessionLocal
from models import Customer, LinkCode, Product, SaleItem, SaleReceipt, StoreTenant, TelegramLink

log = logging.getLogger("hisobgo.telegram")

TZ = timezone(timedelta(hours=5))  # O'zbekiston (yozgi/qishki vaqt yo'q)
BOTS = ("sales", "report")
TOKENS = {"sales": os.getenv("SALES_BOT_TOKEN", "").strip(), "report": os.getenv("REPORT_BOT_TOKEN", "").strip()}
_TOKEN_RE = re.compile(r"^\d{6,}:[A-Za-z0-9_-]{30,}$")
_last_error: dict[str, str] = {}
WEBHOOK_SECRET = os.getenv("TELEGRAM_WEBHOOK_SECRET", "")
CODE_TTL_MIN = 15
LOW_STOCK = 10
_username_cache: dict[str, str] = {}


# ---------------------------------------------------------------------------
# Telegram API
# ---------------------------------------------------------------------------
def configured(bot: str) -> bool:
    return bool(TOKENS.get(bot))


def token_format_ok(bot: str) -> bool:
    return bool(_TOKEN_RE.match(TOKENS.get(bot, "")))


def api_call(bot: str, method: str, payload: dict | None = None) -> dict | None:
    token = TOKENS.get(bot)
    if not token:
        return None
    url = f"https://api.telegram.org/bot{token}/{method}"
    timeout = httpx.Timeout(20.0, connect=10.0)
    data = None
    for attempt in (1, 2):
        try:
            r = httpx.post(url, json=payload or {}, timeout=timeout)
            data = r.json()
        except Exception as exc:  # token URL da bo'lgani uchun xabar matnini loglamaymiz
            _last_error[bot] = type(exc).__name__
            log.warning("telegram %s/%s xato: %s (urinish %d)", bot, method, type(exc).__name__, attempt)
            if attempt == 1:
                _time.sleep(1)
                continue
            return None
        retry_after = (data.get("parameters") or {}).get("retry_after") if isinstance(data, dict) else None
        if not data.get("ok") and retry_after and attempt == 1 and retry_after <= 5:
            _time.sleep(retry_after + 0.5)
            continue
        break
    _last_error.pop(bot, None)
    if not data.get("ok"):
        log.warning("telegram %s/%s rad etdi: %s", bot, method, data.get("description"))
    return data


def send(bot: str, chat_id: int, text: str) -> bool:
    data = api_call(bot, "sendMessage", {
        "chat_id": chat_id, "text": text, "parse_mode": "HTML", "disable_web_page_preview": True,
    })
    return bool(data and data.get("ok"))


def bot_username(bot: str) -> str | None:
    if bot in _username_cache:
        return _username_cache[bot]
    data = api_call(bot, "getMe")
    name = (data or {}).get("result", {}).get("username") if data and data.get("ok") else None
    if name:
        _username_cache[bot] = name
    return name


def setup_webhooks(public_url: str) -> dict:
    result: dict = {}
    for bot in BOTS:
        if not configured(bot):
            result[bot] = {"ok": False, "error": "Token o'rnatilmagan"}
            continue
        if not token_format_ok(bot):
            result[bot] = {"ok": False, "error": "Token formati noto'g'ri. BotFather'dagi tokenni to'liq nusxalang (1234567:AA... ko'rinishida, probelsiz)"}
            continue
        if not WEBHOOK_SECRET:
            result[bot] = {"ok": False, "error": "TELEGRAM_WEBHOOK_SECRET o'rnatilmagan"}
            continue
        target = f"{public_url.rstrip('/')}/api/telegram/{bot}"
        info = api_call(bot, "getWebhookInfo")
        if info is None:
            result[bot] = {"ok": False, "error": f"Telegram javob bermadi ({_last_error.get(bot, 'tarmoq xatosi')}). Birozdan keyin qayta urinib ko'ring"}
            continue
        if info.get("ok") and (info.get("result") or {}).get("url") == target:
            hook = info  # allaqachon o'rnatilgan: qayta o'rnatmaymiz (Telegram tez-tez so'rovni cheklaydi)
        else:
            hook = api_call(bot, "setWebhook", {
                "url": target,
                "secret_token": WEBHOOK_SECRET,
                "allowed_updates": ["message"],
                "drop_pending_updates": True,
            })
        ok = bool(hook and hook.get("ok"))
        if ok:
            commands = [{"command": "start", "description": "Do'konga ulanish"}, {"command": "stop", "description": "Ulanishni o'chirish"}]
            if bot == "report":
                commands.append({"command": "hisobot", "description": "Bugungi hisobot"})
            api_call(bot, "setMyCommands", {"commands": commands})
        err = None
        if not ok:
            err = (hook or {}).get("description") or f"Telegram javob bermadi ({_last_error.get(bot, 'tarmoq xatosi')})"
        result[bot] = {"ok": ok, "error": err, "username": bot_username(bot) if ok else None}
    return result


# ---------------------------------------------------------------------------
# Yordamchilar
# ---------------------------------------------------------------------------
def _e(v) -> str:
    return html.escape(str(v), quote=False)


def uzs(n) -> str:
    return f"{int(n):,}".replace(",", " ") + " so'm"


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _aware(dt: datetime) -> datetime:
    return dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)


def _is_active(store: StoreTenant) -> bool:
    return store.status != "BLOCKED" and store.subscription_expires_at >= date.today()


def chats_for(db: Session, store_id: str, bot: str) -> list[TelegramLink]:
    return list(db.scalars(select(TelegramLink).where(TelegramLink.store_id == store_id, TelegramLink.bot == bot)).all())


def new_link_code(db: Session, store_id: str, bot: str) -> str:
    alphabet = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789"
    code = "".join(secrets.choice(alphabet) for _ in range(10))
    db.execute(delete(LinkCode).where(LinkCode.store_id == store_id, LinkCode.bot == bot))
    db.add(LinkCode(code=code, store_id=store_id, bot=bot, expires_at=_now() + timedelta(minutes=CODE_TTL_MIN)))
    db.commit()
    return code


# ---------------------------------------------------------------------------
# Sotuv -> ombor xabari
# ---------------------------------------------------------------------------
def sale_message(store_name: str, data: dict) -> str:
    lines = []
    for it in data["lines"]:
        left = it["stock_left"]
        flag = "  ❗ <b>tugadi</b>" if left <= 0 else (f"  ⚠️ kam qoldi" if left <= LOW_STOCK else "")
        lines.append(f"• {_e(it['name'])} × <b>{it['qty']}</b>  (qoldiq: {left}){flag}")
    return (
        f"🛒 <b>Yangi sotuv</b> — {_e(store_name)}\n"
        f"Chek: <code>{_e(data['receipt_code'])}</code> • {_e(data['time'])}\n"
        f"Mijoz: {_e(data['customer'])}\n"
        + (f"Sotuvchi: {_e(data['seller'])}\n" if data.get("seller") else "")
        + "\n"
        + "\n".join(lines)
        + f"\n\nJami: <b>{uzs(data['total'])}</b> • To'lov: {_e(data['payment_method'])}"
    )


def notify_sale(store_id: str, data: dict) -> None:
    """BackgroundTasks orqali chaqiriladi: sotuv javobini kechiktirmaydi, xatolar yutiladi."""
    if not configured("sales"):
        return
    try:
        with SessionLocal() as db:
            store = db.get(StoreTenant, store_id)
            if not store:
                return
            text = sale_message(store.name, data)
            for link in chats_for(db, store_id, "sales"):
                send("sales", link.chat_id, text)
    except Exception as exc:
        log.warning("sotuv xabarini yuborishda xato: %s", type(exc).__name__)


# ---------------------------------------------------------------------------
# Kunlik hisobot
# ---------------------------------------------------------------------------
def today_local() -> date:
    return datetime.now(TZ).date()


def build_daily_report(db: Session, store: StoreTenant, day: date) -> str:
    start = datetime.combine(day, time.min, tzinfo=TZ).astimezone(timezone.utc)
    end = start + timedelta(days=1)
    in_day = (SaleReceipt.store_id == store.id, SaleReceipt.created_at >= start, SaleReceipt.created_at < end, SaleReceipt.refunded_at.is_(None))

    receipts = db.scalars(select(SaleReceipt).where(*in_day)).all()
    head = f"📊 <b>Kunlik hisobot</b> — {_e(store.name)}\n📅 {day.strftime('%d.%m.%Y')}\n\n"

    debt_total = db.scalar(select(func.coalesce(func.sum(Customer.debt_uzs), 0)).where(Customer.store_id == store.id)) or 0
    low = db.scalars(
        select(Product).where(Product.store_id == store.id, Product.stock_qty <= LOW_STOCK).order_by(Product.stock_qty).limit(8)
    ).all()
    tail = ""
    if low:
        tail += "\n⚠️ <b>Kam qolgan tovarlar:</b>\n" + "\n".join(f"• {_e(p.name)} — {p.stock_qty} dona" for p in low) + "\n"
    tail += f"\n📒 Jami nasiya qarzi: <b>{uzs(debt_total)}</b>"

    if not receipts:
        return head + "Bugun savdo bo'lmadi." + "\n" + tail

    total = sum(r.total_uzs for r in receipts)
    profit = sum(r.profit_uzs for r in receipts)
    by_method: dict[str, int] = {}
    for r in receipts:
        by_method[r.payment_method] = by_method.get(r.payment_method, 0) + r.total_uzs

    top = db.execute(
        select(
            SaleItem.name,
            func.sum(SaleItem.qty - SaleItem.refunded_qty),
            func.sum(SaleItem.line_total_uzs * (SaleItem.qty - SaleItem.refunded_qty) / SaleItem.qty),
        )
        .join(SaleReceipt, SaleReceipt.id == SaleItem.receipt_id)
        .where(*in_day)
        .group_by(SaleItem.name)
        .having(func.sum(SaleItem.qty - SaleItem.refunded_qty) > 0)
        .order_by(func.sum(SaleItem.qty - SaleItem.refunded_qty).desc())
        .limit(5)
    ).all()

    body = (
        f"🧾 Cheklar soni: <b>{len(receipts)}</b>\n"
        f"💰 Tushum: <b>{uzs(total)}</b>\n"
        f"📈 Sof foyda: <b>{uzs(profit)}</b>\n\n"
        "<b>To'lov turlari:</b>\n"
        + "\n".join(f"• {_e(m)}: {uzs(v)}" for m, v in sorted(by_method.items(), key=lambda x: -x[1]))
        + "\n"
    )
    if by_method.get("Nasiya"):
        body += f"\n📒 Bugun nasiyaga berildi: <b>{uzs(by_method['Nasiya'])}</b>\n"
    if top:
        body += "\n🏆 <b>Eng ko'p sotilganlar:</b>\n" + "\n".join(
            f"{i}. {_e(n)} — {int(q)} dona ({uzs(s)})" for i, (n, q, s) in enumerate(top, 1)
        ) + "\n"
    return head + body + tail


def send_daily_reports(db: Session) -> dict:
    day = today_local()
    sent = failed = stores_count = 0
    for store in db.scalars(select(StoreTenant)).all():
        if not _is_active(store):
            continue
        links = chats_for(db, store.id, "report")
        if not links:
            continue
        stores_count += 1
        text = build_daily_report(db, store, day)
        for link in links:
            if send("report", link.chat_id, text):
                sent += 1
            else:
                failed += 1
    return {"day": day.isoformat(), "stores": stores_count, "sent": sent, "failed": failed}


# ---------------------------------------------------------------------------
# Botga kelgan xabarlar (webhook)
# ---------------------------------------------------------------------------
HELP = {
    "sales": "👋 Bu <b>Sotuv boti</b>: har bir sotuvda omborga xabar yuboradi.\n\nUlash uchun HisobGo CRM → «Botlar» bo'limidan kod oling va <code>/start KOD</code> yuboring.",
    "report": "👋 Bu <b>Hisobot boti</b>: har kuni 20:00 da kunlik savdo hisobotini yuboradi.\n\nUlash uchun HisobGo CRM → «Botlar» bo'limidan kod oling va <code>/start KOD</code> yuboring.",
}
ROLE_TEXT = {"sales": "sotuv xabarlari", "report": "kunlik hisobot (20:00)"}


def handle_update(db: Session, bot: str, update: dict) -> None:
    msg = update.get("message") or {}
    text = (msg.get("text") or "").strip()
    chat = msg.get("chat") or {}
    chat_id = chat.get("id")
    if chat_id is None or not text.startswith("/"):
        return
    cmd, _, arg = text.partition(" ")
    cmd = cmd.split("@")[0].lower()
    arg = arg.strip()
    title = (
        chat.get("title")
        or " ".join(filter(None, [chat.get("first_name"), chat.get("last_name")]))
        or chat.get("username")
        or str(chat_id)
    )[:160]

    if cmd == "/start":
        if not arg:
            send(bot, chat_id, HELP[bot])
            return
        lc = db.get(LinkCode, arg.upper())
        if not lc or lc.bot != bot or _aware(lc.expires_at) < _now():
            send(bot, chat_id, "❌ Kod yaroqsiz yoki muddati tugagan. CRM → «Botlar» bo'limidan yangi kod oling.")
            return
        store = db.get(StoreTenant, lc.store_id)
        db.delete(lc)
        if not store:
            db.commit()
            return
        exists = db.scalar(
            select(TelegramLink).where(TelegramLink.store_id == store.id, TelegramLink.bot == bot, TelegramLink.chat_id == chat_id)
        )
        if not exists:
            db.add(TelegramLink(store_id=store.id, bot=bot, chat_id=chat_id, chat_title=title))
        db.commit()
        send(bot, chat_id, f"✅ Ulandi: <b>{_e(store.name)}</b>\nEndi bu chatga {ROLE_TEXT[bot]} yuboriladi.\nUzish: /stop")
    elif cmd == "/stop":
        db.execute(delete(TelegramLink).where(TelegramLink.bot == bot, TelegramLink.chat_id == chat_id))
        db.commit()
        send(bot, chat_id, "🔌 Ulanish o'chirildi.")
    elif cmd == "/hisobot" and bot == "report":
        links = db.scalars(select(TelegramLink).where(TelegramLink.bot == bot, TelegramLink.chat_id == chat_id)).all()
        if not links:
            send(bot, chat_id, "Avval do'konga ulaning: /start KOD")
            return
        for link in links:
            store = db.get(StoreTenant, link.store_id)
            if store:
                send(bot, chat_id, build_daily_report(db, store, today_local()))
