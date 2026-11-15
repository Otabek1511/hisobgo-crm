import os
import sys
from datetime import date, timedelta

os.environ["ENV"] = "test"
os.environ["DATABASE_URL"] = "sqlite:///./test_hisobgo.db"
os.environ["SALES_BOT_TOKEN"] = "111:test-sales"
os.environ["REPORT_BOT_TOKEN"] = "222:test-report"
os.environ["TELEGRAM_WEBHOOK_SECRET"] = "whsecret"
os.environ["CRON_KEY"] = "cronkey"
sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))

from fastapi.testclient import TestClient  # noqa: E402

from main import SUPERADMIN_SECRET_KEY, app  # noqa: E402

SA = {"X-Superadmin-Key": SUPERADMIN_SECRET_KEY}
STRONG = "Yangi#Parol2026"


def _store_payload(login="shop1"):
    return {
        "name": "Test Do'kon", "tin": "123456789", "owner_name": "Ega Egaev", "phone": "+998901234567",
        "login": login, "plan": "Start", "subscription_expires_at": str(date.today() + timedelta(days=30)),
    }


def test_full_flow():
    with TestClient(app) as c:
        assert c.post("/api/superadmin/stores", json=_store_payload()).status_code == 422  # sarlavha yo'q
        assert c.post("/api/superadmin/stores", json=_store_payload(), headers={"X-Superadmin-Key": "x"}).status_code == 403
        r = c.post("/api/superadmin/stores", json=_store_payload(), headers=SA)
        assert r.status_code == 201, r.text
        otp = r.json()["one_time_password"]

        r = c.post("/api/auth/login", json={"login": "shop1", "password": otp})
        assert r.json()["status"] == "FORCE_PASSWORD_CHANGE_REQUIRED"
        assert c.post("/api/auth/change-initial-password",
                      json={"login": "shop1", "one_time_password": otp, "new_strong_password": "weak"}).status_code == 400
        assert c.post("/api/auth/change-initial-password",
                      json={"login": "shop1", "one_time_password": otp, "new_strong_password": STRONG}).status_code == 200

        token = c.post("/api/auth/login", json={"login": "shop1", "password": STRONG}).json()["access_token"]
        H = {"Authorization": f"Bearer {token}"}
        assert c.post("/api/store/products", headers=H, json={
            "sku": "A1", "name": "Sut", "category": "Sut", "cost_uzs": 1000, "price_uzs": 1500, "stock_qty": 5}).status_code == 201
        cust = c.post("/api/store/customers", headers=H, json={"full_name": "Ali Vali", "phone": "+998931112233"}).json()

        sale = c.post("/api/store/sales", headers=H, json={
            "items": [{"sku": "A1", "qty": 2}], "payment_method": "Nasiya", "customer_id": cust["id"]})
        assert sale.status_code == 201 and sale.json()["total_uzs"] == 3000 and sale.json()["profit_uzs"] == 1000
        assert c.post("/api/store/sales", headers=H, json={
            "items": [{"sku": "A1", "qty": 99}], "payment_method": "Naqd"}).status_code == 400
        assert c.get("/api/store/customers", headers=H).json()[0]["debt_uzs"] == 3000

        c.patch("/api/superadmin/stores/shop1/block", headers=SA)
        assert c.get("/api/store/products", headers=H).status_code == 403
        c.delete("/api/superadmin/stores/shop1", headers=SA)


def test_telegram_flow(monkeypatch):
    import telegram_bot as tg

    sent = []
    monkeypatch.setattr(tg, "send", lambda bot, chat_id, text: sent.append((bot, chat_id, text)) or True)
    monkeypatch.setattr(tg, "bot_username", lambda bot: f"test_{bot}_bot")

    with TestClient(app) as c:
        otp = c.post("/api/superadmin/stores", json=_store_payload("shop2"), headers=SA).json()["one_time_password"]
        c.post("/api/auth/change-initial-password", json={"login": "shop2", "one_time_password": otp, "new_strong_password": STRONG})
        token = c.post("/api/auth/login", json={"login": "shop2", "password": STRONG}).json()["access_token"]
        H = {"Authorization": f"Bearer {token}"}

        # webhook sirsiz rad etiladi
        assert c.post("/api/telegram/sales", json={}).status_code == 403

        # ulash kodi -> /start KOD
        code = c.post("/api/store/bots/sales/link-code", headers=H).json()["code"]
        upd = {"message": {"text": f"/start {code}", "chat": {"id": 555, "first_name": "Omborchi"}}}
        assert c.post("/api/telegram/sales", json=upd, headers={"X-Telegram-Bot-Api-Secret-Token": "whsecret"}).status_code == 200
        assert len(c.get("/api/store/bots", headers=H).json()["sales"]["links"]) == 1

        # sotuv -> ombor xabari
        c.post("/api/store/products", headers=H, json={"name": "Non", "cost_uzs": 1000, "price_uzs": 2000, "stock_qty": 3})
        sku = c.get("/api/store/products", headers=H).json()[0]["sku"]
        assert c.post("/api/store/sales", headers=H, json={"items": [{"sku": sku, "qty": 2}], "payment_method": "Naqd"}).status_code == 201
        assert any(b == "sales" and chat == 555 and "Non" in t for b, chat, t in sent)

        # cron kalitsiz rad etiladi
        assert c.post("/api/internal/daily-report").status_code == 403
        c.delete("/api/superadmin/stores/shop2", headers=SA)
