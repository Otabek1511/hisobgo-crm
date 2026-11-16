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


def test_product_edit_delete_and_refund():
    with TestClient(app) as c:
        otp = c.post("/api/superadmin/stores", json=_store_payload("refund0"), headers=SA).json()["one_time_password"]
        c.post("/api/auth/change-initial-password", json={"login": "refund0", "one_time_password": otp, "new_strong_password": STRONG})
        H = {"Authorization": "Bearer " + c.post("/api/auth/login", json={"login": "refund0", "password": STRONG}).json()["access_token"]}
        for sku in ("A1", "B2"):
            assert c.post("/api/store/products", headers=H, json={
                "sku": sku, "name": "T" + sku, "cost_uzs": 1000, "price_uzs": 1500, "stock_qty": 10}).status_code == 201

        # tahrirlash
        r = c.patch("/api/store/products/A1", headers=H, json={"price_uzs": 2000, "name": "Yangi nom"})
        assert r.status_code == 200 and r.json()["price_uzs"] == 2000 and r.json()["name"] == "Yangi nom"
        assert c.patch("/api/store/products/A1", headers=H, json={"sku": "B2"}).status_code == 400  # band SKU
        assert c.patch("/api/store/products/NOPE", headers=H, json={"price_uzs": 1}).status_code == 404

        # sotuv va qaytarish
        cust = c.post("/api/store/customers", headers=H, json={"full_name": "Ali Vali", "phone": "+998931112233"}).json()
        sale = c.post("/api/store/sales", headers=H, json={
            "items": [{"sku": "A1", "qty": 3}], "payment_method": "Nasiya", "customer_id": cust["id"]}).json()
        code = sale["receipt_code"]
        assert sale["total_uzs"] == 6000
        r = c.post(f"/api/store/sales/{code}/refund", headers=H)
        assert r.status_code == 200 and r.json()["refunded"] and r.json()["stock_restored"]
        assert c.post(f"/api/store/sales/{code}/refund", headers=H).status_code == 409
        prod = {p["sku"]: p for p in c.get("/api/store/products", headers=H).json()}
        assert prod["A1"]["stock_qty"] == 10
        cu = c.get("/api/store/customers", headers=H).json()[0]
        assert cu["debt_uzs"] == 0 and cu["total_spent_uzs"] == 0
        assert c.get("/api/store/dashboard", headers=H).json()["week_revenue_uzs"] == 0

        # o'chirish
        assert c.delete("/api/store/products/B2", headers=H).status_code == 200
        assert c.delete("/api/store/products/B2", headers=H).status_code == 404
        c.delete("/api/superadmin/stores/refund0", headers=SA)


def _login_store(c, login):
    otp = c.post("/api/superadmin/stores", json=_store_payload(login), headers=SA).json()["one_time_password"]
    assert c.post("/api/auth/change-initial-password",
                  json={"login": login, "one_time_password": otp, "new_strong_password": STRONG}).status_code == 200
    token = c.post("/api/auth/login", json={"login": login, "password": STRONG}).json()["access_token"]
    return {"Authorization": f"Bearer {token}"}


def _product(c, H, sku="A1", price=1000, cost=400, stock=10):
    r = c.post("/api/store/products", headers=H, json={
        "sku": sku, "name": "T" + sku, "cost_uzs": cost, "price_uzs": price, "stock_qty": stock})
    assert r.status_code == 201, r.text


def test_password_change_and_token_revocation():
    with TestClient(app) as c:
        H = _login_store(c, "pw1")
        assert c.post("/api/store/change-password", headers=H,
                      json={"current_password": "xato", "new_password": "Boshqa#Parol2027"}).status_code == 400
        assert c.post("/api/store/change-password", headers=H,
                      json={"current_password": STRONG, "new_password": "zaif"}).status_code == 400
        r = c.post("/api/store/change-password", headers=H,
                   json={"current_password": STRONG, "new_password": "Boshqa#Parol2027"})
        assert r.status_code == 200, r.text
        H2 = {"Authorization": "Bearer " + r.json()["access_token"]}
        assert c.get("/api/store/me", headers=H).status_code == 401      # eski token bekor
        assert c.get("/api/store/me", headers=H2).status_code == 200
        assert c.post("/api/auth/login", json={"login": "pw1", "password": "Boshqa#Parol2027"}).status_code == 200
        assert c.post("/api/store/logout", headers=H2).status_code == 200
        assert c.get("/api/store/me", headers=H2).status_code == 401     # serverda chiqish
        c.delete("/api/superadmin/stores/pw1", headers=SA)


def test_idempotent_sale():
    with TestClient(app) as c:
        H = _login_store(c, "idem1")
        _product(c, H, stock=5)
        body = {"items": [{"sku": "A1", "qty": 2}], "payment_method": "Naqd"}
        r1 = c.post("/api/store/sales", headers={**H, "Idempotency-Key": "key-123"}, json=body)
        r2 = c.post("/api/store/sales", headers={**H, "Idempotency-Key": "key-123"}, json=body)
        assert r1.status_code == 201 and r2.status_code == 201
        assert r1.json()["receipt_code"] == r2.json()["receipt_code"]
        assert c.get("/api/store/products", headers=H).json()[0]["stock_qty"] == 3  # bir marta ayirilgan
        r3 = c.post("/api/store/sales", headers={**H, "Idempotency-Key": "key-456"}, json=body)
        assert r3.json()["receipt_code"] != r1.json()["receipt_code"]
        c.delete("/api/superadmin/stores/idem1", headers=SA)


def test_partial_refund():
    with TestClient(app) as c:
        H = _login_store(c, "ref1")
        _product(c, H, price=1000, cost=400, stock=10)
        cust = c.post("/api/store/customers", headers=H, json={"full_name": "Ali Vali", "phone": "+998931112233"}).json()
        sale = c.post("/api/store/sales", headers=H, json={
            "items": [{"sku": "A1", "qty": 4}], "payment_method": "Naqd", "customer_id": cust["id"]}).json()
        code = sale["receipt_code"]
        assert sale["total_uzs"] == 4000 and sale["profit_uzs"] == 2400

        assert c.post(f"/api/store/sales/{code}/refund", headers=H, json={"items": [{"sku": "A1", "qty": 9}]}).status_code == 400
        r = c.post(f"/api/store/sales/{code}/refund", headers=H, json={"items": [{"sku": "A1", "qty": 1}]})
        assert r.status_code == 200, r.text
        j = r.json()
        assert j["refund_uzs"] == 1000 and j["total_uzs"] == 3000 and j["profit_uzs"] == 1800
        assert j["refunded"] is False and j["refunded_uzs"] == 1000 and j["original_total_uzs"] == 4000
        assert c.get("/api/store/products", headers=H).json()[0]["stock_qty"] == 7
        assert c.get(f"/api/store/sales/{code}", headers=H).json()["lines"][0]["refunded_qty"] == 1

        r = c.post(f"/api/store/sales/{code}/refund", headers=H)  # qolgan hammasi
        assert r.status_code == 200 and r.json()["refunded"] is True and r.json()["total_uzs"] == 0
        assert r.json()["refunded_uzs"] == 4000
        assert c.get("/api/store/products", headers=H).json()[0]["stock_qty"] == 10
        cu = c.get("/api/store/customers", headers=H).json()[0]
        assert cu["total_spent_uzs"] == 0 and "cashback_uzs" not in cu
        assert c.post(f"/api/store/customers/{cust['id']}/bonus", headers=H, json={"amount_uzs": 10000}).status_code == 404
        assert c.post(f"/api/store/sales/{code}/refund", headers=H).status_code == 409
        c.delete("/api/superadmin/stores/ref1", headers=SA)


def test_customer_edit_delete():
    with TestClient(app) as c:
        H = _login_store(c, "cust1")
        _product(c, H, stock=10)
        a = c.post("/api/store/customers", headers=H, json={"full_name": "Ali Vali", "phone": "+998931112233"}).json()
        b = c.post("/api/store/customers", headers=H, json={"full_name": "Vali Soliyev", "phone": "+998901112233"}).json()
        r = c.patch(f"/api/store/customers/{a['id']}", headers=H, json={"full_name": "Ali Yangi"})
        assert r.status_code == 200 and r.json()["full_name"] == "Ali Yangi"
        c.post("/api/store/sales", headers=H, json={"items": [{"sku": "A1", "qty": 1}], "payment_method": "Nasiya", "customer_id": a["id"]})
        assert c.delete(f"/api/store/customers/{a['id']}", headers=H).status_code == 400  # qarzi bor
        assert c.delete(f"/api/store/customers/{b['id']}", headers=H).status_code == 200
        assert c.delete(f"/api/store/customers/{b['id']}", headers=H).status_code == 404
        c.delete("/api/superadmin/stores/cust1", headers=SA)


def test_export_and_pagination():
    with TestClient(app) as c:
        H = _login_store(c, "exp1")
        _product(c, H, stock=20)
        for _ in range(3):
            c.post("/api/store/sales", headers=H, json={"items": [{"sku": "A1", "qty": 1}], "payment_method": "Naqd"})
        assert len(c.get("/api/store/sales?limit=2", headers=H).json()) == 2
        assert len(c.get("/api/store/sales?limit=2&offset=2", headers=H).json()) == 1
        code = c.get("/api/store/sales", headers=H).json()[0]["receipt_code"]
        assert len(c.get(f"/api/store/sales?q={code[:7]}", headers=H).json()) >= 1
        r = c.get("/api/store/export/sales", headers=H)
        assert r.status_code == 200 and r.text.startswith("\ufeff") and code in r.text
        assert "A1" in c.get("/api/store/export/products", headers=H).text
        assert c.get("/api/store/export/customers", headers=H).status_code == 200
        assert c.get("/api/store/export/nope", headers=H).status_code == 422
        c.delete("/api/superadmin/stores/exp1", headers=SA)


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
