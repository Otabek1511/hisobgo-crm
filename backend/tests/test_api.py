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


SELLER_PW = "Sotuvchi#2027x"


def _make_seller(c, H, login, name="Karim Kassir"):
    r = c.post("/api/store/staff", headers=H, json={"full_name": name, "login": login})
    assert r.status_code == 201, r.text
    otp = r.json()["one_time_password"]
    first = c.post("/api/auth/login", json={"login": login, "password": otp}).json()
    assert first["status"] == "FORCE_PASSWORD_CHANGE_REQUIRED" and first["role"] == "seller"
    assert c.post("/api/auth/change-initial-password",
                  json={"login": login, "one_time_password": otp, "new_strong_password": SELLER_PW}).status_code == 200
    ok = c.post("/api/auth/login", json={"login": login, "password": SELLER_PW}).json()
    assert ok["role"] == "seller"
    return r.json(), {"Authorization": "Bearer " + ok["access_token"]}


def test_seller_role_isolation():
    with TestClient(app) as c:
        H = _login_store(c, "own1")
        _product(c, H, sku="A1", price=1000, cost=400, stock=10)
        cust = c.post("/api/store/customers", headers=H, json={"full_name": "Ali Vali", "phone": "+998931112233"}).json()
        staff, S = _make_seller(c, H, "sell1")
        assert staff["panel_path"] == "seller.html"

        # login band bo'lsa rad etiladi (egasi loginlari, boshqa sotuvchilar, yangi do'kon)
        assert c.post("/api/store/staff", headers=H, json={"full_name": "Boshqa", "login": "sell1"}).status_code == 409
        assert c.post("/api/store/staff", headers=H, json={"full_name": "Boshqa", "login": "own1"}).status_code == 409
        assert c.post("/api/superadmin/stores", json=_store_payload("sell1"), headers=SA).status_code == 400

        # sotuvchi ko'radigan ma'lumot: tannarxsiz, telefonsiz
        prods = c.get("/api/seller/products", headers=S).json()
        assert prods and "cost_uzs" not in prods[0] and prods[0]["price_uzs"] == 1000
        assert c.get("/api/seller/customers?q=a", headers=S).json() == []           # kamida 2 belgi
        found = c.get("/api/seller/customers?q=ali", headers=S).json()
        assert found[0]["full_name"] == "Ali Vali" and "phone" not in found[0] and found[0]["phone_hint"] == "2233"
        assert "debt_uzs" not in found[0]

        # sotuv: javobda foyda yo'q, chegirma cheklangan
        body = {"items": [{"sku": "A1", "qty": 2}], "payment_method": "Naqd", "customer_id": cust["id"]}
        assert c.post("/api/seller/sales", headers=S, json={**body, "discount_pct": 11}).status_code == 400
        r = c.post("/api/seller/sales", headers={**S, "Idempotency-Key": "s-1"}, json=body)
        assert r.status_code == 201, r.text
        assert "profit_uzs" not in r.json() and r.json()["total_uzs"] == 2000 and r.json()["seller_name"] == "Karim Kassir"
        again = c.post("/api/seller/sales", headers={**S, "Idempotency-Key": "s-1"}, json=body)
        assert again.json()["receipt_code"] == r.json()["receipt_code"]
        mine = c.get("/api/seller/sales", headers=S).json()
        assert len(mine) == 1 and "profit_uzs" not in mine[0]

        # egasi endpointlari sotuvchiga yopiq
        for method, url in [
            ("get", "/api/store/me"), ("get", "/api/store/products"), ("get", "/api/store/customers"),
            ("get", "/api/store/dashboard"), ("get", "/api/store/sales"), ("get", "/api/store/employees"),
            ("get", "/api/store/staff"), ("get", "/api/store/export/sales"), ("get", "/api/store/bots"),
        ]:
            assert getattr(c, method)(url, headers=S).status_code == 403, url
        code = r.json()["receipt_code"]
        assert c.post(f"/api/store/sales/{code}/refund", headers=S).status_code == 403
        assert c.post("/api/store/sales", headers=S, json=body).status_code == 403
        assert c.post("/api/store/staff", headers=S, json={"full_name": "X Y", "login": "hack1"}).status_code == 403
        # egasi tokeni sotuvchi endpointlariga kira olmaydi
        assert c.get("/api/seller/products", headers=H).status_code == 403

        # egasi: sotuvchi nomi va foydani ko'radi
        rec = c.get("/api/store/sales", headers=H).json()[0]
        assert rec["seller_name"] == "Karim Kassir" and rec["profit_uzs"] == 1200
        lst = c.get("/api/store/staff", headers=H).json()
        assert lst[0]["today_count"] == 1 and lst[0]["today_total_uzs"] == 2000

        # bloklash: ochiq sessiya yopiladi, qayta yoqilgach eski token ishlamaydi
        sid = staff["id"]
        assert c.patch(f"/api/store/staff/{sid}", headers=H, json={"active": False}).status_code == 200
        assert c.get("/api/seller/products", headers=S).status_code in (401, 403)
        assert c.post("/api/auth/login", json={"login": "sell1", "password": SELLER_PW}).status_code == 403
        assert c.patch(f"/api/store/staff/{sid}", headers=H, json={"active": True}).status_code == 200
        assert c.get("/api/seller/products", headers=S).status_code == 401
        S = {"Authorization": "Bearer " + c.post("/api/auth/login", json={"login": "sell1", "password": SELLER_PW}).json()["access_token"]}

        # parolni o'zgartirish va qayta tiklash
        r = c.post("/api/seller/change-password", headers=S, json={"current_password": SELLER_PW, "new_password": "Yangi#Parol2027"})
        assert r.status_code == 200
        assert c.get("/api/seller/products", headers=S).status_code == 401
        rs = c.post(f"/api/store/staff/{sid}/reset-password", headers=H)
        assert rs.status_code == 200 and rs.json()["one_time_password"].startswith("OTP-")
        assert c.post("/api/auth/login", json={"login": "sell1", "password": rs.json()["one_time_password"]}).json()["status"] == "FORCE_PASSWORD_CHANGE_REQUIRED"

        # boshqa do'kon egasi bu sotuvchini boshqara olmaydi
        H2 = _login_store(c, "own2")
        assert c.delete(f"/api/store/staff/{sid}", headers=H2).status_code == 404
        assert c.delete(f"/api/store/staff/{sid}", headers=H).status_code == 200
        c.delete("/api/superadmin/stores/own1", headers=SA)
        c.delete("/api/superadmin/stores/own2", headers=SA)


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


def test_stock_entries_keep_time_and_qty():
    with TestClient(app) as c:
        H = _login_store(c, "stk1")
        other = _login_store(c, "stk2")
        assert c.post("/api/store/products", headers=H, json={
            "sku": "A1", "name": "Divan", "cost_uzs": 1000, "price_uzs": 2000, "stock_qty": 50}).status_code == 201
        rows = c.get("/api/store/products/A1/entries", headers=H).json()
        assert len(rows) == 1 and rows[0]["qty"] == 50 and rows[0]["created_at"]
        assert c.post("/api/store/products/A1/restock", headers=H, json={"qty": 10}).status_code == 200
        rows = c.get("/api/store/products/A1/entries", headers=H).json()
        assert [r["qty"] for r in rows] == [10, 50]
        assert c.patch("/api/store/products/A1", headers=H, json={"stock_qty": 70}).status_code == 200
        assert [r["qty"] for r in c.get("/api/store/products/A1/entries", headers=H).json()] == [10, 10, 50]
        assert c.patch("/api/store/products/A1", headers=H, json={"stock_qty": 60}).status_code == 200
        assert [r["qty"] for r in c.get("/api/store/products/A1/entries", headers=H).json()] == [10, 10, 50]
        assert c.get("/api/store/products/A1/entries", headers=other).status_code == 404
        c.delete("/api/superadmin/stores/stk1", headers=SA)
        c.delete("/api/superadmin/stores/stk2", headers=SA)


def test_employees_salary_and_advance():
    with TestClient(app) as c:
        H = _login_store(c, "emp1")
        other = _login_store(c, "emp2")
        assert c.get("/api/store/employees", headers=H).json() == []
        bad = c.post("/api/store/employees", headers=H, json={
            "first_name": "A", "last_name": "Karimov", "phone": "+99890", "salary_uzs": -1, "advance_uzs": 0})
        assert bad.status_code == 422
        r = c.post("/api/store/employees", headers=H, json={
            "first_name": "Jasur", "last_name": "Karimov", "phone": "+998901112233",
            "salary_uzs": 3000000, "advance_uzs": 500000})
        assert r.status_code == 201, r.text
        emp = r.json()
        assert emp["payable_uzs"] == 2500000
        assert c.get("/api/store/employees", headers=other).json() == []
        assert c.patch(f"/api/store/employees/{emp['id']}", headers=other, json={"salary_uzs": 1}).status_code == 404
        updated = c.patch(f"/api/store/employees/{emp['id']}", headers=H, json={
            "advance_uzs": 1000000, "phone": "+998907776655"})
        assert updated.status_code == 200
        assert updated.json()["advance_uzs"] == 1000000 and updated.json()["payable_uzs"] == 2000000
        assert updated.json()["salary_uzs"] == 3000000
        listed = c.get("/api/store/employees?q=karim", headers=H).json()
        assert len(listed) == 1 and listed[0]["first_name"] == "Jasur"
        # avans tarixi: boshlang'ich, qo'lda tuzatish va yangi avans
        r = c.post(f"/api/store/employees/{emp['id']}/advances", headers=H, json={"amount_uzs": 200000, "note": "Kunlik"})
        assert r.status_code == 201 and r.json()["advance_uzs"] == 1200000
        assert c.post(f"/api/store/employees/{emp['id']}/advances", headers=H, json={"amount_uzs": 0}).status_code == 422
        assert c.post(f"/api/store/employees/{emp['id']}/advances", headers=other, json={"amount_uzs": 5}).status_code == 404
        hist = c.get(f"/api/store/employees/{emp['id']}/advances", headers=H).json()
        kinds = [a["kind"] for a in hist["advances"]]
        assert kinds == ["advance", "adjust", "initial"] and hist["advances"][0]["note"] == "Kunlik"
        assert [a["amount_uzs"] for a in hist["advances"]] == [200000, 500000, 500000]
        assert c.get(f"/api/store/employees/{emp['id']}/advances", headers=other).status_code == 404
        rm = c.delete(f"/api/store/employees/{emp['id']}/advances/{hist['advances'][0]['id']}", headers=H)
        assert rm.status_code == 200 and rm.json()["advance_uzs"] == 1000000
        # oylikni to'lash: avans ushlanadi, qolgani to'lanadi
        assert c.post(f"/api/store/employees/{emp['id']}/pay-salary", headers=other).status_code == 404
        ps = c.post(f"/api/store/employees/{emp['id']}/pay-salary", headers=H)
        assert ps.status_code == 200, ps.text
        assert ps.json()["paid_uzs"] == 2000000 and ps.json()["held_uzs"] == 1000000 and ps.json()["advance_uzs"] == 0
        h2 = c.get(f"/api/store/employees/{emp['id']}/advances", headers=H).json()["advances"]
        assert h2[0]["kind"] == "payout" and h2[0]["amount_uzs"] == -1000000
        # avans oylikdan oshsa, ortig'i keyingi oyga o'tadi
        c.post(f"/api/store/employees/{emp['id']}/advances", headers=H, json={"amount_uzs": 3500000})
        ps = c.post(f"/api/store/employees/{emp['id']}/pay-salary", headers=H).json()
        assert ps["paid_uzs"] == 0 and ps["advance_uzs"] == 500000
        assert c.delete(f"/api/store/employees/{emp['id']}", headers=H).status_code == 200
        assert c.delete(f"/api/store/employees/{emp['id']}", headers=H).status_code == 404
        c.delete("/api/superadmin/stores/emp1", headers=SA)
        c.delete("/api/superadmin/stores/emp2", headers=SA)
