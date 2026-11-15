import os
import sys
from datetime import date, timedelta

os.environ["ENV"] = "test"
os.environ["DATABASE_URL"] = "sqlite:///./test_hisobgo.db"
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
