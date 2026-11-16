# HisobGo — Do'konlar uchun Multi-Tenant CRM & Xavfsiz Superadmin Tizimi

Ushbu loyiha [HisobGo](https://HisobGo.io/uz) chakana savdo avtomatlashtirish tizimi andozasida qurilgan bo'lib, ko'p do'konli (Multi-Tenant SaaS) arxitekturaga va yuqori xavfsizlikdagi **Superadmin** boshqaruv paneliga ega.

## Asosiy Imkoniyatlar

1. **Yuqori Xavfsizlikdagi Superadmin Paneli:**
   - Do'kon hisobini qo'shish, o'chirish va vaqtincha bloklash (`ACTIVE` / `BLOCKED` / `EXPIRED`).
   - Abonent to'lovi amal qilish sanasini (`subscription_expires_at`) belgilash va uzaytirish.
   - Yangi do'kon qo'shilganda kriptografik **bir martalik parol (OTP)** (`OTP-XXXX-XX`) generatsiya qilish.
   - O'zgarmas xavfsizlik audit jurnali (`security_audit_logs`).
2. **Bir Martalik Parol va Majburiy Parol Yangilash (`must_change_password`):**
   - Do'kon egasi birinchi marta OTP parol bilan kirganda, tizim uni majburiy ravishda yangi kuchli parol (kamida 8 belgi, `A-Z`, `a-z`, `0-9` va maxsus belgi) o'rnatish ekraniga yo'naltiradi.
3. **HisobGo Andozasidagi Do'kon CRM & POS Modullari:**
   - **Dashboard va Analitika:** Tushum, sof foyda, o'rtacha ustama marjasi, ombor qiymati, haftalik savdo grafigi va kam qolgan tovarlar nazorati.
   - **Kassa (POS Terminal):** Shtrixkod / nom bo'yicha qidiruv, savat, chegirma, mijoz tanlash, Naqd / Karta / Click-Payme / **Nasiya** to'lov turlari va chek chiqarish.
   - **Tovarlar va Ombor:** Katalog, SKU, kelish va sotuv narxlari, marja hisobi va omborga kirim qilish.
   - **Mijozlar va Nasiya (CRM):** Mijozlar ro'yxati, 3% keshbek balansi va nasiya qarzlarini so'ndirish.

## Ishga tushirish

```bash
cp .env.example .env        # qiymatlarni almashtiring (JWT_SECRET, SUPERADMIN_SECRET_KEY, POSTGRES_PASSWORD)
docker compose up --build
```

- Do'kon egalari paneli: http://localhost:8080  •  Superadmin paneli (alohida sahifa): http://localhost:8080/admin.html
- API hujjatlari: http://localhost:8000/docs  (`/health` — holat tekshiruvi)
- Jadvallar birinchi ishga tushishda avtomatik yaratiladi.
- Lokal sinov: `cd backend && pip install -r requirements-dev.txt && pytest` (`ENV=dev` SQLite ishlatadi).

## API qisqacha

| Qism | Endpointlar |
|---|---|
| Superadmin (`X-Superadmin-Key`, ixtiyoriy `X-Superadmin-TOTP`) | `/api/superadmin/stores` (GET/POST), `.../{login}/block`, `.../subscription`, `.../reset-otp`, DELETE, `/api/superadmin/audit-logs` |
| Autentifikatsiya | `/api/auth/login`, `/api/auth/change-initial-password` (5 ta xato urinishdan keyin 15 daqiqa blok) |
| Do'kon (Bearer JWT, har so'rovda status/obuna tekshiriladi) | `/api/store/products` (PATCH/DELETE `/{sku}` — tahrirlash/o'chirish), `/customers`, `/sales`, `POST /sales/{chek}/refund` (to'liq qaytarish), `/dashboard` |

## Telegram botlar

Ikkita bot (BotFather'da alohida yaratiladi):
- **Sotuv boti** — har bir sotuvda ulangan omborchi(lar)ga xabar yuboradi (tovar, soni, ombordagi qoldiq; kam qolsa ogohlantirish).
- **Hisobot boti** — har kuni 20:00 (Toshkent) da egaga kunlik hisobot: cheklar soni, tushum, foyda, to'lov turlari, nasiya, eng ko'p sotilganlar, kam qolgan tovarlar. `/hisobot` buyrug'i bilan istalgan vaqtda olish mumkin.

Sozlash (Render → `hisobgo-api` → Environment): `SALES_BOT_TOKEN`, `REPORT_BOT_TOKEN`, `TELEGRAM_WEBHOOK_SECRET`, `CRON_KEY`. Keyin `admin.html` da **Webhooklarni sozlash** tugmasini bosing. Do'kon egasi CRM → **Botlar** bo'limidan bir martalik kod (15 daqiqa) oladi va Telegram'da `/start KOD` yuboradi (shaxsiy chat yoki guruh).

20:00 jadvali: `.github/workflows/daily-report.yml` (GitHub Actions cron). GitHub repo → Settings → Secrets → Actions ga `API_URL` (`https://hisobgo-api.onrender.com`) va `CRON_KEY` (Render'dagi bilan bir xil) qo'shing. GitHub cron bir necha daqiqa kechikishi mumkin.

## Muhim eslatmalar

- `frontend/index.html` (do'kon egalari) va `frontend/admin.html` (Superadmin, alohida manzil, do'kon sahifasidan havola yo'q) haqiqiy API ga ulangan (Tailwind CDN). API manzili: `localhost` da `http://localhost:8000`, aks holda `https://hisobgo-api.onrender.com` (faylning boshidagi `API` o'zgaruvchisida). Tenant izolyatsiyasi backendda `store_id` filtri orqali amalga oshirilgan; PostgreSQL RLS yoqilmagan.
- Production'da `ENV=production` (standart) bo'lib, `JWT_SECRET` va `SUPERADMIN_SECRET_KEY` majburiy; `CORS_ORIGINS` ni frontend manziliga qo'ying.
