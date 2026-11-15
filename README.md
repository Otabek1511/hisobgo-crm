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

## GitHub (`Otabek1511`) ga Joylashtirish

```bash
git init
git branch -M main
git add .
git commit -m "feat: initial commit of HisobGo Multi-Tenant Retail CRM and Superadmin System"
gh repo create Otabek1511/hisobgo-crm --public --source=. --remote=origin --push
```
