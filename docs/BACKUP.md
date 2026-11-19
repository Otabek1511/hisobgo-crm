# Zaxira nusxa

Har kuni 02:00 (Toshkent) GitHub Actions `backup.yml` bazadan to'liq nusxa oladi, **shifrlaydi** va 30 kun saqlaydi
(Actions → "Zaxira nusxa" → oxirgi ishga tushirish → Artifacts → `hisobgo-backup`).

## Bir martalik sozlash (Settings → Secrets and variables → Actions)
- `DATABASE_URL` — Neon ulanish manzili (Render'dagi `DATABASE_URL` bilan bir xil).
- `BACKUP_PASSPHRASE` — kamida 16 belgili uzun parol. **Uni alohida joyda (parol menejerida) saqlang** — yo'qolsa nusxani ochib bo'lmaydi.

## Tiklash
```bash
gpg -d hisobgo-2026-11-20.dump.gpg > hisobgo.dump      # parol so'raydi
createdb hisobgo_restore                                # yoki yangi Neon bazasi
pg_restore --no-owner --dbname "postgresql://..." hisobgo.dump
```
Tiklangan bazani Render'dagi `DATABASE_URL` ga ulang va API'ni qayta ishga tushiring.
Ishonchli bo'lishi uchun tiklashni ba'zan sinab ko'ring.
