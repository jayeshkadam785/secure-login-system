# Secure Login System

A Flask web app implementing secure authentication: bcrypt password hashing,
parameterized SQL (SQL-injection safe), session management, and optional
TOTP-based Two-Factor Authentication (2FA). Configured to deploy on **Vercel**
with a **Supabase Postgres** database (Vercel's filesystem is serverless/ephemeral,
so SQLite can't be used there).

## Features

- **Registration & Login** — bcrypt (12 salt rounds) password hashing
- **SQL Injection Protection** — 100% parameterized queries (`%s` placeholders), zero string-built SQL
- **Input Validation** — username format, email format, password strength
- **CSRF Protection** — Flask-WTF CSRF token on every form
- **Session Management** — HttpOnly + SameSite + Secure cookies, 30-min timeout, logout
- **Brute-force Protection** — account locks 10 minutes after 5 failed attempts
- **Optional 2FA** — TOTP (Google Authenticator/Authy) with QR code setup

## Project Structure

```
secure-login-app/
├── app.py                  # Main Flask app (Postgres-backed)
├── api/
│   └── index.py             # Vercel serverless entrypoint (imports app.py)
├── vercel.json               # Vercel build/routing config
├── requirements.txt
├── .gitignore
├── static/
│   └── style.css
└── templates/
    ├── base.html, register.html, login.html,
    ├── verify_2fa.html, setup_2fa.html, dashboard.html
```

---

## Step 1 — Create a free Postgres database (Supabase)

1. Go to supabase.com → sign in with GitHub → **New Project**.
2. Once created, go to **Project Settings → Database → Connection string**.
3. Copy the **URI** under **Connection pooling** (port `6543`, not the direct `5432` one — pooled connections are required for serverless functions). It looks like:
   ```
   postgresql://postgres.xxxx:[YOUR-PASSWORD]@aws-0-xxxx.pooler.supabase.com:6543/postgres
   ```
4. Keep this — you'll paste it into Vercel as `DATABASE_URL`.

## Step 2 — Push code to GitHub (mobile-friendly)

Since you're on the delete-then-upload workflow:
1. Create a new GitHub repo (e.g. `secure-login-app`).
2. Upload **all files and folders** from this project keeping the exact structure — `api/`, `static/`, `templates/` must stay as folders, not flattened.
   - Easiest on mobile: use `github.dev` (open your repo, press `.` on GitHub or replace `github.com` with `github.dev` in the URL) — it gives you a full VS Code-like file/folder upload UI.
3. Commit.

## Step 3 — Deploy on Vercel

1. Go to vercel.com → **Add New Project** → **Import** your GitHub repo.
2. Framework preset: choose **Other** (Vercel will detect `vercel.json` automatically).
3. Before deploying, open **Environment Variables** and add:

| Key | Value |
|---|---|
| `DATABASE_URL` | the Supabase pooled connection string from Step 1 |
| `SECRET_KEY` | any long random string (generate one — see below) |

   Generate a `SECRET_KEY` quickly: run `python3 -c "import os;print(os.urandom(32).hex())"` anywhere, or just type 40+ random characters.

   ⚠️ **This step is critical.** Without a fixed `SECRET_KEY`, every serverless cold start creates a new key and instantly invalidates all logged-in sessions.

4. Click **Deploy**.

## Step 4 — Initialize the database table

The `users` table needs to be created once. Easiest way: run this locally before/after deploying —
```bash
pip install -r requirements.txt
export DATABASE_URL="your-supabase-connection-string"
python3 -c "from app import init_db; init_db()"
```
(Or run the same snippet in Supabase's **SQL Editor** using the `CREATE TABLE` statement found in `app.py`'s `init_db()` function.)

## Step 5 — Test

Open your Vercel URL → `/register` → create an account → `/login` → dashboard → try **Enable 2FA**.

---

## Local Development (no Vercel needed)

```bash
pip install -r requirements.txt
export DATABASE_URL="your-supabase-connection-string"
python app.py
```
Open `http://localhost:5000`.

## Security Notes (for your internship report)

| Threat | Mitigation implemented |
|---|---|
| Password theft from DB | bcrypt hash + per-password salt, never store plaintext |
| SQL Injection | 100% parameterized queries |
| Session hijacking | HttpOnly, SameSite, Secure cookies, 30-min expiry, full logout |
| CSRF | Flask-WTF CSRF token required on every POST form |
| Brute-force login | Account lockout after 5 failed attempts (10-min cooldown) |
| Credential-only compromise | Optional TOTP 2FA |
| Weak passwords | Enforced complexity rules at registration |
| Serverless session breakage | Fixed `SECRET_KEY` env var (not regenerated per cold start) |
| Ephemeral filesystem (Vercel) | Persistent Postgres DB instead of local SQLite file |

## Common Deployment Errors

- **"Internal Server Error" on every page** → almost always a missing/wrong `DATABASE_URL` or `SECRET_KEY` env var. Check Vercel → Project → Settings → Environment Variables, then redeploy.
- **Logged out immediately after login** → `SECRET_KEY` not set as a fixed env var.
- **CSS not loading** → make sure the `static/` folder was uploaded to GitHub with the exact folder name and the `vercel.json` static route is present.
