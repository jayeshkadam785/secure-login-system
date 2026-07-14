"""
Secure Login System (Vercel-ready)
-----------------------------------
Flask web app with:
  - User registration & login with bcrypt password hashing
  - Parameterized SQL queries via Postgres (SQL-injection safe)
  - Input validation (username, email, password strength)
  - Session-based auth with logout
  - Optional TOTP-based Two-Factor Authentication (Google Authenticator compatible)
  - Basic login-attempt lockout (brute-force protection)

NOTE: Uses Postgres instead of SQLite because Vercel's serverless filesystem
is read-only/ephemeral — a local SQLite file will NOT persist between requests.
Set DATABASE_URL (e.g. from Supabase) as an environment variable.
"""

import os
import re
import base64
from io import BytesIO
from datetime import datetime, timedelta
from functools import wraps

import bcrypt
import pyotp
import qrcode
import psycopg2
import psycopg2.extras
from flask import (
    Flask, render_template, request, redirect,
    url_for, session, flash
)
from flask_wtf import CSRFProtect

# --------------------------------------------------------------------------
# App configuration
# --------------------------------------------------------------------------
app = Flask(__name__)

# IMPORTANT: On Vercel, set SECRET_KEY as a fixed environment variable.
# If left to the random fallback, every serverless cold start gets a new
# key and all existing sessions/logins break instantly.
app.config["SECRET_KEY"] = os.environ.get("SECRET_KEY", os.urandom(32).hex())
app.config["SESSION_COOKIE_HTTPONLY"] = True
app.config["SESSION_COOKIE_SAMESITE"] = "Lax"
app.config["SESSION_COOKIE_SECURE"] = True   # HTTPS only (Vercel serves HTTPS)
app.permanent_session_lifetime = timedelta(minutes=30)

csrf = CSRFProtect(app)

DATABASE_URL = os.environ.get("DATABASE_URL")

MAX_LOGIN_ATTEMPTS = 5
LOCKOUT_MINUTES = 10

# --------------------------------------------------------------------------
# Database helpers (Postgres, parameterized %s queries only -> no SQL injection)
# --------------------------------------------------------------------------
def get_db():
    """New connection per request — correct pattern for serverless functions."""
    conn = psycopg2.connect(DATABASE_URL, cursor_factory=psycopg2.extras.RealDictCursor)
    return conn


def init_db():
    conn = get_db()
    cur = conn.cursor()
    cur.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id              SERIAL PRIMARY KEY,
            username        TEXT UNIQUE NOT NULL,
            email           TEXT UNIQUE NOT NULL,
            password_hash   TEXT NOT NULL,
            totp_secret     TEXT,
            is_2fa_enabled  BOOLEAN NOT NULL DEFAULT FALSE,
            failed_attempts INTEGER NOT NULL DEFAULT 0,
            locked_until    TIMESTAMP,
            created_at      TIMESTAMP NOT NULL
        )
    """)
    conn.commit()
    cur.close()
    conn.close()


# --------------------------------------------------------------------------
# Validation helpers
# --------------------------------------------------------------------------
USERNAME_RE = re.compile(r"^[A-Za-z0-9_]{3,20}$")
EMAIL_RE = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")


def validate_registration(username, email, password, confirm_password):
    errors = []
    if not USERNAME_RE.match(username or ""):
        errors.append("Username must be 3-20 characters: letters, numbers, underscore only.")
    if not EMAIL_RE.match(email or ""):
        errors.append("Please enter a valid email address.")
    if len(password or "") < 8:
        errors.append("Password must be at least 8 characters long.")
    else:
        if not re.search(r"[A-Z]", password):
            errors.append("Password must contain at least one uppercase letter.")
        if not re.search(r"[a-z]", password):
            errors.append("Password must contain at least one lowercase letter.")
        if not re.search(r"[0-9]", password):
            errors.append("Password must contain at least one digit.")
        if not re.search(r"[!@#$%^&*(),.?\":{}|<>_\-]", password):
            errors.append("Password must contain at least one special character.")
    if password != confirm_password:
        errors.append("Passwords do not match.")
    return errors


# --------------------------------------------------------------------------
# Auth helpers
# --------------------------------------------------------------------------
def hash_password(plain_password: str) -> str:
    salt = bcrypt.gensalt(rounds=12)
    return bcrypt.hashpw(plain_password.encode("utf-8"), salt).decode("utf-8")


def verify_password(plain_password: str, password_hash: str) -> bool:
    try:
        return bcrypt.checkpw(plain_password.encode("utf-8"), password_hash.encode("utf-8"))
    except ValueError:
        return False


def login_required(view_func):
    @wraps(view_func)
    def wrapped(*args, **kwargs):
        if "user_id" not in session:
            flash("Please log in to continue.", "warning")
            return redirect(url_for("login"))
        return view_func(*args, **kwargs)
    return wrapped


# --------------------------------------------------------------------------
# Routes
# --------------------------------------------------------------------------
@app.route("/")
def index():
    if "user_id" in session:
        return redirect(url_for("dashboard"))
    return redirect(url_for("login"))


@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        email = request.form.get("email", "").strip().lower()
        password = request.form.get("password", "")
        confirm_password = request.form.get("confirm_password", "")

        errors = validate_registration(username, email, password, confirm_password)

        conn = get_db()
        cur = conn.cursor()

        if not errors:
            cur.execute(
                "SELECT id FROM users WHERE username = %s OR email = %s",
                (username, email)
            )
            if cur.fetchone():
                errors.append("Username or email is already registered.")

        if errors:
            cur.close()
            conn.close()
            for e in errors:
                flash(e, "danger")
            return render_template("register.html", username=username, email=email)

        password_hash = hash_password(password)
        cur.execute(
            "INSERT INTO users (username, email, password_hash, created_at) VALUES (%s, %s, %s, %s)",
            (username, email, password_hash, datetime.utcnow())
        )
        conn.commit()
        cur.close()
        conn.close()
        flash("Account created successfully. Please log in.", "success")
        return redirect(url_for("login"))

    return render_template("register.html", username="", email="")


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")

        conn = get_db()
        cur = conn.cursor()
        cur.execute("SELECT * FROM users WHERE username = %s", (username,))
        user = cur.fetchone()

        if user and user["locked_until"]:
            if datetime.utcnow() < user["locked_until"]:
                cur.close()
                conn.close()
                flash(f"Account locked. Try again after {user['locked_until'].strftime('%H:%M:%S')} UTC.", "danger")
                return render_template("login.html", username=username)

        if user and verify_password(password, user["password_hash"]):
            cur.execute(
                "UPDATE users SET failed_attempts = 0, locked_until = NULL WHERE id = %s",
                (user["id"],)
            )
            conn.commit()
            cur.close()
            conn.close()

            if user["is_2fa_enabled"]:
                session["pending_user_id"] = user["id"]
                return redirect(url_for("verify_2fa"))

            session.clear()
            session.permanent = True
            session["user_id"] = user["id"]
            session["username"] = user["username"]
            flash("Logged in successfully.", "success")
            return redirect(url_for("dashboard"))

        if user:
            attempts = user["failed_attempts"] + 1
            locked_until = None
            if attempts >= MAX_LOGIN_ATTEMPTS:
                locked_until = datetime.utcnow() + timedelta(minutes=LOCKOUT_MINUTES)
                flash(f"Too many failed attempts. Account locked for {LOCKOUT_MINUTES} minutes.", "danger")
            cur.execute(
                "UPDATE users SET failed_attempts = %s, locked_until = %s WHERE id = %s",
                (attempts, locked_until, user["id"])
            )
            conn.commit()

        cur.close()
        conn.close()
        flash("Invalid username or password.", "danger")

    return render_template("login.html", username="")


@app.route("/verify-2fa", methods=["GET", "POST"])
def verify_2fa():
    pending_id = session.get("pending_user_id")
    if not pending_id:
        return redirect(url_for("login"))

    conn = get_db()
    cur = conn.cursor()
    cur.execute("SELECT * FROM users WHERE id = %s", (pending_id,))
    user = cur.fetchone()
    cur.close()
    conn.close()

    if request.method == "POST":
        code = request.form.get("otp_code", "").strip()
        totp = pyotp.TOTP(user["totp_secret"])
        if totp.verify(code, valid_window=1):
            session.pop("pending_user_id", None)
            session.clear()
            session.permanent = True
            session["user_id"] = user["id"]
            session["username"] = user["username"]
            flash("2FA verified. Logged in successfully.", "success")
            return redirect(url_for("dashboard"))
        flash("Invalid or expired authentication code.", "danger")

    return render_template("verify_2fa.html")


@app.route("/dashboard")
@login_required
def dashboard():
    conn = get_db()
    cur = conn.cursor()
    cur.execute("SELECT * FROM users WHERE id = %s", (session["user_id"],))
    user = cur.fetchone()
    cur.close()
    conn.close()
    return render_template("dashboard.html", user=user)


@app.route("/setup-2fa", methods=["GET", "POST"])
@login_required
def setup_2fa():
    conn = get_db()
    cur = conn.cursor()
    cur.execute("SELECT * FROM users WHERE id = %s", (session["user_id"],))
    user = cur.fetchone()

    if request.method == "POST":
        code = request.form.get("otp_code", "").strip()
        secret = session.get("temp_totp_secret")
        if secret:
            totp = pyotp.TOTP(secret)
            if totp.verify(code, valid_window=1):
                cur.execute(
                    "UPDATE users SET totp_secret = %s, is_2fa_enabled = TRUE WHERE id = %s",
                    (secret, user["id"])
                )
                conn.commit()
                cur.close()
                conn.close()
                session.pop("temp_totp_secret", None)
                flash("Two-Factor Authentication enabled successfully.", "success")
                return redirect(url_for("dashboard"))
            flash("Invalid code. Please try again.", "danger")

    cur.close()
    conn.close()

    secret = pyotp.random_base32()
    session["temp_totp_secret"] = secret
    totp_uri = pyotp.totp.TOTP(secret).provisioning_uri(
        name=user["email"], issuer_name="SecureLoginApp"
    )
    qr_img = qrcode.make(totp_uri)
    buffered = BytesIO()
    qr_img.save(buffered, format="PNG")
    qr_base64 = base64.b64encode(buffered.getvalue()).decode("utf-8")

    return render_template("setup_2fa.html", qr_base64=qr_base64, secret=secret)


@app.route("/disable-2fa", methods=["POST"])
@login_required
def disable_2fa():
    conn = get_db()
    cur = conn.cursor()
    cur.execute(
        "UPDATE users SET is_2fa_enabled = FALSE, totp_secret = NULL WHERE id = %s",
        (session["user_id"],)
    )
    conn.commit()
    cur.close()
    conn.close()
    flash("Two-Factor Authentication disabled.", "info")
    return redirect(url_for("dashboard"))


@app.route("/logout")
def logout():
    session.clear()
    flash("You have been logged out.", "info")
    return redirect(url_for("login"))


# --------------------------------------------------------------------------
# Local dev entrypoint (Vercel uses api/index.py instead)
# --------------------------------------------------------------------------
if __name__ == "__main__":
    init_db()
    app.run(host="0.0.0.0", port=5000, debug=False)
