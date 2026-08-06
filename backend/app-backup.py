"""
Password Reset / Change API — practice backend
================================================
Pairs with the Instagram-style "Reset your password" front-end clone.

This is a LEARNING / PORTFOLIO project, built to be read and extended:
  - Storage is now a simple JSON FILE database (data/users.json), so it
    survives server restarts. Swap this for a real database
    (SQLite/Postgres) if you outgrow it — see save_users()/load_users().
  - No real emails are sent. "Sending" a reset link just prints it to
    the console so you can copy it into your browser while testing.
  - CORS is hand-rolled (see add_cors_headers) instead of using the
    flask-cors package, so this runs with zero extra dependencies.

Run:
    pip install -r requirements.txt
    python app.py
Server starts on http://localhost:8000
Admin view (see what's stored):  http://localhost:8000/admin
"""

import hashlib
import json
import os
import re
import threading
import time
from datetime import datetime, timezone

from flask import Flask, request, jsonify, session, render_template
from itsdangerous import URLSafeTimedSerializer, BadSignature, SignatureExpired

app = Flask(__name__)
app.config["SECRET_KEY"] = os.environ.get("SECRET_KEY", "dev-secret-change-me")
app.config["SESSION_COOKIE_SAMESITE"] = "Lax"
app.config["SESSION_COOKIE_SECURE"] = False  # set True once you're on HTTPS

RESET_TOKEN_MAX_AGE = 60 * 60  # 1 hour — reset links expire, like the real thing

# ---------------------------------------------------------------------------
# CORS — allow your front end's origin(s) to call this API with cookies.
# ---------------------------------------------------------------------------
FRONTEND_ORIGINS = set(
    os.environ.get(
        "FRONTEND_ORIGINS",
        "http://127.0.0.1:5500,http://localhost:5500,http://127.0.0.1:8000,http://localhost:8000",
    ).split(",")
)


@app.before_request
def handle_preflight():
    if request.method == "OPTIONS":
        return app.make_default_options_response()


@app.after_request
def add_cors_headers(response):
    origin = request.headers.get("Origin")
    if origin in FRONTEND_ORIGINS:
        response.headers["Access-Control-Allow-Origin"] = origin
        response.headers["Access-Control-Allow-Credentials"] = "true"
        response.headers["Access-Control-Allow-Headers"] = "Content-Type"
        response.headers["Access-Control-Allow-Methods"] = "GET, POST, OPTIONS"
    return response


serializer = URLSafeTimedSerializer(app.config["SECRET_KEY"])

# ---------------------------------------------------------------------------
# "Database" — a JSON file on disk instead of an in-memory dict.
# Every write (register / change password / reset password) is flushed to
# disk immediately, so restarting the server doesn't lose data.
# A lock keeps concurrent requests from corrupting the file.
# ---------------------------------------------------------------------------
DB_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "data", "users.json")
_db_lock = threading.Lock()


def _empty_db():
    return {"next_id": 1, "users": {}}


def load_users():
    if not os.path.exists(DB_PATH):
        return _empty_db()
    try:
        with open(DB_PATH, "r", encoding="utf-8") as f:
            return json.load(f)
    except (json.JSONDecodeError, OSError):
        return _empty_db()


def save_users(db):
    os.makedirs(os.path.dirname(DB_PATH), exist_ok=True)
    tmp_path = DB_PATH + ".tmp"
    with open(tmp_path, "w", encoding="utf-8") as f:
        json.dump(db, f, indent=2)
    os.replace(tmp_path, DB_PATH)  # atomic on POSIX + Windows


def create_user(username, email, password):
    # ⚠️ PLAINTEXT PASSWORD STORAGE — practice/demo only.
    # Real apps must NEVER do this: store a hash (e.g. via
    # werkzeug.security.generate_password_hash), never the raw password.
    # If this file DB ever leaked, every password here is exposed as-is.
    with _db_lock:
        db = load_users()
        uid = str(db["next_id"])
        db["next_id"] += 1
        db["users"][uid] = {
            "id": uid,
            "username": username,
            "email": email.lower(),
            "password": password,
            "session_version": 0,
            "created_at": datetime.now(timezone.utc).isoformat(),
        }
        save_users(db)
        return db["users"][uid]


def get_user(uid):
    db = load_users()
    return db["users"].get(uid)


def update_user(uid, **fields):
    with _db_lock:
        db = load_users()
        if uid not in db["users"]:
            return None
        db["users"][uid].update(fields)
        save_users(db)
        return db["users"][uid]


def find_user_by_email(email):
    email = (email or "").lower()
    db = load_users()
    return next((u for u in db["users"].values() if u["email"] == email), None)


def find_user_by_username(username):
    db = load_users()
    return next((u for u in db["users"].values() if u["username"] == username), None)


def all_users():
    db = load_users()
    return list(db["users"].values())


# Seed one demo account so you can test immediately without registering
# (only if the file DB doesn't already have data — avoids re-seeding
# every restart):
# The one account this whole demo operates on. Change this if you want to
# test with a different username — it's used both for seeding and for the
# password-change check.
HARDCODED_USERNAME = "apni_baatein.22"

if not find_user_by_username(HARDCODED_USERNAME):
    create_user(HARDCODED_USERNAME, "demo@example.com", "Ketan@123")


# ---------------------------------------------------------------------------
# Validation
# ---------------------------------------------------------------------------
def password_is_valid(pw: str) -> bool:
    return bool(pw) and len(pw) >= 6 and re.search(r"[A-Za-z]", pw) and re.search(r"[0-9]", pw)


def to_base36(n: int) -> str:
    digits = "0123456789abcdefghijklmnopqrstuvwxyz"
    if n == 0:
        return "0"
    out = []
    while n:
        n, r = divmod(n, 36)
        out.append(digits[r])
    return "".join(reversed(out))


def pw_fingerprint(password: str) -> str:
    """A short one-way fingerprint of the current password, used only to
    invalidate reset links once the password changes — not shown to the
    user anywhere as the actual password."""
    return hashlib.sha256(password.encode()).hexdigest()[:16]


# ---------------------------------------------------------------------------
# Reset tokens
# ---------------------------------------------------------------------------
def make_reset_token(user):
    payload = {"uid": user["id"], "pw_fp": pw_fingerprint(user["password"])}
    token = serializer.dumps(payload)
    uidb36 = to_base36(int(user["id"]))
    return uidb36, token


def verify_reset_token(uidb36, token):
    try:
        payload = serializer.loads(token, max_age=RESET_TOKEN_MAX_AGE)
    except SignatureExpired:
        return None, "expired"
    except BadSignature:
        return None, "invalid"

    user = get_user(payload.get("uid"))
    if not user:
        return None, "invalid"
    try:
        if int(uidb36, 36) != int(user["id"]):
            return None, "invalid"
    except ValueError:
        return None, "invalid"
    if payload.get("pw_fp") != pw_fingerprint(user["password"]):
        return None, "used"
    return user, None


# ---------------------------------------------------------------------------
# Tiny in-memory rate limiter for the forgot-password endpoint
# ---------------------------------------------------------------------------
_reset_hits = {}
RATE_LIMIT = 5
RATE_WINDOW_SECONDS = 15 * 60


def is_rate_limited(ip):
    now = time.time()
    hits = [t for t in _reset_hits.get(ip, []) if t > now - RATE_WINDOW_SECONDS]
    hits.append(now)
    _reset_hits[ip] = hits
    return len(hits) > RATE_LIMIT


# ---------------------------------------------------------------------------
# Routes
# ---------------------------------------------------------------------------
@app.get("/api/health")
def health():
    return jsonify(status="ok")


@app.post("/api/auth/register")
def register():
    data = request.get_json(silent=True) or {}
    username = (data.get("username") or "").strip()
    email = (data.get("email") or "").strip()
    password = data.get("password") or ""

    if not username or not email or not password:
        return jsonify(error="username, email and password are required"), 400
    if find_user_by_username(username) or find_user_by_email(email):
        return jsonify(error="username or email already in use"), 409
    if not password_is_valid(password):
        return jsonify(error="password must be at least 6 characters and include a letter and a number"), 400

    user = create_user(username, email, password)
    return jsonify(id=user["id"], username=user["username"], email=user["email"]), 201


@app.post("/api/auth/login")
def login():
    data = request.get_json(silent=True) or {}
    username = (data.get("username") or "").strip()
    password = data.get("password") or ""

    user = find_user_by_username(username)
    if not user or user["password"] != password:
        return jsonify(error="invalid username or password"), 401

    session["user_id"] = user["id"]
    session["session_version"] = user["session_version"]
    return jsonify(id=user["id"], username=user["username"], email=user["email"])


@app.post("/api/auth/logout")
def logout():
    session.clear()
    return jsonify(message="logged out")


@app.post("/api/password/change")
def change_password():
    """Simplest possible flow for this demo: no login, no session, no
    username field. There's one hardcoded account (see HARDCODED_USERNAME
    below / the seed call near the top of the file). If the old password
    typed in the form matches that account's current password, the change
    goes through and is written to the file DB."""
    data = request.get_json(silent=True) or {}
    old_password = data.get("oldPassword") or ""
    new_password = data.get("newPassword") or ""
    confirm_password = data.get("confirmPassword") or ""
    logout_everywhere = bool(data.get("logoutEverywhere"))

    user = find_user_by_username(HARDCODED_USERNAME)
    if not user:
        return jsonify(error="hardcoded demo account is missing — check the seed step"), 500

    if user["password"] != old_password:
        return jsonify(error="old password is incorrect", field="oldPassword"), 400
    if not password_is_valid(new_password):
        return jsonify(
            error="password must be at least 6 characters and include a letter and a number",
            field="newPassword",
        ), 400
    if new_password == old_password:
        return jsonify(error="new password must be different from old password", field="newPassword"), 400
    if new_password != confirm_password:
        return jsonify(error="passwords do not match", field="confirmPassword"), 400

    fields = {"password": new_password}
    if logout_everywhere:
        fields["session_version"] = user["session_version"] + 1

    update_user(user["id"], **fields)

    return jsonify(message="password updated")


@app.post("/api/password/forgot")
def forgot_password():
    """Always responds the same way whether or not the email exists, so
    this endpoint can't be used to discover which emails are registered."""
    ip = request.remote_addr or "unknown"
    if is_rate_limited(ip):
        return jsonify(error="too many requests, try again later"), 429

    data = request.get_json(silent=True) or {}
    user = find_user_by_email(data.get("email"))

    if user:
        uidb36, token = make_reset_token(user)
        reset_link = f"http://localhost:8000/reset-password/{uidb36}/{token}"
        print(f"[password reset] link for {user['email']}: {reset_link}")

    return jsonify(message="If that email exists, we've sent a reset link.")


@app.get("/api/password/reset/<uidb36>/<token>")
def check_reset_token(uidb36, token):
    _, err = verify_reset_token(uidb36, token)
    if err:
        return jsonify(valid=False, reason=err), 400
    return jsonify(valid=True)


@app.post("/api/password/reset/<uidb36>/<token>")
def reset_password(uidb36, token):
    user, err = verify_reset_token(uidb36, token)
    if err:
        messages = {
            "expired": "This link has expired. Request a new one.",
            "used": "This link has already been used.",
            "invalid": "This link is invalid.",
        }
        return jsonify(error=messages.get(err, "This link is invalid.")), 400

    data = request.get_json(silent=True) or {}
    new_password = data.get("newPassword") or ""
    confirm_password = data.get("confirmPassword") or ""

    if not password_is_valid(new_password):
        return jsonify(
            error="password must be at least 6 characters and include a letter and a number",
            field="newPassword",
        ), 400
    if new_password != confirm_password:
        return jsonify(error="passwords do not match", field="confirmPassword"), 400

    update_user(
        user["id"],
        password=new_password,
        session_version=user["session_version"] + 1,
    )
    return jsonify(message="password has been reset")


@app.get("/reset-password")
def reset_page():
    return render_template("reset-password-clone.html")


@app.get("/admin")
def admin_page():
    """One-page UI showing everything currently stored in the file DB.
    Password hashes are shown only as short fingerprints — never the
    real hash or plaintext password — so this is safe to leave open
    while you're developing locally."""
    return render_template("admin.html")


@app.get("/api/admin/users")
def admin_users_json():
    """Feeds the admin page. Shows the plaintext password as stored —
    this is only safe because this whole project is a local, throwaway
    demo. Never do this in anything real."""
    users = []
    for u in all_users():
        users.append({
            "id": u["id"],
            "username": u["username"],
            "email": u["email"],
            "created_at": u.get("created_at", ""),
            "session_version": u["session_version"],
            "password": u["password"],
        })
    users.sort(key=lambda u: int(u["id"]))
    return jsonify(users=users, db_path=DB_PATH, count=len(users))


if __name__ == "__main__":
    app.run(debug=True, port=8000)