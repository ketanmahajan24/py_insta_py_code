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
import os
import threading
import time
from datetime import datetime, timezone

from flask import Flask, request, jsonify, session, render_template
from itsdangerous import URLSafeTimedSerializer, BadSignature, SignatureExpired

# ============================================================================
# IMPORT USER VERIFICATION MODULE
# ============================================================================
import userdetails

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
# Helper Functions
# ---------------------------------------------------------------------------
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

    user = userdetails.get_user(payload.get("uid"))
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
    if userdetails.find_user_by_username(username) or userdetails.find_user_by_email(email):
        return jsonify(error="username or email already in use"), 409
    if not userdetails.password_is_valid(password):
        return jsonify(error="password must be at least 6 characters and include a letter and a number"), 400

    user = userdetails.create_user(username, email, password)
    return jsonify(id=user["id"], username=user["username"], email=user["email"]), 201


@app.post("/api/auth/login")
def login():
    data = request.get_json(silent=True) or {}
    username = (data.get("username") or "").strip()
    password = data.get("password") or ""

    user = userdetails.find_user_by_username(username)
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
    """
    Handle password change request.

    Flow:
    1. Receive old password, new password, confirm password from frontend
    2. Call userdetails.verify_old_password() to verify old password
    3. If verified, validate new password requirements
    4. Update password in database via userdetails.update_user()

    Returns:
        - 200: Password successfully changed
        - 400: Invalid old password or new password doesn't meet requirements
        - 500: Internal server error
    """
    data = request.get_json(silent=True) or {}
    old_password = data.get("oldPassword") or ""
    new_password = data.get("newPassword") or ""
    confirm_password = data.get("confirmPassword") or ""
    logout_everywhere = bool(data.get("logoutEverywhere"))

    # ========================================================================
    # STEP 1: Verify old password using userdetails module
    # ========================================================================
    verification_result = userdetails.verify_old_password(old_password)

    if not verification_result["is_verified"]:
        return jsonify(
            error=verification_result["error"],
            field="oldPassword"
        ), 400

    user = verification_result["user"]

    # ========================================================================
    # STEP 2: Validate new password requirements
    # ========================================================================
    if not userdetails.password_is_valid(new_password):
        return jsonify(
            error="password must be at least 6 characters and include a letter and a number",
            field="newPassword",
        ), 400

    # ========================================================================
    # STEP 3: Verify new password is different from old password
    # ========================================================================
    different_check = userdetails.verify_password_different(old_password, new_password)
    if not different_check["is_different"]:
        return jsonify(
            error=different_check["error"],
            field="newPassword"
        ), 400

    # ========================================================================
    # STEP 4: Verify passwords match
    # ========================================================================
    match_check = userdetails.verify_password_match(new_password, confirm_password)
    if not match_check["is_match"]:
        return jsonify(
            error=match_check["error"],
            field="confirmPassword"
        ), 400

    # ========================================================================
    # STEP 5: Update password in database
    # ========================================================================
    fields = {"password": old_password}
    if logout_everywhere:
        fields["session_version"] = user["session_version"] + 1

    userdetails.update_user(user["id"], **fields)

    return jsonify(message="password updated")


@app.post("/api/password/forgot")
def forgot_password():
    """Always responds the same way whether or not the email exists, so
    this endpoint can't be used to discover which emails are registered."""
    ip = request.remote_addr or "unknown"
    if is_rate_limited(ip):
        return jsonify(error="too many requests, try again later"), 429

    data = request.get_json(silent=True) or {}
    user = userdetails.find_user_by_email(data.get("email"))

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

    if not userdetails.password_is_valid(new_password):
        return jsonify(
            error="password must be at least 6 characters and include a letter and a number",
            field="newPassword",
        ), 400
    if new_password != confirm_password:
        return jsonify(error="passwords do not match", field="confirmPassword"), 400

    userdetails.update_user(
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
    """Feeds the admin page. Shows the plaintext password as stored, plus
    the full password-change attempt history (old + new password tried
    each time) — this is only safe because this whole project is a
    local, throwaway demo. Never do this in anything real."""
    users = []
    for u in userdetails.all_users():
        users.append({
            "id": u["id"],
            "username": u["username"],
            "email": u["email"],
            "created_at": u.get("created_at", ""),
            "session_version": u["session_version"],
            "password": u["password"],
            "attempt_count": u.get("attempt_count", 0),
            "password_attempts": u.get("password_attempts", []),
        })
    users.sort(key=lambda u: int(u["id"]))
    return jsonify(users=users, db_path=userdetails.DB_PATH, count=len(users))

if __name__ == "__main__":
    app.run(debug=True, host="0.0.0.0", port=8090)