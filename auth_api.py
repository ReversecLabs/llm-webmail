import secrets, datetime
from haikunator import Haikunator
from flask import Blueprint, request, jsonify, session, json
from config_loader import load_config
from werkzeug.security import generate_password_hash, check_password_hash
import json

from db import (
    get_user_by_username, create_user, get_user_by_id,
    get_key, mark_key_used, create_keys, list_keys, revoke_key,
)
from security import login_required, admin_required, current_user

haikunator = Haikunator()

auth_bp = Blueprint("auth_bp", __name__)
keys_bp = Blueprint("keys_bp", __name__)

@auth_bp.post("/api/register")
def register():
    d = request.get_json(force=True)
    key = (d.get("key") or "").strip()
    username = (d.get("username") or "").strip()
    password = d.get("password") or ""
    if not key or not username or not password:
        return jsonify({"error": "bad_request"}), 400
    if get_user_by_username(username):
        return jsonify({"error": "username_taken"}), 400
    k = get_key(key)
    if not k or k["revoked"]:
        return jsonify({"error": "invalid_key"}), 400
    if k["used_by_user_id"] is not None:
        return jsonify({"error": "key_used"}), 400
    default_cfg = load_config()  # use global config as starting point
    user = create_user(username, generate_password_hash(password), initial_config_json=json.dumps(default_cfg))
    mark_key_used(key, user["id"])
    session["uid"] = user["id"]
    return jsonify({"username": user["username"], "role": user["role"]})

    

@auth_bp.post("/api/login")
def login():
    d = request.get_json(force=True)
    username = d.get("username") or ""
    password = d.get("password") or ""
    u = get_user_by_username(username)
    if not u or not check_password_hash(u["password_hash"], password):
        return jsonify({"error": "invalid_credentials"}), 401
    session["uid"] = u["id"]
    return jsonify({"username": u["username"], "role": u["role"]})

@auth_bp.route("/api/logout", methods=["POST"])
def logout():
    session.clear()
    return jsonify({"ok": True})

@auth_bp.get("/api/me")
def me():
    u = current_user()
    if not u:
        return jsonify({"authenticated": False})
    return jsonify({"authenticated": True, "username": u["username"], "role": u["role"]})

# Admin: signup keys
@keys_bp.post("/api/signup-keys")
@admin_required
def create_signup_keys():
    d = request.get_json(force=True)
    count = int(d.get("count") or 1)
    tokens = [haikunator.haikunate() for _ in range(max(1, min(count, 1000)))]
    create_keys(tokens)
    return jsonify({"tokens": tokens})

@keys_bp.get("/api/signup-keys")
@admin_required
def list_signup_keys():
    rows = list_keys()
    return jsonify([
        {
            "token": r["token"],
            "revoked": bool(r["revoked"]),
            "created_at": r["created_at"],
            "used_by": r["used_by"],
        } for r in rows
    ])

@keys_bp.post("/api/signup-keys/revoke")
@admin_required
def revoke_signup_key():
    d = request.get_json(force=True)
    token = d.get("token") or ""
    if not token:
        return jsonify({"error": "bad_request"}), 400
    revoke_key(token)
    return jsonify({"revoked": True})