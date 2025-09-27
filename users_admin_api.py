# users_admin_api.py
from flask import Blueprint, request, jsonify
from werkzeug.security import generate_password_hash
from security import admin_required
from db import get_conn

users_admin_bp = Blueprint("users_admin_bp", __name__)

@users_admin_bp.get("/api/admin/users")
@admin_required
def list_users():
    c = get_conn()
    rows = c.execute("SELECT id, username, role FROM users ORDER BY username ASC").fetchall()
    return jsonify([{"id": r["id"], "username": r["username"], "role": r["role"]} for r in rows])

@users_admin_bp.post("/api/admin/users/reset-password")
@admin_required
def reset_password():
    d = request.get_json(force=True)
    username = (d.get("username") or "").strip()
    new_password = d.get("password") or ""
    if not username or not new_password:
        return jsonify({"error": "bad_request"}), 400
    h = generate_password_hash(new_password)
    c = get_conn()
    cur = c.execute("UPDATE users SET password_hash=? WHERE username=?", (h, username))
    c.commit()
    if cur.rowcount == 0:
        return jsonify({"error": "not_found"}), 404
    return jsonify({"ok": True})

@users_admin_bp.post("/api/admin/users/delete")
@admin_required
def delete_user():
    d = request.get_json(force=True)
    username = (d.get("username") or "").strip()
    if not username:
        return jsonify({"error": "bad_request"}), 400
    c = get_conn()
    # find user id
    u = c.execute("SELECT id FROM users WHERE username=?", (username,)).fetchone()
    if not u:
        return jsonify({"error": "not_found"}), 404
    uid = u["id"]
    # clean up usage rows; do NOT “free” old signup keys unless you want that behavior
    c.execute("DELETE FROM daily_usage WHERE user_id=?", (uid,))
    c.execute("DELETE FROM users WHERE id=?", (uid,))
    c.commit()
    return jsonify({"ok": True})
