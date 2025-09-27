from functools import wraps
from flask import session, jsonify, request
from db import get_user_by_id

def current_user():
    uid = session.get("uid")
    return get_user_by_id(uid) if uid else None


def login_required(fn):
    @wraps(fn)
    def w(*a, **k):
        if not session.get("uid"):
            return jsonify({"error": "auth_required"}), 401
        return fn(*a, **k)
    return w


def admin_required(fn):
    @wraps(fn)
    def w(*a, **k):
        u = current_user()
        if not u or u["role"] != "admin":
            return jsonify({"error": "forbidden"}), 403
        return fn(*a, **k)
    return w

# Gate key paths without touching existing handlers
PROTECTED_PREFIXES = ("/api/",)
OPEN_PATHS = {
    "/api/login",
    "/api/register",
    "/api/me",
}
ADMIN_POST_PATHS = {
    ("/api/config", "POST"),
}

from db import get_today, get_usage, inc_usage
from config_loader import load_config

def install_guards(app):
    @app.before_request
    def _auth_gate():
        p = request.path
        if p.startswith("/static/") or p in ("/", "/index.html", "/favicon.ico"):
            return
        if p not in OPEN_PATHS and p.startswith(PROTECTED_PREFIXES):
            if not session.get("uid"):
                return jsonify({"error": "auth_required"}), 401
        # admin-only writes to /api/config
        if (p, request.method) in ADMIN_POST_PATHS:
            u = current_user()
            if not u or u["role"] != "admin":
                return jsonify({"error": "forbidden"}), 403
        # quota check before summarize
        if p == "/api/summarize" and request.method == "POST":
            u = current_user()
            if not u:
                return jsonify({"error": "auth_required"}), 401
            limit = int(load_config().get("limits", {}).get("daily_summarize_quota", 10))
            used = get_usage(u["id"], get_today())
            if used >= limit:
                return jsonify({"error": "quota_exceeded", "limit": limit}), 429

    @app.after_request
    def _usage_hook(resp):
        try:
            if request.path == "/api/summarize" and request.method == "POST" and resp.status_code == 200:
                u = current_user()
                if u:
                    inc_usage(u["id"], get_today())
        finally:
            return resp