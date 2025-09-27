from flask import Blueprint, request, jsonify
from security import admin_required
from config_loader import load_config, save_config

config_admin_bp = Blueprint("config_admin_bp", __name__)

@config_admin_bp.get("/api/admin/config")
@admin_required
def get_admin_config():
    return jsonify(load_config())

@config_admin_bp.post("/api/admin/config")
@admin_required
def update_admin_config():
    d = request.get_json(force=True)
    cfg = load_config()
    limits = cfg.setdefault("limits", {})
    if "daily_summarize_quota" in d.get("limits", {}):
        v = int(d["limits"]["daily_summarize_quota"])
        limits["daily_summarize_quota"] = v
    save_config(cfg)
    return jsonify(cfg)