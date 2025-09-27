from flask import Blueprint, jsonify
from security import login_required, current_user
from db import get_today, get_usage
from config_loader import load_config

quota_bp = Blueprint("quota_bp", __name__)

@quota_bp.get("/api/quota")
@login_required
def get_quota():
    u = current_user()
    limit = int(load_config().get("limits", {}).get("daily_summarize_quota", 10))
    used = get_usage(u["id"], get_today())
    return jsonify({"remaining": max(0, limit - used), "limit": limit})