import os
from pathlib import Path
import secrets
import toml, threading
CONFIG_PATH = "config.toml"
_lock = threading.Lock()

def load_config():
    with _lock:
        return toml.load(CONFIG_PATH)

def save_config(cfg: dict):
    with _lock:
        with open(CONFIG_PATH, "w") as f:
            toml.dump(cfg, f)


TRAINING_FIELDS = {
    "llm": {"selected": str},
    "prompt_engineering": {"mode": str},
    "prompt_injection_filter": {"mode": str},
    "delimiter-filtering": {"mode": str},
    "logging": {"verbose": bool},
}


def training_config(cfg):
    """Allow only the participant controls, never server credentials or models."""
    if not isinstance(cfg, dict):
        return {}
    result = {}
    for section, fields in TRAINING_FIELDS.items():
        values = cfg.get(section)
        if isinstance(values, dict):
            result[section] = {
                name: values[name] for name, kind in fields.items()
                if name in values and type(values[name]) is kind
            }
    return result


def merge_training_config(base, updates):
    """Merge participant controls without replacing server-owned nested fields."""
    result = dict(base)
    for section, fields in training_config(updates).items():
        result[section] = {**result.get(section, {}), **fields}
    return result


def public_config(cfg, global_cfg):
    result = training_config(cfg)
    # The browser needs model identifiers and labels, never provider parameters.
    models = []
    for model in global_cfg.get("llm", {}).get("models", []):
        models.append({
            name: model[name]
            for name, kind in {
                "name": str, "key": str, "readable_name": str,
                "label": str, "enabled": bool,
            }.items()
            if name in model and type(model[name]) is kind
        })
    result.setdefault("llm", {})["models"] = models
    quota = global_cfg.get("limits", {}).get("daily_summarize_quota")
    if type(quota) is int:
        result["limits"] = {"daily_summarize_quota": quota}
    return result


def load_session_secret(path=".session_secret"):
    """Use a private deployment key, independent of the formerly public config."""
    secret_path = Path(path)
    try:
        fd = os.open(secret_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    except FileExistsError:
        key = secret_path.read_text().strip()
        if len(key) < 64:
            raise RuntimeError("Invalid private session signing key")
        return key
    key = secrets.token_hex(32)
    with os.fdopen(fd, "w") as stream:
        stream.write(key + "\n")
    return key
