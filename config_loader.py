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