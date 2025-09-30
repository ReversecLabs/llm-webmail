import sqlite3, os, pathlib, datetime, hashlib
from werkzeug.security import generate_password_hash
import json

DB_PATH = os.environ.get("WEBMAIL_DB", "data.db")
_path = pathlib.Path(DB_PATH)

SCHEMA = """
PRAGMA journal_mode=WAL;
CREATE TABLE IF NOT EXISTS users (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  username TEXT UNIQUE NOT NULL,
  password_hash TEXT NOT NULL,
  role TEXT NOT NULL CHECK(role IN ('admin','user'))
);
CREATE TABLE IF NOT EXISTS signup_keys (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  token TEXT UNIQUE NOT NULL,
  used_by_user_id INTEGER,
  revoked INTEGER NOT NULL DEFAULT 0,
  created_at TEXT NOT NULL,
  FOREIGN KEY (used_by_user_id) REFERENCES users(id)
);
CREATE TABLE IF NOT EXISTS daily_usage (
  user_id INTEGER NOT NULL,
  date TEXT NOT NULL,
  used_count INTEGER NOT NULL DEFAULT 0,
  PRIMARY KEY (user_id, date),
  FOREIGN KEY (user_id) REFERENCES users(id)
);
CREATE TABLE IF NOT EXISTS user_configs (
  user_id INTEGER PRIMARY KEY,
  config_json TEXT NOT NULL,
  FOREIGN KEY (user_id) REFERENCES users(id)
);
"""

def get_conn():
    need_init = not _path.exists()
    conn = sqlite3.connect(DB_PATH, check_same_thread=False)
    conn.row_factory = sqlite3.Row
    if need_init:
        conn.executescript(SCHEMA)
        conn.commit()
    return conn

def ensure_admin(admin_username: str, cleartext_password: str):
    final_hash = generate_password_hash(cleartext_password)
    conn = get_conn()
    try:
        conn.execute(
            """
            INSERT INTO users (username, password_hash, role)
            VALUES (?, ?, 'admin')
            ON CONFLICT(username) DO UPDATE SET
                password_hash=excluded.password_hash,
                role='admin'
            """,
            (admin_username, final_hash),
        )
        conn.commit()
    finally:
        conn.close()

# Users
def get_user_by_username(username):
    return get_conn().execute("SELECT * FROM users WHERE username=?", (username,)).fetchone()

def get_user_by_id(uid):
    return get_conn().execute("SELECT * FROM users WHERE id=?", (uid,)).fetchone()

def create_user(username, password_hash, initial_config_json=None):
    """
    Creates user and optionally creates a default user_config row.
    initial_config_json: JSON string (str) or None.
    Returns the user row.
    """
    conn = get_conn()
    conn.execute(
        "INSERT INTO users (username, password_hash, role) VALUES (?,?,?)",
        (username, password_hash, "user"),
    )
    conn.commit()
    row = conn.execute("SELECT * FROM users WHERE username=?", (username,)).fetchone()
    if initial_config_json is not None:
        conn.execute(
            "INSERT OR REPLACE INTO user_configs (user_id, config_json) VALUES (?,?)",
            (row["id"], initial_config_json),
        )
        conn.commit()
    conn.close()
    return row

# User config helpers
def get_user_config(user_id):
    r = get_conn().execute("SELECT config_json FROM user_configs WHERE user_id=?", (user_id,)).fetchone()
    return json.loads(r["config_json"]) if r else None

def set_user_config(user_id, cfg_dict):
    j = json.dumps(cfg_dict)
    conn = get_conn()
    conn.execute("INSERT OR REPLACE INTO user_configs (user_id, config_json) VALUES (?,?)", (user_id, j))
    conn.commit()
    conn.close()

# Signup keys
def create_keys(tokens):
    conn = get_conn()
    now = datetime.datetime.now().isoformat()
    conn.executemany(
        "INSERT INTO signup_keys (token, created_at) VALUES (?,?)",
        [(t, now) for t in tokens],
    )
    conn.commit()
    conn.close()

def list_keys():
    return get_conn().execute(
        """
        SELECT token, revoked, created_at,
               (SELECT username FROM users u WHERE u.id = s.used_by_user_id) AS used_by
        FROM signup_keys s ORDER BY id DESC
        """
    ).fetchall()

def get_key(token):
    return get_conn().execute(
        "SELECT * FROM signup_keys WHERE token=?", (token,)
    ).fetchone()

def mark_key_used(token, user_id):
    conn = get_conn()
    conn.execute(
        "UPDATE signup_keys SET used_by_user_id=? WHERE token=?",
        (user_id, token),
    )
    conn.commit()
    conn.close()

def revoke_key(token):
    conn = get_conn()
    conn.execute("UPDATE signup_keys SET revoked=1 WHERE token=?", (token,))
    conn.commit()
    conn.close()

# Usage
def get_today():
    return datetime.date.today().isoformat()

def get_usage(user_id, date):
    row = get_conn().execute(
        "SELECT used_count FROM daily_usage WHERE user_id=? AND date=?",
        (user_id, date),
    ).fetchone()
    return row[0] if row else 0

def inc_usage(user_id, date):
    conn = get_conn()
    cur = conn.execute(
        "SELECT used_count FROM daily_usage WHERE user_id=? AND date=?",
        (user_id, date),
    ).fetchone()
    if cur:
        conn.execute(
            "UPDATE daily_usage SET used_count=used_count+1 WHERE user_id=? AND date=?",
            (user_id, date),
        )
    else:
        conn.execute(
            "INSERT INTO daily_usage (user_id, date, used_count) VALUES (?,?,1)",
            (user_id, date),
        )
    conn.commit()
    conn.close()
