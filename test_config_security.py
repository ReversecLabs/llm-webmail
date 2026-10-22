"""Exercise real auth, SQLite and config routes without external model calls."""
import importlib.util
import json
import os
from pathlib import Path
import stat
import sys
import tempfile
from types import ModuleType
import unittest
from unittest.mock import Mock, patch

from flask import Flask
from flask.sessions import SecureCookieSessionInterface
import toml
from werkzeug.security import generate_password_hash, check_password_hash

ROOT = Path(__file__).resolve().parent
PASSWORD = "synthetic-admin-password"


def fixture_config():
    return {
        "admin": {"username": "course-admin", "password": PASSWORD},
        "server": {"session_secret": "formerly-disclosed-signing-key"},
        "llm": {"selected": "training-model", "models": [
            {"name": "training-model", "readable_name": "Training model", "enabled": True,
             "provider": "openai", "params": {"model": "test", "api_key": "synthetic-provider-secret"}},
            {"key": "second-model", "label": "Second model", "enabled": True,
             "params": {"api_key": "another-provider-secret"}},
            {"name": "disabled-model", "enabled": False},
        ]},
        "prompt_engineering": {"mode": "disabled"},
        "prompt_injection_filter": {"mode": "disabled"},
        "delimiter-filtering": {"mode": "disabled"},
        "logging": {"verbose": False},
        "limits": {"daily_summarize_quota": 20},
    }


class ConfigSecurityTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temp = tempfile.TemporaryDirectory()
        cls.addClassCleanup(cls.temp.cleanup)
        old_cwd = os.getcwd()
        os.chdir(cls.temp.name)
        cls.addClassCleanup(os.chdir, old_cwd)
        env = patch.dict(os.environ, {"WEBMAIL_DB": str(Path(cls.temp.name) / "data.db")})
        env.start()
        cls.addClassCleanup(env.stop)
        Path("config.toml").write_text(toml.dumps(fixture_config()))
        stubs = {}
        for name, exports in {
            "langchain_openai": ["ChatOpenAI"],
            "langchain_google_genai": ["ChatGoogleGenerativeAI"],
            "langchain_aws": ["ChatBedrock"],
            "langchain_together": ["ChatTogether"],
            "guardrails.meta_prompt_guard": ["meta_scan_for_injections"],
            "guardrails.azure_prompt_shields": ["azure_detect_prompt_injection"],
            "guardrails.aws_bedrock_guardrail": ["aws_detect_prompt_injection"],
        }.items():
            module = ModuleType(name)
            for export in exports:
                setattr(module, export, Mock())
            stubs[name] = module
        spec = importlib.util.spec_from_file_location("webmail_security_test_app", ROOT / "app.py")
        cls.module = importlib.util.module_from_spec(spec)
        with patch.dict(sys.modules, stubs), patch("dotenv.load_dotenv"):
            spec.loader.exec_module(cls.module)
        cls.app = cls.module.app
        cls.app.config["TESTING"] = True
        import db
        cls.db = db

    def setUp(self):
        # Older application helpers leave read connections open. Keep handles
        # alive until cleanup so the suite closes every real SQLite connection.
        connections = []
        original_get_conn = self.db.get_conn
        def tracked_connection():
            conn = original_get_conn()
            connections.append(conn)
            return conn
        connection_patch = patch.object(self.db, "get_conn", tracked_connection)
        connection_patch.start()
        self.addCleanup(connection_patch.stop)
        self.addCleanup(lambda: [conn.close() for conn in connections])
        from config_loader import save_config
        self.cfg = fixture_config()
        save_config(self.cfg)
        with self.db.get_conn() as conn:
            for table in ("user_configs", "signup_keys", "daily_usage", "users"):
                conn.execute(f"DELETE FROM {table}")
        self.db.ensure_admin("course-admin", PASSWORD)
        self.admin = self.db.get_user_by_username("course-admin")
        self.participant = self.db.create_user("participant", generate_password_hash("participant-password"), json.dumps(self.cfg))
        self.client = self.app.test_client()

    def sign_in(self, admin=False, **extras):
        with self.client.session_transaction() as session:
            session["uid"] = (self.admin if admin else self.participant)["id"]
            session.update(extras)

    def assert_public(self, response):
        self.assertEqual(response.status_code, 200)
        data = response.json.get("config", response.json)
        self.assertNotIn("admin", data)
        self.assertNotIn("server", data)
        for model in data["llm"]["models"]:
            self.assertNotIn("params", model)
            self.assertNotIn("provider", model)
        body = response.get_data(as_text=True)
        for secret in (PASSWORD, "formerly-disclosed-signing-key", "synthetic-provider-secret", "nested-secret"):
            self.assertNotIn(secret, body)
        return data

    def test_participant_get_excludes_credentials_and_provider_params(self):
        self.sign_in()
        data = self.assert_public(self.client.get("/api/config"))
        self.assertEqual(data["llm"]["models"][0], {
            "name": "training-model", "readable_name": "Training model", "enabled": True,
        })
        self.assertEqual(data["llm"]["models"][1]["key"], "second-model")
        self.assertEqual(data["limits"]["daily_summarize_quota"], 20)

    def test_missing_participant_config_has_safe_defaults(self):
        with self.db.get_conn() as conn:
            conn.execute("DELETE FROM user_configs WHERE user_id=?", (self.participant["id"],))
        self.sign_in()
        self.assertEqual(self.assert_public(self.client.get("/api/config"))["llm"]["selected"], "training-model")

    def test_legacy_snapshot_is_safe_before_and_after_scrubbing(self):
        legacy = fixture_config()
        legacy["logging"]["password"] = "nested-secret"
        with self.db.get_conn() as conn:
            conn.execute("UPDATE user_configs SET config_json=? WHERE user_id=?", (json.dumps(legacy), self.participant["id"]))
        self.sign_in()
        self.assert_public(self.client.get("/api/config"))
        before_hash = self.admin["password_hash"]
        self.db.create_keys(["preserved-signup-code"])
        self.db.inc_usage(self.participant["id"], self.db.get_today())
        self.db.scrub_user_configs()
        self.db.scrub_user_configs()
        with self.db.get_conn() as conn:
            stored = json.loads(conn.execute("SELECT config_json FROM user_configs WHERE user_id=?", (self.participant["id"],)).fetchone()[0])
        self.assertNotIn("admin", stored)
        self.assertNotIn("server", stored)
        self.assertEqual(stored["logging"], {"verbose": False})
        self.assertEqual(stored["llm"], {"selected": "training-model"})
        self.assertEqual(self.db.get_user_by_id(self.admin["id"])["password_hash"], before_hash)
        self.assertIsNotNone(self.db.get_key("preserved-signup-code"))
        self.assertEqual(self.db.get_usage(self.participant["id"], self.db.get_today()), 1)

    def test_participant_post_saves_controls_and_ignores_server_fields(self):
        self.sign_in()
        payload = fixture_config()
        payload["llm"]["selected"] = "second-model"
        payload["prompt_engineering"]["mode"] = "system+spotlighting"
        payload["logging"]["password"] = "nested-secret"
        payload["role"] = "admin"
        result = self.assert_public(self.client.post("/api/config", json=payload))
        self.assertEqual(result["llm"]["selected"], "second-model")
        self.assertEqual(result["prompt_engineering"]["mode"], "system+spotlighting")
        stored = self.db.get_user_config(self.participant["id"])
        self.assertEqual(stored["llm"], {"selected": "second-model"})
        self.assertEqual(stored["logging"], {"verbose": False})
        self.assertEqual(self.db.get_user_by_id(self.participant["id"])["role"], "user")
        from config_loader import load_config
        self.assertEqual(load_config(), self.cfg)

    def test_admin_training_updates_preserve_models_and_credentials(self):
        self.sign_in(admin=True)
        response = self.client.post("/api/config", json={
            "llm": {"selected": "second-model", "models": []},
            "admin": {"password": "not-accepted"}, "server": {"session_secret": "not-accepted"},
        })
        self.assert_public(response)
        from config_loader import load_config
        stored = load_config()
        self.assertEqual(stored["llm"]["models"], self.cfg["llm"]["models"])
        self.assertEqual(stored["admin"], self.cfg["admin"])
        self.assertEqual(stored["server"], self.cfg["server"])
        self.assertEqual(stored["llm"]["selected"], "second-model")
        self.assert_public(self.client.get("/api/config"))

    def test_model_allowlist_and_invalid_payloads(self):
        self.sign_in()
        for model in ("unknown-model", "disabled-model"):
            self.assertEqual(self.client.post("/api/config", json={"llm": {"selected": model}}).status_code, 400)
        self.assertEqual(self.client.post("/api/config", json=[]).status_code, 400)

    def test_nested_secrets_cannot_hide_in_allowed_fields(self):
        self.sign_in()
        response = self.client.post("/api/config", json={
            "llm": {"selected": {"password": "nested-secret"}},
            "logging": {"verbose": {"password": "nested-secret"}},
        })
        data = self.assert_public(response)
        self.assertEqual(data["llm"]["selected"], "training-model")
        self.assertEqual(data["logging"], {"verbose": False})

    def test_all_admin_routes_reject_participants(self):
        self.sign_in(role="admin", is_admin=True)
        for method, path in [
            ("GET", "/api/admin/config"), ("POST", "/api/admin/config"),
            ("GET", "/api/admin/users"), ("POST", "/api/admin/users/reset-password"),
            ("POST", "/api/admin/users/delete"), ("POST", "/api/admin/users/reset-quota"),
            ("GET", "/api/signup-keys"), ("POST", "/api/signup-keys"), ("POST", "/api/signup-keys/revoke"),
        ]:
            with self.subTest(path=path, method=method):
                self.assertEqual(self.client.open(path, method=method, json={}).status_code, 403)

    def test_anonymous_and_deleted_sessions_rejected(self):
        self.assertEqual(self.client.get("/api/config").status_code, 401)
        self.assertEqual(self.client.post("/api/config", json={}).status_code, 401)
        self.sign_in()
        with self.db.get_conn() as conn:
            conn.execute("DELETE FROM users WHERE id=?", (self.participant["id"],))
        self.assertEqual(self.client.get("/api/config").status_code, 401)
        self.assertEqual(self.client.get("/api/quota").status_code, 401)

    def test_disclosed_config_key_cannot_forge_admin_session(self):
        old = Flask("old-key")
        old.secret_key = self.cfg["server"]["session_secret"]
        cookie = SecureCookieSessionInterface().get_signing_serializer(old).dumps({"uid": self.admin["id"]})
        self.client.set_cookie("session", cookie)
        self.assertEqual(self.client.get("/api/config").status_code, 401)
        self.assertEqual(self.client.get("/api/admin/users").status_code, 401)

    def test_private_signing_key_is_persistent_and_restricted(self):
        from config_loader import load_session_secret
        self.assertEqual(load_session_secret(), self.app.secret_key)
        self.assertNotEqual(self.app.secret_key, self.cfg["server"]["session_secret"])
        self.assertGreaterEqual(len(self.app.secret_key), 64)
        self.assertEqual(stat.S_IMODE(Path(".session_secret").stat().st_mode), 0o600)

    def test_admin_login_and_signup_code_registration_still_work(self):
        response = self.client.post("/api/login", json={"username": "course-admin", "password": PASSWORD})
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json["role"], "admin")
        self.assertEqual(self.client.get("/api/admin/config").status_code, 200)
        response = self.client.post("/api/signup-keys", json={"count": 1})
        self.assertEqual(response.status_code, 200)
        key = response.json["tokens"][0]
        self.client.post("/api/logout")
        response = self.client.post("/api/register", json={
            "username": "new-participant", "password": "participant-password", "key": key, "role": "admin",
        })
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json["role"], "user")
        self.assert_public(self.client.get("/api/config"))
        with self.db.get_conn() as conn:
            stored = json.loads(conn.execute("SELECT config_json FROM user_configs WHERE user_id=(SELECT id FROM users WHERE username=?)", ("new-participant",)).fetchone()[0])
        self.assertNotIn("admin", stored)
        self.assertNotIn("server", stored)
        self.assertNotIn("models", stored["llm"])
        self.assertEqual(self.client.post("/api/register", json={"username": "reuse", "password": "pw", "key": key}).status_code, 400)
        self.assertTrue(check_password_hash(self.db.get_user_by_username("course-admin")["password_hash"], PASSWORD))

    def test_registration_rejects_invalid_and_revoked_codes(self):
        self.assertEqual(self.client.post("/api/register", json={"username": "bad", "password": "pw", "key": "missing"}).status_code, 400)
        self.db.create_keys(["revoked-code"])
        self.db.revoke_key("revoked-code")
        self.assertEqual(self.client.post("/api/register", json={"username": "bad", "password": "pw", "key": "revoked-code"}).status_code, 400)


if __name__ == "__main__":
    unittest.main()
