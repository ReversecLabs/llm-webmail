import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

import toml

from llm_providers import create_chat_model, create_openrouter_chat_model
from scripts.update_models import apply_model_catalog


class ProviderTests(unittest.TestCase):
    @patch("llm_providers.ChatOpenAI")
    def test_openrouter_uses_environment_key_and_webmail_attribution(self, create):
        with patch.dict(os.environ, {"OPENROUTER_API_KEY": "synthetic-key"}, clear=True):
            create_chat_model({"provider": "openrouter", "params": {"model": "test/model", "max_retries": 2}})
        create.assert_called_once_with(
            api_key="synthetic-key", base_url="https://openrouter.ai/api/v1",
            default_headers={"X-OpenRouter-Title": "LLM Webmail", "HTTP-Referer": "https://llmwebmail.fs-playground.com/"},
            model="test/model", max_retries=2,
        )

    def test_missing_openrouter_key_is_explicit(self):
        with patch.dict(os.environ, {}, clear=True):
            with self.assertRaisesRegex(RuntimeError, "OPENROUTER_API_KEY"):
                create_openrouter_chat_model({"model": "test/model"})

    @patch("llm_providers.ChatOpenAI")
    def test_direct_provider_routes_are_rejected(self, create):
        for provider in ("openai", "llamacpp", "anthropic_bedrock", "together", "google", "ollama"):
            with self.subTest(provider=provider), self.assertRaisesRegex(ValueError, "Unsupported LLM provider"):
                create_chat_model({"provider": provider, "params": {"model": "old-model"}})
        create.assert_not_called()

    @patch("llm_providers.ChatOpenAI")
    def test_luna_tool_call_setting_is_forwarded(self, create):
        with patch.dict(os.environ, {"OPENROUTER_API_KEY": "synthetic-key"}, clear=True):
            create_chat_model({"provider": "openrouter", "params": {"model": "openai/gpt-6-luna", "reasoning_effort": "none"}})
        self.assertEqual(create.call_args.kwargs["reasoning_effort"], "none")

    def test_release_catalog_contains_only_the_thirteen_openrouter_models(self):
        root = Path(__file__).resolve().parent
        catalog = json.loads((root / "model_catalog.json").read_text())
        models = catalog["models"]
        self.assertEqual(len(models), 13)
        self.assertEqual(len({m["name"] for m in models}), 13)
        self.assertTrue(all(m["provider"] == "openrouter" and m["enabled"] for m in models))
        self.assertTrue(all("openrouter" not in m["readable_name"].lower() for m in models))
        self.assertIn(catalog["selected"], {m["name"] for m in models})
        self.assertEqual([m["params"]["model"] for m in models if m["params"]["model"].startswith("openai/")], ["openai/gpt-6-luna", "openai/gpt-oss-120b"])
        self.assertEqual(next(m["params"]["reasoning_effort"] for m in models if m["params"]["model"] == "openai/gpt-6-luna"), "none")

    def test_unknown_provider_does_not_silently_call_another_service(self):
        with self.assertRaisesRegex(ValueError, "Unsupported LLM provider"):
            create_chat_model({"provider": "unknown", "params": {}})

    def test_catalog_update_preserves_non_model_server_settings(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            config_path, catalog_path = root / "config.toml", root / "catalog.json"
            preserved = {"admin": {"username": "admin", "password": "synthetic-secret"}, "server": {"session_secret": "old-key"}, "limits": {"daily_summarize_quota": 123}}
            config_path.write_text(toml.dumps({**preserved, "llm": {"selected": "old"}}))
            catalog = {"selected": "new", "models": [{"name": "new", "provider": "openrouter", "enabled": True}]}
            catalog_path.write_text(json.dumps(catalog))
            self.assertEqual(apply_model_catalog(config_path, catalog_path), 1)
            actual = toml.load(config_path)
            self.assertEqual(actual.pop("llm"), catalog)
            self.assertEqual(actual, preserved)
            catalog["selected"] = "unavailable"
            catalog_path.write_text(json.dumps(catalog))
            with self.assertRaisesRegex(ValueError, "default model"):
                apply_model_catalog(config_path, catalog_path)
            self.assertEqual(toml.load(config_path)["llm"]["selected"], "new")
            catalog["selected"] = "new"
            catalog["models"][0]["provider"] = "openai"
            catalog_path.write_text(json.dumps(catalog))
            with self.assertRaisesRegex(ValueError, "must use OpenRouter"):
                apply_model_catalog(config_path, catalog_path)
            self.assertEqual(toml.load(config_path)["llm"], {"selected": "new", "models": [{"name": "new", "provider": "openrouter", "enabled": True}]})


if __name__ == "__main__":
    unittest.main()
