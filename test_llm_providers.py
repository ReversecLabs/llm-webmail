import json
import os
from pathlib import Path
import tempfile
from types import ModuleType
import unittest
from unittest.mock import Mock, patch

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
    def test_direct_openai_and_local_settings_are_preserved(self, create):
        for provider in ("openai", "llamacpp"):
            params = {"model": "test-model", "temperature": 1}
            create_chat_model({"provider": provider, "params": params})
            create.assert_called_with(**params)

    def test_existing_direct_provider_adapters_are_preserved(self):
        for provider, module_name, factory_name in (
            ("anthropic_bedrock", "langchain_aws", "ChatBedrock"),
            ("together", "langchain_together", "ChatTogether"),
            ("google", "langchain_google_genai", "ChatGoogleGenerativeAI"),
            ("ollama", "langchain_ollama", "ChatOllama"),
        ):
            module = ModuleType(module_name)
            factory = Mock()
            setattr(module, factory_name, factory)
            with patch.dict("sys.modules", {module_name: module}):
                create_chat_model({"provider": provider, "params": {"model": "test-model"}})
            factory.assert_called_once_with(model="test-model")

    def test_unknown_provider_does_not_silently_call_another_service(self):
        with self.assertRaisesRegex(ValueError, "Unsupported LLM provider"):
            create_chat_model({"provider": "unknown", "params": {}})

    def test_catalog_update_preserves_non_model_server_settings(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            config_path, catalog_path = root / "config.toml", root / "catalog.json"
            preserved = {"admin": {"username": "admin", "password": "synthetic-secret"}, "server": {"session_secret": "old-key"}, "limits": {"daily_summarize_quota": 123}}
            config_path.write_text(toml.dumps({**preserved, "llm": {"selected": "old"}}))
            catalog = {"selected": "new", "models": [{"name": "new", "enabled": True}]}
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


if __name__ == "__main__":
    unittest.main()
