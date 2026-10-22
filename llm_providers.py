"""Create chat models using server-owned provider settings and environment keys."""
import os

from langchain_openai import ChatOpenAI

OPENROUTER_BASE_URL = "https://openrouter.ai/api/v1"


def create_openrouter_chat_model(params):
    api_key = os.getenv("OPENROUTER_API_KEY")
    if not api_key:
        raise RuntimeError("OPENROUTER_API_KEY is required for OpenRouter models")
    headers = {
        "X-OpenRouter-Title": os.getenv("OPENROUTER_APP_NAME", "LLM Webmail"),
        "HTTP-Referer": os.getenv("OPENROUTER_SITE_URL", "https://llmwebmail.fs-playground.com/"),
    }
    return ChatOpenAI(
        api_key=api_key,
        base_url=OPENROUTER_BASE_URL,
        default_headers=headers,
        **params,
    )


def create_chat_model(model_config):
    provider = model_config.get("provider")
    params = model_config.get("params", {})
    if provider == "openrouter":
        return create_openrouter_chat_model(params)
    if provider in ("openai", "llamacpp"):
        return ChatOpenAI(**params)
    if provider == "anthropic_bedrock":
        from langchain_aws import ChatBedrock
        return ChatBedrock(**params)
    if provider == "together":
        from langchain_together import ChatTogether
        return ChatTogether(**params)
    if provider == "google":
        from langchain_google_genai import ChatGoogleGenerativeAI
        return ChatGoogleGenerativeAI(**params)
    if provider == "ollama":
        from langchain_ollama import ChatOllama
        return ChatOllama(**params)
    raise ValueError(f"Unsupported LLM provider: {provider}")
