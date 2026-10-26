"""
Unified LLM client for OpenAI, Ollama, and OpenWebUI.

All three expose (or wrap) an OpenAI-compatible Chat Completions API,
so we use the official `openai` SDK with a configurable base_url.
"""

from __future__ import annotations

import logging
import os
from dataclasses import asdict, dataclass
from typing import Any, Dict, List, Optional

from openai import APIConnectionError, APIError, AuthenticationError, OpenAI, OpenAIError

logger = logging.getLogger(__name__)

SUPPORTED_PROVIDERS = ("openai", "ollama", "openwebui")

DEFAULT_MODELS = {
    "openai": "gpt-4o-mini",
    "ollama": "llama3.2",
    # Open WebUI model tags (override via DEFAULT_LLM_MODEL)
    "openwebui": os.getenv("DEFAULT_LLM_MODEL") or "Qwen/Qwen3.6-35B-A3B-FP8:latest",
}

DEFAULT_BASE_URLS = {
    "openai": "https://api.openai.com/v1",
    "ollama": os.getenv("OLLAMA_BASE_URL") or "http://127.0.0.1:11434/v1",
    # OpenAI-compatible surface is /api or /api/v1 (SDK appends /chat/completions)
    "openwebui": os.getenv("OPENWEBUI_BASE_URL") or "http://127.0.0.1:8080/api/v1",
}


class LLMError(Exception):
    """Raised when an LLM call fails in a user-facing way."""

    def __init__(self, message: str, *, code: str = "llm_error"):
        super().__init__(message)
        self.code = code


@dataclass
class LLMConfig:
    provider: str = "openai"
    model: str = ""
    api_key: str = ""
    base_url: str = ""
    temperature: float = 0.7
    max_tokens: int = 512
    timeout: float = 60.0

    def __post_init__(self) -> None:
        provider = (self.provider or "openai").strip().lower()
        if provider not in SUPPORTED_PROVIDERS:
            raise LLMError(
                f"Unsupported provider '{self.provider}'. "
                f"Choose one of: {', '.join(SUPPORTED_PROVIDERS)}",
                code="invalid_provider",
            )
        self.provider = provider
        if not self.model:
            self.model = DEFAULT_MODELS[self.provider]
        if not self.base_url:
            self.base_url = DEFAULT_BASE_URLS[self.provider]
        self.base_url = self.base_url.rstrip("/")
        self.temperature = _clamp_float(self.temperature, 0.0, 2.0, 0.7)
        self.max_tokens = int(_clamp_float(self.max_tokens, 16, 4096, 512))
        self.timeout = float(_clamp_float(self.timeout, 5.0, 180.0, 60.0))

        # Ollama accepts any non-empty key; default one keeps the SDK happy.
        if self.provider == "ollama" and not self.api_key:
            self.api_key = "ollama"

    def to_public_dict(self) -> Dict[str, Any]:
        """Serialize settings for the client without leaking full secrets."""
        data = asdict(self)
        key = data.get("api_key") or ""
        data["api_key_set"] = bool(key)
        data["api_key_masked"] = _mask_secret(key)
        data.pop("api_key", None)
        return data

    @classmethod
    def from_mapping(cls, data: Optional[Dict[str, Any]], defaults: Optional["LLMConfig"] = None) -> "LLMConfig":
        base = defaults or cls()
        raw = data or {}
        provider = str(raw.get("provider") or base.provider)
        api_key = raw.get("api_key")
        # Empty string from the client means "keep existing key".
        if api_key is None or api_key == "":
            api_key = base.api_key
        return cls(
            provider=provider,
            model=str(raw.get("model") or base.model or DEFAULT_MODELS.get(provider, "")),
            api_key=str(api_key or ""),
            base_url=str(raw.get("base_url") or base.base_url or DEFAULT_BASE_URLS.get(provider, "")),
            temperature=float(raw.get("temperature", base.temperature)),
            max_tokens=int(raw.get("max_tokens", base.max_tokens)),
            timeout=float(raw.get("timeout", base.timeout)),
        )


def _clamp_float(value: Any, low: float, high: float, fallback: float) -> float:
    try:
        number = float(value)
    except (TypeError, ValueError):
        return fallback
    return max(low, min(high, number))


def _mask_secret(secret: str) -> str:
    if not secret:
        return ""
    if len(secret) <= 8:
        return "*" * len(secret)
    return f"{secret[:3]}…{secret[-4:]}"


def _build_client(config: LLMConfig) -> OpenAI:
    if config.provider != "ollama" and not config.api_key:
        raise LLMError(
            f"API key required for provider '{config.provider}'. Configure it in Settings.",
            code="missing_api_key",
        )
    return OpenAI(
        api_key=config.api_key or "ollama",
        base_url=config.base_url,
        timeout=config.timeout,
        max_retries=1,
    )


def chat_completion(config: LLMConfig, system_prompt: str, user_prompt: str) -> str:
    """Send a single-turn chat completion and return the assistant text."""
    client = _build_client(config)
    try:
        completion = client.chat.completions.create(
            model=config.model,
            temperature=config.temperature,
            max_tokens=config.max_tokens,
            messages=[
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": user_prompt},
            ],
        )
    except AuthenticationError as exc:
        raise LLMError("Authentication failed. Check your API key in Settings.", code="auth_error") from exc
    except APIConnectionError as exc:
        raise LLMError(
            f"Could not reach {config.provider} at {config.base_url}. "
            "Verify the base URL and that the service is running.",
            code="connection_error",
        ) from exc
    except APIError as exc:
        raise LLMError(f"Provider error: {exc.message or str(exc)}", code="api_error") from exc
    except OpenAIError as exc:
        raise LLMError(f"LLM request failed: {exc}", code="openai_error") from exc

    choice = completion.choices[0].message.content if completion.choices else None
    if not choice:
        raise LLMError("The model returned an empty response.", code="empty_response")
    return choice


def list_models(config: LLMConfig) -> List[str]:
    """List models from the configured OpenAI-compatible provider."""
    client = _build_client(config)
    try:
        models = client.models.list()
        names = sorted({item.id for item in models.data if getattr(item, "id", None)})
        return names
    except AuthenticationError as exc:
        raise LLMError("Authentication failed while listing models. Check your API key.", code="auth_error") from exc
    except APIConnectionError as exc:
        raise LLMError(
            f"Could not reach {config.provider} at {config.base_url} to list models.",
            code="connection_error",
        ) from exc
    except APIError as exc:
        raise LLMError(f"Provider error listing models: {exc.message or str(exc)}", code="api_error") from exc
    except OpenAIError as exc:
        raise LLMError(f"Failed to list models: {exc}", code="openai_error") from exc
    except Exception as exc:  # noqa: BLE001
        logger.warning("list_models failed for %s: %s", config.provider, exc)
        raise LLMError(f"Failed to list models: {exc}", code="list_models_failed") from exc


def test_connection(config: LLMConfig) -> Dict[str, Any]:
    """Lightweight connectivity check used by the settings page."""
    try:
        reply = chat_completion(
            config,
            system_prompt="You are a connectivity probe. Reply with exactly: OK",
            user_prompt="ping",
        )
        return {
            "ok": True,
            "provider": config.provider,
            "model": config.model,
            "base_url": config.base_url,
            "reply": reply[:200],
        }
    except LLMError as exc:
        return {
            "ok": False,
            "provider": config.provider,
            "model": config.model,
            "base_url": config.base_url,
            "error": str(exc),
            "code": exc.code,
        }
