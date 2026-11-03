"""Talks to the local Ollama server (/api/chat) with tool calling."""

import httpx

from . import config


class LLMError(Exception):
    pass


def chat(messages: list[dict], tools: list[dict]) -> dict:
    """Send the conversation to Ollama and return the assistant message dict."""
    payload = {
        "model": config.OLLAMA_MODEL,
        "messages": messages,
        "tools": tools,
        "stream": False,
        "options": {"temperature": config.OLLAMA_TEMPERATURE},
    }
    try:
        r = httpx.post(f"{config.OLLAMA_URL}/api/chat", json=payload, timeout=config.OLLAMA_TIMEOUT)
        r.raise_for_status()
    except httpx.HTTPStatusError as e:
        raise LLMError(f"Ollama returned {e.response.status_code}: {e.response.text[:300]}") from e
    except httpx.HTTPError as e:
        raise LLMError(
            f"Could not reach Ollama at {config.OLLAMA_URL} ({e}). Is the Ollama app running?"
        ) from e
    return r.json().get("message", {})
