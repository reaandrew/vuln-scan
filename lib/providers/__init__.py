"""Provider abstraction for LLM backends used by enrich.py and agent.py.

All providers implement a single normalised method:

    chat(system: str, history: list[dict], tools: list[dict], max_tokens: int)
      -> dict with keys: stop_reason, text, tool_calls (list of
         {id, name, input}), raw_content (provider-native blocks for
         appending to history).

The history shape matches Anthropic's content-block format so we can
round-trip tool_use / tool_result blocks losslessly. Bedrock and Ollama
adapters translate to/from that shape.
"""
from .base import Provider
from .anthropic import AnthropicProvider
from .bedrock import BedrockProvider
from .ollama import OllamaProvider


def get_provider(name: str, **kwargs) -> Provider:
    name = (name or "").lower()
    if name in ("anthropic", "api"):
        return AnthropicProvider(**kwargs)
    if name == "bedrock":
        return BedrockProvider(**kwargs)
    if name == "ollama":
        return OllamaProvider(**kwargs)
    raise ValueError(f"unknown provider: {name!r} (use anthropic | bedrock | ollama)")
