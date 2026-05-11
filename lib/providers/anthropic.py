import os

from .base import Provider


DEFAULT_MODEL = "claude-sonnet-4-6"


class AnthropicProvider(Provider):
    name = "anthropic"

    def __init__(self, model: str | None = None, api_key: str | None = None):
        try:
            from anthropic import Anthropic
        except ImportError as e:
            raise RuntimeError(
                "anthropic SDK missing. Install with: pipx install anthropic "
                "or pip install anthropic"
            ) from e
        self.model = model or os.environ.get("VULN_SCAN_AGENT_MODEL") or DEFAULT_MODEL
        key = api_key or os.environ.get("ANTHROPIC_API_KEY")
        if not key:
            raise RuntimeError("ANTHROPIC_API_KEY is not set")
        self.client = Anthropic(api_key=key)

    def chat(self, system: str, history: list[dict], tools: list[dict],
             max_tokens: int = 4096) -> dict:
        # history is already in Anthropic content-block format; pass through.
        resp = self.client.messages.create(
            model=self.model,
            max_tokens=max_tokens,
            system=system,
            tools=tools,
            messages=history,
        )
        text = ""
        tool_calls: list[dict] = []
        raw_content: list[dict] = []
        for block in resp.content:
            if block.type == "text":
                text += block.text
                raw_content.append({"type": "text", "text": block.text})
            elif block.type == "tool_use":
                tool_calls.append({"id": block.id, "name": block.name, "input": block.input})
                raw_content.append({
                    "type": "tool_use",
                    "id": block.id,
                    "name": block.name,
                    "input": block.input,
                })
        return {
            "stop_reason": resp.stop_reason,
            "text": text,
            "tool_calls": tool_calls,
            "raw_content": raw_content,
        }
