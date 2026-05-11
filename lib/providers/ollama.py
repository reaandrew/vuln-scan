import json
import os
import urllib.request

from .base import Provider


DEFAULT_MODEL = "qwen2.5:7b"


class OllamaProvider(Provider):
    name = "ollama"

    def __init__(self, model: str | None = None, host: str | None = None):
        self.model = model or os.environ.get("VULN_SCAN_AGENT_MODEL") or DEFAULT_MODEL
        self.host = host or os.environ.get("OLLAMA_HOST") or "http://localhost:11434"

    def _to_ollama_messages(self, system: str, history: list[dict]) -> list[dict]:
        out = [{"role": "system", "content": system}]
        for msg in history:
            content = msg["content"]
            if isinstance(content, str):
                out.append({"role": msg["role"], "content": content})
                continue
            # Anthropic-style blocks → Ollama tool_calls / text
            text_parts = []
            tool_calls = []
            tool_results = []
            for b in content:
                t = b.get("type")
                if t == "text":
                    text_parts.append(b["text"])
                elif t == "tool_use":
                    tool_calls.append({
                        "function": {"name": b["name"], "arguments": b["input"]}
                    })
                elif t == "tool_result":
                    c = b["content"]
                    text = c if isinstance(c, str) else " ".join(
                        (i.get("text") or "") for i in c if isinstance(i, dict)
                    )
                    tool_results.append({
                        "role": "tool",
                        "content": text,
                    })
            if tool_calls or text_parts:
                m = {"role": msg["role"], "content": "\n".join(text_parts)}
                if tool_calls:
                    m["tool_calls"] = tool_calls
                out.append(m)
            for tr in tool_results:
                out.append(tr)
        return out

    def chat(self, system: str, history: list[dict], tools: list[dict],
             max_tokens: int = 4096) -> dict:
        ollama_tools = [
            {"type": "function", "function": {
                "name": t["name"],
                "description": t.get("description", ""),
                "parameters": t["input_schema"],
            }}
            for t in tools
        ]
        body = json.dumps({
            "model": self.model,
            "messages": self._to_ollama_messages(system, history),
            "tools": ollama_tools,
            "stream": False,
            "options": {"temperature": 0.1, "num_predict": max_tokens},
        }).encode()
        req = urllib.request.Request(
            f"{self.host}/api/chat",
            data=body,
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        with urllib.request.urlopen(req, timeout=300) as r:
            resp = json.loads(r.read())
        msg = resp.get("message", {})
        text = msg.get("content", "") or ""
        tool_calls = []
        raw_content = []
        if text:
            raw_content.append({"type": "text", "text": text})
        for i, tc in enumerate(msg.get("tool_calls") or []):
            fn = tc.get("function", {})
            tool_id = f"call_{i}"
            args = fn.get("arguments") or {}
            tool_calls.append({"id": tool_id, "name": fn.get("name", ""), "input": args})
            raw_content.append({
                "type": "tool_use", "id": tool_id,
                "name": fn.get("name", ""), "input": args,
            })
        return {
            "stop_reason": resp.get("done_reason"),
            "text": text,
            "tool_calls": tool_calls,
            "raw_content": raw_content,
        }
