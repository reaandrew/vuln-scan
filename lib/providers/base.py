from __future__ import annotations


class Provider:
    name: str = "base"
    model: str = ""

    def chat(self, system: str, history: list[dict], tools: list[dict],
             max_tokens: int = 4096) -> dict:
        raise NotImplementedError
