import json
import os

from .base import Provider


DEFAULT_MODEL = "anthropic.claude-sonnet-4-20250514-v1:0"


class BedrockProvider(Provider):
    name = "bedrock"

    def __init__(self, model: str | None = None, region: str | None = None,
                 profile: str | None = None):
        try:
            import boto3
        except ImportError as e:
            raise RuntimeError(
                "boto3 missing. Install with: pipx install boto3 or pip install boto3"
            ) from e
        self.model = model or os.environ.get("VULN_SCAN_AGENT_MODEL") or DEFAULT_MODEL
        session_kwargs: dict = {}
        if profile or os.environ.get("AWS_PROFILE"):
            session_kwargs["profile_name"] = profile or os.environ["AWS_PROFILE"]
        if region or os.environ.get("AWS_REGION"):
            session_kwargs["region_name"] = region or os.environ["AWS_REGION"]
        self.session = boto3.Session(**session_kwargs)
        self.client = self.session.client("bedrock-runtime")

    def _to_bedrock(self, history: list[dict]) -> list[dict]:
        out = []
        for msg in history:
            content = msg["content"]
            if isinstance(content, str):
                blocks = [{"text": content}]
            else:
                blocks = []
                for b in content:
                    t = b.get("type")
                    if t == "text":
                        blocks.append({"text": b["text"]})
                    elif t == "tool_use":
                        blocks.append({"toolUse": {
                            "toolUseId": b["id"],
                            "name": b["name"],
                            "input": b["input"],
                        }})
                    elif t == "tool_result":
                        c = b["content"]
                        if isinstance(c, str):
                            inner = [{"text": c}]
                        else:
                            inner = c
                        blocks.append({"toolResult": {
                            "toolUseId": b["tool_use_id"],
                            "content": inner,
                        }})
            out.append({"role": msg["role"], "content": blocks})
        return out

    def chat(self, system: str, history: list[dict], tools: list[dict],
             max_tokens: int = 4096) -> dict:
        tool_config = {
            "tools": [
                {"toolSpec": {
                    "name": t["name"],
                    "description": t.get("description", ""),
                    "inputSchema": {"json": t["input_schema"]},
                }}
                for t in tools
            ]
        }
        resp = self.client.converse(
            modelId=self.model,
            system=[{"text": system}],
            messages=self._to_bedrock(history),
            toolConfig=tool_config,
            inferenceConfig={"maxTokens": max_tokens, "temperature": 0.1},
        )
        message = resp["output"]["message"]
        text = ""
        tool_calls: list[dict] = []
        raw_content: list[dict] = []
        for block in message["content"]:
            if "text" in block:
                text += block["text"]
                raw_content.append({"type": "text", "text": block["text"]})
            elif "toolUse" in block:
                tu = block["toolUse"]
                tool_calls.append({"id": tu["toolUseId"], "name": tu["name"], "input": tu["input"]})
                raw_content.append({
                    "type": "tool_use",
                    "id": tu["toolUseId"],
                    "name": tu["name"],
                    "input": tu["input"],
                })
        return {
            "stop_reason": resp.get("stopReason"),
            "text": text,
            "tool_calls": tool_calls,
            "raw_content": raw_content,
        }
