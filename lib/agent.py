#!/usr/bin/env python3
"""Agentic security auditor: an LLM with a small, bounded toolbox.

Reads the report.json produced by the static scanners, lists the file
tree, and asks the model to audit the files that the scanners *didn't*
flag — looking for any of the eight vuln classes. The model can read
files, regex-search, and record findings via tools. Tool inputs and
outputs are all confined to the scan directory.

Findings recorded by the agent are appended to report.json under a
tool name like `agent:anthropic:claude-sonnet-4-6`. A separate
agent-trace.json captures the model's narration.
"""
from __future__ import annotations

import argparse
import fnmatch
import json
import os
import subprocess
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))
from providers import get_provider  # noqa: E402


SYSTEM_PROMPT = """You are a security analyst auditing a codebase.

You have a small toolbox:
- list_files(path, glob)       — list files in a directory under the scan root
- read_file(path, start_line, end_line) — read a file or a chunk of it
- search_code(pattern, glob)   — regex search across files (uses grep -E)
- record_finding(...)          — record a vulnerability you've identified
- finish(reason)               — declare you're done

Vulnerability classes you should look for:
- injection         SQL / Command / Code / XSS / XXE / ReDoS
- path_network     path traversal / SSRF / open redirect
- auth_access      authn bypass / IDOR / CSRF / race conditions
- memory_safety    buffer overflow / UAF / unsafe casts
- cryptography     weak primitive / timing / alg confusion / hardcoded key
- deserialization  pickle / yaml.load / readObject / unserialize
- protocol_encoding cache poisoning / encoding confusion / length-prefix
- secrets          credentials in code

You will receive:
1. The scan root path
2. A list of files in the repo
3. A list of files the automatic scanners ALREADY flagged

Your job is to audit the files the scanners DID NOT flag, find any of
the eight classes above, and call record_finding for each. Don't repeat
existing findings. When you've audited what looks important, call
finish.

Be conservative — only record a finding when you can point at the exact
line and explain why. Skip files that are tests, fixtures, vendor code,
generated code, or third-party libraries.
"""


TOOLS = [
    {
        "name": "list_files",
        "description": "List files and directories under a relative path inside the scan root. Returns up to 200 entries.",
        "input_schema": {
            "type": "object",
            "properties": {
                "path": {"type": "string", "description": "Path relative to the scan root. Use '.' for root."},
                "glob": {"type": "string", "description": "Optional glob, e.g. '*.py'."},
            },
            "required": ["path"],
        },
    },
    {
        "name": "read_file",
        "description": "Read a file (or a chunk by line range). Lines are 1-indexed; max 300 lines per call.",
        "input_schema": {
            "type": "object",
            "properties": {
                "path": {"type": "string"},
                "start_line": {"type": "integer", "default": 1},
                "end_line": {"type": "integer", "default": 300},
            },
            "required": ["path"],
        },
    },
    {
        "name": "search_code",
        "description": "Regex search across files using grep -E. Returns up to 100 matching lines with file:line prefixes.",
        "input_schema": {
            "type": "object",
            "properties": {
                "pattern": {"type": "string"},
                "glob": {"type": "string", "description": "File-name glob to restrict the search (default '*')."},
            },
            "required": ["pattern"],
        },
    },
    {
        "name": "record_finding",
        "description": "Record a vulnerability you've confirmed in the code. Include line number, category, and a concise message.",
        "input_schema": {
            "type": "object",
            "properties": {
                "file": {"type": "string"},
                "line": {"type": "integer"},
                "category": {
                    "type": "string",
                    "enum": [
                        "injection", "path_network", "auth_access", "memory_safety",
                        "cryptography", "deserialization", "protocol_encoding", "secrets",
                    ],
                },
                "severity": {"type": "string", "enum": ["critical", "high", "medium", "low"]},
                "rule_id": {"type": "string", "description": "Short identifier for the finding class, e.g. 'sql-concat'."},
                "message": {"type": "string"},
                "snippet": {"type": "string", "description": "The exact line or lines that demonstrate the issue."},
                "cwe": {"type": "array", "items": {"type": "string"}, "description": "Optional CWE IDs e.g. ['CWE-89']."},
            },
            "required": ["file", "line", "category", "severity", "message"],
        },
    },
    {
        "name": "finish",
        "description": "Signal you're done auditing.",
        "input_schema": {
            "type": "object",
            "properties": {"reason": {"type": "string"}},
            "required": ["reason"],
        },
    },
]


IGNORE_DIR_NAMES = {".git", "node_modules", "vendor", ".venv", "__pycache__", "dist", "build"}


class Agent:
    def __init__(self, scan_dir: Path, provider, max_steps: int = 40):
        self.scan_dir = scan_dir.resolve()
        self.provider = provider
        self.max_steps = max_steps
        self.findings: list[dict] = []
        self.trace: list[dict] = []
        self.finished_reason: str | None = None

    # ── Tool guards ────────────────────────────────────────────────────
    def _safe_path(self, rel: str) -> Path | None:
        # Reject anything that resolves outside scan_dir.
        try:
            p = (self.scan_dir / rel).resolve()
        except Exception:
            return None
        if self.scan_dir != p and self.scan_dir not in p.parents:
            return None
        return p

    # ── Tools ──────────────────────────────────────────────────────────
    def tool_list_files(self, path: str, glob: str | None = None) -> str:
        p = self._safe_path(path)
        if not p or not p.exists() or not p.is_dir():
            return f"Not a directory: {path}"
        out = []
        for item in sorted(p.iterdir()):
            if item.name in IGNORE_DIR_NAMES:
                continue
            if glob and not fnmatch.fnmatch(item.name, glob):
                continue
            mark = "/" if item.is_dir() else " "
            out.append(f"{mark} {item.relative_to(self.scan_dir)}")
            if len(out) >= 200:
                out.append("... (truncated)")
                break
        return "\n".join(out) or "(empty)"

    def tool_read_file(self, path: str, start_line: int = 1, end_line: int = 300) -> str:
        p = self._safe_path(path)
        if not p or not p.is_file():
            return f"Not a file: {path}"
        try:
            lines = p.read_text(encoding="utf-8", errors="replace").splitlines()
        except Exception as e:
            return f"Error reading {path}: {e}"
        s = max(1, int(start_line))
        e = min(len(lines), int(end_line))
        if e - s > 300:
            e = s + 300
        if s > len(lines):
            return f"File has only {len(lines)} lines."
        return "\n".join(f"{i + 1:5d}  {lines[i]}" for i in range(s - 1, e))

    def tool_search_code(self, pattern: str, glob: str = "*") -> str:
        # Bound runtime; refuse very broad regexes.
        if len(pattern) < 2:
            return "Pattern too short."
        try:
            r = subprocess.run(
                ["grep", "-rnIE", "--include", glob,
                 "--exclude-dir=.git", "--exclude-dir=node_modules",
                 "--exclude-dir=vendor", "--exclude-dir=.venv",
                 pattern, str(self.scan_dir)],
                capture_output=True, text=True, timeout=30,
            )
        except subprocess.TimeoutExpired:
            return "Search timed out (30s)."
        except Exception as e:
            return f"Error: {e}"
        lines = r.stdout.splitlines()[:100]
        if not lines:
            return "No matches."
        prefix = str(self.scan_dir) + os.sep
        return "\n".join(
            ln.removeprefix(prefix) for ln in lines
        )

    def tool_record_finding(self, **kw) -> str:
        # Light validation
        file_ = kw.get("file") or ""
        if not self._safe_path(file_):
            return f"Refused: file '{file_}' is outside scan root."
        finding = {
            "file": file_,
            "line_start": int(kw.get("line") or 0),
            "line_end": int(kw.get("line") or 0),
            "category": kw.get("category") or "uncategorized",
            "severity": kw.get("severity") or "medium",
            "rule_id": kw.get("rule_id") or "agent",
            "message": (kw.get("message") or "").strip(),
            "snippet": (kw.get("snippet") or "").strip()[:500],
            "cwe": kw.get("cwe") or [],
        }
        self.findings.append(finding)
        return f"Recorded: {finding['category']} ({finding['severity']}) in {file_}:{finding['line_start']}"

    # ── Loop ──────────────────────────────────────────────────────────
    def execute(self, name: str, args: dict) -> str:
        try:
            if name == "list_files":
                return self.tool_list_files(args.get("path", "."), args.get("glob"))
            if name == "read_file":
                return self.tool_read_file(
                    args["path"],
                    int(args.get("start_line", 1) or 1),
                    int(args.get("end_line", 300) or 300),
                )
            if name == "search_code":
                return self.tool_search_code(args["pattern"], args.get("glob", "*"))
            if name == "record_finding":
                return self.tool_record_finding(**args)
            return f"Unknown tool: {name}"
        except Exception as e:
            return f"Tool error: {e}"

    def run(self, initial_user_msg: str) -> None:
        history: list[dict] = [{"role": "user", "content": initial_user_msg}]
        for step in range(self.max_steps):
            try:
                resp = self.provider.chat(SYSTEM_PROMPT, history, TOOLS)
            except Exception as e:
                self.trace.append({"step": step, "error": str(e)})
                break
            self.trace.append({"step": step, "text": resp.get("text", "")[:1000]})
            history.append({"role": "assistant", "content": resp["raw_content"]})
            tool_calls = resp.get("tool_calls", [])
            if not tool_calls:
                break
            tool_results: list[dict] = []
            for tc in tool_calls:
                if tc["name"] == "finish":
                    self.finished_reason = tc["input"].get("reason", "")
                    return
                result = self.execute(tc["name"], tc["input"] or {})
                tool_results.append({
                    "type": "tool_result",
                    "tool_use_id": tc["id"],
                    "content": str(result)[:6000],
                })
            history.append({"role": "user", "content": tool_results})


def build_initial_context(scan_dir: Path, report: dict) -> str:
    # File tree, depth-limited, top 200
    files = []
    for root, dirs, names in os.walk(scan_dir):
        dirs[:] = [d for d in dirs if d not in IGNORE_DIR_NAMES]
        for n in names:
            rel = Path(root).joinpath(n).relative_to(scan_dir)
            files.append(str(rel))
            if len(files) >= 200:
                break
        if len(files) >= 200:
            break
    files.sort()

    existing = report.get("findings", [])
    files_with = sorted({f["file"] for f in existing if f.get("file")})

    return (
        f"Scan root: {scan_dir}\n\n"
        f"Files in repo (first 200):\n"
        + "\n".join(files)
        + f"\n\nAutomatic scanners already produced {len(existing)} findings, "
          f"covering {len(files_with)} files:\n"
        + "\n".join(files_with[:200])
        + ("\n... (truncated)\n" if len(files_with) > 200 else "\n")
        + "\nAudit the OTHER files. Record findings via record_finding(), "
          "then call finish() when done."
    )


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--scan-dir", required=True)
    ap.add_argument("--report", required=True)
    ap.add_argument("--provider", default=os.environ.get("VULN_SCAN_AGENT_PROVIDER", "anthropic"))
    ap.add_argument("--model", default=None)
    ap.add_argument("--max-steps", type=int, default=40)
    ap.add_argument("--bedrock-region", default=None)
    ap.add_argument("--bedrock-profile", default=None)
    ap.add_argument("--ollama-host", default=None)
    args = ap.parse_args()

    pkwargs: dict = {}
    if args.model:
        pkwargs["model"] = args.model
    if args.provider == "bedrock":
        if args.bedrock_region:
            pkwargs["region"] = args.bedrock_region
        if args.bedrock_profile:
            pkwargs["profile"] = args.bedrock_profile
    if args.provider == "ollama" and args.ollama_host:
        pkwargs["host"] = args.ollama_host

    try:
        provider = get_provider(args.provider, **pkwargs)
    except Exception as e:
        print(f"[agent] failed to init provider: {e}", file=sys.stderr)
        return 2

    report_path = Path(args.report)
    report = json.loads(report_path.read_text())
    scan_dir = Path(args.scan_dir)

    initial = build_initial_context(scan_dir, report)
    print(f"[agent] provider={provider.name} model={provider.model} max_steps={args.max_steps}",
          file=sys.stderr)

    agent = Agent(scan_dir, provider, max_steps=args.max_steps)
    agent.run(initial)

    tool_label = f"agent:{provider.name}:{provider.model}"
    for f in agent.findings:
        f["tool"] = tool_label

    report.setdefault("findings", []).extend(agent.findings)
    summary = report.setdefault("summary", {})
    summary["total_findings"] = len(report["findings"])
    summary["agent_findings"] = len(agent.findings)
    summary["agent_steps"] = len(agent.trace)
    summary["agent_provider"] = provider.name
    summary["agent_model"] = provider.model

    # Recompute by_category / by_tool
    by_cat: dict[str, int] = {}
    by_tool: dict[str, int] = {}
    for f in report["findings"]:
        by_cat[f["category"]] = by_cat.get(f["category"], 0) + 1
        by_tool[f["tool"]] = by_tool.get(f["tool"], 0) + 1
    summary["by_category"] = by_cat
    summary["by_tool"] = by_tool

    report_path.write_text(json.dumps(report, indent=2))
    (report_path.parent / "agent-trace.json").write_text(
        json.dumps({
            "provider": provider.name,
            "model": provider.model,
            "finished_reason": agent.finished_reason,
            "trace": agent.trace,
        }, indent=2)
    )

    print(f"[agent] {len(agent.findings)} new findings in {len(agent.trace)} steps "
          f"(stop: {agent.finished_reason or 'no-finish'})", file=sys.stderr)
    return 0


if __name__ == "__main__":
    sys.exit(main())
