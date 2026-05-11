#!/usr/bin/env python3
"""Enrich vuln-scan findings through a local LLM via the Ollama HTTP API.

For each finding in report.json:
  1. Build a tight prompt with vuln taxonomy + the finding + ±5 lines of
     surrounding source.
  2. POST to Ollama with format=json so output is constrained.
  3. Parse {false_positive_likelihood, plain_english, remediation, category_override}.
  4. Merge into the finding as `enrichment`, then rewrite report.json
     and append a triage section to report.md.

Cache: keyed by (model, rule_id, file, sha256(snippet)) so re-runs are
near-instant. Cache lives at $XDG_CACHE_HOME/vuln-scan/enrich.json (or
~/.cache/vuln-scan/enrich.json).
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import sys
import urllib.request
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path

TAXONOMY = """\
Vulnerability classes (use one of these as `category_override` if you
disagree with the existing label, else leave it empty):
- injection: SQL/Command/Code/XSS/XXE/ReDoS
- path_network: path traversal, SSRF, open redirect
- auth_access: authn bypass, IDOR/BOLA, CSRF, race
- memory_safety: buffer/integer overflow, UAF
- cryptography: weak primitive, timing leak, alg confusion
- deserialization: pickle/yaml/readObject
- protocol_encoding: cache, encoding confusion, length-prefix
- secrets: credentials in code
- dependency: vulnerable library
- iac_misconfiguration: terraform/k8s/dockerfile/cfn issue
"""

PROMPT_TEMPLATE = """\
You are a security triage assistant. Given one finding from a static
analyser plus the surrounding code, decide if it's a real issue or a
false positive, and produce a short plain-English explanation tied to
the code shown.

{taxonomy}

Finding:
  tool        : {tool}
  rule_id     : {rule_id}
  category    : {category}
  severity    : {severity}
  file        : {file}
  line        : {line}
  message     : {message}

Surrounding code ({file}, lines {ctx_start}-{ctx_end}):
```
{context}
```

Respond ONLY with JSON of this exact shape (no markdown, no commentary):
{{
  "false_positive_likelihood": 0.0-1.0,
  "plain_english": "one or two sentences tying the finding to the code",
  "remediation": "one short sentence on how to fix",
  "category_override": "" or one of the taxonomy keys
}}
"""


def cache_path() -> Path:
    base = Path(os.environ.get("XDG_CACHE_HOME", Path.home() / ".cache"))
    p = base / "vuln-scan"
    p.mkdir(parents=True, exist_ok=True)
    return p / "enrich.json"


def load_cache() -> dict:
    cp = cache_path()
    if not cp.exists():
        return {}
    try:
        return json.loads(cp.read_text())
    except Exception:
        return {}


def save_cache(cache: dict) -> None:
    cache_path().write_text(json.dumps(cache, indent=2))


def read_context(scan_dir: Path, file_rel: str, line: int, window: int = 5) -> tuple[str, int, int]:
    if not file_rel:
        return "", 0, 0
    p = scan_dir / file_rel
    if not p.is_file():
        return "", 0, 0
    try:
        lines = p.read_text(encoding="utf-8", errors="replace").splitlines()
    except Exception:
        return "", 0, 0
    if line <= 0 or line > len(lines):
        return "", 0, 0
    start = max(1, line - window)
    end = min(len(lines), line + window)
    return "\n".join(lines[start - 1:end]), start, end


def key_for(model: str, finding: dict, context: str) -> str:
    h = hashlib.sha256()
    h.update(model.encode())
    h.update(b"\0")
    h.update((finding.get("rule_id") or "").encode())
    h.update(b"\0")
    h.update((finding.get("file") or "").encode())
    h.update(b"\0")
    h.update(context.encode())
    return h.hexdigest()


def call_ollama(host: str, model: str, prompt: str, timeout: int = 60) -> dict | None:
    body = json.dumps({
        "model": model,
        "prompt": prompt,
        "format": "json",
        "stream": False,
        "options": {"temperature": 0.1, "num_predict": 400},
    }).encode()
    req = urllib.request.Request(
        f"{host}/api/generate",
        data=body,
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
            resp = json.loads(r.read())
    except Exception as e:
        print(f"[enrich] ollama call failed: {e}", file=sys.stderr)
        return None
    raw = resp.get("response", "").strip()
    try:
        return json.loads(raw)
    except json.JSONDecodeError:
        return None


def enrich_one(host: str, model: str, scan_dir: Path, finding: dict, cache: dict) -> dict:
    context, ctx_start, ctx_end = read_context(
        scan_dir,
        finding.get("file", ""),
        int(finding.get("line_start") or 0),
    )
    cache_key = key_for(model, finding, context)
    if cache_key in cache:
        return cache[cache_key]
    prompt = PROMPT_TEMPLATE.format(
        taxonomy=TAXONOMY,
        tool=finding.get("tool"),
        rule_id=finding.get("rule_id"),
        category=finding.get("category"),
        severity=finding.get("severity"),
        file=finding.get("file"),
        line=finding.get("line_start"),
        message=finding.get("message"),
        ctx_start=ctx_start,
        ctx_end=ctx_end,
        context=context or "(file not available)",
    )
    result = call_ollama(host, model, prompt) or {
        "false_positive_likelihood": None,
        "plain_english": None,
        "remediation": None,
        "category_override": "",
    }
    result["model"] = model
    cache[cache_key] = result
    return result


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--report", required=True, help="Path to report.json")
    ap.add_argument("--scan-dir", required=True, help="Source directory the report relates to")
    ap.add_argument("--model", default="qwen2.5:3b")
    ap.add_argument("--ollama-host", default="http://localhost:11434")
    ap.add_argument("--concurrency", type=int, default=4)
    ap.add_argument("--limit", type=int, default=0, help="Max findings to enrich (0=all)")
    args = ap.parse_args()

    report_path = Path(args.report)
    report = json.loads(report_path.read_text())
    findings = report.get("findings", [])
    if args.limit and args.limit < len(findings):
        # Prioritise: highest severity first, plus any uncategorized
        order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
        findings_sorted = sorted(findings, key=lambda f: order.get(f.get("severity", "info"), 4))
        targets = set(id(f) for f in findings_sorted[: args.limit])
    else:
        targets = set(id(f) for f in findings)

    cache = load_cache()
    scan_dir = Path(args.scan_dir)

    print(f"[enrich] {len(targets)} of {len(findings)} findings via {args.model}", file=sys.stderr)

    done = 0
    with ThreadPoolExecutor(max_workers=args.concurrency) as ex:
        future_to_f = {
            ex.submit(enrich_one, args.ollama_host, args.model, scan_dir, f, cache): f
            for f in findings if id(f) in targets
        }
        for fut in as_completed(future_to_f):
            f = future_to_f[fut]
            f["enrichment"] = fut.result()
            done += 1
            if done % 10 == 0:
                print(f"[enrich] {done}/{len(targets)} done", file=sys.stderr)
                save_cache(cache)

    save_cache(cache)

    # Override categories where the model is confident enough
    for f in findings:
        e = f.get("enrichment") or {}
        cat = (e.get("category_override") or "").strip()
        if cat and cat != f.get("category") and (e.get("false_positive_likelihood") or 0) < 0.5:
            f["category_original"] = f["category"]
            f["category"] = cat

    # Recompute by_category
    by_cat: dict[str, int] = {}
    for f in findings:
        by_cat[f["category"]] = by_cat.get(f["category"], 0) + 1
    report["summary"]["by_category"] = by_cat
    report["summary"]["enriched"] = True
    report["summary"]["enrich_model"] = args.model

    report_path.write_text(json.dumps(report, indent=2))

    # Append triage section to report.md
    md_path = report_path.with_suffix(".md")
    if md_path.exists():
        with md_path.open("a") as fh:
            fh.write("\n\n## LLM triage\n\n")
            fh.write(f"Enriched with `{args.model}` via Ollama.\n\n")
            high_fp = [f for f in findings if (f.get("enrichment") or {}).get("false_positive_likelihood", 0) >= 0.7]
            fh.write(f"Likely false positives (≥0.7 confidence): **{len(high_fp)}**\n\n")
            if high_fp:
                for f in high_fp[:30]:
                    loc = f["file"] + (f":{f['line_start']}" if f.get("line_start") else "")
                    fh.write(f"- `{f['tool']}` `{f['rule_id']}` — `{loc}` (FP: {f['enrichment']['false_positive_likelihood']:.2f})\n")
                    expl = (f["enrichment"].get("plain_english") or "").strip()
                    if expl:
                        fh.write(f"  - {expl}\n")
            fh.write("\n")

    print(f"[enrich] wrote {report_path}", file=sys.stderr)
    return 0


if __name__ == "__main__":
    sys.exit(main())
