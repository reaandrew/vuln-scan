#!/usr/bin/env python3
"""Aggregate per-tool outputs from scan.sh into a unified report (JSON + Markdown).

Each parser is tolerant: missing files, empty results, or schema drift are
treated as "no findings from that tool" rather than fatal errors.
"""
from __future__ import annotations

import argparse
import csv
import datetime as dt
import json
import os
import re
import sys
import xml.etree.ElementTree as ET
from collections import Counter, defaultdict
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any, Iterable

VERSION = "1.0.0"

# ── Vulnerability category taxonomy ─────────────────────────────────────────
# Aligned with the 8 classes in SECURITY-TOOLS.md, plus three "adjacent"
# buckets for tools that step outside SAST proper.
CATEGORIES = [
    "injection",            # SQL, cmd, code, XSS, XXE, ReDoS
    "path_network",         # path traversal, SSRF, open redirect
    "auth_access",          # authn bypass, IDOR, CSRF, race
    "memory_safety",        # buffer/integer overflow, UAF, unsafe
    "cryptography",         # weak primitives, JWT alg=none, timing
    "deserialization",      # pickle, readObject, yaml.load
    "protocol_encoding",    # cache, encoding confusion, length-prefix
    "secrets",              # credentials in code (trufflehog)
    "dependency",           # known-CVE pulled-in dep (trivy fs)
    "iac_misconfiguration", # IaC findings (trivy fs)
    "uncategorized",
]

# CWE → category (best-effort)
CWE_CATEGORY = {
    # Injection
    "CWE-77": "injection", "CWE-78": "injection", "CWE-79": "injection",
    "CWE-89": "injection", "CWE-91": "injection", "CWE-94": "injection",
    "CWE-95": "injection", "CWE-611": "injection", "CWE-643": "injection",
    "CWE-1333": "injection", "CWE-400": "injection",  # ReDoS
    # Path & network
    "CWE-22": "path_network", "CWE-23": "path_network", "CWE-36": "path_network",
    "CWE-918": "path_network", "CWE-601": "path_network",
    # Auth & access
    "CWE-285": "auth_access", "CWE-287": "auth_access", "CWE-306": "auth_access",
    "CWE-352": "auth_access", "CWE-639": "auth_access", "CWE-862": "auth_access",
    "CWE-863": "auth_access", "CWE-269": "auth_access", "CWE-362": "auth_access",
    "CWE-367": "auth_access",
    # Memory safety
    "CWE-119": "memory_safety", "CWE-120": "memory_safety", "CWE-121": "memory_safety",
    "CWE-122": "memory_safety", "CWE-125": "memory_safety", "CWE-126": "memory_safety",
    "CWE-127": "memory_safety", "CWE-190": "memory_safety", "CWE-191": "memory_safety",
    "CWE-415": "memory_safety", "CWE-416": "memory_safety", "CWE-787": "memory_safety",
    "CWE-680": "memory_safety", "CWE-476": "memory_safety", "CWE-401": "memory_safety",
    # Crypto
    "CWE-261": "cryptography", "CWE-310": "cryptography", "CWE-326": "cryptography",
    "CWE-327": "cryptography", "CWE-328": "cryptography", "CWE-329": "cryptography",
    "CWE-330": "cryptography", "CWE-338": "cryptography", "CWE-347": "cryptography",
    "CWE-916": "cryptography", "CWE-1240": "cryptography",
    # Deserialization
    "CWE-502": "deserialization",
    # Protocol & encoding
    "CWE-444": "protocol_encoding", "CWE-113": "protocol_encoding",
    "CWE-93": "protocol_encoding", "CWE-176": "protocol_encoding",
    "CWE-697": "protocol_encoding",
    # Secrets / dep / IaC
    "CWE-798": "secrets", "CWE-200": "secrets",
    "CWE-1104": "dependency", "CWE-937": "dependency",
    "CWE-16": "iac_misconfiguration",
}

# Bandit test IDs → category (https://bandit.readthedocs.io/en/latest/plugins/)
BANDIT_CATEGORY = {
    # B1xx misc, B2xx app, B3xx blacklist (deser), B4xx import, B5xx crypto, B6xx inject, B7xx framework
    "B301": "deserialization", "B302": "deserialization", "B303": "cryptography",
    "B304": "cryptography", "B305": "cryptography", "B306": "path_network",
    "B307": "injection", "B308": "injection", "B310": "path_network",
    "B311": "cryptography", "B312": "protocol_encoding", "B313": "injection",
    "B314": "injection", "B315": "injection", "B316": "injection",
    "B317": "injection", "B318": "injection", "B319": "injection",
    "B320": "injection", "B321": "path_network", "B323": "protocol_encoding",
    "B324": "cryptography", "B325": "memory_safety",
    "B501": "cryptography", "B502": "cryptography", "B503": "cryptography",
    "B504": "cryptography", "B505": "cryptography", "B506": "deserialization",
    "B507": "auth_access",
    "B601": "injection", "B602": "injection", "B603": "injection",
    "B604": "injection", "B605": "injection", "B606": "injection",
    "B607": "injection", "B608": "injection", "B609": "injection",
    "B610": "injection", "B611": "injection",
    "B701": "injection", "B702": "injection", "B703": "injection",
}

# gosec rule IDs → category (https://github.com/securego/gosec)
GOSEC_CATEGORY = {
    "G101": "secrets", "G102": "auth_access", "G103": "memory_safety",
    "G104": "auth_access", "G106": "auth_access", "G107": "path_network",
    "G108": "auth_access", "G109": "memory_safety", "G110": "memory_safety",
    "G111": "path_network", "G112": "memory_safety", "G114": "protocol_encoding",
    "G201": "injection", "G202": "injection", "G203": "injection",
    "G204": "injection",
    "G301": "auth_access", "G302": "auth_access", "G303": "auth_access",
    "G304": "path_network", "G305": "path_network", "G306": "auth_access",
    "G307": "auth_access",
    "G401": "cryptography", "G402": "cryptography", "G403": "cryptography",
    "G404": "cryptography", "G405": "cryptography", "G406": "cryptography",
    "G407": "cryptography",
    "G501": "cryptography", "G502": "cryptography", "G503": "cryptography",
    "G504": "cryptography", "G505": "cryptography",
    "G601": "memory_safety", "G602": "memory_safety",
}

SEVERITY_ORDER = {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}


def normalise_severity(raw: str | None) -> str:
    if not raw:
        return "info"
    s = str(raw).lower().strip()
    if s in ("critical", "crit"):
        return "critical"
    if s in ("error", "high"):
        return "high"
    if s in ("warning", "medium", "med", "moderate"):
        return "medium"
    if s in ("note", "info", "informational", "style", "performance", "portability"):
        return "info"
    if s in ("low",):
        return "low"
    return "info"


@dataclass
class Finding:
    tool: str
    rule_id: str
    category: str
    severity: str
    file: str
    line_start: int = 0
    line_end: int = 0
    message: str = ""
    cwe: list[str] = field(default_factory=list)
    snippet: str = ""
    url: str = ""


def category_from_cwe(cwes: Iterable[str]) -> str | None:
    for c in cwes:
        m = re.search(r"CWE-\d+", c)
        if m and m.group(0) in CWE_CATEGORY:
            return CWE_CATEGORY[m.group(0)]
    return None


def safe_load_json(path: Path) -> Any:
    try:
        if not path.exists() or path.stat().st_size == 0:
            return None
        return json.loads(path.read_text(encoding="utf-8", errors="replace"))
    except Exception as e:
        print(f"[warn] failed to parse {path}: {e}", file=sys.stderr)
        return None


def relpath(p: str, base: str) -> str:
    try:
        return os.path.relpath(p, base)
    except Exception:
        return p


# ── Per-tool parsers ────────────────────────────────────────────────────────
def parse_semgrep(path: Path, scan_dir: str) -> list[Finding]:
    data = safe_load_json(path)
    if not data:
        return []
    out = []
    for r in data.get("results", []):
        meta = r.get("extra", {}).get("metadata", {})
        cwes = []
        for c in meta.get("cwe", []) or []:
            m = re.search(r"CWE-\d+", c)
            if m:
                cwes.append(m.group(0))
        category = category_from_cwe(cwes) or "uncategorized"
        out.append(Finding(
            tool="semgrep",
            rule_id=r.get("check_id", ""),
            category=category,
            severity=normalise_severity(r.get("extra", {}).get("severity")),
            file=relpath(r.get("path", ""), scan_dir),
            line_start=int(r.get("start", {}).get("line", 0) or 0),
            line_end=int(r.get("end", {}).get("line", 0) or 0),
            message=r.get("extra", {}).get("message", "").strip(),
            cwe=cwes,
            snippet=(r.get("extra", {}).get("lines") or "").strip()[:300],
            url=meta.get("source", "") or "",
        ))
    return out


def parse_bandit(path: Path, scan_dir: str) -> list[Finding]:
    data = safe_load_json(path)
    if not data:
        return []
    out = []
    for r in data.get("results", []):
        test_id = r.get("test_id", "")
        cwes = []
        cwe_field = r.get("issue_cwe") or {}
        if isinstance(cwe_field, dict) and "id" in cwe_field:
            cwes.append(f"CWE-{cwe_field['id']}")
        category = (
            category_from_cwe(cwes)
            or BANDIT_CATEGORY.get(test_id)
            or "uncategorized"
        )
        out.append(Finding(
            tool="bandit",
            rule_id=test_id,
            category=category,
            severity=normalise_severity(r.get("issue_severity")),
            file=relpath(r.get("filename", ""), scan_dir),
            line_start=int(r.get("line_number", 0) or 0),
            line_end=int(r.get("line_number", 0) or 0),
            message=(r.get("issue_text") or "").strip(),
            cwe=cwes,
            snippet=(r.get("code") or "").strip()[:300],
            url=(r.get("more_info") or ""),
        ))
    return out


def parse_gosec(path: Path, scan_dir: str) -> list[Finding]:
    data = safe_load_json(path)
    if not data:
        return []
    out = []
    for r in data.get("Issues", []):
        rule_id = r.get("rule_id", "")
        cwes = []
        cwe_field = r.get("cwe") or {}
        if isinstance(cwe_field, dict) and "ID" in cwe_field:
            cwes.append(f"CWE-{cwe_field['ID']}")
        category = (
            category_from_cwe(cwes)
            or GOSEC_CATEGORY.get(rule_id)
            or "uncategorized"
        )
        line_str = str(r.get("line", "0"))
        line_start = int(line_str.split("-")[0] or 0)
        line_end = int(line_str.split("-")[-1] or line_start)
        out.append(Finding(
            tool="gosec",
            rule_id=rule_id,
            category=category,
            severity=normalise_severity(r.get("severity")),
            file=relpath(r.get("file", ""), scan_dir),
            line_start=line_start,
            line_end=line_end,
            message=(r.get("details") or "").strip(),
            cwe=cwes,
            snippet=(r.get("code") or "").strip()[:300],
        ))
    return out


def parse_cppcheck(path: Path, scan_dir: str) -> list[Finding]:
    if not path.exists() or path.stat().st_size == 0:
        return []
    try:
        tree = ET.parse(path)
    except ET.ParseError:
        return []
    out = []
    for err in tree.iterfind(".//error"):
        cwe_id = err.get("cwe")
        cwes = [f"CWE-{cwe_id}"] if cwe_id else []
        category = category_from_cwe(cwes) or "memory_safety"
        loc = err.find("location")
        file_ = loc.get("file") if loc is not None else ""
        line_ = int(loc.get("line", "0") or 0) if loc is not None else 0
        out.append(Finding(
            tool="cppcheck",
            rule_id=err.get("id", ""),
            category=category,
            severity=normalise_severity(err.get("severity")),
            file=relpath(file_, scan_dir),
            line_start=line_,
            line_end=line_,
            message=(err.get("msg") or "").strip(),
            cwe=cwes,
        ))
    return out


def parse_flawfinder(path: Path, scan_dir: str) -> list[Finding]:
    if not path.exists() or path.stat().st_size == 0:
        return []
    out = []
    with path.open(encoding="utf-8", errors="replace") as fh:
        reader = csv.DictReader(fh)
        for row in reader:
            cwes_raw = row.get("CWEs", "") or ""
            cwes = [f"CWE-{x.strip()}" for x in cwes_raw.split(",") if x.strip().isdigit()]
            category = category_from_cwe(cwes) or "memory_safety"
            try:
                level = int(row.get("Level", "0") or 0)
            except ValueError:
                level = 0
            severity = "high" if level >= 4 else "medium" if level >= 2 else "low"
            out.append(Finding(
                tool="flawfinder",
                rule_id=row.get("Name", ""),
                category=category,
                severity=severity,
                file=relpath(row.get("File", ""), scan_dir),
                line_start=int(row.get("Line", "0") or 0),
                line_end=int(row.get("Line", "0") or 0),
                message=(row.get("Warning") or "").strip(),
                cwe=cwes,
                snippet=(row.get("Context") or "").strip()[:300],
            ))
    return out


def parse_trufflehog(path: Path, scan_dir: str) -> list[Finding]:
    if not path.exists() or path.stat().st_size == 0:
        return []
    out = []
    for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            r = json.loads(line)
        except json.JSONDecodeError:
            continue
        meta = (r.get("SourceMetadata") or {}).get("Data") or {}
        fs = meta.get("Filesystem") or {}
        verified = bool(r.get("Verified"))
        out.append(Finding(
            tool="trufflehog",
            rule_id=r.get("DetectorName", "secret"),
            category="secrets",
            severity="critical" if verified else "high",
            file=relpath(fs.get("file", ""), scan_dir),
            line_start=int(fs.get("line", 0) or 0),
            line_end=int(fs.get("line", 0) or 0),
            message=f"{r.get('DetectorName', 'unknown')} secret detected"
                    + (" (verified)" if verified else ""),
            cwe=["CWE-798"],
        ))
    return out


def parse_trivy(path: Path, scan_dir: str) -> list[Finding]:
    data = safe_load_json(path)
    if not data:
        return []
    out = []
    for tgt in data.get("Results", []) or []:
        tgt_path = tgt.get("Target", "")
        for v in tgt.get("Vulnerabilities", []) or []:
            cwes = [c for c in (v.get("CweIDs") or []) if c.startswith("CWE-")]
            out.append(Finding(
                tool="trivy",
                rule_id=v.get("VulnerabilityID", ""),
                category="dependency",
                severity=normalise_severity(v.get("Severity")),
                file=relpath(tgt_path, scan_dir),
                message=f"{v.get('PkgName')} {v.get('InstalledVersion')} → {v.get('Title', '').strip()}",
                cwe=cwes,
                url=(v.get("PrimaryURL") or ""),
            ))
        for m in tgt.get("Misconfigurations", []) or []:
            out.append(Finding(
                tool="trivy",
                rule_id=m.get("ID", ""),
                category="iac_misconfiguration",
                severity=normalise_severity(m.get("Severity")),
                file=relpath(tgt_path, scan_dir),
                line_start=int((m.get("CauseMetadata") or {}).get("StartLine", 0) or 0),
                line_end=int((m.get("CauseMetadata") or {}).get("EndLine", 0) or 0),
                message=(m.get("Title") or m.get("Description") or "").strip(),
            ))
        for s in tgt.get("Secrets", []) or []:
            out.append(Finding(
                tool="trivy",
                rule_id=s.get("RuleID", ""),
                category="secrets",
                severity=normalise_severity(s.get("Severity")),
                file=relpath(tgt_path, scan_dir),
                line_start=int(s.get("StartLine", 0) or 0),
                line_end=int(s.get("EndLine", 0) or 0),
                message=(s.get("Title") or "").strip(),
                cwe=["CWE-798"],
            ))
    return out


def parse_gitleaks(path: Path, scan_dir: str) -> list[Finding]:
    data = safe_load_json(path)
    if not data:
        return []
    out = []
    items = data if isinstance(data, list) else data.get("findings", [])
    for r in items:
        out.append(Finding(
            tool="gitleaks",
            rule_id=r.get("RuleID") or r.get("Rule") or "gitleaks-secret",
            category="secrets",
            severity="high",
            file=relpath(r.get("File", ""), scan_dir),
            line_start=int(r.get("StartLine", 0) or 0),
            line_end=int(r.get("EndLine", 0) or 0),
            message=(r.get("Description") or r.get("Match") or "secret detected").strip()[:300],
            cwe=["CWE-798"],
        ))
    return out


def parse_osv(path: Path, scan_dir: str) -> list[Finding]:
    data = safe_load_json(path)
    if not data:
        return []
    out = []
    for res in data.get("results", []) or []:
        src = (res.get("source") or {}).get("path", "")
        for pkg in res.get("packages", []) or []:
            pkg_name = (pkg.get("package") or {}).get("name", "")
            for v in pkg.get("vulnerabilities", []) or []:
                cwes = [c for c in (v.get("database_specific") or {}).get("cwe_ids", []) or []
                        if isinstance(c, str) and c.startswith("CWE-")]
                sev = "high"
                for s in v.get("severity", []) or []:
                    if (s.get("type") or "").upper() == "CVSS_V3":
                        sev = normalise_severity(s.get("score", "")[:1])
                out.append(Finding(
                    tool="osv-scanner",
                    rule_id=v.get("id", ""),
                    category="dependency",
                    severity=sev,
                    file=relpath(src, scan_dir),
                    message=f"{pkg_name} → {v.get('summary', '')}".strip()[:300],
                    cwe=cwes,
                    url=(v.get("references") or [{}])[0].get("url", "") if v.get("references") else "",
                ))
    return out


def parse_njsscan(path: Path, scan_dir: str) -> list[Finding]:
    data = safe_load_json(path)
    if not data:
        return []
    out = []
    for section in ("nodejs", "templates"):
        block = data.get(section) or {}
        for rule_id, payload in block.items():
            meta = payload.get("metadata", {}) or {}
            sev = normalise_severity(meta.get("severity"))
            cwes = []
            cwe_field = meta.get("cwe")
            if isinstance(cwe_field, str):
                m = re.search(r"CWE-\d+", cwe_field)
                if m:
                    cwes.append(m.group(0))
            category = category_from_cwe(cwes) or "uncategorized"
            for f in payload.get("files", []) or []:
                out.append(Finding(
                    tool="njsscan",
                    rule_id=rule_id,
                    category=category,
                    severity=sev,
                    file=relpath(f.get("file_path", ""), scan_dir),
                    line_start=int(f.get("match_lines", [0])[0] or 0),
                    line_end=int((f.get("match_lines") or [0, 0])[-1] or 0),
                    message=(meta.get("description") or "").strip()[:300],
                    cwe=cwes,
                    snippet=(f.get("match_string") or "").strip()[:300],
                ))
    return out


def parse_checkov(path: Path, scan_dir: str) -> list[Finding]:
    data = safe_load_json(path)
    if not data:
        return []
    out = []
    blocks = data if isinstance(data, list) else [data]
    for block in blocks:
        results = (block.get("results") or {}).get("failed_checks", []) or []
        for r in results:
            cwes = []
            for g in r.get("guideline", "") or "":
                m = re.search(r"CWE-\d+", g)
                if m:
                    cwes.append(m.group(0))
            out.append(Finding(
                tool="checkov",
                rule_id=r.get("check_id", ""),
                category="iac_misconfiguration",
                severity=normalise_severity((r.get("severity") or "").lower()),
                file=relpath(r.get("file_path", "").lstrip("/"), scan_dir),
                line_start=int(((r.get("file_line_range") or [0, 0])[0]) or 0),
                line_end=int(((r.get("file_line_range") or [0, 0])[-1]) or 0),
                message=(r.get("check_name") or "").strip(),
                cwe=cwes,
                url=(r.get("guideline") or ""),
            ))
    return out


def parse_govulncheck(path: Path, scan_dir: str) -> list[Finding]:
    """govulncheck -json emits NDJSON: one JSON object per line, mixed types."""
    if not path.exists() or path.stat().st_size == 0:
        return []
    findings_by_osv: dict[str, dict] = {}
    for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            obj = json.loads(line)
        except json.JSONDecodeError:
            continue
        if "osv" in obj:
            v = obj["osv"]
            findings_by_osv[v.get("id", "")] = v
        elif "finding" in obj:
            fnd = obj["finding"]
            osv_id = fnd.get("osv", "")
            v = findings_by_osv.get(osv_id, {})
            # Reachability: if there's a trace, govulncheck found a path that
            # actually calls the vulnerable function. Without a trace it's
            # only an import-level match.
            trace = fnd.get("trace") or []
            reachable = bool(trace) and bool((trace[0] or {}).get("function"))
            file_ = ""; line_no = 0
            if reachable:
                pos = (trace[0] or {}).get("position") or {}
                file_ = pos.get("filename", "")
                line_no = int(pos.get("line", 0) or 0)
            yield Finding(
                tool="govulncheck",
                rule_id=osv_id,
                category="dependency",
                severity="high" if reachable else "medium",
                file=relpath(file_, scan_dir),
                line_start=line_no,
                line_end=line_no,
                message=(v.get("summary") or v.get("details") or "").strip()[:300]
                        + (" [reachable]" if reachable else " [imported only]"),
                cwe=[],
                url=(v.get("references") or [{}])[0].get("url", "") if v.get("references") else "",
            )


def parse_brakeman(path: Path, scan_dir: str) -> list[Finding]:
    data = safe_load_json(path)
    if not data:
        return []
    out = []
    for w in data.get("warnings", []) or []:
        cwes = []
        for c in w.get("cwe_id", []) or []:
            cwes.append(f"CWE-{c}")
        category = category_from_cwe(cwes) or "uncategorized"
        out.append(Finding(
            tool="brakeman",
            rule_id=w.get("warning_code", w.get("warning_type", "")) or "",
            category=category,
            severity=normalise_severity(w.get("confidence")),
            file=relpath(w.get("file", ""), scan_dir),
            line_start=int(w.get("line", 0) or 0),
            line_end=int(w.get("line", 0) or 0),
            message=f'{w.get("warning_type", "")}: {w.get("message", "")}'.strip()[:300],
            cwe=cwes,
            snippet=(w.get("code") or "").strip()[:300],
            url=(w.get("link") or ""),
        ))
    return out


def parse_retire(path: Path, scan_dir: str) -> list[Finding]:
    """retire.js --outputformat jsonsimple: array of {file, results: [{component, version, vulnerabilities: [...]}]}."""
    data = safe_load_json(path)
    if not data:
        return []
    out = []
    items = data if isinstance(data, list) else [data]
    for entry in items:
        file_ = entry.get("file") or ""
        for r in entry.get("results", []) or []:
            component = r.get("component") or ""
            version = r.get("version") or ""
            for v in r.get("vulnerabilities", []) or []:
                ids = v.get("identifiers", {}) or {}
                cves = ids.get("CVE", []) or []
                cwes = []
                for c in v.get("cwe", []) or []:
                    m = re.search(r"CWE-\d+", str(c))
                    if m:
                        cwes.append(m.group(0))
                summary = ids.get("summary") or v.get("summary") or ""
                out.append(Finding(
                    tool="retire.js",
                    rule_id=(cves[0] if cves else f"retire/{component}"),
                    category="dependency",
                    severity=normalise_severity(v.get("severity")),
                    file=relpath(file_, scan_dir),
                    message=f"{component}@{version}: {summary}".strip()[:300],
                    cwe=cwes,
                    url=(v.get("info") or [""])[0] if v.get("info") else "",
                ))
    return out


def parse_tfsec(path: Path, scan_dir: str) -> list[Finding]:
    data = safe_load_json(path)
    if not data:
        return []
    out = []
    for r in data.get("results", []) or []:
        loc = r.get("location") or {}
        out.append(Finding(
            tool="tfsec",
            rule_id=r.get("rule_id", ""),
            category="iac_misconfiguration",
            severity=normalise_severity(r.get("severity")),
            file=relpath(loc.get("filename", ""), scan_dir),
            line_start=int(loc.get("start_line", 0) or 0),
            line_end=int(loc.get("end_line", 0) or 0),
            message=(r.get("description") or r.get("long_id") or "").strip()[:300],
            cwe=[],
            url=(r.get("links") or [""])[0] if r.get("links") else "",
        ))
    return out


def parse_hadolint(path: Path, scan_dir: str) -> list[Finding]:
    data = safe_load_json(path)
    if not data:
        return []
    out = []
    items = data if isinstance(data, list) else data.get("findings", [])
    for r in items:
        out.append(Finding(
            tool="hadolint",
            rule_id=r.get("code", ""),
            category="iac_misconfiguration",
            severity=normalise_severity(r.get("level")),
            file=relpath(r.get("file", ""), scan_dir),
            line_start=int(r.get("line", 0) or 0),
            line_end=int(r.get("line", 0) or 0),
            message=(r.get("message") or "").strip()[:300],
            cwe=[],
        ))
    return out


def parse_psalm(path: Path, scan_dir: str) -> list[Finding]:
    """psalm --output-format=json: top-level array of issue objects."""
    data = safe_load_json(path)
    if not data:
        return []
    out = []
    items = data if isinstance(data, list) else data.get("issues", [])
    for r in items:
        kind = r.get("type", "") or r.get("issue", "")
        # Taint issues start with "Tainted" — those are the ones we want
        # most (interfile XSS / SQLi / shell etc.). Other Psalm issues are
        # general type errors; skip them to avoid noise.
        is_taint = kind.startswith("Tainted")
        if not is_taint:
            continue
        cwe = []
        if "Sql" in kind:
            cwe = ["CWE-89"]
        elif "Html" in kind or "Xss" in kind:
            cwe = ["CWE-79"]
        elif "Shell" in kind or "Eval" in kind:
            cwe = ["CWE-78"]
        elif "Include" in kind or "File" in kind:
            cwe = ["CWE-22"]
        elif "Header" in kind or "Redirect" in kind:
            cwe = ["CWE-601"]
        category = category_from_cwe(cwe) or "uncategorized"
        out.append(Finding(
            tool="psalm",
            rule_id=kind,
            category=category,
            severity=normalise_severity(r.get("severity") or "high"),
            file=relpath(r.get("file_path", ""), scan_dir),
            line_start=int(r.get("line_from", 0) or 0),
            line_end=int(r.get("line_to", 0) or 0),
            message=(r.get("message") or "").strip()[:300],
            cwe=cwe,
            snippet=(r.get("snippet") or "").strip()[:300],
            url=(r.get("link") or ""),
        ))
    return out


def parse_spotbugs(path: Path, scan_dir: str) -> list[Finding]:
    """spotbugs / find-sec-bugs -xml:withMessages: <BugCollection><BugInstance>…<SourceLine>"""
    if not path.exists() or path.stat().st_size == 0:
        return []
    try:
        tree = ET.parse(path)
    except ET.ParseError:
        return []
    out = []
    for bi in tree.iterfind(".//BugInstance"):
        bug_type = bi.get("type", "")
        category = "uncategorized"
        if any(k in bug_type for k in ("SQL_INJECTION", "SQLI")):
            category = "injection"; cwe = ["CWE-89"]
        elif any(k in bug_type for k in ("XSS", "HTML_INJECTION")):
            category = "injection"; cwe = ["CWE-79"]
        elif "COMMAND_INJECTION" in bug_type:
            category = "injection"; cwe = ["CWE-78"]
        elif "PATH_TRAVERSAL" in bug_type:
            category = "path_network"; cwe = ["CWE-22"]
        elif "WEAK_HASH" in bug_type or "MD5" in bug_type or "DES" in bug_type:
            category = "cryptography"; cwe = ["CWE-327"]
        elif "DESERIALIZATION" in bug_type:
            category = "deserialization"; cwe = ["CWE-502"]
        elif "HARD_CODE" in bug_type:
            category = "secrets"; cwe = ["CWE-798"]
        else:
            cwe = []
        sl = bi.find(".//SourceLine") or bi.find("SourceLine")
        file_ = sl.get("sourcepath") if sl is not None else ""
        line_ = int(sl.get("start", "0") or 0) if sl is not None else 0
        msg = (bi.findtext("LongMessage") or bi.findtext("ShortMessage") or "").strip()
        priority = bi.get("priority", "2")
        sev = {"1": "high", "2": "medium", "3": "low"}.get(priority, "medium")
        out.append(Finding(
            tool="find-sec-bugs",
            rule_id=bug_type,
            category=category,
            severity=sev,
            file=relpath(file_, scan_dir),
            line_start=line_,
            line_end=line_,
            message=msg[:300],
            cwe=cwe,
        ))
    return out


def parse_joern(path: Path, scan_dir: str) -> list[Finding]:
    """joern-scan emits one finding per line: 'Result: <severity>: ... <file>:<line>'"""
    if not path.exists() or path.stat().st_size == 0:
        return []
    out = []
    text = path.read_text(encoding="utf-8", errors="replace")
    for raw_line in text.splitlines():
        line = raw_line.strip()
        if not line or not line.lower().startswith(("result:", "score:")):
            continue
        # Try to extract file:line at the end
        m = re.search(r"([\w./\\-]+):(\d+)\s*$", line)
        file_ = m.group(1) if m else ""
        line_no = int(m.group(2)) if m else 0
        sev_match = re.search(r"^(?:Result|Score):\s*([\d.]+)", line, re.IGNORECASE)
        try:
            score = float(sev_match.group(1)) if sev_match else 5.0
        except ValueError:
            score = 5.0
        sev = "high" if score >= 8 else "medium" if score >= 4 else "low"
        # Heuristic category from message text
        lower = line.lower()
        category = "uncategorized"
        if "sql" in lower or "injection" in lower:
            category = "injection"
        elif "xss" in lower:
            category = "injection"
        elif "redirect" in lower:
            category = "path_network"
        elif "path" in lower and ("traversal" in lower or "..\\" in lower or "../" in lower):
            category = "path_network"
        elif "crypto" in lower or "weak hash" in lower or "md5" in lower:
            category = "cryptography"
        elif "deser" in lower or "pickle" in lower:
            category = "deserialization"
        out.append(Finding(
            tool="joern",
            rule_id=line.split(":", 2)[1].strip().split()[0] if ":" in line else "joern",
            category=category,
            severity=sev,
            file=relpath(file_, scan_dir),
            line_start=line_no,
            line_end=line_no,
            message=line[:300],
        ))
    return out


def parse_phan(path: Path, scan_dir: str) -> list[Finding]:
    data = safe_load_json(path)
    if not data:
        return []
    out = []
    items = data if isinstance(data, list) else data.get("issues", [])
    for r in items:
        check_name = r.get("check_name") or r.get("type") or ""
        # Filter: phan emits a *lot* of type errors. Only keep security-relevant
        # categories so it doesn't drown the unified report. Phan's issue types
        # starting with "Plugin" or "Security" are the ones we care about; the
        # rest are general type quality.
        if not any(k in check_name for k in ("Security", "Plugin", "Taint", "TypeArray", "ClosedArray")):
            continue
        loc = r.get("location") or {}
        path_ = (loc.get("path") or r.get("file") or "")
        ln = (loc.get("lines") or {}).get("begin") or r.get("line") or 0
        out.append(Finding(
            tool="phan",
            rule_id=check_name,
            category="uncategorized",
            severity=normalise_severity(r.get("severity")),
            file=relpath(path_, scan_dir),
            line_start=int(ln or 0),
            line_end=int(ln or 0),
            message=(r.get("description") or "").strip()[:300],
            cwe=[],
        ))
    return out


def parse_regexploit(path: Path, label: str) -> list[Finding]:
    """Best-effort: regexploit emits free text. Each starred regex line is one finding."""
    if not path.exists() or path.stat().st_size == 0:
        return []
    out = []
    text = path.read_text(encoding="utf-8", errors="replace")
    # rough: look for lines starting with "Vulnerable regex"
    for chunk in re.split(r"\n(?=Vulnerable regex|Worst-case)", text):
        chunk = chunk.strip()
        if not chunk or "Vulnerable" not in chunk:
            continue
        m = re.search(r"([^\s]+\.(py|js|ts|tsx|jsx)):(\d+)", chunk)
        file_ = m.group(1) if m else ""
        line_ = int(m.group(3)) if m else 0
        out.append(Finding(
            tool=f"regexploit ({label})",
            rule_id="REDOS",
            category="injection",
            severity="medium",
            file=file_,
            line_start=line_,
            line_end=line_,
            message=chunk.splitlines()[0][:200],
            cwe=["CWE-1333"],
        ))
    return out


# ── Aggregation ─────────────────────────────────────────────────────────────
def render_markdown(report: dict) -> str:
    lines = []
    lines.append(f"# vuln-scan report")
    lines.append("")
    lines.append(f"- **scanned**: {report['scanned_at']}")
    lines.append(f"- **target**: `{report['target']['type']}` — `{report['target']['source']}`")
    if report["target"].get("commit"):
        lines.append(f"- **commit**: `{report['target']['commit']}`")
    lines.append(f"- **total findings**: {report['summary']['total_findings']}")
    lines.append("")

    lines.append("## Severity")
    lines.append("")
    lines.append("| severity | count |")
    lines.append("|---|---|")
    for sev in ("critical", "high", "medium", "low", "info"):
        n = report["summary"]["by_severity"].get(sev, 0)
        lines.append(f"| {sev} | {n} |")
    lines.append("")

    lines.append("## Category")
    lines.append("")
    lines.append("| category | count |")
    lines.append("|---|---|")
    for cat in CATEGORIES:
        n = report["summary"]["by_category"].get(cat, 0)
        if n:
            lines.append(f"| {cat} | {n} |")
    lines.append("")

    lines.append("## Tool")
    lines.append("")
    lines.append("| tool | count |")
    lines.append("|---|---|")
    for tool, n in sorted(report["summary"]["by_tool"].items(), key=lambda kv: -kv[1]):
        lines.append(f"| {tool} | {n} |")
    lines.append("")

    # Top findings (highest severity first)
    findings = report["findings"]
    findings_sorted = sorted(findings, key=lambda f: -SEVERITY_ORDER.get(f["severity"], 0))
    top = findings_sorted[:50]
    if top:
        lines.append(f"## Top findings ({len(top)} of {len(findings)})")
        lines.append("")
        for f in top:
            loc = f["file"]
            if f.get("line_start"):
                loc += f":{f['line_start']}"
            cwe = ", ".join(f.get("cwe") or []) or "—"
            lines.append(
                f"- **[{f['severity']}]** `{f['tool']}` `{f['rule_id']}` "
                f"({f['category']}, {cwe}) — `{loc}`"
            )
            if f.get("message"):
                lines.append(f"  - {f['message']}")
        lines.append("")

    return "\n".join(lines) + "\n"


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--raw-dir", required=True)
    ap.add_argument("--output-dir", required=True)
    ap.add_argument("--target-type", required=True)
    ap.add_argument("--target-source", required=True)
    ap.add_argument("--target-commit", default="")
    ap.add_argument("--scan-dir", required=True)
    args = ap.parse_args()

    raw = Path(args.raw_dir)
    scan_dir = args.scan_dir

    findings: list[Finding] = []
    findings += parse_semgrep(raw / "semgrep.json", scan_dir)
    findings += parse_bandit(raw / "bandit.json", scan_dir)
    findings += parse_gosec(raw / "gosec.json", scan_dir)
    findings += parse_cppcheck(raw / "cppcheck.xml", scan_dir)
    findings += parse_flawfinder(raw / "flawfinder.csv", scan_dir)
    findings += parse_trufflehog(raw / "trufflehog.jsonl", scan_dir)
    findings += parse_gitleaks(raw / "gitleaks.json", scan_dir)
    findings += parse_trivy(raw / "trivy.json", scan_dir)
    findings += parse_osv(raw / "osv.json", scan_dir)
    findings += parse_njsscan(raw / "njsscan.json", scan_dir)
    findings += parse_checkov(raw / "checkov.json", scan_dir)
    findings += list(parse_govulncheck(raw / "govulncheck.json", scan_dir))
    findings += parse_brakeman(raw / "brakeman.json", scan_dir)
    findings += parse_retire(raw / "retire.json", scan_dir)
    findings += parse_tfsec(raw / "tfsec.json", scan_dir)
    findings += parse_hadolint(raw / "hadolint.json", scan_dir)
    findings += parse_psalm(raw / "psalm.json", scan_dir)
    findings += parse_spotbugs(raw / "findsecbugs.xml", scan_dir)
    findings += parse_joern(raw / "joern.txt", scan_dir)
    findings += parse_phan(raw / "phan.json", scan_dir)
    findings += parse_regexploit(raw / "regexploit-py.txt", "py")
    findings += parse_regexploit(raw / "regexploit-js.txt", "js")

    # Summaries
    by_sev = Counter(f.severity for f in findings)
    by_cat = Counter(f.category for f in findings)
    by_tool = Counter(f.tool for f in findings)

    report = {
        "tool": "vuln-scan",
        "version": VERSION,
        "scanned_at": dt.datetime.now(dt.timezone.utc).isoformat(timespec="seconds"),
        "target": {
            "type": args.target_type,
            "source": args.target_source,
            "commit": args.target_commit,
        },
        "summary": {
            "total_findings": len(findings),
            "by_severity": dict(by_sev),
            "by_category": dict(by_cat),
            "by_tool": dict(by_tool),
        },
        "findings": [asdict(f) for f in findings],
    }

    out = Path(args.output_dir)
    out.mkdir(parents=True, exist_ok=True)
    (out / "report.json").write_text(json.dumps(report, indent=2))
    (out / "report.md").write_text(render_markdown(report))

    print(
        f"vuln-scan: {len(findings)} finding(s) "
        f"[{by_sev.get('critical', 0)}c / {by_sev.get('high', 0)}h / "
        f"{by_sev.get('medium', 0)}m / {by_sev.get('low', 0)}l / {by_sev.get('info', 0)}i]",
        file=sys.stderr,
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
