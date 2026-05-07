# vuln-scan

Wrapper around a battery of OSS static-analysis tools. Point it at a git URL or
a local directory; it runs the relevant scanners and emits a single JSON +
Markdown report so an AI agent (or a human) can ingest the findings.

## What it runs

| Tool         | Vulnerability classes                                          |
|--------------|----------------------------------------------------------------|
| semgrep      | injection, path/network, auth/access, crypto, deser, protocol  |
| bandit       | Python: crypto, deser, injection, shell                        |
| gosec        | Go: crypto, injection, SSRF, hardcoded creds                   |
| cppcheck     | C/C++: memory safety, undefined behaviour, leaks               |
| flawfinder   | C/C++: unsafe-API smell pass                                   |
| regexploit   | Python/JS regex literals → ReDoS                               |
| trufflehog   | secret detection (filesystem)                                  |
| trivy        | SCA, IaC misconfiguration, embedded secrets                    |

Tools that don't apply (no Python files? bandit is skipped) self-skip based on
filetype detection.

## Install (Debian/Ubuntu — devenv VM)

```sh
./install.sh
```

Idempotent. Pulls C/C++ analyzers from apt, the rest via pipx / go install /
release tarball / vendor apt repo.

## Run

```sh
./scan.sh https://github.com/owner/repo.git           # clone + scan
./scan.sh /path/to/local/checkout                     # scan in place
./scan.sh URL -o /tmp/results --keep                  # custom output, keep clone
```

Output (default `./vuln-scan-<timestamp>/`):

```
report.json    unified machine-readable report
report.md      Markdown summary
raw/           per-tool outputs as the tools natively produce them
source/        cloned source (only for git URLs; deleted unless --keep)
```

## Unified JSON schema

```json
{
  "tool": "vuln-scan",
  "version": "1.0.0",
  "scanned_at": "ISO-8601",
  "target": {"type": "git|filesystem", "source": "...", "commit": "..."},
  "summary": {
    "total_findings": 42,
    "by_severity": {"critical": 1, "high": 5, "medium": 12, "low": 18, "info": 6},
    "by_category": {"injection": 8, "memory_safety": 4, "...": 0},
    "by_tool": {"semgrep": 20, "bandit": 8, "...": 0}
  },
  "findings": [
    {
      "tool": "semgrep",
      "rule_id": "python.lang.security.audit...",
      "category": "injection",
      "severity": "high",
      "file": "app/db.py",
      "line_start": 42,
      "line_end": 42,
      "message": "...",
      "cwe": ["CWE-89"],
      "snippet": "...",
      "url": "https://semgrep.dev/r?q=..."
    }
  ]
}
```

Categories are the eight from `SECURITY-TOOLS.md` plus three "adjacent"
buckets used by trufflehog/trivy: `secrets`, `dependency`,
`iac_misconfiguration`, plus `uncategorized` for findings without a CWE
mapping. Severity is normalised to `critical | high | medium | low | info`.

## Notes for AI-agent consumers

- `report.json` is the source of truth — `report.md` is a human view.
- Findings without a CWE fall back to `uncategorized`; the tool/rule_id is
  still authoritative.
- gosec needs a Go module (`go.mod`); regexploit only inspects Python/JS
  regex literals; clang-tidy needs a `compile_commands.json` (not invoked
  by default — drop into `raw/` manually if you have one).
- The unified report does not de-duplicate. Two tools flagging the same line
  are kept separately so an agent can use the second tool's report as
  corroboration.

## License

MIT
