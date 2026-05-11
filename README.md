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

## Run via Docker (recommended)

A prebuilt image is published to GHCR by CI on every push to `main`:

```sh
# Scan a git URL (no host install needed)
docker run --rm ghcr.io/reaandrew/vuln-scan:latest \
    https://github.com/owner/repo.git -o /tmp/out --keep

# Scan a local directory (mount it into /work)
docker run --rm -v "$PWD":/work ghcr.io/reaandrew/vuln-scan:latest \
    /work -o /work/results
```

Tags: `latest`, `main`, `sha-<short>`, and `vX.Y.Z` for git tags.

## Install locally (Debian/Ubuntu — devenv VM)

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
./scan.sh URL --enrich                                # add LLM triage (see below)
```

### LLM triage (`--enrich`)

Adds a post-scan pass that sends each finding to a local LLM via Ollama
and tags it with `false_positive_likelihood`, a plain-English
explanation, and a remediation hint. Three-step init runs only on first
use:

1. **initialize**: starts `ollama serve` in background if not already
   running.
2. **download**: pulls the model on first use (default `qwen2.5:3b`,
   ~2 GB). Cached under `~/.ollama/models/` on the host or under
   the Ollama volume in Docker.
3. **activate**: each finding is enriched in parallel; results cached
   under `~/.cache/vuln-scan/enrich.json` so re-runs are near-instant.

```sh
./scan.sh URL --enrich                              # default model
./scan.sh URL --enrich --enrich-model llama3.2:3b   # override
./scan.sh URL --enrich --enrich-limit 50            # cap LLM calls
./scan.sh URL --enrich --ollama-host http://192.0.2.10:11434
```

For Docker, mount a volume to persist the pulled model across runs:

```sh
docker run --rm -v ollama-data:/root/.ollama -v "$PWD":/work \
    ghcr.io/reaandrew/vuln-scan:latest /work --enrich
```

### Agentic mode (`--agent`)

Goes beyond review: an LLM with a small toolbox (`list_files`,
`read_file`, `search_code`, `record_finding`, `finish`) audits files
that the static scanners *didn't* flag and records new findings. The
loop is provider-agnostic; pick which LLM is in the driver's seat:

| Provider | Auth | Default model |
|---|---|---|
| `anthropic` (default) | `ANTHROPIC_API_KEY` env var | `claude-sonnet-4-6` |
| `bedrock` | AWS creds (env, profile, IAM role, aws-vault) | `anthropic.claude-sonnet-4-20250514-v1:0` |
| `ollama` | none (local) | `qwen2.5:7b` |

```sh
# Anthropic API
export ANTHROPIC_API_KEY=sk-ant-...
./scan.sh URL --agent

# Bedrock with named profile
./scan.sh URL --agent --agent-provider bedrock \
    --aws-profile personal --aws-region eu-west-2

# Local Ollama (slower, lower-quality but free + private)
./scan.sh URL --agent --agent-provider ollama --agent-model qwen2.5:7b

# Tune
./scan.sh URL --agent --agent-model claude-opus-4-5 --agent-max-steps 80
```

Agent findings land in `report.json` alongside the static-scanner
findings, tagged with `tool: "agent:<provider>:<model>"`. A separate
`agent-trace.json` captures the model's narration step-by-step for
debugging / auditing.

The agent is bounded:
- All tools resolve paths through the scan root; nothing reads or
  writes outside it.
- `search_code` uses `grep -E`, capped at 30 s and 100 matches.
- `read_file` caps at 300 lines per call.
- `--agent-max-steps` caps the tool-use loop.

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
