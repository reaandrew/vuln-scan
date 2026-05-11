#!/usr/bin/env bash
# vuln-scan — run a battery of OSS static analysers against a target,
# emit raw per-tool output and a unified JSON + Markdown report.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
. "$SCRIPT_DIR/lib/common.sh"

KEEP_CLONE=0
OUTPUT_DIR=""
TARGET=""
NO_HOST_CHECK=0
ENRICH=0
ENRICH_MODEL="${VULN_SCAN_ENRICH_MODEL:-qwen2.5:3b}"
OLLAMA_HOST="${VULN_SCAN_OLLAMA_HOST:-http://localhost:11434}"
ENRICH_LIMIT=0
AGENT=0
AGENT_PROVIDER="${VULN_SCAN_AGENT_PROVIDER:-anthropic}"
AGENT_MODEL="${VULN_SCAN_AGENT_MODEL:-}"
AGENT_MAX_STEPS="${VULN_SCAN_AGENT_MAX_STEPS:-40}"
AGENT_REGION="${VULN_SCAN_AGENT_REGION:-${AWS_REGION:-}}"
AGENT_PROFILE="${VULN_SCAN_AGENT_PROFILE:-${AWS_PROFILE:-}}"

usage() {
    cat <<EOF
Usage: scan.sh <git-url-or-path> [options]

  <git-url-or-path>  Either a git remote (https://…, git@…, ssh://…)
                     or a local directory.
  -o OUTPUT_DIR      Where to write results (default: ./vuln-scan-<ts>).
  --keep             For git URLs, keep the cloned source after scanning.
  --no-spinner       Plain output (also auto-detected when stderr is not a TTY).
  --no-host-check    Disable SSH host-key checking entirely.

  --enrich           Triage findings through a local LLM via Ollama (downloads
                     the model on first use, then caches).
  --enrich-model M   Model name (default: qwen2.5:3b).
  --ollama-host URL  Ollama endpoint (default: http://localhost:11434).
  --enrich-limit N   Cap LLM calls to the top N findings by severity (0=all).

  --agent            Run an LLM agent that audits files the static scanners
                     missed. Records new findings into the report.
  --agent-provider P Provider: anthropic | bedrock | ollama (default: anthropic).
                     Anthropic needs ANTHROPIC_API_KEY; Bedrock uses AWS creds.
  --agent-model M    Model name (provider-specific; see lib/providers/*.py).
  --agent-max-steps N  Cap tool-use iterations (default: 40).
  --aws-region R     AWS region for bedrock provider.
  --aws-profile P    AWS profile for bedrock provider.

Tool list and category mapping: see README.md
EOF
}

while [[ $# -gt 0 ]]; do
    case "$1" in
        -h|--help) usage; exit 0 ;;
        -o) OUTPUT_DIR="$2"; shift 2 ;;
        --keep) KEEP_CLONE=1; shift ;;
        --no-spinner) export NO_SPINNER=1; shift ;;
        --no-host-check) NO_HOST_CHECK=1; shift ;;
        --enrich) ENRICH=1; shift ;;
        --enrich-model) ENRICH_MODEL="$2"; shift 2 ;;
        --enrich-limit) ENRICH_LIMIT="$2"; shift 2 ;;
        --ollama-host) OLLAMA_HOST="$2"; shift 2 ;;
        --agent) AGENT=1; shift ;;
        --agent-provider) AGENT_PROVIDER="$2"; shift 2 ;;
        --agent-model) AGENT_MODEL="$2"; shift 2 ;;
        --agent-max-steps) AGENT_MAX_STEPS="$2"; shift 2 ;;
        --aws-region) AGENT_REGION="$2"; shift 2 ;;
        --aws-profile) AGENT_PROFILE="$2"; shift 2 ;;
        -*) die "Unknown option: $1 (try --help)" ;;
        *) [[ -z "$TARGET" ]] && TARGET="$1" || die "Multiple targets given"; shift ;;
    esac
done

[[ -n "$TARGET" ]] || { usage; exit 1; }

OUTPUT_DIR="${OUTPUT_DIR:-$(pwd)/vuln-scan-$(date +%Y%m%d-%H%M%S)}"
RAW="$OUTPUT_DIR/raw"
mkdir -p "$RAW"

# ── Resolve TARGET ───────────────────────────────────────────────────────
TARGET_TYPE=""; TARGET_SOURCE=""; TARGET_COMMIT=""; SCAN_DIR=""
if [[ "$TARGET" =~ ^(https?://|git@|git://|ssh://) ]]; then
    TARGET_TYPE=git
    TARGET_SOURCE="$TARGET"
    SCAN_DIR="$OUTPUT_DIR/source"
elif [[ -d "$TARGET" ]]; then
    TARGET_TYPE=filesystem
    SCAN_DIR="$(realpath "$TARGET")"
    TARGET_SOURCE="$SCAN_DIR"
else
    die "TARGET must be a git URL or an existing directory"
fi

# ── Detect-language helper (used after clone) ────────────────────────────
detect_lang() {
    local pat="$1"
    find "$SCAN_DIR" -path '*/.git' -prune -o -path '*/node_modules' -prune \
        -o -path '*/vendor' -prune -o -path '*/.venv' -prune \
        -o -type f \( $pat \) -print -quit 2>/dev/null | grep -q .
}

# ── Plan steps so the counter knows the total ────────────────────────────
# Step list order:
#   1: clone (only when git)
#   2: detect
#   3..N: tools (semgrep + conditionals)
#   N+1: aggregate
TOTAL=2  # detect + aggregate
[[ "$TARGET_TYPE" == "git" ]] && TOTAL=$((TOTAL + 1))
TOTAL=$((TOTAL + 1))            # semgrep (always)
TOTAL=$((TOTAL + 4))            # trufflehog + gitleaks + trivy + osv-scanner (always)
# Conditionals are computed after clone; bump the counter dynamically.
export STEP_TOTAL=$TOTAL

log "vuln-scan → $OUTPUT_DIR"

# ── Step: clone ──────────────────────────────────────────────────────────
# Force git to never prompt; SSH is non-interactive (BatchMode). Default is
# accept-new (TOFU); --no-host-check skips verification entirely.
export GIT_TERMINAL_PROMPT=0
if [ "$NO_HOST_CHECK" = "1" ]; then
    export GIT_SSH_COMMAND="${GIT_SSH_COMMAND:-ssh -o BatchMode=yes -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o LogLevel=ERROR}"
else
    export GIT_SSH_COMMAND="${GIT_SSH_COMMAND:-ssh -o BatchMode=yes -o StrictHostKeyChecking=accept-new}"
fi

if [[ "$TARGET_TYPE" == "git" ]]; then
    step_run "clone" "" git clone --depth 1 "$TARGET" "$SCAN_DIR"
    TARGET_COMMIT="$(git -C "$SCAN_DIR" rev-parse HEAD 2>/dev/null || true)"
elif git -C "$SCAN_DIR" rev-parse HEAD >/dev/null 2>&1; then
    TARGET_COMMIT="$(git -C "$SCAN_DIR" rev-parse HEAD)"
fi

# ── Step: detect languages ───────────────────────────────────────────────
HAS_PY=0; HAS_GO=0; HAS_C=0; HAS_JS=0; HAS_RB=0; HAS_GO_MOD=0; HAS_TF=0
HAS_PHP=0; HAS_DOCKER=0; HAS_JVM_BIN=0
detect_lang_step() {
    detect_lang '-name *.py'                              && HAS_PY=1 || true
    detect_lang '-name *.go'                              && HAS_GO=1 || true
    [[ -f "$SCAN_DIR/go.mod" ]]                           && HAS_GO_MOD=1 || true
    detect_lang '-name *.c -o -name *.cc -o -name *.cpp -o -name *.h -o -name *.hpp' && HAS_C=1 || true
    detect_lang '-name *.js -o -name *.jsx -o -name *.ts -o -name *.tsx -o -name *.mjs' && HAS_JS=1 || true
    { [[ -f "$SCAN_DIR/Gemfile" ]] || detect_lang '-name *.rb'; } && HAS_RB=1 || true
    detect_lang '-name *.tf -o -name *.tfvars'            && HAS_TF=1 || true
    detect_lang '-name *.php'                             && HAS_PHP=1 || true
    detect_lang '-name Dockerfile -o -name *.Dockerfile'  && HAS_DOCKER=1 || true
    detect_lang '-name *.class -o -name *.jar'            && HAS_JVM_BIN=1 || true
}
step_run "detect" "" detect_lang_step

# Recompute total now we know which conditionals fire.
extra=0
[[ $HAS_PY -eq 1 ]] && extra=$((extra + 2))     # bandit + regexploit-py
[[ $HAS_JS -eq 1 ]] && extra=$((extra + 1))     # regexploit-js
[[ $HAS_GO -eq 1 ]] && extra=$((extra + 1))     # gosec
[[ $HAS_GO_MOD -eq 1 ]] && extra=$((extra + 1)) # govulncheck
[[ $HAS_C -eq 1 ]]  && extra=$((extra + 2))     # cppcheck + flawfinder
[[ $HAS_RB -eq 1 ]] && extra=$((extra + 1))     # brakeman
[[ $HAS_JS -eq 1 ]] && extra=$((extra + 1))     # retire.js
[[ $HAS_TF -eq 1 ]] && extra=$((extra + 1))     # tfsec
[[ $HAS_PHP -eq 1 ]] && extra=$((extra + 1))    # psalm
[[ $HAS_DOCKER -eq 1 ]] && extra=$((extra + 1)) # hadolint
[[ $HAS_JVM_BIN -eq 1 ]] && extra=$((extra + 1))# spotbugs+find-sec-bugs
export STEP_TOTAL=$((STEP_TOTAL + extra))

log "detected — py:$HAS_PY go:$HAS_GO(mod:$HAS_GO_MOD) c/cpp:$HAS_C js/ts:$HAS_JS rb:$HAS_RB tf:$HAS_TF php:$HAS_PHP docker:$HAS_DOCKER jvm-bin:$HAS_JVM_BIN  (steps: $STEP_TOTAL)"

# ── Tool steps ───────────────────────────────────────────────────────────
step_run "semgrep" "$RAW/semgrep.json" \
    semgrep scan \
        --config p/security-audit \
        --config p/owasp-top-ten \
        --config p/cwe-top-25 \
        --config p/r2c-security-audit \
        --config p/xss \
        --config p/sql-injection \
        --config p/command-injection \
        --config p/insecure-transport \
        --config p/jwt \
        --config p/secrets \
        --config p/dockerfile \
        --config p/php \
        --config p/python \
        --config p/django \
        --config p/flask \
        --config p/javascript \
        --config p/typescript \
        --config p/java \
        --config p/golang \
        --config "$SCRIPT_DIR/rules" \
        --json --metrics off --quiet \
        --output "$RAW/semgrep.json" "$SCAN_DIR"

if [[ $HAS_PY -eq 1 ]]; then
    step_run "bandit" "$RAW/bandit.json" \
        bandit -r "$SCAN_DIR" -f json -o "$RAW/bandit.json" --quiet
    step_run "regexploit-py" "$RAW/regexploit-py.txt" \
        bash -c "regexploit-py '$SCAN_DIR' > '$RAW/regexploit-py.txt' 2>&1"
fi

if [[ $HAS_JS -eq 1 ]]; then
    step_run "regexploit-js" "$RAW/regexploit-js.txt" \
        bash -c "regexploit-js '$SCAN_DIR' > '$RAW/regexploit-js.txt' 2>&1"
fi

if [[ $HAS_GO -eq 1 ]]; then
    step_run "gosec" "$RAW/gosec.json" \
        bash -c "cd '$SCAN_DIR' && gosec -fmt json -out '$RAW/gosec.json' -quiet ./..."
fi

if [[ $HAS_GO_MOD -eq 1 ]] && command -v govulncheck >/dev/null; then
    step_run "govulncheck" "$RAW/govulncheck.json" \
        bash -c "cd '$SCAN_DIR' && govulncheck -json ./... > '$RAW/govulncheck.json' 2>/dev/null || true"
fi

if [[ $HAS_RB -eq 1 ]] && command -v brakeman >/dev/null; then
    step_run "brakeman" "$RAW/brakeman.json" \
        bash -c "brakeman --quiet --no-progress -o '$RAW/brakeman.json' -f json '$SCAN_DIR' 2>/dev/null || true"
fi

if [[ $HAS_JS -eq 1 ]] && command -v retire >/dev/null; then
    step_run "retire.js" "$RAW/retire.json" \
        bash -c "retire --path '$SCAN_DIR' --outputformat jsonsimple --outputpath '$RAW/retire.json' 2>/dev/null || true"
fi

if [[ $HAS_TF -eq 1 ]] && command -v tfsec >/dev/null; then
    step_run "tfsec" "$RAW/tfsec.json" \
        bash -c "tfsec --no-colour --format json --out '$RAW/tfsec.json' '$SCAN_DIR' 2>/dev/null || true"
fi

if [[ $HAS_DOCKER -eq 1 ]] && command -v hadolint >/dev/null; then
    step_run "hadolint" "$RAW/hadolint.json" \
        bash -c "find '$SCAN_DIR' \( -name Dockerfile -o -name '*.Dockerfile' \) -print0 \
                 | xargs -0 -r hadolint --format json > '$RAW/hadolint.json' 2>/dev/null || true"
fi

if [[ $HAS_PHP -eq 1 ]] && command -v psalm >/dev/null; then
    step_run "psalm" "$RAW/psalm.json" \
        bash -c "
            cfg='$OUTPUT_DIR/psalm.xml'
            cat > \"\$cfg\" <<XML
<?xml version=\"1.0\"?>
<psalm errorLevel=\"4\" findUnusedCode=\"false\" findUnusedBaselineEntry=\"false\">
  <projectFiles><directory name=\"$SCAN_DIR\"/></projectFiles>
</psalm>
XML
            psalm --config=\"\$cfg\" --root='$SCAN_DIR' --taint-analysis \
                  --output-format=json --no-progress --no-cache --threads=4 \
                  > '$RAW/psalm.json' 2>/dev/null || true
        "
fi

if command -v joern-scan >/dev/null; then
    export STEP_TOTAL=$((STEP_TOTAL + 1))
    step_run "joern-scan" "$RAW/joern.txt" \
        bash -c "joern-scan '$SCAN_DIR' > '$RAW/joern.txt' 2>/dev/null || true"
fi

if [[ $HAS_PHP -eq 1 ]] && command -v phan >/dev/null; then
    export STEP_TOTAL=$((STEP_TOTAL + 1))
    step_run "phan" "$RAW/phan.json" \
        bash -c "
            mkdir -p '$OUTPUT_DIR/.phan'
            cat > '$OUTPUT_DIR/.phan/config.php' <<PHP
<?php
return [
    'directory_list' => ['.'],
    'exclude_analysis_directory_list' => ['vendor/', 'node_modules/'],
    'plugins' => ['UnusedSuppressionPlugin'],
    'allow_missing_properties' => true,
    'null_casts_as_any_type' => true,
    'unused_variable_detection' => false,
];
PHP
            cd '$SCAN_DIR' && phan --no-progress-bar --output-mode=json \
                --config-file='$OUTPUT_DIR/.phan/config.php' \
                --output='$RAW/phan.json' 2>/dev/null || true
        "
fi

if [[ $HAS_JVM_BIN -eq 1 ]] && command -v findsecbugs >/dev/null; then
    step_run "find-sec-bugs" "$RAW/findsecbugs.xml" \
        bash -c "findsecbugs -nested:false -progress -high -xml:withMessages \
                 -output '$RAW/findsecbugs.xml' '$SCAN_DIR' 2>/dev/null || true"
fi

if [[ $HAS_C -eq 1 ]]; then
    step_run "cppcheck" "$RAW/cppcheck.xml" \
        bash -c "cppcheck --enable=all --inconclusive --xml --xml-version=2 --quiet '$SCAN_DIR' 2> '$RAW/cppcheck.xml'"
    step_run "flawfinder" "$RAW/flawfinder.csv" \
        bash -c "flawfinder --csv --quiet '$SCAN_DIR' > '$RAW/flawfinder.csv'"
fi

# njsscan — JS/Node specific (skipped silently when no JS files)
if [[ $HAS_JS -eq 1 ]] && command -v njsscan >/dev/null; then
    export STEP_TOTAL=$((STEP_TOTAL + 1))
    step_run "njsscan" "$RAW/njsscan.json" \
        bash -c "njsscan -o '$RAW/njsscan.json' --json '$SCAN_DIR' 2>/dev/null || true"
fi

# checkov — IaC (Terraform / k8s / CFN / ARM / Helm).
if command -v checkov >/dev/null; then
    export STEP_TOTAL=$((STEP_TOTAL + 1))
    step_run "checkov" "$RAW/checkov.json" \
        bash -c "checkov -d '$SCAN_DIR' -o json --quiet --compact > '$RAW/checkov.json' 2>/dev/null || true"
fi

step_run "trufflehog" "$RAW/trufflehog.jsonl" \
    bash -c "trufflehog filesystem '$SCAN_DIR' --json --no-update --no-verification > '$RAW/trufflehog.jsonl' 2>/dev/null"

step_run "gitleaks" "$RAW/gitleaks.json" \
    bash -c "gitleaks detect --source '$SCAN_DIR' --report-format json --report-path '$RAW/gitleaks.json' --no-banner --exit-code 0 2>/dev/null"

step_run "trivy" "$RAW/trivy.json" \
    bash -c "trivy fs --quiet --format json --output '$RAW/trivy.json' '$SCAN_DIR'"

step_run "osv-scanner" "$RAW/osv.json" \
    bash -c "osv-scanner --format json --output '$RAW/osv.json' --recursive '$SCAN_DIR' 2>/dev/null || true"

# ── Aggregate ────────────────────────────────────────────────────────────
step_run "aggregate" "" \
    python3 "$SCRIPT_DIR/lib/unify.py" \
        --raw-dir "$RAW" \
        --output-dir "$OUTPUT_DIR" \
        --target-type "$TARGET_TYPE" \
        --target-source "$TARGET_SOURCE" \
        --target-commit "$TARGET_COMMIT" \
        --scan-dir "$SCAN_DIR"

# ── Enrich (initialize → download → activate the LLM, then triage) ───────
ensure_ollama() {
    if ! command -v ollama >/dev/null; then
        die "ollama is not installed (run install.sh, or install via https://ollama.com)"
    fi
    if ! curl -sf "$OLLAMA_HOST/api/tags" >/dev/null 2>&1; then
        log "starting ollama serve"
        nohup ollama serve >/tmp/vuln-scan-ollama.log 2>&1 &
        for _ in $(seq 1 30); do
            sleep 1
            curl -sf "$OLLAMA_HOST/api/tags" >/dev/null 2>&1 && return 0
        done
        die "ollama serve did not become reachable in 30s (see /tmp/vuln-scan-ollama.log)"
    fi
}

ensure_model() {
    if curl -sf "$OLLAMA_HOST/api/tags" \
        | jq -e --arg m "$ENRICH_MODEL" '.models[]? | select(.name == $m or .name == ($m + ":latest"))' \
        >/dev/null 2>&1; then
        return 0
    fi
    log "pulling model $ENRICH_MODEL (one-time, ~2GB)"
    ollama pull "$ENRICH_MODEL" >&2
}

if [[ $ENRICH -eq 1 ]]; then
    export STEP_TOTAL=$((STEP_TOTAL + 3))
    step_run "ollama-init"  "" ensure_ollama
    step_run "ollama-model" "" ensure_model
    step_run "enrich" "" \
        python3 "$SCRIPT_DIR/lib/enrich.py" \
            --report "$OUTPUT_DIR/report.json" \
            --scan-dir "$SCAN_DIR" \
            --model "$ENRICH_MODEL" \
            --ollama-host "$OLLAMA_HOST" \
            --limit "$ENRICH_LIMIT"
fi

# ── Agent (LLM-driven audit of files the scanners didn't flag) ──────────
if [[ $AGENT -eq 1 ]]; then
    AGENT_ARGS=(
        --scan-dir  "$SCAN_DIR"
        --report    "$OUTPUT_DIR/report.json"
        --provider  "$AGENT_PROVIDER"
        --max-steps "$AGENT_MAX_STEPS"
    )
    [[ -n "$AGENT_MODEL"   ]] && AGENT_ARGS+=(--model "$AGENT_MODEL")
    [[ -n "$AGENT_REGION"  ]] && AGENT_ARGS+=(--bedrock-region "$AGENT_REGION")
    [[ -n "$AGENT_PROFILE" ]] && AGENT_ARGS+=(--bedrock-profile "$AGENT_PROFILE")
    [[ "$AGENT_PROVIDER" == "ollama" ]] && AGENT_ARGS+=(--ollama-host "$OLLAMA_HOST")

    if [[ "$AGENT_PROVIDER" == "ollama" ]]; then
        export STEP_TOTAL=$((STEP_TOTAL + 3))
        step_run "ollama-init"  "" ensure_ollama
        ENRICH_MODEL="${AGENT_MODEL:-qwen2.5:7b}" step_run "ollama-model" "" \
            bash -c 'ENRICH_MODEL="'"${AGENT_MODEL:-qwen2.5:7b}"'" '"$(declare -f ensure_model)"'; ensure_model'
    else
        export STEP_TOTAL=$((STEP_TOTAL + 1))
    fi
    step_run "agent" "" python3 "$SCRIPT_DIR/lib/agent.py" "${AGENT_ARGS[@]}"
fi

# ── Cleanup ──────────────────────────────────────────────────────────────
if [[ "$TARGET_TYPE" == "git" && $KEEP_CLONE -eq 0 ]]; then
    rm -rf "$SCAN_DIR"
fi

log "done"
TOTAL_FOUND=$(jq -r '.summary.total_findings' "$OUTPUT_DIR/report.json" 2>/dev/null || echo "?")
log "  $TOTAL_FOUND finding(s) — see $OUTPUT_DIR/report.{json,md}"
