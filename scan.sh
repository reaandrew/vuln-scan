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

usage() {
    cat <<EOF
Usage: scan.sh <git-url-or-path> [-o OUTPUT_DIR] [--keep] [--no-spinner] [--no-host-check]

  <git-url-or-path>  Either a git remote (https://…, git@…, ssh://…)
                     or a local directory.
  -o OUTPUT_DIR      Where to write results (default: ./vuln-scan-<ts>).
  --keep             For git URLs, keep the cloned source after scanning.
  --no-spinner       Plain output (also auto-detected when stderr is not a TTY).
  --no-host-check    Disable SSH host-key checking entirely. Convenient for
                     ephemeral scans; default is accept-new (TOFU).

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
HAS_PY=0; HAS_GO=0; HAS_C=0; HAS_JS=0; HAS_RB=0; HAS_GO_MOD=0
detect_lang_step() {
    detect_lang '-name *.py'                              && HAS_PY=1 || true
    detect_lang '-name *.go'                              && HAS_GO=1 || true
    [[ -f "$SCAN_DIR/go.mod" ]]                           && HAS_GO_MOD=1 || true
    detect_lang '-name *.c -o -name *.cc -o -name *.cpp -o -name *.h -o -name *.hpp' && HAS_C=1 || true
    detect_lang '-name *.js -o -name *.jsx -o -name *.ts -o -name *.tsx -o -name *.mjs' && HAS_JS=1 || true
    { [[ -f "$SCAN_DIR/Gemfile" ]] || detect_lang '-name *.rb'; } && HAS_RB=1 || true
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
export STEP_TOTAL=$((STEP_TOTAL + extra))

log "detected — py:$HAS_PY go:$HAS_GO(mod:$HAS_GO_MOD) c/cpp:$HAS_C js/ts:$HAS_JS rb:$HAS_RB  (steps: $STEP_TOTAL)"

# ── Tool steps ───────────────────────────────────────────────────────────
step_run "semgrep" "$RAW/semgrep.json" \
    semgrep scan \
        --config p/security-audit \
        --config p/owasp-top-ten \
        --config p/cwe-top-25 \
        --config p/xss \
        --config p/php \
        --config p/insecure-transport \
        --config p/jwt \
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

# ── Cleanup ──────────────────────────────────────────────────────────────
if [[ "$TARGET_TYPE" == "git" && $KEEP_CLONE -eq 0 ]]; then
    rm -rf "$SCAN_DIR"
fi

log "done"
TOTAL_FOUND=$(jq -r '.summary.total_findings' "$OUTPUT_DIR/report.json" 2>/dev/null || echo "?")
log "  $TOTAL_FOUND finding(s) — see $OUTPUT_DIR/report.{json,md}"
