#!/usr/bin/env bash
# vuln-scan — run a battery of OSS static analysers against a target,
# emit raw per-tool output and a unified JSON + Markdown report.
#
# Usage:
#   scan.sh <git-url-or-path> [-o OUTPUT_DIR] [--keep]
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
. "$SCRIPT_DIR/lib/common.sh"

KEEP_CLONE=0
OUTPUT_DIR=""
TARGET=""

usage() {
    cat <<EOF
Usage: scan.sh <git-url-or-path> [-o OUTPUT_DIR] [--keep]

  <git-url-or-path>  Either a git remote (https://…, git@…, ssh://…)
                     or a local directory.
  -o OUTPUT_DIR      Where to write results (default: ./vuln-scan-<ts>).
  --keep             For git URLs, keep the cloned source after scanning.

Tool list and category mapping: see README.md
EOF
}

while [[ $# -gt 0 ]]; do
    case "$1" in
        -h|--help) usage; exit 0 ;;
        -o) OUTPUT_DIR="$2"; shift 2 ;;
        --keep) KEEP_CLONE=1; shift ;;
        -*) die "Unknown option: $1 (try --help)" ;;
        *) [[ -z "$TARGET" ]] && TARGET="$1" || die "Multiple targets given"; shift ;;
    esac
done

[[ -n "$TARGET" ]] || { usage; exit 1; }

OUTPUT_DIR="${OUTPUT_DIR:-$(pwd)/vuln-scan-$(date +%Y%m%d-%H%M%S)}"
mkdir -p "$OUTPUT_DIR/raw"

# ── Resolve TARGET ───────────────────────────────────────────────────────
TARGET_TYPE=""; TARGET_SOURCE=""; TARGET_COMMIT=""
if [[ "$TARGET" =~ ^(https?://|git@|git://|ssh://) ]]; then
    TARGET_TYPE=git
    TARGET_SOURCE="$TARGET"
    SCAN_DIR="$OUTPUT_DIR/source"
    log "clone $TARGET → $SCAN_DIR"
    git clone --depth 1 "$TARGET" "$SCAN_DIR" 2>&1 | tail -2
    TARGET_COMMIT="$(git -C "$SCAN_DIR" rev-parse HEAD)"
elif [[ -d "$TARGET" ]]; then
    TARGET_TYPE=filesystem
    SCAN_DIR="$(realpath "$TARGET")"
    TARGET_SOURCE="$SCAN_DIR"
    if git -C "$SCAN_DIR" rev-parse HEAD >/dev/null 2>&1; then
        TARGET_COMMIT="$(git -C "$SCAN_DIR" rev-parse HEAD)"
    fi
else
    die "TARGET must be a git URL or an existing directory"
fi

log "target: $TARGET_TYPE @ $TARGET_SOURCE${TARGET_COMMIT:+ (commit $TARGET_COMMIT)}"

# ── Detect languages present ─────────────────────────────────────────────
detect_lang() {
    local pat="$1"
    find "$SCAN_DIR" -path '*/.git' -prune -o -path '*/node_modules' -prune \
        -o -path '*/vendor' -prune -o -path '*/.venv' -prune \
        -o -type f \( $pat \) -print -quit 2>/dev/null | grep -q .
}

HAS_PY=0; HAS_GO=0; HAS_C=0; HAS_JS=0
detect_lang '-name *.py'                              && HAS_PY=1 || true
[[ -f "$SCAN_DIR/go.mod" ]] || detect_lang '-name *.go' && HAS_GO=1 || true
detect_lang '-name *.c -o -name *.cc -o -name *.cpp -o -name *.h -o -name *.hpp' && HAS_C=1 || true
detect_lang '-name *.js -o -name *.jsx -o -name *.ts -o -name *.tsx -o -name *.mjs' && HAS_JS=1 || true
log "detected — py:$HAS_PY go:$HAS_GO c/cpp:$HAS_C js/ts:$HAS_JS"

# ── Run tools ────────────────────────────────────────────────────────────
RAW="$OUTPUT_DIR/raw"
run() { local name="$1"; shift; log "run: $name"; "$@" || warn "$name returned non-zero — continuing"; }

# Semgrep — polyglot, covers most categories
run semgrep \
    semgrep scan --config p/security-audit --config p/owasp-top-ten \
        --config p/cwe-top-25 --json --metrics off --quiet \
        --output "$RAW/semgrep.json" "$SCAN_DIR"

# Bandit — Python
[[ $HAS_PY -eq 1 ]] && run bandit \
    bandit -r "$SCAN_DIR" -f json -o "$RAW/bandit.json" --quiet

# regexploit — ReDoS in Python regex literals
[[ $HAS_PY -eq 1 ]] && run regexploit-py \
    bash -c "regexploit-py '$SCAN_DIR' > '$RAW/regexploit-py.txt' 2>&1"
[[ $HAS_JS -eq 1 ]] && run regexploit-js \
    bash -c "regexploit-js '$SCAN_DIR' > '$RAW/regexploit-js.txt' 2>&1"

# gosec — Go
if [[ $HAS_GO -eq 1 ]]; then
    run gosec \
        bash -c "cd '$SCAN_DIR' && gosec -fmt json -out '$RAW/gosec.json' -quiet ./..."
fi

# cppcheck + flawfinder — C/C++
if [[ $HAS_C -eq 1 ]]; then
    run cppcheck \
        bash -c "cppcheck --enable=all --inconclusive --xml --xml-version=2 --quiet '$SCAN_DIR' 2> '$RAW/cppcheck.xml'"
    run flawfinder \
        bash -c "flawfinder --csv --quiet '$SCAN_DIR' > '$RAW/flawfinder.csv'"
fi

# trufflehog — secrets (always)
run trufflehog \
    bash -c "trufflehog filesystem '$SCAN_DIR' --json --no-update --no-verification > '$RAW/trufflehog.jsonl' 2>/dev/null"

# trivy — SCA / IaC (always)
run trivy \
    bash -c "trivy fs --quiet --format json --output '$RAW/trivy.json' '$SCAN_DIR'"

# ── Aggregate ────────────────────────────────────────────────────────────
log "aggregate → unified report"
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
echo "  unified JSON: $OUTPUT_DIR/report.json"
echo "  markdown    : $OUTPUT_DIR/report.md"
echo "  raw outputs : $OUTPUT_DIR/raw/"
