# shellcheck shell=bash
# Common helpers for scan.sh.

log() { printf '\033[1;36m==>\033[0m %s\n' "$*" >&2; }
warn() { printf '\033[1;33m[warn]\033[0m %s\n' "$*" >&2; }
die() { printf '\033[1;31m[error]\033[0m %s\n' "$*" >&2; exit 1; }

# Step counter — set by scan.sh.
STEP_TOTAL=${STEP_TOTAL:-0}
STEP_INDEX=0
NO_SPINNER=${NO_SPINNER:-0}

_is_tty() { [ -t 2 ] && [ "$NO_SPINNER" != "1" ]; }

# step_run NAME RAW_FILE_OR_EMPTY -- CMD ...
#
# Runs CMD with a spinner (when stderr is a TTY) showing the step number
# and elapsed time. After the command completes, prints a final line with
# ✓/! and timing, and (if RAW_FILE non-empty) a finding count parsed from
# that file. CMD's stdout/stderr go to /dev/null — tools should write
# their output to files via their own flags.
step_run() {
    local name=$1 raw=$2; shift 2
    STEP_INDEX=$((STEP_INDEX + 1))
    local start=$SECONDS
    local label
    label="$(printf '[%d/%d] %-13s' "$STEP_INDEX" "$STEP_TOTAL" "$name")"

    local spin_pid=""
    if _is_tty; then
        (
            local frames='⠋⠙⠹⠸⠼⠴⠦⠧⠇⠏'
            local i=0
            while :; do
                printf '\r  %s %s %ds ' "$label" "${frames:i++ % ${#frames}:1}" $((SECONDS - start)) >&2
                sleep 0.1
            done
        ) &
        spin_pid=$!
    fi

    local rc=0
    "$@" >/dev/null 2>&1 || rc=$?

    if [ -n "$spin_pid" ]; then
        kill "$spin_pid" 2>/dev/null || true
        wait "$spin_pid" 2>/dev/null || true
    fi

    local elapsed=$((SECONDS - start))
    local found=""
    if [ -n "$raw" ] && [ -f "$raw" ]; then
        found=" ($(_count_findings "$raw" "$name") findings)"
    fi
    local mark
    if [ $rc -eq 0 ]; then mark='\033[32m✓\033[0m'; else mark='\033[33m!\033[0m'; fi
    printf '\r  %s %b %ds%s\033[K\n' "$label" "$mark" "$elapsed" "$found" >&2
    return 0
}

step_skip() {
    local name=$1 reason=$2
    STEP_INDEX=$((STEP_INDEX + 1))
    printf '  [%d/%d] %-13s \033[2m· skipped (%s)\033[0m\n' \
        "$STEP_INDEX" "$STEP_TOTAL" "$name" "$reason" >&2
}

_count_findings() {
    local file=$1 tool=$2
    case "$tool" in
        semgrep)    jq -r '.results | length' "$file" 2>/dev/null || echo "?" ;;
        bandit)     jq -r '.results | length' "$file" 2>/dev/null || echo "?" ;;
        gosec)      jq -r '.Issues // [] | length' "$file" 2>/dev/null || echo "?" ;;
        trivy)      jq -r '[.Results[]? | ((.Vulnerabilities? // []) + (.Misconfigurations? // []) + (.Secrets? // []))[]] | length' "$file" 2>/dev/null || echo "?" ;;
        trufflehog) awk 'NF' "$file" 2>/dev/null | wc -l | tr -d ' ' ;;
        cppcheck)   grep -c '<error ' "$file" 2>/dev/null || echo 0 ;;
        flawfinder) python3 -c "import csv; print(sum(1 for _ in csv.DictReader(open('$file'))))" 2>/dev/null || echo "?" ;;
        regexploit*) grep -c 'Vulnerable regex' "$file" 2>/dev/null || echo 0 ;;
        *)          echo "?" ;;
    esac
}
