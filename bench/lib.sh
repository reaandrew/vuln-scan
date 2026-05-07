# shellcheck shell=bash
# Shared helpers for bench/<target>.sh runners.

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

bench_log() { printf '\033[1;36m==>\033[0m %s\n' "$*" >&2; }

# Clone a benchmark target (or reuse an existing checkout).
#  $1 = git URL
#  $2 = ref (branch / tag / sha) or "default"
#  $3 = local path to clone into
bench_clone() {
    local url=$1 ref=$2 dest=$3
    if [ -d "$dest/.git" ]; then
        bench_log "reuse $dest"
    else
        bench_log "clone $url → $dest"
        if [ "$ref" = "default" ]; then
            git clone --depth 1 "$url" "$dest" >&2
        else
            git clone "$url" "$dest" >&2
            git -C "$dest" checkout "$ref" >&2
        fi
    fi
    git -C "$dest" rev-parse HEAD
}

# Run scan.sh against $1 (source dir) and write results to $2 (output dir).
bench_scan() {
    local src=$1 out=$2
    bench_log "scan.sh $src → $out"
    bash "$REPO_ROOT/scan.sh" "$src" -o "$out/scan" --no-spinner >/dev/null 2>&1 || true
    [ -f "$out/scan/report.json" ]
}

# Did $1 (relative path under the scanned dir) produce any finding?
bench_file_has_finding() {
    local report=$1 path=$2
    jq -r --arg p "$path" '.findings[] | select(.file | endswith($p)) | .rule_id' \
        "$report" 2>/dev/null | head -1 | grep -q .
}

# Compute recall over a ground-truth list passed as: file<TAB>tier
# Returns "<covered> <expected> <fp>" on stdout.
#
# Args:
#   $1 = report.json
#   $2 = path to ground-truth file (one path per line; comments with #)
#   $3 = path to false-positive list (paths that should NOT have findings)
bench_compute_recall() {
    local report=$1 expected_list=$2 fp_list=$3
    local covered=0 expected=0 fp=0 path
    while IFS= read -r path; do
        [[ -z "$path" || "$path" =~ ^# ]] && continue
        expected=$((expected + 1))
        if bench_file_has_finding "$report" "$path"; then
            covered=$((covered + 1))
        fi
    done < "$expected_list"
    while IFS= read -r path; do
        [[ -z "$path" || "$path" =~ ^# ]] && continue
        if bench_file_has_finding "$report" "$path"; then
            fp=$((fp + 1))
            echo "[FP] $path produced a finding" >&2
        fi
    done < "$fp_list"
    printf '%d %d %d\n' "$covered" "$expected" "$fp"
}
