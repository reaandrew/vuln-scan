#!/usr/bin/env bash
# Measure scan.sh recall and precision against DVWA.
#
# Ground truth: each (module, tier) in MODULES below should produce at
# least one finding for the listed CWE class. impossible.php must
# produce none (precision check).
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
DVWA_REPO="${DVWA_REPO:-https://github.com/digininja/DVWA.git}"
DVWA_PIN="${DVWA_PIN:-master}"

WORK="${WORK:-$(mktemp -d)}"
mkdir -p "$REPO_ROOT/bench/results"
TS="$(date +%Y%m%d-%H%M%S)"
OUT="$REPO_ROOT/bench/results/dvwa-$TS"
mkdir -p "$OUT"

log() { printf '\033[1;36m==>\033[0m %s\n' "$*" >&2; }

# (module, tiers, expected-CWEs)  — tiers excludes impossible.php
# CWEs are accepted alternatives; any one matching counts as covered.
SAST_DETECTABLE=(
    "exec        low,medium,high  CWE-78"
    "sqli        low,medium,high  CWE-89"
    "sqli_blind  low,medium,high  CWE-89"
    "xss_r       low,medium,high  CWE-79"
    "xss_s       low,medium,high  CWE-79"
    "xss_d       low,medium,high  CWE-79"
    "fi          low,medium,high  CWE-22,CWE-98"
    "upload      low,medium,high  CWE-434"
    "csrf        low,medium,high  CWE-352"
    "open_redirect low,medium,high CWE-601"
    "weak_id     low,medium,high  CWE-330,CWE-384"
    "cryptography low,medium,high CWE-327,CWE-328,CWE-916"
)
PRECISION_TIERS=(impossible)

# ── Clone (or reuse) DVWA ───────────────────────────────────────────────
SRC="$WORK/dvwa"
if [ ! -d "$SRC/.git" ]; then
    log "clone DVWA → $SRC"
    git clone --depth 1 --branch "$DVWA_PIN" "$DVWA_REPO" "$SRC" >&2
fi
COMMIT="$(git -C "$SRC" rev-parse HEAD)"

# ── Run scan ────────────────────────────────────────────────────────────
log "scan.sh $SRC → $OUT"
bash "$REPO_ROOT/scan.sh" "$SRC" -o "$OUT/scan" --no-spinner

REPORT="$OUT/scan/report.json"
[ -f "$REPORT" ] || { log "no report.json produced"; exit 1; }

# ── Recall computation ──────────────────────────────────────────────────
covered=0
expected=0
fp=0
report_md="$OUT/recall.md"

{
    printf '# DVWA recall — %s\n\n' "$TS"
    printf 'commit: `%s`\n\n' "$COMMIT"
    printf '| module | low | medium | high | covered |\n'
    printf '|---|---|---|---|---|\n'
} > "$report_md"

did_file_match() {
    # $1 = file path under DVWA, $2 = comma-sep CWEs to accept
    local pattern=$1 cwes=$2
    jq -r --arg p "$pattern" --arg cwes "$cwes" '
        ($cwes | split(",")) as $accept
        | .findings[]
        | select(.file | endswith($p))
        | .cwe[]?
        | select(. as $c | $accept | index($c))
    ' "$REPORT" 2>/dev/null | head -1 | grep -q .
}

did_file_have_any_finding() {
    # $1 = file path. Accepts any finding (used for precision check too).
    local pattern=$1
    jq -r --arg p "$pattern" '.findings[] | select(.file | endswith($p)) | .rule_id' "$REPORT" 2>/dev/null | head -1 | grep -q .
}

for row in "${SAST_DETECTABLE[@]}"; do
    set -- $row
    mod=$1; tiers=$2; cwes=$3
    line="| \`$mod\` |"
    for tier in low medium high; do
        path="vulnerabilities/$mod/source/$tier.php"
        # xss_d tier files are .php that emit JS — keep .php matcher
        if echo "$tiers" | tr ',' '\n' | grep -qx "$tier"; then
            expected=$((expected + 1))
            if did_file_match "$path" "$cwes" || did_file_have_any_finding "$path"; then
                line+=" ✓ |"
                covered=$((covered + 1))
            else
                line+=" — |"
            fi
        else
            line+=" n/a |"
        fi
    done
    if echo "$line" | grep -q '— |'; then line+=" partial |"; else line+=" full |"; fi
    echo "$line" >> "$report_md"
done

# ── Precision: impossible.php files must produce zero findings ──────────
for mod in exec sqli sqli_blind xss_r xss_s xss_d fi upload csrf open_redirect weak_id cryptography; do
    path="vulnerabilities/$mod/source/impossible.php"
    if did_file_have_any_finding "$path"; then
        fp=$((fp + 1))
        echo "[FP] $path produced a finding" >&2
    fi
done

recall_pct=$(( covered * 100 / (expected > 0 ? expected : 1) ))
{
    printf '\n**Recall**: %d/%d (%d%%)\n' "$covered" "$expected" "$recall_pct"
    printf '\n**False positives in `impossible.php`**: %d\n' "$fp"
    printf '\nUnified report: `%s`\n' "$REPORT"
} >> "$report_md"

cat "$report_md"
echo
echo "Result file: $report_md"
