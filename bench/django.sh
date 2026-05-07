#!/usr/bin/env bash
# Recall benchmark for django.nV (Python / Django).
set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
. "$SCRIPT_DIR/lib.sh"

NAME=django
URL=${DJANGO_REPO:-https://github.com/nVisium/django.nV.git}
REF=${DJANGO_REF:-default}

WORK=${WORK:-$(mktemp -d)}
TS=$(date +%Y%m%d-%H%M%S)
OUT=$REPO_ROOT/bench/results/${NAME}-${TS}
mkdir -p "$OUT"

SRC=$WORK/$NAME
COMMIT=$(bench_clone "$URL" "$REF" "$SRC")

bench_scan "$SRC" "$OUT"
REPORT=$OUT/scan/report.json

read covered expected fp < <(bench_compute_recall \
    "$REPORT" \
    "$SCRIPT_DIR/${NAME}.expected.txt" \
    "$SCRIPT_DIR/${NAME}.fp.txt")

recall_pct=$(( covered * 100 / (expected > 0 ? expected : 1) ))

{
    printf '# %s recall — %s\n\n' "$NAME" "$TS"
    printf 'commit: `%s`\n\n' "$COMMIT"
    printf '**Recall**: %d/%d (%d%%)\n' "$covered" "$expected" "$recall_pct"
    printf '\n**False positives in framework files**: %d\n' "$fp"
    printf '\nUnified report: `%s`\n' "$REPORT"
} | tee "$OUT/recall.md"

printf '%s recall=%d/%d (%d%%) fp=%d\n' \
    "$NAME" "$covered" "$expected" "$recall_pct" "$fp"
