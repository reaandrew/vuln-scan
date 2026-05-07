#!/usr/bin/env bash
# Run every bench/<target>.sh and print a one-line summary per target.
set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
chmod +x "$SCRIPT_DIR"/*.sh

for runner in "$SCRIPT_DIR"/dvwa.sh "$SCRIPT_DIR"/nodegoat.sh "$SCRIPT_DIR"/django.sh; do
    [ -x "$runner" ] || continue
    "$runner" 2>&1 | tail -1
done
