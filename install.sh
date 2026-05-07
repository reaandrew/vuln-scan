#!/usr/bin/env bash
# Install vuln-scan dependencies on Debian/Ubuntu (the devenv VM).
# Idempotent — safe to re-run.
set -euo pipefail

log() { printf '\n\033[1;36m==> %s\033[0m\n' "$*"; }

[ -r /etc/profile.d/devenv-paths.sh ] && . /etc/profile.d/devenv-paths.sh
export PATH="$HOME/.local/bin:$PATH"

log "apt: jq, git, python3, pipx, build-essential, cppcheck, flawfinder, clang-tools, clang-tidy"
sudo apt-get update -qq
sudo DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
    build-essential ca-certificates clang-tidy clang-tools cppcheck curl \
    flawfinder git jq pipx python3 python3-venv

log "pipx: semgrep, bandit, regexploit"
for t in semgrep bandit regexploit; do
    pipx install --quiet "$t" 2>/dev/null || pipx upgrade --quiet "$t" 2>/dev/null || true
done
pipx ensurepath >/dev/null

log "go install: gosec (requires Go on PATH)"
if command -v go >/dev/null && ! command -v gosec >/dev/null; then
    GOBIN="$HOME/go/bin" go install github.com/securego/gosec/v2/cmd/gosec@latest
fi

log "trufflehog (release tarball)"
if ! command -v trufflehog >/dev/null; then
    TH_VER="$(curl -fsSL https://api.github.com/repos/trufflesecurity/trufflehog/releases/latest | jq -r .tag_name | sed 's/^v//')"
    curl -fsSL "https://github.com/trufflesecurity/trufflehog/releases/download/v${TH_VER}/trufflehog_${TH_VER}_linux_amd64.tar.gz" \
        | sudo tar -xzC /usr/local/bin trufflehog
fi

log "gitleaks (release tarball)"
if ! command -v gitleaks >/dev/null; then
    GL_VER="$(curl -fsSL https://api.github.com/repos/gitleaks/gitleaks/releases/latest | jq -r .tag_name | sed 's/^v//')"
    curl -fsSL "https://github.com/gitleaks/gitleaks/releases/download/v${GL_VER}/gitleaks_${GL_VER}_linux_x64.tar.gz" \
        | sudo tar -xzC /usr/local/bin gitleaks
fi

log "osv-scanner (release tarball)"
if ! command -v osv-scanner >/dev/null; then
    sudo curl -fsSL -o /usr/local/bin/osv-scanner \
        "https://github.com/google/osv-scanner/releases/latest/download/osv-scanner_linux_amd64"
    sudo chmod +x /usr/local/bin/osv-scanner
fi

log "checkov + njsscan via pipx"
for t in checkov njsscan; do
    pipx install --quiet "$t" 2>/dev/null || pipx upgrade --quiet "$t" 2>/dev/null || true
done

log "trivy (aquasecurity apt repo)"
if ! command -v trivy >/dev/null; then
    sudo install -m 0755 -d /etc/apt/keyrings
    curl -fsSL https://aquasecurity.github.io/trivy-repo/deb/public.key \
        | sudo tee /etc/apt/keyrings/trivy.asc >/dev/null
    sudo chmod go+r /etc/apt/keyrings/trivy.asc
    echo "deb [signed-by=/etc/apt/keyrings/trivy.asc] https://aquasecurity.github.io/trivy-repo/deb generic main" \
        | sudo tee /etc/apt/sources.list.d/trivy.list >/dev/null
    sudo apt-get update -qq
    sudo apt-get install -y trivy
fi

log "warm semgrep rule packs"
semgrep --config p/security-audit --config p/owasp-top-ten --config p/cwe-top-25 \
    --metrics off --quiet --error --severity ERROR /dev/null >/dev/null 2>&1 || true

log "vuln-scan dependencies installed"
