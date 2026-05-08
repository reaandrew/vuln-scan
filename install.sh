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

log "go install: gosec, govulncheck (requires Go on PATH)"
if command -v go >/dev/null; then
    [ -x "$HOME/go/bin/gosec" ]        || GOBIN="$HOME/go/bin" go install github.com/securego/gosec/v2/cmd/gosec@latest
    [ -x "$HOME/go/bin/govulncheck" ]  || GOBIN="$HOME/go/bin" go install golang.org/x/vuln/cmd/govulncheck@latest
fi

log "ruby + brakeman (Rails SAST)"
sudo apt-get install -y --no-install-recommends ruby ruby-dev
if ! command -v brakeman >/dev/null; then
    sudo gem install --no-document brakeman
fi

log "retire.js (JS stale-library scanner) via npm"
if command -v npm >/dev/null && ! command -v retire >/dev/null; then
    sudo npm install -g retire
fi

log "tfsec (Terraform IaC scanner)"
if ! command -v tfsec >/dev/null; then
    TFS_VER="$(curl -fsSL https://api.github.com/repos/aquasecurity/tfsec/releases/latest | jq -r .tag_name | sed 's/^v//')"
    sudo curl -fsSL -o /usr/local/bin/tfsec \
        "https://github.com/aquasecurity/tfsec/releases/download/v${TFS_VER}/tfsec-linux-amd64"
    sudo chmod +x /usr/local/bin/tfsec
fi

log "hadolint (Dockerfile linter)"
if ! command -v hadolint >/dev/null; then
    sudo curl -fsSL -o /usr/local/bin/hadolint \
        https://github.com/hadolint/hadolint/releases/latest/download/hadolint-Linux-x86_64
    sudo chmod +x /usr/local/bin/hadolint
fi

log "PHP + composer + psalm (PHP taint analysis)"
sudo apt-get install -y --no-install-recommends php-cli php-mbstring php-xml php-curl unzip
if ! command -v composer >/dev/null; then
    curl -fsSL https://getcomposer.org/installer | php -- --quiet
    sudo mv composer.phar /usr/local/bin/composer
fi
if ! command -v psalm >/dev/null; then
    composer global require --quiet vimeo/psalm
    for cand in \
        "$HOME/.composer/vendor/bin/psalm" \
        "$HOME/.config/composer/vendor/bin/psalm" \
        /root/.composer/vendor/bin/psalm; do
        [ -x "$cand" ] && { sudo ln -sf "$cand" /usr/local/bin/psalm; break; }
    done
fi

log "JDK + findsecbugs-cli (JVM SAST; best-effort, scans .class/.jar)"
sudo apt-get install -y --no-install-recommends default-jre-headless default-jdk-headless
log "joern (CPG dataflow analysis, polyglot)"
JOERN_HOME=/opt/joern
JOERN_BIN=$JOERN_HOME/joern-cli
if [ ! -x "$JOERN_BIN/joern" ]; then
    sudo curl -fsSL -o /tmp/joern-install.sh \
        https://github.com/joernio/joern/releases/latest/download/joern-install.sh
    sudo bash /tmp/joern-install.sh --install-dir="$JOERN_HOME" --no-interactive
fi
sudo ln -sf "$JOERN_BIN/joern-scan"  /usr/local/bin/joern-scan
sudo ln -sf "$JOERN_BIN/joern-parse" /usr/local/bin/joern-parse
sudo ln -sf "$JOERN_BIN/joern"       /usr/local/bin/joern

log "Phan (PHP type-aware analyzer)"
sudo apt-get install -y --no-install-recommends php-ast || true
if ! command -v phan >/dev/null; then
    composer global require --quiet phan/phan
    for cand in \
        "$HOME/.composer/vendor/bin/phan" \
        "$HOME/.config/composer/vendor/bin/phan" \
        /root/.composer/vendor/bin/phan; do
        [ -x "$cand" ] && { sudo ln -sf "$cand" /usr/local/bin/phan; break; }
    done
fi

FSB_HOME=/opt/findsecbugs
if [ ! -x "$FSB_HOME/findsecbugs.sh" ]; then
    FSB_TAG="$(curl -fsSL https://api.github.com/repos/find-sec-bugs/find-sec-bugs/releases/latest | jq -r .tag_name)"
    FSB_NUM="${FSB_TAG#version-}"
    curl -fsSL -o /tmp/fsb.zip \
        "https://github.com/find-sec-bugs/find-sec-bugs/releases/download/${FSB_TAG}/findsecbugs-cli-${FSB_NUM}.zip"
    sudo mkdir -p "$FSB_HOME"
    sudo unzip -qo /tmp/fsb.zip -d "$FSB_HOME"
    sudo sed -i 's/\r$//' "$FSB_HOME/findsecbugs.sh"
    sudo chmod +x "$FSB_HOME/findsecbugs.sh"
    sudo ln -sf "$FSB_HOME/findsecbugs.sh" /usr/local/bin/findsecbugs
    rm -f /tmp/fsb.zip
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
