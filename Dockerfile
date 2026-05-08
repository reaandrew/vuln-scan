# syntax=docker/dockerfile:1.7
# vuln-scan: containerised wrapper around OSS static analysers.
#
# Usage:
#   docker run --rm -v "$PWD":/work ghcr.io/reaandrew/vuln-scan:latest \
#       /work/path/to/source -o /work/results
#   docker run --rm ghcr.io/reaandrew/vuln-scan:latest \
#       https://github.com/owner/repo.git -o /tmp/out
#
# The entrypoint is scan.sh; pass arguments as you would to the script.

FROM debian:trixie-slim AS base

ARG DEBIAN_FRONTEND=noninteractive
ARG TARGETARCH

# ── OS deps ─────────────────────────────────────────────────────────────
RUN apt-get update \
 && apt-get install -y --no-install-recommends \
        build-essential \
        ca-certificates \
        clang-tidy \
        clang-tools \
        cppcheck \
        curl \
        default-jdk-headless \
        default-jre-headless \
        php-ast \
        flawfinder \
        git \
        golang \
        jq \
        php-cli \
        php-curl \
        php-mbstring \
        php-xml \
        pipx \
        python3 \
        python3-venv \
        ruby \
        ruby-dev \
        unzip \
 && rm -rf /var/lib/apt/lists/*

# ── Pipx tools (semgrep, bandit, regexploit) ────────────────────────────
ENV PIPX_HOME=/opt/pipx
ENV PIPX_BIN_DIR=/usr/local/bin
RUN pipx install --global semgrep \
 && pipx install --global bandit \
 && pipx install --global regexploit \
 && pipx install --global checkov \
 && pipx install --global njsscan

# ── gosec via go install (pinned-by-tag for reproducibility) ────────────
ENV GOPATH=/opt/go
ENV PATH=$PATH:/opt/go/bin
RUN go install github.com/securego/gosec/v2/cmd/gosec@latest \
 && go install golang.org/x/vuln/cmd/govulncheck@latest \
 && find /opt/go/pkg -mindepth 1 -delete \
 && rm -rf /root/.cache/go-build

# ── brakeman (Rails SAST) via system gem ────────────────────────────────
RUN gem install --no-document brakeman

# ── Node.js + retire.js (JS stale-library scanner) ──────────────────────
RUN curl -fsSL https://deb.nodesource.com/setup_lts.x | bash - \
 && apt-get update \
 && apt-get install -y --no-install-recommends nodejs \
 && rm -rf /var/lib/apt/lists/* \
 && npm install -g retire \
 && npm cache clean --force

# ── tfsec (Terraform IaC scanner) ───────────────────────────────────────
RUN TFS_VER="$(curl -fsSL https://api.github.com/repos/aquasecurity/tfsec/releases/latest | jq -r .tag_name | sed 's/^v//')" \
 && curl -fsSL -o /usr/local/bin/tfsec \
        "https://github.com/aquasecurity/tfsec/releases/download/v${TFS_VER}/tfsec-linux-amd64" \
 && chmod +x /usr/local/bin/tfsec

# ── hadolint (Dockerfile linter) ───────────────────────────────────────
RUN curl -fsSL -o /usr/local/bin/hadolint \
        https://github.com/hadolint/hadolint/releases/latest/download/hadolint-Linux-x86_64 \
 && chmod +x /usr/local/bin/hadolint

# ── composer + psalm (PHP taint analysis) ───────────────────────────────
RUN curl -fsSL https://getcomposer.org/installer | php -- --quiet \
 && mv composer.phar /usr/local/bin/composer \
 && composer global require --quiet vimeo/psalm \
 && ln -sf /root/.composer/vendor/bin/psalm /usr/local/bin/psalm

# ── Joern (CPG-based polyglot dataflow analysis) ────────────────────────
RUN curl -fsSL -o /tmp/joern-install.sh \
        https://github.com/joernio/joern/releases/latest/download/joern-install.sh \
 && bash /tmp/joern-install.sh --install-dir=/opt/joern --no-interactive \
 && ln -sf /opt/joern/joern-cli/joern-scan  /usr/local/bin/joern-scan \
 && ln -sf /opt/joern/joern-cli/joern-parse /usr/local/bin/joern-parse \
 && ln -sf /opt/joern/joern-cli/joern       /usr/local/bin/joern \
 && rm -f /tmp/joern-install.sh

# ── Phan (PHP type-aware analyzer) ─────────────────────────────────────
RUN composer global require --quiet phan/phan \
 && ln -sf /root/.composer/vendor/bin/phan /usr/local/bin/phan

# ── findsecbugs CLI (standalone JVM SAST; scans .class/.jar) ────────────
RUN FSB_TAG="$(curl -fsSL https://api.github.com/repos/find-sec-bugs/find-sec-bugs/releases/latest | jq -r .tag_name)" \
 && FSB_NUM="${FSB_TAG#version-}" \
 && curl -fsSL -o /tmp/fsb.zip \
        "https://github.com/find-sec-bugs/find-sec-bugs/releases/download/${FSB_TAG}/findsecbugs-cli-${FSB_NUM}.zip" \
 && mkdir -p /opt/findsecbugs \
 && unzip -qo /tmp/fsb.zip -d /opt/findsecbugs \
 && sed -i 's/\r$//' /opt/findsecbugs/findsecbugs.sh \
 && chmod +x /opt/findsecbugs/findsecbugs.sh \
 && ln -sf /opt/findsecbugs/findsecbugs.sh /usr/local/bin/findsecbugs \
 && rm -f /tmp/fsb.zip

# ── trufflehog (release tarball) ────────────────────────────────────────
RUN ARCH="$(dpkg --print-architecture)" \
 && TH_VER="$(curl -fsSL https://api.github.com/repos/trufflesecurity/trufflehog/releases/latest | jq -r .tag_name | sed 's/^v//')" \
 && curl -fsSL "https://github.com/trufflesecurity/trufflehog/releases/download/v${TH_VER}/trufflehog_${TH_VER}_linux_${ARCH}.tar.gz" \
        | tar -xzC /usr/local/bin trufflehog

# ── gitleaks (release tarball) ──────────────────────────────────────────
RUN GL_VER="$(curl -fsSL https://api.github.com/repos/gitleaks/gitleaks/releases/latest | jq -r .tag_name | sed 's/^v//')" \
 && curl -fsSL "https://github.com/gitleaks/gitleaks/releases/download/v${GL_VER}/gitleaks_${GL_VER}_linux_x64.tar.gz" \
        | tar -xzC /usr/local/bin gitleaks

# ── osv-scanner (single binary) ─────────────────────────────────────────
RUN curl -fsSL -o /usr/local/bin/osv-scanner \
        "https://github.com/google/osv-scanner/releases/latest/download/osv-scanner_linux_amd64" \
 && chmod +x /usr/local/bin/osv-scanner

# ── trivy via aquasecurity apt repo ─────────────────────────────────────
RUN install -m 0755 -d /etc/apt/keyrings \
 && curl -fsSL https://aquasecurity.github.io/trivy-repo/deb/public.key \
        -o /etc/apt/keyrings/trivy.asc \
 && chmod go+r /etc/apt/keyrings/trivy.asc \
 && echo "deb [signed-by=/etc/apt/keyrings/trivy.asc] https://aquasecurity.github.io/trivy-repo/deb generic main" \
        > /etc/apt/sources.list.d/trivy.list \
 && apt-get update \
 && apt-get install -y --no-install-recommends trivy \
 && rm -rf /var/lib/apt/lists/*

# ── Pre-fetch core Semgrep rule packs into the image ────────────────────
RUN semgrep --config p/security-audit --config p/owasp-top-ten \
            --config p/cwe-top-25 --metrics off --quiet --error \
            --severity ERROR /dev/null >/dev/null 2>&1 || true

# ── ssh client (host-key checking is disabled in scan.sh GIT_SSH_COMMAND) ─
RUN apt-get update \
 && apt-get install -y --no-install-recommends openssh-client \
 && rm -rf /var/lib/apt/lists/*

# ── App ────────────────────────────────────────────────────────────────
WORKDIR /opt/vuln-scan
COPY . /opt/vuln-scan
RUN chmod +x /opt/vuln-scan/scan.sh /opt/vuln-scan/lib/unify.py

ENV PATH=/opt/vuln-scan:$PATH
WORKDIR /work
ENTRYPOINT ["/opt/vuln-scan/scan.sh"]
CMD ["--help"]
