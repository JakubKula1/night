#!/bin/bash
# =============================================================================
# Testing – Tools Installer / Checker
# Checks and installs: Docker, DVWA, Nikto, Gobuster, OWASP ZAP, SlowHTTPTest
# =============================================================================

set -euo pipefail

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
BOLD='\033[1m'
NC='\033[0m'

OK="${GREEN}[✔]${NC}"
MISS="${RED}[✗]${NC}"
INFO="${CYAN}[i]${NC}"
WARN="${YELLOW}[!]${NC}"

log()  { echo -e "${INFO} $*"; }
ok()   { echo -e "${OK} $*"; }
warn() { echo -e "${WARN} $*"; }
err()  { echo -e "${MISS} $*" >&2; }

# ---------------------------------------------------------------------------- #
#  Privileges check                                                            #
# ---------------------------------------------------------------------------- #
if [[ $EUID -ne 0 ]]; then
    err "This script must be run as root (or via sudo)."
    exit 1
fi

# ---------------------------------------------------------------------------- #
#  Detect distro                                                               #
# ---------------------------------------------------------------------------- #
if ! command -v apt-get &>/dev/null; then
    err "This installer only supports Debian/Ubuntu (apt-based) systems."
    exit 1
fi

echo ""
echo -e "${BOLD}╔═══════════════════════════════════════════════════╗${NC}"
echo -e "${BOLD}║     NIGHT – Testing Tools Check & Install         ║${NC}"
echo -e "${BOLD}╚═══════════════════════════════════════════════════╝${NC}"

# ---------------------------------------------------------------------------- #
#  Helper functions                                                            #
# ---------------------------------------------------------------------------- #
is_installed() {
    command -v "$1" &>/dev/null
}

apt_install() {
    log "Installing: $*"
    env DEBIAN_FRONTEND=noninteractive apt-get install -y -q "$@"
}

log "Ensuring core dependencies (curl, tar, wget) are installed..."
env DEBIAN_FRONTEND=noninteractive apt-get update -qq
apt_install curl tar wget ca-certificates

# ---------------------------------------------------------------------------- #
#  1. Docker                                                                   #
# ---------------------------------------------------------------------------- #
echo ""
echo -e "\n${BOLD}── 1. Docker & Container Engine ──────────────────────${NC}"
if is_installed docker; then
    ok "Docker is installed: $(docker --version)"
else
    warn "Docker not found. Installing via apt..."
    apt_install docker.io docker-compose-v2
    systemctl enable --now docker
    log "Waiting for Docker socket..."
    for i in {1..5}; do
        docker info &>/dev/null && break || sleep 2
    done
    ok "Docker installed and started."
fi

# Check Docker is running
if ! docker info &>/dev/null; then
    echo -e "${WARN} Docker daemon is not running. Starting..."
    sudo systemctl start docker || err "Failed to start Docker service."
fi

# ---------------------------------------------------------------------------- #
#  2. DVWA (via Docker)                                                        #
# ---------------------------------------------------------------------------- #
echo ""
echo -e "\n${BOLD}── 2. DVWA (Vulnerable Target) ───────────────────────${NC}"
DVWA_CONTAINER="dvwa-test"
DVWA_IMAGE="vulnerables/web-dvwa"
DVWA_PORT=8080

if docker inspect "$DVWA_CONTAINER" &>/dev/null; then
    ok "DVWA container '$DVWA_CONTAINER' already exists."
    if [[ "$(docker inspect -f '{{.State.Running}}' "$DVWA_CONTAINER" 2>/dev/null)" == "true" ]]; then
        ok "DVWA is running at http://127.0.0.1:${DVWA_PORT}"
    else
        warn "DVWA is stopped. Attempting to start..."
        if docker start "$DVWA_CONTAINER" >/dev/null; then
            ok "DVWA started at http://127.0.0.1:${DVWA_PORT}"
        else
            err "Failed to start DVWA. Port conflict?"
        fi
    fi
else
    log "Pulling DVWA image (${DVWA_IMAGE})..."
    docker pull "$DVWA_IMAGE" >/dev/null
    log "Creating DVWA container..."
    if docker run --name "$DVWA_CONTAINER" -d -p "${DVWA_PORT}:80" "$DVWA_IMAGE" >/dev/null 2>&1; then
        ok "DVWA deployed at http://127.0.0.1:${DVWA_PORT}"
        echo -e "    Default credentials: admin / password"
    else
        err "Failed to deploy DVWA. Is port ${DVWA_PORT} already in use?"
    fi
fi

# ---------------------------------------------------------------------------- #
#  3. Offensive tools                                                          #
# ---------------------------------------------------------------------------- #
echo -e "\n${BOLD}── 3. CLI Offensive Tools ────────────────────────────${NC}"

# Nikto
echo ""
if is_installed nikto; then
    ok "Nikto is installed."
else
    warn "Nikto not found. Installing..."
    apt_install nikto
    ok "Nikto installed."
fi

# Gobuster and wordlists
echo ""
if is_installed gobuster; then
    ok "Gobuster is installed."
else
    warn "Gobuster not found. Installing..."
    apt_install gobuster
    ok "Gobuster installed."
fi

# Install wordlists if not present
if [[ ! -f /usr/share/dirb/wordlists/common.txt ]]; then
    warn "Wordlists not found. Installing dirb..."
    apt_install dirb
    ok "Wordlists installed."
else
    ok "Wordlists found."
fi

# SlowHTTPTest
if is_installed slowhttptest; then
    ok "SlowHTTPTest is installed."
else
    warn "SlowHTTPTest not found. Installing..."
    apt_install slowhttptest
    ok "SlowHTTPTest installed."
fi

# ---------------------------------------------------------------------------- #
#  4. OWASP ZAP                                                                #
# ---------------------------------------------------------------------------- #
echo ""
echo -e "\n${BOLD}── 4. OWASP ZAP (Application Scanner) ────────────────${NC}"
if is_installed zap.sh || is_installed zaproxy || [[ -f /opt/zaproxy/zap.sh ]]; then
    ok "OWASP ZAP is installed."
else
    warn "OWASP ZAP not found. Installing..."
    if is_installed snap; then
        log "Installing ZAP via snap..."
        snap install zaproxy --classic
        ok "OWASP ZAP installed via snap."
    else
        log "Installing Java & Downloading ZAP tarball..."
        apt_install default-jre-headless
        ZAP_VERSION="2.15.0"
        ZAP_URL="https://github.com/zaproxy/zaproxy/releases/download/v${ZAP_VERSION}/ZAP_${ZAP_VERSION}_Linux.tar.gz"
        TMP_DIR=$(mktemp -d)
        # Safety download and extract
        if curl -fsSL "$ZAP_URL" -o "$TMP_DIR/zap.tar.gz"; then
            mkdir -p /opt/zaproxy
            tar -xzf "$TMP_DIR/zap.tar.gz" -C /opt/zaproxy --strip-components=1
            ln -sf /opt/zaproxy/zap.sh /usr/local/bin/zap.sh
            ok "OWASP ZAP installed."
        else
            err "Failed to download OWASP ZAP. Check your network or the version number."
        fi
        rm -rf "$TMP_DIR"
    fi
fi

# ---------------------------------------------------------------------------- #
#  Summary                                                                     #
# ---------------------------------------------------------------------------- #
echo ""
echo -e "${BOLD}╔═══════════════════════════════════════════════════╗${NC}"
echo -e "${BOLD}║               Installation Complete               ║${NC}"
echo -e "${BOLD}╚═══════════════════════════════════════════════════╝${NC}"
echo "Tool status:"
is_installed docker      && echo -e "  ${OK} Docker"         || echo -e "  ${MISS} Docker (check manually)"
docker inspect "$DVWA_CONTAINER" &>/dev/null && echo -e "  ${OK} DVWA (container exists)" || echo -e "  ${MISS} DVWA"
is_installed nikto       && echo -e "  ${OK} Nikto"          || echo -e "  ${MISS} Nikto"
is_installed gobuster    && echo -e "  ${OK} Gobuster"       || echo -e "  ${MISS} Gobuster"
(is_installed zap.sh || is_installed zaproxy || [[ -f /opt/zaproxy/zap.sh ]]) \
                         && echo -e "  ${OK} OWASP ZAP"      || echo -e "  ${MISS} OWASP ZAP"
is_installed slowhttptest && echo -e "  ${OK} SlowHTTPTest"  || echo -e "  ${MISS} SlowHTTPTest"