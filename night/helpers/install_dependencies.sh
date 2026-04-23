#!/usr/bin/env bash
# =============================================================================
# Active Defense – Dependency Installer / Checker
# Checks for and installs: Certbot, UFW, nftables, Fail2ban,
#                          ModSecurity v3 + Nginx connector + OWASP CRS
# Requires: Ubuntu/Debian, root/sudo
# =============================================================================

set -euo pipefail

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
BOLD='\033[1m'
NC='\033[0m'

OK="${GREEN}[✔]${NC}"
MISS="${RED}[✘]${NC}"
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
echo -e "${BOLD}║     Active Defense – Dependency Check & Install   ║${NC}"
echo -e "${BOLD}╚═══════════════════════════════════════════════════╝${NC}"
echo ""

INSTALL_LIST=()
MODSEC_NEEDS_BUILD=false

# ---------------------------------------------------------------------------- #
#  Helper: check binary                                                        #
# ---------------------------------------------------------------------------- #
check_bin() {
    local name="$1" cmd="$2"
    if command -v "$cmd" &>/dev/null; then
        ok "$name is installed  ($(command -v "$cmd"))"
        return 0
    else
        warn "$name NOT found."
        return 1
    fi
}

# ---------------------------------------------------------------------------- #
#  1. System packages                                                          #
# ---------------------------------------------------------------------------- #
echo -e "\n${BOLD}── 1. Core Tools ─────────────────────────────────────${NC}"

check_bin "Nginx" nginx || INSTALL_LIST+=(nginx)
check_bin "Certbot" certbot || INSTALL_LIST+=(certbot python3-certbot-nginx)
check_bin "UFW" ufw || INSTALL_LIST+=(ufw)
check_bin "nftables" nft || INSTALL_LIST+=(nftables)
check_bin "Fail2ban" fail2ban-client || INSTALL_LIST+=(fail2ban)
check_bin "Git" git || INSTALL_LIST+=(git)

# ---------------------------------------------------------------------------- #
#  2. ModSecurity check                                                        #
# ---------------------------------------------------------------------------- #
echo -e "\n${BOLD}── 2. ModSecurity (WAF) ──────────────────────────────${NC}"

MODSEC_LIB="/usr/local/modsecurity/lib/libmodsecurity.so"
MODSEC_MODULE_CANDIDATES=(
    /usr/lib/nginx/modules/ngx_http_modsecurity_module.so
    /etc/nginx/modules/ngx_http_modsecurity_module.so
    /usr/share/nginx/modules/ngx_http_modsecurity_module.so
)
MODSEC_MODULE_FOUND=false

if [[ -f "$MODSEC_LIB" ]]; then
    ok "libmodsecurity found at $MODSEC_LIB"
else
    warn "libmodsecurity NOT found – will build from source."
    MODSEC_NEEDS_BUILD=true
fi

for mod in "${MODSEC_MODULE_CANDIDATES[@]}"; do
    if [[ -f "$mod" ]]; then
        ok "Nginx ModSecurity module found at $mod"
        MODSEC_MODULE_FOUND=true
        break
    fi
done
if ! $MODSEC_MODULE_FOUND; then
    warn "Nginx ModSecurity connector module NOT found – will build."
    MODSEC_NEEDS_BUILD=true
fi

# OWASP CRS
CRS_CANDIDATES=(/etc/nginx/owasp-crs /usr/local/modsecurity-crs /etc/nginx/modsec/crs)
CRS_FOUND=false
for crs in "${CRS_CANDIDATES[@]}"; do
    if [[ -d "$crs" ]]; then
        ok "OWASP CRS found at $crs"
        CRS_FOUND=true
        break
    fi
done
$CRS_FOUND || warn "OWASP CRS NOT found – will clone from GitHub."

# ---------------------------------------------------------------------------- #
#  3. Install apt packages                                                     #
# ---------------------------------------------------------------------------- #
if [[ ${#INSTALL_LIST[@]} -gt 0 ]]; then
    echo -e "\n${BOLD}── 3. Installing missing apt packages ────────────────${NC}"
    log "Running: apt-get update"
    env DEBIAN_FRONTEND=noninteractive apt-get update -qq

    log "Installing: ${INSTALL_LIST[*]}"
    env DEBIAN_FRONTEND=noninteractive apt-get install -y -q "${INSTALL_LIST[@]}"
    ok "apt packages installed."
else
    echo -e "\n${BOLD}── 3. apt packages ───────────────────────────────────${NC}"
    ok "All apt packages already present, nothing to install."
fi

# ---------------------------------------------------------------------------- #
#  4. Build ModSecurity v3 + Nginx connector (if needed)                       #
# ---------------------------------------------------------------------------- #
if $MODSEC_NEEDS_BUILD; then
    echo -e "\n${BOLD}── 4. Building ModSecurity v3 from source ────────────${NC}"
    warn "This might take some time."

    # Build dependencies
    log "Installing build dependencies..."
    env DEBIAN_FRONTEND=noninteractive apt-get install -y -q \
        bison build-essential ca-certificates curl dh-autoreconf doxygen \
        flex g++ git iputils-ping libcurl4-openssl-dev libexpat1-dev \
        libgeoip-dev liblmdb-dev libpcre3-dev libpcre2-dev libssl-dev \
        libtool libxml2 libxml2-dev libyajl-dev liblua5.3-dev \
        pkg-config wget zlib1g-dev libxslt1-dev libgd-dev automake

    BUILD_DIR="/usr/local/src/modsec-build"
    mkdir -p "$BUILD_DIR" && cd "$BUILD_DIR"

    # Clone & build libmodsecurity
    log "Cloning ModSecurity..."
    [[ -d ModSecurity ]] && rm -rf ModSecurity
    git clone --depth 1 -b v3/master --single-branch \
        https://github.com/SpiderLabs/ModSecurity
    cd ModSecurity
    git submodule init
    git submodule update
    ./build.sh
    ./configure

    TOTAL_RAM_MB=$(free -m | awk '/^Mem:/{print $2}')
    CPU_CORES=$(nproc)
    SAFE_CORES=$((TOTAL_RAM_MB / 1024))
    [[ $SAFE_CORES -lt 1 ]] && SAFE_CORES=1
    [[ $SAFE_CORES -gt $CPU_CORES ]] && SAFE_CORES=$CPU_CORES
    log "Compiling with $SAFE_CORES threads (Available RAM: ${TOTAL_RAM_MB}MB)..."
    make -j"$SAFE_CORES"
    #make -j"$(nproc)"

    make install
    ok "libmodsecurity built and installed."

    # Clone Nginx connector
    log "Cloning ModSecurity-nginx connector..."
    cd "$BUILD_DIR"
    [[ -d ModSecurity-nginx ]] && rm -rf ModSecurity-nginx
    git clone https://github.com/owasp-modsecurity/ModSecurity-nginx.git

    # Get installed Nginx version and its source
    NGINX_VER=$(nginx -v 2>&1 | grep -oP '[\d.]+')
    log "Detected Nginx version: $NGINX_VER – downloading source..."
    wget -q "http://nginx.org/download/nginx-${NGINX_VER}.tar.gz"
    tar -xzf "nginx-${NGINX_VER}.tar.gz"
    cd "nginx-${NGINX_VER}"
    ./configure --with-compat --add-dynamic-module=../ModSecurity-nginx
    make modules

    # Install module
    MODULE_DIR="/usr/lib/nginx/modules"
    mkdir -p "$MODULE_DIR"
    cp objs/ngx_http_modsecurity_module.so "$MODULE_DIR/"
    chmod 0644 "$MODULE_DIR/ngx_http_modsecurity_module.so"
    ok "Nginx ModSecurity connector module installed to $MODULE_DIR"

    # Create load-module conf
    MODULES_AVAIL="/usr/share/nginx/modules-available"
    MODULES_ENABLED="/etc/nginx/modules-enabled"
    mkdir -p "$MODULES_AVAIL" "$MODULES_ENABLED"
    echo "load_module modules/ngx_http_modsecurity_module.so;" > "$MODULES_AVAIL/mod-modsecurity.conf"
    ln -sf "$MODULES_AVAIL/mod-modsecurity.conf" "$MODULES_ENABLED/50-mod-modsecurity.conf"
    ok "ModSecurity load directive written."
fi

# ---------------------------------------------------------------------------- #
#  5. OWASP CRS                                                                #
# ---------------------------------------------------------------------------- #
if ! $CRS_FOUND; then
    echo -e "\n${BOLD}── 5. Installing OWASP Core Rule Set ─────────────────${NC}"
    CRS_PATH="/etc/nginx/owasp-crs"
    log "Cloning OWASP CRS into $CRS_PATH ..."
    git clone --depth 1 https://github.com/coreruleset/coreruleset.git "$CRS_PATH"
    cp "$CRS_PATH/crs-setup.conf.example" "$CRS_PATH/crs-setup.conf"
    ok "OWASP CRS installed at $CRS_PATH"
fi

# ---------------------------------------------------------------------------- #
#  6. ModSecurity base config                                                  #
# ---------------------------------------------------------------------------- #
echo -e "\n${BOLD}── 6. ModSecurity base configuration ─────────────────${NC}"
MODSEC_CFG_DIR="/etc/nginx/modsec"
if [[ ! -d "$MODSEC_CFG_DIR" ]]; then
    mkdir -p "$MODSEC_CFG_DIR"
fi

if [[ ! -f "$MODSEC_CFG_DIR/modsecurity.conf" ]]; then
    wget -q "https://raw.githubusercontent.com/SpiderLabs/ModSecurity/v3/master/modsecurity.conf-recommended" -O "$MODSEC_CFG_DIR/modsecurity.conf"
    wget -q "https://raw.githubusercontent.com/SpiderLabs/ModSecurity/v3/master/unicode.mapping" -O "$MODSEC_CFG_DIR/unicode.mapping"
    ok "modsecurity.conf copied to $MODSEC_CFG_DIR"
else
    ok "modsecurity.conf already present."
fi

if [[ ! -f "$MODSEC_CFG_DIR/main.conf" ]]; then
    cat > "$MODSEC_CFG_DIR/main.conf" <<'EOF'
Include /etc/nginx/modsec/modsecurity.conf
Include /etc/nginx/owasp-crs/crs-setup.conf
Include /etc/nginx/owasp-crs/rules/*.conf
EOF
    ok "main.conf created at $MODSEC_CFG_DIR/main.conf"
fi

# ---------------------------------------------------------------------------- #
#  7. Summary                                                                  #
# ---------------------------------------------------------------------------- #
echo ""
echo -e "${BOLD}╔═══════════════════════════════════════════════════╗${NC}"
echo -e "${BOLD}║               Installation Complete               ║${NC}"
echo -e "${BOLD}╚═══════════════════════════════════════════════════╝${NC}"
echo ""
echo -e "  ${CYAN}Next steps:${NC}"
echo -e "  • Run the CLI tool and choose ${BOLD}Active Defense${NC} from the menu."
echo -e "  • For TLS: have a domain pointed to this server."
echo -e "  • Review /etc/nginx/modsec/modsecurity.conf and set"
echo -e "    ${BOLD}SecRuleEngine On${NC} (detection-only → enforcement)."
echo ""
