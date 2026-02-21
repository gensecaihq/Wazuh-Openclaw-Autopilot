#!/usr/bin/env bash
# =============================================================================
# WAZUH OPENCLAW AUTOPILOT - SECURE TURNKEY INSTALLER
# =============================================================================
#
# Security-hardened installer for autonomous SOC on Wazuh.
#
# SECURITY FEATURES:
#   • Gateway NEVER exposed to public internet (localhost binding only)
#   • Pairing mode for secure initial setup
#   • Directory permissions hardened (700/600)
#   • Tailscale zero-trust networking mandatory
#   • Firewall rules automatically configured
#   • Credential isolation
#   • Interactive security guidance
#
# Prerequisites:
#   - Wazuh Manager installed and running
#   - Root access
#   - Internet connectivity
#
# =============================================================================

set -euo pipefail

# =============================================================================
# CONFIGURATION
# =============================================================================

VERSION="3.2.0"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"

# Installation directories
INSTALL_DIR="/opt/wazuh-autopilot"
CONFIG_DIR="/etc/wazuh-autopilot"
DATA_DIR="/var/lib/wazuh-autopilot"
LOG_DIR="/var/log/wazuh-autopilot"
SECRETS_DIR="/etc/wazuh-autopilot/secrets"

# Upstream repositories
MCP_SERVER_REPO="https://github.com/gensecaihq/Wazuh-MCP-Server.git"
MCP_SERVER_DIR="$INSTALL_DIR/wazuh-mcp-server"

# SECURITY: Gateway binds to localhost ONLY
GATEWAY_BIND="127.0.0.1"
GATEWAY_PORT="18789"
MCP_PORT="3000"
RUNTIME_PORT="9090"

# Flags (set by parse_args or environment)
SKIP_TAILSCALE=false

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
BOLD='\033[1m'
NC='\033[0m'

# =============================================================================
# HELPER FUNCTIONS
# =============================================================================

log_info() { echo -e "${BLUE}[INFO]${NC} $1"; }
log_success() { echo -e "${GREEN}[OK]${NC} $1"; }
log_warn() { echo -e "${YELLOW}[WARN]${NC} $1"; }
log_error() { echo -e "${RED}[ERROR]${NC} $1"; }
log_step() { echo -e "\n${CYAN}${BOLD}━━━ $1 ━━━${NC}\n"; }
log_security() { echo -e "${GREEN}[SECURITY]${NC} $1"; }

confirm() {
    local prompt="$1"
    local default="${2:-n}"
    local response

    if [[ "$default" == "y" ]]; then
        read -rp "$prompt [Y/n]: " response
        response="${response:-y}"
    else
        read -rp "$prompt [y/N]: " response
        response="${response:-n}"
    fi

    [[ "$response" =~ ^[Yy]$ ]]
}

# Generate cryptographically secure random string
generate_secret() {
    local length="${1:-32}"
    openssl rand -hex "$length"
}

# =============================================================================
# ARGUMENT PARSING
# =============================================================================

show_help() {
    echo ""
    echo "Usage: sudo ./install.sh [OPTIONS]"
    echo ""
    echo "Options:"
    echo "  --skip-tailscale    Skip Tailscale installation (for air-gapped/bootstrap)"
    echo "  --help              Show this help message"
    echo "  --version           Show version"
    echo ""
    echo "Environment Variables:"
    echo "  AUTOPILOT_MODE=bootstrap    Automatically skip Tailscale requirement"
    echo "  AUTOPILOT_MODE=production   Full installation with Tailscale (default)"
    echo ""
    echo "Examples:"
    echo "  sudo ./install.sh                          # Standard installation"
    echo "  sudo ./install.sh --skip-tailscale         # Air-gapped / no Tailscale"
    echo "  AUTOPILOT_MODE=bootstrap sudo ./install.sh # Bootstrap mode (skips Tailscale)"
    echo ""
    exit 0
}

parse_args() {
    while [[ $# -gt 0 ]]; do
        case "$1" in
            --skip-tailscale)
                SKIP_TAILSCALE=true
                shift
                ;;
            --help|-h)
                show_help
                ;;
            --version|-v)
                echo "Wazuh OpenClaw Autopilot Installer v$VERSION"
                exit 0
                ;;
            *)
                log_warn "Unknown option: $1 (ignored)"
                shift
                ;;
        esac
    done

    # Read AUTOPILOT_MODE from environment
    if [[ "${AUTOPILOT_MODE:-}" == "bootstrap" ]]; then
        SKIP_TAILSCALE=true
        log_info "AUTOPILOT_MODE=bootstrap detected — Tailscale will be skipped"
    fi
}

# =============================================================================
# SECURITY BANNER
# =============================================================================

show_security_banner() {
    clear
    echo ""
    echo -e "${GREEN}${BOLD}"
    echo "  ╔═══════════════════════════════════════════════════════════════╗"
    echo "  ║                                                               ║"
    echo "  ║     WAZUH OPENCLAW AUTOPILOT                                  ║"
    echo "  ║     Security-Hardened Installation                            ║"
    echo "  ║                                                               ║"
    echo "  ║     Version: $VERSION                                            ║"
    echo "  ║                                                               ║"
    echo "  ╚═══════════════════════════════════════════════════════════════╝"
    echo -e "${NC}"
    echo ""
    echo -e "  ${CYAN}Security Features:${NC}"
    echo ""
    echo "    ✓ Gateway binds to localhost only (never exposed)"
    echo "    ✓ Tailscale zero-trust networking"
    echo "    ✓ Pairing mode for secure device registration"
    echo "    ✓ Directory permissions hardened (700/600)"
    echo "    ✓ Firewall rules auto-configured"
    echo "    ✓ Credential isolation"
    echo "    ✓ Two-tier human approval for all actions"
    echo ""
    echo -e "  ${CYAN}What will be installed:${NC}"
    echo ""
    if [[ "$SKIP_TAILSCALE" != "true" ]]; then
        echo "    • Tailscale (secure networking)"
    else
        echo "    • Tailscale: SKIPPED (bootstrap/air-gapped mode)"
    fi
    echo "    • Wazuh MCP Server (localhost only)"
    echo "    • OpenClaw Gateway (localhost only)"
    echo "    • 7 SOC Agents (read-only by default)"
    echo "    • Runtime Service (case management)"
    echo ""
}

# =============================================================================
# SECURITY GUIDANCE
# =============================================================================

show_security_guidance() {
    log_step "Security Configuration Guide"

    echo ""
    echo -e "  ${YELLOW}${BOLD}IMPORTANT SECURITY INFORMATION${NC}"
    echo ""
    echo "  This installer implements security best practices:"
    echo ""
    echo -e "  ${GREEN}1. Network Isolation${NC}"
    echo "     • OpenClaw Gateway binds to 127.0.0.1:$GATEWAY_PORT (localhost only)"
    echo "     • MCP Server binds to Tailscale IP (never 0.0.0.0)"
    echo "     • Runtime Service binds to 127.0.0.1:$RUNTIME_PORT"
    echo "     • NO services are exposed to the public internet"
    echo ""
    echo -e "  ${GREEN}2. Access Control${NC}"
    echo "     • All remote access goes through Tailscale VPN"
    echo "     • Pairing mode requires explicit device approval"
    echo "     • DM policy set to 'allowlist' (no public messages)"
    echo ""
    echo -e "  ${GREEN}3. File Permissions${NC}"
    echo "     • Config directories: 700 (owner only)"
    echo "     • Credential files: 600 (owner read/write only)"
    echo "     • Secrets directory: 700 with isolated credentials"
    echo ""
    echo -e "  ${GREEN}4. Human-in-the-Loop${NC}"
    echo "     • AI agents can ONLY propose actions"
    echo "     • Humans must Approve then Execute every action"
    echo "     • No autonomous execution possible"
    echo ""

    read -rp "Press Enter to continue..."
}

# =============================================================================
# PREREQUISITE CHECKS
# =============================================================================

check_root() {
    if [[ $EUID -ne 0 ]]; then
        log_error "This installer must be run as root"
        echo "  Run: sudo $0"
        exit 1
    fi
}

check_os() {
    if [[ -f /etc/os-release ]]; then
        source /etc/os-release
        log_info "Detected: $PRETTY_NAME"

        case "$ID" in
            ubuntu|debian)
                PKG_UPDATE="apt-get update -qq"
                PKG_INSTALL="apt-get install -y -qq"
                FIREWALL_CMD="ufw"
                ;;
            centos|rhel|rocky|almalinux|fedora)
                PKG_UPDATE="yum makecache -q"
                PKG_INSTALL="yum install -y -q"
                FIREWALL_CMD="firewalld"
                ;;
            *)
                log_warn "Untested OS: $ID. Proceeding with apt-get..."
                PKG_UPDATE="apt-get update -qq"
                PKG_INSTALL="apt-get install -y -qq"
                FIREWALL_CMD="ufw"
                ;;
        esac
    else
        log_error "Cannot detect OS"
        exit 1
    fi
}

check_wazuh() {
    log_step "Checking Wazuh Installation"

    if [[ ! -d /var/ossec ]]; then
        log_error "Wazuh not found at /var/ossec"
        echo ""
        echo "  This installer requires Wazuh Manager to be installed."
        echo "  Install Wazuh first: https://documentation.wazuh.com"
        echo ""
        exit 1
    fi
    log_success "Wazuh installation found"

    if systemctl is-active --quiet wazuh-manager 2>/dev/null; then
        log_success "Wazuh Manager service is running"
    elif /var/ossec/bin/wazuh-control status 2>/dev/null | grep -q "running"; then
        log_success "Wazuh Manager is running"
    else
        log_error "Wazuh Manager is not running"
        echo "  Start it with: systemctl start wazuh-manager"
        exit 1
    fi

    if curl -sk https://localhost:55000 >/dev/null 2>&1; then
        log_success "Wazuh API is accessible"
    else
        log_warn "Wazuh API not accessible on localhost:55000"
        log_info "Will configure API connection during setup"
    fi
}

install_dependencies() {
    log_step "Installing Dependencies"

    local deps_needed=()

    command -v curl &>/dev/null || deps_needed+=(curl)
    command -v git &>/dev/null || deps_needed+=(git)
    command -v jq &>/dev/null || deps_needed+=(jq)
    command -v openssl &>/dev/null || deps_needed+=(openssl)

    if [[ ${#deps_needed[@]} -gt 0 ]]; then
        log_info "Installing: ${deps_needed[*]}"
        $PKG_UPDATE
        $PKG_INSTALL "${deps_needed[@]}"
    fi

    # Node.js
    if ! command -v node &>/dev/null; then
        log_info "Installing Node.js 22 LTS..."
        curl -fsSL https://deb.nodesource.com/setup_22.x | bash - >/dev/null 2>&1
        $PKG_INSTALL nodejs
    fi

    local node_ver
    node_ver=$(node -v 2>/dev/null | cut -d'v' -f2 | cut -d'.' -f1)
    if [[ -z "$node_ver" ]]; then
        log_error "Could not determine Node.js version"
        exit 1
    fi
    if [[ "$node_ver" -lt 20 ]]; then
        log_error "Node.js 20+ required. Found: $(node -v)"
        exit 1
    fi
    log_success "Node.js $(node -v)"

    # Python 3.11+ (required for Wazuh MCP Server)
    if ! command -v python3 &>/dev/null; then
        log_info "Installing Python 3..."
        $PKG_INSTALL python3 python3-pip python3-venv
    fi

    local py_ver
    py_ver=$(python3 -c 'import sys; print(sys.version_info.minor)' 2>/dev/null || echo "0")
    if [[ "$py_ver" -lt 11 ]]; then
        log_error "Python 3.11+ required for Wazuh MCP Server. Found: $(python3 --version)"
        log_error "Install Python 3.11+: https://www.python.org/downloads/"
        exit 1
    else
        log_success "Python $(python3 --version 2>&1 | awk '{print $2}')"
    fi

    log_success "All dependencies installed"
}

# =============================================================================
# FIREWALL CONFIGURATION
# =============================================================================

configure_firewall() {
    log_step "Configuring Firewall"

    echo ""
    echo "  The firewall will be configured to:"
    echo "    • Block OpenClaw Gateway port ($GATEWAY_PORT) from public"
    echo "    • Block MCP Server port ($MCP_PORT) from public"
    echo "    • Allow Tailscale traffic only"
    echo ""

    if ! confirm "Configure firewall rules?" "y"; then
        log_warn "Skipping firewall configuration"
        log_warn "SECURITY WARNING: Manually ensure ports are not exposed"
        return 0
    fi

    if command -v ufw &>/dev/null; then
        log_info "Configuring UFW firewall..."

        # Enable UFW if not active
        if ! ufw status | grep -q "active"; then
            log_info "Enabling UFW..."
            ufw --force enable
        fi

        # Allow SSH
        ufw allow ssh >/dev/null 2>&1

        # Block gateway and MCP ports from all non-loopback/tailscale interfaces
        local _iface
        while IFS= read -r _iface; do
            ufw deny in on "$_iface" to any port "$GATEWAY_PORT" >/dev/null 2>&1 || true
            ufw deny in on "$_iface" to any port "$MCP_PORT" >/dev/null 2>&1 || true
        done < <(ip -o link show 2>/dev/null | awk -F': ' '{print $2}' | grep -v "^lo$\|^tailscale")

        # Allow Tailscale
        ufw allow in on tailscale0 >/dev/null 2>&1 || true

        log_success "UFW firewall configured"
        log_security "Gateway port $GATEWAY_PORT blocked from public interfaces"
        log_security "MCP port $MCP_PORT blocked from public interfaces"
        log_security "Tailscale traffic allowed"

    elif command -v firewall-cmd &>/dev/null; then
        log_info "Configuring firewalld..."

        # Ensure firewalld is running
        systemctl start firewalld 2>/dev/null || true
        systemctl enable firewalld 2>/dev/null || true

        # Remove any public rules for our ports
        firewall-cmd --permanent --remove-port=$GATEWAY_PORT/tcp 2>/dev/null || true
        firewall-cmd --permanent --remove-port=$MCP_PORT/tcp 2>/dev/null || true

        # Add Tailscale interface to trusted zone
        firewall-cmd --permanent --zone=trusted --add-interface=tailscale0 2>/dev/null || true

        firewall-cmd --reload 2>/dev/null || true

        log_success "Firewalld configured"
    else
        log_warn "No firewall detected - install ufw or firewalld for security"
    fi
}

# =============================================================================
# TAILSCALE INSTALLATION
# =============================================================================

install_tailscale() {
    log_step "Installing Tailscale"

    echo ""
    echo -e "  ${YELLOW}Tailscale is recommended for secure operation${NC}"
    echo ""
    echo "  Tailscale provides:"
    echo "    • Zero-trust VPN between components"
    echo "    • No public port exposure"
    echo "    • Encrypted communication"
    echo "    • Device authentication"
    echo ""

    if command -v tailscale &>/dev/null; then
        log_success "Tailscale already installed"
    else
        log_info "Installing Tailscale..."
        curl -fsSL https://tailscale.com/install.sh | sh
        log_success "Tailscale installed"
    fi

    # Check connection status
    if tailscale status &>/dev/null 2>&1; then
        TAILSCALE_IP=$(tailscale ip -4 2>/dev/null || echo "")
        if [[ -n "$TAILSCALE_IP" ]]; then
            log_success "Tailscale connected: $TAILSCALE_IP"
            return 0
        fi
    fi

    echo ""
    echo -e "${YELLOW}${BOLD}Tailscale Authentication Required${NC}"
    echo ""
    echo "  You MUST authenticate Tailscale for secure networking."
    echo "  This creates a private network for MCP/OpenClaw communication."
    echo ""

    if confirm "Authenticate Tailscale now?" "y"; then
        echo ""
        log_info "Opening Tailscale authentication..."
        echo "  Follow the URL that appears to authenticate."
        echo ""
        tailscale up

        sleep 2
        TAILSCALE_IP=$(tailscale ip -4 2>/dev/null || echo "")
        if [[ -z "$TAILSCALE_IP" ]]; then
            log_error "Could not obtain Tailscale IP"
            return 1
        fi
        log_success "Tailscale IP: $TAILSCALE_IP"
        log_security "MCP Server will bind to Tailscale network only"
    else
        log_error "Tailscale authentication is required for secure operation"
        echo ""
        echo "  Run 'sudo tailscale up' to authenticate, then re-run installer."
        echo ""
        exit 1
    fi
}

# =============================================================================
# DIRECTORY SECURITY
# =============================================================================

setup_secure_directories() {
    log_step "Creating Secure Directories"

    # Create directories with restrictive permissions
    log_info "Creating directories with hardened permissions..."

    # Main directories - 750 (owner full, group read/execute)
    mkdir -p "$INSTALL_DIR"
    mkdir -p "$CONFIG_DIR"
    mkdir -p "$DATA_DIR"/{cases,evidence,plans,reports,state}
    mkdir -p "$LOG_DIR"
    mkdir -p "$SECRETS_DIR"

    # Permissions
    chmod 750 "$INSTALL_DIR"
    chmod 700 "$CONFIG_DIR"        # More restrictive for config
    chmod 750 "$DATA_DIR"
    chmod 750 "$LOG_DIR"
    chmod 700 "$SECRETS_DIR"       # Most restrictive for secrets

    # OpenClaw directories
    local OC_DIR="$HOME/.openclaw"
    mkdir -p "$OC_DIR/wazuh-autopilot/agents"
    mkdir -p "$OC_DIR/wazuh-autopilot/workspace"
    chmod -R 700 "$OC_DIR"         # Full restriction on OpenClaw dir

    log_security "Config directory: $CONFIG_DIR (mode 700)"
    log_security "Secrets directory: $SECRETS_DIR (mode 700)"
    log_security "OpenClaw directory: $OC_DIR (mode 700)"

    log_success "Secure directories created"
}

# =============================================================================
# CREDENTIAL ISOLATION
# =============================================================================

setup_credentials() {
    log_step "Generating Secure Credentials"

    echo ""
    echo "  These will be stored in $SECRETS_DIR with mode 600"
    echo ""

    # Idempotent: reuse existing secrets if present (prevents breaking running services on re-install)
    local MCP_AUTH_TOKEN OPENCLAW_TOKEN PAIRING_SECRET APPROVAL_SECRET
    local _generated_new=false

    if [[ -s "$SECRETS_DIR/mcp_token" ]]; then
        MCP_AUTH_TOKEN=$(cat "$SECRETS_DIR/mcp_token")
        log_info "Reusing existing MCP token"
    else
        MCP_AUTH_TOKEN="wazuh_$(generate_secret 32)"
        _generated_new=true
    fi

    if [[ -s "$SECRETS_DIR/openclaw_token" ]]; then
        OPENCLAW_TOKEN=$(cat "$SECRETS_DIR/openclaw_token")
        log_info "Reusing existing OpenClaw token"
    else
        OPENCLAW_TOKEN=$(generate_secret 32)
        _generated_new=true
    fi

    if [[ -s "$SECRETS_DIR/pairing_code" ]]; then
        PAIRING_SECRET=$(cat "$SECRETS_DIR/pairing_code")
        log_info "Reusing existing pairing code"
    else
        PAIRING_SECRET=$(generate_secret 16)
        _generated_new=true
    fi

    if [[ -s "$SECRETS_DIR/approval_secret" ]]; then
        APPROVAL_SECRET=$(cat "$SECRETS_DIR/approval_secret")
        log_info "Reusing existing approval secret"
    else
        APPROVAL_SECRET=$(generate_secret 32)
        _generated_new=true
    fi

    # Store secrets in isolated files with restrictive umask
    local _old_umask
    _old_umask=$(umask)
    umask 0077
    echo "$MCP_AUTH_TOKEN" > "$SECRETS_DIR/mcp_token"
    echo "$OPENCLAW_TOKEN" > "$SECRETS_DIR/openclaw_token"
    echo "$PAIRING_SECRET" > "$SECRETS_DIR/pairing_code"
    echo "$APPROVAL_SECRET" > "$SECRETS_DIR/approval_secret"
    umask "$_old_umask"

    # Verify permissions
    chmod 600 "$SECRETS_DIR"/*

    log_security "MCP token stored: $SECRETS_DIR/mcp_token (mode 600)"
    log_security "OpenClaw token stored: $SECRETS_DIR/openclaw_token (mode 600)"
    log_security "Pairing code stored: $SECRETS_DIR/pairing_code (mode 600)"

    # Export for later use
    export MCP_AUTH_TOKEN OPENCLAW_TOKEN PAIRING_SECRET APPROVAL_SECRET

    if [[ "$_generated_new" == "true" ]]; then
        log_success "Credentials generated and isolated"
    else
        log_success "Existing credentials preserved"
    fi
}

# =============================================================================
# WAZUH MCP SERVER INSTALLATION
# =============================================================================

install_mcp_server() {
    log_step "Installing Wazuh MCP Server (Localhost Only)"

    mkdir -p "$INSTALL_DIR"

    if [[ -d "$MCP_SERVER_DIR" ]]; then
        log_info "Updating existing MCP Server..."
        cd "$MCP_SERVER_DIR"
        git pull origin main 2>/dev/null || git pull origin master 2>/dev/null || true
    else
        log_info "Cloning Wazuh MCP Server from upstream..."
        git clone "$MCP_SERVER_REPO" "$MCP_SERVER_DIR"
    fi

    cd "$MCP_SERVER_DIR"

    log_info "Installing Python dependencies..."
    python3 -m venv "$MCP_SERVER_DIR/.venv" 2>/dev/null || true
    if [[ -f "$MCP_SERVER_DIR/.venv/bin/pip" ]]; then
        "$MCP_SERVER_DIR/.venv/bin/pip" install --quiet -r requirements.txt
    else
        pip3 install --quiet -r requirements.txt 2>/dev/null || pip install --quiet -r requirements.txt
    fi

    # Get Tailscale IP for binding
    TAILSCALE_IP=$(tailscale ip -4 2>/dev/null || echo "127.0.0.1")

    # Create systemd service with secure binding
    local _ts_after=""
    local _ts_requires=""
    local _ts_desc="Wazuh MCP Server"
    if [[ "$SKIP_TAILSCALE" != "true" ]]; then
        _ts_after=" tailscaled.service"
        _ts_requires="Requires=tailscaled.service"
        _ts_desc="Wazuh MCP Server (Tailscale Only)"
    fi
    cat > /etc/systemd/system/wazuh-mcp-server.service << EOF
[Unit]
Description=$_ts_desc
Documentation=https://github.com/gensecaihq/Wazuh-MCP-Server
After=network.target wazuh-manager.service${_ts_after}
Wants=wazuh-manager.service
${_ts_requires}

[Service]
Type=simple
User=root
WorkingDirectory=$MCP_SERVER_DIR/src
ExecStart=$MCP_SERVER_DIR/.venv/bin/python -m wazuh_mcp_server
Restart=always
RestartSec=10
EnvironmentFile=$CONFIG_DIR/.env
Environment="MCP_HOST=$TAILSCALE_IP"
Environment="MCP_PORT=$MCP_PORT"

# Security hardening
NoNewPrivileges=true
ProtectSystem=strict
ProtectHome=read-only
PrivateTmp=true
ReadWritePaths=$DATA_DIR $LOG_DIR $MCP_SERVER_DIR

[Install]
WantedBy=multi-user.target
EOF

    systemctl daemon-reload

    log_success "Wazuh MCP Server installed (Python)"
    log_security "MCP Server will bind to Tailscale IP: $TAILSCALE_IP:$MCP_PORT"
    log_security "NOT accessible from public internet"
}

# =============================================================================
# OPENCLAW INSTALLATION WITH SECURITY HARDENING
# =============================================================================

install_openclaw() {
    log_step "Installing OpenClaw (Localhost Only)"

    if command -v openclaw &>/dev/null; then
        local oc_version
        oc_version=$(openclaw --version 2>/dev/null || echo "unknown")
        log_success "OpenClaw already installed: $oc_version"
    else
        log_info "Installing OpenClaw from upstream..."
        curl -fsSL https://openclaw.ai/install.sh | sh

        if command -v openclaw &>/dev/null; then
            log_success "OpenClaw installed"
        else
            log_warn "OpenClaw CLI not in PATH"
            log_info "You may need to restart your shell or add to PATH"
        fi
    fi

    log_security "OpenClaw Gateway will bind to $GATEWAY_BIND:$GATEWAY_PORT"
    log_security "NOT accessible from public internet"
}

# =============================================================================
# DEPLOY SECURITY-HARDENED OPENCLAW CONFIG
# =============================================================================

deploy_agents() {
    log_step "Deploying Security-Hardened Agents"

    local OC_DIR="$HOME/.openclaw"
    local AGENTS_SRC="$PROJECT_ROOT/openclaw"

    # Read secrets
    local OPENCLAW_TOKEN
    OPENCLAW_TOKEN=$(cat "$SECRETS_DIR/openclaw_token")

    # Create OpenClaw configuration (JSON5 format — validated by OpenClaw's zod schema)
    cat > "$OC_DIR/openclaw.json" << EOF
{
  "gateway": {
    "port": $GATEWAY_PORT,
    "bind": "loopback",
    "auth": {
      "mode": "token",
      "token": "$OPENCLAW_TOKEN"
    }
  },

  "logging": {
    "redactSensitive": "tools"
  },

  "agents": {
    "defaults": {
      "workspace": "~/.openclaw/wazuh-autopilot/workspace",
      "model": {
        "primary": "anthropic/claude-sonnet-4-5",
        "fallbacks": ["openai/gpt-4o", "groq/llama-3.3-70b-versatile"]
      },
      "models": {
        "anthropic/claude-sonnet-4-5": {"alias": "sonnet"},
        "anthropic/claude-haiku-4-5": {"alias": "haiku"}
      },
      "sandbox": {
        "mode": "all",
        "scope": "session"
      },
      "heartbeat": {
        "every": "30m",
        "model": "anthropic/claude-haiku-4-5"
      },
      "memorySearch": {
        "sources": ["memory", "sessions"],
        "provider": "openai",
        "model": "text-embedding-3-small"
      },
      "maxConcurrent": 3,
      "timeoutSeconds": 600
    },

    "list": [
      {
        "id": "wazuh-triage",
        "default": true,
        "workspace": "~/.openclaw/wazuh-autopilot/agents/triage",
        "agentDir": "~/.openclaw/wazuh-autopilot/agents/triage",
        "tools": {
          "profile": "minimal",
          "allow": ["read", "sessions_list", "sessions_history", "sessions_send"],
          "deny": ["write", "edit", "exec", "delete", "browser"]
        },
        "heartbeat": {"every": "10m"}
      },
      {
        "id": "wazuh-correlation",
        "workspace": "~/.openclaw/wazuh-autopilot/agents/correlation",
        "agentDir": "~/.openclaw/wazuh-autopilot/agents/correlation",
        "tools": {
          "profile": "minimal",
          "allow": ["read", "sessions_list", "sessions_history", "sessions_send"],
          "deny": ["write", "edit", "exec", "delete", "browser"]
        },
        "heartbeat": {"every": "5m"}
      },
      {
        "id": "wazuh-investigation",
        "workspace": "~/.openclaw/wazuh-autopilot/agents/investigation",
        "agentDir": "~/.openclaw/wazuh-autopilot/agents/investigation",
        "tools": {
          "profile": "minimal",
          "allow": ["read", "sessions_list", "sessions_history", "sessions_send"],
          "deny": ["write", "edit", "exec", "delete", "browser"]
        }
      },
      {
        "id": "wazuh-response-planner",
        "workspace": "~/.openclaw/wazuh-autopilot/agents/response-planner",
        "agentDir": "~/.openclaw/wazuh-autopilot/agents/response-planner",
        "tools": {
          "profile": "minimal",
          "allow": ["read", "write", "sessions_list", "sessions_history", "sessions_send"],
          "deny": ["exec", "delete", "browser"]
        }
      },
      {
        "id": "wazuh-policy-guard",
        "workspace": "~/.openclaw/wazuh-autopilot/agents/policy-guard",
        "agentDir": "~/.openclaw/wazuh-autopilot/agents/policy-guard",
        "tools": {
          "profile": "minimal",
          "allow": ["read", "sessions_list", "sessions_history", "sessions_send"],
          "deny": ["write", "edit", "exec", "delete", "browser"]
        }
      },
      {
        "id": "wazuh-responder",
        "workspace": "~/.openclaw/wazuh-autopilot/agents/responder",
        "agentDir": "~/.openclaw/wazuh-autopilot/agents/responder",
        "model": {
          "primary": "anthropic/claude-sonnet-4-5",
          "fallbacks": ["openai/gpt-4o"]
        },
        "tools": {
          "profile": "coding",
          "allow": ["read", "write", "exec", "sessions_list", "sessions_history", "sessions_send"],
          "deny": ["browser", "delete"],
          "elevated": {"enabled": true}
        },
        "sandbox": {
          "mode": "all",
          "scope": "agent"
        }
      },
      {
        "id": "wazuh-reporting",
        "workspace": "~/.openclaw/wazuh-autopilot/agents/reporting",
        "agentDir": "~/.openclaw/wazuh-autopilot/agents/reporting",
        "model": "anthropic/claude-haiku-4-5",
        "tools": {
          "profile": "minimal",
          "allow": ["read", "write", "sessions_list", "sessions_history", "sessions_send"],
          "deny": ["exec", "delete", "browser"]
        }
      }
    ]
  },

  "channels": {
    "slack": {
      "enabled": true,
      "botToken": "__SLACK_BOT_TOKEN__",
      "appToken": "__SLACK_APP_TOKEN__",
      "dmPolicy": "allowlist",
      "allowFrom": [],
      "groupPolicy": "allowlist"
    }
  },

  "bindings": [
    {
      "agentId": "wazuh-triage",
      "match": {"channel": "slack", "peer": {"kind": "group", "id": "*"}}
    },
    {
      "agentId": "wazuh-responder",
      "match": {"channel": "slack", "peer": {"kind": "group", "id": "approvals"}}
    }
  ],

  "tools": {
    "profile": "minimal",
    "allow": ["read", "sessions_list", "sessions_history"],
    "deny": ["browser", "canvas"],
    "web": {
      "search": {"enabled": false},
      "fetch": {"enabled": false}
    }
  },

  "cron": {
    "enabled": true,
    "maxConcurrentRuns": 3
  },

  "hooks": {
    "enabled": true,
    "token": "$OPENCLAW_TOKEN",
    "mappings": [
      {"match": {"path": "/webhook/wazuh-alert"}, "action": "agent", "agentId": "wazuh-triage"},
      {"match": {"path": "/webhook/case-created"}, "action": "agent", "agentId": "wazuh-correlation"},
      {"match": {"path": "/webhook/investigation-request"}, "action": "agent", "agentId": "wazuh-investigation"},
      {"match": {"path": "/webhook/plan-request"}, "action": "agent", "agentId": "wazuh-response-planner"},
      {"match": {"path": "/webhook/policy-check"}, "action": "agent", "agentId": "wazuh-policy-guard"},
      {"match": {"path": "/webhook/execute-action"}, "action": "agent", "agentId": "wazuh-responder"}
    ]
  },

  "env": {
    "ANTHROPIC_API_KEY": "__ANTHROPIC_API_KEY__",
    "WAZUH_MCP_URL": "__WAZUH_MCP_URL__",
    "WAZUH_MCP_TOKEN": "__MCP_AUTH_TOKEN__"
  }
}
EOF

    # Set strict permissions on OpenClaw config
    chmod 600 "$OC_DIR/openclaw.json"

    # Copy agent instruction files
    if [[ -d "$AGENTS_SRC/agents" ]]; then
        log_info "Deploying agent instruction files..."
        # Copy per-agent directories (triage, correlation, etc.)
        for agent_dir in "$AGENTS_SRC/agents"/*/; do
            agent_name=$(basename "$agent_dir")
            [[ "$agent_name" == "_shared" ]] && continue
            mkdir -p "$OC_DIR/wazuh-autopilot/agents/$agent_name"
            cp "$agent_dir"*.md "$OC_DIR/wazuh-autopilot/agents/$agent_name/" 2>/dev/null || true
        done
        # Copy shared files (SOUL.md, USER.md) into each agent workspace
        if [[ -d "$AGENTS_SRC/agents/_shared" ]]; then
            for agent_dir in "$OC_DIR/wazuh-autopilot/agents"/*/; do
                cp "$AGENTS_SRC/agents/_shared"/*.md "$agent_dir" 2>/dev/null || true
            done
        fi
        chmod -R 700 "$OC_DIR/wazuh-autopilot/agents"
    fi

    echo ""
    log_success "7 SOC Agents deployed with security hardening:"
    echo ""
    echo "  ┌─────────────────────┬──────────────────────────────────────────┐"
    echo "  │ Agent               │ Security Profile                         │"
    echo "  ├─────────────────────┼──────────────────────────────────────────┤"
    echo "  │ wazuh-triage        │ Read-only, no exec, sandboxed            │"
    echo "  │ wazuh-correlation   │ Read-only, no exec, sandboxed            │"
    echo "  │ wazuh-investigation │ Read-only, no exec, sandboxed            │"
    echo "  │ wazuh-response-plan │ Plan-only, no exec, sandboxed            │"
    echo "  │ wazuh-policy-guard  │ Read-only, no exec, sandboxed            │"
    echo "  │ wazuh-responder     │ Elevated only via Slack, full sandbox    │"
    echo "  │ wazuh-reporting     │ Read/write reports, no exec              │"
    echo "  └─────────────────────┴──────────────────────────────────────────┘"
    echo ""

    log_security "OpenClaw config: $OC_DIR/openclaw.json (mode 600)"
    log_security "Gateway binding: $GATEWAY_BIND:$GATEWAY_PORT (localhost only)"
    log_security "DM policy: allowlist (no public messages)"
    log_security "Pairing mode: enabled (requires approval)"
}

# =============================================================================
# RUNTIME SERVICE INSTALLATION
# =============================================================================

install_runtime_service() {
    log_step "Installing Runtime Service (Localhost Only)"

    local RUNTIME_SRC="$PROJECT_ROOT/runtime/autopilot-service"
    local RUNTIME_DST="$INSTALL_DIR/runtime"

    mkdir -p "$RUNTIME_DST"
    cp -r "$RUNTIME_SRC"/* "$RUNTIME_DST/"

    cd "$RUNTIME_DST"
    log_info "Installing dependencies..."
    npm install --production 2>/dev/null || npm install

    # Create systemd service with security hardening
    cat > /etc/systemd/system/wazuh-autopilot.service << EOF
[Unit]
Description=Wazuh OpenClaw Autopilot Runtime (Localhost Only)
Documentation=https://github.com/gensecaihq/Wazuh-Openclaw-Autopilot
After=network.target wazuh-mcp-server.service
Wants=wazuh-mcp-server.service

[Service]
Type=simple
User=root
WorkingDirectory=$RUNTIME_DST
Environment="NODE_ENV=production"
ExecStart=/usr/bin/node index.js
Restart=always
RestartSec=10
EnvironmentFile=$CONFIG_DIR/.env

# Security hardening
NoNewPrivileges=true
ProtectSystem=strict
ProtectHome=read-only
PrivateTmp=true
ReadWritePaths=$DATA_DIR $LOG_DIR

[Install]
WantedBy=multi-user.target
EOF

    systemctl daemon-reload

    log_success "Runtime Service installed"
    log_security "Runtime binding: $GATEWAY_BIND:$RUNTIME_PORT (localhost only)"
}

# =============================================================================
# CONFIGURATION
# =============================================================================

configure_system() {
    log_step "System Configuration"

    # Get Tailscale IP
    TAILSCALE_IP=$(tailscale ip -4 2>/dev/null || echo "127.0.0.1")

    # Read secrets
    local MCP_AUTH_TOKEN OPENCLAW_TOKEN APPROVAL_SECRET PAIRING_SECRET
    MCP_AUTH_TOKEN=$(cat "$SECRETS_DIR/mcp_token")
    OPENCLAW_TOKEN=$(cat "$SECRETS_DIR/openclaw_token")
    APPROVAL_SECRET=$(cat "$SECRETS_DIR/approval_secret")
    PAIRING_SECRET=$(cat "$SECRETS_DIR/pairing_code")

    echo ""
    echo -e "${CYAN}${BOLD}Wazuh API Configuration${NC}"
    echo ""
    echo "  Enter your Wazuh API credentials."
    echo ""

    local WAZUH_API_URL WAZUH_HOST WAZUH_PORT_NUM WAZUH_USER WAZUH_PASS
    read -rp "  Wazuh API URL [https://127.0.0.1:55000]: " WAZUH_API_URL
    WAZUH_API_URL="${WAZUH_API_URL:-https://127.0.0.1:55000}"

    # Parse URL into host and port for Wazuh MCP Server
    WAZUH_HOST="${WAZUH_API_URL#https://}"
    WAZUH_HOST="${WAZUH_HOST#http://}"
    if [[ "$WAZUH_HOST" == *:* ]]; then
        WAZUH_PORT_NUM="${WAZUH_HOST##*:}"
        WAZUH_HOST="${WAZUH_HOST%:*}"
    else
        WAZUH_PORT_NUM="55000"
    fi

    read -rp "  Wazuh API Username [wazuh-wui]: " WAZUH_USER
    WAZUH_USER="${WAZUH_USER:-wazuh-wui}"

    read -rsp "  Wazuh API Password: " WAZUH_PASS
    echo ""

    if [[ -z "$WAZUH_PASS" ]]; then
        log_error "Wazuh API password cannot be empty"
        exit 1
    fi

    # Validate Wazuh API connectivity
    # Use .netrc-style file to avoid exposing password in process table via curl -u
    log_info "Testing Wazuh API connectivity..."
    local _wazuh_test_response
    local _curl_netrc
    _curl_netrc=$(mktemp)
    chmod 600 "$_curl_netrc"
    printf 'machine %s\nlogin %s\npassword %s\n' "$WAZUH_HOST" "$WAZUH_USER" "$WAZUH_PASS" > "$_curl_netrc"
    _wazuh_test_response=$(curl -sk -o /dev/null -w "%{http_code}" \
        --netrc-file "$_curl_netrc" \
        "$WAZUH_API_URL/security/user/authenticate" 2>/dev/null || echo "000")
    rm -f "$_curl_netrc"
    if [[ "$_wazuh_test_response" == "000" ]]; then
        log_warn "Cannot reach Wazuh API at $WAZUH_API_URL — verify URL and that Wazuh is running"
        if ! confirm "  Continue anyway?" "n"; then
            exit 1
        fi
    elif [[ "$_wazuh_test_response" == "401" ]]; then
        log_error "Wazuh API authentication failed (HTTP 401) — check username/password"
        if ! confirm "  Continue anyway?" "n"; then
            exit 1
        fi
    elif [[ "$_wazuh_test_response" =~ ^2 ]]; then
        log_success "Wazuh API connection verified (HTTP $_wazuh_test_response)"
    else
        log_warn "Wazuh API returned HTTP $_wazuh_test_response — may indicate a configuration issue"
        if ! confirm "  Continue anyway?" "n"; then
            exit 1
        fi
    fi

    echo ""
    echo -e "${CYAN}${BOLD}API Keys Configuration${NC}"
    echo ""
    echo "  You need an Anthropic API key for the AI agents."
    echo "  Get one at: https://console.anthropic.com/"
    echo ""

    local ANTHROPIC_API_KEY
    read -rsp "  Anthropic API Key (sk-ant-...): " ANTHROPIC_API_KEY
    echo ""

    # Validate API key format
    if [[ -n "$ANTHROPIC_API_KEY" && ! "$ANTHROPIC_API_KEY" =~ ^sk-ant- ]]; then
        log_warn "Anthropic API key doesn't start with 'sk-ant-' — please verify it's correct"
    fi
    if [[ -z "$ANTHROPIC_API_KEY" ]]; then
        log_error "Anthropic API key is required for the AI agents"
        exit 1
    fi

    echo ""
    echo -e "${CYAN}${BOLD}Slack Integration (Optional)${NC}"
    echo ""
    echo "  Slack is used for:"
    echo "    • Alert notifications"
    echo "    • Two-tier approval workflow (Approve → Execute)"
    echo "    • Case cards and reports"
    echo ""

    local SLACK_APP_TOKEN="" SLACK_BOT_TOKEN=""
    local SLACK_ALERTS_CHANNEL="" SLACK_APPROVALS_CHANNEL=""

    if confirm "  Configure Slack now?" "n"; then
        echo ""
        echo "  Create a Slack app at: https://api.slack.com/apps"
        echo ""
        read -rp "  Slack App Token (xapp-...): " SLACK_APP_TOKEN
        read -rp "  Slack Bot Token (xoxb-...): " SLACK_BOT_TOKEN
        read -rp "  Alerts Channel ID (C...): " SLACK_ALERTS_CHANNEL
        read -rp "  Approvals Channel ID (C...): " SLACK_APPROVALS_CHANNEL

        # Validate Slack token formats
        if [[ -n "$SLACK_APP_TOKEN" && ! "$SLACK_APP_TOKEN" =~ ^xapp- ]]; then
            log_warn "Slack App Token doesn't start with 'xapp-' — please verify it's correct"
        fi
        if [[ -n "$SLACK_BOT_TOKEN" && ! "$SLACK_BOT_TOKEN" =~ ^xoxb- ]]; then
            log_warn "Slack Bot Token doesn't start with 'xoxb-' — please verify it's correct"
        fi
        if [[ -n "$SLACK_ALERTS_CHANNEL" && ! "$SLACK_ALERTS_CHANNEL" =~ ^C ]]; then
            log_warn "Slack channel ID should start with 'C' — please verify it's correct"
        fi
    fi

    # Create configuration file
    # Use quoted heredoc to prevent shell expansion of $, then substitute known vars
    local _generated_at
    _generated_at=$(date -Iseconds)
    cat > "$CONFIG_DIR/.env" << 'ENVEOF'
# =============================================================================
# WAZUH OPENCLAW AUTOPILOT - SECURITY HARDENED CONFIGURATION
# =============================================================================
# Two-tier human approval required for all actions
# =============================================================================

# WAZUH CONNECTION (used by Wazuh MCP Server)
WAZUH_HOST=__WAZUH_HOST__
WAZUH_PORT=__WAZUH_PORT_NUM__
WAZUH_USER=__WAZUH_USER__
WAZUH_PASS=__WAZUH_PASS__
WAZUH_VERIFY_SSL=true
WAZUH_ALLOW_SELF_SIGNED=true

# MCP SERVER AUTHENTICATION
AUTH_MODE=bearer
MCP_API_KEY=__MCP_AUTH_TOKEN__

# MCP SERVER NETWORK
MCP_HOST=__TAILSCALE_IP__
MCP_PORT=__MCP_PORT__
MCP_URL=http://__TAILSCALE_IP__:__MCP_PORT__
AUTOPILOT_MCP_AUTH=__MCP_AUTH_TOKEN__

# OPENCLAW GATEWAY (Localhost Only)
OPENCLAW_HOST=__GATEWAY_BIND__
OPENCLAW_PORT=__GATEWAY_PORT__
OPENCLAW_TOKEN=__OPENCLAW_TOKEN__

# AI PROVIDER
ANTHROPIC_API_KEY=__ANTHROPIC_API_KEY__

# RUNTIME SERVICE (Localhost Only)
AUTOPILOT_HOST=__GATEWAY_BIND__
AUTOPILOT_PORT=__RUNTIME_PORT__
AUTOPILOT_DATA_DIR=__DATA_DIR__
AUTOPILOT_LOG_DIR=__LOG_DIR__
AUTOPILOT_CONFIG_DIR=__CONFIG_DIR__

# APPROVAL SYSTEM
AUTOPILOT_TOKEN_SECRET=__APPROVAL_SECRET__
AUTOPILOT_TOKEN_TTL_MINUTES=60

# PAIRING MODE
AUTOPILOT_PAIRING_CODE=__PAIRING_SECRET__
AUTOPILOT_PAIRING_ENABLED=true

# RESPONDER AGENT - TWO-TIER HUMAN APPROVAL
# SAFETY: Disabled by default. Every action requires human Approve + Execute.
AUTOPILOT_RESPONDER_ENABLED=false

# SLACK INTEGRATION
SLACK_APP_TOKEN=__SLACK_APP_TOKEN__
SLACK_BOT_TOKEN=__SLACK_BOT_TOKEN__
SLACK_ALERTS_CHANNEL=__SLACK_ALERTS_CHANNEL__
SLACK_APPROVALS_CHANNEL=__SLACK_APPROVALS_CHANNEL__

# TAILSCALE
TAILSCALE_IP=__TAILSCALE_IP__
ENVEOF

    # Substitute placeholders with actual values (safe for special chars in passwords)
    local _envfile="$CONFIG_DIR/.env"
    sed -i.bak \
        -e "s|__WAZUH_HOST__|${WAZUH_HOST}|g" \
        -e "s|__WAZUH_PORT_NUM__|${WAZUH_PORT_NUM}|g" \
        -e "s|__MCP_PORT__|${MCP_PORT}|g" \
        -e "s|__GATEWAY_BIND__|${GATEWAY_BIND}|g" \
        -e "s|__GATEWAY_PORT__|${GATEWAY_PORT}|g" \
        -e "s|__RUNTIME_PORT__|${RUNTIME_PORT}|g" \
        -e "s|__DATA_DIR__|${DATA_DIR}|g" \
        -e "s|__LOG_DIR__|${LOG_DIR}|g" \
        -e "s|__CONFIG_DIR__|${CONFIG_DIR}|g" \
        "$_envfile"
    rm -f "${_envfile}.bak"

    # Substitute secrets using exported env vars and ENVIRON[] in awk.
    # This avoids both: (a) sed delimiter issues with special chars in secrets,
    # and (b) awk -v backslash interpretation that corrupts passwords with \ chars.
    local _tmpenv
    local _old_umask
    _old_umask=$(umask)
    umask 0077  # Ensure temp files are created with 600 permissions

    _safe_subst() {
        # Usage: _safe_subst PLACEHOLDER ENV_VAR_NAME FILE
        # Uses ENVIRON[] to avoid awk -v backslash interpretation
        local placeholder="$1" envvar="$2" file="$3"
        local tmpf
        tmpf=$(mktemp "${file}.XXXXXX")
        export "$envvar"
        awk -v ph="$placeholder" 'BEGIN{val=ENVIRON[ARGV[2]]; delete ARGV[2]} {gsub(ph, val)}1' "$file" "$envvar" > "$tmpf" && mv "$tmpf" "$file"
    }

    _safe_subst "__WAZUH_USER__" "WAZUH_USER" "$_envfile"
    _safe_subst "__WAZUH_PASS__" "WAZUH_PASS" "$_envfile"
    _safe_subst "__TAILSCALE_IP__" "TAILSCALE_IP" "$_envfile"
    _safe_subst "__MCP_AUTH_TOKEN__" "MCP_AUTH_TOKEN" "$_envfile"
    _safe_subst "__OPENCLAW_TOKEN__" "OPENCLAW_TOKEN" "$_envfile"
    _safe_subst "__ANTHROPIC_API_KEY__" "ANTHROPIC_API_KEY" "$_envfile"
    _safe_subst "__APPROVAL_SECRET__" "APPROVAL_SECRET" "$_envfile"
    _safe_subst "__PAIRING_SECRET__" "PAIRING_SECRET" "$_envfile"
    _safe_subst "__SLACK_APP_TOKEN__" "SLACK_APP_TOKEN" "$_envfile"
    _safe_subst "__SLACK_BOT_TOKEN__" "SLACK_BOT_TOKEN" "$_envfile"
    _safe_subst "__SLACK_ALERTS_CHANNEL__" "SLACK_ALERTS_CHANNEL" "$_envfile"
    _safe_subst "__SLACK_APPROVALS_CHANNEL__" "SLACK_APPROVALS_CHANNEL" "$_envfile"

    umask "$_old_umask"

    chmod 600 "$CONFIG_DIR/.env"

    # Substitute placeholders in openclaw.json (generated earlier with placeholder values)
    local _ocjson="$HOME/.openclaw/openclaw.json"
    if [[ -f "$_ocjson" ]]; then
        local _old_umask2
        _old_umask2=$(umask)
        umask 0077

        # Construct MCP URL for substitution
        export WAZUH_MCP_URL_COMPUTED="http://$TAILSCALE_IP:$MCP_PORT"

        _safe_subst "__ANTHROPIC_API_KEY__" "ANTHROPIC_API_KEY" "$_ocjson"
        _safe_subst "__WAZUH_MCP_URL__" "WAZUH_MCP_URL_COMPUTED" "$_ocjson"
        _safe_subst "__MCP_AUTH_TOKEN__" "MCP_AUTH_TOKEN" "$_ocjson"
        _safe_subst "__SLACK_BOT_TOKEN__" "SLACK_BOT_TOKEN" "$_ocjson"
        _safe_subst "__SLACK_APP_TOKEN__" "SLACK_APP_TOKEN" "$_ocjson"

        umask "$_old_umask2"
        chmod 600 "$_ocjson"
        log_success "OpenClaw config updated with credentials"
    fi

    # Copy policies
    if [[ -d "$PROJECT_ROOT/policies" ]]; then
        mkdir -p "$CONFIG_DIR/policies"
        cp -r "$PROJECT_ROOT/policies"/* "$CONFIG_DIR/policies/"
        chmod -R 640 "$CONFIG_DIR/policies"
    fi

    log_success "Configuration saved"
    log_security "Config file: $CONFIG_DIR/.env (mode 600)"
}

# =============================================================================
# WAZUH INTEGRATOR CONFIGURATION
# =============================================================================

configure_wazuh_integrator() {
    log_step "Configuring Wazuh Alert Forwarding"

    local OSSEC_CONF="/var/ossec/etc/ossec.conf"

    if [[ ! -f "$OSSEC_CONF" ]]; then
        log_warn "ossec.conf not found - skipping integrator setup"
        return 0
    fi

    if grep -q "wazuh-autopilot" "$OSSEC_CONF" 2>/dev/null; then
        log_info "Wazuh Integrator already configured"
        return 0
    fi

    echo ""
    echo "  The Wazuh Integrator will forward high-severity alerts"
    echo "  (level 10+) to Autopilot for autonomous triage."
    echo ""
    echo "  Alerts go to localhost only - no external exposure."
    echo ""

    if confirm "  Configure automatic alert forwarding?" "y"; then
        # Create integrator script
        cat > /var/ossec/integrations/wazuh-autopilot << SCRIPT
#!/bin/bash
# Wazuh OpenClaw Autopilot Integration
# Forwards alerts to localhost runtime service

ALERT_FILE="\$1"
WEBHOOK="http://$GATEWAY_BIND:$RUNTIME_PORT/api/alerts"

if [[ -f "\$ALERT_FILE" ]]; then
    curl -s -X POST "\$WEBHOOK" \\
        -H "Content-Type: application/json" \\
        -d @"\$ALERT_FILE" \\
        --connect-timeout 5 \\
        >/dev/null 2>&1 || true
fi

exit 0
SCRIPT

        chmod 750 /var/ossec/integrations/wazuh-autopilot
        chown root:wazuh /var/ossec/integrations/wazuh-autopilot

        # Backup ossec.conf
        cp "$OSSEC_CONF" "$OSSEC_CONF.backup.$(date +%Y%m%d%H%M%S)"

        # Add integration config
        local INTEGRATOR_CONFIG="
  <!-- Wazuh OpenClaw Autopilot - Localhost Only -->
  <integration>
    <name>wazuh-autopilot</name>
    <hook_url>http://$GATEWAY_BIND:$RUNTIME_PORT/api/alerts</hook_url>
    <level>10</level>
    <alert_format>json</alert_format>
  </integration>
"
        # Use awk for safe multi-line insertion (avoids sed injection with special chars)
        awk -v config="$INTEGRATOR_CONFIG" '/<\/ossec_config>/{print config}1' "$OSSEC_CONF" > "${OSSEC_CONF}.tmp" && mv "${OSSEC_CONF}.tmp" "$OSSEC_CONF"

        log_success "Alert forwarding configured (level 10+)"
        log_security "Alerts sent to localhost only"
    fi
}

# =============================================================================
# PRE-FLIGHT CONFIGURATION VALIDATOR
# =============================================================================

validate_configuration() {
    log_step "Pre-flight Configuration Validation"

    local issues=0
    local warnings=0

    echo ""
    echo "  Validating configuration before starting services..."
    echo ""

    # --- Required checks ---

    # Check Wazuh API config
    if grep -q "^WAZUH_HOST=.\+" "$CONFIG_DIR/.env" 2>/dev/null; then
        echo -e "  ${GREEN}✓${NC} Wazuh host configured"
    else
        echo -e "  ${RED}✗${NC} WAZUH_HOST not configured"
        issues=$((issues + 1))
    fi

    if grep -q "^WAZUH_PASS=.\+" "$CONFIG_DIR/.env" 2>/dev/null; then
        echo -e "  ${GREEN}✓${NC} Wazuh API credentials set"
    else
        echo -e "  ${RED}✗${NC} WAZUH_PASS not set"
        issues=$((issues + 1))
    fi

    # Check MCP URL
    if grep -q "^MCP_URL=.\+" "$CONFIG_DIR/.env" 2>/dev/null; then
        echo -e "  ${GREEN}✓${NC} MCP Server URL configured"
    else
        echo -e "  ${RED}✗${NC} MCP Server URL not configured"
        issues=$((issues + 1))
    fi

    # Check at least one LLM provider (cloud API key OR local Ollama)
    local has_llm_provider=false
    for key in ANTHROPIC_API_KEY OPENAI_API_KEY GROQ_API_KEY MISTRAL_API_KEY XAI_API_KEY GOOGLE_API_KEY OPENROUTER_API_KEY TOGETHER_API_KEY CEREBRAS_API_KEY; do
        if grep -q "^${key}=.\+" "$CONFIG_DIR/.env" 2>/dev/null; then
            has_llm_provider=true
            break
        fi
    done
    # Also check for Ollama (air-gapped deployments)
    if ! $has_llm_provider && command -v ollama &>/dev/null; then
        has_llm_provider=true
    fi
    if $has_llm_provider; then
        echo -e "  ${GREEN}✓${NC} LLM provider available"
    else
        echo -e "  ${YELLOW}!${NC} No LLM API key or local Ollama found"
        echo -e "        Set at least one provider key in .env, or install Ollama for air-gapped mode"
        warnings=$((warnings + 1))
    fi

    # Check policy file exists
    if [[ -f "$CONFIG_DIR/policies/policy.yaml" ]]; then
        echo -e "  ${GREEN}✓${NC} Policy file present"
    else
        echo -e "  ${RED}✗${NC} Policy file missing"
        issues=$((issues + 1))
    fi

    # Check toolmap file exists
    if [[ -f "$CONFIG_DIR/policies/toolmap.yaml" ]]; then
        echo -e "  ${GREEN}✓${NC} Toolmap file present"
    else
        echo -e "  ${RED}✗${NC} Toolmap file missing"
        issues=$((issues + 1))
    fi

    # Check OpenClaw token
    if [[ -f "$SECRETS_DIR/openclaw_token" ]] && [[ -s "$SECRETS_DIR/openclaw_token" ]]; then
        echo -e "  ${GREEN}✓${NC} OpenClaw token generated"
    else
        echo -e "  ${RED}✗${NC} OpenClaw token not found"
        issues=$((issues + 1))
    fi

    # --- Optional checks (warnings only) ---

    echo ""
    echo "  Optional integrations:"
    echo ""

    # Slack (optional)
    if grep -q "^SLACK_APP_TOKEN=xapp-" "$CONFIG_DIR/.env" 2>/dev/null && \
       grep -q "^SLACK_BOT_TOKEN=xoxb-" "$CONFIG_DIR/.env" 2>/dev/null; then
        echo -e "  ${GREEN}✓${NC} Slack integration configured"
    else
        echo -e "  ${YELLOW}○${NC} Slack not configured (optional - approvals work via REST API)"
        warnings=$((warnings + 1))
    fi

    # Check if ports are available
    echo ""
    echo "  Port availability:"
    echo ""

    for port_pair in "GATEWAY:$GATEWAY_PORT" "MCP:$MCP_PORT" "RUNTIME:$RUNTIME_PORT"; do
        local label="${port_pair%%:*}"
        local port="${port_pair##*:}"
        if ! ss -tlnp 2>/dev/null | grep -q ":${port} " && \
           ! netstat -tlnp 2>/dev/null | grep -q ":${port} "; then
            echo -e "  ${GREEN}✓${NC} Port $port ($label) available"
        else
            echo -e "  ${YELLOW}!${NC} Port $port ($label) already in use"
            warnings=$((warnings + 1))
        fi
    done

    # --- Summary ---
    echo ""
    if [[ $issues -gt 0 ]]; then
        log_error "Validation found $issues critical issue(s)"
        echo ""
        if confirm "  Continue anyway? (services may not function correctly)" "n"; then
            log_warn "Continuing with $issues unresolved issue(s)"
        else
            log_error "Fix the issues above and re-run the installer"
            exit 1
        fi
    elif [[ $warnings -gt 0 ]]; then
        log_success "Validation passed with $warnings optional warning(s)"
    else
        log_success "All configuration checks passed"
    fi
}

# =============================================================================
# RESPONDER ACTIVATION PROMPT
# =============================================================================

prompt_responder_activation() {
    log_step "Responder Agent Configuration"

    echo ""
    echo -e "  ${YELLOW}${BOLD}RESPONDER AGENT${NC}"
    echo ""
    echo "  The Responder Agent can execute Wazuh Active Response actions:"
    echo ""
    echo "    • Block IP addresses"
    echo "    • Isolate hosts from network"
    echo "    • Terminate processes"
    echo "    • Disable user accounts"
    echo "    • Quarantine files"
    echo ""
    echo -e "  ${GREEN}SAFETY CONTROLS (always enforced):${NC}"
    echo ""
    echo "    ✓ Two-tier human approval:"
    echo "        1. Human clicks 'Approve' - validates the plan"
    echo "        2. Human clicks 'Execute' - triggers the action"
    echo ""
    echo "    ✓ AI agents CANNOT bypass human approval"
    echo "    ✓ Full audit trail for compliance"
    echo "    ✓ Rollback capability for reversible actions"
    echo ""

    if confirm "  Enable Responder Agent capability?" "n"; then
        sed -i 's/AUTOPILOT_RESPONDER_ENABLED=false/AUTOPILOT_RESPONDER_ENABLED=true/' "$CONFIG_DIR/.env"
        echo ""
        log_success "Responder capability ENABLED"
        echo ""
        echo -e "  ${YELLOW}Remember: Human approval still required for every action${NC}"
        echo ""
    else
        echo ""
        log_info "Responder remains DISABLED (read-only mode)"
        echo ""
        echo "  Enable later by setting AUTOPILOT_RESPONDER_ENABLED=true"
        echo ""
    fi
}

# =============================================================================
# PAIRING MODE DISPLAY
# =============================================================================

show_pairing_info() {
    log_step "Pairing Mode Information"

    local PAIRING_CODE
    PAIRING_CODE=$(cat "$SECRETS_DIR/pairing_code")

    echo ""
    echo -e "  ${GREEN}${BOLD}SECURE PAIRING MODE${NC}"
    echo ""
    echo "  New devices must pair before connecting to the gateway."
    echo ""
    echo "  ┌─────────────────────────────────────────────────────────┐"
    echo "  │                                                         │"
    echo -e "  │  ${BOLD}Pairing Code:${NC}  $PAIRING_CODE                   │"
    echo "  │                                                         │"
    echo "  │  Store this code securely.                              │"
    echo "  │  It's required when adding new devices.                 │"
    echo "  │                                                         │"
    echo "  │  Location: $SECRETS_DIR/pairing_code      │"
    echo "  │                                                         │"
    echo "  └─────────────────────────────────────────────────────────┘"
    echo ""
}

# =============================================================================
# START SERVICES
# =============================================================================

start_services() {
    log_step "Starting Services"

    # Start MCP Server
    log_info "Starting Wazuh MCP Server..."
    systemctl enable wazuh-mcp-server >/dev/null 2>&1
    systemctl start wazuh-mcp-server

    sleep 3

    if systemctl is-active --quiet wazuh-mcp-server; then
        log_success "Wazuh MCP Server running (Tailscale only)"
    else
        log_error "MCP Server failed to start"
        echo "  Check: journalctl -u wazuh-mcp-server -n 50"
    fi

    # Start Runtime Service
    log_info "Starting Runtime Service..."
    systemctl enable wazuh-autopilot >/dev/null 2>&1
    systemctl start wazuh-autopilot

    sleep 3

    if systemctl is-active --quiet wazuh-autopilot; then
        log_success "Runtime Service running (localhost only)"
    else
        log_error "Runtime Service failed to start"
        echo "  Check: journalctl -u wazuh-autopilot -n 50"
    fi

    # Restart Wazuh if integrator configured
    if grep -q "wazuh-autopilot" /var/ossec/etc/ossec.conf 2>/dev/null; then
        log_info "Restarting Wazuh Manager..."
        systemctl restart wazuh-manager 2>/dev/null || /var/ossec/bin/wazuh-control restart
        log_success "Wazuh Manager restarted"
    fi
}

# =============================================================================
# SECURITY AUDIT
# =============================================================================

run_security_audit() {
    log_step "Security Audit"

    echo ""
    echo "  Checking security configuration..."
    echo ""

    local issues=0

    # Check gateway binding
    if grep -q "bind.*loopback\|bind.*127.0.0.1" "$HOME/.openclaw/openclaw.json" 2>/dev/null; then
        echo -e "  ${GREEN}✓${NC} Gateway binds to localhost"
    else
        echo -e "  ${RED}✗${NC} Gateway binding not verified"
        issues=$((issues + 1))
    fi

    # Check directory permissions
    local config_perms
    config_perms=$(stat -f %Lp "$CONFIG_DIR" 2>/dev/null || stat -c %a "$CONFIG_DIR" 2>/dev/null || echo "000")
    if [[ "$config_perms" == "700" ]]; then
        echo -e "  ${GREEN}✓${NC} Config directory permissions (700)"
    else
        echo -e "  ${YELLOW}!${NC} Config directory permissions: $config_perms (should be 700)"
        issues=$((issues + 1))
    fi

    # Check secrets permissions
    local secrets_perms
    secrets_perms=$(stat -f %Lp "$SECRETS_DIR" 2>/dev/null || stat -c %a "$SECRETS_DIR" 2>/dev/null || echo "000")
    if [[ "$secrets_perms" == "700" ]]; then
        echo -e "  ${GREEN}✓${NC} Secrets directory permissions (700)"
    else
        echo -e "  ${YELLOW}!${NC} Secrets directory permissions: $secrets_perms (should be 700)"
        issues=$((issues + 1))
    fi

    # Check env file permissions
    local env_perms
    env_perms=$(stat -f %Lp "$CONFIG_DIR/.env" 2>/dev/null || stat -c %a "$CONFIG_DIR/.env" 2>/dev/null || echo "000")
    if [[ "$env_perms" == "600" ]]; then
        echo -e "  ${GREEN}✓${NC} Environment file permissions (600)"
    else
        echo -e "  ${YELLOW}!${NC} Environment file permissions: $env_perms (should be 600)"
        issues=$((issues + 1))
    fi

    # Check Tailscale
    if [[ "$SKIP_TAILSCALE" == "true" ]]; then
        echo -e "  ${YELLOW}○${NC} Tailscale skipped (bootstrap/air-gapped mode)"
    elif tailscale status &>/dev/null; then
        echo -e "  ${GREEN}✓${NC} Tailscale connected"
    else
        echo -e "  ${RED}✗${NC} Tailscale not connected"
        issues=$((issues + 1))
    fi

    # Check firewall
    if ufw status 2>/dev/null | grep -q "active"; then
        echo -e "  ${GREEN}✓${NC} Firewall active (UFW)"
    elif firewall-cmd --state 2>/dev/null | grep -q "running"; then
        echo -e "  ${GREEN}✓${NC} Firewall active (firewalld)"
    else
        echo -e "  ${YELLOW}!${NC} No firewall detected"
        issues=$((issues + 1))
    fi

    # Check responder status
    if grep -q "AUTOPILOT_RESPONDER_ENABLED=true" "$CONFIG_DIR/.env" 2>/dev/null; then
        echo -e "  ${YELLOW}!${NC} Responder ENABLED (two-tier approval active)"
    else
        echo -e "  ${GREEN}✓${NC} Responder DISABLED (safe mode)"
    fi

    echo ""
    if [[ $issues -eq 0 ]]; then
        log_success "Security audit passed"
    else
        log_warn "Security audit found $issues issue(s) - review above"
    fi
}

# =============================================================================
# COMPLETION SUMMARY
# =============================================================================

print_summary() {
    TAILSCALE_IP="${TAILSCALE_IP:-$(tailscale ip -4 2>/dev/null || echo '127.0.0.1')}"

    echo ""
    echo -e "${GREEN}${BOLD}"
    echo "  ╔═══════════════════════════════════════════════════════════════╗"
    echo "  ║                                                               ║"
    echo "  ║     INSTALLATION COMPLETE                                     ║"
    echo "  ║     Security-Hardened Configuration                           ║"
    echo "  ║                                                               ║"
    echo "  ╚═══════════════════════════════════════════════════════════════╝"
    echo -e "${NC}"
    echo ""
    echo -e "  ${CYAN}Network Security:${NC}"
    echo "    • Gateway:    127.0.0.1:$GATEWAY_PORT (localhost only)"
    echo "    • MCP Server: $TAILSCALE_IP:$MCP_PORT (Tailscale only)"
    echo "    • Runtime:    127.0.0.1:$RUNTIME_PORT (localhost only)"
    echo "    • NO services exposed to public internet"
    echo ""
    echo -e "  ${CYAN}Configuration:${NC}"
    echo "    • Config:   $CONFIG_DIR/.env (mode 600)"
    echo "    • Secrets:  $SECRETS_DIR (mode 700)"
    echo "    • Data:     $DATA_DIR"
    echo ""
    echo -e "  ${CYAN}Commands:${NC}"
    echo "    • View logs:       journalctl -u wazuh-autopilot -f"
    echo "    • Check health:    curl http://127.0.0.1:$RUNTIME_PORT/health"
    echo "    • Start OpenClaw:  openclaw gateway start"
    echo "    • Security audit:  openclaw doctor --fix"
    echo ""
    echo -e "  ${CYAN}Next Steps:${NC}"
    echo "    1. Start OpenClaw: openclaw gateway start"
    echo "    2. Configure Slack channels in $CONFIG_DIR/policies/policy.yaml"
    echo "    3. Test alert ingestion"
    echo ""

    if grep -q "AUTOPILOT_RESPONDER_ENABLED=true" "$CONFIG_DIR/.env" 2>/dev/null; then
        echo -e "  ${YELLOW}Responder: ENABLED - human approval required for every action${NC}"
    else
        echo -e "  ${GREEN}Responder: DISABLED - system is in read-only mode${NC}"
    fi
    echo ""
}

# =============================================================================
# MAIN
# =============================================================================

main() {
    parse_args "$@"

    # Cleanup handler: remove orphaned temp files containing secrets on failure
    trap '_cleanup_on_exit' EXIT INT TERM
    _cleanup_on_exit() {
        local _exit_code=$?
        # Remove any orphaned temp files containing secrets
        if [[ -n "${CONFIG_DIR:-}" ]]; then
            rm -f "${CONFIG_DIR}/.env."?????? 2>/dev/null || true
        fi
        # Also clean up openclaw.json temp files
        local _oc_dir="${HOME:-/root}/.openclaw"
        if [[ -d "$_oc_dir" ]]; then
            rm -f "${_oc_dir}/openclaw.json."?????? 2>/dev/null || true
        fi
        if [[ $_exit_code -ne 0 ]]; then
            echo ""
            echo -e "${RED}Installation failed (exit code $_exit_code). Partial state may remain.${NC}"
            echo -e "${YELLOW}To clean up: sudo bash $0 --uninstall${NC}"
        fi
        exit "$_exit_code"
    }

    show_security_banner

    if ! confirm "Continue with security-hardened installation?" "y"; then
        echo "Installation cancelled."
        exit 0
    fi

    show_security_guidance

    check_root
    check_os
    check_wazuh
    install_dependencies
    configure_firewall

    if [[ "$SKIP_TAILSCALE" == "true" ]]; then
        log_step "Skipping Tailscale (bootstrap/air-gapped mode)"
        log_info "Using 127.0.0.1 for all service bindings"
        TAILSCALE_IP="127.0.0.1"
    else
        install_tailscale
    fi

    setup_secure_directories
    setup_credentials
    install_mcp_server
    install_openclaw
    deploy_agents
    install_runtime_service
    configure_system
    configure_wazuh_integrator
    validate_configuration
    prompt_responder_activation
    show_pairing_info
    start_services
    run_security_audit
    print_summary
}

# Run
main "$@"
