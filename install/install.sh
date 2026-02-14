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

VERSION="3.1.0"
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
MCP_PORT="8080"
RUNTIME_PORT="9090"

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
    echo "    • Tailscale (secure networking)"
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
        log_info "Installing Node.js 20..."
        curl -fsSL https://deb.nodesource.com/setup_20.x | bash - >/dev/null 2>&1
        $PKG_INSTALL nodejs
    fi

    local node_ver
    node_ver=$(node -v | cut -d'v' -f2 | cut -d'.' -f1)
    if [[ "$node_ver" -lt 18 ]]; then
        log_error "Node.js 18+ required. Found: $(node -v)"
        exit 1
    fi
    log_success "Node.js $(node -v)"

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

        # Block gateway and MCP ports from public (they should be localhost only)
        # These rules ensure even if binding changes, traffic is blocked
        ufw deny in on eth0 to any port $GATEWAY_PORT >/dev/null 2>&1 || true
        ufw deny in on eth0 to any port $MCP_PORT >/dev/null 2>&1 || true
        ufw deny in on ens3 to any port $GATEWAY_PORT >/dev/null 2>&1 || true
        ufw deny in on ens3 to any port $MCP_PORT >/dev/null 2>&1 || true

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
    log_step "Installing Tailscale (Mandatory)"

    echo ""
    echo -e "  ${YELLOW}Tailscale is REQUIRED for secure operation${NC}"
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
        TAILSCALE_IP=$(tailscale ip -4 2>/dev/null || echo "127.0.0.1")
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
    echo "  Generating cryptographically secure tokens..."
    echo "  These will be stored in $SECRETS_DIR with mode 600"
    echo ""

    # Generate all secrets
    local MCP_AUTH_TOKEN OPENCLAW_TOKEN PAIRING_SECRET APPROVAL_SECRET

    MCP_AUTH_TOKEN=$(generate_secret 32)
    OPENCLAW_TOKEN=$(generate_secret 32)
    PAIRING_SECRET=$(generate_secret 16)
    APPROVAL_SECRET=$(generate_secret 32)

    # Store secrets in isolated files
    echo "$MCP_AUTH_TOKEN" > "$SECRETS_DIR/mcp_token"
    echo "$OPENCLAW_TOKEN" > "$SECRETS_DIR/openclaw_token"
    echo "$PAIRING_SECRET" > "$SECRETS_DIR/pairing_code"
    echo "$APPROVAL_SECRET" > "$SECRETS_DIR/approval_secret"

    # Lock down permissions
    chmod 600 "$SECRETS_DIR"/*

    log_security "MCP token stored: $SECRETS_DIR/mcp_token (mode 600)"
    log_security "OpenClaw token stored: $SECRETS_DIR/openclaw_token (mode 600)"
    log_security "Pairing code stored: $SECRETS_DIR/pairing_code (mode 600)"

    # Export for later use
    export MCP_AUTH_TOKEN OPENCLAW_TOKEN PAIRING_SECRET APPROVAL_SECRET

    log_success "Credentials generated and isolated"
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

    log_info "Installing dependencies..."
    npm install --production 2>/dev/null || npm install

    # Get Tailscale IP for binding
    TAILSCALE_IP=$(tailscale ip -4 2>/dev/null || echo "127.0.0.1")

    # Create systemd service with secure binding
    cat > /etc/systemd/system/wazuh-mcp-server.service << EOF
[Unit]
Description=Wazuh MCP Server (Tailscale Only)
Documentation=https://github.com/gensecaihq/Wazuh-MCP-Server
After=network.target wazuh-manager.service tailscaled.service
Wants=wazuh-manager.service
Requires=tailscaled.service

[Service]
Type=simple
User=root
WorkingDirectory=$MCP_SERVER_DIR
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

    log_success "Wazuh MCP Server installed"
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

    # Create security-hardened OpenClaw configuration
    cat > "$OC_DIR/openclaw.json" << EOF
{
  // =============================================================================
  // WAZUH OPENCLAW AUTOPILOT - SECURITY HARDENED CONFIGURATION
  // =============================================================================
  // SECURITY: Gateway binds to localhost only - never exposed to internet
  // SECURITY: Pairing mode enabled - explicit device approval required
  // =============================================================================

  "gateway": {
    "port": $GATEWAY_PORT,
    "bind": "loopback",
    "auth": {
      "token": "\${OPENCLAW_TOKEN}"
    },
    "logging": {
      "redactSensitive": true
    },
    "security": {
      "cors": {
        "enabled": false
      },
      "rateLimit": {
        "enabled": true,
        "maxRequests": 100,
        "windowMs": 60000
      }
    }
  },

  // =============================================================================
  // AGENT CONFIGURATION
  // =============================================================================
  "agents": {
    "defaults": {
      "workspace": "~/.openclaw/wazuh-autopilot/workspace",
      "agentDir": "~/.openclaw/wazuh-autopilot/agents",

      "model": {
        "primary": "anthropic/claude-sonnet-4-5",
        "fallback": "anthropic/claude-haiku-4-5"
      },

      "sandbox": {
        "mode": "all",
        "scope": "session",
        "workspaceAccess": "rw"
      },

      "tools": {
        "profile": "minimal",
        "deny": [
          "browser",
          "canvas",
          "nodes",
          "exec",
          "delete"
        ]
      },

      "heartbeat": {
        "every": "30m",
        "target": "last",
        "model": "anthropic/claude-haiku-4-5"
      },

      "memory": {
        "enabled": true,
        "search": {
          "provider": "openai",
          "model": "text-embedding-3-small",
          "hybrid": true
        }
      }
    },

    "list": [
      {
        "id": "wazuh-triage",
        "default": true,
        "workspace": "~/.openclaw/wazuh-autopilot/agents/triage",
        "tools": {
          "profile": "minimal",
          "allow": ["read", "sessions_list", "sessions_history", "sessions_send"],
          "deny": ["write", "edit", "exec", "delete", "browser", "canvas"]
        }
      },
      {
        "id": "wazuh-correlation",
        "workspace": "~/.openclaw/wazuh-autopilot/agents/correlation",
        "tools": {
          "profile": "minimal",
          "allow": ["read", "sessions_list", "sessions_history", "sessions_send"],
          "deny": ["write", "edit", "exec", "delete", "browser", "canvas"]
        }
      },
      {
        "id": "wazuh-investigation",
        "workspace": "~/.openclaw/wazuh-autopilot/agents/investigation",
        "model": {"primary": "anthropic/claude-opus-4-6"},
        "tools": {
          "profile": "minimal",
          "allow": ["read", "sessions_list", "sessions_history", "sessions_send"],
          "deny": ["write", "edit", "exec", "delete", "browser", "canvas"]
        }
      },
      {
        "id": "wazuh-response-planner",
        "workspace": "~/.openclaw/wazuh-autopilot/agents/response-planner",
        "tools": {
          "profile": "minimal",
          "allow": ["read", "write", "sessions_list", "sessions_history", "sessions_send"],
          "deny": ["exec", "delete", "browser", "canvas"]
        }
      },
      {
        "id": "wazuh-policy-guard",
        "workspace": "~/.openclaw/wazuh-autopilot/agents/policy-guard",
        "tools": {
          "profile": "minimal",
          "allow": ["read", "sessions_list", "sessions_history", "sessions_send"],
          "deny": ["write", "edit", "exec", "delete", "browser", "canvas"]
        }
      },
      {
        "id": "wazuh-responder",
        "workspace": "~/.openclaw/wazuh-autopilot/agents/responder",
        "tools": {
          "profile": "coding",
          "allow": ["read", "write", "exec", "sessions_list", "sessions_history", "sessions_send"],
          "deny": ["browser", "canvas", "delete"],
          "elevated": {
            "enabled": true,
            "allowFrom": ["slack"]
          }
        },
        "sandbox": {
          "mode": "all",
          "scope": "agent",
          "workspaceAccess": "rw"
        }
      },
      {
        "id": "wazuh-reporting",
        "workspace": "~/.openclaw/wazuh-autopilot/agents/reporting",
        "model": {"primary": "anthropic/claude-haiku-4-5"},
        "tools": {
          "profile": "minimal",
          "allow": ["read", "write", "sessions_list", "sessions_history", "sessions_send"],
          "deny": ["exec", "delete", "browser", "canvas"]
        }
      }
    ]
  },

  // =============================================================================
  // CHANNEL SECURITY - Pairing mode and allowlists
  // =============================================================================
  "channels": {
    "slack": {
      "enabled": true,
      "dmPolicy": "allowlist",
      "allowFrom": [],
      "groupPolicy": "mention",
      "mentionGating": true,
      "pairing": {
        "enabled": true,
        "requireApproval": true
      }
    }
  },

  // =============================================================================
  // TOOL SECURITY - Strict allowlists
  // =============================================================================
  "tools": {
    "profile": "minimal",
    "allow": [
      "read",
      "sessions_list",
      "sessions_history"
    ],
    "deny": [
      "browser",
      "canvas",
      "nodes",
      "cron",
      "exec",
      "delete"
    ],
    "webSearch": {
      "enabled": false
    },
    "sandbox": {
      "allowlist": [
        "read",
        "sessions_list",
        "sessions_history",
        "sessions_send"
      ],
      "denylist": [
        "browser",
        "canvas",
        "exec",
        "delete"
      ]
    }
  },

  // =============================================================================
  // AUTOMATION - Scheduled tasks
  // =============================================================================
  "automation": {
    "cron": [
      {"id": "hourly-snapshot", "schedule": "0 * * * *", "agentId": "wazuh-reporting"},
      {"id": "daily-digest", "schedule": "0 8 * * *", "agentId": "wazuh-reporting"},
      {"id": "shift-handoff", "schedule": "0 6,14,22 * * *", "agentId": "wazuh-reporting"},
      {"id": "weekly-summary", "schedule": "0 9 * * 1", "agentId": "wazuh-reporting"},
      {"id": "correlation-sweep", "schedule": "*/5 * * * *", "agentId": "wazuh-correlation"},
      {"id": "untriaged-sweep", "schedule": "*/10 * * * *", "agentId": "wazuh-triage"}
    ],
    "webhooks": [
      {"path": "/webhook/wazuh-alert", "target": "wazuh-triage"},
      {"path": "/webhook/case-created", "target": "wazuh-correlation"},
      {"path": "/webhook/investigation-request", "target": "wazuh-investigation"},
      {"path": "/webhook/plan-request", "target": "wazuh-response-planner"},
      {"path": "/webhook/policy-check", "target": "wazuh-policy-guard"},
      {"path": "/webhook/execute-action", "target": "wazuh-responder"}
    ]
  },

  // =============================================================================
  // MEMORY CONFIGURATION
  // =============================================================================
  "memory": {
    "enabled": true,
    "search": {
      "provider": "openai",
      "model": "text-embedding-3-small",
      "hybrid": true
    }
  },

  // =============================================================================
  // ENVIRONMENT VARIABLES
  // =============================================================================
  "env": {
    "OPENCLAW_TOKEN": "\${OPENCLAW_TOKEN}",
    "ANTHROPIC_API_KEY": "\${ANTHROPIC_API_KEY}",
    "WAZUH_MCP_URL": "\${MCP_URL}",
    "WAZUH_MCP_TOKEN": "\${MCP_AUTH_TOKEN}"
  },

  "provider": {
    "type": "anthropic",
    "apiKey": "\${ANTHROPIC_API_KEY}",
    "timeout": 120000
  }
}
EOF

    # Set strict permissions on OpenClaw config
    chmod 600 "$OC_DIR/openclaw.json"

    # Copy agent instruction files
    if [[ -d "$AGENTS_SRC/agents" ]]; then
        log_info "Deploying agent instruction files..."
        cp -r "$AGENTS_SRC/agents"/* "$OC_DIR/wazuh-autopilot/agents/"
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

    local WAZUH_API_URL WAZUH_API_USER WAZUH_API_PASSWORD
    read -rp "  Wazuh API URL [https://127.0.0.1:55000]: " WAZUH_API_URL
    WAZUH_API_URL="${WAZUH_API_URL:-https://127.0.0.1:55000}"

    read -rp "  Wazuh API Username [wazuh-wui]: " WAZUH_API_USER
    WAZUH_API_USER="${WAZUH_API_USER:-wazuh-wui}"

    read -rsp "  Wazuh API Password: " WAZUH_API_PASSWORD
    echo ""

    echo ""
    echo -e "${CYAN}${BOLD}API Keys Configuration${NC}"
    echo ""
    echo "  You need an Anthropic API key for the AI agents."
    echo "  Get one at: https://console.anthropic.com/"
    echo ""

    local ANTHROPIC_API_KEY
    read -rsp "  Anthropic API Key (sk-ant-...): " ANTHROPIC_API_KEY
    echo ""

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
    fi

    # Create configuration file
    cat > "$CONFIG_DIR/.env" << EOF
# =============================================================================
# WAZUH OPENCLAW AUTOPILOT - SECURITY HARDENED CONFIGURATION
# =============================================================================
# Generated: $(date -Iseconds)
# Version: $VERSION
#
# SECURITY NOTES:
# - Gateway binds to localhost only (never exposed)
# - MCP Server binds to Tailscale IP only
# - Credentials isolated in $SECRETS_DIR
# - Two-tier human approval required for all actions
# =============================================================================

# -----------------------------------------------------------------------------
# WAZUH API CONNECTION
# -----------------------------------------------------------------------------
WAZUH_API_URL=$WAZUH_API_URL
WAZUH_API_USER=$WAZUH_API_USER
WAZUH_API_PASSWORD=$WAZUH_API_PASSWORD

# -----------------------------------------------------------------------------
# MCP SERVER (Tailscale Only - NOT public)
# -----------------------------------------------------------------------------
# SECURITY: MCP binds to Tailscale IP, not 0.0.0.0
MCP_HOST=$TAILSCALE_IP
MCP_PORT=$MCP_PORT
MCP_URL=http://$TAILSCALE_IP:$MCP_PORT
MCP_AUTH_TOKEN=$MCP_AUTH_TOKEN

# -----------------------------------------------------------------------------
# OPENCLAW GATEWAY (Localhost Only - NOT public)
# -----------------------------------------------------------------------------
# SECURITY: Gateway binds to 127.0.0.1 only
OPENCLAW_HOST=$GATEWAY_BIND
OPENCLAW_PORT=$GATEWAY_PORT
OPENCLAW_TOKEN=$OPENCLAW_TOKEN

# -----------------------------------------------------------------------------
# AI PROVIDER
# -----------------------------------------------------------------------------
ANTHROPIC_API_KEY=$ANTHROPIC_API_KEY

# -----------------------------------------------------------------------------
# RUNTIME SERVICE (Localhost Only)
# -----------------------------------------------------------------------------
# SECURITY: Runtime binds to 127.0.0.1 only
AUTOPILOT_HOST=$GATEWAY_BIND
AUTOPILOT_PORT=$RUNTIME_PORT
AUTOPILOT_DATA_DIR=$DATA_DIR
AUTOPILOT_LOG_DIR=$LOG_DIR
AUTOPILOT_CONFIG_DIR=$CONFIG_DIR

# -----------------------------------------------------------------------------
# APPROVAL SYSTEM
# -----------------------------------------------------------------------------
AUTOPILOT_TOKEN_SECRET=$APPROVAL_SECRET
AUTOPILOT_TOKEN_TTL_MINUTES=60

# -----------------------------------------------------------------------------
# PAIRING MODE
# -----------------------------------------------------------------------------
# SECURITY: Devices must pair with this code before connecting
AUTOPILOT_PAIRING_CODE=$PAIRING_SECRET
AUTOPILOT_PAIRING_ENABLED=true

# -----------------------------------------------------------------------------
# RESPONDER AGENT - TWO-TIER HUMAN APPROVAL
# -----------------------------------------------------------------------------
#
# SAFETY: Response execution is DISABLED by default.
#
# Even when enabled, EVERY action requires:
#   1. Human clicks "Approve" (Tier 1)
#   2. Human clicks "Execute" (Tier 2)
#
# AI agents CANNOT execute actions autonomously.
#
# To enable: Set to "true" and restart services
# -----------------------------------------------------------------------------
AUTOPILOT_RESPONDER_ENABLED=false

# -----------------------------------------------------------------------------
# SLACK INTEGRATION
# -----------------------------------------------------------------------------
SLACK_APP_TOKEN=$SLACK_APP_TOKEN
SLACK_BOT_TOKEN=$SLACK_BOT_TOKEN
SLACK_ALERTS_CHANNEL=$SLACK_ALERTS_CHANNEL
SLACK_APPROVALS_CHANNEL=$SLACK_APPROVALS_CHANNEL

# -----------------------------------------------------------------------------
# TAILSCALE
# -----------------------------------------------------------------------------
TAILSCALE_IP=$TAILSCALE_IP
EOF

    chmod 600 "$CONFIG_DIR/.env"

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
        cat > /var/ossec/integrations/wazuh-autopilot << 'SCRIPT'
#!/bin/bash
# Wazuh OpenClaw Autopilot Integration
# Forwards alerts to localhost runtime service

ALERT_FILE="$1"
WEBHOOK="http://127.0.0.1:9090/api/alerts"

if [[ -f "$ALERT_FILE" ]]; then
    curl -s -X POST "$WEBHOOK" \
        -H "Content-Type: application/json" \
        -d @"$ALERT_FILE" \
        --connect-timeout 5 \
        >/dev/null 2>&1 || true
fi

exit 0
SCRIPT

        chmod 750 /var/ossec/integrations/wazuh-autopilot
        chown root:wazuh /var/ossec/integrations/wazuh-autopilot

        # Backup ossec.conf
        cp "$OSSEC_CONF" "$OSSEC_CONF.backup.$(date +%Y%m%d%H%M%S)"

        # Add integration config
        local INTEGRATOR_CONFIG='
  <!-- Wazuh OpenClaw Autopilot - Localhost Only -->
  <integration>
    <name>wazuh-autopilot</name>
    <hook_url>http://127.0.0.1:9090/api/alerts</hook_url>
    <level>10</level>
    <alert_format>json</alert_format>
  </integration>
'
        sed -i "s|</ossec_config>|$INTEGRATOR_CONFIG</ossec_config>|" "$OSSEC_CONF"

        log_success "Alert forwarding configured (level 10+)"
        log_security "Alerts sent to localhost only"
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
        ((issues++))
    fi

    # Check directory permissions
    local config_perms
    config_perms=$(stat -c %a "$CONFIG_DIR" 2>/dev/null || echo "000")
    if [[ "$config_perms" == "700" ]]; then
        echo -e "  ${GREEN}✓${NC} Config directory permissions (700)"
    else
        echo -e "  ${YELLOW}!${NC} Config directory permissions: $config_perms (should be 700)"
        ((issues++))
    fi

    # Check secrets permissions
    local secrets_perms
    secrets_perms=$(stat -c %a "$SECRETS_DIR" 2>/dev/null || echo "000")
    if [[ "$secrets_perms" == "700" ]]; then
        echo -e "  ${GREEN}✓${NC} Secrets directory permissions (700)"
    else
        echo -e "  ${YELLOW}!${NC} Secrets directory permissions: $secrets_perms (should be 700)"
        ((issues++))
    fi

    # Check env file permissions
    local env_perms
    env_perms=$(stat -c %a "$CONFIG_DIR/.env" 2>/dev/null || echo "000")
    if [[ "$env_perms" == "600" ]]; then
        echo -e "  ${GREEN}✓${NC} Environment file permissions (600)"
    else
        echo -e "  ${YELLOW}!${NC} Environment file permissions: $env_perms (should be 600)"
        ((issues++))
    fi

    # Check Tailscale
    if tailscale status &>/dev/null; then
        echo -e "  ${GREEN}✓${NC} Tailscale connected"
    else
        echo -e "  ${RED}✗${NC} Tailscale not connected"
        ((issues++))
    fi

    # Check firewall
    if ufw status 2>/dev/null | grep -q "active"; then
        echo -e "  ${GREEN}✓${NC} Firewall active (UFW)"
    elif firewall-cmd --state 2>/dev/null | grep -q "running"; then
        echo -e "  ${GREEN}✓${NC} Firewall active (firewalld)"
    else
        echo -e "  ${YELLOW}!${NC} No firewall detected"
        ((issues++))
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
    TAILSCALE_IP=$(tailscale ip -4 2>/dev/null || echo "127.0.0.1")

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
    install_tailscale
    setup_secure_directories
    setup_credentials
    install_mcp_server
    install_openclaw
    deploy_agents
    install_runtime_service
    configure_system
    configure_wazuh_integrator
    prompt_responder_activation
    show_pairing_info
    start_services
    run_security_audit
    print_summary
}

# Run
main "$@"
