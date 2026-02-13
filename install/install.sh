#!/usr/bin/env bash
#
# Wazuh Autopilot Installer
# Universal installer for Ubuntu 22.04/24.04
#
# Supports:
#   --mode agent-pack     : Scenario 1 - Install agents into existing OpenClaw
#   --mode bootstrap-openclaw : Scenario 2 - Bootstrap OpenClaw + install agents
#   --mode fresh          : Scenario 3 - Full setup from Wazuh-only state
#   --mode doctor         : Run diagnostics only
#
# Environment variables for non-interactive install:
#   AUTOPILOT_MODE           : bootstrap | production
#   AUTOPILOT_REQUIRE_TAILSCALE : true | false
#   MCP_URL                  : Production MCP URL (must be Tailnet in production)
#   MCP_BOOTSTRAP_URL        : Bootstrap MCP URL (optional)
#   AUTOPILOT_MCP_AUTH       : MCP authentication token
#   SLACK_APP_TOKEN          : Slack App-Level Token (xapp-...)
#   SLACK_BOT_TOKEN          : Slack Bot Token (xoxb-...)
#   OPENCLAW_HOME            : OpenClaw installation directory
#   AUTOPILOT_DATA_DIR       : Data directory (default: /var/lib/wazuh-autopilot)
#   AUTOPILOT_ENABLE_RESPONDER : true | false (enable action execution)
#

set -euo pipefail

# =============================================================================
# CONFIGURATION
# =============================================================================

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"
VERSION="1.0.0"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Default values
DEFAULT_DATA_DIR="/var/lib/wazuh-autopilot"
DEFAULT_OPENCLAW_HOME="/opt/openclaw"
DEFAULT_CONFIG_DIR="/etc/wazuh-autopilot"

# Runtime variables
INSTALL_MODE=""
DEPLOYMENT_MODE="${AUTOPILOT_MODE:-}"
REQUIRE_TAILSCALE="${AUTOPILOT_REQUIRE_TAILSCALE:-true}"
MCP_URL="${MCP_URL:-}"
MCP_BOOTSTRAP_URL="${MCP_BOOTSTRAP_URL:-}"
MCP_AUTH="${AUTOPILOT_MCP_AUTH:-}"
SLACK_APP_TOKEN="${SLACK_APP_TOKEN:-}"
SLACK_BOT_TOKEN="${SLACK_BOT_TOKEN:-}"
OPENCLAW_HOME="${OPENCLAW_HOME:-$DEFAULT_OPENCLAW_HOME}"
DATA_DIR="${AUTOPILOT_DATA_DIR:-$DEFAULT_DATA_DIR}"
CONFIG_DIR="${DEFAULT_CONFIG_DIR}"
ENABLE_RESPONDER="${AUTOPILOT_ENABLE_RESPONDER:-false}"
INTERACTIVE=true
FORCE=false

# =============================================================================
# HELPER FUNCTIONS
# =============================================================================

log_info() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

log_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
}

log_warn() {
    echo -e "${YELLOW}[WARN]${NC} $1"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

log_header() {
    echo ""
    echo -e "${BLUE}========================================${NC}"
    echo -e "${BLUE} $1${NC}"
    echo -e "${BLUE}========================================${NC}"
    echo ""
}

prompt_yes_no() {
    local prompt="$1"
    local default="${2:-n}"

    if [[ "$INTERACTIVE" != "true" ]]; then
        [[ "$default" == "y" ]] && return 0 || return 1
    fi

    local yn
    if [[ "$default" == "y" ]]; then
        read -rp "$prompt [Y/n]: " yn
        yn=${yn:-y}
    else
        read -rp "$prompt [y/N]: " yn
        yn=${yn:-n}
    fi

    [[ "$yn" =~ ^[Yy] ]] && return 0 || return 1
}

prompt_input() {
    local prompt="$1"
    local default="${2:-}"
    local var_name="$3"

    if [[ "$INTERACTIVE" != "true" ]]; then
        eval "$var_name=\"$default\""
        return
    fi

    local input
    if [[ -n "$default" ]]; then
        read -rp "$prompt [$default]: " input
        input=${input:-$default}
    else
        read -rp "$prompt: " input
    fi

    eval "$var_name=\"$input\""
}

check_root() {
    if [[ $EUID -ne 0 ]]; then
        log_error "This script must be run as root"
        exit 1
    fi
}

check_ubuntu() {
    if [[ ! -f /etc/os-release ]]; then
        log_error "Cannot determine OS version"
        exit 1
    fi

    source /etc/os-release

    if [[ "$ID" != "ubuntu" ]]; then
        log_error "This installer only supports Ubuntu"
        exit 1
    fi

    if [[ ! "$VERSION_ID" =~ ^(22\.04|24\.04)$ ]]; then
        log_warn "This installer is tested on Ubuntu 22.04/24.04. Your version: $VERSION_ID"
        if ! prompt_yes_no "Continue anyway?"; then
            exit 1
        fi
    fi

    log_success "Ubuntu $VERSION_ID detected"
}

# =============================================================================
# DETECTION FUNCTIONS
# =============================================================================

detect_tailscale() {
    log_info "Checking Tailscale status..."

    if ! command -v tailscale &> /dev/null; then
        log_warn "Tailscale is not installed"
        return 1
    fi

    local status
    if status=$(tailscale status --json 2>/dev/null); then
        local backend_state
        backend_state=$(echo "$status" | jq -r '.BackendState // empty')

        if [[ "$backend_state" == "Running" ]]; then
            local tailnet_name
            tailnet_name=$(echo "$status" | jq -r '.MagicDNSSuffix // empty')
            log_success "Tailscale is running (Tailnet: $tailnet_name)"
            return 0
        else
            log_warn "Tailscale installed but not running (State: $backend_state)"
            return 1
        fi
    else
        log_warn "Tailscale installed but not authenticated"
        return 1
    fi
}

detect_openclaw() {
    log_info "Checking OpenClaw installation..."

    # Check for OpenClaw in common locations
    local openclaw_found=false
    local openclaw_running=false

    for dir in "$OPENCLAW_HOME" "/opt/openclaw" "$HOME/.openclaw" "/usr/local/openclaw"; do
        if [[ -d "$dir" ]] && [[ -f "$dir/package.json" || -f "$dir/openclaw" ]]; then
            OPENCLAW_HOME="$dir"
            openclaw_found=true
            break
        fi
    done

    # Check if OpenClaw is running via Docker
    if docker ps 2>/dev/null | grep -q "openclaw"; then
        openclaw_found=true
        openclaw_running=true
        log_success "OpenClaw running in Docker"
    fi

    # Check if OpenClaw is running as systemd service
    if systemctl is-active --quiet openclaw 2>/dev/null; then
        openclaw_running=true
        log_success "OpenClaw running as systemd service"
    fi

    if [[ "$openclaw_found" == "true" ]]; then
        log_success "OpenClaw found at: $OPENCLAW_HOME"
        return 0
    else
        log_warn "OpenClaw not found"
        return 1
    fi
}

detect_mcp() {
    local url="$1"

    if [[ -z "$url" ]]; then
        log_warn "No MCP URL provided"
        return 1
    fi

    log_info "Testing MCP connectivity at: $url"

    # Basic connectivity test
    local response
    local http_code

    if [[ -n "$MCP_AUTH" ]]; then
        http_code=$(curl -s -o /dev/null -w "%{http_code}" \
            -H "Authorization: Bearer $MCP_AUTH" \
            --connect-timeout 10 \
            "$url/health" 2>/dev/null || echo "000")
    else
        http_code=$(curl -s -o /dev/null -w "%{http_code}" \
            --connect-timeout 10 \
            "$url/health" 2>/dev/null || echo "000")
    fi

    case "$http_code" in
        200|204)
            log_success "MCP is reachable and healthy"
            return 0
            ;;
        401|403)
            log_warn "MCP reachable but authentication required/failed"
            return 2
            ;;
        000)
            log_error "Cannot connect to MCP at $url"
            return 1
            ;;
        *)
            log_warn "MCP returned HTTP $http_code"
            return 1
            ;;
    esac
}

is_tailnet_url() {
    local url="$1"

    # Check if URL contains Tailscale magic DNS suffix or Tailnet IP
    if [[ "$url" =~ \.ts\.net ]] || \
       [[ "$url" =~ ^https?://100\. ]] || \
       [[ "$url" =~ \.tail[a-z0-9]+\.ts\.net ]]; then
        return 0
    fi

    return 1
}

# =============================================================================
# INSTALLATION FUNCTIONS
# =============================================================================

install_dependencies() {
    log_header "Installing Dependencies"

    apt-get update -qq
    apt-get install -y -qq \
        curl \
        jq \
        ca-certificates \
        gnupg \
        lsb-release

    log_success "Dependencies installed"
}

install_tailscale() {
    log_header "Installing Tailscale"

    if command -v tailscale &> /dev/null; then
        log_info "Tailscale already installed"
        return 0
    fi

    curl -fsSL https://tailscale.com/install.sh | sh

    log_success "Tailscale installed"
    log_info "Run 'tailscale up' to authenticate with your Tailnet"

    echo ""
    echo "  To join this machine to your Tailnet, run:"
    echo "    sudo tailscale up"
    echo ""
    echo "  After authenticating, update your configuration to use"
    echo "  the Tailnet MCP URL and set AUTOPILOT_MODE=production"
    echo ""
}

install_docker() {
    log_header "Installing Docker"

    if command -v docker &> /dev/null; then
        log_info "Docker already installed"
        return 0
    fi

    # Install Docker using official script
    curl -fsSL https://get.docker.com | sh

    # Start Docker
    systemctl enable docker
    systemctl start docker

    log_success "Docker installed"
}

bootstrap_openclaw() {
    log_header "Bootstrapping OpenClaw"

    if detect_openclaw; then
        log_info "OpenClaw already installed"
        return 0
    fi

    # Install Docker if needed
    install_docker

    # Create OpenClaw directory
    mkdir -p "$OPENCLAW_HOME"

    # Create Docker Compose file for OpenClaw
    cat > "$OPENCLAW_HOME/docker-compose.yml" << 'EOF'
version: '3.8'

services:
  openclaw:
    image: openclaw/openclaw:latest
    container_name: openclaw
    restart: unless-stopped
    ports:
      - "127.0.0.1:3000:3000"
    volumes:
      - ./agents:/app/agents:ro
      - ./config:/app/config:ro
      - ./data:/app/data
    environment:
      - NODE_ENV=production
    networks:
      - autopilot

networks:
  autopilot:
    driver: bridge
EOF

    log_success "OpenClaw bootstrap files created at $OPENCLAW_HOME"
    log_info "Start OpenClaw with: cd $OPENCLAW_HOME && docker-compose up -d"
}

create_directories() {
    log_header "Creating Directory Structure"

    # Create data directories
    mkdir -p "$DATA_DIR"/{cases,reports,state}
    mkdir -p "$CONFIG_DIR"

    # Set permissions
    chmod 750 "$DATA_DIR"
    chmod 750 "$CONFIG_DIR"

    log_success "Directories created"
}

install_agent_pack() {
    log_header "Installing Agent Pack"

    local agents_dest="$CONFIG_DIR/agents"
    local policies_dest="$CONFIG_DIR/policies"
    local playbooks_dest="$CONFIG_DIR/playbooks"

    # Create directories
    mkdir -p "$agents_dest" "$policies_dest" "$playbooks_dest"

    # Copy agents
    if [[ -d "$PROJECT_ROOT/agents" ]]; then
        cp -r "$PROJECT_ROOT/agents/"* "$agents_dest/"
        log_success "Agents installed to $agents_dest"
    else
        log_error "Agents directory not found at $PROJECT_ROOT/agents"
        return 1
    fi

    # Copy policies
    if [[ -d "$PROJECT_ROOT/policies" ]]; then
        cp -r "$PROJECT_ROOT/policies/"* "$policies_dest/"
        log_success "Policies installed to $policies_dest"
    else
        log_error "Policies directory not found"
        return 1
    fi

    # Copy playbooks
    if [[ -d "$PROJECT_ROOT/playbooks" ]]; then
        cp -r "$PROJECT_ROOT/playbooks/"* "$playbooks_dest/"
        log_success "Playbooks installed to $playbooks_dest"
    fi

    # Link to OpenClaw if installed
    if [[ -d "$OPENCLAW_HOME" ]]; then
        ln -sf "$agents_dest" "$OPENCLAW_HOME/agents" 2>/dev/null || true
        log_info "Agents linked to OpenClaw"
    fi
}

install_runtime_service() {
    log_header "Installing Runtime Service"

    local runtime_dest="$CONFIG_DIR/runtime"
    mkdir -p "$runtime_dest"

    # Copy runtime service if exists
    if [[ -d "$PROJECT_ROOT/runtime/autopilot-service" ]]; then
        cp -r "$PROJECT_ROOT/runtime/autopilot-service/"* "$runtime_dest/"
        log_success "Runtime service installed"
    fi

    # Create systemd service file
    cat > /etc/systemd/system/wazuh-autopilot.service << EOF
[Unit]
Description=Wazuh Autopilot Service
After=network.target docker.service
Wants=docker.service

[Service]
Type=simple
User=root
WorkingDirectory=$runtime_dest
EnvironmentFile=$CONFIG_DIR/.env
ExecStart=/usr/bin/node $runtime_dest/index.js
Restart=always
RestartSec=10

# Security hardening
NoNewPrivileges=true
ProtectSystem=strict
ProtectHome=true
ReadWritePaths=$DATA_DIR $CONFIG_DIR/state

[Install]
WantedBy=multi-user.target
EOF

    systemctl daemon-reload
    log_success "Systemd service created"
}

create_env_file() {
    log_header "Creating Configuration"

    local env_file="$CONFIG_DIR/.env"

    cat > "$env_file" << EOF
# Wazuh Autopilot Configuration
# Generated by installer on $(date -Iseconds)

# =============================================================================
# Deployment Mode
# =============================================================================
# bootstrap = Allow non-Tailnet MCP URLs (evaluation/testing)
# production = Require Tailnet MCP URL (recommended for production)
AUTOPILOT_MODE=${DEPLOYMENT_MODE:-bootstrap}

# Require Tailscale for production mode
AUTOPILOT_REQUIRE_TAILSCALE=${REQUIRE_TAILSCALE}

# =============================================================================
# MCP Configuration
# =============================================================================
# Production MCP URL (must be Tailnet URL in production mode)
MCP_URL=${MCP_URL}

# Bootstrap MCP URL (used only in bootstrap mode if MCP_URL not set)
MCP_BOOTSTRAP_URL=${MCP_BOOTSTRAP_URL}

# MCP Authentication Token
AUTOPILOT_MCP_AUTH=${MCP_AUTH}

# =============================================================================
# Slack Configuration (Socket Mode - no public endpoint required)
# =============================================================================
# Slack App-Level Token (starts with xapp-)
SLACK_APP_TOKEN=${SLACK_APP_TOKEN}

# Slack Bot Token (starts with xoxb-)
SLACK_BOT_TOKEN=${SLACK_BOT_TOKEN}

# =============================================================================
# Data Storage
# =============================================================================
AUTOPILOT_DATA_DIR=${DATA_DIR}
AUTOPILOT_CONFIG_DIR=${CONFIG_DIR}

# =============================================================================
# Agent Configuration
# =============================================================================
# Enable action execution (requires Responder Agent)
# WARNING: Set to true only after configuring policies and testing
AUTOPILOT_ENABLE_RESPONDER=${ENABLE_RESPONDER}

# =============================================================================
# Observability
# =============================================================================
# Metrics endpoint (binds to localhost only for security)
METRICS_ENABLED=true
METRICS_PORT=9090
METRICS_HOST=127.0.0.1

# Structured JSON logging
LOG_FORMAT=json
LOG_LEVEL=info

# =============================================================================
# OpenClaw Integration
# =============================================================================
OPENCLAW_HOME=${OPENCLAW_HOME}
EOF

    chmod 600 "$env_file"
    log_success "Configuration created at $env_file"

    # Create template for reference
    cp "$env_file" "$CONFIG_DIR/env.example"
    chmod 644 "$CONFIG_DIR/env.example"
}

# =============================================================================
# SCENARIO HANDLERS
# =============================================================================

scenario_agent_pack() {
    log_header "Scenario 1: Agent Pack Installation"
    log_info "Installing Autopilot agents into existing OpenClaw environment"

    # Verify OpenClaw exists
    if ! detect_openclaw; then
        log_error "OpenClaw not found. Use --mode bootstrap-openclaw instead."
        exit 1
    fi

    create_directories
    install_agent_pack
    create_env_file

    log_success "Agent pack installed successfully"
}

scenario_bootstrap_openclaw() {
    log_header "Scenario 2: Bootstrap OpenClaw + Agent Pack"
    log_info "Setting up OpenClaw and installing Autopilot agents"

    install_dependencies
    bootstrap_openclaw
    create_directories
    install_agent_pack
    install_runtime_service
    create_env_file

    log_success "OpenClaw bootstrapped and agents installed"
}

scenario_fresh() {
    log_header "Scenario 3: Fresh Installation"
    log_info "Full setup from Wazuh-only state"

    install_dependencies

    # Tailscale is mandatory for fresh installs
    log_info "Installing Tailscale (mandatory for production)"
    install_tailscale

    bootstrap_openclaw
    create_directories
    install_agent_pack
    install_runtime_service
    create_env_file

    # Provide MCP guidance
    echo ""
    log_warn "MCP Server Required"
    echo ""
    echo "  Wazuh Autopilot requires a Wazuh MCP Server."
    echo "  You can deploy one using:"
    echo "    https://github.com/gensecaihq/Wazuh-MCP-Server"
    echo ""
    echo "  After deploying MCP:"
    echo "  1. Join the MCP host to your Tailnet"
    echo "  2. Update $CONFIG_DIR/.env with the Tailnet MCP URL"
    echo "  3. Run: $SCRIPT_DIR/doctor.sh"
    echo ""

    log_success "Fresh installation complete"
}

run_doctor() {
    log_header "Running Diagnostics"

    if [[ -x "$SCRIPT_DIR/doctor.sh" ]]; then
        exec "$SCRIPT_DIR/doctor.sh"
    else
        log_error "Doctor script not found at $SCRIPT_DIR/doctor.sh"
        exit 1
    fi
}

# =============================================================================
# CUTOVER WORKFLOW
# =============================================================================

tailnet_cutover() {
    log_header "Tailnet Cutover Workflow"

    echo "This workflow will help you transition from bootstrap to production mode."
    echo ""

    # Step 1: Check Autopilot host Tailscale
    echo "Step 1: Verify Tailscale on this host"
    if ! detect_tailscale; then
        echo ""
        echo "  Tailscale is not running on this host."
        echo "  To set up Tailscale:"
        echo ""
        echo "    curl -fsSL https://tailscale.com/install.sh | sh"
        echo "    sudo tailscale up"
        echo ""
        return 1
    fi

    # Step 2: Guide for MCP host
    echo ""
    echo "Step 2: Ensure MCP host is on your Tailnet"
    echo ""
    echo "  On the MCP server host, run:"
    echo ""
    echo "    curl -fsSL https://tailscale.com/install.sh | sh"
    echo "    sudo tailscale up"
    echo ""
    echo "  After joining, note the Tailnet hostname or IP."
    echo ""

    # Step 3: Get new MCP URL
    local new_mcp_url
    prompt_input "Enter the Tailnet MCP URL (e.g., https://mcp-server.tail12345.ts.net:8080)" "" new_mcp_url

    if [[ -z "$new_mcp_url" ]]; then
        log_error "MCP URL is required"
        return 1
    fi

    if ! is_tailnet_url "$new_mcp_url"; then
        log_error "URL does not appear to be a Tailnet URL"
        log_info "Tailnet URLs typically contain .ts.net or start with 100.x.x.x"
        return 1
    fi

    # Step 4: Test connectivity
    echo ""
    echo "Step 3: Testing MCP connectivity..."
    if ! detect_mcp "$new_mcp_url"; then
        log_error "Cannot connect to MCP at $new_mcp_url"
        echo ""
        echo "  Ensure:"
        echo "  - MCP server is running"
        echo "  - MCP host is on the same Tailnet"
        echo "  - Tailscale ACLs allow the connection"
        return 1
    fi

    # Step 5: Update configuration
    echo ""
    echo "Step 4: Updating configuration..."

    local env_file="$CONFIG_DIR/.env"
    if [[ -f "$env_file" ]]; then
        # Update MCP_URL
        sed -i "s|^MCP_URL=.*|MCP_URL=$new_mcp_url|" "$env_file"
        # Update mode to production
        sed -i "s|^AUTOPILOT_MODE=.*|AUTOPILOT_MODE=production|" "$env_file"

        log_success "Configuration updated"
    else
        log_error "Configuration file not found at $env_file"
        return 1
    fi

    # Step 6: Restart services
    if systemctl is-active --quiet wazuh-autopilot; then
        systemctl restart wazuh-autopilot
        log_success "Service restarted"
    fi

    echo ""
    log_success "Tailnet cutover complete!"
    echo ""
    echo "  Run doctor to verify: $SCRIPT_DIR/doctor.sh"
    echo ""
}

# =============================================================================
# MAIN
# =============================================================================

usage() {
    cat << EOF
Wazuh Autopilot Installer v${VERSION}

Usage: $0 [OPTIONS]

Installation Modes:
  --mode agent-pack        Install agents into existing OpenClaw (Scenario 1)
  --mode bootstrap-openclaw Bootstrap OpenClaw + install agents (Scenario 2)
  --mode fresh             Full setup from Wazuh-only state (Scenario 3)
  --mode doctor            Run diagnostics only

Additional Options:
  --cutover                Run Tailnet cutover workflow
  --non-interactive        Run without prompts (use env vars)
  --force                  Force installation even with warnings
  -h, --help               Show this help message

Environment Variables (for non-interactive install):
  AUTOPILOT_MODE           bootstrap | production
  MCP_URL                  Production MCP URL
  MCP_BOOTSTRAP_URL        Bootstrap MCP URL
  AUTOPILOT_MCP_AUTH       MCP authentication token
  SLACK_APP_TOKEN          Slack App-Level Token
  SLACK_BOT_TOKEN          Slack Bot Token
  OPENCLAW_HOME            OpenClaw installation directory
  AUTOPILOT_DATA_DIR       Data directory
  AUTOPILOT_ENABLE_RESPONDER  Enable action execution (true/false)

Examples:
  # Interactive installation
  sudo $0 --mode fresh

  # Non-interactive installation
  sudo MCP_URL=https://mcp.tail123.ts.net:8080 \\
       AUTOPILOT_MODE=production \\
       $0 --mode agent-pack --non-interactive

  # Run diagnostics
  $0 --mode doctor

  # Transition to production mode
  sudo $0 --cutover

EOF
}

main() {
    # Parse arguments
    while [[ $# -gt 0 ]]; do
        case "$1" in
            --mode)
                INSTALL_MODE="$2"
                shift 2
                ;;
            --cutover)
                check_root
                tailnet_cutover
                exit $?
                ;;
            --non-interactive)
                INTERACTIVE=false
                shift
                ;;
            --force)
                FORCE=true
                shift
                ;;
            -h|--help)
                usage
                exit 0
                ;;
            *)
                log_error "Unknown option: $1"
                usage
                exit 1
                ;;
        esac
    done

    # Show banner
    echo ""
    echo "╔═══════════════════════════════════════════════════════════╗"
    echo "║           Wazuh Autopilot Installer v${VERSION}              ║"
    echo "║   Autonomous SOC Layer for Wazuh via OpenClaw Agents      ║"
    echo "╚═══════════════════════════════════════════════════════════╝"
    echo ""

    # Validate mode
    if [[ -z "$INSTALL_MODE" ]]; then
        log_error "Installation mode required"
        echo ""
        usage
        exit 1
    fi

    # Run selected mode
    case "$INSTALL_MODE" in
        agent-pack)
            check_root
            check_ubuntu
            scenario_agent_pack
            ;;
        bootstrap-openclaw)
            check_root
            check_ubuntu
            scenario_bootstrap_openclaw
            ;;
        fresh)
            check_root
            check_ubuntu
            scenario_fresh
            ;;
        doctor)
            run_doctor
            ;;
        *)
            log_error "Unknown mode: $INSTALL_MODE"
            usage
            exit 1
            ;;
    esac

    # Final summary
    echo ""
    log_header "Installation Complete"
    echo ""
    echo "  Next steps:"
    echo "  1. Review and update configuration: $CONFIG_DIR/.env"
    echo "  2. Run diagnostics: $SCRIPT_DIR/doctor.sh"
    echo "  3. Start the service: systemctl start wazuh-autopilot"
    echo ""
    echo "  Documentation: $PROJECT_ROOT/docs/"
    echo ""
}

main "$@"
