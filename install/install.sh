#!/usr/bin/env bash
#
# Wazuh Autopilot Installer
# Universal installer supporting all deployment scenarios
#
# Scenarios:
#   1.  All-in-One           - Everything on single server
#   2.  OpenClaw + Runtime   - For remote MCP (Wazuh+MCP on different server)
#   3.  Runtime Only         - Just the runtime service (OpenClaw elsewhere)
#   4.  Agent Pack Only      - Copy agents to existing local OpenClaw
#   5.  Remote OpenClaw      - Copy agents to remote OpenClaw server
#   6.  Docker Compose       - Generate docker-compose.yml
#   7.  Kubernetes           - Generate K8s manifests
#   8.  Doctor               - Run diagnostics only
#   9.  Cutover              - Transition to production mode
#
# Run with --menu for interactive selection
#

set -euo pipefail

# =============================================================================
# CONFIGURATION
# =============================================================================

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"
VERSION="2.0.0"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
BOLD='\033[1m'
NC='\033[0m' # No Color

# Default values
DEFAULT_DATA_DIR="/var/lib/wazuh-autopilot"
DEFAULT_OPENCLAW_HOME="/opt/openclaw"
DEFAULT_CONFIG_DIR="/etc/wazuh-autopilot"

# Runtime variables
INSTALL_MODE=""
DEPLOYMENT_MODE="${AUTOPILOT_MODE:-bootstrap}"
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
REMOTE_HOST=""
REMOTE_USER="root"
REMOTE_OPENCLAW_PATH="/opt/openclaw/agents"

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
        log_warn "Cannot determine OS version - continuing anyway"
        return 0
    fi

    source /etc/os-release

    if [[ "$ID" == "ubuntu" ]]; then
        if [[ ! "$VERSION_ID" =~ ^(22\.04|24\.04)$ ]]; then
            log_warn "This installer is tested on Ubuntu 22.04/24.04. Your version: $VERSION_ID"
            if [[ "$INTERACTIVE" == "true" ]] && ! prompt_yes_no "Continue anyway?"; then
                exit 1
            fi
        fi
        log_success "Ubuntu $VERSION_ID detected"
    elif [[ "$ID" == "debian" ]]; then
        log_info "Debian detected - should work but not fully tested"
    else
        log_warn "Non-Ubuntu system detected ($ID). Some features may not work."
    fi
}

# =============================================================================
# DEPENDENCY CHECKS
# =============================================================================

check_dependencies() {
    log_info "Checking required dependencies..."

    local missing_deps=()

    if ! command -v curl &> /dev/null; then
        missing_deps+=("curl")
    fi

    if ! command -v jq &> /dev/null; then
        missing_deps+=("jq")
    fi

    if ! command -v node &> /dev/null; then
        log_warn "Node.js not found - required for runtime service"
        missing_deps+=("nodejs")
    else
        local node_version
        node_version=$(node --version | sed 's/v//' | cut -d. -f1)
        if [[ "$node_version" -lt 18 ]]; then
            log_warn "Node.js version $node_version detected. Version 18+ recommended."
        else
            log_success "Node.js $(node --version) detected"
        fi
    fi

    if [[ ${#missing_deps[@]} -gt 0 ]]; then
        log_warn "Missing dependencies: ${missing_deps[*]}"
        return 1
    fi

    log_success "All required dependencies are present"
    return 0
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
        fi
    fi

    log_warn "Tailscale not running"
    return 1
}

detect_openclaw() {
    log_info "Checking OpenClaw installation..."

    local openclaw_found=false

    for dir in "$OPENCLAW_HOME" "/opt/openclaw" "$HOME/.openclaw" "/usr/local/openclaw"; do
        if [[ -d "$dir" ]] && [[ -f "$dir/package.json" || -f "$dir/openclaw" || -f "$dir/docker-compose.yml" ]]; then
            OPENCLAW_HOME="$dir"
            openclaw_found=true
            break
        fi
    done

    if docker ps 2>/dev/null | grep -q "openclaw"; then
        openclaw_found=true
        log_success "OpenClaw running in Docker"
    fi

    if systemctl is-active --quiet openclaw 2>/dev/null; then
        log_success "OpenClaw running as systemd service"
        openclaw_found=true
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
        return 1
    fi

    log_info "Testing MCP connectivity at: $url"

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
        *)
            log_error "Cannot connect to MCP (HTTP $http_code)"
            return 1
            ;;
    esac
}

is_tailnet_url() {
    local url="$1"
    [[ "$url" =~ \.ts\.net ]] || [[ "$url" =~ ^https?://100\. ]]
}

# =============================================================================
# INSTALLATION FUNCTIONS
# =============================================================================

install_dependencies() {
    log_header "Installing Dependencies"

    if command -v apt-get &> /dev/null; then
        apt-get update -qq
        apt-get install -y -qq curl jq ca-certificates gnupg lsb-release
    elif command -v yum &> /dev/null; then
        yum install -y -q curl jq ca-certificates gnupg
    else
        log_warn "Unknown package manager - install curl and jq manually"
    fi

    log_success "Dependencies installed"
}

install_nodejs() {
    log_header "Installing Node.js"

    if command -v node &> /dev/null; then
        log_info "Node.js already installed"
        return 0
    fi

    # Install Node.js 18 LTS
    curl -fsSL https://deb.nodesource.com/setup_18.x -o /tmp/nodesource_setup.sh
    if head -1 /tmp/nodesource_setup.sh | grep -q "^#!"; then
        bash /tmp/nodesource_setup.sh
        apt-get install -y nodejs
        rm /tmp/nodesource_setup.sh
        log_success "Node.js installed"
    else
        log_error "Failed to download Node.js installer"
        return 1
    fi
}

install_tailscale() {
    log_header "Installing Tailscale"

    if command -v tailscale &> /dev/null; then
        log_info "Tailscale already installed"
        return 0
    fi

    local installer_tmp
    installer_tmp=$(mktemp)

    log_info "Downloading Tailscale installer..."
    if ! curl -fsSL https://tailscale.com/install.sh -o "$installer_tmp"; then
        log_error "Failed to download Tailscale installer"
        rm -f "$installer_tmp"
        return 1
    fi

    if head -1 "$installer_tmp" | grep -q "^#!"; then
        chmod +x "$installer_tmp"
        sh "$installer_tmp"
        rm -f "$installer_tmp"
        log_success "Tailscale installed"
        log_info "Run 'sudo tailscale up' to authenticate"
    else
        log_error "Invalid installer script"
        rm -f "$installer_tmp"
        return 1
    fi
}

install_docker() {
    log_header "Installing Docker"

    if command -v docker &> /dev/null; then
        log_info "Docker already installed"
        return 0
    fi

    local installer_tmp
    installer_tmp=$(mktemp)

    log_info "Downloading Docker installer..."
    if ! curl -fsSL https://get.docker.com -o "$installer_tmp"; then
        log_error "Failed to download Docker installer"
        rm -f "$installer_tmp"
        return 1
    fi

    if head -1 "$installer_tmp" | grep -q "^#!"; then
        chmod +x "$installer_tmp"
        sh "$installer_tmp"
        rm -f "$installer_tmp"
        systemctl enable docker
        systemctl start docker
        log_success "Docker installed"
    else
        log_error "Invalid installer script"
        rm -f "$installer_tmp"
        return 1
    fi
}

create_directories() {
    log_header "Creating Directory Structure"

    mkdir -p "$DATA_DIR"/{cases,reports,state}
    mkdir -p "$CONFIG_DIR"
    chmod 750 "$DATA_DIR"
    chmod 750 "$CONFIG_DIR"

    log_success "Directories created"
}

install_agent_pack() {
    log_header "Installing Agent Pack"

    local agents_dest="$CONFIG_DIR/agents"
    local policies_dest="$CONFIG_DIR/policies"
    local playbooks_dest="$CONFIG_DIR/playbooks"

    mkdir -p "$agents_dest" "$policies_dest" "$playbooks_dest"

    if [[ -d "$PROJECT_ROOT/agents" ]]; then
        cp -r "$PROJECT_ROOT/agents/"* "$agents_dest/"
        log_success "Agents installed to $agents_dest"
    else
        log_error "Agents directory not found"
        return 1
    fi

    if [[ -d "$PROJECT_ROOT/policies" ]]; then
        cp -r "$PROJECT_ROOT/policies/"* "$policies_dest/"
        log_success "Policies installed to $policies_dest"
    fi

    if [[ -d "$PROJECT_ROOT/playbooks" ]]; then
        cp -r "$PROJECT_ROOT/playbooks/"* "$playbooks_dest/"
        log_success "Playbooks installed to $playbooks_dest"
    fi
}

link_agents_to_openclaw() {
    if [[ -d "$OPENCLAW_HOME" ]]; then
        mkdir -p "$OPENCLAW_HOME/agents" 2>/dev/null || true
        ln -sf "$CONFIG_DIR/agents"/* "$OPENCLAW_HOME/agents/" 2>/dev/null || true
        log_info "Agents linked to OpenClaw at $OPENCLAW_HOME/agents"
    fi
}

install_runtime_service() {
    log_header "Installing Runtime Service"

    local runtime_dest="$CONFIG_DIR/runtime"
    mkdir -p "$runtime_dest"

    if [[ -d "$PROJECT_ROOT/runtime/autopilot-service" ]]; then
        cp -r "$PROJECT_ROOT/runtime/autopilot-service/"* "$runtime_dest/"
        log_success "Runtime service installed"
    fi

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
# Generated by installer v${VERSION} on $(date -Iseconds)

# =============================================================================
# Deployment Mode
# =============================================================================
AUTOPILOT_MODE=${DEPLOYMENT_MODE}
AUTOPILOT_REQUIRE_TAILSCALE=${REQUIRE_TAILSCALE}

# =============================================================================
# MCP Configuration
# =============================================================================
MCP_URL=${MCP_URL}
MCP_BOOTSTRAP_URL=${MCP_BOOTSTRAP_URL}
AUTOPILOT_MCP_AUTH=${MCP_AUTH}

# =============================================================================
# Slack Configuration (Socket Mode)
# =============================================================================
SLACK_APP_TOKEN=${SLACK_APP_TOKEN}
SLACK_BOT_TOKEN=${SLACK_BOT_TOKEN}

# =============================================================================
# Data Storage
# =============================================================================
AUTOPILOT_DATA_DIR=${DATA_DIR}
AUTOPILOT_CONFIG_DIR=${CONFIG_DIR}

# =============================================================================
# Agent Configuration
# =============================================================================
AUTOPILOT_ENABLE_RESPONDER=${ENABLE_RESPONDER}

# =============================================================================
# Observability
# =============================================================================
METRICS_ENABLED=true
METRICS_PORT=9090
METRICS_HOST=127.0.0.1
LOG_FORMAT=json
LOG_LEVEL=info

# =============================================================================
# OpenClaw Integration
# =============================================================================
OPENCLAW_HOME=${OPENCLAW_HOME}
EOF

    chmod 600 "$env_file"
    log_success "Configuration created at $env_file"
}

bootstrap_openclaw() {
    log_header "Bootstrapping OpenClaw"

    if detect_openclaw; then
        log_info "OpenClaw already installed"
        return 0
    fi

    install_docker

    mkdir -p "$OPENCLAW_HOME"/{agents,config,data}

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
      - MCP_URL=${MCP_URL:-}
      - MCP_AUTH_TOKEN=${MCP_AUTH_TOKEN:-}
    networks:
      - autopilot

networks:
  autopilot:
    driver: bridge
EOF

    log_success "OpenClaw bootstrap files created at $OPENCLAW_HOME"
    log_info "Start OpenClaw with: cd $OPENCLAW_HOME && docker-compose up -d"
}

# =============================================================================
# SCENARIO HANDLERS
# =============================================================================

scenario_all_in_one() {
    log_header "Scenario: All-in-One Installation"
    log_info "Installing everything on this server"

    check_dependencies || install_dependencies
    install_nodejs
    install_tailscale
    bootstrap_openclaw
    create_directories
    install_agent_pack
    link_agents_to_openclaw
    install_runtime_service
    create_env_file

    echo ""
    log_success "All-in-One installation complete!"
    echo ""
    echo "  Architecture:"
    echo "  ┌─────────────────────────────────────────┐"
    echo "  │ This Server                             │"
    echo "  │  Wazuh + MCP + OpenClaw + Runtime       │"
    echo "  └─────────────────────────────────────────┘"
    echo ""
    echo "  Next steps:"
    echo "  1. Install Wazuh MCP Server if not done"
    echo "  2. Configure: $CONFIG_DIR/.env"
    echo "  3. Start OpenClaw: cd $OPENCLAW_HOME && docker-compose up -d"
    echo "  4. Start Runtime: systemctl start wazuh-autopilot"
    echo ""
}

scenario_openclaw_runtime() {
    log_header "Scenario: OpenClaw + Runtime Installation"
    log_info "For when MCP is on a remote server"

    prompt_input "Enter remote MCP URL" "https://mcp-server:8080" MCP_URL
    prompt_input "Enter MCP Auth Token (optional)" "" MCP_AUTH

    check_dependencies || install_dependencies
    install_nodejs
    install_tailscale
    bootstrap_openclaw
    create_directories
    install_agent_pack
    link_agents_to_openclaw
    install_runtime_service
    create_env_file

    echo ""
    log_success "OpenClaw + Runtime installation complete!"
    echo ""
    echo "  Architecture:"
    echo "  ┌─────────────────────┐    ┌─────────────────────┐"
    echo "  │ Remote Server       │    │ This Server         │"
    echo "  │  Wazuh + MCP        │◀───│  OpenClaw + Runtime │"
    echo "  └─────────────────────┘    └─────────────────────┘"
    echo ""
    echo "  MCP URL: $MCP_URL"
    echo ""
}

scenario_runtime_only() {
    log_header "Scenario: Runtime Only Installation"
    log_info "When OpenClaw is on a different server"

    prompt_input "Enter MCP URL" "https://mcp-server:8080" MCP_URL
    prompt_input "Enter MCP Auth Token (optional)" "" MCP_AUTH

    check_dependencies || install_dependencies
    install_nodejs
    create_directories
    install_agent_pack
    install_runtime_service
    create_env_file

    echo ""
    log_success "Runtime Only installation complete!"
    echo ""
    echo "  Architecture:"
    echo "  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐"
    echo "  │ Server A    │  │ Server B    │  │ This Server │"
    echo "  │ Wazuh + MCP │◀─│ OpenClaw    │  │ Runtime     │"
    echo "  └─────────────┘  └─────────────┘  └─────────────┘"
    echo ""
    echo "  Note: Copy agents to OpenClaw server separately"
    echo ""
}

scenario_agent_pack() {
    log_header "Scenario: Agent Pack Only"
    log_info "Installing agents into existing local OpenClaw"

    if ! detect_openclaw; then
        log_error "OpenClaw not found on this server"
        log_info "Use 'Remote OpenClaw' option to copy to a remote server"
        exit 1
    fi

    create_directories
    install_agent_pack
    link_agents_to_openclaw

    echo ""
    log_success "Agent pack installed!"
    echo ""
    echo "  Agents installed to: $CONFIG_DIR/agents"
    echo "  Linked to OpenClaw: $OPENCLAW_HOME/agents"
    echo ""
    echo "  Restart OpenClaw to load new agents"
    echo ""
}

scenario_remote_openclaw() {
    log_header "Scenario: Remote OpenClaw"
    log_info "Copy agents to a remote OpenClaw server"

    prompt_input "Enter remote server hostname/IP" "" REMOTE_HOST
    prompt_input "Enter SSH user" "root" REMOTE_USER
    prompt_input "Enter remote OpenClaw agents path" "/opt/openclaw/agents" REMOTE_OPENCLAW_PATH

    if [[ -z "$REMOTE_HOST" ]]; then
        log_error "Remote host is required"
        exit 1
    fi

    log_info "Testing SSH connection..."
    if ! ssh -o ConnectTimeout=10 -o BatchMode=yes "$REMOTE_USER@$REMOTE_HOST" "echo ok" &>/dev/null; then
        log_warn "SSH connection test failed - make sure SSH keys are set up"
        if ! prompt_yes_no "Continue anyway?"; then
            exit 1
        fi
    fi

    log_info "Copying agents to remote server..."

    ssh "$REMOTE_USER@$REMOTE_HOST" "mkdir -p $REMOTE_OPENCLAW_PATH"
    scp -r "$PROJECT_ROOT/agents/"* "$REMOTE_USER@$REMOTE_HOST:$REMOTE_OPENCLAW_PATH/"

    log_info "Copying policies..."
    ssh "$REMOTE_USER@$REMOTE_HOST" "mkdir -p ${REMOTE_OPENCLAW_PATH%/agents}/config"
    scp -r "$PROJECT_ROOT/policies/"* "$REMOTE_USER@$REMOTE_HOST:${REMOTE_OPENCLAW_PATH%/agents}/config/"

    echo ""
    log_success "Agents copied to remote server!"
    echo ""
    echo "  Remote server: $REMOTE_USER@$REMOTE_HOST"
    echo "  Agents path:   $REMOTE_OPENCLAW_PATH"
    echo ""
    echo "  Next: Restart OpenClaw on the remote server"
    echo "        ssh $REMOTE_USER@$REMOTE_HOST 'docker restart openclaw'"
    echo ""
}

scenario_docker_compose() {
    log_header "Scenario: Docker Compose Generation"
    log_info "Generating docker-compose.yml for full stack"

    local output_dir="${1:-$PROJECT_ROOT/deploy/docker}"
    mkdir -p "$output_dir"

    prompt_input "Enter MCP URL (or leave empty for same container)" "" MCP_URL

    cat > "$output_dir/docker-compose.yml" << 'COMPOSE_EOF'
version: '3.8'

services:
  # Wazuh Manager (optional - remove if using external Wazuh)
  wazuh:
    image: wazuh/wazuh-manager:latest
    container_name: wazuh-manager
    restart: unless-stopped
    ports:
      - "1514:1514/udp"
      - "1515:1515"
      - "55000:55000"
    volumes:
      - wazuh-data:/var/ossec/data
      - wazuh-logs:/var/ossec/logs
    networks:
      - autopilot-net

  # Wazuh MCP Server
  mcp:
    image: gensecaihq/wazuh-mcp-server:latest
    container_name: wazuh-mcp
    restart: unless-stopped
    ports:
      - "8080:8080"
    environment:
      - WAZUH_API_URL=https://wazuh:55000
      - WAZUH_API_USER=${WAZUH_API_USER:-wazuh}
      - WAZUH_API_PASSWORD=${WAZUH_API_PASSWORD:-wazuh}
    depends_on:
      - wazuh
    networks:
      - autopilot-net

  # OpenClaw Agent Orchestration
  openclaw:
    image: openclaw/openclaw:latest
    container_name: openclaw
    restart: unless-stopped
    ports:
      - "127.0.0.1:3000:3000"
    volumes:
      - ./agents:/app/agents:ro
      - ./config:/app/config:ro
      - openclaw-data:/app/data
    environment:
      - NODE_ENV=production
      - MCP_URL=http://mcp:8080
      - MCP_AUTH_TOKEN=${MCP_AUTH_TOKEN:-}
    depends_on:
      - mcp
    networks:
      - autopilot-net

  # Autopilot Runtime Service
  runtime:
    image: node:18-slim
    container_name: autopilot-runtime
    restart: unless-stopped
    working_dir: /app
    ports:
      - "127.0.0.1:9090:9090"
    volumes:
      - ./runtime:/app:ro
      - autopilot-data:/var/lib/wazuh-autopilot
    environment:
      - MCP_URL=http://mcp:8080
      - AUTOPILOT_MCP_AUTH=${MCP_AUTH_TOKEN:-}
      - AUTOPILOT_DATA_DIR=/var/lib/wazuh-autopilot
      - AUTOPILOT_MODE=bootstrap
      - METRICS_HOST=0.0.0.0
    command: node index.js
    depends_on:
      - mcp
    networks:
      - autopilot-net

networks:
  autopilot-net:
    driver: bridge

volumes:
  wazuh-data:
  wazuh-logs:
  openclaw-data:
  autopilot-data:
COMPOSE_EOF

    # Copy agents, policies, and runtime
    mkdir -p "$output_dir"/{agents,config,runtime}
    cp -r "$PROJECT_ROOT/agents/"* "$output_dir/agents/"
    cp -r "$PROJECT_ROOT/policies/"* "$output_dir/config/"
    cp -r "$PROJECT_ROOT/runtime/autopilot-service/"* "$output_dir/runtime/"

    # Create .env template
    cat > "$output_dir/.env" << 'ENV_EOF'
# Wazuh API credentials
WAZUH_API_USER=wazuh
WAZUH_API_PASSWORD=wazuh

# MCP Authentication Token
MCP_AUTH_TOKEN=your-secure-token-here

# Slack (optional)
SLACK_APP_TOKEN=
SLACK_BOT_TOKEN=
ENV_EOF

    echo ""
    log_success "Docker Compose files generated!"
    echo ""
    echo "  Output directory: $output_dir"
    echo ""
    echo "  Files created:"
    echo "    - docker-compose.yml"
    echo "    - .env (configure this)"
    echo "    - agents/"
    echo "    - config/"
    echo "    - runtime/"
    echo ""
    echo "  To start:"
    echo "    cd $output_dir"
    echo "    docker-compose up -d"
    echo ""
}

scenario_kubernetes() {
    log_header "Scenario: Kubernetes Manifests Generation"
    log_info "Generating K8s manifests"

    local output_dir="${1:-$PROJECT_ROOT/deploy/kubernetes}"
    mkdir -p "$output_dir"

    # ConfigMap for agents
    cat > "$output_dir/configmap-agents.yaml" << 'K8S_EOF'
apiVersion: v1
kind: ConfigMap
metadata:
  name: autopilot-agents
  namespace: wazuh-autopilot
data:
  # Agent YAML files will be added here
  # Use: kubectl create configmap autopilot-agents --from-file=agents/
K8S_EOF

    # Deployment
    cat > "$output_dir/deployment.yaml" << 'K8S_EOF'
apiVersion: apps/v1
kind: Deployment
metadata:
  name: wazuh-autopilot
  namespace: wazuh-autopilot
  labels:
    app: wazuh-autopilot
spec:
  replicas: 1
  selector:
    matchLabels:
      app: wazuh-autopilot
  template:
    metadata:
      labels:
        app: wazuh-autopilot
    spec:
      containers:
      # OpenClaw
      - name: openclaw
        image: openclaw/openclaw:latest
        ports:
        - containerPort: 3000
        env:
        - name: MCP_URL
          valueFrom:
            configMapKeyRef:
              name: autopilot-config
              key: mcp_url
        - name: MCP_AUTH_TOKEN
          valueFrom:
            secretKeyRef:
              name: autopilot-secrets
              key: mcp_auth_token
        volumeMounts:
        - name: agents
          mountPath: /app/agents
          readOnly: true

      # Runtime
      - name: runtime
        image: node:18-slim
        workingDir: /app
        command: ["node", "index.js"]
        ports:
        - containerPort: 9090
        env:
        - name: MCP_URL
          valueFrom:
            configMapKeyRef:
              name: autopilot-config
              key: mcp_url
        - name: AUTOPILOT_DATA_DIR
          value: /var/lib/wazuh-autopilot
        - name: METRICS_HOST
          value: "0.0.0.0"
        volumeMounts:
        - name: runtime-code
          mountPath: /app
          readOnly: true
        - name: data
          mountPath: /var/lib/wazuh-autopilot

      volumes:
      - name: agents
        configMap:
          name: autopilot-agents
      - name: runtime-code
        configMap:
          name: autopilot-runtime
      - name: data
        persistentVolumeClaim:
          claimName: autopilot-data
---
apiVersion: v1
kind: Service
metadata:
  name: wazuh-autopilot
  namespace: wazuh-autopilot
spec:
  selector:
    app: wazuh-autopilot
  ports:
  - name: openclaw
    port: 3000
    targetPort: 3000
  - name: metrics
    port: 9090
    targetPort: 9090
---
apiVersion: v1
kind: PersistentVolumeClaim
metadata:
  name: autopilot-data
  namespace: wazuh-autopilot
spec:
  accessModes:
    - ReadWriteOnce
  resources:
    requests:
      storage: 10Gi
K8S_EOF

    # Namespace
    cat > "$output_dir/namespace.yaml" << 'K8S_EOF'
apiVersion: v1
kind: Namespace
metadata:
  name: wazuh-autopilot
K8S_EOF

    # ConfigMap template
    cat > "$output_dir/configmap.yaml" << 'K8S_EOF'
apiVersion: v1
kind: ConfigMap
metadata:
  name: autopilot-config
  namespace: wazuh-autopilot
data:
  mcp_url: "http://wazuh-mcp:8080"
K8S_EOF

    # Secret template
    cat > "$output_dir/secret.yaml" << 'K8S_EOF'
apiVersion: v1
kind: Secret
metadata:
  name: autopilot-secrets
  namespace: wazuh-autopilot
type: Opaque
stringData:
  mcp_auth_token: "your-token-here"
  slack_app_token: ""
  slack_bot_token: ""
K8S_EOF

    echo ""
    log_success "Kubernetes manifests generated!"
    echo ""
    echo "  Output directory: $output_dir"
    echo ""
    echo "  Files created:"
    echo "    - namespace.yaml"
    echo "    - configmap.yaml"
    echo "    - configmap-agents.yaml"
    echo "    - secret.yaml"
    echo "    - deployment.yaml"
    echo ""
    echo "  To deploy:"
    echo "    kubectl apply -f $output_dir/namespace.yaml"
    echo "    kubectl create configmap autopilot-agents -n wazuh-autopilot --from-file=$PROJECT_ROOT/agents/"
    echo "    kubectl create configmap autopilot-runtime -n wazuh-autopilot --from-file=$PROJECT_ROOT/runtime/autopilot-service/"
    echo "    kubectl apply -f $output_dir/"
    echo ""
}

# =============================================================================
# TAILNET CUTOVER
# =============================================================================

tailnet_cutover() {
    log_header "Tailnet Cutover Workflow"

    echo "This workflow transitions from bootstrap to production mode."
    echo ""

    if ! detect_tailscale; then
        log_error "Tailscale is not running. Install and configure first."
        echo ""
        echo "  curl -fsSL https://tailscale.com/install.sh | sh"
        echo "  sudo tailscale up"
        exit 1
    fi

    local new_mcp_url
    prompt_input "Enter the Tailnet MCP URL" "" new_mcp_url

    if [[ -z "$new_mcp_url" ]]; then
        log_error "MCP URL is required"
        exit 1
    fi

    if ! is_tailnet_url "$new_mcp_url"; then
        log_warn "URL doesn't look like a Tailnet URL (.ts.net or 100.x.x.x)"
        if ! prompt_yes_no "Continue anyway?"; then
            exit 1
        fi
    fi

    log_info "Testing MCP connectivity..."
    if ! detect_mcp "$new_mcp_url"; then
        log_error "Cannot connect to MCP"
        exit 1
    fi

    local env_file="$CONFIG_DIR/.env"
    if [[ -f "$env_file" ]]; then
        cp "$env_file" "$env_file.bak.$(date +%Y%m%d%H%M%S)"
        sed -i.tmp "s|^MCP_URL=.*|MCP_URL=$new_mcp_url|" "$env_file"
        sed -i.tmp "s|^AUTOPILOT_MODE=.*|AUTOPILOT_MODE=production|" "$env_file"
        rm -f "$env_file.tmp"
        log_success "Configuration updated"
    fi

    if systemctl is-active --quiet wazuh-autopilot; then
        systemctl restart wazuh-autopilot
        log_success "Service restarted"
    fi

    log_success "Cutover complete!"
}

# =============================================================================
# DOCTOR
# =============================================================================

run_doctor() {
    if [[ -x "$SCRIPT_DIR/doctor.sh" ]]; then
        exec "$SCRIPT_DIR/doctor.sh"
    else
        log_error "Doctor script not found"
        exit 1
    fi
}

# =============================================================================
# INTERACTIVE MENU
# =============================================================================

show_menu() {
    clear
    echo ""
    echo -e "${BOLD}╔═══════════════════════════════════════════════════════════════════╗${NC}"
    echo -e "${BOLD}║           Wazuh Autopilot Installer v${VERSION}                       ║${NC}"
    echo -e "${BOLD}║       Autonomous SOC Layer for Wazuh via OpenClaw Agents          ║${NC}"
    echo -e "${BOLD}╚═══════════════════════════════════════════════════════════════════╝${NC}"
    echo ""
    echo -e "${CYAN}Select your deployment scenario:${NC}"
    echo ""
    echo -e "${BOLD}  Single Server:${NC}"
    echo "    1) All-in-One         - Wazuh + MCP + OpenClaw + Runtime on this server"
    echo ""
    echo -e "${BOLD}  Distributed (MCP on remote server):${NC}"
    echo "    2) OpenClaw + Runtime - Install OpenClaw and Runtime here (MCP elsewhere)"
    echo "    3) Runtime Only       - Just the Runtime service (OpenClaw also elsewhere)"
    echo ""
    echo -e "${BOLD}  Existing OpenClaw:${NC}"
    echo "    4) Agent Pack (Local) - Add agents to existing local OpenClaw"
    echo "    5) Agent Pack (Remote)- Copy agents to remote OpenClaw via SSH"
    echo ""
    echo -e "${BOLD}  Container Deployments:${NC}"
    echo "    6) Docker Compose     - Generate docker-compose.yml"
    echo "    7) Kubernetes         - Generate K8s manifests"
    echo ""
    echo -e "${BOLD}  Utilities:${NC}"
    echo "    8) Doctor             - Run diagnostics"
    echo "    9) Cutover            - Transition to production mode (Tailscale)"
    echo ""
    echo "    0) Exit"
    echo ""

    local choice
    read -rp "Enter choice [0-9]: " choice

    case $choice in
        1) check_root; check_ubuntu; scenario_all_in_one ;;
        2) check_root; check_ubuntu; scenario_openclaw_runtime ;;
        3) check_root; check_ubuntu; scenario_runtime_only ;;
        4) check_root; scenario_agent_pack ;;
        5) scenario_remote_openclaw ;;
        6) scenario_docker_compose ;;
        7) scenario_kubernetes ;;
        8) run_doctor ;;
        9) check_root; tailnet_cutover ;;
        0) echo "Goodbye!"; exit 0 ;;
        *) log_error "Invalid choice"; show_menu ;;
    esac
}

# =============================================================================
# USAGE
# =============================================================================

usage() {
    cat << EOF
Wazuh Autopilot Installer v${VERSION}

Usage: $0 [OPTIONS]

Interactive Mode:
  --menu                     Show interactive deployment menu

Installation Modes:
  --mode all-in-one          Everything on single server
  --mode openclaw-runtime    OpenClaw + Runtime (MCP elsewhere)
  --mode runtime-only        Runtime service only
  --mode agent-pack          Agents into existing local OpenClaw
  --mode remote-openclaw     Copy agents to remote OpenClaw
  --mode docker              Generate Docker Compose files
  --mode kubernetes          Generate Kubernetes manifests
  --mode doctor              Run diagnostics
  --mode cutover             Transition to production mode

Options:
  --mcp-url URL              MCP Server URL
  --mcp-auth TOKEN           MCP Authentication token
  --remote-host HOST         Remote server for SSH operations
  --remote-user USER         SSH user (default: root)
  --output-dir DIR           Output directory for generated files
  --non-interactive          Run without prompts
  --force                    Force installation
  -h, --help                 Show this help

Environment Variables:
  MCP_URL                    MCP Server URL
  AUTOPILOT_MCP_AUTH         MCP Authentication token
  AUTOPILOT_MODE             bootstrap | production
  OPENCLAW_HOME              OpenClaw installation directory
  AUTOPILOT_DATA_DIR         Data directory

Examples:
  # Interactive menu
  sudo $0 --menu

  # All-in-one installation
  sudo $0 --mode all-in-one

  # OpenClaw + Runtime with remote MCP
  sudo $0 --mode openclaw-runtime --mcp-url https://mcp.example.com:8080

  # Copy agents to remote OpenClaw
  $0 --mode remote-openclaw --remote-host openclaw.example.com

  # Generate Docker Compose
  $0 --mode docker --output-dir ./deploy

EOF
}

# =============================================================================
# MAIN
# =============================================================================

main() {
    # No arguments - show menu
    if [[ $# -eq 0 ]]; then
        show_menu
        exit 0
    fi

    # Parse arguments
    while [[ $# -gt 0 ]]; do
        case "$1" in
            --menu)
                show_menu
                exit 0
                ;;
            --mode)
                INSTALL_MODE="$2"
                shift 2
                ;;
            --mcp-url)
                MCP_URL="$2"
                shift 2
                ;;
            --mcp-auth)
                MCP_AUTH="$2"
                shift 2
                ;;
            --remote-host)
                REMOTE_HOST="$2"
                shift 2
                ;;
            --remote-user)
                REMOTE_USER="$2"
                shift 2
                ;;
            --output-dir)
                OUTPUT_DIR="$2"
                shift 2
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

    # Run selected mode
    case "$INSTALL_MODE" in
        all-in-one|fresh)
            check_root
            check_ubuntu
            scenario_all_in_one
            ;;
        openclaw-runtime|bootstrap-openclaw)
            check_root
            check_ubuntu
            scenario_openclaw_runtime
            ;;
        runtime-only|runtime)
            check_root
            check_ubuntu
            scenario_runtime_only
            ;;
        agent-pack|agents)
            check_root
            scenario_agent_pack
            ;;
        remote-openclaw|remote)
            scenario_remote_openclaw
            ;;
        docker|docker-compose)
            scenario_docker_compose "${OUTPUT_DIR:-}"
            ;;
        kubernetes|k8s)
            scenario_kubernetes "${OUTPUT_DIR:-}"
            ;;
        doctor)
            run_doctor
            ;;
        cutover)
            check_root
            tailnet_cutover
            ;;
        "")
            show_menu
            ;;
        *)
            log_error "Unknown mode: $INSTALL_MODE"
            usage
            exit 1
            ;;
    esac
}

main "$@"
