#!/usr/bin/env bash
#
# Wazuh Autopilot Uninstaller
# Removes Autopilot components while preserving data (optional)
#

set -euo pipefail

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

CONFIG_DIR="/etc/wazuh-autopilot"
DATA_DIR="/var/lib/wazuh-autopilot"
PRESERVE_DATA=true

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

usage() {
    cat << EOF
Wazuh Autopilot Uninstaller

Usage: $0 [OPTIONS]

Options:
  --purge           Remove all data including cases and evidence packs
  --keep-data       Preserve data directory (default)
  -h, --help        Show this help message

By default, the uninstaller preserves the data directory ($DATA_DIR)
to protect evidence packs and case data.

EOF
}

main() {
    # Parse arguments
    while [[ $# -gt 0 ]]; do
        case "$1" in
            --purge)
                PRESERVE_DATA=false
                shift
                ;;
            --keep-data)
                PRESERVE_DATA=true
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

    # Check root
    if [[ $EUID -ne 0 ]]; then
        log_error "This script must be run as root"
        exit 1
    fi

    echo ""
    echo "╔═══════════════════════════════════════════════════════════╗"
    echo "║           Wazuh Autopilot Uninstaller                     ║"
    echo "╚═══════════════════════════════════════════════════════════╝"
    echo ""

    if [[ "$PRESERVE_DATA" == "true" ]]; then
        log_info "Data directory will be preserved: $DATA_DIR"
    else
        log_warn "Data directory will be DELETED: $DATA_DIR"
        echo ""
        read -rp "Are you sure you want to delete all data? (type 'yes' to confirm): " confirm
        if [[ "$confirm" != "yes" ]]; then
            log_info "Aborted"
            exit 0
        fi
    fi

    echo ""

    # Stop autopilot service
    log_info "Stopping wazuh-autopilot service..."
    if systemctl is-active --quiet wazuh-autopilot 2>/dev/null; then
        systemctl stop wazuh-autopilot
        log_success "wazuh-autopilot service stopped"
    else
        log_info "wazuh-autopilot service not running"
    fi

    # Disable autopilot service
    if systemctl is-enabled --quiet wazuh-autopilot 2>/dev/null; then
        systemctl disable wazuh-autopilot
        log_success "wazuh-autopilot service disabled"
    fi

    # Remove autopilot systemd service file
    if [[ -f /etc/systemd/system/wazuh-autopilot.service ]]; then
        rm /etc/systemd/system/wazuh-autopilot.service
        log_success "wazuh-autopilot systemd service removed"
    fi

    # Stop MCP server service
    log_info "Stopping wazuh-mcp-server service..."
    if systemctl is-active --quiet wazuh-mcp-server 2>/dev/null; then
        systemctl stop wazuh-mcp-server
        log_success "wazuh-mcp-server service stopped"
    else
        log_info "wazuh-mcp-server service not running"
    fi

    # Disable MCP server service
    if systemctl is-enabled --quiet wazuh-mcp-server 2>/dev/null; then
        systemctl disable wazuh-mcp-server
        log_success "wazuh-mcp-server service disabled"
    fi

    # Remove MCP server systemd service file
    if [[ -f /etc/systemd/system/wazuh-mcp-server.service ]]; then
        rm /etc/systemd/system/wazuh-mcp-server.service
        log_success "wazuh-mcp-server systemd service removed"
    fi

    # Reload systemd after removing service files
    systemctl daemon-reload 2>/dev/null || true

    # Remove configuration
    if [[ -d "$CONFIG_DIR" ]]; then
        rm -rf "$CONFIG_DIR"
        log_success "Configuration removed: $CONFIG_DIR"
    fi

    # Remove data (if purge requested)
    if [[ "$PRESERVE_DATA" == "false" ]] && [[ -d "$DATA_DIR" ]]; then
        rm -rf "$DATA_DIR"
        log_success "Data removed: $DATA_DIR"
    elif [[ -d "$DATA_DIR" ]]; then
        log_info "Data preserved: $DATA_DIR"
    fi

    # Remove OpenClaw agent links (but not OpenClaw itself)
    local openclaw_home="${OPENCLAW_HOME:-/opt/openclaw}"
    if [[ -L "$openclaw_home/agents" ]]; then
        rm "$openclaw_home/agents"
        log_success "Removed agent link from OpenClaw"
    fi

    # Offer to remove OpenClaw workspace for Wazuh Autopilot
    local openclaw_workspace="$HOME/.openclaw/wazuh-autopilot"
    if [[ -d "$openclaw_workspace" ]]; then
        echo ""
        read -rp "Remove OpenClaw workspace ($openclaw_workspace)? [y/N]: " remove_workspace
        if [[ "$remove_workspace" =~ ^[Yy]$ ]]; then
            rm -rf "$openclaw_workspace"
            log_success "OpenClaw workspace removed: $openclaw_workspace"
        else
            log_info "OpenClaw workspace preserved: $openclaw_workspace"
        fi
    fi

    echo ""
    log_success "Wazuh Autopilot uninstalled"
    echo ""

    if [[ "$PRESERVE_DATA" == "true" ]]; then
        echo "  Data preserved at: $DATA_DIR"
        echo "  To completely remove data: $0 --purge"
    fi

    echo ""
    echo "  Note: OpenClaw and Tailscale were not removed."
    echo "  Remove them manually if no longer needed."
    echo ""
}

main "$@"
