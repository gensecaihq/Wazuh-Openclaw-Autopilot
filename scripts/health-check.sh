#!/usr/bin/env bash
# =============================================================================
# WAZUH OPENCLAW AUTOPILOT - FULL STACK HEALTH CHECK
# =============================================================================
#
# Verifies connectivity and configuration of all components:
#   - Runtime Service (API health, readiness)
#   - MCP Server (TCP connectivity)
#   - OpenClaw Gateway (TCP connectivity)
#   - Wazuh Manager (API authentication)
#   - Slack Integration (optional, token validation)
#   - Policy & Toolmap files
#   - Directory permissions
#   - Systemd services
#   - Disk space
#
# Usage:
#   ./scripts/health-check.sh              # Full check
#   ./scripts/health-check.sh --quick      # Skip slow checks (Wazuh API, Slack)
#   ./scripts/health-check.sh --json       # Output JSON (for automation)
#
# Exit codes:
#   0 - All checks passed
#   1 - One or more checks failed
#   2 - Script error
#
# =============================================================================

set -uo pipefail

# =============================================================================
# CONFIGURATION
# =============================================================================

CONFIG_DIR="${AUTOPILOT_CONFIG_DIR:-/etc/wazuh-autopilot}"
DATA_DIR="${AUTOPILOT_DATA_DIR:-/var/lib/wazuh-autopilot}"
SECRETS_DIR="$CONFIG_DIR/secrets"

# Default ports (overridden by .env if present)
RUNTIME_PORT="${RUNTIME_PORT:-9090}"
RUNTIME_HOST="${METRICS_HOST:-127.0.0.1}"
GATEWAY_PORT="${GATEWAY_PORT:-18789}"
GATEWAY_HOST="127.0.0.1"
MCP_PORT="${MCP_PORT:-8080}"

# Load .env if available
if [[ -f "$CONFIG_DIR/.env" ]]; then
    # shellcheck disable=SC1091
    set -a
    source "$CONFIG_DIR/.env" 2>/dev/null || true
    set +a
    # RUNTIME_PORT is canonical; fall back to METRICS_PORT for backward compat
    RUNTIME_PORT="${RUNTIME_PORT:-${METRICS_PORT:-9090}}"
    RUNTIME_HOST="${METRICS_HOST:-${RUNTIME_HOST}}"
    GATEWAY_PORT="${GATEWAY_PORT:-${OPENCLAW_PORT:-18789}}"
    MCP_PORT="${MCP_PORT:-8080}"
fi

# Flags
QUICK_MODE=false
JSON_MODE=false

for arg in "$@"; do
    case "$arg" in
        --quick) QUICK_MODE=true ;;
        --json)  JSON_MODE=true ;;
    esac
done

# Colors (disabled in JSON mode)
if $JSON_MODE; then
    RED="" GREEN="" YELLOW="" BLUE="" CYAN="" BOLD="" NC=""
else
    RED='\033[0;31m'
    GREEN='\033[0;32m'
    YELLOW='\033[1;33m'
    BLUE='\033[0;34m'
    CYAN='\033[0;36m'
    BOLD='\033[1m'
    NC='\033[0m'
fi

# Counters
PASS=0
FAIL=0
WARN=0
SKIP=0

# JSON results array
declare -a JSON_RESULTS=()

# =============================================================================
# HELPER FUNCTIONS
# =============================================================================

check_pass() {
    local name="$1"
    local detail="${2:-}"
    ((PASS++))
    if $JSON_MODE; then
        JSON_RESULTS+=("{\"check\":\"$name\",\"status\":\"pass\",\"detail\":\"$detail\"}")
    else
        echo -e "  ${GREEN}PASS${NC}  $name${detail:+ - $detail}"
    fi
}

check_fail() {
    local name="$1"
    local detail="${2:-}"
    ((FAIL++))
    if $JSON_MODE; then
        JSON_RESULTS+=("{\"check\":\"$name\",\"status\":\"fail\",\"detail\":\"$detail\"}")
    else
        echo -e "  ${RED}FAIL${NC}  $name${detail:+ - $detail}"
    fi
}

check_warn() {
    local name="$1"
    local detail="${2:-}"
    ((WARN++))
    if $JSON_MODE; then
        JSON_RESULTS+=("{\"check\":\"$name\",\"status\":\"warn\",\"detail\":\"$detail\"}")
    else
        echo -e "  ${YELLOW}WARN${NC}  $name${detail:+ - $detail}"
    fi
}

check_skip() {
    local name="$1"
    local detail="${2:-}"
    ((SKIP++))
    if $JSON_MODE; then
        JSON_RESULTS+=("{\"check\":\"$name\",\"status\":\"skip\",\"detail\":\"$detail\"}")
    else
        echo -e "  ${BLUE}SKIP${NC}  $name${detail:+ - $detail}"
    fi
}

section() {
    if ! $JSON_MODE; then
        echo ""
        echo -e "  ${CYAN}${BOLD}$1${NC}"
        echo ""
    fi
}

# =============================================================================
# CHECKS
# =============================================================================

check_runtime_service() {
    section "Runtime Service"

    # Health endpoint
    local health_response
    health_response=$(curl -sf --connect-timeout 5 "http://${RUNTIME_HOST}:${RUNTIME_PORT}/health" 2>/dev/null)
    if [[ $? -eq 0 ]] && echo "$health_response" | grep -q '"status"'; then
        local status version mode
        status=$(echo "$health_response" | grep -o '"status":"[^"]*"' | cut -d'"' -f4)
        version=$(echo "$health_response" | grep -o '"version":"[^"]*"' | cut -d'"' -f4)
        mode=$(echo "$health_response" | grep -o '"mode":"[^"]*"' | cut -d'"' -f4)
        check_pass "Runtime /health" "$status (v$version, $mode)"
    else
        check_fail "Runtime /health" "Not responding on ${RUNTIME_HOST}:${RUNTIME_PORT}"
    fi

    # Readiness endpoint
    local ready_response
    ready_response=$(curl -sf --connect-timeout 5 "http://${RUNTIME_HOST}:${RUNTIME_PORT}/ready" 2>/dev/null)
    if [[ $? -eq 0 ]] && echo "$ready_response" | grep -q '"ready":true'; then
        check_pass "Runtime /ready" "Service ready"
    else
        check_fail "Runtime /ready" "Not ready"
    fi

    # Metrics endpoint
    local metrics_response
    metrics_response=$(curl -sf --connect-timeout 5 "http://${RUNTIME_HOST}:${RUNTIME_PORT}/metrics" 2>/dev/null)
    if [[ $? -eq 0 ]] && echo "$metrics_response" | grep -q "autopilot_"; then
        check_pass "Runtime /metrics" "Prometheus metrics available"
    else
        check_warn "Runtime /metrics" "Metrics not available"
    fi

    # Responder status
    local responder_response
    responder_response=$(curl -sf --connect-timeout 5 "http://${RUNTIME_HOST}:${RUNTIME_PORT}/api/responder/status" 2>/dev/null)
    if [[ $? -eq 0 ]]; then
        if echo "$responder_response" | grep -q '"enabled":true'; then
            check_warn "Responder capability" "ENABLED (ensure two-tier approval is configured)"
        else
            check_pass "Responder capability" "Disabled (safe mode)"
        fi
    else
        check_skip "Responder status" "Could not query"
    fi
}

check_mcp_server() {
    section "MCP Server"

    # Extract MCP host/port from env
    local mcp_url="${MCP_URL:-}"
    if [[ -z "$mcp_url" ]]; then
        check_warn "MCP Server URL" "MCP_URL not configured"
        return
    fi

    # Parse host and port from URL
    local mcp_host mcp_port_parsed
    mcp_host=$(echo "$mcp_url" | sed -E 's|https?://||;s|:.*||;s|/.*||')
    mcp_port_parsed=$(echo "$mcp_url" | sed -n 's|.*:\([0-9][0-9]*\).*|\1|p' | head -1)
    mcp_port_parsed="${mcp_port_parsed:-$MCP_PORT}"

    # TCP connectivity
    if timeout 5 bash -c "echo >/dev/tcp/$mcp_host/$mcp_port_parsed" 2>/dev/null; then
        check_pass "MCP Server TCP" "Reachable at $mcp_host:$mcp_port_parsed"
    else
        check_fail "MCP Server TCP" "Cannot connect to $mcp_host:$mcp_port_parsed"
    fi
}

check_openclaw_gateway() {
    section "OpenClaw Gateway"

    # TCP connectivity
    if timeout 5 bash -c "echo >/dev/tcp/$GATEWAY_HOST/$GATEWAY_PORT" 2>/dev/null; then
        check_pass "OpenClaw Gateway TCP" "Reachable at $GATEWAY_HOST:$GATEWAY_PORT"
    else
        check_warn "OpenClaw Gateway TCP" "Not listening on $GATEWAY_HOST:$GATEWAY_PORT (start with: openclaw gateway start)"
    fi

    # Check if openclaw CLI is available
    if command -v openclaw &>/dev/null; then
        check_pass "OpenClaw CLI" "Installed"
    else
        check_warn "OpenClaw CLI" "Not found in PATH"
    fi
}

check_wazuh_api() {
    section "Wazuh Manager"

    if $QUICK_MODE; then
        check_skip "Wazuh API" "Skipped (--quick mode)"
        return
    fi

    local wazuh_url="${WAZUH_API_URL:-}"
    local wazuh_user="${WAZUH_API_USER:-}"
    local wazuh_pass="${WAZUH_API_PASSWORD:-}"

    if [[ -z "$wazuh_url" ]]; then
        check_warn "Wazuh API URL" "WAZUH_API_URL not configured"
        return
    fi

    # TCP connectivity
    local wazuh_host wazuh_port
    wazuh_host=$(echo "$wazuh_url" | sed -E 's|https?://||;s|:.*||;s|/.*||')
    wazuh_port=$(echo "$wazuh_url" | sed -n 's|.*:\([0-9][0-9]*\).*|\1|p' | head -1)
    wazuh_port="${wazuh_port:-55000}"

    if timeout 5 bash -c "echo >/dev/tcp/$wazuh_host/$wazuh_port" 2>/dev/null; then
        check_pass "Wazuh API TCP" "Reachable at $wazuh_host:$wazuh_port"
    else
        check_fail "Wazuh API TCP" "Cannot connect to $wazuh_host:$wazuh_port"
        return
    fi

    # Authentication test
    if [[ -n "$wazuh_user" ]] && [[ -n "$wazuh_pass" ]]; then
        local auth_response
        auth_response=$(curl -sf --connect-timeout 10 -k -u "$wazuh_user:$wazuh_pass" \
            "$wazuh_url/security/user/authenticate" 2>/dev/null)
        if [[ $? -eq 0 ]] && echo "$auth_response" | grep -q "token"; then
            check_pass "Wazuh API Auth" "Authentication successful"
        else
            check_fail "Wazuh API Auth" "Authentication failed"
        fi
    else
        check_warn "Wazuh API Auth" "Credentials not configured"
    fi
}

check_slack_integration() {
    section "Slack Integration (Optional)"

    if $QUICK_MODE; then
        check_skip "Slack" "Skipped (--quick mode)"
        return
    fi

    local app_token="${SLACK_APP_TOKEN:-}"
    local bot_token="${SLACK_BOT_TOKEN:-}"

    if [[ -z "$app_token" ]] || [[ -z "$bot_token" ]]; then
        check_skip "Slack tokens" "Not configured (optional)"
        return
    fi

    # Validate token format
    if [[ "$app_token" == xapp-* ]]; then
        check_pass "Slack App Token" "Format valid (xapp-...)"
    else
        check_fail "Slack App Token" "Invalid format (must start with xapp-)"
    fi

    if [[ "$bot_token" == xoxb-* ]]; then
        check_pass "Slack Bot Token" "Format valid (xoxb-...)"
    else
        check_fail "Slack Bot Token" "Invalid format (must start with xoxb-)"
    fi

    # Test API connectivity
    local auth_response
    auth_response=$(curl -sf --connect-timeout 10 \
        -H "Authorization: Bearer $bot_token" \
        "https://slack.com/api/auth.test" 2>/dev/null)
    if [[ $? -eq 0 ]] && echo "$auth_response" | grep -q '"ok":true'; then
        local team
        team=$(echo "$auth_response" | grep -o '"team":"[^"]*"' | cut -d'"' -f4)
        check_pass "Slack API" "Connected to workspace: $team"
    else
        check_fail "Slack API" "Authentication failed"
    fi
}

check_policy_files() {
    section "Policy & Configuration Files"

    # Policy file
    if [[ -f "$CONFIG_DIR/policies/policy.yaml" ]]; then
        check_pass "Policy file" "$CONFIG_DIR/policies/policy.yaml"
    elif [[ -f "policies/policy.yaml" ]]; then
        check_pass "Policy file" "policies/policy.yaml (local)"
    else
        check_fail "Policy file" "Not found"
    fi

    # Toolmap file
    if [[ -f "$CONFIG_DIR/policies/toolmap.yaml" ]]; then
        check_pass "Toolmap file" "$CONFIG_DIR/policies/toolmap.yaml"
    elif [[ -f "policies/toolmap.yaml" ]]; then
        check_pass "Toolmap file" "policies/toolmap.yaml (local)"
    else
        check_fail "Toolmap file" "Not found"
    fi

    # Environment file
    if [[ -f "$CONFIG_DIR/.env" ]]; then
        local env_perms
        env_perms=$(stat -f %Lp "$CONFIG_DIR/.env" 2>/dev/null || stat -c %a "$CONFIG_DIR/.env" 2>/dev/null || echo "unknown")
        if [[ "$env_perms" == "600" ]]; then
            check_pass "Environment file" "Permissions 600 (secure)"
        else
            check_warn "Environment file" "Permissions $env_perms (should be 600)"
        fi
    else
        check_warn "Environment file" "Not found at $CONFIG_DIR/.env"
    fi
}

check_directory_permissions() {
    section "Directory Permissions"

    for dir_pair in "Config:$CONFIG_DIR:700" "Data:$DATA_DIR:750" "Secrets:$SECRETS_DIR:700"; do
        local label dir expected
        IFS=: read -r label dir expected <<< "$dir_pair"

        if [[ ! -d "$dir" ]]; then
            check_warn "$label directory" "$dir does not exist"
            continue
        fi

        local perms
        perms=$(stat -f %Lp "$dir" 2>/dev/null || stat -c %a "$dir" 2>/dev/null || echo "unknown")
        if [[ "$perms" == "$expected" ]]; then
            check_pass "$label directory" "Permissions $perms"
        else
            check_warn "$label directory" "Permissions $perms (expected $expected)"
        fi
    done
}

check_systemd_services() {
    section "Systemd Services"

    if ! command -v systemctl &>/dev/null; then
        check_skip "Systemd" "Not available (Docker or non-systemd environment)"
        return
    fi

    for svc in "wazuh-autopilot" "wazuh-mcp-server" "wazuh-manager"; do
        if systemctl is-active --quiet "$svc" 2>/dev/null; then
            check_pass "$svc" "Active and running"
        elif systemctl is-enabled --quiet "$svc" 2>/dev/null; then
            check_warn "$svc" "Enabled but not running"
        elif systemctl list-unit-files "$svc.service" 2>/dev/null | grep -q "$svc"; then
            check_warn "$svc" "Installed but not enabled"
        else
            check_skip "$svc" "Not installed"
        fi
    done
}

check_disk_space() {
    section "Disk Space"

    if [[ -d "$DATA_DIR" ]]; then
        local available_mb
        available_mb=$(df -m "$DATA_DIR" 2>/dev/null | tail -1 | awk '{print $4}')
        if [[ -n "$available_mb" ]] && [[ "$available_mb" -gt 500 ]]; then
            check_pass "Data directory disk" "${available_mb}MB available"
        elif [[ -n "$available_mb" ]] && [[ "$available_mb" -gt 100 ]]; then
            check_warn "Data directory disk" "${available_mb}MB available (low)"
        elif [[ -n "$available_mb" ]]; then
            check_fail "Data directory disk" "${available_mb}MB available (critical)"
        else
            check_skip "Data directory disk" "Could not determine"
        fi
    else
        check_skip "Data directory disk" "$DATA_DIR does not exist"
    fi
}

# =============================================================================
# MAIN
# =============================================================================

main() {
    if ! $JSON_MODE; then
        echo ""
        echo -e "  ${BOLD}Wazuh OpenClaw Autopilot - Health Check${NC}"
        echo -e "  $(date -Iseconds)"
        echo ""
    fi

    check_runtime_service
    check_mcp_server
    check_openclaw_gateway
    check_wazuh_api
    check_slack_integration
    check_policy_files
    check_directory_permissions
    check_systemd_services
    check_disk_space

    # Summary
    if $JSON_MODE; then
        local results
        results=$(printf '%s,' "${JSON_RESULTS[@]}")
        results="[${results%,}]"
        echo "{\"timestamp\":\"$(date -Iseconds)\",\"pass\":$PASS,\"fail\":$FAIL,\"warn\":$WARN,\"skip\":$SKIP,\"results\":$results}"
    else
        echo ""
        echo -e "  ${BOLD}Summary${NC}"
        echo ""
        echo -e "  ${GREEN}PASS${NC}: $PASS  ${RED}FAIL${NC}: $FAIL  ${YELLOW}WARN${NC}: $WARN  ${BLUE}SKIP${NC}: $SKIP"
        echo ""
        if [[ $FAIL -eq 0 ]]; then
            echo -e "  ${GREEN}${BOLD}All critical checks passed.${NC}"
        else
            echo -e "  ${RED}${BOLD}$FAIL check(s) failed. Review above for details.${NC}"
        fi
        echo ""
    fi

    if [[ $FAIL -gt 0 ]]; then
        exit 1
    fi
    exit 0
}

main "$@"
