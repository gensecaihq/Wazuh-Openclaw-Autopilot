#!/usr/bin/env bash
#
# Wazuh Autopilot Doctor
# Diagnostic and readiness checker
#
# Outputs:
#   ✅ READY (Production)     - All production requirements met
#   ⚠️  READY (Bootstrap only) - Can run in bootstrap mode only
#   ❌ NOT READY              - Critical requirements missing
#

set -euo pipefail

# =============================================================================
# CONFIGURATION
# =============================================================================

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"
CONFIG_DIR="/etc/wazuh-autopilot"
DATA_DIR="/var/lib/wazuh-autopilot"

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
NC='\033[0m'

# Status tracking
PRODUCTION_READY=true
BOOTSTRAP_READY=true
CHECKS_PASSED=0
CHECKS_WARNED=0
CHECKS_FAILED=0
REMEDIATIONS=()

# =============================================================================
# HELPER FUNCTIONS
# =============================================================================

check_pass() {
    echo -e "  ${GREEN}✓${NC} $1"
    ((CHECKS_PASSED++))
}

check_warn() {
    echo -e "  ${YELLOW}⚠${NC} $1"
    ((CHECKS_WARNED++))
    PRODUCTION_READY=false
}

check_fail() {
    echo -e "  ${RED}✗${NC} $1"
    ((CHECKS_FAILED++))
    PRODUCTION_READY=false
    BOOTSTRAP_READY=false
}

check_info() {
    echo -e "  ${CYAN}ℹ${NC} $1"
}

add_remediation() {
    REMEDIATIONS+=("$1")
}

header() {
    echo ""
    echo -e "${BLUE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    echo -e "${BLUE}  $1${NC}"
    echo -e "${BLUE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
}

# =============================================================================
# ENVIRONMENT LOADING
# =============================================================================

load_env() {
    local env_file="$CONFIG_DIR/.env"

    if [[ -f "$env_file" ]]; then
        set -a
        source "$env_file"
        set +a
        return 0
    fi

    return 1
}

# =============================================================================
# CHECK FUNCTIONS
# =============================================================================

check_configuration() {
    header "Configuration"

    if [[ -f "$CONFIG_DIR/.env" ]]; then
        check_pass "Configuration file exists: $CONFIG_DIR/.env"
        load_env
    else
        check_fail "Configuration file missing: $CONFIG_DIR/.env"
        add_remediation "Run the installer: sudo $SCRIPT_DIR/install.sh --mode fresh"
        return 1
    fi

    # Check required variables
    if [[ -n "${AUTOPILOT_MODE:-}" ]]; then
        check_pass "AUTOPILOT_MODE=$AUTOPILOT_MODE"
    else
        check_warn "AUTOPILOT_MODE not set (defaulting to bootstrap)"
        AUTOPILOT_MODE="bootstrap"
    fi

    if [[ -n "${MCP_URL:-}" ]] || [[ -n "${MCP_BOOTSTRAP_URL:-}" ]]; then
        check_pass "MCP URL configured"
    else
        check_fail "No MCP URL configured (MCP_URL or MCP_BOOTSTRAP_URL required)"
        add_remediation "Set MCP_URL in $CONFIG_DIR/.env"
    fi

    if [[ -d "$DATA_DIR" ]]; then
        check_pass "Data directory exists: $DATA_DIR"
    else
        check_warn "Data directory missing: $DATA_DIR"
        add_remediation "mkdir -p $DATA_DIR/{cases,reports,state}"
    fi
}

check_tailscale() {
    header "Tailscale Status"

    local require_tailscale="${AUTOPILOT_REQUIRE_TAILSCALE:-true}"
    local mode="${AUTOPILOT_MODE:-bootstrap}"

    # Check if Tailscale is installed
    if ! command -v tailscale &> /dev/null; then
        if [[ "$mode" == "production" ]] && [[ "$require_tailscale" == "true" ]]; then
            check_fail "Tailscale not installed (required for production mode)"
            add_remediation "Install Tailscale: curl -fsSL https://tailscale.com/install.sh | sh"
        else
            check_warn "Tailscale not installed (recommended for production)"
            add_remediation "Install Tailscale: curl -fsSL https://tailscale.com/install.sh | sh"
        fi
        return
    fi

    check_pass "Tailscale installed"

    # Check if Tailscale is running
    local status
    if status=$(tailscale status --json 2>/dev/null); then
        local backend_state
        backend_state=$(echo "$status" | jq -r '.BackendState // empty')

        if [[ "$backend_state" == "Running" ]]; then
            local self_ip
            local tailnet_name
            self_ip=$(echo "$status" | jq -r '.Self.TailscaleIPs[0] // empty')
            tailnet_name=$(echo "$status" | jq -r '.MagicDNSSuffix // empty')

            check_pass "Tailscale running (IP: $self_ip)"
            check_info "Tailnet: $tailnet_name"
        else
            if [[ "$mode" == "production" ]]; then
                check_fail "Tailscale not running (State: $backend_state)"
                add_remediation "Start Tailscale: sudo tailscale up"
            else
                check_warn "Tailscale not running (State: $backend_state)"
                add_remediation "Start Tailscale: sudo tailscale up"
            fi
        fi
    else
        if [[ "$mode" == "production" ]]; then
            check_fail "Tailscale not authenticated"
            add_remediation "Authenticate Tailscale: sudo tailscale up"
        else
            check_warn "Tailscale not authenticated"
            add_remediation "Authenticate Tailscale: sudo tailscale up"
        fi
    fi
}

check_mcp_connectivity() {
    header "MCP Connectivity"

    local mode="${AUTOPILOT_MODE:-bootstrap}"
    local mcp_url="${MCP_URL:-}"
    local bootstrap_url="${MCP_BOOTSTRAP_URL:-}"
    local auth="${AUTOPILOT_MCP_AUTH:-}"

    # Determine which URL to test
    local test_url=""
    local is_production_url=false

    if [[ -n "$mcp_url" ]]; then
        test_url="$mcp_url"
        is_production_url=true
    elif [[ -n "$bootstrap_url" ]]; then
        test_url="$bootstrap_url"
    else
        check_fail "No MCP URL configured"
        add_remediation "Set MCP_URL or MCP_BOOTSTRAP_URL in $CONFIG_DIR/.env"
        return 1
    fi

    check_info "Testing: $test_url"

    # Check if URL is Tailnet URL
    local is_tailnet=false
    if [[ "$test_url" =~ \.ts\.net ]] || [[ "$test_url" =~ ^https?://100\. ]]; then
        is_tailnet=true
        check_pass "URL is a Tailnet URL"
    else
        if [[ "$mode" == "production" ]]; then
            check_fail "URL is not a Tailnet URL (required for production)"
            add_remediation "Run cutover: sudo $SCRIPT_DIR/install.sh --cutover"
        else
            check_warn "URL is not a Tailnet URL (ok for bootstrap)"
        fi
    fi

    # Test connectivity
    local http_code
    local curl_opts=(-s -o /dev/null -w "%{http_code}" --connect-timeout 10)

    if [[ -n "$auth" ]]; then
        curl_opts+=(-H "Authorization: Bearer $auth")
    fi

    # Try health endpoint first
    http_code=$(curl "${curl_opts[@]}" "$test_url/health" 2>/dev/null || echo "000")

    case "$http_code" in
        200|204)
            check_pass "MCP health check passed (HTTP $http_code)"
            ;;
        401)
            check_warn "MCP requires authentication"
            add_remediation "Set AUTOPILOT_MCP_AUTH in $CONFIG_DIR/.env"
            ;;
        403)
            check_fail "MCP authentication failed"
            add_remediation "Verify AUTOPILOT_MCP_AUTH token is correct"
            ;;
        000)
            check_fail "Cannot connect to MCP"
            add_remediation "Verify MCP server is running and accessible"
            if [[ "$is_tailnet" == "true" ]]; then
                add_remediation "Check Tailscale ACLs allow connection"
            fi
            ;;
        *)
            check_warn "MCP returned HTTP $http_code"
            ;;
    esac
}

check_mcp_tools() {
    header "MCP Tool Discovery"

    local mcp_url="${MCP_URL:-${MCP_BOOTSTRAP_URL:-}}"
    local auth="${AUTOPILOT_MCP_AUTH:-}"

    if [[ -z "$mcp_url" ]]; then
        check_info "Skipping (no MCP URL)"
        return
    fi

    # Try to list tools
    local response
    local curl_opts=(-s --connect-timeout 10)

    if [[ -n "$auth" ]]; then
        curl_opts+=(-H "Authorization: Bearer $auth")
    fi

    response=$(curl "${curl_opts[@]}" "$mcp_url/tools" 2>/dev/null || echo "")

    if [[ -z "$response" ]] || [[ "$response" == "null" ]]; then
        check_warn "Could not retrieve tool list from MCP"
        return
    fi

    # Parse tool list if it's JSON
    if echo "$response" | jq -e '.' >/dev/null 2>&1; then
        local tool_count
        tool_count=$(echo "$response" | jq -r 'if type == "array" then length else .tools | length end' 2>/dev/null || echo "0")

        if [[ "$tool_count" -gt 0 ]]; then
            check_pass "MCP exposes $tool_count tools"

            # Check for required read tools
            local toolmap="$CONFIG_DIR/policies/toolmap.yaml"
            if [[ -f "$toolmap" ]]; then
                check_info "Validating against toolmap..."

                # Extract required tools from toolmap
                local required_tools=("wazuh_get_alert" "wazuh_search_alerts" "wazuh_search_events")

                for tool in "${required_tools[@]}"; do
                    if echo "$response" | jq -e --arg t "$tool" '.[] | select(.name == $t)' >/dev/null 2>&1 || \
                       echo "$response" | jq -e --arg t "$tool" '.tools[] | select(.name == $t)' >/dev/null 2>&1; then
                        check_pass "Required tool available: $tool"
                    else
                        check_warn "Required tool not found: $tool (may need toolmap update)"
                    fi
                done
            fi
        else
            check_warn "MCP returned empty tool list"
        fi
    else
        check_warn "MCP tool response not in expected format"
    fi
}

check_openclaw() {
    header "OpenClaw Status"

    local openclaw_home="${OPENCLAW_HOME:-/opt/openclaw}"

    # Check for Docker-based OpenClaw
    if docker ps 2>/dev/null | grep -q "openclaw"; then
        check_pass "OpenClaw running in Docker"

        # Check container health
        local container_status
        container_status=$(docker inspect --format='{{.State.Health.Status}}' openclaw 2>/dev/null || echo "unknown")

        if [[ "$container_status" == "healthy" ]]; then
            check_pass "Container health: healthy"
        elif [[ "$container_status" == "unknown" ]]; then
            check_info "Container health check not configured"
        else
            check_warn "Container health: $container_status"
        fi

        return
    fi

    # Check for systemd-based OpenClaw
    if systemctl is-active --quiet openclaw 2>/dev/null; then
        check_pass "OpenClaw running as systemd service"
        return
    fi

    # Check for directory-based installation
    if [[ -d "$openclaw_home" ]]; then
        check_warn "OpenClaw directory exists but service not running"
        add_remediation "Start OpenClaw: cd $openclaw_home && docker-compose up -d"
    else
        check_fail "OpenClaw not found"
        add_remediation "Run: sudo $SCRIPT_DIR/install.sh --mode bootstrap-openclaw"
    fi
}

check_agent_pack() {
    header "Agent Pack"

    local agents_dir="$CONFIG_DIR/agents"

    if [[ ! -d "$agents_dir" ]]; then
        check_fail "Agents directory not found: $agents_dir"
        add_remediation "Run: sudo $SCRIPT_DIR/install.sh --mode agent-pack"
        return
    fi

    # Check for required agents
    local required_agents=(
        "triage.agent.yaml"
        "correlation.agent.yaml"
        "response-planner.agent.yaml"
        "policy-guard.agent.yaml"
        "reporting.agent.yaml"
    )

    local missing=0
    for agent in "${required_agents[@]}"; do
        if [[ -f "$agents_dir/$agent" ]]; then
            check_pass "Agent: $agent"
        else
            check_fail "Missing agent: $agent"
            ((missing++))
        fi
    done

    # Check optional agents
    local optional_agents=(
        "investigation.agent.yaml"
        "responder.agent.yaml"
    )

    for agent in "${optional_agents[@]}"; do
        if [[ -f "$agents_dir/$agent" ]]; then
            check_pass "Agent (optional): $agent"
        else
            check_info "Optional agent not installed: $agent"
        fi
    done

    if [[ $missing -gt 0 ]]; then
        add_remediation "Reinstall agents: sudo $SCRIPT_DIR/install.sh --mode agent-pack"
    fi
}

check_policies() {
    header "Policies"

    local policies_dir="$CONFIG_DIR/policies"

    if [[ ! -d "$policies_dir" ]]; then
        check_fail "Policies directory not found: $policies_dir"
        return
    fi

    # Check policy.yaml
    if [[ -f "$policies_dir/policy.yaml" ]]; then
        check_pass "Policy file: policy.yaml"

        # Validate YAML syntax
        if command -v python3 &> /dev/null; then
            if python3 -c "import yaml; yaml.safe_load(open('$policies_dir/policy.yaml'))" 2>/dev/null; then
                check_pass "Policy YAML syntax valid"
            else
                check_fail "Policy YAML syntax error"
                add_remediation "Validate YAML: python3 -c \"import yaml; yaml.safe_load(open('$policies_dir/policy.yaml'))\""
            fi
        fi
    else
        check_fail "Missing: policy.yaml"
    fi

    # Check toolmap.yaml
    if [[ -f "$policies_dir/toolmap.yaml" ]]; then
        check_pass "Toolmap file: toolmap.yaml"
    else
        check_fail "Missing: toolmap.yaml"
    fi
}

check_slack() {
    header "Slack Configuration"

    local app_token="${SLACK_APP_TOKEN:-}"
    local bot_token="${SLACK_BOT_TOKEN:-}"

    if [[ -z "$app_token" ]] && [[ -z "$bot_token" ]]; then
        check_info "Slack not configured (optional)"
        check_info "Autopilot will work in CLI/local mode only"
        return
    fi

    # Check App Token
    if [[ -n "$app_token" ]]; then
        if [[ "$app_token" =~ ^xapp- ]]; then
            check_pass "Slack App Token configured (xapp-...)"
        else
            check_fail "Slack App Token has wrong format (should start with xapp-)"
        fi
    else
        check_warn "Slack App Token not set (required for Socket Mode)"
        add_remediation "Set SLACK_APP_TOKEN in $CONFIG_DIR/.env"
    fi

    # Check Bot Token
    if [[ -n "$bot_token" ]]; then
        if [[ "$bot_token" =~ ^xoxb- ]]; then
            check_pass "Slack Bot Token configured (xoxb-...)"
        else
            check_fail "Slack Bot Token has wrong format (should start with xoxb-)"
        fi
    else
        check_warn "Slack Bot Token not set"
        add_remediation "Set SLACK_BOT_TOKEN in $CONFIG_DIR/.env"
    fi

    # Test Slack connectivity (if both tokens present)
    if [[ -n "$app_token" ]] && [[ -n "$bot_token" ]]; then
        check_info "Testing Slack API connectivity..."

        local response
        response=$(curl -s -H "Authorization: Bearer $bot_token" \
            "https://slack.com/api/auth.test" 2>/dev/null || echo "{}")

        local ok
        ok=$(echo "$response" | jq -r '.ok // false')

        if [[ "$ok" == "true" ]]; then
            local team
            team=$(echo "$response" | jq -r '.team // "unknown"')
            check_pass "Slack API connected (Team: $team)"
        else
            local error
            error=$(echo "$response" | jq -r '.error // "unknown"')
            check_fail "Slack API error: $error"
        fi
    fi
}

check_service() {
    header "Autopilot Service"

    # Check systemd service
    if [[ -f /etc/systemd/system/wazuh-autopilot.service ]]; then
        check_pass "Systemd service file exists"

        if systemctl is-enabled --quiet wazuh-autopilot 2>/dev/null; then
            check_pass "Service enabled"
        else
            check_warn "Service not enabled"
            add_remediation "Enable service: sudo systemctl enable wazuh-autopilot"
        fi

        if systemctl is-active --quiet wazuh-autopilot 2>/dev/null; then
            check_pass "Service running"
        else
            check_warn "Service not running"
            add_remediation "Start service: sudo systemctl start wazuh-autopilot"
        fi
    else
        check_info "Systemd service not installed (optional)"
    fi
}

check_observability() {
    header "Observability"

    local metrics_enabled="${METRICS_ENABLED:-true}"
    local metrics_port="${METRICS_PORT:-9090}"
    local metrics_host="${METRICS_HOST:-127.0.0.1}"

    if [[ "$metrics_enabled" == "true" ]]; then
        check_pass "Metrics enabled"
        check_info "Metrics endpoint: http://$metrics_host:$metrics_port/metrics"

        # Check if port is listening
        if command -v ss &> /dev/null; then
            if ss -tlnp | grep -q ":$metrics_port"; then
                check_pass "Metrics port $metrics_port is listening"
            else
                check_info "Metrics port $metrics_port not yet listening (service may not be running)"
            fi
        fi
    else
        check_info "Metrics disabled"
    fi

    # Check log format
    local log_format="${LOG_FORMAT:-json}"
    check_info "Log format: $log_format"
}

# =============================================================================
# SUMMARY
# =============================================================================

print_summary() {
    echo ""
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    echo ""

    local total=$((CHECKS_PASSED + CHECKS_WARNED + CHECKS_FAILED))

    if [[ "$PRODUCTION_READY" == "true" ]]; then
        echo -e "  ${GREEN}╔═══════════════════════════════════════╗${NC}"
        echo -e "  ${GREEN}║     ✅ READY (Production)             ║${NC}"
        echo -e "  ${GREEN}╚═══════════════════════════════════════╝${NC}"
    elif [[ "$BOOTSTRAP_READY" == "true" ]]; then
        echo -e "  ${YELLOW}╔═══════════════════════════════════════╗${NC}"
        echo -e "  ${YELLOW}║     ⚠️  READY (Bootstrap only)         ║${NC}"
        echo -e "  ${YELLOW}╚═══════════════════════════════════════╝${NC}"
    else
        echo -e "  ${RED}╔═══════════════════════════════════════╗${NC}"
        echo -e "  ${RED}║     ❌ NOT READY                      ║${NC}"
        echo -e "  ${RED}╚═══════════════════════════════════════╝${NC}"
    fi

    echo ""
    echo "  Summary:"
    echo -e "    ${GREEN}Passed:${NC}  $CHECKS_PASSED"
    echo -e "    ${YELLOW}Warnings:${NC} $CHECKS_WARNED"
    echo -e "    ${RED}Failed:${NC}  $CHECKS_FAILED"
    echo ""

    # Print remediations
    if [[ ${#REMEDIATIONS[@]} -gt 0 ]]; then
        echo "  Remediation Steps:"
        echo ""
        local i=1
        for remediation in "${REMEDIATIONS[@]}"; do
            echo "    $i. $remediation"
            ((i++))
        done
        echo ""
    fi

    # Mode-specific guidance
    if [[ "$PRODUCTION_READY" != "true" ]] && [[ "$BOOTSTRAP_READY" == "true" ]]; then
        echo "  To transition to production mode:"
        echo "    sudo $SCRIPT_DIR/install.sh --cutover"
        echo ""
    fi

    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    echo ""
}

# =============================================================================
# MAIN
# =============================================================================

main() {
    echo ""
    echo "╔═══════════════════════════════════════════════════════════╗"
    echo "║              Wazuh Autopilot Doctor                       ║"
    echo "║           Diagnostic & Readiness Checker                  ║"
    echo "╚═══════════════════════════════════════════════════════════╝"

    # Run all checks
    check_configuration
    check_tailscale
    check_mcp_connectivity
    check_mcp_tools
    check_openclaw
    check_agent_pack
    check_policies
    check_slack
    check_service
    check_observability

    # Print summary
    print_summary

    # Exit with appropriate code
    if [[ "$PRODUCTION_READY" == "true" ]]; then
        exit 0
    elif [[ "$BOOTSTRAP_READY" == "true" ]]; then
        exit 0
    else
        exit 1
    fi
}

main "$@"
