# Wazuh OpenClaw Autopilot - Quick Start Guide

Get Wazuh OpenClaw Autopilot running in under 15 minutes.

## Prerequisites

- **Ubuntu 22.04 or 24.04** (other Linux distros may work)
- **Node.js 18+** for runtime service
- **Wazuh Manager** installed and running
- **Wazuh MCP Server** deployed - [gensecaihq/Wazuh-MCP-Server](https://github.com/gensecaihq/Wazuh-MCP-Server)
- **OpenClaw** for agent orchestration - [openclaw/openclaw](https://github.com/openclaw/openclaw)
- **Root access** for installation

## Step 1: Clone the Repository

```bash
git clone https://github.com/gensecaihq/Wazuh-Openclaw-Autopilot.git
cd Wazuh-Openclaw-Autopilot
```

## Step 2: Run the Installer

### Standard Installation

```bash
sudo ./install/install.sh
```

### Air-Gapped / Bootstrap (No Tailscale)

For environments without internet access or during evaluation:

```bash
sudo ./install/install.sh --skip-tailscale
```

See the [Air-Gapped Deployment Guide](AIR_GAPPED_DEPLOYMENT.md) for Ollama-only setups.

## Step 3: Configure the Service

Edit the configuration file:

```bash
sudo nano /etc/wazuh-autopilot/.env
```

**Required settings:**

```bash
# MCP Server Connection
# Replace with your actual MCP server URL
MCP_URL=https://your-mcp-server:3000

# MCP Authentication Token
# Get this from your MCP server configuration
AUTOPILOT_MCP_AUTH=your-mcp-auth-token
```

**Optional Slack integration:**

```bash
# Slack tokens for notifications and approvals
# Get these from your Slack app configuration
# See: docs/SLACK_SOCKET_MODE.md
SLACK_APP_TOKEN=xapp-1-your-app-token
SLACK_BOT_TOKEN=xoxb-your-bot-token
```

## Step 4: Configure Slack Approvers (Optional)

Slack is optional. Without it, approvals work via the REST API (`POST /api/plans/:id/approve`).

If you want Slack notifications and interactive approval buttons, edit the policy file:

```bash
sudo nano /etc/wazuh-autopilot/policies/policy.yaml
```

Replace the placeholder values:
- `<SLACK_WORKSPACE_ID>` - Your Slack workspace ID
- `<SLACK_CHANNEL_ALERTS>` - Channel ID for security alerts
- `<SLACK_CHANNEL_APPROVALS>` - Channel ID for approval requests
- `<SLACK_USER_*>` - Slack user IDs for your security team

See the comments in the file for instructions on finding these IDs.

## Step 5: Start the Service

```bash
# Start the runtime service
sudo systemctl start wazuh-autopilot

# Enable on boot
sudo systemctl enable wazuh-autopilot

# Check status
sudo systemctl status wazuh-autopilot
```

## Step 6: Verify Installation

### Run health check:

```bash
./scripts/health-check.sh
```

### Check health endpoint (default port 9090, configurable via RUNTIME_PORT):

```bash
curl http://127.0.0.1:9090/health
```

Expected response:
```json
{
  "status": "healthy",
  "version": "2.1.0",
  "mode": "bootstrap"
}
```

### Run diagnostics:

```bash
./scripts/health-check.sh --quick
```

## Step 7: Test Alert Ingestion

Send a test alert to verify triage works:

```bash
curl -X POST http://127.0.0.1:9090/api/alerts \
  -H "Content-Type: application/json" \
  -d '{
    "alert_id": "test-001",
    "rule": {
      "id": "5712",
      "level": 10,
      "description": "Test alert - SSH brute force"
    },
    "agent": {
      "id": "001",
      "name": "test-server",
      "ip": "10.0.1.50"
    },
    "data": {
      "srcip": "192.168.1.100"
    }
  }'
```

Expected response (case_id is a hash-based identifier):
```json
{
  "case_id": "CASE-20260217-6a82c1f38bed",
  "status": "created",
  "severity": "high",
  "entities_extracted": 2
}
```

> If OpenClaw Gateway is running, the runtime will also dispatch a webhook to `/webhook/wazuh-alert` to trigger the Triage Agent automatically.

### View the created case:

```bash
curl http://127.0.0.1:9090/api/cases
```

## Step 8: Test Alert Grouping

Send a second alert with the same source IP — it should be grouped into the same case:

```bash
curl -X POST http://127.0.0.1:9090/api/alerts \
  -H "Content-Type: application/json" \
  -d '{
    "alert_id": "test-002",
    "rule": {
      "id": "5712",
      "level": 12,
      "description": "Test alert - SSH brute force continued"
    },
    "agent": {
      "id": "001",
      "name": "test-server",
      "ip": "10.0.1.50"
    },
    "data": {
      "srcip": "192.168.1.100"
    }
  }'
```

Expected response (note `status: "updated"` and `grouped_into`):
```json
{
  "case_id": "CASE-20260217-6a82c1f38bed",
  "status": "updated",
  "severity": "high",
  "entities_extracted": 2,
  "grouped_into": "CASE-20260217-6a82c1f38bed"
}
```

## Step 9: Submit Feedback (Optional)

Mark a case as a false positive or true positive:

```bash
curl -X POST http://127.0.0.1:9090/api/cases/CASE-20260217-6a82c1f38bed/feedback \
  -H "Content-Type: application/json" \
  -d '{
    "verdict": "true_positive",
    "reason": "Confirmed SSH brute force attack",
    "user_id": "analyst-1"
  }'
```

## What's Next?

1. **Configure OpenClaw** - Load the agent configurations into your OpenClaw instance
2. **Verify agent pipeline** - Update case status to `triaged` and check that the Correlation Agent is triggered via webhook
3. **Enable IP enrichment** - Set `ENRICHMENT_ENABLED=true` and `ABUSEIPDB_API_KEY` in `/etc/wazuh-autopilot/.env` for automatic threat intelligence enrichment
4. **Set up Slack** - See [SLACK_SOCKET_MODE.md](SLACK_SOCKET_MODE.md) for full integration
5. **Production mode** - See [TAILSCALE_MANDATORY.md](TAILSCALE_MANDATORY.md) for zero-trust networking
6. **Customize policies** - Review `policies/policy.yaml` for your environment (inline enforcement is active)
7. **Review playbooks** - Understand response workflows in `playbooks/`

## Troubleshooting

### Service won't start

Check logs:
```bash
sudo journalctl -u wazuh-autopilot -f
```

### MCP connection fails

1. Verify MCP_URL is correct and reachable
2. Check AUTOPILOT_MCP_AUTH token is valid
3. Test connectivity: `curl -v https://your-mcp-server:3000/health`

### Placeholder validation error

If you see "Policy contains placeholder values", edit `/etc/wazuh-autopilot/policies/policy.yaml` and replace all `<PLACEHOLDER>` values with real configuration.

See [TROUBLESHOOTING.md](TROUBLESHOOTING.md) for more help.
