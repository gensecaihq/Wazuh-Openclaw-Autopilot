# OpenClaw Agent Configuration

This directory contains the OpenClaw-native configuration for the Wazuh Autopilot SOC agents.

## Human-in-the-Loop

**All response actions require human approval.** AI agents can analyze alerts and propose response plans, but:

1. **Response Planner** creates plans in `proposed` state
2. **Human** reviews and clicks **Approve** (Tier 1)
3. **Human** reviews and clicks **Execute** (Tier 2)
4. **Responder** executes the actions

AI agents cannot execute response actions autonomously.

## Files

```
openclaw/
├── openclaw.json                    # Main OpenClaw configuration
├── agents/
│   ├── triage/
│   │   └── SYSTEM_PROMPT.md        # Triage agent instructions
│   ├── correlation/
│   │   └── SYSTEM_PROMPT.md        # Correlation agent instructions
│   ├── investigation/
│   │   └── SYSTEM_PROMPT.md        # Investigation agent instructions
│   ├── response-planner/
│   │   └── SYSTEM_PROMPT.md        # Response planner instructions
│   ├── policy-guard/
│   │   └── SYSTEM_PROMPT.md        # Policy guard instructions
│   ├── responder/
│   │   └── SYSTEM_PROMPT.md        # Responder agent instructions
│   └── reporting/
│       └── SYSTEM_PROMPT.md        # Reporting agent instructions
└── README.md                        # This file
```

## Quick Start

### 1. Install OpenClaw

```bash
# Follow OpenClaw installation guide
# https://github.com/openclaw/openclaw
```

### 2. Configure Environment Variables

```bash
export OPENCLAW_TOKEN="your-gateway-token"
export ANTHROPIC_API_KEY="your-anthropic-key"
export OPENAI_API_KEY="your-openai-key"  # For embeddings
export MCP_URL="https://your-mcp-server:8080"
export AUTOPILOT_MCP_AUTH="your-mcp-token"
```

### 3. Copy Configuration

```bash
# Create OpenClaw directory
mkdir -p ~/.openclaw/wazuh-autopilot

# Copy main config
cp openclaw/openclaw.json ~/.openclaw/

# Copy agent instruction files
cp -r openclaw/agents ~/.openclaw/wazuh-autopilot/
```

### 4. Start OpenClaw Gateway

```bash
openclaw gateway start
```

### 5. Verify Agents

```bash
openclaw doctor --fix
```

## Agent Summary

| Agent ID | Purpose | What It Can Do |
|----------|---------|----------------|
| `wazuh-triage` | Alert analysis, case creation | Read alerts, create cases (automatic) |
| `wazuh-correlation` | Pattern detection, timeline | Read data, correlate alerts (automatic) |
| `wazuh-investigation` | Deep analysis, evidence | Read data, gather evidence (automatic) |
| `wazuh-response-planner` | Generate response plans | Create plan proposals only |
| `wazuh-policy-guard` | Validate actions | Check policies only |
| `wazuh-responder` | Execute actions | Execute ONLY after human approval |
| `wazuh-reporting` | Metrics, reports | Read data, generate reports (automatic) |

**Note:** "Automatic" agents can only read data. They cannot execute response actions.

## Two-Tier Approval Workflow

```
┌──────────────────┐    ┌──────────────────┐    ┌──────────────────┐
│  Response        │    │  Human clicks    │    │  Human clicks    │
│  Planner creates │───▶│  [Approve]       │───▶│  [Execute]       │
│  plan            │    │  (Tier 1)        │    │  (Tier 2)        │
└──────────────────┘    └──────────────────┘    └──────────────────┘
                                                         │
                                                         ▼
                                                ┌──────────────────┐
                                                │  Responder       │
                                                │  executes        │
                                                │  actions         │
                                                └──────────────────┘
```

## Webhooks

| Path | Target Agent | Trigger |
|------|--------------|---------|
| `/webhook/wazuh-alert` | wazuh-triage | Alert ingestion |
| `/webhook/case-created` | wazuh-correlation | Case correlation |
| `/webhook/investigation-request` | wazuh-investigation | Deep analysis |
| `/webhook/plan-request` | wazuh-response-planner | Plan generation |
| `/webhook/policy-check` | wazuh-policy-guard | Policy validation |
| `/webhook/execute-action` | wazuh-responder | Human-triggered execution |

### Triggering via Webhook

```bash
# Trigger triage agent with alert
curl -X POST http://localhost:18789/webhook/wazuh-alert \
  -H "Authorization: Bearer ${OPENCLAW_TOKEN}" \
  -H "Content-Type: application/json" \
  -d '{
    "alert_id": "12345",
    "rule": {"id": "5712", "level": 10, "description": "SSH brute force"},
    "agent": {"id": "001", "name": "server-01"},
    "data": {"srcip": "192.168.1.100"}
  }'
```

## Cron Jobs

| Schedule | Agent | Task |
|----------|-------|------|
| Every 10 min | wazuh-triage | Sweep untriaged alerts |
| Every 5 min | wazuh-correlation | Recorrelate active cases |
| Hourly | wazuh-reporting | Operational snapshot |
| 8 AM daily | wazuh-reporting | Daily digest |
| Shift changes | wazuh-reporting | Shift handoff report |
| Monday 9 AM | wazuh-reporting | Weekly summary |

## Integration with Runtime Service

The Runtime Service provides the two-tier approval API:

```bash
# 1. Response Planner creates a plan (via API)
POST /api/plans

# 2. Human approves (Tier 1)
POST /api/plans/{plan_id}/approve

# 3. Human executes (Tier 2)
POST /api/plans/{plan_id}/execute
```

## Security Configuration

### Network Isolation (Never Exposed)

| Component | Binding | Note |
|-----------|---------|------|
| OpenClaw Gateway | `127.0.0.1:18789` | Localhost only, NEVER 0.0.0.0 |
| MCP Server | `<tailscale-ip>:8080` | Tailscale network only |

**The gateway is NEVER exposed to the public internet.** All remote access goes through Tailscale VPN.

### Access Control

| Feature | Setting | Description |
|---------|---------|-------------|
| DM Policy | `allowlist` | No public messages accepted |
| Pairing Mode | `enabled` | Devices must pair before connecting |
| Mention Gating | `enabled` | Agents respond only when mentioned |

### Directory Permissions

```bash
~/.openclaw/                    # mode 700 (owner only)
~/.openclaw/openclaw.json       # mode 600 (owner read/write)
~/.openclaw/wazuh-autopilot/    # mode 700 (owner only)
```

### Tool Restrictions

All agents use strict tool allowlists:

| Agent | Allowed | Denied |
|-------|---------|--------|
| Triage, Correlation, Investigation | read, sessions_* | write, exec, delete, browser |
| Response Planner | read, write, sessions_* | exec, delete, browser |
| Responder | read, write, exec (elevated) | delete, browser |

### Human-in-the-Loop

1. **Human Approval Required**: All response actions require two human approvals
2. **No Autonomous Execution**: AI agents cannot bypass the approval workflow
3. **Elevated Actions**: Responder can only execute via Slack approval
4. **Sandbox Mode**: All agents run in sandboxed environments

## Customization

### Modifying Agent Behavior

Edit the `SYSTEM_PROMPT.md` files in each agent's directory to customize:
- Entity extraction rules
- Severity mappings
- Correlation patterns
- Investigation playbooks
- Risk assessment factors

### Adding Custom Agents

1. Add agent definition to `openclaw.json` agents.list
2. Create `SYSTEM_PROMPT.md` with instructions
3. Add webhook or cron trigger
4. Restart OpenClaw gateway

## Troubleshooting

### Agent Not Responding

```bash
# Check gateway logs
openclaw gateway logs

# Verify agent configuration
openclaw doctor --fix
```

### Webhook Failures

```bash
# Test webhook manually
curl -v http://localhost:18789/webhook/wazuh-alert \
  -H "Authorization: Bearer ${OPENCLAW_TOKEN}"
```

### Tool Permission Errors

Check the agent's `tools.allow` and `tools.deny` arrays in `openclaw.json`.
