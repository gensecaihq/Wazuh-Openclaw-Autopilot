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
├── openclaw.json                    # Main OpenClaw configuration (multi-provider)
├── openclaw-airgapped.json          # Air-gapped config (Ollama only, no cloud APIs)
├── agents/
│   ├── _shared/                     # Shared files (copied into each agent at install)
│   │   ├── SOUL.md                  # SOC operating principles
│   │   └── USER.md                  # Organizational context (customize per deployment)
│   ├── triage/
│   │   ├── AGENTS.md                # Operating instructions
│   │   ├── IDENTITY.md              # Role, pipeline position, consumers
│   │   ├── TOOLS.md                 # Wazuh query patterns, field paths
│   │   ├── HEARTBEAT.md             # 10-min untriaged sweep checklist
│   │   └── MEMORY.md                # Accumulated learnings (grows during operation)
│   ├── correlation/
│   │   ├── AGENTS.md                # Operating instructions
│   │   ├── IDENTITY.md              # Role, pipeline position, consumers
│   │   ├── TOOLS.md                 # Correlation queries, entity matching
│   │   ├── HEARTBEAT.md             # 5-min recorrelation checklist
│   │   └── MEMORY.md                # Accumulated learnings
│   ├── investigation/
│   │   ├── AGENTS.md                # Operating instructions
│   │   ├── IDENTITY.md              # Role, pipeline position, consumers
│   │   ├── TOOLS.md                 # Pivot queries, enrichment patterns
│   │   └── MEMORY.md                # Accumulated learnings
│   ├── response-planner/
│   │   ├── AGENTS.md                # Operating instructions
│   │   ├── IDENTITY.md              # Role, pipeline position, consumers
│   │   ├── TOOLS.md                 # Plan API, risk scoring
│   │   └── MEMORY.md                # Accumulated learnings
│   ├── policy-guard/
│   │   ├── AGENTS.md                # Operating instructions
│   │   ├── IDENTITY.md              # Role, pipeline position, consumers
│   │   ├── TOOLS.md                 # Token validation, approval checks
│   │   └── MEMORY.md                # Accumulated learnings
│   ├── responder/
│   │   ├── AGENTS.md                # Operating instructions
│   │   ├── IDENTITY.md              # Role, pipeline position, consumers
│   │   ├── TOOLS.md                 # Execution API, verification queries
│   │   └── MEMORY.md                # Accumulated learnings
│   └── reporting/
│       ├── AGENTS.md                # Operating instructions
│       ├── IDENTITY.md              # Role, pipeline position, consumers
│       ├── TOOLS.md                 # Prometheus, MCP aggregation, Slack blocks
│       ├── HEARTBEAT.md             # Report schedule checklist
│       └── MEMORY.md                # Accumulated learnings
└── README.md                        # This file
```

### OpenClaw Standard File Roles

| File | Purpose | Loaded |
|------|---------|--------|
| `AGENTS.md` | Main operating instructions, domain knowledge, output formats | Always |
| `SOUL.md` | Shared SOC principles (evidence over assumptions, minimize blast radius, etc.) | Always |
| `USER.md` | Organizational context (industry, compliance, critical assets, noise sources) | Always |
| `IDENTITY.md` | Agent role, pipeline position, what it does/doesn't do, downstream consumers | Always |
| `TOOLS.md` | Practical tool usage guidance (query patterns, field paths, API endpoints) | Always |
| `HEARTBEAT.md` | Cron-triggered run checklists (triage sweep, correlation recycle, report schedule) | Heartbeat runs |
| `MEMORY.md` | Accumulated learnings (FP patterns, attack signatures, tuning notes) | Private sessions |

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
export MCP_URL="https://your-mcp-server:3000"
export AUTOPILOT_MCP_AUTH="your-mcp-token"

# Optional: Additional LLM providers
export GROQ_API_KEY="your-groq-key"       # Fast inference
export MISTRAL_API_KEY="your-mistral-key"
export XAI_API_KEY="your-xai-key"         # Grok
export GOOGLE_API_KEY="your-google-key"   # Gemini
```

## Supported LLM Providers

OpenClaw supports multiple LLM providers. Configure in `openclaw.json`:

| Provider | Models | Use Case | API Key |
|----------|--------|----------|---------|
| [Anthropic](https://console.anthropic.com/) | `claude-opus-4-5`, `claude-sonnet-4-5`, `claude-haiku-4-5` | **Recommended** for SOC tasks | `ANTHROPIC_API_KEY` |
| [OpenAI](https://platform.openai.com/) | `gpt-4o`, `gpt-4.5-preview`, `o3-mini` | General purpose, embeddings | `OPENAI_API_KEY` |
| [Groq](https://console.groq.com/) | `llama-3.3-70b-versatile`, `mixtral-8x7b-32768` | **Ultra-fast** inference | `GROQ_API_KEY` |
| [Google](https://aistudio.google.com/) | `gemini-2.0-flash`, `gemini-2.0-pro` | Multimodal | `GOOGLE_API_KEY` |
| [Mistral](https://console.mistral.ai/) | `mistral-large-latest`, `codestral-latest` | European provider | `MISTRAL_API_KEY` |
| [xAI](https://console.x.ai/) | `grok-2`, `grok-3` | Real-time knowledge | `XAI_API_KEY` |
| [OpenRouter](https://openrouter.ai/) | 300+ models | Multi-provider access | `OPENROUTER_API_KEY` |
| [Ollama](https://ollama.ai/) | `llama3.3`, `mistral`, `codellama` | **Local/free** inference | N/A |
| [Together](https://together.xyz/) | Various open-source | Open-source hosting | `TOGETHER_API_KEY` |
| [Cerebras](https://cerebras.ai/) | Cerebras models | Ultra-fast inference | `CEREBRAS_API_KEY` |

### Model Configuration

```json
// In openclaw.json - model format: "provider/model-name"
"model": {
  "primary": "anthropic/claude-sonnet-4-5",
  "fallback": "openai/gpt-4o",
  "fast": "groq/llama-3.3-70b-versatile"
}
```

### Cost Optimization

| Task Type | Recommended Model | Reason |
|-----------|-------------------|--------|
| Complex investigation | `anthropic/claude-sonnet-4-5` | Best reasoning |
| Simple triage | `groq/llama-3.3-70b-versatile` | Fast & cheap |
| Heartbeats/checks | `anthropic/claude-haiku-4-5` | Low cost |
| Local/air-gapped | `ollama/llama3.3` | No API calls |
| Fallback | `openai/gpt-4o` | High availability |

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
| MCP Server | `<tailscale-ip>:3000` | Tailscale network only |

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

### Organizational Context

Edit `agents/_shared/USER.md` to configure your deployment:
- Industry and compliance frameworks
- Critical asset hostname patterns and IP ranges
- Known noise sources (scanners, service accounts, scheduled jobs)
- SOC team shifts and escalation paths
- VPN ranges and change freeze windows

### SOC Operating Principles

Edit `agents/_shared/SOUL.md` to adjust shared agent behavior:
- Evidence thresholds and confidence calibration
- Blast radius minimization preferences
- Speed vs completeness tradeoffs
- False positive handling philosophy

### Agent-Specific Behavior

Edit `AGENTS.md` in each agent's directory to customize:
- Entity extraction rules and field paths
- Severity mappings and Wazuh rule ID handling
- Correlation patterns and thresholds
- Investigation playbooks and pivot strategies
- Risk assessment factors and scoring
- KPIs and report formats

### Accumulated Learnings

`MEMORY.md` in each agent's directory grows during operation. Agents record:
- False positive patterns discovered during triage
- Confirmed attack signatures
- Threshold tuning notes
- Operational efficiency improvements

### Adding Custom Agents

1. Add agent definition to `openclaw.json` agents.list
2. Create `AGENTS.md` (operating instructions), `IDENTITY.md` (role), `TOOLS.md` (tool usage), `MEMORY.md` (seed template)
3. Copy `_shared/SOUL.md` and `_shared/USER.md` into the agent directory
4. Add webhook or cron trigger
5. Restart OpenClaw gateway

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
