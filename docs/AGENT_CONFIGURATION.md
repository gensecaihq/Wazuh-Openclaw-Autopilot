# Agent Configuration Guide

This document describes how to configure and customize the OpenClaw agents for Wazuh Autopilot.

## Overview

Wazuh Autopilot includes 7 specialized agents, each handling a specific aspect of the SOC workflow:

| Agent | Role | Autonomy Level |
|-------|------|----------------|
| Triage | Alert analysis, entity extraction | Read-only (Full auto) |
| Correlation | Pattern detection, alert linking | Read-only (Full auto) |
| Investigation | Deep analysis, evidence gathering | Read-only (Full auto) |
| Response Planner | Action plan generation | Approval-gated |
| Policy Guard | Constitutional enforcement | Approval-gated |
| Responder | Action execution | Approval-gated (Disabled by default) |
| Reporting | Summary generation, metrics | Read-only (Full auto) |

---

## Agent File Structure

Each agent has a workspace directory containing OpenClaw standard files:

```
~/.openclaw/wazuh-autopilot/agents/
├── triage/
│   ├── AGENTS.md       # Operating instructions (domain knowledge, output formats)
│   ├── SOUL.md         # Shared SOC operating principles
│   ├── USER.md         # Organizational context (customize per deployment)
│   ├── IDENTITY.md     # Role, pipeline position, downstream consumers
│   ├── TOOLS.md        # Query patterns, field paths, API usage
│   ├── HEARTBEAT.md    # 10-min sweep checklist (cron-triggered agents)
│   └── MEMORY.md       # Accumulated learnings (grows during operation)
├── correlation/        # Same structure (+ HEARTBEAT.md)
├── investigation/      # Same structure (no HEARTBEAT.md)
├── response-planner/   # Same structure (no HEARTBEAT.md)
├── policy-guard/       # Same structure (no HEARTBEAT.md)
├── responder/          # Same structure (no HEARTBEAT.md)
└── reporting/          # Same structure (+ HEARTBEAT.md)
```

### File Roles

| File | Loaded | Purpose |
|------|--------|---------|
| `AGENTS.md` | Always | Main operating instructions — Wazuh rule IDs, entity extraction, severity maps, algorithms, output JSON formats |
| `SOUL.md` | Always | Shared SOC principles — evidence standards, blast radius minimization, false positive handling, auditability |
| `USER.md` | Always | Organizational context — industry, compliance, critical assets, noise sources, SOC shifts, escalation paths |
| `IDENTITY.md` | Always | Agent identity — role, what it does/doesn't do, pipeline position, what downstream consumers need |
| `TOOLS.md` | Always | Tool usage guidance — query patterns, field path differences (Linux/Windows/AWS), API endpoints, pitfalls |
| `HEARTBEAT.md` | Cron runs | Step-by-step checklist for scheduled executions (triage sweeps, correlation recycles, report generation) |
| `MEMORY.md` | Private | Persistent learnings — false positive patterns, confirmed attacks, tuning notes, efficiency optimizations |

### Customization

- **`USER.md`**: Edit `_shared/USER.md` before install (or per-agent after install) to set your organization's industry, compliance frameworks, critical asset patterns, known noise sources, and SOC team structure
- **`SOUL.md`**: Edit `_shared/SOUL.md` to adjust operating principles (evidence thresholds, blast radius preferences, speed vs completeness tradeoffs)
- **`AGENTS.md`**: Edit per-agent to modify domain-specific behavior (severity mappings, correlation thresholds, investigation playbooks, KPI targets)
- **`MEMORY.md`**: Seed with known false positive patterns or tuning notes; agents will add to this during operation

### Legacy Note

Previous versions used a single `SYSTEM_PROMPT.md` per agent. This has been replaced by the multi-file structure above, which follows OpenClaw's standard file conventions for improved agent efficiency and maintainability.

---

## Runtime Configuration (openclaw.json)

Agent runtime settings (model, tools, triggers, channels) are configured in `openclaw.json`. Each agent has an entry in the `agents.list` array:

```json
{
  "id": "wazuh-triage",
  "name": "Wazuh Triage Agent",
  "model": "anthropic/claude-sonnet-4-5",
  "tools": {
    "allow": ["read", "sessions_list", "sessions_history", "sessions_send"],
    "deny": ["write", "exec", "delete", "browser"]
  }
}
```

### Tool Permissions

Tool permissions are enforced by the OpenClaw gateway via `tools.allow` and `tools.deny` arrays in `openclaw.json`:

| Agent | Allowed | Denied |
|-------|---------|--------|
| Triage, Correlation, Investigation | `read`, `sessions_*` | `write`, `exec`, `delete`, `browser` |
| Response Planner | `read`, `write`, `sessions_*` | `exec`, `delete`, `browser` |
| Responder | `read`, `write`, `exec` (elevated) | `delete`, `browser` |

### Triggers

Agents are triggered via **heartbeats** (configured per-agent in `openclaw.json`) and **hooks** (webhook endpoints):

**Heartbeats** (periodic sweeps):

| Agent | Interval | Task |
|-------|----------|------|
| wazuh-triage | Every 10 min | Sweep untriaged alerts |
| wazuh-correlation | Every 5 min | Recorrelate active cases |
| All agents | Every 30 min (default) | Health check and maintenance |

**Cron jobs** (reports) can be added via CLI:

```bash
openclaw cron add --schedule "0 8 * * *" --agent wazuh-reporting --name "daily-digest"
openclaw cron add --schedule "0 9 * * 1" --agent wazuh-reporting --name "weekly-summary"
```

---

## Agent-Specific Behavior

Each agent's domain knowledge is defined in its `AGENTS.md` file. Here's what each agent's configuration covers:

### Triage Agent (`openclaw/agents/triage/AGENTS.md`)

- Wazuh rule categories and severity mapping (level 0-15 → informational through critical)
- Critical rule IDs (5710, 5712, 5720, 5763, 100002, 87105, 87106, 92000, 92100)
- Entity extraction fields for 7 entity types across Linux, Windows, AWS, and Syscheck
- MITRE ATT&CK inference patterns and confidence scoring
- Case creation output format

### Correlation Agent (`openclaw/agents/correlation/AGENTS.md`)

- 6 attack patterns (brute force, lateral movement, privilege escalation, data exfiltration, persistence, defense evasion) with indicators, thresholds, and MITRE mappings
- Entity relationship weights and clustering strategies (entity overlap 35%, temporal 25%, rule similarity 20%, attack chain 20%)
- Time windows (5m, 1h, 24h) and correlation score thresholds (0.5, 0.8, 0.95)
- Blast radius calculation across 5 dimensions with asset criticality multipliers

### Investigation Agent (`openclaw/agents/investigation/AGENTS.md`)

- 4 investigation playbooks (brute force, lateral movement, malware, data exfiltration)
- 6 pivot types with Wazuh queries, lookback windows, and aggregation patterns
- Enrichment sources (historical incidents with 0.95/day decay, baseline comparison, related cases)
- Findings classification (confirmed compromise, likely compromise, suspicious activity, reconnaissance)

### Response Planner Agent (`openclaw/agents/response-planner/AGENTS.md`)

- Two-tier approval workflow (Propose → Approve → Execute)
- Action catalog: block IP, isolate host, kill process, disable user, quarantine file
- Risk scoring with 5 weighted factors and risk-level thresholds
- Response playbooks for 5 attack types

### Policy Guard Agent (`openclaw/agents/policy-guard/AGENTS.md`)

- 13-step policy evaluation chain (first DENY wins)
- Asset criticality patterns and privileged user patterns
- Confidence thresholds by risk level (Low: 0.5, Medium: 0.7, High: 0.85, Critical: 0.95)
- 16 deny reason codes and dual approval requirements
- Token validation (HMAC-SHA256) and fail-secure defaults

### Responder Agent (`openclaw/agents/responder/AGENTS.md`)

- 5 action playbooks with Wazuh commands, pre-checks, verification queries, and rollback
- Protected entities (processes: wazuh-agent, init, systemd, lsass; networks: RFC 1918, loopback)
- Safeguards: action limits (10/plan, 50/hour, 200/day), circuit breaker (3 failures, 15-min reset)
- Responder capability toggle: `AUTOPILOT_RESPONDER_ENABLED` (default: `false`)

### Reporting Agent (`openclaw/agents/reporting/AGENTS.md`)

- 6 KPI time metrics (MTTD, MTTT, MTTI, MTTP, MTTR, MTTC) with target/warning/critical thresholds
- 6 report types: hourly snapshot, daily digest, shift handoff, weekly summary, monthly executive, rule effectiveness
- Trend analysis: moving average (7d), linear regression (30d), seasonal decomposition (90d), anomaly detection (Z-score 2.5)
- Recommendation categories: rule tuning, coverage improvement, efficiency, resource optimization

---

## Enabling/Disabling Agents

To disable an agent, remove it from the `agents.list` array in `openclaw.json`, or remove its heartbeat and hook mappings.

The responder capability is disabled by default. Enable it with:
```bash
export AUTOPILOT_RESPONDER_ENABLED=true
```

This does NOT enable autonomous execution — it only allows execution after two-tier human approval.

---

## Custom Agents

### 1. Create Agent Workspace

```bash
mkdir -p ~/.openclaw/wazuh-autopilot/agents/custom-agent/
```

### 2. Create Required Files

| File | Purpose |
|------|---------|
| `AGENTS.md` | Operating instructions and domain knowledge |
| `IDENTITY.md` | Role, pipeline position, what it does/doesn't do |
| `TOOLS.md` | Tool usage guidance, query patterns, API endpoints |
| `MEMORY.md` | Seed template for accumulated learnings |

### 3. Copy Shared Files

```bash
cp ~/.openclaw/wazuh-autopilot/agents/triage/SOUL.md ~/.openclaw/wazuh-autopilot/agents/custom-agent/
cp ~/.openclaw/wazuh-autopilot/agents/triage/USER.md ~/.openclaw/wazuh-autopilot/agents/custom-agent/
```

### 4. Register in openclaw.json

Add the agent to the `agents.list` array in `openclaw.json`.

### 5. Add Trigger

Add a webhook mapping in the `hooks.mappings` array of `openclaw.json`, or configure a heartbeat on the agent.

### 6. Restart OpenClaw

```bash
openclaw gateway restart
```

---

## Wazuh Expertise

Agents embed Wazuh-specific knowledge directly in their `AGENTS.md` files:

- **Rule categories**: syscheck, rootcheck, windows, authentication, sysmon, firewall, ids
- **Severity mapping**: levels 0-3 (informational), 4-6 (low), 7-9 (medium), 10-12 (high), 13-15 (critical)
- **Critical rule IDs**: 5712 (SSH brute force), 87105 (Windows multiple failures), 100002 (Suricata high severity), and more
- **Field paths**: Platform-specific (Linux `data.srcip`, Windows `data.win.eventdata.ipAddress`, AWS `data.aws.sourceIPAddress`)

To customize, edit the relevant `AGENTS.md` or `TOOLS.md` file directly.

---

## Environment Configuration

Environment-specific settings are managed via `.env`:

```bash
# /etc/wazuh-autopilot/.env

# Required: Wazuh connection
WAZUH_HOST=localhost
WAZUH_PORT=55000
WAZUH_USER=wazuh-wui
WAZUH_PASS=your-password

# Required: At least one LLM provider
ANTHROPIC_API_KEY=sk-ant-...

# Runtime settings
RUNTIME_PORT=9090
AUTOPILOT_RESPONDER_ENABLED=false

# Optional: Slack integration
SLACK_APP_TOKEN=xapp-...
SLACK_BOT_TOKEN=xoxb-...
```

---

## Validation

### Check Agent Files

```bash
# Verify all agent directories have required files
for agent in triage correlation investigation response-planner policy-guard responder reporting; do
  echo "--- $agent ---"
  ls ~/.openclaw/wazuh-autopilot/agents/$agent/
done
```

### Verify Runtime

```bash
# Health check
curl http://localhost:9090/health

# Prometheus metrics
curl http://localhost:9090/metrics
```

### Run Tests

```bash
cd runtime/autopilot-service
npm test
```

---

## Troubleshooting

### Agent Not Responding

1. Verify agent workspace files exist: `ls ~/.openclaw/wazuh-autopilot/agents/<agent>/`
2. Check that `AGENTS.md`, `IDENTITY.md`, `TOOLS.md`, and `MEMORY.md` are present
3. Check OpenClaw logs: `docker logs openclaw`
4. Verify MCP connectivity

### Tool Permission Errors

1. Check the agent's `tools.allow` and `tools.deny` arrays in `openclaw.json`
2. Verify the MCP server has the requested tool available

### Missing Shared Files

If `SOUL.md` or `USER.md` are missing from an agent workspace:
```bash
cp /path/to/openclaw/agents/_shared/SOUL.md ~/.openclaw/wazuh-autopilot/agents/<agent>/
cp /path/to/openclaw/agents/_shared/USER.md ~/.openclaw/wazuh-autopilot/agents/<agent>/
```

---

## Best Practices

1. **Customize USER.md first** — Set your organization's industry, compliance, critical assets, and noise sources before deployment
2. **Start with read-only agents** — Enable the responder only after testing the full pipeline
3. **Seed MEMORY.md** — Add known false positive patterns and tuning notes to reduce noise from day one
4. **Keep AGENTS.md focused** — Domain knowledge only; use TOOLS.md for tool usage guidance and IDENTITY.md for role boundaries
5. **Review SOUL.md** — Adjust operating principles to match your organization's risk tolerance
6. **Monitor metrics** — Use `/metrics` endpoint and reporting agent KPIs to track agent effectiveness
7. **Test in isolation** — Test agents individually before full deployment
