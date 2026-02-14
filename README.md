<p align="center">
  <img src="https://img.shields.io/badge/Wazuh-0080FF?style=for-the-badge&logo=wazuh&logoColor=white" alt="Wazuh"/>
  <img src="https://img.shields.io/badge/OpenClaw-FF6B35?style=for-the-badge&logoColor=white" alt="OpenClaw"/>
  <img src="https://img.shields.io/badge/MCP-6B4FBB?style=for-the-badge&logoColor=white" alt="MCP"/>
</p>

<h1 align="center">Wazuh OpenClaw Autopilot</h1>

<p align="center">
  <strong>Autonomous SOC Layer for Wazuh using OpenClaw Agents with MCP</strong>
</p>

<p align="center">
  Auto-triage alerts • Correlate incidents • Generate response plans • Human-in-the-loop approval
</p>

<p align="center">
  <a href="https://github.com/gensecaihq/Wazuh-Openclaw-Autopilot/blob/main/LICENSE">
    <img src="https://img.shields.io/badge/License-MIT-blue.svg" alt="License: MIT">
  </a>
  <a href="https://github.com/gensecaihq/Wazuh-Openclaw-Autopilot/issues">
    <img src="https://img.shields.io/github/issues/gensecaihq/Wazuh-Openclaw-Autopilot" alt="Issues">
  </a>
  <a href="https://github.com/gensecaihq/Wazuh-Openclaw-Autopilot/stargazers">
    <img src="https://img.shields.io/github/stars/gensecaihq/Wazuh-Openclaw-Autopilot" alt="Stars">
  </a>
</p>

---

## Overview

**Wazuh OpenClaw Autopilot** adds an autonomous intelligence layer to your Wazuh SIEM. Using OpenClaw AI agents connected via the Model Context Protocol (MCP), it automatically triages alerts, correlates related incidents, and generates risk-assessed response plans—all with mandatory human approval before any action is taken.

### Key Capabilities

| Capability | Description |
|------------|-------------|
| **Autonomous Triage** | AI agents analyze incoming alerts, extract entities (IPs, users, hosts), and assign severity |
| **Incident Correlation** | Automatically link related alerts into unified cases with attack timelines |
| **Response Planning** | Generate risk-assessed response plans with recommended Wazuh Active Response actions |
| **Human-in-the-Loop** | Two-tier approval workflow ensures humans authorize every response action |
| **Evidence Packs** | Structured JSON evidence packages for compliance and forensics |
| **Prometheus Metrics** | Full observability with SOC KPIs (MTTD, MTTR, auto-triage rate) |
| **Slack Integration** | Real-time alerts and interactive approval buttons via Socket Mode |

---

## Architecture

```
                              WAZUH OPENCLAW AUTOPILOT
┌──────────────────────────────────────────────────────────────────────────────┐
│                                                                              │
│   ┌──────────────┐      ┌──────────────┐      ┌──────────────┐              │
│   │    Wazuh     │      │     MCP      │      │   OpenClaw   │              │
│   │   Manager    │─────▶│    Server    │◀────▶│   Gateway    │              │
│   │              │      │              │      │              │              │
│   └──────────────┘      └──────────────┘      └──────────────┘              │
│          │                     │                     │                       │
│      Alerts               Wazuh API             AI Agents                    │
│          │                                          │                        │
│          ▼                                          ▼                        │
│   ┌──────────────┐                          ┌──────────────┐                │
│   │   Runtime    │◀─────────────────────────│   7 SOC      │                │
│   │   Service    │                          │   Agents     │                │
│   │              │                          │              │                │
│   └──────────────┘                          └──────────────┘                │
│          │                                                                   │
│          ├── Cases & Evidence Packs                                          │
│          ├── Response Plans (human approval required)                        │
│          ├── Prometheus Metrics (/metrics)                                   │
│          └── Slack Notifications (Socket Mode)                               │
│                                                                              │
└──────────────────────────────────────────────────────────────────────────────┘
```

### Agent Pipeline

```
Alert Ingestion ──▶ Triage ──▶ Correlation ──▶ Investigation
                                                     │
                    ┌────────────────────────────────┘
                    ▼
              Response Planner ──▶ Policy Guard ──▶ Human Approval ──▶ Responder
                                                          │
                                                    [Approve] [Execute]
```

---

## Agents

| Agent | Function | Autonomy |
|-------|----------|----------|
| **Triage** | Analyze alerts, extract IOCs, create cases | Automatic |
| **Correlation** | Link related alerts, build attack timelines | Automatic |
| **Investigation** | Deep analysis, process trees, threat intel enrichment | Automatic |
| **Response Planner** | Generate risk-assessed response plans | Proposal only |
| **Policy Guard** | Validate actions against security policies | Advisory |
| **Responder** | Execute Wazuh Active Response commands | Human-gated |
| **Reporting** | Generate SOC metrics, KPIs, shift reports | Automatic |

---

## Human-in-the-Loop Approval

Every response action requires explicit human authorization through a two-tier workflow:

```
┌─────────────────┐      ┌─────────────────┐      ┌─────────────────┐
│    PROPOSED     │ ───▶ │    APPROVED     │ ───▶ │   EXECUTED      │
│                 │      │                 │      │                 │
│  AI generates   │      │  Human clicks   │      │  Human clicks   │
│  response plan  │      │  [Approve]      │      │  [Execute]      │
└─────────────────┘      └─────────────────┘      └─────────────────┘
                                │                        │
                                ▼                        ▼
                         Tier 1: Validate          Tier 2: Authorize
                         the plan is correct       actual execution
```

**AI agents cannot execute actions autonomously.** The responder capability is disabled by default and requires explicit enablement plus human approval for every action.

---

## Quick Start

### Prerequisites

- Wazuh Manager (installed and running)
- Node.js 18+
- Anthropic API key

### Installation

```bash
git clone https://github.com/gensecaihq/Wazuh-Openclaw-Autopilot.git
cd Wazuh-Openclaw-Autopilot
sudo ./install/install.sh
```

The installer will guide you through:
1. Tailscale setup (zero-trust networking)
2. MCP Server installation
3. OpenClaw Gateway configuration
4. Agent deployment
5. Slack integration (optional)

### Configuration

```bash
# Edit configuration
sudo nano /etc/wazuh-autopilot/.env

# Required
ANTHROPIC_API_KEY=sk-ant-...
WAZUH_API_URL=https://localhost:55000
WAZUH_API_USER=wazuh-wui
WAZUH_API_PASSWORD=...

# Optional: Slack
SLACK_APP_TOKEN=xapp-...
SLACK_BOT_TOKEN=xoxb-...
```

### Verify Installation

```bash
# Health check
curl http://localhost:9090/health

# Metrics
curl http://localhost:9090/metrics
```

---

## API Reference

### Cases

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/api/cases` | GET | List all cases |
| `/api/cases` | POST | Create case |
| `/api/cases/:id` | GET | Get case details |
| `/api/alerts` | POST | Ingest Wazuh alert |

### Response Plans

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/api/plans` | GET | List response plans |
| `/api/plans` | POST | Create response plan |
| `/api/plans/:id/approve` | POST | Tier 1: Approve plan |
| `/api/plans/:id/execute` | POST | Tier 2: Execute plan |
| `/api/plans/:id/reject` | POST | Reject plan |

### Observability

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/health` | GET | Service health |
| `/metrics` | GET | Prometheus metrics |
| `/api/responder/status` | GET | Responder capability status |

---

## Metrics

Prometheus metrics available at `/metrics`:

```prometheus
# Cases
autopilot_cases_created_total
autopilot_alerts_ingested_total

# Two-tier approval
autopilot_plans_created_total
autopilot_plans_approved_total
autopilot_plans_executed_total
autopilot_plans_rejected_total

# Performance
autopilot_triage_latency_seconds
autopilot_mcp_tool_call_latency_seconds

# Responder
autopilot_executions_success_total
autopilot_executions_failed_total
autopilot_responder_disabled_blocks_total
```

---

## Evidence Packs

Each case generates a structured evidence pack:

```json
{
  "schema_version": "1.0",
  "case_id": "CASE-20240115-abc123",
  "created_at": "2024-01-15T10:30:00Z",
  "severity": "high",
  "entities": [
    {"type": "ip", "value": "192.168.1.100", "role": "attacker"},
    {"type": "user", "value": "admin", "role": "target"}
  ],
  "timeline": [...],
  "mitre": [{"technique_id": "T1110", "tactic": "Credential Access"}],
  "plans": [...],
  "actions": [...]
}
```

---

## Security

### Network Isolation

| Component | Binding | Access |
|-----------|---------|--------|
| OpenClaw Gateway | `127.0.0.1:18789` | Localhost only |
| MCP Server | Tailscale IP | VPN only |
| Runtime Service | `127.0.0.1:9090` | Localhost only |

No services are exposed to the public internet.

### Access Control

- **Pairing mode**: Devices must be explicitly approved
- **Tailscale**: All inter-component traffic encrypted
- **Credentials**: Isolated storage with 600 permissions
- **Human approval**: Required for all response actions

---

## Slack Integration

Uses Socket Mode (outbound-only, no webhooks required):

```
┌─────────────────┐                    ┌─────────────────┐
│ Runtime Service │ ══ OUTBOUND ══════▶│  Slack API      │
│ (localhost)     │◀══ messages ═══════│  (WebSocket)    │
└─────────────────┘                    └─────────────────┘
```

Features:
- Real-time alert notifications
- Interactive approval buttons
- Slash commands (`/wazuh approve`, `/wazuh execute`)
- No inbound ports required

---

## Project Structure

```
├── install/
│   └── install.sh              # Security-hardened installer
├── openclaw/
│   ├── openclaw.json           # Gateway configuration
│   └── agents/                 # Agent system prompts
├── runtime/
│   └── autopilot-service/      # Node.js runtime
│       ├── index.js            # Main service
│       └── slack.js            # Slack integration
├── policies/
│   ├── policy.yaml             # Security policies
│   └── toolmap.yaml            # MCP tool mappings
└── docs/                       # Documentation
```

---

## Documentation

| Document | Description |
|----------|-------------|
| [QUICKSTART.md](docs/QUICKSTART.md) | Installation guide |
| [SLACK_SOCKET_MODE.md](docs/SLACK_SOCKET_MODE.md) | Slack setup |
| [RUNTIME_API.md](docs/RUNTIME_API.md) | API reference |
| [POLICY_AND_APPROVALS.md](docs/POLICY_AND_APPROVALS.md) | Policy configuration |
| [EVIDENCE_PACK_SCHEMA.md](docs/EVIDENCE_PACK_SCHEMA.md) | Evidence pack format |

---

## Contributing

```bash
cd runtime/autopilot-service
npm install
npm test
```

See [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines.

---

## License

MIT License - see [LICENSE](LICENSE)

---

<p align="center">
  <a href="https://github.com/gensecaihq/Wazuh-Openclaw-Autopilot/issues">Report Issue</a> •
  <a href="https://github.com/gensecaihq/Wazuh-Openclaw-Autopilot/issues">Request Feature</a>
</p>
