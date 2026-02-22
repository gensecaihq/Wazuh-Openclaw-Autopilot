<p align="center">
  <a href="https://wazuh.com"><img src="https://img.shields.io/badge/Wazuh-0080FF?style=for-the-badge&logo=wazuh&logoColor=white" alt="Wazuh"/></a>
  <a href="https://openclaw.ai"><img src="https://img.shields.io/badge/OpenClaw-FF6B35?style=for-the-badge&logoColor=white" alt="OpenClaw"/></a>
  <a href="https://modelcontextprotocol.io"><img src="https://img.shields.io/badge/MCP-6B4FBB?style=for-the-badge&logoColor=white" alt="MCP"/></a>
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

## Built With

<table>
<tr>
<td align="center" width="33%">
<a href="https://openclaw.ai">
<img src="https://img.shields.io/badge/OpenClaw-FF6B35?style=flat-square&logoColor=white" alt="OpenClaw" height="28"/>
</a>
<br/>
<sub><b>AI Agent Framework</b></sub>
<br/>
<sub><a href="https://github.com/openclaw/openclaw">GitHub</a> · <a href="https://openclaw.ai">Website</a></sub>
</td>
<td align="center" width="33%">
<a href="https://github.com/gensecaihq/Wazuh-MCP-Server">
<img src="https://img.shields.io/badge/Wazuh_MCP_Server-6B4FBB?style=flat-square&logoColor=white" alt="Wazuh MCP Server" height="28"/>
</a>
<br/>
<sub><b>Wazuh API Bridge</b></sub>
<br/>
<sub><a href="https://github.com/gensecaihq/Wazuh-MCP-Server">GitHub</a></sub>
</td>
<td align="center" width="33%">
<a href="https://wazuh.com">
<img src="https://img.shields.io/badge/Wazuh-0080FF?style=flat-square&logo=wazuh&logoColor=white" alt="Wazuh" height="28"/>
</a>
<br/>
<sub><b>SIEM & XDR Platform</b></sub>
<br/>
<sub><a href="https://wazuh.com">Website</a></sub>
</td>
</tr>
</table>

---

## Overview

**Wazuh OpenClaw Autopilot** adds an autonomous intelligence layer to your Wazuh SIEM. Using [OpenClaw](https://openclaw.ai) AI agents connected via the [Model Context Protocol (MCP)](https://modelcontextprotocol.io), it automatically triages alerts, correlates related incidents, and generates risk-assessed response plans—all with mandatory human approval before any action is taken.

### Key Capabilities

| Capability | Description |
|------------|-------------|
| **Autonomous Triage** | AI agents analyze incoming alerts, extract entities (IPs, users, hosts), and assign severity |
| **Alert Grouping** | Entity-based correlation groups related alerts (shared IPs, users) into unified cases |
| **IP Enrichment** | Automatic AbuseIPDB lookups on public IPs with TTL caching |
| **Incident Correlation** | Automatically link related alerts into unified cases with attack timelines |
| **Response Planning** | Generate risk-assessed response plans with recommended Wazuh Active Response actions |
| **Policy Enforcement** | Inline enforcement of action allowlists, approver authorization, confidence thresholds, and evidence requirements |
| **Human-in-the-Loop** | Two-tier approval workflow ensures humans authorize every response action |
| **False Positive Feedback** | Analysts submit verdicts (true/false positive) that refine future alert grouping |
| **Webhook Orchestration** | Status-driven agent handoffs via fire-and-forget webhook dispatch to OpenClaw Gateway |
| **MCP JSON-RPC Protocol** | Standards-compliant MCP communication with JWT auth exchange and auto-retry |
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
│   │   Manager    │◀─────│    Server    │      │   Gateway    │              │
│   │   :55000     │      │   :3000      │      │   :18789     │              │
│   └──────────────┘      └──────────────┘      └──────────────┘              │
│                                ▲                     ▲     │                 │
│                           MCP calls             Webhooks   │                 │
│                                │                     │     ▼                 │
│                          ┌─────┴────────┐      ┌─────┴──────────┐           │
│                          │   Runtime    │      │   7 SOC Agents  │           │
│                          │   Service    │◀─────│   (OpenClaw)    │           │
│                          │   :9090      │      │                 │           │
│                          └──────────────┘      └─────────────────┘           │
│                                │                  web.fetch ▲                │
│                                │                            │                │
│    ┌───────────────────────────┤                            │                │
│    │           │               │              webhook dispatch                │
│    ▼           ▼               ▼                                             │
│  Cases     Response      Prometheus        Slack                             │
│  Evidence  Plans         Metrics           Notifications                     │
│  Packs     (policy-      (/metrics)        (Socket Mode)                    │
│            enforced)                                                         │
│                                                                              │
└──────────────────────────────────────────────────────────────────────────────┘

Data Flow:
  Agents ──web.fetch──▶ Runtime ──callMcpTool──▶ MCP Server ──▶ Wazuh API
  Runtime ──webhook──▶ OpenClaw Gateway ──▶ Next Agent
```

### Agent Pipeline

Agents are orchestrated via **webhook dispatch** — the runtime automatically triggers the next agent when a case changes status:

```
Alert Ingestion ──▶ Triage ──▶ Correlation ──▶ Investigation
     │               (auto)       (auto)          (auto)
     │               status:      status:         status:
     │               triaged      correlated      investigated
     │                                                │
     │              ┌─────────────────────────────────┘
     │              ▼
     │        Response Planner ──▶ Policy Enforcement ──▶ Human Approval ──▶ Responder
     │                                  (inline)              │
     │                             action allowlist     [Approve] [Execute]
     │                             approver auth        evidence check
     │                             evidence check
     ▼
  Webhook ──▶ OpenClaw Gateway ──▶ Agent
```

---

## Agents

| Agent | Function | Autonomy |
|-------|----------|----------|
| **Triage** | Analyze alerts, extract IOCs, create cases | Automatic (webhook-triggered) |
| **Correlation** | Link related alerts, build attack timelines | Automatic (webhook-triggered) |
| **Investigation** | Deep analysis, process trees, threat intel enrichment | Automatic (webhook-triggered) |
| **Response Planner** | Generate risk-assessed response plans | Automatic (webhook-triggered) |
| **Policy Guard** | Supplementary LLM analysis (inline enforcement is primary) | Advisory (webhook-triggered) |
| **Responder** | Execute Wazuh Active Response commands | Human-gated |
| **Reporting** | Generate SOC metrics, KPIs, shift reports | Automatic (heartbeat) |

---

## Supported LLM Providers

OpenClaw is model-agnostic and supports 10+ LLM providers. Configure your preferred provider in `openclaw/openclaw.json`:

| Provider | Models | Best For | API Key Env |
|----------|--------|----------|-------------|
| [Anthropic](https://console.anthropic.com/) | `claude-opus-4-5`, `claude-sonnet-4-5`, `claude-haiku-4-5` | **Recommended** for SOC reasoning | `ANTHROPIC_API_KEY` |
| [OpenAI](https://platform.openai.com/) | `gpt-4o`, `gpt-4.5-preview`, `o3-mini` | General purpose, embeddings | `OPENAI_API_KEY` |
| [Groq](https://console.groq.com/) | `llama-3.3-70b-versatile`, `mixtral-8x7b-32768` | **Ultra-fast** inference | `GROQ_API_KEY` |
| [Google](https://aistudio.google.com/) | `gemini-2.0-flash`, `gemini-2.0-pro` | Multimodal capabilities | `GOOGLE_API_KEY` |
| [Mistral](https://console.mistral.ai/) | `mistral-large-latest`, `codestral-latest` | European provider | `MISTRAL_API_KEY` |
| [xAI](https://console.x.ai/) | `grok-2`, `grok-3` | Real-time knowledge | `XAI_API_KEY` |
| [OpenRouter](https://openrouter.ai/) | 300+ models | Multi-provider gateway | `OPENROUTER_API_KEY` |
| [Ollama](https://ollama.ai/) | `llama3.3`, `mistral`, `codellama` | **Local/free** inference | N/A |
| [Together](https://together.xyz/) | Various open-source | Open-source hosting | `TOGETHER_API_KEY` |
| [Cerebras](https://cerebras.ai/) | Cerebras models | Ultra-fast inference | `CEREBRAS_API_KEY` |

### Model Configuration

Model format is `"provider/model-name"`. Example `openclaw.json` snippet:

```json
{
  "model": {
    "primary": "anthropic/claude-sonnet-4-5",
    "fallback": "openai/gpt-4o",
    "fast": "groq/llama-3.3-70b-versatile"
  }
}
```

### Cost Optimization

| Task Type | Recommended Model | Reason |
|-----------|-------------------|--------|
| Complex investigation | `anthropic/claude-sonnet-4-5` | Best reasoning |
| High-volume triage | `groq/llama-3.3-70b-versatile` | Fast & cost-effective |
| Heartbeats/checks | `anthropic/claude-haiku-4-5` | Low cost |
| Air-gapped deployment | `ollama/llama3.3` | No external API calls |

---

## Human-in-the-Loop Approval

Every response action requires explicit human authorization through a two-tier workflow with inline policy enforcement:

```
┌─────────────────┐      ┌─────────────────┐      ┌─────────────────┐
│    PROPOSED     │ ───▶ │    APPROVED     │ ───▶ │   EXECUTED      │
│                 │      │                 │      │                 │
│  AI generates   │      │  Human clicks   │      │  Human clicks   │
│  response plan  │      │  [Approve]      │      │  [Execute]      │
└─────────────────┘      └─────────────────┘      └─────────────────┘
        │                        │                        │
        ▼                        ▼                        ▼
  Policy Check:            Policy Check:            Policy Check:
  action allowlist         approver authorized      evidence sufficient
  confidence threshold     risk level permitted     min items met
```

**AI agents cannot execute actions autonomously.** The responder capability is disabled by default and requires explicit enablement plus human approval for every action. Policy enforcement is applied inline at each step — fail-closed in production mode, fail-open in bootstrap mode.

---

## Compatibility

### Wazuh Version Support

Tested via [Wazuh MCP Server](https://github.com/gensecaihq/Wazuh-MCP-Server) v4.0.6:

| Wazuh Version | Support Level | Notes |
|---------------|-------------|-------|
| **4.14.x** | Fully Supported | Recommended. All 29 MCP tools work. |
| 4.10.x – 4.13.x | Fully Supported | All features available |
| 4.8.x – 4.9.x | Fully Supported | Minimum for vulnerability tools |
| 4.0.0 – 4.7.x | Limited | 3 vulnerability tools unavailable (require Wazuh Indexer) |

### Platform Support

| Platform | Status |
|----------|--------|
| Ubuntu 22.04 / 24.04 | Tested |
| Debian 11 / 12 | Tested |
| RHEL / Rocky / AlmaLinux 8/9 | Supported |
| Air-gapped (Ollama) | Supported — see [Air-Gapped Deployment Guide](docs/AIR_GAPPED_DEPLOYMENT.md) |

---

## Quick Start

### Prerequisites

| Requirement | Description |
|-------------|-------------|
| [Wazuh Manager](https://wazuh.com) | SIEM platform (installed and running, 4.8.0+) |
| [Wazuh MCP Server](https://github.com/gensecaihq/Wazuh-MCP-Server) | MCP bridge for Wazuh API access |
| [OpenClaw](https://github.com/openclaw/openclaw) | AI agent framework ([docs](https://openclaw.ai)) |
| Node.js 18+ | Runtime for autopilot service |
| LLM API Key | Claude, GPT, Groq, Mistral, or [Ollama](https://ollama.com) (local/free) |

### Installation

```bash
git clone https://github.com/gensecaihq/Wazuh-Openclaw-Autopilot.git
cd Wazuh-Openclaw-Autopilot
sudo ./install/install.sh
```

For air-gapped or bootstrap environments (no Tailscale):

```bash
sudo ./install/install.sh --skip-tailscale
```

The installer will guide you through:
1. Tailscale setup (zero-trust networking — skippable with `--skip-tailscale`)
2. MCP Server installation
3. OpenClaw Gateway configuration
4. Agent deployment
5. Slack integration (optional)

### Configuration

```bash
# Edit configuration
sudo nano /etc/wazuh-autopilot/.env

# Required: Wazuh connection
WAZUH_HOST=localhost
WAZUH_PORT=55000
WAZUH_USER=wazuh-wui
WAZUH_PASS=your-password

# Required: At least one LLM provider
ANTHROPIC_API_KEY=sk-ant-...           # Claude (recommended)
OPENAI_API_KEY=sk-...                  # GPT-4o (also used for embeddings)

# Optional: Additional providers for fallback/cost optimization
GROQ_API_KEY=gsk-...                   # Fast inference
MISTRAL_API_KEY=...                    # European provider
XAI_API_KEY=...                        # Grok
GOOGLE_API_KEY=...                     # Gemini

# Optional: Slack integration
SLACK_APP_TOKEN=xapp-...
SLACK_BOT_TOKEN=xoxb-...
```

### Docker Deployment

```bash
# Using Docker Compose
docker-compose up -d

# Or build manually
cd runtime/autopilot-service
docker build -t wazuh-autopilot .
docker run -d -p 127.0.0.1:9090:9090 --env-file .env wazuh-autopilot
```

### Verify Installation

```bash
# Full-stack health check
./scripts/health-check.sh

# Or check individual endpoints (default port 9090, configurable via RUNTIME_PORT)
curl http://localhost:9090/health
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
| `/api/cases/:id` | PUT | Update case |
| `/api/alerts` | POST | Ingest Wazuh alert (auto-triage, enrich, group) |
| `/api/cases/:id/feedback` | POST | Submit analyst verdict (true/false positive) |

### Response Plans

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/api/plans` | GET | List response plans (filter: `?state=`, `?case_id=`) |
| `/api/plans` | POST | Create response plan |
| `/api/plans/:id` | GET | Get plan details |
| `/api/plans/:id/approve` | POST | Tier 1: Approve plan |
| `/api/plans/:id/execute` | POST | Tier 2: Execute plan |
| `/api/plans/:id/reject` | POST | Reject plan |

### Observability

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/health` | GET | Service health |
| `/ready` | GET | Kubernetes readiness probe |
| `/version` | GET | Service version info |
| `/metrics` | GET | Prometheus metrics |
| `/api/responder/status` | GET | Responder capability status |

---

## Metrics

Prometheus metrics available at `/metrics`:

```prometheus
# Cases
autopilot_cases_created_total
autopilot_cases_updated_total
autopilot_alerts_ingested_total

# Two-tier approval
autopilot_plans_created_total
autopilot_plans_approved_total
autopilot_plans_executed_total
autopilot_plans_rejected_total
autopilot_plans_expired_total

# Performance
autopilot_triage_latency_seconds
autopilot_mcp_tool_call_latency_seconds

# Responder
autopilot_executions_success_total
autopilot_executions_failed_total
autopilot_responder_disabled_blocks_total

# Webhook Dispatch
autopilot_webhook_dispatches_total
autopilot_webhook_dispatch_failures_total

# IP Enrichment
autopilot_enrichment_requests_total
autopilot_enrichment_cache_hits_total
autopilot_enrichment_errors_total

# Feedback
autopilot_false_positives_total
autopilot_feedback_submitted_total{verdict="..."}

# Policy
autopilot_policy_denies_total{reason="..."}
autopilot_errors_total{component="..."}
```

---

## Evidence Packs

Each case generates a structured evidence pack:

```json
{
  "schema_version": "1.0",
  "case_id": "CASE-20260217-abc123",
  "created_at": "2026-02-17T10:30:00Z",
  "severity": "high",
  "entities": [
    {"type": "ip", "value": "192.168.1.100", "role": "attacker",
     "enrichment": {"source": "abuseipdb", "abuse_confidence_score": 87, "country_code": "CN"}},
    {"type": "user", "value": "admin", "role": "target"}
  ],
  "feedback": [
    {"verdict": "true_positive", "reason": "Confirmed attack", "user_id": "analyst-1"}
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
- Slash commands (`/wazuh status`, `/wazuh approve`, `/wazuh execute`)
- No inbound ports required

---

## Project Structure

```
├── .github/workflows/          # CI/CD pipeline
├── docker-compose.yml          # Container orchestration
├── install/
│   ├── install.sh              # Security-hardened installer
│   └── env.template            # Environment template (port config)
├── scripts/
│   └── health-check.sh         # Full-stack health check
├── openclaw/
│   ├── openclaw.json           # Gateway & model configuration (multi-provider)
│   ├── openclaw-airgapped.json # Air-gapped config (Ollama only)
│   └── agents/                 # 7 SOC agents + _shared/ (AGENTS.md, IDENTITY.md, TOOLS.md, HEARTBEAT.md, MEMORY.md)
├── runtime/autopilot-service/
│   ├── Dockerfile              # Production container
│   ├── index.js                # Main service (3500+ LOC)
│   ├── slack.js                # Slack Socket Mode integration
│   └── *.test.js               # Test suite (228 tests)
├── policies/
│   ├── policy.yaml             # Security policies & approvers
│   └── toolmap.yaml            # MCP tool mappings
├── playbooks/                  # Incident response playbooks (7 playbooks)
└── docs/                       # Documentation
```

---

## Deployment Options

| Method | Use Case | Command |
|--------|----------|---------|
| **Docker Compose** | Production | `docker-compose up -d` |
| **Docker** | Single container | `docker run -d wazuh-autopilot` |
| **Systemd** | Native Linux | `sudo ./install/install.sh` |
| **Manual** | Development | `cd runtime/autopilot-service && npm start` |

---

## Documentation

| Document | Description |
|----------|-------------|
| [QUICKSTART.md](docs/QUICKSTART.md) | Installation guide |
| [RUNTIME_API.md](docs/RUNTIME_API.md) | REST API reference |
| [POLICY_AND_APPROVALS.md](docs/POLICY_AND_APPROVALS.md) | Policy engine and approval workflow |
| [SLACK_SOCKET_MODE.md](docs/SLACK_SOCKET_MODE.md) | Slack Socket Mode setup |
| [EVIDENCE_PACK_SCHEMA.md](docs/EVIDENCE_PACK_SCHEMA.md) | Evidence pack JSON format |
| [AGENT_CONFIGURATION.md](docs/AGENT_CONFIGURATION.md) | Agent file structure and customization |
| [AIR_GAPPED_DEPLOYMENT.md](docs/AIR_GAPPED_DEPLOYMENT.md) | Air-gapped deployment with Ollama |
| [MCP_INTEGRATION.md](docs/MCP_INTEGRATION.md) | MCP server integration |
| [CLI_REFERENCE.md](docs/CLI_REFERENCE.md) | Installer and CLI commands |
| [OBSERVABILITY_EXPORT.md](docs/OBSERVABILITY_EXPORT.md) | Prometheus metrics and logging |
| [SCENARIOS.md](docs/SCENARIOS.md) | Deployment scenarios |
| [TAILSCALE_MANDATORY.md](docs/TAILSCALE_MANDATORY.md) | Tailscale zero-trust networking |
| [TROUBLESHOOTING.md](docs/TROUBLESHOOTING.md) | Troubleshooting guide |
| [CHANGELOG.md](CHANGELOG.md) | Version history |

---

## Contributing

```bash
cd runtime/autopilot-service
npm install
npm test

# Full-stack health check
./scripts/health-check.sh --quick
```

See [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines.

---

## Community

| Channel | Purpose |
|---------|---------|
| [GitHub Discussions](https://github.com/gensecaihq/Wazuh-Openclaw-Autopilot/discussions) | Questions, ideas, deployment help, community chat |
| [GitHub Issues](https://github.com/gensecaihq/Wazuh-Openclaw-Autopilot/issues) | Bug reports and feature requests |

- **Q&A**: [Deployment Help & Troubleshooting](https://github.com/gensecaihq/Wazuh-Openclaw-Autopilot/discussions/3)
- **Ideas**: [Feature Requests & Integration Ideas](https://github.com/gensecaihq/Wazuh-Openclaw-Autopilot/discussions/4)
- **Show & Tell**: [Share Your Deployment](https://github.com/gensecaihq/Wazuh-Openclaw-Autopilot/discussions/5)

---

## Related Projects

| Project | Description |
|---------|-------------|
| [OpenClaw](https://github.com/openclaw/openclaw) | AI agent framework powering the SOC automation agents |
| [Wazuh MCP Server](https://github.com/gensecaihq/Wazuh-MCP-Server) | Model Context Protocol server for Wazuh API integration |
| [OpenClaw.ai](https://openclaw.ai) | Official OpenClaw documentation and resources |

---

## License

MIT License - see [LICENSE](LICENSE)

---

<p align="center">
  <a href="https://openclaw.ai">OpenClaw</a> •
  <a href="https://github.com/gensecaihq/Wazuh-MCP-Server">Wazuh MCP Server</a> •
  <a href="https://github.com/gensecaihq/Wazuh-Openclaw-Autopilot/issues">Report Issue</a> •
  <a href="https://github.com/gensecaihq/Wazuh-Openclaw-Autopilot/issues">Request Feature</a>
</p>
