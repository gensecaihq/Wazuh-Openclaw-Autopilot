<p align="center">
  <img src="https://img.shields.io/badge/Wazuh-0080FF?style=for-the-badge&logo=wazuh&logoColor=white" alt="Wazuh"/>
  <img src="https://img.shields.io/badge/+-black?style=for-the-badge" alt="+"/>
  <img src="https://img.shields.io/badge/OpenClaw-FF6B35?style=for-the-badge&logo=claw&logoColor=white" alt="OpenClaw"/>
</p>

<h1 align="center">Wazuh OpenClaw Autopilot</h1>

<p align="center">
  <b>SOC Automation Framework for Wazuh using OpenClaw Agents</b>
</p>

<p align="center">
  <a href="https://github.com/gensecaihq/Wazuh-Openclaw-Autopilot/blob/main/LICENSE">
    <img src="https://img.shields.io/badge/License-MIT-blue.svg" alt="License: MIT">
  </a>
  <a href="https://github.com/gensecaihq/Wazuh-Openclaw-Autopilot/issues">
    <img src="https://img.shields.io/github/issues/gensecaihq/Wazuh-Openclaw-Autopilot" alt="Issues">
  </a>
</p>

<p align="center">
  <a href="#what-this-provides">What This Provides</a> •
  <a href="#quick-start">Quick Start</a> •
  <a href="#architecture">Architecture</a> •
  <a href="#configuration">Configuration</a> •
  <a href="#documentation">Documentation</a>
</p>

---

## What This Provides

**Wazuh OpenClaw Autopilot** is a framework for building automated SOC workflows on top of Wazuh. It includes:

| Component | Description |
|-----------|-------------|
| **Agent Configurations** | 7 pre-configured OpenClaw agent YAML files for triage, correlation, investigation, response planning, policy enforcement, execution, and reporting |
| **Runtime Service** | Node.js service providing case/evidence management, approval tokens, metrics, and MCP client |
| **Policy Framework** | Declarative YAML policies for access control, rate limits, and approval workflows |
| **Toolmap** | MCP tool mappings for Wazuh operations (alerts, agents, active response) |
| **Playbooks** | 7 response playbooks for common attack scenarios |
| **Installer** | Multi-scenario installer supporting 9 deployment configurations |

### Architecture

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                       WAZUH OPENCLAW AUTOPILOT                              │
│                                                                             │
│  ┌─────────────┐    ┌─────────────┐    ┌─────────────┐    ┌─────────────┐  │
│  │   Wazuh     │───▶│  MCP Server │───▶│  OpenClaw   │───▶│   Runtime   │  │
│  │   Manager   │    │  (External) │    │  (External) │    │   Service   │  │
│  └─────────────┘    └─────────────┘    └─────────────┘    └─────────────┘  │
│                            │                  │                  │         │
│                     Wazuh API          Agent Configs       Cases/Evidence  │
│                                                                             │
│  External Dependencies:                                                     │
│  • Wazuh MCP Server (github.com/gensecaihq/Wazuh-MCP-Server)               │
│  • OpenClaw Framework (github.com/openclaw/openclaw)                        │
└─────────────────────────────────────────────────────────────────────────────┘
```

### Agent Workflow

The agent configurations define a complete SOC workflow:

```
Wazuh Alert
    │
    ▼
┌─────────────┐     ┌─────────────┐     ┌─────────────┐
│   Triage    │────▶│ Correlation │────▶│Investigation│
│   Agent     │     │    Agent    │     │    Agent    │
└─────────────┘     └─────────────┘     └─────────────┘
                                               │
    ┌──────────────────────────────────────────┘
    ▼
┌─────────────┐     ┌─────────────┐     ┌─────────────┐
│  Response   │────▶│   Policy    │────▶│  Responder  │
│  Planner    │     │   Guard     │     │   Agent     │
└─────────────┘     └─────────────┘     └─────────────┘
                                               │
                                        ┌──────┴──────┐
                                        ▼             ▼
                                   ┌─────────┐  ┌──────────┐
                                   │Reporting│  │ Evidence │
                                   │  Agent  │  │  Packs   │
                                   └─────────┘  └──────────┘
```

---

## Quick Start

### Prerequisites

| Requirement | Description |
|-------------|-------------|
| **Ubuntu 22.04/24.04** | Or compatible Linux distribution |
| **Node.js 18+** | For runtime service |
| **Wazuh Manager** | Installed and running |
| **Wazuh MCP Server** | [gensecaihq/Wazuh-MCP-Server](https://github.com/gensecaihq/Wazuh-MCP-Server) deployed |
| **OpenClaw** | [openclaw/openclaw](https://github.com/openclaw/openclaw) for agent orchestration |

### Installation

```bash
# Clone the repository
git clone https://github.com/gensecaihq/Wazuh-Openclaw-Autopilot.git
cd Wazuh-Openclaw-Autopilot

# Interactive installation
sudo ./install/install.sh

# Or choose a specific mode:
sudo ./install/install.sh --mode all-in-one      # Everything on one server
sudo ./install/install.sh --mode agent-pack      # Just agent configs
sudo ./install/install.sh --mode docker          # Generate Docker Compose
```

### Configuration

After installation, configure the environment:

```bash
sudo nano /etc/wazuh-autopilot/.env
```

**Required settings:**
```bash
# MCP Server connection
MCP_URL=https://<your-mcp-server>:8080
AUTOPILOT_MCP_AUTH=<your-mcp-token>

# Slack integration (optional but recommended)
SLACK_APP_TOKEN=xapp-1-<your-app-token>
SLACK_BOT_TOKEN=xoxb-<your-bot-token>
```

**Configure Slack IDs in policy:**
```bash
sudo nano /etc/wazuh-autopilot/policies/policy.yaml
```

Replace all placeholder values:
- `<SLACK_WORKSPACE_ID>` - Your Slack workspace ID
- `<SLACK_CHANNEL_ALERTS>` - Channel ID for alerts
- `<SLACK_CHANNEL_APPROVALS>` - Channel ID for approvals
- `<SLACK_USER_*>` - Slack user IDs for approvers

### Start the Service

```bash
# Start runtime service
sudo systemctl start wazuh-autopilot
sudo systemctl enable wazuh-autopilot

# Verify
curl http://127.0.0.1:9090/health
```

---

## Deployment Scenarios

| Scenario | Description | Command |
|----------|-------------|---------|
| **All-in-One** | Single server deployment | `--mode all-in-one` |
| **OpenClaw + Runtime** | MCP on remote server | `--mode openclaw-runtime` |
| **Runtime Only** | OpenClaw elsewhere | `--mode runtime-only` |
| **Agent Pack** | Add to existing OpenClaw | `--mode agent-pack` |
| **Remote OpenClaw** | Copy to remote server via SSH | `--mode remote-openclaw` |
| **Docker Compose** | Generate docker-compose.yml | `--mode docker` |
| **Kubernetes** | Generate K8s manifests | `--mode kubernetes` |
| **Doctor** | Run diagnostics | `--mode doctor` |
| **Cutover** | Switch to production mode | `--mode cutover` |

See [SCENARIOS.md](docs/SCENARIOS.md) for detailed deployment diagrams.

---

## Runtime Service

The runtime service provides:

### REST API

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/health` | GET | Health check with version and uptime |
| `/ready` | GET | Readiness probe |
| `/metrics` | GET | Prometheus metrics |
| `/api/cases` | GET | List all cases |
| `/api/cases` | POST | Create new case |
| `/api/cases/:id` | GET | Get case by ID |
| `/api/cases/:id` | PUT | Update case |
| `/api/alerts` | POST | Ingest alert and auto-create case |

### Alert Ingestion

Send Wazuh alerts directly to create cases:

```bash
curl -X POST http://127.0.0.1:9090/api/alerts \
  -H "Content-Type: application/json" \
  -d '{
    "alert_id": "1234567890",
    "rule": {
      "id": "5712",
      "level": 10,
      "description": "SSH brute force attack"
    },
    "agent": {
      "id": "001",
      "name": "server-01",
      "ip": "10.0.1.50"
    },
    "data": {
      "srcip": "192.168.1.100"
    }
  }'
```

### Prometheus Metrics

```prometheus
autopilot_cases_created_total
autopilot_cases_updated_total
autopilot_alerts_ingested_total
autopilot_mcp_tool_calls_total{tool,status}
autopilot_approvals_requested_total
autopilot_approvals_granted_total
```

---

## Agent Configurations

### Included Agents

| Agent | File | Autonomy | Purpose |
|-------|------|----------|---------|
| **Triage** | `triage.agent.yaml` | Auto | Alert analysis, entity extraction, case creation |
| **Correlation** | `correlation.agent.yaml` | Auto | Link related alerts, build timelines |
| **Investigation** | `investigation.agent.yaml` | Auto | Deep analysis, process trees, enrichment |
| **Response Planner** | `response-planner.agent.yaml` | Approval | Generate response plans with risk assessment |
| **Policy Guard** | `policy-guard.agent.yaml` | Approval | Enforce policies, validate approvals |
| **Responder** | `responder.agent.yaml` | Approval | Execute approved actions (disabled by default) |
| **Reporting** | `reporting.agent.yaml` | Auto | Generate reports and KPIs |

### Using with OpenClaw

These YAML configurations are designed for the [OpenClaw](https://github.com/openclaw/openclaw) agent framework. To use them:

1. Install OpenClaw following their documentation
2. Copy agent configs to OpenClaw's agents directory:
   ```bash
   cp /etc/wazuh-autopilot/agents/*.yaml /opt/openclaw/agents/
   ```
3. Configure OpenClaw to connect to your MCP server
4. Restart OpenClaw to load the agents

See [AGENT_CONFIGURATION.md](docs/AGENT_CONFIGURATION.md) for customization options.

---

## Policy Configuration

### Security Policies

The `policy.yaml` file controls:

- **Autonomy levels** - Which operations run automatically vs require approval
- **Slack integration** - Workspace and channel allowlists
- **Approver groups** - Who can approve which actions
- **Action allowlists** - Enabled actions with risk levels
- **Asset criticality** - Rules for production vs development systems
- **Rate limits** - Per-action and global limits
- **Idempotency** - Prevent duplicate actions

### Required Configuration

Before production use, you must configure:

```yaml
# Slack workspace (get from api.slack.com/methods/auth.test)
workspace_allowlist:
  - id: "<SLACK_WORKSPACE_ID>"

# Slack channels (get channel ID from Slack)
channels:
  alerts:
    allowlist:
      - id: "<SLACK_CHANNEL_ALERTS>"
  approvals:
    allowlist:
      - id: "<SLACK_CHANNEL_APPROVALS>"

# Approver Slack user IDs
approvers:
  groups:
    standard:
      members:
        - slack_id: "<SLACK_USER_ANALYST_1>"
        - slack_id: "<SLACK_USER_ANALYST_2>"
    elevated:
      members:
        - slack_id: "<SLACK_USER_SENIOR>"
    admin:
      members:
        - slack_id: "<SLACK_USER_ADMIN>"
```

See [POLICY_AND_APPROVALS.md](docs/POLICY_AND_APPROVALS.md) for complete documentation.

---

## Documentation

### Getting Started
- [QUICKSTART.md](docs/QUICKSTART.md) - Get running in 15 minutes
- [SCENARIOS.md](docs/SCENARIOS.md) - Deployment scenarios with diagrams
- [CLI_REFERENCE.md](docs/CLI_REFERENCE.md) - Command-line reference

### Configuration
- [AGENT_CONFIGURATION.md](docs/AGENT_CONFIGURATION.md) - Customize agent behavior
- [POLICY_AND_APPROVALS.md](docs/POLICY_AND_APPROVALS.md) - Policy framework
- [MCP_INTEGRATION.md](docs/MCP_INTEGRATION.md) - MCP server setup
- [SLACK_SOCKET_MODE.md](docs/SLACK_SOCKET_MODE.md) - Slack integration
- [TAILSCALE_MANDATORY.md](docs/TAILSCALE_MANDATORY.md) - Zero-trust networking

### Reference
- [RUNTIME_API.md](docs/RUNTIME_API.md) - REST API documentation
- [EVIDENCE_PACK_SCHEMA.md](docs/EVIDENCE_PACK_SCHEMA.md) - Evidence pack structure
- [OBSERVABILITY_EXPORT.md](docs/OBSERVABILITY_EXPORT.md) - Metrics and logging
- [TROUBLESHOOTING.md](docs/TROUBLESHOOTING.md) - Common issues

---

## Repository Structure

```
Wazuh-Openclaw-Autopilot/
├── agents/                    # OpenClaw agent configurations
│   ├── triage.agent.yaml
│   ├── correlation.agent.yaml
│   ├── investigation.agent.yaml
│   ├── response-planner.agent.yaml
│   ├── policy-guard.agent.yaml
│   ├── responder.agent.yaml
│   └── reporting.agent.yaml
├── policies/
│   ├── policy.yaml           # Security policies
│   └── toolmap.yaml          # MCP tool mappings
├── playbooks/                 # Response playbooks
├── runtime/
│   └── autopilot-service/    # Node.js runtime service
├── install/
│   └── install.sh            # Multi-scenario installer
├── docs/                      # Documentation
└── README.md
```

---

## Security Model

| Control | Description |
|---------|-------------|
| **Read-only by default** | Action agents disabled until explicitly enabled |
| **Approval-gated** | Response actions require human approval |
| **Policy enforcement** | All actions checked against declarative policies |
| **Input validation** | All inputs validated to prevent injection |
| **Authorization** | Write endpoints require authentication |
| **Rate limiting** | Configurable per-action and global limits |
| **Audit logging** | Structured JSON logs with correlation IDs |

---

## External Dependencies

This framework requires:

| Dependency | Purpose | Link |
|------------|---------|------|
| **Wazuh MCP Server** | Provides MCP interface to Wazuh | [gensecaihq/Wazuh-MCP-Server](https://github.com/gensecaihq/Wazuh-MCP-Server) |
| **OpenClaw** | Agent orchestration framework | [openclaw/openclaw](https://github.com/openclaw/openclaw) |
| **Tailscale** | Zero-trust networking (recommended) | [tailscale.com](https://tailscale.com) |

---

## Contributing

Contributions welcome! See [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines.

```bash
# Run tests
cd runtime/autopilot-service
npm test
```

---

## License

MIT License - see [LICENSE](LICENSE) file.

---

<p align="center">
  <a href="https://github.com/gensecaihq/Wazuh-Openclaw-Autopilot/issues">Report Bug</a> •
  <a href="https://github.com/gensecaihq/Wazuh-Openclaw-Autopilot/issues">Request Feature</a>
</p>
