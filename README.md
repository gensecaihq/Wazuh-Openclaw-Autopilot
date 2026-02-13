<p align="center">
  <img src="https://img.shields.io/badge/Wazuh-0080FF?style=for-the-badge&logo=wazuh&logoColor=white" alt="Wazuh"/>
  <img src="https://img.shields.io/badge/+-black?style=for-the-badge" alt="+"/>
  <img src="https://img.shields.io/badge/OpenClaw-FF6B35?style=for-the-badge&logo=claw&logoColor=white" alt="OpenClaw"/>
</p>

<h1 align="center">Wazuh OpenClaw Autopilot <sup><img src="https://img.shields.io/badge/v2.0-blue?style=flat-square" alt="v2.0"/></sup></h1>

<p align="center">
  <b>Autonomous SOC Layer for Wazuh via OpenClaw Agents</b>
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

<p align="center">
  <a href="#quick-start">Quick Start</a> •
  <a href="#features">Features</a> •
  <a href="#deployment-scenarios">Deployment</a> •
  <a href="#architecture">Architecture</a> •
  <a href="#documentation">Documentation</a>
</p>

---

**Wazuh OpenClaw Autopilot** transforms Wazuh alerts into actionable, audit-ready security cases through intelligent automation. It provides an autonomous incident workflow layer that operates safely within your security policies.

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                       WAZUH OPENCLAW AUTOPILOT                              │
│                                                                             │
│  ┌─────────────┐    ┌─────────────┐    ┌─────────────┐    ┌─────────────┐  │
│  │   Wazuh     │───▶│  MCP Server │───▶│  OpenClaw   │───▶│   Slack     │  │
│  │   Manager   │    │             │    │   Agents    │    │  (Optional) │  │
│  └─────────────┘    └─────────────┘    └─────────────┘    └─────────────┘  │
│        │                   │                  │                  │         │
│        │            ┌──────┴──────┐    ┌─────┴─────┐      ┌─────┴─────┐   │
│        │            │  Tailscale  │    │  Evidence │      │ Approvals │   │
│        │            │  (Secure)   │    │   Packs   │      │ & Reports │   │
│        │            └─────────────┘    └───────────┘      └───────────┘   │
│        │                                                                   │
│        └──────────────────── Alerts ──────────────────────────────────────│
└─────────────────────────────────────────────────────────────────────────────┘
```

## Features

- **Case-First Approach** - Automatically creates structured security cases from alerts
- **Safe Autonomy** - Read-only operations run automatically; actions require approval
- **Evidence Packs** - Every case produces audit-ready, structured evidence bundles
- **Tailscale-First Security** - Production deployments use Tailnet for zero-trust connectivity
- **Policy-Driven** - All behavior controlled by declarative YAML policies
- **Observable** - Prometheus metrics and structured JSON logs out of the box
- **Flexible Deployment** - 9 deployment scenarios from single-server to Kubernetes

## How It Works

1. **Auto-Triage** - New high/critical alerts are automatically analyzed, entities extracted, and cases created
2. **Correlation** - Related alerts are clustered into timelines with blast radius assessment
3. **Investigation** - Deep-dive analysis with process trees, network mapping, and user profiling
4. **Response Planning** - Generates response plans with risk assessment (no automatic execution)
5. **Policy Guard** - Evaluates all actions against configurable security policies
6. **Approval Workflow** - Risky actions require human approval via Slack
7. **Execution & Verification** - Approved actions are executed with verification and rollback capability

## Quick Start

### Prerequisites

| Requirement | Description |
|-------------|-------------|
| **Ubuntu** | 22.04 or 24.04 LTS (other Linux supported) |
| **Wazuh** | Installed and running ([wazuh.com](https://wazuh.com)) |
| **Wazuh MCP Server** | Deployed and accessible ([gensecaihq/Wazuh-MCP-Server](https://github.com/gensecaihq/Wazuh-MCP-Server)) |

### Installation

```bash
# Clone the repository
git clone https://github.com/gensecaihq/Wazuh-Openclaw-Autopilot.git
cd Wazuh-Openclaw-Autopilot

# Interactive installation (recommended)
sudo ./install/install.sh

# Or specify a mode directly:
sudo ./install/install.sh --mode all-in-one
```

### Configuration

```bash
# Edit configuration
sudo nano /etc/wazuh-autopilot/.env

# Required settings:
MCP_URL=https://your-mcp.tailnet.ts.net:8080
AUTOPILOT_MCP_AUTH=your-token

# Verify installation
sudo ./install/install.sh --mode doctor
```

### Start the Service

```bash
sudo systemctl start wazuh-autopilot
sudo systemctl enable wazuh-autopilot

# Check status
sudo systemctl status wazuh-autopilot
```

## Deployment Scenarios

The installer supports 9 deployment scenarios for any infrastructure:

| Scenario | Use Case | Command |
|----------|----------|---------|
| **All-in-One** | Dev/Test, small deployments | `--mode all-in-one` |
| **OpenClaw + Runtime** | MCP on different server | `--mode openclaw-runtime` |
| **Runtime Only** | OpenClaw also elsewhere | `--mode runtime-only` |
| **Agent Pack (Local)** | Existing local OpenClaw | `--mode agent-pack` |
| **Agent Pack (Remote)** | Existing remote OpenClaw | `--mode remote-openclaw` |
| **Docker Compose** | Containerized deployment | `--mode docker` |
| **Kubernetes** | Cloud-native deployment | `--mode kubernetes` |
| **Doctor** | Run diagnostics | `--mode doctor` |
| **Cutover** | Transition to production | `--mode cutover` |

### Architecture Examples

**All-in-One (Single Server):**
```
┌─────────────────────────────────────────────────────────────┐
│                      SINGLE SERVER                          │
│  ┌─────────┐  ┌─────────┐  ┌─────────┐  ┌─────────┐       │
│  │ Wazuh   │─▶│   MCP   │─▶│OpenClaw │─▶│ Runtime │       │
│  │ Manager │  │ :8080   │  │ :3000   │  │ :9090   │       │
│  └─────────┘  └─────────┘  └─────────┘  └─────────┘       │
└─────────────────────────────────────────────────────────────┘
```

**Distributed (MCP Remote):**
```
┌─────────────────────────┐      ┌─────────────────────────┐
│      SERVER A           │      │      SERVER B           │
│   (Security Data)       │      │   (AI Processing)       │
│  ┌─────────┐            │      │            ┌─────────┐ │
│  │ Wazuh   │            │      │            │OpenClaw │ │
│  │ Manager │            │ HTTP │            └────┬────┘ │
│  ├─────────┤            │      │            ┌────┴────┐ │
│  │   MCP   │◀───────────│──────│────────────┤ Runtime │ │
│  │ :8080   │            │      │            │ :9090   │ │
│  └─────────┘            │      │            └─────────┘ │
└─────────────────────────┘      └─────────────────────────┘
```

See [SCENARIOS.md](docs/SCENARIOS.md) for detailed architecture diagrams.

## Architecture

### Agents

Wazuh OpenClaw Autopilot ships with 7 pre-configured [OpenClaw](https://github.com/openclaw/openclaw) agents:

| Agent | Role | Autonomy Level |
|-------|------|----------------|
| **Triage** | Alert analysis, entity extraction, case creation | Read-only (Full auto) |
| **Correlation** | Clusters related alerts, builds timelines | Read-only (Full auto) |
| **Investigation** | Deep-dive queries, process trees, enrichment | Read-only (Full auto) |
| **Response Planner** | Generates response plans with risk assessment | Approval-gated |
| **Policy Guard** | Constitutional enforcement of all actions | Approval-gated |
| **Responder** | Executes approved actions with verification | Approval-gated (Disabled) |
| **Reporting** | Daily digest, KPIs, executive summaries | Read-only (Scheduled) |

### Deployment Modes

| Mode | Description | Status |
|------|-------------|--------|
| **Bootstrap** | MCP accessible via any URL, Tailscale optional | `READY (Bootstrap)` |
| **Production** | MCP must be on Tailnet, Tailscale required | `READY (Production)` |

### Integration Stack

```
┌──────────────────────────────────────────────────────────────┐
│                    Your Infrastructure                        │
├──────────────────────────────────────────────────────────────┤
│  Wazuh Manager ──▶ Wazuh MCP Server ──▶ Wazuh Autopilot     │
│       ▲                   ▲                    │              │
│       │                   │                    ▼              │
│   Agents/Logs        Tailscale           Slack/Metrics       │
└──────────────────────────────────────────────────────────────┘
```

**Related Projects:**
- [Wazuh MCP Server](https://github.com/gensecaihq/Wazuh-MCP-Server) - MCP interface for Wazuh
- [OpenClaw](https://github.com/openclaw/openclaw) - Agent orchestration framework

## Documentation

### Getting Started

| Document | Description |
|----------|-------------|
| [QUICKSTART.md](docs/QUICKSTART.md) | Get running in 15 minutes |
| [SCENARIOS.md](docs/SCENARIOS.md) | All deployment scenarios with diagrams |
| [CLI_REFERENCE.md](docs/CLI_REFERENCE.md) | Complete command-line reference |

### Configuration

| Document | Description |
|----------|-------------|
| [AGENT_CONFIGURATION.md](docs/AGENT_CONFIGURATION.md) | Agent customization guide |
| [POLICY_AND_APPROVALS.md](docs/POLICY_AND_APPROVALS.md) | Policy configuration guide |
| [MCP_INTEGRATION.md](docs/MCP_INTEGRATION.md) | MCP server setup and integration |
| [SLACK_SOCKET_MODE.md](docs/SLACK_SOCKET_MODE.md) | Slack integration setup |
| [TAILSCALE_MANDATORY.md](docs/TAILSCALE_MANDATORY.md) | Why and how to use Tailscale |

### Reference

| Document | Description |
|----------|-------------|
| [RUNTIME_API.md](docs/RUNTIME_API.md) | Runtime service REST API reference |
| [EVIDENCE_PACK_SCHEMA.md](docs/EVIDENCE_PACK_SCHEMA.md) | Evidence pack data structure |
| [OBSERVABILITY_EXPORT.md](docs/OBSERVABILITY_EXPORT.md) | Metrics and logging |
| [TROUBLESHOOTING.md](docs/TROUBLESHOOTING.md) | Common issues and solutions |
| [SECURITY.md](SECURITY.md) | Security policy and vulnerability reporting |

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
├── policies/                  # Policy definitions
│   ├── policy.yaml           # Security policies (source of truth)
│   └── toolmap.yaml          # MCP tool name mapping
├── playbooks/                 # Response playbooks (7 included)
│   ├── bruteforce.md
│   ├── ransomware.md
│   ├── suspicious-powershell.md
│   ├── data-exfil.md
│   ├── vuln-spike.md
│   ├── privilege-escalation.md
│   └── lateral-movement.md
├── install/                   # Installation scripts
│   └── install.sh            # Universal installer (9 scenarios)
├── runtime/                   # Runtime service
│   └── autopilot-service/
│       ├── index.js          # Main service
│       └── index.test.js     # Test suite
├── docs/                      # Documentation
└── README.md
```

## Evidence Packs

Every case produces a structured, audit-ready evidence pack:

```json
{
  "schema_version": "1.0",
  "case_id": "CASE-2024-001",
  "title": "Brute Force Attack on SSH",
  "severity": "high",
  "confidence": 0.85,
  "entities": [
    {"type": "ip", "value": "192.168.1.100", "role": "attacker"},
    {"type": "user", "value": "admin", "role": "target"},
    {"type": "host", "value": "web-server-01", "role": "victim"}
  ],
  "timeline": [],
  "mitre": [{"tactic": "Credential Access", "technique": "T1110"}],
  "mcp_calls": [],
  "plans": [],
  "approvals": [],
  "actions": []
}
```

## Observability

### Prometheus Metrics

```prometheus
# Cases
autopilot_cases_created_total
autopilot_cases_updated_total

# Performance
autopilot_triage_latency_seconds_bucket
autopilot_mcp_tool_calls_total{tool,status}
autopilot_mcp_tool_call_latency_seconds_bucket{tool}

# Approvals
autopilot_approvals_requested_total
autopilot_approvals_granted_total
autopilot_policy_denies_total{reason}

# Errors
autopilot_errors_total{component}
```

### Structured Logs

All logs are JSON-formatted with correlation IDs:

```json
{
  "ts": "2024-01-15T10:30:00.000Z",
  "level": "info",
  "component": "triage",
  "msg": "Case created",
  "correlation_id": "abc123",
  "case_id": "CASE-2024-001",
  "severity": "high"
}
```

## Security Model

| Control | Description |
|---------|-------------|
| **Read-only by default** | Agents cannot execute actions without explicit enablement |
| **Approval-gated actions** | Response actions require human approval via Slack |
| **Policy enforcement** | All actions checked against declarative policies |
| **Tailscale-first** | Production requires Tailnet connectivity |
| **Input validation** | All user inputs validated to prevent injection |
| **Authorization required** | Write API endpoints require authentication |
| **No secrets in logs** | Structured logs automatically redact sensitive data |
| **Localhost metrics** | Metrics endpoint bound to 127.0.0.1 by default |
| **Memory protection** | Bounded data structures prevent resource exhaustion |

## Contributing

Contributions are welcome! Whether it's bug reports, feature requests, or pull requests.

### Development Setup

```bash
# Clone the repository
git clone https://github.com/gensecaihq/Wazuh-Openclaw-Autopilot.git
cd Wazuh-Openclaw-Autopilot

# Run tests
cd runtime/autopilot-service
npm test

# Run diagnostics
sudo ./install/install.sh --mode doctor
```

### Submitting Changes

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

## Roadmap

- [x] Core agent pack (7 agents with full configurations)
- [x] Evidence pack schema v1.0
- [x] Slack Socket Mode integration
- [x] Prometheus metrics export
- [x] Bootstrap/Production deployment modes
- [x] 9 deployment scenarios with interactive installer
- [x] Comprehensive documentation suite
- [x] Security hardening (input validation, auth, memory limits)
- [ ] Teams/Discord integrations
- [ ] S3/R2 evidence pack storage
- [ ] OTEL tracing support
- [ ] Web dashboard

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## Acknowledgments

- [Wazuh](https://wazuh.com/) - Open source security platform
- [OpenClaw](https://github.com/openclaw/openclaw) - Agent orchestration framework
- [Tailscale](https://tailscale.com/) - Zero-trust networking
- [GenSecAI](https://github.com/gensecaihq) - Project maintainers

---

<p align="center">
  <strong>Built with security in mind by <a href="https://github.com/gensecaihq">GenSecAI</a></strong>
</p>

<p align="center">
  <a href="https://github.com/gensecaihq/Wazuh-Openclaw-Autopilot/issues">Report Bug</a>
  ·
  <a href="https://github.com/gensecaihq/Wazuh-Openclaw-Autopilot/issues">Request Feature</a>
  ·
  <a href="https://github.com/gensecaihq/Wazuh-MCP-Server">Wazuh MCP Server</a>
</p>
