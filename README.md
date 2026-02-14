<p align="center">
  <img src="https://img.shields.io/badge/Wazuh-0080FF?style=for-the-badge&logo=wazuh&logoColor=white" alt="Wazuh"/>
  <img src="https://img.shields.io/badge/+-black?style=for-the-badge" alt="+"/>
  <img src="https://img.shields.io/badge/OpenClaw-FF6B35?style=for-the-badge&logo=claw&logoColor=white" alt="OpenClaw"/>
</p>

<h1 align="center">Wazuh OpenClaw Autopilot</h1>

<p align="center">
  <b>Turnkey SOC Automation for Wazuh with AI-Powered Agents</b>
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
  <a href="#quick-start">Quick Start</a> •
  <a href="#human-in-the-loop">Human-in-the-Loop</a> •
  <a href="#architecture">Architecture</a> •
  <a href="#agents">Agents</a> •
  <a href="#documentation">Documentation</a>
</p>

---

## What This Is

**Wazuh OpenClaw Autopilot** is a **turnkey installer** that transforms your existing Wazuh deployment into an autonomous SOC with AI-powered agents. The installer downloads and configures all dependencies automatically.

### Key Features

| Feature | Description |
|---------|-------------|
| **Security-Hardened** | Gateway NEVER exposed to internet, localhost binding only |
| **Turnkey Installation** | Single script with interactive security guidance |
| **Pairing Mode** | Explicit device approval required before connecting |
| **7 SOC Agents** | Triage, Correlation, Investigation, Response Planning, Policy Guard, Responder, Reporting |
| **Human-in-the-Loop** | Two-tier approval: human must Approve AND Execute every response action |
| **No Autonomous Execution** | AI agents propose actions; humans always make the final decision |
| **Slack Socket Mode** | Outbound-only connection to Slack (no inbound ports needed) |
| **Zero-Trust Networking** | Tailscale mandatory for all inter-component communication |
| **Credential Isolation** | Secrets stored in isolated directory with 600 permissions |

---

## Quick Start

### Prerequisites

- **Ubuntu 22.04/24.04** (or compatible Linux)
- **Wazuh Manager** installed and running
- **Node.js 18+**
- **Anthropic API Key** (for AI agents)

### Installation

```bash
# Clone the repository
git clone https://github.com/gensecaihq/Wazuh-Openclaw-Autopilot.git
cd Wazuh-Openclaw-Autopilot

# Run the security-hardened installer
sudo ./install/install.sh
```

The installer provides **interactive security guidance** and will:

1. **Configure firewall** - Block gateway ports from public access
2. **Install Tailscale** - Zero-trust networking (mandatory)
3. **Create secure directories** - Hardened permissions (700/600)
4. **Generate credentials** - Isolated in secrets directory
5. **Install MCP Server** - Binds to Tailscale IP only
6. **Install OpenClaw** - Binds to localhost only
7. **Deploy SOC agents** - Read-only by default
8. **Run security audit** - Verify configuration

### Security Features Applied

```
✓ Gateway binds to localhost only (never exposed)
✓ MCP Server binds to Tailscale IP (not 0.0.0.0)
✓ Pairing mode enabled (device approval required)
✓ Credentials isolated (/etc/wazuh-autopilot/secrets)
✓ Directory permissions hardened (700/600)
✓ Firewall rules configured
✓ Two-tier human approval for all actions
```

### Post-Installation

```bash
# Configure API keys
sudo nano /etc/wazuh-autopilot/.env

# Required:
ANTHROPIC_API_KEY=sk-ant-...
MCP_URL=https://your-mcp-server:8080

# Optional (Slack integration):
SLACK_APP_TOKEN=xapp-...
SLACK_BOT_TOKEN=xoxb-...

# Restart to apply
sudo systemctl restart wazuh-autopilot
```

### Verify Installation

```bash
# Check health
curl http://127.0.0.1:9090/health

# Check responder status
curl http://127.0.0.1:9090/api/responder/status
```

---

## Human-in-the-Loop

**Every response action requires human approval.** AI agents analyze alerts, correlate events, and propose response plans - but humans make the final decision.

### Two-Tier Approval Workflow

```
┌─────────────────────────────────────────────────────────────────┐
│                    TWO-TIER APPROVAL WORKFLOW                    │
│                                                                  │
│   AI proposes plan     Human Approves      Human Executes       │
│   ┌─────────┐         ┌─────────────┐      ┌─────────────┐      │
│   │ proposed│────────▶│  approved   │─────▶│  executing  │      │
│   └─────────┘         └─────────────┘      └─────────────┘      │
│        │                    │                    │               │
│   AI creates plan      Human reviews       Human triggers        │
│   with risk            and clicks          actual execution      │
│   assessment           "Approve"           by clicking "Execute" │
│                                                  │               │
│                                                  ▼               │
│                                           ┌─────────────┐        │
│                                           │ completed/  │        │
│                                           │  failed     │        │
│                                           └─────────────┘        │
└─────────────────────────────────────────────────────────────────┘
```

### How It Works

| Step | Actor | Action |
|------|-------|--------|
| 1 | AI Agent | Analyzes alert, creates response plan with risk assessment |
| 2 | Human | Reviews plan, clicks **Approve** (Tier 1) |
| 3 | Human | Reviews approved plan, clicks **Execute** (Tier 2) |
| 4 | System | Executes the approved actions via Wazuh Active Response |

**Both human approvals are mandatory.** There is no way for AI agents to execute response actions autonomously.

### Responder Capability Toggle

The system has an additional safety layer: `AUTOPILOT_RESPONDER_ENABLED`

| Setting | Behavior |
|---------|----------|
| `false` (default) | Execution capability disabled. Even if human clicks Execute, actions are blocked. |
| `true` | Execution capability enabled. Human approval still required for every action. |

**Important:** Setting `AUTOPILOT_RESPONDER_ENABLED=true` does NOT enable autonomous execution. It only enables the capability for humans to execute approved plans. Human approval is always required.

```bash
# Enable execution capability (human approval still required)
echo "AUTOPILOT_RESPONDER_ENABLED=true" >> /etc/wazuh-autopilot/.env
sudo systemctl restart wazuh-autopilot
```

### Why Two Tiers?

1. **Tier 1 (Approve)**: Human validates the AI's analysis is correct and the proposed actions are appropriate
2. **Tier 2 (Execute)**: Human confirms they want to proceed with the actual execution right now

This separation prevents accidental execution - a human must consciously make two separate decisions.

---

## Architecture

```
┌────────────────────────────────────────────────────────────────────┐
│                      YOUR INFRASTRUCTURE                           │
│                                                                    │
│  ┌─────────────┐                                                   │
│  │   Wazuh     │──┐                                                │
│  │   Manager   │  │                                                │
│  └─────────────┘  │                                                │
│                   │ Alerts (localhost)                             │
│                   ▼                                                │
│  ┌─────────────────────────────────────────────────────────────┐  │
│  │                  WAZUH AUTOPILOT                             │  │
│  │              (All services localhost/Tailscale only)         │  │
│  │                                                              │  │
│  │  ┌────────────────┐  ┌────────────────┐  ┌────────────────┐ │  │
│  │  │  MCP Server    │  │ OpenClaw       │  │ Runtime        │ │  │
│  │  │  Tailscale:8080│◀▶│ localhost:18789│◀▶│ localhost:9090 │ │  │
│  │  │  (NOT public)  │  │ (NOT public)   │  │ (NOT public)   │ │  │
│  │  └────────────────┘  └────────────────┘  └────────────────┘ │  │
│  │         │                   │                   │            │  │
│  │    Wazuh API          AI Agents           Cases/Plans        │  │
│  │   (Tailscale)        (sandboxed)       (human approval)      │  │
│  │                                                              │  │
│  │  Security:                                                   │  │
│  │  ✓ Gateway NEVER exposed to internet                         │  │
│  │  ✓ Pairing mode for device registration                      │  │
│  │  ✓ Credentials isolated (mode 600)                           │  │
│  │  ✓ Two-tier human approval mandatory                         │  │
│  │                                                              │  │
│  └──────────────────────────────────────────────────────────────┘  │
│                   │                                                │
│                   │ Tailscale VPN (encrypted)                      │
│                   ▼                                                │
│  ┌─────────────────────────────────────────────────────────────┐  │
│  │                      SLACK (Socket Mode)                     │  │
│  │                                                              │  │
│  │  Connection: OUTBOUND only (no inbound ports needed)         │  │
│  │  Runtime ──outbound──▶ Slack WebSocket ◀──messages──         │  │
│  │                                                              │  │
│  │  #security-alerts    #security-approvals                     │  │
│  │  Human clicks: [Approve] then [Execute] or [Reject]          │  │
│  └──────────────────────────────────────────────────────────────┘  │
└────────────────────────────────────────────────────────────────────┘
```

### Agent Workflow

```
Wazuh Alert
    │
    ▼
┌─────────────┐     ┌─────────────┐     ┌─────────────┐
│   Triage    │────▶│ Correlation │────▶│Investigation│
│   Agent     │     │    Agent    │     │    Agent    │
│  (auto)     │     │   (auto)    │     │   (auto)    │
└─────────────┘     └─────────────┘     └─────────────┘
                                              │
    ┌─────────────────────────────────────────┘
    ▼
┌─────────────┐     ┌─────────────┐     ┌─────────────┐
│  Response   │────▶│   Policy    │────▶│  Responder  │
│  Planner    │     │   Guard     │     │   Agent     │
│ (proposes)  │     │  (checks)   │     │ (executes)  │
└─────────────┘     └─────────────┘     └─────────────┘
       │                                      │
       │ AI creates plan                      │ Executes ONLY after
       │                                      │ human approval
       ▼                                      ▼
┌─────────────────────────────────────────────────────────┐
│           HUMAN APPROVAL REQUIRED                        │
│                                                          │
│   Step 1: Human clicks [Approve]                         │
│   Step 2: Human clicks [Execute]                         │
│                                                          │
│   No autonomous execution - humans always decide         │
└─────────────────────────────────────────────────────────┘
```

---

## Agents

| Agent | What It Does | Autonomy |
|-------|--------------|----------|
| **Triage** | Analyzes alerts, extracts entities, creates cases | Automatic |
| **Correlation** | Links related alerts, builds attack timelines | Automatic |
| **Investigation** | Deep analysis, process trees, enrichment | Automatic |
| **Response Planner** | Proposes response plans with risk assessment | Creates proposals only |
| **Policy Guard** | Validates actions against security policies | Advisory only |
| **Responder** | Executes actions via Wazuh Active Response | Human-controlled |
| **Reporting** | Generates metrics, KPIs, and reports | Automatic |

**Note:** "Automatic" agents only read and analyze data. They cannot modify systems or execute response actions.

---

## Runtime Service API

### Core Endpoints

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/health` | GET | Health check with responder status |
| `/metrics` | GET | Prometheus metrics |
| `/api/responder/status` | GET | Check responder capability status |
| `/api/cases` | GET/POST | List or create cases |
| `/api/alerts` | POST | Ingest Wazuh alert |

### Response Plan Endpoints (Human Approval Required)

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/api/plans` | GET | List response plans |
| `/api/plans` | POST | Create new response plan (AI creates these) |
| `/api/plans/:id` | GET | Get plan details |
| `/api/plans/:id/approve` | POST | **Tier 1:** Human approves plan |
| `/api/plans/:id/execute` | POST | **Tier 2:** Human triggers execution |
| `/api/plans/:id/reject` | POST | Human rejects plan |

### Example: Complete Human Approval Workflow

```bash
# 1. AI agent creates a response plan
curl -X POST http://127.0.0.1:9090/api/plans \
  -H "Content-Type: application/json" \
  -d '{
    "case_id": "CASE-20240101-abc12345",
    "title": "Block brute force attacker",
    "risk_level": "low",
    "actions": [{"type": "block_ip", "target": "192.168.1.100"}]
  }'
# Returns: {"plan_id": "PLAN-1234-abc", "state": "proposed", ...}

# 2. Human reviews and approves (Tier 1)
curl -X POST http://127.0.0.1:9090/api/plans/PLAN-1234-abc/approve \
  -H "Content-Type: application/json" \
  -d '{"approver_id": "U1234567890", "reason": "Attack confirmed"}'
# Returns: {"state": "approved", ...}

# 3. Human confirms and executes (Tier 2)
curl -X POST http://127.0.0.1:9090/api/plans/PLAN-1234-abc/execute \
  -H "Content-Type: application/json" \
  -d '{"executor_id": "U1234567890"}'
# Returns: {"state": "completed", "execution_result": {...}}
```

---

## Slack Integration

Interactive buttons in Slack for the two-tier human approval:

### Step 1: Plan Proposed (by AI)
```
┌─────────────────────────────────────────────────────────┐
│  Response Plan Requires Approval                         │
│                                                          │
│  Plan: PLAN-1234-abc                                     │
│  Case: CASE-20240101-abc12345                           │
│  Risk: LOW                                               │
│                                                          │
│  Proposed Actions:                                       │
│  • block_ip: 192.168.1.100                              │
│                                                          │
│  [Approve (Tier 1)]  [Reject]                           │
└─────────────────────────────────────────────────────────┘
```

### Step 2: Human Approves (Tier 1)
```
┌─────────────────────────────────────────────────────────┐
│  Plan Approved - Ready for Execution                     │
│                                                          │
│  Approved by: @analyst                                   │
│                                                          │
│  Click Execute to run the actions now.                   │
│                                                          │
│  [Execute (Tier 2)]  [Reject]                           │
└─────────────────────────────────────────────────────────┘
```

### Slack Commands

```
/wazuh status              # Check responder capability status
/wazuh plans proposed      # List plans awaiting human approval
/wazuh approve PLAN-1234   # Tier 1: Human approves plan
/wazuh execute PLAN-1234   # Tier 2: Human triggers execution
/wazuh reject PLAN-1234    # Human rejects plan
```

---

## Security Model

### Network Security (Never Exposed)

| Component | Binding | Accessible From |
|-----------|---------|-----------------|
| OpenClaw Gateway | `127.0.0.1:18789` | Localhost only |
| MCP Server | `<tailscale-ip>:8080` | Tailscale network only |
| Runtime Service | `127.0.0.1:9090` | Localhost only |

**No services are exposed to the public internet.** All remote access requires Tailscale VPN.

### Access Control

| Control | Description |
|---------|-------------|
| **Pairing mode** | New devices must pair with secret code before connecting |
| **DM policy: allowlist** | No public messages accepted |
| **Mention gating** | Agents only respond when explicitly mentioned |
| **Tailscale mandatory** | All inter-component traffic encrypted via VPN |

### File Permissions

| Directory | Mode | Purpose |
|-----------|------|---------|
| `/etc/wazuh-autopilot` | 700 | Configuration (owner only) |
| `/etc/wazuh-autopilot/secrets` | 700 | Credential isolation |
| `~/.openclaw` | 700 | OpenClaw config (owner only) |
| `.env` files | 600 | Environment secrets |

### Human-in-the-Loop

| Control | Description |
|---------|-------------|
| **Human approval mandatory** | Every response action requires Approve + Execute by human |
| **No autonomous execution** | AI agents cannot execute actions without human approval |
| **Responder capability toggle** | Additional safety: disabled by default |
| **Plan expiration** | Plans expire after 60 minutes |
| **Rate limiting** | Per-action and global limits |
| **Protected entities** | Cannot block internal IPs or kill system processes |
| **Audit logging** | All actions logged with correlation IDs |

### What AI Agents CAN Do (Automatically)
- Read and analyze Wazuh alerts
- Extract entities (IPs, users, hosts)
- Correlate related alerts
- Build attack timelines
- Generate reports and metrics
- **Propose** response plans

### What AI Agents CANNOT Do
- Execute any response actions
- Modify any systems
- Bypass human approval
- Auto-approve their own proposals

---

## Documentation

### Getting Started
- [QUICKSTART.md](docs/QUICKSTART.md) - Installation walkthrough
- [SLACK_SOCKET_MODE.md](docs/SLACK_SOCKET_MODE.md) - Slack setup

### Configuration
- [AGENT_CONFIGURATION.md](docs/AGENT_CONFIGURATION.md) - Customize agents
- [POLICY_AND_APPROVALS.md](docs/POLICY_AND_APPROVALS.md) - Policy framework
- [MCP_INTEGRATION.md](docs/MCP_INTEGRATION.md) - MCP server setup

### Reference
- [RUNTIME_API.md](docs/RUNTIME_API.md) - API documentation
- [TROUBLESHOOTING.md](docs/TROUBLESHOOTING.md) - Common issues

---

## Repository Structure

```
Wazuh-Openclaw-Autopilot/
├── install/
│   └── install.sh            # Turnkey installer
├── openclaw/
│   ├── openclaw.json         # OpenClaw gateway config
│   └── agents/               # Agent system prompts
├── runtime/
│   └── autopilot-service/    # Node.js runtime service
│       ├── index.js          # Main service (two-tier approval)
│       └── slack.js          # Slack integration
├── policies/
│   ├── policy.yaml           # Security policies
│   └── toolmap.yaml          # MCP tool mappings
├── agents/                   # YAML agent specs (reference)
├── playbooks/                # Response playbooks
└── docs/                     # Documentation
```

---

## FAQ

### Can AI agents execute response actions automatically?
**No.** AI agents can only propose actions. Every response action requires a human to click Approve (Tier 1) and then Execute (Tier 2).

### What does AUTOPILOT_RESPONDER_ENABLED control?
This toggle enables or disables the execution capability. When disabled (default), even if a human clicks Execute, actions are blocked. When enabled, humans can execute approved plans. **It does not enable autonomous execution.**

### What happens if I enable responder?
Nothing changes about the approval workflow. Humans still must Approve and Execute every plan. The toggle just allows the execution step to actually run the Wazuh Active Response commands.

### Can I skip the two-tier approval?
**No.** The two-tier approval is built into the system architecture. Both human actions are required.

### Is the gateway exposed to the internet?
**No.** The OpenClaw gateway binds to `127.0.0.1:18789` (localhost only). The MCP Server binds to your Tailscale IP. Neither service is accessible from the public internet.

### What is pairing mode?
Pairing mode requires explicit approval before a new device can connect to the gateway. A pairing code is generated during installation and stored in `/etc/wazuh-autopilot/secrets/pairing_code`. New devices must provide this code.

### Where are credentials stored?
Credentials are isolated in `/etc/wazuh-autopilot/secrets/` with mode 700. Individual credential files have mode 600. The main `.env` file also has mode 600.

### What firewall rules are created?
The installer configures UFW/firewalld to:
- Block gateway port (18789) from public interfaces
- Block MCP port (8080) from public interfaces
- Allow Tailscale traffic

### How does Slack work if nothing is exposed?
Slack uses **Socket Mode** - an outbound-only WebSocket connection:
1. Runtime Service connects **OUT** to Slack's servers
2. Slack sends messages back through that same connection
3. No inbound ports needed, no webhooks, no public URLs
4. Works behind firewalls and NAT

---

## Contributing

```bash
# Run tests
cd runtime/autopilot-service
npm install
npm test
```

See [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines.

---

## License

MIT License - see [LICENSE](LICENSE) file.

---

<p align="center">
  <a href="https://github.com/gensecaihq/Wazuh-Openclaw-Autopilot/issues">Report Bug</a> •
  <a href="https://github.com/gensecaihq/Wazuh-Openclaw-Autopilot/issues">Request Feature</a>
</p>
