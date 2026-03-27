<p align="center">
  <a href="https://wazuh.com"><img src="https://img.shields.io/badge/Wazuh-0080FF?style=for-the-badge&logo=wazuh&logoColor=white" alt="Wazuh"/></a>
  <a href="https://openclaw.ai"><img src="https://img.shields.io/badge/OpenClaw-FF6B35?style=for-the-badge&logoColor=white" alt="OpenClaw"/></a>
  <a href="https://modelcontextprotocol.io"><img src="https://img.shields.io/badge/MCP-6B4FBB?style=for-the-badge&logoColor=white" alt="MCP"/></a>
</p>

<h1 align="center">Wazuh OpenClaw Autopilot</h1>

<p align="center">
  <strong>Turn your Wazuh SIEM into an autonomous SOC with AI agents that triage, investigate, and respond — while humans stay in control.</strong>
</p>

<p align="center">
  <a href="https://github.com/gensecaihq/Wazuh-Openclaw-Autopilot/releases"><img src="https://img.shields.io/github/v/release/gensecaihq/Wazuh-Openclaw-Autopilot?color=green&label=release" alt="Release"/></a>
  <a href="https://github.com/gensecaihq/Wazuh-Openclaw-Autopilot/blob/main/LICENSE"><img src="https://img.shields.io/badge/License-MIT-blue.svg" alt="License: MIT"/></a>
  <a href="https://github.com/gensecaihq/Wazuh-Openclaw-Autopilot/actions"><img src="https://img.shields.io/github/actions/workflow/status/gensecaihq/Wazuh-Openclaw-Autopilot/ci.yml?label=CI" alt="CI"/></a>
  <a href="https://github.com/gensecaihq/Wazuh-Openclaw-Autopilot/issues"><img src="https://img.shields.io/github/issues/gensecaihq/Wazuh-Openclaw-Autopilot" alt="Issues"/></a>
  <a href="https://github.com/gensecaihq/Wazuh-Openclaw-Autopilot/stargazers"><img src="https://img.shields.io/github/stars/gensecaihq/Wazuh-Openclaw-Autopilot" alt="Stars"/></a>
</p>

<p align="center">
  <a href="#quick-start">Quick Start</a> &middot;
  <a href="#how-it-works">How It Works</a> &middot;
  <a href="#deployment-options">Deploy</a> &middot;
  <a href="docs/RUNTIME_API.md">API Docs</a> &middot;
  <a href="CHANGELOG.md">Changelog</a>
</p>

---

## What It Does

A Wazuh alert fires. Within minutes — not hours — your SOC has:

1. **Triaged** the alert with entity extraction, MITRE mapping, and severity assessment
2. **Correlated** it with related alerts across hosts, IPs, and users
3. **Investigated** via live Wazuh queries — auth history, process trees, lateral movement checks
4. **Generated a response plan** with risk assessment and rollback procedures
5. **Executed the response** (IP block, host isolation, process kill) — only after human approval

No alert sits unread. No playbook gets skipped. Every action has an evidence trail.

### Before and After

| | Without Autopilot | With Autopilot |
|---|---|---|
| **Alert triage** | Manual review, 15-60 min per alert | Automatic, ~40 seconds |
| **Investigation** | Analyst runs queries, cross-references | 7+ pivot queries run automatically |
| **Response** | Find playbook, execute manually | Risk-assessed plan, one-click approve |
| **Evidence** | Scattered across tools | Structured JSON evidence pack per case |
| **Coverage** | Business hours, analyst availability | 24/7, every alert processed |

---

## How It Works

```
  Wazuh Alert
       │
       ▼
  ┌─────────┐    ┌─────────────┐    ┌───────────────┐    ┌──────────────┐
  │ Triage  │───▶│ Correlation │───▶│ Investigation │───▶│   Response   │
  │  Agent  │    │    Agent    │    │    Agent      │    │   Planner    │
  └─────────┘    └─────────────┘    └───────────────┘    └──────┬───────┘
   Extract IOCs   Group related      Query Wazuh via       Generate plan
   Map MITRE       alerts into        MCP (48 tools)       Assess risk
   Set severity    unified cases      Build timeline       Assign actions
                                                                │
                                                                ▼
                                                     ┌──────────────────┐
                                                     │  Policy Guard    │
                                                     │  + Human Review  │
                                                     └────────┬─────────┘
                                                              │
                                                     [Approve] [Reject]
                                                              │
                                                              ▼
                                                     ┌──────────────────┐
                                                     │   Responder      │
                                                     │   (Execution)    │
                                                     └──────────────────┘
                                                      block_ip, isolate_host,
                                                      kill_process, disable_user...
```

**7 specialized agents** work as a pipeline. Each agent has a single responsibility, its own playbook, and communicates through the runtime service via webhooks. The runtime enforces policy at every step — action allowlists, confidence thresholds, rate limits, time windows, and idempotency checks.

**AI agents never act autonomously.** Every response action requires explicit two-tier human approval (Approve + Execute). The responder capability is disabled by default.

---

## Key Features

**Detection & Analysis**
- Autonomous alert triage with entity extraction (IPs, users, hosts, hashes)
- MITRE ATT&CK technique and tactic mapping
- Entity-based alert grouping into unified cases
- AbuseIPDB IP reputation enrichment with TTL caching
- Investigation agent runs 7+ pivot queries per case via [Wazuh MCP Server](https://github.com/gensecaihq/Wazuh-MCP-Server) (48 tools)

**Response & Enforcement**
- Risk-assessed response plans with rollback metadata
- 9 Wazuh Active Response actions (block IP, isolate host, kill process, disable user, quarantine file, firewall drop, host deny, restart, generic AR)
- Inline policy enforcement: action allowlists, confidence thresholds, approver authorization, evidence requirements, time windows, rate limits, idempotency
- Two-tier approval workflow with separation of duties

**Observability & Reporting**
- Structured JSON evidence packs for compliance and forensics
- Prometheus metrics with SOC KPIs (MTTD, MTTT, MTTI, MTTR, MTTC)
- KPI endpoint with SLA compliance tracking
- Reporting agent generates hourly, daily, weekly, and monthly SOC health reports
- Slack integration with real-time alerts and interactive approval buttons (Socket Mode)

**Operations**
- Crash recovery for plans stuck mid-execution
- Stalled pipeline detection with automatic re-dispatch
- Alert dedup across date boundaries
- LLM type coercion for local model compatibility
- Investigation findings auto-promoted to case severity/confidence

---

## Quick Start

### Prerequisites

| Requirement | Description |
|---|---|
| [Wazuh](https://wazuh.com) 4.8+ | SIEM platform, installed and running |
| [Wazuh MCP Server](https://github.com/gensecaihq/Wazuh-MCP-Server) v4.2.1+ | MCP bridge for Wazuh API (48 tools) |
| [OpenClaw](https://github.com/openclaw/openclaw) v2026.7.3+ | AI agent framework |
| Node.js 20+ | Runtime service (22+ recommended) |
| LLM API Key | Claude, GPT, Groq, Mistral, or [local Ollama/vLLM](#local-llm-options) |

### Install

```bash
git clone https://github.com/gensecaihq/Wazuh-Openclaw-Autopilot.git
cd Wazuh-Openclaw-Autopilot
sudo ./install/install.sh
```

The installer handles MCP Server setup, OpenClaw configuration, agent deployment, and optional Slack integration. For air-gapped environments, use `--mode bootstrap`.

### Configure

```bash
sudo nano /etc/wazuh-autopilot/.env
```

```bash
# Wazuh connection
WAZUH_HOST=localhost
WAZUH_PORT=55000
WAZUH_USER=wazuh-wui
WAZUH_PASS=your-password

# LLM provider (pick one — we recommend OpenRouter for simplicity)
OPENROUTER_API_KEY=sk-or-...

# Optional: Slack approval buttons
SLACK_APP_TOKEN=xapp-...
SLACK_BOT_TOKEN=xoxb-...
```

### Verify

```bash
curl http://localhost:9090/health
curl http://localhost:9090/metrics
```

---

## Deployment Options

| Method | Best For | Command |
|---|---|---|
| **Docker Compose** | Production | `docker-compose up -d` |
| **Systemd** | Native Linux | `sudo ./install/install.sh` |
| **Air-gapped** | Classified / offline | `sudo ./install/install.sh --mode bootstrap` + [guide](docs/AIR_GAPPED_DEPLOYMENT.md) |
| **vLLM** | Self-hosted GPU | [vLLM Guide](docs/VLLM_DEPLOYMENT.md) |
| **Manual** | Development | `cd runtime/autopilot-service && npm start` |

---

## LLM Providers

OpenClaw is model-agnostic. Use any provider:

| Provider | Best For | Cost |
|---|---|---|
| [OpenRouter](https://openrouter.ai/) | Safest option — 300+ models, single key, no ban risk | Pay per token |
| [Anthropic](https://console.anthropic.com/) | Best reasoning (Claude) | Pay per token |
| [Groq](https://console.groq.com/) | Ultra-fast inference | Free tier available |
| [Ollama](https://ollama.com) | Air-gapped / free | Free (local) |
| [vLLM](https://github.com/vllm-project/vllm) | Self-hosted GPU inference | Hardware only |

Plus OpenAI, Google, Mistral, xAI, Together, Cerebras. See [full provider guide](#provider-details) below.

> **API Keys Only**: Use pay-per-token API keys, not subscription OAuth tokens. Anthropic and Google have banned subscription tokens in third-party tools. [Details](#provider-policy-notice).

---

## Human-in-the-Loop Approval

```
 PROPOSED ────▶ APPROVED ────▶ EXECUTED
    │               │               │
    ▼               ▼               ▼
 Policy Check   Policy Check    Policy Check
 ─ allowlist    ─ approver ID   ─ evidence
 ─ confidence   ─ risk level    ─ time window
 ─ time window                  ─ rate limit
                                ─ idempotency
```

AI agents generate plans. Humans approve them. The runtime enforces policy at every step. **No action executes without human authorization.**

---

## Wazuh Compatibility

Tested via [Wazuh MCP Server](https://github.com/gensecaihq/Wazuh-MCP-Server) v4.2.1 (48 tools):

| Wazuh Version | Status |
|---|---|
| **4.14.x** | Fully Supported (recommended) |
| 4.8.x – 4.13.x | Fully Supported |
| 4.0.0 – 4.7.x | Limited (no vulnerability tools) |

Platforms: Ubuntu 22.04/24.04, Debian 11/12, RHEL/Rocky/AlmaLinux 8/9, Docker.

---

## API Reference

### Core Endpoints

| Endpoint | Method | Description |
|---|---|---|
| `POST /api/alerts` | POST | Ingest Wazuh alert — triggers full pipeline |
| `GET /api/cases` | GET | List cases (filter: `?status=`, `?severity=`, `?since=`, `?until=`) |
| `GET /api/cases/summary` | GET | Aggregated case statistics |
| `GET /api/cases/:id` | GET | Full case with evidence pack |
| `GET /api/plans` | GET | List plans (filter: `?state=`, `?case_id=`) |
| `GET /api/plans/:id` | GET | Plan details |
| `POST /api/plans/:id/approve` | POST | Approve plan (Tier 1) |
| `POST /api/plans/:id/execute` | POST | Execute plan (Tier 2) |
| `GET /api/kpis` | GET | SLA/KPI metrics (`?period=24h`) |
| `GET /api/reports` | GET | List stored reports |
| `GET /metrics` | GET | Prometheus metrics |

### Agent Action Endpoints (GET-based for `web_fetch`)

| Endpoint | Description |
|---|---|
| `/api/agent-action/update-case` | Update case status/data |
| `/api/agent-action/create-plan` | Create response plan |
| `/api/agent-action/approve-plan` | Approve/deny plan |
| `/api/agent-action/execute-plan` | Execute approved plan |
| `/api/agent-action/store-report` | Store generated report |
| `/api/agent-action/search-alerts` | Proxy search to Wazuh MCP |

Full API documentation: [RUNTIME_API.md](docs/RUNTIME_API.md)

---

## SOC KPIs & Reporting

The runtime tracks case status transitions and computes SLA metrics:

```bash
curl http://localhost:9090/api/kpis?period=24h
```

```json
{
  "period": "24h",
  "cases_analyzed": 50,
  "mttt": 42,
  "mtti": 138,
  "mttr": 280,
  "mttc": 450,
  "auto_triage_rate": 0.92,
  "false_positive_rate": 0.18,
  "sla_compliance": {
    "triage_within_15m": 0.95,
    "response_within_1h": 0.82
  }
}
```

The reporting agent generates hourly, daily, weekly, and monthly SOC health reports automatically.

---

## Evidence Packs

Every case produces a structured evidence pack for compliance and forensics:

```json
{
  "case_id": "CASE-20260327-1df903b68bc7",
  "severity": "high",
  "confidence": 0.95,
  "entities": [
    {"type": "ip", "value": "176.120.22.47", "role": "source"},
    {"type": "host", "value": "virt-5378", "role": "victim"}
  ],
  "mitre": [{"technique_id": "T1110.001", "tactic": "Credential Access"}],
  "investigation_notes": "200+ failed SSH login attempts over 7 days...",
  "findings": {"classification": "brute_force", "confidence": 0.95},
  "status_history": [
    {"from": "open", "to": "triaged", "timestamp": "..."},
    {"from": "triaged", "to": "investigated", "timestamp": "..."}
  ],
  "plans": [...],
  "actions": [...],
  "mcp_calls": [...]
}
```

---

## Security

| Layer | Protection |
|---|---|
| **Network** | All services localhost-only. Tailscale zero-trust for inter-node. |
| **Auth** | Bearer token + query param auth. Timing-safe comparison. |
| **Policy** | Inline enforcement at every pipeline step. Fail-closed in production. |
| **Agents** | Sandboxed execution. Anti-injection instructions. No `exec` access. |
| **Approval** | Two-tier human approval. Separation of duties. Bootstrap gate requires explicit opt-in. |
| **MCP** | RBAC scopes (`wazuh:read`/`wazuh:write`). JWT auth. Circuit breaker. |

---

## Slack Integration

Socket Mode — outbound-only, no webhooks or public endpoints required:

- Real-time alert notifications with severity coloring
- Interactive **[Approve]** / **[Reject]** / **[Execute]** buttons
- Slash commands: `/wazuh status`, `/wazuh approve`, `/wazuh execute`
- Confirmation dialogs for destructive actions

---

## Project Structure

```
├── install/install.sh              # Security-hardened installer
├── docker-compose.yml              # Production container orchestration
├── openclaw/
│   ├── openclaw.json               # Gateway & model config
│   └── agents/                     # 7 SOC agents (AGENTS.md, TOOLS.md, IDENTITY.md)
├── runtime/autopilot-service/
│   ├── index.js                    # Runtime service (6400+ LOC)
│   ├── slack.js                    # Slack Socket Mode integration
│   └── *.test.js                   # 532 tests across 15 files
├── policies/
│   ├── policy.yaml                 # Action allowlists, approvers, thresholds
│   └── toolmap.yaml                # MCP tool mappings (9 action tools)
├── playbooks/                      # 7 incident response playbooks
└── docs/                           # 15 documentation files
```

---

## Local LLM Options

### Ollama (Air-Gapped)

Zero external network calls. Full data sovereignty. See [Air-Gapped Guide](docs/AIR_GAPPED_DEPLOYMENT.md).

```bash
sudo ./install/install.sh --mode bootstrap
```

### vLLM (Self-Hosted GPU)

Production-grade throughput with open-source models. See [vLLM Guide](docs/VLLM_DEPLOYMENT.md).

```bash
vllm serve Qwen/Qwen3-32B --enable-auto-tool-choice --tool-call-parser hermes
```

| Model | VRAM | Best For |
|---|---|---|
| Qwen3 32B | ~64 GB | Best tool calling |
| Llama 3.3 70B | ~140 GB | Strongest reasoning |
| DeepSeek-R1 70B | ~140 GB | Chain-of-thought |

---

## Provider Details

<details>
<summary>Full provider list and configuration</summary>

| Provider | Models | API Key Env |
|---|---|---|
| [OpenRouter](https://openrouter.ai/) | 300+ models | `OPENROUTER_API_KEY` |
| [Anthropic](https://console.anthropic.com/) | Claude Sonnet 4.5, Haiku 4.5 | `ANTHROPIC_API_KEY` |
| [OpenAI](https://platform.openai.com/) | GPT-4o, o3-mini | `OPENAI_API_KEY` |
| [Groq](https://console.groq.com/) | Llama 3.3 70B, Mixtral | `GROQ_API_KEY` |
| [Google](https://aistudio.google.com/) | Gemini 2.0 Flash/Pro | `GOOGLE_API_KEY` |
| [Mistral](https://console.mistral.ai/) | Mistral Large, Codestral | `MISTRAL_API_KEY` |
| [xAI](https://console.x.ai/) | Grok 2, Grok 3 | `XAI_API_KEY` |
| [Ollama](https://ollama.com) | Llama, Mistral, Qwen | N/A (local) |
| [vLLM](https://github.com/vllm-project/vllm) | Any HuggingFace model | `VLLM_API_KEY` |
| [Together](https://together.xyz/) | Open-source models | `TOGETHER_API_KEY` |
| [Cerebras](https://cerebras.ai/) | Ultra-fast inference | `CEREBRAS_API_KEY` |

Model format: `"provider/model-name"` (e.g., `"anthropic/claude-sonnet-4-5"`).

### Cost Optimization

| Task | Recommended Model | Why |
|---|---|---|
| Complex investigation | `anthropic/claude-sonnet-4-5` | Best reasoning |
| High-volume triage | `groq/llama-3.3-70b-versatile` | Fast and free |
| Heartbeats | `anthropic/claude-haiku-4-5` | Cheapest Claude |
| Air-gapped | `ollama/llama3.3` | No network |
| GPU self-hosted | `vllm/qwen3-32b` | Best open-source tool calling |

</details>

---

## Provider Policy Notice

<details>
<summary>Important: API keys vs subscription tokens</summary>

Anthropic and Google have **banned** subscription-plan OAuth tokens (Claude Pro/Max, Google AI Ultra) in third-party tools. Using them will result in account suspension.

**Always use pay-per-token API keys** from the provider's developer console, or route through **OpenRouter** (billing proxy, no ban risk).

- **OpenRouter**: Single key, 300+ models, no restrictions
- **Groq, Mistral, xAI, Together, Cerebras**: No restrictions reported

</details>

---

## Documentation

| Document | Description |
|---|---|
| [QUICKSTART.md](docs/QUICKSTART.md) | Installation guide |
| [RUNTIME_API.md](docs/RUNTIME_API.md) | REST API reference |
| [POLICY_AND_APPROVALS.md](docs/POLICY_AND_APPROVALS.md) | Policy engine and approval workflow |
| [SLACK_SOCKET_MODE.md](docs/SLACK_SOCKET_MODE.md) | Slack setup |
| [EVIDENCE_PACK_SCHEMA.md](docs/EVIDENCE_PACK_SCHEMA.md) | Evidence pack format |
| [AGENT_CONFIGURATION.md](docs/AGENT_CONFIGURATION.md) | Agent customization |
| [AIR_GAPPED_DEPLOYMENT.md](docs/AIR_GAPPED_DEPLOYMENT.md) | Offline deployment with Ollama |
| [VLLM_DEPLOYMENT.md](docs/VLLM_DEPLOYMENT.md) | GPU inference with vLLM |
| [MCP_INTEGRATION.md](docs/MCP_INTEGRATION.md) | MCP server integration |
| [AGENT_COMMUNICATION.md](docs/AGENT_COMMUNICATION.md) | Agent-to-runtime architecture |
| [TROUBLESHOOTING.md](docs/TROUBLESHOOTING.md) | Common issues and fixes |
| [CHANGELOG.md](CHANGELOG.md) | Version history |

---

## Contributing

```bash
cd runtime/autopilot-service
npm install
npm test   # 532 tests, all passing
```

See [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines.

---

## Community

- [GitHub Discussions](https://github.com/gensecaihq/Wazuh-Openclaw-Autopilot/discussions) — Questions, ideas, deployment help
- [GitHub Issues](https://github.com/gensecaihq/Wazuh-Openclaw-Autopilot/issues) — Bug reports and feature requests

---

## Related Projects

| Project | Description |
|---|---|
| [Wazuh MCP Server](https://github.com/gensecaihq/Wazuh-MCP-Server) | MCP bridge for Wazuh API (48 tools, RBAC, audit logging) |
| [OpenClaw](https://github.com/openclaw/openclaw) | AI agent framework powering the SOC agents |

---

## License

MIT License — see [LICENSE](LICENSE)

---

<p align="center">
  <sub>Built by <a href="https://github.com/gensecaihq">GenSecAI</a></sub>
</p>
