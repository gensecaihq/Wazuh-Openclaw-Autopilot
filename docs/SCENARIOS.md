# Deployment Scenarios

Wazuh OpenClaw Autopilot supports three deployment scenarios to match your existing infrastructure.

## Overview

| Scenario | Wazuh | MCP | OpenClaw | What Installer Does |
|----------|-------|-----|----------|-------------------|
| 1 | ✅ | ✅ | ✅ | Install agents only |
| 2 | ✅ | ✅ | ❌ | Bootstrap OpenClaw + install agents |
| 3 | ✅ | ❌ | ❌ | Full setup + guidance |

## Scenario 1: Full Stack Already Exists

**You have:** Wazuh + MCP Server + OpenClaw

**Use case:** Adding Autopilot capabilities to an existing OpenClaw deployment.

### Installation

```bash
sudo ./install/install.sh --mode agent-pack
```

### What happens:

1. Verifies OpenClaw is installed and accessible
2. Copies agent configurations to `/etc/wazuh-autopilot/agents/`
3. Copies policies to `/etc/wazuh-autopilot/policies/`
4. Creates configuration file
5. Links agents to OpenClaw

### Requirements:

- OpenClaw must be running
- MCP must be reachable
- Tailscale recommended but not required for bootstrap

### Variants:

**1a. MCP via LAN/public URL (no Tailnet yet)**

```bash
# Set bootstrap mode
export AUTOPILOT_MODE=bootstrap
export MCP_BOOTSTRAP_URL=http://192.168.1.100:8080

sudo ./install/install.sh --mode agent-pack
```

**1b. MCP via Tailnet (production-ready)**

```bash
export AUTOPILOT_MODE=production
export MCP_URL=https://mcp.your-tailnet.ts.net:8080

sudo ./install/install.sh --mode agent-pack
```

**1c. Tailnet on Autopilot, not yet on MCP**

```bash
# Start in bootstrap mode
export AUTOPILOT_MODE=bootstrap
export MCP_BOOTSTRAP_URL=http://mcp-server.local:8080

sudo ./install/install.sh --mode agent-pack

# Later, after joining MCP to Tailnet:
sudo ./install/install.sh --cutover
```

---

## Scenario 2: MCP Exists, No OpenClaw

**You have:** Wazuh + MCP Server

**Use case:** Need OpenClaw bootstrapped on the Autopilot host.

### Installation

```bash
sudo ./install/install.sh --mode bootstrap-openclaw
```

### What happens:

1. Installs Docker (if not present)
2. Creates OpenClaw directory structure
3. Deploys OpenClaw via Docker Compose
4. Installs Autopilot agents and policies
5. Configures MCP connectivity
6. Creates systemd service

### Requirements:

- MCP must be reachable
- Docker will be installed automatically
- Tailscale will be installed but not required for bootstrap

### Post-installation:

```bash
# Start OpenClaw
cd /opt/openclaw
docker-compose up -d

# Start Autopilot
sudo systemctl start wazuh-autopilot
```

---

## Scenario 3: Fresh Start (Wazuh Only)

**You have:** Wazuh only

**Use case:** Building the full Autopilot stack from scratch.

### Installation

```bash
sudo ./install/install.sh --mode fresh
```

### What happens:

1. Installs Tailscale (mandatory for production)
2. Installs Docker
3. Bootstraps OpenClaw
4. Installs Autopilot agents and policies
5. Provides MCP deployment guidance

### MCP Deployment Guidance

After installation, you'll need to deploy a Wazuh MCP Server. Recommended:

**Option A: Same host as Wazuh Manager**

```bash
# On your Wazuh Manager host
git clone https://github.com/gensecaihq/Wazuh-MCP-Server.git
cd Wazuh-MCP-Server
docker-compose up -d
```

**Option B: Separate host**

Deploy MCP on a dedicated host, then:

1. Join MCP host to your Tailnet
2. Configure Autopilot with Tailnet MCP URL
3. Run cutover workflow

### Cutover to Production

After MCP is running and on Tailnet:

```bash
sudo ./install/install.sh --cutover
```

---

## Deployment States

Regardless of scenario, Autopilot operates in one of two states:

### Bootstrap Mode (Evaluation/Testing)

- MCP can be any reachable URL (LAN, public, etc.)
- Tailscale not required
- Limited to evaluation purposes
- Doctor shows: `⚠️ READY (Bootstrap only)`

```bash
AUTOPILOT_MODE=bootstrap
```

### Production Mode (Recommended)

- MCP must be a Tailnet URL
- Tailscale required and running
- Full security posture
- Doctor shows: `✅ READY (Production)`

```bash
AUTOPILOT_MODE=production
AUTOPILOT_REQUIRE_TAILSCALE=true
```

---

## Decision Tree

```
Do you have OpenClaw installed?
├── Yes → Use --mode agent-pack (Scenario 1)
└── No
    └── Do you have MCP deployed?
        ├── Yes → Use --mode bootstrap-openclaw (Scenario 2)
        └── No → Use --mode fresh (Scenario 3)
```

---

## Non-Interactive Installation

All scenarios support non-interactive installation via environment variables:

```bash
export AUTOPILOT_MODE=production
export MCP_URL=https://mcp.your-tailnet.ts.net:8080
export AUTOPILOT_MCP_AUTH=your-token
export SLACK_APP_TOKEN=xapp-...
export SLACK_BOT_TOKEN=xoxb-...

sudo ./install/install.sh --mode bootstrap-openclaw --non-interactive
```

---

## Verifying Your Scenario

After installation, verify everything is configured correctly:

```bash
./install/doctor.sh
```

The doctor will identify any issues and provide specific remediation steps.

---

## Related Projects

- [Wazuh MCP Server](https://github.com/gensecaihq/Wazuh-MCP-Server) - MCP interface for Wazuh
- [OpenClaw](https://github.com/openclaw/openclaw) - Agent orchestration framework
- [Wazuh OpenClaw Autopilot](https://github.com/gensecaihq/Wazuh-Openclaw-Autopilot) - This project
