# Deployment Scenarios

Wazuh Autopilot supports multiple deployment architectures. The installer runs a single guided flow — you adapt the resulting configuration for your scenario.

## Quick Reference

| Scenario | Use Case | Installation |
|----------|----------|-------------|
| All-in-One | Dev/Test, small deployments | `sudo ./install/install.sh` |
| Air-Gapped | No internet, Ollama-only | `sudo ./install/install.sh --skip-tailscale` |
| Distributed | MCP on different server | Install on each server, configure MCP_URL |
| Docker Compose | Containerized deployment | See Scenario 6 |
| Kubernetes | Cloud-native deployment | See Scenario 7 |

## Installer Options

```bash
# Standard installation (with Tailscale)
sudo ./install/install.sh

# Air-gapped / bootstrap (skip Tailscale)
sudo ./install/install.sh --skip-tailscale

# Or set the environment variable
export AUTOPILOT_MODE=bootstrap
sudo ./install/install.sh
```

---

## Scenario 1: All-in-One (Single Server)

**Best for:** Development, testing, small deployments

```
┌─────────────────────────────────────────────────────────────┐
│                      SINGLE SERVER                          │
│                                                             │
│  ┌─────────┐  ┌─────────┐  ┌─────────┐  ┌─────────┐       │
│  │ Wazuh   │─▶│   MCP   │─▶│OpenClaw │─▶│ Runtime │       │
│  │ Manager │  │ :8080   │  │ :3000   │  │ :9090   │       │
│  └─────────┘  └─────────┘  └─────────┘  └─────────┘       │
│                                                             │
│            All communication via localhost                  │
└─────────────────────────────────────────────────────────────┘
```

### Installation

```bash
sudo ./install/install.sh
```

### What Gets Installed

- Tailscale (for future production transition)
- Docker + Docker Compose
- OpenClaw (containerized)
- Autopilot Runtime (systemd service)
- All agents and policies

### Configuration

```bash
# Edit configuration
sudo nano /etc/wazuh-autopilot/.env

# Set MCP URL (localhost for all-in-one)
MCP_URL=http://127.0.0.1:8080
```

---

## Scenario 2: OpenClaw + Runtime (MCP Elsewhere)

**Best for:** Separating security data from AI processing

```
┌─────────────────────────┐      ┌─────────────────────────┐
│      SERVER A           │      │      SERVER B           │
│   (Security Data)       │      │   (AI Processing)       │
│                         │      │                         │
│  ┌─────────┐            │      │            ┌─────────┐ │
│  │ Wazuh   │            │      │            │OpenClaw │ │
│  │ Manager │            │      │            └────┬────┘ │
│  └────┬────┘            │      │                 │      │
│       │                 │      │            ┌────┴────┐ │
│  ┌────┴────┐            │ HTTP │            │ Runtime │ │
│  │   MCP   │◀───────────│──────│────────────┤ :9090   │ │
│  │ :8080   │            │      │            └─────────┘ │
│  └─────────┘            │      │                        │
└─────────────────────────┘      └─────────────────────────┘
```

### Installation (on Server B)

```bash
sudo ./install/install.sh
# Then edit /etc/wazuh-autopilot/.env to set MCP_URL
```

### Configuration

```bash
# Server B configuration
MCP_URL=https://server-a.example.com:8080
# Or with Tailscale
MCP_URL=https://server-a.tail12345.ts.net:8080
```

---

## Scenario 3: Runtime Only

**Best for:** OpenClaw managed separately, just need evidence/metrics

```
┌─────────────┐  ┌─────────────┐  ┌─────────────┐
│ Server A    │  │ Server B    │  │ Server C    │
│ Wazuh + MCP │◀─│ OpenClaw    │  │ Runtime     │
└─────────────┘  └─────────────┘  └─────────────┘
```

### Installation (on Server C)

```bash
sudo ./install/install.sh
# Then edit /etc/wazuh-autopilot/.env to set MCP_URL
```

### What Gets Installed

- Node.js runtime
- Autopilot Runtime service
- Agent configs (for reference)

---

## Scenario 4: Agent Pack (Local OpenClaw)

**Best for:** Adding Wazuh agents to existing OpenClaw installation

```
┌────────────────────────────────────────┐
│              THIS SERVER               │
│                                        │
│  ┌────────────────────────────────┐   │
│  │     Existing OpenClaw          │   │
│  │  ┌──────────────────────────┐  │   │
│  │  │  + Wazuh Agents Added    │  │   │
│  │  └──────────────────────────┘  │   │
│  └────────────────────────────────┘   │
└────────────────────────────────────────┘
```

### Installation

```bash
sudo ./install/install.sh
```

### What Happens

1. Detects existing OpenClaw installation
2. Copies agent workspace files to `/etc/wazuh-autopilot/agents/`
3. Creates symlinks in OpenClaw's agents directory
4. Copies policies and playbooks

### Post-Installation

```bash
# Restart OpenClaw to load new agents
sudo systemctl restart openclaw
# or
docker restart openclaw
```

---

## Scenario 5: Agent Pack (Remote OpenClaw)

**Best for:** OpenClaw on a different server

```
┌─────────────────────┐  SSH   ┌─────────────────────┐
│    THIS MACHINE     │───────▶│   REMOTE SERVER     │
│  (run installer)    │        │   (OpenClaw)        │
│                     │        │                     │
│  agents/*/ ─────────│────────│─▶ /opt/openclaw/    │
│  policies/*.yaml ───│────────│─▶    agents/        │
└─────────────────────┘        └─────────────────────┘
```

### Installation

```bash
# Copy agent files to the remote server manually
scp -r openclaw/agents/* admin@openclaw.example.com:/opt/openclaw/agents/
```

### Requirements

- SSH access to remote server
- SSH key authentication recommended

### What Happens

1. Connects to remote server via SSH
2. Creates agents directory if needed
3. Copies all agent workspace files (AGENTS.md, IDENTITY.md, TOOLS.md, MEMORY.md, etc.)
4. Copies policy configurations

---

## Scenario 6: Docker Compose

**Best for:** Containerized environments, easy deployment

```
┌──────────────────────────────────────────────────────┐
│                  Docker Network                       │
│                                                       │
│  ┌──────────┐  ┌──────────┐  ┌──────────┐           │
│  │  wazuh   │  │   mcp    │  │ openclaw │           │
│  │ :55000   │──│  :8080   │──│  :3000   │           │
│  └──────────┘  └──────────┘  └──────────┘           │
│                      │                               │
│                ┌─────┴─────┐                         │
│                │  runtime  │                         │
│                │   :9090   │                         │
│                └───────────┘                         │
└──────────────────────────────────────────────────────┘
```

### Configuration

The `docker-compose.yml` at the project root provides a production-ready deployment:

```bash
# Copy and edit environment variables
cp .env.example .env
nano .env

# Start services
docker-compose up -d

# View logs
docker-compose logs -f
```

---

## Scenario 7: Kubernetes

**Best for:** Cloud-native, scalable deployments

### Deploy

Create Kubernetes manifests for your cluster. Example:

```bash
# Create namespace
kubectl create namespace wazuh-autopilot

# Create ConfigMaps from agent files
kubectl create configmap autopilot-agents \
  -n wazuh-autopilot \
  --from-file=openclaw/agents/

kubectl create configmap autopilot-runtime \
  -n wazuh-autopilot \
  --from-file=runtime/autopilot-service/

# Create secrets from .env
kubectl create secret generic autopilot-secrets \
  -n wazuh-autopilot \
  --from-env-file=.env

# Deploy (create your own deployment manifest)
kubectl apply -f your-deployment.yaml
```

---

## Scenario 8: Cloud Hybrid

**Best for:** On-prem Wazuh, cloud AI processing

```
┌─────────────────────────────────────────────────────────────────┐
│                      ON-PREMISES                                │
│  ┌───────────────────────────────────────────────────────────┐ │
│  │                    DMZ / Secure Zone                       │ │
│  │  ┌─────────┐    ┌─────────┐                               │ │
│  │  │ Wazuh   │───▶│   MCP   │──── Tailscale ────┐          │ │
│  │  │ Manager │    │ :8080   │                    │          │ │
│  │  └─────────┘    └─────────┘                    │          │ │
│  └────────────────────────────────────────────────│──────────┘ │
└───────────────────────────────────────────────────│─────────────┘
                                                    │
                              ┌─────────────────────┘
                              │ Encrypted Tunnel
                              ▼
┌─────────────────────────────────────────────────────────────────┐
│                         CLOUD (AWS/GCP/Azure)                   │
│  ┌───────────────────────────────────────────────────────────┐ │
│  │  ┌─────────────┐    ┌─────────────┐    ┌─────────────┐   │ │
│  │  │  OpenClaw   │───▶│   Runtime   │───▶│  S3/Blob    │   │ │
│  │  │  (EKS/GKE)  │    │             │    │  Evidence   │   │ │
│  │  └─────────────┘    └─────────────┘    └─────────────┘   │ │
│  └───────────────────────────────────────────────────────────┘ │
└─────────────────────────────────────────────────────────────────┘
```

### Setup

Run the standard installer in the cloud, then configure `MCP_URL` to point to the on-prem MCP via Tailscale.

---

## Network Requirements

| From | To | Port | Protocol |
|------|-----|------|----------|
| OpenClaw | MCP | 8080 | HTTPS |
| Runtime | MCP | 8080 | HTTPS |
| MCP | Wazuh API | 55000 | HTTPS |
| Runtime | Slack | 443 | HTTPS |
| Prometheus | Runtime | 9090 | HTTP |

---

## Deployment States

### Bootstrap Mode (Evaluation/Testing)

```bash
AUTOPILOT_MODE=bootstrap
```

- MCP can be any reachable URL
- Tailscale not required
- Doctor shows: `⚠️ READY (Bootstrap only)`

### Production Mode (Recommended)

```bash
AUTOPILOT_MODE=production
AUTOPILOT_REQUIRE_TAILSCALE=true
```

- MCP must be a Tailnet URL
- Tailscale required
- Doctor shows: `✅ READY (Production)`

### Transition to Production

```bash
# 1. Install and authenticate Tailscale
sudo tailscale up

# 2. Update MCP_URL in /etc/wazuh-autopilot/.env to use Tailnet address
# 3. Set AUTOPILOT_MODE=production
# 4. Restart services
sudo systemctl restart wazuh-mcp-server wazuh-autopilot
```

---

## Non-Interactive Installation

```bash
export AUTOPILOT_MODE=production
export MCP_URL=https://mcp.your-tailnet.ts.net:8080
export AUTOPILOT_MCP_AUTH=your-token

sudo ./install/install.sh
```

---

## Verifying Installation

```bash
./install/doctor.sh
```

---

## Related Projects

- [Wazuh MCP Server](https://github.com/gensecaihq/Wazuh-MCP-Server)
- [OpenClaw](https://github.com/openclaw/openclaw)
