# Deployment Scenarios

Wazuh Autopilot supports multiple deployment architectures to fit your infrastructure.

## Quick Reference

| Scenario | Use Case | Command |
|----------|----------|---------|
| All-in-One | Dev/Test, small deployments | `--mode all-in-one` |
| OpenClaw + Runtime | MCP on different server | `--mode openclaw-runtime` |
| Runtime Only | OpenClaw also elsewhere | `--mode runtime-only` |
| Agent Pack (Local) | Existing local OpenClaw | `--mode agent-pack` |
| Agent Pack (Remote) | Existing remote OpenClaw | `--mode remote-openclaw` |
| Docker Compose | Containerized deployment | `--mode docker` |
| Kubernetes | Cloud-native deployment | `--mode kubernetes` |

## Interactive Menu

Run the installer without arguments or with `--menu` for an interactive experience:

```bash
sudo ./install/install.sh
# or
sudo ./install/install.sh --menu
```

```
╔═══════════════════════════════════════════════════════════════════╗
║           Wazuh Autopilot Installer v2.1.0                        ║
║       Autonomous SOC Layer for Wazuh via OpenClaw Agents          ║
╚═══════════════════════════════════════════════════════════════════╝

Select your deployment scenario:

  Single Server:
    1) All-in-One         - Wazuh + MCP + OpenClaw + Runtime on this server

  Distributed (MCP on remote server):
    2) OpenClaw + Runtime - Install OpenClaw and Runtime here (MCP elsewhere)
    3) Runtime Only       - Just the Runtime service (OpenClaw also elsewhere)

  Existing OpenClaw:
    4) Agent Pack (Local) - Add agents to existing local OpenClaw
    5) Agent Pack (Remote)- Copy agents to remote OpenClaw via SSH

  Container Deployments:
    6) Docker Compose     - Generate docker-compose.yml
    7) Kubernetes         - Generate K8s manifests

  Utilities:
    8) Doctor             - Run diagnostics
    9) Cutover            - Transition to production mode (Tailscale)
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
sudo ./install/install.sh --mode all-in-one
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
sudo ./install/install.sh --mode openclaw-runtime \
  --mcp-url https://server-a:8080 \
  --mcp-auth your-token
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
sudo ./install/install.sh --mode runtime-only \
  --mcp-url https://server-a:8080
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
sudo ./install/install.sh --mode agent-pack
```

### What Happens

1. Detects existing OpenClaw installation
2. Copies agent YAML files to `/etc/wazuh-autopilot/agents/`
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
│  agents/*.yaml ─────│────────│─▶ /opt/openclaw/    │
│  policies/*.yaml ───│────────│─▶    agents/        │
└─────────────────────┘        └─────────────────────┘
```

### Installation

```bash
./install/install.sh --mode remote-openclaw \
  --remote-host openclaw.example.com \
  --remote-user admin
```

### Requirements

- SSH access to remote server
- SSH key authentication recommended

### What Happens

1. Connects to remote server via SSH
2. Creates agents directory if needed
3. Copies all agent YAML files
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

### Generate Files

```bash
./install/install.sh --mode docker --output-dir ./deploy/docker
```

### Generated Files

```
deploy/docker/
├── docker-compose.yml
├── .env
├── agents/
├── config/
└── runtime/
```

### Deploy

```bash
cd deploy/docker
# Edit .env with your credentials
nano .env

# Start services
docker-compose up -d

# View logs
docker-compose logs -f
```

---

## Scenario 7: Kubernetes

**Best for:** Cloud-native, scalable deployments

### Generate Manifests

```bash
./install/install.sh --mode kubernetes --output-dir ./deploy/k8s
```

### Generated Files

```
deploy/k8s/
├── namespace.yaml
├── configmap.yaml
├── configmap-agents.yaml
├── secret.yaml
└── deployment.yaml
```

### Deploy

```bash
cd deploy/k8s

# Create namespace
kubectl apply -f namespace.yaml

# Create ConfigMaps from agent files
kubectl create configmap autopilot-agents \
  -n wazuh-autopilot \
  --from-file=../../agents/

kubectl create configmap autopilot-runtime \
  -n wazuh-autopilot \
  --from-file=../../runtime/autopilot-service/

# Apply remaining manifests
kubectl apply -f .
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

Use `--mode openclaw-runtime` in the cloud, with Tailscale connecting to on-prem MCP.

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
sudo ./install/install.sh --mode cutover
```

---

## Non-Interactive Installation

```bash
export AUTOPILOT_MODE=production
export MCP_URL=https://mcp.your-tailnet.ts.net:8080
export AUTOPILOT_MCP_AUTH=your-token

sudo ./install/install.sh --mode all-in-one --non-interactive
```

---

## Verifying Installation

```bash
./install/install.sh --mode doctor
```

---

## Related Projects

- [Wazuh MCP Server](https://github.com/gensecaihq/Wazuh-MCP-Server)
- [OpenClaw](https://github.com/openclaw/openclaw)
