# CLI Reference

Complete command-line reference for Wazuh Autopilot installer and management tools.

## Installer Commands

### Basic Usage

```bash
# Interactive mode (recommended for first installation)
sudo ./install/install.sh

# Interactive menu
sudo ./install/install.sh --menu
```

### Installation Modes

```bash
# All-in-One: Everything on single server
sudo ./install/install.sh --mode all-in-one

# OpenClaw + Runtime: For remote MCP
sudo ./install/install.sh --mode openclaw-runtime \
  --mcp-url https://mcp-server:8080 \
  --mcp-auth YOUR_TOKEN

# Runtime Only: Just runtime service
sudo ./install/install.sh --mode runtime-only \
  --mcp-url https://mcp-server:8080

# Agent Pack: Copy agents to existing local OpenClaw
sudo ./install/install.sh --mode agent-pack

# Remote OpenClaw: Copy agents to remote server
sudo ./install/install.sh --mode remote-openclaw \
  --remote-host openclaw.example.com \
  --remote-user admin \
  --remote-path /opt/openclaw/agents

# Docker Compose: Generate docker-compose.yml
sudo ./install/install.sh --mode docker \
  --output-dir ./deploy/docker

# Kubernetes: Generate K8s manifests
sudo ./install/install.sh --mode kubernetes \
  --output-dir ./deploy/k8s

# Doctor: Run diagnostics
sudo ./install/install.sh --mode doctor

# Cutover: Transition to production mode
sudo ./install/install.sh --mode cutover
```

### Command-Line Options

| Option | Description | Example |
|--------|-------------|---------|
| `--mode <mode>` | Installation mode (see above) | `--mode all-in-one` |
| `--mcp-url <url>` | MCP server URL | `--mcp-url https://mcp:8080` |
| `--mcp-auth <token>` | MCP authentication token | `--mcp-auth abc123` |
| `--remote-host <host>` | Remote server hostname | `--remote-host server.com` |
| `--remote-user <user>` | SSH username | `--remote-user admin` |
| `--remote-path <path>` | Remote agents path | `--remote-path /opt/openclaw/agents` |
| `--output-dir <dir>` | Output directory for manifests | `--output-dir ./deploy` |
| `--non-interactive` | Skip prompts, use defaults | `--non-interactive` |
| `--force` | Force overwrite existing files | `--force` |
| `--help` | Show help message | `--help` |
| `--version` | Show version | `--version` |

### Environment Variables

Set these before running the installer for non-interactive configuration:

```bash
# Deployment mode
export AUTOPILOT_MODE=production          # bootstrap | production

# MCP Configuration
export MCP_URL=https://mcp.ts.net:8080
export MCP_BOOTSTRAP_URL=http://localhost:8080
export AUTOPILOT_MCP_AUTH=your-token

# Slack Configuration
export SLACK_APP_TOKEN=xapp-1-...
export SLACK_BOT_TOKEN=xoxb-...

# Storage Paths
export AUTOPILOT_DATA_DIR=/var/lib/wazuh-autopilot
export AUTOPILOT_CONFIG_DIR=/etc/wazuh-autopilot
export OPENCLAW_HOME=/opt/openclaw

# Feature Flags
export AUTOPILOT_ENABLE_RESPONDER=false   # Enable action execution
export AUTOPILOT_REQUIRE_TAILSCALE=true   # Require Tailscale in production
```

---

## Service Management

### Systemd Commands

```bash
# Start the service
sudo systemctl start wazuh-autopilot

# Stop the service
sudo systemctl stop wazuh-autopilot

# Restart the service
sudo systemctl restart wazuh-autopilot

# Check status
sudo systemctl status wazuh-autopilot

# Enable auto-start
sudo systemctl enable wazuh-autopilot

# View logs
sudo journalctl -u wazuh-autopilot -f

# View recent logs
sudo journalctl -u wazuh-autopilot --since "1 hour ago"
```

### Docker Commands (for OpenClaw)

```bash
# Start OpenClaw
cd /opt/openclaw && docker-compose up -d

# Stop OpenClaw
cd /opt/openclaw && docker-compose down

# View logs
docker logs -f openclaw

# Restart after agent changes
docker restart openclaw
```

---

## Runtime Service API

### Health Check

```bash
# Check service health
curl http://127.0.0.1:9090/health

# Check readiness
curl http://127.0.0.1:9090/ready

# Get version
curl http://127.0.0.1:9090/version
```

### Metrics

```bash
# Prometheus metrics
curl http://127.0.0.1:9090/metrics
```

### Cases API

```bash
# List all cases
curl http://127.0.0.1:9090/api/cases

# Get specific case
curl http://127.0.0.1:9090/api/cases/CASE-20260217-abc12345

# Create new case (requires auth for non-localhost)
curl -X POST http://127.0.0.1:9090/api/cases \
  -H "Content-Type: application/json" \
  -d '{"case_id": "CASE-20260217-abc12345", "title": "Test Case", "severity": "high"}'

# Update case
curl -X PUT http://127.0.0.1:9090/api/cases/CASE-20260217-abc12345 \
  -H "Content-Type: application/json" \
  -d '{"status": "closed"}'
```

---

## Slack Commands

When integrated with Slack, the following commands are available:

| Command | Description |
|---------|-------------|
| `/wazuh triage <alert_id>` | Manually triage a specific alert |
| `/wazuh triage-batch <query>` | Batch triage alerts matching query |
| `/wazuh investigate <case_id>` | Deep investigation on a case |
| `/wazuh correlate <case_id>` | Find related alerts/cases |
| `/wazuh plan <case_id>` | Generate response plan |
| `/wazuh execute <plan_id>` | Execute approved plan |
| `/wazuh rollback <execution_id>` | Rollback executed action |
| `/wazuh halt` | Emergency halt all executions |
| `/wazuh status` | Show system status |
| `/wazuh report <period>` | Generate summary report |

---

## Diagnostics

### Doctor Command

```bash
# Run full diagnostics
sudo ./install/install.sh --mode doctor
```

Doctor checks:
- Operating system compatibility
- Required dependencies (curl, jq, node)
- Tailscale status and connectivity
- Docker status
- OpenClaw installation and status
- MCP connectivity
- Runtime service health
- Configuration file validity
- Disk space

### Manual Checks

```bash
# Check Tailscale status
tailscale status

# Check Docker containers
docker ps

# Check MCP connectivity
curl -s https://your-mcp-server:8080/health

# Check runtime metrics
curl -s http://127.0.0.1:9090/metrics | grep autopilot

# View evidence packs
ls -la /var/lib/wazuh-autopilot/cases/

# Check configuration
cat /etc/wazuh-autopilot/.env
```

---

## Troubleshooting

### Common Issues

**Service won't start:**
```bash
# Check logs for errors
sudo journalctl -u wazuh-autopilot -n 50

# Verify configuration
cat /etc/wazuh-autopilot/.env

# Check file permissions
ls -la /etc/wazuh-autopilot/
ls -la /var/lib/wazuh-autopilot/
```

**MCP connection failed:**
```bash
# Test MCP directly
curl -v https://mcp-server:8080/health

# Check Tailscale connectivity (if using)
tailscale ping mcp-server

# Verify auth token
curl -H "Authorization: Bearer $AUTOPILOT_MCP_AUTH" \
  https://mcp-server:8080/health
```

**Agent not loading:**
```bash
# Check agent workspace files exist
ls /etc/wazuh-autopilot/agents/triage/
# Expected: AGENTS.md IDENTITY.md TOOLS.md MEMORY.md HEARTBEAT.md SOUL.md USER.md

# Restart OpenClaw
docker restart openclaw

# Check OpenClaw logs
docker logs openclaw
```

---

## File Locations

| Path | Description |
|------|-------------|
| `/etc/wazuh-autopilot/.env` | Environment configuration |
| `/etc/wazuh-autopilot/agents/` | Agent workspace directories (AGENTS.md, IDENTITY.md, TOOLS.md, etc.) |
| `/etc/wazuh-autopilot/policies/` | Policy definitions |
| `/etc/wazuh-autopilot/playbooks/` | Response playbooks |
| `/etc/wazuh-autopilot/runtime/` | Runtime service code |
| `/var/lib/wazuh-autopilot/cases/` | Evidence packs |
| `/var/lib/wazuh-autopilot/reports/` | Generated reports |
| `/var/lib/wazuh-autopilot/state/` | Service state |
| `/opt/openclaw/` | OpenClaw installation |
