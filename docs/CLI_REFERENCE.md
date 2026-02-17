# CLI Reference

Complete command-line reference for Wazuh Autopilot installer and management tools.

## Installer Commands

### Basic Usage

```bash
# Standard installation (interactive)
sudo ./install/install.sh

# Air-gapped / bootstrap (skip Tailscale)
sudo ./install/install.sh --skip-tailscale

# Show help
sudo ./install/install.sh --help

# Show version
sudo ./install/install.sh --version
```

### Command-Line Options

| Option | Description | Example |
|--------|-------------|---------|
| `--skip-tailscale` | Skip Tailscale installation (air-gapped/bootstrap) | `--skip-tailscale` |
| `--help` | Show help message | `--help` |
| `--version` | Show version | `--version` |

### Environment Variables

Set these before running the installer:

```bash
# Deployment mode
export AUTOPILOT_MODE=bootstrap           # Skips Tailscale automatically
export AUTOPILOT_MODE=production          # Full install with Tailscale (default)

# Slack Configuration (prompted during install if not set)
export SLACK_APP_TOKEN=xapp-1-...
export SLACK_BOT_TOKEN=xoxb-...
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
| `/wazuh help` | Show available commands |
| `/wazuh status` | Check responder status |
| `/wazuh plans [state]` | List plans (proposed/approved/completed) |
| `/wazuh approve <plan_id>` | Approve a plan (Tier 1) |
| `/wazuh execute <plan_id>` | Execute an approved plan (Tier 2) |
| `/wazuh reject <plan_id> [reason]` | Reject a plan |

---

## Diagnostics

### Doctor Command

```bash
# Run full diagnostics
./install/doctor.sh
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
ls ~/.openclaw/wazuh-autopilot/agents/triage/
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
| `~/.openclaw/wazuh-autopilot/agents/` | Agent workspace directories (AGENTS.md, IDENTITY.md, TOOLS.md, etc.) |
| `/etc/wazuh-autopilot/policies/` | Policy definitions |
| `/etc/wazuh-autopilot/playbooks/` | Response playbooks |
| `/etc/wazuh-autopilot/runtime/` | Runtime service code |
| `/var/lib/wazuh-autopilot/cases/` | Evidence packs |
| `/var/lib/wazuh-autopilot/reports/` | Generated reports |
| `/var/lib/wazuh-autopilot/state/` | Service state |
| `/opt/openclaw/` | OpenClaw installation |
