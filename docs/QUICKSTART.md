# Wazuh OpenClaw Autopilot - Quick Start Guide

Get Wazuh OpenClaw Autopilot running in under 15 minutes.

## Prerequisites

- **Ubuntu 22.04 or 24.04** (other Linux distros may work but are untested)
- **Wazuh** installed and running (Autopilot does not install Wazuh)
- **Wazuh MCP Server** deployed and accessible - [gensecaihq/Wazuh-MCP-Server](https://github.com/gensecaihq/Wazuh-MCP-Server)
- **Root access** for installation

## Choose Your Scenario

### Scenario 1: I have OpenClaw already installed

You just need to install the Autopilot agent pack.

```bash
# Clone the repository
git clone https://github.com/gensecaihq/Wazuh-Openclaw-Autopilot.git
cd Wazuh-Openclaw-Autopilot

# Install agent pack only
sudo ./install/install.sh --mode agent-pack
```

### Scenario 2: I have MCP but no OpenClaw

Autopilot will bootstrap [OpenClaw](https://github.com/openclaw/openclaw) for you.

```bash
# Clone the repository
git clone https://github.com/gensecaihq/Wazuh-Openclaw-Autopilot.git
cd Wazuh-Openclaw-Autopilot

# Bootstrap OpenClaw and install agents
sudo ./install/install.sh --mode bootstrap-openclaw
```

### Scenario 3: Fresh start (Wazuh only)

Complete setup from scratch.

```bash
# Clone the repository
git clone https://github.com/gensecaihq/Wazuh-Openclaw-Autopilot.git
cd Wazuh-Openclaw-Autopilot

# Full installation
sudo ./install/install.sh --mode fresh
```

## Configuration

After installation, configure Autopilot:

```bash
# Edit configuration
sudo nano /etc/wazuh-autopilot/.env
```

**Required settings:**

```bash
# MCP URL (use Tailnet URL for production)
MCP_URL=https://your-mcp-server.tail12345.ts.net:8080

# MCP Authentication
AUTOPILOT_MCP_AUTH=your-mcp-token
```

**Optional Slack configuration:**

```bash
# Slack tokens (for notifications and approvals)
SLACK_APP_TOKEN=xapp-1-...
SLACK_BOT_TOKEN=xoxb-...
```

## Verify Installation

Run the doctor to check everything is working:

```bash
./install/doctor.sh
```

You should see:

```
  ╔═══════════════════════════════════════╗
  ║     ✅ READY (Production)             ║
  ╚═══════════════════════════════════════╝
```

Or for bootstrap mode:

```
  ╔═══════════════════════════════════════╗
  ║     ⚠️  READY (Bootstrap only)         ║
  ╚═══════════════════════════════════════╝
```

## Start the Service

```bash
# Start Autopilot service
sudo systemctl start wazuh-autopilot

# Enable on boot
sudo systemctl enable wazuh-autopilot

# Check status
sudo systemctl status wazuh-autopilot
```

## Test It Out

### Test triage (if Slack is configured)

In your Slack workspace:

```
/wazuh triage <alert_id>
```

### Check metrics

```bash
curl http://localhost:9090/metrics
```

### View cases

```bash
ls /var/lib/wazuh-autopilot/cases/
```

## Next Steps

1. **Configure policies** - Review and customize `policies/policy.yaml`
2. **Set up Slack** - See [SLACK_SOCKET_MODE.md](SLACK_SOCKET_MODE.md)
3. **Production mode** - See [TAILSCALE_MANDATORY.md](TAILSCALE_MANDATORY.md)
4. **Review playbooks** - Understand the response workflows in `playbooks/`

## Troubleshooting

### Doctor shows "NOT READY"

Run doctor and follow the remediation steps:

```bash
./install/doctor.sh
```

### Service won't start

Check logs:

```bash
sudo journalctl -u wazuh-autopilot -f
```

### MCP connection fails

1. Verify MCP URL is correct
2. Check authentication token
3. Ensure network connectivity (Tailscale if production mode)

See [TROUBLESHOOTING.md](TROUBLESHOOTING.md) for more help.

## Related Projects

- [Wazuh MCP Server](https://github.com/gensecaihq/Wazuh-MCP-Server) - MCP interface for Wazuh
- [OpenClaw](https://github.com/openclaw/openclaw) - Agent orchestration framework
