# Troubleshooting Guide

Common issues and their solutions for Wazuh Autopilot.

## Quick Diagnostics

Always start by running the doctor:

```bash
./install/doctor.sh
```

This identifies most common issues and provides specific remediation steps.

## Installation Issues

### "This script must be run as root"

**Solution:**
```bash
sudo ./install/install.sh
```

### "Ubuntu version not supported"

Autopilot is tested on Ubuntu 22.04 and 24.04, Debian 11/12, and RHEL-based distros. Other versions may work but are unsupported.

### "OpenClaw not found"

OpenClaw must be installed first. The installer will attempt to install it automatically. If it fails, install manually:

```bash
curl -fsSL https://openclaw.ai/install.sh | sh
```

### Docker installation fails

**Check Docker status:**
```bash
systemctl status docker
```

**Manual Docker installation:**
```bash
curl -fsSL https://get.docker.com | sh
systemctl enable docker
systemctl start docker
```

## Configuration Issues

### "No MCP URL configured"

**Solution:**

Edit `/etc/wazuh-autopilot/.env`:
```bash
MCP_URL=https://your-mcp-server:8080
# OR for bootstrap mode:
MCP_BOOTSTRAP_URL=http://192.168.1.100:8080
```

### "MCP authentication failed"

1. Verify your token is correct
2. Check token hasn't expired
3. Ensure token has correct permissions

**Test manually:**
```bash
curl -H "Authorization: Bearer YOUR_TOKEN" \
  https://your-mcp-server:8080/health
```

### "Production mode requires Tailnet MCP URL"

In production mode, MCP_URL must be a Tailnet address.

**Options:**

1. Switch to bootstrap mode (for testing):
   ```bash
   AUTOPILOT_MODE=bootstrap
   ```

2. Set up Tailnet properly:
   ```bash
   # Update .env: set AUTOPILOT_MODE=production and MCP_URL to Tailnet address
   sudo systemctl restart wazuh-autopilot
   ```

## Connectivity Issues

### "Cannot connect to MCP"

**Check network connectivity:**
```bash
# Test basic connectivity
ping mcp-server.tail123.ts.net

# Test HTTP
curl -v https://mcp-server.tail123.ts.net:8080/health
```

**If using Tailscale:**
```bash
# Check Tailscale status
tailscale status

# Check if MCP host is visible
tailscale ping mcp-server
```

**Check firewall:**
```bash
# On Autopilot host
sudo ufw status

# On MCP host
sudo ufw status
```

### "Tailscale not running"

**Start Tailscale:**
```bash
sudo tailscale up
```

**If not authenticated:**
```bash
# This will provide an auth URL
sudo tailscale up
```

### MCP returns "401 Unauthorized"

1. Check `AUTOPILOT_MCP_AUTH` is set
2. Verify token format is correct
3. Check if token has expired

### MCP returns "403 Forbidden"

The token is valid but doesn't have required permissions.

**Solution:** Generate a new token with appropriate scopes on your MCP server.

## Slack Issues

### "Invalid token" errors

**Verify token format:**
- App Token should start with `xapp-`
- Bot Token should start with `xoxb-`

**Test tokens:**
```bash
# Test Bot Token
curl -H "Authorization: Bearer xoxb-YOUR-TOKEN" \
  https://slack.com/api/auth.test
```

### Bot doesn't respond to commands

1. **Check Socket Mode is enabled** in Slack App settings

2. **Verify service is running:**
   ```bash
   systemctl status wazuh-autopilot
   ```

3. **Check logs for errors:**
   ```bash
   journalctl -u wazuh-autopilot -f
   ```

4. **Ensure bot is in the channel:**
   ```
   /invite @Wazuh Autopilot
   ```

### "Channel not allowed"

Update `policies/policy.yaml` with the correct channel ID.

**Find channel ID:**
- Right-click channel name → Copy link
- ID is at the end: `.../archives/C0123456789`

### Messages not posting

1. Verify `chat:write` scope in Slack App
2. Check channel is in allowlist
3. Verify bot has access to channel

## Service Issues

### Service won't start

**Check logs:**
```bash
journalctl -u wazuh-autopilot -n 50
```

**Common causes:**
- Configuration file missing
- Invalid configuration values
- Port already in use

**Verify configuration:**
```bash
cat /etc/wazuh-autopilot/.env
```

### Service crashes repeatedly

**Check for resource issues:**
```bash
free -h
df -h
```

**Check Node.js:**
```bash
node --version  # Should be 18+
```

**View crash logs:**
```bash
journalctl -u wazuh-autopilot --since "1 hour ago"
```

### Port 9090 already in use

**Find what's using it:**
```bash
ss -tlnp | grep 9090
```

**Change Autopilot's port:**
```bash
# In /etc/wazuh-autopilot/.env
RUNTIME_PORT=9091
```

## Agent Issues

### "Agent not found" errors

**Verify agents are installed:**
```bash
ls ~/.openclaw/wazuh-autopilot/agents/
```

**Reinstall agents:**
```bash
sudo ./install/install.sh
```

### Agent file validation errors

**Check agent files exist:**
```bash
ls ~/.openclaw/wazuh-autopilot/agents/triage/
# Expected: AGENTS.md IDENTITY.md TOOLS.md MEMORY.md HEARTBEAT.md SOUL.md USER.md
```

### Agents not loading in OpenClaw

1. Check OpenClaw is running
2. Verify agent directory is linked:
   ```bash
   ls -la /opt/openclaw/agents
   ```
3. Restart OpenClaw after adding agents

## Policy Issues

### "Action not allowed"

1. Check `actions.enabled: true` in policy.yaml
2. Verify specific action is in allowlist
3. Check action's `enabled: true`

**Debug policy evaluation:**
```bash
# Check logs for policy decisions
journalctl -u wazuh-autopilot | grep "policy"
```

### "Approver not authorized"

1. Verify approver's Slack ID in policy
2. Check approver is in appropriate group
3. Verify group can approve this action type

### Approvals timing out

Default TTL is 60 minutes.

**Extend if needed:**
```bash
# In .env
APPROVAL_TOKEN_TTL_MINUTES=120
```

## MCP Connectivity Issues

### "Most MCP endpoints not responding"

This is almost always a configuration issue, not a version incompatibility. Follow this 6-step diagnostic process:

**Step 1 — Verify Wazuh API is reachable:**

```bash
curl -k -u YOUR_WAZUH_USER:YOUR_PASSWORD https://YOUR_WAZUH_HOST:55000/
```

You should get a JSON response with manager info. If this fails, the problem is Wazuh API access (firewall, credentials, or the API service is not running).

**Step 2 — Check MCP server logs:**

```bash
# If running as Docker:
docker logs wazuh-mcp-server 2>&1 | tail -50

# If running as systemd:
journalctl -u wazuh-mcp-server -n 50
```

Look for authentication errors, connection timeouts, or SSL certificate issues.

**Step 3 — SSL certificate issues:**

Wazuh uses self-signed certificates by default. If the MCP server can't verify the cert, all requests will fail:

```bash
# In MCP server .env:
WAZUH_VERIFY_SSL=false
WAZUH_ALLOW_SELF_SIGNED=true
```

**Step 4 — Wazuh API user permissions:**

Ensure the API user has the correct roles. The default `wazuh-wui` user should have sufficient permissions, but custom users may need additional roles.

**Step 5 — Wazuh Indexer (for vulnerability tools only):**

3 of the 29 MCP tools (vulnerability scanning) require the Wazuh Indexer (OpenSearch, port 9200). If you don't have the Indexer running, those 3 tools will fail — but the other 26 should work:

```bash
# Check if Indexer is configured in MCP:
WAZUH_INDEXER_HOST=https://YOUR_INDEXER_HOST:9200
WAZUH_INDEXER_USER=admin
WAZUH_INDEXER_PASS=your_password
```

**Step 6 — Network connectivity:**

```bash
# From the MCP server host, test Wazuh API:
curl -k https://YOUR_WAZUH_HOST:55000/ -o /dev/null -w "%{http_code}" -s
# Should return 401 (auth required) or 200 — not 000 (connection refused)
```

### Wazuh version compatibility

| Wazuh Version | MCP Support | Notes |
|---------------|------------|-------|
| **4.14.x** | Fully supported | All 29 tools work |
| 4.10.x – 4.13.x | Fully supported | All features |
| 4.8.x – 4.9.x | Fully supported | Minimum for vulnerability tools |
| 4.0.0 – 4.7.x | Limited | 3 vulnerability tools unavailable |

### MCP authentication failed

1. Verify `AUTOPILOT_MCP_AUTH` token matches the MCP server's `MCP_AUTH_TOKEN`
2. Check the token has no extra whitespace or newlines
3. Test manually:
   ```bash
   curl -H "Authorization: Bearer $AUTOPILOT_MCP_AUTH" \
     https://mcp-server:8080/health
   ```

---

## MCP Tool Issues

### "Required tool not found"

Your MCP server may use different tool names.

**Update toolmap.yaml:**
```yaml
read_operations:
  get_alert:
    mcp_tool: your_actual_tool_name  # Change this
```

**Discover available tools:**
```bash
curl -H "Authorization: Bearer TOKEN" \
  https://mcp-server:8080/tools
```

### Tool calls timing out

**Increase timeout:**
```bash
# In .env
MCP_TIMEOUT_MS=60000
```

### Tool calls failing intermittently

**Check MCP server logs** for errors.

**Verify MCP server resources** (CPU, memory, disk).

**Check network stability** between Autopilot and MCP.

## Data Issues

### Cases not being created

1. Check data directory permissions:
   ```bash
   ls -la /var/lib/wazuh-autopilot/
   ```

2. Ensure directory exists:
   ```bash
   mkdir -p /var/lib/wazuh-autopilot/cases
   ```

### Evidence packs corrupted

**Check JSON validity:**
```bash
cat /var/lib/wazuh-autopilot/cases/CASE-ID/evidence-pack.json | jq .
```

**If corrupted, check for disk issues:**
```bash
dmesg | grep -i error
```

## Metrics Issues

### Metrics endpoint not responding

1. Check service is running
2. Verify port is listening:
   ```bash
   ss -tlnp | grep 9090
   ```
3. Check metrics are enabled in config

### Missing metrics

Some metrics only appear after their first occurrence. Trigger the relevant action to create the metric.

### High memory usage

If metrics are consuming too much memory, you may have too many unique label combinations.

**Reset metrics:**
```bash
systemctl restart wazuh-autopilot
```

## Getting Help

### Collect Diagnostic Information

```bash
# System info
uname -a
cat /etc/os-release

# Autopilot status
./install/doctor.sh > diagnostics.txt 2>&1

# Service logs
journalctl -u wazuh-autopilot --since "24 hours ago" >> diagnostics.txt

# Configuration (redact secrets!)
grep -v TOKEN /etc/wazuh-autopilot/.env >> diagnostics.txt
```

### Log Files

| Component | Location |
|-----------|----------|
| Autopilot service | `journalctl -u wazuh-autopilot` |
| OpenClaw | `docker logs openclaw` or `/opt/openclaw/logs/` |
| Tailscale | `journalctl -u tailscaled` |

### Reporting Issues

When reporting issues, include:

1. Doctor output
2. Relevant log excerpts
3. Steps to reproduce
4. Expected vs actual behavior

**Do not include:**
- API tokens
- Passwords
- Sensitive case data
