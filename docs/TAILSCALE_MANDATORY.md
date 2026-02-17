# Tailscale: Mandatory for Production

Wazuh Autopilot uses Tailscale as the foundation for secure production deployments. This document explains why and how to set it up.

## Why Tailscale is Required

### Security Benefits

1. **Zero Trust Networking** - Every connection is authenticated and encrypted
2. **No Public Exposure** - MCP server doesn't need public internet access
3. **Identity-Based Access** - Connections are tied to machine identities
4. **Audit Trail** - All connections are logged
5. **ACL Control** - Fine-grained access control policies

### Operational Benefits

1. **Simple DNS** - Access MCP via `mcp.your-tailnet.ts.net`
2. **No Firewall Rules** - Works through NAT and firewalls
3. **Automatic Key Rotation** - No manual certificate management
4. **MagicDNS** - Automatic DNS for all devices

## Bootstrap vs Production Mode

### Bootstrap Mode (Testing/Evaluation)

```bash
AUTOPILOT_MODE=bootstrap
```

- Tailscale not required
- MCP can be accessed via LAN or public URL
- **Not recommended for production**
- Doctor shows: `⚠️ READY (Bootstrap only)`

### Production Mode (Required for Enterprise)

```bash
AUTOPILOT_MODE=production
AUTOPILOT_REQUIRE_TAILSCALE=true
```

- Tailscale required on Autopilot host
- MCP URL must be a Tailnet address
- Full security posture
- Doctor shows: `✅ READY (Production)`

## Setup Instructions

### Step 1: Install Tailscale on Autopilot Host

```bash
# The installer does this automatically, or manually:
curl -fsSL https://tailscale.com/install.sh | sh

# Authenticate with your Tailnet
sudo tailscale up
```

Follow the authentication link to connect to your Tailnet.

### Step 2: Install Tailscale on MCP Host

On the machine running your Wazuh MCP Server:

```bash
curl -fsSL https://tailscale.com/install.sh | sh
sudo tailscale up
```

### Step 3: Note the Tailnet Addresses

After both machines join the Tailnet:

```bash
# On MCP host - get the Tailnet hostname
tailscale status

# Example output:
# 100.64.0.1    mcp-server    youruser@  linux   -
```

Your MCP Tailnet URL will be something like:
- `https://mcp-server.your-tailnet.ts.net:8080`
- or `https://100.64.0.1:8080`

### Step 4: Configure Autopilot for Production

Update `/etc/wazuh-autopilot/.env`:

```bash
AUTOPILOT_MODE=production
AUTOPILOT_REQUIRE_TAILSCALE=true
MCP_URL=https://mcp-server.your-tailnet.ts.net:8080
```

### Step 5: Transition to Production (If Previously in Bootstrap)

If you were running in bootstrap mode:

1. Update `/etc/wazuh-autopilot/.env`:
   ```bash
   AUTOPILOT_MODE=production
   AUTOPILOT_REQUIRE_TAILSCALE=true
   MCP_URL=https://mcp-server.your-tailnet.ts.net:8080
   ```

2. Restart the service:
   ```bash
   sudo systemctl restart wazuh-autopilot
   ```

3. Verify with doctor:
   ```bash
   ./install/doctor.sh
   ```

## Tailscale ACLs (Optional but Recommended)

For additional security, configure Tailscale ACLs to restrict access:

```json
{
  "acls": [
    {
      "action": "accept",
      "src": ["tag:autopilot"],
      "dst": ["tag:mcp:8080"]
    }
  ],
  "tagOwners": {
    "tag:autopilot": ["autogroup:admin"],
    "tag:mcp": ["autogroup:admin"]
  }
}
```

Tag your machines:

```bash
# On Autopilot host
sudo tailscale up --advertise-tags=tag:autopilot

# On MCP host
sudo tailscale up --advertise-tags=tag:mcp
```

## Verifying Tailscale Connectivity

### Check Tailscale Status

```bash
tailscale status
```

Should show both machines online.

### Test MCP Connectivity

```bash
# From Autopilot host
curl https://mcp-server.your-tailnet.ts.net:8080/health
```

### Run Doctor

```bash
./install/doctor.sh
```

Look for:
- `✓ Tailscale running`
- `✓ URL is a Tailnet URL`
- `✓ MCP health check passed`

## Troubleshooting

### "Tailscale not running"

```bash
sudo tailscale up
```

### "URL is not a Tailnet URL"

Update `MCP_URL` in `/etc/wazuh-autopilot/.env` to use the Tailnet address.

### "Cannot connect to MCP"

1. Verify MCP host is on the same Tailnet:
   ```bash
   tailscale status
   ```

2. Check MCP is listening:
   ```bash
   # On MCP host
   ss -tlnp | grep 8080
   ```

3. Check Tailscale ACLs allow the connection

### "Production mode requires Tailnet MCP URL"

You're trying to use production mode with a non-Tailnet URL. Either:
- Change `AUTOPILOT_MODE=bootstrap` for testing
- Or update `MCP_URL` to a Tailnet address

## Enterprise Considerations

### Multiple Environments

For dev/staging/prod environments, use:
- Different Tailnets, or
- Tailscale ACLs to segment access

### High Availability

Tailscale supports:
- Multiple relay servers (DERP)
- Subnet routing for HA setups
- Exit nodes for centralized egress

### Compliance

Tailscale provides:
- SOC 2 Type II certified
- Audit logs for all connections
- Admin console for visibility

## Alternatives (Not Recommended)

If you cannot use Tailscale:

1. **VPN** - Configure MCP behind your corporate VPN
2. **mTLS** - Set up mutual TLS between Autopilot and MCP
3. **SSH Tunnel** - Forward MCP port over SSH

These alternatives require manual configuration and are not officially supported.

## Reference

- [Tailscale Documentation](https://tailscale.com/kb/)
- [Tailscale ACLs](https://tailscale.com/kb/1018/acls/)
- [Enterprise Features](https://tailscale.com/enterprise/)
