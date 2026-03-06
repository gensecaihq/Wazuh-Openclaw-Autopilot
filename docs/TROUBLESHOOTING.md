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
MCP_URL=https://your-mcp-server:3000
# OR for bootstrap mode:
MCP_BOOTSTRAP_URL=http://192.168.1.100:3000
```

### "MCP authentication failed"

1. Verify your token is correct
2. Check token hasn't expired
3. Ensure token has correct permissions

**Test manually:**
```bash
curl -H "Authorization: Bearer YOUR_TOKEN" \
  https://your-mcp-server:3000/health
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

### "Production mode cannot use placeholder values in policy"

The runtime refuses to start in production mode if `policies/policy.yaml` contains Slack placeholder values (`<SLACK_WORKSPACE_ID>`, `<SLACK_CHANNEL_*>`, `<SLACK_USER_*>`).

**If you're not using Slack**, switch to bootstrap mode:

```bash
# In /etc/wazuh-autopilot/.env
AUTOPILOT_MODE=bootstrap
```

Bootstrap mode warns about placeholders but doesn't block startup. All core functionality (alert triage, correlation, investigation, response planning, REST API approvals) works normally without Slack.

**If you installed with `--skip-tailscale`**, the installer (v2.4.3+) now automatically sets `AUTOPILOT_MODE=bootstrap`. Older installations may have `AUTOPILOT_MODE=production` set incorrectly — change it to `bootstrap` in your `.env`.

**If you are using Slack**, replace all `<PLACEHOLDER>` values in `policies/policy.yaml` with your actual Slack workspace, channel, and user IDs before running in production mode. See the comments in `policy.yaml` for instructions on finding these IDs.

## OpenClaw Webhook Issues

### 400 "hook mapping requires message"

This error means the OpenClaw Gateway cannot extract the message from the incoming webhook POST body. The root cause is missing `messageTemplate` in the hook mappings.

**Fix:** Ensure every hook mapping in `~/.openclaw/openclaw.json` includes `messageTemplate` and `name`:

```json
{
  "match": { "path": "wazuh-alert" },
  "action": "agent",
  "agentId": "wazuh-triage",
  "messageTemplate": "{{message}}",
  "name": "Wazuh Alert Triage"
}
```

All 6 mappings need these fields: `wazuh-alert`, `case-created`, `investigation-request`, `plan-request`, `policy-check`, `execute-action`.

**Verify with a direct curl test:**

```bash
curl -X POST http://127.0.0.1:18789/webhook/wazuh-alert \
  -H "Authorization: Bearer ${OPENCLAW_WEBHOOK_TOKEN}" \
  -H "Content-Type: application/json" \
  -d '{"message": "Test alert from diagnostic"}'
```

A `200` response confirms the webhook is working. A `400` response means `messageTemplate` is still missing.

**After updating**, restart OpenClaw:
```bash
sudo systemctl restart openclaw
# or
docker restart openclaw
```

### 401 Unauthorized on webhook dispatch

OpenClaw requires a **separate token** for webhook endpoint validation, distinct from the gateway auth token. If you see `401 Unauthorized` on webhook dispatch:

**Fix:** Set `OPENCLAW_WEBHOOK_TOKEN` in your environment:

```bash
# Generate a new webhook token
WEBHOOK_TOKEN=$(openssl rand -hex 32)

# Add to Autopilot environment
echo "OPENCLAW_WEBHOOK_TOKEN=$WEBHOOK_TOKEN" >> /etc/wazuh-autopilot/.env

# Update OpenClaw config hooks.token to match
# In ~/.openclaw/openclaw.json, set:
#   "hooks": { "token": "$WEBHOOK_TOKEN", ... }

# Restart services
sudo systemctl restart wazuh-autopilot
sudo systemctl restart openclaw
```

If `OPENCLAW_WEBHOOK_TOKEN` is not set, the runtime falls back to `OPENCLAW_TOKEN` for backwards compatibility.

### Webhook dispatch diagnostic logging

If webhooks are failing, the Autopilot Runtime (v2.4.0+) logs detailed diagnostics on 4xx errors including:
- Payload keys sent
- Whether the `message` field was present and non-empty
- First 80 chars of the message
- Response body from OpenClaw

Check logs with:
```bash
journalctl -u wazuh-autopilot | grep "dispatch"
```

### OPENCLAW_GATEWAY_URL set to ws:// — webhook dispatch fails

`openclaw status --all` reports the gateway target as `ws://127.0.0.1:18789` (the WebSocket endpoint for interactive sessions). If you copy this URL into `OPENCLAW_GATEWAY_URL`, webhook dispatch fails because Node's `fetch()` does not support the `ws://` scheme.

**Symptoms:**
- Startup log: `OpenClaw Gateway NOT reachable — agent dispatch will fail`
- Webhook dispatch errors with `fetch failed` or `TypeError`
- Agents never start after alert ingestion

**Auto-fix (v2.5.0+):** The runtime automatically normalizes `ws://` → `http://` and `wss://` → `https://` and logs a warning. No manual action needed.

**Manual fix (older versions):** Change the scheme in your `.env`:

```bash
# Wrong (copied from openclaw status)
OPENCLAW_GATEWAY_URL=ws://127.0.0.1:18789

# Correct
OPENCLAW_GATEWAY_URL=http://127.0.0.1:18789
```

### "allowlist contains unknown entries (web.fetch)"

OpenClaw uses **snake_case** tool identifiers in per-agent allow/deny lists. The correct tool name is `web_fetch`, not `web.fetch`. Dot notation is only valid in the global config path (`tools.web.fetch.enabled`).

**Fix:** In your `openclaw.json`, change every occurrence of `"web.fetch"` to `"web_fetch"` in agent `tools.allow` arrays:

```json
"tools": {
  "allow": ["read", "edit", "web_fetch", "sessions_list", "sessions_history", "sessions_send"]
}
```

Also ensure the global web fetch is enabled:
```json
"tools": {
  "web": {
    "fetch": { "enabled": true }
  }
}
```

After updating, restart the gateway:
```bash
systemctl restart openclaw-gateway
```

### 400 "does not support thinking" (Ollama models)

If agent sessions fail with `400 "llama3.1:8b" does not support thinking`, the model is registered with `"reasoning": true` in `openclaw.json`. OpenClaw sends a `thinking_level` parameter to models marked as reasoning-capable, but standard Ollama models (Llama 3.x, Mistral, Qwen 2.5, CodeLlama) don't support this API feature.

**Fix:** Set `"reasoning": false` for all standard models in the `models.providers.ollama.models` array of `~/.openclaw/openclaw.json`:

```json
{ "id": "llama3.1:8b", "name": "Llama 3.1 8B", "reasoning": false, ... }
{ "id": "llama3.3", "name": "Llama 3.3 70B", "reasoning": false, ... }
{ "id": "mistral", "name": "Mistral 7B", "reasoning": false, ... }
```

Only set `"reasoning": true` for models with native structured thinking output: `deepseek-r1`, `qwq`, and similar reasoning-specific models. After updating, restart OpenClaw.

### Tool calls not working / agents output web_fetch as text (OpenRouter)

If agents produce a full triage analysis but write `web_fetch http://...` as plain text in markdown code blocks instead of actually invoking the tool, the model's capability metadata is missing the `toolUse` flag. This is a known upstream OpenClaw issue with the `openai-completions` provider path ([openclaw#1866](https://github.com/openclaw/openclaw/issues/1866), [openclaw#8923](https://github.com/openclaw/openclaw/issues/8923)).

**How to confirm:** Check the agent session log (`~/.openclaw/agents/wazuh-triage/sessions/*.jsonl`). If you see:
- `"stopReason":"stop"` (not `"tool_use"`)
- `"content":[{"type":"text","text":"...web_fetch http://..."}]` (tool call as text, not as `type: "tool_use"`)
- `"modelApi":"openai-completions"`

Then the model never received tool schemas in the API request.

**Fix (in order of reliability):**

1. **Refresh the model catalog** — this populates `toolUse: true` for your configured models:
   ```bash
   openclaw models scan
   sudo systemctl restart openclaw-gateway
   ```

2. **Use direct Anthropic API as primary model** — the `anthropic-messages` wire protocol has native, reliable tool support:
   ```bash
   # Set ANTHROPIC_API_KEY in /etc/wazuh-autopilot/.env
   ANTHROPIC_API_KEY=sk-ant-your-key-here
   ```
   Then in `~/.openclaw/openclaw.json`, change the primary model to use Anthropic directly:
   ```json
   "model": {
     "primary": "anthropic/claude-sonnet-4-5",
     "fallbacks": ["openrouter/openai/gpt-4o"]
   }
   ```
   This routes the primary model through Anthropic's native API (tool calling works) with OpenRouter as fallback. **Important:** Use a pay-per-token API key from [console.anthropic.com](https://console.anthropic.com/), NOT a Claude Pro/Max subscription token — Anthropic has banned subscription OAuth in third-party tools and will suspend your account. See [Provider Policy Notice](../README.md#provider-policy-notice).

3. **Upgrade OpenClaw** to the latest version — newer releases may include catalog updates with correct capabilities:
   ```bash
   curl -fsSL https://openclaw.ai/install.sh | sh
   openclaw models scan
   sudo systemctl restart openclaw-gateway
   ```

After applying the fix, re-test by submitting an alert and checking the session log for `"stopReason":"tool_use"` and `"type":"tool_use"` entries.

### Tool calls not working / agents output raw JSON text (Ollama)

If agents produce output tokens but never actually invoke tools like `web_fetch`, the Ollama provider is likely configured with the OpenAI-compatible API mode. This breaks tool calling — models output raw tool JSON as plain text.

**Fix:** In `~/.openclaw/openclaw.json`, ensure the Ollama provider uses the native API:

```json
"ollama": {
  "baseUrl": "http://127.0.0.1:11434",
  "api": "ollama",
  ...
}
```

Do **not** use `"api": "openai-completions"` with `"baseUrl": "http://127.0.0.1:11434/v1"`. After updating, restart OpenClaw.

### Pipeline stalls after triage (agents don't advance)

If triage processes alerts but no downstream agents (correlation, investigation, etc.) activate, the most common cause is agents unable to call the Runtime API to transition case status.

**Check:**
1. `web_fetch` is in each agent's `tools.allow` list (not `web.fetch`)
2. `web_fetch` and `sessions_send` are in the **global** `tools.allow` list — agent-level overrides cannot re-add tools blocked at global level
3. Global `tools.web.fetch.enabled` is `true`
4. OpenClaw gateway logs show no "unknown entries" warnings

The global `tools.allow` must include every tool that any agent needs:
```json
"tools": {
  "profile": "minimal",
  "allow": ["read", "edit", "write", "exec", "web_fetch", "sessions_list", "sessions_history", "sessions_send"],
  "deny": ["browser", "canvas"],
  "web": {
    "search": { "enabled": false },
    "fetch": { "enabled": true }
  }
}
```

If `web_fetch` is only in agent allow lists but missing from the global allow list, agents silently cannot make HTTP requests — the pipeline stalls with no error.

```bash
journalctl -u openclaw-gateway | grep "unknown entries"
```

### Agent receives webhook but doesn't call web_fetch (EXTERNAL_UNTRUSTED_CONTENT)

OpenClaw wraps all webhook payloads in a security envelope (`EXTERNAL_UNTRUSTED_CONTENT`) that instructs models **not** to execute tools or commands mentioned within the untrusted content. This is a safety feature to prevent prompt injection from external sources.

**Problem:** If your `openclaw.json` hook mappings don't include `"allowUnsafeExternalContent": true`, the model sees the callback URL inside the security envelope and correctly refuses to call `web_fetch`. The agent outputs a text summary but never advances the pipeline.

**Symptoms:**
- Agent sessions show the model producing text analysis but never invoking `web_fetch`
- Cases stay in `open` status despite triage agent running
- Stalled pipeline detector fires repeatedly with no progress
- Session logs show `stopReason: "stop"` (not `"error"`) with token usage > 0

**Fix:** Add `"allowUnsafeExternalContent": true` to each hook mapping in `~/.openclaw/openclaw.json`:

```json
{
  "match": { "path": "wazuh-alert" },
  "action": "agent",
  "agentId": "wazuh-triage",
  "messageTemplate": "{{message}}",
  "name": "Wazuh Alert Triage",
  "allowUnsafeExternalContent": true
}
```

This is safe because webhook payloads come from your own runtime service on loopback (`127.0.0.1`), authenticated by `hooks.token`. Apply to all 6 hook mappings. Version 2.4.4+ of the installer and reference configs include this flag by default.

### Stalled pipeline detector (automatic recovery)

The runtime includes a stalled-pipeline detector that automatically re-dispatches webhooks for cases stuck in transient statuses (`open`, `triaged`, `correlated`, `investigated`, `planned`, `approved`). If a case remains in one of these statuses longer than the threshold, the detector re-sends the appropriate webhook to give the agent another chance.

**Configuration (environment variables):**

| Variable | Default | Description |
|----------|---------|-------------|
| `STALLED_PIPELINE_ENABLED` | `true` | Enable/disable the detector |
| `STALLED_PIPELINE_THRESHOLD_MINUTES` | `30` | Minutes before a case is considered stalled |
| `STALLED_PIPELINE_CHECK_INTERVAL_MS` | `300000` | Interval between checks (5 min) |

**Check logs for stalled-pipeline detections:**
```bash
journalctl -u wazuh-autopilot | grep "stalled-pipeline"
```

**Metrics:**
- `autopilot_stalled_pipeline_detected_total` — number of stalled cases found
- `autopilot_stalled_pipeline_redispatched_total` — number of webhooks re-dispatched

To test quickly, set `STALLED_PIPELINE_THRESHOLD_MINUTES=1` and ingest an alert without advancing it past `open`. After 1 minute + the check interval, you should see re-dispatch logs.

### "fetch failed" with 0 tokens / 5-minute timeout (Ollama)

If Ollama agents fail with `error=fetch failed` and `input: 0, output: 0` after exactly 5 minutes, several issues are usually compounding:

1. **Streaming silently disabled** — OpenClaw injects `streaming: false` for Ollama tool-calling models. Ollama waits for full generation before sending HTTP headers. If generation takes >5 min, undici kills the connection.
2. **undici 300-second headersTimeout** — Node.js `fetch()` kills connections after 5 minutes with no response headers. pi-ai's `http-proxy.ts` sets `setGlobalDispatcher(new EnvHttpProxyAgent())` with default 300s timeout, overwriting any custom dispatcher.
3. **Proxy environment variables** (common on servers with desktop sessions) — `EnvHttpProxyAgent` reads `http_proxy`/`HTTPS_PROXY`/etc and routes ALL requests including localhost through the proxy. Unlike curl, undici does NOT auto-bypass localhost.
4. **Ollama context window too small** — Ollama defaults to 2048 tokens. OpenClaw injects ~12K tokens of system prompt.
5. **Provider cooldown** — After the first timeout, OpenClaw marks Ollama as rate-limited with exponential backoff (1m → 5m → 25m → 1hr).

**Fix all of them:**

```bash
# 1. Set Ollama context window
sudo systemctl edit ollama
# Add: Environment="OLLAMA_NUM_CTX=32768"
# Add: Environment="OLLAMA_KEEP_ALIVE=24h"
sudo systemctl daemon-reload && sudo systemctl restart ollama

# 2. Install undici globally (preload needs it as a module)
npm install -g undici

# 3. Create preload script — see AIR_GAPPED_DEPLOYMENT.md for the full script
#    The script supports two modes via OPENCLAW_LLM_MODE env var:
#      local → air-gapped/Ollama-only (aggressive timeouts, deletes proxy vars)
#      cloud → cloud APIs or hybrid  (conservative timeouts, preserves proxy vars)

# 4. Inject into gateway systemd service
systemctl edit --user openclaw-gateway
# For Ollama-only:
# [Service]
# Environment="NODE_OPTIONS=--require /root/undici-timeout-fix.cjs"
# Environment="NODE_PATH=/usr/lib/node_modules"
# Environment="OPENCLAW_LLM_MODE=local"
# UnsetEnvironment=http_proxy https_proxy HTTP_PROXY HTTPS_PROXY ALL_PROXY all_proxy
#
# For cloud APIs or hybrid (cloud + Ollama):
# [Service]
# Environment="NODE_OPTIONS=--require /root/undici-timeout-fix.cjs"
# Environment="NODE_PATH=/usr/lib/node_modules"
# Environment="OPENCLAW_LLM_MODE=cloud"
# (do NOT add UnsetEnvironment — cloud APIs may need proxy vars)

systemctl --user daemon-reload && systemctl --user restart openclaw-gateway

# 5. Clear cooldown state
find ~/.openclaw -name "auth-profiles.json" -exec grep -l "disabledUntil" {} \;
# If found, edit and remove usageStats/disabledUntil section
```

**Diagnostic:** `systemctl --user show-environment | grep -i proxy` — if this shows proxy vars and you use Ollama locally, switch to `OPENCLAW_LLM_MODE=cloud` mode (uses `NO_PROXY` for localhost) instead of deleting them.

See [AIR_GAPPED_DEPLOYMENT.md](./AIR_GAPPED_DEPLOYMENT.md#fetch-failed-with-0-tokens-5-minute-timeout) for the full preload script and detailed explanation.

### Gateway start blocked: `set gateway.mode=local`

OpenClaw v2026.2.17 requires `gateway.mode` to be set. Without it, the gateway refuses to start:

```
Gateway start blocked: set gateway.mode=local (current: unset) or pass --allow-unconfigured.
```

**Fix:** Ensure your `openclaw.json` gateway section includes `"mode": "local"`:

```json
"gateway": {
  "port": 18789,
  "mode": "local",
  "bind": "loopback",
  "auth": { ... }
}
```

This is included in both reference templates (`openclaw.json` and `openclaw-airgapped.json`) as of v2.4.3.

---

## Connectivity Issues

### "Cannot connect to MCP"

**Check network connectivity:**
```bash
# Test basic connectivity
ping mcp-server.tail123.ts.net

# Test HTTP
curl -v https://mcp-server.tail123.ts.net:3000/health
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
node --version  # Should be 20+
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
# Expected: AGENTS.md IDENTITY.md TOOLS.md MEMORY.md (HEARTBEAT.md for triage/correlation/reporting)
# Shared files in: ~/.openclaw/wazuh-autopilot/agents/_shared/ (SOUL.md USER.md)
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

1. Verify `AUTOPILOT_MCP_AUTH` token matches the MCP server's `MCP_API_KEY`
2. Check the token has no extra whitespace or newlines
3. Test manually:
   ```bash
   curl -H "Authorization: Bearer $AUTOPILOT_MCP_AUTH" \
     https://mcp-server:3000/health
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
  https://mcp-server:3000/tools
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
