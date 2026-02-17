# Slack Socket Mode Integration

Wazuh Autopilot uses Slack's Socket Mode for secure, bidirectional communication without requiring public endpoints.

## How Socket Mode Works

```
┌─────────────────────────────────────────────────────────────────┐
│                                                                 │
│   YOUR SERVER                          SLACK SERVERS            │
│   (localhost)                                                   │
│                                                                 │
│   ┌─────────────────┐                  ┌─────────────────┐     │
│   │ Runtime Service │ ══ OUTBOUND ════▶│ Slack WebSocket │     │
│   │ localhost:9090  │     connection   │ wss://wss-...   │     │
│   └─────────────────┘ ◀═══ messages ═══┘                 │     │
│                           (same socket)                        │
│                                                                 │
│   ✓ NO inbound ports open                                      │
│   ✓ NO public webhook URLs                                     │
│   ✓ Works behind NAT/firewall                                  │
│   ✓ Gateway stays on localhost                                 │
│                                                                 │
└─────────────────────────────────────────────────────────────────┘
```

**Key Point:** Your server initiates an OUTBOUND WebSocket connection to Slack. All messages flow through this connection. No inbound access to your server is ever needed.

## Why Socket Mode?

- **No public URLs required** - Outbound connections only
- **Real-time interaction** - Instant message delivery
- **Secure by design** - No inbound firewall rules needed
- **Approval workflows** - Interactive buttons for approve/deny
- **Works with localhost binding** - Gateway never needs to be exposed

## Setup Overview

1. Create a Slack App
2. Enable Socket Mode
3. Configure Bot permissions
4. Add the App to channels
5. Configure Autopilot with tokens

## Step-by-Step Setup

### 1. Create a Slack App

1. Go to [Slack API Apps](https://api.slack.com/apps)
2. Click **Create New App**
3. Choose **From scratch**
4. Name it "Wazuh Autopilot" (or your preference)
5. Select your workspace

### 2. Enable Socket Mode

1. In your app settings, go to **Socket Mode**
2. Toggle **Enable Socket Mode** to On
3. Click **Generate Token**
4. Name it "autopilot-socket"
5. Add scope: `connections:write`
6. Copy the **App-Level Token** (starts with `xapp-`)

Save this token - you'll need it for `SLACK_APP_TOKEN`.

### 3. Configure OAuth & Permissions

Go to **OAuth & Permissions** and add these **Bot Token Scopes**:

#### Required Scopes

| Scope | Purpose |
|-------|---------|
| `chat:write` | Post messages |
| `chat:write.public` | Post to channels without joining |
| `commands` | Handle slash commands |

#### Recommended Scopes

| Scope | Purpose |
|-------|---------|
| `users:read` | Look up approver information |
| `channels:read` | Verify channel allowlists |
| `groups:read` | Read private channel info |

### 4. Install App to Workspace

1. Go to **Install App**
2. Click **Install to Workspace**
3. Authorize the requested permissions
4. Copy the **Bot User OAuth Token** (starts with `xoxb-`)

Save this token - you'll need it for `SLACK_BOT_TOKEN`.

### 5. Create Slash Commands

Go to **Slash Commands** and create:

#### /wazuh

| Field | Value |
|-------|-------|
| Command | `/wazuh` |
| Request URL | (leave empty for Socket Mode) |
| Short Description | Wazuh Autopilot commands |
| Usage Hint | `[triage|propose|approve|deny|digest|help] [args]` |

Enable **Escape channels, users, and links sent to your app**

### 6. Enable Interactivity

Go to **Interactivity & Shortcuts**:

1. Toggle **Interactivity** to On
2. Leave Request URL empty (Socket Mode handles this)

### 7. Configure Event Subscriptions (Optional)

If you want Autopilot to react to messages:

1. Go to **Event Subscriptions**
2. Toggle **Enable Events** to On
3. Under **Subscribe to bot events**, add:
   - `message.channels`
   - `message.groups`

### 8. Configure Autopilot

Update `/etc/wazuh-autopilot/.env`:

```bash
# Slack App-Level Token (Socket Mode)
SLACK_APP_TOKEN=xapp-1-A0123456789-0123456789012-...

# Slack Bot Token
SLACK_BOT_TOKEN=xoxb-0123456789-0123456789012-...
```

Restart the service:

```bash
sudo systemctl restart wazuh-autopilot
```

### 9. Add Bot to Channels

Invite the bot to channels where you want it to operate:

```
/invite @Wazuh Autopilot
```

Or use the channel settings to add the app.

## Channel Configuration

Configure allowed channels in `policies/policy.yaml`:

```yaml
slack:
  workspace_allowlist:
    - id: "T0123456789"
      name: "Your Workspace"
      enabled: true

  channels:
    alerts:
      allowlist:
        - id: "C0123456789"
          name: "#security-alerts"

    approvals:
      allowlist:
        - id: "C1234567890"
          name: "#security-approvals"

    reports:
      allowlist:
        - id: "C2345678901"
          name: "#security-reports"
```

### Finding Channel and Workspace IDs

**Workspace ID:**
```bash
curl -H "Authorization: Bearer $SLACK_BOT_TOKEN" \
  https://slack.com/api/auth.test | jq '.team_id'
```

**Channel ID:**
- Right-click the channel name → Copy link
- The ID is at the end: `https://workspace.slack.com/archives/C0123456789`

## Usage

### Slash Commands

```
/wazuh help                    # Show available commands
/wazuh triage <alert_id>       # Triage an alert
/wazuh propose <case_id>       # Generate response plan
/wazuh approve <plan_id>       # Approve a plan
/wazuh deny <plan_id> <reason> # Deny a plan
/wazuh digest                  # Generate daily digest
/wazuh kpis                    # Show current KPIs
```

### Interactive Buttons

Approval requests include interactive buttons:

```
┌─────────────────────────────────────────┐
│ 🚨 Approval Request                      │
│                                         │
│ Case: CASE-20260217-abc12345                     │
│ Severity: High                          │
│ Proposed Action: Block IP 192.168.1.100 │
│                                         │
│ [Approve] [Deny] [Investigate More]     │
└─────────────────────────────────────────┘
```

### Case Cards

When alerts are triaged, a case card is posted:

```
┌─────────────────────────────────────────┐
│ 📋 Case Created: CASE-20260217-abc12345          │
│                                         │
│ Severity: High | Confidence: 85%        │
│ Title: Brute force attack detected      │
│                                         │
│ Entities:                               │
│ • IP: 192.168.1.100                     │
│ • User: admin                           │
│ • Host: web-server-01                   │
│                                         │
│ [View Details] [Investigate] [Plan]     │
└─────────────────────────────────────────┘
```

## Fallback Mode

If interactive buttons don't work in your Slack configuration, commands work as fallback:

```
# Instead of clicking Approve button:
/wazuh approve PLAN-20260217-abc12345

# Instead of clicking Deny button:
/wazuh deny PLAN-20260217-abc12345 "Needs more investigation"
```

## Troubleshooting

### "Invalid token" errors

1. Verify token format:
   - App Token: starts with `xapp-`
   - Bot Token: starts with `xoxb-`

2. Regenerate tokens if needed

### Bot doesn't respond to commands

1. Check Socket Mode is enabled
2. Verify app is installed to workspace
3. Check bot is in the channel
4. Review service logs: `journalctl -u wazuh-autopilot -f`

### Messages not posting

1. Verify `chat:write` scope
2. Check channel is in allowlist
3. Verify bot is in channel (or has `chat:write.public`)

### Interactive buttons not working

1. Verify **Interactivity** is enabled
2. Check Socket Mode is enabled
3. Review for errors in service logs

### "Channel not allowed" errors

Update `policies/policy.yaml` with the correct channel IDs.

## Security Considerations

1. **Token Security**
   - Store tokens in `.env` file with restricted permissions
   - Never commit tokens to version control
   - Rotate tokens periodically

2. **Channel Restrictions**
   - Use explicit allowlists
   - Don't allow commands in public channels
   - Use private channels for approvals

3. **Approver Verification**
   - Configure approver allowlists in `policies/policy.yaml`
   - Verify approver identity matches Slack user

## Testing

### Verify Connection

```bash
./install/doctor.sh
```

Look for:
- `✓ Slack App Token configured`
- `✓ Slack Bot Token configured`
- `✓ Slack API connected`

### Send Test Message

```bash
curl -X POST -H "Authorization: Bearer $SLACK_BOT_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"channel":"#security-alerts","text":"Test message from Wazuh Autopilot"}' \
  https://slack.com/api/chat.postMessage
```

## Without Slack (CLI Mode)

Autopilot works without Slack in CLI/local mode:

- Cases are created and stored locally
- Approval requests logged to console
- Reports written to files
- Doctor shows: `ℹ Slack not configured (optional)`

This is useful for testing or environments without Slack.
