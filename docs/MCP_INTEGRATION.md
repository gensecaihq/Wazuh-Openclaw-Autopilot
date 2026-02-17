# MCP Integration Guide

This document describes how Wazuh Autopilot integrates with the Wazuh MCP Server for security data access.

## Overview

The Model Context Protocol (MCP) provides a standardized interface for AI agents to interact with Wazuh. Wazuh Autopilot uses MCP to:

- Retrieve alerts and events
- Query agent information
- Access rule metadata
- Execute active response commands

```
┌─────────────────────────────────────────────────────────────┐
│                    Wazuh Autopilot                          │
│  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐         │
│  │   Triage    │  │   Correlate │  │  Investigate │         │
│  │   Agent     │  │   Agent     │  │    Agent     │         │
│  └──────┬──────┘  └──────┬──────┘  └──────┬───────┘         │
│         │                │                │                  │
│         └────────────────┼────────────────┘                  │
│                          │                                   │
│                   ┌──────▼──────┐                            │
│                   │  Runtime    │                            │
│                   │  Service    │                            │
│                   └──────┬──────┘                            │
└──────────────────────────│───────────────────────────────────┘
                           │ HTTP/HTTPS
                           │ (Tailscale recommended)
                    ┌──────▼──────┐
                    │  Wazuh MCP  │
                    │   Server    │
                    └──────┬──────┘
                           │ HTTPS
                    ┌──────▼──────┐
                    │   Wazuh     │
                    │   Manager   │
                    └─────────────┘
```

## MCP Server Setup

### Prerequisites

1. Wazuh Manager installed and running
2. Wazuh API credentials
3. Network connectivity between MCP and Wazuh

### Installation

```bash
# Clone the MCP server
git clone https://github.com/gensecaihq/Wazuh-MCP-Server
cd Wazuh-MCP-Server

# Configure
cp .env.example .env
nano .env

# Start
docker-compose up -d
```

### Configuration

```env
# .env file for Wazuh MCP Server
WAZUH_API_URL=https://wazuh-manager:55000
WAZUH_API_USER=wazuh
WAZUH_API_PASSWORD=your-password
WAZUH_API_VERIFY_SSL=true

# MCP Server settings
MCP_PORT=8080
MCP_HOST=0.0.0.0
MCP_AUTH_ENABLED=true
MCP_AUTH_TOKEN=your-secret-token

# Rate limiting
RATE_LIMIT_WINDOW_MS=60000
RATE_LIMIT_MAX_REQUESTS=100
```

---

## Connection Methods

### Method 1: Direct Connection (Development)

For development and testing, connect directly to MCP over the local network.

```
Runtime → MCP (HTTP/HTTPS on LAN)
```

**Autopilot Configuration:**
```env
AUTOPILOT_MODE=bootstrap
MCP_URL=http://192.168.1.100:8080
AUTOPILOT_MCP_AUTH=your-token
```

**Security Considerations:**
- Only use for development/testing
- Ensure network segmentation
- Use HTTPS if possible

### Method 2: Tailscale (Production Recommended)

Use Tailscale for zero-trust networking between components.

```
Runtime → Tailscale → MCP (encrypted tunnel)
```

**Autopilot Configuration:**
```env
AUTOPILOT_MODE=production
AUTOPILOT_REQUIRE_TAILSCALE=true
MCP_URL=https://mcp-server.tailnet12345.ts.net:8080
AUTOPILOT_MCP_AUTH=your-token
```

**Benefits:**
- End-to-end encryption
- No port exposure needed
- Works across cloud/on-prem
- Built-in ACLs

### Method 3: Same Server (All-in-One)

When MCP and Autopilot are on the same server.

```
Runtime → localhost → MCP
```

**Autopilot Configuration:**
```env
MCP_URL=http://127.0.0.1:8080
```

---

## Available MCP Tools

### Alert Operations

#### `get_alert`
Retrieve a specific alert by ID.

```yaml
# Agent usage in YAML
allowed_tools:
  - name: get_alert
    purpose: "Fetch complete alert details"
    required: true
```

**Parameters:**
- `alert_id` (string): The Wazuh alert ID

**Response:**
```json
{
  "alert": {
    "_id": "12345",
    "rule": {
      "level": 12,
      "description": "SSH brute force attack",
      "mitre": { "id": ["T1110"], "tactic": ["Credential Access"] }
    },
    "agent": {
      "id": "001",
      "name": "server-prod-01",
      "ip": "10.0.1.100"
    },
    "data": {
      "srcip": "192.168.1.50",
      "srcuser": "root"
    }
  }
}
```

#### `search_alerts`
Search for alerts matching criteria.

**Parameters:**
- `query` (string): Elasticsearch query string
- `size` (number): Maximum results (default: 10)
- `from` (number): Offset for pagination

**Example Query:**
```json
{
  "query": "rule.level:>=10 AND agent.name:server-prod-*",
  "size": 50,
  "from": 0
}
```

#### `search_events`
Search raw events (not just alerts).

**Parameters:**
- `query` (string): Elasticsearch query string
- `index` (string): Index pattern (default: "wazuh-alerts-*")
- `size` (number): Maximum results

### Agent Operations

#### `get_agent`
Get information about a Wazuh agent.

**Parameters:**
- `agent_id` (string): The agent ID

**Response:**
```json
{
  "agent": {
    "id": "001",
    "name": "server-prod-01",
    "ip": "10.0.1.100",
    "status": "active",
    "os": {
      "platform": "ubuntu",
      "version": "22.04"
    },
    "manager": "wazuh-manager"
  }
}
```

#### `list_agents`
List all agents with optional filtering.

**Parameters:**
- `status` (string): Filter by status (active, disconnected, pending)
- `group` (string): Filter by group
- `limit` (number): Maximum results

### Rule Operations

#### `get_rule_info`
Get rule metadata including MITRE mappings.

**Parameters:**
- `rule_id` (string): The Wazuh rule ID

**Response:**
```json
{
  "rule": {
    "id": "5712",
    "level": 10,
    "description": "sshd: brute force attack",
    "groups": ["sshd", "authentication_failed"],
    "mitre": {
      "id": ["T1110"],
      "tactic": ["Credential Access"],
      "technique": ["Brute Force"]
    }
  }
}
```

### Active Response Operations (Restricted)

These tools are restricted and require elevated permissions.

#### `block_ip`
Block an IP address via Wazuh active response.

**Parameters:**
- `agent_id` (string): Target agent
- `ip` (string): IP address to block
- `duration` (number): Block duration in seconds (optional)

#### `isolate_host`
Network isolate an endpoint.

**Parameters:**
- `agent_id` (string): Target agent

#### `kill_process`
Terminate a process on an endpoint.

**Parameters:**
- `agent_id` (string): Target agent
- `pid` (number): Process ID
- `process_name` (string): Process name (alternative to PID)

---

## Toolmap Configuration

The toolmap maps logical action names to MCP tool calls.

```yaml
# policies/toolmap.yaml
tools:
  block_ip:
    mcp_tool: block_ip
    endpoint: /tools/block_ip
    method: POST
    parameters:
      - name: agent_id
        type: string
        required: true
      - name: ip
        type: string
        required: true
    timeout_ms: 30000
    requires_approval: true
```

---

## Authentication

### Token-Based Authentication

MCP uses Bearer token authentication.

**Request:**
```http
POST /tools/get_alert HTTP/1.1
Host: mcp-server:8080
Authorization: Bearer your-secret-token
Content-Type: application/json

{"alert_id": "12345"}
```

**Autopilot Configuration:**
```env
AUTOPILOT_MCP_AUTH=your-secret-token
```

### Rotating Tokens

For production, implement token rotation:

1. Generate new token
2. Update MCP server configuration
3. Update Autopilot configuration
4. Restart both services

---

## Error Handling

### Connection Errors

The runtime service includes retry logic and circuit breaker protection.

```javascript
// Runtime automatically handles:
// - Connection timeouts (30s default)
// - Retry with exponential backoff (3 attempts)
// - Circuit breaker (opens after 3 consecutive failures)
```

### MCP Error Codes

| Code | Meaning | Action |
|------|---------|--------|
| 200 | Success | Process response |
| 400 | Bad request | Check parameters |
| 401 | Unauthorized | Check MCP_AUTH token |
| 403 | Forbidden | Check permissions |
| 404 | Not found | Resource doesn't exist |
| 429 | Rate limited | Retry after delay |
| 500 | Server error | Check MCP logs |
| 503 | Unavailable | MCP or Wazuh down |

### Logging

MCP calls are logged with correlation IDs:

```json
{
  "ts": "2026-02-17T10:30:00Z",
  "level": "info",
  "component": "mcp",
  "msg": "Tool call completed",
  "tool": "get_alert",
  "status": "success",
  "latency_ms": 45,
  "correlation_id": "abc-123-def"
}
```

---

## Security Best Practices

### Network Security

1. **Use Tailscale** for production deployments
2. **Never expose MCP** directly to the internet
3. **Use HTTPS** for all connections
4. **Implement firewall rules** to restrict access

### Authentication

1. **Use strong tokens** (32+ random bytes)
2. **Rotate tokens** regularly
3. **Use separate tokens** for different environments
4. **Log authentication failures**

### Data Protection

1. **Avoid logging sensitive data** (credentials, PII)
2. **Encrypt data at rest** if storing locally
3. **Implement audit logging** for all MCP calls
4. **Use evidence packs** for forensic records

---

## Troubleshooting

### MCP Connection Test

```bash
# Test basic connectivity
curl -v https://mcp-server:8080/health

# Test with authentication
curl -H "Authorization: Bearer $AUTOPILOT_MCP_AUTH" \
  https://mcp-server:8080/health

# Test a tool call
curl -X POST \
  -H "Authorization: Bearer $AUTOPILOT_MCP_AUTH" \
  -H "Content-Type: application/json" \
  -d '{"query": "rule.level:>=10", "size": 1}' \
  https://mcp-server:8080/tools/search_alerts
```

### Common Issues

**Connection refused:**
- Check MCP server is running
- Verify port is correct
- Check firewall rules
- Test with curl from the runtime server

**Authentication failed:**
- Verify token matches MCP configuration
- Check token has no extra whitespace
- Ensure token is properly exported

**Timeout errors:**
- Increase MCP_TIMEOUT_MS in runtime config
- Check network latency
- Verify MCP server isn't overloaded

**Rate limiting:**
- Reduce request frequency
- Implement caching for repeated queries
- Increase rate limits in MCP config

---

## Related Documentation

- [Wazuh MCP Server](https://github.com/gensecaihq/Wazuh-MCP-Server)
- [OpenClaw Framework](https://github.com/openclaw/openclaw)
- [MCP Protocol Specification](https://modelcontextprotocol.io/)
- [Tailscale Documentation](https://tailscale.com/kb/)
