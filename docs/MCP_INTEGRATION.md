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
docker compose up -d
```

### Configuration

```env
# .env file for Wazuh MCP Server
WAZUH_HOST=wazuh-manager
WAZUH_PORT=55000
WAZUH_USER=wazuh
WAZUH_PASS=your-password
WAZUH_VERIFY_SSL=true
WAZUH_ALLOW_SELF_SIGNED=true

# MCP Server settings
MCP_PORT=3000
MCP_HOST=0.0.0.0
AUTH_MODE=bearer
MCP_API_KEY=your-api-key

# Advanced
REQUEST_TIMEOUT_SECONDS=30
MAX_ALERTS_PER_QUERY=1000
MAX_CONNECTIONS=10
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
MCP_URL=http://192.168.1.100:3000
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
MCP_URL=https://mcp-server.tailnet12345.ts.net:3000
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
MCP_URL=http://127.0.0.1:3000
```

---

## Available MCP Tools

The Wazuh MCP Server v4.0.6 exposes **29 tools** organized into five categories. All tools are invoked via the MCP protocol through the `/mcp` (Streamable HTTP) or `/sse` (legacy) endpoints.

### Tool Reference

| Category | Tool | Description |
|----------|------|-------------|
| **Alert Operations** | `get_wazuh_alerts` | Retrieve alerts with filtering (limit, rule_id, level, agent_id, timestamp range) |
| | `get_wazuh_alert_summary` | Alert summary grouped by field (time_range, group_by) |
| | `analyze_alert_patterns` | Identify trends and anomalies (time_range, min_frequency) |
| | `search_security_events` | Search events across Wazuh data (query, time_range, limit) |
| **Agent Operations** | `get_wazuh_agents` | Agent information (agent_id, status filter, limit) |
| | `get_wazuh_running_agents` | List running/active agents |
| | `check_agent_health` | Agent health status (agent_id required) |
| | `get_agent_processes` | Running processes from agent (agent_id, limit) |
| | `get_agent_ports` | Open ports from agent (agent_id, limit) |
| | `get_agent_configuration` | Agent configuration details (agent_id) |
| **Vulnerability Operations** | `get_wazuh_vulnerabilities` | Vulnerability data (agent_id, severity, limit) |
| | `get_wazuh_critical_vulnerabilities` | Critical vulnerabilities only (limit) |
| | `get_wazuh_vulnerability_summary` | Vulnerability statistics (time_range) |
| **Security Analysis** | `analyze_security_threat` | AI-powered threat analysis (indicator, indicator_type) |
| | `check_ioc_reputation` | IoC reputation check (indicator, indicator_type) |
| | `perform_risk_assessment` | Risk assessment (agent_id optional) |
| | `get_top_security_threats` | Top threats by frequency/severity (limit, time_range) |
| | `generate_security_report` | Comprehensive report (report_type, include_recommendations) |
| | `run_compliance_check` | Compliance framework check (framework: PCI-DSS/HIPAA/SOX/GDPR/NIST) |
| **System Monitoring** | `get_wazuh_statistics` | Comprehensive statistics |
| | `get_wazuh_weekly_stats` | Weekly statistics |
| | `get_wazuh_cluster_health` | Cluster health info |
| | `get_wazuh_cluster_nodes` | Cluster node information |
| | `get_wazuh_rules_summary` | Rules and effectiveness |
| | `get_wazuh_remoted_stats` | Agent communication statistics |
| | `get_wazuh_log_collector_stats` | Log collector statistics |
| | `search_wazuh_manager_logs` | Search manager logs (query, limit) |
| | `get_wazuh_manager_error_logs` | Recent error logs (limit) |
| | `validate_wazuh_connection` | Connection validation |

> **Note:** Vulnerability Operations tools require Wazuh Indexer 4.8.0 or later.

### Tool Examples

#### Retrieving Alerts

```json
{
  "tool": "get_wazuh_alerts",
  "arguments": {
    "level": 12,
    "agent_id": "001",
    "limit": 50
  }
}
```

**Response:**
```json
{
  "alerts": [
    {
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
  ]
}
```

#### Checking Agent Health

```json
{
  "tool": "check_agent_health",
  "arguments": {
    "agent_id": "001"
  }
}
```

#### Running a Compliance Check

```json
{
  "tool": "run_compliance_check",
  "arguments": {
    "framework": "PCI-DSS"
  }
}
```

---

## Toolmap Configuration

The toolmap maps logical action names to MCP tool calls.

```yaml
# policies/toolmap.yaml
action_operations:
  block_ip:
    logical_name: block_ip
    mcp_tool: wazuh_block_ip
    description: "Block an IP address via Wazuh active response"
    risk_level: low
    reversible: true
    parameters:
      - name: ip_address
        type: string
        required: true
      - name: duration
        type: integer
        required: false
```

---

## Authentication

The Wazuh MCP Server v4.0.6 supports three authentication modes, configured via `AUTH_MODE`.

### Bearer Token Authentication (Default)

Set `AUTH_MODE=bearer`. An API key (`MCP_API_KEY`) is exchanged for a short-lived JWT.

**Step 1 -- Exchange API key for JWT:**
```http
POST /auth/token HTTP/1.1
Host: mcp-server:3000
Authorization: Bearer your-api-key
Content-Type: application/json
```

**Response:**
```json
{
  "token": "eyJhbGciOiJIUzI1NiIs...",
  "expires_in": 3600
}
```

**Step 2 -- Use the JWT for MCP calls:**

All tool invocations go through the `/mcp` endpoint (Streamable HTTP, MCP protocol 2025-11-25) or `/sse` (legacy SSE).

```http
POST /mcp HTTP/1.1
Host: mcp-server:3000
Authorization: Bearer eyJhbGciOiJIUzI1NiIs...
Content-Type: application/json

{
  "method": "tools/call",
  "params": {
    "name": "get_wazuh_alerts",
    "arguments": { "level": 10, "limit": 20 }
  }
}
```

**Autopilot Configuration:**
```env
MCP_API_KEY=your-api-key
```

### OAuth 2.0 Authentication

Set `AUTH_MODE=oauth`. Uses OAuth 2.0 with Dynamic Client Registration. Suitable for multi-tenant or federated deployments.

### No Authentication (Development Only)

Set `AUTH_MODE=none`. Disables authentication entirely. **Never use in production.**

### Token Validation

You can verify a JWT is still valid:
```http
GET /auth/validate HTTP/1.1
Host: mcp-server:3000
Authorization: Bearer eyJhbGciOiJIUzI1NiIs...
```

---

## Error Handling

### Connection Errors

The runtime service includes retry logic and circuit breaker protection.

```javascript
// Runtime handles:
// - Connection timeouts (configurable via MCP_TIMEOUT_MS, default 30s)
// - Non-JSON response handling (graceful degradation)
// Note: Retry and circuit breaker are configured in toolmap.yaml
// but executed by the MCP client layer, not the runtime directly
```

### MCP Error Codes

| Code | Meaning | Action |
|------|---------|--------|
| 200 | Success | Process response |
| 400 | Bad request | Check parameters |
| 401 | Unauthorized | Check MCP_API_KEY / JWT token |
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
  "tool": "get_wazuh_alerts",
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

## API Endpoints

The Wazuh MCP Server v4.0.6 exposes the following HTTP endpoints:

| Endpoint | Method | Purpose | Auth Required |
|----------|--------|---------|---------------|
| `/mcp` | GET/POST | Primary MCP endpoint (Streamable HTTP, protocol 2025-11-25) | Yes |
| `/sse` | GET | Legacy SSE endpoint | Yes |
| `/health` | GET | Health check | No |
| `/metrics` | GET | Prometheus metrics | No |
| `/docs` | GET | OpenAPI/Swagger documentation | No |
| `/auth/token` | POST | Exchange API key for JWT | API Key |
| `/auth/validate` | GET | Validate a JWT token | Bearer |

---

## Troubleshooting

### MCP Connection Test

```bash
# Test health (no auth required)
curl https://mcp-server:3000/health

# Check Prometheus metrics (no auth required)
curl https://mcp-server:3000/metrics

# View available tools (Swagger docs)
# Open https://mcp-server:3000/docs in a browser

# Exchange API key for a JWT
curl -X POST \
  -H "Authorization: Bearer $MCP_API_KEY" \
  https://mcp-server:3000/auth/token

# Validate a JWT
curl -H "Authorization: Bearer $JWT_TOKEN" \
  https://mcp-server:3000/auth/validate
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
