# Runtime API Reference

The Wazuh Autopilot Runtime Service (v2.2.0) provides a REST API for case management, response plan approval workflow, alert ingestion, metrics, health monitoring, and webhook-driven agent orchestration.

## Base URL

By default, the service listens on `http://127.0.0.1:9090`. The port is configurable via `RUNTIME_PORT` environment variable (`METRICS_PORT` accepted as backward-compat alias).

## Authentication

All API endpoints require a `Bearer` token via the `Authorization` header. Two token types are supported:

| Token | Env Variable | Scope | Purpose |
|-------|-------------|-------|---------|
| Service token | `AUTOPILOT_SERVICE_TOKEN` | Read-only | Agent-to-service queries |
| MCP auth token | `AUTOPILOT_MCP_AUTH` | Read + Write | Full API access |

Requests from localhost (`127.0.0.1` / `::1`) bypass authentication to allow internal agent communication.

**Example:**
```bash
curl -H "Authorization: Bearer YOUR_TOKEN" http://127.0.0.1:9090/api/cases
```

## Endpoints

### Health & Status

#### GET /health

Returns service health status. Exempt from rate limiting and authentication.

**Response** (200 OK when healthy, 503 when degraded):
```json
{
  "status": "healthy",
  "version": "2.1.0",
  "mode": "bootstrap",
  "uptime_seconds": 3600,
  "checks": {
    "data_dir": true,
    "metrics": true
  },
  "responder": {
    "enabled": false,
    "status": "DISABLED"
  },
  "timestamp": "2026-02-17T10:30:00.000Z"
}
```

> **Note:** `status` is `"healthy"` (HTTP 200) when all checks pass, or `"degraded"` (HTTP 503) if the data directory is inaccessible.

#### GET /ready

Kubernetes-style readiness probe. Exempt from rate limiting and authentication.

**Response** (200 OK when ready, 503 when not ready):
```json
{
  "ready": true,
  "checks": {
    "data_dir": true
  }
}
```

> **Note:** Returns 503 with `{"ready": false, "reason": "shutting_down"}` during graceful shutdown, or 503 with `{"ready": false, "checks": {"data_dir": false}}` if the data directory is inaccessible.

#### GET /version

Returns service version information. Exempt from rate limiting and authentication.

**Response:**
```json
{
  "service": "wazuh-openclaw-autopilot",
  "version": "2.1.0",
  "node": "v18.19.0"
}
```

#### GET /metrics

Prometheus-format metrics endpoint. Exempt from rate limiting and authentication.

**Response:** `text/plain`
```prometheus
# TYPE autopilot_cases_created_total counter
autopilot_cases_created_total 42
# TYPE autopilot_mcp_tool_calls_total counter
autopilot_mcp_tool_calls_total{tool="get_alert",status="success"} 100
```

See [OBSERVABILITY_EXPORT.md](OBSERVABILITY_EXPORT.md) for the full metrics catalog.

---

### Cases API

#### GET /api/cases

List all cases (most recent first). Requires `read` scope.

**Query Parameters:**
- `limit` (optional): Maximum number of cases to return (default: 100)

**Response:**
```json
[
  {
    "case_id": "CASE-20260217-abc12345",
    "created_at": "2026-02-17T10:30:00.000Z",
    "updated_at": "2026-02-17T10:35:00.000Z",
    "title": "Brute Force Attack on SSH",
    "severity": "high",
    "status": "open"
  }
]
```

#### POST /api/cases

Create a new case with evidence pack. Requires `write` scope.

**Request Body:**
```json
{
  "case_id": "CASE-20260217-abc12345",
  "title": "Brute Force Attack on SSH",
  "summary": "Multiple failed login attempts detected",
  "severity": "high",
  "confidence": 0.85,
  "entities": [
    {"type": "ip", "value": "192.168.1.100"},
    {"type": "user", "value": "admin"}
  ],
  "evidence_refs": ["alert-123", "alert-124"]
}
```

**Response:** `201 Created`
```json
{
  "schema_version": "1.0",
  "case_id": "CASE-20260217-abc12345",
  "created_at": "2026-02-17T10:30:00.000Z",
  "title": "Brute Force Attack on SSH",
  "severity": "high",
  "confidence": 0.85,
  "entities": [...],
  "timeline": [],
  "mitre": [],
  "mcp_calls": [],
  "evidence_refs": [...],
  "plans": [],
  "approvals": [],
  "actions": []
}
```

#### GET /api/cases/:caseId

Get a specific case by ID. Requires `read` scope. Returns the full evidence pack.

**Response:**
```json
{
  "schema_version": "1.0",
  "case_id": "CASE-20260217-abc12345",
  "created_at": "2026-02-17T10:30:00.000Z",
  "updated_at": "2026-02-17T10:35:00.000Z",
  "title": "Brute Force Attack on SSH",
  "summary": "Multiple failed login attempts detected",
  "severity": "high",
  "confidence": 0.85,
  "entities": [...],
  "timeline": [...],
  "mitre": [...],
  "mcp_calls": [...],
  "evidence_refs": [...],
  "plans": [...],
  "approvals": [...],
  "actions": [...]
}
```

#### PUT /api/cases/:caseId

Update an existing case. Requires `write` scope. Array fields (`entities`, `timeline`, `evidence_refs`, etc.) are appended; scalar fields (`title`, `severity`, `status`) are replaced.

**Request Body:**
```json
{
  "severity": "critical",
  "entities": [{"type": "host", "value": "server-01"}],
  "status": "investigating"
}
```

**Response:** `200 OK` with updated evidence pack.

---

### Alert Ingestion

#### POST /api/alerts

Ingest a Wazuh alert and perform automated triage. Creates a new case or updates an existing one. Requires `write` scope.

The endpoint automatically:
- Extracts entities (IPs, users, hosts) from alert fields
- Determines severity from rule level (4-6: low, 7-9: medium, 10-12: high, 13+: critical)
- Extracts MITRE ATT&CK mappings from rule metadata
- Generates a case ID from the alert ID hash

**Request Body:**
```json
{
  "alert_id": "12345",
  "rule": {
    "id": "5712",
    "level": 10,
    "description": "sshd: brute force attack",
    "mitre": {
      "id": ["T1110"],
      "tactic": ["Credential Access"],
      "technique": ["Brute Force"]
    }
  },
  "agent": {
    "id": "001",
    "name": "server-prod-01",
    "ip": "10.0.1.100"
  },
  "data": {
    "srcip": "192.168.1.100",
    "srcuser": "root"
  }
}
```

**Response:** `201 Created` (new case) or `200 OK` (existing case updated)
```json
{
  "case_id": "CASE-20260217-a1b2c3d4e5f6",
  "status": "created",
  "severity": "high",
  "entities_extracted": 3,
  "mitre_mappings": 1,
  "triage_latency_ms": 12
}
```

> **Webhook Dispatch:** When a new case is created, the runtime dispatches a webhook to the OpenClaw Gateway (`/webhook/wazuh-alert`) to trigger the Triage Agent. This is fire-and-forget and does not block the API response.

---

### Case Status Handoffs

When a case status is updated via `PUT /api/cases/:id`, the runtime automatically dispatches webhooks to trigger downstream agents:

| Status Set To | Webhook Path | Agent Triggered |
|---------------|-------------|-----------------|
| `triaged` | `/webhook/case-created` | Correlation |
| `correlated` | `/webhook/investigation-request` | Investigation |
| `investigated` | `/webhook/plan-request` | Response Planner |

Dispatches are fire-and-forget (async, never block the API response).

---

### Responder Status

#### GET /api/responder/status

Returns the current state of the responder capability. Requires `read` scope.

**Response:**
```json
{
  "enabled": false,
  "message": "Responder capability DISABLED - execution blocked even after human approval",
  "human_approval_required": true,
  "autonomous_execution": false,
  "environment_variable": "AUTOPILOT_RESPONDER_ENABLED",
  "current_value": "false",
  "note": "AI agents cannot execute actions autonomously. Human must always Approve AND Execute."
}
```

---

### Response Plans API (Two-Tier Approval)

The plans API implements a two-tier human-in-the-loop workflow:

```
PROPOSED ──[approve]──> APPROVED ──[execute]──> COMPLETED
    │                       │                       │
    └──[reject]──> REJECTED └──[expire]──> EXPIRED  └──(partial)──> FAILED
```

Plans expire after `PLAN_EXPIRY_MINUTES` (default: 60) if not acted upon.

#### GET /api/plans

List response plans. Requires `read` scope.

**Query Parameters:**
- `state` (optional): Filter by state (`proposed`, `approved`, `rejected`, `completed`, `failed`, `expired`)
- `case_id` (optional): Filter by case ID
- `limit` (optional): Max results (default: 100)
- `offset` (optional): Pagination offset (default: 0)

**Response:**
```json
[
  {
    "plan_id": "PLAN-1708171800000-a1b2c3d4",
    "case_id": "CASE-20260217-abc12345",
    "state": "proposed",
    "created_at": "2026-02-17T10:30:00.000Z",
    "updated_at": "2026-02-17T10:30:00.000Z",
    "expires_at": "2026-02-17T11:30:00.000Z",
    "title": "Block attacker IP",
    "description": "Block source IP of brute force attack",
    "risk_level": "low",
    "actions": [
      {
        "action": "block_ip",
        "target": "192.168.1.100",
        "parameters": {"duration": 86400}
      }
    ],
    "approver_id": null,
    "approved_at": null,
    "executor_id": null,
    "executed_at": null
  }
]
```

#### POST /api/plans

Create a new response plan in `proposed` state. Requires `write` scope. Typically called by the Response Planner agent.

**Request Body:**
```json
{
  "case_id": "CASE-20260217-abc12345",
  "title": "Block attacker IP",
  "description": "Block source IP of brute force attack",
  "risk_level": "low",
  "actions": [
    {
      "action": "block_ip",
      "target": "192.168.1.100",
      "parameters": {"duration": 86400}
    }
  ]
}
```

Required fields: `case_id`, `actions` (non-empty array). Each action must have `action` and `target`.

> **Policy Enforcement:** Each action in the plan is validated against the action allowlist in `policies/policy.yaml`. Actions must be `enabled`, and the plan's confidence must meet the action's `min_confidence` threshold. Unlisted actions are denied when `deny_unlisted: true`. Returns `400` if policy denies an action.

**Response:** `201 Created`
```json
{
  "plan_id": "PLAN-1708171800000-a1b2c3d4",
  "case_id": "CASE-20260217-abc12345",
  "state": "proposed",
  "message": "Plan created in PROPOSED state. Requires Tier 1 approval before execution.",
  "next_step": "POST /api/plans/PLAN-1708171800000-a1b2c3d4/approve"
}
```

#### GET /api/plans/:planId

Get a specific plan by ID. Requires `read` scope. Automatically checks and updates expiry state.

**Response:** Full plan object (same structure as list item).

**Errors:**
- `404`: Plan not found

#### POST /api/plans/:planId/approve

**Tier 1: Approve a plan.** Transitions from `proposed` to `approved`. Requires `write` scope.

**Request Body:**
```json
{
  "approver_id": "U01ABCDEFGH",
  "reason": "Verified attacker IP from threat intel"
}
```

Required fields: `approver_id`.

**Response:** `200 OK`
```json
{
  "plan_id": "PLAN-1708171800000-a1b2c3d4",
  "state": "approved",
  "approver_id": "U01ABCDEFGH",
  "approved_at": "2026-02-17T10:35:00.000Z",
  "message": "Plan APPROVED (Tier 1 complete). Ready for execution.",
  "next_step": "POST /api/plans/PLAN-1708171800000-a1b2c3d4/execute",
  "responder_status": { "enabled": false, "..." : "..." }
}
```

**Errors:**
- `400`: Plan not in `proposed` state, or plan has expired
- `403`: Approver not authorized (policy check — approver group, risk level, action types)
- `404`: Plan not found

#### POST /api/plans/:planId/reject

Reject a plan. Transitions from `proposed` or `approved` to `rejected`. Requires `write` scope.

**Request Body:**
```json
{
  "rejector_id": "U01ABCDEFGH",
  "reason": "Need more investigation before blocking"
}
```

Required fields: `rejector_id`.

**Response:** `200 OK`
```json
{
  "plan_id": "PLAN-1708171800000-a1b2c3d4",
  "state": "rejected",
  "rejector_id": "U01ABCDEFGH",
  "rejected_at": "2026-02-17T10:35:00.000Z",
  "message": "Plan REJECTED. No actions will be executed."
}
```

#### POST /api/plans/:planId/execute

**Tier 2: Execute an approved plan.** Transitions from `approved` to `completed` (or `failed`). Requires `write` scope. Requires `AUTOPILOT_RESPONDER_ENABLED=true`.

**Request Body:**
```json
{
  "executor_id": "U01ABCDEFGH"
}
```

Required fields: `executor_id`.

**Response:** `200 OK` (all actions succeeded) or `207 Multi-Status` (partial failure)
```json
{
  "plan_id": "PLAN-1708171800000-a1b2c3d4",
  "state": "completed",
  "executor_id": "U01ABCDEFGH",
  "executed_at": "2026-02-17T10:40:00.000Z",
  "execution_result": {
    "total_actions": 1,
    "succeeded": 1,
    "failed": 0,
    "results": [...]
  },
  "message": "Plan EXECUTED successfully. All actions completed."
}
```

**Errors:**
- `403`: Responder capability is disabled, approver not authorized (policy check), or insufficient evidence (policy check)
- `400`: Plan not in `approved` state, or plan has expired
- `404`: Plan not found

---

## Error Responses

### 400 Bad Request
```json
{
  "error": "Invalid case ID format"
}
```

### 401 Unauthorized
```json
{
  "error": "Authorization required"
}
```

### 403 Forbidden
```json
{
  "error": "Responder capability is DISABLED",
  "responder_status": {...},
  "resolution": "Contact an administrator to enable AUTOPILOT_RESPONDER_ENABLED=true"
}
```

### 404 Not Found
```json
{
  "error": "Case not found"
}
```

### 429 Too Many Requests
```json
{
  "error": "Too Many Requests",
  "retry_after": 30
}
```

### 500 Internal Server Error
```json
{
  "error": "Internal server error"
}
```

## Rate Limiting

The API implements rate limiting to prevent abuse:
- **Window:** 60 seconds (configurable via `RATE_LIMIT_WINDOW_MS`)
- **Max Requests:** 100 per window (configurable via `RATE_LIMIT_MAX_REQUESTS`)

Rate limit headers are included in responses:
- `X-RateLimit-Remaining`: Requests remaining in current window

Health, ready, version, and metrics endpoints are exempt from rate limiting.

## Auth Failure Protection

After 5 failed auth attempts from an IP (within 15 minutes), the IP is locked out for 30 minutes:
- `AUTH_FAILURE_WINDOW_MS`: Tracking window (default: 900000)
- `AUTH_FAILURE_MAX_ATTEMPTS`: Max failures (default: 5)
- `AUTH_LOCKOUT_DURATION_MS`: Lockout duration (default: 1800000)

## Input Validation

- **Case IDs** must be alphanumeric with hyphens, 1-64 characters
- **Request bodies** are limited to 1MB
- **Plan actions** are validated at creation (each must have `action` and `target` fields)

## Security Headers

All responses include security headers:
- `X-Content-Type-Options: nosniff`
- `X-Frame-Options: DENY`
- `X-XSS-Protection: 1; mode=block`
- `Cache-Control: no-store`

## Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `RUNTIME_PORT` | 9090 | Port to listen on (`METRICS_PORT` accepted as alias) |
| `METRICS_HOST` | 127.0.0.1 | Host to bind to |
| `AUTOPILOT_SERVICE_TOKEN` | (none) | Service token for read-only API access |
| `AUTOPILOT_MCP_AUTH` | (none) | MCP auth token for read+write API access |
| `AUTOPILOT_RESPONDER_ENABLED` | false | Enable plan execution capability |
| `RATE_LIMIT_WINDOW_MS` | 60000 | Rate limit window in ms |
| `RATE_LIMIT_MAX_REQUESTS` | 100 | Max requests per window |
| `MCP_TIMEOUT_MS` | 30000 | MCP call timeout in ms |
| `APPROVAL_TOKEN_TTL_MINUTES` | 60 | Approval token TTL |
| `PLAN_EXPIRY_MINUTES` | 60 | Plan expiry time |
| `CORS_ORIGIN` | http://localhost:3000 | Allowed CORS origin |
| `CORS_ENABLED` | true | Enable CORS headers |
| `SHUTDOWN_TIMEOUT_MS` | 30000 | Graceful shutdown timeout |
| `OPENCLAW_GATEWAY_URL` | http://127.0.0.1:18789 | OpenClaw Gateway URL for webhook dispatch |
| `OPENCLAW_TOKEN` | (none) | Bearer token for Gateway webhook auth |
