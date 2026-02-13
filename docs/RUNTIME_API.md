# Runtime API Reference

The Wazuh Autopilot Runtime Service provides a REST API for case management, metrics, and health monitoring.

## Base URL

By default, the service listens on `http://127.0.0.1:9090`.

## Authentication

The API currently does not require authentication as it binds to localhost only. For production deployments, ensure proper network isolation.

## Endpoints

### Health & Status

#### GET /health

Returns service health status.

**Response:**
```json
{
  "status": "healthy",
  "version": "2.0.0",
  "mode": "bootstrap",
  "uptime_seconds": 3600,
  "checks": {
    "data_dir": true,
    "metrics": true
  },
  "timestamp": "2024-01-15T10:30:00.000Z"
}
```

#### GET /ready

Kubernetes-style readiness probe.

**Response:**
```json
{
  "ready": true
}
```

#### GET /version

Returns service version information.

**Response:**
```json
{
  "service": "wazuh-openclaw-autopilot",
  "version": "2.0.0",
  "node": "v18.19.0"
}
```

#### GET /metrics

Prometheus-format metrics endpoint.

**Response:** `text/plain`
```prometheus
# TYPE autopilot_cases_created_total counter
autopilot_cases_created_total 42
# TYPE autopilot_mcp_tool_calls_total counter
autopilot_mcp_tool_calls_total{tool="get_alert",status="success"} 100
```

### Cases API

#### GET /api/cases

List all cases (most recent first).

**Query Parameters:**
- `limit` (optional): Maximum number of cases to return (default: 100)

**Response:**
```json
[
  {
    "case_id": "CASE-2024-001",
    "created_at": "2024-01-15T10:30:00.000Z",
    "updated_at": "2024-01-15T10:35:00.000Z",
    "title": "Brute Force Attack on SSH",
    "severity": "high",
    "status": "open"
  }
]
```

#### POST /api/cases

Create a new case with evidence pack.

**Request Body:**
```json
{
  "case_id": "CASE-2024-001",
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
  "case_id": "CASE-2024-001",
  "created_at": "2024-01-15T10:30:00.000Z",
  "title": "Brute Force Attack on SSH",
  ...
}
```

#### GET /api/cases/:caseId

Get a specific case by ID.

**Response:**
```json
{
  "schema_version": "1.0",
  "case_id": "CASE-2024-001",
  "created_at": "2024-01-15T10:30:00.000Z",
  "updated_at": "2024-01-15T10:35:00.000Z",
  "title": "Brute Force Attack on SSH",
  "summary": "Multiple failed login attempts detected",
  "severity": "high",
  "confidence": 0.85,
  "entities": [...],
  "timeline": [...],
  "mcp_calls": [...],
  "evidence_refs": [...],
  "plans": [...],
  "approvals": [...],
  "actions": [...]
}
```

#### PUT /api/cases/:caseId

Update an existing case.

**Request Body:**
```json
{
  "severity": "critical",
  "entities": [{"type": "host", "value": "server-01"}],
  "status": "investigating"
}
```

**Response:** `200 OK` with updated case data.

## Error Responses

### 400 Bad Request
```json
{
  "error": "Invalid case ID format"
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

Health and metrics endpoints are exempt from rate limiting.

## Input Validation

- **Case IDs** must be alphanumeric with hyphens, 1-64 characters
- **Request bodies** are limited to 1MB

## Security Headers

All responses include security headers:
- `X-Content-Type-Options: nosniff`
- `X-Frame-Options: DENY`
- `X-XSS-Protection: 1; mode=block`
- `Cache-Control: no-store`

## Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `METRICS_PORT` | 9090 | Port to listen on |
| `METRICS_HOST` | 127.0.0.1 | Host to bind to |
| `RATE_LIMIT_WINDOW_MS` | 60000 | Rate limit window in ms |
| `RATE_LIMIT_MAX_REQUESTS` | 100 | Max requests per window |
| `MCP_TIMEOUT_MS` | 30000 | MCP call timeout in ms |
