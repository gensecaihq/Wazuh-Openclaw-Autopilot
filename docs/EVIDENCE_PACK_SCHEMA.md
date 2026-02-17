# Evidence Pack Schema

Evidence packs are the core data structure for audit-ready security cases in Wazuh Autopilot.

## Schema Version

Current version: `1.0`

## Structure

```json
{
  "schema_version": "1.0",
  "case_id": "CASE-20260217-abc12345",
  "created_at": "2026-02-17T10:30:00.000Z",
  "updated_at": "2026-02-17T10:35:00.000Z",
  "title": "Brute Force Attack on SSH",
  "summary": "Multiple failed login attempts detected from external IP",
  "severity": "high",
  "confidence": 0.85,
  "entities": [],
  "timeline": [],
  "mitre": [],
  "mcp_calls": [],
  "evidence_refs": [],
  "plans": [],
  "approvals": [],
  "actions": []
}
```

## Fields

### Root Fields

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `schema_version` | string | Yes | Schema version (currently "1.0") |
| `case_id` | string | Yes | Unique case identifier |
| `created_at` | ISO 8601 | Yes | Case creation timestamp |
| `updated_at` | ISO 8601 | Yes | Last update timestamp |
| `title` | string | Yes | Brief case title |
| `summary` | string | No | Detailed case summary |
| `severity` | enum | Yes | informational, low, medium, high, critical |
| `confidence` | float | No | Confidence score 0.0-1.0 |

### Entities

Extracted entities from alerts and investigation.

```json
{
  "entities": [
    {
      "type": "ip",
      "value": "192.168.1.100",
      "role": "attacker",
      "context": "Source of brute force attempts"
    },
    {
      "type": "user",
      "value": "admin",
      "role": "victim",
      "context": "Target user account"
    },
    {
      "type": "host",
      "value": "web-server-01",
      "role": "victim",
      "context": "Attacked system"
    }
  ]
}
```

**Entity Types:**
- `ip` - IP address
- `user` - Username
- `host` - Hostname
- `file` - File path or hash
- `process` - Process name or PID
- `domain` - Domain name
- `url` - Full URL
- `hash` - File hash (MD5, SHA1, SHA256)
- `email` - Email address

### Timeline

Chronological sequence of events.

```json
{
  "timeline": [
    {
      "timestamp": "2026-02-17T10:25:00.000Z",
      "event": "First failed login attempt",
      "source": "alert-123",
      "severity": "low"
    },
    {
      "timestamp": "2026-02-17T10:28:00.000Z",
      "event": "100+ failed attempts in 3 minutes",
      "source": "correlation-engine",
      "severity": "high"
    }
  ]
}
```

### MITRE ATT&CK Mapping

```json
{
  "mitre": [
    {
      "tactic": "credential-access",
      "technique": "T1110",
      "sub_technique": "T1110.001",
      "name": "Brute Force: Password Guessing",
      "confidence": 0.9
    }
  ]
}
```

### MCP Calls

Record of all MCP tool calls made during investigation.

```json
{
  "mcp_calls": [
    {
      "tool_name": "search_alerts",
      "request_hash": "abc123...",
      "response_hash": "def456...",
      "status": "success",
      "latency_ms": 150,
      "timestamp": "2026-02-17T10:30:15.000Z"
    }
  ]
}
```

### Evidence References

Links to source alerts and events.

```json
{
  "evidence_refs": [
    "alert-123",
    "alert-124",
    "alert-125"
  ]
}
```

### Plans

Response plans proposed by the Response Planner agent.

```json
{
  "plans": [
    {
      "plan_id": "PLAN-20260217-abc12345",
      "created_at": "2026-02-17T10:32:00.000Z",
      "proposed_by": "response-planner",
      "risk_level": "medium",
      "actions": [
        {
          "sequence": 1,
          "action": "block_ip",
          "target": "192.168.1.100",
          "parameters": {
            "duration": 86400
          },
          "risk": "low",
          "reversible": true
        }
      ],
      "status": "pending_approval"
    }
  ]
}
```

### Approvals

Human approval decisions.

```json
{
  "approvals": [
    {
      "plan_id": "PLAN-20260217-abc12345",
      "token": "abc123...",
      "approver_id": "USER-001",
      "approver_name": "Security Analyst",
      "decision": "approve",
      "decision_reason": "",
      "decided_at": "2026-02-17T10:40:00.000Z"
    }
  ]
}
```

### Actions

Executed response actions.

```json
{
  "actions": [
    {
      "plan_id": "PLAN-20260217-abc12345",
      "sequence": 1,
      "action": "block_ip",
      "target": "192.168.1.100",
      "started_at": "2026-02-17T10:41:00.000Z",
      "completed_at": "2026-02-17T10:41:02.000Z",
      "status": "success",
      "result": {
        "blocked": true,
        "firewall_rule_id": "rule-789"
      },
      "verification": {
        "verified": true,
        "verified_at": "2026-02-17T10:41:05.000Z"
      }
    }
  ]
}
```

## File Storage

Evidence packs are stored as JSON files:

```
/var/lib/wazuh-autopilot/
└── cases/
    └── CASE-20260217-abc12345/
        ├── evidence-pack.json    # Full evidence pack
        └── case.json             # Lightweight summary
```

## Validation Rules

1. **Case ID Format:** Alphanumeric with hyphens, 1-64 characters
2. **Timestamps:** Must be valid ISO 8601 format
3. **Severity:** Must be one of: informational, low, medium, high, critical
4. **Confidence:** Float between 0.0 and 1.0
5. **Entity types:** Must be from the defined list

## Schema Evolution

When the schema version changes:
1. New fields are added with backwards compatibility
2. Old evidence packs remain readable
3. Migration scripts provided for major version changes
