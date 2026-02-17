# Responder Agent - Tool Usage

## Execute a Plan

Trigger execution of an approved plan via the Runtime Service API.

```
POST http://localhost:9090/api/plans/{plan_id}/execute
Content-Type: application/json

{
  "executor_id": "U1234567890"
}
```

**Preconditions checked by the service**:
1. Plan must be in `approved` state (Tier 1 human approval completed)
2. `AUTOPILOT_RESPONDER_ENABLED` must be `true`
3. Action limits and circuit breaker must not be tripped

**Response**: The service executes each action in sequence, records results in the plan, and updates the associated case with execution results.

## Check Responder Status

Verify the responder capability is enabled and healthy before attempting execution.

```
GET http://localhost:9090/api/responder/status
```

Port is configurable via `RUNTIME_PORT` env var (default: 9090).

## Verification Query Construction

After each action executes, construct a Wazuh query to verify the action took effect.

| Action | Query Template | Timeout |
|--------|---------------|---------|
| block_ip | `rule.groups:firewall AND data.srcip:{target} AND action:drop` | 30s |
| isolate_host | Check `agent.isolated == true` via agent status API | 60s |
| kill_process | Query process list on target agent, confirm PID absent | 30s |
| disable_user | Query authentication logs for account disable event | 30s |
| quarantine_file | Query file integrity monitoring for quarantine event | 30s |

Poll verification at 5-second intervals until match or timeout.

## Rollback Procedures

When a rollback is needed, use the corresponding Wazuh command:

| Action | Rollback Command | Notes |
|--------|-----------------|-------|
| `firewall-drop` | `firewall-drop-unblock` | Removes IP from block list |
| `isolate-endpoint` | `unisolate-endpoint` | Restores network connectivity |
| `kill-process` | -- | Not reversible; document in results |
| `disable-account` | `enable-account` | Re-enables the user account |
| `quarantine-file` | `restore-file` | Restores file to original path |

Rollback follows the same two-tier approval workflow as the original action. A new plan must be created, approved, and executed.

## Evidence Capture

Before executing destructive actions, capture baseline state:
- **Isolate Host**: Record current network connections (`netstat` or equivalent)
- **Kill Process**: Record process details (PID, command line, parent, user)
- **Quarantine File**: Record file hash (SHA-256), full path, size, timestamps

Attach captured evidence to the case store as part of the execution result.
