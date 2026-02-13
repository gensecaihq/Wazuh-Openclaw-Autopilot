# Policy and Approval System

Wazuh Autopilot implements an enterprise-grade policy engine that controls all automated actions. This document explains how policies work and how to configure them.

## Core Principles

1. **Deny by Default** - Actions require explicit enablement
2. **Separation of Duties** - Different agents have different permissions
3. **Audit Trail** - Every decision is logged with reason codes
4. **Configurable Autonomy** - Balance automation with human oversight

## Autonomy Levels

Autopilot supports three autonomy levels:

### Read-Only (Default for most agents)

- Can query Wazuh data via MCP
- Can create and update cases
- Can post to Slack
- **Cannot** execute response actions

### Approval (Default for response actions)

- All capabilities of read-only
- Can propose response plans
- Can request approvals
- Executes actions **only after approval**

### Limited-Auto (Optional)

- Executes pre-approved safe actions automatically
- Still requires approval for risky actions
- Must be explicitly enabled

## Policy Configuration

All policies are defined in `policies/policy.yaml`. This file is the **source of truth** for all policy decisions.

### Autonomy Settings

```yaml
autonomy:
  default_level: approval

  operations:
    triage:
      level: read-only
      auto_execute: true

    response_planning:
      level: approval
      auto_execute: false

    action_execution:
      level: approval
      auto_execute: false
```

### Slack Allowlists

Control where Autopilot can operate:

```yaml
slack:
  workspace_allowlist:
    - id: "T0123456789"
      name: "Security Team"
      enabled: true

  channels:
    alerts:
      allowlist:
        - id: "C0123456789"
          name: "#security-alerts"
      deny_action: log_and_skip

    approvals:
      allowlist:
        - id: "C1234567890"
          name: "#security-approvals"
      deny_action: log_and_skip
```

### Approver Configuration

Define who can approve what:

```yaml
approvers:
  groups:
    standard:
      members:
        - slack_id: "U0123456789"
          name: "Security Analyst"
      can_approve:
        - block_ip
        - quarantine_file
      max_risk_level: medium

    elevated:
      members:
        - slack_id: "U1234567890"
          name: "Senior Engineer"
      can_approve:
        - block_ip
        - isolate_host
        - kill_process
      max_risk_level: high

    admin:
      members:
        - slack_id: "U2345678901"
          name: "Security Director"
      can_approve:
        - all
      max_risk_level: critical

  self_approval:
    allowed: false
```

### Action Allowlists

Control which actions are permitted:

```yaml
actions:
  enabled: false  # Global kill switch

  allowlist:
    block_ip:
      enabled: true
      risk_level: low
      requires_approval: true
      min_approver_group: standard
      min_confidence: 0.7
      min_evidence_items: 2

    isolate_host:
      enabled: true
      risk_level: medium
      requires_approval: true
      min_approver_group: elevated
      min_confidence: 0.8
      min_evidence_items: 3

    disable_user:
      enabled: true
      risk_level: high
      requires_approval: true
      min_approver_group: admin
      min_confidence: 0.9
      min_evidence_items: 5

  deny_unlisted: true
```

### Asset Criticality

Different rules for different asset types:

```yaml
assets:
  classifications:
    critical:
      patterns:
        hostnames:
          - "^prod-.*"
          - "^db-.*"
        ips:
          - "10.0.1.0/24"
      requires_approver_group: admin
      extra_evidence_required: 2

    production:
      patterns:
        hostnames:
          - "^app-.*"
          - "^web-.*"
      requires_approver_group: elevated

    development:
      patterns:
        hostnames:
          - "^dev-.*"
          - "^test-.*"
      requires_approver_group: standard

  default_classification: production
```

### Thresholds

Minimum requirements for different operations:

```yaml
thresholds:
  evidence:
    action_execution:
      min_items: 3

  confidence:
    action_execution:
      min: 0.7
    critical_action:
      min: 0.9
```

### Time Windows (Optional)

Restrict actions to certain times:

```yaml
time_windows:
  enabled: true

  operations:
    action_execution:
      windows:
        - days: [mon, tue, wed, thu, fri]
          start: "06:00"
          end: "22:00"
          timezone: UTC
      outside_window_action: deny

  emergency_override:
    enabled: true
    requires_approver_group: admin
```

## Approval Workflow

### 1. Response Planner Creates Plan

When a case reaches high/critical severity, the Response Planner agent generates a plan:

```json
{
  "plan_id": "PLAN-2024-001",
  "case_id": "CASE-2024-001",
  "actions": [
    {
      "action": "block_ip",
      "target": "192.168.1.100",
      "risk_level": "low"
    }
  ],
  "risk_assessment": {...},
  "blast_radius": {...}
}
```

### 2. Policy Guard Evaluates

The Policy Guard agent checks the plan against all policies:

```
Evaluation Order:
1. ✓ Workspace allowlist (passed)
2. ✓ Channel allowlist (passed)
3. ✓ Action allowlist (block_ip enabled)
4. ✓ Asset criticality (dev system, standard ok)
5. ✓ Evidence threshold (3 items >= 2 required)
6. ✓ Confidence threshold (0.85 >= 0.7)
7. ✓ Time window (within allowed hours)
8. ✓ Idempotency (IP not already blocked)

Result: ALLOW (proceed to approval)
```

### 3. Approval Request Posted

An approval request is posted to Slack:

```
🚨 Approval Request

Case: CASE-2024-001
Severity: High
Confidence: 85%

Proposed Actions:
1. Block IP 192.168.1.100 (risk: low)

Risk Assessment:
- Blast radius: 1 host affected
- Reversible: Yes

Evidence:
- 47 brute force attempts
- 3 source IPs correlated
- Pattern matches known attack

Required Approver: standard or higher

[Approve] [Deny] [Request Changes]
```

### 4. Approval Token Generated

A single-use, time-limited token is created:

```json
{
  "token": "abc123...",
  "plan_id": "PLAN-2024-001",
  "case_id": "CASE-2024-001",
  "expires_at": "2024-01-15T11:00:00Z",
  "used": false
}
```

### 5. Approver Responds

The approver clicks **Approve** or uses:

```
/wazuh approve PLAN-2024-001
```

### 6. Token Validated and Consumed

Policy Guard verifies:
- Token is valid
- Token not expired
- Token not already used
- Approver is authorized
- Approver is not the requester (self-approval prevention)

### 7. Action Executed (If Enabled)

If the Responder agent is enabled:
- Action is executed via MCP
- Result is verified
- Evidence pack is updated
- Confirmation posted to Slack

## Deny Reason Codes

Every policy denial includes a structured reason code:

| Code | Description |
|------|-------------|
| `WORKSPACE_NOT_ALLOWED` | Slack workspace not in allowlist |
| `CHANNEL_NOT_ALLOWED` | Slack channel not in allowlist |
| `APPROVER_NOT_AUTHORIZED` | Approver lacks permission for this action |
| `ACTION_NOT_ALLOWED` | Action type not in allowlist |
| `CRITICAL_ASSET_ELEVATED_APPROVAL` | Critical asset requires admin approval |
| `INSUFFICIENT_EVIDENCE` | Not enough evidence items |
| `LOW_CONFIDENCE` | Confidence score below threshold |
| `OUTSIDE_TIME_WINDOW` | Action outside allowed hours |
| `ALREADY_EXECUTED` | Action already performed (idempotency) |
| `DUPLICATE_REQUEST` | Same request within cooldown window |
| `EXPIRED_APPROVAL` | Approval token has expired |
| `INVALID_APPROVAL_TOKEN` | Token is invalid or malformed |

## Metrics

Policy decisions are tracked via Prometheus metrics:

```
autopilot_policy_evaluations_total
autopilot_policy_allows_total
autopilot_policy_denies_total{reason="INSUFFICIENT_EVIDENCE"}
autopilot_policy_denies_total{reason="APPROVER_NOT_AUTHORIZED"}
```

## Best Practices

### Start Restrictive

Begin with conservative settings:

```yaml
actions:
  enabled: false  # Disable actions initially

autonomy:
  default_level: approval
```

### Test in Bootstrap Mode

Use bootstrap mode for testing without Tailscale requirements.

### Review Deny Rates

Monitor `autopilot_policy_denies_total` to identify:
- Over-restrictive policies
- Training needs for approvers
- Potential configuration issues

### Regular Policy Review

Schedule quarterly reviews of:
- Approver lists
- Action allowlists
- Threshold values
- Time windows

### Document Exceptions

When making policy exceptions:
1. Document the business justification
2. Set an expiration date
3. Review during next policy audit

## Troubleshooting

### "Action not allowed"

1. Check `actions.enabled` is `true`
2. Verify action is in `allowlist`
3. Check action's `enabled` is `true`

### "Approver not authorized"

1. Verify approver's Slack ID in policy
2. Check approver is in correct group
3. Verify group can approve this action type

### "Insufficient evidence"

1. Lower threshold temporarily for testing
2. Ensure triage/investigation completed
3. Review evidence collection in playbook

### Self-approval issues

If legitimate need for self-approval:

```yaml
approvers:
  self_approval:
    allowed: true
    exception_groups:
      - admin
```

**Not recommended** - breaks separation of duties.
