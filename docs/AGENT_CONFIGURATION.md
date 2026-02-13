# Agent Configuration Guide

This document describes how to configure and customize the OpenClaw agents for Wazuh Autopilot.

## Overview

Wazuh Autopilot includes 7 specialized agents, each handling a specific aspect of the SOC workflow:

| Agent | Role | Autonomy Level |
|-------|------|----------------|
| Triage | Alert analysis, entity extraction | Read-only (Full auto) |
| Correlation | Pattern detection, alert linking | Read-only (Full auto) |
| Investigation | Deep analysis, evidence gathering | Read-only (Full auto) |
| Response Planner | Action plan generation | Approval-gated |
| Policy Guard | Constitutional enforcement | Approval-gated |
| Responder | Action execution | Approval-gated (Disabled by default) |
| Reporting | Summary generation, metrics | Read-only (Full auto) |

---

## Agent File Structure

Each agent is defined in a YAML file:

```
/etc/wazuh-autopilot/agents/
├── triage.agent.yaml
├── correlation.agent.yaml
├── investigation.agent.yaml
├── response-planner.agent.yaml
├── policy-guard.agent.yaml
├── responder.agent.yaml
└── reporting.agent.yaml
```

---

## Common Configuration Sections

### Identity Section

```yaml
name: wazuh-triage-agent
version: "2.0.0"
description: |
  Brief description of what this agent does.
  Can be multi-line.

role: triage              # Agent's role identifier
autonomy_level: read-only # read-only | approval | limited-auto
autonomous_execution: true # Can run without human prompts
```

### Tool Permissions

```yaml
allowed_tools:
  - name: get_alert
    purpose: "Fetch complete alert details"
    required: true

  - name: search_alerts
    purpose: "Find related alerts"
    required: true

denied_tools:
  - block_ip
  - isolate_host
  - kill_process
  - "*_write"      # Wildcard patterns
  - "*_execute"
  - "*_modify"
```

### Triggers

```yaml
triggers:
  # Event-based triggers
  events:
    - type: wazuh_alert
      conditions:
        severity:
          - high
          - critical
        rule_level_min: 10
      auto_execute: true
      priority: immediate

  # Command-based triggers (Slack commands)
  commands:
    - name: triage
      pattern: "/wazuh triage <alert_id>"
      description: "Manually triage a specific alert"

  # Scheduled triggers
  scheduled:
    - name: sweep_untriaged
      cron: "*/10 * * * *"
      description: "Sweep for untriaged alerts"
      query: "rule.level >= 10 AND NOT _exists_:case_id"
```

### Outputs

```yaml
outputs:
  case:
    create: true
    update: true
    fields:
      - case_id
      - title
      - summary
      - severity

  evidence_pack:
    update: true
    sections:
      - alert_raw
      - entities
      - timeline

  slack:
    enabled: true
    channel_type: alerts
    post_case_card: true
```

### Resilience

```yaml
resilience:
  retry_policy:
    max_attempts: 3
    backoff_type: exponential
    initial_delay_ms: 1000
    max_delay_ms: 30000

  fallback_behavior:
    mcp_unavailable: queue_for_retry
    slack_unavailable: log_and_continue

  circuit_breaker:
    enabled: true
    failure_threshold: 5
    reset_timeout_seconds: 60
```

### Rate Limits

```yaml
rate_limits:
  max_concurrent: 10
  max_per_minute: 100
  max_per_hour: 2000
  burst_allowance: 20
  cooldown_on_error_ms: 5000
```

### Logging & Metrics

```yaml
logging:
  level: info
  structured: true
  fields:
    - correlation_id
    - case_id
    - alert_id
  redact:
    - password
    - token
    - secret

metrics:
  - name: autopilot_triage_total
    type: counter
    labels: [severity, rule_group]
```

---

## Agent-Specific Configuration

### Triage Agent

The triage agent handles first-line alert analysis.

**Key Configuration:**

```yaml
# Entity extraction settings
entity_extraction:
  enabled: true
  autonomous: true
  extractors:
    ip:
      fields:
        - data.srcip
        - data.dstip
      validation: ipv4_or_ipv6
      enrich:
        - geolocation
        - reputation_hint
        - is_internal

    user:
      fields:
        - data.srcuser
        - data.dstuser
      normalize: lowercase
      enrich:
        - is_service_account
        - is_privileged
```

**Customization Examples:**

```yaml
# Add custom entity extraction field
entity_extraction:
  extractors:
    ip:
      fields:
        - data.srcip
        - data.custom_field.ip_address  # Add your custom field
```

### Correlation Agent

Links related alerts into unified cases.

**Key Configuration:**

```yaml
correlation:
  time_windows:
    short: 5m
    medium: 1h
    long: 24h

  matching_rules:
    - name: same_source_ip
      fields: [data.srcip]
      window: short
      weight: 0.8

    - name: same_target_host
      fields: [agent.name]
      window: medium
      weight: 0.6
```

### Investigation Agent

Deep-dives into suspicious activity.

**Key Configuration:**

```yaml
investigation:
  techniques:
    - process_tree_analysis
    - network_connection_mapping
    - file_timeline_construction
    - user_activity_profiling

  depth_levels:
    quick: 1
    standard: 3
    deep: 5
```

### Response Planner Agent

Generates response plans requiring approval.

**Key Configuration:**

```yaml
planning:
  strategies:
    containment_first:
      priority: 1
      actions: [isolate, block]

    evidence_first:
      priority: 2
      actions: [snapshot, preserve]

  risk_assessment:
    factors:
      - asset_criticality
      - user_sensitivity
      - business_impact
```

### Policy Guard Agent

Enforces security policies on all actions.

**Key Configuration:**

```yaml
# Loads policy from separate file
policy_source: /etc/wazuh-autopilot/policies/policy.yaml

constitutional_principles:
  - "Never approve actions on critical infrastructure without admin approval"
  - "Always verify evidence before allowing containment"
  - "Deny actions that could cause data loss"

decision_logging:
  enabled: true
  include_reasoning: true
```

### Responder Agent

Executes approved actions.

**Key Configuration:**

```yaml
# CRITICAL: Disabled by default for safety
enabled: false

enable_requirements:
  - config_flag: AUTOPILOT_ENABLE_RESPONDER=true
  - mcp_tools_available: true
  - policy_guard_active: true
  - approval_workflow_configured: true

# Kill switch for emergency halt
kill_switch:
  enabled: true
  triggers:
    - type: manual
      command: "/wazuh halt"
    - type: automatic
      condition: "consecutive_failures >= 3"
```

### Reporting Agent

Generates summaries and metrics.

**Key Configuration:**

```yaml
reports:
  types:
    - daily_summary
    - weekly_trends
    - incident_closeout

  delivery:
    slack:
      enabled: true
      channel_type: reports
    email:
      enabled: false
    webhook:
      enabled: false
```

---

## Enabling/Disabling Agents

### Disable an Agent

Add `enabled: false` at the top level:

```yaml
name: wazuh-triage-agent
enabled: false  # Agent will not run
```

### Conditional Enablement

```yaml
enabled: true
enable_conditions:
  - environment: production
  - feature_flag: ENABLE_TRIAGE
```

---

## Custom Agents

Create custom agents for specialized workflows.

### Template

```yaml
name: custom-agent
version: "1.0.0"
description: "My custom agent"

role: custom
autonomy_level: read-only
autonomous_execution: false

allowed_tools:
  - name: search_alerts
    purpose: "Search alerts"
    required: true

denied_tools:
  - "*_write"
  - "*_execute"

triggers:
  commands:
    - name: custom-action
      pattern: "/wazuh custom <parameter>"
      description: "Run custom action"

outputs:
  slack:
    enabled: true
    channel_type: alerts

resilience:
  retry_policy:
    max_attempts: 3
    backoff_type: exponential
    initial_delay_ms: 1000

rate_limits:
  max_concurrent: 5
  max_per_minute: 30

logging:
  level: info
  structured: true
```

### Register Custom Agent

1. Save to `/etc/wazuh-autopilot/agents/custom.agent.yaml`
2. Restart OpenClaw: `docker restart openclaw`
3. Verify: Check OpenClaw logs for agent registration

---

## Wazuh Expertise Configuration

Agents include Wazuh-specific knowledge:

```yaml
wazuh_expertise:
  rule_categories:
    - syscheck
    - rootcheck
    - windows
    - authentication

  severity_mapping:
    0-3: informational
    4-6: low
    7-9: medium
    10-12: high
    13-15: critical

  critical_rule_ids:
    - 5712   # SSH brute force
    - 87105  # Windows multiple failures
    - 100002 # Suricata high severity
```

---

## Environment-Specific Configuration

### Development

```yaml
# dev.overrides.yaml
logging:
  level: debug

rate_limits:
  max_per_minute: 1000  # Higher for testing

slack:
  enabled: false  # Disable during dev
```

### Production

```yaml
# prod.overrides.yaml
logging:
  level: info

rate_limits:
  max_per_minute: 100

resilience:
  circuit_breaker:
    failure_threshold: 3  # Stricter
```

---

## Validation

### Syntax Check

```bash
# Validate YAML syntax
yamllint /etc/wazuh-autopilot/agents/*.yaml
```

### Schema Validation

The runtime validates agent configuration on startup. Check logs for validation errors:

```bash
journalctl -u wazuh-autopilot | grep -i "agent.*validation"
```

### Testing

```bash
# Test agent in dry-run mode (if supported)
./test-agent.sh triage --dry-run --alert-id 12345
```

---

## Troubleshooting

### Agent Not Responding

1. Check agent is enabled: `enabled: true`
2. Verify triggers are configured correctly
3. Check OpenClaw logs: `docker logs openclaw`
4. Verify MCP connectivity

### Tool Permission Errors

1. Verify tool is in `allowed_tools`
2. Check tool is not in `denied_tools`
3. Verify MCP server has the tool available

### Rate Limiting Issues

1. Check current rate limits in config
2. Monitor metrics: `curl localhost:9090/metrics | grep rate`
3. Increase limits if needed

---

## Best Practices

1. **Start with read-only agents** - Enable responder only after testing
2. **Use explicit tool denials** - Deny dangerous tools by default
3. **Configure rate limits** - Prevent runaway automation
4. **Enable circuit breakers** - Protect against cascading failures
5. **Log everything** - Enable structured logging with correlation IDs
6. **Test in isolation** - Test agents individually before full deployment
7. **Review policies** - Ensure policy.yaml aligns with agent capabilities
