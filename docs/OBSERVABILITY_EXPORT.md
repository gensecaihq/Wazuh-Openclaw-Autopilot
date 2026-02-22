# Observability Export

Wazuh Autopilot exports metrics and logs for integration with your existing observability stack. This document covers what's exported and how to consume it.

## Design Philosophy

- **No stack shipped** - Autopilot doesn't include Prometheus, Grafana, or Loki
- **Standard formats** - Prometheus metrics, JSON structured logs
- **Secure defaults** - Metrics bound to localhost only
- **Optional OTEL** - OpenTelemetry support when configured

## Metrics

### Prometheus Endpoint

Autopilot exposes metrics at a Prometheus-compatible endpoint.

**Configuration:**

```bash
# In /etc/wazuh-autopilot/.env
METRICS_ENABLED=true
RUNTIME_PORT=9090        # Primary port variable (METRICS_PORT accepted as alias)
METRICS_HOST=127.0.0.1   # Localhost only for security
```

**Endpoint:** `http://127.0.0.1:9090/metrics`

### Available Metrics

#### Case Metrics

```prometheus
# Counter: Total cases created
autopilot_cases_created_total

# Counter: Total cases updated
autopilot_cases_updated_total

# Counter: Total alerts ingested
autopilot_alerts_ingested_total
```

#### Triage Metrics

```prometheus
# Histogram: Triage latency in seconds (sum and count only)
autopilot_triage_latency_seconds_sum
autopilot_triage_latency_seconds_count
```

#### MCP Metrics

```prometheus
# Counter: MCP tool calls by tool and status
autopilot_mcp_tool_calls_total{tool="wazuh_get_alert",status="success"}
autopilot_mcp_tool_calls_total{tool="wazuh_get_alert",status="error"}
autopilot_mcp_tool_calls_total{tool="wazuh_search_alerts",status="success"}

# Histogram: MCP tool call latency by tool (sum and count only)
autopilot_mcp_tool_call_latency_seconds_sum{tool="wazuh_get_alert"}
autopilot_mcp_tool_call_latency_seconds_count{tool="wazuh_get_alert"}
```

#### Planning and Approval Metrics

```prometheus
# Counter: Response plans proposed (by agents)
autopilot_action_plans_proposed_total

# Counter: Approval requests sent
autopilot_approvals_requested_total

# Counter: Approvals granted
autopilot_approvals_granted_total

# Counter: Two-tier approval workflow
autopilot_plans_created_total
autopilot_plans_approved_total
autopilot_plans_executed_total
autopilot_plans_rejected_total
autopilot_plans_expired_total

# Counter: Execution results
autopilot_executions_success_total
autopilot_executions_failed_total

# Counter: Responder disabled blocks
autopilot_responder_disabled_blocks_total

# Counter: Policy denials by reason
autopilot_policy_denies_total{reason="INSUFFICIENT_EVIDENCE"}
autopilot_policy_denies_total{reason="APPROVER_NOT_AUTHORIZED"}
autopilot_policy_denies_total{reason="ACTION_NOT_ALLOWED"}
```

#### Webhook Dispatch Metrics

```prometheus
# Counter: Successful webhook dispatches to OpenClaw Gateway
autopilot_webhook_dispatches_total

# Counter: Failed webhook dispatches
autopilot_webhook_dispatch_failures_total
```

#### Enrichment Metrics

```prometheus
# Counter: Total IP enrichment requests to AbuseIPDB
autopilot_enrichment_requests_total

# Counter: Enrichment cache hits (avoided API calls)
autopilot_enrichment_cache_hits_total

# Counter: Enrichment errors (API failures, timeouts)
autopilot_enrichment_errors_total
```

#### Feedback Metrics

```prometheus
# Counter: Total false positive verdicts
autopilot_false_positives_total

# Counter: Feedback submissions by verdict
autopilot_feedback_submitted_total{verdict="true_positive"}
autopilot_feedback_submitted_total{verdict="false_positive"}
autopilot_feedback_submitted_total{verdict="needs_review"}
```

#### Error Metrics

```prometheus
# Counter: Errors by component
autopilot_errors_total{component="mcp"}
autopilot_errors_total{component="slack"}
autopilot_errors_total{component="policy"}
```

### Scraping Configuration

#### Prometheus

Add to your `prometheus.yml`:

```yaml
scrape_configs:
  - job_name: 'wazuh-autopilot'
    static_configs:
      - targets: ['localhost:9090']
    scrape_interval: 15s
```

#### If running on a different host

Either:

1. **Use Tailscale** (recommended):
   ```yaml
   METRICS_HOST=tailscale0  # Bind to Tailscale interface
   ```
   Then scrape via Tailnet IP.

2. **Use SSH tunnel**:
   ```bash
   ssh -L 9090:localhost:9090 autopilot-host
   ```

3. **Use node_exporter textfile collector**:
   Export metrics to a file for node_exporter to read.

### Grafana Dashboard

Example Grafana queries:

**Cases per hour:**
```promql
rate(autopilot_cases_created_total[1h])
```

**Average triage latency:**
```promql
rate(autopilot_triage_latency_seconds_sum[5m]) / rate(autopilot_triage_latency_seconds_count[5m])
```

**MCP success rate:**
```promql
sum(rate(autopilot_mcp_tool_calls_total{status="success"}[5m])) /
sum(rate(autopilot_mcp_tool_calls_total[5m]))
```

**Policy deny breakdown:**
```promql
sum by (reason) (rate(autopilot_policy_denies_total[1h]))
```

**Webhook dispatch success rate:**
```promql
rate(autopilot_webhook_dispatches_total[5m]) /
(rate(autopilot_webhook_dispatches_total[5m]) + rate(autopilot_webhook_dispatch_failures_total[5m]))
```

**Enrichment cache hit rate:**
```promql
rate(autopilot_enrichment_cache_hits_total[5m]) /
rate(autopilot_enrichment_requests_total[5m])
```

**False positive rate:**
```promql
rate(autopilot_false_positives_total[1h]) /
rate(autopilot_cases_created_total[1h])
```

**Feedback by verdict:**
```promql
sum by (verdict) (rate(autopilot_feedback_submitted_total[1h]))
```

## Structured Logs

### Format

Autopilot emits JSON structured logs to stdout.

**Configuration:**

```bash
LOG_FORMAT=json  # json | text
LOG_LEVEL=info   # debug | info | warn | error
```

### Log Schema

Every log entry includes:

```json
{
  "ts": "2026-02-17T10:30:00.000Z",
  "level": "info",
  "component": "triage",
  "msg": "Case created",
  "correlation_id": "abc123",
  "case_id": "CASE-20260217-abc12345",
  "alert_id": "12345"
}
```

### Standard Fields

| Field | Description | Always Present |
|-------|-------------|----------------|
| `ts` | ISO 8601 timestamp | Yes |
| `level` | Log level | Yes |
| `component` | Source component | Yes |
| `msg` | Human-readable message | Yes |
| `correlation_id` | Request trace ID | When applicable |
| `case_id` | Case identifier | When applicable |
| `alert_id` | Alert identifier | When applicable |
| `plan_id` | Plan identifier | When applicable |
| `approval_id` | Approval identifier | When applicable |

### Slack-Related Fields

```json
{
  "slack_workspace_id": "T0123456789",
  "slack_channel_id": "C0123456789",
  "slack_user_id": "U0123456789"
}
```

### MCP-Related Fields

```json
{
  "mcp_tool": "wazuh_get_alert",
  "mcp_status": "success",
  "latency_ms": 234
}
```

### Security: No Secrets

Logs **never** include:
- API tokens
- Passwords
- Authentication credentials
- Private keys

These fields are automatically redacted.

### Log Collection

#### Loki (with Promtail)

Promtail configuration:

```yaml
scrape_configs:
  - job_name: wazuh-autopilot
    static_configs:
      - targets:
          - localhost
        labels:
          job: wazuh-autopilot
          __path__: /var/log/wazuh-autopilot/*.log

    pipeline_stages:
      - json:
          expressions:
            level: level
            component: component
            case_id: case_id
            correlation_id: correlation_id
      - labels:
          level:
          component:
```

#### systemd journal

If running as systemd service, logs go to journal:

```bash
journalctl -u wazuh-autopilot -f
```

Export to JSON:

```bash
journalctl -u wazuh-autopilot -o json
```

#### File output

Redirect stdout to file:

```bash
# In systemd service file
StandardOutput=append:/var/log/wazuh-autopilot/autopilot.log
```

### Useful Log Queries

**All errors:**
```
{job="wazuh-autopilot"} | json | level="error"
```

**Case activity:**
```
{job="wazuh-autopilot"} | json | case_id="CASE-20260217-abc12345"
```

**MCP failures:**
```
{job="wazuh-autopilot"} | json | component="mcp" | mcp_status="error"
```

**Policy denials:**
```
{job="wazuh-autopilot"} | json | component="policy" | msg=~".*deny.*"
```

## OpenTelemetry (Optional)

### Configuration

Set OTEL environment variables to enable:

```bash
OTEL_EXPORTER_OTLP_ENDPOINT=http://otel-collector:4317
OTEL_SERVICE_NAME=wazuh-autopilot
```

### Exported Spans

When OTEL is configured, Autopilot exports:

- Workflow spans (triage, correlation, planning)
- MCP call spans
- Approval workflow spans

### Trace Context

Correlation IDs are propagated as trace context, allowing end-to-end tracing from alert to action.

## Alerting Examples

### Prometheus Alertmanager

```yaml
groups:
  - name: wazuh-autopilot
    rules:
      - alert: AutopilotMCPFailures
        expr: rate(autopilot_mcp_tool_calls_total{status="error"}[5m]) > 0.1
        for: 5m
        labels:
          severity: warning
        annotations:
          summary: "High MCP failure rate"

      - alert: AutopilotHighDenyRate
        expr: |
          sum(rate(autopilot_policy_denies_total[1h])) /
          sum(rate(autopilot_approvals_requested_total[1h])) > 0.5
        for: 15m
        labels:
          severity: warning
        annotations:
          summary: "High policy denial rate"

      - alert: AutopilotServiceDown
        expr: up{job="wazuh-autopilot"} == 0
        for: 1m
        labels:
          severity: critical
        annotations:
          summary: "Autopilot service is down"
```

## Dashboard Reference

### Key Panels

1. **Cases Overview**
   - Cases created/updated per hour
   - Active cases by severity
   - Average triage time

2. **MCP Health**
   - Tool call success rate
   - Latency percentiles (p50, p95, p99)
   - Errors by tool

3. **Approvals**
   - Requests vs grants
   - Denial reasons breakdown
   - Average approval time

4. **System Health**
   - Error rate by component
   - Memory/CPU (from node_exporter)
   - Uptime

## Troubleshooting

### Metrics endpoint not responding

1. Check service is running:
   ```bash
   systemctl status wazuh-autopilot
   ```

2. Check port binding:
   ```bash
   ss -tlnp | grep 9090
   ```

3. Verify configuration:
   ```bash
   grep METRICS /etc/wazuh-autopilot/.env
   ```

### Missing metrics

Some metrics only appear after their first occurrence. For example, `autopilot_policy_denies_total{reason="X"}` only appears after a denial with that reason.

### Logs not in JSON

Check `LOG_FORMAT=json` in configuration.

### High cardinality warnings

The metrics are designed with bounded cardinality. If you see warnings, check for unexpected label values.
