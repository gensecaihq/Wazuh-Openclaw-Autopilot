# Reporting Agent - Tool Usage

## Prometheus Metrics Parsing

Query the Prometheus endpoint to retrieve SOC operational metrics.

```
GET http://localhost:9090/metrics
```

**Key metrics to extract**:
| Metric Name | Description | Used In |
|-------------|-------------|---------|
| `autopilot_alerts_total` | Total alerts received (counter) | Alert volume, baseline comparison |
| `autopilot_cases_total` | Total cases created (counter) | Case volume, efficiency |
| `autopilot_mttd_seconds` | Mean time to detect (histogram) | MTTD KPI |
| `autopilot_mttr_seconds` | Mean time to respond (histogram) | MTTR KPI |
| `autopilot_false_positive_total` | False positive count (counter) | FP rate calculation |
| `autopilot_actions_total` | Actions executed (counter by status) | Action success rate |
| `autopilot_agent_health` | Agent health gauge (1=healthy) | Agent health section |

**Rate calculations**: Use `increase(metric[window])` logic when computing rates over lookback periods. For hourly snapshots use 1h window, for daily use 24h, etc.

**Histogram percentiles**: For time metrics (MTTD, MTTR), compute p50, p90, p99 from histogram buckets.

## MCP Alert Aggregation Queries

Use `get_wazuh_alerts` to aggregate alert data for report sections.

**Alert volume by severity** (last 24h):
```json
{
  "query": "*",
  "timerange": { "from": "now-24h", "to": "now" },
  "aggregations": {
    "by_severity": { "field": "rule.level", "type": "terms" }
  }
}
```

**Top noisy rules** (last 24h):
```json
{
  "query": "*",
  "timerange": { "from": "now-24h", "to": "now" },
  "aggregations": {
    "by_rule": { "field": "rule.id", "type": "terms", "size": 10 }
  }
}
```

**Recurring offenders** (last 24h):
```json
{
  "query": "rule.level:>=10",
  "timerange": { "from": "now-24h", "to": "now" },
  "aggregations": {
    "by_srcip": { "field": "data.srcip", "type": "terms", "size": 10 }
  }
}
```

**Agent status**: Use `get_wazuh_agents` with the agent ID to check online/offline/disconnected status for the agent health section.

## Slack Block Formatting

Reports posted to Slack should use Block Kit format for readability.

**Header block**:
```json
{
  "type": "header",
  "text": { "type": "plain_text", "text": "Daily Security Digest - 2026-02-17" }
}
```

**KPI section with status indicators**:
- Use `:white_check_mark:` for metrics at or below target
- Use `:warning:` for metrics in warning range
- Use `:red_circle:` for metrics in critical range

**Dividers**: Use `{"type": "divider"}` between report sections.

**Trend arrows in text**:
- Improving: arrow_down (for time metrics) or arrow_up (for coverage)
- Stable: left_right_arrow
- Degrading: arrow_up (for time metrics) or arrow_down (for coverage)

**Character limit**: Slack blocks have a 3000-character limit per text block. Split long sections across multiple blocks.

**Recommendations section**: Use a numbered list in a `section` block. Each recommendation should include the trigger condition and suggested action.

## Report Storage

Write all generated reports to disk:
```
${AUTOPILOT_DATA_DIR}/reports/{report_type}/{YYYY-MM-DD}/{report_type}_{timestamp}.json
```

Example: `reports/daily_digest/2026-02-17/daily_digest_2026-02-17T08:00:00Z.json`
