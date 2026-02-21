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

Use `search_alerts` to aggregate alert data for report sections.

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

**Agent status**: Use `get_agent` with the agent ID to check online/offline/disconnected status for the agent health section.

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

## Runtime API Access

The Reporting Agent can call the runtime REST API at `http://localhost:9090` using `web.fetch`. All requests require Bearer authentication.

```
Authorization: Bearer ${AUTOPILOT_MCP_AUTH}
```

### Prometheus Metrics

The `/metrics` endpoint documented above is also accessible via `web.fetch`:

```
GET http://localhost:9090/metrics
```

### Case Summaries for Report Generation

```
GET http://localhost:9090/api/cases
```

Returns all cases. Use for aggregating case volume, severity distributions, and entity statistics in reports.

### Completed Plans for Action Reports

```
GET http://localhost:9090/api/plans?state=completed
```

Returns plans that were successfully executed. Use for action success rate calculations and response time analysis.

### Failed Plans for Incident Analysis

```
GET http://localhost:9090/api/plans?state=failed
```

Returns plans that failed during execution. Use for failure analysis, root cause breakdown, and improvement recommendations.
