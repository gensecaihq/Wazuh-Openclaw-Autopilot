# Reporting Agent -- Tool Usage Guide

## Runtime API Access

The Reporting Agent calls the runtime REST API at `http://localhost:9090` using `web_fetch`. All requests require the auth token as a `token` query parameter.

> **Note**: These endpoints use GET with query parameters because OpenClaw's `web_fetch` tool only supports GET requests (no custom headers). Pass the auth token as `?token=<AUTOPILOT_MCP_AUTH>` on every request.

### Authentication

All API calls require the `AUTOPILOT_MCP_AUTH` token passed as a query parameter:

    web_fetch(url="http://localhost:9090/api/cases?token=<AUTOPILOT_MCP_AUTH>")

The token value is provided in your workspace environment. Include `&token=<value>` (or `?token=<value>` if it's the first parameter) on every request.

---

## Case Endpoints

### List Cases (with Filtering)

    web_fetch(url="http://localhost:9090/api/cases?token=<AUTOPILOT_MCP_AUTH>")

Returns all cases. Supports filtering and pagination via query parameters:

| Parameter | Type | Description | Example |
|-----------|------|-------------|---------|
| `status` | string | Filter by case status | `status=triaged` |
| `severity` | string | Filter by severity level | `severity=critical` |
| `since` | ISO 8601 | Only cases created on or after this timestamp | `since=2026-03-26T00:00:00Z` |
| `until` | ISO 8601 | Only cases created before this timestamp | `until=2026-03-27T00:00:00Z` |
| `limit` | integer | Max number of results to return | `limit=50` |
| `offset` | integer | Number of results to skip (for pagination) | `offset=100` |

**Example -- last 24h critical cases, page 1**:

    web_fetch(url="http://localhost:9090/api/cases?status=triaged&severity=critical&since=2026-03-26T08:00:00Z&limit=20&offset=0&token=<AUTOPILOT_MCP_AUTH>")

Use for case volume analysis, severity distributions, entity statistics, and time-windowed reporting.

### Case Summary (Aggregated Stats)

    web_fetch(url="http://localhost:9090/api/cases/summary?token=<AUTOPILOT_MCP_AUTH>")

Returns pre-aggregated case statistics without transferring individual case records. Response fields:

| Field | Description |
|-------|-------------|
| `total` | Total case count |
| `by_status` | Object with counts per status (e.g., `{"new": 5, "triaged": 12, "closed": 40}`) |
| `by_severity` | Object with counts per severity (e.g., `{"critical": 2, "high": 8, "medium": 15, "low": 20}`) |
| `false_positive_count` | Number of cases marked as false positive |
| `last_24h` | Case count in the last 24 hours |
| `last_7d` | Case count in the last 7 days |
| `last_30d` | Case count in the last 30 days |

Use this endpoint for executive summaries, KPI dashboards, and trend comparisons. Prefer this over fetching all cases when you only need aggregate numbers.

---

## Plan Endpoints

### List Plans (with Filtering)

    web_fetch(url="http://localhost:9090/api/plans?token=<AUTOPILOT_MCP_AUTH>")

Returns plans. Supports filtering by state:

    web_fetch(url="http://localhost:9090/api/plans?state=completed&token=<AUTOPILOT_MCP_AUTH>")
    web_fetch(url="http://localhost:9090/api/plans?state=failed&token=<AUTOPILOT_MCP_AUTH>")

Use completed plans for action success rate calculations and response time analysis. Use failed plans for failure analysis and improvement recommendations.

### Plan Summary (Aggregated Stats)

    web_fetch(url="http://localhost:9090/api/plans/summary?token=<AUTOPILOT_MCP_AUTH>")

Returns pre-aggregated plan statistics. Response fields:

| Field | Description |
|-------|-------------|
| `total` | Total plan count |
| `by_state` | Object with counts per state (e.g., `{"pending": 3, "approved": 1, "completed": 25, "failed": 2}`) |
| `success_rate` | Percentage of completed plans vs total executed (completed + failed) |
| `last_24h` | Plan count in the last 24 hours |

Use this for action success rate KPIs and plan throughput metrics. Prefer this over listing all plans when you only need aggregate numbers.

---

## KPI Endpoint

### Pre-Computed SLA/KPI Metrics

    web_fetch(url="http://localhost:9090/api/kpis?period=24h&token=<AUTOPILOT_MCP_AUTH>")

Returns pre-computed KPI metrics for the specified period. Supported periods: `1h`, `8h`, `24h`, `7d`, `30d`.

**IMPORTANT: All MTTx values are in SECONDS, not minutes. Convert to minutes by dividing by 60 when displaying in reports. Label as `_seconds` not `_minutes`.**

| Field | Description |
|-------|-------------|
| `mttd` | Mean Time to Detect (**seconds**) |
| `mttt` | Mean Time to Triage (**seconds**) |
| `mtti` | Mean Time to Investigate (**seconds**) |
| `mttr` | Mean Time to Respond (**seconds**) |
| `mttc` | Mean Time to Contain (**seconds**) |
| `auto_triage_rate` | Percentage of cases auto-triaged |
| `false_positive_rate` | Percentage of cases marked false positive |
| `sla_compliance` | Percentage of cases meeting SLA targets |

**Example -- hourly KPIs**:

    web_fetch(url="http://localhost:9090/api/kpis?period=1h&token=<AUTOPILOT_MCP_AUTH>")

**Example -- weekly KPIs**:

    web_fetch(url="http://localhost:9090/api/kpis?period=7d&token=<AUTOPILOT_MCP_AUTH>")

Use this endpoint instead of manually computing KPIs from raw case data. It provides consistent, server-side calculations aligned with the KPI definitions in AGENTS.md.

---

## Prometheus Metrics

    web_fetch(url="http://localhost:9090/metrics?token=<AUTOPILOT_MCP_AUTH>")

Returns raw Prometheus-format metrics. Key metrics to extract:

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

> **Tip**: Prefer the `/api/kpis` endpoint for pre-computed KPI values. Use raw Prometheus metrics only when you need histogram percentile breakdowns, custom rate windows, or metrics not covered by the KPI endpoint.

---

## Report Storage Endpoints

### Store a Generated Report

    web_fetch(url="http://localhost:9090/api/agent-action/store-report?type=daily&data={URL_ENCODED_JSON}&token=<AUTOPILOT_MCP_AUTH>")

Stores a generated report in the report archive. The `data` parameter must be a URL-encoded JSON object containing the full report payload.

| Parameter | Type | Description | Required |
|-----------|------|-------------|----------|
| `type` | string | Report type: `hourly`, `daily`, `weekly`, `monthly`, `shift` | Yes |
| `data` | JSON (URL-encoded) | The complete report content as a JSON object | Yes |

The report JSON should include a `metadata` header as defined in AGENTS.md (report_type, generated_at, lookback_hours, data_sources_queried, version).

### List Stored Reports

    web_fetch(url="http://localhost:9090/api/reports?type=daily&limit=20&token=<AUTOPILOT_MCP_AUTH>")

Returns previously stored reports, filtered by type.

| Parameter | Type | Description | Default |
|-----------|------|-------------|---------|
| `type` | string | Report type to list: `hourly`, `daily`, `weekly`, `monthly`, `shift` | required |
| `limit` | integer | Max number of reports to return | 20 |

Use this to retrieve historical reports for trend comparison (e.g., this week's daily digest vs last week's).

---

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

---

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

## Stalled Pipeline Retries

If this agent is triggered with a message prefixed `[RETRY]`, it means a report generation was previously stalled and is being re-dispatched automatically. The message will contain a pre-built callback URL. Use `web_fetch` to call the provided URL after completing your analysis -- do not construct your own URL when one is provided in the retry message.
