# Investigation Agent -- Tool Usage Guide

## Wazuh Indexer Pivot Queries

### General Query Patterns
All pivots query `wazuh-alerts-*` indices. Use `bool` queries with time-range filters:
```
GET /wazuh-alerts-*/_search
{
  "query": {
    "bool": {
      "must": [
        { "range": { "@timestamp": { "gte": "now-{lookback}h" } } },
        { ... pivot-specific filter ... }
      ]
    }
  },
  "size": 0,
  "aggs": { ... pivot-specific aggregations ... }
}
```

### Aggregation Patterns
- **Terms agg** for cardinality analysis: `"aggs": { "by_rule": { "terms": { "field": "rule.id", "size": 50 } } }`
- **Date histogram** for timeline: `"aggs": { "over_time": { "date_histogram": { "field": "@timestamp", "fixed_interval": "5m" } } }`
- **Stats agg** for volume analysis: `"aggs": { "level_stats": { "stats": { "field": "rule.level" } } }`

### Combining Pivots
Run pivots in parallel where possible. For a brute force investigation, the IP history, target accounts, and success check queries are independent and can run simultaneously.

## Field Path Differences by Platform

### Linux
- Source IP: `data.srcip`
- User: `data.srcuser`, `data.dstuser`
- Process: `data.process.name`
- File paths: `syscheck.path`

### Windows
- Source IP: `data.win.eventdata.ipAddress`
- User: `data.win.eventdata.targetUserName`, `data.win.eventdata.subjectUserName`
- Process: `data.win.eventdata.image`, `data.win.eventdata.parentImage`, `data.win.eventdata.commandLine`
- Process GUID: `data.win.eventdata.processGuid`, `data.win.eventdata.parentProcessGuid`
- File paths: `data.win.eventdata.targetFilename`
- Hashes: `data.win.eventdata.hashes` (format: `SHA256=...,MD5=...`)

### AWS CloudTrail
- Source IP: `data.aws.sourceIPAddress`
- User: `data.aws.userIdentity.userName`
- Action: `data.aws.eventName`
- Service: `data.aws.eventSource`
- Region: `data.aws.awsRegion`

## Lookback Optimization

- Start with the default lookback for each pivot type.
- If the default lookback returns zero results, extend to the maximum lookback.
- If the maximum lookback also returns zero, record this as a negative finding (absence of evidence).
- For high-volume entities (e.g., an IP with >10,000 events), reduce the lookback window and increase aggregation granularity rather than pulling raw events.

## Process Tree Reconstruction

Sysmon process creation events (rule ID 92001, 92002) contain `processGuid` and `parentProcessGuid`. To reconstruct the tree:
1. Start with the suspicious process GUID.
2. Query for all events where `data.win.eventdata.parentProcessGuid` matches.
3. Recursively walk up to the parent using `data.win.eventdata.processGuid`.
4. Stop at system-level processes (`System`, `wininit.exe`, `services.exe`) or after 10 levels.

**Pitfall**: Process GUIDs are host-scoped. Never match GUIDs across different `agent.name` values.

## Network Connection Analysis

- Sysmon network events (rule ID 92003) provide `data.win.eventdata.destinationIp` and `data.win.eventdata.destinationPort`.
- Classify destinations as internal (RFC 1918) vs external.
- For external IPs, flag well-known malicious ports: 4444 (Metasploit default), 8443 (common C2), 1337 (leet port), non-standard high ports with sustained connections.
- Aggregate by destination to find beaconing patterns: regular interval connections to the same IP suggest C2.

## Baseline Comparison

- Compute the baseline over the 7 days preceding the incident window.
- Metrics to compare: total alert count, unique rule IDs triggered, unique destination IPs, authentication failure count.
- Flag any metric exceeding 2.0 standard deviations above baseline mean.
- **Pitfall**: Weekday vs weekend baselines differ significantly. If the incident falls on a weekend, use weekend-only baseline data.

## Historical Incident Matching

- Query the case store for incidents in the last 90 days matching any entity (IP, user, hash) from the current case.
- Apply the 0.95/day relevance decay: a 30-day-old match has relevance `0.95^30 = 0.21`.
- Matches with relevance below 0.1 can be mentioned but should not influence the findings classification.

## IOC Extraction Best Practices

- Always include context with each IOC: what role it played in the incident (source, target, C2, exfil destination).
- Deduplicate IOCs across pivot results before emitting.
- For IP IOCs, include the observed ports and protocols.
- For hash IOCs, include the file name and path where the hash was observed.
- For user IOCs, note whether the account is compromised (attacker used it) or targeted (attacker tried to access it).

## Runtime API Access

The Investigation Agent calls the runtime REST API at `http://localhost:9090` using `web_fetch`. All endpoints use GET requests with query parameters. Pass the auth token as `?token=<AUTOPILOT_MCP_AUTH>` on every request.

> **Note**: These endpoints use GET with query parameters because OpenClaw's `web_fetch` tool only supports GET requests (no custom headers).

### Read Case for Deep Investigation

    web_fetch(url="http://localhost:9090/api/cases/{case_id}?token=<AUTOPILOT_MCP_AUTH>")

Returns the full case object including triage data, correlation results, entities, and evidence references. Use this as the starting point for pivot queries against the Wazuh indexer.

### Search Alerts (Wazuh Indexer Pivot Queries)

Use this endpoint to execute pivot queries against the Wazuh indexer. This is how you answer investigation questions like "did the attacker successfully authenticate?" or "what other hosts did this IP target?"

**Free-text / field query** (uses `search_security_events` MCP tool):

    web_fetch(url="http://localhost:9090/api/agent-action/search-alerts?query={query_string}&time_range={duration}&limit={n}&token=<AUTOPILOT_MCP_AUTH>")

Parameters:
- `query` — Lucene-style query string (e.g., `data.srcip:{SOURCE_IP} AND rule.groups:authentication_success`)
- `time_range` — lookback duration (e.g., `24h`, `7d`, `168h`, `30m`). Default: `24h`
- `limit` — max results to return (1-500). Default: `50`

**Structured filter query** (uses `get_wazuh_alerts` MCP tool — omit `query` param):

    web_fetch(url="http://localhost:9090/api/agent-action/search-alerts?rule_id={id}&agent_id={id}&level={level}&time_range={duration}&limit={n}&token=<AUTOPILOT_MCP_AUTH>")

Parameters:
- `rule_id` — filter by Wazuh rule ID (e.g., `5712`)
- `agent_id` — filter by agent ID (e.g., `002`)
- `level` — filter by rule level (e.g., `12`)
- `time_range` — lookback duration. Default: `24h`
- `limit` — max results. Default: `50`

**Example pivot queries for brute force investigation:**

1. Check for successful authentication from attacker IP:
```
web_fetch(url="http://localhost:9090/api/agent-action/search-alerts?query=data.srcip:{SOURCE_IP}%20AND%20rule.groups:authentication_success&time_range=7d&limit=50&token=<AUTOPILOT_MCP_AUTH>")
```

2. Find all accounts targeted by attacker IP:
```
web_fetch(url="http://localhost:9090/api/agent-action/search-alerts?query=data.srcip:{SOURCE_IP}%20AND%20data.dstuser:*&time_range=7d&limit=100&token=<AUTOPILOT_MCP_AUTH>")
```

3. Get full attack history for an IP:
```
web_fetch(url="http://localhost:9090/api/agent-action/search-alerts?query=data.srcip:{SOURCE_IP}%20AND%20rule.groups:authentication&time_range=168h&limit=200&token=<AUTOPILOT_MCP_AUTH>")
```

4. Get high-severity alerts for a specific agent:
```
web_fetch(url="http://localhost:9090/api/agent-action/search-alerts?agent_id=002&level=12&time_range=24h&limit=50&token=<AUTOPILOT_MCP_AUTH>")
```

Do NOT mark pivot results as `requires_manual_execution`. Always execute them using this endpoint and include the actual results in your findings.

### Get Agent Information

    web_fetch(url="http://localhost:9090/api/agent-action/get-agent?agent_id={id}&token=<AUTOPILOT_MCP_AUTH>")

Returns agent details (name, IP, OS, status, last keep-alive) from the Wazuh manager. Use this to verify agent connectivity and gather host context during investigation.

### Update Case with Investigation Findings

After completing all pivot queries, baseline comparisons, and IOC extraction, write the findings back and advance the case status.

    web_fetch(url="http://localhost:9090/api/agent-action/update-case?case_id={case_id}&status=investigated&data={url_encoded_json}&token=<AUTOPILOT_MCP_AUTH>")

The `data` parameter is a URL-encoded JSON object containing your investigation findings:

```json
{
  "investigation": {
    "findings": "...",
    "iocs": [...],
    "baseline_comparison": {...}
  }
}
```

Setting `status=investigated` automatically triggers the Response Planner.

## Stalled Pipeline Retries

If this agent is triggered with a message prefixed `[RETRY]`, it means the case was previously stalled in the pipeline and is being re-dispatched automatically. The message will contain a pre-built callback URL. Use `web_fetch` to call the provided URL after completing your analysis — do not construct your own URL when one is provided in the retry message.
