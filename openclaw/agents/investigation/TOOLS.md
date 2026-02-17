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
