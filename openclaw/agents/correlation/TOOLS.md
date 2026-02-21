# Correlation Agent -- Tool Usage Guide

## Case Store Queries

### Fetching Recent Triage Cases for Correlation
Query the case store for cases created within the applicable time window. Always request the full entity block and MITRE mappings:
```
GET /cases/_search
{
  "query": {
    "bool": {
      "must": [
        { "range": { "timestamp": { "gte": "now-1h" } } },
        { "term": { "status": "triaged" } }
      ]
    }
  },
  "size": 200,
  "sort": [{ "timestamp": "asc" }]
}
```

### Fetching Active Correlated Clusters
When recorrelating, pull existing clusters that are still open:
```
GET /cases/_search
{
  "query": {
    "bool": {
      "must": [
        { "exists": { "field": "correlation.correlated_alert_ids" } },
        { "term": { "status": "correlated" } },
        { "range": { "timestamp": { "gte": "now-24h" } } }
      ]
    }
  }
}
```

## Entity Overlap Computation

### Efficient Set Intersection
- Extract entity sets from each case: `set(ips)`, `set(users)`, `set(hosts)`.
- Compute Jaccard similarity: `|A intersection B| / |A union B|`.
- Apply the entity relationship weights (same_source_ip: 0.9, same_target_host: 0.95, etc.) as multipliers on top of the Jaccard score.
- Short-circuit: if two cases share zero entities, skip temporal and rule similarity checks entirely.

### Cross-Platform Entity Normalization
- Hostnames: normalize to lowercase. Windows may report `PROD-WEB-01`; Linux reports `prod-web-01`.
- IP addresses: strip leading zeros (`010.000.001.001` -> `10.0.1.1`). Normalize IPv6 to compressed form.
- Users: normalize to lowercase. Windows domain users arrive as `DOMAIN\user`; strip the domain prefix for matching but retain it in the entity record.

## Temporal Analysis

### Gap Calculation
- Sort events by `timestamp` ascending.
- Calculate pairwise gaps between consecutive events.
- Apply the decay factor (0.9) per gap interval (300 seconds).
- If the maximum gap exceeds the time window, split into separate clusters.

### Time Zone Pitfall
- Wazuh alerts may arrive with inconsistent timezone offsets. Always normalize to UTC before computing temporal proximity.
- Cloud alerts (AWS CloudTrail, Azure Activity Log) are already UTC. Agent-based alerts may use local time.

## Attack Chain Scoring

### Pattern Matching Order
Evaluate patterns from highest severity boost to lowest:
1. Data Exfiltration (+3) -- prioritize detection because it indicates data loss
2. Lateral Movement, Privilege Escalation, Persistence, Defense Evasion (+2)
3. Brute Force (+1)

### Kill Chain Completeness
Count distinct kill chain phases present in the cluster. Score:
- 1 phase: 0.2
- 2 phases: 0.4
- 3 phases: 0.7
- 4+ phases: 1.0

## Blast Radius Pitfalls

- **Subnet counting**: Use CIDR-based grouping, not exact IP matching. Two IPs in the same /24 count as one subnet.
- **Service detection**: Infer service from port numbers in network events (22=SSH, 443=HTTPS, 3389=RDP, 5432=PostgreSQL, etc.) when explicit service names are unavailable.
- **Critical asset inflation**: Do not double-count the same host in both "hosts affected" and "services affected" if the host IS the service.

## Batch Strategy
- Process correlation in 5-minute windows during cron runs.
- For high-severity clusters (score >= 0.8), emit immediately without waiting for the batch window to close.
- Cap cluster size at 50 cases to prevent runaway correlation on noisy rule groups.

## Runtime API Access

The Correlation Agent can call the runtime REST API at `http://localhost:9090` using `web.fetch`. All requests require Bearer authentication.

```
Authorization: Bearer ${AUTOPILOT_MCP_AUTH}
```

### List Cases (Find Triaged Cases)

```
GET http://localhost:9090/api/cases
```

Filter the response for cases with `status: "triaged"` to identify cases ready for correlation.

### Read Full Case Evidence Pack

```
GET http://localhost:9090/api/cases/{case_id}
```

Returns the complete case object including entities, timeline, MITRE mappings, and evidence references.

### Update Case with Correlation Data

After computing entity overlaps, temporal clusters, and attack chain scores, write the correlation results back and advance the case status.

```
PUT http://localhost:9090/api/cases/{case_id}
Content-Type: application/json

{
  "correlation": { ... },
  "status": "correlated"
}
```

Setting `status: "correlated"` automatically triggers the Investigation Agent.
