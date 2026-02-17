# Triage Agent -- Tool Usage Guide

## Wazuh Indexer Queries

### Fetching Untriaged Alerts
Use a time-range filter on `@timestamp` combined with the absence of a `triaged` tag:
```
GET /wazuh-alerts-*/_search
{
  "query": {
    "bool": {
      "must": [{ "range": { "@timestamp": { "gte": "now-10m" } } }],
      "must_not": [{ "term": { "tags": "triaged" } }]
    }
  },
  "size": 100,
  "sort": [{ "rule.level": "desc" }, { "@timestamp": "asc" }]
}
```
Sort by `rule.level` descending so critical alerts are processed first.

### Field Path Differences by Platform

**Linux alerts**: Entity data lives under `data.srcip`, `data.srcuser`, `data.dstip`, `agent.name`.

**Windows alerts**: Most enrichment is under `data.win.eventdata.*` -- e.g., `data.win.eventdata.ipAddress`, `data.win.eventdata.targetUserName`, `data.win.eventdata.image`.

**AWS CloudTrail**: User identity is at `data.aws.userIdentity.userName`, source IP at `data.aws.sourceIPAddress`. Region and service are at `data.aws.awsRegion` and `data.aws.eventSource`.

**Syscheck (FIM)**: Hashes are at `syscheck.md5_after`, `syscheck.sha256_after`. File path is at `syscheck.path`.

### Batch Strategy
- Pull up to 100 alerts per query to avoid memory pressure.
- Process critical rule IDs (5710, 5712, 5720, 5763, 100002, 87105, 87106, 92000, 92100) in a dedicated first pass before general alerts.
- Use `_source` filtering to request only the fields needed for entity extraction -- reduces payload size by ~60%.

## Entity Extraction Pitfalls

- **Missing fields**: Not every alert populates every entity field. Always null-check before extraction. A firewall alert may have IPs but no users; an auth alert may have users but no hashes.
- **Duplicate IPs**: `agent.ip` is the agent's own address. Do not confuse it with `data.srcip` (the attacker) or `data.dstip` (the target).
- **Windows hash format**: `data.win.eventdata.hashes` uses the format `SHA256=abc123,MD5=def456`. Split on commas and parse key=value pairs.
- **Service accounts**: Users like `SYSTEM`, `LOCAL SERVICE`, `NETWORK SERVICE`, `DWM-*`, `UMFD-*` on Windows are service accounts. Flag them but do not treat them as human users.
- **Internal vs external IP classification**: Use RFC 1918 ranges (10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16) plus link-local (169.254.0.0/16) and loopback (127.0.0.0/8). Everything else is external.

## MITRE Mapping

- Prefer the mapping from `rule.mitre.id` and `rule.mitre.tactic` when present in the alert.
- Fall back to regex inference only when rule metadata lacks MITRE fields.
- When multiple techniques match, list all of them -- the Correlation Agent uses the full set for kill chain detection.

## Case Store Writes
- Always include `raw_alert_ids` as an array so downstream agents can trace back to source data.
- Ensure `timestamp` is ISO 8601 with timezone (UTC preferred).
- Keep `summary` under 2000 characters to avoid truncation in notification channels (Slack, email).
