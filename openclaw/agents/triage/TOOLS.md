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

## Runtime API Access

The Triage Agent calls the runtime REST API at `http://localhost:9090` using `web_fetch`. All requests require the auth token as a `token` query parameter.

> **Note**: These endpoints use GET with query parameters because OpenClaw's `web_fetch` tool only supports GET requests (no custom headers). Pass the auth token as `?token=<AUTOPILOT_MCP_AUTH>` on every request.

### Authentication

All API calls require the `AUTOPILOT_MCP_AUTH` token passed as a query parameter:

    web_fetch(url="http://localhost:9090/api/cases?token=<AUTOPILOT_MCP_AUTH>")

The token value is provided in your workspace environment. Include `&token=<value>` (or `?token=<value>` if it's the first parameter) on every request.

### List Existing Cases

Check for duplicates before creating a new case.

    web_fetch(url="http://localhost:9090/api/cases?token=<AUTOPILOT_MCP_AUTH>")

### Read a Case

    web_fetch(url="http://localhost:9090/api/cases/{case_id}?token=<AUTOPILOT_MCP_AUTH>")

### Update Case Status

Set `status=triaged` to hand off to the Correlation Agent. The runtime automatically dispatches a webhook to trigger the next agent.

    web_fetch(url="http://localhost:9090/api/agent-action/update-case?case_id={case_id}&status=triaged&token=<AUTOPILOT_MCP_AUTH>")

To include additional data (e.g., entities, timeline, auto_verdict), URL-encode a JSON object in the `data` parameter:

    web_fetch(url="http://localhost:9090/api/agent-action/update-case?case_id={case_id}&status=triaged&data={url_encoded_json}&token=<AUTOPILOT_MCP_AUTH>")

The `data` JSON object should include your triage output fields: `title`, `summary`, `severity`, `confidence`, `auto_verdict`, `verdict_reason`, `mitre`, `entities`, `timeline`. See AGENTS.md for the full output format and auto-verdict categories.

**Note**: Setting `status=triaged` automatically triggers the Correlation Agent.

## Stalled Pipeline Retries

If this agent is triggered with a message prefixed `[RETRY]`, it means the case was previously stalled in the pipeline and is being re-dispatched automatically. The message will contain a pre-built callback URL. Use `web_fetch` to call the provided URL after completing your analysis — do not construct your own URL when one is provided in the retry message.
