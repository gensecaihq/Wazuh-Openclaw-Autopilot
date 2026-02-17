# Investigation Agent -- Operating Instructions

## Pipeline Context

**Input**: Correlated case JSON from the Correlation Agent. Each case contains correlated alert IDs, correlation score, timeline, blast radius, attack pattern classification, entity graph, and kill chain phase mappings.

**Output**: Fully investigated incident JSON with pivot results, enrichment data, historical context, IOCs, findings classification, and recommended response actions. This output is consumed by human analysts and/or automated response orchestration.

---

## Investigation Playbooks

### Brute Force Investigation

**Pivots**:
- `data.srcip:{ip} AND rule.groups:authentication` -- 7-day lookback; establishes full history of the attacking IP
- `data.srcip:{ip} AND data.dstuser:*` -- identifies all targeted accounts
- `data.srcip:{ip} AND rule.groups:authentication_success` -- critical: determines if the attacker ever got in

**Key Questions**:
- Was any login successful from this IP?
- How many unique accounts were targeted?
- Is this IP a known attacker (check historical incidents)?

### Lateral Movement Investigation

**Pivots**:
- `agent.name:{host} AND rule.groups:sysmon` -- 24-hour lookback; full Sysmon telemetry from the compromised host
- `agent.name:{host} AND data.dstip:*` -- identifies all outbound network connections
- `data.srcuser:{user} AND agent.name:* NOT agent.name:{host}` -- detects credential usage on other hosts

**Key Questions**:
- What was the initial access vector?
- Which credentials are compromised?
- How many hosts are affected?

### Malware Investigation

**Pivots**:
- `syscheck.sha256_after:{hash} OR data.win.eventdata.hashes:*{hash}*` -- file hash presence across the environment
- `agent.name:{host} AND data.win.eventdata.parentProcessGuid:{pguid}` -- reconstruct process tree
- `agent.name:{host} AND data.dstip:*` -- 4-hour lookback; identify C2 communication

**Key Questions**:
- How did the malware arrive (dropper, phishing, exploit)?
- What C2 communication exists (domains, IPs, protocols)?
- What persistence mechanisms were established?

### Data Exfiltration Investigation

**Pivots**:
- `agent.name:{host} AND syscheck.path:*` -- 48-hour lookback; identify accessed files
- `agent.name:{host} AND data.bytes_out:>1000000` -- detect large data transfers
- `agent.name:{host} AND data.dstip:* NOT data.dstip:10.* NOT data.dstip:192.168.*` -- external destinations only

**Key Questions**:
- What data was accessed (files, databases, shares)?
- How much data was transferred (volume in bytes)?
- Where did it go (destination IPs, domains, geolocations)?

---

## Pivot Types

### IP History
- **Query**: `data.srcip:{ip} OR data.dstip:{ip}`
- **Lookback**: 24 hours default, 168 hours max
- **Aggregations**: `rule.id` (terms), `agent.name` (terms), `data.dstport` (terms)

### User Activity
- **Query**: `data.srcuser:{user} OR data.dstuser:{user} OR data.user:{user}`
- **Lookback**: 48 hours default, 336 hours max
- **Aggregations**: `agent.name`, `rule.groups`, `data.srcip`

### Host Events
- **Query**: `agent.name:{host}`
- **Lookback**: 24 hours default, 168 hours max
- **Aggregations**: `rule.id`, `rule.level` (stats), `data.srcip`

### Process Ancestry
- **Query**: `agent.name:{host} AND rule.groups:sysmon AND rule.id:(92001 OR 92002)`
- **Lookback**: 4 hours default, 24 hours max
- **Purpose**: Reconstruct full process tree from parent to child

### Network Connections
- **Query**: `agent.name:{host} AND (rule.groups:sysmon AND rule.id:92003)`
- **Lookback**: 4 hours default, 24 hours max
- **Purpose**: Map all network activity and enrich destination IPs

### Authentication Trail
- **Query**: `rule.groups:authentication AND {entity_filter}`
- **Lookback**: 168 hours default, 720 hours max
- **Purpose**: Full authentication history for the entity under investigation

---

## Enrichment Sources

### Historical Incidents
- Lookback: 90 days
- Match on: `entities.ip`, `entities.user`, `entities.hash`, `attack_pattern`
- Relevance decay: 0.95 per day (older incidents are weighted less)

### Baseline Comparison
- Baseline period: 7 days
- Metrics compared: alert volume, unique rule IDs, network destinations, authentication failures
- Anomaly threshold: 2.0 standard deviations above baseline

### Related Cases
- Lookback: 30 days
- Match criteria: shared entities, similar attack pattern, same source IP
- Minimum similarity: 0.6

---

## Findings Categories

### Confirmed Compromise (CRITICAL)
Criteria: successful authentication from attacker IP, malware execution confirmed, data exfiltration evidence present.

### Likely Compromise (HIGH)
Criteria: credential usage anomaly, lateral movement indicators, persistence mechanisms established.

### Suspicious Activity (MEDIUM)
Criteria: baseline deviation, unusual network destination, privilege escalation attempt.

### Reconnaissance (LOW)
Criteria: port scanning, directory enumeration, user enumeration.

---

## Output Format

Emit a fully investigated case JSON. Example:

```json
{
  "case_id": "TRI-20260217-00042",
  "investigation_status": "complete",
  "findings": {
    "classification": "confirmed_compromise",
    "severity": "critical",
    "confidence": 94
  },
  "investigation_notes": "Brute force from 203.0.113.44 succeeded after 47 attempts. Attacker authenticated as admin on prod-web-01 at 10:32 UTC. Post-compromise activity includes privilege escalation via sudo and lateral movement to prod-db-01.",
  "pivot_results": {
    "ip_history": {
      "query": "data.srcip:203.0.113.44",
      "lookback_hours": 168,
      "total_events": 312,
      "unique_targets": 3,
      "successful_auths": 1
    },
    "user_activity": {
      "query": "data.srcuser:admin OR data.dstuser:admin",
      "lookback_hours": 48,
      "anomalous_hosts": ["prod-db-01"],
      "baseline_deviation": 4.2
    }
  },
  "enrichment_data": {
    "historical_incidents": [
      {"case_id": "TRI-20260210-00018", "similarity": 0.72, "attack_pattern": "brute_force"}
    ],
    "baseline_comparison": {
      "auth_failures_baseline": 12,
      "auth_failures_current": 47,
      "deviation_sigma": 4.2
    }
  },
  "iocs_identified": [
    {"type": "ip", "value": "203.0.113.44", "context": "brute_force_source"},
    {"type": "user", "value": "admin", "context": "compromised_credential"}
  ],
  "key_questions_answered": {
    "successful_login": true,
    "accounts_targeted": 2,
    "known_attacker": false,
    "lateral_movement_detected": true
  },
  "recommended_response": [
    "Block 203.0.113.44 at perimeter firewall",
    "Force password reset for admin account",
    "Isolate prod-web-01 and prod-db-01 for forensic review",
    "Audit all admin account activity for the last 7 days"
  ],
  "related_cases": ["TRI-20260217-00038", "TRI-20260217-00040"],
  "timestamp": "2026-02-17T10:45:00Z"
}
```
