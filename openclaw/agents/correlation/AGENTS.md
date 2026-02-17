# Correlation Agent -- Operating Instructions

## Pipeline Context

**Input**: Structured triage case JSON from the Triage Agent. Each case contains extracted entities, severity, confidence score, MITRE mappings, and raw alert IDs.

**Output**: Enriched case JSON with correlation metadata, timelines, blast radius, and attack pattern classification. Handed to the **Investigation Agent** when correlation score or severity warrants deeper analysis.

---

## Attack Patterns to Detect

### Brute Force
- **Indicators**: `rule_groups` containing `authentication_failed`, `pam`, `sshd`
- **Threshold**: 5 or more events within a 10-minute window
- **MITRE**: T1110
- **Severity boost**: +1

### Lateral Movement
- **Indicators**: `rule_groups` containing `sysmon`, `windows`; `rule_ids` 92001, 92002, 92003; sequential events across hosts
- **MITRE**: T1021, T1570
- **Severity boost**: +2

### Privilege Escalation
- **Indicators**: `rule_groups` containing `pam`, `sudo`, `windows_security`; patterns `sudo.*root`, `runas`, `privilege`
- **MITRE**: T1068, T1548
- **Severity boost**: +2

### Data Exfiltration
- **Indicators**: `rule_groups` containing `firewall`, `ids`; data volume >100 MB; external destination IP
- **MITRE**: T1041, T1048
- **Severity boost**: +3

### Persistence
- **Indicators**: `rule_groups` containing `syscheck`, `sysmon`; paths matching `/etc/cron*`, `\Windows\System32`, Registry Run keys
- **MITRE**: T1053, T1547
- **Severity boost**: +2

### Defense Evasion
- **Indicators**: `rule_groups` containing `sysmon`, `rootcheck`; patterns `log.*clear`, `audit.*disable`, `defender.*disable`
- **MITRE**: T1070, T1562
- **Severity boost**: +2

---

## Entity Relationship Weights

When computing correlation links between cases, weight shared entities as follows:

| Relationship | Weight |
|---|---|
| same_source_ip | 0.9 |
| same_target_host | 0.95 |
| same_user | 0.85 |
| process_parent_child | 1.0 |
| network_connection | 0.7 |
| file_access_sequence | 0.8 |
| temporal_proximity | 0.6 |

---

## Time Windows

| Window | Duration | Use |
|---|---|---|
| Short | 5 minutes | Rapid-fire events (brute force, scanning) |
| Medium | 1 hour | Multi-stage attacks within a session |
| Long | 24 hours | Slow-burn campaigns, persistence |

---

## Clustering Strategies

Compute a composite cluster score using these four dimensions:

### Entity Overlap (35% weight)
Cluster alerts that share hosts, users, or IPs. Minimum entity overlap threshold: 30%.

### Temporal Proximity (25% weight)
Cluster alerts within the applicable time window. Maximum gap between events: 300 seconds. Apply a decay factor of 0.9 per gap interval.

### Rule Similarity (20% weight)
Cluster alerts from the same or related rule categories. Same-group boost: 0.8. Related-group boost: 0.5.

### Attack Chain (20% weight)
Match sequences against known attack progression patterns. Score based on how many kill chain phases are represented in the cluster.

---

## Correlation Thresholds

| Level | Score | Meaning |
|---|---|---|
| Minimum link | 0.5 | Cases may be related; weak signal |
| Strong correlation | 0.8 | Cases are likely part of the same incident |
| Definite link | 0.95 | Cases are confirmed as the same incident |

---

## Timeline Construction

Build chronological timelines and tag each event with its MITRE kill chain phase:

1. Initial Access (TA0001)
2. Execution (TA0002)
3. Persistence (TA0003)
4. Privilege Escalation (TA0004)
5. Defense Evasion (TA0005)
6. Credential Access (TA0006)
7. Discovery (TA0007)
8. Lateral Movement (TA0008)
9. Collection (TA0009)
10. Exfiltration (TA0010)
11. Impact (TA0040)

The presence of 3+ kill chain phases in a single cluster is a strong indicator of a coordinated attack and should boost the overall severity.

---

## Blast Radius Calculation

Assess impact across these dimensions:

| Dimension | Weight | Multiplier |
|---|---|---|
| Hosts affected | 1.0 | Asset criticality multiplier |
| Users affected | 0.9 | Privileged user: 2.0x |
| Subnets affected | 0.8 | DMZ: 0.5x, Production: 1.5x |
| Services affected | 0.85 | Critical service: 2.0x |
| Data classifications | 1.0 | PII / financial: 2.0x |

### Blast Radius Score Interpretation

| Score | Label |
|---|---|
| 0-25 | Contained |
| 26-50 | Limited |
| 51-75 | Significant |
| 76-90 | Severe |
| 91-100 | Critical |

---

## Asset Criticality Patterns

Classify hostnames by regex match:

| Pattern | Criticality |
|---|---|
| `^dc-\|^ad-\|^ldap-` | CRITICAL |
| `^prod-\|^prd-` | HIGH |
| `^db-\|^sql-\|^mongo-\|^redis-` | HIGH |
| `^app-\|^web-\|^api-` | HIGH |
| `^stage-\|^staging-\|^stg-` | MEDIUM |
| `^dev-\|^test-\|^sandbox-` | LOW |

---

## Output Format

Emit an enriched case JSON. Example:

```json
{
  "case_id": "TRI-20260217-00042",
  "correlation": {
    "correlated_alert_ids": ["TRI-20260217-00038", "TRI-20260217-00040"],
    "correlation_score": 0.87,
    "attack_pattern": "brute_force",
    "kill_chain_phases": ["TA0006", "TA0001"],
    "timeline": [
      {"timestamp": "2026-02-17T10:24:00Z", "event": "SSH failed login (admin)", "phase": "TA0006"},
      {"timestamp": "2026-02-17T10:28:00Z", "event": "SSH failed login (root)", "phase": "TA0006"},
      {"timestamp": "2026-02-17T10:32:00Z", "event": "SSH successful login (admin)", "phase": "TA0001"}
    ],
    "blast_radius": {
      "score": 34,
      "label": "Limited",
      "hosts": ["prod-web-01"],
      "users": ["admin", "root"],
      "subnets": ["10.0.1.0/24"]
    },
    "entity_graph": {
      "nodes": ["203.0.113.44", "prod-web-01", "admin", "root"],
      "edges": [
        {"from": "203.0.113.44", "to": "prod-web-01", "type": "network"},
        {"from": "203.0.113.44", "to": "admin", "type": "auth_attempt"}
      ]
    },
    "related_cases": [],
    "severity_boosted": true,
    "original_severity": "high",
    "boosted_severity": "critical"
  }
}
```
