# Playbook: Data Exfiltration Detection and Response

## Overview

| Field | Value |
|-------|-------|
| Playbook ID | PB-004 |
| Version | 1.0.0 |
| Severity | High-Critical |
| MITRE ATT&CK | T1041 - Exfiltration Over C2, T1048 - Exfiltration Over Alternative Protocol |
| Priority | HIGH |

## Description

This playbook handles potential data exfiltration attempts. Data exfiltration
is often the final stage of an attack and may indicate:
- Active breach in progress
- Insider threat activity
- Compromised credentials being exploited
- Ransomware data theft (double extortion)

## Detection Criteria

### Primary Indicators

#### Volume-Based
- Unusually large outbound transfers
- Sustained high-bandwidth connections
- Large uploads to cloud storage
- Bulk file access patterns

#### Protocol Anomalies
- DNS tunneling (large TXT queries, high query volume)
- HTTPS to unusual ports
- ICMP data exfiltration
- Encrypted traffic to unknown destinations

#### Behavioral Patterns
- Off-hours bulk data access
- Access to sensitive data by unusual accounts
- Compression before transfer
- Staging data in temp locations

### Wazuh Detection Indicators
| Indicator | Detection Method |
|-----------|------------------|
| Large transfers | Network monitoring + thresholds |
| DNS tunneling | High DNS query volume, long subdomains |
| Cloud uploads | URL filtering / proxy logs |
| File staging | FIM on temp/staging directories |
| Bulk access | Audit log analysis |

### High-Confidence Patterns
```yaml
high_confidence:
  - bulk_file_access AND large_outbound_transfer
  - data_compression AND external_upload
  - dns_tunnel_indicators AND sensitive_data_access
  - known_exfil_tool_execution
  - archive_creation AND cloud_upload
```

## Automated Triage Steps

### 1. Entity Extraction
```yaml
entities:
  - type: host
    source: agent.name
  - type: user
    source: data.user
  - type: ip
    source: data.dst_ip
  - type: domain
    source: data.dns.query
  - type: destination
    source: data.url OR data.dst_ip
  - type: file_paths
    source: data.path
  - type: data_volume
    source: data.bytes_sent
```

### 2. Data Classification Check
- What data was accessed?
- Is it classified/sensitive?
- What's the data volume?
- Where is it going?

### 3. User Context Assessment
| Factor | Check |
|--------|-------|
| User role | Authorized for this data? |
| Access pattern | Normal for this user? |
| Time of access | Unusual timing? |
| Location | Expected location? |

### 4. Severity Assessment
| Condition | Severity |
|-----------|----------|
| PII/PHI data involved | Critical |
| Financial data involved | Critical |
| Source code/IP involved | Critical |
| High volume + sensitive | Critical |
| Unusual destination | High |
| Off-hours activity | High |
| Unknown destination | High |

## Correlation Rules

### Related Alerts to Cluster
- File access events (especially bulk)
- Archive/compression tool usage
- Cloud storage connections
- Large outbound connections
- DNS anomalies
- VPN/proxy usage

### Timeline Construction
```yaml
timeline_query:
  lookback: 24h
  lookahead: 1h
  filters:
    - data.user: ${username}
    - agent.id: ${agent_id}
  include:
    - file_access_events
    - network_connections
    - dns_queries
    - process_executions
```

## Response Plan

### Investigation (Read-Only)

1. **Quantify data exposure**
   - What files were accessed?
   - What's the total volume?
   - What's the data classification?
   - How long has this been happening?

2. **Identify destination**
   - Known cloud storage?
   - Known bad infrastructure?
   - Personal accounts?
   - Competitor infrastructure?

3. **Determine legitimacy**
   - Is this authorized activity?
   - Is there a business justification?
   - Does the user's role support this?

### Containment (Approval Required)

#### Option A: Block Destination
```yaml
action: block_ip
target: ${destination_ip}
risk: low
justification: "Block potential exfiltration destination"
conditions:
  - external_destination: true
  - not_known_legitimate: true
```

#### Option B: Disable User Account
```yaml
action: disable_user
target:
  agent_id: ${agent_id}
  username: ${username}
risk: high
justification: "Stop potential data theft"
conditions:
  - high_confidence: true
  - sensitive_data_confirmed: true
requires_approver_group: admin
```

#### Option C: Isolate Host
```yaml
action: isolate_host
target: ${agent_id}
risk: medium
justification: "Prevent ongoing exfiltration"
conditions:
  - active_exfil_detected: true
  - host_compromised_likely: true
```

### Immediate Notifications

For confirmed or high-confidence exfiltration:
- Security Operations Lead
- Data Privacy Officer (if PII involved)
- Legal (if significant)
- CISO (if critical data)

## Evidence Collection

### Critical Evidence
| Source | Priority | Query |
|--------|----------|-------|
| File access | Critical | Audit logs for accessed files |
| Network flows | Critical | Outbound connections from host |
| DNS queries | High | DNS logs for user/host |
| Process execution | High | What tools were used |
| User activity | High | Login/session information |

### Evidence Pack Fields
```json
{
  "attack_type": "data_exfiltration",
  "exfiltration_method": "",
  "destination": {
    "type": "ip|domain|cloud_service",
    "value": "",
    "reputation": ""
  },
  "data_involved": {
    "classification": "",
    "volume_bytes": 0,
    "file_count": 0,
    "file_types": [],
    "sample_paths": []
  },
  "user_context": {
    "username": "",
    "department": "",
    "authorized_access": false,
    "normal_pattern": false
  },
  "timeline": {
    "first_access": "",
    "last_access": "",
    "duration_hours": 0,
    "transfer_started": "",
    "transfer_ended": ""
  },
  "tools_used": [],
  "protocols_used": []
}
```

## Approval Request Template

```
:rotating_light: *Potential Data Exfiltration Detected*

*Case:* ${case_id}
*Severity:* ${severity}
*User:* ${username}
*Host:* ${hostname}

*Data Exposure Summary:*
- Classification: ${data_classification}
- Volume: ${data_volume}
- Files Accessed: ${file_count}
- Destination: ${destination}

*Activity Timeline:*
${timeline_summary}

*User Context:*
- Role: ${user_role}
- Authorized: ${authorized_status}
- Pattern: ${normal_abnormal}

*Recommended Action:*
${recommended_action}

*Risk if Not Contained:*
${risk_notes}

*This may require legal/privacy team notification*

[Approve Containment] [Deny - Investigate] [Escalate to Legal]
```

## False Positive Handling

### Common False Positives
| Pattern | Likely Benign When |
|---------|-------------------|
| Large cloud uploads | Known backup processes |
| Bulk file access | Authorized data migration |
| High DNS volume | Legitimate cloud services |
| Archive creation | Standard backup procedures |

### Investigation Questions
- Is there a change ticket for this activity?
- Is the user's manager aware?
- Is this a recurring scheduled job?
- Does data destination match approved tools?

## Regulatory Considerations

### If Breach Confirmed
- Document timeline precisely
- Preserve all evidence
- Calculate affected records
- Assess notification requirements:
  - GDPR: 72-hour notification
  - CCPA: "Expedient" notification
  - HIPAA: 60-day notification
  - PCI-DSS: Immediate if cardholder data

## Post-Incident

### Immediate
- Preserve all forensic evidence
- Document data exposure scope
- Engage legal if required
- Begin breach assessment

### Short-term
- Determine root cause
- Identify all compromised data
- Prepare breach notifications if required
- Implement additional controls

### Long-term
- DLP improvements
- User activity monitoring enhancements
- Access control review
- Training updates

## Metrics

| Metric | Target |
|--------|--------|
| Time to detect | < 15 min |
| Time to assess scope | < 1 hour |
| Time to contain | < 2 hours |
| False positive rate | < 15% |

## References

- MITRE ATT&CK: https://attack.mitre.org/tactics/TA0010/
- NIST SP 800-53: Data Loss Prevention Controls
- Data Breach Notification Laws by Jurisdiction
