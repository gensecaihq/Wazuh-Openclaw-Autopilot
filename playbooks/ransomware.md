# Playbook: Ransomware Detection and Response

## Overview

| Field | Value |
|-------|-------|
| Playbook ID | PB-002 |
| Version | 1.0.0 |
| Severity | Critical |
| MITRE ATT&CK | T1486 - Data Encrypted for Impact |
| Priority | IMMEDIATE |

## Description

This playbook handles potential ransomware activity. Ransomware incidents
require immediate response to limit encryption spread and preserve evidence.

**Time is critical** - ransomware can encrypt thousands of files per minute.

## Detection Criteria

### Primary Indicators
- Mass file modifications in short time window
- Suspicious file extensions appearing (.encrypted, .locked, etc.)
- Ransom note file creation (README.txt, DECRYPT.txt, etc.)
- Shadow copy deletion
- Encryption-related process activity

### Wazuh Rules and Indicators
| Indicator | Detection Method |
|-----------|------------------|
| Mass file changes | FIM alerts: 100+ changes/minute |
| Suspicious extensions | FIM: *.encrypted, *.locked, *.crypto |
| Ransom notes | FIM: README*.txt, DECRYPT*.txt, HOW_TO_RECOVER* |
| Shadow deletion | Process: vssadmin delete shadows |
| BCDEdit changes | Process: bcdedit /set {default} recoveryenabled no |

### High-Confidence Patterns
```yaml
high_confidence:
  - shadow_copy_deletion AND file_encryption_activity
  - ransom_note_created AND mass_file_modification
  - known_ransomware_process_name
  - encryption_key_exfiltration_pattern
```

## Automated Triage Steps

### 1. Entity Extraction
```yaml
entities:
  - type: host
    source: agent.name
    priority: critical
  - type: user
    source: data.user
  - type: process
    source: data.process.name
  - type: hash
    source: data.process.hash
  - type: file_paths
    source: data.path
```

### 2. Immediate Assessment
- Identify affected host(s)
- Determine encryption spread rate
- Identify ransomware family if possible
- Check for lateral movement indicators

### 3. Severity Assessment
| Condition | Severity |
|-----------|----------|
| Any ransomware indicator | Critical |
| Production system affected | Critical + Escalate |
| Multiple hosts affected | Critical + Major Incident |
| Domain controller affected | Critical + Emergency |

## Correlation Rules

### Related Alerts to Cluster
- File integrity monitoring alerts
- Process creation alerts
- Network connection alerts
- Privilege escalation attempts
- Lateral movement indicators

### Timeline Construction
```yaml
timeline_query:
  lookback: 24h
  lookahead: 0  # Do not wait
  filters:
    - agent.id: ${agent_id}
    - rule.groups: sysmon OR fim OR rootcheck
  priority_events:
    - shadow_copy_deletion
    - suspicious_process_creation
    - network_share_access
```

## Response Plan

### IMMEDIATE CONTAINMENT (Approval Required - Expedited)

**Default recommendation: ISOLATE AFFECTED HOSTS**

```yaml
action: isolate_host
target: ${agent_id}
risk: medium
priority: immediate
justification: "Prevent ransomware spread - time critical"
approval_timeout: 5m  # Expedited approval window
```

#### Escalation if No Response
If no approval within 5 minutes and confidence > 90%:
- Escalate to on-call security lead
- Page incident commander
- Consider pre-authorized isolation (if policy allows)

### Secondary Actions

#### Block C2 Communication
```yaml
action: block_ip
target: ${suspicious_ips}
risk: low
justification: "Block potential C2 communication"
```

#### Preserve Evidence (Read-Only)
- Capture running processes
- Record network connections
- Document encrypted file samples
- Preserve memory dump request

## Evidence Collection

### Critical Evidence (Time-Sensitive)
| Source | Priority | Query |
|--------|----------|-------|
| FIM alerts | Critical | `rule.groups:fim AND agent.id:${id}` |
| Process events | Critical | `rule.groups:sysmon AND data.process.parent.name:*` |
| Network connections | High | `data.srcip:${host_ip} AND rule.groups:firewall` |
| User activity | High | `data.user:* AND agent.id:${id}` |

### Evidence Pack Fields
```json
{
  "attack_type": "ransomware",
  "ransomware_family": "unknown",
  "affected_hosts": [],
  "encrypted_file_count": 0,
  "encryption_rate_per_minute": 0,
  "ransom_note_content": "",
  "c2_indicators": [],
  "initial_infection_vector": "",
  "lateral_movement_detected": false,
  "backup_status": "unknown"
}
```

## Approval Request Template

```
:skull: *CRITICAL: Ransomware Activity Detected*

:warning: *IMMEDIATE ACTION REQUIRED* :warning:

*Case:* ${case_id}
*Affected Host:* ${hostname} (${agent_id})
*Detection Time:* ${detection_time}

*Indicators:*
${indicator_list}

*Encryption Status:*
- Files affected: ${file_count}
- Encryption rate: ${rate}/min
- Spread detected: ${spread_status}

*RECOMMENDED: Isolate host immediately*

Risk of isolation: Service disruption
Risk of NOT isolating: Continued encryption, potential spread

*This request will expire in 5 minutes*

[ISOLATE NOW] [Deny - Investigate First]
```

## Incident Escalation

### Automatic Escalation Triggers
- Multiple hosts affected
- Domain controller involved
- Backup systems compromised
- C2 communication confirmed
- Lateral movement detected

### Escalation Path
1. Security Analyst (immediate)
2. Security Lead (5 min no response)
3. Incident Commander (10 min)
4. CISO (production/critical systems)

## Post-Containment

### Immediate (0-1 hour)
- Verify isolation effectiveness
- Identify all affected systems
- Preserve volatile evidence
- Document timeline

### Short-term (1-24 hours)
- Determine infection vector
- Identify ransomware family
- Assess backup viability
- Plan recovery strategy

### Recovery Phase
- Rebuild affected systems
- Restore from clean backups
- Implement detection improvements
- Document lessons learned

## Do NOT Do

- Do NOT pay ransom without executive approval
- Do NOT attempt decryption without proper analysis
- Do NOT restore from potentially infected backups
- Do NOT bring systems back online before full scope known
- Do NOT communicate externally without approval

## Metrics

| Metric | Target |
|--------|--------|
| Time to detect | < 5 min |
| Time to isolate | < 15 min |
| Time to scope | < 1 hour |
| Evidence preservation | 100% |

## References

- CISA Ransomware Guide
- MITRE ATT&CK: https://attack.mitre.org/techniques/T1486/
- No More Ransom Project: https://www.nomoreransom.org/
