# Playbook: Brute Force Attack Response

## Overview

| Field | Value |
|-------|-------|
| Playbook ID | PB-001 |
| Version | 1.0.0 |
| Severity | High |
| MITRE ATT&CK | T1110 - Brute Force |
| Wazuh Rules | 5710, 5711, 5712, 5720, 5763, 5764 |

## Description

This playbook handles brute force authentication attacks detected by Wazuh.
Common indicators include:
- Multiple failed authentication attempts from single source
- Distributed brute force from multiple sources
- Password spraying attempts
- Credential stuffing attacks

## Detection Criteria

### Primary Indicators
- 5+ failed login attempts within 2 minutes from same source IP
- Failed logins against multiple accounts from same source
- Authentication failures with common password patterns

### Wazuh Rules Triggered
| Rule ID | Description |
|---------|-------------|
| 5710 | sshd: Attempt to login using a non-existent user |
| 5711 | sshd: Authentication failure |
| 5712 | sshd: Excessive authentication failures |
| 5720 | PAM: Multiple failed logins |
| 5763 | sshd: Brute force attack |
| 5764 | sshd: Possible attack in progress |

## Automated Triage Steps

### 1. Entity Extraction
```yaml
entities:
  - type: ip
    source: data.srcip
  - type: user
    source: data.dstuser
  - type: host
    source: agent.name
```

### 2. Context Enrichment
- Query previous alerts from source IP (24h lookback)
- Check if source IP has successful logins
- Identify all targeted user accounts
- Determine if targeted accounts exist

### 3. Severity Assessment
| Condition | Severity Adjustment |
|-----------|-------------------|
| Targeting privileged accounts | +1 |
| Source IP has previous incidents | +1 |
| Attack successful (any login) | +2 |
| Internal source IP | +1 |
| External source IP | 0 |

## Correlation Rules

### Related Alerts to Cluster
- Authentication failures from same source
- Successful logins following failures
- Account lockouts
- SSH connection alerts
- Firewall blocks from same source

### Timeline Construction
```yaml
timeline_query:
  lookback: 4h
  lookahead: 1h
  filters:
    - srcip: ${source_ip}
    - rule.groups: authentication_failed OR syslog OR sshd
```

## Response Plan

### Containment (Approval Required)

#### Option A: Block Source IP
```yaml
action: block_ip
target: ${source_ip}
duration: 86400  # 24 hours
risk: low
justification: "Block attacking IP to stop brute force"
```

#### Option B: Isolate Target Host (High Risk)
```yaml
action: isolate_host
target: ${agent_id}
risk: medium
justification: "Isolate if compromise suspected"
conditions:
  - successful_login_detected: true
```

### Investigation Steps (Read-Only)

1. **Verify attack scope**
   - Count unique targeted accounts
   - Check for successful authentications
   - Identify attack pattern (distributed, credential stuffing)

2. **Check for lateral movement**
   - Query events from successfully authenticated sessions
   - Look for privilege escalation attempts
   - Check for data access patterns

3. **Historical analysis**
   - Has this IP attacked before?
   - Is this part of a larger campaign?
   - Any related indicators in threat intel?

## Evidence Collection

### Required Evidence
| Source | Query |
|--------|-------|
| Auth failures | `rule.id:(5710 OR 5711 OR 5712) AND data.srcip:${ip}` |
| Auth successes | `rule.groups:authentication_success AND data.srcip:${ip}` |
| Network events | `data.srcip:${ip} AND rule.groups:firewall` |

### Evidence Pack Fields
```json
{
  "attack_type": "brute_force",
  "source_ips": [],
  "targeted_users": [],
  "targeted_hosts": [],
  "total_attempts": 0,
  "successful_logins": 0,
  "attack_duration_minutes": 0,
  "attack_pattern": "single_source|distributed|credential_stuffing"
}
```

## Approval Request Template

```
:rotating_light: *Brute Force Attack Detected*

*Case:* ${case_id}
*Severity:* ${severity}
*Confidence:* ${confidence}%

*Attack Summary:*
- Source IP: ${source_ip}
- Target Host: ${target_host}
- Targeted Users: ${user_count}
- Failed Attempts: ${attempt_count}
- Successful Logins: ${success_count}

*Recommended Action:*
${recommended_action}

*Risk Assessment:*
${risk_notes}

*Evidence:*
- Alert IDs: ${alert_ids}
- Timeline: ${timeline_link}

[Approve] [Deny] [Investigate More]
```

## Post-Incident

### If Contained
- Monitor for attack resume from different source
- Review blocked IP after 24h
- Update firewall rules if persistent threat

### If Compromised
- Force password reset for affected accounts
- Review all activity from compromised sessions
- Check for persistence mechanisms
- Escalate to incident response team

## Metrics

| Metric | Target |
|--------|--------|
| Time to detect | < 5 min |
| Time to triage | < 15 min |
| Time to contain | < 30 min |
| False positive rate | < 10% |

## References

- MITRE ATT&CK: https://attack.mitre.org/techniques/T1110/
- NIST SP 800-61: Computer Security Incident Handling Guide
- Wazuh Ruleset Documentation
