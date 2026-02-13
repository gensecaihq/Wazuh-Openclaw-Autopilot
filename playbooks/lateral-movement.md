# Playbook: Lateral Movement Response

## Overview

| Field | Value |
|-------|-------|
| Playbook ID | PB-007 |
| Version | 1.0.0 |
| Severity | Critical |
| MITRE ATT&CK | T1021, T1570, T1210, T1072 |
| Wazuh Rules | 5700-5720, 18100-18199, 61100-61199 |

## Description

This playbook handles lateral movement detection in the network.
Common indicators include:
- SSH/RDP connections between internal hosts
- WMI/WinRM remote execution
- PsExec and similar tools
- SMB file transfers
- Pass-the-Hash/Pass-the-Ticket attacks

## Detection Criteria

### Primary Indicators
- Internal-to-internal remote authentication
- Remote command execution tools
- Unusual network connections between hosts
- Service/scheduled task creation on remote hosts
- Remote file copies

### Wazuh Rules Triggered
| Rule ID | Description |
|---------|-------------|
| 5700 | sshd: Accepted publickey |
| 5715 | sshd: Accepted password |
| 18100-18199 | Windows remote execution |
| 61100-61199 | Windows authentication |

### Additional Detection Patterns
- Cobalt Strike/C2 lateral movement
- Mimikatz pass-the-hash
- BloodHound execution
- PSRemoting abuse
- Admin share access (C$, ADMIN$)

## Automated Triage Steps

### 1. Entity Extraction
```yaml
entities:
  - type: host
    source: agent.name
    role: target
  - type: host
    source: data.srchost
    role: source
  - type: ip
    source: data.srcip
    role: source
  - type: user
    source: data.srcuser
  - type: user
    source: data.dstuser
```

### 2. Context Enrichment
- Query source host's recent activity
- Check if connection pattern is normal
- Identify authentication method used
- Map all hosts touched by source user
- Check for indicators of prior compromise

### 3. Severity Assessment
| Condition | Severity Adjustment |
|-----------|-------------------|
| Domain admin account used | +2 |
| Access to critical asset | +2 |
| Multiple hosts accessed | +1 per host |
| Use of known attack tool | +2 |
| Non-business hours | +1 |
| Source host already compromised | +2 |

## Correlation Rules

### Related Alerts to Cluster
- Authentication events on source host
- Process execution on both hosts
- Network connections between hosts
- File transfer indicators
- Credential access on source

### Timeline Construction
```yaml
timeline_query:
  lookback: 24h
  lookahead: 4h
  filters:
    - srcuser: ${actor_user}
    - rule.groups: authentication OR sshd OR windows_security
```

### Blast Radius Mapping
```yaml
blast_radius:
  # Map all hosts accessed by the user
  hosts_accessed:
    query: "srcuser:${actor_user} AND rule.groups:authentication"
    extract: agent.name

  # Check for credential access on compromised hosts
  credential_indicators:
    query: "agent.name:${source_host} AND (lsass OR mimikatz OR secretsdump)"

  # Network connections from source
  network_map:
    query: "agent.name:${source_host} AND rule.groups:network_connection"
```

## Response Plan

### Immediate Containment (Approval Required)

#### Option A: Isolate Source Host (Recommended)
```yaml
action: isolate_host
target: ${source_host_agent_id}
risk: high
justification: "Contain compromised host to prevent further lateral movement"
verification:
  check: network_isolated
  timeout: 120s
```

#### Option B: Isolate All Affected Hosts
```yaml
action: isolate_host
target: ${all_affected_agent_ids}
risk: critical
justification: "Full containment of attack path"
requires_approval: dual  # Requires two approvers
```

#### Option C: Block User Account
```yaml
action: disable_user
target: ${actor_user}
risk: high
justification: "Disable compromised user account across domain"
```

#### Option D: Block Source IP
```yaml
action: block_ip
target: ${source_ip}
duration: 86400
risk: medium
justification: "Block lateral movement source"
```

### Investigation Steps

1. **Attack Path Mapping**
   - Identify initial compromised host
   - Map all accessed systems
   - Determine lateral movement technique

2. **Credential Analysis**
   - Check for credential dumping on source
   - Identify stolen credentials
   - Map credential scope (local vs domain)

3. **Persistence Check**
   - Check all touched hosts for persistence
   - Review scheduled tasks/services
   - Check for backdoor accounts

4. **Data Access Review**
   - Identify accessed data
   - Check for staging/exfiltration
   - Review sensitive file access

## Recovery Actions

### After Containment
1. Reset compromised credentials (including service accounts)
2. Revoke Kerberos tickets if Pass-the-Ticket
3. Remove attacker persistence on all hosts
4. Restore from clean baseline if needed
5. Implement additional segmentation

### Post-Incident
- Review network segmentation
- Implement privileged access workstations
- Enable additional logging
- Consider EDR deployment

## Kill Chain Position

```
Initial Access → Execution → Persistence → Privilege Escalation → [LATERAL MOVEMENT] → Collection → Exfiltration
```

This playbook focuses on detecting and containing the lateral movement phase. Related playbooks:
- PB-006 (Privilege Escalation) - often precedes lateral movement
- PB-004 (Data Exfil) - often follows lateral movement

## Evidence Collection

```yaml
evidence_pack:
  authentication_logs:
    source: "wazuh-archives"
    query: "srcuser:${actor_user} AND rule.groups:authentication"
    retention: 90d

  network_logs:
    source: "wazuh-archives"
    query: "agent.name:(${source_host} OR ${target_host})"
    retention: 90d

  process_logs:
    source: "wazuh-archives"
    query: "agent.name:(${source_host} OR ${target_host}) AND rule.groups:sysmon"
    retention: 90d

  file_transfers:
    source: "wazuh-archives"
    query: "(smb OR scp OR pscp OR copy) AND srcuser:${actor_user}"
    retention: 90d
```

## Metrics

| Metric | Target |
|--------|--------|
| Detection to containment | < 10 minutes |
| Blast radius mapping | < 30 minutes |
| Full path identification | < 2 hours |
| Credential reset completion | < 4 hours |

## Related MITRE Techniques

| Technique ID | Name |
|--------------|------|
| T1021.001 | Remote Desktop Protocol |
| T1021.002 | SMB/Windows Admin Shares |
| T1021.004 | SSH |
| T1021.006 | Windows Remote Management |
| T1570 | Lateral Tool Transfer |
| T1210 | Exploitation of Remote Services |
| T1550.002 | Pass the Hash |
| T1550.003 | Pass the Ticket |
