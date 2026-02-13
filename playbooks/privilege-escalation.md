# Playbook: Privilege Escalation Response

## Overview

| Field | Value |
|-------|-------|
| Playbook ID | PB-006 |
| Version | 1.0.0 |
| Severity | Critical |
| MITRE ATT&CK | T1068, T1548, T1134, T1078 |
| Wazuh Rules | 5401, 5402, 5501, 5502, 5503, 80790, 80791 |

## Description

This playbook handles privilege escalation attempts detected by Wazuh.
Common indicators include:
- Unauthorized sudo/su usage
- Exploitation of SUID/SGID binaries
- Token manipulation
- UAC bypass attempts
- Kernel exploit indicators

## Detection Criteria

### Primary Indicators
- Sudo/su commands by non-privileged users
- Execution of known privilege escalation tools
- SUID binary abuse patterns
- Windows UAC bypass techniques
- Unusual privilege token assignments

### Wazuh Rules Triggered
| Rule ID | Description |
|---------|-------------|
| 5401 | PAM: User login failed |
| 5402 | PAM: Possible break-in attempt |
| 5501 | PAM: Login session opened |
| 5502 | Login session closed |
| 5503 | User privilege elevation |
| 80790 | Sudo command executed |
| 80791 | Su command executed |

### Additional Detection Patterns
- GTFOBins exploitation
- CVE-specific exploit signatures
- Unusual process lineage (e.g., web server spawning shells)
- /etc/shadow or /etc/passwd access
- Registry key modifications (Windows)

## Automated Triage Steps

### 1. Entity Extraction
```yaml
entities:
  - type: user
    source: data.srcuser
    role: actor
  - type: user
    source: data.dstuser
    role: target
  - type: host
    source: agent.name
  - type: process
    source: data.command
```

### 2. Context Enrichment
- Query user's normal behavior (24h baseline)
- Check if user has legitimate sudo access
- Identify parent process chain
- Check for associated file modifications
- Query for related reconnaissance activity

### 3. Severity Assessment
| Condition | Severity Adjustment |
|-----------|-------------------|
| Targeting root/SYSTEM | +2 |
| Success indicator | +2 |
| Known exploit tool | +1 |
| Production system | +1 |
| Non-working hours | +1 |
| User has no sudo rights | +1 |

## Correlation Rules

### Related Alerts to Cluster
- Reconnaissance commands before escalation
- File integrity monitoring alerts
- Command execution via web shells
- Anomalous process execution
- Service account abuse

### Timeline Construction
```yaml
timeline_query:
  lookback: 6h
  lookahead: 2h
  filters:
    - srcuser: ${actor_user}
    - agent.id: ${agent_id}
    - rule.groups: authentication OR sysmon OR audit
```

### Blast Radius Assessment
```yaml
blast_radius:
  same_user_sessions:
    query: "srcuser:${actor_user} AND timestamp:[now-24h TO now]"
  lateral_movement_indicators:
    query: "agent.id:${agent_id} AND rule.groups:network_connection"
  data_access:
    query: "srcuser:${actor_user} AND (data.type:read OR data.type:write)"
```

## Response Plan

### Immediate Containment (Approval Required)

#### Option A: Disable Compromised Account
```yaml
action: disable_user
target: ${actor_user}
risk: high
justification: "Disable account pending investigation"
verification:
  check: user_disabled
  timeout: 60s
```

#### Option B: Isolate Affected Host
```yaml
action: isolate_host
target: ${agent_id}
risk: high
justification: "Prevent further privilege abuse and lateral movement"
verification:
  check: network_isolated
  timeout: 120s
```

#### Option C: Kill Malicious Process
```yaml
action: kill_process
target: ${process_id}
agent: ${agent_id}
risk: medium
justification: "Terminate privilege escalation tool"
```

### Investigation Steps

1. **Audit Process Tree**
   - Identify initial access vector
   - Map process parent chain
   - Check for persistence mechanisms

2. **File Analysis**
   - Check for dropped tools/payloads
   - Review recent file modifications
   - Analyze SUID changes

3. **Credential Assessment**
   - Check for credential dumping indicators
   - Review authentication logs
   - Identify accessed secrets

## Recovery Actions

### After Containment
1. Reset affected user credentials
2. Review and revoke elevated permissions
3. Patch exploited vulnerability
4. Remove persistence mechanisms
5. Restore from clean baseline if needed

### Post-Incident
- Update detection rules
- Review sudo/privilege policies
- Implement additional monitoring

## Evidence Collection

```yaml
evidence_pack:
  process_logs:
    source: "wazuh-archives"
    query: "agent.id:${agent_id} AND rule.groups:sysmon"
  file_integrity:
    source: "syscheck"
    query: "agent.id:${agent_id}"
  auth_logs:
    source: "wazuh-archives"
    query: "agent.id:${agent_id} AND rule.groups:authentication"
```

## Metrics

| Metric | Target |
|--------|--------|
| Detection to containment | < 15 minutes |
| False positive rate | < 5% |
| Escalation to SOC | Critical severity only |
