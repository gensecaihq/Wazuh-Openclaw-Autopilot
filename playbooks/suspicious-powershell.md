# Playbook: Suspicious PowerShell Activity

## Overview

| Field | Value |
|-------|-------|
| Playbook ID | PB-003 |
| Version | 1.0.0 |
| Severity | Medium-High |
| MITRE ATT&CK | T1059.001 - PowerShell |
| Wazuh Rules | 91816, 91817, 91818, 92000-92999 (Sysmon) |

## Description

This playbook handles suspicious PowerShell execution patterns commonly
used in attacks. PowerShell is a legitimate tool often abused for:
- Fileless malware execution
- Obfuscated payload delivery
- Lateral movement
- Data exfiltration
- Persistence establishment

## Detection Criteria

### Primary Indicators

#### Obfuscation Patterns
- Base64 encoded commands (`-EncodedCommand`, `-enc`)
- Character replacement/concatenation
- Invoke-Expression with string manipulation
- Compressed/deflated payloads

#### Suspicious Parameters
- `-ExecutionPolicy Bypass`
- `-NoProfile -NonInteractive`
- `-WindowStyle Hidden`
- `-Command` with long encoded strings

#### Network Activity
- `Invoke-WebRequest`, `wget`, `curl` to unknown domains
- `Net.WebClient` download operations
- Direct socket connections

#### Credential Access
- `Get-Credential` in scripts
- Mimikatz-related patterns
- LSASS memory access attempts

### Wazuh/Sysmon Detection
| Rule/Event | Description |
|------------|-------------|
| Sysmon Event 1 | PowerShell process creation |
| Sysmon Event 3 | Network connections from PowerShell |
| Sysmon Event 7 | Image loaded (Suspicious DLLs) |
| Rule 91816 | PowerShell execution policy bypass |
| Rule 91817 | Encoded PowerShell command |
| Rule 91818 | PowerShell download cradle |

### High-Confidence Patterns
```yaml
high_confidence:
  - encoded_command AND (download_cradle OR invoke_expression)
  - execution_policy_bypass AND hidden_window AND network_connection
  - powershell_spawned_by_office
  - powershell_spawned_by_wscript
  - amsi_bypass_pattern
```

## Automated Triage Steps

### 1. Entity Extraction
```yaml
entities:
  - type: host
    source: agent.name
  - type: user
    source: data.user
  - type: process
    source: data.process.name
  - type: parent_process
    source: data.process.parent.name
  - type: command_line
    source: data.process.command_line
  - type: hash
    source: data.process.hash
  - type: ip
    source: data.dst_ip
  - type: domain
    source: data.dns.query
```

### 2. Command Line Analysis
- Decode Base64 commands
- Identify obfuscation techniques
- Extract embedded URLs/IPs
- Identify known malicious patterns

### 3. Context Assessment
| Factor | Check |
|--------|-------|
| Parent process | Is it suspicious (Word, Excel, wscript)? |
| User context | Privileged account? Service account? |
| Time of execution | Business hours? Unusual time? |
| Previous activity | Has this host had incidents? |

### 4. Severity Assessment
| Condition | Severity |
|-----------|----------|
| Encoded + Download | High |
| Spawned by Office | High |
| Credential access | Critical |
| Lateral movement commands | Critical |
| Simple encoded without network | Medium |
| Execution bypass only | Medium |

## Correlation Rules

### Related Alerts to Cluster
- Process creation events (child processes)
- Network connections from PowerShell
- File creation in temp/suspicious locations
- Registry modifications
- Scheduled task creation
- WMI activity

### Timeline Construction
```yaml
timeline_query:
  lookback: 2h
  lookahead: 30m
  filters:
    - agent.id: ${agent_id}
    - data.process.parent.name: powershell.exe OR pwsh.exe
    - rule.groups: sysmon
  include:
    - child_processes
    - network_connections
    - file_operations
```

## Response Plan

### Investigation (Read-Only)

1. **Decode and analyze command**
   ```yaml
   action: decode_command
   input: ${encoded_command}
   extract:
     - urls
     - ip_addresses
     - file_paths
     - credentials_access
   ```

2. **Check process tree**
   - Parent process chain
   - Child processes spawned
   - Network connections made

3. **Threat intelligence lookup**
   - Hash reputation
   - URL/IP reputation
   - Known malware patterns

### Containment (Approval Required)

#### Option A: Kill Process (If Still Running)
```yaml
action: kill_process
target:
  agent_id: ${agent_id}
  process_id: ${pid}
risk: medium
justification: "Terminate malicious PowerShell"
conditions:
  - process_still_running: true
  - confidence: > 0.8
```

#### Option B: Isolate Host (If Compromise Confirmed)
```yaml
action: isolate_host
target: ${agent_id}
risk: medium
justification: "Contain potential compromise"
conditions:
  - lateral_movement_detected: true
  - credential_access_detected: true
```

#### Option C: Block Destination
```yaml
action: block_ip
target: ${c2_ip}
risk: low
justification: "Block C2 communication"
conditions:
  - external_connection_detected: true
```

## Evidence Collection

### Required Evidence
| Source | Query |
|--------|-------|
| PowerShell events | `data.process.name:powershell.exe AND agent.id:${id}` |
| Child processes | `data.process.parent.name:powershell.exe AND agent.id:${id}` |
| Network events | `data.srcip:${host_ip} AND data.process.name:powershell.exe` |
| File writes | `rule.groups:fim AND agent.id:${id}` |

### Evidence Pack Fields
```json
{
  "attack_type": "suspicious_powershell",
  "command_line": "",
  "decoded_command": "",
  "obfuscation_type": "",
  "parent_process": "",
  "parent_chain": [],
  "child_processes": [],
  "network_connections": [],
  "downloaded_files": [],
  "extracted_iocs": {
    "urls": [],
    "ips": [],
    "domains": [],
    "hashes": []
  },
  "mitre_techniques": []
}
```

## Approval Request Template

```
:warning: *Suspicious PowerShell Detected*

*Case:* ${case_id}
*Host:* ${hostname}
*User:* ${username}
*Severity:* ${severity}

*Detection:*
- Parent Process: ${parent_process}
- Suspicious Indicators: ${indicator_list}

*Command Summary:*
\`\`\`
${decoded_command_preview}
\`\`\`

*Network Activity:*
${network_summary}

*Recommended Action:*
${recommended_action}

*Risk Assessment:*
${risk_notes}

[Approve] [Deny] [Investigate More]
```

## False Positive Handling

### Common False Positives
| Pattern | Likely Benign When |
|---------|-------------------|
| Encoded commands | Part of known management scripts |
| Execution bypass | Corporate deployment tools |
| Download cradles | Software installation scripts |
| Hidden window | Scheduled maintenance tasks |

### Whitelist Criteria
```yaml
whitelist_candidates:
  - script_path_matches: "C:\\Admin\\Scripts\\*"
  - signed_by: "Corporate IT"
  - parent_process: "SCCM Agent"
  - user_context: "SYSTEM" AND script_hash_known
```

## Post-Incident

### If Malicious Confirmed
- Capture full process memory (if possible)
- Collect downloaded payloads
- Block extracted IOCs
- Hunt for same pattern across environment
- Update detection rules

### If False Positive
- Document exception criteria
- Update whitelist if appropriate
- Tune detection rules

## Metrics

| Metric | Target |
|--------|--------|
| Time to detect | < 5 min |
| Time to triage | < 15 min |
| False positive rate | < 20% |
| Command decode success | > 95% |

## References

- MITRE ATT&CK: https://attack.mitre.org/techniques/T1059/001/
- PowerShell Logging Guide
- AMSI Bypass Detection
