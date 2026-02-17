# Playbook: Lateral Movement Detection and Response

## Document Control

| Field | Value |
|-------|-------|
| Playbook ID | PB-007 |
| Version | 2.0.0 |
| Classification | TLP:AMBER |
| Distribution | Authorized SOC Personnel Only |
| Last Updated | 2026-02-17 |
| Review Cycle | Quarterly |
| Owner | Security Operations Center |
| Severity | Critical |
| Automation Level | High (Correlation Required) |

## Executive Summary

Lateral movement represents one of the most critical phases in advanced persistent threats and targeted attacks. This playbook provides comprehensive detection, correlation, investigation, and response procedures for identifying and containing adversary movement across enterprise networks. Success requires sophisticated multi-source correlation and rapid blast radius mapping.

**Key Challenge**: Distinguishing malicious lateral movement from legitimate administrative activity requires deep understanding of normal patterns, credential usage, and network topology.

## MITRE ATT&CK Framework Mapping

### Primary Techniques

| Technique ID | Name | Sub-Techniques Covered |
|--------------|------|----------------------|
| **T1021** | **Remote Services** | .001 RDP, .002 SMB/Admin Shares, .003 DCOM, .004 SSH, .005 VNC, .006 WinRM |
| **T1570** | **Lateral Tool Transfer** | File copies via admin shares, remote staging |
| **T1210** | **Exploitation of Remote Services** | EternalBlue, MS17-010, remote code execution |
| **T1072** | **Software Deployment Tools** | SCCM, PDQ Deploy, Group Policy abuse |
| **T1550** | **Use Alternate Authentication Material** | .002 Pass the Hash, .003 Pass the Ticket, .004 Web Session Cookie |
| **T1563** | **Remote Service Session Hijacking** | RDP hijacking, session injection |

### Technique Details

#### T1021.001 - Remote Desktop Protocol
- **Detection**: Windows Event 4624 (Type 10 logon), TerminalServices-LocalSessionManager events
- **Indicators**: Multiple failed RDP attempts followed by success, unusual source IPs, non-standard RDP ports
- **Tools**: mstsc.exe, RDP wrappers, xfreerdp, rdesktop

#### T1021.002 - SMB/Windows Admin Shares
- **Detection**: Windows Event 5140/5145 (share access), Sysmon EID 3 (SMB connections to port 445)
- **Indicators**: ADMIN$, C$, IPC$ access from unusual sources, lateral file transfers
- **Tools**: net use, PsExec, Impacket psexec.py, CrackMapExec

#### T1021.003 - Distributed Component Object Model (DCOM)
- **Detection**: Sysmon EID 1 (unusual DCOM process spawns), network connections from svchost.exe
- **Indicators**: MMC20.Application, ShellWindows, Excel.Application DCOM object abuse
- **Tools**: PowerShell Invoke-DCOM, Empire lateral_dcom module

#### T1021.004 - SSH
- **Detection**: Wazuh rules 5700-5720 (sshd authentication events)
- **Indicators**: Internal SSH connections between Windows/Linux hosts, key-based auth from unusual sources
- **Tools**: ssh, plink, OpenSSH, Paramiko-based tools

#### T1021.005 - VNC
- **Detection**: Network connections to ports 5900-5906, unusual process connections
- **Indicators**: VNC server installation on workstations, remote VNC connections
- **Tools**: TightVNC, RealVNC, UltraVNC

#### T1021.006 - Windows Remote Management (WinRM)
- **Detection**: Windows Event 4624 (Type 3 logon via WinRM), Sysmon EID 3 (port 5985/5986)
- **Indicators**: PowerShell Remoting from unusual sources, WinRM service enabled on workstations
- **Tools**: Enter-PSSession, Invoke-Command, evil-winrm

#### T1550.002 - Pass the Hash
- **Detection**: NTLM authentication without prior Kerberos, Event 4624 with blank LogonType or unusual characteristics
- **Indicators**: Mimikatz sekurlsa::pth usage, NTLM hash usage in authentication
- **Tools**: Mimikatz, Impacket, CrackMapExec, Metasploit

#### T1550.003 - Pass the Ticket
- **Detection**: Unusual Kerberos ticket requests (Event 4768/4769), golden/silver ticket indicators
- **Indicators**: Ticket injection, TGT/TGS manipulation, encryption downgrade
- **Tools**: Mimikatz kerberos::ptt, Rubeus, Kekeo

## Detection Criteria

### Comprehensive Wazuh Rule Coverage

#### SSH-Based Lateral Movement (5700-5720)
| Rule ID | Description | Severity |
|---------|-------------|----------|
| 5700 | sshd: Accepted publickey authentication | Low (baseline) |
| 5710 | sshd: Attempt to login using a denied user | Medium |
| 5715 | sshd: Accepted password authentication | Low (baseline) |
| 5716 | sshd: Authentication failed | Low |
| 5720 | sshd: Multiple authentication failures | High |

**Correlation Logic**: Multiple 5700/5715 events from single source to multiple targets within 10 minutes = lateral movement pattern.

#### Windows Remote Execution (18100-18199)
| Rule ID | Description | Severity |
|---------|-------------|----------|
| 18100 | Windows: Remote command execution detected | High |
| 18145 | Windows: PsExec service installation | High |
| 18150 | Windows: WMI remote process creation | Medium |
| 18160 | Windows: PowerShell remoting connection | Medium |
| 18170 | Windows: Remote scheduled task creation | High |

#### Windows Authentication Events (61100-61199)
| Rule ID | Description | Severity |
|---------|-------------|----------|
| 61100 | Windows: Network logon detected (Type 3) | Low (baseline) |
| 61101 | Windows: Interactive logon detected (Type 2) | Low (baseline) |
| 61102 | Windows: Remote interactive logon (Type 10 - RDP) | Medium |
| 61108 | Windows: Explicit credential usage (Event 4648) | Medium |
| 61110 | Windows: Multiple logon failures | High |
| 61120 | Windows: Unusual authentication patterns | High |

### Windows Event Log Correlation

#### Critical Windows Events
| Event ID | Description | Lateral Movement Indicator |
|----------|-------------|---------------------------|
| **4624** | Successful logon | Type 3 (Network), Type 10 (RemoteInteractive) from internal IPs |
| **4648** | Logon with explicit credentials | Indicates credential usage for remote operations |
| **4672** | Special privileges assigned | Admin rights used on remote system |
| **5140** | Network share accessed | ADMIN$, C$, IPC$ access patterns |
| **5145** | Detailed file share access | File operations on remote shares |
| **7045** | New service installed | Remote service creation (PsExec pattern) |
| **1102** | Audit log cleared | Anti-forensics after lateral movement |
| **4776** | NTLM authentication | Pass-the-Hash indicator when without prior Kerberos |
| **4768** | Kerberos TGT requested | Baseline for Pass-the-Ticket detection |
| **4769** | Kerberos Service Ticket requested | Unusual ticket requests, encryption downgrade |

#### Logon Type Classification
| Logon Type | Name | Lateral Movement Context |
|------------|------|-------------------------|
| 2 | Interactive | Direct console access (unusual for lateral) |
| 3 | Network | SMB, WMI, remote file access - **PRIMARY INDICATOR** |
| 4 | Batch | Scheduled task execution |
| 5 | Service | Service account usage |
| 7 | Unlock | Workstation unlock (not lateral) |
| 8 | NetworkCleartext | IIS basic auth (not typical lateral) |
| 9 | NewCredentials | RunAs with explicit creds |
| 10 | RemoteInteractive | RDP/Terminal Services - **PRIMARY INDICATOR** |
| 11 | CachedInteractive | Cached domain creds (offline) |

### Sysmon Event Correlation

#### Key Sysmon Events for Lateral Movement
| Event ID | Description | Detection Use Case |
|----------|-------------|-------------------|
| **1** | Process Creation | PsExec.exe, WmiPrvSE.exe with command-line args, PowerShell remoting |
| **3** | Network Connection | SMB (445), RDP (3389), WinRM (5985/5986) connections between internal hosts |
| **8** | CreateRemoteThread | Process injection for credential access before lateral movement |
| **10** | ProcessAccess | LSASS access for credential dumping |
| **11** | FileCreate | Lateral tool staging in ADMIN$, C$\Windows\Temp |
| **13** | RegistrySetValue | Persistence establishment on remote hosts |
| **17** | PipeCreated | Named pipe creation (PsExec: \pipe\PSEXESVC) |
| **18** | PipeConnected | Named pipe connections indicating remote tool usage |
| **22** | DNSQuery | C2 DNS lookups from newly compromised hosts |

### Custom Detection Rules

#### PsExec Detection Pattern
```yaml
detection:
  sequence:
    - event: Sysmon EID 1
      process: psexec.exe OR psexec64.exe
      command_line: contains("-s" OR "-c" OR "-d")
    - event: Windows Event 7045
      service_name: PSEXESVC
      within: 30s
    - event: Sysmon EID 17
      pipe_name: \PSEXESVC
      within: 60s
  severity: high
  mitre: T1021.002, T1570
```

#### WMI Lateral Movement Pattern
```yaml
detection:
  sequence:
    - event: Sysmon EID 1
      parent_process: wmiprvse.exe
      process: not(wmic.exe OR scrcons.exe)  # Unusual child process
    - event: Sysmon EID 3
      process: wmiprvse.exe
      destination_port: 135 OR 49152-65535
      destination_ip: internal_network
  severity: high
  mitre: T1021.006, T1047
```

#### PowerShell Remoting Detection
```yaml
detection:
  sequence:
    - event: Sysmon EID 3
      source_port: 5985 OR 5986
      destination_ip: internal_network
    - event: Sysmon EID 1
      parent_process: wsmprovhost.exe
      within: 30s
  severity: medium
  mitre: T1021.006, T1059.001
```

#### Pass-the-Hash Detection
```yaml
detection:
  anomaly:
    - event: Windows Event 4624
      logon_type: 3
      authentication_package: NTLM
      conditions:
        - no_prior_kerberos_auth: true  # Within 1 hour
        - source_workstation: not(expected_admin_host)
        - elevated_token: true
  severity: critical
  mitre: T1550.002
```

#### Named Pipe Lateral Movement
```yaml
detection:
  correlation:
    - event: Sysmon EID 17
      pipe_name: matches("(PSEXESVC|PAExec|RemCom|csexec|winexesvc)")
    - event: Sysmon EID 18
      pipe_name: same_as_above
      source: not(pipe_creator)
  severity: high
  mitre: T1021.002
```

## Multi-Stage Decision Tree

### Stage 1: Initial Triage
```
Internal Authentication Detected (Event 4624 Type 3/10)
│
├─→ Source/Destination Analysis
│   ├─→ Both internal IPs? → PROCEED
│   ├─→ External source? → FALSE POSITIVE (handled by boundary playbook)
│   └─→ Known admin host? → CHECK PATTERN
│
└─→ Pattern Recognition
    ├─→ Known admin pattern? (source in admin_workstations, time = business hours)
    │   └─→ BASELINE (log for trending, no alert)
    │
    └─→ Unusual pattern? → PROCEED TO STAGE 2
```

### Stage 2: Source Host Compromise Assessment
```
Unusual Authentication Pattern Confirmed
│
├─→ Source Host Analysis (lookback 24h)
│   ├─→ Prior credential access alerts? (Mimikatz, LSASS dump) → SOURCE COMPROMISED
│   ├─→ Prior malware/C2 alerts? → SOURCE COMPROMISED
│   ├─→ User account abnormal for source host? → SOURCE LIKELY COMPROMISED
│   └─→ No prior indicators → PROCEED TO STAGE 3
│
└─→ Severity Escalation
    └─→ If SOURCE COMPROMISED → Escalate to CRITICAL
```

### Stage 3: Technique Identification
```
Lateral Movement Confirmed
│
├─→ Tool Detection
│   ├─→ Admin Tools (PsExec, WMI, PowerShell Remoting)?
│   │   ├─→ Legitimate admin activity? (authorized user, business hours, documented change)
│   │   │   └─→ MEDIUM severity, monitor
│   │   └─→ Unusual admin tool usage?
│   │       └─→ HIGH severity, investigate
│   │
│   └─→ Exploitation Tools? (MS17-010, EternalBlue, exploit frameworks)
│       └─→ CRITICAL severity, immediate containment
│
└─→ Credential Type Analysis
    ├─→ Password authentication → Standard compromise
    ├─→ Pass-the-Hash (NTLM without Kerberos) → Advanced attacker, credential dumping occurred
    └─→ Pass-the-Ticket (Kerberos anomaly) → Sophisticated attacker, domain compromise risk
```

### Stage 4: Blast Radius Assessment
```
Technique Identified
│
├─→ Single Hop Analysis
│   └─→ One source → One target?
│       ├─→ Target critical asset? → HIGH/CRITICAL severity
│       └─→ Target standard workstation? → MEDIUM severity
│
└─→ Multi-Hop Chain Detection
    ├─→ Source accessed multiple targets? (query: same source, multiple destinations, time window 4h)
    │   └─→ 2-5 hosts → HIGH severity, orchestrated campaign
    │   └─→ 6+ hosts → CRITICAL severity, active breach
    │
    ├─→ Pivoting detected? (Target becomes new source)
    │   └─→ Host A → Host B → Host C chain?
    │       └─→ CRITICAL severity, advanced persistent threat
    │
    └─→ Blast radius calculation
        ├─→ Query: All hosts accessed by user in 24h
        ├─→ Query: All accounts used from source host
        └─→ Output: Network graph of compromised relationships
```

### Stage 5: Final Severity and Response Classification
```
Blast Radius Mapped
│
├─→ CRITICAL - Immediate Containment Required
│   ├─→ Domain admin account used
│   ├─→ 6+ hosts accessed
│   ├─→ Pivoting/chain detected
│   ├─→ Critical asset accessed (DC, file server, database)
│   └─→ Pass-the-Ticket/Golden Ticket indicators
│
├─→ HIGH - Urgent Investigation and Likely Containment
│   ├─→ Privileged account used
│   ├─→ 2-5 hosts accessed
│   ├─→ Pass-the-Hash detected
│   └─→ Exploitation tools used
│
└─→ MEDIUM - Standard Investigation
    ├─→ Single hop, standard account
    ├─→ Admin tools with partial legitimacy
    └─→ Requires validation of authorization
```

## Forensic Artifacts Collection

### Source Host Forensics

#### Memory Artifacts
| Artifact | Location | Purpose |
|----------|----------|---------|
| **LSASS Memory Dump** | Process memory of lsass.exe | Identify if credentials were dumped (precursor to lateral movement) |
| **Credential Cache** | %SYSTEMROOT%\System32\config\SAM, SECURITY | Cached credentials, password hashes |
| **Kerberos Tickets** | Memory (LSA cache) | Active Kerberos tickets, golden/silver ticket analysis |

#### Disk Artifacts
| Artifact | Location | Purpose |
|----------|----------|---------|
| **PowerShell History** | %APPDATA%\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt | PowerShell remoting commands, Invoke-Command usage |
| **PowerShell Logs** | Event Log: Microsoft-Windows-PowerShell/Operational (EID 4103, 4104) | Script block logging, command execution history |
| **RDP Bitmap Cache** | %LOCALAPPDATA%\Microsoft\Terminal Server Client\Cache | Screenshots of RDP sessions to remote hosts |
| **RDP Connection History** | HKCU\Software\Microsoft\Terminal Server Client\Servers | List of RDP targets |
| **Prefetch** | C:\Windows\Prefetch\PSEXEC*.pf, MSTSC*.pf | Execution of lateral movement tools |
| **NTUSER.DAT** | C:\Users\[username]\NTUSER.DAT | User activity, MRU lists for remote connections |
| **Lateral Tool Staging** | C:\Windows\Temp, C:\Temp, ADMIN$ | Copied attack tools (Mimikatz, PsExec, Impacket scripts) |

#### Event Logs (Source Host)
| Event Log | Event ID | Description |
|-----------|----------|-------------|
| Security | 4648 | Explicit credential usage for remote logon |
| Security | 4624 Type 3 | Outbound authentication to remote host |
| Security | 4672 | Admin privileges used |
| Security | 4776 | NTLM authentication attempt |
| Sysmon | 1 | Process creation (PsExec, WMI, PowerShell) |
| Sysmon | 3 | Network connections (SMB, RDP, WinRM) |
| Sysmon | 10 | LSASS process access (credential dumping) |
| Sysmon | 11 | File creation (tool staging) |

### Target Host Forensics

#### Authentication Evidence
| Artifact | Location | Purpose |
|----------|----------|---------|
| **Security Event Log** | Event 4624 Type 3/10 | Inbound logon from source host |
| **Security Event Log** | Event 4672 | Privilege assignment to remote user |
| **Security Event Log** | Event 4688/Sysmon 1 | Process creation by remote user |

#### Execution Artifacts
| Artifact | Location | Purpose |
|----------|----------|---------|
| **Service Creation** | Event 7045 (System log) | New service installed (PsExec pattern: PSEXESVC) |
| **Scheduled Tasks** | Event 4698 (Security log), C:\Windows\System32\Tasks | Remote scheduled task creation |
| **Prefetch** | C:\Windows\Prefetch | Executed binaries, including remote tools |
| **WMI Event Logs** | Microsoft-Windows-WMI-Activity/Operational | WMI remote execution commands |
| **Named Pipes** | Sysmon EID 17/18 | PsExec (\PSEXESVC), RemCom, PAExec pipes |

#### File System Artifacts
| Artifact | Location | Purpose |
|----------|----------|---------|
| **ADMIN$ Share Access** | Event 5140/5145 | File copies via admin shares |
| **Dropped Files** | C:\Windows\Temp, C:\Temp | Tools dropped during lateral movement |
| **Persistence Mechanisms** | Registry Run keys, Services, Scheduled Tasks | Post-lateral movement persistence |

#### Anti-Forensics Indicators
| Artifact | Location | Purpose |
|----------|----------|---------|
| **Event Log Clearing** | Event 1102 (System log cleared) | Evidence destruction |
| **USN Journal Tampering** | NTFS USN Journal | File system anti-forensics |
| **Timestomping** | File modification times | File timestamp manipulation |

### Network Forensics

#### Network Traffic Patterns
| Protocol | Ports | Indicators |
|----------|-------|-----------|
| **SMB** | 445, 139 | ADMIN$, C$, IPC$ share access; large file transfers |
| **RDP** | 3389 | Multiple internal RDP connections from single source |
| **WinRM** | 5985 (HTTP), 5986 (HTTPS) | PowerShell Remoting traffic |
| **SSH** | 22 | Internal SSH connections between hosts |
| **RPC** | 135, dynamic ports (49152-65535) | WMI, DCOM remote execution |

#### Authentication Protocols
| Protocol | Detection Method | Lateral Movement Context |
|----------|------------------|-------------------------|
| **Kerberos** | Analyze Event 4768/4769 | Pass-the-Ticket, golden ticket, unusual encryption types (RC4 downgrade) |
| **NTLM** | Analyze Event 4776 | Pass-the-Hash (NTLM without prior Kerberos), downgrade attacks |
| **NTLMv1** | Legacy NTLM protocol | Highly suspicious if detected (weak, often attacker-forced downgrade) |

#### Packet Capture Analysis
```yaml
pcap_analysis:
  critical_indicators:
    - smb_admin_share_access: "\\\\[target]\\ADMIN$"
    - psexec_named_pipe: "\\\\[target]\\pipe\\PSEXESVC"
    - ntlm_authentication_without_kerberos: true
    - kerberos_ticket_anomalies: "rc4_hmac encryption with AES-capable systems"
    - large_file_transfers_smb: ">10MB within 60s"
```

## Attack Path Mapping and Visualization

### Kill Chain Visualization

```
┌─────────────────────────────────────────────────────────────────────────┐
│                     LATERAL MOVEMENT KILL CHAIN                          │
└─────────────────────────────────────────────────────────────────────────┘

1. Initial Compromise
   └─→ Host A compromised via phishing/exploit

2. Credential Access (Precursor)
   ├─→ LSASS memory dump (Mimikatz/ProcDump)
   ├─→ SAM/SECURITY registry hive extraction
   └─→ Credentials obtained: User1 (local admin), User2 (domain user)

3. Lateral Movement Execution
   ├─→ Technique Selection
   │   ├─→ Pass-the-Hash (User1 NTLM hash)
   │   ├─→ PsExec (admin shares)
   │   └─→ PowerShell Remoting (WinRM)
   │
   └─→ Movement Pattern
       ├─→ Host A → Host B (via PsExec, User1)
       ├─→ Host B → Host C (via WinRM, User2)
       └─→ Host C → Domain Controller (privilege escalation target)

4. Post-Lateral Actions
   ├─→ Persistence establishment on each host
   ├─→ Additional credential harvesting
   └─→ Data staging for exfiltration

5. Impact Phase
   └─→ Domain Admin compromise, ransomware deployment, data exfiltration
```

### Pivoting Pattern Detection

#### Single-Hop Pattern (Lower Risk)
```
Source Host (Compromised)
    │
    │ [Single lateral connection]
    │
    ▼
Target Host
```

**Query**:
```json
{
  "query": {
    "bool": {
      "must": [
        {"term": {"event.code": "4624"}},
        {"terms": {"data.win.eventdata.logonType": ["3", "10"]}},
        {"term": {"data.win.eventdata.ipAddress": "SOURCE_IP"}}
      ]
    }
  },
  "aggs": {
    "unique_targets": {
      "cardinality": {"field": "agent.name"}
    }
  }
}
```

#### Multi-Hop Chain (High Risk)
```
Initial Compromised Host (A)
    │
    ├─→ Host B (becomes pivot)
    │   │
    │   ├─→ Host D
    │   └─→ Host E
    │
    └─→ Host C (becomes pivot)
        │
        └─→ Host F (Critical Asset)
```

**Detection**: Correlate Event 4624 (inbound logon) on Host B with Event 4648 (outbound explicit cred usage) on Host B within time window.

**Query**:
```json
{
  "query": {
    "bool": {
      "must": [
        {
          "bool": {
            "should": [
              {
                "bool": {
                  "must": [
                    {"term": {"agent.name": "Host_B"}},
                    {"term": {"event.code": "4624"}},
                    {"term": {"data.win.eventdata.sourceNetworkAddress": "Host_A_IP"}}
                  ]
                }
              },
              {
                "bool": {
                  "must": [
                    {"term": {"agent.name": "Host_B"}},
                    {"term": {"event.code": "4648"}},
                    {"term": {"data.win.eventdata.targetServerName": "Host_D OR Host_E"}}
                  ]
                }
              }
            ]
          }
        }
      ]
    }
  }
}
```

#### Spray Pattern (Worm/Automated)
```
Compromised Host
    │
    ├─→ Host 1
    ├─→ Host 2
    ├─→ Host 3
    ├─→ Host 4
    ├─→ Host 5
    ├─→ Host 6
    └─→ ... (rapid propagation)
```

**Detection**: Single source, 10+ unique targets within 10 minutes.

### Network Graph Construction

#### Graph Database Schema
```yaml
nodes:
  - type: host
    properties:
      - hostname
      - ip_address
      - operating_system
      - criticality_tier
      - compromise_status: [clean, suspected, confirmed]
      - first_seen_compromised: timestamp

  - type: user
    properties:
      - username
      - domain
      - privilege_level
      - account_type: [standard, admin, service, domain_admin]

edges:
  - type: authenticated_to
    source: host
    target: host
    properties:
      - timestamp
      - authentication_method: [password, ntlm_hash, kerberos_ticket]
      - logon_type
      - success: boolean
      - tool_used: [psexec, rdp, winrm, ssh]
```

#### Graph Query Example (Cypher-style)
```cypher
// Find all hosts accessed from compromised host within 4 hours
MATCH (source:Host {compromise_status: 'confirmed'})-[auth:AUTHENTICATED_TO]->(target:Host)
WHERE auth.timestamp > compromiseTime AND auth.timestamp < compromiseTime + 4h
RETURN source, auth, target

// Detect pivoting (host is both target and source)
MATCH (pivot:Host)<-[inbound:AUTHENTICATED_TO]-(source:Host)-[outbound:AUTHENTICATED_TO]->(target:Host)
WHERE outbound.timestamp > inbound.timestamp AND (outbound.timestamp - inbound.timestamp) < 1h
RETURN source, pivot, target, "PIVOTING DETECTED" as alert
```

### Automated Path Reconstruction

**Agent Pipeline Integration** (see Agent Pipeline Integration section):
- **Correlation Agent**: Builds network graph, identifies all compromised-to-target relationships
- **Investigation Agent**: Traces full attack path from initial compromise to current state
- **Response Planner**: Generates containment plan for entire graph (all compromised nodes)

## Communication Templates

### Template 1: SOC Internal Alert (High/Critical Severity)

**Subject**: [CRITICAL] Lateral Movement Detected - Immediate Action Required - Incident #${incident_id}

**Body**:
```
CLASSIFICATION: TLP:AMBER
INCIDENT ID: ${incident_id}
SEVERITY: ${severity}
DETECTION TIME: ${detection_timestamp}
ANALYST: ${assigned_analyst}

EXECUTIVE SUMMARY:
Lateral movement activity detected from ${source_host} (${source_ip}) to ${target_count} target host(s) using ${technique}. ${compromise_indicator_summary}.

AFFECTED SYSTEMS:
- Source Host: ${source_host} (${source_ip}) - ${source_os}
- Target Host(s): ${target_hosts_list}
- User Account: ${username} (${account_type})
- Technique: ${mitre_technique} (${technique_name})

ATTACK PATH:
${attack_chain_visualization}

SEVERITY FACTORS:
- Source host compromise indicators: ${source_compromise_evidence}
- Privilege level: ${account_privilege}
- Blast radius: ${affected_host_count} hosts
- Credential type: ${credential_type} (Password/NTLM Hash/Kerberos Ticket)
- Target criticality: ${target_criticality_tier}

IMMEDIATE ACTIONS REQUIRED:
1. Containment Decision: ${containment_recommendation}
   - Isolate source host: ${source_host_agent_id}
   - Isolate target host(s): ${target_host_agent_ids}
   - Disable user account: ${username}

2. Investigation Priority:
   - Timeline: ${investigation_timeline_url}
   - Forensic artifacts: ${artifact_collection_status}
   - Related alerts: ${related_alert_count}

APPROVAL STATUS:
- Containment approval required: ${approval_required}
- Authorized approvers: ${approver_list}
- Approval deadline: ${approval_deadline}

RESPONSE PLAN:
${response_plan_url}

Next Update: ${next_update_time}
Escalation Contact: ${escalation_contact}
```

### Template 2: Network Operations Team Notification

**Subject**: [ACTION REQUIRED] Network Segmentation Review - Lateral Movement Incident #${incident_id}

**Body**:
```
TO: Network Operations Team
FROM: Security Operations Center
RE: Network Segmentation Deficiency - Incident #${incident_id}
PRIORITY: High

SUMMARY:
A confirmed lateral movement incident has exposed insufficient network segmentation between ${source_network_segment} and ${target_network_segment}.

INCIDENT DETAILS:
- Date/Time: ${incident_timestamp}
- Source: ${source_host} (${source_vlan})
- Target(s): ${target_hosts} (${target_vlan})
- Protocol/Ports: ${protocol} (${ports})
- Attack Technique: ${technique_name}

CURRENT NETWORK TOPOLOGY ISSUE:
The attacker was able to move from ${source_segment_description} to ${target_segment_description} without restriction. This violates the principle of least privilege and Zero Trust Architecture.

SEGMENTATION GAP ANALYSIS:
- Current ACL/Firewall Rule: ${current_rule_analysis}
- Expected Behavior: ${expected_segmentation_behavior}
- Gap: ${segmentation_gap_description}

REQUESTED ACTIONS:
1. IMMEDIATE (Within 24h):
   - Review firewall rules between ${source_segment} <-> ${target_segment}
   - Implement temporary ACL to restrict ${protocol}/${port} to authorized admin hosts only
   - Authorized admin hosts: ${authorized_admin_workstation_list}

2. SHORT-TERM (Within 1 week):
   - Conduct comprehensive segmentation review for ${affected_network_zones}
   - Implement micro-segmentation for critical assets: ${critical_asset_list}
   - Deploy network access control (NAC) for endpoint posture validation

3. LONG-TERM (Within 1 month):
   - Zero Trust Architecture pilot for ${pilot_segment}
   - Software-Defined Perimeter (SDP) evaluation
   - Privileged Access Workstation (PAW) deployment

COMPLIANCE IMPACT:
This incident affects compliance with:
- NIST 800-53 SC-7 (Boundary Protection)
- NIST 800-207 (Zero Trust Architecture)
- ${industry_specific_standard} (${specific_requirement})

SOC CONTACT:
${soc_contact_info}

Please confirm receipt and provide ETA for immediate actions within 4 hours.
```

### Template 3: Active Directory Team Notification

**Subject**: [URGENT] Credential Compromise - Mass Password Reset Required - Incident #${incident_id}

**Body**:
```
TO: Active Directory / Identity Management Team
FROM: Security Operations Center
RE: Credential Compromise and Reset Procedure
CLASSIFICATION: TLP:AMBER
PRIORITY: Critical

INCIDENT SUMMARY:
A lateral movement incident has resulted in credential compromise affecting ${affected_account_count} accounts. Immediate credential reset and Kerberos ticket revocation required.

COMPROMISED CREDENTIALS:
1. User Accounts:
   ${compromised_user_accounts_list}

2. Service Accounts:
   ${compromised_service_accounts_list}

3. Administrative Accounts:
   ${compromised_admin_accounts_list}

CREDENTIAL COMPROMISE TYPE:
- ${credential_type}: ${description}
  - Pass-the-Hash: NTLM hashes extracted from LSASS memory
  - Pass-the-Ticket: Kerberos tickets extracted and potentially replayed
  - Plaintext Passwords: Credentials obtained from memory/disk

REQUIRED ACTIONS (In Order):

1. IMMEDIATE - Disable Compromised Accounts (Within 30 minutes):
   ```powershell
   # Disable user accounts
   ${disable_accounts_powershell_commands}
   ```

2. KERBEROS TICKET REVOCATION (Within 1 hour):
   ```powershell
   # Force Kerberos ticket invalidation
   Get-ADUser -Filter {Name -in @(${compromised_accounts})} | Set-ADUser -Replace @{msDS-KeyVersionNumber=(Get-ADUser $_.SamAccountName -Properties msDS-KeyVersionNumber).'msDS-KeyVersionNumber' + 1}
   ```

3. PASSWORD RESETS (Within 4 hours):
   - User accounts: Force password change at next logon
   - Service accounts: Coordinate with application owners for password rotation
   - Admin accounts: Generate high-entropy passwords (20+ characters)

4. DOMAIN CONTROLLER HEALTH CHECK (Within 24 hours):
   - Run DCDiag on all domain controllers
   - Verify replication status: `repadmin /replsummary`
   - Check for unauthorized changes: Review Event 4742 (account modified)

5. GOLDEN TICKET DETECTION (If Pass-the-Ticket detected):
   - Review all Event 4768 (TGT requests) with unusual encryption types (RC4 instead of AES)
   - Check KRBTGT account password age: ${krbtgt_password_age}
   - If >1 year or golden ticket suspected, coordinate KRBTGT password reset (requires planning)

SERVICE IMPACT ASSESSMENT:
The following services may be impacted by credential resets:
${service_impact_list}

Please coordinate with:
- Application Owners: ${app_owner_contacts}
- Service Desk: ${service_desk_contact}
- Change Management: ${change_management_ticket}

POST-RESET VERIFICATION:
1. Confirm all compromised accounts have new credentials
2. Verify Kerberos ticket version incremented
3. Test service account functionality
4. Monitor for authentication failures (Event 4625)

TIMELINE:
- Incident Start: ${incident_start_time}
- Credential Reset Deadline: ${reset_deadline}
- Verification Complete By: ${verification_deadline}

SOC will monitor for:
- Re-use of old credentials (indicates incomplete reset)
- New lateral movement attempts
- Account lockouts (may indicate attacker retry)

Questions or issues: ${soc_contact}
```

### Template 4: Management Briefing (Executive Summary)

**Subject**: [EXECUTIVE BRIEF] Confirmed Security Breach - Lateral Movement Incident #${incident_id}

**Body**:
```
TO: ${executive_distribution_list}
FROM: Chief Information Security Officer
RE: Security Incident Executive Summary
CLASSIFICATION: TLP:AMBER - Executive Leadership Only

INCIDENT CLASSIFICATION: Confirmed Security Breach - Lateral Movement

BUSINESS IMPACT SUMMARY:
- Severity: ${severity} (Critical/High/Medium)
- Affected Systems: ${affected_system_count}
- Affected Business Units: ${affected_business_units}
- Operational Impact: ${operational_impact_summary}
- Data at Risk: ${data_at_risk_classification}

TIMELINE:
- Initial Compromise Estimated: ${initial_compromise_estimate}
- Lateral Movement Detected: ${detection_time}
- Containment Initiated: ${containment_time}
- Incident Contained: ${containment_complete_time}
- Estimated Dwell Time: ${dwell_time}

ATTACK SUMMARY (Non-Technical):
An attacker who had previously compromised ${source_host_description} successfully moved to ${target_host_count} additional systems within our network using ${technique_description}. This is consistent with advanced persistent threat (APT) behavior.

ATTACKER CAPABILITY ASSESSMENT:
- Sophistication Level: ${sophistication_assessment}
- Tools Used: ${tools_summary}
- Potential Attribution: ${attribution_assessment_if_available}

CONTAINMENT STATUS:
✓ ${contained_hosts} hosts isolated from network
✓ ${disabled_accounts} compromised accounts disabled
✓ ${credential_resets} credentials reset
○ ${pending_actions} pending actions (ETA: ${eta})

DATA EXPOSURE ASSESSMENT:
${data_exposure_summary}
- Confirmed Data Access: ${confirmed_data_access}
- Potential Data Exfiltration: ${exfiltration_indicators}

REGULATORY/COMPLIANCE IMPACT:
- Breach Notification Requirements: ${notification_requirements}
- Regulatory Bodies: ${regulatory_bodies}
- Notification Deadline: ${notification_deadline}

REMEDIATION PLAN:
Short-term (Complete by ${short_term_deadline}):
- Full credential rotation
- Network segmentation implementation
- Enhanced monitoring deployment

Long-term (Complete by ${long_term_deadline}):
- Zero Trust Architecture initiative
- EDR deployment across enterprise
- Privileged Access Management (PAM) solution

ESTIMATED FINANCIAL IMPACT:
- Incident Response Costs: ${ir_costs_estimate}
- Business Disruption: ${disruption_costs_estimate}
- Regulatory Fines (potential): ${regulatory_fines_estimate}
- Remediation Costs: ${remediation_costs_estimate}
- Total Estimated Impact: ${total_estimated_impact}

EXTERNAL COMMUNICATION:
- Customer Notification Required: ${customer_notification_required}
- Public Disclosure Required: ${public_disclosure_required}
- PR/Legal Coordination: ${pr_legal_status}

LESSONS LEARNED (Preliminary):
${preliminary_lessons_learned}

Next executive update: ${next_executive_update_time}

For questions or additional information:
CISO: ${ciso_contact}
Incident Commander: ${incident_commander_contact}
Legal: ${legal_contact}
```

## Regulatory Compliance and Standards

### NIST 800-53 Control Mapping

#### SC-7: Boundary Protection
**Control Statement**: Monitor and control communications at external and internal boundaries of the system.

**Lateral Movement Context**:
- **SC-7(5)**: Deny network communications traffic by default; allow network communications traffic by exception - Prevents unauthorized lateral movement between network segments.
- **SC-7(7)**: Prevent split tunneling for remote devices - Ensures VPN traffic cannot bypass security controls for lateral movement.
- **SC-7(20)**: Dynamic isolation/Segregation - Ability to dynamically isolate compromised hosts during lateral movement incident.
- **SC-7(21)**: Isolation of system components - Micro-segmentation to limit lateral movement blast radius.

**Implementation Requirements**:
- Network segmentation between trust zones (user workstations, servers, admin networks)
- Internal firewall/ACL rules restricting lateral protocols (SMB, RDP, WinRM, SSH)
- Jump boxes/bastion hosts for administrative access
- Monitoring of internal network traffic (not just perimeter)

#### AC-3: Access Enforcement
**Control Statement**: Enforce approved authorizations for logical access.

**Lateral Movement Context**:
- Least privilege - Standard users should not have admin rights on multiple hosts
- Just-in-Time (JIT) admin access - Temporary privilege elevation only when needed
- Privileged Access Workstations (PAW) - Admin tasks only from hardened workstations

#### AC-17: Remote Access
**Control Statement**: Establish usage restrictions and implementation guidance for remote access.

**Lateral Movement Context**:
- All remote access (RDP, SSH, WinRM) should be logged and monitored
- Multi-factor authentication required for remote access
- Remote access from standard workstations to servers should be restricted

#### AU-6: Audit Review, Analysis, and Reporting
**Control Statement**: Review and analyze system audit records for indications of inappropriate or unusual activity.

**Lateral Movement Context**:
- Continuous monitoring for lateral movement indicators (Event 4624 Type 3/10, PsExec, WMI)
- Automated correlation of authentication events across multiple hosts
- Alerting on anomalous patterns (user authenticating to unusual hosts)

### NIST 800-207: Zero Trust Architecture (ZTA)

**Core Principles Applied to Lateral Movement Prevention**:

1. **Never Trust, Always Verify**
   - Every internal authentication request is verified, not assumed legitimate
   - Continuous authentication and authorization for all network connections

2. **Assume Breach**
   - Design assumes attacker already has internal access
   - Focus on limiting blast radius through micro-segmentation

3. **Verify Explicitly**
   - Authentication decisions based on multiple data points:
     - User identity
     - Device posture/health
     - Location
     - Time of day
     - Risk score

**ZTA Implementation for Lateral Movement Defense**:

```yaml
zero_trust_controls:
  network_segmentation:
    - micro_segmentation: "Per-application/per-workload"
    - software_defined_perimeter: "Hide resources until authenticated"
    - dynamic_access_control: "Context-aware authorization"

  device_posture:
    - endpoint_health_check: "Before allowing network access"
    - compliance_validation: "AV updated, patches current, EDR running"
    - device_certificate: "Cryptographic device identity"

  continuous_authentication:
    - session_monitoring: "Detect anomalous behavior mid-session"
    - step_up_authentication: "MFA challenge for high-risk actions"
    - adaptive_access: "Restrict access based on risk score"
```

### Network Segmentation Standards

#### Tier-Based Segmentation Model

```
┌────────────────────────────────────────────────────────────┐
│  TIER 0: Domain Controllers, Certificate Authority, PAM    │  (Most Restricted)
│  Access: Admin Tier 0 accounts from PAW only               │
└────────────────────────────────────────────────────────────┘
                        ▲
                        │ (Tightly controlled, logged, MFA)
                        │
┌────────────────────────────────────────────────────────────┐
│  TIER 1: Servers, Databases, File Shares, Applications     │
│  Access: Admin Tier 1 accounts from Jump Boxes             │
└────────────────────────────────────────────────────────────┘
                        ▲
                        │ (Controlled access, jump boxes)
                        │
┌────────────────────────────────────────────────────────────┐
│  TIER 2: User Workstations, Laptops, Mobile Devices        │
│  Access: Standard users, no admin rights                   │
└────────────────────────────────────────────────────────────┘
```

**Lateral Movement Prevention Rules**:
- Tier 2 → Tier 2: Limited protocols (no RDP/SSH/WinRM between workstations)
- Tier 2 → Tier 1: Blocked (users access servers via applications, not direct RDP/SSH)
- Tier 2 → Tier 0: Completely blocked
- Tier 1 → Tier 0: Tightly controlled via Jump Box
- Admin accounts are tier-specific (Tier 2 admin ≠ Tier 1 admin)

#### Protocol-Based Segmentation

| Source Zone | Destination Zone | Allowed Protocols | Justification |
|-------------|------------------|-------------------|---------------|
| User Workstations | User Workstations | HTTP/HTTPS, DNS, ICMP | Limited peer-to-peer; no admin protocols |
| User Workstations | Application Servers | HTTP/HTTPS, App-specific | Application access only, no RDP/SSH |
| Admin Workstations | Servers | RDP, SSH, WinRM | Administrative access from authorized hosts only |
| Servers | Servers | App-specific | Application tier communication |
| Any | Domain Controllers | Kerberos (88), LDAP (389/636), DNS (53) | Domain services |

### Industry-Specific Standards

#### PCI DSS (Payment Card Industry)
- **Requirement 1.3**: Prohibit direct public access between Internet and any system component in the cardholder data environment
- **Requirement 10.2.5**: Log all access to audit trails
- **Requirement 10.6**: Review logs and security events for all system components to identify anomalies

**Lateral Movement Context**: Cardholder data environment (CDE) must be segmented; lateral movement from CDE to corporate network must be detected/prevented.

#### HIPAA (Healthcare)
- **164.312(a)(1)**: Access Control - Implement technical policies to allow only authorized access
- **164.312(b)**: Audit Controls - Hardware, software, procedures to record and examine activity

**Lateral Movement Context**: PHI-containing systems must have restricted access; lateral movement to PHI systems triggers breach investigation requirements.

#### SOC 2 Type II
- **CC6.6**: Logical and Physical Access Controls - Restricts logical access
- **CC7.2**: System Monitoring - Detects and responds to security incidents

**Lateral Movement Context**: Continuous monitoring and incident response capability required for SOC 2 compliance.

## Recovery Procedures

### Phase 1: Emergency Containment (First 30 Minutes)

#### Host Isolation
```bash
# Via Wazuh API (containment agent integration)
curl -X POST "https://wazuh-manager:55000/active-response" \
  -H "Authorization: Bearer $TOKEN" \
  -d '{
    "command": "isolate",
    "agent_id": "${source_agent_id}",
    "alert_id": "${alert_id}"
  }'

# Verification query
curl -X GET "https://wazuh-manager:55000/agents/${source_agent_id}" \
  | jq '.data.affected_items[0].status'
```

#### Account Disablement (Active Directory)
```powershell
# Disable compromised user accounts
$compromisedAccounts = @("user1", "user2", "serviceaccount1")
foreach ($account in $compromisedAccounts) {
    Disable-ADAccount -Identity $account
    Write-Host "[+] Disabled account: $account"

    # Force sign-out (revoke all sessions)
    Get-ADUser $account | Set-ADUser -Replace @{
        msDS-User-Account-Control-Computed = 16
    }
}

# Log action
Add-Content -Path "C:\SecurityLogs\incident_${incident_id}_actions.log" -Value "$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss') - Disabled accounts: $($compromisedAccounts -join ', ')"
```

#### Network-Level Containment
```bash
# Firewall rule to block source host (via network management API)
# Example: Cisco Firepower
curl -X POST "https://firewall/api/fmc_config/v1/domain/default/policy/accesspolicies/${policy_id}/accessrules" \
  -H "X-auth-access-token: $FMC_TOKEN" \
  -d '{
    "action": "BLOCK",
    "enabled": true,
    "type": "AccessRule",
    "name": "INCIDENT_${incident_id}_BLOCK_${source_ip}",
    "sourceNetworks": {
      "objects": [{"type": "Host", "value": "${source_ip}"}]
    },
    "logBegin": true,
    "logEnd": true
  }'
```

### Phase 2: Credential Reset Procedures (First 4 Hours)

#### Standard User Accounts
```powershell
# Force password reset at next logon
$users = Import-Csv "incident_${incident_id}_users.csv"
foreach ($user in $users) {
    Set-ADUser -Identity $user.SamAccountName -ChangePasswordAtLogon $true
    Set-ADUser -Identity $user.SamAccountName -PasswordNeverExpires $false

    # Increment Kerberos key version (invalidates existing tickets)
    $kvno = (Get-ADUser $user.SamAccountName -Properties msDS-KeyVersionNumber).'msDS-KeyVersionNumber'
    Set-ADUser -Identity $user.SamAccountName -Replace @{
        'msDS-KeyVersionNumber' = ($kvno + 1)
    }

    Write-Host "[+] Reset password and revoked Kerberos tickets for: $($user.SamAccountName)"
}
```

#### Service Accounts
```powershell
# Service account credential rotation (requires application owner coordination)
$serviceAccounts = @(
    @{Name="svc_app1"; NewPassword=""; Application="App1"; Owner="app1team@company.com"},
    @{Name="svc_db1"; NewPassword=""; Application="Database1"; Owner="dba@company.com"}
)

foreach ($svcAcct in $serviceAccounts) {
    # Generate high-entropy password (32 characters)
    $newPassword = -join ((65..90) + (97..122) + (48..57) + (33,35,36,37,38,42,64) | Get-Random -Count 32 | % {[char]$_})
    $securePassword = ConvertTo-SecureString $newPassword -AsPlainText -Force

    # Update AD password
    Set-ADAccountPassword -Identity $svcAcct.Name -NewPassword $securePassword -Reset

    # Store in privileged access management system
    # (Example: CyberArk, HashiCorp Vault)
    $pamResponse = Invoke-RestMethod -Uri "https://pam.company.com/api/accounts/$($svcAcct.Name)/password" `
        -Method PUT `
        -Headers @{Authorization="Bearer $PAM_TOKEN"} `
        -Body (@{password=$newPassword} | ConvertTo-Json)

    # Notify application owner
    $emailBody = @"
Service account password has been reset due to security incident ${incident_id}.

Account: $($svcAcct.Name)
Application: $($svcAcct.Application)
New password location: PAM system (request access via ServiceNow)

Action required: Update application configuration with new credentials within 4 hours.
"@
    Send-MailMessage -To $svcAcct.Owner -From "soc@company.com" `
        -Subject "[ACTION REQUIRED] Service Account Password Reset - $($svcAcct.Name)" `
        -Body $emailBody

    Write-Host "[+] Rotated password for service account: $($svcAcct.Name)"
}
```

#### Administrative Accounts
```powershell
# Administrative account credential reset with enhanced security
$adminAccounts = Get-ADGroupMember -Identity "Domain Admins" -Recursive | Select-Object -ExpandProperty SamAccountName

foreach ($admin in $adminAccounts) {
    # Generate 24-character high-entropy password
    $newPassword = -join ((65..90) + (97..122) + (48..57) + (33..47) + (58..64) | Get-Random -Count 24 | % {[char]$_})
    $securePassword = ConvertTo-SecureString $newPassword -AsPlainText -Force

    # Reset password
    Set-ADAccountPassword -Identity $admin -NewPassword $securePassword -Reset
    Set-ADUser -Identity $admin -ChangePasswordAtLogon $false  # Admin will receive new password securely

    # Increment Kerberos key version
    $kvno = (Get-ADUser $admin -Properties msDS-KeyVersionNumber).'msDS-KeyVersionNumber'
    Set-ADUser -Identity $admin -Replace @{'msDS-KeyVersionNumber' = ($kvno + 1)}

    # Deliver new password via secure channel (in-person, encrypted email, PAM system)
    # Example: Store in PAM
    Invoke-RestMethod -Uri "https://pam.company.com/api/accounts/$admin/password" `
        -Method PUT `
        -Headers @{Authorization="Bearer $PAM_TOKEN"} `
        -Body (@{password=$newPassword; type="admin"; incident="${incident_id}"} | ConvertTo-Json)

    Write-Host "[+] Reset admin account: $admin (password stored in PAM)"
}
```

#### Kerberos Ticket Revocation
```powershell
# Force revocation of all Kerberos tickets for compromised accounts
$compromisedUsers = @("user1", "user2", "admin1")

foreach ($user in $compromisedUsers) {
    # Get current key version number
    $currentKVNO = (Get-ADUser $user -Properties msDS-KeyVersionNumber).'msDS-KeyVersionNumber'

    # Increment by 2 (forces immediate invalidation)
    Set-ADUser $user -Replace @{'msDS-KeyVersionNumber' = ($currentKVNO + 2)}

    # Force replication to all DCs
    $dcs = (Get-ADDomainController -Filter *).HostName
    foreach ($dc in $dcs) {
        Sync-ADObject -Object (Get-ADUser $user).DistinguishedName -Source $dc
    }

    Write-Host "[+] Revoked all Kerberos tickets for: $user (KVNO: $currentKVNO -> $($currentKVNO + 2))"
}

# Verify ticket revocation
foreach ($user in $compromisedUsers) {
    $newKVNO = (Get-ADUser $user -Properties msDS-KeyVersionNumber).'msDS-KeyVersionNumber'
    Write-Host "[VERIFY] $user KVNO is now: $newKVNO"
}
```

### Phase 3: Active Directory Health Check (First 24 Hours)

#### Domain Controller Diagnostic
```powershell
# Run DCDiag on all domain controllers
$dcs = (Get-ADDomainController -Filter *).HostName
$dcdiagResults = @()

foreach ($dc in $dcs) {
    Write-Host "[*] Running DCDiag on $dc..."
    $result = Invoke-Command -ComputerName $dc -ScriptBlock {
        dcdiag /v
    }
    $dcdiagResults += @{DC=$dc; Result=$result}

    # Check for failures
    if ($result -match "failed test") {
        Write-Warning "[!] DCDiag failures detected on $dc - Review required"
        # Send alert to AD team
    }
}

# Save results
$dcdiagResults | ConvertTo-Json -Depth 10 | Out-File "incident_${incident_id}_dcdiag.json"
```

#### Replication Status Verification
```powershell
# Check AD replication status
Write-Host "[*] Checking AD replication status..."
$replSummary = repadmin /replsummary
$replSummary | Out-File "incident_${incident_id}_replication.txt"

# Check for replication failures
if ($replSummary -match "fail") {
    Write-Warning "[!] Replication failures detected - Immediate action required"
}

# Detailed replication status
$dcs = (Get-ADDomainController -Filter *).HostName
foreach ($dc in $dcs) {
    $replStatus = repadmin /showrepl $dc
    if ($replStatus -match "Last attempt.*failed") {
        Write-Warning "[!] Replication failure on $dc"
    }
}

# Force replication synchronization
foreach ($dc in $dcs) {
    repadmin /syncall $dc /AdeP
    Write-Host "[+] Forced replication sync on $dc"
}
```

#### Unauthorized Changes Detection
```powershell
# Query for unauthorized account modifications during incident window
$incidentStart = (Get-Date).AddDays(-1)  # Adjust based on incident timeline
$incidentEnd = Get-Date

# Event 4742: A computer account was changed
# Event 4738: A user account was changed
# Event 4720: A user account was created
# Event 4726: A user account was deleted
$unauthorizedChanges = Get-WinEvent -FilterHashtable @{
    LogName='Security'
    ID=4742,4738,4720,4726
    StartTime=$incidentStart
    EndTime=$incidentEnd
} -ComputerName (Get-ADDomainController).HostName[0] | Where-Object {
    # Filter for changes by non-authorized users
    $_.Properties[4].Value -notin @("AuthorizedAdmin1", "AuthorizedAdmin2")
}

if ($unauthorizedChanges) {
    Write-Warning "[!] Unauthorized AD changes detected during incident window:"
    $unauthorizedChanges | Select-Object TimeCreated, Id, Message | Format-Table -AutoSize

    # Export for investigation
    $unauthorizedChanges | Export-Csv "incident_${incident_id}_unauthorized_changes.csv" -NoTypeInformation
}
```

#### KRBTGT Password Reset (Golden Ticket Mitigation)
**WARNING**: This is a high-impact operation requiring careful planning.

```powershell
# Check KRBTGT password age
$krbtgt = Get-ADUser krbtgt -Properties PasswordLastSet
$passwordAge = (New-TimeSpan -Start $krbtgt.PasswordLastSet -End (Get-Date)).Days

Write-Host "[*] KRBTGT password age: $passwordAge days"

if ($passwordAge -gt 180 -or $goldenTicketSuspected) {
    Write-Warning "[!] KRBTGT password reset recommended"
    Write-Host @"
KRBTGT password reset procedure:
1. Reset KRBTGT password (first time)
2. Wait 10 hours for replication and ticket expiration
3. Reset KRBTGT password (second time)
4. Monitor for authentication failures

This operation will:
- Invalidate all existing Kerberos tickets
- Cause temporary authentication failures
- Require 20+ hours to complete safely

Proceed with this operation only after approval and coordination.
"@

    # Automated reset (requires approval flag)
    if ($KRBTGT_RESET_APPROVED) {
        # First reset
        $newPassword = -join ((65..90) + (97..122) + (48..57) | Get-Random -Count 32 | % {[char]$_})
        $securePassword = ConvertTo-SecureString $newPassword -AsPlainText -Force
        Set-ADAccountPassword -Identity krbtgt -NewPassword $securePassword -Reset
        Write-Host "[+] KRBTGT password reset (first pass) - Wait 10 hours before second reset"

        # Schedule second reset
        # (Use task scheduler or orchestration system)
    }
}
```

### Phase 4: Persistence Removal on All Touched Hosts (First 48 Hours)

#### Comprehensive Persistence Check
```powershell
# Run on each compromised host
$affectedHosts = @("Host_A", "Host_B", "Host_C")

foreach ($host in $affectedHosts) {
    Write-Host "[*] Checking persistence mechanisms on $host..."

    $persistenceCheck = Invoke-Command -ComputerName $host -ScriptBlock {
        $findings = @()

        # 1. Scheduled Tasks (created during incident window)
        $suspiciousTasks = Get-ScheduledTask | Where-Object {
            $_.TaskName -match "(update|system|service)" -and
            $_.Date -gt (Get-Date).AddDays(-2)
        }
        if ($suspiciousTasks) {
            $findings += "Suspicious scheduled tasks: $($suspiciousTasks.TaskName -join ', ')"
        }

        # 2. Services (created recently)
        $suspiciousServices = Get-Service | Where-Object {
            $_.Name -match "(update|system|service)" -and
            $_.StartType -eq "Automatic"
        } | ForEach-Object {
            $service = Get-WmiObject -Class Win32_Service -Filter "Name='$($_.Name)'"
            if ($service.PathName -notmatch "C:\\Windows\\System32") {
                $_
            }
        }
        if ($suspiciousServices) {
            $findings += "Suspicious services: $($suspiciousServices.Name -join ', ')"
        }

        # 3. Registry Run Keys
        $runKeys = @(
            "HKLM:\Software\Microsoft\Windows\CurrentVersion\Run",
            "HKLM:\Software\Microsoft\Windows\CurrentVersion\RunOnce",
            "HKCU:\Software\Microsoft\Windows\CurrentVersion\Run",
            "HKCU:\Software\Microsoft\Windows\CurrentVersion\RunOnce"
        )
        foreach ($key in $runKeys) {
            $entries = Get-ItemProperty -Path $key -ErrorAction SilentlyContinue
            if ($entries) {
                $entries.PSObject.Properties | Where-Object {
                    $_.Name -notmatch "PS" -and $_.Value -notmatch "C:\\Windows"
                } | ForEach-Object {
                    $findings += "Suspicious registry run key: $key\$($_.Name) = $($_.Value)"
                }
            }
        }

        # 4. WMI Event Subscriptions
        $wmiSubscriptions = Get-WmiObject -Class __EventFilter -Namespace root\subscription
        if ($wmiSubscriptions) {
            $findings += "WMI Event Subscriptions found: $($wmiSubscriptions.Name -join ', ')"
        }

        # 5. Backdoor User Accounts
        $recentUsers = Get-LocalUser | Where-Object {
            $_.Enabled -eq $true -and
            (New-TimeSpan -Start $_.PasswordLastSet -End (Get-Date)).Days -lt 7
        }
        foreach ($user in $recentUsers) {
            $isAdmin = (Get-LocalGroupMember -Group "Administrators" | Where-Object {$_.Name -match $user.Name})
            if ($isAdmin) {
                $findings += "Recently created admin user: $($user.Name)"
            }
        }

        return $findings
    }

    if ($persistenceCheck) {
        Write-Warning "[!] Persistence mechanisms found on $host:"
        $persistenceCheck | ForEach-Object { Write-Host "    - $_" }

        # Export for remediation
        $persistenceCheck | Out-File "incident_${incident_id}_persistence_${host}.txt"
    } else {
        Write-Host "[+] No obvious persistence mechanisms found on $host"
    }
}
```

#### Automated Persistence Removal
```powershell
# Remove identified persistence mechanisms (requires approval)
foreach ($host in $affectedHosts) {
    if ($PERSISTENCE_REMOVAL_APPROVED) {
        Invoke-Command -ComputerName $host -ScriptBlock {
            param($incidentId)

            # Remove suspicious scheduled tasks
            Get-ScheduledTask | Where-Object {
                $_.TaskName -match "(update|system|service)" -and
                $_.Date -gt (Get-Date).AddDays(-2)
            } | ForEach-Object {
                Unregister-ScheduledTask -TaskName $_.TaskName -Confirm:$false
                Write-Host "[+] Removed scheduled task: $($_.TaskName)"
            }

            # Remove suspicious services
            Get-Service | Where-Object {
                $_.Name -match "(update|system|service)"
            } | ForEach-Object {
                $service = Get-WmiObject -Class Win32_Service -Filter "Name='$($_.Name)'"
                if ($service.PathName -notmatch "C:\\Windows\\System32") {
                    Stop-Service -Name $_.Name -Force
                    sc.exe delete $_.Name
                    Write-Host "[+] Removed service: $($_.Name)"
                }
            }

            # Remove suspicious registry run keys (manual review recommended)
            # Remove WMI subscriptions
            Get-WmiObject -Class __EventFilter -Namespace root\subscription | Remove-WmiObject
            Get-WmiObject -Class __EventConsumer -Namespace root\subscription | Remove-WmiObject
            Get-WmiObject -Class __FilterToConsumerBinding -Namespace root\subscription | Remove-WmiObject
            Write-Host "[+] Removed WMI event subscriptions"

        } -ArgumentList $incident_id

        Write-Host "[+] Persistence removal completed on $host"
    }
}
```

### Phase 5: Network Segmentation Enhancement (Post-Incident)

#### Immediate Segmentation (First Week)
```yaml
network_segmentation_actions:
  immediate_acls:
    - description: "Block lateral RDP between workstations"
      source: "VLAN_Workstations"
      destination: "VLAN_Workstations"
      protocol: "TCP"
      port: 3389
      action: "DENY"
      log: true

    - description: "Block lateral SMB between workstations"
      source: "VLAN_Workstations"
      destination: "VLAN_Workstations"
      protocol: "TCP"
      port: 445
      action: "DENY"
      log: true

    - description: "Block lateral WinRM between workstations"
      source: "VLAN_Workstations"
      destination: "VLAN_Workstations"
      protocol: "TCP"
      port: [5985, 5986]
      action: "DENY"
      log: true

    - description: "Restrict workstation-to-server RDP (allow only from admin workstations)"
      source: "VLAN_Workstations"
      destination: "VLAN_Servers"
      protocol: "TCP"
      port: 3389
      action: "DENY"
      exceptions:
        - source_group: "Admin_Workstations"
          action: "ALLOW"
      log: true
```

#### Long-Term Architecture (First Month)
- Implement Privileged Access Workstations (PAW) for all administrative tasks
- Deploy Software-Defined Perimeter (SDP) for critical assets
- Implement Zero Trust Network Access (ZTNA) for remote access
- Deploy Network Access Control (NAC) for endpoint posture validation

## Agent Pipeline Integration

### Correlation Agent (Critical for Lateral Movement)

**Purpose**: Build network graph of all compromised relationships, map blast radius.

**Inputs**:
- Initial lateral movement alert (Event 4624 Type 3/10, PsExec, WMI, etc.)
- Time window: -24h to +4h

**Correlation Queries**:
1. **All hosts accessed from source**:
   ```json
   {
     "query": "data.win.eventdata.sourceNetworkAddress:${source_ip} AND event.code:4624 AND data.win.eventdata.logonType:(3 OR 10)",
     "time_range": "incident_time -1h to +4h",
     "aggregation": "unique agent.name"
   }
   ```

2. **All accounts used on source host**:
   ```json
   {
     "query": "agent.name:${source_host} AND event.code:4648",
     "extract": "data.win.eventdata.targetUserName"
   }
   ```

3. **Pivoting detection** (hosts that are both target and source):
   ```json
   {
     "query": "agent.name:${intermediate_host} AND (event.code:4624 AND data.win.eventdata.logonType:(3 OR 10)) OR (event.code:4648)",
     "correlation": "Inbound 4624 followed by outbound 4648 within 1 hour = pivoting"
   }
   ```

4. **Credential type identification**:
   - Pass-the-Hash: `event.code:4624 AND data.win.eventdata.authenticationPackageName:NTLM AND NOT (prior Kerberos 4768)`
   - Pass-the-Ticket: `event.code:4769 AND (encryption:RC4 OR anomalous ticket flags)`

**Outputs**:
- Network graph (JSON): `{"nodes": [hosts], "edges": [auth_relationships]}`
- Blast radius count: Number of unique hosts accessed
- Pivoting chains detected: `["Host_A -> Host_B -> Host_C"]`
- Credential types used: `["Password", "NTLM_Hash", "Kerberos_Ticket"]`
- Risk score: `blast_radius_count * technique_severity * target_criticality`

**Pass to**: Investigation Agent, Response Planner

### Investigation Agent (Attack Path Reconstruction)

**Purpose**: Trace full attack path from initial compromise to current state.

**Investigation Steps**:
1. **Identify initial compromise** (lookback 7 days):
   - Malware alerts on source host
   - Phishing indicators
   - Exploit alerts
   - Credential access alerts (LSASS dump, Mimikatz)

2. **Timeline construction**:
   ```yaml
   timeline:
     - t0: Initial compromise (source_host, malware XYZ)
     - t1: Credential access (Mimikatz detected, LSASS dump)
     - t2: Lateral movement attempt 1 (source -> target1 via PsExec)
     - t3: Lateral movement attempt 2 (source -> target2 via WinRM)
     - t4: Pivoting detected (target1 -> target3)
     - t5: Critical asset access (target3 = Domain Controller)
   ```

3. **Forensic artifact collection**:
   - Request memory dumps from source host (if EDR available)
   - PowerShell history extraction
   - Event log export (Security, Sysmon) from all affected hosts

4. **Attack technique mapping**:
   - Map each step to MITRE ATT&CK
   - Identify attacker tools used (PsExec, Mimikatz, custom scripts)
   - Determine sophistication level

**Outputs**:
- Attack narrative (natural language summary)
- Full timeline (JSON)
- MITRE ATT&CK chain: `["T1078", "T1003.001", "T1021.002", "T1550.002"]`
- Attribution indicators (if available)
- Forensic evidence package manifest

**Pass to**: Response Planner, SOC Lead

### Response Planner (Multi-Host Containment)

**Purpose**: Generate comprehensive containment plan for entire compromised graph.

**Containment Strategy**:
1. **Prioritize containment order**:
   - Source host (highest priority - prevent further spread)
   - Pivot hosts (medium priority - break the chain)
   - Leaf hosts (lower priority - endpoints of lateral movement)

2. **Parallel containment** (if blast radius <5 hosts):
   ```yaml
   containment_plan:
     strategy: parallel
     hosts:
       - agent_id: ${source_agent_id}
         action: isolate
         priority: critical
         approval: auto
       - agent_id: ${target1_agent_id}
         action: isolate
         priority: high
         approval: auto
       - agent_id: ${target2_agent_id}
         action: isolate
         priority: high
         approval: auto
   ```

3. **Sequential containment** (if blast radius >5 hosts or includes critical assets):
   ```yaml
   containment_plan:
     strategy: sequential
     phases:
       - phase: 1
         description: "Isolate source host"
         hosts: [${source_agent_id}]
         approval: auto
         wait_for_verification: 60s

       - phase: 2
         description: "Disable compromised accounts"
         accounts: [${user1}, ${user2}]
         approval: required

       - phase: 3
         description: "Isolate pivot hosts"
         hosts: [${pivot_host_agent_ids}]
         approval: required
         requires: dual_approval

       - phase: 4
         description: "Network ACL deployment"
         actions:
           - block_ip: ${source_ip}
           - block_protocol: "SMB from ${source_ip}"
   ```

4. **Rollback plan**:
   ```yaml
   rollback:
     - condition: "False positive confirmed"
       action: "Restore network access to all isolated hosts"
       steps:
         - unisolate_hosts: [${all_isolated_agent_ids}]
         - remove_firewall_rules: [${incident_firewall_rules}]
         - re_enable_accounts: [${disabled_accounts}]

     - condition: "Business critical service impacted"
       action: "Partial rollback with enhanced monitoring"
       steps:
         - unisolate_host: ${critical_host_agent_id}
         - deploy_enhanced_monitoring: true
         - require_mfa: true
   ```

**Outputs**:
- Containment plan (YAML/JSON)
- Approval requirements: `["auto", "single_approver", "dual_approver"]`
- Impact assessment: Business services affected
- Rollback procedures

**Execution**: Passes plan to Containment Agent for approval and execution

## Enhanced SLA/KPI Metrics

### Detection Phase

| Metric | Target | Measurement Method |
|--------|--------|-------------------|
| **Detection Latency** | <3 minutes | Time from authentication event to alert generation |
| **False Positive Rate** | <5% | (False Positives / Total Alerts) * 100 |
| **Alert Fidelity Score** | >90% | Percentage of alerts requiring investigation |

**Measurement**:
```yaml
detection_latency:
  source: "Wazuh alert timestamp - Original event timestamp"
  target: 180  # seconds
  alert_if_exceeds: 300  # Alert if detection takes >5min
```

### Correlation Phase

| Metric | Target | Measurement Method |
|--------|--------|-------------------|
| **Blast Radius Mapping** | <15 minutes | Time from initial alert to complete graph construction |
| **Pivoting Detection** | <10 minutes | Time to identify multi-hop chains |
| **Correlation Accuracy** | >95% | Percentage of correlated events correctly associated |

**Measurement**:
```yaml
blast_radius_mapping:
  start: "Initial alert timestamp"
  end: "Correlation agent output timestamp"
  target: 900  # seconds (15 minutes)
  components:
    - query_execution: <5min
    - graph_construction: <5min
    - output_generation: <5min
```

### Containment Phase

| Metric | Target | Measurement Method |
|--------|--------|-------------------|
| **Source Host Containment** | <10 minutes | Time from alert to source host isolated |
| **Account Disablement** | <15 minutes | Time from alert to compromised account disabled |
| **Full Path Isolation** | <30 minutes | Time to isolate all affected hosts (if <10 hosts) |
| **Network Segmentation** | <1 hour | Time to deploy emergency firewall rules |

**Measurement**:
```yaml
source_containment:
  start: "Alert timestamp"
  end: "Host isolation confirmed timestamp"
  target: 600  # seconds (10 minutes)
  breakdown:
    - alert_to_approval: <3min
    - approval_to_execution: <2min
    - execution_to_verification: <5min
```

### Investigation Phase

| Metric | Target | Measurement Method |
|--------|--------|-------------------|
| **Initial Compromise Identified** | <2 hours | Time to identify initial attack vector |
| **Full Timeline Construction** | <4 hours | Complete attack path mapped |
| **Forensic Evidence Collection** | <24 hours | All artifacts collected from affected hosts |

### Recovery Phase

| Metric | Target | Measurement Method |
|--------|--------|-------------------|
| **Credential Reset (User Accounts)** | <4 hours | All compromised user passwords reset |
| **Credential Reset (Service Accounts)** | <8 hours | All compromised service account passwords rotated |
| **Persistence Removal** | <48 hours | All backdoors removed from affected hosts |
| **Network Segmentation Enhancements** | <7 days | Emergency ACLs deployed |

**Overall Incident Lifecycle SLA**:
```yaml
incident_lifecycle:
  detection: <3min
  correlation_and_blast_radius: <15min
  containment_decision: <25min
  containment_execution: <40min  # Cumulative: Detection + 37min
  investigation_initial_findings: <2h
  full_investigation: <24h
  credential_reset: <4h  # User accounts
  persistence_removal: <48h
  post_incident_review: <7days
```

### Continuous Monitoring KPIs

| KPI | Target | Frequency |
|-----|--------|-----------|
| **Mean Time to Detect (MTTD)** | <3 minutes | Weekly average |
| **Mean Time to Respond (MTTR)** | <30 minutes | Weekly average |
| **Mean Time to Contain (MTTC)** | <40 minutes | Weekly average |
| **Mean Time to Recover (MTTRec)** | <48 hours | Per incident |
| **Incident Recurrence Rate** | 0% | Same attacker, same technique within 90 days |

### Dashboard Metrics
```yaml
soc_dashboard:
  real_time:
    - active_lateral_movement_incidents: count
    - hosts_currently_isolated: count
    - pending_containment_approvals: count
    - blast_radius_average: hosts_per_incident

  weekly:
    - lateral_movement_detections: count
    - false_positive_rate: percentage
    - average_blast_radius: hosts
    - average_dwell_time: hours
    - pivoting_chains_detected: count

  monthly:
    - most_targeted_assets: list
    - most_abused_techniques: [T1021.002, T1021.006, T1550.002]
    - credential_compromise_trends: graph
    - network_segmentation_effectiveness: score
```

---

## Appendix A: Quick Reference

### Critical Wazuh Rules
- **5700-5720**: SSH lateral movement
- **18100-18199**: Windows remote execution (PsExec, WMI, WinRM)
- **61100-61199**: Windows authentication (network logon, RDP)

### Critical Windows Events
- **4624 Type 3**: Network logon (SMB, WMI)
- **4624 Type 10**: Remote interactive (RDP)
- **4648**: Explicit credentials (remote execution)
- **5140/5145**: Share access (ADMIN$, C$)
- **7045**: New service (PsExec indicator)

### Critical Sysmon Events
- **EID 1**: Process creation (PsExec, WMI)
- **EID 3**: Network connection (SMB, RDP, WinRM)
- **EID 17/18**: Named pipes (PsExec, RemCom)

### Containment Decision Matrix
| Blast Radius | Account Type | Target Criticality | Containment Approval |
|--------------|--------------|-------------------|---------------------|
| 1 host | Standard | Low | Auto |
| 1 host | Admin | High | Single Approver |
| 2-5 hosts | Any | Any | Single Approver |
| 6+ hosts | Any | Any | Dual Approver |
| Any | Domain Admin | Critical Asset | Dual Approver + CISO |

---

## Version History

| Version | Date | Author | Changes |
|---------|------|--------|---------|
| 1.0.0 | 2024-XX-XX | SOC Team | Initial playbook |
| 2.0.0 | 2026-02-17 | SOC Team | Comprehensive rewrite: Added expanded MITRE coverage, comprehensive Wazuh rule mapping, multi-stage decision tree, forensic artifacts, attack path visualization, communication templates, regulatory compliance, enhanced recovery procedures, agent pipeline integration, enhanced SLA/KPIs |

---

**Document Classification**: TLP:AMBER
**Distribution**: Authorized SOC Personnel Only
**Review Date**: 2026-05-17 (Quarterly Review)
