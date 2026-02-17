# Playbook: Ransomware Detection and Response

## Document Control

| Field | Value |
|-------|-------|
| **Playbook ID** | PB-002 |
| **Version** | 2.0.0 |
| **Classification** | TLP:RED |
| **Distribution** | RESTRICTED - Authorized Security Personnel Only |
| **Last Updated** | 2026-02-17 |
| **Review Cycle** | Quarterly |
| **Document Owner** | Security Operations Center |
| **Approval Authority** | CISO |

### Version History
| Version | Date | Changes | Author |
|---------|------|---------|--------|
| 2.0.0 | 2026-02-17 | Major revision: Enhanced MITRE coverage, expanded detection rules, regulatory compliance, recovery procedures | SOC Team |
| 1.0.0 | 2025-XX-XX | Initial release | SOC Team |

---

## Overview

| Field | Value |
|-------|-------|
| Playbook ID | PB-002 |
| Version | 2.0.0 |
| Severity | **CRITICAL** |
| Priority | **IMMEDIATE - EMERGENCY RESPONSE** |
| Response SLA | Detection <2min, Isolation <5min, Scope <30min |
| Approval Type | Emergency Fast-Path (5min expedited) |

### MITRE ATT&CK Framework Coverage

#### Primary Tactics & Techniques

| Tactic | Technique | Sub-Technique | Description |
|--------|-----------|---------------|-------------|
| **Impact** | **T1486** | Data Encrypted for Impact | Primary ransomware encryption activity |
| Impact | **T1490** | Inhibit System Recovery | VSS deletion, backup sabotage |
| Impact | **T1489** | Service Stop | Stopping AV, backup, database services |
| Impact | **T1491** | Defacement | Wallpaper changes, ransom notes |
| Defense Evasion | **T1027** | Obfuscated Files or Information | Packed/encrypted ransomware binaries |
| Defense Evasion | **T1027.002** | Software Packing | UPX, Themida, custom packers |
| Defense Evasion | **T1027.005** | Indicator Removal from Tools | Anti-forensics techniques |
| Defense Evasion | **T1036** | Masquerading | Legitimate-looking process names |
| Defense Evasion | **T1036.004** | Masquerade Task or Service | Scheduled tasks for persistence |
| Defense Evasion | **T1055** | Process Injection | Code injection into legitimate processes |
| Defense Evasion | **T1055.001** | Dynamic-link Library Injection | DLL injection techniques |
| Defense Evasion | **T1055.012** | Process Hollowing | Hollow legitimate process for ransomware |
| Defense Evasion | **T1070** | Indicator Removal | Log deletion, timestomping |
| Defense Evasion | **T1070.001** | Clear Windows Event Logs | Clearing Security/System logs |
| Exfiltration | **T1041** | Exfiltration Over C2 | Double extortion - data theft |
| Exfiltration | **T1567** | Exfiltration Over Web Service | Cloud storage exfiltration |
| Command & Control | **T1071** | Application Layer Protocol | HTTPS C2 channels |
| Persistence | **T1053.005** | Scheduled Task/Job | Task Scheduler persistence |

---

## Critical Context

### Threat Landscape (2026)

Ransomware remains the **#1 cybersecurity threat** to enterprises globally. Current trends:

- **Double/Triple Extortion**: Data exfiltration before encryption, DDoS threats
- **Ransomware-as-a-Service (RaaS)**: LockBit 3.0, BlackCat/ALPHV, Cl0p, Royal, Play, Akira
- **Supply Chain Attacks**: MOVEit, ConnectWise vulnerabilities
- **Encryption Speed**: Modern ransomware encrypts 100,000+ files/minute
- **Average Ransom**: $1.5M - $8M (critical infrastructure: $10M+)
- **Recovery Costs**: 5-10x ransom amount
- **SEC Reporting**: 4 business days mandatory disclosure

### Business Impact

- **Operational**: Complete business shutdown, revenue loss ($5M-$50M/day)
- **Reputational**: Customer trust erosion, stock price impact
- **Legal**: Regulatory fines, shareholder lawsuits, customer claims
- **Recovery Timeline**: 2-8 weeks for full restoration

**TIME IS CRITICAL** - Ransomware encrypts thousands of files per minute. Every second counts.

---

## Detection Criteria

### Primary Indicators

1. **Mass File Modifications** - High-velocity changes across multiple directories
2. **Suspicious File Extensions** - .encrypted, .locked, .crypto, .crypt, .locked, .enc, .cry
3. **Ransom Note Creation** - README.txt, DECRYPT.txt, HOW_TO_RECOVER.txt, ransom.html
4. **Shadow Copy Deletion** - vssadmin delete shadows, wmic shadowcopy delete
5. **Recovery Disablement** - bcdedit /set {default} recoveryenabled no
6. **Service Termination** - Stopping SQL, Exchange, VSS, backup services
7. **Known Ransomware Families** - LockBit, BlackCat, Cl0p, Royal, Play, Akira, Conti variants

### Wazuh Detection Rules

#### File Integrity Monitoring (FIM)
| Rule ID | Description | Severity | Action |
|---------|-------------|----------|--------|
| **550** | FIM - File added to the system | Low | Monitor |
| **551** | FIM - File modified | Low | Monitor |
| **552** | FIM - File deleted | Low | Monitor |
| **553** | FIM - File added (Windows) | Low | Monitor |
| **554** | FIM - File checksum changed | Medium | Alert |
| **Custom-RW-001** | FIM - Mass file modifications (100+ in 60s) | Critical | **Immediate Alert** |
| **Custom-RW-002** | FIM - Suspicious extension detected | Critical | **Immediate Alert** |
| **Custom-RW-003** | FIM - Ransom note file created | Critical | **Immediate Alert** |
| **Custom-RW-004** | FIM - Multiple directories modified simultaneously | High | Alert |

#### Sysmon Event Monitoring
| Event ID | Description | Detection Logic | Severity |
|----------|-------------|-----------------|----------|
| **1** | Process Creation | vssadmin.exe, bcdedit.exe, wbadmin.exe with suspicious args | Critical |
| **11** | File Creation | Ransom note patterns, mass .encrypted file creation | Critical |
| **23** | File Delete | Shadow copy deletion, backup file removal | Critical |
| **3** | Network Connection | C2 communication to known ransomware infrastructure | High |
| **7** | Image Loaded | Suspicious DLL loads from temp/appdata | Medium |
| **8** | CreateRemoteThread | Process injection indicators | High |

#### Rootcheck/System Monitoring
| Rule ID | Description | Detection |
|---------|-------------|-----------|
| **510** | Windows Audit - Success | Process creation monitoring |
| **515** | Windows Audit - Failure | Failed access attempts |
| **518** | Windows Audit - Special Logon | Privilege escalation |
| **520** | Windows Audit - User Account Changed | Account manipulation |
| **Custom-RW-010** | VSS Service Stopped | Critical service termination |
| **Custom-RW-011** | Backup Service Stopped | Backup protection disabled |

#### Ransomware Family Signatures

##### LockBit 3.0
```yaml
indicators:
  process_names: ["LockBit.exe", "lockbit.exe", "1.exe", "s.exe"]
  file_extensions: [".lockbit", ".abcd"]
  ransom_note: "Restore-My-Files.txt"
  mutex: "Global\\{GUID}"
  encryption: "AES-256 + RSA-2048"
```

##### BlackCat/ALPHV (Rust-based)
```yaml
indicators:
  process_names: ["alphv.exe", "blackcat.exe", "noname.exe"]
  file_extensions: [".alphv", ".<random 7 chars>"]
  ransom_note: "RECOVER-<extension>-FILES.txt"
  languages: ["Rust"]
  encryption: "ChaCha20 + RSA"
```

##### Cl0p
```yaml
indicators:
  process_names: ["Cl0p.exe", "C1_0P.exe"]
  file_extensions: [".Cl0p", ".C1_0P"]
  ransom_note: "CIOpReadMe.txt"
  targeted_files: [".xls", ".doc", ".pdf", ".sql", ".mdb"]
```

##### Royal Ransomware
```yaml
indicators:
  process_names: ["royal.exe", "svchost.exe" (masquerading)]
  file_extensions: [".royal", ".royal_w", ".royal_x"]
  ransom_note: "README.TXT"
  callback_encryption: "Partial encryption (intermittent)"
```

##### Play Ransomware
```yaml
indicators:
  process_names: ["play.exe", "rundll32.exe" (injected)]
  file_extensions: [".play"]
  ransom_note: "ReadMe[.]txt"
  signature: File marker "PLAY" at end of encrypted files
```

##### Akira
```yaml
indicators:
  process_names: ["akira.exe", "<random>.exe"]
  file_extensions: [".akira", ".powerranges"]
  ransom_note: "akira_readme.txt"
  techniques: "VPN exploitation, credential theft"
```

### High-Confidence Detection Patterns

```yaml
critical_confidence_100:
  - (shadow_copy_deletion OR vss_service_stop)
    AND mass_file_encryption (>1000 files)
    AND ransom_note_created
  - known_ransomware_binary_hash_match
  - file_encryption + data_exfiltration + C2_communication

high_confidence_90:
  - mass_file_modification (>500 files/min)
    AND suspicious_extension_change
  - bcdedit_recovery_disable
    AND service_stop (SQL/Exchange/VSS)
  - process_injection + file_encryption_activity

medium_confidence_70:
  - suspicious_file_extensions (>100 files)
  - mass_file_deletion + unusual_process_activity
  - backup_service_stopped + network_scanning
```

---

## Decision Tree: Ransomware Triage

```
┌─────────────────────────────────────┐
│   Ransomware Alert Triggered        │
│   (Detection <2min SLA)             │
└──────────────┬──────────────────────┘
               │
               ▼
    ┌──────────────────────┐
    │ Encryption Confirmed? │
    └──┬───────────────┬───┘
       │ YES           │ NO
       │               ▼
       │    ┌─────────────────────┐
       │    │ Suspected/Precursor │
       │    │ (VSS delete, etc.)  │
       │    └─────────┬───────────┘
       │              │
       │              ▼
       │    ┌─────────────────────┐
       │    │ Enhanced Monitoring │
       │    │ Prepare Isolation   │
       │    └─────────────────────┘
       │
       ▼
┌──────────────────────┐
│ Single Host vs       │
│ Multi-Host?          │
└──┬─────────────┬─────┘
   │ Single      │ Multi
   │             ▼
   │   ┌─────────────────────────┐
   │   │ MAJOR INCIDENT          │
   │   │ Isolate Network Segment │
   │   │ Page Incident Commander │
   │   │ Activate IR Team        │
   │   └─────────────────────────┘
   │
   ▼
┌──────────────────────────┐
│ Data Exfiltration        │
│ Detected?                │
└──┬───────────────┬───────┘
   │ YES           │ NO
   │ (Double       │ (Encrypt Only)
   │  Extortion)   │
   │               ▼
   │      ┌──────────────────┐
   │      │ Standard         │
   │      │ Ransomware       │
   │      │ Response         │
   │      └──────────────────┘
   │
   ▼
┌──────────────────────────────┐
│ ENHANCED RESPONSE            │
│ - Legal Counsel (breach)     │
│ - Forensic Data Mapping      │
│ - Regulatory Notifications   │
│ - Customer Impact Analysis   │
└──────────────────────────────┘
   │
   ▼
┌──────────────────────────────┐
│ Critical Infrastructure?     │
│ (DC, Exchange, DB, Backups)  │
└──┬───────────────────┬───────┘
   │ YES               │ NO
   │                   ▼
   │          ┌─────────────────┐
   │          │ Standard SLA    │
   │          │ Isolation <5min │
   │          └─────────────────┘
   │
   ▼
┌──────────────────────────────┐
│ EMERGENCY ESCALATION         │
│ - CISO Immediate Notify      │
│ - Business Continuity Plan   │
│ - Isolation <2min            │
│ - Crisis Management Team     │
└──────────────────────────────┘
```

---

## Automated Triage Steps

### 1. Entity Extraction (Automated)

```yaml
entities:
  - type: host
    source: agent.name
    priority: critical
    enrichment: asset_inventory, criticality_score

  - type: user
    source: data.user
    enrichment: AD_groups, privileged_account_status

  - type: process
    source: data.process.name
    enrichment: parent_process, command_line, signing_status

  - type: hash
    source: data.process.hash
    enrichment: VirusTotal, threat_intel_feeds

  - type: file_paths
    source: data.path
    analysis: directory_patterns, file_count, change_velocity

  - type: network
    source: data.destip
    enrichment: threat_intel, geolocation, known_C2

  - type: ransomware_family
    source: pattern_matching
    indicators: file_extension, ransom_note_content, binary_signature
```

### 2. Immediate Assessment (Isolation <5min SLA)

```yaml
assessment_checklist:
  host_identification:
    - primary_affected_hosts: []
    - secondary_affected_hosts: []
    - total_host_count: 0
    - critical_infrastructure_affected: false

  encryption_analysis:
    - files_encrypted: 0
    - encryption_rate_per_minute: 0
    - directories_affected: []
    - encryption_percentage: 0
    - estimated_completion_time: "N/A"

  ransomware_identification:
    - family: "unknown|lockbit|blackcat|clop|royal|play|akira"
    - confidence: "low|medium|high|confirmed"
    - variant: ""
    - known_decryptor_available: false

  lateral_movement:
    - movement_detected: false
    - infection_vector: "unknown|phishing|rdp|vpn|exploit"
    - compromised_accounts: []
    - network_propagation: false

  data_exfiltration:
    - exfiltration_detected: false
    - data_volume_gb: 0
    - exfil_destinations: []
    - double_extortion_confirmed: false
```

### 3. Severity Assessment

| Condition | Severity | SLA | Escalation |
|-----------|----------|-----|------------|
| Any confirmed ransomware | **Critical** | Isolation <5min | SOC Lead |
| Production/critical system | **Critical + P1** | Isolation <2min | Incident Commander |
| Multiple hosts (>3) | **Critical + Major Incident** | Immediate | CISO, Crisis Team |
| Domain controller affected | **Critical + EMERGENCY** | Isolation <1min | CISO, CTO, CEO |
| Backup systems compromised | **Critical + EMERGENCY** | Immediate | CISO, Business Continuity |
| Data exfiltration confirmed | **Critical + Breach** | Immediate | Legal, PR, Compliance |

---

## Correlation and Timeline Analysis

### Related Alerts to Cluster

```yaml
correlation_rules:
  primary_alerts:
    - rule.groups: "fim" AND rule.level: >=7
    - rule.groups: "sysmon" AND event.id: [1, 11, 23]
    - rule.groups: "windows" AND event.id: [4688, 4689, 4697]

  secondary_indicators:
    - process_creation: "vssadmin|bcdedit|wbadmin|cipher"
    - network_connections: "suspicious_ips|tor_exit_nodes"
    - privilege_escalation: "runas|psexec|mimikatz"
    - lateral_movement: "smb|rdp|wmi|psremoting"

  supporting_context:
    - authentication_logs: "event.id: [4624, 4625, 4648]"
    - service_changes: "event.id: [7034, 7035, 7036, 7040]"
    - scheduled_tasks: "event.id: [4698, 4699, 4700, 4701]"
```

### Timeline Construction (Scope Assessment <30min SLA)

```yaml
timeline_query:
  lookback: 72h  # Extended for full infection chain
  lookahead: 0   # Real-time only

  filters:
    - agent.id: ${agent_id}
    - rule.groups: [sysmon, fim, rootcheck, windows, firewall]
    - rule.level: >=3

  priority_events:
    t_minus_72h:
      - initial_access: "phishing_email|rdp_login|vpn_connection|exploit"
      - reconnaissance: "network_scanning|ad_enumeration|share_discovery"

    t_minus_48h:
      - credential_access: "lsass_dump|sam_dump|password_spray"
      - lateral_movement: "psexec|wmi|remote_desktop"

    t_minus_24h:
      - persistence: "scheduled_task|registry_run_key|service_creation"
      - privilege_escalation: "token_manipulation|process_injection"

    t_minus_2h:
      - defense_evasion: "av_disable|log_clearing|indicator_removal"
      - discovery: "system_info|network_mapping|data_staging"

    t_minus_30m:
      - exfiltration: "large_upload|cloud_sync|ftp_transfer"

    t_zero:
      - impact: "shadow_copy_deletion|service_stop|encryption_start"

  aggregation:
    - group_by: [agent.id, data.user, data.process.parent.name]
    - order: timestamp_asc
    - enrichment: threat_intel, asset_context
```

---

## Forensic Artifacts Collection

### Linux Systems

#### Live System Analysis
```bash
# Process Information
ps auxf > /forensics/process_tree.txt
lsof -p $(pgrep -d',' <suspicious_process>) > /forensics/open_files.txt
cat /proc/<PID>/cmdline > /forensics/cmdline.txt
cat /proc/<PID>/environ > /forensics/environment.txt

# Network Connections
netstat -antp > /forensics/network_connections.txt
ss -tulpn > /forensics/sockets.txt
iptables -L -n -v > /forensics/firewall_rules.txt

# File System Timeline
find / -type f -mtime -1 -ls > /forensics/modified_24h.txt
find /tmp /var/tmp /dev/shm -type f -ls > /forensics/temp_files.txt

# Persistence Mechanisms
crontab -l -u root > /forensics/root_crontab.txt
cat /etc/crontab > /forensics/system_crontab.txt
ls -la /etc/cron.* > /forensics/cron_directories.txt
systemctl list-units --type=service --state=running > /forensics/services.txt

# Inode Timeline (Deleted Files)
debugfs -R "lsdel" /dev/sda1 > /forensics/deleted_inodes.txt

# Memory Dump (if available)
dd if=/dev/mem of=/forensics/memory.dump bs=1M
# OR use AVML for crash-consistent capture
./avml /forensics/memory.lime
```

#### File System Artifacts
```bash
# Log Analysis
tar czf /forensics/logs.tar.gz /var/log/
grep -r "ransomware|encrypt|vss|shadow" /var/log/ > /forensics/log_keywords.txt

# User Activity
last -Faiwx > /forensics/login_history.txt
lastlog > /forensics/lastlog.txt
w > /forensics/current_users.txt

# File Integrity
rpm -Va > /forensics/rpm_verify.txt  # RHEL/CentOS
dpkg -V > /forensics/dpkg_verify.txt # Debian/Ubuntu

# Chain of Custody Hash
sha256sum /forensics/* > /forensics/MANIFEST.sha256
```

### Windows Systems

#### Live System Analysis
```powershell
# Process Information
Get-Process | Export-Csv C:\Forensics\processes.csv
Get-WmiObject Win32_Process | Select-Object Name, ProcessId, ParentProcessId, CommandLine, CreationDate | Export-Csv C:\Forensics\process_details.csv

# Network Connections
netstat -anob > C:\Forensics\network_connections.txt
Get-NetTCPConnection | Export-Csv C:\Forensics\tcp_connections.csv

# Services
Get-Service | Export-Csv C:\Forensics\services.csv
sc query | Out-File C:\Forensics\services_query.txt

# Scheduled Tasks
Get-ScheduledTask | Export-Csv C:\Forensics\scheduled_tasks.csv
schtasks /query /fo LIST /v > C:\Forensics\schtasks_verbose.txt

# Registry Run Keys
reg export "HKLM\Software\Microsoft\Windows\CurrentVersion\Run" C:\Forensics\HKLM_Run.reg
reg export "HKCU\Software\Microsoft\Windows\CurrentVersion\Run" C:\Forensics\HKCU_Run.reg
reg export "HKLM\Software\Microsoft\Windows\CurrentVersion\RunOnce" C:\Forensics\HKLM_RunOnce.reg

# Logged-On Users
quser > C:\Forensics\logged_users.txt
query session > C:\Forensics\sessions.txt
```

#### Windows Event Logs (Critical)
```powershell
# Security Event Log
wevtutil epl Security C:\Forensics\Security.evtx
wevtutil epl System C:\Forensics\System.evtx
wevtutil epl Application C:\Forensics\Application.evtx

# Specific Event IDs
# 4688 - Process Creation (with command line)
# 4689 - Process Termination
# 4624 - Account Logon
# 4625 - Failed Logon
# 4648 - Explicit Credential Logon
# 4697 - Service Installation
# 7034 - Service Crashed
# 7035 - Service Control (Start/Stop)
# 7036 - Service State Change
# 7040 - Service Startup Type Changed

Get-WinEvent -FilterHashtable @{LogName='Security'; ID=4688} -MaxEvents 10000 | Export-Csv C:\Forensics\Process_Creation_4688.csv

# Sysmon (if installed)
wevtutil epl Microsoft-Windows-Sysmon/Operational C:\Forensics\Sysmon.evtx
```

#### Volume Shadow Copies (VSS)
```powershell
# List Shadow Copies
vssadmin list shadows > C:\Forensics\vss_list.txt
Get-WmiObject Win32_ShadowCopy | Export-Csv C:\Forensics\vss_wmi.csv

# If VSS deleted - check deletion events
Get-WinEvent -FilterHashtable @{LogName='System'; ID=8222} | Export-Csv C:\Forensics\vss_deletion_8222.csv
```

#### Prefetch Analysis
```powershell
# Copy Prefetch files
Copy-Item C:\Windows\Prefetch\* C:\Forensics\Prefetch\ -Recurse

# Parse with PECmd.exe (Eric Zimmerman Tools)
PECmd.exe -d C:\Windows\Prefetch --csv C:\Forensics\Prefetch_Analysis
```

#### Amcache Analysis
```powershell
# Copy Amcache
Copy-Item C:\Windows\AppCompat\Programs\Amcache.hve C:\Forensics\

# Parse with AmcacheParser.exe
AmcacheParser.exe -f C:\Forensics\Amcache.hve --csv C:\Forensics\Amcache_Analysis
```

#### MFT (Master File Table) Analysis
```powershell
# Extract MFT with RawCopy
RawCopy.exe /FileNamePath:C:\$MFT /OutputPath:C:\Forensics

# Parse with MFTECmd.exe
MFTECmd.exe -f C:\Forensics\$MFT --csv C:\Forensics\MFT_Analysis
```

#### USN Journal (Update Sequence Number)
```powershell
# Extract USN Journal
fsutil usn readjournal C: csv > C:\Forensics\UsnJrnl.csv

# Analyze recent file operations
fsutil usn queryjournal C: > C:\Forensics\UsnJrnl_Info.txt
```

#### Memory Dump (Critical for Encryption Keys)
```powershell
# Windows 10/11 - Built-in
# Right-click Task Manager > Create Dump File
# OR use Winpmem
winpmem_mini_x64.exe -o C:\Forensics\memory.raw

# OR use DumpIt
DumpIt.exe /O C:\Forensics\memory.dmp

# OR use FTK Imager (GUI)
# File > Capture Memory > Save to C:\Forensics\memory.mem
```

#### Ransomware-Specific Artifacts
```powershell
# Search for Ransom Notes
Get-ChildItem C:\ -Recurse -Include "*README*","*DECRYPT*","*HOW_TO*","*RECOVER*" -ErrorAction SilentlyContinue | Export-Csv C:\Forensics\ransom_notes.csv

# Encrypted File Extensions
Get-ChildItem C:\ -Recurse -Include "*.encrypted","*.locked","*.crypto","*.lockbit","*.alphv" -ErrorAction SilentlyContinue | Export-Csv C:\Forensics\encrypted_files.csv

# Suspicious Processes
Get-Process | Where-Object {$_.Path -like "*\Temp\*" -or $_.Path -like "*\AppData\*"} | Export-Csv C:\Forensics\suspicious_processes.csv
```

### Chain of Custody Documentation

**CRITICAL FOR LEGAL/INSURANCE CLAIMS**

```yaml
chain_of_custody:
  case_number: "${case_id}"
  incident_type: "Ransomware Attack"
  evidence_custodian: "${analyst_name}"
  collection_date: "${timestamp}"

  evidence_items:
    - item_id: "EVIDENCE-001"
      description: "Disk image of infected host ${hostname}"
      hash_sha256: "${hash}"
      collection_method: "FTK Imager 4.7"
      storage_location: "Forensic NAS - /cases/${case_id}/disk_images/"
      access_log: []

    - item_id: "EVIDENCE-002"
      description: "Memory dump of ${hostname}"
      hash_sha256: "${hash}"
      collection_method: "Winpmem 4.0"
      storage_location: "Forensic NAS - /cases/${case_id}/memory/"
      access_log: []

    - item_id: "EVIDENCE-003"
      description: "Windows Event Logs (Security, System, Application, Sysmon)"
      hash_sha256: "${hash}"
      collection_method: "wevtutil export"
      storage_location: "Forensic NAS - /cases/${case_id}/logs/"
      access_log: []

    - item_id: "EVIDENCE-004"
      description: "Network traffic capture (PCAP)"
      hash_sha256: "${hash}"
      collection_method: "Wireshark/tcpdump"
      storage_location: "Forensic NAS - /cases/${case_id}/network/"
      access_log: []

    - item_id: "EVIDENCE-005"
      description: "Ransom note file(s)"
      hash_sha256: "${hash}"
      collection_method: "Manual copy"
      storage_location: "Forensic NAS - /cases/${case_id}/artifacts/"
      access_log: []

  custody_transfer:
    - date: "${timestamp}"
      from: "SOC Analyst"
      to: "Forensic Investigator"
      reason: "Deep-dive analysis"
      signature: ""

    - date: "${timestamp}"
      from: "Forensic Investigator"
      to: "Law Enforcement (FBI)"
      reason: "Criminal investigation"
      signature: ""

  integrity_verification:
    - timestamp: "${timestamp}"
      verifier: "${analyst_name}"
      method: "SHA-256 hash verification"
      result: "PASS|FAIL"
      notes: ""

  retention_policy:
    minimum_retention: "7 years (regulatory requirement)"
    destruction_date: "YYYY-MM-DD"
    destruction_method: "DoD 5220.22-M (3-pass wipe)"
    authorized_by: "Legal Counsel"
```

---

## Response Plan

### IMMEDIATE CONTAINMENT (Emergency Fast-Path Approval)

**Default Recommendation: ISOLATE AFFECTED HOSTS IMMEDIATELY**

```yaml
action: isolate_host
target: ${agent_id}
risk_level: medium
business_impact: "Service disruption - ${hostname} offline"
security_impact: "Prevent ransomware spread, protect infrastructure"
priority: immediate
approval_type: emergency_fast_path
approval_timeout: 5m  # Expedited approval window
fallback: auto_escalate_to_security_lead

justification: |
  CRITICAL: Ransomware detected on ${hostname}
  - Encryption rate: ${encryption_rate}/min
  - Files affected: ${file_count}
  - Lateral movement risk: ${movement_risk}
  - Time is critical - encryption accelerating

  ISOLATION REQUIRED to prevent:
  - Continued file encryption
  - Network propagation
  - Backup system compromise
  - Domain-wide outbreak
```

#### Expedited Approval Process (5min SLA)

```yaml
approval_workflow:
  tier_1_auto_approve:
    conditions:
      - confidence_score: >=95
      - single_host: true
      - non_critical_asset: true
      - business_hours: true
    action: auto_isolate
    notification: slack_alert

  tier_2_rapid_approval:
    conditions:
      - confidence_score: >=90
      - affected_hosts: <=3
      - critical_asset: false
    approvers: ["security_lead", "soc_manager"]
    timeout: 5m
    fallback: auto_escalate

  tier_3_emergency_escalation:
    conditions:
      - critical_infrastructure: true
      - domain_controller: true
      - backup_system: true
      - affected_hosts: >3
    approvers: ["ciso", "incident_commander", "cto"]
    timeout: 2m
    fallback: exec_emergency_protocol
    parallel_notify: ["ceo", "legal_counsel", "crisis_team"]
```

#### Escalation if No Response

```yaml
escalation_ladder:
  0_minutes:
    - slack_alert: "#soc-critical"
    - pagerduty_page: "on_call_analyst"

  3_minutes:
    - slack_mention: "@security-lead @soc-manager"
    - email_alert: "security-leadership@company.com"

  5_minutes:
    - pagerduty_page: "incident_commander"
    - sms_alert: "ciso_mobile"
    - voice_call: "security_hotline"

  7_minutes:
    - exec_alert: ["ciso", "cto"]
    - auto_execute_if:
        confidence: >=95
        policy: "pre_authorized_isolation"

  10_minutes:
    - crisis_team_activation
    - business_continuity_plan_trigger
```

### Secondary Actions

#### 1. Network-Level Blocking
```yaml
action: block_c2_communication
targets:
  - type: ip_address
    list: ${suspicious_ips}
    risk: low
    justification: "Block ransomware C2 channels"

  - type: domain
    list: ${malicious_domains}
    risk: low
    justification: "DNS sinkhole for C2 domains"

  - type: url
    list: ${exfiltration_urls}
    risk: low
    justification: "Prevent data exfiltration"

implementation:
  firewall_rule: "DENY ALL from ${internal_network} to ${malicious_ips}"
  dns_blackhole: "Route ${malicious_domains} to 0.0.0.0"
  proxy_block: "Block HTTPS to ${threat_intel_indicators}"
```

#### 2. Account Lockdown
```yaml
action: disable_compromised_accounts
targets: ${compromised_user_accounts}
risk: medium
justification: "Prevent lateral movement via compromised credentials"

implementation:
  ad_disable: "Disable-ADAccount -Identity ${username}"
  revoke_sessions: "Revoke all active sessions for ${username}"
  reset_password: "Force password reset on next login"
  notify_user: "Send security incident notification"
```

#### 3. Evidence Preservation (Read-Only - No Approval Required)
```yaml
evidence_collection:
  - action: capture_running_processes
    command: "Get-Process | Export-Csv"
    storage: "forensic_share"
    priority: critical

  - action: record_network_connections
    command: "netstat -anob"
    storage: "forensic_share"
    priority: critical

  - action: document_encrypted_files
    command: "Get-ChildItem -Recurse *.encrypted"
    storage: "forensic_share"
    priority: high

  - action: request_memory_dump
    method: "winpmem|dumpit|avml"
    approval: "forensic_team"
    priority: critical
    note: "CRITICAL for encryption key recovery"

  - action: export_event_logs
    logs: ["Security", "System", "Application", "Sysmon"]
    storage: "forensic_share"
    priority: high

  - action: capture_vss_state
    command: "vssadmin list shadows"
    storage: "forensic_share"
    priority: critical
```

---

## Evidence Collection and Analysis

### Critical Evidence (Time-Sensitive - <30min Collection SLA)

| Source | Priority | Wazuh Query | Retention |
|--------|----------|-------------|-----------|
| **FIM Alerts** | CRITICAL | `rule.groups:fim AND agent.id:${id} AND rule.level:>=7` | 90 days |
| **Process Events** | CRITICAL | `rule.groups:sysmon AND event.id:(1 OR 11 OR 23) AND agent.id:${id}` | 90 days |
| **Network Connections** | HIGH | `data.srcip:${host_ip} AND (rule.groups:firewall OR rule.groups:sysmon)` | 60 days |
| **Authentication** | HIGH | `event.id:(4624 OR 4625 OR 4648) AND agent.id:${id}` | 90 days |
| **Service Changes** | MEDIUM | `event.id:(7034 OR 7035 OR 7040) AND agent.id:${id}` | 60 days |
| **VSS Events** | CRITICAL | `event.id:8222 OR data.process.name:vssadmin.exe` | 90 days |
| **Scheduled Tasks** | MEDIUM | `event.id:(4698 OR 4699 OR 4700 OR 4701)` | 60 days |

### Evidence Pack Structure

```json
{
  "case_metadata": {
    "case_id": "INC-2026-XXXXX",
    "created_timestamp": "2026-02-17T14:23:45Z",
    "analyst": "analyst@company.com",
    "classification": "TLP:RED",
    "incident_type": "ransomware"
  },

  "attack_details": {
    "attack_type": "ransomware",
    "ransomware_family": "lockbit|blackcat|clop|royal|play|akira|unknown",
    "ransomware_variant": "3.0",
    "confidence_score": 95,
    "detection_method": "wazuh_fim|sysmon|threat_intel",
    "attack_phase": "initial_access|encryption|exfiltration|complete"
  },

  "affected_assets": {
    "primary_hosts": [
      {
        "hostname": "WKS-001",
        "agent_id": "001",
        "ip_address": "10.0.1.100",
        "os": "Windows 10 Pro",
        "criticality": "standard|high|critical",
        "encryption_percentage": 75,
        "isolation_status": "isolated|monitoring|normal"
      }
    ],
    "secondary_hosts": [],
    "total_affected_count": 1,
    "critical_infrastructure_affected": false,
    "domain_controllers_affected": false,
    "backup_systems_affected": false
  },

  "encryption_analysis": {
    "encrypted_file_count": 15420,
    "encryption_rate_per_minute": 523,
    "directories_affected": ["/Users", "/Documents", "/Shared"],
    "file_extensions": [".encrypted", ".lockbit"],
    "encryption_algorithm": "AES-256",
    "ransom_note_files": ["Restore-My-Files.txt"],
    "estimated_data_loss_gb": 342.5,
    "encryption_start_time": "2026-02-17T14:15:00Z",
    "encryption_detection_time": "2026-02-17T14:16:32Z",
    "time_to_detection_seconds": 92
  },

  "threat_indicators": {
    "c2_addresses": ["185.220.101.45:443", "tor://xyz123.onion"],
    "malicious_processes": [
      {
        "name": "svch0st.exe",
        "pid": 4532,
        "path": "C:\\Users\\Public\\AppData\\svch0st.exe",
        "hash_sha256": "a3f4b2...",
        "parent_process": "explorer.exe",
        "command_line": "svch0st.exe -encrypt -fast"
      }
    ],
    "initial_infection_vector": "phishing_email|rdp_brute_force|vpn_exploit|supply_chain",
    "lateral_movement_detected": false,
    "compromised_accounts": ["user@company.com"],
    "persistence_mechanisms": ["scheduled_task", "registry_run_key"]
  },

  "exfiltration_analysis": {
    "exfiltration_detected": true,
    "double_extortion_confirmed": true,
    "data_volume_exfiltrated_gb": 45.2,
    "exfiltration_destinations": ["mega.nz", "185.220.101.45"],
    "exfiltration_start_time": "2026-02-17T13:45:00Z",
    "exfiltration_duration_minutes": 28,
    "data_types": ["documents", "databases", "source_code", "customer_data"]
  },

  "backup_status": {
    "vss_status": "deleted",
    "vss_deletion_time": "2026-02-17T14:14:30Z",
    "backup_systems_accessible": true,
    "last_clean_backup": "2026-02-16T02:00:00Z",
    "backup_integrity": "verified|suspected_compromise|unknown",
    "offline_backups_available": true,
    "estimated_recovery_time_hours": 24
  },

  "forensic_artifacts": {
    "memory_dump_collected": true,
    "disk_image_collected": false,
    "event_logs_collected": true,
    "network_capture_available": true,
    "ransom_note_content": "Your files have been encrypted...",
    "encryption_key_recovered": false,
    "timeline_file": "/forensics/timeline.csv",
    "artifact_hashes": {
      "memory_dump": "sha256:...",
      "event_logs": "sha256:...",
      "ransom_note": "sha256:..."
    }
  },

  "response_timeline": {
    "detection_time": "2026-02-17T14:16:32Z",
    "alert_generation_time": "2026-02-17T14:16:35Z",
    "analyst_acknowledgment_time": "2026-02-17T14:17:10Z",
    "isolation_approval_time": "2026-02-17T14:19:45Z",
    "isolation_execution_time": "2026-02-17T14:20:12Z",
    "time_to_detect_seconds": 92,
    "time_to_isolate_seconds": 340,
    "sla_compliance": {
      "detection_sla_met": true,
      "isolation_sla_met": false,
      "scope_assessment_sla_met": true
    }
  },

  "business_impact": {
    "affected_business_units": ["Finance", "HR"],
    "estimated_downtime_hours": 48,
    "estimated_financial_impact_usd": 2500000,
    "customer_impact": "minimal|moderate|severe",
    "regulatory_impact": "gdpr_breach|pci_incident|hipaa_violation|none",
    "reputation_impact": "low|medium|high|critical"
  }
}
```

---

## Communication Templates

### 1. Board/C-Suite Notification (CRITICAL)

```
TO: Board of Directors, CEO, CFO, General Counsel
FROM: CISO
SUBJECT: CRITICAL: Ransomware Incident - Immediate Notification
CLASSIFICATION: CONFIDENTIAL - ATTORNEY-CLIENT PRIVILEGE

DATE: ${date}
INCIDENT ID: ${case_id}

EXECUTIVE SUMMARY:
Our organization has experienced a confirmed ransomware attack affecting [X] systems.
The Security Operations Center detected the incident at ${detection_time} and initiated
emergency response procedures.

CURRENT STATUS:
- Affected Systems: ${affected_count} hosts (${critical_count} critical)
- Business Impact: ${impact_summary}
- Containment Status: ${containment_status}
- Data Breach: ${exfiltration_confirmed ? "CONFIRMED - Regulatory notifications required" : "Not detected"}

IMMEDIATE ACTIONS TAKEN:
1. Isolated affected systems (${isolation_time})
2. Activated Incident Response Team
3. Engaged external forensics firm (${vendor})
4. Notified cyber insurance carrier (${carrier})
5. Preserved evidence for law enforcement

FINANCIAL IMPACT (PRELIMINARY):
- Estimated downtime cost: $${downtime_cost}/day
- Recovery costs: $${recovery_estimate}
- Ransom demand: $${ransom_amount} (PAYMENT NOT RECOMMENDED)
- Insurance coverage: $${coverage_amount}

REGULATORY OBLIGATIONS:
${if exfiltration_confirmed}
- SEC 8-K Filing: Required within 4 business days
- GDPR Notification: Required within 72 hours (if EU data affected)
- State Breach Laws: Notification required (${states})
- Customer Notification: ${customer_count} affected individuals
${endif}

NEXT STEPS:
1. Forensic investigation (${vendor}) - Ongoing
2. Business continuity plan activation
3. Legal review of notification requirements
4. Media/PR strategy (if required)
5. Recovery planning - ETA ${recovery_eta}

BOARD ACTION REQUIRED:
- Approve crisis management budget: $${crisis_budget}
- Authorize legal counsel engagement
- Approve communication strategy
- Consider cyber insurance claim activation

CONFERENCE CALL SCHEDULED:
Date/Time: ${call_time}
Dial-in: ${conference_bridge}

This communication is confidential and protected by attorney-client privilege.

${ciso_name}
Chief Information Security Officer
${contact_info}
```

### 2. Legal Counsel Alert

```
TO: General Counsel, Outside Counsel (${law_firm})
FROM: CISO
SUBJECT: URGENT: Ransomware Incident - Legal Review Required
CLASSIFICATION: ATTORNEY-CLIENT PRIVILEGED

INCIDENT SUMMARY:
Case ID: ${case_id}
Detection Time: ${detection_time}
Incident Type: Ransomware Attack (${family})

LEGAL ISSUES REQUIRING IMMEDIATE ATTENTION:

1. DATA BREACH NOTIFICATION REQUIREMENTS
   ${if exfiltration_confirmed}
   - Data exfiltration CONFIRMED: ${data_volume_gb} GB
   - Data types: ${data_types}
   - Affected individuals: ${estimated_count} (preliminary)
   - Jurisdictions: ${jurisdictions}

   REGULATORY DEADLINES:
   - SEC 8-K: 4 business days (Deadline: ${sec_deadline})
   - GDPR: 72 hours (Deadline: ${gdpr_deadline})
   - State laws: Variable (California: ${ca_deadline})
   ${endif}

2. LAW ENFORCEMENT COORDINATION
   - FBI contacted: ${fbi_contacted}
   - IC3 complaint: ${ic3_filed}
   - CISA notification: ${cisa_notified}
   - Evidence preservation: Complete

3. INSURANCE CLAIM
   - Carrier: ${carrier}
   - Policy number: ${policy_number}
   - Claim opened: ${claim_time}
   - Coverage limits: $${coverage}

4. RANSOM PAYMENT CONSIDERATIONS
   - Ransom demanded: $${ransom_amount} (${cryptocurrency})
   - Payment wallet: ${wallet_address}
   - OFAC sanctions check: ${ofac_status}
   - Recommendation: DO NOT PAY (backups available)

5. LITIGATION RISK
   - Shareholder derivative action: Possible
   - Customer lawsuits: Likely if PII affected
   - Regulatory enforcement: SEC, FTC, State AGs

IMMEDIATE LEGAL TASKS:
☐ Review notification obligations (all jurisdictions)
☐ Draft breach notification letters
☐ Coordinate with outside forensics (privilege protection)
☐ Assess OFAC sanctions compliance
☐ Prepare SEC 8-K filing (if required)
☐ Engage crisis PR firm
☐ Review D&O insurance coverage

FORENSIC VENDOR (Under Attorney Direction):
${forensic_vendor}
Engagement Letter: Executed under attorney work product

CONFERENCE CALL:
${call_details}

${ciso_name}
Chief Information Security Officer
${contact}
```

### 3. Insurance Carrier Notification

```
TO: ${insurance_carrier} - Cyber Claims Department
FROM: ${company} Risk Management
SUBJECT: Cyber Insurance Claim - Ransomware Incident

CLAIM NOTIFICATION

Policy Holder: ${company_name}
Policy Number: ${policy_number}
Policy Period: ${policy_start} - ${policy_end}
Date of Incident: ${incident_date}
Date of Discovery: ${discovery_date}

INCIDENT DESCRIPTION:
Our organization experienced a ransomware attack affecting ${affected_count} systems.
The incident was detected by our Security Operations Center on ${detection_date}.

INCIDENT DETAILS:
- Attack Type: Ransomware (${family} variant)
- Affected Systems: ${system_list}
- Business Interruption: ${downtime_hours} hours (ongoing)
- Data Breach: ${exfiltration_status}
- Ransom Demand: $${ransom_amount} ${cryptocurrency}

ESTIMATED LOSSES (PRELIMINARY):
- Business Interruption: $${bi_estimate}
- Incident Response Costs: $${ir_costs}
- Forensic Investigation: $${forensic_costs}
- Legal Fees: $${legal_estimate}
- Notification Costs: $${notification_costs}
- Credit Monitoring: $${monitoring_costs}
- Public Relations: $${pr_costs}
- System Restoration: $${restoration_costs}

TOTAL ESTIMATED CLAIM: $${total_estimate}

COVERAGE REQUESTED:
☐ Incident Response Expenses
☐ Forensic Investigation
☐ Legal Defense Costs
☐ Regulatory Defense
☐ Business Interruption
☐ Data Restoration
☐ Crisis Management/PR
☐ Notification Costs
☐ Credit Monitoring
☐ Ransom Payment (if approved)
☐ Cyber Extortion

VENDORS ENGAGED:
- Forensic Firm: ${forensic_vendor}
- Legal Counsel: ${law_firm}
- PR Firm: ${pr_firm}
- Notification Vendor: ${notification_vendor}

CLAIM CONTACTS:
Primary: ${risk_manager} - ${email} - ${phone}
Secondary: ${ciso} - ${email} - ${phone}

ATTACHMENTS:
1. Incident timeline
2. Forensic preliminary report
3. Vendor engagement letters
4. Business interruption calculation

We request immediate assignment of a claims adjuster and approval for
pre-approved vendor panel engagement.

${risk_manager_name}
Chief Risk Officer
${contact}
```

### 4. Law Enforcement Notification (FBI/CISA)

```
TO: FBI Cyber Division / CISA
FROM: ${company} Security Operations Center
SUBJECT: Ransomware Incident Report - ${case_id}

INCIDENT REPORT

REPORTING ORGANIZATION:
Company Name: ${company}
Industry: ${industry_sector}
Location: ${headquarters}
DUNS Number: ${duns}
Point of Contact: ${ciso} - ${email} - ${phone}

INCIDENT SUMMARY:
Date/Time of Incident: ${incident_date} ${incident_time} ${timezone}
Date/Time of Detection: ${detection_date} ${detection_time} ${timezone}
Incident Type: Ransomware Attack

TECHNICAL DETAILS:
Ransomware Family: ${family} (${variant})
Initial Infection Vector: ${infection_vector}
Affected Systems: ${affected_count}
Operating Systems: ${os_list}
Data Encrypted: ${encrypted_data_tb} TB
Data Exfiltrated: ${exfil_confirmed} (${exfil_data_gb} GB)

THREAT ACTOR INFORMATION:
Ransom Demand: $${ransom_usd} (${crypto_amount} ${cryptocurrency})
Payment Wallet: ${wallet_address}
Payment Deadline: ${payment_deadline}
Tor Site: ${tor_site}
Email Contact: ${threat_actor_email}
Negotiation Status: ${negotiation_status}

INDICATORS OF COMPROMISE:
IP Addresses: ${c2_ips}
Domains: ${c2_domains}
File Hashes (SHA-256): ${file_hashes}
Ransom Note Filename: ${ransom_note}
Encryption Extension: ${file_extension}

NETWORK INDICATORS:
C2 Communication: ${c2_communication}
Exfiltration Destination: ${exfil_destination}
Lateral Movement: ${lateral_movement}

EVIDENCE PRESERVATION:
☑ Memory dumps collected
☑ Disk images created
☑ Network traffic captured
☑ Event logs preserved
☑ Ransom communication saved

BUSINESS IMPACT:
Critical Infrastructure Affected: ${critical_infrastructure}
Operational Impact: ${operational_impact}
Estimated Financial Loss: $${financial_loss}
Customer Impact: ${customer_count} potentially affected

ASSISTANCE REQUESTED:
☐ Threat intelligence on ransomware family
☐ Attribution information
☐ Decryption tool availability
☐ C2 infrastructure takedown coordination
☐ Threat actor identification

PREFERRED CONTACT METHOD:
Email: ${contact_email}
Phone: ${contact_phone}
Secure Portal: ${portal_url}

IC3 COMPLAINT ID: ${ic3_id}
CISA REPORT ID: ${cisa_id}

${ciso_name}
Chief Information Security Officer
${company}
${contact_info}

ATTACHMENTS:
- Technical incident report
- IOC list (STIX format)
- Ransom note (sanitized)
- Network diagram
```

### 5. Affected Party Notification Template (GDPR/CCPA Compliant)

```
[COMPANY LETTERHEAD]

${date}

${recipient_name}
${recipient_address}

Re: Notice of Data Security Incident

Dear ${recipient_name},

We are writing to inform you of a data security incident that may have affected
your personal information. At ${company}, we take the security of your information
very seriously, and we are providing you with information about the incident, our
response, and steps you can take to protect yourself.

WHAT HAPPENED
On ${incident_date}, our Security Operations Center detected a ransomware attack
on our systems. We immediately activated our incident response procedures, isolated
affected systems, and engaged leading cybersecurity forensic experts to investigate.

WHAT INFORMATION WAS INVOLVED
Our investigation determined that the following types of information may have been
affected:
${affected_data_types}

The investigation is ongoing, and we will provide updates as more information becomes
available.

WHAT WE ARE DOING
We have taken the following steps:
• Isolated affected systems to prevent further unauthorized access
• Engaged leading cybersecurity forensic firm ${vendor} to investigate
• Notified law enforcement (FBI, CISA)
• Implemented enhanced security monitoring
• Notified relevant regulatory authorities
• ${if credit_monitoring}Arranged for complimentary credit monitoring services${endif}

WHAT YOU CAN DO
We recommend you take the following precautions:
• Monitor your financial account statements for suspicious activity
• Place a fraud alert or security freeze on your credit files
• Review your credit reports for unauthorized accounts or inquiries
• Be alert for phishing emails or phone calls requesting personal information
• ${if credit_monitoring}Enroll in the complimentary credit monitoring (details below)${endif}

CREDIT MONITORING SERVICES (Complimentary for ${monitoring_duration})
We are offering ${monitoring_duration} of complimentary credit monitoring and
identity theft protection services through ${monitoring_vendor}.

Enrollment Deadline: ${enrollment_deadline}
Enrollment Code: ${enrollment_code}
Enrollment Instructions: ${enrollment_url}

FOR MORE INFORMATION
We have established a dedicated call center to answer questions:

Toll-Free Number: ${hotline_number}
Hours: Monday-Friday, 9:00 AM - 9:00 PM ${timezone}
Website: ${incident_website}

We sincerely apologize for this incident and any concern it may cause. Protecting
your information is our top priority.

Sincerely,

${ciso_name}
Chief Information Security Officer
${company}

---
ADDITIONAL RESOURCES

Credit Bureau Contact Information:
• Equifax: 1-800-525-6285 / www.equifax.com
• Experian: 1-888-397-3742 / www.experian.com
• TransUnion: 1-800-680-7289 / www.transunion.com

Fraud Alert: Contact any one credit bureau to place a fraud alert (90 days, free)

Security Freeze: Contact all three bureaus to freeze your credit (free)

Federal Trade Commission:
• Identity Theft Hotline: 1-877-ID-THEFT (438-4338)
• Website: www.identitytheft.gov

State Attorney General: ${state_ag_contact}

${if european_residents}
Data Protection Authority: ${dpa_contact}
GDPR Rights: You have the right to access, rectify, erase, restrict processing,
data portability, and object to processing of your personal data.
${endif}
```

---

## Regulatory Compliance

### NIST Cybersecurity Framework Alignment

| Function | Category | Subcategory | Ransomware Controls |
|----------|----------|-------------|---------------------|
| **IDENTIFY** | Asset Management (ID.AM) | ID.AM-1, ID.AM-2 | Asset inventory, criticality scoring |
| | Risk Assessment (ID.RA) | ID.RA-1, ID.RA-3 | Ransomware threat modeling, vulnerability assessment |
| **PROTECT** | Access Control (PR.AC) | PR.AC-3, PR.AC-4, PR.AC-5 | MFA, least privilege, network segmentation |
| | Data Security (PR.DS) | PR.DS-1, PR.DS-6 | Data-at-rest encryption, integrity checking |
| | Protective Technology (PR.PT) | PR.PT-1, PR.PT-3 | FIM, application whitelisting, EDR |
| **DETECT** | Anomalies & Events (DE.AE) | DE.AE-1, DE.AE-2, DE.AE-3 | Wazuh SIEM, behavioral analytics, correlation |
| | Continuous Monitoring (DE.CM) | DE.CM-1, DE.CM-4, DE.CM-7 | Network monitoring, malware detection, process monitoring |
| **RESPOND** | Response Planning (RS.RP) | RS.RP-1 | Ransomware playbook (this document) |
| | Communications (RS.CO) | RS.CO-2, RS.CO-3, RS.CO-4 | Stakeholder notification, coordination |
| | Analysis (RS.AN) | RS.AN-1, RS.AN-2, RS.AN-3 | Forensic analysis, impact assessment, timeline |
| | Mitigation (RS.MI) | RS.MI-1, RS.MI-2, RS.MI-3 | Incident containment, isolation, eradication |
| **RECOVER** | Recovery Planning (RC.RP) | RC.RP-1 | Disaster recovery, backup restoration |
| | Improvements (RC.IM) | RC.IM-1, RC.IM-2 | Lessons learned, playbook updates |

### CISA Ransomware Guidance Compliance

| CISA Recommendation | Implementation Status | Notes |
|---------------------|----------------------|-------|
| **Maintain offline backups** | ✅ Implemented | 3-2-1 backup strategy, offline/immutable copies |
| **Enable multi-factor authentication** | ✅ Implemented | MFA required for VPN, admin access, email |
| **Patch known exploited vulnerabilities** | ✅ Implemented | CISA KEV catalog monitoring, 48hr patch SLA |
| **Train users to recognize phishing** | ✅ Implemented | Quarterly training, simulated phishing campaigns |
| **Implement application whitelisting** | ⚠️ Partial | Deployed on critical servers, rollout in progress |
| **Disable unused remote access** | ✅ Implemented | RDP disabled, VPN w/ MFA only |
| **Segment networks** | ✅ Implemented | Production/corporate/OT segmentation, micro-segmentation |
| **Install EDR on all endpoints** | ✅ Implemented | EDR deployed enterprise-wide |
| **Review security logs** | ✅ Implemented | Wazuh SIEM, 24/7 SOC monitoring |
| **Implement least privilege** | ✅ Implemented | Privileged Access Management (PAM), JIT access |

### SEC Cybersecurity Disclosure Requirements (17 CFR 229.106)

**Applicable to Public Companies**

| Requirement | Deadline | Ransomware Response |
|-------------|----------|---------------------|
| **Material Incident Disclosure** | 4 business days | Assess materiality with CFO, Legal, Board |
| **Form 8-K Item 1.05** | 4 business days | File if material cybersecurity incident |
| **Periodic Disclosure (10-K/10-Q)** | Quarterly/Annual | Update cybersecurity risk management, governance |
| **Materiality Determination** | Immediate | Consider: business impact, customer data, operational disruption, financial loss |

**Materiality Factors for Ransomware:**
- Revenue impact >1% quarterly revenue
- Critical infrastructure offline >24 hours
- Customer PII breach >100,000 records
- Regulatory enforcement action likely
- Ransom payment >$1M
- Material financial impact on operations

### GDPR Compliance (EU Data Subjects)

| Requirement | Deadline | Implementation |
|-------------|----------|----------------|
| **Breach Notification to DPA** | 72 hours | Auto-notification if EU data confirmed affected |
| **Individual Notification** | Without undue delay | Notification template (see above) |
| **Breach Documentation** | Ongoing | Case management system, evidence pack |
| **DPO Involvement** | Immediate | DPO notified on all incidents |
| **Art. 33 Requirements** | 72 hours | Nature of breach, categories of data, consequences, measures taken |
| **Art. 34 Requirements** | Immediate | Individual notification if "high risk" |

**GDPR Breach Record:**
```yaml
gdpr_breach_record:
  breach_reference: "${case_id}"
  date_of_breach: "${incident_date}"
  date_of_detection: "${detection_date}"
  nature_of_breach: "Ransomware attack with potential data exfiltration"
  categories_of_data: ["name", "email", "address", "financial_data"]
  categories_of_data_subjects: ["customers", "employees"]
  approximate_number: ${affected_count}
  consequences: "Potential unauthorized access to personal data, risk of identity theft"
  measures_taken: "Isolation, forensic investigation, law enforcement notification, individual notification, credit monitoring"
  dpa_notification_date: "${dpa_notification_date}"
  dpa_reference: "${dpa_reference_number}"
```

### State Breach Notification Laws (US)

| State | Notification Trigger | Deadline | Special Requirements |
|-------|---------------------|----------|----------------------|
| **California (CCPA)** | Unencrypted PI | Without unreasonable delay | AG notification if >500 residents |
| **New York (SHIELD Act)** | PI breach | Without unreasonable delay | AG and DFS notification |
| **Massachusetts (201 CMR 17)** | PI breach | As soon as practicable | AG notification |
| **All 50 States** | Varies by state | Varies (immediate to 90 days) | Multi-state notification coordination |

---

## Recovery Procedures

### Phase 1: Containment Verification (0-2 hours)

```yaml
containment_checklist:
  network_isolation:
    ☐ verify_host_isolation_effective
    ☐ confirm_no_outbound_connections
    ☐ verify_firewall_rules_applied
    ☐ check_vlan_isolation

  threat_elimination:
    ☐ confirm_malicious_processes_terminated
    ☐ verify_no_persistence_mechanisms
    ☐ check_scheduled_tasks_removed
    ☐ validate_registry_cleanup

  lateral_movement_prevention:
    ☐ disable_compromised_accounts
    ☐ reset_domain_admin_passwords
    ☐ verify_no_additional_infections
    ☐ monitor_network_for_suspicious_activity

  backup_protection:
    ☐ verify_backup_systems_isolated
    ☐ confirm_backup_integrity
    ☐ protect_offline_backups
    ☐ document_last_clean_backup_timestamp
```

### Phase 2: Forensic Analysis (2-24 hours)

```yaml
forensic_investigation:
  scope_determination:
    ☐ identify_patient_zero
    ☐ map_lateral_movement_path
    ☐ determine_initial_access_vector
    ☐ identify_all_compromised_systems
    ☐ assess_data_exfiltration_scope

  evidence_collection:
    ☐ memory_dumps_all_affected_hosts
    ☐ disk_images_critical_systems
    ☐ event_log_consolidation
    ☐ network_traffic_analysis
    ☐ malware_sample_extraction

  malware_analysis:
    ☐ reverse_engineer_ransomware_binary
    ☐ identify_encryption_algorithm
    ☐ search_for_decryption_tools
    ☐ check_nomoreransom_org
    ☐ analyze_c2_communication

  timeline_reconstruction:
    ☐ initial_compromise_timestamp
    ☐ reconnaissance_activities
    ☐ credential_theft_timeline
    ☐ lateral_movement_map
    ☐ exfiltration_timeline
    ☐ encryption_start_time
```

### Phase 3: Eradication (24-48 hours)

```yaml
eradication_plan:
  threat_removal:
    ☐ remove_all_malware_artifacts
    ☐ delete_ransomware_binaries
    ☐ remove_persistence_mechanisms
    ☐ clean_scheduled_tasks
    ☐ sanitize_registry_keys

  credential_reset:
    ☐ reset_all_privileged_account_passwords
    ☐ reset_compromised_user_passwords
    ☐ revoke_active_sessions
    ☐ rotate_service_account_passwords
    ☐ regenerate_kerberos_krbtgt (twice, 24hr apart)

  vulnerability_remediation:
    ☐ patch_exploited_vulnerabilities
    ☐ close_initial_access_vector
    ☐ harden_remote_access
    ☐ implement_additional_controls
    ☐ update_firewall_rules
```

### Phase 4: Recovery (48-72 hours)

#### Clean Rebuild from Gold Images (RECOMMENDED)

```yaml
rebuild_procedure:
  priority_1_critical_infrastructure:
    order: 1
    systems:
      - domain_controllers
      - dns_servers
      - dhcp_servers
      - active_directory
    method: rebuild_from_gold_image
    validation: full_security_scan
    timeline: 0-12 hours

  priority_2_business_critical:
    order: 2
    systems:
      - email_servers_exchange
      - database_servers_sql
      - file_servers
      - erp_systems_sap
      - crm_salesforce
    method: rebuild_from_gold_image
    validation: integrity_check + security_scan
    timeline: 12-36 hours

  priority_3_standard_systems:
    order: 3
    systems:
      - workstations
      - application_servers
      - web_servers
      - non_critical_infrastructure
    method: rebuild_from_gold_image_or_restore
    validation: antivirus_scan + vulnerability_scan
    timeline: 36-72 hours
```

**Gold Image Requirements:**
```yaml
gold_image_standards:
  validation:
    - last_updated: within_30_days
    - fully_patched: true
    - security_hardened: true
    - malware_free: verified
    - hash_verified: sha256_checksum

  storage:
    - location: offline_secure_storage
    - access_control: restricted_authorized_only
    - encryption: aes_256
    - integrity_monitoring: enabled

  documentation:
    - build_date: documented
    - patch_level: documented
    - configuration_baseline: documented
    - testing_validation: documented
```

#### Backup Integrity Verification (CRITICAL)

```yaml
backup_verification_protocol:
  step_1_identify_clean_backup:
    - identify_last_backup_before_infection
    - subtract_48_hours_safety_margin  # Ransomware may have dormant period
    - verify_backup_timestamp: "${clean_backup_date}"

  step_2_integrity_testing:
    - restore_to_isolated_test_environment
    - scan_with_multiple_av_engines:
        - windows_defender
        - clamav
        - crowdstrike
        - sophos
    - check_for_persistence_mechanisms
    - validate_no_suspicious_processes
    - verify_no_ransomware_indicators

  step_3_data_validation:
    - verify_database_integrity
    - check_file_checksums
    - validate_application_functionality
    - test_user_access
    - confirm_data_consistency

  step_4_security_scan:
    - vulnerability_scan: nessus_openvas
    - malware_scan: full_system
    - configuration_review: cis_benchmarks
    - log_analysis: suspicious_activity
```

**If Backups Compromised:**
```yaml
backup_compromise_response:
  scenario: backups_infected_or_encrypted

  options:
    option_1_older_backups:
      - identify_oldest_verified_clean_backup
      - assess_data_loss_risk
      - calculate_recovery_point_objective_rpo
      - evaluate_business_impact

    option_2_manual_data_recovery:
      - extract_unencrypted_data
      - rebuild_databases_from_transaction_logs
      - recover_from_shadow_copies_if_available
      - manual_data_entry_if_necessary

    option_3_decryption_attempt:
      - check_nomoreransom_org_for_decryptor
      - consult_with_forensic_vendor
      - attempt_decryption_on_test_system_first
      - evaluate_success_rate_before_production

    option_4_business_continuity:
      - activate_disaster_recovery_site
      - failover_to_cloud_infrastructure
      - implement_manual_workarounds
      - prioritize_critical_business_functions
```

#### Phased Restoration Plan

```yaml
restoration_phases:
  phase_1_core_infrastructure:
    duration: 0-12 hours
    systems:
      - active_directory_domain_controllers
      - dns_dhcp_infrastructure
      - network_authentication
    validation:
      - test_domain_authentication
      - verify_dns_resolution
      - confirm_gpo_application
      - security_scan_clean

  phase_2_critical_business_systems:
    duration: 12-24 hours
    systems:
      - email_servers
      - database_servers
      - file_servers
      - erp_crm_systems
    validation:
      - application_functionality_testing
      - database_integrity_checks
      - user_acceptance_testing
      - security_scan_clean
    rollback_criteria:
      - functionality_issues
      - security_concerns
      - performance_degradation

  phase_3_end_user_systems:
    duration: 24-72 hours
    systems:
      - user_workstations
      - departmental_applications
      - non_critical_servers
    validation:
      - user_login_testing
      - application_access_verification
      - data_availability_confirmation
    deployment_method: phased_rollout
      - pilot_group: 5_percent_users
      - wave_1: 25_percent_users
      - wave_2: 50_percent_users
      - wave_3: 100_percent_users
```

### Phase 5: Post-Recovery Validation (72+ hours)

```yaml
validation_checklist:
  security_validation:
    ☐ full_network_vulnerability_scan
    ☐ penetration_testing_initial_access_vector
    ☐ security_configuration_review
    ☐ edr_agent_validation_all_systems
    ☐ siem_log_ingestion_verified
    ☐ backup_integrity_ongoing_monitoring

  operational_validation:
    ☐ all_critical_systems_operational
    ☐ user_productivity_restored
    ☐ business_processes_functioning
    ☐ data_integrity_verified
    ☐ performance_baselines_met

  monitoring_enhancement:
    ☐ enhanced_fim_rules_deployed
    ☐ ransomware_specific_detections_enabled
    ☐ behavioral_analytics_tuned
    ☐ threat_hunting_queries_updated
    ☐ alert_thresholds_optimized
```

### Recovery Time Objectives (RTO) & Recovery Point Objectives (RPO)

| System Tier | RTO Target | RPO Target | Recovery Method |
|-------------|------------|------------|-----------------|
| **Tier 0 - Critical Infrastructure** | 4 hours | 15 minutes | Hot failover + Gold image |
| **Tier 1 - Business Critical** | 24 hours | 1 hour | Backup restore + Gold image |
| **Tier 2 - Important** | 72 hours | 4 hours | Backup restore |
| **Tier 3 - Standard** | 1 week | 24 hours | Backup restore or rebuild |

---

## Agent Pipeline Integration

### Emergency Fast-Path Workflow

```yaml
emergency_fast_path:
  trigger_conditions:
    - playbook_type: "ransomware"
    - severity: "critical"
    - confidence: >=90

  approval_sla: 5_minutes

  workflow:
    step_1_detection:
      - wazuh_alert_generated
      - autopilot_agent_receives_alert
      - agent_analyzes_indicators
      - confidence_score_calculated

    step_2_triage_agent:
      - entity_extraction
      - correlation_analysis
      - timeline_construction
      - severity_assessment
      - evidence_pack_generation

    step_3_response_recommendation:
      - action_recommendation: "isolate_host"
      - justification_generated
      - business_impact_analysis
      - risk_assessment

    step_4_approval_request:
      - slack_alert_channel: "#soc-critical"
      - slack_mention: "@oncall-analyst"
      - approval_buttons: ["ISOLATE NOW", "Investigate First", "Deny"]
      - approval_timeout: 5_minutes

    step_5_auto_escalation:
      - if_no_response_3min: slack_mention: "@security-lead"
      - if_no_response_5min: pagerduty_page: "incident_commander"
      - if_no_response_7min: execute_if_policy_allows

    step_6_action_execution:
      - if_approved: execute_isolation
      - if_denied: enhanced_monitoring
      - if_timeout: escalate_or_auto_execute

    step_7_verification:
      - verify_isolation_effective
      - update_case_status
      - notify_stakeholders
      - continue_investigation
```

### Multi-Agent Coordination

```yaml
agent_roles:
  detection_agent:
    responsibility: "Monitor Wazuh alerts, initial triage"
    triggers: "rule.level:>=12 AND rule.groups:ransomware"
    handoff_to: "triage_agent"

  triage_agent:
    responsibility: "Deep analysis, correlation, evidence collection"
    sla: "Complete within 5 minutes"
    handoff_to: "response_agent"

  response_agent:
    responsibility: "Action recommendation, approval request"
    sla: "Generate recommendation within 2 minutes"
    handoff_to: "approval_workflow"

  communication_agent:
    responsibility: "Stakeholder notifications, status updates"
    triggers: "Major escalation events"
    handoff_to: "incident_commander"

  forensic_agent:
    responsibility: "Evidence collection automation, timeline analysis"
    sla: "Forensic pack within 30 minutes"
    handoff_to: "forensic_team"
```

### Approval Workflow Integration

```yaml
approval_workflow:
  tier_1_low_risk:
    conditions:
      - affected_hosts: 1
      - asset_criticality: "standard"
      - confidence: >=95
    approvers: ["on_call_analyst"]
    timeout: 5_minutes
    auto_approve_if: policy_enabled

  tier_2_medium_risk:
    conditions:
      - affected_hosts: 2-3
      - asset_criticality: "high"
      - confidence: >=90
    approvers: ["security_lead", "soc_manager"]
    timeout: 5_minutes
    escalation: "incident_commander"

  tier_3_high_risk:
    conditions:
      - affected_hosts: >=4
      - asset_criticality: "critical"
      - domain_controller: true
    approvers: ["ciso", "incident_commander"]
    timeout: 2_minutes
    parallel_notify: ["cto", "ceo"]
    emergency_protocol: enabled
```

---

## Enhanced SLA & KPI Metrics

### Response SLAs (Service Level Agreements)

| Metric | Target | Acceptable | Unacceptable | Escalation |
|--------|--------|------------|--------------|------------|
| **Detection Time** | <2 min | <5 min | >10 min | SOC Lead |
| **Alert Acknowledgment** | <1 min | <3 min | >5 min | SOC Manager |
| **Initial Triage** | <5 min | <10 min | >15 min | Incident Commander |
| **Isolation Decision** | <5 min | <10 min | >15 min | CISO |
| **Isolation Execution** | <2 min | <5 min | >10 min | Technical Lead |
| **Scope Assessment** | <30 min | <1 hour | >2 hours | Incident Commander |
| **Forensic Evidence Collection** | <30 min | <1 hour | >2 hours | Forensic Lead |
| **Recovery Plan** | <2 hours | <4 hours | >8 hours | CISO |
| **C-Suite Notification** | <15 min | <30 min | >1 hour | CISO |
| **Regulatory Notification** | Per regulation | - | Missed deadline | Legal Counsel |

### Key Performance Indicators (KPIs)

```yaml
detection_kpis:
  mean_time_to_detect_mttd:
    target: 120_seconds
    measurement: "Time from encryption start to Wazuh alert"
    calculation: "avg(alert_timestamp - incident_timestamp)"

  false_positive_rate:
    target: <5_percent
    measurement: "Percentage of ransomware alerts that are false positives"
    calculation: "(false_positives / total_alerts) * 100"

  detection_coverage:
    target: 100_percent
    measurement: "Percentage of known ransomware families detected"
    calculation: "(detected_families / total_known_families) * 100"

containment_kpis:
  mean_time_to_contain_mttc:
    target: 300_seconds
    measurement: "Time from detection to isolation"
    calculation: "avg(isolation_timestamp - detection_timestamp)"

  containment_effectiveness:
    target: 100_percent
    measurement: "Percentage of incidents where spread was prevented"
    calculation: "(successful_containments / total_incidents) * 100"

  isolation_success_rate:
    target: 100_percent
    measurement: "Percentage of isolation attempts that succeeded"
    calculation: "(successful_isolations / attempted_isolations) * 100"

response_kpis:
  mean_time_to_respond_mttr:
    target: 1800_seconds
    measurement: "Time from detection to scope assessment complete"
    calculation: "avg(scope_complete_timestamp - detection_timestamp)"

  approval_sla_compliance:
    target: 95_percent
    measurement: "Percentage of approvals completed within 5min SLA"
    calculation: "(approvals_within_sla / total_approvals) * 100"

  escalation_rate:
    target: <10_percent
    measurement: "Percentage of incidents requiring escalation"
    calculation: "(escalated_incidents / total_incidents) * 100"

recovery_kpis:
  mean_time_to_recovery_mttr:
    target: 48_hours
    measurement: "Time from detection to full operational recovery"
    calculation: "avg(recovery_timestamp - detection_timestamp)"

  backup_restoration_success_rate:
    target: 100_percent
    measurement: "Percentage of successful backup restorations"
    calculation: "(successful_restores / attempted_restores) * 100"

  data_loss_percentage:
    target: 0_percent
    measurement: "Percentage of data lost due to incident"
    calculation: "(data_lost_gb / total_data_gb) * 100"

business_impact_kpis:
  financial_loss_per_incident:
    target: <$100000
    measurement: "Average cost per ransomware incident"
    calculation: "sum(incident_costs) / total_incidents"

  downtime_hours:
    target: <24_hours
    measurement: "Average downtime per incident"
    calculation: "avg(recovery_timestamp - incident_timestamp)"

  customer_impact:
    target: 0_customers
    measurement: "Number of customers affected by incidents"
    calculation: "sum(affected_customers)"
```

### SLA Monitoring & Reporting

```yaml
sla_monitoring:
  real_time_dashboard:
    metrics:
      - detection_time_current_incident
      - time_to_isolation_countdown
      - sla_compliance_status
      - escalation_status
    alerts:
      - sla_at_risk: 80_percent_of_time_elapsed
      - sla_breach: 100_percent_of_time_elapsed
      - critical_delay: manual_intervention_required

  weekly_reporting:
    report_to: ["soc_manager", "security_lead"]
    metrics:
      - average_detection_time
      - average_containment_time
      - sla_compliance_percentage
      - false_positive_rate
      - incident_count

  monthly_executive_report:
    report_to: ["ciso", "cto", "board"]
    metrics:
      - total_incidents
      - total_financial_impact
      - average_recovery_time
      - sla_compliance_trends
      - year_over_year_comparison
      - security_posture_improvements
```

---

## Post-Incident Activities

### Lessons Learned (MANDATORY - Within 72 hours)

```yaml
lessons_learned_meeting:
  attendees:
    required:
      - incident_commander
      - soc_analysts_involved
      - forensic_investigator
      - it_operations
      - affected_business_units
    optional:
      - ciso
      - legal_counsel
      - third_party_vendors

  agenda:
    1_incident_timeline_review:
      - initial_compromise
      - detection_point
      - containment_actions
      - recovery_completion

    2_what_went_well:
      - effective_detections
      - successful_containment
      - good_communication
      - helpful_tools_processes

    3_what_needs_improvement:
      - detection_gaps
      - response_delays
      - communication_breakdowns
      - tool_limitations

    4_action_items:
      - detection_rule_improvements
      - playbook_updates
      - training_needs
      - tool_enhancements
      - policy_changes

  deliverables:
    - lessons_learned_report
    - action_item_tracker
    - playbook_update_recommendations
    - training_plan
```

### Continuous Improvement

```yaml
improvement_tracking:
  detection_enhancements:
    ☐ update_wazuh_rules_based_on_new_iocs
    ☐ add_ransomware_family_signatures
    ☐ tune_alert_thresholds_reduce_fps
    ☐ implement_behavioral_analytics
    ☐ enhance_correlation_rules

  response_optimization:
    ☐ update_playbook_based_on_lessons_learned
    ☐ automate_additional_response_actions
    ☐ improve_approval_workflow
    ☐ enhance_communication_templates
    ☐ update_escalation_procedures

  recovery_improvements:
    ☐ test_backup_restoration_procedures
    ☐ update_gold_images
    ☐ improve_rto_rpo_targets
    ☐ enhance_business_continuity_plans
    ☐ conduct_disaster_recovery_drills

  training_and_awareness:
    ☐ conduct_tabletop_exercise_ransomware
    ☐ update_user_awareness_training
    ☐ train_soc_on_new_techniques
    ☐ cross_train_response_teams
    ☐ document_new_procedures
```

---

## Do NOT Do (Critical - READ CAREFULLY)

### NEVER Take These Actions Without Explicit Authorization

```yaml
prohibited_actions:
  ransom_payment:
    action: "Pay ransom to threat actors"
    prohibition: "NEVER pay without executive + legal + board approval"
    reasons:
      - "No guarantee of decryption"
      - "Funds terrorism/criminal organizations"
      - "OFAC sanctions violations possible"
      - "Encourages future attacks"
      - "May violate corporate policy/insurance terms"
    approval_required: ["ceo", "board", "legal_counsel", "ciso"]

  unsanctioned_decryption:
    action: "Attempt decryption without forensic analysis"
    prohibition: "NEVER decrypt without understanding the ransomware"
    reasons:
      - "May destroy evidence"
      - "May trigger data wiper"
      - "May cause data corruption"
      - "Forensic investigation compromised"
    approval_required: ["forensic_lead", "incident_commander"]

  infected_backup_restoration:
    action: "Restore from potentially infected backups"
    prohibition: "NEVER restore without integrity verification"
    reasons:
      - "Re-infection risk"
      - "Persistence mechanism restoration"
      - "Wasted recovery effort"
      - "Extended downtime"
    approval_required: ["backup_administrator", "security_lead"]

  premature_system_restore:
    action: "Bring systems online before eradication complete"
    prohibition: "NEVER restore services before threat eliminated"
    reasons:
      - "Re-encryption risk"
      - "Lateral movement continuation"
      - "Incomplete forensic investigation"
      - "Regulatory compliance issues"
    approval_required: ["incident_commander", "security_lead"]

  unauthorized_external_communication:
    action: "Communicate with media/customers/partners without approval"
    prohibition: "NEVER communicate externally without legal/PR approval"
    reasons:
      - "Regulatory notification requirements"
      - "Legal liability"
      - "Reputation management"
      - "Coordinated disclosure strategy"
    approval_required: ["legal_counsel", "pr_team", "ciso"]

  evidence_destruction:
    action: "Delete logs, wipe systems, or destroy evidence"
    prohibition: "NEVER destroy evidence - legal/regulatory requirement"
    reasons:
      - "Criminal investigation obstruction"
      - "Insurance claim denial"
      - "Regulatory penalties"
      - "Civil litigation liability"
    approval_required: ["legal_counsel", "forensic_team"]

  solo_decision_making:
    action: "Make critical decisions without consultation"
    prohibition: "NEVER act alone on critical decisions"
    reasons:
      - "Business impact assessment needed"
      - "Legal implications"
      - "Financial consequences"
      - "Regulatory compliance"
    approval_required: ["incident_commander", "ciso", "legal"]
```

---

## Tools & Resources

### Detection & Analysis Tools

```yaml
detection_tools:
  - name: "Wazuh SIEM"
    purpose: "Primary detection platform"
    url: "https://wazuh.com"

  - name: "Sysmon"
    purpose: "Windows process monitoring"
    url: "https://docs.microsoft.com/sysinternals/sysmon"

  - name: "YARA Rules"
    purpose: "Malware signature detection"
    url: "https://github.com/Yara-Rules/rules"

  - name: "Sigma Rules"
    purpose: "Generic SIEM detection rules"
    url: "https://github.com/SigmaHQ/sigma"

forensic_tools:
  - name: "Eric Zimmerman Tools"
    purpose: "Windows forensic artifact analysis"
    tools: ["PECmd", "MFTECmd", "AmcacheParser", "JLECmd"]
    url: "https://ericzimmerman.github.io"

  - name: "Volatility"
    purpose: "Memory forensics"
    url: "https://www.volatilityfoundation.org"

  - name: "FTK Imager"
    purpose: "Disk imaging and memory capture"
    url: "https://www.exterro.com/ftk-imager"

  - name: "Wireshark"
    purpose: "Network traffic analysis"
    url: "https://www.wireshark.org"

  - name: "KAPE"
    purpose: "Forensic artifact collection"
    url: "https://www.kroll.com/kape"

decryption_resources:
  - name: "No More Ransom"
    purpose: "Free decryption tools"
    url: "https://www.nomoreransom.org"

  - name: "Emsisoft Decryptor Tools"
    purpose: "Ransomware decryptors"
    url: "https://www.emsisoft.com/ransomware-decryption-tools"

  - name: "Kaspersky Decryptors"
    purpose: "Ransomware decryptors"
    url: "https://noransom.kaspersky.com"
```

### Threat Intelligence

```yaml
threat_intel_feeds:
  - name: "Ransomware Tracker (Abuse.ch)"
    purpose: "Ransomware C2 IOCs"
    url: "https://ransomwaretracker.abuse.ch"

  - name: "MalwareBazaar"
    purpose: "Malware sample database"
    url: "https://bazaar.abuse.ch"

  - name: "VirusTotal"
    purpose: "File/URL/IP reputation"
    url: "https://www.virustotal.com"

  - name: "AlienVault OTX"
    purpose: "Community threat intelligence"
    url: "https://otx.alienvault.com"

  - name: "MISP"
    purpose: "Threat intelligence sharing platform"
    url: "https://www.misp-project.org"
```

### Regulatory & Guidance

```yaml
regulatory_resources:
  - name: "CISA Ransomware Guide"
    url: "https://www.cisa.gov/stopransomware"

  - name: "FBI Ransomware Resources"
    url: "https://www.fbi.gov/how-we-can-help-you/safety-resources/scams-and-safety/common-scams-and-crimes/ransomware"

  - name: "NIST Cybersecurity Framework"
    url: "https://www.nist.gov/cyberframework"

  - name: "SEC Cybersecurity Disclosure"
    url: "https://www.sec.gov/rules/final/2023/33-11216.pdf"

  - name: "GDPR Guidelines"
    url: "https://gdpr.eu/data-breach-notification/"
```

---

## References

### MITRE ATT&CK
- **T1486 - Data Encrypted for Impact**: https://attack.mitre.org/techniques/T1486/
- **T1490 - Inhibit System Recovery**: https://attack.mitre.org/techniques/T1490/
- **T1489 - Service Stop**: https://attack.mitre.org/techniques/T1489/
- **T1036 - Masquerading**: https://attack.mitre.org/techniques/T1036/
- **T1027 - Obfuscated Files or Information**: https://attack.mitre.org/techniques/T1027/
- **T1055 - Process Injection**: https://attack.mitre.org/techniques/T1055/

### Industry Resources
- **CISA Ransomware Guide**: https://www.cisa.gov/stopransomware
- **No More Ransom Project**: https://www.nomoreransom.org/
- **NIST Cybersecurity Framework**: https://www.nist.gov/cyberframework
- **Ransomware Task Force**: https://securityandtechnology.org/ransomwaretaskforce/
- **ENISA Threat Landscape**: https://www.enisa.europa.eu/topics/threat-risk-management/threats-and-trends

### Law Enforcement
- **FBI Internet Crime Complaint Center (IC3)**: https://www.ic3.gov
- **FBI Ransomware Portal**: https://www.fbi.gov/investigate/cyber
- **CISA Cyber Incident Reporting**: https://www.cisa.gov/report

---

## Document Approval

| Role | Name | Signature | Date |
|------|------|-----------|------|
| **Author** | SOC Team | | 2026-02-17 |
| **Reviewed By** | Security Lead | | |
| **Approved By** | CISO | | |
| **Legal Review** | General Counsel | | |

---

**END OF PLAYBOOK**

**Classification: TLP:RED - RESTRICTED DISTRIBUTION**

**Next Review Date: 2026-05-17 (Quarterly)**
