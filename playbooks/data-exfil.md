# Playbook: Data Exfiltration Detection and Response

## Document Control

| Field | Value |
|-------|-------|
| Playbook ID | PB-004 |
| Version | 2.0.0 |
| Classification | **TLP:RED** (Data Breach Potential) |
| Distribution | SOC Team, CISO, Legal, Privacy Officer, Incident Response Team Only |
| Last Updated | 2026-02-17 |
| Severity | High-Critical |
| Priority | HIGH |
| Review Cycle | Quarterly or post-breach |

## MITRE ATT&CK Coverage

### Primary Techniques
| Technique ID | Technique Name | Coverage |
|--------------|----------------|----------|
| **TA0010** | **Exfiltration Tactic** | Full coverage |
| T1041 | Exfiltration Over C2 Channel | Network monitoring, C2 indicators |
| T1048 | Exfiltration Over Alternative Protocol | Multi-protocol detection |
| T1048.001 | Exfiltration Over Symmetric Encrypted Non-C2 Protocol (HTTPS) | TLS inspection, HTTPS anomalies |
| T1048.002 | Exfiltration Over Asymmetric Encrypted Non-C2 Protocol | SSH/SFTP monitoring |
| T1048.003 | Exfiltration Over Unencrypted Non-C2 Protocol | FTP/HTTP monitoring |
| T1567 | Exfiltration Over Web Service | Cloud service detection |
| T1567.002 | Exfiltration to Cloud Storage | AWS/Azure/GCP API monitoring |
| T1030 | Data Transfer Size Limits | Small, scheduled transfer detection |
| T1029 | Scheduled Transfer | Pattern analysis, cron/Task Scheduler |
| T1052 | Exfiltration Over Physical Medium | USB monitoring, FIM |
| T1537 | Transfer Data to Cloud Account | Cloud API abuse detection |

### Detection Methods
| Technique | Wazuh Detection Method | Rule IDs |
|-----------|------------------------|----------|
| T1041 | Network flow analysis + C2 IOC correlation | 87401-87410 |
| T1048.001 | HTTPS volume anomalies, unusual SNI patterns | 87420-87425 |
| T1048.002 | SSH connection monitoring, SFTP activity | 87430-87435 |
| T1567.002 | Cloud API logs (AWS CloudTrail, Azure Monitor, GCP Audit) | 87450-87460 |
| T1030 | Statistical analysis of transfer patterns | 87470-87475 |
| T1052 | USB device insertion + FIM on removable media | 87480-87485 |
| T1537 | OAuth token usage, cloud sync client monitoring | 87490-87495 |

## Description

This playbook handles detection, investigation, and response to data exfiltration attempts. Data exfiltration represents a critical phase in the attack lifecycle and may indicate:

- **Active breach in progress** - Threat actor extracting stolen data
- **Insider threat activity** - Malicious or negligent employee data theft
- **Compromised credentials** - External actor using stolen credentials
- **Ransomware data theft** - Double extortion scenario (encrypt + exfiltrate)
- **Supply chain compromise** - Third-party access abuse
- **Nation-state espionage** - Advanced persistent threat (APT) activity

**Regulatory Impact**: Confirmed data exfiltration may trigger mandatory breach notification under GDPR, CCPA, HIPAA, PCI-DSS, and state breach notification laws.

## Detection Criteria

### Primary Indicators

#### Volume-Based Anomalies
- **Large outbound transfers**: >500MB in <1hr from single host
- **Sustained high-bandwidth**: >10Mbps outbound for >30min
- **Large cloud uploads**: >1GB to personal cloud storage (Dropbox, Google Drive, OneDrive personal)
- **Bulk file access**: >100 files accessed in <15min
- **Database dump activity**: Large SELECT queries + network transfer
- **Print spooler abuse**: Large volume to network printer or PDF

#### Protocol Anomalies
- **DNS tunneling**:
  - Query length >100 chars
  - TXT record queries with Base64-encoded data
  - High query volume to single domain (>100/min)
  - Rare DNS query types (NULL, PRIVATE)
- **HTTPS to unusual ports**: HTTPS on ports other than 443 (8443, 9443)
- **ICMP tunneling**: Large ICMP packets (>128 bytes payload)
- **Encrypted traffic to unknown destinations**: TLS to unclassified IPs
- **SSH on non-standard ports**: SSH traffic to high ports (>1024)
- **HTTP POST to rare domains**: Large POST requests to newly-registered domains

#### Behavioral Patterns
- **Off-hours bulk data access**: File access 10pm-6am local time
- **Access to sensitive data by unusual accounts**: Service account accessing HR data
- **Compression before transfer**: zip/7z/tar creation followed by upload
- **Staging data in temp locations**: Files moved to /tmp, C:\Temp, Downloads
- **Lateral movement + data access**: SMB access to file shares after lateral movement
- **Cloud sync client abuse**: OneDrive/Dropbox client transferring non-user data
- **Browser-based exfiltration**: Large file uploads via web browser to personal email

#### DLP Bypass Techniques
- **Steganography**: Embedded data in images, audio files
- **Split-file exfiltration**: Large file split into <10MB chunks
- **Encrypted container uploads**: VeraCrypt, 7z AES containers
- **DNS tunneling tools**: iodine, dnscat2, dns2tcp indicators
- **ICMP tunneling tools**: ptunnel, icmptunnel
- **Fileless exfiltration**: PowerShell Invoke-WebRequest with clipboard/memory data
- **Protocol misuse**: Data in HTTP headers, cookies, User-Agent strings

### Wazuh Detection Rules

#### Network Monitoring Integration
```xml
<!-- High-volume outbound transfer -->
<rule id="87401" level="10">
  <if_group>network</if_group>
  <match>bytes_out</match>
  <if_field name="bytes_out" op="GT">524288000</if_field>
  <if_timeframe>3600</if_timeframe>
  <description>Large outbound data transfer detected (>500MB in 1hr)</description>
  <mitre>
    <id>T1041</id>
  </mitre>
</rule>

<!-- Sustained high bandwidth -->
<rule id="87402" level="8">
  <if_group>network</if_group>
  <match>bandwidth_mbps</match>
  <if_field name="bandwidth_mbps" op="GT">10</if_field>
  <if_timeframe>1800</if_timeframe>
  <description>Sustained high outbound bandwidth (>10Mbps for 30min)</description>
  <mitre>
    <id>T1041</id>
  </mitre>
</rule>
```

#### DNS Query Analysis Rules
```xml
<!-- DNS tunneling - long subdomain -->
<rule id="87420" level="12">
  <if_group>dns</if_group>
  <match>query</match>
  <if_field name="query" op="LENGTH_GT">100</if_field>
  <description>Potential DNS tunneling - abnormally long query</description>
  <mitre>
    <id>T1048.003</id>
  </mitre>
</rule>

<!-- DNS tunneling - high query volume -->
<rule id="87421" level="12">
  <if_group>dns</if_group>
  <match>query</match>
  <if_field name="query_count" op="GT">100</if_field>
  <if_timeframe>60</if_timeframe>
  <same_source_ip />
  <description>DNS tunneling - high query volume (>100/min from single host)</description>
  <mitre>
    <id>T1048.003</id>
  </mitre>
</rule>

<!-- DNS TXT record exfiltration -->
<rule id="87422" level="10">
  <if_group>dns</if_group>
  <match>qtype: TXT</match>
  <if_field name="txt_data" op="REGEX">^[A-Za-z0-9+/=]{50,}</if_field>
  <description>Base64-encoded data in DNS TXT query (potential exfiltration)</description>
  <mitre>
    <id>T1048.003</id>
  </mitre>
</rule>
```

#### File Integrity Monitoring - Staging Directories
```xml
<!-- FIM on temp/staging directories -->
<directories check_all="yes" realtime="yes">/tmp,/var/tmp,/dev/shm</directories>
<directories check_all="yes" realtime="yes">C:\Temp,C:\Windows\Temp,%USERPROFILE%\Downloads</directories>

<!-- Large archive creation in staging -->
<rule id="87430" level="8">
  <if_group>syscheck</if_group>
  <match>archive created</match>
  <if_field name="size" op="GT">104857600</if_field>
  <if_path>/tmp|/var/tmp|C:\Temp|Downloads</if_path>
  <description>Large archive (>100MB) created in staging directory</description>
  <mitre>
    <id>T1560.001</id>
  </mitre>
</rule>
```

#### Proxy/Web Filter Integration
```xml
<!-- Cloud storage upload via proxy logs -->
<rule id="87450" level="10">
  <if_group>web</if_group>
  <match>POST|PUT</match>
  <if_field name="url" op="REGEX">drive\.google\.com|dropbox\.com|onedrive\.live\.com|box\.com</if_field>
  <if_field name="bytes_sent" op="GT">10485760</if_field>
  <description>Large upload (>10MB) to personal cloud storage</description>
  <mitre>
    <id>T1567.002</id>
  </mitre>
</rule>

<!-- File upload to webmail -->
<rule id="87451" level="8">
  <if_group>web</if_group>
  <match>POST</match>
  <if_field name="url" op="REGEX">mail\.google\.com|outlook\.live\.com|mail\.yahoo\.com</if_field>
  <if_field name="content_type" op="MATCH">multipart/form-data</if_field>
  <description>File upload to personal webmail account</description>
  <mitre>
    <id>T1567.002</id>
  </mitre>
</rule>
```

#### DLP Integration Patterns
```xml
<!-- Integration with enterprise DLP (Symantec, McAfee, Forcepoint) -->
<rule id="87460" level="12">
  <if_group>dlp</if_group>
  <match>policy_violation</match>
  <if_field name="severity" op="EQ">high|critical</if_field>
  <if_field name="action" op="EQ">blocked|alerted</if_field>
  <description>DLP policy violation - potential data exfiltration</description>
  <mitre>
    <id>T1041</id>
  </mitre>
</rule>
```

#### Cloud API Usage Anomalies
```xml
<!-- AWS S3 PutObject anomaly -->
<rule id="87470" level="10">
  <if_group>aws</if_group>
  <match>s3:PutObject</match>
  <if_field name="requestParameters.bucketName" op="NOT_IN">approved_buckets_list</if_field>
  <description>AWS S3 upload to non-approved bucket</description>
  <mitre>
    <id>T1537</id>
  </mitre>
</rule>

<!-- Azure Blob Storage upload spike -->
<rule id="87471" level="10">
  <if_group>azure</if_group>
  <match>Microsoft.Storage/storageAccounts/blobServices/containers/blobs/write</match>
  <if_field name="bytes_uploaded" op="GT">1073741824</if_field>
  <if_timeframe>3600</if_timeframe>
  <description>Large Azure Blob Storage upload (>1GB in 1hr)</description>
  <mitre>
    <id>T1537</id>
  </mitre>
</rule>

<!-- GCP Storage bucket exfiltration -->
<rule id="87472" level="10">
  <if_group>gcp</if_group>
  <match>storage.objects.create</match>
  <if_field name="resource.labels.bucket_name" op="NOT_IN">approved_gcp_buckets</if_field>
  <description>GCP Storage upload to non-approved bucket</description>
  <mitre>
    <id>T1537</id>
  </mitre>
</rule>
```

### High-Confidence Patterns

Combinations indicating high probability of actual exfiltration:

```yaml
critical_confidence:
  - bulk_file_access AND large_outbound_transfer AND off_hours
  - sensitive_data_access AND compression_tool AND cloud_upload
  - dns_tunnel_indicators AND base64_encoding AND external_destination
  - known_exfil_tool_execution AND network_transfer
  - database_dump AND sftp_connection AND external_ip
  - lateral_movement AND file_access AND encryption AND transfer
  - privilege_escalation AND data_staging AND scheduled_transfer
  - usb_device_insertion AND fim_changes AND device_removal

high_confidence:
  - archive_creation AND immediate_cloud_upload
  - screenshot_capture_tool AND email_attachment
  - clipboard_monitoring_tool AND web_upload
  - credential_access AND followed_by_data_access
  - fileless_technique AND web_request_with_data
```

## Decision Tree

```
┌─────────────────────────────────┐
│  Volume Anomaly Detected        │
│  (Network/File Access/Cloud)    │
└────────────┬────────────────────┘
             │
             ▼
┌─────────────────────────────────┐
│  Legitimate Business Activity?  │
│  - Backup/Migration ticket?     │
│  - Scheduled job?               │
│  - Manager approval?            │
└─────┬──────────────────┬────────┘
      │ YES              │ NO
      │                  ▼
      │         ┌────────────────────┐
      │         │ Data Classification│
      │         │ Check              │
      │         └─────┬──────────────┘
      │               │
      │               ▼
      │    ┌──────────────────────────┐
      │    │ PII/PHI/PCI/IP/Source?   │
      │    └─┬──────────────┬─────────┘
      │      │ YES          │ NO
      │      │              │
      │      ▼              ▼
      │  ┌───────────┐  ┌──────────┐
      │  │ CRITICAL  │  │ HIGH     │
      │  └─────┬─────┘  └────┬─────┘
      │        │             │
      │        ▼             ▼
      │  ┌─────────────────────────┐
      │  │ Destination Analysis    │
      │  │ - Known malicious?      │
      │  │ - Unknown external?     │
      │  │ - Personal cloud?       │
      │  │ - Competitor infra?     │
      │  └──────┬──────────────────┘
      │         │
      │         ▼
      │  ┌──────────────────────────┐
      │  │ Insider vs External      │
      │  │ - Employee account?      │
      │  │ - Compromised creds?     │
      │  │ - Privileged access?     │
      │  └──────┬───────────────────┘
      │         │
      │         ▼
      │  ┌──────────────────────────┐
      │  │ Active vs Historical     │
      │  │ - Ongoing transfer?      │
      │  │ - Already completed?     │
      │  └──────┬───────────────────┘
      │         │
      │         ▼
      │  ┌──────────────────────────┐
      │  │ Regulatory Trigger?      │
      │  │ - GDPR applies?          │
      │  │ - HIPAA breach?          │
      │  │ - CCPA notification?     │
      │  │ - PCI-DSS incident?      │
      │  │ - SEC disclosure?        │
      │  └──────┬───────────────────┘
      │         │
      │         ▼
      │  ┌──────────────────────────┐
      │  │ CONTAINMENT REQUIRED     │
      │  │ + Legal Notification     │
      │  └──────────────────────────┘
      │
      ▼
┌─────────────────────────────────┐
│  False Positive - Document      │
│  Add to Whitelist              │
└─────────────────────────────────┘
```

## Automated Triage Steps

### 1. Entity Extraction

```yaml
entities:
  - type: host
    source: agent.name, agent.id
    enrich: OS version, patch level, installed software, user population

  - type: user
    source: data.user, data.win.eventdata.targetUserName
    enrich: Department, title, manager, data access rights, VPN status

  - type: source_ip
    source: data.src_ip
    enrich: Internal subnet, geolocation, reputation

  - type: destination_ip
    source: data.dst_ip
    enrich: ASN, geolocation, threat intelligence, cloud provider

  - type: domain
    source: data.dns.query, data.url
    enrich: WHOIS age, reputation, category, DGA detection

  - type: destination_service
    source: data.url, data.dst_ip
    classify: personal_cloud, corporate_cloud, webmail, unknown, C2

  - type: file_paths
    source: data.path, syscheck.path
    enrich: File type, size, hash, data classification, owner

  - type: data_volume
    source: data.bytes_sent, data.size
    calculate: Total volume, rate, duration

  - type: protocols
    source: data.protocol, data.dst_port
    identify: HTTPS, SSH, DNS, ICMP, FTP, custom

  - type: tools_used
    source: data.process, data.command_line
    identify: curl, wget, rclone, 7z, zip, tar, PowerShell, certutil
```

### 2. Data Classification Check

**Automated Classification Queries:**

| Data Type | Detection Method | Criticality |
|-----------|------------------|-------------|
| **PII** | Regex: SSN, credit card, passport, driver's license | CRITICAL |
| **PHI** | File path: medical records, patient data, diagnosis | CRITICAL |
| **Financial** | File path: accounting, financial, payment, invoice | CRITICAL |
| **Intellectual Property** | File extension: .dwg, .psd, .ai, patents, research | CRITICAL |
| **Source Code** | File extension: .py, .java, .cpp, .js, .go | HIGH |
| **Credentials** | File name: password, credentials, key, token, .pem | CRITICAL |
| **Customer Data** | Database: customer table access, CRM queries | HIGH |
| **Internal Only** | Document properties: confidential, internal use | MEDIUM |

**Classification Integration:**
- Query enterprise DLP system for file classification
- Check Microsoft Information Protection labels
- Scan file metadata for sensitivity markings
- Cross-reference with data catalog/governance platform

### 3. User Context Assessment

| Factor | Check | High-Risk Indicators |
|--------|-------|---------------------|
| **User role** | HR system lookup | Service account, contractor, recently terminated |
| **Data authorization** | Access control matrix | No business need for this data |
| **Access pattern** | Behavioral analytics | First-time access, unusual volume |
| **Time of access** | Timestamp analysis | Outside business hours (10pm-6am) |
| **Location** | VPN logs, geolocation | Foreign country, impossible travel |
| **Recent activity** | Alert history | Prior security incidents, policy violations |
| **Employment status** | HR system | Notice period, disciplinary action, termination |
| **Privileged access** | PAM logs | Excessive privileges, recent elevation |

### 4. Severity Assessment Matrix

| Condition | Severity | Auto-Escalate | Legal Notification |
|-----------|----------|---------------|-------------------|
| PII >1000 records | **CRITICAL** | Yes | MANDATORY |
| PHI any amount | **CRITICAL** | Yes | MANDATORY (HIPAA) |
| PCI cardholder data | **CRITICAL** | Yes | MANDATORY (PCI-DSS) |
| Financial records >$100K exposure | **CRITICAL** | Yes | Consider SEC |
| Source code (trade secret) | **CRITICAL** | Yes | Consider |
| Credentials (admin/privileged) | **CRITICAL** | Yes | Yes |
| Customer data >10,000 records | **CRITICAL** | Yes | State law dependent |
| High volume + off-hours + external dest | **HIGH** | Yes | Assess |
| Known malicious destination | **HIGH** | Yes | Assess |
| Insider + sensitive data | **HIGH** | Yes | Assess |
| Unknown destination + encryption | **HIGH** | No | Assess |
| Cloud upload (corporate approved) | **MEDIUM** | No | No |

## Forensic Artifacts

### Linux Systems

#### Network Evidence
```bash
# Active connections at time of detection
/proc/net/tcp, /proc/net/udp, /proc/net/raw

# Packet captures (if enabled)
tcpdump -r /var/log/tcpdump/exfil_${timestamp}.pcap -n 'src host ${source_ip}'

# iptables logs
/var/log/iptables.log
grep "${source_ip}" /var/log/syslog

# DNS cache (systemd-resolved)
resolvectl statistics
journalctl -u systemd-resolved | grep "${suspicious_domain}"

# Network statistics
ss -tunap > /tmp/network_state_${timestamp}.txt
netstat -ano > /tmp/netstat_${timestamp}.txt
```

#### Command History
```bash
# Bash history for all users
/home/*/.bash_history
/root/.bash_history

# Zsh history
/home/*/.zsh_history

# Commands with timestamps
export HISTTIMEFORMAT="%F %T "
history | grep -E "curl|wget|scp|sftp|rsync|nc|socat|rclone"

# SSH configuration and known hosts
/home/*/.ssh/config
/home/*/.ssh/known_hosts
/root/.ssh/known_hosts
```

#### Process and Execution Evidence
```bash
# Process tree at time of detection
ps auxwwf > /tmp/process_tree_${timestamp}.txt

# Process command lines
/proc/*/cmdline

# Recently executed binaries
find /tmp /var/tmp /dev/shm -type f -executable -mtime -1

# Cron jobs and scheduled tasks
/var/spool/cron/*
/etc/cron.*/*
crontab -l -u ${username}
```

#### File System Artifacts
```bash
# Recently modified files
find / -type f -mtime -1 -size +10M 2>/dev/null

# Archive files in staging locations
find /tmp /var/tmp /dev/shm /home/*/Downloads -type f \( -name "*.zip" -o -name "*.tar*" -o -name "*.7z" \) -mtime -1

# Deleted files (if ext4 forensics available)
extundelete /dev/sda1 --inode ${inode}

# Cloud sync client logs
/home/*/.config/Dropbox/logs/
/home/*/.config/onedrive/logs/
```

### Windows Systems

#### Sysmon Events
```xml
<!-- Event ID 3: Network Connection -->
<QueryList>
  <Query Id="0" Path="Microsoft-Windows-Sysmon/Operational">
    <Select Path="Microsoft-Windows-Sysmon/Operational">
      *[System[(EventID=3)]]
      and
      *[EventData[Data[@Name='User']='${username}']]
      and
      *[EventData[Data[@Name='Initiated']='true']]
    </Select>
  </Query>
</QueryList>

<!-- Event ID 22: DNS Query -->
<QueryList>
  <Query Id="0" Path="Microsoft-Windows-Sysmon/Operational">
    <Select Path="Microsoft-Windows-Sysmon/Operational">
      *[System[(EventID=22)]]
      and
      *[EventData[Data[@Name='Image'] contains '${process_name}']]
    </Select>
  </Query>
</QueryList>

<!-- Event ID 11: File Creation (staging) -->
<QueryList>
  <Query Id="0" Path="Microsoft-Windows-Sysmon/Operational">
    <Select Path="Microsoft-Windows-Sysmon/Operational">
      *[System[(EventID=11)]]
      and
      *[EventData[Data[@Name='TargetFilename'] contains 'Temp']]
      and
      *[EventData[Data[@Name='TargetFilename'] contains '.zip' or contains '.7z']]
    </Select>
  </Query>
</QueryList>
```

#### Proxy Logs
```
# Corporate proxy logs (BlueCoat, Zscaler, Squid)
Query proxy for:
- Source IP: ${source_ip}
- Username: ${username}
- Timeframe: ${start_time} to ${end_time}
- Filter: POST/PUT methods, large uploads (>10MB)
- Categories: cloud storage, webmail, file sharing

# Fields to extract:
timestamp, username, source_ip, destination_url, bytes_sent, bytes_received,
http_method, content_type, user_agent, action (allowed/blocked)
```

#### Browser History
```powershell
# Chrome history database
$ChromePath = "$env:LOCALAPPDATA\Google\Chrome\User Data\Default\History"
sqlite3 $ChromePath "SELECT url, title, visit_count, last_visit_time FROM urls WHERE url LIKE '%drive.google.com%' OR url LIKE '%dropbox.com%' ORDER BY last_visit_time DESC LIMIT 100;"

# Edge (Chromium) history
$EdgePath = "$env:LOCALAPPDATA\Microsoft\Edge\User Data\Default\History"

# Firefox history
$FirefoxPath = "$env:APPDATA\Mozilla\Firefox\Profiles\*.default-release\places.sqlite"

# Downloads history
SELECT target_path, total_bytes, start_time, end_time, opened FROM downloads WHERE start_time > ${timestamp};
```

#### USB Device History
```powershell
# USB device connection events (Event ID 20001, 20003)
Get-WinEvent -FilterHashtable @{
  LogName='Microsoft-Windows-DriverFrameworks-UserMode/Operational'
  ID=20001,20003
  StartTime=(Get-Date).AddDays(-7)
} | Where-Object {$_.Message -match "USBSTOR"}

# Registry: USB devices
HKLM\SYSTEM\CurrentControlSet\Enum\USBSTOR
HKLM\SYSTEM\CurrentControlSet\Enum\USB

# Setup API logs
C:\Windows\inf\setupapi.dev.log
```

#### Clipboard History
```powershell
# Windows 10/11 clipboard history (if enabled)
Get-Clipboard -Format Text

# Clipboard monitoring logs (if enterprise DLP deployed)
Query DLP system for clipboard copy events involving sensitive data
```

#### Print Spooler Logs
```powershell
# Print events (potential "print to PDF" exfiltration)
Get-WinEvent -FilterHashtable @{
  LogName='Microsoft-Windows-PrintService/Operational'
  ID=307
  StartTime=(Get-Date).AddDays(-7)
} | Where-Object {$_.Properties[3].Value -eq $username}

# EMF/spool files
C:\Windows\System32\spool\PRINTERS\*.spl
```

#### PowerShell Logging
```powershell
# Script block logging (Event ID 4104)
Get-WinEvent -FilterHashtable @{
  LogName='Microsoft-Windows-PowerShell/Operational'
  ID=4104
  StartTime=(Get-Date).AddDays(-1)
} | Where-Object {$_.Message -match "Invoke-WebRequest|Invoke-RestMethod|System.Net.WebClient|UploadFile"}

# Command execution history
Get-Content "$env:APPDATA\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt"
```

#### Cloud Sync Client Logs
```
# OneDrive
%LOCALAPPDATA%\Microsoft\OneDrive\logs\Business1\SyncEngine-*.odl

# Dropbox
%APPDATA%\Dropbox\logs\*.log

# Google Drive
%LOCALAPPDATA%\Google\Drive\user_default\sync_config.db
```

## Data Classification Integration

### PII Indicators

```yaml
ssn_pattern: '\b\d{3}-\d{2}-\d{4}\b'
credit_card_pattern: '\b\d{4}[\s-]?\d{4}[\s-]?\d{4}[\s-]?\d{4}\b'
passport_pattern: '\b[A-Z]{1,2}\d{6,9}\b'
drivers_license_pattern: '[A-Z]{1,2}\d{5,8}'
email_pattern: '[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}'
phone_pattern: '\b\d{3}[-.\s]?\d{3}[-.\s]?\d{4}\b'

pii_files:
  - employee_roster.*
  - customer_list.*
  - contacts.*
  - ssn.*
  - personnel.*
```

### Financial Data Patterns

```yaml
financial_keywords:
  - accounting
  - financial_statements
  - balance_sheet
  - income_statement
  - tax_return
  - w2
  - 1099
  - payroll
  - accounts_payable
  - accounts_receivable
  - general_ledger

file_extensions:
  - .qbw (QuickBooks)
  - .accdb (Access financial db)
  - .xls/.xlsx (often financial data)
```

### Healthcare (PHI)

```yaml
phi_indicators:
  file_paths:
    - medical_records/
    - patient_data/
    - ehr_export/
    - diagnosis/
    - prescription/
    - lab_results/

  database_tables:
    - patients
    - diagnoses
    - medications
    - procedures
    - encounters

  hl7_messages: true
  fhir_resources: true
  dicom_files: '*.dcm'
```

### Intellectual Property

```yaml
ip_indicators:
  file_types:
    - .dwg (AutoCAD)
    - .psd (Photoshop)
    - .ai (Illustrator)
    - .indd (InDesign)
    - .blend (Blender)
    - .step (CAD)

  keywords:
    - patent
    - trademark
    - confidential
    - proprietary
    - trade_secret
    - research
    - prototype
```

### Source Code

```yaml
source_code_extensions:
  - .py, .pyc, .pyo
  - .java, .class, .jar
  - .cpp, .c, .h, .hpp
  - .js, .jsx, .ts, .tsx
  - .go
  - .rs (Rust)
  - .php
  - .rb (Ruby)
  - .cs (C#)
  - .swift
  - .kt (Kotlin)

repositories:
  - .git/
  - .svn/
  - .hg/
```

### Credentials

```yaml
credential_patterns:
  file_names:
    - password
    - credentials
    - secret
    - token
    - api_key
    - private_key
    - .pem
    - .key
    - .p12
    - .pfx
    - .env
    - vault

  content_patterns:
    - 'password\s*=\s*["\']?[^"\'\\s]+'
    - 'api[_-]?key\s*=\s*["\']?[A-Za-z0-9]+'
    - 'BEGIN (RSA|DSA|EC|OPENSSH) PRIVATE KEY'
    - 'aws_access_key_id'
    - 'AKIA[0-9A-Z]{16}'
```

## Communication Templates

### Legal/Privacy Team Notification (MANDATORY)

**Trigger**: Confirmed or highly probable data exfiltration involving classified data.

**Subject**: URGENT - DATA BREACH NOTIFICATION - Case ${case_id}

```
TO: Legal Team <legal@company.com>, Privacy Officer <privacy@company.com>
CC: CISO <ciso@company.com>, Incident Commander <ic@company.com>
PRIORITY: URGENT
CLASSIFICATION: CONFIDENTIAL - ATTORNEY-CLIENT PRIVILEGED

INCIDENT NOTIFICATION - POTENTIAL DATA BREACH

Case ID: ${case_id}
Detection Time: ${detection_timestamp} UTC
Notification Time: ${notification_timestamp} UTC
Incident Commander: ${ic_name}

INCIDENT SUMMARY:
Security monitoring systems detected unauthorized data exfiltration from our environment. This incident may constitute a data breach requiring regulatory notification.

AFFECTED DATA (Preliminary Assessment):
- Data Type: ${data_classification} (PII/PHI/PCI/Financial/IP)
- Estimated Volume: ${data_volume_gb} GB
- Estimated Record Count: ${estimated_records}
- Data Elements: ${data_elements} (e.g., names, SSN, credit cards, medical records)
- Data Owner: ${data_owner_department}

INCIDENT DETAILS:
- Source System: ${source_system}
- Affected User/Account: ${username}
- Destination: ${destination_analysis}
- Exfiltration Method: ${method} (e.g., cloud upload, email, USB, network transfer)
- Duration: ${start_time} to ${end_time} (${duration_hours} hours)
- Current Status: ${active_or_contained}

AFFECTED INDIVIDUALS (if known):
- Estimated Number: ${affected_individual_count}
- Jurisdictions: ${states_countries}

CONTAINMENT STATUS:
- [X] User account disabled
- [X] Network destination blocked
- [X] Host isolated
- [ ] Data retrieval attempted
- [ ] Law enforcement notified

REGULATORY ASSESSMENT REQUIRED:
- GDPR Applicability: ${gdpr_yes_no} (72-hour clock started: ${gdpr_clock_start})
- HIPAA Applicability: ${hipaa_yes_no}
- CCPA Applicability: ${ccpa_yes_no}
- PCI-DSS Applicability: ${pci_yes_no}
- State Breach Laws: ${state_laws_list}
- SEC Disclosure: ${sec_yes_no}

EVIDENCE PRESERVATION:
All forensic evidence has been preserved and is available for legal review. Chain of custody documentation is maintained.

NEXT STEPS REQUIRED:
1. Legal assessment of breach notification requirements
2. Determination of notification timelines
3. Attorney-client privileged forensic investigation scope
4. External counsel engagement (if required)
5. Cyber insurance carrier notification
6. Regulatory authority notification preparation

IMMEDIATE LEGAL QUESTIONS:
1. Does this incident meet the threshold for breach notification under applicable laws?
2. What is our notification deadline? (GDPR 72hr clock may be running)
3. Should we engage external breach counsel?
4. Should we engage forensic investigation firm under attorney-client privilege?
5. Do we need to notify cyber insurance carrier immediately?

CONTACT INFORMATION:
Incident Commander: ${ic_name} - ${ic_phone} - ${ic_email}
CISO: ${ciso_name} - ${ciso_phone} - ${ciso_email}
On-call Security: ${oncall_phone}

This notification is provided pursuant to company incident response policy and is intended to facilitate legal assessment of potential breach notification obligations.

CONFIDENTIAL - DO NOT FORWARD WITHOUT LEGAL APPROVAL
```

### CISO Briefing

**Subject**: CRITICAL - Data Exfiltration Incident - Case ${case_id}

```
EXECUTIVE SUMMARY - DATA EXFILTRATION INCIDENT

Case: ${case_id}
Status: ${active_or_contained}
Severity: CRITICAL
Business Impact: ${impact_level}

WHAT HAPPENED:
${brief_description_2_sentences}

DATA AT RISK:
- Type: ${data_classification}
- Volume: ${data_volume_gb} GB (~${estimated_records} records)
- Sensitivity: ${pii_phi_pci_ip}

BUSINESS IMPACT:
- Regulatory Notification: ${likely_required_yes_no}
- Customer Impact: ${customer_count} potentially affected
- Financial Exposure: ${estimated_cost_range}
- Reputation Risk: ${high_medium_low}

CONTAINMENT:
- [X] Threat contained at ${containment_time}
- [ ] Ongoing exfiltration (requires immediate action)

REGULATORY CLOCK:
- GDPR 72-hour deadline: ${gdpr_deadline_if_applicable}
- Other deadlines: ${other_deadlines}

RECOMMENDATIONS:
1. ${recommendation_1}
2. ${recommendation_2}
3. ${recommendation_3}

NEXT BRIEFING: ${next_update_time}

Contact: ${ic_name} - ${ic_phone}
```

### Regulatory Body Notification Drafts

#### GDPR - Data Protection Authority (DPA)

**Use**: GDPR Art. 33 notification (72 hours from awareness)

```
PERSONAL DATA BREACH NOTIFICATION
Pursuant to GDPR Article 33

TO: [Data Protection Authority Name]
FROM: [Company Name], Data Controller
DATE: ${notification_date}
REFERENCE: Breach Notification ${breach_ref_number}

1. DESCRIPTION OF BREACH:

On ${detection_date}, [Company Name] detected unauthorized access and exfiltration of personal data from our systems. The breach involved [description of incident].

Nature of breach: Unauthorized data exfiltration
Date of breach: ${breach_date}
Date of detection: ${detection_date}

2. CATEGORIES AND APPROXIMATE NUMBER OF DATA SUBJECTS CONCERNED:

Affected data subjects: ${number_of_individuals}
Categories: ${categories} (e.g., customers, employees, EU residents)
Jurisdictions: ${eu_member_states}

3. CATEGORIES AND APPROXIMATE NUMBER OF PERSONAL DATA RECORDS CONCERNED:

Records affected: ${number_of_records}
Data categories:
- ${category_1} (e.g., names, email addresses)
- ${category_2} (e.g., identification numbers)
- ${category_3} (e.g., financial data)
Special category data: ${yes_no_if_yes_specify}

4. LIKELY CONSEQUENCES OF THE BREACH:

${description_of_consequences}
Risk to rights and freedoms: ${high_medium_low}

5. MEASURES TAKEN OR PROPOSED:

Immediate actions:
- ${action_1}
- ${action_2}

Remediation:
- ${remediation_1}
- ${remediation_2}

Individual notification: ${planned_yes_no}

6. CONTACT POINT:

Data Protection Officer: ${dpo_name}
Email: ${dpo_email}
Phone: ${dpo_phone}

[Company Name] is continuing to investigate this incident and will provide updates as required under Article 33(4).

Signed: ${dpo_name}, Data Protection Officer
```

#### HIPAA - HHS Office for Civil Rights (OCR)

**Use**: HIPAA 164.408 notification (60 days for >500 individuals)

```
BREACH NOTIFICATION
Health Insurance Portability and Accountability Act (HIPAA)

TO: U.S. Department of Health and Human Services, Office for Civil Rights
SUBMITTED VIA: HHS Breach Notification Portal
COVERED ENTITY: [Company Name]

1. COVERED ENTITY INFORMATION:
Name: ${company_legal_name}
Address: ${address}
Type: ${health_plan_or_provider_or_clearinghouse}
Contact: ${privacy_officer_name}, ${privacy_officer_email}, ${privacy_officer_phone}

2. BREACH DISCOVERY DATE: ${discovery_date}

3. DATE BREACH OCCURRED: ${breach_date}

4. NUMBER OF INDIVIDUALS AFFECTED: ${number_of_individuals}

5. TYPE OF BREACH:
[X] Unauthorized Access/Disclosure
[ ] Theft
[ ] Loss
[ ] Improper Disposal
[ ] Hacking/IT Incident
[ ] Other

6. LOCATION OF BREACH:
[X] Electronic Medical Record
[ ] Paper Records
[X] Network Server
[ ] Laptop
[ ] Other Portable Device

7. PHI INVOLVED:
[X] Names
[X] Addresses
[X] Dates of Birth
[ ] Social Security Numbers
[X] Medical Record Numbers
[X] Diagnosis/Treatment Information
[ ] Health Insurance Information
[ ] Financial Information
[ ] Other: ${other_phi}

8. DESCRIPTION OF BREACH:
${detailed_description}

9. SAFEGUARDS IN PLACE:
${safeguards_description}

10. ACTIONS TAKEN IN RESPONSE:
${response_actions}

11. BREACH PREVENTION:
${prevention_measures}

Submitted by: ${privacy_officer_name}, Privacy Officer
Date: ${submission_date}
```

#### CCPA - California Attorney General

**Use**: CCPA 1798.82 notification (California residents)

```
DATA BREACH NOTIFICATION
California Civil Code Section 1798.82

TO: California Attorney General's Office
ATTN: Privacy Enforcement and Protection Unit
FROM: [Company Name]

Pursuant to California Civil Code Section 1798.82(f), [Company Name] is providing notice of a data breach affecting California residents.

SAMPLE NOTIFICATION ATTACHED: Yes

NUMBER OF CALIFORNIA RESIDENTS AFFECTED: ${ca_resident_count}

DATE OF BREACH: ${breach_date}

DESCRIPTION:
${description_of_breach}

TYPES OF PERSONAL INFORMATION INVOLVED:
${pi_types}

ACTIONS TAKEN:
${actions_taken}

INDIVIDUAL NOTIFICATION:
Method: ${email_or_mail}
Date sent: ${notification_sent_date}

CONTACT:
${contact_name}
${contact_email}
${contact_phone}

Submitted: ${submission_date}
```

#### State Breach Notification - Attorney General

**Use**: Various state breach notification laws

```
SECURITY BREACH NOTIFICATION
[State Name] Data Breach Notification Law

TO: [State] Attorney General
FROM: [Company Name]

[Company Name] is providing notice of a data breach affecting residents of [State] pursuant to [State Statute Citation].

Affected Residents: ${state_resident_count}
Breach Date: ${breach_date}
Discovery Date: ${discovery_date}

Description: ${description}

Personal Information Involved: ${pi_types}

Individual Notification: Sent on ${date} via ${method}

Contact: ${name}, ${email}, ${phone}

[Attach copy of individual notification letter]
```

### Affected Individual Notification

**Subject**: Important Security Notice - Your Information

```
[Company Letterhead]

${date}

Dear ${individual_name},

We are writing to inform you of a data security incident that may have affected your personal information.

WHAT HAPPENED:
On ${detection_date}, we discovered that an unauthorized party gained access to certain systems containing personal information. We immediately launched an investigation and took steps to secure our systems.

WHAT INFORMATION WAS INVOLVED:
The information potentially accessed includes:
- ${data_element_1} (e.g., your name and address)
- ${data_element_2} (e.g., Social Security number)
- ${data_element_3} (e.g., financial account information)

WHAT WE ARE DOING:
- We have secured our systems and terminated unauthorized access
- We have notified law enforcement and are cooperating with their investigation
- We have engaged cybersecurity experts to investigate
- We are enhancing our security measures

WHAT YOU CAN DO:
We recommend you take the following steps to protect yourself:

1. Monitor your accounts for suspicious activity
2. Place a fraud alert or credit freeze on your credit files (instructions enclosed)
3. Review your credit reports (free at www.annualcreditreport.com)
4. Report any suspicious activity to your financial institutions

${if_credit_monitoring_offered}
We are offering you complimentary credit monitoring and identity theft protection services for ${duration} months at no cost to you. Enrollment instructions are enclosed.
${end_if}

FOR MORE INFORMATION:
We have established a dedicated assistance line: ${phone_number} (${hours})
You may also visit: ${website_url}
Or write to: ${address}

We sincerely apologize for this incident and any concern it may cause. Protecting your information is a responsibility we take seriously.

Sincerely,

${ceo_or_privacy_officer_name}
${title}

Enclosures:
- Steps to Protect Your Information
- Credit Reporting Agency Contact Information
- ${if_applicable} Credit Monitoring Enrollment Instructions
```

## Regulatory Compliance

### GDPR (General Data Protection Regulation)

**Applicability**: Personal data of EU/EEA residents

| Requirement | Citation | Timeline | Action Required |
|-------------|----------|----------|----------------|
| Breach notification to DPA | Art. 33 | 72 hours from awareness | Notify lead supervisory authority |
| Individual notification | Art. 34 | Without undue delay | If high risk to rights/freedoms |
| Breach documentation | Art. 33(5) | Immediate | Document facts, effects, remediation |
| DPO involvement | Art. 37-39 | Immediate | DPO must be consulted |

**72-Hour Clock**:
- Clock starts when organization becomes "aware" of breach
- Awareness = reasonable degree of certainty a breach occurred
- If full details unavailable, provide information in phases
- Failure to notify: Fines up to €10 million or 2% global revenue

**Notification Content** (Art. 33(3)):
- Nature of breach
- DPO contact
- Likely consequences
- Measures taken/proposed

### CCPA (California Consumer Privacy Act)

**Applicability**: California residents' personal information

| Requirement | Citation | Timeline | Action Required |
|-------------|----------|----------|----------------|
| Individual notification | Civil Code 1798.82 | Without unreasonable delay | Email or mail |
| AG notification | Civil Code 1798.82(f) | If >500 CA residents | Electronic submission + sample notice |
| Substitute notice | Civil Code 1798.82(g) | If cost >$250K or >500K affected | Website + email + media |

**Notification Triggers**:
- Unencrypted personal information
- Encrypted PI + encryption key also compromised
- Personal information = name + SSN/DL/CC/medical/health insurance

**Private Right of Action**:
- $100-$750 per consumer per incident (statutory damages)
- Applies if organization failed to implement reasonable security

### HIPAA (Health Insurance Portability and Accountability Act)

**Applicability**: Protected Health Information (PHI)

| Breach Size | Notification Requirement | Timeline |
|-------------|-------------------------|----------|
| **<500 individuals** | Individual notification | 60 days from discovery |
| | HHS notification | Annual (within 60 days of calendar year end) |
| **≥500 individuals** | Individual notification | 60 days from discovery |
| | HHS notification via portal | 60 days from discovery |
| | Media notification | 60 days (prominent media outlets in state/jurisdiction) |

**Breach Definition** (HITECH Act):
- Unauthorized acquisition, access, use, or disclosure of PHI
- Compromises security or privacy of PHI
- Presumed breach unless low probability of compromise (risk assessment)

**Risk Assessment Factors** (45 CFR 164.402):
1. Nature and extent of PHI involved
2. Unauthorized person who used/disclosed PHI
3. Was PHI actually acquired/viewed
4. Extent to which risk mitigated

**Penalties**:
- Tier 1 (unknowing): $100-$50K per violation
- Tier 4 (willful neglect, uncorrected): $50K+ per violation
- Annual maximum: $1.5 million per violation type

### PCI-DSS (Payment Card Industry Data Security Standard)

**Applicability**: Cardholder data (CHD) or sensitive authentication data (SAD)

| Requirement | Timeline | Action Required |
|-------------|----------|----------------|
| Incident response plan activation | Immediate | Requirement 12.10.1 |
| Payment brand notification | Per brand rules | Visa: 72 hours, MC: immediate |
| Acquiring bank notification | Immediate | Per merchant agreement |
| Forensic investigation (PFI) | ASAP | If CHD/SAD compromised |
| Incident report | 30 days | Submit to acquiring bank |

**Notification Recipients**:
- Acquiring bank (immediate)
- Visa: compromisenotification@visa.com (within 3 business days)
- Mastercard: soc@mastercard.com (immediately)
- Amex, Discover: per brand rules

**PCI Forensic Investigator (PFI)**:
- Required for Level 1/2 merchants or if mandated by acquirer
- Must be on PCI SSC list of approved PFIs

**Consequences**:
- Fines: $5K-$100K per month until compliant
- Increased transaction fees
- Loss of card acceptance privileges
- Lawsuits from issuing banks

### SEC (Securities and Exchange Commission)

**Applicability**: Publicly traded companies (material cybersecurity incidents)

| Requirement | Citation | Timeline | Action Required |
|-------------|----------|----------|----------------|
| Cybersecurity incident disclosure | Form 8-K Item 1.05 | 4 business days | If materially impacts company |
| Annual cyber risk disclosure | Form 10-K Item 1C | Annual | Cybersecurity risk management |

**Materiality Assessment**:
- Could a reasonable investor consider it important?
- Financial impact >5% revenue/assets threshold (rule of thumb)
- Reputational damage
- Customer data breach (especially if >100K individuals)
- Regulatory penalties likely
- Operational disruption

**Form 8-K Requirements** (effective Dec 2023):
- Describe nature, scope, timing of incident
- Material impact or reasonably likely impact
- 4 business days from determination of materiality
- Can delay if DOJ/FBI determines immediate disclosure poses substantial national security or public safety risk

### State Breach Notification Laws

All 50 U.S. states + DC, PR, VI, GU have breach notification laws.

**Key Variations**:

| State | Trigger | Timeline | AG Notification |
|-------|---------|----------|----------------|
| **California** | Unencrypted PI | Without unreasonable delay | Yes, if >500 residents |
| **New York** | Private information | Without unreasonable delay | Yes, NYAG + DFS |
| **Texas** | Sensitive PI | Without unreasonable delay | Yes, TX AG |
| **Florida** | Personal information | 30 days | Yes, if >500 FL residents |
| **Massachusetts** | Personal information of MA residents | As soon as practicable | Yes, MA AG + Director of Consumer Affairs |
| **Illinois** | Personal information | Without unreasonable delay | Yes, IL AG if >500 |

**Encryption Safe Harbor**:
- Most states exempt encrypted data (if key not compromised)
- Exceptions: Some states require notification if encrypted PI accessed

**Harm Threshold**:
- Some states require notification only if "risk of harm"
- Most states: per se notification (no harm threshold)

## DLP Bypass Detection

### Steganography Indicators

```yaml
steganography_detection:

  file_size_anomalies:
    # Image files larger than expected for resolution
    - .png file >5MB for 1920x1080 image
    - .jpg file >2MB for standard photo
    - .bmp file with unusual size-to-dimensions ratio

  tool_indicators:
    - steghide
    - outguess
    - stegosuite
    - openstego
    - process: "steghide embed"
    - command_line: "steghide extract"

  behavioral:
    - Large image downloads followed by upload to external site
    - Image editing tools (GIMP, Photoshop) + network transfer
    - Conversion of documents to images (PDF to PNG) before upload

  forensic_checks:
    - LSB (Least Significant Bit) analysis
    - Statistical analysis (chi-square test)
    - File entropy analysis (high entropy = possible encryption)
```

### Split-File Exfiltration

```yaml
split_file_detection:

  file_patterns:
    - Multiple files with .part*, .001, .002 extensions
    - Sequentially numbered archives: backup_001.zip, backup_002.zip
    - Same file hash prefix but different file names

  behavioral:
    - Large file split using: split, 7z -v, zip -s
    - Sequential uploads to same destination
    - Time correlation: files uploaded <5min apart
    - Similar file sizes (e.g., all exactly 9.9MB to stay under 10MB limit)

  detection_query:
    SELECT src_ip, dst_domain, filename, size, timestamp
    FROM network_transfers
    WHERE size BETWEEN 9000000 AND 10000000
    GROUP BY src_ip, dst_domain
    HAVING COUNT(*) > 5 AND MAX(timestamp)-MIN(timestamp) < 600
```

### Encrypted Container Uploads

```yaml
encrypted_container_detection:

  file_types:
    - .tc (TrueCrypt)
    - .hc (VeraCrypt)
    - .dmg (encrypted disk image)
    - .7z with AES encryption
    - .zip with strong encryption

  tool_indicators:
    - veracrypt
    - truecrypt
    - cryptsetup
    - process: "veracrypt /create"
    - command_line: "7z a -p -mhe=on"

  behavioral:
    - Container creation followed by immediate upload
    - Large binary files with high entropy
    - Files uploaded to personal cloud storage

  entropy_check:
    # Encrypted files typically have entropy >7.9 bits/byte
    if file_entropy > 7.9 and file_size > 10MB:
      alert: possible_encrypted_container
```

### DNS Tunneling Detection

```yaml
dns_tunneling_detection:

  tools:
    - iodine
    - dnscat2
    - dns2tcp
    - dns-tunnel
    - tcp-over-dns

  patterns:
    query_length:
      - Subdomain >50 characters
      - Subdomain >100 characters (high confidence)
      - Multiple levels: aaa.bbb.ccc.ddd.domain.com (>4 levels)

    query_frequency:
      - >50 queries/min to same domain from single host
      - >100 queries/min (high confidence)

    query_types:
      - Excessive TXT queries
      - Excessive NULL queries
      - Mix of A, AAAA, TXT, CNAME to same domain

    encoding:
      - Base64 patterns: [A-Za-z0-9+/=]{40,}
      - Hex encoding: [0-9a-f]{40,}
      - Base32: [A-Z2-7]{40,}

    entropy:
      - High subdomain entropy (random-looking)
      - Low vowel-to-consonant ratio

    response_patterns:
      - TXT records with Base64 data
      - A records with unusual patterns (e.g., 10.x.x.x sequences encoding data)

  wazuh_rule:
    <rule id="87422" level="12">
      <if_group>dns</if_group>
      <match>query</match>
      <if_field name="query" op="LENGTH_GT">100</if_field>
      <if_field name="query" op="REGEX">[A-Za-z0-9]{50,}</if_field>
      <description>DNS tunneling - long encoded subdomain</description>
    </rule>
```

### ICMP Tunneling Detection

```yaml
icmp_tunneling_detection:

  tools:
    - ptunnel
    - icmptunnel
    - ping-tunnel
    - icmp-backdoor

  patterns:
    payload_size:
      - ICMP packet >128 bytes (normal ping = 32-64 bytes)
      - Consistent large payload size

    frequency:
      - High ICMP packet rate (>10 packets/sec sustained)
      - Regular interval patterns (e.g., exactly every 100ms)

    payload_content:
      - Non-zero payload in ICMP Echo Request/Reply
      - High entropy in payload (encrypted data)
      - Printable ASCII in payload (encoded data)

    bidirectional:
      - Both Echo Request and Echo Reply with data
      - Asymmetric payload sizes (different request/reply sizes)

  detection:
    tcpdump_filter: "icmp and greater 128"
    wireshark_filter: "icmp.data.len > 128"
```

## Agent Pipeline Integration

### Correlation Agent

**Purpose**: Link file access events with network transfer events to identify data exfiltration chains.

```yaml
correlation_agent_queries:

  file_access_to_network_transfer:
    description: "Detect file access followed by network transfer within time window"
    query: |
      SELECT
        fa.timestamp AS file_access_time,
        fa.agent_id,
        fa.username,
        fa.file_path,
        fa.file_size,
        nt.timestamp AS network_transfer_time,
        nt.dst_ip,
        nt.dst_domain,
        nt.bytes_sent,
        TIMESTAMPDIFF(SECOND, fa.timestamp, nt.timestamp) AS time_delta
      FROM file_access_events fa
      JOIN network_transfer_events nt
        ON fa.agent_id = nt.agent_id
        AND fa.username = nt.username
        AND nt.timestamp BETWEEN fa.timestamp AND fa.timestamp + INTERVAL 30 MINUTE
      WHERE fa.file_size > 1048576  -- >1MB
        AND nt.bytes_sent > 1048576
        AND nt.dst_ip NOT IN (SELECT ip FROM trusted_destinations)
      ORDER BY time_delta ASC

    high_confidence_pattern:
      - time_delta < 300 seconds (5 minutes)
      - bytes_sent ≈ file_size (±10%)
      - external destination

  compression_then_upload:
    description: "Archive creation followed by upload"
    query: |
      SELECT
        pc.timestamp AS compression_time,
        pc.agent_id,
        pc.username,
        pc.process AS compression_tool,
        pc.file_path AS archive_path,
        nt.timestamp AS upload_time,
        nt.dst_domain,
        nt.bytes_sent
      FROM process_creation pc
      JOIN network_transfer_events nt
        ON pc.agent_id = nt.agent_id
        AND pc.username = nt.username
        AND nt.timestamp BETWEEN pc.timestamp AND pc.timestamp + INTERVAL 10 MINUTE
      WHERE pc.process IN ('7z.exe', 'zip.exe', 'tar', 'rar.exe', 'WinRAR.exe')
        AND nt.dst_domain IN ('drive.google.com', 'dropbox.com', 'onedrive.live.com')

    alert_threshold:
      - archive_size > 100MB
      - time_delta < 600 seconds
      - personal cloud destination

  lateral_movement_then_exfil:
    description: "Lateral movement followed by data access and transfer"
    query: |
      SELECT
        lm.timestamp AS lateral_movement_time,
        lm.src_host,
        lm.dst_host,
        lm.username,
        fa.timestamp AS file_access_time,
        fa.file_path,
        nt.timestamp AS network_transfer_time,
        nt.dst_ip,
        nt.bytes_sent
      FROM lateral_movement_events lm
      JOIN file_access_events fa
        ON lm.dst_host = fa.agent_id
        AND lm.username = fa.username
        AND fa.timestamp > lm.timestamp
      JOIN network_transfer_events nt
        ON fa.agent_id = nt.agent_id
        AND nt.timestamp > fa.timestamp
        AND nt.timestamp < fa.timestamp + INTERVAL 1 HOUR
      WHERE fa.file_path LIKE '%sensitive%'
        OR fa.file_path LIKE '%confidential%'

    killchain_indicator: TRUE  -- High confidence APT activity
```

### Investigation Agent

**Purpose**: Quantify data exposure and assess impact.

```yaml
investigation_agent_functions:

  quantify_data_exposure:
    inputs:
      - agent_id
      - username
      - start_time
      - end_time

    outputs:
      total_files_accessed: ${count}
      total_data_volume: ${bytes}
      unique_destinations: ${list}
      data_classification_breakdown:
        pii_files: ${count}
        phi_files: ${count}
        financial_files: ${count}
        ip_files: ${count}
        credentials_files: ${count}
        unclassified_files: ${count}

    queries:
      - |
        SELECT COUNT(DISTINCT file_path), SUM(file_size)
        FROM file_access_events
        WHERE agent_id = ${agent_id}
          AND username = ${username}
          AND timestamp BETWEEN ${start_time} AND ${end_time}

      - |
        SELECT DISTINCT dst_ip, dst_domain
        FROM network_transfer_events
        WHERE agent_id = ${agent_id}
          AND username = ${username}
          AND timestamp BETWEEN ${start_time} AND ${end_time}

      - |
        SELECT file_path, data_classification, file_size
        FROM file_access_events fa
        JOIN data_classification_catalog dcc
          ON fa.file_path LIKE CONCAT('%', dcc.path_pattern, '%')
        WHERE fa.agent_id = ${agent_id}
          AND fa.timestamp BETWEEN ${start_time} AND ${end_time}

  assess_regulatory_impact:
    inputs:
      - data_classification_breakdown
      - affected_file_list

    outputs:
      gdpr_trigger: ${boolean}
      hipaa_trigger: ${boolean}
      ccpa_trigger: ${boolean}
      pci_trigger: ${boolean}
      estimated_affected_individuals: ${count}
      notification_deadline: ${timestamp}

    logic:
      - IF pii_files > 0 AND contains_eu_data:
          gdpr_trigger = TRUE
          notification_deadline = NOW() + 72 hours

      - IF phi_files > 0:
          hipaa_trigger = TRUE
          notification_deadline = NOW() + 60 days

      - IF pii_files > 0 AND contains_ca_residents:
          ccpa_trigger = TRUE
          notification_deadline = NOW() + reasonable_time

      - IF cardholder_data_files > 0:
          pci_trigger = TRUE
          notification_deadline = IMMEDIATE

      - Estimate affected individuals:
          Query database: SELECT COUNT(DISTINCT customer_id) FROM ${affected_tables}

  destination_analysis:
    inputs:
      - dst_ip
      - dst_domain

    outputs:
      reputation: malicious | suspicious | unknown | legitimate
      category: cloud_storage | webmail | c2 | unknown
      geolocation: ${country}
      first_seen: ${timestamp}
      threat_intel_matches: ${list}

    enrichment_sources:
      - VirusTotal API
      - AbuseIPDB
      - Threat intelligence feeds (MISP, STIX/TAXII)
      - Internal reputation database
      - Cloud provider IP ranges (AWS, Azure, GCP)

  user_behavior_baseline:
    inputs:
      - username
      - baseline_period: 30 days

    outputs:
      normal_data_access_volume: ${bytes_per_day}
      normal_access_hours: ${time_range}
      normal_destinations: ${list}
      deviation_score: ${0-100}

    calculation:
      - Query last 30 days of activity
      - Calculate mean, stddev of data access volume
      - Current incident volume vs baseline:
          IF current > (mean + 3*stddev): HIGH deviation
      - Time-of-day analysis:
          IF access outside normal hours: +20 deviation score
      - Destination analysis:
          IF new destination never seen before: +30 deviation score
```

### Autonomous Approval Logic

```yaml
autonomous_containment_decision:

  block_destination:
    auto_approve_if:
      - threat_intel_reputation = "malicious"
      - AND (
          data_classification IN ("pii", "phi", "pci", "credentials")
          OR deviation_score > 80
        )

    require_human_approval_if:
      - threat_intel_reputation = "unknown"
      - OR legitimate_business_destination = POSSIBLE

  disable_user_account:
    auto_approve_if:
      - confidence_score > 95
      - AND data_classification = "critical"
      - AND (
          user_role != "executive"
          OR after_hours = TRUE
        )

    require_human_approval_if:
      - user_role IN ("executive", "legal", "c-level")
      - OR business_hours = TRUE
      - OR confidence_score < 95

  isolate_host:
    auto_approve_if:
      - active_exfiltration = TRUE
      - AND (
          data_volume > 1GB
          OR data_classification IN ("phi", "pci")
        )
      - AND host_criticality != "critical_business_service"

    require_human_approval_if:
      - host_criticality = "critical_business_service"
      - OR business_impact = "high"
```

## Response Plan

### Investigation Phase (Read-Only - No Approval Required)

#### 1. Quantify Data Exposure

**Automated Investigation Agent Queries:**

```sql
-- Total files accessed
SELECT
  COUNT(DISTINCT file_path) AS file_count,
  SUM(file_size) AS total_bytes,
  MIN(timestamp) AS first_access,
  MAX(timestamp) AS last_access
FROM file_access_events
WHERE agent_id = '${agent_id}'
  AND username = '${username}'
  AND timestamp BETWEEN '${start_time}' AND '${end_time}';

-- Data classification breakdown
SELECT
  dcc.classification,
  COUNT(fa.file_path) AS file_count,
  SUM(fa.file_size) AS total_bytes
FROM file_access_events fa
JOIN data_classification_catalog dcc
  ON fa.file_path LIKE CONCAT('%', dcc.path_pattern, '%')
WHERE fa.agent_id = '${agent_id}'
  AND fa.timestamp BETWEEN '${start_time}' AND '${end_time}'
GROUP BY dcc.classification;

-- Network transfer correlation
SELECT
  dst_ip,
  dst_domain,
  SUM(bytes_sent) AS total_sent,
  COUNT(*) AS connection_count
FROM network_transfer_events
WHERE agent_id = '${agent_id}'
  AND username = '${username}'
  AND timestamp BETWEEN '${start_time}' AND '${end_time}'
GROUP BY dst_ip, dst_domain
ORDER BY total_sent DESC;
```

**Investigation Report Automatically Generated:**
- Total files accessed: ${count}
- Total data volume: ${gb} GB
- Duration: ${hours} hours
- Classification:
  - PII: ${pii_count} files (${pii_gb} GB)
  - PHI: ${phi_count} files (${phi_gb} GB)
  - Financial: ${financial_count} files (${financial_gb} GB)
  - Intellectual Property: ${ip_count} files (${ip_gb} GB)
  - Source Code: ${source_count} files (${source_gb} GB)
  - Credentials: ${cred_count} files
  - Unclassified: ${unclass_count} files

#### 2. Identify Destination

**Automated Enrichment:**

```yaml
destination_analysis:
  ip_address: ${dst_ip}
  domain: ${dst_domain}

  reputation_check:
    virustotal: ${vt_score}/100 malicious
    abuseipdb: ${abuse_confidence}%
    threat_intel_feeds: ${matched_iocs}

  categorization:
    cloud_provider: ${aws|azure|gcp|none}
    service_type: ${cloud_storage|webmail|file_sharing|c2|unknown}
    personal_vs_corporate: ${personal|corporate}

  geolocation:
    country: ${country}
    city: ${city}
    asn: ${asn}
    organization: ${org_name}

  historical_activity:
    first_seen_in_environment: ${timestamp}
    total_connections_last_30d: ${count}
    other_users_accessing: ${user_list}
```

**High-Risk Destinations:**
- Known malicious (threat intel match)
- Newly registered domain (<90 days)
- Foreign adversary country (CN, RU, NK, IR)
- Personal cloud storage (personal Google Drive, Dropbox, OneDrive)
- Competitor infrastructure
- TOR exit nodes
- Anonymization services (VPN providers, proxies)

#### 3. Determine Legitimacy

**Automated Legitimacy Checks:**

```yaml
legitimacy_assessment:

  change_management:
    query_servicenow: "Is there an approved change ticket for data migration?"
    query_jira: "Is there a project ticket for backup/transfer?"
    result: ${ticket_found|no_ticket}

  user_authorization:
    query_iam_system: "Is ${username} authorized to access ${data_type}?"
    check_data_access_matrix: ${authorized|not_authorized}

  manager_awareness:
    query_email_system: "Recent emails mentioning file transfer/backup?"
    result: ${evidence_found|no_evidence}

  business_justification:
    user_role: ${role}
    data_accessed: ${data_type}
    destination: ${destination_type}
    alignment: ${aligned|misaligned}

    examples_aligned:
      - Finance Analyst accessing financial reports → corporate SharePoint
      - HR Manager accessing employee records → approved HRIS system
      - DevOps Engineer accessing source code → GitHub Enterprise

    examples_misaligned:
      - Marketing Coordinator accessing source code → personal Gmail
      - Contractor accessing all customer database → personal Dropbox
      - Sales Rep downloading entire customer list → personal device

  historical_pattern:
    user_baseline_access: ${typical_files_per_day}
    current_incident: ${files_accessed}
    deviation: ${deviation_percentage}%

    first_time_activity: ${boolean}
```

**Legitimacy Score:**
- LIKELY LEGITIMATE (80-100): Change ticket + authorized + business hours + corporate destination
- POSSIBLY LEGITIMATE (50-79): Authorized + within role + some justification
- UNLIKELY LEGITIMATE (20-49): No ticket + outside role + unusual timing
- HIGHLY SUSPICIOUS (0-19): Unauthorized + off-hours + external destination + high volume

### Containment Phase (Approval Required)

All containment actions require approval unless auto-approval criteria met.

#### Option A: Block Network Destination

```yaml
action: block_ip
target: ${destination_ip}
risk_level: LOW
business_impact: Minimal (blocks single external destination)
reversibility: HIGH (easily unblocked)

justification: |
  Block external destination to prevent ongoing/future exfiltration.
  Minimal business impact if destination is not used for legitimate purposes.

conditions_for_execution:
  - external_destination: true
  - not_in_trusted_destinations: true
  - OR reputation: malicious|suspicious

implementation:
  firewall_rule:
    action: deny
    source: ${agent_id} OR any
    destination: ${destination_ip}
    protocol: any
    direction: outbound
    log: true

  duration: permanent OR 24_hours (for investigation)

approval_required:
  - IF reputation = "unknown" AND destination_type = "legitimate_service"
  - ELSE: auto-approved

notification:
  - SOC lead
  - Network operations team
```

#### Option B: Disable User Account

```yaml
action: disable_user
target:
  agent_id: ${agent_id}
  username: ${username}
  domain: ${domain}

risk_level: HIGH
business_impact: HIGH (user cannot work)
reversibility: MEDIUM (requires re-enablement)

justification: |
  Immediately stop potential data theft by disabling user account.
  Prevents further access to systems and data.

conditions_for_execution:
  - confidence_score > 90
  - AND data_classification IN ("pii", "phi", "pci", "credentials")
  - AND (
      user_role NOT IN ("executive", "c-level")
      OR after_hours = TRUE
    )

implementation:
  active_directory:
    action: disable_account
    username: ${username}

  o365:
    action: revoke_all_sessions
    action: block_signin

  vpn:
    action: revoke_access

  email:
    action: set_out_of_office
    message: "This account is temporarily unavailable. Contact IT Security."

approval_required: YES
approver_group: security_operations_manager OR ciso

notification:
  - User's manager
  - HR (if insider threat suspected)
  - Legal (if sensitive data involved)

post_action:
  - Collect forensic evidence from workstation
  - Image user's laptop
  - Preserve email/file access logs
  - Schedule interview (if insider threat)
```

#### Option C: Isolate Host

```yaml
action: isolate_host
target: ${agent_id}

risk_level: MEDIUM-HIGH
business_impact: MEDIUM-HIGH (host offline, user cannot work)
reversibility: MEDIUM (requires manual un-isolation)

justification: |
  Isolate compromised host from network to prevent ongoing exfiltration
  and protect other systems from potential lateral movement.

conditions_for_execution:
  - active_exfiltration_detected: true
  - OR host_compromise_indicators: true
  - AND host_criticality != "tier0_critical"

implementation:
  edr_isolation:
    # CrowdStrike
    - falcon: contain_host(${agent_id})

    # Microsoft Defender
    - mde: isolate_machine(${device_id})

    # SentinelOne
    - s1: disconnect_from_network(${agent_id})

  network_isolation:
    # 802.1X NAC
    - nac: quarantine_vlan(${mac_address})

    # Firewall
    - fw: deny_all_traffic(${ip_address})

  allow_list:
    # Allow connection to management server
    - destination: ${edr_management_server}
    - destination: ${siem_server}
    - destination: ${patch_management_server}

approval_required: YES (unless auto-approval criteria met)

auto_approval_criteria:
  - active_exfiltration = TRUE
  - AND (data_volume > 1GB OR data_classification = "critical")
  - AND host_criticality = "standard"
  - AND business_hours = FALSE

notification:
  - SOC lead
  - User's manager
  - Network operations team
  - System owner (if server)

post_action:
  - Initiate forensic investigation
  - Capture memory dump
  - Capture disk image
  - Collect EDR telemetry
  - Begin incident response
```

#### Option D: Engage Legal/Privacy Immediately

```yaml
action: legal_notification
trigger: AUTOMATIC

conditions_for_automatic_notification:
  - data_classification IN ("pii", "phi", "pci")
  - AND (
      affected_records > 500
      OR data_volume > 100MB
      OR destination_reputation = "malicious"
      OR confidence_score > 80
    )

notification_template: "Legal/Privacy Team Notification (MANDATORY)"

recipients:
  - legal@company.com
  - privacy@company.com
  - dpo@company.com (if GDPR applicable)
  - ciso@company.com

escalation:
  if_no_response_within: 1_hour
  escalate_to: general_counsel

start_regulatory_clock:
  - GDPR: 72-hour clock started at ${detection_timestamp}
  - HIPAA: 60-day clock started at ${detection_timestamp}
  - Document: "Legal notification sent at ${notification_timestamp}"
```

### Immediate Notifications

**Automatic Notifications Sent:**

```yaml
notification_matrix:

  severity_critical:
    - SOC Manager (immediate)
    - CISO (immediate)
    - Legal Team (immediate)
    - Privacy Officer (immediate)
    - Incident Commander (immediate)

  severity_high:
    - SOC Lead (immediate)
    - CISO (within 30 min)
    - Privacy Officer (if PII involved)

  severity_medium:
    - SOC Analyst (immediate)
    - SOC Lead (within 1 hour)

notification_channels:
  - Slack: #security-incidents channel
  - Email: security-alerts@company.com
  - PagerDuty: Critical incidents
  - SMS: CISO (critical only)
  - Phone call: General Counsel (if regulatory trigger)

notification_content:
  - Case ID: ${case_id}
  - Severity: ${severity}
  - Data Classification: ${classification}
  - Estimated Volume: ${volume}
  - User: ${username}
  - Destination: ${destination}
  - Regulatory Trigger: ${yes_no}
  - Action Required: ${action_summary}
```

## Evidence Collection

### Critical Evidence Priority

| Evidence Type | Priority | Volatility | Collection Method |
|---------------|----------|------------|-------------------|
| **Memory dump** | CRITICAL | Highest (lost on reboot) | EDR, DumpIt, WinPMEM |
| **Active network connections** | CRITICAL | High (changes rapidly) | netstat, ss, EDR |
| **Running processes** | CRITICAL | High | ps, tasklist, EDR |
| **DNS cache** | HIGH | Medium | ipconfig /displaydns, resolvectl |
| **File access logs** | HIGH | Low (persisted) | Wazuh FIM, audit logs |
| **Network flow logs** | HIGH | Low (persisted) | NetFlow, firewall logs |
| **Authentication logs** | MEDIUM | Low | Event ID 4624/4625, /var/log/auth.log |
| **Email logs** | MEDIUM | Low | O365 logs, email server logs |

### Evidence Collection Automation

```yaml
automated_evidence_collection:

  trigger: on_incident_creation

  linux_evidence:
    - command: "ps auxwwf > /tmp/evidence/${case_id}/processes.txt"
    - command: "ss -tunap > /tmp/evidence/${case_id}/connections.txt"
    - command: "resolvectl statistics > /tmp/evidence/${case_id}/dns.txt"
    - command: "cp /home/${username}/.bash_history /tmp/evidence/${case_id}/"
    - command: "cp /home/${username}/.ssh/known_hosts /tmp/evidence/${case_id}/"
    - command: "find /home/${username} -type f -mtime -1 > /tmp/evidence/${case_id}/recent_files.txt"

  windows_evidence:
    - powershell: "Get-Process | Export-Csv evidence\${case_id}\processes.csv"
    - powershell: "Get-NetTCPConnection | Export-Csv evidence\${case_id}\connections.csv"
    - powershell: "ipconfig /displaydns > evidence\${case_id}\dns.txt"
    - powershell: "Copy-Item $env:APPDATA\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt evidence\${case_id}\"
    - wevtutil: "wevtutil epl Microsoft-Windows-Sysmon/Operational evidence\${case_id}\sysmon.evtx"

  edr_evidence:
    - crowdstrike: "Get-FalconEvent -DeviceId ${device_id} -Hours 24"
    - microsoft_defender: "Get-MDATPAlert -MachineId ${machine_id}"
    - sentinelone: "Export-S1Timeline -AgentId ${agent_id}"

  network_evidence:
    - firewall_logs: "Export last 24hr of traffic from ${source_ip}"
    - proxy_logs: "Export ${username} activity from ${start_time} to ${end_time}"
    - dns_logs: "Export queries from ${source_ip}"

  cloud_evidence:
    - aws_cloudtrail: "Query S3 API calls by ${iam_user}"
    - azure_monitor: "Export Blob Storage activity"
    - o365_audit_log: "Search-UnifiedAuditLog -UserIds ${email} -StartDate ${start} -EndDate ${end}"

  chain_of_custody:
    - Hash all collected files (SHA256)
    - Timestamp collection
    - Document collector name
    - Store in write-once location
    - Create evidence manifest
```

### Evidence Pack Fields

```json
{
  "case_id": "${case_id}",
  "incident_type": "data_exfiltration",
  "severity": "critical",
  "detection_time": "2026-02-17T14:32:00Z",
  "evidence_collection_time": "2026-02-17T14:45:00Z",

  "exfiltration_details": {
    "method": "cloud_upload|email|network_transfer|usb|dns_tunneling",
    "protocol": "HTTPS|SSH|DNS|ICMP|FTP",
    "tools_used": ["rclone", "7z", "curl"],
    "bypass_techniques": ["encrypted_container", "split_files", "steganography"]
  },

  "destination": {
    "type": "cloud_storage|webmail|c2|unknown",
    "ip_address": "203.0.113.45",
    "domain": "evil-cloud-storage.com",
    "country": "XX",
    "asn": "AS12345",
    "reputation": "malicious|suspicious|unknown|legitimate",
    "threat_intel_matches": ["IOC-12345", "IOC-67890"],
    "categorization": "personal_cloud|corporate_cloud|c2|unknown"
  },

  "data_exposure": {
    "total_volume_bytes": 5368709120,
    "total_file_count": 1523,
    "classification_breakdown": {
      "pii": {"file_count": 450, "volume_bytes": 2147483648, "estimated_records": 125000},
      "phi": {"file_count": 0, "volume_bytes": 0, "estimated_records": 0},
      "pci": {"file_count": 0, "volume_bytes": 0, "estimated_records": 0},
      "financial": {"file_count": 85, "volume_bytes": 536870912},
      "intellectual_property": {"file_count": 12, "volume_bytes": 104857600},
      "source_code": {"file_count": 234, "volume_bytes": 314572800},
      "credentials": {"file_count": 3, "volume_bytes": 12288},
      "unclassified": {"file_count": 739, "volume_bytes": 2252341504}
    },
    "sample_file_paths": [
      "/home/user/Documents/customer_database.xlsx",
      "/home/user/Documents/employee_ssn_list.csv",
      "/home/user/source/proprietary_algorithm.py"
    ],
    "affected_systems": ["fileserver01", "database02", "sharepoint"],
    "affected_data_owners": ["Sales", "HR", "Engineering"]
  },

  "user_context": {
    "username": "jdoe",
    "full_name": "John Doe",
    "email": "jdoe@company.com",
    "department": "Sales",
    "title": "Account Executive",
    "manager": "Jane Manager",
    "employment_status": "active|notice_period|terminated",
    "start_date": "2020-03-15",
    "authorized_data_access": false,
    "normal_access_pattern": false,
    "deviation_score": 95,
    "prior_security_incidents": 1,
    "privileged_access": false
  },

  "timeline": {
    "first_suspicious_activity": "2026-02-17T10:15:00Z",
    "first_file_access": "2026-02-17T10:30:00Z",
    "archive_creation": "2026-02-17T12:45:00Z",
    "exfiltration_started": "2026-02-17T13:00:00Z",
    "exfiltration_ended": "2026-02-17T14:20:00Z",
    "detection": "2026-02-17T14:32:00Z",
    "containment": "2026-02-17T14:50:00Z",
    "total_duration_hours": 4.25,
    "exfiltration_duration_hours": 1.33
  },

  "indicators_of_compromise": {
    "ip_addresses": ["203.0.113.45", "198.51.100.78"],
    "domains": ["evil-cloud-storage.com", "c2-server.net"],
    "file_hashes": {
      "sha256": ["e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"]
    },
    "urls": ["https://evil-cloud-storage.com/upload"],
    "user_agents": ["rclone/v1.55.0"],
    "processes": ["rclone.exe", "7z.exe", "curl.exe"]
  },

  "regulatory_assessment": {
    "gdpr_trigger": true,
    "gdpr_notification_deadline": "2026-02-20T14:32:00Z",
    "hipaa_trigger": false,
    "ccpa_trigger": true,
    "pci_trigger": false,
    "sec_trigger": false,
    "state_laws_triggered": ["California AB 1950", "New York SHIELD"],
    "estimated_affected_individuals": 125000,
    "breach_notification_required": true,
    "notification_jurisdictions": ["US-CA", "US-NY", "EU"]
  },

  "forensic_artifacts": {
    "memory_dump": "/evidence/case-12345/memory.dmp",
    "disk_image": "/evidence/case-12345/disk.e01",
    "packet_capture": "/evidence/case-12345/exfil.pcap",
    "process_list": "/evidence/case-12345/processes.txt",
    "network_connections": "/evidence/case-12345/connections.txt",
    "bash_history": "/evidence/case-12345/bash_history",
    "powershell_history": "/evidence/case-12345/ps_history.txt",
    "browser_history": "/evidence/case-12345/chrome_history.db",
    "sysmon_logs": "/evidence/case-12345/sysmon.evtx",
    "edr_timeline": "/evidence/case-12345/edr_timeline.json"
  },

  "response_actions": {
    "user_account_disabled": true,
    "host_isolated": true,
    "destination_blocked": true,
    "legal_notified": true,
    "law_enforcement_notified": false,
    "cyber_insurance_notified": false,
    "external_counsel_engaged": false,
    "forensic_firm_engaged": false
  },

  "chain_of_custody": [
    {
      "timestamp": "2026-02-17T14:45:00Z",
      "action": "Evidence collected",
      "custodian": "SOC Analyst - Alice Smith",
      "hash": "sha256:abc123..."
    },
    {
      "timestamp": "2026-02-17T15:00:00Z",
      "action": "Evidence transferred to forensic storage",
      "custodian": "Forensic Analyst - Bob Jones",
      "hash": "sha256:abc123..."
    }
  ]
}
```

## Approval Request Template (Slack/Teams)

```
🚨 **CRITICAL - DATA EXFILTRATION DETECTED** 🚨

**Case ID:** ${case_id}
**Severity:** ${severity}
**Status:** ${active_or_contained}

---

**📊 INCIDENT SUMMARY**

**User:** ${username} (${full_name})
**Department:** ${department} | **Title:** ${title}
**Host:** ${hostname} (${agent_id})
**Detection Time:** ${detection_timestamp}

---

**🔐 DATA EXPOSURE**

**Classification:** ${data_classification}
- PII: ${pii_count} files (~${pii_records} records)
- PHI: ${phi_count} files
- Financial: ${financial_count} files
- Source Code: ${source_count} files
- Credentials: ${credentials_count} files

**Total Volume:** ${data_volume_gb} GB (${total_file_count} files)
**Sample Files:**
• ${sample_file_1}
• ${sample_file_2}
• ${sample_file_3}

---

**🌐 DESTINATION ANALYSIS**

**Destination:** ${destination}
**IP Address:** ${dst_ip} (${country})
**Reputation:** ${reputation} ⚠️
**Category:** ${category}
**Threat Intel:** ${threat_intel_matches}

---

**📅 TIMELINE**

• First Activity: ${first_activity_time}
• Exfiltration Started: ${exfil_start_time}
• Detection: ${detection_time}
• Duration: ${duration_hours} hours
• Status: ${active_or_stopped}

---

**👤 USER CONTEXT**

**Authorization:** ❌ NOT authorized for this data
**Access Pattern:** ⚠️ Abnormal (95% deviation from baseline)
**Time:** 🌙 Off-hours access (2:30 AM)
**Employment:** ${employment_status}
**Prior Incidents:** ${prior_incident_count}

---

**⚖️ REGULATORY IMPACT**

**Breach Notification:** ⚠️ LIKELY REQUIRED

- **GDPR:** YES - 72hr deadline: ${gdpr_deadline}
- **CCPA:** YES - California residents affected
- **HIPAA:** ${hipaa_yes_no}
- **PCI-DSS:** ${pci_yes_no}

**Estimated Affected Individuals:** ${affected_count}

**⚠️ LEGAL NOTIFICATION:** Already sent at ${legal_notification_time}

---

**🎯 RECOMMENDED ACTIONS**

**1. Disable User Account** (HIGH impact)
- Stops all user access immediately
- Business Impact: User cannot work
- Reversibility: Can be re-enabled

**2. Isolate Host** (MEDIUM impact)
- Prevents further exfiltration
- Business Impact: Host offline
- Reversibility: Can be un-isolated

**3. Block Destination** (LOW impact)
- Blocks ${destination_ip}
- Business Impact: Minimal
- Reversibility: Easily reversed

**Confidence Score:** ${confidence_score}/100

---

**⚠️ RISK IF NOT CONTAINED**

- Ongoing exfiltration of sensitive data
- Regulatory penalties (GDPR: up to €20M or 4% revenue)
- Customer notification required
- Reputation damage
- Potential lawsuits

---

**⏰ DEADLINE:** Legal notification clock is RUNNING
- GDPR deadline: ${hours_remaining} hours remaining
- Recommended containment: IMMEDIATE

---

**👥 NOTIFICATIONS SENT**

✅ CISO
✅ Legal Team
✅ Privacy Officer
${if_applicable} ✅ HR Team
${if_applicable} ✅ User's Manager

---

**🔗 ACTIONS**

[Approve All Containment Actions] [Approve User Disable Only] [Approve Destination Block Only]

[Deny - Continue Monitoring] [Escalate to CISO] [Escalate to Legal]

---

**📞 INCIDENT COMMANDER**

${ic_name}
📧 ${ic_email} | 📱 ${ic_phone}

**Next Update:** ${next_update_time}
```

## False Positive Handling

### Common False Positives

| Pattern | Likely Benign When | How to Verify |
|---------|-------------------|---------------|
| **Large cloud uploads** | - Approved cloud backup service<br>- Scheduled backup job<br>- Authorized cloud sync | - Check change management tickets<br>- Verify backup schedule<br>- Confirm approved cloud services list |
| **Bulk file access** | - Authorized data migration<br>- Database backup job<br>- Compliance data collection | - Check project tickets (Jira, ServiceNow)<br>- Verify with data owner<br>- Check scheduled job logs |
| **High DNS volume** | - Legitimate cloud services (AWS, Azure, GCP)<br>- CDN activity (Akamai, Cloudflare)<br>- Load balancer health checks | - Check destination domains<br>- Verify service accounts<br>- Review application architecture |
| **Archive creation** | - Standard IT backup procedures<br>- Software builds (CI/CD)<br>- Log rotation/archival | - Check backup software logs<br>- Verify CI/CD pipeline<br>- Confirm with IT operations |
| **Off-hours activity** | - Global teams (different time zones)<br>- Scheduled maintenance windows<br>- On-call engineers | - Check user's time zone<br>- Verify maintenance calendar<br>- Confirm on-call schedule |
| **SFTP/SCP transfers** | - Authorized file transfers to partners<br>- Automated EDI processes<br>- B2B integrations | - Check partner agreements<br>- Verify EDI configuration<br>- Review integration documentation |

### Investigation Checklist for Potential False Positives

```yaml
false_positive_verification:

  step_1_check_change_management:
    - Query ServiceNow for open change tickets
    - Search Jira for project tickets mentioning data migration/backup
    - Check IT operations calendar for scheduled maintenance
    - Result: ${ticket_found | no_ticket}

  step_2_verify_user_authorization:
    - Check user's role and responsibilities
    - Review data access authorization matrix
    - Verify business justification with user's manager
    - Result: ${authorized | not_authorized}

  step_3_confirm_destination:
    - Check approved cloud services list
    - Verify if destination is known business partner
    - Check IT asset inventory for legitimate services
    - Result: ${approved_destination | unknown_destination}

  step_4_validate_timing:
    - Check if scheduled job (cron, Task Scheduler)
    - Verify user's time zone (may be business hours for them)
    - Check on-call rotation schedule
    - Result: ${scheduled_activity | ad_hoc_activity}

  step_5_historical_pattern:
    - Has this user done this before?
    - Is this a recurring pattern (weekly, monthly)?
    - Does this match historical baselines?
    - Result: ${normal_pattern | first_time}

  step_6_contact_user_manager:
    - Email or call user's direct manager
    - Ask: "Are you aware of ${username} transferring ${data_volume} of data to ${destination}?"
    - Document response
    - Result: ${manager_aware | manager_unaware}

decision_matrix:
  likely_false_positive:
    - ticket_found = TRUE
    - AND authorized = TRUE
    - AND approved_destination = TRUE

  likely_true_positive:
    - no_ticket = TRUE
    - AND (not_authorized = TRUE OR unknown_destination = TRUE)
    - AND manager_unaware = TRUE
```

### Whitelisting Process

If confirmed false positive, add to whitelist to prevent future alerts:

```yaml
whitelist_entry:
  type: scheduled_backup | approved_cloud_sync | authorized_migration

  criteria:
    user: ${username}
    source_host: ${hostname}
    destination: ${destination_domain}
    process: ${process_name}
    schedule: ${cron_schedule}

  approval:
    requested_by: ${analyst_name}
    approved_by: ${manager_name}
    approval_date: ${date}
    review_date: ${date + 90 days}

  wazuh_rule_exception:
    <rule id="87999" level="0">
      <if_matched_sid>87450</if_matched_sid>
      <user>${username}</user>
      <url>${destination_domain}</url>
      <time>02:00:00-04:00:00</time>
      <description>Whitelisted: Approved nightly backup to corporate cloud</description>
    </rule>
```

## Post-Incident Activities

### Immediate (0-24 hours)

```yaml
immediate_actions:

  evidence_preservation:
    - [X] All forensic evidence collected and hashed
    - [X] Chain of custody documentation complete
    - [X] Evidence stored in write-once location
    - [X] EDR timeline exported
    - [X] Memory dump captured
    - [ ] Disk image captured (if required)

  scope_documentation:
    - [X] Total data volume quantified
    - [X] Data classification completed
    - [X] Affected systems identified
    - [X] Timeline constructed
    - [X] Estimated affected individuals calculated

  legal_engagement:
    - [X] Legal team notified
    - [X] Privacy officer notified
    - [X] Breach assessment initiated
    - [ ] External counsel engaged (if required)
    - [ ] Cyber insurance carrier notified

  containment_verification:
    - [X] User account disabled
    - [X] Host isolated
    - [X] Destination blocked
    - [ ] Data retrieval attempted
    - [ ] Exfiltration confirmed stopped

  initial_notifications:
    - [X] CISO briefed
    - [X] Incident response team assembled
    - [ ] Board notification (if material)
    - [ ] Regulatory pre-notification (if relationship exists)
```

### Short-term (24 hours - 7 days)

```yaml
short_term_actions:

  root_cause_analysis:
    - [ ] How did attacker gain initial access?
    - [ ] What vulnerabilities were exploited?
    - [ ] What controls failed?
    - [ ] Was this insider threat or external compromise?
    - [ ] Deliverable: RCA report

  full_scope_identification:
    - [ ] All compromised systems identified
    - [ ] All accessed data cataloged
    - [ ] All exfiltrated data confirmed
    - [ ] All affected individuals identified
    - [ ] Deliverable: Complete data inventory

  breach_notification_preparation:
    - [ ] Regulatory notification requirements finalized
    - [ ] Notification templates drafted
    - [ ] Affected individual list compiled
    - [ ] Call center resources arranged (if large breach)
    - [ ] Credit monitoring vendor engaged (if offering)
    - [ ] Deliverable: Notification strategy

  regulatory_notifications:
    - [ ] GDPR DPA notification (if applicable, 72hr deadline)
    - [ ] HHS OCR notification (if HIPAA, 60 day deadline for >500)
    - [ ] State AG notifications (per state law)
    - [ ] Payment brands (if PCI, immediate)
    - [ ] SEC 8-K filing (if material, 4 business days)

  affected_individual_notification:
    - [ ] Notification letters drafted and approved by legal
    - [ ] Mailing service engaged
    - [ ] Email notification prepared (if permitted)
    - [ ] Dedicated hotline established
    - [ ] FAQ prepared
    - [ ] Credit monitoring enrollment codes generated

  public_relations:
    - [ ] PR team briefed
    - [ ] Media statement prepared
    - [ ] Spokesperson designated
    - [ ] Social media response plan
    - [ ] Customer communication plan
```

### Long-term (7+ days)

```yaml
long_term_actions:

  security_improvements:
    dlp_enhancements:
      - [ ] Review DLP policies
      - [ ] Add new detection rules for missed patterns
      - [ ] Increase coverage to additional systems
      - [ ] Implement additional content inspection

    user_activity_monitoring:
      - [ ] Deploy UEBA (User and Entity Behavior Analytics)
      - [ ] Enhance file access auditing
      - [ ] Implement database activity monitoring
      - [ ] Increase cloud access monitoring

    network_controls:
      - [ ] Review firewall rules (deny-by-default)
      - [ ] Implement DNS filtering
      - [ ] Deploy TLS inspection
      - [ ] Segment network (zero trust principles)

    access_controls:
      - [ ] Review data access permissions (least privilege)
      - [ ] Implement PAM (Privileged Access Management)
      - [ ] Enforce MFA for sensitive data access
      - [ ] Implement just-in-time access

  process_improvements:
    - [ ] Update incident response playbook based on lessons learned
    - [ ] Update data classification program
    - [ ] Enhance employee offboarding process
    - [ ] Improve change management for data migrations
    - [ ] Implement insider threat program

  training:
    - [ ] Security awareness training on data handling
    - [ ] Insider threat indicators training for managers
    - [ ] Incident response tabletop exercise
    - [ ] Data classification training

  compliance:
    - [ ] Update risk register
    - [ ] Update breach log (GDPR Art. 33(5))
    - [ ] Board reporting
    - [ ] Audit committee briefing
    - [ ] Update cybersecurity insurance application

  lessons_learned:
    - [ ] Conduct post-incident review
    - [ ] Document what worked well
    - [ ] Document what needs improvement
    - [ ] Update playbooks
    - [ ] Share lessons with industry peers (anonymized)
```

## Enhanced SLA/KPI

### Service Level Agreements

| Phase | Activity | SLA | Measurement |
|-------|----------|-----|-------------|
| **Detection** | Alert generated → SOC aware | **<10 min** | Alert timestamp → Acknowledged timestamp |
| **Triage** | SOC aware → Severity assessed | **<15 min** | Acknowledged → Severity assigned |
| **Scope Assessment** | Severity assigned → Data exposure quantified | **<30 min** | Automated investigation agent completion |
| **Decision** | Scope known → Containment decision | **<20 min** | Scope complete → Approval request sent |
| **Containment** | Approval granted → Action executed | **<10 min** | Approval → Action confirmed |
| **Legal Notification** | Critical data detected → Legal notified | **<4 hrs** | Detection → Legal notification sent |
| **CISO Briefing** | Critical incident → CISO briefed | **<1 hr** | Detection → CISO briefed |
| **Total MTTC** | Detection → Full containment | **<1 hr** | Detection → All containment actions complete |

### Key Performance Indicators (KPIs)

```yaml
detection_kpis:
  mean_time_to_detect: <10 minutes
  detection_coverage: >95% of MITRE ATT&CK exfiltration techniques
  false_positive_rate: <10%

response_kpis:
  mean_time_to_triage: <15 minutes
  mean_time_to_scope: <30 minutes
  mean_time_to_contain: <60 minutes
  mean_time_to_legal_notification: <4 hours

  containment_success_rate: >95%
  autonomous_containment_rate: >60% (auto-approval)

breach_notification_kpis:
  gdpr_72hr_compliance: 100%
  hipaa_60day_compliance: 100%
  state_law_compliance: 100%

  mean_time_to_regulatory_notification: <48 hours
  mean_time_to_individual_notification: <14 days

quality_kpis:
  evidence_preservation_rate: 100%
  chain_of_custody_compliance: 100%
  playbook_adherence: >90%

  post_incident_review_completion: 100%
  lessons_learned_documentation: 100%

efficiency_kpis:
  investigation_agent_usage: >80% of cases
  correlation_agent_usage: >90% of cases

  manual_investigation_time_saved: >50%
  analyst_efficiency_improvement: >40%
```

### Escalation Matrix

| Time Elapsed | If Not Contained | Escalate To |
|--------------|------------------|-------------|
| **1 hour** | Still investigating | SOC Manager |
| **2 hours** | Not contained | CISO |
| **4 hours** | Active exfiltration continuing | CISO + Legal + CEO |
| **24 hours** | Scope unknown | External incident response firm |
| **48 hours** | Approaching GDPR deadline | General Counsel + DPO + External counsel |

### Reporting Dashboard Metrics

```yaml
soc_dashboard_metrics:

  real_time:
    - Active data exfiltration cases: ${count}
    - Cases pending containment: ${count}
    - Cases pending approval: ${count}
    - Legal notifications sent today: ${count}

  daily:
    - Data exfiltration detections: ${count}
    - True positives: ${count}
    - False positives: ${count}
    - False positive rate: ${percentage}%
    - Mean time to detect: ${minutes} min
    - Mean time to contain: ${minutes} min

  weekly:
    - Total data volume at risk: ${gb} GB
    - PII/PHI/PCI exposure incidents: ${count}
    - Regulatory notifications triggered: ${count}
    - Insider threat cases: ${count}
    - External compromise cases: ${count}

  monthly:
    - Trend: Increasing / Stable / Decreasing
    - Top exfiltration methods: ${list}
    - Top targeted data types: ${list}
    - Top user departments involved: ${list}
    - SLA compliance rate: ${percentage}%
    - KPI achievement: ${percentage}%
```

## References and Resources

### Regulatory Guidance

| Regulation | Official Guidance | Link |
|------------|-------------------|------|
| **GDPR** | Art. 33 & 34 - Personal data breach notification | https://gdpr-info.eu/art-33-gdpr/ |
| **GDPR** | WP29 Guidelines on Personal Data Breach Notification | https://ec.europa.eu/newsroom/article29/items/612052 |
| **HIPAA** | Breach Notification Rule | https://www.hhs.gov/hipaa/for-professionals/breach-notification/ |
| **CCPA** | California Civil Code 1798.82 | https://leginfo.legislature.ca.gov/faces/codes_displaySection.xhtml?sectionNum=1798.82&lawCode=CIV |
| **PCI-DSS** | Incident Response Requirements 12.10 | https://www.pcisecuritystandards.org/ |
| **SEC** | Cybersecurity Risk Management, Strategy, Governance (Form 8-K) | https://www.sec.gov/files/rules/final/2023/33-11216.pdf |

### MITRE ATT&CK

- **Exfiltration Tactic (TA0010)**: https://attack.mitre.org/tactics/TA0010/
- **T1041 - Exfiltration Over C2 Channel**: https://attack.mitre.org/techniques/T1041/
- **T1048 - Exfiltration Over Alternative Protocol**: https://attack.mitre.org/techniques/T1048/
- **T1567 - Exfiltration Over Web Service**: https://attack.mitre.org/techniques/T1567/
- **T1030 - Data Transfer Size Limits**: https://attack.mitre.org/techniques/T1030/
- **T1052 - Exfiltration Over Physical Medium**: https://attack.mitre.org/techniques/T1052/

### Industry Standards

- **NIST SP 800-53 Rev. 5**: Security and Privacy Controls (SC-7 Boundary Protection, SI-4 System Monitoring)
- **NIST SP 800-61 Rev. 2**: Computer Security Incident Handling Guide
- **NIST Cybersecurity Framework**: Detect (DE), Respond (RS)
- **ISO/IEC 27001:2022**: Information Security Management (A.5.24 - Information security incident management planning and preparation)
- **ISO/IEC 27035**: Information security incident management
- **CIS Controls**: Control 13 (Network Monitoring and Defense), Control 14 (Security Awareness Training)

### Tools and Technologies

**DNS Tunneling Detection:**
- iodine: https://github.com/yarrick/iodine
- dnscat2: https://github.com/iagox86/dnscat2
- Detection: https://github.com/ahlashkari/CICFlowMeter

**DLP Solutions:**
- Symantec DLP
- McAfee Total Protection for DLP
- Forcepoint DLP
- Microsoft Purview DLP

**UEBA/Behavioral Analytics:**
- Exabeam
- Securonix
- Splunk UBA
- Microsoft Sentinel UEBA

### Forensic Resources

- **SANS Digital Forensics**: https://www.sans.org/digital-forensics-incident-response/
- **Sysmon Configuration**: https://github.com/SwiftOnSecurity/sysmon-config
- **Windows Event Log Reference**: https://www.ultimatewindowssecurity.com/securitylog/encyclopedia/
- **Linux Audit Framework**: https://github.com/linux-audit/audit-documentation

### Breach Notification Resources

- **State Breach Notification Laws**: https://www.ncsl.org/technology-and-communication/security-breach-notification-laws
- **DLA Piper Data Breach Laws of the World**: https://www.dlapiperdataprotection.com/
- **IAPP Resource Center**: https://iapp.org/resources/

---

## Document Version History

| Version | Date | Changes | Author |
|---------|------|---------|--------|
| 2.0.0 | 2026-02-17 | Complete rewrite: Added 11 MITRE techniques, comprehensive Wazuh rules, DLP bypass detection, regulatory compliance (GDPR/HIPAA/CCPA/PCI/SEC), legal notification templates, forensic artifacts (Linux/Windows), data classification integration, decision tree, agent pipeline integration, enhanced SLA (<10min detection, <1hr containment, <4hr legal notification) | Autopilot Security Team |
| 1.0.0 | 2025-XX-XX | Initial version | Original Author |

---

**END OF PLAYBOOK PB-004 v2.0.0**

*This playbook is a living document and should be reviewed quarterly or after each significant data exfiltration incident.*

*For questions or updates, contact: security-operations@company.com*
