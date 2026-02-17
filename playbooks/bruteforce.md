# Playbook: Brute Force Attack Response

## Document Control

| Field | Value |
|-------|-------|
| Playbook ID | PB-001 |
| Version | 2.0.0 |
| Classification | TLP:AMBER |
| Distribution | Internal SOC Use Only - Do Not Distribute Outside Organization |
| Last Updated | 2026-02-17 |
| Next Review | 2026-05-17 |
| Owner | Security Operations Center |
| Approver | CISO / Security Director |

## Overview

| Field | Value |
|-------|-------|
| Severity | High (Elevated to Critical if Successful) |
| MITRE ATT&CK | T1110 - Brute Force (All Sub-Techniques) |
| Primary Objective | Detect, contain, and eradicate unauthorized authentication attempts |
| Automation Level | Semi-Automated (Human-in-the-Loop Required for Containment) |

## Executive Summary

This playbook provides comprehensive procedures for detecting, analyzing, containing, eradicating, and recovering from brute force authentication attacks. Brute force attacks represent a persistent threat to organizational security, targeting authentication mechanisms across SSH, RDP, web applications, and other services. This playbook aligns with NIST 800-61r2 incident response lifecycle and integrates with the Wazuh Autopilot agent pipeline for automated detection and triage.

### Attack Definition
A brute force attack is a trial-and-error method used to obtain authentication credentials by systematically checking all possible passwords or keys until the correct one is found. Modern variants include distributed attacks, password spraying, and credential stuffing.

## MITRE ATT&CK Mapping

### Primary Technique: T1110 - Brute Force

#### T1110.001 - Password Guessing
**Description**: Adversaries try common passwords against authentication interfaces.

**Detection Signatures**:
- Sequential authentication failures with common password patterns
- Dictionary-based login attempts
- Use of default credentials (admin/admin, root/root)
- Failed attempts against well-known administrative accounts

**Wazuh Rules**: 5710, 5711, 5712, 5720, 60100-60105

#### T1110.002 - Password Cracking
**Description**: Adversaries use offline password cracking against captured hashes.

**Detection Signatures**:
- Unusual access to password hash files (SAM, /etc/shadow)
- Process execution of password cracking tools (John the Ripper, Hashcat)
- Elevated CPU usage patterns consistent with hash computation
- Memory dumps targeting LSASS or authentication processes

**Wazuh Rules**: 2501, 2502, 18105, 18106

#### T1110.003 - Password Spraying
**Description**: Adversaries try a single password against multiple accounts to avoid lockouts.

**Detection Signatures**:
- Single source IP attempting authentication against multiple accounts
- Failed login attempts with same password across different users
- Low-frequency attempts per account (below lockout threshold)
- Time-distributed attempts to evade rate limiting

**Wazuh Rules**: 5763, 5764, 60110-60115

#### T1110.004 - Credential Stuffing
**Description**: Adversaries use known username/password pairs from data breaches.

**Detection Signatures**:
- Authentication attempts with valid username formats
- Failed logins from multiple source IPs for same account
- Credential pairs matching known breach databases
- Automated client behaviors (missing cookies, unusual user-agents)

**Wazuh Rules**: 60120-60125, Custom Rules Required

## Detection Criteria

### Wazuh Rule Coverage

#### SSH Authentication Rules
| Rule ID | Severity | Description | Detection Logic |
|---------|----------|-------------|----------------|
| 5503 | 3 | User login failed | Single failed SSH login |
| 5551 | 10 | Multiple authentication failures | 4+ failures in 360s |
| 5710 | 5 | Attempt to login using non-existent user | Invalid username attempt |
| 5711 | 5 | sshd: Authentication failure | PAM authentication denied |
| 5712 | 10 | sshd: Excessive authentication failures | 8+ failures from same source |
| 5716 | 10 | sshd: Brute force trying to get access | Multiple users targeted |
| 5720 | 10 | PAM: Multiple failed logins | PAM module reports repeated failures |
| 5760 | 8 | sshd: insecure connection attempt (scan) | Protocol scanning detected |
| 5761 | 8 | sshd: Possible attack on the ssh server | Unusual SSH traffic pattern |
| 5763 | 10 | sshd: Brute force attack | Composite rule - multiple indicators |
| 5764 | 12 | sshd: Possible attack in progress | Active ongoing attack |

#### PAM Authentication Rules
| Rule ID | Severity | Description | Detection Logic |
|---------|----------|-------------|----------------|
| 2501 | 3 | User authentication failure | Generic PAM failure |
| 2502 | 10 | User missed the password more than once | Multiple PAM failures |

#### Windows Authentication Rules
| Rule ID | Severity | Description | Event ID |
|---------|----------|-------------|----------|
| 18100 | 3 | Windows: User login failed | 4625 |
| 18101 | 5 | Windows: Multiple failed login attempts | 4625 (composite) |
| 18102 | 10 | Windows: Account lockout | 4740 |
| 18103 | 8 | Windows: Kerberos authentication failure | 4771 |
| 18104 | 8 | Windows: Credential validation failure | 4776 |
| 18105 | 10 | Windows: Multiple lockouts detected | 4740 (composite) |
| 18106 | 12 | Windows: Brute force attack detected | Multiple 4625 events |

#### Web Application Authentication Rules
| Rule ID | Severity | Description | Detection Logic |
|---------|----------|-------------|----------------|
| 60100 | 3 | Web authentication failure | HTTP 401/403 responses |
| 60101 | 5 | Multiple web auth failures | 5+ failures in 120s |
| 60102 | 8 | Web login brute force detected | 10+ failures from single IP |
| 60103 | 8 | Web password spraying detected | Multiple accounts targeted |
| 60110 | 10 | Web application under authentication attack | Composite indicators |
| 60115 | 10 | Credential stuffing attack detected | Multiple IPs, valid usernames |
| 60120-60199 | Variable | Custom web application rules | Organization-specific |

### Custom Rule Requirements

For comprehensive detection, organizations should implement custom rules for:

1. **Application-Specific Authentication**: Custom application login failures
2. **API Authentication**: API key and token brute force attempts
3. **Database Authentication**: Direct database connection failures
4. **VPN Authentication**: VPN client authentication failures
5. **Cloud Service Authentication**: AWS, Azure, GCP login failures
6. **Multi-Factor Authentication**: MFA bypass attempts

### Primary Detection Thresholds

| Attack Type | Threshold | Time Window | Severity |
|-------------|-----------|-------------|----------|
| Single Source - Single User | 5 failures | 2 minutes | Medium |
| Single Source - Multiple Users | 3 failures per user | 10 minutes | High |
| Multiple Sources - Single User | 10 failures | 5 minutes | High |
| Multiple Sources - Multiple Users | 20 failures | 15 minutes | Critical |
| Successful Login After Failures | 1 success | 1 hour | Critical |
| Internal Source Attacks | 3 failures | 5 minutes | Critical |

## Decision Tree: Brute Force Attack Triage

```
┌─────────────────────────────────┐
│  Brute Force Alert Triggered    │
│  (Wazuh Autopilot: triage-agent)│
└────────────┬────────────────────┘
             │
             ▼
    ┌────────────────────┐
    │ Extract Entities:  │
    │ - Source IP(s)     │
    │ - Target User(s)   │
    │ - Target Host(s)   │
    │ - Auth Method      │
    └────────┬───────────┘
             │
             ▼
    ┌──────────────────────┐
    │ Attack Pattern?       │
    └──┬──────────┬────────┘
       │          │
       ▼          ▼
   Single      Multiple
   Source      Sources
       │          │
       │          └──────────────┐
       ▼                         ▼
┌─────────────┐         ┌──────────────────┐
│ Target      │         │ DISTRIBUTED       │
│ Scope?      │         │ ATTACK            │
└─┬──────┬────┘         │                   │
  │      │              │ Indicators:       │
  ▼      ▼              │ - Botnet          │
Single  Multiple        │ - Credential      │
User    Users          │   Stuffing        │
  │      │              │                   │
  │      └─────┐        │ Auto-Action:      │
  │            │        │ → GeoIP analysis  │
  │            ▼        │ → Rate limiting   │
  │     ┌───────────┐   │ → WAF rules       │
  │     │ PASSWORD  │   └────────┬──────────┘
  │     │ SPRAYING  │            │
  │     │           │            │
  │     │ Risk:     │            │
  │     │ HIGH      │◄───────────┘
  │     └─────┬─────┘
  │           │
  └───────────┼────────────┐
              │            │
              ▼            ▼
      ┌───────────┐  ┌──────────────┐
      │ Auth      │  │ Attack       │
      │ Method?   │  │ Outcome?     │
      └─┬────┬────┘  └──┬────────┬──┘
        │    │          │        │
        ▼    ▼          ▼        ▼
    Password Key    Success   Failure
      Auth   Auth     Only      Only
        │    │          │        │
        │    └──┐       │        │
        │       │       │        │
        ▼       ▼       ▼        ▼
    ┌──────┐ ┌────┐ ┌─────┐ ┌────────┐
    │Common│ │SSH │ │CRIT │ │Block IP│
    │Attack│ │Key │ │CASE │ │Monitor │
    └──┬───┘ └─┬──┘ └──┬──┘ └───┬────┘
       │       │       │        │
       └───────┴───────┴────────┘
                 │
                 ▼
        ┌─────────────────┐
        │ Source Location? │
        └────┬────────┬────┘
             │        │
             ▼        ▼
        Internal  External
             │        │
             │        │
             ▼        ▼
      ┌──────────┐ ┌──────────┐
      │ CRITICAL │ │ Threat   │
      │ Priority │ │ Intel    │
      │          │ │ Lookup   │
      │ Actions: │ │          │
      │ 1.Isolate│ │ Check:   │
      │ 2.EDR    │ │ - AbuseIP│
      │ 3.Contain│ │ - VirusT │
      │ 4.Hunt   │ │ - OTX    │
      └────┬─────┘ └────┬─────┘
           │            │
           └──────┬─────┘
                  │
                  ▼
        ┌──────────────────────┐
        │ Privileged Account?   │
        └───┬──────────────┬────┘
            │              │
            ▼              ▼
          YES             NO
            │              │
            ▼              │
    ┌──────────────┐       │
    │ ESCALATE     │       │
    │ Severity +2  │       │
    │              │       │
    │ Notify:      │       │
    │ - SOC Lead   │       │
    │ - CISO       │       │
    │ - IT Sec     │       │
    └──────┬───────┘       │
           │               │
           └───────┬───────┘
                   │
                   ▼
        ┌────────────────────────┐
        │ Correlation Check       │
        │ (correlation-agent)     │
        │                         │
        │ Look for:               │
        │ - Related alerts        │
        │ - Historical patterns   │
        │ - IOC matches           │
        │ - Threat campaigns      │
        └────────┬────────────────┘
                 │
                 ▼
        ┌─────────────────────────┐
        │ Generate Response Plan   │
        │ (response-planner-agent) │
        │                          │
        │ Options:                 │
        │ 1. Block source IP       │
        │ 2. Rate limit target     │
        │ 3. Isolate host          │
        │ 4. Disable account       │
        │ 5. Force MFA             │
        └────────┬─────────────────┘
                 │
                 ▼
        ┌──────────────────────┐
        │ Human Approval       │
        │ (policy-guard-agent) │
        │                      │
        │ Risk Assessment      │
        │ Business Impact      │
        └────┬────────────┬────┘
             │            │
             ▼            ▼
        [APPROVE]    [DENY]
             │            │
             ▼            └────────┐
    ┌────────────────┐             │
    │ Execute Actions│             │
    │ (responder)    │             │
    └────────┬───────┘             │
             │                     │
             ▼                     ▼
    ┌─────────────────┐   ┌────────────────┐
    │ Monitor Results │   │ Additional     │
    │ Generate Report │   │ Investigation  │
    │ (reporting)     │   │ (investigation)│
    └─────────────────┘   └────────────────┘
```

## Automated Triage Steps

### Phase 1: Entity Extraction (triage-agent)

```yaml
entities:
  - type: ip
    source: data.srcip
    enrichment:
      - geoip
      - reputation
      - historical_activity
      - internal_asset_check

  - type: user
    source: data.dstuser
    enrichment:
      - account_validity
      - privilege_level
      - department
      - normal_login_locations
      - last_successful_login

  - type: host
    source: agent.name
    enrichment:
      - asset_criticality
      - running_services
      - patch_status
      - edr_status

  - type: service
    source: data.port
    enrichment:
      - service_type
      - version
      - known_vulnerabilities
```

### Phase 2: Context Enrichment (correlation-agent)

**Historical Analysis**:
```yaml
historical_queries:
  - name: previous_attacks
    query: "data.srcip:${source_ip}"
    timerange: 7d
    threshold: 3

  - name: successful_logins
    query: "data.srcip:${source_ip} AND rule.groups:authentication_success"
    timerange: 24h

  - name: targeted_accounts
    query: "rule.id:(5710 OR 5711 OR 5712) AND data.dstuser:${username}"
    timerange: 4h

  - name: account_existence
    query: "data.dstuser:${username}"
    timerange: 30d
    check_type: account_validity
```

**Threat Intelligence Lookup**:
```yaml
threat_intel:
  sources:
    - alienvault_otx
    - abuseipdb
    - virustotal
    - misp
    - custom_feeds

  checks:
    - ip_reputation
    - known_attacker
    - botnet_membership
    - tor_exit_node
    - hosting_provider_type
```

**Asset Context**:
```yaml
asset_enrichment:
  - cmdb_lookup
  - asset_criticality_score
  - data_classification
  - business_owner
  - maintenance_window_check
  - authorized_user_list
```

### Phase 3: Severity Assessment (triage-agent)

```yaml
severity_scoring:
  base_severity: ${alert.severity}

  modifiers:
    - condition: "privileged_account_targeted"
      adjustment: +2
      accounts: ["root", "admin", "administrator", "sa", "sudo"]

    - condition: "successful_login_detected"
      adjustment: +3
      critical: true

    - condition: "internal_source_ip"
      adjustment: +2
      reason: "Possible lateral movement or compromised internal host"

    - condition: "external_known_malicious_ip"
      adjustment: +1
      threat_score_threshold: 70

    - condition: "critical_asset_targeted"
      adjustment: +2
      asset_criticality: ["high", "critical"]

    - condition: "account_lockout_triggered"
      adjustment: +1
      rule_id: [18102, 4740]

    - condition: "distributed_attack_pattern"
      adjustment: +2
      source_ip_count_threshold: 5

    - condition: "business_hours_attack"
      adjustment: 0
      time_range: "08:00-18:00"

    - condition: "off_hours_attack"
      adjustment: +1
      time_range: "18:00-08:00"

    - condition: "weekend_attack"
      adjustment: +1
      days: ["Saturday", "Sunday"]

  final_severity_mapping:
    0-3: "Low"
    4-6: "Medium"
    7-9: "High"
    10+: "Critical"
```

### Phase 4: Attack Pattern Classification (correlation-agent)

```yaml
pattern_detection:
  - type: single_source_focused
    conditions:
      - unique_source_ips: 1
      - unique_target_users: "1-3"
      - failure_rate: ">80%"
    classification: "Traditional Brute Force"
    risk: "Medium-High"

  - type: password_spraying
    conditions:
      - unique_source_ips: "1-3"
      - unique_target_users: ">10"
      - failures_per_account: "<5"
      - time_distribution: "spread"
    classification: "Password Spraying"
    risk: "High"

  - type: credential_stuffing
    conditions:
      - unique_source_ips: ">5"
      - unique_target_users: ">20"
      - username_validity: ">70%"
      - automation_indicators: true
    classification: "Credential Stuffing"
    risk: "Critical"

  - type: distributed_brute_force
    conditions:
      - unique_source_ips: ">10"
      - geographically_distributed: true
      - coordinated_timing: true
    classification: "Distributed/Botnet Attack"
    risk: "High"

  - type: internal_reconnaissance
    conditions:
      - source_internal: true
      - target_multiple_hosts: true
      - service_enumeration: true
    classification: "Internal Reconnaissance"
    risk: "Critical"
```

## Correlation Rules

### Timeline Construction (correlation-agent)

```yaml
timeline_query:
  primary_window:
    lookback: 4h
    lookahead: 1h

  extended_window:
    lookback: 24h
    lookahead: 4h

  event_sources:
    - authentication_logs
    - network_connections
    - firewall_events
    - edr_telemetry
    - web_access_logs
    - vpn_logs

  filters:
    - srcip: ${source_ip}
    - dstuser: ${target_user}
    - agent: ${target_host}
    - rule.groups:
        - authentication_failed
        - authentication_success
        - sshd
        - pam
        - firewall
        - network
```

### Related Alert Clustering

```yaml
correlation_rules:
  - name: failed_then_successful
    pattern:
      - rule.groups: authentication_failed
        count: ">5"
        timeframe: 1h
      - rule.groups: authentication_success
        timeframe: 1h
        same_source: true
    severity_boost: +3
    auto_escalate: true

  - name: multi_host_targeting
    pattern:
      - unique_target_hosts: ">3"
        same_source_ip: true
        timeframe: 30m
    classification: "Lateral Movement Attempt"
    severity_boost: +2

  - name: account_lockout_pattern
    pattern:
      - rule.id: [18102, 4740]
        unique_accounts: ">5"
        timeframe: 15m
    classification: "Mass Account Lockout Attack"
    severity_boost: +2
    notify: ["soc_lead", "it_team"]

  - name: vpn_then_internal
    pattern:
      - rule.groups: vpn_authentication
        result: success
      - rule.groups: authentication_failed
        source: internal
        timeframe: 5m
    classification: "Post-Compromise Activity"
    severity_boost: +3
    auto_escalate: true
```

## Investigation Steps

### Phase 1: Initial Scope Assessment (investigation-agent)

**Automated Read-Only Queries**:

1. **Attack Scope Quantification**:
```yaml
queries:
  - name: unique_source_ips
    query: "rule.id:(5710 OR 5711 OR 5712 OR 5720 OR 5763 OR 5764) AND timestamp:[NOW-4h TO NOW]"
    aggregation: unique(data.srcip)

  - name: unique_target_users
    query: "rule.id:(5710 OR 5711 OR 5712 OR 5720 OR 5763 OR 5764) AND timestamp:[NOW-4h TO NOW]"
    aggregation: unique(data.dstuser)

  - name: unique_target_hosts
    query: "rule.id:(5710 OR 5711 OR 5712 OR 5720 OR 5763 OR 5764) AND timestamp:[NOW-4h TO NOW]"
    aggregation: unique(agent.name)

  - name: total_failure_count
    query: "rule.groups:authentication_failed AND timestamp:[NOW-4h TO NOW]"
    aggregation: count

  - name: successful_authentications
    query: "rule.groups:authentication_success AND data.srcip:${source_ip} AND timestamp:[NOW-4h TO NOW]"
    aggregation: count
```

2. **Attack Pattern Analysis**:
```yaml
pattern_queries:
  - name: temporal_distribution
    query: "data.srcip:${source_ip} AND rule.groups:authentication_failed"
    timeframe: 4h
    buckets: 15m
    analysis: "Check for consistent rate vs burst pattern"

  - name: password_attempts_per_user
    query: "data.srcip:${source_ip} AND rule.groups:authentication_failed"
    groupby: data.dstuser
    aggregation: count
    threshold: 5

  - name: service_targeting
    query: "data.srcip:${source_ip}"
    groupby: data.port
    analysis: "Identify targeted services (22=SSH, 3389=RDP, 443=HTTPS)"
```

### Phase 2: Compromise Assessment (investigation-agent)

**Critical Indicators of Compromise**:

```yaml
compromise_checks:
  - name: successful_login_check
    query: "data.srcip:${source_ip} AND rule.groups:authentication_success"
    timeframe: 24h
    severity: CRITICAL
    action_required: immediate_containment

  - name: post_auth_activity
    query: "agent.name:${target_host} AND timestamp:[${first_success_time} TO NOW]"
    filters:
      - rule.groups: [file_access, process_creation, network_connection]
    analysis: "Look for unauthorized activity"

  - name: privilege_escalation
    query: "agent.name:${target_host} AND rule.groups:privilege_escalation"
    timeframe: 1h
    indicators:
      - sudo_usage
      - runas_execution
      - setusercontext

  - name: lateral_movement
    query: "data.srcuser:${compromised_user} AND agent.name:NOT ${original_host}"
    timeframe: 4h
    indicators:
      - smb_connections
      - rdp_connections
      - psexec_usage
      - wmi_execution
```

### Phase 3: Threat Intelligence Correlation (investigation-agent)

```yaml
threat_intel_investigation:
  - source: abuseipdb
    check: ${source_ip}
    confidence_threshold: 75
    categories: [18, 21, 22]  # Brute force, SSH, Web App Attack

  - source: virustotal
    check: ${source_ip}
    malicious_threshold: 3
    analysis_timeout: 60s

  - source: alienvault_otx
    check: ${source_ip}
    pulse_match: true
    categories: ["brute force", "botnet", "scanning"]

  - source: shodan
    check: ${source_ip}
    data_points:
      - open_ports
      - identified_services
      - organization
      - hosting_provider

  - source: internal_watchlist
    check: ${source_ip}
    lists: ["previous_attackers", "blocked_ips", "monitored_ranges"]
```

### Phase 4: Historical Context (investigation-agent)

```yaml
historical_analysis:
  - name: repeat_offender_check
    query: "data.srcip:${source_ip}"
    timeframe: 30d
    metrics:
      - total_alerts
      - attack_frequency
      - targeted_assets
      - previous_response_actions

  - name: targeted_user_history
    query: "data.dstuser:${target_user}"
    timeframe: 90d
    analysis:
      - previous_targeting_incidents
      - account_compromise_history
      - normal_login_patterns
      - authorized_source_ips

  - name: campaign_correlation
    query: "rule.groups:authentication_failed"
    timeframe: 7d
    groupby: data.srcip
    analysis: "Identify if this is part of larger campaign"
    threshold: ">100 events from single source"
```

## Forensic Evidence Collection

### Linux Systems

#### Log Files to Preserve

| Artifact | Location | Description | Collection Command |
|----------|----------|-------------|-------------------|
| Auth Log | `/var/log/auth.log` | Debian/Ubuntu authentication events | `sudo cp /var/log/auth.log* /evidence/` |
| Secure Log | `/var/log/secure` | RHEL/CentOS authentication events | `sudo cp /var/log/secure* /evidence/` |
| btmp | `/var/log/btmp` | Failed login attempts | `sudo lastb > /evidence/failed_logins.txt` |
| wtmp | `/var/log/wtmp` | Successful login history | `sudo last > /evidence/successful_logins.txt` |
| lastlog | `/var/log/lastlog` | Last login per user | `sudo lastlog > /evidence/lastlog.txt` |
| PAM logs | `/var/log/pam.log` | PAM authentication details | `sudo cp /var/log/pam.log* /evidence/` |
| Faillog | `/var/log/faillog` | Failed login counters | `sudo faillog -a > /evidence/faillog.txt` |
| SSH Config | `/etc/ssh/sshd_config` | SSH daemon configuration | `sudo cp /etc/ssh/sshd_config /evidence/` |
| PAM Config | `/etc/pam.d/` | PAM configuration files | `sudo cp -r /etc/pam.d /evidence/` |
| User DB | `/etc/passwd`, `/etc/shadow` | User account database | `sudo cp /etc/passwd /etc/group /evidence/` |

#### Collection Script

```bash
#!/bin/bash
# Brute Force Evidence Collection - Linux
# Usage: sudo ./collect_bf_evidence.sh <case_id>

CASE_ID="$1"
TIMESTAMP=$(date +%Y%m%d_%H%M%S)
EVIDENCE_DIR="/evidence/${CASE_ID}_${TIMESTAMP}"
HASH_FILE="${EVIDENCE_DIR}/evidence_hashes.sha256"

# Create evidence directory
mkdir -p "$EVIDENCE_DIR"
cd "$EVIDENCE_DIR" || exit 1

echo "[*] Starting evidence collection for case: ${CASE_ID}"
echo "[*] Timestamp: ${TIMESTAMP}"
echo "[*] Evidence directory: ${EVIDENCE_DIR}"

# Authentication logs
echo "[*] Collecting authentication logs..."
cp /var/log/auth.log* . 2>/dev/null || cp /var/log/secure* . 2>/dev/null
cp /var/log/btmp* . 2>/dev/null
cp /var/log/wtmp* . 2>/dev/null
cp /var/log/lastlog . 2>/dev/null

# Failed login records
echo "[*] Extracting failed login records..."
lastb -F > failed_logins_detailed.txt 2>/dev/null
faillog -a > faillog_report.txt 2>/dev/null

# Successful login records
echo "[*] Extracting successful login records..."
last -F > successful_logins_detailed.txt
lastlog > lastlog_report.txt

# Current connections
echo "[*] Capturing current connections..."
w > current_users.txt
who -a > current_sessions.txt
ss -tunap > network_connections.txt

# SSH configuration
echo "[*] Collecting SSH configuration..."
cp /etc/ssh/sshd_config sshd_config.txt
sshd -T > sshd_test_config.txt 2>&1

# PAM configuration
echo "[*] Collecting PAM configuration..."
mkdir pam_config
cp -r /etc/pam.d/* pam_config/

# Account information
echo "[*] Collecting account information..."
cp /etc/passwd passwd.txt
cp /etc/group group.txt
cp /etc/sudoers sudoers.txt 2>/dev/null

# Failed authentication counts
echo "[*] Analyzing failed authentication patterns..."
grep "Failed password" /var/log/auth.log* 2>/dev/null | \
  awk '{print $11}' | sort | uniq -c | sort -rn > failed_auth_by_ip.txt
grep "Failed password" /var/log/auth.log* 2>/dev/null | \
  awk '{print $9}' | sort | uniq -c | sort -rn > failed_auth_by_user.txt

# System information
echo "[*] Collecting system information..."
uname -a > system_info.txt
hostname > hostname.txt
date > collection_time.txt
uptime > uptime.txt

# Network information
echo "[*] Collecting network information..."
ip addr show > network_interfaces.txt
ip route show > routing_table.txt
iptables -L -n -v > iptables_rules.txt 2>/dev/null

# Hash all evidence files
echo "[*] Computing evidence hashes..."
sha256sum * 2>/dev/null > "$HASH_FILE"

# Create collection metadata
cat > collection_metadata.txt <<EOF
Case ID: ${CASE_ID}
Collection Timestamp: ${TIMESTAMP}
Collector: $(whoami)
Hostname: $(hostname)
System: $(uname -a)
Evidence Directory: ${EVIDENCE_DIR}
Total Files: $(ls -1 | wc -l)
EOF

echo "[*] Evidence collection complete"
echo "[*] Evidence location: ${EVIDENCE_DIR}"
echo "[*] Hash file: ${HASH_FILE}"
```

### Windows Systems

#### Event Log Collection

| Event ID | Log Source | Description | Significance |
|----------|------------|-------------|--------------|
| 4625 | Security | Failed logon attempt | Primary brute force indicator |
| 4624 | Security | Successful logon | Compromise verification |
| 4740 | Security | Account lockout | Attack impact indicator |
| 4771 | Security | Kerberos pre-auth failed | Domain-level brute force |
| 4776 | Security | Credential validation failed | NTLM authentication failure |
| 4648 | Security | Logon with explicit credentials | Possible credential reuse |
| 4768 | Security | Kerberos TGT requested | Kerberos authentication activity |
| 4769 | Security | Kerberos service ticket requested | Service access attempts |

#### Collection Script

```powershell
# Brute Force Evidence Collection - Windows
# Usage: .\Collect-BFEvidence.ps1 -CaseID "CASE-001"

param(
    [Parameter(Mandatory=$true)]
    [string]$CaseID
)

$Timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
$EvidenceDir = "C:\Evidence\${CaseID}_${Timestamp}"
$HashFile = Join-Path $EvidenceDir "evidence_hashes.txt"

# Create evidence directory
New-Item -ItemType Directory -Path $EvidenceDir -Force | Out-Null
Write-Host "[*] Starting evidence collection for case: $CaseID"
Write-Host "[*] Evidence directory: $EvidenceDir"

# Export Security Event Log
Write-Host "[*] Exporting Security Event Log..."
wevtutil epl Security "$EvidenceDir\Security.evtx"

# Export System Event Log
Write-Host "[*] Exporting System Event Log..."
wevtutil epl System "$EvidenceDir\System.evtx"

# Extract failed logon events (4625)
Write-Host "[*] Extracting failed logon events (4625)..."
Get-WinEvent -FilterHashtable @{LogName='Security';ID=4625} -ErrorAction SilentlyContinue |
    Export-Csv -Path "$EvidenceDir\EventID_4625_FailedLogons.csv" -NoTypeInformation

# Extract account lockout events (4740)
Write-Host "[*] Extracting account lockout events (4740)..."
Get-WinEvent -FilterHashtable @{LogName='Security';ID=4740} -ErrorAction SilentlyContinue |
    Export-Csv -Path "$EvidenceDir\EventID_4740_AccountLockouts.csv" -NoTypeInformation

# Extract Kerberos failures (4771)
Write-Host "[*] Extracting Kerberos pre-auth failures (4771)..."
Get-WinEvent -FilterHashtable @{LogName='Security';ID=4771} -ErrorAction SilentlyContinue |
    Export-Csv -Path "$EvidenceDir\EventID_4771_KerberosFailures.csv" -NoTypeInformation

# Extract NTLM failures (4776)
Write-Host "[*] Extracting NTLM credential validation failures (4776)..."
Get-WinEvent -FilterHashtable @{LogName='Security';ID=4776} -ErrorAction SilentlyContinue |
    Export-Csv -Path "$EvidenceDir\EventID_4776_NTLMFailures.csv" -NoTypeInformation

# Extract successful logons (4624)
Write-Host "[*] Extracting successful logon events (4624)..."
Get-WinEvent -FilterHashtable @{LogName='Security';ID=4624} -ErrorAction SilentlyContinue |
    Select-Object -First 1000 |
    Export-Csv -Path "$EvidenceDir\EventID_4624_SuccessfulLogons.csv" -NoTypeInformation

# Account information
Write-Host "[*] Collecting account information..."
Get-LocalUser | Export-Csv -Path "$EvidenceDir\LocalUsers.csv" -NoTypeInformation
Get-LocalGroup | Export-Csv -Path "$EvidenceDir\LocalGroups.csv" -NoTypeInformation
Get-LocalGroupMember -Group "Administrators" -ErrorAction SilentlyContinue |
    Export-Csv -Path "$EvidenceDir\Administrators.csv" -NoTypeInformation

# Current sessions
Write-Host "[*] Collecting current session information..."
query user > "$EvidenceDir\CurrentSessions.txt" 2>&1
Get-Process -IncludeUserName |
    Export-Csv -Path "$EvidenceDir\RunningProcesses.csv" -NoTypeInformation

# Network connections
Write-Host "[*] Collecting network connections..."
Get-NetTCPConnection | Export-Csv -Path "$EvidenceDir\TCPConnections.csv" -NoTypeInformation
netstat -ano > "$EvidenceDir\NetstatOutput.txt"

# Firewall rules
Write-Host "[*] Collecting firewall configuration..."
Get-NetFirewallRule | Export-Csv -Path "$EvidenceDir\FirewallRules.csv" -NoTypeInformation
Get-NetFirewallProfile | Export-Csv -Path "$EvidenceDir\FirewallProfiles.csv" -NoTypeInformation

# RDP configuration
Write-Host "[*] Collecting RDP configuration..."
Get-ItemProperty "HKLM:\System\CurrentControlSet\Control\Terminal Server" |
    Out-File "$EvidenceDir\RDPConfiguration.txt"
Get-ItemProperty "HKLM:\System\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp" |
    Out-File "$EvidenceDir\RDPTCPConfiguration.txt" -Append

# Security policy
Write-Host "[*] Exporting security policy..."
secedit /export /cfg "$EvidenceDir\SecurityPolicy.inf" /quiet

# System information
Write-Host "[*] Collecting system information..."
systeminfo > "$EvidenceDir\SystemInfo.txt"
Get-ComputerInfo | Out-File "$EvidenceDir\ComputerInfo.txt"

# Failed logon summary
Write-Host "[*] Analyzing failed logon patterns..."
Get-WinEvent -FilterHashtable @{LogName='Security';ID=4625} -ErrorAction SilentlyContinue |
    Group-Object -Property {$_.Properties[19].Value} |
    Select-Object Name, Count |
    Sort-Object Count -Descending |
    Export-Csv -Path "$EvidenceDir\FailedLogonsByIP.csv" -NoTypeInformation

Get-WinEvent -FilterHashtable @{LogName='Security';ID=4625} -ErrorAction SilentlyContinue |
    Group-Object -Property {$_.Properties[5].Value} |
    Select-Object Name, Count |
    Sort-Object Count -Descending |
    Export-Csv -Path "$EvidenceDir\FailedLogonsByUser.csv" -NoTypeInformation

# Compute hashes
Write-Host "[*] Computing evidence hashes..."
Get-ChildItem -Path $EvidenceDir -File |
    Get-FileHash -Algorithm SHA256 |
    Export-Csv -Path $HashFile -NoTypeInformation

# Create collection metadata
$Metadata = @{
    "CaseID" = $CaseID
    "CollectionTimestamp" = $Timestamp
    "Collector" = $env:USERNAME
    "Hostname" = $env:COMPUTERNAME
    "Domain" = $env:USERDOMAIN
    "OSVersion" = (Get-CimInstance Win32_OperatingSystem).Caption
    "EvidenceDirectory" = $EvidenceDir
    "TotalFiles" = (Get-ChildItem -Path $EvidenceDir -File).Count
}
$Metadata | ConvertTo-Json | Out-File "$EvidenceDir\CollectionMetadata.json"

Write-Host "[*] Evidence collection complete"
Write-Host "[*] Evidence location: $EvidenceDir"
Write-Host "[*] Hash file: $HashFile"
```

## Chain of Custody

### Evidence Handling Requirements

```yaml
chain_of_custody:
  collection:
    - timestamp: UTC format (ISO 8601)
    - collector: Username and role
    - method: Automated script or manual
    - tool_version: Script version or tool name
    - hash_algorithm: SHA256

  storage:
    - location: Secure evidence storage path
    - access_control: Read-only, restricted access
    - encryption: AES-256 at rest
    - retention_period: Per organizational policy (default 1 year)

  transfer:
    - recipient: Name and role
    - timestamp: UTC format
    - method: Secure transfer (encrypted channel)
    - verification: Hash verification required

  analysis:
    - analyst: Name and role
    - start_time: UTC format
    - end_time: UTC format
    - tools_used: List of analysis tools
    - findings: Summary of analysis results

  disposal:
    - authorization: Approval from case owner
    - method: Secure deletion (DoD 5220.22-M or equivalent)
    - verification: Deletion verification
    - documentation: Disposal certificate
```

### Evidence Documentation Template

```
CHAIN OF CUSTODY RECORD
=======================
Case ID: [CASE-ID]
Evidence ID: [EVIDENCE-ID]
Classification: [TLP:AMBER]

ITEM DESCRIPTION
----------------
Description: [Authentication logs for brute force incident]
Source System: [Hostname/IP]
Collection Method: [Automated script / Manual]
File Count: [Number of files]
Total Size: [Size in MB/GB]

COLLECTION
----------
Collected By: [Name]
Role: [SOC Analyst / Incident Responder]
Date/Time: [YYYY-MM-DD HH:MM:SS UTC]
Location: [Evidence storage path]
Hash (SHA256): [Hash value]

CUSTODY TRANSFERS
-----------------
Transfer 1:
  From: [Name] - [Role]
  To: [Name] - [Role]
  Date/Time: [YYYY-MM-DD HH:MM:SS UTC]
  Purpose: [Forensic analysis]
  Hash Verified: [Yes/No]

ANALYSIS RECORDS
----------------
Analyst: [Name]
Analysis Start: [YYYY-MM-DD HH:MM:SS UTC]
Analysis End: [YYYY-MM-DD HH:MM:SS UTC]
Tools Used: [List of tools]
Findings: [Summary]

INTEGRITY VERIFICATION
----------------------
Initial Hash: [SHA256]
Current Hash: [SHA256]
Verification Status: [PASS/FAIL]
Last Verified: [YYYY-MM-DD HH:MM:SS UTC]
```

## Response Plan

### Containment Actions (response-planner-agent + responder-agent)

#### Option 1: Block Source IP (Low Risk)

```yaml
action: block_source_ip
risk_level: low
approval_required: automated_threshold
approval_conditions:
  - external_source: true
  - no_successful_authentications: true
  - threat_intel_confidence: ">70%"

implementation:
  method: firewall_rule
  targets:
    - perimeter_firewall
    - host_firewall
    - waf

  firewall_rule:
    action: drop
    source_ip: ${source_ip}
    duration: 86400  # 24 hours
    protocol: all
    log: true

  verification:
    - check_rule_installed
    - test_connectivity_blocked
    - monitor_for_evasion_attempts

  rollback:
    - automatic_after: 24h
    - manual_extension: authorized_personnel_only
```

#### Option 2: Rate Limiting (Very Low Risk)

```yaml
action: apply_rate_limiting
risk_level: very_low
approval_required: automated

implementation:
  targets:
    - authentication_endpoints
    - api_gateways
    - load_balancers

  rate_limit_rules:
    - source_ip_limit: 10_requests_per_minute
    - user_account_limit: 5_failures_per_10_minutes
    - global_limit: 1000_requests_per_minute

  response_action:
    - exceeds_limit: "temporary_block_300s"
    - repeated_violations: "extend_block_3600s"
```

#### Option 3: Account Protection (Low Risk)

```yaml
action: protect_targeted_accounts
risk_level: low
approval_required: soc_lead

implementation:
  measures:
    - force_mfa: true
    - temporary_lockout: 3600s
    - password_reset_required: false  # Only if compromised
    - notification_to_user: true
    - enhanced_monitoring: true

  affected_accounts: ${targeted_user_list}

  verification:
    - confirm_mfa_enforced
    - test_authentication_requirements
    - verify_user_notification_sent
```

#### Option 4: Isolate Target Host (High Risk)

```yaml
action: isolate_host
risk_level: high
approval_required: soc_lead + business_owner
business_impact: service_disruption

conditions:
  - successful_authentication_confirmed: true
  - post_compromise_activity_detected: true
  - critical_asset: true
  - edr_available: true

implementation:
  method: edr_network_isolation
  targets: ${agent_id}

  isolation_policy:
    - block_all_network: true
    - allow_edr_communication: true
    - allow_management_vlan: conditional

  concurrent_actions:
    - snapshot_memory
    - capture_running_processes
    - export_event_logs
    - notify_asset_owner

  verification:
    - confirm_network_isolated
    - verify_no_lateral_movement
    - check_edr_connectivity
```

#### Option 5: Active Defense - Honeypot Redirect (Medium Risk)

```yaml
action: redirect_to_honeypot
risk_level: medium
approval_required: security_architect
legal_review: required

conditions:
  - sophisticated_attack: true
  - threat_intelligence_value: high
  - legal_approval: granted

implementation:
  method: network_redirection
  target: ${source_ip}
  destination: honeypot_environment

  honeypot_configuration:
    - mirror_real_service: true
    - credential_acceptance: delayed_failure
    - session_logging: comprehensive
    - behavioral_analysis: enabled

  intelligence_collection:
    - attacker_ttps
    - credential_lists
    - source_attribution
    - tool_fingerprinting
```

### Eradication Procedures

#### Step 1: Verify Containment

```yaml
verification_checks:
  - source_ip_blocked: true
  - no_new_attempts_detected: true
  - all_concurrent_sessions_terminated: true
  - network_isolation_confirmed: true

  monitoring_period: 1h
  success_criteria: "zero authentication attempts from blocked source"
```

#### Step 2: Credential Reset (If Compromised)

```bash
# Linux - Force password reset
sudo passwd --expire ${username}
sudo chage -d 0 ${username}

# Invalidate existing sessions
sudo pkill -u ${username}
sudo rm -f /var/run/utmp
sudo touch /var/run/utmp

# Windows - Force password reset
net user ${username} /logonpasswordchg:yes
Get-ADUser ${username} | Set-ADUser -ChangePasswordAtLogon $true

# Revoke all existing sessions
query session | findstr ${username}
logoff ${session_id}
```

#### Step 3: Disable Compromised Accounts (Temporary)

```yaml
account_suspension:
  action: temporary_disable
  duration: pending_investigation

  linux_commands:
    - "sudo usermod -L ${username}"
    - "sudo chage -E 0 ${username}"

  windows_commands:
    - "net user ${username} /active:no"
    - "Disable-ADAccount -Identity ${username}"

  notification:
    - user: true
    - manager: true
    - it_support: true
```

#### Step 4: Revoke Active Sessions and Tokens

```yaml
session_termination:
  - ssh_sessions: "sudo pkill -u ${username}"
  - rdp_sessions: "logoff ${session_id}"
  - web_sessions: "invalidate_session_tokens"
  - api_tokens: "revoke_api_credentials"
  - oauth_tokens: "revoke_oauth_grants"
  - vpn_sessions: "terminate_vpn_connection"
```

#### Step 5: Remove Persistence Mechanisms (If Found)

```bash
# Check for SSH authorized_keys
cat ~/.ssh/authorized_keys
# Remove unauthorized keys

# Check for cron jobs
crontab -l -u ${username}
# Remove malicious entries

# Check for systemd timers
systemctl list-timers --all
# Disable suspicious timers

# Check for backdoor users
awk -F: '$3 >= 1000 {print $1}' /etc/passwd
# Remove unauthorized accounts

# Windows - Check scheduled tasks
schtasks /query /v /fo list
# Remove malicious tasks

# Check for new services
Get-Service | Where-Object {$_.StartType -eq "Automatic"}
# Remove unauthorized services
```

### Recovery Procedures

#### Step 1: Restore Legitimate Access

```yaml
recovery_checklist:
  - verify_account_owner_identity:
      method: multi_factor_verification
      contacts: [manager, hr_department]
      documentation_required: true

  - password_reset:
      method: secure_password_generation
      complexity: organizational_policy
      history_enforcement: 12_passwords
      delivery: out_of_band

  - mfa_enrollment:
      required: true
      methods: [authenticator_app, hardware_token]
      backup_codes: generated

  - account_reactivation:
      linux: "sudo usermod -U ${username} && sudo chage -E -1 ${username}"
      windows: "net user ${username} /active:yes"

  - verification:
      test_login: supervised
      check_permissions: verified
      monitor_activity: 7_days_enhanced
```

#### Step 2: System Hardening

```yaml
hardening_measures:
  ssh_configuration:
    - PermitRootLogin: "no"
    - PasswordAuthentication: "no"  # Force key-based auth
    - PubkeyAuthentication: "yes"
    - MaxAuthTries: 3
    - LoginGraceTime: 30
    - AllowUsers: whitelist_only
    - AllowGroups: ssh_users
    - ClientAliveInterval: 300
    - ClientAliveCountMax: 2
    - UsePAM: "yes"

  pam_configuration:
    - faillock: "deny=5 unlock_time=1800"
    - password_quality: "minlen=16 dcredit=-1 ucredit=-1 ocredit=-1"
    - session_timeout: 900

  rdp_configuration:
    - NetworkLevelAuthentication: enabled
    - AccountLockoutThreshold: 5
    - AccountLockoutDuration: 30_minutes
    - SecurityLayer: SSL

  web_application:
    - rate_limiting: enforced
    - captcha: enabled_after_3_failures
    - account_lockout: 5_attempts_15_minutes
    - mfa_enforcement: mandatory
```

#### Step 3: Monitoring Enhancement

```yaml
enhanced_monitoring:
  duration: 30_days

  wazuh_rule_tuning:
    - lower_thresholds:
        failed_auth_threshold: 3  # Down from 5
        time_window: 60s  # Down from 120s

    - additional_alerting:
        - authentication_success_from_new_ip
        - authentication_outside_business_hours
        - privilege_escalation_attempts
        - file_integrity_monitoring_critical_configs

  log_retention:
    - authentication_logs: 90_days  # Extended
    - system_logs: 90_days
    - network_logs: 90_days

  additional_telemetry:
    - process_creation: enabled
    - network_connections: enabled
    - file_access_auditing: sensitive_directories
    - registry_monitoring: authentication_keys
```

#### Step 4: Communication and Documentation

```yaml
communication_plan:
  internal_notification:
    recipients: [affected_users, it_team, management]
    timing: within_4_hours
    template: internal_notification_template

  management_briefing:
    recipients: [ciso, cio, business_owners]
    timing: within_24_hours
    template: management_escalation_template

  regulatory_reporting:
    required_if: data_breach_confirmed
    timeline: per_regulatory_requirements
    jurisdictions: [gdpr, ccpa, hipaa, pci_dss]
```

## Communication Templates

### Internal SOC Notification

```
Subject: [ALERT] Brute Force Attack Detected - Case ${case_id}

Classification: TLP:AMBER - Internal Use Only
Priority: HIGH
Case ID: ${case_id}
Detection Time: ${detection_timestamp}
Current Status: ${status}

INCIDENT SUMMARY
================
Attack Type: Brute Force Authentication Attack
Attack Pattern: ${attack_pattern}
Source IP(s): ${source_ip_list}
Target System(s): ${target_host_list}
Targeted Account(s): ${target_user_list}
Failed Attempts: ${failure_count}
Successful Logins: ${success_count}

SEVERITY ASSESSMENT
===================
Base Severity: ${base_severity}
Final Severity: ${final_severity}
Confidence: ${confidence_percentage}%

Risk Factors:
${risk_factors_list}

CURRENT STATUS
==============
Containment Status: ${containment_status}
Investigation Status: ${investigation_status}
Business Impact: ${business_impact}

ACTIONS TAKEN
=============
${actions_taken_list}

ACTIONS REQUIRED
================
${actions_required_list}

ASSIGNED ANALYST
================
Primary: ${primary_analyst}
Secondary: ${secondary_analyst}

NEXT UPDATE
===========
${next_update_time}

EVIDENCE LOCATION
=================
${evidence_storage_path}

For questions, contact SOC at ${soc_contact}
```

### Management Escalation

```
Subject: [INCIDENT] Brute Force Attack - Management Notification - Case ${case_id}

Classification: TLP:AMBER
Priority: HIGH
Date: ${incident_date}

EXECUTIVE SUMMARY
=================
Our security monitoring systems detected and contained a brute force
authentication attack targeting ${target_system_description}. The SOC
has implemented containment measures and is conducting a full investigation.

BUSINESS IMPACT
===============
Current Impact: ${business_impact_summary}
Affected Systems: ${affected_systems}
Service Disruption: ${service_disruption_status}
Data Exposure Risk: ${data_exposure_assessment}
Estimated Recovery Time: ${recovery_eta}

INCIDENT DETAILS
================
Attack Type: Brute Force Authentication Attack
Detection Time: ${detection_timestamp}
Source: ${source_description}
Target: ${target_description}
Attack Sophistication: ${sophistication_level}

RESPONSE ACTIONS
================
Immediate Actions Taken:
${immediate_actions}

Ongoing Activities:
${ongoing_activities}

Planned Actions:
${planned_actions}

RECOMMENDATIONS
===============
${management_recommendations}

REGULATORY CONSIDERATIONS
=========================
${regulatory_implications}

NEXT STEPS
==========
${next_steps}

Next Update: ${next_update_time}

Contact: ${incident_commander}
Email: ${contact_email}
Phone: ${contact_phone}
```

### Affected User Notification

```
Subject: Important: Security Alert - Your Account

Date: ${notification_date}

Dear ${user_name},

Our security team has detected suspicious activity involving your account.
Out of an abundance of caution, we have taken steps to protect your account
and require your immediate attention.

WHAT HAPPENED
=============
We detected multiple failed login attempts to your account from an unauthorized
source. This appears to be an automated attack attempting to gain access to
your credentials.

ACTIONS WE HAVE TAKEN
=====================
- Blocked the attacking IP address(es)
- Enhanced monitoring on your account
- ${additional_protections}

ACTIONS YOU MUST TAKE
=====================
1. Change your password immediately using the following link: ${password_reset_link}
2. Review your recent account activity for anything suspicious
3. Ensure multi-factor authentication (MFA) is enabled
4. Check for any unrecognized devices or sessions

WHAT TO LOOK FOR
================
- Emails you didn't send
- Files you didn't create or modify
- Unrecognized login locations or devices
- Unexpected account changes

IF YOU NOTICE ANYTHING SUSPICIOUS
==================================
Please contact the IT Security team immediately:
- Email: ${security_contact_email}
- Phone: ${security_contact_phone}
- Portal: ${security_portal_url}

SECURITY TIPS
=============
- Use a strong, unique password for your account
- Never share your password with anyone
- Enable multi-factor authentication
- Be cautious of phishing emails
- Report suspicious activity immediately

This is not a drill. Please take immediate action to secure your account.

Thank you for your cooperation.

${organization_name} Security Team
```

## Regulatory Compliance Mapping

### NIST 800-61r2 Incident Response Lifecycle

| Phase | Activities | Wazuh Autopilot Integration | Completion Criteria |
|-------|------------|----------------------------|-------------------|
| **1. Preparation** | - Deploy monitoring (Wazuh agents)<br>- Define playbooks<br>- Train personnel<br>- Establish communication channels | - Automated agent deployment<br>- Playbook version control<br>- Agent health monitoring | - All critical systems monitored<br>- Playbooks tested quarterly<br>- Contact lists current |
| **2. Detection & Analysis** | - Alert generation<br>- Triage and validation<br>- Scope determination<br>- Severity assessment<br>- Evidence collection | - **triage-agent**: Initial classification<br>- **correlation-agent**: Pattern detection<br>- **investigation-agent**: Scope analysis<br>- Automated evidence collection | - True positive confirmed<br>- Attack scope identified<br>- Severity assessed<br>- Evidence collected and preserved |
| **3. Containment** | - Short-term containment<br>- System backup<br>- Long-term containment<br>- Evidence preservation | - **response-planner-agent**: Action recommendations<br>- **policy-guard-agent**: Risk assessment<br>- **responder-agent**: Action execution | - Attack contained<br>- Evidence preserved<br>- Business impact minimized<br>- Approval documented |
| **4. Eradication** | - Malware removal<br>- Vulnerability remediation<br>- Credential reset<br>- System hardening | - Guided remediation procedures<br>- Verification scripts<br>- Configuration management | - Attacker access removed<br>- Vulnerabilities patched<br>- Systems hardened<br>- Validation completed |
| **5. Recovery** | - System restoration<br>- Service resumption<br>- Monitoring enhancement<br>- Verification testing | - **responder-agent**: Recovery orchestration<br>- Enhanced monitoring rules<br>- Post-recovery validation | - Systems operational<br>- Services restored<br>- Monitoring enhanced<br>- No recurrence detected |
| **6. Post-Incident Activity** | - Lessons learned<br>- Report generation<br>- Process improvement<br>- Metric tracking | - **reporting-agent**: Automated reports<br>- Metric collection<br>- Improvement tracking | - Report completed<br>- Lessons documented<br>- Improvements implemented<br>- Metrics reviewed |

### ISO 27035 Information Security Incident Management

| Stage | ISO 27035 Requirements | Playbook Implementation | Evidence |
|-------|------------------------|------------------------|----------|
| **Plan and Prepare** | Establish ISIM policy and procedures | Playbook documentation, version control | This document (v2.0.0) |
| **Detect and Report** | Incident detection mechanisms | Wazuh rules 5710-5764, 18100-18106, 60100-60199 | Alert logs, correlation rules |
| **Assessment and Decision** | Incident classification and prioritization | Severity scoring, decision tree, triage automation | Triage logs, severity justification |
| **Responses** | Containment, eradication, recovery actions | Response plan section, automated execution | Action logs, approval records |
| **Lessons Learned** | Post-incident review | Lessons learned template | Post-incident report |

### SANS Incident Handler's Handbook

| SANS Step | Description | Playbook Section | Automation |
|-----------|-------------|------------------|------------|
| **1. Preparation** | Get ready to handle incidents | Detection Criteria, Wazuh Rules | Continuous monitoring |
| **2. Identification** | Determine if an incident occurred | Detection Criteria, Decision Tree | triage-agent, correlation-agent |
| **3. Containment** | Limit the damage | Response Plan - Containment | response-planner-agent, responder-agent |
| **4. Eradication** | Remove the threat | Eradication Procedures | Guided manual procedures |
| **5. Recovery** | Restore operations | Recovery Procedures | responder-agent, monitoring |
| **6. Lessons Learned** | Document and improve | Post-Incident Review | reporting-agent |

## Post-Incident Review

### Lessons Learned Template

```yaml
post_incident_review:
  case_id: ${case_id}
  incident_date: ${incident_date}
  review_date: ${review_date}
  participants: [${participant_list}]

  incident_summary:
    what_happened: |
      ${incident_description}

    timeline:
      detection: ${detection_time}
      triage: ${triage_time}
      containment: ${containment_time}
      eradication: ${eradication_time}
      recovery: ${recovery_time}
      resolution: ${resolution_time}

    impact:
      systems_affected: ${systems_count}
      users_affected: ${users_count}
      data_exposure: ${data_exposure_assessment}
      downtime: ${downtime_duration}
      financial_impact: ${estimated_cost}

  what_went_well:
    - question: "What aspects of the response were effective?"
      answer: ${effective_aspects}

    - question: "Which tools and processes worked as expected?"
      answer: ${working_tools}

    - question: "What automation was beneficial?"
      answer: ${beneficial_automation}

  what_went_wrong:
    - question: "What aspects of the response were ineffective?"
      answer: ${ineffective_aspects}

    - question: "Which tools or processes failed?"
      answer: ${failed_components}

    - question: "What gaps were identified?"
      answer: ${identified_gaps}

  root_cause_analysis:
    primary_cause: ${root_cause}
    contributing_factors: ${contributing_factors}
    vulnerability_exploited: ${vulnerability}
    control_failures: ${control_failures}

  improvement_actions:
    - category: technical
      actions:
        - description: ${technical_improvement_1}
          priority: high
          owner: ${owner}
          due_date: ${due_date}
          status: pending

    - category: process
      actions:
        - description: ${process_improvement_1}
          priority: medium
          owner: ${owner}
          due_date: ${due_date}
          status: pending

    - category: people
      actions:
        - description: ${people_improvement_1}
          priority: medium
          owner: ${owner}
          due_date: ${due_date}
          status: pending

  metrics:
    detection_time: ${detection_metric}
    triage_time: ${triage_metric}
    containment_time: ${containment_metric}
    eradication_time: ${eradication_metric}
    recovery_time: ${recovery_metric}
    total_response_time: ${total_metric}

    sla_compliance:
      detection_sla: ${detection_sla_met}
      triage_sla: ${triage_sla_met}
      containment_sla: ${containment_sla_met}
      eradication_sla: ${eradication_sla_met}

  recommendations:
    immediate: ${immediate_recommendations}
    short_term: ${short_term_recommendations}
    long_term: ${long_term_recommendations}
```

### Key Review Questions

1. **Detection**
   - How was the incident first detected?
   - Was detection automated or manual?
   - How long from attack start to detection?
   - Were there earlier indicators we missed?

2. **Analysis**
   - Was the scope accurately determined?
   - Were all affected systems identified?
   - Was threat intelligence effective?
   - Did correlation rules work as expected?

3. **Containment**
   - Were containment actions effective?
   - Was the business impact acceptable?
   - Were approval processes followed?
   - How long did containment take?

4. **Eradication**
   - Was the threat fully removed?
   - Were all persistence mechanisms found?
   - Were credentials properly reset?
   - Was system hardening sufficient?

5. **Recovery**
   - Were systems fully restored?
   - Was service resumption smooth?
   - Were users properly supported?
   - Is enhanced monitoring effective?

6. **Communication**
   - Were stakeholders notified timely?
   - Was communication clear and accurate?
   - Were templates effective?
   - Were regulatory requirements met?

7. **Automation**
   - Which agent actions were helpful?
   - Which automations need improvement?
   - Were there false positives?
   - What additional automation is needed?

## Agent Pipeline Integration

### Agent Responsibilities by Phase

| Agent | Primary Role | Triggered When | Actions | Output |
|-------|--------------|----------------|---------|--------|
| **triage-agent** | Initial classification and entity extraction | Alert generated | - Extract source IP, user, host<br>- Enrich entities<br>- Calculate initial severity<br>- Classify attack pattern | Triage report with severity and entities |
| **correlation-agent** | Pattern detection and historical analysis | After triage | - Query historical events<br>- Identify related alerts<br>- Build attack timeline<br>- Detect campaign patterns | Correlation report with timeline |
| **investigation-agent** | Deep dive analysis | After correlation | - Scope assessment<br>- Compromise check<br>- Threat intel lookup<br>- Forensic queries | Investigation report with IOCs |
| **response-planner-agent** | Action recommendation | After investigation | - Analyze available actions<br>- Assess risk/benefit<br>- Rank response options<br>- Generate action plan | Prioritized response plan |
| **policy-guard-agent** | Risk and compliance validation | Before action execution | - Evaluate business impact<br>- Check compliance requirements<br>- Request human approval<br>- Validate authorization | Approval decision with justification |
| **responder-agent** | Action execution | After approval | - Execute containment<br>- Apply firewall rules<br>- Isolate systems<br>- Lock accounts | Execution status and results |
| **reporting-agent** | Documentation and metrics | Throughout lifecycle + post-incident | - Generate incident report<br>- Track metrics<br>- Create timeline visualization<br>- Produce lessons learned | Comprehensive incident report |

### Agent Workflow Sequence

```yaml
agent_workflow:
  phase_1_detection:
    trigger: wazuh_alert
    agent: triage-agent
    sla: 2_minutes
    success_criteria: entities_extracted_and_severity_assigned
    escalation_if_exceeded: soc_lead

  phase_2_correlation:
    trigger: triage_complete
    agent: correlation-agent
    sla: 3_minutes
    success_criteria: timeline_built_and_pattern_identified
    escalation_if_exceeded: soc_lead

  phase_3_investigation:
    trigger: correlation_complete
    agent: investigation-agent
    sla: 10_minutes
    success_criteria: scope_determined_and_iocs_identified
    escalation_if_exceeded: senior_analyst
    parallel_execution: true  # Can run multiple investigations

  phase_4_response_planning:
    trigger: investigation_complete
    agent: response-planner-agent
    sla: 5_minutes
    success_criteria: response_options_generated
    escalation_if_exceeded: soc_lead

  phase_5_approval:
    trigger: response_plan_ready
    agent: policy-guard-agent
    sla: 15_minutes  # Includes human approval time
    success_criteria: approval_granted_or_denied
    escalation_if_exceeded: manager

  phase_6_execution:
    trigger: approval_granted
    agent: responder-agent
    sla: 5_minutes
    success_criteria: actions_executed_and_verified
    escalation_if_exceeded: soc_lead
    rollback_on_failure: true

  phase_7_reporting:
    trigger: incident_resolved
    agent: reporting-agent
    sla: 4_hours
    success_criteria: incident_report_generated
    escalation_if_exceeded: manager
```

## Service Level Agreements (SLAs) and Key Performance Indicators (KPIs)

### Detection Phase

| Metric | Target | Measurement | Escalation Threshold |
|--------|--------|-------------|---------------------|
| Time to Detect | < 2 minutes | From attack start to first alert | > 5 minutes |
| Detection Accuracy | > 95% | True positives / Total alerts | < 90% |
| Coverage | 100% | Critical systems monitored | < 99% |
| Agent Health | > 99% | Agents reporting / Total agents | < 95% |

**Escalation Actions (Detection)**:
- \> 5 min to detect: Review detection rules, check agent health
- < 90% accuracy: Tune detection thresholds, review false positives
- < 99% coverage: Deploy missing agents, investigate offline systems
- < 95% agent health: Investigate agent failures, review infrastructure

### Triage Phase

| Metric | Target | Measurement | Escalation Threshold |
|--------|--------|-------------|---------------------|
| Time to Triage | < 5 minutes | From detection to severity assignment | > 10 minutes |
| Triage Accuracy | > 90% | Correct severity / Total incidents | < 80% |
| Entity Extraction Success | > 98% | Successful extractions / Attempts | < 95% |
| Enrichment Success | > 95% | Successful enrichments / Attempts | < 90% |

**Escalation Actions (Triage)**:
- \> 10 min to triage: Manual analyst review, check automation pipeline
- < 80% accuracy: Review severity scoring logic, retrain models
- < 95% extraction: Fix parsing issues, update entity extraction patterns
- < 90% enrichment: Check enrichment sources, review API availability

### Correlation Phase

| Metric | Target | Measurement | Escalation Threshold |
|--------|--------|-------------|---------------------|
| Time to Correlate | < 8 minutes | From triage to correlation complete | > 15 minutes |
| Pattern Detection Rate | > 85% | Patterns identified / Total incidents | < 75% |
| Historical Query Time | < 30 seconds | Average query execution time | > 60 seconds |
| Timeline Accuracy | > 95% | Complete timelines / Total incidents | < 90% |

**Escalation Actions (Correlation)**:
- \> 15 min to correlate: Optimize queries, increase resources
- < 75% detection rate: Update correlation rules, expand pattern library
- \> 60 sec query time: Database optimization, add indexes
- < 90% timeline accuracy: Review data sources, improve log collection

### Containment Phase

| Metric | Target | Measurement | Escalation Threshold |
|--------|--------|-------------|---------------------|
| Time to Contain | < 15 minutes | From approval to containment verified | > 30 minutes |
| Containment Success | > 98% | Successful containments / Attempts | < 95% |
| False Containment Rate | < 2% | Unnecessary containments / Total | > 5% |
| Business Impact | < 5% | Services disrupted / Total services | > 10% |

**Escalation Actions (Containment)**:
- \> 30 min to contain: Emergency procedure, manual intervention
- < 95% success: Review containment mechanisms, test procedures
- \> 5% false containment: Improve decision logic, increase review
- \> 10% business impact: Business continuity activation, management notification

### Eradication Phase

| Metric | Target | Measurement | Escalation Threshold |
|--------|--------|-------------|---------------------|
| Time to Eradicate | < 4 hours | From containment to threat removed | > 8 hours |
| Eradication Completeness | 100% | Threats removed / Threats identified | < 100% |
| Recurrence Rate | < 1% | Re-infections / Total incidents | > 3% |
| Verification Success | 100% | Verifications passed / Total checks | < 100% |

**Escalation Actions (Eradication)**:
- \> 8 hours to eradicate: Incident response team activation, external assistance
- < 100% completeness: Extended investigation, forensic analysis
- \> 3% recurrence: Root cause analysis, improve eradication procedures
- < 100% verification: Additional verification steps, manual inspection

### Recovery Phase

| Metric | Target | Measurement | Escalation Threshold |
|--------|--------|-------------|---------------------|
| Time to Recover | < 8 hours | From eradication to full service restoration | > 24 hours |
| Recovery Success | > 99% | Successful recoveries / Attempts | < 95% |
| Service Availability | > 99.9% | Uptime / Total time (post-recovery) | < 99% |
| User Satisfaction | > 90% | Satisfied users / Survey respondents | < 80% |

**Escalation Actions (Recovery)**:
- \> 24 hours to recover: Business continuity plan activation, c-level notification
- < 95% success: Review recovery procedures, improve documentation
- < 99% availability: Extended monitoring, infrastructure review
- < 80% satisfaction: User communication improvement, support enhancement

### Overall Incident Lifecycle

| Metric | Target | Measurement | Escalation Threshold |
|--------|--------|-------------|---------------------|
| Mean Time to Detect (MTTD) | < 2 minutes | Average detection time | > 5 minutes |
| Mean Time to Respond (MTTR) | < 30 minutes | Average response time | > 60 minutes |
| Mean Time to Recover (MTTR) | < 12 hours | Average full recovery time | > 24 hours |
| Incident Recurrence | < 1% | Repeat incidents / Total incidents | > 3% |
| False Positive Rate | < 10% | False alerts / Total alerts | > 20% |
| Automation Rate | > 80% | Automated actions / Total actions | < 70% |
| Approval Time | < 10 minutes | Average approval wait time | > 20 minutes |

**Escalation Actions (Overall)**:
- Critical SLA breaches: Immediate management notification, process review
- Multiple SLA breaches: Incident response team review, playbook update
- Consistent metric degradation: Root cause analysis, resource allocation review

### Reporting Requirements

```yaml
sla_reporting:
  frequency: weekly
  distribution: [soc_team, management, stakeholders]

  reports:
    - name: sla_compliance_dashboard
      metrics:
        - detection_time_trend
        - triage_time_trend
        - containment_time_trend
        - sla_breach_count
        - escalation_count

    - name: performance_metrics
      metrics:
        - incidents_by_severity
        - mean_time_to_detect
        - mean_time_to_respond
        - mean_time_to_recover
        - automation_rate
        - false_positive_rate

    - name: breach_analysis
      content:
        - breached_slas_list
        - root_cause_analysis
        - corrective_actions_taken
        - trend_analysis
```

## Metrics and Continuous Improvement

### Key Metrics

| Category | Metric | Target | Frequency |
|----------|--------|--------|-----------|
| Detection | MTTD (Mean Time to Detect) | < 2 min | Per incident |
| Triage | MTT-Triage | < 5 min | Per incident |
| Response | MTTR (Mean Time to Respond) | < 30 min | Per incident |
| Resolution | MTTR (Mean Time to Resolve) | < 12 hours | Per incident |
| Accuracy | False Positive Rate | < 10% | Weekly |
| Effectiveness | Recurrence Rate | < 1% | Monthly |
| Automation | Automation Coverage | > 80% | Monthly |

### Continuous Improvement Process

```yaml
improvement_cycle:
  quarterly_review:
    - metric_analysis
    - playbook_effectiveness
    - automation_opportunities
    - tool_evaluation

  monthly_review:
    - incident_trends
    - sla_performance
    - false_positive_analysis
    - rule_tuning_needs

  weekly_review:
    - recent_incidents
    - sla_breaches
    - quick_wins
    - team_feedback
```

## References and Resources

### MITRE ATT&CK
- T1110 - Brute Force: https://attack.mitre.org/techniques/T1110/
- T1110.001 - Password Guessing: https://attack.mitre.org/techniques/T1110/001/
- T1110.002 - Password Cracking: https://attack.mitre.org/techniques/T1110/002/
- T1110.003 - Password Spraying: https://attack.mitre.org/techniques/T1110/003/
- T1110.004 - Credential Stuffing: https://attack.mitre.org/techniques/T1110/004/

### Frameworks and Standards
- NIST SP 800-61r2: Computer Security Incident Handling Guide
- ISO/IEC 27035: Information Security Incident Management
- SANS Incident Handler's Handbook
- NIST Cybersecurity Framework
- CIS Critical Security Controls

### Wazuh Documentation
- Wazuh Ruleset Documentation: https://documentation.wazuh.com/current/user-manual/ruleset/
- Wazuh Active Response: https://documentation.wazuh.com/current/user-manual/capabilities/active-response/
- Wazuh API Reference: https://documentation.wazuh.com/current/user-manual/api/

### Threat Intelligence
- AlienVault OTX: https://otx.alienvault.com/
- AbuseIPDB: https://www.abuseipdb.com/
- VirusTotal: https://www.virustotal.com/
- Shodan: https://www.shodan.io/

### Tools and Utilities
- Wazuh Autopilot: https://github.com/[organization]/wazuh-openclaw-autopilot
- OpenClaw Framework: https://github.com/[organization]/openclaw
- Evidence Collection Scripts: /tools/evidence-collection/

## Appendix A: Quick Reference Card

### Immediate Actions Checklist

```
☐ Alert received and acknowledged
☐ Entities extracted (IP, User, Host)
☐ Severity assessed
☐ Attack pattern identified
☐ Historical context reviewed
☐ Compromise check completed
☐ Response plan generated
☐ Approval obtained (if required)
☐ Containment actions executed
☐ Verification completed
☐ Evidence collected and preserved
☐ Stakeholders notified
☐ Eradication procedures initiated
☐ Recovery plan executed
☐ Enhanced monitoring enabled
☐ Post-incident review scheduled
☐ Documentation completed
```

### Emergency Contact List

```yaml
emergency_contacts:
  soc_team:
    primary: ${soc_primary_contact}
    secondary: ${soc_secondary_contact}
    hotline: ${soc_hotline}

  management:
    ciso: ${ciso_contact}
    it_director: ${it_director_contact}
    security_manager: ${security_manager_contact}

  external:
    incident_response_vendor: ${ir_vendor_contact}
    legal_counsel: ${legal_contact}
    public_relations: ${pr_contact}
```

### Critical Commands Reference

**Linux**:
```bash
# Check failed logins
sudo lastb | head -20

# Check active sessions
who -a

# Block IP (iptables)
sudo iptables -A INPUT -s <IP> -j DROP

# Block IP (ufw)
sudo ufw deny from <IP>

# Lock user account
sudo passwd -l <username>
```

**Windows**:
```powershell
# Check failed logins
Get-WinEvent -FilterHashtable @{LogName='Security';ID=4625} | Select -First 20

# Check active sessions
query user

# Block IP (firewall)
New-NetFirewallRule -DisplayName "Block <IP>" -Direction Inbound -RemoteAddress <IP> -Action Block

# Disable user account
Disable-LocalUser -Name <username>
```

## Document Revision History

| Version | Date | Author | Changes |
|---------|------|--------|---------|
| 1.0.0 | 2025-01-15 | SOC Team | Initial playbook creation |
| 2.0.0 | 2026-02-17 | SOC Team | Major revision: Added comprehensive MITRE ATT&CK mapping, expanded detection rules, enhanced decision tree, forensic procedures, chain of custody, communication templates, regulatory compliance mapping, agent pipeline integration, enhanced SLAs with escalation thresholds |

---

**END OF PLAYBOOK**

*This is a controlled document. Unauthorized distribution is prohibited.*
*Classification: TLP:AMBER - Internal Use Only*
