# Playbook: Vulnerability Spike Detection and Response

## Classification

| Field | Value |
|-------|-------|
| Playbook ID | PB-005 |
| Version | 2.0.0 |
| Last Updated | 2026-02-17 |
| TLP Marking | TLP:AMBER |
| Distribution | Organization Internal / SOC Operations |
| Severity | Variable (CVSS 0.1-10.0) |
| Category | Vulnerability Management & Threat Response |
| Lifecycle Stage | Production |

## Overview

### Purpose

This playbook provides enterprise-grade procedures for detecting, triaging, and responding to vulnerability spikes - sudden increases in vulnerability detections or exploitation attempts. It integrates comprehensive vulnerability management practices with threat intelligence, patch orchestration, and regulatory compliance requirements.

### Scope

**In Scope:**
- Zero-day and n-day vulnerability disclosures
- Active exploitation campaigns
- Mass scanning and reconnaissance activity
- Failed patch deployments leaving systems exposed
- Vulnerability detector anomalies
- IDS/IPS exploitation signature triggers
- Security Configuration Assessment (SCA) failures

**Out of Scope:**
- Routine vulnerability scan results (covered by standard VM process)
- Individual host-specific findings (handled by asset management)
- Penetration testing results (separate workflow)

## MITRE ATT&CK Mapping

| Technique ID | Technique Name | Relevance |
|--------------|----------------|-----------|
| T1190 | Exploit Public-Facing Application | Primary - Internet-facing service exploitation |
| T1203 | Exploitation for Client Execution | Client-side vulnerability exploitation |
| T1210 | Exploitation of Remote Services | Remote service exploitation (SMB, RDP, etc.) |
| T1211 | Exploitation for Defense Evasion | Vulnerabilities used to bypass security controls |
| T1068 | Exploitation for Privilege Escalation | Local privilege escalation vulnerabilities |
| T1212 | Exploitation for Credential Access | Credential harvesting via vulnerabilities |

**Kill Chain Coverage:** Delivery, Exploitation, Installation, Command & Control

## Detection Criteria

### Primary Indicators

#### Volume-Based Detection
```yaml
spike_thresholds:
  new_cve_findings:
    baseline: rolling_7d_average
    trigger: 3x_standard_deviation
    minimum_threshold: 10_findings

  exploitation_attempts:
    baseline: daily_average
    trigger: 5x_increase
    minimum_threshold: 5_attempts

  affected_host_concentration:
    trigger: same_cve_on_20percent_hosts
    minimum_hosts: 5
```

#### Exploitation Attempt Patterns
- CVE-specific IDS/IPS signature matches
- WAF rule violations matching known exploit patterns
- HTTP/HTTPS requests with exploit payloads
- Failed authentication followed by vulnerability scanning
- Successful exploitation indicators (reverse shells, callbacks)
- Post-exploitation behavior (lateral movement, persistence)

### Wazuh Detection Integration

#### Vulnerability Detector Module
```yaml
wazuh_vuln_detector:
  data_sources:
    - NVD (National Vulnerability Database)
    - Red Hat Security Advisories
    - Debian Security Tracker
    - Ubuntu Security Notices
    - Microsoft Security Updates
    - Arch Linux Security

  detection_states:
    - NEW: First detection of CVE on asset
    - PENDING: Vulnerability confirmed, awaiting remediation
    - SOLVED: Patch applied, verification pending
    - REMOVED: Vulnerability no longer present

  alert_rules:
    - rule_id: 23502 # Vulnerability detected in package
    - rule_id: 23503 # Critical vulnerability (CVSS >= 9.0)
    - rule_id: 23504 # High vulnerability (CVSS >= 7.0)
    - rule_id: 23505 # Medium vulnerability (CVSS >= 4.0)
```

#### Security Configuration Assessment (SCA)
```yaml
sca_integration:
  policy_failures:
    - CIS Benchmarks (failed checks indicating vulnerable configs)
    - PCI-DSS requirements (patch management compliance)
    - NIST 800-53 controls (vulnerability management)
    - Custom organizational policies

  alert_correlation:
    - rule_id: 19009 # SCA summary alert
    - rule_id: 19011 # SCA check failed

  criticality_mapping:
    - failed_check_score >= 75: CRITICAL
    - failed_check_score >= 50: HIGH
    - failed_check_score >= 25: MEDIUM
```

#### IDS Integration (Suricata/Snort)
```yaml
ids_rules:
  suricata:
    - rule_groups: exploit_kit
    - rule_groups: shellcode
    - rule_groups: web_application_attack
    - classtype: attempted-admin
    - classtype: attempted-user
    - classtype: web-application-attack

  snort:
    - gid: 1 # Community rules
    - gid: 3 # Emerging Threats
    - priority: 1 # Critical exploits
    - priority: 2 # High-risk attacks

  wazuh_mapping:
    - rule_id: 86600 # Suricata alert
    - rule_id: 40101 # Snort alert
```

#### ModSecurity/OWASP CRS Integration
```yaml
waf_detection:
  modsecurity_rules:
    - paranoia_level >= 2
    - anomaly_score >= 5
    - rule_groups: REQUEST-934-APPLICATION-ATTACK-GENERIC
    - rule_groups: REQUEST-942-APPLICATION-ATTACK-SQLI
    - rule_groups: REQUEST-943-APPLICATION-ATTACK-SESSION-FIXATION

  wazuh_rules:
    - rule_id: 31101 # ModSecurity alert
    - rule_id: 31151 # OWASP CRS critical

  correlation_keys:
    - CVE ID in rule message
    - Attack pattern matching known exploits
```

#### Syscollector Package Inventory Correlation
```yaml
package_correlation:
  syscollector_data:
    - installed_packages (name, version, architecture)
    - hotfixes (Windows KB patches)
    - running_processes (vulnerable service detection)
    - open_ports (exposed vulnerable services)

  correlation_logic: |
    1. Vulnerability Detector identifies CVE in package X v1.0
    2. Syscollector confirms package X v1.0 installed
    3. Syscollector shows service X running on port 8080
    4. Firewall logs show port 8080 internet-accessible
    5. Risk score: CRITICAL (vulnerable + exposed + running)

  enrichment_queries:
    - Affected package install date
    - Package dependencies (transitive vulnerabilities)
    - Service uptime (exploitation window)
    - Asset role/criticality (CMDB lookup)
```

### Severity Classification

#### Base CVSS v3.1 Scoring
| CVSS Score | NVD Rating | Response SLA | Patch SLA |
|------------|------------|--------------|-----------|
| 9.0 - 10.0 | CRITICAL | Immediate (15 min) | 24 hours |
| 7.0 - 8.9 | HIGH | 1 hour | 72 hours |
| 4.0 - 6.9 | MEDIUM | 4 hours | 7 days |
| 0.1 - 3.9 | LOW | 24 hours | 30 days |

#### Environmental Scoring Adjustments
```yaml
environmental_factors:
  modified_impact_subscore:
    confidentiality_requirement:
      HIGH: 1.5x # Healthcare, Financial data
      MEDIUM: 1.0x # General business data
      LOW: 0.5x # Public information

    integrity_requirement:
      HIGH: 1.5x # Financial transactions, SCADA
      MEDIUM: 1.0x # General systems
      LOW: 0.5x # Logging/monitoring only

    availability_requirement:
      HIGH: 1.5x # Critical infrastructure, SaaS
      MEDIUM: 1.0x # Standard services
      LOW: 0.5x # Development/test

  exploit_maturity_modifiers:
    NOT_DEFINED: 1.0x
    UNPROVEN: 0.9x
    PROOF_OF_CONCEPT: 1.1x
    FUNCTIONAL: 1.2x
    HIGH: 1.5x # Weaponized exploits in the wild

  remediation_level_modifiers:
    OFFICIAL_FIX: 0.95x
    TEMPORARY_FIX: 0.97x
    WORKAROUND: 0.99x
    UNAVAILABLE: 1.0x

  report_confidence_modifiers:
    CONFIRMED: 1.0x
    REASONABLE: 0.96x
    UNKNOWN: 0.92x
```

### High-Priority Conditions
```yaml
critical_escalation_triggers:
  # Automatic escalation to Incident Response
  conditions:
    - cvss_base_score >= 9.0
    - AND (public_exploit_available OR active_exploitation_wild)
    - AND (internet_facing OR dmz_asset)
    - AND (critical_asset_tier OR production_environment)

  # CISA KEV (Known Exploited Vulnerabilities) listed
  cisa_kev_match:
    auto_escalate: true
    override_sla: true
    max_remediation_time: cisa_due_date # Per BOD 22-01

  # Zero-day exploitation detected
  zero_day_indicators:
    - nvd_published_date == null
    - AND ids_signature_match == true
    - AND suspicious_outbound_connections == true
    escalation: immediate_ir_activation

  # Mass exploitation campaign
  campaign_detection:
    - same_cve_exploitation_attempts > 100
    - OR unique_source_ips_attacking > 50
    - OR affected_internet_hosts > 10percent_estate
    escalation: soc_manager + ciso_notification
```

## Decision Tree

```
┌─────────────────────────────────┐
│  Vulnerability Spike Detected   │
│  (threshold exceeded)           │
└────────────┬────────────────────┘
             │
             ▼
    ┌────────────────────┐
    │ New CVE disclosure │◄───── CVE-YYYY-NNNNN in alert?
    │ vs existing vuln?  │
    └─────┬──────────────┘
          │
          ├─── NEW CVE ──────────┐
          │                       │
          │                       ▼
          │              ┌──────────────────┐
          │              │ Parse CVSS vector│
          │              │ Calculate score  │
          │              └────────┬─────────┘
          │                       │
          │                       ▼
          │              ┌──────────────────┐
          │              │ CISA KEV listed? │
          │              └─┬────────────┬───┘
          │                │ YES        │ NO
          │                ▼            │
          │         [PRIORITY PATH]     │
          │         SLA: KEV due date   │
          │                │            │
          │                └────┬───────┘
          │                     │
          └─── EXISTING VULN ───┤
                                │
                                ▼
                   ┌────────────────────────┐
                   │ Public exploit         │
                   │ available?             │
                   └──┬──────────────────┬──┘
                      │ YES (ExploitDB,  │ NO
                      │  GitHub, MSF)    │
                      ▼                  │
               ┌──────────────┐          │
               │ Severity +1  │          │
               └──────┬───────┘          │
                      │                  │
                      └────────┬─────────┘
                               │
                               ▼
                  ┌────────────────────────┐
                  │ Active exploitation    │
                  │ detected?              │
                  └──┬──────────────────┬──┘
                     │ YES (IDS hits,   │ NO (scan only)
                     │  successful)     │
                     ▼                  │
              ┌──────────────┐          │
              │ IR ACTIVATION│          │
              │ Severity +2  │          │
              └──────┬───────┘          │
                     │                  │
                     └────────┬─────────┘
                              │
                              ▼
                 ┌────────────────────────┐
                 │ Internet-facing        │
                 │ vs internal?           │
                 └──┬──────────────────┬──┘
                    │ Internet/DMZ     │ Internal only
                    ▼                  │
             ┌──────────────┐          │
             │ Severity +1  │          │
             │ Priority HIGH│          │
             └──────┬───────┘          │
                    │                  │
                    └────────┬─────────┘
                             │
                             ▼
                ┌────────────────────────┐
                │ Asset criticality      │
                │ check (CMDB)           │
                └──┬──────────────────┬──┘
                   │ TIER-1 Critical  │ TIER-2/3
                   ▼                  │
            ┌──────────────┐          │
            │ Severity +1  │          │
            │ Executive    │          │
            │ notification │          │
            └──────┬───────┘          │
                   │                  │
                   └────────┬─────────┘
                            │
                            ▼
               ┌────────────────────────┐
               │ Compensating controls? │
               │ (WAF, segmentation)    │
               └──┬──────────────────┬──┘
                  │ YES              │ NO
                  ▼                  │
           ┌──────────────┐          │
           │ Risk reduced │          │
           │ Extend SLA?  │          │
           └──────┬───────┘          │
                  │                  │
                  └────────┬─────────┘
                           │
                           ▼
              ┌────────────────────────┐
              │ FINAL SEVERITY &       │
              │ REMEDIATION PATH       │
              └────────────────────────┘
                           │
                           ├─── CRITICAL ──► Emergency Patch (24hr)
                           ├─── HIGH ──────► Expedited Patch (72hr)
                           ├─── MEDIUM ────► Standard Patch (7d)
                           └─── LOW ───────► Routine Cycle (30d)
```

## Automated Triage Steps

### 1. Entity Extraction
```yaml
entity_extraction:
  cve_identifiers:
    pattern: CVE-\d{4}-\d{4,7}
    sources:
      - data.vulnerability.cve
      - data.win.eventdata.cve
      - rule.description
      - full_log (regex extraction)

  affected_hosts:
    sources:
      - agent.name
      - agent.id
      - data.srcip (for exploitation attempts)
      - data.dstip (for targeted systems)
    enrichment:
      - CMDB asset lookup
      - Network zone classification
      - Asset criticality tier

  vulnerable_software:
    sources:
      - data.vulnerability.package.name
      - data.vulnerability.package.version
      - syscollector.packages
    correlation:
      - CPE (Common Platform Enumeration) matching
      - Version range validation

  attacker_infrastructure:
    sources:
      - data.srcip (exploitation source)
      - data.http.hostname (C2 domains)
      - data.dns.query (malicious lookups)
    enrichment:
      - GreyNoise (mass scanning activity)
      - AbuseIPDB (reputation scoring)
      - VirusTotal (domain/IP intelligence)
```

### 2. Vulnerability Assessment
```yaml
vulnerability_assessment:
  step_1_cve_validation:
    query_nvd_api: |
      GET https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=${cve_id}
    extract:
      - CVSS v3.1 vector string
      - Base score, impact subscore, exploitability subscore
      - CWE (Common Weakness Enumeration)
      - Affected product CPE URIs
      - Reference links
      - Published and last modified dates

  step_2_exploit_availability:
    sources:
      - exploit_db:
          url: https://www.exploit-db.com/search?cve=${cve_id}
          confidence: HIGH (verified exploits)
      - packetstorm:
          url: https://packetstormsecurity.com/search/?q=${cve_id}
          confidence: MEDIUM
      - github_exploits:
          query: "${cve_id} poc OR exploit"
          confidence: VARIABLE (code review required)
      - metasploit:
          query: msfconsole -q -x "search cve:${cve_year} ${cve_number}"
          confidence: CRITICAL (weaponized)
      - nuclei_templates:
          path: nuclei-templates/cves/${cve_year}/${cve_id}.yaml
          confidence: HIGH (automated scanning)

  step_3_exploitation_status:
    cisa_kev_check: |
      GET https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json
      MATCH cveID == ${cve_id}
      IF MATCH: flag_active_exploitation = TRUE

    greynoise_riot_check: |
      GET https://api.greynoise.io/v3/community/${source_ip}
      IF classification == "malicious" AND tags CONTAINS "exploit":
        active_exploitation_confirmed = TRUE

    threat_intel_feeds:
      - AlienVault OTX pulses
      - MISP threat sharing
      - Commercial feeds (Recorded Future, etc.)

  step_4_cvss_parsing:
    parse_vector: CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H
    components:
      attack_vector: [N]etwork, [A]djacent, [L]ocal, [P]hysical
      attack_complexity: [L]ow, [H]igh
      privileges_required: [N]one, [L]ow, [H]igh
      user_interaction: [N]one, [R]equired
      scope: [U]nchanged, [C]hanged
      confidentiality_impact: [N]one, [L]ow, [H]igh
      integrity_impact: [N]one, [L]ow, [H]igh
      availability_impact: [N]one, [L]ow, [H]igh

    calculate_temporal_score:
      exploit_code_maturity: [X, U, P, F, H]
      remediation_level: [X, O, T, W, U]
      report_confidence: [X, U, R, C]
      formula: base_score * exploit * remediation * confidence

    calculate_environmental_score:
      modified_attack_vector: [X, N, A, L, P]
      # ... (apply organizational context)
      confidentiality_requirement: [X, L, M, H]
      integrity_requirement: [X, L, M, H]
      availability_requirement: [X, L, M, H]
```

### 3. Exposure Assessment
```yaml
exposure_assessment:
  affected_systems_inventory:
    query_wazuh: |
      GET /vulnerability/${cve_id}
      GROUP BY agent.id
      COLLECT: agent.name, agent.ip, agent.os, status

    enrich_with_syscollector:
      - Package install date (exploitation window)
      - Service status (running vs stopped)
      - Open ports (network exposure)
      - User accounts (privilege context)

  internet_exposure_validation:
    firewall_rule_check:
      query: "affected_host_ip IN allowed_public_access"
      sources:
        - Firewall ACL logs
        - Cloud security group rules (AWS/Azure/GCP)
        - Load balancer configurations

    external_scan_verification:
      tools:
        - Shodan API: search "ip:${host_ip} port:${vulnerable_port}"
        - Censys API: search "services.port=${port} AND ip=${host_ip}"
      confirmation: "If external scan confirms open port: INTERNET_FACING=TRUE"

  asset_criticality_lookup:
    cmdb_query: |
      SELECT asset_tier, business_service, rto, rpo, data_classification
      FROM cmdb.assets
      WHERE hostname = '${agent.name}' OR ip_address = '${agent.ip}'

    tier_definitions:
      TIER_1_CRITICAL:
        - Revenue-generating applications
        - Customer-facing services
        - Regulated data processing (PCI, HIPAA, SOX)
        - RTO < 4 hours
      TIER_2_HIGH:
        - Business-critical applications
        - Internal collaboration tools
        - RTO < 24 hours
      TIER_3_MEDIUM:
        - Departmental applications
        - Development/staging environments
        - RTO < 72 hours
      TIER_4_LOW:
        - Lab/test systems
        - Decommissioned assets
        - RTO > 1 week

  compensating_controls_validation:
    waf_coverage:
      query: "vulnerable_app IN waf_protected_backends"
      rule_check: "WAF rules contain virtual_patch_for_${cve_id}"
      effectiveness: "Review WAF block logs for ${cve_id} signatures"

    network_segmentation:
      check: "vulnerable_host IN isolated_vlan"
      validation: "ACLs prevent lateral movement from host"

    service_restriction:
      authentication: "Service requires MFA or VPN access"
      ip_allowlist: "Only trusted IPs can reach vulnerable service"

    monitoring_enhancement:
      ids_coverage: "IDS signatures active for ${cve_id}"
      edr_deployed: "EDR agent with behavioral detection"
      log_forwarding: "Real-time log streaming to SIEM"
```

### 4. Risk Scoring Engine
```yaml
risk_calculation:
  formula: |
    RISK_SCORE = (CVSS_Environmental * Exposure_Multiplier *
                  Threat_Multiplier) - Compensating_Controls_Reduction

  exposure_multiplier:
    internet_facing: 2.0
    dmz: 1.5
    internal_network: 1.0
    isolated_vlan: 0.5

  threat_multiplier:
    cisa_kev_listed: 2.0
    metasploit_module: 1.8
    public_poc: 1.5
    exploit_predicted: 1.2
    no_known_exploit: 1.0

  compensating_controls_reduction:
    waf_virtual_patch: -2.0
    network_isolation: -1.5
    authentication_required: -1.0
    ids_signature_active: -0.5

  final_severity_mapping:
    risk_score >= 9.0: CRITICAL
    risk_score >= 7.0: HIGH
    risk_score >= 4.0: MEDIUM
    risk_score < 4.0: LOW
```

## Correlation Rules

### Multi-Event Clustering
```yaml
correlation_scenarios:
  scenario_1_exploitation_campaign:
    name: "Mass exploitation attempt detected"
    events_required:
      - Multiple IDS alerts (same CVE, different sources)
      - Multiple vulnerable hosts (same CVE)
      - Time window: 1 hour
    correlation_logic: |
      IF COUNT(DISTINCT data.srcip WHERE data.cve=${cve_id}) >= 10
      AND COUNT(DISTINCT agent.id WHERE vulnerability.cve=${cve_id}) >= 5
      AND time_range <= 3600s
      THEN trigger_campaign_alert
    severity_escalation: +2 levels

  scenario_2_successful_exploitation:
    name: "Vulnerability exploit followed by compromise indicators"
    events_required:
      - IDS alert (CVE signature match)
      - Followed by: reverse shell, web shell upload, or privilege escalation
      - Same destination host
      - Time window: 15 minutes
    correlation_logic: |
      IF ids_alert.cve EXISTS
      AND (rule.groups CONTAINS "web_shell"
           OR rule.groups CONTAINS "reverse_shell"
           OR rule.groups CONTAINS "privilege_escalation")
      AND ids_alert.dstip == compromise_indicator.srcip
      AND time_diff <= 900s
      THEN trigger_incident_response
    actions:
      - Isolate affected host (pending approval)
      - Activate IR playbook
      - Notify CISO

  scenario_3_failed_patch_deployment:
    name: "Vulnerability persists after patch cycle"
    events_required:
      - Vulnerability detected in scan N
      - Patch deployment logged
      - Vulnerability still present in scan N+1
      - Time window: 7 days
    correlation_logic: |
      IF vulnerability.state == "SOLVED" AT time_T
      AND patch_deployment_log.package == vulnerability.package
      AND vulnerability.state == "PENDING" AT time_T+7d
      THEN trigger_patch_failure_alert
    actions:
      - Notify IT operations
      - Escalate to change management
      - Request root cause analysis
```

### Timeline Construction
```yaml
timeline_query:
  vulnerability_lifecycle:
    phases:
      - discovery:
          query: "data.vulnerability.cve:${cve_id} AND state:NEW"
          time_range: -30d to now

      - exploitation_attempts:
          query: |
            (rule.groups:ids OR rule.groups:web_attack)
            AND (data.cve:${cve_id} OR rule.description:${cve_id})
          time_range: -30d to now

      - patch_activities:
          query: |
            data.vulnerability.cve:${cve_id}
            AND (state:SOLVED OR data.win.eventdata.package:*)
          time_range: -30d to now

      - validation_scans:
          query: "data.vulnerability.cve:${cve_id} AND state:REMOVED"
          time_range: -30d to now

  aggregation:
    group_by:
      - agent.name (per-host timeline)
      - data.srcip (attacker activity timeline)
      - hour_of_day (temporal pattern analysis)

    visualizations:
      - Heatmap: exploitation attempts by hour/day
      - Graph: affected hosts over time
      - Funnel: vulnerability state transitions
```

## Response Plan

### Phase 1: Immediate Assessment (0-15 minutes)

#### Step 1: Alert Validation
```yaml
validation_checklist:
  - [ ] CVE ID confirmed valid (NVD lookup successful)
  - [ ] CVSS score parsed and environmental score calculated
  - [ ] Affected host count verified (cross-reference syscollector)
  - [ ] False positive indicators checked:
      - [ ] Vulnerability in non-executable package (docs, fonts)
      - [ ] Service not running or not accessible
      - [ ] Patch already applied but scanner not updated

automation:
  agent: triage_agent
  tasks:
    - Extract all CVE IDs from alert
    - Query NVD API for each CVE
    - Cross-reference with Wazuh vulnerability DB
    - Generate initial severity score
    - Flag high-priority conditions (CISA KEV, etc.)
```

#### Step 2: Threat Intelligence Enrichment
```yaml
intel_sources:
  cisa_kev:
    api: https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json
    check: |
      IF cve_id IN kev_catalog:
        priority = CRITICAL
        due_date = kev_entry.dueDate
        notes = kev_entry.notes

  vulncheck_api:
    endpoint: https://api.vulncheck.com/v3/index/vulncheck-kev
    enrichment:
      - Initial exploitation date
      - Exploit maturity level
      - Related malware families

  greynoise:
    endpoint: https://api.greynoise.io/v3/community/${source_ip}
    data:
      - IP reputation
      - Mass scanning activity
      - CVE-specific targeting tags

  exploit_databases:
    parallel_queries:
      - exploit_db: "https://www.exploit-db.com/search?cve=${cve_id}"
      - packetstorm: "https://packetstormsecurity.com/search/?q=${cve_id}"
      - github: "https://api.github.com/search/repositories?q=${cve_id}+exploit"
    parsing:
      - Exploit availability: BOOLEAN
      - Exploit type: [PoC, Functional, Weaponized]
      - Publication date
```

#### Step 3: Exposure Mapping
```yaml
exposure_assessment:
  affected_assets:
    wazuh_query: |
      GET /vulnerability/${cve_id}
      FIELDS: agent.id, agent.name, agent.ip, package.name,
              package.version, detection_time

    enrichment_per_asset:
      - cmdb_lookup:
          criticality_tier: [1-4]
          business_owner: email_address
          business_service: service_name
          data_classification: [PUBLIC, INTERNAL, CONFIDENTIAL, RESTRICTED]

      - network_context:
          zone: [INTERNET, DMZ, INTERNAL, ISOLATED]
          firewall_policy: ACL_rules
          public_ip: BOOLEAN

      - syscollector_data:
          service_running: BOOLEAN
          listening_ports: [list]
          last_boot: timestamp

  aggregated_metrics:
    total_affected: COUNT(DISTINCT agent.id)
    internet_facing: COUNT WHERE zone IN [INTERNET, DMZ]
    critical_assets: COUNT WHERE criticality_tier == 1
    running_vulnerable_service: COUNT WHERE service_running == TRUE
    exploitable_hosts: COUNT WHERE internet_facing AND running_service
```

### Phase 2: Risk Analysis & Prioritization (15-60 minutes)

#### Step 1: CVSS Environmental Scoring
```yaml
environmental_scoring:
  input_base_vector: ${nvd_cvss_vector}

  environmental_modifiers:
    confidentiality_requirement:
      logic: |
        IF data_classification IN [RESTRICTED, CONFIDENTIAL]: CR:H
        ELIF data_classification == INTERNAL: CR:M
        ELSE: CR:L

    integrity_requirement:
      logic: |
        IF business_service IN [financial_processing, scada_control]: IR:H
        ELIF criticality_tier == 1: IR:M
        ELSE: IR:L

    availability_requirement:
      logic: |
        IF rto < 4_hours: AR:H
        ELIF rto < 24_hours: AR:M
        ELSE: AR:L

  modified_base_metrics:
    # Adjust if compensating controls reduce attack vector
    modified_attack_vector:
      IF waf_enabled AND base_av == "N": MAV:A  # Network -> Adjacent
      IF vpn_required AND base_av == "N": MAV:L  # Network -> Local

    modified_privileges_required:
      IF mfa_enforced AND base_pr == "N": MPR:L  # None -> Low

  output: environmental_cvss_score (adjusted for organizational context)
```

#### Step 2: Remediation Path Decision
```yaml
remediation_decision_tree:
  decision_factors:
    - cvss_environmental_score
    - cisa_kev_status
    - active_exploitation_detected
    - patch_availability
    - change_window_availability
    - business_impact_of_downtime

  paths:
    emergency_patching:
      triggers:
        - cvss >= 9.0 AND (cisa_kev OR active_exploitation)
        - cvss >= 7.0 AND active_exploitation AND internet_facing
      sla: 24_hours
      approval: security_manager (can bypass CAB)
      process: emergency_change_process
      rollback_plan: MANDATORY

    expedited_patching:
      triggers:
        - cvss >= 7.0 AND public_exploit_available
        - cvss >= 9.0 AND internal_only
      sla: 72_hours
      approval: change_advisory_board (expedited review)
      process: fast_track_change
      rollback_plan: MANDATORY

    standard_patching:
      triggers:
        - cvss >= 4.0 AND cvss < 7.0
        - cvss >= 7.0 AND compensating_controls_effective
      sla: 7_days
      approval: standard_cab_review
      process: normal_change_window
      rollback_plan: recommended

    deferred_patching:
      triggers:
        - cvss < 4.0
        - affected_asset_decommission_scheduled
      sla: 30_days_or_next_maintenance_window
      approval: asset_owner_acknowledgment
      process: routine_patch_cycle
      rollback_plan: not_required

    risk_acceptance:
      triggers:
        - patch_not_available
        - business_critical_system_cannot_tolerate_downtime
        - compensating_controls_sufficient
      approval: CISO + business_owner (documented exception)
      requirements:
        - Formal risk acceptance form
        - Compensating controls validation
        - Monitoring enhancement
        - Review period: quarterly
```

#### Step 3: Compensating Controls Deployment
```yaml
compensating_controls:
  waf_virtual_patching:
    applicable_when:
      - vulnerability.type IN [web_application, http_protocol]
      - waf_deployed == TRUE

    implementation:
      - Analyze exploit payload patterns
      - Create WAF rule (ModSecurity SecRule format)
      - Deploy to WAF (staged: test -> prod)
      - Validate blocking effectiveness
      - Monitor false positive rate

    example_rule: |
      SecRule REQUEST_URI "@rx /vulnerable-endpoint\.php" \
        "id:9001,phase:2,deny,status:403,\
         msg:'Virtual patch for CVE-2024-1234',\
         tag:'CVE-2024-1234',tag:'VIRTUAL_PATCH'"

    effectiveness_validation:
      - Penetration test with public exploit
      - Monitor block logs for 24 hours
      - False positive review

  network_segmentation:
    applicable_when:
      - vulnerable_service == internal_only
      - firewall_capability == available

    implementation:
      - Identify required communication paths
      - Create restrictive ACL (deny-by-default)
      - Apply to vulnerable host(s)
      - Test business functionality
      - Document exception justification

    example_acl: |
      # Allow only specific source IPs to vulnerable service
      permit tcp 10.100.50.0/24 host ${vulnerable_host} eq ${vuln_port}
      deny ip any host ${vulnerable_host} eq ${vuln_port} log

  service_restriction:
    applicable_when:
      - service_can_be_disabled_temporarily
      - OR authentication_can_be_added

    implementation:
      options:
        - stop_service: systemctl stop ${vulnerable_service}
        - add_authentication: configure nginx basic auth
        - ip_allowlist: iptables -A INPUT -s ${trusted_ip} -j ACCEPT
        - rate_limiting: limit_req_zone configuration

  monitoring_enhancement:
    always_applicable: TRUE

    implementation:
      - Deploy IDS signature for CVE
      - Enable verbose logging on vulnerable service
      - Create SIEM correlation rule for exploitation attempts
      - Alert on any access to vulnerable endpoint
      - EDR behavioral rule for post-exploit activity
```

### Phase 3: Execution & Coordination (1-24 hours)

#### Step 1: Patch Management Workflow
```yaml
patch_deployment_process:
  pre_deployment:
    tasks:
      - [ ] Patch validated in lab/test environment
      - [ ] Rollback plan documented and tested
      - [ ] Change ticket created with all details
      - [ ] Downtime notification sent to stakeholders
      - [ ] Backup of affected systems completed
      - [ ] Patch files downloaded and integrity-checked

    automation:
      - Ansible playbook: pre-patch-validation.yml
      - Terraform: snapshot-creation.tf (cloud instances)
      - CMDB update: maintenance_mode = TRUE

  deployment_phases:
    canary_deployment:
      scope: 1-2 non-critical hosts with same config
      duration: 4_hours
      validation:
        - Service availability check
        - Application functionality test
        - Performance baseline comparison
        - Log review for errors
      go_no_go: If validation passes -> proceed to pilot

    pilot_deployment:
      scope: 10% of affected hosts (diverse sample)
      duration: 24_hours
      validation:
        - User acceptance testing
        - Integration testing
        - Performance monitoring
        - Security scan (verify vuln remediated)
      go_no_go: If validation passes -> proceed to production

    production_deployment:
      scope: remaining 90% of hosts
      method: rolling_deployment (batches of 20%)
      duration: 48_hours
      rollback_triggers:
        - Service outage detected
        - Critical functionality broken
        - Performance degradation > 20%
        - New vulnerabilities introduced

  post_deployment:
    tasks:
      - [ ] Vulnerability scan confirms remediation
      - [ ] Service monitoring shows normal operation
      - [ ] User feedback collected (no major issues)
      - [ ] Change ticket closed with evidence
      - [ ] Metrics updated (MTTD, MTTR, patch coverage)
      - [ ] Lessons learned documented

    automation:
      - Wazuh vulnerability re-scan
      - Nessus/Qualys validation scan
      - CMDB update: patch_level, last_patched_date
      - Metrics dashboard update
```

#### Step 2: Communication Plan
```yaml
stakeholder_communication:
  initial_notification:
    trigger: vulnerability_spike_confirmed
    time: within_15_minutes
    recipients:
      - SOC Team (Slack: #soc-alerts)
      - Security Manager (email + SMS if CRITICAL)
      - IT Operations Manager (email)

    template: |
      Subject: [${severity}] Vulnerability Spike Detected - ${cve_id}

      A vulnerability spike has been detected requiring immediate attention.

      CVE: ${cve_id}
      CVSS Score: ${cvss_score} (${severity})
      Affected Systems: ${affected_count}
      Internet Facing: ${internet_facing_count}
      CISA KEV: ${cisa_kev_status}

      Active Exploitation: ${active_exploitation}
      Public Exploit: ${public_exploit_available}

      Recommended Action: ${primary_recommendation}
      Response SLA: ${response_sla}

      Case ID: ${case_id}
      Incident Dashboard: ${dashboard_link}

  emergency_patch_request:
    trigger: emergency_patch_path_selected
    time: within_1_hour
    recipients:
      - IT Operations (patching team)
      - Change Advisory Board chair
      - Asset owners
      - Business stakeholders

    template: |
      Subject: URGENT: Emergency Patch Required - ${cve_id}

      An emergency patch is required to address critical vulnerability ${cve_id}.

      JUSTIFICATION:
      - CVSS Score: ${cvss_environmental_score}
      - Active exploitation detected: ${active_exploitation}
      - CISA KEV deadline: ${kev_due_date}
      - Affected critical assets: ${critical_asset_count}

      AFFECTED SYSTEMS:
      ${affected_systems_table}

      PATCH DETAILS:
      - Vendor: ${vendor}
      - Patch ID: ${patch_id}
      - Download URL: ${patch_url}
      - Installation time per host: ${estimated_time}

      DEPLOYMENT PLAN:
      - Canary: ${canary_hosts} (${canary_start_time})
      - Pilot: ${pilot_hosts} (${pilot_start_time})
      - Production: ${production_hosts} (${production_start_time})

      ROLLBACK PLAN:
      ${rollback_procedure}

      APPROVAL REQUEST:
      Please approve emergency change ${change_ticket_id} by ${approval_deadline}.

      [Approve] [Request Modifications] [Escalate]

  executive_summary:
    trigger: critical_severity AND (critical_assets OR widespread_exposure)
    time: within_4_hours
    recipients:
      - CISO
      - CTO/CIO
      - VP of Operations
      - Legal (if breach risk)

    template: |
      Subject: Executive Summary - Critical Vulnerability ${cve_id}

      SITUATION:
      A critical vulnerability (${cve_id}) has been identified affecting ${affected_count}
      systems, including ${critical_asset_count} business-critical assets.

      RISK ASSESSMENT:
      - Severity: ${severity} (CVSS ${cvss_score})
      - Exploitation Status: ${exploitation_status}
      - Business Impact: ${business_impact_summary}
      - Regulatory Exposure: ${regulatory_implications}

      CURRENT STATUS:
      - Detection: ${detection_timestamp}
      - Assessment Completed: ${assessment_timestamp}
      - Remediation In Progress: ${remediation_status}
      - Expected Resolution: ${eta}

      REMEDIATION PLAN:
      ${remediation_summary}

      COMPENSATING CONTROLS:
      ${compensating_controls_summary}

      RESOURCE REQUIREMENTS:
      ${resource_needs}

      RECOMMENDATION:
      ${executive_recommendation}

      Detailed report: ${detailed_report_link}

  vendor_escalation:
    trigger: patch_not_available AND severity >= HIGH
    time: within_2_hours
    recipients:
      - Vendor TAM (Technical Account Manager)
      - Vendor Security Team

    template: |
      Subject: URGENT: Security Vulnerability Escalation - ${cve_id}

      Customer: ${organization_name}
      Account ID: ${vendor_account_id}
      Support Contract: ${support_tier}

      We are affected by ${cve_id} in ${product_name} ${product_version}.

      URGENCY JUSTIFICATION:
      - CVSS: ${cvss_score}
      - Active exploitation: ${active_exploitation}
      - Affected production systems: ${affected_count}
      - Business impact: ${business_impact}

      REQUEST:
      1. Expedited patch release timeline
      2. Interim mitigation guidance
      3. Technical support for workaround implementation
      4. Notification when patch is available

      CONTACT:
      Primary: ${primary_contact_name} (${primary_contact_phone})
      Secondary: ${secondary_contact_name} (${secondary_contact_phone})

      Please respond within 4 hours.

  risk_acceptance_form:
    trigger: risk_acceptance_path_selected
    time: before_deferring_remediation
    recipients:
      - CISO (approver)
      - Asset owner (requestor)
      - Security team (reviewer)

    template: |
      RISK ACCEPTANCE REQUEST

      CVE: ${cve_id}
      Affected Asset: ${asset_name}
      Risk Rating: ${risk_score}

      JUSTIFICATION FOR NON-REMEDIATION:
      ${justification_text}

      COMPENSATING CONTROLS:
      ${compensating_controls_detail}

      BUSINESS IMPACT OF PATCHING:
      ${downtime_impact}

      RISK OWNER:
      Name: ${business_owner_name}
      Title: ${business_owner_title}
      Signature: _________________ Date: _________

      SECURITY REVIEW:
      Compensating controls validated: [ ] Yes [ ] No
      Residual risk acceptable: [ ] Yes [ ] No
      Reviewer: ${security_reviewer_name}

      CISO APPROVAL:
      [ ] Approved [ ] Denied
      Exception valid until: ${expiration_date}
      Review frequency: Quarterly

      Signature: _________________ Date: _________
```

### Phase 4: Validation & Closure (24-72 hours post-patch)

#### Step 1: Remediation Verification
```yaml
verification_process:
  vulnerability_scanning:
    tools:
      - wazuh_vulnerability_detector:
          trigger: automatic_rescan_after_patch
          schedule: 24_hours_post_patch
          validation: "CVE state transition to REMOVED"

      - authenticated_scan:
          tool: [Nessus, Qualys, Rapid7]
          scope: all_affected_hosts
          validation: "Vulnerability no longer detected"

      - external_scan:
          tool: [Shodan, Censys, custom_scanner]
          scope: internet_facing_hosts_only
          validation: "Service version updated or vulnerability not exploitable"

    success_criteria:
      - 100% of affected hosts show patch applied
      - 0% residual vulnerability detections
      - Wazuh vulnerability DB updated (state: REMOVED)

  functional_validation:
    application_testing:
      - [ ] Service availability (uptime check)
      - [ ] Core functionality test suite
      - [ ] User acceptance testing (sample users)
      - [ ] Integration point testing
      - [ ] Performance baseline comparison

    security_validation:
      - [ ] Attempt exploitation (ethical hacking)
      - [ ] Review IDS/IPS logs (no new alerts)
      - [ ] Confirm WAF rules can be disabled (if virtual patch was used)
      - [ ] EDR behavioral monitoring (no anomalies)
```

#### Step 2: Metrics & Reporting
```yaml
metrics_collection:
  time_metrics:
    mean_time_to_detect: ${detection_timestamp - spike_start_timestamp}
    mean_time_to_assess: ${assessment_complete - detection_timestamp}
    mean_time_to_respond: ${remediation_start - detection_timestamp}
    mean_time_to_remediate: ${verification_complete - remediation_start}
    total_resolution_time: ${verification_complete - detection_timestamp}

  coverage_metrics:
    affected_hosts_identified: ${total_affected_count}
    hosts_patched: ${patched_count}
    patch_coverage_percentage: ${(patched_count / total_affected_count) * 100}
    hosts_risk_accepted: ${risk_accepted_count}
    hosts_compensating_controls: ${compensating_controls_count}

  effectiveness_metrics:
    false_positive_rate: ${false_positives / total_alerts}
    escalation_accuracy: ${justified_escalations / total_escalations}
    sla_compliance: ${resolved_within_sla / total_cases}
    rollback_rate: ${patches_rolled_back / patches_deployed}

  business_metrics:
    exploitation_prevented: ${internet_facing_patched_before_exploitation}
    downtime_incurred: ${total_downtime_minutes}
    estimated_risk_reduced: ${(cvss_score * affected_count * avg_asset_value)}
```

#### Step 3: Post-Incident Review
```yaml
lessons_learned:
  review_meeting:
    attendees:
      - SOC analysts (case handlers)
      - Incident responders
      - IT operations (patching team)
      - Security engineering
      - Management (Security Manager/CISO)

    agenda:
      - Timeline review (what happened when)
      - What went well
      - What could be improved
      - Process gaps identified
      - Tool/automation opportunities
      - Training needs

  action_items:
    categories:
      - process_improvements:
          example: "Establish pre-approved emergency patch list"
      - tool_enhancements:
          example: "Automate CISA KEV checking in triage"
      - training_needs:
          example: "Train IT ops on emergency rollback procedures"
      - documentation_updates:
          example: "Update playbook with new WAF rule examples"

    tracking:
      - Assign owner to each action item
      - Set due date
      - Track in project management tool
      - Review in next monthly security meeting
```

## Agent Pipeline Integration

### Triage Agent
```yaml
triage_agent_responsibilities:
  entity_extraction:
    - Parse CVE IDs from all alert fields
    - Extract affected hostnames, IPs, packages
    - Identify attacker infrastructure (source IPs, domains)

  enrichment:
    - Query NVD API for CVSS scores
    - Check CISA KEV catalog
    - Lookup exploit availability (ExploitDB, GitHub)
    - GreyNoise reputation check on source IPs

  severity_scoring:
    - Calculate base severity from CVSS
    - Apply environmental modifiers (asset criticality, exposure)
    - Apply threat modifiers (CISA KEV, active exploitation)
    - Subtract compensating controls reduction
    - Output final risk score (0-10)

  prioritization:
    - Rank all vulnerabilities by risk score
    - Flag CISA KEV entries (override priority)
    - Identify clusters (same CVE, multiple hosts)
    - Generate priority queue for correlation agent

  output_format:
    case_id: AUTO-${timestamp}-${cve_id}
    severity: [CRITICAL, HIGH, MEDIUM, LOW]
    priority_score: 0-100
    recommended_sla: timestamp
    escalation_required: BOOLEAN
    triage_summary: text
```

### Correlation Agent
```yaml
correlation_agent_responsibilities:
  asset_grouping:
    - Group affected hosts by business service
    - Group by network zone (Internet, DMZ, Internal)
    - Group by asset criticality tier
    - Group by patch feasibility (maintenance window alignment)

  timeline_construction:
    - Aggregate all events related to CVE
    - Create chronological timeline per affected host
    - Identify first exploitation attempt
    - Track patch deployment progress

  pattern_detection:
    - Detect mass exploitation campaigns
    - Identify attacker infrastructure patterns
    - Correlate multiple CVEs (exploit chains)
    - Detect scanning vs exploitation

  impact_assessment:
    - Calculate total business exposure
    - Estimate potential data at risk
    - Map to regulatory requirements (PCI, HIPAA, etc.)
    - Estimate remediation effort (host-hours)

  output_format:
    affected_asset_groups:
      - group_name: "Internet-facing web servers"
        host_count: 15
        criticality: TIER_1
        business_service: "E-commerce platform"
        recommended_action: "Emergency patch"

    exploitation_timeline:
      - timestamp: "2026-02-17T10:30:00Z"
        event: "First IDS alert"
        host: "web-prod-01"
        severity: HIGH

    campaign_indicators:
      mass_exploitation: TRUE
      unique_attackers: 47
      attack_countries: [CN, RU, US]
```

### Reporting Agent
```yaml
reporting_agent_responsibilities:
  executive_summary_generation:
    inputs:
      - Triage agent severity scores
      - Correlation agent impact assessment
      - Current remediation status

    output: |
      EXECUTIVE SUMMARY: ${cve_id}

      RISK LEVEL: ${severity}
      Affected Systems: ${total_count} (${critical_count} business-critical)
      Exploitation Status: ${exploitation_summary}

      BUSINESS IMPACT:
      ${business_impact_narrative}

      REMEDIATION STATUS:
      - Patched: ${patched_count} / ${total_count}
      - In Progress: ${in_progress_count}
      - Scheduled: ${scheduled_count}
      - Risk Accepted: ${risk_accepted_count}

      ESTIMATED COMPLETION: ${eta}

  technical_report_generation:
    outputs:
      - Detailed vulnerability analysis
      - CVSS breakdown and environmental scoring
      - Complete asset inventory (affected systems)
      - Exploitation attempt log
      - Remediation evidence (scan results, patch logs)
      - Compliance attestation (for auditors)

    format: [PDF, JSON, CSV, HTML_dashboard]

  metrics_dashboard_update:
    metrics:
      - Vulnerability exposure trend (time series)
      - Mean time to patch (by severity)
      - SLA compliance rate
      - Patch coverage percentage
      - Open vulnerability aging

    visualizations:
      - Heatmap: vulnerabilities by severity and asset tier
      - Graph: remediation progress over time
      - Pie chart: vulnerabilities by remediation status
      - Bar chart: top CVEs by risk score

  stakeholder_notifications:
    - Generate templated emails (using templates from Communication Plan)
    - Populate Slack messages with real-time data
    - Create change tickets (Jira, ServiceNow)
    - Update GRC tool (risk register entries)
```

## Regulatory Compliance

### NIST SP 800-40 Rev 4 (Patch Management)
```yaml
nist_sp_800_40_mapping:
  organizational_patch_management:
    playbook_sections:
      - "Patch Management Workflow" (Phase 3, Step 1)
      - "Remediation Path Decision" (Phase 2, Step 2)

    controls:
      - Patch prioritization based on risk (severity scoring)
      - Testing before deployment (canary/pilot phases)
      - Rollback procedures documented
      - Verification scanning post-patch

  enterprise_considerations:
    playbook_sections:
      - "Asset Criticality Lookup" (exposure assessment)
      - "Compensating Controls" (Phase 2, Step 3)

    controls:
      - Business impact assessment
      - Alternative mitigations when patching not feasible
      - Asset inventory integration (CMDB)

  audit_trail:
    evidence_collected:
      - Detection timestamp
      - Assessment documentation
      - Approval records (emergency change, risk acceptance)
      - Patch deployment logs
      - Verification scan results
```

### PCI-DSS v4.0 Requirement 6.3
```yaml
pci_dss_6_3_mapping:
  requirement_6_3_1:
    description: "Critical security patches installed within 30 days"
    playbook_compliance:
      - Critical patches (CVSS >= 9.0): 24-hour SLA
      - High patches (CVSS >= 7.0): 72-hour SLA
      - Exceeds PCI requirement

    evidence:
      - Patch deployment logs
      - Vulnerability scan reports (before/after)
      - Change tickets with timestamps

  requirement_6_3_2:
    description: "All other security patches installed within appropriate timeframe"
    playbook_compliance:
      - Medium patches: 7-day SLA
      - Low patches: 30-day SLA
      - Risk-based prioritization

    evidence:
      - Remediation tracking dashboard
      - SLA compliance metrics
      - Risk acceptance forms (for deferred patches)

  requirement_6_3_3:
    description: "Inventory of security patches"
    playbook_compliance:
      - Wazuh vulnerability database (continuous inventory)
      - Syscollector package inventory
      - Patch status tracking (PENDING, SOLVED, REMOVED)

    evidence:
      - Wazuh vulnerability report
      - CMDB patch level records
      - Monthly vulnerability summary
```

### CISA BOD 22-01 (KEV Remediation)
```yaml
cisa_bod_22_01_mapping:
  federal_applicability:
    note: "Applies to federal agencies; private sector best practice"

  requirement:
    description: "Remediate CISA KEV vulnerabilities by published due date"
    playbook_compliance:
      - Automatic CISA KEV checking (triage agent)
      - Override standard SLA with KEV due date
      - Executive escalation for KEV entries
      - Mandatory reporting to CISO

    implementation:
      detection: |
        IF cve_id IN cisa_kev_catalog:
          priority = CRITICAL_OVERRIDE
          sla = kev_entry.dueDate
          notification = CISO + federal_reporting_team

      tracking:
        - Separate KEV dashboard
        - Daily status reports
        - Escalation if approaching due date

  evidence:
    - KEV remediation tracking log
    - Verification scans post-remediation
    - Compliance attestation report
```

### ISO 27001:2022 A.12.6 (Technical Vulnerability Management)
```yaml
iso_27001_a12_6_mapping:
  control_12_6_1:
    description: "Management of technical vulnerabilities"
    playbook_compliance:
      - Timely identification (continuous Wazuh scanning)
      - Risk assessment (CVSS environmental scoring)
      - Remediation tracking (case management)
      - Verification (post-patch scanning)

    evidence:
      - Vulnerability management policy (references playbook)
      - Detection logs
      - Risk assessments (per vulnerability)
      - Remediation records

  control_12_6_2:
    description: "Software installation restrictions"
    playbook_compliance:
      - Package inventory (syscollector)
      - Unauthorized software detection (SCA policies)
      - Patch validation (only authorized patches deployed)

    evidence:
      - Software inventory reports
      - Patch approval workflow (change tickets)
      - Unauthorized software alerts
```

## Compensating Controls Library

### WAF Virtual Patching
```yaml
waf_virtual_patch_examples:
  sql_injection_cve:
    cve_id: CVE-2024-XXXX
    modsecurity_rule: |
      SecRule REQUEST_URI "@rx /api/v1/search" \
        "id:9100,\
         phase:2,\
         deny,\
         status:403,\
         log,\
         msg:'Virtual patch for SQLi CVE-2024-XXXX',\
         tag:'CVE-2024-XXXX',\
         tag:'OWASP_CRS/WEB_ATTACK/SQL_INJECTION',\
         chain"
      SecRule ARGS "@detectSQLi" \
        "t:none,t:urlDecodeUni"

  path_traversal_cve:
    cve_id: CVE-2024-YYYY
    modsecurity_rule: |
      SecRule REQUEST_FILENAME "@rx \\.\\./|\\.\\.\\\\" \
        "id:9101,\
         phase:2,\
         deny,\
         status:403,\
         log,\
         msg:'Virtual patch for path traversal CVE-2024-YYYY',\
         tag:'CVE-2024-YYYY'"

  command_injection_cve:
    cve_id: CVE-2024-ZZZZ
    modsecurity_rule: |
      SecRule ARGS "@rx (?:\b(?:n(?:e(?:t(?:\b\W+?\blocalgroup|\.exe)|(?:t(?:sh|cat)|wstat))|(?:map|c)|ohup)|t(?:(?:elne|f)t|clsh)|(?:(?:kill|lsof|sudo)al|loa)l|w(?:guest|sh)|rcmd|xterm|ftp)|[\;\|\`]\W*?\b(?:(?:c(?:h(?:grp|mod|own|sh)|md|pp)|p(?:asswd|ython|erl|ing|s)|n(?:asm|map|c)|f(?:inger|tp)|(?:kil|mai)l|(?:xte)?rm|ls(?:of)?|telnet|uname|echo|id)\b|g(?:\+\+|cc\b)))" \
        "id:9102,\
         phase:2,\
         deny,\
         status:403,\
         log,\
         msg:'Virtual patch for command injection CVE-2024-ZZZZ',\
         tag:'CVE-2024-ZZZZ'"

  deserialization_cve:
    cve_id: CVE-2024-AAAA
    modsecurity_rule: |
      SecRule REQUEST_HEADERS:Content-Type "@rx application/x-java-serialized-object" \
        "id:9103,\
         phase:1,\
         deny,\
         status:403,\
         log,\
         msg:'Virtual patch blocking Java deserialization CVE-2024-AAAA',\
         tag:'CVE-2024-AAAA'"
```

### Network Segmentation
```yaml
network_isolation_examples:
  vulnerable_database_server:
    scenario: "Unpatched PostgreSQL with CVE-2024-XXXX"
    implementation: |
      # Cisco ACL example
      ip access-list extended BLOCK_POSTGRES_INTERNET
       deny tcp any host ${db_server_ip} eq 5432 log
       permit tcp 10.100.50.0 0.0.0.255 host ${db_server_ip} eq 5432
       permit tcp 10.100.51.0 0.0.0.255 host ${db_server_ip} eq 5432
       deny ip any host ${db_server_ip} log

      # Apply to VLAN interface
      interface Vlan100
       ip access-group BLOCK_POSTGRES_INTERNET in

    validation:
      - External scan confirms port 5432 not accessible
      - Internal application connectivity test passes
      - ACL hit counters reviewed (no unauthorized access)

  vulnerable_web_application:
    scenario: "Apache server with CVE-2024-YYYY, requires public access"
    implementation: |
      # Layer 7 firewall (cloud WAF or on-prem)
      - Allow HTTPS (443) from Internet to web server
      - Block direct access to Apache (80, 8080)
      - Require all traffic through WAF
      - WAF enforces virtual patch rules

      # Network ACL
      permit tcp any host ${web_server_ip} eq 443 (HTTPS only)
      deny tcp any host ${web_server_ip} eq 80 log
      deny tcp any host ${web_server_ip} eq 8080 log

    validation:
      - Port 80/8080 not accessible externally
      - HTTPS traffic flows through WAF
      - WAF logs show rule enforcement
```

### Service Restriction
```yaml
service_hardening_examples:
  add_authentication:
    scenario: "Internal API with no auth, vulnerable to CVE-2024-ZZZZ"
    implementation: |
      # Nginx reverse proxy with basic auth
      location /vulnerable-api/ {
        auth_basic "Restricted Access";
        auth_basic_user_file /etc/nginx/.htpasswd;
        proxy_pass http://backend-api:8080/;
      }

    validation:
      - Unauthenticated requests return 401
      - Valid credentials grant access
      - Monitor auth logs for brute force attempts

  ip_allowlisting:
    scenario: "Admin interface exposed, CVE-2024-AAAA"
    implementation: |
      # iptables rule
      iptables -A INPUT -p tcp --dport 8443 -s 10.50.100.0/24 -j ACCEPT
      iptables -A INPUT -p tcp --dport 8443 -j DROP

      # Or application-level (Apache .htaccess)
      <Location /admin>
        Require ip 10.50.100.0/24
        Require ip 192.168.1.0/24
      </Location>

    validation:
      - External connection attempts blocked
      - Allowed IPs can access
      - Audit logs reviewed

  rate_limiting:
    scenario: "Exploitation requires repeated requests"
    implementation: |
      # Nginx rate limiting
      limit_req_zone $binary_remote_addr zone=api_limit:10m rate=10r/s;

      location /api/ {
        limit_req zone=api_limit burst=20 nodelay;
        limit_req_status 429;
        proxy_pass http://backend;
      }

    validation:
      - Exploit tools throttled (rate-limited)
      - Legitimate traffic unaffected
      - 429 responses logged
```

### Enhanced Monitoring
```yaml
monitoring_augmentation_examples:
  ids_signature_deployment:
    scenario: "Deploy Suricata rule for CVE-2024-XXXX"
    implementation: |
      # Custom Suricata rule
      alert http any any -> $HOME_NET any \
        (msg:"Exploitation attempt CVE-2024-XXXX"; \
         flow:established,to_server; \
         content:"vulnerable-endpoint"; http_uri; \
         content:"exploit-payload"; http_client_body; \
         classtype:web-application-attack; \
         sid:9000001; rev:1; \
         metadata:cve CVE-2024-XXXX;)

    wazuh_integration: |
      <rule id="100001" level="12">
        <if_sid>86600</if_sid>
        <match>CVE-2024-XXXX</match>
        <description>Exploitation attempt for CVE-2024-XXXX detected</description>
        <mitre>
          <id>T1190</id>
        </mitre>
      </rule>

  verbose_logging:
    scenario: "Enable debug logging on vulnerable service"
    implementation: |
      # Apache verbose logging
      LogLevel warn core:info ssl:warn reqtimeout:info rewrite:trace3

      # Application logging (example: Java)
      log4j.logger.com.vulnerable.package=DEBUG

    wazuh_integration: |
      <localfile>
        <log_format>apache</log_format>
        <location>/var/log/apache2/vulnerable_app_debug.log</location>
      </localfile>

  siem_correlation_rule:
    scenario: "Detect multi-stage exploitation"
    implementation: |
      <rule id="100002" level="14">
        <if_matched_sid>100001</if_matched_sid>
        <same_source_ip />
        <if_sid>5710</if_sid> <!-- Reverse shell detection -->
        <timeframe>300</timeframe>
        <description>CVE-2024-XXXX exploitation followed by reverse shell</description>
        <mitre>
          <id>T1190</id>
        </mitre>
        <options>no_full_log</options>
      </rule>
```

## Service Level Agreements (SLA) & Key Performance Indicators (KPI)

### Detection SLA
```yaml
detection_sla:
  vulnerability_spike_detection:
    target: < 1_hour
    measurement: time_from_first_vuln_event_to_spike_alert

    factors:
      - Wazuh vulnerability detector scan frequency (default: daily)
      - Statistical baseline calculation (rolling 7-day average)
      - Alert aggregation window (5 minutes)

    monitoring:
      metric_name: vuln_spike_detection_time
      dashboard: "Vulnerability Management - Detection Performance"
      alert_if: detection_time > 2_hours

  exploitation_attempt_detection:
    target: < 5_minutes
    measurement: time_from_ids_event_to_soc_alert

    factors:
      - IDS/IPS inline mode (real-time)
      - Wazuh log ingestion latency
      - Rule evaluation time

    monitoring:
      metric_name: exploitation_detection_time
      dashboard: "SOC Operations - Real-time Alerting"
      alert_if: detection_time > 15_minutes
```

### Assessment SLA
```yaml
assessment_sla:
  initial_triage:
    target: < 15_minutes
    measurement: time_from_alert_creation_to_severity_assigned

    automation: triage_agent (auto-scoring)
    manual_review: high_and_critical_only

    monitoring:
      metric_name: triage_completion_time
      dashboard: "SOC Operations - Triage Performance"
      alert_if: triage_time > 30_minutes

  exposure_assessment:
    target: < 2_hours
    measurement: time_from_alert_to_complete_asset_inventory

    tasks:
      - Affected systems identification (automated)
      - Internet exposure validation (semi-automated)
      - Asset criticality lookup (automated CMDB query)
      - Compensating controls check (manual)

    monitoring:
      metric_name: exposure_assessment_time
      dashboard: "Vulnerability Management - Assessment Performance"
      alert_if: assessment_time > 4_hours

  risk_scoring:
    target: < 1_hour
    measurement: time_from_assessment_to_final_risk_score

    automation: correlation_agent (environmental CVSS calculation)

    monitoring:
      metric_name: risk_scoring_time
      dashboard: "Vulnerability Management - Risk Analysis"
      alert_if: scoring_time > 2_hours
```

### Remediation SLA
```yaml
remediation_sla:
  critical_vulnerabilities:
    cvss_range: 9.0 - 10.0
    conditions: CISA_KEV OR active_exploitation OR internet_facing
    target: < 24_hours
    measurement: time_from_detection_to_patch_verified

    escalation:
      at_12_hours: notify_security_manager
      at_18_hours: notify_ciso
      at_24_hours: executive_escalation

    exceptions:
      - Risk acceptance (CISO approval required)
      - Patch not available (vendor escalation + compensating controls mandatory)

  high_vulnerabilities:
    cvss_range: 7.0 - 8.9
    conditions: public_exploit_available OR production_system
    target: < 72_hours
    measurement: time_from_detection_to_patch_verified

    escalation:
      at_48_hours: notify_security_manager
      at_72_hours: notify_ciso + require_status_update

    exceptions:
      - Compensating controls validated (extend to 7 days)
      - Business-critical system (schedule in next maintenance window + controls)

  medium_vulnerabilities:
    cvss_range: 4.0 - 6.9
    target: < 7_days
    measurement: time_from_detection_to_patch_verified

    exceptions:
      - Standard patch cycle (monthly) if internal_only AND no_exploit

  low_vulnerabilities:
    cvss_range: 0.1 - 3.9
    target: < 30_days
    measurement: time_from_detection_to_patch_verified

    exceptions:
      - Next quarterly maintenance window
```

### Verification SLA
```yaml
verification_sla:
  post_patch_scanning:
    target: < 24_hours_after_patch_deployment
    measurement: time_from_patch_applied_to_verification_scan_complete

    automation:
      - Wazuh vulnerability detector (automatic rescan)
      - Authenticated scanner (Nessus/Qualys scheduled scan)

    success_criteria:
      - Vulnerability state: REMOVED (in Wazuh DB)
      - External scanner confirms remediation
      - Functional testing passed

    monitoring:
      metric_name: verification_scan_time
      dashboard: "Patch Management - Verification"
      alert_if: verification_time > 48_hours

  remediation_confirmation:
    target: 100%_verification_rate
    measurement: (verified_patches / deployed_patches) * 100

    process:
      - Automated scan confirmation (90% of cases)
      - Manual validation (complex systems, 10% of cases)
      - Sign-off by IT operations

    monitoring:
      metric_name: verification_completion_rate
      dashboard: "Patch Management - Compliance"
      alert_if: completion_rate < 95%
```

### Key Performance Indicators
```yaml
kpis:
  detection_performance:
    vuln_spike_detection_rate:
      formula: (detected_spikes / actual_spikes) * 100
      target: >= 95%
      note: "Validated against historical analysis"

    false_positive_rate:
      formula: (false_positive_alerts / total_vuln_alerts) * 100
      target: <= 10%
      remediation: tune_statistical_baselines

  response_effectiveness:
    sla_compliance_rate:
      formula: (remediated_within_sla / total_vulnerabilities) * 100
      target: >= 90%
      tracking: by_severity_level

    mean_time_to_patch:
      formula: AVG(patch_verified_time - detection_time)
      targets:
        critical: <= 24_hours
        high: <= 72_hours
        medium: <= 7_days
        low: <= 30_days

  coverage_metrics:
    patch_coverage_rate:
      formula: (patched_vulnerabilities / total_vulnerabilities) * 100
      target: >= 95%
      note: "Excludes risk-accepted exceptions"

    asset_inventory_accuracy:
      formula: (cmdb_assets_with_vuln_data / total_cmdb_assets) * 100
      target: >= 98%
      note: "Ensures complete visibility"

  risk_reduction:
    vulnerability_exposure_days:
      formula: SUM(days_vulnerable * cvss_score * asset_count)
      target: minimize (trend_down)
      tracking: monthly_aggregate

    critical_vuln_backlog:
      formula: COUNT(open_critical_vulnerabilities)
      target: <= 5
      note: "Zero is ideal, <5 acceptable with documented exceptions"

  operational_efficiency:
    automation_rate:
      formula: (automated_triage_cases / total_cases) * 100
      target: >= 80%
      improvement: expand_triage_agent_capabilities

    analyst_workload:
      formula: AVG(cases_per_analyst_per_day)
      target: <= 15_cases
      note: "Ensures quality over quantity"
```

## Evidence Collection

### Required Evidence
```yaml
evidence_collection:
  detection_evidence:
    wazuh_alerts:
      query: |
        GET /alerts
        ?q=data.vulnerability.cve:${cve_id}
        &range=7d
        &sort=timestamp:desc

      fields:
        - timestamp
        - agent.name
        - data.vulnerability.cve
        - data.vulnerability.cvss.cvss3.base_score
        - data.vulnerability.package.name
        - data.vulnerability.state

    ids_alerts:
      query: |
        GET /alerts
        ?q=rule.groups:ids AND data.cve:${cve_id}
        &range=7d

      fields:
        - timestamp
        - data.srcip
        - data.dstip
        - rule.description
        - data.alert.signature

    syscollector_inventory:
      query: |
        GET /syscollector/${agent_id}/packages
        ?search=${vulnerable_package_name}

      fields:
        - name
        - version
        - install_time
        - size

  assessment_evidence:
    nvd_lookup:
      endpoint: https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=${cve_id}
      save: cvss_vector, description, references, published_date

    cisa_kev_check:
      endpoint: https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json
      save: kev_status, due_date, notes

    exploit_availability:
      sources:
        - ExploitDB HTML export
        - GitHub search results JSON
        - Metasploit module listing
      save: exploit_links, exploit_type, publication_dates

    asset_criticality:
      cmdb_export:
        query: "SELECT * FROM assets WHERE hostname IN (${affected_hosts})"
        format: CSV
        fields: asset_tier, business_service, owner, rto, rpo

  remediation_evidence:
    patch_deployment_logs:
      sources:
        - Ansible playbook execution logs
        - SCCM/WSUS deployment reports
        - Package manager logs (apt, yum, dnf)

      required_fields:
        - Patch ID/KB number
        - Target hosts
        - Deployment timestamp
        - Success/failure status
        - Rollback events (if any)

    verification_scans:
      authenticated_scan_report:
        tool: [Nessus, Qualys, Rapid7]
        format: PDF + CSV
        required_sections:
          - Executive summary
          - Vulnerability detail (before/after)
          - Remediation confirmation

      wazuh_vulnerability_report:
        query: |
          GET /vulnerability/${cve_id}
          ?state=REMOVED
        export: JSON
        validation: "All affected agents show state:REMOVED"

  compliance_evidence:
    audit_trail:
      - Detection alert (original Wazuh event)
      - Triage summary (agent output)
      - Risk assessment (scoring calculation)
      - Approval records (change ticket, risk acceptance form)
      - Communication logs (emails, Slack messages)
      - Patch deployment evidence
      - Verification scans
      - Case closure summary

    retention:
      duration: 7_years (compliance requirement)
      storage: immutable_archive (WORM storage)
      format: JSON + PDF reports
```

### Evidence Pack Format
```json
{
  "case_id": "AUTO-20260217-CVE-2024-1234",
  "created_at": "2026-02-17T10:30:00Z",
  "closed_at": "2026-02-18T14:45:00Z",
  "severity": "CRITICAL",
  "sla_met": true,

  "vulnerability": {
    "cve_id": "CVE-2024-1234",
    "cvss": {
      "base_score": 9.8,
      "base_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
      "temporal_score": 10.0,
      "environmental_score": 9.5,
      "environmental_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H/E:H/RL:U/RC:C/CR:H/IR:H/AR:H"
    },
    "description": "Remote code execution in Example Software due to deserialization flaw",
    "cwe": "CWE-502",
    "published_date": "2024-02-15",
    "threat_intel": {
      "cisa_kev": true,
      "kev_due_date": "2024-03-07",
      "public_exploit": true,
      "exploit_maturity": "FUNCTIONAL",
      "active_exploitation": true,
      "metasploit_module": "exploit/multi/http/example_deserialize_rce"
    }
  },

  "exposure": {
    "affected_hosts": [
      {
        "agent_id": "001",
        "agent_name": "web-prod-01.example.com",
        "agent_ip": "10.50.1.10",
        "package": "example-software",
        "version": "2.3.1",
        "criticality_tier": "TIER_1",
        "business_service": "E-commerce Platform",
        "network_zone": "DMZ",
        "internet_facing": true
      }
    ],
    "summary": {
      "total_hosts": 15,
      "internet_facing": 3,
      "critical_assets": 8,
      "tier_1": 8,
      "tier_2": 5,
      "tier_3": 2
    }
  },

  "exploitation_activity": {
    "attempts_detected": 47,
    "unique_source_ips": 23,
    "source_countries": ["CN", "RU", "US"],
    "successful_exploitation": false,
    "first_attempt": "2026-02-17T11:15:00Z",
    "last_attempt": "2026-02-17T18:30:00Z",
    "ids_alerts": [
      {
        "timestamp": "2026-02-17T11:15:23Z",
        "source_ip": "198.51.100.45",
        "dest_ip": "10.50.1.10",
        "signature": "ET EXPLOIT Example Software Deserialization RCE Attempt",
        "severity": "HIGH"
      }
    ]
  },

  "remediation": {
    "path": "emergency_patching",
    "patch_available": true,
    "patch_version": "2.4.0",
    "patch_url": "https://vendor.example.com/security/patches/2.4.0",
    "vendor_advisory": "https://vendor.example.com/security/advisory-2024-001",
    "deployment": {
      "method": "ansible_playbook",
      "canary_start": "2026-02-17T20:00:00Z",
      "canary_complete": "2026-02-17T21:30:00Z",
      "pilot_start": "2026-02-18T02:00:00Z",
      "pilot_complete": "2026-02-18T06:00:00Z",
      "production_start": "2026-02-18T08:00:00Z",
      "production_complete": "2026-02-18T12:00:00Z"
    },
    "compensating_controls": [
      {
        "type": "waf_virtual_patch",
        "deployed_at": "2026-02-17T12:30:00Z",
        "effectiveness": "100% block rate, 0 false positives"
      }
    ]
  },

  "verification": {
    "wazuh_scan": {
      "timestamp": "2026-02-18T13:00:00Z",
      "result": "All 15 hosts show vulnerability state: REMOVED"
    },
    "authenticated_scan": {
      "tool": "Nessus Professional",
      "timestamp": "2026-02-18T14:00:00Z",
      "result": "CVE-2024-1234 not detected on any scanned hosts",
      "report_id": "scan-20260218-140000"
    },
    "functional_testing": {
      "timestamp": "2026-02-18T14:30:00Z",
      "result": "All services operational, no degradation detected"
    }
  },

  "metrics": {
    "time_to_detect": "0.5 hours",
    "time_to_assess": "1.5 hours",
    "time_to_respond": "2.0 hours",
    "time_to_remediate": "26.25 hours",
    "total_resolution_time": "28.25 hours",
    "sla_target": "24 hours",
    "sla_met": false,
    "sla_miss_reason": "Deployment required extended testing for critical e-commerce platform"
  },

  "approvals": {
    "emergency_change": {
      "ticket_id": "CHG0012345",
      "requested_by": "soc-analyst@example.com",
      "approved_by": "security-manager@example.com",
      "approval_timestamp": "2026-02-17T13:00:00Z"
    }
  },

  "communications": [
    {
      "timestamp": "2026-02-17T10:45:00Z",
      "type": "initial_notification",
      "recipients": ["soc-team", "security-manager"],
      "channel": "slack"
    },
    {
      "timestamp": "2026-02-17T13:30:00Z",
      "type": "emergency_patch_request",
      "recipients": ["it-operations", "cab-chair", "asset-owners"],
      "channel": "email"
    },
    {
      "timestamp": "2026-02-17T14:00:00Z",
      "type": "executive_summary",
      "recipients": ["ciso", "cto"],
      "channel": "email"
    }
  ],

  "compliance": {
    "nist_sp_800_40": "compliant",
    "pci_dss_6_3": "compliant",
    "cisa_bod_22_01": "compliant (remediated before KEV due date)",
    "iso_27001_a12_6": "compliant"
  },

  "attachments": [
    "nvd_cve_details.json",
    "cisa_kev_entry.json",
    "wazuh_vulnerability_report.pdf",
    "nessus_scan_report.pdf",
    "patch_deployment_logs.zip",
    "change_ticket_CHG0012345.pdf",
    "executive_summary.pdf"
  ]
}
```

## False Positive Handling

### Common False Positive Scenarios
```yaml
false_positive_types:
  vulnerability_in_non_executable:
    scenario: "CVE detected in documentation package or font files"
    validation: |
      Check package type and file paths:
      - If package.name CONTAINS "doc" OR "fonts" OR "locales"
      - AND no executable files in package
      - THEN likely false positive

    resolution: "Suppress alert or mark as informational"

  service_not_running:
    scenario: "Vulnerable package installed but service disabled"
    validation: |
      Query syscollector:
      - Check if service process running
      - Check systemd/init.d status
      - Verify no listening ports for service

    risk_adjustment: "Reduce severity by 2 levels (still track for future)"

  patch_applied_scanner_lag:
    scenario: "Patch deployed but scanner cache not updated"
    validation: |
      - Check package version vs. NVD fixed version
      - Verify patch deployment logs
      - Re-run authenticated scan (not cached)

    resolution: "Close alert, update scanner database"

  network_isolated_system:
    scenario: "Vulnerable system in isolated lab environment"
    validation: |
      - CMDB lookup: environment = "lab" OR "isolated"
      - Network diagram: no production connectivity
      - Firewall rules: deny any outbound/inbound

    risk_adjustment: "Reduce to LOW priority, document exception"

  compensating_controls_effective:
    scenario: "WAF/IDS blocks all exploitation attempts"
    validation: |
      - WAF logs show 100% block rate
      - IDS testing confirms detection
      - No successful exploitation indicators

    risk_adjustment: "Extend remediation SLA, but maintain tracking"

  decommission_scheduled:
    scenario: "System scheduled for decommissioning within 30 days"
    validation: |
      - CMDB: decommission_date <= now + 30_days
      - Change ticket for decommissioning exists
      - No critical business services dependent

    resolution: "Document exception, skip patching"
```

### Validation Workflow
```yaml
false_positive_validation:
  step_1_automated_checks:
    - syscollector_service_status: running/stopped
    - package_type_classification: executable/library/documentation
    - network_exposure_validation: internet/dmz/internal/isolated
    - patch_level_verification: version_comparison

  step_2_analyst_review:
    triggers:
      - Automated checks inconclusive
      - High/Critical severity
      - Multiple hosts affected

    checklist:
      - [ ] Verified CVE details in NVD
      - [ ] Confirmed package version vulnerable
      - [ ] Validated service running status
      - [ ] Checked network accessibility
      - [ ] Reviewed compensating controls
      - [ ] Consulted vendor advisory

  step_3_disposition:
    options:
      - true_positive:
          action: proceed_with_remediation

      - false_positive_suppress:
          action: create_suppression_rule
          approval: security_engineer
          documentation: justification_required

      - false_positive_tune:
          action: adjust_detection_rule
          approval: detection_engineer
          testing: validate_in_lab_first

      - informational:
          action: lower_severity_to_info
          tracking: maintain_in_inventory_but_no_sla
```

## Post-Incident Activities

### After Successful Patching
```yaml
post_patch_activities:
  verification:
    - [ ] Vulnerability scan confirms CVE remediated (state: REMOVED)
    - [ ] Service availability validated
    - [ ] Application functionality tested
    - [ ] Performance baseline normal
    - [ ] No new vulnerabilities introduced

  documentation:
    - [ ] Change ticket updated with completion details
    - [ ] CMDB patch level updated
    - [ ] Evidence pack finalized (scans, logs, approvals)
    - [ ] Case closed in SIEM/SOAR

  communication:
    - [ ] Notify stakeholders (IT ops, asset owners, management)
    - [ ] Update status dashboard
    - [ ] Post-mortem scheduled (if critical incident)

  metrics_update:
    - [ ] MTTD, MTTR calculated
    - [ ] SLA compliance recorded
    - [ ] Vulnerability backlog updated
    - [ ] Dashboard refreshed
```

### After Exploitation Event
```yaml
post_exploitation_activities:
  immediate_actions:
    - [ ] Activate Incident Response playbook
    - [ ] Isolate affected hosts (pending forensics)
    - [ ] Preserve evidence (disk images, memory dumps, logs)
    - [ ] Notify legal/compliance (breach assessment)

  forensic_analysis:
    - [ ] Timeline reconstruction (first compromise to detection)
    - [ ] Scope assessment (lateral movement, data exfiltration)
    - [ ] Malware analysis (if applicable)
    - [ ] Attribution assessment (threat actor, campaign)

  containment_and_eradication:
    - [ ] Remove attacker persistence mechanisms
    - [ ] Patch vulnerable systems
    - [ ] Reset compromised credentials
    - [ ] Rebuild compromised systems (if necessary)

  recovery:
    - [ ] Restore services from clean backups
    - [ ] Validate integrity of restored data
    - [ ] Enhanced monitoring (detect re-compromise attempts)
    - [ ] Return to normal operations

  lessons_learned:
    - [ ] Root cause analysis (why was system vulnerable?)
    - [ ] Detection efficacy review (why didn't we patch sooner?)
    - [ ] Response effectiveness (what went well/poorly?)
    - [ ] Action items (process improvements, tool enhancements)

  regulatory_reporting:
    - [ ] Determine breach notification requirements (GDPR, CCPA, etc.)
    - [ ] Notify regulators if required (within mandated timeframes)
    - [ ] Prepare external communications (if public disclosure required)
    - [ ] Coordinate with legal counsel
```

### Continuous Improvement
```yaml
continuous_improvement:
  monthly_review:
    participants:
      - SOC manager
      - Vulnerability management team
      - IT operations
      - Security engineering

    agenda:
      - Review vulnerability metrics (trend analysis)
      - Identify process bottlenecks
      - Discuss recurring issues
      - Prioritize automation opportunities

    outputs:
      - Process improvement backlog
      - Tool enhancement requests
      - Training needs identification

  quarterly_metrics_review:
    kpis_evaluated:
      - Mean time to patch (by severity)
      - SLA compliance rate
      - Patch coverage percentage
      - Vulnerability backlog trend
      - False positive rate

    benchmarking:
      - Compare against industry standards
      - Identify gaps
      - Set improvement targets

  annual_playbook_update:
    triggers:
      - Major process changes
      - New regulatory requirements
      - Lessons learned from incidents
      - Tool/technology changes

    process:
      - Review all playbook sections
      - Update MITRE ATT&CK mappings
      - Refresh compliance references
      - Validate detection rules
      - Test response procedures
      - Obtain stakeholder approval

    version_control:
      - Increment version number (2.0 -> 2.1)
      - Document changelog
      - Communicate updates to SOC team
      - Conduct training on changes
```

## References

### Regulatory & Framework
- NIST SP 800-40 Rev 4: Guide to Enterprise Patch Management Planning
  https://csrc.nist.gov/publications/detail/sp/800-40/rev-4/final

- PCI DSS v4.0 Requirement 6.3: Security Vulnerabilities
  https://www.pcisecuritystandards.org/document_library

- CISA Binding Operational Directive 22-01: Reducing the Significant Risk of Known Exploited Vulnerabilities
  https://www.cisa.gov/news-events/directives/bod-22-01-reducing-significant-risk-known-exploited-vulnerabilities

- ISO/IEC 27001:2022 Annex A.12.6: Management of Technical Vulnerabilities
  https://www.iso.org/standard/27001

### Vulnerability Intelligence
- National Vulnerability Database (NVD)
  https://nvd.nist.gov/

- CISA Known Exploited Vulnerabilities (KEV) Catalog
  https://www.cisa.gov/known-exploited-vulnerabilities-catalog

- MITRE CVE Database
  https://cve.mitre.org/

- Exploit Database (ExploitDB)
  https://www.exploit-db.com/

- VulnCheck KEV API
  https://vulncheck.com/api

### MITRE ATT&CK
- T1190: Exploit Public-Facing Application
  https://attack.mitre.org/techniques/T1190/

- T1203: Exploitation for Client Execution
  https://attack.mitre.org/techniques/T1203/

- T1210: Exploitation of Remote Services
  https://attack.mitre.org/techniques/T1210/

- T1211: Exploitation for Defense Evasion
  https://attack.mitre.org/techniques/T1211/

- T1068: Exploitation for Privilege Escalation
  https://attack.mitre.org/techniques/T1068/

- T1212: Exploitation for Credential Access
  https://attack.mitre.org/techniques/T1212/

### Wazuh Documentation
- Wazuh Vulnerability Detector
  https://documentation.wazuh.com/current/user-manual/capabilities/vulnerability-detection/

- Wazuh Security Configuration Assessment (SCA)
  https://documentation.wazuh.com/current/user-manual/capabilities/sec-config-assessment/

- Wazuh Syscollector
  https://documentation.wazuh.com/current/user-manual/capabilities/syscollector.html

- Wazuh Suricata Integration
  https://documentation.wazuh.com/current/proof-of-concept-guide/detect-web-attack-suricata.html

### CVSS Resources
- CVSS v3.1 Specification
  https://www.first.org/cvss/v3.1/specification-document

- CVSS v3.1 Calculator
  https://www.first.org/cvss/calculator/3.1

### Tools & Integrations
- ModSecurity Web Application Firewall
  https://github.com/SpiderLabs/ModSecurity

- OWASP Core Rule Set (CRS)
  https://owasp.org/www-project-modsecurity-core-rule-set/

- Suricata IDS/IPS
  https://suricata.io/

- GreyNoise Intelligence
  https://www.greynoise.io/

---

**Document Control:**
- Version: 2.0.0
- Last Reviewed: 2026-02-17
- Next Review: 2026-08-17 (6 months)
- Owner: Security Operations Center
- Approver: Chief Information Security Officer
- Classification: TLP:AMBER - Organizational Internal Use Only
