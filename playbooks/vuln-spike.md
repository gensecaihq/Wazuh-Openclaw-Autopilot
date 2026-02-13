# Playbook: Vulnerability Spike Detection and Response

## Overview

| Field | Value |
|-------|-------|
| Playbook ID | PB-005 |
| Version | 1.0.0 |
| Severity | Variable (based on CVSS) |
| MITRE ATT&CK | T1190 - Exploit Public-Facing Application |
| Category | Vulnerability Management |

## Description

This playbook handles sudden increases in vulnerability detections or
exploitation attempts. Vulnerability spikes may indicate:
- New critical vulnerability disclosure (0-day or n-day)
- Active exploitation campaign targeting your environment
- Failed patching leaving systems exposed
- Scanning/reconnaissance activity

## Detection Criteria

### Primary Indicators

#### Volume-Based
- Significant increase in vuln scan findings
- Multiple systems reporting same CVE
- Spike in IDS/IPS vulnerability signatures
- Increase in patch-related alerts

#### Exploitation Attempts
- Signature matches for known exploits
- Suspicious requests matching CVE patterns
- Failed exploitation attempts in logs
- Successful exploitation indicators

### Wazuh Detection
| Source | Detection |
|--------|-----------|
| Vulnerability Detector | New CVE findings |
| IDS Integration | Suricata/Snort alerts |
| Web Application | ModSecurity/WAF alerts |
| System Logs | Exploitation indicators |

### Severity Classification
| CVSS Score | Severity | Response Time |
|------------|----------|---------------|
| 9.0 - 10.0 | Critical | Immediate |
| 7.0 - 8.9 | High | < 4 hours |
| 4.0 - 6.9 | Medium | < 24 hours |
| 0.1 - 3.9 | Low | Standard cycle |

### High-Priority Conditions
```yaml
high_priority:
  - cvss_score >= 9.0
  - active_exploitation_in_wild: true
  - public_exploit_available: true
  - internet_facing_affected: true
  - critical_asset_affected: true
```

## Automated Triage Steps

### 1. Entity Extraction
```yaml
entities:
  - type: cve
    source: data.vulnerability.cve
  - type: host
    source: agent.name
  - type: software
    source: data.vulnerability.package
  - type: ip
    source: data.srcip  # For exploitation attempts
```

### 2. Vulnerability Assessment
- What CVE(s) are involved?
- What's the CVSS score?
- Is there a public exploit?
- Is it being actively exploited in the wild?

### 3. Exposure Assessment
| Factor | Check |
|--------|-------|
| Affected systems | How many? |
| Internet exposure | Any public-facing? |
| Asset criticality | Production? Critical? |
| Compensating controls | WAF? Segmentation? |

### 4. Severity Calculation
```yaml
severity_factors:
  base: cvss_score
  modifiers:
    - public_exploit_available: +1
    - active_exploitation: +2
    - internet_facing: +1
    - critical_asset: +1
    - no_compensating_controls: +1
  max_severity: critical
```

## Correlation Rules

### Related Alerts to Cluster
- Vulnerability scan results for same CVE
- IDS/IPS alerts for related exploits
- Failed/successful exploitation attempts
- Anomalous traffic to affected services

### Timeline Construction
```yaml
timeline_query:
  lookback: 7d
  lookahead: 0
  filters:
    - data.vulnerability.cve: ${cve_id}
    - OR rule.groups: ids OR attack
  aggregate_by:
    - host
    - day
```

## Response Plan

### Assessment Phase (Read-Only)

1. **Identify all affected systems**
   ```yaml
   action: search_vulnerabilities
   query: "cve:${cve_id}"
   output: affected_hosts_list
   ```

2. **Prioritize by risk**
   - Internet-facing first
   - Critical assets second
   - Production systems third
   - Development/test last

3. **Check for exploitation**
   - Review IDS/IPS logs
   - Check application logs
   - Look for post-exploitation indicators

### Mitigation Options

#### Option A: Emergency Patching (Recommended)
```yaml
action: create_patch_ticket
priority: emergency
targets: ${affected_hosts}
cve: ${cve_id}
justification: "Critical vulnerability with active exploitation"
```
*Note: Autopilot creates ticket/notification; patching is manual*

#### Option B: Temporary Mitigation
```yaml
actions:
  - type: waf_rule
    description: "Deploy WAF rule to block exploit"
  - type: network_block
    description: "Block known exploit source IPs"
  - type: service_restriction
    description: "Limit access to affected service"
```

#### Option C: Isolate Affected Systems (If Compromised)
```yaml
action: isolate_host
target: ${compromised_hosts}
risk: high
justification: "Host shows signs of successful exploitation"
conditions:
  - exploitation_successful: true
```

### Communication

For critical vulnerabilities:
- Notify Security Operations
- Notify IT Operations (for patching)
- Notify System Owners
- Consider executive notification if widespread

## Evidence Collection

### Required Evidence
| Source | Query |
|--------|-------|
| Vuln findings | `data.vulnerability.cve:${cve_id}` |
| Exploit attempts | `rule.groups:ids AND data.cve:${cve_id}` |
| Affected systems | Vulnerability detector results |
| Network traffic | Traffic to affected services |

### Evidence Pack Fields
```json
{
  "alert_type": "vulnerability_spike",
  "vulnerability": {
    "cve_id": "",
    "cvss_score": 0,
    "cvss_vector": "",
    "description": "",
    "public_exploit": false,
    "active_exploitation": false
  },
  "exposure": {
    "affected_host_count": 0,
    "internet_facing_count": 0,
    "critical_asset_count": 0,
    "affected_software": [],
    "affected_versions": []
  },
  "exploitation_attempts": {
    "count": 0,
    "source_ips": [],
    "successful": false
  },
  "remediation": {
    "patch_available": false,
    "patch_version": "",
    "workaround_available": false,
    "compensating_controls": []
  },
  "timeline": {
    "first_detection": "",
    "spike_start": "",
    "exploitation_first_seen": ""
  }
}
```

## Approval Request Template

```
:shield: *Vulnerability Spike Detected*

*Case:* ${case_id}
*CVE:* ${cve_id}
*CVSS:* ${cvss_score} (${severity})

*Vulnerability Details:*
${cve_description}

*Exposure Summary:*
- Affected Systems: ${affected_count}
- Internet Facing: ${internet_facing_count}
- Critical Assets: ${critical_count}

*Exploitation Status:*
- Public Exploit: ${public_exploit}
- Active in Wild: ${active_exploitation}
- Attempts Detected: ${exploit_attempts}

*Recommended Actions:*
1. ${primary_recommendation}
2. ${secondary_recommendation}

*Patch Status:*
${patch_status}

[Approve Emergency Patch] [Deploy Workaround] [Acknowledge Risk]
```

## Vulnerability Intelligence

### Sources to Check
- NVD (National Vulnerability Database)
- Vendor security advisories
- CISA Known Exploited Vulnerabilities
- Exploit-DB
- Security news feeds

### Enrichment Data
```yaml
enrichment:
  - source: nvd
    data: cvss, description, references
  - source: cisa_kev
    data: known_exploited, due_date
  - source: vendor
    data: patch_info, workarounds
```

## False Positive Handling

### Common False Positives
| Scenario | Validation |
|----------|------------|
| Old vulnerability | Check if truly unpatched |
| Test/dev systems | Verify asset classification |
| Compensating controls | Verify controls effective |
| Incorrect detection | Validate scan accuracy |

## Post-Incident

### After Patching
- Verify patch deployment
- Rescan to confirm remediation
- Close related cases
- Update vulnerability metrics

### After Exploitation
- Full incident response
- Forensic analysis
- Scope assessment
- Lessons learned

## Metrics

| Metric | Target |
|--------|--------|
| Time to detect spike | < 1 hour |
| Time to assess exposure | < 2 hours |
| Time to mitigate (critical) | < 4 hours |
| Patch verification | 100% |

## References

- CISA Known Exploited Vulnerabilities Catalog
- NIST NVD
- MITRE ATT&CK: https://attack.mitre.org/techniques/T1190/
- Vendor Security Advisories
