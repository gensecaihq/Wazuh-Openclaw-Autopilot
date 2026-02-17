# SOC Context

Organizational context that informs agent decision-making. Customize this file for your deployment.

## Organization

- **Industry**: [CUSTOMIZE] (e.g., Financial Services, Healthcare, SaaS, Government)
- **Compliance frameworks**: [CUSTOMIZE] (e.g., PCI-DSS, HIPAA, SOC 2, NIST 800-53, ISO 27001)
- **Risk tolerance**: Moderate
- **Data classification**: Standard (Public, Internal, Confidential, Restricted)

## Critical Assets

Hostname patterns indicating critical infrastructure. Actions targeting these require elevated approval.

- `^(dc|ad|ldap)-.*` — Domain controllers (CRITICAL)
- `^(prod|prd)-.*` — Production systems (HIGH)
- `^(db|sql|mongo|redis|elastic)-.*` — Databases (HIGH)
- `^(app|web|api)-.*` — Application servers (MEDIUM)
- `^(staging|stg)-.*` — Staging (MEDIUM)
- `^(dev|test|sandbox)-.*` — Development (LOW)

### Critical IP Ranges

- [CUSTOMIZE] Add your critical subnets here
- Example: `10.0.1.0/24` — Database tier
- Example: `10.0.2.0/24` — Production application tier

## Known Noise Sources

These generate high alert volumes but are typically benign. Check MEMORY.md for additional FP patterns discovered during operation.

### Internal Scanners
- [CUSTOMIZE] Add your vulnerability scanner IPs
- Example: `10.0.10.50` — Nessus scanner (ignore as source IP in brute force detection)
- Example: `10.0.10.51` — Qualys scanner

### Service Accounts
- [CUSTOMIZE] Add your service accounts
- Accounts matching `^svc_.*` — Automated service accounts (high volume, usually benign)
- Accounts matching `^(backup|monitor|healthcheck)` — Infrastructure automation

### Scheduled Jobs
- [CUSTOMIZE] Add your known noisy scheduled tasks
- Example: Backup jobs at 02:00-04:00 UTC generate syscheck alerts on data directories
- Example: Patch scans on Tuesdays trigger multiple software inventory alerts

## SOC Team

### Shifts
- [CUSTOMIZE] Adjust to your shift schedule
- Shift A: 06:00 - 14:00 UTC
- Shift B: 14:00 - 22:00 UTC
- Shift C: 22:00 - 06:00 UTC

### Escalation Path
1. SOC Analyst (Tier 1) — Initial triage and case management
2. Senior Analyst (Tier 2) — Investigation and response planning
3. SOC Manager — Approval for high-risk actions
4. CISO / Security Director — Critical asset and enterprise-wide decisions

### Communication Preferences
- **Alerts**: Slack #security-alerts channel
- **Approvals**: Slack #security-approvals channel
- **Reports**: Slack #security-reports channel
- **Critical incidents**: Direct mention of on-call analyst

## Environment

### VPN / Remote Access
- [CUSTOMIZE] Add your VPN subnet ranges
- Example: `10.8.0.0/16` — OpenVPN range (legitimate remote access)
- Example: `100.64.0.0/10` — Tailscale range (trusted)

### Change Freeze Windows
- [CUSTOMIZE] Add your change freeze periods
- Example: Last week of each quarter (reduced risk tolerance, escalate more aggressively)

### Business Hours
- [CUSTOMIZE] Primary business hours
- Default: Monday-Friday 06:00-22:00 UTC
- Outside business hours: Higher escalation threshold for non-critical alerts
