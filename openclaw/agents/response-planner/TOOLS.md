# Response Planner Agent - Tool Usage

## Runtime API: Submit Plans

**Endpoint**: `POST http://localhost:9090/api/plans`

The Runtime Service port defaults to 9090 but is configurable via the `RUNTIME_PORT` environment variable. Always check this variable before making requests.

### Request Structure

```json
{
  "case_id": "CASE-YYYYMMDD-xxxxxxxx",
  "title": "Short description of the response action",
  "description": "Detailed explanation of what the plan does and why",
  "risk_level": "low|medium|high|critical",
  "actions": [
    {
      "type": "block_ip|host_deny|restart_wazuh|kill_process|quarantine_file|isolate_host|disable_user",
      "target": "IP address, hostname, process name, or file path",
      "params": {
        "duration": "24h",
        "reason": "Human-readable justification"
      }
    }
  ]
}
```

### Validating Your Request

Before submitting, verify:
1. `case_id` matches the investigation case you are responding to
2. `risk_level` is computed from the weighted risk score (see below)
3. Actions are ordered according to sequencing rules (evidence before eradication, containment before eradication, isolation before process kill, credential reset after user disable)
4. Each action has a valid `type` from the Wazuh action catalog

### Response Handling

- **201 Created**: Plan accepted, enters `proposed` state, Slack notification sent
- **400 Bad Request**: Invalid plan structure -- fix and resubmit
- **500 Server Error**: Runtime Service issue -- retry after delay

## Calculating Risk Scores

Compute the weighted risk score to determine `risk_level`:

```
score = (reversibility * 0.15)
      + (asset_criticality * 0.25)
      + (business_impact * 0.25)
      + (blast_radius * 0.15)
      + (confidence_penalty * 0.20)
```

Each factor is scored 0-10. Map the total:

| Score Range | risk_level |
|-------------|------------|
| 0 - 3 | low |
| 4 - 6 | medium |
| 7 - 8 | high |
| 9 - 10 | critical |

### Scoring Individual Factors

**Reversibility**: Reversible=0, Partial=5, Irreversible=10
**Asset Criticality**: Low=0, Medium=3, High=6, Critical=10
**Business Impact**: Minimal=0, Moderate=4, Significant=7, Severe=10
**Blast Radius**: Single host=0, Multiple hosts=4, Subnet=7, Enterprise=10
**Confidence Penalty**: High confidence=0, Medium=4, Low=8

### Escalation Annotations

When submitting the plan, note in the description if escalation rules apply:
- Score >= 7: Plan will require an ELEVATED approver
- Score >= 9: Plan will require an ADMIN approver
- Critical asset targeted: Plan will require an ADMIN approver
- Confidence < 0.7 with non-low risk: Recommend against execution in the description

## Selecting Playbook Actions

Match the investigation's attack classification to the appropriate playbook (brute force, lateral movement, malware, data exfiltration, privilege escalation) and select primary/secondary actions based on the conditions documented in AGENTS.md. Always check the condition gates (e.g., "attempts > 10", "confidence > 0.8", "malware confirmed") before including an action.
