# Response Planner Agent - Tool Usage

## Runtime API: Submit Plans

**Endpoint**: `GET http://localhost:9090/api/agent-action/create-plan`

The Runtime Service port defaults to 9090 but is configurable via the `RUNTIME_PORT` environment variable.

> **Note**: This endpoint uses GET with query parameters because OpenClaw's `web_fetch` tool only supports GET requests (no custom headers). Pass the auth token as `?token=<AUTOPILOT_MCP_AUTH>` on every request.

### Submitting a Plan

Build the request URL with these query parameters:

- `case_id` (required) — The case this plan responds to
- `title` (required) — Short description of the response action
- `description` (optional) — Detailed explanation
- `risk_level` (optional, default: "medium") — `low|medium|high|critical`
- `actions` (required) — URL-encoded JSON array of actions
- `token` (required) — Your `AUTOPILOT_MCP_AUTH` token

    web_fetch(url="http://localhost:9090/api/agent-action/create-plan?case_id={case_id}&title={url_encoded_title}&risk_level={level}&actions={url_encoded_json_array}&token=<AUTOPILOT_MCP_AUTH>")

**Actions JSON structure** (URL-encode this array):

```json
[
  {
    "type": "block_ip|host_deny|restart_wazuh|kill_process|quarantine_file|isolate_host|disable_user",
    "target": "IP address, hostname, process name, or file path",
    "params": {
      "duration": "24h",
      "reason": "Human-readable justification"
    }
  }
]
```

### Validating Your Request

Before submitting, verify:
1. `case_id` matches the investigation case you are responding to
2. `risk_level` is computed from the weighted risk score (see below)
3. Actions are ordered according to sequencing rules (evidence before eradication, containment before eradication, isolation before process kill, credential reset after user disable)
4. Each action has a valid `type` from the Wazuh action catalog

### Response Handling

- **201 Created**: Plan accepted, enters `proposed` state
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

## Runtime API Access

The Response Planner calls the runtime REST API at `http://localhost:9090` using `web_fetch`. Pass the auth token as `?token=<AUTOPILOT_MCP_AUTH>` on every request.

### Read Case for Context

Before building a response plan, fetch the full case to review investigation findings, correlation data, and severity.

    web_fetch(url="http://localhost:9090/api/cases/{case_id}?token=<AUTOPILOT_MCP_AUTH>")

The `GET /api/agent-action/create-plan` endpoint for submitting plans is documented above in the "Runtime API: Submit Plans" section.

## Stalled Pipeline Retries

If this agent is triggered with a message prefixed `[RETRY]`, it means the case was previously stalled in the pipeline and is being re-dispatched automatically. The message will contain a pre-built callback URL. Use `web_fetch` to call the provided URL after completing your analysis — do not construct your own URL when one is provided in the retry message.
