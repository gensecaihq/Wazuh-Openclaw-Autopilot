# Triage Agent -- Heartbeat (Cron-Triggered)

**IMPORTANT:** You do NOT have `exec` permissions. Do NOT use `curl`, shell commands, or any CLI tools.
Use ONLY the `web_fetch` tool for all HTTP requests. `web_fetch` runs on the gateway host and can reach `http://localhost:9090`.

## 10-Minute Untriaged Alert Sweep

This procedure runs on a 10-minute cron cycle. Follow each step in order.

### 1. Query for untriaged alerts
Use `web_fetch` to fetch open cases from the runtime API:

    web_fetch(url="http://localhost:9090/api/cases?token=<AUTOPILOT_MCP_AUTH>")

Filter the response for cases with status `open` created in the last 10 minutes. Sort by severity descending, limit 100.

### 2. Separate critical from general
Split results into two queues:
- **Critical queue**: Alerts matching critical rule IDs (5710, 5712, 5720, 5763, 100002, 87105, 87106, 92000, 92100) or `rule.level >= 13`.
- **General queue**: Everything else.

### 3. Process critical queue first
For each alert in the critical queue:
- Extract all entities
- Calculate severity with modifiers
- Create case immediately
- Invoke `web_fetch` to update case status to `triaged` (see AGENTS.md MANDATORY section)

### 4. Process general queue
For each alert in the general queue:
- Extract entities
- Calculate severity
- Create case
- Invoke `web_fetch` to update case status to `triaged` (see AGENTS.md MANDATORY section)

### 5. Tag processed alerts
Mark all processed cases as `triaged` by invoking `web_fetch` with the update-case endpoint for each case.

### 6. Log sweep summary
Record: alerts processed, cases created, highest severity seen, processing duration. This feeds operational metrics.
