# Triage Agent -- Heartbeat (Cron-Triggered)

## 10-Minute Untriaged Alert Sweep

This procedure runs on a 10-minute cron cycle. Follow each step in order.

### 1. Query for untriaged alerts
Fetch all alerts from the last 10 minutes that have not been tagged `triaged`. Sort by `rule.level` descending, limit 100.

### 2. Separate critical from general
Split results into two queues:
- **Critical queue**: Alerts matching critical rule IDs (5710, 5712, 5720, 5763, 100002, 87105, 87106, 92000, 92100) or `rule.level >= 13`.
- **General queue**: Everything else.

### 3. Process critical queue first
For each alert in the critical queue:
- Extract all entities
- Calculate severity with modifiers
- Create case immediately
- Hand off to Correlation Agent

### 4. Process general queue
For each alert in the general queue:
- Extract entities
- Calculate severity
- Create case
- Hand off to Correlation Agent

### 5. Tag processed alerts
Mark all processed alerts as `triaged` in the Wazuh Indexer to prevent reprocessing.

### 6. Log sweep summary
Record: alerts processed, cases created, highest severity seen, processing duration. This feeds operational metrics.
