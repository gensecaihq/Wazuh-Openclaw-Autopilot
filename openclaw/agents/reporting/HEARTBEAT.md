# Reporting Agent - Heartbeat Schedule

**IMPORTANT:** Use ONLY the `web_fetch` tool for all HTTP requests. Do NOT use `exec`, `curl`, or shell commands.
`web_fetch` runs on the gateway host and can reach `http://localhost:9090`.

## Hourly Snapshot (every hour)
- [ ] Fetch case summary stats: `web_fetch(url="http://localhost:9090/api/cases/summary?token=<AUTOPILOT_MCP_AUTH>")`
- [ ] Fetch plan summary stats: `web_fetch(url="http://localhost:9090/api/plans/summary?token=<AUTOPILOT_MCP_AUTH>")`
- [ ] Fetch KPIs for last hour: `web_fetch(url="http://localhost:9090/api/kpis?period=1h&token=<AUTOPILOT_MCP_AUTH>")`
- [ ] Query runtime metrics for alert volume: `web_fetch(url="http://localhost:9090/metrics?token=<AUTOPILOT_MCP_AUTH>")`
- [ ] Query agent health status via MCP
- [ ] Output: Slack post to ops channel with 4-section snapshot
- [ ] Store report: `web_fetch(url="http://localhost:9090/api/agent-action/store-report?type=hourly&data={URL_ENCODED_JSON}&token=<AUTOPILOT_MCP_AUTH>")`

## Daily Digest (8 AM UTC)
- [ ] Fetch pre-computed KPIs for last 24h: `web_fetch(url="http://localhost:9090/api/kpis?period=24h&token=<AUTOPILOT_MCP_AUTH>")`
- [ ] Fetch case summary for aggregate counts: `web_fetch(url="http://localhost:9090/api/cases/summary?token=<AUTOPILOT_MCP_AUTH>")`
- [ ] Fetch plan summary for action success rate: `web_fetch(url="http://localhost:9090/api/plans/summary?token=<AUTOPILOT_MCP_AUTH>")`
- [ ] Fetch last 24h cases for detailed analysis: `web_fetch(url="http://localhost:9090/api/cases?since={24h_ago_ISO}&limit=100&token=<AUTOPILOT_MCP_AUTH>")`
- [ ] Compare alert volume against 30-day baseline via Prometheus metrics
- [ ] Identify top 10 noisy rules with FP rates via MCP `search_alerts`
- [ ] Compile recurring offenders (IP, user, host) via MCP `search_alerts`
- [ ] Check endpoint and log source coverage
- [ ] Retrieve previous daily report for trend comparison: `web_fetch(url="http://localhost:9090/api/reports?type=daily&limit=1&token=<AUTOPILOT_MCP_AUTH>")`
- [ ] Generate tuning and efficiency recommendations
- [ ] Output: Full Slack report
- [ ] Store report: `web_fetch(url="http://localhost:9090/api/agent-action/store-report?type=daily&data={URL_ENCODED_JSON}&token=<AUTOPILOT_MCP_AUTH>")`

## Shift Handoff (6 AM, 2 PM, 10 PM UTC)
- [ ] Fetch KPIs for last 8h: `web_fetch(url="http://localhost:9090/api/kpis?period=8h&token=<AUTOPILOT_MCP_AUTH>")`
- [ ] Fetch cases from the shift window: `web_fetch(url="http://localhost:9090/api/cases?since={8h_ago_ISO}&token=<AUTOPILOT_MCP_AUTH>")`
- [ ] Fetch plan summary for pending/active actions: `web_fetch(url="http://localhost:9090/api/plans/summary?token=<AUTOPILOT_MCP_AUTH>")`
- [ ] List pending plans awaiting approval: `web_fetch(url="http://localhost:9090/api/plans?state=pending_approval&token=<AUTOPILOT_MCP_AUTH>")`
- [ ] Note any escalations during the shift
- [ ] Write free-text notes for incoming shift (anomalies, ongoing investigations)
- [ ] Output: Slack post to handoff channel
- [ ] Store report: `web_fetch(url="http://localhost:9090/api/agent-action/store-report?type=shift&data={URL_ENCODED_JSON}&token=<AUTOPILOT_MCP_AUTH>")`

## Weekly Summary (Monday 9 AM UTC)
- [ ] Fetch KPIs for last 7 days: `web_fetch(url="http://localhost:9090/api/kpis?period=7d&token=<AUTOPILOT_MCP_AUTH>")`
- [ ] Fetch case summary for week totals: `web_fetch(url="http://localhost:9090/api/cases/summary?token=<AUTOPILOT_MCP_AUTH>")`
- [ ] Fetch plan summary for week totals: `web_fetch(url="http://localhost:9090/api/plans/summary?token=<AUTOPILOT_MCP_AUTH>")`
- [ ] Retrieve previous weekly report for week-over-week comparison: `web_fetch(url="http://localhost:9090/api/reports?type=weekly&limit=1&token=<AUTOPILOT_MCP_AUTH>")`
- [ ] Run trend analysis: moving average (7d) on alert/case volume via Prometheus metrics
- [ ] Run trend analysis: linear regression (30d) on MTTD, MTTR, FP rate
- [ ] Classify each KPI trend as improving/stable/degrading
- [ ] Compile top incidents and attack pattern analysis
- [ ] Assess rule effectiveness and policy effectiveness
- [ ] Identify coverage gaps (MITRE, log sources, endpoints)
- [ ] Generate strategic recommendations
- [ ] Output: Slack report
- [ ] Store report: `web_fetch(url="http://localhost:9090/api/agent-action/store-report?type=weekly&data={URL_ENCODED_JSON}&token=<AUTOPILOT_MCP_AUTH>")`

## Monthly Executive (1st of month, 9 AM UTC)
- [ ] Fetch KPIs for last 30 days: `web_fetch(url="http://localhost:9090/api/kpis?period=30d&token=<AUTOPILOT_MCP_AUTH>")`
- [ ] Fetch case summary for month totals: `web_fetch(url="http://localhost:9090/api/cases/summary?token=<AUTOPILOT_MCP_AUTH>")`
- [ ] Fetch plan summary for month totals: `web_fetch(url="http://localhost:9090/api/plans/summary?token=<AUTOPILOT_MCP_AUTH>")`
- [ ] Retrieve previous monthly report for month-over-month comparison: `web_fetch(url="http://localhost:9090/api/reports?type=monthly&limit=1&token=<AUTOPILOT_MCP_AUTH>")`
- [ ] Calculate security posture score and risk trend
- [ ] Build KPI scorecard with 30-day aggregates
- [ ] Run seasonal decomposition (90d) on alert volume
- [ ] Run anomaly detection (Z-score) on alert and case volume
- [ ] Assess SOC maturity (SOC-CMM framework)
- [ ] Compile compliance status and resource utilization
- [ ] Generate strategic and budget recommendations
- [ ] Output: Executive Slack report
- [ ] Store report: `web_fetch(url="http://localhost:9090/api/agent-action/store-report?type=monthly&data={URL_ENCODED_JSON}&token=<AUTOPILOT_MCP_AUTH>")`

## Rule Effectiveness (Sunday 2 AM UTC)
- [ ] Fetch KPIs for last 30 days: `web_fetch(url="http://localhost:9090/api/kpis?period=30d&token=<AUTOPILOT_MCP_AUTH>")`
- [ ] Fetch cases for last 30 days: `web_fetch(url="http://localhost:9090/api/cases?since={30d_ago_ISO}&limit=500&token=<AUTOPILOT_MCP_AUTH>")`
- [ ] Query 30 days of rule performance data via MCP `search_alerts`
- [ ] Calculate per-rule: alert count, case conversion rate, FP rate
- [ ] Identify high-volume/low-conversion rules
- [ ] Identify high false-positive rules
- [ ] Detect duplicate alert generators
- [ ] Flag rules missing context enrichment
- [ ] Generate specific tuning recommendations per rule
- [ ] Output: Summary to ops channel
- [ ] Store report: `web_fetch(url="http://localhost:9090/api/agent-action/store-report?type=daily&data={URL_ENCODED_JSON}&token=<AUTOPILOT_MCP_AUTH>")`
