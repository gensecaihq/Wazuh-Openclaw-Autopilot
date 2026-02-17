# Reporting Agent - Heartbeat Schedule

## Hourly Snapshot (every hour)
- [ ] Query Prometheus for alert volume (last 60 min)
- [ ] Count active cases and their severities
- [ ] Check pending approvals in plan store
- [ ] Query agent health status via MCP
- [ ] Output: Slack post to ops channel with 4-section snapshot

## Daily Digest (8 AM UTC)
- [ ] Compute all time KPIs (MTTD, MTTT, MTTI, MTTP, MTTR, MTTC) for last 24h
- [ ] Calculate efficiency metrics (auto-triage rate, FP rate, escalation rate, action success rate)
- [ ] Compare alert volume against 30-day baseline
- [ ] Identify top 10 noisy rules with FP rates
- [ ] Compile recurring offenders (IP, user, host)
- [ ] Check endpoint and log source coverage
- [ ] Generate tuning and efficiency recommendations
- [ ] Output: Full Slack report + JSON archive to report store

## Shift Handoff (6 AM, 2 PM, 10 PM UTC)
- [ ] Summarize last 8 hours: alert count, cases opened/closed
- [ ] List all active incidents with current status
- [ ] List pending actions awaiting approval or execution
- [ ] Note any escalations during the shift
- [ ] Write free-text notes for incoming shift (anomalies, ongoing investigations)
- [ ] Output: Slack post to handoff channel

## Weekly Summary (Monday 9 AM UTC)
- [ ] Compute week-over-week KPI comparison
- [ ] Run trend analysis: moving average (7d) on alert/case volume
- [ ] Run trend analysis: linear regression (30d) on MTTD, MTTR, FP rate
- [ ] Classify each KPI trend as improving/stable/degrading
- [ ] Compile top incidents and attack pattern analysis
- [ ] Assess rule effectiveness and policy effectiveness
- [ ] Identify coverage gaps (MITRE, log sources, endpoints)
- [ ] Generate strategic recommendations
- [ ] Output: Slack report + JSON archive

## Monthly Executive (1st of month, 9 AM UTC)
- [ ] Calculate security posture score and risk trend
- [ ] Build KPI scorecard with 30-day aggregates
- [ ] Run seasonal decomposition (90d) on alert volume
- [ ] Run anomaly detection (Z-score) on alert and case volume
- [ ] Assess SOC maturity (SOC-CMM framework)
- [ ] Compile compliance status and resource utilization
- [ ] Generate strategic and budget recommendations
- [ ] Output: Executive Slack report + JSON + Markdown archive

## Rule Effectiveness (Sunday 2 AM UTC)
- [ ] Query 30 days of rule performance data
- [ ] Calculate per-rule: alert count, case conversion rate, FP rate
- [ ] Identify high-volume/low-conversion rules
- [ ] Identify high false-positive rules
- [ ] Detect duplicate alert generators
- [ ] Flag rules missing context enrichment
- [ ] Generate specific tuning recommendations per rule
- [ ] Output: JSON archive + summary to ops channel
