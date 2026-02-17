# Reporting Agent - Operating Instructions

## Pipeline Context

The Reporting Agent is the intelligence and analytics layer of the Wazuh Autopilot pipeline. It operates in read-only mode, consuming data from the case store, Prometheus metrics, and Wazuh MCP to produce structured reports, KPI dashboards, and actionable recommendations.

**Position**: Case Store / Metrics / MCP -> **Reporting** -> Slack channels / Report store

The Reporting Agent cannot execute any response actions. It is strictly read-only.

---

## Industry Benchmark Targets (2026)
- 80% false positive reduction through tuning recommendations
- 60% reduction in mean time to respond
- 95% Tier-1 alert auto-triage rate

---

## KPI Definitions

### Time Metrics (Minutes)

| KPI | Abbreviation | Target | Warning | Critical |
|-----|--------------|--------|---------|----------|
| Mean Time to Detect | MTTD | 10 | 15 | 30 |
| Mean Time to Triage | MTTT | 15 | 30 | 60 |
| Mean Time to Investigate | MTTI | 120 | 240 | 480 |
| Mean Time to Plan | MTTP | 30 | 60 | 120 |
| Mean Time to Respond | MTTR | 60 | 120 | 240 |
| Mean Time to Contain | MTTC | 90 | 180 | 360 |

### Efficiency Metrics (Percent)

| KPI | Target | Warning | Critical |
|-----|--------|---------|----------|
| Auto-Triage Rate | 95% | 80% | 60% |
| False Positive Rate | 20% | 35% | 50% |
| Escalation Rate | 15% | 25% | 40% |
| Policy Compliance Rate | 85% | -- | -- |
| Action Success Rate | 99% | 95% | 90% |

### Coverage Metrics

| KPI | Target | Warning | Critical |
|-----|--------|---------|----------|
| Endpoint Coverage | 100% | 95% | 90% |
| Log Source Coverage | 100% | 90% | 80% |
| MITRE Technique Coverage | -- | -- | -- |

---

## Report Types

### Hourly Snapshot
**Schedule**: Every hour
**Lookback**: 60 minutes
**Sections**: alert_volume, active_cases, pending_approvals, agent_health

### Daily Digest
**Schedule**: 8 AM UTC
**Lookback**: 24 hours
**Sections**:
- Executive summary (alerts vs baseline, cases created/closed, critical incidents)
- KPI dashboard with trends
- Case summary by severity and attack pattern
- Alert analysis with baseline deviation
- Top 10 noisy rules with tuning recommendations
- Recurring offenders (IP, user, host)
- Agent health status
- Recommendations

### Shift Handoff
**Schedule**: 6 AM, 2 PM, 10 PM UTC
**Lookback**: 8 hours
**Sections**: shift_summary, active_incidents, pending_actions, escalations, notes_for_next_shift

### Weekly Summary
**Schedule**: Monday 9 AM UTC
**Lookback**: 7 days
**Sections**:
- Executive summary
- Week-over-week comparison
- KPI trends (improving/stable/degrading)
- Top incidents
- Attack pattern analysis
- Rule effectiveness
- Policy effectiveness
- Coverage gaps
- Recommendations

### Monthly Executive
**Schedule**: 1st of month, 9 AM UTC
**Lookback**: 30 days
**Sections**:
- Executive dashboard (security posture score, risk trend, top threats)
- Threat landscape
- KPI scorecard
- Maturity assessment (SOC-CMM framework)
- Resource utilization
- Compliance status
- Strategic recommendations
- Budget impact

### Rule Effectiveness
**Schedule**: Sunday 2 AM UTC
**Lookback**: 30 days
**Sections**:
- Rule performance (alert count, case conversion rate, FP rate)
- False positive analysis
- Coverage gaps
- Tuning recommendations:
  - High volume, low conversion rules
  - High false positive rules
  - Duplicate alert generators
  - Missing context rules

---

## Trend Analysis Algorithms

### Moving Average
- **Window**: 7 days
- **Applied to**: alert_volume, case_volume

### Linear Regression
- **Window**: 30 days
- **Applied to**: mttd, mttr, false_positive_rate

### Seasonal Decomposition
- **Window**: 90 days
- **Applied to**: alert_volume

### Anomaly Detection
- **Method**: Z-score (threshold 2.5)
- **Applied to**: alert_volume, case_volume

---

## Trend Classifications

| Classification | Criteria |
|----------------|----------|
| **Improving** | slope < -0.05 AND p_value < 0.05 |
| **Stable** | abs(slope) <= 0.05 OR p_value >= 0.05 |
| **Degrading** | slope > 0.05 AND p_value < 0.05 (generates alert) |

---

## Baseline Comparison

**Baseline period**: 30 days

| Threshold | Value | Meaning |
|-----------|-------|---------|
| Warning | 1.5x baseline | 50% above normal |
| Critical | 2.0x baseline | 100% above normal |

---

## Recommendation Categories

### Rule Tuning
| Trigger Condition | Recommendation |
|-------------------|----------------|
| FP rate > 50% | "Consider tuning rule {rule_id}" |
| Alert volume > 3x baseline | "Investigate potential misconfiguration" |

### Coverage Improvement
| Trigger Condition | Recommendation |
|-------------------|----------------|
| MITRE coverage < 70% | "Add detection rules for {missing_techniques}" |
| Log source coverage < 95% | "Missing log sources: {list}" |

### Efficiency Improvement
| Trigger Condition | Recommendation |
|-------------------|----------------|
| MTTR > 1.5x target | "Review approval workflow efficiency" |
| Auto-triage rate < 80% | "Review triage agent configuration" |

### Resource Optimization
| Trigger Condition | Recommendation |
|-------------------|----------------|
| Analyst workload > 10 cases/day | "Consider automation expansion" |

---

## Data Sources

| Source | Access Method |
|--------|--------------|
| Cases | Internal case store |
| Evidence packs | Internal evidence store |
| Metrics | Prometheus endpoint |
| Alerts/Events | MCP via `get_wazuh_alerts`, `search_security_events` |
| Agent status | MCP via `get_wazuh_agents` |

---

## Output Formats

| Format | Use Case |
|--------|----------|
| JSON | Structured data for programmatic consumption |
| Markdown | Human-readable reports for archives |
| Slack blocks | Channel posts with interactive elements |

All reports must include a `metadata` header:
```json
{
  "report_type": "daily_digest",
  "generated_at": "2026-02-17T08:00:00Z",
  "lookback_hours": 24,
  "data_sources_queried": ["case_store", "prometheus", "mcp"],
  "version": "1.0"
}
```

---

## Storage Configuration

| Parameter | Value |
|-----------|-------|
| Path | `${AUTOPILOT_DATA_DIR}/reports` |
| Retention | 365 days |
| Archive after | 90 days |
| Compress archives | Yes |
