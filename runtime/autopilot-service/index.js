#!/usr/bin/env node
/**
 * Wazuh OpenClaw Autopilot Runtime Service
 *
 * Minimal runtime providing:
 * - Evidence pack persistence
 * - Approval token management
 * - Metrics endpoint
 * - Structured logging
 * - MCP client wrapper with toolmap resolution
 *
 * This service is intentionally minimal - core orchestration
 * is handled by OpenClaw agents.
 */

const http = require("http");
const fs = require("fs").promises;
const path = require("path");
const crypto = require("crypto");

// Slack integration (optional)
let slack = null;
try {
  slack = require("./slack");
} catch (err) {
  // Slack module not available or dependencies not installed
}

// =============================================================================
// CONFIGURATION
// =============================================================================

const config = {
  mode: process.env.AUTOPILOT_MODE || "bootstrap",
  requireTailscale: process.env.AUTOPILOT_REQUIRE_TAILSCALE === "true",
  mcpUrl: process.env.MCP_URL || process.env.MCP_BOOTSTRAP_URL,
  mcpAuth: process.env.AUTOPILOT_MCP_AUTH || "",
  dataDir: process.env.AUTOPILOT_DATA_DIR || "/var/lib/wazuh-autopilot",
  configDir: process.env.AUTOPILOT_CONFIG_DIR || "/etc/wazuh-autopilot",
  metricsEnabled: process.env.METRICS_ENABLED !== "false",
  metricsPort: parseInt(process.env.METRICS_PORT || "9090", 10),
  metricsHost: process.env.METRICS_HOST || "127.0.0.1",
  logFormat: process.env.LOG_FORMAT || "json",
  logLevel: process.env.LOG_LEVEL || "info",
  approvalTtlMinutes: parseInt(
    process.env.APPROVAL_TOKEN_TTL_MINUTES || "60",
    10
  ),
  // Rate limiting
  rateLimitWindowMs: parseInt(process.env.RATE_LIMIT_WINDOW_MS || "60000", 10),
  rateLimitMaxRequests: parseInt(process.env.RATE_LIMIT_MAX_REQUESTS || "100", 10),
  // MCP timeout
  mcpTimeoutMs: parseInt(process.env.MCP_TIMEOUT_MS || "30000", 10),
  // Responder capability toggle - DISABLED by default
  // When enabled, humans can execute approved plans via the two-tier approval workflow
  // This does NOT enable autonomous execution - human approval is ALWAYS required
  responderEnabled: process.env.AUTOPILOT_RESPONDER_ENABLED === "true",
  // Plan expiry
  planExpiryMinutes: parseInt(process.env.PLAN_EXPIRY_MINUTES || "60", 10),
};

// =============================================================================
// LOGGING
// =============================================================================

const LOG_LEVELS = { debug: 0, info: 1, warn: 2, error: 3 };
const currentLogLevel = LOG_LEVELS[config.logLevel] || 1;

function log(level, component, msg, extra = {}) {
  if (LOG_LEVELS[level] < currentLogLevel) return;

  const entry = {
    ts: new Date().toISOString(),
    level,
    component,
    msg,
    ...extra,
  };

  // Ensure we never log secrets
  delete entry.auth;
  delete entry.token;
  delete entry.password;
  delete entry.secret;

  if (config.logFormat === "json") {
    console.log(JSON.stringify(entry));
  } else {
    console.log(`[${entry.ts}] [${level.toUpperCase()}] [${component}] ${msg}`);
  }
}

// =============================================================================
// METRICS
// =============================================================================

const metrics = {
  cases_created_total: 0,
  cases_updated_total: 0,
  alerts_ingested_total: 0,
  triage_latency_seconds: [],
  mcp_tool_calls_total: {},
  mcp_tool_call_latency_seconds: {},
  action_plans_proposed_total: 0,
  approvals_requested_total: 0,
  approvals_granted_total: 0,
  // Two-tier approval metrics
  plans_created_total: 0,
  plans_approved_total: 0,
  plans_executed_total: 0,
  plans_rejected_total: 0,
  plans_expired_total: 0,
  executions_success_total: 0,
  executions_failed_total: 0,
  responder_disabled_blocks_total: 0,
  policy_denies_total: {},
  errors_total: {},
};

function incrementMetric(name, labels = {}) {
  if (Object.keys(labels).length === 0) {
    metrics[name] = (metrics[name] || 0) + 1;
  } else {
    const key = JSON.stringify(labels);
    if (!metrics[name]) metrics[name] = {};
    metrics[name][key] = (metrics[name][key] || 0) + 1;
  }
}

// Maximum samples to retain per metric key (prevents memory leak)
const MAX_LATENCY_SAMPLES = 1000;

function recordLatency(name, seconds, labels = {}) {
  const key = Object.keys(labels).length > 0 ? JSON.stringify(labels) : "default";
  if (!metrics[name]) metrics[name] = {};
  if (!metrics[name][key]) metrics[name][key] = [];

  // Prevent unbounded array growth - keep only recent samples
  if (metrics[name][key].length >= MAX_LATENCY_SAMPLES) {
    metrics[name][key].shift(); // Remove oldest sample
  }
  metrics[name][key].push(seconds);
}

function formatMetrics() {
  const lines = [];

  // Simple counters
  [
    "cases_created_total", "cases_updated_total", "alerts_ingested_total",
    "action_plans_proposed_total", "approvals_requested_total", "approvals_granted_total",
    // Two-tier approval metrics
    "plans_created_total", "plans_approved_total", "plans_executed_total",
    "plans_rejected_total", "plans_expired_total",
    "executions_success_total", "executions_failed_total",
    "responder_disabled_blocks_total",
  ].forEach((name) => {
    lines.push(`# TYPE autopilot_${name} counter`);
    lines.push(`autopilot_${name} ${metrics[name] || 0}`);
  });

  // Labeled counters
  ["mcp_tool_calls_total", "policy_denies_total", "errors_total"].forEach((name) => {
    lines.push(`# TYPE autopilot_${name} counter`);
    const data = metrics[name] || {};
    Object.entries(data).forEach(([labelJson, value]) => {
      const labels = JSON.parse(labelJson);
      const labelStr = Object.entries(labels)
        .map(([k, v]) => `${k}="${v}"`)
        .join(",");
      lines.push(`autopilot_${name}{${labelStr}} ${value}`);
    });
  });

  // Histograms (simplified - just output sum and count)
  ["triage_latency_seconds", "mcp_tool_call_latency_seconds"].forEach((name) => {
    lines.push(`# TYPE autopilot_${name} histogram`);
    const data = metrics[name] || {};
    Object.entries(data).forEach(([labelJson, values]) => {
      if (!Array.isArray(values)) return;
      const sum = values.reduce((a, b) => a + b, 0);
      const count = values.length;
      let labelStr = "";
      if (labelJson !== "default") {
        const labels = JSON.parse(labelJson);
        labelStr = Object.entries(labels)
          .map(([k, v]) => `${k}="${v}"`)
          .join(",");
        labelStr = `{${labelStr}}`;
      }
      lines.push(`autopilot_${name}_sum${labelStr} ${sum.toFixed(6)}`);
      lines.push(`autopilot_${name}_count${labelStr} ${count}`);
    });
  });

  return lines.join("\n");
}

// =============================================================================
// EVIDENCE PACK MANAGEMENT
// =============================================================================

const EVIDENCE_PACK_SCHEMA_VERSION = "1.0";

async function ensureDir(dirPath) {
  try {
    await fs.mkdir(dirPath, { recursive: true });
  } catch (err) {
    if (err.code !== "EEXIST") throw err;
  }
}

async function createCase(caseId, data) {
  const caseDir = path.join(config.dataDir, "cases", caseId);
  await ensureDir(caseDir);

  const now = new Date().toISOString();

  const evidencePack = {
    schema_version: EVIDENCE_PACK_SCHEMA_VERSION,
    case_id: caseId,
    created_at: now,
    updated_at: now,
    title: data.title || "",
    summary: data.summary || "",
    severity: data.severity || "medium",
    confidence: data.confidence || 0,
    entities: data.entities || [],
    timeline: data.timeline || [],
    mitre: data.mitre || [],
    mcp_calls: [],
    evidence_refs: data.evidence_refs || [],
    plans: [],
    approvals: [],
    actions: [],
  };

  await fs.writeFile(
    path.join(caseDir, "evidence-pack.json"),
    JSON.stringify(evidencePack, null, 2)
  );

  // Also create a lightweight summary
  const caseSummary = {
    case_id: caseId,
    created_at: now,
    updated_at: now,
    title: data.title,
    severity: data.severity,
    status: "open",
  };

  await fs.writeFile(
    path.join(caseDir, "case.json"),
    JSON.stringify(caseSummary, null, 2)
  );

  incrementMetric("cases_created_total");
  log("info", "evidence-pack", "Case created", { case_id: caseId });

  // Post to Slack alerts channel (async, don't await)
  if (slack && slack.isInitialized()) {
    slack.postCaseAlert({
      case_id: caseId,
      title: data.title,
      summary: data.summary,
      severity: data.severity,
      entities: data.entities || [],
      created_at: now,
    }).catch((err) => {
      log("warn", "evidence-pack", "Failed to post case to Slack", { error: err.message, case_id: caseId });
    });
  }

  return evidencePack;
}

async function updateCase(caseId, updates) {
  const caseDir = path.join(config.dataDir, "cases", caseId);
  const packPath = path.join(caseDir, "evidence-pack.json");

  let evidencePack;
  try {
    const content = await fs.readFile(packPath, "utf8");
    evidencePack = JSON.parse(content);
  } catch (err) {
    throw new Error(`Case not found: ${caseId}`);
  }

  // Apply updates
  const now = new Date().toISOString();
  evidencePack.updated_at = now;

  if (updates.title) evidencePack.title = updates.title;
  if (updates.summary) evidencePack.summary = updates.summary;
  if (updates.severity) evidencePack.severity = updates.severity;
  if (updates.confidence) evidencePack.confidence = updates.confidence;

  if (updates.entities) {
    evidencePack.entities = [...evidencePack.entities, ...updates.entities];
  }
  if (updates.timeline) {
    evidencePack.timeline = [...evidencePack.timeline, ...updates.timeline];
  }
  if (updates.mcp_calls) {
    evidencePack.mcp_calls = [...evidencePack.mcp_calls, ...updates.mcp_calls];
  }
  if (updates.evidence_refs) {
    evidencePack.evidence_refs = [
      ...evidencePack.evidence_refs,
      ...updates.evidence_refs,
    ];
  }
  if (updates.plans) {
    evidencePack.plans = [...evidencePack.plans, ...updates.plans];
  }
  if (updates.approvals) {
    evidencePack.approvals = [...evidencePack.approvals, ...updates.approvals];
  }
  if (updates.actions) {
    evidencePack.actions = [...evidencePack.actions, ...updates.actions];
  }

  await fs.writeFile(packPath, JSON.stringify(evidencePack, null, 2));

  // Update summary
  const summaryPath = path.join(caseDir, "case.json");
  try {
    const summaryContent = await fs.readFile(summaryPath, "utf8");
    const summary = JSON.parse(summaryContent);
    summary.updated_at = now;
    if (updates.title) summary.title = updates.title;
    if (updates.severity) summary.severity = updates.severity;
    if (updates.status) summary.status = updates.status;
    await fs.writeFile(summaryPath, JSON.stringify(summary, null, 2));
  } catch (err) {
    // Summary file might not exist, that's ok
  }

  incrementMetric("cases_updated_total");
  log("info", "evidence-pack", "Case updated", { case_id: caseId });

  return evidencePack;
}

async function getCase(caseId) {
  const packPath = path.join(
    config.dataDir,
    "cases",
    caseId,
    "evidence-pack.json"
  );
  try {
    const content = await fs.readFile(packPath, "utf8");
    return JSON.parse(content);
  } catch (err) {
    throw new Error(`Case not found: ${caseId}`);
  }
}

async function listCases(options = {}) {
  const casesDir = path.join(config.dataDir, "cases");
  await ensureDir(casesDir);

  const entries = await fs.readdir(casesDir, { withFileTypes: true });
  const cases = [];

  for (const entry of entries) {
    if (entry.isDirectory()) {
      try {
        const summaryPath = path.join(casesDir, entry.name, "case.json");
        const content = await fs.readFile(summaryPath, "utf8");
        cases.push(JSON.parse(content));
      } catch (err) {
        // Skip cases without summary
      }
    }
  }

  // Sort by created_at descending
  cases.sort((a, b) => new Date(b.created_at) - new Date(a.created_at));

  // Apply limit
  if (options.limit) {
    return cases.slice(0, options.limit);
  }

  return cases;
}

// =============================================================================
// APPROVAL TOKEN MANAGEMENT
// =============================================================================

const approvalTokens = new Map();
const MAX_APPROVAL_TOKENS = 10000; // Prevent unbounded growth

function generateApprovalToken(planId, caseId) {
  // Enforce token limit to prevent memory exhaustion
  if (approvalTokens.size >= MAX_APPROVAL_TOKENS) {
    // Remove oldest expired tokens first
    const now = Date.now();
    let removed = 0;
    for (const [token, data] of approvalTokens.entries()) {
      if (new Date(data.expires_at) < new Date(now) || data.used) {
        approvalTokens.delete(token);
        removed++;
        if (approvalTokens.size < MAX_APPROVAL_TOKENS * 0.9) break;
      }
    }
    log("warn", "approval", "Token cleanup triggered", { removed, remaining: approvalTokens.size });

    // If still at limit, reject new token creation
    if (approvalTokens.size >= MAX_APPROVAL_TOKENS) {
      log("error", "approval", "Token limit reached, cannot create new token");
      throw new Error("Approval token limit reached");
    }
  }

  const token = crypto.randomBytes(32).toString("hex");
  const expiresAt = Date.now() + config.approvalTtlMinutes * 60 * 1000;

  approvalTokens.set(token, {
    plan_id: planId,
    case_id: caseId,
    approver_id: null,
    created_at: new Date().toISOString(),
    expires_at: new Date(expiresAt).toISOString(),
    used: false,
  });

  incrementMetric("approvals_requested_total");
  log("info", "approval", "Approval token created", { plan_id: planId, case_id: caseId });

  return token;
}

function validateApprovalToken(token, approverId) {
  const tokenData = approvalTokens.get(token);

  if (!tokenData) {
    return { valid: false, reason: "INVALID_APPROVAL_TOKEN" };
  }

  if (tokenData.used) {
    return { valid: false, reason: "TOKEN_ALREADY_USED" };
  }

  if (new Date(tokenData.expires_at) < new Date()) {
    return { valid: false, reason: "EXPIRED_APPROVAL" };
  }

  return { valid: true, tokenData };
}

function consumeApprovalToken(token, approverId, decision, reason = "") {
  const tokenData = approvalTokens.get(token);
  if (!tokenData) return null;

  tokenData.used = true;
  tokenData.approver_id = approverId;
  tokenData.decision = decision;
  tokenData.decision_reason = reason;
  tokenData.decided_at = new Date().toISOString();

  if (decision === "approve") {
    incrementMetric("approvals_granted_total");
  } else {
    incrementMetric("policy_denies_total", { reason: "APPROVER_DENIED" });
  }

  log("info", "approval", `Approval ${decision}`, {
    plan_id: tokenData.plan_id,
    case_id: tokenData.case_id,
    approver_id: approverId,
  });

  return tokenData;
}

// Note: Token cleanup is now handled by setupCleanupIntervals() during startup

// =============================================================================
// RESPONSE PLANS MANAGEMENT (TWO-TIER APPROVAL)
// =============================================================================
// Plan states: proposed -> approved -> executing -> completed/failed
// Tier 1: Human clicks "Approve" to validate the plan
// Tier 2: Human clicks "Execute" to trigger execution

const responsePlans = new Map();
const MAX_PLANS = 10000;

// Plan states
const PLAN_STATES = {
  PROPOSED: "proposed",
  APPROVED: "approved",
  EXECUTING: "executing",
  COMPLETED: "completed",
  FAILED: "failed",
  REJECTED: "rejected",
  EXPIRED: "expired",
};

function createResponsePlan(planData) {
  // Enforce plan limit
  if (responsePlans.size >= MAX_PLANS) {
    // Clean up old completed/failed/expired plans
    let removed = 0;
    const cutoff = Date.now() - 24 * 60 * 60 * 1000; // 24 hours
    for (const [planId, plan] of responsePlans.entries()) {
      if (
        ["completed", "failed", "rejected", "expired"].includes(plan.state) &&
        new Date(plan.updated_at) < new Date(cutoff)
      ) {
        responsePlans.delete(planId);
        removed++;
        if (responsePlans.size < MAX_PLANS * 0.9) break;
      }
    }
    log("warn", "plans", "Plan cleanup triggered", { removed, remaining: responsePlans.size });

    if (responsePlans.size >= MAX_PLANS) {
      throw new Error("Response plan limit reached");
    }
  }

  const planId = `PLAN-${Date.now()}-${crypto.randomBytes(4).toString("hex")}`;
  const now = new Date().toISOString();
  const expiresAt = new Date(Date.now() + config.planExpiryMinutes * 60 * 1000).toISOString();

  const plan = {
    plan_id: planId,
    case_id: planData.case_id,
    state: PLAN_STATES.PROPOSED,
    created_at: now,
    updated_at: now,
    expires_at: expiresAt,
    // Plan details
    title: planData.title || "Response Plan",
    description: planData.description || "",
    risk_level: planData.risk_level || "medium",
    actions: planData.actions || [],
    // Approval tracking
    approver_id: null,
    approved_at: null,
    approval_reason: null,
    // Execution tracking
    executor_id: null,
    executed_at: null,
    execution_result: null,
    // Rejection tracking
    rejector_id: null,
    rejected_at: null,
    rejection_reason: null,
  };

  responsePlans.set(planId, plan);
  incrementMetric("plans_created_total");
  log("info", "plans", "Response plan created", {
    plan_id: planId,
    case_id: planData.case_id,
    actions_count: plan.actions.length,
    risk_level: plan.risk_level,
  });

  // Post to Slack for approval (async, don't await)
  if (slack && slack.isInitialized()) {
    slack.postPlanForApproval(plan).catch((err) => {
      log("warn", "plans", "Failed to post plan to Slack", { error: err.message, plan_id: planId });
    });
  }

  return plan;
}

function getPlan(planId) {
  const plan = responsePlans.get(planId);
  if (!plan) {
    throw new Error(`Plan not found: ${planId}`);
  }

  // Check if plan has expired
  if (plan.state === PLAN_STATES.PROPOSED || plan.state === PLAN_STATES.APPROVED) {
    if (new Date(plan.expires_at) < new Date()) {
      plan.state = PLAN_STATES.EXPIRED;
      plan.updated_at = new Date().toISOString();
      incrementMetric("plans_expired_total");
      log("info", "plans", "Plan expired", { plan_id: planId });
    }
  }

  return plan;
}

function listPlans(options = {}) {
  const plans = [];
  const { state, case_id, limit = 100 } = options;

  for (const plan of responsePlans.values()) {
    // Filter by state
    if (state && plan.state !== state) continue;
    // Filter by case
    if (case_id && plan.case_id !== case_id) continue;

    plans.push(plan);
  }

  // Sort by created_at descending
  plans.sort((a, b) => new Date(b.created_at) - new Date(a.created_at));

  return plans.slice(0, limit);
}

// TIER 1: Approve a plan (human clicks "Approve")
function approvePlan(planId, approverId, reason = "") {
  const plan = getPlan(planId);

  // Validate state
  if (plan.state !== PLAN_STATES.PROPOSED) {
    throw new Error(`Cannot approve plan in state: ${plan.state}`);
  }

  // Check if expired
  if (new Date(plan.expires_at) < new Date()) {
    plan.state = PLAN_STATES.EXPIRED;
    plan.updated_at = new Date().toISOString();
    incrementMetric("plans_expired_total");
    throw new Error("Plan has expired");
  }

  const now = new Date().toISOString();
  plan.state = PLAN_STATES.APPROVED;
  plan.approver_id = approverId;
  plan.approved_at = now;
  plan.approval_reason = reason;
  plan.updated_at = now;
  // Extend expiry after approval (give time for execution)
  plan.expires_at = new Date(Date.now() + config.planExpiryMinutes * 60 * 1000).toISOString();

  incrementMetric("plans_approved_total");
  log("info", "plans", "Plan approved (Tier 1)", {
    plan_id: planId,
    approver_id: approverId,
    case_id: plan.case_id,
  });

  return plan;
}

// Reject a plan
function rejectPlan(planId, rejectorId, reason = "") {
  const plan = getPlan(planId);

  // Can reject from proposed or approved state
  if (!["proposed", "approved"].includes(plan.state)) {
    throw new Error(`Cannot reject plan in state: ${plan.state}`);
  }

  const now = new Date().toISOString();
  plan.state = PLAN_STATES.REJECTED;
  plan.rejector_id = rejectorId;
  plan.rejected_at = now;
  plan.rejection_reason = reason;
  plan.updated_at = now;

  incrementMetric("plans_rejected_total");
  log("info", "plans", "Plan rejected", {
    plan_id: planId,
    rejector_id: rejectorId,
    case_id: plan.case_id,
    reason,
  });

  return plan;
}

// TIER 2: Execute a plan (human clicks "Execute")
async function executePlan(planId, executorId) {
  // CRITICAL: Check if responder capability is enabled
  if (!config.responderEnabled) {
    incrementMetric("responder_disabled_blocks_total");
    log("warn", "plans", "Execution blocked - Responder capability is DISABLED", {
      plan_id: planId,
      executor_id: executorId,
      hint: "Set AUTOPILOT_RESPONDER_ENABLED=true to enable execution capability",
    });
    throw new Error(
      "Responder capability is DISABLED. Set AUTOPILOT_RESPONDER_ENABLED=true to enable. " +
      "Note: Human approval (Approve + Execute) will still be required for every action."
    );
  }

  const plan = getPlan(planId);

  // Validate state - must be approved first (Tier 1 complete)
  if (plan.state !== PLAN_STATES.APPROVED) {
    if (plan.state === PLAN_STATES.PROPOSED) {
      throw new Error("Plan must be approved before execution (Tier 1 required)");
    }
    throw new Error(`Cannot execute plan in state: ${plan.state}`);
  }

  // Check if expired
  if (new Date(plan.expires_at) < new Date()) {
    plan.state = PLAN_STATES.EXPIRED;
    plan.updated_at = new Date().toISOString();
    incrementMetric("plans_expired_total");
    throw new Error("Plan has expired - approval is no longer valid");
  }

  const now = new Date().toISOString();
  plan.state = PLAN_STATES.EXECUTING;
  plan.executor_id = executorId;
  plan.executed_at = now;
  plan.updated_at = now;

  incrementMetric("plans_executed_total");
  log("info", "plans", "Plan execution started (Tier 2)", {
    plan_id: planId,
    executor_id: executorId,
    case_id: plan.case_id,
    actions_count: plan.actions.length,
  });

  // Execute actions
  const results = [];
  let allSuccess = true;

  for (const action of plan.actions) {
    try {
      // Validate action has required fields
      if (!action.type || !action.target) {
        throw new Error("Action missing required fields: type, target");
      }

      // Call MCP tool for the action
      const correlationId = `${planId}-${action.type}-${Date.now()}`;
      const mcpResult = await callMcpTool(action.type, action.params || {}, correlationId);

      results.push({
        action_type: action.type,
        target: action.target,
        status: mcpResult.success ? "success" : "failed",
        mcp_response: mcpResult.data,
        timestamp: new Date().toISOString(),
      });

      if (!mcpResult.success) {
        allSuccess = false;
      }
    } catch (err) {
      allSuccess = false;
      results.push({
        action_type: action.type,
        target: action.target,
        status: "error",
        error: err.message,
        timestamp: new Date().toISOString(),
      });
      log("error", "plans", "Action execution failed", {
        plan_id: planId,
        action_type: action.type,
        target: action.target,
        error: err.message,
      });
    }
  }

  // Update plan with results
  plan.execution_result = {
    success: allSuccess,
    actions_total: plan.actions.length,
    actions_success: results.filter((r) => r.status === "success").length,
    actions_failed: results.filter((r) => r.status !== "success").length,
    results,
  };
  plan.state = allSuccess ? PLAN_STATES.COMPLETED : PLAN_STATES.FAILED;
  plan.updated_at = new Date().toISOString();

  if (allSuccess) {
    incrementMetric("executions_success_total");
  } else {
    incrementMetric("executions_failed_total");
  }

  log("info", "plans", "Plan execution completed", {
    plan_id: planId,
    case_id: plan.case_id,
    state: plan.state,
    actions_success: plan.execution_result.actions_success,
    actions_failed: plan.execution_result.actions_failed,
  });

  // Update the associated case with execution results
  try {
    await updateCase(plan.case_id, {
      actions: [
        {
          plan_id: planId,
          executed_at: plan.executed_at,
          executor_id: executorId,
          result: plan.execution_result,
        },
      ],
    });
  } catch (err) {
    log("warn", "plans", "Failed to update case with execution results", {
      plan_id: planId,
      case_id: plan.case_id,
      error: err.message,
    });
  }

  return plan;
}

// Check responder status
function getResponderStatus() {
  return {
    enabled: config.responderEnabled,
    message: config.responderEnabled
      ? "Responder capability ENABLED - humans can execute approved plans (two-tier approval always required)"
      : "Responder capability DISABLED - execution blocked even after human approval",
    human_approval_required: true,
    autonomous_execution: false,
    environment_variable: "AUTOPILOT_RESPONDER_ENABLED",
    current_value: process.env.AUTOPILOT_RESPONDER_ENABLED || "false",
    note: "AI agents cannot execute actions autonomously. Human must always Approve AND Execute.",
  };
}

// =============================================================================
// MCP CLIENT WRAPPER
// =============================================================================

// Simple YAML parser for toolmap (handles basic key-value and nested structures)
function parseSimpleYaml(content) {
  const result = {};
  const lines = content.split('\n');
  const stack = [{ indent: -1, obj: result }];

  for (const line of lines) {
    // Skip comments and empty lines
    if (line.trim().startsWith('#') || line.trim() === '') continue;

    const indent = line.search(/\S/);
    if (indent === -1) continue;

    // Pop stack to find parent
    while (stack.length > 1 && stack[stack.length - 1].indent >= indent) {
      stack.pop();
    }

    const parent = stack[stack.length - 1].obj;
    const trimmed = line.trim();

    // Handle list items
    if (trimmed.startsWith('- ')) {
      const value = trimmed.substring(2).trim();
      const lastKey = Object.keys(parent).pop();
      if (lastKey && !Array.isArray(parent[lastKey])) {
        parent[lastKey] = [];
      }
      if (lastKey) {
        if (value.includes(':')) {
          const obj = {};
          const [k, v] = value.split(':').map(s => s.trim());
          obj[k] = v.replace(/^["']|["']$/g, '');
          parent[lastKey].push(obj);
        } else {
          parent[lastKey].push(value.replace(/^["']|["']$/g, ''));
        }
      }
      continue;
    }

    // Handle key: value pairs
    const colonIndex = trimmed.indexOf(':');
    if (colonIndex > 0) {
      const key = trimmed.substring(0, colonIndex).trim();
      let value = trimmed.substring(colonIndex + 1).trim();

      if (value === '' || value === '|' || value === '>') {
        // Nested object or multiline string
        parent[key] = {};
        stack.push({ indent, obj: parent[key] });
      } else {
        // Parse value
        if (value === 'true') value = true;
        else if (value === 'false') value = false;
        else if (value === 'null') value = null;
        else if (/^\d+$/.test(value)) value = parseInt(value, 10);
        else if (/^\d+\.\d+$/.test(value)) value = parseFloat(value);
        else value = value.replace(/^["']|["']$/g, '');

        parent[key] = value;
      }
    }
  }

  return result;
}

// Loaded toolmap configuration
let toolmapConfig = null;

async function loadToolmap() {
  const toolmapPath = path.join(config.configDir, "policies", "toolmap.yaml");
  try {
    const content = await fs.readFile(toolmapPath, "utf8");
    toolmapConfig = parseSimpleYaml(content);

    // Count loaded tools
    let toolCount = 0;
    if (toolmapConfig.read_operations) {
      toolCount += Object.keys(toolmapConfig.read_operations).length;
    }
    if (toolmapConfig.action_operations) {
      toolCount += Object.keys(toolmapConfig.action_operations).length;
    }

    log("info", "mcp", "Toolmap loaded and parsed", {
      path: toolmapPath,
      tools_loaded: toolCount,
    });
    return toolmapConfig;
  } catch (err) {
    log("warn", "mcp", "Toolmap not found or invalid, using defaults", {
      path: toolmapPath,
      error: err.message,
    });
    // Provide default tool mappings
    toolmapConfig = {
      read_operations: {
        get_alert: { mcp_tool: "wazuh_get_alert", enabled: true },
        search_alerts: { mcp_tool: "wazuh_search_alerts", enabled: true },
        search_events: { mcp_tool: "wazuh_search_events", enabled: true },
        get_agent: { mcp_tool: "wazuh_get_agent", enabled: true },
        get_rule_info: { mcp_tool: "wazuh_get_rule", enabled: true },
      },
      action_operations: {
        block_ip: { mcp_tool: "wazuh_block_ip", enabled: false },
        isolate_host: { mcp_tool: "wazuh_isolate_host", enabled: false },
        kill_process: { mcp_tool: "wazuh_kill_process", enabled: false },
      },
    };
    return toolmapConfig;
  }
}

// Resolve logical tool name to MCP tool name
function resolveMcpTool(logicalName) {
  if (!toolmapConfig) return logicalName;

  // Check read operations
  if (toolmapConfig.read_operations && toolmapConfig.read_operations[logicalName]) {
    const tool = toolmapConfig.read_operations[logicalName];
    if (typeof tool === 'object' && tool.mcp_tool) {
      return tool.mcp_tool;
    }
  }

  // Check action operations
  if (toolmapConfig.action_operations && toolmapConfig.action_operations[logicalName]) {
    const tool = toolmapConfig.action_operations[logicalName];
    if (typeof tool === 'object' && tool.mcp_tool) {
      return tool.mcp_tool;
    }
  }

  return logicalName;
}

// Check if a tool is enabled
function isToolEnabled(logicalName) {
  if (!toolmapConfig) return true;

  // Check read operations (default enabled)
  if (toolmapConfig.read_operations && toolmapConfig.read_operations[logicalName]) {
    const tool = toolmapConfig.read_operations[logicalName];
    return typeof tool === 'object' ? tool.enabled !== false : true;
  }

  // Check action operations (default disabled)
  if (toolmapConfig.action_operations && toolmapConfig.action_operations[logicalName]) {
    const tool = toolmapConfig.action_operations[logicalName];
    return typeof tool === 'object' ? tool.enabled === true : false;
  }

  return true;
}

async function callMcpTool(toolName, params, correlationId) {
  const startTime = Date.now();

  if (!config.mcpUrl) {
    incrementMetric("errors_total", { component: "mcp" });
    throw new Error("MCP_URL not configured");
  }

  // Check if tool is enabled
  if (!isToolEnabled(toolName)) {
    incrementMetric("errors_total", { component: "mcp" });
    throw new Error(`Tool '${toolName}' is disabled in toolmap configuration`);
  }

  // Resolve logical tool name to MCP tool name
  const mcpToolName = resolveMcpTool(toolName);

  const requestHash = crypto
    .createHash("sha256")
    .update(JSON.stringify({ toolName: mcpToolName, params }))
    .digest("hex")
    .substring(0, 16);

  try {
    // Create abort controller for timeout
    const controller = new AbortController();
    const timeoutId = setTimeout(() => controller.abort(), config.mcpTimeoutMs);

    const response = await fetch(`${config.mcpUrl}/tools/${mcpToolName}`, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        ...(config.mcpAuth && { Authorization: `Bearer ${config.mcpAuth}` }),
        ...(correlationId && { "X-Correlation-ID": correlationId }),
      },
      body: JSON.stringify(params),
      signal: controller.signal,
    });

    clearTimeout(timeoutId);

    const latencySeconds = (Date.now() - startTime) / 1000;
    const status = response.ok ? "success" : "error";

    incrementMetric("mcp_tool_calls_total", { tool: toolName, status });
    recordLatency("mcp_tool_call_latency_seconds", latencySeconds, { tool: toolName });

    const responseData = await response.json();
    const responseHash = crypto
      .createHash("sha256")
      .update(JSON.stringify(responseData))
      .digest("hex")
      .substring(0, 16);

    log("info", "mcp", "Tool call completed", {
      tool: toolName,
      status,
      latency_ms: Math.round(latencySeconds * 1000),
      correlation_id: correlationId,
    });

    return {
      success: response.ok,
      data: responseData,
      metadata: {
        tool_name: toolName,
        request_hash: requestHash,
        response_hash: responseHash,
        status,
        latency_ms: Math.round(latencySeconds * 1000),
        timestamp: new Date().toISOString(),
      },
    };
  } catch (err) {
    const latencySeconds = (Date.now() - startTime) / 1000;
    incrementMetric("mcp_tool_calls_total", { tool: toolName, status: "error" });
    incrementMetric("errors_total", { component: "mcp" });
    recordLatency("mcp_tool_call_latency_seconds", latencySeconds, { tool: toolName });

    log("error", "mcp", "Tool call failed", {
      tool: toolName,
      error: err.message,
      correlation_id: correlationId,
    });

    throw err;
  }
}

// =============================================================================
// RATE LIMITING
// =============================================================================

const rateLimitState = {
  requests: new Map(), // IP -> { count, resetTime }
};

function checkRateLimit(clientIp) {
  const now = Date.now();
  const clientData = rateLimitState.requests.get(clientIp);

  if (!clientData || now > clientData.resetTime) {
    rateLimitState.requests.set(clientIp, {
      count: 1,
      resetTime: now + config.rateLimitWindowMs,
    });
    return { allowed: true, remaining: config.rateLimitMaxRequests - 1 };
  }

  if (clientData.count >= config.rateLimitMaxRequests) {
    return {
      allowed: false,
      remaining: 0,
      retryAfter: Math.ceil((clientData.resetTime - now) / 1000),
    };
  }

  clientData.count++;
  return { allowed: true, remaining: config.rateLimitMaxRequests - clientData.count };
}

// Note: Rate limit cleanup is now handled by setupCleanupIntervals() during startup

// =============================================================================
// HTTP SERVER
// =============================================================================

const SERVICE_VERSION = "2.0.0";
const startTime = Date.now();

// Input validation
function isValidCaseId(caseId) {
  // Case IDs must be alphanumeric with hyphens, 1-64 chars
  return /^[a-zA-Z0-9-]{1,64}$/.test(caseId);
}

// Authorization validation for sensitive endpoints
function validateAuthorization(req, requiredScope = "write") {
  const authHeader = req.headers.authorization;

  // Allow requests from localhost without auth (for internal agents)
  const clientIp = req.headers["x-forwarded-for"]?.split(",")[0]?.trim() ||
                   req.socket.remoteAddress || "unknown";
  const isLocalhost = clientIp === "127.0.0.1" || clientIp === "::1" ||
                      clientIp === "::ffff:127.0.0.1";

  if (isLocalhost && !authHeader) {
    return { valid: true, source: "localhost" };
  }

  // Require authorization for non-localhost requests
  if (!authHeader) {
    return { valid: false, reason: "Missing Authorization header" };
  }

  // Validate Bearer token format
  if (!authHeader.startsWith("Bearer ")) {
    return { valid: false, reason: "Invalid Authorization format" };
  }

  const token = authHeader.substring(7);

  // Validate against configured MCP auth token
  // In production, this should use proper token validation (JWT, etc.)
  if (config.mcpAuth && token === config.mcpAuth) {
    return { valid: true, source: "api_token" };
  }

  // Also check for internal service token (environment variable)
  const serviceToken = process.env.AUTOPILOT_SERVICE_TOKEN;
  if (serviceToken && token === serviceToken) {
    return { valid: true, source: "service_token" };
  }

  return { valid: false, reason: "Invalid or expired token" };
}

// Parse JSON body from request
async function parseJsonBody(req) {
  return new Promise((resolve, reject) => {
    let body = "";
    req.on("data", (chunk) => {
      body += chunk;
      // Limit body size to 1MB
      if (body.length > 1024 * 1024) {
        reject(new Error("Request body too large"));
      }
    });
    req.on("end", () => {
      try {
        resolve(body ? JSON.parse(body) : {});
      } catch (err) {
        reject(new Error("Invalid JSON"));
      }
    });
    req.on("error", reject);
  });
}

function createServer() {
  const server = http.createServer(async (req, res) => {
    const url = new URL(req.url, `http://${req.headers.host}`);

    // Get client IP for rate limiting
    const clientIp = req.headers["x-forwarded-for"]?.split(",")[0]?.trim() ||
                     req.socket.remoteAddress || "unknown";

    // Security headers
    res.setHeader("X-Content-Type-Options", "nosniff");
    res.setHeader("X-Frame-Options", "DENY");
    res.setHeader("X-XSS-Protection", "1; mode=block");
    res.setHeader("Cache-Control", "no-store");

    // CORS headers for local development
    res.setHeader("Access-Control-Allow-Origin", "http://localhost:3000");
    res.setHeader("Access-Control-Allow-Methods", "GET, POST, PUT, OPTIONS");
    res.setHeader("Access-Control-Allow-Headers", "Content-Type, Authorization");

    if (req.method === "OPTIONS") {
      res.writeHead(204);
      res.end();
      return;
    }

    // Rate limiting (skip for health/metrics endpoints)
    if (!["/health", "/ready", "/metrics"].includes(url.pathname)) {
      const rateLimit = checkRateLimit(clientIp);
      res.setHeader("X-RateLimit-Remaining", rateLimit.remaining);

      if (!rateLimit.allowed) {
        res.setHeader("Retry-After", rateLimit.retryAfter);
        res.writeHead(429, { "Content-Type": "application/json" });
        res.end(JSON.stringify({
          error: "Too Many Requests",
          retry_after: rateLimit.retryAfter,
        }));
        return;
      }
    }

    try {
      // Metrics endpoint
      if (url.pathname === "/metrics" && req.method === "GET") {
        res.writeHead(200, { "Content-Type": "text/plain" });
        res.end(formatMetrics());
        return;
      }

      // Health endpoint (enhanced)
      if (url.pathname === "/health" && req.method === "GET") {
        const uptimeSeconds = Math.floor((Date.now() - startTime) / 1000);
        const health = {
          status: "healthy",
          version: SERVICE_VERSION,
          mode: config.mode,
          uptime_seconds: uptimeSeconds,
          checks: {
            data_dir: true,
            metrics: config.metricsEnabled,
          },
          responder: {
            enabled: config.responderEnabled,
            status: config.responderEnabled ? "ACTIVE" : "DISABLED",
          },
          timestamp: new Date().toISOString(),
        };
        res.writeHead(200, { "Content-Type": "application/json" });
        res.end(JSON.stringify(health));
        return;
      }

      // Readiness endpoint
      if (url.pathname === "/ready" && req.method === "GET") {
        res.writeHead(200, { "Content-Type": "application/json" });
        res.end(JSON.stringify({ ready: true }));
        return;
      }

      // Version endpoint
      if (url.pathname === "/version" && req.method === "GET") {
        res.writeHead(200, { "Content-Type": "application/json" });
        res.end(JSON.stringify({
          service: "wazuh-openclaw-autopilot",
          version: SERVICE_VERSION,
          node: process.version,
        }));
        return;
      }

      // Cases API - GET all
      if (url.pathname === "/api/cases" && req.method === "GET") {
        const cases = await listCases({ limit: 100 });
        res.writeHead(200, { "Content-Type": "application/json" });
        res.end(JSON.stringify(cases));
        return;
      }

      // Cases API - POST create
      if (url.pathname === "/api/cases" && req.method === "POST") {
        // Require authorization for write operations
        const authResult = validateAuthorization(req, "write");
        if (!authResult.valid) {
          res.writeHead(401, { "Content-Type": "application/json" });
          res.end(JSON.stringify({ error: authResult.reason }));
          return;
        }

        const body = await parseJsonBody(req);

        if (!body.case_id || !isValidCaseId(body.case_id)) {
          res.writeHead(400, { "Content-Type": "application/json" });
          res.end(JSON.stringify({ error: "Invalid or missing case_id" }));
          return;
        }

        const newCase = await createCase(body.case_id, body);
        res.writeHead(201, { "Content-Type": "application/json" });
        res.end(JSON.stringify(newCase));
        return;
      }

      // Cases API - GET single
      if (url.pathname.startsWith("/api/cases/") && req.method === "GET") {
        const caseId = url.pathname.split("/")[3];

        // Input validation
        if (!caseId || !isValidCaseId(caseId)) {
          res.writeHead(400, { "Content-Type": "application/json" });
          res.end(JSON.stringify({ error: "Invalid case ID format" }));
          return;
        }

        try {
          const caseData = await getCase(caseId);
          res.writeHead(200, { "Content-Type": "application/json" });
          res.end(JSON.stringify(caseData));
        } catch (err) {
          res.writeHead(404, { "Content-Type": "application/json" });
          res.end(JSON.stringify({ error: "Case not found" }));
        }
        return;
      }

      // Cases API - PUT update
      if (url.pathname.startsWith("/api/cases/") && req.method === "PUT") {
        // Require authorization for write operations
        const authResult = validateAuthorization(req, "write");
        if (!authResult.valid) {
          res.writeHead(401, { "Content-Type": "application/json" });
          res.end(JSON.stringify({ error: authResult.reason }));
          return;
        }

        const caseId = url.pathname.split("/")[3];

        if (!caseId || !isValidCaseId(caseId)) {
          res.writeHead(400, { "Content-Type": "application/json" });
          res.end(JSON.stringify({ error: "Invalid case ID format" }));
          return;
        }

        try {
          const body = await parseJsonBody(req);
          const updatedCase = await updateCase(caseId, body);
          res.writeHead(200, { "Content-Type": "application/json" });
          res.end(JSON.stringify(updatedCase));
        } catch (err) {
          if (err.message.includes("not found")) {
            res.writeHead(404, { "Content-Type": "application/json" });
            res.end(JSON.stringify({ error: "Case not found" }));
          } else {
            throw err;
          }
        }
        return;
      }

      // =================================================================
      // ALERT INGESTION ENDPOINT - Core autonomous triage
      // =================================================================
      if (url.pathname === "/api/alerts" && req.method === "POST") {
        const triageStart = Date.now();

        // Require authorization for alert ingestion
        const authResult = validateAuthorization(req, "write");
        if (!authResult.valid) {
          res.writeHead(401, { "Content-Type": "application/json" });
          res.end(JSON.stringify({ error: authResult.reason }));
          return;
        }

        const alert = await parseJsonBody(req);

        // Validate alert has minimum required fields
        if (!alert.alert_id && !alert._id && !alert.id) {
          res.writeHead(400, { "Content-Type": "application/json" });
          res.end(JSON.stringify({ error: "Alert must have alert_id, _id, or id field" }));
          return;
        }

        // Generate case ID from alert
        const alertId = alert.alert_id || alert._id || alert.id;
        const timestamp = new Date().toISOString().split('T')[0].replace(/-/g, '');
        const caseId = `CASE-${timestamp}-${alertId.toString().substring(0, 8)}`;

        // Extract entities from alert (basic triage)
        const entities = [];

        // Extract IPs
        const ipFields = ['srcip', 'dstip', 'src_ip', 'dst_ip'];
        for (const field of ipFields) {
          const ip = alert.data?.[field] || alert[field];
          if (ip && /^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$/.test(ip)) {
            entities.push({
              type: 'ip',
              value: ip,
              role: field.includes('src') ? 'source' : 'destination',
              extracted_from: `data.${field}`,
            });
          }
        }

        // Extract users
        const userFields = ['srcuser', 'dstuser', 'user'];
        for (const field of userFields) {
          const user = alert.data?.[field] || alert[field];
          if (user && typeof user === 'string' && user.length > 0) {
            entities.push({
              type: 'user',
              value: user,
              role: field === 'srcuser' ? 'actor' : 'target',
              extracted_from: `data.${field}`,
            });
          }
        }

        // Extract host/agent info
        if (alert.agent?.name) {
          entities.push({
            type: 'host',
            value: alert.agent.name,
            role: 'victim',
            agent_id: alert.agent.id,
            agent_ip: alert.agent.ip,
          });
        }

        // Determine severity from rule level
        let severity = 'medium';
        const ruleLevel = alert.rule?.level || alert.level || 0;
        if (ruleLevel >= 13) severity = 'critical';
        else if (ruleLevel >= 10) severity = 'high';
        else if (ruleLevel >= 7) severity = 'medium';
        else if (ruleLevel >= 4) severity = 'low';
        else severity = 'informational';

        // Build timeline entry
        const timeline = [{
          timestamp: alert.timestamp || new Date().toISOString(),
          event_type: 'alert_received',
          description: alert.rule?.description || 'Alert received',
          source: 'wazuh',
          raw_data: {
            rule_id: alert.rule?.id,
            rule_level: ruleLevel,
            agent_id: alert.agent?.id,
          },
        }];

        // Extract MITRE ATT&CK mappings
        const mitre = [];
        if (alert.rule?.mitre) {
          const mitreData = alert.rule.mitre;
          if (Array.isArray(mitreData.id)) {
            for (let i = 0; i < mitreData.id.length; i++) {
              mitre.push({
                technique_id: mitreData.id[i],
                tactic: mitreData.tactic?.[i] || 'unknown',
                technique: mitreData.technique?.[i] || 'unknown',
              });
            }
          } else if (mitreData.id) {
            mitre.push({
              technique_id: mitreData.id,
              tactic: mitreData.tactic || 'unknown',
              technique: mitreData.technique || 'unknown',
            });
          }
        }

        // Create the case with triage data
        const caseData = {
          title: `[${severity.toUpperCase()}] ${alert.rule?.description || 'Security Alert'} on ${alert.agent?.name || 'Unknown Host'}`,
          summary: `Automated triage of Wazuh alert. Rule: ${alert.rule?.id || 'N/A'}, Level: ${ruleLevel}, Agent: ${alert.agent?.name || 'N/A'}`,
          severity,
          confidence: ruleLevel >= 10 ? 0.8 : ruleLevel >= 7 ? 0.6 : 0.4,
          entities,
          timeline,
          mitre,
          evidence_refs: [{
            type: 'wazuh_alert',
            ref_id: alertId,
            timestamp: alert.timestamp || new Date().toISOString(),
          }],
        };

        // Check if case already exists (idempotency)
        let existingCase = null;
        try {
          existingCase = await getCase(caseId);
        } catch (e) {
          // Case doesn't exist, which is expected
        }

        let result;
        if (existingCase) {
          // Update existing case with new evidence
          result = await updateCase(caseId, {
            entities: caseData.entities,
            timeline: caseData.timeline,
            evidence_refs: caseData.evidence_refs,
          });
          log("info", "triage", "Updated existing case with new alert", { case_id: caseId, alert_id: alertId });
        } else {
          // Create new case
          result = await createCase(caseId, caseData);
          log("info", "triage", "Created new case from alert", { case_id: caseId, alert_id: alertId, severity });
        }

        // Record metrics
        incrementMetric("alerts_ingested_total");
        const triageLatency = (Date.now() - triageStart) / 1000;
        recordLatency("triage_latency_seconds", triageLatency);

        res.writeHead(existingCase ? 200 : 201, { "Content-Type": "application/json" });
        res.end(JSON.stringify({
          case_id: caseId,
          status: existingCase ? 'updated' : 'created',
          severity,
          entities_extracted: entities.length,
          mitre_mappings: mitre.length,
          triage_latency_ms: Math.round(triageLatency * 1000),
        }));
        return;
      }

      // =================================================================
      // RESPONDER STATUS ENDPOINT
      // =================================================================
      if (url.pathname === "/api/responder/status" && req.method === "GET") {
        const status = getResponderStatus();
        res.writeHead(200, { "Content-Type": "application/json" });
        res.end(JSON.stringify(status));
        return;
      }

      // =================================================================
      // RESPONSE PLANS API - Two-Tier Human-in-the-Loop
      // =================================================================

      // List plans
      if (url.pathname === "/api/plans" && req.method === "GET") {
        const state = url.searchParams.get("state");
        const case_id = url.searchParams.get("case_id");
        const plans = listPlans({ state, case_id });
        res.writeHead(200, { "Content-Type": "application/json" });
        res.end(JSON.stringify(plans));
        return;
      }

      // Create plan (Response Planner agent creates plans)
      if (url.pathname === "/api/plans" && req.method === "POST") {
        const authResult = validateAuthorization(req, "write");
        if (!authResult.valid) {
          res.writeHead(401, { "Content-Type": "application/json" });
          res.end(JSON.stringify({ error: authResult.reason }));
          return;
        }

        const body = await parseJsonBody(req);

        if (!body.case_id) {
          res.writeHead(400, { "Content-Type": "application/json" });
          res.end(JSON.stringify({ error: "case_id is required" }));
          return;
        }

        if (!body.actions || !Array.isArray(body.actions) || body.actions.length === 0) {
          res.writeHead(400, { "Content-Type": "application/json" });
          res.end(JSON.stringify({ error: "actions array is required and must not be empty" }));
          return;
        }

        try {
          const plan = createResponsePlan(body);

          // Also update the case with the proposed plan
          try {
            await updateCase(body.case_id, {
              plans: [{
                plan_id: plan.plan_id,
                state: plan.state,
                created_at: plan.created_at,
                title: plan.title,
                risk_level: plan.risk_level,
                actions_count: plan.actions.length,
              }],
            });
          } catch (err) {
            log("warn", "plans", "Failed to update case with plan", {
              plan_id: plan.plan_id,
              case_id: body.case_id,
              error: err.message,
            });
          }

          res.writeHead(201, { "Content-Type": "application/json" });
          res.end(JSON.stringify({
            ...plan,
            message: "Plan created in PROPOSED state. Requires Tier 1 approval before execution.",
            next_step: "POST /api/plans/" + plan.plan_id + "/approve",
          }));
        } catch (err) {
          res.writeHead(400, { "Content-Type": "application/json" });
          res.end(JSON.stringify({ error: err.message }));
        }
        return;
      }

      // Get single plan
      if (url.pathname.match(/^\/api\/plans\/[^/]+$/) && req.method === "GET") {
        const planId = url.pathname.split("/")[3];
        try {
          const plan = getPlan(planId);
          res.writeHead(200, { "Content-Type": "application/json" });
          res.end(JSON.stringify(plan));
        } catch (err) {
          res.writeHead(404, { "Content-Type": "application/json" });
          res.end(JSON.stringify({ error: err.message }));
        }
        return;
      }

      // TIER 1: Approve plan
      if (url.pathname.match(/^\/api\/plans\/[^/]+\/approve$/) && req.method === "POST") {
        const authResult = validateAuthorization(req, "write");
        if (!authResult.valid) {
          res.writeHead(401, { "Content-Type": "application/json" });
          res.end(JSON.stringify({ error: authResult.reason }));
          return;
        }

        const planId = url.pathname.split("/")[3];
        const body = await parseJsonBody(req);

        if (!body.approver_id) {
          res.writeHead(400, { "Content-Type": "application/json" });
          res.end(JSON.stringify({ error: "approver_id is required" }));
          return;
        }

        try {
          const plan = approvePlan(planId, body.approver_id, body.reason || "");
          res.writeHead(200, { "Content-Type": "application/json" });
          res.end(JSON.stringify({
            ...plan,
            message: "Plan APPROVED (Tier 1 complete). Ready for execution.",
            next_step: "POST /api/plans/" + planId + "/execute",
            responder_status: getResponderStatus(),
          }));
        } catch (err) {
          const statusCode = err.message.includes("not found") ? 404 : 400;
          res.writeHead(statusCode, { "Content-Type": "application/json" });
          res.end(JSON.stringify({ error: err.message }));
        }
        return;
      }

      // Reject plan
      if (url.pathname.match(/^\/api\/plans\/[^/]+\/reject$/) && req.method === "POST") {
        const authResult = validateAuthorization(req, "write");
        if (!authResult.valid) {
          res.writeHead(401, { "Content-Type": "application/json" });
          res.end(JSON.stringify({ error: authResult.reason }));
          return;
        }

        const planId = url.pathname.split("/")[3];
        const body = await parseJsonBody(req);

        if (!body.rejector_id) {
          res.writeHead(400, { "Content-Type": "application/json" });
          res.end(JSON.stringify({ error: "rejector_id is required" }));
          return;
        }

        try {
          const plan = rejectPlan(planId, body.rejector_id, body.reason || "");
          res.writeHead(200, { "Content-Type": "application/json" });
          res.end(JSON.stringify({
            ...plan,
            message: "Plan REJECTED. No actions will be executed.",
          }));
        } catch (err) {
          const statusCode = err.message.includes("not found") ? 404 : 400;
          res.writeHead(statusCode, { "Content-Type": "application/json" });
          res.end(JSON.stringify({ error: err.message }));
        }
        return;
      }

      // TIER 2: Execute plan
      if (url.pathname.match(/^\/api\/plans\/[^/]+\/execute$/) && req.method === "POST") {
        const authResult = validateAuthorization(req, "write");
        if (!authResult.valid) {
          res.writeHead(401, { "Content-Type": "application/json" });
          res.end(JSON.stringify({ error: authResult.reason }));
          return;
        }

        const planId = url.pathname.split("/")[3];
        const body = await parseJsonBody(req);

        if (!body.executor_id) {
          res.writeHead(400, { "Content-Type": "application/json" });
          res.end(JSON.stringify({ error: "executor_id is required" }));
          return;
        }

        try {
          const plan = await executePlan(planId, body.executor_id);
          const statusCode = plan.state === PLAN_STATES.COMPLETED ? 200 : 200;
          res.writeHead(statusCode, { "Content-Type": "application/json" });
          res.end(JSON.stringify({
            ...plan,
            message: plan.state === PLAN_STATES.COMPLETED
              ? "Plan EXECUTED successfully. All actions completed."
              : "Plan execution completed with some failures.",
          }));
        } catch (err) {
          // Check if this is a responder disabled error
          if (err.message.includes("Responder is DISABLED")) {
            res.writeHead(403, { "Content-Type": "application/json" });
            res.end(JSON.stringify({
              error: err.message,
              responder_status: getResponderStatus(),
              resolution: "Contact an administrator to enable AUTOPILOT_RESPONDER_ENABLED=true",
            }));
            return;
          }

          const statusCode = err.message.includes("not found") ? 404 : 400;
          res.writeHead(statusCode, { "Content-Type": "application/json" });
          res.end(JSON.stringify({ error: err.message }));
        }
        return;
      }

      // 404 for unknown routes
      res.writeHead(404, { "Content-Type": "application/json" });
      res.end(JSON.stringify({ error: "Not found" }));
    } catch (err) {
      log("error", "http", "Request error", { error: err.message });
      res.writeHead(500, { "Content-Type": "application/json" });
      res.end(JSON.stringify({ error: "Internal server error" }));
    }
  });

  return server;
}

// =============================================================================
// STARTUP
// =============================================================================

// Validate that critical configuration doesn't contain placeholder values
function validateNoPlaceholders(configObj, path = "") {
  const PLACEHOLDER_PATTERNS = [
    /^YOUR_/i,
    /^PLACEHOLDER_/i,
    /_ID$/i,
    /^TODO:/i,
    /^CHANGE_ME$/i,
    /^EXAMPLE_/i,
  ];

  const warnings = [];

  function check(obj, currentPath) {
    if (typeof obj === "string") {
      for (const pattern of PLACEHOLDER_PATTERNS) {
        if (pattern.test(obj) && obj.includes("_ID")) {
          warnings.push({ path: currentPath, value: obj });
        }
      }
      // Also check for specific placeholder patterns
      if (obj === "YOUR_WORKSPACE_ID" || obj.match(/^(USER_ID|ADMIN_USER_ID|MANAGER_USER_ID|SENIOR_USER_ID)/)) {
        warnings.push({ path: currentPath, value: obj });
      }
    } else if (typeof obj === "object" && obj !== null) {
      for (const [key, value] of Object.entries(obj)) {
        check(value, currentPath ? `${currentPath}.${key}` : key);
      }
    }
  }

  check(configObj, path);
  return warnings;
}

async function validateStartup() {
  log("info", "startup", "Validating configuration...");

  // Check mode
  if (config.mode === "production") {
    // Check Tailscale requirement
    if (config.requireTailscale) {
      // In a real implementation, we'd check if Tailscale is running
      // For now, just check if MCP_URL looks like a Tailnet URL
      if (config.mcpUrl && !config.mcpUrl.includes(".ts.net") && !config.mcpUrl.match(/^https?:\/\/100\./)) {
        log("error", "startup", "Production mode requires Tailnet MCP URL");
        process.exit(1);
      }
    }
  }

  // Ensure data directories exist
  await ensureDir(path.join(config.dataDir, "cases"));
  await ensureDir(path.join(config.dataDir, "reports"));
  await ensureDir(path.join(config.dataDir, "state"));

  // Load and validate policy configuration
  const policyPath = path.join(config.configDir, "policies", "policy.yaml");
  try {
    await fs.access(policyPath);
    const policyContent = await fs.readFile(policyPath, "utf8");

    // Simple placeholder check (in production, parse YAML properly)
    const placeholderMatches = policyContent.match(/(<SLACK_[A-Z_]+>|YOUR_|USER_ID_|ADMIN_USER_ID|_CHANNEL_ID)/g);
    if (placeholderMatches && placeholderMatches.length > 0) {
      log("warn", "startup", "Policy contains placeholder values - configure before production use", {
        placeholders_found: placeholderMatches.length,
        examples: [...new Set(placeholderMatches)].slice(0, 5),
      });

      // In production mode, fail startup if placeholders exist
      if (config.mode === "production") {
        log("error", "startup", "Production mode cannot use placeholder values in policy");
        process.exit(1);
      }
    }
  } catch (err) {
    log("warn", "startup", "Could not validate policy file", { path: policyPath, error: err.message });
  }

  // Load toolmap
  await loadToolmap();

  log("info", "startup", "Configuration validated", { mode: config.mode });
}

async function main() {
  console.log("");
  console.log("╔═══════════════════════════════════════════════════════════╗");
  console.log("║           Wazuh Autopilot Runtime Service                 ║");
  console.log("╚═══════════════════════════════════════════════════════════╝");
  console.log("");

  // Clear responder status
  if (config.responderEnabled) {
    console.log("┌─────────────────────────────────────────────────────────────┐");
    console.log("│  RESPONDER CAPABILITY: ENABLED                              │");
    console.log("│                                                             │");
    console.log("│  Humans CAN execute approved response plans.                │");
    console.log("│  Two-tier approval ALWAYS required: Approve → Execute       │");
    console.log("│  AI agents CANNOT execute actions autonomously.             │");
    console.log("└─────────────────────────────────────────────────────────────┘");
  } else {
    console.log("┌─────────────────────────────────────────────────────────────┐");
    console.log("│  RESPONDER CAPABILITY: DISABLED (Default)                   │");
    console.log("│                                                             │");
    console.log("│  Execution is blocked even after human approval.            │");
    console.log("│  Set AUTOPILOT_RESPONDER_ENABLED=true to enable.            │");
    console.log("│  Human approval will still be required for every action.    │");
    console.log("└─────────────────────────────────────────────────────────────┘");
  }
  console.log("");

  await validateStartup();

  // Setup cleanup intervals for memory management
  setupCleanupIntervals();

  if (config.metricsEnabled) {
    server = createServer();
    server.listen(config.metricsPort, config.metricsHost, () => {
      log("info", "startup", `Server listening`, {
        host: config.metricsHost,
        port: config.metricsPort,
      });
      log("info", "startup", `Metrics available at http://${config.metricsHost}:${config.metricsPort}/metrics`);
    });
  }

  // Initialize Slack integration (optional)
  if (slack) {
    const runtimeExports = module.exports;
    await slack.initSlack(runtimeExports);
    if (slack.isInitialized()) {
      log("info", "startup", "Slack integration active");
    }
  }

  log("info", "startup", "Wazuh Autopilot started", { mode: config.mode });
}

// Export for testing
module.exports = {
  // Case management
  createCase,
  updateCase,
  getCase,
  listCases,
  // Legacy approval tokens
  generateApprovalToken,
  validateApprovalToken,
  consumeApprovalToken,
  // Two-tier approval (Response Plans)
  createResponsePlan,
  getPlan,
  listPlans,
  approvePlan,
  rejectPlan,
  executePlan,
  getResponderStatus,
  PLAN_STATES,
  // MCP
  callMcpTool,
  loadToolmap,
  resolveMcpTool,
  isToolEnabled,
  // Metrics
  incrementMetric,
  recordLatency,
};

// Graceful shutdown handling
let server = null;
const cleanupIntervals = [];

function setupCleanupIntervals() {
  // Approval token cleanup
  const tokenCleanup = setInterval(() => {
    const now = Date.now();
    let removed = 0;
    for (const [token, data] of approvalTokens.entries()) {
      if (new Date(data.expires_at) < new Date(now)) {
        approvalTokens.delete(token);
        removed++;
      }
    }
    if (removed > 0) {
      log("debug", "cleanup", "Expired approval tokens removed", { count: removed });
    }
  }, 60000);
  cleanupIntervals.push(tokenCleanup);

  // Rate limit state cleanup
  const rateLimitCleanup = setInterval(() => {
    const now = Date.now();
    let removed = 0;
    for (const [ip, data] of rateLimitState.requests.entries()) {
      if (now > data.resetTime) {
        rateLimitState.requests.delete(ip);
        removed++;
      }
    }
    if (removed > 0) {
      log("debug", "cleanup", "Expired rate limit entries removed", { count: removed });
    }
  }, 60000);
  cleanupIntervals.push(rateLimitCleanup);

  // Response plans cleanup (expire old proposed/approved plans)
  const plansCleanup = setInterval(() => {
    const now = new Date();
    let expired = 0;
    for (const [planId, plan] of responsePlans.entries()) {
      if (
        (plan.state === PLAN_STATES.PROPOSED || plan.state === PLAN_STATES.APPROVED) &&
        new Date(plan.expires_at) < now
      ) {
        plan.state = PLAN_STATES.EXPIRED;
        plan.updated_at = now.toISOString();
        expired++;
        incrementMetric("plans_expired_total");
      }
    }
    if (expired > 0) {
      log("info", "cleanup", "Plans expired", { count: expired });
    }

    // Also clean up very old completed/failed plans (older than 7 days)
    const cutoff = Date.now() - 7 * 24 * 60 * 60 * 1000;
    let removed = 0;
    for (const [planId, plan] of responsePlans.entries()) {
      if (
        ["completed", "failed", "rejected", "expired"].includes(plan.state) &&
        new Date(plan.updated_at) < new Date(cutoff)
      ) {
        responsePlans.delete(planId);
        removed++;
      }
    }
    if (removed > 0) {
      log("debug", "cleanup", "Old plans removed", { count: removed });
    }
  }, 60000);
  cleanupIntervals.push(plansCleanup);
}

function gracefulShutdown(signal) {
  log("info", "shutdown", `Received ${signal}, shutting down gracefully...`);

  // Stop accepting new requests
  if (server) {
    server.close(() => {
      log("info", "shutdown", "HTTP server closed");
    });
  }

  // Clear all cleanup intervals
  for (const interval of cleanupIntervals) {
    clearInterval(interval);
  }

  // Allow pending operations to complete
  setTimeout(() => {
    log("info", "shutdown", "Shutdown complete");
    process.exit(0);
  }, 1000);
}

process.on("SIGTERM", () => gracefulShutdown("SIGTERM"));
process.on("SIGINT", () => gracefulShutdown("SIGINT"));

// Run if executed directly
if (require.main === module) {
  main().catch((err) => {
    log("error", "startup", "Failed to start", { error: err.message });
    process.exit(1);
  });
}
