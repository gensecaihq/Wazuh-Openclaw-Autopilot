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
  if (err.code === "MODULE_NOT_FOUND" && err.message.includes("@slack/bolt")) {
    // Slack dependencies not installed -- optional integration disabled
  } else {
    console.error(`[WARN] Slack module failed to load: ${err.message}`);
  }
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
  metricsPort: parseInt(process.env.RUNTIME_PORT || process.env.METRICS_PORT || "9090", 10),
  metricsHost: process.env.METRICS_HOST || "127.0.0.1",
  logFormat: process.env.LOG_FORMAT || "json",
  logLevel: process.env.LOG_LEVEL || "info",
  approvalTtlMinutes: parseInt(
    process.env.APPROVAL_TOKEN_TTL_MINUTES || "60",
    10,
  ),
  // Rate limiting
  rateLimitWindowMs: parseInt(process.env.RATE_LIMIT_WINDOW_MS || "60000", 10),
  rateLimitMaxRequests: parseInt(process.env.RATE_LIMIT_MAX_REQUESTS || "100", 10),
  // Auth failure rate limiting (Issue #3 fix)
  authFailureWindowMs: parseInt(process.env.AUTH_FAILURE_WINDOW_MS || "900000", 10), // 15 minutes
  authFailureMaxAttempts: parseInt(process.env.AUTH_FAILURE_MAX_ATTEMPTS || "5", 10),
  authLockoutDurationMs: parseInt(process.env.AUTH_LOCKOUT_DURATION_MS || "1800000", 10), // 30 minutes
  // MCP timeout
  mcpTimeoutMs: parseInt(process.env.MCP_TIMEOUT_MS || "30000", 10),
  // Responder capability toggle - DISABLED by default
  // When enabled, humans can execute approved plans via the two-tier approval workflow
  // This does NOT enable autonomous execution - human approval is ALWAYS required
  responderEnabled: process.env.AUTOPILOT_RESPONDER_ENABLED === "true",
  // Plan expiry
  planExpiryMinutes: parseInt(process.env.PLAN_EXPIRY_MINUTES || "60", 10),
  // CORS configuration (Issue #7 fix)
  corsOrigin: process.env.CORS_ORIGIN || "http://localhost:3000",
  corsEnabled: process.env.CORS_ENABLED !== "false",
  // Graceful shutdown timeout (Issue #12 fix)
  shutdownTimeoutMs: parseInt(process.env.SHUTDOWN_TIMEOUT_MS || "30000", 10),
};

// =============================================================================
// LOGGING
// =============================================================================

const LOG_LEVELS = { debug: 0, info: 1, warn: 2, error: 3 };
const currentLogLevel = LOG_LEVELS[config.logLevel] || 1;

function log(level, component, msg, extra = {}) {
  const levelValue = LOG_LEVELS[level];
  // Skip if invalid level or below current threshold (Bug #12 fix)
  if (levelValue === undefined || levelValue < currentLogLevel) return;

  const entry = {
    ...extra,
    ts: new Date().toISOString(),
    level,
    component,
    msg,
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
  triage_latency_seconds: {}, // Object with keys mapping to arrays (Bug #8 fix)
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

function sanitizeMetricLabelName(name) {
  return String(name).replace(/[^a-zA-Z0-9_]/g, "_");
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
        .map(([k, v]) => `${sanitizeMetricLabelName(k)}="${String(v).replace(/[\\"]/g, "\\$&").replace(/\n/g, "\\n")}"`)
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
          .map(([k, v]) => `${sanitizeMetricLabelName(k)}="${v}"`)
          .join(",");
        labelStr = `{${labelStr}}`;
      }
      lines.push(`autopilot_${name}_sum${labelStr} ${sum.toFixed(6)}`);
      lines.push(`autopilot_${name}_count${labelStr} ${count}`);
    });
  });

  // Gauges
  lines.push("# TYPE autopilot_plans_executing gauge");
  lines.push(`autopilot_plans_executing ${executingPlans.size}`);

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
    JSON.stringify(evidencePack, null, 2),
  );

  // Also create a lightweight summary (Bug #10 fix: add defaults)
  const caseSummary = {
    case_id: caseId,
    created_at: now,
    updated_at: now,
    title: data.title || "",
    severity: data.severity || "medium",
    status: "open",
  };

  await fs.writeFile(
    path.join(caseDir, "case.json"),
    JSON.stringify(caseSummary, null, 2),
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

  // Bug #14 fix: Use hasOwnProperty to allow falsy values (0, "", etc.)
  if (Object.prototype.hasOwnProperty.call(updates, "title")) evidencePack.title = updates.title;
  if (Object.prototype.hasOwnProperty.call(updates, "summary")) evidencePack.summary = updates.summary;
  if (Object.prototype.hasOwnProperty.call(updates, "severity")) evidencePack.severity = updates.severity;
  if (Object.prototype.hasOwnProperty.call(updates, "confidence")) evidencePack.confidence = updates.confidence;
  // Bug #11 fix: Sync status field to evidence pack
  if (Object.prototype.hasOwnProperty.call(updates, "status")) evidencePack.status = updates.status;

  // Append arrays with size cap to prevent unbounded growth
  const MAX_ARRAY_ITEMS = 10000;
  const appendCapped = (existing, incoming) => {
    const merged = [...existing, ...incoming];
    return merged.length > MAX_ARRAY_ITEMS ? merged.slice(-MAX_ARRAY_ITEMS) : merged;
  };

  if (updates.entities) {
    evidencePack.entities = appendCapped(evidencePack.entities, updates.entities);
  }
  if (updates.timeline) {
    evidencePack.timeline = appendCapped(evidencePack.timeline, updates.timeline);
  }
  if (updates.mcp_calls) {
    evidencePack.mcp_calls = appendCapped(evidencePack.mcp_calls, updates.mcp_calls);
  }
  if (updates.evidence_refs) {
    evidencePack.evidence_refs = appendCapped(evidencePack.evidence_refs, updates.evidence_refs);
  }
  if (updates.plans) {
    evidencePack.plans = appendCapped(evidencePack.plans, updates.plans);
  }
  if (updates.approvals) {
    evidencePack.approvals = appendCapped(evidencePack.approvals, updates.approvals);
  }
  if (updates.actions) {
    evidencePack.actions = appendCapped(evidencePack.actions, updates.actions);
  }

  await fs.writeFile(packPath, JSON.stringify(evidencePack, null, 2));

  // Update summary
  const summaryPath = path.join(caseDir, "case.json");
  try {
    const summaryContent = await fs.readFile(summaryPath, "utf8");
    const summary = JSON.parse(summaryContent);
    summary.updated_at = now;
    if (Object.prototype.hasOwnProperty.call(updates, "title")) summary.title = updates.title;
    if (Object.prototype.hasOwnProperty.call(updates, "severity")) summary.severity = updates.severity;
    if (Object.prototype.hasOwnProperty.call(updates, "status")) summary.status = updates.status;
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
    "evidence-pack.json",
  );
  try {
    const content = await fs.readFile(packPath, "utf8");
    return JSON.parse(content);
  } catch (err) {
    throw new Error(`Case not found: ${caseId}`);
  }
}

// Issue #11 fix: Add offset pagination and default limit
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

  // Issue #13 fix: More efficient date sorting
  cases.sort((a, b) => new Date(b.created_at).getTime() - new Date(a.created_at).getTime());

  // Issue #11 fix: Apply offset and limit with defaults
  const offset = options.offset || 0;
  const limit = options.limit || 100; // Default limit to prevent unbounded responses

  return cases.slice(offset, offset + limit);
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
      if (Date.parse(data.expires_at) < now || data.used) {
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
  // Bug #3 fix: Validate approverId parameter
  if (!approverId || typeof approverId !== "string" || approverId.trim() === "") {
    return { valid: false, reason: "INVALID_APPROVER_ID" };
  }

  const tokenData = approvalTokens.get(token);

  if (!tokenData) {
    return { valid: false, reason: "INVALID_APPROVAL_TOKEN" };
  }

  if (tokenData.used) {
    return { valid: false, reason: "TOKEN_ALREADY_USED" };
  }

  // Issue #13 fix: Use timestamp comparison
  if (new Date(tokenData.expires_at).getTime() < Date.now()) {
    return { valid: false, reason: "EXPIRED_APPROVAL" };
  }

  // Note: Full approver authorization (group membership, etc.) should be
  // validated by the Policy Guard agent before generating the token

  return { valid: true, tokenData, approverId };
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
const MAX_ACTIONS_PER_PLAN = 100;
// Bug #7 fix: Track plans currently being executed to prevent race conditions
const executingPlans = new Set();

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

// Issue #6 fix: Validate action structure
function validatePlanAction(action, index) {
  const errors = [];
  if (!action.type || typeof action.type !== "string") {
    errors.push(`Action ${index}: missing or invalid 'type' field`);
  }
  if (!action.target || typeof action.target !== "string") {
    errors.push(`Action ${index}: missing or invalid 'target' field`);
  }
  return errors;
}

function createResponsePlan(planData) {
  // Enforce max actions per plan to prevent OOM
  if (planData.actions && Array.isArray(planData.actions) && planData.actions.length > MAX_ACTIONS_PER_PLAN) {
    throw new Error(`Too many actions: ${planData.actions.length} exceeds maximum of ${MAX_ACTIONS_PER_PLAN}`);
  }
  // Issue #6 fix: Validate all actions at creation time
  if (planData.actions && Array.isArray(planData.actions)) {
    const validationErrors = [];
    planData.actions.forEach((action, index) => {
      validationErrors.push(...validatePlanAction(action, index));
    });
    if (validationErrors.length > 0) {
      throw new Error(`Invalid actions: ${validationErrors.join("; ")}`);
    }
  }

  // Enforce plan limit
  if (responsePlans.size >= MAX_PLANS) {
    // Clean up old completed/failed/expired plans
    let removed = 0;
    const cutoff = Date.now() - 24 * 60 * 60 * 1000; // 24 hours
    const cutoffTime = new Date(cutoff).getTime(); // Issue #13 fix
    for (const [planId, plan] of responsePlans.entries()) {
      if (
        ["completed", "failed", "rejected", "expired"].includes(plan.state) &&
        new Date(plan.updated_at).getTime() < cutoffTime
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

// Bug #4 fix: Add updateExpiry flag to prevent double metric increment
function getPlan(planId, { updateExpiry = true } = {}) {
  const plan = responsePlans.get(planId);
  if (!plan) {
    throw new Error(`Plan not found: ${planId}`);
  }

  // Check if plan has expired
  // Issue #13 fix: Use timestamp comparison
  if (updateExpiry && (plan.state === PLAN_STATES.PROPOSED || plan.state === PLAN_STATES.APPROVED)) {
    const now = Date.now();
    if (new Date(plan.expires_at).getTime() < now) {
      plan.state = PLAN_STATES.EXPIRED;
      plan.updated_at = new Date(now).toISOString();
      incrementMetric("plans_expired_total");
      log("info", "plans", "Plan expired", { plan_id: planId });
    }
  }

  return plan;
}

// Issue #11 fix: Add offset pagination
function listPlans(options = {}) {
  const plans = [];
  const { state, case_id, limit = 100, offset = 0 } = options;

  for (const plan of responsePlans.values()) {
    // Filter by state
    if (state && plan.state !== state) continue;
    // Filter by case
    if (case_id && plan.case_id !== case_id) continue;

    plans.push(plan);
  }

  // Issue #13 fix: More efficient date sorting
  plans.sort((a, b) => new Date(b.created_at).getTime() - new Date(a.created_at).getTime());

  return plans.slice(offset, offset + limit);
}

// TIER 1: Approve a plan (human clicks "Approve")
function approvePlan(planId, approverId, reason = "") {
  // Bug #4 fix: Don't auto-update expiry in getPlan to avoid double metric
  const plan = getPlan(planId, { updateExpiry: false });

  // Check if expired first
  // Issue #13 fix: Use timestamp comparison
  const now = Date.now();
  if (new Date(plan.expires_at).getTime() < now) {
    plan.state = PLAN_STATES.EXPIRED;
    plan.updated_at = new Date(now).toISOString();
    incrementMetric("plans_expired_total");
    log("info", "plans", "Plan expired", { plan_id: planId });
    throw new Error("Plan has expired");
  }

  // Validate state
  if (plan.state !== PLAN_STATES.PROPOSED) {
    throw new Error(`Cannot approve plan in state: ${plan.state}`);
  }

  const nowIso = new Date(now).toISOString();
  plan.state = PLAN_STATES.APPROVED;
  plan.approver_id = approverId;
  plan.approved_at = nowIso;
  plan.approval_reason = reason;
  plan.updated_at = nowIso;
  // Extend expiry after approval (give time for execution)
  plan.expires_at = new Date(now + config.planExpiryMinutes * 60 * 1000).toISOString();

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
  // Bug #4 fix: Don't auto-update expiry in getPlan
  const plan = getPlan(planId, { updateExpiry: false });

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
      "Note: Human approval (Approve + Execute) will still be required for every action.",
    );
  }

  // Bug #4 fix: Don't auto-update expiry in getPlan
  const plan = getPlan(planId, { updateExpiry: false });

  // Check if expired first
  // Issue #13 fix: Use timestamp comparison
  const nowTs = Date.now();
  if (new Date(plan.expires_at).getTime() < nowTs) {
    plan.state = PLAN_STATES.EXPIRED;
    plan.updated_at = new Date(nowTs).toISOString();
    incrementMetric("plans_expired_total");
    log("info", "plans", "Plan expired", { plan_id: planId });
    throw new Error("Plan has expired - approval is no longer valid");
  }

  // Validate state - must be approved first (Tier 1 complete)
  if (plan.state !== PLAN_STATES.APPROVED) {
    if (plan.state === PLAN_STATES.PROPOSED) {
      throw new Error("Plan must be approved before execution (Tier 1 required)");
    }
    throw new Error(`Cannot execute plan in state: ${plan.state}`);
  }

  // Bug #7 fix: Prevent concurrent execution of the same plan
  if (executingPlans.has(planId)) {
    throw new Error("Plan is already being executed");
  }
  executingPlans.add(planId);

  const now = new Date(nowTs).toISOString();
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

  try {
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
  } finally {
    // Bug #7 fix: Always remove from executing set
    executingPlans.delete(planId);
  }
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
// Bug #5 and #6 fixes: Improved list and multi-colon handling
function parseSimpleYaml(content) {
  const result = {};
  const lines = content.split("\n");
  const stack = [{ indent: -1, obj: result, pendingListKey: null }];

  for (const line of lines) {
    // Skip comments and empty lines
    if (line.trim().startsWith("#") || line.trim() === "") continue;

    const indent = line.search(/\S/);
    if (indent === -1) continue;

    // Pop stack to find parent
    while (stack.length > 1 && stack[stack.length - 1].indent >= indent) {
      stack.pop();
    }

    const current = stack[stack.length - 1];
    const parent = current.obj;
    const trimmed = line.trim();

    // Handle list items
    if (trimmed.startsWith("- ")) {
      const value = trimmed.substring(2).trim();
      // Bug #5 fix: Use pendingListKey to track which key should receive list items
      const listKey = current.pendingListKey;
      if (listKey) {
        // Ensure array exists
        if (!Array.isArray(parent[listKey])) {
          parent[listKey] = [];
        }
        // Bug #6 fix: Use indexOf to split on first colon only
        const colonIdx = value.indexOf(":");
        if (colonIdx > 0) {
          const obj = {};
          const k = value.substring(0, colonIdx).trim();
          const v = value.substring(colonIdx + 1).trim().replace(/^["']|["']$/g, "");
          obj[k] = v;
          parent[listKey].push(obj);
        } else {
          parent[listKey].push(value.replace(/^["']|["']$/g, ""));
        }
      }
      continue;
    }

    // Handle key: value pairs
    const colonIndex = trimmed.indexOf(":");
    if (colonIndex > 0) {
      const key = trimmed.substring(0, colonIndex).trim();
      // Bug #6 fix: Get everything after first colon
      let value = trimmed.substring(colonIndex + 1).trim();

      if (value === "" || value === "|" || value === ">") {
        // Nested object or list - set as pending list key
        parent[key] = {};
        stack.push({ indent, obj: parent[key], pendingListKey: null });
        // Mark current level as expecting list items for this key
        current.pendingListKey = key;
      } else {
        // Parse value
        if (value === "true") value = true;
        else if (value === "false") value = false;
        else if (value === "null") value = null;
        else if (/^\d+$/.test(value)) value = parseInt(value, 10);
        else if (/^\d+\.\d+$/.test(value)) value = parseFloat(value);
        else value = value.replace(/^["']|["']$/g, "");

        parent[key] = value;
        // Clear pending list key — scalar value assigned, not expecting list items
        current.pendingListKey = null;
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
    if (typeof tool === "object" && tool.mcp_tool) {
      return tool.mcp_tool;
    }
  }

  // Check action operations
  if (toolmapConfig.action_operations && toolmapConfig.action_operations[logicalName]) {
    const tool = toolmapConfig.action_operations[logicalName];
    if (typeof tool === "object" && tool.mcp_tool) {
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
    return typeof tool === "object" ? tool.enabled !== false : true;
  }

  // Check action operations (default disabled)
  if (toolmapConfig.action_operations && toolmapConfig.action_operations[logicalName]) {
    const tool = toolmapConfig.action_operations[logicalName];
    return typeof tool === "object" ? tool.enabled === true : false;
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
        "Content-Type": JSON_CONTENT_TYPE,
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

    let responseData;
    const contentType = response.headers.get("content-type") || "";
    if (contentType.includes("application/json")) {
      responseData = await response.json();
    } else {
      const text = await response.text();
      responseData = { raw_response: text.substring(0, 1000), content_type: contentType };
    }
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
// AUTH FAILURE RATE LIMITING (Issue #3 fix)
// =============================================================================

const authFailureState = {
  attempts: new Map(), // IP -> { count, firstAttempt, lockedUntil }
};

function recordAuthFailure(clientIp) {
  const now = Date.now();
  const data = authFailureState.attempts.get(clientIp);

  if (!data || now > data.firstAttempt + config.authFailureWindowMs) {
    // Start new window
    authFailureState.attempts.set(clientIp, {
      count: 1,
      firstAttempt: now,
      lockedUntil: null,
    });
    return { locked: false };
  }

  data.count++;

  // Check if should lock
  if (data.count >= config.authFailureMaxAttempts) {
    data.lockedUntil = now + config.authLockoutDurationMs;
    log("warn", "auth", "Auth lockout triggered", {
      client_ip: clientIp,
      attempts: data.count,
      locked_until: new Date(data.lockedUntil).toISOString(),
    });
    return { locked: true, retryAfter: Math.ceil(config.authLockoutDurationMs / 1000) };
  }

  return { locked: false, attemptsRemaining: config.authFailureMaxAttempts - data.count };
}

function isAuthLocked(clientIp) {
  const data = authFailureState.attempts.get(clientIp);
  if (!data || !data.lockedUntil) return { locked: false };

  const now = Date.now();
  if (now >= data.lockedUntil) {
    // Lockout expired, reset
    authFailureState.attempts.delete(clientIp);
    return { locked: false };
  }

  return {
    locked: true,
    retryAfter: Math.ceil((data.lockedUntil - now) / 1000),
  };
}

function clearAuthFailures(clientIp) {
  authFailureState.attempts.delete(clientIp);
}

// =============================================================================
// SECURE HELPERS (Issue #1 fix - timing-safe comparison)
// =============================================================================

/**
 * Timing-safe string comparison to prevent timing attacks
 */
function secureCompare(a, b) {
  if (typeof a !== "string" || typeof b !== "string") {
    return false;
  }

  // Hash both values to fixed-length buffers before comparing.
  // This prevents length-based timing leaks — both hashes are always 32 bytes
  // regardless of input length, and timingSafeEqual runs in constant time.
  const aHash = crypto.createHash("sha256").update(a).digest();
  const bHash = crypto.createHash("sha256").update(b).digest();

  return crypto.timingSafeEqual(aHash, bHash);
}

// =============================================================================
// REQUEST ID GENERATION (Issue #15 fix)
// =============================================================================

function generateRequestId() {
  return `req-${Date.now()}-${crypto.randomBytes(4).toString("hex")}`;
}

// =============================================================================
// HTTP SERVER
// =============================================================================

const SERVICE_VERSION = "2.2.0";
const JSON_CONTENT_TYPE = "application/json; charset=utf-8";
const startTime = Date.now();

// Auth error response helper
function sendAuthError(res, authResult, requestId) {
  if (authResult.locked) {
    res.setHeader("Retry-After", authResult.retryAfter);
    res.writeHead(429, { "Content-Type": JSON_CONTENT_TYPE });
    res.end(JSON.stringify({ error: authResult.reason, retry_after: authResult.retryAfter, request_id: requestId }));
  } else {
    res.writeHead(401, { "Content-Type": JSON_CONTENT_TYPE });
    res.end(JSON.stringify({ error: authResult.reason, request_id: requestId }));
  }
}

// Standard JSON error response helper (consistent format with request_id)
function sendJsonError(res, statusCode, error, requestId) {
  res.writeHead(statusCode, { "Content-Type": JSON_CONTENT_TYPE });
  res.end(JSON.stringify({ error, request_id: requestId }));
}

// Input validation
function isValidCaseId(caseId) {
  // Case IDs must be alphanumeric with hyphens, 1-64 chars
  return /^[a-zA-Z0-9-]{1,64}$/.test(caseId);
}

// Authorization validation for sensitive endpoints
// Issue #1 fix: Uses timing-safe comparison
// Issue #3 fix: Includes auth failure rate limiting
function validateAuthorization(req, requiredScope = "write") {
  const authHeader = req.headers.authorization;

  // Get client IP for auth failure tracking
  // Only trust X-Forwarded-For from loopback connections (behind a local reverse proxy)
  const directIp = req.socket.remoteAddress || "unknown";
  const isDirectLocalhost = directIp === "127.0.0.1" || directIp === "::1" ||
                            directIp === "::ffff:127.0.0.1";
  const clientIp = (isDirectLocalhost && req.headers["x-forwarded-for"])
    ? req.headers["x-forwarded-for"].split(",")[0].trim()
    : directIp;
  const isLocalhost = clientIp === "127.0.0.1" || clientIp === "::1" ||
                      clientIp === "::ffff:127.0.0.1";

  // Check if client is locked out due to too many auth failures
  const lockStatus = isAuthLocked(clientIp);
  if (lockStatus.locked) {
    return {
      valid: false,
      reason: "Too many authentication failures",
      retryAfter: lockStatus.retryAfter,
      locked: true,
    };
  }

  // Allow requests from localhost without auth (for internal agents)
  if (isLocalhost && !authHeader) {
    return { valid: true, source: "localhost" };
  }

  // Require authorization for non-localhost requests
  if (!authHeader) {
    recordAuthFailure(clientIp);
    return { valid: false, reason: "Missing Authorization header" };
  }

  // Validate Bearer token format
  if (!authHeader.startsWith("Bearer ")) {
    recordAuthFailure(clientIp);
    return { valid: false, reason: "Invalid Authorization format" };
  }

  const token = authHeader.substring(7);

  // Validate against configured MCP auth token using timing-safe comparison
  if (config.mcpAuth && secureCompare(token, config.mcpAuth)) {
    clearAuthFailures(clientIp); // Clear on success
    return { valid: true, source: "api_token", scope: "write" };
  }

  // Also check for internal service token (environment variable)
  // Service tokens have read-only scope; MCP auth tokens have full write access
  const serviceToken = process.env.AUTOPILOT_SERVICE_TOKEN;
  if (serviceToken && secureCompare(token, serviceToken)) {
    clearAuthFailures(clientIp); // Clear on success
    const tokenScope = "read";
    if (requiredScope === "write" && tokenScope !== "write") {
      return { valid: false, reason: "Insufficient scope: write access required" };
    }
    return { valid: true, source: "service_token", scope: tokenScope };
  }

  // Record auth failure for rate limiting
  recordAuthFailure(clientIp);
  return { valid: false, reason: "Invalid or expired token" };
}

// Parse JSON body from request
// Issue #8 fix: Track cumulative size before appending to prevent memory issues
const MAX_BODY_SIZE = 1024 * 1024; // 1MB

function parseJsonBody(req) {
  return new Promise((resolve, reject) => {
    const chunks = [];
    let totalSize = 0;
    let rejected = false;

    // Body timeout to prevent slow-loris attacks
    const bodyTimeout = setTimeout(() => {
      if (!rejected) {
        rejected = true;
        req.destroy();
        reject(new Error("Request body timeout"));
      }
    }, 30000);

    req.on("data", (chunk) => {
      if (rejected) return;

      // Check cumulative size BEFORE adding chunk
      totalSize += chunk.length;
      if (totalSize > MAX_BODY_SIZE) {
        rejected = true;
        clearTimeout(bodyTimeout);
        req.destroy(); // Stop receiving data
        reject(new Error("Request body too large"));
        return;
      }
      chunks.push(chunk);
    });

    req.on("end", () => {
      clearTimeout(bodyTimeout);
      if (rejected) return;
      try {
        const body = Buffer.concat(chunks).toString("utf8");
        resolve(body ? JSON.parse(body) : {});
      } catch (err) {
        reject(new Error("Invalid JSON"));
      }
    });

    req.on("error", (err) => {
      clearTimeout(bodyTimeout);
      if (!rejected) reject(err);
    });
  });
}

function createServer() {
  const server = http.createServer(async (req, res) => {
    const url = new URL(req.url, `http://${req.headers.host}`);

    // Issue #15 fix: Generate unique request ID for tracing
    const requestId = req.headers["x-request-id"] || generateRequestId();
    res.setHeader("X-Request-ID", requestId);

    // Get client IP for rate limiting
    // Only trust X-Forwarded-For from loopback connections (behind a local reverse proxy)
    const directIpRL = req.socket.remoteAddress || "unknown";
    const isDirectLocalRL = directIpRL === "127.0.0.1" || directIpRL === "::1" ||
                            directIpRL === "::ffff:127.0.0.1";
    const clientIp = (isDirectLocalRL && req.headers["x-forwarded-for"])
      ? req.headers["x-forwarded-for"].split(",")[0].trim()
      : directIpRL;

    // Security headers
    res.setHeader("X-Content-Type-Options", "nosniff");
    res.setHeader("X-Frame-Options", "DENY");
    res.setHeader("X-XSS-Protection", "1; mode=block");
    res.setHeader("Cache-Control", "no-store");

    // Issue #7 fix: Configurable CORS headers
    if (config.corsEnabled) {
      res.setHeader("Access-Control-Allow-Origin", config.corsOrigin);
      res.setHeader("Access-Control-Allow-Methods", "GET, POST, PUT, OPTIONS");
      res.setHeader("Access-Control-Allow-Headers", "Content-Type, Authorization, X-Request-ID");
    }

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
        sendJsonError(res, 429, "Too Many Requests", requestId);
        return;
      }
    }

    try {
      // Reject new requests during shutdown (except health checks)
      if (isShuttingDown && url.pathname !== "/health" && url.pathname !== "/ready") {
        res.setHeader("Connection", "close");
        sendJsonError(res, 503, "Service is shutting down", requestId);
        return;
      }

      // Metrics endpoint
      if (url.pathname === "/metrics" && req.method === "GET") {
        res.writeHead(200, { "Content-Type": "text/plain" });
        res.end(formatMetrics());
        return;
      }

      // Health endpoint (enhanced)
      if (url.pathname === "/health" && req.method === "GET") {
        const uptimeSeconds = Math.floor((Date.now() - startTime) / 1000);
        let dataDirOk = false;
        try {
          await fs.access(path.join(config.dataDir, "cases"));
          dataDirOk = true;
        } catch {
          // data dir not accessible
        }
        const overallStatus = dataDirOk ? "healthy" : "degraded";
        const statusCode = dataDirOk ? 200 : 503;
        const health = {
          status: overallStatus,
          version: SERVICE_VERSION,
          mode: config.mode,
          uptime_seconds: uptimeSeconds,
          checks: {
            data_dir: dataDirOk,
            metrics: config.metricsEnabled,
          },
          responder: {
            enabled: config.responderEnabled,
            status: config.responderEnabled ? "ACTIVE" : "DISABLED",
          },
          timestamp: new Date().toISOString(),
        };
        res.writeHead(statusCode, { "Content-Type": JSON_CONTENT_TYPE });
        res.end(JSON.stringify(health));
        return;
      }

      // Readiness endpoint
      if (url.pathname === "/ready" && req.method === "GET") {
        if (isShuttingDown) {
          res.writeHead(503, { "Content-Type": JSON_CONTENT_TYPE });
          res.end(JSON.stringify({ ready: false, reason: "shutting_down" }));
          return;
        }
        let dataDirReady = false;
        try {
          await fs.access(path.join(config.dataDir, "cases"));
          dataDirReady = true;
        } catch {
          // data dir not accessible
        }
        const ready = dataDirReady;
        res.writeHead(ready ? 200 : 503, { "Content-Type": JSON_CONTENT_TYPE });
        res.end(JSON.stringify({ ready, checks: { data_dir: dataDirReady } }));
        return;
      }

      // Version endpoint
      if (url.pathname === "/version" && req.method === "GET") {
        res.writeHead(200, { "Content-Type": JSON_CONTENT_TYPE });
        res.end(JSON.stringify({
          service: "wazuh-openclaw-autopilot",
          version: SERVICE_VERSION,
          node: process.version,
        }));
        return;
      }

      // Cases API - GET all
      if (url.pathname === "/api/cases" && req.method === "GET") {
        const authResult = validateAuthorization(req, "read");
        if (!authResult.valid) {
          sendAuthError(res, authResult, requestId);
          return;
        }

        const cases = await listCases({ limit: 100 });
        res.writeHead(200, { "Content-Type": JSON_CONTENT_TYPE });
        res.end(JSON.stringify(cases));
        return;
      }

      // Cases API - POST create
      if (url.pathname === "/api/cases" && req.method === "POST") {
        // Require authorization for write operations
        const authResult = validateAuthorization(req, "write");
        if (!authResult.valid) {
          sendAuthError(res, authResult, requestId);
          return;
        }

        const body = await parseJsonBody(req);

        if (!body.case_id || !isValidCaseId(body.case_id)) {
          sendJsonError(res, 400, "Invalid or missing case_id", requestId);
          return;
        }

        const newCase = await createCase(body.case_id, body);
        res.writeHead(201, { "Content-Type": JSON_CONTENT_TYPE });
        res.end(JSON.stringify(newCase));
        return;
      }

      // Cases API - GET single
      if (url.pathname.startsWith("/api/cases/") && req.method === "GET") {
        const authResult = validateAuthorization(req, "read");
        if (!authResult.valid) {
          sendAuthError(res, authResult, requestId);
          return;
        }

        const caseId = url.pathname.split("/")[3];

        // Input validation
        if (!caseId || !isValidCaseId(caseId)) {
          sendJsonError(res, 400, "Invalid case ID format", requestId);
          return;
        }

        try {
          const caseData = await getCase(caseId);
          res.writeHead(200, { "Content-Type": JSON_CONTENT_TYPE });
          res.end(JSON.stringify(caseData));
        } catch (err) {
          sendJsonError(res, 404, "Case not found", requestId);
        }
        return;
      }

      // Cases API - PUT update
      if (url.pathname.startsWith("/api/cases/") && req.method === "PUT") {
        // Require authorization for write operations
        const authResult = validateAuthorization(req, "write");
        if (!authResult.valid) {
          sendAuthError(res, authResult, requestId);
          return;
        }

        const caseId = url.pathname.split("/")[3];

        if (!caseId || !isValidCaseId(caseId)) {
          sendJsonError(res, 400, "Invalid case ID format", requestId);
          return;
        }

        try {
          const body = await parseJsonBody(req);
          const updatedCase = await updateCase(caseId, body);
          res.writeHead(200, { "Content-Type": JSON_CONTENT_TYPE });
          res.end(JSON.stringify(updatedCase));
        } catch (err) {
          if (err.message.includes("not found")) {
            sendJsonError(res, 404, "Case not found", requestId);
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
          sendAuthError(res, authResult, requestId);
          return;
        }

        const alert = await parseJsonBody(req);

        // Validate alert has minimum required fields
        if (!alert.alert_id && !alert._id && !alert.id) {
          sendJsonError(res, 400, "Alert must have alert_id, _id, or id field", requestId);
          return;
        }

        // Generate case ID from alert
        // Bug #15 fix: Use hash of full alert ID to prevent collisions
        const alertId = alert.alert_id || alert._id || alert.id;
        const timestamp = new Date().toISOString().split("T")[0].replace(/-/g, "");
        const alertIdHash = crypto.createHash("sha256")
          .update(alertId.toString())
          .digest("hex")
          .substring(0, 12);
        const caseId = `CASE-${timestamp}-${alertIdHash}`;

        // Extract entities from alert (basic triage)
        const entities = [];

        // Extract IPs
        const ipFields = ["srcip", "dstip", "src_ip", "dst_ip"];
        // Bug #9 fix: Proper IPv4 validation (each octet 0-255)
        const isValidIPv4 = (ip) => {
          if (!/^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$/.test(ip)) return false;
          const octets = ip.split(".").map(Number);
          return octets.every(o => o >= 0 && o <= 255);
        };
        for (const field of ipFields) {
          const ip = alert.data?.[field] || alert[field];
          if (ip && isValidIPv4(ip)) {
            entities.push({
              type: "ip",
              value: ip,
              role: field.includes("src") ? "source" : "destination",
              extracted_from: `data.${field}`,
            });
          }
        }

        // Extract users
        const userFields = ["srcuser", "dstuser", "user"];
        for (const field of userFields) {
          const user = alert.data?.[field] || alert[field];
          if (user && typeof user === "string" && user.length > 0) {
            entities.push({
              type: "user",
              value: user,
              role: field === "srcuser" ? "actor" : "target",
              extracted_from: `data.${field}`,
            });
          }
        }

        // Extract host/agent info
        if (alert.agent?.name) {
          entities.push({
            type: "host",
            value: alert.agent.name,
            role: "victim",
            agent_id: alert.agent.id,
            agent_ip: alert.agent.ip,
          });
        }

        // Determine severity from rule level
        let severity = "medium";
        const ruleLevel = alert.rule?.level || alert.level || 0;
        if (ruleLevel >= 13) severity = "critical";
        else if (ruleLevel >= 10) severity = "high";
        else if (ruleLevel >= 7) severity = "medium";
        else if (ruleLevel >= 4) severity = "low";
        else severity = "informational";

        // Build timeline entry
        const timeline = [{
          timestamp: alert.timestamp || new Date().toISOString(),
          event_type: "alert_received",
          description: alert.rule?.description || "Alert received",
          source: "wazuh",
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
                tactic: mitreData.tactic?.[i] || "unknown",
                technique: mitreData.technique?.[i] || "unknown",
              });
            }
          } else if (mitreData.id) {
            mitre.push({
              technique_id: mitreData.id,
              tactic: mitreData.tactic || "unknown",
              technique: mitreData.technique || "unknown",
            });
          }
        }

        // Create the case with triage data
        const caseData = {
          title: `[${severity.toUpperCase()}] ${alert.rule?.description || "Security Alert"} on ${alert.agent?.name || "Unknown Host"}`,
          summary: `Automated triage of Wazuh alert. Rule: ${alert.rule?.id || "N/A"}, Level: ${ruleLevel}, Agent: ${alert.agent?.name || "N/A"}`,
          severity,
          confidence: ruleLevel >= 10 ? 0.8 : ruleLevel >= 7 ? 0.6 : 0.4,
          entities,
          timeline,
          mitre,
          evidence_refs: [{
            type: "wazuh_alert",
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

        if (existingCase) {
          // Update existing case with new evidence
          await updateCase(caseId, {
            entities: caseData.entities,
            timeline: caseData.timeline,
            evidence_refs: caseData.evidence_refs,
          });
          log("info", "triage", "Updated existing case with new alert", { case_id: caseId, alert_id: alertId });
        } else {
          // Create new case
          await createCase(caseId, caseData);
          log("info", "triage", "Created new case from alert", { case_id: caseId, alert_id: alertId, severity });
        }

        // Record metrics
        incrementMetric("alerts_ingested_total");
        const triageLatency = (Date.now() - triageStart) / 1000;
        recordLatency("triage_latency_seconds", triageLatency);

        res.writeHead(existingCase ? 200 : 201, { "Content-Type": JSON_CONTENT_TYPE });
        res.end(JSON.stringify({
          case_id: caseId,
          status: existingCase ? "updated" : "created",
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
        const authResult = validateAuthorization(req, "read");
        if (!authResult.valid) {
          sendAuthError(res, authResult, requestId);
          return;
        }

        const status = getResponderStatus();
        res.writeHead(200, { "Content-Type": JSON_CONTENT_TYPE });
        res.end(JSON.stringify(status));
        return;
      }

      // =================================================================
      // RESPONSE PLANS API - Two-Tier Human-in-the-Loop
      // =================================================================

      // List plans
      if (url.pathname === "/api/plans" && req.method === "GET") {
        const authResult = validateAuthorization(req, "read");
        if (!authResult.valid) {
          sendAuthError(res, authResult, requestId);
          return;
        }

        const state = url.searchParams.get("state");
        const case_id = url.searchParams.get("case_id");
        const plans = listPlans({ state, case_id });
        res.writeHead(200, { "Content-Type": JSON_CONTENT_TYPE });
        res.end(JSON.stringify(plans));
        return;
      }

      // Create plan (Response Planner agent creates plans)
      if (url.pathname === "/api/plans" && req.method === "POST") {
        const authResult = validateAuthorization(req, "write");
        if (!authResult.valid) {
          sendAuthError(res, authResult, requestId);
          return;
        }

        const body = await parseJsonBody(req);

        if (!body.case_id || !isValidCaseId(body.case_id)) {
          sendJsonError(res, 400, "Invalid or missing case_id", requestId);
          return;
        }

        if (!body.actions || !Array.isArray(body.actions) || body.actions.length === 0) {
          sendJsonError(res, 400, "actions array is required and must not be empty", requestId);
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

          res.writeHead(201, { "Content-Type": JSON_CONTENT_TYPE });
          res.end(JSON.stringify({
            ...plan,
            message: "Plan created in PROPOSED state. Requires Tier 1 approval before execution.",
            next_step: `POST /api/plans/${plan.plan_id}/approve`,
          }));
        } catch (err) {
          sendJsonError(res, 400, err.message, requestId);
        }
        return;
      }

      // Get single plan
      if (url.pathname.match(/^\/api\/plans\/[^/]+$/) && req.method === "GET") {
        const authResult = validateAuthorization(req, "read");
        if (!authResult.valid) {
          sendAuthError(res, authResult, requestId);
          return;
        }

        const planId = url.pathname.split("/")[3];
        try {
          const plan = getPlan(planId);
          res.writeHead(200, { "Content-Type": JSON_CONTENT_TYPE });
          res.end(JSON.stringify(plan));
        } catch (err) {
          sendJsonError(res, 404, err.message, requestId);
        }
        return;
      }

      // TIER 1: Approve plan
      if (url.pathname.match(/^\/api\/plans\/[^/]+\/approve$/) && req.method === "POST") {
        const authResult = validateAuthorization(req, "write");
        if (!authResult.valid) {
          sendAuthError(res, authResult, requestId);
          return;
        }

        const planId = url.pathname.split("/")[3];
        const body = await parseJsonBody(req);

        if (!body.approver_id) {
          sendJsonError(res, 400, "approver_id is required", requestId);
          return;
        }

        try {
          const plan = approvePlan(planId, body.approver_id, body.reason || "");
          res.writeHead(200, { "Content-Type": JSON_CONTENT_TYPE });
          res.end(JSON.stringify({
            ...plan,
            message: "Plan APPROVED (Tier 1 complete). Ready for execution.",
            next_step: `POST /api/plans/${planId}/execute`,
            responder_status: getResponderStatus(),
          }));
        } catch (err) {
          sendJsonError(res, err.message.includes("not found") ? 404 : 400, err.message, requestId);
        }
        return;
      }

      // Reject plan
      if (url.pathname.match(/^\/api\/plans\/[^/]+\/reject$/) && req.method === "POST") {
        const authResult = validateAuthorization(req, "write");
        if (!authResult.valid) {
          sendAuthError(res, authResult, requestId);
          return;
        }

        const planId = url.pathname.split("/")[3];
        const body = await parseJsonBody(req);

        if (!body.rejector_id) {
          sendJsonError(res, 400, "rejector_id is required", requestId);
          return;
        }

        try {
          const plan = rejectPlan(planId, body.rejector_id, body.reason || "");
          res.writeHead(200, { "Content-Type": JSON_CONTENT_TYPE });
          res.end(JSON.stringify({
            ...plan,
            message: "Plan REJECTED. No actions will be executed.",
          }));
        } catch (err) {
          sendJsonError(res, err.message.includes("not found") ? 404 : 400, err.message, requestId);
        }
        return;
      }

      // TIER 2: Execute plan
      if (url.pathname.match(/^\/api\/plans\/[^/]+\/execute$/) && req.method === "POST") {
        const authResult = validateAuthorization(req, "write");
        if (!authResult.valid) {
          sendAuthError(res, authResult, requestId);
          return;
        }

        const planId = url.pathname.split("/")[3];
        const body = await parseJsonBody(req);

        if (!body.executor_id) {
          sendJsonError(res, 400, "executor_id is required", requestId);
          return;
        }

        try {
          const plan = await executePlan(planId, body.executor_id);
          // Bug #2 fix: Return 200 for success, 207 (Multi-Status) for partial failure
          const statusCode = plan.state === PLAN_STATES.COMPLETED ? 200 : 207;
          res.writeHead(statusCode, { "Content-Type": JSON_CONTENT_TYPE });
          res.end(JSON.stringify({
            ...plan,
            message: plan.state === PLAN_STATES.COMPLETED
              ? "Plan EXECUTED successfully. All actions completed."
              : "Plan execution completed with some failures.",
          }));
        } catch (err) {
          // Bug #1 fix: Match the actual error message from executePlan
          if (err.message.includes("Responder capability is DISABLED")) {
            res.writeHead(403, { "Content-Type": JSON_CONTENT_TYPE });
            res.end(JSON.stringify({
              error: err.message,
              responder_status: getResponderStatus(),
              resolution: "Contact an administrator to enable AUTOPILOT_RESPONDER_ENABLED=true",
            }));
            return;
          }

          sendJsonError(res, err.message.includes("not found") ? 404 : 400, err.message, requestId);
        }
        return;
      }

      // 404 for unknown routes
      sendJsonError(res, 404, "Not found", requestId);
    } catch (err) {
      log("error", "http", "Request error", { error: err.message });
      sendJsonError(res, 500, "Internal server error", requestId);
    }
  });

  return server;
}

// =============================================================================
// STARTUP
// =============================================================================

// Graceful shutdown handling - declared here for use in startup
let server = null;
const cleanupIntervals = [];

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
  // Issue #10 fix: Fail fast in production mode if policy is missing or invalid
  const policyPath = path.join(config.configDir, "policies", "policy.yaml");
  try {
    await fs.access(policyPath);
    const policyContent = await fs.readFile(policyPath, "utf8");

    // Validate YAML syntax by attempting to parse
    try {
      parseSimpleYaml(policyContent);
    } catch (parseErr) {
      log("error", "startup", "Policy file contains invalid YAML", { path: policyPath, error: parseErr.message });
      if (config.mode === "production") {
        process.exit(1);
      }
    }

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
    // Issue #10 fix: In production, policy file must exist and be valid
    if (config.mode === "production") {
      log("error", "startup", "Production mode requires valid policy file", { path: policyPath, error: err.message });
      process.exit(1);
    }
    log("warn", "startup", "Could not validate policy file", { path: policyPath, error: err.message });
  }

  // Load toolmap
  await loadToolmap();

  // Validate numeric configuration values
  const numericConfigs = [
    ["metricsPort", config.metricsPort],
    ["approvalTtlMinutes", config.approvalTtlMinutes],
    ["rateLimitWindowMs", config.rateLimitWindowMs],
    ["rateLimitMaxRequests", config.rateLimitMaxRequests],
    ["authFailureWindowMs", config.authFailureWindowMs],
    ["authFailureMaxAttempts", config.authFailureMaxAttempts],
    ["authLockoutDurationMs", config.authLockoutDurationMs],
    ["mcpTimeoutMs", config.mcpTimeoutMs],
    ["planExpiryMinutes", config.planExpiryMinutes],
    ["shutdownTimeoutMs", config.shutdownTimeoutMs],
  ];
  for (const [name, value] of numericConfigs) {
    if (isNaN(value) || value < 0) {
      log("error", "startup", `Invalid configuration: ${name} = ${value}`);
      process.exit(1);
    }
  }

  // Port range validation
  if (config.metricsPort < 1 || config.metricsPort > 65535) {
    log("error", "startup", `Invalid port: RUNTIME_PORT = ${config.metricsPort} (must be 1-65535)`);
    process.exit(1);
  }

  // MCP URL format validation
  if (config.mcpUrl) {
    try {
      new URL(config.mcpUrl);
    } catch (err) {
      log("error", "startup", `Invalid MCP_URL: ${config.mcpUrl}`, { error: err.message });
      process.exit(1);
    }
  }

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
    server.on("error", (err) => {
      log("error", "startup", "Server failed to start", {
        error: err.message,
        code: err.code,
        host: config.metricsHost,
        port: config.metricsPort,
      });
      process.exit(1);
    });
    server.listen(config.metricsPort, config.metricsHost, () => {
      log("info", "startup", "Server listening", {
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
  formatMetrics,
  // Auth (exported for testing)
  validateAuthorization,
  isValidCaseId,
  // Rate limiting & auth lockout
  checkRateLimit,
  recordAuthFailure,
  isAuthLocked,
  clearAuthFailures,
  // HTTP helpers
  parseJsonBody,
  createServer,
  sendJsonError,
  // Utilities
  parseSimpleYaml,
  sanitizeMetricLabelName,
};

function setupCleanupIntervals() {
  // Approval token cleanup
  const tokenCleanup = setInterval(() => {
    const now = Date.now();
    let removed = 0;
    for (const [token, data] of approvalTokens.entries()) {
      // Issue #13 fix: Direct timestamp comparison
      if (new Date(data.expires_at).getTime() < now) {
        approvalTokens.delete(token);
        removed++;
      }
    }
    if (removed > 0) {
      log("debug", "cleanup", "Expired approval tokens removed", { count: removed });
    }
  }, 60000);
  cleanupIntervals.push(tokenCleanup);

  // Auth failure state cleanup
  const authCleanup = setInterval(() => {
    const now = Date.now();
    let removed = 0;
    for (const [ip, data] of authFailureState.attempts.entries()) {
      // Clean up old entries (lockout expired or window passed)
      const windowExpired = now > data.firstAttempt + config.authFailureWindowMs;
      const lockoutExpired = data.lockedUntil && now >= data.lockedUntil;
      if (windowExpired || lockoutExpired) {
        authFailureState.attempts.delete(ip);
        removed++;
      }
    }
    if (removed > 0) {
      log("debug", "cleanup", "Expired auth failure entries removed", { count: removed });
    }
  }, 60000);
  cleanupIntervals.push(authCleanup);

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
    const nowTs = Date.now();
    const nowIso = new Date(nowTs).toISOString();
    let expired = 0;
    for (const [, plan] of responsePlans.entries()) {
      if (
        (plan.state === PLAN_STATES.PROPOSED || plan.state === PLAN_STATES.APPROVED) &&
        new Date(plan.expires_at).getTime() < nowTs // Issue #13 fix
      ) {
        plan.state = PLAN_STATES.EXPIRED;
        plan.updated_at = nowIso;
        expired++;
        incrementMetric("plans_expired_total");
      }
    }
    if (expired > 0) {
      log("info", "cleanup", "Plans expired", { count: expired });
    }

    // Also clean up very old completed/failed plans (older than 7 days)
    const cutoff = nowTs - 7 * 24 * 60 * 60 * 1000;
    let removed = 0;
    for (const [planId, plan] of responsePlans.entries()) {
      if (
        ["completed", "failed", "rejected", "expired"].includes(plan.state) &&
        new Date(plan.updated_at).getTime() < cutoff // Issue #13 fix
      ) {
        responsePlans.delete(planId);
        removed++;
      }
    }
    if (removed > 0) {
      log("debug", "cleanup", "Old plans removed", { count: removed });
    }

    // Clean up stale executingPlans entries (plan no longer in EXECUTING state)
    for (const planId of executingPlans) {
      const plan = responsePlans.get(planId);
      if (!plan || plan.state !== PLAN_STATES.EXECUTING) {
        executingPlans.delete(planId);
      }
    }
  }, 60000);
  cleanupIntervals.push(plansCleanup);
}

// Issue #12 fix: Add configurable shutdown timeout with force kill
let isShuttingDown = false;

async function gracefulShutdown(signal) {
  if (isShuttingDown) {
    log("warn", "shutdown", "Shutdown already in progress, forcing exit");
    process.exit(1);
  }
  isShuttingDown = true;

  log("info", "shutdown", `Received ${signal}, shutting down gracefully...`);

  // Set force-kill timeout
  const forceKillTimer = setTimeout(() => {
    log("error", "shutdown", "Graceful shutdown timeout exceeded, forcing exit");
    process.exit(1);
  }, config.shutdownTimeoutMs);
  forceKillTimer.unref(); // Don't keep process alive just for this timer

  // Stop Slack WebSocket connection
  if (slack && slack.isInitialized()) {
    try {
      await slack.stopSlack();
      log("info", "shutdown", "Slack connection closed");
    } catch (err) {
      log("warn", "shutdown", "Error stopping Slack", { error: err.message });
    }
  }

  // Stop accepting new requests and close idle connections
  if (server) {
    if (typeof server.closeIdleConnections === "function") {
      server.closeIdleConnections();
    }
    server.close(() => {
      log("info", "shutdown", "HTTP server closed");
    });
    // After grace period, force-close remaining connections
    setTimeout(() => {
      if (typeof server.closeAllConnections === "function") {
        server.closeAllConnections();
      }
    }, 5000);
  }

  // Clear all cleanup intervals
  for (const interval of cleanupIntervals) {
    clearInterval(interval);
  }

  // Allow pending operations to complete (use shorter timeout than force-kill)
  setTimeout(() => {
    clearTimeout(forceKillTimer);
    log("info", "shutdown", "Shutdown complete");
    process.exit(0);
  }, 1000);
}

process.on("SIGTERM", () => gracefulShutdown("SIGTERM"));
process.on("SIGINT", () => gracefulShutdown("SIGINT"));

process.on("unhandledRejection", (reason) => {
  log("error", "process", "Unhandled promise rejection", {
    reason: reason instanceof Error ? reason.message : String(reason),
    stack: reason instanceof Error ? reason.stack : undefined,
  });
});

process.on("uncaughtException", (err) => {
  log("error", "process", "Uncaught exception", {
    error: err.message,
    stack: err.stack,
  });
  setTimeout(() => process.exit(1), 1000);
});

// Run if executed directly
if (require.main === module) {
  main().catch((err) => {
    log("error", "startup", "Failed to start", { error: err.message });
    process.exit(1);
  });
}
