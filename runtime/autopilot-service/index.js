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
  ["cases_created_total", "cases_updated_total", "alerts_ingested_total",
   "action_plans_proposed_total", "approvals_requested_total", "approvals_granted_total"].forEach((name) => {
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

  log("info", "startup", "Wazuh Autopilot started", { mode: config.mode });
}

// Export for testing
module.exports = {
  createCase,
  updateCase,
  getCase,
  listCases,
  generateApprovalToken,
  validateApprovalToken,
  consumeApprovalToken,
  callMcpTool,
  loadToolmap,
  resolveMcpTool,
  isToolEnabled,
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
