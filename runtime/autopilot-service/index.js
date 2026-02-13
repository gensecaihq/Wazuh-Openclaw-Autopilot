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

function recordLatency(name, seconds, labels = {}) {
  const key = Object.keys(labels).length > 0 ? JSON.stringify(labels) : "default";
  if (!metrics[name]) metrics[name] = {};
  if (!metrics[name][key]) metrics[name][key] = [];
  metrics[name][key].push(seconds);
}

function formatMetrics() {
  const lines = [];

  // Simple counters
  ["cases_created_total", "cases_updated_total", "action_plans_proposed_total",
   "approvals_requested_total", "approvals_granted_total"].forEach((name) => {
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
  const content = await fs.readFile(packPath, "utf8");
  return JSON.parse(content);
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

function generateApprovalToken(planId, caseId) {
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

// Clean up expired tokens periodically
setInterval(() => {
  const now = Date.now();
  for (const [token, data] of approvalTokens.entries()) {
    if (new Date(data.expires_at) < new Date(now)) {
      approvalTokens.delete(token);
    }
  }
}, 60000); // Every minute

// =============================================================================
// MCP CLIENT WRAPPER
// =============================================================================

async function loadToolmap() {
  const toolmapPath = path.join(config.configDir, "policies", "toolmap.yaml");
  try {
    // For simplicity, we'll just check if file exists
    // In production, use a proper YAML parser
    await fs.access(toolmapPath);
    log("info", "mcp", "Toolmap loaded", { path: toolmapPath });
    return true;
  } catch (err) {
    log("warn", "mcp", "Toolmap not found, using defaults", { path: toolmapPath });
    return false;
  }
}

async function callMcpTool(toolName, params, correlationId) {
  const startTime = Date.now();

  if (!config.mcpUrl) {
    incrementMetric("errors_total", { component: "mcp" });
    throw new Error("MCP_URL not configured");
  }

  const requestHash = crypto
    .createHash("sha256")
    .update(JSON.stringify({ toolName, params }))
    .digest("hex")
    .substring(0, 16);

  try {
    const response = await fetch(`${config.mcpUrl}/tools/${toolName}`, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        ...(config.mcpAuth && { Authorization: `Bearer ${config.mcpAuth}` }),
        ...(correlationId && { "X-Correlation-ID": correlationId }),
      },
      body: JSON.stringify(params),
    });

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
// HTTP SERVER
// =============================================================================

function createServer() {
  const server = http.createServer(async (req, res) => {
    const url = new URL(req.url, `http://${req.headers.host}`);

    // CORS headers for local development
    res.setHeader("Access-Control-Allow-Origin", "http://localhost:3000");
    res.setHeader("Access-Control-Allow-Methods", "GET, POST, OPTIONS");
    res.setHeader("Access-Control-Allow-Headers", "Content-Type, Authorization");

    if (req.method === "OPTIONS") {
      res.writeHead(204);
      res.end();
      return;
    }

    try {
      // Metrics endpoint
      if (url.pathname === "/metrics" && req.method === "GET") {
        res.writeHead(200, { "Content-Type": "text/plain" });
        res.end(formatMetrics());
        return;
      }

      // Health endpoint
      if (url.pathname === "/health" && req.method === "GET") {
        res.writeHead(200, { "Content-Type": "application/json" });
        res.end(JSON.stringify({ status: "healthy", mode: config.mode }));
        return;
      }

      // Cases API
      if (url.pathname === "/api/cases" && req.method === "GET") {
        const cases = await listCases({ limit: 100 });
        res.writeHead(200, { "Content-Type": "application/json" });
        res.end(JSON.stringify(cases));
        return;
      }

      if (url.pathname.startsWith("/api/cases/") && req.method === "GET") {
        const caseId = url.pathname.split("/")[3];
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

  if (config.metricsEnabled) {
    const server = createServer();
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
  incrementMetric,
  recordLatency,
};

// Run if executed directly
if (require.main === module) {
  main().catch((err) => {
    log("error", "startup", "Failed to start", { error: err.message });
    process.exit(1);
  });
}
