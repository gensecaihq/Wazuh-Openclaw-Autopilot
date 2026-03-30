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

/**
 * Normalize gateway URL scheme: ws:// → http://, wss:// → https://.
 * OpenClaw `status --all` reports the gateway target as ws:// (its WebSocket
 * endpoint for interactive sessions), but webhook dispatch uses HTTP POST.
 * Users who copy the ws:// URL from `openclaw status` would get fetch errors.
 */
function normalizeGatewayUrl(url) {
  if (!url) return url;
  return url.replace(/^ws(s?):\/\//i, (_, s) => `http${s.toLowerCase()}://`);
}

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
  // MCP timeout and retry
  mcpTimeoutMs: parseInt(process.env.MCP_TIMEOUT_MS || "30000", 10),
  mcpMaxRetries: parseInt(process.env.MCP_MAX_RETRIES || "2", 10),
  mcpRetryBaseMs: parseInt(process.env.MCP_RETRY_BASE_MS || "1000", 10),
  // Responder capability toggle - DISABLED by default
  // When enabled, humans can execute approved plans via the two-tier approval workflow
  // This does NOT enable autonomous execution - human approval is ALWAYS required
  responderEnabled: process.env.AUTOPILOT_RESPONDER_ENABLED === "true",
  // Plan expiry
  planExpiryMinutes: parseInt(process.env.PLAN_EXPIRY_MINUTES || "60", 10),
  // Maximum concurrent plan executions
  maxConcurrentExecutions: parseInt(process.env.MAX_CONCURRENT_EXECUTIONS || "5", 10),
  // CORS configuration (Issue #7 fix)
  corsOrigin: process.env.CORS_ORIGIN || "http://localhost:3000",
  corsEnabled: process.env.CORS_ENABLED !== "false",
  // Graceful shutdown timeout (Issue #12 fix)
  shutdownTimeoutMs: parseInt(process.env.SHUTDOWN_TIMEOUT_MS || "30000", 10),
  // OpenClaw Gateway dispatch (for agent pipeline handoffs)
  openclawGatewayUrl: normalizeGatewayUrl(process.env.OPENCLAW_GATEWAY_URL || "http://127.0.0.1:18789"),
  openclawToken: process.env.OPENCLAW_TOKEN || "",
  // Separate webhook token for hook validation (falls back to gateway token for backwards compat)
  openclawWebhookToken: process.env.OPENCLAW_WEBHOOK_TOKEN || process.env.OPENCLAW_TOKEN || "",
  // MCP auth mode: "mcp-jsonrpc" (proper MCP protocol) or "legacy-rest" (backwards compat)
  mcpAuthMode: process.env.MCP_AUTH_MODE || "mcp-jsonrpc",
  mcpJwtTtlMs: parseInt(process.env.MCP_JWT_TTL_MS || "3000000", 10), // 50 min
  // IP Enrichment (AbuseIPDB)
  enrichmentEnabled: process.env.ENRICHMENT_ENABLED === "true",
  abuseIpdbApiKey: process.env.ABUSEIPDB_API_KEY || "",
  enrichmentCacheTtlMs: parseInt(process.env.ENRICHMENT_CACHE_TTL_MS || "3600000", 10),
  enrichmentErrorCacheTtlMs: parseInt(process.env.ENRICHMENT_ERROR_CACHE_TTL_MS || "300000", 10),
  enrichmentTimeoutMs: parseInt(process.env.ENRICHMENT_TIMEOUT_MS || "5000", 10),
  // Webhook dispatch timeout per attempt
  webhookDispatchTimeoutMs: parseInt(process.env.WEBHOOK_DISPATCH_TIMEOUT_MS || "10000", 10),
  // Alert grouping
  alertGroupEnabled: process.env.ALERT_GROUP_ENABLED !== "false",
  alertGroupWindowMs: parseInt(process.env.ALERT_GROUP_WINDOW_MS || "3600000", 10),
  // Bootstrap approval — allows agent auto-approval when all approver Slack IDs are placeholders
  // WARNING: This disables human-in-the-loop review for response plans
  bootstrapApproval: process.env.AUTOPILOT_BOOTSTRAP_APPROVAL === "true",
  // Stalled pipeline detection
  stalledPipelineEnabled: process.env.STALLED_PIPELINE_ENABLED !== "false",
  stalledPipelineThresholdMs: parseInt(process.env.STALLED_PIPELINE_THRESHOLD_MINUTES || "30", 10) * 60 * 1000,
  stalledPipelineCheckIntervalMs: parseInt(process.env.STALLED_PIPELINE_CHECK_INTERVAL_MS || "300000", 10),
  // Trusted proxy: only trust X-Forwarded-For when explicitly enabled
  trustedProxy: process.env.TRUSTED_PROXY === "true",
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
  delete entry.api_key;
  delete entry.apiKey;
  delete entry.authorization;
  delete entry.credential;
  delete entry.bearer;
  delete entry.session_token;

  if (config.logFormat === "json") {
    console.log(JSON.stringify(entry));
  } else {
    console.log(`[${entry.ts}] [${level.toUpperCase()}] [${component}] ${msg}`);
  }
}

// =============================================================================
// TRUSTED PROXY WARNING (log once)
// =============================================================================

let _untrustedProxyWarned = false;
function warnUntrustedProxy() {
  if (_untrustedProxyWarned) return;
  _untrustedProxyWarned = true;
  log("warn", "security",
    "X-Forwarded-For header received from localhost but TRUSTED_PROXY is not set. " +
    "Using socket remote address instead. Set TRUSTED_PROXY=true if behind a reverse proxy.");
}

// =============================================================================
// ALERT DEDUP (cross-midnight alert ID → case ID mapping)
// =============================================================================

const ALERT_DEDUP_TTL_MS = 60 * 60 * 1000; // 1 hour
const ALERT_DEDUP_MAX_SIZE = 50000;
const alertDedup = new Map(); // alertId → { caseId, ts }

function alertDedupGet(alertId) {
  const entry = alertDedup.get(alertId);
  if (!entry) return null;
  if (Date.now() - entry.ts > ALERT_DEDUP_TTL_MS) {
    alertDedup.delete(alertId);
    return null;
  }
  return entry.caseId;
}

function alertDedupSet(alertId, caseId) {
  // Cap size: evict oldest entries when at capacity
  if (alertDedup.size >= ALERT_DEDUP_MAX_SIZE && !alertDedup.has(alertId)) {
    // Delete the first (oldest-inserted) entry
    const firstKey = alertDedup.keys().next().value;
    alertDedup.delete(firstKey);
  }
  alertDedup.set(alertId, { caseId, ts: Date.now() });
}

// Periodic cleanup of expired entries (every 5 minutes)
const _alertDedupCleanupInterval = setInterval(() => {
  const now = Date.now();
  for (const [key, entry] of alertDedup) {
    if (now - entry.ts > ALERT_DEDUP_TTL_MS) {
      alertDedup.delete(key);
    }
  }
}, 5 * 60 * 1000);
// Allow process to exit without waiting for cleanup timer
if (_alertDedupCleanupInterval.unref) _alertDedupCleanupInterval.unref();

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
  // Webhook dispatch metrics
  webhook_dispatches_total: 0,
  webhook_dispatch_failures_total: 0,
  // Enrichment metrics
  enrichment_requests_total: 0,
  enrichment_cache_hits_total: 0,
  enrichment_errors_total: 0,
  // Feedback metrics
  false_positives_total: 0,
  feedback_submitted_total: {},
  policy_denies_total: {},
  errors_total: {},
  // Stalled pipeline metrics
  stalled_pipeline_detected_total: 0,
  stalled_pipeline_redispatched_total: 0,
};

function incrementMetric(name, labels = {}) {
  if (Object.keys(labels).length === 0) {
    metrics[name] = (metrics[name] || 0) + 1;
  } else {
    const key = JSON.stringify(labels);
    if (!metrics[name]) metrics[name] = {};
    // Cap unique label combinations to prevent unbounded memory growth
    if (!(key in metrics[name]) && Object.keys(metrics[name]).length >= MAX_METRIC_KEYS) {
      return; // Silently drop — metric cardinality limit reached
    }
    metrics[name][key] = (metrics[name][key] || 0) + 1;
  }
}

// Maximum samples to retain per metric key (prevents memory leak)
const MAX_LATENCY_SAMPLES = 1000;
// Maximum unique label combinations per metric (prevents OOM from dynamic labels)
const MAX_METRIC_KEYS = 200;

function recordLatency(name, seconds, labels = {}) {
  const key = Object.keys(labels).length > 0 ? JSON.stringify(labels) : "default";
  if (!metrics[name]) metrics[name] = {};
  // Cap unique label combinations to prevent unbounded memory growth
  if (!(key in metrics[name]) && Object.keys(metrics[name]).length >= MAX_METRIC_KEYS) {
    return; // Silently drop — metric cardinality limit reached
  }
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
    "approvals_requested_total", "approvals_granted_total",
    // Two-tier approval metrics
    "plans_created_total", "plans_approved_total", "plans_executed_total",
    "plans_rejected_total", "plans_expired_total",
    "executions_success_total", "executions_failed_total",
    "responder_disabled_blocks_total",
    "webhook_dispatches_total", "webhook_dispatch_failures_total",
    "enrichment_requests_total", "enrichment_cache_hits_total", "enrichment_errors_total",
    "false_positives_total",
    "stalled_pipeline_detected_total", "stalled_pipeline_redispatched_total",
  ].forEach((name) => {
    lines.push(`# TYPE autopilot_${name} counter`);
    lines.push(`autopilot_${name} ${metrics[name] || 0}`);
  });

  // Labeled counters
  ["mcp_tool_calls_total", "policy_denies_total", "errors_total", "feedback_submitted_total"].forEach((name) => {
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
          .map(([k, v]) => `${sanitizeMetricLabelName(k)}="${String(v).replace(/[\\"]/g, "\\$&").replace(/\n/g, "\\n")}"`)
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

  lines.push("# TYPE autopilot_entity_index_size gauge");
  lines.push(`autopilot_entity_index_size ${entityCaseIndex.size}`);

  lines.push("# TYPE autopilot_plans_in_memory gauge");
  lines.push(`autopilot_plans_in_memory ${responsePlans.size}`);

  return lines.join("\n");
}

// =============================================================================
// OPENCLAW GATEWAY DISPATCH (Agent Pipeline Handoffs)
// =============================================================================

/**
 * Fire-and-forget async POST to OpenClaw Gateway webhook endpoint.
 * Triggers downstream agents via OpenClaw's hook routing.
 * Never throws — logs and records metrics on failure.
 */
async function dispatchToGateway(webhookPath, payload) {
  const webhookToken = config.openclawWebhookToken || config.openclawToken;
  if (!config.openclawGatewayUrl || !webhookToken) {
    log("warn", "dispatch", "Gateway dispatch skipped — OPENCLAW_WEBHOOK_TOKEN/OPENCLAW_TOKEN not configured. Agent pipeline is disabled.", { path: webhookPath });
    return;
  }

  const url = `${config.openclawGatewayUrl}${webhookPath}`;
  const outgoingPayload = { ...payload, dispatched_at: new Date().toISOString() };

  for (let attempt = 0; attempt < 2; attempt++) {
    let timeoutId;
    try {
      const controller = new AbortController();
      timeoutId = setTimeout(() => controller.abort(), config.webhookDispatchTimeoutMs);

      const response = await fetch(url, {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          Authorization: `Bearer ${webhookToken}`,
        },
        body: JSON.stringify(outgoingPayload),
        signal: controller.signal,
      });

      clearTimeout(timeoutId);

      if (response.ok) {
        await response.text().catch(() => ""); // drain response body
        incrementMetric("webhook_dispatches_total");
        log("info", "dispatch", "Webhook dispatched", {
          path: webhookPath,
          status: response.status,
          ...(attempt > 0 && { attempt: attempt + 1 }),
        });
        return;
      }

      if (response.status < 500) {
        // Client error (400, 401, 403, 404) — log as failure with diagnostic detail, don't retry
        incrementMetric("webhook_dispatch_failures_total");
        const errBody = await response.text().catch(() => "");
        log("warn", "dispatch", "Webhook dispatch client error", {
          path: webhookPath,
          url,
          status: response.status,
          response_body: errBody.substring(0, 200),
          payload_keys: Object.keys(outgoingPayload),
          has_message: typeof outgoingPayload.message === "string" && outgoingPayload.message.length > 0,
          message_preview: typeof outgoingPayload.message === "string" ? outgoingPayload.message.substring(0, 80) : "(missing)",
        });
        return;
      }

      // 5xx — retry once
      if (attempt === 0) {
        await response.text().catch(() => ""); // drain body
        continue;
      }
      // Final attempt 5xx — drain body to release connection
      await response.text().catch(() => "");
    } catch (err) {
      clearTimeout(timeoutId);
      if (attempt === 0 && (err.name === "AbortError" ||
        (err.cause && ["ECONNREFUSED", "ECONNRESET", "ETIMEDOUT"].includes(err.cause.code)))) {
        continue; // retry once on transient errors
      }

      incrementMetric("webhook_dispatch_failures_total");
      log("warn", "dispatch", "Webhook dispatch failed", {
        path: webhookPath,
        error: err.message,
        attempts: attempt + 1,
      });
      return;
    }
  }

  // All attempts exhausted
  incrementMetric("webhook_dispatch_failures_total");
  log("warn", "dispatch", "Webhook dispatch failed after retries", { path: webhookPath });
  queueFailedDispatch(webhookPath, outgoingPayload).catch(() => {});
}

// =============================================================================
// WEBHOOK DEAD-LETTER QUEUE (DLQ)
// =============================================================================

const MAX_DLQ_SIZE = 500;
const DLQ_RETRY_BATCH = 20; // max items per retry cycle

async function getDlqPath() {
  return path.join(config.dataDir, "state", "dlq.json");
}

async function loadDlq() {
  try {
    const content = await fs.readFile(await getDlqPath(), "utf8");
    const entries = JSON.parse(content);
    return Array.isArray(entries) ? entries : [];
  } catch {
    return [];
  }
}

async function saveDlq(entries) {
  await atomicWriteFile(await getDlqPath(), JSON.stringify(entries, null, 2));
}

async function queueFailedDispatch(webhookPathOrEntry, payload) {
  try {
    const entries = await loadDlq();
    if (entries.length >= MAX_DLQ_SIZE) {
      // Evict oldest entries to make room
      entries.splice(0, entries.length - MAX_DLQ_SIZE + 1);
      incrementMetric("webhook_dlq_evictions_total");
    }
    // Support both signatures: (webhookPath, payload) and (entryObject)
    let entry;
    if (typeof webhookPathOrEntry === "object" && webhookPathOrEntry !== null) {
      entry = {
        ...webhookPathOrEntry,
        queued_at: new Date().toISOString(),
        attempts: 0,
      };
    } else {
      entry = {
        webhookPath: webhookPathOrEntry,
        payload,
        queued_at: new Date().toISOString(),
        attempts: 0,
      };
    }
    entries.push(entry);
    await saveDlq(entries);
    incrementMetric("webhook_dlq_queued_total");
    log("info", "dispatch", "Failed dispatch queued to DLQ", { path: entry.webhookPath || entry.webhook_url, dlq_size: entries.length });
  } catch (err) {
    log("warn", "dispatch", "Failed to write to DLQ", { error: err.message });
  }
}

async function retryDlqDispatches() {
  let entries;
  try {
    entries = await loadDlq();
  } catch {
    return;
  }
  if (entries.length === 0) return;

  const webhookToken = config.openclawWebhookToken || config.openclawToken;
  if (!config.openclawGatewayUrl || !webhookToken) return;

  const batch = entries.splice(0, DLQ_RETRY_BATCH);
  const failed = [];

  for (const entry of batch) {
    try {
      const url = `${config.openclawGatewayUrl}${entry.webhookPath}`;
      const controller = new AbortController();
      const timeoutId = setTimeout(() => controller.abort(), config.webhookDispatchTimeoutMs);

      const response = await fetch(url, {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          Authorization: `Bearer ${webhookToken}`,
        },
        body: JSON.stringify(entry.payload),
        signal: controller.signal,
      });

      clearTimeout(timeoutId);
      await response.text().catch(() => "");

      if (response.ok) {
        incrementMetric("webhook_dlq_retried_success_total");
        log("info", "dispatch", "DLQ retry succeeded", { path: entry.webhookPath });
      } else {
        entry.attempts++;
        entry.last_retry = new Date().toISOString();
        if (entry.attempts < 10) {
          failed.push(entry);
        } else {
          incrementMetric("webhook_dlq_expired_total");
          log("warn", "dispatch", "DLQ entry expired after max attempts", { path: entry.webhookPath, attempts: entry.attempts });
        }
      }
    } catch (err) {
      entry.attempts++;
      entry.last_retry = new Date().toISOString();
      if (entry.attempts < 10) {
        failed.push(entry);
      }
    }
  }

  // Re-save: failed retries + remaining unprocessed entries
  const remaining = [...failed, ...entries];
  try {
    await saveDlq(remaining);
  } catch (err) {
    log("warn", "dispatch", "Failed to save DLQ after retry", { error: err.message });
  }
}

// =============================================================================
// MCP JWT CACHE
// =============================================================================

let mcpJwtCache = { token: null, expiresAt: 0 };
let mcpAuthNegativeCache = 0; // timestamp when negative cache expires
let mcpJwtExchangePromise = null; // dedup: only one JWT exchange in-flight at a time

/**
 * Get an auth token for MCP calls.
 * - legacy-rest mode: returns the raw API key as Bearer token
 * - mcp-jsonrpc mode: exchanges API key for JWT via /auth/token, caches result
 * - Negative cache: skips JWT exchange for 60s after failure to avoid latency loops
 * - Deduplication: concurrent callers share a single in-flight exchange to avoid thundering herd
 */
async function getMcpAuthToken() {
  if (!config.mcpAuth) return null;

  // Legacy REST mode: use raw API key directly
  if (config.mcpAuthMode === "legacy-rest") {
    return config.mcpAuth;
  }

  // Check cached JWT
  if (mcpJwtCache.token && Date.now() < mcpJwtCache.expiresAt) {
    return mcpJwtCache.token;
  }

  // Skip JWT exchange if we recently failed (avoid 3x latency per MCP call)
  if (Date.now() < mcpAuthNegativeCache) {
    return config.mcpAuth;
  }

  // Dedup: if an exchange is already in-flight, await it instead of starting another
  if (mcpJwtExchangePromise) {
    return await mcpJwtExchangePromise;
  }

  // Exchange API key for JWT (single in-flight request)
  mcpJwtExchangePromise = (async () => {
    try {
      const controller = new AbortController();
      const timeoutId = setTimeout(() => controller.abort(), 10000);

      const response = await fetch(`${config.mcpUrl}/auth/token`, {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
        },
        body: JSON.stringify({ api_key: config.mcpAuth }),
        signal: controller.signal,
      });

      clearTimeout(timeoutId);

      if (!response.ok) {
        log("warn", "mcp", "JWT exchange failed, falling back to raw key", { status: response.status });
        mcpAuthNegativeCache = Date.now() + 60000;
        return config.mcpAuth;
      }

      const data = await response.json();
      const token = data.access_token || data.token;
      if (token) {
        mcpAuthNegativeCache = 0; // Clear negative cache on success
        mcpJwtCache = {
          token,
          expiresAt: Date.now() + config.mcpJwtTtlMs,
        };
        return token;
      }

      mcpAuthNegativeCache = Date.now() + 60000;
      return config.mcpAuth;
    } catch (err) {
      log("warn", "mcp", "JWT exchange error, falling back to raw key", { error: err.message });
      mcpAuthNegativeCache = Date.now() + 60000;
      return config.mcpAuth;
    }
  })();

  try {
    return await mcpJwtExchangePromise;
  } finally {
    mcpJwtExchangePromise = null;
  }
}

// =============================================================================
// MCP SESSION STATE
// =============================================================================

// Tracks the MCP session ID returned by the server (reused across tool calls)
let mcpSessionId = null;

// Whether we've completed the MCP initialize handshake for the current session
let mcpSessionInitialized = false;

// Dedup guard: in-flight session init promise (prevents concurrent callers from racing)
let mcpSessionInitPromise = null;

// MCP protocol version to negotiate with the server
const MCP_PROTOCOL_VERSION = "2025-03-26";

/**
 * Perform the MCP initialize handshake (required by MCP spec before tools/call).
 * Sends initialize request, captures session ID, then sends notifications/initialized.
 * No-op if already initialized for the current session or in legacy-rest mode.
 */
async function ensureMcpSession() {
  if (config.mcpAuthMode === "legacy-rest") return;
  if (mcpSessionInitialized && mcpSessionId) return;
  if (!config.mcpUrl) return;

  // Dedup: if an init is already in-flight, await it instead of starting another
  if (mcpSessionInitPromise) {
    return await mcpSessionInitPromise;
  }

  mcpSessionInitPromise = _doMcpSessionInit();
  try {
    return await mcpSessionInitPromise;
  } finally {
    mcpSessionInitPromise = null;
  }
}

async function _doMcpSessionInit() {
  const authToken = await getMcpAuthToken();

  try {
    const controller = new AbortController();
    const timeoutId = setTimeout(() => controller.abort(), config.mcpTimeoutMs || 30000);

    // Step 1: Send "initialize" request
    const initResponse = await fetch(`${config.mcpUrl}/mcp`, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        "MCP-Protocol-Version": MCP_PROTOCOL_VERSION,
        ...(authToken && { Authorization: `Bearer ${authToken}` }),
      },
      body: JSON.stringify({
        jsonrpc: "2.0",
        id: "init-1",
        method: "initialize",
        params: {
          protocolVersion: MCP_PROTOCOL_VERSION,
          capabilities: {},
          clientInfo: { name: "wazuh-autopilot", version: "1.0.0" },
        },
      }),
      signal: controller.signal,
    });

    clearTimeout(timeoutId);

    // Capture session ID from response header
    const sessionId = initResponse.headers.get("mcp-session-id");
    if (sessionId) {
      mcpSessionId = sessionId;
    }

    if (!initResponse.ok) {
      log("warn", "mcp", "MCP initialize failed, will retry on next call", { status: initResponse.status });
      await initResponse.text().catch(() => "");
      return;
    }

    const initData = await initResponse.json();
    if (initData.jsonrpc === "2.0" && initData.error) {
      log("warn", "mcp", "MCP initialize returned error", { error: initData.error.message });
      return;
    }

    log("info", "mcp", "MCP session initialized", {
      session_id: mcpSessionId,
      server: initData.result?.serverInfo?.name,
      protocol: initData.result?.protocolVersion,
    });

    // Step 2: Send "notifications/initialized" (no id — it's a notification, no response expected)
    const controller2 = new AbortController();
    const timeoutId2 = setTimeout(() => controller2.abort(), 5000);

    try {
      const notifResp = await fetch(`${config.mcpUrl}/mcp`, {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          "MCP-Protocol-Version": MCP_PROTOCOL_VERSION,
          ...(mcpSessionId && { "MCP-Session-Id": mcpSessionId }),
          ...(authToken && { Authorization: `Bearer ${authToken}` }),
        },
        body: JSON.stringify({
          jsonrpc: "2.0",
          method: "notifications/initialized",
        }),
        signal: controller2.signal,
      });
      await notifResp.text().catch(() => ""); // drain response body
    } finally {
      clearTimeout(timeoutId2);
    }

    mcpSessionInitialized = true;
  } catch (err) {
    log("warn", "mcp", "MCP session init error, tool calls will proceed without session", { error: err.message });
  }
}

/**
 * Invalidate the current MCP session (e.g., on 404 "session not found").
 * Next tool call will re-initialize.
 */
function invalidateMcpSession() {
  mcpSessionId = null;
  mcpSessionInitialized = false;
  mcpSessionInitPromise = null;
}

// =============================================================================
// IP ENRICHMENT
// =============================================================================

const enrichmentCache = new Map();
const MAX_ENRICHMENT_CACHE_SIZE = 10000;

function isPrivateIp(ip) {
  if (!ip || typeof ip !== "string") return true;
  const parts = ip.split(".");
  if (parts.length !== 4) return true;
  const a = parseInt(parts[0], 10);
  const b = parseInt(parts[1], 10);
  // 10.0.0.0/8
  if (a === 10) return true;
  // 172.16.0.0/12
  if (a === 172 && b >= 16 && b <= 31) return true;
  // 192.168.0.0/16
  if (a === 192 && b === 168) return true;
  // 127.0.0.0/8 (loopback)
  if (a === 127) return true;
  // 0.0.0.0/8
  if (a === 0) return true;
  // 169.254.0.0/16 (link-local / APIPA)
  if (a === 169 && b === 254) return true;
  // 100.64.0.0/10 (CGNAT / Tailscale)
  if (a === 100 && b >= 64 && b <= 127) return true;
  return false;
}

async function enrichIpAddress(ip) {
  if (!config.enrichmentEnabled || !config.abuseIpdbApiKey) return null;
  if (isPrivateIp(ip)) return null;

  // Check cache
  const cached = enrichmentCache.get(ip);
  if (cached) {
    if (Date.now() < cached.expiresAt) {
      incrementMetric("enrichment_cache_hits_total");
      return cached.data;
    }
    enrichmentCache.delete(ip);
  }

  incrementMetric("enrichment_requests_total");

  try {
    const controller = new AbortController();
    const timeoutId = setTimeout(() => controller.abort(), config.enrichmentTimeoutMs);

    const response = await fetch(
      `https://api.abuseipdb.com/api/v2/check?ipAddress=${encodeURIComponent(ip)}&maxAgeInDays=90`,
      {
        method: "GET",
        headers: {
          Accept: "application/json",
          Key: config.abuseIpdbApiKey,
        },
        signal: controller.signal,
      },
    );

    clearTimeout(timeoutId);

    if (!response.ok) {
      incrementMetric("enrichment_errors_total");
      // Cache errors with shorter TTL to avoid hammering the API
      if (enrichmentCache.size < MAX_ENRICHMENT_CACHE_SIZE) {
        enrichmentCache.set(ip, { data: null, expiresAt: Date.now() + config.enrichmentErrorCacheTtlMs });
      }
      return null;
    }

    const body = await response.json();
    const d = body.data || {};
    const result = {
      source: "abuseipdb",
      abuse_confidence_score: d.abuseConfidenceScore,
      isp: d.isp || null,
      domain: d.domain || null,
      country_code: d.countryCode || null,
      total_reports: d.totalReports || 0,
      is_tor: d.isTor || false,
      last_reported_at: d.lastReportedAt || null,
      checked_at: new Date().toISOString(),
    };

    // Cache successful result
    if (enrichmentCache.size >= MAX_ENRICHMENT_CACHE_SIZE) {
      // Evict oldest entry
      const firstKey = enrichmentCache.keys().next().value;
      enrichmentCache.delete(firstKey);
    }
    enrichmentCache.set(ip, { data: result, expiresAt: Date.now() + config.enrichmentCacheTtlMs });
    return result;
  } catch (err) {
    incrementMetric("enrichment_errors_total");
    log("warn", "enrichment", "IP enrichment failed", { ip, error: err.message });
    // Cache errors with shorter TTL
    if (enrichmentCache.size < MAX_ENRICHMENT_CACHE_SIZE) {
      enrichmentCache.set(ip, { data: null, expiresAt: Date.now() + config.enrichmentErrorCacheTtlMs });
    }
    return null;
  }
}

// =============================================================================
// ALERT GROUPING (Entity-Based Correlation)
// =============================================================================

// Maps "type:value" → [{caseId, severity, createdAt, isFalsePositive}]
const entityCaseIndex = new Map();
const MAX_ENTITY_INDEX_SIZE = 50000;
let entityIndexWarningLogged = false;

function indexCaseEntities(caseId, entities, severity) {
  if (!config.alertGroupEnabled) return;
  const now = Date.now();
  for (const entity of entities) {
    const key = `${entity.type}:${entity.value}`;
    if (!entityCaseIndex.has(key)) {
      if (entityCaseIndex.size >= MAX_ENTITY_INDEX_SIZE) {
        log("error", "entity-index", "Entity index full — new entities are being skipped", { size: entityCaseIndex.size, limit: MAX_ENTITY_INDEX_SIZE });
        continue;
      }
      if (!entityIndexWarningLogged && entityCaseIndex.size >= MAX_ENTITY_INDEX_SIZE * 0.9) {
        log("warn", "entity-index", "Entity index at 90% capacity", { size: entityCaseIndex.size, limit: MAX_ENTITY_INDEX_SIZE });
        entityIndexWarningLogged = true;
      }
      entityCaseIndex.set(key, []);
    }
    const entries = entityCaseIndex.get(key);
    // Don't add duplicate case entries
    if (!entries.some((e) => e.caseId === caseId)) {
      entries.push({ caseId, severity, createdAt: now, isFalsePositive: false });
    }
  }
}

function findRelatedCase(entities) {
  if (!config.alertGroupEnabled || entities.length === 0) return null;

  const now = Date.now();
  const windowStart = now - config.alertGroupWindowMs;
  const caseScores = new Map(); // caseId → {matches, severity}

  for (const entity of entities) {
    const key = `${entity.type}:${entity.value}`;
    const entries = entityCaseIndex.get(key);
    if (!entries) continue;

    for (const entry of entries) {
      if (entry.isFalsePositive) continue;
      if (entry.createdAt < windowStart) continue;

      if (!caseScores.has(entry.caseId)) {
        caseScores.set(entry.caseId, { matches: 0, severity: entry.severity });
      }
      caseScores.get(entry.caseId).matches++;
    }
  }

  if (caseScores.size === 0) return null;

  // Pick case with most entity matches, tiebreak by severity
  const severityRank = { critical: 4, high: 3, medium: 2, low: 1, informational: 0 };
  let bestCaseId = null;
  let bestScore = { matches: 0, rank: -1 };

  for (const [caseId, score] of caseScores) {
    const rank = severityRank[score.severity] || 0;
    if (
      score.matches > bestScore.matches ||
      (score.matches === bestScore.matches && rank > bestScore.rank)
    ) {
      bestCaseId = caseId;
      bestScore = { matches: score.matches, rank };
    }
  }

  return bestCaseId;
}

function markEntityFalsePositive(caseId) {
  for (const [, entries] of entityCaseIndex) {
    for (const entry of entries) {
      if (entry.caseId === caseId) {
        entry.isFalsePositive = true;
      }
    }
  }
}

// =============================================================================
// EVIDENCE PACK MANAGEMENT
// =============================================================================

const EVIDENCE_PACK_SCHEMA_VERSION = "1.0";

// Atomic file write: write to temp then rename (prevents corruption on crash)
async function atomicWriteFile(filePath, content) {
  const tmpPath = `${filePath}.tmp.${process.pid}`;
  await fs.writeFile(tmpPath, content);
  await fs.rename(tmpPath, filePath);
}

// Per-case async mutex to prevent lost-update on concurrent updateCase calls.
// Uses a proper queue pattern so 3+ concurrent callers are serialized correctly.
const MAX_CASE_LOCKS = 10000;
const caseLocks = new Map();
async function withCaseLock(caseId, fn) {
  let lock = caseLocks.get(caseId);
  if (!lock) {
    // Evict oldest lock entries if we hit the cap (prevents unbounded growth)
    if (caseLocks.size >= MAX_CASE_LOCKS) {
      for (const [oldId, oldLock] of caseLocks) {
        if (!oldLock.running && oldLock.queue.length === 0) {
          caseLocks.delete(oldId);
          break;
        }
      }
    }
    lock = { queue: [], running: false };
    caseLocks.set(caseId, lock);
  }
  if (lock.running) {
    await new Promise((resolve) => lock.queue.push(resolve));
  }
  lock.running = true;
  try {
    return await fn();
  } finally {
    lock.running = false;
    if (lock.queue.length > 0) {
      lock.queue.shift()();
    } else {
      caseLocks.delete(caseId);
    }
  }
}

async function ensureDir(dirPath) {
  try {
    await fs.mkdir(dirPath, { recursive: true });
  } catch (err) {
    if (err.code !== "EEXIST") throw err;
  }
}

async function createCase(caseId, data) {
  if (!isValidCaseId(caseId)) {
    throw new Error(`Invalid case ID: ${caseId}`);
  }

  return withCaseLock(caseId, async () => {
    const caseDir = path.join(config.dataDir, "cases", caseId);
    const packPath = path.join(caseDir, "evidence-pack.json");

    // Check if case already exists to prevent silent overwrite
    try {
      await fs.access(packPath);
      throw new Error(`Case already exists: ${caseId}`);
    } catch (err) {
      if (err.message.startsWith("Case already exists")) throw err;
      // ENOENT is expected — case doesn't exist yet
    }

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
      status: "open",
      status_history: [{ from: null, to: "open", timestamp: now }],
      feedback: [],
    };

    await atomicWriteFile(
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

    await atomicWriteFile(
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
  });
}

async function updateCase(caseId, updates) {
  if (!isValidCaseId(caseId)) {
    throw new Error(`Invalid case ID: ${caseId}`);
  }

  // Use per-case lock to prevent lost-update on concurrent updateCase calls
  return withCaseLock(caseId, async () => {
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

    // Status transition validation — enforce valid pipeline progression
    if (Object.prototype.hasOwnProperty.call(updates, "status")) {
      const VALID_STATUS_TRANSITIONS = {
        open: ["triaged", "false_positive", "closed"],
        triaged: ["correlated", "false_positive", "closed"],
        correlated: ["investigated", "false_positive", "closed"],
        investigated: ["planned", "false_positive", "closed"],
        planned: ["approved", "rejected", "false_positive", "closed"],
        approved: ["executed", "false_positive", "closed"],
        executed: ["closed", "false_positive"],
        rejected: ["open", "closed"],
        false_positive: ["open"],
        closed: [], // Terminal state — no transitions allowed
      };
      const currentStatus = evidencePack.status || "open";
      const allowed = VALID_STATUS_TRANSITIONS[currentStatus];
      if (allowed && !allowed.includes(updates.status)) {
        throw new Error(`Invalid status transition: ${currentStatus} → ${updates.status}. Allowed: ${allowed.join(", ")}`);
      }
    }

    // Bug #14 fix: Use hasOwnProperty to allow falsy values (0, "", etc.)
    if (Object.prototype.hasOwnProperty.call(updates, "title")) evidencePack.title = updates.title;
    if (Object.prototype.hasOwnProperty.call(updates, "summary")) evidencePack.summary = updates.summary;
    if (Object.prototype.hasOwnProperty.call(updates, "severity")) evidencePack.severity = updates.severity;
    if (Object.prototype.hasOwnProperty.call(updates, "confidence")) evidencePack.confidence = updates.confidence;
    if (Object.prototype.hasOwnProperty.call(updates, "status")) {
      // Track status transition history
      if (!evidencePack.status_history) { evidencePack.status_history = []; }
      evidencePack.status_history.push({
        from: evidencePack.status,
        to: updates.status,
        timestamp: now,
      });
      evidencePack.status = updates.status;
      stalledRedispatchCounts.delete(caseId); // Reset backoff counter on status transition
    }

    // Append arrays with size cap to prevent unbounded growth
    const MAX_ARRAY_ITEMS = 10000;
    const appendCapped = (existing, incoming) => {
      const merged = [...existing, ...incoming];
      return merged.length > MAX_ARRAY_ITEMS ? merged.slice(-MAX_ARRAY_ITEMS) : merged;
    };

    if (updates.entities) {
      // Deduplicate entities by (type, value) tuple to prevent bloat from grouped alerts
      const existing = new Map((evidencePack.entities || []).map(e => [`${e.type}:${e.value}`, e]));
      for (const entity of updates.entities) {
        const key = `${entity.type}:${entity.value}`;
        if (!existing.has(key)) {
          existing.set(key, entity);
        }
      }
      const merged = [...existing.values()];
      evidencePack.entities = merged.length > MAX_ARRAY_ITEMS ? merged.slice(-MAX_ARRAY_ITEMS) : merged;
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
    // Feedback: replace entire array (legacy callers) or atomic append (race-safe)
    if (updates.feedback) {
      evidencePack.feedback = updates.feedback;
    }
    if (updates.appendFeedback) {
      if (!evidencePack.feedback) evidencePack.feedback = [];
      evidencePack.feedback.push(updates.appendFeedback);
    }

    // MITRE ATT&CK mapping — normalize to array and merge
    if (updates.mitre !== undefined) {
      const incoming = Array.isArray(updates.mitre) ? updates.mitre : [updates.mitre];
      const existing = Array.isArray(evidencePack.mitre) ? evidencePack.mitre : (evidencePack.mitre ? [evidencePack.mitre] : []);
      // Deduplicate by technique ID — prioritize technique_id over technique (which may be the name)
      const mitreKey = (m) => m.technique_id || m.id || (m.technique && /^T\d{4}/.test(m.technique) ? m.technique : null) || JSON.stringify(m);
      const seen = new Map(existing.map(m => [mitreKey(m), m]));
      for (const m of incoming) {
        const key = mitreKey(m);
        if (!seen.has(key)) seen.set(key, m);
      }
      evidencePack.mitre = [...seen.values()];
    }

    // Triage agent auto-verdict — direct assignment (latest wins, separate from analyst feedback verdict)
    if (updates.auto_verdict !== undefined) evidencePack.auto_verdict = updates.auto_verdict;
    if (updates.verdict_reason !== undefined) evidencePack.verdict_reason = updates.verdict_reason;

    // Agent investigation/correlation output fields — direct assignment (latest wins)
    if (updates.investigation_notes !== undefined) evidencePack.investigation_notes = updates.investigation_notes;
    if (updates.findings !== undefined) {
      evidencePack.findings = updates.findings;
      // Promote findings severity/confidence to top-level case fields so the
      // investigation agent's assessment overwrites the initial triage values.
      const FINDINGS_VALID_SEVERITIES = ["informational", "low", "medium", "high", "critical"];
      if (updates.findings.severity && FINDINGS_VALID_SEVERITIES.includes(updates.findings.severity)) {
        evidencePack.severity = updates.findings.severity;
      }
      if (typeof updates.findings.confidence === "number" && updates.findings.confidence >= 0 && updates.findings.confidence <= 1) {
        // Only promote if investigation confidence is higher than current
        if (updates.findings.confidence > (evidencePack.confidence || 0)) {
          evidencePack.confidence = updates.findings.confidence;
        }
      }
      // Promote classification to title prefix and auto_verdict when investigation
      // reveals a different picture than initial triage (e.g. single failure → brute_force)
      if (updates.findings.classification && typeof updates.findings.classification === "string") {
        const classification = updates.findings.classification.replace(/_/g, " ");
        const severity = (updates.findings.severity || evidencePack.severity || "unknown").toUpperCase();
        const currentTitle = evidencePack.title || "";
        // Only update title if the classification isn't already reflected
        if (!currentTitle.toLowerCase().includes(classification.toLowerCase())) {
          const host = (evidencePack.entities || []).find(e => e.type === "host")?.value || "unknown host";
          const source = (evidencePack.entities || []).find(e => e.type === "ip" && e.role === "source")?.value || "";
          evidencePack.title = `[${severity}] ${classification.charAt(0).toUpperCase() + classification.slice(1)} detected on ${host}${source ? ` from ${source}` : ""}`;
        }
        // Update auto_verdict to match findings classification
        evidencePack.auto_verdict = updates.findings.classification;
      }
    }
    if (updates.pivot_results !== undefined) evidencePack.pivot_results = updates.pivot_results;
    if (updates.enrichment_data !== undefined) evidencePack.enrichment_data = updates.enrichment_data;
    if (updates.key_questions_answered !== undefined) evidencePack.key_questions_answered = updates.key_questions_answered;
    if (updates.recommended_response !== undefined) evidencePack.recommended_response = updates.recommended_response;
    if (updates.correlation !== undefined) evidencePack.correlation = updates.correlation;
    if (updates.related_cases !== undefined) evidencePack.related_cases = updates.related_cases;
    // iocs_identified or iocs — normalize to iocs_identified
    if (updates.iocs_identified !== undefined) evidencePack.iocs_identified = updates.iocs_identified;
    if (updates.iocs !== undefined) evidencePack.iocs_identified = updates.iocs;

    await atomicWriteFile(packPath, JSON.stringify(evidencePack, null, 2));

    // Update summary
    const summaryPath = path.join(caseDir, "case.json");
    try {
      const summaryContent = await fs.readFile(summaryPath, "utf8");
      const summary = JSON.parse(summaryContent);
      summary.updated_at = now;
      if (Object.prototype.hasOwnProperty.call(updates, "title")) summary.title = updates.title;
      if (Object.prototype.hasOwnProperty.call(updates, "severity")) summary.severity = updates.severity;
      if (Object.prototype.hasOwnProperty.call(updates, "status")) summary.status = updates.status;
      // Sync findings-promoted fields to summary (investigation agent override)
      if (updates.findings) {
        const FINDINGS_VALID_SEVERITIES = ["informational", "low", "medium", "high", "critical"];
        if (updates.findings.severity && FINDINGS_VALID_SEVERITIES.includes(updates.findings.severity)) {
          summary.severity = updates.findings.severity;
        }
        // Sync promoted title from findings classification
        if (evidencePack.title) {
          summary.title = evidencePack.title;
        }
      }
      await atomicWriteFile(summaryPath, JSON.stringify(summary, null, 2));
    } catch (err) {
      // Summary file might not exist, that's ok
    }

    incrementMetric("cases_updated_total");
    log("info", "evidence-pack", "Case updated", { case_id: caseId });

    // Dispatch to downstream agents based on status transitions
    if (Object.prototype.hasOwnProperty.call(updates, "status")) {
      const statusWebhooks = {
        triaged: "/webhook/case-created",       // → correlation agent
        correlated: "/webhook/investigation-request", // → investigation agent
        investigated: "/webhook/plan-request",   // → response-planner agent
        planned: "/webhook/policy-check",        // → policy-guard agent
        approved: "/webhook/execute-action",     // → responder agent
      };
      const webhookPath = statusWebhooks[updates.status];
      if (webhookPath) {
        // NOTE: Callback URLs are in each agent's AGENTS.md (system prompt), not here.
        // OpenClaw wraps webhook content in EXTERNAL_UNTRUSTED_CONTENT which blocks
        // tool invocations from the message body. Agents read case_id from the data
        // below and use the URL templates from their system prompt.
        const statusMessages = {
          triaged: `New correlation task. Case ID: ${caseId}. Severity: ${evidencePack.severity}. Search for related alerts, identify attack patterns, and advance the pipeline per your AGENTS.md instructions.`,
          correlated: `New investigation task. Case ID: ${caseId}. Severity: ${evidencePack.severity}. Perform deep analysis using MCP tools, then advance the pipeline per your AGENTS.md instructions.`,
          investigated: `New response planning task. Case ID: ${caseId}. Severity: ${evidencePack.severity}. Title: ${evidencePack.title || ""}. Summary: ${(evidencePack.summary || "").substring(0, 500)}. Investigation notes: ${(evidencePack.investigation_notes || "No investigation notes available.").substring(0, 2000)}. Recommended response: ${JSON.stringify((evidencePack.recommended_response || []).slice(0, 5))}. IOCs: ${JSON.stringify((evidencePack.iocs_identified || evidencePack.iocs || []).slice(0, 10))}. Entities: ${JSON.stringify((evidencePack.entities || []).slice(0, 10))}. Create a response plan per your AGENTS.md instructions.`,
          // planned and approved messages are built below after plan_id lookup
          planned: null,
          approved: null,
        };
        // Issue #22 fix: Include plan_id for "planned" and "approved" statuses.
        // plan_id MUST be in the message text — OpenClaw only shows the message to the agent,
        // not the JSON payload fields. Without it, LLMs fabricate plan IDs from case IDs.
        let resolvedPlanId = null;
        if (updates.status === "planned" || updates.status === "approved") {
          const targetState = updates.status === "planned" ? "proposed" : "approved";
          for (const [planId, plan] of responsePlans.entries()) {
            if (plan.case_id === caseId && plan.state === targetState) {
              resolvedPlanId = planId;
              // Don't break — keep iterating to find the LAST (most recent) match
            }
          }
        }
        if (updates.status === "planned") {
          statusMessages.planned = `New policy evaluation task. Case ID: ${caseId}. Plan ID: ${resolvedPlanId || "UNKNOWN"}.  Severity: ${evidencePack.severity}. Review the response plan and check all policy rules, risk levels, and approval requirements per your AGENTS.md instructions.`;
        }
        if (updates.status === "approved") {
          statusMessages.approved = `New execution task. Case ID: ${caseId}. Plan ID: ${resolvedPlanId || "UNKNOWN"}. Severity: ${evidencePack.severity}. Execute the approved plan using the Plan ID above — do NOT construct or guess the plan_id.`;
        }
        const dispatchPayload = {
          message: statusMessages[updates.status] || `Process case ${caseId} — status changed to ${updates.status}.`,
          case_id: caseId,
          status: updates.status,
          severity: evidencePack.severity,
          trigger: "status_change",
        };
        if (resolvedPlanId) {
          dispatchPayload.plan_id = resolvedPlanId;
          const resolvedPlan = responsePlans.get(resolvedPlanId);
          if (resolvedPlan) {
            dispatchPayload.risk_level = resolvedPlan.risk_level;
            dispatchPayload.actions_count = resolvedPlan.actions ? resolvedPlan.actions.length : 0;
          }
        }
        dispatchToGateway(webhookPath, dispatchPayload).catch((err) => {
          log("warn", "dispatch", "Failed to dispatch status change webhook", { case_id: caseId, status: updates.status, error: err.message });
          incrementMetric("webhook_dispatch_failures_total");
        });
      }
    }

    return evidencePack;
  }); // end withCaseLock
}

async function getCase(caseId) {
  if (!isValidCaseId(caseId)) {
    throw new Error(`Invalid case ID: ${caseId}`);
  }
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
      if (new Date(data.expires_at).getTime() < now || data.used) {
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

  // Prevent double-use: check before setting (atomic in single-threaded Node.js)
  if (tokenData.used) return null;

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
const MAX_ACTIONS_PER_PLAN = 10;
// Bug #7 fix: Track plans currently being executed to prevent race conditions
const executingPlans = new Set();

// Plan persistence: save plan to disk so it survives service restarts
async function savePlanToDisk(plan) {
  try {
    const plansDir = path.join(config.dataDir, "plans");
    await ensureDir(plansDir);
    await atomicWriteFile(
      path.join(plansDir, `${plan.plan_id}.json`),
      JSON.stringify(plan, null, 2),
    );
  } catch (err) {
    log("warn", "plans", "Failed to persist plan to disk", {
      plan_id: plan.plan_id,
      error: err.message,
    });
  }
}

// Load all plans from disk on startup
async function loadPlansFromDisk() {
  const plansDir = path.join(config.dataDir, "plans");
  try {
    await ensureDir(plansDir);
    const entries = await fs.readdir(plansDir);
    let loaded = 0;
    for (const entry of entries) {
      if (!entry.endsWith(".json")) continue;
      try {
        const content = await fs.readFile(path.join(plansDir, entry), "utf8");
        const plan = JSON.parse(content);
        if (plan.plan_id) {
          responsePlans.set(plan.plan_id, plan);
          loaded++;
        }
      } catch (err) {
        // H5 audit fix: Log corrupted plan files for operational visibility
        log("warn", "plans", "Skipped corrupt plan file during load", {
          file: entry,
          error: err.message,
        });
      }
    }
    if (loaded > 0) {
      log("info", "plans", "Loaded plans from disk", { count: loaded });
    }

    // Crash recovery: reset any plans stuck in EXECUTING state
    // If the process crashed mid-executePlan(), the plan is persisted as EXECUTING
    // but cannot be re-executed (requires APPROVED) or re-approved (requires PROPOSED).
    // Reset them to FAILED so operators can investigate and re-create if needed.
    let recovered = 0;
    for (const [planId, plan] of responsePlans.entries()) {
      if (plan.state === "executing") {
        plan.state = "failed";
        plan.execution_result = {
          success: false,
          reason: "Process crashed during execution — plan state recovered on restart",
        };
        plan.updated_at = new Date().toISOString();
        log("warn", "plans", "Recovered stuck EXECUTING plan on startup", {
          plan_id: planId,
          case_id: plan.case_id,
        });
        await savePlanToDisk(plan);
        recovered++;
      }
    }
    if (recovered > 0) {
      log("warn", "plans", "Crash recovery: reset EXECUTING plans to FAILED", { count: recovered });
    }
  } catch {
    // Plans directory doesn't exist yet — will be created on first plan
  }
}

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

// Audit fix C2: Allowed action types for response plans.
// Only Wazuh Active Response commands that the MCP server supports are permitted.
// Any plan containing an unknown action type is rejected at creation time.
const ALLOWED_ACTION_TYPES = new Set([
  "block_ip",
  "firewall_drop",
  "host_deny",
  "isolate_host",
  "kill_process",
  "disable_user",
  "quarantine_file",
  "restart_wazuh",
  "active_response",
]);

// Issue #6 fix: Validate action structure
function validatePlanAction(action, index) {
  const errors = [];
  if (!action.type || typeof action.type !== "string") {
    errors.push(`Action ${index}: missing or invalid 'type' field`);
  }
  if (action.type && typeof action.type === "string" && !ALLOWED_ACTION_TYPES.has(action.type)) {
    errors.push(`Action ${index}: unknown action type '${action.type}'. Allowed: ${[...ALLOWED_ACTION_TYPES].join(", ")}`);
  }
  if (!action.target || typeof action.target !== "string") {
    errors.push(`Action ${index}: missing or invalid 'target' field`);
  }
  // Action-specific required parameter validation (Wazuh MCP Server v4.2.1)
  if (action.type === "kill_process") {
    if (!action.params || !action.params.process_id || (typeof action.params.process_id !== "number" || !Number.isInteger(action.params.process_id) || action.params.process_id <= 0)) {
      errors.push(`Action ${index}: 'kill_process' requires params.process_id as a positive integer`);
    }
  }
  if (action.type === "disable_user") {
    if (!action.params || !action.params.username || typeof action.params.username !== "string" || action.params.username.trim() === "") {
      errors.push(`Action ${index}: 'disable_user' requires params.username as a non-empty string`);
    }
  }
  if (action.type === "quarantine_file") {
    if (!action.params || !action.params.file_path || typeof action.params.file_path !== "string" || action.params.file_path.trim() === "") {
      errors.push(`Action ${index}: 'quarantine_file' requires params.file_path as a non-empty string`);
    }
  }
  // Rollback metadata validation (optional fields)
  // Coerce string booleans from LLMs (e.g. "true"/"false") to actual booleans
  if (action.rollback_available !== undefined) {
    if (typeof action.rollback_available === "string") {
      const lower = action.rollback_available.toLowerCase().trim();
      if (lower === "true") { action.rollback_available = true; }
      else if (lower === "false") { action.rollback_available = false; }
      else { errors.push(`Action ${index}: 'rollback_available' must be a boolean`); }
    } else if (typeof action.rollback_available !== "boolean") {
      errors.push(`Action ${index}: 'rollback_available' must be a boolean`);
    }
  }
  if (action.rollback_command !== undefined && typeof action.rollback_command !== "string") {
    errors.push(`Action ${index}: 'rollback_command' must be a string`);
  }
  if (action.rollback_note !== undefined && typeof action.rollback_note !== "string") {
    errors.push(`Action ${index}: 'rollback_note' must be a string`);
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

    // Policy enforcement: check time window for response planning
    const twResult = policyCheckTimeWindow("response_planning");
    if (!twResult.allowed) {
      incrementMetric("policy_denies_total", { reason: "time_window_denied", action: "response_planning" });
      log("warn", "policy", "Response planning denied by time window", { reason: twResult.reason });
      throw new Error(`Time window denied: ${twResult.reason}`);
    }

    // Policy enforcement: check each action against allowlist
    for (const action of planData.actions) {
      const policyResult = policyCheckAction(action.type, planData.confidence || 0);
      if (!policyResult.allowed) {
        incrementMetric("policy_denies_total", { reason: "action_denied", action: action.type });
        log("warn", "policy", "Action denied by policy", { action: action.type, reason: policyResult.reason });
        throw new Error(`Policy denied action '${action.type}': ${policyResult.reason}`);
      }
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
  savePlanToDisk(plan).catch((err) => {
    log("error", "plans", "Failed to persist plan to disk", { plan_id: planId, error: err.message });
  });
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

  // Dispatch to policy-guard agent for supplementary analysis
  dispatchToGateway("/webhook/policy-check", {
    message: `Review response plan ${planId} for case ${planData.case_id}. Risk level: ${plan.risk_level}, ${plan.actions.length} action(s) proposed. Validate actions against security policies and approve or flag concerns.`,
    plan_id: planId,
    case_id: planData.case_id,
    risk_level: plan.risk_level,
    actions_count: plan.actions.length,
    trigger: "plan_created",
  }).catch((err) => {
    log("warn", "dispatch", "Failed to dispatch plan-created webhook", { plan_id: planId, case_id: planData.case_id, error: err.message });
    incrementMetric("webhook_dispatch_failures_total");
  });

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
      savePlanToDisk(plan); // persist expiry
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

  for (const [planId, plan] of responsePlans.entries()) {
    // Trigger expiry check via getPlan (updates stale PROPOSED/APPROVED → EXPIRED)
    let freshPlan;
    try {
      freshPlan = getPlan(planId, { updateExpiry: true });
    } catch {
      continue; // Plan was deleted during iteration
    }
    // Filter by state (after expiry update)
    if (state && freshPlan.state !== state) continue;
    // Filter by case
    if (case_id && freshPlan.case_id !== case_id) continue;

    plans.push(freshPlan);
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
    savePlanToDisk(plan); // persist expired state to survive restarts
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

  savePlanToDisk(plan); // persist state change
  incrementMetric("plans_approved_total");
  log("info", "plans", "Plan approved (Tier 1)", {
    plan_id: planId,
    approver_id: approverId,
    case_id: plan.case_id,
  });

  // Sync case status to "approved" so stalled pipeline detector doesn't re-dispatch.
  // Skip if case is already in "approved" state (policy-guard may have set it first).
  if (plan.case_id) {
    getCase(plan.case_id).then((caseData) => {
      if (caseData.status !== "approved") {
        return updateCase(plan.case_id, { status: "approved" });
      }
    }).catch((err) => {
      if (!err.message.includes("Invalid status transition")) {
        log("warn", "plans", "Failed to sync case status on plan approval", {
          plan_id: planId,
          case_id: plan.case_id,
          error: err.message,
        });
      }
    });
  }

  return plan;
}

// Reject a plan
function rejectPlan(planId, rejectorId, reason = "") {
  // Bug #4 fix: Don't auto-update expiry in getPlan
  const plan = getPlan(planId, { updateExpiry: false });

  // Can reject from proposed or approved state (but not if currently executing)
  if (executingPlans.has(planId)) {
    throw new Error("Cannot reject plan that is currently executing");
  }
  if (!["proposed", "approved"].includes(plan.state)) {
    throw new Error(`Cannot reject plan in state: ${plan.state}`);
  }

  const now = new Date().toISOString();
  plan.state = PLAN_STATES.REJECTED;
  plan.rejector_id = rejectorId;
  plan.rejected_at = now;
  plan.rejection_reason = reason;
  plan.updated_at = now;
  savePlanToDisk(plan); // persist state change

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
    savePlanToDisk(plan); // persist expired state to survive restarts
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

  // Separation of duties: executor must differ from approver
  if (plan.approver_id && plan.approver_id === executorId) {
    throw new Error("Executor must be different from approver (separation of duties)");
  }

  // Bug #7 fix: Prevent concurrent execution of the same plan
  if (executingPlans.has(planId)) {
    throw new Error("Plan is already being executed");
  }

  // Enforce concurrent execution limit
  if (executingPlans.size >= config.maxConcurrentExecutions) {
    throw new Error(`Concurrent execution limit reached (${config.maxConcurrentExecutions} plans executing)`);
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

  // Policy enforcement: check time window for action execution
  const twExecResult = policyCheckTimeWindow("action_execution");
  if (!twExecResult.allowed) {
    incrementMetric("policy_denies_total", { reason: "time_window_denied", action: "action_execution" });
    log("warn", "policy", "Execution denied by time window", { plan_id: planId, reason: twExecResult.reason });
    plan.state = PLAN_STATES.FAILED;
    plan.updated_at = new Date().toISOString();
    plan.execution_result = { success: false, reason: twExecResult.reason };
    savePlanToDisk(plan); // persist state change
    executingPlans.delete(planId);
    incrementMetric("executions_failed_total");
    return plan;
  }

  // Execute actions
  const results = [];
  let allSuccess = true;

  // Resolve agent_id from case entities for actions that need it (e.g., block_ip)
  // This avoids hardcoding agent IDs and uses the actual reporting agent from the case
  let caseAgentId = null;
  try {
    const caseData = await getCase(plan.case_id);
    if (caseData) {
      const hostEntity = (caseData.entities || []).find(e => e.type === "host" && e.agent_id);
      if (hostEntity) {
        caseAgentId = hostEntity.agent_id;
        log("info", "plans", "Resolved agent_id from case entities", {
          plan_id: planId, agent_id: caseAgentId, host: hostEntity.value,
        });
      }
    }
  } catch { /* best effort */ }

  try {
    for (const action of plan.actions) {
      // Inject resolved agent_id for actions that need it
      if (caseAgentId && !action.agent_id && !(action.params && action.params.agent_id)) {
        action._case_agent_id = caseAgentId;
      }
      try {
      // Validate action has required fields
        if (!action.type || !action.target) {
          throw new Error("Action missing required fields: type, target");
        }

        // Issue #22 fix: Validate target format for IP-based actions.
        // LLMs sometimes resolve IPs to hostnames or use domain names.
        if (action.type === "block_ip" || action.type === "unblock_ip") {
          const ipv4 = /^(\d{1,3}\.){3}\d{1,3}$/;
          const ipv6 = /^([0-9a-fA-F]{0,4}:){2,7}[0-9a-fA-F]{0,4}$/;
          if (!ipv4.test(action.target) && !ipv6.test(action.target)) {
            log("warn", "plans", "block_ip target is not a valid IP address — possibly a hostname or domain", {
              plan_id: planId, target: action.target, action_type: action.type,
            });
            throw new Error(`Invalid target for ${action.type}: "${action.target}" is not a valid IP address. Expected IPv4 (e.g., 10.0.1.1) or IPv6 format.`);
          }
        }

        // Policy enforcement: idempotency check
        const idempResult = policyCheckIdempotency(action.type, action.target);
        if (!idempResult.allowed) {
          allSuccess = false;
          incrementMetric("policy_denies_total", { reason: "duplicate_action", action: action.type });
          log("warn", "policy", "Action denied by idempotency check", {
            plan_id: planId, action_type: action.type, target: action.target, reason: idempResult.reason,
          });
          results.push({
            action_type: action.type,
            target: action.target,
            status: "denied",
            reason: idempResult.reason,
            timestamp: new Date().toISOString(),
          });
          continue;
        }

        // Policy enforcement: rate limit check
        const rlResult = policyCheckActionRateLimit(action.type);
        if (!rlResult.allowed) {
          allSuccess = false;
          const rlReason = rlResult.reason.includes("global") ? "global_rate_limited" : "action_rate_limited";
          incrementMetric("policy_denies_total", { reason: rlReason, action: action.type });
          log("warn", "policy", "Action denied by rate limit", {
            plan_id: planId, action_type: action.type, reason: rlResult.reason,
          });
          results.push({
            action_type: action.type,
            target: action.target,
            status: "denied",
            reason: rlResult.reason,
            timestamp: new Date().toISOString(),
          });
          continue;
        }

        // Call MCP tool for the action with per-action timeout
        const correlationId = `${planId}-${action.type}-${Date.now()}`;
        const mcpParams = buildMcpParams(action);
        const actionTimeoutMs = config.mcpTimeoutMs * 2; // allow 2x MCP timeout per action
        const mcpResult = await Promise.race([
          callMcpTool(action.type, mcpParams, correlationId),
          new Promise((_, reject) =>
            setTimeout(() => reject(new Error(`Action timed out after ${actionTimeoutMs}ms`)), actionTimeoutMs)
          ),
        ]);

        // Check for MCP-level isError flag (HTTP 200 but tool returned error)
        // The MCP server may return HTTP 200 with isError: true in the response body
        const mcpIsError = mcpResult.data && mcpResult.data.isError === true;
        const actionSuccess = mcpResult.success && !mcpIsError;

        // Enrich error messages for common active-response failures
        let actionNote = undefined;
        if (mcpIsError) {
          const errText = mcpResult.data.content?.[0]?.text || "";
          log("warn", "plans", "MCP tool returned isError despite HTTP success", {
            plan_id: planId, action_type: action.type, target: action.target,
            mcp_error: errText,
          });
          // Detect "already applied" patterns from Wazuh 400 responses
          if (errText.includes("HTTP 400") || errText.includes("Bad Request")) {
            const arActions = { block_ip: "blocked", isolate_host: "isolated", disable_user: "disabled", quarantine_file: "quarantined", firewall_drop: "firewall-dropped", host_deny: "host-denied" };
            const verb = arActions[action.type] || "applied";
            actionNote = `Wazuh returned 400 — the target may already be ${verb}, or the active response command is not configured on this agent. Check iptables/agent status to confirm.`;
          }
        }

        // Record successful execution for rate limiting and dedup tracking
        if (actionSuccess) {
          recordActionExecution(action.type);
          recordActionForDedup(action.type, action.target);
        }

        results.push({
          action_type: action.type,
          target: action.target,
          status: actionSuccess ? "success" : "failed",
          mcp_response: mcpResult.data,
          ...(actionNote && { note: actionNote }),
          timestamp: new Date().toISOString(),
        });

        if (!actionSuccess) {
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
    const actionsDenied = results.filter((r) => r.status === "denied").length;
    plan.execution_result = {
      success: allSuccess,
      actions_total: plan.actions.length,
      actions_success: results.filter((r) => r.status === "success").length,
      actions_denied: actionsDenied,
      actions_failed: results.filter((r) => r.status === "failed" || r.status === "error").length,
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
    // Build mcp_calls records from execution results for evidence pack
    const mcpCallRecords = results
      .filter((r) => r.mcp_response)
      .map((r) => ({
        tool: r.action_type,
        target: r.target,
        status: r.status,
        timestamp: r.timestamp,
        plan_id: planId,
      }));

    try {
      await updateCase(plan.case_id, {
        status: "executed",
        actions: [
          {
            plan_id: planId,
            executed_at: plan.executed_at,
            executor_id: executorId,
            result: plan.execution_result,
          },
        ],
        ...(mcpCallRecords.length > 0 && { mcp_calls: mcpCallRecords }),
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
    // If plan is still EXECUTING (unexpected throw before state update), mark as FAILED
    if (plan.state === PLAN_STATES.EXECUTING) {
      plan.state = PLAN_STATES.FAILED;
      plan.updated_at = new Date().toISOString();
      incrementMetric("executions_failed_total");
    }
    savePlanToDisk(plan); // persist final state
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
const PROTO_POISON_KEYS = new Set(["__proto__", "constructor", "prototype"]);

function parseSimpleYaml(content) {
  const result = Object.create(null);
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
      // Fix: When list items are indented under their key (standard YAML style),
      // pendingListKey is on the parent stack entry. Look up the stack to find it.
      let listKey = current.pendingListKey;
      let targetObj = parent;
      if (!listKey && stack.length > 1) {
        const parentEntry = stack[stack.length - 2];
        if (parentEntry.pendingListKey) {
          listKey = parentEntry.pendingListKey;
          targetObj = parentEntry.obj;
        }
      }
      if (listKey) {
        // Ensure array exists (replaces the placeholder Object.create(null))
        if (!Array.isArray(targetObj[listKey])) {
          targetObj[listKey] = [];
        }
        // Bug #6 fix: Use indexOf to split on first colon only
        const colonIdx = value.indexOf(":");
        if (colonIdx > 0) {
          const obj = {};
          const k = value.substring(0, colonIdx).trim();
          const v = value.substring(colonIdx + 1).trim().replace(/^["']|["']$/g, "");
          obj[k] = v;
          targetObj[listKey].push(obj);
        } else {
          targetObj[listKey].push(value.replace(/^["']|["']$/g, ""));
        }
      }
      continue;
    }

    // Handle key: value pairs
    const colonIndex = trimmed.indexOf(":");
    if (colonIndex > 0) {
      const key = trimmed.substring(0, colonIndex).trim();
      // Reject prototype pollution keys
      if (PROTO_POISON_KEYS.has(key)) continue;
      // Bug #6 fix: Get everything after first colon
      let value = trimmed.substring(colonIndex + 1).trim();

      if (value === "" || value === "|" || value === ">") {
        // Nested object or list - set as pending list key
        parent[key] = Object.create(null);
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

    // H4 audit fix: Validate toolmap structure — each entry needs mcp_tool
    const validationErrors = [];
    for (const section of ["read_operations", "action_operations"]) {
      if (toolmapConfig[section] && typeof toolmapConfig[section] === "object") {
        for (const [name, entry] of Object.entries(toolmapConfig[section])) {
          if (!entry || typeof entry !== "object") {
            validationErrors.push(`${section}.${name}: not an object`);
          } else if (!entry.mcp_tool || typeof entry.mcp_tool !== "string") {
            validationErrors.push(`${section}.${name}: missing or invalid mcp_tool`);
          }
        }
      }
    }
    if (validationErrors.length > 0) {
      log("warn", "mcp", "Toolmap has validation warnings", {
        path: toolmapPath,
        errors: validationErrors.slice(0, 10),
      });
    }

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
        get_alert: { mcp_tool: "get_wazuh_alerts", enabled: true },
        search_alerts: { mcp_tool: "get_wazuh_alerts", enabled: true },
        search_events: { mcp_tool: "search_security_events", enabled: true },
        get_agent: { mcp_tool: "get_wazuh_agents", enabled: true },
        get_rule_info: { mcp_tool: "get_wazuh_rules_summary", enabled: true },
      },
      action_operations: {
        block_ip: { mcp_tool: "wazuh_block_ip", enabled: false, target_param: "ip_address" },
        isolate_host: { mcp_tool: "wazuh_isolate_host", enabled: false, target_param: "agent_id" },
        kill_process: { mcp_tool: "wazuh_kill_process", enabled: false, target_param: "agent_id" },
        disable_user: { mcp_tool: "wazuh_disable_user", enabled: false, target_param: "agent_id" },
        quarantine_file: { mcp_tool: "wazuh_quarantine_file", enabled: false, target_param: "agent_id" },
        firewall_drop: { mcp_tool: "wazuh_firewall_drop", enabled: false, target_param: "agent_id" },
        host_deny: { mcp_tool: "wazuh_host_deny", enabled: false, target_param: "agent_id" },
        restart_wazuh: { mcp_tool: "wazuh_restart", enabled: false, target_param: "agent_id" },
        active_response: { mcp_tool: "wazuh_active_response", enabled: false, target_param: "agent_id" },
      },
    };
    return toolmapConfig;
  }
}

// =============================================================================
// POLICY ENFORCEMENT (Inline checks against policies/policy.yaml)
// =============================================================================

let policyConfig = null;

// Action rate limit state (policy-driven, per-action + global counters)
const MAX_DEDUP_ENTRIES = 10000;
const actionRateLimitState = {
  perAction: new Map(),
  global: { hourly: { count: 0, resetTime: 0 }, daily: { count: 0, resetTime: 0 } },
};
const actionDeduplicationState = new Map();

function resetActionRateLimitState() {
  actionRateLimitState.perAction.clear();
  actionRateLimitState.global.hourly = { count: 0, resetTime: 0 };
  actionRateLimitState.global.daily = { count: 0, resetTime: 0 };
}

function resetDeduplicationState() {
  actionDeduplicationState.clear();
}

async function loadPolicyConfig(overrideConfigDir) {
  const policyPath = path.join(overrideConfigDir || config.configDir, "policies", "policy.yaml");
  try {
    const content = await fs.readFile(policyPath, "utf8");
    policyConfig = parseSimpleYaml(content);
    log("info", "policy", "Policy config loaded", { path: policyPath });
    return policyConfig;
  } catch (err) {
    if (config.mode === "production") {
      log("error", "policy", "Failed to load policy config (required in production)", { error: err.message });
      throw err;
    }
    log("warn", "policy", "Policy config not loaded, enforcement will allow all in bootstrap mode", { error: err.message });
    return null;
  }
}

/**
 * Check if an action type is allowed by policy.
 * Returns { allowed: boolean, reason: string }
 */
function policyCheckAction(actionType, confidence = 0) {
  if (!policyConfig) {
    if (config.mode === "production") {
      return { allowed: false, reason: "Policy not loaded" };
    }
    return { allowed: true, reason: "Policy not loaded (bootstrap mode — allowing)" };
  }

  const actions = policyConfig.actions;
  if (!actions || actions.enabled === false) {
    return { allowed: false, reason: "Actions globally disabled in policy" };
  }

  const allowlist = actions.allowlist;
  if (!allowlist || !allowlist[actionType]) {
    if (actions.deny_unlisted === true || actions.deny_unlisted === "true") {
      return { allowed: false, reason: `Action '${actionType}' not in allowlist (deny_unlisted=true)` };
    }
    return { allowed: true, reason: "Action not in allowlist but deny_unlisted is false" };
  }

  const actionConfig = allowlist[actionType];

  // Check if action is enabled
  if (actionConfig.enabled === false || actionConfig.enabled === "false") {
    return { allowed: false, reason: `Action '${actionType}' is disabled in policy` };
  }

  // Check minimum confidence
  // When minConfidence is configured, reject if confidence is unknown (0) or below threshold
  const minConfidence = parseFloat(actionConfig.min_confidence) || 0;
  if (minConfidence > 0 && confidence < minConfidence) {
    return { allowed: false, reason: `Confidence ${confidence} below minimum ${minConfidence} for '${actionType}'` };
  }

  return { allowed: true, reason: "Action allowed by policy" };
}

/**
 * Check if an approver is authorized for given actions and risk level.
 * Returns { authorized: boolean, reason: string }
 */
function policyCheckApprover(approverId, actionTypes = [], planRiskLevel = "medium") {
  if (!policyConfig) {
    if (config.mode === "production") {
      return { authorized: false, reason: "Policy not loaded" };
    }
    return { authorized: true, reason: "Policy not loaded (bootstrap mode — allowing)" };
  }

  const approvers = policyConfig.approvers;
  if (!approvers || !approvers.groups) {
    return { authorized: true, reason: "No approver groups configured" };
  }

  // Check if all Slack IDs are placeholders (development/bootstrap scenario)
  const allPlaceholders = Object.values(approvers.groups).every((group) => {
    if (!group.members) return true;
    if (Array.isArray(group.members)) {
      return group.members.every((m) => {
        const id = typeof m === "object" ? (m.slack_id || "") : String(m);
        return id.startsWith("<") && id.endsWith(">");
      });
    }
    return true;
  });

  if (allPlaceholders) {
    // Check if explicit bootstrap approval is enabled (env var checked at call time to allow test overrides)
    const bootstrapApprovalEnabled = process.env.AUTOPILOT_BOOTSTRAP_APPROVAL === "true";
    if (bootstrapApprovalEnabled) {
      log("warn", "policy", "All approver Slack IDs are placeholders — bypassing approver check (AUTOPILOT_BOOTSTRAP_APPROVAL=true)", { approver_id: approverId });
      return { authorized: true, reason: "Approver check bypassed (placeholder Slack IDs, bootstrap approval enabled)" };
    }
    log("error", "policy", "All approver Slack IDs are placeholders and AUTOPILOT_BOOTSTRAP_APPROVAL is not set — denying approval", { approver_id: approverId });
    return { authorized: false, reason: "Approver check bypassed in bootstrap mode but AUTOPILOT_BOOTSTRAP_APPROVAL is not set. Set AUTOPILOT_BOOTSTRAP_APPROVAL=true to allow agent auto-approval, or configure real Slack approver IDs in policy.yaml" };
  }

  // Risk level hierarchy
  const riskHierarchy = { low: 0, medium: 1, high: 2, critical: 3 };
  const planRisk = riskHierarchy[planRiskLevel] !== undefined ? riskHierarchy[planRiskLevel] : 1;

  // Search for this approver in all groups
  for (const [groupName, group] of Object.entries(approvers.groups)) {
    if (!group.members) continue;

    const isMember = Array.isArray(group.members) && group.members.some((m) => {
      const id = typeof m === "object" ? (m.slack_id || "") : String(m);
      return id === approverId;
    });

    if (!isMember) continue;

    // Check risk level
    const maxRisk = riskHierarchy[group.max_risk_level] !== undefined ? riskHierarchy[group.max_risk_level] : 1;
    if (planRisk > maxRisk) {
      continue; // This group can't handle this risk level, try next
    }

    // Check if group can approve all requested action types
    const canApprove = group.can_approve;
    if (canApprove && Array.isArray(canApprove)) {
      const canApproveList = canApprove.map((a) => typeof a === "object" ? Object.keys(a)[0] : String(a));
      const allAllowed = actionTypes.every((at) => canApproveList.includes(at));
      if (allAllowed) {
        return { authorized: true, reason: `Authorized via '${groupName}' group` };
      }
    }
  }

  return { authorized: false, reason: `Approver '${approverId}' not authorized for risk='${planRiskLevel}' actions=[${actionTypes.join(",")}]` };
}

/**
 * Check if a plan has sufficient evidence.
 * Returns { sufficient: boolean, reason: string }
 */
async function policyCheckEvidence(planActions, caseId) {
  if (!policyConfig) {
    if (config.mode === "production") {
      return { sufficient: false, reason: "Policy not loaded" };
    }
    return { sufficient: true, reason: "Policy not loaded (bootstrap mode — allowing)" };
  }

  // Count evidence items in the case
  let evidenceCount = 0;
  try {
    const caseData = await getCase(caseId);
    evidenceCount = (caseData.evidence_refs || []).length +
                    (caseData.mcp_calls || []).length +
                    (caseData.timeline || []).length;
  } catch (err) {
    log("warn", "policy", "Could not read case for evidence check", { case_id: caseId, error: err.message });
    if (config.mode === "production") {
      return { sufficient: false, reason: `Cannot verify evidence: ${err.message}` };
    }
    return { sufficient: true, reason: "Case not found (bootstrap mode — allowing)" };
  }

  // Check minimum evidence for each action
  const allowlist = policyConfig.actions?.allowlist;
  if (!allowlist) {
    return { sufficient: true, reason: "No action allowlist configured" };
  }

  for (const action of planActions) {
    const actionConfig = allowlist[action.type];
    if (actionConfig) {
      const minEvidence = parseInt(actionConfig.min_evidence_items, 10) || 0;
      if (evidenceCount < minEvidence) {
        return {
          sufficient: false,
          reason: `Action '${action.type}' requires ${minEvidence} evidence items, case has ${evidenceCount}`,
        };
      }
    }
  }

  return { sufficient: true, reason: `Evidence sufficient (${evidenceCount} items)` };
}

/**
 * Check if the current time is within an allowed window for the given operation.
 * Returns { allowed: boolean, reason: string }
 */
function policyCheckTimeWindow(operationType) {
  if (!policyConfig) {
    if (config.mode === "production") {
      return { allowed: false, reason: "Policy not loaded" };
    }
    return { allowed: true, reason: "Policy not loaded (bootstrap mode — allowing)" };
  }

  const tw = policyConfig.time_windows;
  if (!tw || tw.enabled === false || tw.enabled === "false") {
    return { allowed: true, reason: "Time windows disabled in policy" };
  }

  const ops = tw.operations;
  if (!ops || !ops[operationType]) {
    return { allowed: true, reason: `No time window configured for '${operationType}'` };
  }

  const opConfig = ops[operationType];
  const windows = opConfig.windows;
  if (!windows || !Array.isArray(windows) || windows.length === 0) {
    return { allowed: true, reason: `No windows defined for '${operationType}'` };
  }

  const now = new Date();
  const dayNames = ["sun", "mon", "tue", "wed", "thu", "fri", "sat"];
  const currentDay = dayNames[now.getUTCDay()];
  const currentMinutes = now.getUTCHours() * 60 + now.getUTCMinutes();

  for (const win of windows) {
    // Parse days — handle both array and inline string "[mon, tue, ...]"
    let days = win.days;
    if (typeof days === "string") {
      days = days.replace(/^\[|\]$/g, "").split(",").map((d) => d.trim().toLowerCase());
    }
    if (!Array.isArray(days) || !days.includes(currentDay)) continue;

    // parseSimpleYaml may place start/end on parent opConfig instead of list item
    const start = win.start || opConfig.start || "00:00";
    const end = win.end || opConfig.end || "23:59";
    const [startH, startM] = String(start).split(":").map(Number);
    const [endH, endM] = String(end).split(":").map(Number);
    const startMin = startH * 60 + (startM || 0);
    const endMin = endH * 60 + (endM || 0);

    if (currentMinutes >= startMin && currentMinutes <= endMin) {
      return { allowed: true, reason: `Within time window for '${operationType}'` };
    }
  }

  const outsideAction = opConfig.outside_window_action || "deny";
  if (outsideAction === "allow") {
    return { allowed: true, reason: `Outside time window for '${operationType}' but outside_window_action=allow` };
  }
  return { allowed: false, reason: `Outside allowed time window for '${operationType}'` };
}

/**
 * Check if an action type has exceeded its policy-defined rate limit.
 * Returns { allowed: boolean, reason: string }
 */
function policyCheckActionRateLimit(actionType) {
  if (!policyConfig) {
    if (config.mode === "production") {
      return { allowed: false, reason: "Policy not loaded" };
    }
    return { allowed: true, reason: "Policy not loaded (bootstrap mode — allowing)" };
  }

  const rl = policyConfig.rate_limits;
  if (!rl) {
    return { allowed: true, reason: "No rate limits configured" };
  }

  const now = Date.now();
  const ONE_HOUR = 3600000;
  const ONE_DAY = 86400000;

  // Per-action rate limit
  if (rl.actions && rl.actions[actionType]) {
    const limits = rl.actions[actionType];
    const maxPerHour = parseInt(limits.max_per_hour, 10) || Infinity;
    const maxPerDay = parseInt(limits.max_per_day, 10) || Infinity;

    let state = actionRateLimitState.perAction.get(actionType);
    if (!state) {
      state = { hourly: { count: 0, resetTime: now + ONE_HOUR }, daily: { count: 0, resetTime: now + ONE_DAY } };
      actionRateLimitState.perAction.set(actionType, state);
    }
    if (now > state.hourly.resetTime) state.hourly = { count: 0, resetTime: now + ONE_HOUR };
    if (now > state.daily.resetTime) state.daily = { count: 0, resetTime: now + ONE_DAY };

    if (state.hourly.count >= maxPerHour) {
      return { allowed: false, reason: `Action '${actionType}' hourly rate limit exceeded (${maxPerHour}/hr)` };
    }
    if (state.daily.count >= maxPerDay) {
      return { allowed: false, reason: `Action '${actionType}' daily rate limit exceeded (${maxPerDay}/day)` };
    }
  }

  // Global rate limit
  if (rl.global) {
    const maxHour = parseInt(rl.global.max_actions_per_hour, 10) || Infinity;
    const maxDay = parseInt(rl.global.max_actions_per_day, 10) || Infinity;
    const g = actionRateLimitState.global;
    if (now > g.hourly.resetTime) g.hourly = { count: 0, resetTime: now + ONE_HOUR };
    if (now > g.daily.resetTime) g.daily = { count: 0, resetTime: now + ONE_DAY };

    if (g.hourly.count >= maxHour) {
      return { allowed: false, reason: `Global hourly action rate limit exceeded (${maxHour}/hr)` };
    }
    if (g.daily.count >= maxDay) {
      return { allowed: false, reason: `Global daily action rate limit exceeded (${maxDay}/day)` };
    }
  }

  return { allowed: true, reason: "Action rate limit OK" };
}

/**
 * Increment action rate limit counters after successful execution.
 */
function recordActionExecution(actionType) {
  const now = Date.now();
  const ONE_HOUR = 3600000;
  const ONE_DAY = 86400000;

  let state = actionRateLimitState.perAction.get(actionType);
  if (!state) {
    state = { hourly: { count: 0, resetTime: now + ONE_HOUR }, daily: { count: 0, resetTime: now + ONE_DAY } };
    actionRateLimitState.perAction.set(actionType, state);
  }
  if (now > state.hourly.resetTime) state.hourly = { count: 0, resetTime: now + ONE_HOUR };
  if (now > state.daily.resetTime) state.daily = { count: 0, resetTime: now + ONE_DAY };
  state.hourly.count++;
  state.daily.count++;

  const g = actionRateLimitState.global;
  if (now > g.hourly.resetTime) g.hourly = { count: 0, resetTime: now + ONE_HOUR };
  if (now > g.daily.resetTime) g.daily = { count: 0, resetTime: now + ONE_DAY };
  g.hourly.count++;
  g.daily.count++;
}

/**
 * Check idempotency / duplicate detection for an action.
 * Returns { allowed: boolean, reason: string }
 */
function policyCheckIdempotency(actionType, target) {
  if (!policyConfig) {
    if (config.mode === "production") {
      return { allowed: false, reason: "Policy not loaded" };
    }
    return { allowed: true, reason: "Policy not loaded (bootstrap mode — allowing)" };
  }

  const idemp = policyConfig.idempotency;
  if (!idemp || idemp.enabled === false || idemp.enabled === "false") {
    return { allowed: true, reason: "Idempotency checks disabled in policy" };
  }

  const dd = idemp.duplicate_detection;
  if (dd && (dd.enabled === true || dd.enabled === "true")) {
    const windowMs = (parseInt(dd.window_minutes, 10) || 60) * 60 * 1000;
    const key = `${actionType}:${target}`;
    const lastExec = actionDeduplicationState.get(key);

    if (lastExec && (Date.now() - lastExec) < windowMs) {
      const denyReason = dd.deny_reason || "DUPLICATE_REQUEST";
      const minutesAgo = Math.round((Date.now() - lastExec) / 60000);
      return {
        allowed: false,
        reason: `${denyReason}: '${actionType}' on '${target}' was executed ${minutesAgo} minutes ago (window: ${dd.window_minutes || 60}min)`,
      };
    }
  }

  return { allowed: true, reason: "Idempotency check passed" };
}

/**
 * Record a successful action execution for deduplication tracking.
 */
function recordActionForDedup(actionType, target) {
  const key = `${actionType}:${target}`;
  if (actionDeduplicationState.size >= MAX_DEDUP_ENTRIES && !actionDeduplicationState.has(key)) {
    let oldestKey = null;
    let oldestTime = Infinity;
    for (const [k, t] of actionDeduplicationState) {
      if (t < oldestTime) { oldestTime = t; oldestKey = k; }
    }
    if (oldestKey) actionDeduplicationState.delete(oldestKey);
  }
  actionDeduplicationState.set(key, Date.now());
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

// Parse human-readable duration strings to integer seconds
// Supports: "24h", "30m", "2d", "1h30m", "3600", "86400s", etc.
function parseDurationToSeconds(value) {
  if (typeof value === "number") return Math.floor(value);
  if (typeof value !== "string") return null;

  const trimmed = value.trim();
  if (!trimmed) return null;

  // Pure integer string (already seconds)
  if (/^\d+$/.test(trimmed)) return parseInt(trimmed, 10);

  // Duration with units: "24h", "30m", "2d", "1h30m", "90s"
  const units = { s: 1, m: 60, h: 3600, d: 86400, w: 604800 };
  let total = 0;
  let matched = false;
  const regex = /(\d+)\s*([smhdw])/gi;
  let match;
  while ((match = regex.exec(trimmed)) !== null) {
    const num = parseInt(match[1], 10);
    const unit = match[2].toLowerCase();
    total += num * (units[unit] || 0);
    matched = true;
  }

  return matched ? total : null;
}

// Build MCP tool call params from plan action
// Maps action.target to the correct MCP parameter name using toolmap config
// Coerces duration strings to integer seconds
function buildMcpParams(action) {
  const params = { ...(action.params || {}) };

  // Determine which MCP parameter action.target maps to
  let targetParamName = "target"; // default fallback
  if (toolmapConfig && toolmapConfig.action_operations) {
    const toolConfig = toolmapConfig.action_operations[action.type];
    if (toolConfig && toolConfig.target_param) {
      targetParamName = toolConfig.target_param;
    } else if (toolConfig && Array.isArray(toolConfig.parameters)) {
      // Use the first required parameter as the target param
      const requiredParam = toolConfig.parameters.find((p) => p.required === true || p.required === "true");
      if (requiredParam) {
        targetParamName = requiredParam.name;
      }
    }
  }

  // Inject action.target as the resolved parameter name (don't overwrite if already set)
  if (action.target && !params[targetParamName]) {
    params[targetParamName] = action.target;
  }

  // Coerce duration-like values to integer seconds
  if (params.duration !== undefined) {
    const seconds = parseDurationToSeconds(params.duration);
    if (seconds !== null) {
      params.duration = seconds;
    } else if (typeof params.duration === "string") {
      log("warn", "mcp", "Could not parse duration value, removing", { duration: params.duration, action: action.type });
      delete params.duration;
    }
  }

  // For block_ip: ensure agent_id is set. Wazuh active-response API requires a
  // specific agent ID, not "all". Resolve from plan params, action, or case entities.
  if (action.type === "block_ip" && !params.agent_id) {
    if (action.agent_id) {
      params.agent_id = action.agent_id;
    } else if (action._case_agent_id) {
      // Resolved from case entities during executePlan() — see below
      params.agent_id = action._case_agent_id;
    } else {
      // Last resort: use "all" and let the MCP Server handle it
      // Note: Wazuh 4.14+ may reject "all" — prefer specific agent IDs
      params.agent_id = "all";
      log("warn", "plans", "block_ip action missing agent_id, using 'all' (may fail on some Wazuh versions)", {
        target: action.target, action_type: action.type,
      });
    }
  }

  // Clamp duration to Wazuh MCP Server max (86400s = 24h)
  // LLMs sometimes request longer durations (e.g. 7d) that exceed the server limit
  const MAX_BLOCK_DURATION = 86400;
  if (params.duration !== undefined && params.duration > MAX_BLOCK_DURATION) {
    log("warn", "mcp", "Duration exceeds max allowed, clamping to 86400s (24h)", {
      original: params.duration, clamped: MAX_BLOCK_DURATION, action: action.type,
    });
    params.duration = MAX_BLOCK_DURATION;
  }

  return params;
}

// MCP Circuit Breaker — prevents hammering a down MCP server
const mcpCircuitBreaker = {
  failures: 0,
  state: "closed", // "closed" (normal), "open" (tripped), "half-open" (probing)
  openedAt: 0,
  cooldownMs: 30000,
  threshold: 5,
};

function mcpCircuitBreakerCheck() {
  if (mcpCircuitBreaker.state === "closed") return { allowed: true };
  if (mcpCircuitBreaker.state === "open") {
    if (Date.now() - mcpCircuitBreaker.openedAt >= mcpCircuitBreaker.cooldownMs) {
      mcpCircuitBreaker.state = "half-open";
      return { allowed: true };
    }
    return { allowed: false, reason: "MCP circuit breaker open — server unreachable" };
  }
  // half-open: allow one probe
  return { allowed: true };
}

function mcpCircuitBreakerRecord(success) {
  if (success) {
    mcpCircuitBreaker.failures = 0;
    mcpCircuitBreaker.state = "closed";
  } else {
    mcpCircuitBreaker.failures++;
    if (mcpCircuitBreaker.failures >= mcpCircuitBreaker.threshold) {
      mcpCircuitBreaker.state = "open";
      mcpCircuitBreaker.openedAt = Date.now();
      log("warn", "mcp", "Circuit breaker OPEN — MCP server unreachable", {
        failures: mcpCircuitBreaker.failures,
        cooldown_ms: mcpCircuitBreaker.cooldownMs,
      });
      incrementMetric("mcp_circuit_breaker_trips_total");
    }
  }
}

async function callMcpTool(toolName, params, correlationId) {
  const startTime = Date.now();

  // Circuit breaker: fail fast if MCP server is known to be down
  const cbCheck = mcpCircuitBreakerCheck();
  if (!cbCheck.allowed) {
    incrementMetric("mcp_circuit_breaker_rejections_total");
    throw new Error(cbCheck.reason);
  }

  if (!config.mcpUrl) {
    incrementMetric("errors_total", { component: "mcp" });
    throw new Error("MCP_URL not configured");
  }

  // Ensure MCP session is initialized before calling tools
  await ensureMcpSession();

  // Check if tool is enabled
  if (!isToolEnabled(toolName)) {
    incrementMetric("errors_total", { component: "mcp" });
    throw new Error(`Tool '${toolName}' is disabled in toolmap configuration`);
  }

  // Resolve logical tool name to MCP tool name
  const mcpToolName = resolveMcpTool(toolName);

  // Validate tool name to prevent path traversal (SSRF)
  if (!/^[a-zA-Z0-9_.\-]+$/.test(mcpToolName)) {
    incrementMetric("errors_total", { component: "mcp" });
    throw new Error(`Invalid tool name: contains disallowed characters`);
  }

  const requestHash = crypto
    .createHash("sha256")
    .update(JSON.stringify({ toolName: mcpToolName, params }))
    .digest("hex")
    .substring(0, 16);

  let lastError;

  for (let attempt = 0; attempt <= config.mcpMaxRetries; attempt++) {
    // Exponential backoff between retries
    if (attempt > 0) {
      const delay = config.mcpRetryBaseMs * Math.pow(2, attempt - 1);
      log("info", "mcp", `Retrying tool call (attempt ${attempt + 1}/${config.mcpMaxRetries + 1})`, {
        tool: toolName,
        delay_ms: delay,
        correlation_id: correlationId,
      });
      await new Promise((resolve) => setTimeout(resolve, delay));
    }

    try {
      // Create abort controller for timeout
      const controller = new AbortController();
      const timeoutId = setTimeout(() => controller.abort(), config.mcpTimeoutMs);

      // Get auth token (JWT exchange for jsonrpc mode, raw key for legacy)
      const authToken = await getMcpAuthToken();

      // Build request based on auth mode
      let fetchUrl, fetchBody;
      if (config.mcpAuthMode === "legacy-rest") {
        // Legacy REST: POST /tools/<name> with raw params
        fetchUrl = `${config.mcpUrl}/tools/${mcpToolName}`;
        fetchBody = JSON.stringify(params);
      } else {
        // MCP JSON-RPC: POST /mcp with JSON-RPC 2.0 envelope
        fetchUrl = `${config.mcpUrl}/mcp`;
        fetchBody = JSON.stringify({
          jsonrpc: "2.0",
          id: requestHash,
          method: "tools/call",
          params: { name: mcpToolName, arguments: params },
        });
      }

      const response = await fetch(fetchUrl, {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          ...(authToken && { Authorization: `Bearer ${authToken}` }),
          ...(correlationId && { "X-Correlation-ID": correlationId }),
          ...(config.mcpAuthMode !== "legacy-rest" && { "MCP-Protocol-Version": MCP_PROTOCOL_VERSION }),
          ...(mcpSessionId && { "MCP-Session-Id": mcpSessionId }),
        },
        body: fetchBody,
        signal: controller.signal,
      });

      clearTimeout(timeoutId);

      // Capture/update session ID from response header
      const respSessionId = response.headers.get("mcp-session-id");
      if (respSessionId) {
        mcpSessionId = respSessionId;
      }

      // Handle 401: invalidate JWT cache and retry
      if (response.status === 401 && config.mcpAuthMode !== "legacy-rest") {
        mcpJwtCache = { token: null, expiresAt: 0 };
        invalidateMcpSession();
        if (attempt < config.mcpMaxRetries) {
          await response.text().catch(() => "");
          lastError = new Error("MCP auth expired (401)");
          continue;
        }
      }

      // Handle 404: session expired, reinitialize and retry
      if (response.status === 404 && config.mcpAuthMode !== "legacy-rest") {
        invalidateMcpSession();
        if (attempt < config.mcpMaxRetries) {
          await response.text().catch(() => "");
          await ensureMcpSession();
          lastError = new Error("MCP session expired (404)");
          continue;
        }
      }

      // Retry on 5xx server errors (transient)
      if (!response.ok && response.status >= 500 && attempt < config.mcpMaxRetries) {
        await response.text().catch(() => ""); // drain body
        lastError = new Error(`MCP server error: ${response.status}`);
        continue;
      }

      const latencySeconds = (Date.now() - startTime) / 1000;
      const status = response.ok ? "success" : "error";

      incrementMetric("mcp_tool_calls_total", { tool: toolName, status });
      recordLatency("mcp_tool_call_latency_seconds", latencySeconds, { tool: toolName });

      let responseData;
      const contentType = response.headers.get("content-type") || "";
      if (contentType.includes("application/json")) {
        responseData = await response.json();

        // Unwrap JSON-RPC envelope if present
        if (responseData.jsonrpc === "2.0") {
          if (responseData.error) {
            const rpcError = responseData.error;
            // Correct the metric we already recorded (was "success" based on HTTP status)
            incrementMetric("mcp_tool_calls_total", { tool: toolName, status: "rpc_error" });
            incrementMetric("errors_total", { component: "mcp" });
            const rpcErr = new Error(`MCP RPC error ${rpcError.code}: ${rpcError.message}`);
            rpcErr._metricsRecorded = true;
            throw rpcErr;
          }
          responseData = responseData.result || responseData;
        }
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
        ...(attempt > 0 && { attempts: attempt + 1 }),
      });

      mcpCircuitBreakerRecord(response.ok);

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
      lastError = err;

      // Only retry on transient network errors (timeout, connection refused/reset)
      const isRetryable = err.name === "AbortError" ||
        (err.cause && ["ECONNREFUSED", "ECONNRESET", "ETIMEDOUT", "EPIPE"].includes(err.cause.code));

      if (attempt < config.mcpMaxRetries && isRetryable) {
        continue;
      }

      break;
    }
  }

  // All attempts exhausted — skip metric recording if already done (e.g., RPC errors)
  if (lastError && !lastError._metricsRecorded) {
    const latencySeconds = (Date.now() - startTime) / 1000;
    incrementMetric("mcp_tool_calls_total", { tool: toolName, status: "error" });
    incrementMetric("errors_total", { component: "mcp" });
    recordLatency("mcp_tool_call_latency_seconds", latencySeconds, { tool: toolName });
  }

  mcpCircuitBreakerRecord(false);

  log("error", "mcp", "Tool call failed after retries", {
    tool: toolName,
    error: lastError.message,
    correlation_id: correlationId,
    attempts: config.mcpMaxRetries + 1,
  });

  throw lastError;
}

// =============================================================================
// RATE LIMITING
// =============================================================================

const MAX_RATE_LIMIT_ENTRIES = 10000;
const rateLimitState = {
  requests: new Map(), // IP -> { count, resetTime }
};

function checkRateLimit(clientIp) {
  const now = Date.now();
  const clientData = rateLimitState.requests.get(clientIp);

  if (!clientData || now > clientData.resetTime) {
    // Evict expired entries if approaching limit
    if (rateLimitState.requests.size >= MAX_RATE_LIMIT_ENTRIES) {
      for (const [ip, data] of rateLimitState.requests) {
        if (now > data.resetTime) rateLimitState.requests.delete(ip);
      }
      // If still at limit after eviction, reject to prevent OOM
      if (rateLimitState.requests.size >= MAX_RATE_LIMIT_ENTRIES) {
        return { allowed: false, remaining: 0, retryAfter: 60 };
      }
    }
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
    // Evict expired entries if approaching limit
    if (authFailureState.attempts.size >= MAX_RATE_LIMIT_ENTRIES) {
      for (const [ip, d] of authFailureState.attempts) {
        if (now > d.firstAttempt + config.authFailureWindowMs || (d.lockedUntil && now >= d.lockedUntil)) {
          authFailureState.attempts.delete(ip);
        }
      }
    }
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

const SERVICE_VERSION = require("./package.json").version;
const JSON_CONTENT_TYPE = "application/json; charset=utf-8";
const startTime = Date.now();

// Auth error response helper
function sendAuthError(res, authResult, requestId) {
  if (authResult.locked) {
    res.setHeader("Retry-After", authResult.retryAfter);
    res.writeHead(429, { "Content-Type": JSON_CONTENT_TYPE });
    res.end(JSON.stringify({ error: authResult.reason, retry_after: authResult.retryAfter, request_id: requestId }));
  } else if (authResult.forbidden) {
    res.writeHead(403, { "Content-Type": JSON_CONTENT_TYPE });
    res.end(JSON.stringify({ error: authResult.reason, request_id: requestId }));
  } else {
    res.writeHead(401, { "Content-Type": JSON_CONTENT_TYPE });
    res.end(JSON.stringify({ error: authResult.reason, request_id: requestId }));
  }
}

// Standard JSON error response helper (consistent format with request_id)
function sendJsonError(res, statusCode, error, requestId) {
  if (res.headersSent) return;
  res.writeHead(statusCode, { "Content-Type": JSON_CONTENT_TYPE });
  res.end(JSON.stringify({ error, request_id: requestId }));
}

// Input validation
function isValidCaseId(caseId) {
  // Case IDs must be alphanumeric with hyphens, 1-64 chars
  return /^[a-zA-Z0-9-]{1,64}$/.test(caseId);
}

function isValidPlanId(planId) {
  return typeof planId === "string" && /^PLAN-\d+-[a-f0-9]{8}$/.test(planId);
}

// Issue #22 fix: Resolve LLM-fabricated plan_id to actual plan.
// LLMs commonly fabricate plan IDs using case_id format (PLAN-20260323-{case_hash})
// or use partial hashes. This scans responsePlans to find the best match.
function resolvePlanId(fabricatedId, caseId, targetState) {
  if (!fabricatedId) return null;

  // Strategy 1: If a case_id is available (from query param or extracted from fabricated ID),
  // find the most recent plan for that case in the target state.
  let resolvedCaseId = caseId;
  if (!resolvedCaseId) {
    // Try to extract case hash from fabricated ID (e.g., PLAN-20260323-723b2febbe95)
    const hashMatch = fabricatedId.match(/[a-f0-9]{8,12}$/);
    if (hashMatch) {
      // Search for a case_id ending with this hash
      for (const [, plan] of responsePlans.entries()) {
        if (plan.case_id && plan.case_id.endsWith(hashMatch[0])) {
          resolvedCaseId = plan.case_id;
          break;
        }
      }
    }
  }

  if (resolvedCaseId) {
    let bestPlanId = null;
    for (const [planId, plan] of responsePlans.entries()) {
      if (plan.case_id === resolvedCaseId) {
        // Match by target state, or any state if no target specified
        if (!targetState || plan.state === targetState) {
          bestPlanId = planId; // keep iterating — last match = most recent
        }
      }
    }
    if (bestPlanId) return bestPlanId;
  }

  // Strategy 2: If fabricated ID contains a hash suffix, try to match any plan
  // that has this suffix in its actual plan_id
  const suffixMatch = fabricatedId.match(/([a-f0-9]{8})$/);
  if (suffixMatch) {
    for (const [planId, plan] of responsePlans.entries()) {
      if (planId.endsWith(suffixMatch[1])) {
        if (!targetState || plan.state === targetState) {
          return planId;
        }
      }
    }
  }

  return null;
}

function isValidIdentityId(id) {
  // Identity IDs: alphanumeric, @, ., -, _ — 1-128 chars
  return typeof id === "string" && id.trim().length > 0 && id.length <= 128 && /^[\w@.\-]+$/.test(id);
}

function sanitizeRequestId(rawId) {
  // Only allow alphanumeric, hyphens, underscores — max 128 chars
  if (typeof rawId === "string" && /^[a-zA-Z0-9_\-]{1,128}$/.test(rawId)) {
    return rawId;
  }
  return generateRequestId();
}

// Authorization validation for sensitive endpoints
// Issue #1 fix: Uses timing-safe comparison
// Issue #3 fix: Includes auth failure rate limiting
// Issue #17/#18 fix: Accept auth token via query parameter for agent-action
// endpoints — OpenClaw's web_fetch tool is GET-only and cannot set headers.
function validateAuthorization(req, requiredScope = "write", url = null) {
  const authHeader = req.headers.authorization;

  // Fallback: accept token via query parameter for GET endpoints.
  // OpenClaw's web_fetch tool only supports GET requests with no custom headers,
  // so agents must pass the auth token as ?token=<value> in the URL.
  // Limited to GET requests to prevent token leakage in POST/PUT bodies.
  const queryToken = url && req.method === "GET"
    ? url.searchParams.get("token")
    : null;

  // Get client IP for auth failure tracking
  // Only trust X-Forwarded-For when TRUSTED_PROXY=true and connection is from localhost
  const directIp = req.socket.remoteAddress || "unknown";
  const isDirectLocalhost = directIp === "127.0.0.1" || directIp === "::1" ||
                            directIp === "::ffff:127.0.0.1";
  const forwardedFor = req.headers["x-forwarded-for"];
  const clientIp = (isDirectLocalhost && forwardedFor && config.trustedProxy)
    ? forwardedFor.split(",")[0].trim()
    : directIp;
  if (isDirectLocalhost && forwardedFor && !config.trustedProxy) {
    warnUntrustedProxy();
  }
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

  // Allow requests from localhost without auth ONLY in bootstrap mode
  // Production mode always requires token auth to prevent co-located process abuse
  if (isLocalhost && !authHeader && !queryToken && config.mode === "bootstrap") {
    return { valid: true, source: "localhost", scope: "write" };
  }

  // Resolve token: prefer Authorization header, fall back to query parameter
  let token;
  let tokenSource;
  if (authHeader) {
    // Validate Bearer token format
    if (!authHeader.startsWith("Bearer ")) {
      recordAuthFailure(clientIp);
      return { valid: false, reason: "Invalid Authorization format" };
    }
    token = authHeader.substring(7);
    tokenSource = "header";
  } else if (queryToken) {
    token = queryToken;
    tokenSource = "query";
  } else {
    recordAuthFailure(clientIp);
    return { valid: false, reason: "Missing Authorization header" };
  }

  // Reject empty or too-short tokens before comparison
  if (!token || token.length < 8) {
    recordAuthFailure(clientIp);
    return { valid: false, reason: "Invalid token" };
  }

  // Validate against configured MCP auth token using timing-safe comparison
  if (config.mcpAuth && config.mcpAuth.length >= 8 && secureCompare(token, config.mcpAuth)) {
    clearAuthFailures(clientIp); // Clear on success
    return { valid: true, source: tokenSource === "query" ? "api_token_query" : "api_token", scope: "write" };
  }

  // Also check for internal service token (environment variable)
  // Service tokens have read-only scope; MCP auth tokens have full write access
  const serviceToken = process.env.AUTOPILOT_SERVICE_TOKEN;
  if (serviceToken && serviceToken.length >= 8 && secureCompare(token, serviceToken)) {
    clearAuthFailures(clientIp); // Clear on success
    const tokenScope = "read";
    if (requiredScope === "write" && tokenScope !== "write") {
      return { valid: false, reason: "Insufficient scope: write access required", forbidden: true };
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
    // Pre-check Content-Length header to reject oversized requests early
    const contentLength = parseInt(req.headers?.["content-length"], 10);
    if (contentLength > 0 && contentLength > MAX_BODY_SIZE) {
      const err = new Error("Request body too large");
      err.httpStatus = 413;
      reject(err);
      return;
    }

    const chunks = [];
    let totalSize = 0;
    let rejected = false;

    // Body timeout to prevent slow-loris attacks
    const bodyTimeout = setTimeout(() => {
      if (!rejected) {
        rejected = true;
        req.destroy();
        const err = new Error("Request body timeout");
        err.httpStatus = 408;
        reject(err);
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
        const err = new Error("Request body too large");
        err.httpStatus = 413;
        reject(err);
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
        const parseErr = new Error("Invalid JSON");
        parseErr.httpStatus = 400;
        reject(parseErr);
      }
    });

    req.on("error", (err) => {
      clearTimeout(bodyTimeout);
      if (!rejected) reject(err);
    });
  });
}

// Audit fix C1: Sanitize alert payloads before forwarding to agents via webhooks.
// Wazuh alert fields (SSH banners, HTTP user-agents, filenames) are attacker-controlled.
// Strip control characters and enforce size limits to reduce prompt injection surface.
function sanitizeAlertPayload(payload) {
  if (typeof payload === "string") {
    // Remove control characters except newline/tab, cap length
    return payload.replace(/[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]/g, "").slice(0, 100000);
  }
  if (Array.isArray(payload)) {
    return payload.slice(0, 1000).map(sanitizeAlertPayload);
  }
  if (payload && typeof payload === "object") {
    const sanitized = {};
    const keys = Object.keys(payload);
    for (let i = 0; i < Math.min(keys.length, 500); i++) {
      const key = keys[i];
      // Sanitize key too (prevent injection via field names)
      const safeKey = key.replace(/[\x00-\x1f\x7f]/g, "").slice(0, 256);
      sanitized[safeKey] = sanitizeAlertPayload(payload[key]);
    }
    return sanitized;
  }
  return payload;
}

function createServer() {
  const server = http.createServer(async (req, res) => {
    const url = new URL(req.url, `http://${req.headers.host}`);

    // Issue #15 fix: Generate unique request ID for tracing (sanitized to prevent log injection)
    const requestId = sanitizeRequestId(req.headers["x-request-id"]) || generateRequestId();
    res.setHeader("X-Request-ID", requestId);

    // Get client IP for rate limiting
    // Only trust X-Forwarded-For when TRUSTED_PROXY=true and connection is from localhost
    const directIpRL = req.socket.remoteAddress || "unknown";
    const isDirectLocalRL = directIpRL === "127.0.0.1" || directIpRL === "::1" ||
                            directIpRL === "::ffff:127.0.0.1";
    const forwardedForRL = req.headers["x-forwarded-for"];
    const clientIp = (isDirectLocalRL && forwardedForRL && config.trustedProxy)
      ? forwardedForRL.split(",")[0].trim()
      : directIpRL;
    if (isDirectLocalRL && forwardedForRL && !config.trustedProxy) {
      warnUntrustedProxy();
    }

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
      res.setHeader("Vary", "Origin");
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
        if (!config.metricsEnabled) {
          sendJsonError(res, 404, "Metrics disabled (METRICS_ENABLED=false)", requestId);
          return;
        }
        // Audit fix M1: Require authentication for metrics to prevent info disclosure
        const metricsAuth = validateAuthorization(req, "read", url);
        if (!metricsAuth.valid) {
          sendAuthError(res, metricsAuth, requestId);
          return;
        }
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
            mcp_configured: !!config.mcpUrl,
            gateway_configured: !!(config.openclawGatewayUrl && config.openclawToken),
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

      // Cases summary endpoint (must be BEFORE /api/cases/:id to avoid pattern conflict)
      if (url.pathname === "/api/cases/summary" && req.method === "GET") {
        const authResult = validateAuthorization(req, "read", url);
        if (!authResult.valid) {
          sendAuthError(res, authResult, requestId);
          return;
        }

        const allCases = await listCases({ limit: 100000 });
        const now = Date.now();
        const by_status = {};
        const by_severity = {};
        let false_positive_count = 0;
        let last_24h = 0;
        let last_7d = 0;
        let last_30d = 0;

        for (const c of allCases) {
          const st = c.status || "open";
          by_status[st] = (by_status[st] || 0) + 1;
          const sev = c.severity || "medium";
          by_severity[sev] = (by_severity[sev] || 0) + 1;
          if (st === "false_positive") false_positive_count++;
          const created = new Date(c.created_at).getTime();
          if (now - created <= 24 * 3600 * 1000) last_24h++;
          if (now - created <= 7 * 24 * 3600 * 1000) last_7d++;
          if (now - created <= 30 * 24 * 3600 * 1000) last_30d++;
        }

        res.writeHead(200, { "Content-Type": JSON_CONTENT_TYPE });
        res.end(JSON.stringify({
          total: allCases.length,
          by_status,
          by_severity,
          false_positive_count,
          last_24h,
          last_7d,
          last_30d,
          request_id: requestId,
        }));
        return;
      }

      // Cases API - GET all (with filtering)
      if (url.pathname === "/api/cases" && req.method === "GET") {
        const authResult = validateAuthorization(req, "read", url);
        if (!authResult.valid) {
          sendAuthError(res, authResult, requestId);
          return;
        }

        const requestedLimit = parseInt(url.searchParams.get("limit") || "100", 10);
        const requestedOffset = parseInt(url.searchParams.get("offset") || "0", 10);
        const filterStatus = url.searchParams.get("status");
        const filterSeverity = url.searchParams.get("severity");
        const filterSince = url.searchParams.get("since");
        const filterUntil = url.searchParams.get("until");

        // Fetch all cases (we filter in-memory after)
        let cases = await listCases({ limit: 100000 });

        if (filterStatus) {
          cases = cases.filter(c => c.status === filterStatus);
        }
        if (filterSeverity) {
          cases = cases.filter(c => c.severity === filterSeverity);
        }
        if (filterSince) {
          const sinceTs = new Date(filterSince).getTime();
          if (!isNaN(sinceTs)) {
            cases = cases.filter(c => new Date(c.created_at).getTime() >= sinceTs);
          }
        }
        if (filterUntil) {
          const untilTs = new Date(filterUntil).getTime();
          if (!isNaN(untilTs)) {
            cases = cases.filter(c => new Date(c.created_at).getTime() <= untilTs);
          }
        }

        const safeOffset = Math.max(requestedOffset, 0);
        const safeLimit = Math.min(Math.max(requestedLimit, 1), 1000);
        const paged = cases.slice(safeOffset, safeOffset + safeLimit);

        res.writeHead(200, { "Content-Type": JSON_CONTENT_TYPE });
        res.end(JSON.stringify(paged));
        return;
      }

      // Cases API - POST create
      if (url.pathname === "/api/cases" && req.method === "POST") {
        // Require authorization for write operations
        const authResult = validateAuthorization(req, "write", url);
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
        const authResult = validateAuthorization(req, "read", url);
        if (!authResult.valid) {
          sendAuthError(res, authResult, requestId);
          return;
        }

        const caseId = url.pathname.split("/")[3];

        // Issue #22 fix: If case_id is just the hash suffix (LLM stripped CASE-date- prefix),
        // attempt to find the full case_id by scanning recent cases.
        let effectiveCaseId = caseId;
        if (caseId && !isValidCaseId(caseId) && /^[a-f0-9]{6,12}$/.test(caseId)) {
          try {
            const recentCases = await listCases({ limit: 200 });
            const match = recentCases.find(c => c.case_id && c.case_id.endsWith(caseId));
            if (match) {
              effectiveCaseId = match.case_id;
              log("warn", "cases", "Resolved truncated case_id to full ID (GET)", {
                original: caseId, resolved: effectiveCaseId,
              });
            }
          } catch { /* fallthrough to validation error */ }
        }

        // Input validation
        if (!effectiveCaseId || !isValidCaseId(effectiveCaseId)) {
          sendJsonError(res, 400, "Invalid case ID format — use the full ID including CASE- prefix", requestId);
          return;
        }

        try {
          const caseData = await getCase(effectiveCaseId);
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
        const authResult = validateAuthorization(req, "write", url);
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
          } else if (err.message.includes("Invalid status transition")) {
            sendJsonError(res, 400, err.message, requestId);
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
        const authResult = validateAuthorization(req, "write", url);
        if (!authResult.valid) {
          sendAuthError(res, authResult, requestId);
          return;
        }

        const rawAlert = await parseJsonBody(req);

        // CRIT-1 audit fix: Sanitize attacker-controlled alert fields before processing.
        // Wazuh alert fields (SSH banners, HTTP user-agents, filenames) can contain
        // control characters and prompt injection payloads.
        const alert = sanitizeAlertPayload(rawAlert);

        // Normalize alert_id from Wazuh native format
        if (!alert.alert_id && (alert.id || alert._id)) {
          alert.alert_id = String(alert.id || alert._id);
        }

        // Validate alert has minimum required fields
        if (!alert.alert_id && !alert._id && !alert.id) {
          sendJsonError(res, 400, "Alert must have alert_id, _id, or id field", requestId);
          return;
        }

        // Generate case ID from alert
        // Bug #15 fix: Use hash of full alert ID to prevent collisions
        const rawAlertId = alert.alert_id || alert._id || alert.id;
        const alertId = typeof rawAlertId === "object" ? JSON.stringify(rawAlertId) : String(rawAlertId);

        // M2 fix: Check alert dedup map first to prevent date-boundary case ID splits.
        // An alert retried across midnight would otherwise get a different CASE-YYYYMMDD prefix.
        let caseId = alertDedupGet(alertId);
        if (!caseId) {
          const timestamp = new Date().toISOString().split("T")[0].replace(/-/g, "");
          const alertIdHash = crypto.createHash("sha256")
            .update(alertId)
            .digest("hex")
            .substring(0, 12);
          caseId = `CASE-${timestamp}-${alertIdHash}`;
          alertDedupSet(alertId, caseId);
        }

        // Extract entities from alert (basic triage)
        const entities = [];

        // Extract IPs
        const ipFields = ["srcip", "dstip", "src_ip", "dst_ip"];
        // Bug #9 fix: Proper IPv4 validation (each octet 0-255, no leading zeros)
        const isValidIPv4 = (ip) => {
          if (!/^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$/.test(ip)) return false;
          const octets = ip.split(".");
          return octets.every(o => {
            if (o.length > 1 && o[0] === "0") return false;
            const n = Number(o);
            return n >= 0 && n <= 255;
          });
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

        // Extract file hashes (syscheck, VirusTotal integration)
        const hashFields = ["md5_before", "md5_after", "sha1_before", "sha1_after", "sha256_before", "sha256_after"];
        for (const field of hashFields) {
          const hash = alert.data?.syscheck?.[field] || alert.data?.[field];
          if (hash && typeof hash === "string" && /^[a-fA-F0-9]{32,64}$/.test(hash)) {
            entities.push({
              type: "hash",
              value: hash.toLowerCase(),
              role: field.includes("before") ? "original" : "modified",
              hash_type: field.startsWith("md5") ? "md5" : field.startsWith("sha1") ? "sha1" : "sha256",
              extracted_from: `data.syscheck.${field}`,
            });
          }
        }

        // Extract CVE IDs (vulnerability detection)
        const cvePattern = /CVE-\d{4}-\d{4,}/gi;
        const alertDataStr = JSON.stringify(alert.data || {});
        const cveMatches = [...new Set((alertDataStr.match(cvePattern) || []).map(c => c.toUpperCase()))];
        for (const cve of cveMatches.slice(0, 10)) {
          entities.push({ type: "cve", value: cve, role: "vulnerability", extracted_from: "data" });
        }

        // Extract process names (Sysmon, audit)
        const processFields = ["process.name", "parentprocess.name", "win.eventdata.image", "win.eventdata.parentImage"];
        for (const fieldPath of processFields) {
          const parts = fieldPath.split(".");
          let processVal = alert.data;
          for (const p of parts) { processVal = processVal?.[p]; }
          if (processVal && typeof processVal === "string" && processVal.length > 0 && processVal.length < 256) {
            entities.push({
              type: "process",
              value: processVal,
              role: fieldPath.includes("parent") ? "parent" : "child",
              extracted_from: `data.${fieldPath}`,
            });
          }
        }

        // Extract port numbers
        const portFields = ["srcport", "dstport", "src_port", "dst_port"];
        for (const field of portFields) {
          const port = alert.data?.[field] || alert[field];
          const portNum = parseInt(port, 10);
          if (portNum > 0 && portNum <= 65535) {
            entities.push({
              type: "port",
              value: String(portNum),
              role: field.includes("src") ? "source" : "destination",
              extracted_from: `data.${field}`,
            });
          }
        }

        // Enrich IP entities (non-blocking, best-effort)
        if (config.enrichmentEnabled) {
          const ipEntities = entities.filter((e) => e.type === "ip");
          const enrichmentPromises = ipEntities.map(async (entity) => {
            const enrichment = await enrichIpAddress(entity.value);
            if (enrichment) entity.enrichment = enrichment;
          });
          await Promise.all(enrichmentPromises);
        }

        // Determine severity from rule level (handle string, number, null)
        let severity = "medium";
        const rawLevel = alert.rule?.level ?? alert.level ?? 0;
        const parsedLevel = typeof rawLevel === "string" ? parseInt(rawLevel, 10) : Number(rawLevel);
        // Default NaN to 5 (medium) rather than 0 (informational) — safer for unknown alerts
        const ruleLevel = isNaN(parsedLevel) ? 5 : parsedLevel;
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

        // Entity-based alert grouping: check for related cases (in-memory, no lock needed)
        let groupedCaseId = null;
        if (entities.length > 0) {
          groupedCaseId = findRelatedCase(entities);
        }

        const effectiveCaseId = groupedCaseId || caseId;

        // Use withCaseLock to atomically check-then-create/update, preventing
        // race conditions when concurrent requests arrive for the same alert_id.
        // We inline the file operations instead of calling createCase/updateCase
        // because those functions acquire the same lock (non-reentrant) and would deadlock.
        let existingCase = false;
        await withCaseLock(effectiveCaseId, async () => {
          let caseExists = false;
          try {
            await getCase(effectiveCaseId);
            caseExists = true;
          } catch (e) {
            // Case doesn't exist, which is expected
          }

          if (caseExists) {
            existingCase = true;
            // Update existing case with new evidence directly (lock already held)
            const caseDir = path.join(config.dataDir, "cases", effectiveCaseId);
            const packPath = path.join(caseDir, "evidence-pack.json");
            const content = await fs.readFile(packPath, "utf8");
            const evidencePack = JSON.parse(content);
            const now = new Date().toISOString();
            evidencePack.updated_at = now;

            // Merge entities (deduplicate by type+value)
            if (caseData.entities) {
              const existingKeys = new Set(
                (evidencePack.entities || []).map((e) => `${e.type}:${e.value}`)
              );
              for (const entity of caseData.entities) {
                if (!existingKeys.has(`${entity.type}:${entity.value}`)) {
                  evidencePack.entities.push(entity);
                  existingKeys.add(`${entity.type}:${entity.value}`);
                }
              }
            }

            // Append timeline entries
            if (caseData.timeline) {
              evidencePack.timeline = (evidencePack.timeline || []).concat(caseData.timeline);
            }

            // Append evidence refs (deduplicate by ref_id)
            if (caseData.evidence_refs) {
              const existingRefs = new Set(
                (evidencePack.evidence_refs || []).map((r) => r.ref_id)
              );
              for (const ref of caseData.evidence_refs) {
                if (!existingRefs.has(ref.ref_id)) {
                  evidencePack.evidence_refs.push(ref);
                  existingRefs.add(ref.ref_id);
                }
              }
            }

            await atomicWriteFile(packPath, JSON.stringify(evidencePack, null, 2));
          } else {
            // Create new case directly (lock already held)
            const caseDir = path.join(config.dataDir, "cases", effectiveCaseId);
            const packPath = path.join(caseDir, "evidence-pack.json");

            await ensureDir(caseDir);

            const now = new Date().toISOString();

            const evidencePack = {
              schema_version: EVIDENCE_PACK_SCHEMA_VERSION,
              case_id: effectiveCaseId,
              created_at: now,
              updated_at: now,
              title: caseData.title || "",
              summary: caseData.summary || "",
              severity: caseData.severity || "medium",
              confidence: caseData.confidence || 0,
              entities: caseData.entities || [],
              timeline: caseData.timeline || [],
              mitre: caseData.mitre || [],
              mcp_calls: [],
              evidence_refs: caseData.evidence_refs || [],
              plans: [],
              approvals: [],
              actions: [],
              status: "open",
              feedback: [],
            };

            await atomicWriteFile(packPath, JSON.stringify(evidencePack, null, 2));

            const caseSummary = {
              case_id: effectiveCaseId,
              created_at: now,
              updated_at: now,
              title: caseData.title || "",
              severity: caseData.severity || "medium",
              status: "open",
            };

            await atomicWriteFile(
              path.join(caseDir, "case.json"),
              JSON.stringify(caseSummary, null, 2),
            );

            incrementMetric("cases_created_total");
            log("info", "evidence-pack", "Case created", { case_id: effectiveCaseId });

            // Post to Slack alerts channel (async, don't await)
            if (slack && slack.isInitialized()) {
              slack.postCaseAlert({
                case_id: effectiveCaseId,
                title: caseData.title,
                summary: caseData.summary,
                severity: caseData.severity,
                entities: caseData.entities || [],
                created_at: now,
              }).catch((err) => {
                log("warn", "evidence-pack", "Failed to post case to Slack", { error: err.message, case_id: effectiveCaseId });
              });
            }
          }
        });

        // Entity indexing and webhook dispatch stay OUTSIDE the lock
        indexCaseEntities(effectiveCaseId, entities, severity);

        if (existingCase) {
          log("info", "triage", "Updated existing case with new alert", {
            case_id: effectiveCaseId,
            alert_id: alertId,
            ...(groupedCaseId && { grouped_from: caseId }),
          });
        } else {
          log("info", "triage", "Created new case from alert", { case_id: effectiveCaseId, alert_id: alertId, severity });

          // Dispatch to triage agent via OpenClaw gateway
          // NOTE: Callback URLs are NOT included in the webhook message because
          // OpenClaw wraps webhook content in an EXTERNAL_UNTRUSTED_CONTENT security
          // envelope that instructs models not to execute tools from untrusted content.
          // Instead, each agent's AGENTS.md (loaded as system prompt) contains the
          // callback URL templates. The agent reads case_id from this data and
          // substitutes it into the URL pattern from its system prompt.
          dispatchToGateway("/webhook/wazuh-alert", {
            message: `New triage task. Case ID: ${effectiveCaseId}. Severity: ${severity}. Title: ${caseData.title}. Entities: ${entities.length} extracted. Follow your AGENTS.md instructions to triage this alert and advance the pipeline.`,
            case_id: effectiveCaseId,
            severity,
            title: caseData.title,
            entities_count: entities.length,
            trigger: "alert_ingestion",
          }).catch((err) => {
            log("warn", "dispatch", "Failed to dispatch alert ingestion webhook", { case_id: effectiveCaseId, error: err.message });
            incrementMetric("webhook_dispatch_failures_total");
          });
        }

        // Record metrics
        incrementMetric("alerts_ingested_total");
        const triageLatency = (Date.now() - triageStart) / 1000;
        recordLatency("triage_latency_seconds", triageLatency);

        res.writeHead(existingCase ? 200 : 201, { "Content-Type": JSON_CONTENT_TYPE });
        res.end(JSON.stringify({
          case_id: effectiveCaseId,
          status: existingCase ? "updated" : "created",
          severity,
          entities_extracted: entities.length,
          mitre_mappings: mitre.length,
          triage_latency_ms: Math.round(triageLatency * 1000),
          ...(groupedCaseId && { grouped_into: groupedCaseId }),
        }));
        return;
      }

      // =================================================================
      // RESPONDER STATUS ENDPOINT
      // =================================================================
      if (url.pathname === "/api/responder/status" && req.method === "GET") {
        const authResult = validateAuthorization(req, "read", url);
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
      // AGENT ACTION ENDPOINTS — GET-based write-back for OpenClaw agents
      // OpenClaw's web_fetch tool is GET-only (no method/body/headers params).
      // These endpoints let agents advance the pipeline via GET + query params.
      // Auth: Bearer header OR ?token= query parameter (for web_fetch compat).
      // Same validation as POST/PUT counterparts.
      // =================================================================

      // Agent action: update case status (replaces PUT /api/cases/:id)
      if (url.pathname === "/api/agent-action/update-case" && req.method === "GET") {
        const authResult = validateAuthorization(req, "write", url);
        if (!authResult.valid) {
          sendAuthError(res, authResult, requestId);
          return;
        }

        const caseId = url.searchParams.get("case_id");
        const status = url.searchParams.get("status");
        const dataParam = url.searchParams.get("data");

        if (!caseId) {
          sendJsonError(res, 400, "Missing case_id", requestId);
          return;
        }
        // Issue #22 fix: If case_id is just the hash suffix (LLM stripped CASE-date- prefix),
        // attempt to find the full case_id by scanning recent cases.
        let effectiveCaseId = caseId;
        if (!isValidCaseId(caseId) && /^[a-f0-9]{6,12}$/.test(caseId)) {
          try {
            const recentCases = await listCases({ limit: 200 });
            const match = recentCases.find(c => c.case_id && c.case_id.endsWith(caseId));
            if (match) {
              effectiveCaseId = match.case_id;
              log("warn", "agent-action", "Resolved truncated case_id to full ID", {
                original: caseId, resolved: effectiveCaseId,
              });
            }
          } catch { /* fallthrough to validation error */ }
        }
        if (!isValidCaseId(effectiveCaseId)) {
          sendJsonError(res, 400, "Invalid case_id — use the full ID including CASE- prefix", requestId);
          return;
        }

        const VALID_AGENT_STATUSES = ["triaged", "correlated", "investigated", "planned", "approved", "executed", "closed", "false_positive"];
        if (status && !VALID_AGENT_STATUSES.includes(status)) {
          sendJsonError(res, 400, `Invalid status: must be one of ${VALID_AGENT_STATUSES.join(", ")}`, requestId);
          return;
        }

        const ALLOWED_DATA_FIELDS = [
          "title", "summary", "severity", "confidence",
          // Triage agent output
          "auto_verdict", "verdict_reason",
          // Correlation agent output
          "correlation", "related_cases",
          // Investigation agent output
          "findings", "investigation_notes", "pivot_results", "enrichment_data",
          "iocs_identified", "iocs", "key_questions_answered", "recommended_response",
          // Shared fields
          "mitre", "entities", "timeline",
        ];
        const STRING_FIELDS = ["title", "summary", "severity", "investigation_notes", "auto_verdict", "verdict_reason"];
        const NUMBER_FIELDS = ["confidence"];
        const OBJECT_FIELDS = ["correlation", "enrichment_data", "findings", "pivot_results", "key_questions_answered"];
        const ARRAY_FIELDS = ["iocs_identified", "iocs", "entities", "timeline", "recommended_response", "related_cases"];
        // mitre accepts both object (single mapping) and array (multiple mappings) — normalized in updateCase()
        const OBJECT_OR_ARRAY_FIELDS = ["mitre"];
        const VALID_SEVERITIES = ["informational", "low", "medium", "high", "critical"];
        const MAX_DATA_SIZE = 512 * 1024; // 512 KB
        const updates = {};
        if (status) updates.status = status;
        if (dataParam) {
          if (dataParam.length > MAX_DATA_SIZE) {
            sendJsonError(res, 400, "Data parameter exceeds 512 KB limit", requestId);
            return;
          }
          // Issue #22 fix: Local LLMs often fail to URL-encode JSON, so
          // &data={"key":"val & more"} gets split at the & inside the JSON.
          // Try primary parse first; only attempt reconstruction on failure.
          let parsed;
          try {
            parsed = JSON.parse(dataParam);
          } catch {
            // Fallback: re-join orphan query params that were split from the data value
            const KNOWN_PARAMS = new Set(["case_id", "status", "data", "token"]);
            const orphanParts = [];
            for (const [key, value] of url.searchParams.entries()) {
              if (!KNOWN_PARAMS.has(key)) {
                orphanParts.push(value ? `${key}=${value}` : key);
              }
            }
            if (orphanParts.length > 0) {
              const reconstructed = dataParam + "&" + orphanParts.join("&");
              try {
                parsed = JSON.parse(reconstructed);
                log("warn", "agent-action", "Reconstructed truncated JSON from unencoded data param", {
                  case_id: effectiveCaseId,
                  original_length: dataParam.length,
                  reconstructed_length: reconstructed.length,
                });
              } catch {
                // Both attempts failed — fall through to error below
              }
            }
          }
          try {
            if (!parsed) throw new Error("Invalid JSON");
            // parsed is already set from above
            if (typeof parsed !== "object" || parsed === null || Array.isArray(parsed)) {
              sendJsonError(res, 400, "Data parameter must be a JSON object", requestId);
              return;
            }
            const skippedFields = [];
            for (const key of Object.keys(parsed)) {
              if (!ALLOWED_DATA_FIELDS.includes(key)) continue;
              const val = parsed[key];
              if (STRING_FIELDS.includes(key) && typeof val !== "string") { skippedFields.push(key); continue; }
              if (NUMBER_FIELDS.includes(key) && typeof val !== "number") {
                // Coerce string numbers from LLMs (e.g. "0.9" → 0.9)
                if (typeof val === "string") {
                  const coerced = Number(val);
                  if (!Number.isNaN(coerced)) { parsed[key] = coerced; } else { skippedFields.push(key); continue; }
                } else { skippedFields.push(key); continue; }
              }
              if (OBJECT_FIELDS.includes(key) && (typeof val !== "object" || val === null || Array.isArray(val))) { skippedFields.push(key); continue; }
              if (ARRAY_FIELDS.includes(key) && !Array.isArray(val)) {
                // entities: accept nested object format {ips:[...], users:[...], ...} and normalize to flat array
                if (key === "entities" && typeof val === "object" && val !== null) {
                  const flat = [];
                  const categoryToType = { ips: "ip", users: "user", hosts: "host", processes: "process", hashes: "hash", domains: "domain", files: "file", urls: "url", emails: "email" };
                  for (const [cat, items] of Object.entries(val)) {
                    if (!Array.isArray(items)) continue;
                    const entityType = categoryToType[cat] || cat.replace(/s$/, "");
                    for (const item of items) {
                      if (typeof item === "object" && item !== null && item.value) {
                        flat.push({ type: entityType, value: item.value, role: item.direction || item.type || item.role || "unknown", context: item.context || "" });
                      }
                    }
                  }
                  if (flat.length > 0) { updates[key] = flat; continue; }
                }
                skippedFields.push(key); continue;
              }
              if (OBJECT_OR_ARRAY_FIELDS.includes(key) && typeof val !== "object") { skippedFields.push(key); continue; }
              // Severity enum validation (normalize case from LLMs e.g. "Critical" → "critical")
              if (key === "severity") {
                const normalized = typeof val === "string" ? val.toLowerCase().trim() : val;
                if (!VALID_SEVERITIES.includes(normalized)) {
                  sendJsonError(res, 400, `Invalid severity '${val}': must be one of ${VALID_SEVERITIES.join(", ")}`, requestId);
                  return;
                }
                parsed[key] = normalized;
              }
              // Confidence range validation
              if (key === "confidence" && (parsed[key] < 0 || parsed[key] > 1)) {
                sendJsonError(res, 400, `Invalid confidence ${val}: must be between 0.0 and 1.0`, requestId);
                return;
              }
              updates[key] = parsed[key]; // Use parsed[key] to pick up coerced values
            }
            if (skippedFields.length > 0) {
              log("warn", "agent-action", "Skipped fields with wrong type", {
                case_id: effectiveCaseId,
                skipped: skippedFields,
              });
            }
          } catch {
            sendJsonError(res, 400, "Invalid JSON in data parameter", requestId);
            return;
          }
        }

        if (Object.keys(updates).length === 0) {
          sendJsonError(res, 400, "No updates provided (use status and/or data params)", requestId);
          return;
        }

        // Stage-specific mandatory field checks — reject incomplete agent output
        // Only enforced when agent provides data that produced accepted fields (status-only
        // updates and data with only dropped/unknown fields skip this for backward compatibility)
        const STAGE_REQUIRED_FIELDS = {
          triaged: ["title", "severity"],
          investigated: ["findings", "investigation_notes"],
        };
        const dataFieldCount = Object.keys(updates).filter(k => k !== "status").length;
        if (status && dataParam && dataFieldCount > 0 && STAGE_REQUIRED_FIELDS[status]) {
          const missing = STAGE_REQUIRED_FIELDS[status].filter(f => !updates[f]);
          if (missing.length > 0) {
            sendJsonError(res, 400, `Status '${status}' requires data fields: ${missing.join(", ")}`, requestId);
            return;
          }
        }

        try {
          const updatedCase = await updateCase(effectiveCaseId, updates);
          log("info", "agent-action", "Case updated via agent action", { case_id: effectiveCaseId, status });
          res.writeHead(200, { "Content-Type": JSON_CONTENT_TYPE });
          res.end(JSON.stringify({ ok: true, case_id: effectiveCaseId, status: updatedCase.status }));
        } catch (err) {
          if (err.message.includes("not found")) {
            sendJsonError(res, 404, "Case not found", requestId);
          } else if (err.message.includes("Invalid status transition")) {
            sendJsonError(res, 400, err.message, requestId);
          } else {
            throw err;
          }
        }
        return;
      }

      // Agent action: create response plan (replaces POST /api/plans)
      if (url.pathname === "/api/agent-action/create-plan" && req.method === "GET") {
        const authResult = validateAuthorization(req, "write", url);
        if (!authResult.valid) {
          sendAuthError(res, authResult, requestId);
          return;
        }

        const caseId = url.searchParams.get("case_id");
        const title = url.searchParams.get("title");
        const description = url.searchParams.get("description") || "";
        const riskLevelRaw = url.searchParams.get("risk_level") || "medium";
        const riskLevel = riskLevelRaw.toLowerCase().trim(); // Normalize case from LLMs
        const actionsParam = url.searchParams.get("actions");

        const VALID_RISK_LEVELS = ["low", "medium", "high", "critical"];
        if (!VALID_RISK_LEVELS.includes(riskLevel)) {
          sendJsonError(res, 400, `Invalid risk_level: must be one of ${VALID_RISK_LEVELS.join(", ")}`, requestId);
          return;
        }

        if (!caseId) {
          sendJsonError(res, 400, "Missing case_id", requestId);
          return;
        }
        // Issue #22 fix: If case_id is just the hash suffix (LLM stripped CASE-date- prefix),
        // attempt to find the full case_id by scanning recent cases.
        let effectiveCaseId = caseId;
        if (!isValidCaseId(caseId) && /^[a-f0-9]{6,12}$/.test(caseId)) {
          try {
            const recentCases = await listCases({ limit: 200 });
            const match = recentCases.find(c => c.case_id && c.case_id.endsWith(caseId));
            if (match) {
              effectiveCaseId = match.case_id;
              log("warn", "agent-action", "Resolved truncated case_id to full ID", {
                original: caseId, resolved: effectiveCaseId,
              });
            }
          } catch { /* fallthrough to validation error */ }
        }
        if (!isValidCaseId(effectiveCaseId)) {
          sendJsonError(res, 400, "Invalid case_id — use the full ID including CASE- prefix", requestId);
          return;
        }
        if (!title) {
          sendJsonError(res, 400, "Missing title parameter", requestId);
          return;
        }
        if (title.length > 500) {
          sendJsonError(res, 400, "Title exceeds 500 character limit", requestId);
          return;
        }
        if (description.length > 10000) {
          sendJsonError(res, 400, "Description exceeds 10000 character limit", requestId);
          return;
        }

        let actions;
        try {
          actions = JSON.parse(actionsParam || "[]");
        } catch {
          sendJsonError(res, 400, "Invalid JSON in actions parameter", requestId);
          return;
        }
        if (!Array.isArray(actions) || actions.length === 0) {
          sendJsonError(res, 400, "actions parameter must be a non-empty JSON array", requestId);
          return;
        }
        if (actions.length > MAX_ACTIONS_PER_PLAN) {
          sendJsonError(res, 400, `actions array exceeds maximum of ${MAX_ACTIONS_PER_PLAN} actions`, requestId);
          return;
        }

        // Verify case exists and get its confidence for policy checks
        let caseData;
        try {
          caseData = await getCase(effectiveCaseId);
        } catch {
          sendJsonError(res, 404, `Case ${effectiveCaseId} not found — cannot create plan for non-existent case`, requestId);
          return;
        }

        // Use explicit confidence param if provided, otherwise inherit from case
        const confidenceParam = url.searchParams.get("confidence");
        let confidence = caseData.confidence || 0;
        if (confidenceParam !== null) {
          const parsed = parseFloat(confidenceParam);
          if (Number.isNaN(parsed) || parsed < 0 || parsed > 1) {
            sendJsonError(res, 400, "confidence must be a number between 0 and 1", requestId);
            return;
          }
          confidence = parsed;
        }

        try {
          const planData = { case_id: effectiveCaseId, title, description, risk_level: riskLevel, actions, confidence };
          const plan = createResponsePlan(planData);

          try {
            await updateCase(effectiveCaseId, {
              status: "planned",
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
              case_id: effectiveCaseId,
              error: err.message,
            });
          }

          log("info", "agent-action", "Plan created via agent action", { plan_id: plan.plan_id, case_id: effectiveCaseId });
          res.writeHead(201, { "Content-Type": JSON_CONTENT_TYPE });
          res.end(JSON.stringify({
            ok: true,
            plan_id: plan.plan_id,
            state: plan.state,
            message: "Plan created in PROPOSED state. Requires Tier 1 approval before execution.",
          }));
        } catch (err) {
          sendJsonError(res, 400, err.message, requestId);
        }
        return;
      }

      // Agent action: approve plan (replaces POST /api/plans/:id/approve)
      if (url.pathname === "/api/agent-action/approve-plan" && req.method === "GET") {
        const authResult = validateAuthorization(req, "write", url);
        if (!authResult.valid) {
          sendAuthError(res, authResult, requestId);
          return;
        }

        const planId = url.searchParams.get("plan_id");
        const approverId = url.searchParams.get("approver_id");
        const decision = url.searchParams.get("decision") || "allow";
        const reason = url.searchParams.get("reason") || "";

        const VALID_DECISIONS = ["allow", "deny", "escalate"];
        if (!VALID_DECISIONS.includes(decision)) {
          sendJsonError(res, 400, `Invalid decision: must be one of ${VALID_DECISIONS.join(", ")}`, requestId);
          return;
        }

        // Issue #22 fix: If plan_id is fabricated by LLM (e.g., PLAN-20260323-{case_hash}),
        // attempt to find the actual plan by scanning for plans matching the case_id.
        let effectivePlanId = planId;
        if (planId && !isValidPlanId(planId)) {
          const caseId = url.searchParams.get("case_id");
          const resolved = resolvePlanId(planId, caseId, "proposed");
          if (resolved) {
            effectivePlanId = resolved;
            log("warn", "agent-action", "Resolved fabricated plan_id to actual plan", {
              original: planId, resolved: effectivePlanId, endpoint: "approve-plan",
            });
          }
        }
        if (!effectivePlanId || !isValidPlanId(effectivePlanId)) {
          sendJsonError(res, 400, "Invalid or missing plan_id — plan IDs have the format PLAN-{timestamp}-{hash} (e.g., PLAN-1774277057126-d40a2c58). Do NOT construct plan_id from the case_id.", requestId);
          return;
        }
        if (!approverId || !isValidIdentityId(approverId)) {
          sendJsonError(res, 400, "Invalid or missing approver_id", requestId);
          return;
        }

        try {
          if (decision === "deny" || decision === "escalate") {
            const plan = rejectPlan(effectivePlanId, approverId, reason || decision);
            log("info", "agent-action", "Plan rejected via agent action", { plan_id: effectivePlanId, decision });
            res.writeHead(200, { "Content-Type": JSON_CONTENT_TYPE });
            res.end(JSON.stringify({ ok: true, plan_id: effectivePlanId, state: plan.state, decision }));
            return;
          }

          // Policy enforcement: check approver authorization
          const planForCheck = getPlan(effectivePlanId, { updateExpiry: false });
          const actionTypes = (planForCheck.actions || []).map((a) => a.type);
          const approverResult = policyCheckApprover(approverId, actionTypes, planForCheck.risk_level);
          if (!approverResult.authorized) {
            incrementMetric("policy_denies_total", { reason: "approver_denied" });
            sendJsonError(res, 403, `Approver not authorized: ${approverResult.reason}`, requestId);
            return;
          }

          const plan = approvePlan(effectivePlanId, approverId, reason);
          log("info", "agent-action", "Plan approved via agent action", { plan_id: effectivePlanId, approver_id: approverId });
          res.writeHead(200, { "Content-Type": JSON_CONTENT_TYPE });
          res.end(JSON.stringify({
            ok: true,
            plan_id: effectivePlanId,
            state: plan.state,
            message: "Plan APPROVED (Tier 1 complete). Ready for execution.",
          }));
        } catch (err) {
          sendJsonError(res, err.message.includes("not found") ? 404 : 400, err.message, requestId);
        }
        return;
      }

      // Agent action: execute plan (replaces POST /api/plans/:id/execute)
      if (url.pathname === "/api/agent-action/execute-plan" && req.method === "GET") {
        const authResult = validateAuthorization(req, "write", url);
        if (!authResult.valid) {
          sendAuthError(res, authResult, requestId);
          return;
        }

        const planId = url.searchParams.get("plan_id");
        const executorId = url.searchParams.get("executor_id");

        // Issue #22 fix: If plan_id is fabricated by LLM, resolve to actual plan
        let effectivePlanId = planId;
        if (planId && !isValidPlanId(planId)) {
          const caseId = url.searchParams.get("case_id");
          const resolved = resolvePlanId(planId, caseId, "approved");
          if (resolved) {
            effectivePlanId = resolved;
            log("warn", "agent-action", "Resolved fabricated plan_id to actual plan", {
              original: planId, resolved: effectivePlanId, endpoint: "execute-plan",
            });
          }
        }
        if (!effectivePlanId || !isValidPlanId(effectivePlanId)) {
          sendJsonError(res, 400, "Invalid or missing plan_id — plan IDs have the format PLAN-{timestamp}-{hash} (e.g., PLAN-1774277057126-d40a2c58). Do NOT construct plan_id from the case_id.", requestId);
          return;
        }
        if (!executorId || !isValidIdentityId(executorId)) {
          sendJsonError(res, 400, "Invalid or missing executor_id", requestId);
          return;
        }

        try {
          // Policy enforcement: check evidence sufficiency
          const planForEvidence = getPlan(effectivePlanId, { updateExpiry: false });
          const evidenceResult = await policyCheckEvidence(planForEvidence.actions, planForEvidence.case_id);
          if (!evidenceResult.sufficient) {
            incrementMetric("policy_denies_total", { reason: "insufficient_evidence" });
            sendJsonError(res, 403, `Insufficient evidence: ${evidenceResult.reason}`, requestId);
            return;
          }

          const plan = await executePlan(effectivePlanId, executorId);
          const statusCode = plan.state === PLAN_STATES.COMPLETED ? 200 : 207;
          log("info", "agent-action", "Plan executed via agent action", { plan_id: effectivePlanId, state: plan.state });
          res.writeHead(statusCode, { "Content-Type": JSON_CONTENT_TYPE });
          res.end(JSON.stringify({
            ok: true,
            plan_id: effectivePlanId,
            state: plan.state,
            message: plan.state === PLAN_STATES.COMPLETED
              ? "Plan EXECUTED successfully."
              : "Plan execution completed with some failures.",
          }));
        } catch (err) {
          if (err.message.includes("Responder capability is DISABLED")) {
            res.writeHead(403, { "Content-Type": JSON_CONTENT_TYPE });
            res.end(JSON.stringify({
              error: err.message,
              request_id: requestId,
              responder_status: getResponderStatus(),
            }));
            return;
          }
          sendJsonError(res, err.message.includes("not found") ? 404 : 400, err.message, requestId);
        }
        return;
      }

      // =================================================================
      // AGENT-ACTION: SEARCH ALERTS — Proxy read queries to Wazuh MCP
      // =================================================================
      if (url.pathname === "/api/agent-action/search-alerts" && req.method === "GET") {
        const authResult = validateAuthorization(req, "read", url);
        if (!authResult.valid) {
          sendAuthError(res, authResult, requestId);
          return;
        }

        const query = url.searchParams.get("query") || "";
        const timeRange = url.searchParams.get("time_range") || "24h";
        const limitParam = url.searchParams.get("limit");
        const ruleId = url.searchParams.get("rule_id");
        const agentId = url.searchParams.get("agent_id");
        const level = url.searchParams.get("level");

        // Validate limit
        let limit = 50;
        if (limitParam) {
          limit = parseInt(limitParam, 10);
          if (Number.isNaN(limit) || limit < 1 || limit > 500) {
            sendJsonError(res, 400, "limit must be a number between 1 and 500", requestId);
            return;
          }
        }

        // Validate time_range format (e.g., "24h", "7d", "30m", "168h")
        if (!/^\d+[smhdw]$/.test(timeRange)) {
          sendJsonError(res, 400, "time_range must be a duration like 24h, 7d, 30m", requestId);
          return;
        }

        if (!config.mcpUrl) {
          sendJsonError(res, 503, "MCP server not configured — cannot proxy alert queries", requestId);
          return;
        }

        try {
          let mcpResult;
          const correlationId = `search-${requestId}`;

          if (query) {
            // Use search_security_events for free-text/field queries
            mcpResult = await callMcpTool("search_events", {
              query,
              time_range: timeRange,
              limit,
            }, correlationId);
          } else {
            // Use get_wazuh_alerts for structured filter queries
            const params = { limit };
            if (ruleId) params.rule_id = ruleId;
            if (agentId) params.agent_id = agentId;
            if (level) params.level = level;
            // Convert time_range to timestamp_start
            const durationSec = parseDurationToSeconds(timeRange);
            if (durationSec) {
              params.timestamp_start = new Date(Date.now() - durationSec * 1000).toISOString();
            }
            mcpResult = await callMcpTool("get_alert", params, correlationId);
          }

          log("info", "agent-action", "Search alerts proxy completed", {
            query: query || "(structured)",
            time_range: timeRange,
            limit,
            request_id: requestId,
          });

          res.writeHead(200, { "Content-Type": JSON_CONTENT_TYPE });
          res.end(JSON.stringify({
            ok: true,
            query: query || null,
            time_range: timeRange,
            limit,
            results: mcpResult,
          }));
        } catch (err) {
          log("error", "agent-action", "Search alerts proxy failed", {
            error: err.message,
            request_id: requestId,
          });
          sendJsonError(res, 502, `MCP query failed: ${err.message}`, requestId);
        }
        return;
      }

      // =================================================================
      // AGENT-ACTION: GET AGENT INFO — Proxy agent queries to Wazuh MCP
      // =================================================================
      if (url.pathname === "/api/agent-action/get-agent" && req.method === "GET") {
        const authResult = validateAuthorization(req, "read", url);
        if (!authResult.valid) {
          sendAuthError(res, authResult, requestId);
          return;
        }

        const agentId = url.searchParams.get("agent_id");
        if (!agentId) {
          sendJsonError(res, 400, "agent_id parameter is required", requestId);
          return;
        }
        // Audit fix H6: Validate agent_id format to prevent path traversal
        if (!/^\d{1,6}$/.test(agentId)) {
          sendJsonError(res, 400, "agent_id must be numeric (1-6 digits)", requestId);
          return;
        }

        if (!config.mcpUrl) {
          sendJsonError(res, 503, "MCP server not configured — cannot proxy agent queries", requestId);
          return;
        }

        try {
          const correlationId = `agent-info-${requestId}`;
          const mcpResult = await callMcpTool("get_agent", { agent_id: agentId }, correlationId);

          res.writeHead(200, { "Content-Type": JSON_CONTENT_TYPE });
          res.end(JSON.stringify({
            ok: true,
            agent_id: agentId,
            results: mcpResult,
          }));
        } catch (err) {
          log("error", "agent-action", "Get agent proxy failed", {
            error: err.message,
            request_id: requestId,
          });
          sendJsonError(res, 502, `MCP query failed: ${err.message}`, requestId);
        }
        return;
      }

      // =================================================================
      // RESPONSE PLANS API - Two-Tier Human-in-the-Loop
      // =================================================================

      // List plans
      if (url.pathname === "/api/plans" && req.method === "GET") {
        const authResult = validateAuthorization(req, "read", url);
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
        const authResult = validateAuthorization(req, "write", url);
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

        // Verify case exists and inherit confidence for policy checks
        let planCaseData;
        try {
          planCaseData = await getCase(body.case_id);
        } catch (e) {
          sendJsonError(res, 404, `Case ${body.case_id} not found — cannot create plan for non-existent case`, requestId);
          return;
        }

        // If confidence not provided in body, inherit from case
        if (body.confidence === undefined || body.confidence === null) {
          body.confidence = planCaseData.confidence || 0;
        } else if (typeof body.confidence === "string") {
          // Coerce string numbers from LLMs (e.g. "0.9" → 0.9)
          const parsed = parseFloat(body.confidence);
          body.confidence = Number.isNaN(parsed) ? 0 : parsed;
        }

        try {
          const plan = createResponsePlan(body);

          // Also update the case with the proposed plan and advance status to planned
          try {
            await updateCase(body.case_id, {
              status: "planned",
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

      // Plans summary (must be BEFORE plans/:id to avoid regex matching "summary" as an ID)
      if (url.pathname === "/api/plans/summary" && req.method === "GET") {
        const authResult = validateAuthorization(req, "read", url);
        if (!authResult.valid) {
          sendAuthError(res, authResult, requestId);
          return;
        }

        const allPlans = listPlans({ limit: 100000 });
        const now = Date.now();
        const by_state = {};
        let completed = 0;
        let failed = 0;
        let last_24h = 0;

        for (const p of allPlans) {
          const st = p.state || "proposed";
          by_state[st] = (by_state[st] || 0) + 1;
          if (st === "completed") completed++;
          if (st === "failed") failed++;
          const created = new Date(p.created_at).getTime();
          if (now - created <= 24 * 3600 * 1000) last_24h++;
        }

        const total = allPlans.length;
        const success_rate = (completed + failed) > 0 ? completed / (completed + failed) : 0;

        res.writeHead(200, { "Content-Type": JSON_CONTENT_TYPE });
        res.end(JSON.stringify({
          total,
          by_state,
          success_rate: Math.round(success_rate * 100) / 100,
          last_24h,
          request_id: requestId,
        }));
        return;
      }

      // Get single plan
      if (url.pathname.match(/^\/api\/plans\/[^/]+$/) && req.method === "GET") {
        const authResult = validateAuthorization(req, "read", url);
        if (!authResult.valid) {
          sendAuthError(res, authResult, requestId);
          return;
        }

        const planId = url.pathname.split("/")[3];
        if (!isValidPlanId(planId)) {
          sendJsonError(res, 400, "Invalid plan ID format", requestId);
          return;
        }
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
        const authResult = validateAuthorization(req, "write", url);
        if (!authResult.valid) {
          sendAuthError(res, authResult, requestId);
          return;
        }

        const planId = url.pathname.split("/")[3];
        if (!isValidPlanId(planId)) {
          sendJsonError(res, 400, "Invalid plan ID format", requestId);
          return;
        }
        const body = await parseJsonBody(req);

        if (!body.approver_id || !isValidIdentityId(body.approver_id)) {
          sendJsonError(res, 400, "Valid approver_id is required (alphanumeric, 1-128 chars)", requestId);
          return;
        }

        try {
          // Policy enforcement: check approver authorization
          const planForCheck = getPlan(planId, { updateExpiry: false });
          const actionTypes = (planForCheck.actions || []).map((a) => a.type);
          const approverResult = policyCheckApprover(body.approver_id, actionTypes, planForCheck.risk_level);
          if (!approverResult.authorized) {
            incrementMetric("policy_denies_total", { reason: "approver_denied" });
            log("warn", "policy", "Approver denied by policy", {
              approver_id: body.approver_id,
              plan_id: planId,
              reason: approverResult.reason,
            });
            sendJsonError(res, 403, `Approver not authorized: ${approverResult.reason}`, requestId);
            return;
          }

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
        const authResult = validateAuthorization(req, "write", url);
        if (!authResult.valid) {
          sendAuthError(res, authResult, requestId);
          return;
        }

        const planId = url.pathname.split("/")[3];
        if (!isValidPlanId(planId)) {
          sendJsonError(res, 400, "Invalid plan ID format", requestId);
          return;
        }
        const body = await parseJsonBody(req);

        if (!body.rejector_id || !isValidIdentityId(body.rejector_id)) {
          sendJsonError(res, 400, "Valid rejector_id is required (alphanumeric, 1-128 chars)", requestId);
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
        const authResult = validateAuthorization(req, "write", url);
        if (!authResult.valid) {
          sendAuthError(res, authResult, requestId);
          return;
        }

        const planId = url.pathname.split("/")[3];
        if (!isValidPlanId(planId)) {
          sendJsonError(res, 400, "Invalid plan ID format", requestId);
          return;
        }
        const body = await parseJsonBody(req);

        if (!body.executor_id || !isValidIdentityId(body.executor_id)) {
          sendJsonError(res, 400, "Valid executor_id is required (alphanumeric, 1-128 chars)", requestId);
          return;
        }

        try {
          // Policy enforcement: check evidence sufficiency before execution
          const planForEvidence = getPlan(planId, { updateExpiry: false });
          const evidenceResult = await policyCheckEvidence(planForEvidence.actions, planForEvidence.case_id);
          if (!evidenceResult.sufficient) {
            incrementMetric("policy_denies_total", { reason: "insufficient_evidence" });
            log("warn", "policy", "Execution denied: insufficient evidence", {
              plan_id: planId,
              case_id: planForEvidence.case_id,
              reason: evidenceResult.reason,
            });
            sendJsonError(res, 403, `Insufficient evidence: ${evidenceResult.reason}`, requestId);
            return;
          }

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
              request_id: requestId,
              responder_status: getResponderStatus(),
              resolution: "Contact an administrator to enable AUTOPILOT_RESPONDER_ENABLED=true",
            }));
            return;
          }

          sendJsonError(res, err.message.includes("not found") ? 404 : 400, err.message, requestId);
        }
        return;
      }

      // =================================================================
      // CASE FEEDBACK ENDPOINT
      // =================================================================
      if (url.pathname.match(/^\/api\/cases\/[^/]+\/feedback$/) && req.method === "POST") {
        const authResult = validateAuthorization(req, "write", url);
        if (!authResult.valid) {
          sendAuthError(res, authResult, requestId);
          return;
        }

        const feedbackCaseId = url.pathname.split("/")[3];
        if (!feedbackCaseId || !isValidCaseId(feedbackCaseId)) {
          sendJsonError(res, 400, "Invalid case ID format", requestId);
          return;
        }

        const body = await parseJsonBody(req);

        const validVerdicts = ["false_positive", "true_positive", "needs_review"];
        // Normalize case and whitespace from LLMs (e.g. "True_Positive" → "true_positive")
        if (body.verdict && typeof body.verdict === "string") {
          body.verdict = body.verdict.toLowerCase().trim();
        }
        if (!body.verdict || !validVerdicts.includes(body.verdict)) {
          sendJsonError(res, 400, `verdict must be one of: ${validVerdicts.join(", ")}`, requestId);
          return;
        }

        try {
          // Build feedback record
          const feedback = {
            verdict: body.verdict,
            reason: body.reason || "",
            user_id: body.user_id || "anonymous",
            submitted_at: new Date().toISOString(),
          };

          // Use appendFeedback for atomic append inside the case lock (race-safe)
          const updates = { appendFeedback: feedback };

          // If false positive, update case status and entity index
          // Only attempt status change if the case isn't in a terminal state
          if (body.verdict === "false_positive") {
            markEntityFalsePositive(feedbackCaseId);
            incrementMetric("false_positives_total");
            try {
              const currentCase = await getCase(feedbackCaseId);
              if (!["closed", "false_positive", "executed"].includes(currentCase.status)) {
                updates.status = "false_positive";
              }
            } catch { /* proceed without status change */ }
          }

          const updatedCase = await updateCase(feedbackCaseId, updates);
          const feedbackCount = (updatedCase.feedback || []).length;

          incrementMetric("feedback_submitted_total", { verdict: body.verdict });
          log("info", "feedback", "Case feedback submitted", {
            case_id: feedbackCaseId,
            verdict: body.verdict,
            user_id: feedback.user_id,
          });

          res.writeHead(200, { "Content-Type": JSON_CONTENT_TYPE });
          res.end(JSON.stringify({
            case_id: feedbackCaseId,
            verdict: body.verdict,
            feedback_count: feedbackCount,
            status: updatedCase.status || "open",
          }));
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
      // REPORTING ENDPOINTS
      // =================================================================

      // KPI metrics
      if (url.pathname === "/api/kpis" && req.method === "GET") {
        const authResult = validateAuthorization(req, "read", url);
        if (!authResult.valid) {
          sendAuthError(res, authResult, requestId);
          return;
        }

        const period = url.searchParams.get("period") || "24h";
        const periodMap = { "1h": 3600, "8h": 28800, "24h": 86400, "7d": 604800, "30d": 2592000 };
        const periodSeconds = periodMap[period];
        if (!periodSeconds) {
          sendJsonError(res, 400, "Invalid period. Supported: 1h, 8h, 24h, 7d, 30d", requestId);
          return;
        }

        const slaTriage = parseInt(process.env.SLA_TRIAGE_SECONDS || "900", 10);
        const slaResponse = parseInt(process.env.SLA_RESPONSE_SECONDS || "3600", 10);
        const now = Date.now();
        const cutoff = now - periodSeconds * 1000;

        const allCases = await listCases({ limit: 100000 });
        const periodCases = allCases.filter(c => new Date(c.created_at).getTime() >= cutoff);

        // Read full evidence packs for cases in the period to get status_history
        const mttdValues = [];
        const mtttValues = [];
        const mttiValues = [];
        const mttrValues = [];
        const mttcValues = [];
        let autoTriaged = 0;
        let falsePositives = 0;
        let triageWithinSla = 0;
        let responseWithinSla = 0;

        for (const caseSummary of periodCases) {
          try {
            const caseData = await getCase(caseSummary.case_id);
            const history = caseData.status_history;
            const hasHistory = history && Array.isArray(history) && history.length > 0;

            const findTransition = (toStatus) =>
              hasHistory ? history.find(h => h.to === toStatus) : undefined;

            const openEntry = findTransition("open");
            const triagedEntry = findTransition("triaged");
            const investigatedEntry = findTransition("investigated");
            const executedEntry = findTransition("executed");
            const closedEntry = findTransition("closed");

            // Use the open transition timestamp, falling back to created_at for legacy cases
            const openTs = openEntry ? new Date(openEntry.timestamp).getTime() : new Date(caseData.created_at).getTime();

            // MTTD: time from first alert to case creation (detection)
            // Use timeline[0].timestamp as the alert time if available, otherwise skip
            const alertTs = (caseData.timeline && caseData.timeline.length > 0 && caseData.timeline[0].timestamp)
              ? new Date(caseData.timeline[0].timestamp).getTime()
              : null;
            if (alertTs) {
              const detectionDelta = (new Date(caseData.created_at).getTime() - alertTs) / 1000;
              if (detectionDelta >= 0) mttdValues.push(detectionDelta);
            }

            if (triagedEntry) {
              const triageTime = (new Date(triagedEntry.timestamp).getTime() - openTs) / 1000;
              if (triageTime >= 0) {
                mtttValues.push(triageTime);
                if (triageTime <= slaTriage) triageWithinSla++;
              }
              autoTriaged++;
            }

            if (investigatedEntry && triagedEntry) {
              const delta = (new Date(investigatedEntry.timestamp).getTime() - new Date(triagedEntry.timestamp).getTime()) / 1000;
              if (delta >= 0) mttiValues.push(delta);
            }

            // MTTR: time from open to response (executed or closed)
            // Look for "executed" transition first, fall back to "closed"
            const responseEntry = executedEntry || closedEntry;
            if (responseEntry) {
              const delta = (new Date(responseEntry.timestamp).getTime() - openTs) / 1000;
              if (delta >= 0) {
                mttrValues.push(delta);
                if (delta <= slaResponse) responseWithinSla++;
              }
            }

            // MTTC: only include cases that actually have a "closed" transition
            if (closedEntry) {
              const delta = (new Date(closedEntry.timestamp).getTime() - openTs) / 1000;
              if (delta >= 0) mttcValues.push(delta);
            }

            // Count false positives by status OR auto_verdict (investigation may classify
            // as false_positive while the pipeline status continues to executed/closed)
            if (caseData.status === "false_positive" || caseData.auto_verdict === "false_positive") falsePositives++;
          } catch {
            // Skip cases that can't be read
          }
        }

        const avg = (arr) => arr.length > 0 ? Math.round(arr.reduce((a, b) => a + b, 0) / arr.length) : 0;
        const casesAnalyzed = periodCases.length;

        res.writeHead(200, { "Content-Type": JSON_CONTENT_TYPE });
        res.end(JSON.stringify({
          period,
          cases_analyzed: casesAnalyzed,
          mttd: avg(mttdValues),
          mttd_cases: mttdValues.length,
          mttt: avg(mtttValues),
          mttt_cases: mtttValues.length,
          mtti: avg(mttiValues),
          mtti_cases: mttiValues.length,
          mttr: avg(mttrValues),
          mttr_cases: mttrValues.length,
          mttc: avg(mttcValues),
          mttc_cases: mttcValues.length,
          auto_triage_rate: casesAnalyzed > 0 ? Math.round((autoTriaged / casesAnalyzed) * 100) / 100 : 0,
          false_positive_rate: casesAnalyzed > 0 ? Math.round((falsePositives / casesAnalyzed) * 100) / 100 : 0,
          sla_compliance: {
            triage_within_15m: mtttValues.length > 0 ? Math.round((triageWithinSla / mtttValues.length) * 100) / 100 : 0,
            response_within_1h: mttrValues.length > 0 ? Math.round((responseWithinSla / mttrValues.length) * 100) / 100 : 0,
          },
          request_id: requestId,
        }));
        return;
      }

      // Agent action: store report (GET-only for web_fetch compatibility)
      if (url.pathname === "/api/agent-action/store-report" && req.method === "GET") {
        const authResult = validateAuthorization(req, "write", url);
        if (!authResult.valid) {
          sendAuthError(res, authResult, requestId);
          return;
        }

        const reportType = url.searchParams.get("type");
        const reportData = url.searchParams.get("data");

        const validTypes = ["hourly", "daily", "weekly", "monthly", "shift"];
        if (!reportType || !validTypes.includes(reportType)) {
          sendJsonError(res, 400, `Invalid or missing type. Supported: ${validTypes.join(", ")}`, requestId);
          return;
        }

        if (!reportData) {
          sendJsonError(res, 400, "Missing required 'data' query parameter (JSON-encoded report)", requestId);
          return;
        }

        let parsedData;
        try {
          parsedData = JSON.parse(reportData);
        } catch {
          sendJsonError(res, 400, "Invalid JSON in 'data' query parameter", requestId);
          return;
        }

        const now = new Date();
        const dateStr = now.toISOString().slice(0, 10); // YYYY-MM-DD
        const timestamp = now.toISOString().replace(/[:.]/g, "-");
        const reportId = `RPT-${timestamp}-${crypto.randomBytes(4).toString("hex")}`;
        const reportDir = path.join(config.dataDir, "reports", reportType, dateStr);
        await ensureDir(reportDir);

        const reportFile = path.join(reportDir, `${timestamp}.json`);
        const report = {
          report_id: reportId,
          type: reportType,
          created_at: now.toISOString(),
          data: parsedData,
        };

        await atomicWriteFile(reportFile, JSON.stringify(report, null, 2));
        incrementMetric("reports_stored_total", { type: reportType });
        log("info", "reports", "Report stored", { report_id: reportId, type: reportType });

        res.writeHead(201, { "Content-Type": JSON_CONTENT_TYPE });
        res.end(JSON.stringify({
          ok: true,
          report_id: reportId,
          path: reportFile,
          request_id: requestId,
        }));
        return;
      }

      // List stored reports
      if (url.pathname === "/api/reports" && req.method === "GET") {
        const authResult = validateAuthorization(req, "read", url);
        if (!authResult.valid) {
          sendAuthError(res, authResult, requestId);
          return;
        }

        const filterType = url.searchParams.get("type");
        const limit = Math.min(Math.max(parseInt(url.searchParams.get("limit") || "20", 10), 1), 1000);
        const reportsBaseDir = path.join(config.dataDir, "reports");

        const reports = [];
        try {
          await ensureDir(reportsBaseDir);
          const typeDirs = filterType ? [filterType] : await fs.readdir(reportsBaseDir).catch(() => []);

          for (const typeDir of typeDirs) {
            const typePath = path.join(reportsBaseDir, typeDir);
            let dateDirs;
            try {
              dateDirs = await fs.readdir(typePath);
            } catch { continue; }

            for (const dateDir of dateDirs) {
              const datePath = path.join(typePath, dateDir);
              let files;
              try {
                files = await fs.readdir(datePath);
              } catch { continue; }

              for (const file of files) {
                if (!file.endsWith(".json")) continue;
                try {
                  const content = await fs.readFile(path.join(datePath, file), "utf8");
                  const report = JSON.parse(content);
                  reports.push({
                    id: report.report_id,
                    type: report.type,
                    created_at: report.created_at,
                    path: path.join(datePath, file),
                  });
                } catch { /* skip unreadable reports */ }
              }
            }
          }
        } catch { /* empty reports directory */ }

        // Sort newest first
        reports.sort((a, b) => new Date(b.created_at).getTime() - new Date(a.created_at).getTime());

        res.writeHead(200, { "Content-Type": JSON_CONTENT_TYPE });
        res.end(JSON.stringify(reports.slice(0, limit)));
        return;
      }

      // 404 for unknown routes
      sendJsonError(res, 404, "Not found", requestId);
    } catch (err) {
      const status = err.httpStatus || 500;
      const message = err.httpStatus ? err.message : "Internal server error";
      log("error", "http", "Request error", { error: err.message, status });
      sendJsonError(res, status, message, requestId);
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

  // Validate AUTOPILOT_MODE
  const VALID_MODES = ["bootstrap", "production"];
  if (!VALID_MODES.includes(config.mode)) {
    log("error", "startup", `Invalid AUTOPILOT_MODE: "${config.mode}" — must be one of: ${VALID_MODES.join(", ")}`);
    process.exit(1);
  }

  // Reject known placeholder auth tokens
  const KNOWN_PLACEHOLDERS = ["your-mcp-auth-token", "your-openclaw-gateway-token", "changeme", "test"];
  const tokensToCheck = [
    ["AUTOPILOT_MCP_AUTH", config.mcpAuth],
    ["OPENCLAW_TOKEN", config.openclawToken],
    ["OPENCLAW_WEBHOOK_TOKEN", config.openclawWebhookToken],
    ["AUTOPILOT_SERVICE_TOKEN", process.env.AUTOPILOT_SERVICE_TOKEN],
  ];
  for (const [name, value] of tokensToCheck) {
    if (value && KNOWN_PLACEHOLDERS.includes(value)) {
      log("error", "startup", `${name} is set to a known placeholder value — change it before running`);
      process.exit(1);
    }
  }

  // Warn if no auth tokens configured
  if (!config.mcpAuth && !process.env.AUTOPILOT_SERVICE_TOKEN) {
    if (config.mode === "production") {
      log("error", "startup", "Production mode requires at least one auth token (AUTOPILOT_MCP_AUTH or AUTOPILOT_SERVICE_TOKEN)");
      process.exit(1);
    } else {
      log("warn", "startup", "No auth tokens configured — write operations will only work from localhost in bootstrap mode");
    }
  }

  // Check mode
  if (config.mode === "production") {
    // Check Tailscale requirement
    if (config.requireTailscale) {
      if (config.mcpUrl && !config.mcpUrl.includes(".ts.net") && !config.mcpUrl.match(/^https?:\/\/100\./)) {
        log("error", "startup", "Production mode requires Tailnet MCP URL");
        process.exit(1);
      }
    }

    // Validate CORS origin in production
    if (config.corsEnabled && (config.corsOrigin === "*" || config.corsOrigin === "http://localhost:3000")) {
      log("warn", "startup", "Production mode: CORS_ORIGIN should be set to a specific origin, not wildcard or localhost");
    }
  }

  // Warn if OPENCLAW_GATEWAY_URL was set with ws:// scheme (auto-corrected at config load)
  const rawGatewayUrl = process.env.OPENCLAW_GATEWAY_URL || "";
  if (/^wss?:\/\//i.test(rawGatewayUrl)) {
    log("warn", "startup", `OPENCLAW_GATEWAY_URL uses WebSocket scheme "${rawGatewayUrl}" — auto-corrected to "${config.openclawGatewayUrl}". OpenClaw status shows ws:// but webhook dispatch requires HTTP.`);
  }

  // Ensure data directories exist
  await ensureDir(path.join(config.dataDir, "cases"));
  await ensureDir(path.join(config.dataDir, "reports"));
  await ensureDir(path.join(config.dataDir, "state"));

  // Load toolmap
  await loadToolmap();

  // Load and validate policy configuration (single read, no TOCTOU gap)
  // Issue #10 fix: Fail fast in production mode if policy is missing or invalid
  const policyPath = path.join(config.configDir, "policies", "policy.yaml");
  try {
    const policyContent = await fs.readFile(policyPath, "utf8");

    // Check for angle-bracket placeholders (e.g., <SLACK_WORKSPACE_ID>, <SLACK_CHANNEL_ALERTS>)
    const placeholderMatches = policyContent.match(/<[A-Z][A-Z_]+>/g);
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

    // Parse once for both validation and runtime use
    policyConfig = parseSimpleYaml(policyContent);
    log("info", "policy", "Policy config loaded", { path: policyPath });
  } catch (err) {
    if (config.mode === "production") {
      log("error", "startup", "Production mode requires valid policy file", { path: policyPath, error: err.message });
      process.exit(1);
    }
    log("warn", "startup", "Could not validate policy file", { path: policyPath, error: err.message });
  }

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

  // Warn if bootstrap approval is enabled (human-in-the-loop is disabled)
  if (config.bootstrapApproval) {
    log("warn", "startup", "AUTOPILOT_BOOTSTRAP_APPROVAL=true — human-in-the-loop approval is DISABLED. Agents can auto-approve and execute response plans without human review. Unset this variable before production use.");
  }

  // Warn if OPENCLAW_TOKEN is not set (agent pipeline will be disabled)
  if (!config.openclawToken) {
    log("warn", "startup", "OPENCLAW_TOKEN not set — agent pipeline dispatch is disabled. Set OPENCLAW_TOKEN to enable agent orchestration.");
  }

  // Warn if enrichment is enabled but API key is missing
  if (config.enrichmentEnabled && !config.abuseIpdbApiKey) {
    log("warn", "startup", "ENRICHMENT_ENABLED=true but ABUSEIPDB_API_KEY is empty — enrichment will be silently skipped");
  }

  // Connectivity probes (non-blocking, warn-only)
  if (config.mcpUrl) {
    try {
      const probe = await fetch(`${config.mcpUrl}/health`, { signal: AbortSignal.timeout(5000) });
      log("info", "startup", "MCP server reachable", { url: config.mcpUrl, status: probe.status });
    } catch (e) {
      log("warn", "startup", "MCP server NOT reachable — MCP tool calls will fail until connectivity is restored", { url: config.mcpUrl, error: e.message });
    }
  }

  if (config.openclawGatewayUrl && config.openclawToken) {
    try {
      const probe = await fetch(`${config.openclawGatewayUrl}/health`, { signal: AbortSignal.timeout(5000) });
      log("info", "startup", "OpenClaw Gateway reachable", { url: config.openclawGatewayUrl, status: probe.status });
    } catch (e) {
      log("warn", "startup", "OpenClaw Gateway NOT reachable — agent dispatch will fail", { url: config.openclawGatewayUrl, error: e.message });
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

  // Load persisted plans from disk
  await loadPlansFromDisk();

  // Setup cleanup intervals for memory management
  setupCleanupIntervals();

  // HTTP server always starts — it's the core API, not just metrics
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
    if (config.metricsEnabled) {
      log("info", "startup", `Metrics available at http://${config.metricsHost}:${config.metricsPort}/metrics`);
    }
  });

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
  ALLOWED_ACTION_TYPES,
  sanitizeAlertPayload,
  // MCP
  callMcpTool,
  getMcpAuthToken,
  ensureMcpSession,
  invalidateMcpSession,
  loadToolmap,
  resolveMcpTool,
  isToolEnabled,
  buildMcpParams,
  mcpCircuitBreaker,
  mcpCircuitBreakerCheck,
  mcpCircuitBreakerRecord,
  parseDurationToSeconds,
  // Gateway dispatch
  dispatchToGateway,
  queueFailedDispatch,
  retryDlqDispatches,
  loadDlq,
  // Enrichment
  isPrivateIp,
  enrichIpAddress,
  enrichmentCache,
  MAX_ENRICHMENT_CACHE_SIZE,
  // Alert grouping
  findRelatedCase,
  indexCaseEntities,
  markEntityFalsePositive,
  entityCaseIndex,
  MAX_ENTITY_INDEX_SIZE,
  get entityIndexWarningLogged() { return entityIndexWarningLogged; },
  set entityIndexWarningLogged(v) { entityIndexWarningLogged = v; },
  // Response plans internals (for testing)
  responsePlans,
  // Policy enforcement
  loadPolicyConfig,
  policyCheckAction,
  policyCheckApprover,
  policyCheckEvidence,
  policyCheckTimeWindow,
  policyCheckActionRateLimit,
  policyCheckIdempotency,
  recordActionExecution,
  recordActionForDedup,
  resetActionRateLimitState,
  resetDeduplicationState,
  // Metrics
  incrementMetric,
  recordLatency,
  formatMetrics,
  // Auth & validation (exported for testing)
  validateAuthorization,
  isValidCaseId,
  isValidPlanId,
  resolvePlanId,
  isValidIdentityId,
  sanitizeRequestId,
  // Rate limiting & auth lockout
  checkRateLimit,
  recordAuthFailure,
  isAuthLocked,
  clearAuthFailures,
  // HTTP helpers
  parseJsonBody,
  createServer,
  sendJsonError,
  // Plan persistence
  savePlanToDisk,
  loadPlansFromDisk,
  // Stalled pipeline
  checkStalledPipeline,
  // Utilities
  parseSimpleYaml,
  sanitizeMetricLabelName,
  normalizeGatewayUrl,
  // Alert dedup (exported for testing)
  alertDedup,
  alertDedupGet,
  alertDedupSet,
  ALERT_DEDUP_TTL_MS,
  ALERT_DEDUP_MAX_SIZE,
};

// =============================================================================
// STALLED PIPELINE DETECTION
// =============================================================================

const MAX_REDISPATCH_ATTEMPTS = 5;
const stalledRedispatchCounts = new Map();

async function checkStalledPipeline() {
  if (!config.stalledPipelineEnabled) return;

  const now = Date.now();
  const threshold = config.stalledPipelineThresholdMs;

  // Statuses that should transition — if stuck here, something failed
  const transientStatuses = ["open", "triaged", "correlated", "investigated", "planned", "approved"];

  // The webhook paths for re-dispatch (same as statusWebhooks in updateCase)
  const redispatchWebhooks = {
    open: "/webhook/wazuh-alert",
    triaged: "/webhook/case-created",
    correlated: "/webhook/investigation-request",
    investigated: "/webhook/plan-request",
    planned: "/webhook/policy-check",
    approved: "/webhook/execute-action",
  };

  try {
    const cases = await listCases({ limit: 500 });
    let detected = 0;

    for (const caseSummary of cases) {
      if (!transientStatuses.includes(caseSummary.status)) continue;

      const updatedAt = new Date(caseSummary.updated_at).getTime();
      const age = now - updatedAt;

      if (age < threshold) continue;

      detected++;
      incrementMetric("stalled_pipeline_detected_total");

      const webhookPath = redispatchWebhooks[caseSummary.status];
      if (!webhookPath) continue;

      // Backoff: stop re-dispatching after MAX_REDISPATCH_ATTEMPTS
      const attempts = stalledRedispatchCounts.get(caseSummary.case_id) || 0;
      if (attempts >= MAX_REDISPATCH_ATTEMPTS) {
        log("warn", "stalled-pipeline", `Case exceeded max redispatch attempts (${MAX_REDISPATCH_ATTEMPTS}), skipping`, {
          case_id: caseSummary.case_id,
          status: caseSummary.status,
          attempts,
        });
        continue;
      }

      const ageMinutes = Math.round(age / 60000);
      log("warn", "stalled-pipeline", `Case stalled in ${caseSummary.status} for ${ageMinutes}m, re-dispatching (attempt ${attempts + 1}/${MAX_REDISPATCH_ATTEMPTS})`, {
        case_id: caseSummary.case_id,
        status: caseSummary.status,
        age_minutes: ageMinutes,
        severity: caseSummary.severity,
      });

      try {
        const evidencePack = await getCase(caseSummary.case_id);
        // NOTE: Callback URLs are in each agent's AGENTS.md (system prompt), not
        // in the webhook message. See comment in updateCase() for rationale.
        const msg = `[RETRY] Case ID: ${caseSummary.case_id}. Severity: ${evidencePack.severity || caseSummary.severity}. Status: ${caseSummary.status}. Stalled for ${ageMinutes}m. Follow your AGENTS.md instructions to process this case and advance the pipeline.`;

        dispatchToGateway(webhookPath, {
          message: msg,
          case_id: caseSummary.case_id,
          status: caseSummary.status,
          severity: evidencePack.severity || caseSummary.severity,
          trigger: "stalled_pipeline_redispatch",
        }).catch((err) => {
          log("warn", "dispatch", "Failed to dispatch stalled pipeline webhook", { case_id: caseSummary.case_id, status: caseSummary.status, error: err.message });
          incrementMetric("webhook_dispatch_failures_total");
        });

        incrementMetric("stalled_pipeline_redispatched_total");
        stalledRedispatchCounts.set(caseSummary.case_id, attempts + 1);

        // Touch updated_at so we don't re-dispatch every check interval
        // Use withCaseLock to prevent data corruption from concurrent updateCase calls
        await withCaseLock(caseSummary.case_id, async () => {
          const caseDir = path.join(config.dataDir, "cases", caseSummary.case_id);
          try {
            const currentPack = JSON.parse(await fs.readFile(path.join(caseDir, "evidence-pack.json"), "utf8"));
            currentPack.updated_at = new Date(now).toISOString();
            await atomicWriteFile(path.join(caseDir, "evidence-pack.json"), JSON.stringify(currentPack, null, 2));
          } catch { /* ok — case may have been updated/deleted concurrently */ }
          try {
            const summaryPath = path.join(caseDir, "case.json");
            const summary = JSON.parse(await fs.readFile(summaryPath, "utf8"));
            summary.updated_at = new Date(now).toISOString();
            await atomicWriteFile(summaryPath, JSON.stringify(summary, null, 2));
          } catch { /* ok — summary may not exist */ }
        });

      } catch (err) {
        log("warn", "stalled-pipeline", "Failed to re-dispatch stalled case", {
          case_id: caseSummary.case_id,
          error: err.message,
        });
      }
    }

    // Audit fix H11: Evict stale entries from stalledRedispatchCounts to prevent unbounded growth
    if (stalledRedispatchCounts.size > 1000) {
      const caseIds = new Set(cases.map(c => c.case_id));
      for (const [id] of stalledRedispatchCounts) {
        if (!caseIds.has(id)) stalledRedispatchCounts.delete(id);
      }
    }

    if (detected > 0) {
      log("info", "stalled-pipeline", `Stalled pipeline check: ${detected} case(s) detected`, { detected });
    }
  } catch (err) {
    log("error", "stalled-pipeline", "Stalled pipeline check failed", { error: err.message });
  }
}

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

  // Periodic response plan eviction: remove terminal plans older than 24 hours
  const planEvictionCleanup = setInterval(() => {
    const cutoff = Date.now() - 24 * 60 * 60 * 1000;
    let evicted = 0;
    for (const [planId, plan] of responsePlans.entries()) {
      if (
        ["completed", "failed", "rejected", "expired"].includes(plan.state) &&
        new Date(plan.updated_at).getTime() < cutoff
      ) {
        responsePlans.delete(planId);
        evicted++;
      }
    }
    if (evicted > 0) {
      log("info", "cleanup", "Periodic plan eviction: removed terminal plans older than 24h", { evicted, remaining: responsePlans.size });
    }
  }, 30 * 60 * 1000); // every 30 minutes
  cleanupIntervals.push(planEvictionCleanup);

  // Entity case index cleanup (evict entries outside group window)
  const entityCleanup = setInterval(() => {
    const cutoff = Date.now() - config.alertGroupWindowMs;
    let removed = 0;
    for (const [key, entries] of entityCaseIndex) {
      const filtered = entries.filter((e) => e.createdAt >= cutoff);
      if (filtered.length === 0) {
        entityCaseIndex.delete(key);
        removed++;
      } else if (filtered.length < entries.length) {
        entityCaseIndex.set(key, filtered);
        removed += entries.length - filtered.length;
      }
    }
    if (removed > 0) {
      log("debug", "cleanup", "Expired entity index entries removed", { count: removed });
    }
  }, 300000); // every 5 minutes
  cleanupIntervals.push(entityCleanup);

  // Enrichment cache cleanup
  const enrichmentCleanup = setInterval(() => {
    const now = Date.now();
    let removed = 0;
    for (const [ip, entry] of enrichmentCache) {
      if (now >= entry.expiresAt) {
        enrichmentCache.delete(ip);
        removed++;
      }
    }
    if (removed > 0) {
      log("debug", "cleanup", "Expired enrichment cache entries removed", { count: removed });
    }
  }, 300000);
  cleanupIntervals.push(enrichmentCleanup);

  // Action rate limit state cleanup (evict entries with both windows expired)
  const actionRateLimitCleanup = setInterval(() => {
    const now = Date.now();
    let removed = 0;
    for (const [actionType, counters] of actionRateLimitState.perAction) {
      if (now > counters.hourly.resetTime && now > counters.daily.resetTime) {
        actionRateLimitState.perAction.delete(actionType);
        removed++;
      }
    }
    if (removed > 0) {
      log("debug", "cleanup", "Expired action rate limit entries removed", { count: removed });
    }
  }, 300000);
  cleanupIntervals.push(actionRateLimitCleanup);

  // Deduplication state cleanup (evict entries older than window)
  const dedupCleanup = setInterval(() => {
    const windowMs = policyConfig?.idempotency?.duplicate_detection?.window_minutes
      ? parseInt(policyConfig.idempotency.duplicate_detection.window_minutes, 10) * 60 * 1000
      : 60 * 60 * 1000; // default 60 minutes
    const cutoff = Date.now() - windowMs;
    let removed = 0;
    for (const [key, ts] of actionDeduplicationState) {
      if (ts < cutoff) {
        actionDeduplicationState.delete(key);
        removed++;
      }
    }
    if (removed > 0) {
      log("debug", "cleanup", "Expired dedup entries removed", { count: removed });
    }
  }, 300000);
  cleanupIntervals.push(dedupCleanup);

  // Webhook DLQ retry
  const dlqRetry = setInterval(() => retryDlqDispatches().catch(() => {}), 5 * 60 * 1000);
  cleanupIntervals.push(dlqRetry);

  // Stalled pipeline detection
  if (config.stalledPipelineEnabled) {
    const stalledCheck = setInterval(() => {
      checkStalledPipeline().catch((err) => {
        log("error", "stalled-pipeline", "Unhandled error in stalled pipeline check", { error: err.message });
      });
    }, config.stalledPipelineCheckIntervalMs);
    cleanupIntervals.push(stalledCheck);
    log("info", "startup", "Stalled pipeline detector enabled", {
      threshold_minutes: config.stalledPipelineThresholdMs / 60000,
      check_interval_ms: config.stalledPipelineCheckIntervalMs,
    });
  }
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

  // Wait for in-flight plan executions to complete (up to 10s)
  if (executingPlans.size > 0) {
    log("info", "shutdown", `Waiting for ${executingPlans.size} in-flight plan execution(s) to complete...`);
    const execWaitStart = Date.now();
    while (executingPlans.size > 0 && Date.now() - execWaitStart < 10000) {
      await new Promise((resolve) => setTimeout(resolve, 500));
    }
    if (executingPlans.size > 0) {
      log("warn", "shutdown", `${executingPlans.size} plan execution(s) still in-flight at shutdown`);
    }
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
  isShuttingDown = true; // Reject new requests during drain window
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
