/**
 * Tests for:
 *  - M2: Date-boundary alert dedup (alertDedup map prevents split case IDs across midnight)
 *  - M7: X-Forwarded-For spoofing prevention (TRUSTED_PROXY env var)
 *
 * Uses Node.js built-in test runner -- no external dependencies.
 */

const path = require("path");
const os = require("os");
const fs = require("fs");
const http = require("http");

// Set env vars BEFORE requiring index.js
process.env.AUTOPILOT_MODE = "bootstrap";
process.env.AUTOPILOT_DATA_DIR = path.join(os.tmpdir(), `dedup-proxy-test-${Date.now()}-${process.pid}`);
process.env.AUTOPILOT_MCP_AUTH = "test-token-dedup";
process.env.RATE_LIMIT_MAX_REQUESTS = "200";
process.env.RATE_LIMIT_WINDOW_MS = "60000";
process.env.LOG_LEVEL = "error"; // keep test output clean
// Do NOT set TRUSTED_PROXY — tests verify default (untrusted) behavior

const { describe, it, before, after, beforeEach } = require("node:test");
const assert = require("node:assert/strict");

const {
  alertDedup,
  alertDedupGet,
  alertDedupSet,
  ALERT_DEDUP_TTL_MS,
  ALERT_DEDUP_MAX_SIZE,
  createServer,
} = require("./index.js");

const dataDir = process.env.AUTOPILOT_DATA_DIR;

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function request(server, method, urlPath, body = null, headers = {}) {
  return new Promise((resolve, reject) => {
    const addr = server.address();
    const opts = {
      hostname: "127.0.0.1",
      port: addr.port,
      path: urlPath,
      method,
      headers: { ...headers },
    };
    if (body) {
      const data = JSON.stringify(body);
      opts.headers["Content-Type"] = "application/json";
      opts.headers["Content-Length"] = Buffer.byteLength(data);
    }
    const req = http.request(opts, (res) => {
      const chunks = [];
      res.on("data", (c) => chunks.push(c));
      res.on("end", () => {
        const raw = Buffer.concat(chunks).toString();
        let parsed;
        try { parsed = JSON.parse(raw); } catch { parsed = raw; }
        resolve({ status: res.statusCode, headers: res.headers, body: parsed, raw });
      });
    });
    req.on("error", reject);
    if (body) req.write(JSON.stringify(body));
    req.end();
  });
}

// ---------------------------------------------------------------------------
// M2: Alert dedup across midnight
// ---------------------------------------------------------------------------

describe("M2: Alert dedup across date boundary", () => {
  beforeEach(() => {
    alertDedup.clear();
  });

  it("alertDedupSet and alertDedupGet round-trip", () => {
    alertDedupSet("alert-100", "CASE-20260326-abc123def456");
    const result = alertDedupGet("alert-100");
    assert.equal(result, "CASE-20260326-abc123def456");
  });

  it("alertDedupGet returns null for unknown alertId", () => {
    const result = alertDedupGet("nonexistent");
    assert.equal(result, null);
  });

  it("alertDedupGet returns null for expired entries", () => {
    // Manually insert an expired entry
    alertDedup.set("alert-expired", { caseId: "CASE-OLD", ts: Date.now() - ALERT_DEDUP_TTL_MS - 1000 });
    const result = alertDedupGet("alert-expired");
    assert.equal(result, null);
    // Entry should have been cleaned up
    assert.equal(alertDedup.has("alert-expired"), false);
  });

  it("alertDedupSet caps at ALERT_DEDUP_MAX_SIZE", () => {
    // Fill to max
    for (let i = 0; i < ALERT_DEDUP_MAX_SIZE; i++) {
      alertDedup.set(`fill-${i}`, { caseId: `CASE-${i}`, ts: Date.now() });
    }
    assert.equal(alertDedup.size, ALERT_DEDUP_MAX_SIZE);

    // Adding one more should evict the oldest
    alertDedupSet("new-alert", "CASE-NEW");
    assert.equal(alertDedup.size, ALERT_DEDUP_MAX_SIZE);
    // The first entry should have been evicted
    assert.equal(alertDedup.has("fill-0"), false);
    // The new entry should exist
    assert.equal(alertDedupGet("new-alert"), "CASE-NEW");
  });

  it("alertDedupSet does not evict when updating existing key", () => {
    for (let i = 0; i < 10; i++) {
      alertDedup.set(`key-${i}`, { caseId: `CASE-${i}`, ts: Date.now() });
    }
    // Update existing key — should NOT evict anything
    alertDedupSet("key-5", "CASE-UPDATED");
    assert.equal(alertDedup.size, 10);
    assert.equal(alertDedupGet("key-5"), "CASE-UPDATED");
  });

  it("same alert_id ingested twice gets the same caseId (simulating midnight boundary)", () => {
    // Simulate: first alert creates a case ID with today's date
    const alertId = "wazuh-alert-99999";
    alertDedupSet(alertId, "CASE-20260325-aabbccddeeff");

    // Second ingestion (after midnight) should return the SAME case ID from dedup,
    // NOT generate a new one with a different date prefix
    const cached = alertDedupGet(alertId);
    assert.equal(cached, "CASE-20260325-aabbccddeeff");
  });
});

describe("M2: Alert ingestion dedup via HTTP", () => {
  let server;

  before((_, done) => {
    fs.mkdirSync(dataDir, { recursive: true });
    fs.mkdirSync(path.join(dataDir, "cases"), { recursive: true });
    server = createServer();
    server.listen(0, "127.0.0.1", done);
  });

  after((_, done) => {
    alertDedup.clear();
    server.close(() => {
      fs.rmSync(dataDir, { recursive: true, force: true });
      done();
    });
  });

  it("two alerts with same alert_id produce the same caseId", async () => {
    const alert = {
      alert_id: "dedup-test-alert-001",
      rule: { level: 10, description: "Test brute force" },
      data: { srcip: "10.0.0.1" },
    };

    // First ingestion — creates a new case (201 Created)
    const res1 = await request(server, "POST", "/api/alerts", alert, {
      Authorization: "Bearer test-token-dedup",
    });
    assert.ok(res1.status >= 200 && res1.status < 300, `First alert failed: status=${res1.status}`);
    const caseId1 = res1.body.case_id;
    assert.ok(caseId1, "First response should have case_id");

    // Second ingestion (same alert_id — simulates retry after midnight)
    const res2 = await request(server, "POST", "/api/alerts", alert, {
      Authorization: "Bearer test-token-dedup",
    });
    assert.ok(res2.status >= 200 && res2.status < 300, `Second alert failed: status=${res2.status}`);
    const caseId2 = res2.body.case_id;
    assert.ok(caseId2, "Second response should have case_id");

    // Both should have the exact same case ID
    assert.equal(caseId1, caseId2, "Same alert_id should produce same caseId across retries");
  });
});

// ---------------------------------------------------------------------------
// M7: X-Forwarded-For spoofing prevention
// ---------------------------------------------------------------------------

describe("M7: Rate limiting uses socket IP when TRUSTED_PROXY is not set", () => {
  let server;

  before((_, done) => {
    fs.mkdirSync(dataDir, { recursive: true });
    fs.mkdirSync(path.join(dataDir, "cases"), { recursive: true });
    server = createServer();
    server.listen(0, "127.0.0.1", done);
  });

  after((_, done) => {
    server.close(() => {
      fs.rmSync(dataDir, { recursive: true, force: true });
      done();
    });
  });

  it("spoofed X-Forwarded-For IPs share rate limit bucket (socket IP used)", async () => {
    // Use /api/cases (rate-limited endpoint, unlike /health which is exempt)
    // Make several requests with different X-Forwarded-For values.
    // They should all hit the same rate limit bucket (127.0.0.1 socket IP)
    // because TRUSTED_PROXY is not set.
    const results = [];
    for (let i = 0; i < 3; i++) {
      const res = await request(server, "GET", "/api/cases", null, {
        "X-Forwarded-For": `10.${i}.0.1`,
        Authorization: "Bearer test-token-dedup",
      });
      results.push(res);
    }

    // All requests should succeed (under rate limit)
    for (const res of results) {
      assert.equal(res.status, 200, `Expected 200 but got ${res.status}`);
    }

    // Check that X-RateLimit-Remaining decreases (proves same bucket)
    const remaining = results.map(r => parseInt(r.headers["x-ratelimit-remaining"], 10));
    for (let i = 1; i < remaining.length; i++) {
      assert.ok(remaining[i] < remaining[i - 1],
        `Rate limit remaining should decrease: got ${remaining[i]}, previous was ${remaining[i - 1]}. ` +
        "If they were independent, each IP would have its own bucket.");
    }
  });
});
