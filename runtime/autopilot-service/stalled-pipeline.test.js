/**
 * Tests for stalled pipeline detection, plan disk persistence, and toolmap validation.
 * Covers audit findings H2, H4, H5.
 *
 * Run:  node --test stalled-pipeline.test.js
 */

const { describe, it, before, after } = require("node:test");
const assert = require("node:assert/strict");
const http = require("http");
const os = require("os");
const path = require("path");
const fs = require("fs");

const TEST_DATA_DIR = path.join(
  os.tmpdir(),
  `autopilot-stalled-test-${Date.now()}-${process.pid}`,
);

process.env.AUTOPILOT_MODE = "bootstrap";
process.env.AUTOPILOT_DATA_DIR = TEST_DATA_DIR;
process.env.AUTOPILOT_MCP_AUTH = "test-mcp-secret-token";
process.env.AUTOPILOT_RESPONDER_ENABLED = "true";
process.env.RATE_LIMIT_MAX_REQUESTS = "500";
process.env.LOG_LEVEL = "error";
process.env.STALLED_PIPELINE_ENABLED = "true";
process.env.STALLED_PIPELINE_THRESHOLD_MINUTES = "1"; // 1 minute for testing

const { createServer, loadPlansFromDisk, checkStalledPipeline, sanitizeAlertPayload, ALLOWED_ACTION_TYPES, checkRateLimit } = require("./index");

function request(server, method, urlPath, body = null) {
  return new Promise((resolve, reject) => {
    const addr = server.address();
    const opts = {
      hostname: "127.0.0.1",
      port: addr.port,
      path: urlPath,
      method,
      headers: {},
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
        resolve({ status: res.statusCode, body: parsed });
      });
    });
    req.on("error", reject);
    if (body) req.write(JSON.stringify(body));
    req.end();
  });
}

function ensureTestDirs() {
  fs.mkdirSync(path.join(TEST_DATA_DIR, "cases"), { recursive: true });
  fs.mkdirSync(path.join(TEST_DATA_DIR, "plans"), { recursive: true });
  fs.mkdirSync(path.join(TEST_DATA_DIR, "reports"), { recursive: true });
  fs.mkdirSync(path.join(TEST_DATA_DIR, "state"), { recursive: true });
}

function rmTestDir() {
  try { fs.rmSync(TEST_DATA_DIR, { recursive: true, force: true }); } catch {}
}

// ===================================================================
// H5: loadPlansFromDisk — corrupted file handling
// ===================================================================

describe("loadPlansFromDisk (H5 audit fix)", () => {
  before(() => ensureTestDirs());
  after(() => rmTestDir());

  it("loads valid plan files", async () => {
    const planId = `PLAN-${Date.now()}-loadtest1`;
    const plan = {
      plan_id: planId,
      state: "proposed",
      case_id: "CASE-test-001",
      title: "Test Plan",
      actions: [{ type: "block_ip", target: "1.2.3.4" }],
      created_at: new Date().toISOString(),
      updated_at: new Date().toISOString(),
    };
    fs.writeFileSync(
      path.join(TEST_DATA_DIR, "plans", `${planId}.json`),
      JSON.stringify(plan),
    );
    // loadPlansFromDisk loads into in-memory map; just verify it doesn't throw
    await loadPlansFromDisk();
  });

  it("skips corrupted JSON files without crashing", async () => {
    // Write a corrupt file
    fs.writeFileSync(
      path.join(TEST_DATA_DIR, "plans", "PLAN-corrupt.json"),
      "{ this is not valid JSON!!!",
    );
    // Should not throw
    await loadPlansFromDisk();
  });

  it("skips plan files without plan_id", async () => {
    fs.writeFileSync(
      path.join(TEST_DATA_DIR, "plans", "PLAN-noid.json"),
      JSON.stringify({ state: "proposed", title: "No ID" }),
    );
    await loadPlansFromDisk();
  });

  it("handles empty plans directory gracefully", async () => {
    // Remove all plan files, leave dir empty
    const plansDir = path.join(TEST_DATA_DIR, "plans");
    const entries = fs.readdirSync(plansDir);
    for (const entry of entries) {
      fs.unlinkSync(path.join(plansDir, entry));
    }
    // Should not throw on empty dir
    await loadPlansFromDisk();
  });

  it("ignores non-JSON files in plans directory", async () => {
    fs.writeFileSync(
      path.join(TEST_DATA_DIR, "plans", "README.txt"),
      "This is not a plan file",
    );
    fs.writeFileSync(
      path.join(TEST_DATA_DIR, "plans", ".gitkeep"),
      "",
    );
    // Should not throw and should ignore non-.json files
    await loadPlansFromDisk();
  });
});

// ===================================================================
// CRIT-1: sanitizeAlertPayload — verify function works
// ===================================================================

describe("sanitizeAlertPayload (CRIT-1 audit fix)", () => {
  it("strips control characters from strings", () => {
    const result = sanitizeAlertPayload("hello\x00world\x07test");
    assert.equal(result, "helloworldtest");
  });

  it("preserves newlines and tabs", () => {
    const result = sanitizeAlertPayload("line1\nline2\ttab");
    assert.equal(result, "line1\nline2\ttab");
  });

  it("caps string length at 100000", () => {
    const longStr = "a".repeat(200000);
    const result = sanitizeAlertPayload(longStr);
    assert.equal(result.length, 100000);
  });

  it("limits arrays to 1000 items", () => {
    const arr = Array.from({ length: 2000 }, (_, i) => i);
    const result = sanitizeAlertPayload(arr);
    assert.equal(result.length, 1000);
  });

  it("limits object keys to 500", () => {
    const obj = {};
    for (let i = 0; i < 600; i++) obj[`key${i}`] = "val";
    const result = sanitizeAlertPayload(obj);
    assert.equal(Object.keys(result).length, 500);
  });

  it("sanitizes nested objects recursively", () => {
    const obj = {
      rule: { description: "SSH \x00brute force\x07" },
      data: { srcip: "1.2.3.4" },
    };
    const result = sanitizeAlertPayload(obj);
    assert.equal(result.rule.description, "SSH brute force");
    assert.equal(result.data.srcip, "1.2.3.4");
  });

  it("passes through numbers and booleans unchanged", () => {
    assert.equal(sanitizeAlertPayload(42), 42);
    assert.equal(sanitizeAlertPayload(true), true);
    assert.equal(sanitizeAlertPayload(null), null);
  });

  it("sanitizes object keys with control characters", () => {
    const obj = { "bad\x00key": "value" };
    const result = sanitizeAlertPayload(obj);
    assert.ok("badkey" in result);
  });

  it("handles undefined input", () => {
    const result = sanitizeAlertPayload(undefined);
    assert.equal(result, undefined);
  });

  it("handles deeply nested structures", () => {
    const obj = { a: { b: { c: { d: "deep\x00value" } } } };
    const result = sanitizeAlertPayload(obj);
    assert.equal(result.a.b.c.d, "deepvalue");
  });

  it("preserves empty strings", () => {
    assert.equal(sanitizeAlertPayload(""), "");
  });

  it("preserves empty arrays", () => {
    const result = sanitizeAlertPayload([]);
    assert.deepEqual(result, []);
  });

  it("preserves empty objects", () => {
    const result = sanitizeAlertPayload({});
    assert.deepEqual(result, {});
  });
});

// ===================================================================
// ALLOWED_ACTION_TYPES export verification
// ===================================================================

describe("ALLOWED_ACTION_TYPES export", () => {
  it("is a Set with expected action types", () => {
    assert.ok(ALLOWED_ACTION_TYPES instanceof Set);
    assert.ok(ALLOWED_ACTION_TYPES.has("block_ip"));
    assert.ok(ALLOWED_ACTION_TYPES.has("isolate_host"));
    assert.ok(ALLOWED_ACTION_TYPES.has("kill_process"));
    assert.ok(ALLOWED_ACTION_TYPES.has("disable_user"));
    assert.ok(ALLOWED_ACTION_TYPES.has("quarantine_file"));
    assert.ok(ALLOWED_ACTION_TYPES.has("firewall_drop"));
    assert.ok(ALLOWED_ACTION_TYPES.has("host_deny"));
    assert.ok(ALLOWED_ACTION_TYPES.has("restart_wazuh"));
  });

  it("does not contain dangerous action types", () => {
    assert.ok(!ALLOWED_ACTION_TYPES.has("exec"));
    assert.ok(!ALLOWED_ACTION_TYPES.has("rm"));
    assert.ok(!ALLOWED_ACTION_TYPES.has("format_disk"));
    assert.ok(!ALLOWED_ACTION_TYPES.has(""));
  });
});

// ===================================================================
// Stalled pipeline detection (H2 audit fix)
// NOTE: Must come BEFORE rate limit tests which exhaust loopback IPs
// ===================================================================

describe("checkStalledPipeline (H2 audit fix)", () => {
  let server;

  before(() => {
    ensureTestDirs();
    server = createServer();
    return new Promise((resolve) => server.listen(0, "127.0.0.1", resolve));
  });

  after(() => {
    return new Promise((resolve) => server.close(() => { rmTestDir(); resolve(); }));
  });

  it("runs without error when no cases exist", async () => {
    await checkStalledPipeline();
  });

  it("runs without error when cases exist but are not stalled", async () => {
    const res = await request(server, "POST", "/api/alerts", {
      alert_id: `stalled-test-${Date.now()}`,
      rule: { id: "5712", level: 10, description: "Test stalled detection" },
      agent: { id: "001", name: "test-host", ip: "10.0.0.1" },
      data: { srcip: "1.2.3.4" },
    });
    assert.equal(res.status, 201);

    // Case was just created so it's not stalled yet (threshold is 1 minute)
    await checkStalledPipeline();
  });

  it("is callable as an async function", () => {
    assert.equal(typeof checkStalledPipeline, "function");
    const result = checkStalledPipeline();
    assert.ok(result instanceof Promise);
  });
});

// ===================================================================
// Alert ingestion uses sanitized data (CRIT-1 integration check)
// NOTE: Must come BEFORE rate limit tests which exhaust loopback IPs
// ===================================================================

describe("Alert ingestion sanitization (CRIT-1 integration)", () => {
  let server;

  before(() => {
    ensureTestDirs();
    server = createServer();
    return new Promise((resolve) => server.listen(0, "127.0.0.1", resolve));
  });

  after(() => {
    return new Promise((resolve) => server.close(() => { rmTestDir(); resolve(); }));
  });

  it("sanitizes control characters in alert rule description", async () => {
    const res = await request(server, "POST", "/api/alerts", {
      alert_id: `sanitize-${Date.now()}`,
      rule: { id: "5712", level: 12, description: "SSH\x00brute\x07force\x1battack" },
      agent: { id: "001", name: "test-host", ip: "10.0.0.1" },
      data: { srcip: "1.2.3.4" },
    });
    assert.equal(res.status, 201);
    const caseId = res.body.case_id;
    const caseRes = await request(server, "GET", `/api/cases/${caseId}`);
    assert.ok(!caseRes.body.title.includes("\x00"));
    assert.ok(!caseRes.body.title.includes("\x07"));
    assert.ok(caseRes.body.title.includes("brute"));
  });

  it("sanitizes alert data fields used in entity extraction", async () => {
    const uniqueIp = `192.168.${Math.floor(Math.random() * 254) + 1}.${Math.floor(Math.random() * 254) + 1}`;
    const res = await request(server, "POST", "/api/alerts", {
      alert_id: `entity-sanitize-${Date.now()}`,
      rule: { id: "5710", level: 8, description: "Sanitize entity test" },
      agent: { id: "099", name: "unique-host-entity", ip: "10.99.99.99" },
      data: { srcip: uniqueIp, dstuser: "admin\x00injected" },
    });
    // Accept 200 (grouped with existing case) or 201 (new case)
    assert.ok(res.status === 200 || res.status === 201, `Expected 200 or 201, got ${res.status}`);
  });
});

// ===================================================================
// Rate limit returns 429 (M2 audit fix) — unit test via checkRateLimit
// NOTE: This MUST be the last describe block because it exhausts the
// rate limit for loopback IPs, which affects all subsequent HTTP tests.
// ===================================================================

describe("Rate limit returns 429 (M2 audit fix)", () => {
  it("checkRateLimit returns allowed:false after max requests", () => {
    // Use a unique IP so we don't collide with other tests
    const testIp = `10.99.99.${Math.floor(Math.random() * 254) + 1}`;

    // config.rateLimitMaxRequests is 500 (set from env before module load)
    for (let i = 0; i < 500; i++) {
      const result = checkRateLimit(testIp);
      assert.equal(result.allowed, true, `request ${i + 1} should be allowed`);
    }

    // Next request should be denied
    const denied = checkRateLimit(testIp);
    assert.equal(denied.allowed, false);
    assert.equal(denied.remaining, 0);
    assert.ok(denied.retryAfter > 0);
  });

  it("returns 429 via HTTP when rate limit exceeded", async () => {
    // Exhaust the rate limit for all possible loopback representations
    for (const ip of ["127.0.0.1", "::ffff:127.0.0.1", "::1"]) {
      for (let i = 0; i < 500; i++) {
        checkRateLimit(ip);
      }
    }

    ensureTestDirs();
    const srv = createServer();
    await new Promise((resolve) => srv.listen(0, "127.0.0.1", resolve));

    try {
      const res = await request(srv, "GET", "/api/cases");
      assert.equal(res.status, 429);
    } finally {
      await new Promise((resolve) => srv.close(resolve));
    }
  });
});
