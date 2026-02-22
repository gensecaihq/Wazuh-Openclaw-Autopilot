/**
 * Integration tests for the Wazuh OpenClaw Autopilot Runtime Service.
 *
 * These tests exercise the HTTP endpoints end-to-end using Node's built-in
 * test runner and the http module.  No external test dependencies are needed.
 *
 * Run:  node --test integration.test.js
 */

const { describe, it, before, after } = require("node:test");
const assert = require("node:assert/strict");
const http = require("http");
const os = require("os");
const path = require("path");
const fs = require("fs");

// ---------------------------------------------------------------------------
// Environment – must be set BEFORE requiring index.js because the module
// reads process.env at parse time to build its config object.
// ---------------------------------------------------------------------------

const TEST_DATA_DIR = path.join(
  os.tmpdir(),
  `autopilot-integration-test-${Date.now()}-${process.pid}`,
);

process.env.AUTOPILOT_MODE = "bootstrap";
process.env.AUTOPILOT_DATA_DIR = TEST_DATA_DIR;
process.env.AUTOPILOT_MCP_AUTH = "test-mcp-secret-token";
process.env.AUTOPILOT_SERVICE_TOKEN = "test-service-token";
process.env.AUTOPILOT_RESPONDER_ENABLED = "false";
process.env.RATE_LIMIT_MAX_REQUESTS = "200";
process.env.RATE_LIMIT_WINDOW_MS = "60000";
process.env.LOG_LEVEL = "error"; // keep test output clean

const { createServer } = require("./index");

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/**
 * Fire an HTTP request against the given server instance and return a
 * promise that resolves to { status, headers, body, raw }.
 */
function request(server, method, path, body = null, headers = {}) {
  return new Promise((resolve, reject) => {
    const addr = server.address();
    const opts = {
      hostname: "127.0.0.1",
      port: addr.port,
      path,
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
        try {
          parsed = JSON.parse(raw);
        } catch {
          parsed = raw;
        }
        resolve({ status: res.statusCode, headers: res.headers, body: parsed, raw });
      });
    });
    req.on("error", reject);
    if (body) req.write(JSON.stringify(body));
    req.end();
  });
}

/**
 * Helper to create the cases directory tree that the server expects.
 */
function ensureTestDirs() {
  fs.mkdirSync(path.join(TEST_DATA_DIR, "cases"), { recursive: true });
  fs.mkdirSync(path.join(TEST_DATA_DIR, "reports"), { recursive: true });
  fs.mkdirSync(path.join(TEST_DATA_DIR, "state"), { recursive: true });
}

/**
 * Remove a directory recursively.
 */
function rmTestDir() {
  try {
    fs.rmSync(TEST_DATA_DIR, { recursive: true, force: true });
  } catch {
    // best-effort cleanup
  }
}

// ===================================================================
// 1. Health / Metrics / Ready / Version endpoints
// ===================================================================

describe("Health, Metrics, Ready, Version endpoints", () => {
  let server;

  before(() => {
    ensureTestDirs();
    server = createServer();
    return new Promise((resolve) => server.listen(0, "127.0.0.1", resolve));
  });

  after(() => new Promise((resolve) => server.close(resolve)));

  it("GET /health returns 200 with expected fields", async () => {
    const res = await request(server, "GET", "/health");
    assert.equal(res.status, 200);
    assert.equal(res.body.status, "healthy");
    assert.ok(res.body.version);
    assert.equal(res.body.mode, "bootstrap");
    assert.equal(typeof res.body.uptime_seconds, "number");
    assert.ok(res.body.checks);
    assert.equal(res.body.checks.data_dir, true);
    assert.ok(res.body.responder);
    assert.equal(res.body.responder.enabled, false);
  });

  it("GET /ready returns 200 with ready=true when data dir exists", async () => {
    const res = await request(server, "GET", "/ready");
    assert.equal(res.status, 200);
    assert.equal(res.body.ready, true);
    assert.equal(res.body.checks.data_dir, true);
  });

  it("GET /metrics returns 200 with text/plain Prometheus format", async () => {
    const res = await request(server, "GET", "/metrics");
    assert.equal(res.status, 200);
    assert.ok(res.headers["content-type"].includes("text/plain"));
    assert.ok(res.raw.includes("autopilot_cases_created_total"));
    assert.ok(res.raw.includes("autopilot_plans_created_total"));
  });

  it("GET /version returns service name, version, and node version", async () => {
    const res = await request(server, "GET", "/version");
    assert.equal(res.status, 200);
    assert.equal(res.body.service, "wazuh-openclaw-autopilot");
    assert.ok(res.body.version);
    assert.ok(res.body.node);
  });

  it("GET /health includes a timestamp field", async () => {
    const res = await request(server, "GET", "/health");
    assert.equal(res.status, 200);
    assert.ok(res.body.timestamp);
    // Verify it parses as a valid ISO date
    const d = new Date(res.body.timestamp);
    assert.equal(isNaN(d.getTime()), false);
  });
});

// ===================================================================
// 2. CORS preflight
// ===================================================================

describe("CORS preflight", () => {
  let server;

  before(() => {
    ensureTestDirs();
    server = createServer();
    return new Promise((resolve) => server.listen(0, "127.0.0.1", resolve));
  });

  after(() => new Promise((resolve) => server.close(resolve)));

  it("OPTIONS request returns 204 with CORS headers", async () => {
    const res = await request(server, "OPTIONS", "/api/cases");
    assert.equal(res.status, 204);
    assert.ok(res.headers["access-control-allow-origin"]);
    assert.ok(res.headers["access-control-allow-methods"]);
    assert.ok(res.headers["access-control-allow-headers"]);
  });
});

// ===================================================================
// 3. Cases CRUD via HTTP
// ===================================================================

describe("Cases CRUD", () => {
  let server;

  before(() => {
    ensureTestDirs();
    server = createServer();
    return new Promise((resolve) => server.listen(0, "127.0.0.1", resolve));
  });

  after(() => new Promise((resolve) => server.close(resolve)));

  it("POST /api/cases creates a case and returns 201", async () => {
    const res = await request(server, "POST", "/api/cases", {
      case_id: "CASE-int-001",
      title: "Integration Test Case",
      severity: "high",
      summary: "Created via integration test",
    });
    assert.equal(res.status, 201);
    assert.equal(res.body.case_id, "CASE-int-001");
    assert.equal(res.body.title, "Integration Test Case");
    assert.equal(res.body.severity, "high");
  });

  it("GET /api/cases lists cases including the one just created", async () => {
    const res = await request(server, "GET", "/api/cases");
    assert.equal(res.status, 200);
    assert.ok(Array.isArray(res.body));
    const found = res.body.find((c) => c.case_id === "CASE-int-001");
    assert.ok(found, "Expected CASE-int-001 in list");
  });

  it("GET /api/cases/:id returns the specific case", async () => {
    const res = await request(server, "GET", "/api/cases/CASE-int-001");
    assert.equal(res.status, 200);
    assert.equal(res.body.case_id, "CASE-int-001");
    assert.equal(res.body.schema_version, "1.0");
  });

  it("PUT /api/cases/:id updates the case", async () => {
    const res = await request(server, "PUT", "/api/cases/CASE-int-001", {
      severity: "critical",
      title: "Updated Integration Case",
    });
    assert.equal(res.status, 200);
    assert.equal(res.body.severity, "critical");
    assert.equal(res.body.title, "Updated Integration Case");
  });

  it("GET /api/cases/:id after update reflects changes", async () => {
    const res = await request(server, "GET", "/api/cases/CASE-int-001");
    assert.equal(res.status, 200);
    assert.equal(res.body.severity, "critical");
    assert.equal(res.body.title, "Updated Integration Case");
  });

  it("GET /api/cases/:id for non-existent case returns 404", async () => {
    const res = await request(server, "GET", "/api/cases/DOES-NOT-EXIST");
    assert.equal(res.status, 404);
    assert.ok(res.body.error);
  });

  it("POST /api/cases with missing case_id returns 400", async () => {
    const res = await request(server, "POST", "/api/cases", {
      title: "No Case ID",
    });
    assert.equal(res.status, 400);
    assert.ok(res.body.error.includes("case_id"));
  });
});

// ===================================================================
// 4. Alert ingestion
// ===================================================================

describe("Alert ingestion", () => {
  let server;

  before(() => {
    ensureTestDirs();
    server = createServer();
    return new Promise((resolve) => server.listen(0, "127.0.0.1", resolve));
  });

  after(() => new Promise((resolve) => server.close(resolve)));

  it("POST /api/alerts with valid alert returns 201 and creates a case", async () => {
    const res = await request(server, "POST", "/api/alerts", {
      alert_id: "alert-1001",
      rule: {
        id: "5502",
        description: "Login failure",
        level: 8,
      },
      agent: {
        id: "003",
        name: "web-server-01",
        ip: "10.0.0.3",
      },
      data: {
        srcip: "192.168.1.100",
      },
    });
    assert.equal(res.status, 201);
    assert.ok(res.body.case_id);
    assert.equal(res.body.status, "created");
    assert.equal(res.body.severity, "medium"); // level 8 => medium
    assert.ok(res.body.entities_extracted >= 1);
  });

  it("POST /api/alerts with high-level rule sets correct severity", async () => {
    const res = await request(server, "POST", "/api/alerts", {
      alert_id: "alert-1002",
      rule: {
        id: "5710",
        description: "Multiple authentication failures",
        level: 14,
      },
      agent: {
        id: "005",
        name: "db-server-01",
      },
    });
    assert.equal(res.status, 201);
    assert.equal(res.body.severity, "critical"); // level 14 => critical
  });

  it("POST /api/alerts without alert_id returns 400", async () => {
    const res = await request(server, "POST", "/api/alerts", {
      rule: { description: "test", level: 5 },
    });
    assert.equal(res.status, 400);
    assert.ok(res.body.error);
  });

  it("POST /api/alerts extracts MITRE ATT&CK mappings", async () => {
    const res = await request(server, "POST", "/api/alerts", {
      alert_id: "alert-mitre-001",
      rule: {
        id: "92001",
        description: "Credential Dumping detected",
        level: 15,
        mitre: {
          id: ["T1003"],
          tactic: ["Credential Access"],
          technique: ["OS Credential Dumping"],
        },
      },
      agent: {
        id: "010",
        name: "dc-01",
      },
    });
    assert.equal(res.status, 201);
    assert.equal(res.body.mitre_mappings, 1);
  });
});

// ===================================================================
// 5. Plans lifecycle via HTTP
// ===================================================================

describe("Plans lifecycle", () => {
  let server;
  let planId;
  const testCaseId = "CASE-plan-test-01";

  before(async () => {
    ensureTestDirs();
    server = createServer();
    await new Promise((resolve) => server.listen(0, "127.0.0.1", resolve));

    // Create a case so plans can reference it
    await request(server, "POST", "/api/cases", {
      case_id: testCaseId,
      title: "Plan Test Case",
      severity: "high",
    });
  });

  after(() => new Promise((resolve) => server.close(resolve)));

  it("POST /api/plans creates a plan in proposed state", async () => {
    const res = await request(server, "POST", "/api/plans", {
      case_id: testCaseId,
      title: "Block malicious IP",
      description: "Block the attacker's IP address at the firewall",
      risk_level: "high",
      actions: [
        { type: "block_ip", target: "10.0.0.99", params: { ip: "10.0.0.99" } },
      ],
    });
    assert.equal(res.status, 201);
    assert.equal(res.body.state, "proposed");
    assert.ok(res.body.plan_id);
    assert.ok(res.body.message.includes("PROPOSED"));
    planId = res.body.plan_id;
  });

  it("GET /api/plans lists plans", async () => {
    const res = await request(server, "GET", "/api/plans");
    assert.equal(res.status, 200);
    assert.ok(Array.isArray(res.body));
    assert.ok(res.body.length >= 1);
    const found = res.body.find((p) => p.plan_id === planId);
    assert.ok(found);
  });

  it("GET /api/plans/:id returns specific plan", async () => {
    const res = await request(server, "GET", `/api/plans/${planId}`);
    assert.equal(res.status, 200);
    assert.equal(res.body.plan_id, planId);
    assert.equal(res.body.state, "proposed");
  });

  it("POST /api/plans/:id/approve transitions plan to approved", async () => {
    const res = await request(server, "POST", `/api/plans/${planId}/approve`, {
      approver_id: "admin@example.com",
      reason: "Verified the IP is malicious",
    });
    assert.equal(res.status, 200);
    assert.equal(res.body.state, "approved");
    assert.equal(res.body.approver_id, "admin@example.com");
    assert.ok(res.body.message.includes("APPROVED"));
  });

  it("POST /api/plans/:id/execute fails when responder is disabled", async () => {
    const res = await request(server, "POST", `/api/plans/${planId}/execute`, {
      executor_id: "ops@example.com",
    });
    assert.equal(res.status, 403);
    assert.ok(res.body.error.includes("DISABLED"));
    assert.ok(res.body.responder_status);
    assert.equal(res.body.responder_status.enabled, false);
  });

  it("POST /api/plans/:id/reject rejects a proposed plan", async () => {
    // Create a fresh plan to reject
    const createRes = await request(server, "POST", "/api/plans", {
      case_id: testCaseId,
      title: "Plan to reject",
      actions: [{ type: "isolate_host", target: "server-99" }],
    });
    const rejectPlanId = createRes.body.plan_id;

    const res = await request(server, "POST", `/api/plans/${rejectPlanId}/reject`, {
      rejector_id: "manager@example.com",
      reason: "Not warranted at this time",
    });
    assert.equal(res.status, 200);
    assert.equal(res.body.state, "rejected");
    assert.equal(res.body.rejector_id, "manager@example.com");
  });

  it("POST /api/plans with missing actions returns 400", async () => {
    const res = await request(server, "POST", "/api/plans", {
      case_id: testCaseId,
      title: "No actions plan",
    });
    assert.equal(res.status, 400);
    assert.ok(res.body.error.includes("actions"));
  });
});

// ===================================================================
// 6. 404 for unknown routes
// ===================================================================

describe("Unknown routes", () => {
  let server;

  before(() => {
    ensureTestDirs();
    server = createServer();
    return new Promise((resolve) => server.listen(0, "127.0.0.1", resolve));
  });

  after(() => new Promise((resolve) => server.close(resolve)));

  it("GET /nonexistent returns 404", async () => {
    const res = await request(server, "GET", "/nonexistent");
    assert.equal(res.status, 404);
    assert.equal(res.body.error, "Not found");
  });
});

// ===================================================================
// 7. Security headers
// ===================================================================

describe("Security headers", () => {
  let server;

  before(() => {
    ensureTestDirs();
    server = createServer();
    return new Promise((resolve) => server.listen(0, "127.0.0.1", resolve));
  });

  after(() => new Promise((resolve) => server.close(resolve)));

  it("Responses include standard security headers", async () => {
    const res = await request(server, "GET", "/health");
    assert.equal(res.headers["x-content-type-options"], "nosniff");
    assert.equal(res.headers["x-frame-options"], "DENY");
    assert.equal(res.headers["x-xss-protection"], "1; mode=block");
    assert.equal(res.headers["cache-control"], "no-store");
  });
});

// ===================================================================
// 8. Rate limiting via HTTP
// ===================================================================

describe("Rate limiting", () => {
  let server;

  before(() => {
    // We create a server instance after temporarily setting a very low limit.
    // Because the config object was already parsed from env at module load,
    // we cannot re-read env vars.  Instead we rely on the fact that the
    // checkRateLimit function uses the already-parsed config.
    //
    // Approach: set the env var before importing, and the first describe
    // block uses 200.  For rate-limit testing we spin a fresh server but
    // work within the global config's 200-request window – instead we
    // just send enough requests to exhaust it.  But 200 is a lot.
    //
    // Better approach: the integration tests share one config read.  We
    // set RATE_LIMIT_MAX_REQUESTS=200 globally but we can still test by
    // sending >200 requests... that is expensive.  Instead, let's test
    // by verifying the X-RateLimit-Remaining header decrements correctly
    // for non-health endpoints.
    ensureTestDirs();
    server = createServer();
    return new Promise((resolve) => server.listen(0, "127.0.0.1", resolve));
  });

  after(() => new Promise((resolve) => server.close(resolve)));

  it("X-RateLimit-Remaining header decrements on API requests", async () => {
    const res1 = await request(server, "GET", "/api/cases");
    const remaining1 = parseInt(res1.headers["x-ratelimit-remaining"], 10);
    assert.equal(typeof remaining1, "number");
    assert.ok(remaining1 >= 0);

    const res2 = await request(server, "GET", "/api/cases");
    const remaining2 = parseInt(res2.headers["x-ratelimit-remaining"], 10);
    // The remaining count should be less than or equal to the previous
    assert.ok(remaining2 <= remaining1);
  });

  it("Health endpoints are exempt from rate limiting (no X-RateLimit-Remaining)", async () => {
    const res = await request(server, "GET", "/health");
    assert.equal(res.status, 200);
    // Health/metrics/ready should NOT have rate limit header
    assert.equal(res.headers["x-ratelimit-remaining"], undefined);
  });

  it("Metrics endpoint is exempt from rate limiting", async () => {
    const res = await request(server, "GET", "/metrics");
    assert.equal(res.status, 200);
    assert.equal(res.headers["x-ratelimit-remaining"], undefined);
  });

  it("Ready endpoint is exempt from rate limiting", async () => {
    const res = await request(server, "GET", "/ready");
    assert.equal(res.status, 200);
    assert.equal(res.headers["x-ratelimit-remaining"], undefined);
  });
});

// ===================================================================
// 9. Request ID tracking
// ===================================================================

describe("Request ID tracking", () => {
  let server;

  before(() => {
    ensureTestDirs();
    server = createServer();
    return new Promise((resolve) => server.listen(0, "127.0.0.1", resolve));
  });

  after(() => new Promise((resolve) => server.close(resolve)));

  it("Response includes X-Request-ID header (auto-generated)", async () => {
    const res = await request(server, "GET", "/health");
    const reqId = res.headers["x-request-id"];
    assert.ok(reqId);
    assert.ok(reqId.startsWith("req-"));
  });

  it("Server echoes client-supplied X-Request-ID", async () => {
    const customId = "my-custom-request-id-12345";
    const res = await request(server, "GET", "/version", null, {
      "X-Request-ID": customId,
    });
    assert.equal(res.headers["x-request-id"], customId);
  });

  it("Error responses include request_id in body", async () => {
    const res = await request(server, "GET", "/nonexistent");
    assert.equal(res.status, 404);
    assert.ok(res.body.request_id);
    // Should match the header
    assert.equal(res.body.request_id, res.headers["x-request-id"]);
  });
});

// ===================================================================
// 10. Authorization validation
// ===================================================================

describe("Authorization", () => {
  let server;

  before(() => {
    ensureTestDirs();
    server = createServer();
    return new Promise((resolve) => server.listen(0, "127.0.0.1", resolve));
  });

  after(() => new Promise((resolve) => server.close(resolve)));

  it("Localhost requests succeed without Authorization header", async () => {
    // All our test requests come from 127.0.0.1 already
    const res = await request(server, "GET", "/api/cases");
    assert.equal(res.status, 200);
  });

  it("Requests with valid Bearer MCP auth token succeed", async () => {
    const res = await request(server, "POST", "/api/cases", {
      case_id: "CASE-auth-test-01",
      title: "Auth test",
    }, {
      Authorization: "Bearer test-mcp-secret-token",
    });
    assert.equal(res.status, 201);
  });

  it("Case ID with invalid characters returns 400", async () => {
    const res = await request(server, "POST", "/api/cases", {
      case_id: "../etc/passwd",
      title: "Path traversal attempt",
    });
    assert.equal(res.status, 400);
    assert.ok(res.body.error.includes("case_id"));
  });
});

// ===================================================================
// 11. Additional edge cases and validation
// ===================================================================

describe("Validation and edge cases", () => {
  let server;

  before(() => {
    ensureTestDirs();
    server = createServer();
    return new Promise((resolve) => server.listen(0, "127.0.0.1", resolve));
  });

  after(() => new Promise((resolve) => server.close(resolve)));

  it("POST /api/plans/:id/approve without approver_id returns 400", async () => {
    // First create a plan
    const createRes = await request(server, "POST", "/api/cases", {
      case_id: "CASE-val-edge-01",
      title: "Validation edge case",
    });
    assert.equal(createRes.status, 201);

    const planRes = await request(server, "POST", "/api/plans", {
      case_id: "CASE-val-edge-01",
      title: "Validate approve body",
      actions: [{ type: "block_ip", target: "10.0.0.1" }],
    });
    assert.equal(planRes.status, 201);

    const res = await request(server, "POST", `/api/plans/${planRes.body.plan_id}/approve`, {});
    assert.equal(res.status, 400);
    assert.ok(res.body.error.includes("approver_id"));
  });

  it("POST /api/plans/:id/reject without rejector_id returns 400", async () => {
    const planRes = await request(server, "POST", "/api/plans", {
      case_id: "CASE-val-edge-01",
      title: "Validate reject body",
      actions: [{ type: "kill_process", target: "malware.exe" }],
    });
    assert.equal(planRes.status, 201);

    const res = await request(server, "POST", `/api/plans/${planRes.body.plan_id}/reject`, {});
    assert.equal(res.status, 400);
    assert.ok(res.body.error.includes("rejector_id"));
  });

  it("POST /api/plans/:id/execute without executor_id returns 400", async () => {
    const planRes = await request(server, "POST", "/api/plans", {
      case_id: "CASE-val-edge-01",
      title: "Validate execute body",
      actions: [{ type: "block_ip", target: "10.0.0.50" }],
    });
    assert.equal(planRes.status, 201);

    // Approve first
    await request(server, "POST", `/api/plans/${planRes.body.plan_id}/approve`, {
      approver_id: "admin@example.com",
    });

    const res = await request(server, "POST", `/api/plans/${planRes.body.plan_id}/execute`, {});
    assert.equal(res.status, 400);
    assert.ok(res.body.error.includes("executor_id"));
  });

  it("GET /api/plans/:id for non-existent plan returns 404", async () => {
    const res = await request(server, "GET", "/api/plans/PLAN-9999999999999-deadbeef");
    assert.equal(res.status, 404);
    assert.ok(res.body.error);
  });

  it("GET /api/plans/:id with invalid format returns 400", async () => {
    const res = await request(server, "GET", "/api/plans/PLAN-does-not-exist");
    assert.equal(res.status, 400);
    assert.ok(res.body.error.includes("Invalid plan ID"));
  });

  it("POST /api/plans with invalid action structure returns 400", async () => {
    const res = await request(server, "POST", "/api/plans", {
      case_id: "CASE-val-edge-01",
      title: "Plan with bad actions",
      actions: [{ foo: "bar" }], // missing type and target
    });
    assert.equal(res.status, 400);
    assert.ok(res.body.error.includes("Invalid actions"));
  });

  it("PUT /api/cases/:id for non-existent case returns 404", async () => {
    const res = await request(server, "PUT", "/api/cases/NONEXISTENT-99", {
      title: "updated",
    });
    assert.equal(res.status, 404);
  });

  it("POST /api/cases with case_id containing special chars returns 400", async () => {
    const res = await request(server, "POST", "/api/cases", {
      case_id: "CASE with spaces!",
      title: "Bad ID",
    });
    assert.equal(res.status, 400);
  });

  it("GET /api/plans filters by state query parameter", async () => {
    const res = await request(server, "GET", "/api/plans?state=proposed");
    assert.equal(res.status, 200);
    assert.ok(Array.isArray(res.body));
    // All returned plans should be in proposed state
    for (const plan of res.body) {
      assert.equal(plan.state, "proposed");
    }
  });
});

// ===================================================================
// 8. End-to-End Pipeline
// ===================================================================

describe("End-to-End Pipeline", () => {
  let server;
  let pipelineCaseId;

  before(() => {
    ensureTestDirs();
    server = createServer();
    return new Promise((resolve) => server.listen(0, "127.0.0.1", resolve));
  });

  after(() => new Promise((resolve) => server.close(resolve)));

  it("POST /api/alerts creates a case with entities and severity", async () => {
    const res = await request(
      server,
      "POST",
      "/api/alerts",
      {
        alert_id: "e2e-alert-001",
        rule: { id: "5712", level: 10, description: "SSH brute force" },
        agent: { id: "001", name: "prod-01", ip: "10.0.1.50" },
        data: { srcip: "203.0.113.50" },
      },
      { Authorization: "Bearer test-mcp-secret-token" },
    );
    assert.equal(res.status, 201);
    assert.ok(res.body.case_id);
    assert.equal(res.body.status, "created");
    assert.equal(res.body.severity, "high");
    assert.ok(res.body.entities_extracted >= 2);
    pipelineCaseId = res.body.case_id;
  });

  it("GET /api/cases/:id returns full case structure", async () => {
    const res = await request(
      server,
      "GET",
      `/api/cases/${pipelineCaseId}`,
      null,
      { Authorization: "Bearer test-mcp-secret-token" },
    );
    assert.equal(res.status, 200);
    assert.ok(res.body.entities);
    assert.ok(res.body.timeline);
    assert.ok(res.body.evidence_refs);
    assert.equal(res.body.severity, "high");
  });

  it("PUT /api/cases/:id updates status to triaged", async () => {
    const res = await request(
      server,
      "PUT",
      `/api/cases/${pipelineCaseId}`,
      { status: "triaged" },
      { Authorization: "Bearer test-mcp-secret-token" },
    );
    assert.equal(res.status, 200);
  });

  it("PUT /api/cases/:id updates status to correlated", async () => {
    const res = await request(
      server,
      "PUT",
      `/api/cases/${pipelineCaseId}`,
      { status: "correlated" },
      { Authorization: "Bearer test-mcp-secret-token" },
    );
    assert.equal(res.status, 200);
  });

  it("PUT /api/cases/:id updates status to investigated", async () => {
    const res = await request(
      server,
      "PUT",
      `/api/cases/${pipelineCaseId}`,
      { status: "investigated" },
      { Authorization: "Bearer test-mcp-secret-token" },
    );
    assert.equal(res.status, 200);
  });

  it("POST /api/plans creates a proposed plan on the case", async () => {
    const res = await request(
      server,
      "POST",
      "/api/plans",
      {
        case_id: pipelineCaseId,
        risk_level: "medium",
        actions: [
          { type: "block_ip", target: "203.0.113.50", params: { ip: "203.0.113.50" } },
        ],
      },
      { Authorization: "Bearer test-mcp-secret-token" },
    );
    assert.equal(res.status, 201);
    assert.equal(res.body.state, "proposed");
    assert.ok(res.body.plan_id);
  });

  it("POST /api/alerts groups second alert with same IP into existing case", async () => {
    const res = await request(
      server,
      "POST",
      "/api/alerts",
      {
        alert_id: "e2e-alert-002",
        rule: { id: "5712", level: 12, description: "SSH brute force continued" },
        agent: { id: "001", name: "prod-01", ip: "10.0.1.50" },
        data: { srcip: "203.0.113.50" },
      },
      { Authorization: "Bearer test-mcp-secret-token" },
    );
    assert.equal(res.status, 200); // 200 = updated existing
    assert.equal(res.body.status, "updated");
  });

  it("GET /metrics includes incremented counters", async () => {
    const res = await request(server, "GET", "/metrics");
    assert.equal(res.status, 200);
    assert.ok(res.raw.includes("autopilot_alerts_ingested_total"));
    assert.ok(res.raw.includes("autopilot_cases_created_total"));
  });
});

// ===================================================================
// 9. Case Feedback Endpoint
// ===================================================================

describe("Case Feedback Endpoint", () => {
  let server;
  let feedbackCaseId;

  before(async () => {
    ensureTestDirs();
    server = createServer();
    await new Promise((resolve) => server.listen(0, "127.0.0.1", resolve));

    // Create a case for feedback testing
    const res = await request(
      server,
      "POST",
      "/api/alerts",
      {
        alert_id: "feedback-test-001",
        rule: { id: "5000", level: 8, description: "Test alert for feedback" },
        agent: { id: "002", name: "test-host" },
        data: { srcip: "198.51.100.10" },
      },
      { Authorization: "Bearer test-mcp-secret-token" },
    );
    feedbackCaseId = res.body.case_id;
  });

  after(() => new Promise((resolve) => server.close(resolve)));

  it("POST /api/cases/:id/feedback records true_positive verdict", async () => {
    const res = await request(
      server,
      "POST",
      `/api/cases/${feedbackCaseId}/feedback`,
      { verdict: "true_positive", reason: "Confirmed attack", user_id: "analyst-1" },
      { Authorization: "Bearer test-mcp-secret-token" },
    );
    assert.equal(res.status, 200);
    assert.equal(res.body.verdict, "true_positive");
    assert.equal(res.body.feedback_count, 1);
  });

  it("POST /api/cases/:id/feedback records false_positive verdict and updates status", async () => {
    const res = await request(
      server,
      "POST",
      `/api/cases/${feedbackCaseId}/feedback`,
      { verdict: "false_positive", reason: "Known scanner", user_id: "analyst-2" },
      { Authorization: "Bearer test-mcp-secret-token" },
    );
    assert.equal(res.status, 200);
    assert.equal(res.body.verdict, "false_positive");
    assert.equal(res.body.status, "false_positive");
    assert.equal(res.body.feedback_count, 2);
  });

  it("POST /api/cases/:id/feedback rejects invalid verdict", async () => {
    const res = await request(
      server,
      "POST",
      `/api/cases/${feedbackCaseId}/feedback`,
      { verdict: "invalid_verdict" },
      { Authorization: "Bearer test-mcp-secret-token" },
    );
    assert.equal(res.status, 400);
  });

  it("POST /api/cases/:id/feedback returns 404 for non-existent case", async () => {
    const res = await request(
      server,
      "POST",
      "/api/cases/CASE-00000000-000000000000/feedback",
      { verdict: "true_positive", reason: "test" },
      { Authorization: "Bearer test-mcp-secret-token" },
    );
    assert.equal(res.status, 404);
  });

  it("POST /api/cases/:id/feedback allows localhost in bootstrap mode", async () => {
    // In bootstrap mode, localhost requests are allowed without auth
    const res = await request(
      server,
      "POST",
      `/api/cases/${feedbackCaseId}/feedback`,
      { verdict: "needs_review", reason: "auto-test" },
    );
    assert.equal(res.status, 200);
    assert.equal(res.body.verdict, "needs_review");
  });
});

// ===================================================================
// STATUS TRANSITION ENFORCEMENT (HTTP)
// ===================================================================

describe("Status Transition Enforcement", () => {
  let server;
  let validCaseId;
  const AUTH = { Authorization: "Bearer test-mcp-secret-token" };

  before(() => {
    ensureTestDirs();
    server = createServer();
    return new Promise((resolve) => server.listen(0, "127.0.0.1", resolve));
  });

  after(() => new Promise((resolve) => server.close(resolve)));

  it("creates a case for transition tests", async () => {
    const res = await request(server, "POST", "/api/alerts", {
      alert_id: "transition-test-001",
      rule: { id: "5712", level: 10, description: "Transition test" },
      agent: { id: "001", name: "test-server" },
      data: { srcip: "172.16.99.1" },
    }, AUTH);
    assert.strictEqual(res.status, 201);
    validCaseId = res.body.case_id;
  });

  it("rejects invalid transition open → executed with 400", async () => {
    const res = await request(server, "PUT", `/api/cases/${validCaseId}`, { status: "executed" }, AUTH);
    assert.strictEqual(res.status, 400);
    assert.ok(res.raw.includes("Invalid status transition"));
  });

  it("allows valid transition open → triaged", async () => {
    const res = await request(server, "PUT", `/api/cases/${validCaseId}`, { status: "triaged" }, AUTH);
    assert.strictEqual(res.status, 200);
  });

  it("rejects triaged → executed", async () => {
    const res = await request(server, "PUT", `/api/cases/${validCaseId}`, { status: "executed" }, AUTH);
    assert.strictEqual(res.status, 400);
  });
});

// ===================================================================
// PLAN CASE EXISTENCE CHECK
// ===================================================================

describe("Plan Case Existence Check", () => {
  let server;
  const AUTH = { Authorization: "Bearer test-mcp-secret-token" };

  before(() => {
    ensureTestDirs();
    server = createServer();
    return new Promise((resolve) => server.listen(0, "127.0.0.1", resolve));
  });

  after(() => new Promise((resolve) => server.close(resolve)));

  it("rejects plan for non-existent case with 404", async () => {
    const res = await request(server, "POST", "/api/plans", {
      case_id: "CASE-99999999-fakecase1234",
      title: "Phantom plan",
      actions: [{ action: "block_ip", params: { ip: "1.2.3.4" } }],
    }, AUTH);
    assert.strictEqual(res.status, 404);
    assert.ok(res.raw.includes("not found"));
  });
});

// ===================================================================
// EXPANDED ENTITY EXTRACTION
// ===================================================================

describe("Expanded Entity Extraction", () => {
  let server;
  const AUTH = { Authorization: "Bearer test-mcp-secret-token" };

  before(() => {
    ensureTestDirs();
    server = createServer();
    return new Promise((resolve) => server.listen(0, "127.0.0.1", resolve));
  });

  after(() => new Promise((resolve) => server.close(resolve)));

  it("extracts file hashes from syscheck alerts", async () => {
    const res = await request(server, "POST", "/api/alerts", {
      alert_id: "hash-test-001",
      rule: { id: "550", level: 7, description: "File integrity change" },
      agent: { id: "002", name: "file-server" },
      data: { syscheck: { md5_after: "d41d8cd98f00b204e9800998ecf8427e", sha256_after: "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855" } },
    }, AUTH);
    assert.strictEqual(res.status, 201);
    assert.ok(res.body.entities_extracted >= 3); // host + 2 hashes
  });

  it("extracts CVE IDs from vulnerability alerts", async () => {
    const res = await request(server, "POST", "/api/alerts", {
      alert_id: "cve-test-001",
      rule: { id: "23504", level: 10, description: "Vulnerability detected" },
      agent: { id: "003", name: "vuln-server" },
      data: { vulnerability: { cve: "CVE-2024-1234", severity: "high", reference: "CVE-2024-5678" } },
    }, AUTH);
    assert.strictEqual(res.status, 201);
    assert.ok(res.body.entities_extracted >= 3); // host + 2 CVEs
  });

  it("extracts port numbers from alerts", async () => {
    const res = await request(server, "POST", "/api/alerts", {
      alert_id: "port-test-001",
      rule: { id: "5712", level: 10, description: "Port test" },
      agent: { id: "004", name: "net-server" },
      data: { srcip: "10.0.0.1", srcport: "44322", dstport: "22" },
    }, AUTH);
    assert.strictEqual(res.status, 201);
    assert.ok(res.body.entities_extracted >= 4); // host + IP + 2 ports
  });

  it("handles string rule.level correctly", async () => {
    const res = await request(server, "POST", "/api/alerts", {
      alert_id: "strlevel-test-001",
      rule: { id: "5712", level: "12", description: "String level test" },
      agent: { id: "005", name: "str-server" },
      data: { srcip: "10.0.0.5" },
    }, AUTH);
    assert.strictEqual(res.status, 201);
    assert.strictEqual(res.body.severity, "high"); // 12 should be "high"
  });
});

// ===================================================================
// METRICS ENDPOINT GATING
// ===================================================================

describe("Metrics endpoint gating", () => {
  let server;

  before(() => {
    ensureTestDirs();
    server = createServer();
    return new Promise((resolve) => server.listen(0, "127.0.0.1", resolve));
  });

  after(() => new Promise((resolve) => server.close(resolve)));

  it("returns metrics when METRICS_ENABLED is not false (default)", async () => {
    const res = await request(server, "GET", "/metrics");
    assert.strictEqual(res.status, 200);
    assert.ok(res.raw.includes("autopilot_cases_created_total"));
  });
});

// ===================================================================
// HEALTH ENDPOINT CONNECTIVITY CHECKS
// ===================================================================

describe("Health endpoint connectivity fields", () => {
  let server;

  before(() => {
    ensureTestDirs();
    server = createServer();
    return new Promise((resolve) => server.listen(0, "127.0.0.1", resolve));
  });

  after(() => new Promise((resolve) => server.close(resolve)));

  it("includes mcp_configured and gateway_configured in checks", async () => {
    const res = await request(server, "GET", "/health");
    assert.strictEqual(res.status, 200);
    assert.ok("mcp_configured" in res.body.checks);
    assert.ok("gateway_configured" in res.body.checks);
  });
});

// ===================================================================
// Cleanup
// ===================================================================

describe("Cleanup", () => {
  it("removes the temporary data directory", () => {
    rmTestDir();
    assert.equal(fs.existsSync(TEST_DATA_DIR), false);
  });
});
