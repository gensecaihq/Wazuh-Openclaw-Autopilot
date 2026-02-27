/**
 * Tests for the GET-based agent action endpoints.
 *
 * These endpoints exist because OpenClaw's web_fetch tool is GET-only.
 * Agents use these instead of PUT/POST to advance the pipeline.
 *
 * Run:  node --test agent-actions.test.js
 */

const { describe, it, before, after, beforeEach } = require("node:test");
const assert = require("node:assert/strict");
const http = require("http");
const os = require("os");
const path = require("path");
const fs = require("fs");

const TEST_DATA_DIR = path.join(
  os.tmpdir(),
  `autopilot-agent-actions-test-${Date.now()}-${process.pid}`,
);

process.env.AUTOPILOT_MODE = "bootstrap";
process.env.AUTOPILOT_DATA_DIR = TEST_DATA_DIR;
process.env.AUTOPILOT_MCP_AUTH = "test-mcp-secret-token";
process.env.AUTOPILOT_SERVICE_TOKEN = "test-service-token";
process.env.AUTOPILOT_RESPONDER_ENABLED = "true";
process.env.RATE_LIMIT_MAX_REQUESTS = "500";
process.env.RATE_LIMIT_WINDOW_MS = "60000";
process.env.LOG_LEVEL = "error";

const { createServer } = require("./index");

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

function ensureTestDirs() {
  fs.mkdirSync(path.join(TEST_DATA_DIR, "cases"), { recursive: true });
  fs.mkdirSync(path.join(TEST_DATA_DIR, "reports"), { recursive: true });
  fs.mkdirSync(path.join(TEST_DATA_DIR, "state"), { recursive: true });
}

function rmTestDir() {
  try { fs.rmSync(TEST_DATA_DIR, { recursive: true, force: true }); } catch {}
}

// Helper: create a case via the alert endpoint (reuses existing triage logic)
async function ingestAlert(server, alertId = `test-${Date.now()}`) {
  const res = await request(server, "POST", "/api/alerts", {
    alert_id: alertId,
    rule: { id: "5712", level: 12, description: "SSH brute force attack" },
    agent: { id: "001", name: "prod-web-01", ip: "10.0.1.50" },
    data: { srcip: "185.220.101.42", dstuser: "root" },
  });
  return res.body;
}

// ===================================================================
// Agent Action: update-case
// ===================================================================

describe("GET /api/agent-action/update-case", () => {
  let server;

  before(() => {
    ensureTestDirs();
    server = createServer();
    return new Promise((resolve) => server.listen(0, "127.0.0.1", resolve));
  });

  after(() => {
    return new Promise((resolve) => server.close(() => { rmTestDir(); resolve(); }));
  });

  it("updates case status to triaged", async () => {
    const alert = await ingestAlert(server, `aa-triaged-${Date.now()}`);
    const caseId = alert.case_id;

    const res = await request(server, "GET",
      `/api/agent-action/update-case?case_id=${caseId}&status=triaged`);
    assert.equal(res.status, 200);
    assert.equal(res.body.ok, true);
    assert.equal(res.body.case_id, caseId);
    assert.equal(res.body.status, "triaged");
  });

  it("updates case with data parameter", async () => {
    const alert = await ingestAlert(server, `aa-data-${Date.now()}`);
    const caseId = alert.case_id;
    const data = JSON.stringify({ title: "Updated title" });

    const res = await request(server, "GET",
      `/api/agent-action/update-case?case_id=${caseId}&data=${encodeURIComponent(data)}`);
    assert.equal(res.status, 200);
    assert.equal(res.body.ok, true);
  });

  it("rejects missing case_id", async () => {
    const res = await request(server, "GET",
      "/api/agent-action/update-case?status=triaged");
    assert.equal(res.status, 400);
  });

  it("rejects invalid case_id format", async () => {
    // Case IDs allow alphanumeric+hyphens, so use a format with invalid chars
    const res = await request(server, "GET",
      "/api/agent-action/update-case?case_id=INVALID%20SPACES%21&status=triaged");
    assert.equal(res.status, 400);
  });

  it("rejects no updates", async () => {
    const alert = await ingestAlert(server, `aa-noupdate-${Date.now()}`);
    const res = await request(server, "GET",
      `/api/agent-action/update-case?case_id=${alert.case_id}`);
    assert.equal(res.status, 400);
  });

  it("returns 404 for non-existent case", async () => {
    const res = await request(server, "GET",
      "/api/agent-action/update-case?case_id=CASE-20260228-00000000&status=triaged");
    assert.equal(res.status, 404);
  });

  it("rejects invalid JSON in data parameter", async () => {
    const alert = await ingestAlert(server, `aa-badjson-${Date.now()}`);
    const res = await request(server, "GET",
      `/api/agent-action/update-case?case_id=${alert.case_id}&data=not-json`);
    assert.equal(res.status, 400);
  });
});

// ===================================================================
// Agent Action: create-plan
// ===================================================================

describe("GET /api/agent-action/create-plan", () => {
  let server;
  let testCaseId;

  before(async () => {
    ensureTestDirs();
    server = createServer();
    await new Promise((resolve) => server.listen(0, "127.0.0.1", resolve));
    // Create a case to reference in plans
    const alert = await ingestAlert(server, `aa-plan-${Date.now()}`);
    testCaseId = alert.case_id;
  });

  after(() => {
    return new Promise((resolve) => server.close(() => { rmTestDir(); resolve(); }));
  });

  it("creates a response plan", async () => {
    const actions = JSON.stringify([{ type: "block_ip", target: "1.2.3.4" }]);
    const res = await request(server, "GET",
      `/api/agent-action/create-plan?case_id=${testCaseId}&title=Block%20attacker&risk_level=low&actions=${encodeURIComponent(actions)}`);
    assert.equal(res.status, 201);
    assert.equal(res.body.ok, true);
    assert.ok(res.body.plan_id);
    assert.equal(res.body.state, "proposed");
  });

  it("rejects missing case_id", async () => {
    const actions = JSON.stringify([{ type: "block_ip", target: "1.2.3.4" }]);
    const res = await request(server, "GET",
      `/api/agent-action/create-plan?title=Test&actions=${encodeURIComponent(actions)}`);
    assert.equal(res.status, 400);
  });

  it("rejects missing title", async () => {
    const actions = JSON.stringify([{ type: "block_ip", target: "1.2.3.4" }]);
    const res = await request(server, "GET",
      `/api/agent-action/create-plan?case_id=${testCaseId}&actions=${encodeURIComponent(actions)}`);
    assert.equal(res.status, 400);
  });

  it("rejects invalid actions JSON", async () => {
    const res = await request(server, "GET",
      `/api/agent-action/create-plan?case_id=${testCaseId}&title=Test&actions=not-json`);
    assert.equal(res.status, 400);
  });

  it("rejects empty actions array", async () => {
    const res = await request(server, "GET",
      `/api/agent-action/create-plan?case_id=${testCaseId}&title=Test&actions=${encodeURIComponent("[]")}`);
    assert.equal(res.status, 400);
  });

  it("rejects non-existent case", async () => {
    const actions = JSON.stringify([{ type: "block_ip", target: "1.2.3.4" }]);
    const res = await request(server, "GET",
      `/api/agent-action/create-plan?case_id=CASE-20260228-00000000&title=Test&actions=${encodeURIComponent(actions)}`);
    assert.equal(res.status, 404);
  });
});

// ===================================================================
// Agent Action: approve-plan
// ===================================================================

describe("GET /api/agent-action/approve-plan", () => {
  let server;
  let testPlanId;

  before(async () => {
    ensureTestDirs();
    server = createServer();
    await new Promise((resolve) => server.listen(0, "127.0.0.1", resolve));
    // Create a case + plan
    const alert = await ingestAlert(server, `aa-approve-${Date.now()}`);
    const actions = JSON.stringify([{ type: "block_ip", target: "1.2.3.4" }]);
    const planRes = await request(server, "GET",
      `/api/agent-action/create-plan?case_id=${alert.case_id}&title=Block%20attacker&risk_level=low&actions=${encodeURIComponent(actions)}`);
    testPlanId = planRes.body.plan_id;
  });

  after(() => {
    return new Promise((resolve) => server.close(() => { rmTestDir(); resolve(); }));
  });

  it("approves a plan", async () => {
    const res = await request(server, "GET",
      `/api/agent-action/approve-plan?plan_id=${testPlanId}&approver_id=approver-001&decision=allow&reason=Looks%20good`);
    assert.equal(res.status, 200);
    assert.equal(res.body.ok, true);
    assert.equal(res.body.state, "approved");
  });

  it("rejects missing plan_id", async () => {
    const res = await request(server, "GET",
      "/api/agent-action/approve-plan?approver_id=approver-001&decision=allow");
    assert.equal(res.status, 400);
  });

  it("rejects missing approver_id", async () => {
    const res = await request(server, "GET",
      `/api/agent-action/approve-plan?plan_id=${testPlanId}&decision=allow`);
    assert.equal(res.status, 400);
  });
});

// ===================================================================
// Agent Action: approve-plan (deny path)
// ===================================================================

describe("GET /api/agent-action/approve-plan (deny)", () => {
  let server;
  let testPlanId;

  before(async () => {
    ensureTestDirs();
    server = createServer();
    await new Promise((resolve) => server.listen(0, "127.0.0.1", resolve));
    const alert = await ingestAlert(server, `aa-deny-${Date.now()}`);
    const actions = JSON.stringify([{ type: "block_ip", target: "5.6.7.8" }]);
    const planRes = await request(server, "GET",
      `/api/agent-action/create-plan?case_id=${alert.case_id}&title=Deny%20test&risk_level=low&actions=${encodeURIComponent(actions)}`);
    testPlanId = planRes.body.plan_id;
  });

  after(() => {
    return new Promise((resolve) => server.close(() => { rmTestDir(); resolve(); }));
  });

  it("denies a plan with decision=deny", async () => {
    const res = await request(server, "GET",
      `/api/agent-action/approve-plan?plan_id=${testPlanId}&approver_id=approver-001&decision=deny&reason=Too%20risky`);
    assert.equal(res.status, 200);
    assert.equal(res.body.ok, true);
    assert.equal(res.body.state, "rejected");
    assert.equal(res.body.decision, "deny");
  });
});

// ===================================================================
// Agent Action: execute-plan
// ===================================================================

describe("GET /api/agent-action/execute-plan", () => {
  let server;

  before(() => {
    ensureTestDirs();
    server = createServer();
    return new Promise((resolve) => server.listen(0, "127.0.0.1", resolve));
  });

  after(() => {
    return new Promise((resolve) => server.close(() => { rmTestDir(); resolve(); }));
  });

  it("rejects missing plan_id", async () => {
    const res = await request(server, "GET",
      "/api/agent-action/execute-plan?executor_id=exec-001");
    assert.equal(res.status, 400);
  });

  it("rejects missing executor_id", async () => {
    const res = await request(server, "GET",
      "/api/agent-action/execute-plan?plan_id=PLAN-1234567890-abcdef01");
    assert.equal(res.status, 400);
  });

  it("executes an approved plan", async () => {
    // Create case, plan, approve, then execute
    const alert = await ingestAlert(server, `aa-exec-${Date.now()}`);
    const actions = JSON.stringify([{ type: "block_ip", target: "9.8.7.6" }]);
    const planRes = await request(server, "GET",
      `/api/agent-action/create-plan?case_id=${alert.case_id}&title=Execute%20test&risk_level=low&actions=${encodeURIComponent(actions)}`);
    const planId = planRes.body.plan_id;

    // Approve
    await request(server, "GET",
      `/api/agent-action/approve-plan?plan_id=${planId}&approver_id=approver-001&decision=allow`);

    // Execute
    const res = await request(server, "GET",
      `/api/agent-action/execute-plan?plan_id=${planId}&executor_id=exec-001`);
    // Should succeed (200) or partial (207) — but not 400/404
    assert.ok(res.status === 200 || res.status === 207, `Expected 200/207, got ${res.status}`);
    assert.equal(res.body.ok, true);
  });
});
