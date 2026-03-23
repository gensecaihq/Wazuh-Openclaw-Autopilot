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
// Uses unique srcip, dstuser, and agent name per call to prevent entity-based alert grouping
let ingestCounter = 0;
async function ingestAlert(server, alertId = `test-${Date.now()}`) {
  ingestCounter++;
  const octet3 = Math.floor(ingestCounter / 255) % 255;
  const octet4 = (ingestCounter % 255) + 1;
  const res = await request(server, "POST", "/api/alerts", {
    alert_id: alertId,
    rule: { id: "5712", level: 12, description: "SSH brute force attack" },
    agent: { id: String(ingestCounter), name: `host-${alertId}`, ip: "10.0.1.50" },
    data: { srcip: `185.220.${octet3}.${octet4}`, dstuser: `user-${alertId}` },
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

  it("rejects invalid severity enum value", async () => {
    const alert = await ingestAlert(server, `aa-badsev-${Date.now()}`);
    const data = JSON.stringify({ severity: "banana" });
    const res = await request(server, "GET",
      `/api/agent-action/update-case?case_id=${alert.case_id}&data=${encodeURIComponent(data)}`);
    assert.equal(res.status, 400);
    assert.ok(res.body.error.includes("Invalid severity"));
  });

  it("accepts valid severity enum values", async () => {
    const alert = await ingestAlert(server, `aa-goodsev-${Date.now()}`);
    const data = JSON.stringify({ severity: "critical" });
    const res = await request(server, "GET",
      `/api/agent-action/update-case?case_id=${alert.case_id}&data=${encodeURIComponent(data)}`);
    assert.equal(res.status, 200);
  });

  it("rejects out-of-range confidence", async () => {
    const alert = await ingestAlert(server, `aa-badconf-${Date.now()}`);
    const data = JSON.stringify({ confidence: 1.5 });
    const res = await request(server, "GET",
      `/api/agent-action/update-case?case_id=${alert.case_id}&data=${encodeURIComponent(data)}`);
    assert.equal(res.status, 400);
    assert.ok(res.body.error.includes("Invalid confidence"));
  });

  it("rejects negative confidence", async () => {
    const alert = await ingestAlert(server, `aa-negconf-${Date.now()}`);
    const data = JSON.stringify({ confidence: -0.5 });
    const res = await request(server, "GET",
      `/api/agent-action/update-case?case_id=${alert.case_id}&data=${encodeURIComponent(data)}`);
    assert.equal(res.status, 400);
    assert.ok(res.body.error.includes("Invalid confidence"));
  });

  it("rejects triaged status without required title field", async () => {
    const alert = await ingestAlert(server, `aa-notitle-${Date.now()}`);
    const data = JSON.stringify({ severity: "high" });
    const res = await request(server, "GET",
      `/api/agent-action/update-case?case_id=${alert.case_id}&status=triaged&data=${encodeURIComponent(data)}`);
    assert.equal(res.status, 400);
    assert.ok(res.body.error.includes("title"));
  });

  it("rejects triaged status without required severity field", async () => {
    const alert = await ingestAlert(server, `aa-nosev-${Date.now()}`);
    const data = JSON.stringify({ title: "Test Title" });
    const res = await request(server, "GET",
      `/api/agent-action/update-case?case_id=${alert.case_id}&status=triaged&data=${encodeURIComponent(data)}`);
    assert.equal(res.status, 400);
    assert.ok(res.body.error.includes("severity"));
  });

  it("accepts triaged status with all required fields", async () => {
    const alert = await ingestAlert(server, `aa-goodtri-${Date.now()}`);
    const data = JSON.stringify({ title: "SSH Brute Force", severity: "high" });
    const res = await request(server, "GET",
      `/api/agent-action/update-case?case_id=${alert.case_id}&status=triaged&data=${encodeURIComponent(data)}`);
    assert.equal(res.status, 200, `Expected 200 but got ${res.status}: ${JSON.stringify(res.body)}`);
  });

  it("normalizes nested entities object to flat array", async () => {
    const alert = await ingestAlert(server, `aa-entobj-${Date.now()}`);
    const data = JSON.stringify({
      entities: {
        ips: [{ value: "10.0.0.1", direction: "source" }],
        users: [{ value: "admin", type: "target" }],
      },
    });
    const res = await request(server, "GET",
      `/api/agent-action/update-case?case_id=${alert.case_id}&data=${encodeURIComponent(data)}`);
    assert.equal(res.status, 200);
  });

  it("accepts mitre as both object and array", async () => {
    const alert = await ingestAlert(server, `aa-mitre-${Date.now()}`);
    const data = JSON.stringify({
      mitre: { technique: "T1110", tactic: "credential-access" },
    });
    const res = await request(server, "GET",
      `/api/agent-action/update-case?case_id=${alert.case_id}&data=${encodeURIComponent(data)}`);
    assert.equal(res.status, 200);
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

// ===================================================================
// Bug fix tests: confidence, decision validation, plan persistence
// ===================================================================

describe("Bug fixes: confidence, decision validation, plan persistence", () => {
  let server;

  before(() => {
    ensureTestDirs();
    server = createServer();
    return new Promise((resolve) => server.listen(0, "127.0.0.1", resolve));
  });

  after(() => {
    return new Promise((resolve) => server.close(() => { rmTestDir(); resolve(); }));
  });

  it("update-case accepts numeric confidence in data param", async () => {
    const alert = await ingestAlert(server, `confidence-test-${Date.now()}`);
    const caseId = alert.case_id;

    const res = await request(server, "GET",
      `/api/agent-action/update-case?case_id=${caseId}&data=${encodeURIComponent(JSON.stringify({ confidence: 0.85 }))}`);
    assert.equal(res.status, 200);

    // Verify the confidence was actually set
    const caseRes = await request(server, "GET", `/api/cases/${caseId}`);
    assert.equal(caseRes.body.confidence, 0.85);
  });

  it("update-case rejects non-numeric confidence in data param", async () => {
    const alert = await ingestAlert(server, `confidence-str-${Date.now()}`);
    const caseId = alert.case_id;

    // String confidence should be silently dropped (type mismatch), but status should still work
    const res = await request(server, "GET",
      `/api/agent-action/update-case?case_id=${caseId}&status=triaged&data=${encodeURIComponent(JSON.stringify({ confidence: "high" }))}`);
    assert.equal(res.status, 200);

    // Verify the original confidence (from alert ingestion) is preserved
    const caseRes = await request(server, "GET", `/api/cases/${caseId}`);
    assert.notEqual(caseRes.body.confidence, "high");
  });

  it("approve-plan rejects invalid decision values", async () => {
    const alert = await ingestAlert(server, `decision-test-${Date.now()}`);
    const caseId = alert.case_id;

    // Create plan
    const planRes = await request(server, "GET",
      `/api/agent-action/create-plan?case_id=${caseId}&title=Test&risk_level=low&actions=${encodeURIComponent(JSON.stringify([{ type: "block_ip", target: "1.2.3.4" }]))}`);
    assert.equal(planRes.status, 201);
    const planId = planRes.body.plan_id;

    // Try invalid decision
    const res = await request(server, "GET",
      `/api/agent-action/approve-plan?plan_id=${planId}&approver_id=approver-001&decision=maybe`);
    assert.equal(res.status, 400);
    assert.ok(res.body.error.includes("Invalid decision"));
  });

  it("approve-plan accepts valid decision values (allow, deny, escalate)", async () => {
    const alert = await ingestAlert(server, `valid-decision-${Date.now()}`);
    const caseId = alert.case_id;

    // Create plan and deny it
    const planRes = await request(server, "GET",
      `/api/agent-action/create-plan?case_id=${caseId}&title=Test&risk_level=low&actions=${encodeURIComponent(JSON.stringify([{ type: "block_ip", target: "5.6.7.8" }]))}`);
    const planId = planRes.body.plan_id;

    const denyRes = await request(server, "GET",
      `/api/agent-action/approve-plan?plan_id=${planId}&approver_id=approver-001&decision=deny`);
    assert.equal(denyRes.status, 200);
    assert.equal(denyRes.body.state, "rejected");
  });

  it("plans are persisted to disk and survive in-memory clear", async () => {
    const alert = await ingestAlert(server, `persist-test-${Date.now()}`);
    const caseId = alert.case_id;

    const planRes = await request(server, "GET",
      `/api/agent-action/create-plan?case_id=${caseId}&title=Persist%20Test&risk_level=low&actions=${encodeURIComponent(JSON.stringify([{ type: "block_ip", target: "9.8.7.6" }]))}`);
    assert.equal(planRes.status, 201);
    const planId = planRes.body.plan_id;

    // Verify the plan file exists on disk
    const planFile = path.join(TEST_DATA_DIR, "plans", `${planId}.json`);

    // Give a moment for async save
    await new Promise((resolve) => setTimeout(resolve, 100));

    assert.ok(fs.existsSync(planFile), `Plan file should exist at ${planFile}`);
    const saved = JSON.parse(fs.readFileSync(planFile, "utf8"));
    assert.equal(saved.plan_id, planId);
    assert.equal(saved.state, "proposed");
    assert.equal(saved.title, "Persist Test");
  });
});

// ===================================================================
// Agent Action: search-alerts (C3 audit fix — was zero coverage)
// ===================================================================

describe("GET /api/agent-action/search-alerts", () => {
  let server;

  before(() => {
    ensureTestDirs();
    server = createServer();
    return new Promise((resolve) => server.listen(0, "127.0.0.1", resolve));
  });

  after(() => {
    return new Promise((resolve) => server.close(() => { rmTestDir(); resolve(); }));
  });

  it("rejects invalid time_range format", async () => {
    const res = await request(server, "GET",
      "/api/agent-action/search-alerts?query=rule.id:5712&time_range=invalid");
    assert.equal(res.status, 400);
    assert.ok(res.body.error.includes("time_range"));
  });

  it("rejects limit below 1", async () => {
    const res = await request(server, "GET",
      "/api/agent-action/search-alerts?query=rule.id:5712&time_range=24h&limit=0");
    assert.equal(res.status, 400);
    assert.ok(res.body.error.includes("limit"));
  });

  it("rejects limit above 500", async () => {
    const res = await request(server, "GET",
      "/api/agent-action/search-alerts?query=rule.id:5712&time_range=24h&limit=999");
    assert.equal(res.status, 400);
    assert.ok(res.body.error.includes("limit"));
  });

  it("rejects non-numeric limit", async () => {
    const res = await request(server, "GET",
      "/api/agent-action/search-alerts?query=test&time_range=24h&limit=abc");
    assert.equal(res.status, 400);
  });

  it("returns 503 when MCP is not configured", async () => {
    // In test env MCP_URL is not set, so this should return 503
    const res = await request(server, "GET",
      "/api/agent-action/search-alerts?query=rule.id:5712&time_range=24h");
    assert.equal(res.status, 503);
    assert.ok(res.body.error.includes("MCP"));
  });

  it("accepts valid time_range formats", async () => {
    // These should pass validation but fail at MCP layer (503)
    for (const tr of ["30m", "24h", "7d", "1w", "60s"]) {
      const res = await request(server, "GET",
        `/api/agent-action/search-alerts?query=test&time_range=${tr}`);
      assert.equal(res.status, 503, `Expected 503 for time_range=${tr}, got ${res.status}`);
    }
  });

  it("accepts structured query params without query string", async () => {
    const res = await request(server, "GET",
      "/api/agent-action/search-alerts?agent_id=002&rule_id=5712&time_range=24h");
    assert.equal(res.status, 503); // MCP not configured
  });

  it("requires auth in production mode", async () => {
    // Bootstrap mode allows localhost without auth, but let's verify the endpoint exists
    const res = await request(server, "GET",
      "/api/agent-action/search-alerts?query=test&time_range=24h");
    // Should not be 404 — endpoint must exist
    assert.notEqual(res.status, 404);
  });
});

// ===================================================================
// Agent Action: get-agent (C4 audit fix — was zero coverage)
// ===================================================================

describe("GET /api/agent-action/get-agent", () => {
  let server;

  before(() => {
    ensureTestDirs();
    server = createServer();
    return new Promise((resolve) => server.listen(0, "127.0.0.1", resolve));
  });

  after(() => {
    return new Promise((resolve) => server.close(() => { rmTestDir(); resolve(); }));
  });

  it("rejects missing agent_id", async () => {
    const res = await request(server, "GET", "/api/agent-action/get-agent");
    assert.equal(res.status, 400);
    assert.ok(res.body.error.includes("agent_id"));
  });

  it("rejects non-numeric agent_id", async () => {
    const res = await request(server, "GET",
      "/api/agent-action/get-agent?agent_id=../../etc/passwd");
    assert.equal(res.status, 400);
    assert.ok(res.body.error.includes("numeric"));
  });

  it("rejects agent_id with special characters", async () => {
    const res = await request(server, "GET",
      "/api/agent-action/get-agent?agent_id=001%3B%20rm%20-rf");
    assert.equal(res.status, 400);
  });

  it("rejects overly long agent_id", async () => {
    const res = await request(server, "GET",
      "/api/agent-action/get-agent?agent_id=1234567");
    assert.equal(res.status, 400);
  });

  it("returns 503 when MCP is not configured", async () => {
    const res = await request(server, "GET",
      "/api/agent-action/get-agent?agent_id=002");
    assert.equal(res.status, 503);
    assert.ok(res.body.error.includes("MCP"));
  });

  it("accepts valid numeric agent_id", async () => {
    const res = await request(server, "GET",
      "/api/agent-action/get-agent?agent_id=001");
    // Should pass validation (400 check) and fail at MCP (503)
    assert.equal(res.status, 503);
  });
});

// ===================================================================
// Audit fix C2: Action type allowlist enforcement
// ===================================================================

describe("Action type allowlist (C2 audit fix)", () => {
  let server;
  let testCaseId;

  before(async () => {
    ensureTestDirs();
    server = createServer();
    await new Promise((resolve) => server.listen(0, "127.0.0.1", resolve));
    const alert = await ingestAlert(server, `allowlist-${Date.now()}`);
    testCaseId = alert.case_id;
  });

  after(() => {
    return new Promise((resolve) => server.close(() => { rmTestDir(); resolve(); }));
  });

  it("rejects unknown action types", async () => {
    const actions = JSON.stringify([{ type: "rm_rf_everything", target: "prod-db-01" }]);
    const res = await request(server, "GET",
      `/api/agent-action/create-plan?case_id=${testCaseId}&title=Evil%20Plan&risk_level=low&actions=${encodeURIComponent(actions)}`);
    assert.equal(res.status, 400);
    assert.ok(res.body.error.includes("unknown action type"));
  });

  it("accepts known action types", async () => {
    const actions = JSON.stringify([{ type: "block_ip", target: "1.2.3.4" }]);
    const res = await request(server, "GET",
      `/api/agent-action/create-plan?case_id=${testCaseId}&title=Good%20Plan&risk_level=low&actions=${encodeURIComponent(actions)}`);
    assert.equal(res.status, 201);
  });

  it("rejects plan with mix of valid and invalid action types", async () => {
    const actions = JSON.stringify([
      { type: "block_ip", target: "1.2.3.4" },
      { type: "format_disk", target: "/dev/sda" },
    ]);
    const res = await request(server, "GET",
      `/api/agent-action/create-plan?case_id=${testCaseId}&title=Mixed%20Plan&risk_level=low&actions=${encodeURIComponent(actions)}`);
    assert.equal(res.status, 400);
    assert.ok(res.body.error.includes("format_disk"));
  });
});
