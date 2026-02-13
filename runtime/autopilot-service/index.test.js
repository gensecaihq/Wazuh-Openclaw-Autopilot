#!/usr/bin/env node
/**
 * Wazuh OpenClaw Autopilot - Runtime Service Tests
 */

const { describe, it, beforeEach, afterEach } = require("node:test");
const assert = require("node:assert");
const fs = require("fs").promises;
const path = require("path");
const os = require("os");

// Set test environment
process.env.AUTOPILOT_MODE = "bootstrap";
process.env.AUTOPILOT_DATA_DIR = path.join(os.tmpdir(), "autopilot-test-" + Date.now());

const {
  createCase,
  updateCase,
  getCase,
  listCases,
  generateApprovalToken,
  validateApprovalToken,
  consumeApprovalToken,
  incrementMetric,
  recordLatency,
} = require("./index.js");

describe("Evidence Pack Management", () => {
  beforeEach(async () => {
    await fs.mkdir(process.env.AUTOPILOT_DATA_DIR, { recursive: true });
    await fs.mkdir(path.join(process.env.AUTOPILOT_DATA_DIR, "cases"), { recursive: true });
  });

  afterEach(async () => {
    await fs.rm(process.env.AUTOPILOT_DATA_DIR, { recursive: true, force: true });
  });

  it("should create a case with evidence pack", async () => {
    const caseData = {
      title: "Test Brute Force Attack",
      summary: "Multiple failed login attempts detected",
      severity: "high",
      confidence: 0.85,
      entities: [
        { type: "ip", value: "192.168.1.100" },
        { type: "user", value: "admin" },
      ],
      evidence_refs: ["alert-123", "alert-124"],
    };

    const result = await createCase("CASE-TEST-001", caseData);

    assert.strictEqual(result.case_id, "CASE-TEST-001");
    assert.strictEqual(result.title, "Test Brute Force Attack");
    assert.strictEqual(result.severity, "high");
    assert.strictEqual(result.confidence, 0.85);
    assert.strictEqual(result.entities.length, 2);
    assert.strictEqual(result.schema_version, "1.0");
  });

  it("should update an existing case", async () => {
    // Create initial case
    await createCase("CASE-TEST-002", {
      title: "Initial Title",
      severity: "medium",
    });

    // Update it
    const updated = await updateCase("CASE-TEST-002", {
      title: "Updated Title",
      severity: "high",
      entities: [{ type: "host", value: "server-01" }],
    });

    assert.strictEqual(updated.title, "Updated Title");
    assert.strictEqual(updated.severity, "high");
    assert.strictEqual(updated.entities.length, 1);
  });

  it("should get a case by ID", async () => {
    await createCase("CASE-TEST-003", {
      title: "Retrievable Case",
      severity: "low",
    });

    const retrieved = await getCase("CASE-TEST-003");

    assert.strictEqual(retrieved.case_id, "CASE-TEST-003");
    assert.strictEqual(retrieved.title, "Retrievable Case");
  });

  it("should list all cases", async () => {
    await createCase("CASE-TEST-004", { title: "Case 1" });
    await createCase("CASE-TEST-005", { title: "Case 2" });

    const cases = await listCases();

    assert.strictEqual(cases.length, 2);
  });

  it("should throw error for non-existent case", async () => {
    await assert.rejects(
      async () => await getCase("CASE-NONEXISTENT"),
      /Case not found/
    );
  });
});

describe("Approval Token Management", () => {
  it("should generate a valid approval token", () => {
    const token = generateApprovalToken("PLAN-001", "CASE-001");

    assert.ok(token);
    assert.strictEqual(typeof token, "string");
    assert.strictEqual(token.length, 64); // 32 bytes hex = 64 chars
  });

  it("should validate a valid token", () => {
    const token = generateApprovalToken("PLAN-002", "CASE-002");
    const result = validateApprovalToken(token, "USER-001");

    assert.strictEqual(result.valid, true);
    assert.ok(result.tokenData);
    assert.strictEqual(result.tokenData.plan_id, "PLAN-002");
    assert.strictEqual(result.tokenData.case_id, "CASE-002");
  });

  it("should reject invalid token", () => {
    const result = validateApprovalToken("invalid-token", "USER-001");

    assert.strictEqual(result.valid, false);
    assert.strictEqual(result.reason, "INVALID_APPROVAL_TOKEN");
  });

  it("should consume token and prevent reuse", () => {
    const token = generateApprovalToken("PLAN-003", "CASE-003");

    // First consumption should succeed
    const consumed = consumeApprovalToken(token, "USER-001", "approve");
    assert.ok(consumed);
    assert.strictEqual(consumed.decision, "approve");

    // Second validation should fail (already used)
    const result = validateApprovalToken(token, "USER-001");
    assert.strictEqual(result.valid, false);
    assert.strictEqual(result.reason, "TOKEN_ALREADY_USED");
  });

  it("should record denial with reason", () => {
    const token = generateApprovalToken("PLAN-004", "CASE-004");

    const consumed = consumeApprovalToken(token, "USER-002", "deny", "Insufficient evidence");

    assert.strictEqual(consumed.decision, "deny");
    assert.strictEqual(consumed.decision_reason, "Insufficient evidence");
    assert.strictEqual(consumed.approver_id, "USER-002");
  });
});

describe("Metrics", () => {
  it("should increment simple counter", () => {
    const initialValue = 0;
    incrementMetric("cases_created_total");
    incrementMetric("cases_created_total");
    // Metrics are internal, just verify no errors
    assert.ok(true);
  });

  it("should increment labeled counter", () => {
    incrementMetric("mcp_tool_calls_total", { tool: "get_alert", status: "success" });
    incrementMetric("mcp_tool_calls_total", { tool: "get_alert", status: "error" });
    assert.ok(true);
  });

  it("should record latency", () => {
    recordLatency("triage_latency_seconds", 1.5);
    recordLatency("triage_latency_seconds", 2.0);
    recordLatency("mcp_tool_call_latency_seconds", 0.5, { tool: "search_alerts" });
    assert.ok(true);
  });
});

// Run if executed directly
if (require.main === module) {
  console.log("Running tests...");
}
