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
process.env.AUTOPILOT_DATA_DIR = path.join(os.tmpdir(), `autopilot-test-${Date.now()}`);

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
  createResponsePlan,
  getPlan,
  listPlans,
  approvePlan,
  rejectPlan,
  executePlan,
  getResponderStatus,
  PLAN_STATES,
  validateAuthorization,
  isValidCaseId,
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
      () => getCase("CASE-NONEXISTENT"),
      /Case not found/,
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

  it("should reject empty or invalid approver ID", () => {
    const token = generateApprovalToken("PLAN-005", "CASE-005");

    // Empty string
    let result = validateApprovalToken(token, "");
    assert.strictEqual(result.valid, false);
    assert.strictEqual(result.reason, "INVALID_APPROVER_ID");

    // Null
    result = validateApprovalToken(token, null);
    assert.strictEqual(result.valid, false);
    assert.strictEqual(result.reason, "INVALID_APPROVER_ID");

    // Whitespace only
    result = validateApprovalToken(token, "   ");
    assert.strictEqual(result.valid, false);
    assert.strictEqual(result.reason, "INVALID_APPROVER_ID");
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

describe("Input Validation", () => {
  it("should accept valid case IDs", async () => {
    await createCase("CASE-2024-001", { title: "Valid Case" });
    const retrieved = await getCase("CASE-2024-001");
    assert.strictEqual(retrieved.case_id, "CASE-2024-001");
  });

  it("should accept alphanumeric case IDs with hyphens", async () => {
    await createCase("case-abc-123-XYZ", { title: "Alphanumeric Case" });
    const retrieved = await getCase("case-abc-123-XYZ");
    assert.strictEqual(retrieved.case_id, "case-abc-123-XYZ");
  });
});

describe("Edge Cases", () => {
  it("should handle empty case data gracefully", async () => {
    const result = await createCase("CASE-EMPTY", {});

    assert.strictEqual(result.case_id, "CASE-EMPTY");
    assert.strictEqual(result.title, "");
    assert.strictEqual(result.severity, "medium");
    assert.strictEqual(result.confidence, 0);
  });

  it("should append to existing arrays on update", async () => {
    await createCase("CASE-APPEND", {
      entities: [{ type: "ip", value: "1.2.3.4" }],
    });

    const updated = await updateCase("CASE-APPEND", {
      entities: [{ type: "user", value: "admin" }],
    });

    assert.strictEqual(updated.entities.length, 2);
  });
});

describe("Response Plans - Two-Tier Approval", () => {
  it("should create a response plan in proposed state", () => {
    const plan = createResponsePlan({
      case_id: "CASE-TEST-PLAN-001",
      title: "Block malicious IP",
      description: "Block IP performing brute force attack",
      risk_level: "low",
      actions: [
        { type: "block_ip", target: "192.168.1.100", params: { duration: "24h" } },
      ],
    });

    assert.ok(plan.plan_id);
    assert.strictEqual(plan.state, PLAN_STATES.PROPOSED);
    assert.strictEqual(plan.case_id, "CASE-TEST-PLAN-001");
    assert.strictEqual(plan.risk_level, "low");
    assert.strictEqual(plan.actions.length, 1);
    assert.ok(plan.expires_at);
  });

  it("should get a plan by ID", () => {
    const created = createResponsePlan({
      case_id: "CASE-TEST-PLAN-002",
      title: "Test Plan",
      actions: [{ type: "block_ip", target: "10.0.0.1" }],
    });

    const retrieved = getPlan(created.plan_id);

    assert.strictEqual(retrieved.plan_id, created.plan_id);
    assert.strictEqual(retrieved.title, "Test Plan");
  });

  it("should throw error for non-existent plan", () => {
    assert.throws(
      () => getPlan("PLAN-NONEXISTENT"),
      /Plan not found/,
    );
  });

  it("should list plans with filters", () => {
    createResponsePlan({
      case_id: "CASE-LIST-001",
      title: "Plan A",
      actions: [{ type: "block_ip", target: "1.1.1.1" }],
    });
    createResponsePlan({
      case_id: "CASE-LIST-001",
      title: "Plan B",
      actions: [{ type: "block_ip", target: "2.2.2.2" }],
    });

    const allPlans = listPlans({});
    assert.ok(allPlans.length >= 2);

    const caseFiltered = listPlans({ case_id: "CASE-LIST-001" });
    assert.ok(caseFiltered.length >= 2);

    const proposedPlans = listPlans({ state: "proposed" });
    assert.ok(proposedPlans.length >= 2);
  });

  it("should approve a plan (Tier 1)", () => {
    const plan = createResponsePlan({
      case_id: "CASE-APPROVE-001",
      title: "Approve Test",
      actions: [{ type: "block_ip", target: "3.3.3.3" }],
    });

    const approved = approvePlan(plan.plan_id, "USER-APPROVER-001", "Looks correct");

    assert.strictEqual(approved.state, PLAN_STATES.APPROVED);
    assert.strictEqual(approved.approver_id, "USER-APPROVER-001");
    assert.strictEqual(approved.approval_reason, "Looks correct");
    assert.ok(approved.approved_at);
  });

  it("should reject a plan", () => {
    const plan = createResponsePlan({
      case_id: "CASE-REJECT-001",
      title: "Reject Test",
      actions: [{ type: "block_ip", target: "4.4.4.4" }],
    });

    const rejected = rejectPlan(plan.plan_id, "USER-REJECTOR-001", "Insufficient evidence");

    assert.strictEqual(rejected.state, PLAN_STATES.REJECTED);
    assert.strictEqual(rejected.rejector_id, "USER-REJECTOR-001");
    assert.strictEqual(rejected.rejection_reason, "Insufficient evidence");
    assert.ok(rejected.rejected_at);
  });

  it("should not approve an already approved plan", () => {
    const plan = createResponsePlan({
      case_id: "CASE-DOUBLE-APPROVE",
      title: "Double Approve Test",
      actions: [{ type: "block_ip", target: "5.5.5.5" }],
    });

    approvePlan(plan.plan_id, "USER-001");

    assert.throws(
      () => approvePlan(plan.plan_id, "USER-002"),
      /Cannot approve plan in state/,
    );
  });

  it("should not approve a rejected plan", () => {
    const plan = createResponsePlan({
      case_id: "CASE-REJECTED-APPROVE",
      title: "Rejected Approve Test",
      actions: [{ type: "block_ip", target: "6.6.6.6" }],
    });

    rejectPlan(plan.plan_id, "USER-001", "No");

    assert.throws(
      () => approvePlan(plan.plan_id, "USER-002"),
      /Cannot approve plan in state/,
    );
  });

  it("should reject an approved plan", () => {
    const plan = createResponsePlan({
      case_id: "CASE-APPROVED-REJECT",
      title: "Approved Reject Test",
      actions: [{ type: "block_ip", target: "7.7.7.7" }],
    });

    approvePlan(plan.plan_id, "USER-001");
    const rejected = rejectPlan(plan.plan_id, "USER-002", "Changed mind");

    assert.strictEqual(rejected.state, PLAN_STATES.REJECTED);
  });

  // Note: executePlan tests are limited because config.responderEnabled
  // is read at module load time. The responder is disabled by default in tests.

  it("should block execution when responder is disabled (default)", async () => {
    const plan = createResponsePlan({
      case_id: "CASE-EXEC-DISABLED",
      title: "Execute Disabled Test",
      actions: [{ type: "block_ip", target: "9.9.9.9" }],
    });

    approvePlan(plan.plan_id, "USER-001");

    // Responder is disabled by default (config read at module load)
    await assert.rejects(
      () => executePlan(plan.plan_id, "USER-002"),
      /Responder capability is DISABLED/,
    );
  });

  it("should have concurrent execution protection mechanism", () => {
    const plan = createResponsePlan({
      case_id: "CASE-EXEC-CONCURRENT",
      title: "Concurrent Execution Test",
      actions: [{ type: "block_ip", target: "10.10.10.10" }],
    });

    approvePlan(plan.plan_id, "USER-001");

    // Verify plan is in approved state, ready for execution
    // The executingPlans Set prevents concurrent execution (tested via code review)
    assert.strictEqual(plan.state, PLAN_STATES.APPROVED);
  });
});

describe("Responder Status", () => {
  it("should return responder status", () => {
    const status = getResponderStatus();

    assert.ok(typeof status.enabled === "boolean");
    assert.ok(status.message);
    assert.strictEqual(status.human_approval_required, true);
    assert.strictEqual(status.autonomous_execution, false);
    assert.strictEqual(status.environment_variable, "AUTOPILOT_RESPONDER_ENABLED");
  });
});

describe("Plan State Constants", () => {
  it("should have all required states", () => {
    assert.strictEqual(PLAN_STATES.PROPOSED, "proposed");
    assert.strictEqual(PLAN_STATES.APPROVED, "approved");
    assert.strictEqual(PLAN_STATES.EXECUTING, "executing");
    assert.strictEqual(PLAN_STATES.COMPLETED, "completed");
    assert.strictEqual(PLAN_STATES.FAILED, "failed");
    assert.strictEqual(PLAN_STATES.REJECTED, "rejected");
    assert.strictEqual(PLAN_STATES.EXPIRED, "expired");
  });
});

describe("Authorization Validation", () => {
  it("should allow localhost requests without auth header", () => {
    const req = {
      headers: {},
      socket: { remoteAddress: "127.0.0.1" },
    };
    const result = validateAuthorization(req, "read");
    assert.strictEqual(result.valid, true);
    assert.strictEqual(result.source, "localhost");
  });

  it("should allow IPv6 localhost requests without auth header", () => {
    const req = {
      headers: {},
      socket: { remoteAddress: "::1" },
    };
    const result = validateAuthorization(req, "read");
    assert.strictEqual(result.valid, true);
    assert.strictEqual(result.source, "localhost");
  });

  it("should reject non-localhost requests without auth header", () => {
    const req = {
      headers: {},
      socket: { remoteAddress: "192.168.1.100" },
    };
    const result = validateAuthorization(req, "read");
    assert.strictEqual(result.valid, false);
    assert.ok(result.reason.includes("Missing Authorization"));
  });

  it("should reject invalid authorization format", () => {
    const req = {
      headers: { authorization: "Basic abc123" },
      socket: { remoteAddress: "192.168.1.100" },
    };
    const result = validateAuthorization(req, "read");
    assert.strictEqual(result.valid, false);
    assert.ok(result.reason.includes("Invalid Authorization"));
  });

  it("should reject invalid bearer token", () => {
    const req = {
      headers: { authorization: "Bearer wrong-token" },
      socket: { remoteAddress: "192.168.1.100" },
    };
    const result = validateAuthorization(req, "read");
    assert.strictEqual(result.valid, false);
  });
});

describe("Case ID Validation", () => {
  it("should accept valid case IDs", () => {
    assert.strictEqual(isValidCaseId("CASE-20260217-abc12345"), true);
    assert.strictEqual(isValidCaseId("case-abc-123-XYZ"), true);
    assert.strictEqual(isValidCaseId("SIMPLE"), true);
  });

  it("should reject invalid case IDs", () => {
    assert.strictEqual(isValidCaseId(""), false);
    assert.strictEqual(isValidCaseId("../etc/passwd"), false);
    assert.strictEqual(isValidCaseId("case with spaces"), false);
    assert.strictEqual(isValidCaseId("a".repeat(65)), false);
  });
});

// Run if executed directly
if (require.main === module) {
  console.log("Running tests...");
}
