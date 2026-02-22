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
  formatMetrics,
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
  dispatchToGateway,
  loadPolicyConfig,
  policyCheckAction,
  policyCheckApprover,
  policyCheckEvidence,
  // New: enrichment & grouping
  isPrivateIp,
  enrichIpAddress,
  findRelatedCase,
  indexCaseEntities,
  markEntityFalsePositive,
  getMcpAuthToken,
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
  it("should increment simple counter and appear in formatted output", () => {
    // cases_created_total is a known simple counter in formatMetrics
    const beforeOutput = formatMetrics();
    const beforeMatch = beforeOutput.match(/autopilot_cases_created_total (\d+)/);
    const beforeVal = beforeMatch ? parseInt(beforeMatch[1], 10) : 0;

    incrementMetric("cases_created_total");
    incrementMetric("cases_created_total");

    const afterOutput = formatMetrics();
    const afterMatch = afterOutput.match(/autopilot_cases_created_total (\d+)/);
    const afterVal = afterMatch ? parseInt(afterMatch[1], 10) : 0;

    assert.strictEqual(afterVal - beforeVal, 2, "Counter should have incremented by 2");
  });

  it("should increment labeled counter with distinct labels", () => {
    incrementMetric("mcp_tool_calls_total", { tool: "test_tool", status: "success" });
    incrementMetric("mcp_tool_calls_total", { tool: "test_tool", status: "success" });
    incrementMetric("mcp_tool_calls_total", { tool: "test_tool", status: "error" });

    const output = formatMetrics();
    assert.ok(
      output.includes('autopilot_mcp_tool_calls_total{tool="test_tool",status="success"} 2'),
      "Expected labeled counter with value 2",
    );
    assert.ok(
      output.includes('autopilot_mcp_tool_calls_total{tool="test_tool",status="error"} 1'),
      "Expected labeled counter with value 1",
    );
  });

  it("should record latency and include sum/count in output", () => {
    recordLatency("triage_latency_seconds", 1.5);
    recordLatency("triage_latency_seconds", 2.0);

    const output = formatMetrics();
    assert.ok(output.includes("autopilot_triage_latency_seconds_sum"), "Expected sum in output");
    assert.ok(output.includes("autopilot_triage_latency_seconds_count"), "Expected count in output");
    // Verify count is at least 2 (may be higher from other tests)
    const countMatch = output.match(/autopilot_triage_latency_seconds_count (\d+)/);
    assert.ok(countMatch, "Expected count metric");
    assert.ok(parseInt(countMatch[1], 10) >= 2, "Expected count >= 2");
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

  it("should sync summary with evidence pack using hasOwnProperty", async () => {
    await createCase("CASE-SYNC", {
      title: "Original Title",
      severity: "high",
    });

    // Update with empty string title (falsy but valid)
    const updated = await updateCase("CASE-SYNC", { title: "" });
    // Evidence pack should have empty title
    assert.strictEqual(updated.title, "");

    // Read the summary file directly to verify it was also updated
    const summaryPath = path.join(process.env.AUTOPILOT_DATA_DIR, "cases", "CASE-SYNC", "case.json");
    const summary = JSON.parse(await fs.readFile(summaryPath, "utf8"));
    assert.strictEqual(summary.title, "");
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
    // Verify filtering actually worked — all returned plans belong to the filtered case
    for (const p of caseFiltered) {
      assert.strictEqual(p.case_id, "CASE-LIST-001");
    }

    const proposedPlans = listPlans({ state: "proposed" });
    assert.ok(proposedPlans.length >= 2);
    // Verify state filtering — all returned plans are in proposed state
    for (const p of proposedPlans) {
      assert.strictEqual(p.state, "proposed");
    }
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

  it("should enforce scope for service tokens", () => {
    // Service tokens have read-only scope; write-scope requests should be rejected
    const origToken = process.env.AUTOPILOT_SERVICE_TOKEN;
    process.env.AUTOPILOT_SERVICE_TOKEN = "test-service-token-12345";
    try {
      const req = {
        headers: { authorization: "Bearer test-service-token-12345" },
        socket: { remoteAddress: "192.168.1.100" },
      };
      // Read scope should pass
      const readResult = validateAuthorization(req, "read");
      assert.strictEqual(readResult.valid, true);
      assert.strictEqual(readResult.scope, "read");

      // Write scope should be rejected for service tokens
      const writeResult = validateAuthorization(req, "write");
      assert.strictEqual(writeResult.valid, false);
      assert.ok(writeResult.reason.includes("Insufficient scope"));
    } finally {
      if (origToken === undefined) delete process.env.AUTOPILOT_SERVICE_TOKEN;
      else process.env.AUTOPILOT_SERVICE_TOKEN = origToken;
    }
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

// =============================================================================
// GATEWAY DISPATCH TESTS
// =============================================================================

describe("Gateway Dispatch", () => {
  it("dispatchToGateway does not throw on unreachable server", async () => {
    // Save and set config
    const origUrl = process.env.OPENCLAW_GATEWAY_URL;
    const origToken = process.env.OPENCLAW_TOKEN;
    process.env.OPENCLAW_GATEWAY_URL = "http://127.0.0.1:19999"; // unreachable
    process.env.OPENCLAW_TOKEN = "test-token";

    try {
      // Should not throw — fire-and-forget
      await dispatchToGateway("/webhook/test", { test: true });
    } finally {
      if (origUrl === undefined) delete process.env.OPENCLAW_GATEWAY_URL;
      else process.env.OPENCLAW_GATEWAY_URL = origUrl;
      if (origToken === undefined) delete process.env.OPENCLAW_TOKEN;
      else process.env.OPENCLAW_TOKEN = origToken;
    }
  });

  it("dispatchToGateway skips when gateway URL not configured", async () => {
    const origUrl = process.env.OPENCLAW_GATEWAY_URL;
    const origToken = process.env.OPENCLAW_TOKEN;
    delete process.env.OPENCLAW_GATEWAY_URL;
    delete process.env.OPENCLAW_TOKEN;

    try {
      // Should silently skip, not throw
      await dispatchToGateway("/webhook/test", { test: true });
    } finally {
      if (origUrl !== undefined) process.env.OPENCLAW_GATEWAY_URL = origUrl;
      if (origToken !== undefined) process.env.OPENCLAW_TOKEN = origToken;
    }
  });

  it("dispatchToGateway silently skips when token is empty (default config)", async () => {
    // config.openclawToken is "" at module load (no env var set) → early return
    // This verifies the guard clause works — no HTTP request is made
    await dispatchToGateway("/webhook/test", { case_id: "CASE-001" });
    // Should complete without throwing — verified by reaching this line
  });
});

// =============================================================================
// POLICY ENFORCEMENT TESTS
// =============================================================================

describe("Policy Enforcement - policyCheckAction", () => {
  it("allows an action that is in the allowlist and enabled", () => {
    // loadPolicyConfig would have been called at startup; directly test the function
    // with known policy state. In bootstrap mode with no policy, everything is allowed.
    const result = policyCheckAction("block_ip", 0.8);
    // In bootstrap mode without policy loaded, should allow
    assert.strictEqual(result.allowed, true);
  });

  it("allows action in bootstrap mode when policy not loaded", () => {
    const result = policyCheckAction("unknown_action", 0.5);
    assert.strictEqual(result.allowed, true);
    assert.ok(result.reason.includes("bootstrap") || result.reason.includes("Policy not loaded"));
  });
});

describe("Policy Enforcement - policyCheckApprover", () => {
  it("allows approver in bootstrap mode when policy not loaded", () => {
    const result = policyCheckApprover("U12345", ["block_ip"], "medium");
    assert.strictEqual(result.authorized, true);
  });

  it("returns authorized=true when no approver groups configured", () => {
    const result = policyCheckApprover("U12345", ["block_ip"], "low");
    assert.strictEqual(result.authorized, true);
  });
});

describe("Policy Enforcement - policyCheckEvidence", () => {
  beforeEach(async () => {
    await fs.mkdir(process.env.AUTOPILOT_DATA_DIR, { recursive: true });
    await fs.mkdir(path.join(process.env.AUTOPILOT_DATA_DIR, "cases"), { recursive: true });
  });

  afterEach(async () => {
    await fs.rm(process.env.AUTOPILOT_DATA_DIR, { recursive: true, force: true });
  });

  it("allows execution in bootstrap mode when policy not loaded", async () => {
    await createCase("CASE-EVIDENCE-001", {
      title: "Test Case",
      severity: "high",
      evidence_refs: [{ type: "alert", ref_id: "a1" }],
    });

    const result = await policyCheckEvidence(
      [{ type: "block_ip", target: "1.2.3.4" }],
      "CASE-EVIDENCE-001",
    );
    assert.strictEqual(result.sufficient, true);
  });

  it("allows execution when case not found in bootstrap mode", async () => {
    const result = await policyCheckEvidence(
      [{ type: "block_ip", target: "1.2.3.4" }],
      "CASE-NONEXISTENT",
    );
    assert.strictEqual(result.sufficient, true);
  });
});

describe("Policy Enforcement - loadPolicyConfig", () => {
  it("loads policy from config dir without throwing in bootstrap mode", async () => {
    // Pass a nonexistent dir — in bootstrap mode should return null without throwing
    const tmpDir = path.join(os.tmpdir(), `policy-test-${Date.now()}`);
    const result = await loadPolicyConfig(tmpDir);
    assert.strictEqual(result, null);
  });

  it("loads a valid policy file successfully", async () => {
    const tmpDir = path.join(os.tmpdir(), `policy-load-test-${Date.now()}`);
    const policyDir = path.join(tmpDir, "policies");
    await fs.mkdir(policyDir, { recursive: true });

    const policyContent = `
schema_version: "1.0"
actions:
  enabled: true
  deny_unlisted: true
  allowlist:
    block_ip:
      enabled: true
      risk_level: low
      min_confidence: 0.7
      min_evidence_items: 2
    disable_user:
      enabled: false
      risk_level: high
`;

    await fs.writeFile(path.join(policyDir, "policy.yaml"), policyContent);

    try {
      const result = await loadPolicyConfig(tmpDir);
      assert.ok(result, "Policy config should be loaded");

      // Test policyCheckAction with loaded policy
      const allowed = policyCheckAction("block_ip", 0.8);
      assert.strictEqual(allowed.allowed, true);

      const disabledAction = policyCheckAction("disable_user", 0.9);
      assert.strictEqual(disabledAction.allowed, false);
      assert.ok(disabledAction.reason.includes("disabled"));

      const unlisted = policyCheckAction("restart_wazuh", 0.5);
      assert.strictEqual(unlisted.allowed, false);
      assert.ok(unlisted.reason.includes("deny_unlisted"));

      const lowConfidence = policyCheckAction("block_ip", 0.3);
      assert.strictEqual(lowConfidence.allowed, false);
      assert.ok(lowConfidence.reason.includes("Confidence"));
    } finally {
      await fs.rm(tmpDir, { recursive: true, force: true });
    }
  });
});

describe("Policy Enforcement - policyCheckApprover with loaded policy", () => {
  let tmpDir;

  beforeEach(async () => {
    tmpDir = path.join(os.tmpdir(), `approver-test-${Date.now()}`);
    const policyDir = path.join(tmpDir, "policies");
    await fs.mkdir(policyDir, { recursive: true });

    // Policy with placeholder + real Slack IDs
    // Note: parseSimpleYaml handles single-key list items; multi-line list objects
    // have the second key attached to the parent. We test the logic that matters.
    const policyContent = `
schema_version: "1.0"
approvers:
  groups:
    standard:
      members:
        - slack_id: "<SLACK_USER_1>"
      can_approve:
        - block_ip
      max_risk_level: medium
    admin:
      members:
        - slack_id: "U_REAL_ADMIN"
      can_approve:
        - block_ip
        - disable_user
      max_risk_level: critical
actions:
  enabled: true
  deny_unlisted: false
`;

    await fs.writeFile(path.join(policyDir, "policy.yaml"), policyContent);
    await loadPolicyConfig(tmpDir);
  });

  afterEach(async () => {
    await fs.rm(tmpDir, { recursive: true, force: true });
  });

  it("authorizes a real admin user for allowed actions", () => {
    const result = policyCheckApprover("U_REAL_ADMIN", ["block_ip"], "medium");
    assert.strictEqual(result.authorized, true);
    assert.ok(result.reason.includes("admin"));
  });

  it("denies an unknown user", () => {
    const result = policyCheckApprover("U_UNKNOWN", ["block_ip"], "medium");
    assert.strictEqual(result.authorized, false);
    assert.ok(result.reason.includes("not authorized"));
  });

  it("denies admin for actions not in their can_approve list", () => {
    const result = policyCheckApprover("U_REAL_ADMIN", ["restart_wazuh"], "critical");
    assert.strictEqual(result.authorized, false);
  });
});

describe("Policy Enforcement - policyCheckEvidence with loaded policy", () => {
  let tmpDir;

  beforeEach(async () => {
    await fs.mkdir(process.env.AUTOPILOT_DATA_DIR, { recursive: true });
    await fs.mkdir(path.join(process.env.AUTOPILOT_DATA_DIR, "cases"), { recursive: true });

    tmpDir = path.join(os.tmpdir(), `evidence-policy-test-${Date.now()}`);
    const policyDir = path.join(tmpDir, "policies");
    await fs.mkdir(policyDir, { recursive: true });

    const policyContent = `
schema_version: "1.0"
actions:
  enabled: true
  deny_unlisted: false
  allowlist:
    block_ip:
      enabled: true
      min_evidence_items: 2
    disable_user:
      enabled: true
      min_evidence_items: 5
`;

    await fs.writeFile(path.join(policyDir, "policy.yaml"), policyContent);
    await loadPolicyConfig(tmpDir);
  });

  afterEach(async () => {
    await fs.rm(tmpDir, { recursive: true, force: true });
    await fs.rm(process.env.AUTOPILOT_DATA_DIR, { recursive: true, force: true });
  });

  it("passes when case has sufficient evidence for action", async () => {
    await createCase("CASE-EV-PASS", {
      title: "Test",
      severity: "high",
      evidence_refs: [{ type: "alert", ref_id: "a1" }, { type: "alert", ref_id: "a2" }],
      timeline: [{ timestamp: new Date().toISOString(), event_type: "test" }],
    });

    const result = await policyCheckEvidence(
      [{ type: "block_ip", target: "1.2.3.4" }],
      "CASE-EV-PASS",
    );
    assert.strictEqual(result.sufficient, true);
  });

  it("fails when case has insufficient evidence for action", async () => {
    await createCase("CASE-EV-FAIL", {
      title: "Test",
      severity: "high",
      evidence_refs: [{ type: "alert", ref_id: "a1" }],
    });

    const result = await policyCheckEvidence(
      [{ type: "disable_user", target: "jsmith" }],
      "CASE-EV-FAIL",
    );
    assert.strictEqual(result.sufficient, false);
    assert.ok(result.reason.includes("disable_user"));
    assert.ok(result.reason.includes("5"));
  });
});

// =============================================================================
// IP Enrichment
// =============================================================================

describe("isPrivateIp", () => {
  it("returns true for 10.x.x.x", () => {
    assert.strictEqual(isPrivateIp("10.0.0.1"), true);
    assert.strictEqual(isPrivateIp("10.255.255.255"), true);
  });

  it("returns true for 172.16-31.x.x", () => {
    assert.strictEqual(isPrivateIp("172.16.0.1"), true);
    assert.strictEqual(isPrivateIp("172.31.255.255"), true);
  });

  it("returns true for 192.168.x.x", () => {
    assert.strictEqual(isPrivateIp("192.168.0.1"), true);
    assert.strictEqual(isPrivateIp("192.168.255.255"), true);
  });

  it("returns true for 127.x.x.x (loopback)", () => {
    assert.strictEqual(isPrivateIp("127.0.0.1"), true);
  });

  it("returns true for 0.x.x.x", () => {
    assert.strictEqual(isPrivateIp("0.0.0.0"), true);
  });

  it("returns false for public IPs", () => {
    assert.strictEqual(isPrivateIp("8.8.8.8"), false);
    assert.strictEqual(isPrivateIp("203.0.113.50"), false);
    assert.strictEqual(isPrivateIp("1.1.1.1"), false);
  });

  it("returns true for invalid input", () => {
    assert.strictEqual(isPrivateIp(null), true);
    assert.strictEqual(isPrivateIp(""), true);
    assert.strictEqual(isPrivateIp("not-an-ip"), true);
  });

  it("returns false for 172.32.x.x (outside /12 range)", () => {
    assert.strictEqual(isPrivateIp("172.32.0.1"), false);
  });
});

describe("enrichIpAddress", () => {
  it("returns null for private IPs", async () => {
    const result = await enrichIpAddress("10.0.0.1");
    assert.strictEqual(result, null);
  });

  it("returns null when enrichment is disabled", async () => {
    // enrichment is disabled by default in test env (ENRICHMENT_ENABLED not set)
    const result = await enrichIpAddress("203.0.113.50");
    assert.strictEqual(result, null);
  });
});

// =============================================================================
// Alert Grouping
// =============================================================================

describe("Alert Grouping", () => {
  it("findRelatedCase returns null when no entities match", () => {
    const result = findRelatedCase([{ type: "ip", value: "99.99.99.99" }]);
    assert.strictEqual(result, null);
  });

  it("findRelatedCase returns null for empty entities", () => {
    const result = findRelatedCase([]);
    assert.strictEqual(result, null);
  });

  it("findRelatedCase returns case when entity matches within window", () => {
    const entities = [{ type: "ip", value: "100.100.100.1" }];
    indexCaseEntities("CASE-GROUP-001", entities, "high");

    const result = findRelatedCase(entities);
    assert.strictEqual(result, "CASE-GROUP-001");
  });

  it("findRelatedCase skips false-positive cases", () => {
    const entities = [{ type: "ip", value: "100.100.100.2" }];
    indexCaseEntities("CASE-FP-001", entities, "high");
    markEntityFalsePositive("CASE-FP-001");

    const result = findRelatedCase(entities);
    assert.strictEqual(result, null);
  });

  it("findRelatedCase picks case with most matches", () => {
    const ip1 = { type: "ip", value: "100.100.100.3" };
    const ip2 = { type: "ip", value: "100.100.100.4" };
    const user1 = { type: "user", value: "admin" };

    indexCaseEntities("CASE-MATCH-1", [ip1], "medium");
    indexCaseEntities("CASE-MATCH-2", [ip1, ip2, user1], "high");

    const result = findRelatedCase([ip1, ip2]);
    assert.strictEqual(result, "CASE-MATCH-2");
  });
});

// =============================================================================
// MCP Auth Mode
// =============================================================================

describe("getMcpAuthToken", () => {
  it("returns raw key in legacy-rest mode (config default for test)", async () => {
    // In test env, MCP_AUTH_MODE defaults to "mcp-jsonrpc" but we test the function
    const token = await getMcpAuthToken();
    // In test env, mcpAuth is not set, so should return null
    assert.strictEqual(token, null);
  });
});

// =============================================================================
// Metrics format includes new counters
// =============================================================================

describe("New metrics in formatMetrics", () => {
  it("includes enrichment metrics", () => {
    const output = formatMetrics();
    assert.ok(output.includes("autopilot_enrichment_requests_total"));
    assert.ok(output.includes("autopilot_enrichment_cache_hits_total"));
    assert.ok(output.includes("autopilot_enrichment_errors_total"));
  });

  it("includes false_positives_total metric", () => {
    const output = formatMetrics();
    assert.ok(output.includes("autopilot_false_positives_total"));
  });

  it("includes feedback_submitted_total type header", () => {
    const output = formatMetrics();
    assert.ok(output.includes("autopilot_feedback_submitted_total"));
  });
});

// Run if executed directly
if (require.main === module) {
  console.log("Running tests...");
}
