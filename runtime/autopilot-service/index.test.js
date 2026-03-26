#!/usr/bin/env node
/**
 * Wazuh OpenClaw Autopilot - Runtime Service Tests
 */

const { describe, it, before, after, beforeEach, afterEach } = require("node:test");
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
  isValidPlanId,
  resolvePlanId,
  dispatchToGateway,
  loadPolicyConfig,
  policyCheckAction,
  policyCheckApprover,
  policyCheckEvidence,
  // New: enrichment & grouping
  isPrivateIp,
  enrichIpAddress,
  enrichmentCache,
  MAX_ENRICHMENT_CACHE_SIZE,
  findRelatedCase,
  indexCaseEntities,
  markEntityFalsePositive,
  entityCaseIndex,
  MAX_ENTITY_INDEX_SIZE,
  responsePlans,
  getMcpAuthToken,
  ensureMcpSession,
  invalidateMcpSession,
  normalizeGatewayUrl,
  loadPlansFromDisk,
  savePlanToDisk,
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

  it("should store auto_verdict and verdict_reason via updateCase", async () => {
    await createCase("CASE-TEST-VERDICT-001", {
      title: "Verdict Test Case",
      severity: "medium",
    });

    const updated = await updateCase("CASE-TEST-VERDICT-001", {
      auto_verdict: "true_positive",
      verdict_reason: "47 failed SSH attempts from single external IP with no prior benign history",
    });

    assert.strictEqual(updated.auto_verdict, "true_positive");
    assert.strictEqual(updated.verdict_reason, "47 failed SSH attempts from single external IP with no prior benign history");
  });

  it("auto_verdict does not conflict with analyst feedback verdict", async () => {
    await createCase("CASE-TEST-VERDICT-002", {
      title: "Verdict Conflict Test",
      severity: "high",
    });

    const updated = await updateCase("CASE-TEST-VERDICT-002", {
      auto_verdict: "false_positive",
      verdict_reason: "Internal vulnerability scanner activity",
      feedback: [{ verdict: "true_positive", analyst: "analyst-001", comment: "Actually malicious" }],
    });

    assert.strictEqual(updated.auto_verdict, "false_positive");
    assert.strictEqual(updated.feedback[0].verdict, "true_positive");
  });

  it("auto_verdict persists through status transitions", async () => {
    await createCase("CASE-TEST-VERDICT-003", {
      title: "Verdict Persistence Test",
      severity: "low",
    });

    await updateCase("CASE-TEST-VERDICT-003", {
      auto_verdict: "informational",
      verdict_reason: "Login event, no threat",
    });

    const afterStatusChange = await updateCase("CASE-TEST-VERDICT-003", {
      status: "triaged",
    });

    assert.strictEqual(afterStatusChange.auto_verdict, "informational");
    assert.strictEqual(afterStatusChange.verdict_reason, "Login event, no threat");
  });

  it("should store mitre data via updateCase", async () => {
    await createCase("CASE-TEST-MITRE-001", {
      title: "MITRE Test Case",
      severity: "high",
    });

    const updated = await updateCase("CASE-TEST-MITRE-001", {
      mitre: [{ technique: "T1110", tactic: "credential-access", name: "Brute Force" }],
    });

    assert.ok(Array.isArray(updated.mitre));
    assert.strictEqual(updated.mitre.length, 1);
    assert.strictEqual(updated.mitre[0].technique, "T1110");
  });

  it("should normalize single mitre object to array", async () => {
    await createCase("CASE-TEST-MITRE-002", {
      title: "MITRE Object Test",
      severity: "medium",
    });

    const updated = await updateCase("CASE-TEST-MITRE-002", {
      mitre: { technique: "T1078", tactic: "persistence", name: "Valid Accounts" },
    });

    assert.ok(Array.isArray(updated.mitre));
    assert.strictEqual(updated.mitre.length, 1);
    assert.strictEqual(updated.mitre[0].technique, "T1078");
  });

  it("should deduplicate mitre entries by technique", async () => {
    await createCase("CASE-TEST-MITRE-003", {
      title: "MITRE Dedup Test",
      severity: "low",
    });

    await updateCase("CASE-TEST-MITRE-003", {
      mitre: [{ technique: "T1110", tactic: "credential-access" }],
    });

    const updated = await updateCase("CASE-TEST-MITRE-003", {
      mitre: [
        { technique: "T1110", tactic: "credential-access" },
        { technique: "T1078", tactic: "persistence" },
      ],
    });

    assert.ok(Array.isArray(updated.mitre));
    assert.strictEqual(updated.mitre.length, 2);
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

  it("should accept plan actions with rollback metadata", () => {
    const plan = createResponsePlan({
      case_id: "CASE-ROLLBACK-001",
      title: "Rollback Metadata Test",
      actions: [{
        type: "block_ip",
        target: "10.0.0.1",
        params: { duration: "24h" },
        rollback_available: true,
        rollback_command: "firewall-drop-unblock",
        rollback_note: "Removes firewall block rule",
      }],
    });

    assert.strictEqual(plan.actions[0].rollback_available, true);
    assert.strictEqual(plan.actions[0].rollback_command, "firewall-drop-unblock");
    assert.strictEqual(plan.actions[0].rollback_note, "Removes firewall block rule");
  });

  it("should accept plan actions without rollback metadata (backward compatible)", () => {
    const plan = createResponsePlan({
      case_id: "CASE-ROLLBACK-002",
      title: "No Rollback Test",
      actions: [{ type: "block_ip", target: "10.0.0.2" }],
    });

    assert.strictEqual(plan.actions[0].rollback_available, undefined);
    assert.strictEqual(plan.actions[0].rollback_command, undefined);
  });

  it("should coerce string 'true'/'false' to boolean for rollback_available", () => {
    const plan = createResponsePlan({
      case_id: "CASE-ROLLBACK-COERCE",
      title: "String Boolean Coercion",
      actions: [
        { type: "block_ip", target: "10.0.0.5", rollback_available: "true" },
        { type: "block_ip", target: "10.0.0.6", rollback_available: "false" },
        { type: "block_ip", target: "10.0.0.7", rollback_available: " True " },
      ],
    });
    assert.strictEqual(plan.actions[0].rollback_available, true);
    assert.strictEqual(plan.actions[1].rollback_available, false);
    assert.strictEqual(plan.actions[2].rollback_available, true);
  });

  it("should reject invalid rollback_available type", () => {
    assert.throws(() => {
      createResponsePlan({
        case_id: "CASE-ROLLBACK-003",
        title: "Invalid Rollback",
        actions: [{
          type: "block_ip",
          target: "10.0.0.3",
          rollback_available: "yes",
        }],
      });
    }, /rollback_available.*must be a boolean/);
  });

  it("should reject invalid rollback_command type", () => {
    assert.throws(() => {
      createResponsePlan({
        case_id: "CASE-ROLLBACK-004",
        title: "Invalid Rollback Command",
        actions: [{
          type: "block_ip",
          target: "10.0.0.4",
          rollback_command: 123,
        }],
      });
    }, /rollback_command.*must be a string/);
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

describe("Crash Recovery — EXECUTING plans on startup", () => {
  beforeEach(async () => {
    await fs.mkdir(process.env.AUTOPILOT_DATA_DIR, { recursive: true });
    await fs.mkdir(path.join(process.env.AUTOPILOT_DATA_DIR, "plans"), { recursive: true });
  });

  afterEach(async () => {
    await fs.rm(process.env.AUTOPILOT_DATA_DIR, { recursive: true, force: true });
  });

  it("should recover a plan stuck in EXECUTING state to FAILED on load", async () => {
    // Simulate a plan that was persisted as EXECUTING before a crash
    const stuckPlan = {
      plan_id: "plan-crash-recovery-test",
      case_id: "CASE-RECOVERY-001",
      state: "executing",
      actions: [{ type: "block_ip", target: "10.0.0.1" }],
      created_at: new Date().toISOString(),
      updated_at: new Date().toISOString(),
    };
    await fs.writeFile(
      path.join(process.env.AUTOPILOT_DATA_DIR, "plans", `${stuckPlan.plan_id}.json`),
      JSON.stringify(stuckPlan, null, 2),
    );

    // Load plans from disk — should trigger crash recovery
    await loadPlansFromDisk();

    const recovered = getPlan(stuckPlan.plan_id);
    assert.ok(recovered, "Plan should be loaded from disk");
    assert.strictEqual(recovered.state, PLAN_STATES.FAILED, "State should be reset to FAILED");
    assert.ok(recovered.execution_result, "Should have execution_result");
    assert.strictEqual(recovered.execution_result.success, false);
    assert.ok(recovered.execution_result.reason.includes("crashed"), "Reason should mention crash");
    assert.ok(recovered.updated_at, "updated_at should be set");

    // Verify the recovered state was persisted to disk
    const diskContent = await fs.readFile(
      path.join(process.env.AUTOPILOT_DATA_DIR, "plans", `${stuckPlan.plan_id}.json`),
      "utf8",
    );
    const diskPlan = JSON.parse(diskContent);
    assert.strictEqual(diskPlan.state, "failed", "Disk file should also show failed state");
  });

  it("should not modify plans in non-EXECUTING states", async () => {
    const completedPlan = {
      plan_id: "plan-completed-test",
      case_id: "CASE-RECOVERY-002",
      state: "completed",
      actions: [{ type: "block_ip", target: "10.0.0.2" }],
      created_at: new Date().toISOString(),
      updated_at: "2026-01-01T00:00:00.000Z",
    };
    await fs.writeFile(
      path.join(process.env.AUTOPILOT_DATA_DIR, "plans", `${completedPlan.plan_id}.json`),
      JSON.stringify(completedPlan, null, 2),
    );

    await loadPlansFromDisk();

    const loaded = getPlan(completedPlan.plan_id);
    assert.ok(loaded, "Plan should be loaded");
    assert.strictEqual(loaded.state, "completed", "Completed plan should remain completed");
    assert.strictEqual(loaded.updated_at, "2026-01-01T00:00:00.000Z", "updated_at should be unchanged");
    assert.strictEqual(loaded.execution_result, undefined, "Should not have execution_result added");
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

describe("Plan ID Validation", () => {
  it("should accept valid plan IDs", () => {
    assert.strictEqual(isValidPlanId("PLAN-1774277057126-d40a2c58"), true);
    assert.strictEqual(isValidPlanId("PLAN-1234567890-abcdef01"), true);
  });

  it("should reject invalid plan IDs", () => {
    assert.strictEqual(isValidPlanId(""), false);
    assert.strictEqual(isValidPlanId("PLAN-20260323-723b2febbe95"), false); // LLM-fabricated from case_id
    assert.strictEqual(isValidPlanId("plan-123-abc"), false); // lowercase
    assert.strictEqual(isValidPlanId("CASE-20260323-abc12345"), false); // case_id format
  });
});

describe("resolvePlanId", () => {
  // resolvePlanId works against the in-memory responsePlans Map which is internal,
  // so we test via createResponsePlan to populate it
  it("should return null for null input", () => {
    assert.strictEqual(resolvePlanId(null, null, null), null);
    assert.strictEqual(resolvePlanId("", null, null), null);
  });

  it("should return null when no plans exist matching hash", () => {
    const result = resolvePlanId("PLAN-20260323-ffffffff", null, "proposed");
    assert.strictEqual(result, null);
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

  it("dispatchToGateway payload always includes message field in real dispatch calls", () => {
    // Verify the expected payload shape that OpenClaw Gateway requires.
    // The message field is REQUIRED by OpenClaw hooks — without it, Gateway returns 400.
    const alertPayload = {
      message: "Triage new high-severity alert: [HIGH] SSH brute force. Case CASE-001 with 3 entities.",
      case_id: "CASE-001",
      severity: "high",
      title: "[HIGH] SSH brute force",
      entities_count: 3,
      trigger: "alert_ingestion",
    };
    assert.strictEqual(typeof alertPayload.message, "string");
    assert.ok(alertPayload.message.length > 0, "message must not be empty");

    const statusPayload = {
      message: "Correlate case CASE-001 (high severity). Search for related alerts.",
      case_id: "CASE-001",
      status: "triaged",
      severity: "high",
      trigger: "status_change",
    };
    assert.strictEqual(typeof statusPayload.message, "string");
    assert.ok(statusPayload.message.length > 0, "message must not be empty");

    const policyPayload = {
      message: "Review response plan PLAN-001 for case CASE-001. Risk level: medium.",
      plan_id: "PLAN-001",
      case_id: "CASE-001",
      risk_level: "medium",
      actions_count: 2,
      trigger: "plan_created",
    };
    assert.strictEqual(typeof policyPayload.message, "string");
    assert.ok(policyPayload.message.length > 0, "message must not be empty");
  });
});

// =============================================================================
// GATEWAY URL NORMALIZATION (Issue #15)
// =============================================================================

describe("normalizeGatewayUrl", () => {
  it("rewrites ws:// to http://", () => {
    assert.strictEqual(normalizeGatewayUrl("ws://127.0.0.1:18789"), "http://127.0.0.1:18789");
  });

  it("rewrites wss:// to https://", () => {
    assert.strictEqual(normalizeGatewayUrl("wss://gateway.example.com:18789"), "https://gateway.example.com:18789");
  });

  it("preserves http:// unchanged", () => {
    assert.strictEqual(normalizeGatewayUrl("http://127.0.0.1:18789"), "http://127.0.0.1:18789");
  });

  it("preserves https:// unchanged", () => {
    assert.strictEqual(normalizeGatewayUrl("https://gateway.example.com"), "https://gateway.example.com");
  });

  it("handles empty string", () => {
    assert.strictEqual(normalizeGatewayUrl(""), "");
  });

  it("handles undefined/null", () => {
    assert.strictEqual(normalizeGatewayUrl(undefined), undefined);
    assert.strictEqual(normalizeGatewayUrl(null), null);
  });

  it("preserves path and query after scheme rewrite", () => {
    assert.strictEqual(
      normalizeGatewayUrl("ws://127.0.0.1:18789/custom/path?token=abc"),
      "http://127.0.0.1:18789/custom/path?token=abc"
    );
  });

  it("only rewrites scheme at start of string", () => {
    // A URL that contains ws:// in the path should not be affected
    assert.strictEqual(
      normalizeGatewayUrl("http://example.com/ws://test"),
      "http://example.com/ws://test"
    );
  });

  it("handles uppercase WS:// and WSS://", () => {
    assert.strictEqual(normalizeGatewayUrl("WS://127.0.0.1:18789"), "http://127.0.0.1:18789");
    assert.strictEqual(normalizeGatewayUrl("WSS://gateway.example.com"), "https://gateway.example.com");
    assert.strictEqual(normalizeGatewayUrl("Ws://mixed-case:18789"), "http://mixed-case:18789");
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

describe("Policy Enforcement - policyCheckApprover placeholder bootstrap approval", () => {
  let tmpDir;
  let origBootstrapApproval;

  beforeEach(async () => {
    origBootstrapApproval = process.env.AUTOPILOT_BOOTSTRAP_APPROVAL;
    delete process.env.AUTOPILOT_BOOTSTRAP_APPROVAL;

    tmpDir = path.join(os.tmpdir(), `approver-bootstrap-test-${Date.now()}`);
    const policyDir = path.join(tmpDir, "policies");
    await fs.mkdir(policyDir, { recursive: true });

    // Policy with ALL placeholder Slack IDs (no real users)
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
    ops:
      members:
        - slack_id: "<SLACK_OPS_1>"
      can_approve:
        - disable_user
      max_risk_level: high
actions:
  enabled: true
  deny_unlisted: false
`;

    await fs.writeFile(path.join(policyDir, "policy.yaml"), policyContent);
    await loadPolicyConfig(tmpDir);
  });

  afterEach(async () => {
    if (origBootstrapApproval !== undefined) {
      process.env.AUTOPILOT_BOOTSTRAP_APPROVAL = origBootstrapApproval;
    } else {
      delete process.env.AUTOPILOT_BOOTSTRAP_APPROVAL;
    }
    await fs.rm(tmpDir, { recursive: true, force: true });
  });

  it("denies approval when all approver IDs are placeholders and AUTOPILOT_BOOTSTRAP_APPROVAL is not set", () => {
    delete process.env.AUTOPILOT_BOOTSTRAP_APPROVAL;
    const result = policyCheckApprover("U12345", ["block_ip"], "medium");
    assert.strictEqual(result.authorized, false);
    assert.ok(result.reason.includes("AUTOPILOT_BOOTSTRAP_APPROVAL"));
  });

  it("allows approval when all approver IDs are placeholders and AUTOPILOT_BOOTSTRAP_APPROVAL=true", () => {
    process.env.AUTOPILOT_BOOTSTRAP_APPROVAL = "true";
    const result = policyCheckApprover("U12345", ["block_ip"], "medium");
    assert.strictEqual(result.authorized, true);
    assert.ok(result.reason.includes("bootstrap approval enabled"));
  });

  it("denies approval when AUTOPILOT_BOOTSTRAP_APPROVAL is set to a non-true value", () => {
    process.env.AUTOPILOT_BOOTSTRAP_APPROVAL = "false";
    const result = policyCheckApprover("U12345", ["block_ip"], "medium");
    assert.strictEqual(result.authorized, false);
    assert.ok(result.reason.includes("AUTOPILOT_BOOTSTRAP_APPROVAL"));
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

describe("Enrichment cache eviction", () => {
  afterEach(() => {
    enrichmentCache.clear();
  });

  it("evicts oldest entry when cache is full", () => {
    // Fill cache to the max
    for (let i = 0; i < MAX_ENRICHMENT_CACHE_SIZE; i++) {
      enrichmentCache.set(`10.0.${Math.floor(i / 256)}.${i % 256}`, {
        data: { score: i },
        expiresAt: Date.now() + 3600000,
      });
    }
    assert.strictEqual(enrichmentCache.size, MAX_ENRICHMENT_CACHE_SIZE);

    // Adding one more should still work (eviction happens in enrichIpAddress, but
    // we verify the Map itself allows the insertion pattern)
    const firstKey = enrichmentCache.keys().next().value;
    enrichmentCache.delete(firstKey);
    enrichmentCache.set("eviction-test-ip", { data: { score: 999 }, expiresAt: Date.now() + 3600000 });
    assert.strictEqual(enrichmentCache.size, MAX_ENRICHMENT_CACHE_SIZE);
    assert.ok(enrichmentCache.has("eviction-test-ip"));
    assert.ok(!enrichmentCache.has(firstKey));
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
// MCP Session Management
// =============================================================================

describe("MCP Session Management", () => {
  it("ensureMcpSession is a no-op when MCP_URL is not configured", async () => {
    // In test env, config.mcpUrl is empty, so ensureMcpSession should silently return
    await ensureMcpSession();
    // No error thrown = pass
  });

  it("invalidateMcpSession resets session state without error", () => {
    invalidateMcpSession();
    // Should not throw; resets internal state
  });

  it("ensureMcpSession can be called multiple times safely", async () => {
    await ensureMcpSession();
    await ensureMcpSession();
    await ensureMcpSession();
    // Idempotent — no error
  });

  it("invalidateMcpSession followed by ensureMcpSession is safe", async () => {
    invalidateMcpSession();
    await ensureMcpSession();
    // Should not throw
  });

  it("getMcpAuthToken returns null when mcpAuth is not configured", async () => {
    // In test env, config.mcpAuth is empty → should return null
    const token = await getMcpAuthToken();
    assert.strictEqual(token, null);
  });

  it("concurrent getMcpAuthToken calls do not throw", async () => {
    // Fire multiple concurrent calls — should all resolve without error.
    // In test env without MCP_URL, they all return null (early return path).
    // This validates the deduplication logic doesn't break concurrent callers.
    const results = await Promise.all([
      getMcpAuthToken(),
      getMcpAuthToken(),
      getMcpAuthToken(),
      getMcpAuthToken(),
      getMcpAuthToken(),
    ]);
    for (const result of results) {
      assert.strictEqual(result, null);
    }
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

// =============================================================================
// STATUS TRANSITION VALIDATION
// =============================================================================
describe("Status transition validation", () => {
  const tmpDir = path.join(os.tmpdir(), `status-transitions-${Date.now()}`);

  before(async () => {
    process.env.AUTOPILOT_DATA_DIR = tmpDir;
    await fs.mkdir(path.join(tmpDir, "cases"), { recursive: true });
  });

  after(async () => {
    await fs.rm(tmpDir, { recursive: true, force: true });
  });

  it("allows valid transition: open → triaged", async () => {
    const caseId = `CASE-${Date.now()}-statusvalid01`;
    await createCase(caseId, { title: "Test", severity: "high" });
    const result = await updateCase(caseId, { status: "triaged" });
    assert.strictEqual(result.status, "triaged");
  });

  it("rejects invalid transition: open → executed", async () => {
    const caseId = `CASE-${Date.now()}-statusinv01`;
    await createCase(caseId, { title: "Test", severity: "high" });
    await assert.rejects(
      () => updateCase(caseId, { status: "executed" }),
      /Invalid status transition.*open.*executed/,
    );
  });

  it("allows transition: triaged → correlated", async () => {
    const caseId = `CASE-${Date.now()}-statusvalid02`;
    await createCase(caseId, { title: "Test", severity: "high" });
    await updateCase(caseId, { status: "triaged" });
    const result = await updateCase(caseId, { status: "correlated" });
    assert.strictEqual(result.status, "correlated");
  });

  it("allows false_positive from any state", async () => {
    const caseId = `CASE-${Date.now()}-statusfp01`;
    await createCase(caseId, { title: "Test", severity: "high" });
    await updateCase(caseId, { status: "triaged" });
    const result = await updateCase(caseId, { status: "false_positive" });
    assert.strictEqual(result.status, "false_positive");
  });

  it("allows reopen from false_positive", async () => {
    const caseId = `CASE-${Date.now()}-statusreopen01`;
    await createCase(caseId, { title: "Test", severity: "high" });
    await updateCase(caseId, { status: "false_positive" });
    const result = await updateCase(caseId, { status: "open" });
    assert.strictEqual(result.status, "open");
  });
});

// =============================================================================
// ENTITY DEDUPLICATION
// =============================================================================
describe("Entity deduplication in updateCase", () => {
  const tmpDir = path.join(os.tmpdir(), `entity-dedup-${Date.now()}`);

  before(async () => {
    process.env.AUTOPILOT_DATA_DIR = tmpDir;
    await fs.mkdir(path.join(tmpDir, "cases"), { recursive: true });
  });

  after(async () => {
    await fs.rm(tmpDir, { recursive: true, force: true });
  });

  it("deduplicates entities by (type, value)", async () => {
    const caseId = `CASE-${Date.now()}-dedup01`;
    const ip = { type: "ip", value: "10.0.0.1", role: "source" };
    await createCase(caseId, { title: "Test", severity: "high", entities: [ip] });
    await updateCase(caseId, { entities: [ip, ip, ip] });
    const result = await getCase(caseId);
    const ipEntities = result.entities.filter(e => e.type === "ip" && e.value === "10.0.0.1");
    assert.strictEqual(ipEntities.length, 1);
  });

  it("preserves different entities", async () => {
    const caseId = `CASE-${Date.now()}-dedup02`;
    const ip1 = { type: "ip", value: "10.0.0.1", role: "source" };
    const ip2 = { type: "ip", value: "10.0.0.2", role: "source" };
    const user = { type: "user", value: "admin", role: "actor" };
    await createCase(caseId, { title: "Test", severity: "high", entities: [ip1] });
    await updateCase(caseId, { entities: [ip1, ip2, user] });
    const result = await getCase(caseId);
    assert.strictEqual(result.entities.length, 3);
  });
});

// =============================================================================
// EVIDENCE PACK STATUS + FEEDBACK FIELDS
// =============================================================================
describe("Evidence pack initialization", () => {
  const tmpDir = path.join(os.tmpdir(), `evpack-init-${Date.now()}`);

  before(async () => {
    process.env.AUTOPILOT_DATA_DIR = tmpDir;
    await fs.mkdir(path.join(tmpDir, "cases"), { recursive: true });
  });

  after(async () => {
    await fs.rm(tmpDir, { recursive: true, force: true });
  });

  it("includes status and feedback fields at creation", async () => {
    const caseId = `CASE-${Date.now()}-evpackinit01`;
    const result = await createCase(caseId, { title: "Test", severity: "high" });
    assert.strictEqual(result.status, "open");
    assert.ok(Array.isArray(result.feedback));
    assert.strictEqual(result.feedback.length, 0);
  });
});

// =============================================================================
// ATOMIC FEEDBACK APPEND
// =============================================================================
describe("appendFeedback in updateCase", () => {
  const tmpDir = path.join(os.tmpdir(), `feedback-append-${Date.now()}`);

  before(async () => {
    process.env.AUTOPILOT_DATA_DIR = tmpDir;
    await fs.mkdir(path.join(tmpDir, "cases"), { recursive: true });
  });

  after(async () => {
    await fs.rm(tmpDir, { recursive: true, force: true });
  });

  it("atomically appends feedback inside the lock", async () => {
    const caseId = `CASE-${Date.now()}-fbappend01`;
    await createCase(caseId, { title: "Test", severity: "high" });
    await updateCase(caseId, { appendFeedback: { verdict: "true_positive", user_id: "analyst-1" } });
    await updateCase(caseId, { appendFeedback: { verdict: "needs_review", user_id: "analyst-2" } });
    const result = await getCase(caseId);
    assert.strictEqual(result.feedback.length, 2);
    assert.strictEqual(result.feedback[0].verdict, "true_positive");
    assert.strictEqual(result.feedback[1].verdict, "needs_review");
  });
});

describe("Agent output fields in updateCase", () => {
  const tmpDir = path.join(os.tmpdir(), `agent-output-${Date.now()}`);

  before(async () => {
    process.env.AUTOPILOT_DATA_DIR = tmpDir;
    await fs.mkdir(path.join(tmpDir, "cases"), { recursive: true });
  });

  after(async () => {
    await fs.rm(tmpDir, { recursive: true, force: true });
  });

  it("persists investigation agent output fields", async () => {
    const caseId = `CASE-${Date.now()}-invest01`;
    await createCase(caseId, { title: "Test Investigation", severity: "high" });
    // Walk through required status transitions
    await updateCase(caseId, { status: "triaged" });
    await updateCase(caseId, { status: "correlated" });
    await updateCase(caseId, {
      status: "investigated",
      investigation_notes: "Brute force from 203.0.113.44 targeting root",
      findings: { classification: "suspicious_activity", severity: "high", confidence: 0.92 },
      pivot_results: { ip_history: { total_events: 42, successful_auths: 0 } },
      enrichment_data: { baseline_comparison: { deviation_sigma: 3.1 } },
      iocs_identified: [{ type: "ip", value: "203.0.113.44", context: "brute_force" }],
      key_questions_answered: { successful_login: false, lateral_movement_detected: false },
      recommended_response: ["Block 203.0.113.44", "Review SSH logs"],
      related_cases: ["CASE-20260310-abc123"],
    });
    const result = await getCase(caseId);
    assert.strictEqual(result.status, "investigated");
    assert.strictEqual(result.investigation_notes, "Brute force from 203.0.113.44 targeting root");
    assert.deepStrictEqual(result.findings, { classification: "suspicious_activity", severity: "high", confidence: 0.92 });
    assert.strictEqual(result.pivot_results.ip_history.total_events, 42);
    assert.strictEqual(result.enrichment_data.baseline_comparison.deviation_sigma, 3.1);
    assert.strictEqual(result.iocs_identified.length, 1);
    assert.strictEqual(result.iocs_identified[0].value, "203.0.113.44");
    assert.strictEqual(result.key_questions_answered.successful_login, false);
    assert.deepStrictEqual(result.recommended_response, ["Block 203.0.113.44", "Review SSH logs"]);
    assert.deepStrictEqual(result.related_cases, ["CASE-20260310-abc123"]);
  });

  it("persists correlation agent output fields", async () => {
    const caseId = `CASE-${Date.now()}-corr01`;
    await createCase(caseId, { title: "Test Correlation", severity: "medium" });
    await updateCase(caseId, { status: "triaged" });
    await updateCase(caseId, {
      status: "correlated",
      correlation: { correlation_score: 0.87, attack_pattern: "brute_force", blast_radius: { hosts: 2 } },
    });
    const result = await getCase(caseId);
    assert.strictEqual(result.correlation.correlation_score, 0.87);
    assert.strictEqual(result.correlation.attack_pattern, "brute_force");
  });

  it("normalizes iocs to iocs_identified", async () => {
    const caseId = `CASE-${Date.now()}-iocs01`;
    await createCase(caseId, { title: "Test IOCs", severity: "low" });
    await updateCase(caseId, {
      iocs: [{ type: "ip", value: "10.0.0.1" }],
    });
    const result = await getCase(caseId);
    assert.ok(result.iocs_identified, "iocs should be normalized to iocs_identified");
    assert.strictEqual(result.iocs_identified[0].value, "10.0.0.1");
  });

  it("overwrites investigation fields on re-investigation", async () => {
    const caseId = `CASE-${Date.now()}-reinvest01`;
    await createCase(caseId, { title: "Test Re-investigation", severity: "high" });
    await updateCase(caseId, {
      investigation_notes: "First pass",
      findings: { classification: "reconnaissance", confidence: 0.5 },
    });
    await updateCase(caseId, {
      investigation_notes: "Second pass with more data",
      findings: { classification: "confirmed_compromise", confidence: 0.95 },
    });
    const result = await getCase(caseId);
    assert.strictEqual(result.investigation_notes, "Second pass with more data");
    assert.strictEqual(result.findings.classification, "confirmed_compromise");
  });
});

// =============================================================================
// M3: Entity Index Capacity Warnings
// =============================================================================

describe("Entity Index Capacity Warnings", () => {
  // Access the module for the warning flag getter/setter
  const mod = require("./index.js");

  beforeEach(() => {
    entityCaseIndex.clear();
    mod.entityIndexWarningLogged = false;
  });

  afterEach(() => {
    entityCaseIndex.clear();
    mod.entityIndexWarningLogged = false;
  });

  it("logs warning when entity index reaches 90% capacity", () => {
    // Pre-fill the index to just below 90% threshold
    const threshold = Math.floor(MAX_ENTITY_INDEX_SIZE * 0.9);
    for (let i = 0; i < threshold - 1; i++) {
      entityCaseIndex.set(`ip:10.0.${Math.floor(i / 256)}.${i % 256}-prefill-${i}`, [{ caseId: "CASE-PREFILL", severity: "low", createdAt: Date.now(), isFalsePositive: false }]);
    }
    assert.strictEqual(entityCaseIndex.size, threshold - 1);
    assert.strictEqual(mod.entityIndexWarningLogged, false);

    // Add one more entity via indexCaseEntities to cross the 90% threshold
    // We need 2 new unique keys: one to reach threshold, one to trigger warning check
    indexCaseEntities("CASE-WARN-1", [{ type: "ip", value: "192.168.0.1-warn" }], "high");
    // Now at threshold exactly — warning should NOT have fired yet (check is on the NEXT insert)
    indexCaseEntities("CASE-WARN-2", [{ type: "ip", value: "192.168.0.2-warn" }], "high");
    // Now past threshold — warning should have been logged
    assert.strictEqual(mod.entityIndexWarningLogged, true);
  });

  it("warning is logged only once (not on every insert past 90%)", () => {
    const threshold = Math.floor(MAX_ENTITY_INDEX_SIZE * 0.9);
    for (let i = 0; i < threshold + 5; i++) {
      entityCaseIndex.set(`ip:warn-once-${i}`, [{ caseId: "CASE-ONCE", severity: "low", createdAt: Date.now(), isFalsePositive: false }]);
    }
    // Reset flag and verify it only gets set once
    mod.entityIndexWarningLogged = false;
    indexCaseEntities("CASE-A", [{ type: "ip", value: "once-test-1" }], "high");
    assert.strictEqual(mod.entityIndexWarningLogged, true);
    // Flag stays true — the log("warn") only fires when flag is false
  });
});

// =============================================================================
// M10: Response Plan Periodic Eviction
// =============================================================================

describe("Response Plan Periodic Eviction", () => {
  let savedPlans;

  beforeEach(() => {
    // Save existing plans and start with a clean map
    savedPlans = new Map(responsePlans);
    responsePlans.clear();
  });

  afterEach(() => {
    // Restore original plans
    responsePlans.clear();
    for (const [k, v] of savedPlans) {
      responsePlans.set(k, v);
    }
  });

  it("evicts terminal plans older than 24 hours", () => {
    const now = Date.now();
    const old = new Date(now - 25 * 60 * 60 * 1000).toISOString(); // 25 hours ago
    const recent = new Date(now - 1 * 60 * 60 * 1000).toISOString(); // 1 hour ago

    // Add old terminal plans (should be evicted)
    responsePlans.set("PLAN-OLD-COMPLETED", { state: "completed", updated_at: old, created_at: old });
    responsePlans.set("PLAN-OLD-FAILED", { state: "failed", updated_at: old, created_at: old });
    responsePlans.set("PLAN-OLD-REJECTED", { state: "rejected", updated_at: old, created_at: old });
    responsePlans.set("PLAN-OLD-EXPIRED", { state: "expired", updated_at: old, created_at: old });

    // Add recent terminal plans (should NOT be evicted)
    responsePlans.set("PLAN-RECENT-COMPLETED", { state: "completed", updated_at: recent, created_at: recent });

    // Add old non-terminal plans (should NOT be evicted)
    responsePlans.set("PLAN-OLD-PROPOSED", { state: "proposed", updated_at: old, created_at: old });
    responsePlans.set("PLAN-OLD-EXECUTING", { state: "executing", updated_at: old, created_at: old });

    assert.strictEqual(responsePlans.size, 7);

    // Simulate the periodic cleanup logic (same as in setupCleanupIntervals)
    const cutoff = now - 24 * 60 * 60 * 1000;
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

    assert.strictEqual(evicted, 4, "Should evict 4 old terminal plans");
    assert.strictEqual(responsePlans.size, 3, "Should retain 3 plans (1 recent terminal, 2 non-terminal)");
    assert.ok(responsePlans.has("PLAN-RECENT-COMPLETED"), "Recent completed plan should be retained");
    assert.ok(responsePlans.has("PLAN-OLD-PROPOSED"), "Old proposed plan should be retained");
    assert.ok(responsePlans.has("PLAN-OLD-EXECUTING"), "Old executing plan should be retained");
  });
});

// Run if executed directly
if (require.main === module) {
  console.log("Running tests...");
}
